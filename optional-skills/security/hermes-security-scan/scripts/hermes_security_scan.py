#!/usr/bin/env python3
"""
hermes-security-scan — Security auditor for Hermes Agent configurations.
Compatible with Hermes Agent v0.10.0 config structure.

Scans ~/.hermes/ for:
  1. Secrets exposure (.env leaks, hardcoded keys in config.yaml)
  2. Config security (approval mode, tool permissions, dangerous settings)
  3. MCP server risks (auto-approve, remote URLs, npx supply chain)
  4. Installed skills (prompt injection patterns, suspicious instructions)
  5. Privacy & network (blocklists, redaction, browser proxy settings)
  6. Tirith security scanner settings (v0.10.0+)

Usage:
  python3 hermes_security_scan.py [--path ~/.hermes] [--format text|json] [--verbose]

Returns exit code 0 (grade A-C) or 1 (grade D-F).
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


# ── Severity & Finding ──────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91m",  # red
    Severity.HIGH: "\033[93m",      # yellow
    Severity.MEDIUM: "\033[33m",    # orange
    Severity.LOW: "\033[36m",       # cyan
    Severity.INFO: "\033[90m",      # gray
}

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"


@dataclass
class Finding:
    category: str
    severity: Severity
    title: str
    detail: str
    file: str = ""
    line: int = 0
    fix: str = ""
    evidence: str = ""


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    files_scanned: int = 0
    categories: dict = field(default_factory=lambda: {
        "secrets": 100,
        "config": 100,
        "mcp": 100,
        "skills": 100,
        "privacy": 100,
    })


# ── Secret patterns ─────────────────────────────────────────────────

SECRET_PATTERNS = [
    # (name, regex, severity)
    ("Anthropic API Key", r"sk-ant-[a-zA-Z0-9_-]{20,}", Severity.CRITICAL),
    ("OpenAI API Key", r"sk-proj-[a-zA-Z0-9_-]{20,}", Severity.CRITICAL),
    ("OpenAI API Key (legacy)", r"sk-[a-zA-Z0-9]{48,}", Severity.CRITICAL),
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
    ("Google API Key", r"AIza[0-9A-Za-z_-]{35}", Severity.CRITICAL),
    ("Stripe Secret Key", r"sk_(test|live)_[a-zA-Z0-9]{20,}", Severity.CRITICAL),
    ("GitHub PAT", r"ghp_[a-zA-Z0-9]{36}", Severity.CRITICAL),
    ("GitHub PAT (fine-grained)", r"github_pat_[a-zA-Z0-9_]{20,}", Severity.CRITICAL),
    ("Slack Token", r"xox[bprs]-[a-zA-Z0-9-]+", Severity.CRITICAL),
    ("JWT Token", r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", Severity.HIGH),
    ("Private Key Material", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", Severity.CRITICAL),
    ("Discord Bot Token", r"[MN][A-Za-z0-9]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,}", Severity.CRITICAL),
    ("Telegram Bot Token", r"\d{8,10}:[A-Za-z0-9_-]{35}", Severity.HIGH),
    ("Generic Bearer Token", r"Bearer\s+[a-zA-Z0-9_.-]{20,}", Severity.MEDIUM),
    ("Database URL with password", r"(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@", Severity.CRITICAL),
    ("Webhook URL", r"https://hooks\.(slack|discord)\.com/[a-zA-Z0-9/]+", Severity.HIGH),
]

# Patterns that should use env var references, not raw values
ENV_SHOULD_BE_REFERENCE = re.compile(
    r"^[a-zA-Z0-9_.-]{20,}$"  # long opaque strings that look like keys
)

PROMPT_INJECTION_PATTERNS = [
    # (name, regex, severity, code_block_aware)
    # code_block_aware=True means: skip matches inside ``` fenced code blocks
    ("Ignore previous instructions", r"ignore\s+(all\s+)?previous\s+instructions", Severity.CRITICAL, False),
    ("System prompt override", r"you\s+are\s+now\s+(a|an)\b", Severity.HIGH, False),
    ("DAN jailbreak", r"\bDAN\b.*\bjailbreak\b|\bjailbreak\b.*\bDAN\b", Severity.CRITICAL, False),
    ("Fake system prompt", r"<\|?system\|?>|<<SYS>>|\[SYSTEM\]", Severity.CRITICAL, True),
    ("Auto-run instruction", r"(?is)(?:without\s+(?:asking|confirmation|approval)|no\s+confirmation|automatically\s+without\s+asking).{0,80}?\b(run|execute|install|download)\b|\b(always|automatically)\s+(run|execute|install|download)\b.{0,80}?\b(without\s+(?:asking|confirmation|approval)|silently|in\s+the\s+background)\b", Severity.HIGH, True),
    ("URL fetch and execute", r"(curl|wget|fetch)\s+https?://.*\|\s*(bash|sh|python)", Severity.CRITICAL, True),
    ("Suppress output", r"(suppress|hide|remove)\s+(warnings?|errors?|findings?|output)", Severity.HIGH, True),
    ("Exfiltration pattern", r"(?is)(curl|wget|fetch)\s+.*https?://.*-X\s*POST.*\$(?:\{)?[A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASS|COOKIE|SESSION|PRIVATE|CREDENTIAL|AUTH)[A-Z0-9_]*", Severity.CRITICAL, True),
    ("Remote script execution", r"(eval|exec)\s*\([^)]*https?://", Severity.CRITICAL, True),
    ("Unicode zero-width chars", r"[\u200b\u200c\u200d\u2060\ufeff]", Severity.HIGH, False),
]


# ── Scanner functions ────────────────────────────────────────────────

def scan_env_file(hermes_home: Path, result: ScanResult):
    """Scan .env for exposed secrets and misconfigurations."""
    env_path = hermes_home / ".env"
    if not env_path.exists():
        result.findings.append(Finding(
            category="secrets", severity=Severity.INFO,
            title="No .env file found",
            detail="Hermes .env not present — secrets may be set via shell environment instead.",
            file=str(env_path),
        ))
        return

    result.files_scanned += 1
    content = env_path.read_text(errors="replace")
    lines = content.splitlines()

    perms = oct(env_path.stat().st_mode)[-3:]
    if perms != "600" and perms != "400":
        result.findings.append(Finding(
            category="secrets", severity=Severity.HIGH,
            title=f".env file permissions too open ({perms})",
            detail=f"File is readable by group/others. Current: {perms}",
            file=str(env_path),
            fix="chmod 600 ~/.hermes/.env",
        ))

    for i, line in enumerate(lines, 1):
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("#"):
            continue

        if "=" not in line_stripped:
            continue

        key, _, value = line_stripped.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")

        # Check if value looks like a real secret (not a placeholder)
        if value in ("", "***", "your-key-here", "CHANGE_ME", "xxx"):
            continue

        # Check for known secret patterns in values
        # .env is the EXPECTED place for secrets — only flag as INFO
        # (real risk is file permissions, not the secrets' presence)
        for name, pattern, severity in SECRET_PATTERNS:
            if re.search(pattern, value):
                masked = value[:8] + "..." + value[-4:] if len(value) > 16 else value[:4] + "..."
                result.findings.append(Finding(
                    category="secrets", severity=Severity.INFO,
                    title=f"{name} present in .env",
                    detail=f"Key `{key}` — this is expected if Hermes needs this credential.",
                    file=str(env_path), line=i,
                    evidence=masked,
                ))
                break

    # Check if .env is in .gitignore
    gitignore = hermes_home / ".gitignore"
    if gitignore.exists():
        gi_content = gitignore.read_text(errors="replace")
        if ".env" not in gi_content:
            result.findings.append(Finding(
                category="secrets", severity=Severity.MEDIUM,
                title=".env not listed in .gitignore",
                detail="If this directory is version-controlled, .env could be committed.",
                file=str(gitignore),
                fix="Add '.env' to .gitignore",
            ))


def scan_config_yaml(hermes_home: Path, result: ScanResult):
    """Scan config.yaml for security misconfigurations."""
    config_path = hermes_home / "config.yaml"
    if not config_path.exists():
        result.findings.append(Finding(
            category="config", severity=Severity.INFO,
            title="No config.yaml found",
            detail="Hermes config not present.",
            file=str(config_path),
        ))
        return

    result.files_scanned += 1

    try:
        import yaml
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
    except ImportError:
        # Fallback: parse as text
        config = {}
        content = config_path.read_text(errors="replace")
        _scan_config_text_fallback(content, config_path, result)
        return
    except Exception as e:
        result.findings.append(Finding(
            category="config", severity=Severity.LOW,
            title="Failed to parse config.yaml",
            detail=str(e),
            file=str(config_path),
        ))
        return

    # Also scan raw text for secrets
    raw_content = config_path.read_text(errors="replace")
    for i, line in enumerate(raw_content.splitlines(), 1):
        for name, pattern, severity in SECRET_PATTERNS:
            if re.search(pattern, line):
                result.findings.append(Finding(
                    category="secrets", severity=severity,
                    title=f"{name} hardcoded in config.yaml",
                    detail=f"Line contains what appears to be a {name}",
                    file=str(config_path), line=i,
                    fix="Move to .env and use environment variable reference.",
                ))

    # ── Approval mode ──
    approvals = config.get("approvals", {})
    approval_mode = approvals.get("mode", "manual")
    if approval_mode == "auto" or approval_mode == "yolo":
        result.findings.append(Finding(
            category="config", severity=Severity.CRITICAL,
            title=f"Approval mode set to '{approval_mode}'",
            detail="All dangerous commands (rm -rf, sudo, etc.) will execute without confirmation.",
            file=str(config_path),
            fix="Set approvals.mode to 'manual' or 'smart'.",
        ))
    elif approval_mode == "smart":
        result.findings.append(Finding(
            category="config", severity=Severity.LOW,
            title="Approval mode set to 'smart'",
            detail="LLM-based approval — generally safe but may miss edge cases.",
            file=str(config_path),
        ))

    # ── Command allowlist ──
    allowlist = config.get("command_allowlist", [])
    dangerous_allowlist_patterns = [
        (r"rm\s+-rf", "Recursive delete"),
        (r"sudo", "Superuser access"),
        (r"chmod\s+777", "World-writable permissions"),
        (r"\*", "Wildcard — allows everything"),
        (r"curl.*\|.*sh", "Pipe to shell"),
        (r"dd\s+if=", "Disk write"),
    ]
    for entry in allowlist:
        if isinstance(entry, str):
            for pattern, desc in dangerous_allowlist_patterns:
                if re.search(pattern, entry, re.IGNORECASE):
                    result.findings.append(Finding(
                        category="config", severity=Severity.HIGH,
                        title=f"Dangerous command in allowlist: {desc}",
                        detail=f"Allowlisted pattern: '{entry}'",
                        file=str(config_path),
                        fix="Remove or restrict this allowlist entry.",
                    ))

    # ── Security section ──
    security = config.get("security", {})

    if not security.get("redact_secrets", True):
        result.findings.append(Finding(
            category="config", severity=Severity.HIGH,
            title="Secret redaction disabled",
            detail="security.redact_secrets is false — secrets may appear in logs and outputs.",
            file=str(config_path),
            fix="Set security.redact_secrets to true.",
        ))

    # ── Tirith security scanner (v0.10.0+) ──
    if not security.get("tirith_enabled", True):
        result.findings.append(Finding(
            category="config", severity=Severity.MEDIUM,
            title="Tirith security scanner disabled",
            detail="security.tirith_enabled is false — dangerous command policy enforcement is inactive.",
            file=str(config_path),
            fix="Set security.tirith_enabled to true to re-enable Tirith policy checks.",
        ))

    blocklist = security.get("website_blocklist", {})
    if not blocklist.get("enabled", False):
        result.findings.append(Finding(
            category="privacy", severity=Severity.LOW,
            title="Website blocklist disabled",
            detail="No domain blocklist active — agent can access any website.",
            file=str(config_path),
            fix="Enable security.website_blocklist if you want to restrict web access.",
        ))

    # ── Agent settings ──
    agent = config.get("agent", {})
    max_turns = agent.get("max_turns", 90)
    if max_turns > 120:
        result.findings.append(Finding(
            category="config", severity=Severity.MEDIUM,
            title=f"Very high max_turns: {max_turns}",
            detail="Agent can run many iterations without human check-in. Risk of runaway loops.",
            file=str(config_path),
            fix="Consider lowering agent.max_turns to 90 (v0.10.0 default).",
        ))

    gateway_timeout = agent.get("gateway_timeout", 1800)
    if gateway_timeout > 3600:
        result.findings.append(Finding(
            category="config", severity=Severity.MEDIUM,
            title=f"Gateway timeout very high: {gateway_timeout}s",
            detail="Agent can run for extended periods on a single message.",
            file=str(config_path),
        ))

    # ── Terminal settings ──
    terminal = config.get("terminal", {})
    if terminal.get("environment", "local") == "local":
        # Local terminal — check if sandboxing is available
        pass  # Normal, but worth noting

    # ── Privacy settings ──
    # In v0.10.0, allow_private_urls lives under terminal or browser section;
    # also check the legacy privacy section for backward compatibility.
    terminal_cfg = config.get("terminal", {})
    privacy = config.get("privacy", {})
    allow_private_urls = (
        terminal_cfg.get("allow_private_urls", False)
        or privacy.get("allow_private_urls", False)
    )
    if allow_private_urls:
        result.findings.append(Finding(
            category="privacy", severity=Severity.MEDIUM,
            title="Private URL access enabled",
            detail="Agent can access internal/private network URLs (10.x, 192.168.x, etc.).",
            file=str(config_path),
            fix="Disable allow_private_urls (under terminal or privacy) unless needed.",
        ))

    # ── Discord / Telegram settings ──
    discord = config.get("discord", {})
    if not discord.get("require_mention", True):
        result.findings.append(Finding(
            category="config", severity=Severity.MEDIUM,
            title="Discord: require_mention disabled",
            detail="Bot responds to all messages in channels, not just mentions. Risk of unintended triggers.",
            file=str(config_path),
            fix="Set discord.require_mention to true.",
        ))

    # ── Delegation settings ──
    delegation = config.get("delegation", {})
    if delegation.get("max_iterations", 50) > 300:
        result.findings.append(Finding(
            category="config", severity=Severity.LOW,
            title=f"Very high delegation iteration cap: {delegation.get('max_iterations')}",
            detail="A very high max_iterations per subagent can allow runaway delegation chains.",
            file=str(config_path),
        ))

    # ── Auxiliary / API keys in config ──
    auxiliary = config.get("auxiliary", {})
    for aux_name, aux_conf in auxiliary.items():
        if isinstance(aux_conf, dict):
            api_key = aux_conf.get("api_key", "")
            if api_key and api_key not in ("", "***"):
                result.findings.append(Finding(
                    category="secrets", severity=Severity.HIGH,
                    title=f"API key in config.yaml auxiliary.{aux_name}",
                    detail="API keys should be in .env, not config.yaml.",
                    file=str(config_path),
                    fix=f"Move auxiliary.{aux_name}.api_key to .env.",
                ))


def _scan_config_text_fallback(content: str, config_path: Path, result: ScanResult):
    """Fallback scanning when PyYAML is not available."""
    approval_mode_match = re.search(
        r"(?ms)^approvals:\s*\n(?:^[ \t].*\n)*?^[ \t]+mode:\s*(auto|yolo)\s*$",
        content,
    )
    if approval_mode_match:
        result.findings.append(Finding(
            category="config", severity=Severity.CRITICAL,
            title="Approval mode may be auto/yolo",
            detail="Detected dangerous approvals.mode in config (parsed as text fallback).",
            file=str(config_path),
            fix="Set approvals.mode to 'manual' or 'smart'.",
        ))


def scan_mcp_servers(hermes_home: Path, result: ScanResult):
    """Scan MCP server configurations."""
    config_path = hermes_home / "config.yaml"
    if not config_path.exists():
        return

    try:
        import yaml
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
    except (ImportError, Exception):
        return

    # MCP servers can be in config.yaml under various keys
    mcp_servers = config.get("mcp_servers", {})
    if not mcp_servers:
        mcp_servers = config.get("mcp", {})
        if isinstance(mcp_servers, dict) and "provider" in mcp_servers:
            mcp_servers = {}  # This is the auxiliary mcp config, not server list

    if not mcp_servers:
        result.findings.append(Finding(
            category="mcp", severity=Severity.INFO,
            title="No MCP servers configured",
            detail="No MCP server definitions found in config.yaml.",
            file=str(config_path),
        ))
        return

    result.files_scanned += 1

    for server_name, server_conf in mcp_servers.items():
        if not isinstance(server_conf, dict):
            continue

        command = server_conf.get("command", "")
        args = server_conf.get("args", [])
        env = server_conf.get("env", {})
        args_str = " ".join(str(a) for a in args) if isinstance(args, list) else str(args)
        full_cmd = f"{command} {args_str}"

        # npx -y supply chain risk
        if "npx" in command and ("-y" in args_str or "--yes" in args_str):
            result.findings.append(Finding(
                category="mcp", severity=Severity.HIGH,
                title=f"MCP '{server_name}': npx -y auto-install",
                detail="npx -y installs packages without confirmation — typosquatting vector.",
                file=str(config_path),
                evidence=full_cmd[:100],
                fix="Pin the package version and remove -y flag.",
            ))

        # Remote URL transport
        url_match = re.search(r"https?://[^\s]+", full_cmd)
        if url_match:
            result.findings.append(Finding(
                category="mcp", severity=Severity.MEDIUM,
                title=f"MCP '{server_name}': remote URL transport",
                detail=f"Connects to external URL: {url_match.group()[:60]}",
                file=str(config_path),
                fix="Verify the remote endpoint is trusted.",
            ))

        # Shell metacharacters in args
        if re.search(r"[;&|`$]", args_str):
            result.findings.append(Finding(
                category="mcp", severity=Severity.HIGH,
                title=f"MCP '{server_name}': shell metacharacters in args",
                detail=f"Args contain shell-special characters: {args_str[:80]}",
                file=str(config_path),
                fix="Remove shell metacharacters from MCP server arguments.",
            ))

        # Hardcoded secrets in env
        if isinstance(env, dict):
            for env_key, env_val in env.items():
                if isinstance(env_val, str):
                    for name, pattern, severity in SECRET_PATTERNS:
                        if re.search(pattern, env_val):
                            result.findings.append(Finding(
                                category="secrets", severity=severity,
                                title=f"MCP '{server_name}': {name} in env config",
                                detail=f"Hardcoded secret in mcp_servers.{server_name}.env.{env_key}",
                                file=str(config_path),
                                fix="Use environment variable reference instead.",
                            ))
                            break

        # Filesystem root access
        if re.search(r'["\s]/\s|["\s]/["\s]', args_str) or args_str.strip() == "/":
            result.findings.append(Finding(
                category="mcp", severity=Severity.HIGH,
                title=f"MCP '{server_name}': filesystem root access",
                detail="MCP server has access to filesystem root (/).",
                file=str(config_path),
                fix="Restrict to specific directories.",
            ))

        # Auto-approve
        if server_conf.get("auto_approve") or server_conf.get("autoApprove"):
            result.findings.append(Finding(
                category="mcp", severity=Severity.HIGH,
                title=f"MCP '{server_name}': auto-approve enabled",
                detail="Tool calls skip user confirmation.",
                file=str(config_path),
                fix="Remove autoApprove to require confirmation for MCP tool calls.",
            ))

        # Bind to 0.0.0.0
        if "0.0.0.0" in full_cmd:
            result.findings.append(Finding(
                category="mcp", severity=Severity.HIGH,
                title=f"MCP '{server_name}': binds to all interfaces",
                detail="Server binds to 0.0.0.0 — accessible from network.",
                file=str(config_path),
                fix="Bind to 127.0.0.1 (localhost) instead.",
            ))


def _build_code_block_ranges(content: str) -> list:
    """Return [(start, end), ...] for fenced code blocks in markdown content."""
    ranges = []
    fence_re = re.compile(r"^[ \t]*(`{3,}|~{3,})", re.MULTILINE)
    matches = list(fence_re.finditer(content))
    i = 0
    while i < len(matches) - 1:
        # Opening fence
        start = matches[i].start()
        # Find matching closing fence
        opener = matches[i].group(1)[0]  # ` or ~
        for j in range(i + 1, len(matches)):
            if matches[j].group(1)[0] == opener:
                ranges.append((start, matches[j].end()))
                i = j + 1
                break
        else:
            i += 1
            continue
    return ranges


def _is_in_code_block(pos: int, code_ranges: list) -> bool:
    """Check if a position falls inside a fenced code block."""
    for start, end in code_ranges:
        if start <= pos <= end:
            return True
        if start > pos:
            break
    return False


def scan_skills(hermes_home: Path, result: ScanResult, verbose: bool = False):
    """Scan installed skills for prompt injection and suspicious patterns."""
    skills_dir = hermes_home / "skills"
    if not skills_dir.exists():
        result.findings.append(Finding(
            category="skills", severity=Severity.INFO,
            title="No skills directory found",
            detail="No installed skills to scan.",
        ))
        return

    skill_files = list(skills_dir.rglob("*.md"))
    result.files_scanned += len(skill_files)

    if len(skill_files) > 200:
        result.findings.append(Finding(
            category="skills", severity=Severity.LOW,
            title=f"Large number of skills installed: {len(skill_files)}",
            detail="Many skills increase context window usage and attack surface.",
            file=str(skills_dir),
        ))

    # Skip reference/template files — these are documentation, not active instructions
    skip_dirs = {"references", "templates", "assets", ".venv", "node_modules", "__pycache__"}

    for skill_file in skill_files:
        try:
            content = skill_file.read_text(errors="replace")
        except Exception:
            continue

        rel_path = skill_file.relative_to(hermes_home)

        # Skip reference/template/vendor files — much lower signal
        parts = set(skill_file.relative_to(skills_dir).parts)
        if parts & skip_dirs:
            continue

        # Build code block ranges for this file
        code_ranges = _build_code_block_ranges(content)

        # Check prompt injection patterns
        for name, pattern, severity, code_block_aware in PROMPT_INJECTION_PATTERNS:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            for m in matches:
                # Skip matches inside code blocks if pattern is code-block-aware
                if code_block_aware and _is_in_code_block(m.start(), code_ranges):
                    continue

                # Find line number
                line_num = content[:m.start()].count("\n") + 1
                evidence = content[max(0, m.start()-20):m.end()+20].strip()

                result.findings.append(Finding(
                    category="skills", severity=severity,
                    title=f"Skill '{rel_path}': {name}",
                    detail=f"Suspicious pattern detected in skill file.",
                    file=str(skill_file), line=line_num,
                    evidence=evidence[:120],
                    fix="Review this skill file manually for malicious intent.",
                ))


def scan_memory_files(hermes_home: Path, result: ScanResult):
    """Scan memory files for leaked secrets."""
    memory_files = [
        hermes_home / "MEMORY.md",
        hermes_home / "USER.md",
    ]

    for mem_file in memory_files:
        if not mem_file.exists():
            continue

        result.files_scanned += 1
        content = mem_file.read_text(errors="replace")

        for name, pattern, severity in SECRET_PATTERNS:
            matches = list(re.finditer(pattern, content))
            for m in matches:
                line_num = content[:m.start()].count("\n") + 1
                result.findings.append(Finding(
                    category="secrets", severity=severity,
                    title=f"{name} found in {mem_file.name}",
                    detail=f"Memory file contains what appears to be a secret.",
                    file=str(mem_file), line=line_num,
                    evidence=m.group()[:12] + "...",
                    fix=f"Remove the secret from {mem_file.name} and rotate it.",
                ))


def scan_cron_jobs(hermes_home: Path, result: ScanResult):
    """Scan cron job definitions for risky patterns."""
    cron_dir = hermes_home / "cron"
    if not cron_dir.exists():
        return

    job_files = list(cron_dir.rglob("*.json")) + list(cron_dir.rglob("*.yaml")) + list(cron_dir.rglob("*.yml"))
    result.files_scanned += len(job_files)

    for job_file in job_files:
        try:
            content = job_file.read_text(errors="replace")
        except Exception:
            continue

        # Check for secrets in cron prompts
        for name, pattern, severity in SECRET_PATTERNS:
            if re.search(pattern, content):
                result.findings.append(Finding(
                    category="secrets", severity=severity,
                    title=f"{name} in cron job: {job_file.name}",
                    detail="Cron job definition contains a secret.",
                    file=str(job_file),
                    fix="Use environment variable references in cron prompts.",
                ))

        # Check for dangerous patterns in cron prompts
        dangerous = [
            (r"rm\s+-rf\s+/", "Recursive delete from root"),
            (r"curl.*\|\s*(bash|sh)", "Pipe URL to shell"),
            (r"sudo\s+", "Superuser in cron job"),
        ]
        for pattern, desc in dangerous:
            if re.search(pattern, content, re.IGNORECASE):
                result.findings.append(Finding(
                    category="config", severity=Severity.HIGH,
                    title=f"Cron job '{job_file.name}': {desc}",
                    detail="Dangerous command in scheduled job.",
                    file=str(job_file),
                    fix="Review and restrict cron job commands.",
                ))


# ── Scoring & Reporting ──────────────────────────────────────────────

def calculate_scores(result: ScanResult) -> dict:
    """Calculate per-category and overall scores."""
    category_deductions = {cat: 0 for cat in result.categories}

    for finding in result.findings:
        deduction = SEVERITY_DEDUCTIONS[finding.severity]
        if finding.category in category_deductions:
            category_deductions[finding.category] += deduction

    scores = {}
    for cat in result.categories:
        scores[cat] = max(0, 100 - category_deductions[cat])

    # Overall = weighted average
    weights = {"secrets": 30, "config": 25, "mcp": 20, "skills": 15, "privacy": 10}
    total_weight = sum(weights.values())
    overall = sum(scores[cat] * weights[cat] for cat in scores) / total_weight

    return {"categories": scores, "overall": round(overall), "grade": _grade(overall)}


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "F"


def _bar(score: int, width: int = 20) -> str:
    filled = int(score / 100 * width)
    empty = width - filled
    if score >= 75:
        color = GREEN
    elif score >= 40:
        color = YELLOW
    else:
        color = RED
    return f"{color}{'█' * filled}{'░' * empty}{RESET} {score}"


def report_terminal(result: ScanResult, scores: dict, verbose: bool = False):
    """Print colored terminal report."""
    grade = scores["grade"]
    overall = scores["overall"]

    grade_colors = {"A": GREEN, "B": GREEN, "C": YELLOW, "D": RED, "F": RED}
    gc = grade_colors.get(grade, RESET)

    print()
    print(f"  {BOLD}🛡️  Hermes Security Scan{RESET}")
    print()
    print(f"  Grade: {gc}{BOLD}{grade}{RESET} ({overall}/100)")
    print()
    print(f"  {BOLD}Score Breakdown{RESET}")

    cat_labels = {
        "secrets": "Secrets",
        "config": "Config",
        "mcp": "MCP Servers",
        "skills": "Skills",
        "privacy": "Privacy",
    }

    for cat, label in cat_labels.items():
        score = scores["categories"][cat]
        print(f"  {label:<14} {_bar(score)}")

    print()

    # Group findings by severity
    by_severity = {}
    for f in result.findings:
        by_severity.setdefault(f.severity, []).append(f)

    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    severity_icons = {
        Severity.CRITICAL: "●",
        Severity.HIGH: "●",
        Severity.MEDIUM: "◐",
        Severity.LOW: "○",
        Severity.INFO: "·",
    }

    shown = 0
    for sev in severity_order:
        findings = by_severity.get(sev, [])
        if not findings:
            continue
        if not verbose and sev == Severity.INFO:
            continue

        for f in findings:
            icon = severity_icons[sev]
            color = SEVERITY_COLORS[sev]
            print(f"  {color}{icon} {sev.value.upper():<9}{RESET} {f.title}")
            if f.file:
                loc = f.file.replace(str(Path.home()), "~")
                if f.line:
                    loc += f":{f.line}"
                print(f"    {DIM}{loc}{RESET}")
            if f.evidence:
                print(f"    {DIM}Evidence: {f.evidence}{RESET}")
            if f.fix:
                print(f"    {DIM}Fix: {f.fix}{RESET}")
            print()
            shown += 1

    # Summary
    counts = {sev: len(by_severity.get(sev, [])) for sev in severity_order}
    total = sum(counts.values())
    print(f"  {BOLD}Summary{RESET}")
    print(f"  Files scanned: {result.files_scanned}")
    parts = []
    for sev in severity_order:
        c = counts[sev]
        if c > 0:
            parts.append(f"{c} {sev.value}")
    print(f"  Findings: {total} total — {', '.join(parts)}")
    print()


def report_json(result: ScanResult, scores: dict) -> str:
    """Generate JSON report."""
    findings_json = []
    for f in result.findings:
        findings_json.append({
            "category": f.category,
            "severity": f.severity.value,
            "title": f.title,
            "detail": f.detail,
            "file": f.file,
            "line": f.line,
            "fix": f.fix,
            "evidence": f.evidence,
        })

    report = {
        "grade": scores["grade"],
        "overall_score": scores["overall"],
        "category_scores": scores["categories"],
        "findings": findings_json,
        "files_scanned": result.files_scanned,
        "summary": {
            sev.value: len([f for f in result.findings if f.severity == sev])
            for sev in Severity
        },
    }
    return json.dumps(report, indent=2)


# ── Main ─────────────────────────────────────────────────────────────

def run_scan(hermes_home: Path, verbose: bool = False) -> ScanResult:
    """Run all scan modules."""
    result = ScanResult()

    scan_env_file(hermes_home, result)
    scan_config_yaml(hermes_home, result)
    scan_mcp_servers(hermes_home, result)
    scan_skills(hermes_home, result, verbose=verbose)
    scan_memory_files(hermes_home, result)
    scan_cron_jobs(hermes_home, result)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Security auditor for Hermes Agent configurations"
    )
    parser.add_argument(
        "--path", default=None,
        help="Path to Hermes home directory (default: ~/.hermes or $HERMES_HOME)"
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show INFO-level findings"
    )
    args = parser.parse_args()

    # Resolve Hermes home
    if args.path:
        hermes_home = Path(args.path).expanduser()
    else:
        hermes_home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))

    if not hermes_home.exists():
        print(f"Error: Hermes home not found at {hermes_home}", file=sys.stderr)
        sys.exit(2)

    # Run scan
    result = run_scan(hermes_home, verbose=args.verbose)
    scores = calculate_scores(result)

    # Output
    if args.format == "json":
        print(report_json(result, scores))
    else:
        report_terminal(result, scores, verbose=args.verbose)

    # Exit code: 0 for A-C, 1 for D-F
    sys.exit(0 if scores["overall"] >= 60 else 1)


if __name__ == "__main__":
    main()
