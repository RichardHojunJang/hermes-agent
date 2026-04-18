---
name: hermes-security-scan
description: "Security auditor for Hermes Agent configurations — scans config.yaml, .env, installed skills, MCP servers, memory files, and cron jobs for vulnerabilities, misconfigurations, and prompt injection. Compatible with Hermes Agent v0.10.0+."
version: "1.1.0"
tags: [security, audit, hermes]
---

# Hermes Security Scan

Security auditor purpose-built for Hermes Agent. Scans your `~/.hermes/` directory and reports vulnerabilities with severity grades (A–F).

## When to Use

- After installing new skills from external sources
- Before deploying Hermes to a new environment
- Periodic security hygiene check
- After changing config.yaml, .env, or MCP server settings
- When you suspect a skill might contain prompt injection

## What It Scans

| Category | What | Weight |
|----------|------|--------|
| **Secrets** | .env permissions, hardcoded API keys in config.yaml, secrets in memory/cron files | 30% |
| **Config** | Approval mode (auto/yolo = critical), command allowlist, agent limits, Tirith scanner status, gateway timeout | 25% |
| **MCP Servers** | npx -y supply chain, remote URLs, shell metacharacters, auto-approve, 0.0.0.0 binding | 20% |
| **Skills** | Prompt injection patterns (13 types), suspicious code execution, Unicode zero-width chars | 15% |
| **Privacy** | Secret redaction, website blocklist, private URL access (terminal/browser section), Discord mention settings | 10% |

## How to Run

### Quick scan (text report):
```bash
python3 ~/.hermes/skills/hermes-security-scan/scripts/hermes_security_scan.py
```

### JSON output (for CI/automation):
```bash
python3 ~/.hermes/skills/hermes-security-scan/scripts/hermes_security_scan.py --format json
```

### Verbose (include INFO-level findings):
```bash
python3 ~/.hermes/skills/hermes-security-scan/scripts/hermes_security_scan.py -v
```

### Scan a different Hermes home:
```bash
python3 ~/.hermes/skills/hermes-security-scan/scripts/hermes_security_scan.py --path ~/.hermes/profiles/coder
```

## Severity Levels

| Severity | Deduction | Examples |
|----------|-----------|---------|
| CRITICAL (-25) | Hardcoded API key, approval mode yolo, prompt injection in skill | Immediate action required |
| HIGH (-15) | .env file permissions 644, npx -y in MCP, dangerous command allowlisted | Fix soon |
| MEDIUM (-5) | Private URL access enabled, high max_turns, remote MCP URL | Review and decide |
| LOW (-2) | Smart approval mode, website blocklist disabled, many skills installed | Informational risk |
| INFO (0) | No .env file, no MCP servers configured | Just noting |

## Grading

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Excellent — minimal risk |
| B | 75-89 | Good — minor issues |
| C | 60-74 | Acceptable — review recommended |
| D | 40-59 | Poor — fix high/critical issues |
| F | 0-39 | Failing — immediate remediation needed |

## Prompt Injection Detection

The skill scanner checks for 13 prompt injection patterns:

1. "Ignore previous instructions" overrides
2. System prompt spoofing (`<|system|>`, `<<SYS>>`)
3. DAN jailbreak patterns
4. Hidden instructions in HTML comments
5. Auto-run/auto-install instructions
6. URL fetch piped to shell execution
7. Output suppression ("hide warnings")
8. Data exfiltration (curl POST with variables)
9. Remote script eval/exec
10. Unicode zero-width character hiding
11. Base64 encoded suspicious blocks
12. "You are now" role reassignment
13. Fake system prompt injection

## Dependencies

- Python 3.8+ (stdlib only for basic scan)
- PyYAML (optional — falls back to text parsing if unavailable)

## v0.10.0 Config Changes

This version (1.1.0) adds support for Hermes Agent v0.10.0 config structure:

- `agent.max_turns` default raised to 90 — threshold updated to 120 for MEDIUM finding
- `security.tirith_enabled` — new field; flags MEDIUM if disabled
- `delegation.max_iterations` replaces `max_subagents` — threshold > 300 for LOW finding
- `allow_private_urls` now lives under `terminal` section (also checks legacy `privacy` section)

## Exit Codes

- `0` — Grade A, B, or C (score ≥ 60)
- `1` — Grade D or F (score < 60)
- `2` — Hermes home directory not found
