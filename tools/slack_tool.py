"""Slack thread tools: fetch a file attached earlier in the current Slack thread, on demand.

When the bot is mentioned in a thread, files on earlier messages reach the agent only as text markers
(``[file: report.pdf (application/pdf), file_id=F…]``); downloading every earlier attachment up front
would spend bandwidth, vision calls, and context on files nobody asked about (#134486). This tool lets the
agent pull exactly the file it needs.

Scope is enforced by the gateway, not the model: the channel and thread always come from the bound
session, the adapter refuses a file that is not attached to a message in that thread, and only files posted
by this bot or by an allowlisted user are downloaded (see ``SlackAdapter.fetch_thread_file``). The bot token
never leaves the gateway process; the agent receives a cache path that its terminal backend can open.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from tools.registry import registry, tool_error

logger = logging.getLogger(__name__)

_FILE_ID_RE = re.compile(r"^F[A-Z0-9]{6,20}$")

SLACK_THREAD_FILE_SCHEMA = {
    "name": "slack_thread_file",
    "description": (
        "Download a file attached earlier in the current Slack thread. "
        "Thread context shows such attachments only as markers like "
        "`[file: report.pdf (application/pdf), file_id=F0123ABCDEF]` or `[image: chart.png, file_id=F…]`; "
        "their contents are not downloaded automatically. Call this only for files the user's request "
        "actually needs, one file_id per call, then open the returned `path` with your file or terminal "
        "tools (vision_analyze for images). Only files posted in this thread by allowed users or by you can "
        "be fetched; files from other threads or channels are refused. Files attached to the message that "
        "mentioned you are already delivered and do not need this tool."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "file_id": {
                "type": "string",
                "description": "The Slack file ID from the thread-context marker, e.g. F0123ABCDEF.",
            },
        },
        "required": ["file_id"],
    },
}


def _session(name: str) -> str:
    try:
        from gateway.session_context import get_session_env
        return get_session_env(name, "") or ""
    except Exception:
        return ""


def _live_slack_adapter():
    """``(runner, adapter)`` for this process's Slack gateway adapter (profile-scoped), else ``(None, None)``."""
    try:
        from gateway.config import Platform
        from tools.send_message_senders import _live_adapter
        return _live_adapter(Platform("slack"))
    except Exception:
        logger.debug("slack_thread_file: live adapter lookup failed", exc_info=True)
        return None, None


def check_slack_thread_file_requirements() -> bool:
    """Available in Slack gateway sessions (or wherever a live Slack adapter runs in-process)."""
    if _session("HERMES_SESSION_PLATFORM") == "slack":
        return True
    _, adapter = _live_slack_adapter()
    return adapter is not None


def _agent_visible_path(host_path: str, task_id: str | None) -> str:
    """Translate a gateway cache path to where the terminal backend sees it, and force a file sync for
    synced remote backends (ssh, modal, …) so the very next command can open it."""
    try:
        from tools.credential_files import to_agent_visible_cache_path
        visible = to_agent_visible_cache_path(host_path)
    except Exception:
        logger.debug("slack_thread_file: cache path translation failed", exc_info=True)
        return host_path
    if visible != host_path:
        try:
            from tools.terminal_tool_lifecycle import get_active_env
            env = get_active_env(task_id or "default")
            sync_manager = getattr(env, "_sync_manager", None)
            if sync_manager is not None:
                sync_manager.sync(force=True)
        except Exception as exc:
            # No active env yet: the backend's first command performs an initial full sync.
            logger.debug("slack_thread_file: forced sync skipped: %s", exc)
    return visible


async def slack_thread_file(args: dict[str, Any], **kw: Any) -> str:
    file_id = str((args or {}).get("file_id") or "").strip()
    if not _FILE_ID_RE.match(file_id):
        return tool_error(
            "file_id must be a Slack file ID such as F0123ABCDEF (shown as file_id=… in the thread context).")
    if _session("HERMES_SESSION_PLATFORM") != "slack":
        return tool_error("slack_thread_file is only available in a Slack conversation.")
    channel_id = _session("HERMES_SESSION_CHAT_ID")
    thread_ts = _session("HERMES_SESSION_THREAD_ID")
    if not channel_id or not thread_ts:
        return tool_error("slack_thread_file only works inside a Slack thread.")
    runner, adapter = _live_slack_adapter()
    fetch = getattr(adapter, "fetch_thread_file", None)
    if adapter is None or not callable(fetch):
        return tool_error("The Slack adapter is not connected in this process.")
    from tools.send_message_tool import _dispatch_on_gateway_loop
    try:
        result = await _dispatch_on_gateway_loop(
            runner, lambda: fetch(channel_id, thread_ts, file_id),
            "slack_thread_file: failed to schedule on gateway loop")
    except Exception as exc:
        logger.warning("slack_thread_file: fetch raised: %s", exc)
        return tool_error(f"Fetching the file failed: {type(exc).__name__}")
    if not isinstance(result, dict) or not result.get("success"):
        error = result.get("error") if isinstance(result, dict) else None
        return tool_error(error or "Fetching the file failed.")
    payload = dict(result)
    payload["path"] = _agent_visible_path(str(payload.get("path") or ""), kw.get("task_id"))
    return json.dumps(payload, ensure_ascii=False)


registry.register(
    name="slack_thread_file",
    toolset="slack",
    schema=SLACK_THREAD_FILE_SCHEMA,
    handler=slack_thread_file,
    check_fn=check_slack_thread_file_requirements,
    is_async=True,
    emoji="📎",
)
