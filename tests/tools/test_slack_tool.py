"""Tests for tools/slack_tool.py — the on-demand ``slack_thread_file`` tool (#134486)."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from tools import slack_tool

FILE_ID = "F0BKY3BG6F4"
THREAD = "1792127508.299579"


@pytest.fixture
def slack_session(monkeypatch):
    monkeypatch.setenv("HERMES_SESSION_PLATFORM", "slack")
    monkeypatch.setenv("HERMES_SESSION_CHAT_ID", "C1")
    monkeypatch.setenv("HERMES_SESSION_THREAD_ID", THREAD)


@pytest.fixture
def fake_adapter(monkeypatch):
    adapter = MagicMock()
    adapter.fetch_thread_file = AsyncMock(return_value={
        "success": True, "file_id": FILE_ID, "name": "plan.pdf", "mimetype": "application/pdf",
        "size": 2048, "kind": "document", "path": "/gw/home/cache/documents/doc_plan.pdf",
        "posted_by": "U_ALLOWED", "message_ts": "1792127600.000100",
    })
    monkeypatch.setattr(slack_tool, "_live_slack_adapter", lambda: (None, adapter))
    return adapter


def _call(args, **kw):
    return json.loads(asyncio.run(slack_tool.slack_thread_file(args, **kw)))


def test_fetches_with_session_channel_and_thread_not_model_input(slack_session, fake_adapter, monkeypatch):
    monkeypatch.setattr("tools.credential_files.to_agent_visible_cache_path", lambda p, *a, **k: p)

    out = _call({"file_id": FILE_ID, "channel": "C_OTHER", "thread_ts": "1.2"})

    assert out["success"] is True
    assert out["path"] == "/gw/home/cache/documents/doc_plan.pdf"
    fake_adapter.fetch_thread_file.assert_awaited_once_with("C1", THREAD, FILE_ID)


def test_path_is_translated_for_remote_backend_and_sync_is_forced(slack_session, fake_adapter, monkeypatch):
    monkeypatch.setattr(
        "tools.credential_files.to_agent_visible_cache_path",
        lambda p, *a, **k: "~/.hermes/cache/documents/doc_plan.pdf")
    env = MagicMock()
    monkeypatch.setattr("tools.terminal_tool_lifecycle.get_active_env", lambda task_id: env)

    out = _call({"file_id": FILE_ID}, task_id="t-1")

    assert out["path"] == "~/.hermes/cache/documents/doc_plan.pdf"
    env._sync_manager.sync.assert_called_once_with(force=True)


def test_missing_active_env_still_returns_visible_path(slack_session, fake_adapter, monkeypatch):
    monkeypatch.setattr(
        "tools.credential_files.to_agent_visible_cache_path",
        lambda p, *a, **k: "~/.hermes/cache/documents/doc_plan.pdf")
    monkeypatch.setattr("tools.terminal_tool_lifecycle.get_active_env", lambda task_id: None)

    out = _call({"file_id": FILE_ID})

    assert out["path"] == "~/.hermes/cache/documents/doc_plan.pdf"


@pytest.mark.parametrize("bad_id", ["", "F1", "u123", "F0BKY3BG6F4; rm -rf /", "../x"])
def test_malformed_file_id_is_rejected_before_adapter(slack_session, fake_adapter, bad_id):
    out = _call({"file_id": bad_id})

    assert "file_id must be" in out["error"]
    fake_adapter.fetch_thread_file.assert_not_awaited()


def test_non_slack_session_is_rejected(monkeypatch, fake_adapter):
    monkeypatch.setenv("HERMES_SESSION_PLATFORM", "telegram")
    monkeypatch.setenv("HERMES_SESSION_CHAT_ID", "C1")
    monkeypatch.setenv("HERMES_SESSION_THREAD_ID", THREAD)

    out = _call({"file_id": FILE_ID})

    assert "only available in a Slack conversation" in out["error"]
    fake_adapter.fetch_thread_file.assert_not_awaited()


def test_session_without_thread_is_rejected(monkeypatch, fake_adapter):
    monkeypatch.setenv("HERMES_SESSION_PLATFORM", "slack")
    monkeypatch.setenv("HERMES_SESSION_CHAT_ID", "C1")
    monkeypatch.delenv("HERMES_SESSION_THREAD_ID", raising=False)

    out = _call({"file_id": FILE_ID})

    assert "inside a Slack thread" in out["error"]
    fake_adapter.fetch_thread_file.assert_not_awaited()


def test_adapter_refusal_is_returned_as_tool_error(slack_session, fake_adapter):
    fake_adapter.fetch_thread_file.return_value = {"error": "File F0BKY3BG6F4 is not attached to any message in this thread."}

    out = _call({"file_id": FILE_ID})

    assert "not attached" in out["error"]
    assert "path" not in out


def test_no_live_adapter(slack_session, monkeypatch):
    monkeypatch.setattr(slack_tool, "_live_slack_adapter", lambda: (None, None))

    out = _call({"file_id": FILE_ID})

    assert "not connected" in out["error"]


def test_registered_in_slack_toolset_and_slack_bundle_only():
    from tools.registry import registry
    from toolsets import resolve_toolset

    entry = registry.get_entry("slack_thread_file")
    assert entry is not None and entry.toolset == "slack" and entry.is_async
    assert "slack_thread_file" in resolve_toolset("hermes-slack")
    assert "slack_thread_file" not in resolve_toolset("hermes-cli")
    assert "slack_thread_file" not in resolve_toolset("hermes-telegram")


def test_explicit_slack_platform_toolsets_still_get_the_slack_toolset():
    """A saved ``platform_toolsets.slack`` list (no ``slack`` entry) recovers the platform-native
    toolset, so existing deployments get the tool without a config edit."""
    from hermes_cli.tools_config import _get_platform_tools

    cfg = {"platform_toolsets": {"slack": ["terminal", "file", "web", "vision", "skills"]}}
    assert "slack" in _get_platform_tools(cfg, "slack")
    assert "slack" not in _get_platform_tools(cfg, "cli")


def test_check_fn_tracks_slack_session(monkeypatch):
    monkeypatch.setattr(slack_tool, "_live_slack_adapter", lambda: (None, None))
    monkeypatch.setenv("HERMES_SESSION_PLATFORM", "slack")
    assert slack_tool.check_slack_thread_file_requirements() is True
    monkeypatch.setenv("HERMES_SESSION_PLATFORM", "cli")
    assert slack_tool.check_slack_thread_file_requirements() is False
