"""Tests for Zalo Bot platform adapter."""
import asyncio

import httpx
import pytest

from gateway.config import PlatformConfig


class TestZaloRequirements:
    def test_false_without_httpx(self, monkeypatch):
        monkeypatch.setattr("gateway.platforms.zalo.HTTPX_AVAILABLE", False)
        from gateway.platforms.zalo import check_zalo_requirements

        assert check_zalo_requirements() is False

    def test_false_without_token(self, monkeypatch):
        monkeypatch.setattr("gateway.platforms.zalo.HTTPX_AVAILABLE", True)
        monkeypatch.delenv("ZALO_BOT_TOKEN", raising=False)
        from gateway.platforms.zalo import check_zalo_requirements

        assert check_zalo_requirements() is False

    def test_true_when_configured(self, monkeypatch):
        monkeypatch.setattr("gateway.platforms.zalo.HTTPX_AVAILABLE", True)
        monkeypatch.setenv("ZALO_BOT_TOKEN", "tok")
        from gateway.platforms.zalo import check_zalo_requirements

        assert check_zalo_requirements() is True


class TestZaloAdapterInit:
    def test_reads_token_from_config(self, monkeypatch):
        monkeypatch.setenv("ZALO_BOT_TOKEN", "envtok")
        from gateway.platforms.zalo import ZaloBotAdapter

        cfg = PlatformConfig(enabled=True, token="cfgtok")
        ad = ZaloBotAdapter(cfg)
        assert ad._token == "cfgtok"

    def test_falls_back_to_env(self, monkeypatch):
        monkeypatch.setenv("ZALO_BOT_TOKEN", "envtok")
        from gateway.platforms.zalo import ZaloBotAdapter

        ad = ZaloBotAdapter(PlatformConfig(enabled=True))
        assert ad._token == "envtok"


class TestZaloDispatch:
    @pytest.mark.asyncio
    async def test_dispatches_text_message(self, monkeypatch):
        from gateway.platforms.zalo import ZaloBotAdapter

        cfg = PlatformConfig(enabled=True, token="t")
        ad = ZaloBotAdapter(cfg)
        seen = []

        async def capture(ev):
            seen.append(ev)
            return None

        ad.set_message_handler(capture)
        item = {
            "event_name": "message.text.received",
            "message": {
                "message_id": "mid1",
                "text": "hello",
                "from": {"id": "u1", "display_name": "U1", "is_bot": False},
                "chat": {"id": "c1", "chat_type": "PRIVATE"},
                "date": 1_700_000_000_000,
            },
        }
        await ad._dispatch_update(item)
        await asyncio.sleep(0.05)
        assert len(seen) == 1
        assert seen[0].text == "hello"
        assert seen[0].source.user_id == "u1"
        assert seen[0].source.chat_id == "c1"

    @pytest.mark.asyncio
    async def test_skips_bot_messages(self, monkeypatch):
        from gateway.platforms.zalo import ZaloBotAdapter

        ad = ZaloBotAdapter(PlatformConfig(enabled=True, token="t"))
        seen = []

        async def capture(ev):
            seen.append(ev)
            return None

        ad.set_message_handler(capture)
        item = {
            "event_name": "message.text.received",
            "message": {
                "text": "x",
                "from": {"id": "b1", "is_bot": True},
                "chat": {"id": "c1"},
            },
        }
        await ad._dispatch_update(item)
        await asyncio.sleep(0.05)
        assert seen == []


class TestSendMessageZaloRouting:
    @pytest.mark.asyncio
    async def test_send_zalo_success(self, monkeypatch):
        import tools.send_message_tool as sm

        class FakeResp:
            status_code = 200
            text = ""

            def json(self):
                return {"ok": True, "result": {"message_id": "m1"}}

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def post(self, url, json=None):
                assert "sendMessage" in url
                assert json["chat_id"] == "chat1"
                return FakeResp()

        monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: FakeClient())
        out = await sm._send_zalo("tok", "chat1", "hi")
        assert out["success"] is True
        assert out["platform"] == "zalo"
