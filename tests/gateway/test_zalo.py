"""Tests for Zalo Bot platform adapter."""
import asyncio

import httpx
import pytest

from gateway.config import PlatformConfig
from gateway.platforms.base import MessageType


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

    def test_webhook_mode_reads_extra(self):
        from gateway.platforms.zalo import ZaloBotAdapter

        cfg = PlatformConfig(
            enabled=True,
            token="t",
            extra={
                "connection_mode": "webhook",
                "webhook_public_url": "https://example.com/hook",
                "webhook_secret": "12345678",
                "webhook_port": 9001,
            },
        )
        ad = ZaloBotAdapter(cfg)
        assert ad._connection_mode == "webhook"
        assert ad._webhook_public_url == "https://example.com/hook"
        assert ad._webhook_secret == "12345678"
        assert ad._webhook_port == 9001
        assert ad._webhook_path == "/hook"


class TestParseWebhookPath:
    def test_uses_path_from_public_url(self):
        from gateway.platforms.zalo import _parse_webhook_path

        assert _parse_webhook_path("https://ex.com/api/zalo", None) == "/api/zalo"

    def test_default_path_when_root_url(self):
        from gateway.platforms.zalo import _parse_webhook_path

        assert _parse_webhook_path("https://ex.com", None) == "/zalo/webhook"

    def test_path_override(self):
        from gateway.platforms.zalo import _parse_webhook_path

        assert _parse_webhook_path("https://ex.com", "/custom") == "/custom"


class TestPollBackoff:
    def test_backoff_in_expected_range(self):
        from gateway.platforms.zalo import ZaloBotAdapter, _POLL_BACKOFF_SEC

        ad = ZaloBotAdapter(PlatformConfig(enabled=True, token="t"))
        for idx in range(len(_POLL_BACKOFF_SEC) + 2):
            delay = ad._poll_backoff_sleep(idx)
            cap = _POLL_BACKOFF_SEC[min(idx, len(_POLL_BACKOFF_SEC) - 1)]
            assert delay >= cap
            assert delay <= cap * 1.26


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

    @pytest.mark.asyncio
    async def test_dispatches_image_message(self, monkeypatch):
        from gateway.platforms.zalo import ZaloBotAdapter

        async def fake_cache(url: str, ext: str = ".jpg"):
            assert url.startswith("https://")
            return "/cached/img.jpg"

        monkeypatch.setattr("gateway.platforms.zalo.cache_image_from_url", fake_cache)

        ad = ZaloBotAdapter(PlatformConfig(enabled=True, token="t"))
        seen = []

        async def capture(ev):
            seen.append(ev)
            return None

        ad.set_message_handler(capture)
        item = {
            "event_name": "message.image.received",
            "message": {
                "message_id": "img1",
                "photo": "https://cdn.example/photo.jpg",
                "caption": "hi",
                "from": {"id": "u1", "display_name": "U1", "is_bot": False},
                "chat": {"id": "c1", "chat_type": "PRIVATE"},
                "date": 1_700_000_000_000,
            },
        }
        await ad._dispatch_update(item)
        await asyncio.sleep(0.05)
        assert len(seen) == 1
        assert seen[0].message_type == MessageType.PHOTO
        assert "hi" in seen[0].text
        assert seen[0].media_urls == ["/cached/img.jpg"]

    @pytest.mark.asyncio
    async def test_dispatches_sticker_message(self, monkeypatch):
        from gateway.platforms.zalo import ZaloBotAdapter

        ad = ZaloBotAdapter(PlatformConfig(enabled=True, token="t"))
        seen = []

        async def capture(ev):
            seen.append(ev)
            return None

        ad.set_message_handler(capture)
        item = {
            "event_name": "message.sticker.received",
            "message": {
                "message_id": "st1",
                "sticker": "sticker-id-xyz",
                "from": {"id": "u1", "display_name": "U1", "is_bot": False},
                "chat": {"id": "c1"},
                "date": 1_700_000_000_000,
            },
        }
        await ad._dispatch_update(item)
        await asyncio.sleep(0.05)
        assert len(seen) == 1
        assert seen[0].message_type == MessageType.STICKER
        assert "sticker-id-xyz" in seen[0].text


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


class TestZaloSendPhoto:
    @pytest.mark.asyncio
    async def test_send_image_posts_sendphoto(self, monkeypatch):
        from gateway.platforms.zalo import ZaloBotAdapter

        class FakeResp:
            def json(self):
                return {"ok": True, "result": {"message_id": "p1"}}

        posts = []

        class FakeClient:
            async def post(self, url, json=None):
                posts.append((url, json))
                return FakeResp()

            async def aclose(self):
                pass

        ad = ZaloBotAdapter(PlatformConfig(enabled=True, token="tok"))
        ad._http_client = FakeClient()  # type: ignore[assignment]

        r = await ad.send_image("c1", "https://img.example/x.png", caption="cap")
        assert r.success
        assert any("sendPhoto" in u for u, _ in posts)
        payload = next(j for u, j in posts if "sendPhoto" in u)
        assert payload["chat_id"] == "c1"
        assert payload["photo"] == "https://img.example/x.png"
        assert payload["caption"] == "cap"
