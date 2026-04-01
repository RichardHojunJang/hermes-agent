"""
Zalo Bot Platform adapter — long polling (getUpdates) or webhook.

Uses the Zalo Bot HTTP API — not Zalo Official Account (OA).
See https://bot.zapps.me/docs/

Requires:
    pip install httpx
    ZALO_BOT_TOKEN in ~/.hermes/.env (from Zalo Bot Creator)

Modes:
    - polling (default): getUpdates long polling. Does not work if a webhook is
      already set — call deleteWebhook first (Zalo docs).
    - webhook: local aiohttp server + setWebhook with a public HTTPS URL.
      Requires aiohttp, ZALO_WEBHOOK_PUBLIC_URL (https), ZALO_WEBHOOK_SECRET (8–256 chars).

API base: https://bot-api.zaloplatforms.com/bot<BOT_TOKEN>/<method>
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import urlparse

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    httpx = None  # type: ignore[assignment]

try:
    from aiohttp import web

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None  # type: ignore[assignment]

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
    cache_image_from_url,
)

logger = logging.getLogger(__name__)

# https://bot.zapps.me/docs/apis/sendMessage/
MAX_MESSAGE_LENGTH = 2000

ZALO_API_BASE = "https://bot-api.zaloplatforms.com/bot"

DEDUP_WINDOW_SECONDS = 300
DEDUP_MAX_SIZE = 1000

# Backoff after transport/API errors (seconds). Reset on successful poll cycle.
_POLL_BACKOFF_SEC = (1, 2, 4, 8, 16, 30, 45, 60, 90, 120)
_MAX_BACKOFF_JITTER_RATIO = 0.25


def _api_url(token: str, method: str) -> str:
    return f"{ZALO_API_BASE}{token}/{method}"


def check_zalo_requirements() -> bool:
    """Return True if httpx is available and ZALO_BOT_TOKEN is set."""
    if not HTTPX_AVAILABLE:
        return False
    return bool(os.getenv("ZALO_BOT_TOKEN", "").strip())


def _iter_updates(result: Any) -> Iterator[Dict[str, Any]]:
    """Normalize getUpdates `result` into per-update dicts."""
    if result is None:
        return
    if isinstance(result, list):
        for item in result:
            if isinstance(item, dict):
                yield item
    elif isinstance(result, dict):
        if "event_name" in result or "message" in result:
            yield result


def _parse_webhook_path(public_url: str, path_override: Optional[str]) -> str:
    if path_override and path_override.strip():
        p = path_override.strip()
        return p if p.startswith("/") else f"/{p}"
    parsed = urlparse(public_url)
    path = parsed.path or "/"
    if path == "/":
        return "/zalo/webhook"
    return path


class ZaloBotAdapter(BasePlatformAdapter):
    """Zalo Bot Platform — polling or webhook; text, images, stickers."""

    MAX_MESSAGE_LENGTH = MAX_MESSAGE_LENGTH

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.ZALO)
        extra = config.extra or {}
        self._token: str = (config.token or extra.get("bot_token") or os.getenv("ZALO_BOT_TOKEN", "")).strip()
        self._http_client: Optional["httpx.AsyncClient"] = None
        self._poll_task: Optional[asyncio.Task] = None
        self._seen_messages: Dict[str, float] = {}

        self._connection_mode: str = (
            str(extra.get("connection_mode") or os.getenv("ZALO_CONNECTION_MODE", "polling") or "polling")
        ).lower()
        if self._connection_mode not in ("polling", "webhook"):
            self._connection_mode = "polling"

        self._webhook_public_url: str = str(
            extra.get("webhook_public_url") or os.getenv("ZALO_WEBHOOK_PUBLIC_URL", "") or ""
        ).strip()
        self._webhook_secret: str = str(
            extra.get("webhook_secret") or os.getenv("ZALO_WEBHOOK_SECRET", "") or ""
        ).strip()
        self._webhook_host: str = str(
            extra.get("webhook_host") or os.getenv("ZALO_WEBHOOK_HOST", "0.0.0.0") or "0.0.0.0"
        )
        self._webhook_port: int = int(extra.get("webhook_port") or os.getenv("ZALO_WEBHOOK_PORT", "8790") or 8790)
        path_ov = extra.get("webhook_path") or os.getenv("ZALO_WEBHOOK_PATH")
        self._webhook_path: str = _parse_webhook_path(self._webhook_public_url, path_ov if path_ov else None)

        self._webhook_runner: Any = None
        self._webhook_site: Any = None
        self._webhook_registered: bool = False
        self._delete_webhook_on_disconnect: bool = False

    async def connect(self) -> bool:
        if not HTTPX_AVAILABLE:
            logger.warning("[%s] httpx not installed. Run: pip install httpx", self.name)
            return False
        if not self._token:
            logger.warning("[%s] ZALO_BOT_TOKEN is not set", self.name)
            return False

        try:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(65.0, connect=15.0),
                headers={"User-Agent": "HermesAgent/1.0 (Zalo Bot)"},
            )
        except Exception as e:
            logger.error("[%s] Failed to create HTTP client: %s", self.name, e)
            return False

        if self._connection_mode == "webhook":
            return await self._connect_webhook()
        return await self._connect_polling()

    async def _connect_polling(self) -> bool:
        self._poll_task = asyncio.create_task(self._poll_loop())
        self._mark_connected()
        logger.info("[%s] Long polling started (getUpdates)", self.name)
        return True

    async def _connect_webhook(self) -> bool:
        if not AIOHTTP_AVAILABLE or web is None:
            logger.warning("[%s] Webhook mode requires aiohttp. Run: pip install aiohttp", self.name)
            await self._http_client.aclose()
            self._http_client = None
            return False
        if not self._webhook_public_url.startswith("https://"):
            logger.error(
                "[%s] ZALO_WEBHOOK_PUBLIC_URL must be an https:// URL (Zalo requirement)",
                self.name,
            )
            await self._http_client.aclose()
            self._http_client = None
            return False
        slen = len(self._webhook_secret)
        if slen < 8 or slen > 256:
            logger.error(
                "[%s] ZALO_WEBHOOK_SECRET must be 8–256 characters (see setWebhook docs)",
                self.name,
            )
            await self._http_client.aclose()
            self._http_client = None
            return False

        app = web.Application()
        app.router.add_post(self._webhook_path, self._handle_webhook_post)

        self._webhook_runner = web.AppRunner(app)
        await self._webhook_runner.setup()
        self._webhook_site = web.TCPSite(self._webhook_runner, self._webhook_host, self._webhook_port)
        try:
            await self._webhook_site.start()
        except OSError as e:
            logger.error("[%s] Webhook bind failed %s:%s: %s", self.name, self._webhook_host, self._webhook_port, e)
            await self._webhook_runner.cleanup()
            self._webhook_runner = None
            self._webhook_site = None
            await self._http_client.aclose()
            self._http_client = None
            return False

        sw_url = _api_url(self._token, "setWebhook")
        try:
            resp = await self._http_client.post(
                sw_url,
                json={"url": self._webhook_public_url, "secret_token": self._webhook_secret},
            )
            body = resp.json() if resp.content else {}
            if not body.get("ok"):
                logger.error(
                    "[%s] setWebhook failed: %s",
                    self.name,
                    str(body.get("description") or body.get("error_code") or resp.text)[:300],
                )
                await self._disconnect_webhook_server()
                await self._http_client.aclose()
                self._http_client = None
                return False
        except Exception as e:
            logger.error("[%s] setWebhook request failed: %s", self.name, e)
            await self._disconnect_webhook_server()
            await self._http_client.aclose()
            self._http_client = None
            return False

        self._webhook_registered = True
        self._delete_webhook_on_disconnect = True
        self._mark_connected()
        logger.info(
            "[%s] Webhook listening on http://%s:%s%s (public URL registered with Zalo)",
            self.name,
            self._webhook_host,
            self._webhook_port,
            self._webhook_path,
        )
        return True

    async def _handle_webhook_post(self, request: "web.Request") -> "web.StreamResponse":
        token_hdr = request.headers.get("X-Bot-Api-Secret-Token", "")
        if token_hdr != self._webhook_secret:
            logger.warning("[%s] Webhook rejected: bad secret token", self.name)
            return web.Response(status=403, text="Forbidden")

        try:
            data = await request.json()
        except Exception:
            return web.Response(status=400, text="Bad JSON")

        if not isinstance(data, dict):
            return web.Response(text="ok")

        if not data.get("ok", True):
            return web.Response(text="ok")

        result = data.get("result")
        if isinstance(result, dict) and (result.get("event_name") or result.get("message")):
            await self._dispatch_update(result)
        return web.Response(text="ok")

    async def _disconnect_webhook_server(self) -> None:
        if self._webhook_site:
            await self._webhook_site.stop()
            self._webhook_site = None
        if self._webhook_runner:
            await self._webhook_runner.cleanup()
            self._webhook_runner = None

    async def disconnect(self) -> None:
        self._running = False
        self._mark_disconnected()

        if self._connection_mode == "webhook" and self._delete_webhook_on_disconnect and self._http_client:
            try:
                dw = _api_url(self._token, "deleteWebhook")
                await self._http_client.post(dw)
                logger.info("[%s] deleteWebhook called", self.name)
            except Exception as e:
                logger.warning("[%s] deleteWebhook failed (non-fatal): %s", self.name, e)
        self._webhook_registered = False
        self._delete_webhook_on_disconnect = False

        await self._disconnect_webhook_server()

        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            self._poll_task = None
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
        self._seen_messages.clear()
        logger.info("[%s] Disconnected", self.name)

    def _poll_backoff_sleep(self, backoff_idx: int) -> float:
        cap = _POLL_BACKOFF_SEC[min(backoff_idx, len(_POLL_BACKOFF_SEC) - 1)]
        jitter = cap * _MAX_BACKOFF_JITTER_RATIO * random.random()
        return cap + jitter

    async def _poll_loop(self) -> None:
        assert self._http_client is not None
        url = _api_url(self._token, "getUpdates")
        backoff_idx = 0
        while self._running:
            try:
                resp = await self._http_client.post(
                    url,
                    json={"timeout": "30"},
                )
                if resp.status_code != 200:
                    logger.warning(
                        "[%s] getUpdates HTTP %s: %s",
                        self.name,
                        resp.status_code,
                        (resp.text or "")[:200],
                    )
                    await asyncio.sleep(self._poll_backoff_sleep(backoff_idx))
                    backoff_idx = min(backoff_idx + 1, len(_POLL_BACKOFF_SEC) - 1)
                    continue

                data = resp.json()
                if not data.get("ok"):
                    desc = str(data.get("description") or data.get("error_code") or "unknown")
                    logger.warning("[%s] getUpdates error: %s", self.name, desc)
                    if "webhook" in desc.lower():
                        logger.warning(
                            "[%s] Webhook may be active — deleteWebhook before getUpdates, "
                            "or switch to connection_mode webhook in config.",
                            self.name,
                        )
                    await asyncio.sleep(self._poll_backoff_sleep(backoff_idx))
                    backoff_idx = min(backoff_idx + 1, len(_POLL_BACKOFF_SEC) - 1)
                    continue

                backoff_idx = 0
                for item in _iter_updates(data.get("result")):
                    await self._dispatch_update(item)

            except asyncio.CancelledError:
                break
            except Exception as e:
                if not self._running:
                    break
                logger.warning("[%s] Poll error: %s", self.name, e)
                await asyncio.sleep(self._poll_backoff_sleep(backoff_idx))
                backoff_idx = min(backoff_idx + 1, len(_POLL_BACKOFF_SEC) - 1)

    def _base_source_and_meta(
        self, msg: Dict[str, Any]
    ) -> Optional[tuple]:
        from_o = msg.get("from") or {}
        if from_o.get("is_bot"):
            return None

        msg_id = str(msg.get("message_id") or "")
        if msg_id and self._is_duplicate(msg_id):
            return None

        chat = msg.get("chat") or {}
        chat_id = str(chat.get("id") or "")
        if not chat_id:
            return None

        chat_type_raw = str(chat.get("chat_type") or "PRIVATE").upper()
        chat_type = "dm" if chat_type_raw == "PRIVATE" else "group"

        user_id = str(from_o.get("id") or "")
        user_name = (from_o.get("display_name") or user_id or "user").strip()

        date_ms = msg.get("date")
        try:
            if date_ms is not None:
                ts = datetime.fromtimestamp(float(date_ms) / 1000.0, tz=timezone.utc)
            else:
                ts = datetime.now(tz=timezone.utc)
        except (TypeError, ValueError, OSError):
            ts = datetime.now(tz=timezone.utc)

        source = self.build_source(
            chat_id=chat_id,
            chat_name=user_name if chat_type == "dm" else None,
            chat_type=chat_type,
            user_id=user_id,
            user_name=user_name,
        )
        return source, ts, msg_id

    async def _dispatch_update(self, item: Dict[str, Any]) -> None:
        event_name = item.get("event_name")
        msg = item.get("message") or {}

        if event_name == "message.unsupported.received":
            logger.debug("[%s] Unsupported message event (policy or type)", self.name)
            return

        meta = self._base_source_and_meta(msg)
        if meta is None:
            return
        source, ts, msg_id = meta

        if event_name == "message.text.received":
            text = (msg.get("text") or "").strip()
            if not text:
                return
            event = MessageEvent(
                text=text,
                message_type=MessageType.TEXT,
                source=source,
                message_id=msg_id or None,
                raw_message=item,
                timestamp=ts,
            )
            await self.handle_message(event)
            return

        if event_name == "message.image.received":
            photo_url = (msg.get("photo") or "").strip()
            caption = (msg.get("caption") or "").strip()
            text = caption or "[Photo]"
            media_urls: List[str] = []
            if photo_url:
                try:
                    media_urls.append(await cache_image_from_url(photo_url))
                except Exception as e:
                    logger.warning("[%s] Image cache failed: %s", self.name, e)
                    text = f"{text}\n{photo_url}".strip()
            event = MessageEvent(
                text=text,
                message_type=MessageType.PHOTO,
                source=source,
                message_id=msg_id or None,
                raw_message=item,
                timestamp=ts,
                media_urls=media_urls,
                media_types=["image"] * len(media_urls),
            )
            await self.handle_message(event)
            return

        if event_name == "message.sticker.received":
            sticker_id = (msg.get("sticker") or "").strip()
            sticker_url = (msg.get("url") or "").strip()
            parts = [p for p in (sticker_id, sticker_url) if p]
            text = f"[Sticker] {' | '.join(parts)}" if parts else "[Sticker]"
            event = MessageEvent(
                text=text,
                message_type=MessageType.STICKER,
                source=source,
                message_id=msg_id or None,
                raw_message=item,
                timestamp=ts,
            )
            await self.handle_message(event)
            return

    def _is_duplicate(self, msg_id: str) -> bool:
        now = time.time()
        if len(self._seen_messages) > DEDUP_MAX_SIZE:
            cutoff = now - DEDUP_WINDOW_SECONDS
            self._seen_messages = {k: v for k, v in self._seen_messages.items() if v > cutoff}
        if msg_id in self._seen_messages:
            return True
        self._seen_messages[msg_id] = now
        return False

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        _ = reply_to, metadata
        if not self._http_client:
            return SendResult(success=False, error="HTTP client not initialized")
        formatted = self.format_message(content)
        chunks = self.truncate_message(formatted, self.MAX_MESSAGE_LENGTH)
        url = _api_url(self._token, "sendMessage")
        last_mid: Optional[str] = None
        try:
            for chunk in chunks:
                resp = await self._http_client.post(
                    url,
                    json={"chat_id": str(chat_id), "text": chunk},
                )
                try:
                    body: Dict[str, Any] = resp.json()
                except Exception:
                    return SendResult(
                        success=False,
                        error=f"Invalid JSON from Zalo API (HTTP {resp.status_code})",
                    )
                if not body.get("ok"):
                    err = str(body.get("description") or body.get("error_code") or resp.text)[:500]
                    return SendResult(success=False, error=err)
                res = body.get("result") or {}
                if isinstance(res, dict):
                    last_mid = str(res.get("message_id") or last_mid or "")
            return SendResult(success=True, message_id=last_mid)
        except httpx.TimeoutException:
            return SendResult(success=False, error="Timeout sending to Zalo", retryable=True)
        except Exception as e:
            logger.error("[%s] send error: %s", self.name, e)
            return SendResult(success=False, error=str(e))

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        _ = metadata
        if not self._http_client:
            return
        try:
            url = _api_url(self._token, "sendChatAction")
            await self._http_client.post(
                url,
                json={"chat_id": str(chat_id), "action": "typing"},
            )
        except Exception as e:
            logger.debug("[%s] sendChatAction failed: %s", self.name, e)

    async def send_image(
        self,
        chat_id: str,
        image_url: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        _ = reply_to, metadata
        if not image_url:
            return SendResult(success=False, error="No image URL")
        if not self._http_client:
            return SendResult(success=False, error="HTTP client not initialized")
        url = _api_url(self._token, "sendPhoto")
        payload: Dict[str, Any] = {"chat_id": str(chat_id), "photo": image_url}
        cap = (caption or "").strip()
        if cap:
            payload["caption"] = cap[:MAX_MESSAGE_LENGTH]
        try:
            resp = await self._http_client.post(url, json=payload)
            try:
                body: Dict[str, Any] = resp.json()
            except Exception:
                return SendResult(success=False, error=f"Invalid JSON (HTTP {resp.status_code})")
            if not body.get("ok"):
                err = str(body.get("description") or body.get("error_code") or resp.text)[:500]
                return SendResult(success=False, error=err)
            res = body.get("result") or {}
            mid = str(res.get("message_id") or "") if isinstance(res, dict) else None
            return SendResult(success=True, message_id=mid)
        except httpx.TimeoutException:
            return SendResult(success=False, error="Timeout sendPhoto", retryable=True)
        except Exception as e:
            logger.error("[%s] sendPhoto error: %s", self.name, e)
            return SendResult(success=False, error=str(e))

    async def send_animation(
        self,
        chat_id: str,
        animation_url: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send a sticker via sendSticker (animation_url = Zalo sticker id from stickers.zaloapp.com)."""
        _ = reply_to, metadata
        sticker = (animation_url or "").strip()
        if not sticker:
            return SendResult(success=False, error="No sticker id")
        if not self._http_client:
            return SendResult(success=False, error="HTTP client not initialized")
        url = _api_url(self._token, "sendSticker")
        try:
            resp = await self._http_client.post(
                url,
                json={"chat_id": str(chat_id), "sticker": sticker},
            )
            try:
                body: Dict[str, Any] = resp.json()
            except Exception:
                return SendResult(success=False, error=f"Invalid JSON (HTTP {resp.status_code})")
            if not body.get("ok"):
                err = str(body.get("description") or body.get("error_code") or resp.text)[:500]
                return SendResult(success=False, error=err)
            res = body.get("result") or {}
            mid = str(res.get("message_id") or "") if isinstance(res, dict) else None
            return SendResult(success=True, message_id=mid)
        except Exception as e:
            logger.error("[%s] sendSticker error: %s", self.name, e)
            return SendResult(success=False, error=str(e))

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {"name": chat_id, "type": "dm", "chat_id": chat_id}
