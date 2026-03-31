"""
Zalo Bot Platform adapter (long polling via getUpdates).

Uses the Zalo Bot HTTP API — not Zalo Official Account (OA).
See https://bot.zapps.me/docs/

Requires:
    pip install httpx
    ZALO_BOT_TOKEN in ~/.hermes/.env (from Zalo Bot Creator after creating a bot)

Inbound updates use getUpdates (POST). Outbound replies use sendMessage.
If a Webhook is configured for the bot, getUpdates will not work until
deleteWebhook is called — see Zalo Bot Platform docs.

API base: https://bot-api.zaloplatforms.com/bot<BOT_TOKEN>/<method>
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, Optional

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    httpx = None  # type: ignore[assignment]

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
)

logger = logging.getLogger(__name__)

# https://bot.zapps.me/docs/apis/sendMessage/
MAX_MESSAGE_LENGTH = 2000

ZALO_API_BASE = "https://bot-api.zaloplatforms.com/bot"

DEDUP_WINDOW_SECONDS = 300
DEDUP_MAX_SIZE = 1000


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


class ZaloBotAdapter(BasePlatformAdapter):
    """Zalo Bot Platform — text messages via getUpdates long polling."""

    MAX_MESSAGE_LENGTH = MAX_MESSAGE_LENGTH

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.ZALO)
        extra = config.extra or {}
        self._token: str = (config.token or extra.get("bot_token") or os.getenv("ZALO_BOT_TOKEN", "")).strip()
        self._http_client: Optional["httpx.AsyncClient"] = None
        self._poll_task: Optional[asyncio.Task] = None
        self._seen_messages: Dict[str, float] = {}

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
            self._poll_task = asyncio.create_task(self._poll_loop())
            self._mark_connected()
            logger.info("[%s] Long polling started (getUpdates)", self.name)
            return True
        except Exception as e:
            logger.error("[%s] Failed to connect: %s", self.name, e)
            return False

    async def disconnect(self) -> None:
        self._running = False
        self._mark_disconnected()
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

    async def _poll_loop(self) -> None:
        assert self._http_client is not None
        url = _api_url(self._token, "getUpdates")
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
                    await asyncio.sleep(3)
                    continue

                data = resp.json()
                if not data.get("ok"):
                    desc = str(data.get("description") or data.get("error_code") or "unknown")
                    logger.warning("[%s] getUpdates error: %s", self.name, desc)
                    if "webhook" in desc.lower():
                        logger.warning(
                            "[%s] Webhook may be active — deleteWebhook must be used before getUpdates "
                            "(see Zalo Bot Platform docs).",
                            self.name,
                        )
                    await asyncio.sleep(2)
                    continue

                for item in _iter_updates(data.get("result")):
                    await self._dispatch_update(item)

            except asyncio.CancelledError:
                break
            except Exception as e:
                if not self._running:
                    break
                logger.warning("[%s] Poll error: %s", self.name, e)
                await asyncio.sleep(5)

    async def _dispatch_update(self, item: Dict[str, Any]) -> None:
        event_name = item.get("event_name")
        if event_name != "message.text.received":
            return

        msg = item.get("message") or {}
        from_o = msg.get("from") or {}
        if from_o.get("is_bot"):
            return

        msg_id = str(msg.get("message_id") or "")
        if msg_id and self._is_duplicate(msg_id):
            return

        text = (msg.get("text") or "").strip()
        if not text:
            return

        chat = msg.get("chat") or {}
        chat_id = str(chat.get("id") or "")
        if not chat_id:
            return

        chat_type_raw = str(chat.get("chat_type") or "PRIVATE").upper()
        chat_type = "dm" if chat_type_raw == "PRIVATE" else "group"

        user_id = str(from_o.get("id") or "")
        user_name = (from_o.get("display_name") or user_id or "user").strip()

        source = self.build_source(
            chat_id=chat_id,
            chat_name=user_name if chat_type == "dm" else None,
            chat_type=chat_type,
            user_id=user_id,
            user_name=user_name,
        )

        date_ms = msg.get("date")
        try:
            if date_ms is not None:
                ts = datetime.fromtimestamp(float(date_ms) / 1000.0, tz=timezone.utc)
            else:
                ts = datetime.now(tz=timezone.utc)
        except (TypeError, ValueError, OSError):
            ts = datetime.now(tz=timezone.utc)

        event = MessageEvent(
            text=text,
            message_type=MessageType.TEXT,
            source=source,
            message_id=msg_id or None,
            raw_message=item,
            timestamp=ts,
        )
        await self.handle_message(event)

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
        _ = chat_id, metadata

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
        line = image_url if not caption else f"{caption}\n{image_url}"
        return await self.send(chat_id, line)

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {"name": chat_id, "type": "dm", "chat_id": chat_id}
