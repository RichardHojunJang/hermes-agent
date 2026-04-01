---
sidebar_position: 11
title: "Zalo Bot"
description: "Connect Hermes Agent to Zalo Bot Platform (polling or webhook)"
---

# Zalo Bot Setup

Hermes integrates with **[Zalo Bot Platform](https://bot.zapps.me/docs/)** (the Bot Creator flow — **not** Zalo Official Account / OA APIs from [developers.zalo.me](https://developers.zalo.me/docs)). You get a **Bot Token** after creating a bot whose name starts with the `Bot` prefix.

## Modes

| Mode | When to use | Requirements |
|------|-------------|----------------|
| **Polling** (default) | Local dev, no public URL | `httpx`, `ZALO_BOT_TOKEN`. Uses [`getUpdates`](https://bot.zapps.me/docs/apis/getUpdates/) long polling. |
| **Webhook** | Production, stable HTTPS | `httpx` + **`aiohttp`**, public **`https://`** URL, webhook secret. Hermes calls [`setWebhook`](https://bot.zapps.me/docs/apis/setWebhook/) on startup and [`deleteWebhook`](https://bot.zapps.me/docs/apis/deleteWebhook/) on shutdown. |

:::warning Polling vs webhook
If a webhook is already registered for the bot, **`getUpdates` will not work** until you call `deleteWebhook` or switch to webhook mode. See the [polling build guide](https://bot.zaloplatforms.com/docs/build-your-bot/).
:::

## Prerequisites

**httpx** is a core dependency of `hermes-agent` — a normal `pip install -e .` (or `uv pip install -e .`) already includes it for Zalo **polling**.

**aiohttp** is only required for **webhook** mode. Install it explicitly or use the optional extra:

```bash
pip install "hermes-agent[zalo]"    # pulls aiohttp for Zalo webhook
# or, if you already use the messaging stack:
pip install "hermes-agent[messaging]"   # includes aiohttp (Telegram, Discord, …)
```

Hermes does **not** auto-install missing packages at runtime; if a dependency is missing, the gateway logs a warning and the Zalo adapter will not connect.

## Step 1: Create a bot

1. In the Zalo app, find **Zalo Bot Manager** (OA) and use **Create bot** / **Zalo Bot Creator**.
2. After creation, Zalo sends **`Bot Token`** to your account.
3. Restrict access in production with allowlists (see below).

## Step 2: Environment variables

Add to `~/.hermes/.env`:

```bash
# Required
ZALO_BOT_TOKEN=your-bot-token

# Security (recommended)
ZALO_ALLOWED_USERS=user-id-1,user-id-2
# Or for testing only:
# ZALO_ALLOW_ALL_USERS=true

# Optional: default target for cron / send_message without explicit chat
# ZALO_HOME_CHANNEL=chat-id
```

### Polling (default)

No extra variables. Optionally set:

```bash
# ZALO_CONNECTION_MODE=polling   # default if omitted
```

### Webhook

You need a **public HTTPS URL** that reaches the machine running the gateway (reverse proxy, tunnel, load balancer).

```bash
ZALO_CONNECTION_MODE=webhook
ZALO_WEBHOOK_PUBLIC_URL=https://your-domain.com/zalo/webhook
ZALO_WEBHOOK_SECRET=your-secret-at-least-8-chars
```

Hermes listens locally on **`ZALO_WEBHOOK_HOST`** (default `0.0.0.0`) and **`ZALO_WEBHOOK_PORT`** (default `8790`). The HTTP path defaults to the path component of `ZALO_WEBHOOK_PUBLIC_URL`, or `/zalo/webhook` if the URL has no path. Override with **`ZALO_WEBHOOK_PATH`** if your proxy strips or rewrites paths.

Zalo sends header **`X-Bot-Api-Secret-Token`** on each POST; it must match `ZALO_WEBHOOK_SECRET` ([webhook docs](https://bot.zapps.me/docs/webhook/)).

## Step 3: Start the gateway

```bash
hermes gateway run
```

Use the same Python environment as the rest of Hermes (venv / `uv run`) so `httpx` (and `aiohttp` for webhook) are installed.

## Media and replies

- **Inbound:** Text, images (`message.image.received`), and stickers are turned into agent messages. Images are cached locally for vision tools when download succeeds.
- **Outbound text:** [`sendMessage`](https://bot.zapps.me/docs/apis/sendMessage/) (~2000 characters per segment; Hermes chunks long replies).
- **Outbound images:** [`sendPhoto`](https://bot.zapps.me/docs/apis/sendPhoto/) with an **HTTPS URL** for the image.
- **Typing:** [`sendChatAction`](https://bot.zapps.me/docs/apis/sendChatAction/) with action `typing`.
- **Stickers:** [`sendSticker`](https://bot.zapps.me/docs/apis/sendSticker/) — sticker identifiers from [Zalo stickers](https://stickers.zaloapp.com/).

## config.yaml (optional)

You can set the same options under `platforms.zalo.extra` instead of env vars, for example:

```yaml
platforms:
  zalo:
    enabled: true
    token: "${ZALO_BOT_TOKEN}"   # or inline token (not recommended)
    extra:
      connection_mode: webhook
      webhook_public_url: https://example.com/zalo/webhook
      webhook_secret: your-secret
      webhook_port: 8790
```

Environment variables still override or merge per `gateway` config loading rules.

## Troubleshooting

| Issue | What to check |
|-------|----------------|
| `ModuleNotFoundError: yaml` or missing `httpx` | Run Hermes from the project venv / `uv run`. |
| Polling never receives messages | Webhook may be active — delete it or use webhook mode. |
| `setWebhook` fails | URL must be `https://`; secret length 8–256 characters. |
| Webhook 403 | `X-Bot-Api-Secret-Token` mismatch; proxy must forward headers. |
| Long polling errors after network blips | Hermes uses exponential backoff with jitter between retries. |

## Further reading

- [Zalo Bot Platform docs](https://bot.zapps.me/docs/)
- [Polling tutorial](https://bot.zaloplatforms.com/docs/build-your-bot/)
