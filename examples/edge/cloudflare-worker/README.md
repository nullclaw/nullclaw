# Edge MVP: Telegram + OpenAI + WASM policy core (Cloudflare Worker)

This example demonstrates the **hybrid edge path**:

- Edge host (`worker.mjs`) handles HTTP, secrets, Telegram webhook, OpenAI call.
- Tiny Zig WASM module (`agent_core.zig`) decides response policy.

This keeps secrets and network in the host while agent logic stays swappable as WASM.

## What it does

1. Receives Telegram webhook update.
2. Extracts simple text features in JS.
3. Calls WASM `choose_policy(...)`.
4. Builds a system prompt from selected policy.
5. Sends request to OpenAI Chat Completions.
6. Sends the reply back to Telegram chat.

## Prerequisites

- Cloudflare account + [`wrangler`](https://developers.cloudflare.com/workers/wrangler/)
- Zig `0.15.2`
- Telegram bot token
- OpenAI API key

## Build WASM core

From repository root:

```bash
mkdir -p examples/edge/cloudflare-worker/dist
zig build-exe examples/edge/cloudflare-worker/agent_core.zig \
  -target wasm32-freestanding \
  -fno-entry \
  -rdynamic \
  -O ReleaseSmall \
  -femit-bin=examples/edge/cloudflare-worker/dist/agent_core.wasm
```

## Configure secrets

```bash
cd examples/edge/cloudflare-worker
wrangler secret put TELEGRAM_BOT_TOKEN
wrangler secret put OPENAI_API_KEY
wrangler secret put TELEGRAM_WEBHOOK_SECRET
```

## Enable Telegram dedup (KV)

Create KV namespaces:

```bash
cd examples/edge/cloudflare-worker
wrangler kv namespace create TELEGRAM_DEDUP
wrangler kv namespace create TELEGRAM_DEDUP --preview
```

Then add this binding block to `wrangler.toml` with your IDs:

```toml
[[kv_namespaces]]
binding = "TELEGRAM_DEDUP"
id = "<your_prod_namespace_id>"
preview_id = "<your_preview_namespace_id>"
```

Worker deduplicates by `update_id` and skips retries already seen in KV.

Optional variables in `wrangler.toml`:

- `OPENAI_MODEL` (default `gpt-4o-mini`)
- `DEDUP_TTL_SECONDS` (default `86400`)
- `PUBLIC_BASE_URL` (required only for `/telegram/set-webhook` helper route)

## Deploy

```bash
cd examples/edge/cloudflare-worker
wrangler deploy
```

## Set Telegram webhook

Option A: helper endpoint (after setting `PUBLIC_BASE_URL` var)

```bash
curl -X POST "https://<your-worker-domain>/telegram/set-webhook"
```

Option B: set manually

```bash
curl -X POST "https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/setWebhook" \
  -H "content-type: application/json" \
  -d '{
    "url": "https://<your-worker-domain>/telegram/webhook",
    "secret_token": "<TELEGRAM_WEBHOOK_SECRET>",
    "allowed_updates": ["message", "edited_message"]
  }'
```

## Notes

- This is intentionally minimal and stateless.
- Dedup with KV is best-effort (eventual consistency), but removes the common Telegram retry duplicates.
- For production, still add retries for outbound calls and rate limiting.
- To evolve behavior, update only `agent_core.zig` and redeploy the wasm artifact.
