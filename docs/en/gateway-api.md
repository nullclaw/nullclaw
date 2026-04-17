# Gateway API

Default gateway endpoint: `http://127.0.0.1:3000`

## Page Guide

**Who this page is for**

- Operators wiring external systems into the local gateway
- Integrators testing pairing, bearer-token auth, and webhook delivery
- Reviewers checking what the HTTP surface exposes by default

**Read this next**

- Open [Security](./security.md) before exposing any gateway path beyond loopback or tunnel defaults
- Open [Configuration](./configuration.md) if you need the concrete `gateway` and channel keys behind these examples
- Open [Usage and Operations](./usage.md) for runtime checks, restarts, and troubleshooting around gateway behavior

**If you came from ...**

- [Usage and Operations](./usage.md): this page provides the endpoint-level detail behind the gateway health and webhook checks
- [Security](./security.md): come here when a security review needs the concrete HTTP auth and endpoint surface
- [Configuration](./configuration.md): return here after editing `gateway` settings to validate the API-facing behavior

## Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/health` | GET | None | Health check |
| `/pair` | POST | `X-Pairing-Code` | Exchange one-time pairing code for bearer token |
| `/webhook` | POST | `Authorization: Bearer <token>` | Send message payload: `{"message":"..."}` |
| `/cron` | GET | `Authorization: Bearer <token>` when pairing tokens exist | List live scheduler jobs from the running daemon |
| `/cron/add` | POST | `Authorization: Bearer <token>` when pairing tokens exist | Add or schedule a live cron job |
| `/cron/remove` | POST | `Authorization: Bearer <token>` when pairing tokens exist | Remove a live cron job by `id` |
| `/cron/pause` | POST | `Authorization: Bearer <token>` when pairing tokens exist | Pause a live cron job by `id` |
| `/cron/resume` | POST | `Authorization: Bearer <token>` when pairing tokens exist | Resume a live cron job by `id` |
| `/cron/update` | POST | `Authorization: Bearer <token>` when pairing tokens exist | Partially update a live cron job |
| `/whatsapp` | GET | Query params | Meta webhook verification |
| `/whatsapp` | POST | Meta signature | WhatsApp inbound webhook |
| `/max` | POST | `X-Max-Bot-Api-Secret` when configured | Max inbound webhook delivery |
| `/.well-known/agent-card.json` | GET | None | A2A Agent Card discovery (public) |
| `/a2a` | POST | `Authorization: Bearer <token>` | A2A JSON-RPC 2.0 endpoint |

## Quick Examples

### 1) Health check

```bash
curl http://127.0.0.1:3000/health
```

### 2) Pair and get token

```bash
curl -X POST \
  -H "X-Pairing-Code: 123456" \
  http://127.0.0.1:3000/pair
```

Expected: bearer token response (exact JSON shape may vary by version).

### 3) Send webhook message

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"hello from webhook"}' \
  http://127.0.0.1:3000/webhook
```

### 4) List live cron jobs

```bash
curl -X GET \
  -H "Authorization: Bearer YOUR_TOKEN" \
  http://127.0.0.1:3000/cron
```

### 5) Add a live cron job

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"expression":"*/15 * * * *","command":"echo hello"}' \
  http://127.0.0.1:3000/cron/add
```

`/cron/add` also accepts one-shot payloads such as `{"delay":"10m","command":"echo later"}` and agent payloads such as `{"expression":"0 * * * *","prompt":"Summarize alerts","model":"openrouter/anthropic/claude-sonnet-4"}`.

### 6) Max webhook delivery

Single-account example:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Max-Bot-Api-Secret: YOUR_MAX_SECRET" \
  -d '{"update_type":"bot_started","chat_id":100,"timestamp":1710000000000,"user":{"user_id":42,"first_name":"Igor"}}' \
  http://127.0.0.1:3000/max
```

Multi-account example:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Max-Bot-Api-Secret: YOUR_MAX_SECRET" \
  -d '{"update_type":"message_created","timestamp":1710000000000,"message":{"sender":{"user_id":42,"first_name":"Igor"},"recipient":{"chat_id":100,"chat_type":"dialog"},"body":{"mid":"m1","text":"ping"}}}' \
  "http://127.0.0.1:3000/max?account_id=main"
```

Max webhook notes:

- `nullclaw` routes `/max` to the configured Max account by `account_id` query first, then by `X-Max-Bot-Api-Secret`.
- If `channels.max[].webhook_secret` is configured, the header is required and must match exactly.
- Use HTTPS in the configured Max-side webhook URL.

## A2A (Agent-to-Agent Protocol)

NullClaw implements [Google's A2A protocol v0.3.0](https://github.com/google/A2A) over JSON-RPC 2.0, enabling interoperability with any A2A-compatible agent or client.

### Configuration

Add to `~/.nullclaw/config.json`:

```json
{
  "a2a": {
    "enabled": true,
    "name": "My Agent",
    "description": "General-purpose AI assistant",
    "url": "https://your-public-url.example.com",
    "version": "0.3.0"
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable A2A endpoints |
| `name` | `"NullClaw"` | Agent name in the Agent Card |
| `description` | `"AI assistant"` | Agent description |
| `url` | `""` | Public URL (used in Agent Card and `supportedInterfaces`) |
| `version` | `"1.0.0"` | Agent version string |
| `multi_modal` | `false` | Advertise multi-modal capability in the Agent Card. Set to `true` when the configured model supports image inputs. The gateway probes the model at startup and sets this automatically; override manually if needed. |

**Multi-modal support**

When `multi_modal` is `true`, the Agent Card includes `"multi_modal": true` in its capabilities object, signalling to A2A clients that the agent accepts image attachments. Incoming A2A messages may include `inlineData` parts (base64-encoded images) alongside `text` parts; the gateway forwards them to the model as `[IMAGE: <mime_type>]` markers.

To accept large image payloads, raise the gateway's HTTP body limit and socket read timeout in the `gateway` config block (see [configuration.md](./configuration.md) `gateway` section):

```json
{
  "gateway": {
    "max_body_size_bytes": 20971520,
    "request_timeout_secs": 120
  }
}
```

### Agent Card Discovery

```bash
curl http://127.0.0.1:3000/.well-known/agent-card.json
```

Returns the Agent Card with capabilities, skills, security schemes, and supported interfaces. No authentication required.

### JSON-RPC Methods

All methods are called via `POST /a2a` with a bearer token from `/pair`.

| Method | Description |
|--------|-------------|
| `message/send` | Send a message, receive completed task |
| `message/stream` | Send a message, receive SSE stream of events |
| `tasks/get` | Retrieve task by ID (supports `historyLength`) |
| `tasks/cancel` | Cancel an active task |
| `tasks/list` | List tasks with optional `state`/`contextId` filters |
| `tasks/resubscribe` | Resume SSE stream for an existing task |

### Task Lifecycle

```
submitted → working → completed
                    → failed
                    → canceled
                    → input-required
                    → auth-required
                    → rejected
```

Terminal states: `completed`, `failed`, `canceled`, `rejected`.

### Examples

**Send a message:**

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/send",
    "params": {
      "message": {
        "messageId": "msg-1",
        "role": "user",
        "parts": [{"kind": "text", "text": "What is nullclaw?"}]
      }
    }
  }' \
  http://127.0.0.1:3000/a2a
```

**Stream a response (SSE):**

```bash
curl -N -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/stream",
    "params": {
      "message": {
        "messageId": "msg-2",
        "role": "user",
        "parts": [{"kind": "text", "text": "Explain A2A protocol"}]
      }
    }
  }' \
  http://127.0.0.1:3000/a2a
```

**Get a task:**

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"task-1"}}' \
  http://127.0.0.1:3000/a2a
```

**Cancel a task:**

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tasks/cancel","params":{"id":"task-1"}}' \
  http://127.0.0.1:3000/a2a
```

### Multi-turn Conversations

Include `contextId` in the message to group tasks into a conversation. All messages with the same `contextId` share session state and conversation history:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "message/send",
  "params": {
    "message": {
      "messageId": "msg-3",
      "contextId": "my-conversation",
      "role": "user",
      "parts": [{"kind": "text", "text": "Follow-up question"}]
    }
  }
}
```

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| -32700 | JSONParseError | Invalid JSON payload |
| -32600 | InvalidRequestError | Request validation error |
| -32601 | MethodNotFoundError | Unknown method |
| -32602 | InvalidParamsError | Missing or invalid parameters |
| -32603 | InternalError | Server-side error |
| -32001 | TaskNotFoundError | Task ID not found |
| -32002 | TaskNotCancelableError | Task already in terminal state |
| -32003 | PushNotificationNotSupportedError | Push notifications not supported |
| -32005 | ContentTypeNotSupportedError | Incompatible content types |
| -32007 | AuthenticatedExtendedCardNotConfiguredError | Extended card not available |

## Security Guidance

1. Keep `gateway.require_pairing = true`.
2. Keep gateway on loopback (`127.0.0.1`) and expose externally through tunnel/proxy.
3. Treat bearer tokens as secrets; do not commit or log them.
4. Treat Max webhook secrets the same way: randomize them per account and do not reuse one secret across multiple bots.

## Next Steps

- Review [Security](./security.md) before changing public exposure, pairing, or token-handling assumptions
- Check [Configuration](./configuration.md) for the settings that back the examples on this page
- Use [Usage and Operations](./usage.md) for gateway startup, health checks, and post-change validation flow

## Related Pages

- [Configuration](./configuration.md)
- [Usage and Operations](./usage.md)
- [Security](./security.md)
- [README](./README.md)
