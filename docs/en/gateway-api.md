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
| `/api/status` | GET | `Authorization: Bearer <token>` | REST Admin API — version, pid, uptime, overall status, and component health detail (requires `gateway.admin_api: true`) |

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

## REST Admin API (`/api/`)

The REST Admin API provides programmatic access to runtime state for trusted clients such as the NullClaw iOS app. It is **opt-in** and disabled by default.

### Enabling

Add `"admin_api": true` under the `gateway` key in `config.json`:

```json
{
  "gateway": {
    "require_pairing": true,
    "admin_api": true
  }
}
```

When `admin_api` is `false` (the default), every request to `/api/*` returns:

```json
{"success":false,"data":null,"error":{"code":"ADMIN_API_DISABLED","message":"Set gateway.admin_api=true in config.json to enable the REST admin API"}}
```

### Auth

The same Bearer token used for `/webhook` and `/cron` is required. Requests without a valid token receive `401 Unauthorized`.

### Response envelope

All Admin API responses use a consistent JSON envelope:

```json
{"success":true,"data":{...},"error":null}
{"success":false,"data":null,"error":{"code":"ERROR_CODE","message":"human-readable message"}}
```

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/status` | GET | Version, pid, uptime, overall status, and component health |
| `/api/doctor` | GET | Deep health report: per-component status, timestamps, restart counts, readiness |
| `/api/spec` | GET | OpenAPI 3.1 spec for all Admin API endpoints |
| `/api/config?path=<dotted>` | GET | Read a single config value |
| `/api/config` | PATCH | Mutate a config value (allowlisted paths only) |
| `/api/config` | DELETE | Unset a config value |
| `/api/config/reload` | POST | Hot-reload config from disk |
| `/api/config/validate` | POST | Validate config without applying |
| `/api/models` | GET | List configured providers (no key values) |
| `/api/cron` | GET | List all scheduled jobs |
| `/api/cron` | POST | Create a recurring cron job |
| `/api/cron/once` | POST | Create a one-shot delayed job |
| `/api/cron/:id/run` | POST | Trigger a job immediately |
| `/api/cron/:id/pause` | POST | Pause a job |
| `/api/cron/:id/resume` | POST | Resume a paused job |
| `/api/cron/:id` | PATCH | Update job fields |
| `/api/cron/:id` | DELETE | Remove a job |
| `/api/channels` | GET | List configured channels and health status |
| `/api/channels/:name` | GET | Detail for a single channel type |
| `/api/skills` | GET | List installed skills |
| `/api/skills/install` | POST | Install a skill by name or URL |
| `/api/skills/:name` | DELETE | Uninstall a skill |
| `/api/mcp` | GET | List configured MCP servers (env/header values redacted) |
| `/api/mcp/:name` | GET | Detail for a single MCP server |
| `/api/agent` | POST | One-shot agent invocation (body: `{"message":"...","session":"..."}`) |
| `/api/agent/stream` | POST | SSE streaming variant — returns 501 until gateway transport supports chunked responses |
| `/api/agent/sessions` | GET | List active agent sessions |
| `/api/agent/sessions/:id` | DELETE | Terminate an agent session |
| `/api/memory` | GET | List memory entries; filter with `?category=`, `?session=`, `?q=` (FTS), `?limit=`, `?include_internal=true` |
| `/api/memory/stats` | GET | Memory backend name and total entry count |
| `/api/memory/search` | POST | Full-text memory search (body: `{"query":"...","limit":10}`) |
| `/api/memory/:key` | GET | Get a single memory entry by key |
| `/api/memory/:key` | DELETE | Delete a memory entry by key |
| `/api/history` | GET | List conversation history sessions |

#### `GET /api/status`

Returns version, pid, uptime, overall health status, and per-component detail.

```json
{
  "success": true,
  "data": {
    "version": "v2026.4.4",
    "pid": 12345,
    "uptime_seconds": 3600,
    "status": "ok",
    "components": {
      "gateway": {"status": "ok", "restart_count": 0}
    }
  },
  "error": null
}
```

`status` is `"ok"` when all components report `"ok"`, otherwise `"degraded"`.

#### `GET /api/doctor`

Deep health report. Includes per-component `updated_at`, `last_ok`, `last_error`, `restart_count`, and a top-level `ready` boolean.

```json
{
  "success": true,
  "data": {
    "pid": 12345,
    "uptime_seconds": 3600,
    "ready": true,
    "components": {
      "gateway": {
        "status": "ok",
        "restart_count": 0,
        "updated_at": "2026-04-06T12:00:00Z",
        "last_ok": "2026-04-06T12:00:00Z",
        "last_error": null
      }
    }
  },
  "error": null
}
```

`ready` is `true` only when every registered component reports `"ok"`.

#### `GET /api/spec`

Returns the full OpenAPI 3.1 JSON document for the REST Admin API, wrapped in the standard success envelope. Useful for generating client SDKs or importing into tools like Postman.

#### `POST /api/agent`

Sends a message to the agent and waits for a response. Useful for single-message fire-and-wait use cases (e.g. menubar apps, iOS shortcuts, CLI dashboards). Not a replacement for A2A, which handles multi-turn delegation.

Request body:

```json
{ "message": "summarise open issues", "session": "my-session" }
```

`session` is optional; defaults to `"api:default"`. Session keys containing `:` must be percent-encoded as `%3A` in URL paths.

Response:

```json
{
  "success": true,
  "data": {
    "response": "Here are the open issues...",
    "session": "my-session",
    "turn_count": 1
  },
  "error": null
}
```

`POST /api/agent/stream` returns `501 Not Implemented` — the gateway HTTP transport is a single-write model and chunked SSE is not yet supported.

#### `GET /api/agent/sessions`

Lists active sessions with key, turn count, and last-active timestamp.

#### `DELETE /api/agent/sessions/:id`

Terminates the named session and frees its resources. Returns `404` if the session does not exist.

#### `GET /api/memory`

Lists memory entries from the configured backend. All query parameters are optional:

| Parameter | Description |
|-----------|-------------|
| `?category=<name>` | Filter by category: `core`, `daily`, `conversation`, or a custom name |
| `?session=<id>` | Filter by session ID |
| `?q=<text>` | Full-text search via the backend's `recall()` — overrides `category`/`session` filters |
| `?limit=<n>` | Max entries (default 100 for list, 20 for search) |
| `?include_internal=true` | Include autosave/bootstrap internal keys (excluded by default) |

Returns `503 MEMORY_UNAVAILABLE` when no memory backend is configured.

```json
{
  "success": true,
  "data": {
    "entries": [
      {
        "id": "1",
        "key": "greeting",
        "content": "Hello world",
        "category": "core",
        "timestamp": "2026-04-06T00:00:00Z",
        "session_id": null,
        "score": null
      }
    ],
    "total": 1,
    "backend": "sqlite"
  },
  "error": null
}
```

#### `GET /api/memory/stats`

Returns the backend name and total entry count.

```json
{ "success": true, "data": { "backend": "sqlite", "count": 42 }, "error": null }
```

Returns `503 MEMORY_UNAVAILABLE` when no memory backend is configured.

#### `POST /api/memory/search`

Full-text search via the backend's `recall()` method.

Request body:

```json
{ "query": "project deadlines", "limit": 10, "session": "opt-session-id" }
```

`limit` defaults to 20. `session` is optional and scopes the search to a specific session.

Response shape matches `GET /api/memory` (same `entries`/`total`/`backend` envelope).

Returns `503 MEMORY_UNAVAILABLE` when no memory backend is configured.

#### `GET /api/memory/:key`

Returns a single memory entry by its key. The key is percent-decoded before lookup (`%2F` → `/`, `%3A` → `:`). Returns `404 NOT_FOUND` if no entry with that key exists.

Returns `503 MEMORY_UNAVAILABLE` when no memory backend is configured.

#### `DELETE /api/memory/:key`

Deletes a memory entry by key. The key is percent-decoded before lookup (e.g. `%2F` → `/`). Returns `404 NOT_FOUND` if no entry with that key exists.

```json
{ "success": true, "data": { "key": "greeting", "deleted": true }, "error": null }
```

Returns `503 MEMORY_UNAVAILABLE` when no memory backend is configured.

#### `GET /api/history`

Lists conversation history sessions. When a durable session store is configured (SQLite backend), returns persisted session metadata. Falls back to listing active in-memory sessions when no store is available.

Query parameters:

| Parameter | Description |
|-----------|-------------|
| `?limit=<n>` | Max sessions to return (default 50) |
| `?offset=<n>` | Pagination offset (default 0) |

Response (session store):

```json
{
  "success": true,
  "data": {
    "sessions": [
      {
        "session_id": "telegram:chat123",
        "message_count": 10,
        "first_message_at": "2026-04-01T00:00:00Z",
        "last_message_at": "2026-04-06T12:00:00Z"
      }
    ],
    "total": 1,
    "source": "session_store"
  },
  "error": null
}
```

Response (active sessions fallback):

```json
{
  "success": true,
  "data": {
    "sessions": [
      {
        "session_key": "api:default",
        "created_at": 1712345678,
        "last_active": 1712349278,
        "turn_count": 5
      }
    ],
    "total": 1,
    "source": "active_sessions"
  },
  "error": null
}
```

`source` is either `"session_store"` or `"active_sessions"` so callers can distinguish the shape.

Returns `503 SESSION_MANAGER_UNAVAILABLE` when no session manager is running.

## Security Guidance

1. Keep `gateway.require_pairing = true`.
2. Keep gateway on loopback (`127.0.0.1`) and expose externally through tunnel/proxy.
3. Treat bearer tokens as secrets; do not commit or log them.
4. Treat Max webhook secrets the same way: randomize them per account and do not reuse one secret across multiple bots.
5. Only enable `gateway.admin_api = true` when a trusted client (e.g. NullClaw iOS app) requires it.

## Next Steps

- Review [Security](./security.md) before changing public exposure, pairing, or token-handling assumptions
- Check [Configuration](./configuration.md) for the settings that back the examples on this page
- Use [Usage and Operations](./usage.md) for gateway startup, health checks, and post-change validation flow

## Related Pages

- [Configuration](./configuration.md)
- [Usage and Operations](./usage.md)
- [Security](./security.md)
- [README](./README.md)
