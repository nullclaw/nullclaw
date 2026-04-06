# REST Admin API — Implementation Plan

Tracking document for the `/api/*` REST Admin API rollout.

**Goal:** Give lightweight general-purpose clients (menubar apps, mobile clients, CLI dashboards) a
uniform, structured interface for gateway inspection and control — without requiring the A2A protocol
or a full LLM round-trip. The `/cron/*` endpoints already establish this REST pattern; this plan
extends it systematically across all major subsystems.

**Constraints:**
- Zero new dependencies. Single static Zig binary.
- All endpoints opt-in via `gateway.admin_api: true` (default `false`).
- Auth mirrors `/cron`: Bearer token via existing `isWebhookAuthorized`.
- Standard envelope on every response: `{"success":bool,"data":...,"error":...}`.
- Binary size increase target: < 30 KB total across all phases.
- Path prefix: `/api/` (no version number — YAGNI).

---

## Status

| Phase | Scope | Status | Branch / PR |
|-------|-------|--------|-------------|
| 0 | Foundation + `GET /api/status` | ✅ Done | feat/api-phase5-config-mutation |
| 1 | Observability: status, config read, models | ✅ Done | feat/api-phase5-config-mutation |
| 2 | Cron CRUD under `/api/cron/*` | ✅ Done | feat/api-phase5-config-mutation |
| 3 | Memory & history | ⬜ Upcoming | — |
| 4 | Channels & skills | ✅ Done | feat/api-phase5-config-mutation |
| 5 | Config mutation (write, reload, validate) | ✅ Done | feat/api-phase5-config-mutation |
| 6 | MCP server management (read-only) | ✅ Done | feat/api-phase6-mcp (this PR) |
| 7 | Agent control & SSE streaming | ✅ Done | feat/api-phase7-agent |
| 8 | Polish (OpenAPI spec, docs, iOS snippets) | ⬜ Upcoming | — |

---

## Done

### Phase 0 — Foundation

New files: `src/api/context.zig`, `src/api/api.zig`  
Config: `GatewayConfig.admin_api: bool = false`  
Gateway: `/api/*` branch wired into main dispatch loop with cron-style auth guard.  
Routing: two-pass (exact match then prefix-match for `/:param` segments).

### Phase 1 — Observability

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | Version, pid, uptime, component health snapshot |
| GET | `/api/config?path=<dotted.path>` | Read a single config value from disk |
| GET | `/api/models` | List configured providers — name + `has_key` flag; key values never returned |

### Phase 2 — Cron CRUD

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/cron` | List live scheduler jobs |
| POST | `/api/cron` | Schedule a cron job (body: `{"expression":"0 * * * *","prompt":"..."}`) |
| POST | `/api/cron/once` | One-shot task (body: `{"delay":60,"prompt":"..."}`) |
| POST | `/api/cron/:id/run` | Trigger a job immediately |
| POST | `/api/cron/:id/pause` | Pause a job |
| POST | `/api/cron/:id/resume` | Resume a paused job |
| PATCH | `/api/cron/:id` | Partial update (schedule, prompt, etc.) |
| DELETE | `/api/cron/:id` | Remove a job |

### Phase 4 — Channels & Skills

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/channels` | List configured channel instances with health status |
| GET | `/api/channels/:name` | Single channel type detail (all accounts) |
| GET | `/api/skills` | List installed skills by scanning skillforge output dir |
| POST | `/api/skills/install` | Install a skill by name or URL |
| DELETE | `/api/skills/:name` | Remove an installed skill |

### Phase 5 — Config Mutation

| Method | Path | Description |
|--------|------|-------------|
| PATCH | `/api/config` | Set a config value (body: `{"path":"...","value":<json>}`) |
| DELETE | `/api/config` | Unset a config key (body: `{"path":"..."}`) |
| POST | `/api/config/reload` | Validate on-disk config; report restart requirements |
| POST | `/api/config/validate` | Dry-run validation of a candidate JSON blob |

**Notes:**
- Mutation allowlist enforced in `config_mutator.zig` — unlisted paths return 422 `PATH_NOT_ALLOWED`.
- `value` must be a JSON-typed value (e.g. `0.85` for float, `true` for bool) — not a string.
- `POST /api/config/validate` body is a bare config JSON object (same schema as `config.json`).

### Phase 6 — MCP Server Management (read-only)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/mcp` | List configured MCP servers (name, transport, command/url, arg count, env key names) |
| GET | `/api/mcp/:name` | Detail for one server (adds full `args` array) |

**Scope notes:**
- `restart` / `enable` / `disable` were deferred: MCP servers connect per-session only — there is
  no persistent MCP daemon or runtime registry. `McpServerConfig` also has no `enabled` field.
  These belong in a future phase once a shared MCP manager is introduced.
- Env values and header values are **redacted** in all responses — only key/header names are
  returned to avoid leaking credentials.

---

## Upcoming

### Phase 3 — Memory & History

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/memory/stats` | Backend type, record count, index size |
| GET | `/api/memory/count` | Record count only (fast) |
| POST | `/api/memory/search` | Keyword/vector search (body: `{"query":"...","limit":10}`) |
| GET | `/api/memory/:key` | Fetch a single memory record |
| DELETE | `/api/memory/:key` | Delete a memory record |
| POST | `/api/memory/reindex` | Trigger reindex |
| GET | `/api/history` | List sessions (paginated: `?limit=20&offset=0`) |
| GET | `/api/history/:session_id` | Fetch turns for a session |

---

### Phase 7 — Agent Control & SSE Streaming

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/agent` | One-shot agent invocation (body: `{"message":"...","session":"..."}`) |
| POST | `/api/agent/stream` | SSE streaming variant — lighter than full A2A |
| GET | `/api/agent/sessions` | List active sessions |
| DELETE | `/api/agent/sessions/:id` | Terminate a session |

**Notes:**
- `/api/agent` is not a replacement for A2A (which handles multi-turn delegation well).
  It is a simpler trigger surface for single-message fire-and-wait use cases.
- `POST /api/agent/stream` returns **501 Not Implemented**: the gateway HTTP transport is a
  single-write model (no persistent connections / chunked transfer). True SSE requires a
  gateway transport refactor and is deferred.
- Session keys containing `:` (e.g. `api:default`) must be percent-encoded as `%3A` in
  URL paths. A `percentDecode()` helper handles this in the DELETE handler.

---

### Phase 8 — Polish

| Item | Description |
|------|-------------|
| `GET /api/spec` | OpenAPI 3.1 JSON document generated at comptime from the endpoint registry |
| `GET /api/doctor` | `nullclaw doctor` output as structured JSON (component probe results) |
| Docs | `docs/en/gateway-api.md` fully rewritten with all endpoints, request/response examples |
| iOS snippets | Example Swift `GatewayClient` calls for each endpoint family |
| Chinese docs | Sync `docs/zh/gateway-api.md` |

---

## Architecture Notes

- `src/api/api.zig` registry is the single place to register endpoints. Adding one is:
  1. Write `fn handleX(ctx: *ApiContext) anyerror!void` in `api.zig`.
  2. Append `.{ .method = "GET", .path = "/api/x", .handler = handleX }` to `registry`.
- Routing: two-pass — exact match first, then `matchPathParam()` for `/:param` segments.
- The `dispatch()` function is the only gateway integration point. `gateway.zig` does not
  need to change again after Phase 0.
- `api.zig` must NOT import `gateway.zig` (circular dependency). The gateway calls `api.dispatch()`.
- Health status is cross-referenced from `health.snapshot()` — not queried live.
- MCP has no health registry; channels do (per-type, shared across accounts).
- Config mutation allowlist lives in `config_mutator.zig`. Unlisted paths return 422.
