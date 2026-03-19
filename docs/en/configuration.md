# Configuration

NullClaw is compatible with OpenClaw config structure and uses `snake_case` keys.

## Page Guide

**Who this page is for**

- Users creating or editing the main `config.json`
- Operators tuning channels, gateway behavior, and autonomy limits
- Migrators mapping existing OpenClaw-style settings into NullClaw

**Read this next**

- Open [Usage and Operations](./usage.md) after config edits to validate runtime behavior
- Open [Security](./security.md) before widening permissions, public exposure, or tool scope
- Open [Gateway API](./gateway-api.md) if your config changes affect pairing, webhooks, or external integrations
- Open [External Channel Plugins](./external-channels.md) if you are wiring a non-core channel

**If you came from ...**

- [Installation](./installation.md): this page takes over once `nullclaw` is installed and ready for first-run setup
- [README](./README.md): this is the detailed config path after choosing the operator/user docs route
- [Gateway API](./gateway-api.md): come back here when the API workflow depends on concrete `gateway` or channel settings

## Config File Path

- macOS/Linux: `~/.nullclaw/config.json`
- Windows: `%USERPROFILE%\\.nullclaw\\config.json`

Recommended first step:

```bash
nullclaw onboard --interactive
```

This generates your initial config file.

## Minimal Working Config

The example below is enough to run local CLI mode (replace API key):

```json
{
  "models": {
    "providers": {
      "openrouter": {
        "api_key": "YOUR_OPENROUTER_API_KEY"
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "openrouter/anthropic/claude-sonnet-4"
      }
    }
  },
  "channels": {
    "cli": true
  },
  "memory": {
    "backend": "sqlite",
    "auto_save": true
  },
  "gateway": {
    "host": "127.0.0.1",
    "port": 3000,
    "require_pairing": true
  },
  "autonomy": {
    "level": "supervised",
    "workspace_only": true,
    "max_actions_per_hour": 20
  },
  "security": {
    "sandbox": {
      "backend": "auto"
    },
    "audit": {
      "enabled": true
    }
  }
}
```

## Core Sections

### `models.providers`

- Defines LLM provider connection parameters and API keys.
- Common providers: `openrouter`, `openai`, `anthropic`, `groq`.

Example:

```json
{
  "models": {
    "providers": {
      "openrouter": { "api_key": "sk-or-..." },
      "anthropic": { "api_key": "sk-ant-..." },
      "openai": { "api_key": "sk-..." }
    }
  }
}
```

### `agents.defaults.model.primary`

- Sets default model route, typically `provider/vendor/model`.
- Example: `openrouter/anthropic/claude-sonnet-4`

### `model_routes`

- Optional top-level routing table for automatic per-turn model selection in `nullclaw agent`.
- Each entry maps a route `hint` to a concrete `provider` and `model`.
- Recognized routing hints in the current daemon are `fast`, `balanced`, `deep`, `reasoning`, and `vision`.
- `balanced` is the normal fallback when configured. `fast` is preferred for short status/list/check prompts and other short structured tasks such as extraction, counting, classification, or narrow return-only transforms. `deep` and `reasoning` are preferred for investigation, planning, tradeoff analysis, and longer contexts. `vision` is used for image turns.
- `api_key` is optional. If omitted, NullClaw uses the normal credential from `models.providers.<provider>`.
- `cost_class` is optional metadata with values `free`, `cheap`, `standard`, or `premium`.
- `quota_class` is optional metadata with values `unlimited`, `normal`, or `constrained`.

Example:

```json
{
  "model_routes": [
    { "hint": "fast", "provider": "groq", "model": "llama-3.3-70b", "cost_class": "free", "quota_class": "unlimited" },
    { "hint": "balanced", "provider": "openrouter", "model": "anthropic/claude-sonnet-4", "cost_class": "standard", "quota_class": "normal" },
    { "hint": "deep", "provider": "openrouter", "model": "anthropic/claude-opus-4", "cost_class": "premium", "quota_class": "constrained" },
    { "hint": "vision", "provider": "openrouter", "model": "openai/gpt-4.1", "cost_class": "standard", "quota_class": "normal" }
  ]
}
```

Notes:

- `model_routes` are used only when the session is not pinned to an explicit model.
- If both `deep` and `reasoning` are configured, deep-analysis prompts prefer `deep`.
- `/model` shows the last auto-route decision so operators can see which route was picked and why.
- Auto-routed sessions temporarily degrade a route after quota or rate-limit failures and skip it until the cooldown expires.
- Route metadata only nudges scoring. Ambiguous prompts still stay on `balanced`; `fast` is reserved for high-confidence cheap tasks, and strong deep-analysis signals still win over cheaper routes.

### `agents.list`

- Defines named agent profiles used by the `delegate` tool, `/subagents spawn --agent`, and `bindings`.
- Each entry may set `provider` + `model`, or a full `provider/model` ref in `model.primary`.
- Example:

```json
{
  "agents": {
    "list": [
      {
        "id": "coder",
        "model": { "primary": "ollama/qwen3.5:cloud" },
        "system_prompt": "You're an experienced coder"
      }
    ]
  }
}
```

### Subagent Profiles + Routing (Practical Pattern)

Use this pattern when you want one "orchestrator" agent to delegate specialized tasks:

1. Define reusable specialists under `agents.list`.
2. Keep a general default under `agents.defaults`.
3. Use `bindings` to route specific chats/topics to a specialist.
4. Use `/subagents spawn --agent <agent-id> <task>` when you want explicit one-off delegation from the operator side.

Example:

```json
{
  "agents": {
    "defaults": {
      "model": { "primary": "openrouter/anthropic/claude-sonnet-4" }
    },
    "list": [
      {
        "id": "orchestrator",
        "model": { "primary": "openrouter/anthropic/claude-sonnet-4" },
        "system_prompt": "Coordinate tasks and delegate to specialists."
      },
      {
        "id": "coder",
        "model": { "primary": "openrouter/qwen/qwen3-coder" },
        "system_prompt": "You are focused on implementation and tests."
      },
      {
        "id": "researcher",
        "model": { "primary": "openrouter/openai/gpt-4.1" },
        "system_prompt": "You are focused on investigation and synthesis."
      }
    ]
  }
}
```

Notes:

- `agents.list[].id` is the value used by `/subagents spawn --agent <name>`, the `delegate` tool's `agent` argument, and `bindings[].agent_id`.
- Prefer short stable ids (`coder`, `researcher`) so chat commands stay simple.
- Keep specialist prompts narrow; broad prompts overlap and reduce routing clarity.

#### `agents.list[].workspace_path`

Use `workspace_path` when a named agent should run from its own workspace instead of the global one.

Example:

```json
{
  "agents": {
    "list": [
      {
        "id": "coder",
        "model": { "primary": "ollama/qwen2.5-coder:14b" },
        "system_prompt": "Focus on implementation and tests.",
        "workspace_path": "agents/coder"
      }
    ]
  }
}
```

Behavior:

- Relative paths are resolved relative to the directory that contains `config.json`.
- Absolute paths are used as-is.
- Both `/` and `\` are accepted in config; the runtime normalizes separators for the current OS.
- On first use, nullclaw scaffolds the workspace if missing and creates:
  - `AGENTS.md`
  - `SOUL.md`
  - `IDENTITY.md`
  - `MEMORY.md`

Isolation model:

- The agent's file operations, markdown memory files, and workspace-scoped context use that workspace.
- When `workspace_path` is set, the agent also gets a durable memory namespace of the form `agent:<agent-id>`.
- That namespace is used by:
  - `nullclaw agent --agent <id>`
  - `/subagents spawn --agent <id> ...`
  - routed sessions that resolve to that named agent through `bindings`

Practical effect:

- Two named agents can share the same provider/model family but keep separate durable notes and separate workspaces.
- `workspace_path` does not route chats by itself. Routing still comes from `bindings`, `/bind`, or explicit `--agent` / `/subagents spawn --agent`.

### `identity` (AIEOS v1.1)

Use this section when you want the runtime identity to come from an AIEOS document.
When configured, nullclaw injects the parsed AIEOS content into the system prompt alongside workspace identity files such as `AGENTS.md` and `IDENTITY.md`:

```json
{
  "identity": {
    "format": "aieos",
    "aieos_path": "./identity/aieos.identity.json"
  }
}
```

You can also inline the same document directly in config:

```json
{
  "identity": {
    "format": "aieos",
    "aieos_inline": "{\"identity\":{\"names\":{\"first\":\"nullclaw-assistant\"},\"bio\":\"General-purpose autonomous assistant\"},\"linguistics\":{\"style\":\"concise\"},\"motivations\":{\"core_drive\":\"Help the operator finish tasks safely\"}}"
  }
}
```

Minimal AIEOS v1.1 example file (`identity/aieos.identity.json`):

```json
{
  "identity": {
    "names": {
      "first": "nullclaw-assistant"
    },
    "bio": "General-purpose autonomous assistant"
  },
  "linguistics": {
    "style": "concise"
  },
  "motivations": {
    "core_drive": "Help the operator finish tasks safely"
  }
}
```

Notes:

- AIEOS payloads use top-level sections such as `identity`, `psychology`, `linguistics`, `motivations`, and `capabilities`.
- Prefer `aieos_path` for maintainability and version control readability.
- Use `aieos_inline` only when you need a fully self-contained single config file.
- Keep `identity.format` aligned with the payload source (`aieos`).
- Relative `aieos_path` values are resolved against the active workspace first, then against the current working directory.

### `channels`

- Channel config lives under `channels.<name>`.
- Multi-account channels typically use an `accounts` wrapper.

External channel plugin example:

```json
{
  "channels": {
    "external": {
      "accounts": {
        "wa-web": {
          "runtime_name": "whatsapp_web",
          "transport": {
            "command": "nullclaw-plugin-whatsapp-web",
            "args": ["--stdio"],
            "timeout_ms": 10000,
            "env": {
              "PLUGIN_TOKEN": "secret"
            }
          },
          "config": {
            "bridge_url": "http://127.0.0.1:3301",
            "allow_from": ["*"]
          }
        }
      }
    }
  }
}
```

External channel notes:

For the full protocol, lifecycle, metadata conventions, and plugin author
contract, see [External Channel Plugins](./external-channels.md).

- `runtime_name` is the nullclaw runtime channel id used by routing, bindings, session keys, and outbound dispatch. It must not reuse a built-in channel name or any runtime name already claimed by another configured channel.
- `transport.command` plus optional `transport.args` starts the plugin as a child process over line-delimited JSON-RPC on stdio.
- `transport.timeout_ms` bounds host->plugin RPC waits; nullclaw still caps control-plane waits internally so one broken plugin cannot stall supervision for minutes.
- `transport.env` is forwarded only to the plugin process.
- `config` must be a JSON object; it is forwarded to the plugin `start` request as `params.config`.
- Plugins must answer `get_manifest`, handle `start`/`send`/`stop`; `health` is recommended so supervision can detect disconnected sidecars instead of only live processes.
- `get_manifest.result` must contain `protocol_version: 2`; `capabilities.health`, `capabilities.streaming`, `capabilities.send_rich`, `capabilities.typing`, `capabilities.edit`, `capabilities.delete`, `capabilities.reactions`, and `capabilities.read_receipts` are optional capability bits.
- `health.result` must report an explicit boolean (`healthy`) or explicit health signals (`ok`, `connected`, `logged_in`); an empty object is treated as invalid.
- `start.params` now has a nested `runtime` object with `name`, `account_id`, and host-owned `state_dir`.
- `start.result` must contain `started: true`; `send`, `send_rich`, `edit_message`, `delete_message`, and typing/message-action RPCs must return `result.accepted: true` when the plugin actually accepts the action. A JSON-RPC success envelope by itself is not enough.
- `send.params` now has nested `runtime` and `message` objects; text payloads use `message.text`.
- If a plugin declares both `capabilities.edit=true` and `capabilities.delete=true`, `send.result` may also include `message_id` or `message { target?, message_id }`; that lets nullclaw keep a tracked draft updated on channels that do not support native `.chunk` streaming.
- If `capabilities.streaming=true`, nullclaw may emit `.chunk` staged `send` events during model streaming. If it is absent or `false`, nullclaw will only emit final responses.
- If `capabilities.send_rich=true`, the host may call `send_rich` with nested `runtime` and `message { target, text, attachments, choices }`.
- If `capabilities.typing=true`, the host may call `start_typing` / `stop_typing` with nested `runtime` plus `recipient`.
- If `capabilities.edit=true` / `capabilities.delete=true`, the host may call `edit_message` / `delete_message`.
- If `capabilities.reactions=true` or `capabilities.read_receipts=true`, the host may call `set_reaction` and `mark_read`.
- `inbound_message.params.message` must include `sender_id`, `chat_id`, and `text`; if `metadata` is present it must be a JSON object, and if `media` is present it must be an array of non-empty strings.
- Include `metadata.peer_kind` plus `metadata.peer_id` when you want routing/bindings to distinguish direct vs group peers for unknown channels.
- Unknown/external channels can also set `metadata.is_group`, `metadata.is_dm`, or `metadata.typing_recipient`; nullclaw promotes that metadata into prompt conversation context and processing-indicator routing.
- A reference bridge adapter for the PR #265 WhatsApp Web sidecar lives in `examples/whatsapp-web/nullclaw-plugin-whatsapp-web`.
- Production companion repositories now live out of tree: [nullclaw/nullclaw-channel-baileys](https://github.com/nullclaw/nullclaw-channel-baileys) and [nullclaw/nullclaw-channel-whatsmeow-bridge](https://github.com/nullclaw/nullclaw-channel-whatsmeow-bridge).
- `nullclaw channel start external` starts the first configured external account; `nullclaw channel start <runtime_name>` targets a specific configured runtime name such as `whatsapp_web`.

Telegram example:

```json
{
  "channels": {
    "telegram": {
      "accounts": {
        "main": {
          "bot_token": "123456:ABCDEF",
          "allow_from": ["YOUR_TELEGRAM_USER_ID"]
        }
      }
    }
  }
}
```

Telegram forum topics:

- Topic session isolation is automatic; there is no separate `topic_id` field under `channels.telegram`.
- The practical operator flow is:
  1. configure named agent profiles under `agents.list`
  2. open the target Telegram chat or forum topic
  3. run `/bind <agent>`
- If you want a specific forum topic to use a specific agent, configure it in `bindings` with `match.peer.id = "<chat_id>:thread:<topic_id>"`.
- If you also want a fallback agent for the rest of the same Telegram group, add another binding for the plain group id `"<chat_id>"`.
- `/bind status` shows the current effective route and the available agent ids.
- `/bind clear` removes only the exact binding for the current account/chat/topic and lets routing fall back to the broader match.
- `/bind` writes an exact `bindings[]` entry for the current Telegram account and peer.
- `/bind status` distinguishes an exact local override from an inherited broader fallback.
- Topic-specific bindings win over group fallback by route priority; the order in `bindings[]` does not matter.
- Telegram menu visibility for `/bind` is controlled by `channels.telegram.accounts.<id>.binding_commands_enabled`.

Example:

```json
{
  "bindings": [
    {
      "agent_id": "coder",
      "match": {
        "channel": "telegram",
        "account_id": "main",
        "peer": { "kind": "group", "id": "-1001234567890:thread:42" }
      }
    },
    {
      "agent_id": "orchestrator",
      "match": {
        "channel": "telegram",
        "account_id": "main",
        "peer": { "kind": "group", "id": "-1001234567890" }
      }
    }
  ]
}
```

In that setup, topic `42` routes to `coder`, while the rest of the forum falls back to `orchestrator`.

> **Peer ID format note**: Topic peer IDs in `bindings` must use the canonical `:thread:N` format (e.g. `"-1001234567890:thread:42"`). The legacy `#topic:N` format (e.g. `"-1001234567890#topic:42"`) is auto-converted at load time but is **deprecated** — a warning will appear in the logs. If you see `#topic:` in nullclaw's log output, convert it to `:thread:` when copying into your config. The `/bind` command always saves in the correct format automatically.

Named agent profiles and bindings are separate concerns: `agents.list` defines reusable profiles, while `bindings` decides which profile is used for a given chat/topic.

Minimal end-to-end example:

```json
{
  "agents": {
    "list": [
      {
        "id": "orchestrator",
        "provider": "openrouter",
        "model": "anthropic/claude-sonnet-4"
      },
      {
        "id": "coder",
        "provider": "ollama",
        "model": "qwen2.5-coder:14b",
        "system_prompt": "You are the coding agent for this topic."
      }
    ]
  },
  "channels": {
    "telegram": {
      "accounts": {
        "main": {
          "bot_token": "123456:ABCDEF",
          "allow_from": ["YOUR_TELEGRAM_USER_ID"],
          "binding_commands_enabled": true,
          "topic_commands_enabled": true,
          "topic_map_command_enabled": true,
          "commands_menu_mode": "scoped"
        }
      }
    }
  },
  "bindings": [
    {
      "agent_id": "orchestrator",
      "match": {
        "channel": "telegram",
        "account_id": "main",
        "peer": { "kind": "group", "id": "-1001234567890" }
      }
    }
  ]
}
```

Operator flow:

- Send `/bind coder` inside the target forum topic.
- `nullclaw` writes a new exact `bindings[]` entry to `~/.nullclaw/config.json` for that topic and Telegram account.
- The next message in that topic uses the new routed agent profile.
- `nullclaw` must have write access to `~/.nullclaw/config.json` for `/bind` to persist changes.

About `account_id`:

- `account_id` identifies the configured Telegram account entry, not a topic and not an agent.
- In the standard `channels.telegram.accounts` layout, the object key becomes the account id. For example, `accounts.main` means `account_id = "main"`.
- In `bindings`, `match.account_id` restricts a binding to one specific Telegram account.
- If `match.account_id` is omitted, the binding can match any Telegram account for that channel.
- Different account ids are only useful when the same nullclaw instance runs multiple Telegram bot accounts/tokens.

Effect on delivery:

- Incoming Telegram updates are handled by the account that received them.
- Routing uses that same `account_id`, so `match.account_id = "main"` matches only messages received through `channels.telegram.accounts.main`.
- Replies go back out through the same Telegram account/runtime that handled the message.
- If one binding uses `account_id = "main"` and another uses `account_id = "sub"`, they apply to different configured Telegram accounts; this does not split a single Telegram account's traffic by itself.

Rules:

- `allow_from: []` means deny all inbound messages.
- `allow_from: ["*"]` means allow all sources (use only when you accept the risk).

Max example:

```json
{
  "channels": {
    "max": [
      {
        "account_id": "main",
        "bot_token": "MAX_BOT_TOKEN",
        "allow_from": ["YOUR_MAX_USER_ID"],
        "group_allow_from": ["YOUR_MAX_USER_ID"],
        "group_policy": "allowlist",
        "mode": "webhook",
        "webhook_url": "https://bot.example.com/max?account_id=main",
        "webhook_secret": "replace-with-random-secret",
        "require_mention": true,
        "streaming": true,
        "interactive": {
          "enabled": true,
          "ttl_secs": 900,
          "owner_only": true
        }
      }
    ]
  }
}
```

Max notes:

- `channels.max` is an array of account entries; `account_id` distinguishes multiple Max bots.
- Prefer `mode = "webhook"` for production. Max documents long polling as suitable for development/testing, while webhooks are the recommended production path.
- `webhook_url` must be HTTPS.
- For multi-account webhook setups, give each account either a unique `webhook_secret` or a unique `account_id` query in the webhook URL, for example `/max?account_id=main`.
- `allow_from` and `group_allow_from` accept either Max `user_id` values or usernames. `user_id` is the stable choice for bindings and routing.
- `require_mention = true` only affects group chats. Direct messages and `bot_started` deep links still work normally.
- Max inline buttons are one-shot in nullclaw: after a valid click, the original keyboard is cleared to avoid stale buttons.

### Discord

Discord example:

```json
{
  "channels": {
    "discord": {
      "accounts": {
        "default": {
          "token": "YOUR_DISCORD_BOT_TOKEN",
          "intents": 37377,
          "allow_from": ["YOUR_DISCORD_USER_ID"]
        }
      }
    }
  }
}
```

Set `allow_from` explicitly unless you intentionally want an open bot. In the current Discord runtime, an omitted or empty `allow_from` list disables filtering instead of denying all inbound messages.

Enable MESSAGE CONTENT INTENT in the Discord Developer Portal if you want the bot to process ordinary guild messages. Without it, Discord omits message content for most guild traffic; direct messages and messages that mention the bot still include content.

Gateway intents (`intents`) is a bitmask. Default 37377 = GUILDS (1) + GUILD_MESSAGES (512) + MESSAGE_CONTENT (32768) + DIRECT_MESSAGES (4096). Calculate custom intents from https://discord.com/developers/docs/topics/gateway#gateway-intents.

Discord setup flow:
1. Create application at https://discord.com/developers/applications
2. Bot section → Add Bot → Reset Token (copy immediately)
3. Privileged Gateway Intents → Enable MESSAGE CONTENT INTENT → Save
4. OAuth2 → URL Generator → Scopes: `bot`
5. Bot Permissions: Send Messages, Read Message History, Read Messages/View Channels
6. Copy URL, open in browser, select server, authorize

The current Discord integration does not require extra OAuth scopes or elevated permissions such as `Administrator`.

Multi-bot setup uses `accounts` wrapper. Each `account_id` creates an independent Discord bot connection with separate session state and routing:

```json
{
  "channels": {
    "discord": {
      "accounts": {
        "production": {
          "token": "PRODUCTION_BOT_TOKEN",
          "intents": 37377,
          "allow_from": ["ADMIN_USER_ID"]
        },
        "testing": {
          "token": "TESTING_BOT_TOKEN",
          "intents": 37377,
          "allow_from": ["DEV_USER_ID"]
        }
      }
    }
  }
}
```

Channel-specific bindings use `peer.kind = "channel"` with Discord channel IDs (enable Developer Mode → right-click channel → Copy ID):

```json
{
  "bindings": [
    {
      "agent_id": "coder",
      "match": {
        "channel": "discord",
        "account_id": "default",
        "peer": {"kind": "channel", "id": "CHANNEL_ID_HERE"}
      }
    }
  ]
}
```

Direct message bindings use `peer.kind = "direct"` with user IDs:

```json
{
  "bindings": [
    {
      "agent_id": "personal",
      "match": {
        "channel": "discord",
        "account_id": "default",
        "peer": {"kind": "direct", "id": "USER_ID_HERE"}
      }
    }
  ]
}
```

Parameters:
- `token` (required) - Bot token from Discord Developer Portal
- `intents` (default: 37377) - Gateway intents bitmask
- `allow_bots` (default: false) - Allow messages from other bots
- `allow_from` (default: []) - Optional allowlist of user IDs; for Discord, an omitted or empty list disables filtering, so set explicit IDs for a private bot. `["*"]` also matches all users
- `require_mention` (default: false) - Require bot mention in guilds to respond
- `guild_id` (optional) - Reserved for Discord server scoping; current runtime does not enforce it

NullClaw splits messages >2000 characters (Discord API limit).

Verification:
```bash
nullclaw channel start discord
nullclaw channel status
```

`nullclaw channel start discord` starts only the first configured Discord account. For multi-account validation, run `nullclaw gateway` and send a test message to each configured bot.

Common issues:
- Bot only responds in DMs or explicit mentions: enable MESSAGE CONTENT INTENT, then re-invite the bot if needed
- "Privileged Intents" error: enable MESSAGE CONTENT INTENT in Discord Developer Portal; verified apps may also need Discord approval
- Bot offline: Check `nullclaw service status`, verify token hasn't been reset
- No response in guilds: Check `require_mention` setting, verify Read Messages permission

### `memory`

- `backend`: start with `sqlite`. Available engines: `sqlite`, `markdown`, `clickhouse`, `postgres`, `redis`, `lancedb`, `lucid`, `memory` (LRU), `api`, `none`.
- `auto_save`: persists conversation memory automatically.
- For hybrid retrieval and embedding settings, see root `config.example.json`.

### `gateway`

Recommended defaults:

- `host = "127.0.0.1"`
- `require_pairing = true`

Avoid direct public exposure. Use tunnel when external access is required.

### `tunnel`

Tunnel providers for exposing the gateway to the public internet. Required for webhook-based channels when running without a public IP.

**Providers:**

| Provider | Description |
|----------|-------------|
| `none` | No tunnel (default) |
| `cloudflare` | Cloudflare Tunnel |
| `ngrok` | ngrok tunnel |
| `tailscale` | Tailscale Funnel |
| `custom` | Custom tunnel command |

**Example: ngrok**

```json
{
  "tunnel": {
    "provider": "ngrok",
    "ngrok": {
      "auth_token": "YOUR_NGROK_AUTH_TOKEN",
      "domain": "your-domain.ngrok-free.app"
    }
  }
}
```

**Example: Cloudflare**

```json
{
  "tunnel": {
    "provider": "cloudflare",
    "cloudflare": {
      "token": "YOUR_CLOUDFLARE_TUNNEL_TOKEN"
    }
  }
}
```

**Notes:**

- Tunnel starts before gateway.
- Public URL is printed on startup and written to `daemon_state.json`.

### `autonomy`

- `level`: start with `supervised`.
- `level = "yolo"`: bypasses command policy checks; use only for trusted local debugging.
- `workspace_only`: keep `true` to limit file access scope.
- `max_actions_per_hour`: keep conservative limits first.

### `security`

- `sandbox.backend = "auto"`: auto-selects an available sandbox backend.
- `audit.enabled = true`: recommended for traceability.

### Advanced: Web Search + Full Shell (high risk)

Use only in controlled environments:

```json
{
  "http_request": {
    "enabled": true,
    "allowed_domains": ["192.168.1.10", "*.internal.example.com"],
    "search_base_url": "https://searx.example.com",
    "search_provider": "auto",
    "search_fallback_providers": ["jina", "duckduckgo"]
  },
  "autonomy": {
    "level": "full",
    "allowed_commands": ["*"],
    "allowed_paths": ["*"],
    "require_approval_for_medium_risk": false,
    "block_high_risk_commands": false
  }
}
```

Notes:

- `search_base_url` (for web_search tool): Must be `https://host[/search]` or a local/private `http://host[:port][/search]` URL. HTTP is allowed only for localhost/private hosts (e.g., `http://localhost:8888`, `http://192.168.1.10:8888`). This URL is used by the `web_search` tool to query SearXNG instances.
- `allowed_commands: ["*"]` and `allowed_paths: ["*"]` significantly widen execution scope.
- `http_request.allowed_domains`: Domains that bypass SSRF protection for the `http_request` and `web_fetch` tools.
  - `[]` (empty): All domains go through SSRF check (default, safest).
  - `["example.com"]`: Only specified domains skip SSRF protection.
  - `["*.example.com"]`: Matches all subdomains (e.g., `api.example.com`, `www.example.com`).
  - `["192.168.1.10"]`: IP addresses can also be allowlisted (exact match only, CIDR ranges not supported).
  - `["*"]`: **DANGEROUS** - All domains skip SSRF protection and DNS pinning. Use only in trusted network environments where you control DNS and need to allow access to any IP address. This effectively disables SSRF protection.
  - **Example**: If your SearXNG runs on `192.168.1.10`, add `"192.168.1.10"` to access it via `http_request` tool.
  - **Security trade-off**: Allowlisted domains skip DNS pinning, allowing access to private IPs. This trades DNS rebinding protection for operational flexibility.
  - **HTTPS-only policy**: The `http_request` and `web_fetch` tools require `https://` URLs. Plain HTTP is rejected for security. Note: This does not affect `web_search` tool's `search_base_url` which allows HTTP for local hosts.
  - **Check order**: Allowlist is checked BEFORE DNS resolution to prevent DNS exfiltration attacks.

## Validate After Config Changes

After each config change:

```bash
nullclaw doctor
nullclaw status
nullclaw channel status
```

If gateway/channel changed, also run:

```bash
nullclaw gateway
```

## Next Steps

- Run `nullclaw doctor` and `nullclaw status` after each edit to confirm the config still loads cleanly
- Use [Usage and Operations](./usage.md) for operational checks, service mode, and troubleshooting flow
- Review [Security](./security.md) before enabling broader autonomy, public bind, or wildcard allowlists

## Related Pages

- [Installation](./installation.md)
- [Usage and Operations](./usage.md)
- [Security](./security.md)
- [Gateway API](./gateway-api.md)
