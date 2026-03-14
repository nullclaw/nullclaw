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

- Defines named agent profiles used by tools such as `/delegate`.
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
### `channels`

- Channel config lives under `channels.<name>`.
- Multi-account channels typically use an `accounts` wrapper.

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

- `search_base_url` must be `https://host[/search]` or a local/private `http://host[:port][/search]` URL, otherwise startup validation fails.
- `allowed_commands: ["*"]` and `allowed_paths: ["*"]` significantly widen execution scope.

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
