**Official website:** [nullclaw.io](https://nullclaw.io)

<p align="center">
  <img src="nullclaw.png" alt="nullclaw" width="200" />
</p>

<h1 align="center">NullClaw</h1>

<p align="center">
  <strong>Null overhead. Null compromise. 100% Zig. 100% Agnostic.</strong><br>
  <strong>678 KB binary. ~1 MB RAM. Boots in <2 ms. Runs on anything with a CPU.</strong>
</p>

<p align="center">
  <a href="https://github.com/nullclaw/nullclaw/actions/workflows/ci.yml"><img src="https://github.com/nullclaw/nullclaw/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://nullclaw.github.io"><img src="https://img.shields.io/badge/docs-nullclaw.github.io-informational" alt="Documentation" /></a>
  <a href="https://discord.gg/Bfmdua22Ud"><img src="https://img.shields.io/badge/discord-join%20community-5865F2?logo=discord&logoColor=white" alt="Discord" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
</p>

The smallest fully autonomous AI assistant infrastructure — a static Zig binary that fits on any $5 board, boots in milliseconds, and requires nothing but libc.

Docs: [English](docs/en/README.md) · [中文](docs/zh/README.md) · [Contributing](CONTRIBUTING.md) · [Discord](https://discord.gg/Bfmdua22Ud)

```
678 KB binary · <2 ms startup · 5,300+ tests · 50+ providers · 19 channels · Pluggable everything
```

### Features

- **Impossibly Small:** 678 KB static binary — no runtime, no VM, no framework overhead.
- **Near-Zero Memory:** ~1 MB peak RSS. Runs comfortably on the cheapest ARM SBCs and microcontrollers.
- **Instant Startup:** <2 ms on Apple Silicon, <8 ms on a 0.8 GHz edge core.
- **True Portability:** Single self-contained binary across ARM, x86, and RISC-V. Drop it anywhere, it just runs.
- **Feature-Complete:** 50+ providers, 19 channels, 35+ tools, 10 memory engines, multi-layer sandbox, tunnels, hardware peripherals, MCP, subagents, streaming, voice — the full stack.

### Why nullclaw

- **Lean by default:** Zig compiles to a tiny static binary. No allocator overhead, no garbage collector, no runtime.
- **Secure by design:** pairing, strict sandboxing (landlock, firejail, bubblewrap, docker), explicit allowlists, workspace scoping, encrypted secrets.
- **Fully swappable:** core systems are vtable interfaces (providers, channels, tools, memory, tunnels, peripherals, observers, runtimes).
- **No lock-in:** OpenAI-compatible provider support + pluggable custom endpoints.

## Benchmark Snapshot

Local machine benchmark (macOS arm64, Feb 2026), normalized for 0.8 GHz edge hardware.

| | [OpenClaw](https://github.com/openclaw/openclaw) | [NanoBot](https://github.com/HKUDS/nanobot) | [PicoClaw](https://github.com/sipeed/picoclaw) | [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) | **[🦞 NullClaw](https://github.com/nullclaw/nullclaw)** |
|---|---|---|---|---|---|
| **Language** | TypeScript | Python | Go | Rust | **Zig** |
| **RAM** | > 1 GB | > 100 MB | < 10 MB | < 5 MB | **~1 MB** |
| **Startup (0.8 GHz)** | > 500 s | > 30 s | < 1 s | < 10 ms | **< 8 ms** |
| **Binary Size** | ~28 MB (dist) | N/A (Scripts) | ~8 MB | ~8.8 MB | **678 KB** |
| **Tests** | — | — | — | 1,017 | **5,300+** |
| **Source Files** | ~400+ | — | — | ~120 | **~230** |
| **Cost** | Mac Mini $599 | Linux SBC ~$50 | Linux Board $10 | Any $10 hardware | **Any $5 hardware** |

> Measured with `/usr/bin/time -l` on ReleaseSmall builds. nullclaw is a static binary with zero runtime dependencies.

Reproduce locally:

```bash
zig build -Doptimize=ReleaseSmall
ls -lh zig-out/bin/nullclaw

/usr/bin/time -l zig-out/bin/nullclaw --help
/usr/bin/time -l zig-out/bin/nullclaw status
```

## Documentation

Start here if you want the shortest path to install, configure, operate, or extend nullclaw.

Localized documentation lives under `docs/en/` and `docs/zh/`. Use the links below to jump straight to the page you need.

| Need | English | 中文 |
|---|---|---|
| Start here | [`docs/en/README.md`](docs/en/README.md) | [`docs/zh/README.md`](docs/zh/README.md) |
| Install | [`docs/en/installation.md`](docs/en/installation.md) | [`docs/zh/installation.md`](docs/zh/installation.md) |
| Configure | [`docs/en/configuration.md`](docs/en/configuration.md) | [`docs/zh/configuration.md`](docs/zh/configuration.md) |
| Commands | [`docs/en/commands.md`](docs/en/commands.md) | [`docs/zh/commands.md`](docs/zh/commands.md) |
| Development | [`docs/en/development.md`](docs/en/development.md) | [`docs/zh/development.md`](docs/zh/development.md) |
| Operations | [`docs/en/usage.md`](docs/en/usage.md) | [`docs/zh/usage.md`](docs/zh/usage.md) |
| Architecture | [`docs/en/architecture.md`](docs/en/architecture.md) | [`docs/zh/architecture.md`](docs/zh/architecture.md) |
| Security | [`docs/en/security.md`](docs/en/security.md) | [`docs/zh/security.md`](docs/zh/security.md) |
| Gateway API | [`docs/en/gateway-api.md`](docs/en/gateway-api.md) | [`docs/zh/gateway-api.md`](docs/zh/gateway-api.md) |

- Specialized guides: [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md), [`SIGNAL.md`](SIGNAL.md)

## Choose Your Path

| Goal | Open this first | Then go to |
|---|---|---|
| First run in English | [`docs/en/README.md`](docs/en/README.md) | [`docs/en/installation.md`](docs/en/installation.md) → [`docs/en/configuration.md`](docs/en/configuration.md) → [`docs/en/usage.md`](docs/en/usage.md) |
| Chinese Quick Start (中文快速上手) | [`docs/zh/README.md`](docs/zh/README.md) | [`docs/zh/installation.md`](docs/zh/installation.md) → [`docs/zh/configuration.md`](docs/zh/configuration.md) → [`docs/zh/usage.md`](docs/zh/usage.md) |
| Find the right CLI command | [`docs/en/commands.md`](docs/en/commands.md) / [`docs/zh/commands.md`](docs/zh/commands.md) | `nullclaw help` → task-specific subcommand page |
| Contribute code or docs | [`CONTRIBUTING.md`](CONTRIBUTING.md) | [`docs/en/development.md`](docs/en/development.md) / [`docs/zh/development.md`](docs/zh/development.md) → relevant architecture page |
| Operate or secure a deployment | [`docs/en/usage.md`](docs/en/usage.md) / [`docs/zh/usage.md`](docs/zh/usage.md) | [`docs/en/security.md`](docs/en/security.md) / [`docs/zh/security.md`](docs/zh/security.md) → Gateway API |

## After This README

- New here: jump to [`docs/en/README.md`](docs/en/README.md) or [`docs/zh/README.md`](docs/zh/README.md) and follow the guided reading order.
- Want commands fast: open [`docs/en/commands.md`](docs/en/commands.md) or [`docs/zh/commands.md`](docs/zh/commands.md).
- Want to submit a PR: start with [`CONTRIBUTING.md`](CONTRIBUTING.md), then read [`docs/en/development.md`](docs/en/development.md) or [`docs/zh/development.md`](docs/zh/development.md).

## Quick Start

### 1) Recommended install (Homebrew)

The simplest path: install a ready-to-run binary with no extra runtime dependencies.

```bash
brew install nullclaw
nullclaw --help
```

### 2) Build from source

> **Prerequisite:** use **Zig 0.15.2** (exact version).
> `0.16.0-dev` and other Zig versions are currently unsupported and may fail to build.
> Verify before building: `zig version` should print `0.15.2`.

```bash
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig build -Doptimize=ReleaseSmall
zig build test --summary all
```

Make `nullclaw` available on `PATH`:

macOS/Linux (zsh/bash):

```bash
zig build -Doptimize=ReleaseSmall -p "$HOME/.local"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
# or ~/.bashrc
```

Windows (PowerShell):

```powershell
zig build -Doptimize=ReleaseSmall -p "$HOME\.local"

$bin = "$HOME\.local\bin"
$user_path = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($user_path -split ";" | Where-Object { $_ -eq $bin })) {
  [Environment]::SetEnvironmentVariable("Path", "$user_path;$bin", "User")
}
$env:Path = "$env:Path;$bin"
```

Then:

```bash
nullclaw --help
```

### 3) Common commands

```bash

# Quick setup
nullclaw onboard --api-key sk-... --provider openrouter

# Or interactive wizard
nullclaw onboard --interactive

# Chat
nullclaw agent -m "Hello, nullclaw!"

# Interactive mode
nullclaw agent

# Start gateway runtime (gateway + all configured channels/accounts + heartbeat + scheduler)
nullclaw gateway                # default: 127.0.0.1:3000
nullclaw gateway --port 8080    # custom port

# Check status
nullclaw status

# Run system diagnostics
nullclaw doctor

# Check channel health
nullclaw channel status

# Start specific channels
nullclaw channel start telegram
nullclaw channel start discord
nullclaw channel start signal

# Manage background service
# Linux supports systemd user services and OpenRC
nullclaw service install
nullclaw service status

# Migrate memory from OpenClaw
nullclaw migrate openclaw --dry-run
nullclaw migrate openclaw
```

## Edge MVP (Hybrid Host + WASM Logic)

If you want edge deployment (Cloudflare Worker) with Telegram + OpenAI while keeping agent policy in WASM, see:

`examples/edge/cloudflare-worker/`

This pattern keeps networking/secrets in the edge host and lets you swap/update logic by replacing a tiny Zig WASM module.

## Architecture

Every subsystem is a **vtable interface** — swap implementations with a config change, zero code changes.

| Subsystem | Interface | Ships with | Extend |
|-----------|-----------|------------|--------|
| **AI Models** | `Provider` | 50+ providers (OpenRouter, Anthropic, OpenAI, Azure OpenAI, Gemini, Vertex AI, Ollama, Venice, Groq, Mistral, xAI, DeepSeek, Together, Fireworks, Perplexity, Cohere, Bedrock, and many OpenAI-compatible endpoints) | `custom:https://your-api.com` — any OpenAI-compatible API |
| **Channels** | `Channel` | CLI, Telegram, Signal, Discord, Slack, iMessage, Matrix, WhatsApp, Webhook, IRC, Lark/Feishu, OneBot, Line, DingTalk, Email, Nostr, QQ, MaixCam, Mattermost | Any messaging API |
| **Memory** | `Memory` | SQLite with hybrid search (FTS5 + vector cosine similarity), Markdown, ClickHouse, PostgreSQL, Redis, LanceDB, Lucid, LRU, API | Any persistence backend |
| **Tools** | `Tool` | shell, file_read, file_write, file_edit, file_edit_hashed, file_read_hashed, file_append, memory_store, memory_recall, memory_forget, memory_list, browser_open, screenshot, composio, http_request, web_fetch, web_search, delegate, schedule, hardware_info, hardware_memory, pushover, message, spawn, git, image, i2c, spi, and more | Any capability |
| **Observability** | `Observer` | Noop, Log, File, Multi | Prometheus, OTel |
| **Runtime** | `RuntimeAdapter` | Native, Docker (sandboxed), WASM (wasmtime) | Any runtime |
| **Security** | `Sandbox` | Landlock, Firejail, Bubblewrap, Docker, auto-detect | Any sandbox backend |
| **Identity** | `IdentityConfig` | OpenClaw (markdown), AIEOS v1.1 (JSON) | Any identity format |
| **Tunnel** | `Tunnel` | None, Cloudflare, Tailscale, ngrok, Custom | Any tunnel binary |
| **Heartbeat** | Engine | HEARTBEAT.md periodic tasks | — |
| **Skills** | Loader | TOML/JSON manifests or YAML frontmatter in `SKILL.md` | Community skill packs |
| **Peripherals** | `Peripheral` | Serial, Arduino, Raspberry Pi GPIO, STM32/Nucleo | Any hardware interface |
| **Cron** | Scheduler | Cron expressions + one-shot timers with JSON persistence | — |

### Memory System

All custom, zero external dependencies for the core path:

| Layer | Implementation |
|-------|---------------|
| **Vector DB** | Embeddings stored as BLOB in SQLite, cosine similarity search |
| **Keyword Search** | FTS5 virtual tables with BM25 scoring |
| **Hybrid Merge** | Weighted merge (configurable vector/keyword weights) |
| **Embeddings** | `EmbeddingProvider` vtable — OpenAI, custom URL, or noop |
| **Hygiene** | Automatic archival + purge of stale memories |
| **Snapshots** | Export/import full memory state for migration |
| **Engines** | SQLite (default), Markdown, ClickHouse, PostgreSQL, Redis, LanceDB, Lucid, LRU, API, None |

```json
{
  "memory": {
    "backend": "sqlite",
    "auto_save": true,
    "embedding_provider": "openai",
    "vector_weight": 0.7,
    "keyword_weight": 0.3,
    "hygiene_enabled": true,
    "snapshot_enabled": false
  }
}
```

## Security

nullclaw enforces security at **every layer**.

| # | Item | Status | How |
|---|------|--------|-----|
| 1 | **Gateway not publicly exposed** | Done | Binds `127.0.0.1` by default. Refuses `0.0.0.0` without tunnel or explicit `allow_public_bind`. |
| 2 | **Pairing required** | Done | 6-digit one-time code on startup. Exchange via `POST /pair` for bearer token. |
| 3 | **Filesystem scoped** | Done | `workspace_only = true` by default. Null byte injection blocked. Symlink escape detection. |
| 4 | **Access via tunnel only** | Done | Gateway refuses public bind without active tunnel. Supports Tailscale, Cloudflare, ngrok, or custom. |
| 5 | **Sandbox isolation** | Done | Auto-detects best backend: Landlock, Firejail, Bubblewrap, or Docker. |
| 6 | **Encrypted secrets** | Done | API keys encrypted with ChaCha20-Poly1305 using local key file. |
| 7 | **Resource limits** | Done | Configurable memory, CPU, disk, and subprocess limits. |
| 8 | **Audit logging** | Done | Signed event trail with configurable retention. |

### Channel Allowlists

- Empty allowlist = **deny all inbound messages**
- `"*"` = **allow all** (explicit opt-in)
- Otherwise = exact-match allowlist

Nostr additionally: the `owner_pubkey` is **always** allowed regardless of `dm_allowed_pubkeys`. Private keys are encrypted at rest via SecretStore (`enc2:` prefix) and only decrypted into memory while the channel is running; zeroed on channel stop.

### Nostr Channel Setup

`nullclaw` speaks Nostr natively via NIP-17 (gift-wrapped private DMs) and NIP-04 (legacy DMs), using [`nak`](https://github.com/fiatjaf/nak).

**Prerequisites:** Install `nak` and ensure it's in your `$PATH`.

**Setup via onboarding wizard:**

```bash
nullclaw onboard --interactive   # Step 7 configures Nostr
```

The wizard will:
1. Generate a new keypair for your bot or import a key & encrypt it with ChaCha20-Poly1305
2. Ask for your (owner) pubkey (npub or hex) — always allowed through DM policy
3. Configure relays and DM relays (kind:10050 inbox)
4. Display the bot's pubkey

Or configure manually in the [config](#configuration).

**How it works:** On startup, nullclaw announces its DM inbox relays (kind:10050), then listens for incoming NIP-17 gift wraps and NIP-04 encrypted DMs. Outbound messages mirror the sender's protocol. Multi-relay rumor deduplication prevents duplicate responses when the same message is delivered via multiple relays.

## Configuration

Config: `~/.nullclaw/config.json` (created by `onboard`)

> **OpenClaw compatible:** nullclaw uses the same config structure as [OpenClaw](https://github.com/openclaw/openclaw) (snake_case). Providers live under `models.providers`, the default model under `agents.defaults.model.primary`, and channels use `accounts` wrappers.
> Top-level `default_provider` / `default_model` keys are not supported.
>
> **Vertex AI note:** `models.providers.vertex.api_key` supports either:
> 1. a bearer token (`ya29...`), or
> 2. a full Google service-account JSON object (same shape as Apps Script `GEMINI_KEY` with `project_id`, `client_email`, `private_key`).
>
> `models.providers.vertex.base_url` can be set explicitly (`.../projects/<id>/locations/<loc>/publishers/google/models`), or omitted when service-account JSON is used (nullclaw will derive it from `project_id`, with `VERTEX_LOCATION` defaulting to `global`).
> Service-account mode requires `openssl` available in `$PATH` for RS256 JWT signing.

```json
{
  "default_temperature": 0.7,

  "models": {
    "providers": {
      "openrouter": { "api_key": "sk-or-..." },
      "groq": { "api_key": "gsk_..." },
      "vertex": {
        "api_key": {
          "type": "service_account",
          "project_id": "your-project",
          "client_email": "svc@your-project.iam.gserviceaccount.com",
          "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
        },
        "base_url": "https://aiplatform.googleapis.com/v1/projects/your-project/locations/global/publishers/google/models"
      },
      "anthropic": { "api_key": "sk-ant-...", "base_url": "https://api.anthropic.com" }
    }
  },

  "agents": {
    "defaults": {
      "model": { "primary": "openrouter/anthropic/claude-sonnet-4" },
      "heartbeat": { "every": "30m" }
    },
    "list": [
      { "id": "researcher", "model": { "primary": "openrouter/anthropic/claude-opus-4" }, "system_prompt": "..." }
    ]
  },

  "channels": {
    "telegram": {
      "accounts": {
        "main": {
          "bot_token": "123:ABC",
          "allow_from": ["user1"],
          "reply_in_private": true,
          "proxy": "socks5://..."
        }
      }
    },
    "discord": {
      "accounts": {
        "main": {
          "token": "disc-token",
          "guild_id": "12345",
          "allow_from": ["user1"],
          "allow_bots": false
        }
      }
    },
    "irc": {
      "accounts": {
        "main": {
          "host": "irc.libera.chat",
          "port": 6697,
          "nick": "nullclaw",
          "channel": "#nullclaw",
          "tls": true,
          "allow_from": ["user1"]
        },
        "meshrelay": {
          "host": "irc.meshrelay.xyz",
          "port": 6697,
          "nick": "nullclaw",
          "channels": ["#agents"],
          "tls": true,
          "nickserv_password": "YOUR_NICKSERV_PASSWORD",
          "allow_from": ["*"]
        }
      }
    },
    "slack": {
      "accounts": {
        "main": {
          "bot_token": "xoxb-...",
          "app_token": "xapp-...",
          "allow_from": ["user1"]
        }
      }
    },
    "nostr": {
      "private_key": "enc2:...",
      "owner_pubkey": "hex-pubkey-of-owner",
      "relays": ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.nostr.band"],
      "dm_allowed_pubkeys": ["*"],
      "display_name": "NullClaw",
      "about": "AI assistant on Nostr",
      "nip05": "nullclaw@yourdomain.com",
      "lnurl": "lnurl1..."
    }
  },

  "tools": {
    "media": {
      "audio": {
        "enabled": true,
        "language": "ru",
        "models": [{ "provider": "groq", "model": "whisper-large-v3" }]
      }
    }
  },

  "mcp_servers": {
    "filesystem": {
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"]
    },
    "remote": {
      "transport": "http",
      "url": "https://mcp.example.com/rpc",
      "timeout_ms": 10000,
      "headers": {
        "Authorization": "Bearer ${MCP_TOKEN}"
      }
    }
  },

  "memory": {
    "backend": "sqlite",
    "auto_save": true,
    "embedding_provider": "openai",
    "vector_weight": 0.7,
    "keyword_weight": 0.3
  },

  "gateway": {
    "port": 3000,
    "require_pairing": true,
    "allow_public_bind": false
  },

  "autonomy": {
    "level": "supervised",
    "workspace_only": true,
    "max_actions_per_hour": 20
  },

  "runtime": {
    "kind": "native",
    "docker": {
      "image": "alpine:3.20",
      "network": "none",
      "memory_limit_mb": 512,
      "read_only_rootfs": true
    }
  },


  "tunnel": { "provider": "none" },
  "secrets": { "encrypt": true },
  "identity": { "format": "openclaw" },

  "security": {
    "sandbox": { "backend": "auto" },
    "resources": { "max_memory_mb": 512, "max_cpu_percent": 80 },
    "audit": { "enabled": true, "retention_days": 90 }
  }
}
```

Telegram forum topics:

- Topic session isolation is automatic. You do not add a `topic_id` field under `channels.telegram`.
- The easiest operator flow is:
  1. define named agent profiles under `agents.list`
  2. open the target Telegram chat or forum topic
  3. run `/bind <agent>`
- To bind a specific Telegram forum topic to a specific agent, use `bindings[].match.peer.id` with the canonical thread form `"<chat_id>:thread:<topic_id>"`.
- To bind the whole Telegram group as a fallback for all other topics, keep a normal group binding with `"<chat_id>"`.
- `/bind status` shows the current effective route and the available agent ids.
- `/bind clear` removes only the exact binding for the current account/chat/topic and falls back to the broader route.
- `/bind` persists an exact `bindings[]` entry for the current Telegram account and peer.
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

Named agent profiles are configured separately from bindings. Bindings only choose which named agent handles a given chat/topic.

If a named agent should run from its own workspace, set `agents.list[].workspace_path`.
Relative paths are resolved from the directory that contains `config.json`, the workspace is scaffolded on first use, and the agent gets a durable memory namespace `agent:<agent-id>`.
This applies to `nullclaw agent --agent <id>`, `/subagents spawn --agent <id>`, and routed sessions resolved through `bindings`.

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
- In the usual `channels.telegram.accounts` form, the object key becomes the account id. For example, `accounts.main` means `account_id = "main"`, and `accounts.backup` means `account_id = "backup"`.
- In `bindings`, `match.account_id` limits that binding to one specific Telegram account.
- If `match.account_id` is omitted, the binding can match any Telegram account for that channel.
- Use different account ids only when you run multiple Telegram bot accounts/tokens in the same nullclaw instance.

Effect on delivery:

- Incoming Telegram updates are processed by the account that received them.
- Routing uses that same `account_id`, so `match.account_id = "main"` matches only messages received by `channels.telegram.accounts.main`.
- Replies go back out through the same Telegram account/runtime that handled the message.
- Setting one binding to `account_id = "main"` and another to `account_id = "sub"` does not split one chat across two agents automatically; it scopes each binding to a different configured Telegram account.

### Full Web Search + Shell Access

Use this when you want full web-search provider control plus unrestricted shell command allowlist behavior:

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

- `http_request.search_base_url` accepts either instance root (`https://host`) or explicit endpoint (`https://host/search`); local/private SearXNG instances may also use plain HTTP such as `http://localhost:8888` or `http://192.168.1.10:8888/search`.
- Invalid `http_request.search_base_url` now fails config validation at startup (no automatic fallback for malformed URL).
- `http_request.search_provider` supports: `auto`, `searxng`, `duckduckgo` (`ddg`), `brave`, `firecrawl`, `tavily`, `perplexity`, `exa`, `jina`.
- `http_request.search_fallback_providers` is optional and is tried in order when the primary provider fails.
- Provider env vars: `BRAVE_API_KEY`, `FIRECRAWL_API_KEY`, `TAVILY_API_KEY`, `PERPLEXITY_API_KEY`, `EXA_API_KEY`, `JINA_API_KEY` (or shared `WEB_SEARCH_API_KEY` where supported). DuckDuckGo and SearXNG do not require API keys.
- `allowed_commands` entries support `"cmd"`, `"cmd *"`, and `"*"` formats.
  - `"cmd"` and `"cmd *"` both allow that command family at the allowlist stage.
  - `"*"` allows any command at the allowlist stage.
- `allowed_paths: ["*"]` allows access outside workspace, except system-protected paths.

### Web UI / Browser Relay

Use `channels.web` for browser UI events (WebChannel v1):

```json
{
  "channels": {
    "web": {
      "accounts": {
        "default": {
          "transport": "local",
          "listen": "127.0.0.1",
          "port": 32123,
          "path": "/ws",
          "auth_token": "replace-with-long-random-token",
          "message_auth_mode": "pairing",
          "allowed_origins": ["http://localhost:5173", "chrome-extension://your-extension-id"]
        }
      }
    }
  }
}
```

- Local: keep `"listen": "127.0.0.1"`.
- `message_auth_mode` controls inbound `user_message` auth:
  - `"pairing"` (default): send `pairing_request`, receive `pairing_result`, include UI `access_token` in every `user_message`.
  - `"token"` (local transport only): include `auth_token` in each `user_message` payload (`access_token` is also accepted for compatibility).
- `auth_token` is optional hardening for WebSocket upgrade and required when binding non-loopback addresses.
- Remote host: set `"listen": "0.0.0.0"` and terminate TLS at proxy/CDN (`wss://...`).
- UI/extension should live in a separate repository and connect via this WebSocket endpoint.
- For orchestration, use local token mode with a stable token from config or env (`NULLCLAW_WEB_TOKEN`, `NULLCLAW_GATEWAY_TOKEN`, `OPENCLAW_GATEWAY_TOKEN`).
- Relay transport (outbound agent socket) is configured via:

```json
{
  "channels": {
    "web": {
      "accounts": {
        "default": {
          "transport": "relay",
          "relay_url": "wss://relay.nullclaw.io/ws/agent",
          "relay_agent_id": "default",
          "relay_token": "replace-with-relay-token",
          "relay_token_ttl_secs": 2592000,
          "relay_pairing_code_ttl_secs": 300,
          "relay_ui_token_ttl_secs": 86400,
          "relay_e2e_required": false
        }
      }
    }
  }
}
```

- Relay token lifecycle (dedicated): `relay_token` (config) -> `NULLCLAW_RELAY_TOKEN` (env) -> persisted `web-relay-<account_id>` credential -> generated token.
- Relay UI handshake: send `pairing_request` with one-time `pairing_code`, receive `pairing_result` with UI `access_token` JWT (and optional `set_cookie` string for relay HTTP layer).
- Relay `user_message` must include valid UI JWT in `access_token` (top-level or `payload.access_token`).
- If E2E is enabled (`relay_e2e_required=true`), UI and agent exchange X25519 keys during pairing and send encrypted payloads in `payload.e2e`.
- WebChannel event envelope is defined in [`spec/webchannel_v1.json`](spec/webchannel_v1.json).

## Gateway API

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | None | Health check (always public) |
| `/pair` | POST | `X-Pairing-Code` header | Exchange one-time code for bearer token |
| `/webhook` | POST | `Authorization: Bearer <token>` | Send message: `{"message": "your prompt"}` |
| `/.well-known/agent-card.json` | GET | None | A2A Agent Card discovery (public) |
| `/a2a` | POST | `Authorization: Bearer <token>` | A2A JSON-RPC endpoint (canonical methods plus legacy slash aliases) |
| `/whatsapp` | GET | Query params | Meta webhook verification |
| `/whatsapp` | POST | None (Meta signature) | WhatsApp incoming message webhook |

### A2A

Enable the gateway binding with:

```json
{
  "a2a": {
    "enabled": true,
    "name": "nullclaw",
    "description": "General-purpose AI assistant",
    "url": "https://example.com",
    "version": "1.0.0"
  }
}
```

- Discover the agent card at `/.well-known/agent-card.json`.
- Send JSON-RPC requests to `/a2a` using a bearer token obtained from `/pair`.
- Canonical JSON-RPC methods: `SendMessage`, `SendStreamingMessage`, `GetTask`, `CancelTask`, `ListTasks`, `SubscribeToTask`.
- Legacy slash aliases remain accepted for compatibility: `message/send`, `message/stream`, `tasks/get`, `tasks/cancel`, `tasks/list`, `tasks/resubscribe`.

## Commands

| Command | Description |
|---------|-------------|
| `onboard --api-key sk-... --provider openrouter` | Quick setup with API key and provider |
| `onboard --interactive` | Full interactive wizard |
| `onboard --channels-only` | Reconfigure channels/allowlists only |
| `agent -m "..."` | Single message mode |
| `agent` | Interactive chat mode |
| `gateway` | Start long-running runtime (default: `127.0.0.1:3000`) |
| `service install\|start\|stop\|restart\|status\|uninstall` | Manage background service |
| `doctor` | Diagnose system health |
| `status` | Show full system status |
| `channel list\|start\|status\|add\|remove` | Manage channels |
| `cron list\|add\|add-agent\|once\|once-agent\|remove\|pause\|resume\|run\|update\|runs` | Manage scheduled tasks |
| `skills list\|install\|remove\|info` | Manage skill packs |
| `history list\|show` | View session conversation history |
| `memory stats\|count\|reindex\|search\|get\|list\|drain-outbox\|forget` | Inspect and maintain memory |
| `hardware scan\|flash\|monitor` | Hardware device management |
| `models list\|info\|benchmark\|refresh` | Model catalog |
| `workspace edit\|reset-md` | Maintain workspace markdown/bootstrap files |
| `capabilities [--json]` | Show runtime capabilities manifest |
| `auth login\|status\|logout` | Manage OAuth authentication |
| `migrate openclaw [--dry-run] [--source PATH]` | Import memory + migrate config from OpenClaw |
| `update [--check] [--yes]` | Check for and install updates |

## Development

Build and tests are pinned to **Zig 0.15.2**.

```bash
zig build                          # Dev build
zig build -Doptimize=ReleaseSmall  # Release build (678 KB)
zig build test --summary all       # 5,300+ tests
```

### Channel Flow Coverage

Channel CJM coverage (ingress parsing/filtering, session key routing, account propagation, bus handoff) is validated by tests in:

- `src/channel_manager.zig` (runtime channel registration/start semantics + listener mode wiring)
- `src/config.zig` (OpenClaw-compatible `channels.*.accounts` parsing, multi-account selection/ordering, aliases)
- `src/gateway.zig` (Telegram/WhatsApp/LINE/Lark routed session keys from webhook payloads)
- `src/daemon.zig` (gateway-loop inbound route resolution for Discord/QQ/OneBot/Mattermost/MaixCam)
- `src/channels/discord.zig`, `src/channels/mattermost.zig`, `src/channels/qq.zig`, `src/channels/onebot.zig`, `src/channels/signal.zig`, `src/channels/line.zig`, `src/channels/whatsapp.zig` (per-channel inbound/outbound contracts)

### Project Stats

```
Language:     Zig 0.15.2
Source files: ~250
Lines of code: ~249,000
Tests:        5,300+
Binary:       678 KB (ReleaseSmall)
Peak RSS:     ~1 MB
Startup:      <2 ms (Apple Silicon)
Dependencies: 0 (besides libc + optional SQLite)
```

### Source Layout

```
src/
  main.zig              CLI entry point + argument parsing
  root.zig              Module hierarchy (public API)
  config.zig            JSON config loader + 30 sub-config structs
  agent.zig             Agent loop, auto-compaction, tool dispatch
  daemon.zig            Daemon supervisor with exponential backoff
  gateway.zig           HTTP gateway (rate limiting, idempotency, pairing)
  channels/             19 channel implementations (telegram, signal, discord, slack, nostr, matrix, whatsapp, line, lark, onebot, mattermost, qq, ...)
  providers/            50+ AI provider integrations
  memory/               SQLite backend, embeddings, vector search, hygiene, snapshots
  tools/                35+ tool implementations
  security/             Secrets (ChaCha20), sandbox backends (landlock, firejail, ...)
  cron.zig              Cron scheduler with JSON persistence
  health.zig            Component health registry
  tunnel.zig            Tunnel vtable (cloudflare, ngrok, tailscale, custom)
  peripherals.zig       Hardware peripheral vtable (serial, Arduino, RPi, Nucleo)
  runtime.zig           Runtime vtable (native, docker, WASM)
  skillforge.zig        Skill discovery (GitHub), evaluation, integration
  ...
```

## Versioning

nullclaw uses **CalVer** (`YYYY.M.D`) for releases — e.g. `v2026.2.20`.

- **Tag format:** `vYYYY.M.D` (one release per day max; patch suffix `vYYYY.M.D.N` if needed)
- **Release binaries derive their embedded version from the git tag** (`v...` -> `nullclaw --version`)
- **Non-release builds default to `dev`** unless you override with `zig build -Dversion=...`
- **No stability guarantees yet** — the project is pre-1.0, config and CLI may change between releases
- **`nullclaw --version`** prints the current version

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development environment setup, workflow, validation commands, and the PR checklist.

Implement a vtable interface, submit a PR:

- New `Provider` -> `src/providers/`
- New `Channel` -> `src/channels/`
- New `Tool` -> `src/tools/`
- New `Memory` backend -> `src/memory/`
- New `Tunnel` -> `src/tunnel.zig`
- New `Sandbox` backend -> `src/security/`
- New `Peripheral` -> `src/peripherals.zig`
- New `Skill` -> `~/.nullclaw/workspace/skills/<name>/`

## Chinese Docs (中文文档)

- [Chinese docs overview (中文文档总览)](docs/zh/README.md)
- [Installation guide (安装指南)](docs/zh/installation.md)
- [Configuration guide (配置指南)](docs/zh/configuration.md)
- [Usage and operations (使用与运维)](docs/zh/usage.md)
- [Architecture overview (架构总览)](docs/zh/architecture.md)
- [Security model (安全机制)](docs/zh/security.md)
- [Gateway API (中文)](docs/zh/gateway-api.md)
- [Commands reference (命令参考)](docs/zh/commands.md)
- [Development guide (开发指南)](docs/zh/development.md)

## English Docs

- [English docs overview](docs/en/README.md)
- [Installation](docs/en/installation.md)
- [Configuration](docs/en/configuration.md)
- [Usage and operations](docs/en/usage.md)
- [Architecture](docs/en/architecture.md)
- [Security](docs/en/security.md)
- [Gateway API](docs/en/gateway-api.md)
- [Commands](docs/en/commands.md)
- [Development](docs/en/development.md)

## Disclaimer

nullclaw is a pure open-source software project. It has **no token, no cryptocurrency, no blockchain component, and no financial instrument** of any kind. This project is not affiliated with any token or financial product.

## License

MIT — see [LICENSE](LICENSE)

---

**nullclaw** — Null overhead. Null compromise. Deploy anywhere. Swap anything.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=nullclaw/nullclaw&type=date&legend=top-left)](https://www.star-history.com/#nullclaw/nullclaw&type=date&legend=top-left)
