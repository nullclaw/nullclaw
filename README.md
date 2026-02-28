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
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
</p>

The smallest fully autonomous AI assistant infrastructure — a static Zig binary that fits on any $5 board, boots in milliseconds, and requires nothing but libc.

```
678 KB binary · <2 ms startup · 3,230+ tests · 22+ providers · 18 channels · Pluggable everything
```

### Features

- **Impossibly Small:** 678 KB static binary — no runtime, no VM, no framework overhead.
- **Near-Zero Memory:** ~1 MB peak RSS. Runs comfortably on the cheapest ARM SBCs and microcontrollers.
- **Instant Startup:** <2 ms on Apple Silicon, <8 ms on a 0.8 GHz edge core.
- **True Portability:** Single self-contained binary across ARM, x86, and RISC-V. Drop it anywhere, it just runs.
- **Feature-Complete:** 22+ providers, 18 channels, 18+ tools, hybrid vector+FTS5 memory, multi-layer sandbox, tunnels, hardware peripherals, MCP, subagents, streaming, voice — the full stack.

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
| **Binary Size** | ~28 MB (dist) | N/A (Scripts) | ~8 MB | 3.4 MB | **678 KB** |
| **Tests** | — | — | — | 1,017 | **3,230+** |
| **Source Files** | ~400+ | — | — | ~120 | **~110** |
| **Cost** | Mac Mini $599 | Linux SBC ~$50 | Linux Board $10 | Any $10 hardware | **Any $5 hardware** |

> Measured with `/usr/bin/time -l` on ReleaseSmall builds. nullclaw is a static binary with zero runtime dependencies.

Reproduce locally:

```bash
zig build -Doptimize=ReleaseSmall
ls -lh zig-out/bin/nullclaw

/usr/bin/time -l zig-out/bin/nullclaw --help
/usr/bin/time -l zig-out/bin/nullclaw status
```

## Quick Start

> **Prerequisite:** use **Zig 0.15.2** (exact version).
> `0.16.0-dev` and other Zig versions are currently unsupported and may fail to build.
> Verify before building: `zig version` should print `0.15.2`.

```bash
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig build -Doptimize=ReleaseSmall

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
nullclaw service install
nullclaw service status

# Migrate memory from OpenClaw
nullclaw migrate openclaw --dry-run
nullclaw migrate openclaw
```

> **Dev fallback (no global install):** prefix commands with `zig-out/bin/` (example: `zig-out/bin/nullclaw status`).

## Edge MVP (Hybrid Host + WASM Logic)

If you want edge deployment (Cloudflare Worker) with Telegram + OpenAI while keeping agent policy in WASM, see:

`examples/edge/cloudflare-worker/`

This pattern keeps networking/secrets in the edge host and lets you swap/update logic by replacing a tiny Zig WASM module.

## Architecture

Every subsystem is a **vtable interface** — swap implementations with a config change, zero code changes.

| Subsystem | Interface | Ships with | Extend |
|-----------|-----------|------------|--------|
| **AI Models** | `Provider` | 22+ providers (OpenRouter, Anthropic, OpenAI, Ollama, Venice, Groq, Mistral, xAI, DeepSeek, Together, Fireworks, Perplexity, Cohere, Bedrock, etc.) | `custom:https://your-api.com` — any OpenAI-compatible API |
| **Channels** | `Channel` | CLI, Telegram, Signal, Discord, Slack, iMessage, Matrix, WhatsApp, Webhook, IRC, Lark/Feishu, OneBot, Line, DingTalk, Email, Nostr, QQ, MaixCam, Mattermost | Any messaging API |
| **Memory** | `Memory` | SQLite with hybrid search (FTS5 + vector cosine similarity), Markdown | Any persistence backend |
| **Tools** | `Tool` | shell, file_read, file_write, file_edit, memory_store, memory_recall, memory_forget, browser_open, screenshot, composio, http_request, hardware_info, hardware_memory, and more | Any capability |
| **Observability** | `Observer` | Noop, Log, File, Multi | Prometheus, OTel |
| **Runtime** | `RuntimeAdapter` | Native, Docker (sandboxed), WASM (wasmtime) | Any runtime |
| **Security** | `Sandbox` | Landlock, Firejail, Bubblewrap, Docker, auto-detect | Any sandbox backend |
| **Identity** | `IdentityConfig` | OpenClaw (markdown), AIEOS v1.1 (JSON) | Any identity format |
| **Tunnel** | `Tunnel` | None, Cloudflare, Tailscale, ngrok, Custom | Any tunnel binary |
| **Heartbeat** | Engine | HEARTBEAT.md periodic tasks | — |
| **Skills** | Loader | TOML manifests + SKILL.md instructions | Community skill packs |
| **Peripherals** | `Peripheral` | Serial, Arduino, Raspberry Pi GPIO, STM32/Nucleo | Any hardware interface |
| **Cron** | Scheduler | Cron expressions + one-shot timers with JSON persistence | — |

### Memory System

All custom, zero external dependencies:

| Layer | Implementation |
|-------|---------------|
| **Vector DB** | Embeddings stored as BLOB in SQLite, cosine similarity search |
| **Keyword Search** | FTS5 virtual tables with BM25 scoring |
| **Hybrid Merge** | Weighted merge (configurable vector/keyword weights) |
| **Embeddings** | `EmbeddingProvider` vtable — OpenAI, custom URL, or noop |
| **Hygiene** | Automatic archival + purge of stale memories |
| **Snapshots** | Export/import full memory state for migration |

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

```json
{
  "default_temperature": 0.7,

  "models": {
    "providers": {
      "openrouter": { "api_key": "sk-or-..." },
      "groq": { "api_key": "gsk_..." },
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
    "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"] }
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

- `http_request.search_base_url` accepts either instance root (`https://host`) or explicit endpoint (`https://host/search`).
- Invalid `http_request.search_base_url` now fails config validation at startup (no automatic fallback for malformed URL).
- `http_request.search_provider` supports: `auto`, `searxng`, `duckduckgo` (`ddg`), `brave`, `firecrawl`, `tavily`, `perplexity`, `exa`, `jina`.
- `http_request.search_fallback_providers` is optional and is tried in order when the primary provider fails.
- Provider env vars: `BRAVE_API_KEY`, `FIRECRAWL_API_KEY`, `TAVILY_API_KEY`, `PERPLEXITY_API_KEY`, `EXA_API_KEY`, `JINA_API_KEY` (or shared `WEB_SEARCH_API_KEY` where supported). DuckDuckGo and SearXNG do not require API keys.
- `allowed_commands: ["*"]` enables wildcard command allowlist matching.
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
          "allowed_origins": ["http://localhost:5173", "chrome-extension://your-extension-id"]
        }
      }
    }
  }
}
```

- Local: keep `"listen": "127.0.0.1"`.
- Local and relay use the same pairing flow: send `pairing_request`, receive `pairing_result`, then include UI `access_token` in every `user_message`.
- `auth_token` is optional hardening for WebSocket upgrade and required when binding non-loopback addresses.
- Remote host: set `"listen": "0.0.0.0"` and terminate TLS at proxy/CDN (`wss://...`).
- UI/extension should live in a separate repository and connect via this WebSocket endpoint.
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
| `/whatsapp` | GET | Query params | Meta webhook verification |
| `/whatsapp` | POST | None (Meta signature) | WhatsApp incoming message webhook |

## Commands

| Command | Description |
|---------|-------------|
| `onboard --api-key sk-... --provider openrouter` | Quick setup with API key and provider |
| `onboard --interactive` | Full interactive wizard |
| `onboard --channels-only` | Reconfigure channels/allowlists only |
| `agent -m "..."` | Single message mode |
| `agent` | Interactive chat mode |
| `gateway` | Start long-running runtime (default: `127.0.0.1:3000`) |
| `service install\|start\|stop\|status\|uninstall` | Manage background service |
| `doctor` | Diagnose system health |
| `status` | Show full system status |
| `channel status` | Show channel health/status |
| `cron list\|add\|remove\|pause\|resume\|run` | Manage scheduled tasks |
| `skills list\|install\|remove\|info` | Manage skill packs |
| `hardware scan\|flash\|monitor` | Hardware device management |
| `models list\|info\|benchmark` | Model catalog |
| `migrate openclaw [--dry-run] [--source PATH]` | Import memory + migrate config from OpenClaw |

## Development

Build and tests are pinned to **Zig 0.15.2**.

```bash
zig build                          # Dev build
zig build -Doptimize=ReleaseSmall  # Release build (678 KB)
zig build test --summary all       # 3,230+ tests
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
Source files: ~110
Lines of code: ~45,000
Tests:        3,230+
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
  providers/            22+ AI provider implementations
  memory/               SQLite backend, embeddings, vector search, hygiene, snapshots
  tools/                18 tool implementations
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
- **No stability guarantees yet** — the project is pre-1.0, config and CLI may change between releases
- **`nullclaw --version`** prints the current version

## Contributing

Implement a vtable interface, submit a PR:

- New `Provider` -> `src/providers/`
- New `Channel` -> `src/channels/`
- New `Tool` -> `src/tools/`
- New `Memory` backend -> `src/memory/`
- New `Tunnel` -> `src/tunnel.zig`
- New `Sandbox` backend -> `src/security/`
- New `Peripheral` -> `src/peripherals.zig`
- New `Skill` -> `~/.nullclaw/workspace/skills/<name>/`

## Disclaimer

nullclaw is a pure open-source software project. It has **no token, no cryptocurrency, no blockchain component, and no financial instrument** of any kind. This project is not affiliated with any token or financial product.

## License

MIT — see [LICENSE](LICENSE)

---

**nullclaw** — Null overhead. Null compromise. Deploy anywhere. Swap anything.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=nullclaw/nullclaw&type=date&legend=top-left)](https://www.star-history.com/#nullclaw/nullclaw&type=date&legend=top-left)
