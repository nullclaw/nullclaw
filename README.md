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
678 KB binary · <2 ms startup · 3,230+ tests · 22+ providers · 17 channels · Pluggable everything
```

### Features

- **Impossibly Small:** 678 KB static binary — no runtime, no VM, no framework overhead.
- **Near-Zero Memory:** ~1 MB peak RSS. Runs comfortably on the cheapest ARM SBCs and microcontrollers.
- **Instant Startup:** <2 ms on Apple Silicon, <8 ms on a 0.8 GHz edge core.
- **True Portability:** Single self-contained binary across ARM, x86, and RISC-V. Drop it anywhere, it just runs.
- **Feature-Complete:** 22+ providers, 17 channels, 18+ tools, hybrid vector+FTS5 memory, multi-layer sandbox, tunnels, hardware peripherals, MCP, subagents, streaming, voice — the full stack.

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

# Start the gateway (webhook server)
nullclaw gateway                # default: 127.0.0.1:3000
nullclaw gateway --port 8080    # custom port

# Start full autonomous runtime
nullclaw daemon

# Check status
nullclaw status

# Run system diagnostics
nullclaw doctor

# Check channel health
nullclaw channel doctor

# Manage background service
nullclaw service install
nullclaw service status

# Migrate memory from OpenClaw
nullclaw migrate openclaw --dry-run
nullclaw migrate openclaw
```

> **Dev fallback (no global install):** prefix commands with `zig-out/bin/` (example: `zig-out/bin/nullclaw status`).

## Architecture

Every subsystem is a **vtable interface** — swap implementations with a config change, zero code changes.

| Subsystem | Interface | Ships with | Extend |
|-----------|-----------|------------|--------|
| **AI Models** | `Provider` | 22+ providers (OpenRouter, Anthropic, OpenAI, Ollama, Venice, Groq, Mistral, xAI, DeepSeek, Together, Fireworks, Perplexity, Cohere, Bedrock, etc.) | `custom:https://your-api.com` — any OpenAI-compatible API |
| **Channels** | `Channel` | CLI, Telegram, Signal, Discord, Slack, WhatsApp, Line, Lark/Feishu, OneBot, QQ, Matrix, IRC, iMessage, Email, DingTalk, MaixCam, Webhook | Any messaging API |
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

## Configuration

Config: `~/.nullclaw/config.json` (created by `onboard`)

> **OpenClaw compatible:** nullclaw uses the same config structure as [OpenClaw](https://github.com/openclaw/openclaw) (snake_case). Providers live under `models.providers`, the default model under `agents.defaults.model.primary`, and channels use `accounts` wrappers.

```json
{
  "default_provider": "openrouter",
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
      "model": { "primary": "anthropic/claude-sonnet-4" },
      "heartbeat": { "every": "30m" }
    },
    "list": [
      { "id": "researcher", "model": { "primary": "anthropic/claude-opus-4" }, "system_prompt": "..." }
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
| `gateway` | Start webhook server (default: `127.0.0.1:3000`) |
| `daemon` | Start long-running autonomous runtime |
| `service install\|start\|stop\|status\|uninstall` | Manage background service |
| `doctor` | Diagnose system health |
| `status` | Show full system status |
| `channel doctor` | Run channel health checks |
| `cron list\|add\|remove\|pause\|resume\|run` | Manage scheduled tasks |
| `skills list\|install\|remove\|info` | Manage skill packs |
| `hardware scan\|flash\|monitor` | Hardware device management |
| `models list\|info\|benchmark` | Model catalog |
| `migrate openclaw [--dry-run] [--source PATH]` | Import memory from OpenClaw workspace |

## Development

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
Language:     Zig 0.15
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
  channels/             18 channel implementations (telegram, signal, matrix, mattermost, discord, slack, whatsapp, line, lark, onebot, qq, ...)
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
