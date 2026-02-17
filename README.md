<p align="center">
  <img src="nullclaw.png" alt="nullclaw" width="200" />
</p>

<h1 align="center">NullClaw</h1>

<p align="center">
  <strong>Null overhead. Null compromise. 100% Zig. 100% Agnostic.</strong><br>
  <strong>678 KB binary. ~1 MB RAM. Boots in <2 ms. Runs on anything with a CPU.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
</p>

The smallest fully autonomous AI assistant infrastructure — a complete Zig rewrite of [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw), 5x smaller binary, same feature set.

```
678 KB binary · <2 ms startup · 1,653 tests · 22+ providers · 11 channels · Pluggable everything
```

### Features

- **Impossibly Small:** 678 KB static binary — 5x smaller than ZeroClaw, 44x smaller than OpenClaw.
- **Near-Zero Memory:** ~1 MB peak RSS — 5,000x less than OpenClaw, 5x less than ZeroClaw.
- **Instant Startup:** <2 ms on Apple Silicon, <8 ms on a 0.8 GHz edge core.
- **True Portability:** Single self-contained binary across ARM, x86, and RISC-V. No runtime, no VM, no dependencies.
- **Feature-Complete:** All 22+ providers, 11 channels, 18 tools, hybrid memory, sandbox, tunnels, peripherals — everything ZeroClaw has.

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
| **Tests** | — | — | — | 1,017 | **1,653** |
| **Source Files** | ~400+ | — | — | ~120 | **96** |
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
| **Channels** | `Channel` | CLI, Telegram, Discord, Slack, iMessage, Matrix, WhatsApp, Webhook, IRC, Lark/Feishu, DingTalk | Any messaging API |
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

```json
{
  "api_key": "sk-...",
  "default_provider": "openrouter",
  "default_model": "anthropic/claude-sonnet-4",
  "default_temperature": 0.7,

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
    "max_actions_per_hour": 20,
    "max_cost_per_day_cents": 500
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

  "heartbeat": {
    "enabled": false,
    "interval_minutes": 30
  },

  "tunnel": {
    "provider": "none"
  },

  "secrets": {
    "encrypt": true
  },

  "identity": {
    "format": "openclaw"
  },

  "cost": {
    "enabled": false,
    "daily_limit_usd": 10.0,
    "monthly_limit_usd": 100.0
  },

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
| `onboard` | Quick setup (default) |
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
| `migrate openclaw` | Import from OpenClaw |

## Development

```bash
zig build                          # Dev build
zig build -Doptimize=ReleaseSmall  # Release build (678 KB)
zig build test --summary all       # 1,653 tests
```

### Project Stats

```
Language:     Zig 0.15
Source files: 96
Lines of code: 36,197
Tests:        1,653
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
  channels/             11 channel implementations (telegram, discord, slack, ...)
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
