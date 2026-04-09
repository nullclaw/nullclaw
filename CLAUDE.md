# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Mandatory Reference

Read `AGENTS.md` before any code change. It is the authoritative engineering protocol covering architecture, naming conventions, anti-patterns, change playbooks, and validation requirements.

## Quick Reference

```bash
zig build                           # dev build
zig build -Doptimize=ReleaseSmall   # release build
zig build test --summary all        # run all 6,300+ tests (must pass with 0 leaks)
zig fmt --check src/                # check formatting (pre-commit hook)
```

For build flags, git hooks, Zig 0.15.2 API gotchas, testing conventions, and engineering principles, see `AGENTS.md`.

### Build Flags

```bash
zig build -Dchannels=telegram,cli   # compile only specific channels (default: all)
zig build -Dengines=base,sqlite     # compile only specific memory engines (default: base,sqlite)
zig build -Dtarget=x86_64-linux-musl  # cross-compile for target triple
zig build -Dversion=2026.3.1        # override CalVer version string
```

Channel tokens: `all`, `none`, or comma-separated names (`cli`, `telegram`, `discord`, `slack`, `signal`, `matrix`, `web`, `nostr`, `irc`, `email`, `imessage`, `whatsapp`, `mattermost`, `lark`, `dingtalk`, `line`, `onebot`, `qq`, `maixcam`).

Engine tokens: `base`/`minimal` (enables `none`, `markdown`, `memory`, `api`), `sqlite`, `lucid`, `redis`, `lancedb`, `postgres`, `all`.

## Project Overview

NullClaw is an autonomous AI assistant runtime written in Zig 0.15.2. ~2.7 MB minimal binary, ~1 MB peak RSS, <2 ms startup. Only two external dependencies: vendored SQLite (build-time SHA256 verification) and `websocket.zig` (pinned commit). See `AGENTS.md` section 1 for full project snapshot.

## Module Initialization Order

Defined in `src/root.zig`. Phases mirror deployment dependencies:

1. **Core**: `bus`, `config`, `util`, `platform`, `version`, `state`, `json_util`, `http_util`
2. **Agent**: `agent`, `session`, `providers`, `memory`
3. **Networking**: `gateway`, `channels`
4. **Extensions**: `security`, `cron`, `health`, `tools`, `identity`, `cost`, `observability`, `heartbeat`, `runtime`, `mcp`, `subagent`, `auth`, `multimodal`, `agent_routing`
5. **Hardware/Integrations**: `hardware`, `peripherals`, `rag`, `skillforge`, `tunnel`, `voice`

## Key Entry Points

- `src/main.zig` - CLI command routing (`agent`, `gateway`, `onboard`, `doctor`, `status`, `service`, `cron`, `channel`, `memory`, `skills`, `hardware`, `migrate`, `workspace`, `capabilities`, `models`, `auth`, `update`, `history`)
- `src/root.zig` - Module hierarchy and public API exports (also serves as library root)
- `src/config.zig` - JSON config loading (~30 sub-config structs from `config_types.zig`, loads from `~/.nullclaw/config.json`)
- `src/agent.zig` - Agent orchestration (delegates to `src/agent/root.zig`)
- `src/gateway.zig` - HTTP gateway server (rate limiting, pairing, webhooks)
- `src/daemon.zig` - Supervisor with exponential backoff for gateway mode

## Subsystem Directories

- `src/providers/` - 12 core implementations + 92+ OpenAI-compatible services via `compatible.zig`. Factory in `factory.zig`.
- `src/channels/` - 24 channel implementations. Each implements `Channel.VTable`. Factory in `root.zig`.
- `src/tools/` - 38+ tool implementations. Each implements `Tool.VTable`. Factory in `root.zig`.
- `src/memory/` - Layered: **engines** (SQLite, Markdown, LRU, Redis, PostgreSQL, LanceDB, Lucid, ClickHouse, API, None) and **retrieval** (hybrid search, RRF, embeddings). Conditionally compiled via build flags.
- `src/security/` - Policy (`policy.zig`), pairing (`pairing.zig`), secrets (`secrets.zig`), sandbox backends (`landlock.zig`, `firejail.zig`, `bubblewrap.zig`, `docker.zig`, `detect.zig`).
- `src/agent/` - Agent loop internals: `dispatcher.zig`, `compaction.zig`, `prompt.zig`, `memory_loader.zig`, `commands.zig`. Config defaults: `max_tool_iterations = 1000`, `max_history_messages = 100` (see `src/config_types.zig`).

## Dependency Direction

Concrete implementations depend inward on vtable interfaces, config, and util. Never import across subsystems (e.g., provider code must not import channel internals).

## Config System

Config loads from `~/.nullclaw/config.json`. Runtime overrides via `NULLCLAW_*` env vars (see `Config.applyEnvOverrides()` in `src/config.zig`). Types in `src/config_types.zig`, re-exported from `src/config.zig`.

`Config.load()` heap-allocates an internal `ArenaAllocator`. Always call `defer cfg.deinit()`. In tests:

```zig
var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
defer arena.deinit();
var cfg = try Config.load(arena.allocator());
defer cfg.deinit();
```

Key sections: `models.providers`, `agents`, `channels`, `memory`, `gateway`, `security`, `autonomy`, `runtime`.

## Versioning

CalVer format: `YYYY.M.D` (e.g., `v2026.2.26`). Defined in `build.zig.zon`.

## CI

Tests run on Ubuntu (x86_64), macOS (aarch64), and Windows (x86_64). Release builds target 7 platforms including linux-riscv64. Docker images published to ghcr.io (linux/amd64, linux/arm64).

## Docker

Multi-stage build: Alpine builder with Zig, then minimal Alpine runtime. Runs as non-root (uid 65534) by default.

```bash
docker-compose --profile gateway up   # HTTP gateway daemon
docker-compose --profile agent up     # interactive agent
```

## Nix

`flake.nix` provides a dev shell with Zig and ZLS. Activate with `direnv allow` (uses `.envrc`).

## License

MIT License.
