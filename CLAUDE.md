# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Mandatory Reference

Read `AGENTS.md` before any code change. It is the authoritative engineering protocol covering architecture, naming conventions, anti-patterns, change playbooks, and validation requirements.

## Build & Test Commands

Quick reference. The normative version, including the validation matrix, is
`AGENTS.md` §1 and §8.

```bash
# Requires exactly Zig 0.16.0 (verify: zig version)
zig build                           # dev build
zig build -Doptimize=ReleaseSmall   # release build
zig build test --summary all        # full suite (must pass with 0 leaks)
zig fmt src/                        # format all source files
zig fmt --check src/                # check formatting (used by pre-commit hook)
```

Primary validation command is `zig build test --summary all` (project-wide). Individual files can still be run with `zig test <file>.zig` when needed.

### Build Flags

```bash
zig build -Dchannels=telegram,cli   # compile only specific channels (default: all)
zig build -Dengines=base,sqlite     # compile only specific memory engines (default: base,sqlite)
zig build -Dtarget=x86_64-linux-musl  # cross-compile for target triple
zig build -Dversion=2026.3.1        # override CalVer version string
```

Channel tokens: `all`, `none`, or comma-separated names (`cli`, `telegram`, `discord`, `slack`, `signal`, `matrix`, `web`, `nostr`, `irc`, `email`, `imessage`, `whatsapp`, `mattermost`, `lark`, `dingtalk`, `line`, `onebot`, `qq`, `maixcam`).

Engine tokens: `base`/`minimal` (enables `none`, `markdown`, `memory`, `api`), `sqlite`, `lucid`, `redis`, `lancedb`, `postgres`, `all`.

## Git Hooks

Activate once per clone with `git config core.hooksPath .githooks`. What each
hook runs is documented in `AGENTS.md` §8.2.

## Project Overview

NullClaw is an autonomous AI assistant runtime written in Zig 0.16.0. The
project snapshot, hard constraints, and dependency policy live in `AGENTS.md`
§1 — they are maintained there, not here.

## Architecture

The entire codebase is **vtable-driven**. All major subsystems use `ptr: *anyopaque` + `vtable: *const VTable` for pluggable implementations. Extending NullClaw means implementing a vtable struct and registering it in the subsystem's factory (see `AGENTS.md` section 7 for playbooks).

**Critical ownership rule**: callers must OWN the implementing struct (local var or heap-alloc). Never return a vtable interface pointing to a temporary -- the pointer will dangle.

### Module Initialization Order

Defined in `src/root.zig`. Phases mirror deployment dependencies:

1. **Core**: `bus`, `config`, `util`, `platform`, `version`, `state`, `json_util`, `http_util`
2. **Agent**: `agent`, `session`, `providers`, `memory`
3. **Networking**: `gateway`, `channels`
4. **Extensions**: `security`, `cron`, `health`, `tools`, `identity`, `cost`, `observability`, `heartbeat`, `runtime`, `mcp`, `subagent`, `auth`, `multimodal`, `agent_routing`
5. **Hardware/Integrations**: `hardware`, `peripherals`, `rag`, `skillforge`, `tunnel`, `voice`

### Key Entry Points

- `src/main.zig` - CLI command routing (`agent`, `gateway`, `onboard`, `doctor`, `status`, `service`, `cron`, `channel`, `memory`, `skills`, `hardware`, `migrate`, `workspace`, `capabilities`, `models`, `auth`, `update`, `history`)
- `src/root.zig` - Module hierarchy and public API exports (also serves as library root)
- `src/config.zig` - JSON config loading (~30 sub-config structs from `config_types.zig`, loads from `~/.nullclaw/config.json`)
- `src/agent.zig` - Agent orchestration (delegates to `src/agent/root.zig`)
- `src/gateway.zig` - HTTP gateway server (rate limiting, pairing, webhooks)
- `src/daemon.zig` - Supervisor with exponential backoff for gateway mode

### Subsystem Directories

- `src/providers/` - AI model providers. 9 core implementations + 41+ OpenAI-compatible services via `compatible.zig`. Factory in `factory.zig`, single source of truth for provider URLs and auth styles.
- `src/channels/` - Messaging channels. Each implements `Channel.VTable` (`start`, `stop`, `send`, `name`, `healthCheck`). Factory in `root.zig`.
- `src/tools/` - Tool implementations. Each implements `Tool.VTable` (`execute`, `name`, `description`, `parameters_json`). Tools receive args as `JsonObjectMap` and return `ToolResult`. Factory in `root.zig`.
- `src/memory/` - Layered architecture: **engines** (SQLite, Markdown, LRU, Redis, PostgreSQL, LanceDB, Lucid, ClickHouse, API, None) and **retrieval** (hybrid search, RRF, embeddings). Engines conditionally compiled via build flags.
- `src/security/` - Policy enforcement (`policy.zig`), pairing (`pairing.zig`), encrypted secrets (`secrets.zig`), sandbox backends (`landlock.zig`, `firejail.zig`, `bubblewrap.zig`, `docker.zig`, `detect.zig`).
- `src/agent/` - Agent loop internals: `dispatcher.zig` (tool call parsing), `compaction.zig` (history trimming), `prompt.zig` (system prompt builder), `memory_loader.zig` (context injection), `commands.zig` (agent-mode commands). Config defaults are `max_tool_iterations = 1000` and `max_history_messages = 100` (see `src/config_types.zig`).

### Provider Boundary Notes

- Keep canonical tool names in the runtime and prompt layer. Provider-specific quirks should be normalized at the provider boundary when possible.
- `src/providers/ollama.zig` already normalizes common local-model tool-name drift such as `tool.shell` -> `shell`, `tools.file_read` -> `file_read`, and `scheduler_tool` / `schedule_tool` -> `schedule`.
- If a local model invents another wrapper-style tool name, prefer extending the Ollama normalization helper and adding a regression test instead of teaching alternate names to the tool registry or prompt text.

### Dependency Direction

Concrete implementations depend inward on vtable interfaces, config, and util. Never import across subsystems (e.g., provider code must not import channel internals).

## Config System

Config loads from `~/.nullclaw/config.json`. Runtime behavior is then adjusted by `NULLCLAW_*` environment overrides (see `Config.applyEnvOverrides()` in `src/config.zig`). Types are defined in `src/config_types.zig` and re-exported from `src/config.zig`.

`Config.load()` heap-allocates an internal `ArenaAllocator`. Always call `defer cfg.deinit()` to free. In tests, wrap in a parent arena:

```zig
var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
defer arena.deinit();
var cfg = try Config.load(arena.allocator());
defer cfg.deinit();
```

Key config sections: `models.providers` (API keys/endpoints), `agents` (named agent configs), `channels` (per-channel settings), `memory` (backend/search/lifecycle), `gateway` (port/host/pairing), `security` (sandbox/audit/autonomy), `autonomy` (level/limits/allowlists), `runtime` (native/docker/wasm).

## Zig 0.16.0 API Gotchas

Maintained in **`AGENTS.md` §2.4** (API baseline: `std.io.getStdOut()`,
HTTP client, child processes, stdout, SQLite linkage, `ArrayListUnmanaged`) and
**`AGENTS.md` §10** (anti-patterns: `SQLITE_TRANSIENT`, `ChaCha20Poly1305`
decrypt buffers, `ArrayListUnmanaged.writer`).

They are not repeated here on purpose. Two files restating the same rules is how
the Zig pin drifted to `0.15.2` in one place while the build used `0.16.0`.

When unsure about an API, search `src/` for existing usage rather than guessing.

## Search Zig Source

Run `zig env` to locate Zig source directories. `.std_dir` points to the standard library, `.lib_dir` to the broader lib tree. Read the source directly to verify struct fields, function signatures, and available methods.

## Testing Conventions

The normative rules are `AGENTS.md` §3.6 (determinism) and §8.1 (test coverage
mandate). Repository-specific conventions, which are not in AGENTS.md:

- Vendored SQLite hashes are validated at build time.
- Use `std.testing.tmpDir(.{})` with `defer tmp.cleanup()` for file-based test fixtures.
- Contract tests in `src/memory/engines/contract_test.zig` verify all memory backends satisfy the same vtable invariants. Follow this pattern when adding new backends.
- Test helpers (e.g., `TestHelper` structs with `dummyConfig()` / `initTestChannel()`) are defined within each module. Prefer this pattern over shared test utilities.
- Test naming: `subject_expected_behavior` (e.g., `"sendUrl constructs correct URL"`).

## Versioning

CalVer format: `YYYY.M.D` (e.g., `v2026.2.26`). Defined in `build.zig.zon`.

## CI

Tests run on Ubuntu (x86_64), macOS (aarch64), and Windows (x86_64). Release builds target 7 platforms including linux-riscv64. Docker images published to ghcr.io (linux/amd64, linux/arm64).

## Docker

Multi-stage build: Alpine builder with Zig, then minimal Alpine runtime. Runs as non-root (uid 65534) by default. Use `--target release-root` for root access.

```bash
docker-compose --profile gateway up   # HTTP gateway daemon
docker-compose --profile agent up     # interactive agent
```

## Nix

`flake.nix` provides a dev shell with Zig and ZLS. Activate with `direnv allow` (uses `.envrc`).

## License

MIT License.
