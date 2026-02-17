# AGENTS.md — nullclaw Agent Engineering Protocol

This file defines the default working protocol for coding agents in this repository.
Scope: entire repository.

## 1) Project Snapshot (Read First)

nullclaw is a Zig-first autonomous AI assistant runtime optimized for:

- minimal binary size (target: < 1 MB ReleaseSmall)
- minimal memory footprint (target: < 5 MB peak RSS)
- zero dependencies beyond libc and optional SQLite
- full feature parity with ZeroClaw (Rust reference implementation)

Core architecture is **vtable-driven** and modular. All extension work is done by implementing
vtable structs and registering them in factory functions.

Key extension points:

- `src/providers/root.zig` (`Provider`) — AI model providers
- `src/channels/root.zig` (`Channel`) — messaging channels
- `src/tools/root.zig` (`Tool`) — tool execution surface
- `src/memory/root.zig` (`Memory`) — memory backends
- `src/observability.zig` (`Observer`) — observability hooks
- `src/runtime.zig` (`RuntimeAdapter`) — execution environments
- `src/peripherals.zig` (`Peripheral`) — hardware boards (Arduino, STM32, RPi)

Build and test:

```bash
zig build                           # dev build
zig build -Doptimize=ReleaseSmall  # release build
zig build test --summary all        # run all tests
```

## 2) Deep Architecture Observations (Why This Protocol Exists)

These codebase realities should drive every design decision:

1. **Vtable + factory architecture is the stability backbone**
   - Extension points are explicit and swappable via `ptr: *anyopaque` + `vtable: *const VTable`.
   - Callers must OWN the implementing struct (local var or heap-alloc). Never return a vtable interface pointing to a temporary — the pointer will dangle.
   - Most features should be added via vtable implementation + factory registration, not cross-cutting rewrites.

2. **Binary size and memory are hard product constraints**
   - `zig build -Doptimize=ReleaseSmall` is the release target. Every dependency and abstraction has a size cost.
   - Avoid adding libc calls, runtime allocations, or large data tables without justification.
   - `MaxRSS` during `zig build test` must stay well under 50 MB.

3. **Security-critical surfaces are first-class**
   - `src/gateway.zig`, `src/security/`, `src/tools/`, `src/runtime.zig` carry high blast radius.
   - Defaults are secure-by-default (pairing, HTTPS-only, allowlists, AEAD encryption). Keep it that way.

4. **Zig 0.15.2 API is the baseline — no newer features**
   - HTTP client: `std.http.Client.fetch()` with `std.Io.Writer.Allocating` for response body capture.
   - Child processes: `std.process.Child.init(argv, allocator)`, `.Pipe` (capitalized).
   - stdout: `std.fs.File.stdout().writer(&buf)` → use `.interface` for `print`/`flush`.
   - `std.io.getStdOut()` does NOT exist in 0.15 — use `std.fs.File.stdout()`.
   - SQLite: linked via `/opt/homebrew/opt/sqlite/{lib,include}` on the compile step, not the module.
   - `ArrayListUnmanaged`: init with `.empty`, pass allocator to every method.

5. **All 1700+ tests must pass at zero leaks**
   - The test suite uses `std.testing.allocator` (leak-detecting GPA). Every allocation must be freed.
   - `Config.load()` allocates — always wrap in `std.heap.ArenaAllocator` in tests and production.
   - `ChaCha20Poly1305.decrypt` segfaults on tag failure with heap-allocated output on macOS/Zig 0.15 — use a stack buffer then `allocator.dupe()`.

## 3) Engineering Principles (Normative)

These principles are mandatory. They are implementation constraints, not suggestions.

### 3.1 KISS

Required:
- Prefer straightforward control flow over meta-programming.
- Prefer explicit comptime branches and typed structs over hidden dynamic behavior.
- Keep error paths obvious and localized.

### 3.2 YAGNI

Required:
- Do not add config keys, vtable methods, or feature flags without a concrete caller.
- Do not introduce speculative abstractions.
- Keep unsupported paths explicit (`return error.NotSupported`) rather than silent no-ops.

### 3.3 DRY + Rule of Three

Required:
- Duplicate small local logic when it preserves clarity.
- Extract shared helpers only after repeated, stable patterns (rule-of-three).
- When extracting, preserve module boundaries and avoid hidden coupling.

### 3.4 Fail Fast + Explicit Errors

Required:
- Prefer explicit errors for unsupported or unsafe states.
- Never silently broaden permissions or capabilities.
- In tests: `builtin.is_test` guards are acceptable to skip side effects (e.g., spawning browsers), but the guard must be explicit and documented.

### 3.5 Secure by Default + Least Privilege

Required:
- Deny-by-default for access and exposure boundaries.
- Never log secrets, raw tokens, or sensitive payloads.
- All outbound URLs must be HTTPS. HTTP is rejected at the tool layer.
- Keep network/filesystem/shell scope as narrow as possible.

### 3.6 Determinism + No Flaky Tests

Required:
- Tests must not spawn real network connections, open browsers, or depend on system state.
- Use `builtin.is_test` to bypass side effects (spawning, opening URLs, real hardware I/O).
- Tests must be reproducible across macOS and Linux.

## 4) Repository Map (High-Level)

```
src/
  main.zig              CLI entrypoint and command routing
  root.zig              module exports (lib root)
  agent.zig             orchestration loop
  config.zig            schema + config loading/merging (~/.nullclaw/config.json)
  gateway.zig           webhook/HTTP gateway server
  onboard.zig           interactive setup wizard
  health.zig            component health registry
  runtime.zig           runtime adapters (native, docker, wasm, cloudflare)
  tunnel.zig            tunnel providers (cloudflared, ngrok, tailscale, custom)
  skillforge.zig        skill discovery and integration
  migration.zig         memory migration from other backends
  hardware.zig          hardware discovery and management
  peripherals.zig       hardware peripherals (Arduino, STM32/Nucleo, RPi)
  security/             policy, pairing, secrets, sandbox backends
  memory/               SQLite + markdown backends, embeddings, vector search
  providers/            22+ AI provider implementations
  channels/             11 channel implementations (telegram, discord, slack, ...)
  tools/                18 tool implementations
  agent/                agent loop, context, planner
```

## 5) Risk Tiers by Path (Review Depth Contract)

- **Low risk**: docs, comments, test additions, minor formatting
- **Medium risk**: most `src/**` behavior changes without boundary/security impact
- **High risk**: `src/security/**`, `src/gateway.zig`, `src/tools/**`, `src/runtime.zig`, config schema, vtable interfaces

When uncertain, classify as higher risk.

## 6) Agent Workflow (Required)

1. **Read before write** — inspect existing module, vtable wiring, and adjacent tests before editing.
2. **Define scope boundary** — one concern per change; avoid mixed feature+refactor+infra patches.
3. **Implement minimal patch** — apply KISS/YAGNI/DRY rule-of-three explicitly.
4. **Validate** — `zig build test --summary all` must show 0 failures and 0 leaks.
5. **Document impact** — update comments/docs for behavior changes, risk, and side effects.

### 6.1 Code Naming Contract (Required)

Apply these naming rules consistently:

- All identifiers: `snake_case` for functions, variables, fields, modules, files.
- Types, structs, enums, unions: `PascalCase` (e.g., `AnthropicProvider`, `BrowserTool`).
- Constants and comptime values: `SCREAMING_SNAKE_CASE` or `PascalCase` depending on context.
- Vtable implementer naming: `<Name>Provider`, `<Name>Channel`, `<Name>Tool`, `<Name>Memory`, `<Name>Sandbox`.
- Factory registration keys: stable, lowercase, user-facing (e.g., `"openai"`, `"telegram"`, `"shell"`).
- Tests: named by behavior (`subject_expected_behavior`), fixtures use neutral names.

### 6.2 Architecture Boundary Contract (Required)

- Extend capabilities by adding vtable implementations + factory wiring first.
- Keep dependency direction inward to contracts: concrete implementations depend on vtable/config/util, not on each other.
- Avoid cross-subsystem coupling (provider code importing channel internals, tool code mutating gateway policy).
- Keep module responsibilities single-purpose: orchestration in `agent/`, transport in `channels/`, model I/O in `providers/`, policy in `security/`, execution in `tools/`.

## 7) Change Playbooks

### 7.1 Adding a Provider

- Add `src/providers/<name>.zig` implementing `Provider.VTable` (`chatWithSystem`, `chat`, `supportsNativeTools`, `getName`, `deinit`).
- Register in `src/providers/root.zig` factory.
- `chatImpl` must extract system/user from `request.messages` (see existing providers for pattern).
- Add tests for vtable wiring, error paths, and config parsing.

### 7.2 Adding a Channel

- Add `src/channels/<name>.zig` implementing `Channel.VTable`.
- Keep `send`, `listen`, `name`, `isConfigured` semantics consistent with existing channels.
- Cover auth/config/health behavior with tests.

### 7.3 Adding a Tool

- Add `src/tools/<name>.zig` implementing `Tool.VTable` (`execute`, `name`, `description`, `parameters_json`).
- Validate and sanitize all inputs. Return `ToolResult`; never panic in the runtime path.
- Add `builtin.is_test` guard if the tool spawns processes or opens network connections.
- Register in `src/tools/root.zig`.

### 7.4 Adding a Peripheral

- Implement the `Peripheral` interface in `src/peripherals.zig`.
- Peripherals expose `read`/`write` methods that delegate to real hardware I/O.
- Use `probe-rs` CLI for STM32/Nucleo flash access; serial JSON protocol for Arduino.
- Non-Linux platforms must return `error.UnsupportedOperation` (not silent 0).

### 7.5 Security / Runtime / Gateway Changes

- Include threat/risk notes in the commit or PR.
- Add/update tests for failure modes and boundaries.
- Keep observability useful but non-sensitive (no secrets in logs or errors).

## 8) Validation Matrix

Required before any code commit:

```bash
zig build test --summary all        # all tests must pass, 0 leaks
```

For release changes:

```bash
zig build -Doptimize=ReleaseSmall  # must compile clean
```

Additional expectations by change type:

- **Docs/comments only**: no build required, but verify no broken code references.
- **Security/runtime/gateway/tools**: include at least one boundary/failure-mode test.
- **Provider additions**: test vtable wiring + graceful failure without credentials.

If full validation is impractical, document what was run and what was skipped.

### 8.1 Git Hooks

The repository ships with pre-configured hooks in `.githooks/`. Activate once per clone:

```bash
git config core.hooksPath .githooks
```

Hooks:

| Hook | What it does |
|------|-------------|
| `pre-commit` | Runs `zig fmt --check src/` — blocks commit if any file is not formatted |
| `pre-push` | Runs `zig build test --summary all` — blocks push if any test fails or leaks |

To bypass a hook in an emergency: `git commit --no-verify` / `git push --no-verify`.

## 9) Privacy and Sensitive Data (Required)

- Never commit real API keys, tokens, credentials, personal data, or private URLs.
- Use neutral placeholders in tests: `"test-key"`, `"example.com"`, `"user_a"`.
- Test fixtures must be impersonal and system-focused.
- Review `git diff --cached` before push for accidental sensitive strings.

## 10) Anti-Patterns (Do Not)

- Do not add C dependencies or large Zig packages without strong justification (binary size impact).
- Do not return vtable interfaces pointing to temporaries — dangling pointer.
- Do not use `std.io.getStdOut()` — it does not exist in Zig 0.15.
- Do not silently weaken security policy or access constraints.
- Do not add speculative config/feature flags "just in case".
- Do not skip `defer allocator.free(...)` — every allocation must be freed.
- Do not use `ArrayListUnmanaged.writer()` as `?*Io.Writer` — incompatible types.
- Do not modify unrelated modules "while here".
- Do not include personal identity or sensitive information in tests, examples, docs, or commits.
- Do not use `SQLITE_TRANSIENT` in auto-translated C code — use `SQLITE_STATIC` (null) instead.
- Do not use heap-allocated output buffers in `ChaCha20Poly1305.decrypt` — use stack buffer + `allocator.dupe()`.

## 11) Handoff Template (Agent → Agent / Maintainer)

When handing off work, include:

1. What changed
2. What did not change
3. Validation run and results (`zig build test --summary all`)
4. Remaining risks / unknowns
5. Next recommended action

## 12) Vibe Coding Guardrails

When working in fast iterative mode:

- Keep each iteration reversible (small commits, clear rollback).
- Validate assumptions with code search before implementing.
- Prefer deterministic behavior over clever shortcuts.
- Do not "ship and hope" on security-sensitive paths.
- If uncertain about Zig 0.15 API, check `src/` for existing usage patterns before guessing.
- If uncertain about architecture, read the vtable interface definition before implementing.
