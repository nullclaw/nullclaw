# Contributing to NullClaw

Thanks for contributing to NullClaw.

For detailed contributor workflows, validation expectations, and PR preparation, see [`docs/en/development.md`](docs/en/development.md) ([中文](docs/zh/development.md)).

## Quick Start

1. Use **Zig 0.15.2** exactly (`zig version` → `0.15.2`)
2. Read `AGENTS.md` for engineering rules
3. Clone, build, test:

```bash
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig build
zig build test --summary all
```

4. Enable git hooks:

```bash
git config core.hooksPath .githooks
```

## PR Checklist

- [ ] Scope is focused — one concern per PR
- [ ] `zig build test --summary all` passes with 0 failures, 0 leaks
- [ ] Docs updated for any user-facing behavior change
- [ ] No secrets, tokens, or personal data
- [ ] New code follows existing naming and module boundaries

## PR Description Template

```text
## Summary
- ...

## Validation
- zig build test --summary all

## Notes
- ...
```

## Where to Put New Work

- New provider: `src/providers/`
- New channel: `src/channels/`
- New tool: `src/tools/`
- New memory backend: `src/memory/`
- New sandbox/security logic: `src/security/`
- New peripheral support: `src/peripherals.zig`
- New user docs: `docs/en/` and `docs/zh/`

If unsure where a feature belongs, start with `AGENTS.md` and trace the relevant vtable interface.
