# Contributing to NullClaw

Thanks for contributing to NullClaw.

This guide focuses on the fastest safe path to open a useful PR without guessing about local setup, validation, or documentation expectations.

## Before You Start

- Use **Zig 0.15.2** exactly.
- Read `AGENTS.md` for repository-wide engineering rules.
- If you touch architecture-sensitive code, also read `CLAUDE.md` for project context and validation details.

Check your toolchain first:

```bash
zig version
```

Expected output:

```text
0.15.2
```

## Local Setup

Clone and build:

```bash
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig build
```

Run the full test suite before you open a PR for code changes:

```bash
zig build test --summary all
```

Optional release build check:

```bash
zig build -Doptimize=ReleaseSmall
```

## Recommended Workflow

1. Create a focused branch for one concern.
2. Read the existing module and adjacent tests before editing.
3. Keep changes small and reversible.
4. Update docs when behavior, commands, configuration, or architecture notes change.
5. Run the required validation before opening the PR.

## Enable Git Hooks

The repository ships with hooks that catch common mistakes early:

```bash
git config core.hooksPath .githooks
```

Hooks:

- `pre-commit` runs `zig fmt --check src/`
- `pre-push` runs `zig build test --summary all`

## Documentation Expectations

If your change affects users, contributors, or operators, update the matching docs in the same PR.

- Root landing page: `README.md`
- English docs: `docs/en/`
- Chinese docs: `docs/zh/`
- Security policy: `SECURITY.md`
- Specialized deployment guide: `SIGNAL.md`

When updating docs:

- Prefer concise, task-oriented sections.
- Keep command examples copy-paste friendly.
- Keep README as a landing page; move deep detail into `docs/` when possible.
- Sync English and Chinese pages when both audiences are affected.
- Avoid documenting commands or flags that do not exist in `src/main.zig`.

## Validation Matrix

Use the smallest validation that honestly covers your change.

### Docs-only changes

Recommended:

```bash
git diff --check
```

Also verify links and referenced file paths manually.

### Code changes

Required:

```bash
zig build test --summary all
```

### Release-sensitive changes

Also run:

```bash
zig build -Doptimize=ReleaseSmall
```

## PR Checklist

Before opening a PR, confirm all of the following:

- [ ] Scope is focused and does not mix unrelated refactors
- [ ] Commands, config keys, and examples match the current codebase
- [ ] Docs are updated for any user-facing behavior change
- [ ] Validation was run and results are included in the PR description
- [ ] No secrets, tokens, or personal data were added
- [ ] New code follows existing naming and module boundaries

## What to Include in the PR Description

Keep it short and concrete:

1. What changed
2. Why it changed
3. Validation run
4. Risks or follow-up work

Suggested template:

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

If you are unsure where a feature belongs, start with `AGENTS.md` and trace the relevant vtable interface before writing code.
