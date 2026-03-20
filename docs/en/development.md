# Development

This page is for contributors. The goal is to help you set up the repo, make a focused change, validate it, and open a PR without guesswork.

## Page Guide

**Who this page is for**

- Contributors preparing a local dev environment
- Maintainers validating changes before opening or reviewing a PR
- Doc or code authors checking the repo workflow and validation baseline

**Read this next**

- Open [Architecture](./architecture.md) before touching unfamiliar subsystems
- Open [Commands](./commands.md) if your change affects CLI behavior or docs
- Open [README](./README.md) if you need the broader English docs map

**If you came from ...**

- [README](./README.md): this page narrows the path to contributor-specific setup and validation
- [Commands](./commands.md): come here when a CLI change also needs workflow, testing, or PR guidance
- `AGENTS.md`: use this page for the practical day-to-day contributor checklist

## Before You Edit

- Development and testing are pinned to **Zig 0.15.2**.
- Read `AGENTS.md` before code changes.
- Read `CLAUDE.md` if you need more project context, validation rules, or subsystem guidance.
- If you use the repository flake, both `nix build` and `nix develop` are pinned to **Zig 0.15.2**.

Check your Zig version first:

```bash
zig version
```

## Local Build and Test

```bash
zig build
zig build -Doptimize=ReleaseSmall
zig build test --summary all
```

At minimum, run this before opening a PR for code changes:

```bash
zig build test --summary all
```

## Common Build Flags

```bash
zig build -Dchannels=telegram,cli
zig build -Dengines=base,sqlite
zig build -Dtarget=x86_64-linux-musl
zig build -Dversion=2026.3.1
```

Notes:

- `channels`: limit which channel implementations are compiled in
- `engines`: limit memory engines in the build
- `target`: cross-compile target triple
- `version`: override the embedded version string (`dev` by default; release workflow injects the git tag)

## Recommended Workflow

1. Read the target module and nearby tests first.
2. Keep each PR focused on one concern.
3. Update docs and tests as part of the same change.
4. Validate before you open the PR.

## Documentation Sync

If your change affects users, operators, or contributors, update the related docs in the same PR:

- Landing page: `README.md`
- English docs: `docs/en/`
- Chinese docs: `docs/zh/`
- Security policy: `SECURITY.md`
- Specialized deployment guide: `SIGNAL.md`
- Contribution guide: `CONTRIBUTING.md`

Documentation should stay:

- task-oriented
- copy-paste friendly
- consistent with `src/main.zig` and the current config schema
- synchronized across English and Chinese when both audiences are affected

## Git Hooks

Enable the repository hooks once per clone:

```bash
git config core.hooksPath .githooks
```

Hooks included:

- `pre-commit` runs `zig fmt --check src/`
- `pre-push` runs `zig build test --summary all`

## Validation Before PR

### Docs-only changes

Recommended:

```bash
git diff --check
```

Also verify links, paths, and command examples manually.

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

## PR Guidance

Your PR description should explain:

1. what changed
2. why it changed
3. what validation you ran
4. any risks or follow-up work

Suggested template:

```text
## Summary
- ...

## Validation
- zig build test --summary all

## Notes
- ...
```

## High-Frequency Paths

| Path | Purpose |
|---|---|
| `src/main.zig` | CLI command routing |
| `src/config.zig` | Config loading and environment overrides |
| `src/gateway.zig` | Gateway and webhooks |
| `src/security/` | Security and sandboxing |
| `src/providers/` | Model providers |
| `src/channels/` | Messaging channels |
| `src/tools/` | Tool implementations |
| `src/memory/` | Memory backends and retrieval |

## More Reading

- Architecture: `docs/en/architecture.md`
- Commands: `docs/en/commands.md`
- Contribution guide: `CONTRIBUTING.md`
- Engineering protocol: `AGENTS.md`

## Next Steps

- Read [Architecture](./architecture.md) before editing deeper runtime, security, or provider code
- Use [Commands](./commands.md) when your change touches the CLI surface or examples
- Open [CONTRIBUTING.md](../../CONTRIBUTING.md) before preparing the final PR description and review flow

## Related Pages

- [README](./README.md)
- [Installation](./installation.md)
- [Configuration](./configuration.md)
- [Commands](./commands.md)
