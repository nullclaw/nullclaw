# Skills

NullClaw supports extensible skill packs — self-contained modules that add new capabilities to the agent.

## CLI Commands

```bash
nullclaw skills list              # List installed skills
nullclaw skills install <url>     # Install from GitHub URL
nullclaw skills remove <name>     # Remove an installed skill
nullclaw skills info <name>       # Show skill metadata
```

## Skill Structure

Skills live in `~/.nullclaw/workspace/skills/<name>/` and must contain a manifest:

```
skills/
  my-skill/
    SKILL.md          # YAML frontmatter + description (preferred)
    skill.json        # or JSON manifest
    build.zig         # optional Zig build (enhanced compatibility scoring)
    root.zig          # optional Zig entry point
```

### SKILL.md Format

```markdown
---
name: my-skill
version: 1.0.0
description: Does something useful
---

Detailed skill documentation here.
```

### skill.json Format

```json
{
  "name": "my-skill",
  "version": "1.0.0",
  "description": "Does something useful"
}
```

## Symlinked skill directories

A skill directory in the workspace `skills/` folder may be a symbolic link.
Keep one canonical copy of your skills in a git repo or synced folder, and
place a symlink per agent or host:

```bash
ln -s /srv/git/my-skills/git-helper ~/.nullclaw/workspace/skills/git-helper
```

`nullclaw skills list` and the agent follow such links like normal skill
directories; broken links are ignored. Because `SKILL.md` is a cross-runtime
format, the same canonical copy can also be linked into other agents that read
it (e.g. ZeroClaw or Hermes Agent workspaces). Skills installed from
web-downloaded archives are unaffected — the archive security audit still
rejects symlink entries inside archives.

## SkillForge (Auto-Discovery)

SkillForge can automatically discover and evaluate skills from GitHub.

```json
{
  "skillforge": {
    "enabled": true,
    "auto_integrate": true,
    "scan_interval_hours": 24,
    "min_score": 0.7,
    "output_dir": "./skills"
  }
}
```

### Scoring

Skills are evaluated on a weighted scale:

| Factor | Weight | Scoring |
|--------|--------|---------|
| Compatibility | 30% | Zig/Rust = 1.0, Python/TS/JS = 0.6, others = 0.3 |
| Quality | 35% | Log-scale based on GitHub stars |
| Security | 35% | +0.3 for license, -0.5 for suspicious patterns |

Recommendations: `auto` (score >= 0.7), `manual` (0.4-0.7), `skip` (< 0.4).

## Related

- [Commands](./commands.md) — Full CLI reference
- [Configuration](./configuration.md) — Config reference
