# 技能包（Skills）

NullClaw 支持可扩展的技能包，为 agent 添加新能力。

## CLI 命令

```bash
nullclaw skills list              # 列出已安装技能
nullclaw skills install <url>     # 从 GitHub URL 安装
nullclaw skills remove <name>     # 移除技能
nullclaw skills info <name>       # 查看技能元数据
```

## 技能结构

技能位于 `~/.nullclaw/workspace/skills/<name>/`，需包含 manifest：

- `SKILL.md` — YAML frontmatter + 描述（推荐）
- `skill.json` — JSON manifest
- `build.zig` / `root.zig` — 可选 Zig 构建文件

## SkillForge（自动发现）

```json
{
  "skillforge": {
    "enabled": true,
    "auto_integrate": true,
    "scan_interval_hours": 24,
    "min_score": 0.7
  }
}
```

自动从 GitHub 发现并评估技能，按兼容性（30%）、质量（35%）、安全性（35%）加权评分。

## 相关页面

- [命令参考](./commands.md)
- [配置指南](./configuration.md)
