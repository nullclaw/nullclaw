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

技能位于 `~/.nullclaw/workspace/skills/<name>/`，需包含 manifest。

`loadSkill` 按以下顺序读取第一个找到的 manifest：

1. `SKILL.toml` — **推荐**
2. `skill.json` — 旧版 JSON manifest
3. `SKILL.md` — 回退项；若不存在任何 manifest，则作为纯 markdown 技能加载，
   并以 `SKILL.md` 作为其说明文件

- `SKILL.toml` — 推荐的 manifest
- `skill.json` — 旧版替代方案
- `SKILL.md` — 说明文件，同时作为 manifest 回退项
- `build.zig` / `root.zig` — 可选 Zig 构建文件

### 跨 agent、跨主机共享技能（符号链接）

工作区 `skills/` 目录中的技能目录可以是**符号链接**。把技能的唯一权威副本
放在 git 仓库或同步目录中，然后为每个 agent / 主机放置一个链接：

```bash
ln -s /srv/git/my-skills/git-helper ~/.nullclaw/workspace/skills/git-helper
```

`nullclaw skills list` 和 agent 会像普通技能目录一样跟随这些链接；失效的
链接会被忽略。由于 `SKILL.md` 是跨运行时的格式，同一份权威副本也可以链接
到其他读取该格式的 agent（例如 ZeroClaw 或 Hermes Agent 的工作区）。从网络
安装包安装的技能不受影响 —— 安装包安全审计仍然拒绝包内的符号链接条目。

## SkillForge（自动发现）

SkillForge 是一个库模块（`src/skillforge.zig`），可从 GitHub 发现并评估技能。

**下面的 `skillforge` 配置块不会被 `Config` 解析，运行时也不会调度它。**
此处仅用于说明该模块的能力，并非可直接生效的配置示例 —— 设置它目前不会有任何
效果。发现流程只扫描上文所述的 `workspace/skills/` 目录。若要将其接入为真实
配置，需要改动配置 schema。

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
