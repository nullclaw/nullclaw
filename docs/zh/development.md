# 开发指南

本页面向贡献者，目标是让你能用最短路径搭好环境、改完文档或代码、跑完校验并提交 PR。

## 页面导航

- 这页适合谁：准备改代码、文档、测试，或者想提交 PR 的贡献者。
- 看完去哪里：理解模块边界看 [架构总览](./architecture.md)；查 CLI 行为和示例看 [命令参考](./commands.md)；确认提交流程看 [贡献指南](../../CONTRIBUTING.md)。
- 如果你是从某页来的：从 [README](./README.md) 来，这页就是贡献路径的下一站；从 [命令参考](./commands.md) 来，适合继续补本地构建、测试和提交前校验；从 `AGENTS.md` 来，可把本页当作具体落地流程。

## 开发前先确认

- 本项目开发与测试固定在 **Zig 0.15.2**。
- 修改代码前，先读 `AGENTS.md`。
- 如需理解工程背景、模块边界、测试与构建约束，可继续读 `CLAUDE.md`。
- 如果你使用仓库里的 flake，则 `nix build` 和 `nix develop` 都固定为 **Zig 0.15.2**。

先确认本机 Zig 版本：

```bash
zig version
```

## 本地构建与测试

```bash
zig build
zig build -Doptimize=ReleaseSmall
zig build test --summary all
```

建议在提交前至少执行：

```bash
zig build test --summary all
```

## 常用构建参数

```bash
zig build -Dchannels=telegram,cli
zig build -Dengines=base,sqlite
zig build -Dtarget=x86_64-linux-musl
zig build -Dversion=2026.3.1
```

说明：

- `channels`：裁剪编译进制中的渠道实现。
- `engines`：裁剪 memory engine。
- `target`：交叉编译目标。
- `version`：覆盖嵌入版本字符串（默认是 `dev`；release workflow 会注入 git tag）。

## 推荐工作流

1. 先阅读相关模块与相邻测试。
2. 只做一个关注点的改动，不把功能、重构、杂项修复混在一起。
3. 改完立刻补文档或测试，不要留到最后一起补。
4. 提交前跑校验，确认没有把 README、命令、配置示例写错。

## 文档同步要求

如果你的改动会影响用户、运维、贡献者，最好在同一个 PR 里同步文档：

- 根落地页：`README.md`
- 英文文档：`docs/en/`
- 中文文档：`docs/zh/`
- 安全披露：`SECURITY.md`
- 专题部署：`SIGNAL.md`
- 贡献流程：`CONTRIBUTING.md`

文档更新时建议遵循：

- 让命令示例可以直接复制执行。
- README 只做 landing page，细节尽量放到 `docs/`。
- 命令、flags、配置字段必须以 `src/main.zig` 和当前配置结构为准。
- 若改动同时影响中英文用户，尽量同步更新 `docs/en/` 与 `docs/zh/`。

## Git Hooks

仓库自带 hooks，建议 clone 后立刻启用：

```bash
git config core.hooksPath .githooks
```

其中：

- `pre-commit` 会执行 `zig fmt --check src/`
- `pre-push` 会执行 `zig build test --summary all`

## 提交前校验

### 文档改动

至少执行：

```bash
git diff --check
```

并人工确认链接、文件路径、命令示例可读可用。

### 代码改动

必须执行：

```bash
zig build test --summary all
```

### Release / 构建敏感改动

额外执行：

```bash
zig build -Doptimize=ReleaseSmall
```

## PR 建议

PR 描述至少写清楚：

1. 改了什么
2. 为什么改
3. 跑了什么验证
4. 是否有风险或后续事项

可直接套用：

```text
## Summary
- ...

## Validation
- zig build test --summary all

## Notes
- ...
```

## 代码结构（高频目录）

| 路径 | 说明 |
|---|---|
| `src/main.zig` | CLI 命令路由 |
| `src/config.zig` | 配置加载与环境覆盖 |
| `src/gateway.zig` | 网关与 webhook |
| `src/security/` | 安全与沙箱 |
| `src/providers/` | 模型 provider 实现 |
| `src/channels/` | 消息渠道实现 |
| `src/tools/` | tool 实现 |
| `src/memory/` | memory backend 与检索 |

## 更多入口

- 架构：`docs/zh/architecture.md`
- 命令：`docs/zh/commands.md`
- 贡献流程：`CONTRIBUTING.md`
- 工程协议：`AGENTS.md`

## 下一步

- 要开始改代码：先读 [架构总览](./architecture.md)，再回到本页执行构建与测试。
- 要同步文档或核对 CLI：继续看 [命令参考](./commands.md) 和 `src/main.zig`。
- 要准备提交 PR：继续看 [贡献指南](../../CONTRIBUTING.md)，并按本页“提交前校验”执行。

## 相关页面

- [中文文档入口](./README.md)
- [架构总览](./architecture.md)
- [命令参考](./commands.md)
- [贡献指南](../../CONTRIBUTING.md)
