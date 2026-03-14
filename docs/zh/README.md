# NullClaw 中文文档

本目录提供面向使用者、运维者、贡献者的中文文档入口。

如果你刚接触 NullClaw，先从这里找对阅读路径，再进入具体章节。

## 页面怎么用

**这页适合谁**

- 刚进入项目、还不知道先看哪篇文档的用户
- 需要在运维、开发、使用三条路线之间做选择的人
- 想从中文总览快速跳到细节页的贡献者

**看完先去哪里**

- 还没跑起来：先看 [安装指南](./installation.md)
- 已经装好，准备接 provider / memory / channel：看 [配置指南](./configuration.md)
- 只想找命令：直接去 [命令参考](./commands.md)

**如果你是从这里跳过来的**

- `README.md`：把这页当成中文落地页，然后按你的目标继续往下走
- [命令参考](./commands.md)：回到这里可重新选择“上手 / 运维 / 开发”的阅读路径
- [开发指南](./development.md)：回到这里可切换到用户或运维视角的文档

## 从哪开始

### 1. 我只想先跑起来

推荐顺序：

1. [安装指南](./installation.md)
2. [配置指南](./configuration.md)
3. [使用与运维](./usage.md)
4. [命令参考](./commands.md)

### 2. 我要部署和长期运行

重点看：

- [使用与运维](./usage.md)
- [安全机制](./security.md)
- [Gateway API](./gateway-api.md)
- [Signal 部署专题](../../SIGNAL.md)

### 3. 我要开发、改代码、提 PR

重点看：

- [架构总览](./architecture.md)
- [开发指南](./development.md)
- [命令参考](./commands.md)
- [贡献指南](../../CONTRIBUTING.md)

## 文档导航

- [安装指南](./installation.md)
- [Termux 指南](./termux.md)
- [配置指南](./configuration.md)
- [使用与运维](./usage.md)
- [架构总览](./architecture.md)
- [安全机制](./security.md)
- [Gateway API](./gateway-api.md)
- [命令参考](./commands.md)
- [开发指南](./development.md)

## 先看这 3 条

1. NullClaw 当前要求 **Zig 0.15.2**（精确版本）。
2. 默认配置文件路径为 `~/.nullclaw/config.json`（由 `nullclaw onboard` 生成）。
3. 首次上手建议先跑 `onboard --interactive`，再用 `agent` 和 `gateway` 验证。

## 最短上手路径（3 分钟）

```bash
brew install nullclaw
nullclaw onboard --interactive
nullclaw agent -m "你好，nullclaw"
```

如果你不用 Homebrew，请按 [安装指南](./installation.md) 走源码构建流程。

## 推荐阅读顺序

### 新用户

1. [安装指南](./installation.md)
2. [配置指南](./configuration.md)
3. [使用与运维](./usage.md)
4. [命令参考](./commands.md)

### 运维 / 集成

1. [使用与运维](./usage.md)
2. [安全机制](./security.md)
3. [Gateway API](./gateway-api.md)
4. [Signal 部署专题](../../SIGNAL.md)

### 贡献者

1. [架构总览](./architecture.md)
2. [开发指南](./development.md)
3. [贡献指南](../../CONTRIBUTING.md)

## 专题文档

- [安全披露流程](../../SECURITY.md)
- [Signal 渠道部署](../../SIGNAL.md)
- [贡献指南](../../CONTRIBUTING.md)

## 下一步

- 新用户：按 [安装指南](./installation.md) → [配置指南](./configuration.md) → [使用与运维](./usage.md) 继续。
- 运维 / 集成：先看 [使用与运维](./usage.md)，再补 [安全机制](./security.md) 与 [Gateway API](./gateway-api.md)。
- 贡献者：先读 [开发指南](./development.md)，需要提交流程时再看 [贡献指南](../../CONTRIBUTING.md)。

## 相关页面

- [Termux 指南](./termux.md)
- [命令参考](./commands.md)
- [架构总览](./architecture.md)
- [安全机制](./security.md)
- [Gateway API](./gateway-api.md)
