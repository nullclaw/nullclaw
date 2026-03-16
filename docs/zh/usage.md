# 使用与运维

本页聚焦日常操作、服务化运行和常见故障排查。

## 页面导航

- 这页适合谁：已经完成安装与基础配置，准备日常使用、服务化运行或排障的人。
- 看完去哪里：命令细节继续看 [命令参考](./commands.md)；要核对配置字段看 [配置指南](./configuration.md)；涉及 webhook 与对外接入看 [Gateway API](./gateway-api.md)。
- 如果你是从某页来的：从 [安装指南](./installation.md) 来，这页就是首次跑通的下一站；从 [配置指南](./configuration.md) 来，这页用来验证配置是否真能工作；从 [Gateway API](./gateway-api.md) 来，可回到这里看长期运行与排障顺序。

## 首次启动流程

1. 执行初始化：

```bash
nullclaw onboard --interactive
```

2. 发送一条测试消息：

```bash
nullclaw agent -m "你好，nullclaw"
```

3. 启动长期运行网关：

```bash
nullclaw gateway
```

## 常用命令速查

| 命令 | 用途 |
|---|---|
| `nullclaw onboard --api-key sk-... --provider openrouter` | 快速写入 provider 与 API Key |
| `nullclaw onboard --interactive` | 交互式完整初始化 |
| `nullclaw onboard --channels-only` | 只重配 channel / allowlist |
| `nullclaw agent -m "..."` | 单条消息模式 |
| `nullclaw agent` | 交互会话模式 |
| `nullclaw gateway` | 启动长期运行 runtime（默认 `127.0.0.1:3000`） |
| `nullclaw service install` | 安装后台服务 |
| `nullclaw service start` | 启动后台服务 |
| `nullclaw service status` | 查看后台服务状态 |
| `nullclaw service stop` | 停止后台服务 |
| `nullclaw service uninstall` | 卸载后台服务 |
| `nullclaw doctor` | 系统诊断 |
| `nullclaw status` | 全局状态 |
| `nullclaw channel status` | 渠道健康状态 |
| `nullclaw channel start telegram` | 启动指定渠道 |
| `nullclaw migrate openclaw --dry-run` | 预演迁移 OpenClaw 数据 |
| `nullclaw migrate openclaw` | 执行迁移 |
| `nullclaw history list [--limit N] [--offset N] [--json]` | 列出会话记录 |
| `nullclaw history show <session_id> [--limit N] [--offset N] [--json]` | 查看指定会话的消息详情 |

## 服务化运行建议

建议在长期运行场景使用 service 子命令：

```bash
nullclaw service install
nullclaw service start
nullclaw service status
```

如果配置改动较大，建议重启服务：

```bash
nullclaw service stop
nullclaw service start
```

## 网关与配对（Pairing）

- 默认网关地址：`127.0.0.1:3000`
- 推荐保持 `gateway.require_pairing = true`
- 建议通过 tunnel 暴露外网访问，不直接公网监听网关

网关健康检查：

```bash
curl http://127.0.0.1:3000/health
```

## 常见问题（FAQ）

### 1) 启动失败，提示配置错误

处理步骤：

1. 先跑 `nullclaw doctor` 看具体报错。
2. 对照 `config.example.json` 检查字段拼写与层级。
3. 检查 JSON 语法（逗号、引号、括号）。

### 2) 模型调用失败（401/403）

常见原因：

- API Key 无效或过期。
- provider 写错（例如填了 `openrouter` 但 key 属于其他平台）。
- 模型路由字符串不匹配 provider。

建议排查：

```bash
nullclaw status
```

并重新执行：

```bash
nullclaw onboard --interactive
```

### 3) 收不到渠道消息

重点检查：

- `channels.<name>.accounts.*` 的 token / webhook / account 字段是否正确。
- `allow_from` 是否误设为空数组。
- `nullclaw channel status` 是否有 unhealthy 标记。

### 4) 网关启动但外部不可访问

常见原因：

- 仍绑定在 `127.0.0.1`。
- 未配置 tunnel 或反向代理。
- 防火墙未放行端口。

### 5) provider 返回 429 / “rate limit exceeded”

常见原因：

- 额度较低的 coding plan 往往扛不住 tool-heavy 的 agent 回合，即使普通聊天还看起来能用。
- 当前 provider 计划对重试频率很敏感。
- 主 provider 被限流后，没有配置可切换的 fallback。

建议排查：

- 前台运行时先用 `nullclaw agent --verbose`。
- service 模式下查看 `~/.nullclaw/logs/daemon.stdout.log` 与 `~/.nullclaw/logs/daemon.stderr.log`。
- 跑一次 `nullclaw status`，确认当前实际使用的 provider / model。

如果 plan 本身可用但限流很严，建议保守调整 reliability：

```json
{
  "reliability": {
    "provider_retries": 1,
    "provider_backoff_ms": 3000,
    "fallback_providers": ["openrouter"]
  }
}
```

如果同一 provider 有多把 key，可以配置 `reliability.api_keys` 让 NullClaw 在限流时轮转。

## 变更后回归检查清单

每次改配置后，建议按顺序执行：

```bash
nullclaw doctor
nullclaw status
nullclaw channel status
nullclaw agent -m "self-check"
```

对 gateway 场景，额外验证：

```bash
nullclaw gateway
curl http://127.0.0.1:3000/health
```

## 下一步

- 要细查具体 CLI 行为：继续看 [命令参考](./commands.md)，按子命令逐项核对。
- 要排查配置或调整 provider/channel：继续看 [配置指南](./configuration.md)。
- 要把网关开放给外部系统：继续看 [Gateway API](./gateway-api.md) 和 [安全机制](./security.md)。

## 相关页面

- [安装指南](./installation.md)
- [配置指南](./configuration.md)
- [命令参考](./commands.md)
- [Gateway API](./gateway-api.md)
