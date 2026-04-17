# Gateway API

默认网关地址：`http://127.0.0.1:3000`

## 页面导航

- 这页适合谁：要对接 webhook、做健康检查，或调试网关配对与鉴权流程的人。
- 看完去哪里：要看网关字段与监听策略看 [配置指南](./configuration.md)；要排查服务启动与长期运行看 [使用与运维](./usage.md)；要确认暴露边界与 token 管理看 [安全机制](./security.md)。
- 如果你是从某页来的：从 [使用与运维](./usage.md) 来，这页补的是 HTTP 端点与请求示例；从 [配置指南](./configuration.md) 来，可在这里确认 `gateway` 配置对应的实际接口；从 [安全机制](./security.md) 来，这页提供配对和 bearer token 的具体调用面。

## 端点总览

| Endpoint | Method | 鉴权 | 说明 |
|---|---|---|---|
| `/health` | GET | 无 | 健康检查 |
| `/pair` | POST | `X-Pairing-Code` | 用一次性配对码换取 bearer token |
| `/webhook` | POST | `Authorization: Bearer <token>` | 发送消息：`{"message":"..."}` |
| `/cron` | GET | 已存在配对 token 时需要 `Authorization: Bearer <token>` | 查看运行中 daemon 的实时 scheduler 任务 |
| `/cron/add` | POST | 已存在配对 token 时需要 `Authorization: Bearer <token>` | 新增实时 cron 任务 |
| `/cron/remove` | POST | 已存在配对 token 时需要 `Authorization: Bearer <token>` | 按 `id` 删除实时 cron 任务 |
| `/cron/pause` | POST | 已存在配对 token 时需要 `Authorization: Bearer <token>` | 按 `id` 暂停实时 cron 任务 |
| `/cron/resume` | POST | 已存在配对 token 时需要 `Authorization: Bearer <token>` | 按 `id` 恢复实时 cron 任务 |
| `/cron/update` | POST | 已存在配对 token 时需要 `Authorization: Bearer <token>` | 部分更新实时 cron 任务 |
| `/whatsapp` | GET | Query 参数 | Meta Webhook 验证 |
| `/whatsapp` | POST | Meta 签名 | WhatsApp 入站消息 |
| `/max` | POST | `X-Max-Bot-Api-Secret`（配置后必填） | Max 入站 webhook |
| `/.well-known/agent-card.json` | GET | 无 | A2A Agent Card 发现（公开） |
| `/a2a` | POST | `Authorization: Bearer <token>` | A2A JSON-RPC 2.0 端点 |

## 快速示例

### 1) 健康检查

```bash
curl http://127.0.0.1:3000/health
```

### 2) 配对换 token

```bash
curl -X POST \
  -H "X-Pairing-Code: 123456" \
  http://127.0.0.1:3000/pair
```

预期返回 bearer token（结构可能随版本调整）。

### 3) 发送 webhook 消息

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"hello from webhook"}' \
  http://127.0.0.1:3000/webhook
```

### 4) 查看实时 cron 任务

```bash
curl -X GET \
  -H "Authorization: Bearer YOUR_TOKEN" \
  http://127.0.0.1:3000/cron
```

### 5) 新增实时 cron 任务

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"expression":"*/15 * * * *","command":"echo hello"}' \
  http://127.0.0.1:3000/cron/add
```

`/cron/add` 也支持一次性任务，例如 `{"delay":"10m","command":"echo later"}`，以及 agent 任务，例如 `{"expression":"0 * * * *","prompt":"Summarize alerts","model":"openrouter/anthropic/claude-sonnet-4"}`。

### 6) Max webhook 投递

单账号示例：

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Max-Bot-Api-Secret: YOUR_MAX_SECRET" \
  -d '{"update_type":"bot_started","chat_id":100,"timestamp":1710000000000,"user":{"user_id":42,"first_name":"Igor"}}' \
  http://127.0.0.1:3000/max
```

多账号示例：

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Max-Bot-Api-Secret: YOUR_MAX_SECRET" \
  -d '{"update_type":"message_created","timestamp":1710000000000,"message":{"sender":{"user_id":42,"first_name":"Igor"},"recipient":{"chat_id":100,"chat_type":"dialog"},"body":{"mid":"m1","text":"ping"}}}' \
  "http://127.0.0.1:3000/max?account_id=main"
```

Max webhook 说明：

- `nullclaw` 对 `/max` 路由优先按 `account_id` query 参数匹配，其次按 `X-Max-Bot-Api-Secret` 匹配。
- 如果 `channels.max[].webhook_secret` 已配置，header 必须存在且完全匹配。
- Max 侧配置的 webhook URL 必须使用 HTTPS。

## A2A（Agent-to-Agent 协议）

NullClaw 实现了 [Google A2A 协议 v0.3.0](https://github.com/google/A2A)，基于 JSON-RPC 2.0，支持与任何兼容 A2A 的代理或客户端互操作。

### 配置

在 `~/.nullclaw/config.json` 中添加：

```json
{
  "a2a": {
    "enabled": true,
    "name": "My Agent",
    "description": "通用 AI 助手",
    "url": "https://your-public-url.example.com",
    "version": "0.3.0"
  }
}
```

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `enabled` | `false` | 启用 A2A 端点 |
| `name` | `"NullClaw"` | Agent Card 中显示的名称 |
| `description` | `"AI assistant"` | 代理描述 |
| `url` | `""` | 公开 URL（用于 Agent Card 和 `supportedInterfaces`） |
| `version` | `"1.0.0"` | 代理版本号 |
| `multi_modal` | `false` | 在 Agent Card 中声明多模态能力。当配置的模型支持图片输入时设为 `true`。网关启动时会自动探测模型能力并设置此值；如需覆盖可手动配置。 |

**多模态支持**

当 `multi_modal` 为 `true` 时，Agent Card 的 capabilities 对象中会包含 `"multi_modal": true`，向 A2A 客户端表明该代理可接受图片附件。A2A 消息中可在 `text` 部件之外包含 `inlineData` 部件（base64 编码的图片）；网关会将其转发给模型，格式为 `[IMAGE: <mime_type>]` 标记。

接受大型图片负载时，需在 `gateway` 配置块中提高 HTTP 请求体上限和 socket 读取超时（参见 [configuration.md](./configuration.md) `gateway` 节）：

```json
{
  "gateway": {
    "max_body_size_bytes": 20971520,
    "request_timeout_secs": 120
  }
}
```

### Agent Card 发现

```bash
curl http://127.0.0.1:3000/.well-known/agent-card.json
```

返回 Agent Card，包含能力声明、技能列表、安全机制和支持的接口。无需鉴权。

### JSON-RPC 方法

所有方法通过 `POST /a2a` 调用，需要从 `/pair` 获取的 bearer token。

| 方法 | 说明 |
|------|------|
| `message/send` | 发送消息，返回完成的任务 |
| `message/stream` | 发送消息，返回 SSE 事件流 |
| `tasks/get` | 按 ID 查询任务（支持 `historyLength`） |
| `tasks/cancel` | 取消进行中的任务 |
| `tasks/list` | 列出任务，支持 `state`/`contextId` 过滤 |
| `tasks/resubscribe` | 恢复已有任务的 SSE 流 |

### 任务生命周期

```
submitted → working → completed
                    → failed
                    → canceled
                    → input-required
                    → auth-required
                    → rejected
```

终态：`completed`、`failed`、`canceled`、`rejected`。

### 示例

**发送消息：**

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/send",
    "params": {
      "message": {
        "messageId": "msg-1",
        "role": "user",
        "parts": [{"kind": "text", "text": "什么是 nullclaw？"}]
      }
    }
  }' \
  http://127.0.0.1:3000/a2a
```

**流式响应（SSE）：**

```bash
curl -N -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/stream",
    "params": {
      "message": {
        "messageId": "msg-2",
        "role": "user",
        "parts": [{"kind": "text", "text": "解释 A2A 协议"}]
      }
    }
  }' \
  http://127.0.0.1:3000/a2a
```

**查询任务：**

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"task-1"}}' \
  http://127.0.0.1:3000/a2a
```

### 多轮对话

在消息中包含 `contextId` 将任务归入同一对话。相同 `contextId` 的消息共享会话状态和对话历史：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "message/send",
  "params": {
    "message": {
      "messageId": "msg-3",
      "contextId": "my-conversation",
      "role": "user",
      "parts": [{"kind": "text", "text": "后续问题"}]
    }
  }
}
```

### 错误码

| 错误码 | 名称 | 说明 |
|--------|------|------|
| -32700 | JSONParseError | JSON 格式无效 |
| -32600 | InvalidRequestError | 请求校验失败 |
| -32601 | MethodNotFoundError | 未知方法 |
| -32602 | InvalidParamsError | 缺少或无效参数 |
| -32603 | InternalError | 服务端错误 |
| -32001 | TaskNotFoundError | 任务 ID 不存在 |
| -32002 | TaskNotCancelableError | 任务已处于终态 |
| -32003 | PushNotificationNotSupportedError | 不支持推送通知 |
| -32005 | ContentTypeNotSupportedError | 内容类型不兼容 |
| -32007 | AuthenticatedExtendedCardNotConfiguredError | 未配置扩展卡片 |

## 鉴权与安全建议

1. 保持 `gateway.require_pairing = true`。
2. 网关优先绑定 `127.0.0.1`，外网访问通过 tunnel/反向代理。
3. token 视为密钥，不写入公开仓库或日志。
4. Max webhook secret 同理：每个账号使用独立随机值，不跨 bot 复用。

## 下一步

- 要先把网关配置对：继续看 [配置指南](./configuration.md)，确认 host、port、pairing 与 channel 设置。
- 要验证服务是否稳定运行：继续看 [使用与运维](./usage.md)，按健康检查与回归顺序排查。
- 要审查公网暴露风险：继续看 [安全机制](./security.md)，确认最小权限与默认拒绝策略。

## 相关页面

- [配置指南](./configuration.md)
- [使用与运维](./usage.md)
- [安全机制](./security.md)
- [命令参考](./commands.md)
