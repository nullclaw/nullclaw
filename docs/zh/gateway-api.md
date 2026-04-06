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

## REST 管理 API（`/api/`）

通过在 `config.json` 中设置 `gateway.admin_api: true` 启用。使用与 webhook 相同的 Bearer token 鉴权。

所有响应均使用统一 JSON 信封：

```json
{ "success": true,  "data": {...},  "error": null }
{ "success": false, "data": null,   "error": {"code":"...", "message":"..."} }
```

### 端点

| 端点 | Method | 说明 |
|---|---|---|
| `/api/status` | GET | 版本、pid、运行时长、整体状态与组件健康 |
| `/api/config?path=<dot路径>` | GET | 读取单个配置项 |
| `/api/config` | PATCH | 修改配置项（仅限白名单路径） |
| `/api/config` | DELETE | 删除配置项 |
| `/api/config/reload` | POST | 从磁盘热重载配置 |
| `/api/config/validate` | POST | 校验配置但不应用 |
| `/api/models` | GET | 列出已配置的 provider（不返回密钥） |
| `/api/cron` | GET | 列出所有定时任务 |
| `/api/cron` | POST | 新建周期性 cron 任务 |
| `/api/cron/once` | POST | 新建一次性延迟任务 |
| `/api/cron/:id/run` | POST | 立即触发任务 |
| `/api/cron/:id/pause` | POST | 暂停任务 |
| `/api/cron/:id/resume` | POST | 恢复任务 |
| `/api/cron/:id` | PATCH | 更新任务字段 |
| `/api/cron/:id` | DELETE | 删除任务 |
| `/api/channels` | GET | 列出已配置的 channel 及其健康状态 |
| `/api/channels/:name` | GET | 指定 channel 类型的详情 |
| `/api/skills` | GET | 列出已安装的 skill |
| `/api/skills/:name` | POST | 安装 skill |
| `/api/skills/:name` | DELETE | 卸载 skill |
| `/api/mcp` | GET | 列出已配置的 MCP server（env/header 值已脱敏） |
| `/api/mcp/:name` | GET | 指定 MCP server 的详情 |
| `/api/agent` | POST | 单次 agent 调用（请求体：`{"message":"...","session":"..."}`） |
| `/api/agent/stream` | POST | SSE 流式变体 — 网关 HTTP 传输层支持分块响应前返回 501 |
| `/api/agent/sessions` | GET | 列出活跃的 agent 会话 |
| `/api/agent/sessions/:id` | DELETE | 终止指定 agent 会话 |
| `/api/memory` | GET | 列出记忆条目；支持过滤参数：`?category=`、`?session=`、`?q=`（全文检索）、`?limit=`、`?include_internal=true` |
| `/api/memory/:key` | DELETE | 按 key 删除记忆条目 |

#### `POST /api/agent`

向 agent 发送消息并等待响应，适用于单次触发场景（菜单栏 App、iOS 快捷指令、CLI 仪表板等）。

请求体：

```json
{ "message": "总结未解决的 issue", "session": "my-session" }
```

`session` 可选，默认为 `"api:default"`。包含 `:` 的会话 key 在 URL 路径中须以 `%3A` 进行百分号编码。

响应：

```json
{
  "success": true,
  "data": {
    "response": "以下是未解决的 issue……",
    "session": "my-session",
    "turn_count": 1
  },
  "error": null
}
```

#### `GET /api/memory`

从已配置的记忆后端列出记忆条目。所有查询参数均为可选：

| 参数 | 说明 |
|------|------|
| `?category=<name>` | 按类别过滤：`core`、`daily`、`conversation` 或自定义名称 |
| `?session=<id>` | 按会话 ID 过滤 |
| `?q=<text>` | 全文搜索（调用后端 `recall()`），忽略 `category`/`session` 过滤 |
| `?limit=<n>` | 最大返回条数（列表默认 100，搜索默认 20） |
| `?include_internal=true` | 包含 autosave/bootstrap 内部 key（默认不包含） |

未配置记忆后端时返回 `503 MEMORY_UNAVAILABLE`。

```json
{
  "success": true,
  "data": {
    "entries": [
      {
        "id": "1",
        "key": "greeting",
        "content": "Hello world",
        "category": "core",
        "timestamp": "2026-04-06T00:00:00Z",
        "session_id": null,
        "score": null
      }
    ],
    "total": 1,
    "backend": "sqlite"
  },
  "error": null
}
```

#### `DELETE /api/memory/:key`

按 key 删除记忆条目。key 在查找前会进行百分号解码（如 `%2F` → `/`）。key 不存在时返回 `404 NOT_FOUND`。

```json
{ "success": true, "data": { "key": "greeting", "deleted": true }, "error": null }
```

未配置记忆后端时返回 `503 MEMORY_UNAVAILABLE`。

## 鉴权与安全建议

1. 保持 `gateway.require_pairing = true`。
2. 网关优先绑定 `127.0.0.1`，外网访问通过 tunnel/反向代理。
3. token 视为密钥，不写入公开仓库或日志。
4. Max webhook secret 同理：每个账号使用独立随机值，不跨 bot 复用。
5. 仅在可信客户端（如 NullClaw iOS App）需要时开启 `gateway.admin_api = true`。

## 下一步

- 要先把网关配置对：继续看 [配置指南](./configuration.md)，确认 host、port、pairing 与 channel 设置。
- 要验证服务是否稳定运行：继续看 [使用与运维](./usage.md)，按健康检查与回归顺序排查。
- 要审查公网暴露风险：继续看 [安全机制](./security.md)，确认最小权限与默认拒绝策略。

## 相关页面

- [配置指南](./configuration.md)
- [使用与运维](./usage.md)
- [安全机制](./security.md)
- [命令参考](./commands.md)
