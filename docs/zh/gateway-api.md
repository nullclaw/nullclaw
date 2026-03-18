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
| `/whatsapp` | GET | Query 参数 | Meta Webhook 验证 |
| `/whatsapp` | POST | Meta 签名 | WhatsApp 入站消息 |
| `/max` | POST | `X-Max-Bot-Api-Secret`（配置后必填） | Max 入站 webhook |

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

### 4) Max webhook 投递

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
