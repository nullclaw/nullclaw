# 配置指南

NullClaw 与 OpenClaw 配置结构兼容，使用 `snake_case` 字段风格。

## 页面导航

- 这页适合谁：已经装好 NullClaw，准备生成、修改或审查 `config.json` 的使用者与运维者。
- 看完去哪里：要把配置真正跑起来看 [使用与运维](./usage.md)；要理解安全边界看 [安全机制](./security.md)；要查看命令入口与覆盖参数看 [命令参考](./commands.md)。
- 如果你是从某页来的：从 [安装指南](./installation.md) 来，下一步通常就是生成初始配置；从 [Gateway API](./gateway-api.md) 来，这页可回查 `gateway` 与 channel 相关字段；从 [安全机制](./security.md) 来，这页提供具体配置落点与示例。

## 配置文件位置

- macOS/Linux: `~/.nullclaw/config.json`
- Windows: `%USERPROFILE%\\.nullclaw\\config.json`

建议先执行：

```bash
nullclaw onboard --interactive
```

这会自动生成初始配置文件。

## 最小可运行配置

下面示例可在本地 CLI 模式跑通（需要替换 API Key）：

```json
{
  "models": {
    "providers": {
      "openrouter": {
        "api_key": "YOUR_OPENROUTER_API_KEY"
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "openrouter/anthropic/claude-sonnet-4"
      }
    }
  },
  "channels": {
    "cli": true
  },
  "memory": {
    "backend": "sqlite",
    "auto_save": true
  },
  "gateway": {
    "host": "127.0.0.1",
    "port": 3000,
    "require_pairing": true
  },
  "autonomy": {
    "level": "supervised",
    "workspace_only": true,
    "max_actions_per_hour": 20
  },
  "security": {
    "sandbox": {
      "backend": "auto"
    },
    "audit": {
      "enabled": true
    }
  }
}
```

## 核心配置块说明

### `models.providers`

- 定义各 LLM provider 的连接参数与 API Key。
- 常见 provider：`openrouter`、`openai`、`anthropic`、`groq` 等。

示例：

```json
{
  "models": {
    "providers": {
      "openrouter": { "api_key": "sk-or-..." },
      "anthropic": { "api_key": "sk-ant-..." },
      "openai": { "api_key": "sk-..." }
    }
  }
}
```

### `agents.defaults.model.primary`

- 设置默认模型路由，格式通常为：`provider/vendor/model`。
- 示例：`openrouter/anthropic/claude-sonnet-4`

### `model_routes`

- 顶层可选路由表，用于 `nullclaw agent` 在每一轮对话里自动选择模型。
- 每个条目用 `hint` 映射到具体的 `provider` 和 `model`。
- 当前 daemon 识别的路由提示词包括：`fast`、`balanced`、`deep`、`reasoning`、`vision`。
- 配置了 `balanced` 时，它会作为常规兜底路线。`fast` 更适合简短的状态/列表/检查类请求，以及提取、计数、分类、只返回结果这类边界清晰的短结构化任务。`deep` 和 `reasoning` 更适合调查、规划、权衡分析和长上下文。`vision` 用于图片输入回合。
- `api_key` 是可选的；如果不填，会继续使用 `models.providers.<provider>` 里的常规凭据。
- `cost_class` 是可选元数据，可选值为 `free`、`cheap`、`standard`、`premium`。
- `quota_class` 是可选元数据，可选值为 `unlimited`、`normal`、`constrained`。

示例：

```json
{
  "model_routes": [
    { "hint": "fast", "provider": "groq", "model": "llama-3.3-70b", "cost_class": "free", "quota_class": "unlimited" },
    { "hint": "balanced", "provider": "openrouter", "model": "anthropic/claude-sonnet-4", "cost_class": "standard", "quota_class": "normal" },
    { "hint": "deep", "provider": "openrouter", "model": "anthropic/claude-opus-4", "cost_class": "premium", "quota_class": "constrained" },
    { "hint": "vision", "provider": "openrouter", "model": "openai/gpt-4.1", "cost_class": "standard", "quota_class": "normal" }
  ]
}
```

说明：

- 只有在当前会话没有被显式 pin 到某个模型时，`model_routes` 才会生效。
- 如果同时配置了 `deep` 和 `reasoning`，深度分析类请求会优先选择 `deep`。
- `/model` 还会显示最近一次自动路由决策，方便查看选中了哪条路线以及原因。
- 如果自动路由命中的提供方遇到配额或限流错误，这条路线会被临时降级，直到冷却时间结束才会再次尝试。
- 路由元数据只会轻微影响评分，不会推翻保守策略。含糊请求仍然优先留在 `balanced`，`fast` 只给高置信度且便宜的任务，强烈的深度分析信号仍然会压过更便宜的路线。

### `agents.list`

- 定义可供 `/delegate` 等工具使用的命名 agent 配置。
- 每个条目既可以显式写 `provider` + `model`，也可以直接在 `model.primary` 中写完整的 `provider/model` 引用。
- 示例：

```json
{
  "agents": {
    "list": [
      {
        "id": "coder",
        "model": { "primary": "ollama/qwen3.5:cloud" },
        "system_prompt": "You're an experienced coder"
      }
    ]
  }
}
```
### `channels`

- 渠道配置统一在 `channels.<name>` 下。
- 多账号渠道通常用 `accounts` 包裹。

Telegram 示例：

```json
{
  "channels": {
    "telegram": {
      "accounts": {
        "main": {
          "bot_token": "123456:ABCDEF",
          "allow_from": ["YOUR_TELEGRAM_USER_ID"]
        }
      }
    }
  }
}
```

规则说明：

- `allow_from: []` 表示拒绝所有入站消息。
- `allow_from: ["*"]` 表示允许所有来源（仅在你明确接受风险时使用）。

Telegram forum topics：

- Topic 会话隔离是自动的，`channels.telegram` 下无需单独配置 `topic_id` 字段。
- 实际操作流程：
  1. 在 `agents.list` 中配置命名 agent 配置
  2. 打开目标 Telegram 群组或 forum topic
  3. 发送 `/bind <agent>`
- 如果要让某个 forum topic 使用特定 agent，在 `bindings` 中配置 `match.peer.id = "<chat_id>:thread:<topic_id>"`。
- 如果还需要为同一 Telegram 群组的其余部分设置兜底 agent，再添加一条 binding，peer id 为纯群组 id `"<chat_id>"`。
- `/bind status` 显示当前生效的路由和可用 agent id。
- `/bind clear` 仅移除当前 account/chat/topic 的精确 binding，让路由回退到更宽泛的匹配。
- `/bind` 会为当前 Telegram account 和 peer 写入一条精确的 `bindings[]` 条目。
- Topic 级 binding 优先于群组级兜底（按路由优先级，与 `bindings[]` 中的顺序无关）。
- Telegram 菜单中 `/bind` 的可见性由 `channels.telegram.accounts.<id>.binding_commands_enabled` 控制。

示例：

```json
{
  "bindings": [
    {
      "agent_id": "coder",
      "match": {
        "channel": "telegram",
        "account_id": "main",
        "peer": { "kind": "group", "id": "-1001234567890:thread:42" }
      }
    },
    {
      "agent_id": "orchestrator",
      "match": {
        "channel": "telegram",
        "account_id": "main",
        "peer": { "kind": "group", "id": "-1001234567890" }
      }
    }
  ]
}
```

上述配置中，topic `42` 路由到 `coder`，群组其余部分兜底到 `orchestrator`。

命名 agent 配置与 bindings 是独立关注点：`agents.list` 定义可复用的配置，`bindings` 决定哪个配置用于哪个 chat/topic。

完整端到端示例：

```json
{
  "agents": {
    "list": [
      {
        "id": "orchestrator",
        "provider": "openrouter",
        "model": "anthropic/claude-sonnet-4"
      },
      {
        "id": "coder",
        "provider": "ollama",
        "model": "qwen2.5-coder:14b",
        "system_prompt": "You are the coding agent for this topic."
      }
    ]
  },
  "channels": {
    "telegram": {
      "accounts": {
        "main": {
          "bot_token": "123456:ABCDEF",
          "allow_from": ["YOUR_TELEGRAM_USER_ID"],
          "binding_commands_enabled": true,
          "topic_commands_enabled": true,
          "topic_map_command_enabled": true,
          "commands_menu_mode": "scoped"
        }
      }
    }
  },
  "bindings": [
    {
      "agent_id": "orchestrator",
      "match": {
        "channel": "telegram",
        "account_id": "main",
        "peer": { "kind": "group", "id": "-1001234567890" }
      }
    }
  ]
}
```

操作流程：

- 在目标 forum topic 中发送 `/bind coder`。
- `nullclaw` 会为该 topic 和 Telegram account 写入一条新的精确 `bindings[]` 条目到 `~/.nullclaw/config.json`。
- 该 topic 中的下一条消息将使用新路由的 agent 配置。
- `nullclaw` 必须对 `~/.nullclaw/config.json` 有写权限，`/bind` 才能持久化变更。

关于 `account_id`：

- `account_id` 标识的是配置中的 Telegram 账号条目，不是 topic 也不是 agent。
- 在标准 `channels.telegram.accounts` 布局中，对象 key 就是 account id。例如 `accounts.main` 意味着 `account_id = "main"`。
- `bindings` 中的 `match.account_id` 将 binding 限定到某个特定 Telegram 账号。
- 如果省略 `match.account_id`，该 binding 可匹配该 channel 下的任意 Telegram 账号。
- 只有同一个 nullclaw 实例运行多个 Telegram bot 账号/token 时，不同 account id 才有意义。

Max 示例：

```json
{
  "channels": {
    "max": [
      {
        "account_id": "main",
        "bot_token": "MAX_BOT_TOKEN",
        "allow_from": ["YOUR_MAX_USER_ID"],
        "group_allow_from": ["YOUR_MAX_USER_ID"],
        "group_policy": "allowlist",
        "mode": "webhook",
        "webhook_url": "https://bot.example.com/max?account_id=main",
        "webhook_secret": "replace-with-random-secret",
        "require_mention": true,
        "streaming": true,
        "interactive": {
          "enabled": true,
          "ttl_secs": 900,
          "owner_only": true
        }
      }
    ]
  }
}
```

Max 说明：

- `channels.max` 是账号条目数组；`account_id` 用于区分多个 Max bot。
- 生产环境推荐 `mode = "webhook"`。Max 文档将 long polling 定位为开发/测试用途，webhook 是推荐的生产路径。
- `webhook_url` 必须使用 HTTPS。
- 多账号 webhook 场景下，每个账号应使用独立的 `webhook_secret` 或在 webhook URL 中使用独立的 `account_id` query，例如 `/max?account_id=main`。
- `allow_from` 和 `group_allow_from` 接受 Max `user_id` 或用户名。`user_id` 是更稳定的选择。
- `require_mention = true` 仅影响群聊。私聊和 `bot_started` deep link 不受影响。
- Max inline button 在 nullclaw 中是一次性的：有效点击后原始键盘会被清除，避免过期按钮。

### `memory`

- `backend`: 建议从 `sqlite` 开始。可选引擎：`sqlite`、`markdown`、`clickhouse`、`postgres`、`redis`、`lancedb`、`lucid`、`memory`（LRU）、`api`、`none`。
- `auto_save`: 开启后会自动持久化会话记忆。
- 可扩展 hybrid 检索与 embedding 配置（见根目录 `config.example.json`）。

### `gateway`

- 默认推荐：
  - `host = "127.0.0.1"`
  - `require_pairing = true`
- 不建议直接公网监听；如需外网访问，优先使用 tunnel。

### `tunnel`

隧道服务，用于将本地网关暴露到公网。当没有公网 IP 但需要接收 webhook 回调时使用。

**支持的隧道：**

| 隧道 | 说明 |
|--------|------|
| `none` | 不使用隧道（默认） |
| `cloudflare` | Cloudflare Tunnel |
| `ngrok` | ngrok 隧道 |
| `tailscale` | Tailscale Funnel |
| `custom` | 自定义命令启动隧道 |

**ngrok 示例：**

```json
{
  "tunnel": {
    "provider": "ngrok",
    "ngrok": {
      "auth_token": "YOUR_NGROK_AUTH_TOKEN",
      "domain": "your-domain.ngrok-free.app"
    }
  }
}
```

**Cloudflare 示例：**

```json
{
  "tunnel": {
    "provider": "cloudflare",
    "cloudflare": {
      "token": "YOUR_CLOUDFLARE_TUNNEL_TOKEN"
    }
  }
}
```

**注意：**

- 隧道会在网关启动前自动启动。
- 启动后公网 URL 会打印到控制台，同时写入 `daemon_state.json`。

### `autonomy`

- `level`: 推荐先用 `supervised`。
- `workspace_only`: 建议保持 `true`，限制文件访问范围。
- `max_actions_per_hour`: 建议保守设置，避免高频自动动作。

### `security`

- `sandbox.backend = "auto"`：自动选择可用隔离后端（如 landlock/firejail/bubblewrap/docker）。
- `audit.enabled = true`：建议开启审计日志。

### 进阶：Web Search + Full Shell（高风险）

仅在你明确理解风险时使用。示例：

```json
{
  "http_request": {
    "enabled": true,
    "allowed_domains": ["192.168.1.10", "*.internal.example.com"],
    "search_base_url": "https://searx.example.com",
    "search_provider": "auto",
    "search_fallback_providers": ["jina", "duckduckgo"]
  },
  "autonomy": {
    "level": "full",
    "allowed_commands": ["*"],
    "allowed_paths": ["*"],
    "require_approval_for_medium_risk": false,
    "block_high_risk_commands": false
  }
}
```

注意：

- `search_base_url`（用于 web_search 工具）：必须是 `https://host[/search]` 或本地/内网的 `http://host[:port][/search]` URL。HTTP 仅允许用于 localhost/私有主机（如 `http://localhost:8888`、`http://192.168.1.10:8888`）。此 URL 供 `web_search` 工具查询 SearXNG 实例使用。
- `allowed_commands: ["*"]` 与 `allowed_paths: ["*"]` 会显著扩大执行范围。
- `http_request.allowed_domains`：绕过 SSRF 保护的域名列表，用于 `http_request` 和 `web_fetch` 工具。
  - `[]` (空数组)：所有域名经过 SSRF 检查（默认，最安全）。
  - `["example.com"]`：只有指定域名跳过 SSRF 保护。
  - `["*.example.com"]`：匹配所有子域名（如 `api.example.com`、`www.example.com`）。
  - `["192.168.1.10"]`：IP 地址也可以加入白名单（仅支持精确匹配，不支持 CIDR 范围）。
  - `["*"]`：**危险** - 所有域名跳过 SSRF 保护和 DNS 钉扎。仅用于可信网络环境，当你控制 DNS 且需要访问任意 IP 地址时使用。这实际上禁用了 SSRF 保护。
  - **示例**：如果你的 SearXNG 运行在 `192.168.1.10`，添加 `"192.168.1.10"` 即可通过 `http_request` 工具访问它。
  - **安全权衡**：白名单域名跳过 DNS 钉扎，允许访问私有 IP。这是用 DNS 重绑定防护换取操作灵活性。
  - **HTTPS-only 策略**：`http_request` 和 `web_fetch` 工具要求使用 `https://` URL。明文 HTTP 因安全原因被拒绝。注意：这不影响 `web_search` 工具的 `search_base_url`，后者允许本地主机使用 HTTP。
  - **检查顺序**：白名单在 DNS 解析之前检查，防止 DNS 渗漏攻击。

## 配置变更后的验证

每次改完配置建议执行：

```bash
nullclaw doctor
nullclaw status
nullclaw channel status
```

如果你修改了 gateway 或 channel，额外执行：

```bash
nullclaw gateway
```

确认服务能正常启动且日志无错误。

## 下一步

- 要验证配置是否可用：继续看 [使用与运维](./usage.md)，按回归检查清单逐项执行。
- 要加固默认边界：继续看 [安全机制](./security.md)，确认 pairing、sandbox 与 allowlist 设置。
- 要对接 webhook 或长期运行网关：继续看 [Gateway API](./gateway-api.md) 和 [命令参考](./commands.md)。

## 相关页面

- [安装指南](./installation.md)
- [使用与运维](./usage.md)
- [安全机制](./security.md)
- [Gateway API](./gateway-api.md)
