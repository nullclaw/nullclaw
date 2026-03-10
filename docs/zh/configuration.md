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

### `memory`

- `backend`: 建议从 `sqlite` 开始。
- `auto_save`: 开启后会自动持久化会话记忆。
- 可扩展 hybrid 检索与 embedding 配置（见根目录 `config.example.json`）。

### `gateway`

- 默认推荐：
  - `host = "127.0.0.1"`
  - `require_pairing = true`
- 不建议直接公网监听；如需外网访问，优先使用 tunnel。

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

- `search_base_url` 必须是 `https://host[/search]`，或者本地/内网可达的 `http://host[:port][/search]`，否则启动校验会失败。
- `allowed_commands: ["*"]` 与 `allowed_paths: ["*"]` 会显著扩大执行范围。

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
