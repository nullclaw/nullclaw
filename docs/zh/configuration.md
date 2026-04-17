# 配置指南

NullClaw 与 OpenClaw 配置结构兼容，使用 `snake_case` 字段风格。

## 页面导航

- 这页适合谁：已经装好 NullClaw，准备生成、修改或审查 `config.json` 的使用者与运维者。
- 看完去哪里：要把配置真正跑起来看 [使用与运维](./usage.md)；要理解安全边界看 [安全机制](./security.md)；要查看命令入口与覆盖参数看 [命令参考](./commands.md)；要接非 core 渠道看 [外部渠道插件](./external-channels.md)。
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

### `diagnostics`

- 用于控制运行时诊断与可观测性输出。
- 配置 OpenTelemetry 时，请使用嵌套的 `diagnostics.otel` 对象。
- OTEL spans 会在回合完成、agent 结束等自然运行边界触发 flush；更长运行流程仍保留批量 flush 作为兜底。
- OTEL endpoint 应优先使用 HTTPS；只有 localhost、私有网络 collector，或 `host.docker.internal`、`host.containers.internal`、`otel` 这类容器本地目标才适合使用明文 HTTP。

示例：

```json
{
  "diagnostics": {
    "backend": "otel",
    "log_tool_calls": true,
    "log_message_receipts": true,
    "log_message_payloads": true,
    "log_llm_io": true,
    "otel": {
      "endpoint": "https://otel:4318",
      "service_name": "nullclaw",
      "headers": {
        "Authorization": "Bearer example-token"
      }
    }
  }
}
```

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

常见的 provider 级字段：

- `api_key`：该 provider 条目的凭据。
- `base_url`：用于自定义或自托管 OpenAI 兼容端点的地址覆盖。
- `api_mode`：为兼容 provider 选择 `chat_completions` 或 `responses`。
- `user_agent`：可选的 `User-Agent` 请求头覆盖。
- `max_streaming_prompt_bytes`：当估算 prompt 大小超过该阈值时跳过流式请求。
- `chat_template_enable_thinking_param`：针对自定义 OpenAI 兼容的 vLLM/Qwen 端点，把 `reasoning_effort` 映射到 `chat_template_kwargs.enable_thinking`。

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

#### `agents.list[].workspace_path`

当某个命名 agent 需要使用独立工作区而不是全局工作区时，使用 `workspace_path`。

示例：

```json
{
  "agents": {
    "list": [
      {
        "id": "coder",
        "model": { "primary": "ollama/qwen2.5-coder:14b" },
        "system_prompt": "Focus on implementation and tests.",
        "workspace_path": "agents/coder"
      }
    ]
  }
}
```

行为说明：

- 相对路径会相对于 `config.json` 所在目录解析。
- 绝对路径会原样使用。
- 配置中可以写 `/` 或 `\`，运行时会按当前操作系统规范化路径分隔符。
- `workspace_path` 不会禁用 `system_prompt`。如果两者同时设置，nullclaw 仍会应用命名 agent 的 profile prompt，并从该独立工作区加载 bootstrap 上下文。
- 首次使用时，如果工作区不存在，nullclaw 会自动创建并初始化：
  - `AGENTS.md`
  - `SOUL.md`
  - `IDENTITY.md`
  - `MEMORY.md`

隔离模型：

- 该 agent 的文件操作、markdown memory 文件以及 workspace 相关上下文都会使用这个工作区。
- 设置 `workspace_path` 后，该 agent 还会获得一个持久 memory namespace，格式为 `agent:<agent-id>`。
- 这个 namespace 会用于：
  - `nullclaw agent --agent <id>`
  - `/subagents spawn --agent <id> ...`
  - 通过 `bindings` 路由到该命名 agent 的会话

实际效果：

- 两个命名 agent 即使使用相同的 provider/model，也可以保持各自独立的持久笔记和工作区。
- `workspace_path` 本身不会决定聊天路由；路由仍然由 `bindings`、`/bind` 或显式 `--agent` / `/subagents spawn --agent` 决定。

### `messages.inbound`

- `debounce_ms` 用来延迟处理连续快速到达的纯文本入站消息，把短时间内的多条碎片合并成一次 turn。
- 默认值：`3000`。
- 作用范围包括 daemon 路由的入站文本和 Agent CLI REPL。
- 设为 `0` 可关闭。
- slash 命令和带媒体的入站消息会跳过 debounce。
- Telegram 仍保留自己的长消息分段合并逻辑；这里的值会作为那条逻辑的基础 debounce 窗口。

示例：

```json
{
  "messages": {
    "inbound": {
      "debounce_ms": 1500
    }
  }
}
```

### `reliability`

- 配置 LLM 提供者的全局重试和故障转移行为。
- `provider_retries`: 重试失败的 LLM 请求的次数（默认值：2）。
- `provider_backoff_ms`: 重试之间的初始指数退避延迟（默认值：500 毫秒）。
- `fallback_providers`: 当未显式指定 provider 的模型需要在主要提供方之外继续尝试时，可使用的备用提供方名称列表。
- `model_fallbacks`: 模型到有序备用模型列表的映射。每个备用项既可以是裸模型名，也可以是显式的 `provider/model` 引用。

示例：

```json
{
  "reliability": {
    "provider_retries": 2,
    "provider_backoff_ms": 500,
    "fallback_providers": ["groq", "openai"],
    "model_fallbacks": [
      {
        "model": "anthropic/claude-sonnet-4",
        "fallbacks": ["openai/gpt-4o", "groq/llama-3.3-70b"]
      }
    ]
  }
}
```

备注：

- 裸模型名的故障转移顺序：先尝试主要提供方，再依次尝试每个列出的 `fallback_provider`。
- 像 `openai/gpt-4o` 这样的显式 `provider/model` 备用项会直接路由到对应 provider，不会再走通用 provider 扇出链路。
- `api_keys`: (可选) 用于在速率限制 (429) 错误时轮换的额外 API 密钥列表。
### `identity`（AIEOS v1.1）

如果你希望运行时身份来自 AIEOS 文档，可以使用这一节。配置后，nullclaw 会把解析后的 AIEOS 内容连同 `AGENTS.md`、`IDENTITY.md` 等工作区身份文件一起注入 system prompt：

```json
{
  "identity": {
    "format": "aieos",
    "aieos_path": "./identity/aieos.identity.json"
  }
}
```

也可以直接把同样的文档内联到配置里：

```json
{
  "identity": {
    "format": "aieos",
    "aieos_inline": "{\"identity\":{\"names\":{\"first\":\"nullclaw-assistant\"},\"bio\":\"通用自主助手\"},\"linguistics\":{\"style\":\"concise\"},\"motivations\":{\"core_drive\":\"安全地帮助操作者完成任务\"}}"
  }
}
```

最小 AIEOS v1.1 示例文件（`identity/aieos.identity.json`）：

```json
{
  "identity": {
    "names": {
      "first": "nullclaw-assistant"
    },
    "bio": "通用自主助手"
  },
  "linguistics": {
    "style": "concise"
  },
  "motivations": {
    "core_drive": "安全地帮助操作者完成任务"
  }
}
```

说明：

- AIEOS payload 采用 `identity`、`psychology`、`linguistics`、`motivations`、`capabilities` 等顶层 section。
- 为了可维护性和版本控制可读性，优先使用 `aieos_path`。
- 只有在你确实需要单文件自包含配置时，再使用 `aieos_inline`。
- `identity.format` 应与 payload 来源保持一致，也就是 `aieos`。
- 相对路径的 `aieos_path` 会优先按当前 workspace 解析，找不到时再按当前工作目录解析。

### `channels`

- 渠道配置统一在 `channels.<name>` 下。
- 多账号渠道通常用 `accounts` 包裹。

外部渠道插件示例：

```json
{
  "channels": {
    "external": {
      "accounts": {
        "wa-web": {
          "runtime_name": "whatsapp_web",
          "transport": {
            "command": "nullclaw-plugin-whatsapp-web",
            "args": ["--stdio"],
            "timeout_ms": 10000,
            "env": {
              "PLUGIN_TOKEN": "secret"
            }
          },
          "config": {
            "bridge_url": "http://127.0.0.1:3301",
            "allow_from": ["*"]
          }
        }
      }
    }
  }
}
```

外部渠道说明：

完整的协议、生命周期、metadata 约定和插件作者契约，请继续看
[外部渠道插件](./external-channels.md)。

- `runtime_name` 是 nullclaw 内部使用的运行时渠道 id，routing、bindings、session key 和出站分发都会使用它。它不能复用内建 channel 名称，也不能和任何其他已配置 channel 已占用的运行时名字冲突。
- `transport.command` 和可选的 `transport.args` 会把插件作为子进程启动，并通过 stdio 上的逐行 JSON-RPC 通信。
- `transport.timeout_ms` 会限制 host 到插件的 RPC 等待时间；同时 nullclaw 还会在内部对 control-plane 请求做上限裁剪，避免一个坏插件把 supervision 卡住几分钟。
- `transport.env` 只会传给插件进程本身。
- `config` 必须是 JSON object；它会原样透传给插件 `start` 请求里的 `params.config`。
- 插件必须响应 `get_manifest`，处理 `start`、`send`、`stop`；建议实现 `health`，这样 supervision 才能识别“进程活着但 sidecar 已断开”的状态。
- `get_manifest.result` 现在必须显式声明 `protocol_version: 2`；`capabilities.health`、`capabilities.streaming`、`capabilities.send_rich`、`capabilities.typing`、`capabilities.edit`、`capabilities.delete`、`capabilities.reactions`、`capabilities.read_receipts` 都是可选能力标记。
- `health.result` 必须返回显式布尔值（`healthy`）或显式健康信号（`ok`、`connected`、`logged_in`）；空对象会被视为无效响应。对于需要扫码或设备绑定的渠道，后台认证尚未完成时，应在这里报告 `connected: false` 或 `logged_in: false`。
- `start.params` 现在包含嵌套的 `runtime` 对象，里面有 `name`、`account_id` 和 host 提供的 `state_dir`。
- `start.result` 必须返回 `started: true`；`start` 应在完成本地初始化后尽快返回，而不是阻塞等待扫码或人工登录。`send`、`send_rich`、`edit_message`、`delete_message` 以及其他 typing/message-action RPC 在真正接受动作时都必须返回 `result.accepted: true`。仅仅没有 JSON-RPC `error` 已经不够了。
- `send.params` 现在也拆成嵌套的 `runtime` 和 `message` 对象；文本字段统一使用 `message.text`。
- 如果插件同时声明了 `capabilities.edit=true` 和 `capabilities.delete=true`，那么 `send.result` 还可以返回 `message_id`，或者返回 `message { target?, message_id }`；这样 nullclaw 就能在不支持原生 `.chunk` 流式发送的渠道上维护一条可编辑的草稿消息。
- 如果 `capabilities.streaming=true`，nullclaw 可能在模型流式输出时发送 `.chunk` 阶段的 `send` 事件；如果缺省或为 `false`，只会发送最终结果。
- 如果 `capabilities.send_rich=true`，host 还可能调用 `send_rich`，其参数同样包含嵌套的 `runtime` 和 `message { target, text, attachments, choices }`。
- 如果 `capabilities.typing=true`，host 还可能调用 `start_typing` / `stop_typing`，参数包含嵌套的 `runtime` 和 `recipient`。
- 如果声明了 `capabilities.edit=true` / `capabilities.delete=true`，host 还可能调用 `edit_message` / `delete_message`。
- 如果声明了 `capabilities.reactions=true` 或 `capabilities.read_receipts=true`，host 还可能调用 `set_reaction` 和 `mark_read`。
- `inbound_message.params.message` 必须包含 `sender_id`、`chat_id`、`text`；如果带了 `metadata`，它必须是 JSON object；如果带了 `media`，它必须是由非空字符串组成的数组。
- 如果希望 unknown channel 也能正确做 routing/bindings，建议在 `metadata` 里带上 `peer_kind` 和 `peer_id`。
- unknown/external channel 也可以提供 `metadata.is_group`、`metadata.is_dm` 或 `metadata.typing_recipient`，nullclaw 会把这些信息提升到 prompt 的 conversation context 和处理状态路由里。
- PR #265 的 WhatsApp Web bridge 兼容适配器示例放在 `examples/whatsapp-web/nullclaw-plugin-whatsapp-web`。
- 生产级的配套仓库已经移到仓库外：[nullclaw/nullclaw-channel-baileys](https://github.com/nullclaw/nullclaw-channel-baileys) 和 [nullclaw/nullclaw-channel-whatsmeow-bridge](https://github.com/nullclaw/nullclaw-channel-whatsmeow-bridge)。
- `nullclaw channel start external` 会启动第一个已配置的外部账号；`nullclaw channel start <runtime_name>` 可以直接启动某个具体运行时名字，比如 `whatsapp_web`。

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

WeChat 示例：

```json
{
  "channels": {
    "wechat": [
      {
        "account_id": "main",
        "callback_token": "wechat-callback-token",
        "encoding_aes_key": "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
        "app_id": "wx1234567890abcdef",
        "app_secret": "wechat-app-secret",
        "allow_from": ["openid_123"]
      }
    ]
  }
}
```

WeChat 说明：

- NullClaw 已经内置 WeChat webhook channel；接收公众号回调时不需要额外的 external plugin。
- Gateway webhook 路径是 `/wechat`。配置多个 WeChat 账号时，可通过 `?account_id=<id>` 选择账号。
- `callback_token` 是签名校验必填项。
- `encoding_aes_key` 是可选项；当 WeChat 回调配置为 `encrypt_type=aes` 时必须提供。
- `app_id` 和 `app_secret` 只有在需要通过 WeChat custom message API 主动发送消息时才需要。
- `allow_from` 应显式列出可信 OpenID，不要依赖空 allowlist 来实现隐私隔离。
- 如果当前二进制未编译 WeChat channel，请使用 `-Dchannels=wechat`（或 `-Dchannels=all`）重新构建。

规则说明：

- 空 `allow_from` 的行为因渠道而异。有些渠道（例如 WeChat 和 Discord）会把省略或留空视为“关闭过滤”，而不是“拒绝所有”；如果要做私有机器人，请显式填写 ID/OpenID。
- `allow_from: ["*"]` 会在基于 allowlist 的渠道上允许所有来源，仅在你明确接受风险时使用。

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
          "draft_previews": false,
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

关于 `draft_previews`：

- 默认值也是推荐值是 `false`。
- 关闭后，Telegram 仍会在回复生成期间显示活动状态/typing，但不会使用临时的 `sendMessageDraft` 预览。
- 只有在你明确想要实时部分预览，并且能接受 Telegram 在最终消息到达前隐藏、替换这些 draft 时，才建议设置 `draft_previews=true`。

关于 `account_id`：

- `account_id` 标识的是配置中的 Telegram 账号条目，不是 topic 也不是 agent。
- 在标准 `channels.telegram.accounts` 布局中，对象 key 就是 account id。例如 `accounts.main` 意味着 `account_id = "main"`。
- `bindings` 中的 `match.account_id` 将 binding 限定到某个特定 Telegram 账号。
- 如果省略 `match.account_id`，该 binding 可匹配该 channel 下的任意 Telegram 账号。
- 只有同一个 nullclaw 实例运行多个 Telegram bot 账号/token 时，不同 account id 才有意义。

### Web UI / Browser Relay

`channels.web` 用于浏览器 UI / 扩展通过 WebSocket 接入，默认路径是 `/ws`。

示例：

```json
{
  "channels": {
    "web": {
      "accounts": {
        "default": {
          "transport": "local",
          "listen": "127.0.0.1",
          "port": 32123,
          "path": "/ws",
          "auth_token": "replace-with-long-random-token",
          "message_auth_mode": "pairing",
          "allowed_origins": ["http://localhost:5173"]
        }
      }
    }
  }
}
```

实用规则：

- 想使用“先连上再配对”的本地体验，保持 `listen = "127.0.0.1"`。
- 在 local transport 下，只有 loopback 才允许未鉴权的 WebSocket upgrade；这样 UI 才能先连上，再发送 `pairing_request`。
- 如果把 `listen` 改成 `0.0.0.0` 或其他非 loopback 地址，那么 WebSocket upgrade 一开始就必须带上 channel token：
  - `ws://host:32123/ws?token=<auth_token>`
  - 或 `Authorization: Bearer <auth_token>`
- 非 loopback bind 下，不要假设 local `pairing_request` 还能在未鉴权连接上工作；这个 pairing-first 流程本来就是只给 loopback 用的。
- `message_auth_mode = "pairing"` 表示每条 `user_message` 都要带上 pairing 流程返回的 UI `access_token`。
- `message_auth_mode = "token"` 只支持 local transport，并且要求使用配置或环境变量中的稳定 token。此模式下，UI 每条 `user_message` 发送 `auth_token`，而不是 pairing JWT。
- `auth_token` 既可以加固 WebSocket upgrade，在非 loopback bind 时也会变成必需项。
- WebSocket 端点用的是 `/ws`。`/pair` 属于 HTTP gateway API，不是 web channel 的 WebSocket 配对入口。
- 对于 headless/LAN 场景，更稳妥的运维路径仍然是 SSH 隧道，或者在 loopback 绑定前面加反向代理。

远程 / 无头设备示例：

```json
{
  "channels": {
    "web": {
      "accounts": {
        "default": {
          "transport": "local",
          "listen": "0.0.0.0",
          "port": 32123,
          "path": "/ws",
          "auth_token": "replace-with-long-random-token",
          "message_auth_mode": "token",
          "allowed_origins": ["https://chat-ui.example.com"]
        }
      }
    }
  }
}
```

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

**注意**：`markdown_only` 内存配置文件会自动启用混合检索和时间衰减（半衰期 30 天），以实现最佳的相关性评分。这确保了对纯 markdown 文件的时间感知能力。

### `gateway`

- 默认推荐：
  - `host = "127.0.0.1"`
  - `require_pairing = true`
- 不建议直接公网监听；如需外网访问，优先使用 tunnel。

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `host` | `"127.0.0.1"` | 监听地址 |
| `port` | `3000` | 监听端口 |
| `require_pairing` | `true` | 所有 API 请求均需 bearer token |
| `allow_public_bind` | `false` | 允许绑定非回环地址 |
| `pair_rate_limit_per_minute` | `10` | 每 IP 每分钟最大 `/pair` 请求数 |
| `webhook_rate_limit_per_minute` | `60` | 每 IP 每分钟最大 webhook 请求数 |
| `idempotency_ttl_secs` | `300` | 幂等请求结果缓存时长（秒） |
| `max_body_size_bytes` | `65536` | HTTP 请求体最大字节数（64 KB）。接受图片或文件负载时需调高（如 `20971520` 表示 20 MB）。 |
| `request_timeout_secs` | `30` | 入站 HTTP 请求的 socket 读取超时（秒）。在慢速或高延迟连接下接受大体积负载时需调高。 |

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
