# 外部渠道插件

这页专门说明 `channels.external` 运行时，以及如何在不把渠道专用代码并入 core 的前提下为 nullclaw 增加新渠道。

## 页面导航

**这页适合谁**

- 需要在 `config.json` 里接入外部渠道的运维者
- 正在实现新渠道 bridge/plugin 的作者
- 需要判断某个集成应不应该进 core 的维护者

**下一步建议**

- 配置全貌看 [配置指南](./configuration.md)
- 想理解整体运行时模型看 [架构总览](./architecture.md)
- 想看上线后的运行与排障看 [使用与运维](./usage.md)

## 为什么要有 External Channel

`channels.external` 是社区渠道和站点私有渠道的干净扩展路径。它的目标是：

- 不把渠道专用 SDK、sidecar、bridge 逻辑塞进 nullclaw core
- 避免 in-process ABI/plugin loading 带来的复杂度
- 允许每个渠道的实现独立使用自己的语言和仓库
- 让 host/plugin 边界足够窄、显式且易于 supervision

host/plugin 边界如下：

- transport：`stdin`/`stdout` 上逐行 JSON-RPC
- process model：由 nullclaw 启动的子进程
- routing surface：只暴露通用 `Channel` 操作
- 渠道专用逻辑：完全留在插件内

## 什么时候该用它

适合用 external channel 的情况：

- 这个渠道依赖很大的 SDK 或非 Zig 运行时
- 集成是小众、实验性或强站点定制的
- 更适合通过本地 sidecar / bridge 来接入
- 你希望独立于 nullclaw 发布节奏快速迭代

不适合用它的情况：

- 这其实是产品层 / app 层，而不是 channel
- 你需要改动 core routing、memory、安全边界或 agent 语义
- 这个集成更像 tools/MCP，而不是消息传输层

## 配置模型

外部渠道配置放在 `channels.external.accounts.<id>` 下。

示例：

```json
{
  "channels": {
    "external": {
      "accounts": {
        "wa-web": {
          "runtime_name": "whatsapp_web",
          "transport": {
            "command": "/opt/nullclaw/plugins/nullclaw-plugin-whatsapp-web",
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

字段含义：

- `runtime_name`
  运行时 channel 名称，会参与 routing、bindings、session key、daemon dispatch，以及 `nullclaw channel start <runtime_name>`。
- `transport.command`
  插件进程的可执行路径或命令名。
- `transport.args`
  可选参数数组。
- `transport.env`
  仅传给插件进程的环境变量。
- `transport.timeout_ms`
  这个账号的 host RPC 超时上限。host 对 supervision 敏感路径还会继续做更短的内部裁剪。
- `config`
  不透明 JSON object，会原样传给插件 `start` RPC 的 `params.config`。

校验规则：

- `runtime_name` 不能为空，只能包含字母、数字、`_`、`-`、`.`
- `runtime_name` 必须在所有 built-in 和已配置运行时渠道中全局唯一
- `transport.command` 必填
- `transport.timeout_ms` 必须在 `[1, 600000]`
- `config` 必须是 JSON object

## 运行时架构

运行时里，host 会为每个账号创建一个通用 `ExternalChannel`，流程如下：

1. 启动插件子进程
2. 获取并校验 manifest
3. 发送 `start`
4. 把通用 `Channel` 调用映射成 JSON-RPC 请求
5. 接收 `inbound_message` 通知并发布到 bus
6. 用有界健康探针做 supervision

关键性质：

- 一个配置账号对应一个插件子进程
- 插件会像其他 channel runtime 一样被 supervision
- 插件 stdout 只能输出 JSON-RPC
- 插件 stderr 可以写诊断信息

## 传输契约

传输层是基于 stdio 的逐行 JSON-RPC 2.0。

规则：

- 每个 request、response、notification 都必须占一行
- stdout 只能输出 JSON-RPC
- stderr 不参与协议，可以自由打印
- request/response 通过 JSON-RPC `id` 关联
- 下文要求为 object 的 `params`/`result` 必须真的是 JSON object

## Manifest

host 会先发：

```json
{"jsonrpc":"2.0","id":1,"method":"get_manifest","params":{}}
```

插件必须返回：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocol_version": 2,
    "capabilities": {
      "health": true,
      "streaming": false,
      "send_rich": false,
      "typing": false,
      "edit": false,
      "delete": false,
      "reactions": false,
      "read_receipts": false
    }
  }
}
```

规则：

- `protocol_version` 必须等于 `2`
- `capabilities` 可省略
- 没声明的 capability 一律按不支持处理

Capability 含义：

- `health`
  插件实现了 `health` RPC，可以汇报渠道级健康状态。
- `streaming`
  插件能接受模型流式输出产生的 `.chunk` 分段发送事件。
- `send_rich`
  插件实现了 `send_rich`。
- `typing`
  插件实现了 `start_typing` 和 `stop_typing`。
- `edit`
  插件实现了 `edit_message`，允许 host 后续原地更新同一条消息。
- `delete`
  插件实现了 `delete_message`，允许 host 后续删除同一条消息。
- `reactions`
  插件实现了 `set_reaction`。
- `read_receipts`
  插件实现了 `mark_read`。

## 生命周期 RPC

### `start`

Host 请求：

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "start",
  "params": {
    "runtime": {
      "name": "whatsapp_web",
      "account_id": "wa-web",
      "state_dir": "/home/user/.nullclaw/workspace/state/channels/external/whatsapp_web/wa-web"
    },
    "config": {
      "bridge_url": "http://127.0.0.1:3301",
      "allow_from": ["*"]
    }
  }
}
```

必须返回的成功响应：

```json
{"jsonrpc":"2.0","id":2,"result":{"started":true}}
```

说明：

- `runtime.state_dir` 是 host 分配给这个账号的持久化目录
- 插件应把 `config` 当成自己的 opaque settings
- 只有 JSON-RPC 成功但没有 `result.started: true` 会被 host 拒绝

### `stop`

Host 请求：

```json
{"jsonrpc":"2.0","id":3,"method":"stop","params":{}}
```

host 不要求额外的固定字段，但仍然建议插件返回一个 `result` object。

## 健康检查 RPC

如果 `capabilities.health=true`，host 可能调用：

```json
{"jsonrpc":"2.0","id":4,"method":"health","params":{}}
```

可接受的响应形态：

```json
{"jsonrpc":"2.0","id":4,"result":{"healthy":true}}
```

或：

```json
{"jsonrpc":"2.0","id":4,"result":{"ok":true,"connected":true,"logged_in":true}}
```

规则：

- 如果有 `healthy`，它必须是布尔值
- 否则 `ok`、`connected`、`logged_in` 至少要出现一个
- 空对象 `{}` 是非法响应
- 如果插件不支持 `health`，就不要声明 capability，不要返回假的 stub 成功

## 出站 RPC

### `send`

Host 请求：

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "send",
  "params": {
    "runtime": {
      "name": "whatsapp_web",
      "account_id": "wa-web"
    },
    "message": {
      "target": "room-1",
      "text": "hello",
      "stage": "final",
      "media": []
    }
  }
}
```

必须返回的成功响应：

```json
{"jsonrpc":"2.0","id":5,"result":{"accepted":true}}
```

如果插件同时声明了 `capabilities.edit=true` 和
`capabilities.delete=true`，那么 `send` 还可以返回稳定的消息引用，
这样 host 后面就能继续更新或删除同一条消息：

```json
{"jsonrpc":"2.0","id":5,"result":{"accepted":true,"message_id":"msg-42"}}
```

或者：

```json
{"jsonrpc":"2.0","id":5,"result":{"accepted":true,"message":{"target":"room-1","message_id":"msg-42"}}}
```

规则：

- `message.target` 的语义由插件自己定义
- 文本字段统一叫 `message.text`，`content` 已经不再合法
- `message.stage` 只能是 `"final"` 或 `"chunk"`
- `message.media` 是字符串数组
- 如果插件实际上没有接受这个动作，就不能伪造成功
- 如果要让 host 后续执行 edit/delete，`message_id` 必须是非空且稳定的渠道消息标识
- `result.message.target` 可以省略；省略时 host 会沿用原始出站目标
- 没声明 `edit` + `delete` 的插件，只返回 `{"accepted": true}` 就可以

host 现在严格区分：

- JSON-RPC success：请求传输成功
- `result.accepted: true`：插件真正接受了这个动作

返回 `{"accepted": false}` 会被当成拒绝，而不是成功。

### `send_rich`

只有在 `capabilities.send_rich=true` 时才会调用。

Host 请求：

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "send_rich",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "text": "Choose one",
      "attachments": [
        {
          "kind": "image",
          "target": "/tmp/card.png",
          "caption": "preview"
        }
      ],
      "choices": [
        {
          "id": "yes",
          "label": "Yes",
          "submit_text": "yes"
        }
      ]
    }
  }
}
```

必须返回：

```json
{"jsonrpc":"2.0","id":6,"result":{"accepted":true}}
```

`attachments[].kind` 目前支持：

- `image`
- `document`
- `video`
- `audio`
- `voice`

如果不支持 `send_rich`，就不要声明 capability。只有在 payload 足够简单时，host 才可能退化为普通 `send`。

### `edit_message`

只有在 `capabilities.edit=true` 时才会调用。

Host 请求：

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "edit_message",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "message_id": "msg-42",
      "text": "patched",
      "attachments": [],
      "choices": []
    }
  }
}
```

必须返回：

```json
{"jsonrpc":"2.0","id":7,"result":{"accepted":true}}
```

当某个渠道本身不支持原生 `.chunk` 流式发送时，host 可能会先 `send`
一条草稿消息，再用这个 RPC 持续更新它。

### `delete_message`

只有在 `capabilities.delete=true` 时才会调用。

Host 请求：

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "delete_message",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "message_id": "msg-42"
    }
  }
}
```

必须返回：

```json
{"jsonrpc":"2.0","id":8,"result":{"accepted":true}}
```

### `set_reaction`

只有在 `capabilities.reactions=true` 时才会调用。

Host 请求：

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "set_reaction",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "message_id": "msg-42",
      "emoji": "✅"
    }
  }
}
```

必须返回：

```json
{"jsonrpc":"2.0","id":9,"result":{"accepted":true}}
```

规则：

- `emoji` 为字符串时表示设置或更新 reaction
- `emoji: null` 表示清除这个消息上的 reaction

### `mark_read`

只有在 `capabilities.read_receipts=true` 时才会调用。

Host 请求：

```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "mark_read",
  "params": {
    "runtime": {
      "name": "plugin_chat",
      "account_id": "main"
    },
    "message": {
      "target": "room-1",
      "message_id": "msg-42"
    }
  }
}
```

必须返回：

```json
{"jsonrpc":"2.0","id":10,"result":{"accepted":true}}
```

### Typing RPC

只有在 `capabilities.typing=true` 时才会调用。

请求：

```json
{"jsonrpc":"2.0","id":11,"method":"start_typing","params":{"runtime":{"name":"plugin_chat","account_id":"main"},"recipient":"room-1"}}
```

```json
{"jsonrpc":"2.0","id":12,"method":"stop_typing","params":{"runtime":{"name":"plugin_chat","account_id":"main"},"recipient":"room-1"}}
```

必须返回：

```json
{"jsonrpc":"2.0","id":13,"result":{"accepted":true}}
```

## 入站通知

插件通过通知上报入站消息：

```json
{
  "jsonrpc": "2.0",
  "method": "inbound_message",
  "params": {
    "message": {
      "sender_id": "5511",
      "chat_id": "room-1",
      "text": "hello",
      "session_key": "optional-custom-session",
      "media": ["https://example.com/a.jpg"],
      "metadata": {
        "peer_kind": "group",
        "peer_id": "room-1",
        "is_group": true,
        "typing_recipient": "room-1"
      }
    }
  }
}
```

必填字段：

- `sender_id`
- `chat_id`
- `text`

可选字段：

- `session_key`
- `media`
- `metadata`

校验规则：

- `sender_id` 和 `chat_id` 必须是非空字符串
- `text` 必须是字符串
- `media` 如果存在，必须是非空字符串数组
- `metadata` 如果存在，必须是 JSON object

## Metadata 约定

`metadata` 是渠道专用语义的主要扩展面。

推荐字段：

- `peer_kind`
  稳定的 peer 类型，例如 `dm`、`group`、`thread`，或渠道自定义值。
- `peer_id`
  与 `peer_kind` 配套使用的稳定 peer 标识。
- `is_group`
  显式 group hint。
- `is_dm`
  显式 direct-message hint。
- `typing_recipient`
  typing indicator 应发送到的目标。

Host 行为：

- host 会自动把 `account_id` 注入 inbound metadata
- 如果插件没给 `session_key`，host 会按下面规则派生：
  - 优先 `runtime_name + account_id + peer_kind + peer_id`
  - 否则 `runtime_name + account_id + chat_id`
- 对 unknown/external channels，metadata 会被提升到 conversation context

## 错误语义

以下情况应用 JSON-RPC `error`：

- 参数非法
- 方法不支持
- bridge/transport 失败
- 插件内部错误

只有真的接受了动作，才返回 `result.accepted: true`。

推荐错误码：

- `-32601`
  Method not found / not implemented
- `-32602`
  Invalid params
- `-32000` 及以下
  插件自定义运行时错误

## 超时与 Supervision

配置里的 `transport.timeout_ms` 并不意味着所有 control path 都会真的等这么久。NullClaw 会对 health 和 supervision 敏感的请求施加更短的内部上限。

这意味着：

- 挂死的插件不会把 daemon 永久卡住
- 不支持的可选 RPC 会被学习并缓存
- health 结果会被短暂缓存，避免高频探测

插件自己仍然应该：

- 快速响应 `stop`
- 保持 stdout 不被阻塞
- 尽量不要在 JSON-RPC 主线程里做过长耗时工作

## 安全与隔离

host/plugin 边界虽然很窄，但插件本质上仍然是以 nullclaw 用户权限运行的本地进程。

建议：

- 把插件视为受信任的本地软件，而不是 sandbox 里的不可信代码
- bridge URL 尽量使用本地地址或 HTTPS
- 谨慎通过 `transport.env` 或插件配置传递密钥
- 不要把 token 或原始敏感消息打印到 stderr
- 账号持久化状态只写入 `runtime.state_dir`

## CLI 与运行

常用命令：

```bash
nullclaw channel start external
```

启动第一个已配置的 external 账号。

```bash
nullclaw channel start whatsapp_web
```

启动 `runtime_name = whatsapp_web` 的 external 账号。

## 参考适配器

仓库里提供了一个 bridge 适配器示例：

- [`examples/whatsapp-web/nullclaw-plugin-whatsapp-web`](../../examples/whatsapp-web/nullclaw-plugin-whatsapp-web)
- [`examples/external-channel-template/nullclaw-plugin-template`](../../examples/external-channel-template/nullclaw-plugin-template)

它把 PR #265 里的 WhatsApp Web HTTP bridge 形态转换成当前 ExternalChannel JSON-RPC 协议。

如果你要看 WhatsApp Web 的完整 operator journey，包括 bridge 鉴权和
WhatsApp 登录的职责边界、QR/pairing 归属以及首次联调步骤，请继续看：

- [`examples/whatsapp-web/README.md`](../../examples/whatsapp-web/README.md)

如果你需要的是一个不绑定任何具体渠道的起步模板，而不是 WhatsApp
专用 bridge 示例，请看：

- [`examples/external-channel-template/README.md`](../../examples/external-channel-template/README.md)

配套的仓库外实现：

- [nullclaw/nullclaw-channel-baileys](https://github.com/nullclaw/nullclaw-channel-baileys)
  基于 Node/Baileys 的直连 external channel 插件，包含 QR 和 pairing-code 流程。
- [nullclaw/nullclaw-channel-whatsmeow-bridge](https://github.com/nullclaw/nullclaw-channel-whatsmeow-bridge)
  独立的 Go/whatsmeow HTTP bridge，包含 QR、pairing-code 和 deployment assets。
- `nullclaw-channel-imap-connector`
  基于 Python 的 IMAP/SMTP external channel 插件，用于双向邮件和配套的邮箱 CLI 工作流。

推荐把真正的生产级渠道实现放在这些仓库外 repo 中。本仓库里的示例主要是
reference adapter 和 authoring template。

## 插件作者检查单

- 实现 `get_manifest`
- 实现 `start`、`send`、`stop`
- 返回 `protocol_version: 2`
- `start` 返回 `started: true`
- 被接受的出站动作返回 `accepted: true`
- `inbound_message` 使用 `text`，不要再用 `content`
- peer routing 有意义时，在 metadata 里带上 `peer_kind` 和 `peer_id`
- 使用 `state_dir` 存放持久化账号状态
- 保持 stdout 只有协议数据

## 排障

`channel start <runtime_name>` 立刻失败：

- 检查 `transport.command`
- 检查 manifest 的 `protocol_version` 是否为 `2`
- 检查 `start.result.started` 是否存在且为 true

消息进了错误会话：

- 显式提供 `session_key`，或者至少提供 `metadata.peer_kind` 和 `metadata.peer_id`
- 检查多个账号是否复用了同一个 `runtime_name`

明明 bridge 已断，但 health 还是绿的：

- 实现 `health`
- 如果健康结果没有真实语义，就不要声明 `capabilities.health=true`

插件日志把 host 搞坏了：

- stdout 只能输出 JSON-RPC
- 可读日志请写到 stderr
