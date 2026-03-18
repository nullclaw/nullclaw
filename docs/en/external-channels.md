# External Channel Plugins

This page documents the `channels.external` runtime and the plugin protocol used
to add new messaging channels without merging channel-specific code into core.

## Page Guide

**Who this page is for**

- Operators wiring an external channel into `config.json`
- Plugin authors implementing a new channel bridge
- Maintainers reviewing whether a new integration belongs in core or as a plugin

**Read this next**

- Open [Configuration](./configuration.md) for the full config file context
- Open [Architecture](./architecture.md) if you want the broader runtime model
- Open [Usage and Operations](./usage.md) when you are validating a live deployment

## Why External Channels Exist

`channels.external` is the clean extension path for community or site-specific
channels. The design goals are:

- keep channel-specific SDKs, sidecars, and bridge logic out of nullclaw core
- avoid in-process ABI/plugin loading complexity
- allow per-channel code to live in separate repositories and languages
- keep the host contract narrow, explicit, and easy to supervise

The host/plugin boundary is:

- transport: line-delimited JSON-RPC over `stdin`/`stdout`
- process model: child process started by nullclaw
- routing surface: generic `Channel` operations only
- channel-specific behavior: implemented entirely in the plugin

## When To Use This

Use an external channel plugin when:

- the channel requires a large SDK or non-Zig dependency
- the integration is niche, experimental, or operator-specific
- the channel is best represented by a local sidecar or bridge
- you want to iterate independently from nullclaw release cadence

Do not use it when:

- the feature is really a product/app layer, not a channel
- you need to change core routing, memory, security, or agent semantics
- the integration is better expressed as tools/MCP rather than as a message transport

## Config Model

External channels live under `channels.external.accounts.<id>`.

Example:

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

Fields:

- `runtime_name`
  The runtime channel name used by routing, bindings, session keys, daemon
  dispatch, and `nullclaw channel start <runtime_name>`.
- `transport.command`
  Executable path or command name for the plugin process.
- `transport.args`
  Optional argument vector.
- `transport.env`
  Optional environment variables passed only to the plugin process.
- `transport.timeout_ms`
  Per-account upper bound for host RPC waits. The host still applies shorter
  caps internally for supervision-sensitive requests.
- `config`
  Opaque JSON object forwarded to the plugin `start` RPC as `params.config`.

Validation rules:

- `runtime_name` must be non-empty and contain only letters, digits, `_`, `-`, or `.`
- `runtime_name` must be globally unique across built-in and configured runtime channels
- `transport.command` is required
- `transport.timeout_ms` must be in `[1, 600000]`
- `config` must be a JSON object

## Runtime Architecture

At runtime the host creates a generic `ExternalChannel`, which:

1. Starts the plugin child process
2. Fetches and validates the plugin manifest
3. Sends `start`
4. Maps generic `Channel` operations into JSON-RPC requests
5. Receives `inbound_message` notifications and publishes them into the bus
6. Supervises plugin health with bounded probes

Important properties:

- one configured account equals one plugin child process
- the plugin is supervised like any other channel runtime
- plugin stdout is reserved for JSON-RPC lines only
- plugin stderr may be used for diagnostics

## Transport Contract

The transport is line-delimited JSON-RPC 2.0 over stdio.

Rules:

- each request, response, or notification must fit on a single line
- stdout must contain JSON-RPC only
- stderr is free-form and does not participate in the protocol
- request/response correlation uses JSON-RPC `id`
- `params` and `result` payloads must be JSON objects where required below

## Manifest

The host calls:

```json
{"jsonrpc":"2.0","id":1,"method":"get_manifest","params":{}}
```

The plugin must respond with:

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

Rules:

- `protocol_version` must equal `2`
- `capabilities` is optional
- absent capability bits are treated as unsupported

Capability meanings:

- `health`
  The plugin implements the `health` RPC and can report channel-level health.
- `streaming`
  The plugin accepts staged `.chunk` outbound events from model streaming.
- `send_rich`
  The plugin implements `send_rich`.
- `typing`
  The plugin implements `start_typing` and `stop_typing`.
- `edit`
  The plugin implements `edit_message` for host-managed follow-up updates.
- `delete`
  The plugin implements `delete_message` for host-managed cleanup.
- `reactions`
  The plugin implements `set_reaction`.
- `read_receipts`
  The plugin implements `mark_read`.

## Lifecycle RPCs

### `start`

Host request:

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

Required success response:

```json
{"jsonrpc":"2.0","id":2,"result":{"started":true}}
```

Notes:

- `runtime.state_dir` is host-owned persistent storage for the plugin account
- plugins should treat `config` as opaque plugin-local settings
- a JSON-RPC success envelope without `result.started: true` is rejected

### `stop`

Host request:

```json
{"jsonrpc":"2.0","id":3,"method":"stop","params":{}}
```

The host does not require a special payload beyond a valid JSON-RPC success
response, but returning a result object is still recommended.

## Health RPC

If `capabilities.health=true`, the host may call:

```json
{"jsonrpc":"2.0","id":4,"method":"health","params":{}}
```

Accepted response shapes:

```json
{"jsonrpc":"2.0","id":4,"result":{"healthy":true}}
```

or

```json
{"jsonrpc":"2.0","id":4,"result":{"ok":true,"connected":true,"logged_in":true}}
```

Rules:

- `healthy` must be a boolean if present
- otherwise at least one of `ok`, `connected`, `logged_in` must be present
- an empty `{}` result is invalid
- if the plugin does not support `health`, omit the capability bit rather than
  returning stub success

## Outbound RPCs

### `send`

Host request:

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

Required success response:

```json
{"jsonrpc":"2.0","id":5,"result":{"accepted":true}}
```

If the plugin advertises both `capabilities.edit=true` and
`capabilities.delete=true`, `send` may also return a stable message ref so the
host can update or remove the same message later:

```json
{"jsonrpc":"2.0","id":5,"result":{"accepted":true,"message_id":"msg-42"}}
```

or

```json
{"jsonrpc":"2.0","id":5,"result":{"accepted":true,"message":{"target":"room-1","message_id":"msg-42"}}}
```

Rules:

- `message.target` is plugin-defined channel destination data
- `message.text` is always the text field name; `content` is no longer valid
- `message.stage` is `"final"` or `"chunk"`
- `message.media` is an array of strings
- if the plugin cannot or will not accept the send, it must not fake success
- when using host-managed follow-up edits/deletes, `message_id` must be a
  non-empty stable platform identifier
- `result.message.target` is optional; if omitted, the host reuses the original
  outbound target
- plugins that do not advertise `edit` + `delete` may return only
  `{"accepted": true}`

The host now distinguishes:

- JSON-RPC success: request transport completed
- `result.accepted: true`: plugin actually accepted the action

Returning `{"accepted": false}` is treated as a rejected action, not as success.

### `send_rich`

Only used when `capabilities.send_rich=true`.

Host request:

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

Required success response:

```json
{"jsonrpc":"2.0","id":6,"result":{"accepted":true}}
```

Attachment `kind` values:

- `image`
- `document`
- `video`
- `audio`
- `voice`

If `send_rich` is unsupported, leave the capability bit unset. The host may
fall back to plain `send` only when the payload is simple enough.

### `edit_message`

Only used when `capabilities.edit=true`.

Host request:

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

Required success response:

```json
{"jsonrpc":"2.0","id":7,"result":{"accepted":true}}
```

The host may use this after an earlier `send` when keeping a tracked draft up
to date on a channel that does not support native `.chunk` streaming.

### `delete_message`

Only used when `capabilities.delete=true`.

Host request:

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

Required success response:

```json
{"jsonrpc":"2.0","id":8,"result":{"accepted":true}}
```

### `set_reaction`

Only used when `capabilities.reactions=true`.

Host request:

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

Required success response:

```json
{"jsonrpc":"2.0","id":9,"result":{"accepted":true}}
```

Rules:

- `emoji` must be a string to set/update a reaction
- `emoji: null` means clear the reaction for that message

### `mark_read`

Only used when `capabilities.read_receipts=true`.

Host request:

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

Required success response:

```json
{"jsonrpc":"2.0","id":10,"result":{"accepted":true}}
```

### Typing RPCs

Only used when `capabilities.typing=true`.

Requests:

```json
{"jsonrpc":"2.0","id":11,"method":"start_typing","params":{"runtime":{"name":"plugin_chat","account_id":"main"},"recipient":"room-1"}}
```

```json
{"jsonrpc":"2.0","id":12,"method":"stop_typing","params":{"runtime":{"name":"plugin_chat","account_id":"main"},"recipient":"room-1"}}
```

Required success response:

```json
{"jsonrpc":"2.0","id":13,"result":{"accepted":true}}
```

## Inbound Notifications

Plugins deliver inbound traffic as notifications:

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

Required fields:

- `sender_id`
- `chat_id`
- `text`

Optional fields:

- `session_key`
- `media`
- `metadata`

Validation rules:

- `sender_id` and `chat_id` must be non-empty strings
- `text` must be a string
- `media`, if present, must be an array of non-empty strings
- `metadata`, if present, must be a JSON object

## Metadata Conventions

`metadata` is the main extensibility surface for per-channel semantics.

Recommended keys:

- `peer_kind`
  A stable peer type such as `dm`, `group`, `thread`, or channel-specific values.
- `peer_id`
  Stable peer identity used with `peer_kind` for routing/session separation.
- `is_group`
  Explicit group hint.
- `is_dm`
  Explicit direct-message hint.
- `typing_recipient`
  Destination identifier to use for typing indicators.

Host behavior:

- the host injects `account_id` into inbound metadata automatically
- if no `session_key` is provided, the host derives one from:
  - `runtime_name + account_id + peer_kind + peer_id`, when available
  - otherwise `runtime_name + account_id + chat_id`
- metadata is promoted into conversation context for unknown/external channels

## Error Semantics

Use JSON-RPC `error` for:

- invalid params
- unsupported methods
- bridge/transport failures
- internal plugin failures

Use `result.accepted: true` only when the action was actually accepted.

Recommended JSON-RPC error cases:

- `-32601`
  Method not found / not implemented
- `-32602`
  Invalid params
- `-32000` and below
  Plugin-defined runtime failures

## Timeouts And Supervision

The configured `transport.timeout_ms` is not a promise that every call may
block that long in every control path. NullClaw applies tighter caps internally
for health and supervision-sensitive requests.

Operational implications:

- hung plugins do not block the daemon forever
- unsupported optional RPCs are learned and cached
- health results are cached briefly to avoid hot-loop probing

Plugins should still:

- respond quickly to `stop`
- keep stdout unblocked
- avoid long-running work on the JSON-RPC main thread when possible

## Security And Isolation

The host boundary is intentionally narrow, but plugin code still runs as a local
process with the privileges of the nullclaw user.

Recommendations:

- treat plugins as trusted local software, not as sandboxed untrusted code
- keep bridge URLs local or HTTPS
- pass secrets through `transport.env` or plugin-local config carefully
- avoid logging tokens or raw user content to stderr
- store plugin state only under `runtime.state_dir`

## CLI And Operations

Useful commands:

```bash
nullclaw channel start external
```

Starts the first configured external account.

```bash
nullclaw channel start whatsapp_web
```

Starts the configured external account with runtime name `whatsapp_web`.

## Reference Adapter

The repository includes a bridge adapter at:

- [`examples/whatsapp-web/nullclaw-plugin-whatsapp-web`](../../examples/whatsapp-web/nullclaw-plugin-whatsapp-web)
- [`examples/external-channel-template/nullclaw-plugin-template`](../../examples/external-channel-template/nullclaw-plugin-template)

It converts the WhatsApp Web HTTP bridge shape from PR #265 into the current
ExternalChannel JSON-RPC contract.

For the full WhatsApp Web operator journey, including bridge auth vs WhatsApp
auth, QR/pairing ownership, and first-run validation, see the example README:

- [`examples/whatsapp-web/README.md`](../../examples/whatsapp-web/README.md)

If you want a generic authoring starting point rather than a WhatsApp-specific
bridge, use:

- [`examples/external-channel-template/README.md`](../../examples/external-channel-template/README.md)

Companion out-of-tree repositories:

- [nullclaw/nullclaw-channel-baileys](https://github.com/nullclaw/nullclaw-channel-baileys)
  Direct Node/Baileys external channel plugin with QR and pairing-code flows.
- [nullclaw/nullclaw-channel-whatsmeow-bridge](https://github.com/nullclaw/nullclaw-channel-whatsmeow-bridge)
  Standalone Go/whatsmeow HTTP bridge with QR, pairing-code, and deployment assets.
- `nullclaw-channel-imap-connector`
  Python IMAP/SMTP external channel plugin for bidirectional email plus
  companion mailbox CLI workflows.

Those repositories are the recommended place for production channel-specific
code. The in-tree examples here are reference adapters and templates.

## Plugin Author Checklist

- Implement `get_manifest`
- Implement `start`, `send`, and `stop`
- Return `protocol_version: 2`
- Return `started: true` from `start`
- Return `accepted: true` from accepted outbound actions
- Emit `inbound_message` with `text`, not `content`
- Include `peer_kind` and `peer_id` in metadata when peer routing matters
- Use `state_dir` for persistent account state
- Keep stdout protocol-clean

## Troubleshooting

`channel start <runtime_name>` fails immediately:

- check `transport.command`
- verify manifest uses `protocol_version: 2`
- verify `start.result.started` is present and true

Messages never arrive in the right session:

- include `session_key`, or at least `metadata.peer_kind` plus `metadata.peer_id`
- make sure multiple accounts do not reuse the same `runtime_name`

Health looks green while the real bridge is dead:

- implement `health`
- do not advertise `capabilities.health=true` unless the response is meaningful

Plugin logs break the host:

- stdout must contain JSON-RPC only
- send human-readable logs to stderr instead
