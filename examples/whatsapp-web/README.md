# WhatsApp Web External Plugin Example

This directory contains a reference adapter for `channels.external`:

- `nullclaw-plugin-whatsapp-web`
  Converts the ExternalChannel JSON-RPC/stdio plugin protocol into the
  HTTP bridge contract from the whatsmeow example (`/health`, `/poll`, `/send`).
  The adapter advertises `protocol_version=2`, `capabilities.health=true`,
  `capabilities.streaming=false`,
  `capabilities.send_rich=false`, `capabilities.typing=false`,
  `capabilities.edit=false`, and `capabilities.delete=false`
  in `get_manifest`.
  `config.bridge_url` must be `https://...` or loopback `http://127.0.0.1/...`.

Related out-of-tree repositories:

- [nullclaw/nullclaw-channel-whatsmeow-bridge](https://github.com/nullclaw/nullclaw-channel-whatsmeow-bridge)
  Production-oriented Go/whatsmeow bridge with QR, pairing-code, and deployment assets.
- [nullclaw/nullclaw-channel-baileys](https://github.com/nullclaw/nullclaw-channel-baileys)
  Direct Node/Baileys external channel plugin if you do not want an HTTP bridge at all.

This in-tree directory remains a reference adapter and compatibility example.

Typical config:

```json
{
  "channels": {
    "external": {
      "accounts": {
        "wa-web": {
          "runtime_name": "whatsapp_web",
          "transport": {
            "command": "/absolute/path/to/examples/whatsapp-web/nullclaw-plugin-whatsapp-web",
            "timeout_ms": 10000
          },
          "config": {
            "bridge_url": "http://127.0.0.1:3301",
            "allow_from": ["*"],
            "group_policy": "allowlist"
          }
        }
      }
    }
  }
}
```

Optional `config` keys understood by the adapter:

- `api_key`
- `allow_from`
- `group_allow_from`
- `group_policy`
- `poll_interval_ms`
- `timeout_ms`

## Responsibility Split

This example is intentionally split into three layers:

1. `nullclaw`
   Starts the external plugin process, supervises it, and routes inbound and
   outbound messages through the generic `Channel` runtime.
2. `nullclaw-plugin-whatsapp-web`
   Adapts the generic ExternalChannel JSON-RPC contract to a simple HTTP bridge.
   It can authenticate to that bridge with `config.api_key`.
3. Your WhatsApp bridge / sidecar
   Owns the real WhatsApp session, QR or pairing UX, device linking, and bridge
   persistence.

The important consequence is:

- nullclaw does not log into WhatsApp directly
- the plugin does not show QR codes or create WhatsApp sessions
- the bridge must implement WhatsApp login and keep its own auth/session state

## Authorization Model

There are two separate authorization layers in this setup.

### 1. Plugin -> bridge authorization

If `config.api_key` is set, the adapter sends:

```http
Authorization: Bearer <api_key>
```

on every bridge request to:

- `GET /health`
- `POST /poll`
- `POST /send`

This protects the local or remote bridge API itself.

### 2. Bridge -> WhatsApp authorization

Actual WhatsApp authentication lives entirely inside the bridge sidecar.
That bridge is responsible for:

- creating or restoring a WhatsApp session
- showing a QR code or pair code to the operator
- waiting for the phone to link
- persisting the linked device/session
- returning `connected` / `logged_in` from `GET /health`

The plugin only observes that state through `/health`. It does not implement a
pairing UI and does not standardize how QR delivery works.

## Full CJM

This is the expected operator journey for the `whatsapp_web` example.

### 1. Prepare the bridge

Run a bridge/sidecar that exposes:

- `GET /health`
- `POST /poll`
- `POST /send`

If the bridge is protected, decide on an API token and keep it for
`config.api_key`.

### 2. Complete WhatsApp login on the bridge side

Before nullclaw can send or receive messages, the bridge must complete the real
WhatsApp login flow.

Typical flow:

1. Start the bridge.
2. Open the bridge UI, terminal output, or admin endpoint that shows a QR code
   or pair code.
3. In WhatsApp on the phone, link a new device.
4. Wait for the bridge to report that the device is linked.
5. Confirm the bridge health endpoint reports `logged_in=true`.

This part is bridge-specific by design. Nullclaw does not define how the QR is
displayed.

### 3. Verify bridge health before wiring nullclaw

Check the bridge directly first.

Without bridge auth:

```bash
curl http://127.0.0.1:3301/health
```

With bridge auth:

```bash
curl -H 'Authorization: Bearer YOUR_BRIDGE_TOKEN' http://127.0.0.1:3301/health
```

The adapter expects a JSON object with signals like:

```json
{
  "ok": true,
  "connected": true,
  "logged_in": true
}
```

If `logged_in` is `false`, nullclaw will keep seeing the channel as unhealthy.

### 4. Configure nullclaw

Add an external channel account:

```json
{
  "channels": {
    "external": {
      "accounts": {
        "wa-web": {
          "runtime_name": "whatsapp_web",
          "transport": {
            "command": "/absolute/path/to/examples/whatsapp-web/nullclaw-plugin-whatsapp-web",
            "timeout_ms": 10000
          },
          "config": {
            "bridge_url": "http://127.0.0.1:3301",
            "api_key": "YOUR_BRIDGE_TOKEN",
            "allow_from": ["*"],
            "group_policy": "allowlist"
          }
        }
      }
    }
  }
}
```

Meaning of the main fields:

- `bridge_url`
  Where the plugin reaches the WhatsApp bridge.
- `api_key`
  Optional Bearer token for bridge auth. This is not a WhatsApp credential.
- `allow_from`
  Direct-message allowlist. `["*"]` allows any sender.
- `group_allow_from`
  Group-message allowlist. If omitted, falls back to `allow_from`.
- `group_policy`
  Group handling mode:
  - `allowlist`: only allowed senders may trigger group inbound messages
  - `open`: accept all group senders
  - `disabled`: ignore group messages entirely

### 5. Start the channel

Start by runtime name:

```bash
nullclaw channel start whatsapp_web
```

Or start the first configured external account:

```bash
nullclaw channel start external
```

On startup:

1. nullclaw starts the plugin process
2. the plugin validates `bridge_url` and config
3. the plugin loads its local state from `state_dir`
4. the plugin begins polling `/poll`
5. health checks start probing `/health`

### 6. Validate inbound flow

Send a test WhatsApp message from an allowed sender to the linked device.

The bridge should surface that message through `/poll`, and the adapter will:

- drop duplicates by `message.id`
- enforce `allow_from` / `group_allow_from`
- derive `peer_kind` and `peer_id`
- emit `inbound_message` into nullclaw

For groups:

- `is_group=true` in bridge payload marks the message as group traffic
- `group_id` is used as the stable peer identity when present

### 7. Validate outbound flow

Once the channel is healthy, nullclaw sends outbound text through:

- plugin `send`
- bridge `POST /send`

This reference adapter is text-only:

- rich attachments are unsupported
- typing indicators are unsupported
- streaming chunks are rejected and only final messages are accepted

### 8. Restart behavior

Two kinds of state exist:

Bridge-owned state:

- WhatsApp linked-device session
- device credentials
- bridge-specific persistent auth

Plugin-owned state:

- poll cursor
- recently seen message ids for dedupe

Plugin state is stored under the host-provided `state_dir`. If `state_dir` is
missing, the plugin falls back to XDG or `~/.local/state/nullclaw/external/`.

The plugin does not store the WhatsApp login session itself. If the bridge loses
its own session, the operator must re-link on the bridge side.

## Bridge Payload Expectations

For `GET /health`, the adapter expects a JSON object with booleans such as:

- `ok`
- `connected`
- `logged_in`

For `POST /poll`, the adapter expects a JSON object like:

```json
{
  "next_cursor": "opaque-cursor",
  "messages": [
    {
      "id": "msg-123",
      "from": "551199999999",
      "text": "hello",
      "chat_id": "551199999999",
      "is_group": false
    }
  ]
}
```

Recognized inbound fields:

- `id`
- `from` or `sender_id`
- `text` or `content`
- `chat_id`
- `is_group`
- `group_id`

For `POST /send`, the adapter sends:

```json
{
  "account_id": "wa-web",
  "to": "room-or-user-id",
  "text": "hello"
}
```

## Common Misunderstandings

- `api_key` is bridge auth, not WhatsApp auth.
- `state_dir` stores plugin poll state, not the real WhatsApp device session.
- If your bridge does not expose QR/pairing UX, this example is incomplete.
- If `/health` does not return `logged_in=true` after linking, nullclaw is right
  to treat the channel as not ready.

Protocol notes:

- `start.params.runtime` contains `name`, `account_id`, and host-owned `state_dir`
- `start.result` must return `started: true`; successful `send` calls must return `accepted: true`
- `send.params` contains nested `runtime` and `message` objects; text uses `message.text`
- `inbound_message.params` contains a nested `message` object
- `health.result` must return `healthy` or explicit boolean health signals; `{}` is invalid
- `inbound_message.params.message` uses `text`, not `content`
- `send_rich` and typing RPCs are intentionally unsupported by this text-only bridge adapter
