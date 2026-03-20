# External Channel Plugin Template

This directory contains a minimal reference plugin for `channels.external`.

Files:

- `nullclaw-plugin-template`
  Minimal Python 3 plugin that implements the core JSON-RPC lifecycle:
  `get_manifest`, `start`, `stop`, `health`, and `send`.

Use this when you want to build a new external channel and do not need the
WhatsApp-specific HTTP bridge example.

## What This Template Covers

- stdio JSON-RPC framing
- manifest negotiation
- runtime/config parsing
- bounded lifecycle state
- `accepted: true` outbound responses
- helper for emitting `inbound_message` notifications

What it does not cover:

- real network I/O
- webhooks
- long polling
- QR or OAuth flows
- media upload pipelines
- channel-specific auth/session storage

Those parts are intentionally left for your plugin implementation.

## Quick Start

Example config:

```json
{
  "channels": {
    "external": {
      "accounts": {
        "demo": {
          "runtime_name": "demo_channel",
          "transport": {
            "command": "/absolute/path/to/examples/external-channel-template/nullclaw-plugin-template",
            "timeout_ms": 5000
          },
          "config": {
            "demo_mode": true
          }
        }
      }
    }
  }
}
```

Start it with:

```bash
nullclaw channel start demo_channel
```

## How To Extend It

Typical next steps:

1. Replace `send()` with your real outbound transport logic.
2. Start a receiver thread, webhook listener, or poll loop inside `start()`.
3. Call `emit_inbound_message(...)` whenever a real inbound message arrives.
4. Return meaningful `health()` signals from your transport/session state.
5. If your channel supports richer UX, advertise and implement:
   - `capabilities.streaming`
   - `capabilities.send_rich`
   - `capabilities.typing`
   - `capabilities.edit`
   - `capabilities.delete`
   - `capabilities.reactions`
   - `capabilities.read_receipts`

## Minimal Development Notes

- stdout must contain JSON-RPC lines only
- stderr is safe for logs
- `message.text` is the canonical text field
- accepted outbound actions must return `{"accepted": true}`
- if you enable host-managed edits/deletes, `send` should also return a stable
  `message_id` (or `message { target?, message_id }`) so the host can follow up
  with `edit_message` / `delete_message`
- if you emit inbound messages, include `peer_kind` and `peer_id` in metadata
  whenever routing/session separation matters
- optional message action RPCs are `edit_message`, `delete_message`,
  `set_reaction`, and `mark_read`

For the full protocol contract, see:

- [`docs/en/external-channels.md`](../../docs/en/external-channels.md)
- [`docs/zh/external-channels.md`](../../docs/zh/external-channels.md)
