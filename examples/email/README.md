# Email External Plugin Example

This directory documents the recommended email integration shape for nullclaw:
run bidirectional email as an `ExternalChannel` plugin, not as a large native
core channel.

Companion repository:

- `nullclaw-channel-imap-connector`
  Long-lived Python external plugin for IMAP/SMTP transport plus companion CLI
  commands for mailbox operations, thread inspection, and delegated workflows.

This keeps IMAP/SMTP libraries, HTML sanitization, attachment handling, and
mailbox-specific workflows outside nullclaw core while still using the generic
channel runtime already built into `channels.external`.

## What Stays In Core

- `channels.external` supervision and stdio JSON-RPC transport
- inbound routing, session separation, and outbound reply dispatch
- generic operator workflow: `nullclaw channel start <runtime_name>`

## What Lives In The Companion Repo

- IMAP polling-first receive loop
- SMTP send + threaded replies
- email HTML sanitization and prompt-injection defense
- attachment extraction / saving
- optional mailbox CLI operations (`list_emails`, `read_email`, `reply_email`, ...)
- delegated thread tracking for unknown senders

## Typical Config

See [`config.external.example.json`](./config.external.example.json).

The important part is that `transport.command` points at the plugin entrypoint
from the companion repo, for example:

```json
{
  "channels": {
    "external": {
      "accounts": {
        "mailbox": {
          "runtime_name": "imap_connector",
          "transport": {
            "command": "/absolute/path/to/nullclaw-channel-imap-connector/nullclaw-plugin-imap-connector",
            "timeout_ms": 10000
          },
          "config": {
            "imap": {
              "host": "imap.example.com",
              "port": 993,
              "username": "agent@example.com",
              "password": "YOUR_APP_PASSWORD",
              "tls": true
            },
            "smtp": {
              "host": "smtp.example.com",
              "port": 587,
              "username": "agent@example.com",
              "password": "YOUR_APP_PASSWORD",
              "tls": true
            },
            "from_address": "agent@example.com",
            "allow_from": ["*@your-company.com"],
            "attachment_save_dir": "/absolute/path/inside/runtime-state-dir/attachments",
            "state_file": "imap-connector-state.json"
          }
        }
      }
    }
  }
}
```

If you enable attachment saving, prefer an absolute path under the account
`runtime.state_dir`. Relative paths resolve against the nullclaw process cwd.

## Operator Flow

1. Clone or install `nullclaw-channel-imap-connector`.
2. Configure IMAP/SMTP credentials in `channels.external.accounts.<id>.config`.
3. Start the external channel with `nullclaw channel start imap_connector`.
4. Validate inbound delivery by sending a test email.
5. Validate outbound delivery by replying in the session created by that email.

## Why This Is Preferred

- keeps email-specific dependencies out of the nullclaw binary
- avoids growing `channel_loop.zig` with mailbox-specific polling code
- lets the email integration evolve independently from nullclaw core releases
- matches the same out-of-tree model already used for WhatsApp bridges/plugins
