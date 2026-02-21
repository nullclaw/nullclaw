# Discord Integration (RISC-V / Zig 0.15.2)

This fork adds working Discord gateway support to the nullclaw daemon, plus Zig 0.15.2 compatibility fixes.

## What's changed

- `src/channel_loop.zig` — `DiscordLoopState` + `runDiscordLoop` (WebSocket → bus → AI → REST)
- `src/daemon.zig` — Discord supervision thread wired into `channelSupervisorThread`
- `src/channels/discord.zig` — `posix.close()` void fix
- `src/websocket.zig` — `Io.Reader.readSliceShort` migration for Zig 0.15.2

## Build (cross-compile for RISC-V)

```bash
# Zig 0.15.2 required
zig build -Dtarget=riscv64-linux -Doptimize=ReleaseSmall
# => zig-out/bin/nullclaw  (~1.9 MB, statically linked)
```

## Config

```jsonc
// ~/.nullclaw/config.json
{
  "default_provider": "anthropic",
  "default_temperature": 0.7,
  "models": {
    "providers": {
      "anthropic": {
        // Claude Pro/Max: use `claude setup-token` (sk-ant-oat01-...)
        // Standard API:   sk-ant-api...
        "api_key": "sk-ant-oat01-...",
        "base_url": "https://api.anthropic.com"
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        // Do NOT use "anthropic/claude-sonnet-4-6" — Anthropic API rejects the prefix
        "primary": "claude-sonnet-4-6"
      }
    }
  },
  "channels": {
    "discord": {
      "accounts": {
        "main": {
          "token": "MTxxxxxxx.Gxxxxx.xxxx",
          "mention_only": false   // true = respond only when @mentioned
          // "guild_id": "...",   // optional: restrict to one server
          // "allow_from": ["user_id_1"]  // optional: allowlist
        }
      }
    }
  }
}
```

> **Discord Developer Portal**: enable **Message Content Intent** (Privileged Gateway Intents) or the bot won't see message content.

## Run

```bash
# One-shot CLI
nullclaw agent -m "hello"

# Daemon (all channels including Discord)
nullclaw daemon

# systemd user service
mkdir -p ~/.config/systemd/user/
nullclaw service install
systemctl --user enable --now nullclaw.service
journalctl --user -u nullclaw.service -f
# => info(daemon): Discord gateway thread started
```

## Architecture (inbound flow)

```
Discord WS → handleMessageCreate → bus.publishInbound
                                           ↓
                                   runDiscordLoop
                                           ↓
                              SessionManager.processMessage (Claude)
                                           ↓
                              DiscordChannel.sendMessage (REST)
```

## Notes

- Tested on Milk-V Duo 256M (riscv64, Debian 13 trixie, 170 MB RAM)
- Auth: Claude Code setup-token (`claude setup-token`) — no API billing, uses subscription
- The upstream daemon only supervised Telegram; this fork adds Discord to the supervisor loop
