# Nostr Channel Testing Guide

Branch: `nostr-channel`

## Current Status — Ready for E2E Testing

All implementation is complete. 3037 tests pass, 0 failures, 0 leaks.

| Component | File | Status |
|---|---|---|
| `NostrChannel` vtable | `src/channels/nostr.zig` | Complete |
| `isValidHexKey` + `validateConfig` | `src/channels/nostr.zig` | Complete |
| `signing_sec` lifecycle (decrypt/zero/free) | `src/channels/nostr.zig` | Complete |
| `readerLoop` + reader thread | `src/channels/nostr.zig` | Complete |
| `healthCheck` (running flag, not listener pointer) | `src/channels/nostr.zig` | Complete |
| `vtableSend` (3-step nak pipeline) | `src/channels/nostr.zig` | Complete |
| `SecretStore` (`enc2:` ChaCha20-Poly1305) | `src/security/secrets.zig` | Complete |
| Onboarding wizard (step 7) | `src/onboard.zig` | Complete |
| `config_dir` field | `src/config_types.zig` | Complete |
| JSON serialization (`Config.save`) | `src/config.zig` | Complete |
| JSON parsing (`Config.load`) | `src/config_parse.zig` | Complete |
| Daemon supervisor wiring | `src/daemon.zig` | Complete |
| `runInboundDispatcher` (inbound → session → outbound) | `src/channels/dispatch.zig` | Complete |
| Inbound dispatcher thread spawn | `src/daemon.zig` | Complete |
| Nostr supervised restart (max 5, exponential backoff) | `src/daemon.zig` | Complete |

### Known limitations (accepted for v1)

- Auto-restart attempts up to 5 times with exponential backoff (1 s → 2 s → 4 s → … → 60 s cap).
  After 5 failures health shows "gave up after max restarts" and the daemon must be restarted manually.
- Other channel configs (Telegram, Discord, etc.) are not persisted by `Config.save()`.
  If you have Nostr + another channel, load works (both channels start) but save only
  writes the Nostr section. Keep manual backups if editing other channel config.

---

## Build and Install

### Prerequisites on the server

- Zig 0.15.x: `zig version` should show `0.15.x`
- `nak` in PATH: `nak --version` should succeed
- Network access to Nostr relays (default set uses WSS — ports 443/80)

### Build

```bash
# On dev machine
git checkout nostr-channel
zig build -Doptimize=ReleaseSmall

# Binary at: zig-out/bin/nullclaw (~678 KB)
scp zig-out/bin/nullclaw user@server:~/bin/
```

### Unit tests (no network needed)

```bash
zig build test --summary all
# Expected: 3037+ tests, 0 failures, 0 leaks
```

---

## Onboarding Walkthrough

Run on the server where `nak` is installed:

```bash
nullclaw --onboard
```

Step 7 of 8 will ask about Nostr. When prompted:

```
  Step 7/8: Configure Nostr DM channel? [y/N]:
```

Type `y` to configure.

```
  Generate new bot keypair? [Y/n]:
```

- **Enter (default Y)** — generates a fresh keypair via `nak key generate`. The bot's npub1
  (bech32) address is printed so you can follow it on Nostr clients. This is the address to
  share with senders.
- **n** — enter your own `nsec1...` key (decoded and encrypted at rest automatically).

```
  Your Nostr pubkey (npub1... or hex):
```

Enter your personal pubkey (not the bot's). This is the "owner" who is always allowed
through DM policy. Both `npub1...` and 64-char hex are accepted.

After onboarding completes the config is saved. Verify:

```bash
cat ~/.config/nullclaw/config.json | python3 -m json.tool | grep -A 20 '"nostr"'
```

Expected:
```json
"channels": {
  "nostr": {
    "private_key": "enc2:...",
    "owner_pubkey": "64hexchars...",
    "relays": ["wss://relay.damus.io", ...],
    "dm_relays": ["wss://auth.nostr1.com"],
    "display_name": "NullClaw",
    "about": "AI assistant",
    "nak_path": "nak"
  }
}
```

Verify `.secret_key` exists and is owner-only:
```bash
ls -la ~/.config/nullclaw/.secret_key
# -rw------- 1 user user ... .secret_key
```

---

## Functional Testing

### Prerequisite: a personal Nostr client

Any NIP-17 capable client works. [0xchat](https://0xchat.com) and [Gossip](https://github.com/mikedilger/gossip) support NIP-17 DMs. You need your own keypair loaded in the client.

### Test 1: Start the daemon and check it connects

```bash
nullclaw
```

Daemon logs should show:
```
info(nostr): listener started
info(nostr): published kind:10050 DM inbox relay list (1 relays)
info(nostr): Nostr channel started
```

No errors like `nak: command not found` or `invalid key format`.

The listener subscribes to kind:1059 (NIP-17 gift wraps) and kind:4 (NIP-04 DMs) on all configured relays.

### Test 2: Send a DM from owner — verify full inbound→reply pipeline

From your Nostr client (logged in as `owner_pubkey`):

1. Find the bot's npub (printed during onboarding, or `nak key public <hex>` from the config)
2. Send a NIP-17 DM: `Hello from owner`

Expected on daemon:
```
info(nostr): received DM from <owner_pubkey_hex>
```

Expected reply from bot (within 5–10 seconds): the bot's AI response as a NIP-17 DM back.

This test exercises the complete pipeline: nak reader thread → `bus.inbound` → `runInboundDispatcher`
→ `SessionManager.processMessage` → `bus.outbound` → outbound dispatcher → `vtableSend`.

### Test 2b: Send a NIP-04 (kind:4) DM — protocol mirroring

Some older Nostr clients send NIP-04 encrypted DMs (kind:4) rather than NIP-17 gift wraps (kind:1059).

From a Nostr client that supports NIP-04 (most clients):
1. Send a kind:4 DM to the bot

Expected: bot replies with a kind:4 DM (protocol mirroring — the bot replies in the same protocol the sender used).

**Note:** Requires nak v0.2.x or later for `nak encrypt`/`nak decrypt` support. Verify: `nak --version`.

### Test 3: Send a DM from a non-owner, non-allowlisted pubkey

From a different Nostr account (not the owner):

1. Send a DM to the bot.

Expected: no reply, daemon logs show the DM rejected by policy.

### Test 4: Allowlist a specific pubkey

Edit config directly:

```json
"dm_allowed_pubkeys": ["<hex-pubkey-of-friend>"]
```

Restart daemon. Send DM from that account — should now get a reply.

### Test 5: Wildcard allow-all

```json
"dm_allowed_pubkeys": ["*"]
```

Restart. Send DM from any account — should get a reply.

### Test 6: Config persists across restart

1. Run onboarding, configure Nostr
2. Start daemon, verify it works (Test 1)
3. Stop and restart daemon
4. Verify daemon reconnects to relays and responds to DMs (no re-onboarding needed)

This tests the full save/load roundtrip: `Config.save()` → JSON → `Config.load()` → `config_dir` backfill → `vtableStart` decrypts key.

### Test 7: Invalid key format rejection

Edit config to break `owner_pubkey` (set it to an npub string or wrong length).
Restart daemon. Expected:

```
err(nostr): nostr config has invalid key format — owner_pubkey and dm_allowed_pubkeys must be 64-char lowercase hex; private_key must be enc2:-encrypted
```

Daemon should mark channel as errored and not crash.

### Test 8: Missing nak binary

Set `"nak_path": "/nonexistent/nak"` in config. Restart. Attempt to send a DM to the bot.

Expected: send fails with a log error, daemon does not crash.

### Test 9: Relay connectivity failure

Set relays to a non-existent relay:
```json
"relays": ["wss://does-not-exist.example.com"]
```

Restart. Expected: listener fails to connect, logs an error. Daemon continues running
(does not crash). Restore relays and confirm recovery on restart.

### Test 10: Auto-restart when nak subprocess dies

With the daemon running and the Nostr channel healthy:

1. Find the nak listener PID:
   ```bash
   pgrep -a nak
   ```
2. Kill it:
   ```bash
   kill <nak-pid>
   ```
3. Wait up to 60 seconds (the channel watch interval).

Expected daemon logs:
```
warn(daemon): Nostr channel unhealthy (listener may have stopped)
info(daemon): Restarting Nostr channel (attempt 1)
info(nostr): listener started
info(daemon): Nostr channel restarted successfully
```

Expected: bot responds to DMs again after restart. Health returns to `ok`.

To verify the give-up behaviour (optional — destructive): kill nak each time it restarts,
5 times in a row. After the 5th failure:
```
err(daemon): Nostr channel gave up after 5 restarts
```

Health will show "gave up after max restarts". Daemon continues running; restart it to recover.

---

## Edge Cases and Known Limitations

### Private key exposure window

Each outbound NIP-17 DM requires three `nak` subprocess invocations (inner rumor,
gift wrap, publish). The plaintext hex key appears in `/proc/<pid>/cmdline` for
~50–200ms per invocation. This is the accepted v1 tradeoff.

On Linux, ensure the bot runs as a dedicated user account with no other processes
sharing the UID. Disable core dumps:

```bash
ulimit -c 0
```

Or in a systemd unit:
```
LimitCORE=0
```

### Listener restart on subprocess death

If the `nak req --stream` listener subprocess dies (relay disconnect, nak crash),
the reader thread exits and sets `running = false`. The daemon health check detects
this at the next 60-second poll interval and automatically restarts the channel.

Restart behaviour: exponential backoff starting at 1 s, doubling each attempt, capped
at 60 s. Maximum 5 restart attempts. After 5 failures the channel is marked
"gave up after max restarts" and the daemon must be restarted manually.

### Relay authentication (NIP-42)

The `nak` listener and publisher handle NIP-42 AUTH automatically for relays that
require it. No extra config needed.

### Other channels not persisted by save()

`Config.save()` only writes the Nostr section. If Telegram or other channels are
also configured (loaded from a manually edited config), they will be absent from
any file written by save() (e.g., after onboarding). This is a pre-existing
limitation — load works fine for all channels, only save is Nostr-only.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `nak: not found` | `nak_path` wrong or not in PATH | Set `"nak_path": "/full/path/to/nak"` in config |
| `invalid key format` on start | `owner_pubkey` is npub or wrong length | Re-run onboarding or manually fix to 64-char hex |
| `enc2:` decryption error | `.secret_key` file missing or wrong machine | Re-run onboarding to re-encrypt key |
| No inbound DMs | Relay connectivity or listener crash | Check relay URLs; daemon will auto-restart up to 5 times, then restart daemon manually |
| Bot replies to everything | `dm_allowed_pubkeys` is `["*"]` | Restrict to specific pubkeys |
| Health shows "nostr" error | Listener subprocess died | Daemon auto-restarts; if "gave up after max restarts" appears, restart daemon manually |
| Config not persisting after save | Other channels only — Nostr config saves fine | Edit config manually for non-Nostr channels |
