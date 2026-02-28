# Nostr Channel

**File:** `src/channels/nostr.zig`
**Branch:** `nostr-channel`
**Protocols:** NIP-17 (gift-wrapped DMs), NIP-04 (legacy DMs)
**Signing:** direct via `nak` subprocess (no bunker)

---

## Runtime Architecture

```
nak req --stream   →  reader thread  →  Bus  →  outbound dispatcher  →  vtableSend
  (listener child)      (processes          (InboundMessage)
                         stdout lines)
```

1. **vtableStart** decrypts `enc2:` key → `signing_sec`, spawns `nak req --stream` subprocess, sets `listen_start_at = now()`, spawns reader thread, publishes kind:10050 inbox relay list (best-effort).
2. **Reader thread** reads listener stdout line-by-line. Each line is a raw Nostr event JSON. Kind 1059 → `processWrappedEvent`, kind 4 → `processNip04Event`.
3. Events with `rumor.created_at < listen_start_at` are discarded (stale history from relay).
4. Duplicate inner rumors (same `id`, delivered once per relay) are suppressed via `seen_rumor_ids` (10-min TTL).
5. Accepted messages are published to the Bus as `InboundMessage` with `session_key = "nostr:<sender_hex>"`.

## Send Path

`vtableSend` checks `getSenderProtocol(target)` for protocol mirroring:

| Protocol | Pipeline |
|----------|----------|
| NIP-17 (default) | look up recipient's kind:10050 inbox relays → `nak event -k 14` → `nak gift wrap --sec <sec> -p <recipient> <inbox_relays>` |
| NIP-04 | `nak encrypt` → `nak event -k 4` → `nak event --sec <sec> --auth <config.relays>` |

NIP-17 publishes directly to the recipient's inbox relays (not `config.relays`). Falls back to `config.relays` if kind:10050 lookup fails.

## Config (`NostrConfig`)

| Field | Notes |
|-------|-------|
| `private_key` | `enc2:` encrypted blob; decrypted to `signing_sec` at start |
| `owner_pubkey` | 64-char hex; always allowed through DM policy |
| `bot_pubkey` | 64-char hex; derived from `private_key` during onboarding; used as `-p` in listener filter |
| `relays` | publish + subscribe (5 defaults) |
| `dm_relays` | announced in kind:10050; also subscribed by listener (default: `wss://auth.nostr1.com`) |
| `dm_allowed_pubkeys` | `[]` = deny all, `["*"]` = allow all; owner always allowed |
| `nak_path` | path to `nak` binary (default: `"nak"`) |
| `bunker_uri` | optional; if set, passed as `--sec` directly (external bunker upgrade path) |

## Listener Command

```
nak req --stream -k 1059 -k 4 --auth --sec <signing_sec> -p <bot_pubkey> <relays+dm_relays deduplicated>
```

`--auth` is a boolean flag (no value). `--sec` provides the key for NIP-42 AUTH challenges.

## Key Lifecycle

```
vtableStart  →  SecretStore.decryptSecret(enc2:...)  →  signing_sec (heap, plaintext hex)
vtableStop   →  @memset(signing_sec, 0)  →  allocator.free  →  signing_sec = null
```

`signing_sec` is zeroed before free to reduce post-free exposure window. `errdefer` in vtableStart handles cleanup if listener/thread spawn fails after key is decrypted.

## Notable Details

- **Deduplication:** `seen_rumor_ids: StringHashMapUnmanaged(i64)` keyed on inner rumor `id`. Evicts entries older than 600 s on each `recordSeenRumor` call.
- **Protocol mirroring:** `sender_protocols: StringHashMapUnmanaged(DmProtocol)` remembers last-used protocol per sender. New senders default to NIP-17.
- **kind:10050:** Published at startup announcing `dm_relays`. Also queried outbound via `nak req -k 10050 -a <recipient> <relays>` to find where to deliver replies.
- **nak gift wrap:** Relays are passed directly to `nak gift wrap` (not a separate publish step) so the internally-generated ephemeral key is preserved for the outer wrapper.
- **nak debug output:** `nak gift unwrap` prints NIP-4E decoupled key attempts to stderr (inherited). The `000...` line is normal — the bot has no kind:10044 dekey.
- **Config dir:** `~/.nullclaw/` (not `~/.config/nullclaw/`). `.secret_key` lives here at 0600.
