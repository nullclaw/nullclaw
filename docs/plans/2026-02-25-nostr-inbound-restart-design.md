# Nostr Inbound Dispatcher + Restart Logic — Design

Date: 2026-02-25
Branch: nostr-channel

## Problem

Two related gaps in the Nostr channel implementation:

1. **Inbound messages are never processed.** The Nostr reader thread publishes to
   `bus.inbound`, but nothing consumes that queue. The bus was wired up in
   anticipation of an agent processing loop that was never implemented. Nostr
   messages arrive, pass DM policy, and silently disappear into the ring buffer.

2. **No auto-restart when nak dies.** When the `nak req --stream` subprocess exits
   (relay disconnect, network blip), the reader thread exits via EOF but does not
   signal this. `healthCheck()` returns `self.started and self.listener != null`,
   which remains true even with a dead subprocess. The daemon sees the channel as
   healthy and never restarts it.

## Design

### Section 1 — Health check fix (`nostr.zig`)

Add `defer self.running.store(false, .release)` at the top of `readerLoop`. This
deferred store runs on all exit paths: EOF, read error, or stop-requested. Update
`healthCheck()` to use the `running` flag instead of `listener != null`:

```zig
pub fn healthCheck(self: *NostrChannel) bool {
    return self.started and self.running.load(.acquire);
}
```

`vtableStop` is unaffected — it sets `running = false`, kills the listener (forcing
EOF if still alive), then joins the reader thread (already exited → returns
immediately). No race condition.

State matrix:

| State                   | `started` | `running` | `healthCheck()` |
|-------------------------|-----------|-----------|-----------------|
| Never started           | false     | false     | false           |
| Running normally        | true      | true      | true            |
| nak died silently       | true      | false     | **false** ← fixed |
| `stop()` called         | false     | false     | false           |

### Section 2 — Inbound dispatcher (`dispatch.zig` + `daemon.zig`)

Add `runInboundDispatcher` to `dispatch.zig` alongside `runOutboundDispatcher`:

```zig
pub fn runInboundDispatcher(
    allocator: Allocator,
    event_bus: *bus.Bus,
    session_mgr: *session_mod.SessionManager,
    registry: *const ChannelRegistry,
) void
```

Processing loop:
1. `consumeInbound()` — blocks until a message arrives or bus closes
2. `session_mgr.processMessage(msg.session_key, msg.content)` — runs the agent
3. On success: `bus.publishOutbound({.channel=msg.channel, .chat_id=msg.chat_id, .content=reply})`
4. On LLM error: `bus.publishOutbound` an error string (consistent with Telegram's
   error handling pattern)
5. Exits when bus closes (returns null from consumeInbound)

Reply routing uses Option A (full bus round-trip): the inbound dispatcher publishes
to `bus.outbound` and the existing `runOutboundDispatcher` routes to `channel.send()`.
This is consistent with how cron/scheduler publish outbound messages. The inbound
dispatcher needs no registry coupling — it just names the channel from the inbound
message's `.channel` field.

In `daemon.run()`: spawned after `channel_rt` is initialised, before the main wait
loop. Guard: only spawn if `channel_rt != null`. Stack: 512 KB. Registered as
`"inbound_dispatcher"` in `DaemonState`.

### Section 3 — Nostr restart logic (`daemon.zig`)

Wrap the Nostr channel in a `SupervisedChannel` (max 5 restarts) immediately after
successful start:

```zig
var nostr_supervised: ?dispatch.SupervisedChannel = null;
if (nostr_ch != null) {
    nostr_supervised = dispatch.spawnSupervisedChannel(nostr_ch.channel(), 5);
    nostr_supervised.recordSuccess();
}
```

In the monitoring loop (every 60s), replace the log-only health block:

```zig
if (nostr_ch) |ch| {
    if (ch.channel().healthCheck()) {
        health.markComponentOk("nostr");
        if (nostr_supervised) |*s| if (s.state != .running) s.recordSuccess();
    } else {
        health.markComponentError("nostr", "channel unhealthy");
        if (nostr_supervised) |*s| {
            s.recordFailure();
            if (s.shouldRestart()) {
                log.info("Restarting Nostr channel (attempt {d})", .{s.restart_count});
                ch.channel().stop();
                std.Thread.sleep(s.currentBackoffMs() * std.time.ns_per_ms);
                ch.channel().start() catch |err| {
                    log.err("Nostr restart failed: {}", .{err});
                    health.markComponentError("nostr", @errorName(err));
                };
            } else if (s.state == .gave_up) {
                health.markComponentError("nostr", "gave up after max restarts");
            }
        }
    }
}
```

`setBus()` does not need to be called again after restart — `event_bus` persists on
the struct through `stop()`/`start()` cycles. The channel remains registered in
`ChannelRegistry` (same instance pointer), so the outbound dispatcher continues
routing to it. During the restart window, `vtableSend` returns `NoSigningKey` which
the outbound dispatcher counts as an error and drops.

State that survives restarts:
- `sender_protocols` map (NIP-17/NIP-04 mirroring per sender) — intentionally preserved
- `event_bus` pointer — preserved
- `listen_start_at` — reset to `now()` in `vtableStart` (correct: don't replay events)
- `signing_sec` — cleared in stop, re-derived in start (correct: by design)

### Section 4 — Testing

**`nostr.zig`:**
- `healthCheck returns false after reader exits naturally` — set `running = false`,
  `started = true`, assert false
- `healthCheck returns true when started and running` — assert true with both true
- Existing `vtableStop is safe on unstarted channel` covers stop-after-natural-exit

**`dispatch.zig`:**
- `runInboundDispatcher routes message through session_mgr and publishes outbound`
- `runInboundDispatcher exits when bus closes`
- `runInboundDispatcher publishes error reply on processMessage failure`

**`daemon.zig`:**
- Existing `channelSupervisorThread respects shutdown` test covers the no-channel path
- No new daemon-level unit tests needed — `SupervisedChannel` restart logic is
  already fully tested in dispatch.zig tests

## Compatibility

The two fixes are orthogonal:
- Restart fix touches `nostr.zig` (health signal) and `daemon.zig` (supervisor loop)
- Inbound fix adds a new thread in `dispatch.zig` and a spawn site in `daemon.zig`
- They share no code paths or data structures
- `SessionManager` is thread-safe (two-level mutex: map-level + per-session) so the
  inbound dispatcher and Telegram polling thread can safely share the same instance

## Files changed

| File | Change |
|------|--------|
| `src/channels/nostr.zig` | `defer running.store(false)` in readerLoop; update healthCheck |
| `src/channels/dispatch.zig` | Add `runInboundDispatcher` + tests |
| `src/daemon.zig` | Spawn inbound dispatcher thread; add SupervisedChannel for Nostr |
