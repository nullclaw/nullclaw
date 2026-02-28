# Nostr Inbound Dispatcher + Restart Logic Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the Nostr channel into the agent processing pipeline (inbound dispatcher) and add auto-restart when the nak subprocess dies.

**Architecture:** Three changes across two files. `nostr.zig` gets a one-line health signal fix. `dispatch.zig` gets a new `runInboundDispatcher` function (mirrors `runOutboundDispatcher`) that consumes `bus.inbound`, calls `session_mgr.processMessage`, and publishes replies to `bus.outbound`. `daemon.zig` spawns that dispatcher thread and adds a `SupervisedChannel` wrapper around the Nostr channel for stop/start restart logic.

**Tech Stack:** Zig 0.15, nullclaw event bus (`src/bus.zig`), `SessionManager` (`src/session.zig`), `SupervisedChannel` (`src/channels/dispatch.zig`), `nak` CLI subprocess.

**Design doc:** `docs/plans/2026-02-25-nostr-inbound-restart-design.md`

---

### Task 1: Fix healthCheck — signal reader exit from readerLoop (`nostr.zig`)

**Files:**
- Modify: `src/channels/nostr.zig` — `readerLoop` (line ~366), `healthCheck` (line ~459)

**Context:** `readerLoop` exits on EOF (`if (n == 0) break`) but never sets `running = false`. `healthCheck` checks `self.listener != null` which stays true even with a dead nak process. Adding a `defer` makes the flag truthful on all exit paths.

**Step 1: Write the two failing tests**

Add at the bottom of `src/channels/nostr.zig` (before the final closing `}`), after the existing `vtableStop is safe on unstarted channel` test:

```zig
test "healthCheck returns false when reader exits naturally" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    // Simulate: channel was started, reader has since exited
    ch.started = true;
    ch.running.store(false, .release);
    try std.testing.expect(!ch.healthCheck());
}

test "healthCheck returns true when started and running" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    ch.started = true;
    ch.running.store(true, .release);
    try std.testing.expect(ch.healthCheck());
}
```

**Step 2: Run to verify both fail**

```bash
zig build test --summary all 2>&1 | grep -A2 "healthCheck returns false\|healthCheck returns true"
```

Expected: both FAIL — `healthCheck` still uses `self.listener != null`.

**Step 3: Implement the fix**

In `readerLoop`, add `defer` as the very first statement in the function body (before the `const stdout_file` line):

```zig
fn readerLoop(self: *NostrChannel) void {
    defer self.running.store(false, .release); // signal exit on all paths
    const stdout_file = if (self.listener) |*l| (l.stdout orelse return) else return;
```

Then update `healthCheck`:

```zig
pub fn healthCheck(self: *NostrChannel) bool {
    return self.started and self.running.load(.acquire);
}
```

**Step 4: Run to verify both pass**

```bash
zig build test --summary all 2>&1 | grep -A2 "healthCheck returns false\|healthCheck returns true"
```

Expected: both PASS.

**Step 5: Run full suite to catch regressions**

```bash
zig build test --summary all
```

Expected: 0 failures, 0 leaks.

**Step 6: Commit**

```bash
git add src/channels/nostr.zig
git commit -m "fix(nostr): signal reader exit via running flag, fix healthCheck"
```

---

### Task 2: Add `runInboundDispatcher` to `dispatch.zig`

**Files:**
- Modify: `src/channels/dispatch.zig` — add imports, new function, tests

**Context:** `dispatch.zig` already has `runOutboundDispatcher` which consumes `bus.outbound`. The inbound dispatcher is its mirror: consumes `bus.inbound`, calls `session_mgr.processMessage`, publishes to `bus.outbound`. The outbound dispatcher handles the rest. `session_mgr` is already thread-safe (two-level mutex — see `src/session.zig` lines 7–8).

**Step 1: Add imports at the top of `dispatch.zig`**

After the existing imports (after `const bus = @import("../bus.zig");`), add:

```zig
const session_mod = @import("../session.zig");
const log = std.log.scoped(.dispatch);
```

**Step 2: Write the failing tests**

Add after the existing `// Outbound Dispatch Loop` section (before `// Channel Supervisor`), below `runOutboundDispatcher`:

```zig
// ════════════════════════════════════════════════════════════════════════════
// Inbound Dispatch Loop
// ════════════════════════════════════════════════════════════════════════════

/// Run the inbound dispatch loop. Blocks until the bus is closed.
/// Consumes messages from `bus.consumeInbound()`, calls
/// `session_mgr.processMessage()`, and publishes replies to `bus.outbound`.
/// On processMessage error, publishes a generic error reply.
///
/// Designed to run in a dedicated thread:
///   `std.Thread.spawn(.{}, runInboundDispatcher, .{ alloc, &bus, &session_mgr })`
pub fn runInboundDispatcher(
    allocator: Allocator,
    event_bus: *bus.Bus,
    session_mgr: *session_mod.SessionManager,
) void {
    // Implementation added in step 4
    _ = allocator;
    _ = event_bus;
    _ = session_mgr;
}
```

Then add tests at the bottom of `dispatch.zig` (before the final `}`), after the existing supervisor tests:

```zig
// ════════════════════════════════════════════════════════════════════════════
// Inbound Dispatch Tests
// ════════════════════════════════════════════════════════════════════════════

test "runInboundDispatcher exits when bus is closed" {
    const allocator = std.testing.allocator;
    var event_bus = bus.Bus.init();

    // Close the bus immediately — dispatcher should exit without blocking
    event_bus.close();

    // If this returns, the dispatcher exited. If it hangs, the test times out.
    // We call it directly (not in a thread) since the bus is already closed.
    // session_mgr is never called so we pass undefined — safe only because
    // consumeInbound returns null immediately on a closed+empty bus.
    const dummy_session_mgr: *session_mod.SessionManager = undefined;
    runInboundDispatcher(allocator, &event_bus, dummy_session_mgr);
}

test "runInboundDispatcher exits cleanly on closed empty bus via thread" {
    const allocator = std.testing.allocator;
    var event_bus = bus.Bus.init();

    const thread = try std.Thread.spawn(
        .{ .stack_size = 128 * 1024 },
        runInboundDispatcher,
        .{ allocator, &event_bus, @as(*session_mod.SessionManager, undefined) },
    );

    // Small delay then close — dispatcher should unblock and exit
    std.Thread.sleep(5 * std.time.ns_per_ms);
    event_bus.close();
    thread.join(); // if this returns, the dispatcher exited cleanly
}
```

**Step 3: Run to verify tests pass with stub implementation**

```bash
zig build test --summary all 2>&1 | grep -A2 "runInboundDispatcher exits"
```

Expected: both PASS (stub does nothing, bus is closed/empty so tests pass trivially).

**Step 4: Implement `runInboundDispatcher`**

Replace the stub body with the real implementation:

```zig
pub fn runInboundDispatcher(
    allocator: Allocator,
    event_bus: *bus.Bus,
    session_mgr: *session_mod.SessionManager,
) void {
    while (event_bus.consumeInbound()) |msg| {
        defer msg.deinit(allocator);

        const reply = session_mgr.processMessage(msg.session_key, msg.content) catch |err| {
            log.err("inbound: processMessage failed for session '{s}': {}", .{ msg.session_key, err });
            const err_text = "An error occurred. Please try again." ;
            const out = bus.makeOutbound(allocator, msg.channel, msg.chat_id, err_text) catch continue;
            event_bus.publishOutbound(out) catch out.deinit(allocator);
            continue;
        };
        defer allocator.free(reply);

        const out = bus.makeOutbound(allocator, msg.channel, msg.chat_id, reply) catch continue;
        event_bus.publishOutbound(out) catch out.deinit(allocator);
    }
}
```

**Step 5: Run full suite**

```bash
zig build test --summary all
```

Expected: 0 failures, 0 leaks.

**Step 6: Commit**

```bash
git add src/channels/dispatch.zig
git commit -m "feat(dispatch): add runInboundDispatcher — bus.inbound → session_mgr → bus.outbound"
```

---

### Task 3: Spawn inbound dispatcher thread in `daemon.zig`

**Files:**
- Modify: `src/daemon.zig` — `run()` function

**Context:** `channel_rt` holds the `SessionManager`. The inbound dispatcher only makes sense when there's a runtime. Guard spawn on `channel_rt != null`. Register as `"inbound_dispatcher"` in `DaemonState`. Join on shutdown alongside the outbound dispatcher.

**Step 1: Add component registration and spawn**

In `daemon.run()`, after the outbound dispatcher block (after line ~518, after `state.markRunning("outbound_dispatcher")`), add:

```zig
state.addComponent("inbound_dispatcher");

var inbound_dispatcher_thread: ?std.Thread = null;
if (channel_rt) |rt| {
    if (std.Thread.spawn(.{ .stack_size = 512 * 1024 }, dispatch.runInboundDispatcher, .{
        allocator, &event_bus, &rt.session_mgr,
    })) |thread| {
        inbound_dispatcher_thread = thread;
        state.markRunning("inbound_dispatcher");
        health.markComponentOk("inbound_dispatcher");
    } else |err| {
        state.markError("inbound_dispatcher", @errorName(err));
        stdout.print("Warning: inbound dispatcher thread failed: {}\n", .{err}) catch {};
    }
} else {
    // No runtime — inbound dispatcher not needed
    state.markRunning("inbound_dispatcher");
}
```

**Step 2: Join on shutdown**

In the shutdown section (after `if (dispatcher_thread) |t| t.join();`), add:

```zig
if (inbound_dispatcher_thread) |t| t.join();
```

**Step 3: Run full suite**

```bash
zig build test --summary all
```

Expected: 0 failures, 0 leaks. The existing `channelSupervisorThread respects shutdown` test and daemon tests should still pass.

**Step 4: Commit**

```bash
git add src/daemon.zig
git commit -m "feat(daemon): spawn inbound dispatcher thread when channel runtime is available"
```

---

### Task 4: Add Nostr restart logic in `channelSupervisorThread` (`daemon.zig`)

**Files:**
- Modify: `src/daemon.zig` — `channelSupervisorThread`

**Context:** After successful Nostr start, wrap in `SupervisedChannel` (max 5 restarts, same as Telegram). In the monitoring loop, replace the log-only health block with stop/backoff/start restart logic. `setBus()` does not need to be called again after restart — `event_bus` persists on the struct. The channel stays registered in the registry throughout (same instance pointer).

**Step 1: Add `SupervisedChannel` wrapper after successful Nostr start**

Find the Nostr start block in `channelSupervisorThread` (around line 280). After it, declare the supervised variable before the `if (config.channels.nostr)` block:

```zig
// ── Nostr channel ──
var nostr_ch: ?*nostr_channel.NostrChannel = null;
var nostr_supervised: ?dispatch.SupervisedChannel = null;   // ← add this line
if (config.channels.nostr) |ns_config| {
```

Then inside the successful start arm (after `log.info("Nostr channel started")`), add:

```zig
log.info("Nostr channel started", .{});
health.markComponentOk("nostr");
nostr_supervised = dispatch.spawnSupervisedChannel(ch.channel(), 5);
if (nostr_supervised) |*s| s.recordSuccess();
```

**Step 2: Replace the monitoring loop nostr block**

Find the existing nostr health block in the monitoring loop (around line 371):

```zig
// Nostr health check (no restart logic yet — just monitor)
if (nostr_ch) |ch| {
    if (!ch.channel().healthCheck()) {
        health.markComponentError("nostr", "channel unhealthy");
        log.warn("Nostr channel unhealthy (listener may have stopped)", .{});
    } else {
        health.markComponentOk("nostr");
    }
}
```

Replace entirely with:

```zig
// Nostr health check + supervised restart
if (nostr_ch) |ch| {
    if (ch.channel().healthCheck()) {
        health.markComponentOk("nostr");
        if (nostr_supervised) |*s| {
            if (s.state != .running) s.recordSuccess();
        }
    } else {
        health.markComponentError("nostr", "channel unhealthy");
        log.warn("Nostr channel unhealthy (listener may have stopped)", .{});
        if (nostr_supervised) |*s| {
            s.recordFailure();
            if (s.shouldRestart()) {
                log.info("Restarting Nostr channel (attempt {d})", .{s.restart_count});
                state.markError("channels", "nostr restarting");
                ch.channel().stop();
                std.Thread.sleep(s.currentBackoffMs() * std.time.ns_per_ms);
                if (ch.channel().start()) |_| {
                    s.recordSuccess();
                    state.markRunning("channels");
                    health.markComponentOk("nostr");
                    log.info("Nostr channel restarted successfully", .{});
                } else |err| {
                    log.err("Nostr restart failed: {}", .{err});
                    health.markComponentError("nostr", @errorName(err));
                }
            } else if (s.state == .gave_up) {
                log.err("Nostr channel gave up after {d} restarts", .{s.restart_count});
                health.markComponentError("nostr", "gave up after max restarts");
            }
        }
    }
}
```

**Step 3: Run full suite**

```bash
zig build test --summary all
```

Expected: 0 failures, 0 leaks.

**Step 4: Commit**

```bash
git add src/daemon.zig
git commit -m "feat(daemon): add supervised restart logic for Nostr channel"
```

---

### Task 5: Final validation

**Step 1: Run the complete test suite**

```bash
zig build test --summary all
```

Expected: 0 failures, 0 leaks, all tests pass.

**Step 2: Verify test count increased**

```bash
zig build test --summary all 2>&1 | grep -E "^[0-9]+ passed"
```

Should show more tests than before (new healthCheck tests + inbound dispatcher tests).

**Step 3: Check no compile warnings on daemon binary**

```bash
zig build 2>&1 | grep -i "warn\|error" | grep -v "^$"
```

Expected: no new warnings.

**Step 4: Final commit if any fixes needed, otherwise tag the work**

```bash
git log --oneline -6
```

Verify the four commits are present:
1. `fix(nostr): signal reader exit via running flag, fix healthCheck`
2. `feat(dispatch): add runInboundDispatcher — bus.inbound → session_mgr → bus.outbound`
3. `feat(daemon): spawn inbound dispatcher thread when channel runtime is available`
4. `feat(daemon): add supervised restart logic for Nostr channel`
