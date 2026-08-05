const std = @import("std");

// Shared thread stack budgets by operational role.
//
// Keep repeated `std.Thread.spawn` sizes aligned across runtime code and
// tests, and make intent visible at the call site.

/// Queue/mutex coordination, short-lived test helpers, and other tiny worker
/// tasks that do not enter the full agent/runtime path.
///
/// Zig 0.16's pthread backend can reject smaller custom stacks on glibc with
/// `pthread_create(...)=EINVAL`, so keep the floor at 512 KiB.
pub const COORDINATION_STACK_SIZE: usize = 512 * 1024;

/// Typing indicators, websocket heartbeats, and similarly small auxiliary
/// loops that do not initialize memory/runtime state.
pub const AUXILIARY_LOOP_STACK_SIZE: usize = 512 * 1024;

/// Supervisors, readers, pollers, and other medium-weight control loops.
pub const CONTROL_LOOP_STACK_SIZE: usize = 512 * 1024;

/// Daemon-owned services such as the HTTP gateway, scheduler, and channel
/// supervisor. These traverse deeper webhook, cron, and channel bootstrap
/// paths than generic control loops.
pub const DAEMON_SERVICE_STACK_SIZE: usize = 1024 * 1024;

/// Long-lived network/runtime threads such as channel gateways, outbound
/// dispatch, and subagents.
pub const HEAVY_RUNTIME_STACK_SIZE: usize = 2 * 1024 * 1024;

/// Dedicated threads that execute `SessionManager.processMessage*()` /
/// `Agent.turn()`.
///
/// The turn path (channel decode -> session -> agent -> provider -> tools) is
/// the deepest stack in the runtime, and aarch64 frames are larger than x86_64
/// ones, so 2 MiB overflowed into the guard page and killed the process on
/// every inbound message there. `nullclaw agent` never hit it because it runs
/// on the 8 MiB main-thread stack.
///
/// This is address space, not resident memory: Linux commits stack pages on
/// first touch, so a thread that stays shallow still costs a few pages of RSS.
pub const SESSION_TURN_STACK_SIZE: usize = 16 * 1024 * 1024;

test "coordination stack size can spawn a thread" {
    const thread = try std.Thread.spawn(.{ .stack_size = COORDINATION_STACK_SIZE }, struct {
        fn run() void {}
    }.run, .{});
    thread.join();
}

test "auxiliary stack size can spawn a thread" {
    const thread = try std.Thread.spawn(.{ .stack_size = AUXILIARY_LOOP_STACK_SIZE }, struct {
        fn run() void {}
    }.run, .{});
    thread.join();
}

test "session turn stack size can spawn a thread" {
    const thread = try std.Thread.spawn(.{ .stack_size = SESSION_TURN_STACK_SIZE }, struct {
        fn run() void {}
    }.run, .{});
    thread.join();
}

test "session turn stack clears the main-thread budget" {
    // Regression: every inbound message segfaulted on aarch64 because the turn
    // path ran on a 2 MiB thread and overflowed into the guard page, while the
    // same path was fine on the 8 MiB main-thread stack. Anything at or below
    // that 8 MiB reference is not a safe budget for the deepest path we have.
    const main_thread_reference: usize = 8 * 1024 * 1024;
    try std.testing.expect(SESSION_TURN_STACK_SIZE > main_thread_reference);
    try std.testing.expect(SESSION_TURN_STACK_SIZE > HEAVY_RUNTIME_STACK_SIZE);
}
