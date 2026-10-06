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

/// Websocket heartbeats and similarly small auxiliary loops that do not
/// initialize TLS connections or memory/runtime state. HTTPS typing workers
/// use HEAVY_RUNTIME_STACK_SIZE.
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

test "heavy runtime stack reaches TLS peer validation" {
    // Regression (#1002): HTTPS typing workers overflowed the auxiliary stack
    // inside TLS initialization. Exercise the handshake with an invalid in-memory
    // peer, so the stack budget is tested without network access or credentials.
    const Probe = struct {
        failure: ?anyerror = null,
        hello_bytes: usize = 0,

        fn run(self: *@This()) void {
            const Tls = std.crypto.tls.Client;
            var peer_bytes: [Tls.min_buffer_len]u8 = @splat(0);
            var peer = std.Io.Reader.fixed(&peer_bytes);
            var output_bytes: [32 * 1024]u8 = undefined;
            var output = std.Io.Writer.fixed(&output_bytes);
            var read_buffer: [Tls.min_buffer_len]u8 = undefined;
            var write_buffer: [Tls.min_buffer_len]u8 = undefined;
            const entropy: [Tls.Options.entropy_len]u8 = @splat(42);
            _ = Tls.init(&peer, &output, .{
                .host = .{ .explicit = "example.test" },
                .ca = .self_signed,
                .read_buffer = &read_buffer,
                .write_buffer = &write_buffer,
                .entropy = &entropy,
                .realtime_now = .zero,
            }) catch |err| {
                self.failure = err;
                self.hello_bytes = output.end;
                return;
            };
        }
    };
    var probe: Probe = .{};
    const thread = try std.Thread.spawn(.{ .stack_size = HEAVY_RUNTIME_STACK_SIZE }, Probe.run, .{&probe});
    thread.join();
    try std.testing.expect(probe.failure != null);
    try std.testing.expect(probe.failure.? == error.TlsUnexpectedMessage);
    try std.testing.expect(probe.hello_bytes > 0);
}
