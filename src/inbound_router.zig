//! Pure routing logic for inbound messages.
//!
//! Given session state and the configured queue policy, returns the action
//! the effectful shell should take. No I/O, no allocations; fully unit-testable.
//!
//! Usage:
//!   const input = session_mgr.routeInput(session_key);
//!   switch (inbound_router.route(input)) {
//!       .process           => session_mgr.processMessageStreaming(...),
//!       .inject            => session_mgr.injectMidTurn(session_key, text),
//!       .replace_injection => session_mgr.injectMidTurn(session_key, text),  // same effect
//!       .queue             => session_mgr.processMessageStreaming(...),      // waits on session lock
//!       .drop              => {},
//!   }

const config_types = @import("config_types.zig");

pub const QueueMode = config_types.QueueMode;

/// Snapshot of the state needed to make a routing decision.
/// Obtained via SessionManager.routeInput().
pub const RouteInput = struct {
    /// True when agent.turn() is currently executing for this session.
    turn_running: bool,
    /// The session's configured inbound queue policy.
    queue_mode: QueueMode,
    /// True when there is already a message pending in the injection buffer.
    has_pending_injection: bool,
};

/// Action the effectful shell should perform for an inbound message.
pub const RoutingDecision = enum {
    /// No turn in progress: acquire the session lock and start a new turn.
    process,
    /// Turn running, serial mode: enqueue behind the current turn.
    queue,
    /// Turn running: deposit text in the injection buffer so the active turn
    /// picks it up at the next tool-loop boundary.
    inject,
    /// Turn running and an injection is already pending: replace it (latest-wins).
    replace_injection,
    /// Turn running, queue mode is off: discard the message silently.
    drop,
};

/// Decide how to handle an inbound message given the current session state.
pub fn route(input: RouteInput) RoutingDecision {
    if (!input.turn_running) return .process;
    return switch (input.queue_mode) {
        .off => .drop,
        .serial => .queue,
        .latest => if (input.has_pending_injection) .replace_injection else .inject,
        .debounce => .inject,
    };
}

// Tests

const testing = @import("std").testing;

test "route returns process when turn is not running" {
    for ([_]QueueMode{ .off, .serial, .latest, .debounce }) |mode| {
        const decision = route(.{
            .turn_running = false,
            .queue_mode = mode,
            .has_pending_injection = false,
        });
        try testing.expectEqual(RoutingDecision.process, decision);
    }
}

test "route drops when turn running and queue_mode is off" {
    try testing.expectEqual(RoutingDecision.drop, route(.{
        .turn_running = true,
        .queue_mode = .off,
        .has_pending_injection = false,
    }));
}

test "route queues when turn running and queue_mode is serial" {
    try testing.expectEqual(RoutingDecision.queue, route(.{
        .turn_running = true,
        .queue_mode = .serial,
        .has_pending_injection = false,
    }));
    // serial always queues regardless of pending injection
    try testing.expectEqual(RoutingDecision.queue, route(.{
        .turn_running = true,
        .queue_mode = .serial,
        .has_pending_injection = true,
    }));
}

test "route injects when turn running and queue_mode is latest with no pending" {
    try testing.expectEqual(RoutingDecision.inject, route(.{
        .turn_running = true,
        .queue_mode = .latest,
        .has_pending_injection = false,
    }));
}

test "route replaces injection when turn running and queue_mode is latest with pending" {
    try testing.expectEqual(RoutingDecision.replace_injection, route(.{
        .turn_running = true,
        .queue_mode = .latest,
        .has_pending_injection = true,
    }));
}

test "route injects when turn running and queue_mode is debounce" {
    try testing.expectEqual(RoutingDecision.inject, route(.{
        .turn_running = true,
        .queue_mode = .debounce,
        .has_pending_injection = false,
    }));
    // Debounce timing/merge is handled by the caller before depositing text.
    try testing.expectEqual(RoutingDecision.inject, route(.{
        .turn_running = true,
        .queue_mode = .debounce,
        .has_pending_injection = true,
    }));
}

test "route process takes priority over all modes when not running" {
    const inputs = [_]RouteInput{
        .{ .turn_running = false, .queue_mode = .off, .has_pending_injection = true },
        .{ .turn_running = false, .queue_mode = .latest, .has_pending_injection = true },
        .{ .turn_running = false, .queue_mode = .debounce, .has_pending_injection = false },
    };
    for (inputs) |input| {
        try testing.expectEqual(RoutingDecision.process, route(input));
    }
}
