const std = @import("std");

/// Standalone action tracker for rate limiting.
/// This is a convenience wrapper that can be used independently of SecurityPolicy.
///
/// Tracks actions in a sliding window (default 1 hour) and provides
/// rate limiting functionality.
pub const RateTracker = struct {
    /// Timestamps of recent actions in nanoseconds (monotonic)
    timestamps: std.ArrayList(i128) = .empty,
    /// Window duration in nanoseconds
    window_ns: i128,
    /// Maximum allowed actions per window
    max_actions: u32,
    allocator: std.mem.Allocator,

    /// Default window: 1 hour
    const DEFAULT_WINDOW_NS: i128 = 3600 * std.time.ns_per_s;

    pub fn init(allocator: std.mem.Allocator, max_actions: u32) RateTracker {
        return initWithWindow(allocator, max_actions, DEFAULT_WINDOW_NS);
    }

    pub fn initWithWindow(allocator: std.mem.Allocator, max_actions: u32, window_ns: i128) RateTracker {
        return .{
            .window_ns = window_ns,
            .max_actions = max_actions,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RateTracker) void {
        self.timestamps.deinit(self.allocator);
    }

    /// Record an action. Returns true if the action is allowed (within limit),
    /// false if rate-limited.
    pub fn recordAction(self: *RateTracker) !bool {
        self.prune();
        try self.timestamps.append(self.allocator, std.time.nanoTimestamp());
        return self.timestamps.items.len <= self.max_actions;
    }

    /// Check if the rate limit would be exceeded without recording.
    pub fn isLimited(self: *RateTracker) bool {
        self.prune();
        return self.timestamps.items.len >= self.max_actions;
    }

    /// Current count of actions in the window.
    pub fn count(self: *RateTracker) usize {
        self.prune();
        return self.timestamps.items.len;
    }

    /// Remaining allowed actions before hitting the limit.
    pub fn remaining(self: *RateTracker) u32 {
        self.prune();
        const used: u32 = @intCast(@min(self.timestamps.items.len, self.max_actions));
        return self.max_actions - used;
    }

    /// Reset the tracker (clear all recorded actions).
    pub fn reset(self: *RateTracker) void {
        self.timestamps.clearRetainingCapacity();
    }

    fn prune(self: *RateTracker) void {
        const now = std.time.nanoTimestamp();
        const cutoff = now - self.window_ns;
        var write_idx: usize = 0;
        for (self.timestamps.items) |ts| {
            if (ts > cutoff) {
                self.timestamps.items[write_idx] = ts;
                write_idx += 1;
            }
        }
        self.timestamps.shrinkRetainingCapacity(write_idx);
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

test "rate tracker starts empty" {
    var tracker = RateTracker.init(std.testing.allocator, 10);
    defer tracker.deinit();
    try std.testing.expectEqual(@as(usize, 0), tracker.count());
    try std.testing.expect(!tracker.isLimited());
    try std.testing.expectEqual(@as(u32, 10), tracker.remaining());
}

test "rate tracker records and counts" {
    var tracker = RateTracker.init(std.testing.allocator, 10);
    defer tracker.deinit();
    try std.testing.expect(try tracker.recordAction());
    try std.testing.expect(try tracker.recordAction());
    try std.testing.expect(try tracker.recordAction());
    try std.testing.expectEqual(@as(usize, 3), tracker.count());
    try std.testing.expectEqual(@as(u32, 7), tracker.remaining());
}

test "rate tracker blocks when over limit" {
    var tracker = RateTracker.init(std.testing.allocator, 3);
    defer tracker.deinit();
    try std.testing.expect(try tracker.recordAction()); // 1
    try std.testing.expect(try tracker.recordAction()); // 2
    try std.testing.expect(try tracker.recordAction()); // 3
    try std.testing.expect(!try tracker.recordAction()); // 4 — over limit
}

test "rate tracker is limited at boundary" {
    var tracker = RateTracker.init(std.testing.allocator, 2);
    defer tracker.deinit();
    try std.testing.expect(!tracker.isLimited());
    _ = try tracker.recordAction();
    try std.testing.expect(!tracker.isLimited());
    _ = try tracker.recordAction();
    try std.testing.expect(tracker.isLimited());
}

test "rate tracker zero limit blocks everything" {
    var tracker = RateTracker.init(std.testing.allocator, 0);
    defer tracker.deinit();
    try std.testing.expect(!try tracker.recordAction());
    try std.testing.expect(tracker.isLimited());
}

test "rate tracker reset clears actions" {
    var tracker = RateTracker.init(std.testing.allocator, 5);
    defer tracker.deinit();
    _ = try tracker.recordAction();
    _ = try tracker.recordAction();
    try std.testing.expectEqual(@as(usize, 2), tracker.count());

    tracker.reset();
    try std.testing.expectEqual(@as(usize, 0), tracker.count());
    try std.testing.expectEqual(@as(u32, 5), tracker.remaining());
}

test "rate tracker high limit allows many" {
    var tracker = RateTracker.init(std.testing.allocator, 10000);
    defer tracker.deinit();
    for (0..100) |_| {
        try std.testing.expect(try tracker.recordAction());
    }
}

test "rate tracker remaining decreases" {
    var tracker = RateTracker.init(std.testing.allocator, 5);
    defer tracker.deinit();
    try std.testing.expectEqual(@as(u32, 5), tracker.remaining());
    _ = try tracker.recordAction();
    try std.testing.expectEqual(@as(u32, 4), tracker.remaining());
    _ = try tracker.recordAction();
    try std.testing.expectEqual(@as(u32, 3), tracker.remaining());
}

test "rate tracker remaining at zero when full" {
    var tracker = RateTracker.init(std.testing.allocator, 2);
    defer tracker.deinit();
    _ = try tracker.recordAction();
    _ = try tracker.recordAction();
    try std.testing.expectEqual(@as(u32, 0), tracker.remaining());
}

test "rate tracker remaining stays at zero when over limit" {
    var tracker = RateTracker.init(std.testing.allocator, 1);
    defer tracker.deinit();
    _ = try tracker.recordAction();
    _ = try tracker.recordAction(); // over limit
    try std.testing.expectEqual(@as(u32, 0), tracker.remaining());
}

test "rate tracker reset then reuse" {
    var tracker = RateTracker.init(std.testing.allocator, 3);
    defer tracker.deinit();
    _ = try tracker.recordAction();
    _ = try tracker.recordAction();
    _ = try tracker.recordAction();
    try std.testing.expect(!try tracker.recordAction()); // over

    tracker.reset();
    try std.testing.expect(try tracker.recordAction()); // fresh start
    try std.testing.expectEqual(@as(usize, 1), tracker.count());
}

test "rate tracker custom window" {
    // Use a very large window (effectively infinite)
    var tracker = RateTracker.initWithWindow(std.testing.allocator, 5, 3600 * std.time.ns_per_s * 24);
    defer tracker.deinit();
    try std.testing.expect(try tracker.recordAction());
    try std.testing.expectEqual(@as(usize, 1), tracker.count());
}

test "rate tracker init with window preserves params" {
    var tracker = RateTracker.initWithWindow(std.testing.allocator, 42, 999);
    defer tracker.deinit();
    try std.testing.expectEqual(@as(u32, 42), tracker.max_actions);
    try std.testing.expectEqual(@as(i128, 999), tracker.window_ns);
}

test "rate tracker limit of one" {
    var tracker = RateTracker.init(std.testing.allocator, 1);
    defer tracker.deinit();
    try std.testing.expect(!tracker.isLimited());
    try std.testing.expect(try tracker.recordAction()); // 1 allowed
    try std.testing.expect(tracker.isLimited());
    try std.testing.expect(!try tracker.recordAction()); // 2 blocked
}

test "rate tracker many actions count correct" {
    var tracker = RateTracker.init(std.testing.allocator, 1000);
    defer tracker.deinit();
    for (0..50) |_| {
        _ = try tracker.recordAction();
    }
    try std.testing.expectEqual(@as(usize, 50), tracker.count());
    try std.testing.expectEqual(@as(u32, 950), tracker.remaining());
}
