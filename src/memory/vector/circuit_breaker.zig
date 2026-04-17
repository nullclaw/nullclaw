//! Circuit breaker — pure state machine for embedding provider failure protection.
//!
//! States: closed (normal), open (tripped), half_open (cooldown expired, probe).
//! No I/O, no allocator, no external dependencies.

const std = @import("std");
const std_compat = @import("compat");

pub const State = enum { closed, open, half_open };

pub const CircuitBreaker = struct {
    state: State,
    failure_count: u32,
    threshold: u32,
    cooldown_ns: u64,
    last_failure_ns: i128,
    /// Guards half_open to allow exactly one probe request before requiring
    /// recordSuccess/recordFailure.
    half_open_probe_sent: bool = false,

    pub fn init(threshold: u32, cooldown_ms: u32) CircuitBreaker {
        return .{
            .state = .closed,
            .failure_count = 0,
            .threshold = threshold,
            .cooldown_ns = @as(u64, cooldown_ms) * 1_000_000,
            .last_failure_ns = 0,
            .half_open_probe_sent = false,
        };
    }

    /// Can we attempt an operation? Returns true if closed or half_open (cooldown expired).
    /// In half_open state, only the first call returns true (single probe request).
    /// Subsequent calls return false until recordSuccess/recordFailure is called.
    pub fn allow(self: *CircuitBreaker) bool {
        switch (self.state) {
            .closed => return true,
            .open => {
                const now = std_compat.time.nanoTimestamp();
                if (now - self.last_failure_ns >= self.cooldown_ns) {
                    self.state = .half_open;
                    self.half_open_probe_sent = true;
                    return true;
                }
                return false;
            },
            .half_open => {
                // Only allow one probe request in half_open state.
                if (!self.half_open_probe_sent) {
                    self.half_open_probe_sent = true;
                    return true;
                }
                return false;
            },
        }
    }

    /// Record successful operation. Resets to closed.
    pub fn recordSuccess(self: *CircuitBreaker) void {
        self.state = .closed;
        self.failure_count = 0;
        self.half_open_probe_sent = false;
    }

    /// Record failed operation. Increments counter, trips to open at threshold.
    pub fn recordFailure(self: *CircuitBreaker) void {
        self.failure_count +|= 1;
        self.last_failure_ns = std_compat.time.nanoTimestamp();

        if (self.state == .half_open or (self.state == .closed and self.failure_count >= self.threshold)) {
            self.state = .open;
            self.half_open_probe_sent = false;
        }
    }

    /// Is the breaker currently tripped?
    pub fn isOpen(self: *const CircuitBreaker) bool {
        return self.state == .open;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "init creates closed state with zero failure count" {
    const cb = CircuitBreaker.init(5, 1000);
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expectEqual(@as(u32, 0), cb.failure_count);
    try std.testing.expectEqual(@as(u64, 1_000_000_000), cb.cooldown_ns);
    try std.testing.expectEqual(@as(i128, 0), cb.last_failure_ns);
}

test "allow returns true when closed" {
    var cb = CircuitBreaker.init(5, 1000);
    try std.testing.expect(cb.allow());
    try std.testing.expectEqual(State.closed, cb.state);
}

test "recordFailure increments count" {
    var cb = CircuitBreaker.init(5, 1000);
    cb.recordFailure();
    try std.testing.expectEqual(@as(u32, 1), cb.failure_count);
    cb.recordFailure();
    try std.testing.expectEqual(@as(u32, 2), cb.failure_count);
}

test "threshold failures trips to open" {
    var cb = CircuitBreaker.init(3, 1000);
    cb.recordFailure();
    cb.recordFailure();
    try std.testing.expectEqual(State.closed, cb.state);
    cb.recordFailure(); // 3rd failure hits threshold
    try std.testing.expectEqual(State.open, cb.state);
    try std.testing.expect(cb.isOpen());
}

test "allow returns false when open before cooldown" {
    var cb = CircuitBreaker.init(1, 999_999);
    cb.recordFailure(); // trips immediately (threshold=1)
    try std.testing.expectEqual(State.open, cb.state);
    try std.testing.expect(!cb.allow());
}

test "open transitions to half_open after cooldown" {
    var cb = CircuitBreaker.init(1, 0); // 0ms cooldown — expires immediately
    cb.recordFailure(); // trips to open
    try std.testing.expectEqual(State.open, cb.state);
    try std.testing.expect(cb.allow()); // cooldown already expired → half_open
    try std.testing.expectEqual(State.half_open, cb.state);
}

test "half_open plus success transitions to closed" {
    var cb = CircuitBreaker.init(1, 0);
    cb.recordFailure(); // → open
    _ = cb.allow(); // → half_open
    try std.testing.expectEqual(State.half_open, cb.state);
    cb.recordSuccess();
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expectEqual(@as(u32, 0), cb.failure_count);
}

test "half_open plus failure transitions to open" {
    var cb = CircuitBreaker.init(1, 0);
    cb.recordFailure(); // → open
    _ = cb.allow(); // → half_open
    try std.testing.expectEqual(State.half_open, cb.state);
    const before = cb.last_failure_ns;
    cb.recordFailure(); // → open again, timestamp updated
    try std.testing.expectEqual(State.open, cb.state);
    try std.testing.expect(cb.last_failure_ns >= before);
}

test "recordSuccess resets failure count" {
    var cb = CircuitBreaker.init(5, 1000);
    cb.recordFailure();
    cb.recordFailure();
    try std.testing.expectEqual(@as(u32, 2), cb.failure_count);
    cb.recordSuccess();
    try std.testing.expectEqual(@as(u32, 0), cb.failure_count);
    try std.testing.expectEqual(State.closed, cb.state);
}

test "isOpen reflects state correctly" {
    var cb = CircuitBreaker.init(2, 999_999);
    try std.testing.expect(!cb.isOpen());
    cb.recordFailure();
    try std.testing.expect(!cb.isOpen()); // still closed
    cb.recordFailure(); // trips to open
    try std.testing.expect(cb.isOpen());
    cb.recordSuccess(); // back to closed
    try std.testing.expect(!cb.isOpen());
}

test "multiple success failure cycles" {
    var cb = CircuitBreaker.init(3, 0);
    // Partial failures then success resets count
    cb.recordFailure();
    cb.recordFailure();
    try std.testing.expectEqual(@as(u32, 2), cb.failure_count);
    cb.recordSuccess();
    try std.testing.expectEqual(@as(u32, 0), cb.failure_count);
    try std.testing.expectEqual(State.closed, cb.state);

    // Need full threshold again to trip
    cb.recordFailure();
    try std.testing.expectEqual(State.closed, cb.state);
    cb.recordFailure();
    try std.testing.expectEqual(State.closed, cb.state);
    cb.recordFailure(); // 3rd → open
    try std.testing.expectEqual(State.open, cb.state);

    // Recover via half_open
    _ = cb.allow(); // 0ms cooldown → half_open
    cb.recordSuccess();
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expectEqual(@as(u32, 0), cb.failure_count);
}

test "threshold zero trips immediately on first failure" {
    var cb = CircuitBreaker.init(0, 1000);
    try std.testing.expectEqual(State.closed, cb.state);
    cb.recordFailure(); // failure_count=1 >= threshold=0 → open
    try std.testing.expectEqual(State.open, cb.state);
    try std.testing.expect(cb.isOpen());
}

test "half_open allows exactly one probe request" {
    var cb = CircuitBreaker.init(1, 0);
    cb.recordFailure(); // → open
    try std.testing.expect(cb.allow()); // → half_open, first probe allowed
    try std.testing.expectEqual(State.half_open, cb.state);
    // Second call in half_open must be rejected (only one probe)
    try std.testing.expect(!cb.allow());
    try std.testing.expectEqual(State.half_open, cb.state);
    // After recordSuccess, should be closed again and allow normally
    cb.recordSuccess();
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expect(cb.allow());
}

test "half_open probe resets after failure cycle" {
    var cb = CircuitBreaker.init(1, 0);
    cb.recordFailure(); // → open
    try std.testing.expect(cb.allow()); // → half_open, probe sent
    try std.testing.expect(!cb.allow()); // blocked
    cb.recordFailure(); // → open again, probe_sent reset
    try std.testing.expectEqual(State.open, cb.state);
    // After cooldown expires again, a new probe should be allowed
    try std.testing.expect(cb.allow()); // → half_open, new probe
    try std.testing.expectEqual(State.half_open, cb.state);
}

// ── R3 tests ──────────────────────────────────────────────────────

test "full lifecycle: closed → open → half_open → probe → success → closed" {
    var cb = CircuitBreaker.init(3, 0); // threshold=3, 0ms cooldown

    // Phase 1: closed — allow succeeds
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expect(cb.allow());

    // Phase 2: accumulate failures up to threshold
    cb.recordFailure(); // count=1, still closed
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expectEqual(@as(u32, 1), cb.failure_count);

    cb.recordFailure(); // count=2, still closed
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expectEqual(@as(u32, 2), cb.failure_count);

    cb.recordFailure(); // count=3, trips to open
    try std.testing.expectEqual(State.open, cb.state);
    try std.testing.expectEqual(@as(u32, 3), cb.failure_count);
    try std.testing.expect(cb.isOpen());

    // Phase 3: cooldown expired (0ms) → allow transitions to half_open
    try std.testing.expect(cb.allow()); // → half_open, probe sent
    try std.testing.expectEqual(State.half_open, cb.state);

    // Phase 4: single probe — second allow is blocked
    try std.testing.expect(!cb.allow()); // blocked, only one probe

    // Phase 5: probe succeeds → closed
    cb.recordSuccess();
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expectEqual(@as(u32, 0), cb.failure_count);
    try std.testing.expect(!cb.isOpen());

    // Phase 6: after recovery, allow works normally
    try std.testing.expect(cb.allow());
    try std.testing.expectEqual(State.closed, cb.state);
}

test "open state blocks all requests before cooldown" {
    var cb = CircuitBreaker.init(1, 999_999); // long cooldown
    cb.recordFailure(); // trips immediately (threshold=1)
    try std.testing.expectEqual(State.open, cb.state);

    // Multiple allow() calls all return false — no probe allowed before cooldown
    for (0..10) |_| {
        try std.testing.expect(!cb.allow());
        try std.testing.expectEqual(State.open, cb.state);
    }
}

test "half_open allows exactly one probe then blocks" {
    var cb = CircuitBreaker.init(1, 0);
    cb.recordFailure(); // → open

    // First allow → transitions to half_open, returns true (probe allowed)
    try std.testing.expect(cb.allow());
    try std.testing.expectEqual(State.half_open, cb.state);
    try std.testing.expect(cb.half_open_probe_sent);

    // Second allow → still half_open, returns false (probe already sent)
    try std.testing.expect(!cb.allow());
    try std.testing.expectEqual(State.half_open, cb.state);

    // Third allow → still blocked
    try std.testing.expect(!cb.allow());
    try std.testing.expectEqual(State.half_open, cb.state);
}

test "saturating add — many failures do not overflow u32" {
    var cb = CircuitBreaker.init(std.math.maxInt(u32), 0);

    // Set failure_count near max to test saturation
    cb.failure_count = std.math.maxInt(u32) - 1;
    cb.recordFailure(); // should go to maxInt(u32), not overflow
    try std.testing.expectEqual(std.math.maxInt(u32), cb.failure_count);

    // One more failure — should saturate at maxInt, not wrap to 0
    cb.recordFailure();
    try std.testing.expectEqual(std.math.maxInt(u32), cb.failure_count);

    // Another to be sure
    cb.recordFailure();
    try std.testing.expectEqual(std.math.maxInt(u32), cb.failure_count);
}
