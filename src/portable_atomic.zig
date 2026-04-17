//! Platform-portable atomic value.
//!
//! On targets where the requested integer width fits the native word size,
//! this is a zero-cost alias for `std.atomic.Value(T)`.
//!
//! On 32-bit targets (e.g. ARM32) where `T` exceeds the native word width,
//! falls back to a mutex-protected wrapper with an API-compatible surface
//! (init / load / store / fetchAdd).

const std = @import("std");
const std_compat = @import("compat");

pub fn Atomic(comptime T: type) type {
    if (@bitSizeOf(T) <= @bitSizeOf(usize)) {
        return std.atomic.Value(T);
    }
    return MutexAtomic(T);
}

fn MutexAtomic(comptime T: type) type {
    return struct {
        raw: T,
        _mutex: std_compat.sync.Mutex = .{},

        const Self = @This();

        pub fn init(value: T) Self {
            return .{ .raw = value };
        }

        pub fn load(self: *const Self, comptime _: std.builtin.AtomicOrder) T {
            const m = &@constCast(self)._mutex;
            m.lock();
            defer m.unlock();
            return self.raw;
        }

        pub fn store(self: *Self, value: T, comptime _: std.builtin.AtomicOrder) void {
            self._mutex.lock();
            defer self._mutex.unlock();
            self.raw = value;
        }

        pub fn fetchAdd(self: *Self, operand: T, comptime _: std.builtin.AtomicOrder) T {
            self._mutex.lock();
            defer self._mutex.unlock();
            const old = self.raw;
            self.raw +%= operand;
            return old;
        }

        pub fn swap(self: *Self, value: T, comptime _: std.builtin.AtomicOrder) T {
            self._mutex.lock();
            defer self._mutex.unlock();
            const old = self.raw;
            self.raw = value;
            return old;
        }
    };
}

// ── Tests ───────────────────────────────────────────────────────────

test "Atomic i64 init load store" {
    var a = Atomic(i64).init(42);
    try std.testing.expectEqual(@as(i64, 42), a.load(.acquire));
    a.store(99, .release);
    try std.testing.expectEqual(@as(i64, 99), a.load(.acquire));
}

test "Atomic u64 fetchAdd" {
    var a = Atomic(u64).init(0);
    const old = a.fetchAdd(5, .monotonic);
    try std.testing.expectEqual(@as(u64, 0), old);
    try std.testing.expectEqual(@as(u64, 5), a.load(.monotonic));
}

test "Atomic bool passthrough" {
    // bool fits in usize, so this must be std.atomic.Value(bool)
    var a = Atomic(bool).init(false);
    try std.testing.expect(!a.load(.acquire));
    a.store(true, .release);
    try std.testing.expect(a.load(.acquire));
}
