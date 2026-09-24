//! Detect repeated identical tool calls within a turn and veto runaway loops.

const std = @import("std");

pub const LoopGuardConfig = struct {
    warn_at: u32 = 3,
    veto_at: u32 = 5,
    force_reply_after_vetoes: u32 = 3,
};

pub const LoopGuardAction = enum {
    ok,
    warn,
    veto,
    force_reply,
};

pub const LoopGuard = struct {
    config: LoopGuardConfig,
    counts: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    consecutive_vetoes: u32 = 0,
    last_fingerprint: ?u64 = null,

    pub fn init(config: LoopGuardConfig) LoopGuard {
        return .{ .config = config };
    }

    pub fn deinit(self: *LoopGuard, allocator: std.mem.Allocator) void {
        self.counts.deinit(allocator);
    }

    pub fn reset(self: *LoopGuard) void {
        self.counts.clearRetainingCapacity();
        self.consecutive_vetoes = 0;
        self.last_fingerprint = null;
    }

    pub fn record(self: *LoopGuard, allocator: std.mem.Allocator, name: []const u8, args_json: []const u8) !LoopGuardAction {
        const fingerprint = fingerprintToolCall(name, args_json);
        if (self.last_fingerprint) |prev| {
            if (prev != fingerprint) self.consecutive_vetoes = 0;
        }
        self.last_fingerprint = fingerprint;

        const gop = try self.counts.getOrPut(allocator, fingerprint);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* +|= 1;
        const count = gop.value_ptr.*;

        if (count >= self.config.veto_at) {
            self.consecutive_vetoes +|= 1;
            if (self.consecutive_vetoes >= self.config.force_reply_after_vetoes) {
                return .force_reply;
            }
            return .veto;
        }
        if (count >= self.config.warn_at) return .warn;
        return .ok;
    }
};

pub fn fingerprintToolCall(name: []const u8, args_json: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(name);
    hasher.update("\x00");
    hasher.update(args_json);
    return hasher.final();
}

test "loop guard warns on third identical call" {
    var guard = LoopGuard.init(.{});
    defer guard.deinit(std.testing.allocator);

    try std.testing.expectEqual(LoopGuardAction.ok, try guard.record(std.testing.allocator, "file_read", "{\"path\":\"a\"}"));
    try std.testing.expectEqual(LoopGuardAction.ok, try guard.record(std.testing.allocator, "file_read", "{\"path\":\"a\"}"));
    try std.testing.expectEqual(LoopGuardAction.warn, try guard.record(std.testing.allocator, "file_read", "{\"path\":\"a\"}"));
}

test "loop guard vetoes on fifth identical call" {
    var guard = LoopGuard.init(.{});
    defer guard.deinit(std.testing.allocator);

    _ = try guard.record(std.testing.allocator, "web_search", "{\"query\":\"x\"}");
    _ = try guard.record(std.testing.allocator, "web_search", "{\"query\":\"x\"}");
    _ = try guard.record(std.testing.allocator, "web_search", "{\"query\":\"x\"}");
    _ = try guard.record(std.testing.allocator, "web_search", "{\"query\":\"x\"}");
    try std.testing.expectEqual(LoopGuardAction.veto, try guard.record(std.testing.allocator, "web_search", "{\"query\":\"x\"}"));
}

test "loop guard force reply after three consecutive vetoes" {
    var guard = LoopGuard.init(.{ .warn_at = 1, .veto_at = 2, .force_reply_after_vetoes = 3 });
    defer guard.deinit(std.testing.allocator);

    _ = try guard.record(std.testing.allocator, "shell", "{\"command\":\"ls\"}");
    _ = try guard.record(std.testing.allocator, "shell", "{\"command\":\"ls\"}"); // veto #1
    _ = try guard.record(std.testing.allocator, "shell", "{\"command\":\"ls\"}"); // veto #2
    const action = try guard.record(std.testing.allocator, "shell", "{\"command\":\"ls\"}"); // veto #3 -> force_reply
    try std.testing.expectEqual(LoopGuardAction.force_reply, action);
}

test "loop guard resets consecutive vetoes when fingerprint changes before veto threshold" {
    var guard = LoopGuard.init(.{ .warn_at = 2, .veto_at = 5 });
    defer guard.deinit(std.testing.allocator);

    _ = try guard.record(std.testing.allocator, "file_read", "{\"path\":\"a\"}");
    _ = try guard.record(std.testing.allocator, "file_read", "{\"path\":\"b\"}");
    try std.testing.expectEqual(@as(u32, 0), guard.consecutive_vetoes);
}
