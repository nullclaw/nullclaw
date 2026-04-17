const std = @import("std");
const std_compat = @import("compat");
const bus = @import("bus.zig");

pub const FLUSH_POLL_MS: u32 = 100;

const PendingEntry = struct {
    msg: bus.InboundMessage,
    flush_at_ms: i64,
};

pub const InboundDebouncer = struct {
    allocator: std.mem.Allocator,
    debounce_ms: u32,
    pending: std.ArrayListUnmanaged(PendingEntry) = .empty,

    pub fn init(allocator: std.mem.Allocator, debounce_ms: u32) InboundDebouncer {
        return .{
            .allocator = allocator,
            .debounce_ms = debounce_ms,
        };
    }

    pub fn deinit(self: *InboundDebouncer) void {
        for (self.pending.items) |entry| {
            entry.msg.deinit(self.allocator);
        }
        self.pending.deinit(self.allocator);
    }

    pub fn enabled(self: *const InboundDebouncer) bool {
        return self.debounce_ms > 0;
    }

    pub fn nextPollTimeoutMs(self: *const InboundDebouncer, now_ms: i64) u32 {
        if (!self.enabled() or self.pending.items.len == 0) return FLUSH_POLL_MS;

        var min_deadline = self.pending.items[0].flush_at_ms;
        for (self.pending.items[1..]) |entry| {
            if (entry.flush_at_ms < min_deadline) min_deadline = entry.flush_at_ms;
        }
        if (min_deadline <= now_ms) return 0;

        const remaining: u64 = @intCast(min_deadline - now_ms);
        if (remaining < FLUSH_POLL_MS) return @intCast(remaining);
        return FLUSH_POLL_MS;
    }

    pub fn push(
        self: *InboundDebouncer,
        msg: bus.InboundMessage,
        now_ms: i64,
        out: *std.ArrayListUnmanaged(bus.InboundMessage),
    ) !void {
        var owned_msg = msg;

        if (!self.enabled() or !isDebounceEligible(owned_msg)) {
            errdefer owned_msg.deinit(self.allocator);

            if (self.findPendingIndex(owned_msg)) |idx| {
                const entry = self.pending.orderedRemove(idx);
                try appendPendingMessage(self.allocator, entry.msg, out);
            }

            try out.append(self.allocator, owned_msg);
            return;
        }

        if (self.findPendingIndex(owned_msg)) |idx| {
            defer owned_msg.deinit(self.allocator);
            try mergeIntoPending(self.allocator, &self.pending.items[idx].msg, owned_msg);
            self.pending.items[idx].flush_at_ms = now_ms + self.debounce_ms;
            return;
        }

        errdefer owned_msg.deinit(self.allocator);
        try self.pending.append(self.allocator, .{
            .msg = owned_msg,
            .flush_at_ms = now_ms + self.debounce_ms,
        });
    }

    pub fn flushMatured(
        self: *InboundDebouncer,
        now_ms: i64,
        out: *std.ArrayListUnmanaged(bus.InboundMessage),
    ) !void {
        var i: usize = 0;
        while (i < self.pending.items.len) {
            if (self.pending.items[i].flush_at_ms > now_ms) {
                i += 1;
                continue;
            }
            const entry = self.pending.orderedRemove(i);
            try appendPendingMessage(self.allocator, entry.msg, out);
        }
    }

    pub fn flushAll(self: *InboundDebouncer, out: *std.ArrayListUnmanaged(bus.InboundMessage)) !void {
        while (self.pending.items.len > 0) {
            const entry = self.pending.orderedRemove(0);
            try appendPendingMessage(self.allocator, entry.msg, out);
        }
    }

    fn findPendingIndex(self: *const InboundDebouncer, msg: bus.InboundMessage) ?usize {
        for (self.pending.items, 0..) |entry, idx| {
            if (std.mem.eql(u8, entry.msg.session_key, msg.session_key) and
                std.mem.eql(u8, entry.msg.sender_id, msg.sender_id))
            {
                return idx;
            }
        }
        return null;
    }
};

pub fn nowMs() i64 {
    return std_compat.time.milliTimestamp();
}

fn isDebounceEligible(msg: bus.InboundMessage) bool {
    if (msg.media.len > 0) return false;
    const trimmed = std.mem.trim(u8, msg.content, " \t\r\n");
    if (trimmed.len == 0) return false;
    if (trimmed[0] == '/') return false;
    return true;
}

fn appendPendingMessage(
    allocator: std.mem.Allocator,
    msg: bus.InboundMessage,
    out: *std.ArrayListUnmanaged(bus.InboundMessage),
) !void {
    var owned_msg = msg;
    errdefer owned_msg.deinit(allocator);
    try out.append(allocator, owned_msg);
}

fn mergeIntoPending(allocator: std.mem.Allocator, pending: *bus.InboundMessage, incoming: bus.InboundMessage) !void {
    var merged: std.ArrayListUnmanaged(u8) = .empty;
    errdefer merged.deinit(allocator);

    try merged.appendSlice(allocator, pending.content);
    if (pending.content.len > 0 and incoming.content.len > 0) {
        try merged.appendSlice(allocator, "\n");
    }
    try merged.appendSlice(allocator, incoming.content);

    const merged_content = try merged.toOwnedSlice(allocator);
    allocator.free(pending.content);
    pending.content = merged_content;
}

test "inbound debouncer merges same sender and session key" {
    const allocator = std.testing.allocator;
    var debouncer = InboundDebouncer.init(allocator, 3000);
    defer debouncer.deinit();

    var out: std.ArrayListUnmanaged(bus.InboundMessage) = .empty;
    defer {
        for (out.items) |msg| msg.deinit(allocator);
        out.deinit(allocator);
    }

    try debouncer.push(try bus.makeInbound(allocator, "discord", "u1", "c1", "hello", "discord:c1"), 1_000, &out);
    try debouncer.push(try bus.makeInbound(allocator, "discord", "u1", "c1", "world", "discord:c1"), 2_000, &out);
    try std.testing.expectEqual(@as(usize, 0), out.items.len);

    try debouncer.flushMatured(5_100, &out);
    try std.testing.expectEqual(@as(usize, 1), out.items.len);
    try std.testing.expectEqualStrings("hello\nworld", out.items[0].content);
}

test "inbound debouncer bypasses slash commands" {
    const allocator = std.testing.allocator;
    var debouncer = InboundDebouncer.init(allocator, 3000);
    defer debouncer.deinit();

    var out: std.ArrayListUnmanaged(bus.InboundMessage) = .empty;
    defer {
        for (out.items) |msg| msg.deinit(allocator);
        out.deinit(allocator);
    }

    try debouncer.push(try bus.makeInbound(allocator, "cli", "user", "chat", "/help", "cli:chat"), 10, &out);
    try std.testing.expectEqual(@as(usize, 1), out.items.len);
    try std.testing.expectEqualStrings("/help", out.items[0].content);
}

test "inbound debouncer flushes same-session text before bypassed command" {
    const allocator = std.testing.allocator;
    var debouncer = InboundDebouncer.init(allocator, 3000);
    defer debouncer.deinit();

    var out: std.ArrayListUnmanaged(bus.InboundMessage) = .empty;
    defer {
        for (out.items) |msg| msg.deinit(allocator);
        out.deinit(allocator);
    }

    try debouncer.push(try bus.makeInbound(allocator, "cli", "user", "chat", "hello", "cli:chat"), 1_000, &out);
    try debouncer.push(try bus.makeInbound(allocator, "cli", "user", "chat", "/help", "cli:chat"), 1_100, &out);

    try std.testing.expectEqual(@as(usize, 2), out.items.len);
    try std.testing.expectEqualStrings("hello", out.items[0].content);
    try std.testing.expectEqualStrings("/help", out.items[1].content);
    try std.testing.expectEqual(@as(usize, 0), debouncer.pending.items.len);
}

fn mergeIntoPendingAllocationTest(allocator: std.mem.Allocator) !void {
    var debouncer = InboundDebouncer.init(allocator, 3000);
    defer debouncer.deinit();

    var out: std.ArrayListUnmanaged(bus.InboundMessage) = .empty;
    defer {
        for (out.items) |msg| msg.deinit(allocator);
        out.deinit(allocator);
    }

    const first = try bus.makeInbound(allocator, "discord", "u1", "c1", "hello", "discord:c1");
    try debouncer.push(first, 1_000, &out);

    const second = try bus.makeInbound(allocator, "discord", "u1", "c1", "world", "discord:c1");
    try debouncer.push(second, 2_000, &out);
}

test "inbound debouncer merge frees allocations on out-of-memory" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        mergeIntoPendingAllocationTest,
        .{},
    );
}

fn flushMaturedAllocationTest(allocator: std.mem.Allocator) !void {
    var debouncer = InboundDebouncer.init(allocator, 3000);
    defer debouncer.deinit();

    var out: std.ArrayListUnmanaged(bus.InboundMessage) = .empty;
    defer {
        for (out.items) |msg| msg.deinit(allocator);
        out.deinit(allocator);
    }

    try debouncer.push(try bus.makeInbound(allocator, "discord", "u1", "c1", "hello", "discord:c1"), 1_000, &out);
    try debouncer.flushMatured(5_000, &out);
}

test "inbound debouncer flushMatured frees allocations on out-of-memory" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        flushMaturedAllocationTest,
        .{},
    );
}

fn flushAllAllocationTest(allocator: std.mem.Allocator) !void {
    var debouncer = InboundDebouncer.init(allocator, 3000);
    defer debouncer.deinit();

    var out: std.ArrayListUnmanaged(bus.InboundMessage) = .empty;
    defer {
        for (out.items) |msg| msg.deinit(allocator);
        out.deinit(allocator);
    }

    try debouncer.push(try bus.makeInbound(allocator, "discord", "u1", "c1", "hello", "discord:c1"), 1_000, &out);
    try debouncer.flushAll(&out);
}

test "inbound debouncer flushAll frees allocations on out-of-memory" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        flushAllAllocationTest,
        .{},
    );
}
