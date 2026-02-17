const std = @import("std");
const root = @import("root.zig");

/// CLI channel — reads from stdin, writes to stdout.
/// Simplest channel implementation; used for local interactive testing.
pub const CliChannel = struct {
    allocator: std.mem.Allocator,
    running: bool,

    pub fn init(allocator: std.mem.Allocator) CliChannel {
        return .{ .allocator = allocator, .running = false };
    }

    pub fn channelName(_: *CliChannel) []const u8 {
        return "cli";
    }

    pub fn sendMessage(_: *CliChannel, _: []const u8, message: []const u8) !void {
        var out_buf: [4096]u8 = undefined;
        var bw = std.fs.File.stdout().writer(&out_buf);
        const w = &bw.interface;
        try w.print("{s}\n", .{message});
        try w.flush();
    }

    pub fn readLine(_: *CliChannel, buf: []u8) !?[]const u8 {
        const stdin = std.fs.File.stdin();
        var pos: usize = 0;
        while (pos < buf.len) {
            const n = stdin.read(buf[pos .. pos + 1]) catch return null;
            if (n == 0) return null; // EOF
            if (buf[pos] == '\n') break;
            pos += 1;
        }
        return buf[0..pos];
    }

    pub fn isQuitCommand(line: []const u8) bool {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        return std.mem.eql(u8, trimmed, "exit") or
            std.mem.eql(u8, trimmed, "quit") or
            std.mem.eql(u8, trimmed, "/quit") or
            std.mem.eql(u8, trimmed, "/exit");
    }

    pub fn healthCheck(_: *CliChannel) bool {
        return true; // CLI is always available
    }

    // ── Channel vtable ──────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *CliChannel = @ptrCast(@alignCast(ptr));
        self.running = true;
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *CliChannel = @ptrCast(@alignCast(ptr));
        self.running = false;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8) anyerror!void {
        const self: *CliChannel = @ptrCast(@alignCast(ptr));
        return self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *CliChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *CliChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *CliChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "cli channel name" {
    var ch = CliChannel.init(std.testing.allocator);
    try std.testing.expectEqualStrings("cli", ch.channelName());
}

test "cli health check always true" {
    var ch = CliChannel.init(std.testing.allocator);
    try std.testing.expect(ch.healthCheck());
}

test "cli quit commands" {
    try std.testing.expect(CliChannel.isQuitCommand("exit"));
    try std.testing.expect(CliChannel.isQuitCommand("quit"));
    try std.testing.expect(CliChannel.isQuitCommand("/quit"));
    try std.testing.expect(CliChannel.isQuitCommand("/exit"));
    try std.testing.expect(CliChannel.isQuitCommand("  exit  "));
    try std.testing.expect(!CliChannel.isQuitCommand("hello"));
    try std.testing.expect(!CliChannel.isQuitCommand(""));
}

test "cli vtable channel interface" {
    var ch = CliChannel.init(std.testing.allocator);
    const iface = ch.channel();
    try std.testing.expectEqualStrings("cli", iface.name());
    try std.testing.expect(iface.healthCheck());
}
