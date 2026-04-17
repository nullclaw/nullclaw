//! State Manager — persistent runtime state across daemon restarts.
//!
//! Stores last active channel/chat so heartbeat, cron, and other
//! components know where to route messages.
//! Persisted to `~/.nullclaw/state.json` with atomic writes (temp + rename).

const std = @import("std");
const std_compat = @import("compat");
const json_util = @import("json_util.zig");
const Allocator = std.mem.Allocator;
const thread_stacks = @import("thread_stacks.zig");

/// Runtime state persisted to disk.
pub const State = struct {
    last_channel: ?[]const u8 = null,
    last_chat_id: ?[]const u8 = null,
    updated_at: i64 = 0,

    pub fn deinit(self: *State, allocator: Allocator) void {
        if (self.last_channel) |ch| allocator.free(ch);
        if (self.last_chat_id) |cid| allocator.free(cid);
        self.* = .{};
    }
};

/// Thread-safe state manager with file persistence.
pub const StateManager = struct {
    allocator: Allocator,
    state_path: []const u8, // owned
    mutex: std_compat.sync.Mutex = .{},
    state: State = .{},

    pub fn init(allocator: Allocator, state_path: []const u8) Allocator.Error!StateManager {
        return .{
            .allocator = allocator,
            .state_path = try allocator.dupe(u8, state_path),
        };
    }

    pub fn deinit(self: *StateManager) void {
        self.state.deinit(self.allocator);
        self.allocator.free(self.state_path);
    }

    /// Set the last active channel and chat_id. Thread-safe.
    pub fn setLastChannel(self: *StateManager, channel: []const u8, chat_id: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Free old values
        if (self.state.last_channel) |old| self.allocator.free(old);
        if (self.state.last_chat_id) |old| self.allocator.free(old);

        self.state.last_channel = self.allocator.dupe(u8, channel) catch null;
        self.state.last_chat_id = self.allocator.dupe(u8, chat_id) catch null;
        self.state.updated_at = std_compat.time.timestamp();
    }

    /// Get the last active channel. Returns null if not set.
    /// Caller does NOT own the returned slices (valid until next setLastChannel).
    pub fn getLastChannel(self: *StateManager) struct { channel: ?[]const u8, chat_id: ?[]const u8 } {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{
            .channel = self.state.last_channel,
            .chat_id = self.state.last_chat_id,
        };
    }

    /// Get updated_at timestamp.
    pub fn getUpdatedAt(self: *StateManager) i64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.state.updated_at;
    }

    /// Save state to disk. Atomic: write to temp file then rename.
    pub fn save(self: *StateManager) !void {
        self.mutex.lock();
        const channel = if (self.state.last_channel) |ch| self.allocator.dupe(u8, ch) catch null else null;
        const chat_id = if (self.state.last_chat_id) |cid| self.allocator.dupe(u8, cid) catch null else null;
        const updated = self.state.updated_at;
        self.mutex.unlock();

        defer if (channel) |ch| self.allocator.free(ch);
        defer if (chat_id) |cid| self.allocator.free(cid);

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "{\n");
        if (channel) |ch| {
            try buf.appendSlice(self.allocator, "  \"last_channel\": ");
            try json_util.appendJsonString(&buf, self.allocator, ch);
            try buf.appendSlice(self.allocator, ",\n");
        } else {
            try buf.appendSlice(self.allocator, "  \"last_channel\": null,\n");
        }
        if (chat_id) |cid| {
            try buf.appendSlice(self.allocator, "  \"last_chat_id\": ");
            try json_util.appendJsonString(&buf, self.allocator, cid);
            try buf.appendSlice(self.allocator, ",\n");
        } else {
            try buf.appendSlice(self.allocator, "  \"last_chat_id\": null,\n");
        }
        var buf_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &buf);
        try buf_writer.writer.print("  \"updated_at\": {d}\n", .{updated});
        try buf_writer.writer.print("}}\n", .{});
        buf = buf_writer.toArrayList();

        // Atomic write: temp file + rename
        const tmp_path = try std.fmt.allocPrint(self.allocator, "{s}.tmp", .{self.state_path});
        defer self.allocator.free(tmp_path);

        const tmp_file = try std_compat.fs.createFileAbsolute(tmp_path, .{});
        try tmp_file.writeAll(buf.items);
        tmp_file.close();

        std_compat.fs.renameAbsolute(tmp_path, self.state_path) catch {
            // If rename fails (cross-device), fall back to direct write
            std_compat.fs.deleteFileAbsolute(tmp_path) catch {};
            const file = try std_compat.fs.createFileAbsolute(self.state_path, .{});
            try file.writeAll(buf.items);
            file.close();
        };
    }

    /// Load state from disk. Overwrites current in-memory state.
    pub fn load(self: *StateManager) !void {
        const file = std_compat.fs.openFileAbsolute(self.state_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return, // No state file — fresh start
            else => return err,
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 64 * 1024);
        defer self.allocator.free(content);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, content, .{}) catch return;
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => return,
        };

        self.mutex.lock();
        defer self.mutex.unlock();

        // Free old values
        if (self.state.last_channel) |old| self.allocator.free(old);
        if (self.state.last_chat_id) |old| self.allocator.free(old);

        self.state.last_channel = if (obj.get("last_channel")) |v| switch (v) {
            .string => |s| self.allocator.dupe(u8, s) catch null,
            else => null,
        } else null;

        self.state.last_chat_id = if (obj.get("last_chat_id")) |v| switch (v) {
            .string => |s| self.allocator.dupe(u8, s) catch null,
            else => null,
        } else null;

        self.state.updated_at = if (obj.get("updated_at")) |v| switch (v) {
            .integer => |i| i,
            else => 0,
        } else 0;
    }
};

/// Derive the default state file path from workspace dir.
pub fn defaultStatePath(allocator: Allocator, workspace_dir: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/state.json", .{workspace_dir});
}

// ══════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════

const testing = std.testing;

test "State init defaults to null" {
    var s = State{};
    defer s.deinit(testing.allocator);
    try testing.expect(s.last_channel == null);
    try testing.expect(s.last_chat_id == null);
    try testing.expectEqual(@as(i64, 0), s.updated_at);
}

test "StateManager init and deinit — no leaks" {
    var mgr = try StateManager.init(testing.allocator, "/tmp/test-state.json");
    mgr.deinit();
}

test "StateManager setLastChannel and getLastChannel" {
    var mgr = try StateManager.init(testing.allocator, "/tmp/test-state.json");
    defer mgr.deinit();

    const before = mgr.getLastChannel();
    try testing.expect(before.channel == null);
    try testing.expect(before.chat_id == null);

    mgr.setLastChannel("telegram", "chat_42");
    const after = mgr.getLastChannel();
    try testing.expectEqualStrings("telegram", after.channel.?);
    try testing.expectEqualStrings("chat_42", after.chat_id.?);
}

test "StateManager setLastChannel overwrites previous" {
    var mgr = try StateManager.init(testing.allocator, "/tmp/test-state.json");
    defer mgr.deinit();

    mgr.setLastChannel("telegram", "c1");
    mgr.setLastChannel("discord", "c2");

    const last = mgr.getLastChannel();
    try testing.expectEqualStrings("discord", last.channel.?);
    try testing.expectEqualStrings("c2", last.chat_id.?);
}

test "StateManager updated_at is set" {
    var mgr = try StateManager.init(testing.allocator, "/tmp/test-state.json");
    defer mgr.deinit();

    try testing.expectEqual(@as(i64, 0), mgr.getUpdatedAt());
    mgr.setLastChannel("slack", "room1");
    try testing.expect(mgr.getUpdatedAt() > 0);
}

test "StateManager save and load roundtrip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir);
    const path = try std_compat.fs.path.join(testing.allocator, &.{ dir, "state.json" });
    defer testing.allocator.free(path);

    // Save
    {
        var mgr = try StateManager.init(testing.allocator, path);
        defer mgr.deinit();
        mgr.setLastChannel("telegram", "chat_99");
        try mgr.save();
    }

    // Load into fresh manager
    {
        var mgr = try StateManager.init(testing.allocator, path);
        defer mgr.deinit();
        try mgr.load();
        const last = mgr.getLastChannel();
        try testing.expectEqualStrings("telegram", last.channel.?);
        try testing.expectEqualStrings("chat_99", last.chat_id.?);
        try testing.expect(mgr.getUpdatedAt() > 0);
    }
}

test "StateManager load missing file is ok" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir);
    const path = try std_compat.fs.path.join(testing.allocator, &.{ dir, "nonexistent.json" });
    defer testing.allocator.free(path);

    var mgr = try StateManager.init(testing.allocator, path);
    defer mgr.deinit();
    try mgr.load(); // should not error
    try testing.expect(mgr.getLastChannel().channel == null);
}

test "StateManager save with null values" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir);
    const path = try std_compat.fs.path.join(testing.allocator, &.{ dir, "state-null.json" });
    defer testing.allocator.free(path);

    {
        var mgr = try StateManager.init(testing.allocator, path);
        defer mgr.deinit();
        // Don't set anything — save with nulls
        try mgr.save();
    }

    {
        var mgr = try StateManager.init(testing.allocator, path);
        defer mgr.deinit();
        try mgr.load();
        try testing.expect(mgr.getLastChannel().channel == null);
        try testing.expect(mgr.getLastChannel().chat_id == null);
    }
}

test "StateManager save overwrites previous file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir);
    const path = try std_compat.fs.path.join(testing.allocator, &.{ dir, "state-overwrite.json" });
    defer testing.allocator.free(path);

    var mgr = try StateManager.init(testing.allocator, path);
    defer mgr.deinit();

    mgr.setLastChannel("telegram", "c1");
    try mgr.save();
    mgr.setLastChannel("discord", "c2");
    try mgr.save();

    // Reload — should have latest
    var mgr2 = try StateManager.init(testing.allocator, path);
    defer mgr2.deinit();
    try mgr2.load();
    try testing.expectEqualStrings("discord", mgr2.getLastChannel().channel.?);
    try testing.expectEqualStrings("c2", mgr2.getLastChannel().chat_id.?);
}

test "StateManager handles special chars in values" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir);
    const path = try std_compat.fs.path.join(testing.allocator, &.{ dir, "state-special.json" });
    defer testing.allocator.free(path);

    {
        var mgr = try StateManager.init(testing.allocator, path);
        defer mgr.deinit();
        mgr.setLastChannel("tele\"gram", "chat\n42");
        try mgr.save();
    }
    {
        var mgr = try StateManager.init(testing.allocator, path);
        defer mgr.deinit();
        try mgr.load();
        try testing.expectEqualStrings("tele\"gram", mgr.getLastChannel().channel.?);
        try testing.expectEqualStrings("chat\n42", mgr.getLastChannel().chat_id.?);
    }
}

test "StateManager concurrent setLastChannel" {
    var mgr = try StateManager.init(testing.allocator, "/tmp/test-state-concurrent.json");
    defer mgr.deinit();

    const num_threads = 4;
    var threads: [num_threads]std.Thread = undefined;
    for (0..num_threads) |i| {
        threads[i] = try std.Thread.spawn(.{ .stack_size = thread_stacks.COORDINATION_STACK_SIZE }, struct {
            fn run(m: *StateManager, tid: usize) void {
                for (0..50) |_| {
                    var ch_buf: [16]u8 = undefined;
                    const ch = std.fmt.bufPrint(&ch_buf, "ch{d}", .{tid}) catch "?";
                    m.setLastChannel(ch, "x");
                }
            }
        }.run, .{ &mgr, i });
    }
    for (&threads) |*t| t.join();

    // No crash, last_channel is set to something
    try testing.expect(mgr.getLastChannel().channel != null);
}

test "defaultStatePath" {
    const path = try defaultStatePath(testing.allocator, "/home/user/.nullclaw");
    defer testing.allocator.free(path);
    try testing.expectEqualStrings("/home/user/.nullclaw/state.json", path);
}
