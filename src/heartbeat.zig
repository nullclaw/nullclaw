const std = @import("std");
const observability = @import("observability.zig");

pub const TickOutcome = enum {
    processed,
    skipped_empty_file,
    skipped_missing_file,
};

pub const TickResult = struct {
    outcome: TickOutcome,
    task_count: usize = 0,
};

/// Heartbeat engine — reads HEARTBEAT.md and processes periodic tasks.
pub const HeartbeatEngine = struct {
    enabled: bool,
    interval_minutes: u32,
    workspace_dir: []const u8,
    observer: ?observability.Observer,

    pub fn init(enabled: bool, interval_minutes: u32, workspace_dir: []const u8, observer: ?observability.Observer) HeartbeatEngine {
        return .{
            .enabled = enabled,
            .interval_minutes = if (interval_minutes < 5) 5 else interval_minutes,
            .workspace_dir = workspace_dir,
            .observer = observer,
        };
    }

    /// Parse tasks from HEARTBEAT.md content (lines starting with `- `).
    pub fn parseTasks(allocator: std.mem.Allocator, content: []const u8) ![][]const u8 {
        var list: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (list.items) |task| allocator.free(task);
            list.deinit(allocator);
        }

        var iter = std.mem.splitScalar(u8, content, '\n');
        while (iter.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (std.mem.startsWith(u8, trimmed, "- ")) {
                const task = std.mem.trimLeft(u8, trimmed[2..], " \t");
                if (task.len > 0) {
                    try list.append(allocator, try allocator.dupe(u8, task));
                }
            }
        }

        return list.toOwnedSlice(allocator);
    }

    /// Collect tasks from the HEARTBEAT.md file in the workspace.
    pub fn collectTasks(self: *const HeartbeatEngine, allocator: std.mem.Allocator) ![][]const u8 {
        const heartbeat_path = try std.fs.path.join(allocator, &.{ self.workspace_dir, "HEARTBEAT.md" });
        defer allocator.free(heartbeat_path);

        const file = std.fs.openFileAbsolute(heartbeat_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return &.{},
            else => return err,
        };
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 64);
        defer allocator.free(content);

        if (isContentEffectivelyEmpty(content)) return &.{};
        return parseTasks(allocator, content);
    }

    pub fn freeTasks(allocator: std.mem.Allocator, tasks: []const []const u8) void {
        for (tasks) |task| allocator.free(task);
        if (tasks.len > 0) allocator.free(tasks);
    }

    /// OpenClaw parity rule: comment/header-only HEARTBEAT.md means "skip heartbeat run".
    pub fn isContentEffectivelyEmpty(content: []const u8) bool {
        var iter = std.mem.splitScalar(u8, content, '\n');
        while (iter.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;
            if (isMarkdownHeader(trimmed)) continue;
            if (isEmptyMarkdownBullet(trimmed)) continue;
            return false;
        }
        return true;
    }

    /// Perform a single heartbeat tick.
    pub fn tick(self: *const HeartbeatEngine, allocator: std.mem.Allocator) !TickResult {
        const heartbeat_path = try std.fs.path.join(allocator, &.{ self.workspace_dir, "HEARTBEAT.md" });
        defer allocator.free(heartbeat_path);

        const file = std.fs.openFileAbsolute(heartbeat_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return .{ .outcome = .skipped_missing_file, .task_count = 0 },
            else => return err,
        };
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 64);
        defer allocator.free(content);
        if (isContentEffectivelyEmpty(content)) {
            return .{ .outcome = .skipped_empty_file, .task_count = 0 };
        }

        const tasks = try self.collectTasks(allocator);
        defer freeTasks(allocator, tasks);

        return .{ .outcome = .processed, .task_count = tasks.len };
    }

    /// Create a default HEARTBEAT.md if it doesn't exist.
    pub fn ensureHeartbeatFile(workspace_dir: []const u8, allocator: std.mem.Allocator) !void {
        const path = try std.fs.path.join(allocator, &.{ workspace_dir, "HEARTBEAT.md" });
        defer allocator.free(path);

        // Try to open to check existence
        if (std.fs.openFileAbsolute(path, .{})) |file| {
            file.close();
            return; // Already exists
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }

        const default_content =
            \\# Periodic Tasks
            \\
            \\# Add tasks below (one per line, starting with `- `)
            \\# The agent will check this file on each heartbeat tick.
            \\#
            \\# Examples:
            \\# - Check my email for important messages
            \\# - Review my calendar for upcoming events
            \\# - Check the weather forecast
        ;

        const file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();
        try file.writeAll(default_content);
    }
};

fn isMarkdownBulletPrefix(ch: u8) bool {
    return ch == '-' or ch == '*' or ch == '+';
}

fn isMarkdownHeader(line: []const u8) bool {
    var idx: usize = 0;
    while (idx < line.len and line[idx] == '#') : (idx += 1) {}
    if (idx == 0) return false;
    if (idx == line.len) return true;
    return std.ascii.isWhitespace(line[idx]);
}

fn isEmptyMarkdownBullet(line: []const u8) bool {
    if (line.len == 0 or !isMarkdownBulletPrefix(line[0])) return false;

    const rest = std.mem.trimLeft(u8, line[1..], " \t");
    if (rest.len == 0) return true;

    if (std.mem.startsWith(u8, rest, "[ ]") or
        std.mem.startsWith(u8, rest, "[x]") or
        std.mem.startsWith(u8, rest, "[X]"))
    {
        const after_checkbox = std.mem.trimLeft(u8, rest[3..], " \t");
        return after_checkbox.len == 0;
    }

    return false;
}

// ── Tests ────────────────────────────────────────────────────────────

test "parseTasks basic" {
    const allocator = std.testing.allocator;
    const content = "# Tasks\n\n- Check email\n- Review calendar\nNot a task\n- Third task";
    const tasks = try HeartbeatEngine.parseTasks(allocator, content);
    defer HeartbeatEngine.freeTasks(allocator, tasks);
    try std.testing.expectEqual(@as(usize, 3), tasks.len);
    try std.testing.expectEqualStrings("Check email", tasks[0]);
    try std.testing.expectEqualStrings("Review calendar", tasks[1]);
    try std.testing.expectEqualStrings("Third task", tasks[2]);
}

test "parseTasks empty content" {
    const allocator = std.testing.allocator;
    const tasks = try HeartbeatEngine.parseTasks(allocator, "");
    defer HeartbeatEngine.freeTasks(allocator, tasks);
    try std.testing.expectEqual(@as(usize, 0), tasks.len);
}

test "parseTasks only comments" {
    const allocator = std.testing.allocator;
    const tasks = try HeartbeatEngine.parseTasks(allocator, "# No tasks here\n\nJust comments\n# Another");
    defer HeartbeatEngine.freeTasks(allocator, tasks);
    try std.testing.expectEqual(@as(usize, 0), tasks.len);
}

test "parseTasks with leading whitespace" {
    const allocator = std.testing.allocator;
    const content = "  - Indented task\n\t- Tab indented";
    const tasks = try HeartbeatEngine.parseTasks(allocator, content);
    defer HeartbeatEngine.freeTasks(allocator, tasks);
    try std.testing.expectEqual(@as(usize, 2), tasks.len);
    try std.testing.expectEqualStrings("Indented task", tasks[0]);
    try std.testing.expectEqualStrings("Tab indented", tasks[1]);
}

test "parseTasks dash without space ignored" {
    const allocator = std.testing.allocator;
    const content = "- Real task\n-\n- Another";
    const tasks = try HeartbeatEngine.parseTasks(allocator, content);
    defer HeartbeatEngine.freeTasks(allocator, tasks);
    try std.testing.expectEqual(@as(usize, 2), tasks.len);
    try std.testing.expectEqualStrings("Real task", tasks[0]);
    try std.testing.expectEqualStrings("Another", tasks[1]);
}

test "parseTasks trailing space bullet skipped" {
    const allocator = std.testing.allocator;
    const content = "- ";
    const tasks = try HeartbeatEngine.parseTasks(allocator, content);
    defer HeartbeatEngine.freeTasks(allocator, tasks);
    try std.testing.expectEqual(@as(usize, 0), tasks.len);
}

test "parseTasks unicode" {
    const allocator = std.testing.allocator;
    const content = "- Check email \xf0\x9f\x93\xa7\n- Review calendar \xf0\x9f\x93\x85";
    const tasks = try HeartbeatEngine.parseTasks(allocator, content);
    defer HeartbeatEngine.freeTasks(allocator, tasks);
    try std.testing.expectEqual(@as(usize, 2), tasks.len);
}

test "parseTasks single task" {
    const allocator = std.testing.allocator;
    const tasks = try HeartbeatEngine.parseTasks(allocator, "- Only one");
    defer HeartbeatEngine.freeTasks(allocator, tasks);
    try std.testing.expectEqual(@as(usize, 1), tasks.len);
    try std.testing.expectEqualStrings("Only one", tasks[0]);
}

test "parseTasks mixed markdown" {
    const allocator = std.testing.allocator;
    const content = "# Periodic Tasks\n\n## Quick\n- Task A\n\n## Long\n- Task B\n\n* Not a dash bullet\n1. Not numbered";
    const tasks = try HeartbeatEngine.parseTasks(allocator, content);
    defer HeartbeatEngine.freeTasks(allocator, tasks);
    try std.testing.expectEqual(@as(usize, 2), tasks.len);
    try std.testing.expectEqualStrings("Task A", tasks[0]);
    try std.testing.expectEqualStrings("Task B", tasks[1]);
}

test "HeartbeatEngine init clamps interval" {
    const engine = HeartbeatEngine.init(true, 2, "/tmp", null);
    try std.testing.expectEqual(@as(u32, 5), engine.interval_minutes);
}

test "HeartbeatEngine init preserves valid interval" {
    const engine = HeartbeatEngine.init(true, 30, "/tmp", null);
    try std.testing.expectEqual(@as(u32, 30), engine.interval_minutes);
}

test "isContentEffectivelyEmpty mirrors OpenClaw file gating semantics" {
    try std.testing.expect(HeartbeatEngine.isContentEffectivelyEmpty(""));
    try std.testing.expect(HeartbeatEngine.isContentEffectivelyEmpty("# HEARTBEAT.md\n\n# comment"));
    try std.testing.expect(HeartbeatEngine.isContentEffectivelyEmpty("## Tasks\n- [ ]\n+ [x]\n* [X]"));
    try std.testing.expect(!HeartbeatEngine.isContentEffectivelyEmpty("Check status"));
    try std.testing.expect(!HeartbeatEngine.isContentEffectivelyEmpty("#TODO keep this"));
}
