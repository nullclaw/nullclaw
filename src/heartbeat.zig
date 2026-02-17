const std = @import("std");
const observability = @import("observability.zig");

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

        var iter = std.mem.splitScalar(u8, content, '\n');
        while (iter.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (std.mem.startsWith(u8, trimmed, "- ")) {
                const task = trimmed[2..];
                if (task.len > 0) {
                    try list.append(allocator, task);
                }
            }
        }

        return list.items;
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

        return parseTasks(allocator, content);
    }

    /// Perform a single heartbeat tick.
    pub fn tick(self: *const HeartbeatEngine, allocator: std.mem.Allocator) !usize {
        const tasks = try self.collectTasks(allocator);
        return tasks.len;
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

// ── Tests ────────────────────────────────────────────────────────────

test "parseTasks basic" {
    const content = "# Tasks\n\n- Check email\n- Review calendar\nNot a task\n- Third task";
    const tasks = try HeartbeatEngine.parseTasks(std.heap.page_allocator, content);
    try std.testing.expectEqual(@as(usize, 3), tasks.len);
    try std.testing.expectEqualStrings("Check email", tasks[0]);
    try std.testing.expectEqualStrings("Review calendar", tasks[1]);
    try std.testing.expectEqualStrings("Third task", tasks[2]);
}

test "parseTasks empty content" {
    const tasks = try HeartbeatEngine.parseTasks(std.heap.page_allocator, "");
    try std.testing.expectEqual(@as(usize, 0), tasks.len);
}

test "parseTasks only comments" {
    const tasks = try HeartbeatEngine.parseTasks(std.heap.page_allocator, "# No tasks here\n\nJust comments\n# Another");
    try std.testing.expectEqual(@as(usize, 0), tasks.len);
}

test "parseTasks with leading whitespace" {
    const content = "  - Indented task\n\t- Tab indented";
    const tasks = try HeartbeatEngine.parseTasks(std.heap.page_allocator, content);
    try std.testing.expectEqual(@as(usize, 2), tasks.len);
    try std.testing.expectEqualStrings("Indented task", tasks[0]);
    try std.testing.expectEqualStrings("Tab indented", tasks[1]);
}

test "parseTasks dash without space ignored" {
    const content = "- Real task\n-\n- Another";
    const tasks = try HeartbeatEngine.parseTasks(std.heap.page_allocator, content);
    try std.testing.expectEqual(@as(usize, 2), tasks.len);
    try std.testing.expectEqualStrings("Real task", tasks[0]);
    try std.testing.expectEqualStrings("Another", tasks[1]);
}

test "parseTasks trailing space bullet skipped" {
    const content = "- ";
    const tasks = try HeartbeatEngine.parseTasks(std.heap.page_allocator, content);
    try std.testing.expectEqual(@as(usize, 0), tasks.len);
}

test "parseTasks unicode" {
    const content = "- Check email \xf0\x9f\x93\xa7\n- Review calendar \xf0\x9f\x93\x85";
    const tasks = try HeartbeatEngine.parseTasks(std.heap.page_allocator, content);
    try std.testing.expectEqual(@as(usize, 2), tasks.len);
}

test "parseTasks single task" {
    const tasks = try HeartbeatEngine.parseTasks(std.heap.page_allocator, "- Only one");
    try std.testing.expectEqual(@as(usize, 1), tasks.len);
    try std.testing.expectEqualStrings("Only one", tasks[0]);
}

test "parseTasks mixed markdown" {
    const content = "# Periodic Tasks\n\n## Quick\n- Task A\n\n## Long\n- Task B\n\n* Not a dash bullet\n1. Not numbered";
    const tasks = try HeartbeatEngine.parseTasks(std.heap.page_allocator, content);
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
