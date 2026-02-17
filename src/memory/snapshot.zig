//! Memory snapshot — export/import core memories as JSON.
//!
//! Mirrors ZeroClaw's snapshot module:
//!   - export_snapshot: dumps all Memory entries to a JSON file
//!   - hydrate_from_snapshot: restores entries from JSON
//!   - should_hydrate: checks if memory is empty but snapshot exists

const std = @import("std");
const root = @import("root.zig");
const Memory = root.Memory;
const MemoryEntry = root.MemoryEntry;
const MemoryCategory = root.MemoryCategory;

/// Default snapshot filename.
pub const SNAPSHOT_FILENAME = "MEMORY_SNAPSHOT.json";

// ── Export ─────────────────────────────────────────────────────────

/// Export all core memories to a JSON snapshot file.
/// Returns the number of entries exported.
pub fn exportSnapshot(allocator: std.mem.Allocator, mem: Memory, workspace_dir: []const u8) !usize {
    // List all core memories
    const entries = try mem.list(allocator, .core);
    defer root.freeEntries(allocator, entries);

    if (entries.len == 0) return 0;

    // Build JSON output
    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(allocator);

    try json_buf.appendSlice(allocator, "[\n");

    for (entries, 0..) |entry, i| {
        if (i > 0) try json_buf.appendSlice(allocator, ",\n");
        try json_buf.appendSlice(allocator, "  {\"key\":\"");
        try appendJsonEscaped(allocator, &json_buf, entry.key);
        try json_buf.appendSlice(allocator, "\",\"content\":\"");
        try appendJsonEscaped(allocator, &json_buf, entry.content);
        try json_buf.appendSlice(allocator, "\",\"category\":\"");
        try appendJsonEscaped(allocator, &json_buf, entry.category.toString());
        try json_buf.appendSlice(allocator, "\",\"timestamp\":\"");
        try appendJsonEscaped(allocator, &json_buf, entry.timestamp);
        try json_buf.appendSlice(allocator, "\"}");
    }

    try json_buf.appendSlice(allocator, "\n]\n");

    // Write to file
    const snapshot_path = try std.fs.path.join(allocator, &.{ workspace_dir, SNAPSHOT_FILENAME });
    defer allocator.free(snapshot_path);

    const file = try std.fs.cwd().createFile(snapshot_path, .{});
    defer file.close();

    try file.writeAll(json_buf.items);

    return entries.len;
}

// ── Hydrate ───────────────────────────────────────────────────────

/// A parsed snapshot entry.
const SnapshotEntry = struct {
    key: []const u8,
    content: []const u8,
    category: []const u8,
};

/// Restore memory entries from a JSON snapshot file.
/// Returns the number of entries hydrated.
pub fn hydrateFromSnapshot(allocator: std.mem.Allocator, mem: Memory, workspace_dir: []const u8) !usize {
    const snapshot_path = try std.fs.path.join(allocator, &.{ workspace_dir, SNAPSHOT_FILENAME });
    defer allocator.free(snapshot_path);

    // Read snapshot file
    const content = std.fs.cwd().readFileAlloc(allocator, snapshot_path, 10 * 1024 * 1024) catch return 0;
    defer allocator.free(content);

    if (content.len == 0) return 0;

    // Parse JSON array
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{}) catch return 0;
    defer parsed.deinit();

    const array = switch (parsed.value) {
        .array => |a| a,
        else => return 0,
    };

    var hydrated: usize = 0;
    for (array.items) |item| {
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };

        const key_val = obj.get("key") orelse continue;
        const content_val = obj.get("content") orelse continue;

        const key = switch (key_val) {
            .string => |s| s,
            else => continue,
        };
        const entry_content = switch (content_val) {
            .string => |s| s,
            else => continue,
        };

        // Determine category
        var category: MemoryCategory = .core;
        if (obj.get("category")) |cat_val| {
            const cat_str = switch (cat_val) {
                .string => |s| s,
                else => "core",
            };
            category = MemoryCategory.fromString(cat_str);
        }

        mem.store(key, entry_content, category) catch continue;
        hydrated += 1;
    }

    return hydrated;
}

// ── Should hydrate ────────────────────────────────────────────────

/// Check if we should auto-hydrate on startup.
/// Returns true if memory is empty but snapshot file exists.
pub fn shouldHydrate(allocator: std.mem.Allocator, mem: ?Memory, workspace_dir: []const u8) bool {
    // Check if memory is empty
    if (mem) |m| {
        const count = m.count() catch 0;
        if (count > 0) return false;
    }

    // Check if snapshot file exists
    const snapshot_path = std.fs.path.join(allocator, &.{ workspace_dir, SNAPSHOT_FILENAME }) catch return false;
    defer allocator.free(snapshot_path);

    std.fs.cwd().access(snapshot_path, .{}) catch return false;
    return true;
}

// ── Helpers ───────────────────────────────────────────────────────

fn appendJsonEscaped(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), s: []const u8) !void {
    for (s) |ch| {
        switch (ch) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            else => {
                if (ch < 0x20) {
                    var hex_buf: [6]u8 = undefined;
                    const hex = std.fmt.bufPrint(&hex_buf, "\\u{x:0>4}", .{ch}) catch continue;
                    try buf.appendSlice(allocator, hex);
                } else {
                    try buf.append(allocator, ch);
                }
            },
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────

test "appendJsonEscaped basic" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    try appendJsonEscaped(std.testing.allocator, &buf, "hello \"world\"");
    try std.testing.expectEqualStrings("hello \\\"world\\\"", buf.items);
}

test "appendJsonEscaped newlines" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    try appendJsonEscaped(std.testing.allocator, &buf, "line1\nline2\r\n");
    try std.testing.expectEqualStrings("line1\\nline2\\r\\n", buf.items);
}

test "appendJsonEscaped backslash" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    try appendJsonEscaped(std.testing.allocator, &buf, "path\\to\\file");
    try std.testing.expectEqualStrings("path\\\\to\\\\file", buf.items);
}

test "appendJsonEscaped empty string" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    try appendJsonEscaped(std.testing.allocator, &buf, "");
    try std.testing.expectEqual(@as(usize, 0), buf.items.len);
}

test "shouldHydrate no memory no snapshot" {
    try std.testing.expect(!shouldHydrate(std.testing.allocator, null, "/nonexistent"));
}

test "shouldHydrate with non-empty memory" {
    // Create an in-memory SQLite for test
    const sqlite = @import("sqlite.zig");
    var mem_impl = try sqlite.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem_impl.deinit();
    const mem = mem_impl.memory();

    // Store something
    try mem.store("test", "data", .core);

    // Should not hydrate because memory is not empty
    try std.testing.expect(!shouldHydrate(std.testing.allocator, mem, "/nonexistent"));
}

test "exportSnapshot returns zero for empty memory" {
    const sqlite = @import("sqlite.zig");
    var mem_impl = try sqlite.SqliteMemory.init(std.testing.allocator, ":memory:");
    defer mem_impl.deinit();
    const mem = mem_impl.memory();

    const count = try exportSnapshot(std.testing.allocator, mem, "/tmp/yc_snapshot_test_nonexist");
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "SNAPSHOT_FILENAME is correct" {
    try std.testing.expectEqualStrings("MEMORY_SNAPSHOT.json", SNAPSHOT_FILENAME);
}
