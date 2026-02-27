const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const mem_root = @import("../memory/root.zig");
const Memory = mem_root.Memory;
const MemoryCategory = mem_root.MemoryCategory;
const MemoryEntry = mem_root.MemoryEntry;

pub const MemoryListTool = struct {
    memory: ?Memory = null,

    pub const tool_name = "memory_list";
    pub const tool_description = "List memory entries in recency order. Use for requests like 'show first N memory records' without shell/sqlite access.";
    pub const tool_params =
        \\{"type":"object","properties":{"limit":{"type":"integer","description":"Max entries to return (default: 5, max: 100)"},"category":{"type":"string","description":"Optional category filter (core|daily|conversation|custom)"},"session_id":{"type":"string","description":"Optional session filter"},"include_content":{"type":"boolean","description":"Include content preview (default: true)"},"include_internal":{"type":"boolean","description":"Include internal autosave/hygiene keys (default: false)"}}}
    ;

    pub const vtable = root.ToolVTable(@This());

    pub fn tool(self: *MemoryListTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *MemoryListTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const m = self.memory orelse {
            const msg = try std.fmt.allocPrint(allocator, "Memory backend not configured. Cannot list entries.", .{});
            return ToolResult{ .success = false, .output = msg };
        };

        const limit_raw = root.getInt(args, "limit") orelse 5;
        const limit: usize = if (limit_raw > 0 and limit_raw <= 100) @intCast(limit_raw) else 5;

        const category_opt: ?MemoryCategory = if (root.getString(args, "category")) |cat_raw|
            if (cat_raw.len > 0) MemoryCategory.fromString(cat_raw) else null
        else
            null;

        const session_id_opt: ?[]const u8 = if (root.getString(args, "session_id")) |sid_raw|
            if (sid_raw.len > 0) sid_raw else null
        else
            null;

        const include_content = root.getBool(args, "include_content") orelse true;
        const include_internal = root.getBool(args, "include_internal") orelse false;

        const entries = m.list(allocator, category_opt, session_id_opt) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to list memory entries: {s}", .{@errorName(err)});
            return ToolResult{ .success = false, .output = msg };
        };
        defer mem_root.freeEntries(allocator, entries);

        var filtered_total: usize = 0;
        for (entries) |entry| {
            if (!include_internal and isInternalEntry(entry)) continue;
            filtered_total += 1;
        }

        if (filtered_total == 0) {
            const msg = if (category_opt != null)
                "No memory entries found for this filter."
            else
                "No memory entries found.";
            return ToolResult{ .success = true, .output = msg };
        }

        const shown = @min(limit, filtered_total);
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(allocator);
        const w = out.writer(allocator);
        try w.print("Memory entries: showing {d}/{d}\n", .{ shown, filtered_total });

        var written: usize = 0;
        for (entries) |entry| {
            if (!include_internal and isInternalEntry(entry)) continue;
            if (written >= shown) break;
            try w.print("  {d}. {s} [{s}] {s}\n", .{ written + 1, entry.key, entry.category.toString(), entry.timestamp });
            if (include_content) {
                const preview = truncateUtf8(entry.content, 120);
                try w.print("     {s}{s}\n", .{ preview, if (entry.content.len > preview.len) "..." else "" });
            }
            written += 1;
        }

        return ToolResult{ .success = true, .output = try out.toOwnedSlice(allocator) };
    }

    fn isInternalEntry(entry: MemoryEntry) bool {
        return mem_root.isInternalMemoryEntryKeyOrContent(entry.key, entry.content);
    }

    fn truncateUtf8(s: []const u8, max_len: usize) []const u8 {
        if (s.len <= max_len) return s;
        var end: usize = max_len;
        while (end > 0 and s[end] & 0xC0 == 0x80) end -= 1;
        return s[0..end];
    }
};

test "memory_list tool name" {
    var mt = MemoryListTool{};
    const t = mt.tool();
    try std.testing.expectEqualStrings("memory_list", t.name());
}

test "memory_list executes without backend" {
    var mt = MemoryListTool{};
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "not configured") != null);
}

test "memory_list filters internal keys by default" {
    const allocator = std.testing.allocator;
    var sqlite_mem = try mem_root.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("autosave_user_1", "hello", .conversation, null);
    try mem.store("user_language", "ru", .core, null);
    try mem.store("last_hygiene_at", "1772051598", .core, null);

    var mt = MemoryListTool{ .memory = mem };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"limit\":10}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.output.len > 0) allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "user_language") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "autosave_user_") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "last_hygiene_at") == null);
}

test "memory_list include_internal true includes autosave entries" {
    const allocator = std.testing.allocator;
    var sqlite_mem = try mem_root.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("autosave_user_1", "hello", .conversation, null);

    var mt = MemoryListTool{ .memory = mem };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"include_internal\":true}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.output.len > 0) allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "autosave_user_1") != null);
}

test "memory_list filters markdown-encoded internal keys in content" {
    const allocator = std.testing.allocator;
    var sqlite_mem = try mem_root.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("MEMORY:3", "**last_hygiene_at**: 1772051598", .core, null);
    try mem.store("MEMORY:4", "**Name**: User", .core, null);

    var mt = MemoryListTool{ .memory = mem };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"limit\":10}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.output.len > 0) allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "last_hygiene_at") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "**Name**: User") != null);
}

test "memory_list filters bootstrap internal keys by default" {
    const allocator = std.testing.allocator;
    var sqlite_mem = try mem_root.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("__bootstrap.prompt.AGENTS.md", "internal-agents", .core, null);
    try mem.store("user_topic", "shipping", .core, null);

    var mt = MemoryListTool{ .memory = mem };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"limit\":10}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.output.len > 0) allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "user_topic") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "__bootstrap.prompt.AGENTS.md") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "internal-agents") == null);
}
