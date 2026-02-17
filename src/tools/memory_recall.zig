const std = @import("std");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;
const parseIntField = @import("shell.zig").parseIntField;
const mem_root = @import("../memory/root.zig");
const Memory = mem_root.Memory;
const MemoryEntry = mem_root.MemoryEntry;

/// Memory recall tool — lets the agent search its own memory.
pub const MemoryRecallTool = struct {
    memory: ?Memory = null,

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *MemoryRecallTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *MemoryRecallTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "memory_recall";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Search long-term memory for relevant facts, preferences, or context.";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"query":{"type":"string","description":"Keywords or phrase to search for in memory"},"limit":{"type":"integer","description":"Max results to return (default: 5)"}},"required":["query"]}
        ;
    }

    fn execute(self: *MemoryRecallTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const query = parseStringField(args_json, "query") orelse
            return ToolResult.fail("Missing 'query' parameter");

        const limit_raw = parseIntField(args_json, "limit") orelse 5;
        const limit: usize = if (limit_raw > 0) @intCast(limit_raw) else 5;

        const m = self.memory orelse {
            const msg = try std.fmt.allocPrint(allocator, "Memory backend not configured. Cannot search for: {s}", .{query});
            return ToolResult{ .success = true, .output = msg };
        };

        const entries = m.recall(allocator, query, limit) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to recall memories for '{s}': {s}", .{ query, @errorName(err) });
            return ToolResult{ .success = false, .output = msg };
        };
        defer mem_root.freeEntries(allocator, entries);

        if (entries.len == 0) {
            const msg = try std.fmt.allocPrint(allocator, "No memories found matching: {s}", .{query});
            return ToolResult{ .success = true, .output = msg };
        }

        // Format results as a readable list
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);

        try buf.appendSlice(allocator, "Found ");
        // Write count
        var count_buf: [20]u8 = undefined;
        const count_str = std.fmt.bufPrint(&count_buf, "{d}", .{entries.len}) catch "?";
        try buf.appendSlice(allocator, count_str);
        try buf.appendSlice(allocator, " memor");
        if (entries.len == 1) {
            try buf.appendSlice(allocator, "y:\n");
        } else {
            try buf.appendSlice(allocator, "ies:\n");
        }

        for (entries, 0..) |entry, i| {
            var idx_buf: [20]u8 = undefined;
            const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{i + 1}) catch "?";
            try buf.appendSlice(allocator, idx_str);
            try buf.appendSlice(allocator, ". [");
            try buf.appendSlice(allocator, entry.key);
            try buf.appendSlice(allocator, "] (");
            try buf.appendSlice(allocator, entry.category.toString());
            try buf.appendSlice(allocator, "): ");
            try buf.appendSlice(allocator, entry.content);
            try buf.append(allocator, '\n');
        }

        return ToolResult{ .success = true, .output = try buf.toOwnedSlice(allocator) };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "memory_recall tool name" {
    var mt = MemoryRecallTool{};
    const t = mt.tool();
    try std.testing.expectEqualStrings("memory_recall", t.name());
}

test "memory_recall schema has query" {
    var mt = MemoryRecallTool{};
    const t = mt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "query") != null);
}

test "memory_recall executes without backend" {
    var mt = MemoryRecallTool{};
    const t = mt.tool();
    const result = try t.execute(std.testing.allocator, "{\"query\": \"Zig\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "not configured") != null);
}

test "memory_recall missing query" {
    var mt = MemoryRecallTool{};
    const t = mt.tool();
    const result = try t.execute(std.testing.allocator, "{}");
    try std.testing.expect(!result.success);
}

test "memory_recall with real backend empty result" {
    const NoneMemory = mem_root.NoneMemory;
    var backend = NoneMemory.init();
    defer backend.deinit();

    var mt = MemoryRecallTool{ .memory = backend.memory() };
    const t = mt.tool();
    const result = try t.execute(std.testing.allocator, "{\"query\": \"Zig\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "No memories found") != null);
}

test "memory_recall with custom limit" {
    const NoneMemory = mem_root.NoneMemory;
    var backend = NoneMemory.init();
    defer backend.deinit();

    var mt = MemoryRecallTool{ .memory = backend.memory() };
    const t = mt.tool();
    const result = try t.execute(std.testing.allocator, "{\"query\": \"test\", \"limit\": 10}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
}
