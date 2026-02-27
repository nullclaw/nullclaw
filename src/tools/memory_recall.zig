const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const mem_root = @import("../memory/root.zig");
const Memory = mem_root.Memory;
const MemoryEntry = mem_root.MemoryEntry;

/// Memory recall tool — lets the agent search its own memory.
/// When a MemoryRuntime is available, uses the full retrieval pipeline
/// (hybrid search, RRF merge, temporal decay, MMR, etc.) instead of
/// raw `mem.recall()`.
pub const MemoryRecallTool = struct {
    memory: ?Memory = null,
    mem_rt: ?*mem_root.MemoryRuntime = null,

    pub const tool_name = "memory_recall";
    pub const tool_description = "Search long-term memory for relevant facts, preferences, or context.";
    pub const tool_params =
        \\{"type":"object","properties":{"query":{"type":"string","description":"Keywords or phrase to search for in memory"},"limit":{"type":"integer","description":"Max results to return (default: 5)"}},"required":["query"]}
    ;

    pub const vtable = root.ToolVTable(@This());

    pub fn tool(self: *MemoryRecallTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *MemoryRecallTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const query = root.getString(args, "query") orelse
            return ToolResult.fail("Missing 'query' parameter");
        if (query.len == 0) return ToolResult.fail("'query' must not be empty");

        const limit_raw = root.getInt(args, "limit") orelse 5;
        const limit: usize = if (limit_raw > 0 and limit_raw <= 100) @intCast(limit_raw) else 5;

        const m = self.memory orelse {
            const msg = try std.fmt.allocPrint(allocator, "Memory backend not configured. Cannot search for: {s}", .{query});
            return ToolResult{ .success = false, .output = msg };
        };

        // Use retrieval engine (hybrid pipeline) when MemoryRuntime is available,
        // fall back to raw mem.recall() otherwise.
        if (self.mem_rt) |rt| {
            const candidates = rt.search(allocator, query, limit, null) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to search memories for '{s}': {s}", .{ query, @errorName(err) });
                return ToolResult{ .success = false, .output = msg };
            };
            defer mem_root.retrieval.freeCandidates(allocator, candidates);

            const visible_candidates = countVisibleCandidates(candidates);
            if (visible_candidates == 0) {
                const msg = try std.fmt.allocPrint(allocator, "No memories found matching: {s}", .{query});
                return ToolResult{ .success = true, .output = msg };
            }

            return formatCandidates(allocator, candidates, visible_candidates);
        }

        const entries = m.recall(allocator, query, limit, null) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to recall memories for '{s}': {s}", .{ query, @errorName(err) });
            return ToolResult{ .success = false, .output = msg };
        };
        defer mem_root.freeEntries(allocator, entries);

        const visible_entries = countVisibleEntries(entries);
        if (visible_entries == 0) {
            const msg = try std.fmt.allocPrint(allocator, "No memories found matching: {s}", .{query});
            return ToolResult{ .success = true, .output = msg };
        }

        return formatEntries(allocator, entries, visible_entries);
    }

    fn countVisibleEntries(entries: []const MemoryEntry) usize {
        var count: usize = 0;
        for (entries) |entry| {
            if (mem_root.isInternalMemoryEntryKeyOrContent(entry.key, entry.content)) continue;
            count += 1;
        }
        return count;
    }

    fn countVisibleCandidates(candidates: []const mem_root.RetrievalCandidate) usize {
        var count: usize = 0;
        for (candidates) |cand| {
            if (mem_root.isInternalMemoryEntryKeyOrContent(cand.key, cand.snippet)) continue;
            count += 1;
        }
        return count;
    }

    fn formatEntries(allocator: std.mem.Allocator, entries: []const MemoryEntry, visible_count: usize) !ToolResult {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);

        try buf.appendSlice(allocator, "Found ");
        var count_buf: [20]u8 = undefined;
        const count_str = std.fmt.bufPrint(&count_buf, "{d}", .{visible_count}) catch "?";
        try buf.appendSlice(allocator, count_str);
        try buf.appendSlice(allocator, if (visible_count == 1) " memory:\n" else " memories:\n");

        var shown_idx: usize = 0;
        for (entries, 0..) |entry, i| {
            _ = i;
            if (mem_root.isInternalMemoryEntryKeyOrContent(entry.key, entry.content)) continue;
            var idx_buf: [20]u8 = undefined;
            shown_idx += 1;
            const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{shown_idx}) catch "?";
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

    fn formatCandidates(
        allocator: std.mem.Allocator,
        candidates: []const mem_root.RetrievalCandidate,
        visible_count: usize,
    ) !ToolResult {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);

        try buf.appendSlice(allocator, "Found ");
        var count_buf: [20]u8 = undefined;
        const count_str = std.fmt.bufPrint(&count_buf, "{d}", .{visible_count}) catch "?";
        try buf.appendSlice(allocator, count_str);
        try buf.appendSlice(allocator, if (visible_count == 1) " memory:\n" else " memories:\n");

        var shown_idx: usize = 0;
        for (candidates, 0..) |cand, i| {
            _ = i;
            if (mem_root.isInternalMemoryEntryKeyOrContent(cand.key, cand.snippet)) continue;
            var idx_buf: [20]u8 = undefined;
            shown_idx += 1;
            const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{shown_idx}) catch "?";
            try buf.appendSlice(allocator, idx_str);
            try buf.appendSlice(allocator, ". [");
            try buf.appendSlice(allocator, cand.key);
            try buf.appendSlice(allocator, "] (");
            try buf.appendSlice(allocator, cand.source);
            var score_buf: [20]u8 = undefined;
            const score_str = std.fmt.bufPrint(&score_buf, " {d:.2}", .{cand.final_score}) catch "";
            try buf.appendSlice(allocator, score_str);
            try buf.appendSlice(allocator, "): ");
            try buf.appendSlice(allocator, cand.snippet);
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
    const parsed = try root.parseTestArgs("{\"query\": \"Zig\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "not configured") != null);
}

test "memory_recall missing query" {
    var mt = MemoryRecallTool{};
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "memory_recall with real backend empty result" {
    const NoneMemory = mem_root.NoneMemory;
    var backend = NoneMemory.init();
    defer backend.deinit();

    var mt = MemoryRecallTool{ .memory = backend.memory() };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"query\": \"Zig\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
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
    const parsed = try root.parseTestArgs("{\"query\": \"test\", \"limit\": 10}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
}

test "memory_recall filters internal bootstrap keys" {
    const allocator = std.testing.allocator;
    var sqlite_mem = try mem_root.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("__bootstrap.prompt.SOUL.md", "internal-soul", .core, null);
    try mem.store("user_pref", "loves zig", .core, null);

    var mt = MemoryRecallTool{ .memory = mem };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"query\": \"zig\"}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.output.len > 0) allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "user_pref") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "__bootstrap.prompt.SOUL.md") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "internal-soul") == null);
}
