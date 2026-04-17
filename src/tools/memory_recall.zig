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
        \\{"type":"object","properties":{"query":{"type":"string","description":"Keywords or phrase to search for in memory"},"limit":{"type":"integer","description":"Max results to return (default: 5)"},"session_id":{"type":"string","description":"Optional session scope. Omit to search the current session plus global memory; pass an empty string to search only the current thread session."}},"required":["query"]}
    ;

    pub const vtable = root.ToolVTable(@This());
    const GLOBAL_RECALL_CANDIDATE_LIMIT: usize = 64;

    const SessionSelection = struct {
        explicit_scope: bool,
        preferred_session_id: ?[]const u8,
    };

    pub fn tool(self: *MemoryRecallTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn resolveSessionSelection(args: JsonObjectMap) SessionSelection {
        if (args.get("session_id") != null) {
            if (root.getString(args, "session_id")) |sid_raw| {
                if (sid_raw.len > 0) {
                    return .{ .explicit_scope = true, .preferred_session_id = sid_raw };
                }
            }
            return .{ .explicit_scope = true, .preferred_session_id = root.threadMemorySessionId() };
        }

        return .{
            .explicit_scope = false,
            .preferred_session_id = root.threadMemorySessionId(),
        };
    }

    fn containsEntryKey(entries: []const MemoryEntry, key: []const u8) bool {
        for (entries) |entry| {
            if (std.mem.eql(u8, entry.key, key)) return true;
        }
        return false;
    }

    fn containsCandidateKey(candidates: []const mem_root.RetrievalCandidate, key: []const u8) bool {
        for (candidates) |candidate| {
            if (std.mem.eql(u8, candidate.key, key)) return true;
        }
        return false;
    }

    fn appendMissingEntries(
        allocator: std.mem.Allocator,
        dest: *std.ArrayList(MemoryEntry),
        entries: []const MemoryEntry,
        limit: usize,
    ) !void {
        for (entries) |entry| {
            if (dest.items.len >= limit) break;
            if (containsEntryKey(dest.items, entry.key)) continue;

            const cloned_category: mem_root.MemoryCategory = switch (entry.category) {
                .custom => |name| .{ .custom = try allocator.dupe(u8, name) },
                else => entry.category,
            };
            errdefer switch (cloned_category) {
                .custom => |name| allocator.free(name),
                else => {},
            };

            try dest.append(allocator, .{
                .id = try allocator.dupe(u8, entry.id),
                .key = try allocator.dupe(u8, entry.key),
                .content = try allocator.dupe(u8, entry.content),
                .category = cloned_category,
                .timestamp = try allocator.dupe(u8, entry.timestamp),
                .session_id = if (entry.session_id) |sid| try allocator.dupe(u8, sid) else null,
                .score = entry.score,
            });
        }
    }

    fn appendMissingCandidates(
        allocator: std.mem.Allocator,
        dest: *std.ArrayList(mem_root.RetrievalCandidate),
        candidates: []const mem_root.RetrievalCandidate,
        limit: usize,
    ) !void {
        for (candidates) |candidate| {
            if (dest.items.len >= limit) break;
            if (containsCandidateKey(dest.items, candidate.key)) continue;

            const cloned_category: mem_root.MemoryCategory = switch (candidate.category) {
                .custom => |name| .{ .custom = try allocator.dupe(u8, name) },
                else => candidate.category,
            };
            errdefer switch (cloned_category) {
                .custom => |name| allocator.free(name),
                else => {},
            };

            try dest.append(allocator, .{
                .id = try allocator.dupe(u8, candidate.id),
                .key = try allocator.dupe(u8, candidate.key),
                .content = try allocator.dupe(u8, candidate.content),
                .snippet = try allocator.dupe(u8, candidate.snippet),
                .category = cloned_category,
                .keyword_rank = candidate.keyword_rank,
                .vector_score = candidate.vector_score,
                .final_score = candidate.final_score,
                .source = try allocator.dupe(u8, candidate.source),
                .source_path = try allocator.dupe(u8, candidate.source_path),
                .start_line = candidate.start_line,
                .end_line = candidate.end_line,
                .created_at = candidate.created_at,
            });
        }
    }

    fn partitionGlobalEntries(entries: []MemoryEntry) usize {
        var global_count: usize = 0;
        for (entries, 0..) |_, i| {
            if (entries[i].session_id != null) continue;
            if (global_count != i) {
                std.mem.swap(MemoryEntry, &entries[global_count], &entries[i]);
            }
            global_count += 1;
        }
        return global_count;
    }

    pub fn execute(self: *MemoryRecallTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const query = root.getString(args, "query") orelse
            return ToolResult.fail("Missing 'query' parameter");
        if (query.len == 0) return ToolResult.fail("'query' must not be empty");

        const limit_raw = root.getInt(args, "limit") orelse 5;
        const limit: usize = if (limit_raw > 0 and limit_raw <= 100) @intCast(limit_raw) else 5;
        const selection = resolveSessionSelection(args);

        const m = self.memory orelse {
            const msg = try std.fmt.allocPrint(allocator, "Memory backend not configured. Cannot search for: {s}", .{query});
            return ToolResult{ .success = false, .output = msg };
        };

        // Use retrieval engine (hybrid pipeline) when MemoryRuntime is available,
        // fall back to raw mem.recall() otherwise.
        if (self.mem_rt) |rt| {
            const primary_candidates = rt.search(allocator, query, limit, selection.preferred_session_id) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to search memories for '{s}': {s}", .{ query, @errorName(err) });
                return ToolResult{ .success = false, .output = msg };
            };
            defer mem_root.retrieval.freeCandidates(allocator, primary_candidates);

            var merged_candidates = std.ArrayList(mem_root.RetrievalCandidate).empty;
            defer {
                for (merged_candidates.items) |*candidate| candidate.deinit(allocator);
                merged_candidates.deinit(allocator);
            }
            try appendMissingCandidates(allocator, &merged_candidates, primary_candidates, limit);

            if (!selection.explicit_scope and selection.preferred_session_id != null and merged_candidates.items.len < limit) {
                var global_entries = m.recall(allocator, query, GLOBAL_RECALL_CANDIDATE_LIMIT, null) catch |err| {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to recall global memories for '{s}': {s}", .{ query, @errorName(err) });
                    return ToolResult{ .success = false, .output = msg };
                };
                defer mem_root.freeEntries(allocator, global_entries);

                const global_count = partitionGlobalEntries(global_entries);
                const global_candidates = try mem_root.retrieval.entriesToCandidates(allocator, global_entries[0..global_count]);
                defer mem_root.retrieval.freeCandidates(allocator, global_candidates);
                try appendMissingCandidates(allocator, &merged_candidates, global_candidates, limit);
            }

            const visible_candidates = countVisibleCandidates(merged_candidates.items);
            if (visible_candidates == 0) {
                const msg = try std.fmt.allocPrint(allocator, "No memories found matching: {s}", .{query});
                return ToolResult{ .success = true, .output = msg };
            }

            return formatCandidates(allocator, merged_candidates.items, visible_candidates);
        }

        const primary_entries = m.recall(allocator, query, limit, selection.preferred_session_id) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to recall memories for '{s}': {s}", .{ query, @errorName(err) });
            return ToolResult{ .success = false, .output = msg };
        };
        defer mem_root.freeEntries(allocator, primary_entries);

        var merged_entries = std.ArrayList(MemoryEntry).empty;
        defer {
            for (merged_entries.items) |*entry| entry.deinit(allocator);
            merged_entries.deinit(allocator);
        }
        try appendMissingEntries(allocator, &merged_entries, primary_entries, limit);

        if (!selection.explicit_scope and selection.preferred_session_id != null and merged_entries.items.len < limit) {
            var global_entries = m.recall(allocator, query, GLOBAL_RECALL_CANDIDATE_LIMIT, null) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to recall global memories for '{s}': {s}", .{ query, @errorName(err) });
                return ToolResult{ .success = false, .output = msg };
            };
            defer mem_root.freeEntries(allocator, global_entries);
            const global_count = partitionGlobalEntries(global_entries);
            try appendMissingEntries(allocator, &merged_entries, global_entries[0..global_count], limit);
        }

        const visible_entries = countVisibleEntries(merged_entries.items);
        if (visible_entries == 0) {
            const msg = try std.fmt.allocPrint(allocator, "No memories found matching: {s}", .{query});
            return ToolResult{ .success = true, .output = msg };
        }

        return formatEntries(allocator, merged_entries.items, visible_entries);
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
    try std.testing.expect(std.mem.indexOf(u8, schema, "session_id") != null);
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

test "memory_recall includes global memory without cross-session bleed" {
    const allocator = std.testing.allocator;
    var sqlite_mem = try mem_root.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("pickup.sister", "Pick up sister from Heathrow tomorrow", .daily, null);
    try mem.store("chat.note", "Discuss Heathrow parking", .conversation, "chat-123");
    try mem.store("other.note", "Drop luggage at Heathrow terminal 3", .conversation, "chat-999");

    const previous = root.setThreadMemorySessionId("chat-123");
    defer _ = root.setThreadMemorySessionId(previous);

    var mt = MemoryRecallTool{ .memory = mem };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"query\": \"Heathrow\"}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.output.len > 0) allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "pickup.sister") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "chat.note") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "other.note") == null);
}

test "memory_recall runtime includes global memory without cross-session bleed" {
    const allocator = std.testing.allocator;
    var sqlite_mem = try mem_root.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("pickup.sister", "Pick up sister from Heathrow tomorrow", .daily, null);
    try mem.store("chat.note", "Discuss Heathrow parking", .conversation, "chat-123");
    try mem.store("other.note", "Drop luggage at Heathrow terminal 3", .conversation, "chat-999");

    const resolved = mem_root.ResolvedConfig{
        .primary_backend = "test",
        .retrieval_mode = "keyword",
        .vector_mode = "none",
        .embedding_provider = "none",
        .rollout_mode = "off",
        .vector_sync_mode = "best_effort",
        .hygiene_enabled = false,
        .snapshot_enabled = false,
        .cache_enabled = false,
        .semantic_cache_enabled = false,
        .summarizer_enabled = false,
        .source_count = 0,
        .fallback_policy = "degrade",
    };
    var rt = mem_root.MemoryRuntime{
        .memory = mem,
        .session_store = null,
        .response_cache = null,
        .capabilities = .{
            .supports_keyword_rank = false,
            .supports_session_store = false,
            .supports_transactions = false,
            .supports_outbox = false,
        },
        .resolved = resolved,
        ._db_path = null,
        ._cache_db_path = null,
        ._engine = null,
        ._allocator = allocator,
    };

    const previous = root.setThreadMemorySessionId("chat-123");
    defer _ = root.setThreadMemorySessionId(previous);

    var mt = MemoryRecallTool{ .memory = mem, .mem_rt = &rt };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"query\": \"Heathrow\"}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.output.len > 0) allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "pickup.sister") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "chat.note") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "other.note") == null);
}

test "memory_recall respects explicit session scope" {
    const allocator = std.testing.allocator;
    var sqlite_mem = try mem_root.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("pickup.sister", "Pick up sister from Heathrow tomorrow", .daily, null);
    try mem.store("chat.note", "Discuss airport parking", .conversation, "chat-123");

    var mt = MemoryRecallTool{ .memory = mem };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"query\": \"Heathrow\", \"session_id\": \"chat-123\"}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.output.len > 0) allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "pickup.sister") == null);
}
