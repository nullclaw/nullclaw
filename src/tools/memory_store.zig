const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const mem_root = @import("../memory/root.zig");
const Memory = mem_root.Memory;
const MemoryCategory = mem_root.MemoryCategory;

/// Memory store tool — lets the agent persist facts to long-term memory.
/// When a MemoryRuntime is available, also triggers vector sync after store.
/// After store, generates extractive L0/L1 tiers for tiered context loading.
pub const MemoryStoreTool = struct {
    memory: ?Memory = null,
    mem_rt: ?*mem_root.MemoryRuntime = null,
    /// Enable tier generation after store. Disabled by default for backwards compat.
    tier_generation_enabled: bool = false,

    /// Rough token count estimate (4 chars per token).
    fn estimateTokens(text: []const u8) usize {
        return text.len / 4;
    }

    /// Minimum content length (in estimated tokens) to trigger L0 abstract generation.
    const L0_THRESHOLD: usize = 200;
    /// Minimum content length (in estimated tokens) to trigger L1 overview generation.
    const L1_THRESHOLD: usize = 1000;
    /// Max chars for L0 abstract (~50-100 tokens).
    const L0_MAX_CHARS: usize = 400;
    /// Max chars for L1 overview (~300-500 tokens).
    const L1_MAX_CHARS: usize = 2000;

    /// Generate an extractive summary by taking the first N chars at a
    /// sentence boundary. Fast, free, zero API calls.
    fn extractiveSummary(allocator: std.mem.Allocator, content: []const u8, max_chars: usize) ![]const u8 {
        if (content.len <= max_chars) return try allocator.dupe(u8, content);
        // Find last sentence-ending punctuation within budget
        var end = max_chars;
        while (end > max_chars / 2) : (end -= 1) {
            const ch = content[end - 1];
            if (ch == '.' or ch == '!' or ch == '?' or ch == '\n') break;
        }
        if (end <= max_chars / 2) end = max_chars; // no sentence boundary found, hard cut
        // Don't split UTF-8 multi-byte sequences
        while (end > 0 and content[end] & 0xC0 == 0x80) end -= 1;
        return try allocator.dupe(u8, content[0..end]);
    }

    pub const tool_name = "memory_store";
    pub const tool_description = "Store durable user facts, preferences, and decisions in long-term memory. Use category 'core' for stable facts, 'daily' for session notes, 'conversation' for important context only. Do not store routine greetings or every chat message.";
    pub const tool_params =
        \\{"type":"object","properties":{"key":{"type":"string","description":"Unique key for this memory"},"content":{"type":"string","description":"The information to remember"},"category":{"type":"string","enum":["core","daily","conversation"],"description":"Memory category"}},"required":["key","content"]}
    ;

    pub const vtable = root.ToolVTable(@This());

    pub fn tool(self: *MemoryStoreTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *MemoryStoreTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const key = root.getString(args, "key") orelse
            return ToolResult.fail("Missing 'key' parameter");
        if (key.len == 0) return ToolResult.fail("'key' must not be empty");

        const content = root.getString(args, "content") orelse
            return ToolResult.fail("Missing 'content' parameter");
        if (content.len == 0) return ToolResult.fail("'content' must not be empty");

        const category_str = root.getString(args, "category") orelse "core";
        const category = MemoryCategory.fromString(category_str);
        const session_id = if (root.getString(args, "session_id")) |sid_raw|
            if (sid_raw.len > 0) sid_raw else root.threadMemorySessionId()
        else
            root.threadMemorySessionId();

        const m = self.memory orelse {
            const msg = try std.fmt.allocPrint(allocator, "Memory backend not configured. Cannot store: {s} = {s}", .{ key, content });
            return ToolResult{ .success = false, .output = msg };
        };

        m.store(key, content, category, session_id) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to store memory '{s}': {s}", .{ key, @errorName(err) });
            return ToolResult{ .success = false, .output = msg };
        };

        // Vector sync: embed and upsert into vector store (best-effort)
        if (self.mem_rt) |rt| {
            rt.syncVectorAfterStore(allocator, key, content, session_id);
        }

        // Tiered context generation (best-effort): generate extractive L0/L1 summaries
        // for long content so future recalls can use lighter tiers.
        if (self.tier_generation_enabled) {
            const tokens = estimateTokens(content);
            var abstract_text: ?[]const u8 = null;
            var overview_text: ?[]const u8 = null;
            defer if (abstract_text) |a| allocator.free(a);
            defer if (overview_text) |o| allocator.free(o);

            if (tokens >= L0_THRESHOLD) {
                abstract_text = extractiveSummary(allocator, content, L0_MAX_CHARS) catch null;
            }
            if (tokens >= L1_THRESHOLD) {
                overview_text = extractiveSummary(allocator, content, L1_MAX_CHARS) catch null;
            }
            if (abstract_text != null or overview_text != null) {
                m.updateTiers(key, abstract_text, overview_text) catch {};
            }
        }

        const msg = try std.fmt.allocPrint(allocator, "Stored memory: {s} ({s})", .{ key, category.toString() });
        return ToolResult{ .success = true, .output = msg };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "memory_store tool name" {
    var mt = MemoryStoreTool{};
    const t = mt.tool();
    try std.testing.expectEqualStrings("memory_store", t.name());
}

test "memory_store schema has key and content" {
    var mt = MemoryStoreTool{};
    const t = mt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "key") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "content") != null);
}

test "memory_store executes without backend" {
    var mt = MemoryStoreTool{};
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"key\": \"lang\", \"content\": \"Prefers Zig\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "not configured") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "lang") != null);
}

test "memory_store missing key" {
    var mt = MemoryStoreTool{};
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"content\": \"no key\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "memory_store missing content" {
    var mt = MemoryStoreTool{};
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"key\": \"no_content\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "memory_store with real backend" {
    const NoneMemory = mem_root.NoneMemory;
    var backend = NoneMemory.init();
    defer backend.deinit();

    var mt = MemoryStoreTool{ .memory = backend.memory() };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"key\": \"lang\", \"content\": \"Prefers Zig\", \"category\": \"core\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "Stored memory: lang") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "core") != null);
}

test "memory_store default category is core" {
    const NoneMemory = mem_root.NoneMemory;
    var backend = NoneMemory.init();
    defer backend.deinit();

    var mt = MemoryStoreTool{ .memory = backend.memory() };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"key\": \"test\", \"content\": \"value\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "core") != null);
}

test "memory_store with daily category" {
    const NoneMemory = mem_root.NoneMemory;
    var backend = NoneMemory.init();
    defer backend.deinit();

    var mt = MemoryStoreTool{ .memory = backend.memory() };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"key\": \"note\", \"content\": \"today's note\", \"category\": \"daily\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "daily") != null);
}

test "extractiveSummary returns full text when under limit" {
    const allocator = std.testing.allocator;
    const result = try MemoryStoreTool.extractiveSummary(allocator, "short text", 100);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("short text", result);
}

test "extractiveSummary truncates at sentence boundary" {
    const allocator = std.testing.allocator;
    const content = "First sentence. Second sentence. Third sentence is quite long and goes on.";
    const result = try MemoryStoreTool.extractiveSummary(allocator, content, 35);
    defer allocator.free(result);
    // Should cut at a period within the budget
    try std.testing.expect(result.len <= 35);
    try std.testing.expect(result.len > 0);
    try std.testing.expect(result[result.len - 1] == '.');
}

test "memory_store generates tiers for long content" {
    const allocator = std.testing.allocator;
    var sqlite_mem = try mem_root.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    // Content > 200 estimated tokens (800+ chars) to trigger L0
    var long_content: [1000]u8 = undefined;
    @memset(&long_content, 'a');
    // Add sentence boundaries
    long_content[200] = '.';
    long_content[400] = '.';
    long_content[600] = '.';
    long_content[800] = '.';

    var mt = MemoryStoreTool{ .memory = mem, .tier_generation_enabled = true };
    const t = mt.tool();

    const args_str = try std.fmt.allocPrint(allocator, "{{\"key\": \"long_note\", \"content\": \"{s}\"}}", .{&long_content});
    defer allocator.free(args_str);
    const parsed = try root.parseTestArgs(args_str);
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.output.len > 0) allocator.free(result.output);
    try std.testing.expect(result.success);

    // Verify tiers were stored
    const entry = try mem.get(allocator, "long_note");
    try std.testing.expect(entry != null);
    if (entry) |e| {
        defer e.deinit(allocator);
        try std.testing.expect(e.abstract != null);
        try std.testing.expect(e.abstract.?.len < e.content.len);
    }
}

test "ContextDepth.fromString parses correctly" {
    try std.testing.expectEqual(mem_root.ContextDepth.abstract, mem_root.ContextDepth.fromString("abstract"));
    try std.testing.expectEqual(mem_root.ContextDepth.overview, mem_root.ContextDepth.fromString("overview"));
    try std.testing.expectEqual(mem_root.ContextDepth.full, mem_root.ContextDepth.fromString("full"));
    try std.testing.expectEqual(mem_root.ContextDepth.abstract, mem_root.ContextDepth.fromString("unknown"));
}

test "MemoryEntry.atDepth returns correct tier" {
    const entry = mem_root.MemoryEntry{
        .id = "1",
        .key = "k",
        .content = "full content here",
        .category = .core,
        .timestamp = "0",
        .abstract = "brief",
        .overview = "medium detail",
    };
    try std.testing.expectEqualStrings("brief", entry.atDepth(.abstract));
    try std.testing.expectEqualStrings("medium detail", entry.atDepth(.overview));
    try std.testing.expectEqualStrings("full content here", entry.atDepth(.full));
}

test "MemoryEntry.atDepth falls back to content when tier is null" {
    const entry = mem_root.MemoryEntry{
        .id = "1",
        .key = "k",
        .content = "full content",
        .category = .core,
        .timestamp = "0",
    };
    try std.testing.expectEqualStrings("full content", entry.atDepth(.abstract));
    try std.testing.expectEqualStrings("full content", entry.atDepth(.overview));
}
