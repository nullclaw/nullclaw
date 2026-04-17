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
pub const MemoryStoreTool = struct {
    memory: ?Memory = null,
    mem_rt: ?*mem_root.MemoryRuntime = null,

    pub const tool_name = "memory_store";
    pub const tool_description = "Store durable user facts, preferences, and decisions in long-term memory. Omit session_id for cross-session memory. Use category 'core' for stable facts, 'daily' for short-lived reminders, 'conversation' for important context only. Do not store routine greetings or every chat message.";
    pub const tool_params =
        \\{"type":"object","properties":{"key":{"type":"string","description":"Unique key for this memory"},"content":{"type":"string","description":"The information to remember"},"category":{"type":"string","enum":["core","daily","conversation"],"description":"Memory category"},"session_id":{"type":"string","description":"Optional session scope. Omit for durable cross-session memory; pass an empty string to use the current thread session."}},"required":["key","content"]}
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
        const session_id = if (args.get("session_id")) |_|
            if (root.getString(args, "session_id")) |sid_raw|
                if (sid_raw.len > 0) sid_raw else root.threadMemorySessionId()
            else
                root.threadMemorySessionId()
        else
            null;

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

test "memory_store defaults to global memory when session_id is omitted" {
    const allocator = std.testing.allocator;
    var sqlite_mem = try mem_root.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();

    var mt = MemoryStoreTool{ .memory = sqlite_mem.memory() };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"key\": \"pickup.sister\", \"content\": \"Pick up sister from Heathrow tomorrow\", \"category\": \"daily\"}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.output.len > 0) allocator.free(result.output);

    try std.testing.expect(result.success);

    const global_entry = (try sqlite_mem.memory().getScoped(allocator, "pickup.sister", null)).?;
    defer global_entry.deinit(allocator);
    try std.testing.expect(global_entry.session_id == null);
}

test "memory_store uses current thread session when session_id is empty string" {
    const allocator = std.testing.allocator;
    var sqlite_mem = try mem_root.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();

    const previous = root.setThreadMemorySessionId("chat-123");
    defer _ = root.setThreadMemorySessionId(previous);

    var mt = MemoryStoreTool{ .memory = sqlite_mem.memory() };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"key\": \"chat.note\", \"content\": \"Scoped note\", \"session_id\": \"\"}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer if (result.output.len > 0) allocator.free(result.output);

    try std.testing.expect(result.success);

    const scoped_entry = (try sqlite_mem.memory().getScoped(allocator, "chat.note", "chat-123")).?;
    defer scoped_entry.deinit(allocator);
    try std.testing.expectEqualStrings("chat-123", scoped_entry.session_id.?);
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
