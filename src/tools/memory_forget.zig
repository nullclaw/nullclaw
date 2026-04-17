const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const mem_root = @import("../memory/root.zig");
const Memory = mem_root.Memory;

/// Memory forget tool — lets the agent delete a memory entry.
/// When a MemoryRuntime is available, also cleans up the vector store.
pub const MemoryForgetTool = struct {
    memory: ?Memory = null,
    mem_rt: ?*mem_root.MemoryRuntime = null,

    pub const tool_name = "memory_forget";
    pub const tool_description = "Remove a memory by key. Use to delete outdated facts or sensitive data.";
    pub const tool_params =
        \\{"type":"object","properties":{"key":{"type":"string","description":"The key of the memory to forget"}},"required":["key"]}
    ;

    pub const vtable = root.ToolVTable(@This());

    pub fn tool(self: *MemoryForgetTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *MemoryForgetTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const key = root.getString(args, "key") orelse
            return ToolResult.fail("Missing 'key' parameter");
        if (key.len == 0) return ToolResult.fail("'key' must not be empty");
        const session_id = if (root.getString(args, "session_id")) |sid_raw|
            if (sid_raw.len > 0) sid_raw else root.threadMemorySessionId()
        else
            root.threadMemorySessionId();

        const m = self.memory orelse {
            const msg = try std.fmt.allocPrint(allocator, "Memory backend not configured. Cannot forget: {s}", .{key});
            return ToolResult{ .success = false, .output = msg };
        };

        const forgotten = m.forgetScoped(allocator, key, session_id) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to forget memory '{s}': {s}", .{ key, @errorName(err) });
            return ToolResult{ .success = false, .output = msg };
        };

        if (forgotten) {
            // Best-effort vector store cleanup
            if (self.mem_rt) |rt| {
                rt.deleteFromVectorStore(key, session_id);
            }
            const msg = try std.fmt.allocPrint(allocator, "Forgot memory: {s}", .{key});
            return ToolResult{ .success = true, .output = msg };
        } else {
            const msg = try std.fmt.allocPrint(allocator, "No memory found with key: {s}", .{key});
            return ToolResult{ .success = true, .output = msg };
        }
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "memory_forget tool name" {
    var mt = MemoryForgetTool{};
    const t = mt.tool();
    try std.testing.expectEqualStrings("memory_forget", t.name());
}

test "memory_forget schema has key" {
    var mt = MemoryForgetTool{};
    const t = mt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "key") != null);
}

test "memory_forget executes without backend" {
    var mt = MemoryForgetTool{};
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"key\": \"temp\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "not configured") != null);
}

test "memory_forget missing key" {
    var mt = MemoryForgetTool{};
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "memory_forget with real backend key not found" {
    const NoneMemory = mem_root.NoneMemory;
    var backend = NoneMemory.init();
    defer backend.deinit();

    var mt = MemoryForgetTool{ .memory = backend.memory() };
    const t = mt.tool();
    const parsed = try root.parseTestArgs("{\"key\": \"nonexistent\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "No memory found") != null);
}

test "memory_forget with real backend returns appropriate message" {
    const NoneMemory = mem_root.NoneMemory;
    var backend = NoneMemory.init();
    defer backend.deinit();

    var mt = MemoryForgetTool{ .memory = backend.memory() };
    const t = mt.tool();
    // NoneMemory.forget always returns false (nothing to forget)
    const parsed = try root.parseTestArgs("{\"key\": \"test_key\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "No memory found with key: test_key") != null);
}
