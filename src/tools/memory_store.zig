const std = @import("std");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;
const mem_root = @import("../memory/root.zig");
const Memory = mem_root.Memory;
const MemoryCategory = mem_root.MemoryCategory;

/// Memory store tool — lets the agent persist facts to long-term memory.
pub const MemoryStoreTool = struct {
    memory: ?Memory = null,

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *MemoryStoreTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *MemoryStoreTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "memory_store";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Store a fact, preference, or note in long-term memory. Use category 'core' for permanent facts, 'daily' for session notes, 'conversation' for chat context.";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"key":{"type":"string","description":"Unique key for this memory"},"content":{"type":"string","description":"The information to remember"},"category":{"type":"string","enum":["core","daily","conversation"],"description":"Memory category"}},"required":["key","content"]}
        ;
    }

    fn execute(self: *MemoryStoreTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const key = parseStringField(args_json, "key") orelse
            return ToolResult.fail("Missing 'key' parameter");

        const content = parseStringField(args_json, "content") orelse
            return ToolResult.fail("Missing 'content' parameter");

        const category_str = parseStringField(args_json, "category") orelse "core";
        const category = MemoryCategory.fromString(category_str);

        const m = self.memory orelse {
            const msg = try std.fmt.allocPrint(allocator, "Memory backend not configured. Would store: {s} = {s}", .{ key, content });
            return ToolResult{ .success = true, .output = msg };
        };

        m.store(key, content, category) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to store memory '{s}': {s}", .{ key, @errorName(err) });
            return ToolResult{ .success = false, .output = msg };
        };

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
    const result = try t.execute(std.testing.allocator, "{\"key\": \"lang\", \"content\": \"Prefers Zig\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "not configured") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "lang") != null);
}

test "memory_store missing key" {
    var mt = MemoryStoreTool{};
    const t = mt.tool();
    const result = try t.execute(std.testing.allocator, "{\"content\": \"no key\"}");
    try std.testing.expect(!result.success);
}

test "memory_store missing content" {
    var mt = MemoryStoreTool{};
    const t = mt.tool();
    const result = try t.execute(std.testing.allocator, "{\"key\": \"no_content\"}");
    try std.testing.expect(!result.success);
}

test "memory_store with real backend" {
    const NoneMemory = mem_root.NoneMemory;
    var backend = NoneMemory.init();
    defer backend.deinit();

    var mt = MemoryStoreTool{ .memory = backend.memory() };
    const t = mt.tool();
    const result = try t.execute(std.testing.allocator, "{\"key\": \"lang\", \"content\": \"Prefers Zig\", \"category\": \"core\"}");
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
    const result = try t.execute(std.testing.allocator, "{\"key\": \"test\", \"content\": \"value\"}");
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
    const result = try t.execute(std.testing.allocator, "{\"key\": \"note\", \"content\": \"today's note\", \"category\": \"daily\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "daily") != null);
}
