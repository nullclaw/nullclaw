const std = @import("std");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;
const mem_root = @import("../memory/root.zig");
const Memory = mem_root.Memory;

/// Memory forget tool — lets the agent delete a memory entry.
pub const MemoryForgetTool = struct {
    memory: ?Memory = null,

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *MemoryForgetTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *MemoryForgetTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "memory_forget";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Remove a memory by key. Use to delete outdated facts or sensitive data.";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"key":{"type":"string","description":"The key of the memory to forget"}},"required":["key"]}
        ;
    }

    fn execute(self: *MemoryForgetTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const key = parseStringField(args_json, "key") orelse
            return ToolResult.fail("Missing 'key' parameter");

        const m = self.memory orelse {
            const msg = try std.fmt.allocPrint(allocator, "Memory backend not configured. Cannot forget: {s}", .{key});
            return ToolResult{ .success = true, .output = msg };
        };

        const forgotten = m.forget(key) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to forget memory '{s}': {s}", .{ key, @errorName(err) });
            return ToolResult{ .success = false, .output = msg };
        };

        if (forgotten) {
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
    const result = try t.execute(std.testing.allocator, "{\"key\": \"temp\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "not configured") != null);
}

test "memory_forget missing key" {
    var mt = MemoryForgetTool{};
    const t = mt.tool();
    const result = try t.execute(std.testing.allocator, "{}");
    try std.testing.expect(!result.success);
}

test "memory_forget with real backend key not found" {
    const NoneMemory = mem_root.NoneMemory;
    var backend = NoneMemory.init();
    defer backend.deinit();

    var mt = MemoryForgetTool{ .memory = backend.memory() };
    const t = mt.tool();
    const result = try t.execute(std.testing.allocator, "{\"key\": \"nonexistent\"}");
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
    const result = try t.execute(std.testing.allocator, "{\"key\": \"test_key\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "No memory found with key: test_key") != null);
}
