//! Parallel read-only tool batch helpers for the agent loop.

const std = @import("std");
const dispatcher = @import("dispatcher.zig");

const ParsedToolCall = dispatcher.ParsedToolCall;

const parallel_readonly_tools = [_][]const u8{
    "file_read",
    "file_read_hashed",
    "memory_recall",
    "memory_list",
    "memory_search",
    "web_fetch",
    "web_search",
    "sqlite_query",
};

pub fn isParallelReadOnlyTool(name: []const u8) bool {
    const trimmed = std.mem.trim(u8, name, " \t\r\n");
    for (parallel_readonly_tools) |allowed| {
        if (std.mem.eql(u8, trimmed, allowed)) return true;
    }
    return false;
}

pub fn batchAllParallelReadOnly(calls: []const ParsedToolCall) bool {
    if (calls.len <= 1) return false;
    for (calls) |call| {
        if (!isParallelReadOnlyTool(call.name)) return false;
    }
    return true;
}

pub fn shouldRunParallelReadOnlyBatch(parallel_tools_enabled: bool, calls: []const ParsedToolCall) bool {
    return parallel_tools_enabled and batchAllParallelReadOnly(calls);
}

test "batchAllParallelReadOnly accepts file_read batch" {
    const calls = [_]ParsedToolCall{
        .{ .name = "file_read", .arguments_json = "{\"path\":\"a\"}" },
        .{ .name = "file_read", .arguments_json = "{\"path\":\"b\"}" },
    };
    try std.testing.expect(batchAllParallelReadOnly(&calls));
}

test "batchAllParallelReadOnly rejects shell mixed with file_read" {
    const calls = [_]ParsedToolCall{
        .{ .name = "file_read", .arguments_json = "{\"path\":\"a\"}" },
        .{ .name = "shell", .arguments_json = "{\"command\":\"ls\"}" },
    };
    try std.testing.expect(!batchAllParallelReadOnly(&calls));
}

test "shouldRunParallelReadOnlyBatch requires parallel_tools flag" {
    const calls = [_]ParsedToolCall{
        .{ .name = "file_read", .arguments_json = "{\"path\":\"a\"}" },
        .{ .name = "file_read", .arguments_json = "{\"path\":\"b\"}" },
    };
    try std.testing.expect(!shouldRunParallelReadOnlyBatch(false, &calls));
    try std.testing.expect(shouldRunParallelReadOnlyBatch(true, &calls));
}
