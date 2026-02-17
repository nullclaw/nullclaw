const std = @import("std");

// Tools — agent tool integrations (50+ in ZeroClaw).
// Each tool will implement a common interface.
//
// Core tools to implement:
//   - Shell command execution (sandboxed)
//   - File read/write (workspace-scoped)
//   - Web search (Brave, DuckDuckGo)
//   - HTTP fetch
//   - Screenshot / image processing

/// Tool interface — Zig equivalent of ZeroClaw's tool traits.
pub const Tool = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        execute: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, input: []const u8) anyerror![]const u8,
        name: *const fn (ptr: *anyopaque) []const u8,
        description: *const fn (ptr: *anyopaque) []const u8,
    };

    pub fn execute(self: Tool, allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
        return self.vtable.execute(self.ptr, allocator, input);
    }

    pub fn name(self: Tool) []const u8 {
        return self.vtable.name(self.ptr);
    }

    pub fn description(self: Tool) []const u8 {
        return self.vtable.description(self.ptr);
    }
};

test "tools module compiles" {}
