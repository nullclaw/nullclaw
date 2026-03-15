// src/bootstrap/provider.zig
const std = @import("std");
const memory_root = @import("../memory/root.zig");

/// Bootstrap document provider — abstracts where identity files are stored.
pub const BootstrapProvider = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        load: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, filename: []const u8) anyerror!?[]const u8,
        load_excerpt: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, filename: []const u8, max_bytes: usize) anyerror!?[]const u8,
        store: *const fn (ptr: *anyopaque, filename: []const u8, content: []const u8) anyerror!void,
        remove: *const fn (ptr: *anyopaque, filename: []const u8) anyerror!bool,
        exists: *const fn (ptr: *anyopaque, filename: []const u8) bool,
        list: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]const []const u8,
        fingerprint: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror!u64,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn load(self: BootstrapProvider, allocator: std.mem.Allocator, filename: []const u8) !?[]const u8 {
        return self.vtable.load(self.ptr, allocator, filename);
    }

    pub fn load_excerpt(self: BootstrapProvider, allocator: std.mem.Allocator, filename: []const u8, max_bytes: usize) !?[]const u8 {
        return self.vtable.load_excerpt(self.ptr, allocator, filename, max_bytes);
    }

    pub fn store(self: BootstrapProvider, filename: []const u8, content: []const u8) !void {
        return self.vtable.store(self.ptr, filename, content);
    }

    pub fn remove(self: BootstrapProvider, filename: []const u8) !bool {
        return self.vtable.remove(self.ptr, filename);
    }

    pub fn exists(self: BootstrapProvider, filename: []const u8) bool {
        return self.vtable.exists(self.ptr, filename);
    }

    pub fn list(self: BootstrapProvider, allocator: std.mem.Allocator) ![]const []const u8 {
        return self.vtable.list(self.ptr, allocator);
    }

    pub fn fingerprint(self: BootstrapProvider, allocator: std.mem.Allocator) !u64 {
        return self.vtable.fingerprint(self.ptr, allocator);
    }

    pub fn deinit(self: BootstrapProvider) void {
        self.vtable.deinit(self.ptr);
    }
};

/// Check if a filename is a known bootstrap document.
pub fn isBootstrapFilename(basename: []const u8) bool {
    for (memory_root.prompt_bootstrap_docs) |doc| {
        if (std.mem.eql(u8, basename, doc.filename)) return true;
    }
    return false;
}

comptime {
    _ = @import("file_provider.zig");
    _ = @import("null_provider.zig");
    _ = @import("memory_provider.zig");
    _ = @import("contract_test.zig");
    _ = @import("integration_test.zig");
}

test "isBootstrapFilename recognizes known files" {
    try std.testing.expect(isBootstrapFilename("AGENTS.md"));
    try std.testing.expect(isBootstrapFilename("SOUL.md"));
    try std.testing.expect(isBootstrapFilename("TOOLS.md"));
    try std.testing.expect(isBootstrapFilename("IDENTITY.md"));
    try std.testing.expect(isBootstrapFilename("USER.md"));
    try std.testing.expect(isBootstrapFilename("HEARTBEAT.md"));
    try std.testing.expect(isBootstrapFilename("BOOTSTRAP.md"));
    try std.testing.expect(isBootstrapFilename("MEMORY.md"));
    try std.testing.expect(!isBootstrapFilename("random.md"));
    try std.testing.expect(!isBootstrapFilename("config.json"));
}
