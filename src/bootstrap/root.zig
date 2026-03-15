// src/bootstrap/root.zig
const std = @import("std");
const memory_root = @import("../memory/root.zig");

pub const BootstrapProvider = @import("provider.zig").BootstrapProvider;
pub const FileBootstrapProvider = @import("file_provider.zig").FileBootstrapProvider;
pub const MemoryBootstrapProvider = @import("memory_provider.zig").MemoryBootstrapProvider;
pub const NullBootstrapProvider = @import("null_provider.zig").NullBootstrapProvider;
pub const isBootstrapFilename = @import("provider.zig").isBootstrapFilename;

/// Backend names that use null (no-op) bootstrap storage.
const null_backends = [_][]const u8{ "none", "memory" };

/// Returns true if the given backend stores bootstrap files on disk.
pub fn backendUsesFiles(backend: []const u8) bool {
    return memory_root.usesWorkspaceBootstrapFiles(backend);
}

/// Factory: create the appropriate BootstrapProvider for a backend.
pub fn createProvider(
    allocator: std.mem.Allocator,
    backend: []const u8,
    mem: ?memory_root.Memory,
    workspace_dir: ?[]const u8,
) !BootstrapProvider {
    // File-based backends
    if (backendUsesFiles(backend)) {
        const ws = workspace_dir orelse return error.WorkspaceDirRequired;
        const impl = try allocator.create(FileBootstrapProvider);
        impl.* = FileBootstrapProvider.init(allocator, ws);
        impl.owns_self = true;
        return impl.provider();
    }
    // Null backends
    for (&null_backends) |name| {
        if (std.mem.eql(u8, name, backend)) {
            const impl = try allocator.create(NullBootstrapProvider);
            impl.* = .{
                .allocator = allocator,
                .owns_self = true,
            };
            return impl.provider();
        }
    }
    // DB-backed
    const memory = mem orelse return error.MemoryRequired;
    const impl = try allocator.create(MemoryBootstrapProvider);
    impl.* = MemoryBootstrapProvider.init(allocator, memory, workspace_dir);
    impl.owns_self = true;
    return impl.provider();
}

test "backendUsesFiles" {
    try std.testing.expect(backendUsesFiles("hybrid"));
    try std.testing.expect(backendUsesFiles("markdown"));
    try std.testing.expect(!backendUsesFiles("sqlite"));
    try std.testing.expect(!backendUsesFiles("postgres"));
    try std.testing.expect(!backendUsesFiles("redis"));
    try std.testing.expect(!backendUsesFiles("none"));
}

test "createProvider returns FileBootstrapProvider for hybrid" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir);

    const bp = try createProvider(std.testing.allocator, "hybrid", null, dir);
    defer bp.deinit();

    try bp.store("SOUL.md", "test");
    const content = try bp.load(std.testing.allocator, "SOUL.md");
    defer if (content) |c| std.testing.allocator.free(c);
    try std.testing.expectEqualStrings("test", content.?);
}

test "createProvider returns NullBootstrapProvider for none" {
    const bp = try createProvider(std.testing.allocator, "none", null, null);
    defer bp.deinit();

    const content = try bp.load(std.testing.allocator, "SOUL.md");
    try std.testing.expect(content == null);
}

test "createProvider errors without workspace for hybrid" {
    const result = createProvider(std.testing.allocator, "hybrid", null, null);
    try std.testing.expectError(error.WorkspaceDirRequired, result);
}

test "createProvider errors without memory for sqlite" {
    const result = createProvider(std.testing.allocator, "sqlite", null, null);
    try std.testing.expectError(error.MemoryRequired, result);
}

// Pull in all submodule tests
test {
    @import("std").testing.refAllDecls(@This());
}
