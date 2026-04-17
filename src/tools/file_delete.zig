const std = @import("std");
const std_compat = @import("compat");
const fs_compat = @import("../fs_compat.zig");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isPathSafe = @import("path_security.zig").isPathSafe;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;
const file_common = @import("file_common.zig");
const bootstrap_mod = @import("../bootstrap/root.zig");
const onboard = @import("../onboard.zig");
const resolveNearestExistingAncestor = file_common.resolveNearestExistingAncestor;

/// Delete BOOTSTRAP.md from the workspace or bootstrap memory backend.
pub const FileDeleteTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    bootstrap_provider: ?bootstrap_mod.BootstrapProvider = null,
    backend_name: []const u8 = "hybrid",

    pub const tool_name = "file_delete";
    pub const tool_description = "Delete BOOTSTRAP.md when onboarding is complete. Works for both file and memory-backed bootstrap storage.";
    pub const tool_params =
        \\{"type":"object","properties":{"path":{"type":"string","description":"Relative path to delete. Currently only BOOTSTRAP.md is supported."}},"required":["path"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *FileDeleteTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *FileDeleteTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const path = root.getString(args, "path") orelse
            return ToolResult.fail("Missing 'path' parameter");

        if (std_compat.fs.path.isAbsolute(path) or !isPathSafe(path))
            return ToolResult.fail("Path not allowed: use a workspace-relative BOOTSTRAP.md path");

        if (!std.mem.eql(u8, path, "BOOTSTRAP.md"))
            return ToolResult.fail("Only BOOTSTRAP.md can be deleted with this tool");

        const full_path = try std_compat.fs.path.join(allocator, &.{ self.workspace_dir, path });
        defer allocator.free(full_path);

        const ws_resolved: ?[]const u8 = fs_compat.realpathAllocPath(allocator, self.workspace_dir) catch null;
        defer if (ws_resolved) |wr| allocator.free(wr);
        const ws_path = ws_resolved orelse "";

        const parent_to_check = std_compat.fs.path.dirname(full_path) orelse full_path;
        const resolved_ancestor = resolveNearestExistingAncestor(allocator, parent_to_check) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to resolve path: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(resolved_ancestor);

        if (!isResolvedPathAllowed(allocator, resolved_ancestor, ws_path, self.allowed_paths)) {
            return ToolResult.fail("Path is outside allowed areas");
        }

        const removed_from_provider = if (!bootstrap_mod.backendUsesFiles(self.backend_name) and self.bootstrap_provider != null)
            try self.bootstrap_provider.?.remove("BOOTSTRAP.md")
        else
            false;

        const removed_from_disk = blk: {
            std_compat.fs.deleteFileAbsolute(full_path) catch |err| switch (err) {
                error.FileNotFound => break :blk false,
                else => {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to delete file: {}", .{err});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                },
            };
            break :blk true;
        };
        const removed = removed_from_provider or removed_from_disk;

        if (!removed) {
            return ToolResult.fail("BOOTSTRAP.md not found");
        }

        onboard.markOnboardingCompletedAfterBootstrapRemoval(allocator, self.workspace_dir) catch {};

        return ToolResult.ok("Deleted BOOTSTRAP.md");
    }
};

test "file_delete tool name" {
    var ft = FileDeleteTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    try std.testing.expectEqualStrings("file_delete", t.name());
}

test "file_delete rejects non-bootstrap paths" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileDeleteTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"USER.md\"}");
    defer parsed.deinit();

    const result = try t.execute(std.testing.allocator, parsed.value.object);

    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("Only BOOTSTRAP.md can be deleted with this tool", result.error_msg.?);
}

test "file_delete removes sqlite bootstrap and marks onboarding complete" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var lru = @import("../memory/root.zig").InMemoryLruMemory.init(std.testing.allocator, 16);
    defer lru.deinit();
    var bp_impl = @import("../bootstrap/root.zig").MemoryBootstrapProvider.init(std.testing.allocator, lru.memory(), ws_path);
    const provider = bp_impl.provider();
    try provider.store("BOOTSTRAP.md", "hello");

    var ft = FileDeleteTool{
        .workspace_dir = ws_path,
        .allowed_paths = &.{ws_path},
        .bootstrap_provider = provider,
        .backend_name = "sqlite",
    };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"BOOTSTRAP.md\"}");
    defer parsed.deinit();

    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("Deleted BOOTSTRAP.md", result.output);
    try std.testing.expect(!provider.exists("BOOTSTRAP.md"));

    const state_path = try std_compat.fs.path.join(std.testing.allocator, &.{ ws_path, ".nullclaw", "workspace-state.json" });
    defer std.testing.allocator.free(state_path);
    const file = try std_compat.fs.openFileAbsolute(state_path, .{});
    defer file.close();
    const state_raw = try file.readToEndAlloc(std.testing.allocator, 4096);
    defer std.testing.allocator.free(state_raw);
    try std.testing.expect(std.mem.indexOf(u8, state_raw, "\"onboarding_completed_at\"") != null);
}

test "file_delete removes sqlite bootstrap disk fallback when DB entry is absent" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "BOOTSTRAP.md", .data = "legacy bootstrap" });

    var lru = @import("../memory/root.zig").InMemoryLruMemory.init(std.testing.allocator, 16);
    defer lru.deinit();
    var bp_impl = @import("../bootstrap/root.zig").MemoryBootstrapProvider.init(std.testing.allocator, lru.memory(), ws_path);
    const provider = bp_impl.provider();

    var ft = FileDeleteTool{
        .workspace_dir = ws_path,
        .allowed_paths = &.{ws_path},
        .bootstrap_provider = provider,
        .backend_name = "sqlite",
    };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"BOOTSTRAP.md\"}");
    defer parsed.deinit();

    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("Deleted BOOTSTRAP.md", result.output);
    try std.testing.expect(!provider.exists("BOOTSTRAP.md"));
    try std.testing.expectError(error.FileNotFound, @import("compat").fs.Dir.wrap(tmp_dir.dir).openFile("BOOTSTRAP.md", .{}));
}

test "file_delete removes sqlite bootstrap from DB and disk fallback together" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "BOOTSTRAP.md", .data = "legacy bootstrap" });

    var lru = @import("../memory/root.zig").InMemoryLruMemory.init(std.testing.allocator, 16);
    defer lru.deinit();
    var bp_impl = @import("../bootstrap/root.zig").MemoryBootstrapProvider.init(std.testing.allocator, lru.memory(), ws_path);
    const provider = bp_impl.provider();
    try provider.store("BOOTSTRAP.md", "fresh bootstrap");

    var ft = FileDeleteTool{
        .workspace_dir = ws_path,
        .allowed_paths = &.{ws_path},
        .bootstrap_provider = provider,
        .backend_name = "sqlite",
    };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"BOOTSTRAP.md\"}");
    defer parsed.deinit();

    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(!provider.exists("BOOTSTRAP.md"));
    try std.testing.expectError(error.FileNotFound, @import("compat").fs.Dir.wrap(tmp_dir.dir).openFile("BOOTSTRAP.md", .{}));
}
