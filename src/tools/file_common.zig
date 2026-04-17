const std = @import("std");
const std_compat = @import("compat");
const fs_compat = @import("../fs_compat.zig");
const bootstrap_mod = @import("../bootstrap/root.zig");
const isPathSafe = @import("path_security.zig").isPathSafe;

pub const PrepareWorkspacePathError = error{
    OutOfMemory,
    AbsolutePathsNotAllowed,
    PathContainsNullBytes,
    UnsafePath,
};

pub const WorkspacePathInfo = struct {
    full_path: []u8,
    workspace_resolved: ?[]u8,

    pub fn deinit(self: WorkspacePathInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.full_path);
        if (self.workspace_resolved) |resolved| allocator.free(resolved);
    }

    pub fn workspacePath(self: WorkspacePathInfo) []const u8 {
        return self.workspace_resolved orelse "";
    }
};

pub fn prepareWorkspacePath(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    path: []const u8,
    allow_absolute_paths: bool,
) PrepareWorkspacePathError!WorkspacePathInfo {
    const full_path = if (std_compat.fs.path.isAbsolute(path)) blk: {
        if (!allow_absolute_paths) return error.AbsolutePathsNotAllowed;
        if (std.mem.indexOfScalar(u8, path, 0) != null) return error.PathContainsNullBytes;
        break :blk try allocator.dupe(u8, path);
    } else blk: {
        if (!isPathSafe(path)) return error.UnsafePath;
        break :blk try std_compat.fs.path.join(allocator, &.{ workspace_dir, path });
    };
    errdefer allocator.free(full_path);

    const workspace_resolved = fs_compat.realpathAllocPath(allocator, workspace_dir) catch null;
    errdefer if (workspace_resolved) |resolved| allocator.free(resolved);

    return .{
        .full_path = full_path,
        .workspace_resolved = workspace_resolved,
    };
}

pub fn resolveNearestExistingAncestor(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    return fs_compat.realpathAllocPath(allocator, path) catch |err| switch (err) {
        error.FileNotFound => {
            const parent = std_compat.fs.path.dirname(path) orelse return err;
            if (std.mem.eql(u8, parent, path)) return err;
            return resolveNearestExistingAncestor(allocator, parent);
        },
        else => return err,
    };
}

pub fn bootstrapRootFilename(path: []const u8) ?[]const u8 {
    if (std_compat.fs.path.isAbsolute(path)) return null;
    const basename = std_compat.fs.path.basename(path);
    if (!std.mem.eql(u8, basename, path)) return null;
    if (!bootstrap_mod.isBootstrapFilename(basename)) return null;
    return basename;
}

pub fn isSymlinkPath(path: []const u8) !bool {
    const dir_path = std_compat.fs.path.dirname(path) orelse ".";
    const entry_name = std_compat.fs.path.basename(path);
    var dir = if (std_compat.fs.path.isAbsolute(dir_path))
        try std_compat.fs.openDirAbsolute(dir_path, .{})
    else
        try fs_compat.openDirPath(dir_path, .{});
    defer dir.close();

    var link_buf: [std_compat.fs.max_path_bytes]u8 = undefined;
    _ = dir.readLink(entry_name, &link_buf) catch |err| switch (err) {
        error.NotLink => return false,
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

test "bootstrapRootFilename returns basename for workspace root bootstrap file" {
    try std.testing.expectEqualStrings("BOOTSTRAP.md", bootstrapRootFilename("BOOTSTRAP.md").?);
}

test "prepareWorkspacePath joins relative path and resolves workspace" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const workspace_dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace_dir);

    const info = try prepareWorkspacePath(std.testing.allocator, workspace_dir, "notes/todo.md", false);
    defer info.deinit(std.testing.allocator);

    const expected = try std_compat.fs.path.join(std.testing.allocator, &.{ workspace_dir, "notes/todo.md" });
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqualStrings(expected, info.full_path);
    try std.testing.expectEqualStrings(workspace_dir, info.workspacePath());
}

test "prepareWorkspacePath rejects absolute path when not allowed" {
    const absolute_path = if (std_compat.fs.path.sep == '\\')
        "C:\\workspace\\todo.md"
    else
        "/workspace/todo.md";

    try std.testing.expectError(
        error.AbsolutePathsNotAllowed,
        prepareWorkspacePath(std.testing.allocator, ".", absolute_path, false),
    );
}

test "bootstrapRootFilename rejects nested and absolute paths" {
    try std.testing.expect(bootstrapRootFilename("docs/BOOTSTRAP.md") == null);

    const absolute_path = if (std_compat.fs.path.sep == '\\')
        "C:\\workspace\\BOOTSTRAP.md"
    else
        "/workspace/BOOTSTRAP.md";
    try std.testing.expect(bootstrapRootFilename(absolute_path) == null);
}

test "resolveNearestExistingAncestor returns nearest existing parent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try @import("compat").fs.Dir.wrap(tmp.dir).makePath("existing/child");

    const existing_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, "existing/child");
    defer std.testing.allocator.free(existing_path);

    const missing_path = try std_compat.fs.path.join(std.testing.allocator, &.{ existing_path, "missing", "leaf.txt" });
    defer std.testing.allocator.free(missing_path);

    const resolved = try resolveNearestExistingAncestor(std.testing.allocator, missing_path);
    defer std.testing.allocator.free(resolved);

    try std.testing.expectEqualStrings(existing_path, resolved);
}

test "isSymlinkPath detects symlink and regular file" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try @import("compat").fs.Dir.wrap(tmp.dir).writeFile(.{ .sub_path = "target.txt", .data = "hello" });
    try @import("compat").fs.Dir.wrap(tmp.dir).writeFile(.{ .sub_path = "regular.txt", .data = "world" });
    try @import("compat").fs.Dir.wrap(tmp.dir).symLink("target.txt", "link.txt", .{});

    const workspace_dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace_dir);

    const link_path = try std_compat.fs.path.join(std.testing.allocator, &.{ workspace_dir, "link.txt" });
    defer std.testing.allocator.free(link_path);
    try std.testing.expect(try isSymlinkPath(link_path));

    const regular_path = try std_compat.fs.path.join(std.testing.allocator, &.{ workspace_dir, "regular.txt" });
    defer std.testing.allocator.free(regular_path);
    try std.testing.expect(!(try isSymlinkPath(regular_path)));
}
