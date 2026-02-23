const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isPathSafe = @import("path_security.zig").isPathSafe;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;

/// Write file contents with workspace path scoping.
pub const FileWriteTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},

    pub const tool_name = "file_write";
    pub const tool_description = "Write contents to a file in the workspace";
    pub const tool_params =
        \\{"type":"object","properties":{"path":{"type":"string","description":"Relative path to the file within the workspace"},"content":{"type":"string","description":"Content to write to the file"}},"required":["path","content"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *FileWriteTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *FileWriteTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const path = root.getString(args, "path") orelse
            return ToolResult.fail("Missing 'path' parameter");

        const content = root.getString(args, "content") orelse
            return ToolResult.fail("Missing 'content' parameter");

        // Build full path — absolute or relative
        const full_path = if (std.fs.path.isAbsolute(path)) blk: {
            if (self.allowed_paths.len == 0)
                return ToolResult.fail("Absolute paths not allowed (no allowed_paths configured)");
            if (std.mem.indexOfScalar(u8, path, 0) != null)
                return ToolResult.fail("Path contains null bytes");
            break :blk try allocator.dupe(u8, path);
        } else blk: {
            if (!isPathSafe(path))
                return ToolResult.fail("Path not allowed: contains traversal or absolute path");
            break :blk try std.fs.path.join(allocator, &.{ self.workspace_dir, path });
        };
        defer allocator.free(full_path);

        const ws_resolved: ?[]const u8 = std.fs.cwd().realpathAlloc(allocator, self.workspace_dir) catch null;
        defer if (ws_resolved) |wr| allocator.free(wr);
        const ws_path = ws_resolved orelse "";

        // Resolve and validate before any filesystem writes so symlink targets
        // and disallowed absolute destinations are rejected without side effects.
        const resolved_target: ?[]const u8 = std.fs.cwd().realpathAlloc(allocator, full_path) catch |err| switch (err) {
            error.FileNotFound => null,
            else => {
                const msg = try std.fmt.allocPrint(allocator, "Failed to resolve path: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            },
        };
        defer if (resolved_target) |rt| allocator.free(rt);

        if (resolved_target) |resolved| {
            if (!isResolvedPathAllowed(allocator, resolved, ws_path, self.allowed_paths)) {
                return ToolResult.fail("Path is outside allowed areas");
            }
        } else {
            const parent_to_check = std.fs.path.dirname(full_path) orelse full_path;
            const resolved_ancestor = resolveNearestExistingAncestor(allocator, parent_to_check) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to resolve path: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
            defer allocator.free(resolved_ancestor);

            if (!isResolvedPathAllowed(allocator, resolved_ancestor, ws_path, self.allowed_paths)) {
                return ToolResult.fail("Path is outside allowed areas");
            }
        }

        // Preserve symlink semantics by writing to the resolved target path.
        const write_path = if (resolved_target) |resolved|
            if (isSymlinkPath(full_path))
                try allocator.dupe(u8, resolved)
            else
                try allocator.dupe(u8, full_path)
        else
            try allocator.dupe(u8, full_path);
        defer allocator.free(write_path);

        const existing_mode: ?std.fs.File.Mode = blk: {
            const st = std.fs.cwd().statFile(write_path) catch |err| switch (err) {
                error.FileNotFound => break :blk null,
                else => {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to stat file: {}", .{err});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                },
            };
            break :blk st.mode;
        };

        // Ensure parent directory exists after policy checks pass.
        if (std.fs.path.dirname(write_path)) |parent| {
            std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => {
                    std.fs.cwd().makePath(parent) catch |e| {
                        const msg = try std.fmt.allocPrint(allocator, "Failed to create directory: {}", .{e});
                        return ToolResult{ .success = false, .output = "", .error_msg = msg };
                    };
                },
            };
        }

        // Write via temp file + rename so existing hard links are not modified in place.
        const parent = std.fs.path.dirname(write_path) orelse write_path;
        const basename = std.fs.path.basename(write_path);
        var parent_dir = if (std.fs.path.isAbsolute(parent))
            std.fs.openDirAbsolute(parent, .{}) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to open directory: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            }
        else
            std.fs.cwd().openDir(parent, .{}) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to open directory: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
        defer parent_dir.close();

        var tmp_name_buf: [128]u8 = undefined;
        var tmp_name_len: usize = 0;
        var tmp_file: ?std.fs.File = null;
        var attempt: usize = 0;
        while (attempt < 32) : (attempt += 1) {
            const tmp_name = std.fmt.bufPrint(
                &tmp_name_buf,
                ".nullclaw-write-{d}-{d}.tmp",
                .{ std.time.nanoTimestamp(), attempt },
            ) catch unreachable;
            tmp_file = parent_dir.createFile(tmp_name, .{ .exclusive = true }) catch |err| switch (err) {
                error.PathAlreadyExists => continue,
                else => {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to create file: {}", .{err});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                },
            };
            tmp_name_len = tmp_name.len;
            break;
        }
        if (tmp_file == null) {
            return ToolResult.fail("Failed to create temporary file");
        }

        var file = tmp_file.?;
        defer file.close();

        if (comptime std.fs.has_executable_bit) {
            if (existing_mode) |mode| {
                if (mode != 0) {
                    file.chmod(mode) catch |err| {
                        const msg = try std.fmt.allocPrint(allocator, "Failed to preserve file mode: {}", .{err});
                        return ToolResult{ .success = false, .output = "", .error_msg = msg };
                    };
                }
            }
        }

        var committed = false;
        defer if (!committed and tmp_name_len > 0) {
            parent_dir.deleteFile(tmp_name_buf[0..tmp_name_len]) catch {};
        };

        file.writeAll(content) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to write file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        parent_dir.rename(tmp_name_buf[0..tmp_name_len], basename) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to replace file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        committed = true;

        const final_resolved = std.fs.cwd().realpathAlloc(allocator, full_path) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to resolve path: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(final_resolved);

        if (!isResolvedPathAllowed(allocator, final_resolved, ws_path, self.allowed_paths)) {
            if (std.fs.path.isAbsolute(write_path)) {
                std.fs.deleteFileAbsolute(write_path) catch {};
            } else {
                std.fs.cwd().deleteFile(write_path) catch {};
            }
            return ToolResult.fail("Path is outside allowed areas");
        }

        const msg = try std.fmt.allocPrint(allocator, "Written {d} bytes to {s}", .{ content.len, path });
        return ToolResult{ .success = true, .output = msg };
    }
};

fn resolveNearestExistingAncestor(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    return std.fs.cwd().realpathAlloc(allocator, path) catch |err| switch (err) {
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse return err;
            if (std.mem.eql(u8, parent, path)) return err;
            return resolveNearestExistingAncestor(allocator, parent);
        },
        else => return err,
    };
}

fn isSymlinkPath(path: []const u8) bool {
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (std.fs.path.isAbsolute(path)) {
        _ = std.fs.readLinkAbsolute(path, &link_buf) catch return false;
        return true;
    }
    _ = std.fs.cwd().readLink(path, &link_buf) catch return false;
    return true;
}

// ── Tests ───────────────────────────────────────────────────────────

test "file_write tool name" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    try std.testing.expectEqualStrings("file_write", t.name());
}

test "file_write tool schema has path and content" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "path") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "content") != null);
}

test "file_write creates file" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileWriteTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"out.txt\", \"content\": \"written!\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "8 bytes") != null);

    // Verify file contents
    const actual = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "out.txt", 1024);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings("written!", actual);
}

test "file_write creates parent dirs" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileWriteTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"a/b/c/deep.txt\", \"content\": \"deep\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);

    const actual = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "a/b/c/deep.txt", 1024);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings("deep", actual);
}

test "file_write overwrites existing" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = "exist.txt", .data = "old" });
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileWriteTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"exist.txt\", \"content\": \"new\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);

    const actual = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "exist.txt", 1024);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings("new", actual);
}

test "file_write blocks path traversal" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp/workspace" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"../../etc/evil\", \"content\": \"bad\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not allowed") != null);
}

test "file_write blocks absolute path" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp/workspace" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"/etc/evil\", \"content\": \"bad\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_write missing path param" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"content\": \"data\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_write missing content param" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"file.txt\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_write empty content" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileWriteTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"empty.txt\", \"content\": \"\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "0 bytes") != null);
}

test "file_write blocks symlink target escape outside workspace" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    var outside_tmp = std.testing.tmpDir(.{});
    defer outside_tmp.cleanup();

    const ws_path = try ws_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const outside_path = try outside_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(outside_path);

    try outside_tmp.dir.writeFile(.{ .sub_path = "outside.txt", .data = "safe" });
    const outside_file = try std.fs.path.join(std.testing.allocator, &.{ outside_path, "outside.txt" });
    defer std.testing.allocator.free(outside_file);

    try ws_tmp.dir.symLink(outside_file, "escape.txt", .{});

    var ft = FileWriteTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"escape.txt\", \"content\": \"pwned\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "outside allowed areas") != null);

    const outside_actual = try outside_tmp.dir.readFileAlloc(std.testing.allocator, "outside.txt", 1024);
    defer std.testing.allocator.free(outside_actual);
    try std.testing.expectEqualStrings("safe", outside_actual);
}

test "file_write does not mutate outside inode through hard link" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    var outside_tmp = std.testing.tmpDir(.{});
    defer outside_tmp.cleanup();

    const ws_path = try ws_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const outside_path = try outside_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(outside_path);

    try outside_tmp.dir.writeFile(.{ .sub_path = "outside.txt", .data = "SAFE" });
    const outside_file = try std.fs.path.join(std.testing.allocator, &.{ outside_path, "outside.txt" });
    defer std.testing.allocator.free(outside_file);
    const hardlink_path = try std.fs.path.join(std.testing.allocator, &.{ ws_path, "hl.txt" });
    defer std.testing.allocator.free(hardlink_path);

    try std.posix.link(outside_file, hardlink_path);

    var ft = FileWriteTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"hl.txt\", \"content\": \"PWNED\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);

    const workspace_actual = try ws_tmp.dir.readFileAlloc(std.testing.allocator, "hl.txt", 1024);
    defer std.testing.allocator.free(workspace_actual);
    try std.testing.expectEqualStrings("PWNED", workspace_actual);

    const outside_actual = try outside_tmp.dir.readFileAlloc(std.testing.allocator, "outside.txt", 1024);
    defer std.testing.allocator.free(outside_actual);
    try std.testing.expectEqualStrings("SAFE", outside_actual);
}

test "file_write keeps symlink and updates target" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const ws_path = try ws_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    try ws_tmp.dir.writeFile(.{ .sub_path = "target.txt", .data = "old" });
    try ws_tmp.dir.symLink("target.txt", "link.txt", .{});

    var ft = FileWriteTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"link.txt\", \"content\": \"new\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_target = try ws_tmp.dir.readLink("link.txt", &link_buf);
    try std.testing.expectEqualStrings("target.txt", link_target);

    const target_actual = try ws_tmp.dir.readFileAlloc(std.testing.allocator, "target.txt", 1024);
    defer std.testing.allocator.free(target_actual);
    try std.testing.expectEqualStrings("new", target_actual);
}

test "file_write preserves executable mode on overwrite" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const ws_path = try ws_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    try ws_tmp.dir.writeFile(.{ .sub_path = "script.sh", .data = "#!/bin/sh\necho old\n" });
    var file = try ws_tmp.dir.openFile("script.sh", .{ .mode = .read_write });
    defer file.close();
    try file.chmod(@as(std.fs.File.Mode, 0o755));

    var ft = FileWriteTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"script.sh\", \"content\": \"#!/bin/sh\\necho new\\n\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(result.success);

    const st = try ws_tmp.dir.statFile("script.sh");
    const perms: std.fs.File.Mode = st.mode & @as(std.fs.File.Mode, 0o777);
    try std.testing.expectEqual(@as(std.fs.File.Mode, 0o755), perms);
}

test "file_write rejects disallowed absolute path without creating parent directories" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;

    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    var outside_tmp = std.testing.tmpDir(.{});
    defer outside_tmp.cleanup();

    const ws_path = try ws_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const outside_path = try outside_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(outside_path);

    const outside_parent = try std.fs.path.join(std.testing.allocator, &.{ outside_path, "created_by_rejected_write" });
    defer std.testing.allocator.free(outside_parent);
    const outside_file = try std.fs.path.join(std.testing.allocator, &.{ outside_parent, "note.txt" });
    defer std.testing.allocator.free(outside_file);

    const json_args = try std.fmt.allocPrint(std.testing.allocator, "{{\"path\": \"{s}\", \"content\": \"x\"}}", .{outside_file});
    defer std.testing.allocator.free(json_args);

    var ft = FileWriteTool{ .workspace_dir = ws_path, .allowed_paths = &.{ws_path} };
    const t = ft.tool();
    const parsed = try root.parseTestArgs(json_args);
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "outside allowed areas") != null);

    const dir_exists = blk: {
        var d = std.fs.openDirAbsolute(outside_parent, .{}) catch |err| switch (err) {
            error.FileNotFound => break :blk false,
            else => return err,
        };
        d.close();
        break :blk true;
    };
    try std.testing.expect(!dir_exists);
}
