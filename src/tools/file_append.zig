//! File Append Tool — append content to the end of a file within workspace.
//!
//! Creates the file if it doesn't exist. Uses workspace path scoping
//! and the same path safety checks as file_edit.

const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const fs_compat = @import("../fs_compat.zig");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;
const file_common = @import("file_common.zig");
const bootstrap_mod = @import("../bootstrap/root.zig");
const memory_root = @import("../memory/root.zig");
const bootstrapRootFilename = file_common.bootstrapRootFilename;
const isSymlinkPath = file_common.isSymlinkPath;
const prepareWorkspacePath = file_common.prepareWorkspacePath;
const resolveNearestExistingAncestor = file_common.resolveNearestExistingAncestor;

/// Default maximum file size to read before appending (10MB).
const DEFAULT_MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

/// Append content to the end of a file with workspace path scoping.
pub const FileAppendTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    max_file_size: usize = DEFAULT_MAX_FILE_SIZE,
    bootstrap_provider: ?bootstrap_mod.BootstrapProvider = null,
    backend_name: []const u8 = "hybrid",

    pub const tool_name = "file_append";
    pub const tool_description = "Append content to the end of a file (creates the file if it doesn't exist)";
    pub const tool_params =
        \\{"type":"object","properties":{"path":{"type":"string","description":"Relative path to the file within the workspace"},"content":{"type":"string","description":"Content to append to the file"}},"required":["path","content"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *FileAppendTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *FileAppendTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const path = root.getString(args, "path") orelse
            return ToolResult.fail("Missing 'path' parameter");

        const content = root.getString(args, "content") orelse
            return ToolResult.fail("Missing 'content' parameter");

        // Build full path — absolute or relative
        const path_info = prepareWorkspacePath(allocator, self.workspace_dir, path, self.allowed_paths.len > 0) catch |err| switch (err) {
            error.AbsolutePathsNotAllowed => return ToolResult.fail("Absolute paths not allowed (no allowed_paths configured)"),
            error.PathContainsNullBytes => return ToolResult.fail("Path contains null bytes"),
            error.UnsafePath => return ToolResult.fail("Path not allowed: contains traversal or absolute path"),
            else => return err,
        };
        defer path_info.deinit(allocator);

        const full_path = path_info.full_path;
        const ws_str = path_info.workspacePath();
        const resolved_target: ?[]const u8 = fs_compat.realpathAllocPath(allocator, full_path) catch |err| switch (err) {
            error.FileNotFound => null,
            else => {
                const msg = try std.fmt.allocPrint(allocator, "Failed to resolve file path: {} ({s})", .{ err, path });
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            },
        };
        defer if (resolved_target) |rt| allocator.free(rt);

        const parent_to_check = std_compat.fs.path.dirname(full_path) orelse full_path;
        const resolved_ancestor = resolveNearestExistingAncestor(allocator, parent_to_check) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to resolve file path: {} ({s})", .{ err, path });
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(resolved_ancestor);

        if (!isResolvedPathAllowed(allocator, resolved_ancestor, ws_str, self.allowed_paths)) {
            return ToolResult.fail("Path is outside allowed areas");
        }

        const bootstrap_filename = bootstrapRootFilename(path);
        if (bootstrap_filename) |filename| {
            if (self.bootstrap_provider) |bp| {
                if (!bootstrap_mod.backendUsesFiles(self.backend_name)) {
                    const existing = try bp.load(allocator, filename);
                    defer if (existing) |e| allocator.free(e);

                    if (existing) |e| {
                        if (e.len > self.max_file_size) {
                            const msg = try std.fmt.allocPrint(
                                allocator,
                                "Failed to read file: FileTooBig (limit: {} bytes)",
                                .{self.max_file_size},
                            );
                            return ToolResult{ .success = false, .output = "", .error_msg = msg };
                        }
                    }

                    const new_contents = if (existing) |e|
                        try std.mem.concat(allocator, u8, &.{ e, content })
                    else
                        try allocator.dupe(u8, content);
                    defer allocator.free(new_contents);

                    try bp.store(filename, new_contents);

                    const msg = try std.fmt.allocPrint(allocator, "Appended {d} bytes to {s} (memory backend)", .{ content.len, path });
                    return ToolResult{ .success = true, .output = msg };
                }
            }
        }

        const existing_is_symlink = if (resolved_target != null) blk: {
            if (comptime builtin.os.tag == .windows) break :blk false;
            break :blk isSymlinkPath(full_path) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to inspect path: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
        } else false;

        if (resolved_target) |resolved| {
            if (comptime builtin.os.tag == .windows) {
                if (!isResolvedPathAllowed(allocator, resolved, ws_str, self.allowed_paths)) {
                    return ToolResult.fail("Path is outside allowed areas");
                }
            } else if (existing_is_symlink) {
                if (!isResolvedPathAllowed(allocator, resolved, ws_str, self.allowed_paths)) {
                    return ToolResult.fail("Path is outside allowed areas");
                }
            }
        }

        // Try to read existing content
        const existing = blk: {
            if (resolved_target == null) break :blk @as(?[]const u8, null);
            const read_path = if (existing_is_symlink) resolved_target.? else full_path;
            const file = fs_compat.openPath(read_path, .{}) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to open file: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
            defer file.close();
            const data = file.readToEndAlloc(allocator, self.max_file_size) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to read file: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
            break :blk @as(?[]const u8, data);
        };
        defer if (existing) |e| allocator.free(e);

        // Build new content
        const new_contents = if (existing) |e|
            try std.mem.concat(allocator, u8, &.{ e, content })
        else
            try allocator.dupe(u8, content);
        defer allocator.free(new_contents);

        const write_path = if (existing_is_symlink)
            try allocator.dupe(u8, resolved_target.?)
        else
            try allocator.dupe(u8, full_path);
        defer allocator.free(write_path);

        const existing_mode: ?std_compat.fs.File.Mode = blk: {
            const st = fs_compat.statPath(write_path) catch |err| switch (err) {
                error.FileNotFound => break :blk null,
                else => {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to stat file: {}", .{err});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                },
            };
            break :blk st.mode;
        };

        // Ensure parent directory exists after policy checks pass.
        if (std_compat.fs.path.dirname(write_path)) |parent_dir_path| {
            std_compat.fs.makeDirAbsolute(parent_dir_path) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => {
                    fs_compat.makePath(parent_dir_path) catch |e| {
                        const msg = try std.fmt.allocPrint(allocator, "Failed to create directory: {}", .{e});
                        return ToolResult{ .success = false, .output = "", .error_msg = msg };
                    };
                },
            };
        }

        const parent = std_compat.fs.path.dirname(write_path) orelse write_path;
        const basename = std_compat.fs.path.basename(write_path);
        var parent_dir = if (std_compat.fs.path.isAbsolute(parent))
            std_compat.fs.openDirAbsolute(parent, .{}) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to open directory: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            }
        else
            fs_compat.openDirPath(parent, .{}) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to open directory: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
        defer parent_dir.close();

        var tmp_name_buf: [128]u8 = undefined;
        var tmp_name_len: usize = 0;
        var tmp_file: ?std_compat.fs.File = null;
        var attempt: usize = 0;
        while (attempt < 32) : (attempt += 1) {
            const tmp_name = std.fmt.bufPrint(
                &tmp_name_buf,
                ".nullclaw-append-{d}-{d}.tmp",
                .{ std_compat.time.nanoTimestamp(), attempt },
            ) catch unreachable;
            tmp_file = parent_dir.createFile(tmp_name, .{ .exclusive = true }) catch |err| switch (err) {
                error.PathAlreadyExists => continue,
                else => {
                    const msg = try std.fmt.allocPrint(allocator, "Failed to create/open file: {}", .{err});
                    return ToolResult{ .success = false, .output = "", .error_msg = msg };
                },
            };
            tmp_name_len = tmp_name.len;
            break;
        }
        if (tmp_file == null) {
            return ToolResult.fail("Failed to create temporary file");
        }

        var file_w = tmp_file.?;
        defer file_w.close();

        if (comptime std_compat.fs.has_executable_bit) {
            if (existing_mode) |mode| {
                if (mode != 0) {
                    file_w.chmod(mode) catch |err| {
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

        file_w.writeAll(new_contents) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to write file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        parent_dir.rename(tmp_name_buf[0..tmp_name_len], basename) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to replace file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        committed = true;

        const final_resolved = fs_compat.realpathAllocPath(allocator, write_path) catch {
            if (std_compat.fs.path.isAbsolute(write_path)) {
                std_compat.fs.deleteFileAbsolute(write_path) catch {};
            } else {
                fs_compat.deletePath(write_path) catch {};
            }
            return ToolResult.fail("Failed to verify created file location");
        };
        defer allocator.free(final_resolved);

        if (!isResolvedPathAllowed(allocator, final_resolved, ws_str, self.allowed_paths)) {
            if (std_compat.fs.path.isAbsolute(write_path)) {
                std_compat.fs.deleteFileAbsolute(write_path) catch {};
            } else {
                fs_compat.deletePath(write_path) catch {};
            }
            return ToolResult.fail("Path is outside allowed areas");
        }

        const msg = try std.fmt.allocPrint(allocator, "Appended {d} bytes to {s}", .{ content.len, path });
        return ToolResult{ .success = true, .output = msg };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "FileAppendTool name and description" {
    var fat = FileAppendTool{ .workspace_dir = "/tmp" };
    const t = fat.tool();
    try testing.expectEqualStrings("file_append", t.name());
    try testing.expect(t.description().len > 0);
    try testing.expect(t.parametersJson()[0] == '{');
}

test "FileAppendTool missing path" {
    var fat = FileAppendTool{ .workspace_dir = "/tmp" };
    const parsed = try root.parseTestArgs("{\"content\":\"hello\"}");
    defer parsed.deinit();
    const result = try fat.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expectEqualStrings("Missing 'path' parameter", result.error_msg.?);
}

test "FileAppendTool missing content" {
    var fat = FileAppendTool{ .workspace_dir = "/tmp" };
    const parsed = try root.parseTestArgs("{\"path\":\"test.txt\"}");
    defer parsed.deinit();
    const result = try fat.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expectEqualStrings("Missing 'content' parameter", result.error_msg.?);
}

test "FileAppendTool blocks path traversal" {
    var fat = FileAppendTool{ .workspace_dir = "/tmp/workspace" };
    const parsed = try root.parseTestArgs("{\"path\":\"../../etc/evil\",\"content\":\"x\"}");
    defer parsed.deinit();
    const result = try fat.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not allowed") != null);
}

test "FileAppendTool appends to existing file" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "log.txt", .data = "line1" });

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(ws_path);

    var fat = FileAppendTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\":\"log.txt\",\"content\":\"line2\"}");
    defer parsed.deinit();
    const result = try fat.execute(testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) testing.allocator.free(result.output);
    defer if (result.error_msg) |e| testing.allocator.free(e);

    try testing.expect(result.success);
    try testing.expect(std.mem.indexOf(u8, result.output, "Appended") != null);

    const actual = try fs_compat.readFileAlloc(tmp_dir.dir, testing.allocator, "log.txt", 4096);
    defer testing.allocator.free(actual);
    try testing.expectEqualStrings("line1line2", actual);
}

test "FileAppendTool creates new file" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(ws_path);

    var fat = FileAppendTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\":\"new.txt\",\"content\":\"hello\"}");
    defer parsed.deinit();
    const result = try fat.execute(testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) testing.allocator.free(result.output);
    defer if (result.error_msg) |e| testing.allocator.free(e);

    try testing.expect(result.success);

    const actual = try fs_compat.readFileAlloc(tmp_dir.dir, testing.allocator, "new.txt", 4096);
    defer testing.allocator.free(actual);
    try testing.expectEqualStrings("hello", actual);
}

test "FileAppendTool creates parent dirs for new file" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(ws_path);

    var fat = FileAppendTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\":\"logs/2026/output.txt\",\"content\":\"hello\"}");
    defer parsed.deinit();
    const result = try fat.execute(testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) testing.allocator.free(result.output);
    defer if (result.error_msg) |e| testing.allocator.free(e);

    try testing.expect(result.success);

    const actual = try fs_compat.readFileAlloc(tmp_dir.dir, testing.allocator, "logs/2026/output.txt", 4096);
    defer testing.allocator.free(actual);
    try testing.expectEqualStrings("hello", actual);
}

test "FileAppendTool appends to empty file" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "empty.txt", .data = "" });

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(ws_path);

    var fat = FileAppendTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\":\"empty.txt\",\"content\":\"data\"}");
    defer parsed.deinit();
    const result = try fat.execute(testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) testing.allocator.free(result.output);
    defer if (result.error_msg) |e| testing.allocator.free(e);

    try testing.expect(result.success);

    const actual = try fs_compat.readFileAlloc(tmp_dir.dir, testing.allocator, "empty.txt", 4096);
    defer testing.allocator.free(actual);
    try testing.expectEqualStrings("data", actual);
}

test "FileAppendTool multiple appends" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "multi.txt", .data = "A" });

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(ws_path);

    var fat = FileAppendTool{ .workspace_dir = ws_path };

    const p1 = try root.parseTestArgs("{\"path\":\"multi.txt\",\"content\":\"B\"}");
    defer p1.deinit();
    const r1 = try fat.execute(testing.allocator, p1.value.object);
    defer if (r1.output.len > 0) testing.allocator.free(r1.output);
    defer if (r1.error_msg) |e| testing.allocator.free(e);
    try testing.expect(r1.success);

    const p2 = try root.parseTestArgs("{\"path\":\"multi.txt\",\"content\":\"C\"}");
    defer p2.deinit();
    const r2 = try fat.execute(testing.allocator, p2.value.object);
    defer if (r2.output.len > 0) testing.allocator.free(r2.output);
    defer if (r2.error_msg) |e| testing.allocator.free(e);
    try testing.expect(r2.success);

    const actual = try fs_compat.readFileAlloc(tmp_dir.dir, testing.allocator, "multi.txt", 4096);
    defer testing.allocator.free(actual);
    try testing.expectEqualStrings("ABC", actual);
}

test "FileAppendTool appends bootstrap file in memory backend" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(ws_path);

    var lru = @import("../memory/root.zig").InMemoryLruMemory.init(testing.allocator, 16);
    defer lru.deinit();
    var bp_impl = bootstrap_mod.MemoryBootstrapProvider.init(testing.allocator, lru.memory(), ws_path);
    try bp_impl.provider().store("USER.md", "name: Igor");

    var fat = FileAppendTool{
        .workspace_dir = ws_path,
        .allowed_paths = &.{ws_path},
        .bootstrap_provider = bp_impl.provider(),
        .backend_name = "sqlite",
    };
    const parsed = try root.parseTestArgs("{\"path\":\"USER.md\",\"content\":\"\\nrole: coder\"}");
    defer parsed.deinit();
    const result = try fat.execute(testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) testing.allocator.free(result.output);
    defer if (result.error_msg) |e| testing.allocator.free(e);

    try testing.expect(result.success);
    try testing.expect(std.mem.indexOf(u8, result.output, "memory backend") != null);

    const actual = try bp_impl.provider().load(testing.allocator, "USER.md") orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(actual);
    try testing.expectEqualStrings("name: Igor\nrole: coder", actual);
    try testing.expectError(error.FileNotFound, @import("compat").fs.Dir.wrap(tmp_dir.dir).openFile("USER.md", .{}));
}

test "FileAppendTool rejects disallowed absolute path without creating parent directories" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    var ws_tmp = testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    var outside_tmp = testing.tmpDir(.{});
    defer outside_tmp.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(ws_tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(ws_path);
    const outside_path = try @import("compat").fs.Dir.wrap(outside_tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(outside_path);

    const outside_parent = try std_compat.fs.path.join(testing.allocator, &.{ outside_path, "created_by_rejected_append" });
    defer testing.allocator.free(outside_parent);
    const outside_file = try std_compat.fs.path.join(testing.allocator, &.{ outside_parent, "rejected.txt" });
    defer testing.allocator.free(outside_file);

    const json_args = try std.fmt.allocPrint(testing.allocator, "{{\"path\":\"{s}\",\"content\":\"x\"}}", .{outside_file});
    defer testing.allocator.free(json_args);

    var fat = FileAppendTool{ .workspace_dir = ws_path, .allowed_paths = &.{ws_path} };
    const parsed = try root.parseTestArgs(json_args);
    defer parsed.deinit();

    // Regression: wiring file_append into runtime must not create outside files before policy rejection.
    const result = try fat.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expect(std.mem.indexOf(u8, result.error_msg.?, "outside allowed areas") != null);

    const dir_exists = blk: {
        var dir = std_compat.fs.openDirAbsolute(outside_parent, .{}) catch |err| switch (err) {
            error.FileNotFound => break :blk false,
            else => return err,
        };
        dir.close();
        break :blk true;
    };
    try testing.expect(!dir_exists);
}

test "FileAppendTool blocks symlink parent escape outside workspace" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    var ws_tmp = testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    var outside_tmp = testing.tmpDir(.{});
    defer outside_tmp.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(ws_tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(ws_path);
    const outside_path = try @import("compat").fs.Dir.wrap(outside_tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(outside_path);

    try @import("compat").fs.Dir.wrap(ws_tmp.dir).symLink(outside_path, "escape", .{});

    const outside_file = try std_compat.fs.path.join(testing.allocator, &.{ outside_path, "pwned.txt" });
    defer testing.allocator.free(outside_file);

    var fat = FileAppendTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\":\"escape/pwned.txt\",\"content\":\"boom\"}");
    defer parsed.deinit();

    // Regression: appending through a symlinked parent must be rejected before any write occurs.
    const result = try fat.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expect(std.mem.indexOf(u8, result.error_msg.?, "outside allowed areas") != null);

    const file_exists = blk: {
        const file = std_compat.fs.openFileAbsolute(outside_file, .{}) catch |err| switch (err) {
            error.FileNotFound => break :blk false,
            else => return err,
        };
        file.close();
        break :blk true;
    };
    try testing.expect(!file_exists);
}

test "FileAppendTool does not mutate outside inode through hard link" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    var ws_tmp = testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    var outside_tmp = testing.tmpDir(.{});
    defer outside_tmp.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(ws_tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(ws_path);
    const outside_path = try @import("compat").fs.Dir.wrap(outside_tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(outside_path);

    try @import("compat").fs.Dir.wrap(outside_tmp.dir).writeFile(.{ .sub_path = "outside.txt", .data = "SAFE" });
    const outside_file = try std_compat.fs.path.join(testing.allocator, &.{ outside_path, "outside.txt" });
    defer testing.allocator.free(outside_file);
    const hardlink_path = try std_compat.fs.path.join(testing.allocator, &.{ ws_path, "hl.txt" });
    defer testing.allocator.free(hardlink_path);

    try std_compat.fs.hardLinkAbsolute(outside_file, hardlink_path, .{});

    var fat = FileAppendTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\":\"hl.txt\",\"content\":\"++\"}");
    defer parsed.deinit();

    // Regression: appending via a workspace hard link must not modify an outside inode in place.
    const result = try fat.execute(testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) testing.allocator.free(result.output);
    defer if (result.error_msg) |e| testing.allocator.free(e);

    try testing.expect(result.success);

    const workspace_actual = try fs_compat.readFileAlloc(ws_tmp.dir, testing.allocator, "hl.txt", 1024);
    defer testing.allocator.free(workspace_actual);
    try testing.expectEqualStrings("SAFE++", workspace_actual);

    const outside_actual = try fs_compat.readFileAlloc(outside_tmp.dir, testing.allocator, "outside.txt", 1024);
    defer testing.allocator.free(outside_actual);
    try testing.expectEqualStrings("SAFE", outside_actual);
}

test "FileAppendTool keeps symlink and updates target" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    var ws_tmp = testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(ws_tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(ws_path);

    try @import("compat").fs.Dir.wrap(ws_tmp.dir).writeFile(.{ .sub_path = "target.txt", .data = "old" });
    try @import("compat").fs.Dir.wrap(ws_tmp.dir).symLink("target.txt", "link.txt", .{});

    var fat = FileAppendTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\":\"link.txt\",\"content\":\"new\"}");
    defer parsed.deinit();

    const result = try fat.execute(testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) testing.allocator.free(result.output);
    defer if (result.error_msg) |e| testing.allocator.free(e);
    try testing.expect(result.success);

    var link_buf: [std_compat.fs.max_path_bytes]u8 = undefined;
    const link_target = try std_compat.fs.Dir.wrap(ws_tmp.dir).readLink("link.txt", &link_buf);
    try testing.expectEqualStrings("target.txt", link_target);

    const target_actual = try fs_compat.readFileAlloc(ws_tmp.dir, testing.allocator, "target.txt", 1024);
    defer testing.allocator.free(target_actual);
    try testing.expectEqualStrings("oldnew", target_actual);
}

test "FileAppendTool does not bypass allowed_paths for bootstrap memory appends" {
    var ws_tmp = testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    var outside_tmp = testing.tmpDir(.{});
    defer outside_tmp.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(ws_tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(ws_path);
    const outside_path = try @import("compat").fs.Dir.wrap(outside_tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(outside_path);

    try @import("compat").fs.Dir.wrap(outside_tmp.dir).writeFile(.{ .sub_path = "AGENTS.md", .data = "outside-before" });
    const outside_file = try std_compat.fs.path.join(testing.allocator, &.{ outside_path, "AGENTS.md" });
    defer testing.allocator.free(outside_file);

    var escaped_buf: [1024]u8 = undefined;
    var esc_len: usize = 0;
    for (outside_file) |c| {
        if (c == '\\') {
            escaped_buf[esc_len] = '\\';
            esc_len += 1;
        }
        escaped_buf[esc_len] = c;
        esc_len += 1;
    }

    const json_args = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"path\":\"{s}\",\"content\":\"\\ndenied\"}}",
        .{escaped_buf[0..esc_len]},
    );
    defer testing.allocator.free(json_args);

    var lru = memory_root.InMemoryLruMemory.init(testing.allocator, 16);
    defer lru.deinit();
    var bp_impl = bootstrap_mod.MemoryBootstrapProvider.init(testing.allocator, lru.memory(), null);
    try bp_impl.provider().store("AGENTS.md", "alpha");

    var fat = FileAppendTool{
        .workspace_dir = ws_path,
        .allowed_paths = &.{ws_path},
        .bootstrap_provider = bp_impl.provider(),
        .backend_name = "sqlite",
    };
    const parsed = try root.parseTestArgs(json_args);
    defer parsed.deinit();

    const result = try fat.execute(testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) testing.allocator.free(result.output);
    try testing.expect(!result.success);
    try testing.expect(std.mem.indexOf(u8, result.error_msg.?, "outside allowed areas") != null);

    const content = try bp_impl.provider().load(testing.allocator, "AGENTS.md") orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(content);
    try testing.expectEqualStrings("alpha", content);

    const outside_after = try fs_compat.readFileAlloc(outside_tmp.dir, testing.allocator, "AGENTS.md", 1024);
    defer testing.allocator.free(outside_after);
    try testing.expectEqualStrings("outside-before", outside_after);
}

test "FileAppendTool schema has required params" {
    var fat = FileAppendTool{ .workspace_dir = "/tmp" };
    const t = fat.tool();
    const schema = t.parametersJson();
    try testing.expect(std.mem.indexOf(u8, schema, "path") != null);
    try testing.expect(std.mem.indexOf(u8, schema, "content") != null);
}
