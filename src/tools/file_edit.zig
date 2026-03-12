const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isPathSafe = @import("path_security.zig").isPathSafe;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;
const bootstrap_mod = @import("../bootstrap/root.zig");
const memory_root = @import("../memory/root.zig");

/// Default maximum file size to read for editing (10MB).
const DEFAULT_MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

/// Find and replace text in a file with workspace path scoping.
pub const FileEditTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    max_file_size: usize = DEFAULT_MAX_FILE_SIZE,
    bootstrap_provider: ?bootstrap_mod.BootstrapProvider = null,
    backend_name: []const u8 = "hybrid",

    pub const tool_name = "file_edit";
    pub const tool_description = "Find and replace text in a file";
    pub const tool_params =
        \\{"type":"object","properties":{"path":{"type":"string","description":"Relative path to the file within the workspace"},"old_text":{"type":"string","description":"Text to find in the file"},"new_text":{"type":"string","description":"Replacement text"}},"required":["path","old_text","new_text"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *FileEditTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *FileEditTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const path = root.getString(args, "path") orelse
            return ToolResult.fail("Missing 'path' parameter");

        const old_text = root.getString(args, "old_text") orelse
            return ToolResult.fail("Missing 'old_text' parameter");

        const new_text = root.getString(args, "new_text") orelse
            return ToolResult.fail("Missing 'new_text' parameter");

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
        const bootstrap_filename = bootstrapRootFilename(path);

        // Intercept bootstrap file edits for non-file backends.
        if (bootstrap_filename) |filename| {
            if (self.bootstrap_provider) |bp| {
                if (!bootstrap_mod.backendUsesFiles(self.backend_name)) {
                    const parent_to_check = std.fs.path.dirname(full_path) orelse full_path;
                    const resolved_ancestor = resolveNearestExistingAncestor(allocator, parent_to_check) catch |err| {
                        const msg = try std.fmt.allocPrint(allocator, "Failed to resolve file path: {} ({s})", .{ err, path });
                        return ToolResult{ .success = false, .output = "", .error_msg = msg };
                    };
                    defer allocator.free(resolved_ancestor);

                    if (!isResolvedPathAllowed(allocator, resolved_ancestor, ws_path, self.allowed_paths)) {
                        return ToolResult.fail("Path is outside allowed areas");
                    }

                    const existing = try bp.load(allocator, filename) orelse
                        return ToolResult.fail("File not found in memory backend");
                    defer allocator.free(existing);

                    if (old_text.len == 0)
                        return ToolResult.fail("old_text must not be empty");

                    const pos = std.mem.indexOf(u8, existing, old_text) orelse
                        return ToolResult.fail("old_text not found in file");

                    const before = existing[0..pos];
                    const after = existing[pos + old_text.len ..];
                    const new_contents = try std.mem.concat(allocator, u8, &.{ before, new_text, after });
                    defer allocator.free(new_contents);

                    try bp.store(filename, new_contents);
                    const msg = try std.fmt.allocPrint(allocator, "Replaced {d} bytes with {d} bytes in {s} (memory backend)", .{ old_text.len, new_text.len, path });
                    return ToolResult{ .success = true, .output = msg };
                }
            }
        }

        // Resolve to catch symlink escapes
        const resolved = std.fs.cwd().realpathAlloc(allocator, full_path) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to resolve file path: {} ({s})", .{ err, path });
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(resolved);

        // Validate against workspace + allowed_paths + system blocklist
        if (!isResolvedPathAllowed(allocator, resolved, ws_path, self.allowed_paths)) {
            return ToolResult.fail("Path is outside allowed areas");
        }

        // Read existing file contents
        const file_r = std.fs.openFileAbsolute(resolved, .{}) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to open file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        const contents = file_r.readToEndAlloc(allocator, self.max_file_size) catch |err| {
            file_r.close();
            const msg = try std.fmt.allocPrint(allocator, "Failed to read file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        file_r.close();
        defer allocator.free(contents);

        // old_text must not be empty
        if (old_text.len == 0) {
            return ToolResult.fail("old_text must not be empty");
        }

        // Find first occurrence of old_text
        const pos = std.mem.indexOf(u8, contents, old_text) orelse {
            return ToolResult.fail("old_text not found in file");
        };

        // Build new contents: before + new_text + after
        const before = contents[0..pos];
        const after = contents[pos + old_text.len ..];
        const new_contents = try std.mem.concat(allocator, u8, &.{ before, new_text, after });
        defer allocator.free(new_contents);

        // Write back
        const file_w = std.fs.createFileAbsolute(resolved, .{ .truncate = true }) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to write file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer file_w.close();

        file_w.writeAll(new_contents) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to write file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        const msg = try std.fmt.allocPrint(allocator, "Replaced {d} bytes with {d} bytes in {s}", .{ old_text.len, new_text.len, path });
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

fn bootstrapRootFilename(path: []const u8) ?[]const u8 {
    if (std.fs.path.isAbsolute(path)) return null;
    const basename = std.fs.path.basename(path);
    if (!std.mem.eql(u8, basename, path)) return null;
    if (!bootstrap_mod.isBootstrapFilename(basename)) return null;
    return basename;
}

// ── Tests ───────────────────────────────────────────────────────────

test "file_edit tool name" {
    var ft = FileEditTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    try std.testing.expectEqualStrings("file_edit", t.name());
}

test "file_edit tool schema has required params" {
    var ft = FileEditTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "path") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "old_text") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "new_text") != null);
}

test "file_edit basic replace" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = "hello world" });

    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileEditTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"test.txt\", \"old_text\": \"world\", \"new_text\": \"zig\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "Replaced") != null);

    // Verify file contents
    const actual = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "test.txt", 1024);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings("hello zig", actual);
}

test "file_edit old_text not found" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = "hello world" });

    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileEditTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"test.txt\", \"old_text\": \"missing\", \"new_text\": \"replacement\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    // error_msg is a static string from ToolResult.fail(), don't free it

    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
}

test "file_edit nonexistent file error includes requested path" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileEditTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"missing.txt\", \"old_text\": \"old\", \"new_text\": \"new\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "missing.txt") != null);
}

test "file_edit empty file returns not found" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = "empty.txt", .data = "" });

    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileEditTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"empty.txt\", \"old_text\": \"something\", \"new_text\": \"other\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    // error_msg is a static string from ToolResult.fail(), don't free it

    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
}

test "file_edit replaces only first occurrence" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = "dup.txt", .data = "aaa bbb aaa" });

    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileEditTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"dup.txt\", \"old_text\": \"aaa\", \"new_text\": \"ccc\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);

    const actual = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "dup.txt", 1024);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings("ccc bbb aaa", actual);
}

test "file_edit blocks path traversal" {
    var ft = FileEditTool{ .workspace_dir = "/tmp/workspace" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"../../etc/evil\", \"old_text\": \"a\", \"new_text\": \"b\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not allowed") != null);
}

test "file_edit missing path param" {
    var ft = FileEditTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"old_text\": \"a\", \"new_text\": \"b\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_edit missing old_text param" {
    var ft = FileEditTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"file.txt\", \"new_text\": \"b\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_edit missing new_text param" {
    var ft = FileEditTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"file.txt\", \"old_text\": \"a\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_edit empty old_text" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = "content" });

    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileEditTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"test.txt\", \"old_text\": \"\", \"new_text\": \"new\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    // error_msg is a static string from ToolResult.fail(), don't free it

    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "must not be empty") != null);
}

// ── Absolute path support tests ─────────────────────────────────────

test "file_edit absolute path without allowed_paths is rejected" {
    var ft = FileEditTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"/tmp/file.txt\", \"old_text\": \"a\", \"new_text\": \"b\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Absolute paths not allowed") != null);
}

test "file_edit absolute path with allowed_paths works" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = "hello world" });

    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const abs_file = try std.fs.path.join(std.testing.allocator, &.{ ws_path, "test.txt" });
    defer std.testing.allocator.free(abs_file);

    // JSON-escape backslashes in the path (needed on Windows where paths use \)
    var escaped_buf: [1024]u8 = undefined;
    var esc_len: usize = 0;
    for (abs_file) |c| {
        if (c == '\\') {
            escaped_buf[esc_len] = '\\';
            esc_len += 1;
        }
        escaped_buf[esc_len] = c;
        esc_len += 1;
    }

    // Use a different workspace but allow tmp_dir via allowed_paths
    var args_buf: [2048]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"path\": \"{s}\", \"old_text\": \"world\", \"new_text\": \"zig\"}}", .{escaped_buf[0..esc_len]});
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();

    var ft = FileEditTool{ .workspace_dir = "/nonexistent", .allowed_paths = &.{ws_path} };
    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);

    const actual = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "test.txt", 1024);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings("hello zig", actual);
}

test "file_edit does not bypass allowed_paths for bootstrap memory edits" {
    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    var outside_tmp = std.testing.tmpDir(.{});
    defer outside_tmp.cleanup();

    const ws_path = try ws_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const outside_path = try outside_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(outside_path);

    try outside_tmp.dir.writeFile(.{ .sub_path = "AGENTS.md", .data = "outside-before" });
    const outside_file = try std.fs.path.join(std.testing.allocator, &.{ outside_path, "AGENTS.md" });
    defer std.testing.allocator.free(outside_file);

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
        std.testing.allocator,
        "{{\"path\":\"{s}\",\"old_text\":\"outside-before\",\"new_text\":\"outside-after\"}}",
        .{escaped_buf[0..esc_len]},
    );
    defer std.testing.allocator.free(json_args);

    var lru = memory_root.InMemoryLruMemory.init(std.testing.allocator, 16);
    defer lru.deinit();
    var bp_impl = bootstrap_mod.MemoryBootstrapProvider.init(std.testing.allocator, lru.memory(), null);
    try bp_impl.provider().store("AGENTS.md", "alpha");

    var ft = FileEditTool{
        .workspace_dir = ws_path,
        .allowed_paths = &.{ws_path},
        .bootstrap_provider = bp_impl.provider(),
        .backend_name = "sqlite",
    };
    const t = ft.tool();
    const parsed = try root.parseTestArgs(json_args);
    defer parsed.deinit();

    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "outside allowed areas") != null);

    const content = try bp_impl.provider().load(std.testing.allocator, "AGENTS.md") orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("alpha", content);

    const outside_after = try outside_tmp.dir.readFileAlloc(std.testing.allocator, "AGENTS.md", 1024);
    defer std.testing.allocator.free(outside_after);
    try std.testing.expectEqualStrings("outside-before", outside_after);
}
