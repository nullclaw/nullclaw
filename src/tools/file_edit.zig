const std = @import("std");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;

/// Maximum file size to read for editing (10MB).
const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

/// Find and replace text in a file with workspace path scoping.
pub const FileEditTool = struct {
    workspace_dir: []const u8,

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *FileEditTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *FileEditTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "file_edit";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Find and replace text in a file";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"path":{"type":"string","description":"Relative path to the file within the workspace"},"old_text":{"type":"string","description":"Text to find in the file"},"new_text":{"type":"string","description":"Replacement text"}},"required":["path","old_text","new_text"]}
        ;
    }

    fn execute(self: *FileEditTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const rel_path = parseStringField(args_json, "path") orelse
            return ToolResult.fail("Missing 'path' parameter");

        const old_text = parseStringField(args_json, "old_text") orelse
            return ToolResult.fail("Missing 'old_text' parameter");

        const new_text = parseStringField(args_json, "new_text") orelse
            return ToolResult.fail("Missing 'new_text' parameter");

        // Block path traversal
        if (!isPathSafe(rel_path)) {
            return ToolResult.fail("Path not allowed: contains traversal or absolute path");
        }

        // Build full path
        const full_path = try std.fs.path.join(allocator, &.{ self.workspace_dir, rel_path });
        defer allocator.free(full_path);

        // Resolve to catch symlink escapes
        const resolved = std.fs.cwd().realpathAlloc(allocator, full_path) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to resolve file path: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(resolved);

        // Ensure resolved path is still within workspace
        const ws_resolved = std.fs.cwd().realpathAlloc(allocator, self.workspace_dir) catch {
            return ToolResult.fail("Failed to resolve workspace directory");
        };
        defer allocator.free(ws_resolved);

        if (!std.mem.startsWith(u8, resolved, ws_resolved)) {
            return ToolResult.fail("Resolved path escapes workspace");
        }

        // Read existing file contents
        const file_r = std.fs.openFileAbsolute(resolved, .{}) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to open file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        const contents = file_r.readToEndAlloc(allocator, MAX_FILE_SIZE) catch |err| {
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

        const msg = try std.fmt.allocPrint(allocator, "Replaced {d} bytes with {d} bytes in {s}", .{ old_text.len, new_text.len, rel_path });
        return ToolResult{ .success = true, .output = msg };
    }
};

/// Check if a relative path is safe (no traversal, no absolute path).
fn isPathSafe(path: []const u8) bool {
    if (path.len > 0 and path[0] == '/') return false;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return false;
    var iter = std.mem.splitScalar(u8, path, '/');
    while (iter.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }
    return true;
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
    const result = try t.execute(std.testing.allocator, "{\"path\": \"test.txt\", \"old_text\": \"world\", \"new_text\": \"zig\"}");
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
    const result = try t.execute(std.testing.allocator, "{\"path\": \"test.txt\", \"old_text\": \"missing\", \"new_text\": \"replacement\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    // error_msg is a static string from ToolResult.fail(), don't free it

    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
}

test "file_edit empty file returns not found" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = "empty.txt", .data = "" });

    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileEditTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{\"path\": \"empty.txt\", \"old_text\": \"something\", \"new_text\": \"other\"}");
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
    const result = try t.execute(std.testing.allocator, "{\"path\": \"dup.txt\", \"old_text\": \"aaa\", \"new_text\": \"ccc\"}");
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
    const result = try t.execute(std.testing.allocator, "{\"path\": \"../../etc/evil\", \"old_text\": \"a\", \"new_text\": \"b\"}");
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not allowed") != null);
}

test "file_edit missing path param" {
    var ft = FileEditTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{\"old_text\": \"a\", \"new_text\": \"b\"}");
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_edit missing old_text param" {
    var ft = FileEditTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{\"path\": \"file.txt\", \"new_text\": \"b\"}");
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_edit missing new_text param" {
    var ft = FileEditTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{\"path\": \"file.txt\", \"old_text\": \"a\"}");
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
    const result = try t.execute(std.testing.allocator, "{\"path\": \"test.txt\", \"old_text\": \"\", \"new_text\": \"new\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    // error_msg is a static string from ToolResult.fail(), don't free it

    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "must not be empty") != null);
}
