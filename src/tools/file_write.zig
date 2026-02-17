const std = @import("std");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;

/// Write file contents with workspace path scoping.
pub const FileWriteTool = struct {
    workspace_dir: []const u8,

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *FileWriteTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *FileWriteTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "file_write";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Write contents to a file in the workspace";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"path":{"type":"string","description":"Relative path to the file within the workspace"},"content":{"type":"string","description":"Content to write to the file"}},"required":["path","content"]}
        ;
    }

    fn execute(self: *FileWriteTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const rel_path = parseStringField(args_json, "path") orelse
            return ToolResult.fail("Missing 'path' parameter");

        const content = parseStringField(args_json, "content") orelse
            return ToolResult.fail("Missing 'content' parameter");

        // Block path traversal
        if (!isPathSafe(rel_path)) {
            return ToolResult.fail("Path not allowed: contains traversal or absolute path");
        }

        // Build full path
        const full_path = try std.fs.path.join(allocator, &.{ self.workspace_dir, rel_path });
        defer allocator.free(full_path);

        // Ensure parent directory exists
        if (std.fs.path.dirname(full_path)) |parent| {
            std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => {
                    // Try creating intermediate dirs
                    std.fs.cwd().makePath(parent) catch |e| {
                        const msg = try std.fmt.allocPrint(allocator, "Failed to create directory: {}", .{e});
                        return ToolResult{ .success = false, .output = "", .error_msg = msg };
                    };
                },
            };

            // Resolve parent to block symlink escapes
            const resolved_parent = std.fs.cwd().realpathAlloc(allocator, parent) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to resolve path: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
            defer allocator.free(resolved_parent);

            const ws_resolved = std.fs.cwd().realpathAlloc(allocator, self.workspace_dir) catch {
                return ToolResult.fail("Failed to resolve workspace directory");
            };
            defer allocator.free(ws_resolved);

            if (!std.mem.startsWith(u8, resolved_parent, ws_resolved)) {
                return ToolResult.fail("Resolved path escapes workspace");
            }
        }

        // Write file
        const file = std.fs.createFileAbsolute(full_path, .{}) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to create file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer file.close();

        file.writeAll(content) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to write file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        const msg = try std.fmt.allocPrint(allocator, "Written {d} bytes to {s}", .{ content.len, rel_path });
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
    const result = try t.execute(std.testing.allocator, "{\"path\": \"out.txt\", \"content\": \"written!\"}");
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
    const result = try t.execute(std.testing.allocator, "{\"path\": \"a/b/c/deep.txt\", \"content\": \"deep\"}");
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
    const result = try t.execute(std.testing.allocator, "{\"path\": \"exist.txt\", \"content\": \"new\"}");
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
    const result = try t.execute(std.testing.allocator, "{\"path\": \"../../etc/evil\", \"content\": \"bad\"}");
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not allowed") != null);
}

test "file_write blocks absolute path" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp/workspace" };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{\"path\": \"/etc/evil\", \"content\": \"bad\"}");
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_write missing path param" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{\"content\": \"data\"}");
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_write missing content param" {
    var ft = FileWriteTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{\"path\": \"file.txt\"}");
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
    const result = try t.execute(std.testing.allocator, "{\"path\": \"empty.txt\", \"content\": \"\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "0 bytes") != null);
}
