const std = @import("std");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;

/// Maximum file size to read (10MB).
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Read file contents with workspace path scoping.
pub const FileReadTool = struct {
    workspace_dir: []const u8,

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *FileReadTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *FileReadTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "file_read";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Read the contents of a file in the workspace";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"path":{"type":"string","description":"Relative path to the file within the workspace"}},"required":["path"]}
        ;
    }

    fn execute(self: *FileReadTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const rel_path = parseStringField(args_json, "path") orelse
            return ToolResult.fail("Missing 'path' parameter");

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

        // Check file size
        const file = std.fs.openFileAbsolute(resolved, .{}) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to open file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer file.close();

        const stat = try file.stat();
        if (stat.size > MAX_FILE_SIZE) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "File too large: {} bytes (limit: {} bytes)",
                .{ stat.size, MAX_FILE_SIZE },
            );
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        // Read contents
        const contents = file.readToEndAlloc(allocator, MAX_FILE_SIZE) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to read file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        return ToolResult{ .success = true, .output = contents };
    }
};

/// Check if a relative path is safe (no traversal, no absolute path).
fn isPathSafe(path: []const u8) bool {
    // Block absolute paths
    if (path.len > 0 and path[0] == '/') return false;

    // Block null bytes
    if (std.mem.indexOfScalar(u8, path, 0) != null) return false;

    // Block ".." components
    var iter = std.mem.splitScalar(u8, path, '/');
    while (iter.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }
    return true;
}

// ── Tests ───────────────────────────────────────────────────────────

test "file_read tool name" {
    var ft = FileReadTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    try std.testing.expectEqualStrings("file_read", t.name());
}

test "file_read tool schema has path" {
    var ft = FileReadTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "path") != null);
}

test "file_read reads existing file" {
    // Create temp dir and file
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = "hello world" });

    // Get the real path of the tmp dir
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{\"path\": \"test.txt\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("hello world", result.output);
}

test "file_read nonexistent file" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{\"path\": \"nope.txt\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
}

test "file_read blocks path traversal" {
    var ft = FileReadTool{ .workspace_dir = "/tmp/workspace" };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{\"path\": \"../../../etc/passwd\"}");
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not allowed") != null);
}

test "file_read blocks absolute path" {
    var ft = FileReadTool{ .workspace_dir = "/tmp/workspace" };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{\"path\": \"/etc/passwd\"}");
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_read missing path param" {
    var ft = FileReadTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{}");
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
}

test "file_read nested path" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.makePath("sub/dir");
    try tmp_dir.dir.writeFile(.{ .sub_path = "sub/dir/deep.txt", .data = "deep content" });

    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{\"path\": \"sub/dir/deep.txt\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("deep content", result.output);
}

test "file_read empty file" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = "empty.txt", .data = "" });

    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const result = try t.execute(std.testing.allocator, "{\"path\": \"empty.txt\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("", result.output);
}

test "isPathSafe blocks null bytes" {
    try std.testing.expect(!isPathSafe("file\x00.txt"));
}

test "isPathSafe allows relative" {
    try std.testing.expect(isPathSafe("file.txt"));
    try std.testing.expect(isPathSafe("src/main.zig"));
}
