//! File Append Tool — append content to the end of a file within workspace.
//!
//! Creates the file if it doesn't exist. Uses workspace path scoping
//! and the same path safety checks as file_edit.

const std = @import("std");
const fs_compat = @import("../fs_compat.zig");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isPathSafe = @import("path_security.zig").isPathSafe;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;

/// Default maximum file size to read before appending (10MB).
const DEFAULT_MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

/// Append content to the end of a file with workspace path scoping.
pub const FileAppendTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    max_file_size: usize = DEFAULT_MAX_FILE_SIZE,

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

        // Resolve workspace path (may fail if workspace doesn't exist yet)
        const ws_resolved: ?[]const u8 = std.fs.cwd().realpathAlloc(allocator, self.workspace_dir) catch null;
        defer if (ws_resolved) |wr| allocator.free(wr);
        const ws_str = ws_resolved orelse "";

        // Try to read existing content
        const existing = blk: {
            const resolved = std.fs.cwd().realpathAlloc(allocator, full_path) catch {
                break :blk @as(?[]const u8, null);
            };
            defer allocator.free(resolved);

            if (!isResolvedPathAllowed(allocator, resolved, ws_str, self.allowed_paths)) {
                return ToolResult.fail("Path is outside allowed areas");
            }

            const file = std.fs.openFileAbsolute(resolved, .{}) catch |err| {
                const msg = try std.fmt.allocPrint(allocator, "Failed to open file: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
            const data = file.readToEndAlloc(allocator, self.max_file_size) catch |err| {
                file.close();
                const msg = try std.fmt.allocPrint(allocator, "Failed to read file: {}", .{err});
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };
            file.close();
            break :blk @as(?[]const u8, data);
        };
        defer if (existing) |e| allocator.free(e);

        // Build new content
        const new_contents = if (existing) |e|
            try std.mem.concat(allocator, u8, &.{ e, content })
        else
            try allocator.dupe(u8, content);
        defer allocator.free(new_contents);

        // Write back
        const file_w = std.fs.cwd().createFile(full_path, .{ .truncate = true }) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to create/open file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer file_w.close();

        file_w.writeAll(new_contents) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to write file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        // Verify newly created files are within allowed areas
        if (existing == null) {
            const new_resolved = std.fs.cwd().realpathAlloc(allocator, full_path) catch {
                std.fs.cwd().deleteFile(full_path) catch {};
                return ToolResult.fail("Failed to verify created file location");
            };
            defer allocator.free(new_resolved);
            if (!isResolvedPathAllowed(allocator, new_resolved, ws_str, self.allowed_paths)) {
                std.fs.cwd().deleteFile(full_path) catch {};
                return ToolResult.fail("Created file is outside allowed areas");
            }
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
    try tmp_dir.dir.writeFile(.{ .sub_path = "log.txt", .data = "line1" });

    const ws_path = try tmp_dir.dir.realpathAlloc(testing.allocator, ".");
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

    const ws_path = try tmp_dir.dir.realpathAlloc(testing.allocator, ".");
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

test "FileAppendTool appends to empty file" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = "empty.txt", .data = "" });

    const ws_path = try tmp_dir.dir.realpathAlloc(testing.allocator, ".");
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
    try tmp_dir.dir.writeFile(.{ .sub_path = "multi.txt", .data = "A" });

    const ws_path = try tmp_dir.dir.realpathAlloc(testing.allocator, ".");
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

test "FileAppendTool schema has required params" {
    var fat = FileAppendTool{ .workspace_dir = "/tmp" };
    const t = fat.tool();
    const schema = t.parametersJson();
    try testing.expect(std.mem.indexOf(u8, schema, "path") != null);
    try testing.expect(std.mem.indexOf(u8, schema, "content") != null);
}
