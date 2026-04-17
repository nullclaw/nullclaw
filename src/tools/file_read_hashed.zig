const std = @import("std");
const std_compat = @import("compat");
const fs_compat = @import("../fs_compat.zig");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;
const file_common = @import("file_common.zig");
const getBinaryFileType = @import("file_read.zig").getBinaryFileType;
const isBinaryContent = @import("file_read.zig").isBinaryContent;
const prepareWorkspacePath = file_common.prepareWorkspacePath;

/// Default maximum file size to read (10MB).
const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Generate a 3-character hex hash for a line, including parent context.
pub fn generateLineHash(parent: []const u8, current: []const u8) [3]u8 {
    var hasher = std.hash.Fnv1a_32.init();
    const p_trimmed = std.mem.trim(u8, parent, " \t\r\n");
    const c_trimmed = std.mem.trim(u8, current, " \t\r\n");
    hasher.update(p_trimmed);
    hasher.update("|");
    hasher.update(c_trimmed);
    const hash = hasher.final();
    const truncated = hash & 0xFFF;
    var buf: [3]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{x:0>3}", .{truncated}) catch unreachable;
    return buf;
}

/// Read file contents with Hashline tagging (L<num>:<hash>| content).
pub const FileReadHashedTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    max_file_size: u64 = DEFAULT_MAX_FILE_SIZE,

    pub const tool_name = "file_read_hashed";
    pub const tool_description = "Read file contents with Hashline tagging for precise, verifiable editing";
    pub const tool_params =
        \\{"type":"object","properties":{"path":{"type":"string","description":"Relative path to the file within the workspace"}},"required":["path"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *FileReadHashedTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *FileReadHashedTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const path = root.getString(args, "path") orelse
            return ToolResult.fail("Missing 'path' parameter");

        const path_info = prepareWorkspacePath(allocator, self.workspace_dir, path, self.allowed_paths.len > 0) catch |err| switch (err) {
            error.AbsolutePathsNotAllowed => return ToolResult.fail("Absolute paths not allowed (no allowed_paths configured)"),
            error.PathContainsNullBytes => return ToolResult.fail("Path contains null bytes"),
            error.UnsafePath => return ToolResult.fail("Path not allowed: contains traversal or absolute path"),
            else => return err,
        };
        defer path_info.deinit(allocator);

        const resolved = fs_compat.realpathAllocPath(allocator, path_info.full_path) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to resolve file path: {} ({s})", .{ err, path });
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(resolved);

        if (!isResolvedPathAllowed(allocator, resolved, path_info.workspacePath(), self.allowed_paths)) {
            return ToolResult.fail("Path is outside allowed areas");
        }

        const file = std_compat.fs.openFileAbsolute(resolved, .{}) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to open file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer file.close();

        const stat = try fs_compat.stat(file);
        const max_usize_u64: u64 = @intCast(std.math.maxInt(usize));
        const effective_max_file_size = @min(self.max_file_size, max_usize_u64);
        if (stat.size > effective_max_file_size) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "File too large: {} bytes (limit: {} bytes)",
                .{ stat.size, effective_max_file_size },
            );
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        const contents = file.readToEndAlloc(allocator, @intCast(effective_max_file_size)) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to read file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        errdefer allocator.free(contents);

        if (isBinaryContent(contents)) {
            const file_type = getBinaryFileType(contents, path);
            const msg = try std.fmt.allocPrint(
                allocator,
                "[Binary file detected: {s}, size: {d} bytes. Use [IMAGE:path] marker for images, or appropriate tool for other binary files.]",
                .{ file_type, contents.len },
            );
            allocator.free(contents);
            return ToolResult{ .success = true, .output = msg };
        }
        defer allocator.free(contents);

        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);

        var line_it = std.mem.splitScalar(u8, contents, '\n');
        var line_num: usize = 1;
        var last_line: []const u8 = "";
        while (line_it.next()) |line| {
            const hash = generateLineHash(last_line, line);
            try output.print(allocator, "L{d}:{s}|{s}\n", .{ line_num, hash, line });
            last_line = line;
            line_num += 1;
        }

        return ToolResult{ .success = true, .output = try output.toOwnedSlice(allocator) };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "generateLineHash is context-aware" {
    const h1 = generateLineHash("parent1", "child");
    const h2 = generateLineHash("parent2", "child");
    const h3 = generateLineHash("parent1", "child");

    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
    try std.testing.expectEqualStrings(&h1, &h3);
}

test "file_read_hashed adds tags to lines" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const content = "const x = 1;\nconst y = 2;";
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "test.zig", .data = content });

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadHashedTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\": \"test.zig\"}");
    defer parsed.deinit();

    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);

    try std.testing.expect(result.success);
    // Check first line format L1:hash|content
    try std.testing.expect(std.mem.startsWith(u8, result.output, "L1:"));
    try std.testing.expect(std.mem.indexOf(u8, result.output, "|const x = 1;") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "L2:") != null);
}

test "file_read_hashed reports binary files like file_read" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "test.png", .data = "\x89PNG\r\n\x1a\nrest" });

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadHashedTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\": \"test.png\"}");
    defer parsed.deinit();

    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "Binary file detected") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "PNG image") != null);
}
