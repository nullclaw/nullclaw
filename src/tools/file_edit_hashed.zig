const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isPathSafe = @import("path_security.zig").isPathSafe;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;
const generateLineHash = @import("file_read_hashed.zig").generateLineHash;

/// Default maximum file size to read (10MB).
const DEFAULT_MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

const Target = struct {
    line_num: usize,
    hash: []const u8,

    fn parse(input: []const u8) !Target {
        if (!std.mem.startsWith(u8, input, "L")) return error.InvalidFormat;
        const colon = std.mem.indexOfScalar(u8, input, ':') orelse return error.InvalidFormat;
        const line_num = try std.fmt.parseInt(usize, input[1..colon], 10);
        const hash = input[colon + 1 ..];
        if (hash.len != 3) return error.InvalidHashLength;
        return .{ .line_num = line_num, .hash = hash };
    }
};

const LineInfo = struct {
    start: usize,
    content: []const u8,
};

fn collectLines(allocator: std.mem.Allocator, contents: []const u8, lines: *std.ArrayList(LineInfo)) !void {
    var line_start: usize = 0;
    var idx: usize = 0;

    while (true) {
        if (idx == contents.len or contents[idx] == '\n') {
            try lines.append(allocator, .{
                .start = line_start,
                .content = contents[line_start..idx],
            });
            if (idx == contents.len) break;
            idx += 1;
            line_start = idx;
            continue;
        }
        idx += 1;
    }
}

/// Edit file contents using Hashline anchors for verifiable changes.
pub const FileEditHashedTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    max_file_size: usize = DEFAULT_MAX_FILE_SIZE,

    pub const tool_name = "file_edit_hashed";
    pub const tool_description = "Replace lines in a file using Hashline anchors to ensure edit integrity";
    pub const tool_params =
        \\{"type":"object","properties":{"path":{"type":"string","description":"Relative path to the file"},"target":{"type":"string","description":"The Hashline tag to replace (e.g. L10:abc)"},"end_target":{"type":"string","description":"Optional end tag for range replacement (e.g. L15:def)"},"new_text":{"type":"string","description":"The new content to insert"}},"required":["path","target","new_text"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *FileEditHashedTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *FileEditHashedTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const path = root.getString(args, "path") orelse return ToolResult.fail("Missing 'path' parameter");
        const target_str = root.getString(args, "target") orelse return ToolResult.fail("Missing 'target' parameter");
        const end_target_str = root.getString(args, "end_target");
        const new_text = root.getString(args, "new_text") orelse return ToolResult.fail("Missing 'new_text' parameter");

        const target = Target.parse(target_str) catch return ToolResult.fail("Invalid target format. Use L<num>:<hash>");
        const end_target = if (end_target_str) |s| Target.parse(s) catch return ToolResult.fail("Invalid end_target format") else null;

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

        const resolved = std.fs.cwd().realpathAlloc(allocator, full_path) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to resolve file path: {} ({s})", .{ err, path });
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(resolved);

        if (!isResolvedPathAllowed(allocator, resolved, ws_path, self.allowed_paths)) {
            return ToolResult.fail("Path is outside allowed areas");
        }

        const file = std.fs.openFileAbsolute(resolved, .{}) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to open file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer file.close();

        const stat = file.stat() catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to stat file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        if (stat.size > self.max_file_size) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "File too large: {} bytes (limit: {} bytes)",
                .{ stat.size, self.max_file_size },
            );
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        const contents = file.readToEndAlloc(allocator, self.max_file_size) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to read file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(contents);

        var lines: std.ArrayList(LineInfo) = .{};
        defer lines.deinit(allocator);
        try collectLines(allocator, contents, &lines);

        if (target.line_num == 0 or target.line_num > lines.items.len) return ToolResult.fail("Target line number out of range");

        // Verify start line hash
        const current_start_hash = generateLineHash(lines.items[target.line_num - 1].content);
        if (!std.mem.eql(u8, &current_start_hash, target.hash)) {
            const msg = try std.fmt.allocPrint(allocator, "Hash mismatch at line {d}. Expected {s}, found {s}. The file may have changed.", .{ target.line_num, target.hash, current_start_hash });
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        const end_line_idx = if (end_target) |et| blk: {
            if (et.line_num < target.line_num or et.line_num > lines.items.len) return ToolResult.fail("End target out of range");
            const current_end_hash = generateLineHash(lines.items[et.line_num - 1].content);
            if (!std.mem.eql(u8, &current_end_hash, et.hash)) {
                return ToolResult.fail("Hash mismatch at end line");
            }
            break :blk et.line_num;
        } else target.line_num;

        const prefix = contents[0..lines.items[target.line_num - 1].start];
        const replacement_end = if (end_line_idx < lines.items.len) lines.items[end_line_idx].start else contents.len;
        const suffix = contents[replacement_end..];
        const separator = if (suffix.len > 0 and new_text.len > 0 and !std.mem.endsWith(u8, new_text, "\n")) "\n" else "";
        const new_contents = try std.mem.concat(allocator, u8, &.{ prefix, new_text, separator, suffix });
        defer allocator.free(new_contents);

        const out_file = std.fs.createFileAbsolute(resolved, .{ .truncate = true }) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to write file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer out_file.close();

        out_file.writeAll(new_contents) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to write file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        return ToolResult.ok("File updated successfully using Hashline verification");
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "file_edit_hashed replaces line when hash matches" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const content = "line one\nline two\nline three";
    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = content });
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    const h2 = generateLineHash("line two");
    var args_buf: [128]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"path\": \"test.txt\", \"target\": \"L2:{s}\", \"new_text\": \"NEW LINE\"}}", .{h2});

    var ft = FileEditHashedTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();

    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(result.success);

    const updated = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "test.txt", 1024);
    defer std.testing.allocator.free(updated);
    try std.testing.expect(std.mem.indexOf(u8, updated, "NEW LINE") != null);
    try std.testing.expect(std.mem.indexOf(u8, updated, "line two") == null);
}

test "file_edit_hashed fails when hash mismatches" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = "wrong content" });
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileEditHashedTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\": \"test.txt\", \"target\": \"L1:abc\", \"new_text\": \"data\"}");
    defer parsed.deinit();

    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |em| std.testing.allocator.free(em);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Hash mismatch") != null);
}

test "file_edit_hashed preserves missing trailing newline at eof" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = "line one\nline two" });
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    const h2 = generateLineHash("line two");
    var args_buf: [128]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"path\": \"test.txt\", \"target\": \"L2:{s}\", \"new_text\": \"tail\"}}", .{h2});

    var ft = FileEditHashedTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();

    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(result.success);

    const updated = try tmp_dir.dir.readFileAlloc(std.testing.allocator, "test.txt", 1024);
    defer std.testing.allocator.free(updated);
    try std.testing.expectEqualStrings("line one\ntail", updated);
}

test "file_edit_hashed rejects absolute path outside allowed areas" {
    var ws_tmp = std.testing.tmpDir(.{});
    defer ws_tmp.cleanup();
    var outside_tmp = std.testing.tmpDir(.{});
    defer outside_tmp.cleanup();

    const ws_path = try ws_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const outside_path = try outside_tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(outside_path);

    try outside_tmp.dir.writeFile(.{ .sub_path = "test.txt", .data = "outside-before" });
    const outside_file = try std.fs.path.join(std.testing.allocator, &.{ outside_path, "test.txt" });
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

    const h1 = generateLineHash("outside-before");
    var args_buf: [2048]u8 = undefined;
    const args = try std.fmt.bufPrint(
        &args_buf,
        "{{\"path\": \"{s}\", \"target\": \"L1:{s}\", \"new_text\": \"outside-after\"}}",
        .{ escaped_buf[0..esc_len], h1 },
    );

    var ft = FileEditHashedTool{ .workspace_dir = ws_path, .allowed_paths = &.{ws_path} };
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();

    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "outside allowed areas") != null);

    const outside_after = try outside_tmp.dir.readFileAlloc(std.testing.allocator, "test.txt", 1024);
    defer std.testing.allocator.free(outside_after);
    try std.testing.expectEqualStrings("outside-before", outside_after);
}
