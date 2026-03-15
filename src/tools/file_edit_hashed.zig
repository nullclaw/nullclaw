const std = @import("std");
const fs_compat = @import("../fs_compat.zig");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isPathSafe = @import("path_security.zig").isPathSafe;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;
const generateLineHash = @import("file_read_hashed.zig").generateLineHash;

const RADIUS: usize = 50;

const LineSearchResult = union(enum) {
    found: usize,
    not_found,
    ambiguous,
};

fn findLineWithRadius(lines: []const LineInfo, hint_idx: usize, target_hash: []const u8) LineSearchResult {
    const start = if (hint_idx > RADIUS) hint_idx - RADIUS else 0;
    const end = @min(lines.len, hint_idx + RADIUS + 1);
    var found_idx: ?usize = null;

    for (lines[start..end], start..) |line, i| {
        const parent = if (i > 0) lines[i - 1].content else "";
        const h = generateLineHash(parent, line.content);
        if (std.mem.eql(u8, &h, target_hash)) {
            if (found_idx != null) return .ambiguous;
            found_idx = i;
        }
    }

    if (found_idx) |idx| return .{ .found = idx };
    return .not_found;
}

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

        const stat = fs_compat.stat(file) catch |err| {
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

        // Find real start line using radius search
        const real_start_idx = switch (findLineWithRadius(lines.items, target.line_num - 1, target.hash)) {
            .found => |idx| idx,
            .not_found => {
                const msg = try std.fmt.allocPrint(allocator, "Hash mismatch for start target {s} near line {d}. Context changed.", .{ target.hash, target.line_num });
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            },
            .ambiguous => {
                const msg = try std.fmt.allocPrint(allocator, "Ambiguous start target {s} near line {d}. Re-read file to refresh Hashlines.", .{ target.hash, target.line_num });
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            },
        };

        const real_end_idx = if (end_target) |et| blk: {
            if (et.line_num == 0 or et.line_num > lines.items.len or et.line_num < target.line_num) {
                return ToolResult.fail("End target out of range");
            }

            // Adjust search hint for end based on how much start moved
            const drift: i64 = @as(i64, @intCast(real_start_idx)) - @as(i64, @intCast(target.line_num - 1));
            const hinted_i64 = @as(i64, @intCast(et.line_num - 1)) + drift;
            const hint = if (hinted_i64 <= 0)
                @as(usize, 0)
            else if (hinted_i64 >= @as(i64, @intCast(lines.items.len - 1)))
                lines.items.len - 1
            else
                @as(usize, @intCast(hinted_i64));

            const resolved_end = switch (findLineWithRadius(lines.items, hint, et.hash)) {
                .found => |idx| idx,
                .not_found => return ToolResult.fail("Hash mismatch for end target. Context changed."),
                .ambiguous => return ToolResult.fail("Ambiguous end target. Re-read file to refresh Hashlines."),
            };
            if (resolved_end < real_start_idx) return ToolResult.fail("End target resolved before start target");
            break :blk resolved_end;
        } else real_start_idx;

        const prefix = contents[0..lines.items[real_start_idx].start];
        const replacement_end = if (real_end_idx + 1 < lines.items.len) lines.items[real_end_idx + 1].start else contents.len;
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

        const msg = try std.fmt.allocPrint(allocator, "File updated successfully. Target shifted from L{d} to L{d} (Context-Aware).", .{ target.line_num, real_start_idx + 1 });
        return ToolResult{ .success = true, .output = msg };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "file_edit_hashed replaces line when hash matches with shift" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const content = "line one\nline two\nline three";
    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = content });
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    const h2 = generateLineHash("line one", "line two");

    // Now insert a line at the top manually to cause a shift
    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = "new top line\nline one\nline two\nline three" });

    var args_buf: [128]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"path\": \"test.txt\", \"target\": \"L2:{s}\", \"new_text\": \"NEW LINE\"}}", .{h2});

    var ft = FileEditHashedTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();

    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "shifted from L2 to L3") != null);

    const updated = try fs_compat.readFileAlloc(tmp_dir.dir, std.testing.allocator, "test.txt", 1024);
    defer std.testing.allocator.free(updated);
    try std.testing.expect(std.mem.indexOf(u8, updated, "NEW LINE") != null);
    try std.testing.expect(std.mem.indexOf(u8, updated, "line two") == null);
}

test "file_edit_hashed rejects ambiguous collision during shift" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const content = "line one\nline two\nline three";
    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = content });
    const ws_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    const h2 = generateLineHash("line one", "line two");

    // "bms" collides with the target hash when paired with "line one".
    const shifted = "bms\nline one\nline two\nline three";
    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = shifted });

    var args_buf: [128]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"path\": \"test.txt\", \"target\": \"L2:{s}\", \"new_text\": \"NEW LINE\"}}", .{h2});

    var ft = FileEditHashedTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();

    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |em| std.testing.allocator.free(em);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Ambiguous start target") != null);

    const updated = try fs_compat.readFileAlloc(tmp_dir.dir, std.testing.allocator, "test.txt", 1024);
    defer std.testing.allocator.free(updated);
    try std.testing.expectEqualStrings(shifted, updated);
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

    const h2 = generateLineHash("line one", "line two");
    var args_buf: [128]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"path\": \"test.txt\", \"target\": \"L2:{s}\", \"new_text\": \"tail\"}}", .{h2});

    var ft = FileEditHashedTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();

    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);

    const updated = try fs_compat.readFileAlloc(tmp_dir.dir, std.testing.allocator, "test.txt", 1024);
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

    const h1 = generateLineHash("", "outside-before");
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

    const outside_after = try fs_compat.readFileAlloc(outside_tmp.dir, std.testing.allocator, "test.txt", 1024);
    defer std.testing.allocator.free(outside_after);
    try std.testing.expectEqualStrings("outside-before", outside_after);
}
