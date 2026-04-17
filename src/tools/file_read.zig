const std = @import("std");
const std_compat = @import("compat");
const fs_compat = @import("../fs_compat.zig");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const isPathSafe = @import("path_security.zig").isPathSafe;
const isResolvedPathAllowed = @import("path_security.zig").isResolvedPathAllowed;
const file_common = @import("file_common.zig");
const bootstrap_mod = @import("../bootstrap/root.zig");
const memory_root = @import("../memory/root.zig");
const bootstrapRootFilename = file_common.bootstrapRootFilename;
const prepareWorkspacePath = file_common.prepareWorkspacePath;
const resolveNearestExistingAncestor = file_common.resolveNearestExistingAncestor;

/// Default maximum file size to read (10MB).
const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Binary file signature entry
const BinarySignature = struct {
    magic: []const u8,
    type_name: []const u8,
};

/// Known binary file signatures (magic numbers) with type names
const BINARY_SIGNATURES: []const BinarySignature = &.{
    .{ .magic = "\x89PNG", .type_name = "PNG image" },
    .{ .magic = "\xFF\xD8\xFF", .type_name = "JPEG image" },
    .{ .magic = "GIF87a", .type_name = "GIF image" },
    .{ .magic = "GIF89a", .type_name = "GIF image" },
    .{ .magic = "%PDF", .type_name = "PDF document" },
    .{ .magic = "PK\x03\x04", .type_name = "ZIP archive" },
    .{ .magic = "Rar!", .type_name = "RAR archive" },
    .{ .magic = "7z\xBC\xAF\x27\x1C", .type_name = "7z archive" },
    .{ .magic = "MZ", .type_name = "Windows executable" },
    .{ .magic = "\x7FELF", .type_name = "Linux executable" },
};

/// Extension to type name mapping (fallback when magic number not detected)
const EXTENSION_TYPES: []const struct { []const u8, []const u8 } = &.{
    .{ ".png", "PNG image" },
    .{ ".jpg", "JPEG image" },
    .{ ".jpeg", "JPEG image" },
    .{ ".gif", "GIF image" },
    .{ ".webp", "WebP image" },
    .{ ".avif", "AVIF image" },
    .{ ".heic", "HEIC image" },
    .{ ".heif", "HEIF image" },
    .{ ".pdf", "PDF document" },
    .{ ".zip", "ZIP archive" },
    .{ ".mp4", "MP4 video" },
    .{ ".mov", "QuickTime video" },
    .{ ".mp3", "MP3 audio" },
    .{ ".m4a", "M4A audio" },
    .{ ".wav", "WAV audio" },
    .{ ".exe", "Windows executable" },
    .{ ".dll", "Windows DLL" },
    .{ ".so", "Linux shared library" },
    .{ ".dylib", "macOS shared library" },
};

fn isWebP(data: []const u8) bool {
    return data.len >= 12 and
        std.mem.eql(u8, data[0..4], "RIFF") and
        std.mem.eql(u8, data[8..12], "WEBP");
}

fn hasIsoBmffHeader(data: []const u8) bool {
    return data.len >= 8 and std.mem.eql(u8, data[4..8], "ftyp");
}

pub fn isBinaryContent(data: []const u8) bool {
    if (data.len == 0) return false;

    for (BINARY_SIGNATURES) |sig| {
        if (std.mem.startsWith(u8, data, sig.magic)) return true;
    }

    if (isWebP(data)) return true;
    if (hasIsoBmffHeader(data)) return true;

    const check_len = @min(data.len, 8192);
    for (data[0..check_len]) |byte| {
        if (byte == 0) return true;
    }

    return false;
}

pub fn getBinaryFileType(data: []const u8, path: []const u8) []const u8 {
    for (BINARY_SIGNATURES) |sig| {
        if (std.mem.startsWith(u8, data, sig.magic)) return sig.type_name;
    }

    const ext = std_compat.fs.path.extension(path);
    for (EXTENSION_TYPES) |entry| {
        if (std.mem.eql(u8, ext, entry[0])) return entry[1];
    }

    if (isWebP(data)) return "WebP image";
    if (hasIsoBmffHeader(data)) return "ISO media container";

    return "binary file";
}

/// Read file contents with workspace path scoping.
pub const FileReadTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    max_file_size: u64 = DEFAULT_MAX_FILE_SIZE,
    bootstrap_provider: ?bootstrap_mod.BootstrapProvider = null,
    backend_name: []const u8 = "hybrid",

    pub const tool_name = "file_read";
    pub const tool_description = "Read the contents of a file in the workspace";
    pub const tool_params =
        \\{"type":"object","properties":{"path":{"type":"string","description":"Relative path to the file within the workspace"}},"required":["path"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *FileReadTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *FileReadTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const path = root.getString(args, "path") orelse
            return ToolResult.fail("Missing 'path' parameter");

        // Build full path — absolute or relative
        const path_info = prepareWorkspacePath(allocator, self.workspace_dir, path, self.allowed_paths.len > 0) catch |err| switch (err) {
            error.AbsolutePathsNotAllowed => return ToolResult.fail("Absolute paths not allowed (no allowed_paths configured)"),
            error.PathContainsNullBytes => return ToolResult.fail("Path contains null bytes"),
            error.UnsafePath => return ToolResult.fail("Path not allowed: contains traversal or absolute path"),
            else => return err,
        };
        defer path_info.deinit(allocator);

        const full_path = path_info.full_path;
        const ws_path = path_info.workspacePath();
        const bootstrap_filename = bootstrapRootFilename(path);
        const max_usize_u64: u64 = @intCast(std.math.maxInt(usize));
        const effective_max_file_size = @min(self.max_file_size, max_usize_u64);

        if (bootstrap_filename) |filename| {
            if (self.bootstrap_provider) |bp| {
                if (!bootstrap_mod.backendUsesFiles(self.backend_name)) {
                    const parent_to_check = std_compat.fs.path.dirname(full_path) orelse full_path;
                    const resolved_ancestor = resolveNearestExistingAncestor(allocator, parent_to_check) catch |err| {
                        const msg = try std.fmt.allocPrint(allocator, "Failed to resolve file path: {} ({s})", .{ err, path });
                        return ToolResult{ .success = false, .output = "", .error_msg = msg };
                    };
                    defer allocator.free(resolved_ancestor);

                    if (!isResolvedPathAllowed(allocator, resolved_ancestor, ws_path, self.allowed_paths)) {
                        return ToolResult.fail("Path is outside allowed areas");
                    }

                    const contents = try bp.load(allocator, filename) orelse
                        return ToolResult.fail("File not found in memory backend");
                    errdefer allocator.free(contents);

                    if (@as(u64, @intCast(contents.len)) > effective_max_file_size) {
                        const msg = try std.fmt.allocPrint(
                            allocator,
                            "File too large: {} bytes (limit: {} bytes)",
                            .{ contents.len, effective_max_file_size },
                        );
                        allocator.free(contents);
                        return ToolResult{ .success = false, .output = "", .error_msg = msg };
                    }

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

                    return ToolResult{ .success = true, .output = contents };
                }
            }
        }

        // Resolve to catch symlink escapes
        const resolved = fs_compat.realpathAllocPath(allocator, full_path) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to resolve file path: {} ({s})", .{ err, path });
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(resolved);

        // Validate against workspace + allowed_paths + system blocklist
        if (!isResolvedPathAllowed(allocator, resolved, path_info.workspacePath(), self.allowed_paths)) {
            return ToolResult.fail("Path is outside allowed areas");
        }

        // Check file size
        const file = std_compat.fs.openFileAbsolute(resolved, .{}) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to open file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer file.close();

        const stat = try fs_compat.stat(file);
        if (stat.size > effective_max_file_size) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "File too large: {} bytes (limit: {} bytes)",
                .{ stat.size, effective_max_file_size },
            );
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        // Read contents
        const contents = file.readToEndAlloc(allocator, @intCast(effective_max_file_size)) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to read file: {}", .{err});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        errdefer allocator.free(contents);

        // Check if content is binary
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

        return ToolResult{ .success = true, .output = contents };
    }
};

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

    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "test.txt", .data = "hello world" });

    // Get the real path of the tmp dir
    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"test.txt\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("hello world", result.output);
}

test "file_read nonexistent file" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"nope.txt\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "nope.txt") != null);
}

test "file_read blocks path traversal" {
    var ft = FileReadTool{ .workspace_dir = "/tmp/workspace" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"../../../etc/passwd\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not allowed") != null);
}

test "file_read blocks absolute path" {
    var ft = FileReadTool{ .workspace_dir = "/tmp/workspace" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"/etc/passwd\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
}

test "file_read missing path param" {
    var ft = FileReadTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // error_msg is a static string from ToolResult.fail(), don't free it
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
}

test "file_read nested path" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makePath("sub/dir");
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "sub/dir/deep.txt", .data = "deep content" });

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"sub/dir/deep.txt\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("deep content", result.output);
}

test "file_read empty file" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "empty.txt", .data = "" });

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadTool{ .workspace_dir = ws_path };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"empty.txt\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("", result.output);
}

test "file_read reads bootstrap doc from memory backend" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var lru = memory_root.InMemoryLruMemory.init(std.testing.allocator, 16);
    defer lru.deinit();
    var bp_impl = bootstrap_mod.MemoryBootstrapProvider.init(std.testing.allocator, lru.memory(), ws_path);
    try bp_impl.provider().store("USER.md", "name: Igor");

    var ft = FileReadTool{
        .workspace_dir = ws_path,
        .allowed_paths = &.{ws_path},
        .bootstrap_provider = bp_impl.provider(),
        .backend_name = "sqlite",
    };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"USER.md\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("name: Igor", result.output);
}

test "isPathSafe blocks null bytes" {
    try std.testing.expect(!isPathSafe("file\x00.txt"));
}

test "isPathSafe allows relative" {
    try std.testing.expect(isPathSafe("file.txt"));
    try std.testing.expect(isPathSafe("src/main.zig"));
}

test "file_read absolute path without allowed_paths is rejected" {
    var ft = FileReadTool{ .workspace_dir = "/tmp" };
    const t = ft.tool();
    const parsed = try root.parseTestArgs("{\"path\": \"/tmp/foo.txt\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Absolute paths not allowed") != null);
}

test "file_read absolute path with allowed_paths works" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "hello.txt", .data = "allowed content" });

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const abs_file = try std_compat.fs.path.join(std.testing.allocator, &.{ ws_path, "hello.txt" });
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

    var args_buf: [2048]u8 = undefined;
    const args = try std.fmt.bufPrint(&args_buf, "{{\"path\": \"{s}\"}}", .{escaped_buf[0..esc_len]});
    const parsed = try root.parseTestArgs(args);
    defer parsed.deinit();

    var ft = FileReadTool{ .workspace_dir = "/nonexistent", .allowed_paths = &.{ws_path} };
    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("allowed content", result.output);
}

test "file_read reports PNG files as binary" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const png_data = [_]u8{ 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A };
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "image.png", .data = &png_data });

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\": \"image.png\"}");
    defer parsed.deinit();
    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "PNG image") != null);
}

test "file_read reports WAV files as WAV instead of WebP" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const wav_data = [_]u8{
        'R', 'I', 'F', 'F', 0x24, 0x00, 0x00, 0x00,
        'W', 'A', 'V', 'E', 'f',  'm',  't',  ' ',
    };
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "sound.wav", .data = &wav_data });

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\": \"sound.wav\"}");
    defer parsed.deinit();
    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "WAV audio") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "WebP image") == null);
}

test "file_read reports WebP files as WebP" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const webp_data = [_]u8{
        'R', 'I', 'F', 'F', 0x1A, 0x00, 0x00, 0x00,
        'W', 'E', 'B', 'P', 'V',  'P',  '8',  ' ',
    };
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "image.webp", .data = &webp_data });

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\": \"image.webp\"}");
    defer parsed.deinit();
    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "WebP image") != null);
}

test "file_read reports HEIC files as HEIC instead of MP4" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const heic_data = [_]u8{
        0x00, 0x00, 0x00, 0x18, 'f',  't',  'y',  'p',
        'h',  'e',  'i',  'c',  0x00, 0x00, 0x00, 0x00,
    };
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "photo.heic", .data = &heic_data });

    const ws_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    var ft = FileReadTool{ .workspace_dir = ws_path };
    const parsed = try root.parseTestArgs("{\"path\": \"photo.heic\"}");
    defer parsed.deinit();
    const result = try ft.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "HEIC image") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "MP4 video") == null);
}
