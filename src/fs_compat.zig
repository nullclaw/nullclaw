const std = @import("std");
const builtin = @import("builtin");
const std_compat = @import("compat");

fn capped_read_limit(max_bytes: u64) usize {
    const max_usize_u64: u64 = @intCast(std.math.maxInt(usize));
    return @intCast(@min(max_bytes, max_usize_u64));
}

/// Compatibility wrapper for `Dir.readFileAlloc` that avoids Zig 0.15.2's
/// `File.stat()` path on Linux kernels where `statx` is unavailable.
pub fn readFileAlloc(dir: anytype, allocator: std.mem.Allocator, sub_path: []const u8, max_bytes: u64) ![]u8 {
    if (std.fs.path.isAbsolute(sub_path)) {
        const file = try openPath(sub_path, .{});
        defer file.close();
        return try file.readToEndAlloc(allocator, capped_read_limit(max_bytes));
    }

    const compat_dir = if (@TypeOf(dir) == std_compat.fs.Dir) dir else std_compat.fs.Dir.wrap(dir);
    const file = try compat_dir.openFile(sub_path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, capped_read_limit(max_bytes));
}

/// Compatibility wrapper for `Dir.makePath` / `cwd().makePath()` that avoids
/// the `statx`-dependent recursive path walk in Zig 0.15.2 stdlib.
///
/// Each ancestor directory is created in order, treating existing
/// directories as success.
pub fn makePath(path: []const u8) !void {
    if (path.len == 0) return;

    const is_absolute = std.fs.path.isAbsolute(path);
    var it = std.fs.path.componentIterator(path);
    var component = it.last() orelse return error.BadPathName;

    while (true) {
        if (if (is_absolute) std_compat.fs.makeDirAbsolute(component.path) else std_compat.fs.cwd().makeDir(component.path)) |_| {
            // created
        } else |err| switch (err) {
            error.PathAlreadyExists => {
                // Keep stdlib behavior: existing component must be a directory.
                var existing_dir = (if (is_absolute)
                    std_compat.fs.openDirAbsolute(component.path, .{})
                else
                    std_compat.fs.cwd().openDir(component.path, .{})) catch |open_err| switch (open_err) {
                    error.NotDir => return error.NotDir,
                    else => |e| return e,
                };
                existing_dir.close();
            },
            error.FileNotFound => {
                component = it.previous() orelse return err;
                continue;
            },
            else => |e| return e,
        }

        component = it.next() orelse return;
    }
}

/// Compatibility wrapper that forwards to the file's `stat` implementation.
pub fn stat(file: anytype) @TypeOf(file.stat()) {
    return file.stat();
}

pub fn openPath(path: []const u8, options: std_compat.fs.Dir.OpenFileOptions) !std_compat.fs.File {
    if (std.fs.path.isAbsolute(path)) {
        return try std_compat.fs.openFileAbsolute(path, options);
    }
    return try std_compat.fs.cwd().openFile(path, options);
}

pub fn createPath(path: []const u8, options: std_compat.fs.Dir.CreateFileOptions) !std_compat.fs.File {
    if (std.fs.path.isAbsolute(path)) {
        return try std_compat.fs.createFileAbsolute(path, options);
    }
    return try std_compat.fs.cwd().createFile(path, options);
}

pub fn openDirPath(path: []const u8, options: std_compat.fs.Dir.OpenDirOptions) !std_compat.fs.Dir {
    if (std.fs.path.isAbsolute(path)) {
        return try std_compat.fs.openDirAbsolute(path, options);
    }
    return try std_compat.fs.cwd().openDir(path, options);
}

pub fn statPath(path: []const u8) !std_compat.fs.File.Stat {
    const file = try openPath(path, .{});
    defer file.close();
    return try stat(file);
}

pub fn accessPath(path: []const u8, options: std_compat.fs.Dir.AccessOptions) !void {
    if (std.fs.path.isAbsolute(path)) {
        return try std_compat.fs.accessAbsolute(path, options);
    }
    return try std_compat.fs.cwd().access(path, options);
}

pub fn renamePath(old_path: []const u8, new_path: []const u8) !void {
    if (std.fs.path.isAbsolute(old_path) or std.fs.path.isAbsolute(new_path)) {
        return try std_compat.fs.renameAbsolute(old_path, new_path);
    }
    return try std_compat.fs.cwd().rename(old_path, new_path);
}

pub fn deletePath(path: []const u8) !void {
    if (std.fs.path.isAbsolute(path)) {
        return try std_compat.fs.deleteFileAbsolute(path);
    }
    return try std_compat.fs.cwd().deleteFile(path);
}

/// Atomically replace `path` with a mode-0600 regular file.
///
/// The temporary file is created in the destination directory with a random,
/// exclusive name so pre-planted symlinks and concurrent writers cannot redirect
/// or share the write. Failed writes and renames remove the temporary file.
pub fn writeFileAtomicSecure(path: []const u8, contents: []const u8) !void {
    const parent_path = std.fs.path.dirname(path) orelse ".";
    const basename = std.fs.path.basename(path);
    var parent_dir = try openDirPath(parent_path, .{});
    defer parent_dir.close();

    var tmp_name_buf: [96]u8 = undefined;
    var tmp_name: []const u8 = undefined;
    var tmp_file_opt: ?std_compat.fs.File = null;
    var attempt: usize = 0;
    while (attempt < 16) : (attempt += 1) {
        tmp_name = std.fmt.bufPrint(
            &tmp_name_buf,
            ".nullclaw-secure-{x}.tmp",
            .{std_compat.crypto.random.int(u64)},
        ) catch return error.NameTooLong;
        tmp_file_opt = parent_dir.createFile(tmp_name, .{
            .truncate = false,
            .exclusive = true,
            .permissions = std_compat.fs.permissionsFromMode(0o600),
        }) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => |e| return e,
        };
        break;
    }
    var tmp_file = tmp_file_opt orelse return error.TempFileUnavailable;
    var file_open = true;
    defer if (file_open) tmp_file.close();

    var committed = false;
    defer if (!committed) parent_dir.deleteFile(tmp_name) catch {};

    try tmp_file.writeAll(contents);
    try tmp_file.sync();
    tmp_file.close();
    file_open = false;

    try parent_dir.rename(tmp_name, basename);
    committed = true;
}

pub const SecureInstallResult = enum {
    installed,
    already_exists,
};

fn publishSecureTempNoReplace(
    parent_dir: std_compat.fs.Dir,
    tmp_name: []const u8,
    basename: []const u8,
    force_hard_link: bool,
) !SecureInstallResult {
    var use_hard_link = force_hard_link;
    if (!use_hard_link) {
        parent_dir.renamePreserve(tmp_name, basename) catch |err| switch (err) {
            error.PathAlreadyExists => return .already_exists,
            // Older Linux kernels and some filesystems lack renameat2 with
            // RENAME_NOREPLACE. A same-directory hard link provides the same
            // atomic no-replace publication guarantee for regular files.
            error.OperationUnsupported, error.Unexpected => {
                if (builtin.os.tag == .windows) return err;
                use_hard_link = true;
            },
            else => |e| return e,
        };
        if (!use_hard_link) return .installed;
    }

    parent_dir.hardLink(tmp_name, parent_dir, basename, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.PathAlreadyExists => return .already_exists,
        else => |e| return e,
    };
    try parent_dir.deleteFile(tmp_name);
    return .installed;
}

/// Atomically create a mode-0600 regular file without replacing an existing path.
///
/// The fully written and synced random candidate is published with no-replace
/// semantics. Failure cleanup only removes that candidate, never `path`.
pub fn writeFileAtomicSecureNoReplace(path: []const u8, contents: []const u8) !SecureInstallResult {
    const parent_path = std.fs.path.dirname(path) orelse ".";
    const basename = std.fs.path.basename(path);
    var parent_dir = try openDirPath(parent_path, .{});
    defer parent_dir.close();

    var tmp_name_buf: [96]u8 = undefined;
    var tmp_name: []const u8 = undefined;
    var tmp_file_opt: ?std_compat.fs.File = null;
    var attempt: usize = 0;
    while (attempt < 16) : (attempt += 1) {
        tmp_name = std.fmt.bufPrint(
            &tmp_name_buf,
            ".nullclaw-secure-{x}.tmp",
            .{std_compat.crypto.random.int(u64)},
        ) catch return error.NameTooLong;
        tmp_file_opt = parent_dir.createFile(tmp_name, .{
            .truncate = false,
            .exclusive = true,
            .permissions = std_compat.fs.permissionsFromMode(0o600),
        }) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => |e| return e,
        };
        break;
    }
    var tmp_file = tmp_file_opt orelse return error.TempFileUnavailable;
    var file_open = true;
    defer if (file_open) tmp_file.close();

    var installed = false;
    defer if (!installed) parent_dir.deleteFile(tmp_name) catch {};

    try tmp_file.writeAll(contents);
    try tmp_file.sync();
    tmp_file.close();
    file_open = false;

    const result = try publishSecureTempNoReplace(parent_dir, tmp_name, basename, false);
    installed = result == .installed;
    return result;
}

pub fn realpathAllocPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(path)) {
        return try std_compat.fs.realpathAlloc(allocator, path);
    }
    return try std_compat.fs.cwd().realpathAlloc(allocator, path);
}

pub fn openPathForAppend(path: []const u8) !std_compat.fs.File {
    return openPath(path, .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => createPath(path, .{ .truncate = false, .read = true }),
        else => |e| return e,
    };
}

pub fn appendBytes(path: []const u8, bytes: []const u8) !void {
    var file = try openPathForAppend(path);
    defer file.close();
    try file.seekFromEnd(0);
    try file.writeAll(bytes);
}

pub fn appendLine(path: []const u8, line: []const u8) !void {
    var file = try openPathForAppend(path);
    defer file.close();
    try file.seekFromEnd(0);
    try file.writeAll(line);
    try file.writeAll("\n");
}

test "readFileAlloc reads file contents" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "sample.txt", .data = "hello" });

    const content = try readFileAlloc(tmp_dir.dir, std.testing.allocator, "sample.txt", 64);
    defer std.testing.allocator.free(content);

    try std.testing.expectEqualStrings("hello", content);
}

test "writeFileAtomicSecure writes mode 0600 and replaces symlink itself" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.SkipZigTest;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "victim", .data = "unchanged" });
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).symLink("victim", "secure", .{});

    const secure_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_path, "secure" });
    defer std.testing.allocator.free(secure_path);
    try writeFileAtomicSecure(secure_path, "secret-data");

    const secure = try readFileAlloc(tmp_dir.dir, std.testing.allocator, "secure", 64);
    defer std.testing.allocator.free(secure);
    try std.testing.expectEqualStrings("secret-data", secure);
    const victim = try readFileAlloc(tmp_dir.dir, std.testing.allocator, "victim", 64);
    defer std.testing.allocator.free(victim);
    try std.testing.expectEqualStrings("unchanged", victim);

    const file = try @import("compat").fs.Dir.wrap(tmp_dir.dir).openFile("secure", .{});
    defer file.close();
    const metadata = try file.stat();
    try std.testing.expectEqual(@as(std_compat.fs.File.Mode, 0o600), metadata.mode & 0o777);
}

test "writeFileAtomicSecure removes temporary file after rename failure" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).makeDir("target");

    const target_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_path, "target" });
    defer std.testing.allocator.free(target_path);
    const result = writeFileAtomicSecure(target_path, "secret-data");
    try std.testing.expect(std.meta.isError(result));

    var dir = try std_compat.fs.openDirAbsolute(tmp_path, .{ .iterate = true });
    defer dir.close();
    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        try std.testing.expect(!std.mem.startsWith(u8, entry.name, ".nullclaw-secure-"));
    }
}

test "writeFileAtomicSecureNoReplace preserves existing file and removes candidate" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const target_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_path, "secure" });
    defer std.testing.allocator.free(target_path);
    try std.testing.expectEqual(
        SecureInstallResult.installed,
        try writeFileAtomicSecureNoReplace(target_path, "first"),
    );
    try std.testing.expectEqual(
        SecureInstallResult.already_exists,
        try writeFileAtomicSecureNoReplace(target_path, "second"),
    );

    const content = try readFileAlloc(tmp_dir.dir, std.testing.allocator, "secure", 64);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("first", content);

    var dir = try std_compat.fs.openDirAbsolute(tmp_path, .{ .iterate = true });
    defer dir.close();
    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        try std.testing.expect(!std.mem.startsWith(u8, entry.name, ".nullclaw-secure-"));
    }
}

test "secure no-replace publication supports hard-link fallback" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.SkipZigTest;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const dir = std_compat.fs.Dir.wrap(tmp_dir.dir);
    const candidate = try dir.createFile("candidate", .{
        .truncate = false,
        .exclusive = true,
        .permissions = std_compat.fs.permissionsFromMode(0o600),
    });
    try candidate.writeAll("complete-secret");
    try candidate.sync();
    candidate.close();

    try std.testing.expectEqual(
        SecureInstallResult.installed,
        try publishSecureTempNoReplace(dir, "candidate", "installed", true),
    );
    const content = try readFileAlloc(tmp_dir.dir, std.testing.allocator, "installed", 64);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("complete-secret", content);
    try std.testing.expectError(error.FileNotFound, dir.access("candidate", .{}));
}

test "stat returns file size" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "sample.txt", .data = "hello" });

    const file = try @import("compat").fs.Dir.wrap(tmp_dir.dir).openFile("sample.txt", .{});
    defer file.close();

    const meta = try stat(file);
    try std.testing.expectEqual(@as(u64, 5), meta.size);
}

test "makePath creates single directory" {
    if (builtin.os.tag == .wasi) return;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const abs = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    const target = try std.fs.path.join(std.testing.allocator, &.{ abs, "single" });
    defer std.testing.allocator.free(target);

    try makePath(target);

    // Verify it exists by opening it.
    var dir = try std_compat.fs.openDirAbsolute(target, .{});
    dir.close();
}

test "makePath creates nested directories" {
    if (builtin.os.tag == .wasi) return;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const abs = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    const target = try std.fs.path.join(std.testing.allocator, &.{ abs, "a", "b", "c" });
    defer std.testing.allocator.free(target);

    try makePath(target);

    var dir = try std_compat.fs.openDirAbsolute(target, .{});
    dir.close();
}

test "makePath succeeds when directory already exists" {
    if (builtin.os.tag == .wasi) return;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const abs = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    const target = try std.fs.path.join(std.testing.allocator, &.{ abs, "existing" });
    defer std.testing.allocator.free(target);

    try std_compat.fs.makeDirAbsolute(target);

    // Second call must not fail.
    try makePath(target);

    var dir = try std_compat.fs.openDirAbsolute(target, .{});
    dir.close();
}

test "makePath is a no-op for empty string" {
    try makePath("");
}

test "makePath fails when a path component is a file" {
    if (builtin.os.tag == .wasi) return;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const abs = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    // Create a regular file where a directory component is expected.
    try @import("compat").fs.Dir.wrap(tmp_dir.dir).writeFile(.{ .sub_path = "blocker", .data = "" });

    const target = try std.fs.path.join(std.testing.allocator, &.{ abs, "blocker", "child" });
    defer std.testing.allocator.free(target);

    // Must propagate the error, not silently succeed.
    try std.testing.expectError(error.NotDir, makePath(target));
}

test "makePath supports relative paths" {
    if (builtin.os.tag == .wasi) return;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const old_cwd = try @import("compat").fs.cwd().realpath(".", &cwd_buf);

    const abs = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    try std.Io.Threaded.chdir(abs);
    defer std.Io.Threaded.chdir(old_cwd) catch {};

    try makePath("rel/a/b");

    var dir = try std_compat.fs.cwd().openDir("rel/a/b", .{});
    dir.close();
}

test "appendLine writes to absolute paths" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const abs = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    const target = try std.fs.path.join(std.testing.allocator, &.{ abs, "append.log" });
    defer std.testing.allocator.free(target);

    try appendLine(target, "one");
    try appendLine(target, "two");

    const file = try std_compat.fs.openFileAbsolute(target, .{});
    defer file.close();
    const content = try file.readToEndAlloc(std.testing.allocator, 64);
    defer std.testing.allocator.free(content);

    try std.testing.expectEqualStrings("one\ntwo\n", content);
}

test "renamePath supports absolute paths" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const abs = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    const source = try std.fs.path.join(std.testing.allocator, &.{ abs, "old.txt" });
    defer std.testing.allocator.free(source);
    const dest = try std.fs.path.join(std.testing.allocator, &.{ abs, "new.txt" });
    defer std.testing.allocator.free(dest);

    const file = try createPath(source, .{});
    defer file.close();
    try file.writeAll("moved");

    try renamePath(source, dest);

    const moved = try std_compat.fs.openFileAbsolute(dest, .{});
    defer moved.close();
    const content = try moved.readToEndAlloc(std.testing.allocator, 64);
    defer std.testing.allocator.free(content);

    try std.testing.expectEqualStrings("moved", content);
}

test "readFileAlloc reads absolute path contents" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const abs = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    const target = try std.fs.path.join(std.testing.allocator, &.{ abs, "absolute.txt" });
    defer std.testing.allocator.free(target);

    const file = try createPath(target, .{});
    defer file.close();
    try file.writeAll("absolute");

    const content = try readFileAlloc(std_compat.fs.cwd(), std.testing.allocator, target, 64);
    defer std.testing.allocator.free(content);

    try std.testing.expectEqualStrings("absolute", content);
}

test "openDirPath and accessPath support absolute paths" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const abs = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    try accessPath(abs, .{});

    var dir = try openDirPath(abs, .{ .iterate = true });
    defer dir.close();

    const nested = try std.fs.path.join(std.testing.allocator, &.{ abs, "nested.txt" });
    defer std.testing.allocator.free(nested);
    const nested_file = try createPath(nested, .{});
    defer nested_file.close();
    try nested_file.writeAll("nested");

    try accessPath(nested, .{});
}

test "realpathAllocPath resolves absolute paths" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const abs = try @import("compat").fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    const resolved = try realpathAllocPath(std.testing.allocator, abs);
    defer std.testing.allocator.free(resolved);

    try std.testing.expectEqualStrings(abs, resolved);
}
