const std = @import("std");
const builtin = @import("builtin");

fn capped_read_limit(max_bytes: u64) usize {
    const max_usize_u64: u64 = @intCast(std.math.maxInt(usize));
    return @intCast(@min(max_bytes, max_usize_u64));
}

/// Compatibility wrapper for `Dir.readFileAlloc` that avoids Zig 0.15.2's
/// `File.stat()` path on Linux kernels where `statx` is unavailable.
pub fn readFileAlloc(dir: std.fs.Dir, allocator: std.mem.Allocator, sub_path: []const u8, max_bytes: u64) ![]u8 {
    const file = try dir.openFile(sub_path, .{});
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
    var it = try std.fs.path.componentIterator(path);
    var component = it.last() orelse return error.BadPathName;

    while (true) {
        if (if (is_absolute) std.fs.makeDirAbsolute(component.path) else std.fs.cwd().makeDir(component.path)) |_| {
            // created
        } else |err| switch (err) {
            error.PathAlreadyExists => {
                // Keep stdlib behavior: existing component must be a directory.
                var existing_dir = (if (is_absolute)
                    std.fs.openDirAbsolute(component.path, .{})
                else
                    std.fs.cwd().openDir(component.path, .{})) catch |open_err| switch (open_err) {
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

/// Compatibility wrapper for `File.stat()` that uses `fstat` on POSIX
/// platforms instead of the Linux `statx` fast path in Zig 0.15.2.
pub fn stat(file: std.fs.File) std.fs.File.StatError!std.fs.File.Stat {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return file.stat();
    }
    return std.fs.File.Stat.fromPosix(try std.posix.fstat(file.handle));
}

test "readFileAlloc reads file contents" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "sample.txt", .data = "hello" });

    const content = try readFileAlloc(tmp_dir.dir, std.testing.allocator, "sample.txt", 64);
    defer std.testing.allocator.free(content);

    try std.testing.expectEqualStrings("hello", content);
}

test "stat returns file size" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "sample.txt", .data = "hello" });

    const file = try tmp_dir.dir.openFile("sample.txt", .{});
    defer file.close();

    const meta = try stat(file);
    try std.testing.expectEqual(@as(u64, 5), meta.size);
}

test "makePath creates single directory" {
    if (builtin.os.tag == .wasi) return;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const abs = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    const target = try std.fs.path.join(std.testing.allocator, &.{ abs, "single" });
    defer std.testing.allocator.free(target);

    try makePath(target);

    // Verify it exists by opening it.
    var dir = try std.fs.openDirAbsolute(target, .{});
    dir.close();
}

test "makePath creates nested directories" {
    if (builtin.os.tag == .wasi) return;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const abs = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    const target = try std.fs.path.join(std.testing.allocator, &.{ abs, "a", "b", "c" });
    defer std.testing.allocator.free(target);

    try makePath(target);

    var dir = try std.fs.openDirAbsolute(target, .{});
    dir.close();
}

test "makePath succeeds when directory already exists" {
    if (builtin.os.tag == .wasi) return;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const abs = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    const target = try std.fs.path.join(std.testing.allocator, &.{ abs, "existing" });
    defer std.testing.allocator.free(target);

    try std.fs.makeDirAbsolute(target);

    // Second call must not fail.
    try makePath(target);

    var dir = try std.fs.openDirAbsolute(target, .{});
    dir.close();
}

test "makePath is a no-op for empty string" {
    try makePath("");
}

test "makePath fails when a path component is a file" {
    if (builtin.os.tag == .wasi) return;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const abs = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    // Create a regular file where a directory component is expected.
    try tmp_dir.dir.writeFile(.{ .sub_path = "blocker", .data = "" });

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
    const old_cwd = try std.posix.getcwd(&cwd_buf);

    const abs = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    try std.posix.chdir(abs);
    defer std.posix.chdir(old_cwd) catch {};

    try makePath("rel/a/b");

    var dir = try std.fs.cwd().openDir("rel/a/b", .{});
    dir.close();
}
