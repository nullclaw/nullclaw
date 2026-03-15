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
