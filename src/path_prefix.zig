const std = @import("std");

pub fn pathStartsWith(path: []const u8, prefix: []const u8) bool {
    const builtin = @import("builtin");
    if (builtin.os.tag == .windows) {
        const norm_path = normalizeWindowsPrefix(path);
        const norm_prefix = normalizeWindowsPrefix(prefix);
        if (!windowsPrefixEquals(norm_path, norm_prefix)) return false;
        if (norm_path.len == norm_prefix.len) return true;
        if (norm_prefix.len > 0 and isWindowsPathSeparator(norm_prefix[norm_prefix.len - 1])) return true;
        return isWindowsPathSeparator(norm_path[norm_prefix.len]);
    }

    if (!std.mem.startsWith(u8, path, prefix)) return false;
    if (path.len == prefix.len) return true;
    if (prefix.len > 0 and (prefix[prefix.len - 1] == '/' or prefix[prefix.len - 1] == '\\')) return true;
    const c = path[prefix.len];
    return c == '/' or c == '\\';
}

fn normalizeWindowsPrefix(path: []const u8) []const u8 {
    if (path.len >= 4 and path[0] == '\\' and path[1] == '\\' and path[2] == '?' and path[3] == '\\') {
        return path[4..];
    }
    return path;
}

fn isWindowsPathSeparator(c: u8) bool {
    return c == '\\' or c == '/';
}

fn windowsPrefixEquals(path: []const u8, prefix: []const u8) bool {
    if (path.len < prefix.len) return false;
    for (prefix, 0..) |pc, i| {
        const c = path[i];
        if (isWindowsPathSeparator(c) and isWindowsPathSeparator(pc)) continue;
        if (std.ascii.toLower(c) != std.ascii.toLower(pc)) return false;
    }
    return true;
}

test "path_prefix exact and nested match" {
    try std.testing.expect(pathStartsWith("/foo/bar", "/foo/bar"));
    try std.testing.expect(pathStartsWith("/foo/bar/baz", "/foo/bar"));
}

test "path_prefix rejects partial segment" {
    try std.testing.expect(!pathStartsWith("/foo/barbaz", "/foo/bar"));
}

test "path_prefix accepts separator-terminated roots" {
    try std.testing.expect(pathStartsWith("/tmp/workspace", "/"));
    try std.testing.expect(pathStartsWith("C:\\tmp\\workspace", "C:\\"));
}

test "path_prefix windows case-insensitive and separators" {
    if (comptime @import("builtin").os.tag != .windows) return;
    try std.testing.expect(pathStartsWith("c:\\windows\\system32\\cmd.exe", "C:\\Windows"));
    try std.testing.expect(pathStartsWith("C:/Windows/System32/cmd.exe", "C:\\Windows"));
    try std.testing.expect(pathStartsWith("\\\\?\\C:\\Windows\\System32\\cmd.exe", "C:\\Windows"));
}
