//! Path security helpers shared by file_read, file_write, file_edit, file_append,
//! shell, and git tools.
//!
//! Extracted from file_edit.zig to eliminate cross-imports between tool files.

const std = @import("std");
const builtin = @import("builtin");

/// System-critical prefixes (Unix) — always blocked even if they match allowed_paths.
const SYSTEM_BLOCKED_PREFIXES_UNIX = [_][]const u8{
    "/System",
    "/Library",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/etc",
    "/private/etc",
    "/private/var",
    "/dev",
    "/boot",
    "/proc",
    "/sys",
};

/// System-critical prefixes (Windows).
const SYSTEM_BLOCKED_PREFIXES_WINDOWS = [_][]const u8{
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    "C:\\System32",
    "C:\\Recovery",
};

/// Platform-selected system blocked prefixes.
pub const SYSTEM_BLOCKED_PREFIXES: []const []const u8 = if (@import("builtin").os.tag == .windows)
    &SYSTEM_BLOCKED_PREFIXES_WINDOWS
else
    &SYSTEM_BLOCKED_PREFIXES_UNIX;

/// Check whether a directory-style prefix matches (exact or followed by a path separator).
pub fn pathStartsWith(path: []const u8, prefix: []const u8) bool {
    if (builtin.os.tag == .windows) {
        const norm_path = normalizeWindowsPrefix(path);
        const norm_prefix = normalizeWindowsPrefix(prefix);
        if (!windowsPrefixEquals(norm_path, norm_prefix)) return false;
        if (norm_path.len == norm_prefix.len) return true;
        return isWindowsPathSeparator(norm_path[norm_prefix.len]);
    } else {
        if (!std.mem.startsWith(u8, path, prefix)) return false;
        if (path.len == prefix.len) return true;
        const c = path[prefix.len];
        return c == '/' or c == '\\';
    }
}

fn normalizeWindowsPrefix(path: []const u8) []const u8 {
    // std.fs.realpath on Windows may produce verbatim paths (\\?\C:\...).
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

/// Check whether a **resolved** absolute path is allowed by the policy:
///  1. System blocklist always rejects.
///  2. Workspace prefix matches → allowed.
///  3. Any allowed_path prefix matches (resolved on the fly) → allowed.
pub fn isResolvedPathAllowed(
    allocator: std.mem.Allocator,
    resolved: []const u8,
    ws_resolved: []const u8,
    allowed_paths: []const []const u8,
) bool {
    // 1. System blocklist
    for (SYSTEM_BLOCKED_PREFIXES) |prefix| {
        if (pathStartsWith(resolved, prefix)) return false;
    }
    // 2. Workspace
    if (pathStartsWith(resolved, ws_resolved)) return true;
    // 3. Allowed paths (resolve each to handle symlinks)
    for (allowed_paths) |raw_allowed_path| {
        const ap = std.mem.trim(u8, raw_allowed_path, " \t\r\n");
        if (ap.len == 0) continue;
        if (std.mem.eql(u8, ap, "*")) return true;
        const ap_resolved = std.fs.cwd().realpathAlloc(allocator, ap) catch continue;
        defer allocator.free(ap_resolved);
        if (pathStartsWith(resolved, ap_resolved)) return true;
    }
    return false;
}

/// Check if a relative path is safe (no traversal, no absolute path).
pub fn isPathSafe(path: []const u8) bool {
    if (std.fs.path.isAbsolute(path)) return false;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return false;
    var iter = std.mem.splitAny(u8, path, "/\\");
    while (iter.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }
    // Block URL-encoded traversal (..%2f, %2f.., ..%5c, %5c..)
    {
        var lower: [4096]u8 = undefined;
        if (path.len > lower.len) return false; // reject rather than silently truncate
        const len = path.len;
        for (path[0..len], 0..) |c, i| {
            lower[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        }
        const lp = lower[0..len];
        if (std.mem.indexOf(u8, lp, "..%2f") != null or
            std.mem.indexOf(u8, lp, "%2f..") != null or
            std.mem.indexOf(u8, lp, "..%5c") != null or
            std.mem.indexOf(u8, lp, "%5c..") != null) return false;
    }
    return true;
}

// ── Tests ───────────────────────────────────────────────────────────

test "isPathSafe blocks null bytes" {
    try std.testing.expect(!isPathSafe("file\x00.txt"));
}

test "isPathSafe allows relative" {
    try std.testing.expect(isPathSafe("file.txt"));
    try std.testing.expect(isPathSafe("src/main.zig"));
}

test "isPathSafe blocks traversal" {
    try std.testing.expect(!isPathSafe("../../etc/passwd"));
    try std.testing.expect(!isPathSafe("foo/../../../bar"));
}

test "isPathSafe blocks absolute" {
    try std.testing.expect(!isPathSafe("/etc/passwd"));
}

test "isPathSafe blocks URL-encoded traversal" {
    try std.testing.expect(!isPathSafe("..%2fetc/passwd"));
    try std.testing.expect(!isPathSafe("%2f..%2fetc/passwd"));
    try std.testing.expect(!isPathSafe("..%5c..%5cwindows"));
    try std.testing.expect(!isPathSafe("%5c..%5csecret"));
    // Case-insensitive
    try std.testing.expect(!isPathSafe("..%2Fetc/passwd"));
    try std.testing.expect(!isPathSafe("..%2fetc/passwd"));
}

test "isPathSafe allows percent in non-traversal context" {
    try std.testing.expect(isPathSafe("file%20name.txt"));
    try std.testing.expect(isPathSafe("100%25done.txt"));
}

test "isResolvedPathAllowed allows workspace path" {
    try std.testing.expect(isResolvedPathAllowed(
        std.testing.allocator,
        "/home/user/workspace/file.txt",
        "/home/user/workspace",
        &.{},
    ));
}

test "isResolvedPathAllowed allows exact workspace" {
    try std.testing.expect(isResolvedPathAllowed(
        std.testing.allocator,
        "/home/user/workspace",
        "/home/user/workspace",
        &.{},
    ));
}

test "isResolvedPathAllowed rejects outside workspace" {
    try std.testing.expect(!isResolvedPathAllowed(
        std.testing.allocator,
        "/home/user/other/file.txt",
        "/home/user/workspace",
        &.{},
    ));
}

test "isResolvedPathAllowed rejects partial prefix match" {
    try std.testing.expect(!isResolvedPathAllowed(
        std.testing.allocator,
        "/home/user/workspace-evil/file.txt",
        "/home/user/workspace",
        &.{},
    ));
}

test "isResolvedPathAllowed blocks system paths" {
    if (comptime @import("builtin").os.tag == .windows) {
        try std.testing.expect(!isResolvedPathAllowed(
            std.testing.allocator,
            "C:\\Windows\\system32\\cmd.exe",
            "C:\\Users\\ws",
            &.{},
        ));
        try std.testing.expect(!isResolvedPathAllowed(
            std.testing.allocator,
            "C:\\Program Files\\app\\evil.exe",
            "C:\\Users\\ws",
            &.{},
        ));
    } else {
        try std.testing.expect(!isResolvedPathAllowed(
            std.testing.allocator,
            "/etc/passwd",
            "/etc",
            &.{},
        ));
        try std.testing.expect(!isResolvedPathAllowed(
            std.testing.allocator,
            "/System/Library/something",
            "/home/ws",
            &.{"/System"},
        ));
        try std.testing.expect(!isResolvedPathAllowed(
            std.testing.allocator,
            "/bin/sh",
            "/home/ws",
            &.{"/bin"},
        ));
    }
}

test "isResolvedPathAllowed allows via allowed_paths" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = "" });
    const file_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_path, "test.txt" });
    defer std.testing.allocator.free(file_path);

    try std.testing.expect(isResolvedPathAllowed(
        std.testing.allocator,
        file_path,
        "/nonexistent-workspace",
        &.{tmp_path},
    ));
}

test "isResolvedPathAllowed wildcard allows non-system paths" {
    try std.testing.expect(isResolvedPathAllowed(
        std.testing.allocator,
        "/home/user/random/path.txt",
        "/nonexistent-workspace",
        &.{"*"},
    ));
}

test "isResolvedPathAllowed wildcard with whitespace allows non-system paths" {
    try std.testing.expect(isResolvedPathAllowed(
        std.testing.allocator,
        "/home/user/random/path.txt",
        "/nonexistent-workspace",
        &.{"  *  "},
    ));
}

test "isResolvedPathAllowed trims allowed path entries before resolving" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.txt", .data = "" });
    const file_path = try std.fs.path.join(std.testing.allocator, &.{ tmp_path, "test.txt" });
    defer std.testing.allocator.free(file_path);

    const spaced_allowed = try std.fmt.allocPrint(std.testing.allocator, "  {s}  ", .{tmp_path});
    defer std.testing.allocator.free(spaced_allowed);

    try std.testing.expect(isResolvedPathAllowed(
        std.testing.allocator,
        file_path,
        "/nonexistent-workspace",
        &.{spaced_allowed},
    ));
}

test "isResolvedPathAllowed wildcard does not bypass system blocklist" {
    if (comptime @import("builtin").os.tag == .windows) {
        try std.testing.expect(!isResolvedPathAllowed(
            std.testing.allocator,
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Users\\workspace",
            &.{"*"},
        ));
    } else {
        try std.testing.expect(!isResolvedPathAllowed(
            std.testing.allocator,
            "/etc/passwd",
            "/home/user/workspace",
            &.{"*"},
        ));
    }
}

test "pathStartsWith exact match" {
    try std.testing.expect(pathStartsWith("/foo/bar", "/foo/bar"));
}

test "pathStartsWith with trailing component" {
    try std.testing.expect(pathStartsWith("/foo/bar/baz", "/foo/bar"));
}

test "pathStartsWith windows is case-insensitive" {
    if (comptime @import("builtin").os.tag != .windows) return;
    try std.testing.expect(pathStartsWith("c:\\windows\\system32\\cmd.exe", "C:\\Windows"));
}

test "pathStartsWith windows accepts mixed separators and verbatim prefix" {
    if (comptime @import("builtin").os.tag != .windows) return;
    try std.testing.expect(pathStartsWith("C:/Windows/System32/cmd.exe", "C:\\Windows"));
    try std.testing.expect(pathStartsWith("\\\\?\\C:\\Windows\\System32\\cmd.exe", "C:\\Windows"));
}

test "pathStartsWith rejects partial" {
    try std.testing.expect(!pathStartsWith("/foo/barbaz", "/foo/bar"));
}
