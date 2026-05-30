const std = @import("std");
const std_compat = @import("compat");
const fs_compat = @import("../fs_compat.zig");
const builtin = @import("builtin");
const process_util = @import("../tools/process_util.zig");

const DEFAULT_PROBE_TIMEOUT_NS: u64 = 2 * std.time.ns_per_s;
const MAX_PROBE_OUTPUT_BYTES: usize = 64 * 1024;

/// Run a probe command with stdio suppressed and treat exit code 0 as success.
pub fn runQuietCommand(argv: []const []const u8) bool {
    if (argv.len == 0) return false;
    if (!canResolveExecutable(argv[0])) return false;

    const result = process_util.run(std.heap.page_allocator, argv, .{
        .max_output_bytes = MAX_PROBE_OUTPUT_BYTES,
        .timeout_ns = DEFAULT_PROBE_TIMEOUT_NS,
    }) catch return false;
    defer result.deinit(std.heap.page_allocator);

    return result.success and !result.timed_out;
}

/// Check whether an executable name can be found -- either as an absolute or
/// relative path, or by searching each PATH directory for an executable file.
fn canResolveExecutable(name: []const u8) bool {
    if (name.len == 0) return false;

    // Absolute or relative path -- check directly.
    if (std_compat.fs.path.isAbsolute(name) or std.mem.indexOfAny(u8, name, "/\\") != null) {
        return fileIsExecutable(name);
    }

    // Search PATH.
    const path_env = std_compat.process.getEnvVarOwned(std.heap.page_allocator, "PATH") catch return false;
    defer std.heap.page_allocator.free(path_env);

    var it = std.mem.splitScalar(u8, path_env, std_compat.fs.path.delimiter);
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        if (executableInDirectory(dir, name)) return true;
    }
    return false;
}

fn executableInDirectory(dir: []const u8, name: []const u8) bool {
    var buf: [std_compat.fs.max_path_bytes]u8 = undefined;
    const needs_sep = dir.len > 0 and !std_compat.fs.path.isSep(dir[dir.len - 1]);
    const sep_len = if (needs_sep) std_compat.fs.path.sep_str.len else 0;
    if (dir.len + sep_len + name.len > buf.len) return false;

    @memcpy(buf[0..dir.len], dir);
    var len = dir.len;
    if (needs_sep) {
        @memcpy(buf[len..][0..std_compat.fs.path.sep_str.len], std_compat.fs.path.sep_str);
        len += std_compat.fs.path.sep_str.len;
    }
    @memcpy(buf[len..][0..name.len], name);
    len += name.len;

    return fileIsExecutable(buf[0..len]);
}

fn fileIsExecutable(path: []const u8) bool {
    const stat = fs_compat.statPath(path) catch return false;
    if (stat.kind != .file) return false;
    fs_compat.accessPath(path, .{ .execute = true }) catch return false;
    return true;
}

test "runQuietCommand reports child exit status" {
    const platform = @import("../platform.zig");
    try std.testing.expect(runQuietCommand(&.{ platform.getShell(), platform.getShellFlag(), "exit 0" }));
    try std.testing.expect(!runQuietCommand(&.{ platform.getShell(), platform.getShellFlag(), "exit 9" }));
}

test "runQuietCommand rejects empty argv" {
    try std.testing.expect(!runQuietCommand(&.{}));
}

test "canResolveExecutable finds absolute path" {
    const platform = @import("../platform.zig");
    try std.testing.expect(canResolveExecutable(platform.getShell()));
}

test "canResolveExecutable finds relative path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std_compat.fs.Dir.wrap(tmp.dir).writeFile(.{
        .sub_path = "probe-test-exe",
        .data = "#!/bin/sh\nexit 0\n",
        .flags = .{ .permissions = std_compat.fs.permissionsFromMode(0o755) },
    });

    const cwd_abs = try std_compat.fs.cwd().realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const tmp_abs = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_abs);
    const tmp_rel = try std_compat.fs.path.relative(std.testing.allocator, cwd_abs, tmp_abs);
    defer std.testing.allocator.free(tmp_rel);
    const exe_rel = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_rel, "probe-test-exe" });
    defer std.testing.allocator.free(exe_rel);

    // Regression: relative argv[0] with a slash must not go through accessAbsolute.
    try std.testing.expect(canResolveExecutable(exe_rel));
}

test "canResolveExecutable finds bare name on PATH" {
    const name = if (comptime builtin.os.tag == .windows) "cmd.exe" else "sh";
    try std.testing.expect(canResolveExecutable(name));
}

test "canResolveExecutable rejects directory on PATH" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std_compat.fs.Dir.wrap(tmp.dir).makeDir("bin");
    try std_compat.fs.Dir.wrap(tmp.dir).makeDir("bin/nullclaw_probe_dir");
    const bin_abs = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, "bin");
    defer std.testing.allocator.free(bin_abs);

    const platform = @import("../platform.zig");
    const c = @cImport({
        @cInclude("stdlib.h");
    });

    const key_z = try std.testing.allocator.dupeZ(u8, "PATH");
    defer std.testing.allocator.free(key_z);

    const old_path = platform.getEnvOrNull(std.testing.allocator, "PATH");
    defer if (old_path) |path| std.testing.allocator.free(path);

    const old_path_z = if (old_path) |path| try std.testing.allocator.dupeZ(u8, path) else null;
    defer if (old_path_z) |path| std.testing.allocator.free(path);

    defer {
        if (old_path_z) |path| {
            _ = if (comptime builtin.os.tag == .windows)
                c._putenv_s(key_z.ptr, path.ptr)
            else
                c.setenv(key_z.ptr, path.ptr, 1);
        } else {
            _ = if (comptime builtin.os.tag == .windows)
                c._putenv_s(key_z.ptr, "")
            else
                c.unsetenv(key_z.ptr);
        }
    }

    const bin_z = try std.testing.allocator.dupeZ(u8, bin_abs);
    defer std.testing.allocator.free(bin_z);
    const set_rc = if (comptime builtin.os.tag == .windows)
        c._putenv_s(key_z.ptr, bin_z.ptr)
    else
        c.setenv(key_z.ptr, bin_z.ptr, 1);
    try std.testing.expectEqual(@as(c_int, 0), set_rc);

    // Regression: executable resolution must reject directories with execute access.
    try std.testing.expect(!canResolveExecutable("nullclaw_probe_dir"));
}

test "canResolveExecutable rejects empty and nonexistent" {
    try std.testing.expect(!canResolveExecutable(""));
    try std.testing.expect(!canResolveExecutable("__nonexistent_binary_nullclaw_test__"));
}

test "runQuietCommand times out stalled child" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const platform = @import("../platform.zig");
    const start_ns = std_compat.time.nanoTimestamp();
    try std.testing.expect(!runQuietCommand(&.{ platform.getShell(), platform.getShellFlag(), "sleep 30" }));
    const elapsed_ns = std_compat.time.nanoTimestamp() - start_ns;
    try std.testing.expect(elapsed_ns < 10 * std.time.ns_per_s);
}
