//! Agent subprocess runner — spawns `nullclaw agent -m "<prompt>"` as a child
//! process with timeout, output capture, and platform-specific exec fallbacks.
//!
//! Extracted from cron.zig so that any subsystem (cron, heartbeat, etc.) can
//! spawn agent jobs without depending on the scheduler.

const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const platform = @import("platform.zig");

pub const AgentRunResult = struct {
    success: bool,
    output: []const u8,
};

pub const AgentRunOptions = struct {
    origin_channel: ?[]const u8 = null,
    origin_account_id: ?[]const u8 = null,
};

pub const MAX_OUTPUT_BYTES: usize = 1_048_576;
const POLL_STEP_NS: u64 = 200 * std.time.ns_per_ms;
const LINUX_SELF_EXE_PATH = "/proc/self/exe";
const DELETED_EXE_SUFFIX = " (deleted)";

fn pathAgentExecutableName() []const u8 {
    return if (comptime builtin.os.tag == .windows) "nullclaw.exe" else "nullclaw";
}

fn hasTimeoutExpired(start_ns: i128, timeout_secs: u64) bool {
    if (timeout_secs == 0) return false;
    const timeout_ns = @as(i128, @intCast(timeout_secs)) * std.time.ns_per_s;
    const now_ns = std_compat.time.nanoTimestamp();
    return now_ns - start_ns >= timeout_ns;
}

fn collectChildOutputWithTimeout(
    child: *std_compat.process.Child,
    allocator: std.mem.Allocator,
    stdout: *std.ArrayList(u8),
    stderr: *std.ArrayList(u8),
    timeout_secs: u64,
    start_ns: i128,
) !bool {
    const stdout_file = child.stdout.?;
    const stderr_file = child.stderr.?;
    var stdout_open = true;
    var stderr_open = true;
    var timed_out = false;
    var read_buf: [4096]u8 = undefined;
    while (true) {
        if (!stdout_open and !stderr_open) break;

        if (comptime builtin.os.tag == .windows) {
            if (stdout_open) {
                const n = stdout_file.read(&read_buf) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => return err,
                };
                if (n == 0) {
                    stdout_open = false;
                } else {
                    try stdout.appendSlice(allocator, read_buf[0..n]);
                    if (stdout.items.len > MAX_OUTPUT_BYTES) return error.StdoutStreamTooLong;
                }
            }

            if (stderr_open) {
                const n = stderr_file.read(&read_buf) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => return err,
                };
                if (n == 0) {
                    stderr_open = false;
                } else {
                    try stderr.appendSlice(allocator, read_buf[0..n]);
                    if (stderr.items.len > MAX_OUTPUT_BYTES) return error.StderrStreamTooLong;
                }
            }

            if (stdout_open or stderr_open) {
                std_compat.thread.sleep(POLL_STEP_NS);
            }
        } else {
            const poll_ms: i32 = if (timeout_secs == 0 or timed_out)
                -1
            else
                @intCast(@divTrunc(POLL_STEP_NS, std.time.ns_per_ms));
            var poll_fds = [_]std.posix.pollfd{
                .{
                    .fd = if (stdout_open) stdout_file.handle else -1,
                    .events = if (stdout_open) std.posix.POLL.IN | std.posix.POLL.HUP else 0,
                    .revents = 0,
                },
                .{
                    .fd = if (stderr_open) stderr_file.handle else -1,
                    .events = if (stderr_open) std.posix.POLL.IN | std.posix.POLL.HUP else 0,
                    .revents = 0,
                },
            };
            _ = try std.posix.poll(&poll_fds, poll_ms);

            if (stdout_open and (poll_fds[0].revents & (std.posix.POLL.IN | std.posix.POLL.HUP)) != 0) {
                const n = stdout_file.read(&read_buf) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => return err,
                };
                if (n == 0) {
                    stdout_open = false;
                } else {
                    try stdout.appendSlice(allocator, read_buf[0..n]);
                    if (stdout.items.len > MAX_OUTPUT_BYTES) return error.StdoutStreamTooLong;
                }
            }

            if (stderr_open and (poll_fds[1].revents & (std.posix.POLL.IN | std.posix.POLL.HUP)) != 0) {
                const n = stderr_file.read(&read_buf) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => return err,
                };
                if (n == 0) {
                    stderr_open = false;
                } else {
                    try stderr.appendSlice(allocator, read_buf[0..n]);
                    if (stderr.items.len > MAX_OUTPUT_BYTES) return error.StderrStreamTooLong;
                }
            }
        }

        if (!timed_out and hasTimeoutExpired(start_ns, timeout_secs)) {
            try terminateChildHard(child);
            timed_out = true;
        }
    }

    return timed_out;
}

fn terminateChildHard(child: *std_compat.process.Child) !void {
    if (comptime builtin.os.tag == .windows) {
        _ = child.kill() catch return;
        return;
    }
    if (comptime builtin.os.tag == .wasi) return error.UnsupportedOperation;

    std.posix.kill(child.id, std.posix.SIG.KILL) catch |err| switch (err) {
        error.ProcessNotFound => return,
        else => return err,
    };
}

fn buildAgentOutput(
    allocator: std.mem.Allocator,
    stdout: []const u8,
    stderr: []const u8,
    timeout_secs: u64,
    timed_out: bool,
) ![]const u8 {
    if (timed_out) {
        const source = if (stdout.len > 0) stdout else stderr;
        if (source.len > 0) {
            return std.fmt.allocPrint(allocator, "{s}\n\n[agent timed out after {d}s]", .{ source, timeout_secs });
        }
        return std.fmt.allocPrint(allocator, "agent timed out after {d}s", .{timeout_secs});
    }

    const output_source = if (stdout.len > 0) stdout else if (stderr.len > 0) stderr else "";
    return allocator.dupe(u8, output_source);
}

fn preferExecPath(self_exe_path: []const u8) []const u8 {
    if (comptime builtin.os.tag == .linux) {
        if (std.mem.endsWith(u8, self_exe_path, DELETED_EXE_SUFFIX)) {
            return LINUX_SELF_EXE_PATH;
        }
    }
    return self_exe_path;
}

fn appendAgentArgv(
    allocator: std.mem.Allocator,
    argv: *std.ArrayListUnmanaged([]const u8),
    exec_path: []const u8,
    prompt: []const u8,
    model: ?[]const u8,
    options: AgentRunOptions,
) !void {
    try argv.append(allocator, exec_path);
    try argv.append(allocator, "agent");
    if (model) |m| {
        try argv.append(allocator, "--model");
        try argv.append(allocator, m);
    }
    if (options.origin_channel) |channel| {
        try argv.append(allocator, "--origin-channel");
        try argv.append(allocator, channel);
    }
    if (options.origin_account_id) |account_id| {
        try argv.append(allocator, "--origin-account-id");
        try argv.append(allocator, account_id);
    }
    try argv.append(allocator, "-m");
    try argv.append(allocator, prompt);
}

pub fn run(
    allocator: std.mem.Allocator,
    cwd: ?[]const u8,
    prompt: []const u8,
    model: ?[]const u8,
    timeout_secs: u64,
) !AgentRunResult {
    return runWithOptions(allocator, cwd, prompt, model, timeout_secs, .{});
}

pub fn runWithOptions(
    allocator: std.mem.Allocator,
    cwd: ?[]const u8,
    prompt: []const u8,
    model: ?[]const u8,
    timeout_secs: u64,
    options: AgentRunOptions,
) !AgentRunResult {
    const exe_path = try std_compat.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe_path);

    var exec_path = preferExecPath(exe_path);
    var exec_cwd = cwd;
    var tried_no_cwd = false;
    var tried_proc_self_exe = std.mem.eql(u8, exec_path, LINUX_SELF_EXE_PATH);
    var tried_path_exec = false;

    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer argv.deinit(allocator);

    var child: std_compat.process.Child = undefined;
    spawn_loop: while (true) {
        argv.clearRetainingCapacity();
        try appendAgentArgv(allocator, &argv, exec_path, prompt, model, options);

        child = std_compat.process.Child.init(argv.items, allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        child.cwd = exec_cwd;

        child.spawn() catch |err| switch (err) {
            error.FileNotFound => {
                // If cwd disappeared, retry from process cwd.
                if (exec_cwd != null and !tried_no_cwd) {
                    exec_cwd = null;
                    tried_no_cwd = true;
                    continue :spawn_loop;
                }

                // If current binary path became stale after in-place rebuild,
                // Linux can still re-exec through /proc/self/exe.
                if (comptime builtin.os.tag == .linux) {
                    if (!tried_proc_self_exe and !std.mem.eql(u8, exec_path, LINUX_SELF_EXE_PATH)) {
                        exec_path = LINUX_SELF_EXE_PATH;
                        exec_cwd = cwd;
                        tried_no_cwd = false;
                        tried_proc_self_exe = true;
                        continue :spawn_loop;
                    }
                }

                // Cross-platform fallback: try resolving `nullclaw` from PATH.
                // Useful when self-exe path is stale or inaccessible outside Linux.
                if (!tried_path_exec) {
                    exec_path = pathAgentExecutableName();
                    exec_cwd = null;
                    tried_no_cwd = true;
                    tried_path_exec = true;
                    continue :spawn_loop;
                }

                return err;
            },
            else => return err,
        };
        break :spawn_loop;
    }

    errdefer {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
    }

    const start_ns = std_compat.time.nanoTimestamp();

    var stdout: std.ArrayList(u8) = .empty;
    defer stdout.deinit(allocator);
    var stderr: std.ArrayList(u8) = .empty;
    defer stderr.deinit(allocator);

    const timed_out = try collectChildOutputWithTimeout(
        &child,
        allocator,
        &stdout,
        &stderr,
        timeout_secs,
        start_ns,
    );

    const term = try child.wait();
    const success = !timed_out and switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
    const output = try buildAgentOutput(allocator, stdout.items, stderr.items, timeout_secs, timed_out);
    return .{ .success = success, .output = output };
}

// ── Tests ──────────────────────────────────────────────────────────

test "collectChildOutputWithTimeout disables timeout when set to zero" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var child = std_compat.process.Child.init(&.{ platform.getShell(), platform.getShellFlag(), "echo ready" }, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    errdefer {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
    }

    var stdout: std.ArrayList(u8) = .empty;
    defer stdout.deinit(allocator);
    var stderr: std.ArrayList(u8) = .empty;
    defer stderr.deinit(allocator);

    const timed_out = try collectChildOutputWithTimeout(
        &child,
        allocator,
        &stdout,
        &stderr,
        0,
        std_compat.time.nanoTimestamp(),
    );
    const term = try child.wait();

    try std.testing.expect(!timed_out);
    switch (term) {
        .exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => try std.testing.expect(false),
    }
    try std.testing.expect(std.mem.indexOf(u8, stdout.items, "ready") != null);
}

test "collectChildOutputWithTimeout kills process after deadline" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var child = std_compat.process.Child.init(&.{ platform.getShell(), platform.getShellFlag(), "sleep 2; echo never" }, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    errdefer {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
    }

    var stdout: std.ArrayList(u8) = .empty;
    defer stdout.deinit(allocator);
    var stderr: std.ArrayList(u8) = .empty;
    defer stderr.deinit(allocator);

    const timed_out = try collectChildOutputWithTimeout(
        &child,
        allocator,
        &stdout,
        &stderr,
        1,
        std_compat.time.nanoTimestamp(),
    );
    const term = try child.wait();

    try std.testing.expect(timed_out);
    const completed_ok = switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
    try std.testing.expect(!completed_ok);
}

test "preferExecPath keeps regular executable path" {
    const input = "/home/user/bin/nullclaw";
    try std.testing.expectEqualStrings(input, preferExecPath(input));
}

test "preferExecPath uses proc self exe for deleted linux path" {
    if (comptime builtin.os.tag != .linux) return;
    try std.testing.expectEqualStrings(LINUX_SELF_EXE_PATH, preferExecPath("/tmp/nullclaw (deleted)"));
}

test "pathAgentExecutableName returns platform command name" {
    const expected = if (comptime builtin.os.tag == .windows) "nullclaw.exe" else "nullclaw";
    try std.testing.expectEqualStrings(expected, pathAgentExecutableName());
}

test "appendAgentArgv includes cron origin attribution" {
    // Regression: scheduled child agents must receive origin metadata in every spawn attempt.
    const allocator = std.testing.allocator;
    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer argv.deinit(allocator);

    try appendAgentArgv(allocator, &argv, "/usr/bin/nullclaw", "Summarize status", "test-model", .{
        .origin_channel = "telegram",
        .origin_account_id = "main",
    });

    const expected = [_][]const u8{
        "/usr/bin/nullclaw",
        "agent",
        "--model",
        "test-model",
        "--origin-channel",
        "telegram",
        "--origin-account-id",
        "main",
        "-m",
        "Summarize status",
    };
    try std.testing.expectEqual(expected.len, argv.items.len);
    for (expected, argv.items) |want, got| {
        try std.testing.expectEqualStrings(want, got);
    }
}
