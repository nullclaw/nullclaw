const std = @import("std");
const AtomicBool = std.atomic.Value(bool);
const builtin = @import("builtin");

// Win32 APIs used for codepage fallback decoding on Windows.
extern "kernel32" fn MultiByteToWideChar(
    code_page: std.os.windows.UINT,
    flags: std.os.windows.DWORD,
    input: ?[*]const u8,
    input_len: i32,
    output: ?[*]u16,
    output_len: i32,
) callconv(.winapi) i32;

extern "kernel32" fn WideCharToMultiByte(
    code_page: std.os.windows.UINT,
    flags: std.os.windows.DWORD,
    input: ?[*]const u16,
    input_len: i32,
    output: ?[*]u8,
    output_len: i32,
    default_char: ?[*]const u8,
    used_default_char: ?*std.os.windows.BOOL,
) callconv(.winapi) i32;

extern "kernel32" fn GetACP() callconv(.winapi) std.os.windows.UINT;

const CP_UTF8: std.os.windows.UINT = 65001;
const CP_GBK: std.os.windows.UINT = 936;
const MB_ERR_INVALID_CHARS: std.os.windows.DWORD = 0x00000008;

threadlocal var thread_interrupt_flag: ?*const AtomicBool = null;

pub fn setThreadInterruptFlag(flag: ?*const AtomicBool) void {
    thread_interrupt_flag = flag;
}

/// Result of a child process execution.
pub const RunResult = struct {
    stdout: []u8,
    stderr: []u8,
    success: bool,
    exit_code: ?u32 = null,
    interrupted: bool = false,

    /// Free both stdout and stderr buffers.
    pub fn deinit(self: *const RunResult, allocator: std.mem.Allocator) void {
        if (self.stdout.len > 0) allocator.free(self.stdout);
        if (self.stderr.len > 0) allocator.free(self.stderr);
    }
};

/// Options for running a child process.
pub const RunOptions = struct {
    cwd: ?[]const u8 = null,
    env_map: ?*std.process.EnvMap = null,
    max_output_bytes: usize = 1_048_576,
    cancel_flag: ?*const AtomicBool = null,
};

const CancelWatcherCtx = struct {
    child: *std.process.Child,
    cancel_flag: *const AtomicBool,
    done: *AtomicBool,
};

fn cancelWatcherMain(ctx: *CancelWatcherCtx) void {
    while (!ctx.done.load(.acquire)) {
        if (ctx.cancel_flag.load(.acquire)) {
            if (comptime @import("builtin").os.tag == .windows) {
                std.os.windows.TerminateProcess(ctx.child.id, 1) catch {};
            } else {
                std.posix.kill(ctx.child.id, std.posix.SIG.TERM) catch {};
            }
            break;
        }
        std.Thread.sleep(20 * std.time.ns_per_ms);
    }
}

fn appendUtf8Replacement(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator) !void {
    try out.appendSlice(allocator, "\xEF\xBF\xBD");
}

fn lossilyNormalizeToUtf8(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.ensureTotalCapacity(allocator, input.len);

    var i: usize = 0;
    while (i < input.len) {
        const byte = input[i];
        if (byte < 0x80) {
            try out.append(allocator, byte);
            i += 1;
            continue;
        }

        const seq_len = std.unicode.utf8ByteSequenceLength(byte) catch {
            try appendUtf8Replacement(&out, allocator);
            i += 1;
            continue;
        };

        const step: usize = @intCast(seq_len);
        if (i + step > input.len) {
            try appendUtf8Replacement(&out, allocator);
            i += 1;
            continue;
        }

        const candidate = input[i .. i + step];
        _ = std.unicode.utf8Decode(candidate) catch {
            try appendUtf8Replacement(&out, allocator);
            i += 1;
            continue;
        };

        try out.appendSlice(allocator, candidate);
        i += step;
    }

    return out.toOwnedSlice(allocator);
}

fn tryDecodeWindowsCodePageToUtf8(
    allocator: std.mem.Allocator,
    input: []const u8,
    code_page: std.os.windows.UINT,
) !?[]u8 {
    if (input.len == 0 or code_page == 0) return null;

    const in_len: i32 = std.math.cast(i32, input.len) orelse return null;
    // Keep UTF-8 strict so a console forced to CP_UTF8 does not swallow
    // ACP/GBK bytes with U+FFFD substitutions before we can try fallbacks.
    const decode_flags: std.os.windows.DWORD = if (code_page == CP_UTF8) MB_ERR_INVALID_CHARS else 0;

    const wide_len = MultiByteToWideChar(code_page, decode_flags, input.ptr, in_len, null, 0);
    if (wide_len <= 0) return null;

    const wide_len_usize: usize = @intCast(wide_len);
    const wide = try allocator.alloc(u16, wide_len_usize);
    defer allocator.free(wide);

    if (MultiByteToWideChar(code_page, decode_flags, input.ptr, in_len, wide.ptr, wide_len) <= 0) return null;

    const utf8_len = WideCharToMultiByte(CP_UTF8, 0, wide.ptr, wide_len, null, 0, null, null);
    if (utf8_len <= 0) return null;

    const utf8_len_usize: usize = @intCast(utf8_len);
    const out = try allocator.alloc(u8, utf8_len_usize);
    errdefer allocator.free(out);

    if (WideCharToMultiByte(CP_UTF8, 0, wide.ptr, wide_len, out.ptr, utf8_len, null, null) <= 0) return null;

    return out;
}

fn tryDecodeWindowsOutputToUtf8(allocator: std.mem.Allocator, input: []const u8) !?[]u8 {
    const console_cp = std.os.windows.kernel32.GetConsoleOutputCP();
    if (try tryDecodeWindowsCodePageToUtf8(allocator, input, console_cp)) |decoded| return decoded;

    // Prefer GBK before ACP: Western single-byte ACPs like CP1252 will happily
    // decode arbitrary high bytes into mojibake ("ÖÐÎÄ"), which would mask
    // genuine GBK console output that we can still recover losslessly.
    const ansi_cp = GetACP();
    if (console_cp != CP_GBK and ansi_cp != CP_GBK) {
        if (try tryDecodeWindowsCodePageToUtf8(allocator, input, CP_GBK)) |decoded| return decoded;
    }

    if (ansi_cp != console_cp) {
        if (try tryDecodeWindowsCodePageToUtf8(allocator, input, ansi_cp)) |decoded| return decoded;
    }

    return null;
}

fn normalizeCapturedOutputOwned(allocator: std.mem.Allocator, input: []u8) ![]u8 {
    if (std.unicode.utf8ValidateSlice(input)) return input;

    if (comptime builtin.os.tag == .windows) {
        if (try tryDecodeWindowsOutputToUtf8(allocator, input)) |decoded| {
            allocator.free(input);
            return decoded;
        }
    }

    const lossy = try lossilyNormalizeToUtf8(allocator, input);
    allocator.free(input);
    return lossy;
}

/// Run a child process, capture stdout and stderr, and return the result.
///
/// The caller owns the returned stdout and stderr buffers.
/// Use `result.deinit(allocator)` to free them.
pub fn run(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    opts: RunOptions,
) !RunResult {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    if (opts.cwd) |cwd| child.cwd = cwd;
    if (opts.env_map) |env| child.env_map = env;

    try child.spawn();

    const effective_cancel_flag = opts.cancel_flag orelse thread_interrupt_flag;
    var cancel_done = AtomicBool.init(false);
    var cancel_watcher: ?std.Thread = null;
    var watcher_ctx: CancelWatcherCtx = undefined;
    if (effective_cancel_flag) |flag| {
        watcher_ctx = .{
            .child = &child,
            .cancel_flag = flag,
            .done = &cancel_done,
        };
        cancel_watcher = std.Thread.spawn(.{}, cancelWatcherMain, .{&watcher_ctx}) catch null;
    }
    defer {
        cancel_done.store(true, .release);
        if (cancel_watcher) |t| t.join();
    }

    var stdout = if (child.stdout) |stdout_file| blk: {
        break :blk stdout_file.readToEndAlloc(allocator, opts.max_output_bytes) catch |err| {
            if (effective_cancel_flag != null and effective_cancel_flag.?.load(.acquire)) {
                break :blk try allocator.dupe(u8, "");
            }
            return err;
        };
    } else try allocator.dupe(u8, "");
    errdefer allocator.free(stdout);
    stdout = try normalizeCapturedOutputOwned(allocator, stdout);

    var stderr = if (child.stderr) |stderr_file| blk: {
        break :blk stderr_file.readToEndAlloc(allocator, opts.max_output_bytes) catch |err| {
            if (effective_cancel_flag != null and effective_cancel_flag.?.load(.acquire)) {
                break :blk try allocator.dupe(u8, "");
            }
            return err;
        };
    } else try allocator.dupe(u8, "");
    errdefer allocator.free(stderr);
    stderr = try normalizeCapturedOutputOwned(allocator, stderr);

    const term = try child.wait();
    const interrupted = if (effective_cancel_flag) |flag| flag.load(.acquire) else false;

    return switch (term) {
        .Exited => |code| .{
            .stdout = stdout,
            .stderr = stderr,
            .success = code == 0,
            .exit_code = code,
            .interrupted = interrupted,
        },
        else => .{
            .stdout = stdout,
            .stderr = stderr,
            .success = false,
            .exit_code = null,
            .interrupted = interrupted,
        },
    };
}

// ── Tests ───────────────────────────────────────────────────────────

test "run echo returns stdout" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{ "echo", "hello" }, .{});
    defer result.deinit(allocator);

    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(u32, 0), result.exit_code.?);
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "hello") != null);
}

test "run failing command returns exit code" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{ "ls", "/nonexistent_dir_xyz_42" }, .{});
    defer result.deinit(allocator);

    try std.testing.expect(!result.success);
    try std.testing.expect(result.exit_code.? != 0);
    try std.testing.expect(result.stderr.len > 0);
}

test "run with cwd" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const result = try run(allocator, &.{"pwd"}, .{ .cwd = "/tmp" });
    defer result.deinit(allocator);

    try std.testing.expect(result.success);
    // /tmp may resolve to /private/tmp on macOS
    try std.testing.expect(result.stdout.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "tmp") != null);
}

test "run honors cancel flag and interrupts child" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var cancel = AtomicBool.init(false);

    const ThreadResult = struct {
        res: ?RunResult = null,
        err: ?anyerror = null,
    };
    var thread_result = ThreadResult{};

    const Runner = struct {
        fn runThread(
            allocator_inner: std.mem.Allocator,
            cancel_flag: *const AtomicBool,
            out: *ThreadResult,
        ) void {
            out.res = run(allocator_inner, &.{ "sh", "-c", "sleep 5; echo done" }, .{
                .cancel_flag = cancel_flag,
            }) catch |err| {
                out.err = err;
                return;
            };
        }
    };

    const t = try std.Thread.spawn(.{}, Runner.runThread, .{ allocator, &cancel, &thread_result });
    std.Thread.sleep(100 * std.time.ns_per_ms);
    cancel.store(true, .release);
    t.join();

    try std.testing.expect(thread_result.err == null);
    const result = thread_result.res orelse return error.TestUnexpectedResult;
    defer result.deinit(allocator);
    try std.testing.expect(!result.success);
    try std.testing.expect(result.interrupted);
}

test "RunResult deinit frees buffers" {
    const allocator = std.testing.allocator;
    const stdout = try allocator.dupe(u8, "output");
    const stderr = try allocator.dupe(u8, "error");
    const result = RunResult{
        .stdout = stdout,
        .stderr = stderr,
        .success = true,
        .exit_code = 0,
    };
    result.deinit(allocator);
}

test "RunResult deinit with empty buffers" {
    const allocator = std.testing.allocator;
    const result = RunResult{
        .stdout = "",
        .stderr = "",
        .success = true,
        .exit_code = 0,
    };
    result.deinit(allocator); // should not crash or attempt to free ""
}

test "normalizeCapturedOutputOwned converts invalid UTF-8 to safe text" {
    const allocator = std.testing.allocator;
    const invalid = try allocator.dupe(u8, &[_]u8{ 'f', 0x80, 'o' });
    const normalized = try normalizeCapturedOutputOwned(allocator, invalid);
    defer allocator.free(normalized);

    try std.testing.expect(std.unicode.utf8ValidateSlice(normalized));
    try std.testing.expect(std.mem.indexOf(u8, normalized, "f") != null);
    try std.testing.expect(std.mem.indexOf(u8, normalized, "o") != null);
}

test "run normalizes invalid stderr before returning" {
    const allocator = std.testing.allocator;
    const argv: []const []const u8 = if (comptime builtin.os.tag == .windows)
        &.{
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "[Console]::OpenStandardError().Write([byte[]](0xD6,0xD0,0xCE,0xC4),0,4); exit 1",
        }
    else
        &.{ "sh", "-c", "printf '\\200' >&2; exit 1" };

    const result = try run(allocator, argv, .{});
    defer result.deinit(allocator);

    try std.testing.expect(!result.success);
    try std.testing.expect(std.unicode.utf8ValidateSlice(result.stderr));
    if (comptime builtin.os.tag == .windows) {
        try std.testing.expect(std.mem.indexOf(u8, result.stderr, "中文") != null);
    } else {
        try std.testing.expect(std.mem.indexOf(u8, result.stderr, "\xEF\xBF\xBD") != null);
    }
}

test "windows gbk fallback decodes to utf8" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const gbk = [_]u8{ 0xD6, 0xD0, 0xCE, 0xC4 }; // "中文" in GBK/CP936
    const decoded = try tryDecodeWindowsCodePageToUtf8(allocator, &gbk, CP_GBK);
    try std.testing.expect(decoded != null);
    defer allocator.free(decoded.?);

    try std.testing.expect(std.unicode.utf8ValidateSlice(decoded.?));
    const expected_utf8 = [_]u8{ 0xE4, 0xB8, 0xAD, 0xE6, 0x96, 0x87 }; // "zhongwen" (Chinese chars) in UTF-8 bytes
    try std.testing.expectEqualSlices(u8, &expected_utf8, decoded.?);
}

test "windows utf8 decoder rejects gbk bytes so ansi fallback can run" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const gbk = [_]u8{ 0xD6, 0xD0, 0xCE, 0xC4 }; // "中文" in GBK/CP936
    const decoded = try tryDecodeWindowsCodePageToUtf8(allocator, &gbk, CP_UTF8);
    try std.testing.expect(decoded == null);
}
