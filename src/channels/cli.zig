const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const fs_compat = @import("../fs_compat.zig");
const platform = @import("../platform.zig");
const root = @import("root.zig");
const cli_line_editor = @import("cli_line_editor.zig");

const ESCAPE_SEQUENCE_TIMEOUT_MS: i32 = 50;
const DEFAULT_TERMINAL_COLUMNS: usize = 80;

fn supportsRawMode() bool {
    return comptime builtin.os.tag != .windows and builtin.os.tag != .wasi;
}

const CliRawMode = if (builtin.os.tag == .windows or builtin.os.tag == .wasi)
    struct {
        fn enable(_: std_compat.fs.File.Handle) !CliRawMode {
            return error.NotSupported;
        }

        fn disable(_: *CliRawMode) void {}

        fn waitForEscapeContinuation(_: std_compat.fs.File.Handle) bool {
            return false;
        }

        fn terminalColumns(_: std_compat.fs.File.Handle) usize {
            return DEFAULT_TERMINAL_COLUMNS;
        }

        fn suspendProcess(_: *CliRawMode) !void {
            return error.NotSupported;
        }

        fn quitProcess(_: *CliRawMode) !void {
            return error.NotSupported;
        }
    }
else
    struct {
        const enable_action: std.posix.TCSA = .NOW;
        const disable_action: std.posix.TCSA = .DRAIN;

        fd: std.posix.fd_t,
        original: std.posix.termios,

        fn makeRaw(original: std.posix.termios) std.posix.termios {
            var raw = original;
            raw.iflag.IXON = false;
            raw.iflag.IXOFF = false;
            raw.lflag.ICANON = false;
            raw.lflag.ECHO = false;
            raw.lflag.ISIG = false;
            raw.lflag.IEXTEN = false;
            raw.cc[@intFromEnum(std.posix.V.MIN)] = 1;
            raw.cc[@intFromEnum(std.posix.V.TIME)] = 0;
            return raw;
        }

        fn enable(fd: std.posix.fd_t) !CliRawMode {
            const original = try std.posix.tcgetattr(fd);
            try std.posix.tcsetattr(fd, enable_action, makeRaw(original));
            return .{ .fd = fd, .original = original };
        }

        fn disable(self: *CliRawMode) void {
            std.posix.tcsetattr(self.fd, disable_action, self.original) catch {};
        }

        fn waitForEscapeContinuation(fd: std.posix.fd_t) bool {
            // Keep timing at this thin OS boundary. Parser reset/reprocessing is
            // covered deterministically in cli_line_editor tests; a real PTY
            // timing test would violate the repository's no-flaky-tests rule.
            var poll_fds = [_]std.posix.pollfd{
                .{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 },
            };
            const ready = std.posix.poll(&poll_fds, ESCAPE_SEQUENCE_TIMEOUT_MS) catch return false;
            if (ready == 0) return false;
            return (poll_fds[0].revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL)) != 0;
        }

        fn terminalColumns(fd: std.posix.fd_t) usize {
            var size: std.posix.winsize = .{ .row = 0, .col = 0, .xpixel = 0, .ypixel = 0 };
            const rc = std.posix.system.ioctl(
                fd,
                @intCast(std.posix.T.IOCGWINSZ),
                @intFromPtr(&size),
            );
            if (std.posix.errno(rc) != .SUCCESS or size.col == 0) return DEFAULT_TERMINAL_COLUMNS;
            return size.col;
        }

        fn forwardSignal(self: *CliRawMode, signal: std.posix.SIG) !void {
            const fd = self.fd;
            self.disable();
            std.posix.raise(signal) catch |err| {
                self.* = try enable(fd);
                return err;
            };
            self.* = try enable(fd);
        }

        fn suspendProcess(self: *CliRawMode) !void {
            return self.forwardSignal(.TSTP);
        }

        fn quitProcess(self: *CliRawMode) !void {
            return self.forwardSignal(.QUIT);
        }
    };

/// Read a canonical line without printing a prompt. Overlong input is drained
/// through its newline so the next read starts at a real line boundary.
pub fn readCanonicalLine(stdin: std_compat.fs.File, line_buf: []u8) !?[]const u8 {
    var pos: usize = 0;
    var overflowed = false;
    while (true) {
        var byte_buf: [1]u8 = undefined;
        const n = try stdin.read(&byte_buf);
        if (n == 0) {
            if (overflowed) return error.LineTooLong;
            return if (pos == 0) null else line_buf[0..pos];
        }
        if (byte_buf[0] == '\n') {
            if (overflowed) return error.LineTooLong;
            if (pos > 0 and line_buf[pos - 1] == '\r') pos -= 1;
            return line_buf[0..pos];
        }
        if (pos < line_buf.len) {
            line_buf[pos] = byte_buf[0];
            pos += 1;
        } else {
            overflowed = true;
        }
    }
}

fn readPromptedCanonicalLine(
    stdin: std_compat.fs.File,
    writer: *std.Io.Writer,
    prompt: []const u8,
    line_buf: []u8,
) !?[]const u8 {
    try writer.writeAll(prompt);
    try writer.flush();
    return readCanonicalLine(stdin, line_buf);
}

/// Read one interactive CLI line. POSIX TTYs use the allocation-free editor;
/// Windows, WASI, redirected input, and redirected output keep canonical I/O.
pub fn readInteractiveLine(
    stdin: std_compat.fs.File,
    stdout: std_compat.fs.File,
    writer: *std.Io.Writer,
    prompt: []const u8,
    history: []const []const u8,
    line_buf: []u8,
) !?[]const u8 {
    if (!supportsRawMode() or !stdin.isTty() or !stdout.isTty()) {
        return readPromptedCanonicalLine(stdin, writer, prompt, line_buf);
    }

    var raw = CliRawMode.enable(stdin.handle) catch {
        return readPromptedCanonicalLine(stdin, writer, prompt, line_buf);
    };
    defer raw.disable();
    const terminal_columns = CliRawMode.terminalColumns(stdout.handle);

    try cli_line_editor.renderPrompt(writer, prompt);
    try writer.flush();

    var editor = cli_line_editor.LineEditor.init(history);
    while (true) {
        if (editor.hasPendingEscape() and !CliRawMode.waitForEscapeContinuation(stdin.handle)) {
            editor.cancelPendingEscape();
            continue;
        }

        var byte_buf: [1]u8 = undefined;
        const n = try stdin.read(&byte_buf);
        if (n == 0) {
            try cli_line_editor.renderLineRefresh(writer, prompt, editor.line(), editor.line().len, terminal_columns);
            try writer.writeAll("\r\n");
            try writer.flush();
            return null;
        }

        switch (byte_buf[0]) {
            '\r', '\n' => {
                editor.cancelPendingInput();
                try cli_line_editor.renderLineRefresh(writer, prompt, editor.line(), editor.line().len, terminal_columns);
                try writer.writeAll("\r\n");
                try writer.flush();
                if (editor.hasOverflowed()) return error.LineTooLong;
                const line = editor.line();
                if (line.len > line_buf.len) return error.LineTooLong;
                @memcpy(line_buf[0..line.len], line);
                return line_buf[0..line.len];
            },
            0x03 => {
                editor.cancelPendingInput();
                try cli_line_editor.renderLineRefresh(writer, prompt, editor.line(), editor.line().len, terminal_columns);
                try writer.writeAll("^C\r\n");
                try writer.flush();
                return error.Interrupted;
            },
            0x04 => {
                editor.cancelPendingInput();
                if (editor.line().len == 0) {
                    try cli_line_editor.renderLineRefresh(writer, prompt, editor.line(), 0, terminal_columns);
                    try writer.writeAll("\r\n");
                    try writer.flush();
                    return null;
                }
                if (editor.feedInput(0x04) == .changed) {
                    try cli_line_editor.renderLineRefresh(writer, prompt, editor.line(), editor.cursor(), terminal_columns);
                    try writer.flush();
                }
            },
            0x1a => {
                editor.cancelPendingInput();
                try raw.suspendProcess();
                try cli_line_editor.renderLineRefresh(writer, prompt, editor.line(), editor.cursor(), terminal_columns);
                try writer.flush();
            },
            0x1c => {
                editor.cancelPendingInput();
                try raw.quitProcess();
                try cli_line_editor.renderLineRefresh(writer, prompt, editor.line(), editor.cursor(), terminal_columns);
                try writer.flush();
            },
            else => switch (editor.feedInput(byte_buf[0])) {
                .changed => {
                    try cli_line_editor.renderLineRefresh(writer, prompt, editor.line(), editor.cursor(), terminal_columns);
                    try writer.flush();
                },
                .full => {
                    try writer.writeAll("\x07");
                    try writer.flush();
                },
                .pending, .unchanged => {},
            },
        }
    }
}

/// CLI channel — reads from stdin, writes to stdout.
/// Simplest channel implementation; used for local interactive testing.
pub const CliChannel = struct {
    allocator: std.mem.Allocator,
    running: bool,

    pub fn init(allocator: std.mem.Allocator) CliChannel {
        return .{ .allocator = allocator, .running = false };
    }

    pub fn channelName(_: *CliChannel) []const u8 {
        return "cli";
    }

    pub fn sendMessage(_: *CliChannel, _: []const u8, message: []const u8) !void {
        var out_buf: [4096]u8 = undefined;
        var bw = std_compat.fs.File.stdout().writer(&out_buf);
        const w = &bw.interface;
        try w.print("{s}\n", .{message});
        try w.flush();
    }

    /// Retained for source compatibility with the public CLI channel API.
    pub fn readLine(_: *CliChannel, buf: []u8) !?[]const u8 {
        return readCanonicalLine(std_compat.fs.File.stdin(), buf);
    }

    pub fn isQuitCommand(line: []const u8) bool {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        return std.mem.eql(u8, trimmed, "exit") or
            std.mem.eql(u8, trimmed, "quit") or
            std.mem.eql(u8, trimmed, ":q") or
            std.mem.eql(u8, trimmed, "/quit") or
            std.mem.eql(u8, trimmed, "/exit");
    }

    pub fn healthCheck(_: *CliChannel) bool {
        return true; // CLI is always available
    }

    // ── Channel vtable ──────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *CliChannel = @ptrCast(@alignCast(ptr));
        self.running = true;
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *CliChannel = @ptrCast(@alignCast(ptr));
        self.running = false;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *CliChannel = @ptrCast(@alignCast(ptr));
        return self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *CliChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *CliChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *CliChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// History — persistent REPL command history (~/.nullclaw_history)
// ═══════════════════════════════════════════════════════════════════════════

const MAX_HISTORY_LINES: usize = 500;

/// Load command history from a file (one command per line).
/// Returns up to MAX_HISTORY_LINES most recent entries.
/// If the file does not exist, returns an empty slice.
/// Caller owns the returned slice and all strings within it.
pub fn loadHistory(allocator: std.mem.Allocator, path: []const u8) ![][]const u8 {
    const file = fs_compat.openPath(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return try allocator.alloc([]const u8, 0),
        else => return err,
    };
    defer file.close();

    var lines: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (lines.items) |l| allocator.free(l);
        lines.deinit(allocator);
    }

    var read_buf: [8192]u8 = undefined;
    var carry: std.ArrayListUnmanaged(u8) = .empty;
    defer carry.deinit(allocator);

    while (true) {
        const n = file.read(&read_buf) catch break;
        if (n == 0) break;
        const data = read_buf[0..n];

        var start: usize = 0;
        for (data, 0..) |byte, i| {
            if (byte == '\n') {
                const segment = data[start..i];
                if (carry.items.len > 0) {
                    try carry.appendSlice(allocator, segment);
                    const trimmed = std.mem.trim(u8, carry.items, " \t\r");
                    if (trimmed.len > 0) {
                        try lines.append(allocator, try allocator.dupe(u8, trimmed));
                    }
                    carry.clearRetainingCapacity();
                } else {
                    const trimmed = std.mem.trim(u8, segment, " \t\r");
                    if (trimmed.len > 0) {
                        try lines.append(allocator, try allocator.dupe(u8, trimmed));
                    }
                }
                start = i + 1;
            }
        }
        // Leftover bytes (no newline yet)
        if (start < data.len) {
            try carry.appendSlice(allocator, data[start..]);
        }
    }

    // Trailing content without final newline
    if (carry.items.len > 0) {
        const trimmed = std.mem.trim(u8, carry.items, " \t\r");
        if (trimmed.len > 0) {
            try lines.append(allocator, try allocator.dupe(u8, trimmed));
        }
    }

    // Keep only the most recent MAX_HISTORY_LINES
    if (lines.items.len > MAX_HISTORY_LINES) {
        const excess = lines.items.len - MAX_HISTORY_LINES;
        for (lines.items[0..excess]) |l| allocator.free(l);
        std.mem.copyForwards([]const u8, lines.items[0..MAX_HISTORY_LINES], lines.items[excess..]);
        lines.shrinkRetainingCapacity(MAX_HISTORY_LINES);
    }

    return lines.toOwnedSlice(allocator);
}

/// Free history entries returned by loadHistory.
pub fn freeHistory(allocator: std.mem.Allocator, history: [][]const u8) void {
    for (history) |entry| allocator.free(entry);
    allocator.free(history);
}

/// Save command history to a file (one command per line).
/// Writes at most MAX_HISTORY_LINES entries.
pub fn saveHistory(history: []const []const u8, path: []const u8) !void {
    const file = try fs_compat.createPath(path, .{ .truncate = true });
    defer file.close();

    const start = if (history.len > MAX_HISTORY_LINES) history.len - MAX_HISTORY_LINES else 0;
    for (history[start..]) |entry| {
        file.writeAll(entry) catch return;
        file.writeAll("\n") catch return;
    }
}

/// Resolve the default history file path (~/.nullclaw_history).
/// Caller owns the returned string.
pub fn defaultHistoryPath(allocator: std.mem.Allocator) ![]const u8 {
    const home = try platform.getHomeDir(allocator);
    defer allocator.free(home);
    return std_compat.fs.path.join(allocator, &.{ home, ".nullclaw_history" });
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "cli canonical reader trims CRLF and preserves partial EOF" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = std_compat.fs.Dir.wrap(tmp.dir);
    try dir.writeFile(.{ .sub_path = "input", .data = "first\r\nlast" });

    const file = try dir.openFile("input", .{});
    defer file.close();
    var line_buf: [32]u8 = undefined;

    const first = (try readCanonicalLine(file, &line_buf)).?;
    try std.testing.expectEqualStrings("first", first);
    const last = (try readCanonicalLine(file, &line_buf)).?;
    try std.testing.expectEqualStrings("last", last);
    try std.testing.expect((try readCanonicalLine(file, &line_buf)) == null);
}

test "cli canonical reader drains an overlong line" {
    // Regression: #865 follow-up — an oversized paste must not poison the next prompt.
    var input: [cli_line_editor.MAX_LINE_BYTES + 7]u8 = undefined;
    @memset(input[0 .. cli_line_editor.MAX_LINE_BYTES + 1], 'a');
    input[cli_line_editor.MAX_LINE_BYTES + 1] = '\n';
    @memcpy(input[cli_line_editor.MAX_LINE_BYTES + 2 ..], "next\n");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = std_compat.fs.Dir.wrap(tmp.dir);
    try dir.writeFile(.{ .sub_path = "input", .data = &input });

    const file = try dir.openFile("input", .{});
    defer file.close();
    var line_buf: [cli_line_editor.MAX_LINE_BYTES]u8 = undefined;

    try std.testing.expectError(error.LineTooLong, readCanonicalLine(file, &line_buf));
    const next = (try readCanonicalLine(file, &line_buf)).?;
    try std.testing.expectEqualStrings("next", next);
}

test "cli interactive reader uses canonical fallback for non-TTY input" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = std_compat.fs.Dir.wrap(tmp.dir);
    try dir.writeFile(.{ .sub_path = "input", .data = "hello\n" });

    const file = try dir.openFile("input", .{});
    defer file.close();
    var output_buf: [32]u8 = undefined;
    var writer = std.Io.Writer.fixed(&output_buf);
    var line_buf: [32]u8 = undefined;

    const line = (try readInteractiveLine(file, file, &writer, "> ", &.{}, &line_buf)).?;
    try std.testing.expectEqualStrings("hello", line);
    try std.testing.expectEqualStrings("> ", writer.buffered());
}

test "cli raw termios preserves queued input and disables line discipline" {
    // Regression: TCSA.FLUSH discarded typeahead and multi-line paste before debounce.
    if (comptime supportsRawMode()) {
        var original = std.mem.zeroes(std.posix.termios);
        original.iflag.IXON = true;
        original.iflag.IXOFF = true;
        original.lflag.ICANON = true;
        original.lflag.ECHO = true;
        original.lflag.ISIG = true;
        original.lflag.IEXTEN = true;

        const raw = CliRawMode.makeRaw(original);
        try std.testing.expect(!raw.iflag.IXON);
        try std.testing.expect(!raw.iflag.IXOFF);
        try std.testing.expect(!raw.lflag.ICANON);
        try std.testing.expect(!raw.lflag.ECHO);
        try std.testing.expect(!raw.lflag.ISIG);
        try std.testing.expect(!raw.lflag.IEXTEN);
        try std.testing.expectEqual(std.posix.TCSA.NOW, CliRawMode.enable_action);
        try std.testing.expectEqual(std.posix.TCSA.DRAIN, CliRawMode.disable_action);
    } else {
        return error.SkipZigTest;
    }
}

test "cli channel retains public readLine API" {
    comptime {
        _ = CliChannel.readLine;
    }
}

test "cli quit commands" {
    try std.testing.expect(CliChannel.isQuitCommand("exit"));
    try std.testing.expect(CliChannel.isQuitCommand("quit"));
    try std.testing.expect(CliChannel.isQuitCommand(":q"));
    try std.testing.expect(CliChannel.isQuitCommand("/quit"));
    try std.testing.expect(CliChannel.isQuitCommand("/exit"));
    try std.testing.expect(CliChannel.isQuitCommand("  exit  "));
    try std.testing.expect(CliChannel.isQuitCommand("  :q  "));
    try std.testing.expect(!CliChannel.isQuitCommand("hello"));
    try std.testing.expect(!CliChannel.isQuitCommand(""));
}

test "loadHistory reads file lines" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const tmp_path = try std_compat.fs.path.join(allocator, &.{ base, "history_test" });
    defer allocator.free(tmp_path);

    // Write a temporary history file
    {
        const f = try fs_compat.createPath(tmp_path, .{ .truncate = true });
        defer f.close();
        try f.writeAll("hello world\nhow are you\ngoodbye\n");
    }

    const history = try loadHistory(allocator, tmp_path);
    defer freeHistory(allocator, history);

    try std.testing.expectEqual(@as(usize, 3), history.len);
    try std.testing.expectEqualStrings("hello world", history[0]);
    try std.testing.expectEqualStrings("how are you", history[1]);
    try std.testing.expectEqualStrings("goodbye", history[2]);
}

test "loadHistory returns empty for missing file" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const tmp_path = try std_compat.fs.path.join(allocator, &.{ base, "nonexistent_history_file" });
    defer allocator.free(tmp_path);

    const history = try loadHistory(allocator, tmp_path);
    defer freeHistory(allocator, history);
    try std.testing.expectEqual(@as(usize, 0), history.len);
}

test "saveHistory writes file" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const tmp_path = try std_compat.fs.path.join(allocator, &.{ base, "save_history_test" });
    defer allocator.free(tmp_path);

    const entries = [_][]const u8{ "first", "second", "third" };
    try saveHistory(&entries, tmp_path);

    // Read back and verify
    const loaded = try loadHistory(allocator, tmp_path);
    defer freeHistory(allocator, loaded);

    try std.testing.expectEqual(@as(usize, 3), loaded.len);
    try std.testing.expectEqualStrings("first", loaded[0]);
    try std.testing.expectEqualStrings("second", loaded[1]);
    try std.testing.expectEqualStrings("third", loaded[2]);
}

test "saveHistory and loadHistory roundtrip" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const tmp_path = try std_compat.fs.path.join(allocator, &.{ base, "roundtrip_history_test" });
    defer allocator.free(tmp_path);

    // Save
    const entries = [_][]const u8{ "alpha", "beta" };
    try saveHistory(&entries, tmp_path);

    // Load
    const loaded = try loadHistory(allocator, tmp_path);
    defer freeHistory(allocator, loaded);

    try std.testing.expectEqual(@as(usize, 2), loaded.len);
    try std.testing.expectEqualStrings("alpha", loaded[0]);
    try std.testing.expectEqualStrings("beta", loaded[1]);
}

test "loadHistory trims whitespace from entries" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const tmp_path = try std_compat.fs.path.join(allocator, &.{ base, "trim_history_test" });
    defer allocator.free(tmp_path);

    {
        const f = try fs_compat.createPath(tmp_path, .{ .truncate = true });
        defer f.close();
        try f.writeAll("  hello  \n\t world \t\nfoo\r\n");
    }

    const history = try loadHistory(allocator, tmp_path);
    defer freeHistory(allocator, history);

    try std.testing.expectEqual(@as(usize, 3), history.len);
    try std.testing.expectEqualStrings("hello", history[0]);
    try std.testing.expectEqualStrings("world", history[1]);
    try std.testing.expectEqualStrings("foo", history[2]);
}

test "loadHistory skips blank lines" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const tmp_path = try std_compat.fs.path.join(allocator, &.{ base, "blank_history_test" });
    defer allocator.free(tmp_path);

    {
        const f = try fs_compat.createPath(tmp_path, .{ .truncate = true });
        defer f.close();
        try f.writeAll("first\n\n   \n\nsecond\n  \nthird\n");
    }

    const history = try loadHistory(allocator, tmp_path);
    defer freeHistory(allocator, history);

    try std.testing.expectEqual(@as(usize, 3), history.len);
    try std.testing.expectEqualStrings("first", history[0]);
    try std.testing.expectEqualStrings("second", history[1]);
    try std.testing.expectEqualStrings("third", history[2]);
}

test "loadHistory enforces max entries limit" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const tmp_path = try std_compat.fs.path.join(allocator, &.{ base, "max_history_test" });
    defer allocator.free(tmp_path);

    {
        const f = try fs_compat.createPath(tmp_path, .{ .truncate = true });
        defer f.close();
        // Write more than MAX_HISTORY_LINES (500) entries
        for (0..600) |i| {
            var buf: [32]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, "cmd-{d}\n", .{i}) catch unreachable;
            f.writeAll(line) catch break;
        }
    }

    const history = try loadHistory(allocator, tmp_path);
    defer freeHistory(allocator, history);

    // Should be capped at MAX_HISTORY_LINES (500)
    try std.testing.expectEqual(@as(usize, MAX_HISTORY_LINES), history.len);
    // First entry should be cmd-100 (600 - 500 = 100 oldest dropped)
    try std.testing.expectEqualStrings("cmd-100", history[0]);
    // Last entry should be cmd-599
    try std.testing.expectEqualStrings("cmd-599", history[history.len - 1]);
}

test "MAX_HISTORY_LINES is 500" {
    try std.testing.expectEqual(@as(usize, 500), MAX_HISTORY_LINES);
}

test "CliChannel create + healthCheck + stop leaks zero bytes" {
    const alloc = std.testing.allocator;

    // CliChannel has no config — allocator only.
    var ch_struct = CliChannel.init(alloc);

    // Acquire vtable interface.
    const ch = ch_struct.channel();

    // healthCheck must be callable in any state.
    _ = ch.healthCheck();

    // stop without start must be safe (per Channel contract).
    ch.stop();
}
