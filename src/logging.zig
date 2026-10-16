//! Non-blocking logging for the gateway.
//!
//! Zig's default `std.log` implementation formats straight to stderr while
//! holding a process-global lock (`std.debug.lockStderr`). In the gateway every
//! session turn holds its `Session.mutex` for the whole turn, and a turn that
//! logs while a *different* thread is blocked inside a stderr write parks on
//! that global lock: one wedged stderr write (a full docker json-file log pipe,
//! a stalled log driver) then parks every logging thread in `futex_do_wait`
//! with the CPU idle — the incident signature.
//!
//! `logFn` formats the line into a fixed stack buffer and hands it to `emit`, a
//! single non-generic (`noinline`) function. After `start()` `emit` enqueues
//! into a bounded ring drained by one dedicated thread; producers never block:
//! if the ring lock is busy or the ring is full the line is dropped and counted.
//! Only the drain thread can block on stderr, so a stuck log sink can no longer
//! wedge a turn.
//!
//! Formatting stays generic (it must, to type-check `format`/`args` per call
//! site), but the fallback no longer reaches `std.log.defaultLog`: calling it
//! instantiated the whole `defaultLog`/`defaultLogFileTerminal` body — with its
//! own per-call-site formatting — at every log call site, roughly doubling the
//! formatting code and adding ~300 KB to a ReleaseSmall musl binary. `emit` is
//! one out-of-line function instead.
//!
//! Install with `pub const std_options: std.Options = .{ .logFn = logging.logFn };`
//! in the executable root, and call `start()` from the gateway. Until `start()`
//! runs (other CLI commands, tests) `emit` writes the already-formatted line to
//! stderr itself: the same `level(scope): message` prefix as `std.log.defaultLog`,
//! but plain monochrome text — it does not emit the ANSI color sequences
//! `defaultLogFileTerminal` uses on a TTY, and (like the ring) it bounds the
//! line to `MAX_LINE` and keeps it newline-terminated.

const std = @import("std");
const std_compat = @import("compat");

/// Longest record, including the terminating newline. The formatted line is
/// truncated to `MAX_LINE - 1` bytes at a UTF-8 boundary so the reserved last
/// byte can hold `'\n'`; a record is therefore always a single newline-
/// terminated, bounded write.
const MAX_LINE = 1024;

/// Number of queued records. When full, producers drop rather than block.
///
/// 256 × 1 KiB = 256 KiB of BSS.
/// The ring only has to absorb the burst that arrives between two drain cycles
/// (the drain thread empties it continuously) and overflow is a counted drop,
/// never a block, so a shallow ring costs nothing in correctness.
const RING_CAPACITY = 256;

const Record = struct {
    len: u16,
    buf: [MAX_LINE]u8,
};

var mutex: std_compat.sync.Mutex = .{};
var not_empty: std_compat.sync.Condition = .{};
var ring: [RING_CAPACITY]Record = undefined;
var head: usize = 0;
var tail: usize = 0;
var stop_requested: bool = false;
var running = std.atomic.Value(bool).init(false);
var drain_thread: ?std.Thread = null;

/// Lines dropped because a producer could not take the ring lock or found the
/// ring full. Kept for diagnostics and the regression test.
var dropped = std.atomic.Value(usize).init(0);

/// Spawn the drain thread and route logging through the ring. Idempotent.
/// Call once from the gateway before serving traffic.
pub fn start() void {
    mutex.lock();
    defer mutex.unlock();
    if (running.load(.acquire)) return;

    head = 0;
    tail = 0;
    stop_requested = false;
    running.store(true, .release);
    drain_thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, drainMain, .{}) catch |err| {
        // Without a drain thread the ring would never empty: fall back to the
        // default (blocking) logger rather than dropping every line.
        running.store(false, .release);
        std.log.scoped(.logging).warn("non-blocking logger unavailable, using default: {}", .{err});
        return;
    };
}

/// std_options.logFn: format one line into a fixed stack buffer, then hand the
/// bytes to the single non-generic `emit`. Keeping only the formatting generic
/// (it must type-check `format`/`args` per call site) is what avoids a per-call-
/// site copy of `std.log.defaultLog`.
pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    var buf: [MAX_LINE]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    w.print("{s}", .{level.asText()}) catch {};
    if (scope != .default) w.print("({t})", .{scope}) catch {};
    w.print(": " ++ format ++ "\n", args) catch {};
    emit(buf[0..w.end]);
}

/// The one non-generic logging function: either enqueue the line for the drain
/// thread, or — before `start()` — write it to stderr directly. Never blocks a
/// producer on the log sink. `noinline` keeps this a single out-of-line copy so
/// the ring/stderr logic is not duplicated into every generic `logFn` call site.
noinline fn emit(line: []const u8) void {
    if (!running.load(.acquire)) {
        const stderr = std_compat.fs.File.stderr();
        const shown = clampToRecord(line);
        stderr.writeAll(shown) catch {};
        if (shown.len < line.len) stderr.writeAll("\n") catch {};
        return;
    }

    if (!mutex.tryLock()) {
        // A drain (or another producer) holds the lock; do not wait.
        _ = dropped.fetchAdd(1, .monotonic);
        return;
    }
    defer mutex.unlock();

    const next = (head + 1) % RING_CAPACITY;
    if (next == tail) {
        _ = dropped.fetchAdd(1, .monotonic);
        return;
    }

    const rec = &ring[head];
    const shown = clampToRecord(line);
    @memcpy(rec.buf[0..shown.len], shown);
    if (shown.len < line.len) {
        // clampToRecord cut before the formatter's trailing newline; put one in
        // the byte it reserved so the drained line stays newline-terminated.
        rec.buf[shown.len] = '\n';
        rec.len = @intCast(shown.len + 1);
    } else {
        rec.len = @intCast(shown.len);
    }
    head = next;
    not_empty.signal();
}

/// Truncate `line` to at most `MAX_LINE - 1` bytes without splitting a UTF-8
/// sequence, leaving the last byte of a record for the terminating newline.
fn clampToRecord(line: []const u8) []const u8 {
    if (line.len <= MAX_LINE - 1) return line;
    var end: usize = MAX_LINE - 1;
    // Walk back over UTF-8 continuation bytes (0b10xxxxxx) so the cut lands on
    // the start of a code point rather than inside one.
    while (end > 0 and (line[end] & 0xC0) == 0x80) end -= 1;
    return line[0..end];
}

fn drainMain() void {
    const stderr = std_compat.fs.File.stderr();
    while (true) {
        mutex.lock();
        while (head == tail and !stop_requested) not_empty.wait(&mutex);
        if (head == tail) {
            mutex.unlock();
            return;
        }
        const rec = ring[tail];
        tail = (tail + 1) % RING_CAPACITY;
        mutex.unlock();

        // This is the only place that can block on the log sink. If it does,
        // producers keep dropping into the ring and the gateway keeps running.
        stderr.writeAll(rec.buf[0..rec.len]) catch {};
    }
}

fn resetForTest() void {
    mutex.lock();
    defer mutex.unlock();
    head = 0;
    tail = 0;
    stop_requested = false;
    dropped.store(0, .monotonic);
    running.store(false, .release);
}

test "logFn formats and enqueues a newline-terminated line into the ring" {
    resetForTest();
    defer resetForTest();
    running.store(true, .release);

    logFn(.warn, .test_scope, "value={d}", .{42});

    mutex.lock();
    const count = head;
    const rec = ring[0];
    mutex.unlock();

    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expect(std.mem.startsWith(u8, rec.buf[0..rec.len], "warning(test_scope): "));
    try std.testing.expect(std.mem.indexOf(u8, rec.buf[0..rec.len], "value=42") != null);
    try std.testing.expectEqual(@as(u8, '\n'), rec.buf[rec.len - 1]);
}

test "logFn drops instead of blocking when the ring lock is held" {
    resetForTest();
    defer resetForTest();
    running.store(true, .release);

    // Simulate a drain thread parked on a wedged stderr write: it holds the
    // lock, so a producer must return immediately and count the drop rather
    // than waiting (which is what wedged the whole process in futex_do_wait).
    mutex.lock();
    logFn(.info, .test_scope, "while locked", .{});
    mutex.unlock();

    try std.testing.expectEqual(@as(usize, 1), dropped.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), head);
}

test "logFn drops when the ring is full" {
    resetForTest();
    defer resetForTest();
    running.store(true, .release);

    // Fill to capacity (one slot is reserved to distinguish full from empty).
    var i: usize = 0;
    while (i < RING_CAPACITY - 1) : (i += 1) {
        logFn(.info, .test_scope, "line {d}", .{i});
    }
    try std.testing.expectEqual(@as(usize, 0), dropped.load(.monotonic));

    logFn(.info, .test_scope, "overflow", .{});
    try std.testing.expectEqual(@as(usize, 1), dropped.load(.monotonic));
}

test "clampToRecord truncates at a UTF-8 boundary and reserves the newline" {
    resetForTest();
    defer resetForTest();
    running.store(true, .release);

    // U+1F600 is four bytes, and MAX_LINE - 1 == 1023 is not a multiple of 4
    // (1023 % 4 == 3), so a naive `line[0 .. MAX_LINE - 1]` bisects a character
    // and the walk-back over continuation bytes is what makes the cut valid.
    const emoji = "\xf0\x9f\x98\x80";
    var line: [2100]u8 = undefined;
    var i: usize = 0;
    while (i < line.len) : (i += 4) @memcpy(line[i..][0..4], emoji);

    const clamped = clampToRecord(&line);
    try std.testing.expectEqual(@as(usize, 1020), clamped.len);
    try std.testing.expectEqual(@as(usize, 0), clamped.len % 4);
    try std.testing.expectEqualSlices(u8, emoji, clamped[clamped.len - 4 ..]);

    // emit must turn the truncated record into a newline-terminated one.
    emit(&line);
    mutex.lock();
    const rec = ring[0];
    mutex.unlock();
    try std.testing.expectEqual(@as(usize, 1021), rec.len);
    try std.testing.expectEqual(@as(u8, '\n'), rec.buf[rec.len - 1]);
}
