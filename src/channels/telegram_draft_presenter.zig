const std = @import("std");

// Telegram draft previews are easy to rate-limit if we flush tiny deltas too
// aggressively. Use noticeably coarser thresholds so users still see progress
// without hammering sendMessageDraft on every token burst.
pub const DRAFT_FLUSH_MIN_DELTA_BYTES: usize = 512;
pub const DRAFT_FLUSH_MIN_INTERVAL_MS: i64 = 4 * std.time.ms_per_s;
pub const DRAFT_HEARTBEAT_INTERVAL_MS: i64 = 12 * std.time.ms_per_s;
pub const DRAFT_TRANSPORT_MAX_BYTES: usize = 3000;

const DRAFT_TRIM_BYTES = " \t\r\n";
const DRAFT_PROGRESS_PREFIX = "Processing request...\n";
const DRAFT_PROGRESS_TAIL_LABEL = "\n\nLatest excerpt:\n";
const DRAFT_PROGRESS_HEARTBEAT_ONLY = "Interim result is still being prepared.";

pub const DraftState = struct {
    draft_id: u64,
    buffer: std.ArrayListUnmanaged(u8) = .empty,
    last_flush_len: usize = 0,
    last_flush_time: i64 = 0,
    started_at_ms: i64 = 0,
    suppress_until_ms: i64 = 0,

    pub fn deinit(self: *DraftState, allocator: std.mem.Allocator) void {
        self.buffer.deinit(allocator);
    }
};

pub const DraftFlush = struct {
    draft_id: u64,
    text: []u8,
    started_at_ms: i64,

    pub fn deinit(self: *DraftFlush, allocator: std.mem.Allocator) void {
        allocator.free(self.text);
    }
};

fn trimmedDraftText(text: []const u8) []const u8 {
    return std.mem.trim(u8, text, DRAFT_TRIM_BYTES);
}

pub fn hasVisibleDraftText(text: []const u8) bool {
    return trimmedDraftText(text).len != 0;
}

fn bytesSinceLastFlush(state: *const DraftState) usize {
    return state.buffer.items.len - state.last_flush_len;
}

fn millisSinceLastFlush(state: *const DraftState, now_ms: i64) i64 {
    return now_ms - state.last_flush_time;
}

fn flushDeltaReached(state: *const DraftState) bool {
    return bytesSinceLastFlush(state) >= DRAFT_FLUSH_MIN_DELTA_BYTES;
}

fn flushIntervalElapsed(state: *const DraftState, now_ms: i64) bool {
    return millisSinceLastFlush(state, now_ms) >= DRAFT_FLUSH_MIN_INTERVAL_MS;
}

fn draftSuppressed(state: *const DraftState, now_ms: i64) bool {
    return state.suppress_until_ms > now_ms;
}

fn shouldFlushDraft(state: *const DraftState, now_ms: i64) bool {
    if (draftSuppressed(state, now_ms)) return false;
    return flushDeltaReached(state) or flushIntervalElapsed(state, now_ms);
}

fn hasPendingVisibleDraft(state: *const DraftState) bool {
    if (state.buffer.items.len <= state.last_flush_len) return false;
    return hasVisibleDraftText(state.buffer.items[state.last_flush_len..]);
}

fn snapshotDraftText(allocator: std.mem.Allocator, state: *const DraftState) ![]u8 {
    return allocator.dupe(u8, state.buffer.items);
}

fn alignUtf8Start(text: []const u8, start: usize) usize {
    var idx = @min(start, text.len);
    while (idx < text.len and (text[idx] & 0xC0) == 0x80) : (idx += 1) {}
    return idx;
}

fn draftTailSlice(text: []const u8, max_bytes: usize) []const u8 {
    if (text.len <= max_bytes) return text;
    const raw_start = text.len - max_bytes;
    return text[alignUtf8Start(text, raw_start)..];
}

fn appendElapsedSummary(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, text_len: usize, started_at_ms: i64, now_ms: i64) !void {
    const elapsed_ms = if (started_at_ms > 0 and now_ms > started_at_ms) now_ms - started_at_ms else 0;
    const elapsed_secs = @divFloor(elapsed_ms, std.time.ms_per_s);
    try buf.writer(allocator).print("Elapsed: {d}s\nCurrent size: {d} bytes", .{
        elapsed_secs,
        text_len,
    });
}

pub fn buildHeartbeatText(allocator: std.mem.Allocator, started_at_ms: i64, now_ms: i64) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, DRAFT_PROGRESS_PREFIX);
    try appendElapsedSummary(&out, allocator, 0, started_at_ms, now_ms);
    try out.appendSlice(allocator, "\n");
    try out.appendSlice(allocator, DRAFT_PROGRESS_HEARTBEAT_ONLY);
    return out.toOwnedSlice(allocator);
}

pub fn buildTransportText(
    allocator: std.mem.Allocator,
    text: []const u8,
    started_at_ms: i64,
    now_ms: i64,
) ![]u8 {
    if (text.len <= DRAFT_TRANSPORT_MAX_BYTES) return allocator.dupe(u8, text);

    var prefix: std.ArrayListUnmanaged(u8) = .empty;
    defer prefix.deinit(allocator);
    try prefix.appendSlice(allocator, DRAFT_PROGRESS_PREFIX);
    try appendElapsedSummary(&prefix, allocator, text.len, started_at_ms, now_ms);
    try prefix.appendSlice(allocator, DRAFT_PROGRESS_TAIL_LABEL);

    if (prefix.items.len >= DRAFT_TRANSPORT_MAX_BYTES) {
        return allocator.dupe(u8, prefix.items[0..DRAFT_TRANSPORT_MAX_BYTES]);
    }

    const tail_budget = DRAFT_TRANSPORT_MAX_BYTES - prefix.items.len;
    const tail = draftTailSlice(text, tail_budget);

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, prefix.items);
    try out.appendSlice(allocator, tail);
    return out.toOwnedSlice(allocator);
}

fn markDraftFlushed(state: *DraftState, now_ms: i64) void {
    state.last_flush_len = state.buffer.items.len;
    state.last_flush_time = now_ms;
}

pub fn appendDraftChunk(
    allocator: std.mem.Allocator,
    state: *DraftState,
    chunk: []const u8,
    now_ms: i64,
) !?DraftFlush {
    if (chunk.len == 0) return null;

    try state.buffer.appendSlice(allocator, chunk);
    if (!shouldFlushDraft(state, now_ms)) return null;
    if (!hasVisibleDraftText(state.buffer.items)) return null;

    const text = try snapshotDraftText(allocator, state);
    markDraftFlushed(state, now_ms);
    return .{
        .draft_id = state.draft_id,
        .text = text,
        .started_at_ms = state.started_at_ms,
    };
}

pub fn heartbeatDraft(
    allocator: std.mem.Allocator,
    state: *DraftState,
    now_ms: i64,
) !?DraftFlush {
    if (draftSuppressed(state, now_ms)) return null;
    if (millisSinceLastFlush(state, now_ms) < DRAFT_HEARTBEAT_INTERVAL_MS) return null;

    if (hasPendingVisibleDraft(state)) {
        const text = try snapshotDraftText(allocator, state);
        markDraftFlushed(state, now_ms);
        return .{
            .draft_id = state.draft_id,
            .text = text,
            .started_at_ms = state.started_at_ms,
        };
    }

    if (hasVisibleDraftText(state.buffer.items)) return null;

    state.last_flush_time = now_ms;
    return .{
        .draft_id = state.draft_id,
        .text = try buildHeartbeatText(allocator, state.started_at_ms, now_ms),
        .started_at_ms = state.started_at_ms,
    };
}

pub fn suppressDraft(state: *DraftState, now_ms: i64, retry_after_secs: u32) void {
    const retry_after_ms = @as(i64, @intCast(retry_after_secs)) * std.time.ms_per_s;
    suppressDraftUntilMs(state, now_ms + retry_after_ms);
}

pub fn suppressDraftUntilMs(state: *DraftState, suppress_until_ms: i64) void {
    if (suppress_until_ms > state.suppress_until_ms) {
        state.suppress_until_ms = suppress_until_ms;
    }
}

pub fn clearDraftForTarget(
    allocator: std.mem.Allocator,
    draft_buffers: *std.StringHashMapUnmanaged(DraftState),
    target: []const u8,
) void {
    if (draft_buffers.fetchRemove(target)) |entry| {
        allocator.free(entry.key);
        var draft = entry.value;
        draft.deinit(allocator);
    }
}

pub fn deinitDraftBuffers(
    allocator: std.mem.Allocator,
    draft_buffers: *std.StringHashMapUnmanaged(DraftState),
) void {
    var it = draft_buffers.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        entry.value_ptr.deinit(allocator);
    }
    draft_buffers.deinit(allocator);
    draft_buffers.* = .empty;
}

test "appendDraftChunk ignores empty chunks" {
    var draft: DraftState = .{ .draft_id = 1 };
    defer draft.deinit(std.testing.allocator);

    try std.testing.expect((try appendDraftChunk(std.testing.allocator, &draft, "", 0)) == null);
    try std.testing.expectEqual(@as(usize, 0), draft.buffer.items.len);
}

test "appendDraftChunk keeps whitespace-only drafts local" {
    var draft: DraftState = .{ .draft_id = 7 };
    defer draft.deinit(std.testing.allocator);

    try std.testing.expect((try appendDraftChunk(std.testing.allocator, &draft, "   \n\t", DRAFT_FLUSH_MIN_INTERVAL_MS)) == null);
    try std.testing.expectEqual(@as(usize, 5), draft.buffer.items.len);
    try std.testing.expectEqual(@as(usize, 0), draft.last_flush_len);
}

test "appendDraftChunk flushes visible content after interval" {
    var draft: DraftState = .{ .draft_id = 3 };
    defer draft.deinit(std.testing.allocator);

    const flush = (try appendDraftChunk(std.testing.allocator, &draft, "hello", DRAFT_FLUSH_MIN_INTERVAL_MS + 1)) orelse
        return error.TestUnexpectedResult;
    defer {
        var tmp = flush;
        tmp.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(u64, 3), flush.draft_id);
    try std.testing.expectEqualStrings("hello", flush.text);
    try std.testing.expectEqual(@as(i64, 0), flush.started_at_ms);
    try std.testing.expectEqual(@as(usize, 5), draft.last_flush_len);
}

test "appendDraftChunk stays quiet while suppressed" {
    var draft: DraftState = .{ .draft_id = 11 };
    defer draft.deinit(std.testing.allocator);

    suppressDraft(&draft, 1000, 5);
    try std.testing.expect((try appendDraftChunk(std.testing.allocator, &draft, "hello world", 2000)) == null);
    try std.testing.expectEqual(@as(usize, 11), draft.buffer.items.len);
    try std.testing.expectEqual(@as(usize, 0), draft.last_flush_len);
}

test "buildTransportText compacts long draft into progress preview" {
    const long_text = "abcdef" ** 700;
    const compact = try buildTransportText(std.testing.allocator, long_text, 1_000, 16_000);
    defer std.testing.allocator.free(compact);

    try std.testing.expect(compact.len <= DRAFT_TRANSPORT_MAX_BYTES);
    try std.testing.expect(std.mem.startsWith(u8, compact, DRAFT_PROGRESS_PREFIX));
    try std.testing.expect(std.mem.indexOf(u8, compact, "Latest excerpt:") != null);
    try std.testing.expect(std.mem.endsWith(u8, compact, long_text[long_text.len - 32 ..]));
}

test "buildHeartbeatText emits visible progress status" {
    const heartbeat = try buildHeartbeatText(std.testing.allocator, 5_000, 17_500);
    defer std.testing.allocator.free(heartbeat);

    try std.testing.expect(hasVisibleDraftText(heartbeat));
    try std.testing.expect(std.mem.indexOf(u8, heartbeat, "Interim result is still being prepared.") != null);
}

test "heartbeatDraft flushes pending visible text after interval" {
    var draft: DraftState = .{
        .draft_id = 21,
        .started_at_ms = 1_000,
        .last_flush_time = 1_000,
    };
    defer draft.deinit(std.testing.allocator);
    try draft.buffer.appendSlice(std.testing.allocator, "hello");

    const flush = (try heartbeatDraft(std.testing.allocator, &draft, 1_000 + DRAFT_HEARTBEAT_INTERVAL_MS + 1)) orelse
        return error.TestUnexpectedResult;
    defer {
        var tmp = flush;
        tmp.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(u64, 21), flush.draft_id);
    try std.testing.expectEqualStrings("hello", flush.text);
    try std.testing.expectEqual(@as(usize, 5), draft.last_flush_len);
    try std.testing.expectEqual(@as(i64, 1_000 + DRAFT_HEARTBEAT_INTERVAL_MS + 1), draft.last_flush_time);
}

test "heartbeatDraft stays quiet when visible text was already flushed" {
    var draft: DraftState = .{
        .draft_id = 22,
        .started_at_ms = 1_000,
        .last_flush_time = 1_000,
        .last_flush_len = 5,
    };
    defer draft.deinit(std.testing.allocator);
    try draft.buffer.appendSlice(std.testing.allocator, "hello");

    try std.testing.expect((try heartbeatDraft(std.testing.allocator, &draft, 1_000 + DRAFT_HEARTBEAT_INTERVAL_MS + 1)) == null);
}

test "heartbeatDraft emits heartbeat when no visible draft is available" {
    var draft: DraftState = .{
        .draft_id = 23,
        .started_at_ms = 5_000,
        .last_flush_time = 5_000,
    };
    defer draft.deinit(std.testing.allocator);
    try draft.buffer.appendSlice(std.testing.allocator, " \n\t");

    const flush = (try heartbeatDraft(std.testing.allocator, &draft, 5_000 + DRAFT_HEARTBEAT_INTERVAL_MS + 1)) orelse
        return error.TestUnexpectedResult;
    defer {
        var tmp = flush;
        tmp.deinit(std.testing.allocator);
    }

    try std.testing.expect(std.mem.indexOf(u8, flush.text, "Interim result is still being prepared.") != null);
    try std.testing.expectEqual(@as(usize, 0), draft.last_flush_len);
    try std.testing.expectEqual(@as(i64, 5_000 + DRAFT_HEARTBEAT_INTERVAL_MS + 1), draft.last_flush_time);
}
