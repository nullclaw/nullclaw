//! Standalone SSE (Server-Sent Events) streaming client.
//!
//! This module is kept separate from the rest of the codebase to avoid
//! Zig 0.15 namespace collision bugs when std.http is used alongside
//! modules that export 'http' symbols.
//!
//! Provides persistent SSE connections with chunked transfer encoding
//! support for real-time message delivery.

const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const http_util = @import("http_util.zig");
const log = std.log.scoped(.sse_client);

/// Maximum SSE event size (256KB)
/// Events larger than this are truncated to prevent memory exhaustion
const MAX_EVENT_SIZE = 256 * 1024;

/// Maximum buffer size for read operations
/// Prevents buffer overflow attacks and memory exhaustion
const MAX_BUFFER_SIZE = 8192;

/// Maximum wait time for new bytes before returning to caller.
/// Keeps polling loops responsive to shutdown and reconnect signals.
const READ_TIMEOUT_MS: i32 = 1000;

/// SSE connection that maintains a persistent HTTP connection for streaming
pub const SseConnection = struct {
    allocator: std.mem.Allocator,
    client: http_util.ProxyHttpClient,
    request: ?std.http.Client.Request,
    /// The body reader for streaming response data
    body_reader: ?*std.Io.Reader,
    url: []const u8,
    /// Buffer for reading response data
    transfer_buf: [4096]u8,
    /// Last received event ID for reconnection (W3C SSE spec).
    /// Sent as Last-Event-ID header on reconnect so the server can resume.
    last_event_id: ?[]const u8 = null,

    pub const Error = error{
        NotConnected,
        ConnectionFailed,
        ConnectionClosed,
        ReadError,
    };

    /// Initialize a new SSE connection (not yet connected)
    pub fn init(allocator: std.mem.Allocator, url: []const u8) !SseConnection {
        return .{
            .allocator = allocator,
            .client = try http_util.ProxyHttpClient.init(allocator),
            .request = null,
            .body_reader = null,
            .url = url,
            .transfer_buf = undefined,
        };
    }

    /// Clean up resources
    /// Properly closes HTTP connection and frees client resources
    pub fn deinit(self: *SseConnection) void {
        self.body_reader = null;
        // Deinit request (this also releases the connection).
        if (self.request) |*req| {
            req.deinit();
            self.request = null;
        }
        // Deinit client (closes any remaining connections).
        self.client.deinit();
        if (self.last_event_id) |id| self.allocator.free(id);
        self.last_event_id = null;
    }

    /// Update the stored last event ID (takes ownership via dupe).
    pub fn setLastEventId(self: *SseConnection, id: []const u8) void {
        if (self.last_event_id) |old| self.allocator.free(old);
        self.last_event_id = self.allocator.dupe(u8, id) catch null;
    }

    /// Connect to SSE endpoint and start streaming
    /// Returns the HTTP status code
    pub fn connect(self: *SseConnection) !u16 {
        // URL already includes account query param from Signal channel config.
        const uri = try std.Uri.parse(self.url);
        self.body_reader = null;

        // Build request options with SSE headers.
        // Per W3C SSE spec, send Last-Event-ID on reconnection so the server
        // can replay missed events.
        var extra_headers_buf: [2]std.http.Header = undefined;
        var n_headers: usize = 0;
        extra_headers_buf[n_headers] = .{ .name = "Accept", .value = "text/event-stream" };
        n_headers += 1;
        if (self.last_event_id) |id| {
            extra_headers_buf[n_headers] = .{ .name = "Last-Event-ID", .value = id };
            n_headers += 1;
        }
        const options: std.http.Client.RequestOptions = .{ .extra_headers = extra_headers_buf[0..n_headers] };

        // Replace any previous request before opening a new stream.
        if (self.request) |*req| {
            req.deinit();
            self.request = null;
        }

        self.request = try self.client.client.request(.GET, uri, options);
        const req = &self.request.?;
        errdefer {
            req.deinit();
            self.request = null;
            self.body_reader = null;
        }

        // Send request (no body for GET)
        try req.sendBodiless();

        // Receive response headers
        var redirect_buf: [4096]u8 = undefined;
        const response = try req.receiveHead(&redirect_buf);

        const status_code = @intFromEnum(response.head.status);
        if (status_code < 200 or status_code >= 300) {
            return error.ConnectionFailed;
        }

        // Read via HTTP body reader so chunked framing is decoded correctly.
        self.body_reader = req.reader.bodyReader(&self.transfer_buf, response.head.transfer_encoding, response.head.content_length);

        log.info("SSE connected to {s} (status: {d})", .{ self.url, status_code });
        return status_code;
    }

    /// Read data from the SSE stream into the provided buffer
    /// Returns the number of bytes read, or 0 if no data available
    ///
    /// Strategy:
    /// 1. Drain all already-buffered HTTP body bytes (non-blocking)
    /// 2. If data was read, return it immediately
    /// 3. If empty, poll socket for readability with timeout
    /// 4. Read one byte, then drain additional arrivals
    /// 5. Return accumulated data
    ///
    /// This approach minimizes latency while maximizing throughput by:
    /// - Returning immediately when buffered data is available
    /// - Bounding empty waits with a poll timeout
    /// - Coalescing multiple small reads into larger batches
    pub fn read(self: *SseConnection, buf: []u8) !usize {
        const reader = self.body_reader orelse return error.NotConnected;
        if (buf.len == 0) return 0;
        // Limit buffer size to prevent overflow
        if (buf.len > MAX_BUFFER_SIZE) {
            return self.read(buf[0..MAX_BUFFER_SIZE]);
        }

        var total_read: usize = 0;

        // Phase 1: Drain all already-buffered data
        var buffered = reader.bufferedLen();
        while (buffered > 0 and total_read < buf.len) {
            const to_read = @min(buffered, buf.len - total_read);
            const data = reader.take(to_read) catch |err| switch (err) {
                error.EndOfStream => {
                    if (total_read > 0) return total_read;
                    return error.ConnectionClosed;
                },
                else => return error.ReadError,
            };
            if (data.len == 0) break;
            @memcpy(buf[total_read..][0..data.len], data);
            total_read += data.len;
            buffered = reader.bufferedLen();
        }

        if (total_read >= buf.len) {
            // Buffer full - return what we have
            return total_read;
        }

        // Phase 2: If we have some data already, return it now
        // The caller will poll again soon for any new arrivals
        if (total_read > 0) {
            return total_read;
        }

        // Phase 3: Buffer empty and no data yet - wait briefly for readability
        if (!(try self.waitForReadable(READ_TIMEOUT_MS))) {
            return 0;
        }

        const first = reader.take(1) catch |err| switch (err) {
            error.EndOfStream => return error.ConnectionClosed,
            else => return error.ReadError,
        };

        if (first.len == 0) return 0;

        buf[0] = first[0];
        total_read = 1;

        // Phase 4: After getting first byte, drain any additional buffered data
        buffered = reader.bufferedLen();
        while (buffered > 0 and total_read < buf.len) {
            const to_read = @min(buffered, buf.len - total_read);
            const data = reader.take(to_read) catch |err| switch (err) {
                error.EndOfStream => return total_read,
                else => return error.ReadError,
            };
            if (data.len == 0) break;
            @memcpy(buf[total_read..][0..data.len], data);
            total_read += data.len;
            buffered = reader.bufferedLen();
        }

        return total_read;
    }

    fn waitForReadable(self: *SseConnection, timeout_ms: i32) Error!bool {
        if (self.request == null) return error.NotConnected;
        const conn = self.request.?.connection orelse return error.NotConnected;
        // For TLS and buffered transports, data may already be decoded and
        // available even when the socket is not currently poll-readable.
        if (conn.reader().bufferedLen() > 0) return true;

        if (comptime builtin.os.tag == .windows) {
            if (timeout_ms > 0) {
                std_compat.thread.sleep(@as(u64, @intCast(timeout_ms)) * std.time.ns_per_ms);
            }
            return conn.reader().bufferedLen() > 0;
        }

        const stream = conn.stream_reader.stream;

        var poll_fds = [_]std.posix.pollfd{
            .{
                .fd = stream.socket.handle,
                .events = std.posix.POLL.IN,
                .revents = undefined,
            },
        };

        const events = std.posix.poll(&poll_fds, timeout_ms) catch return error.ReadError;
        if (events == 0) return false;

        const revents = poll_fds[0].revents;
        if (revents & std.posix.POLL.IN != 0) return true;
        if (revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL) != 0) {
            return error.ConnectionClosed;
        }
        return false;
    }

    /// Check if the connection is still active
    pub fn isConnected(self: *SseConnection) bool {
        return self.request != null and self.body_reader != null;
    }
};

/// SSE event data structure
pub const SseEvent = struct {
    data: []const u8,
    /// Event type from the "event:" field (empty string means default "message").
    /// Owned by the caller; freed on deinit.
    event_type: []const u8 = "",
    /// Last event ID from the "id:" field (empty string if not set).
    /// Owned by the caller; freed on deinit.
    id: []const u8 = "",

    pub fn deinit(self: *SseEvent, allocator: std.mem.Allocator) void {
        if (self.event_type.len > 0) allocator.free(self.event_type);
        if (self.id.len > 0) allocator.free(self.id);
        allocator.free(self.data);
    }
};

/// Helper to transfer ownership of an ArrayList(u8) to a caller-owned slice,
/// or free the backing capacity if items are empty. Returns &.{} when empty.
fn ownOrFreeList(list: *std.ArrayList(u8), allocator: std.mem.Allocator) ![]u8 {
    if (list.items.len > 0) {
        return try list.toOwnedSlice(allocator);
    } else {
        // Free any retained capacity (e.g. from clearRetainingCapacity)
        list.deinit(allocator);
        return @as([]u8, &.{});
    }
}

/// Parse SSE events from a buffer
/// Returns a slice of events (caller must free each event.data and the slice itself)
///
/// Safety: Truncates events larger than MAX_EVENT_SIZE to prevent memory exhaustion.
/// Events are delimited by double newlines (\n\n).
/// Each data: line contributes to the event data, with newlines preserved.
///
/// Per the W3C SSE specification:
/// - Lines starting with ":" are comments (ignored)
/// - Field names: "data", "event", "id", "retry"
/// - After "field:", exactly ONE leading space is stripped from the value
/// - Empty data: lines append an empty string (producing a newline in multi-line data)
pub fn parseEvents(allocator: std.mem.Allocator, buffer: []const u8) ![]SseEvent {
    var events: std.ArrayList(SseEvent) = .empty;
    defer events.deinit(allocator);

    var current_data: std.ArrayList(u8) = .empty;
    defer current_data.deinit(allocator);

    var current_event_type: std.ArrayList(u8) = .empty;
    defer current_event_type.deinit(allocator);

    var current_id: std.ArrayList(u8) = .empty;
    defer current_id.deinit(allocator);

    var total_event_size: usize = 0;
    var has_data: bool = false;

    var lines = std.mem.splitScalar(u8, buffer, '\n');
    while (lines.next()) |raw_line| {
        // Strip trailing CR for CRLF line endings
        const line = std_compat.mem.trimRight(u8, raw_line, "\r");

        if (line.len == 0) {
            // Empty line marks end of event — dispatch if we have data
            if (has_data) {
                const data = try current_data.toOwnedSlice(allocator);
                errdefer allocator.free(data);

                const event_type = try ownOrFreeList(&current_event_type, allocator);
                const id = try ownOrFreeList(&current_id, allocator);

                try events.append(allocator, .{
                    .data = data,
                    .event_type = event_type,
                    .id = id,
                });

                current_data = .empty;
                current_event_type = .empty;
                current_id = .empty;
                total_event_size = 0;
                has_data = false;
            }
            continue;
        }

        // Skip comments (lines starting with :)
        if (line[0] == ':') continue;

        // Parse field: value (per SSE spec, strip exactly one leading space from value)
        const field_and_value = parseField(line);
        const field = field_and_value.field;
        const value = field_and_value.value;

        if (std.mem.eql(u8, field, "data")) {
            // Check event size limit before appending
            const newline_len: usize = if (has_data) 1 else 0;
            const new_size = total_event_size + value.len + newline_len;
            if (new_size > MAX_EVENT_SIZE) {
                // Event too large - finalize current event and skip remaining data.
                // Include event_type/id so the caller can still identify the truncated event.
                if (has_data) {
                    const owned = try current_data.toOwnedSlice(allocator);
                    errdefer allocator.free(owned);

                    const etype = try ownOrFreeList(&current_event_type, allocator);
                    const eid = try ownOrFreeList(&current_id, allocator);

                    try events.append(allocator, .{
                        .data = owned,
                        .event_type = etype,
                        .id = eid,
                    });
                } else {
                    // No data yet but event_type/id may have backing allocations
                    current_event_type.deinit(allocator);
                    current_id.deinit(allocator);
                }
                current_data = .empty;
                current_event_type = .empty;
                current_id = .empty;
                total_event_size = 0;
                has_data = false;
                continue;
            }

            if (has_data) {
                try current_data.append(allocator, '\n');
            }
            try current_data.appendSlice(allocator, value);
            total_event_size = new_size;
            has_data = true;
        } else if (std.mem.eql(u8, field, "event")) {
            current_event_type.clearRetainingCapacity();
            try current_event_type.appendSlice(allocator, value);
        } else if (std.mem.eql(u8, field, "id")) {
            // Per spec, id field must not contain null (U+0000)
            if (std.mem.indexOfScalar(u8, value, 0) == null) {
                current_id.clearRetainingCapacity();
                try current_id.appendSlice(allocator, value);
            }
        } else if (std.mem.eql(u8, field, "retry")) {
            // retry: <integer> — reconnection time in milliseconds
            // We parse it but don't act on it (caller should handle via returned events)
            _ = std.fmt.parseInt(u64, value, 10) catch {};
        }
        // Unknown fields are ignored per spec
    }

    // Handle any remaining data without trailing newline
    if (has_data) {
        const data = try current_data.toOwnedSlice(allocator);
        errdefer allocator.free(data);

        const event_type = try ownOrFreeList(&current_event_type, allocator);
        const id = try ownOrFreeList(&current_id, allocator);

        try events.append(allocator, .{
            .data = data,
            .event_type = event_type,
            .id = id,
        });
        // Mark as consumed so the defers don't double-free
        current_data = .empty;
        current_event_type = .empty;
        current_id = .empty;
    }

    return try events.toOwnedSlice(allocator);
}

/// Parse a single SSE line into field name and value.
/// Per the W3C spec: if the line contains ":", the field is everything before the first ":"
/// and the value is everything after, with exactly one leading space stripped if present.
/// If the line contains no ":", the entire line is the field name and value is empty.
fn parseField(line: []const u8) struct { field: []const u8, value: []const u8 } {
    if (std.mem.indexOfScalar(u8, line, ':')) |colon_pos| {
        const field = line[0..colon_pos];
        const rest = line[colon_pos + 1 ..];
        // Strip exactly one leading space (per SSE spec)
        const value = if (rest.len > 0 and rest[0] == ' ') rest[1..] else rest;
        return .{ .field = field, .value = value };
    }
    // No colon — entire line is field name, value is empty string
    return .{ .field = line, .value = "" };
}

fn freeEvents(allocator: std.mem.Allocator, events: []SseEvent) void {
    for (events) |*e| e.deinit(allocator);
    allocator.free(events);
}

test "parseEvents extracts SSE data fields" {
    const allocator = std.testing.allocator;

    // Test basic SSE format: data: json\n\n
    const sse_data = "data: {\"message\":\"hello\"}\n\ndata: {\"message\":\"world\"}\n\n";
    const events = try parseEvents(allocator, sse_data);
    defer freeEvents(allocator, events);

    try std.testing.expectEqual(@as(usize, 2), events.len);
    try std.testing.expectEqualStrings("{\"message\":\"hello\"}", events[0].data);
    try std.testing.expectEqualStrings("{\"message\":\"world\"}", events[1].data);
}

test "parseEvents skips comments" {
    const allocator = std.testing.allocator;

    const sse_data = ": comment\ndata: {\"msg\":\"test\"}\n\n";
    const events = try parseEvents(allocator, sse_data);
    defer freeEvents(allocator, events);

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("{\"msg\":\"test\"}", events[0].data);
}

test "parseEvents handles multi-line data" {
    const allocator = std.testing.allocator;

    // Multi-line data should have newlines preserved
    const sse_data = "data: line1\ndata: line2\n\n";
    const events = try parseEvents(allocator, sse_data);
    defer freeEvents(allocator, events);

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("line1\nline2", events[0].data);
}

test "parseEvents parses event type and id fields" {
    const allocator = std.testing.allocator;

    const sse_data = "event: update\nid: 42\ndata: payload\n\n";
    const events = try parseEvents(allocator, sse_data);
    defer freeEvents(allocator, events);

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("payload", events[0].data);
    try std.testing.expectEqualStrings("update", events[0].event_type);
    try std.testing.expectEqualStrings("42", events[0].id);
}

test "parseEvents strips exactly one leading space from value" {
    const allocator = std.testing.allocator;

    // "data:  two spaces" should produce " two spaces" (one space stripped)
    const sse_data = "data:  two spaces\n\n";
    const events = try parseEvents(allocator, sse_data);
    defer freeEvents(allocator, events);

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings(" two spaces", events[0].data);
}

test "parseEvents handles data field with no value" {
    const allocator = std.testing.allocator;

    // "data:" followed by "data: content" should produce "\ncontent"
    const sse_data = "data:\ndata: content\n\n";
    const events = try parseEvents(allocator, sse_data);
    defer freeEvents(allocator, events);

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("\ncontent", events[0].data);
}

test "parseEvents handles CRLF line endings" {
    const allocator = std.testing.allocator;

    const sse_data = "data: hello\r\n\r\n";
    const events = try parseEvents(allocator, sse_data);
    defer freeEvents(allocator, events);

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("hello", events[0].data);
}

test "parseField parses field:value correctly" {
    // Normal field with space
    const r1 = parseField("data: hello");
    try std.testing.expectEqualStrings("data", r1.field);
    try std.testing.expectEqualStrings("hello", r1.value);

    // No space after colon
    const r2 = parseField("data:hello");
    try std.testing.expectEqualStrings("data", r2.field);
    try std.testing.expectEqualStrings("hello", r2.value);

    // No colon — entire line is field name
    const r3 = parseField("data");
    try std.testing.expectEqualStrings("data", r3.field);
    try std.testing.expectEqualStrings("", r3.value);

    // Empty value after colon
    const r4 = parseField("data:");
    try std.testing.expectEqualStrings("data", r4.field);
    try std.testing.expectEqualStrings("", r4.value);
}
