//! Standalone SSE (Server-Sent Events) streaming client.
//!
//! This module is kept separate from the rest of the codebase to avoid
//! Zig 0.15 namespace collision bugs when std.http is used alongside
//! modules that export 'http' symbols.
//!
//! Provides persistent SSE connections with chunked transfer encoding
//! support for real-time message delivery.

const std = @import("std");
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
    client: std.http.Client,
    request: ?std.http.Client.Request,
    /// The body reader for streaming response data
    body_reader: ?*std.Io.Reader,
    url: []const u8,
    /// Buffer for reading response data
    transfer_buf: [4096]u8,

    pub const Error = error{
        NotConnected,
        ConnectionFailed,
        ConnectionClosed,
        ReadError,
    };

    /// Initialize a new SSE connection (not yet connected)
    pub fn init(allocator: std.mem.Allocator, url: []const u8) SseConnection {
        return .{
            .allocator = allocator,
            .client = std.http.Client{ .allocator = allocator },
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
    }

    /// Connect to SSE endpoint and start streaming
    /// Returns the HTTP status code
    pub fn connect(self: *SseConnection) !u16 {
        // URL already includes account query param from Signal channel config.
        const uri = try std.Uri.parse(self.url);
        self.body_reader = null;

        // Build request options with SSE headers
        const extra_headers = [_]std.http.Header{
            .{ .name = "Accept", .value = "text/event-stream" },
        };
        const options: std.http.Client.RequestOptions = .{ .extra_headers = &extra_headers };

        // Replace any previous request before opening a new stream.
        if (self.request) |*req| {
            req.deinit();
            self.request = null;
        }

        self.request = try self.client.request(.GET, uri, options);
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
        const stream = conn.stream_reader.getStream();

        var poll_fds = [_]std.posix.pollfd{
            .{
                .fd = stream.handle,
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

    pub fn deinit(self: *SseEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

/// Parse SSE events from a buffer
/// Returns a slice of events (caller must free each event.data and the slice itself)
///
/// Safety: Truncates events larger than MAX_EVENT_SIZE to prevent memory exhaustion.
/// Events are delimited by double newlines (\n\n).
/// Each data: line contributes to the event data, with newlines preserved.
pub fn parseEvents(allocator: std.mem.Allocator, buffer: []const u8) ![]SseEvent {
    var events: std.ArrayList(SseEvent) = .{};
    defer events.deinit(allocator);

    var current_data: std.ArrayList(u8) = .{};
    defer current_data.deinit(allocator);

    var total_event_size: usize = 0;

    var lines = std.mem.splitScalar(u8, buffer, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r");

        if (trimmed.len == 0) {
            // Empty line marks end of event
            if (current_data.items.len > 0) {
                const data = try current_data.toOwnedSlice(allocator);
                try events.append(allocator, .{ .data = data });
                current_data = .{};
                total_event_size = 0;
            }
            continue;
        }

        // Skip comments (lines starting with :)
        if (trimmed[0] == ':') continue;

        // Parse data field
        if (std.mem.startsWith(u8, trimmed, "data:")) {
            const data_start = 5; // Skip "data:"
            const data = std.mem.trim(u8, trimmed[data_start..], " ");

            // Check event size limit before appending
            const newline_len: usize = if (current_data.items.len > 0) 1 else 0;
            const new_size = total_event_size + data.len + newline_len;
            if (new_size > MAX_EVENT_SIZE) {
                // Event too large - finalize current event and skip remaining data
                if (current_data.items.len > 0) {
                    const owned = try current_data.toOwnedSlice(allocator);
                    try events.append(allocator, .{ .data = owned });
                }
                current_data = .{};
                total_event_size = 0;
                continue;
            }

            if (current_data.items.len > 0) {
                try current_data.append(allocator, '\n');
            }
            try current_data.appendSlice(allocator, data);
            total_event_size = new_size;
        }
        // Could also handle id: and event: fields here if needed
    }

    // Handle any remaining data without trailing newline
    if (current_data.items.len > 0) {
        const data = try current_data.toOwnedSlice(allocator);
        try events.append(allocator, .{ .data = data });
    }

    return try events.toOwnedSlice(allocator);
}

test "parseEvents extracts SSE data fields" {
    const allocator = std.testing.allocator;

    // Test basic SSE format: data: json\n\n
    const sse_data = "data: {\"message\":\"hello\"}\n\ndata: {\"message\":\"world\"}\n\n";
    const events = try parseEvents(allocator, sse_data);
    defer {
        for (events) |*e| e.deinit(allocator);
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 2), events.len);
    try std.testing.expectEqualStrings("{\"message\":\"hello\"}", events[0].data);
    try std.testing.expectEqualStrings("{\"message\":\"world\"}", events[1].data);
}

test "parseEvents skips comments" {
    const allocator = std.testing.allocator;

    const sse_data = ": comment\ndata: {\"msg\":\"test\"}\n\n";
    const events = try parseEvents(allocator, sse_data);
    defer {
        for (events) |*e| e.deinit(allocator);
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("{\"msg\":\"test\"}", events[0].data);
}

test "parseEvents handles multi-line data" {
    const allocator = std.testing.allocator;

    // Multi-line data should have newlines preserved
    const sse_data = "data: line1\ndata: line2\n\n";
    const events = try parseEvents(allocator, sse_data);
    defer {
        for (events) |*e| e.deinit(allocator);
        allocator.free(events);
    }

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("line1\nline2", events[0].data);
}
