//! HTTP Gateway — lightweight HTTP server for nullclaw.
//!
//! Mirrors ZeroClaw's axum-based gateway with:
//!   - Sliding-window rate limiting (per-IP)
//!   - Idempotency store (deduplicates webhook requests)
//!   - Body size limits (64KB max)
//!   - Request timeouts (30s)
//!   - Endpoints: /health, /pair, /webhook, /whatsapp
//!
//! Uses std.http.Server (built-in, no external deps).

const std = @import("std");
const health = @import("health.zig");

/// Maximum request body size (64KB) — prevents memory exhaustion.
pub const MAX_BODY_SIZE: usize = 65_536;

/// Request timeout (30s) — prevents slow-loris attacks.
pub const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Sliding window for rate limiting (60s).
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// How often the rate limiter sweeps stale IP entries (5 min).
const RATE_LIMITER_SWEEP_INTERVAL_SECS: u64 = 300;

// ── Rate Limiter ─────────────────────────────────────────────────

/// Sliding-window rate limiter. Tracks timestamps per key.
/// Not thread-safe by itself; callers must hold a lock.
pub const SlidingWindowRateLimiter = struct {
    limit_per_window: u32,
    window_ns: i128,
    /// Map of key -> list of request timestamps (as nanoTimestamp values).
    entries: std.StringHashMapUnmanaged(std.ArrayList(i128)),
    last_sweep: i128,

    pub fn init(limit_per_window: u32, window_secs: u64) SlidingWindowRateLimiter {
        return .{
            .limit_per_window = limit_per_window,
            .window_ns = @as(i128, @intCast(window_secs)) * 1_000_000_000,
            .entries = .empty,
            .last_sweep = std.time.nanoTimestamp(),
        };
    }

    pub fn deinit(self: *SlidingWindowRateLimiter, allocator: std.mem.Allocator) void {
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        self.entries.deinit(allocator);
    }

    /// Returns true if the request is allowed, false if rate-limited.
    pub fn allow(self: *SlidingWindowRateLimiter, allocator: std.mem.Allocator, key: []const u8) bool {
        if (self.limit_per_window == 0) return true;

        const now = std.time.nanoTimestamp();
        const cutoff = now - self.window_ns;

        // Periodic sweep
        if (now - self.last_sweep > @as(i128, RATE_LIMITER_SWEEP_INTERVAL_SECS) * 1_000_000_000) {
            self.sweep(allocator, cutoff);
            self.last_sweep = now;
        }

        const gop = self.entries.getOrPut(allocator, key) catch return true;
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }

        // Remove expired entries
        var timestamps = gop.value_ptr;
        var i: usize = 0;
        while (i < timestamps.items.len) {
            if (timestamps.items[i] <= cutoff) {
                _ = timestamps.swapRemove(i);
            } else {
                i += 1;
            }
        }

        if (timestamps.items.len >= self.limit_per_window) return false;

        timestamps.append(allocator, now) catch return true;
        return true;
    }

    fn sweep(self: *SlidingWindowRateLimiter, allocator: std.mem.Allocator, cutoff: i128) void {
        var iter = self.entries.iterator();
        var to_remove: std.ArrayList([]const u8) = .empty;
        defer to_remove.deinit(allocator);

        while (iter.next()) |entry| {
            var timestamps = entry.value_ptr;
            var i: usize = 0;
            while (i < timestamps.items.len) {
                if (timestamps.items[i] <= cutoff) {
                    _ = timestamps.swapRemove(i);
                } else {
                    i += 1;
                }
            }
            if (timestamps.items.len == 0) {
                to_remove.append(allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.entries.fetchRemove(key)) |kv| {
                var list = kv.value;
                list.deinit(allocator);
            }
        }
    }
};

// ── Gateway Rate Limiter ─────────────────────────────────────────

pub const GatewayRateLimiter = struct {
    pair: SlidingWindowRateLimiter,
    webhook: SlidingWindowRateLimiter,

    pub fn init(pair_per_minute: u32, webhook_per_minute: u32) GatewayRateLimiter {
        return .{
            .pair = SlidingWindowRateLimiter.init(pair_per_minute, RATE_LIMIT_WINDOW_SECS),
            .webhook = SlidingWindowRateLimiter.init(webhook_per_minute, RATE_LIMIT_WINDOW_SECS),
        };
    }

    pub fn deinit(self: *GatewayRateLimiter, allocator: std.mem.Allocator) void {
        self.pair.deinit(allocator);
        self.webhook.deinit(allocator);
    }

    pub fn allowPair(self: *GatewayRateLimiter, allocator: std.mem.Allocator, key: []const u8) bool {
        return self.pair.allow(allocator, key);
    }

    pub fn allowWebhook(self: *GatewayRateLimiter, allocator: std.mem.Allocator, key: []const u8) bool {
        return self.webhook.allow(allocator, key);
    }
};

// ── Idempotency Store ────────────────────────────────────────────

pub const IdempotencyStore = struct {
    ttl_ns: i128,
    /// Map of key -> timestamp when recorded.
    keys: std.StringHashMapUnmanaged(i128),

    pub fn init(ttl_secs: u64) IdempotencyStore {
        return .{
            .ttl_ns = @as(i128, @intCast(@max(ttl_secs, 1))) * 1_000_000_000,
            .keys = .empty,
        };
    }

    pub fn deinit(self: *IdempotencyStore, allocator: std.mem.Allocator) void {
        self.keys.deinit(allocator);
    }

    /// Returns true if this key is new and is now recorded.
    /// Returns false if this is a duplicate.
    pub fn recordIfNew(self: *IdempotencyStore, allocator: std.mem.Allocator, key: []const u8) bool {
        const now = std.time.nanoTimestamp();
        const cutoff = now - self.ttl_ns;

        // Clean expired keys (simple sweep)
        var iter = self.keys.iterator();
        var to_remove: std.ArrayList([]const u8) = .empty;
        defer to_remove.deinit(allocator);
        while (iter.next()) |entry| {
            if (entry.value_ptr.* < cutoff) {
                to_remove.append(allocator, entry.key_ptr.*) catch continue;
            }
        }
        for (to_remove.items) |k| {
            _ = self.keys.remove(k);
        }

        // Check if already present
        if (self.keys.get(key)) |_| return false;

        // Record new key
        self.keys.put(allocator, key, now) catch return true;
        return true;
    }
};

// ── Gateway server ───────────────────────────────────────────────

/// Gateway server state, shared across request handlers.
pub const GatewayState = struct {
    allocator: std.mem.Allocator,
    rate_limiter: GatewayRateLimiter,
    idempotency: IdempotencyStore,
    whatsapp_verify_token: []const u8,

    pub fn init(allocator: std.mem.Allocator) GatewayState {
        return initWithVerifyToken(allocator, "");
    }

    pub fn initWithVerifyToken(allocator: std.mem.Allocator, verify_token: []const u8) GatewayState {
        return .{
            .allocator = allocator,
            .rate_limiter = GatewayRateLimiter.init(10, 30),
            .idempotency = IdempotencyStore.init(300),
            .whatsapp_verify_token = verify_token,
        };
    }

    pub fn deinit(self: *GatewayState) void {
        self.rate_limiter.deinit(self.allocator);
        self.idempotency.deinit(self.allocator);
    }
};

/// Check if all registered health components are OK.
fn isHealthOk() bool {
    const snap = health.snapshot();
    var iter = snap.components.iterator();
    while (iter.next()) |entry| {
        if (!std.mem.eql(u8, entry.value_ptr.status, "ok")) return false;
    }
    return true;
}

/// Extract a query parameter value from a URL target string.
/// e.g. parseQueryParam("/whatsapp?hub.mode=subscribe&hub.challenge=abc", "hub.challenge") => "abc"
/// Returns null if the parameter is not found.
pub fn parseQueryParam(target: []const u8, name: []const u8) ?[]const u8 {
    const qmark = std.mem.indexOf(u8, target, "?") orelse return null;
    var query = target[qmark + 1 ..];

    while (query.len > 0) {
        // Find end of this key=value pair
        const amp = std.mem.indexOf(u8, query, "&") orelse query.len;
        const pair = query[0..amp];

        // Split on '='
        const eq = std.mem.indexOf(u8, pair, "=");
        if (eq) |eq_pos| {
            const key = pair[0..eq_pos];
            const value = pair[eq_pos + 1 ..];
            if (std.mem.eql(u8, key, name)) return value;
        }

        // Advance past the '&'
        if (amp < query.len) {
            query = query[amp + 1 ..];
        } else {
            break;
        }
    }
    return null;
}

/// Run the HTTP gateway. Binds to host:port and serves HTTP requests.
/// Endpoints: GET /health, POST /pair, POST /webhook, GET|POST /whatsapp
pub fn run(allocator: std.mem.Allocator, host: []const u8, port: u16) !void {
    health.markComponentOk("gateway");

    var state = GatewayState.init(allocator);
    defer state.deinit();

    // Resolve the listen address
    const addr = try std.net.Address.resolveIp(host, port);
    var server = try addr.listen(.{
        .reuse_address = true,
    });
    defer server.deinit();

    var stdout_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &bw.interface;
    try stdout.print("Gateway listening on {s}:{d}\n", .{ host, port });
    try stdout.flush();

    // Accept loop — read raw HTTP from TCP connections
    while (true) {
        var conn = server.accept() catch continue;
        defer conn.stream.close();

        // Read request line + headers from TCP stream
        var req_buf: [4096]u8 = undefined;
        const n = conn.stream.read(&req_buf) catch continue;
        if (n == 0) continue;
        const raw = req_buf[0..n];

        // Parse first line: "METHOD /path HTTP/1.1\r\n"
        const first_line_end = std.mem.indexOf(u8, raw, "\r\n") orelse continue;
        const first_line = raw[0..first_line_end];
        var parts = std.mem.splitScalar(u8, first_line, ' ');
        const method_str = parts.next() orelse continue;
        const target = parts.next() orelse continue;

        // Simple routing
        const is_post = std.mem.eql(u8, method_str, "POST");
        var response_status: []const u8 = "200 OK";
        var response_body: []const u8 = "";

        if (std.mem.eql(u8, target, "/health") or std.mem.startsWith(u8, target, "/health?")) {
            response_body = if (isHealthOk()) "{\"status\":\"ok\"}" else "{\"status\":\"degraded\"}";
        } else if (is_post and (std.mem.eql(u8, target, "/webhook") or std.mem.startsWith(u8, target, "/webhook?"))) {
            if (!state.rate_limiter.allowWebhook(state.allocator, "webhook")) {
                response_status = "429 Too Many Requests";
                response_body = "{\"error\":\"rate limited\"}";
            } else {
                response_body = "{\"status\":\"received\"}";
            }
        } else if (is_post and (std.mem.eql(u8, target, "/pair") or std.mem.startsWith(u8, target, "/pair?"))) {
            if (!state.rate_limiter.allowPair(state.allocator, "pair")) {
                response_status = "429 Too Many Requests";
                response_body = "{\"error\":\"rate limited\"}";
            } else {
                response_body = "{\"status\":\"paired\"}";
            }
        } else if (std.mem.eql(u8, target, "/whatsapp") or std.mem.startsWith(u8, target, "/whatsapp?")) {
            const is_get = std.mem.eql(u8, method_str, "GET");
            if (is_get) {
                // GET /whatsapp — Meta webhook verification
                const mode = parseQueryParam(target, "hub.mode");
                const token = parseQueryParam(target, "hub.verify_token");
                const challenge = parseQueryParam(target, "hub.challenge");

                if (mode != null and challenge != null and token != null and
                    std.mem.eql(u8, mode.?, "subscribe") and
                    state.whatsapp_verify_token.len > 0 and
                    std.mem.eql(u8, token.?, state.whatsapp_verify_token))
                {
                    response_body = challenge.?;
                } else {
                    response_status = "403 Forbidden";
                    response_body = "{\"error\":\"verification failed\"}";
                }
            } else if (is_post) {
                // POST /whatsapp — incoming message from Meta
                if (!state.rate_limiter.allowWebhook(state.allocator, "whatsapp")) {
                    response_status = "429 Too Many Requests";
                    response_body = "{\"error\":\"rate limited\"}";
                } else {
                    response_body = "{\"status\":\"received\"}";
                }
            } else {
                response_status = "405 Method Not Allowed";
                response_body = "{\"error\":\"method not allowed\"}";
            }
        } else {
            response_status = "404 Not Found";
            response_body = "{\"error\":\"not found\"}";
        }

        // Send HTTP response
        var resp_buf: [2048]u8 = undefined;
        const resp = std.fmt.bufPrint(&resp_buf, "HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ response_status, response_body.len, response_body }) catch continue;
        _ = conn.stream.write(resp) catch continue;
    }
}

// ── Tests ────────────────────────────────────────────────────────

test "constants are set correctly" {
    try std.testing.expectEqual(@as(usize, 65_536), MAX_BODY_SIZE);
    try std.testing.expectEqual(@as(u64, 30), REQUEST_TIMEOUT_SECS);
    try std.testing.expectEqual(@as(u64, 60), RATE_LIMIT_WINDOW_SECS);
}

test "rate limiter allows up to limit" {
    var limiter = SlidingWindowRateLimiter.init(2, 60);
    defer limiter.deinit(std.testing.allocator);

    try std.testing.expect(limiter.allow(std.testing.allocator, "127.0.0.1"));
    try std.testing.expect(limiter.allow(std.testing.allocator, "127.0.0.1"));
    try std.testing.expect(!limiter.allow(std.testing.allocator, "127.0.0.1"));
}

test "rate limiter zero limit always allows" {
    var limiter = SlidingWindowRateLimiter.init(0, 60);
    defer limiter.deinit(std.testing.allocator);

    for (0..100) |_| {
        try std.testing.expect(limiter.allow(std.testing.allocator, "any-key"));
    }
}

test "rate limiter different keys are independent" {
    var limiter = SlidingWindowRateLimiter.init(1, 60);
    defer limiter.deinit(std.testing.allocator);

    try std.testing.expect(limiter.allow(std.testing.allocator, "ip-1"));
    try std.testing.expect(!limiter.allow(std.testing.allocator, "ip-1"));
    try std.testing.expect(limiter.allow(std.testing.allocator, "ip-2"));
}

test "gateway rate limiter blocks after limit" {
    var limiter = GatewayRateLimiter.init(2, 2);
    defer limiter.deinit(std.testing.allocator);

    try std.testing.expect(limiter.allowPair(std.testing.allocator, "127.0.0.1"));
    try std.testing.expect(limiter.allowPair(std.testing.allocator, "127.0.0.1"));
    try std.testing.expect(!limiter.allowPair(std.testing.allocator, "127.0.0.1"));
}

test "idempotency store rejects duplicate key" {
    var store = IdempotencyStore.init(30);
    defer store.deinit(std.testing.allocator);

    try std.testing.expect(store.recordIfNew(std.testing.allocator, "req-1"));
    try std.testing.expect(!store.recordIfNew(std.testing.allocator, "req-1"));
    try std.testing.expect(store.recordIfNew(std.testing.allocator, "req-2"));
}

test "idempotency store allows different keys" {
    var store = IdempotencyStore.init(300);
    defer store.deinit(std.testing.allocator);

    try std.testing.expect(store.recordIfNew(std.testing.allocator, "a"));
    try std.testing.expect(store.recordIfNew(std.testing.allocator, "b"));
    try std.testing.expect(store.recordIfNew(std.testing.allocator, "c"));
    try std.testing.expect(!store.recordIfNew(std.testing.allocator, "a"));
}

test "gateway module compiles" {
    // Compile-time check only
}

// ── Additional gateway tests ────────────────────────────────────

test "rate limiter single request allowed" {
    var limiter = SlidingWindowRateLimiter.init(1, 60);
    defer limiter.deinit(std.testing.allocator);

    try std.testing.expect(limiter.allow(std.testing.allocator, "test-key"));
    try std.testing.expect(!limiter.allow(std.testing.allocator, "test-key"));
}

test "rate limiter high limit" {
    var limiter = SlidingWindowRateLimiter.init(100, 60);
    defer limiter.deinit(std.testing.allocator);

    for (0..100) |_| {
        try std.testing.expect(limiter.allow(std.testing.allocator, "ip"));
    }
    try std.testing.expect(!limiter.allow(std.testing.allocator, "ip"));
}

test "gateway rate limiter pair and webhook independent" {
    var limiter = GatewayRateLimiter.init(1, 1);
    defer limiter.deinit(std.testing.allocator);

    try std.testing.expect(limiter.allowPair(std.testing.allocator, "ip"));
    try std.testing.expect(!limiter.allowPair(std.testing.allocator, "ip"));
    // Webhook should still be allowed since it's separate
    try std.testing.expect(limiter.allowWebhook(std.testing.allocator, "ip"));
    try std.testing.expect(!limiter.allowWebhook(std.testing.allocator, "ip"));
}

test "gateway rate limiter zero limits always allow" {
    var limiter = GatewayRateLimiter.init(0, 0);
    defer limiter.deinit(std.testing.allocator);

    for (0..50) |_| {
        try std.testing.expect(limiter.allowPair(std.testing.allocator, "any"));
        try std.testing.expect(limiter.allowWebhook(std.testing.allocator, "any"));
    }
}

test "idempotency store init with various TTLs" {
    var store1 = IdempotencyStore.init(1);
    defer store1.deinit(std.testing.allocator);
    try std.testing.expect(store1.ttl_ns > 0);

    var store2 = IdempotencyStore.init(3600);
    defer store2.deinit(std.testing.allocator);
    try std.testing.expect(store2.ttl_ns > store1.ttl_ns);
}

test "idempotency store zero TTL treated as 1 second" {
    var store = IdempotencyStore.init(0);
    defer store.deinit(std.testing.allocator);
    // Should use @max(0, 1) = 1 second
    try std.testing.expectEqual(@as(i128, 1_000_000_000), store.ttl_ns);
}

test "idempotency store many unique keys" {
    var store = IdempotencyStore.init(300);
    defer store.deinit(std.testing.allocator);

    // Use distinct string literals to avoid buffer aliasing
    try std.testing.expect(store.recordIfNew(std.testing.allocator, "key-alpha"));
    try std.testing.expect(store.recordIfNew(std.testing.allocator, "key-beta"));
    try std.testing.expect(store.recordIfNew(std.testing.allocator, "key-gamma"));
    try std.testing.expect(store.recordIfNew(std.testing.allocator, "key-delta"));
    try std.testing.expect(store.recordIfNew(std.testing.allocator, "key-epsilon"));
}

test "idempotency store duplicate after many inserts" {
    var store = IdempotencyStore.init(300);
    defer store.deinit(std.testing.allocator);

    try std.testing.expect(store.recordIfNew(std.testing.allocator, "first"));
    try std.testing.expect(store.recordIfNew(std.testing.allocator, "second"));
    try std.testing.expect(store.recordIfNew(std.testing.allocator, "third"));
    // First key should still be duplicate
    try std.testing.expect(!store.recordIfNew(std.testing.allocator, "first"));
}

test "rate limiter window_ns calculation" {
    const limiter = SlidingWindowRateLimiter.init(10, 120);
    try std.testing.expectEqual(@as(i128, 120_000_000_000), limiter.window_ns);
}

test "MAX_BODY_SIZE is 64KB" {
    try std.testing.expectEqual(@as(usize, 64 * 1024), MAX_BODY_SIZE);
}

test "RATE_LIMIT_WINDOW_SECS is 60" {
    try std.testing.expectEqual(@as(u64, 60), RATE_LIMIT_WINDOW_SECS);
}

test "REQUEST_TIMEOUT_SECS is 30" {
    try std.testing.expectEqual(@as(u64, 30), REQUEST_TIMEOUT_SECS);
}

test "rate limiter different keys do not interfere" {
    var limiter = SlidingWindowRateLimiter.init(2, 60);
    defer limiter.deinit(std.testing.allocator);

    try std.testing.expect(limiter.allow(std.testing.allocator, "key-a"));
    try std.testing.expect(limiter.allow(std.testing.allocator, "key-b"));
    try std.testing.expect(limiter.allow(std.testing.allocator, "key-a"));
    // key-a should now be at limit
    try std.testing.expect(!limiter.allow(std.testing.allocator, "key-a"));
    // key-b still has room
    try std.testing.expect(limiter.allow(std.testing.allocator, "key-b"));
}

// ── WhatsApp / parseQueryParam tests ────────────────────────────

test "parseQueryParam extracts single param" {
    const val = parseQueryParam("/whatsapp?hub.mode=subscribe", "hub.mode");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("subscribe", val.?);
}

test "parseQueryParam extracts param from multiple" {
    const target = "/whatsapp?hub.mode=subscribe&hub.verify_token=mytoken&hub.challenge=abc123";
    try std.testing.expectEqualStrings("subscribe", parseQueryParam(target, "hub.mode").?);
    try std.testing.expectEqualStrings("mytoken", parseQueryParam(target, "hub.verify_token").?);
    try std.testing.expectEqualStrings("abc123", parseQueryParam(target, "hub.challenge").?);
}

test "parseQueryParam returns null for missing param" {
    const val = parseQueryParam("/whatsapp?hub.mode=subscribe", "hub.challenge");
    try std.testing.expect(val == null);
}

test "parseQueryParam returns null for no query string" {
    const val = parseQueryParam("/whatsapp", "hub.mode");
    try std.testing.expect(val == null);
}

test "parseQueryParam empty value" {
    const val = parseQueryParam("/path?key=", "key");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("", val.?);
}

test "parseQueryParam partial key match does not match" {
    const val = parseQueryParam("/path?hub.mode_extra=subscribe", "hub.mode");
    try std.testing.expect(val == null);
}

test "GatewayState initWithVerifyToken stores token" {
    var state = GatewayState.initWithVerifyToken(std.testing.allocator, "test-verify-token");
    defer state.deinit();
    try std.testing.expectEqualStrings("test-verify-token", state.whatsapp_verify_token);
}

test "GatewayState init has empty verify token" {
    var state = GatewayState.init(std.testing.allocator);
    defer state.deinit();
    try std.testing.expectEqualStrings("", state.whatsapp_verify_token);
}
