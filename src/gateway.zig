//! HTTP Gateway — lightweight HTTP server for nullclaw.
//!
//! Mirrors ZeroClaw's axum-based gateway with:
//!   - Sliding-window rate limiting (per-IP)
//!   - Idempotency store (deduplicates webhook requests)
//!   - Body size limits (64KB max)
//!   - Request timeouts (30s)
//!   - Bearer token authentication (PairingGuard)
//!   - Endpoints: /health, /ready, /pair, /webhook, /whatsapp, /telegram, /line, /lark, /slack/events
//!
//! Uses std.http.Server (built-in, no external deps).

const std = @import("std");
const build_options = @import("build_options");
const health = @import("health.zig");
const Config = @import("config.zig").Config;
const config_types = @import("config_types.zig");
const session_mod = @import("session.zig");
const providers = @import("providers/root.zig");
const tools_mod = @import("tools/root.zig");
const memory_mod = @import("memory/root.zig");
const subagent_mod = @import("subagent.zig");
const observability = @import("observability.zig");
const agent_routing = @import("agent_routing.zig");
const PairingGuard = @import("security/pairing.zig").PairingGuard;
const channels = @import("channels/root.zig");
const bus_mod = @import("bus.zig");

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
    whatsapp_app_secret: []const u8,
    whatsapp_access_token: []const u8,
    whatsapp_account_id: []const u8 = "default",
    telegram_bot_token: []const u8,
    telegram_account_id: []const u8 = "default",
    telegram_allow_from: []const []const u8 = &.{},
    whatsapp_allow_from: []const []const u8 = &.{},
    whatsapp_group_allow_from: []const []const u8 = &.{},
    whatsapp_groups: []const []const u8 = &.{},
    whatsapp_group_policy: []const u8 = "allowlist",
    line_channel_secret: []const u8 = "",
    line_access_token: []const u8 = "",
    line_account_id: []const u8 = "default",
    line_allow_from: []const []const u8 = &.{},
    lark_verification_token: []const u8 = "",
    lark_app_id: []const u8 = "",
    lark_app_secret: []const u8 = "",
    lark_account_id: []const u8 = "default",
    lark_allow_from: []const []const u8 = &.{},
    pairing_guard: ?PairingGuard,
    event_bus: ?*bus_mod.Bus = null,

    pub fn init(allocator: std.mem.Allocator) GatewayState {
        return initWithVerifyToken(allocator, "");
    }

    pub fn initWithVerifyToken(allocator: std.mem.Allocator, verify_token: []const u8) GatewayState {
        return .{
            .allocator = allocator,
            .rate_limiter = GatewayRateLimiter.init(10, 30),
            .idempotency = IdempotencyStore.init(300),
            .whatsapp_verify_token = verify_token,
            .whatsapp_app_secret = "",
            .whatsapp_access_token = "",
            .telegram_bot_token = "",
            .pairing_guard = null,
        };
    }

    pub fn deinit(self: *GatewayState) void {
        self.rate_limiter.deinit(self.allocator);
        self.idempotency.deinit(self.allocator);
        if (self.pairing_guard) |*guard| {
            guard.deinit();
        }
    }
};

/// Publish an inbound message to the event bus. Returns true on success.
fn publishToBus(
    eb: *bus_mod.Bus,
    allocator: std.mem.Allocator,
    channel: []const u8,
    sender_id: []const u8,
    chat_id: []const u8,
    content: []const u8,
    session_key: []const u8,
    metadata_json: ?[]const u8,
) bool {
    const msg = bus_mod.makeInboundFull(
        allocator,
        channel,
        sender_id,
        chat_id,
        content,
        session_key,
        &.{},
        metadata_json,
    ) catch return false;
    eb.publishInbound(msg) catch {
        msg.deinit(allocator);
        return false;
    };
    return true;
}

/// Check if all registered health components are OK.
fn isHealthOk() bool {
    const snap = health.snapshot();
    var iter = snap.components.iterator();
    while (iter.next()) |entry| {
        if (!std.mem.eql(u8, entry.value_ptr.status, "ok")) return false;
    }
    return true;
}

/// Readiness response — encapsulates HTTP status and body for /ready.
pub const ReadyResponse = struct {
    http_status: []const u8,
    body: []const u8,
    /// Whether body was allocated and should be freed by caller.
    allocated: bool,
};

/// Handle the /ready endpoint logic. Queries the global health registry
/// and returns the appropriate HTTP status and JSON body.
/// If `allocated` is true in the result, the caller owns `body` memory.
pub fn handleReady(allocator: std.mem.Allocator) ReadyResponse {
    const readiness = health.checkRegistryReadiness(allocator) catch {
        return .{
            .http_status = "500 Internal Server Error",
            .body = "{\"status\":\"not_ready\",\"checks\":[]}",
            .allocated = false,
        };
    };
    // formatJson must be called before freeing the checks slice
    const json_body = readiness.formatJson(allocator) catch {
        if (readiness.checks.len > 0) {
            allocator.free(readiness.checks);
        }
        return .{
            .http_status = "500 Internal Server Error",
            .body = "{\"status\":\"not_ready\",\"checks\":[]}",
            .allocated = false,
        };
    };
    if (readiness.checks.len > 0) {
        allocator.free(readiness.checks);
    }
    return .{
        .http_status = if (readiness.status == .ready) "200 OK" else "503 Service Unavailable",
        .body = json_body,
        .allocated = true,
    };
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

// ── Bearer Token Validation ──────────────────────────────────────

/// Validate a bearer token against a list of paired tokens.
/// Returns true if paired_tokens is empty (backwards compat) or token matches.
pub fn validateBearerToken(token: []const u8, paired_tokens: []const []const u8) bool {
    if (paired_tokens.len == 0) return true;
    for (paired_tokens) |pt| {
        if (std.mem.eql(u8, token, pt)) return true;
    }
    return false;
}

/// Extract the value of a named header from raw HTTP bytes.
/// Searches for "Name: value\r\n" (case-insensitive name match).
pub fn extractHeader(raw: []const u8, name: []const u8) ?[]const u8 {
    // Skip past the first line (request line)
    var pos: usize = 0;
    while (pos + 1 < raw.len) {
        if (raw[pos] == '\r' and raw[pos + 1] == '\n') {
            pos += 2;
            break;
        }
        pos += 1;
    }

    // Scan headers
    while (pos < raw.len) {
        // Find end of this header line
        const line_end = std.mem.indexOf(u8, raw[pos..], "\r\n") orelse break;
        const line = raw[pos .. pos + line_end];
        if (line.len == 0) break; // empty line = end of headers

        // Check if this line starts with "name:"
        if (line.len > name.len and line[name.len] == ':') {
            const header_name = line[0..name.len];
            if (asciiEqlIgnoreCase(header_name, name)) {
                // Skip ": " and any leading whitespace
                var val_start: usize = name.len + 1;
                while (val_start < line.len and line[val_start] == ' ') val_start += 1;
                return line[val_start..];
            }
        }

        pos += line_end + 2;
    }
    return null;
}

/// Extract the bearer token from an Authorization header value.
/// "Bearer <token>" -> "<token>", or null if format doesn't match.
pub fn extractBearerToken(auth_header: []const u8) ?[]const u8 {
    const prefix = "Bearer ";
    if (auth_header.len > prefix.len and std.mem.startsWith(u8, auth_header, prefix)) {
        return auth_header[prefix.len..];
    }
    return null;
}

/// Returns true when a webhook request should be accepted for the current
/// pairing state and bearer token. Missing pairing state fails closed.
pub fn isWebhookAuthorized(pairing_guard: ?*const PairingGuard, bearer_token: ?[]const u8) bool {
    const guard = pairing_guard orelse return false;
    if (!guard.requirePairing()) return true;
    const token = bearer_token orelse return false;
    return guard.isAuthenticated(token);
}

/// Format the /pair success payload. Returns null when buffer is too small.
pub fn formatPairSuccessResponse(buf: []u8, token: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, "{{\"status\":\"paired\",\"token\":\"{s}\"}}", .{token}) catch null;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        const al = if (ac >= 'A' and ac <= 'Z') ac + 32 else ac;
        const bl = if (bc >= 'A' and bc <= 'Z') bc + 32 else bc;
        if (al != bl) return false;
    }
    return true;
}

// ── WhatsApp HMAC-SHA256 Signature Verification ─────────────────

/// Verify a WhatsApp webhook HMAC-SHA256 signature.
///
/// Meta sends `X-Hub-Signature-256: sha256=<hex-digest>` on every webhook POST.
/// This function computes HMAC-SHA256 over `body` using `app_secret` as the key,
/// then performs a constant-time comparison against the hex digest in the header.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verifyWhatsappSignature(body: []const u8, signature_header: []const u8, app_secret: []const u8) bool {
    // Reject empty secrets — misconfiguration guard
    if (app_secret.len == 0) return false;

    // Header must start with "sha256="
    const prefix = "sha256=";
    if (!std.mem.startsWith(u8, signature_header, prefix)) return false;

    const provided_hex = signature_header[prefix.len..];

    // HMAC-SHA256 digest is 32 bytes = 64 hex chars
    if (provided_hex.len != 64) return false;

    // Decode the provided hex string into bytes
    const provided_bytes = hexDecode(provided_hex) orelse return false;

    // Compute expected HMAC-SHA256
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var expected: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&expected, body, app_secret);

    // Constant-time comparison — prevents timing side-channels
    return constantTimeEql(&expected, &provided_bytes);
}

/// Decode a 64-char lowercase hex string into 32 bytes.
/// Returns null if any character is not a valid hex digit.
fn hexDecode(hex: []const u8) ?[32]u8 {
    if (hex.len != 64) return null;
    var out: [32]u8 = undefined;
    for (0..32) |i| {
        const hi = hexVal(hex[i * 2]) orelse return null;
        const lo = hexVal(hex[i * 2 + 1]) orelse return null;
        out[i] = (hi << 4) | lo;
    }
    return out;
}

/// Convert a single hex character to its 4-bit value.
fn hexVal(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return null;
}

/// Constant-time comparison of two 32-byte arrays.
/// Always examines all bytes regardless of where a mismatch occurs.
fn constantTimeEql(a: *const [32]u8, b: *const [32]u8) bool {
    var diff: u8 = 0;
    for (a, b) |ab, bb| {
        diff |= ab ^ bb;
    }
    return diff == 0;
}

// ── JSON Helpers ────────────────────────────────────────────────

/// Escape a string for safe embedding inside a JSON string value.
/// Handles: \ → \\, " → \", control chars (0x00-0x1F) → \uXXXX,
/// newlines → \n, tabs → \t, carriage returns → \r.
pub fn jsonEscapeInto(writer: anytype, input: []const u8) !void {
    for (input) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0x08 => try writer.writeAll("\\b"),
            0x0C => try writer.writeAll("\\f"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

/// Wrap a value as a JSON string field: `"key":"escaped_value"`.
/// Returns an owned slice allocated with the provided allocator.
pub fn jsonWrapField(allocator: std.mem.Allocator, key: []const u8, value: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try w.writeByte('"');
    try w.writeAll(key);
    try w.writeAll("\":\"");
    try jsonEscapeInto(w, value);
    try w.writeByte('"');
    return buf.toOwnedSlice(allocator);
}

/// Build a JSON response object: `{"status":"ok","response":"<escaped>"}`.
/// Returns an owned slice. Caller must free.
pub fn jsonWrapResponse(allocator: std.mem.Allocator, response: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try w.writeAll("{\"status\":\"ok\",\"response\":\"");
    try jsonEscapeInto(w, response);
    try w.writeAll("\"}");
    return buf.toOwnedSlice(allocator);
}

/// Build a JSON challenge response: `{"challenge":"<escaped>"}`.
/// Returns an owned slice. Caller must free.
fn jsonWrapChallenge(allocator: std.mem.Allocator, challenge: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try w.writeAll("{\"challenge\":\"");
    try jsonEscapeInto(w, challenge);
    try w.writeAll("\"}");
    return buf.toOwnedSlice(allocator);
}

/// Extract a string field from a JSON blob (minimal parser, no allocations).
pub fn jsonStringField(json: []const u8, key: []const u8) ?[]const u8 {
    var needle_buf: [256]u8 = undefined;
    const quoted_key = std.fmt.bufPrint(&needle_buf, "\"{s}\"", .{key}) catch return null;

    const key_pos = std.mem.indexOf(u8, json, quoted_key) orelse return null;
    const after_key = json[key_pos + quoted_key.len ..];

    // Skip whitespace and colon
    var i: usize = 0;
    while (i < after_key.len and (after_key[i] == ' ' or after_key[i] == ':' or
        after_key[i] == '\t' or after_key[i] == '\n' or after_key[i] == '\r')) : (i += 1)
    {}

    if (i >= after_key.len or after_key[i] != '"') return null;
    i += 1; // skip opening quote

    // Find closing quote (handle escaped quotes)
    const start = i;
    while (i < after_key.len) : (i += 1) {
        if (after_key[i] == '\\' and i + 1 < after_key.len) {
            i += 1;
            continue;
        }
        if (after_key[i] == '"') {
            return after_key[start..i];
        }
    }
    return null;
}

/// Extract an integer field from a JSON blob.
pub fn jsonIntField(json: []const u8, key: []const u8) ?i64 {
    var needle_buf: [256]u8 = undefined;
    const quoted_key = std.fmt.bufPrint(&needle_buf, "\"{s}\"", .{key}) catch return null;

    const key_pos = std.mem.indexOf(u8, json, quoted_key) orelse return null;
    const after_key = json[key_pos + quoted_key.len ..];

    // Skip whitespace and colon
    var i: usize = 0;
    while (i < after_key.len and (after_key[i] == ' ' or after_key[i] == ':' or
        after_key[i] == '\t' or after_key[i] == '\n' or after_key[i] == '\r')) : (i += 1)
    {}

    if (i >= after_key.len) return null;

    // Parse integer (possibly negative)
    const is_negative = after_key[i] == '-';
    if (is_negative) i += 1;
    if (i >= after_key.len or after_key[i] < '0' or after_key[i] > '9') return null;

    var result: i64 = 0;
    while (i < after_key.len and after_key[i] >= '0' and after_key[i] <= '9') : (i += 1) {
        result = result * 10 + @as(i64, after_key[i] - '0');
    }
    return if (is_negative) -result else result;
}

fn findWhatsAppConfigByVerifyToken(cfg: *const Config, verify_token: []const u8) ?*const config_types.WhatsAppConfig {
    for (cfg.channels.whatsapp) |*wa_cfg| {
        if (std.mem.eql(u8, wa_cfg.verify_token, verify_token)) return wa_cfg;
    }
    return null;
}

fn findWhatsAppConfigByPhoneNumberId(cfg: *const Config, phone_number_id: []const u8) ?*const config_types.WhatsAppConfig {
    for (cfg.channels.whatsapp) |*wa_cfg| {
        if (std.mem.eql(u8, wa_cfg.phone_number_id, phone_number_id)) return wa_cfg;
    }
    return null;
}

fn selectWhatsAppConfig(
    cfg_opt: ?*const Config,
    body: ?[]const u8,
    verify_token: ?[]const u8,
) ?*const config_types.WhatsAppConfig {
    if (!build_options.enable_channel_whatsapp) return null;
    const cfg = cfg_opt orelse return null;
    if (cfg.channels.whatsapp.len == 0) return null;

    if (verify_token) |token| {
        if (findWhatsAppConfigByVerifyToken(cfg, token)) |wa_cfg| {
            return wa_cfg;
        }
    }

    if (body) |b| {
        if (jsonStringField(b, "phone_number_id")) |phone_number_id| {
            if (findWhatsAppConfigByPhoneNumberId(cfg, phone_number_id)) |wa_cfg| {
                return wa_cfg;
            }
        }
    }

    return &cfg.channels.whatsapp[0];
}

fn findTelegramConfigByAccountId(cfg: *const Config, account_id: []const u8) ?*const config_types.TelegramConfig {
    for (cfg.channels.telegram) |*tg_cfg| {
        if (std.ascii.eqlIgnoreCase(tg_cfg.account_id, account_id)) return tg_cfg;
    }
    return null;
}

fn selectTelegramConfig(
    cfg_opt: ?*const Config,
    target: []const u8,
) ?*const config_types.TelegramConfig {
    if (!build_options.enable_channel_telegram) return null;
    const cfg = cfg_opt orelse return null;
    if (cfg.channels.telegram.len == 0) return null;

    if (parseQueryParam(target, "account_id")) |account_id| {
        if (findTelegramConfigByAccountId(cfg, account_id)) |tg_cfg| {
            return tg_cfg;
        }
    }
    if (parseQueryParam(target, "account")) |account_id| {
        if (findTelegramConfigByAccountId(cfg, account_id)) |tg_cfg| {
            return tg_cfg;
        }
    }

    if (cfg.channels.telegramPrimary()) |primary| {
        if (findTelegramConfigByAccountId(cfg, primary.account_id)) |tg_cfg| {
            return tg_cfg;
        }
    }
    return &cfg.channels.telegram[0];
}

fn hasLineSecrets(cfg: *const Config) bool {
    if (!build_options.enable_channel_line) return false;
    for (cfg.channels.line) |line_cfg| {
        if (line_cfg.channel_secret.len > 0) return true;
    }
    return false;
}

fn selectLineConfigBySignature(
    cfg_opt: ?*const Config,
    body: []const u8,
    signature: ?[]const u8,
) ?*const config_types.LineConfig {
    if (!build_options.enable_channel_line) return null;
    const cfg = cfg_opt orelse return null;
    if (cfg.channels.line.len == 0) return null;

    if (signature) |sig| {
        for (cfg.channels.line) |*line_cfg| {
            if (channels.line.LineChannel.verifySignature(body, sig, line_cfg.channel_secret)) {
                return line_cfg;
            }
        }
        return null;
    }

    return &cfg.channels.line[0];
}

fn findLarkConfigByVerificationToken(
    cfg: *const Config,
    verification_token: []const u8,
) ?*const config_types.LarkConfig {
    for (cfg.channels.lark) |*lark_cfg| {
        if (std.mem.eql(u8, lark_cfg.verification_token orelse "", verification_token)) {
            return lark_cfg;
        }
    }
    return null;
}

fn selectLarkConfig(
    cfg_opt: ?*const Config,
    body: []const u8,
) ?*const config_types.LarkConfig {
    if (!build_options.enable_channel_lark) return null;
    const cfg = cfg_opt orelse return null;
    if (cfg.channels.lark.len == 0) return null;

    if (jsonStringField(body, "token")) |verification_token| {
        if (findLarkConfigByVerificationToken(cfg, verification_token)) |lark_cfg| {
            return lark_cfg;
        }
    }

    return &cfg.channels.lark[0];
}

fn webhookBasePath(target: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, target, '?')) |qi| return target[0..qi];
    return target;
}

fn normalizeSlackWebhookPath(path: []const u8) []const u8 {
    if (!build_options.enable_channel_slack) return path;
    return channels.slack.SlackChannel.normalizeWebhookPath(path);
}

fn hasSlackHttpEndpoint(cfg_opt: ?*const Config, base_path: []const u8) bool {
    if (!build_options.enable_channel_slack) return false;
    const cfg = cfg_opt orelse return std.mem.eql(u8, base_path, channels.slack.SlackChannel.DEFAULT_WEBHOOK_PATH);
    for (cfg.channels.slack) |slack_cfg| {
        if (slack_cfg.mode != .http) continue;
        if (std.mem.eql(u8, normalizeSlackWebhookPath(slack_cfg.webhook_path), base_path)) return true;
    }
    return false;
}

fn verifySlackSignature(
    allocator: std.mem.Allocator,
    body: []const u8,
    timestamp_header: []const u8,
    signature_header: []const u8,
    signing_secret: []const u8,
) bool {
    if (signing_secret.len == 0) return false;
    const ts_trimmed = std.mem.trim(u8, timestamp_header, " \t\r\n");
    const sig_trimmed = std.mem.trim(u8, signature_header, " \t\r\n");
    if (!std.mem.startsWith(u8, sig_trimmed, "v0=")) return false;

    const provided_hex = sig_trimmed["v0=".len..];
    if (provided_hex.len != 64) return false;

    const ts = std.fmt.parseInt(i64, ts_trimmed, 10) catch return false;
    const now = std.time.timestamp();
    const delta = if (now >= ts) now - ts else ts - now;
    if (delta > 300) return false; // 5-minute replay window

    var base_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer base_buf.deinit(allocator);
    const bw = base_buf.writer(allocator);
    bw.print("v0:{s}:", .{ts_trimmed}) catch return false;
    bw.writeAll(body) catch return false;

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, base_buf.items, signing_secret);

    var provided: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const hi = hexVal(provided_hex[i * 2]) orelse return false;
        const lo = hexVal(provided_hex[i * 2 + 1]) orelse return false;
        provided[i] = (hi << 4) | lo;
    }
    return constantTimeEql(&mac, &provided);
}

fn findSlackConfigForRequest(
    allocator: std.mem.Allocator,
    cfg_opt: ?*const Config,
    target: []const u8,
    body: []const u8,
    timestamp_header: ?[]const u8,
    signature_header: ?[]const u8,
) ?*const config_types.SlackConfig {
    if (!build_options.enable_channel_slack) return null;
    const cfg = cfg_opt orelse return null;
    if (cfg.channels.slack.len == 0) return null;

    const base_path = webhookBasePath(target);
    for (cfg.channels.slack) |*slack_cfg| {
        if (slack_cfg.mode != .http) continue;
        if (!std.mem.eql(u8, normalizeSlackWebhookPath(slack_cfg.webhook_path), base_path)) continue;

        const secret = slack_cfg.signing_secret orelse continue;
        if (timestamp_header == null or signature_header == null) continue;
        if (verifySlackSignature(
            allocator,
            body,
            timestamp_header.?,
            signature_header.?,
            secret,
        )) return slack_cfg;
    }
    return null;
}

fn slackSessionKey(
    buf: []u8,
    account_id: []const u8,
    sender_id: []const u8,
    channel_id: []const u8,
    is_dm: bool,
) []const u8 {
    if (is_dm) {
        return std.fmt.bufPrint(buf, "slack:{s}:direct:{s}", .{ account_id, sender_id }) catch "slack:unknown";
    }
    return std.fmt.bufPrint(buf, "slack:{s}:channel:{s}", .{ account_id, channel_id }) catch "slack:unknown";
}

fn slackSessionKeyRouted(
    allocator: std.mem.Allocator,
    fallback_buf: []u8,
    account_id: []const u8,
    sender_id: []const u8,
    channel_id: []const u8,
    is_dm: bool,
    cfg_opt: ?*const Config,
) []const u8 {
    const fallback = slackSessionKey(fallback_buf, account_id, sender_id, channel_id, is_dm);
    return resolveRouteSessionKey(
        allocator,
        cfg_opt,
        "slack",
        account_id,
        .{
            .kind = if (is_dm) .direct else .channel,
            .id = if (is_dm) sender_id else channel_id,
        },
        fallback,
    );
}

fn slackEnvelopeBotUserId(payload_root: std.json.ObjectMap) ?[]const u8 {
    const authz = payload_root.get("authorizations") orelse return null;
    if (authz != .array or authz.array.items.len == 0) return null;
    const first = authz.array.items[0];
    if (first != .object) return null;
    const uid_val = first.object.get("user_id") orelse return null;
    if (uid_val != .string or uid_val.string.len == 0) return null;
    return uid_val.string;
}

fn whatsappSessionKey(buf: []u8, body: []const u8) []const u8 {
    const sender = jsonStringField(body, "from") orelse "unknown";
    const group_id = jsonStringField(body, "group_jid") orelse jsonStringField(body, "group_id");
    if (group_id) |gid| {
        return std.fmt.bufPrint(buf, "whatsapp:group:{s}:{s}", .{ gid, sender }) catch "whatsapp:unknown";
    }
    return std.fmt.bufPrint(buf, "whatsapp:{s}", .{sender}) catch "whatsapp:unknown";
}

fn whatsappReplyTarget(body: []const u8) []const u8 {
    // Cloud API delivery is addressed by recipient id ("from" for inbound DMs).
    // Group IDs are used for routing/session isolation, not outbound target.
    return jsonStringField(body, "from") orelse "unknown";
}

fn whatsappIsGroupMessage(body: []const u8) bool {
    return jsonStringField(body, "group_jid") != null or
        jsonStringField(body, "group_id") != null;
}

fn whatsappGroupId(body: []const u8) ?[]const u8 {
    return jsonStringField(body, "group_jid") orelse
        jsonStringField(body, "group_id");
}

fn whatsappSenderAllowed(
    sender: ?[]const u8,
    is_group: bool,
    group_id: ?[]const u8,
    allow_from: []const []const u8,
    group_allow_from: []const []const u8,
    groups: []const []const u8,
    group_policy: []const u8,
) bool {
    const sender_id = sender orelse return false;

    if (!is_group) {
        if (allow_from.len == 0) return false;
        return whatsappSenderInAllowlist(allow_from, sender_id);
    }

    if (std.mem.eql(u8, group_policy, "disabled")) return false;

    const group_allowlist_enabled = std.mem.eql(u8, group_policy, "allowlist") or groups.len > 0;
    if (group_allowlist_enabled) {
        const gid = group_id orelse return false;
        if (!channels.isAllowed(groups, gid)) return false;
    }

    if (std.mem.eql(u8, group_policy, "open")) return true;

    const effective_allow = if (group_allow_from.len > 0) group_allow_from else allow_from;
    if (effective_allow.len == 0) return false;
    return whatsappSenderInAllowlist(effective_allow, sender_id);
}

fn whatsappSenderInAllowlist(allowlist: []const []const u8, sender_raw: []const u8) bool {
    if (channels.isAllowed(allowlist, sender_raw)) return true;

    var normalized_buf: [64]u8 = undefined;
    const sender_normalized = channels.whatsapp.WhatsAppChannel.normalizePhone(&normalized_buf, sender_raw);
    if (!std.mem.eql(u8, sender_normalized, sender_raw) and channels.isAllowed(allowlist, sender_normalized)) {
        return true;
    }
    if (sender_normalized.len > 0 and sender_normalized[0] == '+' and
        channels.isAllowed(allowlist, sender_normalized[1..]))
    {
        return true;
    }
    return false;
}

fn whatsappSessionKeyRouted(
    allocator: std.mem.Allocator,
    fallback_buf: []u8,
    body: []const u8,
    cfg_opt: ?*const Config,
    account_id: []const u8,
) []const u8 {
    const sender = jsonStringField(body, "from") orelse "unknown";
    const group_id = jsonStringField(body, "group_jid") orelse jsonStringField(body, "group_id");
    const peer_id = if (group_id) |gid|
        if (gid.len > 0) gid else sender
    else
        sender;
    const peer_kind: agent_routing.ChatType = if (group_id != null) .group else .direct;

    if (cfg_opt) |cfg| {
        const route = agent_routing.resolveRouteWithSession(allocator, .{
            .channel = "whatsapp",
            .account_id = account_id,
            .peer = .{ .kind = peer_kind, .id = peer_id },
        }, cfg.agent_bindings, cfg.agents, cfg.session) catch return whatsappSessionKey(fallback_buf, body);
        allocator.free(route.main_session_key);
        return route.session_key;
    }

    return whatsappSessionKey(fallback_buf, body);
}

fn resolveRouteSessionKey(
    allocator: std.mem.Allocator,
    cfg_opt: ?*const Config,
    channel: []const u8,
    account_id: []const u8,
    peer: agent_routing.PeerRef,
    fallback: []const u8,
) []const u8 {
    if (cfg_opt) |cfg| {
        const route = agent_routing.resolveRouteWithSession(allocator, .{
            .channel = channel,
            .account_id = account_id,
            .peer = peer,
        }, cfg.agent_bindings, cfg.agents, cfg.session) catch return fallback;
        allocator.free(route.main_session_key);
        return route.session_key;
    }
    return fallback;
}

fn telegramChatIsGroup(allocator: std.mem.Allocator, body: []const u8) bool {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;

    const msg_obj = parsed.value.object.get("message") orelse
        parsed.value.object.get("edited_message") orelse return false;
    if (msg_obj != .object) return false;

    const chat_obj = msg_obj.object.get("chat") orelse return false;
    if (chat_obj != .object) return false;

    const type_val = chat_obj.object.get("type") orelse return false;
    if (type_val != .string) return false;

    return std.mem.eql(u8, type_val.string, "group") or
        std.mem.eql(u8, type_val.string, "supergroup") or
        std.mem.eql(u8, type_val.string, "channel");
}

fn telegramSenderAllowed(allocator: std.mem.Allocator, allow_from: []const []const u8, body: []const u8) bool {
    if (allow_from.len == 0) return true;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;

    const msg_obj = parsed.value.object.get("message") orelse
        parsed.value.object.get("edited_message") orelse return false;
    if (msg_obj != .object) return false;

    const from_obj = msg_obj.object.get("from") orelse return false;
    if (from_obj != .object) return false;

    if (from_obj.object.get("username")) |uname| {
        if (uname == .string and channels.isAllowed(allow_from, uname.string)) return true;
    }

    if (from_obj.object.get("id")) |id_val| {
        if (id_val == .integer) {
            var id_buf: [32]u8 = undefined;
            const id_str = std.fmt.bufPrint(&id_buf, "{d}", .{id_val.integer}) catch return false;
            if (channels.isAllowed(allow_from, id_str)) return true;
        }
    }

    return false;
}

fn telegramSessionKeyRouted(
    allocator: std.mem.Allocator,
    fallback_buf: []u8,
    chat_id: i64,
    body: []const u8,
    cfg_opt: ?*const Config,
    account_id: []const u8,
) []const u8 {
    const fallback = std.fmt.bufPrint(fallback_buf, "telegram:{d}", .{chat_id}) catch "telegram:0";
    var peer_buf: [64]u8 = undefined;
    const peer_id = std.fmt.bufPrint(&peer_buf, "{d}", .{chat_id}) catch return fallback;
    const peer_kind: agent_routing.ChatType = if (telegramChatIsGroup(allocator, body)) .group else .direct;
    return resolveRouteSessionKey(
        allocator,
        cfg_opt,
        "telegram",
        account_id,
        .{ .kind = peer_kind, .id = peer_id },
        fallback,
    );
}

fn telegramChatId(allocator: std.mem.Allocator, body: []const u8) ?i64 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch {
        return jsonIntField(body, "chat_id");
    };
    defer parsed.deinit();
    if (parsed.value != .object) return jsonIntField(body, "chat_id");

    const msg_obj = parsed.value.object.get("message") orelse
        parsed.value.object.get("edited_message") orelse return jsonIntField(body, "chat_id");
    if (msg_obj != .object) return jsonIntField(body, "chat_id");

    const chat_obj = msg_obj.object.get("chat") orelse return jsonIntField(body, "chat_id");
    if (chat_obj != .object) return jsonIntField(body, "chat_id");

    const id_val = chat_obj.object.get("id") orelse return jsonIntField(body, "chat_id");
    if (id_val != .integer) return jsonIntField(body, "chat_id");
    return id_val.integer;
}

fn telegramSenderIdentity(
    allocator: std.mem.Allocator,
    body: []const u8,
    id_buf: []u8,
) []const u8 {
    if (jsonStringField(body, "username")) |uname| return uname;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return "unknown";
    defer parsed.deinit();
    if (parsed.value != .object) return "unknown";

    const msg_obj = parsed.value.object.get("message") orelse
        parsed.value.object.get("edited_message") orelse return "unknown";
    if (msg_obj != .object) return "unknown";

    const from_obj = msg_obj.object.get("from") orelse return "unknown";
    if (from_obj != .object) return "unknown";
    if (from_obj.object.get("id")) |id_val| {
        if (id_val == .integer) {
            return std.fmt.bufPrint(id_buf, "{d}", .{id_val.integer}) catch "unknown";
        }
    }
    return "unknown";
}

fn lineSessionKey(buf: []u8, evt: channels.line.LineEvent) []const u8 {
    return std.fmt.bufPrint(buf, "line:{s}", .{evt.user_id orelse "unknown"}) catch "line:unknown";
}

fn lineReplyTarget(evt: channels.line.LineEvent) []const u8 {
    const source_type = evt.source_type orelse "";
    if (std.mem.eql(u8, source_type, "group")) {
        return evt.group_id orelse evt.user_id orelse "unknown";
    }
    if (std.mem.eql(u8, source_type, "room")) {
        return evt.room_id orelse evt.user_id orelse "unknown";
    }
    return evt.user_id orelse "unknown";
}

fn lineSessionKeyRouted(
    allocator: std.mem.Allocator,
    fallback_buf: []u8,
    evt: channels.line.LineEvent,
    cfg_opt: ?*const Config,
    account_id: []const u8,
) []const u8 {
    const fallback = lineSessionKey(fallback_buf, evt);
    const src_type = evt.source_type orelse "";
    const peer_kind: agent_routing.ChatType = if (std.mem.eql(u8, src_type, "group") or std.mem.eql(u8, src_type, "room")) .group else .direct;
    var peer_buf: [160]u8 = undefined;
    const peer_id = if (std.mem.eql(u8, src_type, "group"))
        std.fmt.bufPrint(&peer_buf, "group:{s}", .{evt.group_id orelse evt.user_id orelse "unknown"}) catch return fallback
    else if (std.mem.eql(u8, src_type, "room"))
        std.fmt.bufPrint(&peer_buf, "room:{s}", .{evt.room_id orelse evt.user_id orelse "unknown"}) catch return fallback
    else
        evt.user_id orelse "unknown";
    return resolveRouteSessionKey(
        allocator,
        cfg_opt,
        "line",
        account_id,
        .{ .kind = peer_kind, .id = peer_id },
        fallback,
    );
}

fn larkSessionKey(buf: []u8, msg: channels.lark.ParsedLarkMessage) []const u8 {
    return std.fmt.bufPrint(buf, "lark:{s}", .{msg.sender}) catch "lark:unknown";
}

fn larkSessionKeyRouted(
    allocator: std.mem.Allocator,
    fallback_buf: []u8,
    msg: channels.lark.ParsedLarkMessage,
    cfg_opt: ?*const Config,
    account_id: []const u8,
) []const u8 {
    const fallback = larkSessionKey(fallback_buf, msg);
    const peer_kind: agent_routing.ChatType = if (msg.is_group) .group else .direct;
    return resolveRouteSessionKey(
        allocator,
        cfg_opt,
        "lark",
        account_id,
        .{ .kind = peer_kind, .id = msg.sender },
        fallback,
    );
}

// ── Message Processing ──────────────────────────────────────────

/// Extract the HTTP request body from raw bytes.
/// Finds the \r\n\r\n boundary and returns everything after it.
pub fn extractBody(raw: []const u8) ?[]const u8 {
    const separator = "\r\n\r\n";
    const pos = std.mem.indexOf(u8, raw, separator) orelse return null;
    const body = raw[pos + separator.len ..];
    if (body.len == 0) return null;
    return body;
}

/// Process an incoming message by spawning `nullclaw agent -m "..."`.
/// Returns the agent's response text. Caller owns the returned memory.
pub fn processIncomingMessage(allocator: std.mem.Allocator, message: []const u8) ![]u8 {
    // Find our own executable path
    var self_buf: [std.fs.max_path_bytes]u8 = undefined;
    const self_path = std.fs.selfExePath(&self_buf) catch "nullclaw";

    var child = std.process.Child.init(
        &[_][]const u8{ self_path, "agent", "-m", message },
        allocator,
    );
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();

    // Read stdout
    var stdout_buf: std.ArrayList(u8) = .empty;
    defer stdout_buf.deinit(allocator);

    const stdout_reader = child.stdout.?;
    var read_buf: [4096]u8 = undefined;
    while (true) {
        const n = stdout_reader.read(&read_buf) catch break;
        if (n == 0) break;
        try stdout_buf.appendSlice(allocator, read_buf[0..n]);
    }

    const term = try child.wait();
    _ = term;

    if (stdout_buf.items.len > 0) {
        return try allocator.dupe(u8, stdout_buf.items);
    }
    return try allocator.dupe(u8, "No response from agent");
}

/// Send a reply to a Telegram chat using the Bot API.
pub fn sendTelegramReply(allocator: std.mem.Allocator, bot_token: []const u8, chat_id: i64, text: []const u8) !void {
    // Build the curl command to call the Telegram API
    const url = try std.fmt.allocPrint(allocator, "https://api.telegram.org/bot{s}/sendMessage", .{bot_token});
    defer allocator.free(url);

    // JSON-escape the text for the body
    var body_buf: std.ArrayList(u8) = .empty;
    defer body_buf.deinit(allocator);
    const w = body_buf.writer(allocator);
    try w.print("{{\"chat_id\":{d},\"text\":\"", .{chat_id});
    for (text) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => try w.writeByte(c),
        }
    }
    try w.writeAll("\"}");

    const body = body_buf.items;

    var curl_child = std.process.Child.init(
        &[_][]const u8{
            "curl", "-s",                             "-X", "POST",
            "-H",   "Content-Type: application/json", "-d", body,
            url,
        },
        allocator,
    );
    curl_child.stdout_behavior = .Pipe;
    curl_child.stderr_behavior = .Pipe;

    curl_child.spawn() catch return;
    _ = curl_child.wait() catch {};
}

fn userFacingAgentError(err: anyerror) []const u8 {
    return switch (err) {
        error.CurlFailed, error.CurlReadError, error.CurlWaitError, error.CurlWriteError => "Network error. Please try again.",
        error.ProviderDoesNotSupportVision => "The current provider does not support image input.",
        error.AllProvidersFailed => "All configured providers failed for this request. Check model/provider compatibility and credentials.",
        error.NoResponseContent => "Model returned an empty response. Please try again.",
        error.OutOfMemory => "Out of memory.",
        else => "An error occurred. Try again.",
    };
}

fn userFacingAgentErrorJson(err: anyerror) []const u8 {
    return switch (err) {
        error.CurlFailed, error.CurlReadError, error.CurlWaitError, error.CurlWriteError => "{\"error\":\"network error\"}",
        error.ProviderDoesNotSupportVision => "{\"error\":\"provider does not support image input\"}",
        error.AllProvidersFailed => "{\"error\":\"all providers failed for this request\"}",
        error.NoResponseContent => "{\"error\":\"model returned empty response\"}",
        error.OutOfMemory => "{\"error\":\"out of memory\"}",
        else => "{\"error\":\"agent failure\"}",
    };
}

const WebhookHandlerContext = struct {
    root_allocator: std.mem.Allocator,
    req_allocator: std.mem.Allocator,
    raw_request: []const u8,
    method: []const u8,
    target: []const u8,
    config_opt: ?*const Config,
    state: *GatewayState,
    session_mgr_opt: ?*session_mod.SessionManager,
    response_status: []const u8 = "200 OK",
    response_body: []const u8 = "",
};

const WebhookHandlerFn = *const fn (ctx: *WebhookHandlerContext) void;

const WebhookRouteDescriptor = struct {
    path: []const u8,
    handler: WebhookHandlerFn,
};

const webhook_route_descriptors = [_]WebhookRouteDescriptor{
    .{ .path = "/telegram", .handler = handleTelegramWebhookRoute },
    .{ .path = "/whatsapp", .handler = handleWhatsAppWebhookRoute },
    .{ .path = "/slack/events", .handler = handleSlackWebhookRoute },
    .{ .path = "/line", .handler = handleLineWebhookRoute },
    .{ .path = "/lark", .handler = handleLarkWebhookRoute },
};

fn findWebhookRouteDescriptor(path: []const u8) ?*const WebhookRouteDescriptor {
    for (&webhook_route_descriptors) |*desc| {
        if (std.mem.eql(u8, desc.path, path)) return desc;
    }
    return null;
}

fn handleTelegramWebhookRoute(ctx: *WebhookHandlerContext) void {
    if (!build_options.enable_channel_telegram) {
        ctx.response_status = "404 Not Found";
        ctx.response_body = "{\"error\":\"telegram channel disabled in this build\"}";
        return;
    }

    const is_post = std.mem.eql(u8, ctx.method, "POST");
    if (!is_post) {
        ctx.response_status = "405 Method Not Allowed";
        ctx.response_body = "{\"error\":\"method not allowed\"}";
        return;
    }

    if (!ctx.state.rate_limiter.allowWebhook(ctx.state.allocator, "telegram")) {
        ctx.response_status = "429 Too Many Requests";
        ctx.response_body = "{\"error\":\"rate limited\"}";
        return;
    }

    const body = extractBody(ctx.raw_request);
    if (body) |b| {
        var tg_bot_token = ctx.state.telegram_bot_token;
        var tg_allow_from = ctx.state.telegram_allow_from;
        var tg_account_id = ctx.state.telegram_account_id;
        if (selectTelegramConfig(ctx.config_opt, ctx.target)) |tg_cfg| {
            tg_bot_token = tg_cfg.bot_token;
            tg_allow_from = tg_cfg.allow_from;
            tg_account_id = tg_cfg.account_id;
        }

        const msg_text = jsonStringField(b, "text");
        const chat_id = telegramChatId(ctx.req_allocator, b);
        const tg_authorized = telegramSenderAllowed(ctx.req_allocator, tg_allow_from, b);
        if (!tg_authorized) {
            ctx.response_body = "{\"status\":\"unauthorized\"}";
            return;
        }

        if (msg_text != null and chat_id != null) {
            var sender_buf: [32]u8 = undefined;
            const sender = telegramSenderIdentity(ctx.req_allocator, b, &sender_buf);
            var cid_buf: [32]u8 = undefined;
            const cid_str = std.fmt.bufPrint(&cid_buf, "{d}", .{chat_id.?}) catch "0";
            const is_group = telegramChatIsGroup(ctx.req_allocator, b);
            const peer_kind = if (is_group) "group" else "direct";

            if (ctx.state.event_bus) |eb| {
                var meta_buf: [320]u8 = undefined;
                const meta = std.fmt.bufPrint(&meta_buf, "{{\"account_id\":\"{s}\",\"peer_kind\":\"{s}\",\"peer_id\":\"{s}\"}}", .{
                    tg_account_id,
                    peer_kind,
                    cid_str,
                }) catch null;
                var kb: [64]u8 = undefined;
                const tg_cfg_opt: ?*const Config = if (ctx.config_opt) |cfg| cfg else null;
                const sk = telegramSessionKeyRouted(ctx.req_allocator, &kb, chat_id.?, b, tg_cfg_opt, tg_account_id);
                _ = publishToBus(eb, ctx.state.allocator, "telegram", sender, cid_str, msg_text.?, sk, meta);
                ctx.response_body = "{\"status\":\"ok\"}";
            } else if (ctx.session_mgr_opt) |sm| {
                var kb: [64]u8 = undefined;
                const tg_cfg_opt: ?*const Config = if (ctx.config_opt) |cfg| cfg else null;
                const sk = telegramSessionKeyRouted(ctx.req_allocator, &kb, chat_id.?, b, tg_cfg_opt, tg_account_id);
                const reply: ?[]const u8 = sm.processMessage(sk, msg_text.?, null) catch |err| blk: {
                    if (tg_bot_token.len > 0) {
                        sendTelegramReply(ctx.req_allocator, tg_bot_token, chat_id.?, userFacingAgentError(err)) catch {};
                    }
                    break :blk null;
                };
                if (reply) |r| {
                    defer ctx.root_allocator.free(r);
                    if (tg_bot_token.len > 0) {
                        sendTelegramReply(ctx.req_allocator, tg_bot_token, chat_id.?, r) catch {};
                    }
                    ctx.response_body = "{\"status\":\"ok\"}";
                } else {
                    ctx.response_body = "{\"status\":\"received\"}";
                }
            } else {
                ctx.response_body = "{\"status\":\"received\"}";
            }
        } else {
            ctx.response_body = "{\"status\":\"ok\"}";
        }
    } else {
        ctx.response_body = "{\"status\":\"received\"}";
    }
}

fn handleWhatsAppWebhookRoute(ctx: *WebhookHandlerContext) void {
    if (!build_options.enable_channel_whatsapp) {
        ctx.response_status = "404 Not Found";
        ctx.response_body = "{\"error\":\"whatsapp channel disabled in this build\"}";
        return;
    }

    const is_get = std.mem.eql(u8, ctx.method, "GET");
    if (is_get) {
        const mode = parseQueryParam(ctx.target, "hub.mode");
        const token = parseQueryParam(ctx.target, "hub.verify_token");
        const challenge = parseQueryParam(ctx.target, "hub.challenge");
        var wa_verify_token = ctx.state.whatsapp_verify_token;
        if (selectWhatsAppConfig(ctx.config_opt, null, token)) |wa_cfg| {
            wa_verify_token = wa_cfg.verify_token;
        }

        if (mode != null and challenge != null and token != null and
            std.mem.eql(u8, mode.?, "subscribe") and
            wa_verify_token.len > 0 and
            std.mem.eql(u8, token.?, wa_verify_token))
        {
            ctx.response_body = challenge.?;
        } else {
            ctx.response_status = "403 Forbidden";
            ctx.response_body = "{\"error\":\"verification failed\"}";
        }
        return;
    }

    const is_post = std.mem.eql(u8, ctx.method, "POST");
    if (!is_post) {
        ctx.response_status = "405 Method Not Allowed";
        ctx.response_body = "{\"error\":\"method not allowed\"}";
        return;
    }

    if (!ctx.state.rate_limiter.allowWebhook(ctx.state.allocator, "whatsapp")) {
        ctx.response_status = "429 Too Many Requests";
        ctx.response_body = "{\"error\":\"rate limited\"}";
        return;
    }

    const wa_body = extractBody(ctx.raw_request);
    var wa_app_secret = ctx.state.whatsapp_app_secret;
    var wa_access_token = ctx.state.whatsapp_access_token;
    var wa_allow_from = ctx.state.whatsapp_allow_from;
    var wa_group_allow_from = ctx.state.whatsapp_group_allow_from;
    var wa_groups = ctx.state.whatsapp_groups;
    var wa_group_policy = ctx.state.whatsapp_group_policy;
    var wa_account_id = ctx.state.whatsapp_account_id;
    if (selectWhatsAppConfig(ctx.config_opt, wa_body, null)) |wa_cfg| {
        wa_app_secret = wa_cfg.app_secret orelse "";
        wa_access_token = wa_cfg.access_token;
        wa_allow_from = wa_cfg.allow_from;
        wa_group_allow_from = wa_cfg.group_allow_from;
        wa_groups = wa_cfg.groups;
        wa_group_policy = wa_cfg.group_policy;
        wa_account_id = wa_cfg.account_id;
    }

    const sig_header = extractHeader(ctx.raw_request, "X-Hub-Signature-256");
    if (wa_app_secret.len > 0) sig_check: {
        const sig = sig_header orelse {
            ctx.response_status = "403 Forbidden";
            ctx.response_body = "{\"error\":\"missing signature\"}";
            break :sig_check;
        };
        const body = wa_body orelse {
            ctx.response_body = "{\"status\":\"received\"}";
            break :sig_check;
        };
        if (!verifyWhatsappSignature(body, sig, wa_app_secret)) {
            ctx.response_status = "403 Forbidden";
            ctx.response_body = "{\"error\":\"invalid signature\"}";
            break :sig_check;
        }
        const wa_sender = jsonStringField(body, "from");
        const wa_is_group = whatsappIsGroupMessage(body);
        const wa_group_id = whatsappGroupId(body);
        if (!whatsappSenderAllowed(
            wa_sender,
            wa_is_group,
            wa_group_id,
            wa_allow_from,
            wa_group_allow_from,
            wa_groups,
            wa_group_policy,
        )) {
            ctx.response_body = "{\"status\":\"unauthorized\"}";
            break :sig_check;
        }
        const msg_text = jsonStringField(body, "text") orelse jsonStringField(body, "body") orelse
            channels.whatsapp.WhatsAppChannel.downloadMediaFromPayload(ctx.req_allocator, wa_access_token, body);
        if (msg_text) |mt| {
            var wa_key_buf: [256]u8 = undefined;
            const wa_cfg_opt: ?*const Config = if (ctx.config_opt) |cfg| cfg else null;
            const wa_session_key = whatsappSessionKeyRouted(ctx.req_allocator, &wa_key_buf, body, wa_cfg_opt, wa_account_id);
            const wa_sender_id = wa_sender orelse "unknown";
            const wa_chat_target = whatsappReplyTarget(body);
            const wa_peer_kind = if (wa_is_group) "group" else "direct";
            const wa_peer_id = wa_group_id orelse wa_sender_id;

            if (ctx.state.event_bus) |eb| {
                var meta_buf: [384]u8 = undefined;
                const meta = std.fmt.bufPrint(&meta_buf, "{{\"account_id\":\"{s}\",\"peer_kind\":\"{s}\",\"peer_id\":\"{s}\"}}", .{
                    wa_account_id,
                    wa_peer_kind,
                    wa_peer_id,
                }) catch null;
                _ = publishToBus(eb, ctx.state.allocator, "whatsapp", wa_sender_id, wa_chat_target, mt, wa_session_key, meta);
                ctx.response_body = "{\"status\":\"received\"}";
            } else if (ctx.session_mgr_opt) |sm| {
                const reply: ?[]const u8 = sm.processMessage(wa_session_key, mt, null) catch |err| blk: {
                    ctx.response_body = userFacingAgentErrorJson(err);
                    break :blk null;
                };
                if (reply) |r| {
                    defer ctx.root_allocator.free(r);
                    ctx.response_body = ctx.req_allocator.dupe(u8, r) catch "{\"status\":\"received\"}";
                } else {
                    ctx.response_body = "{\"status\":\"received\"}";
                }
            } else {
                ctx.response_body = "{\"status\":\"received\"}";
            }
        } else {
            ctx.response_body = "{\"status\":\"received\"}";
        }
        return;
    }

    if (wa_body) |b| {
        const wa_sender = jsonStringField(b, "from");
        const wa_is_group = whatsappIsGroupMessage(b);
        const wa_group_id = whatsappGroupId(b);
        if (!whatsappSenderAllowed(
            wa_sender,
            wa_is_group,
            wa_group_id,
            wa_allow_from,
            wa_group_allow_from,
            wa_groups,
            wa_group_policy,
        )) {
            ctx.response_body = "{\"status\":\"unauthorized\"}";
            return;
        }
        const msg_text = jsonStringField(b, "text") orelse jsonStringField(b, "body") orelse
            channels.whatsapp.WhatsAppChannel.downloadMediaFromPayload(ctx.req_allocator, wa_access_token, b);
        if (msg_text) |mt| {
            var wa_key_buf: [256]u8 = undefined;
            const wa_cfg_opt: ?*const Config = if (ctx.config_opt) |cfg| cfg else null;
            const wa_session_key = whatsappSessionKeyRouted(ctx.req_allocator, &wa_key_buf, b, wa_cfg_opt, wa_account_id);
            const wa_sender_ns = wa_sender orelse "unknown";
            const wa_chat_target_ns = whatsappReplyTarget(b);
            const wa_peer_kind = if (wa_is_group) "group" else "direct";
            const wa_peer_id = wa_group_id orelse wa_sender_ns;

            if (ctx.state.event_bus) |eb| {
                var meta_buf: [384]u8 = undefined;
                const meta = std.fmt.bufPrint(&meta_buf, "{{\"account_id\":\"{s}\",\"peer_kind\":\"{s}\",\"peer_id\":\"{s}\"}}", .{
                    wa_account_id,
                    wa_peer_kind,
                    wa_peer_id,
                }) catch null;
                _ = publishToBus(eb, ctx.state.allocator, "whatsapp", wa_sender_ns, wa_chat_target_ns, mt, wa_session_key, meta);
                ctx.response_body = "{\"status\":\"received\"}";
            } else if (ctx.session_mgr_opt) |sm| {
                const reply: ?[]const u8 = sm.processMessage(wa_session_key, mt, null) catch |err| blk: {
                    ctx.response_body = userFacingAgentErrorJson(err);
                    break :blk null;
                };
                if (reply) |r| {
                    defer ctx.root_allocator.free(r);
                    ctx.response_body = ctx.req_allocator.dupe(u8, r) catch "{\"status\":\"received\"}";
                } else {
                    ctx.response_body = "{\"status\":\"received\"}";
                }
            } else {
                ctx.response_body = "{\"status\":\"received\"}";
            }
        } else {
            ctx.response_body = "{\"status\":\"received\"}";
        }
    } else {
        ctx.response_body = "{\"status\":\"received\"}";
    }
}

fn handleSlackWebhookRoute(ctx: *WebhookHandlerContext) void {
    if (!build_options.enable_channel_slack) {
        ctx.response_status = "404 Not Found";
        ctx.response_body = "{\"error\":\"slack channel disabled in this build\"}";
        return;
    }

    if (!std.mem.eql(u8, ctx.method, "POST")) {
        ctx.response_status = "405 Method Not Allowed";
        ctx.response_body = "{\"error\":\"method not allowed\"}";
        return;
    }
    if (!ctx.state.rate_limiter.allowWebhook(ctx.state.allocator, "slack")) {
        ctx.response_status = "429 Too Many Requests";
        ctx.response_body = "{\"error\":\"rate limited\"}";
        return;
    }

    const body = extractBody(ctx.raw_request) orelse {
        ctx.response_body = "{\"status\":\"received\"}";
        return;
    };

    const ts_header = extractHeader(ctx.raw_request, "X-Slack-Request-Timestamp");
    const sig_header = extractHeader(ctx.raw_request, "X-Slack-Signature");

    const slack_cfg = findSlackConfigForRequest(ctx.req_allocator, ctx.config_opt, ctx.target, body, ts_header, sig_header) orelse {
        if (hasSlackHttpEndpoint(ctx.config_opt, webhookBasePath(ctx.target))) {
            ctx.response_status = "403 Forbidden";
            ctx.response_body = "{\"error\":\"invalid signature\"}";
            return;
        }
        ctx.response_status = "404 Not Found";
        ctx.response_body = "{\"error\":\"slack account not configured\"}";
        return;
    };

    const parsed = std.json.parseFromSlice(std.json.Value, ctx.req_allocator, body, .{}) catch {
        ctx.response_body = "{\"status\":\"parse_error\"}";
        return;
    };
    defer parsed.deinit();
    if (parsed.value != .object) {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    }

    const payload_type = if (parsed.value.object.get("type")) |tv|
        if (tv == .string) tv.string else ""
    else
        "";

    if (std.mem.eql(u8, payload_type, "url_verification")) {
        const challenge = jsonStringField(body, "challenge") orelse "";
        if (challenge.len == 0) {
            ctx.response_body = "{\"status\":\"ok\"}";
            return;
        }
        const challenge_resp = jsonWrapChallenge(ctx.req_allocator, challenge) catch {
            ctx.response_body = "{\"status\":\"ok\"}";
            return;
        };
        ctx.response_body = challenge_resp;
        return;
    }

    if (!std.mem.eql(u8, payload_type, "event_callback")) {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    }

    const event_val = parsed.value.object.get("event") orelse {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    };
    if (event_val != .object) {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    }
    const event_obj = event_val.object;

    const event_type_val = event_obj.get("type") orelse {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    };
    if (event_type_val != .string) {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    }
    const event_type = event_type_val.string;
    if (!std.mem.eql(u8, event_type, "message") and !std.mem.eql(u8, event_type, "app_mention")) {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    }

    if (event_obj.get("subtype")) |subtype_val| {
        if (subtype_val == .string and subtype_val.string.len > 0) {
            ctx.response_body = "{\"status\":\"ok\"}";
            return;
        }
    }

    const user_val = event_obj.get("user") orelse {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    };
    if (user_val != .string or user_val.string.len == 0) {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    }
    const sender_id = user_val.string;

    const text_val = event_obj.get("text") orelse {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    };
    if (text_val != .string) {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    }
    const text = std.mem.trim(u8, text_val.string, " \t\r\n");
    if (text.len == 0) {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    }

    const channel_val = event_obj.get("channel") orelse {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    };
    if (channel_val != .string or channel_val.string.len == 0) {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    }
    const channel_id = channel_val.string;
    const is_dm = blk: {
        if (event_obj.get("channel_type")) |ct| {
            if (ct == .string and std.mem.eql(u8, ct.string, "im")) break :blk true;
        }
        break :blk channel_id.len > 0 and channel_id[0] == 'D';
    };

    var policy_channel = channels.slack.SlackChannel.initFromConfig(ctx.req_allocator, slack_cfg.*);
    const envelope_bot_user_id = slackEnvelopeBotUserId(parsed.value.object);
    var allowed = policy_channel.shouldHandle(sender_id, is_dm, text, envelope_bot_user_id);
    if (!allowed and std.mem.eql(u8, event_type, "app_mention")) {
        allowed = channels.checkPolicy(policy_channel.policy, sender_id, is_dm, true);
    }
    if (!allowed) {
        ctx.response_body = "{\"status\":\"ok\"}";
        return;
    }

    var key_buf: [256]u8 = undefined;
    const sk = slackSessionKeyRouted(
        ctx.req_allocator,
        &key_buf,
        slack_cfg.account_id,
        sender_id,
        channel_id,
        is_dm,
        ctx.config_opt,
    );

    if (ctx.state.event_bus) |eb| {
        var meta_buf: [384]u8 = undefined;
        const peer_kind = if (is_dm) "direct" else "channel";
        const peer_id = if (is_dm) sender_id else channel_id;
        const metadata = std.fmt.bufPrint(
            &meta_buf,
            "{{\"account_id\":\"{s}\",\"is_dm\":{s},\"channel_id\":\"{s}\",\"peer_kind\":\"{s}\",\"peer_id\":\"{s}\"}}",
            .{
                slack_cfg.account_id,
                if (is_dm) "true" else "false",
                channel_id,
                peer_kind,
                peer_id,
            },
        ) catch null;
        _ = publishToBus(eb, ctx.state.allocator, "slack", sender_id, channel_id, text, sk, metadata);
    } else if (ctx.session_mgr_opt) |sm| {
        const reply: ?[]const u8 = sm.processMessage(sk, text, null) catch |err| blk: {
            var outbound_ch = channels.slack.SlackChannel.initFromConfig(ctx.req_allocator, slack_cfg.*);
            outbound_ch.sendMessage(channel_id, userFacingAgentError(err)) catch {};
            break :blk null;
        };
        if (reply) |r| {
            defer ctx.root_allocator.free(r);
            var outbound_ch = channels.slack.SlackChannel.initFromConfig(ctx.req_allocator, slack_cfg.*);
            outbound_ch.sendMessage(channel_id, r) catch {};
        }
    }

    ctx.response_body = "{\"status\":\"ok\"}";
}

fn linePeerMetadata(evt: channels.line.LineEvent, peer_buf: []u8) struct {
    kind: []const u8,
    id: []const u8,
} {
    const src_type = evt.source_type orelse "";
    if (std.mem.eql(u8, src_type, "group")) {
        return .{
            .kind = "group",
            .id = std.fmt.bufPrint(peer_buf, "group:{s}", .{evt.group_id orelse evt.user_id orelse "unknown"}) catch "group:unknown",
        };
    }
    if (std.mem.eql(u8, src_type, "room")) {
        return .{
            .kind = "group",
            .id = std.fmt.bufPrint(peer_buf, "room:{s}", .{evt.room_id orelse evt.user_id orelse "unknown"}) catch "room:unknown",
        };
    }
    return .{
        .kind = "direct",
        .id = evt.user_id orelse "unknown",
    };
}

fn handleLineWebhookRoute(ctx: *WebhookHandlerContext) void {
    if (!build_options.enable_channel_line) {
        ctx.response_status = "404 Not Found";
        ctx.response_body = "{\"error\":\"line channel disabled in this build\"}";
        return;
    }

    const is_post = std.mem.eql(u8, ctx.method, "POST");
    if (!is_post) {
        ctx.response_status = "405 Method Not Allowed";
        ctx.response_body = "{\"error\":\"method not allowed\"}";
        return;
    }
    if (!ctx.state.rate_limiter.allowWebhook(ctx.state.allocator, "line")) {
        ctx.response_status = "429 Too Many Requests";
        ctx.response_body = "{\"error\":\"rate limited\"}";
        return;
    }

    const body = extractBody(ctx.raw_request);
    if (body) |b| {
        var line_channel_secret = ctx.state.line_channel_secret;
        var line_access_token = ctx.state.line_access_token;
        var line_allow_from = ctx.state.line_allow_from;
        var line_account_id = ctx.state.line_account_id;

        const sig_header = extractHeader(ctx.raw_request, "X-Line-Signature");
        if (ctx.config_opt) |cfg| {
            const needs_signature = hasLineSecrets(cfg);
            if (needs_signature) {
                const sig = sig_header orelse {
                    ctx.response_status = "403 Forbidden";
                    ctx.response_body = "{\"error\":\"missing signature\"}";
                    return;
                };
                const matched_line_cfg = selectLineConfigBySignature(ctx.config_opt, b, sig) orelse {
                    ctx.response_status = "403 Forbidden";
                    ctx.response_body = "{\"error\":\"invalid signature\"}";
                    return;
                };
                line_channel_secret = matched_line_cfg.channel_secret;
                line_access_token = matched_line_cfg.access_token;
                line_allow_from = matched_line_cfg.allow_from;
                line_account_id = matched_line_cfg.account_id;
            } else if (cfg.channels.linePrimary()) |line_cfg| {
                line_channel_secret = line_cfg.channel_secret;
                line_access_token = line_cfg.access_token;
                line_allow_from = line_cfg.allow_from;
                line_account_id = line_cfg.account_id;
            }
        } else if (line_channel_secret.len > 0) {
            const sig = sig_header orelse {
                ctx.response_status = "403 Forbidden";
                ctx.response_body = "{\"error\":\"missing signature\"}";
                return;
            };
            if (!channels.line.LineChannel.verifySignature(b, sig, line_channel_secret)) {
                ctx.response_status = "403 Forbidden";
                ctx.response_body = "{\"error\":\"invalid signature\"}";
                return;
            }
        }

        const events = channels.line.LineChannel.parseWebhookEvents(ctx.req_allocator, b) catch {
            ctx.response_body = "{\"status\":\"parse_error\"}";
            return;
        };
        for (events) |evt| {
            if (line_allow_from.len > 0) {
                if (evt.user_id) |uid| {
                    if (!channels.isAllowed(line_allow_from, uid)) continue;
                } else continue;
            }
            if (evt.message_text) |text| {
                var kb: [128]u8 = undefined;
                const line_cfg_opt: ?*const Config = if (ctx.config_opt) |cfg| cfg else null;
                const sk = lineSessionKeyRouted(ctx.req_allocator, &kb, evt, line_cfg_opt, line_account_id);
                const uid = evt.user_id orelse "unknown";
                const line_target = lineReplyTarget(evt);
                var peer_buf: [160]u8 = undefined;
                const line_peer = linePeerMetadata(evt, &peer_buf);

                if (ctx.state.event_bus) |eb| {
                    var meta_buf: [384]u8 = undefined;
                    const meta = std.fmt.bufPrint(&meta_buf, "{{\"account_id\":\"{s}\",\"peer_kind\":\"{s}\",\"peer_id\":\"{s}\"}}", .{
                        line_account_id,
                        line_peer.kind,
                        line_peer.id,
                    }) catch null;
                    _ = publishToBus(eb, ctx.state.allocator, "line", uid, line_target, text, sk, meta);
                } else if (ctx.session_mgr_opt) |sm| {
                    const reply: ?[]const u8 = sm.processMessage(sk, text, null) catch |err| blk: {
                        if (evt.reply_token) |rt| {
                            var line_ch = channels.line.LineChannel.init(ctx.req_allocator, .{
                                .access_token = line_access_token,
                                .channel_secret = line_channel_secret,
                            });
                            line_ch.replyMessage(rt, userFacingAgentError(err)) catch {};
                        }
                        break :blk null;
                    };
                    if (reply) |r| {
                        defer ctx.root_allocator.free(r);
                        if (evt.reply_token) |rt| {
                            var line_ch = channels.line.LineChannel.init(ctx.req_allocator, .{
                                .access_token = line_access_token,
                                .channel_secret = line_channel_secret,
                            });
                            line_ch.replyMessage(rt, r) catch {};
                        }
                    }
                }
            }
        }
        ctx.response_body = "{\"status\":\"ok\"}";
    } else {
        ctx.response_body = "{\"status\":\"received\"}";
    }
}

fn handleLarkWebhookRoute(ctx: *WebhookHandlerContext) void {
    if (!build_options.enable_channel_lark) {
        ctx.response_status = "404 Not Found";
        ctx.response_body = "{\"error\":\"lark channel disabled in this build\"}";
        return;
    }

    const is_post = std.mem.eql(u8, ctx.method, "POST");
    if (!is_post) {
        ctx.response_status = "405 Method Not Allowed";
        ctx.response_body = "{\"error\":\"method not allowed\"}";
        return;
    }
    if (!ctx.state.rate_limiter.allowWebhook(ctx.state.allocator, "lark")) {
        ctx.response_status = "429 Too Many Requests";
        ctx.response_body = "{\"error\":\"rate limited\"}";
        return;
    }

    const body = extractBody(ctx.raw_request) orelse {
        ctx.response_body = "{\"status\":\"received\"}";
        return;
    };
    var lark_verification_token = ctx.state.lark_verification_token;
    var lark_app_id = ctx.state.lark_app_id;
    var lark_app_secret = ctx.state.lark_app_secret;
    var lark_allow_from = ctx.state.lark_allow_from;
    var lark_account_id = ctx.state.lark_account_id;
    if (selectLarkConfig(ctx.config_opt, body)) |lark_cfg| {
        lark_verification_token = lark_cfg.verification_token orelse "";
        lark_app_id = lark_cfg.app_id;
        lark_app_secret = lark_cfg.app_secret;
        lark_allow_from = lark_cfg.allow_from;
        lark_account_id = lark_cfg.account_id;
    }

    if (std.mem.indexOf(u8, body, "\"url_verification\"") != null) {
        const challenge = jsonStringField(body, "challenge");
        if (challenge) |c| {
            const challenge_resp = jsonWrapChallenge(ctx.req_allocator, c) catch null;
            ctx.response_body = challenge_resp orelse "{\"status\":\"ok\"}";
        } else {
            ctx.response_body = "{\"status\":\"ok\"}";
        }
        return;
    }

    if (lark_verification_token.len > 0) {
        const payload_token = blk: {
            const parsed = std.json.parseFromSlice(std.json.Value, ctx.req_allocator, body, .{}) catch break :blk @as(?[]const u8, null);
            defer parsed.deinit();
            if (parsed.value != .object) break :blk @as(?[]const u8, null);
            const header = parsed.value.object.get("header") orelse break :blk @as(?[]const u8, null);
            if (header != .object) break :blk @as(?[]const u8, null);
            const token_val = header.object.get("token") orelse break :blk @as(?[]const u8, null);
            break :blk if (token_val == .string) ctx.req_allocator.dupe(u8, token_val.string) catch null else null;
        };
        if (payload_token) |pt| {
            if (!std.mem.eql(u8, pt, lark_verification_token)) {
                ctx.response_status = "403 Forbidden";
                ctx.response_body = "{\"error\":\"invalid verification token\"}";
                return;
            }
        }
    }

    var lark_ch = channels.lark.LarkChannel.init(
        ctx.req_allocator,
        lark_app_id,
        lark_app_secret,
        lark_verification_token,
        0,
        lark_allow_from,
    );
    const messages = lark_ch.parseEventPayload(ctx.req_allocator, body) catch {
        ctx.response_body = "{\"status\":\"parse_error\"}";
        return;
    };
    for (messages) |msg| {
        var kb: [128]u8 = undefined;
        const lark_cfg_opt: ?*const Config = if (ctx.config_opt) |cfg| cfg else null;
        const sk = larkSessionKeyRouted(ctx.req_allocator, &kb, msg, lark_cfg_opt, lark_account_id);

        if (ctx.state.event_bus) |eb| {
            var meta_buf: [320]u8 = undefined;
            const meta = std.fmt.bufPrint(&meta_buf, "{{\"account_id\":\"{s}\",\"peer_kind\":\"{s}\",\"peer_id\":\"{s}\"}}", .{
                lark_account_id,
                if (msg.is_group) "group" else "direct",
                msg.sender,
            }) catch null;
            _ = publishToBus(eb, ctx.state.allocator, "lark", msg.sender, msg.sender, msg.content, sk, meta);
        } else if (ctx.session_mgr_opt) |sm| {
            const reply: ?[]const u8 = sm.processMessage(sk, msg.content, null) catch |err| blk: {
                lark_ch.sendMessage(msg.sender, userFacingAgentError(err)) catch {};
                break :blk null;
            };
            if (reply) |r| {
                defer ctx.root_allocator.free(r);
                lark_ch.sendMessage(msg.sender, r) catch {};
            }
        }
    }
    ctx.response_body = "{\"status\":\"ok\"}";
}

/// Run the HTTP gateway. Binds to host:port and serves HTTP requests.
/// Endpoints: GET /health, GET /ready, POST /pair, POST /webhook, GET|POST /whatsapp, POST /telegram, POST /slack/events, POST /line, POST /lark
/// If config_ptr is null, loads config internally (for backward compatibility).
pub fn run(allocator: std.mem.Allocator, host: []const u8, port: u16, config_ptr: ?*const Config, event_bus: ?*bus_mod.Bus) !void {
    health.markComponentOk("gateway");

    var state = GatewayState.init(allocator);
    defer state.deinit();
    state.event_bus = event_bus;

    var owned_config: ?Config = null;
    var config_opt: ?*const Config = null;
    if (config_ptr) |cfg| {
        config_opt = cfg;
    } else {
        owned_config = Config.load(allocator) catch null;
        if (owned_config) |*c| {
            config_opt = c;
        }
    }
    defer if (owned_config) |*c| c.deinit();

    // Provider runtime bundle (primary + reliability wrapper) must outlive the accept loop.
    var provider_bundle_opt: ?providers.runtime_bundle.RuntimeProviderBundle = null;
    var session_mgr_opt: ?session_mod.SessionManager = null;
    var tools_slice: []const tools_mod.Tool = &.{};
    var mem_rt: ?memory_mod.MemoryRuntime = null;
    var subagent_manager_opt: ?*subagent_mod.SubagentManager = null;
    var noop_obs_gateway = observability.NoopObserver{};
    const needs_local_agent = event_bus == null;

    if (config_opt) |cfg_ptr| {
        const cfg = cfg_ptr;
        state.rate_limiter = GatewayRateLimiter.init(
            cfg.gateway.pair_rate_limit_per_minute,
            cfg.gateway.webhook_rate_limit_per_minute,
        );
        state.idempotency = IdempotencyStore.init(cfg.gateway.idempotency_ttl_secs);
        state.pairing_guard = try PairingGuard.init(
            allocator,
            cfg.gateway.require_pairing,
            cfg.gateway.paired_tokens,
        );
        if (cfg.channels.telegramPrimary()) |tg_cfg| {
            state.telegram_bot_token = tg_cfg.bot_token;
            state.telegram_allow_from = tg_cfg.allow_from;
            state.telegram_account_id = tg_cfg.account_id;
        }
        if (cfg.channels.whatsappPrimary()) |wa_cfg| {
            state.whatsapp_verify_token = wa_cfg.verify_token;
            state.whatsapp_app_secret = wa_cfg.app_secret orelse "";
            state.whatsapp_access_token = wa_cfg.access_token;
            state.whatsapp_allow_from = wa_cfg.allow_from;
            state.whatsapp_group_allow_from = wa_cfg.group_allow_from;
            state.whatsapp_groups = wa_cfg.groups;
            state.whatsapp_group_policy = wa_cfg.group_policy;
            state.whatsapp_account_id = wa_cfg.account_id;
        }
        if (cfg.channels.linePrimary()) |line_cfg| {
            state.line_channel_secret = line_cfg.channel_secret;
            state.line_access_token = line_cfg.access_token;
            state.line_allow_from = line_cfg.allow_from;
            state.line_account_id = line_cfg.account_id;
        }
        if (cfg.channels.larkPrimary()) |lark_cfg| {
            state.lark_verification_token = lark_cfg.verification_token orelse "";
            state.lark_app_id = lark_cfg.app_id;
            state.lark_app_secret = lark_cfg.app_secret;
            state.lark_allow_from = lark_cfg.allow_from;
            state.lark_account_id = lark_cfg.account_id;
        }

        // In daemon mode (`event_bus` is present), inbound processing is delegated to
        // the bus + channel runtime. Avoid creating a second local agent runtime here.
        if (needs_local_agent) {
            provider_bundle_opt = try providers.runtime_bundle.RuntimeProviderBundle.init(allocator, cfg);

            if (provider_bundle_opt) |*bundle| {
                const provider_i: providers.Provider = bundle.provider();
                const resolved_api_key = bundle.primaryApiKey();

                // Optional memory backend.
                mem_rt = memory_mod.initRuntime(allocator, &cfg.memory, cfg.workspace_dir);

                const subagent_manager = allocator.create(subagent_mod.SubagentManager) catch null;
                if (subagent_manager) |mgr| {
                    mgr.* = subagent_mod.SubagentManager.init(allocator, cfg, event_bus, .{});
                    subagent_manager_opt = mgr;
                }

                // Tools.
                tools_slice = tools_mod.allTools(allocator, cfg.workspace_dir, .{
                    .http_enabled = cfg.http_request.enabled,
                    .browser_enabled = cfg.browser.enabled,
                    .screenshot_enabled = true,
                    .agents = cfg.agents,
                    .fallback_api_key = resolved_api_key,
                    .subagent_manager = subagent_manager_opt,
                }) catch &.{};

                const mem_opt: ?memory_mod.Memory = if (mem_rt) |rt| rt.memory else null;
                var sm = session_mod.SessionManager.init(allocator, cfg, provider_i, tools_slice, mem_opt, noop_obs_gateway.observer(), if (mem_rt) |rt| rt.session_store else null, if (mem_rt) |*rt| rt.response_cache else null);
                if (mem_rt) |*rt| {
                    sm.mem_rt = rt;
                    tools_mod.bindMemoryRuntime(tools_slice, rt);
                }
                session_mgr_opt = sm;
            }
        }
    }
    if (state.pairing_guard == null) {
        state.pairing_guard = try PairingGuard.init(allocator, true, &.{});
    }
    defer if (provider_bundle_opt) |*bundle| bundle.deinit();
    defer if (mem_rt) |*rt| rt.deinit();
    defer if (subagent_manager_opt) |mgr| {
        mgr.deinit();
        allocator.destroy(mgr);
    };
    defer if (tools_slice.len > 0) tools_mod.deinitTools(allocator, tools_slice);
    defer if (session_mgr_opt) |*sm| sm.deinit();

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
    if (config_opt) |cfg| {
        // In daemon mode the parent already prints model/provider.
        if (config_ptr == null) cfg.printModelConfig();
    }
    if (state.pairing_guard) |*guard| {
        if (guard.pairingCode()) |code| {
            try stdout.print("Gateway pairing code: {s}\n", .{code});
            try stdout.flush();
        }
    }

    // Accept loop — read raw HTTP from TCP connections
    while (true) {
        var conn = server.accept() catch continue;
        defer conn.stream.close();

        // Per-request arena — all request-scoped allocations freed in one shot
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const req_allocator = arena.allocator();

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

        // Simple routing — control endpoints + descriptor-driven channel webhooks.
        const ControlRoute = enum { health, ready, webhook, pair };
        const control_route_map = std.StaticStringMap(ControlRoute).initComptime(.{
            .{ "/health", .health },
            .{ "/ready", .ready },
            .{ "/webhook", .webhook },
            .{ "/pair", .pair },
        });
        const base_path = if (std.mem.indexOfScalar(u8, target, '?')) |qi| target[0..qi] else target;
        const is_post = std.mem.eql(u8, method_str, "POST");
        var response_status: []const u8 = "200 OK";
        var response_body: []const u8 = "";
        var pair_response_buf: [256]u8 = undefined;

        if (findWebhookRouteDescriptor(base_path)) |desc| {
            var webhook_ctx = WebhookHandlerContext{
                .root_allocator = allocator,
                .req_allocator = req_allocator,
                .raw_request = raw,
                .method = method_str,
                .target = target,
                .config_opt = config_opt,
                .state = &state,
                .session_mgr_opt = if (session_mgr_opt) |*sm| sm else null,
            };
            desc.handler(&webhook_ctx);
            response_status = webhook_ctx.response_status;
            response_body = webhook_ctx.response_body;
        } else if (hasSlackHttpEndpoint(config_opt, base_path)) {
            var webhook_ctx = WebhookHandlerContext{
                .root_allocator = allocator,
                .req_allocator = req_allocator,
                .raw_request = raw,
                .method = method_str,
                .target = target,
                .config_opt = config_opt,
                .state = &state,
                .session_mgr_opt = if (session_mgr_opt) |*sm| sm else null,
            };
            handleSlackWebhookRoute(&webhook_ctx);
            response_status = webhook_ctx.response_status;
            response_body = webhook_ctx.response_body;
        } else if (control_route_map.get(base_path)) |route| switch (route) {
            .health => {
                response_body = if (isHealthOk()) "{\"status\":\"ok\"}" else "{\"status\":\"degraded\"}";
            },
            .ready => {
                const readiness = health.checkRegistryReadiness(req_allocator) catch {
                    response_status = "500 Internal Server Error";
                    response_body = "{\"status\":\"not_ready\",\"checks\":[]}";
                    continue;
                };
                const json_body = readiness.formatJson(req_allocator) catch {
                    response_status = "500 Internal Server Error";
                    response_body = "{\"status\":\"not_ready\",\"checks\":[]}";
                    continue;
                };
                response_body = json_body;
                if (readiness.status != .ready) {
                    response_status = "503 Service Unavailable";
                }
            },
            .webhook => {
                if (!is_post) {
                    response_status = "405 Method Not Allowed";
                    response_body = "{\"error\":\"method not allowed\"}";
                } else {
                    const auth_header = extractHeader(raw, "Authorization");
                    const bearer = if (auth_header) |ah| extractBearerToken(ah) else null;
                    const pairing_guard = if (state.pairing_guard) |*guard| guard else null;
                    if (!isWebhookAuthorized(pairing_guard, bearer)) {
                        response_status = "401 Unauthorized";
                        response_body = "{\"error\":\"unauthorized\"}";
                    } else if (!state.rate_limiter.allowWebhook(state.allocator, "webhook")) {
                        response_status = "429 Too Many Requests";
                        response_body = "{\"error\":\"rate limited\"}";
                    } else {
                        const body = extractBody(raw);
                        if (body) |b| {
                            const msg_text = jsonStringField(b, "message") orelse jsonStringField(b, "text") orelse b;
                            var sk_buf: [128]u8 = undefined;
                            const session_key = std.fmt.bufPrint(&sk_buf, "webhook:{s}", .{bearer orelse "anon"}) catch "webhook:anon";

                            if (state.event_bus) |eb| {
                                _ = publishToBus(eb, state.allocator, "webhook", bearer orelse "anon", session_key, msg_text, session_key, null);
                                response_body = "{\"status\":\"received\"}";
                            } else if (session_mgr_opt) |*sm| {
                                const reply: ?[]const u8 = sm.processMessage(session_key, msg_text, null) catch |err| blk: {
                                    response_body = userFacingAgentErrorJson(err);
                                    break :blk null;
                                };
                                if (reply) |r| {
                                    defer allocator.free(r);
                                    const json_resp = jsonWrapResponse(req_allocator, r) catch null;
                                    response_body = json_resp orelse "{\"status\":\"received\"}";
                                } else {
                                    response_body = "{\"status\":\"received\"}";
                                }
                            } else {
                                response_body = "{\"status\":\"received\"}";
                            }
                        } else {
                            response_body = "{\"status\":\"received\"}";
                        }
                    }
                }
            },
            .pair => {
                if (!is_post) {
                    response_status = "405 Method Not Allowed";
                    response_body = "{\"error\":\"method not allowed\"}";
                } else if (!state.rate_limiter.allowPair(state.allocator, "pair")) {
                    response_status = "429 Too Many Requests";
                    response_body = "{\"error\":\"rate limited\"}";
                } else {
                    if (state.pairing_guard) |*guard| {
                        const pairing_code = extractHeader(raw, "X-Pairing-Code");
                        switch (guard.attemptPair(pairing_code)) {
                            .paired => |token| {
                                defer allocator.free(token);
                                if (formatPairSuccessResponse(&pair_response_buf, token)) |pair_resp| {
                                    response_body = pair_resp;
                                } else {
                                    response_status = "500 Internal Server Error";
                                    response_body = "{\"error\":\"pairing response failed\"}";
                                }
                            },
                            .missing_code => {
                                response_status = "400 Bad Request";
                                response_body = "{\"error\":\"missing X-Pairing-Code\"}";
                            },
                            .invalid_code => {
                                response_status = "401 Unauthorized";
                                response_body = "{\"error\":\"invalid pairing code\"}";
                            },
                            .already_paired => {
                                response_status = "409 Conflict";
                                response_body = "{\"error\":\"already paired\"}";
                            },
                            .disabled => {
                                response_status = "403 Forbidden";
                                response_body = "{\"error\":\"pairing disabled\"}";
                            },
                            .locked_out => {
                                response_status = "429 Too Many Requests";
                                response_body = "{\"error\":\"pairing locked out\"}";
                            },
                            .internal_error => {
                                response_status = "500 Internal Server Error";
                                response_body = "{\"error\":\"pairing failed\"}";
                            },
                        }
                    } else {
                        response_status = "500 Internal Server Error";
                        response_body = "{\"error\":\"pairing unavailable\"}";
                    }
                }
            },
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

test "findWebhookRouteDescriptor resolves known webhook paths" {
    try std.testing.expect(findWebhookRouteDescriptor("/telegram") != null);
    try std.testing.expect(findWebhookRouteDescriptor("/whatsapp") != null);
    try std.testing.expect(findWebhookRouteDescriptor("/slack/events") != null);
    try std.testing.expect(findWebhookRouteDescriptor("/line") != null);
    try std.testing.expect(findWebhookRouteDescriptor("/lark") != null);
    try std.testing.expect(findWebhookRouteDescriptor("/health") == null);
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

// ── Bearer Token Validation tests ───────────────────────────────

test "validateBearerToken allows when no paired tokens" {
    try std.testing.expect(validateBearerToken("anything", &.{}));
}

test "validateBearerToken allows valid token" {
    const tokens = &[_][]const u8{ "token-a", "token-b", "token-c" };
    try std.testing.expect(validateBearerToken("token-b", tokens));
}

test "validateBearerToken rejects invalid token" {
    const tokens = &[_][]const u8{ "token-a", "token-b" };
    try std.testing.expect(!validateBearerToken("token-c", tokens));
}

test "validateBearerToken rejects empty token when tokens configured" {
    const tokens = &[_][]const u8{"secret"};
    try std.testing.expect(!validateBearerToken("", tokens));
}

test "validateBearerToken exact match required" {
    const tokens = &[_][]const u8{"abc123"};
    try std.testing.expect(validateBearerToken("abc123", tokens));
    try std.testing.expect(!validateBearerToken("abc1234", tokens));
    try std.testing.expect(!validateBearerToken("abc12", tokens));
}

test "isWebhookAuthorized fails closed when pairing guard missing" {
    try std.testing.expect(!isWebhookAuthorized(null, "token"));
}

test "isWebhookAuthorized allows when pairing disabled" {
    var guard = try PairingGuard.init(std.testing.allocator, false, &.{});
    defer guard.deinit();
    try std.testing.expect(isWebhookAuthorized(&guard, null));
}

test "isWebhookAuthorized requires valid bearer token when pairing enabled" {
    const tokens = [_][]const u8{"zc_valid"};
    var guard = try PairingGuard.init(std.testing.allocator, true, &tokens);
    defer guard.deinit();

    try std.testing.expect(isWebhookAuthorized(&guard, "zc_valid"));
    try std.testing.expect(!isWebhookAuthorized(&guard, null));
    try std.testing.expect(!isWebhookAuthorized(&guard, "zc_invalid"));
}

test "formatPairSuccessResponse includes paired token" {
    var buf: [256]u8 = undefined;
    const response = formatPairSuccessResponse(&buf, "zc_token_123") orelse unreachable;
    try std.testing.expectEqualStrings(
        "{\"status\":\"paired\",\"token\":\"zc_token_123\"}",
        response,
    );
}

test "formatPairSuccessResponse fails when buffer is too small" {
    var buf: [8]u8 = undefined;
    try std.testing.expect(formatPairSuccessResponse(&buf, "zc_token_123") == null);
}

// ── extractHeader tests ──────────────────────────────────────────

test "extractHeader finds Authorization header" {
    const raw = "POST /webhook HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret123\r\nContent-Type: application/json\r\n\r\n";
    const val = extractHeader(raw, "Authorization");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("Bearer secret123", val.?);
}

test "extractHeader case insensitive" {
    const raw = "GET /health HTTP/1.1\r\ncontent-type: text/plain\r\n\r\n";
    const val = extractHeader(raw, "Content-Type");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("text/plain", val.?);
}

test "extractHeader returns null for missing header" {
    const raw = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const val = extractHeader(raw, "Authorization");
    try std.testing.expect(val == null);
}

test "extractHeader returns null for empty headers" {
    const raw = "GET / HTTP/1.1\r\n\r\n";
    try std.testing.expect(extractHeader(raw, "Host") == null);
}

// ── extractBearerToken tests ─────────────────────────────────────

test "extractBearerToken extracts token" {
    try std.testing.expectEqualStrings("mytoken", extractBearerToken("Bearer mytoken").?);
}

test "extractBearerToken returns null for non-Bearer" {
    try std.testing.expect(extractBearerToken("Basic abc123") == null);
}

test "extractBearerToken returns null for empty string" {
    try std.testing.expect(extractBearerToken("") == null);
}

test "extractBearerToken returns null for just Bearer" {
    // "Bearer " is 7 chars, "Bearer" is 6 — no space
    try std.testing.expect(extractBearerToken("Bearer") == null);
}

// ── JSON helper tests ────────────────────────────────────────────

test "jsonStringField extracts value" {
    const json = "{\"message\": \"hello world\"}";
    const val = jsonStringField(json, "message");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("hello world", val.?);
}

test "jsonStringField returns null for missing key" {
    const json = "{\"other\": \"value\"}";
    try std.testing.expect(jsonStringField(json, "message") == null);
}

test "jsonStringField handles nested JSON" {
    const json = "{\"message\": {\"text\": \"hi\"}, \"text\": \"direct\"}";
    const val = jsonStringField(json, "text");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("hi", val.?);
}

test "jsonIntField extracts positive integer" {
    const json = "{\"chat_id\": 12345}";
    const val = jsonIntField(json, "chat_id");
    try std.testing.expect(val != null);
    try std.testing.expectEqual(@as(i64, 12345), val.?);
}

test "jsonIntField extracts negative integer" {
    const json = "{\"offset\": -100}";
    const val = jsonIntField(json, "offset");
    try std.testing.expect(val != null);
    try std.testing.expectEqual(@as(i64, -100), val.?);
}

test "jsonIntField returns null for missing key" {
    const json = "{\"other\": 42}";
    try std.testing.expect(jsonIntField(json, "chat_id") == null);
}

test "jsonIntField returns null for string value" {
    const json = "{\"chat_id\": \"not a number\"}";
    try std.testing.expect(jsonIntField(json, "chat_id") == null);
}

test "selectWhatsAppConfig picks account by phone_number_id" {
    const wa_accounts = [_]config_types.WhatsAppConfig{
        .{
            .account_id = "main",
            .access_token = "tok-a",
            .phone_number_id = "111",
            .verify_token = "verify-a",
        },
        .{
            .account_id = "backup",
            .access_token = "tok-b",
            .phone_number_id = "222",
            .verify_token = "verify-b",
        },
    };
    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .whatsapp = &wa_accounts,
        },
    };
    const body = "{\"entry\":[{\"changes\":[{\"value\":{\"metadata\":{\"phone_number_id\":\"222\"}}}]}]}";
    const selected = selectWhatsAppConfig(&cfg, body, null);
    if (!build_options.enable_channel_whatsapp) {
        try std.testing.expect(selected == null);
        return;
    }
    try std.testing.expect(selected != null);
    try std.testing.expectEqualStrings("backup", selected.?.account_id);
}

test "selectTelegramConfig picks account by query account_id" {
    const tg_accounts = [_]config_types.TelegramConfig{
        .{
            .account_id = "main",
            .bot_token = "token-main",
            .allow_from = &.{"main-user"},
        },
        .{
            .account_id = "backup",
            .bot_token = "token-backup",
            .allow_from = &.{"backup-user"},
        },
    };
    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .telegram = &tg_accounts,
        },
    };

    const selected = selectTelegramConfig(&cfg, "/telegram?account_id=backup");
    if (!build_options.enable_channel_telegram) {
        try std.testing.expect(selected == null);
        return;
    }
    try std.testing.expect(selected != null);
    try std.testing.expectEqualStrings("backup", selected.?.account_id);
}

test "selectTelegramConfig falls back to preferred primary account" {
    const tg_accounts = [_]config_types.TelegramConfig{
        .{
            .account_id = "z-last",
            .bot_token = "token-z",
        },
        .{
            .account_id = "default",
            .bot_token = "token-default",
        },
    };
    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .telegram = &tg_accounts,
        },
    };

    const selected = selectTelegramConfig(&cfg, "/telegram");
    if (!build_options.enable_channel_telegram) {
        try std.testing.expect(selected == null);
        return;
    }
    try std.testing.expect(selected != null);
    try std.testing.expectEqualStrings("default", selected.?.account_id);
}

test "selectWhatsAppConfig picks account by verify_token" {
    const wa_accounts = [_]config_types.WhatsAppConfig{
        .{
            .account_id = "main",
            .access_token = "tok-a",
            .phone_number_id = "111",
            .verify_token = "verify-a",
        },
        .{
            .account_id = "backup",
            .access_token = "tok-b",
            .phone_number_id = "222",
            .verify_token = "verify-b",
        },
    };
    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .whatsapp = &wa_accounts,
        },
    };
    const selected = selectWhatsAppConfig(&cfg, null, "verify-b");
    if (!build_options.enable_channel_whatsapp) {
        try std.testing.expect(selected == null);
        return;
    }
    try std.testing.expect(selected != null);
    try std.testing.expectEqualStrings("backup", selected.?.account_id);
}

test "selectLineConfigBySignature matches account and rejects bad signature" {
    const body = "{\"events\":[]}";
    const line_accounts = [_]config_types.LineConfig{
        .{
            .account_id = "main",
            .access_token = "line-a",
            .channel_secret = "secret-a",
        },
        .{
            .account_id = "backup",
            .access_token = "line-b",
            .channel_secret = "secret-b",
        },
    };
    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .line = &line_accounts,
        },
    };

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, body, "secret-b");
    var sig_buf: [44]u8 = undefined;
    const signature = std.base64.standard.Encoder.encode(&sig_buf, &mac);

    const selected = selectLineConfigBySignature(&cfg, body, signature);
    if (!build_options.enable_channel_line) {
        try std.testing.expect(selected == null);
        try std.testing.expect(selectLineConfigBySignature(&cfg, body, "invalid-signature") == null);
        return;
    }
    try std.testing.expect(selected != null);
    try std.testing.expectEqualStrings("backup", selected.?.account_id);
    try std.testing.expect(selectLineConfigBySignature(&cfg, body, "invalid-signature") == null);
}

test "selectLarkConfig picks account by verification token" {
    const lark_accounts = [_]config_types.LarkConfig{
        .{
            .account_id = "main",
            .app_id = "app-a",
            .app_secret = "secret-a",
            .verification_token = "token-a",
        },
        .{
            .account_id = "backup",
            .app_id = "app-b",
            .app_secret = "secret-b",
            .verification_token = "token-b",
        },
    };
    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .lark = &lark_accounts,
        },
    };
    const body = "{\"header\":{\"token\":\"token-b\"}}";
    const selected = selectLarkConfig(&cfg, body);
    if (!build_options.enable_channel_lark) {
        try std.testing.expect(selected == null);
        return;
    }
    try std.testing.expect(selected != null);
    try std.testing.expectEqualStrings("backup", selected.?.account_id);
}

test "whatsappSessionKey builds direct key by sender" {
    const body = "{\"from\":\"15550001111\",\"text\":{\"body\":\"hi\"}}";
    var key_buf: [256]u8 = undefined;
    const key = whatsappSessionKey(&key_buf, body);
    try std.testing.expectEqualStrings("whatsapp:15550001111", key);
}

test "whatsappSessionKey builds group key when group id exists" {
    const body = "{\"from\":\"15550001111\",\"context\":{\"group_jid\":\"1203630@g.us\"},\"text\":{\"body\":\"hi\"}}";
    var key_buf: [256]u8 = undefined;
    const key = whatsappSessionKey(&key_buf, body);
    try std.testing.expectEqualStrings("whatsapp:group:1203630@g.us:15550001111", key);
}

test "telegramSenderAllowed permits when allow_from is empty" {
    const allocator = std.testing.allocator;
    const body =
        \\{"message":{"from":{"id":12345,"username":"alice"}}}
    ;
    try std.testing.expect(telegramSenderAllowed(allocator, &.{}, body));
}

test "telegramChatId extracts nested message.chat.id" {
    const allocator = std.testing.allocator;
    const body =
        \\{"update_id":1,"message":{"chat":{"id":-100777},"from":{"id":12345},"text":"hi"}}
    ;
    try std.testing.expectEqual(@as(i64, -100777), telegramChatId(allocator, body).?);
}

test "telegramChatId falls back to flat chat_id for backward compatibility" {
    const allocator = std.testing.allocator;
    const body = "{\"chat_id\":12345,\"text\":\"hi\"}";
    try std.testing.expectEqual(@as(i64, 12345), telegramChatId(allocator, body).?);
}

test "telegramSenderAllowed matches numeric sender id from nested from object" {
    const allocator = std.testing.allocator;
    const allow_from = [_][]const u8{"12345"};
    const body =
        \\{"message":{"from":{"id":12345},"chat":{"id":-100777}}}
    ;
    try std.testing.expect(telegramSenderAllowed(allocator, &allow_from, body));
}

test "telegramSenderAllowed does not confuse chat id with sender id" {
    const allocator = std.testing.allocator;
    const allow_from = [_][]const u8{"-100777"};
    const body =
        \\{"message":{"from":{"id":12345},"chat":{"id":-100777}}}
    ;
    try std.testing.expect(!telegramSenderAllowed(allocator, &allow_from, body));
}

test "telegramSenderAllowed rejects sender outside allowlist" {
    const allocator = std.testing.allocator;
    const allow_from = [_][]const u8{"alice"};
    const body =
        \\{"message":{"from":{"id":12345}}}
    ;
    try std.testing.expect(!telegramSenderAllowed(allocator, &allow_from, body));
}

test "telegramSenderIdentity falls back to numeric id when username is missing" {
    const allocator = std.testing.allocator;
    var sender_buf: [32]u8 = undefined;
    const body =
        \\{"message":{"from":{"id":12345},"chat":{"id":-100777}}}
    ;
    try std.testing.expectEqualStrings("12345", telegramSenderIdentity(allocator, body, &sender_buf));
}

test "whatsappSenderAllowed direct respects allow_from" {
    const allow_from = [_][]const u8{"+1111111111"};
    try std.testing.expect(whatsappSenderAllowed("+1111111111", false, null, &allow_from, &.{}, &.{}, "allowlist"));
    try std.testing.expect(!whatsappSenderAllowed("+2222222222", false, null, &allow_from, &.{}, &.{}, "allowlist"));
}

test "whatsappSenderAllowed direct denies all when allow_from is empty" {
    try std.testing.expect(!whatsappSenderAllowed("+1111111111", false, null, &.{}, &.{}, &.{}, "allowlist"));
}

test "whatsappSenderAllowed group open bypasses allow_from" {
    const allow_from = [_][]const u8{"+1111111111"};
    try std.testing.expect(whatsappSenderAllowed("+2222222222", true, "1203630@g.us", &allow_from, &.{}, &.{}, "open"));
}

test "whatsappSenderAllowed open policy still respects explicit groups allowlist" {
    const allow_from = [_][]const u8{"+1111111111"};
    const groups = [_][]const u8{"1203630@g.us"};
    try std.testing.expect(whatsappSenderAllowed("+2222222222", true, "1203630@g.us", &allow_from, &.{}, &groups, "open"));
    try std.testing.expect(!whatsappSenderAllowed("+2222222222", true, "1203631@g.us", &allow_from, &.{}, &groups, "open"));
}

test "whatsappSenderAllowed group allowlist uses groups and sender allowlists" {
    const allow_from = [_][]const u8{"+1111111111"};
    const group_allow = [_][]const u8{"+3333333333"};
    const groups = [_][]const u8{"1203630@g.us"};

    try std.testing.expect(whatsappSenderAllowed("+3333333333", true, "1203630@g.us", &allow_from, &group_allow, &groups, "allowlist"));
    try std.testing.expect(!whatsappSenderAllowed("+1111111111", true, "1203630@g.us", &allow_from, &group_allow, &groups, "allowlist"));

    try std.testing.expect(whatsappSenderAllowed("+1111111111", true, "1203630@g.us", &allow_from, &.{}, &groups, "allowlist"));
    try std.testing.expect(!whatsappSenderAllowed("+1111111111", true, "1203631@g.us", &allow_from, &.{}, &groups, "allowlist"));
    try std.testing.expect(!whatsappSenderAllowed("+9999999999", true, "1203630@g.us", &.{}, &.{}, &groups, "allowlist"));
    try std.testing.expect(!whatsappSenderAllowed("+1111111111", true, "1203630@g.us", &allow_from, &.{}, &.{}, "allowlist"));
}

test "whatsappSenderAllowed matches with and without plus prefix" {
    const allow_with_plus = [_][]const u8{"+15550001111"};
    const allow_without_plus = [_][]const u8{"15550001111"};

    try std.testing.expect(whatsappSenderAllowed("15550001111", false, null, &allow_with_plus, &.{}, &.{}, "allowlist"));
    try std.testing.expect(whatsappSenderAllowed("+15550001111", false, null, &allow_without_plus, &.{}, &.{}, "allowlist"));
}

test "whatsappSessionKeyRouted falls back without config" {
    const allocator = std.testing.allocator;
    const body = "{\"from\":\"15550001111\",\"text\":{\"body\":\"hi\"}}";
    var key_buf: [256]u8 = undefined;
    const key = whatsappSessionKeyRouted(allocator, &key_buf, body, null, "default");
    try std.testing.expectEqualStrings("whatsapp:15550001111", key);
}

test "whatsappSessionKeyRouted uses route engine when config exists" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const body = "{\"from\":\"15550001111\",\"group_jid\":\"1203630@g.us\",\"text\":{\"body\":\"hi\"}}";
    var key_buf: [256]u8 = undefined;

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &[_]agent_routing.AgentBinding{
            .{
                .agent_id = "wa-agent",
                .match = .{
                    .channel = "whatsapp",
                    .account_id = "wa-prod",
                    .peer = .{ .kind = .group, .id = "1203630@g.us" },
                },
            },
        },
    };

    const key = whatsappSessionKeyRouted(allocator, &key_buf, body, &cfg, "wa-prod");
    try std.testing.expectEqualStrings("agent:wa-agent:whatsapp:group:1203630@g.us", key);
}

test "whatsappSessionKeyRouted uses nested context.group_jid for group routing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const body = "{\"from\":\"15550001111\",\"context\":{\"group_jid\":\"1203631@g.us\"},\"text\":{\"body\":\"hi\"}}";
    var key_buf: [256]u8 = undefined;

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &[_]agent_routing.AgentBinding{
            .{
                .agent_id = "wa-context-agent",
                .match = .{
                    .channel = "whatsapp",
                    .account_id = "wa-main",
                    .peer = .{ .kind = .group, .id = "1203631@g.us" },
                },
            },
        },
    };

    const key = whatsappSessionKeyRouted(allocator, &key_buf, body, &cfg, "wa-main");
    try std.testing.expectEqualStrings("agent:wa-context-agent:whatsapp:group:1203631@g.us", key);
}

test "telegramSessionKeyRouted uses group peer for group chats" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const body =
        \\{"message":{"chat":{"id":-10012345,"type":"supergroup"}}}
    ;
    var key_buf: [128]u8 = undefined;

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &[_]agent_routing.AgentBinding{
            .{
                .agent_id = "tg-group-agent",
                .match = .{
                    .channel = "telegram",
                    .account_id = "tg-main",
                    .peer = .{ .kind = .group, .id = "-10012345" },
                },
            },
        },
    };

    const key = telegramSessionKeyRouted(allocator, &key_buf, -10012345, body, &cfg, "tg-main");
    try std.testing.expectEqualStrings("agent:tg-group-agent:telegram:group:-10012345", key);
}

test "telegramSessionKeyRouted uses direct peer for private chats" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const body =
        \\{"message":{"chat":{"id":4242,"type":"private"}}}
    ;
    var key_buf: [128]u8 = undefined;

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &[_]agent_routing.AgentBinding{
            .{
                .agent_id = "tg-dm-agent",
                .match = .{
                    .channel = "telegram",
                    .account_id = "tg-main",
                    .peer = .{ .kind = .direct, .id = "4242" },
                },
            },
        },
    };

    const key = telegramSessionKeyRouted(allocator, &key_buf, 4242, body, &cfg, "tg-main");
    try std.testing.expectEqualStrings("agent:tg-dm-agent:telegram:direct:4242", key);
}

test "telegramSessionKeyRouted applies session dm_scope for direct chats" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const body =
        \\{"message":{"chat":{"id":4242,"type":"private"}}}
    ;
    var key_buf: [128]u8 = undefined;

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &[_]agent_routing.AgentBinding{
            .{
                .agent_id = "tg-dm-agent",
                .match = .{
                    .channel = "telegram",
                    .account_id = "tg-main",
                    .peer = .{ .kind = .direct, .id = "4242" },
                },
            },
        },
        .session = .{
            .dm_scope = .per_peer,
        },
    };

    const key = telegramSessionKeyRouted(allocator, &key_buf, 4242, body, &cfg, "tg-main");
    try std.testing.expectEqualStrings("agent:tg-dm-agent:direct:4242", key);
}

test "lineSessionKeyRouted uses group id for group events" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key_buf: [128]u8 = undefined;
    const evt = channels.line.LineEvent{
        .event_type = "message",
        .user_id = "U111",
        .group_id = "G222",
        .source_type = "group",
    };

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &[_]agent_routing.AgentBinding{
            .{
                .agent_id = "line-group-agent",
                .match = .{
                    .channel = "line",
                    .account_id = "line-main",
                    .peer = .{ .kind = .group, .id = "group:G222" },
                },
            },
        },
    };

    const key = lineSessionKeyRouted(allocator, &key_buf, evt, &cfg, "line-main");
    try std.testing.expectEqualStrings("agent:line-group-agent:line:group:group:G222", key);
}

test "lineSessionKeyRouted falls back to user session key without config" {
    const allocator = std.testing.allocator;
    var key_buf: [128]u8 = undefined;
    const evt = channels.line.LineEvent{
        .event_type = "message",
        .user_id = "U777",
    };

    const key = lineSessionKeyRouted(allocator, &key_buf, evt, null, "default");
    try std.testing.expectEqualStrings("line:U777", key);
}

test "lineSessionKeyRouted uses room-prefixed peer id for room events" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key_buf: [128]u8 = undefined;
    const evt = channels.line.LineEvent{
        .event_type = "message",
        .user_id = "U111",
        .room_id = "R333",
        .source_type = "room",
    };

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &[_]agent_routing.AgentBinding{
            .{
                .agent_id = "line-room-agent",
                .match = .{
                    .channel = "line",
                    .account_id = "line-main",
                    .peer = .{ .kind = .group, .id = "room:R333" },
                },
            },
        },
    };

    const key = lineSessionKeyRouted(allocator, &key_buf, evt, &cfg, "line-main");
    try std.testing.expectEqualStrings("agent:line-room-agent:line:group:room:R333", key);
}

test "lineReplyTarget resolves conversation target for group events" {
    const evt = channels.line.LineEvent{
        .event_type = "message",
        .user_id = "U111",
        .group_id = "G222",
        .source_type = "group",
    };
    try std.testing.expectEqualStrings("G222", lineReplyTarget(evt));
}

test "lineReplyTarget resolves conversation target for room events" {
    const evt = channels.line.LineEvent{
        .event_type = "message",
        .user_id = "U111",
        .room_id = "R333",
        .source_type = "room",
    };
    try std.testing.expectEqualStrings("R333", lineReplyTarget(evt));
}

test "lineReplyTarget falls back to user for direct events" {
    const evt = channels.line.LineEvent{
        .event_type = "message",
        .user_id = "U111",
        .source_type = "user",
    };
    try std.testing.expectEqualStrings("U111", lineReplyTarget(evt));
}

test "larkSessionKeyRouted uses route engine when config exists" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var key_buf: [128]u8 = undefined;
    const msg = channels.lark.ParsedLarkMessage{
        .sender = "ou_abc123",
        .content = "hello",
        .timestamp = 123,
        .is_group = true,
    };

    var cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &[_]agent_routing.AgentBinding{
            .{
                .agent_id = "lark-group-agent",
                .match = .{
                    .channel = "lark",
                    .account_id = "lark-main",
                    .peer = .{ .kind = .group, .id = "ou_abc123" },
                },
            },
        },
    };

    const key = larkSessionKeyRouted(allocator, &key_buf, msg, &cfg, "lark-main");
    try std.testing.expectEqualStrings("agent:lark-group-agent:lark:group:ou_abc123", key);
}

// ── extractBody tests ────────────────────────────────────────────

test "extractBody finds body after headers" {
    const raw = "POST /webhook HTTP/1.1\r\nHost: localhost\r\n\r\n{\"message\":\"hi\"}";
    const body = extractBody(raw);
    try std.testing.expect(body != null);
    try std.testing.expectEqualStrings("{\"message\":\"hi\"}", body.?);
}

test "extractBody returns null for no body" {
    const raw = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    try std.testing.expect(extractBody(raw) == null);
}

test "extractBody returns null for no separator" {
    const raw = "GET /health HTTP/1.1\r\nHost: localhost\r\n";
    try std.testing.expect(extractBody(raw) == null);
}

test "userFacingAgentError maps ProviderDoesNotSupportVision" {
    try std.testing.expectEqualStrings(
        "The current provider does not support image input.",
        userFacingAgentError(error.ProviderDoesNotSupportVision),
    );
}

test "userFacingAgentError maps NoResponseContent" {
    try std.testing.expectEqualStrings(
        "Model returned an empty response. Please try again.",
        userFacingAgentError(error.NoResponseContent),
    );
}

test "userFacingAgentError maps AllProvidersFailed" {
    try std.testing.expectEqualStrings(
        "All configured providers failed for this request. Check model/provider compatibility and credentials.",
        userFacingAgentError(error.AllProvidersFailed),
    );
}

test "userFacingAgentError maps generic error fallback" {
    try std.testing.expectEqualStrings(
        "An error occurred. Try again.",
        userFacingAgentError(error.Unexpected),
    );
}

test "userFacingAgentErrorJson maps NoResponseContent" {
    try std.testing.expectEqualStrings(
        "{\"error\":\"model returned empty response\"}",
        userFacingAgentErrorJson(error.NoResponseContent),
    );
}

test "userFacingAgentErrorJson maps AllProvidersFailed" {
    try std.testing.expectEqualStrings(
        "{\"error\":\"all providers failed for this request\"}",
        userFacingAgentErrorJson(error.AllProvidersFailed),
    );
}

test "userFacingAgentErrorJson maps generic error fallback" {
    try std.testing.expectEqualStrings(
        "{\"error\":\"agent failure\"}",
        userFacingAgentErrorJson(error.Unexpected),
    );
}

test "GatewayState init has empty telegram_bot_token" {
    var state = GatewayState.init(std.testing.allocator);
    defer state.deinit();
    try std.testing.expectEqualStrings("", state.telegram_bot_token);
}

// ── asciiEqlIgnoreCase tests ─────────────────────────────────────

test "asciiEqlIgnoreCase equal strings" {
    try std.testing.expect(asciiEqlIgnoreCase("Authorization", "authorization"));
    try std.testing.expect(asciiEqlIgnoreCase("CONTENT-TYPE", "content-type"));
    try std.testing.expect(asciiEqlIgnoreCase("Host", "Host"));
}

test "asciiEqlIgnoreCase different strings" {
    try std.testing.expect(!asciiEqlIgnoreCase("Authorization", "authenticate"));
    try std.testing.expect(!asciiEqlIgnoreCase("a", "ab"));
}

test "asciiEqlIgnoreCase empty strings" {
    try std.testing.expect(asciiEqlIgnoreCase("", ""));
}

// ── WhatsApp HMAC-SHA256 Signature Verification tests ───────────

test "verifyWhatsappSignature valid signature" {
    // Compute a real HMAC-SHA256 and verify it passes
    const body = "{\"entry\":[{\"changes\":[{\"value\":{\"messages\":[{\"text\":{\"body\":\"hello\"}}]}}]}]}";
    const secret = "my_app_secret";
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, body, secret);
    // Format as hex
    var hex_buf: [64]u8 = undefined;
    for (0..32) |i| {
        const byte = mac[i];
        hex_buf[i * 2] = "0123456789abcdef"[byte >> 4];
        hex_buf[i * 2 + 1] = "0123456789abcdef"[byte & 0x0f];
    }
    var header_buf: [71]u8 = undefined; // "sha256=" (7) + 64 hex chars
    @memcpy(header_buf[0..7], "sha256=");
    @memcpy(header_buf[7..71], &hex_buf);
    try std.testing.expect(verifyWhatsappSignature(body, &header_buf, secret));
}

test "verifyWhatsappSignature invalid signature rejected" {
    const body = "{\"message\":\"test\"}";
    const secret = "correct_secret";
    // Provide a well-formed but wrong signature (all zeros)
    const bad_sig = "sha256=0000000000000000000000000000000000000000000000000000000000000000";
    try std.testing.expect(!verifyWhatsappSignature(body, bad_sig, secret));
}

test "verifyWhatsappSignature missing sha256= prefix rejected" {
    const body = "test body";
    const secret = "secret";
    const no_prefix = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    try std.testing.expect(!verifyWhatsappSignature(body, no_prefix, secret));
}

test "verifyWhatsappSignature empty body with valid signature" {
    const body = "";
    const secret = "empty_body_secret";
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, body, secret);
    var hex_buf: [64]u8 = undefined;
    for (0..32) |i| {
        const byte = mac[i];
        hex_buf[i * 2] = "0123456789abcdef"[byte >> 4];
        hex_buf[i * 2 + 1] = "0123456789abcdef"[byte & 0x0f];
    }
    var header_buf: [71]u8 = undefined;
    @memcpy(header_buf[0..7], "sha256=");
    @memcpy(header_buf[7..71], &hex_buf);
    try std.testing.expect(verifyWhatsappSignature(body, &header_buf, secret));
}

test "verifyWhatsappSignature empty secret returns false" {
    const body = "any body";
    const sig = "sha256=0000000000000000000000000000000000000000000000000000000000000000";
    try std.testing.expect(!verifyWhatsappSignature(body, sig, ""));
}

test "verifyWhatsappSignature wrong secret rejected" {
    const body = "{\"data\":\"payload\"}";
    const correct_secret = "real_secret";
    const wrong_secret = "wrong_secret";
    // Compute signature with correct secret
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, body, correct_secret);
    var hex_buf: [64]u8 = undefined;
    for (0..32) |i| {
        const byte = mac[i];
        hex_buf[i * 2] = "0123456789abcdef"[byte >> 4];
        hex_buf[i * 2 + 1] = "0123456789abcdef"[byte & 0x0f];
    }
    var header_buf: [71]u8 = undefined;
    @memcpy(header_buf[0..7], "sha256=");
    @memcpy(header_buf[7..71], &hex_buf);
    // Verify with wrong secret — should fail
    try std.testing.expect(!verifyWhatsappSignature(body, &header_buf, wrong_secret));
}

test "verifyWhatsappSignature constant-time comparison basic check" {
    // Verify that two identical MACs pass and two differing-by-one-bit MACs fail.
    // This doesn't prove constant-time, but ensures the comparison logic is correct.
    const body = "timing test body";
    const secret = "timing_secret";
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, body, secret);

    // constantTimeEql with itself
    try std.testing.expect(constantTimeEql(&mac, &mac));

    // Flip one bit in the last byte
    var altered = mac;
    altered[31] ^= 0x01;
    try std.testing.expect(!constantTimeEql(&mac, &altered));

    // Flip one bit in the first byte
    var altered2 = mac;
    altered2[0] ^= 0x80;
    try std.testing.expect(!constantTimeEql(&mac, &altered2));
}

test "verifyWhatsappSignature hex encoding edge cases" {
    // Truncated hex (too short)
    try std.testing.expect(!verifyWhatsappSignature("body", "sha256=abcdef", "secret"));
    // Too long hex
    try std.testing.expect(!verifyWhatsappSignature("body", "sha256=00000000000000000000000000000000000000000000000000000000000000001", "secret"));
    // Invalid hex characters
    try std.testing.expect(!verifyWhatsappSignature("body", "sha256=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "secret"));
    // Empty signature header
    try std.testing.expect(!verifyWhatsappSignature("body", "", "secret"));
    // Just the prefix, no hex
    try std.testing.expect(!verifyWhatsappSignature("body", "sha256=", "secret"));
}

test "verifyWhatsappSignature uppercase hex accepted" {
    // Meta typically sends lowercase, but we accept uppercase too
    const body = "uppercase hex test";
    const secret = "hex_secret";
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, body, secret);
    var hex_buf: [64]u8 = undefined;
    for (0..32) |i| {
        const byte = mac[i];
        hex_buf[i * 2] = "0123456789ABCDEF"[byte >> 4];
        hex_buf[i * 2 + 1] = "0123456789ABCDEF"[byte & 0x0f];
    }
    var header_buf: [71]u8 = undefined;
    @memcpy(header_buf[0..7], "sha256=");
    @memcpy(header_buf[7..71], &hex_buf);
    try std.testing.expect(verifyWhatsappSignature(body, &header_buf, secret));
}

test "verifySlackSignature accepts valid signature" {
    const body = "{\"type\":\"event_callback\"}";
    const secret = "slack_signing_secret";

    var ts_buf: [32]u8 = undefined;
    const ts = std.fmt.bufPrint(&ts_buf, "{d}", .{std.time.timestamp()}) catch unreachable;

    var signed: std.ArrayListUnmanaged(u8) = .empty;
    defer signed.deinit(std.testing.allocator);
    const sw = signed.writer(std.testing.allocator);
    try sw.print("v0:{s}:", .{ts});
    try sw.writeAll(body);

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, signed.items, secret);

    var sig_buf: [67]u8 = undefined; // "v0=" + 64 hex
    @memcpy(sig_buf[0..3], "v0=");
    for (0..32) |i| {
        const byte = mac[i];
        sig_buf[3 + i * 2] = "0123456789abcdef"[byte >> 4];
        sig_buf[3 + i * 2 + 1] = "0123456789abcdef"[byte & 0x0f];
    }

    try std.testing.expect(verifySlackSignature(std.testing.allocator, body, ts, &sig_buf, secret));
}

test "verifySlackSignature rejects stale timestamp" {
    const body = "{\"type\":\"event_callback\"}";
    const secret = "slack_signing_secret";

    var ts_buf: [32]u8 = undefined;
    const ts = std.fmt.bufPrint(&ts_buf, "{d}", .{std.time.timestamp() - 900}) catch unreachable;

    var signed: std.ArrayListUnmanaged(u8) = .empty;
    defer signed.deinit(std.testing.allocator);
    const sw = signed.writer(std.testing.allocator);
    try sw.print("v0:{s}:", .{ts});
    try sw.writeAll(body);

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, signed.items, secret);

    var sig_buf: [67]u8 = undefined;
    @memcpy(sig_buf[0..3], "v0=");
    for (0..32) |i| {
        const byte = mac[i];
        sig_buf[3 + i * 2] = "0123456789abcdef"[byte >> 4];
        sig_buf[3 + i * 2 + 1] = "0123456789abcdef"[byte & 0x0f];
    }

    try std.testing.expect(!verifySlackSignature(std.testing.allocator, body, ts, &sig_buf, secret));
}

test "hasSlackHttpEndpoint respects mode and webhook_path" {
    const slack_accounts = [_]config_types.SlackConfig{
        .{
            .account_id = "sl-http",
            .mode = .http,
            .bot_token = "xoxb-http",
            .signing_secret = "sec-http",
            .webhook_path = "/slack/custom",
        },
        .{
            .account_id = "sl-socket",
            .mode = .socket,
            .bot_token = "xoxb-socket",
            .app_token = "xapp-socket",
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .slack = &slack_accounts,
        },
    };

    if (!build_options.enable_channel_slack) {
        try std.testing.expect(!hasSlackHttpEndpoint(&cfg, "/slack/custom"));
        try std.testing.expect(!hasSlackHttpEndpoint(&cfg, "/slack/events"));
        try std.testing.expect(!hasSlackHttpEndpoint(&cfg, "/line"));
        return;
    }

    try std.testing.expect(hasSlackHttpEndpoint(&cfg, "/slack/custom"));
    try std.testing.expect(!hasSlackHttpEndpoint(&cfg, "/slack/events"));
    try std.testing.expect(!hasSlackHttpEndpoint(&cfg, "/line"));
}

test "findSlackConfigForRequest selects account by verified signature" {
    const body = "{\"type\":\"event_callback\",\"event\":{\"type\":\"message\",\"channel\":\"C1\",\"user\":\"U1\",\"text\":\"hi\"}}";
    const ts_val = std.time.timestamp();
    var ts_buf: [32]u8 = undefined;
    const ts = std.fmt.bufPrint(&ts_buf, "{d}", .{ts_val}) catch unreachable;

    const secret_a = "slack_secret_a";
    const secret_b = "slack_secret_b";

    var signed: std.ArrayListUnmanaged(u8) = .empty;
    defer signed.deinit(std.testing.allocator);
    const sw = signed.writer(std.testing.allocator);
    try sw.print("v0:{s}:", .{ts});
    try sw.writeAll(body);

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac_b: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac_b, signed.items, secret_b);

    var sig_buf: [67]u8 = undefined;
    @memcpy(sig_buf[0..3], "v0=");
    for (0..32) |i| {
        const byte = mac_b[i];
        sig_buf[3 + i * 2] = "0123456789abcdef"[byte >> 4];
        sig_buf[3 + i * 2 + 1] = "0123456789abcdef"[byte & 0x0f];
    }

    const slack_accounts = [_]config_types.SlackConfig{
        .{
            .account_id = "a",
            .mode = .http,
            .bot_token = "xoxb-a",
            .signing_secret = secret_a,
            .webhook_path = "/slack/events",
        },
        .{
            .account_id = "b",
            .mode = .http,
            .bot_token = "xoxb-b",
            .signing_secret = secret_b,
            .webhook_path = "/slack/events",
        },
    };
    const cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .slack = &slack_accounts,
        },
    };

    const selected = findSlackConfigForRequest(std.testing.allocator, &cfg, "/slack/events", body, ts, &sig_buf);
    if (!build_options.enable_channel_slack) {
        try std.testing.expect(selected == null);
        return;
    }
    try std.testing.expect(selected != null);
    try std.testing.expectEqualStrings("b", selected.?.account_id);
}

test "GatewayState init has empty whatsapp_app_secret" {
    var state = GatewayState.init(std.testing.allocator);
    defer state.deinit();
    try std.testing.expectEqualStrings("", state.whatsapp_app_secret);
}

// ── /ready endpoint tests ────────────────────────────────────────────

test "handleReady all components healthy returns 200" {
    health.reset();
    health.markComponentOk("gateway");
    health.markComponentOk("database");
    const resp = handleReady(std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(@constCast(resp.body));
    try std.testing.expectEqualStrings("200 OK", resp.http_status);
    // Verify JSON contains "ready" status
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"status\":\"ready\"") != null);
}

test "handleReady one component unhealthy returns 503" {
    health.reset();
    health.markComponentOk("gateway");
    health.markComponentError("database", "connection refused");
    const resp = handleReady(std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(@constCast(resp.body));
    try std.testing.expectEqualStrings("503 Service Unavailable", resp.http_status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"status\":\"not_ready\"") != null);
}

test "handleReady no components returns 200 vacuously" {
    health.reset();
    const resp = handleReady(std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(@constCast(resp.body));
    try std.testing.expectEqualStrings("200 OK", resp.http_status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"status\":\"ready\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"checks\":[]") != null);
}

test "handleReady JSON output has checks array" {
    health.reset();
    health.markComponentOk("agent");
    const resp = handleReady(std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(@constCast(resp.body));
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"checks\":[") != null);
    // Should contain the agent component
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"name\":\"agent\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"healthy\":true") != null);
}

test "handleReady multiple unhealthy components returns 503" {
    health.reset();
    health.markComponentError("gateway", "port in use");
    health.markComponentError("database", "disk full");
    const resp = handleReady(std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(@constCast(resp.body));
    try std.testing.expectEqualStrings("503 Service Unavailable", resp.http_status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"status\":\"not_ready\"") != null);
}

test "handleReady response body is valid JSON structure" {
    health.reset();
    health.markComponentOk("test-svc");
    const resp = handleReady(std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(@constCast(resp.body));
    // Must start with { and end with }
    try std.testing.expect(resp.body.len > 0);
    try std.testing.expectEqual(@as(u8, '{'), resp.body[0]);
    try std.testing.expectEqual(@as(u8, '}'), resp.body[resp.body.len - 1]);
}

test "handleReady unhealthy component includes error message" {
    health.reset();
    health.markComponentError("cache", "redis timeout");
    const resp = handleReady(std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(@constCast(resp.body));
    try std.testing.expectEqualStrings("503 Service Unavailable", resp.http_status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"message\":\"redis timeout\"") != null);
}

test "handleReady recovered component shows healthy" {
    health.reset();
    health.markComponentError("db", "down");
    health.markComponentOk("db");
    const resp = handleReady(std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(@constCast(resp.body));
    try std.testing.expectEqualStrings("200 OK", resp.http_status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"healthy\":true") != null);
}

test "publishToBus creates inbound message on bus" {
    const alloc = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    const ok = publishToBus(&eb, alloc, "telegram", "user1", "chat42", "hello", "telegram:chat42", null);
    try std.testing.expect(ok);

    // Consume the message
    const msg = eb.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("telegram", msg.channel);
    try std.testing.expectEqualStrings("user1", msg.sender_id);
    try std.testing.expectEqualStrings("chat42", msg.chat_id);
    try std.testing.expectEqualStrings("hello", msg.content);
    try std.testing.expectEqualStrings("telegram:chat42", msg.session_key);
}

test "publishToBus with metadata" {
    const alloc = std.testing.allocator;
    var eb = bus_mod.Bus.init();
    defer eb.close();

    const meta = "{\"account_id\":\"personal\"}";
    const ok = publishToBus(&eb, alloc, "whatsapp", "sender", "chat1", "hi", "wa:chat1", meta);
    try std.testing.expect(ok);

    const msg = eb.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("whatsapp", msg.channel);
    try std.testing.expectEqualStrings("hi", msg.content);
    try std.testing.expect(msg.metadata_json != null);
    try std.testing.expectEqualStrings("{\"account_id\":\"personal\"}", msg.metadata_json.?);
}

test "GatewayState event_bus defaults to null" {
    var gs = GatewayState.init(std.testing.allocator);
    defer gs.deinit();
    try std.testing.expect(gs.event_bus == null);
}

// ── jsonEscapeInto tests ────────────────────────────────────────

fn escapeToString(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    try jsonEscapeInto(w, input);
    return buf.toOwnedSlice(allocator);
}

test "jsonEscapeInto escapes double quotes" {
    const result = try escapeToString(std.testing.allocator, "hello \"world\"");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("hello \\\"world\\\"", result);
}

test "jsonEscapeInto escapes backslashes" {
    const result = try escapeToString(std.testing.allocator, "path\\to\\file");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("path\\\\to\\\\file", result);
}

test "jsonEscapeInto escapes newlines and tabs" {
    const result = try escapeToString(std.testing.allocator, "line1\nline2\ttab");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("line1\\nline2\\ttab", result);
}

test "jsonEscapeInto escapes control chars as unicode" {
    // 0x00, 0x01, 0x1F
    const result = try escapeToString(std.testing.allocator, &[_]u8{ 0x00, 0x01, 0x1F });
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("\\u0000\\u0001\\u001f", result);
}

test "jsonEscapeInto empty string yields empty output" {
    const result = try escapeToString(std.testing.allocator, "");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "jsonEscapeInto passes through unicode and emoji unchanged" {
    const result = try escapeToString(std.testing.allocator, "hello \xc3\xa9\xf0\x9f\x98\x80 world");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("hello \xc3\xa9\xf0\x9f\x98\x80 world", result);
}

test "jsonEscapeInto escapes carriage return" {
    const result = try escapeToString(std.testing.allocator, "hello\r\nworld");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("hello\\r\\nworld", result);
}

test "jsonEscapeInto escapes backspace and form feed" {
    const result = try escapeToString(std.testing.allocator, "a\x08b\x0Cc");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("a\\bb\\fc", result);
}

test "jsonEscapeInto mixed special characters" {
    const result = try escapeToString(std.testing.allocator, "He said \"hi\\there\"\nnew line");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("He said \\\"hi\\\\there\\\"\\nnew line", result);
}

// ── jsonWrapField tests ─────────────────────────────────────────

test "jsonWrapField produces valid JSON string field" {
    const result = try jsonWrapField(std.testing.allocator, "msg", "hello \"world\"");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("\"msg\":\"hello \\\"world\\\"\"", result);
}

test "jsonWrapField with empty value" {
    const result = try jsonWrapField(std.testing.allocator, "key", "");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("\"key\":\"\"", result);
}

test "jsonWrapField result is valid JSON when wrapped in braces" {
    const field = try jsonWrapField(std.testing.allocator, "response", "test\nvalue");
    defer std.testing.allocator.free(field);
    // Wrap in object: {"response":"test\nvalue"}
    const json = try std.fmt.allocPrint(std.testing.allocator, "{{{s}}}", .{field});
    defer std.testing.allocator.free(json);
    // Parse to verify it's valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
    const val = parsed.value.object.get("response") orelse unreachable;
    try std.testing.expect(val == .string);
    try std.testing.expectEqualStrings("test\nvalue", val.string);
}

// ── jsonWrapResponse tests ──────────────────────────────────────

test "jsonWrapResponse produces valid JSON with escaped content" {
    const result = try jsonWrapResponse(std.testing.allocator, "Hello \"user\"\nLine 2");
    defer std.testing.allocator.free(result);
    // Verify it's valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, result, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
    const status = parsed.value.object.get("status") orelse unreachable;
    try std.testing.expectEqualStrings("ok", status.string);
    const response = parsed.value.object.get("response") orelse unreachable;
    try std.testing.expectEqualStrings("Hello \"user\"\nLine 2", response.string);
}

test "jsonWrapResponse with clean input" {
    const result = try jsonWrapResponse(std.testing.allocator, "simple reply");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("{\"status\":\"ok\",\"response\":\"simple reply\"}", result);
}

// ── jsonWrapChallenge tests ─────────────────────────────────────

test "jsonWrapChallenge produces valid JSON" {
    const result = try jsonWrapChallenge(std.testing.allocator, "abc123");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("{\"challenge\":\"abc123\"}", result);
}

test "jsonWrapChallenge escapes malicious challenge value" {
    const result = try jsonWrapChallenge(std.testing.allocator, "abc\",\"evil\":\"true");
    defer std.testing.allocator.free(result);
    // Must be valid JSON with the value properly escaped
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, result, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
    const challenge = parsed.value.object.get("challenge") orelse unreachable;
    try std.testing.expectEqualStrings("abc\",\"evil\":\"true", challenge.string);
    // Must NOT have an "evil" key (injection prevented)
    try std.testing.expect(parsed.value.object.get("evil") == null);
}
