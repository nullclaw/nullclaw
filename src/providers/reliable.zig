const std = @import("std");
const root = @import("root.zig");

const Provider = root.Provider;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;

/// Check if an error message indicates a non-retryable client error (4xx except 429/408).
pub fn isNonRetryable(err_msg: []const u8) bool {
    // Look for 4xx status codes
    var i: usize = 0;
    while (i < err_msg.len) {
        // Find a digit sequence
        if (std.ascii.isDigit(err_msg[i])) {
            var end = i;
            while (end < err_msg.len and std.ascii.isDigit(err_msg[end])) {
                end += 1;
            }
            if (end - i == 3) {
                const code = std.fmt.parseInt(u16, err_msg[i..end], 10) catch {
                    i = end;
                    continue;
                };
                if (code >= 400 and code < 500) {
                    return code != 429 and code != 408;
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
    return false;
}

/// Check if an error message indicates a rate-limit (429) error.
pub fn isRateLimited(err_msg: []const u8) bool {
    return std.mem.indexOf(u8, err_msg, "429") != null and
        (std.mem.indexOf(u8, err_msg, "Too Many") != null or
            std.mem.indexOf(u8, err_msg, "rate") != null or
            std.mem.indexOf(u8, err_msg, "limit") != null);
}

/// Try to extract a Retry-After value (in milliseconds) from an error message.
pub fn parseRetryAfterMs(err_msg: []const u8) ?u64 {
    const prefixes = [_][]const u8{
        "retry-after:",
        "retry_after:",
        "retry-after ",
        "retry_after ",
    };

    // Case-insensitive search
    var lower_buf: [4096]u8 = undefined;
    const check_len = @min(err_msg.len, lower_buf.len);
    for (err_msg[0..check_len], 0..) |c, idx| {
        lower_buf[idx] = std.ascii.toLower(c);
    }
    const lower = lower_buf[0..check_len];

    for (prefixes) |prefix| {
        if (std.mem.indexOf(u8, lower, prefix)) |pos| {
            const after_start = pos + prefix.len;
            if (after_start >= check_len) continue;

            // Skip whitespace
            var start = after_start;
            while (start < check_len and (err_msg[start] == ' ' or err_msg[start] == '\t')) {
                start += 1;
            }

            // Parse number
            var end = start;
            var has_dot = false;
            while (end < check_len) {
                if (std.ascii.isDigit(err_msg[end])) {
                    end += 1;
                } else if (err_msg[end] == '.' and !has_dot) {
                    has_dot = true;
                    end += 1;
                } else {
                    break;
                }
            }

            if (end > start) {
                const num_str = err_msg[start..end];
                if (std.fmt.parseFloat(f64, num_str)) |secs| {
                    if (std.math.isFinite(secs) and secs >= 0.0) {
                        const millis = @as(u64, @intFromFloat(secs * 1000.0));
                        return millis;
                    }
                } else |_| {}
            }
        }
    }

    return null;
}

/// Provider wrapper with retry and provider fallback behavior.
///
/// Wraps multiple providers and tries them in order. For each provider,
/// retries with exponential backoff on transient errors. Skips retries
/// for non-retryable client errors (4xx except 429/408).
pub const ReliableProvider = struct {
    /// List of (name, provider) pairs. First is primary.
    provider_names: []const []const u8,
    max_retries: u32,
    base_backoff_ms: u64,
    /// Extra API keys for rotation on rate-limit errors.
    api_keys: []const []const u8,
    key_index: usize,

    pub fn init(
        provider_names: []const []const u8,
        max_retries: u32,
        base_backoff_ms: u64,
    ) ReliableProvider {
        return .{
            .provider_names = provider_names,
            .max_retries = max_retries,
            .base_backoff_ms = @max(base_backoff_ms, 50),
            .api_keys = &.{},
            .key_index = 0,
        };
    }

    pub fn withApiKeys(self: *ReliableProvider, keys: []const []const u8) *ReliableProvider {
        self.api_keys = keys;
        return self;
    }

    /// Advance to the next API key (round-robin) and return it.
    pub fn rotateKey(self: *ReliableProvider) ?[]const u8 {
        if (self.api_keys.len == 0) return null;
        const idx = self.key_index % self.api_keys.len;
        self.key_index += 1;
        return self.api_keys[idx];
    }

    /// Compute backoff duration, respecting Retry-After if present.
    pub fn computeBackoff(_: ReliableProvider, base: u64, err_msg: []const u8) u64 {
        if (parseRetryAfterMs(err_msg)) |retry_after| {
            // Cap at 30s
            return @max(@min(retry_after, 30_000), base);
        }
        return base;
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "isNonRetryable detects common patterns" {
    try std.testing.expect(isNonRetryable("400 Bad Request"));
    try std.testing.expect(isNonRetryable("401 Unauthorized"));
    try std.testing.expect(isNonRetryable("403 Forbidden"));
    try std.testing.expect(isNonRetryable("404 Not Found"));
    try std.testing.expect(!isNonRetryable("429 Too Many Requests"));
    try std.testing.expect(!isNonRetryable("408 Request Timeout"));
    try std.testing.expect(!isNonRetryable("500 Internal Server Error"));
    try std.testing.expect(!isNonRetryable("502 Bad Gateway"));
    try std.testing.expect(!isNonRetryable("timeout"));
    try std.testing.expect(!isNonRetryable("connection reset"));
}

test "isRateLimited detection" {
    try std.testing.expect(isRateLimited("429 Too Many Requests"));
    try std.testing.expect(isRateLimited("HTTP 429 rate limit exceeded"));
    try std.testing.expect(!isRateLimited("401 Unauthorized"));
    try std.testing.expect(!isRateLimited("500 Internal Server Error"));
}

test "parseRetryAfterMs integer" {
    try std.testing.expect(parseRetryAfterMs("429 Too Many Requests, Retry-After: 5").? == 5000);
}

test "parseRetryAfterMs float" {
    try std.testing.expect(parseRetryAfterMs("Rate limited. retry_after: 2.5 seconds").? == 2500);
}

test "parseRetryAfterMs missing" {
    try std.testing.expect(parseRetryAfterMs("500 Internal Server Error") == null);
}

test "ReliableProvider computeBackoff uses retry-after" {
    const provider = ReliableProvider.init(&.{}, 0, 500);
    try std.testing.expect(provider.computeBackoff(500, "429 Retry-After: 3") == 3000);
}

test "ReliableProvider computeBackoff caps at 30s" {
    const provider = ReliableProvider.init(&.{}, 0, 500);
    try std.testing.expect(provider.computeBackoff(500, "429 Retry-After: 120") == 30_000);
}

test "ReliableProvider computeBackoff falls back to base" {
    const provider = ReliableProvider.init(&.{}, 0, 500);
    try std.testing.expect(provider.computeBackoff(500, "500 Server Error") == 500);
}

test "ReliableProvider auth rotation cycles keys" {
    const keys = [_][]const u8{ "key-a", "key-b", "key-c" };
    var provider = ReliableProvider.init(&.{}, 0, 1);
    _ = provider.withApiKeys(&keys);

    // Rotate 5 times, verify round-robin
    try std.testing.expectEqualStrings("key-a", provider.rotateKey().?);
    try std.testing.expectEqualStrings("key-b", provider.rotateKey().?);
    try std.testing.expectEqualStrings("key-c", provider.rotateKey().?);
    try std.testing.expectEqualStrings("key-a", provider.rotateKey().?);
    try std.testing.expectEqualStrings("key-b", provider.rotateKey().?);
}

test "ReliableProvider auth rotation returns null when empty" {
    var provider = ReliableProvider.init(&.{}, 0, 1);
    try std.testing.expect(provider.rotateKey() == null);
}

test "isNonRetryable returns false for empty string" {
    try std.testing.expect(!isNonRetryable(""));
}

test "isNonRetryable returns false for 5xx errors" {
    try std.testing.expect(!isNonRetryable("503 Service Unavailable"));
    try std.testing.expect(!isNonRetryable("504 Gateway Timeout"));
}

test "isNonRetryable embedded in longer message" {
    try std.testing.expect(isNonRetryable("Error: got 401 from upstream API"));
    try std.testing.expect(!isNonRetryable("Server returned 500 error"));
}

test "isRateLimited requires both 429 and keyword" {
    // Just "429" alone without rate/limit/Too Many should be false
    try std.testing.expect(!isRateLimited("error code 429"));
    // With proper keywords
    try std.testing.expect(isRateLimited("429 rate exceeded"));
    try std.testing.expect(isRateLimited("429 limit reached"));
}

test "isRateLimited empty string" {
    try std.testing.expect(!isRateLimited(""));
}

test "parseRetryAfterMs with underscore separator" {
    try std.testing.expect(parseRetryAfterMs("retry_after: 10").? == 10000);
}

test "parseRetryAfterMs with space separator" {
    try std.testing.expect(parseRetryAfterMs("retry-after 7").? == 7000);
}

test "parseRetryAfterMs zero value" {
    try std.testing.expect(parseRetryAfterMs("Retry-After: 0").? == 0);
}

test "parseRetryAfterMs case insensitive" {
    try std.testing.expect(parseRetryAfterMs("RETRY-AFTER: 3").? == 3000);
    try std.testing.expect(parseRetryAfterMs("Retry-After: 3").? == 3000);
}

test "parseRetryAfterMs ignores non-numeric" {
    try std.testing.expect(parseRetryAfterMs("Retry-After: abc") == null);
}

test "ReliableProvider init enforces min backoff 50ms" {
    const provider = ReliableProvider.init(&.{}, 0, 10);
    try std.testing.expect(provider.base_backoff_ms == 50);
}

test "ReliableProvider init keeps backoff above 50" {
    const provider = ReliableProvider.init(&.{}, 0, 100);
    try std.testing.expect(provider.base_backoff_ms == 100);
}

test "ReliableProvider computeBackoff uses base when retry-after is smaller" {
    const provider = ReliableProvider.init(&.{}, 0, 5000);
    // Retry-After: 1 second = 1000ms, but base is 5000ms -> max(1000, 5000) = 5000
    try std.testing.expect(provider.computeBackoff(5000, "429 Retry-After: 1") == 5000);
}

test "ReliableProvider auth rotation wraps around" {
    const keys = [_][]const u8{ "key-a", "key-b" };
    var provider = ReliableProvider.init(&.{}, 0, 1);
    _ = provider.withApiKeys(&keys);

    // Exhaust all keys and wrap
    try std.testing.expectEqualStrings("key-a", provider.rotateKey().?);
    try std.testing.expectEqualStrings("key-b", provider.rotateKey().?);
    try std.testing.expectEqualStrings("key-a", provider.rotateKey().?);
}

test "ReliableProvider single key rotation" {
    const keys = [_][]const u8{"only-key"};
    var provider = ReliableProvider.init(&.{}, 0, 1);
    _ = provider.withApiKeys(&keys);

    try std.testing.expectEqualStrings("only-key", provider.rotateKey().?);
    try std.testing.expectEqualStrings("only-key", provider.rotateKey().?);
}
