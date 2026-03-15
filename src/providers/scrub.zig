const std = @import("std");
const builtin = @import("builtin");

const DEFAULT_MAX_API_ERROR_CHARS: usize = 200;
const MIN_MAX_API_ERROR_CHARS: usize = 200;
const MAX_MAX_API_ERROR_CHARS: usize = 10_000;

const NO_API_ERROR_LIMIT_OVERRIDE: usize = 0;
var max_api_error_chars_override: std.atomic.Value(usize) =
    std.atomic.Value(usize).init(NO_API_ERROR_LIMIT_OVERRIDE);

pub const ApiErrorLimitOverrideError = error{OutOfRange};

/// Set process-wide API error truncation limit from config.
/// Null clears the override and falls back to env/default behavior.
pub fn setApiErrorLimitOverride(limit: ?u32) ApiErrorLimitOverrideError!void {
    if (limit) |v| {
        const n: usize = @intCast(v);
        if (n < MIN_MAX_API_ERROR_CHARS or n > MAX_MAX_API_ERROR_CHARS) {
            return error.OutOfRange;
        }
        max_api_error_chars_override.store(n, .release);
        return;
    }
    max_api_error_chars_override.store(NO_API_ERROR_LIMIT_OVERRIDE, .release);
}

fn readMaxApiErrorCharsFromEnv() usize {
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "NULLCLAW_MAX_ERROR_CHARS")) |env_val| {
        defer std.heap.page_allocator.free(env_val);
        const val = std.fmt.parseInt(usize, env_val, 10) catch DEFAULT_MAX_API_ERROR_CHARS;
        return if (val < MIN_MAX_API_ERROR_CHARS)
            MIN_MAX_API_ERROR_CHARS
        else if (val > MAX_MAX_API_ERROR_CHARS)
            MAX_MAX_API_ERROR_CHARS
        else
            val;
    } else |_| {
        return DEFAULT_MAX_API_ERROR_CHARS;
    }
}

fn getMaxApiErrorChars() usize {
    const override = max_api_error_chars_override.load(.acquire);
    if (override != NO_API_ERROR_LIMIT_OVERRIDE) return override;
    if (builtin.is_test) return DEFAULT_MAX_API_ERROR_CHARS;
    return readMaxApiErrorCharsFromEnv();
}

fn isSecretChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == ':';
}

fn tokenEnd(input: []const u8, from: usize) usize {
    var end = from;
    for (input[from..]) |c| {
        if (isSecretChar(c)) {
            end += 1;
        } else {
            break;
        }
    }
    return end;
}

/// Scrub known secret-like token prefixes from text.
/// Redacts tokens with prefixes like `sk-`, `xoxb-`, `ghp_`, etc.
pub fn scrubSecretPatterns(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const prefixes = [_][]const u8{
        "sk-",  "xoxb-", "xoxp-", "ghp_",
        "gho_", "ghs_",  "ghu_",  "glpat-",
        "AKIA", "pypi-", "npm_",  "shpat_",
    };
    const redacted = "[REDACTED]";

    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        // 1. Check key-value patterns: api_key=VALUE, token=VALUE, etc.
        if (matchKeyValueSecret(input, i)) |kv| {
            // Keep key + separator, redact the value (show first 4 chars)
            try result.appendSlice(allocator, input[i..kv.value_start]);
            const val = input[kv.value_start..kv.value_end];
            if (val.len > 4) {
                try result.appendSlice(allocator, val[0..4]);
            }
            try result.appendSlice(allocator, redacted);
            i = kv.value_end;
            continue;
        }

        // 2. Check "bearer TOKEN" (case-insensitive)
        if (matchBearerToken(input, i)) |bt| {
            try result.appendSlice(allocator, input[i .. i + bt.prefix_len]);
            const val = input[i + bt.prefix_len .. bt.end];
            if (val.len > 4) {
                try result.appendSlice(allocator, val[0..4]);
            }
            try result.appendSlice(allocator, redacted);
            i = bt.end;
            continue;
        }

        // 3. Check prefix-based tokens
        var matched = false;
        for (prefixes) |prefix| {
            if (i + prefix.len <= input.len and std.mem.eql(u8, input[i..][0..prefix.len], prefix)) {
                const content_start = i + prefix.len;
                const end = tokenEnd(input, content_start);
                if (end > content_start) {
                    try result.appendSlice(allocator, redacted);
                    i = end;
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) {
            try result.append(allocator, input[i]);
            i += 1;
        }
    }

    return try result.toOwnedSlice(allocator);
}

const KeyValueMatch = struct { value_start: usize, value_end: usize };

/// Match patterns like `api_key=VALUE`, `token=VALUE`, `password: VALUE`, `secret=VALUE`.
fn matchKeyValueSecret(input: []const u8, pos: usize) ?KeyValueMatch {
    const keywords = [_][]const u8{
        "api_key", "api-key",    "apikey",
        "token",   "password",   "passwd",
        "secret",  "api_secret", "access_key",
    };
    for (keywords) |kw| {
        if (pos + kw.len >= input.len) continue;
        if (!eqlLowercase(input[pos..][0..kw.len], kw)) continue;
        // Check separator after keyword: `=`, `:`, `= `, `: `
        var sep_end = pos + kw.len;
        if (sep_end < input.len and (input[sep_end] == '=' or input[sep_end] == ':')) {
            sep_end += 1;
            // Skip optional space after separator
            while (sep_end < input.len and input[sep_end] == ' ') sep_end += 1;
            // Skip optional quotes
            var quote: u8 = 0;
            if (sep_end < input.len and (input[sep_end] == '"' or input[sep_end] == '\'')) {
                quote = input[sep_end];
                sep_end += 1;
            }
            const value_start = sep_end;
            var value_end = value_start;
            if (quote != 0) {
                // Read until closing quote
                while (value_end < input.len and input[value_end] != quote) value_end += 1;
                if (value_end < input.len) value_end += 1; // skip closing quote
            } else {
                value_end = tokenEnd(input, value_start);
            }
            if (value_end > value_start) {
                return .{ .value_start = value_start, .value_end = value_end };
            }
        }
    }
    return null;
}

const BearerMatch = struct { prefix_len: usize, end: usize };

/// Match "Bearer TOKEN" or "bearer TOKEN" pattern.
fn matchBearerToken(input: []const u8, pos: usize) ?BearerMatch {
    const bearer_variants = [_][]const u8{ "Bearer ", "bearer ", "BEARER " };
    for (bearer_variants) |prefix| {
        if (pos + prefix.len <= input.len and std.mem.eql(u8, input[pos..][0..prefix.len], prefix)) {
            const token_start = pos + prefix.len;
            const end = tokenEnd(input, token_start);
            if (end > token_start) {
                return .{ .prefix_len = prefix.len, .end = end };
            }
        }
    }
    return null;
}

/// Case-insensitive comparison (input can be mixed case, kw is lowercase).
fn eqlLowercase(input: []const u8, kw: []const u8) bool {
    if (input.len != kw.len) return false;
    for (input, kw) |a, b| {
        if (std.ascii.toLower(a) != b) return false;
    }
    return true;
}

/// Maximum tool output length before truncation.
/// Set high enough to accommodate paginated MCP tool responses (e.g. full
/// task lists from Vikunja) while still bounding pathological cases.
const MAX_TOOL_OUTPUT_CHARS: usize = 100_000;

/// Scrub credentials from tool execution output and truncate if too long.
/// Returns an owned slice. Caller must free.
pub fn scrubToolOutput(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    // First truncate if too long
    const truncated = if (input.len > MAX_TOOL_OUTPUT_CHARS) blk: {
        const suffix = "\n[output truncated]";
        var buf = try allocator.alloc(u8, MAX_TOOL_OUTPUT_CHARS + suffix.len);
        @memcpy(buf[0..MAX_TOOL_OUTPUT_CHARS], input[0..MAX_TOOL_OUTPUT_CHARS]);
        @memcpy(buf[MAX_TOOL_OUTPUT_CHARS..], suffix);
        break :blk buf;
    } else try allocator.dupe(u8, input);
    defer allocator.free(truncated);

    // Then scrub secrets
    return scrubSecretPatterns(allocator, truncated);
}

/// Sanitize API error text by scrubbing secrets and truncating length.
pub fn sanitizeApiError(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const scrubbed = try scrubSecretPatterns(allocator, input);

    const max_chars = getMaxApiErrorChars();
    if (scrubbed.len <= max_chars) {
        return scrubbed;
    }

    // Truncate
    var truncated = try allocator.alloc(u8, max_chars + 3);
    @memcpy(truncated[0..max_chars], scrubbed[0..max_chars]);
    @memcpy(truncated[max_chars..][0..3], "...");
    allocator.free(scrubbed);
    return truncated;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "scrubSecretPatterns redacts sk- tokens" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "request failed: sk-1234567890abcdef");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "sk-1234567890abcdef") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[REDACTED]") != null);
}

test "scrubSecretPatterns handles multiple prefixes" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "keys sk-abcdef xoxb-12345 xoxp-67890");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "sk-abcdef") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "xoxb-12345") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "xoxp-67890") == null);
}

test "scrubSecretPatterns keeps bare prefix" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "only prefix sk- present");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "sk-") != null);
}

test "sanitizeApiError truncates long errors" {
    const allocator = std.testing.allocator;
    const long = try allocator.alloc(u8, 400);
    defer allocator.free(long);
    @memset(long, 'a');
    const result = try sanitizeApiError(allocator, long);
    defer allocator.free(result);
    try std.testing.expect(result.len <= DEFAULT_MAX_API_ERROR_CHARS + 3);
    try std.testing.expect(std.mem.endsWith(u8, result, "..."));
}

test "sanitizeApiError no secret no change" {
    const allocator = std.testing.allocator;
    const result = try sanitizeApiError(allocator, "simple upstream timeout");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("simple upstream timeout", result);
}

test "sanitizeApiError respects config override limit" {
    try setApiErrorLimitOverride(350);
    defer setApiErrorLimitOverride(null) catch unreachable;

    const allocator = std.testing.allocator;
    const long = try allocator.alloc(u8, 500);
    defer allocator.free(long);
    @memset(long, 'b');

    const result = try sanitizeApiError(allocator, long);
    defer allocator.free(result);
    try std.testing.expect(result.len <= 353);
    try std.testing.expect(std.mem.endsWith(u8, result, "..."));
}

test "setApiErrorLimitOverride rejects out-of-range values" {
    try std.testing.expectError(error.OutOfRange, setApiErrorLimitOverride(10));
    try std.testing.expectError(error.OutOfRange, setApiErrorLimitOverride(20_000));
}

test "scrubSecretPatterns redacts ghp_ GitHub tokens" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "token is ghp_ABCDef123456789012345678901234567890");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "ghp_") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[REDACTED]") != null);
}

test "scrubSecretPatterns redacts gho_ GitHub OAuth tokens" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "got gho_abcdef12345");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "gho_abcdef") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[REDACTED]") != null);
}

test "scrubSecretPatterns redacts glpat- GitLab tokens" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "gitlab glpat-ABCDEF123456");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "glpat-ABCDEF") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[REDACTED]") != null);
}

test "scrubSecretPatterns redacts AKIA AWS keys" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "aws AKIAIOSFODNN7EXAMPLE");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "AKIAIOSFODNN7EXAMPLE") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[REDACTED]") != null);
}

test "scrubSecretPatterns redacts api_key=VALUE pattern" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "config: api_key=sk_live_1234567890abcdef");
    defer allocator.free(result);
    // Should keep key name and first 4 chars of value
    try std.testing.expect(std.mem.indexOf(u8, result, "api_key=") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "sk_l") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[REDACTED]") != null);
    // Full value should not be present
    try std.testing.expect(std.mem.indexOf(u8, result, "sk_live_1234567890abcdef") == null);
}

test "scrubSecretPatterns redacts token: VALUE pattern" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "token: mySecretToken123");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "token: ") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[REDACTED]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "mySecretToken123") == null);
}

test "scrubSecretPatterns redacts password=VALUE pattern" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "PASSWORD=hunter2 rest");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "[REDACTED]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "hunter2") == null);
}

test "scrubSecretPatterns redacts Bearer TOKEN pattern" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "Bearer ") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "[REDACTED]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret") == null);
}

test "scrubSecretPatterns redacts secret= with quoted value" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "secret=\"my_very_secret_value\" next");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "[REDACTED]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "my_very_secret_value") == null);
}

test "scrubSecretPatterns no false positives on normal text" {
    const allocator = std.testing.allocator;
    const result = try scrubSecretPatterns(allocator, "the password policy requires 8 chars. See token docs.");
    defer allocator.free(result);
    // "password" and "token" without separator should not trigger redaction
    try std.testing.expect(std.mem.indexOf(u8, result, "[REDACTED]") == null);
}

test "scrubToolOutput truncates long output" {
    const allocator = std.testing.allocator;
    const long = try allocator.alloc(u8, 110_000);
    defer allocator.free(long);
    @memset(long, 'x');
    const result = try scrubToolOutput(allocator, long);
    defer allocator.free(result);
    try std.testing.expect(result.len < 110_000);
    try std.testing.expect(std.mem.endsWith(u8, result, "[output truncated]"));
}

test "scrubToolOutput scrubs secrets and truncates" {
    const allocator = std.testing.allocator;
    const result = try scrubToolOutput(allocator, "cat .env output: api_key=sk_live_abcdef123456");
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "[REDACTED]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "sk_live_abcdef123456") == null);
}

test "scrubToolOutput passes through clean short output" {
    const allocator = std.testing.allocator;
    const result = try scrubToolOutput(allocator, "ls output: file1.txt file2.txt");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("ls output: file1.txt file2.txt", result);
}

test "scrubSecretPatterns handles multiple patterns in one string" {
    const allocator = std.testing.allocator;
    const input = "keys: api_key=abc123 token=xyz789 ghp_TokenHere sk-mykey123";
    const result = try scrubSecretPatterns(allocator, input);
    defer allocator.free(result);
    // All secrets should be redacted
    try std.testing.expect(std.mem.indexOf(u8, result, "abc123") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "xyz789") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "ghp_TokenHere") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "sk-mykey123") == null);
}

test "eqlLowercase matches case-insensitively" {
    try std.testing.expect(eqlLowercase("API_KEY", "api_key"));
    try std.testing.expect(eqlLowercase("api_key", "api_key"));
    try std.testing.expect(eqlLowercase("Api_Key", "api_key"));
    try std.testing.expect(!eqlLowercase("api_keys", "api_key")); // different length — won't match
}
