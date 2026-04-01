//! Tool Retry Policy — structured retry with exponential backoff.
//!
//! Classifies tool errors as transient or permanent and provides
//! deterministic retry logic (backoff + jitter) instead of relying
//! on LLM prompt instructions.

const std = @import("std");
const builtin = @import("builtin");

/// Per-tool retry configuration.
pub const ToolRetryPolicy = struct {
    /// Maximum number of retries (0 = no retries, just the initial attempt).
    max_retries: u8 = 2,
    /// Base backoff in milliseconds. Doubles each retry: base, base*2, base*4.
    backoff_base_ms: u32 = 1000,
    /// Which error classes are eligible for retry.
    retry_on: RetryConditions = .{},
};

/// Bit flags for retryable error conditions.
pub const RetryConditions = packed struct {
    timeout: bool = true,
    network_error: bool = true,
    rate_limit: bool = true,
    transient_error: bool = true,
    permission_denied: bool = false, // Never auto-retry
    invalid_args: bool = false, // Never auto-retry
    _padding: u2 = 0,
};

/// Classification of a tool failure.
pub const ErrorClass = enum {
    /// Transient: worth retrying (network, timeout, rate limit, server error)
    transient,
    /// Permanent: do not retry (invalid args, permission denied, unknown tool)
    permanent,
};

/// Default policy used when no tool-specific override is configured.
pub const default_policy = ToolRetryPolicy{};

/// Classify a tool error based on its error name and output message.
/// Returns `.transient` for errors that are likely to succeed on retry.
pub fn classifyError(error_name: []const u8, output: []const u8) ErrorClass {
    // Check error name patterns
    const transient_errors = [_][]const u8{
        "Timeout",
        "TimedOut",
        "ConnectionRefused",
        "ConnectionReset",
        "ConnectionTimedOut",
        "BrokenPipe",
        "NetworkUnreachable",
        "HostUnreachable",
        "TemporaryNameError",
        "CurlFailed",
        "HttpRequestFailed",
        "EmbeddingApiError",
        "EndOfStream",
        "Unexpected",
        "InputOutput",
    };
    for (transient_errors) |te| {
        if (std.mem.indexOf(u8, error_name, te) != null) return .transient;
    }

    // Check output message patterns
    const transient_output_patterns = [_][]const u8{
        "rate limit",
        "Rate limit",
        "rate_limit",
        "429",
        "503",
        "502",
        "timeout",
        "Timeout",
        "ETIMEDOUT",
        "ECONNREFUSED",
        "ECONNRESET",
        "temporarily unavailable",
        "server error",
        "internal server error",
        "overloaded",
    };
    for (transient_output_patterns) |pat| {
        if (std.mem.indexOf(u8, output, pat) != null) return .transient;
    }

    // Permanent error patterns — explicitly classify to avoid false retries
    const permanent_patterns = [_][]const u8{
        "permission",
        "Permission",
        "not found",
        "Not found",
        "Invalid",
        "invalid",
        "blocked",
        "Blocked",
        "Unknown tool",
        "read-only",
    };
    for (permanent_patterns) |pat| {
        if (std.mem.indexOf(u8, output, pat) != null) return .permanent;
    }

    // Default: treat unknown errors as permanent (safe — avoid wasting retries)
    return .permanent;
}

/// Check whether a specific error class should be retried per the policy.
pub fn shouldRetry(policy: ToolRetryPolicy, class: ErrorClass, attempt: u8) bool {
    if (attempt >= policy.max_retries) return false;
    if (class == .permanent) return false;
    // All transient errors are retryable if conditions allow
    const cond = policy.retry_on;
    return cond.timeout or cond.network_error or cond.rate_limit or cond.transient_error;
}

/// Calculate backoff duration for a given attempt (0-indexed).
/// Returns milliseconds with ±25% jitter.
pub fn backoffMs(policy: ToolRetryPolicy, attempt: u8) u64 {
    const base: u64 = policy.backoff_base_ms;
    const shift: u6 = @intCast(@min(attempt, 5)); // Cap at 2^5 = 32x
    const exponential = base << shift;
    // Add jitter: ±25% using cheap random
    if (builtin.is_test) return exponential; // Deterministic in tests
    const jitter_range = exponential / 4;
    if (jitter_range == 0) return exponential;
    const jitter = std.crypto.random.uintLessThan(u64, jitter_range * 2);
    return exponential - jitter_range + jitter;
}

// ── Tests ───────────────────────────────────────────────────────────

test "classifyError detects transient errors" {
    try std.testing.expectEqual(ErrorClass.transient, classifyError("Timeout", ""));
    try std.testing.expectEqual(ErrorClass.transient, classifyError("ConnectionRefused", ""));
    try std.testing.expectEqual(ErrorClass.transient, classifyError("CurlFailed", ""));
    try std.testing.expectEqual(ErrorClass.transient, classifyError("EmbeddingApiError", ""));
}

test "classifyError detects transient from output" {
    try std.testing.expectEqual(ErrorClass.transient, classifyError("", "rate limit exceeded"));
    try std.testing.expectEqual(ErrorClass.transient, classifyError("", "HTTP 429 Too Many Requests"));
    try std.testing.expectEqual(ErrorClass.transient, classifyError("", "503 Service Unavailable"));
    try std.testing.expectEqual(ErrorClass.transient, classifyError("", "connection timeout"));
}

test "classifyError detects permanent errors" {
    try std.testing.expectEqual(ErrorClass.permanent, classifyError("", "permission denied"));
    try std.testing.expectEqual(ErrorClass.permanent, classifyError("", "Unknown tool"));
    try std.testing.expectEqual(ErrorClass.permanent, classifyError("", "Invalid arguments"));
    try std.testing.expectEqual(ErrorClass.permanent, classifyError("", "Action blocked: agent is in read-only mode"));
}

test "classifyError defaults to permanent for unknown" {
    try std.testing.expectEqual(ErrorClass.permanent, classifyError("SomethingWeird", "unexpected output"));
}

test "shouldRetry respects max_retries" {
    const policy = ToolRetryPolicy{ .max_retries = 2 };
    try std.testing.expect(shouldRetry(policy, .transient, 0));
    try std.testing.expect(shouldRetry(policy, .transient, 1));
    try std.testing.expect(!shouldRetry(policy, .transient, 2));
}

test "shouldRetry rejects permanent errors" {
    const policy = ToolRetryPolicy{ .max_retries = 3 };
    try std.testing.expect(!shouldRetry(policy, .permanent, 0));
}

test "shouldRetry with all conditions disabled rejects transient" {
    const policy = ToolRetryPolicy{
        .max_retries = 2,
        .retry_on = .{
            .timeout = false,
            .network_error = false,
            .rate_limit = false,
            .transient_error = false,
        },
    };
    try std.testing.expect(!shouldRetry(policy, .transient, 0));
}

test "backoffMs is exponential" {
    const policy = ToolRetryPolicy{ .backoff_base_ms = 1000 };
    // In test mode, jitter is disabled for determinism
    try std.testing.expectEqual(@as(u64, 1000), backoffMs(policy, 0));
    try std.testing.expectEqual(@as(u64, 2000), backoffMs(policy, 1));
    try std.testing.expectEqual(@as(u64, 4000), backoffMs(policy, 2));
    try std.testing.expectEqual(@as(u64, 8000), backoffMs(policy, 3));
}

test "backoffMs caps shift at 5" {
    const policy = ToolRetryPolicy{ .backoff_base_ms = 1000 };
    try std.testing.expectEqual(@as(u64, 32000), backoffMs(policy, 5));
    try std.testing.expectEqual(@as(u64, 32000), backoffMs(policy, 6));
    try std.testing.expectEqual(@as(u64, 32000), backoffMs(policy, 10));
}

test "RetryConditions is 1 byte packed struct" {
    try std.testing.expectEqual(@as(usize, 1), @sizeOf(RetryConditions));
}

test "default_policy has sensible defaults" {
    try std.testing.expectEqual(@as(u8, 2), default_policy.max_retries);
    try std.testing.expectEqual(@as(u32, 1000), default_policy.backoff_base_ms);
    try std.testing.expect(default_policy.retry_on.timeout);
    try std.testing.expect(default_policy.retry_on.network_error);
    try std.testing.expect(!default_policy.retry_on.permission_denied);
}
