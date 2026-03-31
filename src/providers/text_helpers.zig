const std = @import("std");

/// Case-insensitive byte-level string equality.
pub fn sliceEqlAsciiFold(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

/// Case-insensitive substring search.
pub fn containsAsciiFold(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (sliceEqlAsciiFold(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

/// Returns true if `text` indicates a rate-limit error.
pub fn isRateLimitedText(text: []const u8) bool {
    if (text.len == 0) return false;
    if (containsAsciiFold(text, "ratelimited") or
        containsAsciiFold(text, "rate limited") or
        containsAsciiFold(text, "rate_limit") or
        containsAsciiFold(text, "too many requests") or
        containsAsciiFold(text, "throttle") or
        containsAsciiFold(text, "quota exceeded"))
    {
        return true;
    }
    return containsAsciiFold(text, "429") and
        (containsAsciiFold(text, "rate") or
            containsAsciiFold(text, "limit") or
            containsAsciiFold(text, "too many"));
}

/// Returns true if `text` indicates a context-window exhaustion error.
pub fn isContextExhaustedText(text: []const u8) bool {
    if (text.len == 0) return false;
    if (containsAsciiFold(text, "context length exceeded") or
        containsAsciiFold(text, "contextlengthexceeded") or
        containsAsciiFold(text, "maximum context length") or
        containsAsciiFold(text, "context window") or
        containsAsciiFold(text, "prompt is too long") or
        containsAsciiFold(text, "input is too long"))
    {
        return true;
    }
    const has_context = containsAsciiFold(text, "context");
    const has_token = containsAsciiFold(text, "token");
    if (has_context and (containsAsciiFold(text, "length") or
        containsAsciiFold(text, "maximum") or
        containsAsciiFold(text, "window") or
        containsAsciiFold(text, "exceed")))
    {
        return true;
    }
    if (has_token and (containsAsciiFold(text, "limit") or
        containsAsciiFold(text, "maximum") or
        containsAsciiFold(text, "too many") or
        containsAsciiFold(text, "exceed")))
    {
        return true;
    }
    return containsAsciiFold(text, "413") and containsAsciiFold(text, "too large");
}

/// Returns true if `text` indicates a vision-unsupported error.
pub fn isVisionUnsupportedText(text: []const u8) bool {
    if (text.len == 0) return false;
    if (containsAsciiFold(text, "does not support image") or
        containsAsciiFold(text, "doesn't support image") or
        containsAsciiFold(text, "image input not supported") or
        containsAsciiFold(text, "no endpoints found that support image input") or
        containsAsciiFold(text, "vision not supported") or
        containsAsciiFold(text, "multimodal not supported") or
        containsAsciiFold(text, "not a multimodal model"))
    {
        return true;
    }
    return false;
}

test "isRateLimitedText" {
    try std.testing.expect(isRateLimitedText("Rate limit exceeded"));
    try std.testing.expect(isRateLimitedText("RATE_LIMIT_ERROR"));
    try std.testing.expect(isRateLimitedText("429: too many requests"));
    try std.testing.expect(isRateLimitedText("quota exceeded"));
    try std.testing.expect(!isRateLimitedText(""));
    try std.testing.expect(!isRateLimitedText("context window exceeded"));
}

test "isContextExhaustedText" {
    try std.testing.expect(isContextExhaustedText("context length exceeded"));
    try std.testing.expect(isContextExhaustedText("context window"));
    try std.testing.expect(isContextExhaustedText("token limit exceeded"));
    try std.testing.expect(isContextExhaustedText("413 too large"));
    try std.testing.expect(!isContextExhaustedText(""));
    try std.testing.expect(!isContextExhaustedText("rate limit exceeded"));
}

test "isVisionUnsupportedText" {
    try std.testing.expect(isVisionUnsupportedText("does not support image"));
    try std.testing.expect(isVisionUnsupportedText("VISION NOT SUPPORTED"));
    try std.testing.expect(isVisionUnsupportedText("not a multimodal model"));
    try std.testing.expect(!isVisionUnsupportedText(""));
    try std.testing.expect(!isVisionUnsupportedText("rate limit exceeded"));
}
