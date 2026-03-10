const std = @import("std");

pub const ApiErrorKind = enum {
    rate_limited,
    context_exhausted,
    vision_unsupported,
    other,
};

pub fn kindToError(kind: ApiErrorKind) anyerror {
    return switch (kind) {
        .rate_limited => error.RateLimited,
        .context_exhausted => error.ContextLengthExceeded,
        .vision_unsupported => error.ProviderDoesNotSupportVision,
        .other => error.ApiError,
    };
}

fn sliceEqlAsciiFold(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

fn containsAsciiFold(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (sliceEqlAsciiFold(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

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

fn parseStatusCode(value: std.json.Value) ?u16 {
    return switch (value) {
        .integer => |i| blk: {
            if (i < 0 or i > std.math.maxInt(u16)) break :blk null;
            break :blk @intCast(i);
        },
        .string => |s| std.fmt.parseInt(u16, std.mem.trim(u8, s, " \t\r\n"), 10) catch null,
        else => null,
    };
}

fn extractErrorFields(root_obj: anytype) ?struct {
    status: ?u16,
    code: ?[]const u8,
    type_name: ?[]const u8,
    message: ?[]const u8,
} {
    var status: ?u16 = null;
    var code: ?[]const u8 = null;
    var type_name: ?[]const u8 = null;
    var message: ?[]const u8 = null;
    var has_error_signal = false;

    if (root_obj.get("error")) |err_value| {
        has_error_signal = true;
        if (err_value == .string) {
            message = err_value.string;
        } else if (err_value == .object) {
            const err_obj = err_value.object;

            if (err_obj.get("status")) |v| {
                status = parseStatusCode(v);
            }

            if (err_obj.get("code")) |v| {
                switch (v) {
                    .string => |s| {
                        code = s;
                        if (status == null) status = parseStatusCode(v);
                    },
                    .integer => {
                        if (status == null) status = parseStatusCode(v);
                    },
                    else => {},
                }
            }

            if (err_obj.get("type")) |v| {
                if (v == .string) type_name = v.string;
            }
            if (err_obj.get("message")) |v| {
                if (v == .string) message = v.string;
            }
        }
    }

    if (message == null) {
        if (root_obj.get("message")) |v| {
            if (v == .string) message = v.string;
        }
    }

    if (status == null) {
        if (root_obj.get("status")) |v| {
            status = parseStatusCode(v);
            if (status != null) has_error_signal = true;
        }
    }

    if (code == null) {
        if (root_obj.get("code")) |v| {
            has_error_signal = true;
            switch (v) {
                .string => |s| code = s,
                .integer => {
                    if (status == null) status = parseStatusCode(v);
                },
                else => {},
            }
        }
    }

    if (type_name == null) {
        if (root_obj.get("type")) |v| {
            if (v == .string) {
                type_name = v.string;
                if (containsAsciiFold(v.string, "error")) has_error_signal = true;
            }
        }
    }

    if (!has_error_signal and message == null and status == null and code == null and type_name == null) {
        return null;
    }

    return .{
        .status = status,
        .code = code,
        .type_name = type_name,
        .message = message,
    };
}

fn appendBounded(out: []u8, idx: *usize, text: []const u8) void {
    if (text.len == 0 or idx.* >= out.len) return;
    const n = @min(out.len - idx.*, text.len);
    @memcpy(out[idx.* .. idx.* + n], text[0..n]);
    idx.* += n;
}

fn appendFieldPrefix(out: []u8, idx: *usize, wrote_any: *bool, name: []const u8) void {
    if (wrote_any.*) appendBounded(out, idx, " ");
    appendBounded(out, idx, name);
    appendBounded(out, idx, "=");
    wrote_any.* = true;
}

fn appendMessageValue(out: []u8, idx: *usize, raw: []const u8) void {
    for (raw) |c| {
        if (idx.* >= out.len) break;
        out[idx.*] = switch (c) {
            '\r', '\n', '\t' => ' ',
            else => c,
        };
        idx.* += 1;
    }
}

/// Build a compact summary for known provider API errors.
/// Returns null when the payload does not look like an error envelope.
pub fn summarizeKnownApiError(root_obj: anytype, out: []u8) ?[]const u8 {
    if (out.len == 0) return null;
    const fields = extractErrorFields(root_obj) orelse return null;

    var idx: usize = 0;
    var wrote_any = false;

    if (fields.status) |status| {
        appendFieldPrefix(out, &idx, &wrote_any, "status");
        var status_buf: [16]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch "0";
        appendBounded(out, &idx, status_str);
    }
    if (fields.code) |code| {
        appendFieldPrefix(out, &idx, &wrote_any, "code");
        appendBounded(out, &idx, std.mem.trim(u8, code, " \t\r\n"));
    }
    if (fields.type_name) |type_name| {
        appendFieldPrefix(out, &idx, &wrote_any, "type");
        appendBounded(out, &idx, std.mem.trim(u8, type_name, " \t\r\n"));
    }
    if (fields.message) |message| {
        appendFieldPrefix(out, &idx, &wrote_any, "message");
        appendMessageValue(out, &idx, std.mem.trim(u8, message, " \t\r\n"));
    }

    if (!wrote_any or idx == 0) return null;
    return out[0..idx];
}

fn classifyFromFields(
    status: ?u16,
    code: ?[]const u8,
    type_name: ?[]const u8,
    message: ?[]const u8,
) ApiErrorKind {
    if (status) |status_code| {
        if (status_code == 429 or status_code == 408) return .rate_limited;
        if (status_code == 413) return .context_exhausted;
    }

    if (message) |msg| {
        if (isRateLimitedText(msg)) return .rate_limited;
        if (isContextExhaustedText(msg)) return .context_exhausted;
        if (isVisionUnsupportedText(msg)) return .vision_unsupported;
    }
    if (type_name) |typ| {
        if (isRateLimitedText(typ)) return .rate_limited;
        if (isContextExhaustedText(typ)) return .context_exhausted;
        if (isVisionUnsupportedText(typ)) return .vision_unsupported;
    }
    if (code) |raw_code| {
        if (isRateLimitedText(raw_code)) return .rate_limited;
        if (isContextExhaustedText(raw_code)) return .context_exhausted;
        if (isVisionUnsupportedText(raw_code)) return .vision_unsupported;
    }

    return .other;
}

/// Classify `{"error": {...}}` payloads used by OpenAI-compatible,
/// Anthropic, and Gemini APIs.
pub fn classifyErrorObject(root_obj: anytype) ?ApiErrorKind {
    const err_value = root_obj.get("error") orelse return null;
    if (err_value == .string) {
        return classifyFromFields(null, null, null, err_value.string);
    }
    if (err_value != .object) return .other;
    const err_obj = err_value.object;

    var status: ?u16 = null;
    if (err_obj.get("status")) |v| {
        status = parseStatusCode(v);
    }

    var code: ?[]const u8 = null;
    if (err_obj.get("code")) |v| {
        switch (v) {
            .string => |s| {
                code = s;
                if (status == null) status = parseStatusCode(v);
            },
            .integer => {
                if (status == null) status = parseStatusCode(v);
            },
            else => {},
        }
    }

    var type_name: ?[]const u8 = null;
    if (err_obj.get("type")) |v| {
        if (v == .string) type_name = v.string;
    }

    var message: ?[]const u8 = null;
    if (err_obj.get("message")) |v| {
        if (v == .string) message = v.string;
    }
    if (message == null) {
        if (root_obj.get("message")) |v| {
            if (v == .string) message = v.string;
        }
    }

    return classifyFromFields(status, code, type_name, message);
}

fn classifyTopLevelError(root_obj: anytype) ?ApiErrorKind {
    var has_error_signal = false;

    var status: ?u16 = null;
    if (root_obj.get("status")) |v| {
        status = parseStatusCode(v);
        if (status != null) has_error_signal = true;
    }

    var code: ?[]const u8 = null;
    if (root_obj.get("code")) |v| {
        has_error_signal = true;
        switch (v) {
            .string => |s| code = s,
            .integer => {
                if (status == null) status = parseStatusCode(v);
            },
            else => {},
        }
    }

    var type_name: ?[]const u8 = null;
    if (root_obj.get("type")) |v| {
        if (v == .string) {
            type_name = v.string;
            if (containsAsciiFold(v.string, "error")) has_error_signal = true;
        }
    }

    var message: ?[]const u8 = null;
    if (root_obj.get("message")) |v| {
        if (v == .string) {
            message = v.string;
        }
    }

    if (!has_error_signal) return null;
    return classifyFromFields(status, code, type_name, message);
}

/// Classify known API error envelopes.
/// Returns null when no error envelope is present.
pub fn classifyKnownApiError(root_obj: anytype) ?ApiErrorKind {
    if (classifyErrorObject(root_obj)) |kind| return kind;
    return classifyTopLevelError(root_obj);
}

test "classifyKnownApiError detects rate-limit payloads" {
    const body = "{\"error\":{\"message\":\"Rate limit exceeded\",\"type\":\"rate_limit_error\",\"code\":429}}";
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    try std.testing.expectEqual(.rate_limited, classifyKnownApiError(parsed.value.object).?);
}

test "classifyKnownApiError detects context payloads" {
    const body = "{\"error\":{\"message\":\"This model's maximum context length is 128000 tokens\",\"type\":\"invalid_request_error\"}}";
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    try std.testing.expectEqual(.context_exhausted, classifyKnownApiError(parsed.value.object).?);
}

test "classifyKnownApiError detects vision unsupported payloads" {
    const body = "{\"error\":{\"message\":\"No endpoints found that support image input\",\"code\":404}}";
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    try std.testing.expectEqual(.vision_unsupported, classifyKnownApiError(parsed.value.object).?);
    try std.testing.expect(kindToError(.vision_unsupported) == error.ProviderDoesNotSupportVision);
}

test "classifyKnownApiError returns null for non-error payload" {
    const body = "{\"choices\":[{\"message\":{\"content\":\"ok\"}}]}";
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    try std.testing.expect(classifyKnownApiError(parsed.value.object) == null);
}

test "summarizeKnownApiError captures status code and message" {
    const body =
        \\{"error":{"code":503,"message":"This model is currently experiencing high demand.","status":"UNAVAILABLE"}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    var buf: [512]u8 = undefined;
    const summary = summarizeKnownApiError(parsed.value.object, &buf).?;
    try std.testing.expect(std.mem.indexOf(u8, summary, "status=503") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "message=This model is currently experiencing high demand.") != null);
}

test "summarizeKnownApiError returns null for non-error payload" {
    const body = "{\"choices\":[{\"message\":{\"content\":\"ok\"}}]}";
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    var buf: [128]u8 = undefined;
    try std.testing.expect(summarizeKnownApiError(parsed.value.object, &buf) == null);
}
