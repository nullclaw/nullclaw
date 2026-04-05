//! ApiContext — per-request context for /api/v1/* handlers.
//!
//! Mirrors the WebhookHandlerContext pattern used throughout gateway.zig:
//! raw HTTP bytes in, structured response fields out.  Handlers set
//! `response_status`, `response_body`, and optionally `response_allocated`
//! then return.  The dispatch loop in api.zig writes the wire response.
//!
//! Auth is performed by the caller (api.zig dispatcher) before invoking a
//! handler, using the same extractBearerToken / isWebhookAuthorized helpers
//! already exported by gateway.zig.

const std = @import("std");
const Config = @import("../config.zig").Config;

// ── Constants ────────────────────────────────────────────────────────

pub const CONTENT_TYPE_JSON = "application/json";

/// Maximum path segment length accepted in /api/v1/* routes.
pub const MAX_PATH_SEGMENT = 128;

// ── ApiContext ───────────────────────────────────────────────────────

/// Per-request context passed to every /api/v1/* handler.
///
/// Lifetime: stack-allocated in the dispatch loop, valid for the duration
/// of a single request.  Handlers must not store pointers to this struct.
pub const ApiContext = struct {
    /// Arena-backed allocator scoped to the current request.
    allocator: std.mem.Allocator,
    /// Raw HTTP request bytes (headers + body), owned by the caller.
    raw_request: []const u8,
    /// HTTP method string, e.g. "GET", "POST".
    method: []const u8,
    /// Request target including query string, e.g. "/api/v1/health".
    target: []const u8,
    /// Base path without query string.
    base_path: []const u8,
    /// Active config, or null when the gateway was started without one.
    config_opt: ?*const Config,

    // ── Response fields (set by handler) ────────────────────────────

    /// HTTP status line, e.g. "200 OK".  Default: "200 OK".
    response_status: []const u8 = "200 OK",
    /// Response body.  Default: empty string.
    response_body: []const u8 = "",
    /// True when response_body was heap-allocated and must be freed by the
    /// dispatch loop after writing the wire response.
    response_allocated: bool = false,

    // ── Helpers ──────────────────────────────────────────────────────

    /// Extract the request body (bytes after the blank header line).
    /// Returns null when no body is present.
    pub fn body(self: *const ApiContext) ?[]const u8 {
        return extractBody(self.raw_request);
    }

    /// Set a JSON response body (not heap-allocated — caller must ensure
    /// the slice outlives the response write).
    pub fn setJson(self: *ApiContext, status: []const u8, json_body: []const u8) void {
        self.response_status = status;
        self.response_body = json_body;
    }

    /// Set a JSON response body from a heap-allocated slice.
    /// The dispatch loop will free the slice after writing.
    pub fn setJsonOwned(self: *ApiContext, status: []const u8, json_body: []const u8) void {
        self.response_status = status;
        self.response_body = json_body;
        self.response_allocated = true;
    }

    /// Convenience: set a 200 OK JSON success envelope.
    /// data_json must be a valid JSON value (object, array, string, etc.).
    pub fn sendSuccess(self: *ApiContext, data_json: []const u8) !void {
        const body_str = try std.fmt.allocPrint(
            self.allocator,
            "{{\"success\":true,\"data\":{s},\"error\":null}}",
            .{data_json},
        );
        self.setJsonOwned("200 OK", body_str);
    }

    /// Convenience: set a JSON error envelope with the given HTTP status code,
    /// machine-readable error code string, and human-readable message.
    pub fn sendError(self: *ApiContext, http_status: []const u8, code: []const u8, message: []const u8) !void {
        const body_str = try std.fmt.allocPrint(
            self.allocator,
            "{{\"success\":false,\"data\":null,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
            .{ code, message },
        );
        self.setJsonOwned(http_status, body_str);
    }
};

// ── Body extraction (mirrors gateway.zig extractBody) ────────────────

/// Extract the HTTP body bytes from a raw request.
/// The body begins after the first blank line (\r\n\r\n or \n\n).
fn extractBody(raw: []const u8) ?[]const u8 {
    if (std.mem.indexOf(u8, raw, "\r\n\r\n")) |pos| {
        const start = pos + 4;
        return if (start < raw.len) raw[start..] else null;
    }
    if (std.mem.indexOf(u8, raw, "\n\n")) |pos| {
        const start = pos + 2;
        return if (start < raw.len) raw[start..] else null;
    }
    return null;
}

// ── Tests ─────────────────────────────────────────────────────────────

test "ApiContext setJson sets status and body" {
    var ctx = ApiContext{
        .allocator = std.testing.allocator,
        .raw_request = "GET /api/v1/health HTTP/1.1\r\n\r\n",
        .method = "GET",
        .target = "/api/v1/health",
        .base_path = "/api/v1/health",
        .config_opt = null,
    };
    ctx.setJson("200 OK", "{\"status\":\"ok\"}");
    try std.testing.expectEqualStrings("200 OK", ctx.response_status);
    try std.testing.expectEqualStrings("{\"status\":\"ok\"}", ctx.response_body);
    try std.testing.expect(!ctx.response_allocated);
}

test "ApiContext sendSuccess wraps data in envelope" {
    var ctx = ApiContext{
        .allocator = std.testing.allocator,
        .raw_request = "GET /api/v1/health HTTP/1.1\r\n\r\n",
        .method = "GET",
        .target = "/api/v1/health",
        .base_path = "/api/v1/health",
        .config_opt = null,
    };
    try ctx.sendSuccess("{\"version\":\"1.0\"}");
    defer if (ctx.response_allocated) std.testing.allocator.free(ctx.response_body);
    try std.testing.expectEqualStrings("200 OK", ctx.response_status);
    try std.testing.expectEqualStrings(
        "{\"success\":true,\"data\":{\"version\":\"1.0\"},\"error\":null}",
        ctx.response_body,
    );
    try std.testing.expect(ctx.response_allocated);
}

test "ApiContext sendError wraps error in envelope" {
    var ctx = ApiContext{
        .allocator = std.testing.allocator,
        .raw_request = "GET /api/v1/health HTTP/1.1\r\n\r\n",
        .method = "GET",
        .target = "/api/v1/health",
        .base_path = "/api/v1/health",
        .config_opt = null,
    };
    try ctx.sendError("403 Forbidden", "FORBIDDEN", "Admin API is disabled");
    defer if (ctx.response_allocated) std.testing.allocator.free(ctx.response_body);
    try std.testing.expectEqualStrings("403 Forbidden", ctx.response_status);
    try std.testing.expect(std.mem.indexOf(u8, ctx.response_body, "FORBIDDEN") != null);
    try std.testing.expect(std.mem.indexOf(u8, ctx.response_body, "Admin API is disabled") != null);
}

test "ApiContext body extracts CRLF-delimited body" {
    const raw = "POST /api/v1/health HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
    const ctx = ApiContext{
        .allocator = std.testing.allocator,
        .raw_request = raw,
        .method = "POST",
        .target = "/api/v1/health",
        .base_path = "/api/v1/health",
        .config_opt = null,
    };
    const b = ctx.body();
    try std.testing.expect(b != null);
    try std.testing.expectEqualStrings("{}", b.?);
}

test "ApiContext body returns null for bodyless request" {
    const raw = "GET /api/v1/health HTTP/1.1\r\n\r\n";
    const ctx = ApiContext{
        .allocator = std.testing.allocator,
        .raw_request = raw,
        .method = "GET",
        .target = "/api/v1/health",
        .base_path = "/api/v1/health",
        .config_opt = null,
    };
    try std.testing.expect(ctx.body() == null);
}
