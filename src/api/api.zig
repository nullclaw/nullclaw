//! REST Admin API — v1 router and endpoint registry.
//!
//! All endpoints live under /api/v1/.  The surface is opt-in: when
//! `gateway.admin_api` is false (the default) every request to /api/v1/*
//! receives a 403 with a clear error message so clients can surface a
//! useful hint rather than a silent 404.
//!
//! Adding a new endpoint in a later phase is a one-step operation:
//!   1. Write a handler fn(ctx: *ApiContext) anyerror!void in this file
//!      (or import it from a dedicated file for larger phases).
//!   2. Append an Endpoint entry to the `endpoints` slice in `registry`.
//!
//! Auth model (mirrors the /cron pattern from gateway.zig):
//!   - No pairing guard configured → allow (gateway running without auth).
//!   - Pairing disabled → allow.
//!   - Pairing enabled, no tokens yet → deny (bootstrap phase).
//!   - Pairing enabled, tokens present → require valid Bearer token.
//!
//! Path parameter convention: for paths with a dynamic segment (e.g.
//! /api/v1/models/:name) the Endpoint.path field ends with "/:param" and
//! matchPath() returns the segment after the last "/" as the path param.

const std = @import("std");
const builtin = @import("builtin");
const health = @import("../health.zig");
const Config = @import("../config.zig").Config;
const ApiContext = @import("context.zig").ApiContext;

// ── Endpoint registry ────────────────────────────────────────────────

pub const Endpoint = struct {
    /// HTTP method string, e.g. "GET".
    method: []const u8,
    /// URL path, e.g. "/api/v1/health".
    /// A trailing "/:param" suffix indicates a single dynamic path segment.
    path: []const u8,
    /// Handler function.  Must not panic; errors are caught by the dispatcher.
    handler: *const fn (ctx: *ApiContext) anyerror!void,
};

/// Comptime-built slice of all registered /api/v1/* endpoints.
/// Phase 0 registers only /api/v1/health.  Later phases append more.
pub const registry: []const Endpoint = &.{
    .{ .method = "GET", .path = "/api/v1/health", .handler = handleHealth },
};

// ── Dispatcher ───────────────────────────────────────────────────────

/// Result returned to gateway.zig so it can write the wire response.
pub const DispatchResult = struct {
    /// HTTP status line, e.g. "200 OK".
    status: []const u8,
    /// Response body.
    body: []const u8,
    /// True when body was heap-allocated and must be freed with `allocator`.
    allocated: bool,
};

/// Main entry point called by gateway.zig for every request whose base_path
/// starts with "/api/v1/".
///
/// `pairing_guard_ptr` is `?*const PairingGuard` erased to `?*anyopaque` so
/// this file does not need to import the pairing module directly; the gateway
/// passes the already-checked boolean `auth_ok` instead.
///
/// Parameters:
///   allocator    — request-scoped arena allocator
///   raw_request  — full raw HTTP bytes
///   method       — HTTP method string
///   target       — full request target (may include query string)
///   base_path    — target without query string
///   config_opt   — active config or null
///   auth_ok      — true when the bearer token has already been validated
///                  by the caller (gateway.zig) using isWebhookAuthorized.
pub fn dispatch(
    allocator: std.mem.Allocator,
    raw_request: []const u8,
    method: []const u8,
    target: []const u8,
    base_path: []const u8,
    config_opt: ?*const Config,
    auth_ok: bool,
) DispatchResult {
    // Guard: admin_api must be explicitly enabled in gateway config.
    const enabled = if (config_opt) |cfg| cfg.gateway.admin_api else false;
    if (!enabled) {
        return .{
            .status = "403 Forbidden",
            .body = "{\"success\":false,\"data\":null,\"error\":{\"code\":\"ADMIN_API_DISABLED\",\"message\":\"Set gateway.admin_api=true in config.json to enable the REST admin API\"}}",
            .allocated = false,
        };
    }

    // Guard: bearer auth.
    if (!auth_ok) {
        return .{
            .status = "401 Unauthorized",
            .body = "{\"success\":false,\"data\":null,\"error\":{\"code\":\"UNAUTHORIZED\",\"message\":\"Valid Bearer token required\"}}",
            .allocated = false,
        };
    }

    // Route: walk registry for exact path + method match, then try prefix for
    // dynamic segments.
    var ctx = ApiContext{
        .allocator = allocator,
        .raw_request = raw_request,
        .method = method,
        .target = target,
        .base_path = base_path,
        .config_opt = config_opt,
    };

    for (registry) |ep| {
        if (std.mem.eql(u8, ep.method, method) and std.mem.eql(u8, ep.path, base_path)) {
            ep.handler(&ctx) catch |err| {
                return internalError(allocator, err);
            };
            return .{
                .status = ctx.response_status,
                .body = ctx.response_body,
                .allocated = ctx.response_allocated,
            };
        }
    }

    return .{
        .status = "404 Not Found",
        .body = "{\"success\":false,\"data\":null,\"error\":{\"code\":\"NOT_FOUND\",\"message\":\"Unknown API endpoint\"}}",
        .allocated = false,
    };
}

// ── Internal helpers ─────────────────────────────────────────────────

fn internalError(allocator: std.mem.Allocator, err: anyerror) DispatchResult {
    const msg = std.fmt.allocPrint(
        allocator,
        "{{\"success\":false,\"data\":null,\"error\":{{\"code\":\"INTERNAL_ERROR\",\"message\":\"{s}\"}}}}",
        .{@errorName(err)},
    ) catch return .{
        .status = "500 Internal Server Error",
        .body = "{\"success\":false,\"data\":null,\"error\":{\"code\":\"INTERNAL_ERROR\",\"message\":\"internal error\"}}",
        .allocated = false,
    };
    return .{ .status = "500 Internal Server Error", .body = msg, .allocated = true };
}

// ── Phase 0 handler: GET /api/v1/health ─────────────────────────────

/// Expanded health endpoint.
///
/// Returns structured component health from the global registry, plus pid
/// and uptime — a richer version of the plain {"status":"ok"} at /health.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": {
///     "status": "ok",
///     "pid": 12345,
///     "uptime_seconds": 3600,
///     "components": {
///       "gateway": { "status": "ok", "restart_count": 0 }
///     }
///   },
///   "error": null
/// }
/// ```
fn handleHealth(ctx: *ApiContext) anyerror!void {
    const snap = health.snapshot();

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    const w = buf.writer(ctx.allocator);

    // Determine overall status.
    var all_ok = true;
    {
        var iter = snap.components.iterator();
        while (iter.next()) |entry| {
            if (!std.mem.eql(u8, entry.value_ptr.status, "ok")) {
                all_ok = false;
                break;
            }
        }
    }
    const overall = if (all_ok) "ok" else "degraded";

    try w.print(
        "{{\"status\":\"{s}\",\"pid\":{d},\"uptime_seconds\":{d},\"components\":{{",
        .{ overall, snap.pid, snap.uptime_seconds },
    );

    var iter = snap.components.iterator();
    var first = true;
    while (iter.next()) |entry| {
        if (!first) try w.writeByte(',');
        first = false;
        const ch = entry.value_ptr;
        try w.print(
            "\"{s}\":{{\"status\":\"{s}\",\"restart_count\":{d}",
            .{ entry.key_ptr.*, ch.status, ch.restart_count },
        );
        if (ch.last_error) |le| {
            try w.print(",\"last_error\":\"{s}\"", .{le});
        }
        try w.writeByte('}');
    }
    try w.writeAll("}}");

    const data = try ctx.allocator.dupe(u8, buf.items);
    try ctx.sendSuccess(data);
    // sendSuccess already allocated its own envelope, free the intermediate data.
    ctx.allocator.free(data);
}

// ── Tests ─────────────────────────────────────────────────────────────

test "dispatch returns 403 when admin_api disabled" {
    var cfg = Config{ .workspace_dir = "/tmp", .config_path = "/tmp/config.json", .allocator = std.testing.allocator };
    cfg.gateway.admin_api = false;
    const result = dispatch(
        std.testing.allocator,
        "GET /api/v1/health HTTP/1.1\r\n\r\n",
        "GET",
        "/api/v1/health",
        "/api/v1/health",
        &cfg,
        true,
    );
    try std.testing.expectEqualStrings("403 Forbidden", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "ADMIN_API_DISABLED") != null);
}

test "dispatch returns 401 when not authorized" {
    var cfg = Config{ .workspace_dir = "/tmp", .config_path = "/tmp/config.json", .allocator = std.testing.allocator };
    cfg.gateway.admin_api = true;
    const result = dispatch(
        std.testing.allocator,
        "GET /api/v1/health HTTP/1.1\r\n\r\n",
        "GET",
        "/api/v1/health",
        "/api/v1/health",
        &cfg,
        false,
    );
    try std.testing.expectEqualStrings("401 Unauthorized", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "UNAUTHORIZED") != null);
}

test "dispatch returns 404 for unknown route" {
    var cfg = Config{ .workspace_dir = "/tmp", .config_path = "/tmp/config.json", .allocator = std.testing.allocator };
    cfg.gateway.admin_api = true;
    const result = dispatch(
        std.testing.allocator,
        "GET /api/v1/unknown HTTP/1.1\r\n\r\n",
        "GET",
        "/api/v1/unknown",
        "/api/v1/unknown",
        &cfg,
        true,
    );
    try std.testing.expectEqualStrings("404 Not Found", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "NOT_FOUND") != null);
}

test "dispatch GET /api/v1/health returns success envelope" {
    health.reset();
    health.markComponentOk("gateway");

    var cfg = Config{ .workspace_dir = "/tmp", .config_path = "/tmp/config.json", .allocator = std.testing.allocator };
    cfg.gateway.admin_api = true;
    const result = dispatch(
        std.testing.allocator,
        "GET /api/v1/health HTTP/1.1\r\n\r\n",
        "GET",
        "/api/v1/health",
        "/api/v1/health",
        &cfg,
        true,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "uptime_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "components") != null);
}

test "dispatch method mismatch returns 404" {
    var cfg = Config{ .workspace_dir = "/tmp", .config_path = "/tmp/config.json", .allocator = std.testing.allocator };
    cfg.gateway.admin_api = true;
    const result = dispatch(
        std.testing.allocator,
        "POST /api/v1/health HTTP/1.1\r\n\r\n",
        "POST",
        "/api/v1/health",
        "/api/v1/health",
        &cfg,
        true,
    );
    try std.testing.expectEqualStrings("404 Not Found", result.status);
}
