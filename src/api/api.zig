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
const version = @import("../version.zig");
const config_mutator = @import("../config_mutator.zig");
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
pub const registry: []const Endpoint = &.{
    // Phase 0
    .{ .method = "GET", .path = "/api/v1/health", .handler = handleHealth },
    // Phase 1
    .{ .method = "GET", .path = "/api/v1/status", .handler = handleStatus },
    .{ .method = "GET", .path = "/api/v1/config", .handler = handleConfig },
    .{ .method = "GET", .path = "/api/v1/models", .handler = handleModels },
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

// ── Phase 1 handlers ────────────────────────────────────────────────

/// GET /api/v1/status
///
/// Returns runtime identity: version string, pid, and uptime.
/// Lighter than /api/v1/health — no component detail, just the basics
/// needed to verify connectivity and binary identity.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": {
///     "version": "v2026.4.4",
///     "pid": 12345,
///     "uptime_seconds": 3600
///   },
///   "error": null
/// }
/// ```
fn handleStatus(ctx: *ApiContext) anyerror!void {
    const snap = health.snapshot();
    const data = try std.fmt.allocPrint(
        ctx.allocator,
        "{{\"version\":\"{s}\",\"pid\":{d},\"uptime_seconds\":{d}}}",
        .{ version.string, snap.pid, snap.uptime_seconds },
    );
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// GET /api/v1/config?path=<dotted.path>
///
/// Read a single config value at the given dotted path (e.g.
/// `gateway.admin_api`, `default_provider`).  The value is returned as
/// its JSON representation.
///
/// Uses config_mutator.getPathValueJson which reads from the on-disk
/// config file, so it always reflects the persisted state (not the
/// in-memory merged state).
///
/// Query parameters:
///   path  (required) — dotted config path, e.g. "gateway.port"
///
/// Response shape (value is a raw JSON value):
/// ```json
/// {"success":true,"data":{"path":"gateway.port","value":3000},"error":null}
/// ```
///
/// Errors:
///   MISSING_PARAM  — path query parameter not provided
///   CONFIG_ERROR   — path not found or config unreadable
fn handleConfig(ctx: *ApiContext) anyerror!void {
    // Extract path query param from target, e.g. /api/v1/config?path=foo.bar
    const path_param = extractQueryParam(ctx.target, "path") orelse {
        try ctx.sendError("400 Bad Request", "MISSING_PARAM", "query parameter 'path' is required");
        return;
    };

    const value_json = config_mutator.getPathValueJson(ctx.allocator, path_param) catch |err| {
        const msg = try std.fmt.allocPrint(ctx.allocator, "config read failed: {s}", .{@errorName(err)});
        defer ctx.allocator.free(msg);
        try ctx.sendError("500 Internal Server Error", "CONFIG_ERROR", msg);
        return;
    };
    defer ctx.allocator.free(value_json);

    // Escape path_param for JSON string embedding.
    const escaped_path = try jsonEscapeString(ctx.allocator, path_param);
    defer ctx.allocator.free(escaped_path);

    const data = try std.fmt.allocPrint(
        ctx.allocator,
        "{{\"path\":\"{s}\",\"value\":{s}}}",
        .{ escaped_path, value_json },
    );
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// GET /api/v1/models
///
/// Lists configured provider entries from the in-memory config.
/// Returns the provider name and whether an API key is set.
/// Never returns the API key value itself.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": {
///     "default_provider": "openrouter",
///     "default_model": "openai/gpt-4o",
///     "providers": [
///       {"name": "openrouter", "has_key": true},
///       {"name": "ollama", "has_key": false}
///     ]
///   },
///   "error": null
/// }
/// ```
fn handleModels(ctx: *ApiContext) anyerror!void {
    // config_opt is always non-null here: dispatch() checks admin_api first,
    // which is false when config is null, so it returns 403 before reaching handlers.
    const cfg = ctx.config_opt.?;

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    const w = buf.writer(ctx.allocator);

    try w.print("{{\"default_provider\":\"{s}\"", .{cfg.default_provider});
    if (cfg.default_model) |dm| {
        const escaped = try jsonEscapeString(ctx.allocator, dm);
        defer ctx.allocator.free(escaped);
        try w.print(",\"default_model\":\"{s}\"", .{escaped});
    } else {
        try w.writeAll(",\"default_model\":null");
    }
    try w.writeAll(",\"providers\":[");
    for (cfg.providers, 0..) |entry, i| {
        if (i > 0) try w.writeByte(',');
        const escaped_name = try jsonEscapeString(ctx.allocator, entry.name);
        defer ctx.allocator.free(escaped_name);
        try w.print("{{\"name\":\"{s}\",\"has_key\":{s}}}", .{
            escaped_name,
            if (entry.api_key != null) "true" else "false",
        });
    }
    try w.writeAll("]}");

    const data = try ctx.allocator.dupe(u8, buf.items);
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

// ── Phase 1 helpers ──────────────────────────────────────────────────

/// Extract the value of a query parameter from a URL target string.
/// e.g. extractQueryParam("/api/v1/config?path=foo.bar", "path") → "foo.bar"
/// Returns null if the parameter is absent or has no value.
fn extractQueryParam(target: []const u8, param: []const u8) ?[]const u8 {
    const q_pos = std.mem.indexOfScalar(u8, target, '?') orelse return null;
    var query = target[q_pos + 1 ..];
    while (query.len > 0) {
        const amp = std.mem.indexOfScalar(u8, query, '&') orelse query.len;
        const pair = query[0..amp];
        if (std.mem.indexOfScalar(u8, pair, '=')) |eq_pos| {
            const key = pair[0..eq_pos];
            const val = pair[eq_pos + 1 ..];
            if (std.mem.eql(u8, key, param) and val.len > 0) return val;
        }
        query = if (amp < query.len) query[amp + 1 ..] else "";
    }
    return null;
}

/// Escape a UTF-8 string for embedding inside a JSON string value.
/// Escapes backslash, double-quote, and the standard control characters.
fn jsonEscapeString(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator); // deinit only on error; caller owns on success
    const w = out.writer(allocator);
    for (input) |c| {
        switch (c) {
            '\\' => try w.writeAll("\\\\"),
            '"' => try w.writeAll("\\\""),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => try w.print("\\u{x:0>4}", .{c}),
            else => try w.writeByte(c),
        }
    }
    return out.toOwnedSlice(allocator);
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

// ── Phase 1 tests ────────────────────────────────────────────────────

test "dispatch GET /api/v1/status returns version and uptime" {
    health.reset();
    var cfg = Config{ .workspace_dir = "/tmp", .config_path = "/tmp/config.json", .allocator = std.testing.allocator };
    cfg.gateway.admin_api = true;
    const result = dispatch(
        std.testing.allocator,
        "GET /api/v1/status HTTP/1.1\r\n\r\n",
        "GET",
        "/api/v1/status",
        "/api/v1/status",
        &cfg,
        true,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"version\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"pid\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"uptime_seconds\"") != null);
}

test "dispatch GET /api/v1/config missing param returns 400" {
    var cfg = Config{ .workspace_dir = "/tmp", .config_path = "/tmp/config.json", .allocator = std.testing.allocator };
    cfg.gateway.admin_api = true;
    const result = dispatch(
        std.testing.allocator,
        "GET /api/v1/config HTTP/1.1\r\n\r\n",
        "GET",
        "/api/v1/config",
        "/api/v1/config",
        &cfg,
        true,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("400 Bad Request", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MISSING_PARAM") != null);
}

test "dispatch GET /api/v1/models returns provider list" {
    const config_types = @import("../config_types.zig");
    const providers = [_]config_types.ProviderEntry{
        .{ .name = "openrouter", .api_key = "sk-test" },
        .{ .name = "ollama" },
    };
    var cfg = Config{ .workspace_dir = "/tmp", .config_path = "/tmp/config.json", .allocator = std.testing.allocator };
    cfg.gateway.admin_api = true;
    cfg.providers = &providers;
    cfg.default_provider = "openrouter";
    const result = dispatch(
        std.testing.allocator,
        "GET /api/v1/models HTTP/1.1\r\n\r\n",
        "GET",
        "/api/v1/models",
        "/api/v1/models",
        &cfg,
        true,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "openrouter") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "ollama") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"has_key\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"has_key\":false") != null);
    // API key value must not appear in response.
    try std.testing.expect(std.mem.indexOf(u8, result.body, "sk-test") == null);
}

test "dispatch GET /api/v1/models no config returns 403 disabled" {
    // When config is null, admin_api defaults to false → 403 ADMIN_API_DISABLED
    // before any handler is reached.  There is no reachable path to handleModels
    // with a null config.
    const result = dispatch(
        std.testing.allocator,
        "GET /api/v1/models HTTP/1.1\r\n\r\n",
        "GET",
        "/api/v1/models",
        "/api/v1/models",
        null, // no config → admin_api=false → 403
        true,
    );
    try std.testing.expectEqualStrings("403 Forbidden", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "ADMIN_API_DISABLED") != null);
}

test "extractQueryParam finds value" {
    try std.testing.expectEqualStrings("foo.bar", extractQueryParam("/api/v1/config?path=foo.bar", "path").?);
}

test "extractQueryParam returns null when absent" {
    try std.testing.expect(extractQueryParam("/api/v1/config", "path") == null);
}

test "extractQueryParam returns null for empty value" {
    try std.testing.expect(extractQueryParam("/api/v1/config?path=", "path") == null);
}

test "jsonEscapeString escapes special chars" {
    const out = try jsonEscapeString(std.testing.allocator, "a\"b\\c\nd");
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("a\\\"b\\\\c\\nd", out);
}
