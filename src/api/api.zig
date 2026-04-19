//! REST Admin API — router and endpoint registry.
//!
//! All endpoints live under /api/.  The surface is opt-in: when
//! `gateway.admin_api` is false (the default) every request to /api/*
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
//! /api/cron/:id/run) the Endpoint.path field uses "/:param/" or ends
//! with "/:param".  matchPath() extracts the dynamic segment and stores it
//! in ApiContext.path_param.

const std = @import("std");
const builtin = @import("builtin");
const health = @import("../health.zig");
const version = @import("../version.zig");
const config_mutator = @import("../config_mutator.zig");
const cron_mod = @import("../cron.zig");
const agent_routing = @import("../agent_routing.zig");
const Config = @import("../config.zig").Config;
const ApiContext = @import("context.zig").ApiContext;

// ── Endpoint registry ────────────────────────────────────────────────

pub const Endpoint = struct {
    /// HTTP method string, e.g. "GET".
    method: []const u8,
    /// URL path, e.g. "/api/status".
    /// A "/:param" segment is a single dynamic path segment.
    path: []const u8,
    /// Handler function.  Must not panic; errors are caught by the dispatcher.
    handler: *const fn (ctx: *ApiContext) anyerror!void,
};

/// Comptime-built slice of all registered /api/* endpoints.
pub const registry: []const Endpoint = &.{
    // Phase 1
    .{ .method = "GET", .path = "/api/status", .handler = handleStatus },
    .{ .method = "GET", .path = "/api/config", .handler = handleConfig },
    .{ .method = "GET", .path = "/api/models", .handler = handleModels },
    // Phase 2 — cron
    .{ .method = "GET", .path = "/api/cron", .handler = handleCronList },
    .{ .method = "POST", .path = "/api/cron", .handler = handleCronCreate },
    .{ .method = "POST", .path = "/api/cron/once", .handler = handleCronCreateOnce },
    .{ .method = "POST", .path = "/api/cron/:id/run", .handler = handleCronRun },
    .{ .method = "POST", .path = "/api/cron/:id/pause", .handler = handleCronPause },
    .{ .method = "POST", .path = "/api/cron/:id/resume", .handler = handleCronResume },
    .{ .method = "PATCH", .path = "/api/cron/:id", .handler = handleCronUpdate },
    .{ .method = "DELETE", .path = "/api/cron/:id", .handler = handleCronDelete },
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
/// starts with "/api/".
///
/// `scheduler_opt` is the live CronScheduler, already locked by the caller.
/// The caller is responsible for unlocking it after this function returns.
/// Pass null when no scheduler is running (scheduler endpoints return 503).
///
/// Parameters:
///   allocator      — request-scoped arena allocator
///   raw_request    — full raw HTTP bytes
///   method         — HTTP method string
///   target         — full request target (may include query string)
///   base_path      — target without query string
///   config_opt     — active config or null
///   auth_ok        — true when the bearer token has already been validated
///                    by the caller (gateway.zig) using isWebhookAuthorized.
///   scheduler_opt  — live CronScheduler (already mutex-locked by caller), or null.
pub fn dispatch(
    allocator: std.mem.Allocator,
    raw_request: []const u8,
    method: []const u8,
    target: []const u8,
    base_path: []const u8,
    config_opt: ?*const Config,
    auth_ok: bool,
    scheduler_opt: ?*cron_mod.CronScheduler,
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

    // Route: walk registry for exact path + method match, then try prefix
    // match for dynamic /:param segments.
    var ctx = ApiContext{
        .allocator = allocator,
        .raw_request = raw_request,
        .method = method,
        .target = target,
        .base_path = base_path,
        .config_opt = config_opt,
        .scheduler_opt = scheduler_opt,
    };

    // Pass 1: exact match.
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

    // Pass 2: prefix match for dynamic /:param segments.
    // Pattern: replace the /:param segment with the actual path segment and
    // store the extracted value in ctx.path_param.
    for (registry) |ep| {
        if (!std.mem.eql(u8, ep.method, method)) continue;
        if (matchPathParam(ep.path, base_path)) |param| {
            ctx.path_param = param;
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

// ── Path matching ─────────────────────────────────────────────────────

/// Match a pattern containing exactly one "/:param" segment against a concrete
/// path.  Returns the extracted parameter value if the pattern matches,
/// otherwise null.
///
/// Examples:
///   matchPathParam("/api/cron/:id/run", "/api/cron/abc123/run") → "abc123"
///   matchPathParam("/api/cron/:id",     "/api/cron/abc123")     → "abc123"
///   matchPathParam("/api/cron/:id/run", "/api/cron/abc123")     → null
fn matchPathParam(pattern: []const u8, path: []const u8) ?[]const u8 {
    // Find the "/:param" segment position.
    const sep = std.mem.indexOf(u8, pattern, "/:") orelse return null;
    // Prefix before /:param must match literally.
    const prefix = pattern[0..sep];
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    // The remainder of the path starts after the prefix.
    const rest = path[prefix.len..];
    // rest must start with '/'.
    if (rest.len == 0 or rest[0] != '/') return null;
    const after_slash = rest[1..];
    // Find what comes after /:param in the pattern (the suffix).
    // sep points to '/'; find the next '/' after ":param".
    const param_end_in_pattern = std.mem.indexOfScalarPos(u8, pattern, sep + 2, '/') orelse pattern.len;
    const suffix = pattern[param_end_in_pattern..];
    if (suffix.len == 0) {
        // No suffix — the entire remainder is the param value.
        // Reject if path has additional segments.
        if (std.mem.indexOfScalar(u8, after_slash, '/') != null) return null;
        if (after_slash.len == 0) return null;
        return after_slash;
    } else {
        // suffix must appear at the end of the path's remainder.
        if (!std.mem.endsWith(u8, after_slash, suffix)) return null;
        const param = after_slash[0 .. after_slash.len - suffix.len];
        if (param.len == 0) return null;
        // Param itself must not contain '/'.
        if (std.mem.indexOfScalar(u8, param, '/') != null) return null;
        return param;
    }
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

// ── Phase 1 handlers ────────────────────────────────────────────────

/// GET /api/status
///
/// Returns runtime identity and structured component health from the
/// global registry: version string, pid, uptime, overall status, and
/// per-component detail.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": {
///     "version": "v2026.4.4",
///     "pid": 12345,
///     "uptime_seconds": 3600,
///     "status": "ok",
///     "components": {
///       "gateway": { "status": "ok", "restart_count": 0 }
///     }
///   },
///   "error": null
/// }
/// ```
///
/// `status` is `"ok"` when all components report `"ok"`, otherwise `"degraded"`.
fn handleStatus(ctx: *ApiContext) anyerror!void {
    const snap = health.snapshot();

    // Determine overall status from component health.
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

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    const w = buf.writer(ctx.allocator);

    try w.print(
        "{{\"version\":\"{s}\",\"pid\":{d},\"uptime_seconds\":{d},\"status\":\"{s}\",\"components\":{{",
        .{ version.string, snap.pid, snap.uptime_seconds, overall },
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
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// GET /api/config?path=<dotted.path>
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
    // Extract path query param from target, e.g. /api/config?path=foo.bar
    const path_param = extractQueryParam(ctx.target, "path") orelse {
        try ctx.sendError("400 Bad Request", "MISSING_PARAM", "query parameter 'path' is required");
        return;
    };

    // Guard: only non-sensitive paths may be read via the API.
    // Paths such as models.providers.*.api_key, channels.*.bot_token, and
    // security.* are intentionally absent from the read allowlist.
    if (!config_mutator.isAllowedReadPath(path_param)) {
        try ctx.sendError("403 Forbidden", "PATH_FORBIDDEN", "that config path is not readable via the API");
        return;
    }

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

/// GET /api/models
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

// ── Phase 2 handlers — cron ──────────────────────────────────────────

/// GET /api/cron
///
/// Returns the list of all scheduled jobs.  Mirrors GET /cron but wraps
/// the array in the standard success envelope and includes all job fields.
///
/// Response shape:
/// ```json
/// {"success":true,"data":[{...job...}],"error":null}
/// ```
fn handleCronList(ctx: *ApiContext) anyerror!void {
    const sched = ctx.scheduler_opt orelse {
        try ctx.sendError("503 Service Unavailable", "SCHEDULER_UNAVAILABLE", "scheduler not running");
        return;
    };

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    const w = buf.writer(ctx.allocator);

    try w.writeByte('[');
    const jobs = sched.listJobs();
    for (jobs, 0..) |job, i| {
        if (i > 0) try w.writeByte(',');
        try appendCronJobJson(&buf, ctx.allocator, job);
    }
    try w.writeByte(']');

    const data = try ctx.allocator.dupe(u8, buf.items);
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// POST /api/cron
///
/// Create a new recurring cron job.  Mirrors POST /cron/add.
/// Body: same JSON fields as the legacy endpoint.
/// Response: the created job object wrapped in the success envelope.
fn handleCronCreate(ctx: *ApiContext) anyerror!void {
    const sched = ctx.scheduler_opt orelse {
        try ctx.sendError("503 Service Unavailable", "SCHEDULER_UNAVAILABLE", "scheduler not running");
        return;
    };
    const raw_body = ctx.body() orelse {
        try ctx.sendError("400 Bad Request", "MISSING_BODY", "request body required");
        return;
    };
    const job_ptr = try parseCronCreateBody(ctx, sched, raw_body, false) orelse return;
    cron_mod.saveJobs(sched) catch {};

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    try appendCronJobJson(&buf, ctx.allocator, job_ptr.*);
    const data = try ctx.allocator.dupe(u8, buf.items);
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// POST /api/cron/once
///
/// Create a one-shot delayed job.  Mirrors POST /cron/add with a delay field.
/// Body: same JSON fields as the legacy endpoint (use "delay" instead of "expression").
/// Response: the created job object wrapped in the success envelope.
fn handleCronCreateOnce(ctx: *ApiContext) anyerror!void {
    const sched = ctx.scheduler_opt orelse {
        try ctx.sendError("503 Service Unavailable", "SCHEDULER_UNAVAILABLE", "scheduler not running");
        return;
    };
    const raw_body = ctx.body() orelse {
        try ctx.sendError("400 Bad Request", "MISSING_BODY", "request body required");
        return;
    };
    const job_ptr = try parseCronCreateBody(ctx, sched, raw_body, true) orelse return;
    cron_mod.saveJobs(sched) catch {};

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    try appendCronJobJson(&buf, ctx.allocator, job_ptr.*);
    const data = try ctx.allocator.dupe(u8, buf.items);
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// POST /api/cron/:id/run
///
/// Trigger a job to run immediately by setting next_run_secs = 0.
/// The scheduler will execute it on its next tick.
///
/// Response: {"triggered":true,"id":"<id>"}
fn handleCronRun(ctx: *ApiContext) anyerror!void {
    const sched = ctx.scheduler_opt orelse {
        try ctx.sendError("503 Service Unavailable", "SCHEDULER_UNAVAILABLE", "scheduler not running");
        return;
    };
    const id = ctx.path_param orelse {
        try ctx.sendError("400 Bad Request", "MISSING_ID", "job id required in path");
        return;
    };
    const job = sched.getMutableJob(id) orelse {
        try ctx.sendError("404 Not Found", "JOB_NOT_FOUND", "no job with that id");
        return;
    };
    // Set next_run_secs to 0 so the scheduler's next tick fires it immediately.
    job.next_run_secs = 0;
    cron_mod.saveJobs(sched) catch {};

    const escaped_id = try jsonEscapeString(ctx.allocator, id);
    defer ctx.allocator.free(escaped_id);
    const data = try std.fmt.allocPrint(
        ctx.allocator,
        "{{\"triggered\":true,\"id\":\"{s}\"}}",
        .{escaped_id},
    );
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// POST /api/cron/:id/pause
///
/// Pause a job.  Mirrors POST /cron/pause.
/// Response: {"paused":true,"id":"<id>"}
fn handleCronPause(ctx: *ApiContext) anyerror!void {
    const sched = ctx.scheduler_opt orelse {
        try ctx.sendError("503 Service Unavailable", "SCHEDULER_UNAVAILABLE", "scheduler not running");
        return;
    };
    const id = ctx.path_param orelse {
        try ctx.sendError("400 Bad Request", "MISSING_ID", "job id required in path");
        return;
    };
    if (!sched.pauseJob(id)) {
        try ctx.sendError("404 Not Found", "JOB_NOT_FOUND", "no job with that id");
        return;
    }
    cron_mod.saveJobs(sched) catch {};

    const escaped_id = try jsonEscapeString(ctx.allocator, id);
    defer ctx.allocator.free(escaped_id);
    const data = try std.fmt.allocPrint(
        ctx.allocator,
        "{{\"paused\":true,\"id\":\"{s}\"}}",
        .{escaped_id},
    );
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// POST /api/cron/:id/resume
///
/// Resume a paused job.  Mirrors POST /cron/resume.
/// Response: {"resumed":true,"id":"<id>"}
fn handleCronResume(ctx: *ApiContext) anyerror!void {
    const sched = ctx.scheduler_opt orelse {
        try ctx.sendError("503 Service Unavailable", "SCHEDULER_UNAVAILABLE", "scheduler not running");
        return;
    };
    const id = ctx.path_param orelse {
        try ctx.sendError("400 Bad Request", "MISSING_ID", "job id required in path");
        return;
    };
    if (!sched.resumeJob(id)) {
        try ctx.sendError("404 Not Found", "JOB_NOT_FOUND", "no job with that id");
        return;
    }
    cron_mod.saveJobs(sched) catch {};

    const escaped_id = try jsonEscapeString(ctx.allocator, id);
    defer ctx.allocator.free(escaped_id);
    const data = try std.fmt.allocPrint(
        ctx.allocator,
        "{{\"resumed\":true,\"id\":\"{s}\"}}",
        .{escaped_id},
    );
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// PATCH /api/cron/:id
///
/// Update fields on an existing job.  Mirrors POST /cron/update.
/// Body: JSON object with optional fields: expression, command, prompt,
///       model, session_target, enabled, paused, delete_after_run.
/// Response: {"updated":true,"id":"<id>"}
fn handleCronUpdate(ctx: *ApiContext) anyerror!void {
    const sched = ctx.scheduler_opt orelse {
        try ctx.sendError("503 Service Unavailable", "SCHEDULER_UNAVAILABLE", "scheduler not running");
        return;
    };
    const id = ctx.path_param orelse {
        try ctx.sendError("400 Bad Request", "MISSING_ID", "job id required in path");
        return;
    };
    const raw_body = ctx.body() orelse {
        try ctx.sendError("400 Bad Request", "MISSING_BODY", "request body required");
        return;
    };
    const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, raw_body, .{}) catch {
        try ctx.sendError("400 Bad Request", "INVALID_JSON", "request body must be valid JSON");
        return;
    };
    defer parsed.deinit();
    if (parsed.value != .object) {
        try ctx.sendError("400 Bad Request", "INVALID_JSON", "request body must be a JSON object");
        return;
    }
    const obj = parsed.value.object;

    const expression = cronObjectStringField(obj, "expression");
    const command = cronObjectStringField(obj, "command");
    const prompt = cronObjectStringField(obj, "prompt");
    const model = cronObjectStringField(obj, "model");
    const session_target_opt = if (cronObjectStringField(obj, "session_target")) |raw|
        cron_mod.SessionTarget.parseStrict(raw) catch {
            try ctx.sendError("400 Bad Request", "INVALID_SESSION_TARGET", "invalid session_target value");
            return;
        }
    else
        null;
    const paused_opt = cronObjectBoolField(obj, "paused");
    const enabled_explicit = cronObjectBoolField(obj, "enabled");
    const enabled_opt = if (enabled_explicit) |en|
        en
    else if (paused_opt) |p|
        !p
    else
        null;
    const delete_after_run_opt = cronObjectBoolField(obj, "delete_after_run");

    if (session_target_opt != null) {
        const existing = sched.getJob(id) orelse {
            try ctx.sendError("404 Not Found", "JOB_NOT_FOUND", "no job with that id");
            return;
        };
        if (existing.job_type != .agent) {
            try ctx.sendError("400 Bad Request", "INVALID_FIELD", "session_target requires an agent job");
            return;
        }
    }

    const patch = cron_mod.CronJobPatch{
        .expression = expression,
        .command = command,
        .prompt = prompt,
        .model = model,
        .session_target = session_target_opt,
        .enabled = enabled_opt,
        .delete_after_run = delete_after_run_opt,
    };
    if (!sched.updateJob(ctx.allocator, id, patch)) {
        try ctx.sendError("404 Not Found", "JOB_NOT_FOUND", "no job with that id or update failed");
        return;
    }
    cron_mod.saveJobs(sched) catch {};

    const escaped_id = try jsonEscapeString(ctx.allocator, id);
    defer ctx.allocator.free(escaped_id);
    const data = try std.fmt.allocPrint(
        ctx.allocator,
        "{{\"updated\":true,\"id\":\"{s}\"}}",
        .{escaped_id},
    );
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// DELETE /api/cron/:id
///
/// Remove a job.  Mirrors POST /cron/remove.
/// Response: {"deleted":true,"id":"<id>"}
fn handleCronDelete(ctx: *ApiContext) anyerror!void {
    const sched = ctx.scheduler_opt orelse {
        try ctx.sendError("503 Service Unavailable", "SCHEDULER_UNAVAILABLE", "scheduler not running");
        return;
    };
    const id = ctx.path_param orelse {
        try ctx.sendError("400 Bad Request", "MISSING_ID", "job id required in path");
        return;
    };
    if (!sched.removeJob(id)) {
        try ctx.sendError("404 Not Found", "JOB_NOT_FOUND", "no job with that id");
        return;
    }
    cron_mod.saveJobs(sched) catch {};

    const escaped_id = try jsonEscapeString(ctx.allocator, id);
    defer ctx.allocator.free(escaped_id);
    const data = try std.fmt.allocPrint(
        ctx.allocator,
        "{{\"deleted\":true,\"id\":\"{s}\"}}",
        .{escaped_id},
    );
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

// ── Phase 2 helpers ──────────────────────────────────────────────────

/// Parse the JSON body for POST /api/cron and POST /api/cron/once.
/// When `once_only` is true the body must have a "delay" field; when false
/// it must have an "expression" field.
/// Returns the newly created *CronJob on success, or null after writing an
/// error response.
fn parseCronCreateBody(
    ctx: *ApiContext,
    sched: *cron_mod.CronScheduler,
    raw_body: []const u8,
    once_only: bool,
) anyerror!?*cron_mod.CronJob {
    const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, raw_body, .{}) catch {
        try ctx.sendError("400 Bad Request", "INVALID_JSON", "request body must be valid JSON");
        return null;
    };
    defer parsed.deinit();
    if (parsed.value != .object) {
        try ctx.sendError("400 Bad Request", "INVALID_JSON", "request body must be a JSON object");
        return null;
    }
    const obj = parsed.value.object;

    const expression_opt = cronObjectStringField(obj, "expression");
    const delay_opt = cronObjectStringField(obj, "delay");

    // For the /once endpoint we require a delay; for the recurring endpoint
    // we require an expression.  Validate mutual exclusion.
    if (once_only) {
        if (expression_opt != null) {
            try ctx.sendError("400 Bad Request", "INVALID_FIELD", "provide delay, not expression, for one-shot jobs");
            return null;
        }
        if (delay_opt == null) {
            try ctx.sendError("400 Bad Request", "MISSING_FIELD", "delay field required for one-shot jobs");
            return null;
        }
    } else {
        if (delay_opt != null) {
            try ctx.sendError("400 Bad Request", "INVALID_FIELD", "provide expression, not delay, for recurring jobs");
            return null;
        }
        if (expression_opt == null) {
            try ctx.sendError("400 Bad Request", "MISSING_FIELD", "expression field required for recurring jobs");
            return null;
        }
    }

    const prompt_opt = cronObjectStringField(obj, "prompt");
    const command_opt = cronObjectStringField(obj, "command");
    const model_opt = cronObjectStringField(obj, "model");

    const session_target = if (cronObjectStringField(obj, "session_target")) |raw|
        cron_mod.SessionTarget.parseStrict(raw) catch {
            try ctx.sendError("400 Bad Request", "INVALID_SESSION_TARGET", "invalid session_target value");
            return null;
        }
    else
        cron_mod.SessionTarget.isolated;

    const delivery_mode_opt = cronObjectStringField(obj, "delivery_mode");
    const delivery_channel_opt = cronObjectStringField(obj, "delivery_channel");
    const delivery_account_id_opt = cronObjectStringField(obj, "delivery_account_id");
    const delivery_to_opt = cronObjectStringField(obj, "delivery_to");
    const delivery_peer_kind: ?agent_routing.ChatType = blk: {
        const raw = cronObjectStringField(obj, "delivery_peer_kind") orelse break :blk null;
        if (std.mem.eql(u8, raw, "direct")) break :blk .direct;
        if (std.mem.eql(u8, raw, "group")) break :blk .group;
        if (std.mem.eql(u8, raw, "channel")) break :blk .channel;
        try ctx.sendError("400 Bad Request", "INVALID_FIELD", "invalid delivery_peer_kind");
        return null;
    };
    const delivery_peer_id_opt = cronObjectStringField(obj, "delivery_peer_id");
    const delivery_thread_id_opt = cronObjectStringField(obj, "delivery_thread_id");
    const delivery_best_effort = cronObjectBoolField(obj, "delivery_best_effort") orelse true;

    if (prompt_opt == null and session_target != .isolated) {
        try ctx.sendError("400 Bad Request", "INVALID_FIELD", "session_target requires prompt");
        return null;
    }

    const delivery = cron_mod.enrichDeliveryRouting(.{
        .mode = if (delivery_mode_opt) |raw|
            cron_mod.DeliveryMode.parse(raw)
        else if (delivery_channel_opt != null or delivery_account_id_opt != null or delivery_to_opt != null)
            .always
        else
            .none,
        .channel = delivery_channel_opt,
        .account_id = delivery_account_id_opt,
        .to = delivery_to_opt,
        .peer_kind = delivery_peer_kind,
        .peer_id = delivery_peer_id_opt,
        .thread_id = delivery_thread_id_opt,
        .best_effort = delivery_best_effort,
        .channel_owned = false,
        .account_id_owned = false,
        .to_owned = false,
    });

    const job_ptr = if (delay_opt) |delay|
        if (prompt_opt != null)
            sched.addAgentOnce(delay, prompt_opt.?, model_opt, delivery) catch |err| {
                const msg = cronAddError(err);
                try ctx.sendError("400 Bad Request", "CREATE_FAILED", msg);
                return null;
            }
        else blk: {
            const cmd = command_opt orelse {
                try ctx.sendError("400 Bad Request", "MISSING_FIELD", "command or prompt required");
                return null;
            };
            break :blk sched.addOnce(delay, cmd) catch |err| {
                const msg = cronAddError(err);
                try ctx.sendError("400 Bad Request", "CREATE_FAILED", msg);
                return null;
            };
        }
    else if (prompt_opt != null)
        sched.addAgentJob(expression_opt.?, prompt_opt.?, model_opt, delivery) catch |err| {
            const msg = cronAddError(err);
            try ctx.sendError("400 Bad Request", "CREATE_FAILED", msg);
            return null;
        }
    else blk: {
        const cmd = command_opt orelse {
            try ctx.sendError("400 Bad Request", "MISSING_FIELD", "command or prompt required");
            return null;
        };
        break :blk sched.addJob(expression_opt.?, cmd) catch |err| {
            const msg = cronAddError(err);
            try ctx.sendError("400 Bad Request", "CREATE_FAILED", msg);
            return null;
        };
    };

    job_ptr.session_target = session_target;
    return job_ptr;
}

fn cronAddError(err: anyerror) []const u8 {
    return switch (err) {
        error.MaxTasksReached => "max tasks reached",
        error.InvalidCronExpression => "invalid cron expression",
        error.EmptyDelay,
        error.InvalidDurationNumber,
        error.UnknownDurationUnit,
        error.DurationTooLarge,
        => "invalid delay",
        else => "add failed",
    };
}

/// Append a JSON object for `job` to `buf`.
/// Mirrors appendCronJobJson in gateway.zig but uses std.ArrayList.
fn appendCronJobJson(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, job: cron_mod.CronJob) !void {
    const w = buf.writer(allocator);
    try w.writeByte('{');
    try w.writeAll("\"id\":");
    try appendJsonString(buf, allocator, job.id);
    try w.writeAll(",\"expression\":");
    try appendJsonString(buf, allocator, job.expression);
    try w.writeAll(",\"command\":");
    try appendJsonString(buf, allocator, job.command);
    try w.print(",\"next_run_secs\":{d}", .{job.next_run_secs});
    if (job.last_run_secs) |lrs| {
        try w.print(",\"last_run_secs\":{d}", .{lrs});
    } else {
        try w.writeAll(",\"last_run_secs\":null");
    }
    if (job.last_status) |ls| {
        try w.writeAll(",\"last_status\":");
        try appendJsonString(buf, allocator, ls);
    } else {
        try w.writeAll(",\"last_status\":null");
    }
    try w.print(",\"paused\":{s}", .{if (job.paused) "true" else "false"});
    try w.print(",\"one_shot\":{s}", .{if (job.one_shot) "true" else "false"});
    try w.writeAll(",\"job_type\":");
    try appendJsonString(buf, allocator, job.job_type.asStr());
    try w.writeAll(",\"session_target\":");
    try appendJsonString(buf, allocator, job.session_target.asStr());
    try w.print(",\"enabled\":{s}", .{if (job.enabled) "true" else "false"});
    try w.print(",\"delete_after_run\":{s}", .{if (job.delete_after_run) "true" else "false"});
    if (job.prompt) |p| {
        try w.writeAll(",\"prompt\":");
        try appendJsonString(buf, allocator, p);
    } else {
        try w.writeAll(",\"prompt\":null");
    }
    if (job.model) |m| {
        try w.writeAll(",\"model\":");
        try appendJsonString(buf, allocator, m);
    } else {
        try w.writeAll(",\"model\":null");
    }
    try w.writeAll(",\"delivery_mode\":");
    try appendJsonString(buf, allocator, job.delivery.mode.asStr());
    if (job.delivery.channel) |ch| {
        try w.writeAll(",\"delivery_channel\":");
        try appendJsonString(buf, allocator, ch);
    } else {
        try w.writeAll(",\"delivery_channel\":null");
    }
    if (job.delivery.account_id) |aid| {
        try w.writeAll(",\"delivery_account_id\":");
        try appendJsonString(buf, allocator, aid);
    } else {
        try w.writeAll(",\"delivery_account_id\":null");
    }
    if (job.delivery.to) |to| {
        try w.writeAll(",\"delivery_to\":");
        try appendJsonString(buf, allocator, to);
    } else {
        try w.writeAll(",\"delivery_to\":null");
    }
    if (job.delivery.peer_kind) |pk| {
        try w.writeAll(",\"delivery_peer_kind\":");
        try appendJsonString(buf, allocator, switch (pk) {
            .direct => "direct",
            .group => "group",
            .channel => "channel",
        });
    } else {
        try w.writeAll(",\"delivery_peer_kind\":null");
    }
    if (job.delivery.peer_id) |pi| {
        try w.writeAll(",\"delivery_peer_id\":");
        try appendJsonString(buf, allocator, pi);
    } else {
        try w.writeAll(",\"delivery_peer_id\":null");
    }
    if (job.delivery.thread_id) |ti| {
        try w.writeAll(",\"delivery_thread_id\":");
        try appendJsonString(buf, allocator, ti);
    } else {
        try w.writeAll(",\"delivery_thread_id\":null");
    }
    try w.print(",\"delivery_best_effort\":{s}", .{if (job.delivery.best_effort) "true" else "false"});
    try w.print(",\"created_at_s\":{d}", .{job.created_at_s});
    try w.writeByte('}');
}

/// Append a JSON-escaped string literal (with surrounding quotes) to `buf`.
fn appendJsonString(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    const w = buf.writer(allocator);
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}

/// Extract a string field from a JSON object map.
fn cronObjectStringField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    if (value == .string and value.string.len > 0) return value.string;
    return null;
}

/// Extract a bool field from a JSON object map.
fn cronObjectBoolField(obj: std.json.ObjectMap, key: []const u8) ?bool {
    const value = obj.get(key) orelse return null;
    if (value == .bool) return value.bool;
    return null;
}

// ── Phase 1 helpers ──────────────────────────────────────────────────

/// Extract the value of a query parameter from a URL target string.
/// e.g. extractQueryParam("/api/config?path=foo.bar", "path") → "foo.bar"
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

fn makeEnabledCfg() Config {
    var cfg = Config{ .workspace_dir = "/tmp", .config_path = "/tmp/config.json", .allocator = std.testing.allocator };
    cfg.gateway.admin_api = true;
    return cfg;
}

test "dispatch returns 403 when admin_api disabled" {
    var cfg = Config{ .workspace_dir = "/tmp", .config_path = "/tmp/config.json", .allocator = std.testing.allocator };
    cfg.gateway.admin_api = false;
    const result = dispatch(
        std.testing.allocator,
        "GET /api/status HTTP/1.1\r\n\r\n",
        "GET",
        "/api/status",
        "/api/status",
        &cfg,
        true,
        null,
    );
    try std.testing.expectEqualStrings("403 Forbidden", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "ADMIN_API_DISABLED") != null);
}

test "dispatch returns 401 when not authorized" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/status HTTP/1.1\r\n\r\n",
        "GET",
        "/api/status",
        "/api/status",
        &cfg,
        false,
        null,
    );
    try std.testing.expectEqualStrings("401 Unauthorized", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "UNAUTHORIZED") != null);
}

test "dispatch returns 404 for unknown route" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/unknown HTTP/1.1\r\n\r\n",
        "GET",
        "/api/unknown",
        "/api/unknown",
        &cfg,
        true,
        null,
    );
    try std.testing.expectEqualStrings("404 Not Found", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "NOT_FOUND") != null);
}

test "dispatch GET /api/status returns success envelope with components" {
    health.reset();
    health.markComponentOk("gateway");

    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/status HTTP/1.1\r\n\r\n",
        "GET",
        "/api/status",
        "/api/status",
        &cfg,
        true,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"version\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"pid\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "uptime_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "components") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"status\"") != null);
}

test "dispatch method mismatch returns 404" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "POST /api/status HTTP/1.1\r\n\r\n",
        "POST",
        "/api/status",
        "/api/status",
        &cfg,
        true,
        null,
    );
    try std.testing.expectEqualStrings("404 Not Found", result.status);
}

// ── Phase 1 tests ────────────────────────────────────────────────────

test "dispatch GET /api/status returns version and uptime" {
    health.reset();
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/status HTTP/1.1\r\n\r\n",
        "GET",
        "/api/status",
        "/api/status",
        &cfg,
        true,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"version\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"pid\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"uptime_seconds\"") != null);
}

test "dispatch GET /api/config missing param returns 400" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/config HTTP/1.1\r\n\r\n",
        "GET",
        "/api/config",
        "/api/config",
        &cfg,
        true,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("400 Bad Request", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MISSING_PARAM") != null);
}

test "dispatch GET /api/config forbidden path returns 403" {
    // Regression: credential-bearing paths must never be readable via the API.
    var cfg = makeEnabledCfg();
    const sensitive_paths = [_][]const u8{
        "/api/config?path=models.providers.0.api_key",
        "/api/config?path=channels.telegram.accounts.default.bot_token",
        "/api/config?path=security.pairing.tokens",
    };
    for (sensitive_paths) |target| {
        const result = dispatch(
            std.testing.allocator,
            "GET /api/config HTTP/1.1\r\n\r\n",
            "GET",
            target,
            "/api/config",
            &cfg,
            true,
            null,
        );
        defer if (result.allocated) std.testing.allocator.free(result.body);
        try std.testing.expectEqualStrings("403 Forbidden", result.status);
        try std.testing.expect(std.mem.indexOf(u8, result.body, "PATH_FORBIDDEN") != null);
    }
}

test "dispatch GET /api/config allowed path reaches handler" {
    // Confirm the allowlist guard passes non-sensitive paths through to the
    // handler.  getPathValueJson will return an error (no on-disk config in
    // the test environment), but the important assertion is that we do NOT
    // get PATH_FORBIDDEN — the allowlist is wired correctly.
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/config HTTP/1.1\r\n\r\n",
        "GET",
        "/api/config?path=default_temperature",
        "/api/config",
        &cfg,
        true,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "PATH_FORBIDDEN") == null);
}

test "dispatch GET /api/models returns provider list" {
    const config_types = @import("../config_types.zig");
    const providers = [_]config_types.ProviderEntry{
        .{ .name = "openrouter", .api_key = "sk-test" },
        .{ .name = "ollama" },
    };
    var cfg = makeEnabledCfg();
    cfg.providers = &providers;
    cfg.default_provider = "openrouter";
    const result = dispatch(
        std.testing.allocator,
        "GET /api/models HTTP/1.1\r\n\r\n",
        "GET",
        "/api/models",
        "/api/models",
        &cfg,
        true,
        null,
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

test "dispatch GET /api/models no config returns 403 disabled" {
    // When config is null, admin_api defaults to false → 403 ADMIN_API_DISABLED
    // before any handler is reached.  There is no reachable path to handleModels
    // with a null config.
    const result = dispatch(
        std.testing.allocator,
        "GET /api/models HTTP/1.1\r\n\r\n",
        "GET",
        "/api/models",
        "/api/models",
        null, // no config → admin_api=false → 403
        true,
        null,
    );
    try std.testing.expectEqualStrings("403 Forbidden", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "ADMIN_API_DISABLED") != null);
}

test "extractQueryParam finds value" {
    try std.testing.expectEqualStrings("foo.bar", extractQueryParam("/api/config?path=foo.bar", "path").?);
}

test "extractQueryParam returns null when absent" {
    try std.testing.expect(extractQueryParam("/api/config", "path") == null);
}

test "extractQueryParam returns null for empty value" {
    try std.testing.expect(extractQueryParam("/api/config?path=", "path") == null);
}

test "jsonEscapeString escapes special chars" {
    const out = try jsonEscapeString(std.testing.allocator, "a\"b\\c\nd");
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("a\\\"b\\\\c\\nd", out);
}

// ── Path matching tests ───────────────────────────────────────────────

test "matchPathParam extracts id from trailing segment" {
    const param = matchPathParam("/api/cron/:id", "/api/cron/abc123");
    try std.testing.expect(param != null);
    try std.testing.expectEqualStrings("abc123", param.?);
}

test "matchPathParam extracts id with suffix" {
    const param = matchPathParam("/api/cron/:id/run", "/api/cron/abc123/run");
    try std.testing.expect(param != null);
    try std.testing.expectEqualStrings("abc123", param.?);
}

test "matchPathParam returns null on wrong suffix" {
    try std.testing.expect(matchPathParam("/api/cron/:id/run", "/api/cron/abc123/pause") == null);
}

test "matchPathParam returns null on extra segment" {
    try std.testing.expect(matchPathParam("/api/cron/:id", "/api/cron/abc/extra") == null);
}

test "matchPathParam returns null on missing segment" {
    try std.testing.expect(matchPathParam("/api/cron/:id", "/api/cron/") == null);
}

test "matchPathParam returns null on no param in pattern" {
    try std.testing.expect(matchPathParam("/api/cron", "/api/cron") == null);
}

// ── Phase 2 cron tests ───────────────────────────────────────────────

test "GET /api/cron returns 503 when scheduler unavailable" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/cron HTTP/1.1\r\n\r\n",
        "GET",
        "/api/cron",
        "/api/cron",
        &cfg,
        true,
        null, // no scheduler
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("503 Service Unavailable", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "SCHEDULER_UNAVAILABLE") != null);
}

test "GET /api/cron returns empty array when no jobs" {
    var scheduler = cron_mod.CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();

    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/cron HTTP/1.1\r\n\r\n",
        "GET",
        "/api/cron",
        "/api/cron",
        &cfg,
        true,
        &scheduler,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"data\":[]") != null);
}

test "GET /api/cron lists jobs" {
    var scheduler = cron_mod.CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();
    _ = try scheduler.addJob("*/5 * * * *", "echo hello");

    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/cron HTTP/1.1\r\n\r\n",
        "GET",
        "/api/cron",
        "/api/cron",
        &cfg,
        true,
        &scheduler,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "echo hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "*/5 * * * *") != null);
}

test "POST /api/cron creates job" {
    var scheduler = cron_mod.CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();

    var cfg = makeEnabledCfg();
    const raw = "POST /api/cron HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" ++
        "{\"expression\":\"0 * * * *\",\"command\":\"echo periodic\"}";
    const result = dispatch(
        std.testing.allocator,
        raw,
        "POST",
        "/api/cron",
        "/api/cron",
        &cfg,
        true,
        &scheduler,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "echo periodic") != null);
    try std.testing.expectEqual(@as(usize, 1), scheduler.listJobs().len);
}

test "POST /api/cron missing expression returns 400" {
    var scheduler = cron_mod.CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();

    var cfg = makeEnabledCfg();
    const raw = "POST /api/cron HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" ++
        "{\"command\":\"echo oops\"}";
    const result = dispatch(
        std.testing.allocator,
        raw,
        "POST",
        "/api/cron",
        "/api/cron",
        &cfg,
        true,
        &scheduler,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("400 Bad Request", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MISSING_FIELD") != null);
}

test "POST /api/cron/once creates one-shot job" {
    var scheduler = cron_mod.CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();

    var cfg = makeEnabledCfg();
    const raw = "POST /api/cron/once HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" ++
        "{\"delay\":\"1h\",\"command\":\"echo once\"}";
    const result = dispatch(
        std.testing.allocator,
        raw,
        "POST",
        "/api/cron/once",
        "/api/cron/once",
        &cfg,
        true,
        &scheduler,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "echo once") != null);
    try std.testing.expectEqual(@as(usize, 1), scheduler.listJobs().len);
    try std.testing.expect(scheduler.listJobs()[0].one_shot);
}

test "POST /api/cron/once with expression returns 400" {
    var scheduler = cron_mod.CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();

    var cfg = makeEnabledCfg();
    const raw = "POST /api/cron/once HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" ++
        "{\"expression\":\"* * * * *\",\"command\":\"echo bad\"}";
    const result = dispatch(
        std.testing.allocator,
        raw,
        "POST",
        "/api/cron/once",
        "/api/cron/once",
        &cfg,
        true,
        &scheduler,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("400 Bad Request", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "INVALID_FIELD") != null);
}

test "POST /api/cron/:id/run triggers job" {
    var scheduler = cron_mod.CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();
    const job = try scheduler.addJob("0 0 * * *", "echo daily");
    const job_id = job.id;
    // Ensure next_run_secs is in the future before trigger.
    try std.testing.expect(job.next_run_secs > 0);

    var cfg = makeEnabledCfg();
    const path = try std.fmt.allocPrint(std.testing.allocator, "/api/cron/{s}/run", .{job_id});
    defer std.testing.allocator.free(path);
    const raw = try std.fmt.allocPrint(
        std.testing.allocator,
        "POST {s} HTTP/1.1\r\n\r\n",
        .{path},
    );
    defer std.testing.allocator.free(raw);
    const result = dispatch(
        std.testing.allocator,
        raw,
        "POST",
        path,
        path,
        &cfg,
        true,
        &scheduler,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"triggered\":true") != null);
    // next_run_secs should now be 0.
    const updated = scheduler.getJob(job_id).?;
    try std.testing.expectEqual(@as(i64, 0), updated.next_run_secs);
}

test "POST /api/cron/:id/run unknown id returns 404" {
    var scheduler = cron_mod.CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();

    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "POST /api/cron/no-such-job/run HTTP/1.1\r\n\r\n",
        "POST",
        "/api/cron/no-such-job/run",
        "/api/cron/no-such-job/run",
        &cfg,
        true,
        &scheduler,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("404 Not Found", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "JOB_NOT_FOUND") != null);
}

test "POST /api/cron/:id/pause pauses job" {
    var scheduler = cron_mod.CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();
    const job = try scheduler.addJob("*/5 * * * *", "echo hi");
    const job_id = job.id;

    var cfg = makeEnabledCfg();
    const path = try std.fmt.allocPrint(std.testing.allocator, "/api/cron/{s}/pause", .{job_id});
    defer std.testing.allocator.free(path);
    const raw = try std.fmt.allocPrint(std.testing.allocator, "POST {s} HTTP/1.1\r\n\r\n", .{path});
    defer std.testing.allocator.free(raw);
    const result = dispatch(
        std.testing.allocator,
        raw,
        "POST",
        path,
        path,
        &cfg,
        true,
        &scheduler,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"paused\":true") != null);
    try std.testing.expect(scheduler.getJob(job_id).?.paused);
}

test "POST /api/cron/:id/resume resumes job" {
    var scheduler = cron_mod.CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();
    const job = try scheduler.addJob("*/5 * * * *", "echo hi");
    const job_id = job.id;
    _ = scheduler.pauseJob(job_id);

    var cfg = makeEnabledCfg();
    const path = try std.fmt.allocPrint(std.testing.allocator, "/api/cron/{s}/resume", .{job_id});
    defer std.testing.allocator.free(path);
    const raw = try std.fmt.allocPrint(std.testing.allocator, "POST {s} HTTP/1.1\r\n\r\n", .{path});
    defer std.testing.allocator.free(raw);
    const result = dispatch(
        std.testing.allocator,
        raw,
        "POST",
        path,
        path,
        &cfg,
        true,
        &scheduler,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"resumed\":true") != null);
    try std.testing.expect(!scheduler.getJob(job_id).?.paused);
}

test "PATCH /api/cron/:id updates job command" {
    var scheduler = cron_mod.CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();
    const job = try scheduler.addJob("*/5 * * * *", "echo old");
    const job_id = job.id;

    var cfg = makeEnabledCfg();
    const path = try std.fmt.allocPrint(std.testing.allocator, "/api/cron/{s}", .{job_id});
    defer std.testing.allocator.free(path);
    const raw = try std.fmt.allocPrint(
        std.testing.allocator,
        "PATCH {s} HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{{\"command\":\"echo new\"}}",
        .{path},
    );
    defer std.testing.allocator.free(raw);
    const result = dispatch(
        std.testing.allocator,
        raw,
        "PATCH",
        path,
        path,
        &cfg,
        true,
        &scheduler,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"updated\":true") != null);
    try std.testing.expectEqualStrings("echo new", scheduler.getJob(job_id).?.command);
}

test "DELETE /api/cron/:id deletes job" {
    var scheduler = cron_mod.CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();
    const job = try scheduler.addJob("*/5 * * * *", "echo bye");
    const job_id = job.id;

    var cfg = makeEnabledCfg();
    const path = try std.fmt.allocPrint(std.testing.allocator, "/api/cron/{s}", .{job_id});
    defer std.testing.allocator.free(path);
    const raw = try std.fmt.allocPrint(std.testing.allocator, "DELETE {s} HTTP/1.1\r\n\r\n", .{path});
    defer std.testing.allocator.free(raw);
    const result = dispatch(
        std.testing.allocator,
        raw,
        "DELETE",
        path,
        path,
        &cfg,
        true,
        &scheduler,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"deleted\":true") != null);
    try std.testing.expectEqual(@as(usize, 0), scheduler.listJobs().len);
}

test "DELETE /api/cron/:id unknown id returns 404" {
    var scheduler = cron_mod.CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();

    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "DELETE /api/cron/no-such-job HTTP/1.1\r\n\r\n",
        "DELETE",
        "/api/cron/no-such-job",
        "/api/cron/no-such-job",
        &cfg,
        true,
        &scheduler,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("404 Not Found", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "JOB_NOT_FOUND") != null);
}
