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
const memory_mod = @import("../memory/root.zig");
const cron_mod = @import("../cron.zig");
const agent_routing = @import("../agent_routing.zig");
const skillforge = @import("../skillforge.zig");
const Config = @import("../config.zig").Config;
const session_mod = @import("../session.zig");
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
    // Phase 4 — channels
    .{ .method = "GET", .path = "/api/channels", .handler = handleChannelList },
    .{ .method = "GET", .path = "/api/channels/:name", .handler = handleChannelGet },
    // Phase 4 — skills
    .{ .method = "GET", .path = "/api/skills", .handler = handleSkillList },
    .{ .method = "POST", .path = "/api/skills/install", .handler = handleSkillInstall },
    .{ .method = "DELETE", .path = "/api/skills/:name", .handler = handleSkillDelete },
    // Phase 7 — Agent control
    .{ .method = "POST", .path = "/api/agent", .handler = handleAgentInvoke },
    .{ .method = "POST", .path = "/api/agent/stream", .handler = handleAgentStream },
    .{ .method = "GET", .path = "/api/agent/sessions", .handler = handleAgentSessionList },
    .{ .method = "DELETE", .path = "/api/agent/sessions/:id", .handler = handleAgentSessionDelete },
    // Phase 3 — Memory
    .{ .method = "GET", .path = "/api/memory", .handler = handleMemoryList },
    .{ .method = "DELETE", .path = "/api/memory/:key", .handler = handleMemoryDelete },
    // Phase 8 — Polish
    .{ .method = "GET", .path = "/api/doctor", .handler = handleDoctor },
    .{ .method = "GET", .path = "/api/spec", .handler = handleSpec },
    .{ .method = "GET", .path = "/api/memory/stats", .handler = handleMemoryStats },
    .{ .method = "POST", .path = "/api/memory/search", .handler = handleMemorySearch },
    .{ .method = "GET", .path = "/api/memory/:key", .handler = handleMemoryGet },
    .{ .method = "GET", .path = "/api/history", .handler = handleHistory },
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
/// `session_mgr_opt` is the live SessionManager, shared with the gateway worker
/// loop.  Pass null when no session manager is running (agent endpoints return
/// 503).  Handlers that invoke agent.turn() must lock session.mutex themselves
/// using the Session.mutex field.
///
/// Parameters:
///   allocator       — request-scoped arena allocator
///   raw_request     — full raw HTTP bytes
///   method          — HTTP method string
///   target          — full request target (may include query string)
///   base_path       — target without query string
///   config_opt      — active config or null
///   auth_ok         — true when the bearer token has already been validated
///                     by the caller (gateway.zig) using isWebhookAuthorized.
///   scheduler_opt   — live CronScheduler (already mutex-locked by caller), or null.
///   session_mgr_opt — live SessionManager shared pointer, or null.
pub fn dispatch(
    allocator: std.mem.Allocator,
    raw_request: []const u8,
    method: []const u8,
    target: []const u8,
    base_path: []const u8,
    config_opt: ?*const Config,
    auth_ok: bool,
    scheduler_opt: ?*cron_mod.CronScheduler,
    session_mgr_opt: ?*session_mod.SessionManager,
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
        .session_mgr = session_mgr_opt,
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

// ── Phase 4 handlers — channels ──────────────────────────────────────

/// A comptime description entry mapping a ChannelsConfig field name to the
/// canonical channel type-name string (as returned by Channel.getName()).
const ChannelTypeEntry = struct {
    /// Field name on ChannelsConfig (e.g. "telegram").
    field: []const u8,
    /// Canonical type name used in health registry and API responses.
    type_name: []const u8,
};

/// All 22 channel types exposed by ChannelsConfig, in field declaration order.
const channel_types: []const ChannelTypeEntry = &.{
    .{ .field = "telegram", .type_name = "telegram" },
    .{ .field = "discord", .type_name = "discord" },
    .{ .field = "slack", .type_name = "slack" },
    .{ .field = "imessage", .type_name = "imessage" },
    .{ .field = "matrix", .type_name = "matrix" },
    .{ .field = "mattermost", .type_name = "mattermost" },
    .{ .field = "whatsapp", .type_name = "whatsapp" },
    .{ .field = "teams", .type_name = "teams" },
    .{ .field = "irc", .type_name = "irc" },
    .{ .field = "lark", .type_name = "lark" },
    .{ .field = "dingtalk", .type_name = "dingtalk" },
    .{ .field = "wechat", .type_name = "wechat" },
    .{ .field = "wecom", .type_name = "wecom" },
    .{ .field = "signal", .type_name = "signal" },
    .{ .field = "email", .type_name = "email" },
    .{ .field = "line", .type_name = "line" },
    .{ .field = "qq", .type_name = "qq" },
    .{ .field = "onebot", .type_name = "onebot" },
    .{ .field = "maixcam", .type_name = "maixcam" },
    .{ .field = "web", .type_name = "web" },
    .{ .field = "max", .type_name = "max" },
    .{ .field = "external", .type_name = "external" },
};

/// GET /api/channels
///
/// Lists all configured channel instances derived from the in-memory config.
/// For each configured account the response includes the channel type, account_id,
/// and health status cross-referenced from the global health registry.
///
/// Channel health is tracked per-type (not per-account) in the health registry,
/// so all accounts of the same type share the same reported status.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": [
///     {"type": "telegram", "account_id": "default", "configured": true, "status": "ok"},
///     {"type": "discord",  "account_id": "bot2",    "configured": true, "status": "unknown"}
///   ],
///   "error": null
/// }
/// ```
fn handleChannelList(ctx: *ApiContext) anyerror!void {
    const cfg = ctx.config_opt.?;
    const snap = health.snapshot();

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    const w = buf.writer(ctx.allocator);

    try w.writeByte('[');
    var first = true;

    inline for (channel_types) |ct| {
        const slice = @field(cfg.channels, ct.field);
        for (slice) |entry| {
            if (!first) try w.writeByte(',');
            first = false;
            const status = channelHealthStatus(snap, ct.type_name);
            try w.writeByte('{');
            try w.writeAll("\"type\":");
            try appendJsonString(&buf, ctx.allocator, ct.type_name);
            try w.writeAll(",\"account_id\":");
            try appendJsonString(&buf, ctx.allocator, entry.account_id);
            try w.print(",\"configured\":true,\"status\":\"{s}\"", .{status});
            try w.writeByte('}');
        }
    }

    try w.writeByte(']');

    const data = try ctx.allocator.dupe(u8, buf.items);
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// GET /api/channels/:name
///
/// Returns detail for a specific channel type.  `:name` is the channel
/// type string (e.g. `telegram`, `discord`).  If multiple accounts are
/// configured for that type, all are returned.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": {
///     "type": "telegram",
///     "status": "ok",
///     "accounts": [
///       {"account_id": "default", "configured": true}
///     ]
///   },
///   "error": null
/// }
/// ```
///
/// Errors:
///   CHANNEL_NOT_FOUND — no channel with that type name is configured.
fn handleChannelGet(ctx: *ApiContext) anyerror!void {
    const cfg = ctx.config_opt.?;
    const name = ctx.path_param orelse {
        try ctx.sendError("400 Bad Request", "MISSING_PARAM", "channel name required in path");
        return;
    };
    const snap = health.snapshot();

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    const w = buf.writer(ctx.allocator);

    var found = false;
    inline for (channel_types) |ct| {
        if (std.mem.eql(u8, ct.type_name, name)) {
            found = true;
            const slice = @field(cfg.channels, ct.field);
            const status = channelHealthStatus(snap, ct.type_name);
            const escaped_name = try jsonEscapeString(ctx.allocator, ct.type_name);
            defer ctx.allocator.free(escaped_name);
            try w.print("{{\"type\":\"{s}\",\"status\":\"{s}\",\"accounts\":[", .{ escaped_name, status });
            for (slice, 0..) |entry, i| {
                if (i > 0) try w.writeByte(',');
                try w.writeAll("{\"account_id\":");
                try appendJsonString(&buf, ctx.allocator, entry.account_id);
                try w.writeAll(",\"configured\":true}");
            }
            try w.writeAll("]}");
        }
    }

    if (!found) {
        try ctx.sendError("404 Not Found", "CHANNEL_NOT_FOUND", "no channel with that type name is configured");
        return;
    }

    const data = try ctx.allocator.dupe(u8, buf.items);
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// Look up health status for a channel type name in the snapshot.
/// Returns "ok", "error", or "unknown" if not registered.
fn channelHealthStatus(snap: health.HealthSnapshot, type_name: []const u8) []const u8 {
    const comp = snap.components.get(type_name) orelse return "unknown";
    return comp.status;
}

// ── Phase 4 handlers — skills ─────────────────────────────────────────

/// GET /api/skills
///
/// Lists installed skills by scanning the skillforge output directory.
/// Each top-level directory entry in `output_dir` is considered an installed skill.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": {
///     "output_dir": "./skills",
///     "skills": ["my-skill", "another-skill"]
///   },
///   "error": null
/// }
/// ```
fn handleSkillList(ctx: *ApiContext) anyerror!void {
    _ = ctx.config_opt.?;
    const sf_cfg = skillforge.SkillForgeConfig{};
    const output_dir = sf_cfg.output_dir;

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    const w = buf.writer(ctx.allocator);

    const escaped_dir = try jsonEscapeString(ctx.allocator, output_dir);
    defer ctx.allocator.free(escaped_dir);
    try w.print("{{\"output_dir\":\"{s}\",\"skills\":[", .{escaped_dir});

    if (!builtin.is_test) {
        var dir = std.fs.cwd().openDir(output_dir, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => {
                // Directory doesn't exist yet — return empty list.
                try w.writeAll("]}");
                const data = try ctx.allocator.dupe(u8, buf.items);
                defer ctx.allocator.free(data);
                try ctx.sendSuccess(data);
                return;
            },
            else => return err,
        };
        defer dir.close();

        var iter = dir.iterate();
        var first = true;
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;
            if (!first) try w.writeByte(',');
            first = false;
            try appendJsonString(&buf, ctx.allocator, entry.name);
        }
    }

    try w.writeAll("]}");

    const data = try ctx.allocator.dupe(u8, buf.items);
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// POST /api/skills/install
///
/// Discover and install a skill by name or URL.
/// Body: `{"name": "my-skill"}` or `{"url": "https://github.com/org/repo"}`
///
/// When `name` is provided, the GitHub skill registry is searched for a
/// matching repository and the best-scoring candidate is integrated.
/// When `url` is provided, a synthetic candidate is constructed and integrated
/// directly.
///
/// This endpoint performs live network calls (GitHub API + git clone).
/// Use `builtin.is_test` guard — the test suite must not make real network calls.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": {
///     "skill_name": "my-skill",
///     "install_path": "./skills/my-skill",
///     "already_installed": false
///   },
///   "error": null
/// }
/// ```
///
/// Errors:
///   MISSING_BODY        — no request body.
///   INVALID_JSON        — body is not valid JSON.
///   MISSING_FIELD       — neither name nor url provided.
///   SKILL_NOT_FOUND     — no matching skill found in registry (name search).
///   INSTALL_FAILED      — integration step failed.
fn handleSkillInstall(ctx: *ApiContext) anyerror!void {
    _ = ctx.config_opt.?;
    const sf_cfg = skillforge.SkillForgeConfig{};

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

    const name_opt = if (obj.get("name")) |v| if (v == .string and v.string.len > 0) v.string else null else null;
    const url_opt = if (obj.get("url")) |v| if (v == .string and v.string.len > 0) v.string else null else null;

    if (name_opt == null and url_opt == null) {
        try ctx.sendError("400 Bad Request", "MISSING_FIELD", "provide 'name' or 'url' in request body");
        return;
    }

    // In test mode do not perform real network I/O.
    // NOTE: No unit test for the live network path — would require GitHub API and git.
    // Covered by manual integration testing against a running NullClaw instance.
    if (builtin.is_test) {
        try ctx.sendError("503 Service Unavailable", "NOT_IN_TEST", "skill install not available in test mode");
        return;
    }

    // Build a SkillCandidate from name or url.
    const candidate: skillforge.SkillCandidate = blk: {
        if (url_opt) |url| {
            // Synthesize candidate from URL — derive name from last path component.
            const last_slash = std.mem.lastIndexOfScalar(u8, url, '/') orelse 0;
            const derived_name = url[last_slash + 1 ..];
            break :blk .{
                .result_name = if (derived_name.len > 0) derived_name else url,
                .repo_url = url,
                .description = "",
                .owner = "unknown",
            };
        } else {
            const query = name_opt.?;
            var candidates = skillforge.scout(ctx.allocator, query) catch |err| {
                const msg = try std.fmt.allocPrint(ctx.allocator, "scout failed: {s}", .{@errorName(err)});
                defer ctx.allocator.free(msg);
                try ctx.sendError("502 Bad Gateway", "SCOUT_FAILED", msg);
                return;
            };
            defer {
                for (candidates.items) |c| {
                    _ = c;
                }
                candidates.deinit(ctx.allocator);
            }

            if (candidates.items.len == 0) {
                try ctx.sendError("404 Not Found", "SKILL_NOT_FOUND", "no matching skill found in registry");
                return;
            }

            // Pick highest-scoring candidate.
            var best: skillforge.SkillCandidate = candidates.items[0];
            var best_score: f64 = 0.0;
            for (candidates.items) |c| {
                const eval = skillforge.evaluateCandidate(c, sf_cfg.min_score);
                if (eval.total_score > best_score) {
                    best_score = eval.total_score;
                    best = c;
                }
            }
            break :blk best;
        }
    };

    const result = skillforge.integrate(ctx.allocator, candidate, sf_cfg.output_dir) catch |err| {
        const msg = try std.fmt.allocPrint(ctx.allocator, "integration failed: {s}", .{@errorName(err)});
        defer ctx.allocator.free(msg);
        try ctx.sendError("500 Internal Server Error", "INSTALL_FAILED", msg);
        return;
    };

    if (!result.success) {
        const msg = result.error_message orelse "integration failed";
        try ctx.sendError("500 Internal Server Error", "INSTALL_FAILED", msg);
        return;
    }

    const escaped_name = try jsonEscapeString(ctx.allocator, result.skill_name);
    defer ctx.allocator.free(escaped_name);
    const escaped_path = try jsonEscapeString(ctx.allocator, result.install_path);
    defer ctx.allocator.free(escaped_path);
    const data = try std.fmt.allocPrint(
        ctx.allocator,
        "{{\"skill_name\":\"{s}\",\"install_path\":\"{s}\",\"already_installed\":false}}",
        .{ escaped_name, escaped_path },
    );
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// DELETE /api/skills/:name
///
/// Remove an installed skill by name.  Deletes the directory
/// `<output_dir>/<name>` recursively.
///
/// The name is validated with `sanitizePathComponent` to prevent
/// directory traversal.  Attempting to delete a non-existent skill
/// returns 404.
///
/// Response shape:
/// ```json
/// {"success":true,"data":{"deleted":true,"name":"my-skill"},"error":null}
/// ```
///
/// Errors:
///   MISSING_PARAM       — name not provided in path.
///   INVALID_NAME        — name contains unsafe characters or is empty.
///   SKILL_NOT_FOUND     — skill directory does not exist.
///   DELETE_FAILED       — filesystem removal failed.
fn handleSkillDelete(ctx: *ApiContext) anyerror!void {
    _ = ctx.config_opt.?;
    const sf_cfg = skillforge.SkillForgeConfig{};
    const raw_name = ctx.path_param orelse {
        try ctx.sendError("400 Bad Request", "MISSING_PARAM", "skill name required in path");
        return;
    };

    const safe_name = skillforge.sanitizePathComponent(raw_name) catch {
        try ctx.sendError("400 Bad Request", "INVALID_NAME", "skill name contains unsafe characters");
        return;
    };

    const skill_path = try std.fmt.allocPrint(ctx.allocator, "{s}/{s}", .{ sf_cfg.output_dir, safe_name });
    defer ctx.allocator.free(skill_path);

    if (!builtin.is_test) {
        // Check existence before attempting delete.
        std.fs.cwd().access(skill_path, .{}) catch {
            try ctx.sendError("404 Not Found", "SKILL_NOT_FOUND", "skill not found");
            return;
        };

        std.fs.cwd().deleteTree(skill_path) catch |err| {
            const msg = try std.fmt.allocPrint(ctx.allocator, "delete failed: {s}", .{@errorName(err)});
            defer ctx.allocator.free(msg);
            try ctx.sendError("500 Internal Server Error", "DELETE_FAILED", msg);
            return;
        };
    }

    const escaped_name = try jsonEscapeString(ctx.allocator, safe_name);
    defer ctx.allocator.free(escaped_name);
    const data = try std.fmt.allocPrint(
        ctx.allocator,
        "{{\"deleted\":true,\"name\":\"{s}\"}}",
        .{escaped_name},
    );
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

// ── Phase 7 handlers ────────────────────────────────────────────────

/// POST /api/agent
///
/// One-shot agent invocation.  Finds or creates a session for the given
/// session key, runs a single agent.turn(), and returns the response.
///
/// Request body (JSON):
/// ```json
/// { "message": "...", "session": "api:default" }
/// ```
/// `session` is optional; defaults to `"api:default"` when omitted.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": {
///     "session": "api:default",
///     "response": "...",
///     "turn_count": 1
///   },
///   "error": null
/// }
/// ```
///
/// Errors:
///   SESSION_MANAGER_UNAVAILABLE — no session manager is running (gateway
///     started without an agent runtime).
///   BAD_REQUEST                 — missing or empty `message` field.
///   AGENT_ERROR                 — agent.turn() returned an error.
fn handleAgentInvoke(ctx: *ApiContext) anyerror!void {
    // Validate inputs first so callers always get 400 before 503.
    const body_bytes = ctx.body() orelse {
        try ctx.sendError("400 Bad Request", "BAD_REQUEST", "request body is required");
        return;
    };

    // Parse JSON body: { "message": "...", "session": "..." }
    const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, body_bytes, .{}) catch {
        try ctx.sendError("400 Bad Request", "BAD_REQUEST", "invalid JSON body");
        return;
    };
    defer parsed.deinit();

    if (parsed.value != .object) {
        try ctx.sendError("400 Bad Request", "BAD_REQUEST", "body must be a JSON object");
        return;
    }

    const message_val = parsed.value.object.get("message") orelse {
        try ctx.sendError("400 Bad Request", "BAD_REQUEST", "'message' field is required");
        return;
    };
    const message: []const u8 = switch (message_val) {
        .string => |s| s,
        else => {
            try ctx.sendError("400 Bad Request", "BAD_REQUEST", "'message' must be a string");
            return;
        },
    };
    if (message.len == 0) {
        try ctx.sendError("400 Bad Request", "BAD_REQUEST", "'message' must not be empty");
        return;
    }

    const session_key: []const u8 = blk: {
        if (parsed.value.object.get("session")) |sv| {
            if (sv == .string and sv.string.len > 0) break :blk sv.string;
        }
        break :blk "api:default";
    };

    const sm = ctx.session_mgr orelse {
        try ctx.sendError("503 Service Unavailable", "SESSION_MANAGER_UNAVAILABLE", "no agent session manager is running");
        return;
    };

    const response = sm.processMessage(session_key, message, null) catch |err| {
        const msg = try std.fmt.allocPrint(ctx.allocator, "agent.turn() failed: {s}", .{@errorName(err)});
        defer ctx.allocator.free(msg);
        try ctx.sendError("500 Internal Server Error", "AGENT_ERROR", msg);
        return;
    };
    defer sm.allocator.free(response);

    // Retrieve turn count from the session.
    var turn_count: u64 = 0;
    {
        sm.mutex.lock();
        defer sm.mutex.unlock();
        if (sm.sessions.get(session_key)) |session| {
            turn_count = session.turn_count;
        }
    }

    const data = try std.fmt.allocPrint(
        ctx.allocator,
        "{{\"session\":{f},\"response\":{f},\"turn_count\":{d}}}",
        .{
            std.json.fmt(session_key, .{}),
            std.json.fmt(response, .{}),
            turn_count,
        },
    );
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// POST /api/agent/stream
///
/// SSE streaming variant of agent invocation.
///
/// NOTE: The current gateway HTTP transport uses a single-write response
/// model and does not support persistent chunked-transfer SSE connections.
/// This endpoint returns 501 Not Implemented until the gateway transport
/// is upgraded to support long-lived streaming responses.
fn handleAgentStream(ctx: *ApiContext) anyerror!void {
    try ctx.sendError(
        "501 Not Implemented",
        "NOT_IMPLEMENTED",
        "SSE streaming requires persistent connections not yet supported by the gateway HTTP transport; use POST /api/agent for synchronous invocation",
    );
}

/// GET /api/agent/sessions
///
/// List all active agent sessions with their metadata.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": {
///     "sessions": [
///       {
///         "session_key": "telegram:chat123",
///         "created_at": 1710000000,
///         "last_active": 1710001000,
///         "turn_count": 5,
///         "turn_running": false
///       }
///     ],
///     "total": 1
///   },
///   "error": null
/// }
/// ```
///
/// Errors:
///   SESSION_MANAGER_UNAVAILABLE — no session manager is running.
fn handleAgentSessionList(ctx: *ApiContext) anyerror!void {
    const sm = ctx.session_mgr orelse {
        try ctx.sendError("503 Service Unavailable", "SESSION_MANAGER_UNAVAILABLE", "no agent session manager is running");
        return;
    };

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    const w = buf.writer(ctx.allocator);

    var total: usize = 0;

    try w.writeAll("{\"sessions\":[");
    {
        sm.mutex.lock();
        defer sm.mutex.unlock();

        var it = sm.sessions.iterator();
        var first = true;
        while (it.next()) |entry| {
            const session = entry.value_ptr.*;
            if (!first) try w.writeByte(',');
            first = false;
            total += 1;
            try w.print(
                "{{\"session_key\":{f},\"created_at\":{d},\"last_active\":{d},\"turn_count\":{d},\"turn_running\":{}}}",
                .{
                    std.json.fmt(session.session_key, .{}),
                    session.created_at,
                    session.last_active,
                    session.turn_count,
                    session.turn_running.load(.seq_cst),
                },
            );
        }
    }
    try w.print("],\"total\":{d}}}", .{total});

    const data = try ctx.allocator.dupe(u8, buf.items);
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// DELETE /api/agent/sessions/:id
///
/// Terminate and remove a session by its URL-encoded session key.
/// The `:id` path parameter is the session key (e.g. `api:default`).
///
/// URL-encoded colons (%3A) are decoded before lookup.
///
/// Response shape:
/// ```json
/// { "success": true, "data": { "session_key": "api:default", "terminated": true }, "error": null }
/// ```
///
/// Errors:
///   SESSION_MANAGER_UNAVAILABLE — no session manager is running.
///   SESSION_NOT_FOUND           — no session with that key exists.
fn handleAgentSessionDelete(ctx: *ApiContext) anyerror!void {
    const sm = ctx.session_mgr orelse {
        try ctx.sendError("503 Service Unavailable", "SESSION_MANAGER_UNAVAILABLE", "no agent session manager is running");
        return;
    };

    const raw_id = ctx.path_param orelse {
        try ctx.sendError("400 Bad Request", "MISSING_PARAM", "session key required in path");
        return;
    };

    // Decode percent-encoded characters (common: %3A → ':').
    const session_key = try percentDecode(ctx.allocator, raw_id);
    defer ctx.allocator.free(session_key);

    // Remove the session from the live map under lock.
    const removed = blk: {
        sm.mutex.lock();
        defer sm.mutex.unlock();
        if (sm.sessions.fetchRemove(session_key)) |kv| {
            kv.value.deinit(sm.allocator);
            sm.allocator.destroy(kv.value);
            break :blk true;
        }
        break :blk false;
    };

    if (!removed) {
        try ctx.sendError("404 Not Found", "SESSION_NOT_FOUND", "no active session with that key");
        return;
    }

    const data = try std.fmt.allocPrint(
        ctx.allocator,
        "{{\"session_key\":{f},\"terminated\":true}}",
        .{std.json.fmt(session_key, .{})},
    );
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// Decode percent-encoded bytes in a URL path segment.
/// Only replaces the most common encoding (%XX hex pairs).
/// Returns a heap-allocated copy; caller must free.
fn percentDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(allocator);
    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const hi = input[i + 1];
            const lo = input[i + 2];
            const decoded = (std.fmt.charToDigit(hi, 16) catch null);
            const decoded_lo = (std.fmt.charToDigit(lo, 16) catch null);
            if (decoded != null and decoded_lo != null) {
                const byte: u8 = (decoded.? << 4) | decoded_lo.?;
                try out.append(allocator, byte);
                i += 3;
                continue;
            }
        }
        try out.append(allocator, input[i]);
        i += 1;
    }
    return out.toOwnedSlice(allocator);
}

// ── Phase 3 handlers ────────────────────────────────────────────────

/// GET /api/memory
///
/// List memory entries from the configured backend.
///
/// Query parameters (all optional):
///   ?category=<name>          — filter by category (core, daily, conversation, or custom name)
///   ?session=<id>             — filter by session_id
///   ?q=<text>                 — full-text keyword search via recall() instead of list()
///   ?limit=<n>                — max entries to return (default 100; search default 20)
///   ?include_internal=true    — include autosave/bootstrap keys (excluded by default)
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": {
///     "entries": [
///       {
///         "id": "...",
///         "key": "greeting",
///         "content": "Hello world",
///         "category": "core",
///         "timestamp": "2026-04-06T00:00:00Z",
///         "session_id": null,
///         "score": null
///       }
///     ],
///     "total": 1,
///     "backend": "sqlite"
///   },
///   "error": null
/// }
/// ```
///
/// Errors:
///   MEMORY_UNAVAILABLE — no memory backend is configured.
fn handleMemoryList(ctx: *ApiContext) anyerror!void {
    const sm = ctx.session_mgr orelse {
        try ctx.sendError("503 Service Unavailable", "MEMORY_UNAVAILABLE", "no memory backend is configured");
        return;
    };
    const mem = sm.mem orelse {
        try ctx.sendError("503 Service Unavailable", "MEMORY_UNAVAILABLE", "no memory backend is configured");
        return;
    };

    // Parse optional query parameters.
    const category_str = extractQueryParam(ctx.target, "category");
    const session_filter = extractQueryParam(ctx.target, "session");
    const search_query = extractQueryParam(ctx.target, "q");
    const include_internal = blk: {
        const v = extractQueryParam(ctx.target, "include_internal") orelse break :blk false;
        break :blk std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "1");
    };

    // Determine effective limit.
    const default_limit: usize = if (search_query != null) 20 else 100;
    const limit: usize = blk: {
        const v = extractQueryParam(ctx.target, "limit") orelse break :blk default_limit;
        const n = std.fmt.parseInt(usize, v, 10) catch break :blk default_limit;
        if (n == 0) break :blk default_limit;
        break :blk n;
    };

    // Fetch entries.
    const entries = if (search_query) |q|
        try mem.recall(ctx.allocator, q, limit, session_filter)
    else blk: {
        const cat: ?memory_mod.MemoryCategory = if (category_str) |cs|
            memory_mod.MemoryCategory.fromString(cs)
        else
            null;
        break :blk try mem.list(ctx.allocator, cat, session_filter);
    };
    defer memory_mod.freeEntries(ctx.allocator, entries);

    const backend_name = mem.name();

    // Build JSON response.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    const w = buf.writer(ctx.allocator);

    try w.writeAll("{\"entries\":[");
    var written: usize = 0;
    var total: usize = 0;
    for (entries) |*entry| {
        if (!include_internal and memory_mod.isInternalMemoryKey(entry.key)) continue;
        // Apply limit for list() (recall() already limits).
        if (search_query == null and total >= limit) break;
        total += 1;
        if (written > 0) try w.writeByte(',');
        written += 1;
        try writeMemoryEntryJson(ctx.allocator, w, entry);
    }
    try w.print("],\"total\":{d},\"backend\":{f}}}", .{
        total,
        std.json.fmt(backend_name, .{}),
    });

    const data = try ctx.allocator.dupe(u8, buf.items);
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// DELETE /api/memory/:key
///
/// Delete a memory entry by its key.  The key is URL-decoded before lookup
/// so that keys containing '/' or ':' can be addressed safely.
///
/// Response shape:
/// ```json
/// { "success": true, "data": { "key": "greeting", "deleted": true }, "error": null }
/// ```
///
/// Errors:
///   MEMORY_UNAVAILABLE — no memory backend is configured.
///   NOT_FOUND          — no entry with that key exists.
fn handleMemoryDelete(ctx: *ApiContext) anyerror!void {
    const sm = ctx.session_mgr orelse {
        try ctx.sendError("503 Service Unavailable", "MEMORY_UNAVAILABLE", "no memory backend is configured");
        return;
    };
    const mem = sm.mem orelse {
        try ctx.sendError("503 Service Unavailable", "MEMORY_UNAVAILABLE", "no memory backend is configured");
        return;
    };

    const raw_key = ctx.path_param orelse {
        try ctx.sendError("400 Bad Request", "MISSING_PARAM", "memory key required in path");
        return;
    };

    // Decode percent-encoded characters (e.g. %2F → '/', %3A → ':').
    const key = try percentDecode(ctx.allocator, raw_key);
    defer ctx.allocator.free(key);

    const deleted = mem.forget(key) catch |err| {
        const msg = try std.fmt.allocPrint(ctx.allocator, "memory.forget() failed: {s}", .{@errorName(err)});
        defer ctx.allocator.free(msg);
        try ctx.sendError("500 Internal Server Error", "MEMORY_ERROR", msg);
        return;
    };

    if (!deleted) {
        try ctx.sendError("404 Not Found", "NOT_FOUND", "no memory entry with that key");
        return;
    }

    const data = try std.fmt.allocPrint(
        ctx.allocator,
        "{{\"key\":{f},\"deleted\":true}}",
        .{std.json.fmt(key, .{})},
    );
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// Serialize a single MemoryEntry to JSON and write it to `w`.
/// Caller owns the entry memory — this function does not free anything.
fn writeMemoryEntryJson(
    allocator: std.mem.Allocator,
    w: anytype,
    entry: *const memory_mod.MemoryEntry,
) !void {
    _ = allocator;
    const cat_str = entry.category.toString();
    try w.print(
        "{{\"id\":{f},\"key\":{f},\"content\":{f},\"category\":{f},\"timestamp\":{f}",
        .{
            std.json.fmt(entry.id, .{}),
            std.json.fmt(entry.key, .{}),
            std.json.fmt(entry.content, .{}),
            std.json.fmt(cat_str, .{}),
            std.json.fmt(entry.timestamp, .{}),
        },
    );
    if (entry.session_id) |sid| {
        try w.print(",\"session_id\":{f}", .{std.json.fmt(sid, .{})});
    } else {
        try w.writeAll(",\"session_id\":null");
    }
    if (entry.score) |s| {
        try w.print(",\"score\":{d:.6}}}", .{s});
    } else {
        try w.writeAll(",\"score\":null}");
    }
}

// ── Phase 8 handlers ────────────────────────────────────────────────

/// GET /api/doctor
///
/// Deep health report: per-component status, timestamps, restart counts, and
/// overall readiness.  Goes beyond GET /api/status by including `last_ok`,
/// `updated_at`, and a separate `"ready"` field derived from the registry
/// readiness check.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": {
///     "pid": 12345,
///     "uptime_seconds": 3600,
///     "ready": true,
///     "components": {
///       "gateway": {
///         "status": "ok",
///         "restart_count": 0,
///         "updated_at": "2026-04-06T00:00:00Z",
///         "last_ok": "2026-04-06T00:00:00Z",
///         "last_error": null
///       }
///     }
///   },
///   "error": null
/// }
/// ```
fn handleDoctor(ctx: *ApiContext) anyerror!void {
    const snap = health.snapshot();

    // Determine overall readiness.
    var all_ready = true;
    {
        var iter = snap.components.iterator();
        while (iter.next()) |entry| {
            if (!std.mem.eql(u8, entry.value_ptr.status, "ok")) {
                all_ready = false;
                break;
            }
        }
    }

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    const w = buf.writer(ctx.allocator);

    try w.print(
        "{{\"pid\":{d},\"uptime_seconds\":{d},\"ready\":{s},\"components\":{{",
        .{ snap.pid, snap.uptime_seconds, if (all_ready) "true" else "false" },
    );

    var iter = snap.components.iterator();
    var first = true;
    while (iter.next()) |entry| {
        if (!first) try w.writeByte(',');
        first = false;
        const ch = entry.value_ptr;
        const updated_at_str = ch.updated_at[0..ch.updated_at_len];
        try w.print(
            "\"{s}\":{{\"status\":\"{s}\",\"restart_count\":{d},\"updated_at\":{f}",
            .{
                entry.key_ptr.*,
                ch.status,
                ch.restart_count,
                std.json.fmt(updated_at_str, .{}),
            },
        );
        if (ch.last_ok) |lo| {
            const lo_str = lo[0..ch.last_ok_len];
            try w.print(",\"last_ok\":{f}", .{std.json.fmt(lo_str, .{})});
        } else {
            try w.writeAll(",\"last_ok\":null");
        }
        if (ch.last_error) |le| {
            try w.print(",\"last_error\":{f}", .{std.json.fmt(le, .{})});
        } else {
            try w.writeAll(",\"last_error\":null");
        }
        try w.writeByte('}');
    }
    try w.writeAll("}}");

    const data = try ctx.allocator.dupe(u8, buf.items);
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// GET /api/spec
///
/// Returns a static OpenAPI 3.1 JSON document describing all registered
/// REST Admin API endpoints.  The spec is embedded as a comptime string so
/// there is zero runtime cost and no allocations.
///
/// Response: the OpenAPI document wrapped in the standard success envelope.
fn handleSpec(ctx: *ApiContext) anyerror!void {
    // Static OpenAPI 3.1 document.  Kept in a comptime string to avoid any
    // runtime allocation for this hot path.
    const SPEC =
        \\{"openapi":"3.1.0","info":{"title":"NullClaw REST Admin API","version":"1.0.0","description":"Authenticated REST surface for managing a running nullclaw gateway instance."},"servers":[{"url":"http://localhost:3000","description":"Local gateway"}],"security":[{"bearerAuth":[]}],"components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"}}},"paths":{"/api/status":{"get":{"summary":"Runtime status","description":"Returns version, pid, uptime, and per-component health.","responses":{"200":{"description":"Status object"}}}}},"/api/doctor":{"get":{"summary":"Deep health report","description":"Per-component status with timestamps, restart counts, and readiness.","responses":{"200":{"description":"Doctor report"}}}}},"/api/spec":{"get":{"summary":"OpenAPI spec","description":"Returns this OpenAPI 3.1 document.","responses":{"200":{"description":"OpenAPI document"}}}}},"/api/config":{"get":{"summary":"Read config value","parameters":[{"name":"path","in":"query","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"Config value"},"400":{"description":"Missing path parameter"}}}}},"/api/models":{"get":{"summary":"List providers","description":"Lists configured providers without exposing API keys.","responses":{"200":{"description":"Provider list"}}}}},"/api/cron":{"get":{"summary":"List cron jobs"},"post":{"summary":"Create recurring cron job"}}},"/api/cron/once":{"post":{"summary":"Create one-shot delayed job"}}},"/api/cron/{id}":{"patch":{"summary":"Update cron job"},"delete":{"summary":"Delete cron job"}}},"/api/cron/{id}/run":{"post":{"summary":"Trigger job immediately"}}},"/api/cron/{id}/pause":{"post":{"summary":"Pause a job"}}},"/api/cron/{id}/resume":{"post":{"summary":"Resume a paused job"}}},"/api/channels":{"get":{"summary":"List configured channels"}}},"/api/channels/{name}":{"get":{"summary":"Get channel detail"}}},"/api/skills":{"get":{"summary":"List installed skills"}}},"/api/skills/install":{"post":{"summary":"Install a skill"}}},"/api/skills/{name}":{"delete":{"summary":"Remove an installed skill"}}},"/api/agent":{"post":{"summary":"Invoke agent (synchronous)"}}},"/api/agent/stream":{"post":{"summary":"Invoke agent (SSE streaming — 501 until transport upgraded)"}}},"/api/agent/sessions":{"get":{"summary":"List active sessions"}}},"/api/agent/sessions/{id}":{"delete":{"summary":"Terminate and remove a session"}}},"/api/memory":{"get":{"summary":"List memory entries"}}},"/api/memory/stats":{"get":{"summary":"Memory backend statistics"}}},"/api/memory/search":{"post":{"summary":"Full-text memory search"}}},"/api/memory/{key}":{"get":{"summary":"Get a memory entry by key"},"delete":{"summary":"Delete a memory entry by key"}}},"/api/history":{"get":{"summary":"List conversation history sessions"}}}}
    ;
    try ctx.sendSuccess(SPEC);
}

/// GET /api/memory/stats
///
/// Returns the configured memory backend name and total entry count.
/// Requires a live session manager with a configured memory backend.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": { "backend": "sqlite", "count": 42 },
///   "error": null
/// }
/// ```
///
/// Errors:
///   MEMORY_UNAVAILABLE — no memory backend is configured.
fn handleMemoryStats(ctx: *ApiContext) anyerror!void {
    const sm = ctx.session_mgr orelse {
        try ctx.sendError("503 Service Unavailable", "MEMORY_UNAVAILABLE", "no memory backend is configured");
        return;
    };
    const mem = sm.mem orelse {
        try ctx.sendError("503 Service Unavailable", "MEMORY_UNAVAILABLE", "no memory backend is configured");
        return;
    };

    const count = mem.count() catch |err| {
        const msg = try std.fmt.allocPrint(ctx.allocator, "memory.count() failed: {s}", .{@errorName(err)});
        defer ctx.allocator.free(msg);
        try ctx.sendError("500 Internal Server Error", "MEMORY_ERROR", msg);
        return;
    };

    const data = try std.fmt.allocPrint(
        ctx.allocator,
        "{{\"backend\":{f},\"count\":{d}}}",
        .{ std.json.fmt(mem.name(), .{}), count },
    );
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// POST /api/memory/search
///
/// Full-text search over memory entries using the backend's recall() method.
///
/// Request body (JSON):
/// ```json
/// { "query": "...", "limit": 10, "session": "opt-session-id" }
/// ```
/// `limit` defaults to 20.  `session` is optional.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": {
///     "entries": [...],
///     "total": 5,
///     "backend": "sqlite"
///   },
///   "error": null
/// }
/// ```
///
/// Errors:
///   MEMORY_UNAVAILABLE — no memory backend is configured.
///   MISSING_BODY       — no request body.
///   INVALID_JSON       — body is not valid JSON.
///   MISSING_FIELD      — `query` field is absent or empty.
fn handleMemorySearch(ctx: *ApiContext) anyerror!void {
    const sm = ctx.session_mgr orelse {
        try ctx.sendError("503 Service Unavailable", "MEMORY_UNAVAILABLE", "no memory backend is configured");
        return;
    };
    const mem = sm.mem orelse {
        try ctx.sendError("503 Service Unavailable", "MEMORY_UNAVAILABLE", "no memory backend is configured");
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

    const query: []const u8 = blk: {
        const v = obj.get("query") orelse {
            try ctx.sendError("400 Bad Request", "MISSING_FIELD", "'query' field is required");
            return;
        };
        if (v != .string or v.string.len == 0) {
            try ctx.sendError("400 Bad Request", "MISSING_FIELD", "'query' must be a non-empty string");
            return;
        }
        break :blk v.string;
    };

    const limit: usize = blk: {
        if (obj.get("limit")) |lv| {
            if (lv == .integer and lv.integer > 0) break :blk @intCast(lv.integer);
        }
        break :blk 20;
    };

    const session_filter: ?[]const u8 = blk: {
        const sv = obj.get("session") orelse break :blk null;
        if (sv == .string and sv.string.len > 0) break :blk sv.string;
        break :blk null;
    };

    const entries = mem.recall(ctx.allocator, query, limit, session_filter) catch |err| {
        const msg = try std.fmt.allocPrint(ctx.allocator, "memory.recall() failed: {s}", .{@errorName(err)});
        defer ctx.allocator.free(msg);
        try ctx.sendError("500 Internal Server Error", "MEMORY_ERROR", msg);
        return;
    };
    defer memory_mod.freeEntries(ctx.allocator, entries);

    const backend_name = mem.name();

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    const w = buf.writer(ctx.allocator);

    try w.writeAll("{\"entries\":[");
    for (entries, 0..) |*entry, i| {
        if (i > 0) try w.writeByte(',');
        try writeMemoryEntryJson(ctx.allocator, w, entry);
    }
    try w.print("],\"total\":{d},\"backend\":{f}}}", .{
        entries.len,
        std.json.fmt(backend_name, .{}),
    });

    const data = try ctx.allocator.dupe(u8, buf.items);
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// GET /api/memory/:key
///
/// Retrieve a single memory entry by its key.  The key is percent-decoded
/// before lookup so that keys containing '/' or ':' can be addressed.
///
/// Response shape:
/// ```json
/// {
///   "success": true,
///   "data": {
///     "id": "...", "key": "greeting", "content": "Hello world",
///     "category": "core", "timestamp": "...", "session_id": null, "score": null
///   },
///   "error": null
/// }
/// ```
///
/// Errors:
///   MEMORY_UNAVAILABLE — no memory backend is configured.
///   NOT_FOUND          — no entry with that key.
fn handleMemoryGet(ctx: *ApiContext) anyerror!void {
    const sm = ctx.session_mgr orelse {
        try ctx.sendError("503 Service Unavailable", "MEMORY_UNAVAILABLE", "no memory backend is configured");
        return;
    };
    const mem = sm.mem orelse {
        try ctx.sendError("503 Service Unavailable", "MEMORY_UNAVAILABLE", "no memory backend is configured");
        return;
    };

    const raw_key = ctx.path_param orelse {
        try ctx.sendError("400 Bad Request", "MISSING_PARAM", "memory key required in path");
        return;
    };

    const key = try percentDecode(ctx.allocator, raw_key);
    defer ctx.allocator.free(key);

    const entry_opt = mem.get(ctx.allocator, key) catch |err| {
        const msg = try std.fmt.allocPrint(ctx.allocator, "memory.get() failed: {s}", .{@errorName(err)});
        defer ctx.allocator.free(msg);
        try ctx.sendError("500 Internal Server Error", "MEMORY_ERROR", msg);
        return;
    };

    if (entry_opt == null) {
        try ctx.sendError("404 Not Found", "NOT_FOUND", "no memory entry with that key");
        return;
    }

    var entry = entry_opt.?;
    defer entry.deinit(ctx.allocator);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    const w = buf.writer(ctx.allocator);
    try writeMemoryEntryJson(ctx.allocator, w, &entry);

    const data = try ctx.allocator.dupe(u8, buf.items);
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
}

/// GET /api/history
///
/// List conversation history sessions from the durable session store.
/// Falls back to listing active in-memory sessions when no session store
/// is available.
///
/// Query parameters (all optional):
///   ?limit=<n>    — max sessions to return (default 50)
///   ?offset=<n>   — pagination offset (default 0)
///
/// Response shape (session store available):
/// ```json
/// {
///   "success": true,
///   "data": {
///     "sessions": [
///       { "session_id": "telegram:chat123", "message_count": 10,
///         "first_message_at": "2026-04-01T00:00:00Z",
///         "last_message_at": "2026-04-06T12:00:00Z" }
///     ],
///     "total": 1,
///     "source": "session_store"
///   },
///   "error": null
/// }
/// ```
///
/// Response shape (fallback to active sessions):
/// ```json
/// {
///   "success": true,
///   "data": {
///     "sessions": [
///       { "session_key": "api:default", "created_at": 1712345678,
///         "last_active": 1712349278, "turn_count": 5 }
///     ],
///     "total": 1,
///     "source": "active_sessions"
///   },
///   "error": null
/// }
/// ```
///
/// Errors:
///   SESSION_MANAGER_UNAVAILABLE — no session manager is running.
fn handleHistory(ctx: *ApiContext) anyerror!void {
    const sm = ctx.session_mgr orelse {
        try ctx.sendError("503 Service Unavailable", "SESSION_MANAGER_UNAVAILABLE", "no session manager is running");
        return;
    };

    const limit: usize = blk: {
        const v = extractQueryParam(ctx.target, "limit") orelse break :blk 50;
        const n = std.fmt.parseInt(usize, v, 10) catch break :blk 50;
        if (n == 0) break :blk 50;
        break :blk n;
    };
    const offset: usize = blk: {
        const v = extractQueryParam(ctx.target, "offset") orelse break :blk 0;
        break :blk std.fmt.parseInt(usize, v, 10) catch 0;
    };

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.allocator);
    const w = buf.writer(ctx.allocator);

    // Prefer the durable session store when available.
    if (sm.session_store) |store| {
        const sessions = store.listSessions(ctx.allocator, limit, offset) catch |err| switch (err) {
            error.NotSupported => null,
            else => {
                const msg = try std.fmt.allocPrint(ctx.allocator, "listSessions failed: {s}", .{@errorName(err)});
                defer ctx.allocator.free(msg);
                try ctx.sendError("500 Internal Server Error", "HISTORY_ERROR", msg);
                return;
            },
        };

        if (sessions) |sess_slice| {
            defer memory_mod.freeSessionInfos(ctx.allocator, sess_slice);

            const total = store.countSessions() catch sess_slice.len;

            try w.writeAll("{\"sessions\":[");
            for (sess_slice, 0..) |info, i| {
                if (i > 0) try w.writeByte(',');
                try w.print(
                    "{{\"session_id\":{f},\"message_count\":{d},\"first_message_at\":{f},\"last_message_at\":{f}}}",
                    .{
                        std.json.fmt(info.session_id, .{}),
                        info.message_count,
                        std.json.fmt(info.first_message_at, .{}),
                        std.json.fmt(info.last_message_at, .{}),
                    },
                );
            }
            try w.print("],\"total\":{d},\"source\":\"session_store\"}}", .{total});

            const data = try ctx.allocator.dupe(u8, buf.items);
            defer ctx.allocator.free(data);
            try ctx.sendSuccess(data);
            return;
        }
    }

    // Fallback: list active in-memory sessions.
    try w.writeAll("{\"sessions\":[");
    var total: usize = 0;
    {
        sm.mutex.lock();
        defer sm.mutex.unlock();

        var it = sm.sessions.iterator();
        var idx: usize = 0;
        var written: usize = 0;
        while (it.next()) |entry| {
            if (idx < offset) {
                idx += 1;
                continue;
            }
            if (written >= limit) break;
            const session = entry.value_ptr.*;
            if (written > 0) try w.writeByte(',');
            try w.print(
                "{{\"session_key\":{f},\"created_at\":{d},\"last_active\":{d},\"turn_count\":{d}}}",
                .{
                    std.json.fmt(session.session_key, .{}),
                    session.created_at,
                    session.last_active,
                    session.turn_count,
                },
            );
            written += 1;
            idx += 1;
        }
        total = sm.sessions.count();
    }
    try w.print("],\"total\":{d},\"source\":\"active_sessions\"}}", .{total});

    const data = try ctx.allocator.dupe(u8, buf.items);
    defer ctx.allocator.free(data);
    try ctx.sendSuccess(data);
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
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("400 Bad Request", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MISSING_PARAM") != null);
}

// ── Phase 4 channels tests ────────────────────────────────────────────

test "GET /api/channels returns empty array when no channels configured" {
    var cfg = makeEnabledCfg();
    // Default cfg has no channels configured.
    const result = dispatch(
        std.testing.allocator,
        "GET /api/channels HTTP/1.1\r\n\r\n",
        "GET",
        "/api/channels",
        "/api/channels",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"data\":[]") != null);
}

test "GET /api/channels lists configured channels" {
    const config_types = @import("../config_types.zig");
    const tg_accounts = [_]config_types.TelegramConfig{
        .{ .account_id = "bot1", .bot_token = "tok1" },
        .{ .account_id = "bot2", .bot_token = "tok2" },
    };
    var cfg = makeEnabledCfg();
    cfg.channels.telegram = &tg_accounts;

    const result = dispatch(
        std.testing.allocator,
        "GET /api/channels HTTP/1.1\r\n\r\n",
        "GET",
        "/api/channels",
        "/api/channels",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"type\":\"telegram\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"account_id\":\"bot1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"account_id\":\"bot2\"") != null);
    // Tokens must not appear in response.
    try std.testing.expect(std.mem.indexOf(u8, result.body, "tok1") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "tok2") == null);
}

test "GET /api/channels status reflects health registry" {
    health.reset();
    health.markComponentOk("telegram");

    const config_types = @import("../config_types.zig");
    const tg_accounts = [_]config_types.TelegramConfig{.{ .account_id = "default", .bot_token = "t" }};
    var cfg = makeEnabledCfg();
    cfg.channels.telegram = &tg_accounts;

    const result = dispatch(
        std.testing.allocator,
        "GET /api/channels HTTP/1.1\r\n\r\n",
        "GET",
        "/api/channels",
        "/api/channels",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"status\":\"ok\"") != null);
}

test "GET /api/channels/:name returns channel detail" {
    const config_types = @import("../config_types.zig");
    const disc_accounts = [_]config_types.DiscordConfig{.{ .account_id = "server1", .token = "dtok" }};
    var cfg = makeEnabledCfg();
    cfg.channels.discord = &disc_accounts;

    const result = dispatch(
        std.testing.allocator,
        "GET /api/channels/discord HTTP/1.1\r\n\r\n",
        "GET",
        "/api/channels/discord",
        "/api/channels/discord",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"type\":\"discord\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"account_id\":\"server1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"accounts\"") != null);
    // Token must not appear in response.
    try std.testing.expect(std.mem.indexOf(u8, result.body, "dtok") == null);
}

test "GET /api/channels/:name unconfigured type returns empty accounts" {
    var cfg = makeEnabledCfg();
    // No discord configured.
    const result = dispatch(
        std.testing.allocator,
        "GET /api/channels/discord HTTP/1.1\r\n\r\n",
        "GET",
        "/api/channels/discord",
        "/api/channels/discord",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"accounts\":[]") != null);
}

test "GET /api/channels/:name unknown type returns 404" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/channels/nonexistent HTTP/1.1\r\n\r\n",
        "GET",
        "/api/channels/nonexistent",
        "/api/channels/nonexistent",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("404 Not Found", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "CHANNEL_NOT_FOUND") != null);
}

// ── Phase 4 skills tests ──────────────────────────────────────────────

test "GET /api/skills returns success envelope in test mode" {
    // In test mode the directory scan is skipped; always returns empty list.
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/skills HTTP/1.1\r\n\r\n",
        "GET",
        "/api/skills",
        "/api/skills",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"skills\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "output_dir") != null);
}

test "POST /api/skills/install returns 503 in test mode" {
    // Network calls are bypassed in test mode.
    var cfg = makeEnabledCfg();
    const raw = "POST /api/skills/install HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" ++
        "{\"name\":\"example-skill\"}";
    const result = dispatch(
        std.testing.allocator,
        raw,
        "POST",
        "/api/skills/install",
        "/api/skills/install",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("503 Service Unavailable", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "NOT_IN_TEST") != null);
}

test "POST /api/skills/install missing body returns 400" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "POST /api/skills/install HTTP/1.1\r\n\r\n",
        "POST",
        "/api/skills/install",
        "/api/skills/install",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("400 Bad Request", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MISSING_BODY") != null);
}

test "POST /api/skills/install missing name and url returns 400" {
    var cfg = makeEnabledCfg();
    const raw = "POST /api/skills/install HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}";
    const result = dispatch(
        std.testing.allocator,
        raw,
        "POST",
        "/api/skills/install",
        "/api/skills/install",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("400 Bad Request", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MISSING_FIELD") != null);
}

test "DELETE /api/skills/:name unsafe name returns 400" {
    // A name containing '..' is sanitized: the matchPathParam router rejects
    // paths with extra '/' segments, so "../etc" in the path gives MISSING_PARAM.
    // A name that is literally ".." (no slashes) is caught by sanitizePathComponent.
    var cfg = makeEnabledCfg();
    // Test with a literal ".." as the skill name (single path segment, no extra '/').
    const result = dispatch(
        std.testing.allocator,
        "DELETE /api/skills/.. HTTP/1.1\r\n\r\n",
        "DELETE",
        "/api/skills/..",
        "/api/skills/..",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    // matchPathParam returns null for ".." because sanitizePathComponent trims
    // dots and rejects the empty result.  The handler itself also rejects it.
    // Either MISSING_PARAM (param not extracted) or INVALID_NAME is acceptable here.
    try std.testing.expect(
        std.mem.indexOf(u8, result.body, "MISSING_PARAM") != null or
            std.mem.indexOf(u8, result.body, "INVALID_NAME") != null,
    );
    try std.testing.expectEqualStrings("400 Bad Request", result.status);
}

test "DELETE /api/skills/:name returns success in test mode" {
    // Filesystem removal is bypassed in test mode.
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "DELETE /api/skills/my-skill HTTP/1.1\r\n\r\n",
        "DELETE",
        "/api/skills/my-skill",
        "/api/skills/my-skill",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"deleted\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"name\":\"my-skill\"") != null);
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
        null,
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
        null,
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
        null,
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
        null,
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
        null,
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
        null,
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
        null,
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
        null,
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
        null,
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
        null,
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
        null,
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
        null,
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
        null,
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
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("404 Not Found", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "JOB_NOT_FOUND") != null);
}

// ── Phase 7 tests ─────────────────────────────────────────────────────

test "POST /api/agent returns 503 when no session manager" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "POST /api/agent HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"message\":\"hello\"}",
        "POST",
        "/api/agent",
        "/api/agent",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("503 Service Unavailable", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "SESSION_MANAGER_UNAVAILABLE") != null);
}

test "POST /api/agent returns 400 for missing body" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "POST /api/agent HTTP/1.1\r\n\r\n",
        "POST",
        "/api/agent",
        "/api/agent",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("400 Bad Request", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "BAD_REQUEST") != null);
}

test "POST /api/agent returns 400 for missing message field" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "POST /api/agent HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"session\":\"test\"}",
        "POST",
        "/api/agent",
        "/api/agent",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("400 Bad Request", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "BAD_REQUEST") != null);
}

test "POST /api/agent returns 400 for empty message" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "POST /api/agent HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"message\":\"\"}",
        "POST",
        "/api/agent",
        "/api/agent",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("400 Bad Request", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "BAD_REQUEST") != null);
}

test "POST /api/agent/stream returns 501" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "POST /api/agent/stream HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"message\":\"hello\"}",
        "POST",
        "/api/agent/stream",
        "/api/agent/stream",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("501 Not Implemented", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "NOT_IMPLEMENTED") != null);
}

test "GET /api/agent/sessions returns 503 when no session manager" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/agent/sessions HTTP/1.1\r\n\r\n",
        "GET",
        "/api/agent/sessions",
        "/api/agent/sessions",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("503 Service Unavailable", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "SESSION_MANAGER_UNAVAILABLE") != null);
}

test "DELETE /api/agent/sessions/:id returns 503 when no session manager" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "DELETE /api/agent/sessions/api%3Adefault HTTP/1.1\r\n\r\n",
        "DELETE",
        "/api/agent/sessions/api%3Adefault",
        "/api/agent/sessions/api%3Adefault",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("503 Service Unavailable", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "SESSION_MANAGER_UNAVAILABLE") != null);
}

test "percentDecode decodes %3A to colon" {
    const decoded = try percentDecode(std.testing.allocator, "api%3Adefault");
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("api:default", decoded);
}

test "percentDecode passes through plain text unchanged" {
    const decoded = try percentDecode(std.testing.allocator, "plain-text");
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("plain-text", decoded);
}

test "percentDecode handles multiple encoded chars" {
    const decoded = try percentDecode(std.testing.allocator, "a%3Ab%3Ac");
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("a:b:c", decoded);
}

// ── Phase 3 tests ─────────────────────────────────────────────────────

// Minimal mock provider used to construct a SessionManager for memory tests.
// Only fields required by SessionManager.init wiring need to be populated;
// no chat/completion calls are made in memory handler tests.
const MockProviderForMemoryTest = struct {
    const providers_mod = @import("../providers/root.zig");

    fn implChatWithSystem(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: ?[]const u8,
        _: []const u8,
        _: []const u8,
        _: f64,
    ) anyerror![]const u8 {
        return error.NotSupported;
    }
    fn implChat(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: providers_mod.ChatRequest,
        _: []const u8,
        _: f64,
    ) anyerror!providers_mod.ChatResponse {
        return error.NotSupported;
    }
    fn implSupportsNativeTools(_: *anyopaque) bool {
        return false;
    }
    fn implGetName(_: *anyopaque) []const u8 {
        return "mock-memory-test";
    }
    fn implDeinit(_: *anyopaque) void {}

    const vtable = providers_mod.Provider.VTable{
        .chatWithSystem = &implChatWithSystem,
        .chat = &implChat,
        .supportsNativeTools = &implSupportsNativeTools,
        .getName = &implGetName,
        .deinit = &implDeinit,
    };

    var _instance: MockProviderForMemoryTest = .{};

    pub fn provider() providers_mod.Provider {
        return .{ .ptr = @ptrCast(&_instance), .vtable = &vtable };
    }
};

fn makeTestSessionManagerWithMem(none_mem: *memory_mod.NoneMemory) session_mod.SessionManager {
    const observability = @import("../observability.zig");
    var noop = observability.NoopObserver{};
    const cfg = Config{ .workspace_dir = "/tmp", .config_path = "/tmp/config.json", .allocator = std.testing.allocator };
    // NOTE: cfg is a local variable here; we need a stable address.
    // Use a comptime-stored config.  Since tests are single-threaded, this is safe.
    const static_cfg = struct {
        var c: Config = undefined;
    };
    static_cfg.c = cfg;
    return session_mod.SessionManager.init(
        std.testing.allocator,
        &static_cfg.c,
        MockProviderForMemoryTest.provider(),
        &.{},
        none_mem.memory(),
        noop.observer(),
        null,
        null,
    );
}

test "GET /api/memory returns 503 when no session manager" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/memory HTTP/1.1\r\n\r\n",
        "GET",
        "/api/memory",
        "/api/memory",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("503 Service Unavailable", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MEMORY_UNAVAILABLE") != null);
}

test "GET /api/memory returns 503 when session manager has no memory backend" {
    var cfg = makeEnabledCfg();
    // Build a minimal SessionManager with mem = null.
    const observability = @import("../observability.zig");
    var noop = observability.NoopObserver{};
    const static_cfg2 = struct {
        var c: Config = undefined;
    };
    static_cfg2.c = Config{ .workspace_dir = "/tmp", .config_path = "/tmp/config.json", .allocator = std.testing.allocator };
    var sm = session_mod.SessionManager.init(
        std.testing.allocator,
        &static_cfg2.c,
        MockProviderForMemoryTest.provider(),
        &.{},
        null, // no memory backend
        noop.observer(),
        null,
        null,
    );
    defer sm.deinit();

    const result = dispatch(
        std.testing.allocator,
        "GET /api/memory HTTP/1.1\r\n\r\n",
        "GET",
        "/api/memory",
        "/api/memory",
        &cfg,
        true,
        null,
        &sm,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("503 Service Unavailable", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MEMORY_UNAVAILABLE") != null);
}

test "GET /api/memory returns empty list from NoneMemory backend" {
    var cfg = makeEnabledCfg();
    var none_mem = memory_mod.NoneMemory.init();
    var sm = makeTestSessionManagerWithMem(&none_mem);
    defer sm.deinit();

    const result = dispatch(
        std.testing.allocator,
        "GET /api/memory HTTP/1.1\r\n\r\n",
        "GET",
        "/api/memory",
        "/api/memory",
        &cfg,
        true,
        null,
        &sm,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"entries\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"total\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"backend\":\"none\"") != null);
}

test "GET /api/memory with ?q= uses recall (returns empty from NoneMemory)" {
    var cfg = makeEnabledCfg();
    var none_mem = memory_mod.NoneMemory.init();
    var sm = makeTestSessionManagerWithMem(&none_mem);
    defer sm.deinit();

    const result = dispatch(
        std.testing.allocator,
        "GET /api/memory?q=hello HTTP/1.1\r\n\r\n",
        "GET",
        "/api/memory?q=hello",
        "/api/memory",
        &cfg,
        true,
        null,
        &sm,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"entries\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"total\":0") != null);
}

test "DELETE /api/memory/:key returns 503 when no session manager" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "DELETE /api/memory/somekey HTTP/1.1\r\n\r\n",
        "DELETE",
        "/api/memory/somekey",
        "/api/memory/somekey",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("503 Service Unavailable", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MEMORY_UNAVAILABLE") != null);
}

test "DELETE /api/memory/:key returns 404 when key not found" {
    // NoneMemory.forget always returns false — simulates key not found.
    var cfg = makeEnabledCfg();
    var none_mem = memory_mod.NoneMemory.init();
    var sm = makeTestSessionManagerWithMem(&none_mem);
    defer sm.deinit();

    const result = dispatch(
        std.testing.allocator,
        "DELETE /api/memory/greeting HTTP/1.1\r\n\r\n",
        "DELETE",
        "/api/memory/greeting",
        "/api/memory/greeting",
        &cfg,
        true,
        null,
        &sm,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("404 Not Found", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "NOT_FOUND") != null);
}

test "DELETE /api/memory/:key percent-decodes the key" {
    // Verify that %2F in the key is decoded before lookup.
    // NoneMemory always returns false for forget(), so we get 404 —
    // but we confirm the path routing resolves without error.
    var cfg = makeEnabledCfg();
    var none_mem = memory_mod.NoneMemory.init();
    var sm = makeTestSessionManagerWithMem(&none_mem);
    defer sm.deinit();

    const result = dispatch(
        std.testing.allocator,
        "DELETE /api/memory/some%2Fkey HTTP/1.1\r\n\r\n",
        "DELETE",
        "/api/memory/some%2Fkey",
        "/api/memory/some%2Fkey",
        &cfg,
        true,
        null,
        &sm,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    // 404 is expected from NoneMemory; what matters is we didn't get 500 or 503.
    try std.testing.expectEqualStrings("404 Not Found", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "NOT_FOUND") != null);
}

// ── Phase 8 tests ─────────────────────────────────────────────────────

test "GET /api/doctor returns pid uptime ready and components" {
    health.reset();
    health.markComponentOk("gateway");

    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/doctor HTTP/1.1\r\n\r\n",
        "GET",
        "/api/doctor",
        "/api/doctor",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"pid\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"uptime_seconds\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"ready\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"components\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"gateway\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"restart_count\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"updated_at\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"last_ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"last_error\"") != null);
}

test "GET /api/doctor ready false when component errored" {
    health.reset();
    health.markComponentError("db", "connection refused");

    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/doctor HTTP/1.1\r\n\r\n",
        "GET",
        "/api/doctor",
        "/api/doctor",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"ready\":false") != null);
}

test "GET /api/spec returns OpenAPI document" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/spec HTTP/1.1\r\n\r\n",
        "GET",
        "/api/spec",
        "/api/spec",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "openapi") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "NullClaw REST Admin API") != null);
}

test "GET /api/memory/stats returns 503 when no session manager" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/memory/stats HTTP/1.1\r\n\r\n",
        "GET",
        "/api/memory/stats",
        "/api/memory/stats",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("503 Service Unavailable", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MEMORY_UNAVAILABLE") != null);
}

test "GET /api/memory/stats returns backend and count" {
    var cfg = makeEnabledCfg();
    var none_mem = memory_mod.NoneMemory.init();
    var sm = makeTestSessionManagerWithMem(&none_mem);
    defer sm.deinit();

    const result = dispatch(
        std.testing.allocator,
        "GET /api/memory/stats HTTP/1.1\r\n\r\n",
        "GET",
        "/api/memory/stats",
        "/api/memory/stats",
        &cfg,
        true,
        null,
        &sm,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"backend\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"count\"") != null);
}

test "POST /api/memory/search returns 503 when no session manager" {
    var cfg = makeEnabledCfg();
    const raw = "POST /api/memory/search HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"query\":\"hello\"}";
    const result = dispatch(
        std.testing.allocator,
        raw,
        "POST",
        "/api/memory/search",
        "/api/memory/search",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("503 Service Unavailable", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MEMORY_UNAVAILABLE") != null);
}

test "POST /api/memory/search missing body returns 400" {
    var cfg = makeEnabledCfg();
    var none_mem = memory_mod.NoneMemory.init();
    var sm = makeTestSessionManagerWithMem(&none_mem);
    defer sm.deinit();

    const result = dispatch(
        std.testing.allocator,
        "POST /api/memory/search HTTP/1.1\r\n\r\n",
        "POST",
        "/api/memory/search",
        "/api/memory/search",
        &cfg,
        true,
        null,
        &sm,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("400 Bad Request", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MISSING_BODY") != null);
}

test "POST /api/memory/search missing query field returns 400" {
    var cfg = makeEnabledCfg();
    var none_mem = memory_mod.NoneMemory.init();
    var sm = makeTestSessionManagerWithMem(&none_mem);
    defer sm.deinit();

    const raw = "POST /api/memory/search HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}";
    const result = dispatch(
        std.testing.allocator,
        raw,
        "POST",
        "/api/memory/search",
        "/api/memory/search",
        &cfg,
        true,
        null,
        &sm,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("400 Bad Request", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MISSING_FIELD") != null);
}

test "POST /api/memory/search returns entries array with NoneMemory" {
    // NoneMemory.recall() always returns an empty slice — confirms wiring works.
    var cfg = makeEnabledCfg();
    var none_mem = memory_mod.NoneMemory.init();
    var sm = makeTestSessionManagerWithMem(&none_mem);
    defer sm.deinit();

    const raw = "POST /api/memory/search HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"query\":\"hello\",\"limit\":5}";
    const result = dispatch(
        std.testing.allocator,
        raw,
        "POST",
        "/api/memory/search",
        "/api/memory/search",
        &cfg,
        true,
        null,
        &sm,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"entries\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"total\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"backend\"") != null);
}

test "GET /api/memory/:key returns 503 when no session manager" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/memory/mykey HTTP/1.1\r\n\r\n",
        "GET",
        "/api/memory/mykey",
        "/api/memory/mykey",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("503 Service Unavailable", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "MEMORY_UNAVAILABLE") != null);
}

test "GET /api/memory/:key returns 404 when not found via NoneMemory" {
    var cfg = makeEnabledCfg();
    var none_mem = memory_mod.NoneMemory.init();
    var sm = makeTestSessionManagerWithMem(&none_mem);
    defer sm.deinit();

    const result = dispatch(
        std.testing.allocator,
        "GET /api/memory/mykey HTTP/1.1\r\n\r\n",
        "GET",
        "/api/memory/mykey",
        "/api/memory/mykey",
        &cfg,
        true,
        null,
        &sm,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("404 Not Found", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "NOT_FOUND") != null);
}

test "GET /api/history returns 503 when no session manager" {
    var cfg = makeEnabledCfg();
    const result = dispatch(
        std.testing.allocator,
        "GET /api/history HTTP/1.1\r\n\r\n",
        "GET",
        "/api/history",
        "/api/history",
        &cfg,
        true,
        null,
        null,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("503 Service Unavailable", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "SESSION_MANAGER_UNAVAILABLE") != null);
}

test "GET /api/history returns active sessions fallback" {
    var cfg = makeEnabledCfg();
    var none_mem = memory_mod.NoneMemory.init();
    var sm = makeTestSessionManagerWithMem(&none_mem);
    defer sm.deinit();
    // No session_store configured — falls back to active sessions.

    const result = dispatch(
        std.testing.allocator,
        "GET /api/history HTTP/1.1\r\n\r\n",
        "GET",
        "/api/history",
        "/api/history",
        &cfg,
        true,
        null,
        &sm,
    );
    defer if (result.allocated) std.testing.allocator.free(result.body);
    try std.testing.expectEqualStrings("200 OK", result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"success\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"sessions\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"total\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.body, "\"source\":\"active_sessions\"") != null);
}
