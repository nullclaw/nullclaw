const std = @import("std");
const builtin = @import("builtin");
const util = @import("util.zig");

/// Component health status.
pub const ComponentHealth = struct {
    status: []const u8,
    updated_at: [32]u8 = undefined,
    updated_at_len: usize = 0,
    last_ok: ?[32]u8 = null,
    last_ok_len: usize = 0,
    last_error: ?[]const u8 = null,
    restart_count: u64 = 0,
};

/// Full health snapshot.
pub const HealthSnapshot = struct {
    pid: u32,
    uptime_seconds: u64,
    components: *std.StringHashMapUnmanaged(ComponentHealth),
};

/// Global health registry — thread-safe singleton.
var registry_mutex: std.Thread.Mutex = .{};
var registry_components: std.StringHashMapUnmanaged(ComponentHealth) = .empty;
var registry_started: bool = false;
var registry_start_time: i64 = 0;
var pending_error_msg: ?[]const u8 = null;

fn ensureInit() void {
    if (!registry_started) {
        registry_start_time = std.time.timestamp();
        registry_started = true;
    }
}

fn nowTimestamp(buf: *[32]u8) usize {
    const ts = util.timestamp(buf);
    return ts.len;
}

fn upsertComponent(component: []const u8, update_fn: *const fn (*ComponentHealth, [32]u8, usize) void) void {
    registry_mutex.lock();
    defer registry_mutex.unlock();
    ensureInit();

    var ts_buf: [32]u8 = undefined;
    const ts_len = nowTimestamp(&ts_buf);

    const gop = registry_components.getOrPut(std.heap.smp_allocator, component) catch return;
    if (!gop.found_existing) {
        gop.value_ptr.* = .{
            .status = "starting",
        };
    }
    update_fn(gop.value_ptr, ts_buf, ts_len);
    gop.value_ptr.updated_at = ts_buf;
    gop.value_ptr.updated_at_len = ts_len;
}

fn markOkUpdate(entry: *ComponentHealth, ts_buf: [32]u8, ts_len: usize) void {
    entry.status = "ok";
    entry.last_ok = ts_buf;
    entry.last_ok_len = ts_len;
    entry.last_error = null;
}

fn markErrorUpdate(entry: *ComponentHealth, _: [32]u8, _: usize) void {
    entry.status = "error";
    entry.last_error = pending_error_msg;
    pending_error_msg = null;
}

fn bumpRestartUpdate(entry: *ComponentHealth, _: [32]u8, _: usize) void {
    entry.restart_count = entry.restart_count +| 1;
}

/// Mark a component as healthy.
pub fn markComponentOk(component: []const u8) void {
    upsertComponent(component, &markOkUpdate);
}

/// Mark a component as errored.
pub fn markComponentError(component: []const u8, err_msg: []const u8) void {
    registry_mutex.lock();
    defer registry_mutex.unlock();
    ensureInit();

    var ts_buf: [32]u8 = undefined;
    const ts_len = nowTimestamp(&ts_buf);

    // Set pending_error_msg INSIDE the mutex to avoid a race condition.
    pending_error_msg = err_msg;

    const gop = registry_components.getOrPut(std.heap.smp_allocator, component) catch return;
    if (!gop.found_existing) {
        gop.value_ptr.* = .{
            .status = "starting",
        };
    }
    markErrorUpdate(gop.value_ptr, ts_buf, ts_len);
    gop.value_ptr.updated_at = ts_buf;
    gop.value_ptr.updated_at_len = ts_len;
}

/// Bump the restart count for a component.
pub fn bumpComponentRestart(component: []const u8) void {
    upsertComponent(component, &bumpRestartUpdate);
}

/// Get a snapshot of the current health state.
pub fn snapshot() HealthSnapshot {
    registry_mutex.lock();
    defer registry_mutex.unlock();
    ensureInit();

    const now = std.time.timestamp();
    const uptime: u64 = if (now > registry_start_time) @intCast(now - registry_start_time) else 0;

    return .{
        .pid = if (builtin.os.tag == .linux) @intCast(std.os.linux.getpid()) else if (builtin.os.tag == .macos) @intCast(std.c.getpid()) else 0,
        .uptime_seconds = uptime,
        .components = &registry_components,
    };
}

/// Get a specific component's health.
pub fn getComponentHealth(component: []const u8) ?ComponentHealth {
    registry_mutex.lock();
    defer registry_mutex.unlock();
    return registry_components.get(component);
}

/// Reset the health registry (for testing).
pub fn reset() void {
    registry_mutex.lock();
    defer registry_mutex.unlock();
    registry_components = .empty;
    registry_started = false;
    registry_start_time = 0;
    pending_error_msg = null;
}

// ── Legacy types for backwards compatibility ─────────────────────────

pub const HealthStatus = enum {
    healthy,
    degraded,
    unhealthy,
};

pub const HealthCheck = struct {
    name: []const u8,
    status: HealthStatus,
    message: ?[]const u8 = null,
};

// ── Readiness Check System ───────────────────────────────────────────

pub const ReadinessStatus = enum {
    ready,
    not_ready,
};

pub const ComponentCheck = struct {
    name: []const u8,
    healthy: bool,
    message: ?[]const u8 = null,
};

pub const ReadinessResult = struct {
    status: ReadinessStatus,
    checks: []const ComponentCheck,

    /// Serialize the readiness result as JSON. Caller owns the returned memory.
    pub fn formatJson(self: ReadinessResult, allocator: std.mem.Allocator) ![]const u8 {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        const w = buf.writer(allocator);

        const status_str = if (self.status == .ready) "ready" else "not_ready";
        try w.print("{{\"status\":\"{s}\",\"checks\":[", .{status_str});

        for (self.checks, 0..) |check, i| {
            if (i > 0) try w.writeByte(',');
            const healthy_str = if (check.healthy) "true" else "false";
            try w.print("{{\"name\":\"{s}\",\"healthy\":{s}", .{ check.name, healthy_str });
            if (check.message) |msg| {
                try w.print(",\"message\":\"{s}\"", .{msg});
            }
            try w.writeByte('}');
        }

        try w.writeAll("]}");
        return try allocator.dupe(u8, buf.items);
    }
};

/// Check readiness of a set of component health entries.
/// Returns `.ready` if all components are healthy (or slice is empty), `.not_ready` otherwise.
pub fn checkReadiness(components: []const ComponentHealth) ReadinessResult {
    // We need to build ComponentCheck entries. Since we can't allocate here
    // (no allocator), we use a static buffer for up to 32 components.
    const max_components = 32;
    const S = struct {
        var checks_buf: [max_components]ComponentCheck = undefined;
    };

    const count = @min(components.len, max_components);
    var all_healthy = true;

    for (0..count) |i| {
        const c = components[i];
        const healthy = std.mem.eql(u8, c.status, "ok");
        if (!healthy) all_healthy = false;
        S.checks_buf[i] = .{
            .name = c.last_error orelse c.status,
            .healthy = healthy,
            .message = c.last_error,
        };
    }

    return .{
        .status = if (all_healthy) .ready else .not_ready,
        .checks = S.checks_buf[0..count],
    };
}

/// Check readiness from the global health registry. Returns result with
/// named component checks. Uses provided allocator for the checks slice.
/// Caller owns the returned checks slice.
pub fn checkRegistryReadiness(allocator: std.mem.Allocator) !ReadinessResult {
    registry_mutex.lock();
    defer registry_mutex.unlock();
    ensureInit();

    const count = registry_components.count();
    if (count == 0) {
        return .{
            .status = .ready,
            .checks = &.{},
        };
    }

    const checks = try allocator.alloc(ComponentCheck, count);
    var all_healthy = true;
    var i: usize = 0;

    var iter = registry_components.iterator();
    while (iter.next()) |entry| {
        const healthy = std.mem.eql(u8, entry.value_ptr.status, "ok");
        if (!healthy) all_healthy = false;
        checks[i] = .{
            .name = entry.key_ptr.*,
            .healthy = healthy,
            .message = entry.value_ptr.last_error,
        };
        i += 1;
    }

    return .{
        .status = if (all_healthy) .ready else .not_ready,
        .checks = checks,
    };
}

// ── Tests ────────────────────────────────────────────────────────────

test "markComponentOk initializes component" {
    reset();
    markComponentOk("test-ok");
    const entry = getComponentHealth("test-ok");
    try std.testing.expect(entry != null);
    try std.testing.expectEqualStrings("ok", entry.?.status);
    try std.testing.expect(entry.?.last_ok != null);
    try std.testing.expect(entry.?.last_error == null);
}

test "markComponentError then ok clears error" {
    reset();
    markComponentError("test-err", "first failure");
    const errored = getComponentHealth("test-err");
    try std.testing.expect(errored != null);
    try std.testing.expectEqualStrings("error", errored.?.status);
    try std.testing.expectEqualStrings("first failure", errored.?.last_error.?);

    markComponentOk("test-err");
    const recovered = getComponentHealth("test-err");
    try std.testing.expect(recovered != null);
    try std.testing.expectEqualStrings("ok", recovered.?.status);
    try std.testing.expect(recovered.?.last_error == null);
    try std.testing.expect(recovered.?.last_ok != null);
}

test "bumpComponentRestart increments counter" {
    reset();
    bumpComponentRestart("test-restart");
    bumpComponentRestart("test-restart");
    const entry = getComponentHealth("test-restart");
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(@as(u64, 2), entry.?.restart_count);
}

test "snapshot returns valid state" {
    reset();
    markComponentOk("test-snap");
    const snap = snapshot();
    try std.testing.expect(snap.components.count() >= 1);
}

// ── Readiness Check tests ────────────────────────────────────────────

test "checkReadiness all healthy returns ready" {
    const components = [_]ComponentHealth{
        .{ .status = "ok" },
        .{ .status = "ok" },
        .{ .status = "ok" },
    };
    const result = checkReadiness(&components);
    try std.testing.expectEqual(ReadinessStatus.ready, result.status);
    try std.testing.expectEqual(@as(usize, 3), result.checks.len);
    for (result.checks) |check| {
        try std.testing.expect(check.healthy);
    }
}

test "checkReadiness one unhealthy returns not_ready" {
    const components = [_]ComponentHealth{
        .{ .status = "ok" },
        .{ .status = "error", .last_error = "connection refused" },
        .{ .status = "ok" },
    };
    const result = checkReadiness(&components);
    try std.testing.expectEqual(ReadinessStatus.not_ready, result.status);
    try std.testing.expectEqual(@as(usize, 3), result.checks.len);
    // At least one check should be unhealthy
    var found_unhealthy = false;
    for (result.checks) |check| {
        if (!check.healthy) found_unhealthy = true;
    }
    try std.testing.expect(found_unhealthy);
}

test "checkReadiness empty slice returns ready" {
    const components = [_]ComponentHealth{};
    const result = checkReadiness(&components);
    try std.testing.expectEqual(ReadinessStatus.ready, result.status);
    try std.testing.expectEqual(@as(usize, 0), result.checks.len);
}

test "checkReadiness multiple unhealthy returns not_ready" {
    const components = [_]ComponentHealth{
        .{ .status = "error", .last_error = "timeout" },
        .{ .status = "error", .last_error = "dns failure" },
    };
    const result = checkReadiness(&components);
    try std.testing.expectEqual(ReadinessStatus.not_ready, result.status);
    for (result.checks) |check| {
        try std.testing.expect(!check.healthy);
    }
}

test "ComponentCheck defaults message to null" {
    const check: ComponentCheck = .{
        .name = "test-component",
        .healthy = true,
    };
    try std.testing.expect(check.message == null);
    try std.testing.expect(check.healthy);
    try std.testing.expectEqualStrings("test-component", check.name);
}

test "ReadinessResult formatJson ready with no checks" {
    const result: ReadinessResult = .{
        .status = .ready,
        .checks = &.{},
    };
    const json = try result.formatJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings("{\"status\":\"ready\",\"checks\":[]}", json);
}

test "ReadinessResult formatJson ready with healthy checks" {
    const checks = [_]ComponentCheck{
        .{ .name = "gateway", .healthy = true, .message = null },
    };
    const result: ReadinessResult = .{
        .status = .ready,
        .checks = &checks,
    };
    const json = try result.formatJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings(
        "{\"status\":\"ready\",\"checks\":[{\"name\":\"gateway\",\"healthy\":true}]}",
        json,
    );
}

test "ReadinessResult formatJson not_ready with message" {
    const checks = [_]ComponentCheck{
        .{ .name = "db", .healthy = false, .message = "connection lost" },
    };
    const result: ReadinessResult = .{
        .status = .not_ready,
        .checks = &checks,
    };
    const json = try result.formatJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings(
        "{\"status\":\"not_ready\",\"checks\":[{\"name\":\"db\",\"healthy\":false,\"message\":\"connection lost\"}]}",
        json,
    );
}

test "ReadinessResult formatJson multiple checks" {
    const checks = [_]ComponentCheck{
        .{ .name = "gateway", .healthy = true, .message = null },
        .{ .name = "db", .healthy = false, .message = "timeout" },
    };
    const result: ReadinessResult = .{
        .status = .not_ready,
        .checks = &checks,
    };
    const json = try result.formatJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings(
        "{\"status\":\"not_ready\",\"checks\":[{\"name\":\"gateway\",\"healthy\":true},{\"name\":\"db\",\"healthy\":false,\"message\":\"timeout\"}]}",
        json,
    );
}

test "checkRegistryReadiness no components returns ready" {
    reset();
    const result = try checkRegistryReadiness(std.testing.allocator);
    // Empty checks slice from static empty, no need to free
    try std.testing.expectEqual(ReadinessStatus.ready, result.status);
    try std.testing.expectEqual(@as(usize, 0), result.checks.len);
}

test "checkRegistryReadiness all ok returns ready" {
    reset();
    markComponentOk("gw");
    markComponentOk("db");
    const result = try checkRegistryReadiness(std.testing.allocator);
    defer std.testing.allocator.free(result.checks);
    try std.testing.expectEqual(ReadinessStatus.ready, result.status);
    try std.testing.expectEqual(@as(usize, 2), result.checks.len);
    for (result.checks) |check| {
        try std.testing.expect(check.healthy);
    }
}

test "checkRegistryReadiness with error returns not_ready" {
    reset();
    markComponentOk("gw");
    markComponentError("db", "connection refused");
    const result = try checkRegistryReadiness(std.testing.allocator);
    defer std.testing.allocator.free(result.checks);
    try std.testing.expectEqual(ReadinessStatus.not_ready, result.status);
    try std.testing.expectEqual(@as(usize, 2), result.checks.len);
    var found_unhealthy = false;
    for (result.checks) |check| {
        if (!check.healthy) {
            found_unhealthy = true;
            try std.testing.expectEqualStrings("connection refused", check.message.?);
        }
    }
    try std.testing.expect(found_unhealthy);
}
