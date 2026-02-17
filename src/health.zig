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

    const gop = registry_components.getOrPut(std.heap.page_allocator, component) catch return;
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
    pending_error_msg = err_msg;
    upsertComponent(component, &markErrorUpdate);
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

test "health module compiles" {}
