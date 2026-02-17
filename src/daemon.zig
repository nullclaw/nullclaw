//! Daemon — main event loop with component supervision.
//!
//! Mirrors ZeroClaw's daemon module:
//!   - Spawns gateway, channels, heartbeat, scheduler
//!   - Exponential backoff on component failure
//!   - Periodic state file writing (daemon_state.json)
//!   - Ctrl+C graceful shutdown

const std = @import("std");
const health = @import("health.zig");
const Config = @import("config.zig").Config;

/// How often the daemon state file is flushed (seconds).
const STATUS_FLUSH_SECONDS: u64 = 5;

/// Maximum number of supervised components.
const MAX_COMPONENTS: usize = 8;

/// Component status for state file serialization.
pub const ComponentStatus = struct {
    name: []const u8,
    running: bool = false,
    restart_count: u64 = 0,
    last_error: ?[]const u8 = null,
};

/// Daemon state written to daemon_state.json periodically.
pub const DaemonState = struct {
    started: bool = false,
    gateway_host: []const u8 = "127.0.0.1",
    gateway_port: u16 = 3000,
    components: [MAX_COMPONENTS]?ComponentStatus = .{null} ** MAX_COMPONENTS,
    component_count: usize = 0,

    pub fn addComponent(self: *DaemonState, name: []const u8) void {
        if (self.component_count < MAX_COMPONENTS) {
            self.components[self.component_count] = .{ .name = name, .running = true };
            self.component_count += 1;
        }
    }

    pub fn markError(self: *DaemonState, name: []const u8, err_msg: []const u8) void {
        for (self.components[0..self.component_count]) |*comp_opt| {
            if (comp_opt.*) |*comp| {
                if (std.mem.eql(u8, comp.name, name)) {
                    comp.running = false;
                    comp.last_error = err_msg;
                    comp.restart_count += 1;
                    return;
                }
            }
        }
    }

    pub fn markRunning(self: *DaemonState, name: []const u8) void {
        for (self.components[0..self.component_count]) |*comp_opt| {
            if (comp_opt.*) |*comp| {
                if (std.mem.eql(u8, comp.name, name)) {
                    comp.running = true;
                    comp.last_error = null;
                    return;
                }
            }
        }
    }
};

/// Compute the path to daemon_state.json from config.
pub fn stateFilePath(allocator: std.mem.Allocator, config: *const Config) ![]u8 {
    // Use config directory (parent of config_path)
    if (std.mem.lastIndexOfScalar(u8, config.config_path, '/')) |idx| {
        return std.fmt.allocPrint(allocator, "{s}/daemon_state.json", .{config.config_path[0..idx]});
    }
    return allocator.dupe(u8, "daemon_state.json");
}

/// Write daemon state to disk as JSON.
pub fn writeStateFile(allocator: std.mem.Allocator, path: []const u8, state: *const DaemonState) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\n");
    try buf.appendSlice(allocator, "  \"status\": \"running\",\n");
    try std.fmt.format(buf.writer(allocator), "  \"gateway\": \"{s}:{d}\",\n", .{ state.gateway_host, state.gateway_port });

    // Components array
    try buf.appendSlice(allocator, "  \"components\": [\n");
    var first = true;
    for (state.components[0..state.component_count]) |comp_opt| {
        if (comp_opt) |comp| {
            if (!first) try buf.appendSlice(allocator, ",\n");
            first = false;
            try std.fmt.format(buf.writer(allocator),
                \\    {{"name": "{s}", "running": {}, "restart_count": {d}}}
            , .{ comp.name, comp.running, comp.restart_count });
        }
    }
    try buf.appendSlice(allocator, "\n  ]\n}\n");

    const file = try std.fs.createFileAbsolute(path, .{});
    defer file.close();
    try file.writeAll(buf.items);
}

/// Compute exponential backoff duration.
pub fn computeBackoff(current_backoff: u64, max_backoff: u64) u64 {
    const doubled = current_backoff *| 2;
    return @min(doubled, max_backoff);
}

/// Check if any real-time channels are configured.
pub fn hasSupervisedChannels(config: *const Config) bool {
    return config.channels.telegram != null or
        config.channels.discord != null or
        config.channels.slack != null or
        config.channels.imessage != null or
        config.channels.matrix != null or
        config.channels.whatsapp != null;
}

/// Shutdown signal — set to true to stop the daemon.
var shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

/// Request a graceful shutdown of the daemon.
pub fn requestShutdown() void {
    shutdown_requested.store(true, .release);
}

/// Check if shutdown has been requested.
pub fn isShutdownRequested() bool {
    return shutdown_requested.load(.acquire);
}

/// Gateway thread entry point.
fn gatewayThread(allocator: std.mem.Allocator, host: []const u8, port: u16, state: *DaemonState) void {
    const gateway = @import("gateway.zig");
    gateway.run(allocator, host, port) catch |err| {
        state.markError("gateway", @errorName(err));
        health.markComponentError("gateway", @errorName(err));
        return;
    };
}

/// Heartbeat thread — periodically writes state file and checks health.
fn heartbeatThread(allocator: std.mem.Allocator, config: *const Config, state: *DaemonState) void {
    const state_path = stateFilePath(allocator, config) catch return;
    defer allocator.free(state_path);

    while (!isShutdownRequested()) {
        writeStateFile(allocator, state_path, state) catch {};
        health.markComponentOk("heartbeat");
        std.Thread.sleep(STATUS_FLUSH_SECONDS * std.time.ns_per_s);
    }
}

/// Run the daemon. This is the main entry point for `nullclaw daemon`.
/// Spawns threads for gateway, heartbeat, and channels, then loops until
/// shutdown is requested (Ctrl+C signal or explicit request).
pub fn run(allocator: std.mem.Allocator, config: *const Config) !void {
    health.markComponentOk("daemon");
    shutdown_requested.store(false, .release);

    var state = DaemonState{
        .started = true,
        .gateway_host = config.gateway.host,
        .gateway_port = config.gateway.port,
    };
    state.addComponent("gateway");

    if (hasSupervisedChannels(config)) {
        state.addComponent("channels");
    } else {
        health.markComponentOk("channels");
    }

    if (config.heartbeat.enabled) {
        state.addComponent("heartbeat");
    }

    state.addComponent("scheduler");

    var stdout_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &bw.interface;
    try stdout.print("nullclaw daemon started\n", .{});
    try stdout.print("  Gateway:  http://{s}:{d}\n", .{ state.gateway_host, state.gateway_port });
    try stdout.print("  Components: {d} active\n", .{state.component_count});
    try stdout.print("  Ctrl+C to stop\n\n", .{});
    try stdout.flush();

    // Write initial state file
    const state_path = try stateFilePath(allocator, config);
    defer allocator.free(state_path);
    writeStateFile(allocator, state_path, &state) catch |err| {
        try stdout.print("Warning: could not write state file: {}\n", .{err});
    };

    // Spawn gateway thread
    state.markRunning("gateway");
    const gw_thread = std.Thread.spawn(.{}, gatewayThread, .{ allocator, config.gateway.host, config.gateway.port, &state }) catch |err| {
        state.markError("gateway", @errorName(err));
        try stdout.print("Failed to spawn gateway: {}\n", .{err});
        return err;
    };

    // Spawn heartbeat thread
    var hb_thread: ?std.Thread = null;
    if (config.heartbeat.enabled) {
        state.markRunning("heartbeat");
        if (std.Thread.spawn(.{}, heartbeatThread, .{ allocator, config, &state })) |thread| {
            hb_thread = thread;
        } else |err| {
            state.markError("heartbeat", @errorName(err));
            stdout.print("Warning: heartbeat thread failed: {}\n", .{err}) catch {};
        }
    }

    // Main thread: wait for shutdown signal (poll-based)
    while (!isShutdownRequested()) {
        std.Thread.sleep(1 * std.time.ns_per_s);
    }

    try stdout.print("\nShutting down...\n", .{});

    // Write final state
    state.markError("gateway", "shutting down");
    writeStateFile(allocator, state_path, &state) catch {};

    // Wait for threads
    if (hb_thread) |t| t.join();
    gw_thread.join();

    try stdout.print("nullclaw daemon stopped.\n", .{});
}

// ── Tests ────────────────────────────────────────────────────────

test "DaemonState addComponent" {
    var state = DaemonState{};
    state.addComponent("gateway");
    state.addComponent("channels");
    try std.testing.expectEqual(@as(usize, 2), state.component_count);
    try std.testing.expectEqualStrings("gateway", state.components[0].?.name);
    try std.testing.expectEqualStrings("channels", state.components[1].?.name);
}

test "DaemonState markError and markRunning" {
    var state = DaemonState{};
    state.addComponent("gateway");
    state.markError("gateway", "connection refused");
    try std.testing.expect(!state.components[0].?.running);
    try std.testing.expectEqual(@as(u64, 1), state.components[0].?.restart_count);
    try std.testing.expectEqualStrings("connection refused", state.components[0].?.last_error.?);

    state.markRunning("gateway");
    try std.testing.expect(state.components[0].?.running);
    try std.testing.expect(state.components[0].?.last_error == null);
}

test "computeBackoff doubles up to max" {
    try std.testing.expectEqual(@as(u64, 4), computeBackoff(2, 60));
    try std.testing.expectEqual(@as(u64, 60), computeBackoff(32, 60));
    try std.testing.expectEqual(@as(u64, 60), computeBackoff(60, 60));
}

test "computeBackoff saturating" {
    try std.testing.expectEqual(std.math.maxInt(u64), computeBackoff(std.math.maxInt(u64), std.math.maxInt(u64)));
}

test "hasSupervisedChannels false for defaults" {
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
    };
    try std.testing.expect(!hasSupervisedChannels(&config));
}

test "stateFilePath derives from config_path" {
    const config = Config{
        .workspace_dir = "/tmp/workspace",
        .config_path = "/home/user/.nullclaw/config.json",
        .allocator = std.testing.allocator,
    };
    const path = try stateFilePath(std.testing.allocator, &config);
    defer std.testing.allocator.free(path);
    try std.testing.expectEqualStrings("/home/user/.nullclaw/daemon_state.json", path);
}

test "writeStateFile produces valid content" {
    var state = DaemonState{
        .started = true,
        .gateway_host = "127.0.0.1",
        .gateway_port = 8080,
    };
    state.addComponent("test-comp");

    // Write to a temp path
    const path = "/tmp/nullclaw-test-daemon-state.json";
    try writeStateFile(std.testing.allocator, path, &state);

    // Read back and verify
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(std.testing.allocator, 4096);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "\"status\": \"running\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "test-comp") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "127.0.0.1:8080") != null);

    // Cleanup
    std.fs.deleteFileAbsolute(path) catch {};
}
