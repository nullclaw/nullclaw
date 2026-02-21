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
const CronScheduler = @import("cron.zig").CronScheduler;
const cron = @import("cron.zig");
const bus_mod = @import("bus.zig");
const dispatch = @import("channels/dispatch.zig");
const channel_loop = @import("channel_loop.zig");
const telegram = @import("channels/telegram.zig");

const log = std.log.scoped(.daemon);

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
    if (std.fs.path.dirname(config.config_path)) |dir| {
        return std.fs.path.join(allocator, &.{ dir, "daemon_state.json" });
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

/// Initial backoff for scheduler restarts (seconds).
const SCHEDULER_INITIAL_BACKOFF_SECS: u64 = 1;

/// Maximum backoff for scheduler restarts (seconds).
const SCHEDULER_MAX_BACKOFF_SECS: u64 = 60;

/// How often the channel watcher checks health (seconds).
const CHANNEL_WATCH_INTERVAL_SECS: u64 = 60;

/// Scheduler supervision thread — loads cron jobs and runs the scheduler loop.
/// On error (scheduler crash), logs and restarts with exponential backoff.
fn schedulerThread(allocator: std.mem.Allocator, config: *const Config, state: *DaemonState, event_bus: *bus_mod.Bus) void {
    var backoff_secs: u64 = SCHEDULER_INITIAL_BACKOFF_SECS;

    while (!isShutdownRequested()) {
        var scheduler = CronScheduler.init(allocator, config.scheduler.max_tasks, config.scheduler.enabled);
        defer scheduler.deinit();

        // Load persisted jobs (ignore errors — fresh start if file missing)
        cron.loadJobs(&scheduler) catch {};

        state.markRunning("scheduler");
        health.markComponentOk("scheduler");

        // run() blocks forever (while(true) loop) — if it returns, something went wrong.
        // Since run() can't actually return an error (it catches internally), we treat
        // any return from run() as an unexpected exit.
        scheduler.run(config.reliability.scheduler_poll_secs, event_bus);

        // If we reach here, scheduler exited unexpectedly
        if (isShutdownRequested()) break;

        state.markError("scheduler", "unexpected exit");
        health.markComponentError("scheduler", "unexpected exit");

        // Exponential backoff before restart
        std.Thread.sleep(backoff_secs * std.time.ns_per_s);
        backoff_secs = computeBackoff(backoff_secs, SCHEDULER_MAX_BACKOFF_SECS);
    }
}

/// Stale detection threshold: 3x the Telegram long-poll timeout (30s).
const STALE_THRESHOLD_SECS: i64 = 90;

/// Channel supervisor thread — spawns polling threads for configured channels,
/// monitors their health, and restarts on failure using SupervisedChannel.
fn channelSupervisorThread(
    allocator: std.mem.Allocator,
    config: *const Config,
    state: *DaemonState,
    channel_registry: *dispatch.ChannelRegistry,
    channel_rt: ?*channel_loop.ChannelRuntime,
    event_bus: *bus_mod.Bus,
) void {
    state.markRunning("channels");
    health.markComponentOk("channels");

    // ── Telegram supervision ──
    var tg_loop_state: ?*channel_loop.TelegramLoopState = null;
    var tg_health_channel: ?*telegram.TelegramChannel = null;
    var supervised: ?dispatch.SupervisedChannel = null;

    if (config.channels.telegram) |tg_config| {
        if (channel_rt == null) {
            state.markError("channels", "runtime init failed");
            health.markComponentError("channels", "runtime init failed");
        }
        if (channel_rt) |rt| {
            // Heap-alloc loop state
            const ls = allocator.create(channel_loop.TelegramLoopState) catch {
                state.markError("channels", "failed to alloc loop state");
                health.markComponentError("channels", "alloc failed");
                return;
            };
            ls.* = channel_loop.TelegramLoopState.init();
            tg_loop_state = ls;

            // Separate TelegramChannel for health-check probe (stateless HTTP GET)
            const hc = allocator.create(telegram.TelegramChannel) catch {
                state.markError("channels", "failed to alloc health channel");
                return;
            };
            hc.* = telegram.TelegramChannel.init(allocator, tg_config.bot_token, tg_config.allow_from);
            hc.proxy = tg_config.proxy;
            tg_health_channel = hc;

            // Register in channel registry for outbound dispatch
            channel_registry.register(hc.channel()) catch |err| {
                log.warn("Failed to register telegram in channel registry: {}", .{err});
            };

            // SupervisedChannel wrapper
            supervised = dispatch.spawnSupervisedChannel(hc.channel(), 5);

            // Spawn the polling thread
            ls.thread = spawnTelegramThread(allocator, config, rt, ls);
            if (ls.thread != null) {
                if (supervised) |*s| s.recordSuccess();
                log.info("Telegram polling thread started", .{});
            }
        }
    }

    defer {
        // Shutdown: signal polling thread to stop and join
        if (tg_loop_state) |ls| {
            ls.stop_requested.store(true, .release);
            if (ls.thread) |t| t.join();
            allocator.destroy(ls);
        }
        if (tg_health_channel) |hc| allocator.destroy(hc);
    }

    // ── Discord supervision ──
    var dc_loop_state: ?*channel_loop.DiscordLoopState = null;

    discord_setup: {
        if (config.channels.discord == null) break :discord_setup;
        const rt = channel_rt orelse break :discord_setup;

        const ls = allocator.create(channel_loop.DiscordLoopState) catch {
            log.warn("Failed to alloc discord loop state", .{});
            health.markComponentError("discord", "alloc failed");
            break :discord_setup;
        };
        ls.* = channel_loop.DiscordLoopState.init();
        dc_loop_state = ls;

        ls.thread = std.Thread.spawn(
            .{ .stack_size = 512 * 1024 },
            channel_loop.runDiscordLoop,
            .{ allocator, config, rt, ls, event_bus },
        ) catch |err| blk: {
            log.err("Failed to spawn Discord thread: {}", .{err});
            health.markComponentError("discord", "spawn failed");
            break :blk null;
        };
        if (ls.thread != null) {
            log.info("Discord gateway thread started", .{});
        }
    }

    defer {
        if (dc_loop_state) |ls| {
            ls.stop_requested.store(true, .release);
            if (ls.thread) |t| t.join();
            allocator.destroy(ls);
        }
    }

    // ── Monitoring loop ──
    while (!isShutdownRequested()) {
        std.Thread.sleep(CHANNEL_WATCH_INTERVAL_SECS * std.time.ns_per_s);
        if (isShutdownRequested()) break;

        if (tg_loop_state) |ls| {
            const now = std.time.timestamp();
            const last = ls.last_activity.load(.acquire);
            const stale = (now - last) > STALE_THRESHOLD_SECS;

            // Active HTTP health-check probe
            const probe_ok = if (tg_health_channel) |hc| hc.healthCheck() else true;

            if (!stale and probe_ok) {
                health.markComponentOk("telegram");
                state.markRunning("channels");
                if (supervised) |*s| {
                    if (s.state != .running) s.recordSuccess();
                }
            } else {
                // Problem detected
                const reason = if (stale) "polling thread stale" else "health check failed";
                log.warn("Telegram issue: {s}", .{reason});
                health.markComponentError("telegram", reason);

                if (supervised) |*s| {
                    s.recordFailure();

                    if (s.shouldRestart()) {
                        log.info("Restarting Telegram polling (attempt {d})", .{s.restart_count});
                        state.markError("channels", reason);

                        // Stop old thread
                        ls.stop_requested.store(true, .release);
                        if (ls.thread) |t| t.join();

                        // Backoff sleep
                        std.Thread.sleep(s.currentBackoffMs() * std.time.ns_per_ms);

                        // Respawn
                        ls.stop_requested.store(false, .release);
                        ls.last_activity.store(std.time.timestamp(), .release);
                        if (channel_rt) |rt| {
                            ls.thread = spawnTelegramThread(allocator, config, rt, ls);
                            if (ls.thread != null) {
                                s.recordSuccess();
                                state.markRunning("channels");
                                health.markComponentOk("telegram");
                            }
                        }
                    } else if (s.state == .gave_up) {
                        state.markError("channels", "gave up after max restarts");
                        health.markComponentError("telegram", "gave up after max restarts");
                    }
                }
            }
        } else {
            // No telegram configured — just report ok
            health.markComponentOk("channels");
        }
    }
}

/// Spawn a Telegram polling thread.
fn spawnTelegramThread(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *channel_loop.ChannelRuntime,
    loop_state: *channel_loop.TelegramLoopState,
) ?std.Thread {
    return std.Thread.spawn(
        .{ .stack_size = 512 * 1024 },
        channel_loop.runTelegramLoop,
        .{ allocator, config, runtime, loop_state },
    ) catch |err| {
        log.err("Failed to spawn Telegram thread: {}", .{err});
        return null;
    };
}

/// Run the daemon. This is the main entry point for `nullclaw daemon`.
/// Spawns threads for gateway, heartbeat, and channels, then loops until
/// shutdown is requested (Ctrl+C signal or explicit request).
/// `host` and `port` are CLI-parsed values that override `config.gateway`.
pub fn run(allocator: std.mem.Allocator, config: *const Config, host: []const u8, port: u16) !void {
    health.markComponentOk("daemon");
    shutdown_requested.store(false, .release);

    var state = DaemonState{
        .started = true,
        .gateway_host = host,
        .gateway_port = port,
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
    const gw_thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, gatewayThread, .{ allocator, host, port, &state }) catch |err| {
        state.markError("gateway", @errorName(err));
        try stdout.print("Failed to spawn gateway: {}\n", .{err});
        return err;
    };

    // Spawn heartbeat thread
    var hb_thread: ?std.Thread = null;
    if (config.heartbeat.enabled) {
        state.markRunning("heartbeat");
        if (std.Thread.spawn(.{ .stack_size = 128 * 1024 }, heartbeatThread, .{ allocator, config, &state })) |thread| {
            hb_thread = thread;
        } else |err| {
            state.markError("heartbeat", @errorName(err));
            stdout.print("Warning: heartbeat thread failed: {}\n", .{err}) catch {};
        }
    }

    // Event bus (created before scheduler so cron jobs can deliver via bus)
    var event_bus = bus_mod.Bus.init();

    // Spawn scheduler thread
    var sched_thread: ?std.Thread = null;
    if (config.scheduler.enabled) {
        state.markRunning("scheduler");
        if (std.Thread.spawn(.{ .stack_size = 256 * 1024 }, schedulerThread, .{ allocator, config, &state, &event_bus })) |thread| {
            sched_thread = thread;
        } else |err| {
            state.markError("scheduler", @errorName(err));
            stdout.print("Warning: scheduler thread failed: {}\n", .{err}) catch {};
        }
    }

    // Outbound dispatcher (created before supervisor so channels can register)
    var channel_registry = dispatch.ChannelRegistry.init(allocator);
    defer channel_registry.deinit();

    // Channel runtime for supervised polling (provider, tools, sessions)
    var channel_rt: ?*channel_loop.ChannelRuntime = null;
    if (hasSupervisedChannels(config)) {
        channel_rt = channel_loop.ChannelRuntime.init(allocator, config) catch |err| blk: {
            stdout.print("Warning: channel runtime init failed: {}\n", .{err}) catch {};
            state.markError("channels", @errorName(err));
            break :blk null;
        };
    }
    defer if (channel_rt) |rt| rt.deinit();

    // Spawn channel supervisor thread (only if channels are configured)
    var chan_thread: ?std.Thread = null;
    if (hasSupervisedChannels(config)) {
        if (std.Thread.spawn(.{ .stack_size = 256 * 1024 }, channelSupervisorThread, .{
            allocator, config, &state, &channel_registry, channel_rt, &event_bus,
        })) |thread| {
            chan_thread = thread;
        } else |err| {
            state.markError("channels", @errorName(err));
            stdout.print("Warning: channel supervisor thread failed: {}\n", .{err}) catch {};
        }
    }
    var dispatch_stats = dispatch.DispatchStats{};

    state.addComponent("outbound_dispatcher");

    var dispatcher_thread: ?std.Thread = null;
    if (std.Thread.spawn(.{ .stack_size = 512 * 1024 }, dispatch.runOutboundDispatcher, .{
        allocator, &event_bus, &channel_registry, &dispatch_stats,
    })) |thread| {
        dispatcher_thread = thread;
        state.markRunning("outbound_dispatcher");
        health.markComponentOk("outbound_dispatcher");
    } else |err| {
        state.markError("outbound_dispatcher", @errorName(err));
        stdout.print("Warning: outbound dispatcher thread failed: {}\n", .{err}) catch {};
    }

    // Main thread: wait for shutdown signal (poll-based)
    while (!isShutdownRequested()) {
        std.Thread.sleep(1 * std.time.ns_per_s);
    }

    try stdout.print("\nShutting down...\n", .{});

    // Close bus to signal dispatcher to exit
    event_bus.close();

    // Write final state
    state.markError("gateway", "shutting down");
    writeStateFile(allocator, state_path, &state) catch {};

    // Wait for threads
    if (dispatcher_thread) |t| t.join();
    if (chan_thread) |t| t.join();
    if (sched_thread) |t| t.join();
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
    const expected = try std.fs.path.join(std.testing.allocator, &.{ "/home/user/.nullclaw", "daemon_state.json" });
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, path);
}

test "scheduler backoff constants" {
    try std.testing.expectEqual(@as(u64, 1), SCHEDULER_INITIAL_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 60), SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 60), CHANNEL_WATCH_INTERVAL_SECS);
}

test "scheduler backoff progression" {
    var backoff: u64 = SCHEDULER_INITIAL_BACKOFF_SECS;
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 2), backoff);
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 4), backoff);
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 8), backoff);
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 16), backoff);
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 32), backoff);
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 60), backoff); // capped at max
    backoff = computeBackoff(backoff, SCHEDULER_MAX_BACKOFF_SECS);
    try std.testing.expectEqual(@as(u64, 60), backoff); // stays at max
}

test "channelSupervisorThread respects shutdown" {
    // Pre-request shutdown so the supervisor exits immediately
    shutdown_requested.store(true, .release);
    defer shutdown_requested.store(false, .release);

    // Config with no telegram → supervisor goes straight to idle loop → exits on shutdown
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
    };

    var state = DaemonState{};
    state.addComponent("channels");

    var channel_registry = dispatch.ChannelRegistry.init(std.testing.allocator);
    defer channel_registry.deinit();

    const thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, channelSupervisorThread, .{
        std.testing.allocator, &config, &state, &channel_registry, null,
    });
    thread.join();

    // Channel component should have been marked running before the loop
    try std.testing.expect(state.components[0].?.running);
}

test "DaemonState supports all supervised components" {
    var state = DaemonState{};
    state.addComponent("gateway");
    state.addComponent("channels");
    state.addComponent("heartbeat");
    state.addComponent("scheduler");
    try std.testing.expectEqual(@as(usize, 4), state.component_count);
    try std.testing.expectEqualStrings("scheduler", state.components[3].?.name);
    try std.testing.expect(state.components[3].?.running);
}

test "writeStateFile produces valid content" {
    var state = DaemonState{
        .started = true,
        .gateway_host = "127.0.0.1",
        .gateway_port = 8080,
    };
    state.addComponent("test-comp");

    // Write to a temp path
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir);
    const path = try std.fs.path.join(std.testing.allocator, &.{ dir, "daemon_state.json" });
    defer std.testing.allocator.free(path);

    try writeStateFile(std.testing.allocator, path, &state);

    // Read back and verify
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(std.testing.allocator, 4096);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "\"status\": \"running\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "test-comp") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "127.0.0.1:8080") != null);
}
