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
const channel_manager = @import("channel_manager.zig");
const agent_routing = @import("agent_routing.zig");
const channel_catalog = @import("channel_catalog.zig");
const channel_adapters = @import("channel_adapters.zig");
const heartbeat_mod = @import("heartbeat.zig");
const onboard = @import("onboard.zig");

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
    return channel_catalog.hasSupervisedChannels(config);
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
fn gatewayThread(allocator: std.mem.Allocator, config: *const Config, host: []const u8, port: u16, state: *DaemonState, event_bus: *bus_mod.Bus) void {
    const gateway = @import("gateway.zig");
    gateway.run(allocator, host, port, config, event_bus) catch |err| {
        state.markError("gateway", @errorName(err));
        health.markComponentError("gateway", @errorName(err));
        return;
    };
}

/// Heartbeat thread — periodically writes state file, checks health, and
/// runs HEARTBEAT.md polling ticks on the configured heartbeat interval.
fn heartbeatThread(allocator: std.mem.Allocator, config: *const Config, state: *DaemonState) void {
    const state_path = stateFilePath(allocator, config) catch return;
    defer allocator.free(state_path);

    const heartbeat_engine = heartbeat_mod.HeartbeatEngine.init(
        config.heartbeat.enabled,
        config.heartbeat.interval_minutes,
        config.workspace_dir,
        null,
    );
    const heartbeat_interval_ns: i128 = @as(i128, @intCast(heartbeat_engine.interval_minutes)) * 60 * std.time.ns_per_s;
    var next_heartbeat_tick_at_ns: i128 = std.time.nanoTimestamp() + heartbeat_interval_ns;

    while (!isShutdownRequested()) {
        writeStateFile(allocator, state_path, state) catch {};
        health.markComponentOk("heartbeat");

        const now_ns = std.time.nanoTimestamp();
        if (heartbeat_engine.enabled and now_ns >= next_heartbeat_tick_at_ns) {
            const tick_result = heartbeat_engine.tick(allocator) catch |err| {
                log.warn("heartbeat tick failed: {s}", .{@errorName(err)});
                next_heartbeat_tick_at_ns = now_ns + heartbeat_interval_ns;
                std.Thread.sleep(STATUS_FLUSH_SECONDS * std.time.ns_per_s);
                continue;
            };
            switch (tick_result.outcome) {
                .processed => log.info("heartbeat tick loaded {d} task(s) from HEARTBEAT.md", .{tick_result.task_count}),
                .skipped_empty_file => log.debug("heartbeat tick skipped: HEARTBEAT.md has no actionable content", .{}),
                .skipped_missing_file => log.debug("heartbeat tick skipped: HEARTBEAT.md is missing", .{}),
            }
            next_heartbeat_tick_at_ns = now_ns + heartbeat_interval_ns;
        }

        std.Thread.sleep(STATUS_FLUSH_SECONDS * std.time.ns_per_s);
    }
}

/// How often the channel watcher checks health (seconds).
const CHANNEL_WATCH_INTERVAL_SECS: u64 = 60;

/// Initial backoff for scheduler restarts (seconds).
/// Kept for compatibility with existing tests and supervision semantics.
const SCHEDULER_INITIAL_BACKOFF_SECS: u64 = 1;

/// Maximum backoff for scheduler restarts (seconds).
/// Kept for compatibility with existing tests and supervision semantics.
const SCHEDULER_MAX_BACKOFF_SECS: u64 = 60;

const SchedulerJobSnapshot = struct {
    next_run_secs: i64,
    last_run_secs: ?i64,
    last_status: ?[]const u8,
    paused: bool,
    one_shot: bool,
};

fn schedulerStatusEquals(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?, b.?);
}

fn schedulerJobChanged(job: *const cron.CronJob, snapshot: SchedulerJobSnapshot) bool {
    if (job.next_run_secs != snapshot.next_run_secs) return true;
    if (job.last_run_secs != snapshot.last_run_secs) return true;
    if (job.paused != snapshot.paused) return true;
    if (job.one_shot != snapshot.one_shot) return true;
    if (!schedulerStatusEquals(job.last_status, snapshot.last_status)) return true;
    return false;
}

fn clearSchedulerSnapshot(
    allocator: std.mem.Allocator,
    snapshot: *std.StringHashMapUnmanaged(SchedulerJobSnapshot),
) void {
    var it = snapshot.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
    snapshot.clearRetainingCapacity();
}

fn buildSchedulerSnapshot(
    allocator: std.mem.Allocator,
    scheduler: *const CronScheduler,
    snapshot: *std.StringHashMapUnmanaged(SchedulerJobSnapshot),
) !void {
    clearSchedulerSnapshot(allocator, snapshot);
    for (scheduler.listJobs()) |job| {
        const key = try allocator.dupe(u8, job.id);
        snapshot.put(allocator, key, .{
            .next_run_secs = job.next_run_secs,
            .last_run_secs = job.last_run_secs,
            .last_status = job.last_status,
            .paused = job.paused,
            .one_shot = job.one_shot,
        }) catch |err| {
            allocator.free(key);
            return err;
        };
    }
}

fn upsertSchedulerRuntimeJob(
    allocator: std.mem.Allocator,
    latest: *CronScheduler,
    runtime_job: *const cron.CronJob,
) !void {
    if (latest.getMutableJob(runtime_job.id)) |dst| {
        dst.next_run_secs = runtime_job.next_run_secs;
        dst.last_run_secs = runtime_job.last_run_secs;
        dst.last_status = runtime_job.last_status;
        dst.paused = runtime_job.paused;
        dst.one_shot = runtime_job.one_shot;
        return;
    }

    try latest.jobs.append(allocator, .{
        .id = try allocator.dupe(u8, runtime_job.id),
        .expression = try allocator.dupe(u8, runtime_job.expression),
        .command = try allocator.dupe(u8, runtime_job.command),
        .next_run_secs = runtime_job.next_run_secs,
        .last_run_secs = runtime_job.last_run_secs,
        .last_status = runtime_job.last_status,
        .paused = runtime_job.paused,
        .one_shot = runtime_job.one_shot,
    });
}

fn mergeSchedulerTickChangesAndSave(
    allocator: std.mem.Allocator,
    runtime: *const CronScheduler,
    before_tick: *const std.StringHashMapUnmanaged(SchedulerJobSnapshot),
) !void {
    var latest = CronScheduler.init(allocator, runtime.max_tasks, runtime.enabled);
    defer latest.deinit();
    try cron.loadJobsStrict(&latest);

    var runtime_ids: std.StringHashMapUnmanaged(void) = .empty;
    defer runtime_ids.deinit(allocator);

    for (runtime.listJobs()) |job| {
        try runtime_ids.put(allocator, job.id, {});
        if (before_tick.get(job.id)) |snapshot| {
            if (!schedulerJobChanged(&job, snapshot)) continue;
        }
        try upsertSchedulerRuntimeJob(allocator, &latest, &job);
    }

    var removed_it = before_tick.iterator();
    while (removed_it.next()) |entry| {
        const job_id = entry.key_ptr.*;
        if (!runtime_ids.contains(job_id)) {
            _ = latest.removeJob(job_id);
        }
    }

    try cron.saveJobs(&latest);
}

/// Scheduler thread — executes due cron jobs and periodically reloads cron.json
/// so tasks created/updated after daemon startup are picked up without restart.
fn schedulerThread(allocator: std.mem.Allocator, config: *const Config, state: *DaemonState, event_bus: *bus_mod.Bus) void {
    var scheduler = CronScheduler.init(allocator, config.scheduler.max_tasks, config.scheduler.enabled);
    defer scheduler.deinit();
    var before_tick: std.StringHashMapUnmanaged(SchedulerJobSnapshot) = .empty;
    defer {
        clearSchedulerSnapshot(allocator, &before_tick);
        before_tick.deinit(allocator);
    }

    const poll_secs: u64 = @max(@as(u64, 1), config.reliability.scheduler_poll_secs);

    // Initial load from disk (ignore errors — start empty if file missing/corrupt)
    cron.loadJobs(&scheduler) catch {};

    state.markRunning("scheduler");
    health.markComponentOk("scheduler");

    while (!isShutdownRequested()) {
        // Refresh scheduler view from store so jobs created/updated after daemon startup are picked up.
        cron.reloadJobs(&scheduler) catch |err| {
            log.warn("scheduler reload failed: {}", .{err});
            state.markError("scheduler", @errorName(err));
            health.markComponentError("scheduler", @errorName(err));
        };

        buildSchedulerSnapshot(allocator, &scheduler, &before_tick) catch |err| {
            log.warn("scheduler snapshot failed: {}", .{err});
            state.markError("scheduler", @errorName(err));
            health.markComponentError("scheduler", @errorName(err));
            var snapshot_sleep: u64 = 0;
            while (snapshot_sleep < poll_secs and !isShutdownRequested()) : (snapshot_sleep += 1) {
                std.Thread.sleep(std.time.ns_per_s);
            }
            continue;
        };

        const changed = scheduler.tick(std.time.timestamp(), event_bus);
        if (changed) {
            mergeSchedulerTickChangesAndSave(allocator, &scheduler, &before_tick) catch |err| {
                log.warn("scheduler merge-save failed: {}", .{err});
                state.markError("scheduler", @errorName(err));
                health.markComponentError("scheduler", @errorName(err));
            };
        }

        state.markRunning("scheduler");
        health.markComponentOk("scheduler");

        var slept: u64 = 0;
        while (slept < poll_secs and !isShutdownRequested()) : (slept += 1) {
            std.Thread.sleep(std.time.ns_per_s);
        }
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
    var mgr = channel_manager.ChannelManager.init(allocator, config, channel_registry) catch {
        state.markError("channels", "init_failed");
        health.markComponentError("channels", "init_failed");
        return;
    };
    defer mgr.deinit();

    if (channel_rt) |rt| mgr.setRuntime(rt);
    mgr.setEventBus(event_bus);

    mgr.collectConfiguredChannels() catch |err| {
        state.markError("channels", @errorName(err));
        health.markComponentError("channels", @errorName(err));
        return;
    };

    const started = mgr.startAll() catch |err| {
        state.markError("channels", @errorName(err));
        health.markComponentError("channels", @errorName(err));
        return;
    };

    if (started > 0) {
        state.markRunning("channels");
        health.markComponentOk("channels");
        mgr.supervisionLoop(state); // blocks until shutdown
    } else {
        health.markComponentOk("channels");
    }
}

/// Inbound dispatcher thread:
/// consumes inbound events from channels, runs SessionManager, publishes outbound replies.
const ParsedInboundMetadata = struct {
    parsed: ?std.json.Parsed(std.json.Value) = null,
    fields: channel_adapters.InboundMetadata = .{},

    fn deinit(self: *ParsedInboundMetadata) void {
        if (self.parsed) |*pm| pm.deinit();
    }
};

fn parseInboundMetadata(allocator: std.mem.Allocator, metadata_json: ?[]const u8) ParsedInboundMetadata {
    var parsed = ParsedInboundMetadata{};
    const meta_json = metadata_json orelse return parsed;

    parsed.parsed = std.json.parseFromSlice(std.json.Value, allocator, meta_json, .{}) catch null;
    if (parsed.parsed) |*pm| {
        if (pm.value != .object) return parsed;

        if (pm.value.object.get("account_id")) |v| {
            if (v == .string) parsed.fields.account_id = v.string;
        }
        if (pm.value.object.get("peer_kind")) |v| {
            if (v == .string) parsed.fields.peer_kind = channel_adapters.parsePeerKind(v.string);
        }
        if (pm.value.object.get("peer_id")) |v| {
            if (v == .string and v.string.len > 0) parsed.fields.peer_id = v.string;
        }
        if (pm.value.object.get("message_id")) |v| {
            if (v == .string and v.string.len > 0) parsed.fields.message_id = v.string;
        }
        if (pm.value.object.get("guild_id")) |v| {
            if (v == .string) parsed.fields.guild_id = v.string;
        }
        if (pm.value.object.get("team_id")) |v| {
            if (v == .string) parsed.fields.team_id = v.string;
        }
        if (pm.value.object.get("channel_id")) |v| {
            if (v == .string) parsed.fields.channel_id = v.string;
        }
        if (pm.value.object.get("thread_id")) |v| {
            if (v == .string and v.string.len > 0) parsed.fields.thread_id = v.string;
        }
        if (pm.value.object.get("is_dm")) |v| {
            if (v == .bool) parsed.fields.is_dm = v.bool;
        }
        if (pm.value.object.get("is_group")) |v| {
            if (v == .bool) parsed.fields.is_group = v.bool;
        }
    }
    return parsed;
}

fn resolveInboundRouteSessionKeyWithMetadata(
    allocator: std.mem.Allocator,
    config: *const Config,
    msg: *const bus_mod.InboundMessage,
    meta: channel_adapters.InboundMetadata,
) ?[]const u8 {
    const route_desc = channel_adapters.findInboundRouteDescriptor(config, msg.channel);

    const account_id = meta.account_id orelse if (route_desc) |desc|
        desc.default_account_id(config, msg.channel) orelse "default"
    else
        "default";

    const peer = if (meta.peer_kind != null and meta.peer_id != null)
        agent_routing.PeerRef{ .kind = meta.peer_kind.?, .id = meta.peer_id.? }
    else if (route_desc) |desc|
        desc.derive_peer(.{
            .channel_name = msg.channel,
            .sender_id = msg.sender_id,
            .chat_id = msg.chat_id,
        }, meta) orelse return null
    else
        return null;
    const route = agent_routing.resolveRouteWithSession(allocator, .{
        .channel = msg.channel,
        .account_id = account_id,
        .peer = peer,
        .guild_id = meta.guild_id,
        .team_id = meta.team_id,
    }, config.agent_bindings, config.agents, config.session) catch return null;
    allocator.free(route.main_session_key);

    if (meta.thread_id) |thread_id| {
        const threaded = agent_routing.buildThreadSessionKey(allocator, route.session_key, thread_id) catch return route.session_key;
        allocator.free(route.session_key);
        return threaded;
    }
    return route.session_key;
}

fn resolveInboundRouteSessionKey(
    allocator: std.mem.Allocator,
    config: *const Config,
    msg: *const bus_mod.InboundMessage,
) ?[]const u8 {
    var parsed_meta = parseInboundMetadata(allocator, msg.metadata_json);
    defer parsed_meta.deinit();
    return resolveInboundRouteSessionKeyWithMetadata(allocator, config, msg, parsed_meta.fields);
}

const SlackStatusTarget = struct {
    channel_id: []const u8,
    thread_ts: []const u8,
};

fn resolveSlackStatusTarget(meta: channel_adapters.InboundMetadata, chat_id: []const u8) ?SlackStatusTarget {
    var channel_id = meta.channel_id orelse chat_id;
    if (std.mem.indexOfScalar(u8, channel_id, ':')) |idx| {
        if (idx > 0) channel_id = channel_id[0..idx];
    }
    if (channel_id.len == 0) return null;

    const thread_ts = meta.thread_id orelse meta.message_id orelse return null;
    if (thread_ts.len == 0) return null;

    return .{
        .channel_id = channel_id,
        .thread_ts = thread_ts,
    };
}

fn resolveTypingRecipient(
    allocator: std.mem.Allocator,
    channel_name: []const u8,
    chat_id: []const u8,
    meta: channel_adapters.InboundMetadata,
) ?[]u8 {
    if (std.mem.eql(u8, channel_name, "slack")) {
        const slack_target = resolveSlackStatusTarget(meta, chat_id) orelse return null;
        return std.fmt.allocPrint(allocator, "{s}:{s}", .{ slack_target.channel_id, slack_target.thread_ts }) catch null;
    }

    if (!std.mem.eql(u8, channel_name, "discord") and !std.mem.eql(u8, channel_name, "mattermost")) {
        return null;
    }
    if (chat_id.len == 0) return null;
    return allocator.dupe(u8, chat_id) catch null;
}

fn sendInboundProcessingIndicator(
    allocator: std.mem.Allocator,
    registry: *const dispatch.ChannelRegistry,
    channel_name: []const u8,
    account_id: ?[]const u8,
    chat_id: []const u8,
    meta: channel_adapters.InboundMetadata,
) ?[]u8 {
    const channel_opt = if (account_id) |aid|
        registry.findByNameAccount(channel_name, aid)
    else
        registry.findByName(channel_name);
    const ch = channel_opt orelse return null;

    const recipient = resolveTypingRecipient(allocator, channel_name, chat_id, meta) orelse return null;
    ch.startTyping(recipient) catch {
        allocator.free(recipient);
        return null;
    };
    return recipient;
}

fn clearInboundProcessingIndicator(
    allocator: std.mem.Allocator,
    registry: *const dispatch.ChannelRegistry,
    channel_name: []const u8,
    account_id: ?[]const u8,
    recipient: ?[]u8,
) void {
    const target = recipient orelse return;
    defer allocator.free(target);
    const channel_opt = if (account_id) |aid|
        registry.findByNameAccount(channel_name, aid)
    else
        registry.findByName(channel_name);
    const ch = channel_opt orelse return;
    ch.stopTyping(target) catch {};
}

fn inboundDispatcherThread(
    allocator: std.mem.Allocator,
    event_bus: *bus_mod.Bus,
    registry: *const dispatch.ChannelRegistry,
    runtime: *channel_loop.ChannelRuntime,
    state: *DaemonState,
) void {
    var evict_counter: u32 = 0;

    while (event_bus.consumeInbound()) |msg| {
        defer msg.deinit(allocator);

        var parsed_meta = parseInboundMetadata(allocator, msg.metadata_json);
        defer parsed_meta.deinit();

        const outbound_account_id = parsed_meta.fields.account_id;
        const routed_session_key = resolveInboundRouteSessionKeyWithMetadata(
            allocator,
            runtime.config,
            &msg,
            parsed_meta.fields,
        );
        defer if (routed_session_key) |key| allocator.free(key);
        const session_key = routed_session_key orelse msg.session_key;

        const typing_recipient = sendInboundProcessingIndicator(
            allocator,
            registry,
            msg.channel,
            outbound_account_id,
            msg.chat_id,
            parsed_meta.fields,
        );
        defer clearInboundProcessingIndicator(
            allocator,
            registry,
            msg.channel,
            outbound_account_id,
            typing_recipient,
        );

        const reply = runtime.session_mgr.processMessage(session_key, msg.content, null) catch |err| {
            log.warn("inbound dispatch process failed: {}", .{err});

            // Send user-visible error reply back to the originating channel
            const err_msg: []const u8 = switch (err) {
                error.CurlFailed, error.CurlReadError, error.CurlWaitError => "Network error. Please try again.",
                error.ProviderDoesNotSupportVision => "The current provider does not support image input.",
                error.NoResponseContent => "Model returned an empty response. Please try again.",
                error.OutOfMemory => "Out of memory.",
                else => "An error occurred. Try again.",
            };
            const err_out = if (outbound_account_id) |aid|
                bus_mod.makeOutboundWithAccount(allocator, msg.channel, aid, msg.chat_id, err_msg) catch continue
            else
                bus_mod.makeOutbound(allocator, msg.channel, msg.chat_id, err_msg) catch continue;
            event_bus.publishOutbound(err_out) catch {
                err_out.deinit(allocator);
            };
            continue;
        };
        defer allocator.free(reply);

        const out = (if (outbound_account_id) |aid|
            bus_mod.makeOutboundWithAccount(allocator, msg.channel, aid, msg.chat_id, reply)
        else
            bus_mod.makeOutbound(allocator, msg.channel, msg.chat_id, reply)) catch |err| {
            log.err("inbound dispatch makeOutbound failed: {}", .{err});
            continue;
        };

        event_bus.publishOutbound(out) catch |err| {
            out.deinit(allocator);
            if (err == error.Closed) break;
            log.err("inbound dispatch publishOutbound failed: {}", .{err});
            continue;
        };

        state.markRunning("inbound_dispatcher");
        health.markComponentOk("inbound_dispatcher");

        // Periodic session eviction for bus-based channels
        evict_counter += 1;
        if (evict_counter >= 100) {
            evict_counter = 0;
            _ = runtime.session_mgr.evictIdle(runtime.config.agent.session_idle_timeout_secs);
        }
    }
}

/// Run the long-lived runtime. This is the main entry point for `nullclaw gateway`.
/// Spawns threads for gateway, heartbeat, and channels, then loops until
/// shutdown is requested (Ctrl+C signal or explicit request).
/// `host` and `port` are CLI-parsed values that override `config.gateway`.
pub fn run(allocator: std.mem.Allocator, config: *const Config, host: []const u8, port: u16) !void {
    // Ensure lifecycle parity: workspace bootstrap files must exist
    // even when users skip onboard and start runtime directly.
    try onboard.scaffoldWorkspace(allocator, config.workspace_dir, &onboard.ProjectContext{});

    health.markComponentOk("daemon");
    shutdown_requested.store(false, .release);
    const has_supervised_channels = hasSupervisedChannels(config);
    const has_runtime_dependent_channels = channel_catalog.hasRuntimeDependentChannels(config);

    var state = DaemonState{
        .started = true,
        .gateway_host = host,
        .gateway_port = port,
    };
    state.addComponent("gateway");

    if (has_supervised_channels) {
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
    try stdout.print("nullclaw gateway runtime started\n", .{});
    try stdout.print("  Gateway:  http://{s}:{d}\n", .{ state.gateway_host, state.gateway_port });
    try stdout.print("  Components: {d} active\n", .{state.component_count});
    try stdout.flush();
    config.printModelConfig();
    try stdout.print("  Ctrl+C to stop\n\n", .{});
    try stdout.flush();

    // Write initial state file
    const state_path = try stateFilePath(allocator, config);
    defer allocator.free(state_path);
    writeStateFile(allocator, state_path, &state) catch |err| {
        try stdout.print("Warning: could not write state file: {}\n", .{err});
    };

    // Event bus (created before gateway+scheduler so all threads can publish)
    var event_bus = bus_mod.Bus.init();

    // Spawn gateway thread
    state.markRunning("gateway");
    const gw_thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, gatewayThread, .{ allocator, config, host, port, &state, &event_bus }) catch |err| {
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
    if (has_runtime_dependent_channels) {
        channel_rt = channel_loop.ChannelRuntime.init(allocator, config) catch |err| blk: {
            state.markError("channels", @errorName(err));
            health.markComponentError("channels", "runtime init failed");
            stdout.print(
                "Warning: channel runtime init failed ({s}); runtime-dependent channels disabled.\n",
                .{@errorName(err)},
            ) catch {};
            break :blk null;
        };
    }
    defer if (channel_rt) |rt| rt.deinit();

    // Spawn channel supervisor thread (only if channels are configured)
    var chan_thread: ?std.Thread = null;
    if (has_supervised_channels) {
        if (std.Thread.spawn(.{ .stack_size = 256 * 1024 }, channelSupervisorThread, .{
            allocator, config, &state, &channel_registry, channel_rt, &event_bus,
        })) |thread| {
            chan_thread = thread;
        } else |err| {
            state.markError("channels", @errorName(err));
            stdout.print("Warning: channel supervisor thread failed: {}\n", .{err}) catch {};
        }
    }

    var inbound_thread: ?std.Thread = null;
    if (channel_rt) |rt| {
        state.addComponent("inbound_dispatcher");
        if (std.Thread.spawn(.{ .stack_size = 512 * 1024 }, inboundDispatcherThread, .{
            allocator, &event_bus, &channel_registry, rt, &state,
        })) |thread| {
            inbound_thread = thread;
            state.markRunning("inbound_dispatcher");
            health.markComponentOk("inbound_dispatcher");
        } else |err| {
            state.markError("inbound_dispatcher", @errorName(err));
            stdout.print("Warning: inbound dispatcher thread failed: {}\n", .{err}) catch {};
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
    if (inbound_thread) |t| t.join();
    if (dispatcher_thread) |t| t.join();
    if (chan_thread) |t| t.join();
    if (sched_thread) |t| t.join();
    if (hb_thread) |t| t.join();
    gw_thread.join();

    try stdout.print("nullclaw gateway runtime stopped.\n", .{});
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

test "resolveInboundRouteSessionKey falls back to configured account_id" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "onebot-agent",
            .match = .{
                .channel = "onebot",
                .account_id = "onebot-main",
                .peer = .{ .kind = .direct, .id = "12345" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .onebot = &[_]@import("config_types.zig").OneBotConfig{.{
                .account_id = "onebot-main",
            }},
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "onebot",
        .sender_id = "12345",
        .chat_id = "12345",
        .content = "hello",
        .session_key = "onebot:12345",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:onebot-agent:onebot:direct:12345", routed.?);
}

test "resolveInboundRouteSessionKey routes onebot group messages by group id" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "onebot-group-agent",
            .match = .{
                .channel = "onebot",
                .account_id = "onebot-main",
                .peer = .{ .kind = .group, .id = "777" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .onebot = &[_]@import("config_types.zig").OneBotConfig{.{
                .account_id = "onebot-main",
            }},
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "onebot",
        .sender_id = "12345",
        .chat_id = "group:777",
        .content = "hello group",
        .session_key = "onebot:group:777",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:onebot-group-agent:onebot:group:777", routed.?);
}

test "resolveInboundRouteSessionKey prefers metadata account_id override" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "onebot-main-agent",
            .match = .{
                .channel = "onebot",
                .account_id = "main",
                .peer = .{ .kind = .direct, .id = "12345" },
            },
        },
        .{
            .agent_id = "onebot-backup-agent",
            .match = .{
                .channel = "onebot",
                .account_id = "backup",
                .peer = .{ .kind = .direct, .id = "12345" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .onebot = &[_]@import("config_types.zig").OneBotConfig{
                .{ .account_id = "main" },
                .{ .account_id = "backup" },
            },
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "onebot",
        .sender_id = "12345",
        .chat_id = "12345",
        .content = "hello",
        .session_key = "onebot:12345",
        .metadata_json = "{\"account_id\":\"backup\"}",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:onebot-backup-agent:onebot:direct:12345", routed.?);
}

test "resolveInboundRouteSessionKey supports custom maixcam channel name" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "camera-agent",
            .match = .{
                .channel = "vision-cam",
                .account_id = "cam-main",
                .peer = .{ .kind = .direct, .id = "device-1" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .maixcam = &[_]@import("config_types.zig").MaixCamConfig{.{
                .name = "vision-cam",
                .account_id = "cam-main",
            }},
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "vision-cam",
        .sender_id = "device-1",
        .chat_id = "device-1",
        .content = "person detected",
        .session_key = "vision-cam:device-1",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:camera-agent:vision-cam:direct:device-1", routed.?);
}

test "resolveInboundRouteSessionKey matches non-primary maixcam account by channel name" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "lab-camera-agent",
            .match = .{
                .channel = "vision-lab",
                .account_id = "cam-lab",
                .peer = .{ .kind = .direct, .id = "device-2" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .maixcam = &[_]@import("config_types.zig").MaixCamConfig{
                .{ .name = "vision-main", .account_id = "cam-main" },
                .{ .name = "vision-lab", .account_id = "cam-lab" },
            },
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "vision-lab",
        .sender_id = "device-2",
        .chat_id = "device-2",
        .content = "movement",
        .session_key = "vision-lab:device-2",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:lab-camera-agent:vision-lab:direct:device-2", routed.?);
}

test "resolveInboundRouteSessionKey routes discord channel messages by chat_id" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "discord-channel-agent",
            .match = .{
                .channel = "discord",
                .account_id = "discord-main",
                .peer = .{ .kind = .channel, .id = "778899" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .discord = &[_]@import("config_types.zig").DiscordConfig{
                .{ .account_id = "discord-main", .token = "token" },
            },
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "discord",
        .sender_id = "user-1",
        .chat_id = "778899",
        .content = "hello",
        .session_key = "discord:778899",
        .metadata_json = "{\"guild_id\":\"guild-1\"}",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:discord-channel-agent:discord:channel:778899", routed.?);
}

test "resolveInboundRouteSessionKey routes discord direct messages by sender" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "discord-dm-agent",
            .match = .{
                .channel = "discord",
                .account_id = "discord-main",
                .peer = .{ .kind = .direct, .id = "user-42" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .discord = &[_]@import("config_types.zig").DiscordConfig{
                .{ .account_id = "discord-main", .token = "token" },
            },
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "discord",
        .sender_id = "user-42",
        .chat_id = "some-channel",
        .content = "ping",
        .session_key = "discord:dm:user-42",
        .metadata_json = "{\"is_dm\":true}",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:discord-dm-agent:discord:direct:user-42", routed.?);
}

test "resolveInboundRouteSessionKey applies session dm_scope for direct messages" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "discord-dm-agent",
            .match = .{
                .channel = "discord",
                .account_id = "discord-main",
                .peer = .{ .kind = .direct, .id = "user-42" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .discord = &[_]@import("config_types.zig").DiscordConfig{
                .{ .account_id = "discord-main", .token = "token" },
            },
        },
        .session = .{
            .dm_scope = .per_peer,
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "discord",
        .sender_id = "user-42",
        .chat_id = "some-channel",
        .content = "ping",
        .session_key = "discord:dm:user-42",
        .metadata_json = "{\"is_dm\":true}",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:discord-dm-agent:direct:user-42", routed.?);
}

test "resolveInboundRouteSessionKey normalizes qq channel prefix for routed peer id" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "qq-channel-agent",
            .match = .{
                .channel = "qq",
                .account_id = "qq-main",
                .peer = .{ .kind = .channel, .id = "998877" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .qq = &[_]@import("config_types.zig").QQConfig{
                .{ .account_id = "qq-main" },
            },
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "qq",
        .sender_id = "qq-user",
        .chat_id = "channel:998877",
        .content = "hello",
        .session_key = "qq:channel:998877",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:qq-channel-agent:qq:channel:998877", routed.?);
}

test "resolveInboundRouteSessionKey routes slack channel messages by chat_id" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "slack-channel-agent",
            .match = .{
                .channel = "slack",
                .account_id = "sl-main",
                .peer = .{ .kind = .channel, .id = "C12345" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .slack = &[_]@import("config_types.zig").SlackConfig{
                .{ .account_id = "sl-main", .bot_token = "xoxb-token", .channel_id = "C12345" },
            },
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "slack",
        .sender_id = "U777",
        .chat_id = "C12345",
        .content = "hello",
        .session_key = "slack:sl-main:channel:C12345",
        .metadata_json = "{\"account_id\":\"sl-main\",\"is_dm\":false}",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:slack-channel-agent:slack:channel:C12345", routed.?);
}

test "resolveInboundRouteSessionKey routes slack direct messages by sender" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "slack-dm-agent",
            .match = .{
                .channel = "slack",
                .account_id = "sl-main",
                .peer = .{ .kind = .direct, .id = "U777" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .slack = &[_]@import("config_types.zig").SlackConfig{
                .{ .account_id = "sl-main", .bot_token = "xoxb-token", .channel_id = "D22222" },
            },
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "slack",
        .sender_id = "U777",
        .chat_id = "D22222",
        .content = "hi dm",
        .session_key = "slack:sl-main:direct:U777",
        .metadata_json = "{\"account_id\":\"sl-main\",\"is_dm\":true}",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:slack-dm-agent:slack:direct:U777", routed.?);
}

test "resolveInboundRouteSessionKey routes qq dm messages by sender id" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "qq-dm-agent",
            .match = .{
                .channel = "qq",
                .account_id = "qq-main",
                .peer = .{ .kind = .direct, .id = "qq-user-1" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .qq = &[_]@import("config_types.zig").QQConfig{
                .{ .account_id = "qq-main" },
            },
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "qq",
        .sender_id = "qq-user-1",
        .chat_id = "dm:session-abc",
        .content = "hello",
        .session_key = "qq:dm:session-abc",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:qq-dm-agent:qq:direct:qq-user-1", routed.?);
}

test "resolveInboundRouteSessionKey routes irc channel messages by chat id" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "irc-group-agent",
            .match = .{
                .channel = "irc",
                .account_id = "irc-main",
                .peer = .{ .kind = .group, .id = "#dev" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .irc = &[_]@import("config_types.zig").IrcConfig{
                .{ .account_id = "irc-main", .host = "irc.example.org", .nick = "bot" },
            },
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "irc",
        .sender_id = "alice",
        .chat_id = "#dev",
        .content = "hello",
        .session_key = "irc:irc-main:group:#dev",
        .metadata_json = "{\"account_id\":\"irc-main\",\"is_group\":true}",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:irc-group-agent:irc:group:#dev", routed.?);
}

test "resolveInboundRouteSessionKey routes irc direct messages by sender" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "irc-dm-agent",
            .match = .{
                .channel = "irc",
                .account_id = "irc-main",
                .peer = .{ .kind = .direct, .id = "alice" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .irc = &[_]@import("config_types.zig").IrcConfig{
                .{ .account_id = "irc-main", .host = "irc.example.org", .nick = "bot" },
            },
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "irc",
        .sender_id = "alice",
        .chat_id = "alice",
        .content = "hello dm",
        .session_key = "irc:irc-main:direct:alice",
        .metadata_json = "{\"account_id\":\"irc-main\",\"is_dm\":true}",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:irc-dm-agent:irc:direct:alice", routed.?);
}

test "resolveInboundRouteSessionKey routes mattermost by channel id and team" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "mm-group-agent",
            .match = .{
                .channel = "mattermost",
                .account_id = "mm-main",
                .team_id = "team-1",
                .peer = .{ .kind = .group, .id = "chan-g1" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .mattermost = &[_]@import("config_types.zig").MattermostConfig{
                .{
                    .account_id = "mm-main",
                    .bot_token = "token",
                    .base_url = "https://chat.example.com",
                },
            },
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "mattermost",
        .sender_id = "user-42",
        .chat_id = "channel:chan-g1",
        .content = "hello",
        .session_key = "mattermost:mm-main:group:chan-g1",
        .metadata_json = "{\"account_id\":\"mm-main\",\"is_group\":true,\"channel_id\":\"chan-g1\",\"team_id\":\"team-1\"}",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:mm-group-agent:mattermost:group:chan-g1", routed.?);
}

test "resolveInboundRouteSessionKey appends mattermost thread suffix" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "mm-thread-agent",
            .match = .{
                .channel = "mattermost",
                .account_id = "mm-main",
                .peer = .{ .kind = .channel, .id = "chan-c1" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
        .channels = .{
            .mattermost = &[_]@import("config_types.zig").MattermostConfig{
                .{
                    .account_id = "mm-main",
                    .bot_token = "token",
                    .base_url = "https://chat.example.com",
                },
            },
        },
    };
    const msg = bus_mod.InboundMessage{
        .channel = "mattermost",
        .sender_id = "user-11",
        .chat_id = "channel:chan-c1:thread:root-99",
        .content = "threaded",
        .session_key = "mattermost:mm-main:channel:chan-c1:thread:root-99",
        .metadata_json = "{\"account_id\":\"mm-main\",\"channel_id\":\"chan-c1\",\"thread_id\":\"root-99\"}",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:mm-thread-agent:mattermost:channel:chan-c1:thread:root-99", routed.?);
}

test "resolveInboundRouteSessionKey supports standardized peer metadata for unknown channel" {
    const allocator = std.testing.allocator;
    const bindings = [_]agent_routing.AgentBinding{
        .{
            .agent_id = "custom-agent",
            .match = .{
                .channel = "custom",
                .account_id = "custom-main",
                .peer = .{ .kind = .direct, .id = "user-7" },
            },
        },
    };
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .agent_bindings = &bindings,
    };
    const msg = bus_mod.InboundMessage{
        .channel = "custom",
        .sender_id = "ignored-sender",
        .chat_id = "ignored-chat",
        .content = "hello",
        .session_key = "custom:legacy",
        .metadata_json = "{\"account_id\":\"custom-main\",\"peer_kind\":\"direct\",\"peer_id\":\"user-7\"}",
    };

    const routed = resolveInboundRouteSessionKey(allocator, &config, &msg);
    try std.testing.expect(routed != null);
    defer allocator.free(routed.?);
    try std.testing.expectEqualStrings("agent:custom-agent:custom:direct:user-7", routed.?);
}

test "parseInboundMetadata extracts message_id and thread_id" {
    var parsed = parseInboundMetadata(
        std.testing.allocator,
        "{\"account_id\":\"sl-main\",\"channel_id\":\"C1\",\"message_id\":\"1700.1\",\"thread_id\":\"1700.0\"}",
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings("sl-main", parsed.fields.account_id.?);
    try std.testing.expectEqualStrings("C1", parsed.fields.channel_id.?);
    try std.testing.expectEqualStrings("1700.1", parsed.fields.message_id.?);
    try std.testing.expectEqualStrings("1700.0", parsed.fields.thread_id.?);
}

test "resolveSlackStatusTarget prefers thread_id then falls back to message_id" {
    const with_thread = resolveSlackStatusTarget(.{
        .channel_id = "C123",
        .message_id = "1700.1",
        .thread_id = "1700.0",
    }, "C123");
    try std.testing.expect(with_thread != null);
    try std.testing.expectEqualStrings("C123", with_thread.?.channel_id);
    try std.testing.expectEqualStrings("1700.0", with_thread.?.thread_ts);

    const with_message_only = resolveSlackStatusTarget(.{
        .channel_id = "C123",
        .message_id = "1700.1",
    }, "C123");
    try std.testing.expect(with_message_only != null);
    try std.testing.expectEqualStrings("1700.1", with_message_only.?.thread_ts);
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

test "mergeSchedulerTickChangesAndSave preserves externally added jobs" {
    const allocator = std.testing.allocator;
    const cmd_runtime = "echo merge_runtime_keep_7d1c";
    const cmd_external = "echo merge_external_add_9a42";

    var runtime = CronScheduler.init(allocator, 32, true);
    defer runtime.deinit();
    _ = try runtime.addJob("* * * * *", cmd_runtime);
    runtime.jobs.items[runtime.jobs.items.len - 1].next_run_secs = 0;
    try cron.saveJobs(&runtime);

    var loaded = CronScheduler.init(allocator, 32, true);
    defer loaded.deinit();
    try cron.loadJobs(&loaded);

    var before_tick: std.StringHashMapUnmanaged(SchedulerJobSnapshot) = .empty;
    defer {
        clearSchedulerSnapshot(allocator, &before_tick);
        before_tick.deinit(allocator);
    }
    try buildSchedulerSnapshot(allocator, &loaded, &before_tick);

    // Simulate concurrent writer adding a new job after scheduler reload.
    var external = CronScheduler.init(allocator, 32, true);
    defer external.deinit();
    try cron.loadJobs(&external);
    _ = try external.addJob("*/5 * * * *", cmd_external);
    try cron.saveJobs(&external);

    _ = loaded.tick(std.time.timestamp(), null);
    try mergeSchedulerTickChangesAndSave(allocator, &loaded, &before_tick);

    var merged = CronScheduler.init(allocator, 64, true);
    defer merged.deinit();
    try cron.loadJobs(&merged);

    var found_runtime = false;
    var found_external = false;
    for (merged.listJobs()) |job| {
        if (std.mem.eql(u8, job.command, cmd_runtime)) found_runtime = true;
        if (std.mem.eql(u8, job.command, cmd_external)) found_external = true;
    }
    try std.testing.expect(found_runtime);
    try std.testing.expect(found_external);
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
    var event_bus = bus_mod.Bus.init();

    const thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, channelSupervisorThread, .{
        std.testing.allocator, &config, &state, &channel_registry, null, &event_bus,
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
