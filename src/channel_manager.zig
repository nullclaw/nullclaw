//! Channel Manager — centralizes channel lifecycle (init, start, supervise, stop).
//!
//! Replaces the hardcoded Telegram/Signal-only logic in daemon.zig with a
//! generic system that handles all configured channels.

const std = @import("std");
const std_compat = @import("compat");
const Allocator = std.mem.Allocator;
const bus_mod = @import("bus.zig");
const Config = @import("config.zig").Config;
const config_types = @import("config_types.zig");
const channel_catalog = @import("channel_catalog.zig");
const channel_adapters = @import("channel_adapters.zig");
const dispatch = @import("channels/dispatch.zig");
const channel_loop = @import("channel_loop.zig");
const health = @import("health.zig");
const daemon = @import("daemon.zig");
const channels_mod = @import("channels/root.zig");
const telegram = channels_mod.telegram;
const mattermost = channels_mod.mattermost;
const discord = channels_mod.discord;
const dingtalk = channels_mod.dingtalk;
const imessage = channels_mod.imessage;
const qq = channels_mod.qq;
const onebot = channels_mod.onebot;
const maixcam = channels_mod.maixcam;
const external = channels_mod.external;
const slack = channels_mod.slack;
const irc = channels_mod.irc;
const web = channels_mod.web;
const Channel = channels_mod.Channel;

const log = std.log.scoped(.channel_manager);
const Atomic = @import("portable_atomic.zig").Atomic;

pub const ListenerType = enum {
    /// Telegram, Signal — poll in a loop
    polling,
    /// Discord, Mattermost, Slack, IRC, QQ(websocket), OneBot — internal socket/WebSocket loop
    gateway_loop,
    /// WhatsApp, Line, Lark — HTTP gateway receives
    webhook_only,
    /// Outbound-only channel lifecycle (start/stop/send, no inbound listener thread yet)
    send_only,
    /// Channel exists but no listener yet
    not_implemented,
};

pub const Entry = struct {
    name: []const u8,
    adapter_key: []const u8,
    account_id: []const u8 = "default",
    channel: Channel,
    listener_type: ListenerType,
    supervised: dispatch.SupervisedChannel,
    thread: ?std.Thread = null,
    polling_state: ?PollingState = null,
};

pub const PollingState = channel_loop.PollingState;

pub const ChannelManager = struct {
    allocator: Allocator,
    config: *const Config,
    registry: *dispatch.ChannelRegistry,
    runtime: ?*channel_loop.ChannelRuntime = null,
    event_bus: ?*bus_mod.Bus = null,
    entries: std.ArrayListUnmanaged(Entry) = .empty,

    pub fn init(allocator: Allocator, config: *const Config, registry: *dispatch.ChannelRegistry) !*ChannelManager {
        const self = try allocator.create(ChannelManager);
        self.* = .{
            .allocator = allocator,
            .config = config,
            .registry = registry,
        };
        return self;
    }

    pub fn deinit(self: *ChannelManager) void {
        // Stop all threads
        self.stopAll();

        self.entries.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn setRuntime(self: *ChannelManager, rt: *channel_loop.ChannelRuntime) void {
        self.runtime = rt;
    }

    pub fn setEventBus(self: *ChannelManager, eb: *bus_mod.Bus) void {
        self.event_bus = eb;
    }

    fn pollingLastActivity(state: PollingState) i64 {
        return switch (state) {
            .telegram => |ls| ls.last_activity.load(.acquire),
            .signal => |ls| ls.last_activity.load(.acquire),
            .weixin => |ls| ls.last_activity.load(.acquire),
            .matrix => |ls| ls.last_activity.load(.acquire),
            .max => |ls| ls.last_activity.load(.acquire),
        };
    }

    fn requestPollingStop(state: PollingState) void {
        switch (state) {
            .telegram => |ls| ls.stop_requested.store(true, .release),
            .signal => |ls| ls.stop_requested.store(true, .release),
            .weixin => |ls| ls.stop_requested.store(true, .release),
            .matrix => |ls| ls.stop_requested.store(true, .release),
            .max => |ls| ls.stop_requested.store(true, .release),
        }
    }

    fn destroyPollingState(allocator: Allocator, state: PollingState) void {
        switch (state) {
            .telegram => |ls| allocator.destroy(ls),
            .signal => |ls| allocator.destroy(ls),
            .weixin => |ls| allocator.destroy(ls),
            .matrix => |ls| allocator.destroy(ls),
            .max => |ls| allocator.destroy(ls),
        }
    }

    fn spawnPollingThread(self: *ChannelManager, entry: *Entry, rt: *channel_loop.ChannelRuntime) !void {
        const polling_desc = channel_adapters.findPollingDescriptor(entry.adapter_key) orelse
            return error.UnsupportedChannel;
        const spawned = try polling_desc.spawn(self.allocator, self.config, rt, entry.channel);
        entry.polling_state = spawned.state;
        entry.thread = spawned.thread;
    }

    fn isPollingSourceDuplicate(
        allocator: Allocator,
        entries: []const Entry,
        current_index: usize,
        polling_desc: *const channel_adapters.PollingDescriptor,
    ) bool {
        const source_key_fn = polling_desc.source_key orelse return false;
        const current = entries[current_index];
        if (!std.mem.eql(u8, current.adapter_key, polling_desc.channel_name)) return false;
        if (current.listener_type != .polling) return false;

        const current_source = source_key_fn(allocator, current.channel) orelse return false;
        defer allocator.free(current_source);

        var i: usize = 0;
        while (i < current_index) : (i += 1) {
            const prev = entries[i];
            if (!std.mem.eql(u8, prev.adapter_key, polling_desc.channel_name)) continue;
            if (prev.listener_type != .polling) continue;
            if (prev.supervised.state != .running) continue;

            const prev_source = source_key_fn(allocator, prev.channel) orelse continue;
            const duplicate = std.mem.eql(u8, prev_source, current_source);
            allocator.free(prev_source);
            if (duplicate) return true;
        }
        return false;
    }

    /// Grace period for a polling thread to observe `stop_requested` and exit.
    /// Every blocking call on the poller path is time-bounded (curl --max-time),
    /// so a cooperative poller joins cleanly once it returns from the call it is
    /// in. The grace must exceed the largest such bound on the poller path - a
    /// media upload on the reply-send path is bounded at 120s - so 150s lets a
    /// normal restart join; only a genuinely wedged thread is detached.
    const POLLING_STOP_GRACE_NS: u64 = 150 * std.time.ns_per_s;

    /// A dispatching poller that has not refreshed its turn heartbeat for this
    /// long is treated as stalled (a hung turn, tool, or worker join). Generous,
    /// because a single provider request can run for minutes before the next
    /// progress hint, and a long-but-progressing turn must not be restarted.
    const DISPATCH_STALL_SECS: i64 = 900;

    /// Hard wall-clock bound on how long a poller may stay out of the poll step,
    /// regardless of turn progress. `last_activity` only advances when a poll
    /// completes, so `now - last_activity` is the time spent dispatching. Without
    /// this, a turn that keeps emitting progress hints but never terminates is
    /// never declared stale - the one stall freshness alone cannot recover.
    const MAX_DISPATCH_SECS: i64 = 1800;

    /// Wait up to `grace_ns` for a polling thread to record that it exited.
    ///
    /// `std.Thread.join` has no timeout, so joining a thread wedged in a
    /// blocking syscall hangs the caller forever - the incident where a stale
    /// Telegram poller could not be restarted and only a manual container
    /// restart recovered the process. The polling loops set `exited` as their
    /// last action, so the supervisor can bound the wait and detach a thread
    /// that never comes back instead of blocking on it.
    fn waitForExit(exited: *const Atomic(bool), grace_ns: u64) bool {
        const deadline = std_compat.time.nanoTimestamp() + @as(i128, grace_ns);
        while (!exited.load(.acquire)) {
            if (std_compat.time.nanoTimestamp() >= deadline) return false;
            std_compat.thread.sleep(25 * std.time.ns_per_ms);
        }
        return true;
    }

    fn pollingExited(state: PollingState) *const Atomic(bool) {
        return switch (state) {
            .telegram => |ls| &ls.exited,
            .signal => |ls| &ls.exited,
            .weixin => |ls| &ls.exited,
            .matrix => |ls| &ls.exited,
            .max => |ls| &ls.exited,
        };
    }

    fn pollingStep(state: PollingState) u8 {
        return switch (state) {
            .telegram => |ls| ls.step.load(.acquire),
            .signal => |ls| ls.step.load(.acquire),
            .weixin => |ls| ls.step.load(.acquire),
            .matrix => |ls| ls.step.load(.acquire),
            .max => |ls| ls.step.load(.acquire),
        };
    }

    fn pollingProgress(state: PollingState) i64 {
        return switch (state) {
            .telegram => |ls| ls.progress.load(.acquire),
            .signal => |ls| ls.progress.load(.acquire),
            .weixin => |ls| ls.progress.load(.acquire),
            .matrix => |ls| ls.progress.load(.acquire),
            .max => |ls| ls.progress.load(.acquire),
        };
    }

    /// The poller's own liveness: the last completed poll (`last_activity`) or
    /// the last turn heartbeat (`progress`). Both are written only by the
    /// polling thread - a parallel worker's turn bumps the separate
    /// `turn_progress` cell - so a frozen value means the poller itself stalled.
    /// Do NOT fold worker progress in here: a wedged poller whose worker keeps
    /// streaming is exactly the stall the supervisor must recover.
    fn pollingFreshness(state: PollingState) i64 {
        return @max(pollingLastActivity(state), pollingProgress(state));
    }

    /// A poller in the poll step that has not completed a poll for this long is
    /// stale. Also the bound on how long a poller may go without re-entering the
    /// poll step (e.g. blocked joining a worker).
    const STALE_THRESHOLD_SECS: i64 = 600;

    /// Whether a poller is stale at `now`, from its own liveness only (see
    /// `pollingFreshness`), with a longer bound while it is dispatching so a
    /// long-but-progressing turn is not restarted. Also bounded by the hard
    /// dispatch wall-clock (`MAX_DISPATCH_SECS`): a turn that keeps progressing
    /// forever is still recovered.
    fn pollingStale(state: PollingState, now: i64) bool {
        const dispatching = pollingStep(state) == @intFromEnum(channel_loop.PollStep.dispatching);
        const threshold: i64 = if (dispatching) DISPATCH_STALL_SECS else STALE_THRESHOLD_SECS;
        if ((now - pollingFreshness(state)) > threshold) return true;
        return dispatching and (now - pollingLastActivity(state)) > MAX_DISPATCH_SECS;
    }

    fn pollingStepName(step: u8) []const u8 {
        return switch (step) {
            @intFromEnum(channel_loop.PollStep.polling) => "polling",
            @intFromEnum(channel_loop.PollStep.dispatching) => "dispatching",
            else => "startup",
        };
    }

    fn stopPollingThread(self: *ChannelManager, entry: *Entry) bool {
        return stopPollingThreadGrace(self.allocator, entry, POLLING_STOP_GRACE_NS);
    }

    /// Stop a polling thread, bounded so a wedged poller can never hang the
    /// caller (`std.Thread.join` has no timeout - the incident's supervisor
    /// deadlocked on exactly that).
    ///
    /// Returns true when the thread is gone (joined or detached) and the entry
    /// is cleared, so the caller may respawn; false when the poller is doing
    /// real work and was deliberately left running.
    fn stopPollingThreadGrace(allocator: Allocator, entry: *Entry, grace_ns: u64) bool {
        const state = entry.polling_state;
        if (entry.thread) |t| {
            if (state) |s| {
                // Leave a poller alone only while it is doing real, progressing
                // work: a turn that keeps refreshing its heartbeat. A poller in
                // the poll step is network-bound and bounded, and a poller whose
                // heartbeat has frozen is wedged - both are safe to stop. This is
                // what lets the supervisor recover a stall that happens *while
                // dispatching* (a hung turn or worker join), which the earlier
                // blanket dispatching-suppression made unrecoverable.
                const now = std_compat.time.timestamp();
                const progressing = (now - pollingProgress(s)) <= DISPATCH_STALL_SECS and
                    (now - pollingLastActivity(s)) <= MAX_DISPATCH_SECS;
                if (!pollingExited(s).load(.acquire) and
                    pollingStep(s) == @intFromEnum(channel_loop.PollStep.dispatching) and
                    progressing and
                    !daemon.isShutdownRequested())
                {
                    log.info("{s} poller busy (step={s}); leaving it running", .{ entry.name, pollingStepName(pollingStep(s)) });
                    return false;
                }
                requestPollingStop(s);
                if (waitForExit(pollingExited(s), grace_ns)) {
                    // The loop has left its body; join reclaims the thread promptly.
                    t.join();
                    destroyPollingState(allocator, s);
                    entry.polling_state = null;
                } else {
                    log.warn(
                        "{s} polling thread did not exit within {d}s (step={s}); detaching it so supervision can continue",
                        .{ entry.name, grace_ns / std.time.ns_per_s, pollingStepName(pollingStep(s)) },
                    );
                    // detach() lets the OS reclaim the thread and its 16 MiB
                    // stack on exit; dropping the handle without join/detach
                    // would leak that stack forever. The loop state is left
                    // allocated - the detached thread still owns it.
                    //
                    // The detached poller re-checks `stop_requested` at the top
                    // of its loop, so it exits as soon as the blocked call
                    // returns. Until then it can briefly run alongside the
                    // respawned poller and touch the same channel object (e.g.
                    // Telegram's last_update_id). Accepted: that window needs the
                    // blocked call to return after the grace, and the alternative
                    // - never restarting a wedged poller - is the incident.
                    t.detach();
                    entry.polling_state = null;
                }
            } else {
                // No loop state to signal stop through; detach rather than risk
                // an unbounded join (unreachable in practice: spawnPollingThread
                // always sets thread and state together).
                t.detach();
            }
            entry.thread = null;
            return true;
        }
        if (state) |s| {
            destroyPollingState(allocator, s);
            entry.polling_state = null;
        }
        return true;
    }

    fn listenerTypeFromMode(mode: channel_catalog.ListenerMode) ListenerType {
        return switch (mode) {
            .polling => .polling,
            .gateway_loop => .gateway_loop,
            .webhook_only => .webhook_only,
            .send_only => .send_only,
            .none => .not_implemented,
        };
    }

    fn listenerTypeForField(comptime field_name: []const u8) ListenerType {
        const meta = channel_catalog.findByKey(field_name) orelse
            @compileError("missing channel_catalog metadata for channel field: " ++ field_name);
        return listenerTypeFromMode(meta.listener_mode);
    }

    fn accountIdFromConfig(cfg: anytype) []const u8 {
        if (comptime @hasField(@TypeOf(cfg), "account_id")) {
            return cfg.account_id;
        }
        return "default";
    }

    fn maybeAttachBus(self: *ChannelManager, channel_ptr: anytype) void {
        const ChannelType = @TypeOf(channel_ptr.*);
        if (self.event_bus) |eb| {
            if (comptime @hasDecl(ChannelType, "setBus")) {
                channel_ptr.setBus(eb);
            }
        }
    }

    fn appendChannelFromConfig(self: *ChannelManager, comptime field_name: []const u8, cfg: anytype) !void {
        const channel_module = @field(channels_mod, field_name);
        const ChannelType = channelTypeForModule(channel_module, field_name);

        const ch_ptr = try self.allocator.create(ChannelType);
        ch_ptr.* = ChannelType.initFromConfig(self.allocator, cfg);
        if (comptime std.mem.eql(u8, field_name, "telegram")) {
            ch_ptr.text_debounce_secs = telegram.TelegramChannel.textDebounceSecsFromMs(
                self.config.messages.inbound.debounce_ms,
            );
        }
        self.maybeAttachBus(ch_ptr);

        const ch = ch_ptr.channel();
        const account_id = accountIdFromConfig(cfg);
        try self.registry.registerWithAccount(ch, account_id);

        var listener_type = comptime listenerTypeForField(field_name);
        if (comptime std.mem.eql(u8, field_name, "qq") or std.mem.eql(u8, field_name, "lark")) {
            listener_type = if (cfg.receive_mode == .webhook) .webhook_only else .gateway_loop;
        }
        if (comptime std.mem.eql(u8, field_name, "max")) {
            listener_type = if (cfg.mode == .webhook) .webhook_only else .polling;
        }
        try self.entries.append(self.allocator, .{
            .name = ch.name(),
            .adapter_key = field_name,
            .account_id = account_id,
            .channel = ch,
            .listener_type = listener_type,
            .supervised = dispatch.spawnSupervisedChannel(ch, 5),
        });
    }

    fn channelTypeForModule(comptime module: type, comptime field_name: []const u8) type {
        inline for (std.meta.declarations(module)) |decl| {
            const candidate = @field(module, decl.name);
            if (comptime @TypeOf(candidate) == type) {
                const T = candidate;
                if (comptime @hasDecl(T, "initFromConfig") and @hasDecl(T, "channel")) {
                    return T;
                }
            }
        }
        @compileError("channel module has no type with initFromConfig+channel methods: " ++ field_name);
    }

    /// Scan config, create channel instances, register in registry.
    pub fn collectConfiguredChannels(self: *ChannelManager) !void {
        inline for (std.meta.fields(config_types.ChannelsConfig)) |field| {
            if (comptime std.mem.eql(u8, field.name, "cli") or std.mem.eql(u8, field.name, "webhook")) {
                continue;
            }
            if (comptime !channel_catalog.isBuildEnabledByKey(field.name)) {
                continue;
            }
            if (comptime !@hasDecl(channels_mod, field.name)) {
                @compileError("channels/root.zig is missing module export for channel: " ++ field.name);
            }

            switch (@typeInfo(field.type)) {
                .pointer => |ptr| {
                    if (ptr.size != .slice) continue;
                    const items = @field(self.config.channels, field.name);
                    for (items) |cfg| {
                        try self.appendChannelFromConfig(field.name, cfg);
                    }
                },
                .optional => |opt| {
                    if (@field(self.config.channels, field.name)) |cfg| {
                        const inner = comptime blk: {
                            const info = @typeInfo(opt.child);
                            break :blk info == .pointer and info.pointer.size == .one;
                        };
                        if (inner) {
                            try self.appendChannelFromConfig(field.name, cfg.*);
                        } else {
                            try self.appendChannelFromConfig(field.name, cfg);
                        }
                    }
                },
                else => {},
            }
        }
    }

    /// Spawn listener threads for polling/gateway channels.
    pub fn startAll(self: *ChannelManager) !usize {
        var started: usize = 0;
        const runtime_available = self.runtime != null;

        for (self.entries.items, 0..) |*entry, index| {
            switch (entry.listener_type) {
                .polling => {
                    if (!runtime_available) {
                        log.warn("Cannot start {s}: no runtime available", .{entry.name});
                        continue;
                    }

                    if (channel_adapters.findPollingDescriptor(entry.adapter_key)) |polling_desc| {
                        if (isPollingSourceDuplicate(self.allocator, self.entries.items, index, polling_desc)) {
                            log.warn("Skipping duplicate {s} polling source for account_id={s}", .{ entry.name, entry.account_id });
                            continue;
                        }
                    }

                    self.spawnPollingThread(entry, self.runtime.?) catch |err| {
                        log.err("Failed to spawn {s} thread: {}", .{ entry.name, err });
                        continue;
                    };

                    entry.supervised.recordSuccess();
                    started += 1;
                    log.info("{s} polling thread started", .{entry.name});
                },
                .gateway_loop => {
                    if (!runtime_available) {
                        log.warn("Cannot start {s} gateway: no runtime available", .{entry.name});
                        continue;
                    }
                    // Gateway-loop channels (Discord, Mattermost, Slack, IRC, QQ, OneBot)
                    // manage their own connection/read loops.
                    entry.channel.start() catch |err| {
                        log.warn("Failed to start {s} gateway: {}", .{ entry.name, err });
                        continue;
                    };
                    started += 1;
                    log.info("{s} gateway started", .{entry.name});
                },
                .webhook_only => {
                    if (!runtime_available) {
                        log.warn("Cannot register {s} webhook: no runtime available", .{entry.name});
                        continue;
                    }
                    // Webhook channels don't need a thread — they receive via the HTTP gateway
                    entry.channel.start() catch |err| {
                        log.warn("Failed to start {s}: {}", .{ entry.name, err });
                        continue;
                    };
                    started += 1;
                    log.info("{s} registered (webhook-only)", .{entry.name});
                },
                .send_only => {
                    entry.channel.start() catch |err| {
                        log.warn("Failed to start {s}: {}", .{ entry.name, err });
                        continue;
                    };
                    started += 1;
                    log.info("{s} started (send-only)", .{entry.name});
                },
                .not_implemented => {
                    log.info("{s} configured but not implemented — skipping", .{entry.name});
                },
            }
        }

        return started;
    }

    /// On shutdown, wait up to the largest bound on the poller path so a poller
    /// parked in a bounded call (getUpdates ~45s, a media upload ~120s) exits
    /// and is joined rather than detached. Detaching on shutdown would let the
    /// poller outlive `ChannelManager.deinit` (which frees `entries`) and the
    /// daemon's `channel_rt.deinit()`/channel teardown, touching freed state.
    /// A genuinely wedged poller (no bounded call in flight) is still detached
    /// once this bound elapses; the daemon then exits promptly, so the process -
    /// not shared state - reclaims it.
    const SHUTDOWN_STOP_GRACE_NS: u64 = POLLING_STOP_GRACE_NS;

    /// Signal all threads to stop and join them.
    pub fn stopAll(self: *ChannelManager) void {
        for (self.entries.items) |*entry| {
            switch (entry.listener_type) {
                .polling => {
                    _ = stopPollingThreadGrace(self.allocator, entry, SHUTDOWN_STOP_GRACE_NS);
                },
                .gateway_loop, .webhook_only, .send_only => entry.channel.stop(),
                .not_implemented => {},
            }
        }
    }

    /// Monitoring loop: check health, restart failed channels with backoff.
    /// Blocks until shutdown.
    pub fn supervisionLoop(self: *ChannelManager, state: *daemon.DaemonState) void {
        const WATCH_INTERVAL_SECS: u64 = 10;

        while (!daemon.isShutdownRequested()) {
            std_compat.thread.sleep(WATCH_INTERVAL_SECS * std.time.ns_per_s);
            if (daemon.isShutdownRequested()) break;

            for (self.entries.items) |*entry| {
                // Gateway-loop channels: health check + restart on failure
                if (entry.listener_type == .gateway_loop) {
                    const probe_ok = entry.channel.healthCheck();
                    if (probe_ok) {
                        health.markComponentOk(entry.name);
                        if (entry.supervised.state != .running) entry.supervised.recordSuccess();
                    } else {
                        log.warn("{s} gateway health check failed", .{entry.name});
                        health.markComponentError(entry.name, "gateway health check failed");
                        entry.supervised.recordFailure();

                        if (entry.supervised.shouldRestart()) {
                            log.info("Restarting {s} gateway (attempt {d})", .{ entry.name, entry.supervised.restart_count });
                            state.markError("channels", "gateway health check failed");
                            entry.channel.stop();
                            std_compat.thread.sleep(entry.supervised.currentBackoffMs() * std.time.ns_per_ms);
                            entry.channel.start() catch |err| {
                                log.err("Failed to restart {s} gateway: {}", .{ entry.name, err });
                                continue;
                            };
                            entry.supervised.recordSuccess();
                            state.markRunning("channels");
                            health.markComponentOk(entry.name);
                        } else if (entry.supervised.state == .gave_up) {
                            state.markError("channels", "gave up after max restarts");
                            health.markComponentError(entry.name, "gave up after max restarts");
                        }
                    }
                    continue;
                }

                if (entry.listener_type != .polling) continue;

                const polling_state = entry.polling_state orelse continue;
                const now = std_compat.time.timestamp();
                const poller_step = pollingStep(polling_state);
                const stale = pollingStale(polling_state, now);

                const probe_ok = entry.channel.healthCheck();

                if (!stale and probe_ok) {
                    health.markComponentOk(entry.name);
                    state.markRunning("channels");
                    if (entry.supervised.state != .running) entry.supervised.recordSuccess();
                } else {
                    const reason: []const u8 = if (stale) "polling thread stale" else "health check failed";
                    log.warn("{s} issue: {s} (poller step: {s}, idle {d}s)", .{
                        entry.name,
                        reason,
                        pollingStepName(poller_step),
                        now - pollingFreshness(polling_state),
                    });
                    health.markComponentError(entry.name, reason);

                    // Snapshot before recording: a restart deferred because the
                    // poller is busy and progressing must not count against the
                    // circuit breaker, or repeated ticks would drive a healthy
                    // channel to gave_up.
                    const supervised_before = entry.supervised;
                    entry.supervised.recordFailure();

                    if (entry.supervised.shouldRestart()) {
                        log.info("Restarting {s} (attempt {d})", .{ entry.name, entry.supervised.restart_count });
                        state.markError("channels", reason);

                        // Stop old thread. Bounded: never blocks on a wedged
                        // poller. A poller busy dispatching is left running and
                        // the restart is retried on the next supervision tick.
                        if (!self.stopPollingThread(entry)) {
                            entry.supervised = supervised_before;
                            continue;
                        }

                        // Backoff
                        std_compat.thread.sleep(entry.supervised.currentBackoffMs() * std.time.ns_per_ms);

                        // Respawn
                        if (self.runtime) |rt| {
                            self.spawnPollingThread(entry, rt) catch |err| {
                                log.err("Failed to respawn {s} thread: {}", .{ entry.name, err });
                                continue;
                            };
                            log.info("{s} polling thread started", .{entry.name});
                            entry.supervised.recordSuccess();
                            state.markRunning("channels");
                            health.markComponentOk(entry.name);
                        }
                    } else if (entry.supervised.state == .gave_up) {
                        state.markError("channels", "gave up after max restarts");
                        health.markComponentError(entry.name, "gave up after max restarts");
                    }
                }
            }

            // If no polling channels, just mark healthy
            const has_polling = for (self.entries.items) |entry| {
                if (entry.listener_type == .polling) break true;
            } else false;
            if (!has_polling) {
                health.markComponentOk("channels");
            }
        }
    }

    /// Get all configured channel entries.
    pub fn channelEntries(self: *const ChannelManager) []const Entry {
        return self.entries.items;
    }

    /// Return the number of configured channels.
    pub fn count(self: *const ChannelManager) usize {
        return self.entries.items.len;
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "waitForExit honors an already-set exit flag and its deadline" {
    var exited = Atomic(bool).init(true);
    try std.testing.expect(ChannelManager.waitForExit(&exited, 1 * std.time.ns_per_s));

    var stuck = Atomic(bool).init(false);
    const start = std_compat.time.nanoTimestamp();
    try std.testing.expect(!ChannelManager.waitForExit(&stuck, 150 * std.time.ns_per_ms));
    const elapsed = std_compat.time.nanoTimestamp() - start;
    try std.testing.expect(elapsed >= 100 * std.time.ns_per_ms);
    try std.testing.expect(elapsed < 2 * std.time.ns_per_s);
}

test "pollingStepName maps recorded poll steps" {
    try std.testing.expectEqualStrings("polling", ChannelManager.pollingStepName(@intFromEnum(channel_loop.PollStep.polling)));
    try std.testing.expectEqualStrings("dispatching", ChannelManager.pollingStepName(@intFromEnum(channel_loop.PollStep.dispatching)));
    try std.testing.expectEqualStrings("startup", ChannelManager.pollingStepName(@intFromEnum(channel_loop.PollStep.startup)));
}

var test_stuck_release = Atomic(bool).init(false);

/// Stands in for a poller wedged in a blocking syscall: it never sets `exited`.
fn testStuckPoller() void {
    const deadline = std_compat.time.nanoTimestamp() + 5 * std.time.ns_per_s;
    while (!test_stuck_release.load(.acquire) and std_compat.time.nanoTimestamp() < deadline) {
        std_compat.thread.sleep(5 * std.time.ns_per_ms);
    }
}

/// Stands in for a cooperative poller: it records `exited` shortly after start.
fn testQuickExiter(state: *channel_loop.TelegramLoopState) void {
    std_compat.thread.sleep(50 * std.time.ns_per_ms);
    state.exited.store(true, .release);
}

fn testPollingEntry(thread: std.Thread, state: *channel_loop.TelegramLoopState) Entry {
    return .{
        .name = "telegram",
        .adapter_key = "telegram",
        .channel = undefined,
        .listener_type = .polling,
        .supervised = undefined,
        .thread = thread,
        .polling_state = .{ .telegram = state },
    };
}

test "stopPollingThreadGrace detaches a wedged poller instead of blocking" {
    // page_allocator: the detach path intentionally leaves the loop state
    // allocated (the detached thread owns it), so testing.allocator would flag
    // an expected leak.
    const allocator = std.heap.page_allocator;
    const state = try allocator.create(channel_loop.TelegramLoopState);
    state.* = channel_loop.TelegramLoopState.init();
    state.step.store(@intFromEnum(channel_loop.PollStep.polling), .release);

    test_stuck_release.store(false, .release);
    const thread = try std.Thread.spawn(.{}, testStuckPoller, .{});
    var entry = testPollingEntry(thread, state);

    const start = std_compat.time.nanoTimestamp();
    const stopped = ChannelManager.stopPollingThreadGrace(allocator, &entry, 150 * std.time.ns_per_ms);
    const elapsed = std_compat.time.nanoTimestamp() - start;

    // Must return within the grace instead of joining forever (the incident).
    try std.testing.expect(stopped);
    try std.testing.expect(elapsed < 2 * std.time.ns_per_s);
    try std.testing.expect(entry.thread == null);
    try std.testing.expect(entry.polling_state == null);
    // The stop was requested before detaching.
    try std.testing.expect(state.stop_requested.load(.acquire));

    test_stuck_release.store(true, .release);
}

test "stopPollingThreadGrace leaves a dispatching poller running" {
    const allocator = std.testing.allocator;
    const state = try allocator.create(channel_loop.TelegramLoopState);
    state.* = channel_loop.TelegramLoopState.init();
    state.step.store(@intFromEnum(channel_loop.PollStep.dispatching), .release);

    const thread = try std.Thread.spawn(.{}, testQuickExiter, .{state});
    var entry = testPollingEntry(thread, state);

    // A short grace must not detach a poller that is mid-turn.
    const stopped = ChannelManager.stopPollingThreadGrace(allocator, &entry, 20 * std.time.ns_per_ms);

    try std.testing.expect(!stopped);
    try std.testing.expect(entry.thread != null);
    try std.testing.expect(entry.polling_state != null);
    // It must never have been signalled to stop.
    try std.testing.expect(!state.stop_requested.load(.acquire));

    thread.join();
    allocator.destroy(state);
}

test "stopPollingThreadGrace stops a dispatching poller whose heartbeat is stale" {
    // page_allocator: the detach path intentionally leaves the loop state
    // allocated (the detached thread owns it).
    const allocator = std.heap.page_allocator;
    const state = try allocator.create(channel_loop.TelegramLoopState);
    state.* = channel_loop.TelegramLoopState.init();
    state.step.store(@intFromEnum(channel_loop.PollStep.dispatching), .release);
    // Frozen heartbeat: no turn progress for longer than the stall bound. This
    // is the hung turn/worker join the earlier suppression could never recover.
    state.progress.store(std_compat.time.timestamp() - (ChannelManager.DISPATCH_STALL_SECS + 30), .release);

    test_stuck_release.store(false, .release);
    const thread = try std.Thread.spawn(.{}, testStuckPoller, .{});
    var entry = testPollingEntry(thread, state);

    const stopped = ChannelManager.stopPollingThreadGrace(allocator, &entry, 150 * std.time.ns_per_ms);

    try std.testing.expect(stopped);
    try std.testing.expect(entry.thread == null);
    try std.testing.expect(entry.polling_state == null);
    try std.testing.expect(state.stop_requested.load(.acquire));

    test_stuck_release.store(true, .release);
}

test "pollingStale ignores a worker turn's progress while the poller is wedged" {
    const allocator = std.testing.allocator;
    const state = try allocator.create(channel_loop.TelegramLoopState);
    defer allocator.destroy(state);
    state.* = channel_loop.TelegramLoopState.init();

    const now: i64 = 10_000;
    // The poller itself has made no progress for 1000s (frozen in the poll
    // step)...
    state.last_activity.store(now - 1000, .release);
    state.progress.store(now - 1000, .release);
    state.step.store(@intFromEnum(channel_loop.PollStep.polling), .release);
    // ...but a parallel worker turn is still streaming.
    state.turn_progress.store(now, .release);

    // The supervisor must still declare it stale: worker progress is not poller
    // liveness. This fails if freshness goes back to max() over a cell that
    // worker turns also write.
    try std.testing.expect(ChannelManager.pollingStale(.{ .telegram = state }, now));

    // A progressing turn on the poller thread (dispatching step) is not stale...
    state.step.store(@intFromEnum(channel_loop.PollStep.dispatching), .release);
    state.progress.store(now, .release);
    try std.testing.expect(!ChannelManager.pollingStale(.{ .telegram = state }, now));

    // ...but a dispatching poller whose own heartbeat has frozen is.
    state.progress.store(now - (ChannelManager.DISPATCH_STALL_SECS + 1), .release);
    try std.testing.expect(ChannelManager.pollingStale(.{ .telegram = state }, now));
}

test "pollingFreshness tracks the newest of poll activity and turn progress" {
    const allocator = std.testing.allocator;
    const state = try allocator.create(channel_loop.TelegramLoopState);
    defer allocator.destroy(state);
    state.* = channel_loop.TelegramLoopState.init();

    state.last_activity.store(100, .release);
    state.progress.store(250, .release);
    try std.testing.expectEqual(@as(i64, 250), ChannelManager.pollingFreshness(.{ .telegram = state }));

    state.last_activity.store(300, .release);
    try std.testing.expectEqual(@as(i64, 300), ChannelManager.pollingFreshness(.{ .telegram = state }));
}

test "stopPollingThreadGrace joins a cooperative poller and frees its state" {
    const allocator = std.testing.allocator;
    const state = try allocator.create(channel_loop.TelegramLoopState);
    state.* = channel_loop.TelegramLoopState.init();
    state.step.store(@intFromEnum(channel_loop.PollStep.polling), .release);

    const thread = try std.Thread.spawn(.{}, testQuickExiter, .{state});
    var entry = testPollingEntry(thread, state);

    const stopped = ChannelManager.stopPollingThreadGrace(allocator, &entry, 3 * std.time.ns_per_s);

    try std.testing.expect(stopped);
    try std.testing.expect(entry.thread == null);
    try std.testing.expect(entry.polling_state == null);
    // testing.allocator fails the test if the loop state was not freed by the
    // join path.
}

test "PollingState has telegram signal weixin matrix and max variants" {
    try std.testing.expect(@intFromEnum(@as(std.meta.Tag(PollingState), .telegram)) !=
        @intFromEnum(@as(std.meta.Tag(PollingState), .signal)));
    try std.testing.expect(@intFromEnum(@as(std.meta.Tag(PollingState), .signal)) !=
        @intFromEnum(@as(std.meta.Tag(PollingState), .weixin)));
    try std.testing.expect(@intFromEnum(@as(std.meta.Tag(PollingState), .weixin)) !=
        @intFromEnum(@as(std.meta.Tag(PollingState), .matrix)));
    try std.testing.expect(@intFromEnum(@as(std.meta.Tag(PollingState), .matrix)) !=
        @intFromEnum(@as(std.meta.Tag(PollingState), .max)));
}

test "ListenerType enum values distinct" {
    try std.testing.expect(@intFromEnum(ListenerType.polling) != @intFromEnum(ListenerType.gateway_loop));
    try std.testing.expect(@intFromEnum(ListenerType.gateway_loop) != @intFromEnum(ListenerType.webhook_only));
    try std.testing.expect(@intFromEnum(ListenerType.webhook_only) != @intFromEnum(ListenerType.not_implemented));
}

test "isPollingSourceDuplicate detects duplicate signal source" {
    const allocator = std.testing.allocator;

    var sig_a = @import("channels/signal.zig").SignalChannel.init(
        allocator,
        "http://127.0.0.1:8080",
        "+15550001111",
        &.{},
        &.{},
        false,
        false,
    );
    sig_a.account_id = "main";
    var sig_b = @import("channels/signal.zig").SignalChannel.init(
        allocator,
        "http://127.0.0.1:8080",
        "+15550001111",
        &.{},
        &.{},
        false,
        false,
    );
    sig_b.account_id = "backup";

    var sup_a = dispatch.spawnSupervisedChannel(sig_a.channel(), 5);
    sup_a.recordSuccess();
    const sup_b = dispatch.spawnSupervisedChannel(sig_b.channel(), 5);

    var entries = [_]Entry{
        .{
            .name = "signal",
            .adapter_key = "signal",
            .account_id = "main",
            .channel = sig_a.channel(),
            .listener_type = .polling,
            .supervised = sup_a,
            .thread = null,
        },
        .{
            .name = "signal",
            .adapter_key = "signal",
            .account_id = "backup",
            .channel = sig_b.channel(),
            .listener_type = .polling,
            .supervised = sup_b,
            .thread = null,
        },
    };

    const desc = channel_adapters.findPollingDescriptor("signal").?;
    try std.testing.expect(ChannelManager.isPollingSourceDuplicate(allocator, &entries, 1, desc));
}

test "isPollingSourceDuplicate ignores distinct signal source" {
    const allocator = std.testing.allocator;

    var sig_a = @import("channels/signal.zig").SignalChannel.init(
        allocator,
        "http://127.0.0.1:8080",
        "+15550001111",
        &.{},
        &.{},
        false,
        false,
    );
    var sig_b = @import("channels/signal.zig").SignalChannel.init(
        allocator,
        "http://127.0.0.1:8080",
        "+15550002222",
        &.{},
        &.{},
        false,
        false,
    );

    var sup_a = dispatch.spawnSupervisedChannel(sig_a.channel(), 5);
    sup_a.recordSuccess();
    const sup_b = dispatch.spawnSupervisedChannel(sig_b.channel(), 5);

    var entries = [_]Entry{
        .{
            .name = "signal",
            .adapter_key = "signal",
            .account_id = "main",
            .channel = sig_a.channel(),
            .listener_type = .polling,
            .supervised = sup_a,
            .thread = null,
        },
        .{
            .name = "signal",
            .adapter_key = "signal",
            .account_id = "backup",
            .channel = sig_b.channel(),
            .listener_type = .polling,
            .supervised = sup_b,
            .thread = null,
        },
    };

    const desc = channel_adapters.findPollingDescriptor("signal").?;
    try std.testing.expect(!ChannelManager.isPollingSourceDuplicate(allocator, &entries, 1, desc));
}

test "isPollingSourceDuplicate detects duplicate telegram source" {
    const allocator = std.testing.allocator;

    var tg_a = @import("channels/telegram.zig").TelegramChannel.init(
        allocator,
        "same-token",
        &.{},
        &.{},
        "allowlist",
    );
    tg_a.account_id = "main";
    var tg_b = @import("channels/telegram.zig").TelegramChannel.init(
        allocator,
        "same-token",
        &.{},
        &.{},
        "allowlist",
    );
    tg_b.account_id = "backup";

    var sup_a = dispatch.spawnSupervisedChannel(tg_a.channel(), 5);
    sup_a.recordSuccess();
    const sup_b = dispatch.spawnSupervisedChannel(tg_b.channel(), 5);

    var entries = [_]Entry{
        .{
            .name = "telegram",
            .adapter_key = "telegram",
            .account_id = "main",
            .channel = tg_a.channel(),
            .listener_type = .polling,
            .supervised = sup_a,
            .thread = null,
        },
        .{
            .name = "telegram",
            .adapter_key = "telegram",
            .account_id = "backup",
            .channel = tg_b.channel(),
            .listener_type = .polling,
            .supervised = sup_b,
            .thread = null,
        },
    };

    const desc = channel_adapters.findPollingDescriptor("telegram").?;
    try std.testing.expect(ChannelManager.isPollingSourceDuplicate(allocator, &entries, 1, desc));
}

test "isPollingSourceDuplicate ignores distinct telegram source" {
    const allocator = std.testing.allocator;

    var tg_a = @import("channels/telegram.zig").TelegramChannel.init(
        allocator,
        "token-a",
        &.{},
        &.{},
        "allowlist",
    );
    var tg_b = @import("channels/telegram.zig").TelegramChannel.init(
        allocator,
        "token-b",
        &.{},
        &.{},
        "allowlist",
    );

    var sup_a = dispatch.spawnSupervisedChannel(tg_a.channel(), 5);
    sup_a.recordSuccess();
    const sup_b = dispatch.spawnSupervisedChannel(tg_b.channel(), 5);

    var entries = [_]Entry{
        .{
            .name = "telegram",
            .adapter_key = "telegram",
            .account_id = "main",
            .channel = tg_a.channel(),
            .listener_type = .polling,
            .supervised = sup_a,
            .thread = null,
        },
        .{
            .name = "telegram",
            .adapter_key = "telegram",
            .account_id = "backup",
            .channel = tg_b.channel(),
            .listener_type = .polling,
            .supervised = sup_b,
            .thread = null,
        },
    };

    const desc = channel_adapters.findPollingDescriptor("telegram").?;
    try std.testing.expect(!ChannelManager.isPollingSourceDuplicate(allocator, &entries, 1, desc));
}

test "ChannelManager init and deinit" {
    const allocator = std.testing.allocator;
    var reg = dispatch.ChannelRegistry.init(allocator);
    defer reg.deinit();
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
    };
    const mgr = try ChannelManager.init(allocator, &config, &reg);
    try std.testing.expectEqual(@as(usize, 0), mgr.count());
    mgr.deinit();
}

test "ChannelManager no channels configured" {
    const allocator = std.testing.allocator;
    var reg = dispatch.ChannelRegistry.init(allocator);
    defer reg.deinit();
    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
    };
    const mgr = try ChannelManager.init(allocator, &config, &reg);
    defer mgr.deinit();

    try mgr.collectConfiguredChannels();
    try std.testing.expectEqual(@as(usize, 0), mgr.count());
    try std.testing.expectEqual(@as(usize, 0), mgr.channelEntries().len);
}

fn countEntriesByListenerType(entries: []const Entry, listener_type: ListenerType) usize {
    var count: usize = 0;
    for (entries) |entry| {
        if (entry.listener_type == listener_type) count += 1;
    }
    return count;
}

fn findEntryByNameAccount(entries: []const Entry, name: []const u8, account_id: []const u8) ?*const Entry {
    for (entries) |*entry| {
        if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.account_id, account_id)) {
            return entry;
        }
    }
    return null;
}

fn expectEntryPresence(entries: []const Entry, name: []const u8, account_id: []const u8, should_exist: bool) !void {
    try std.testing.expectEqual(should_exist, findEntryByNameAccount(entries, name, account_id) != null);
}

test "ChannelManager collectConfiguredChannels wires listener types accounts and bus" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const telegram_accounts = [_]@import("config_types.zig").TelegramConfig{
        .{ .account_id = "main", .bot_token = "tg-main-token" },
        .{ .account_id = "backup", .bot_token = "tg-backup-token" },
    };
    const signal_accounts = [_]@import("config_types.zig").SignalConfig{
        .{
            .account_id = "sig-main",
            .http_url = "http://localhost:8080",
            .account = "+15550001111",
        },
    };
    const discord_accounts = [_]@import("config_types.zig").DiscordConfig{
        .{ .account_id = "dc-main", .token = "discord-token" },
    };
    const qq_accounts = [_]@import("config_types.zig").QQConfig{
        .{
            .account_id = "qq-main",
            .app_id = "appid",
            .app_secret = "appsecret",
            .bot_token = "bottoken",
            .receive_mode = .websocket,
        },
    };
    const onebot_accounts = [_]@import("config_types.zig").OneBotConfig{
        .{ .account_id = "ob-main", .url = "ws://localhost:6700" },
    };
    const mattermost_accounts = [_]@import("config_types.zig").MattermostConfig{
        .{
            .account_id = "mm-main",
            .bot_token = "mm-token",
            .base_url = "https://chat.example.com",
            .allow_from = &.{"user-a"},
            .group_policy = "allowlist",
        },
    };
    const slack_allow = [_][]const u8{"slack-admin"};
    const slack_accounts = [_]@import("config_types.zig").SlackConfig{
        .{
            .account_id = "sl-main",
            .bot_token = "xoxb-token",
            .allow_from = &slack_allow,
            .dm_policy = "deny",
            .group_policy = "allowlist",
        },
    };
    const maixcam_accounts = [_]@import("config_types.zig").MaixCamConfig{
        .{ .account_id = "cam-main", .name = "maixcam-main" },
    };
    const external_accounts = [_]@import("config_types.zig").ExternalChannelConfig{
        .{
            .account_id = "ext-main",
            .runtime_name = "whatsapp_web",
            .transport = .{
                .command = "nullclaw-plugin-whatsapp-web",
            },
            .plugin_config_json = "{\"allow_from\":[\"*\"]}",
        },
    };
    const max_accounts = [_]@import("config_types.zig").MaxConfig{
        .{
            .account_id = "max-poll",
            .bot_token = "max-token-poll",
            .mode = .polling,
        },
        .{
            .account_id = "max-webhook",
            .bot_token = "max-token-hook",
            .mode = .webhook,
            .webhook_url = "https://example.com/max",
        },
    };

    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .channels = .{
            .telegram = &telegram_accounts,
            .signal = &signal_accounts,
            .discord = &discord_accounts,
            .qq = &qq_accounts,
            .onebot = &onebot_accounts,
            .mattermost = &mattermost_accounts,
            .slack = &slack_accounts,
            .maixcam = &maixcam_accounts,
            .external = &external_accounts,
            .max = &max_accounts,
            .whatsapp = &[_]@import("config_types.zig").WhatsAppConfig{
                .{
                    .account_id = "wa-main",
                    .access_token = "wa-access",
                    .phone_number_id = "123456",
                    .verify_token = "wa-verify",
                },
            },
            .line = &[_]@import("config_types.zig").LineConfig{
                .{
                    .account_id = "line-main",
                    .access_token = "line-token",
                    .channel_secret = "line-secret",
                },
            },
            .lark = &[_]@import("config_types.zig").LarkConfig{
                .{
                    .account_id = "lark-main",
                    .app_id = "cli_xxx",
                    .app_secret = "secret_xxx",
                },
            },
            .matrix = &[_]@import("config_types.zig").MatrixConfig{
                .{
                    .account_id = "mx-main",
                    .homeserver = "https://matrix.example",
                    .access_token = "mx-token",
                    .room_id = "!room:example",
                },
            },
            .irc = &[_]@import("config_types.zig").IrcConfig{
                .{
                    .account_id = "irc-main",
                    .host = "irc.example.net",
                    .nick = "nullclaw",
                },
            },
            .imessage = &[_]@import("config_types.zig").IMessageConfig{
                .{
                    .account_id = "imain",
                    .allow_from = &.{"user@example.com"},
                    .enabled = true,
                },
            },
            .email = &[_]@import("config_types.zig").EmailConfig{
                .{
                    .account_id = "email-main",
                    .username = "bot@example.com",
                    .password = "secret",
                    .from_address = "bot@example.com",
                },
            },
            .dingtalk = &[_]@import("config_types.zig").DingTalkConfig{
                .{
                    .account_id = "ding-main",
                    .client_id = "ding-id",
                    .client_secret = "ding-secret",
                },
            },
        },
    };

    var reg = dispatch.ChannelRegistry.init(allocator);
    defer reg.deinit();

    var event_bus = bus_mod.Bus.init();

    const mgr = try ChannelManager.init(allocator, &config, &reg);
    defer mgr.deinit();
    mgr.setEventBus(&event_bus);

    try mgr.collectConfiguredChannels();

    var expected_total: usize = 0;
    var expected_polling: usize = 0;
    var expected_gateway_loop: usize = 0;
    var expected_webhook_only: usize = 0;
    var expected_send_only: usize = 0;

    if (channel_catalog.isBuildEnabled(.telegram)) {
        expected_total += telegram_accounts.len;
        expected_polling += telegram_accounts.len;
    }
    if (channel_catalog.isBuildEnabled(.signal)) {
        expected_total += signal_accounts.len;
        expected_polling += signal_accounts.len;
    }
    if (channel_catalog.isBuildEnabled(.discord)) {
        expected_total += discord_accounts.len;
        expected_gateway_loop += discord_accounts.len;
    }
    if (channel_catalog.isBuildEnabled(.qq)) {
        expected_total += qq_accounts.len;
        expected_gateway_loop += qq_accounts.len;
    }
    if (channel_catalog.isBuildEnabled(.onebot)) {
        expected_total += onebot_accounts.len;
        expected_gateway_loop += onebot_accounts.len;
    }
    if (channel_catalog.isBuildEnabled(.mattermost)) {
        expected_total += mattermost_accounts.len;
        expected_gateway_loop += mattermost_accounts.len;
    }
    if (channel_catalog.isBuildEnabled(.slack)) {
        expected_total += slack_accounts.len;
        expected_gateway_loop += slack_accounts.len;
    }
    if (channel_catalog.isBuildEnabled(.maixcam)) {
        expected_total += maixcam_accounts.len;
        expected_send_only += maixcam_accounts.len;
    }
    if (channel_catalog.isBuildEnabled(.external)) {
        expected_total += external_accounts.len;
        expected_gateway_loop += external_accounts.len;
    }
    if (channel_catalog.isBuildEnabled(.max)) {
        expected_total += max_accounts.len;
        for (max_accounts) |max_cfg| {
            if (max_cfg.mode == .webhook) {
                expected_webhook_only += 1;
            } else {
                expected_polling += 1;
            }
        }
    }
    if (channel_catalog.isBuildEnabled(.whatsapp)) {
        expected_total += config.channels.whatsapp.len;
        expected_webhook_only += config.channels.whatsapp.len;
    }
    if (channel_catalog.isBuildEnabled(.line)) {
        expected_total += config.channels.line.len;
        expected_webhook_only += config.channels.line.len;
    }
    if (channel_catalog.isBuildEnabled(.lark)) {
        expected_total += config.channels.lark.len;
        for (config.channels.lark) |lark_cfg| {
            if (lark_cfg.receive_mode == .webhook) {
                expected_webhook_only += 1;
            } else {
                expected_gateway_loop += 1;
            }
        }
    }
    if (channel_catalog.isBuildEnabled(.matrix)) {
        expected_total += config.channels.matrix.len;
        expected_polling += config.channels.matrix.len;
    }
    if (channel_catalog.isBuildEnabled(.irc)) {
        expected_total += config.channels.irc.len;
        expected_gateway_loop += config.channels.irc.len;
    }
    if (channel_catalog.isBuildEnabled(.imessage)) {
        expected_total += config.channels.imessage.len;
        expected_gateway_loop += config.channels.imessage.len;
    }
    if (channel_catalog.isBuildEnabled(.email)) {
        expected_total += config.channels.email.len;
        expected_send_only += config.channels.email.len;
    }
    if (channel_catalog.isBuildEnabled(.dingtalk)) {
        expected_total += config.channels.dingtalk.len;
        expected_gateway_loop += config.channels.dingtalk.len;
    }

    try std.testing.expectEqual(expected_total, mgr.count());
    try std.testing.expectEqual(expected_total, reg.count());

    const entries = mgr.channelEntries();
    try std.testing.expectEqual(expected_polling, countEntriesByListenerType(entries, .polling));
    try std.testing.expectEqual(expected_gateway_loop, countEntriesByListenerType(entries, .gateway_loop));
    try std.testing.expectEqual(expected_webhook_only, countEntriesByListenerType(entries, .webhook_only));
    try std.testing.expectEqual(expected_send_only, countEntriesByListenerType(entries, .send_only));
    try std.testing.expectEqual(@as(usize, 0), countEntriesByListenerType(entries, .not_implemented));

    try expectEntryPresence(entries, "telegram", "main", channel_catalog.isBuildEnabled(.telegram));
    try expectEntryPresence(entries, "telegram", "backup", channel_catalog.isBuildEnabled(.telegram));
    try expectEntryPresence(entries, "signal", "sig-main", channel_catalog.isBuildEnabled(.signal));
    try expectEntryPresence(entries, "discord", "dc-main", channel_catalog.isBuildEnabled(.discord));
    try expectEntryPresence(entries, "qq", "qq-main", channel_catalog.isBuildEnabled(.qq));
    try expectEntryPresence(entries, "onebot", "ob-main", channel_catalog.isBuildEnabled(.onebot));
    try expectEntryPresence(entries, "mattermost", "mm-main", channel_catalog.isBuildEnabled(.mattermost));
    try expectEntryPresence(entries, "slack", "sl-main", channel_catalog.isBuildEnabled(.slack));
    try expectEntryPresence(entries, "maixcam-main", "cam-main", channel_catalog.isBuildEnabled(.maixcam));
    try expectEntryPresence(entries, "whatsapp_web", "ext-main", channel_catalog.isBuildEnabled(.external));
    try expectEntryPresence(entries, "max", "max-poll", channel_catalog.isBuildEnabled(.max));
    try expectEntryPresence(entries, "max", "max-webhook", channel_catalog.isBuildEnabled(.max));
    try expectEntryPresence(entries, "whatsapp", "wa-main", channel_catalog.isBuildEnabled(.whatsapp));
    try expectEntryPresence(entries, "line", "line-main", channel_catalog.isBuildEnabled(.line));
    try expectEntryPresence(entries, "lark", "lark-main", channel_catalog.isBuildEnabled(.lark));
    try expectEntryPresence(entries, "matrix", "mx-main", channel_catalog.isBuildEnabled(.matrix));
    try expectEntryPresence(entries, "irc", "irc-main", channel_catalog.isBuildEnabled(.irc));
    try expectEntryPresence(entries, "imessage", "imain", channel_catalog.isBuildEnabled(.imessage));
    try expectEntryPresence(entries, "email", "email-main", channel_catalog.isBuildEnabled(.email));
    try expectEntryPresence(entries, "dingtalk", "ding-main", channel_catalog.isBuildEnabled(.dingtalk));

    if (channel_catalog.isBuildEnabled(.discord)) {
        const discord_entry = findEntryByNameAccount(entries, "discord", "dc-main") orelse
            return error.TestUnexpectedResult;
        const discord_ptr: *discord.DiscordChannel = @ptrCast(@alignCast(discord_entry.channel.ptr));
        try std.testing.expect(discord_ptr.bus == &event_bus);
    }

    if (channel_catalog.isBuildEnabled(.qq)) {
        const qq_entry = findEntryByNameAccount(entries, "qq", "qq-main") orelse
            return error.TestUnexpectedResult;
        const qq_ptr: *qq.QQChannel = @ptrCast(@alignCast(qq_entry.channel.ptr));
        try std.testing.expect(qq_ptr.event_bus == &event_bus);
    }

    if (channel_catalog.isBuildEnabled(.onebot)) {
        const onebot_entry = findEntryByNameAccount(entries, "onebot", "ob-main") orelse
            return error.TestUnexpectedResult;
        const onebot_ptr: *onebot.OneBotChannel = @ptrCast(@alignCast(onebot_entry.channel.ptr));
        try std.testing.expect(onebot_ptr.event_bus == &event_bus);
    }

    if (channel_catalog.isBuildEnabled(.mattermost)) {
        const mattermost_entry = findEntryByNameAccount(entries, "mattermost", "mm-main") orelse
            return error.TestUnexpectedResult;
        const mattermost_ptr: *mattermost.MattermostChannel = @ptrCast(@alignCast(mattermost_entry.channel.ptr));
        try std.testing.expect(mattermost_ptr.bus == &event_bus);
    }

    if (channel_catalog.isBuildEnabled(.irc)) {
        const irc_entry = findEntryByNameAccount(entries, "irc", "irc-main") orelse
            return error.TestUnexpectedResult;
        const irc_ptr: *irc.IrcChannel = @ptrCast(@alignCast(irc_entry.channel.ptr));
        try std.testing.expect(irc_ptr.bus == &event_bus);
    }

    if (channel_catalog.isBuildEnabled(.imessage)) {
        const imessage_entry = findEntryByNameAccount(entries, "imessage", "imain") orelse
            return error.TestUnexpectedResult;
        const imessage_ptr: *imessage.IMessageChannel = @ptrCast(@alignCast(imessage_entry.channel.ptr));
        try std.testing.expect(imessage_ptr.bus == &event_bus);
    }

    if (channel_catalog.isBuildEnabled(.maixcam)) {
        const maixcam_entry = findEntryByNameAccount(entries, "maixcam-main", "cam-main") orelse
            return error.TestUnexpectedResult;
        const maixcam_ptr: *maixcam.MaixCamChannel = @ptrCast(@alignCast(maixcam_entry.channel.ptr));
        try std.testing.expect(maixcam_ptr.event_bus == &event_bus);
    }

    if (channel_catalog.isBuildEnabled(.external)) {
        const external_entry = findEntryByNameAccount(entries, "whatsapp_web", "ext-main") orelse
            return error.TestUnexpectedResult;
        const external_ptr: *external.ExternalChannel = @ptrCast(@alignCast(external_entry.channel.ptr));
        try std.testing.expectEqualStrings("external", external_entry.adapter_key);
        try std.testing.expectEqual(ListenerType.gateway_loop, external_entry.listener_type);
        try std.testing.expect(external_ptr.event_bus == &event_bus);
    }

    if (channel_catalog.isBuildEnabled(.slack)) {
        const slack_entry = findEntryByNameAccount(entries, "slack", "sl-main") orelse
            return error.TestUnexpectedResult;
        const slack_ptr: *slack.SlackChannel = @ptrCast(@alignCast(slack_entry.channel.ptr));
        try std.testing.expect(slack_ptr.bus == &event_bus);
        try std.testing.expect(slack_ptr.policy.dm == .deny);
        try std.testing.expect(slack_ptr.policy.group == .allowlist);
        try std.testing.expectEqual(@as(usize, 1), slack_ptr.policy.allowlist.len);
        try std.testing.expectEqualStrings("slack-admin", slack_ptr.policy.allowlist[0]);
    }

    if (channel_catalog.isBuildEnabled(.dingtalk)) {
        const dingtalk_entry = findEntryByNameAccount(entries, "dingtalk", "ding-main") orelse
            return error.TestUnexpectedResult;
        const dingtalk_ptr: *dingtalk.DingTalkChannel = @ptrCast(@alignCast(dingtalk_entry.channel.ptr));
        try std.testing.expectEqual(ListenerType.gateway_loop, dingtalk_entry.listener_type);
        try std.testing.expect(dingtalk_ptr.event_bus == &event_bus);
    }
}

test "ChannelManager marks qq webhook receive_mode as webhook_only" {
    if (!channel_catalog.isBuildEnabled(.qq)) return;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const qq_accounts = [_]config_types.QQConfig{
        .{
            .account_id = "qq-main",
            .app_id = "appid",
            .app_secret = "appsecret",
            .bot_token = "bottoken",
            .receive_mode = .webhook,
        },
    };

    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .channels = .{
            .qq = &qq_accounts,
        },
    };

    var reg = dispatch.ChannelRegistry.init(allocator);
    defer reg.deinit();

    const mgr = try ChannelManager.init(allocator, &config, &reg);
    defer mgr.deinit();

    try mgr.collectConfiguredChannels();
    const qq_entry = findEntryByNameAccount(mgr.channelEntries(), "qq", "qq-main") orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(ListenerType.webhook_only, qq_entry.listener_type);
}

test "ChannelManager marks lark websocket receive_mode as gateway_loop" {
    if (!channel_catalog.isBuildEnabled(.lark)) return;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const lark_accounts = [_]config_types.LarkConfig{
        .{
            .account_id = "lark-main",
            .app_id = "cli_xxx",
            .app_secret = "secret_xxx",
            .use_feishu = true,
            .receive_mode = .websocket,
        },
    };

    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .channels = .{
            .lark = &lark_accounts,
        },
    };

    var reg = dispatch.ChannelRegistry.init(allocator);
    defer reg.deinit();

    const mgr = try ChannelManager.init(allocator, &config, &reg);
    defer mgr.deinit();

    try mgr.collectConfiguredChannels();
    const lark_entry = findEntryByNameAccount(mgr.channelEntries(), "lark", "lark-main") orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(ListenerType.gateway_loop, lark_entry.listener_type);
}

test "ChannelManager marks lark webhook receive_mode as webhook_only" {
    if (!channel_catalog.isBuildEnabled(.lark)) return;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const lark_accounts = [_]config_types.LarkConfig{
        .{
            .account_id = "lark-main",
            .app_id = "cli_xxx",
            .app_secret = "secret_xxx",
            .receive_mode = .webhook,
        },
    };

    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .channels = .{
            .lark = &lark_accounts,
        },
    };

    var reg = dispatch.ChannelRegistry.init(allocator);
    defer reg.deinit();

    const mgr = try ChannelManager.init(allocator, &config, &reg);
    defer mgr.deinit();

    try mgr.collectConfiguredChannels();
    const lark_entry = findEntryByNameAccount(mgr.channelEntries(), "lark", "lark-main") orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(ListenerType.webhook_only, lark_entry.listener_type);
}

test "ChannelManager collects web channel from config" {
    if (!channel_catalog.isBuildEnabled(.web)) return;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const web_accounts = [_]config_types.WebConfig{
        .{
            .account_id = "local",
            .port = 32123,
            .path = "/relay/",
            .auth_token = "relay-token-0123456789",
        },
    };

    const config = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = allocator,
        .channels = .{
            .web = &web_accounts,
        },
    };

    var reg = dispatch.ChannelRegistry.init(allocator);
    defer reg.deinit();

    var event_bus = bus_mod.Bus.init();

    const mgr = try ChannelManager.init(allocator, &config, &reg);
    defer mgr.deinit();
    mgr.setEventBus(&event_bus);

    try mgr.collectConfiguredChannels();

    try expectEntryPresence(mgr.channelEntries(), "web", "local", true);

    // Verify it was registered with correct listener type
    const web_entry = findEntryByNameAccount(mgr.channelEntries(), "web", "local").?;
    try std.testing.expectEqual(ListenerType.gateway_loop, web_entry.listener_type);

    const web_ptr: *web.WebChannel = @ptrCast(@alignCast(web_entry.channel.ptr));
    try std.testing.expect(web_ptr.bus == &event_bus);
    try std.testing.expectEqualStrings("/relay", web_ptr.ws_path);
    try std.testing.expectEqualStrings("relay-token-0123456789", web_ptr.configured_auth_token.?);
}

test "pollingStale recovers a progressing turn past the hard dispatch bound" {
    const allocator = std.testing.allocator;
    const state = try allocator.create(channel_loop.TelegramLoopState);
    defer allocator.destroy(state);
    state.* = channel_loop.TelegramLoopState.init();

    const now: i64 = 100_000;
    state.step.store(@intFromEnum(channel_loop.PollStep.dispatching), .release);
    // The turn keeps emitting progress hints...
    state.progress.store(now, .release);

    // ...within the hard bound it is not stale...
    state.last_activity.store(now - (ChannelManager.MAX_DISPATCH_SECS - 1), .release);
    try std.testing.expect(!ChannelManager.pollingStale(.{ .telegram = state }, now));

    // ...but past it the poller must be recovered even though the turn is
    // still progressing (the stall freshness alone cannot recover).
    state.last_activity.store(now - (ChannelManager.MAX_DISPATCH_SECS + 1), .release);
    try std.testing.expect(ChannelManager.pollingStale(.{ .telegram = state }, now));
}

test "stopPollingThreadGrace stops a progressing turn past the hard dispatch bound" {
    // page_allocator: the detach path intentionally leaves the loop state
    // allocated (the detached thread owns it).
    const allocator = std.heap.page_allocator;
    const state = try allocator.create(channel_loop.TelegramLoopState);
    state.* = channel_loop.TelegramLoopState.init();
    state.step.store(@intFromEnum(channel_loop.PollStep.dispatching), .release);
    // Fresh heartbeat, but the poller has been out of the poll step too long.
    state.progress.store(std_compat.time.timestamp(), .release);
    state.last_activity.store(std_compat.time.timestamp() - (ChannelManager.MAX_DISPATCH_SECS + 10), .release);

    test_stuck_release.store(false, .release);
    const thread = try std.Thread.spawn(.{}, testStuckPoller, .{});
    var entry = testPollingEntry(thread, state);

    const stopped = ChannelManager.stopPollingThreadGrace(allocator, &entry, 150 * std.time.ns_per_ms);

    try std.testing.expect(stopped);
    try std.testing.expect(entry.thread == null);
    try std.testing.expect(entry.polling_state == null);
    try std.testing.expect(state.stop_requested.load(.acquire));

    test_stuck_release.store(true, .release);
}
