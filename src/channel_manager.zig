//! Channel Manager — centralizes channel lifecycle (init, start, supervise, stop).
//!
//! Replaces the hardcoded Telegram/Signal-only logic in daemon.zig with a
//! generic system that handles all configured channels.

const std = @import("std");
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
const mattermost = channels_mod.mattermost;
const discord = channels_mod.discord;
const imessage = channels_mod.imessage;
const qq = channels_mod.qq;
const onebot = channels_mod.onebot;
const maixcam = channels_mod.maixcam;
const slack = channels_mod.slack;
const irc = channels_mod.irc;
const Channel = channels_mod.Channel;

const log = std.log.scoped(.channel_manager);

pub const ListenerType = enum {
    /// Telegram, Signal — poll in a loop
    polling,
    /// Discord, Mattermost, Slack, IRC, QQ, OneBot — internal socket/WebSocket loop
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
            .matrix => |ls| ls.last_activity.load(.acquire),
        };
    }

    fn requestPollingStop(state: PollingState) void {
        switch (state) {
            .telegram => |ls| ls.stop_requested.store(true, .release),
            .signal => |ls| ls.stop_requested.store(true, .release),
            .matrix => |ls| ls.stop_requested.store(true, .release),
        }
    }

    fn destroyPollingState(self: *ChannelManager, state: PollingState) void {
        switch (state) {
            .telegram => |ls| self.allocator.destroy(ls),
            .signal => |ls| self.allocator.destroy(ls),
            .matrix => |ls| self.allocator.destroy(ls),
        }
    }

    fn spawnPollingThread(self: *ChannelManager, entry: *Entry, rt: *channel_loop.ChannelRuntime) !void {
        const polling_desc = channel_adapters.findPollingDescriptor(entry.name) orelse
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
        if (!std.mem.eql(u8, current.name, polling_desc.channel_name)) return false;
        if (current.listener_type != .polling) return false;

        const current_source = source_key_fn(allocator, current.channel) orelse return false;
        defer allocator.free(current_source);

        var i: usize = 0;
        while (i < current_index) : (i += 1) {
            const prev = entries[i];
            if (!std.mem.eql(u8, prev.name, polling_desc.channel_name)) continue;
            if (prev.listener_type != .polling) continue;
            if (prev.supervised.state != .running) continue;

            const prev_source = source_key_fn(allocator, prev.channel) orelse continue;
            const duplicate = std.mem.eql(u8, prev_source, current_source);
            allocator.free(prev_source);
            if (duplicate) return true;
        }
        return false;
    }

    fn stopPollingThread(self: *ChannelManager, entry: *Entry) void {
        if (entry.polling_state) |state| {
            requestPollingStop(state);
        }

        if (entry.thread) |t| {
            t.join();
            entry.thread = null;
        }

        if (entry.polling_state) |state| {
            self.destroyPollingState(state);
            entry.polling_state = null;
        }
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
        self.maybeAttachBus(ch_ptr);

        const ch = ch_ptr.channel();
        const account_id = accountIdFromConfig(cfg);
        try self.registry.registerWithAccount(ch, account_id);

        const listener_type = comptime listenerTypeForField(field_name);
        try self.entries.append(self.allocator, .{
            .name = field_name,
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
                .optional => {
                    if (@field(self.config.channels, field.name)) |cfg| {
                        try self.appendChannelFromConfig(field.name, cfg);
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

                    if (channel_adapters.findPollingDescriptor(entry.name)) |polling_desc| {
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

    /// Signal all threads to stop and join them.
    pub fn stopAll(self: *ChannelManager) void {
        for (self.entries.items) |*entry| {
            switch (entry.listener_type) {
                .polling => self.stopPollingThread(entry),
                .gateway_loop, .webhook_only, .send_only => entry.channel.stop(),
                .not_implemented => {},
            }
        }
    }

    /// Monitoring loop: check health, restart failed channels with backoff.
    /// Blocks until shutdown.
    pub fn supervisionLoop(self: *ChannelManager, state: *daemon.DaemonState) void {
        const STALE_THRESHOLD_SECS: i64 = 90;
        const WATCH_INTERVAL_SECS: u64 = 10;

        while (!daemon.isShutdownRequested()) {
            std.Thread.sleep(WATCH_INTERVAL_SECS * std.time.ns_per_s);
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
                            std.Thread.sleep(entry.supervised.currentBackoffMs() * std.time.ns_per_ms);
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
                const now = std.time.timestamp();
                const last = pollingLastActivity(polling_state);
                const stale = (now - last) > STALE_THRESHOLD_SECS;

                const probe_ok = entry.channel.healthCheck();

                if (!stale and probe_ok) {
                    health.markComponentOk(entry.name);
                    state.markRunning("channels");
                    if (entry.supervised.state != .running) entry.supervised.recordSuccess();
                } else {
                    const reason: []const u8 = if (stale) "polling thread stale" else "health check failed";
                    log.warn("{s} issue: {s}", .{ entry.name, reason });
                    health.markComponentError(entry.name, reason);

                    entry.supervised.recordFailure();

                    if (entry.supervised.shouldRestart()) {
                        log.info("Restarting {s} (attempt {d})", .{ entry.name, entry.supervised.restart_count });
                        state.markError("channels", reason);

                        // Stop old thread
                        self.stopPollingThread(entry);

                        // Backoff
                        std.Thread.sleep(entry.supervised.currentBackoffMs() * std.time.ns_per_ms);

                        // Respawn
                        if (self.runtime) |rt| {
                            self.spawnPollingThread(entry, rt) catch |err| {
                                log.err("Failed to respawn {s} thread: {}", .{ entry.name, err });
                                continue;
                            };
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

test "PollingState has telegram signal and matrix variants" {
    try std.testing.expect(@intFromEnum(@as(std.meta.Tag(PollingState), .telegram)) !=
        @intFromEnum(@as(std.meta.Tag(PollingState), .signal)));
    try std.testing.expect(@intFromEnum(@as(std.meta.Tag(PollingState), .signal)) !=
        @intFromEnum(@as(std.meta.Tag(PollingState), .matrix)));
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
            .account_id = "main",
            .channel = sig_a.channel(),
            .listener_type = .polling,
            .supervised = sup_a,
            .thread = null,
        },
        .{
            .name = "signal",
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
            .account_id = "main",
            .channel = sig_a.channel(),
            .listener_type = .polling,
            .supervised = sup_a,
            .thread = null,
        },
        .{
            .name = "signal",
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
            .account_id = "main",
            .channel = tg_a.channel(),
            .listener_type = .polling,
            .supervised = sup_a,
            .thread = null,
        },
        .{
            .name = "telegram",
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
            .account_id = "main",
            .channel = tg_a.channel(),
            .listener_type = .polling,
            .supervised = sup_a,
            .thread = null,
        },
        .{
            .name = "telegram",
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

    try std.testing.expectEqual(@as(usize, 17), mgr.count());
    try std.testing.expectEqual(@as(usize, 17), reg.count());

    const entries = mgr.channelEntries();
    try std.testing.expectEqual(@as(usize, 4), countEntriesByListenerType(entries, .polling));
    try std.testing.expectEqual(@as(usize, 7), countEntriesByListenerType(entries, .gateway_loop));
    try std.testing.expectEqual(@as(usize, 3), countEntriesByListenerType(entries, .webhook_only));
    try std.testing.expectEqual(@as(usize, 3), countEntriesByListenerType(entries, .send_only));
    try std.testing.expectEqual(@as(usize, 0), countEntriesByListenerType(entries, .not_implemented));

    try std.testing.expect(findEntryByNameAccount(entries, "telegram", "main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "telegram", "backup") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "signal", "sig-main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "discord", "dc-main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "qq", "qq-main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "onebot", "ob-main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "mattermost", "mm-main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "slack", "sl-main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "maixcam", "cam-main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "whatsapp", "wa-main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "line", "line-main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "lark", "lark-main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "matrix", "mx-main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "irc", "irc-main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "imessage", "imain") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "email", "email-main") != null);
    try std.testing.expect(findEntryByNameAccount(entries, "dingtalk", "ding-main") != null);

    const discord_entry = findEntryByNameAccount(entries, "discord", "dc-main").?;
    const discord_ptr: *discord.DiscordChannel = @ptrCast(@alignCast(discord_entry.channel.ptr));
    try std.testing.expect(discord_ptr.bus == &event_bus);

    const qq_entry = findEntryByNameAccount(entries, "qq", "qq-main").?;
    const qq_ptr: *qq.QQChannel = @ptrCast(@alignCast(qq_entry.channel.ptr));
    try std.testing.expect(qq_ptr.event_bus == &event_bus);

    const onebot_entry = findEntryByNameAccount(entries, "onebot", "ob-main").?;
    const onebot_ptr: *onebot.OneBotChannel = @ptrCast(@alignCast(onebot_entry.channel.ptr));
    try std.testing.expect(onebot_ptr.event_bus == &event_bus);

    const mattermost_entry = findEntryByNameAccount(entries, "mattermost", "mm-main").?;
    const mattermost_ptr: *mattermost.MattermostChannel = @ptrCast(@alignCast(mattermost_entry.channel.ptr));
    try std.testing.expect(mattermost_ptr.bus == &event_bus);

    const irc_entry = findEntryByNameAccount(entries, "irc", "irc-main").?;
    const irc_ptr: *irc.IrcChannel = @ptrCast(@alignCast(irc_entry.channel.ptr));
    try std.testing.expect(irc_ptr.bus == &event_bus);

    const imessage_entry = findEntryByNameAccount(entries, "imessage", "imain").?;
    const imessage_ptr: *imessage.IMessageChannel = @ptrCast(@alignCast(imessage_entry.channel.ptr));
    try std.testing.expect(imessage_ptr.bus == &event_bus);

    const maixcam_entry = findEntryByNameAccount(entries, "maixcam", "cam-main").?;
    const maixcam_ptr: *maixcam.MaixCamChannel = @ptrCast(@alignCast(maixcam_entry.channel.ptr));
    try std.testing.expect(maixcam_ptr.event_bus == &event_bus);

    const slack_entry = findEntryByNameAccount(entries, "slack", "sl-main").?;
    const slack_ptr: *slack.SlackChannel = @ptrCast(@alignCast(slack_entry.channel.ptr));
    try std.testing.expect(slack_ptr.bus == &event_bus);
    try std.testing.expect(slack_ptr.policy.dm == .deny);
    try std.testing.expect(slack_ptr.policy.group == .allowlist);
    try std.testing.expectEqual(@as(usize, 1), slack_ptr.policy.allowlist.len);
    try std.testing.expectEqualStrings("slack-admin", slack_ptr.policy.allowlist[0]);
}
