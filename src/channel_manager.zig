//! Channel Manager — centralizes channel lifecycle (init, start, supervise, stop).
//!
//! Replaces the hardcoded Telegram/Signal-only logic in daemon.zig with a
//! generic system that handles all configured channels.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Config = @import("config.zig").Config;
const dispatch = @import("channels/dispatch.zig");
const channel_loop = @import("channel_loop.zig");
const health = @import("health.zig");
const daemon = @import("daemon.zig");

// Channel modules
const telegram = @import("channels/telegram.zig");
const signal_ch = @import("channels/signal.zig");
const discord = @import("channels/discord.zig");
const qq = @import("channels/qq.zig");
const onebot = @import("channels/onebot.zig");
const whatsapp = @import("channels/whatsapp.zig");
const line = @import("channels/line.zig");
const lark = @import("channels/lark.zig");

// Channel type from channels/root.zig
const Channel = @import("channels/root.zig").Channel;

const log = std.log.scoped(.channel_manager);

pub const ListenerType = enum {
    /// Telegram, Signal — poll in a loop
    polling,
    /// Discord, QQ, OneBot — internal WebSocket/gateway
    gateway_loop,
    /// WhatsApp, Line, Lark — HTTP gateway receives
    webhook_only,
    /// Channel exists but no listener yet
    not_implemented,
};

pub const Entry = struct {
    name: []const u8,
    channel: Channel,
    listener_type: ListenerType,
    supervised: dispatch.SupervisedChannel,
    thread: ?std.Thread = null,
    loop_state: ?*GenericLoopState = null,
};

/// Generic loop state that replaces TelegramLoopState/SignalLoopState for monitoring.
pub const GenericLoopState = struct {
    last_activity: std.atomic.Value(i64),
    stop_requested: std.atomic.Value(bool),
    thread: ?std.Thread = null,

    pub fn init() GenericLoopState {
        return .{
            .last_activity = std.atomic.Value(i64).init(std.time.timestamp()),
            .stop_requested = std.atomic.Value(bool).init(false),
        };
    }

    pub fn touch(self: *GenericLoopState) void {
        self.last_activity.store(std.time.timestamp(), .release);
    }

    pub fn shouldStop(self: *const GenericLoopState) bool {
        return self.stop_requested.load(.acquire);
    }
};

pub const ChannelManager = struct {
    allocator: Allocator,
    config: *const Config,
    registry: *dispatch.ChannelRegistry,
    runtime: ?*channel_loop.ChannelRuntime = null,
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

        // Free loop states
        for (self.entries.items) |*entry| {
            if (entry.loop_state) |ls| {
                self.allocator.destroy(ls);
            }
        }

        self.entries.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn setRuntime(self: *ChannelManager, rt: *channel_loop.ChannelRuntime) void {
        self.runtime = rt;
    }

    /// Scan config, create channel instances, register in registry.
    pub fn collectConfiguredChannels(self: *ChannelManager) !void {
        // Telegram
        if (self.config.channels.telegram) |tg_cfg| {
            const tg_ptr = try self.allocator.create(telegram.TelegramChannel);
            tg_ptr.* = telegram.TelegramChannel.init(
                self.allocator,
                tg_cfg.bot_token,
                tg_cfg.allow_from,
                tg_cfg.group_allow_from,
                tg_cfg.group_policy,
            );
            tg_ptr.proxy = tg_cfg.proxy;
            try self.registry.register(tg_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "telegram",
                .channel = tg_ptr.channel(),
                .listener_type = .polling,
                .supervised = dispatch.spawnSupervisedChannel(tg_ptr.channel(), 5),
            });
        }

        // Signal
        if (self.config.channels.signal) |sg_cfg| {
            const sg_ptr = try self.allocator.create(signal_ch.SignalChannel);
            sg_ptr.* = signal_ch.SignalChannel.init(
                self.allocator,
                sg_cfg.http_url,
                sg_cfg.account,
                sg_cfg.allow_from,
                sg_cfg.group_allow_from,
                sg_cfg.ignore_attachments,
                sg_cfg.ignore_stories,
            );
            try self.registry.register(sg_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "signal",
                .channel = sg_ptr.channel(),
                .listener_type = .polling,
                .supervised = dispatch.spawnSupervisedChannel(sg_ptr.channel(), 5),
            });
        }

        // Discord — has its own gateway loop; use initFromConfig for full config
        if (self.config.channels.discord) |dc_cfg| {
            const dc_ptr = try self.allocator.create(discord.DiscordChannel);
            dc_ptr.* = discord.DiscordChannel.initFromConfig(self.allocator, dc_cfg);
            try self.registry.register(dc_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "discord",
                .channel = dc_ptr.channel(),
                .listener_type = .gateway_loop,
                .supervised = dispatch.spawnSupervisedChannel(dc_ptr.channel(), 5),
            });
            log.info("Discord channel configured (gateway_loop)", .{});
        }

        // QQ
        if (self.config.channels.qq) |qq_cfg| {
            const qq_ptr = try self.allocator.create(qq.QQChannel);
            qq_ptr.* = qq.QQChannel.init(self.allocator, qq_cfg);
            try self.registry.register(qq_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "qq",
                .channel = qq_ptr.channel(),
                .listener_type = .gateway_loop,
                .supervised = dispatch.spawnSupervisedChannel(qq_ptr.channel(), 5),
            });
        }

        // OneBot
        if (self.config.channels.onebot) |ob_cfg| {
            const ob_ptr = try self.allocator.create(onebot.OneBotChannel);
            ob_ptr.* = onebot.OneBotChannel.init(self.allocator, ob_cfg);
            try self.registry.register(ob_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "onebot",
                .channel = ob_ptr.channel(),
                .listener_type = .gateway_loop,
                .supervised = dispatch.spawnSupervisedChannel(ob_ptr.channel(), 5),
            });
        }

        // WhatsApp — webhook only (inbound via gateway)
        if (self.config.channels.whatsapp) |wa_cfg| {
            const wa_ptr = try self.allocator.create(whatsapp.WhatsAppChannel);
            wa_ptr.* = whatsapp.WhatsAppChannel.init(
                self.allocator,
                wa_cfg.access_token,
                wa_cfg.phone_number_id,
                wa_cfg.verify_token,
                wa_cfg.allow_from,
                wa_cfg.group_allow_from,
                wa_cfg.group_policy,
            );
            try self.registry.register(wa_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "whatsapp",
                .channel = wa_ptr.channel(),
                .listener_type = .webhook_only,
                .supervised = dispatch.spawnSupervisedChannel(wa_ptr.channel(), 5),
            });
        }

        // Line — webhook only
        if (self.config.channels.line) |ln_cfg| {
            const ln_ptr = try self.allocator.create(line.LineChannel);
            ln_ptr.* = line.LineChannel.init(self.allocator, ln_cfg);
            try self.registry.register(ln_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "line",
                .channel = ln_ptr.channel(),
                .listener_type = .webhook_only,
                .supervised = dispatch.spawnSupervisedChannel(ln_ptr.channel(), 5),
            });
        }

        // Lark — webhook only
        if (self.config.channels.lark) |lk_cfg| {
            const lk_ptr = try self.allocator.create(lark.LarkChannel);
            lk_ptr.* = lark.LarkChannel.init(
                self.allocator,
                lk_cfg.app_id,
                lk_cfg.app_secret,
                lk_cfg.verification_token orelse "",
                lk_cfg.port orelse 9000,
                lk_cfg.allow_from,
            );
            try self.registry.register(lk_ptr.channel());
            try self.entries.append(self.allocator, .{
                .name = "lark",
                .channel = lk_ptr.channel(),
                .listener_type = .webhook_only,
                .supervised = dispatch.spawnSupervisedChannel(lk_ptr.channel(), 5),
            });
        }

        // Not-implemented channels: just log
        if (self.config.channels.slack != null) {
            log.info("slack channel configured but no listener implemented yet", .{});
        }
        if (self.config.channels.matrix != null) {
            log.info("matrix channel configured but no listener implemented yet", .{});
        }
        if (self.config.channels.irc != null) {
            log.info("irc channel configured but no listener implemented yet", .{});
        }
        if (self.config.channels.imessage != null) {
            log.info("imessage channel configured but no listener implemented yet", .{});
        }
        if (self.config.channels.email != null) {
            log.info("email channel configured but no listener implemented yet", .{});
        }
        if (self.config.channels.dingtalk != null) {
            log.info("dingtalk channel configured but no listener implemented yet", .{});
        }
        if (self.config.channels.maixcam != null) {
            log.info("maixcam channel configured but no listener implemented yet", .{});
        }
    }

    /// Spawn listener threads for polling/gateway channels.
    pub fn startAll(self: *ChannelManager) !usize {
        var started: usize = 0;

        for (self.entries.items) |*entry| {
            switch (entry.listener_type) {
                .polling => {
                    if (self.runtime == null) {
                        log.warn("Cannot start {s}: no runtime available", .{entry.name});
                        continue;
                    }

                    // Allocate generic loop state for monitoring
                    const ls = try self.allocator.create(GenericLoopState);
                    ls.* = GenericLoopState.init();
                    entry.loop_state = ls;

                    // Spawn appropriate loop
                    if (std.mem.eql(u8, entry.name, "telegram")) {
                        const tg_ls = try self.allocator.create(channel_loop.TelegramLoopState);
                        tg_ls.* = channel_loop.TelegramLoopState.init();

                        entry.thread = std.Thread.spawn(
                            .{ .stack_size = 512 * 1024 },
                            channel_loop.runTelegramLoop,
                            .{ self.allocator, self.config, self.runtime.?, tg_ls },
                        ) catch |err| {
                            log.err("Failed to spawn Telegram thread: {}", .{err});
                            continue;
                        };
                    } else if (std.mem.eql(u8, entry.name, "signal")) {
                        const sg_ls = try self.allocator.create(channel_loop.SignalLoopState);
                        sg_ls.* = channel_loop.SignalLoopState.init();

                        entry.thread = std.Thread.spawn(
                            .{ .stack_size = 512 * 1024 },
                            channel_loop.runSignalLoop,
                            .{ self.allocator, self.config, self.runtime.?, sg_ls },
                        ) catch |err| {
                            log.err("Failed to spawn Signal thread: {}", .{err});
                            continue;
                        };
                    }

                    if (entry.thread != null) {
                        entry.supervised.recordSuccess();
                        started += 1;
                        log.info("{s} polling thread started", .{entry.name});
                    }
                },
                .gateway_loop => {
                    // Gateway-loop channels (Discord, QQ, OneBot) manage their own connections
                    entry.channel.start() catch |err| {
                        log.warn("Failed to start {s} gateway: {}", .{ entry.name, err });
                        continue;
                    };
                    started += 1;
                    log.info("{s} gateway started", .{entry.name});
                },
                .webhook_only => {
                    // Webhook channels don't need a thread — they receive via the HTTP gateway
                    entry.channel.start() catch |err| {
                        log.warn("Failed to start {s}: {}", .{ entry.name, err });
                        continue;
                    };
                    started += 1;
                    log.info("{s} registered (webhook-only)", .{entry.name});
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
            if (entry.loop_state) |ls| {
                ls.stop_requested.store(true, .release);
            }
            if (entry.thread) |t| {
                t.join();
                entry.thread = null;
            }
            // Stop gateway/webhook channels
            if (entry.listener_type == .gateway_loop or entry.listener_type == .webhook_only) {
                entry.channel.stop();
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
                if (entry.listener_type != .polling) continue;

                const ls = entry.loop_state orelse continue;
                const now = std.time.timestamp();
                const last = ls.last_activity.load(.acquire);
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
                        ls.stop_requested.store(true, .release);
                        if (entry.thread) |t| t.join();

                        // Backoff
                        std.Thread.sleep(entry.supervised.currentBackoffMs() * std.time.ns_per_ms);

                        // Respawn
                        ls.stop_requested.store(false, .release);
                        ls.last_activity.store(std.time.timestamp(), .release);

                        if (self.runtime) |rt| {
                            if (std.mem.eql(u8, entry.name, "telegram")) {
                                const tg_ls = self.allocator.create(channel_loop.TelegramLoopState) catch continue;
                                tg_ls.* = channel_loop.TelegramLoopState.init();
                                entry.thread = std.Thread.spawn(
                                    .{ .stack_size = 512 * 1024 },
                                    channel_loop.runTelegramLoop,
                                    .{ self.allocator, self.config, rt, tg_ls },
                                ) catch |err| {
                                    log.err("Failed to respawn Telegram thread: {}", .{err});
                                    continue;
                                };
                            } else if (std.mem.eql(u8, entry.name, "signal")) {
                                const sg_ls = self.allocator.create(channel_loop.SignalLoopState) catch continue;
                                sg_ls.* = channel_loop.SignalLoopState.init();
                                entry.thread = std.Thread.spawn(
                                    .{ .stack_size = 512 * 1024 },
                                    channel_loop.runSignalLoop,
                                    .{ self.allocator, self.config, rt, sg_ls },
                                ) catch |err| {
                                    log.err("Failed to respawn Signal thread: {}", .{err});
                                    continue;
                                };
                            }

                            if (entry.thread != null) {
                                entry.supervised.recordSuccess();
                                state.markRunning("channels");
                                health.markComponentOk(entry.name);
                            }
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

test "GenericLoopState init defaults" {
    const ls = GenericLoopState.init();
    try std.testing.expect(!ls.shouldStop());
    try std.testing.expect(ls.thread == null);
    try std.testing.expect(ls.last_activity.load(.acquire) > 0);
}

test "GenericLoopState stop_requested toggle" {
    var ls = GenericLoopState.init();
    try std.testing.expect(!ls.shouldStop());
    ls.stop_requested.store(true, .release);
    try std.testing.expect(ls.shouldStop());
}

test "GenericLoopState touch updates timestamp" {
    var ls = GenericLoopState.init();
    const before = ls.last_activity.load(.acquire);
    std.Thread.sleep(10 * std.time.ns_per_ms);
    ls.touch();
    const after = ls.last_activity.load(.acquire);
    try std.testing.expect(after >= before);
}

test "ListenerType enum values distinct" {
    try std.testing.expect(@intFromEnum(ListenerType.polling) != @intFromEnum(ListenerType.gateway_loop));
    try std.testing.expect(@intFromEnum(ListenerType.gateway_loop) != @intFromEnum(ListenerType.webhook_only));
    try std.testing.expect(@intFromEnum(ListenerType.webhook_only) != @intFromEnum(ListenerType.not_implemented));
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
