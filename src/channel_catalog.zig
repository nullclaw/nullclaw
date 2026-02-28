const std = @import("std");
const build_options = @import("build_options");
const Config = @import("config.zig").Config;

pub const ChannelId = enum {
    cli,
    telegram,
    discord,
    slack,
    webhook,
    imessage,
    matrix,
    mattermost,
    whatsapp,
    irc,
    lark,
    dingtalk,
    signal,
    email,
    line,
    qq,
    onebot,
    maixcam,
    nostr,
    web,
};

pub const ChannelMeta = struct {
    id: ChannelId,
    key: []const u8,
    label: []const u8,
    configured_message: []const u8,
    listener_mode: ListenerMode,
};

pub const ListenerMode = enum {
    none,
    polling,
    gateway_loop,
    webhook_only,
    send_only,
};

pub const known_channels = [_]ChannelMeta{
    .{ .id = .cli, .key = "cli", .label = "CLI", .configured_message = "CLI enabled", .listener_mode = .none },
    .{ .id = .telegram, .key = "telegram", .label = "Telegram", .configured_message = "Telegram configured", .listener_mode = .polling },
    .{ .id = .discord, .key = "discord", .label = "Discord", .configured_message = "Discord configured", .listener_mode = .gateway_loop },
    .{ .id = .slack, .key = "slack", .label = "Slack", .configured_message = "Slack configured", .listener_mode = .gateway_loop },
    .{ .id = .webhook, .key = "webhook", .label = "Webhook", .configured_message = "Webhook configured", .listener_mode = .none },
    .{ .id = .imessage, .key = "imessage", .label = "iMessage", .configured_message = "iMessage configured", .listener_mode = .gateway_loop },
    .{ .id = .matrix, .key = "matrix", .label = "Matrix", .configured_message = "Matrix configured", .listener_mode = .polling },
    .{ .id = .mattermost, .key = "mattermost", .label = "Mattermost", .configured_message = "Mattermost configured", .listener_mode = .gateway_loop },
    .{ .id = .whatsapp, .key = "whatsapp", .label = "WhatsApp", .configured_message = "WhatsApp configured", .listener_mode = .webhook_only },
    .{ .id = .irc, .key = "irc", .label = "IRC", .configured_message = "IRC configured", .listener_mode = .gateway_loop },
    .{ .id = .lark, .key = "lark", .label = "Lark", .configured_message = "Lark configured", .listener_mode = .webhook_only },
    .{ .id = .dingtalk, .key = "dingtalk", .label = "DingTalk", .configured_message = "DingTalk configured", .listener_mode = .send_only },
    .{ .id = .signal, .key = "signal", .label = "Signal", .configured_message = "Signal configured", .listener_mode = .polling },
    .{ .id = .email, .key = "email", .label = "Email", .configured_message = "Email configured", .listener_mode = .send_only },
    .{ .id = .line, .key = "line", .label = "Line", .configured_message = "Line configured", .listener_mode = .webhook_only },
    .{ .id = .qq, .key = "qq", .label = "QQ", .configured_message = "QQ configured", .listener_mode = .gateway_loop },
    .{ .id = .onebot, .key = "onebot", .label = "OneBot", .configured_message = "OneBot configured", .listener_mode = .gateway_loop },
    .{ .id = .maixcam, .key = "maixcam", .label = "MaixCam", .configured_message = "MaixCam configured", .listener_mode = .send_only },
    .{ .id = .nostr, .key = "nostr", .label = "Nostr", .configured_message = "Nostr configured", .listener_mode = .gateway_loop },
    .{ .id = .web, .key = "web", .label = "Web", .configured_message = "Web configured", .listener_mode = .gateway_loop },
};

pub fn isBuildEnabled(channel_id: ChannelId) bool {
    return switch (channel_id) {
        .cli => build_options.enable_channel_cli,
        .telegram => build_options.enable_channel_telegram,
        .discord => build_options.enable_channel_discord,
        .slack => build_options.enable_channel_slack,
        .webhook => true,
        .imessage => build_options.enable_channel_imessage,
        .matrix => build_options.enable_channel_matrix,
        .mattermost => build_options.enable_channel_mattermost,
        .whatsapp => build_options.enable_channel_whatsapp,
        .irc => build_options.enable_channel_irc,
        .lark => build_options.enable_channel_lark,
        .dingtalk => build_options.enable_channel_dingtalk,
        .signal => build_options.enable_channel_signal,
        .email => build_options.enable_channel_email,
        .line => build_options.enable_channel_line,
        .qq => build_options.enable_channel_qq,
        .onebot => build_options.enable_channel_onebot,
        .maixcam => build_options.enable_channel_maixcam,
        .nostr => build_options.enable_channel_nostr,
        .web => build_options.enable_channel_web,
    };
}

pub fn isBuildEnabledByKey(comptime key: []const u8) bool {
    if (comptime std.mem.eql(u8, key, "cli")) return build_options.enable_channel_cli;
    if (comptime std.mem.eql(u8, key, "telegram")) return build_options.enable_channel_telegram;
    if (comptime std.mem.eql(u8, key, "discord")) return build_options.enable_channel_discord;
    if (comptime std.mem.eql(u8, key, "slack")) return build_options.enable_channel_slack;
    if (comptime std.mem.eql(u8, key, "webhook")) return true;
    if (comptime std.mem.eql(u8, key, "imessage")) return build_options.enable_channel_imessage;
    if (comptime std.mem.eql(u8, key, "matrix")) return build_options.enable_channel_matrix;
    if (comptime std.mem.eql(u8, key, "mattermost")) return build_options.enable_channel_mattermost;
    if (comptime std.mem.eql(u8, key, "whatsapp")) return build_options.enable_channel_whatsapp;
    if (comptime std.mem.eql(u8, key, "irc")) return build_options.enable_channel_irc;
    if (comptime std.mem.eql(u8, key, "lark")) return build_options.enable_channel_lark;
    if (comptime std.mem.eql(u8, key, "dingtalk")) return build_options.enable_channel_dingtalk;
    if (comptime std.mem.eql(u8, key, "signal")) return build_options.enable_channel_signal;
    if (comptime std.mem.eql(u8, key, "email")) return build_options.enable_channel_email;
    if (comptime std.mem.eql(u8, key, "line")) return build_options.enable_channel_line;
    if (comptime std.mem.eql(u8, key, "qq")) return build_options.enable_channel_qq;
    if (comptime std.mem.eql(u8, key, "onebot")) return build_options.enable_channel_onebot;
    if (comptime std.mem.eql(u8, key, "maixcam")) return build_options.enable_channel_maixcam;
    if (comptime std.mem.eql(u8, key, "nostr")) return build_options.enable_channel_nostr;
    if (comptime std.mem.eql(u8, key, "web")) return build_options.enable_channel_web;
    return true;
}

pub fn configuredCount(cfg: *const Config, channel_id: ChannelId) usize {
    return switch (channel_id) {
        .cli => if (cfg.channels.cli) 1 else 0,
        .telegram => cfg.channels.telegram.len,
        .discord => cfg.channels.discord.len,
        .slack => cfg.channels.slack.len,
        .webhook => if (cfg.channels.webhook != null) 1 else 0,
        .imessage => cfg.channels.imessage.len,
        .matrix => cfg.channels.matrix.len,
        .mattermost => cfg.channels.mattermost.len,
        .whatsapp => cfg.channels.whatsapp.len,
        .irc => cfg.channels.irc.len,
        .lark => cfg.channels.lark.len,
        .dingtalk => cfg.channels.dingtalk.len,
        .signal => cfg.channels.signal.len,
        .email => cfg.channels.email.len,
        .line => cfg.channels.line.len,
        .qq => cfg.channels.qq.len,
        .onebot => cfg.channels.onebot.len,
        .maixcam => cfg.channels.maixcam.len,
        .nostr => if (cfg.channels.nostr != null) 1 else 0,
        .web => cfg.channels.web.len,
    };
}

pub fn isConfigured(cfg: *const Config, channel_id: ChannelId) bool {
    return isBuildEnabled(channel_id) and configuredCount(cfg, channel_id) > 0;
}

pub fn statusText(cfg: *const Config, meta: ChannelMeta, buf: []u8) []const u8 {
    if (!isBuildEnabled(meta.id)) return "disabled in build";

    const count = configuredCount(cfg, meta.id);
    if (meta.id == .cli) {
        return if (count > 0) "enabled" else "disabled";
    }
    if (count == 0) return "not configured";
    if (count == 1) return "configured";
    return std.fmt.bufPrint(buf, "configured ({d} accounts)", .{count}) catch "configured";
}

pub fn findByKey(key: []const u8) ?ChannelMeta {
    for (known_channels) |meta| {
        if (std.mem.eql(u8, meta.key, key)) return meta;
    }
    return null;
}

pub fn hasAnyConfigured(cfg: *const Config, include_cli: bool) bool {
    for (known_channels) |meta| {
        if (!include_cli and meta.id == .cli) continue;
        if (!isBuildEnabled(meta.id)) continue;
        if (isConfigured(cfg, meta.id)) return true;
    }
    return false;
}

pub fn contributesToDaemonSupervision(channel_id: ChannelId) bool {
    const meta = findById(channel_id) orelse return false;
    return meta.listener_mode != .none;
}

pub fn requiresRuntime(channel_id: ChannelId) bool {
    const meta = findById(channel_id) orelse return false;
    return switch (meta.listener_mode) {
        .polling, .gateway_loop, .webhook_only => true,
        .send_only, .none => false,
    };
}

pub fn hasSupervisedChannels(cfg: *const Config) bool {
    for (known_channels) |meta| {
        if (!isBuildEnabled(meta.id)) continue;
        if (!contributesToDaemonSupervision(meta.id)) continue;
        if (isConfigured(cfg, meta.id)) return true;
    }
    return false;
}

pub fn hasRuntimeDependentChannels(cfg: *const Config) bool {
    for (known_channels) |meta| {
        if (!isBuildEnabled(meta.id)) continue;
        if (!requiresRuntime(meta.id)) continue;
        if (isConfigured(cfg, meta.id)) return true;
    }
    return false;
}

pub fn isChannelStartSupported(channel_id: ChannelId) bool {
    if (!isBuildEnabled(channel_id)) return false;
    const meta = findById(channel_id) orelse return false;
    return meta.listener_mode != .none and channel_id != .webhook;
}

pub fn findById(channel_id: ChannelId) ?ChannelMeta {
    for (known_channels) |meta| {
        if (meta.id == channel_id) return meta;
    }
    return null;
}

test "configuredCount handles array and optional channels" {
    const cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .telegram = &[_]@import("config_types.zig").TelegramConfig{
                .{ .account_id = "main", .bot_token = "tok" },
            },
            .qq = &[_]@import("config_types.zig").QQConfig{
                .{ .account_id = "main" },
                .{ .account_id = "backup" },
            },
            .whatsapp = &[_]@import("config_types.zig").WhatsAppConfig{
                .{
                    .account_id = "main",
                    .access_token = "a",
                    .phone_number_id = "b",
                    .verify_token = "c",
                },
            },
        },
    };

    try std.testing.expectEqual(@as(usize, 1), configuredCount(&cfg, .telegram));
    try std.testing.expectEqual(@as(usize, 2), configuredCount(&cfg, .qq));
    try std.testing.expectEqual(@as(usize, 1), configuredCount(&cfg, .whatsapp));
    try std.testing.expectEqual(@as(usize, 0), configuredCount(&cfg, .line));
}

test "hasSupervisedChannels excludes webhook and cli" {
    const cfg_webhook_only = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .cli = true,
            .webhook = .{ .port = 8080 },
        },
    };
    try std.testing.expect(!hasSupervisedChannels(&cfg_webhook_only));

    const cfg_signal = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .signal = &[_]@import("config_types.zig").SignalConfig{
                .{
                    .account_id = "main",
                    .http_url = "http://localhost:8080",
                    .account = "+15550001111",
                },
            },
        },
    };
    try std.testing.expectEqual(isBuildEnabled(.signal), hasSupervisedChannels(&cfg_signal));
}

test "hasRuntimeDependentChannels includes inbound listeners only" {
    const cfg_send_only = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .imessage = &[_]@import("config_types.zig").IMessageConfig{
                .{ .account_id = "main", .enabled = true },
            },
        },
    };
    try std.testing.expectEqual(isBuildEnabled(.imessage), hasRuntimeDependentChannels(&cfg_send_only));

    const cfg_webhook = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .line = &[_]@import("config_types.zig").LineConfig{
                .{
                    .account_id = "line-main",
                    .access_token = "tok",
                    .channel_secret = "sec",
                },
            },
        },
    };
    try std.testing.expectEqual(isBuildEnabled(.line), hasRuntimeDependentChannels(&cfg_webhook));
}

test "findByKey finds known channels" {
    const telegram = findByKey("telegram");
    try std.testing.expect(telegram != null);
    try std.testing.expectEqual(ChannelId.telegram, telegram.?.id);
    try std.testing.expectEqualStrings("Telegram", telegram.?.label);
    const mattermost = findByKey("mattermost");
    try std.testing.expect(mattermost != null);
    try std.testing.expectEqual(ChannelId.mattermost, mattermost.?.id);
    try std.testing.expect(findByKey("unknown") == null);
}
