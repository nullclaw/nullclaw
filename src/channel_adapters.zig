const std = @import("std");
const Config = @import("config.zig").Config;
const channel_loop = @import("channel_loop.zig");
const channels_root = @import("channels/root.zig");
const telegram = @import("channels/telegram.zig");
const signal = @import("channels/signal.zig");
const agent_routing = @import("agent_routing.zig");

pub const PollingSpawnFn = *const fn (
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *channel_loop.ChannelRuntime,
    channel: channels_root.Channel,
) anyerror!channel_loop.PollingSpawnResult;

pub const PollingSourceKeyFn = *const fn (
    allocator: std.mem.Allocator,
    channel: channels_root.Channel,
) ?[]u8;

pub const PollingDescriptor = struct {
    channel_name: []const u8,
    spawn: PollingSpawnFn,
    source_key: ?PollingSourceKeyFn = null,
};

fn telegramPollingSourceKey(allocator: std.mem.Allocator, channel: channels_root.Channel) ?[]u8 {
    const tg_ptr: *const telegram.TelegramChannel = @ptrCast(@alignCast(channel.ptr));
    return allocator.dupe(u8, tg_ptr.bot_token) catch null;
}

fn signalPollingSourceKey(allocator: std.mem.Allocator, channel: channels_root.Channel) ?[]u8 {
    const sg_ptr: *const signal.SignalChannel = @ptrCast(@alignCast(channel.ptr));
    return std.fmt.allocPrint(allocator, "{s}|{s}", .{ sg_ptr.http_url, sg_ptr.account }) catch null;
}

pub const polling_descriptors = [_]PollingDescriptor{
    .{
        .channel_name = "telegram",
        .spawn = channel_loop.spawnTelegramPolling,
        .source_key = telegramPollingSourceKey,
    },
    .{
        .channel_name = "signal",
        .spawn = channel_loop.spawnSignalPolling,
        .source_key = signalPollingSourceKey,
    },
    .{
        .channel_name = "matrix",
        .spawn = channel_loop.spawnMatrixPolling,
    },
};

pub fn findPollingDescriptor(channel_name: []const u8) ?*const PollingDescriptor {
    for (&polling_descriptors) |*desc| {
        if (std.mem.eql(u8, desc.channel_name, channel_name)) return desc;
    }
    return null;
}

pub const InboundMetadata = struct {
    account_id: ?[]const u8 = null,
    peer_kind: ?agent_routing.ChatType = null,
    peer_id: ?[]const u8 = null,
    guild_id: ?[]const u8 = null,
    team_id: ?[]const u8 = null,
    channel_id: ?[]const u8 = null,
    thread_id: ?[]const u8 = null,
    is_dm: ?bool = null,
    is_group: ?bool = null,
};

pub const InboundRouteInput = struct {
    channel_name: []const u8,
    sender_id: []const u8,
    chat_id: []const u8,
};

pub const InboundRouteDescriptor = struct {
    channel_name: ?[]const u8 = null,
    matches_fn: ?*const fn (config: *const Config, channel_name: []const u8) bool = null,
    default_account_id: *const fn (config: *const Config, channel_name: []const u8) ?[]const u8,
    derive_peer: *const fn (input: InboundRouteInput, meta: InboundMetadata) ?agent_routing.PeerRef,
};

pub fn parsePeerKind(raw: []const u8) ?agent_routing.ChatType {
    if (std.mem.eql(u8, raw, "direct")) return .direct;
    if (std.mem.eql(u8, raw, "group")) return .group;
    if (std.mem.eql(u8, raw, "channel")) return .channel;
    return null;
}

fn defaultDiscordAccount(config: *const Config, _: []const u8) ?[]const u8 {
    if (config.channels.discordPrimary()) |dc| return dc.account_id;
    return null;
}

fn defaultSlackAccount(config: *const Config, _: []const u8) ?[]const u8 {
    if (config.channels.slackPrimary()) |sc| return sc.account_id;
    return null;
}

fn defaultQQAccount(config: *const Config, _: []const u8) ?[]const u8 {
    if (config.channels.qqPrimary()) |qc| return qc.account_id;
    return null;
}

fn defaultOnebotAccount(config: *const Config, _: []const u8) ?[]const u8 {
    if (config.channels.onebotPrimary()) |oc| return oc.account_id;
    return null;
}

fn defaultIrcAccount(config: *const Config, _: []const u8) ?[]const u8 {
    if (config.channels.ircPrimary()) |ic| return ic.account_id;
    return null;
}

fn defaultMattermostAccount(config: *const Config, _: []const u8) ?[]const u8 {
    if (config.channels.mattermostPrimary()) |mc| return mc.account_id;
    return null;
}

fn defaultIMessageAccount(config: *const Config, _: []const u8) ?[]const u8 {
    if (config.channels.imessagePrimary()) |im| return im.account_id;
    return null;
}

fn matchesMaixcam(config: *const Config, channel_name: []const u8) bool {
    if (std.mem.eql(u8, channel_name, "maixcam")) return config.channels.maixcam.len > 0;
    for (config.channels.maixcam) |mc| {
        if (std.mem.eql(u8, channel_name, mc.name)) return true;
    }
    return false;
}

fn defaultMaixcamAccount(config: *const Config, channel_name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, channel_name, "maixcam")) {
        if (config.channels.maixcamPrimary()) |mc| return mc.account_id;
        return null;
    }
    for (config.channels.maixcam) |mc| {
        if (std.mem.eql(u8, channel_name, mc.name)) return mc.account_id;
    }
    return null;
}

fn stripPrefix(value: []const u8, prefix: []const u8) []const u8 {
    if (std.mem.startsWith(u8, value, prefix)) return value[prefix.len..];
    return value;
}

fn deriveDiscordPeer(input: InboundRouteInput, meta: InboundMetadata) ?agent_routing.PeerRef {
    const is_dm = meta.is_dm orelse (meta.guild_id == null);
    return .{
        .kind = if (is_dm) .direct else .channel,
        .id = if (is_dm) input.sender_id else input.chat_id,
    };
}

fn deriveSlackPeer(input: InboundRouteInput, meta: InboundMetadata) ?agent_routing.PeerRef {
    const is_dm = meta.is_dm orelse (input.chat_id.len > 0 and input.chat_id[0] == 'D');
    return .{
        .kind = if (is_dm) .direct else .channel,
        .id = if (is_dm) input.sender_id else input.chat_id,
    };
}

fn deriveQQPeer(input: InboundRouteInput, meta: InboundMetadata) ?agent_routing.PeerRef {
    const is_dm = meta.is_dm orelse std.mem.startsWith(u8, input.chat_id, "dm:");
    const raw_channel = meta.channel_id orelse input.chat_id;
    const channel_id = stripPrefix(raw_channel, "channel:");
    return .{
        .kind = if (is_dm) .direct else .channel,
        .id = if (is_dm) input.sender_id else channel_id,
    };
}

fn deriveOnebotPeer(input: InboundRouteInput, meta: InboundMetadata) ?agent_routing.PeerRef {
    if (std.mem.startsWith(u8, input.chat_id, "group:")) {
        return .{ .kind = .group, .id = input.chat_id["group:".len..] };
    }
    if (meta.is_group orelse false) {
        return .{ .kind = .group, .id = input.chat_id };
    }
    return .{ .kind = .direct, .id = input.sender_id };
}

fn deriveIrcPeer(input: InboundRouteInput, meta: InboundMetadata) ?agent_routing.PeerRef {
    const looks_like_channel = input.chat_id.len > 0 and (input.chat_id[0] == '#' or input.chat_id[0] == '&');
    const is_dm = meta.is_dm orelse !looks_like_channel;
    return .{
        .kind = if (is_dm) .direct else .group,
        .id = if (is_dm) input.sender_id else input.chat_id,
    };
}

fn deriveMattermostPeer(input: InboundRouteInput, meta: InboundMetadata) ?agent_routing.PeerRef {
    const channel_id = stripPrefix(meta.channel_id orelse input.chat_id, "channel:");
    if (meta.is_dm orelse false) return .{ .kind = .direct, .id = input.sender_id };
    if (meta.is_group orelse false) return .{ .kind = .group, .id = channel_id };
    return .{ .kind = .channel, .id = channel_id };
}

fn deriveIMessagePeer(input: InboundRouteInput, meta: InboundMetadata) ?agent_routing.PeerRef {
    const is_group = meta.is_group orelse std.mem.startsWith(u8, input.chat_id, "chat:");
    const group_id = stripPrefix(input.chat_id, "chat:");
    return .{
        .kind = if (is_group) .group else .direct,
        .id = if (is_group) group_id else input.sender_id,
    };
}

fn deriveMaixcamPeer(input: InboundRouteInput, _: InboundMetadata) ?agent_routing.PeerRef {
    return .{ .kind = .direct, .id = input.chat_id };
}

pub const inbound_route_descriptors = [_]InboundRouteDescriptor{
    .{
        .channel_name = "discord",
        .default_account_id = defaultDiscordAccount,
        .derive_peer = deriveDiscordPeer,
    },
    .{
        .channel_name = "slack",
        .default_account_id = defaultSlackAccount,
        .derive_peer = deriveSlackPeer,
    },
    .{
        .channel_name = "qq",
        .default_account_id = defaultQQAccount,
        .derive_peer = deriveQQPeer,
    },
    .{
        .channel_name = "onebot",
        .default_account_id = defaultOnebotAccount,
        .derive_peer = deriveOnebotPeer,
    },
    .{
        .channel_name = "irc",
        .default_account_id = defaultIrcAccount,
        .derive_peer = deriveIrcPeer,
    },
    .{
        .channel_name = "mattermost",
        .default_account_id = defaultMattermostAccount,
        .derive_peer = deriveMattermostPeer,
    },
    .{
        .channel_name = "imessage",
        .default_account_id = defaultIMessageAccount,
        .derive_peer = deriveIMessagePeer,
    },
    .{
        .matches_fn = matchesMaixcam,
        .default_account_id = defaultMaixcamAccount,
        .derive_peer = deriveMaixcamPeer,
    },
};

pub fn findInboundRouteDescriptor(config: *const Config, channel_name: []const u8) ?*const InboundRouteDescriptor {
    for (&inbound_route_descriptors) |*desc| {
        if (desc.channel_name) |name| {
            if (std.mem.eql(u8, name, channel_name)) return desc;
        } else if (desc.matches_fn) |matches| {
            if (matches(config, channel_name)) return desc;
        }
    }
    return null;
}

test "findPollingDescriptor returns known polling adapters" {
    try std.testing.expect(findPollingDescriptor("telegram") != null);
    try std.testing.expect(findPollingDescriptor("signal") != null);
    try std.testing.expect(findPollingDescriptor("matrix") != null);
    try std.testing.expect(findPollingDescriptor("discord") == null);
}

test "parsePeerKind handles supported values" {
    try std.testing.expectEqual(agent_routing.ChatType.direct, parsePeerKind("direct").?);
    try std.testing.expectEqual(agent_routing.ChatType.group, parsePeerKind("group").?);
    try std.testing.expectEqual(agent_routing.ChatType.channel, parsePeerKind("channel").?);
    try std.testing.expect(parsePeerKind("invalid") == null);
}

test "findInboundRouteDescriptor supports custom maixcam names" {
    const cfg = Config{
        .workspace_dir = "/tmp",
        .config_path = "/tmp/config.json",
        .allocator = std.testing.allocator,
        .channels = .{
            .maixcam = &[_]@import("config_types.zig").MaixCamConfig{
                .{ .account_id = "main", .name = "edge-cam" },
            },
        },
    };
    try std.testing.expect(findInboundRouteDescriptor(&cfg, "maixcam") != null);
    try std.testing.expect(findInboundRouteDescriptor(&cfg, "edge-cam") != null);
}
