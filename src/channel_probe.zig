/// --probe-channel-health subcommand: validate channel credentials.
///
/// Usage: nullclaw --probe-channel-health --channel telegram --account default [--timeout-secs 10]
///
/// Returns JSON to stdout:
///   {"channel":"telegram","account":"default","live_ok":false,"reason":"missing_bot_token"}
const std = @import("std");
const config_mod = @import("config.zig");
const config_types = @import("config_types.zig");
const channel_catalog = @import("channel_catalog.zig");
const http_util = @import("http_util.zig");

const ProbeResult = struct {
    channel: []const u8,
    account: []const u8,
    live_ok: bool,
    reason: []const u8,
};

const ReadConfigError = error{
    ConfigLoadFailed,
    ConfigReadFailed,
    ConfigParseFailed,
    ConfigRootNotObject,
    MissingChannels,
    InvalidChannels,
};

const ParsedChannels = struct {
    parsed: std.json.Parsed(std.json.Value),
    channels: std.json.ObjectMap,
};

fn ok(channel: []const u8, account: []const u8) ProbeResult {
    return .{
        .channel = channel,
        .account = account,
        .live_ok = true,
        .reason = "ok",
    };
}

fn fail(channel: []const u8, account: []const u8, reason: []const u8) ProbeResult {
    return .{
        .channel = channel,
        .account = account,
        .live_ok = false,
        .reason = reason,
    };
}

fn channelSupportsAccounts(channel_type: []const u8) bool {
    inline for (std.meta.fields(config_mod.ChannelsConfig)) |field| {
        if (std.mem.eql(u8, channel_type, field.name)) {
            return switch (@typeInfo(field.type)) {
                .pointer => |ptr| ptr.size == .slice,
                else => false,
            };
        }
    }
    return false;
}

fn objectHasNonObjectValue(obj: std.json.ObjectMap) bool {
    var it = obj.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* != .object) return true;
    }
    return false;
}

fn firstObjectAccount(obj: std.json.ObjectMap) ?std.json.ObjectMap {
    var it = obj.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* == .object) return entry.value_ptr.*.object;
    }
    return null;
}

fn pickAccountObject(obj: std.json.ObjectMap, requested: []const u8, channel_type: []const u8) ?std.json.ObjectMap {
    if (obj.get(requested)) |v| {
        if (v == .object) return v.object;
    }
    if (std.mem.eql(u8, requested, "default")) {
        if (obj.get("default")) |v| {
            if (v == .object) return v.object;
        }
        if (obj.get("main")) |v| {
            if (v == .object) return v.object;
        }
    }
    if (obj.get(channel_type)) |v| {
        if (v == .object) return v.object;
    }
    if (obj.count() == 1) return firstObjectAccount(obj);
    return null;
}

fn resolveChannelAccountObject(
    channels_obj: std.json.ObjectMap,
    channel_type: []const u8,
    account_name: []const u8,
) ?std.json.ObjectMap {
    const channel_value = channels_obj.get(channel_type) orelse return null;
    if (channel_value != .object) return null;
    const channel_obj = channel_value.object;

    // Canonical config format: {"accounts": {"default": {...}}}
    if (channel_obj.get("accounts")) |accounts_val| {
        if (accounts_val == .object) {
            if (pickAccountObject(accounts_val.object, account_name, channel_type)) |obj| {
                return obj;
            }
        }
    }

    // Multi-account channels in wizard payload format: {"default": {...}}
    if (channelSupportsAccounts(channel_type)) {
        return pickAccountObject(channel_obj, account_name, channel_type);
    }

    // Single-account channels in canonical format: {"secret": "..."}
    if (objectHasNonObjectValue(channel_obj)) {
        return channel_obj;
    }

    // Single-account channels in wizard payload format: {"webhook": {"secret": "..."}}
    return pickAccountObject(channel_obj, account_name, channel_type) orelse firstObjectAccount(channel_obj);
}

fn trimWhitespace(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\n");
}

fn nonEmptyString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    if (value != .string) return null;
    const trimmed = trimWhitespace(value.string);
    if (trimmed.len == 0) return null;
    return trimmed;
}

fn optionalString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    if (value != .string) return null;
    const trimmed = trimWhitespace(value.string);
    if (trimmed.len == 0) return null;
    return trimmed;
}

fn boolOrDefault(obj: std.json.ObjectMap, key: []const u8, fallback: bool) bool {
    const value = obj.get(key) orelse return fallback;
    if (value == .bool) return value.bool;
    return fallback;
}

fn u32OrDefault(obj: std.json.ObjectMap, key: []const u8, fallback: u32) u32 {
    const value = obj.get(key) orelse return fallback;
    if (value == .integer and value.integer >= 0 and value.integer <= std.math.maxInt(u32)) {
        return @intCast(value.integer);
    }
    return fallback;
}

fn trimTrailingSlash(value: []const u8) []const u8 {
    var out = value;
    while (out.len > 1 and out[out.len - 1] == '/') {
        out = out[0 .. out.len - 1];
    }
    return out;
}

fn timeoutString(buf: []u8, timeout_secs: u64) []const u8 {
    return std.fmt.bufPrint(buf, "{d}", .{timeout_secs}) catch "10";
}

fn classifyProbeError(err: anyerror) []const u8 {
    if (err == error.CurlFailed) return "auth_check_failed";
    if (err == error.CurlReadError or
        err == error.CurlWriteError or
        err == error.CurlWaitError or
        err == error.CurlDnsError or
        err == error.CurlConnectError or
        err == error.CurlTimeout or
        err == error.CurlTlsError)
    {
        return "network_error";
    }

    const name = @errorName(err);
    if (std.mem.indexOf(u8, name, "Timeout") != null or
        std.mem.indexOf(u8, name, "Network") != null or
        std.mem.indexOf(u8, name, "Connection") != null)
    {
        return "network_error";
    }
    return "probe_failed";
}

fn responseHasNonEmptyStringField(allocator: std.mem.Allocator, response: []const u8, key: []const u8) bool {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, response, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const field = parsed.value.object.get(key) orelse return false;
    if (field != .string) return false;
    return trimWhitespace(field.string).len > 0;
}

fn extractJsonStringFieldOwned(allocator: std.mem.Allocator, response: []const u8, key: []const u8) ?[]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, response, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;

    const field = parsed.value.object.get(key) orelse return null;
    if (field != .string) return null;

    const value = trimWhitespace(field.string);
    if (value.len == 0) return null;
    return allocator.dupe(u8, value) catch null;
}

fn oneBotResponseLooksHealthy(allocator: std.mem.Allocator, response: []const u8) bool {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, response, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;

    var has_health_marker = false;

    if (parsed.value.object.get("retcode")) |retcode| {
        has_health_marker = true;
        const value: i64 = switch (retcode) {
            .integer => retcode.integer,
            .number_string => std.fmt.parseInt(i64, retcode.number_string, 10) catch return false,
            else => return false,
        };
        if (value != 0) return false;
    }

    if (parsed.value.object.get("status")) |status| {
        has_health_marker = true;
        if (status != .string) return false;
        if (!std.ascii.eqlIgnoreCase(trimWhitespace(status.string), "ok")) return false;
    }

    if (!has_health_marker) {
        // Some adapters return only {"data":{...}} for get_login_info.
        if (parsed.value.object.get("data")) |data| {
            if (data == .object and data.object.count() > 0) return true;
        }
        if (parsed.value.object.get("user_id")) |uid| {
            if (uid == .string and trimWhitespace(uid.string).len > 0) return true;
            if (uid == .integer and uid.integer > 0) return true;
            if (uid == .number_string) {
                _ = std.fmt.parseInt(i64, uid.number_string, 10) catch return false;
                return true;
            }
        }
        return false;
    }

    return true;
}

fn timeoutPollMs(timeout_secs: u64) i32 {
    const effective_secs = if (timeout_secs == 0) 10 else timeout_secs;
    const max_secs: u64 = @intCast(@divFloor(std.math.maxInt(i32), 1000));
    if (effective_secs >= max_secs) return std.math.maxInt(i32);
    const ms = effective_secs * 1000;
    return @intCast(ms);
}

fn tcpReachableWithTimeout(allocator: std.mem.Allocator, host: []const u8, port: u16, timeout_secs: u64) !void {
    const addresses = try std.net.getAddressList(allocator, host, port);
    defer addresses.deinit();
    if (addresses.addrs.len == 0) return error.DnsResolutionFailed;

    const poll_ms = timeoutPollMs(timeout_secs);

    for (addresses.addrs) |addr| {
        const sockfd = std.posix.socket(
            addr.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC,
            std.posix.IPPROTO.TCP,
        ) catch continue;
        defer std.posix.close(sockfd);

        std.posix.connect(sockfd, &addr.any, addr.getOsSockLen()) catch |err| switch (err) {
            error.WouldBlock, error.ConnectionPending => {
                var poll_fds = [_]std.posix.pollfd{
                    .{
                        .fd = sockfd,
                        .events = std.posix.POLL.OUT,
                        .revents = 0,
                    },
                };

                const events = std.posix.poll(&poll_fds, poll_ms) catch continue;
                if (events == 0) continue; // timeout on this address

                const revents = poll_fds[0].revents;
                if ((revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL | std.posix.POLL.OUT)) == 0) {
                    continue;
                }

                std.posix.getsockoptError(sockfd) catch continue;
                return;
            },
            else => continue,
        };

        // Connected immediately.
        return;
    }

    return error.ConnectFailed;
}

fn allocOneBotApiBase(allocator: std.mem.Allocator, raw_url: []const u8) ![]u8 {
    const trimmed = trimTrailingSlash(trimWhitespace(raw_url));
    if (std.mem.startsWith(u8, trimmed, "ws://")) {
        return std.fmt.allocPrint(allocator, "http://{s}", .{trimmed["ws://".len..]});
    }
    if (std.mem.startsWith(u8, trimmed, "wss://")) {
        return std.fmt.allocPrint(allocator, "https://{s}", .{trimmed["wss://".len..]});
    }
    return allocator.dupe(u8, trimmed);
}

fn probeTelegram(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const token = nonEmptyString(cfg, "bot_token") orelse return fail(channel, account, "missing_bot_token");
    const proxy = optionalString(cfg, "proxy");

    var url_buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "https://api.telegram.org/bot{s}/getMe", .{token}) catch {
        return fail(channel, account, "probe_setup_failed");
    };

    var timeout_buf: [32]u8 = undefined;
    const timeout = timeoutString(&timeout_buf, timeout_secs);

    const resp = http_util.curlPostWithProxy(allocator, url, "{}", &.{}, proxy, timeout) catch |err| {
        return fail(channel, account, classifyProbeError(err));
    };
    defer allocator.free(resp);

    if (std.mem.indexOf(u8, resp, "\"ok\":true") == null) {
        return fail(channel, account, "invalid_bot_token");
    }
    return ok(channel, account);
}

fn probeDiscord(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const token = nonEmptyString(cfg, "token") orelse return fail(channel, account, "missing_token");

    var header_buf: [1024]u8 = undefined;
    const auth_header = std.fmt.bufPrint(&header_buf, "Authorization: Bot {s}", .{token}) catch {
        return fail(channel, account, "probe_setup_failed");
    };

    var timeout_buf: [32]u8 = undefined;
    const timeout = timeoutString(&timeout_buf, timeout_secs);

    const resp = http_util.curlGet(allocator, "https://discord.com/api/v10/users/@me", &.{auth_header}, timeout) catch |err| {
        return fail(channel, account, classifyProbeError(err));
    };
    defer allocator.free(resp);

    if (std.mem.indexOf(u8, resp, "\"id\"") == null) {
        return fail(channel, account, "invalid_token");
    }
    return ok(channel, account);
}

fn probeSlack(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const token = nonEmptyString(cfg, "bot_token") orelse return fail(channel, account, "missing_bot_token");

    var header_buf: [1024]u8 = undefined;
    const auth_header = std.fmt.bufPrint(&header_buf, "Authorization: Bearer {s}", .{token}) catch {
        return fail(channel, account, "probe_setup_failed");
    };

    var timeout_buf: [32]u8 = undefined;
    const timeout = timeoutString(&timeout_buf, timeout_secs);

    const resp = http_util.curlGet(allocator, "https://slack.com/api/auth.test", &.{auth_header}, timeout) catch |err| {
        return fail(channel, account, classifyProbeError(err));
    };
    defer allocator.free(resp);

    if (std.mem.indexOf(u8, resp, "\"ok\":true") == null) {
        return fail(channel, account, "invalid_bot_token");
    }
    return ok(channel, account);
}

fn probeMatrix(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const homeserver = nonEmptyString(cfg, "homeserver") orelse return fail(channel, account, "missing_homeserver");
    _ = nonEmptyString(cfg, "room_id") orelse return fail(channel, account, "missing_room_id");
    const access_token = nonEmptyString(cfg, "access_token") orelse return fail(channel, account, "missing_access_token");

    const base = trimTrailingSlash(homeserver);
    const url = std.fmt.allocPrint(allocator, "{s}/_matrix/client/v3/account/whoami", .{base}) catch {
        return fail(channel, account, "probe_setup_failed");
    };
    defer allocator.free(url);

    var header_buf: [2048]u8 = undefined;
    const auth_header = std.fmt.bufPrint(&header_buf, "Authorization: Bearer {s}", .{access_token}) catch {
        return fail(channel, account, "probe_setup_failed");
    };

    var timeout_buf: [32]u8 = undefined;
    const timeout = timeoutString(&timeout_buf, timeout_secs);

    const resp = http_util.curlGet(allocator, url, &.{auth_header}, timeout) catch |err| {
        return fail(channel, account, classifyProbeError(err));
    };
    defer allocator.free(resp);

    if (std.mem.indexOf(u8, resp, "\"user_id\"") == null) {
        return fail(channel, account, "auth_check_failed");
    }
    return ok(channel, account);
}

fn probeMattermost(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const base_url = nonEmptyString(cfg, "base_url") orelse return fail(channel, account, "missing_base_url");
    const bot_token = nonEmptyString(cfg, "bot_token") orelse return fail(channel, account, "missing_bot_token");

    const base = trimTrailingSlash(base_url);
    const url = std.fmt.allocPrint(allocator, "{s}/api/v4/users/me", .{base}) catch {
        return fail(channel, account, "probe_setup_failed");
    };
    defer allocator.free(url);

    var header_buf: [2048]u8 = undefined;
    const auth_header = std.fmt.bufPrint(&header_buf, "Authorization: Bearer {s}", .{bot_token}) catch {
        return fail(channel, account, "probe_setup_failed");
    };

    var timeout_buf: [32]u8 = undefined;
    const timeout = timeoutString(&timeout_buf, timeout_secs);

    const resp = http_util.curlGet(allocator, url, &.{auth_header}, timeout) catch |err| {
        return fail(channel, account, classifyProbeError(err));
    };
    defer allocator.free(resp);

    if (std.mem.indexOf(u8, resp, "\"id\"") == null) {
        return fail(channel, account, "auth_check_failed");
    }
    return ok(channel, account);
}

fn probeSignal(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const http_url = nonEmptyString(cfg, "http_url") orelse return fail(channel, account, "missing_http_url");
    _ = nonEmptyString(cfg, "account") orelse return fail(channel, account, "missing_account");

    const base = trimTrailingSlash(http_url);
    const url_rest = std.fmt.allocPrint(allocator, "{s}/v1/health", .{base}) catch {
        return fail(channel, account, "probe_setup_failed");
    };
    defer allocator.free(url_rest);

    const url_rpc = std.fmt.allocPrint(allocator, "{s}/api/v1/check", .{base}) catch {
        return fail(channel, account, "probe_setup_failed");
    };
    defer allocator.free(url_rpc);

    var timeout_buf: [32]u8 = undefined;
    const timeout = timeoutString(&timeout_buf, timeout_secs);

    const rest_probe = http_util.curlGet(allocator, url_rest, &.{}, timeout);
    if (rest_probe) |resp| {
        allocator.free(resp);
        return ok(channel, account);
    } else |_| {}

    const rpc_probe = http_util.curlGet(allocator, url_rpc, &.{}, timeout);
    if (rpc_probe) |resp| {
        allocator.free(resp);
        return ok(channel, account);
    } else |err| {
        return fail(channel, account, classifyProbeError(err));
    }
}

fn probeLine(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const access_token = nonEmptyString(cfg, "access_token") orelse return fail(channel, account, "missing_access_token");
    _ = nonEmptyString(cfg, "channel_secret") orelse return fail(channel, account, "missing_channel_secret");

    var header_buf: [2048]u8 = undefined;
    const auth_header = std.fmt.bufPrint(&header_buf, "Authorization: Bearer {s}", .{access_token}) catch {
        return fail(channel, account, "probe_setup_failed");
    };

    var timeout_buf: [32]u8 = undefined;
    const timeout = timeoutString(&timeout_buf, timeout_secs);

    const resp = http_util.curlGet(allocator, "https://api.line.me/v2/bot/info", &.{auth_header}, timeout) catch |err| {
        return fail(channel, account, classifyProbeError(err));
    };
    defer allocator.free(resp);

    if (std.mem.indexOf(u8, resp, "\"userId\"") == null and std.mem.indexOf(u8, resp, "\"displayName\"") == null) {
        return fail(channel, account, "auth_check_failed");
    }
    return ok(channel, account);
}

fn probeWhatsApp(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const access_token = nonEmptyString(cfg, "access_token") orelse return fail(channel, account, "missing_access_token");
    const phone_number_id = nonEmptyString(cfg, "phone_number_id") orelse return fail(channel, account, "missing_phone_number_id");
    _ = nonEmptyString(cfg, "verify_token") orelse return fail(channel, account, "missing_verify_token");

    var url_buf: [512]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "https://graph.facebook.com/v18.0/{s}?fields=id", .{phone_number_id}) catch {
        return fail(channel, account, "probe_setup_failed");
    };

    var header_buf: [2048]u8 = undefined;
    const auth_header = std.fmt.bufPrint(&header_buf, "Authorization: Bearer {s}", .{access_token}) catch {
        return fail(channel, account, "probe_setup_failed");
    };

    var timeout_buf: [32]u8 = undefined;
    const timeout = timeoutString(&timeout_buf, timeout_secs);

    const resp = http_util.curlGet(allocator, url, &.{auth_header}, timeout) catch |err| {
        return fail(channel, account, classifyProbeError(err));
    };
    defer allocator.free(resp);

    if (!responseHasNonEmptyStringField(allocator, resp, "id")) {
        return fail(channel, account, "invalid_access_token_or_phone_number_id");
    }
    return ok(channel, account);
}

fn probeLark(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const app_id = nonEmptyString(cfg, "app_id") orelse return fail(channel, account, "missing_app_id");
    const app_secret = nonEmptyString(cfg, "app_secret") orelse return fail(channel, account, "missing_app_secret");

    const use_feishu = boolOrDefault(cfg, "use_feishu", false);
    const base = if (use_feishu) "https://open.feishu.cn/open-apis" else "https://open.larksuite.com/open-apis";

    var url_buf: [512]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "{s}/auth/v3/tenant_access_token/internal", .{base}) catch {
        return fail(channel, account, "probe_setup_failed");
    };

    var body_buf: [2048]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{{\"app_id\":{f},\"app_secret\":{f}}}", .{
        std.json.fmt(app_id, .{}),
        std.json.fmt(app_secret, .{}),
    }) catch {
        return fail(channel, account, "probe_setup_failed");
    };

    var timeout_buf: [32]u8 = undefined;
    const timeout = timeoutString(&timeout_buf, timeout_secs);

    const resp = http_util.curlPostWithProxy(allocator, url, body, &.{}, null, timeout) catch |err| {
        return fail(channel, account, classifyProbeError(err));
    };
    defer allocator.free(resp);

    if (!responseHasNonEmptyStringField(allocator, resp, "tenant_access_token")) {
        return fail(channel, account, "invalid_app_credentials");
    }
    return ok(channel, account);
}

fn probeDingTalk(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const client_id = nonEmptyString(cfg, "client_id") orelse return fail(channel, account, "missing_client_id");
    const client_secret = nonEmptyString(cfg, "client_secret") orelse return fail(channel, account, "missing_client_secret");

    var body_buf: [2048]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{{\"appKey\":{f},\"appSecret\":{f}}}", .{
        std.json.fmt(client_id, .{}),
        std.json.fmt(client_secret, .{}),
    }) catch {
        return fail(channel, account, "probe_setup_failed");
    };

    var timeout_buf: [32]u8 = undefined;
    const timeout = timeoutString(&timeout_buf, timeout_secs);

    const resp = http_util.curlPostWithProxy(
        allocator,
        "https://api.dingtalk.com/v1.0/oauth2/accessToken",
        body,
        &.{},
        null,
        timeout,
    ) catch |err| {
        return fail(channel, account, classifyProbeError(err));
    };
    defer allocator.free(resp);

    if (!responseHasNonEmptyStringField(allocator, resp, "accessToken")) {
        return fail(channel, account, "invalid_client_credentials");
    }
    return ok(channel, account);
}

fn probeQQ(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const app_id = nonEmptyString(cfg, "app_id") orelse return fail(channel, account, "missing_app_id");
    const app_secret = nonEmptyString(cfg, "app_secret") orelse return fail(channel, account, "missing_app_secret");
    _ = nonEmptyString(cfg, "bot_token") orelse return fail(channel, account, "missing_bot_token");

    var body_buf: [2048]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{{\"appId\":{f},\"clientSecret\":{f}}}", .{
        std.json.fmt(app_id, .{}),
        std.json.fmt(app_secret, .{}),
    }) catch {
        return fail(channel, account, "probe_setup_failed");
    };

    var timeout_buf: [32]u8 = undefined;
    const timeout = timeoutString(&timeout_buf, timeout_secs);

    const token_resp = http_util.curlPostWithProxy(
        allocator,
        "https://bots.qq.com/app/getAppAccessToken",
        body,
        &.{},
        null,
        timeout,
    ) catch |err| {
        return fail(channel, account, classifyProbeError(err));
    };
    defer allocator.free(token_resp);

    const access_token = extractJsonStringFieldOwned(allocator, token_resp, "access_token") orelse {
        return fail(channel, account, "invalid_app_credentials");
    };
    defer allocator.free(access_token);

    const sandbox = boolOrDefault(cfg, "sandbox", false);
    const gateway_url = if (sandbox)
        "https://sandbox.api.sgroup.qq.com/gateway"
    else
        "https://api.sgroup.qq.com/gateway";

    var header_buf: [2048]u8 = undefined;
    const auth_header = std.fmt.bufPrint(&header_buf, "Authorization: QQBot {s}", .{access_token}) catch {
        return fail(channel, account, "probe_setup_failed");
    };

    const gateway_resp = http_util.curlGet(allocator, gateway_url, &.{auth_header}, timeout) catch |err| {
        return fail(channel, account, classifyProbeError(err));
    };
    defer allocator.free(gateway_resp);

    if (!responseHasNonEmptyStringField(allocator, gateway_resp, "url")) {
        return fail(channel, account, "gateway_resolution_failed");
    }
    return ok(channel, account);
}

fn probeOneBot(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const endpoint = nonEmptyString(cfg, "url") orelse return fail(channel, account, "missing_url");

    const api_base = allocOneBotApiBase(allocator, endpoint) catch {
        return fail(channel, account, "probe_setup_failed");
    };
    defer allocator.free(api_base);

    const url = std.fmt.allocPrint(allocator, "{s}/get_login_info", .{api_base}) catch {
        return fail(channel, account, "probe_setup_failed");
    };
    defer allocator.free(url);

    var headers: [1][]const u8 = undefined;
    var headers_slice: []const []const u8 = &.{};
    var auth_buf: [2048]u8 = undefined;
    if (optionalString(cfg, "access_token")) |token| {
        const auth_header = std.fmt.bufPrint(&auth_buf, "Authorization: Bearer {s}", .{token}) catch {
            return fail(channel, account, "probe_setup_failed");
        };
        headers[0] = auth_header;
        headers_slice = headers[0..1];
    }

    var timeout_buf: [32]u8 = undefined;
    const timeout = timeoutString(&timeout_buf, timeout_secs);

    const resp = http_util.curlPostWithProxy(
        allocator,
        url,
        "{\"action\":\"get_login_info\",\"params\":{}}",
        headers_slice,
        null,
        timeout,
    ) catch |err| {
        return fail(channel, account, classifyProbeError(err));
    };
    defer allocator.free(resp);

    if (!oneBotResponseLooksHealthy(allocator, resp)) {
        return fail(channel, account, "invalid_onebot_endpoint_or_token");
    }
    return ok(channel, account);
}

fn probeIrc(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const host = nonEmptyString(cfg, "host") orelse return fail(channel, account, "missing_host");
    _ = nonEmptyString(cfg, "nick") orelse return fail(channel, account, "missing_nick");

    const port_raw = u32OrDefault(cfg, "port", 6697);
    if (port_raw == 0 or port_raw > std.math.maxInt(u16)) {
        return fail(channel, account, "invalid_port");
    }
    const port: u16 = @intCast(port_raw);

    tcpReachableWithTimeout(allocator, host, port, timeout_secs) catch |err| {
        return fail(channel, account, switch (err) {
            error.DnsResolutionFailed => "dns_resolve_failed",
            error.ConnectFailed => "network_error",
            else => classifyProbeError(err),
        });
    };
    return ok(channel, account);
}

fn probeEmail(
    allocator: std.mem.Allocator,
    channel: []const u8,
    account: []const u8,
    cfg: std.json.ObjectMap,
    timeout_secs: u64,
) ProbeResult {
    const smtp_host = nonEmptyString(cfg, "smtp_host") orelse return fail(channel, account, "missing_smtp_host");
    _ = nonEmptyString(cfg, "username") orelse return fail(channel, account, "missing_username");
    _ = nonEmptyString(cfg, "password") orelse return fail(channel, account, "missing_password");
    _ = nonEmptyString(cfg, "from_address") orelse return fail(channel, account, "missing_from_address");

    const smtp_port_raw = u32OrDefault(cfg, "smtp_port", 587);
    if (smtp_port_raw == 0 or smtp_port_raw > std.math.maxInt(u16)) {
        return fail(channel, account, "invalid_smtp_port");
    }
    const smtp_port: u16 = @intCast(smtp_port_raw);

    tcpReachableWithTimeout(allocator, smtp_host, smtp_port, timeout_secs) catch |err| {
        return fail(channel, account, switch (err) {
            error.DnsResolutionFailed => "dns_resolve_failed",
            error.ConnectFailed => "network_error",
            else => classifyProbeError(err),
        });
    };
    return ok(channel, account);
}

fn validateWebConfig(channel: []const u8, account: []const u8, cfg: std.json.ObjectMap) ProbeResult {
    const transport = optionalString(cfg, "transport") orelse config_types.WebConfig.DEFAULT_TRANSPORT;
    if (!config_types.WebConfig.isValidTransport(transport)) {
        return fail(channel, account, "invalid_web_transport");
    }

    const message_auth_mode = optionalString(cfg, "message_auth_mode") orelse config_types.WebConfig.DEFAULT_MESSAGE_AUTH_MODE;
    if (!config_types.WebConfig.isValidMessageAuthMode(message_auth_mode)) {
        return fail(channel, account, "invalid_web_message_auth_mode");
    }

    if (optionalString(cfg, "auth_token")) |token| {
        if (!config_types.WebConfig.isValidAuthToken(token)) {
            return fail(channel, account, "invalid_web_auth_token");
        }
    }
    if (optionalString(cfg, "relay_token")) |token| {
        if (!config_types.WebConfig.isValidAuthToken(token)) {
            return fail(channel, account, "invalid_web_relay_token");
        }
    }

    if (config_types.WebConfig.isRelayTransport(transport)) {
        const relay_url = nonEmptyString(cfg, "relay_url") orelse return fail(channel, account, "missing_relay_url");
        if (!config_types.WebConfig.isValidRelayUrl(relay_url)) {
            return fail(channel, account, "invalid_relay_url");
        }
        const relay_agent_id = optionalString(cfg, "relay_agent_id") orelse "default";
        if (!config_types.WebConfig.isValidRelayAgentId(relay_agent_id)) {
            return fail(channel, account, "invalid_relay_agent_id");
        }

        const relay_pairing_ttl = u32OrDefault(cfg, "relay_pairing_code_ttl_secs", 300);
        if (!config_types.WebConfig.isValidRelayPairingCodeTtl(relay_pairing_ttl)) {
            return fail(channel, account, "invalid_relay_pairing_ttl");
        }

        const relay_ui_ttl = u32OrDefault(cfg, "relay_ui_token_ttl_secs", 86_400);
        if (!config_types.WebConfig.isValidRelayUiTokenTtl(relay_ui_ttl)) {
            return fail(channel, account, "invalid_relay_ui_ttl");
        }

        const relay_token_ttl = u32OrDefault(cfg, "relay_token_ttl_secs", 2_592_000);
        if (!config_types.WebConfig.isValidRelayTokenTtl(relay_token_ttl)) {
            return fail(channel, account, "invalid_relay_token_ttl");
        }
    } else {
        const path = optionalString(cfg, "path") orelse config_types.WebConfig.DEFAULT_PATH;
        if (!config_types.WebConfig.isPathWellFormed(path)) {
            return fail(channel, account, "invalid_web_path");
        }
        if (config_types.WebConfig.isTokenMessageAuthMode(message_auth_mode)) {
            if (!config_types.WebConfig.isValidTransport(transport) or config_types.WebConfig.isRelayTransport(transport)) {
                return fail(channel, account, "invalid_web_message_auth_transport");
            }
        }
    }

    return ok(channel, account);
}

fn validateConfigOnlyChannel(channel: []const u8, account: []const u8, cfg: std.json.ObjectMap) ProbeResult {
    if (std.mem.eql(u8, channel, "whatsapp")) {
        _ = nonEmptyString(cfg, "access_token") orelse return fail(channel, account, "missing_access_token");
        _ = nonEmptyString(cfg, "phone_number_id") orelse return fail(channel, account, "missing_phone_number_id");
        _ = nonEmptyString(cfg, "verify_token") orelse return fail(channel, account, "missing_verify_token");
        return ok(channel, account);
    }
    if (std.mem.eql(u8, channel, "irc")) {
        _ = nonEmptyString(cfg, "host") orelse return fail(channel, account, "missing_host");
        _ = nonEmptyString(cfg, "nick") orelse return fail(channel, account, "missing_nick");
        return ok(channel, account);
    }
    if (std.mem.eql(u8, channel, "lark")) {
        _ = nonEmptyString(cfg, "app_id") orelse return fail(channel, account, "missing_app_id");
        _ = nonEmptyString(cfg, "app_secret") orelse return fail(channel, account, "missing_app_secret");
        return ok(channel, account);
    }
    if (std.mem.eql(u8, channel, "dingtalk")) {
        _ = nonEmptyString(cfg, "client_id") orelse return fail(channel, account, "missing_client_id");
        _ = nonEmptyString(cfg, "client_secret") orelse return fail(channel, account, "missing_client_secret");
        return ok(channel, account);
    }
    if (std.mem.eql(u8, channel, "email")) {
        _ = nonEmptyString(cfg, "smtp_host") orelse return fail(channel, account, "missing_smtp_host");
        _ = nonEmptyString(cfg, "username") orelse return fail(channel, account, "missing_username");
        _ = nonEmptyString(cfg, "password") orelse return fail(channel, account, "missing_password");
        _ = nonEmptyString(cfg, "from_address") orelse return fail(channel, account, "missing_from_address");
        return ok(channel, account);
    }
    if (std.mem.eql(u8, channel, "qq")) {
        _ = nonEmptyString(cfg, "app_id") orelse return fail(channel, account, "missing_app_id");
        _ = nonEmptyString(cfg, "app_secret") orelse return fail(channel, account, "missing_app_secret");
        _ = nonEmptyString(cfg, "bot_token") orelse return fail(channel, account, "missing_bot_token");
        return ok(channel, account);
    }
    if (std.mem.eql(u8, channel, "onebot")) {
        _ = nonEmptyString(cfg, "url") orelse return fail(channel, account, "missing_url");
        return ok(channel, account);
    }
    if (std.mem.eql(u8, channel, "nostr")) {
        _ = nonEmptyString(cfg, "private_key") orelse return fail(channel, account, "missing_private_key");
        _ = nonEmptyString(cfg, "owner_pubkey") orelse return fail(channel, account, "missing_owner_pubkey");
        return ok(channel, account);
    }
    if (std.mem.eql(u8, channel, "maixcam")) {
        _ = nonEmptyString(cfg, "host") orelse return fail(channel, account, "missing_host");
        return ok(channel, account);
    }

    // imessage, webhook and any future channels default to config-only success.
    return ok(channel, account);
}

fn probeChannel(
    allocator: std.mem.Allocator,
    channels_obj: std.json.ObjectMap,
    channel: []const u8,
    account: []const u8,
    timeout_secs: u64,
) ProbeResult {
    if (std.mem.eql(u8, channel, "cli")) {
        const cli_enabled = switch (channels_obj.get("cli") orelse std.json.Value{ .bool = true }) {
            .bool => |enabled| enabled,
            else => true,
        };
        if (!cli_enabled) return fail(channel, account, "channel_disabled");
        return ok(channel, account);
    }

    const meta = channel_catalog.findByKey(channel) orelse return fail(channel, account, "unknown_channel");
    if (!channel_catalog.isBuildEnabled(meta.id)) {
        return fail(channel, account, "channel_disabled_in_build");
    }

    const account_obj = resolveChannelAccountObject(channels_obj, channel, account) orelse return fail(channel, account, "account_not_found");

    if (std.mem.eql(u8, channel, "telegram")) {
        return probeTelegram(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "discord")) {
        return probeDiscord(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "slack")) {
        return probeSlack(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "matrix")) {
        return probeMatrix(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "mattermost")) {
        return probeMattermost(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "signal")) {
        return probeSignal(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "line")) {
        return probeLine(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "whatsapp")) {
        return probeWhatsApp(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "lark")) {
        return probeLark(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "dingtalk")) {
        return probeDingTalk(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "qq")) {
        return probeQQ(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "onebot")) {
        return probeOneBot(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "irc")) {
        return probeIrc(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "email")) {
        return probeEmail(allocator, channel, account, account_obj, timeout_secs);
    }
    if (std.mem.eql(u8, channel, "web")) {
        return validateWebConfig(channel, account, account_obj);
    }

    return validateConfigOnlyChannel(channel, account, account_obj);
}

fn readChannelsObject(allocator: std.mem.Allocator) ReadConfigError!ParsedChannels {
    var cfg = config_mod.Config.load(allocator) catch return error.ConfigLoadFailed;
    defer cfg.deinit();

    const file = std.fs.openFileAbsolute(cfg.config_path, .{}) catch return error.ConfigReadFailed;
    defer file.close();

    const content = file.readToEndAlloc(allocator, 1024 * 512) catch return error.ConfigReadFailed;
    defer allocator.free(content);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{ .allocate = .alloc_always }) catch return error.ConfigParseFailed;

    if (parsed.value != .object) {
        parsed.deinit();
        return error.ConfigRootNotObject;
    }
    const channels_value = parsed.value.object.get("channels") orelse {
        parsed.deinit();
        return error.MissingChannels;
    };
    if (channels_value != .object) {
        parsed.deinit();
        return error.InvalidChannels;
    }

    return .{
        .parsed = parsed,
        .channels = channels_value.object,
    };
}

fn writeResult(result: ProbeResult) !void {
    var buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&buf);
    const out = &bw.interface;

    try out.writeAll("{\"channel\":");
    try out.print("{f}", .{std.json.fmt(result.channel, .{})});
    try out.writeAll(",\"account\":");
    try out.print("{f}", .{std.json.fmt(result.account, .{})});
    try out.print(",\"live_ok\":{}", .{result.live_ok});
    try out.writeAll(",\"status\":\"");
    try out.writeAll(if (result.live_ok) "ok" else "error");
    try out.writeAll("\",\"reason\":");
    try out.print("{f}", .{std.json.fmt(result.reason, .{})});
    try out.writeAll("}\n");
    try bw.interface.flush();
}

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var channel: ?[]const u8 = null;
    var account: ?[]const u8 = null;
    var timeout_secs: u64 = 10;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--channel") and i + 1 < args.len) {
            channel = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--account") and i + 1 < args.len) {
            account = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--timeout-secs") and i + 1 < args.len) {
            timeout_secs = std.fmt.parseInt(u64, args[i + 1], 10) catch 10;
            i += 1;
        }
    }

    const ch = channel orelse {
        try writeResult(fail("unknown", account orelse "default", "missing_channel_arg"));
        return;
    };
    const acc = account orelse "default";

    var parsed_channels = readChannelsObject(allocator) catch |err| {
        const reason = switch (err) {
            error.ConfigLoadFailed => "config_load_failed",
            error.ConfigReadFailed => "config_read_failed",
            error.ConfigParseFailed => "config_parse_failed",
            error.ConfigRootNotObject => "config_root_invalid",
            error.MissingChannels => "channel_not_configured",
            error.InvalidChannels => "channels_section_invalid",
        };
        try writeResult(fail(ch, acc, reason));
        return;
    };
    defer parsed_channels.parsed.deinit();

    try writeResult(probeChannel(allocator, parsed_channels.channels, ch, acc, timeout_secs));
}

test "channelSupportsAccounts differentiates account models" {
    try std.testing.expect(channelSupportsAccounts("telegram"));
    try std.testing.expect(channelSupportsAccounts("web"));
    try std.testing.expect(!channelSupportsAccounts("webhook"));
    try std.testing.expect(!channelSupportsAccounts("cli"));
}

test "classifyProbeError maps specific curl network errors" {
    try std.testing.expectEqualStrings("network_error", classifyProbeError(error.CurlDnsError));
    try std.testing.expectEqualStrings("network_error", classifyProbeError(error.CurlConnectError));
    try std.testing.expectEqualStrings("network_error", classifyProbeError(error.CurlTimeout));
    try std.testing.expectEqualStrings("network_error", classifyProbeError(error.CurlTlsError));
}

test "resolveChannelAccountObject handles canonical accounts wrapper" {
    const allocator = std.testing.allocator;
    const payload =
        \\{
        \\  "channels": {
        \\    "telegram": {
        \\      "accounts": {
        \\        "default": { "bot_token": "a" }
        \\      }
        \\    }
        \\  }
        \\}
    ;

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{ .allocate = .alloc_always });
    defer parsed.deinit();

    const channels_obj = parsed.value.object.get("channels").?.object;
    const account_obj = resolveChannelAccountObject(channels_obj, "telegram", "default");
    try std.testing.expect(account_obj != null);
    try std.testing.expectEqualStrings("a", account_obj.?.get("bot_token").?.string);
}

test "resolveChannelAccountObject handles wizard account map" {
    const allocator = std.testing.allocator;
    const payload =
        \\{
        \\  "channels": {
        \\    "telegram": {
        \\      "default": { "bot_token": "a" }
        \\    }
        \\  }
        \\}
    ;

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{ .allocate = .alloc_always });
    defer parsed.deinit();

    const channels_obj = parsed.value.object.get("channels").?.object;
    const account_obj = resolveChannelAccountObject(channels_obj, "telegram", "default");
    try std.testing.expect(account_obj != null);
    try std.testing.expectEqualStrings("a", account_obj.?.get("bot_token").?.string);
}

test "resolveChannelAccountObject handles single-account wizard shape" {
    const allocator = std.testing.allocator;
    const payload =
        \\{
        \\  "channels": {
        \\    "webhook": {
        \\      "webhook": { "secret": "s" }
        \\    }
        \\  }
        \\}
    ;

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{ .allocate = .alloc_always });
    defer parsed.deinit();

    const channels_obj = parsed.value.object.get("channels").?.object;
    const account_obj = resolveChannelAccountObject(channels_obj, "webhook", "webhook");
    try std.testing.expect(account_obj != null);
    try std.testing.expectEqualStrings("s", account_obj.?.get("secret").?.string);
}

test "allocOneBotApiBase normalizes websocket schemes" {
    const allocator = std.testing.allocator;

    const ws_base = try allocOneBotApiBase(allocator, "ws://127.0.0.1:6700");
    defer allocator.free(ws_base);
    try std.testing.expectEqualStrings("http://127.0.0.1:6700", ws_base);

    const wss_base = try allocOneBotApiBase(allocator, "wss://onebot.example/ws");
    defer allocator.free(wss_base);
    try std.testing.expectEqualStrings("https://onebot.example/ws", wss_base);
}

test "oneBotResponseLooksHealthy validates retcode and status" {
    const allocator = std.testing.allocator;

    const ok_payload = "{\"status\":\"ok\",\"retcode\":0,\"data\":{\"user_id\":1}}";
    try std.testing.expect(oneBotResponseLooksHealthy(allocator, ok_payload));

    const bad_payload = "{\"status\":\"failed\",\"retcode\":1400}";
    try std.testing.expect(!oneBotResponseLooksHealthy(allocator, bad_payload));
}
