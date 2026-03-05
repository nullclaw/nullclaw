const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const bus_mod = @import("../bus.zig");
const websocket = @import("../websocket.zig");
const config_types = @import("../config_types.zig");
const http_util = @import("../http_util.zig");

const log = std.log.scoped(.dingtalk);

/// Environment variable to force native Zig WebSocket on Linux (avoids Python dependency).
/// Set to "1" to enable native WebSocket even on Linux.
/// Default: use Python on Linux (to avoid Zig 0.15 TLS segfault in subthreads), native on Windows.
const ENV_FORCE_NATIVE_WS = "NULLCLAW_DINGTALK_USE_NATIVE_WS";

/// Global atomic flag for verbose logging - set when --verbose flag is present.
var verbose_logging_enabled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

/// Set the verbose logging flag (called from main.zig when --verbose is present).
pub fn setVerboseLogging(enabled: bool) void {
    verbose_logging_enabled.store(enabled, .release);
}

/// Check if verbose logging is enabled.
fn isVerboseLog() bool {
    const enabled = verbose_logging_enabled.load(.acquire);
    return enabled;
}

/// Check if we should use native Zig WebSocket instead of Python.
fn useNativeWebSocket() bool {
    if (builtin.os.tag == .windows) return true;
    var env_map = std.process.getEnvMap(std.heap.c_allocator) catch return false;
    defer env_map.deinit();
    if (env_map.get(ENV_FORCE_NATIVE_WS)) |val| {
        return val.len > 0 and val[0] == '1';
    }
    return false;
}

/// Python script for WebSocket client (embedded to avoid external dependencies).
/// Handles WebSocket connection and ACK responses to work around Zig 0.15 TLS segfault.
const PYTHON_WS_SCRIPT =
    "import sys,os,json,ssl,traceback\n" ++
    "try:\n" ++
    "    import websocket\n" ++
    "except ImportError:\n" ++
    "    print('ERROR: websocket-client not installed',file=sys.stderr)\n" ++
    "    sys.exit(1)\n" ++
    "url=sys.argv[1]\n" ++
    "sys.stderr.write('CONNECTING\\n')\n" ++
    "sys.stderr.flush()\n" ++
    "try:\n" ++
    "    ws=websocket.WebSocket(sslopt={'cert_reqs':ssl.CERT_NONE},timeout=30)\n" ++
    "    ws.connect(url)\n" ++
    "    print('CONNECTED',flush=True)\n" ++
    "except Exception as e:\n" ++
    "    print(f'CONNECT_ERROR:{e}',file=sys.stderr,flush=True)\n" ++
    "    sys.exit(1)\n" ++
    "print('READY',flush=True)\n" ++
    "while True:\n" ++
    "    try:\n" ++
    "        msg=ws.recv()\n" ++
    "        if not msg:\n" ++
    "            continue\n" ++
    "        print(msg,flush=True)\n" ++
    "        # Parse and send ACK\n" ++
    "        try:\n" ++
    "            p=json.loads(msg)\n" ++
    "            mt=p.get('type','')\n" ++
    "            h=p.get('headers',{})\n" ++
    "            mid=h.get('messageId','')\n" ++
    "            topic=h.get('topic','')\n" ++
    "            data=p.get('data','')\n" ++
    "            if mt=='SYSTEM':\n" ++
    "                ack=json.dumps({'opaque':json.loads(data).get('opaque','')}) if topic=='ping' and data else '{}'\n" ++
    "            elif mt=='EVENT':\n" ++
    "                ack=json.dumps({'status':'SUCCESS','message':'success'})\n" ++
    "            else:\n" ++
    "                ack='{}'\n" ++
    "            if mid:\n" ++
    "                ws.send(json.dumps({'code':200,'headers':{'messageId':mid,'contentType':'application/json'},'message':'OK','data':ack}))\n" ++
    "        except Exception:\n" ++
    "            pass\n" ++
    "    except websocket.WebSocketTimeoutException:\n" ++
    "        continue\n" ++
    "    except Exception as e:\n" ++
    "        print(f'ERR:{e}',file=sys.stderr,flush=True)\n" ++
    "        break\n" ++
    "ws.close()\n";

pub const DingTalkChannel = struct {
    allocator: std.mem.Allocator,
    account_id: []const u8,
    client_id: []const u8,
    client_secret: []const u8,
    allow_from: []const []const u8,
    subscribe_events: bool = false,
    subscriptions: []const config_types.DingTalkSubscription = &.{},
    ua: ?[]const u8 = null,
    local_ip: ?[]const u8 = null,
    typing_message: []const u8 = DEFAULT_TYPING_MESSAGE,
    bus: ?*bus_mod.Bus = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    gateway_thread: ?std.Thread = null,
    ws_fd: std.atomic.Value(SocketFd) = std.atomic.Value(SocketFd).init(invalid_socket),

    const SocketFd = std.net.Stream.Handle;
    const invalid_socket: SocketFd = switch (builtin.os.tag) {
        .windows => std.os.windows.ws2_32.INVALID_SOCKET,
        else => -1,
    };

    pub const GATEWAY_URL = "https://api.dingtalk.com/v1.0/gateway/connections/open";
    pub const BOT_MESSAGE_TOPIC = "/v1.0/im/bot/messages/get";
    pub const BOT_SEND_API_URL = "https://api.dingtalk.com/v1.0/robot/oToMessages/batchSend";
    pub const DEFAULT_TYPING_MESSAGE = "⏳ Thinking ...";
    
    pub const OAUTH2_TOKEN_URL = "https://api.dingtalk.com/v1.0/oauth2/accessToken";
    pub const RECALL_API_URL = "https://api.dingtalk.com/v1.0/robot/otoMessages/batchRecall";
    pub const RECONNECT_DELAY_NS: u64 = 5 * std.time.ns_per_s;

    pub fn extractTypingInfo(allocator: std.mem.Allocator, metadata_json: []const u8) !struct { msg_id: ?[]const u8, robot_code: ?[]const u8 } {
        if (metadata_json.len == 0) return .{ .msg_id = null, .robot_code = null };

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, metadata_json, .{}) catch return .{ .msg_id = null, .robot_code = null };
        defer parsed.deinit();
        if (parsed.value != .object) return .{ .msg_id = null, .robot_code = null };

        const obj = parsed.value.object;
        const typing_msg_id_val = obj.get("typing_msg_id");
        const robot_code_val = obj.get("robot_code");

        const msg_id: ?[]const u8 = if (typing_msg_id_val != null and typing_msg_id_val.? == .string)
            try allocator.dupe(u8, typing_msg_id_val.?.string)
        else
            null;

        const robot_code: ?[]const u8 = if (robot_code_val != null and robot_code_val.? == .string)
            try allocator.dupe(u8, robot_code_val.?.string)
        else
            null;

        return .{ .msg_id = msg_id, .robot_code = robot_code };
    }

    const ConnectionInfo = struct {
        endpoint: []const u8,
        ticket: []const u8,
    };

    const EndpointParts = struct {
        host: []const u8,
        port: u16,
        path: []const u8,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        client_id: []const u8,
        client_secret: []const u8,
        allow_from: []const []const u8,
    ) DingTalkChannel {
        return .{
            .allocator = allocator,
            .account_id = "default",
            .client_id = client_id,
            .client_secret = client_secret,
            .allow_from = allow_from,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.DingTalkConfig) DingTalkChannel {
        return .{
            .allocator = allocator,
            .account_id = cfg.account_id,
            .client_id = cfg.client_id,
            .client_secret = cfg.client_secret,
            .allow_from = cfg.allow_from,
            .subscribe_events = cfg.subscribe_events,
            .subscriptions = cfg.subscriptions,
            .ua = cfg.ua,
            .local_ip = cfg.local_ip,
            .typing_message = cfg.typing_message orelse DEFAULT_TYPING_MESSAGE,
        };
    }

    pub fn setBus(self: *DingTalkChannel, b: *bus_mod.Bus) void {
        self.bus = b;
    }

    pub fn channelName(_: *DingTalkChannel) []const u8 {
        return "dingtalk";
    }

    pub fn isUserAllowed(self: *const DingTalkChannel, user_id: []const u8) bool {
        return root.isAllowedExact(self.allow_from, user_id);
    }

    pub fn healthCheck(self: *DingTalkChannel) bool {
        return self.running.load(.acquire);
    }

    /// Send an immediate "typing..." response and return the message ID.
    /// This is used to give the user immediate feedback while the AI is thinking.
    /// Returns null if sending fails or no message ID is returned.
    fn sendImmediateResponse(self: *DingTalkChannel, webhook_url: []const u8) ?[]const u8 {
        if (isVerboseLog()) log.info("DingTalk sendImmediateResponse: starting for webhook: {s}", .{webhook_url});
        
        var body_buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        w.writeAll("{\"msgtype\":\"text\",\"text\":{\"content\":") catch return null;
        root.appendJsonStringW(w, self.typing_message) catch return null;
        w.writeAll("}}") catch return null;
        const body = fbs.getWritten();

        if (isVerboseLog()) log.info("DingTalk sendImmediateResponse: request body: {s}", .{body});

        const resp = http_util.curlPostWithProxy(self.allocator, webhook_url, body, &.{}, null, null) catch |err| {
            log.err("DingTalk sendImmediateResponse: HTTP request failed: {}", .{err});
            return null;
        };
        defer self.allocator.free(resp);

        if (isVerboseLog()) log.info("DingTalk sendImmediateResponse: HTTP response ({d} bytes): {s}", .{ resp.len, resp });

        if (resp.len == 0) {
            log.err("DingTalk sendImmediateResponse: empty response, cannot get processKey", .{});
            return null;
        }
        if (isVerboseLog()) log.info("DingTalk sendImmediateResponse: parsing JSON response...", .{});
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp, .{}) catch |err| {
            log.err("DingTalk sendImmediateResponse: JSON parse error: {} (response: {s})", .{ err, resp });
            return null;
        };
        defer parsed.deinit();
        if (parsed.value != .object) {
            log.err("DingTalk sendImmediateResponse: response is not a JSON object (type: {s})", .{@tagName(parsed.value)});
            return null;
        }

        if (isVerboseLog()) log.info("DingTalk sendImmediateResponse: looking for processKey in response object...", .{});
        const process_key = parsed.value.object.get("processKey") orelse {
            if (parsed.value.object.get("errcode")) |errcode| {
                log.err("DingTalk sendImmediateResponse: API returned error code: {any}", .{errcode});
            }
            if (parsed.value.object.get("errmsg")) |errmsg| {
                log.err("DingTalk sendImmediateResponse: API error message: {any}", .{errmsg});
            }
            log.err("DingTalk sendImmediateResponse: no processKey in response. Full response: {s}", .{resp});
            return null;
        };
        if (process_key != .string) {
            log.err("DingTalk sendImmediateResponse: processKey is not a string (type: {s})", .{@tagName(process_key)});
            return null;
        }

        if (isVerboseLog()) log.info("DingTalk sendImmediateResponse: SUCCESS - processKey: {s}", .{process_key.string});
        return self.allocator.dupe(u8, process_key.string) catch null;
    }

    /// Get OAuth2 access token for DingTalk API calls.
    /// Returns the access token string (caller must free) or null on failure.
    /// Motivation: The Bot Message API and Recall API require OAuth2 authentication.
    /// This function obtains an access token using the client credentials flow.
    pub fn getAccessToken(self: *DingTalkChannel) ?[]const u8 {
        if (isVerboseLog()) log.info("DingTalk getAccessToken: requesting token for client_id={s}", .{self.client_id});
        
        var body_buf: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        w.writeAll("{\"appKey\":") catch return null;
        root.appendJsonStringW(w, self.client_id) catch return null;
        w.writeAll(",\"appSecret\":") catch return null;
        root.appendJsonStringW(w, self.client_secret) catch return null;
        w.writeByte('}') catch return null;
        const body = fbs.getWritten();

        const headers = &.{
            "Content-Type: application/json",
        };
        
        const resp = http_util.curlPostWithProxy(self.allocator, OAUTH2_TOKEN_URL, body, headers, null, null) catch |err| {
            log.err("DingTalk getAccessToken: HTTP request failed: {}", .{err});
            return null;
        };
        defer self.allocator.free(resp);

        // Parse response to get access_token
        if (resp.len == 0) {
            log.err("DingTalk getAccessToken: empty response", .{});
            return null;
        }
        
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp, .{}) catch |err| {
            log.err("DingTalk getAccessToken: JSON parse error: {} (response: {s})", .{ err, resp });
            return null;
        };
        defer parsed.deinit();
        
        if (parsed.value != .object) {
            log.err("DingTalk getAccessToken: response not object", .{});
            return null;
        }

        // Check for errors
        if (parsed.value.object.get("errcode")) |errcode| {
            if (errcode != .integer or errcode.integer != 0) {
                const errmsg = parsed.value.object.get("errmsg") orelse .null;
                log.err("DingTalk getAccessToken: API error - errcode={any}, errmsg={any}", .{ errcode, errmsg });
                return null;
            }
        }

        const access_token = parsed.value.object.get("accessToken") orelse {
            log.err("DingTalk getAccessToken: no accessToken in response", .{});
            return null;
        };
        
        if (access_token != .string) {
            log.err("DingTalk getAccessToken: accessToken not string", .{});
            return null;
        }

        return self.allocator.dupe(u8, access_token.string) catch null;
    }

    /// Send a message using Bot Message API (supports recall).
    /// Returns the message ID (processQueryKey) or null on failure.
    /// Motivation: This function sends messages using the Bot Message API which supports recall.
    /// It's used to send typing indicators that can be automatically withdrawn when the actual response is sent.
    /// The API requires OAuth2 authentication and returns a processQueryKey for message recall.
    pub fn sendBotMessage(self: *DingTalkChannel, user_id: []const u8, msg: []const u8) ?[]const u8 {
        const access_token = self.getAccessToken() orelse {
            log.err("DingTalk sendBotMessage: failed to get access token", .{});
            return null;
        };
        defer self.allocator.free(access_token);
        var body_buf: [4096]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        
        // First, build msgParam JSON string separately
        var msg_param_buf: [1024]u8 = undefined;
        var msg_param_fbs = std.io.fixedBufferStream(&msg_param_buf);
        const msg_param_w = msg_param_fbs.writer();
        msg_param_w.writeAll("{\"content\":") catch {};
        root.appendJsonStringW(msg_param_w, msg) catch {};
        msg_param_w.writeAll("}") catch {};
        const msg_param_str = msg_param_fbs.getWritten();
        
        // Now build the full request body with msgParam as a JSON string
        w.writeAll("{\"robotCode\":") catch return null;
        root.appendJsonStringW(w, self.client_id) catch return null;
        w.writeAll(",\"userIds\":[\"") catch return null;
        w.writeAll(user_id) catch return null;
        w.writeAll("\"],\"msgKey\":\"sampleText\",\"msgParam\":") catch return null;
        root.appendJsonStringW(w, msg_param_str) catch return null;
        w.writeAll("}") catch return null;
        const body = fbs.getWritten();

        // Build auth header
        var auth_header_buf: [512]u8 = undefined;
        const auth_header = std.fmt.bufPrint(&auth_header_buf, "x-acs-dingtalk-access-token: {s}", .{access_token}) catch {
            log.err("DingTalk sendBotMessage: auth header too long", .{});
            return null;
        };
        const headers = &.{
            "Content-Type: application/json",
            auth_header,
        };

        const resp = http_util.curlPostWithProxy(self.allocator, BOT_SEND_API_URL, body, headers, null, null) catch |err| {
            log.err("DingTalk sendBotMessage: HTTP request failed: {}", .{err});
            return null;
        };
        defer self.allocator.free(resp);

        // Parse response to get processKey
        if (resp.len == 0) {
            log.err("DingTalk sendBotMessage: empty response", .{});
            return null;
        }
        
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp, .{}) catch |err| {
            log.err("DingTalk sendBotMessage: JSON parse error: {} (response: {s})", .{ err, resp });
            return null;
        };
        defer parsed.deinit();
        
        if (parsed.value != .object) {
            log.err("DingTalk sendBotMessage: response not object", .{});
            return null;
        }

        // Check for errors
        if (parsed.value.object.get("errcode")) |errcode| {
            if (errcode != .integer or errcode.integer != 0) {
                const errmsg = parsed.value.object.get("errmsg") orelse .null;
                log.err("DingTalk sendBotMessage: API error - errcode={any}, errmsg={any}", .{ errcode, errmsg });
                return null;
            }
        }

        const process_key = parsed.value.object.get("processQueryKey") orelse {
            log.err("DingTalk sendBotMessage: no processQueryKey in response", .{});
            return null;
        };
        
        if (process_key != .string) {
            log.err("DingTalk sendBotMessage: processQueryKey not string", .{});
            return null;
        }

        if (isVerboseLog()) log.info("DingTalk sendBotMessage: SUCCESS - processQueryKey={s}", .{process_key.string});
        return self.allocator.dupe(u8, process_key.string) catch null;
    }

    pub fn recallMessage(self: *DingTalkChannel, msg_id: []const u8, robot_code: []const u8) void {
        if (isVerboseLog()) log.info("DingTalk recallMessage: attempting to recall msg_id={s}, robot_code={s}", .{ msg_id, robot_code });
        
        // Get access token for authentication
        const access_token = self.getAccessToken() orelse {
            log.err("DingTalk recallMessage: failed to get access token", .{});
            return;
        };
        defer self.allocator.free(access_token);
        
        var body_buf: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        w.writeAll("{\"robotCode\":") catch return;
        root.appendJsonStringW(w, robot_code) catch return;
        w.writeAll(",\"processQueryKeys\":[") catch return;
        root.appendJsonStringW(w, msg_id) catch return;
        w.writeAll("]}") catch return;
        const body = fbs.getWritten();

        if (isVerboseLog()) log.info("DingTalk recallMessage: request body: {s}", .{body});

        var auth_header_buf: [512]u8 = undefined;
        const auth_header = std.fmt.bufPrint(&auth_header_buf, "x-acs-dingtalk-access-token: {s}", .{access_token}) catch {
            log.err("DingTalk recallMessage: auth header too long", .{});
            return;
        };
        const headers = &.{
            "Content-Type: application/json",
            auth_header,
        };

        if (isVerboseLog()) log.info("DingTalk recallMessage: sending recall request to {s}", .{RECALL_API_URL});
        const resp = http_util.curlPostWithProxy(
            self.allocator,
            RECALL_API_URL,
            body,
            headers,
            null,
            null,
        ) catch |err| {
            log.err("DingTalk recallMessage failed: {} (msg_id={s}, robot_code={s})", .{ err, msg_id, robot_code });
            return;
        };
        defer self.allocator.free(resp);

        if (isVerboseLog()) log.info("DingTalk recallMessage: API response: {s}", .{resp});
    }

    pub fn sendMessage(self: *DingTalkChannel, webhook_url: []const u8, text: []const u8) !void {
        if (isVerboseLog()) log.info("[DingTalk SEND] {s}", .{text});

        var body_buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&body_buf);
        const w = fbs.writer();
        try w.writeAll("{\"msgtype\":\"markdown\",\"markdown\":{\"title\":\"nullclaw\",\"text\":");
        try root.appendJsonStringW(w, text);
        try w.writeAll("}}");
        const body = fbs.getWritten();

        // Use curl to avoid Zig 0.15 std.http.Client segfaults
        const resp = http_util.curlPostWithProxy(self.allocator, webhook_url, body, &.{}, null, null) catch |err| {
            log.err("DingTalk sendMessage failed: {}", .{err});
            return error.DingTalkApiError;
        };
        defer self.allocator.free(resp);
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        self.running.store(true, .release);
        self.gateway_thread = try std.Thread.spawn(.{ .stack_size = 1024 * 1024 }, gatewayLoop, .{self});
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        self.running.store(false, .release);
        const fd = self.ws_fd.load(.acquire);
        if (fd != invalid_socket) {
            if (comptime builtin.os.tag == .windows) {
                _ = std.os.windows.ws2_32.closesocket(fd);
            } else {
                std.posix.close(fd);
            }
        }
        if (self.gateway_thread) |t| {
            t.join();
            self.gateway_thread = null;
        }
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableSendEvent(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8, stage: root.Channel.OutboundStage, metadata: ?[]const u8) anyerror!void {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));

        if (stage == .chunk) {
            try self.sendMessage(target, message);
            return;
        }

        if (isVerboseLog()) log.info("DingTalk vtableSendEvent: sending final response via webhook to {s}", .{target});
        try self.sendMessage(target, message);
        if (isVerboseLog()) log.info("DingTalk vtableSendEvent: final response sent successfully", .{});

        if (isVerboseLog()) log.info("DingTalk vtableSendEvent: checking metadata for typing recall, metadata present: {}", .{metadata != null});
        if (metadata) |meta| {
            if (isVerboseLog()) log.info("DingTalk vtableSendEvent: metadata length: {d}", .{meta.len});
            if (meta.len > 0) {
                const typing_info = DingTalkChannel.extractTypingInfo(self.allocator, meta) catch |err| {
                    log.warn("DingTalk vtableSendEvent: extractTypingInfo failed: {}", .{err});
                    return;
                };
                defer {
                    if (typing_info.msg_id) |msg_id| self.allocator.free(msg_id);
                    if (typing_info.robot_code) |robot_code| self.allocator.free(robot_code);
                }
                if (isVerboseLog()) log.info("DingTalk vtableSendEvent: extracted typing info - msg_id: {?s}, robot_code: {?s}", .{ typing_info.msg_id, typing_info.robot_code });
                if (typing_info.msg_id != null and typing_info.robot_code != null) {
                    if (isVerboseLog()) log.info("DingTalk vtableSendEvent: recalling typing message {s} with robot code {s}", .{ typing_info.msg_id.?, typing_info.robot_code.? });
                    self.recallMessage(typing_info.msg_id.?, typing_info.robot_code.?);
                } else {
                    if (isVerboseLog()) log.warn("DingTalk vtableSendEvent: missing msg_id or robot_code for recall", .{});
                }
            } else {
                if (isVerboseLog()) log.warn("DingTalk vtableSendEvent: metadata is empty", .{});
            }
        } else {
            if (isVerboseLog()) log.warn("DingTalk vtableSendEvent: no metadata provided", .{});
        }
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *DingTalkChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .sendEventWithMeta = &vtableSendEvent,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *DingTalkChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn gatewayLoop(self: *DingTalkChannel) void {
        while (self.running.load(.acquire)) {
            self.runGatewayOnce() catch |err| {
                log.warn("DingTalk gateway error: {}", .{err});
            };
            if (!self.running.load(.acquire)) break;
            var slept: u64 = 0;
            while (slept < RECONNECT_DELAY_NS and self.running.load(.acquire)) {
                std.Thread.sleep(100 * std.time.ns_per_ms);
                slept += 100 * std.time.ns_per_ms;
            }
        }
        self.ws_fd.store(invalid_socket, .release);
    }

    fn runGatewayOnce(self: *DingTalkChannel) !void {
        const conn = try self.openConnection();
        log.info("DingTalk opened connection: endpoint={s}", .{conn.endpoint});
        defer {
            self.allocator.free(conn.endpoint);
            self.allocator.free(conn.ticket);
        }

        const parts = try parseEndpoint(conn.endpoint);
        const path = try buildTicketPath(self.allocator, parts.path, conn.ticket);
        defer self.allocator.free(path);

        if (useNativeWebSocket()) {
            if (isVerboseLog()) log.info("DingTalk using native Zig WebSocket", .{});
            try self.runNativeWsLoop(parts.host, parts.port, path);
        } else {
            if (isVerboseLog()) log.info("DingTalk using Python WebSocket (to avoid Zig 0.15 TLS segfault on Linux)", .{});
            const ws_url = try std.fmt.allocPrint(self.allocator, "wss://{s}:{d}{s}", .{ parts.host, parts.port, path });
            defer self.allocator.free(ws_url);
            try self.runPythonWsLoop(ws_url);
        }
    }

    fn openConnection(self: *DingTalkChannel) !ConnectionInfo {
        const body = try self.buildOpenBody();
        defer self.allocator.free(body);

        // Use curl to avoid Zig 0.15 std.http.Client segfaults
        const resp_body = http_util.curlPostWithProxy(
            self.allocator,
            GATEWAY_URL,
            body,
            &.{
                "Content-Type: application/json; charset=utf-8",
                "Accept: application/json",
            },
            null,
            null,
        ) catch return error.DingTalkApiError;
        defer self.allocator.free(resp_body);

        if (resp_body.len == 0) return error.DingTalkApiError;

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp_body, .{}) catch return error.DingTalkApiError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.DingTalkApiError;

        const endpoint_val = parsed.value.object.get("endpoint") orelse return error.DingTalkApiError;
        const ticket_val = parsed.value.object.get("ticket") orelse return error.DingTalkApiError;
        if (endpoint_val != .string or ticket_val != .string) return error.DingTalkApiError;

        return .{
            .endpoint = try self.allocator.dupe(u8, endpoint_val.string),
            .ticket = try self.allocator.dupe(u8, ticket_val.string),
        };
    }

    fn buildOpenBody(self: *DingTalkChannel) ![]u8 {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        errdefer body.deinit(self.allocator);
        const w = body.writer(self.allocator);

        try w.writeAll("{\"clientId\":");
        try root.appendJsonStringW(w, self.client_id);
        try w.writeAll(",\"clientSecret\":");
        try root.appendJsonStringW(w, self.client_secret);
        try w.writeAll(",\"subscriptions\":[");

        var wrote_any = false;
        if (!self.hasSubscription(BOT_MESSAGE_TOPIC, "CALLBACK")) {
            try appendSubscription(w, BOT_MESSAGE_TOPIC, "CALLBACK", &wrote_any);
        }
        if (self.subscribe_events and !self.hasSubscription("*", "EVENT")) {
            try appendSubscription(w, "*", "EVENT", &wrote_any);
        }
        for (self.subscriptions) |sub| {
            const sub_type = if (sub.subscription_type.len > 0) sub.subscription_type else "CALLBACK";
            try appendSubscription(w, sub.topic, sub_type, &wrote_any);
        }

        try w.writeAll("]");

        if (self.ua) |ua_val| {
            try w.writeAll(",\"ua\":");
            try root.appendJsonStringW(w, ua_val);
        }
        if (self.local_ip) |ip_val| {
            try w.writeAll(",\"localIp\":");
            try root.appendJsonStringW(w, ip_val);
        }

        try w.writeByte('}');
        return body.toOwnedSlice(self.allocator);
    }

    fn hasSubscription(self: *const DingTalkChannel, topic: []const u8, subscription_type: []const u8) bool {
        for (self.subscriptions) |sub| {
            if (std.mem.eql(u8, sub.topic, topic) and std.mem.eql(u8, sub.subscription_type, subscription_type)) {
                return true;
            }
        }
        return false;
    }

    fn appendSubscription(w: anytype, topic: []const u8, subscription_type: []const u8, wrote_any: *bool) !void {
        if (wrote_any.*) {
            try w.writeByte(',');
        }
        wrote_any.* = true;
        try w.writeAll("{\"topic\":");
        try root.appendJsonStringW(w, topic);
        try w.writeAll(",\"type\":");
        try root.appendJsonStringW(w, subscription_type);
        try w.writeByte('}');
    }

    fn parseEndpoint(endpoint: []const u8) !EndpointParts {
        const is_ws = std.mem.startsWith(u8, endpoint, "ws://");
        const is_wss = std.mem.startsWith(u8, endpoint, "wss://");
        const no_scheme = if (is_wss)
            endpoint[6..]
        else if (is_ws)
            endpoint[5..]
        else
            endpoint;

        const slash_pos = std.mem.indexOfScalar(u8, no_scheme, '/') orelse no_scheme.len;
        const host_port = no_scheme[0..slash_pos];
        const path = if (slash_pos < no_scheme.len) no_scheme[slash_pos..] else "/";

        var host = host_port;
        var port: u16 = if (is_ws) 80 else 443;
        if (std.mem.lastIndexOfScalar(u8, host_port, ':')) |idx| {
            host = host_port[0..idx];
            const port_str = host_port[idx + 1 ..];
            if (port_str.len > 0) {
                port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidEndpoint;
            }
        }
        if (host.len == 0) return error.InvalidEndpoint;
        return .{ .host = host, .port = port, .path = path };
    }

    fn buildTicketPath(allocator: std.mem.Allocator, base_path: []const u8, ticket: []const u8) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);
        const w = buf.writer(allocator);
        if (base_path.len == 0) {
            try w.writeByte('/');
        } else {
            try w.writeAll(base_path);
        }
        if (std.mem.indexOfScalar(u8, base_path, '?') != null) {
            try w.writeAll("&ticket=");
        } else {
            try w.writeAll("?ticket=");
        }
        try w.writeAll(ticket);
        return buf.toOwnedSlice(allocator);
    }

    fn handleBotMessage(self: *DingTalkChannel, data_str: []const u8) void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data_str, .{}) catch {
            log.err("DingTalk handleBotMessage failed to parse JSON", .{});
            return;
        };
        defer parsed.deinit();
        if (parsed.value != .object) {
            log.warn("DingTalk handleBotMessage parsed value is not an object", .{});
            return;
        }
        const obj = parsed.value.object;

        // Try to get real user ID from various fields
        // Priority: senderStaffId > staffId > dingtalkId > chatbotUserId > senderId
        // Note: senderStaffId, staffId, dingtalkId are real DingTalk user IDs
        //       chatbotUserId and senderId are encrypted IDs
        const staff_id = getJsonStringObj(obj, "senderStaffId") orelse 
            getJsonStringObj(obj, "staffId") orelse 
            getJsonStringObj(obj, "dingtalkId") orelse 
            getJsonStringObj(obj, "chatbotUserId") orelse 
            getJsonStringObj(obj, "senderId") orelse {
                log.warn("DingTalk handleBotMessage: no valid user ID found", .{});
                return;
            };
        
        if (!self.isUserAllowed(staff_id)) {
            log.warn("DingTalk handleBotMessage sender not allowed: {s}", .{staff_id});
            return;
        }

        const msg_type = getJsonStringObj(obj, "msgtype") orelse "";
        if (!std.mem.eql(u8, msg_type, "text")) {
            return;
        }

        const text_obj_val = obj.get("text") orelse {
            log.warn("DingTalk handleBotMessage missing text field", .{});
            return;
        };
        if (text_obj_val != .object) return;
        const text_obj = text_obj_val.object;
        const content = getJsonStringObj(text_obj, "content") orelse return;
        const trimmed = std.mem.trim(u8, content, " \t\r\n");
        if (trimmed.len == 0) return;

        if (isVerboseLog()) log.info("[DingTalk RECV] from={s} {s}", .{staff_id, trimmed});

        const session_webhook = getJsonStringObj(obj, "sessionWebhook") orelse {
            log.warn("DingTalk handleBotMessage missing sessionWebhook", .{});
            return;
        };
        if (session_webhook.len == 0) {
            log.warn("DingTalk handleBotMessage empty sessionWebhook", .{});
            return;
        }

        const conversation_type = getJsonStringObj(obj, "conversationType") orelse "";
        const is_group = std.mem.eql(u8, conversation_type, "2");
        const conversation_id = getJsonStringObj(obj, "conversationId") orelse "";
        const msg_id = getJsonStringObj(obj, "msgId") orelse "";

        const peer_kind = if (is_group) "group" else "direct";
        const peer_id = if (is_group and conversation_id.len > 0) conversation_id else staff_id;

        if (isVerboseLog()) log.info("DingTalk handleBotMessage: sending typing indicator via Bot API to user {s}", .{staff_id});
        const maybe_typing_msg_id = self.sendBotMessage(staff_id, self.typing_message);
        var typing_id_owned: ?[]const u8 = null;
        if (maybe_typing_msg_id) |typing_id| {
            typing_id_owned = typing_id;
            if (isVerboseLog()) log.info("DingTalk handleBotMessage: typing message sent successfully, ID: {s}", .{typing_id});
        } else {
            log.err("DingTalk handleBotMessage: failed to send typing message, recall will not work!", .{});
        }
        defer if (typing_id_owned) |id| self.allocator.free(id);

        var session_buf: [256]u8 = undefined;
        const session_key = std.fmt.bufPrint(&session_buf, "dingtalk:{s}:{s}:{s}", .{
            self.account_id,
            peer_kind,
            peer_id,
        }) catch return;

        var meta: std.ArrayListUnmanaged(u8) = .empty;
        defer meta.deinit(self.allocator);
        const mw = meta.writer(self.allocator);
        mw.writeAll("{\"account_id\":") catch return;
        root.appendJsonStringW(mw, self.account_id) catch return;
        mw.writeAll(",\"peer_kind\":") catch return;
        root.appendJsonStringW(mw, peer_kind) catch return;
        mw.writeAll(",\"peer_id\":") catch return;
        root.appendJsonStringW(mw, peer_id) catch return;
        mw.writeAll(",\"is_dm\":") catch return;
        mw.writeAll(if (is_group) "false" else "true") catch return;
        mw.writeAll(",\"is_group\":") catch return;
        mw.writeAll(if (is_group) "true" else "false") catch return;
        if (conversation_id.len > 0) {
            mw.writeAll(",\"channel_id\":") catch return;
            root.appendJsonStringW(mw, conversation_id) catch return;
        }
        if (msg_id.len > 0) {
            mw.writeAll(",\"message_id\":") catch return;
            root.appendJsonStringW(mw, msg_id) catch return;
        }
        if (typing_id_owned) |typing_id| {
            mw.writeAll(",\"typing_msg_id\":") catch return;
            root.appendJsonStringW(mw, typing_id) catch return;
            if (isVerboseLog()) log.info("DingTalk handleBotMessage: stored typing_msg_id={s} in metadata", .{typing_id});
        } else {
            if (isVerboseLog()) log.warn("DingTalk handleBotMessage: no typing_id to store in metadata", .{});
        }
        mw.writeAll(",\"robot_code\":") catch return;
        root.appendJsonStringW(mw, self.client_id) catch return;
        mw.writeByte('}') catch return;
        
        if (isVerboseLog()) log.info("DingTalk handleBotMessage: metadata built ({d} bytes): {s}", .{ meta.items.len, meta.items });

        const msg = bus_mod.makeInboundFull(
            self.allocator,
            "dingtalk",
            staff_id,
            session_webhook,
            trimmed,
            session_key,
            &.{},
            meta.items,
        ) catch |err| {
            log.err("DingTalk makeInbound failed: {}", .{err});
            return;
        };

        if (self.bus) |b| {
            b.publishInbound(msg) catch |err| {
                log.err("DingTalk publishInbound failed: {}", .{err});
                msg.deinit(self.allocator);
            };
        } else {
            log.err("DingTalk handleBotMessage: self.bus is null, message dropped!", .{});
            msg.deinit(self.allocator);
        }
    }

    fn buildPingData(self: *DingTalkChannel, data_str: []const u8) ?[]u8 {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data_str, .{}) catch return null;
        defer parsed.deinit();
        if (parsed.value != .object) return null;
        const obj = parsed.value.object;
        const opaque_value = getJsonStringObj(obj, "opaque") orelse "";
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);
        w.writeAll("{\"opaque\":") catch return null;
        root.appendJsonStringW(w, opaque_value) catch return null;
        w.writeByte('}') catch return null;
        return buf.toOwnedSlice(self.allocator) catch null;
    }

    fn sendAck(self: *DingTalkChannel, ws: *websocket.WsClient, message_id: []const u8, data_payload: []const u8) !void {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        const w = body.writer(self.allocator);
        try w.writeAll("{\"code\":200,\"headers\":{\"messageId\":");
        try root.appendJsonStringW(w, message_id);
        try w.writeAll(",\"contentType\":\"application/json\"},\"message\":\"OK\",\"data\":");
        try root.appendJsonStringW(w, data_payload);
        try w.writeByte('}');
        try ws.writeText(body.items);
    }

    fn getJsonStringObj(obj: anytype, key: []const u8) ?[]const u8 {
        const val = obj.get(key) orelse return null;
        if (val != .string) return null;
        return val.string;
    }

    /// Run WebSocket connection via Python subprocess (avoids Zig 0.15 TLS segfault)
    fn runPythonWsLoop(self: *DingTalkChannel, ws_url: []const u8) !void {
        const script_path = "/tmp/dingtalk_ws.py";
        {
            const script_file = try std.fs.cwd().createFile(script_path, .{ .truncate = true });
            defer script_file.close();
            try script_file.writeAll(PYTHON_WS_SCRIPT);
        }
        defer std.fs.cwd().deleteFile(script_path) catch {};

        const argv = &[_][]const u8{ "python3", script_path, ws_url };
        var child = std.process.Child.init(argv, self.allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Inherit;

        try child.spawn();
        errdefer {
            _ = child.kill() catch {};
        }

        const stdout = child.stdout.?;

        // Wait for CONNECTED signal
        var conn_buf: [256]u8 = undefined;
        var conn_offset: usize = 0;
        var connected = false;
        const start_time = std.time.milliTimestamp();
        while (std.time.milliTimestamp() - start_time < 10000) {
            const n = stdout.read(conn_buf[conn_offset..]) catch break;
            if (n == 0) break;
            conn_offset += n;
            if (std.mem.indexOf(u8, conn_buf[0..conn_offset], "CONNECTED")) |_| {
                connected = true;
                break;
            }
            if (std.mem.indexOf(u8, conn_buf[0..conn_offset], "READY")) |_| {
                connected = true;
                break;
            }
        }
        if (!connected) {
            log.err("DingTalk Python WebSocket failed to connect, stdout: {s}", .{conn_buf[0..conn_offset]});
            _ = child.kill() catch {};
            return error.WebSocketConnectFailed;
        }
        log.info("DingTalk WebSocket connected via Python, waiting for messages...", .{});

        // Find the position of the connection signal in conn_buf
        var signal_end: usize = 0;
        if (std.mem.indexOf(u8, conn_buf[0..conn_offset], "CONNECTED")) |pos| {
            signal_end = pos + "CONNECTED".len;
        } else if (std.mem.indexOf(u8, conn_buf[0..conn_offset], "READY")) |pos| {
            signal_end = pos + "READY".len;
        }
        // Append any data after the signal to line_buf
        var line_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer line_buf.deinit(self.allocator);
        if (signal_end < conn_offset) {
            try line_buf.appendSlice(self.allocator, conn_buf[signal_end..conn_offset]);
        }

        // Set non-blocking mode for stdout
        if (builtin.os.tag == .linux) {
            const stdout_flags = std.posix.fcntl(stdout.handle, std.posix.F.GETFL, 0) catch 0;
            _ = std.posix.fcntl(stdout.handle, std.posix.F.SETFL, stdout_flags | 0o4000) catch {};
        }

        var read_buf: [8192]u8 = undefined;

        while (self.running.load(.acquire)) {
            const n = stdout.read(&read_buf) catch |err| switch (err) {
                error.WouldBlock => {
                    std.Thread.sleep(10 * std.time.ns_per_ms);
                    continue;
                },
                else => return err,
            };

            if (n == 0) {
                log.info("DingTalk WebSocket (Python) closed", .{});
                return error.ConnectionClosed;
            }

            try line_buf.appendSlice(self.allocator, read_buf[0..n]);

            while (true) {
                const newline_idx = std.mem.indexOfScalar(u8, line_buf.items, '\n');
                if (newline_idx == null) break;

                const line = std.mem.trimRight(u8, line_buf.items[0..newline_idx.?], "\r");
                if (line.len > 0) {
                    // Skip log lines from Python script
                    if (std.mem.startsWith(u8, line, "RX:") or
                        std.mem.startsWith(u8, line, "ACK") or
                        std.mem.startsWith(u8, line, "CONNECTED") or
                        std.mem.startsWith(u8, line, "READY") or
                        std.mem.startsWith(u8, line, "ERR:") or
                        std.mem.startsWith(u8, line, "CONNECT_ERROR:") or
                        std.mem.startsWith(u8, line, "CONNECT_TRACE:"))
                    {
                        // log line, ignore
                    } else {
                        if (!self.handleWsMessage(line, null)) {
                            return error.ConnectionClosed;
                        }
                    }
                }

                const remove_len = newline_idx.? + 1;
                std.mem.copyForwards(u8, line_buf.items[0..], line_buf.items[remove_len..]);
                line_buf.items.len -= remove_len;
            }
        }
    }

    /// Run WebSocket connection using native Zig implementation
    fn runNativeWsLoop(self: *DingTalkChannel, host: []const u8, port: u16, path: []const u8) !void {
        var ws = try websocket.WsClient.connect(self.allocator, host, port, path, &.{});
        defer ws.deinit();

        log.info("DingTalk native WebSocket connected, waiting for messages...", .{});

        while (self.running.load(.acquire)) {
            const message = ws.readTextMessage() catch |err| {
                log.warn("DingTalk native WS read error: {}", .{err});
                return err;
            };

            if (message == null) {
                log.info("DingTalk native WebSocket closed by server", .{});
                return error.ConnectionClosed;
            }
            const msg = message.?;
            defer self.allocator.free(msg);

            if (!self.handleWsMessage(msg, &ws)) {
                return error.ConnectionClosed;
            }
        }
    }

    /// Handle a message from WebSocket
    fn handleWsMessage(self: *DingTalkChannel, text: []const u8, ws: ?*websocket.WsClient) bool {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, text, .{}) catch {
            log.warn("DingTalk failed to parse message as JSON", .{});
            return true;
        };
        defer parsed.deinit();

        if (parsed.value != .object) {
            log.warn("DingTalk message is not an object", .{});
            return true;
        }

        const msg_obj = parsed.value.object;

        const type_val = msg_obj.get("type") orelse {
            log.warn("DingTalk message has no 'type' field", .{});
            return true;
        };
        if (type_val != .string) return true;
        const msg_type = type_val.string;

        const headers_val = msg_obj.get("headers");
        if (headers_val == null) {
            log.warn("DingTalk message has no 'headers' field", .{});
            return true;
        }
        if (headers_val.? != .object) return true;
        const headers = headers_val.?.object;
        const message_id = getJsonStringObj(headers, "messageId") orelse "";
        const topic = getJsonStringObj(headers, "topic") orelse "";

        const data_val = msg_obj.get("data") orelse return true;
        const data_str: []const u8 = if (data_val == .string) data_val.string else "";

        // Send ACK if we have a WebSocket connection
        if (ws) |w| {
            if (std.mem.eql(u8, msg_type, "SYSTEM")) {
                if (std.mem.eql(u8, topic, "ping")) {
                    const ping_data = self.buildPingData(data_str);
                    const data_payload = ping_data orelse "{\"opaque\":\"\"}";
                    defer if (ping_data) |pd| self.allocator.free(pd);
                    _ = self.sendAck(w, message_id, data_payload) catch {};
                } else {
                    _ = self.sendAck(w, message_id, "{\"response\":null}") catch {};
                }
            } else if (std.mem.eql(u8, msg_type, "EVENT")) {
                _ = self.sendAck(w, message_id, "{\"status\":\"SUCCESS\",\"message\":\"success\"}") catch {};
            } else if (std.mem.eql(u8, msg_type, "CALLBACK")) {
                _ = self.sendAck(w, message_id, "{\"response\":null}") catch {};
            }
        }

        if (std.mem.eql(u8, msg_type, "SYSTEM")) {
            if (std.mem.eql(u8, topic, "disconnect")) {
                return false;
            }
            return true;
        }

        if (std.mem.eql(u8, msg_type, "EVENT")) {
            return true;
        }

        if (std.mem.eql(u8, msg_type, "CALLBACK")) {
            if (std.mem.eql(u8, topic, BOT_MESSAGE_TOPIC)) {
                self.handleBotMessage(data_str);
            }
        }
        return true;
    }
};

test "dingtalk parseEndpoint" {
    const parts = try DingTalkChannel.parseEndpoint("wss://wss-open-connection.dingtalk.com:443/connect");
    try std.testing.expectEqualStrings("wss-open-connection.dingtalk.com", parts.host);
    try std.testing.expectEqual(@as(u16, 443), parts.port);
    try std.testing.expectEqualStrings("/connect", parts.path);
}

test "dingtalk buildTicketPath appends ticket" {
    const alloc = std.testing.allocator;
    const path = try DingTalkChannel.buildTicketPath(alloc, "/connect", "abc");
    defer alloc.free(path);
    try std.testing.expectEqualStrings("/connect?ticket=abc", path);
}
