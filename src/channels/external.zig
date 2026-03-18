//! External channel host.
//!
//! Community channel extensions run out-of-process as child processes that
//! speak line-delimited JSON-RPC over stdio.

const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const bus_mod = @import("../bus.zig");
const json_util = @import("../json_util.zig");
const external_protocol = @import("external_protocol.zig");
const stdio_jsonrpc = @import("stdio_jsonrpc.zig");

const log = std.log.scoped(.external_channel);

const HEALTH_CHECK_TIMEOUT_MS: u32 = 2_000;
const CONTROL_REQUEST_TIMEOUT_MS: u32 = 10_000;
const SEND_REQUEST_TIMEOUT_MS: u32 = 30_000;
const INBOUND_PUBLISH_TIMEOUT_MS: u32 = 5_000;
const HEALTH_CHECK_CACHE_TTL_NS: i64 = 5 * std.time.ns_per_s;

pub const ExternalChannel = struct {
    allocator: std.mem.Allocator,
    config: config_types.ExternalChannelConfig,
    event_bus: ?*bus_mod.Bus = null,
    lifecycle_mutex: std.Thread.Mutex = .{},
    rpc: stdio_jsonrpc.StdioJsonRpc,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    health_rpc_mode: std.atomic.Value(i8) = std.atomic.Value(i8).init(HEALTH_RPC_UNKNOWN),
    streaming_supported: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    send_rich_rpc_mode: std.atomic.Value(i8) = std.atomic.Value(i8).init(RPC_UNKNOWN),
    typing_rpc_mode: std.atomic.Value(i8) = std.atomic.Value(i8).init(RPC_UNKNOWN),
    edit_rpc_mode: std.atomic.Value(i8) = std.atomic.Value(i8).init(RPC_UNKNOWN),
    delete_rpc_mode: std.atomic.Value(i8) = std.atomic.Value(i8).init(RPC_UNKNOWN),
    reactions_rpc_mode: std.atomic.Value(i8) = std.atomic.Value(i8).init(RPC_UNKNOWN),
    read_receipts_rpc_mode: std.atomic.Value(i8) = std.atomic.Value(i8).init(RPC_UNKNOWN),
    last_health_probe_ns: i64 = 0,
    last_health_result: bool = false,

    const Self = @This();
    const RPC_UNKNOWN: i8 = 0;
    const RPC_SUPPORTED: i8 = 1;
    const RPC_UNSUPPORTED: i8 = -1;
    const HEALTH_RPC_UNKNOWN: i8 = 0;
    const HEALTH_RPC_SUPPORTED: i8 = 1;
    const HEALTH_RPC_UNSUPPORTED: i8 = -1;

    pub const Error = error{
        InvalidConfiguration,
        ExternalChannelNotRunning,
        InboundPublishTimeout,
    } || stdio_jsonrpc.StdioJsonRpc.Error || external_protocol.Error;

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.ExternalChannelConfig) Self {
        return .{
            .allocator = allocator,
            .config = cfg,
            .rpc = stdio_jsonrpc.StdioJsonRpc.init(allocator),
        };
    }

    pub fn setBus(self: *Self, event_bus: *bus_mod.Bus) void {
        self.event_bus = event_bus;
    }

    pub fn channel(self: *Self) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn start(self: *Self) !void {
        self.lifecycle_mutex.lock();
        defer self.lifecycle_mutex.unlock();
        try self.startLocked();
    }

    fn stop(self: *Self) void {
        self.lifecycle_mutex.lock();
        defer self.lifecycle_mutex.unlock();
        self.stopLocked(true);
    }

    fn send(self: *Self, target: []const u8, message: []const u8, media: []const []const u8) !void {
        self.lifecycle_mutex.lock();
        defer self.lifecycle_mutex.unlock();
        try self.sendLocked(target, message, media, .final);
    }

    fn sendEvent(self: *Self, target: []const u8, message: []const u8, media: []const []const u8, stage: root.Channel.OutboundStage) !void {
        self.lifecycle_mutex.lock();
        defer self.lifecycle_mutex.unlock();
        try self.sendLocked(target, message, media, stage);
    }

    fn sendRich(self: *Self, target: []const u8, payload: root.Channel.OutboundPayload) !void {
        self.lifecycle_mutex.lock();
        defer self.lifecycle_mutex.unlock();
        try self.sendRichLocked(target, payload);
    }

    fn sendTracked(self: *Self, target: []const u8, message: []const u8) !?root.Channel.MessageRef {
        self.lifecycle_mutex.lock();
        defer self.lifecycle_mutex.unlock();
        return self.sendTrackedLocked(target, message);
    }

    fn healthCheck(self: *Self) bool {
        self.lifecycle_mutex.lock();
        defer self.lifecycle_mutex.unlock();
        return self.healthCheckLocked();
    }

    fn startTyping(self: *Self, recipient: []const u8) !void {
        self.lifecycle_mutex.lock();
        defer self.lifecycle_mutex.unlock();
        try self.typingRpcLocked("start_typing", recipient);
    }

    fn stopTyping(self: *Self, recipient: []const u8) !void {
        self.lifecycle_mutex.lock();
        defer self.lifecycle_mutex.unlock();
        try self.typingRpcLocked("stop_typing", recipient);
    }

    fn editMessage(self: *Self, edit: root.Channel.MessageEdit) !void {
        self.lifecycle_mutex.lock();
        defer self.lifecycle_mutex.unlock();
        try self.editMessageLocked(edit);
    }

    fn deleteMessage(self: *Self, message_ref: root.Channel.MessageRef) !void {
        self.lifecycle_mutex.lock();
        defer self.lifecycle_mutex.unlock();
        try self.deleteMessageLocked(message_ref);
    }

    fn setReaction(self: *Self, update: root.Channel.ReactionUpdate) !void {
        self.lifecycle_mutex.lock();
        defer self.lifecycle_mutex.unlock();
        try self.setReactionLocked(update);
    }

    fn markRead(self: *Self, message_ref: root.Channel.MessageRef) !void {
        self.lifecycle_mutex.lock();
        defer self.lifecycle_mutex.unlock();
        try self.markReadLocked(message_ref);
    }

    fn startLocked(self: *Self) !void {
        if (self.running.load(.acquire)) return;
        if (!config_types.ExternalChannelConfig.isValidRuntimeName(self.config.runtime_name)) {
            return Error.InvalidConfiguration;
        }
        if (!config_types.ExternalChannelConfig.hasCommand(self.config.transport.command)) {
            return Error.InvalidConfiguration;
        }
        if (!config_types.ExternalChannelConfig.isValidTimeoutMs(self.config.transport.timeout_ms)) {
            return Error.InvalidConfiguration;
        }

        var process_env: []const stdio_jsonrpc.ProcessEnvEntry = &.{};
        if (self.config.transport.env.len > 0) {
            const env_entries = try self.allocator.alloc(stdio_jsonrpc.ProcessEnvEntry, self.config.transport.env.len);
            defer self.allocator.free(env_entries);
            for (self.config.transport.env, 0..) |entry, index| {
                env_entries[index] = .{
                    .key = entry.key,
                    .value = entry.value,
                };
            }
            process_env = env_entries;
        }

        try self.rpc.start(.{
            .command = self.config.transport.command,
            .args = self.config.transport.args,
            .env = process_env,
        }, self, handleNotification);
        errdefer self.stopLocked(false);

        self.health_rpc_mode.store(HEALTH_RPC_UNKNOWN, .release);
        self.streaming_supported.store(false, .release);
        self.send_rich_rpc_mode.store(RPC_UNKNOWN, .release);
        self.typing_rpc_mode.store(RPC_UNKNOWN, .release);
        self.edit_rpc_mode.store(RPC_UNKNOWN, .release);
        self.delete_rpc_mode.store(RPC_UNKNOWN, .release);
        self.reactions_rpc_mode.store(RPC_UNKNOWN, .release);
        self.read_receipts_rpc_mode.store(RPC_UNKNOWN, .release);
        self.last_health_probe_ns = 0;
        self.last_health_result = false;

        const manifest_response = try self.rpc.request("get_manifest", "{}", self.controlRequestTimeoutMs());
        defer self.allocator.free(manifest_response);
        const manifest = try external_protocol.parseManifestResponse(self.allocator, manifest_response);
        self.health_rpc_mode.store(if (manifest.health_supported orelse false) HEALTH_RPC_SUPPORTED else HEALTH_RPC_UNSUPPORTED, .release);
        self.streaming_supported.store(manifest.streaming_supported orelse false, .release);
        self.send_rich_rpc_mode.store(if (manifest.send_rich_supported orelse false) RPC_SUPPORTED else RPC_UNSUPPORTED, .release);
        self.typing_rpc_mode.store(if (manifest.typing_supported orelse false) RPC_SUPPORTED else RPC_UNSUPPORTED, .release);
        self.edit_rpc_mode.store(if (manifest.edit_supported orelse false) RPC_SUPPORTED else RPC_UNSUPPORTED, .release);
        self.delete_rpc_mode.store(if (manifest.delete_supported orelse false) RPC_SUPPORTED else RPC_UNSUPPORTED, .release);
        self.reactions_rpc_mode.store(if (manifest.reactions_supported orelse false) RPC_SUPPORTED else RPC_UNSUPPORTED, .release);
        self.read_receipts_rpc_mode.store(if (manifest.read_receipts_supported orelse false) RPC_SUPPORTED else RPC_UNSUPPORTED, .release);

        const start_params = try external_protocol.buildStartParams(self.allocator, self.config);
        defer self.allocator.free(start_params);
        const start_response = try self.rpc.request("start", start_params, self.controlRequestTimeoutMs());
        defer self.allocator.free(start_response);
        try external_protocol.validateStartedResponse(self.allocator, start_response);

        self.running.store(true, .release);
    }

    fn stopLocked(self: *Self, notify_plugin: bool) void {
        if (notify_plugin and self.rpc.hasChild()) {
            const stop_response = self.rpc.request("stop", "{}", self.controlRequestTimeoutMs()) catch null;
            if (stop_response) |response| self.allocator.free(response);
        }

        self.running.store(false, .release);
        self.rpc.stop();
        self.health_rpc_mode.store(HEALTH_RPC_UNKNOWN, .release);
        self.streaming_supported.store(false, .release);
        self.send_rich_rpc_mode.store(RPC_UNKNOWN, .release);
        self.typing_rpc_mode.store(RPC_UNKNOWN, .release);
        self.edit_rpc_mode.store(RPC_UNKNOWN, .release);
        self.delete_rpc_mode.store(RPC_UNKNOWN, .release);
        self.reactions_rpc_mode.store(RPC_UNKNOWN, .release);
        self.read_receipts_rpc_mode.store(RPC_UNKNOWN, .release);
        self.last_health_probe_ns = 0;
        self.last_health_result = false;
    }

    fn sendLocked(self: *Self, target: []const u8, message: []const u8, media: []const []const u8, stage: root.Channel.OutboundStage) !void {
        if (!self.running.load(.acquire) or !self.rpc.hasChild()) {
            return Error.ExternalChannelNotRunning;
        }

        const params = try external_protocol.buildSendParams(self.allocator, self.config, target, message, media, stage);
        defer self.allocator.free(params);

        const response = try self.rpc.request("send", params, self.sendRequestTimeoutMs());
        defer self.allocator.free(response);
        try external_protocol.validateAcceptedResponse(self.allocator, response);
    }

    fn sendRichLocked(self: *Self, target: []const u8, payload: root.Channel.OutboundPayload) !void {
        const params = try external_protocol.buildSendRichParams(self.allocator, self.config, target, payload);
        defer self.allocator.free(params);

        self.requestAcceptedOptionalRpcLocked("send_rich", params, &self.send_rich_rpc_mode, self.sendRequestTimeoutMs()) catch |err| switch (err) {
            error.NotSupported => {
                return self.sendRichFallbackLocked(target, payload);
            },
            else => return err,
        };
    }

    fn sendRichFallbackLocked(self: *Self, target: []const u8, payload: root.Channel.OutboundPayload) !void {
        if (payload.attachments.len == 0 and payload.choices.len == 0) {
            return self.sendLocked(target, payload.text, &.{}, .final);
        }
        return error.NotSupported;
    }

    fn sendTrackedLocked(self: *Self, target: []const u8, message: []const u8) !?root.Channel.MessageRef {
        if (!self.running.load(.acquire) or !self.rpc.hasChild()) {
            return Error.ExternalChannelNotRunning;
        }

        const params = try external_protocol.buildSendParams(self.allocator, self.config, target, message, &.{}, .final);
        defer self.allocator.free(params);

        const response = try self.rpc.request("send", params, self.sendRequestTimeoutMs());
        defer self.allocator.free(response);
        return (try external_protocol.parseAcceptedMessageRef(self.allocator, response, target)) orelse
            external_protocol.Error.InvalidPluginResponse;
    }

    fn healthCheckLocked(self: *Self) bool {
        if (!self.running.load(.acquire) or !self.rpc.hasChild() or !self.rpc.isReaderAlive()) {
            self.last_health_probe_ns = 0;
            self.last_health_result = false;
            return false;
        }

        if (self.health_rpc_mode.load(.acquire) == HEALTH_RPC_UNSUPPORTED) {
            return true;
        }

        const now_ns: i64 = @intCast(std.time.nanoTimestamp());
        if (self.last_health_probe_ns != 0 and (now_ns - self.last_health_probe_ns) < HEALTH_CHECK_CACHE_TTL_NS) {
            return self.last_health_result;
        }

        const timeout_ms = @min(self.config.transport.timeout_ms, HEALTH_CHECK_TIMEOUT_MS);
        const response = self.rpc.request("health", "{}", timeout_ms) catch |err| switch (err) {
            else => {
                self.last_health_probe_ns = now_ns;
                self.last_health_result = false;
                return false;
            },
        };
        defer self.allocator.free(response);

        const healthy = external_protocol.parseHealthResponse(self.allocator, response) catch |err| switch (err) {
            error.HealthMethodNotSupported => {
                self.health_rpc_mode.store(HEALTH_RPC_UNSUPPORTED, .release);
                self.last_health_probe_ns = now_ns;
                self.last_health_result = true;
                return true;
            },
            else => {
                self.last_health_probe_ns = now_ns;
                self.last_health_result = false;
                return false;
            },
        };
        self.health_rpc_mode.store(HEALTH_RPC_SUPPORTED, .release);
        self.last_health_probe_ns = now_ns;
        self.last_health_result = healthy;
        return healthy;
    }

    fn controlRequestTimeoutMs(self: *const Self) u32 {
        return @min(self.config.transport.timeout_ms, CONTROL_REQUEST_TIMEOUT_MS);
    }

    fn sendRequestTimeoutMs(self: *const Self) u32 {
        return @min(self.config.transport.timeout_ms, SEND_REQUEST_TIMEOUT_MS);
    }

    fn requestAcceptedOptionalRpcLocked(
        self: *Self,
        method: []const u8,
        params: []const u8,
        rpc_mode: *std.atomic.Value(i8),
        timeout_ms: u32,
    ) !void {
        if (!self.running.load(.acquire) or !self.rpc.hasChild()) {
            return Error.ExternalChannelNotRunning;
        }
        if (rpc_mode.load(.acquire) == RPC_UNSUPPORTED) {
            return error.NotSupported;
        }

        const response = try self.rpc.request(method, params, timeout_ms);
        defer self.allocator.free(response);

        external_protocol.validateAcceptedResponse(self.allocator, response) catch |err| switch (err) {
            error.MethodNotSupported => {
                rpc_mode.store(RPC_UNSUPPORTED, .release);
                return error.NotSupported;
            },
            else => return err,
        };
        rpc_mode.store(RPC_SUPPORTED, .release);
    }

    fn typingRpcLocked(self: *Self, method: []const u8, recipient: []const u8) !void {
        const params = try external_protocol.buildTypingParams(self.allocator, self.config, recipient);
        defer self.allocator.free(params);

        self.requestAcceptedOptionalRpcLocked(method, params, &self.typing_rpc_mode, self.controlRequestTimeoutMs()) catch |err| switch (err) {
            error.NotSupported => {
                return;
            },
            else => return err,
        };
    }

    fn editMessageLocked(self: *Self, edit: root.Channel.MessageEdit) !void {
        const params = try external_protocol.buildEditMessageParams(self.allocator, self.config, edit);
        defer self.allocator.free(params);
        try self.requestAcceptedOptionalRpcLocked("edit_message", params, &self.edit_rpc_mode, self.sendRequestTimeoutMs());
    }

    fn deleteMessageLocked(self: *Self, message_ref: root.Channel.MessageRef) !void {
        const params = try external_protocol.buildDeleteMessageParams(self.allocator, self.config, message_ref);
        defer self.allocator.free(params);
        try self.requestAcceptedOptionalRpcLocked("delete_message", params, &self.delete_rpc_mode, self.sendRequestTimeoutMs());
    }

    fn setReactionLocked(self: *Self, update: root.Channel.ReactionUpdate) !void {
        const params = try external_protocol.buildSetReactionParams(self.allocator, self.config, update);
        defer self.allocator.free(params);
        try self.requestAcceptedOptionalRpcLocked("set_reaction", params, &self.reactions_rpc_mode, self.sendRequestTimeoutMs());
    }

    fn markReadLocked(self: *Self, message_ref: root.Channel.MessageRef) !void {
        const params = try external_protocol.buildMarkReadParams(self.allocator, self.config, message_ref);
        defer self.allocator.free(params);
        try self.requestAcceptedOptionalRpcLocked("mark_read", params, &self.read_receipts_rpc_mode, self.sendRequestTimeoutMs());
    }

    fn handleNotification(ctx: *anyopaque, method: []const u8, params: std.json.Value) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        if (!std.mem.eql(u8, method, "inbound_message")) return;
        try self.handleInboundMessage(params);
    }

    fn handleInboundMessage(self: *Self, params: std.json.Value) !void {
        const event_bus = self.event_bus orelse {
            log.warn("external channel '{s}' dropped inbound message because no bus is attached", .{self.config.runtime_name});
            return;
        };

        const inbound = try external_protocol.parseInboundMessageParams(self.allocator, params);
        defer if (inbound.media.len > 0) self.allocator.free(inbound.media);

        var derived_session_key: ?[]u8 = null;
        defer if (derived_session_key) |owned| self.allocator.free(owned);
        const session_key = if (inbound.session_key) |provided|
            provided
        else blk: {
            derived_session_key = try self.deriveFallbackSessionKey(inbound);
            break :blk derived_session_key.?;
        };

        const metadata_json = try self.buildInboundMetadataJson(inbound.metadata_value);
        defer self.allocator.free(metadata_json);

        const msg = try bus_mod.makeInboundFull(
            self.allocator,
            self.config.runtime_name,
            inbound.sender_id,
            inbound.chat_id,
            inbound.content,
            session_key,
            inbound.media,
            metadata_json,
        );

        event_bus.publishInboundTimeout(msg, INBOUND_PUBLISH_TIMEOUT_MS) catch |err| {
            var owned_msg = msg;
            owned_msg.deinit(self.allocator);
            switch (err) {
                error.Closed => return,
                error.Timeout => return Error.InboundPublishTimeout,
            }
        };
    }

    fn deriveFallbackSessionKey(self: *Self, inbound: external_protocol.InboundMessage) ![]u8 {
        if (inbound.metadata_value) |metadata| {
            if (metadata == .object) {
                const peer_kind_value = metadata.object.get("peer_kind");
                const peer_id_value = metadata.object.get("peer_id");
                if (peer_kind_value != null and peer_kind_value.? == .string and
                    peer_id_value != null and peer_id_value.? == .string and
                    peer_id_value.?.string.len > 0)
                {
                    return std.fmt.allocPrint(self.allocator, "{s}:{s}:{s}:{s}", .{
                        self.config.runtime_name,
                        self.config.account_id,
                        peer_kind_value.?.string,
                        peer_id_value.?.string,
                    });
                }
            }
        }

        return std.fmt.allocPrint(self.allocator, "{s}:{s}:{s}", .{
            self.config.runtime_name,
            self.config.account_id,
            inbound.chat_id,
        });
    }

    fn buildInboundMetadataJson(self: *Self, metadata_value: ?std.json.Value) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "{\"account_id\":");
        try appendJsonString(&buf, self.allocator, self.config.account_id);

        if (metadata_value) |metadata| {
            if (metadata == .object) {
                var it = metadata.object.iterator();
                while (it.next()) |entry| {
                    if (std.mem.eql(u8, entry.key_ptr.*, "account_id")) continue;
                    const value_json = try std.json.Stringify.valueAlloc(self.allocator, entry.value_ptr.*, .{});
                    defer self.allocator.free(value_json);

                    try buf.append(self.allocator, ',');
                    try appendJsonString(&buf, self.allocator, entry.key_ptr.*);
                    try buf.append(self.allocator, ':');
                    try buf.appendSlice(self.allocator, value_json);
                }
            }
        }

        try buf.append(self.allocator, '}');
        return try buf.toOwnedSlice(self.allocator);
    }

    fn channelName(self: *Self) []const u8 {
        return self.config.runtime_name;
    }

    fn supportsStreamingOutbound(self: *Self) bool {
        return self.streaming_supported.load(.acquire);
    }

    fn supportsTrackedDrafts(self: *Self) bool {
        return self.edit_rpc_mode.load(.acquire) == RPC_SUPPORTED and
            self.delete_rpc_mode.load(.acquire) == RPC_SUPPORTED;
    }

    fn appendJsonString(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, value: []const u8) !void {
        try json_util.appendJsonString(buf, allocator, value);
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.start();
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.stop();
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, media: []const []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.send(target, message, media);
    }

    fn vtableSendEvent(ptr: *anyopaque, target: []const u8, message: []const u8, media: []const []const u8, stage: root.Channel.OutboundStage) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.sendEvent(target, message, media, stage);
    }

    fn vtableSendRich(ptr: *anyopaque, target: []const u8, payload: root.Channel.OutboundPayload) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.sendRich(target, payload);
    }

    fn vtableSendTracked(ptr: *anyopaque, target: []const u8, message: []const u8) anyerror!?root.Channel.MessageRef {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.sendTracked(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    fn vtableStartTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.startTyping(recipient);
    }

    fn vtableStopTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.stopTyping(recipient);
    }

    fn vtableEditMessage(ptr: *anyopaque, edit: root.Channel.MessageEdit) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.editMessage(edit);
    }

    fn vtableDeleteMessage(ptr: *anyopaque, message_ref: root.Channel.MessageRef) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.deleteMessage(message_ref);
    }

    fn vtableSetReaction(ptr: *anyopaque, update: root.Channel.ReactionUpdate) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.setReaction(update);
    }

    fn vtableMarkRead(ptr: *anyopaque, message_ref: root.Channel.MessageRef) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.markRead(message_ref);
    }

    fn vtableSupportsStreamingOutbound(ptr: *anyopaque) bool {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.supportsStreamingOutbound();
    }

    fn vtableSupportsTrackedDrafts(ptr: *anyopaque) bool {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.supportsTrackedDrafts();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
        .sendEvent = &vtableSendEvent,
        .sendRich = &vtableSendRich,
        .sendTracked = &vtableSendTracked,
        .startTyping = &vtableStartTyping,
        .stopTyping = &vtableStopTyping,
        .editMessage = &vtableEditMessage,
        .deleteMessage = &vtableDeleteMessage,
        .setReaction = &vtableSetReaction,
        .markRead = &vtableMarkRead,
        .supportsStreamingOutbound = &vtableSupportsStreamingOutbound,
        .supportsTrackedDrafts = &vtableSupportsTrackedDrafts,
    };
};

test "buildInboundMetadataJson injects account_id and preserves metadata fields" {
    const allocator = std.testing.allocator;
    var channel = ExternalChannel.initFromConfig(allocator, .{
        .account_id = "backup",
        .runtime_name = "plugin-chat",
        .transport = .{ .command = "plugin" },
    });

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"peer_kind\":\"group\",\"peer_id\":\"room-1\"}", .{});
    defer parsed.deinit();

    const metadata_json = try channel.buildInboundMetadataJson(parsed.value);
    defer allocator.free(metadata_json);

    try std.testing.expect(std.mem.indexOf(u8, metadata_json, "\"account_id\":\"backup\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, metadata_json, "\"peer_kind\":\"group\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, metadata_json, "\"peer_id\":\"room-1\"") != null);
}

test "handleInboundMessage publishes nested notification to bus with injected account id" {
    const allocator = std.testing.allocator;

    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var channel = ExternalChannel.initFromConfig(allocator, .{
        .account_id = "main",
        .runtime_name = "whatsapp_web",
        .transport = .{ .command = "plugin" },
    });
    channel.setBus(&event_bus);

    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        "{\"message\":{\"sender_id\":\"5511\",\"chat_id\":\"room-1\",\"text\":\"hello\",\"metadata\":{\"peer_kind\":\"group\",\"peer_id\":\"room-1\"}}}",
        .{},
    );
    defer parsed.deinit();

    try channel.handleInboundMessage(parsed.value);

    const msg = event_bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer {
        var owned = msg;
        owned.deinit(allocator);
    }

    try std.testing.expectEqualStrings("whatsapp_web", msg.channel);
    try std.testing.expectEqualStrings("5511", msg.sender_id);
    try std.testing.expectEqualStrings("room-1", msg.chat_id);
    try std.testing.expectEqualStrings("hello", msg.content);
    try std.testing.expectEqualStrings("whatsapp_web:main:group:room-1", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"account_id\":\"main\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"peer_kind\":\"group\"") != null);
}
