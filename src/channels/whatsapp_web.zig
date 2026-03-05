const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const bus = @import("../bus.zig");

const log = std.log.scoped(.whatsapp_web);
const CURSOR_STORE_VERSION: i64 = 1;

const HttpGetFn = *const fn (
    allocator: std.mem.Allocator,
    url: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
) anyerror![]u8;

const HttpPostFn = *const fn (
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
) anyerror![]u8;

/// WhatsApp Web channel backed by a local sidecar bridge.
///
/// Bridge contract:
/// - POST `{bridge_url}/poll` with body `{"account_id":"...","cursor":"..."?}`
/// - POST `{bridge_url}/send` with body `{"account_id":"...","to":"...","text":"..."}`
/// - optional GET `{bridge_url}/health` for operator diagnostics.
pub const WhatsAppWebChannel = struct {
    const MAX_SEEN_MESSAGE_IDS: usize = 256;
    const PublishOutcome = struct {
        published: bool,
        state_dirty: bool,
    };

    allocator: std.mem.Allocator,
    config: config_types.WhatsAppWebConfig,
    event_bus: ?*bus.Bus = null,
    running: bool = false,
    stop_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    poll_thread: ?std.Thread = null,
    cursor: ?[]u8 = null,
    seen_message_ids: std.ArrayListUnmanaged([]u8) = .empty,
    seen_message_id_index: std.StringHashMapUnmanaged(void) = .empty,
    state_root: ?[]u8 = null,

    http_get: HttpGetFn = root.http_util.curlGet,
    http_post: HttpPostFn = root.http_util.curlPost,

    pub const MAX_MESSAGE_LEN: usize = 3500;
    pub const POLL_ENDPOINT: []const u8 = "/poll";
    pub const SEND_ENDPOINT: []const u8 = "/send";
    pub const HEALTH_ENDPOINT: []const u8 = "/health";

    pub fn init(allocator: std.mem.Allocator, config: config_types.WhatsAppWebConfig) WhatsAppWebChannel {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.WhatsAppWebConfig) WhatsAppWebChannel {
        return init(allocator, cfg);
    }

    pub fn deinit(self: *WhatsAppWebChannel) void {
        vtableStop(@ptrCast(self));
        if (self.cursor) |cursor| {
            self.allocator.free(cursor);
            self.cursor = null;
        }
        self.clearSeenMessageIds();
        self.seen_message_id_index.deinit(self.allocator);
        self.seen_message_ids.deinit(self.allocator);
        if (self.state_root) |state_root| {
            self.allocator.free(state_root);
            self.state_root = null;
        }
    }

    pub fn setBus(self: *WhatsAppWebChannel, b: *bus.Bus) void {
        self.event_bus = b;
    }

    pub fn channelName(_: *WhatsAppWebChannel) []const u8 {
        return "whatsapp_web";
    }

    pub fn healthCheck(self: *WhatsAppWebChannel) bool {
        return self.running and self.poll_thread != null;
    }

    fn trimTrailingSlash(value: []const u8) []const u8 {
        var trimmed = std.mem.trim(u8, value, " \t\r\n");
        while (trimmed.len > 1 and trimmed[trimmed.len - 1] == '/') {
            trimmed = trimmed[0 .. trimmed.len - 1];
        }
        return trimmed;
    }

    fn endpointUrl(self: *const WhatsAppWebChannel, suffix: []const u8) ![]u8 {
        const base = trimTrailingSlash(self.config.bridge_url);
        if (base.len == 0) return error.InvalidConfiguration;
        return std.fmt.allocPrint(self.allocator, "{s}{s}", .{ base, suffix });
    }

    fn authHeaders(self: *const WhatsAppWebChannel, auth_buf: *[512]u8, header_slots: *[1][]const u8) []const []const u8 {
        if (self.config.api_key) |api_key| {
            header_slots[0] = std.fmt.bufPrint(auth_buf, "Authorization: Bearer {s}", .{api_key}) catch return &.{};
            return header_slots[0..1];
        }
        return &.{};
    }

    fn isSenderAllowed(self: *const WhatsAppWebChannel, sender: []const u8, is_group: bool) bool {
        if (!is_group) {
            if (self.config.allow_from.len == 0) return true;
            return root.isAllowed(self.config.allow_from, sender);
        }

        if (std.mem.eql(u8, self.config.group_policy, "disabled")) return false;
        if (std.mem.eql(u8, self.config.group_policy, "open")) return true;

        const effective_allowlist = if (self.config.group_allow_from.len > 0)
            self.config.group_allow_from
        else
            self.config.allow_from;
        if (effective_allowlist.len == 0) return false;
        return root.isAllowed(effective_allowlist, sender);
    }

    fn getObjString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
        const value = obj.get(key) orelse return null;
        if (value != .string) return null;
        if (value.string.len == 0) return null;
        return value.string;
    }

    fn getObjBool(obj: std.json.ObjectMap, key: []const u8) ?bool {
        const value = obj.get(key) orelse return null;
        if (value != .bool) return null;
        return value.bool;
    }

    fn normalizeAccountId(allocator: std.mem.Allocator, account_id: []const u8) ![]u8 {
        const trimmed = std.mem.trim(u8, account_id, " \t\r\n");
        const source = if (trimmed.len == 0) "default" else trimmed;
        var normalized = try allocator.alloc(u8, source.len);
        for (source, 0..) |c, i| {
            normalized[i] = if (std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-') c else '_';
        }
        return normalized;
    }

    fn cursorStatePath(self: *const WhatsAppWebChannel) ![]u8 {
        const state_root = self.state_root orelse return error.StateRootNotConfigured;
        const normalized_account_id = try normalizeAccountId(self.allocator, self.config.account_id);
        defer self.allocator.free(normalized_account_id);

        const file_name = try std.fmt.allocPrint(self.allocator, "cursor-{s}.json", .{normalized_account_id});
        defer self.allocator.free(file_name);

        return std.fs.path.join(self.allocator, &.{ state_root, "state", "whatsapp_web", file_name });
    }

    fn replaceCursor(self: *WhatsAppWebChannel, next_cursor: []const u8) !bool {
        if (self.cursor) |cursor| {
            if (std.mem.eql(u8, cursor, next_cursor)) return false;
            self.allocator.free(cursor);
        }
        self.cursor = try self.allocator.dupe(u8, next_cursor);
        return true;
    }

    fn clearSeenMessageIds(self: *WhatsAppWebChannel) void {
        for (self.seen_message_ids.items) |id| {
            self.allocator.free(id);
        }
        self.seen_message_ids.clearRetainingCapacity();
        self.seen_message_id_index.clearRetainingCapacity();
    }

    fn hasSeenMessageId(self: *const WhatsAppWebChannel, message_id: []const u8) bool {
        const trimmed = std.mem.trim(u8, message_id, " \t\r\n");
        if (trimmed.len == 0) return false;
        return self.seen_message_id_index.contains(trimmed);
    }

    fn rememberMessageId(self: *WhatsAppWebChannel, message_id: []const u8) !bool {
        const trimmed = std.mem.trim(u8, message_id, " \t\r\n");
        if (trimmed.len == 0) return false;
        if (self.seen_message_id_index.contains(trimmed)) return false;

        const owned = try self.allocator.dupe(u8, trimmed);
        errdefer self.allocator.free(owned);

        try self.seen_message_ids.append(self.allocator, owned);
        try self.seen_message_id_index.put(self.allocator, owned, {});

        if (self.seen_message_ids.items.len > MAX_SEEN_MESSAGE_IDS) {
            const evicted = self.seen_message_ids.orderedRemove(0);
            _ = self.seen_message_id_index.remove(evicted);
            self.allocator.free(evicted);
        }
        return true;
    }

    fn restorePersistedCursor(self: *WhatsAppWebChannel) !void {
        const path = self.cursorStatePath() catch |err| switch (err) {
            error.StateRootNotConfigured => return,
            else => return err,
        };
        defer self.allocator.free(path);

        const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 16 * 1024);
        defer self.allocator.free(content);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, content, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value != .object) return;
        const obj = parsed.value.object;

        if (obj.get("version")) |version_val| {
            if (version_val != .integer or version_val.integer != CURSOR_STORE_VERSION) return;
        }

        const account_id_val = obj.get("account_id") orelse return;
        if (account_id_val != .string) return;
        if (!std.mem.eql(u8, account_id_val.string, self.config.account_id)) return;

        const bridge_url_val = obj.get("bridge_url") orelse return;
        if (bridge_url_val != .string) return;
        if (!std.mem.eql(u8, trimTrailingSlash(bridge_url_val.string), trimTrailingSlash(self.config.bridge_url))) return;

        const cursor_val = obj.get("cursor") orelse return;
        if (cursor_val != .string or cursor_val.string.len == 0) return;
        _ = try self.replaceCursor(cursor_val.string);

        self.clearSeenMessageIds();
        if (obj.get("seen_message_ids")) |seen_val| {
            if (seen_val != .array) return;
            for (seen_val.array.items) |id_val| {
                if (id_val != .string) continue;
                _ = try self.rememberMessageId(id_val.string);
            }
        }
    }

    fn persistCursor(self: *WhatsAppWebChannel) !void {
        const cursor = self.cursor orelse return;
        const path = self.cursorStatePath() catch |err| switch (err) {
            error.StateRootNotConfigured => return,
            else => return err,
        };
        defer self.allocator.free(path);

        if (std.fs.path.dirname(path)) |dir| {
            std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => try std.fs.cwd().makePath(dir),
            };
        }

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);
        const bw = buf.writer(self.allocator);
        try bw.writeAll("{\n  \"version\": ");
        try std.fmt.format(bw, "{d}", .{CURSOR_STORE_VERSION});
        try bw.writeAll(",\n  \"account_id\": ");
        try root.appendJsonStringW(bw, self.config.account_id);
        try bw.writeAll(",\n  \"bridge_url\": ");
        try root.appendJsonStringW(bw, trimTrailingSlash(self.config.bridge_url));
        try bw.writeAll(",\n  \"cursor\": ");
        try root.appendJsonStringW(bw, cursor);
        try bw.writeAll(",\n  \"seen_message_ids\": [");
        for (self.seen_message_ids.items, 0..) |id, i| {
            if (i > 0) try bw.writeAll(", ");
            try root.appendJsonStringW(bw, id);
        }
        try bw.writeAll("]");
        try bw.writeAll("\n}\n");

        const tmp_path = try std.fmt.allocPrint(self.allocator, "{s}.tmp", .{path});
        defer self.allocator.free(tmp_path);

        {
            var tmp_file = try std.fs.createFileAbsolute(tmp_path, .{});
            defer tmp_file.close();
            try tmp_file.writeAll(buf.items);
        }

        std.fs.renameAbsolute(tmp_path, path) catch {
            std.fs.deleteFileAbsolute(tmp_path) catch {};
            const file = try std.fs.createFileAbsolute(path, .{});
            defer file.close();
            try file.writeAll(buf.items);
        };
    }

    pub fn setStateRootFromConfigPath(self: *WhatsAppWebChannel, config_path: []const u8) !void {
        const config_dir = std.fs.path.dirname(config_path) orelse ".";
        if (self.state_root) |state_root| self.allocator.free(state_root);
        self.state_root = try self.allocator.dupe(u8, config_dir);
        self.restorePersistedCursor() catch |err| {
            log.warn("failed to restore whatsapp_web cursor (account_id={s}): {}", .{ self.config.account_id, err });
        };
    }

    fn publishParsedMessage(self: *WhatsAppWebChannel, obj: std.json.ObjectMap) !PublishOutcome {
        const sender = getObjString(obj, "from") orelse return .{ .published = false, .state_dirty = false };
        const text = getObjString(obj, "text") orelse getObjString(obj, "content") orelse return .{ .published = false, .state_dirty = false };
        const cleaned_text = std.mem.trim(u8, text, " \t\r\n");
        if (cleaned_text.len == 0) return .{ .published = false, .state_dirty = false };

        const is_group = getObjBool(obj, "is_group") orelse false;
        const group_id = getObjString(obj, "group_id");
        const chat_id = getObjString(obj, "chat_id") orelse if (is_group) (group_id orelse sender) else sender;

        if (!self.isSenderAllowed(sender, is_group)) return .{ .published = false, .state_dirty = false };

        const peer_kind = if (is_group) "group" else "direct";
        const peer_id = if (is_group) (group_id orelse chat_id) else sender;
        const message_id = getObjString(obj, "id");
        if (message_id) |mid| {
            if (self.hasSeenMessageId(mid)) {
                return .{ .published = false, .state_dirty = false };
            }
        }

        const session_key = try std.fmt.allocPrint(
            self.allocator,
            "whatsapp_web:{s}:{s}:{s}",
            .{ self.config.account_id, peer_kind, peer_id },
        );
        defer self.allocator.free(session_key);

        var meta_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer meta_buf.deinit(self.allocator);
        const mw = meta_buf.writer(self.allocator);
        try mw.writeAll("{\"account_id\":");
        try root.appendJsonStringW(mw, self.config.account_id);
        try mw.writeAll(",\"is_group\":");
        try mw.writeAll(if (is_group) "true" else "false");
        try mw.writeAll(",\"peer_kind\":");
        try root.appendJsonStringW(mw, peer_kind);
        try mw.writeAll(",\"peer_id\":");
        try root.appendJsonStringW(mw, peer_id);
        if (message_id) |mid| {
            try mw.writeAll(",\"message_id\":");
            try root.appendJsonStringW(mw, mid);
        }
        try mw.writeByte('}');

        const inbound = try bus.makeInboundFull(
            self.allocator,
            "whatsapp_web",
            sender,
            chat_id,
            cleaned_text,
            session_key,
            &.{},
            meta_buf.items,
        );

        if (self.event_bus) |eb| {
            eb.publishInbound(inbound) catch |err| {
                inbound.deinit(self.allocator);
                if (err != error.Closed) {
                    log.warn("failed to publish whatsapp_web inbound: {}", .{err});
                }
                return .{ .published = false, .state_dirty = false };
            };
            var state_dirty = false;
            if (message_id) |mid| {
                state_dirty = try self.rememberMessageId(mid);
            }
            return .{ .published = true, .state_dirty = state_dirty };
        }

        inbound.deinit(self.allocator);
        return .{ .published = false, .state_dirty = false };
    }

    /// Parse bridge poll payload and publish all accepted messages to the bus.
    pub fn ingestPollPayload(self: *WhatsAppWebChannel, payload: []const u8) !usize {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return 0;
        defer parsed.deinit();
        if (parsed.value != .object) return 0;
        const root_obj = parsed.value.object;
        var state_dirty = false;

        if (getObjString(root_obj, "next_cursor")) |next_cursor| {
            if (try self.replaceCursor(next_cursor)) {
                state_dirty = true;
            }
        }

        const messages_val = root_obj.get("messages") orelse return 0;
        if (messages_val != .array) return 0;

        var published: usize = 0;
        for (messages_val.array.items) |item| {
            if (item != .object) continue;
            const outcome = try self.publishParsedMessage(item.object);
            if (outcome.published) {
                published += 1;
            }
            if (outcome.state_dirty) state_dirty = true;
        }

        if (state_dirty) {
            self.persistCursor() catch |err| {
                log.warn("failed to persist whatsapp_web cursor (account_id={s}): {}", .{ self.config.account_id, err });
            };
        }
        return published;
    }

    /// Fetch one poll batch from the sidecar and forward accepted messages.
    pub fn pollOnce(self: *WhatsAppWebChannel) !usize {
        const url = try self.endpointUrl(POLL_ENDPOINT);
        defer self.allocator.free(url);

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        const bw = body.writer(self.allocator);
        try bw.writeAll("{\"account_id\":");
        try root.appendJsonStringW(bw, self.config.account_id);
        if (self.cursor) |cursor| {
            try bw.writeAll(",\"cursor\":");
            try root.appendJsonStringW(bw, cursor);
        }
        try bw.writeByte('}');

        var auth_buf: [512]u8 = undefined;
        var header_slots: [1][]const u8 = undefined;
        const headers = self.authHeaders(&auth_buf, &header_slots);

        const response = try self.http_post(self.allocator, url, body.items, headers);
        defer self.allocator.free(response);

        return self.ingestPollPayload(response);
    }

    fn buildSendPayload(
        allocator: std.mem.Allocator,
        account_id: []const u8,
        target: []const u8,
        text: []const u8,
    ) ![]u8 {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        errdefer body.deinit(allocator);
        const bw = body.writer(allocator);
        try bw.writeAll("{\"account_id\":");
        try root.appendJsonStringW(bw, account_id);
        try bw.writeAll(",\"to\":");
        try root.appendJsonStringW(bw, target);
        try bw.writeAll(",\"text\":");
        try root.appendJsonStringW(bw, text);
        try bw.writeByte('}');
        return body.toOwnedSlice(allocator);
    }

    fn sendChunk(self: *WhatsAppWebChannel, target: []const u8, text: []const u8) !void {
        const url = try self.endpointUrl(SEND_ENDPOINT);
        defer self.allocator.free(url);

        const payload = try buildSendPayload(self.allocator, self.config.account_id, target, text);
        defer self.allocator.free(payload);

        var auth_buf: [512]u8 = undefined;
        var header_slots: [1][]const u8 = undefined;
        const headers = self.authHeaders(&auth_buf, &header_slots);

        const response = try self.http_post(self.allocator, url, payload, headers);
        self.allocator.free(response);
    }

    pub fn sendMessage(self: *WhatsAppWebChannel, target: []const u8, text: []const u8) !void {
        var chunks = root.splitMessage(text, MAX_MESSAGE_LEN);
        while (chunks.next()) |chunk| {
            try self.sendChunk(target, chunk);
        }
    }

    pub fn probeBridgeHealth(self: *WhatsAppWebChannel) !void {
        const url = try self.endpointUrl(HEALTH_ENDPOINT);
        defer self.allocator.free(url);

        var auth_buf: [512]u8 = undefined;
        var header_slots: [1][]const u8 = undefined;
        const headers = self.authHeaders(&auth_buf, &header_slots);

        const body = try self.http_get(self.allocator, url, headers, "5");
        self.allocator.free(body);
    }

    fn pollLoop(self: *WhatsAppWebChannel) void {
        while (!self.stop_requested.load(.acquire)) {
            _ = self.pollOnce() catch |err| {
                log.warn("whatsapp_web poll failed (account_id={s}): {}", .{ self.config.account_id, err });
                continue;
            };
            std.Thread.sleep(@as(u64, self.config.poll_interval_ms) * std.time.ns_per_ms);
        }
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *WhatsAppWebChannel = @ptrCast(@alignCast(ptr));
        if (self.running) return;

        if (trimTrailingSlash(self.config.bridge_url).len == 0) {
            return error.InvalidConfiguration;
        }

        self.stop_requested.store(false, .release);
        self.running = true;
        self.poll_thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, pollLoop, .{self});
        log.info("whatsapp_web channel started (account_id={s}, bridge_url={s})", .{
            self.config.account_id,
            self.config.bridge_url,
        });
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *WhatsAppWebChannel = @ptrCast(@alignCast(ptr));
        self.stop_requested.store(true, .release);
        if (self.poll_thread) |thread| {
            thread.join();
            self.poll_thread = null;
        }
        self.running = false;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *WhatsAppWebChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *WhatsAppWebChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *WhatsAppWebChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *WhatsAppWebChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

fn mockPollPost(allocator: std.mem.Allocator, _: []const u8, _: []const u8, _: []const []const u8) ![]u8 {
    return allocator.dupe(u8,
        \\{"next_cursor":"cursor-2","messages":[{"id":"m-1","from":"551199999999","chat_id":"551199999999","text":"oi","is_group":false}]}
    );
}

var mock_send_calls: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

fn mockSendPost(allocator: std.mem.Allocator, _: []const u8, _: []const u8, _: []const []const u8) ![]u8 {
    _ = mock_send_calls.fetchAdd(1, .monotonic);
    return allocator.dupe(u8, "{}");
}

fn mockPollPostExpectPersistedCursor(allocator: std.mem.Allocator, _: []const u8, body: []const u8, _: []const []const u8) ![]u8 {
    if (std.mem.indexOf(u8, body, "\"cursor\":\"persisted-cursor-1\"") == null) {
        return error.TestUnexpectedResult;
    }
    return allocator.dupe(u8, "{\"messages\":[]}");
}

test "whatsapp_web ingest poll payload publishes metadata and session key" {
    var event_bus = bus.Bus.init();
    defer event_bus.close();

    var ch = WhatsAppWebChannel.init(std.testing.allocator, .{
        .account_id = "wa-web-main",
        .bridge_url = "http://127.0.0.1:3301",
        .allow_from = &.{"*"},
        .group_policy = "open",
    });
    defer ch.deinit();
    ch.setBus(&event_bus);

    const payload =
        \\{
        \\  "next_cursor": "next-1",
        \\  "messages": [
        \\    {
        \\      "id": "m-01",
        \\      "from": "5511912345678",
        \\      "chat_id": "5511912345678",
        \\      "text": "hello from bridge",
        \\      "is_group": false
        \\    }
        \\  ]
        \\}
    ;

    const published = try ch.ingestPollPayload(payload);
    try std.testing.expectEqual(@as(usize, 1), published);
    try std.testing.expect(ch.cursor != null);
    try std.testing.expectEqualStrings("next-1", ch.cursor.?);

    var msg = event_bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("whatsapp_web", msg.channel);
    try std.testing.expectEqualStrings("5511912345678", msg.sender_id);
    try std.testing.expectEqualStrings("5511912345678", msg.chat_id);
    try std.testing.expectEqualStrings("hello from bridge", msg.content);
    try std.testing.expectEqualStrings("whatsapp_web:wa-web-main:direct:5511912345678", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"account_id\":\"wa-web-main\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"peer_kind\":\"direct\"") != null);
}

test "whatsapp_web group allowlist blocks unlisted senders" {
    var event_bus = bus.Bus.init();
    defer event_bus.close();

    var ch = WhatsAppWebChannel.init(std.testing.allocator, .{
        .account_id = "wa-web-main",
        .bridge_url = "http://127.0.0.1:3301",
        .group_policy = "allowlist",
        .group_allow_from = &.{"5511911111111"},
    });
    defer ch.deinit();
    ch.setBus(&event_bus);

    const payload =
        \\{"messages":[{"id":"m-02","from":"5511999999999","group_id":"1203630","chat_id":"1203630","text":"blocked","is_group":true}]}
    ;

    const published = try ch.ingestPollPayload(payload);
    try std.testing.expectEqual(@as(usize, 0), published);
    try std.testing.expectEqual(@as(usize, 0), event_bus.inboundDepth());
}

test "whatsapp_web pollOnce uses transport hook and updates cursor" {
    var event_bus = bus.Bus.init();
    defer event_bus.close();

    var ch = WhatsAppWebChannel.init(std.testing.allocator, .{
        .account_id = "wa-web-main",
        .bridge_url = "http://127.0.0.1:3301",
        .allow_from = &.{"*"},
    });
    defer ch.deinit();
    ch.setBus(&event_bus);
    ch.http_post = mockPollPost;

    const published = try ch.pollOnce();
    try std.testing.expectEqual(@as(usize, 1), published);
    try std.testing.expect(ch.cursor != null);
    try std.testing.expectEqualStrings("cursor-2", ch.cursor.?);

    var msg = event_bus.consumeInbound() orelse return error.TestUnexpectedResult;
    msg.deinit(std.testing.allocator);
}

test "whatsapp_web sendMessage splits long text into chunks" {
    mock_send_calls.store(0, .monotonic);

    var ch = WhatsAppWebChannel.init(std.testing.allocator, .{
        .account_id = "wa-web-main",
        .bridge_url = "http://127.0.0.1:3301",
    });
    defer ch.deinit();
    ch.http_post = mockSendPost;

    const long_msg = "A" ** (WhatsAppWebChannel.MAX_MESSAGE_LEN + 11);
    try ch.sendMessage("5511912345678", long_msg);
    try std.testing.expectEqual(@as(u32, 2), mock_send_calls.load(.monotonic));
}

test "whatsapp_web channel interface and lifecycle" {
    var ch = WhatsAppWebChannel.init(std.testing.allocator, .{
        .account_id = "wa-web-main",
        .bridge_url = "http://127.0.0.1:3301",
        .poll_interval_ms = 1,
    });
    ch.http_post = mockPollPost;
    const iface = ch.channel();
    try std.testing.expectEqualStrings("whatsapp_web", iface.name());
    try iface.start();
    try std.testing.expect(ch.healthCheck());
    iface.stop();
    try std.testing.expect(!ch.healthCheck());
    ch.deinit();
}

test "whatsapp_web persists cursor across restart when state root is configured" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fs.path.join(allocator, &.{ base, "config.json" });
    defer allocator.free(config_path);

    var first = WhatsAppWebChannel.init(allocator, .{
        .account_id = "wa-web-main",
        .bridge_url = "http://127.0.0.1:3301",
        .allow_from = &.{"*"},
    });
    defer first.deinit();
    try first.setStateRootFromConfigPath(config_path);
    _ = try first.ingestPollPayload("{\"next_cursor\":\"persisted-cursor-1\",\"messages\":[]}");

    var second = WhatsAppWebChannel.init(allocator, .{
        .account_id = "wa-web-main",
        .bridge_url = "http://127.0.0.1:3301",
        .allow_from = &.{"*"},
    });
    defer second.deinit();
    try second.setStateRootFromConfigPath(config_path);
    try std.testing.expect(second.cursor != null);
    try std.testing.expectEqualStrings("persisted-cursor-1", second.cursor.?);

    second.http_post = mockPollPostExpectPersistedCursor;
    const published = try second.pollOnce();
    try std.testing.expectEqual(@as(usize, 0), published);
}

test "whatsapp_web does not republish seen message ids after restart" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const config_path = try std.fs.path.join(allocator, &.{ base, "config.json" });
    defer allocator.free(config_path);

    var event_bus_first = bus.Bus.init();
    defer event_bus_first.close();

    var first = WhatsAppWebChannel.init(allocator, .{
        .account_id = "wa-web-main",
        .bridge_url = "http://127.0.0.1:3301",
        .allow_from = &.{"*"},
    });
    defer first.deinit();
    first.setBus(&event_bus_first);
    try first.setStateRootFromConfigPath(config_path);

    const first_payload =
        \\{
        \\  "next_cursor": "20",
        \\  "messages": [
        \\    {
        \\      "id": "m-replay-1",
        \\      "from": "5511999999999",
        \\      "chat_id": "5511999999999",
        \\      "text": "primeira entrega",
        \\      "is_group": false
        \\    }
        \\  ]
        \\}
    ;
    const first_published = try first.ingestPollPayload(first_payload);
    try std.testing.expectEqual(@as(usize, 1), first_published);
    var first_msg = event_bus_first.consumeInbound() orelse return error.TestUnexpectedResult;
    first_msg.deinit(allocator);

    var event_bus_second = bus.Bus.init();
    defer event_bus_second.close();

    var second = WhatsAppWebChannel.init(allocator, .{
        .account_id = "wa-web-main",
        .bridge_url = "http://127.0.0.1:3301",
        .allow_from = &.{"*"},
    });
    defer second.deinit();
    second.setBus(&event_bus_second);
    try second.setStateRootFromConfigPath(config_path);

    const replay_payload =
        \\{
        \\  "next_cursor": "1",
        \\  "messages": [
        \\    {
        \\      "id": "m-replay-1",
        \\      "from": "5511999999999",
        \\      "chat_id": "5511999999999",
        \\      "text": "primeira entrega",
        \\      "is_group": false
        \\    }
        \\  ]
        \\}
    ;
    const replay_published = try second.ingestPollPayload(replay_payload);
    try std.testing.expectEqual(@as(usize, 0), replay_published);
    try std.testing.expectEqual(@as(usize, 0), event_bus_second.inboundDepth());
}
