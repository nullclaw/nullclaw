//! HTTP API Memory backend — delegates to an external REST service.
//!
//! Implements the Memory + SessionStore vtable interfaces by sending
//! HTTP requests to a user-provided REST API server.
//! Pattern follows store_qdrant.zig: std.http.Client + std.Io.Writer.Allocating.

const std = @import("std");
const Allocator = std.mem.Allocator;
const appendJsonEscaped = @import("../../util.zig").appendJsonEscaped;
const root = @import("../root.zig");
const Memory = root.Memory;
const MemoryCategory = root.MemoryCategory;
const MemoryEntry = root.MemoryEntry;
const MessageEntry = root.MessageEntry;
const SessionStore = root.SessionStore;
const config_types = @import("../../config_types.zig");
const net_security = @import("../../net_security.zig");
const log = std.log.scoped(.api_memory);

// ── ApiMemory ─────────────────────────────────────────────────────

pub const ApiMemory = struct {
    allocator: Allocator,
    base_url: []const u8, // "{url}{namespace}" — owned
    api_key: ?[]const u8, // owned, null if empty
    timeout_ms: u32,
    owns_self: bool = false,
    has_session_store: bool = true,

    const Self = @This();

    pub fn init(allocator: Allocator, config: config_types.MemoryApiConfig) !Self {
        // Build base_url = url + namespace
        // Strip trailing slashes; ensure namespace starts with /
        var url = config.url;
        if (url.len > 0 and url[url.len - 1] == '/') {
            url = url[0 .. url.len - 1];
        }
        if (url.len == 0) return error.InvalidApiUrl;
        try validateBaseUrl(url);
        var ns = config.namespace;
        if (ns.len > 0 and ns[ns.len - 1] == '/') {
            ns = ns[0 .. ns.len - 1];
        }
        const base_url = if (ns.len > 0) blk: {
            if (ns[0] == '/') {
                break :blk try std.fmt.allocPrint(allocator, "{s}{s}", .{ url, ns });
            } else {
                break :blk try std.fmt.allocPrint(allocator, "{s}/{s}", .{ url, ns });
            }
        } else try allocator.dupe(u8, url);
        errdefer allocator.free(base_url);

        const api_key: ?[]const u8 = if (config.api_key.len > 0)
            try allocator.dupe(u8, config.api_key)
        else
            null;

        return .{
            .allocator = allocator,
            .base_url = base_url,
            .api_key = api_key,
            .timeout_ms = config.timeout_ms,
        };
    }

    /// Require a parseable HTTP(S) URL. Plain HTTP is only allowed for local hosts.
    fn validateBaseUrl(url: []const u8) !void {
        _ = std.Uri.parse(url) catch return error.InvalidApiUrl;

        const is_https = std.mem.startsWith(u8, url, "https://");
        const is_http = std.mem.startsWith(u8, url, "http://");
        if (!is_https and !is_http) return error.InvalidApiUrl;

        if (is_http) {
            const host = net_security.extractHost(url) orelse return error.InvalidApiUrl;
            if (!net_security.isLocalHost(host)) return error.InsecureApiUrl;
        }
    }

    pub fn deinit(self: *Self) void {
        const alloc = self.allocator;
        alloc.free(self.base_url);
        if (self.api_key) |k| alloc.free(k);
        if (self.owns_self) alloc.destroy(self);
    }

    pub fn memory(self: *Self) Memory {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &mem_vtable,
        };
    }

    pub fn sessionStore(self: *Self) ?SessionStore {
        if (!self.has_session_store) return null;
        return .{
            .ptr = @ptrCast(self),
            .vtable = &session_vtable,
        };
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    fn doRequest(
        self: *const Self,
        alloc: Allocator,
        url: []const u8,
        method: std.http.Method,
        payload: ?[]const u8,
    ) !struct { status: std.http.Status, body: []u8 } {
        var client = std.http.Client{ .allocator = alloc };
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(alloc);
        errdefer aw.deinit();

        var extra_headers_buf: [3]std.http.Header = undefined;
        var header_count: usize = 0;

        extra_headers_buf[header_count] = .{ .name = "Content-Type", .value = "application/json" };
        header_count += 1;

        var auth_header: ?[]u8 = null;
        defer if (auth_header) |h| alloc.free(h);

        if (self.api_key) |key| {
            auth_header = try std.fmt.allocPrint(alloc, "Bearer {s}", .{key});
            extra_headers_buf[header_count] = .{ .name = "Authorization", .value = auth_header.? };
            header_count += 1;
        }

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = method,
            .payload = payload,
            .extra_headers = extra_headers_buf[0..header_count],
            .response_writer = &aw.writer,
        }) catch return error.ApiConnectionError;

        const body = try alloc.dupe(u8, aw.writer.buffer[0..aw.writer.end]);
        aw.deinit();

        return .{ .status = result.status, .body = body };
    }

    // ── URL builders ─────────────────────────────────────────────

    fn buildMemoryUrl(self: *const Self, alloc: Allocator, key: ?[]const u8) ![]u8 {
        if (key) |k| {
            const encoded_key = try urlEncode(alloc, k);
            defer alloc.free(encoded_key);
            return std.fmt.allocPrint(alloc, "{s}/memories/{s}", .{ self.base_url, encoded_key });
        }
        return std.fmt.allocPrint(alloc, "{s}/memories", .{self.base_url});
    }

    fn buildMemoryUrlWithQuery(self: *const Self, alloc: Allocator, category: ?[]const u8, session_id: ?[]const u8) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(alloc);

        try buf.appendSlice(alloc, self.base_url);
        try buf.appendSlice(alloc, "/memories");

        var has_param = false;
        if (category) |cat| {
            try buf.append(alloc, '?');
            try buf.appendSlice(alloc, "category=");
            try appendUrlEncoded(&buf, alloc, cat);
            has_param = true;
        }
        if (session_id) |sid| {
            try buf.append(alloc, if (has_param) '&' else '?');
            try buf.appendSlice(alloc, "session_id=");
            try appendUrlEncoded(&buf, alloc, sid);
        }

        return buf.toOwnedSlice(alloc);
    }

    fn buildSearchUrl(self: *const Self, alloc: Allocator) ![]u8 {
        return std.fmt.allocPrint(alloc, "{s}/memories/search", .{self.base_url});
    }

    fn buildCountUrl(self: *const Self, alloc: Allocator) ![]u8 {
        return std.fmt.allocPrint(alloc, "{s}/memories/count", .{self.base_url});
    }

    fn buildHealthUrl(self: *const Self, alloc: Allocator) ![]u8 {
        return std.fmt.allocPrint(alloc, "{s}/health", .{self.base_url});
    }

    fn buildSessionMessagesUrl(self: *const Self, alloc: Allocator, session_id: []const u8) ![]u8 {
        const encoded_sid = try urlEncode(alloc, session_id);
        defer alloc.free(encoded_sid);
        return std.fmt.allocPrint(alloc, "{s}/sessions/{s}/messages", .{ self.base_url, encoded_sid });
    }

    fn buildAutoSavedUrl(self: *const Self, alloc: Allocator, session_id: ?[]const u8) ![]u8 {
        if (session_id) |sid| {
            const encoded_sid = try urlEncode(alloc, sid);
            defer alloc.free(encoded_sid);
            return std.fmt.allocPrint(alloc, "{s}/sessions/auto-saved?session_id={s}", .{ self.base_url, encoded_sid });
        }
        return std.fmt.allocPrint(alloc, "{s}/sessions/auto-saved", .{self.base_url});
    }

    // ── JSON builders ────────────────────────────────────────────

    fn buildStorePayload(alloc: Allocator, content: []const u8, category: MemoryCategory, session_id: ?[]const u8) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(alloc);

        try buf.appendSlice(alloc, "{\"content\":\"");
        try appendJsonEscaped(&buf, alloc, content);
        try buf.appendSlice(alloc, "\",\"category\":\"");
        try appendJsonEscaped(&buf, alloc, category.toString());
        try buf.append(alloc, '"');

        if (session_id) |sid| {
            try buf.appendSlice(alloc, ",\"session_id\":\"");
            try appendJsonEscaped(&buf, alloc, sid);
            try buf.append(alloc, '"');
        } else {
            try buf.appendSlice(alloc, ",\"session_id\":null");
        }

        try buf.append(alloc, '}');
        return buf.toOwnedSlice(alloc);
    }

    fn buildSearchPayload(alloc: Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(alloc);

        try buf.appendSlice(alloc, "{\"query\":\"");
        try appendJsonEscaped(&buf, alloc, query);
        try buf.appendSlice(alloc, "\",\"limit\":");
        var lim_buf: [20]u8 = undefined;
        const lim_str = std.fmt.bufPrint(&lim_buf, "{d}", .{limit}) catch "10";
        try buf.appendSlice(alloc, lim_str);

        if (session_id) |sid| {
            try buf.appendSlice(alloc, ",\"session_id\":\"");
            try appendJsonEscaped(&buf, alloc, sid);
            try buf.append(alloc, '"');
        } else {
            try buf.appendSlice(alloc, ",\"session_id\":null");
        }

        try buf.append(alloc, '}');
        return buf.toOwnedSlice(alloc);
    }

    fn buildMessagePayload(alloc: Allocator, role: []const u8, content: []const u8) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(alloc);

        try buf.appendSlice(alloc, "{\"role\":\"");
        try appendJsonEscaped(&buf, alloc, role);
        try buf.appendSlice(alloc, "\",\"content\":\"");
        try appendJsonEscaped(&buf, alloc, content);
        try buf.appendSlice(alloc, "\"}");
        return buf.toOwnedSlice(alloc);
    }

    // ── URL encoding ──────────────────────────────────────────────

    fn appendUrlEncoded(buf: *std.ArrayListUnmanaged(u8), alloc: Allocator, text: []const u8) !void {
        for (text) |ch| {
            if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == '~') {
                try buf.append(alloc, ch);
            } else {
                var hex_buf: [3]u8 = undefined;
                const hex = std.fmt.bufPrint(&hex_buf, "%{X:0>2}", .{ch}) catch unreachable;
                try buf.appendSlice(alloc, hex);
            }
        }
    }

    fn urlEncode(alloc: Allocator, text: []const u8) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(alloc);
        try appendUrlEncoded(&buf, alloc, text);
        return buf.toOwnedSlice(alloc);
    }

    // ── Response parsers ─────────────────────────────────────────

    fn parseEntries(alloc: Allocator, body: []const u8) ![]MemoryEntry {
        const parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch return error.ApiInvalidResponse;
        defer parsed.deinit();

        const entries_arr = switch (parsed.value) {
            .object => |obj| blk: {
                const e = obj.get("entries") orelse return error.ApiInvalidResponse;
                break :blk switch (e) {
                    .array => |a| a,
                    else => return error.ApiInvalidResponse,
                };
            },
            else => return error.ApiInvalidResponse,
        };

        var results: std.ArrayListUnmanaged(MemoryEntry) = .empty;
        errdefer {
            for (results.items) |*r| r.deinit(alloc);
            results.deinit(alloc);
        }

        for (entries_arr.items) |item| {
            const entry = parseOneEntry(alloc, item) catch continue;
            try results.append(alloc, entry);
        }

        return results.toOwnedSlice(alloc);
    }

    fn parseSingleEntry(alloc: Allocator, body: []const u8) !?MemoryEntry {
        const parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch return error.ApiInvalidResponse;
        defer parsed.deinit();

        const entry_val = switch (parsed.value) {
            .object => |obj| obj.get("entry") orelse return error.ApiInvalidResponse,
            else => return error.ApiInvalidResponse,
        };

        return parseOneEntry(alloc, entry_val) catch return error.ApiInvalidResponse;
    }

    fn parseOneEntry(alloc: Allocator, item: std.json.Value) !MemoryEntry {
        const obj = switch (item) {
            .object => |o| o,
            else => return error.ApiInvalidResponse,
        };

        const id_str = if (obj.get("id")) |v| switch (v) {
            .string => |s| s,
            else => "",
        } else "";

        const key_str = if (obj.get("key")) |v| switch (v) {
            .string => |s| s,
            else => "",
        } else "";

        const content_str = if (obj.get("content")) |v| switch (v) {
            .string => |s| s,
            else => "",
        } else "";

        const timestamp_str = if (obj.get("timestamp")) |v| switch (v) {
            .string => |s| s,
            else => "0",
        } else "0";

        const cat_str = if (obj.get("category")) |v| switch (v) {
            .string => |s| s,
            else => "core",
        } else "core";

        const category = MemoryCategory.fromString(cat_str);
        const final_category: MemoryCategory = switch (category) {
            .custom => .{ .custom = try alloc.dupe(u8, cat_str) },
            else => category,
        };
        errdefer switch (final_category) {
            .custom => |name| alloc.free(name),
            else => {},
        };

        var session_id: ?[]const u8 = null;
        if (obj.get("session_id")) |v| {
            switch (v) {
                .string => |s| {
                    if (s.len > 0) session_id = try alloc.dupe(u8, s);
                },
                else => {},
            }
        }
        errdefer if (session_id) |sid| alloc.free(sid);

        var score: ?f64 = null;
        if (obj.get("score")) |v| {
            score = switch (v) {
                .float => |f| f,
                .integer => |n| @floatFromInt(n),
                else => null,
            };
        }

        const id = try alloc.dupe(u8, id_str);
        errdefer alloc.free(id);
        const key = try alloc.dupe(u8, key_str);
        errdefer alloc.free(key);
        const content = try alloc.dupe(u8, content_str);
        errdefer alloc.free(content);
        const timestamp = try alloc.dupe(u8, timestamp_str);

        return .{
            .id = id,
            .key = key,
            .content = content,
            .category = final_category,
            .timestamp = timestamp,
            .session_id = session_id,
            .score = score,
        };
    }

    fn parseMessages(alloc: Allocator, body: []const u8) ![]MessageEntry {
        const parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch return error.ApiInvalidResponse;
        defer parsed.deinit();

        const msgs_arr = switch (parsed.value) {
            .object => |obj| blk: {
                const m = obj.get("messages") orelse return error.ApiInvalidResponse;
                break :blk switch (m) {
                    .array => |a| a,
                    else => return error.ApiInvalidResponse,
                };
            },
            else => return error.ApiInvalidResponse,
        };

        var results: std.ArrayListUnmanaged(MessageEntry) = .empty;
        errdefer {
            for (results.items) |entry| {
                alloc.free(entry.role);
                alloc.free(entry.content);
            }
            results.deinit(alloc);
        }

        for (msgs_arr.items) |item| {
            const obj = switch (item) {
                .object => |o| o,
                else => continue,
            };

            const role = if (obj.get("role")) |v| switch (v) {
                .string => |s| s,
                else => continue,
            } else continue;

            const content = if (obj.get("content")) |v| switch (v) {
                .string => |s| s,
                else => continue,
            } else continue;

            const duped_role = try alloc.dupe(u8, role);
            errdefer alloc.free(duped_role);
            const duped_content = try alloc.dupe(u8, content);
            try results.append(alloc, .{
                .role = duped_role,
                .content = duped_content,
            });
        }

        return results.toOwnedSlice(alloc);
    }

    fn parseCount(alloc: Allocator, body: []const u8) !usize {
        const parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch return error.ApiInvalidResponse;
        defer parsed.deinit();

        const count_val = switch (parsed.value) {
            .object => |obj| obj.get("count") orelse return error.ApiInvalidResponse,
            else => return error.ApiInvalidResponse,
        };

        return switch (count_val) {
            .integer => |n| if (n >= 0) @intCast(n) else return error.ApiInvalidResponse,
            else => return error.ApiInvalidResponse,
        };
    }

    // ── Memory vtable implementation ─────────────────────────────

    fn implName(_: *anyopaque) []const u8 {
        return "api";
    }

    fn implStore(ptr: *anyopaque, key: []const u8, content: []const u8, category: MemoryCategory, session_id: ?[]const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const alloc = self.allocator;

        const url = try self.buildMemoryUrl(alloc, key);
        defer alloc.free(url);

        const payload = try buildStorePayload(alloc, content, category, session_id);
        defer alloc.free(payload);

        const resp = try self.doRequest(alloc, url, .PUT, payload);
        defer alloc.free(resp.body);

        if (resp.status != .ok) {
            log.warn("API store failed: status={d}", .{@intFromEnum(resp.status)});
            return error.ApiRequestFailed;
        }
    }

    fn implRecall(ptr: *anyopaque, alloc: Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const url = try self.buildSearchUrl(alloc);
        defer alloc.free(url);

        const payload = try buildSearchPayload(alloc, query, limit, session_id);
        defer alloc.free(payload);

        const resp = try self.doRequest(alloc, url, .POST, payload);
        defer alloc.free(resp.body);

        if (resp.status != .ok) {
            log.warn("API recall failed: status={d}", .{@intFromEnum(resp.status)});
            return error.ApiRequestFailed;
        }

        return parseEntries(alloc, resp.body);
    }

    fn implGet(ptr: *anyopaque, alloc: Allocator, key: []const u8) anyerror!?MemoryEntry {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const url = try self.buildMemoryUrl(alloc, key);
        defer alloc.free(url);

        const resp = self.doRequest(alloc, url, .GET, null) catch return null;
        defer alloc.free(resp.body);

        if (resp.status == .not_found) return null;
        if (resp.status != .ok) return null;

        return parseSingleEntry(alloc, resp.body) catch null;
    }

    fn implList(ptr: *anyopaque, alloc: Allocator, category: ?MemoryCategory, session_id: ?[]const u8) anyerror![]MemoryEntry {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const cat_str: ?[]const u8 = if (category) |c| c.toString() else null;
        const url = try self.buildMemoryUrlWithQuery(alloc, cat_str, session_id);
        defer alloc.free(url);

        const resp = try self.doRequest(alloc, url, .GET, null);
        defer alloc.free(resp.body);

        if (resp.status != .ok) {
            log.warn("API list failed: status={d}", .{@intFromEnum(resp.status)});
            return error.ApiRequestFailed;
        }

        return parseEntries(alloc, resp.body);
    }

    fn implForget(ptr: *anyopaque, key: []const u8) anyerror!bool {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const alloc = self.allocator;

        const url = try self.buildMemoryUrl(alloc, key);
        defer alloc.free(url);

        const resp = self.doRequest(alloc, url, .DELETE, null) catch return false;
        defer alloc.free(resp.body);

        return resp.status == .ok;
    }

    fn implCount(ptr: *anyopaque) anyerror!usize {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const alloc = self.allocator;

        const url = try self.buildCountUrl(alloc);
        defer alloc.free(url);

        const resp = try self.doRequest(alloc, url, .GET, null);
        defer alloc.free(resp.body);

        if (resp.status != .ok) return error.ApiRequestFailed;

        return parseCount(alloc, resp.body);
    }

    fn implHealthCheck(ptr: *anyopaque) bool {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const alloc = self.allocator;

        const url = self.buildHealthUrl(alloc) catch return false;
        defer alloc.free(url);

        const resp = self.doRequest(alloc, url, .GET, null) catch return false;
        defer alloc.free(resp.body);

        return resp.status == .ok;
    }

    fn implDeinit(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.deinit();
    }

    const mem_vtable = Memory.VTable{
        .name = &implName,
        .store = &implStore,
        .recall = &implRecall,
        .get = &implGet,
        .list = &implList,
        .forget = &implForget,
        .count = &implCount,
        .healthCheck = &implHealthCheck,
        .deinit = &implDeinit,
    };

    // ── SessionStore vtable implementation ───────────────────────

    fn implSaveMessage(ptr: *anyopaque, session_id: []const u8, role: []const u8, content: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const alloc = self.allocator;

        const url = try self.buildSessionMessagesUrl(alloc, session_id);
        defer alloc.free(url);

        const payload = try buildMessagePayload(alloc, role, content);
        defer alloc.free(payload);

        const resp = try self.doRequest(alloc, url, .POST, payload);
        defer alloc.free(resp.body);

        if (resp.status != .ok) {
            log.warn("API saveMessage failed: status={d}", .{@intFromEnum(resp.status)});
            return error.ApiRequestFailed;
        }
    }

    fn implLoadMessages(ptr: *anyopaque, alloc: Allocator, session_id: []const u8) anyerror![]MessageEntry {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const url = try self.buildSessionMessagesUrl(alloc, session_id);
        defer alloc.free(url);

        const resp = try self.doRequest(alloc, url, .GET, null);
        defer alloc.free(resp.body);

        if (resp.status != .ok) {
            log.warn("API loadMessages failed: status={d}", .{@intFromEnum(resp.status)});
            return error.ApiRequestFailed;
        }

        return parseMessages(alloc, resp.body);
    }

    fn implClearMessages(ptr: *anyopaque, session_id: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const alloc = self.allocator;

        const url = try self.buildSessionMessagesUrl(alloc, session_id);
        defer alloc.free(url);

        const resp = try self.doRequest(alloc, url, .DELETE, null);
        defer alloc.free(resp.body);

        if (resp.status != .ok) {
            log.warn("API clearMessages failed: status={d}", .{@intFromEnum(resp.status)});
            return error.ApiRequestFailed;
        }
    }

    fn implClearAutoSaved(ptr: *anyopaque, session_id: ?[]const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const alloc = self.allocator;

        const url = try self.buildAutoSavedUrl(alloc, session_id);
        defer alloc.free(url);

        const resp = try self.doRequest(alloc, url, .DELETE, null);
        defer alloc.free(resp.body);

        if (resp.status != .ok) {
            log.warn("API clearAutoSaved failed: status={d}", .{@intFromEnum(resp.status)});
            return error.ApiRequestFailed;
        }
    }

    const session_vtable = SessionStore.VTable{
        .saveMessage = &implSaveMessage,
        .loadMessages = &implLoadMessages,
        .clearMessages = &implClearMessages,
        .clearAutoSaved = &implClearAutoSaved,
    };
};

// ── Tests ─────────────────────────────────────────────────────────

test "api memory name" {
    var mem = try ApiMemory.init(std.testing.allocator, .{ .url = "http://127.0.0.1:8080" });
    defer mem.deinit();

    const m = mem.memory();
    try std.testing.expectEqualStrings("api", m.name());
}

test "api memory health check no server" {
    var mem = try ApiMemory.init(std.testing.allocator, .{
        .url = "http://127.0.0.1:19999",
    });
    defer mem.deinit();

    const m = mem.memory();
    try std.testing.expect(!m.healthCheck());
}

test "api memory init/deinit" {
    // Empty URL is invalid for API backend
    try std.testing.expectError(error.InvalidApiUrl, ApiMemory.init(std.testing.allocator, .{}));

    // With URL and api_key
    var mem2 = try ApiMemory.init(std.testing.allocator, .{
        .url = "http://localhost:8080",
        .api_key = "test-secret",
        .timeout_ms = 5000,
        .namespace = "/v1",
    });
    defer mem2.deinit();

    try std.testing.expectEqualStrings("http://localhost:8080/v1", mem2.base_url);
    try std.testing.expectEqualStrings("test-secret", mem2.api_key.?);
    try std.testing.expectEqual(@as(u32, 5000), mem2.timeout_ms);
}

test "api init rejects insecure remote http url" {
    try std.testing.expectError(error.InsecureApiUrl, ApiMemory.init(std.testing.allocator, .{
        .url = "http://example.com",
    }));
}

test "api init accepts https remote url" {
    var mem = try ApiMemory.init(std.testing.allocator, .{
        .url = "https://example.com",
    });
    defer mem.deinit();
    try std.testing.expectEqualStrings("https://example.com", mem.base_url);
}

test "api url building" {
    var mem = try ApiMemory.init(std.testing.allocator, .{
        .url = "http://localhost:8080",
        .namespace = "/v1/agent",
    });
    defer mem.deinit();

    // Memory URL with key
    const url1 = try mem.buildMemoryUrl(std.testing.allocator, "my_key");
    defer std.testing.allocator.free(url1);
    try std.testing.expectEqualStrings("http://localhost:8080/v1/agent/memories/my_key", url1);

    // Memory URL without key
    const url2 = try mem.buildMemoryUrl(std.testing.allocator, null);
    defer std.testing.allocator.free(url2);
    try std.testing.expectEqualStrings("http://localhost:8080/v1/agent/memories", url2);

    // Search URL
    const url3 = try mem.buildSearchUrl(std.testing.allocator);
    defer std.testing.allocator.free(url3);
    try std.testing.expectEqualStrings("http://localhost:8080/v1/agent/memories/search", url3);

    // Count URL
    const url4 = try mem.buildCountUrl(std.testing.allocator);
    defer std.testing.allocator.free(url4);
    try std.testing.expectEqualStrings("http://localhost:8080/v1/agent/memories/count", url4);

    // Health URL
    const url5 = try mem.buildHealthUrl(std.testing.allocator);
    defer std.testing.allocator.free(url5);
    try std.testing.expectEqualStrings("http://localhost:8080/v1/agent/health", url5);

    // Session messages URL
    const url6 = try mem.buildSessionMessagesUrl(std.testing.allocator, "sess-42");
    defer std.testing.allocator.free(url6);
    try std.testing.expectEqualStrings("http://localhost:8080/v1/agent/sessions/sess-42/messages", url6);
}

test "api url building with trailing slash" {
    var mem = try ApiMemory.init(std.testing.allocator, .{
        .url = "http://localhost:8080/",
    });
    defer mem.deinit();

    try std.testing.expectEqualStrings("http://localhost:8080", mem.base_url);
}

test "api url building no namespace" {
    var mem = try ApiMemory.init(std.testing.allocator, .{
        .url = "http://localhost:8080",
    });
    defer mem.deinit();

    const url = try mem.buildMemoryUrl(std.testing.allocator, "key1");
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("http://localhost:8080/memories/key1", url);
}

test "api url building list with query params" {
    var mem = try ApiMemory.init(std.testing.allocator, .{
        .url = "http://localhost:8080",
    });
    defer mem.deinit();

    // Both params
    const url1 = try mem.buildMemoryUrlWithQuery(std.testing.allocator, "core", "sess-1");
    defer std.testing.allocator.free(url1);
    try std.testing.expectEqualStrings("http://localhost:8080/memories?category=core&session_id=sess-1", url1);

    // Category only
    const url2 = try mem.buildMemoryUrlWithQuery(std.testing.allocator, "daily", null);
    defer std.testing.allocator.free(url2);
    try std.testing.expectEqualStrings("http://localhost:8080/memories?category=daily", url2);

    // Session only
    const url3 = try mem.buildMemoryUrlWithQuery(std.testing.allocator, null, "sess-2");
    defer std.testing.allocator.free(url3);
    try std.testing.expectEqualStrings("http://localhost:8080/memories?session_id=sess-2", url3);

    // Neither
    const url4 = try mem.buildMemoryUrlWithQuery(std.testing.allocator, null, null);
    defer std.testing.allocator.free(url4);
    try std.testing.expectEqualStrings("http://localhost:8080/memories", url4);
}

test "api json escaping" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try appendJsonEscaped(&buf, alloc, "hello \"world\"\nnewline\\slash\ttab");
    try std.testing.expectEqualStrings("hello \\\"world\\\"\\nnewline\\\\slash\\ttab", buf.items);
}

test "api json escaping control chars" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    // Test null byte and other control characters
    try appendJsonEscaped(&buf, alloc, "a\x01b");
    try std.testing.expectEqualStrings("a\\u0001b", buf.items);
}

test "api json escaping plain text" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try appendJsonEscaped(&buf, alloc, "simple text 123");
    try std.testing.expectEqualStrings("simple text 123", buf.items);
}

test "api parse entries" {
    const alloc = std.testing.allocator;
    const json =
        \\{"entries":[
        \\  {"id":"uuid-1","key":"pref_theme","content":"dark theme","category":"core","timestamp":"2026-02-25T12:00:00Z","session_id":null,"score":0.95},
        \\  {"id":"uuid-2","key":"user_lang","content":"Russian","category":"daily","timestamp":"2026-02-25T13:00:00Z","session_id":"s1","score":0.8}
        \\]}
    ;

    const entries = try ApiMemory.parseEntries(alloc, json);
    defer {
        for (entries) |*e| e.deinit(alloc);
        alloc.free(entries);
    }

    try std.testing.expectEqual(@as(usize, 2), entries.len);

    try std.testing.expectEqualStrings("uuid-1", entries[0].id);
    try std.testing.expectEqualStrings("pref_theme", entries[0].key);
    try std.testing.expectEqualStrings("dark theme", entries[0].content);
    try std.testing.expect(entries[0].category.eql(.core));
    try std.testing.expectEqualStrings("2026-02-25T12:00:00Z", entries[0].timestamp);
    try std.testing.expect(entries[0].session_id == null);
    try std.testing.expect(@abs(entries[0].score.? - 0.95) < 0.01);

    try std.testing.expectEqualStrings("uuid-2", entries[1].id);
    try std.testing.expect(entries[1].category.eql(.daily));
    try std.testing.expectEqualStrings("s1", entries[1].session_id.?);
}

test "api parse entries empty" {
    const alloc = std.testing.allocator;
    const json =
        \\{"entries":[]}
    ;

    const entries = try ApiMemory.parseEntries(alloc, json);
    defer alloc.free(entries);

    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "api parse entries invalid json" {
    const alloc = std.testing.allocator;
    const result = ApiMemory.parseEntries(alloc, "not json");
    try std.testing.expectError(error.ApiInvalidResponse, result);
}

test "api parse entries missing field" {
    const alloc = std.testing.allocator;
    const json =
        \\{"data":[]}
    ;
    const result = ApiMemory.parseEntries(alloc, json);
    try std.testing.expectError(error.ApiInvalidResponse, result);
}

test "api parse messages" {
    const alloc = std.testing.allocator;
    const json =
        \\{"messages":[
        \\  {"role":"user","content":"Hello"},
        \\  {"role":"assistant","content":"Hi there!"}
        \\]}
    ;

    const messages = try ApiMemory.parseMessages(alloc, json);
    defer {
        for (messages) |entry| {
            alloc.free(entry.role);
            alloc.free(entry.content);
        }
        alloc.free(messages);
    }

    try std.testing.expectEqual(@as(usize, 2), messages.len);
    try std.testing.expectEqualStrings("user", messages[0].role);
    try std.testing.expectEqualStrings("Hello", messages[0].content);
    try std.testing.expectEqualStrings("assistant", messages[1].role);
    try std.testing.expectEqualStrings("Hi there!", messages[1].content);
}

test "api parse messages empty" {
    const alloc = std.testing.allocator;
    const json =
        \\{"messages":[]}
    ;

    const messages = try ApiMemory.parseMessages(alloc, json);
    defer alloc.free(messages);

    try std.testing.expectEqual(@as(usize, 0), messages.len);
}

test "api parse messages invalid json" {
    const alloc = std.testing.allocator;
    const result = ApiMemory.parseMessages(alloc, "bad");
    try std.testing.expectError(error.ApiInvalidResponse, result);
}

test "api parse count" {
    const alloc = std.testing.allocator;
    const json =
        \\{"count":42}
    ;
    const count = try ApiMemory.parseCount(alloc, json);
    try std.testing.expectEqual(@as(usize, 42), count);
}

test "api parse count zero" {
    const alloc = std.testing.allocator;
    const json =
        \\{"count":0}
    ;
    const count = try ApiMemory.parseCount(alloc, json);
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "api parse count invalid" {
    const alloc = std.testing.allocator;
    const result = ApiMemory.parseCount(alloc, "bad");
    try std.testing.expectError(error.ApiInvalidResponse, result);
}

test "api parse count missing field" {
    const alloc = std.testing.allocator;
    const json =
        \\{"total":5}
    ;
    const result = ApiMemory.parseCount(alloc, json);
    try std.testing.expectError(error.ApiInvalidResponse, result);
}

test "api build store payload" {
    const alloc = std.testing.allocator;
    const payload = try ApiMemory.buildStorePayload(alloc, "dark theme", .core, null);
    defer alloc.free(payload);

    // Validate it's valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("dark theme", obj.get("content").?.string);
    try std.testing.expectEqualStrings("core", obj.get("category").?.string);
    try std.testing.expect(obj.get("session_id").? == .null);
}

test "api build store payload with session" {
    const alloc = std.testing.allocator;
    const payload = try ApiMemory.buildStorePayload(alloc, "content", .daily, "sess-1");
    defer alloc.free(payload);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("content", obj.get("content").?.string);
    try std.testing.expectEqualStrings("daily", obj.get("category").?.string);
    try std.testing.expectEqualStrings("sess-1", obj.get("session_id").?.string);
}

test "api build search payload" {
    const alloc = std.testing.allocator;
    const payload = try ApiMemory.buildSearchPayload(alloc, "search query", 5, null);
    defer alloc.free(payload);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("search query", obj.get("query").?.string);
    try std.testing.expectEqual(@as(i64, 5), obj.get("limit").?.integer);
    try std.testing.expect(obj.get("session_id").? == .null);
}

test "api build message payload" {
    const alloc = std.testing.allocator;
    const payload = try ApiMemory.buildMessagePayload(alloc, "user", "Hello world");
    defer alloc.free(payload);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("user", obj.get("role").?.string);
    try std.testing.expectEqualStrings("Hello world", obj.get("content").?.string);
}

test "api memory produces vtable" {
    var mem = try ApiMemory.init(std.testing.allocator, .{ .url = "http://127.0.0.1:8080" });
    defer mem.deinit();

    const m = mem.memory();
    try std.testing.expect(m.vtable.name == &ApiMemory.implName);
    try std.testing.expect(m.vtable.store == &ApiMemory.implStore);
    try std.testing.expect(m.vtable.recall == &ApiMemory.implRecall);
    try std.testing.expect(m.vtable.get == &ApiMemory.implGet);
    try std.testing.expect(m.vtable.list == &ApiMemory.implList);
    try std.testing.expect(m.vtable.forget == &ApiMemory.implForget);
    try std.testing.expect(m.vtable.count == &ApiMemory.implCount);
    try std.testing.expect(m.vtable.healthCheck == &ApiMemory.implHealthCheck);
    try std.testing.expect(m.vtable.deinit == &ApiMemory.implDeinit);
}

test "api memory produces session store vtable" {
    var mem = try ApiMemory.init(std.testing.allocator, .{ .url = "http://127.0.0.1:8080" });
    defer mem.deinit();

    const ss = mem.sessionStore() orelse return error.TestUnexpectedResult;
    try std.testing.expect(ss.vtable.saveMessage == &ApiMemory.implSaveMessage);
    try std.testing.expect(ss.vtable.loadMessages == &ApiMemory.implLoadMessages);
    try std.testing.expect(ss.vtable.clearMessages == &ApiMemory.implClearMessages);
    try std.testing.expect(ss.vtable.clearAutoSaved == &ApiMemory.implClearAutoSaved);
}

test "api memory no session store when disabled" {
    var mem = try ApiMemory.init(std.testing.allocator, .{ .url = "http://127.0.0.1:8080" });
    defer mem.deinit();

    mem.has_session_store = false;
    try std.testing.expect(mem.sessionStore() == null);
}

test "api init with empty api_key" {
    var mem = try ApiMemory.init(std.testing.allocator, .{
        .url = "http://localhost:8080",
        .api_key = "",
    });
    defer mem.deinit();

    try std.testing.expect(mem.api_key == null);
}

test "api parse single entry" {
    const alloc = std.testing.allocator;
    const json =
        \\{"entry":{"id":"u1","key":"k1","content":"data","category":"conversation","timestamp":"123","session_id":"s1","score":0.5}}
    ;

    const entry = try ApiMemory.parseSingleEntry(alloc, json) orelse return error.TestUnexpectedResult;
    defer entry.deinit(alloc);

    try std.testing.expectEqualStrings("u1", entry.id);
    try std.testing.expectEqualStrings("k1", entry.key);
    try std.testing.expectEqualStrings("data", entry.content);
    try std.testing.expect(entry.category.eql(.conversation));
    try std.testing.expectEqualStrings("s1", entry.session_id.?);
}

test "api parse entries with custom category" {
    const alloc = std.testing.allocator;
    const json =
        \\{"entries":[{"id":"u1","key":"k1","content":"x","category":"my_custom","timestamp":"0"}]}
    ;

    const entries = try ApiMemory.parseEntries(alloc, json);
    defer {
        for (entries) |*e| e.deinit(alloc);
        alloc.free(entries);
    }

    try std.testing.expectEqual(@as(usize, 1), entries.len);
    switch (entries[0].category) {
        .custom => |name| try std.testing.expectEqualStrings("my_custom", name),
        else => return error.TestUnexpectedResult,
    }
}

test "api namespace without leading slash" {
    var mem = try ApiMemory.init(std.testing.allocator, .{
        .url = "http://localhost:8080",
        .namespace = "v1",
    });
    defer mem.deinit();
    try std.testing.expectEqualStrings("http://localhost:8080/v1", mem.base_url);
}

test "api namespace with trailing slash" {
    var mem = try ApiMemory.init(std.testing.allocator, .{
        .url = "http://localhost:8080",
        .namespace = "/v1/",
    });
    defer mem.deinit();
    try std.testing.expectEqualStrings("http://localhost:8080/v1", mem.base_url);
}

test "api url encoding in path" {
    const alloc = std.testing.allocator;
    var mem = try ApiMemory.init(alloc, .{ .url = "http://localhost:8080" });
    defer mem.deinit();

    const url = try mem.buildMemoryUrl(alloc, "key with spaces");
    defer alloc.free(url);
    try std.testing.expectEqualStrings("http://localhost:8080/memories/key%20with%20spaces", url);
}

test "api url encoding in query params" {
    const alloc = std.testing.allocator;
    var mem = try ApiMemory.init(alloc, .{ .url = "http://localhost:8080" });
    defer mem.deinit();

    const url = try mem.buildMemoryUrlWithQuery(alloc, "custom&cat", "sess id=1");
    defer alloc.free(url);
    try std.testing.expectEqualStrings("http://localhost:8080/memories?category=custom%26cat&session_id=sess%20id%3D1", url);
}

test "api url encoding preserves safe chars" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try ApiMemory.appendUrlEncoded(&buf, alloc, "hello-world_2.0~test");
    try std.testing.expectEqualStrings("hello-world_2.0~test", buf.items);
}

test "api parse count rejects negative" {
    const alloc = std.testing.allocator;
    const json =
        \\{"count":-1}
    ;
    const result = ApiMemory.parseCount(alloc, json);
    try std.testing.expectError(error.ApiInvalidResponse, result);
}
