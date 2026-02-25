//! QdrantVectorStore — VectorStore vtable adapter for Qdrant REST API.
//!
//! Implements the VectorStore interface by sending HTTP requests to a
//! running Qdrant instance. Supports upsert, search, delete, count,
//! and healthCheck via the Qdrant REST endpoints.

const std = @import("std");
const Allocator = std.mem.Allocator;
const store_mod = @import("store.zig");
const VectorStore = store_mod.VectorStore;
const VectorResult = store_mod.VectorResult;
const HealthStatus = store_mod.HealthStatus;
const appendJsonEscaped = @import("../../util.zig").appendJsonEscaped;
const net_security = @import("../../net_security.zig");

// ── Config ────────────────────────────────────────────────────────

pub const QdrantConfig = struct {
    url: []const u8, // e.g. "http://localhost:6333"
    api_key: ?[]const u8, // optional
    collection_name: []const u8, // e.g. "nullclaw_memories"
    dimensions: u32, // must match embedding provider
};

// ── QdrantVectorStore ─────────────────────────────────────────────

pub const QdrantVectorStore = struct {
    allocator: Allocator,
    url: []const u8,
    api_key: ?[]const u8,
    collection_name: []const u8,
    dimensions: u32,
    owns_self: bool = false,

    const Self = @This();

    /// Validate that a collection name is safe for URL interpolation.
    /// Qdrant collection names must be alphanumeric, underscore, or hyphen.
    pub fn validateCollectionName(name: []const u8) !void {
        if (name.len == 0 or name.len > 255) return error.InvalidCollectionName;
        for (name) |ch| {
            if (!std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-') return error.InvalidCollectionName;
        }
    }

    /// Require a parseable HTTP(S) endpoint. Plain HTTP is only allowed on local hosts.
    fn validateEndpointUrl(url: []const u8) !void {
        if (url.len == 0) return error.InvalidQdrantUrl;
        _ = std.Uri.parse(url) catch return error.InvalidQdrantUrl;

        const is_https = std.mem.startsWith(u8, url, "https://");
        const is_http = std.mem.startsWith(u8, url, "http://");
        if (!is_https and !is_http) return error.InvalidQdrantUrl;

        if (is_http) {
            const host = net_security.extractHost(url) orelse return error.InvalidQdrantUrl;
            if (!net_security.isLocalHost(host)) return error.InsecureQdrantUrl;
        }
    }

    pub fn init(allocator: Allocator, config: QdrantConfig) !*Self {
        try validateEndpointUrl(config.url);
        try validateCollectionName(config.collection_name);

        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const owned_url = try allocator.dupe(u8, config.url);
        errdefer allocator.free(owned_url);
        const owned_key = if (config.api_key) |k| try allocator.dupe(u8, k) else null;
        errdefer if (owned_key) |k| allocator.free(k);
        const owned_name = try allocator.dupe(u8, config.collection_name);
        errdefer allocator.free(owned_name);

        self.* = .{
            .allocator = allocator,
            .url = owned_url,
            .api_key = owned_key,
            .collection_name = owned_name,
            .dimensions = config.dimensions,
            .owns_self = true,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        const alloc = self.allocator;
        alloc.free(self.url);
        if (self.api_key) |k| alloc.free(k);
        alloc.free(self.collection_name);
        if (self.owns_self) alloc.destroy(self);
    }

    pub fn store(self: *Self) VectorStore {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable_instance,
        };
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    fn buildUrl(self: *const Self, alloc: Allocator, path: []const u8) ![]u8 {
        return std.fmt.allocPrint(alloc, "{s}/collections/{s}{s}", .{
            self.url,
            self.collection_name,
            path,
        });
    }

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

        if (self.api_key) |key| {
            extra_headers_buf[header_count] = .{ .name = "api-key", .value = key };
            header_count += 1;
        }

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = method,
            .payload = payload,
            .extra_headers = extra_headers_buf[0..header_count],
            .response_writer = &aw.writer,
        }) catch return error.QdrantConnectionError;

        const body = try alloc.dupe(u8, aw.writer.buffer[0..aw.writer.end]);
        aw.deinit();

        return .{ .status = result.status, .body = body };
    }

    // ── Helpers ────────────────────────────────────────────────────

    /// Derive a deterministic UUID (v5-style) from a key string.
    /// Qdrant point IDs must be valid UUIDs or integers — arbitrary strings are rejected.
    fn keyToUuid(key: []const u8) [36]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(key, &digest, .{});
        // Format as UUID: xxxxxxxx-xxxx-5xxx-yxxx-xxxxxxxxxxxx
        // Set version nibble to 5 and variant bits to 10xx
        digest[6] = (digest[6] & 0x0f) | 0x50; // version 5
        digest[8] = (digest[8] & 0x3f) | 0x80; // variant 10xx
        var uuid: [36]u8 = undefined;
        const hex = "0123456789abcdef";
        var out: usize = 0;
        for (0..16) |i| {
            if (i == 4 or i == 6 or i == 8 or i == 10) {
                uuid[out] = '-';
                out += 1;
            }
            uuid[out] = hex[digest[i] >> 4];
            out += 1;
            uuid[out] = hex[digest[i] & 0x0f];
            out += 1;
        }
        return uuid;
    }

    // ── JSON builders ─────────────────────────────────────────────

    fn buildUpsertPayload(alloc: Allocator, key: []const u8, embedding: []const f32) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(alloc);

        const uuid = keyToUuid(key);
        try buf.appendSlice(alloc, "{\"points\":[{\"id\":\"");
        try buf.appendSlice(alloc, &uuid);
        try buf.appendSlice(alloc, "\",\"vector\":[");
        for (embedding, 0..) |val, i| {
            if (i > 0) try buf.append(alloc, ',');
            // NaN/Inf produce invalid JSON — reject them.
            if (std.math.isNan(val) or std.math.isInf(val)) return error.InvalidEmbeddingValue;
            var tmp: [32]u8 = undefined;
            const s = std.fmt.bufPrint(&tmp, "{d}", .{val}) catch return error.FormatError;
            try buf.appendSlice(alloc, s);
        }
        try buf.appendSlice(alloc, "],\"payload\":{\"key\":\"");
        try appendJsonEscaped(&buf, alloc, key);
        try buf.appendSlice(alloc, "\"}}]}");

        return alloc.dupe(u8, buf.items);
    }

    fn buildSearchPayload(alloc: Allocator, query_embedding: []const f32, limit: u32) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(alloc);

        try buf.appendSlice(alloc, "{\"vector\":[");
        for (query_embedding, 0..) |val, i| {
            if (i > 0) try buf.append(alloc, ',');
            // NaN/Inf produce invalid JSON — reject them.
            if (std.math.isNan(val) or std.math.isInf(val)) return error.InvalidEmbeddingValue;
            var tmp: [32]u8 = undefined;
            const s = std.fmt.bufPrint(&tmp, "{d}", .{val}) catch return error.FormatError;
            try buf.appendSlice(alloc, s);
        }
        try buf.appendSlice(alloc, "],\"limit\":");
        var lim_buf: [16]u8 = undefined;
        const lim_str = std.fmt.bufPrint(&lim_buf, "{d}", .{limit}) catch return error.FormatError;
        try buf.appendSlice(alloc, lim_str);
        try buf.appendSlice(alloc, ",\"with_payload\":true}");

        return alloc.dupe(u8, buf.items);
    }

    fn buildDeletePayload(alloc: Allocator, key: []const u8) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(alloc);

        try buf.appendSlice(alloc, "{\"filter\":{\"must\":[{\"key\":\"key\",\"match\":{\"value\":\"");
        try appendJsonEscaped(&buf, alloc, key);
        try buf.appendSlice(alloc, "\"}}]}}");

        return alloc.dupe(u8, buf.items);
    }

    // ── Response parsers ──────────────────────────────────────────

    fn parseSearchResults(alloc: Allocator, body: []const u8) ![]VectorResult {
        const parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch return error.QdrantInvalidResponse;
        defer parsed.deinit();

        const root = parsed.value;
        const result_arr = switch (root) {
            .object => |obj| blk: {
                const r = obj.get("result") orelse return error.QdrantInvalidResponse;
                break :blk switch (r) {
                    .array => |a| a,
                    else => return error.QdrantInvalidResponse,
                };
            },
            else => return error.QdrantInvalidResponse,
        };

        var results: std.ArrayListUnmanaged(VectorResult) = .empty;
        errdefer {
            for (results.items) |*r| r.deinit(alloc);
            results.deinit(alloc);
        }

        for (result_arr.items) |item| {
            const obj = switch (item) {
                .object => |o| o,
                else => continue,
            };

            // Extract score
            const score_val = obj.get("score") orelse continue;
            const score: f32 = switch (score_val) {
                .float => |f| @floatCast(f),
                .integer => |n| @floatFromInt(n),
                else => continue,
            };

            // Extract key from payload
            const payload_val = obj.get("payload") orelse continue;
            const payload = switch (payload_val) {
                .object => |o| o,
                else => continue,
            };
            const key_val = payload.get("key") orelse continue;
            const key_str = switch (key_val) {
                .string => |s| s,
                else => continue,
            };

            const owned_key = try alloc.dupe(u8, key_str);
            errdefer alloc.free(owned_key);
            try results.append(alloc, .{
                .key = owned_key,
                .score = score,
            });
        }

        const out = try alloc.dupe(VectorResult, results.items);
        results.deinit(alloc);
        return out;
    }

    fn parseCountResult(alloc: Allocator, body: []const u8) !usize {
        const parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch return error.QdrantInvalidResponse;
        defer parsed.deinit();

        const root = parsed.value;
        const result_obj = switch (root) {
            .object => |obj| blk: {
                const r = obj.get("result") orelse return error.QdrantInvalidResponse;
                break :blk switch (r) {
                    .object => |o| o,
                    else => return error.QdrantInvalidResponse,
                };
            },
            else => return error.QdrantInvalidResponse,
        };

        const count_val = result_obj.get("count") orelse return error.QdrantInvalidResponse;
        return switch (count_val) {
            .integer => |n| @intCast(n),
            else => return error.QdrantInvalidResponse,
        };
    }

    // ── VTable implementations ────────────────────────────────────

    fn implUpsert(ptr: *anyopaque, key: []const u8, embedding: []const f32) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const alloc = self.allocator;

        const url = try self.buildUrl(alloc, "/points?wait=true");
        defer alloc.free(url);

        const payload = try buildUpsertPayload(alloc, key, embedding);
        defer alloc.free(payload);

        const resp = try self.doRequest(alloc, url, .PUT, payload);
        defer alloc.free(resp.body);

        if (resp.status != .ok) return error.QdrantApiError;
    }

    fn implSearch(ptr: *anyopaque, alloc: Allocator, query_embedding: []const f32, limit: u32) anyerror![]VectorResult {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const url = try self.buildUrl(alloc, "/points/search");
        defer alloc.free(url);

        const payload = try buildSearchPayload(alloc, query_embedding, limit);
        defer alloc.free(payload);

        const resp = try self.doRequest(alloc, url, .POST, payload);
        defer alloc.free(resp.body);

        if (resp.status != .ok) return error.QdrantApiError;

        return parseSearchResults(alloc, resp.body);
    }

    fn implDelete(ptr: *anyopaque, key: []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const alloc = self.allocator;

        const url = try self.buildUrl(alloc, "/points/delete?wait=true");
        defer alloc.free(url);

        const payload = try buildDeletePayload(alloc, key);
        defer alloc.free(payload);

        const resp = try self.doRequest(alloc, url, .POST, payload);
        defer alloc.free(resp.body);

        if (resp.status != .ok) return error.QdrantApiError;
    }

    fn implCount(ptr: *anyopaque) anyerror!usize {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const alloc = self.allocator;

        const url = try self.buildUrl(alloc, "/points/count");
        defer alloc.free(url);

        const payload = "{\"exact\":true}";
        const resp = try self.doRequest(alloc, url, .POST, payload);
        defer alloc.free(resp.body);

        if (resp.status != .ok) return error.QdrantApiError;

        return parseCountResult(alloc, resp.body);
    }

    fn implHealthCheck(ptr: *anyopaque, alloc: Allocator) anyerror!HealthStatus {
        const self: *Self = @ptrCast(@alignCast(ptr));
        const start = std.time.nanoTimestamp();

        // Hit the Qdrant healthz endpoint (not collection-scoped)
        const url = try std.fmt.allocPrint(alloc, "{s}/healthz", .{self.url});
        defer alloc.free(url);

        var client = std.http.Client{ .allocator = alloc };
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(alloc);
        defer aw.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .response_writer = &aw.writer,
        }) catch {
            const elapsed: u64 = @intCast(@max(0, std.time.nanoTimestamp() - start));
            return HealthStatus{
                .ok = false,
                .latency_ns = elapsed,
                .entry_count = null,
                .error_msg = try alloc.dupe(u8, "qdrant connection failed"),
            };
        };

        const elapsed: u64 = @intCast(@max(0, std.time.nanoTimestamp() - start));

        if (result.status != .ok) {
            return HealthStatus{
                .ok = false,
                .latency_ns = elapsed,
                .entry_count = null,
                .error_msg = try alloc.dupe(u8, "qdrant healthz returned non-200"),
            };
        }

        // Optionally get entry count (best-effort)
        const entry_count: ?usize = self.implCountInternal() catch null;

        return HealthStatus{
            .ok = true,
            .latency_ns = elapsed,
            .entry_count = entry_count,
            .error_msg = null,
        };
    }

    fn implCountInternal(self: *Self) !usize {
        const alloc = self.allocator;
        const url = try self.buildUrl(alloc, "/points/count");
        defer alloc.free(url);

        const payload = "{\"exact\":true}";
        const resp = try self.doRequest(alloc, url, .POST, payload);
        defer alloc.free(resp.body);

        if (resp.status != .ok) return error.QdrantApiError;

        return parseCountResult(alloc, resp.body);
    }

    fn implDeinit(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.deinit();
    }

    const vtable_instance = VectorStore.VTable{
        .upsert = &implUpsert,
        .search = &implSearch,
        .delete = &implDelete,
        .count = &implCount,
        .health_check = &implHealthCheck,
        .deinit = &implDeinit,
    };
};

// ── Tests ─────────────────────────────────────────────────────────

test "QdrantVectorStore init and deinit" {
    const q = try QdrantVectorStore.init(std.testing.allocator, .{
        .url = "http://localhost:6333",
        .api_key = "test-key",
        .collection_name = "test_collection",
        .dimensions = 384,
    });
    // Verify fields are duped (not pointers to stack memory)
    try std.testing.expectEqualStrings("http://localhost:6333", q.url);
    try std.testing.expectEqualStrings("test-key", q.api_key.?);
    try std.testing.expectEqualStrings("test_collection", q.collection_name);
    try std.testing.expectEqual(@as(u32, 384), q.dimensions);
    q.deinit();
}

test "QdrantVectorStore init without api_key" {
    const q = try QdrantVectorStore.init(std.testing.allocator, .{
        .url = "http://localhost:6333",
        .api_key = null,
        .collection_name = "nullclaw",
        .dimensions = 1536,
    });
    try std.testing.expectEqual(@as(?[]const u8, null), q.api_key);
    q.deinit();
}

test "QdrantVectorStore rejects insecure remote http url" {
    const init_result = QdrantVectorStore.init(std.testing.allocator, .{
        .url = "http://example.com:6333",
        .api_key = null,
        .collection_name = "test",
        .dimensions = 3,
    });
    try std.testing.expectError(error.InsecureQdrantUrl, init_result);
}

test "QdrantVectorStore accepts https remote url" {
    const q = try QdrantVectorStore.init(std.testing.allocator, .{
        .url = "https://example.com:6333",
        .api_key = null,
        .collection_name = "test",
        .dimensions = 3,
    });
    q.deinit();
}

test "QdrantVectorStore produces valid VectorStore vtable" {
    var q = try QdrantVectorStore.init(std.testing.allocator, .{
        .url = "http://localhost:6333",
        .api_key = null,
        .collection_name = "test",
        .dimensions = 3,
    });
    const s = q.store();
    // Verify the vtable is wired correctly (methods are non-null function pointers)
    try std.testing.expect(s.vtable.upsert == &QdrantVectorStore.implUpsert);
    try std.testing.expect(s.vtable.search == &QdrantVectorStore.implSearch);
    try std.testing.expect(s.vtable.delete == &QdrantVectorStore.implDelete);
    try std.testing.expect(s.vtable.count == &QdrantVectorStore.implCount);
    try std.testing.expect(s.vtable.health_check == &QdrantVectorStore.implHealthCheck);
    try std.testing.expect(s.vtable.deinit == &QdrantVectorStore.implDeinit);
    s.deinitStore();
}

test "buildUpsertPayload generates valid JSON" {
    const alloc = std.testing.allocator;
    const embedding = [_]f32{ 0.1, 0.2, 0.3 };
    const payload = try QdrantVectorStore.buildUpsertPayload(alloc, "test_key", &embedding);
    defer alloc.free(payload);

    // Parse the JSON to verify it's valid
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
    defer parsed.deinit();

    // Verify structure: {"points":[{"id":"<uuid>","vector":[...],"payload":{"key":"test_key"}}]}
    const points = parsed.value.object.get("points").?.array;
    try std.testing.expectEqual(@as(usize, 1), points.items.len);

    const point = points.items[0].object;
    // id is now a deterministic UUID derived from key, verify it's a valid UUID format (36 chars with dashes)
    const id_str = point.get("id").?.string;
    try std.testing.expectEqual(@as(usize, 36), id_str.len);
    try std.testing.expect(id_str[8] == '-');
    try std.testing.expect(id_str[13] == '-');
    try std.testing.expect(id_str[18] == '-');
    try std.testing.expect(id_str[23] == '-');

    const vec = point.get("vector").?.array;
    try std.testing.expectEqual(@as(usize, 3), vec.items.len);

    const pl = point.get("payload").?.object;
    try std.testing.expectEqualStrings("test_key", pl.get("key").?.string);
}

test "buildUpsertPayload escapes special characters" {
    const alloc = std.testing.allocator;
    const embedding = [_]f32{1.0};
    const payload = try QdrantVectorStore.buildUpsertPayload(alloc, "key\"with\\quotes", &embedding);
    defer alloc.free(payload);

    // Should be valid JSON despite special chars in key
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
    defer parsed.deinit();

    const points = parsed.value.object.get("points").?.array;
    const point = points.items[0].object;
    // id is a UUID (special chars are hashed away), payload key preserves the original
    const id_str = point.get("id").?.string;
    try std.testing.expectEqual(@as(usize, 36), id_str.len);
    const pl = point.get("payload").?.object;
    try std.testing.expectEqualStrings("key\"with\\quotes", pl.get("key").?.string);
}

test "buildSearchPayload generates valid JSON" {
    const alloc = std.testing.allocator;
    const query = [_]f32{ 1.0, 2.0 };
    const payload = try QdrantVectorStore.buildSearchPayload(alloc, &query, 5);
    defer alloc.free(payload);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
    defer parsed.deinit();

    const root = parsed.value.object;
    const vec = root.get("vector").?.array;
    try std.testing.expectEqual(@as(usize, 2), vec.items.len);

    const limit = root.get("limit").?.integer;
    try std.testing.expectEqual(@as(i64, 5), limit);

    try std.testing.expect(root.get("with_payload").?.bool);
}

test "buildDeletePayload generates valid JSON" {
    const alloc = std.testing.allocator;
    const payload = try QdrantVectorStore.buildDeletePayload(alloc, "my_key");
    defer alloc.free(payload);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
    defer parsed.deinit();

    // {"filter":{"must":[{"key":"key","match":{"value":"my_key"}}]}}
    const filter = parsed.value.object.get("filter").?.object;
    const must = filter.get("must").?.array;
    try std.testing.expectEqual(@as(usize, 1), must.items.len);

    const cond = must.items[0].object;
    try std.testing.expectEqualStrings("key", cond.get("key").?.string);
    const match = cond.get("match").?.object;
    try std.testing.expectEqualStrings("my_key", match.get("value").?.string);
}

test "parseSearchResults valid response" {
    const alloc = std.testing.allocator;
    const json =
        \\{"result":[{"id":"abc","score":0.95,"payload":{"key":"mem_1"}},{"id":"def","score":0.8,"payload":{"key":"mem_2"}}],"status":"ok"}
    ;

    const results = try QdrantVectorStore.parseSearchResults(alloc, json);
    defer {
        for (results) |*r| r.deinit(alloc);
        alloc.free(results);
    }

    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqualStrings("mem_1", results[0].key);
    try std.testing.expect(@abs(results[0].score - 0.95) < 0.01);
    try std.testing.expectEqualStrings("mem_2", results[1].key);
    try std.testing.expect(@abs(results[1].score - 0.8) < 0.01);
}

test "parseSearchResults empty result" {
    const alloc = std.testing.allocator;
    const json =
        \\{"result":[],"status":"ok"}
    ;

    const results = try QdrantVectorStore.parseSearchResults(alloc, json);
    defer alloc.free(results);

    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "parseSearchResults invalid JSON returns error" {
    const alloc = std.testing.allocator;
    const result = QdrantVectorStore.parseSearchResults(alloc, "not json");
    try std.testing.expectError(error.QdrantInvalidResponse, result);
}

test "parseSearchResults missing result field returns error" {
    const alloc = std.testing.allocator;
    const json =
        \\{"status":"ok"}
    ;
    const result = QdrantVectorStore.parseSearchResults(alloc, json);
    try std.testing.expectError(error.QdrantInvalidResponse, result);
}

test "parseCountResult valid response" {
    const alloc = std.testing.allocator;
    const json =
        \\{"result":{"count":42},"status":"ok"}
    ;

    const count = try QdrantVectorStore.parseCountResult(alloc, json);
    try std.testing.expectEqual(@as(usize, 42), count);
}

test "parseCountResult zero count" {
    const alloc = std.testing.allocator;
    const json =
        \\{"result":{"count":0},"status":"ok"}
    ;

    const count = try QdrantVectorStore.parseCountResult(alloc, json);
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "parseCountResult invalid JSON returns error" {
    const alloc = std.testing.allocator;
    const result = QdrantVectorStore.parseCountResult(alloc, "bad");
    try std.testing.expectError(error.QdrantInvalidResponse, result);
}

test "parseCountResult missing count field returns error" {
    const alloc = std.testing.allocator;
    const json =
        \\{"result":{},"status":"ok"}
    ;
    const result = QdrantVectorStore.parseCountResult(alloc, json);
    try std.testing.expectError(error.QdrantInvalidResponse, result);
}

test "appendJsonEscaped handles special characters" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try appendJsonEscaped(&buf, alloc, "hello \"world\"\nnewline\\slash");

    try std.testing.expectEqualStrings("hello \\\"world\\\"\\nnewline\\\\slash", buf.items);
}

test "appendJsonEscaped handles plain text" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try appendJsonEscaped(&buf, alloc, "simple text");

    try std.testing.expectEqualStrings("simple text", buf.items);
}

test "buildUrl constructs correct endpoint" {
    var q = try QdrantVectorStore.init(std.testing.allocator, .{
        .url = "http://localhost:6333",
        .api_key = null,
        .collection_name = "my_coll",
        .dimensions = 3,
    });
    defer q.deinit();

    const url = try q.buildUrl(std.testing.allocator, "/points/search");
    defer std.testing.allocator.free(url);

    try std.testing.expectEqualStrings("http://localhost:6333/collections/my_coll/points/search", url);
}

test "buildUrl with empty path" {
    var q = try QdrantVectorStore.init(std.testing.allocator, .{
        .url = "http://localhost:6333",
        .api_key = null,
        .collection_name = "test",
        .dimensions = 3,
    });
    defer q.deinit();

    const url = try q.buildUrl(std.testing.allocator, "");
    defer std.testing.allocator.free(url);

    try std.testing.expectEqualStrings("http://localhost:6333/collections/test", url);
}

test "keyToUuid produces valid UUID format" {
    const uuid = QdrantVectorStore.keyToUuid("test_key");
    try std.testing.expectEqual(@as(usize, 36), uuid.len);
    // Check dash positions
    try std.testing.expect(uuid[8] == '-');
    try std.testing.expect(uuid[13] == '-');
    try std.testing.expect(uuid[18] == '-');
    try std.testing.expect(uuid[23] == '-');
    // Check version nibble (position 14) is '5'
    try std.testing.expect(uuid[14] == '5');
    // Check variant nibble (position 19) is 8, 9, a, or b
    try std.testing.expect(uuid[19] == '8' or uuid[19] == '9' or uuid[19] == 'a' or uuid[19] == 'b');
}

test "keyToUuid is deterministic" {
    const uuid_a = QdrantVectorStore.keyToUuid("hello");
    const uuid_b = QdrantVectorStore.keyToUuid("hello");
    try std.testing.expectEqualSlices(u8, &uuid_a, &uuid_b);
}

test "keyToUuid differs for different keys" {
    const uuid_a = QdrantVectorStore.keyToUuid("alpha");
    const uuid_b = QdrantVectorStore.keyToUuid("beta");
    try std.testing.expect(!std.mem.eql(u8, &uuid_a, &uuid_b));
}

// ── R3 tests ──────────────────────────────────────────────────────

test "buildUpsertPayload rejects NaN embedding" {
    const alloc = std.testing.allocator;
    const embedding = [_]f32{ 0.1, std.math.nan(f32), 0.3 };
    const result = QdrantVectorStore.buildUpsertPayload(alloc, "key", &embedding);
    try std.testing.expectError(error.InvalidEmbeddingValue, result);
}

test "buildUpsertPayload rejects Inf embedding" {
    const alloc = std.testing.allocator;
    const embedding = [_]f32{std.math.inf(f32)};
    const result = QdrantVectorStore.buildUpsertPayload(alloc, "key", &embedding);
    try std.testing.expectError(error.InvalidEmbeddingValue, result);
}

test "buildSearchPayload rejects NaN query" {
    const alloc = std.testing.allocator;
    const query = [_]f32{ 0.1, std.math.nan(f32) };
    const result = QdrantVectorStore.buildSearchPayload(alloc, &query, 5);
    try std.testing.expectError(error.InvalidEmbeddingValue, result);
}

test "validateCollectionName rejects invalid names" {
    try std.testing.expectError(error.InvalidCollectionName, QdrantVectorStore.validateCollectionName(""));
    try std.testing.expectError(error.InvalidCollectionName, QdrantVectorStore.validateCollectionName("has space"));
    try std.testing.expectError(error.InvalidCollectionName, QdrantVectorStore.validateCollectionName("has.dot"));
    try std.testing.expectError(error.InvalidCollectionName, QdrantVectorStore.validateCollectionName("has/slash"));
}

test "validateCollectionName accepts valid names" {
    try QdrantVectorStore.validateCollectionName("valid_name");
    try QdrantVectorStore.validateCollectionName("valid-name");
    try QdrantVectorStore.validateCollectionName("valid123");
    try QdrantVectorStore.validateCollectionName("a");
}

test "QdrantVectorStore init rejects bad collection name" {
    const result = QdrantVectorStore.init(std.testing.allocator, .{
        .url = "http://localhost:6333",
        .api_key = null,
        .collection_name = "bad name!",
        .dimensions = 3,
    });
    try std.testing.expectError(error.InvalidCollectionName, result);
}
