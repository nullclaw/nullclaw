//! Voyage AI embedding provider — voyage-3-lite via /v1/embeddings API.
//!
//! API: POST https://api.voyageai.com/v1/embeddings
//! Auth: Bearer token in Authorization header
//! Default model: "voyage-3-lite", 512 dimensions
//! Note: input_type matters — "query" for search, "document" for storage.

const std = @import("std");
const std_compat = @import("compat");
const EmbeddingProvider = @import("embeddings.zig").EmbeddingProvider;
const http_util = @import("../../http_util.zig");
const appendJsonEscaped = @import("../../util.zig").appendJsonEscaped;

pub const VoyageEmbedding = struct {
    allocator: std.mem.Allocator,
    base_url: []const u8,
    api_key: []const u8,
    model: []const u8,
    dims: u32,

    const Self = @This();

    pub const default_base_url = "https://api.voyageai.com";
    pub const default_model = "voyage-3-lite";
    pub const default_dims: u32 = 512;

    pub fn init(
        allocator: std.mem.Allocator,
        api_key: []const u8,
        model: ?[]const u8,
        base_url: ?[]const u8,
        dims: ?u32,
    ) !*Self {
        const self_ = try allocator.create(Self);
        errdefer allocator.destroy(self_);

        const owned_url = try allocator.dupe(u8, base_url orelse default_base_url);
        errdefer allocator.free(owned_url);
        const owned_key = try allocator.dupe(u8, api_key);
        errdefer allocator.free(owned_key);
        const owned_model = try allocator.dupe(u8, model orelse default_model);

        self_.* = .{
            .allocator = allocator,
            .base_url = owned_url,
            .api_key = owned_key,
            .model = owned_model,
            .dims = dims orelse default_dims,
        };
        return self_;
    }

    pub fn deinitSelf(self: *Self) void {
        self.allocator.free(self.base_url);
        self.allocator.free(self.api_key);
        self.allocator.free(self.model);
        self.allocator.destroy(self);
    }

    fn buildUrl(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/v1/embeddings", .{self.base_url});
    }

    /// Build request body JSON: {"model":"...","input":["..."],"input_type":"query"}
    /// input_type defaults to "query" (for search); callers embedding documents for storage
    /// should use buildRequestBodyWithType directly.
    pub fn buildRequestBody(allocator: std.mem.Allocator, model: []const u8, text: []const u8, input_type: []const u8) ![]u8 {
        var body_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer body_buf.deinit(allocator);

        try body_buf.appendSlice(allocator, "{\"model\":\"");
        try appendJsonEscaped(&body_buf, allocator, model);
        try body_buf.appendSlice(allocator, "\",\"input\":[\"");
        try appendJsonEscaped(&body_buf, allocator, text);
        try body_buf.appendSlice(allocator, "\"],\"input_type\":\"");
        try appendJsonEscaped(&body_buf, allocator, input_type);
        try body_buf.appendSlice(allocator, "\"}");

        return allocator.dupe(u8, body_buf.items);
    }

    fn implName(_: *anyopaque) []const u8 {
        return "voyage";
    }

    fn implDimensions(ptr: *anyopaque) u32 {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        return self_.dims;
    }

    fn implEmbed(ptr: *anyopaque, allocator: std.mem.Allocator, text: []const u8) anyerror![]f32 {
        const self_: *Self = @ptrCast(@alignCast(ptr));

        if (text.len == 0) {
            return allocator.alloc(f32, 0);
        }

        // Default to "query" input_type for the vtable embed call
        const body = try buildRequestBody(allocator, self_.model, text, "query");
        defer allocator.free(body);

        const url = try self_.buildUrl(allocator);
        defer allocator.free(url);

        const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{self_.api_key});
        defer allocator.free(auth_header);

        var client = try http_util.ProxyHttpClient.init(allocator);
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(allocator);
        defer aw.deinit();

        const result = client.client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Authorization", .value = auth_header },
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .response_writer = &aw.writer,
        }) catch return error.EmbeddingApiError;

        if (result.status != .ok) {
            return error.EmbeddingApiError;
        }

        const resp_body = aw.writer.buffer[0..aw.writer.end];
        if (resp_body.len == 0) return error.EmbeddingApiError;

        return parseVoyageResponse(allocator, resp_body);
    }

    fn implDeinit(ptr: *anyopaque) void {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        self_.deinitSelf();
    }

    const vtable = EmbeddingProvider.VTable{
        .name = &implName,
        .dimensions = &implDimensions,
        .embed = &implEmbed,
        .deinit = &implDeinit,
    };

    pub fn provider(self: *Self) EmbeddingProvider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }
};

/// Parse Voyage response: {"data":[{"embedding":[0.1, 0.2, ...]}]}
pub fn parseVoyageResponse(allocator: std.mem.Allocator, json_bytes: []const u8) ![]f32 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return error.InvalidEmbeddingResponse;
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidEmbeddingResponse,
    };
    const data = root.get("data") orelse return error.InvalidEmbeddingResponse;
    const data_array = switch (data) {
        .array => |a| a,
        else => return error.InvalidEmbeddingResponse,
    };
    if (data_array.items.len == 0) return error.InvalidEmbeddingResponse;

    const first = data_array.items[0];
    const embedding = switch (first) {
        .object => |obj| obj.get("embedding") orelse return error.InvalidEmbeddingResponse,
        else => return error.InvalidEmbeddingResponse,
    };
    const emb_array = switch (embedding) {
        .array => |a| a,
        else => return error.InvalidEmbeddingResponse,
    };

    const result = try allocator.alloc(f32, emb_array.items.len);
    errdefer allocator.free(result);
    for (emb_array.items, 0..) |val, i| {
        result[i] = switch (val) {
            .float => |f| @floatCast(f),
            .integer => |n| @floatFromInt(n),
            else => return error.InvalidEmbeddingResponse,
        };
    }
    return result;
}

// ── Tests ─────────────────────────────────────────────────────────

test "VoyageEmbedding init and deinit" {
    var impl_ = try VoyageEmbedding.init(
        std.testing.allocator,
        "test-api-key",
        null,
        null,
        null,
    );
    const p = impl_.provider();
    try std.testing.expectEqualStrings("voyage", p.getName());
    try std.testing.expectEqual(@as(u32, 512), p.getDimensions());
    p.deinit();
}

test "VoyageEmbedding init with custom values" {
    var impl_ = try VoyageEmbedding.init(
        std.testing.allocator,
        "my-key",
        "voyage-3",
        "https://custom.voyageai.com",
        1024,
    );
    const p = impl_.provider();
    try std.testing.expectEqualStrings("voyage", p.getName());
    try std.testing.expectEqual(@as(u32, 1024), p.getDimensions());
    p.deinit();
}

test "VoyageEmbedding embed empty text" {
    var impl_ = try VoyageEmbedding.init(
        std.testing.allocator,
        "test-key",
        null,
        null,
        null,
    );
    const p = impl_.provider();
    defer p.deinit();

    const vec = try p.embed(std.testing.allocator, "");
    defer std.testing.allocator.free(vec);
    try std.testing.expectEqual(@as(usize, 0), vec.len);
}

test "VoyageEmbedding buildRequestBody query" {
    const body = try VoyageEmbedding.buildRequestBody(std.testing.allocator, "voyage-3-lite", "hello world", "query");
    defer std.testing.allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    const root = parsed.value;
    const model_val = root.object.get("model") orelse return error.TestFailed;
    try std.testing.expectEqualStrings("voyage-3-lite", model_val.string);

    const input = root.object.get("input") orelse return error.TestFailed;
    try std.testing.expectEqualStrings("hello world", input.array.items[0].string);

    const input_type = root.object.get("input_type") orelse return error.TestFailed;
    try std.testing.expectEqualStrings("query", input_type.string);
}

test "VoyageEmbedding buildRequestBody document" {
    const body = try VoyageEmbedding.buildRequestBody(std.testing.allocator, "voyage-3-lite", "some document", "document");
    defer std.testing.allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    const root = parsed.value;
    const input_type = root.object.get("input_type") orelse return error.TestFailed;
    try std.testing.expectEqualStrings("document", input_type.string);
}

test "VoyageEmbedding buildRequestBody escapes special chars" {
    const body = try VoyageEmbedding.buildRequestBody(std.testing.allocator, "model", "hello \"world\"\nnewline", "query");
    defer std.testing.allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    const root = parsed.value;
    const input = root.object.get("input") orelse return error.TestFailed;
    try std.testing.expectEqualStrings("hello \"world\"\nnewline", input.array.items[0].string);
}

test "parseVoyageResponse valid" {
    const json =
        \\{"data":[{"embedding":[0.1,0.2,0.3]}]}
    ;
    const result = try parseVoyageResponse(std.testing.allocator, json);
    defer std.testing.allocator.free(result);

    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expect(@abs(result[0] - 0.1) < 0.001);
    try std.testing.expect(@abs(result[1] - 0.2) < 0.001);
    try std.testing.expect(@abs(result[2] - 0.3) < 0.001);
}

test "parseVoyageResponse empty data" {
    const json =
        \\{"data":[]}
    ;
    const result = parseVoyageResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "parseVoyageResponse missing data" {
    const json =
        \\{"error":"bad request"}
    ;
    const result = parseVoyageResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "parseVoyageResponse integer values" {
    const json =
        \\{"data":[{"embedding":[1,2,3]}]}
    ;
    const result = try parseVoyageResponse(std.testing.allocator, json);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expect(@abs(result[0] - 1.0) < 0.001);
}

// ── R3 regression tests ───────────────────────────────────────────

test "parseVoyageResponse string value returns error" {
    const json =
        \\{"data":[{"embedding":[0.1,"bad",0.3]}]}
    ;
    const result = parseVoyageResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "parseVoyageResponse null value returns error" {
    const json =
        \\{"data":[{"embedding":[0.1,null,0.3]}]}
    ;
    const result = parseVoyageResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "parseVoyageResponse root is array returns error" {
    const json =
        \\[{"data":[{"embedding":[0.1]}]}]
    ;
    const result = parseVoyageResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "buildRequestBody model with quotes is properly escaped" {
    const body = try VoyageEmbedding.buildRequestBody(std.testing.allocator, "model\"evil", "test", "query");
    defer std.testing.allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    const root = parsed.value;
    const model_val = root.object.get("model") orelse return error.TestFailed;
    try std.testing.expectEqualStrings("model\"evil", model_val.string);
}
