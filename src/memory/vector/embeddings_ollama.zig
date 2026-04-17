//! Ollama local embedding provider — nomic-embed-text via /api/embed endpoint.
//!
//! API: POST http://localhost:11434/api/embed
//! Auth: none (local service)
//! Default model: "nomic-embed-text", 768 dimensions (model-dependent)

const std = @import("std");
const std_compat = @import("compat");
const EmbeddingProvider = @import("embeddings.zig").EmbeddingProvider;
const http_util = @import("../../http_util.zig");
const appendJsonEscaped = @import("../../util.zig").appendJsonEscaped;
const net_security = @import("../../net_security.zig");

pub const OllamaEmbedding = struct {
    allocator: std.mem.Allocator,
    base_url: []const u8,
    model: []const u8,
    dims: u32,

    const Self = @This();

    pub const default_base_url = "http://localhost:11434";
    pub const default_model = "nomic-embed-text";
    pub const default_dims: u32 = 768;

    pub fn init(
        allocator: std.mem.Allocator,
        model: ?[]const u8,
        base_url: ?[]const u8,
        dims: ?u32,
    ) !*Self {
        try validateBaseUrl(base_url orelse default_base_url);

        const self_ = try allocator.create(Self);
        errdefer allocator.destroy(self_);

        const owned_url = try allocator.dupe(u8, base_url orelse default_base_url);
        errdefer allocator.free(owned_url);
        const owned_model = try allocator.dupe(u8, model orelse default_model);

        self_.* = .{
            .allocator = allocator,
            .base_url = owned_url,
            .model = owned_model,
            .dims = dims orelse default_dims,
        };
        return self_;
    }

    /// Require a parseable HTTP(S) endpoint. Plain HTTP is only allowed on local hosts.
    fn validateBaseUrl(url: []const u8) !void {
        if (url.len == 0) return error.InvalidEmbeddingApiUrl;
        _ = std.Uri.parse(url) catch return error.InvalidEmbeddingApiUrl;

        const is_https = std.mem.startsWith(u8, url, "https://");
        const is_http = std.mem.startsWith(u8, url, "http://");
        if (!is_https and !is_http) return error.InvalidEmbeddingApiUrl;

        if (is_http) {
            const host = net_security.extractHost(url) orelse return error.InvalidEmbeddingApiUrl;
            if (!net_security.isLocalHost(host)) return error.InsecureEmbeddingApiUrl;
        }
    }

    pub fn deinitSelf(self: *Self) void {
        self.allocator.free(self.base_url);
        self.allocator.free(self.model);
        self.allocator.destroy(self);
    }

    fn buildUrl(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/api/embed", .{self.base_url});
    }

    /// Build request body JSON: {"model":"...","input":"..."}
    pub fn buildRequestBody(allocator: std.mem.Allocator, model: []const u8, text: []const u8) ![]u8 {
        var body_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer body_buf.deinit(allocator);

        try body_buf.appendSlice(allocator, "{\"model\":\"");
        try appendJsonEscaped(&body_buf, allocator, model);
        try body_buf.appendSlice(allocator, "\",\"input\":\"");
        try appendJsonEscaped(&body_buf, allocator, text);
        try body_buf.appendSlice(allocator, "\"}");

        return allocator.dupe(u8, body_buf.items);
    }

    fn implName(_: *anyopaque) []const u8 {
        return "ollama";
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

        const body = try buildRequestBody(allocator, self_.model, text);
        defer allocator.free(body);

        const url = try self_.buildUrl(allocator);
        defer allocator.free(url);

        var client = try http_util.ProxyHttpClient.init(allocator);
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(allocator);
        defer aw.deinit();

        const result = client.client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .response_writer = &aw.writer,
        }) catch return error.EmbeddingApiError;

        if (result.status != .ok) {
            return error.EmbeddingApiError;
        }

        const resp_body = aw.writer.buffer[0..aw.writer.end];
        if (resp_body.len == 0) return error.EmbeddingApiError;

        return parseOllamaResponse(allocator, resp_body);
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

/// Parse Ollama response: {"embeddings":[[0.1, 0.2, ...]]}
pub fn parseOllamaResponse(allocator: std.mem.Allocator, json_bytes: []const u8) ![]f32 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return error.InvalidEmbeddingResponse;
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return error.InvalidEmbeddingResponse,
    };
    const embeddings = root.get("embeddings") orelse return error.InvalidEmbeddingResponse;
    const outer_array = switch (embeddings) {
        .array => |a| a,
        else => return error.InvalidEmbeddingResponse,
    };
    if (outer_array.items.len == 0) return error.InvalidEmbeddingResponse;

    const inner = outer_array.items[0];
    const emb_array = switch (inner) {
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

test "OllamaEmbedding init and deinit" {
    var impl_ = try OllamaEmbedding.init(
        std.testing.allocator,
        null,
        null,
        null,
    );
    const p = impl_.provider();
    try std.testing.expectEqualStrings("ollama", p.getName());
    try std.testing.expectEqual(@as(u32, 768), p.getDimensions());
    p.deinit();
}

test "OllamaEmbedding init with custom values" {
    var impl_ = try OllamaEmbedding.init(
        std.testing.allocator,
        "mxbai-embed-large",
        "https://gpu-server:11434",
        1024,
    );
    const p = impl_.provider();
    try std.testing.expectEqualStrings("ollama", p.getName());
    try std.testing.expectEqual(@as(u32, 1024), p.getDimensions());
    p.deinit();
}

test "OllamaEmbedding init rejects insecure remote http url" {
    const result = OllamaEmbedding.init(
        std.testing.allocator,
        "nomic-embed-text",
        "http://gpu-server:11434",
        768,
    );
    try std.testing.expectError(error.InsecureEmbeddingApiUrl, result);
}

test "OllamaEmbedding embed empty text" {
    var impl_ = try OllamaEmbedding.init(
        std.testing.allocator,
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

test "OllamaEmbedding buildRequestBody" {
    const body = try OllamaEmbedding.buildRequestBody(std.testing.allocator, "nomic-embed-text", "hello world");
    defer std.testing.allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    const root = parsed.value;
    const model_val = root.object.get("model") orelse return error.TestFailed;
    try std.testing.expectEqualStrings("nomic-embed-text", model_val.string);

    const input = root.object.get("input") orelse return error.TestFailed;
    try std.testing.expectEqualStrings("hello world", input.string);
}

test "OllamaEmbedding buildRequestBody escapes special chars" {
    const body = try OllamaEmbedding.buildRequestBody(std.testing.allocator, "model", "hello \"world\"\nnewline");
    defer std.testing.allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    const root = parsed.value;
    const input = root.object.get("input") orelse return error.TestFailed;
    try std.testing.expectEqualStrings("hello \"world\"\nnewline", input.string);
}

test "parseOllamaResponse valid" {
    const json =
        \\{"embeddings":[[0.1,0.2,0.3]]}
    ;
    const result = try parseOllamaResponse(std.testing.allocator, json);
    defer std.testing.allocator.free(result);

    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expect(@abs(result[0] - 0.1) < 0.001);
    try std.testing.expect(@abs(result[1] - 0.2) < 0.001);
    try std.testing.expect(@abs(result[2] - 0.3) < 0.001);
}

test "parseOllamaResponse empty outer array" {
    const json =
        \\{"embeddings":[]}
    ;
    const result = parseOllamaResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "parseOllamaResponse missing embeddings" {
    const json =
        \\{"error":"model not found"}
    ;
    const result = parseOllamaResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "parseOllamaResponse integer values" {
    const json =
        \\{"embeddings":[[1,2,3]]}
    ;
    const result = try parseOllamaResponse(std.testing.allocator, json);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expect(@abs(result[0] - 1.0) < 0.001);
}

test "parseOllamaResponse empty inner array" {
    const json =
        \\{"embeddings":[[]]}
    ;
    const result = try parseOllamaResponse(std.testing.allocator, json);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

// ── R3 regression tests ───────────────────────────────────────────

test "parseOllamaResponse string value returns error" {
    const json =
        \\{"embeddings":[["bad",0.2,0.3]]}
    ;
    const result = parseOllamaResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "parseOllamaResponse null value returns error" {
    const json =
        \\{"embeddings":[[0.1,null,0.3]]}
    ;
    const result = parseOllamaResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "parseOllamaResponse root is array returns error" {
    const json =
        \\[{"embeddings":[[0.1]]}]
    ;
    const result = parseOllamaResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "buildRequestBody model with quotes is properly escaped" {
    const body = try OllamaEmbedding.buildRequestBody(std.testing.allocator, "model\"evil", "test");
    defer std.testing.allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body, .{});
    defer parsed.deinit();

    const root = parsed.value;
    const model_val = root.object.get("model") orelse return error.TestFailed;
    try std.testing.expectEqualStrings("model\"evil", model_val.string);
}
