//! Embedding providers — convert text to vectors for semantic search.
//!
//! Mirrors ZeroClaw's embeddings module:
//!   - EmbeddingProvider vtable interface
//!   - NoopEmbedding (returns empty/zero vectors, keyword-only fallback)
//!   - OpenAiEmbedding (HTTP POST to /v1/embeddings)
//!   - Factory function: createEmbeddingProvider()

const std = @import("std");

// ── Embedding provider vtable ─────────────────────────────────────

pub const EmbeddingProvider = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        name: *const fn (ptr: *anyopaque) []const u8,
        dimensions: *const fn (ptr: *anyopaque) u32,
        embed: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, text: []const u8) anyerror![]f32,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn getName(self: EmbeddingProvider) []const u8 {
        return self.vtable.name(self.ptr);
    }

    pub fn getDimensions(self: EmbeddingProvider) u32 {
        return self.vtable.dimensions(self.ptr);
    }

    /// Embed a single text into a vector. Caller owns the returned slice.
    pub fn embed(self: EmbeddingProvider, allocator: std.mem.Allocator, text: []const u8) ![]f32 {
        return self.vtable.embed(self.ptr, allocator, text);
    }

    pub fn deinit(self: EmbeddingProvider) void {
        self.vtable.deinit(self.ptr);
    }
};

// ── Noop provider (keyword-only fallback) ─────────────────────────

pub const NoopEmbedding = struct {
    const Self = @This();

    fn implName(_: *anyopaque) []const u8 {
        return "none";
    }

    fn implDimensions(_: *anyopaque) u32 {
        return 0;
    }

    fn implEmbed(_: *anyopaque, allocator: std.mem.Allocator, _: []const u8) anyerror![]f32 {
        return allocator.alloc(f32, 0);
    }

    fn implDeinit(_: *anyopaque) void {}

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

// ── OpenAI-compatible embedding provider ──────────────────────────

pub const OpenAiEmbedding = struct {
    allocator: std.mem.Allocator,
    base_url: []const u8,
    api_key: []const u8,
    model: []const u8,
    dims: u32,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, base_url: []const u8, api_key: []const u8, model: []const u8, dims: u32) !*Self {
        const self_ = try allocator.create(Self);
        self_.* = .{
            .allocator = allocator,
            .base_url = try allocator.dupe(u8, base_url),
            .api_key = try allocator.dupe(u8, api_key),
            .model = try allocator.dupe(u8, model),
            .dims = dims,
        };
        return self_;
    }

    pub fn deinitSelf(self: *Self) void {
        self.allocator.free(self.base_url);
        self.allocator.free(self.api_key);
        self.allocator.free(self.model);
        self.allocator.destroy(self);
    }

    fn embeddingsUrl(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        // If URL already ends with /embeddings, use as-is
        if (std.mem.endsWith(u8, self.base_url, "/embeddings")) {
            return allocator.dupe(u8, self.base_url);
        }

        // If URL has a path component beyond /, append /embeddings
        // Otherwise append /v1/embeddings
        if (hasExplicitApiPath(self.base_url)) {
            return std.fmt.allocPrint(allocator, "{s}/embeddings", .{self.base_url});
        }

        return std.fmt.allocPrint(allocator, "{s}/v1/embeddings", .{self.base_url});
    }

    fn implName(_: *anyopaque) []const u8 {
        return "openai";
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

        // Build request body JSON
        var body_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer body_buf.deinit(allocator);

        try body_buf.appendSlice(allocator, "{\"model\":\"");
        // Escape model name
        for (self_.model) |ch| {
            if (ch == '"') {
                try body_buf.appendSlice(allocator, "\\\"");
            } else {
                try body_buf.append(allocator, ch);
            }
        }
        try body_buf.appendSlice(allocator, "\",\"input\":\"");
        // Escape text
        for (text) |ch| {
            switch (ch) {
                '"' => try body_buf.appendSlice(allocator, "\\\""),
                '\\' => try body_buf.appendSlice(allocator, "\\\\"),
                '\n' => try body_buf.appendSlice(allocator, "\\n"),
                '\r' => try body_buf.appendSlice(allocator, "\\r"),
                '\t' => try body_buf.appendSlice(allocator, "\\t"),
                else => {
                    if (ch < 0x20) {
                        var hex_buf: [6]u8 = undefined;
                        const hex = std.fmt.bufPrint(&hex_buf, "\\u{x:0>4}", .{ch}) catch continue;
                        try body_buf.appendSlice(allocator, hex);
                    } else {
                        try body_buf.append(allocator, ch);
                    }
                },
            }
        }
        try body_buf.appendSlice(allocator, "\"}");

        const url = try self_.embeddingsUrl(allocator);
        defer allocator.free(url);

        const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{self_.api_key});
        defer allocator.free(auth_header);

        var client = std.http.Client{ .allocator = allocator };
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(allocator);
        defer aw.deinit();

        const result = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body_buf.items,
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

        // Parse JSON to extract embedding array
        return parseEmbeddingResponse(allocator, resp_body);
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

// ── Helpers ───────────────────────────────────────────────────────

fn hasExplicitApiPath(url: []const u8) bool {
    // Find the path portion after the host
    const after_scheme = blk: {
        if (std.mem.indexOf(u8, url, "://")) |idx| {
            break :blk url[idx + 3 ..];
        }
        break :blk url;
    };
    const path_start = std.mem.indexOfScalar(u8, after_scheme, '/') orelse return false;
    const path = after_scheme[path_start..];
    // Trim trailing slashes
    const trimmed = std.mem.trimRight(u8, path, "/");
    return trimmed.len > 0 and !std.mem.eql(u8, trimmed, "/");
}

/// Parse an OpenAI-compatible embeddings API response to extract the embedding vector.
fn parseEmbeddingResponse(allocator: std.mem.Allocator, json_bytes: []const u8) ![]f32 {
    // We need to find the "embedding" array inside "data"[0]
    // Structure: {"data": [{"embedding": [0.1, 0.2, ...]}]}
    // Use std.json for parsing
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return error.InvalidEmbeddingResponse;
    defer parsed.deinit();

    const root = parsed.value;
    const data = root.object.get("data") orelse return error.InvalidEmbeddingResponse;
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
    for (emb_array.items, 0..) |val, i| {
        result[i] = switch (val) {
            .float => |f| @floatCast(f),
            .integer => |n| @floatFromInt(n),
            else => 0.0,
        };
    }
    return result;
}

// ── Factory ───────────────────────────────────────────────────────

/// Create an embedding provider by name.
/// Returns a NoopEmbedding for unknown providers.
pub fn createEmbeddingProvider(
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    api_key: ?[]const u8,
    model: []const u8,
    dims: u32,
) !EmbeddingProvider {
    if (std.mem.eql(u8, provider_name, "openai")) {
        var impl_ = try OpenAiEmbedding.init(
            allocator,
            "https://api.openai.com",
            api_key orelse "",
            model,
            dims,
        );
        return impl_.provider();
    }

    if (std.mem.startsWith(u8, provider_name, "custom:")) {
        const base_url = provider_name[7..];
        var impl_ = try OpenAiEmbedding.init(
            allocator,
            base_url,
            api_key orelse "",
            model,
            dims,
        );
        return impl_.provider();
    }

    // Default: noop (keyword-only search)
    var noop_inst = NoopEmbedding{};
    return noop_inst.provider();
}

// ── Tests ─────────────────────────────────────────────────────────

test "noop embedding name" {
    var noop = NoopEmbedding{};
    const p = noop.provider();
    try std.testing.expectEqualStrings("none", p.getName());
}

test "noop embedding dimensions" {
    var noop = NoopEmbedding{};
    const p = noop.provider();
    try std.testing.expectEqual(@as(u32, 0), p.getDimensions());
}

test "noop embedding returns empty" {
    var noop = NoopEmbedding{};
    const p = noop.provider();
    const result = try p.embed(std.testing.allocator, "hello");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "noop embedding empty text" {
    var noop = NoopEmbedding{};
    const p = noop.provider();
    const result = try p.embed(std.testing.allocator, "");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "hasExplicitApiPath" {
    try std.testing.expect(!hasExplicitApiPath("https://api.openai.com"));
    try std.testing.expect(!hasExplicitApiPath("https://api.openai.com/"));
    try std.testing.expect(hasExplicitApiPath("https://api.openai.com/v1"));
    try std.testing.expect(hasExplicitApiPath("https://api.example.com/v1/embeddings"));
}

test "parseEmbeddingResponse valid" {
    const json =
        \\{"data":[{"embedding":[0.1,0.2,0.3]}]}
    ;
    const result = try parseEmbeddingResponse(std.testing.allocator, json);
    defer std.testing.allocator.free(result);

    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expect(@abs(result[0] - 0.1) < 0.001);
    try std.testing.expect(@abs(result[1] - 0.2) < 0.001);
    try std.testing.expect(@abs(result[2] - 0.3) < 0.001);
}

test "parseEmbeddingResponse empty data" {
    const json =
        \\{"data":[]}
    ;
    const result = parseEmbeddingResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "parseEmbeddingResponse missing data" {
    const json =
        \\{"error":"bad request"}
    ;
    const result = parseEmbeddingResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "parseEmbeddingResponse integer values" {
    const json =
        \\{"data":[{"embedding":[1,2,3]}]}
    ;
    const result = try parseEmbeddingResponse(std.testing.allocator, json);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expect(@abs(result[0] - 1.0) < 0.001);
}

test "OpenAiEmbedding init and deinit" {
    var impl_ = try OpenAiEmbedding.init(
        std.testing.allocator,
        "https://api.openai.com",
        "test-key",
        "text-embedding-3-small",
        1536,
    );
    const p = impl_.provider();
    try std.testing.expectEqualStrings("openai", p.getName());
    try std.testing.expectEqual(@as(u32, 1536), p.getDimensions());
    p.deinit();
}

test "OpenAiEmbedding embeddingsUrl standard" {
    var impl_ = try OpenAiEmbedding.init(
        std.testing.allocator,
        "https://api.openai.com",
        "key",
        "model",
        1536,
    );
    defer impl_.deinitSelf();

    const url = try impl_.embeddingsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.openai.com/v1/embeddings", url);
}

test "OpenAiEmbedding embeddingsUrl with v1 path" {
    var impl_ = try OpenAiEmbedding.init(
        std.testing.allocator,
        "https://api.example.com/v1",
        "key",
        "model",
        1536,
    );
    defer impl_.deinitSelf();

    const url = try impl_.embeddingsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://api.example.com/v1/embeddings", url);
}

test "OpenAiEmbedding embeddingsUrl already has embeddings" {
    var impl_ = try OpenAiEmbedding.init(
        std.testing.allocator,
        "https://my-api.example.com/api/v2/embeddings",
        "key",
        "model",
        1536,
    );
    defer impl_.deinitSelf();

    const url = try impl_.embeddingsUrl(std.testing.allocator);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://my-api.example.com/api/v2/embeddings", url);
}
