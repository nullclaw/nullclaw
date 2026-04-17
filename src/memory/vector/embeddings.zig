//! Embedding providers — convert text to vectors for semantic search.
//!
//! Mirrors ZeroClaw's embeddings module:
//!   - EmbeddingProvider vtable interface
//!   - NoopEmbedding (returns empty/zero vectors, keyword-only fallback)
//!   - OpenAiEmbedding (HTTP POST to /v1/embeddings)
//!   - Factory function: createEmbeddingProvider()

const std = @import("std");
const std_compat = @import("compat");
const build_options = @import("build_options");
const http_util = @import("../../http_util.zig");
const appendJsonEscaped = @import("../../util.zig").appendJsonEscaped;
const GeminiEmbedding = @import("embeddings_gemini.zig").GeminiEmbedding;
const VoyageEmbedding = @import("embeddings_voyage.zig").VoyageEmbedding;
const OllamaEmbedding = @import("embeddings_ollama.zig").OllamaEmbedding;
const net_security = @import("../../net_security.zig");

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
    /// Allocator used to free the heap allocation in deinit.
    /// Set to null only when the instance is stack-allocated by the caller.
    allocator: ?std.mem.Allocator = null,

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

    fn implDeinit(ptr: *anyopaque) void {
        const self_: *Self = @ptrCast(@alignCast(ptr));
        if (self_.allocator) |alloc| {
            alloc.destroy(self_);
        }
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

// ── OpenAI-compatible embedding provider ──────────────────────────

pub const OpenAiEmbedding = struct {
    allocator: std.mem.Allocator,
    base_url: []const u8,
    api_key: []const u8,
    model: []const u8,
    dims: u32,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, base_url: []const u8, api_key: []const u8, model: []const u8, dims: u32) !*Self {
        try validateEmbeddingBaseUrl(base_url);

        const self_ = try allocator.create(Self);
        errdefer allocator.destroy(self_);

        const owned_url = try allocator.dupe(u8, base_url);
        errdefer allocator.free(owned_url);
        const owned_key = try allocator.dupe(u8, api_key);
        errdefer allocator.free(owned_key);
        const owned_model = try allocator.dupe(u8, model);

        self_.* = .{
            .allocator = allocator,
            .base_url = owned_url,
            .api_key = owned_key,
            .model = owned_model,
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
        try appendJsonEscaped(&body_buf, allocator, self_.model);
        try body_buf.appendSlice(allocator, "\",\"input\":\"");
        try appendJsonEscaped(&body_buf, allocator, text);
        try body_buf.appendSlice(allocator, "\"}");

        const url = try self_.embeddingsUrl(allocator);
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
    const trimmed = std_compat.mem.trimRight(u8, path, "/");
    return trimmed.len > 0 and !std.mem.eql(u8, trimmed, "/");
}

/// Require a parseable HTTP(S) endpoint. Plain HTTP is only allowed on local hosts.
fn validateEmbeddingBaseUrl(url: []const u8) !void {
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

/// Parse an OpenAI-compatible embeddings API response to extract the embedding vector.
fn parseEmbeddingResponse(allocator: std.mem.Allocator, json_bytes: []const u8) ![]f32 {
    // We need to find the "embedding" array inside "data"[0]
    // Structure: {"data": [{"embedding": [0.1, 0.2, ...]}]}
    // Use std.json for parsing
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

// ── Embedding cache ───────────────────────────────────────────────

const sqlite_mod = if (build_options.enable_sqlite) @import("../engines/sqlite.zig") else @import("../engines/sqlite_disabled.zig");
const SqliteMemory = sqlite_mod.SqliteMemory;
const c = sqlite_mod.c;
const SQLITE_STATIC = sqlite_mod.SQLITE_STATIC;

/// Compute a content hash for embedding cache lookups.
/// SHA-256 the content, take first 8 bytes, format as 16 hex characters.
///
/// IMPORTANT: For cache correctness, callers should use `contentHashWithModel`
/// instead, which includes the model name in the hash. Using this function
/// alone risks returning stale embeddings if the embedding model changes.
pub fn contentHash(content: []const u8) [16]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(content, &digest, .{});

    var result: [16]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (0..8) |i| {
        result[i * 2] = hex_chars[digest[i] >> 4];
        result[i * 2 + 1] = hex_chars[digest[i] & 0x0f];
    }
    return result;
}

/// Compute a content hash that includes the model name.
/// This prevents returning stale cached embeddings when the model changes.
pub fn contentHashWithModel(content: []const u8, model: []const u8) [16]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(model);
    hasher.update("\x00"); // separator to prevent "modelAcontentB" == "modelAcontent" + "B"
    hasher.update(content);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    var result: [16]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (0..8) |i| {
        result[i * 2] = hex_chars[digest[i] >> 4];
        result[i * 2 + 1] = hex_chars[digest[i] & 0x0f];
    }
    return result;
}

/// Cache an embedding vector for a content hash.
/// Serializes the f32 slice as a JSON array and stores it in embedding_cache.
pub fn cacheEmbedding(db: *SqliteMemory, content_hash: []const u8, embedding: []const f32) !void {
    // Serialize embedding as JSON array text
    var json_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer json_buf.deinit(db.allocator);

    try json_buf.append(db.allocator, '[');
    for (embedding, 0..) |val, i| {
        if (i > 0) try json_buf.append(db.allocator, ',');
        var tmp: [32]u8 = undefined;
        const s = std.fmt.bufPrint(&tmp, "{d}", .{val}) catch return error.FormatError;
        try json_buf.appendSlice(db.allocator, s);
    }
    try json_buf.append(db.allocator, ']');

    const sql = "INSERT OR REPLACE INTO embedding_cache (content_hash, embedding) VALUES (?1, ?2)";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(db.db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    _ = c.sqlite3_bind_text(stmt, 1, content_hash.ptr, @intCast(content_hash.len), SQLITE_STATIC);
    _ = c.sqlite3_bind_text(stmt, 2, json_buf.items.ptr, @intCast(json_buf.items.len), SQLITE_STATIC);

    rc = c.sqlite3_step(stmt);
    if (rc != c.SQLITE_DONE) return error.StepFailed;
}

/// Retrieve a cached embedding by content hash.
/// Returns null if not found. Caller owns the returned slice.
pub fn getCachedEmbedding(db: *SqliteMemory, content_hash: []const u8, allocator: std.mem.Allocator) !?[]f32 {
    const sql = "SELECT embedding FROM embedding_cache WHERE content_hash = ?1";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(db.db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    _ = c.sqlite3_bind_text(stmt, 1, content_hash.ptr, @intCast(content_hash.len), SQLITE_STATIC);

    rc = c.sqlite3_step(stmt);
    if (rc != c.SQLITE_ROW) return null;

    // Read the JSON text from the blob/text column
    const raw = c.sqlite3_column_text(stmt, 0);
    const len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    if (raw == null or len == 0) return null;

    const json_text: []const u8 = @as([*]const u8, @ptrCast(raw))[0..len];

    // Parse JSON array → []f32
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch return error.InvalidEmbeddingCache;
    defer parsed.deinit();

    const arr = switch (parsed.value) {
        .array => |a| a,
        else => return error.InvalidEmbeddingCache,
    };

    const result = try allocator.alloc(f32, arr.items.len);
    errdefer allocator.free(result);

    for (arr.items, 0..) |val, i| {
        result[i] = switch (val) {
            .float => |f| @floatCast(f),
            .integer => |n| @floatFromInt(n),
            else => return error.InvalidEmbeddingCache,
        };
    }
    return result;
}

/// Prune the embedding cache, keeping only the newest `max_entries` entries.
/// Returns the number of entries deleted.
pub fn pruneEmbeddingCache(db: *SqliteMemory, max_entries: u32) !u32 {
    // First check the count
    const count_sql = "SELECT COUNT(*) FROM embedding_cache";
    var count_stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(db.db, count_sql, -1, &count_stmt, null);
    if (rc != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(count_stmt);

    rc = c.sqlite3_step(count_stmt);
    if (rc != c.SQLITE_ROW) return 0;

    const total: u32 = @intCast(c.sqlite3_column_int(count_stmt, 0));
    if (total <= max_entries) return 0;

    // Delete oldest entries (those with the earliest created_at) beyond max_entries
    const delete_sql =
        "DELETE FROM embedding_cache WHERE content_hash IN (" ++
        "SELECT content_hash FROM embedding_cache ORDER BY created_at ASC LIMIT ?1" ++
        ")";
    var del_stmt: ?*c.sqlite3_stmt = null;
    rc = c.sqlite3_prepare_v2(db.db, delete_sql, -1, &del_stmt, null);
    if (rc != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(del_stmt);

    const to_delete = total - max_entries;
    _ = c.sqlite3_bind_int(del_stmt, 1, @intCast(to_delete));

    rc = c.sqlite3_step(del_stmt);
    if (rc != c.SQLITE_DONE) return error.StepFailed;

    return @intCast(c.sqlite3_changes(db.db));
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

    if (std.mem.eql(u8, provider_name, "gemini")) {
        var impl_ = try GeminiEmbedding.init(
            allocator,
            api_key orelse "",
            if (model.len > 0) model else null,
            null,
            if (dims > 0) dims else null,
        );
        return impl_.provider();
    }

    if (std.mem.eql(u8, provider_name, "voyage")) {
        var impl_ = try VoyageEmbedding.init(
            allocator,
            api_key orelse "",
            if (model.len > 0) model else null,
            null,
            if (dims > 0) dims else null,
        );
        return impl_.provider();
    }

    if (std.mem.eql(u8, provider_name, "ollama")) {
        var impl_ = try OllamaEmbedding.init(
            allocator,
            if (model.len > 0) model else null,
            null,
            if (dims > 0) dims else null,
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

    // Default: noop (keyword-only search) — heap-allocate so the vtable pointer stays valid.
    const noop_inst = try allocator.create(NoopEmbedding);
    noop_inst.* = .{ .allocator = allocator };
    return noop_inst.provider();
}

// ── Tests ─────────────────────────────────────────────────────────

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

test "OpenAiEmbedding init rejects insecure remote http url" {
    const result = OpenAiEmbedding.init(
        std.testing.allocator,
        "http://example.com",
        "test-key",
        "text-embedding-3-small",
        1536,
    );
    try std.testing.expectError(error.InsecureEmbeddingApiUrl, result);
}

test "OpenAiEmbedding init accepts localhost http url" {
    var impl_ = try OpenAiEmbedding.init(
        std.testing.allocator,
        "http://127.0.0.1:11434",
        "test-key",
        "text-embedding-3-small",
        1536,
    );
    const p = impl_.provider();
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

// Regression test: createEmbeddingProvider("none") must heap-allocate NoopEmbedding
// so the returned EmbeddingProvider vtable pointer remains valid after the factory returns.
test "createEmbeddingProvider noop is heap allocated and deinit frees memory" {
    const p = try createEmbeddingProvider(std.testing.allocator, "none", null, "", 0);
    // Use the provider — pointer must still be valid here (no dangling ptr).
    try std.testing.expectEqualStrings("none", p.getName());
    try std.testing.expectEqual(@as(u32, 0), p.getDimensions());
    const vec = try p.embed(std.testing.allocator, "hello");
    defer std.testing.allocator.free(vec);
    try std.testing.expectEqual(@as(usize, 0), vec.len);
    // deinit must free the heap allocation without crashing (verified by allocator leak check).
    p.deinit();
}

test "createEmbeddingProvider openai is heap allocated and deinit frees memory" {
    const p = try createEmbeddingProvider(std.testing.allocator, "openai", "test-key", "text-embedding-3-small", 1536);
    try std.testing.expectEqualStrings("openai", p.getName());
    try std.testing.expectEqual(@as(u32, 1536), p.getDimensions());
    // deinit must free all allocations without crashing.
    p.deinit();
}

test "createEmbeddingProvider gemini" {
    const p = try createEmbeddingProvider(std.testing.allocator, "gemini", "test-key", "", 0);
    try std.testing.expectEqualStrings("gemini", p.getName());
    try std.testing.expectEqual(@as(u32, 768), p.getDimensions());
    p.deinit();
}

test "createEmbeddingProvider gemini with custom model" {
    const p = try createEmbeddingProvider(std.testing.allocator, "gemini", "test-key", "gemini-embedding-001", 1024);
    try std.testing.expectEqualStrings("gemini", p.getName());
    try std.testing.expectEqual(@as(u32, 1024), p.getDimensions());
    p.deinit();
}

test "createEmbeddingProvider voyage" {
    const p = try createEmbeddingProvider(std.testing.allocator, "voyage", "test-key", "", 0);
    try std.testing.expectEqualStrings("voyage", p.getName());
    try std.testing.expectEqual(@as(u32, 512), p.getDimensions());
    p.deinit();
}

test "createEmbeddingProvider voyage with custom model" {
    const p = try createEmbeddingProvider(std.testing.allocator, "voyage", "test-key", "voyage-3", 1024);
    try std.testing.expectEqualStrings("voyage", p.getName());
    try std.testing.expectEqual(@as(u32, 1024), p.getDimensions());
    p.deinit();
}

test "createEmbeddingProvider ollama" {
    const p = try createEmbeddingProvider(std.testing.allocator, "ollama", null, "", 0);
    try std.testing.expectEqualStrings("ollama", p.getName());
    try std.testing.expectEqual(@as(u32, 768), p.getDimensions());
    p.deinit();
}

test "createEmbeddingProvider ollama with custom model" {
    const p = try createEmbeddingProvider(std.testing.allocator, "ollama", null, "mxbai-embed-large", 1024);
    try std.testing.expectEqualStrings("ollama", p.getName());
    try std.testing.expectEqual(@as(u32, 1024), p.getDimensions());
    p.deinit();
}

test "createEmbeddingProvider custom rejects insecure remote http url" {
    const provider = createEmbeddingProvider(
        std.testing.allocator,
        "custom:http://example.com/v1",
        "test-key",
        "text-embedding-3-small",
        1536,
    );
    try std.testing.expectError(error.InsecureEmbeddingApiUrl, provider);
}

// ── Embedding cache tests ─────────────────────────────────────────

test "contentHash produces 16 hex chars" {
    const hash = contentHash("hello world");
    try std.testing.expectEqual(@as(usize, 16), hash.len);
    // Verify all characters are hex
    for (hash) |ch| {
        try std.testing.expect((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'));
    }
}

test "contentHash is deterministic" {
    const h1 = contentHash("test content");
    const h2 = contentHash("test content");
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "contentHash differs for different inputs" {
    const h1 = contentHash("alpha");
    const h2 = contentHash("beta");
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "contentHashWithModel differs by model" {
    const h1 = contentHashWithModel("same text", "text-embedding-3-small");
    const h2 = contentHashWithModel("same text", "text-embedding-3-large");
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "contentHashWithModel same model same content is deterministic" {
    const h1 = contentHashWithModel("hello", "model-a");
    const h2 = contentHashWithModel("hello", "model-a");
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "contentHashWithModel differs from contentHash" {
    const h1 = contentHash("hello");
    const h2 = contentHashWithModel("hello", "");
    // Even with empty model, the null separator makes them differ
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "cacheEmbedding and getCachedEmbedding roundtrip" {
    var mem = SqliteMemory.init(std.testing.allocator, ":memory:") catch return;
    defer mem.deinit();

    const embedding = [_]f32{ 0.1, 0.2, 0.3, -0.5 };
    const hash = contentHash("some text");

    try cacheEmbedding(&mem, &hash, &embedding);

    const cached = try getCachedEmbedding(&mem, &hash, std.testing.allocator);
    try std.testing.expect(cached != null);
    defer std.testing.allocator.free(cached.?);

    try std.testing.expectEqual(@as(usize, 4), cached.?.len);
    try std.testing.expect(@abs(cached.?[0] - 0.1) < 0.001);
    try std.testing.expect(@abs(cached.?[1] - 0.2) < 0.001);
    try std.testing.expect(@abs(cached.?[2] - 0.3) < 0.001);
    try std.testing.expect(@abs(cached.?[3] - (-0.5)) < 0.001);
}

test "getCachedEmbedding returns null for missing hash" {
    var mem = SqliteMemory.init(std.testing.allocator, ":memory:") catch return;
    defer mem.deinit();

    const cached = try getCachedEmbedding(&mem, "nonexistent_hash", std.testing.allocator);
    try std.testing.expect(cached == null);
}

test "cacheEmbedding overwrites existing entry" {
    var mem = SqliteMemory.init(std.testing.allocator, ":memory:") catch return;
    defer mem.deinit();

    const hash = contentHash("overwrite test");
    const emb1 = [_]f32{ 1.0, 2.0 };
    const emb2 = [_]f32{ 3.0, 4.0, 5.0 };

    try cacheEmbedding(&mem, &hash, &emb1);
    try cacheEmbedding(&mem, &hash, &emb2);

    const cached = try getCachedEmbedding(&mem, &hash, std.testing.allocator);
    try std.testing.expect(cached != null);
    defer std.testing.allocator.free(cached.?);

    // Should have the second embedding (3 elements, not 2)
    try std.testing.expectEqual(@as(usize, 3), cached.?.len);
    try std.testing.expect(@abs(cached.?[0] - 3.0) < 0.001);
}

test "pruneEmbeddingCache deletes oldest entries" {
    var mem = SqliteMemory.init(std.testing.allocator, ":memory:") catch return;
    defer mem.deinit();

    // Insert 5 entries with distinct hashes
    for (0..5) |i| {
        var content_buf: [32]u8 = undefined;
        const content = std.fmt.bufPrint(&content_buf, "content_{d}", .{i}) catch continue;
        const hash = contentHash(content);
        const emb = [_]f32{@floatFromInt(i)};
        try cacheEmbedding(&mem, &hash, &emb);
    }

    // Prune to keep only 3
    const deleted = try pruneEmbeddingCache(&mem, 3);
    try std.testing.expectEqual(@as(u32, 2), deleted);

    // Verify count is now 3
    const count_sql = "SELECT COUNT(*) FROM embedding_cache";
    var stmt: ?*c.sqlite3_stmt = null;
    var rc = c.sqlite3_prepare_v2(mem.db, count_sql, -1, &stmt, null);
    try std.testing.expectEqual(c.SQLITE_OK, rc);
    defer _ = c.sqlite3_finalize(stmt);
    rc = c.sqlite3_step(stmt);
    try std.testing.expectEqual(c.SQLITE_ROW, rc);
    try std.testing.expectEqual(@as(i32, 3), c.sqlite3_column_int(stmt, 0));
}

test "pruneEmbeddingCache returns 0 when under limit" {
    var mem = SqliteMemory.init(std.testing.allocator, ":memory:") catch return;
    defer mem.deinit();

    const hash = contentHash("only one");
    const emb = [_]f32{1.0};
    try cacheEmbedding(&mem, &hash, &emb);

    const deleted = try pruneEmbeddingCache(&mem, 10);
    try std.testing.expectEqual(@as(u32, 0), deleted);
}

test "cacheEmbedding empty vector" {
    var mem = SqliteMemory.init(std.testing.allocator, ":memory:") catch return;
    defer mem.deinit();

    const hash = contentHash("empty vec");
    const emb = [_]f32{};
    try cacheEmbedding(&mem, &hash, &emb);

    const cached = try getCachedEmbedding(&mem, &hash, std.testing.allocator);
    try std.testing.expect(cached != null);
    defer std.testing.allocator.free(cached.?);
    try std.testing.expectEqual(@as(usize, 0), cached.?.len);
}

// ── R3 regression tests ───────────────────────────────────────────

test "parseEmbeddingResponse valid extracts correct f32 array" {
    const json =
        \\{"data":[{"embedding":[0.5,-0.25,1.0,0.0]}]}
    ;
    const result = try parseEmbeddingResponse(std.testing.allocator, json);
    defer std.testing.allocator.free(result);

    try std.testing.expectEqual(@as(usize, 4), result.len);
    try std.testing.expect(@abs(result[0] - 0.5) < 0.0001);
    try std.testing.expect(@abs(result[1] - (-0.25)) < 0.0001);
    try std.testing.expect(@abs(result[2] - 1.0) < 0.0001);
    try std.testing.expect(@abs(result[3] - 0.0) < 0.0001);
}

test "parseEmbeddingResponse root is array not object returns error" {
    const json =
        \\[{"embedding":[0.1,0.2]}]
    ;
    const result = parseEmbeddingResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "parseEmbeddingResponse string value in embedding returns error not silent 0" {
    const json =
        \\{"data":[{"embedding":[0.1,"bad",0.3]}]}
    ;
    const result = parseEmbeddingResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "parseEmbeddingResponse null value in embedding returns error" {
    const json =
        \\{"data":[{"embedding":[0.1,null,0.3]}]}
    ;
    const result = parseEmbeddingResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "parseEmbeddingResponse bool value in embedding returns error" {
    const json =
        \\{"data":[{"embedding":[0.1,true,0.3]}]}
    ;
    const result = parseEmbeddingResponse(std.testing.allocator, json);
    try std.testing.expectError(error.InvalidEmbeddingResponse, result);
}

test "contentHashWithModel different models same text produce different hashes" {
    const h1 = contentHashWithModel("identical text", "model-alpha");
    const h2 = contentHashWithModel("identical text", "model-beta");
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "contentHashWithModel same model different text produce different hashes" {
    const h1 = contentHashWithModel("text one", "model-x");
    const h2 = contentHashWithModel("text two", "model-x");
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}
