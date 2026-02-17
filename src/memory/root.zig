//! Memory module — persistent knowledge storage for nullclaw.
//!
//! Mirrors ZeroClaw's memory architecture:
//!   - Memory vtable interface (store, recall, get, list, forget, count)
//!   - MemoryEntry, MemoryCategory
//!   - Multiple backends: SQLite (FTS5), Markdown (file-based), None (no-op)
//!   - ResponseCache for LLM response deduplication
//!   - Document chunking for large markdown files

const std = @import("std");

pub const sqlite = @import("sqlite.zig");
pub const markdown = @import("markdown.zig");
pub const none = @import("none.zig");
pub const cache = @import("cache.zig");
pub const chunker = @import("chunker.zig");
pub const embeddings = @import("embeddings.zig");
pub const vector = @import("vector.zig");
pub const hygiene = @import("hygiene.zig");
pub const snapshot = @import("snapshot.zig");

pub const SqliteMemory = sqlite.SqliteMemory;
pub const MarkdownMemory = markdown.MarkdownMemory;
pub const NoneMemory = none.NoneMemory;
pub const ResponseCache = cache.ResponseCache;
pub const Chunk = chunker.Chunk;
pub const chunkMarkdown = chunker.chunkMarkdown;
pub const EmbeddingProvider = embeddings.EmbeddingProvider;
pub const NoopEmbedding = embeddings.NoopEmbedding;
pub const cosineSimilarity = vector.cosineSimilarity;
pub const ScoredResult = vector.ScoredResult;
pub const hybridMerge = vector.hybridMerge;
pub const HygieneReport = hygiene.HygieneReport;
pub const exportSnapshot = snapshot.exportSnapshot;
pub const hydrateFromSnapshot = snapshot.hydrateFromSnapshot;
pub const shouldHydrate = snapshot.shouldHydrate;

// ── Memory categories ──────────────────────────────────────────────

pub const MemoryCategory = union(enum) {
    core,
    daily,
    conversation,
    custom: []const u8,

    pub fn toString(self: MemoryCategory) []const u8 {
        return switch (self) {
            .core => "core",
            .daily => "daily",
            .conversation => "conversation",
            .custom => |name| name,
        };
    }

    pub fn fromString(s: []const u8) MemoryCategory {
        if (std.mem.eql(u8, s, "core")) return .core;
        if (std.mem.eql(u8, s, "daily")) return .daily;
        if (std.mem.eql(u8, s, "conversation")) return .conversation;
        return .{ .custom = s };
    }

    pub fn eql(a: MemoryCategory, b: MemoryCategory) bool {
        const TagType = @typeInfo(MemoryCategory).@"union".tag_type.?;
        const tag_a: TagType = a;
        const tag_b: TagType = b;
        if (tag_a != tag_b) return false;
        if (tag_a == .custom) {
            return std.mem.eql(u8, a.custom, b.custom);
        }
        return true;
    }
};

// ── Memory entry ───────────────────────────────────────────────────

pub const MemoryEntry = struct {
    id: []const u8,
    key: []const u8,
    content: []const u8,
    category: MemoryCategory,
    timestamp: []const u8,
    session_id: ?[]const u8 = null,
    score: ?f64 = null,

    /// Free all allocated strings owned by this entry.
    pub fn deinit(self: *const MemoryEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.key);
        allocator.free(self.content);
        allocator.free(self.timestamp);
        if (self.session_id) |sid| allocator.free(sid);
        switch (self.category) {
            .custom => |name| allocator.free(name),
            else => {},
        }
    }
};

pub fn freeEntries(allocator: std.mem.Allocator, entries: []MemoryEntry) void {
    for (entries) |*entry| {
        entry.deinit(allocator);
    }
    allocator.free(entries);
}

// ── Memory vtable interface ────────────────────────────────────────

pub const Memory = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        name: *const fn (ptr: *anyopaque) []const u8,
        store: *const fn (ptr: *anyopaque, key: []const u8, content: []const u8, category: MemoryCategory) anyerror!void,
        recall: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, query: []const u8, limit: usize) anyerror![]MemoryEntry,
        get: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) anyerror!?MemoryEntry,
        list: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory) anyerror![]MemoryEntry,
        forget: *const fn (ptr: *anyopaque, key: []const u8) anyerror!bool,
        count: *const fn (ptr: *anyopaque) anyerror!usize,
        healthCheck: *const fn (ptr: *anyopaque) bool,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn name(self: Memory) []const u8 {
        return self.vtable.name(self.ptr);
    }

    pub fn store(self: Memory, key: []const u8, content: []const u8, category: MemoryCategory) !void {
        return self.vtable.store(self.ptr, key, content, category);
    }

    pub fn recall(self: Memory, allocator: std.mem.Allocator, query: []const u8, limit: usize) ![]MemoryEntry {
        return self.vtable.recall(self.ptr, allocator, query, limit);
    }

    pub fn get(self: Memory, allocator: std.mem.Allocator, key: []const u8) !?MemoryEntry {
        return self.vtable.get(self.ptr, allocator, key);
    }

    pub fn list(self: Memory, allocator: std.mem.Allocator, category: ?MemoryCategory) ![]MemoryEntry {
        return self.vtable.list(self.ptr, allocator, category);
    }

    pub fn forget(self: Memory, key: []const u8) !bool {
        return self.vtable.forget(self.ptr, key);
    }

    pub fn count(self: Memory) !usize {
        return self.vtable.count(self.ptr);
    }

    pub fn healthCheck(self: Memory) bool {
        return self.vtable.healthCheck(self.ptr);
    }

    pub fn deinit(self: Memory) void {
        self.vtable.deinit(self.ptr);
    }

    /// Hybrid search: combine keyword recall with optional vector similarity.
    /// This is a convenience method that wraps recall() and merges results.
    /// If an embedding provider is available, it can be used for vector search;
    /// otherwise falls back to keyword-only search via recall().
    pub fn search(self: Memory, allocator: std.mem.Allocator, query: []const u8, limit: usize) ![]MemoryEntry {
        // For now, delegate to recall() which uses FTS5/keyword search.
        // When embeddings are integrated at a higher level, this serves as
        // the standard entry point that can be upgraded to hybrid search.
        return self.recall(allocator, query, limit);
    }
};

// ── Backend kind classification ────────────────────────────────────

pub const MemoryBackendKind = enum {
    sqlite_backend,
    markdown_backend,
    none_backend,
    unknown,
};

pub const MemoryBackendProfile = struct {
    key: []const u8,
    label: []const u8,
    auto_save_default: bool,
    uses_sqlite_hygiene: bool,
    sqlite_based: bool,
};

pub fn classifyBackend(backend_name: []const u8) MemoryBackendKind {
    if (std.mem.eql(u8, backend_name, "sqlite")) return .sqlite_backend;
    if (std.mem.eql(u8, backend_name, "markdown")) return .markdown_backend;
    if (std.mem.eql(u8, backend_name, "none")) return .none_backend;
    return .unknown;
}

pub fn defaultBackendKey() []const u8 {
    return "sqlite";
}

pub const selectable_backends = [_]MemoryBackendProfile{
    .{
        .key = "sqlite",
        .label = "SQLite with FTS5 search (recommended)",
        .auto_save_default = true,
        .uses_sqlite_hygiene = true,
        .sqlite_based = true,
    },
    .{
        .key = "markdown",
        .label = "Markdown files — simple, human-readable",
        .auto_save_default = true,
        .uses_sqlite_hygiene = false,
        .sqlite_based = false,
    },
    .{
        .key = "none",
        .label = "None — disable persistent memory",
        .auto_save_default = false,
        .uses_sqlite_hygiene = false,
        .sqlite_based = false,
    },
};

// ── Factory ────────────────────────────────────────────────────────

pub const CreateError = error{
    SqliteOpenFailed,
    MigrationFailed,
    PrepareFailed,
    StepFailed,
    MarkdownInitFailed,
};

/// Create a memory backend by name. Caller owns the returned Memory and must call deinit().
/// For sqlite, pass the db_path (e.g. ":memory:" for tests, or a file path).
/// For markdown, pass workspace_dir as the path.
/// For none, path is ignored.
pub fn createMemory(allocator: std.mem.Allocator, backend_name: []const u8, path: [*:0]const u8) !Memory {
    const kind = classifyBackend(backend_name);
    return switch (kind) {
        .sqlite_backend => {
            var impl_ = try SqliteMemory.init(allocator, path);
            return impl_.memory();
        },
        .markdown_backend => {
            var impl_ = try MarkdownMemory.init(allocator, std.mem.span(path));
            return impl_.memory();
        },
        .none_backend => {
            var impl_ = NoneMemory.init();
            return impl_.memory();
        },
        .unknown => {
            // Fallback to markdown for unknown backends
            var impl_ = try MarkdownMemory.init(allocator, std.mem.span(path));
            return impl_.memory();
        },
    };
}

// ── Tests ──────────────────────────────────────────────────────────

test "MemoryCategory toString roundtrip" {
    const core: MemoryCategory = .core;
    try std.testing.expectEqualStrings("core", core.toString());

    const daily: MemoryCategory = .daily;
    try std.testing.expectEqualStrings("daily", daily.toString());

    const conversation: MemoryCategory = .conversation;
    try std.testing.expectEqualStrings("conversation", conversation.toString());

    const custom: MemoryCategory = .{ .custom = "project" };
    try std.testing.expectEqualStrings("project", custom.toString());
}

test "MemoryCategory fromString" {
    const core = MemoryCategory.fromString("core");
    try std.testing.expect(core.eql(.core));

    const daily = MemoryCategory.fromString("daily");
    try std.testing.expect(daily.eql(.daily));

    const conversation = MemoryCategory.fromString("conversation");
    try std.testing.expect(conversation.eql(.conversation));

    const custom = MemoryCategory.fromString("project");
    try std.testing.expectEqualStrings("project", custom.custom);
}

test "MemoryCategory equality" {
    const core: MemoryCategory = .core;
    try std.testing.expect(core.eql(.core));
    try std.testing.expect(!core.eql(.daily));
    const c1: MemoryCategory = .{ .custom = "a" };
    const c2: MemoryCategory = .{ .custom = "a" };
    const c3: MemoryCategory = .{ .custom = "b" };
    try std.testing.expect(c1.eql(c2));
    try std.testing.expect(!c1.eql(c3));
}

test "classifyBackend" {
    try std.testing.expect(classifyBackend("sqlite") == .sqlite_backend);
    try std.testing.expect(classifyBackend("markdown") == .markdown_backend);
    try std.testing.expect(classifyBackend("none") == .none_backend);
    try std.testing.expect(classifyBackend("redis") == .unknown);
}

test "selectable backends are ordered" {
    try std.testing.expect(selectable_backends.len == 3);
    try std.testing.expectEqualStrings("sqlite", selectable_backends[0].key);
    try std.testing.expectEqualStrings("markdown", selectable_backends[1].key);
    try std.testing.expectEqualStrings("none", selectable_backends[2].key);
}

test "defaultBackendKey is sqlite" {
    try std.testing.expectEqualStrings("sqlite", defaultBackendKey());
}

test "MemoryCategory custom toString" {
    const cat: MemoryCategory = .{ .custom = "my_project" };
    try std.testing.expectEqualStrings("my_project", cat.toString());
}

test "MemoryCategory fromString custom" {
    const cat = MemoryCategory.fromString("unknown_category");
    try std.testing.expectEqualStrings("unknown_category", cat.custom);
}

test "MemoryCategory eql different tags" {
    const core: MemoryCategory = .core;
    const daily: MemoryCategory = .daily;
    const conv: MemoryCategory = .conversation;
    try std.testing.expect(!core.eql(daily));
    try std.testing.expect(!core.eql(conv));
    try std.testing.expect(!daily.eql(conv));
}

test "classifyBackend unknown returns unknown" {
    try std.testing.expect(classifyBackend("redis") == .unknown);
    try std.testing.expect(classifyBackend("") == .unknown);
    try std.testing.expect(classifyBackend("SQLITE") == .unknown);
}

test "selectable backends sqlite is recommended" {
    try std.testing.expect(selectable_backends[0].sqlite_based);
    try std.testing.expect(selectable_backends[0].uses_sqlite_hygiene);
    try std.testing.expect(selectable_backends[0].auto_save_default);
}

test "selectable backends none has no auto save" {
    try std.testing.expect(!selectable_backends[2].auto_save_default);
    try std.testing.expect(!selectable_backends[2].sqlite_based);
    try std.testing.expect(!selectable_backends[2].uses_sqlite_hygiene);
}

test {
    _ = sqlite;
    _ = markdown;
    _ = none;
    _ = cache;
    _ = chunker;
    _ = embeddings;
    _ = vector;
    _ = hygiene;
    _ = snapshot;
}
