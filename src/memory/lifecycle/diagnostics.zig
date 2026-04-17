//! Memory doctor — diagnostics for the memory subsystem.
//!
//! Produces a DiagnosticReport by querying each component of the
//! MemoryRuntime: primary store, vector plane, outbox, cache,
//! retrieval engine, rollout policy, and lifecycle settings.

const std = @import("std");
const build_options = @import("build_options");
const root = @import("../root.zig");
const registry = @import("../engines/registry.zig");
const cache_mod = @import("cache.zig");
const rollout_mod = @import("rollout.zig");
const outbox_mod = @import("../vector/outbox.zig");
const vector_store_mod = @import("../vector/store.zig");
const retrieval_mod = @import("../retrieval/engine.zig");
const log = std.log.scoped(.memory_doctor);

// ── CacheStats ─────────────────────────────────────────────────────

pub const CacheStats = struct {
    count: usize,
    hits: u64,
    tokens_saved: u64,
};

// ── DiagnosticReport ───────────────────────────────────────────────

pub const DiagnosticReport = struct {
    backend_name: []const u8,
    backend_healthy: bool,
    entry_count: usize,
    capabilities: registry.BackendCapabilities,
    vector_store_active: bool,
    vector_entry_count: ?usize,
    outbox_active: bool,
    outbox_pending: ?usize,
    cache_active: bool,
    cache_stats: ?CacheStats,
    retrieval_sources: usize,
    rollout_mode: []const u8,
    session_store_active: bool,
    // Extended pipeline stages
    query_expansion_enabled: bool = false,
    adaptive_retrieval_enabled: bool = false,
    llm_reranker_enabled: bool = false,
    summarizer_enabled: bool = false,
    semantic_cache_active: bool = false,
};

// ── diagnose ───────────────────────────────────────────────────────

/// Populate a DiagnosticReport by inspecting all components of a MemoryRuntime.
pub fn diagnose(rt: *root.MemoryRuntime) DiagnosticReport {
    // Backend basics
    const backend_name = rt.memory.name();
    const backend_healthy = rt.memory.healthCheck();
    const entry_count: usize = rt.memory.count() catch 0;

    // Vector plane
    const vector_store_active = rt._vector_store != null;
    const vector_entry_count: ?usize = if (rt._vector_store) |vs| blk: {
        break :blk vs.count() catch null;
    } else null;

    // Outbox
    const outbox_active = rt._outbox != null;
    const outbox_pending: ?usize = if (rt._outbox) |ob|
        ob.pendingCount() catch null
    else
        null;

    // Cache
    const cache_active = rt.response_cache != null;
    const cache_stats: ?CacheStats = if (rt.response_cache) |rc| blk: {
        const s = rc.stats() catch break :blk null;
        break :blk .{
            .count = s.count,
            .hits = s.hits,
            .tokens_saved = s.tokens_saved,
        };
    } else null;

    // Retrieval engine
    const retrieval_sources: usize = if (rt._engine) |eng| eng.sources.items.len else 0;

    // Rollout
    const rollout_mode = @tagName(rt._rollout_policy.mode);

    // Session store
    const session_store_active = rt.session_store != null;

    // Extended pipeline stages
    const query_exp = if (rt._engine) |eng| eng.query_expansion_enabled else false;
    const adaptive_on = if (rt._engine) |eng| eng.adaptive_cfg.enabled else false;
    const llm_rerank = if (rt._engine) |eng| eng.llm_reranker_cfg.enabled else false;
    const summarizer_on = rt._summarizer_cfg.enabled;
    const sem_cache_on = rt._semantic_cache != null;

    log.info("doctor: backend={s} healthy={} entries={d} vector={} outbox={} cache={} sources={d} rollout={s} qexp={} adaptive={} reranker={} summarizer={} sem_cache={}", .{
        backend_name,
        backend_healthy,
        entry_count,
        vector_store_active,
        outbox_active,
        cache_active,
        retrieval_sources,
        rollout_mode,
        query_exp,
        adaptive_on,
        llm_rerank,
        summarizer_on,
        sem_cache_on,
    });

    return .{
        .backend_name = backend_name,
        .backend_healthy = backend_healthy,
        .entry_count = entry_count,
        .capabilities = rt.capabilities,
        .vector_store_active = vector_store_active,
        .vector_entry_count = vector_entry_count,
        .outbox_active = outbox_active,
        .outbox_pending = outbox_pending,
        .cache_active = cache_active,
        .cache_stats = cache_stats,
        .retrieval_sources = retrieval_sources,
        .rollout_mode = rollout_mode,
        .session_store_active = session_store_active,
        .query_expansion_enabled = query_exp,
        .adaptive_retrieval_enabled = adaptive_on,
        .llm_reranker_enabled = llm_rerank,
        .summarizer_enabled = summarizer_on,
        .semantic_cache_active = sem_cache_on,
    };
}

// ── formatReport ───────────────────────────────────────────────────

/// Render a DiagnosticReport as human-readable text.
/// Caller owns the returned slice.
pub fn formatReport(report: DiagnosticReport, allocator: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    var buf_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &buf);
    const w = &buf_writer.writer;

    try w.writeAll("=== Memory Doctor ===\n\n");

    // Backend section
    try w.writeAll("Backend\n");
    try w.print("  name:    {s}\n", .{report.backend_name});
    try w.print("  healthy: {}\n", .{report.backend_healthy});
    try w.print("  entries: {d}\n", .{report.entry_count});

    // Capabilities
    try w.writeAll("\nCapabilities\n");
    try w.print("  keyword_rank:    {}\n", .{report.capabilities.supports_keyword_rank});
    try w.print("  session_store:   {}\n", .{report.capabilities.supports_session_store});
    try w.print("  transactions:    {}\n", .{report.capabilities.supports_transactions});
    try w.print("  outbox:          {}\n", .{report.capabilities.supports_outbox});

    // Vector plane
    try w.writeAll("\nVector Plane\n");
    try w.print("  active:  {}\n", .{report.vector_store_active});
    if (report.vector_entry_count) |vc| {
        try w.print("  vectors: {d}\n", .{vc});
    } else {
        try w.writeAll("  vectors: n/a\n");
    }

    // Outbox
    try w.writeAll("\nOutbox\n");
    try w.print("  active:  {}\n", .{report.outbox_active});
    if (report.outbox_pending) |p| {
        try w.print("  pending: {d}\n", .{p});
    } else {
        try w.writeAll("  pending: n/a\n");
    }

    // Cache
    try w.writeAll("\nResponse Cache\n");
    try w.print("  active: {}\n", .{report.cache_active});
    if (report.cache_stats) |cs| {
        try w.print("  count:  {d}\n", .{cs.count});
        try w.print("  hits:   {d}\n", .{cs.hits});
        try w.print("  tokens saved: {d}\n", .{cs.tokens_saved});
    }

    // Retrieval
    try w.writeAll("\nRetrieval\n");
    try w.print("  sources: {d}\n", .{report.retrieval_sources});
    try w.print("  rollout: {s}\n", .{report.rollout_mode});

    // Session store
    try w.writeAll("\nSession Store\n");
    try w.print("  active: {}\n", .{report.session_store_active});

    // Extended pipeline
    try w.writeAll("\nPipeline Stages\n");
    try w.print("  query_expansion:  {}\n", .{report.query_expansion_enabled});
    try w.print("  adaptive:         {}\n", .{report.adaptive_retrieval_enabled});
    try w.print("  llm_reranker:     {}\n", .{report.llm_reranker_enabled});
    try w.print("  summarizer:       {}\n", .{report.summarizer_enabled});
    try w.print("  semantic_cache:   {}\n", .{report.semantic_cache_active});

    buf = buf_writer.toArrayList();
    return try buf.toOwnedSlice(allocator);
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

const test_resolved: root.ResolvedConfig = .{
    .primary_backend = "test",
    .retrieval_mode = "keyword",
    .vector_mode = "none",
    .embedding_provider = "none",
    .rollout_mode = "off",
    .vector_sync_mode = "best_effort",
    .hygiene_enabled = false,
    .snapshot_enabled = false,
    .cache_enabled = false,
    .semantic_cache_enabled = false,
    .summarizer_enabled = false,
    .source_count = 0,
    .fallback_policy = "degrade",
};

fn makeTestRuntime(allocator: std.mem.Allocator) !struct { rt: root.MemoryRuntime, mem_impl: *root.NoneMemory } {
    const impl_ = try allocator.create(root.NoneMemory);
    impl_.* = root.NoneMemory.init();
    impl_.allocator = allocator;
    return .{
        .rt = .{
            .memory = impl_.memory(),
            .session_store = null,
            .response_cache = null,
            .capabilities = .{
                .supports_keyword_rank = false,
                .supports_session_store = false,
                .supports_transactions = false,
                .supports_outbox = false,
            },
            .resolved = test_resolved,
            ._db_path = null,
            ._cache_db_path = null,
            ._engine = null,
            ._allocator = allocator,
        },
        .mem_impl = impl_,
    };
}

test "diagnose with none backend" {
    const allocator = testing.allocator;
    var setup = try makeTestRuntime(allocator);
    defer setup.rt.deinit();

    const report = diagnose(&setup.rt);

    try testing.expectEqualStrings("none", report.backend_name);
    try testing.expect(report.backend_healthy);
    try testing.expectEqual(@as(usize, 0), report.entry_count);
    try testing.expect(!report.vector_store_active);
    try testing.expect(report.vector_entry_count == null);
    try testing.expect(!report.outbox_active);
    try testing.expect(report.outbox_pending == null);
    try testing.expect(!report.cache_active);
    try testing.expect(report.cache_stats == null);
    try testing.expectEqual(@as(usize, 0), report.retrieval_sources);
    try testing.expect(!report.session_store_active);
}

test "diagnose with sqlite backend and entries" {
    if (!build_options.enable_sqlite) return error.SkipZigTest;

    const allocator = testing.allocator;
    const impl_ = try allocator.create(root.SqliteMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try root.SqliteMemory.init(allocator, ":memory:");
    impl_.owns_self = true;

    const mem = impl_.memory();

    // Store some entries
    try mem.store("k1", "content1", .core, null);
    try mem.store("k2", "content2", .core, null);

    var rt = root.MemoryRuntime{
        .memory = mem,
        .session_store = impl_.sessionStore(),
        .response_cache = null,
        .capabilities = .{
            .supports_keyword_rank = true,
            .supports_session_store = true,
            .supports_transactions = true,
            .supports_outbox = true,
        },
        .resolved = test_resolved,
        ._db_path = null,
        ._cache_db_path = null,
        ._engine = null,
        ._allocator = allocator,
    };
    defer rt.deinit();

    const report = diagnose(&rt);

    try testing.expectEqualStrings("sqlite", report.backend_name);
    try testing.expect(report.backend_healthy);
    try testing.expectEqual(@as(usize, 2), report.entry_count);
    try testing.expect(report.capabilities.supports_keyword_rank);
    try testing.expect(report.capabilities.supports_session_store);
    try testing.expect(report.session_store_active);
}

test "diagnose with response cache" {
    if (!build_options.enable_sqlite) return error.SkipZigTest;

    const allocator = testing.allocator;
    var setup = try makeTestRuntime(allocator);

    // Create a response cache
    const rc = try allocator.create(cache_mod.ResponseCache);
    rc.* = try cache_mod.ResponseCache.init(":memory:", 60, 100);
    setup.rt.response_cache = rc;
    defer setup.rt.deinit();

    // Add a cache entry
    var key_buf: [16]u8 = undefined;
    const key_hex = cache_mod.ResponseCache.cacheKeyHex(&key_buf, "gpt-4", null, "test");
    try rc.put(allocator, key_hex, "gpt-4", "response", 50);

    // Hit it once
    const r = try rc.get(allocator, key_hex);
    if (r) |resp| allocator.free(resp);

    const report = diagnose(&setup.rt);

    try testing.expect(report.cache_active);
    try testing.expect(report.cache_stats != null);
    const cs = report.cache_stats.?;
    try testing.expectEqual(@as(usize, 1), cs.count);
    try testing.expectEqual(@as(u64, 1), cs.hits);
    try testing.expectEqual(@as(u64, 50), cs.tokens_saved);
}

test "diagnose with vector store" {
    if (!build_options.enable_sqlite) return error.SkipZigTest;

    const allocator = testing.allocator;
    const sqlite_impl = try allocator.create(root.SqliteMemory);
    errdefer allocator.destroy(sqlite_impl);
    sqlite_impl.* = try root.SqliteMemory.init(allocator, ":memory:");
    sqlite_impl.owns_self = true;

    const vs = try allocator.create(vector_store_mod.SqliteSharedVectorStore);
    vs.* = vector_store_mod.SqliteSharedVectorStore.init(allocator, sqlite_impl.db);
    vs.owns_self = true; // vtable deinit will destroy

    // Upsert a vector
    const vs_iface = vs.store();
    try vs_iface.upsert("vec1", &[_]f32{ 1.0, 2.0, 3.0 });

    var rt = root.MemoryRuntime{
        .memory = sqlite_impl.memory(),
        .session_store = null,
        .response_cache = null,
        .capabilities = .{
            .supports_keyword_rank = true,
            .supports_session_store = true,
            .supports_transactions = true,
            .supports_outbox = true,
        },
        .resolved = test_resolved,
        ._db_path = null,
        ._cache_db_path = null,
        ._engine = null,
        ._allocator = allocator,
        ._vector_store = vs_iface,
    };
    defer rt.deinit();

    const report = diagnose(&rt);

    try testing.expect(report.vector_store_active);
    try testing.expect(report.vector_entry_count != null);
    try testing.expectEqual(@as(usize, 1), report.vector_entry_count.?);
}

test "diagnose with outbox" {
    if (!build_options.enable_sqlite) return error.SkipZigTest;

    const allocator = testing.allocator;
    const sqlite_impl = try allocator.create(root.SqliteMemory);
    errdefer allocator.destroy(sqlite_impl);
    sqlite_impl.* = try root.SqliteMemory.init(allocator, ":memory:");
    sqlite_impl.owns_self = true;

    const ob = try allocator.create(outbox_mod.VectorOutbox);
    ob.* = outbox_mod.VectorOutbox.init(allocator, sqlite_impl.db, 2);
    ob.owns_self = true; // deinit() destroys self when owned
    try ob.migrate();

    // Enqueue an item
    try ob.enqueue("key1", "upsert");

    var rt = root.MemoryRuntime{
        .memory = sqlite_impl.memory(),
        .session_store = null,
        .response_cache = null,
        .capabilities = .{
            .supports_keyword_rank = true,
            .supports_session_store = true,
            .supports_transactions = true,
            .supports_outbox = true,
        },
        .resolved = test_resolved,
        ._db_path = null,
        ._cache_db_path = null,
        ._engine = null,
        ._allocator = allocator,
        ._outbox = ob,
    };
    defer rt.deinit();

    const report = diagnose(&rt);

    try testing.expect(report.outbox_active);
    try testing.expect(report.outbox_pending != null);
    try testing.expectEqual(@as(usize, 1), report.outbox_pending.?);
}

test "diagnose with retrieval engine" {
    const allocator = testing.allocator;
    var setup = try makeTestRuntime(allocator);

    // Create a retrieval engine with a primary adapter
    const config_types = @import("../../config_types.zig");
    const eng = try allocator.create(retrieval_mod.RetrievalEngine);
    eng.* = retrieval_mod.RetrievalEngine.init(allocator, config_types.MemoryQueryConfig{});

    const primary = try allocator.create(retrieval_mod.PrimaryAdapter);
    primary.* = retrieval_mod.PrimaryAdapter.init(setup.rt.memory);
    primary.owns_self = true;
    primary.allocator = allocator;
    try eng.addSource(primary.adapter());

    setup.rt._engine = eng;
    defer setup.rt.deinit();

    const report = diagnose(&setup.rt);

    try testing.expectEqual(@as(usize, 1), report.retrieval_sources);
}

test "diagnose rollout mode" {
    const allocator = testing.allocator;
    var setup = try makeTestRuntime(allocator);
    defer setup.rt.deinit();

    // Default rollout mode is 'on'
    const report = diagnose(&setup.rt);
    try testing.expectEqualStrings("on", report.rollout_mode);
}

test "diagnose rollout mode shadow" {
    const allocator = testing.allocator;
    var setup = try makeTestRuntime(allocator);
    setup.rt._rollout_policy = .{ .mode = .shadow, .canary_percent = 0, .shadow_percent = 50 };
    defer setup.rt.deinit();

    const report = diagnose(&setup.rt);
    try testing.expectEqualStrings("shadow", report.rollout_mode);
}

test "diagnose rollout mode canary" {
    const allocator = testing.allocator;
    var setup = try makeTestRuntime(allocator);
    setup.rt._rollout_policy = .{ .mode = .canary, .canary_percent = 25, .shadow_percent = 0 };
    defer setup.rt.deinit();

    const report = diagnose(&setup.rt);
    try testing.expectEqualStrings("canary", report.rollout_mode);
}

test "diagnose rollout mode off" {
    const allocator = testing.allocator;
    var setup = try makeTestRuntime(allocator);
    setup.rt._rollout_policy = .{ .mode = .off, .canary_percent = 0, .shadow_percent = 0 };
    defer setup.rt.deinit();

    const report = diagnose(&setup.rt);
    try testing.expectEqualStrings("off", report.rollout_mode);
}

test "formatReport produces valid output" {
    const allocator = testing.allocator;
    var setup = try makeTestRuntime(allocator);
    defer setup.rt.deinit();

    const report = diagnose(&setup.rt);
    const text = try formatReport(report, allocator);
    defer allocator.free(text);

    // Check key sections present
    try testing.expect(std.mem.indexOf(u8, text, "=== Memory Doctor ===") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Backend") != null);
    try testing.expect(std.mem.indexOf(u8, text, "none") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Capabilities") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Vector Plane") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Outbox") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Response Cache") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Retrieval") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Session Store") != null);
}

test "formatReport with cache stats" {
    const allocator = testing.allocator;
    const report = DiagnosticReport{
        .backend_name = "sqlite",
        .backend_healthy = true,
        .entry_count = 42,
        .capabilities = .{
            .supports_keyword_rank = true,
            .supports_session_store = true,
            .supports_transactions = true,
            .supports_outbox = true,
        },
        .vector_store_active = true,
        .vector_entry_count = 10,
        .outbox_active = true,
        .outbox_pending = 3,
        .cache_active = true,
        .cache_stats = .{
            .count = 5,
            .hits = 20,
            .tokens_saved = 1000,
        },
        .retrieval_sources = 2,
        .rollout_mode = "canary",
        .session_store_active = true,
    };

    const text = try formatReport(report, allocator);
    defer allocator.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "42") != null);
    try testing.expect(std.mem.indexOf(u8, text, "canary") != null);
    try testing.expect(std.mem.indexOf(u8, text, "1000") != null);
    try testing.expect(std.mem.indexOf(u8, text, "tokens saved") != null);
}

test "formatReport without optional components" {
    const allocator = testing.allocator;
    const report = DiagnosticReport{
        .backend_name = "none",
        .backend_healthy = true,
        .entry_count = 0,
        .capabilities = .{
            .supports_keyword_rank = false,
            .supports_session_store = false,
            .supports_transactions = false,
            .supports_outbox = false,
        },
        .vector_store_active = false,
        .vector_entry_count = null,
        .outbox_active = false,
        .outbox_pending = null,
        .cache_active = false,
        .cache_stats = null,
        .retrieval_sources = 0,
        .rollout_mode = "off",
        .session_store_active = false,
    };

    const text = try formatReport(report, allocator);
    defer allocator.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "n/a") != null);
    try testing.expect(std.mem.indexOf(u8, text, "off") != null);
}

// ── R3 Tests ──────────────────────────────────────────────────────

test "R3: diagnose on empty system returns valid report with formatReport" {
    const allocator = testing.allocator;
    var setup = try makeTestRuntime(allocator);
    defer setup.rt.deinit();

    const report = diagnose(&setup.rt);

    // Verify defaults
    try testing.expectEqualStrings("none", report.backend_name);
    try testing.expect(report.backend_healthy);
    try testing.expectEqual(@as(usize, 0), report.entry_count);
    try testing.expect(!report.cache_active);
    try testing.expect(!report.vector_store_active);
    try testing.expect(!report.outbox_active);
    try testing.expect(!report.session_store_active);
    try testing.expectEqual(@as(usize, 0), report.retrieval_sources);
    try testing.expect(!report.query_expansion_enabled);
    try testing.expect(!report.adaptive_retrieval_enabled);
    try testing.expect(!report.llm_reranker_enabled);
    try testing.expect(!report.semantic_cache_active);

    // Format it — should not crash and should produce non-empty output
    const text = try formatReport(report, allocator);
    defer allocator.free(text);
    try testing.expect(text.len > 0);

    // Check Pipeline Stages section is present (extended fields)
    try testing.expect(std.mem.indexOf(u8, text, "Pipeline Stages") != null);
    try testing.expect(std.mem.indexOf(u8, text, "query_expansion") != null);
    try testing.expect(std.mem.indexOf(u8, text, "semantic_cache") != null);
}
