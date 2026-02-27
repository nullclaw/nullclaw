//! Memory module — persistent knowledge storage for nullclaw.
//!
//! Mirrors ZeroClaw's memory architecture:
//!   - Memory vtable interface (store, recall, get, list, forget, count)
//!   - MemoryEntry, MemoryCategory
//!   - Multiple backends: SQLite (FTS5), Markdown (file-based), None (no-op)
//!   - ResponseCache for LLM response deduplication
//!   - Document chunking for large markdown files

const std = @import("std");
const build_options = @import("build_options");
const config_types = @import("../config_types.zig");
const provider_api_key = @import("../providers/api_key.zig");
const log = std.log.scoped(.memory);

// engines/ (Layer A: Primary Store)
pub const sqlite = if (build_options.enable_sqlite) @import("engines/sqlite.zig") else @import("engines/sqlite_disabled.zig");
pub const markdown = @import("engines/markdown.zig");
pub const none = @import("engines/none.zig");
pub const memory_lru = @import("engines/memory_lru.zig");
pub const lucid = if (build_options.enable_memory_lucid) @import("engines/lucid.zig") else struct {
    pub const LucidMemory = struct {};
};
pub const postgres = if (build_options.enable_postgres) @import("engines/postgres.zig") else struct {};
pub const redis = @import("engines/redis.zig");
pub const lancedb = if (build_options.enable_memory_lancedb) @import("engines/lancedb.zig") else struct {
    pub const LanceDbMemory = struct {};
};
pub const api = @import("engines/api.zig");
pub const registry = @import("engines/registry.zig");

// retrieval/ (Layer B: Retrieval Engine)
pub const retrieval = @import("retrieval/engine.zig");
pub const retrieval_qmd = @import("retrieval/qmd.zig");
pub const rrf = @import("retrieval/rrf.zig");
pub const query_expansion = @import("retrieval/query_expansion.zig");
pub const temporal_decay = @import("retrieval/temporal_decay.zig");
pub const mmr = @import("retrieval/mmr.zig");
pub const adaptive = @import("retrieval/adaptive.zig");
pub const llm_reranker = @import("retrieval/llm_reranker.zig");

// vector/ (Layer C: Vector Plane)
pub const vector = @import("vector/math.zig");
pub const vector_store = @import("vector/store.zig");
pub const embeddings = @import("vector/embeddings.zig");
pub const embeddings_gemini = @import("vector/embeddings_gemini.zig");
pub const embeddings_voyage = @import("vector/embeddings_voyage.zig");
pub const embeddings_ollama = @import("vector/embeddings_ollama.zig");
pub const provider_router = @import("vector/provider_router.zig");
pub const store_qdrant = @import("vector/store_qdrant.zig");
pub const store_pgvector = @import("vector/store_pgvector.zig");
pub const circuit_breaker = @import("vector/circuit_breaker.zig");
pub const outbox = @import("vector/outbox.zig");
pub const chunker = @import("vector/chunker.zig");

// lifecycle/ (Layer D: Runtime Orchestrator)
pub const cache = @import("lifecycle/cache.zig");
pub const semantic_cache = @import("lifecycle/semantic_cache.zig");
pub const hygiene = @import("lifecycle/hygiene.zig");
pub const snapshot = @import("lifecycle/snapshot.zig");
pub const rollout = @import("lifecycle/rollout.zig");
pub const migrate = @import("lifecycle/migrate.zig");
pub const diagnostics = @import("lifecycle/diagnostics.zig");
pub const summarizer = @import("lifecycle/summarizer.zig");

pub const SqliteMemory = sqlite.SqliteMemory;
pub const MarkdownMemory = markdown.MarkdownMemory;
pub const NoneMemory = none.NoneMemory;
pub const InMemoryLruMemory = memory_lru.InMemoryLruMemory;
pub const LucidMemory = lucid.LucidMemory;
pub const PostgresMemory = if (build_options.enable_postgres) postgres.PostgresMemory else struct {};
pub const RedisMemory = redis.RedisMemory;
pub const LanceDbMemory = lancedb.LanceDbMemory;
pub const ApiMemory = api.ApiMemory;
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
pub const BackendDescriptor = registry.BackendDescriptor;
pub const BackendConfig = registry.BackendConfig;
pub const BackendInstance = registry.BackendInstance;
pub const BackendCapabilities = registry.BackendCapabilities;
pub const findBackend = registry.findBackend;
pub const RetrievalCandidate = retrieval.RetrievalCandidate;
pub const RetrievalSourceAdapter = retrieval.RetrievalSourceAdapter;
pub const PrimaryAdapter = retrieval.PrimaryAdapter;
pub const RetrievalEngine = retrieval.RetrievalEngine;
pub const QmdAdapter = retrieval_qmd.QmdAdapter;
pub const rrfMerge = rrf.rrfMerge;
pub const applyTemporalDecay = temporal_decay.applyTemporalDecay;
pub const VectorStore = vector_store.VectorStore;
pub const VectorResult = vector_store.VectorResult;
pub const HealthStatus = vector_store.HealthStatus;
pub const SqliteSharedVectorStore = vector_store.SqliteSharedVectorStore;
pub const SqliteSidecarVectorStore = vector_store.SqliteSidecarVectorStore;
pub const QdrantVectorStore = store_qdrant.QdrantVectorStore;
pub const freeVectorResults = vector_store.freeVectorResults;
pub const VectorOutbox = outbox.VectorOutbox;
pub const CircuitBreaker = circuit_breaker.CircuitBreaker;
pub const RolloutMode = rollout.RolloutMode;
pub const RolloutPolicy = rollout.RolloutPolicy;
pub const RolloutDecision = rollout.RolloutDecision;
pub const SqliteSourceEntry = migrate.SqliteSourceEntry;
pub const readBrainDb = migrate.readBrainDb;
pub const freeSqliteEntries = migrate.freeSqliteEntries;
pub const DiagnosticReport = diagnostics.DiagnosticReport;
pub const CacheStats = diagnostics.CacheStats;
pub const diagnoseRuntime = diagnostics.diagnose;
pub const formatDiagnosticReport = diagnostics.formatReport;

// Extended retrieval stages
pub const expandQuery = query_expansion.expandQuery;
pub const ExpandedQuery = query_expansion.ExpandedQuery;
pub const analyzeQuery = adaptive.analyzeQuery;
pub const AdaptiveConfig = adaptive.AdaptiveConfig;
pub const QueryAnalysis = adaptive.QueryAnalysis;
pub const RetrievalStrategy = adaptive.RetrievalStrategy;
pub const buildRerankPrompt = llm_reranker.buildRerankPrompt;
pub const parseRerankResponse = llm_reranker.parseRerankResponse;
pub const LlmRerankerConfig = llm_reranker.LlmRerankerConfig;

// Lifecycle: summarizer
pub const SummarizerConfig = summarizer.SummarizerConfig;
pub const SummaryResult = summarizer.SummaryResult;
pub const shouldSummarize = summarizer.shouldSummarize;
pub const buildSummarizationPrompt = summarizer.buildSummarizationPrompt;
pub const parseSummaryResponse = summarizer.parseSummaryResponse;

// Lifecycle: semantic cache
pub const SemanticCache = semantic_cache.SemanticCache;

// ── Session message types ─────────────────────────────────────────

pub const MessageEntry = struct {
    role: []const u8,
    content: []const u8,
};

pub fn freeMessages(allocator: std.mem.Allocator, messages: []MessageEntry) void {
    for (messages) |entry| {
        allocator.free(entry.role);
        allocator.free(entry.content);
    }
    allocator.free(messages);
}

// ── SessionStore vtable interface ─────────────────────────────────

pub const SessionStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        saveMessage: *const fn (ptr: *anyopaque, session_id: []const u8, role: []const u8, content: []const u8) anyerror!void,
        loadMessages: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, session_id: []const u8) anyerror![]MessageEntry,
        clearMessages: *const fn (ptr: *anyopaque, session_id: []const u8) anyerror!void,
        clearAutoSaved: *const fn (ptr: *anyopaque, session_id: ?[]const u8) anyerror!void,
    };

    pub fn saveMessage(self: SessionStore, session_id: []const u8, role: []const u8, content: []const u8) !void {
        return self.vtable.saveMessage(self.ptr, session_id, role, content);
    }

    pub fn loadMessages(self: SessionStore, allocator: std.mem.Allocator, session_id: []const u8) ![]MessageEntry {
        return self.vtable.loadMessages(self.ptr, allocator, session_id);
    }

    pub fn clearMessages(self: SessionStore, session_id: []const u8) !void {
        return self.vtable.clearMessages(self.ptr, session_id);
    }

    pub fn clearAutoSaved(self: SessionStore, session_id: ?[]const u8) !void {
        return self.vtable.clearAutoSaved(self.ptr, session_id);
    }
};

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

pub const PromptBootstrapKeyPrefix = "__bootstrap.prompt.";

pub const PromptBootstrapDoc = struct {
    filename: []const u8,
    memory_key: []const u8,
};

pub const prompt_bootstrap_docs = [_]PromptBootstrapDoc{
    .{ .filename = "AGENTS.md", .memory_key = "__bootstrap.prompt.AGENTS.md" },
    .{ .filename = "SOUL.md", .memory_key = "__bootstrap.prompt.SOUL.md" },
    .{ .filename = "TOOLS.md", .memory_key = "__bootstrap.prompt.TOOLS.md" },
    .{ .filename = "IDENTITY.md", .memory_key = "__bootstrap.prompt.IDENTITY.md" },
    .{ .filename = "USER.md", .memory_key = "__bootstrap.prompt.USER.md" },
    .{ .filename = "HEARTBEAT.md", .memory_key = "__bootstrap.prompt.HEARTBEAT.md" },
    .{ .filename = "BOOTSTRAP.md", .memory_key = "__bootstrap.prompt.BOOTSTRAP.md" },
    .{ .filename = "MEMORY.md", .memory_key = "__bootstrap.prompt.MEMORY.md" },
};

pub fn promptBootstrapMemoryKey(filename: []const u8) ?[]const u8 {
    for (prompt_bootstrap_docs) |doc| {
        if (std.mem.eql(u8, doc.filename, filename)) return doc.memory_key;
    }
    return null;
}

/// markdown backend keeps bootstrap identity in workspace files;
/// all other backends use backend-native key/value entries.
pub fn usesWorkspaceBootstrapFiles(memory_backend: ?[]const u8) bool {
    const backend = memory_backend orelse return true;
    return std.mem.eql(u8, backend, "markdown");
}

pub fn isInternalMemoryKey(key: []const u8) bool {
    return std.mem.startsWith(u8, key, "autosave_user_") or
        std.mem.startsWith(u8, key, "autosave_assistant_") or
        std.mem.eql(u8, key, "last_hygiene_at") or
        std.mem.startsWith(u8, key, PromptBootstrapKeyPrefix);
}

pub fn extractMarkdownMemoryKey(content: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, content, " \t");
    if (!std.mem.startsWith(u8, trimmed, "**")) return null;
    const rest = trimmed[2..];
    const suffix = std.mem.indexOf(u8, rest, "**:") orelse return null;
    if (suffix == 0) return null;
    return rest[0..suffix];
}

pub fn isInternalMemoryEntryKeyOrContent(key: []const u8, content: []const u8) bool {
    if (isInternalMemoryKey(key)) return true;
    if (extractMarkdownMemoryKey(content)) |extracted| {
        if (isInternalMemoryKey(extracted)) return true;
    }
    return false;
}

fn trimCandidatesToLimit(allocator: std.mem.Allocator, candidates: []RetrievalCandidate, limit: usize) ![]RetrievalCandidate {
    if (candidates.len <= limit) return candidates;

    // If allocation fails while trimming, free the original result to avoid leaks.
    errdefer retrieval.freeCandidates(allocator, candidates);

    var trimmed = try allocator.alloc(RetrievalCandidate, limit);
    for (candidates[0..limit], 0..) |candidate, i| {
        trimmed[i] = candidate;
    }
    for (candidates[limit..]) |*candidate| {
        candidate.deinit(allocator);
    }
    allocator.free(candidates);

    return trimmed;
}

// ── Memory vtable interface ────────────────────────────────────────

pub const Memory = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        name: *const fn (ptr: *anyopaque) []const u8,
        store: *const fn (ptr: *anyopaque, key: []const u8, content: []const u8, category: MemoryCategory, session_id: ?[]const u8) anyerror!void,
        recall: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) anyerror![]MemoryEntry,
        get: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, key: []const u8) anyerror!?MemoryEntry,
        list: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, category: ?MemoryCategory, session_id: ?[]const u8) anyerror![]MemoryEntry,
        forget: *const fn (ptr: *anyopaque, key: []const u8) anyerror!bool,
        count: *const fn (ptr: *anyopaque) anyerror!usize,
        healthCheck: *const fn (ptr: *anyopaque) bool,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn name(self: Memory) []const u8 {
        return self.vtable.name(self.ptr);
    }

    pub fn store(self: Memory, key: []const u8, content: []const u8, category: MemoryCategory, session_id: ?[]const u8) !void {
        return self.vtable.store(self.ptr, key, content, category, session_id);
    }

    pub fn recall(self: Memory, allocator: std.mem.Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) ![]MemoryEntry {
        return self.vtable.recall(self.ptr, allocator, query, limit, session_id);
    }

    pub fn get(self: Memory, allocator: std.mem.Allocator, key: []const u8) !?MemoryEntry {
        return self.vtable.get(self.ptr, allocator, key);
    }

    pub fn list(self: Memory, allocator: std.mem.Allocator, category: ?MemoryCategory, session_id: ?[]const u8) ![]MemoryEntry {
        return self.vtable.list(self.ptr, allocator, category, session_id);
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
        return self.recall(allocator, query, limit, null);
    }
};

// ── MemoryRuntime — bundled memory + session store + capabilities ──

/// Resolved configuration snapshot — captures what was actually resolved during init.
/// Stored in MemoryRuntime for diagnostics, `/doctor`, and runtime inspection.
pub const ResolvedConfig = struct {
    primary_backend: []const u8,
    retrieval_mode: []const u8, // "disabled" | "keyword" | "hybrid"
    vector_mode: []const u8, // "none" | "sqlite_shared" | "sqlite_sidecar" | "qdrant" | "pgvector"
    embedding_provider: []const u8, // "none" | "openai" | "gemini" | "voyage" | "ollama" | "auto"
    rollout_mode: []const u8,
    vector_sync_mode: []const u8, // "best_effort" | "durable_outbox"
    hygiene_enabled: bool,
    snapshot_enabled: bool,
    cache_enabled: bool,
    semantic_cache_enabled: bool,
    summarizer_enabled: bool,
    source_count: usize,
    fallback_policy: []const u8, // "degrade" | "fail_fast"
};

pub const MemoryRuntime = struct {
    memory: Memory,
    session_store: ?SessionStore,
    response_cache: ?*cache.ResponseCache,
    capabilities: BackendCapabilities,
    resolved: ResolvedConfig,

    // Internal: owned resources for cleanup
    _db_path: ?[*:0]const u8,
    _cache_db_path: ?[*:0]const u8,
    _engine: ?*retrieval.RetrievalEngine,
    _allocator: std.mem.Allocator,
    _search_enabled: bool = true,

    // P5: rollout policy
    _rollout_policy: rollout.RolloutPolicy = .{ .mode = .on, .canary_percent = 0, .shadow_percent = 0 },

    // Lifecycle: summarizer config
    _summarizer_cfg: summarizer.SummarizerConfig = .{},

    // Lifecycle: semantic cache (optional, extends response cache with cosine similarity)
    _semantic_cache: ?*semantic_cache.SemanticCache = null,
    _semantic_cache_db_path: ?[*:0]const u8 = null,

    // P3: vector plane components (all optional)
    _embedding_provider: ?embeddings.EmbeddingProvider = null,
    _vector_store: ?vector_store.VectorStore = null,
    _circuit_breaker: ?*circuit_breaker.CircuitBreaker = null,
    _outbox: ?*outbox.VectorOutbox = null,
    _sidecar_db_path: ?[*:0]const u8 = null,

    /// High-level search: uses rollout policy to decide keyword-only vs hybrid.
    pub fn search(self: *MemoryRuntime, allocator: std.mem.Allocator, query: []const u8, limit: usize, session_id: ?[]const u8) ![]RetrievalCandidate {
        if (!self._search_enabled) return allocator.alloc(RetrievalCandidate, 0);

        const decision = self._rollout_policy.decide(session_id);

        switch (decision) {
            .keyword_only => {
                // Bypass engine, use recall() directly
                const entries = try self.memory.recall(allocator, query, limit, session_id);
                defer freeEntries(allocator, entries);
                return retrieval.entriesToCandidates(allocator, entries);
            },
            .hybrid => {
                // Use engine if available, else fall back
                if (self._engine) |engine| {
                    const candidates = try engine.search(allocator, query, session_id);
                    return trimCandidatesToLimit(allocator, candidates, limit);
                }
                const entries = try self.memory.recall(allocator, query, limit, session_id);
                defer freeEntries(allocator, entries);
                return retrieval.entriesToCandidates(allocator, entries);
            },
            .shadow_hybrid => {
                // Run both, serve keyword result, log hybrid for comparison
                const keyword_entries = try self.memory.recall(allocator, query, limit, session_id);
                defer freeEntries(allocator, keyword_entries);
                const keyword_results = try retrieval.entriesToCandidates(allocator, keyword_entries);

                if (self._engine) |engine| {
                    const hybrid_results = engine.search(allocator, query, session_id) catch |err| {
                        log.warn("shadow hybrid search failed: {}", .{err});
                        return keyword_results;
                    };
                    defer retrieval.freeCandidates(allocator, hybrid_results);

                    log.info("shadow: keyword={d} hybrid={d} results", .{ keyword_results.len, hybrid_results.len });
                }

                return keyword_results;
            },
        }
    }

    /// Get current rollout mode.
    pub fn rolloutMode(self: *const MemoryRuntime) rollout.RolloutMode {
        return self._rollout_policy.mode;
    }

    /// Best-effort vector sync after a store() call.
    /// Embeds the content and upserts into the vector store.
    /// Errors are caught and logged, never propagated.
    pub fn syncVectorAfterStore(self: *MemoryRuntime, allocator: std.mem.Allocator, key: []const u8, content: []const u8) void {
        // Durable mode: enqueue and return (drain happens at turn boundaries / shutdown).
        if (self._outbox) |ob| {
            ob.enqueue(key, "upsert") catch |err| {
                log.warn("outbox enqueue failed for key '{s}': {}", .{ key, err });
            };
            return;
        }

        const provider = self._embedding_provider orelse return;
        const vs = self._vector_store orelse return;

        // Check circuit breaker
        if (self._circuit_breaker) |cb| {
            if (!cb.allow()) return;
        }

        const emb = provider.embed(allocator, content) catch |err| {
            log.warn("vector sync embed failed for key '{s}': {}", .{ key, err });
            if (self._circuit_breaker) |cb| cb.recordFailure();
            return;
        };
        defer allocator.free(emb);

        if (self._circuit_breaker) |cb| cb.recordSuccess();
        if (emb.len == 0) return;

        vs.upsert(key, emb) catch |err| {
            log.warn("vector sync upsert failed for key '{s}': {}", .{ key, err });
        };
    }

    /// Drain the durable outbox (if configured).
    /// Call periodically (e.g., after each agent turn).
    pub fn drainOutbox(self: *MemoryRuntime, allocator: std.mem.Allocator) u32 {
        const ob = self._outbox orelse return 0;
        const provider = self._embedding_provider orelse return 0;
        const vs = self._vector_store orelse return 0;
        return ob.drain(allocator, provider, vs, self._circuit_breaker) catch 0;
    }

    /// Best-effort delete from vector store after a forget() call.
    /// Errors are caught and logged, never propagated.
    pub fn deleteFromVectorStore(self: *MemoryRuntime, key: []const u8) void {
        if (self._outbox) |ob| {
            ob.enqueue(key, "delete") catch |err| {
                log.warn("outbox enqueue failed for key '{s}': {}", .{ key, err });
            };
            return;
        }

        const vs = self._vector_store orelse return;
        vs.delete(key) catch |err| {
            log.warn("vector store delete failed for key '{s}': {}", .{ key, err });
        };
    }

    /// Rebuild the entire vector store from primary memory entries.
    /// Used for recovery after vector store corruption, embedding model changes,
    /// or migration to a different vector store backend.
    /// Returns the number of entries reindexed, or 0 if no vector plane is configured.
    pub fn reindex(self: *MemoryRuntime, allocator: std.mem.Allocator) u32 {
        const provider = self._embedding_provider orelse return 0;
        const vs = self._vector_store orelse return 0;

        // List all entries from primary store
        const entries = self.memory.list(allocator, null, null) catch |err| {
            log.warn("reindex: failed to list primary entries: {}", .{err});
            return 0;
        };
        defer freeEntries(allocator, entries);

        var reindexed: u32 = 0;
        for (entries) |entry| {
            const emb = provider.embed(allocator, entry.content) catch |err| {
                log.warn("reindex: embed failed for key '{s}': {}", .{ entry.key, err });
                continue;
            };
            defer allocator.free(emb);
            if (emb.len == 0) continue;

            vs.upsert(entry.key, emb) catch |err| {
                log.warn("reindex: upsert failed for key '{s}': {}", .{ entry.key, err });
                continue;
            };
            reindexed += 1;
        }

        log.info("reindex complete: {d}/{d} entries reindexed", .{ reindexed, entries.len });
        return reindexed;
    }

    /// Enqueue a key for vector sync via the outbox (if configured).
    pub fn enqueueVectorSync(self: *MemoryRuntime, key: []const u8, operation: []const u8) void {
        const ob = self._outbox orelse return;
        ob.enqueue(key, operation) catch |err| {
            log.warn("outbox enqueue failed for key '{s}': {}", .{ key, err });
        };
    }

    /// Get the summarizer configuration (for the agent/session layer to use).
    pub fn summarizerConfig(self: *const MemoryRuntime) summarizer.SummarizerConfig {
        return self._summarizer_cfg;
    }

    /// Get the semantic cache (for the agent/session layer to use).
    pub fn semanticCache(self: *MemoryRuntime) ?*semantic_cache.SemanticCache {
        return self._semantic_cache;
    }

    /// Run memory doctor diagnostics and return a report.
    pub fn diagnose(self: *MemoryRuntime) diagnostics.DiagnosticReport {
        return diagnostics.diagnose(self);
    }

    pub fn deinit(self: *MemoryRuntime) void {
        // Best-effort: drain any pending vector sync operations before teardown.
        // Must happen while embedding provider, vector store, and circuit breaker
        // are still alive (drainOutbox uses all three).
        _ = self.drainOutbox(self._allocator);

        // Engine first: it holds references to P3 components (vector store,
        // embedding provider, circuit breaker) — must deinit before them.
        if (self._engine) |engine| {
            engine.deinit();
            self._allocator.destroy(engine);
        }

        // P3 cleanup (outbox borrows db from vector store or primary — deinit before them)
        if (self._outbox) |ob| {
            ob.deinit(); // handles owns_self destroy
        }
        if (self._circuit_breaker) |cb| {
            self._allocator.destroy(cb);
        }
        if (self._vector_store) |vs| {
            vs.deinitStore(); // vtable deinit handles owns_self destroy
        }
        if (self._sidecar_db_path) |p| self._allocator.free(std.mem.span(p));
        if (self._embedding_provider) |ep| {
            ep.deinit();
        }
        if (self._semantic_cache) |sc| {
            sc.deinit();
            self._allocator.destroy(sc);
        }
        if (self._semantic_cache_db_path) |p| self._allocator.free(std.mem.span(p));
        if (self.response_cache) |rc| {
            rc.deinit();
            self._allocator.destroy(rc);
        }
        if (self._cache_db_path) |p| self._allocator.free(std.mem.span(p));
        self.memory.deinit();
        if (self._db_path) |p| self._allocator.free(std.mem.span(p));
    }
};

/// Create a MemoryRuntime from a MemoryConfig and workspace directory.
/// Goes through the registry to find the backend, resolve paths, and
/// create the instance. Returns null on any error (unknown backend,
/// path resolution failure, backend init failure).
pub fn initRuntime(
    allocator: std.mem.Allocator,
    config: *const config_types.MemoryConfig,
    workspace_dir: []const u8,
) ?MemoryRuntime {
    const desc = registry.findBackend(config.backend) orelse {
        const enabled_backends = registry.formatEnabledBackends(allocator) catch null;
        defer if (enabled_backends) |names| allocator.free(names);

        if (registry.isKnownBackend(config.backend)) {
            const engine_token = registry.engineTokenForBackend(config.backend) orelse config.backend;
            log.warn("memory backend '{s}' is configured but disabled in this build", .{config.backend});
            log.warn("rebuild with -Dengines={s} (or include it in your -Dengines=... list)", .{engine_token});
        } else {
            log.warn("unknown memory backend '{s}' — check config.memory.backend", .{config.backend});
            log.warn("known memory backends: {s}", .{registry.known_backends_csv});
        }
        if (enabled_backends) |names| {
            log.warn("enabled memory backends in this build: {s}", .{names});
        }
        return null;
    };

    const pg_cfg: ?config_types.MemoryPostgresConfig = if (std.mem.eql(u8, config.backend, "postgres")) config.postgres else null;
    const redis_cfg: ?config_types.MemoryRedisConfig = if (std.mem.eql(u8, config.backend, "redis")) config.redis else null;
    const api_cfg: ?config_types.MemoryApiConfig = if (std.mem.eql(u8, config.backend, "api")) config.api else null;
    const cfg = registry.resolvePaths(allocator, desc, workspace_dir, pg_cfg, redis_cfg, api_cfg) catch |err| {
        log.warn("memory path resolution failed for backend '{s}': {}", .{ config.backend, err });
        return null;
    };

    const instance = desc.create(allocator, cfg) catch |err| {
        log.warn("memory backend '{s}' init failed: {}", .{ config.backend, err });
        if (std.mem.eql(u8, config.backend, "sqlite") and err == error.MigrationFailed) {
            const db_path = if (cfg.db_path) |p| std.mem.span(p) else "(unknown path)";
            log.warn("sqlite migration failed for {s}", .{db_path});
            log.warn("common causes: database locked/read-only, corrupt sqlite file, or sqlite build without FTS5", .{});
            log.warn("hint: stop other nullclaw processes; if needed, back up/remove the db file and retry", .{});
        }
        if (cfg.postgres_url) |pu| allocator.free(std.mem.span(pu));
        if (cfg.db_path) |p| allocator.free(std.mem.span(p));
        return null;
    };

    // ── Lifecycle: snapshot hydrate (before hygiene) ──
    if (config.lifecycle.auto_hydrate) {
        if (snapshot.shouldHydrate(allocator, instance.memory, workspace_dir)) {
            _ = snapshot.hydrateFromSnapshot(allocator, instance.memory, workspace_dir) catch |e| {
                log.warn("snapshot hydration failed: {}", .{e});
            };
        }
    }

    // ── Lifecycle: hygiene ──
    if (config.lifecycle.hygiene_enabled) {
        const hygiene_cfg = hygiene.HygieneConfig{
            .hygiene_enabled = true,
            .archive_after_days = config.lifecycle.archive_after_days,
            .purge_after_days = config.lifecycle.purge_after_days,
            .conversation_retention_days = config.lifecycle.conversation_retention_days,
            .workspace_dir = workspace_dir,
        };
        const report = hygiene.runIfDue(allocator, hygiene_cfg, instance.memory);

        // Snapshot after hygiene if configured and hygiene did work
        if (config.lifecycle.snapshot_on_hygiene and report.totalActions() > 0) {
            _ = snapshot.exportSnapshot(allocator, instance.memory, workspace_dir) catch |e| {
                log.warn("snapshot export after hygiene failed: {}", .{e});
            };
        }
    }

    // ── Lifecycle: response cache ──
    var resp_cache: ?*cache.ResponseCache = null;
    var cache_db_path: ?[*:0]const u8 = null;
    if (build_options.enable_sqlite and config.response_cache.enabled) blk: {
        const cp_slice = std.fs.path.joinZ(allocator, &.{ workspace_dir, "response_cache.db" }) catch break :blk;
        const cp: [*:0]const u8 = cp_slice.ptr;
        const rc = allocator.create(cache.ResponseCache) catch {
            allocator.free(std.mem.span(cp));
            break :blk;
        };
        rc.* = cache.ResponseCache.init(cp, config.response_cache.ttl_minutes, config.response_cache.max_entries) catch {
            allocator.destroy(rc);
            allocator.free(std.mem.span(cp));
            break :blk;
        };
        resp_cache = rc;
        cache_db_path = cp;
    }

    // ── Retrieval engine ──
    var engine: ?*retrieval.RetrievalEngine = null;
    if (config.search.enabled) build_engine: {
        const eng = allocator.create(retrieval.RetrievalEngine) catch break :build_engine;
        eng.* = retrieval.RetrievalEngine.init(allocator, config.search.query);

        // Add primary adapter unless QMD-only mode is explicitly requested.
        const include_primary = !config.qmd.enabled or config.qmd.include_default_memory;
        if (include_primary) {
            const primary = allocator.create(retrieval.PrimaryAdapter) catch {
                allocator.destroy(eng);
                break :build_engine;
            };
            primary.* = retrieval.PrimaryAdapter.init(instance.memory);
            primary.owns_self = true;
            primary.allocator = allocator;
            eng.addSource(primary.adapter()) catch {
                allocator.destroy(primary);
                eng.deinit();
                allocator.destroy(eng);
                break :build_engine;
            };
        }

        // QMD adapter (optional — alloc failure just skips it, engine remains usable)
        if (config.qmd.enabled) {
            if (allocator.create(retrieval_qmd.QmdAdapter)) |qmd| {
                qmd.* = retrieval_qmd.QmdAdapter.init(allocator, config.qmd, workspace_dir);
                qmd.owns_self = true;
                eng.addSource(qmd.adapter()) catch {
                    allocator.destroy(qmd);
                };
            } else |_| {}
        }

        // Configure extended pipeline stages (query expansion, adaptive, LLM reranker)
        eng.setRetrievalStages(config.retrieval_stages);

        engine = eng;
    }

    // ── P3: Vector plane wiring ──
    var embed_provider: ?embeddings.EmbeddingProvider = null;
    var vs_iface: ?vector_store.VectorStore = null;
    var cb_inst: ?*circuit_breaker.CircuitBreaker = null;
    var outbox_inst: ?*outbox.VectorOutbox = null;
    var sidecar_db_path: ?[*:0]const u8 = null;
    var resolved_vector_mode: []const u8 = "none";
    var resolved_vector_sync_mode: []const u8 = "best_effort";
    if (config.search.enabled and !std.mem.eql(u8, config.search.provider, "none") and config.search.query.hybrid.enabled) vec_plane: {
        const primary_api_key = provider_api_key.resolveApiKey(allocator, config.search.provider, null) catch null;
        defer if (primary_api_key) |k| allocator.free(k);

        // 1. Create EmbeddingProvider (with optional fallback via ProviderRouter)
        const primary_ep = embeddings.createEmbeddingProvider(
            allocator,
            config.search.provider,
            primary_api_key,
            config.search.model,
            config.search.dimensions,
        ) catch break :vec_plane;

        embed_provider = primary_ep;

        // Wrap primary + fallback in a ProviderRouter when fallback is configured
        if (!std.mem.eql(u8, config.search.fallback_provider, "none") and
            config.search.fallback_provider.len > 0)
        wrap_router: {
            const fallback_api_key = provider_api_key.resolveApiKey(allocator, config.search.fallback_provider, null) catch null;
            defer if (fallback_api_key) |k| allocator.free(k);

            const fallback_ep = embeddings.createEmbeddingProvider(
                allocator,
                config.search.fallback_provider,
                fallback_api_key,
                config.search.model,
                config.search.dimensions,
            ) catch {
                log.warn("fallback embedding provider '{s}' init failed, using primary only", .{config.search.fallback_provider});
                break :wrap_router;
            };
            const router = provider_router.ProviderRouter.init(
                allocator,
                primary_ep,
                &.{fallback_ep},
                &.{},
            ) catch {
                fallback_ep.deinit();
                break :wrap_router;
            };
            embed_provider = router.provider();
        }

        // 2. Resolve vector store mode based on config.search.store.kind
        //    "auto"           → sqlite_shared if primary is sqlite-based, else sqlite_sidecar
        //    "qdrant"         → QdrantVectorStore via REST API
        //    "pgvector"       → PgvectorVectorStore via libpq (requires enable_postgres)
        //    "sqlite_shared"  → explicit sqlite shared (requires sqlite-based primary)
        //    "sqlite_sidecar" → explicit sqlite sidecar (separate vectors.db)
        var db_handle_for_outbox: ?*c.sqlite3 = null;
        const store_kind = config.search.store.kind;

        if (std.mem.eql(u8, store_kind, "qdrant")) {
            // Qdrant via REST API
            if (config.search.store.qdrant_url.len == 0) {
                log.warn("vector store kind 'qdrant' requires search.store.qdrant_url to be set", .{});
                break :vec_plane;
            }
            const qdrant = store_qdrant.QdrantVectorStore.init(allocator, .{
                .url = config.search.store.qdrant_url,
                .api_key = if (config.search.store.qdrant_api_key.len > 0) config.search.store.qdrant_api_key else null,
                .collection_name = config.search.store.qdrant_collection,
                .dimensions = config.search.dimensions,
            }) catch |err| {
                log.warn("qdrant vector store init failed: {}", .{err});
                break :vec_plane;
            };
            vs_iface = qdrant.store();
            resolved_vector_mode = "qdrant";
        } else if (std.mem.eql(u8, store_kind, "pgvector")) {
            // pgvector via PostgreSQL
            if (build_options.enable_postgres) {
                const pg_url = if (config.postgres.url.len > 0)
                    config.postgres.url
                else {
                    log.warn("vector store kind 'pgvector' requires postgres.url to be set", .{});
                    break :vec_plane;
                };
                const pgvs = store_pgvector.PgvectorVectorStore.init(allocator, .{
                    .connection_url = pg_url,
                    .table_name = config.search.store.pgvector_table,
                    .dimensions = config.search.dimensions,
                }) catch |err| {
                    log.warn("pgvector vector store init failed: {}", .{err});
                    break :vec_plane;
                };
                vs_iface = pgvs.store();
                resolved_vector_mode = "pgvector";
            } else {
                log.warn("vector store kind 'pgvector' requires build with enable_postgres=true", .{});
                break :vec_plane;
            }
        } else if (!build_options.enable_sqlite) {
            log.warn("vector store kind '{s}' requires build with enable_sqlite=true", .{store_kind});
            break :vec_plane;
        } else {
            // auto / sqlite_shared / sqlite_sidecar
            const use_shared = std.mem.eql(u8, store_kind, "auto") or std.mem.eql(u8, store_kind, "sqlite_shared");
            if (use_shared) {
                if (extractSqliteDb(instance.memory)) |db_handle| {
                    // sqlite_shared: reuse existing sqlite db handle
                    const vs = allocator.create(vector_store.SqliteSharedVectorStore) catch break :vec_plane;
                    vs.* = vector_store.SqliteSharedVectorStore.init(allocator, db_handle);
                    vs.owns_self = true;
                    vs_iface = vs.store();
                    db_handle_for_outbox = db_handle;
                    resolved_vector_mode = "sqlite_shared";
                } else if (std.mem.eql(u8, store_kind, "sqlite_shared")) {
                    log.warn("vector store kind 'sqlite_shared' requires a sqlite-based primary backend", .{});
                    break :vec_plane;
                }
                // else: auto fallthrough to sidecar below
            }

            // sqlite_sidecar: explicit or auto fallback for non-sqlite backends
            if (vs_iface == null) {
                const sidecar_path_slice = blk: {
                    const configured = config.search.store.sidecar_path;
                    if (configured.len == 0) {
                        break :blk std.fs.path.joinZ(allocator, &.{ workspace_dir, "vectors.db" }) catch break :vec_plane;
                    }
                    if (std.fs.path.isAbsolute(configured)) {
                        break :blk allocator.dupeZ(u8, configured) catch break :vec_plane;
                    }
                    break :blk std.fs.path.joinZ(allocator, &.{ workspace_dir, configured }) catch break :vec_plane;
                };
                const sidecar_path: [*:0]const u8 = sidecar_path_slice.ptr;
                const vs = allocator.create(vector_store.SqliteSidecarVectorStore) catch {
                    allocator.free(sidecar_path_slice);
                    break :vec_plane;
                };
                vs.* = vector_store.SqliteSidecarVectorStore.init(allocator, sidecar_path) catch {
                    allocator.destroy(vs);
                    allocator.free(sidecar_path_slice);
                    break :vec_plane;
                };
                vs.owns_self = true;
                vs_iface = vs.store();
                db_handle_for_outbox = vs.db; // sidecar's own db for outbox
                sidecar_db_path = sidecar_path;
                resolved_vector_mode = "sqlite_sidecar";
            }
        }

        // 3. Create CircuitBreaker
        const cb = allocator.create(circuit_breaker.CircuitBreaker) catch break :vec_plane;
        cb.* = circuit_breaker.CircuitBreaker.init(
            config.reliability.circuit_breaker_failures,
            config.reliability.circuit_breaker_cooldown_ms,
        );
        cb_inst = cb;

        // 4. Create VectorOutbox if not best_effort
        if (!std.mem.eql(u8, config.search.sync.mode, "best_effort")) {
            if (db_handle_for_outbox) |db_h| {
                const ob = allocator.create(outbox.VectorOutbox) catch break :vec_plane;
                const outbox_retries = @max(config.search.sync.embed_max_retries, config.search.sync.vector_max_retries);
                ob.* = outbox.VectorOutbox.init(allocator, db_h, outbox_retries);
                ob.owns_self = true;
                ob.migrate() catch {
                    allocator.destroy(ob);
                    break :vec_plane;
                };
                outbox_inst = ob;
                resolved_vector_sync_mode = "durable_outbox";
            }
        }

        // 5. Wire into retrieval engine
        if (engine) |eng| {
            eng.setVectorSearch(embed_provider.?, vs_iface.?, cb, config.search.query.hybrid);
        }
    }

    // Enforce fallback_policy: if fail_fast and vector plane was expected but failed, abort.
    if (std.mem.eql(u8, config.reliability.fallback_policy, "fail_fast")) {
        const vector_expected = config.search.enabled and
            !std.mem.eql(u8, config.search.provider, "none") and
            config.search.query.hybrid.enabled;
        const durable_requested = !std.mem.eql(u8, config.search.sync.mode, "best_effort");
        const vector_plane_failed = vector_expected and vs_iface == null;
        const durable_outbox_unavailable = vector_expected and durable_requested and outbox_inst == null;
        if (vector_plane_failed or durable_outbox_unavailable) {
            if (vector_plane_failed) {
                log.warn("fallback_policy=fail_fast: vector plane init failed, aborting runtime creation", .{});
            } else {
                log.warn("fallback_policy=fail_fast: durable vector sync unavailable, aborting runtime creation", .{});
            }
            // Clean up partially-created P3 resources
            if (outbox_inst) |ob| ob.deinit();
            if (vs_iface) |vs| vs.deinitStore();
            if (embed_provider) |ep| ep.deinit();
            if (cb_inst) |cb| allocator.destroy(cb);
            if (sidecar_db_path) |p| allocator.free(std.mem.span(p));
            // Clean up response cache
            if (resp_cache) |rc| {
                rc.deinit();
                allocator.destroy(rc);
            }
            if (cache_db_path) |p| allocator.free(std.mem.span(p));
            if (engine) |eng| {
                eng.deinit();
                allocator.destroy(eng);
            }
            instance.memory.deinit();
            if (cfg.postgres_url) |pu| allocator.free(std.mem.span(pu));
            if (cfg.db_path) |p| allocator.free(std.mem.span(p));
            return null;
        }
    }

    // Free postgres_url after backend creation (backend dupes what it needs)
    if (cfg.postgres_url) |pu| allocator.free(std.mem.span(pu));

    // ── Lifecycle: semantic cache ──
    var sem_cache: ?*semantic_cache.SemanticCache = null;
    var sem_cache_db_path: ?[*:0]const u8 = null;
    if (build_options.enable_sqlite and config.response_cache.enabled and embed_provider != null) sem_cache_blk: {
        const sc_path = std.fs.path.joinZ(allocator, &.{ workspace_dir, "semantic_cache.db" }) catch break :sem_cache_blk;
        const sc = allocator.create(semantic_cache.SemanticCache) catch {
            allocator.free(std.mem.span(sc_path.ptr));
            break :sem_cache_blk;
        };
        sc.* = semantic_cache.SemanticCache.init(
            sc_path.ptr,
            config.response_cache.ttl_minutes,
            config.response_cache.max_entries,
            0.95, // cosine similarity threshold
            embed_provider,
        ) catch {
            allocator.destroy(sc);
            allocator.free(std.mem.span(sc_path.ptr));
            break :sem_cache_blk;
        };
        sem_cache = sc;
        sem_cache_db_path = sc_path.ptr;
    }

    // ── Lifecycle: summarizer config ──
    const summarizer_cfg = summarizer.SummarizerConfig{
        .enabled = config.summarizer.enabled,
        .window_size_tokens = @intCast(config.summarizer.window_size_tokens),
        .summary_max_tokens = @intCast(config.summarizer.summary_max_tokens),
        .auto_extract_semantic = config.summarizer.auto_extract_semantic,
    };

    // ── Startup diagnostic ──
    const retrieval_mode: []const u8 = if (!config.search.enabled)
        "disabled"
    else if (config.search.query.hybrid.enabled)
        "hybrid"
    else
        "keyword";
    const source_count: usize = if (engine) |eng| eng.sources.items.len else 0;
    const vector_mode: []const u8 = if (vs_iface == null) "none" else resolved_vector_mode;
    const cache_enabled = resp_cache != null;
    log.info("memory plan resolved: backend={s} retrieval={s} vector={s} rollout={s} hygiene={} snapshot={} cache={} semantic_cache={} summarizer={} sources={d}", .{
        config.backend,
        retrieval_mode,
        vector_mode,
        config.reliability.rollout_mode,
        config.lifecycle.hygiene_enabled,
        config.lifecycle.snapshot_enabled,
        cache_enabled,
        sem_cache != null,
        config.summarizer.enabled,
        source_count,
    });

    const embed_name: []const u8 = if (embed_provider) |ep_| ep_.getName() else "none";

    return .{
        .memory = instance.memory,
        .session_store = instance.session_store,
        .response_cache = resp_cache,
        .capabilities = desc.capabilities,
        .resolved = .{
            .primary_backend = config.backend,
            .retrieval_mode = retrieval_mode,
            .vector_mode = vector_mode,
            .embedding_provider = embed_name,
            .rollout_mode = config.reliability.rollout_mode,
            .vector_sync_mode = resolved_vector_sync_mode,
            .hygiene_enabled = config.lifecycle.hygiene_enabled,
            .snapshot_enabled = config.lifecycle.snapshot_enabled,
            .cache_enabled = cache_enabled,
            .semantic_cache_enabled = sem_cache != null,
            .summarizer_enabled = config.summarizer.enabled,
            .source_count = source_count,
            .fallback_policy = config.reliability.fallback_policy,
        },
        ._db_path = cfg.db_path,
        ._cache_db_path = cache_db_path,
        ._engine = engine,
        ._allocator = allocator,
        ._search_enabled = config.search.enabled,
        ._rollout_policy = rollout.RolloutPolicy.init(config.reliability),
        ._summarizer_cfg = summarizer_cfg,
        ._semantic_cache = sem_cache,
        ._semantic_cache_db_path = sem_cache_db_path,
        ._embedding_provider = embed_provider,
        ._vector_store = vs_iface,
        ._circuit_breaker = cb_inst,
        ._outbox = outbox_inst,
        ._sidecar_db_path = sidecar_db_path,
    };
}

// ── Helpers ────────────────────────────────────────────────────────

const c = sqlite.c;

/// Extract the raw sqlite3* handle from a Memory vtable, if the backend is sqlite-based.
fn extractSqliteDb(mem: Memory) ?*c.sqlite3 {
    if (!build_options.enable_sqlite) return null;

    const name_str = mem.name();
    if (std.mem.eql(u8, name_str, "sqlite")) {
        const impl_: *SqliteMemory = @ptrCast(@alignCast(mem.ptr));
        return impl_.db;
    }
    if (build_options.enable_memory_lucid and std.mem.eql(u8, name_str, "lucid")) {
        const impl_: *LucidMemory = @ptrCast(@alignCast(mem.ptr));
        return impl_.local.db;
    }
    return null;
}

// ── Tests ──────────────────────────────────────────────────────────

const test_resolved_cfg: ResolvedConfig = .{
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

test "Memory convenience store accepts session_id" {
    var backend = none.NoneMemory.init();
    defer backend.deinit();
    const m = backend.memory();
    try m.store("key", "value", .core, null);
    try m.store("key2", "value2", .daily, "session-abc");
}

test "Memory convenience recall accepts session_id" {
    var backend = none.NoneMemory.init();
    defer backend.deinit();
    const m = backend.memory();
    const results = try m.recall(std.testing.allocator, "query", 5, null);
    defer std.testing.allocator.free(results);
    try std.testing.expectEqual(@as(usize, 0), results.len);

    const results2 = try m.recall(std.testing.allocator, "query", 5, "session-abc");
    defer std.testing.allocator.free(results2);
    try std.testing.expectEqual(@as(usize, 0), results2.len);
}

test "Memory convenience list accepts session_id" {
    var backend = none.NoneMemory.init();
    defer backend.deinit();
    const m = backend.memory();
    const results = try m.list(std.testing.allocator, null, null);
    defer std.testing.allocator.free(results);
    try std.testing.expectEqual(@as(usize, 0), results.len);

    const results2 = try m.list(std.testing.allocator, .core, "session-abc");
    defer std.testing.allocator.free(results2);
    try std.testing.expectEqual(@as(usize, 0), results2.len);
}

test "SessionStore delegates through vtable" {
    const TestSessionStore = struct {
        call_count: usize = 0,

        fn implSaveMessage(ptr: *anyopaque, _: []const u8, _: []const u8, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.call_count += 1;
        }
        fn implLoadMessages(_: *anyopaque, allocator: std.mem.Allocator, _: []const u8) anyerror![]MessageEntry {
            return allocator.alloc(MessageEntry, 0);
        }
        fn implClearMessages(ptr: *anyopaque, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.call_count += 1;
        }
        fn implClearAutoSaved(ptr: *anyopaque, _: ?[]const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.call_count += 1;
        }

        const sess_vtable = SessionStore.VTable{
            .saveMessage = &implSaveMessage,
            .loadMessages = &implLoadMessages,
            .clearMessages = &implClearMessages,
            .clearAutoSaved = &implClearAutoSaved,
        };
    };

    var mock = TestSessionStore{};
    const store = SessionStore{ .ptr = @ptrCast(&mock), .vtable = &TestSessionStore.sess_vtable };

    try store.saveMessage("s1", "user", "hello");
    try std.testing.expectEqual(@as(usize, 1), mock.call_count);

    const msgs = try store.loadMessages(std.testing.allocator, "s1");
    defer std.testing.allocator.free(msgs);
    try std.testing.expectEqual(@as(usize, 0), msgs.len);

    try store.clearMessages("s1");
    try std.testing.expectEqual(@as(usize, 2), mock.call_count);

    try store.clearAutoSaved(null);
    try std.testing.expectEqual(@as(usize, 3), mock.call_count);
}

test "freeMessages frees all entries" {
    const allocator = std.testing.allocator;
    var messages = try allocator.alloc(MessageEntry, 2);
    messages[0] = .{ .role = try allocator.dupe(u8, "user"), .content = try allocator.dupe(u8, "hello") };
    messages[1] = .{ .role = try allocator.dupe(u8, "assistant"), .content = try allocator.dupe(u8, "hi") };
    freeMessages(allocator, messages);
    // No leak = pass (allocator is testing allocator with leak detection)
}

fn requireBackendEnabledForTests(name: []const u8) !void {
    if (findBackend(name) == null) return error.SkipZigTest;
}

const TestTmpDir = @TypeOf(std.testing.tmpDir(.{}));
const TestWorkspace = struct {
    tmp: TestTmpDir,
    path: []u8,

    fn init(allocator: std.mem.Allocator) !TestWorkspace {
        var tmp = std.testing.tmpDir(.{});
        const path = try tmp.dir.realpathAlloc(allocator, ".");
        return .{ .tmp = tmp, .path = path };
    }

    fn deinit(self: *TestWorkspace, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.tmp.cleanup();
    }
};

test "initRuntime none returns valid runtime" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{ .backend = "none" }, "/tmp") orelse
        return error.TestUnexpectedResult;
    defer rt.deinit();

    try std.testing.expectEqualStrings("none", rt.memory.name());
    try std.testing.expect(rt.session_store == null);
    try std.testing.expect(!rt.capabilities.supports_session_store);
    try std.testing.expect(!rt.capabilities.supports_keyword_rank);
}

test "initRuntime unknown backend returns null" {
    try std.testing.expect(initRuntime(std.testing.allocator, &.{ .backend = "unknown_backend" }, "/tmp") == null);
}

test "initRuntime none deinit does not leak" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{ .backend = "none" }, "/tmp") orelse
        return error.TestUnexpectedResult;
    rt.deinit();
    // testing allocator detects leaks — if we get here, no leak
}

test "initRuntime none has null db_path" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{ .backend = "none" }, "/tmp") orelse
        return error.TestUnexpectedResult;
    defer rt.deinit();

    try std.testing.expect(rt._db_path == null);
    try std.testing.expect(rt.response_cache == null);
}

test "initRuntime sqlite returns full runtime" {
    if (!build_options.enable_memory_sqlite) return;
    var ws = try TestWorkspace.init(std.testing.allocator);
    defer ws.deinit(std.testing.allocator);

    var rt = initRuntime(std.testing.allocator, &.{ .backend = "sqlite" }, ws.path) orelse
        return error.TestUnexpectedResult;
    defer rt.deinit();

    try std.testing.expectEqualStrings("sqlite", rt.memory.name());
    try std.testing.expect(rt.session_store != null);
    try std.testing.expect(rt.capabilities.supports_session_store);
    try std.testing.expect(rt.capabilities.supports_keyword_rank);
    try std.testing.expect(rt.capabilities.supports_transactions);
    try std.testing.expect(rt._db_path != null);
    const path_slice = std.mem.span(rt._db_path.?);
    try std.testing.expect(std.mem.endsWith(u8, path_slice, "memory.db"));
}

test "initRuntime with lifecycle defaults does not crash" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{ .backend = "none" }, "/tmp/test_lifecycle");
    if (rt) |*r| r.deinit();
}

test "initRuntime with cache disabled leaves response_cache null" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{ .backend = "none" }, "/tmp/test_nocache") orelse return;
    defer rt.deinit();
    try std.testing.expect(rt.response_cache == null);
    try std.testing.expect(rt._cache_db_path == null);
}

test "initRuntime with cache enabled creates ResponseCache" {
    if (!build_options.enable_sqlite) return error.SkipZigTest;
    try requireBackendEnabledForTests("none");

    var ws = try TestWorkspace.init(std.testing.allocator);
    defer ws.deinit(std.testing.allocator);

    var rt = initRuntime(std.testing.allocator, &.{
        .backend = "none",
        .response_cache = .{
            .enabled = true,
            .ttl_minutes = 5,
            .max_entries = 100,
        },
    }, ws.path) orelse return;
    defer rt.deinit();
    try std.testing.expect(rt.response_cache != null);
    try std.testing.expect(rt._cache_db_path != null);
}

test "initRuntime creates engine with primary source" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{ .backend = "none" }, "/tmp") orelse
        return error.TestUnexpectedResult;
    defer rt.deinit();
    try std.testing.expect(rt._engine != null);
}

test "initRuntime engine with qmd disabled has one source" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{ .backend = "none" }, "/tmp") orelse
        return error.TestUnexpectedResult;
    defer rt.deinit();
    if (rt._engine) |eng| {
        try std.testing.expectEqual(@as(usize, 1), eng.sources.items.len);
    }
}

test "initRuntime engine with qmd enabled and include_default_memory=true has primary and qmd sources" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{
        .backend = "none",
        .qmd = .{
            .enabled = true,
            .include_default_memory = true,
        },
    }, "/tmp") orelse return error.TestUnexpectedResult;
    defer rt.deinit();

    if (rt._engine) |eng| {
        try std.testing.expectEqual(@as(usize, 2), eng.sources.items.len);
        try std.testing.expectEqualStrings("primary", eng.sources.items[0].getName());
        try std.testing.expectEqualStrings("qmd", eng.sources.items[1].getName());
    } else return error.TestUnexpectedResult;
}

test "initRuntime engine with qmd enabled and include_default_memory=false has qmd-only source" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{
        .backend = "none",
        .qmd = .{
            .enabled = true,
            .include_default_memory = false,
        },
    }, "/tmp") orelse return error.TestUnexpectedResult;
    defer rt.deinit();

    if (rt._engine) |eng| {
        try std.testing.expectEqual(@as(usize, 1), eng.sources.items.len);
        try std.testing.expectEqualStrings("qmd", eng.sources.items[0].getName());
    } else return error.TestUnexpectedResult;
}

test "MemoryRuntime.search without engine falls back to recall" {
    var backend = none.NoneMemory.init();
    defer backend.deinit();
    var rt = MemoryRuntime{
        .memory = backend.memory(),
        .session_store = null,
        .response_cache = null,
        .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = false, .supports_transactions = false, .supports_outbox = false },
        .resolved = test_resolved_cfg,
        ._db_path = null,
        ._cache_db_path = null,
        ._engine = null,
        ._allocator = std.testing.allocator,
        ._embedding_provider = null,
        ._vector_store = null,
        ._circuit_breaker = null,
        ._outbox = null,
    };
    const results = try rt.search(std.testing.allocator, "query", 5, null);
    defer retrieval.freeCandidates(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "MemoryRuntime.search with engine delegates" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{ .backend = "none" }, "/tmp") orelse
        return error.TestUnexpectedResult;
    defer rt.deinit();
    const results = try rt.search(std.testing.allocator, "query", 5, null);
    defer retrieval.freeCandidates(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "MemoryRuntime.search hybrid path respects caller limit" {
    if (findBackend("memory") == null) return error.SkipZigTest;

    var rt = initRuntime(std.testing.allocator, &.{ .backend = "memory" }, "/tmp") orelse
        return error.TestUnexpectedResult;
    defer rt.deinit();

    try rt.memory.store("k1", "alpha one", .core, null);
    try rt.memory.store("k2", "alpha two", .core, null);
    try rt.memory.store("k3", "alpha three", .core, null);

    rt._rollout_policy = .{ .mode = .on, .canary_percent = 0, .shadow_percent = 0 };

    const results = try rt.search(std.testing.allocator, "alpha", 1, null);
    defer retrieval.freeCandidates(std.testing.allocator, results);
    try std.testing.expectEqual(@as(usize, 1), results.len);
}

test "initRuntime with hybrid disabled has no embedding provider" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{ .backend = "none" }, "/tmp") orelse
        return error.TestUnexpectedResult;
    defer rt.deinit();

    try std.testing.expect(rt._embedding_provider == null);
    try std.testing.expect(rt._vector_store == null);
    try std.testing.expect(rt._circuit_breaker == null);
    try std.testing.expect(rt._outbox == null);
}

test "initRuntime with search.provider=none has no vector store" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{
        .backend = "none",
        .search = .{
            .provider = "none",
            .query = .{ .hybrid = .{ .enabled = true } },
        },
    }, "/tmp") orelse
        return error.TestUnexpectedResult;
    defer rt.deinit();

    try std.testing.expect(rt._embedding_provider == null);
    try std.testing.expect(rt._vector_store == null);
}

test "initRuntime resolves sqlite_sidecar mode when explicitly configured" {
    if (!build_options.enable_memory_sqlite) return;
    var ws = try TestWorkspace.init(std.testing.allocator);
    defer ws.deinit(std.testing.allocator);

    var rt = initRuntime(std.testing.allocator, &.{
        .backend = "sqlite",
        .search = .{
            .provider = "openai",
            .query = .{ .hybrid = .{ .enabled = true } },
            .store = .{ .kind = "sqlite_sidecar" },
        },
    }, ws.path) orelse return error.TestUnexpectedResult;
    defer rt.deinit();

    try std.testing.expect(rt._vector_store != null);
    try std.testing.expectEqualStrings("sqlite_sidecar", rt.resolved.vector_mode);
}

test "initRuntime uses configured relative sqlite_sidecar path" {
    if (!build_options.enable_memory_sqlite) return;
    var ws = try TestWorkspace.init(std.testing.allocator);
    defer ws.deinit(std.testing.allocator);

    var rt = initRuntime(std.testing.allocator, &.{
        .backend = "sqlite",
        .search = .{
            .provider = "openai",
            .query = .{ .hybrid = .{ .enabled = true } },
            .store = .{
                .kind = "sqlite_sidecar",
                .sidecar_path = "vectors-custom.db",
            },
        },
    }, ws.path) orelse return error.TestUnexpectedResult;
    defer rt.deinit();

    const expected_path = try std.fs.path.join(std.testing.allocator, &.{ ws.path, "vectors-custom.db" });
    defer std.testing.allocator.free(expected_path);

    try std.testing.expect(rt._sidecar_db_path != null);
    try std.testing.expectEqualStrings(expected_path, std.mem.span(rt._sidecar_db_path.?));
}

test "initRuntime uses configured absolute sqlite_sidecar path" {
    if (!build_options.enable_memory_sqlite) return;
    var ws = try TestWorkspace.init(std.testing.allocator);
    defer ws.deinit(std.testing.allocator);
    const absolute_sidecar_path = try std.fs.path.join(std.testing.allocator, &.{ ws.path, "vectors-absolute.db" });
    defer std.testing.allocator.free(absolute_sidecar_path);

    var rt = initRuntime(std.testing.allocator, &.{
        .backend = "sqlite",
        .search = .{
            .provider = "openai",
            .query = .{ .hybrid = .{ .enabled = true } },
            .store = .{
                .kind = "sqlite_sidecar",
                .sidecar_path = absolute_sidecar_path,
            },
        },
    }, ws.path) orelse return error.TestUnexpectedResult;
    defer rt.deinit();

    try std.testing.expect(rt._sidecar_db_path != null);
    try std.testing.expectEqualStrings(absolute_sidecar_path, std.mem.span(rt._sidecar_db_path.?));
}

test "initRuntime respects search.enabled=false" {
    if (!build_options.enable_memory_sqlite) return;
    var ws = try TestWorkspace.init(std.testing.allocator);
    defer ws.deinit(std.testing.allocator);

    var rt = initRuntime(std.testing.allocator, &.{
        .backend = "sqlite",
        .search = .{
            .enabled = false,
            .provider = "openai",
            .query = .{ .hybrid = .{ .enabled = true } },
        },
    }, ws.path) orelse return error.TestUnexpectedResult;
    defer rt.deinit();

    try std.testing.expect(rt._engine == null);
    try std.testing.expect(rt._embedding_provider == null);
    try std.testing.expect(rt._vector_store == null);
    try std.testing.expectEqualStrings("disabled", rt.resolved.retrieval_mode);

    const candidates = try rt.search(std.testing.allocator, "query", 5, null);
    defer retrieval.freeCandidates(std.testing.allocator, candidates);
    try std.testing.expectEqual(@as(usize, 0), candidates.len);
}

test "initRuntime durable_outbox uses max of embed/vector retry config" {
    if (!build_options.enable_memory_sqlite) return;
    var ws = try TestWorkspace.init(std.testing.allocator);
    defer ws.deinit(std.testing.allocator);

    var rt = initRuntime(std.testing.allocator, &.{
        .backend = "sqlite",
        .search = .{
            .provider = "openai",
            .query = .{ .hybrid = .{ .enabled = true } },
            .sync = .{
                .mode = "durable_outbox",
                .embed_max_retries = 1,
                .vector_max_retries = 5,
            },
        },
    }, ws.path) orelse return error.TestUnexpectedResult;
    defer rt.deinit();

    const ob = rt._outbox orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 5), ob.max_retries);
    try std.testing.expectEqualStrings("durable_outbox", rt.resolved.vector_sync_mode);
}

test "initRuntime resolves best_effort vector sync when outbox backend unavailable" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{
        .backend = "none",
        .search = .{
            .provider = "openai",
            .query = .{ .hybrid = .{ .enabled = true } },
            .store = .{
                .kind = "qdrant",
                .qdrant_url = "http://127.0.0.1:6333",
            },
            .sync = .{
                .mode = "durable_outbox",
            },
        },
    }, "/tmp") orelse return error.TestUnexpectedResult;
    defer rt.deinit();

    try std.testing.expect(rt._vector_store != null);
    try std.testing.expect(rt._outbox == null);
    try std.testing.expectEqualStrings("best_effort", rt.resolved.vector_sync_mode);
}

test "initRuntime fail_fast returns null when durable outbox is unavailable" {
    try requireBackendEnabledForTests("none");

    const rt = initRuntime(std.testing.allocator, &.{
        .backend = "none",
        .search = .{
            .provider = "openai",
            .query = .{ .hybrid = .{ .enabled = true } },
            .store = .{
                .kind = "qdrant",
                .qdrant_url = "http://127.0.0.1:6333",
            },
            .sync = .{
                .mode = "durable_outbox",
            },
        },
        .reliability = .{
            .fallback_policy = "fail_fast",
        },
    }, "/tmp");
    try std.testing.expect(rt == null);
}

test "syncVectorAfterStore enqueues when durable outbox is active" {
    if (!build_options.enable_memory_sqlite) return;
    var ws = try TestWorkspace.init(std.testing.allocator);
    defer ws.deinit(std.testing.allocator);

    var rt = initRuntime(std.testing.allocator, &.{
        .backend = "sqlite",
        .search = .{
            .provider = "openai",
            .query = .{ .hybrid = .{ .enabled = true } },
            .sync = .{
                .mode = "durable_outbox",
            },
        },
    }, ws.path) orelse return error.TestUnexpectedResult;
    defer rt.deinit();

    const ob = rt._outbox orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), try ob.pendingCount());

    rt.syncVectorAfterStore(std.testing.allocator, "k1", "content");
    try std.testing.expectEqual(@as(usize, 1), try ob.pendingCount());
}

test "deleteFromVectorStore enqueues delete when durable outbox is active" {
    if (!build_options.enable_memory_sqlite) return;
    var ws = try TestWorkspace.init(std.testing.allocator);
    defer ws.deinit(std.testing.allocator);

    var rt = initRuntime(std.testing.allocator, &.{
        .backend = "sqlite",
        .search = .{
            .provider = "openai",
            .query = .{ .hybrid = .{ .enabled = true } },
            .sync = .{
                .mode = "durable_outbox",
            },
        },
    }, ws.path) orelse return error.TestUnexpectedResult;
    defer rt.deinit();

    const ob = rt._outbox orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), try ob.pendingCount());

    rt.deleteFromVectorStore("k1");
    try std.testing.expectEqual(@as(usize, 1), try ob.pendingCount());
}

test "MemoryRuntime.syncVectorAfterStore with no provider is no-op" {
    var backend = none.NoneMemory.init();
    defer backend.deinit();
    var rt = MemoryRuntime{
        .memory = backend.memory(),
        .session_store = null,
        .response_cache = null,
        .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = false, .supports_transactions = false, .supports_outbox = false },
        .resolved = test_resolved_cfg,
        ._db_path = null,
        ._cache_db_path = null,
        ._engine = null,
        ._allocator = std.testing.allocator,
        ._embedding_provider = null,
        ._vector_store = null,
        ._circuit_breaker = null,
        ._outbox = null,
    };
    // Should not crash — just a no-op
    rt.syncVectorAfterStore(std.testing.allocator, "key", "content");
}

test "MemoryRuntime.drainOutbox with no outbox returns 0" {
    var backend = none.NoneMemory.init();
    defer backend.deinit();
    var rt = MemoryRuntime{
        .memory = backend.memory(),
        .session_store = null,
        .response_cache = null,
        .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = false, .supports_transactions = false, .supports_outbox = false },
        .resolved = test_resolved_cfg,
        ._db_path = null,
        ._cache_db_path = null,
        ._engine = null,
        ._allocator = std.testing.allocator,
        ._embedding_provider = null,
        ._vector_store = null,
        ._circuit_breaker = null,
        ._outbox = null,
    };
    try std.testing.expectEqual(@as(u32, 0), rt.drainOutbox(std.testing.allocator));
}

test "MemoryRuntime.deinit cleans up P3 resources" {
    try requireBackendEnabledForTests("none");

    var rt = initRuntime(std.testing.allocator, &.{ .backend = "none" }, "/tmp") orelse
        return error.TestUnexpectedResult;
    // P3 fields are null for "none" backend with hybrid disabled, but deinit should handle that.
    rt.deinit();
    // testing allocator detects leaks
}

test {
    // engines/ (Layer A)
    _ = sqlite;
    _ = markdown;
    _ = none;
    _ = memory_lru;
    _ = lucid;
    _ = postgres;
    _ = redis;
    _ = lancedb;
    _ = registry;
    _ = @import("engines/contract_test.zig");

    // retrieval/ (Layer B)
    _ = retrieval;
    _ = retrieval_qmd;
    _ = rrf;
    _ = query_expansion;
    _ = temporal_decay;
    _ = mmr;
    _ = adaptive;
    _ = llm_reranker;

    // vector/ (Layer C)
    _ = vector;
    _ = vector_store;
    _ = embeddings;
    _ = embeddings_gemini;
    _ = embeddings_voyage;
    _ = embeddings_ollama;
    _ = provider_router;
    _ = store_qdrant;
    _ = store_pgvector;
    _ = circuit_breaker;
    _ = outbox;
    _ = chunker;

    // lifecycle/ (Layer D)
    _ = cache;
    _ = semantic_cache;
    _ = hygiene;
    _ = snapshot;
    _ = rollout;
    _ = migrate;
    _ = diagnostics;
    _ = summarizer;
}
