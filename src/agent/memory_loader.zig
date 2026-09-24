const std = @import("std");
const memory_mod = @import("../memory/root.zig");
const multimodal = @import("../multimodal.zig");
const util = @import("../util.zig");
const Memory = memory_mod.Memory;
const MemoryEntry = memory_mod.MemoryEntry;
const MemoryRuntime = memory_mod.MemoryRuntime;

// ═══════════════════════════════════════════════════════════════════════════
// Memory Loader — inject relevant memory context into user messages
// ═══════════════════════════════════════════════════════════════════════════

/// Configurable recall parameters — controls how many memories to inject,
/// how large the context block can be, and how many candidates to fetch.
pub const RecallParams = struct {
    recall_limit: usize = 5,
    max_context_bytes: usize = 4_000,
    scoped_candidate_limit: usize = 64,
    global_candidate_limit: usize = 64,
};

fn containsKey(entries: []const MemoryEntry, key: []const u8) bool {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return true;
    }
    return false;
}

fn containsCandidateKey(candidates: []const memory_mod.RetrievalCandidate, key: []const u8) bool {
    for (candidates) |candidate| {
        if (std.mem.eql(u8, candidate.key, key)) return true;
    }
    return false;
}

fn isInternalMemoryKey(key: []const u8) bool {
    return memory_mod.isInternalMemoryKey(key);
}

fn extractMarkdownMemoryKey(content: []const u8) ?[]const u8 {
    return memory_mod.extractMarkdownMemoryKey(content);
}

fn isInternalMemoryEntry(entry: MemoryEntry) bool {
    return memory_mod.isInternalMemoryEntryKeyOrContent(entry.key, entry.content);
}

fn isArchiveConversationKey(key: []const u8) bool {
    return std.mem.startsWith(u8, key, "archive:conversation:");
}

fn isArchiveConversationEntry(entry: MemoryEntry) bool {
    if (isArchiveConversationKey(entry.key)) return true;
    if (extractMarkdownMemoryKey(entry.content)) |extracted| {
        return isArchiveConversationKey(extracted);
    }
    return false;
}

fn isArchiveConversationCandidate(cand: memory_mod.RetrievalCandidate) bool {
    if (isArchiveConversationKey(cand.key)) return true;
    if (extractMarkdownMemoryKey(cand.snippet)) |extracted| {
        return isArchiveConversationKey(extracted);
    }
    return false;
}

fn sanitizeMemoryText(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    // Strip inline image markers from recalled snippets so stale
    // [IMAGE:...] references do not accidentally trigger multimodal mode.
    const parsed = multimodal.parseImageMarkers(allocator, text) catch return try allocator.dupe(u8, text);
    defer allocator.free(parsed.refs);
    return parsed.cleaned_text;
}

/// Build a memory context preamble by searching stored memories.
///
/// Returns a formatted string like:
/// ```
/// [Memory context]
/// - key1: value1
/// - key2: value2
/// ```
///
/// Returns an empty owned string if no relevant memories are found.
pub fn loadContext(
    allocator: std.mem.Allocator,
    mem: Memory,
    user_message: []const u8,
    session_id: ?[]const u8,
    params: RecallParams,
) ![]const u8 {
    const scoped_entries = mem.recall(allocator, user_message, params.scoped_candidate_limit, session_id) catch {
        return try allocator.dupe(u8, "");
    };
    defer memory_mod.freeEntries(allocator, scoped_entries);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    var buf_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &buf);
    const w = &buf_writer.writer;

    var appended: usize = 0;
    var wrote_header = false;

    // Prefer scoped high-signal entries first. Archived conversation chunks are
    // still allowed, but only after non-archived matches from the same scope.
    for ([_]bool{ false, true }) |include_archived| {
        for (scoped_entries) |entry| {
            if (isInternalMemoryEntry(entry)) continue;
            if (isArchiveConversationEntry(entry) != include_archived) continue;
            if (appended >= params.recall_limit or buf.items.len >= params.max_context_bytes) break;
            if (!wrote_header) {
                try w.writeAll("[Memory context]\n");
                wrote_header = true;
            }
            // Truncate individual entry content to prevent a single large memory from blowing the budget
            const content = util.truncateUtf8(entry.content, params.max_context_bytes / 2);
            const sanitized = try sanitizeMemoryText(allocator, content);
            defer allocator.free(sanitized);
            try w.print("- {s}: {s}\n", .{ entry.key, sanitized });
            appended += 1;
        }
        if (appended >= params.recall_limit or buf.items.len >= params.max_context_bytes) break;
    }

    if (appended < params.recall_limit and buf.items.len < params.max_context_bytes and session_id != null) {
        // When scoped recall is enabled, also include global (session_id = null)
        // memory so long-term facts from memory_store remain visible in session chats.
        const global_entries = mem.recall(allocator, user_message, params.global_candidate_limit, null) catch null;
        defer if (global_entries) |entries| memory_mod.freeEntries(allocator, entries);

        if (global_entries) |entries| {
            for (entries) |entry| {
                if (entry.session_id != null) continue; // keep scoped isolation (no cross-session bleed)
                if (containsKey(scoped_entries, entry.key)) continue;
                if (isInternalMemoryEntry(entry)) continue;
                if (isArchiveConversationEntry(entry)) continue; // avoid low-provenance global archive bleed
                if (appended >= params.recall_limit or buf.items.len >= params.max_context_bytes) break;

                if (!wrote_header) {
                    try w.writeAll("[Memory context]\n");
                    wrote_header = true;
                }
                const content = util.truncateUtf8(entry.content, params.max_context_bytes / 2);
                const sanitized = try sanitizeMemoryText(allocator, content);
                defer allocator.free(sanitized);
                try w.print("- {s}: {s}\n", .{ entry.key, sanitized });
                appended += 1;
            }
        }
    }

    if (!wrote_header) {
        return try allocator.dupe(u8, "");
    }
    try w.writeAll("\n");

    buf = buf_writer.toArrayList();
    return try buf.toOwnedSlice(allocator);
}

/// Load context using the full retrieval pipeline (hybrid search, RRF, etc.)
/// when a MemoryRuntime is available.
pub fn loadContextWithRuntime(
    allocator: std.mem.Allocator,
    rt: *MemoryRuntime,
    user_message: []const u8,
    session_id: ?[]const u8,
    params: RecallParams,
) ![]const u8 {
    const scoped_candidates = rt.search(allocator, user_message, params.scoped_candidate_limit, session_id) catch {
        return try allocator.dupe(u8, "");
    };
    defer memory_mod.retrieval.freeCandidates(allocator, scoped_candidates);

    var scoped_fallback_entries: ?[]MemoryEntry = null;
    if (scoped_candidates.len < params.scoped_candidate_limit) {
        scoped_fallback_entries = rt.memory.recall(allocator, user_message, params.scoped_candidate_limit, session_id) catch null;
    }
    defer if (scoped_fallback_entries) |entries| memory_mod.freeEntries(allocator, entries);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    var buf_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &buf);
    const w = &buf_writer.writer;
    var appended: usize = 0;
    var wrote_header = false;

    for ([_]bool{ false, true }) |include_archived| {
        for (scoped_candidates) |cand| {
            if (isInternalMemoryKey(cand.key)) continue;
            if (extractMarkdownMemoryKey(cand.snippet)) |extracted| {
                if (isInternalMemoryKey(extracted)) continue;
            }
            if (isArchiveConversationCandidate(cand) != include_archived) continue;
            if (appended >= params.recall_limit or buf.items.len >= params.max_context_bytes) break;
            if (!wrote_header) {
                try w.writeAll("[Memory context]\n");
                wrote_header = true;
            }
            const snippet = util.truncateUtf8(cand.snippet, params.max_context_bytes / 2);
            const sanitized = try sanitizeMemoryText(allocator, snippet);
            defer allocator.free(sanitized);
            try w.print("- {s}: {s}\n", .{ cand.key, sanitized });
            appended += 1;
        }
        if (appended < params.recall_limit and buf.items.len < params.max_context_bytes) {
            if (scoped_fallback_entries) |entries| {
                for (entries) |entry| {
                    if (containsCandidateKey(scoped_candidates, entry.key)) continue;
                    if (isInternalMemoryEntry(entry)) continue;
                    if (isArchiveConversationEntry(entry) != include_archived) continue;
                    if (appended >= params.recall_limit or buf.items.len >= params.max_context_bytes) break;
                    if (!wrote_header) {
                        try w.writeAll("[Memory context]\n");
                        wrote_header = true;
                    }
                    const content = util.truncateUtf8(entry.content, params.max_context_bytes / 2);
                    const sanitized = try sanitizeMemoryText(allocator, content);
                    defer allocator.free(sanitized);
                    try w.print("- {s}: {s}\n", .{ entry.key, sanitized });
                    appended += 1;
                }
            }
        }
        if (appended >= params.recall_limit or buf.items.len >= params.max_context_bytes) break;
    }

    if (appended < params.recall_limit and buf.items.len < params.max_context_bytes and session_id != null) {
        const global_entries = rt.memory.recall(allocator, user_message, params.global_candidate_limit, null) catch null;
        defer if (global_entries) |entries| memory_mod.freeEntries(allocator, entries);

        if (global_entries) |entries| {
            for (entries) |entry| {
                if (entry.session_id != null) continue; // keep scoped isolation (no cross-session bleed)
                if (containsCandidateKey(scoped_candidates, entry.key)) continue;
                if (scoped_fallback_entries) |fallback_entries| {
                    if (containsKey(fallback_entries, entry.key)) continue;
                }
                if (isInternalMemoryEntry(entry)) continue;
                if (isArchiveConversationEntry(entry)) continue; // avoid low-provenance global archive bleed
                if (appended >= params.recall_limit or buf.items.len >= params.max_context_bytes) break;

                if (!wrote_header) {
                    try w.writeAll("[Memory context]\n");
                    wrote_header = true;
                }
                const content = util.truncateUtf8(entry.content, params.max_context_bytes / 2);
                const sanitized = try sanitizeMemoryText(allocator, content);
                defer allocator.free(sanitized);
                try w.print("- {s}: {s}\n", .{ entry.key, sanitized });
                appended += 1;
            }
        }
    }

    if (!wrote_header) return try allocator.dupe(u8, "");
    try w.writeAll("\n");

    buf = buf_writer.toArrayList();
    return try buf.toOwnedSlice(allocator);
}

/// Enrich a user message with memory context prepended.
/// If no context is available, returns an owned dupe of the original message.
pub fn enrichMessage(
    allocator: std.mem.Allocator,
    mem: Memory,
    user_message: []const u8,
    session_id: ?[]const u8,
    params: RecallParams,
) ![]const u8 {
    const context = try loadContext(allocator, mem, user_message, session_id, params);
    if (context.len == 0) {
        allocator.free(context);
        return try allocator.dupe(u8, user_message);
    }

    defer allocator.free(context);
    return try std.fmt.allocPrint(allocator, "{s}{s}", .{ context, user_message });
}

/// Enrich a user message using the retrieval engine if available, else raw recall.
pub fn enrichMessageWithRuntime(
    allocator: std.mem.Allocator,
    mem: Memory,
    mem_rt: ?*MemoryRuntime,
    user_message: []const u8,
    session_id: ?[]const u8,
    params: RecallParams,
) ![]const u8 {
    const context = if (mem_rt) |rt|
        try loadContextWithRuntime(allocator, rt, user_message, session_id, params)
    else
        try loadContext(allocator, mem, user_message, session_id, params);

    if (context.len == 0) {
        allocator.free(context);
        return try allocator.dupe(u8, user_message);
    }

    defer allocator.free(context);
    return try std.fmt.allocPrint(allocator, "{s}{s}", .{ context, user_message });
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

const test_recall_params = RecallParams{};

test "loadContext returns empty for no-op memory" {
    const allocator = std.testing.allocator;
    var none_mem = memory_mod.NoneMemory.init();
    const mem = none_mem.memory();

    const context = try loadContext(allocator, mem, "hello", null, test_recall_params);
    defer allocator.free(context);

    try std.testing.expectEqualStrings("", context);
}

test "enrichMessage with no context returns original" {
    const allocator = std.testing.allocator;
    var none_mem = memory_mod.NoneMemory.init();
    const mem = none_mem.memory();

    const enriched = try enrichMessage(allocator, mem, "hello", null, test_recall_params);
    defer allocator.free(enriched);

    try std.testing.expectEqualStrings("hello", enriched);
}

test "loadContext with session_id includes global entries but not other sessions" {
    const allocator = std.testing.allocator;

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("sess_a_fact", "session A favorite", .core, "sess-a");
    try mem.store("global_fact", "global favorite", .core, null);
    try mem.store("sess_b_fact", "session B favorite", .core, "sess-b");

    const context = try loadContext(allocator, mem, "favorite", "sess-a", test_recall_params);
    defer allocator.free(context);

    try std.testing.expect(std.mem.indexOf(u8, context, "sess_a_fact") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "global_fact") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "sess_b_fact") == null);
}

test "enrichMessageWithRuntime with no memories returns original message" {
    const allocator = std.testing.allocator;
    var none_mem = memory_mod.NoneMemory.init();
    const mem = none_mem.memory();

    const enriched = try enrichMessageWithRuntime(allocator, mem, null, "hello world", null, test_recall_params);
    defer allocator.free(enriched);

    try std.testing.expectEqualStrings("hello world", enriched);
}

test "enrichMessageWithRuntime recall_limit 0 skips context injection" {
    const allocator = std.testing.allocator;

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("user_lang", "Zig is the favorite language", .core, null);

    const params_disabled = RecallParams{ .recall_limit = 0 };
    const enriched = try enrichMessageWithRuntime(allocator, mem, null, "language", null, params_disabled);
    defer allocator.free(enriched);

    // Should return the original message unchanged — no context injected
    try std.testing.expectEqualStrings("language", enriched);
}

test "enrichMessageWithRuntime with memories prepends context" {
    const allocator = std.testing.allocator;

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("user_lang", "Zig is the favorite language", .core, null);

    const enriched = try enrichMessageWithRuntime(allocator, mem, null, "language", null, test_recall_params);
    defer allocator.free(enriched);

    // Should contain [Memory context] header and the stored entry
    try std.testing.expect(std.mem.indexOf(u8, enriched, "[Memory context]") != null);
    try std.testing.expect(std.mem.indexOf(u8, enriched, "user_lang") != null);
    try std.testing.expect(std.mem.indexOf(u8, enriched, "Zig is the favorite language") != null);
    // The original message should appear at the end
    try std.testing.expect(std.mem.endsWith(u8, enriched, "language"));
}

test "loadContext filters internal autosave and hygiene entries" {
    const allocator = std.testing.allocator;

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("autosave_user_1", "привет", .conversation, null);
    try mem.store("autosave_assistant_1", "Stored memory: autosave_user_1", .conversation, null);
    try mem.store("last_hygiene_at", "1772051598", .core, null);
    try mem.store("user_language", "Отвечай на русском языке", .core, null);

    const context = try loadContext(allocator, mem, "русском", null, test_recall_params);
    defer allocator.free(context);

    try std.testing.expect(std.mem.indexOf(u8, context, "user_language") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "autosave_user_") == null);
    try std.testing.expect(std.mem.indexOf(u8, context, "autosave_assistant_") == null);
    try std.testing.expect(std.mem.indexOf(u8, context, "last_hygiene_at") == null);
}

test "loadContext filters markdown-encoded internal entries" {
    const allocator = std.testing.allocator;

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    // Markdown backend serializes memory as "**key**: value".
    try mem.store("MEMORY:3", "**last_hygiene_at**: 1772051598", .core, null);
    try mem.store("MEMORY:4", "**Name**: User", .core, null);

    const context = try loadContext(allocator, mem, "User", null, test_recall_params);
    defer allocator.free(context);

    try std.testing.expect(std.mem.indexOf(u8, context, "last_hygiene_at") == null);
    try std.testing.expect(std.mem.indexOf(u8, context, "**Name**: User") != null);
}

test "loadContext filters bootstrap prompt internal keys" {
    const allocator = std.testing.allocator;

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("__bootstrap.prompt.SOUL.md", "persona-internal", .core, null);
    try mem.store("user_goal", "ship reliable builds", .core, null);

    const context = try loadContext(allocator, mem, "ship", null, test_recall_params);
    defer allocator.free(context);

    try std.testing.expect(std.mem.indexOf(u8, context, "user_goal") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "__bootstrap.prompt.SOUL.md") == null);
    try std.testing.expect(std.mem.indexOf(u8, context, "persona-internal") == null);
}

test "loadContextWithRuntime returns empty when only internal entries match" {
    const allocator = std.testing.allocator;

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("autosave_user_1", "привет", .conversation, null);
    try mem.store("autosave_assistant_1", "Stored memory: autosave_user_1", .conversation, null);
    try mem.store("last_hygiene_at", "1772051598", .core, null);

    const resolved = memory_mod.ResolvedConfig{
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
    var rt = memory_mod.MemoryRuntime{
        .memory = mem,
        .session_store = null,
        .response_cache = null,
        .capabilities = .{
            .supports_keyword_rank = false,
            .supports_session_store = false,
            .supports_transactions = false,
            .supports_outbox = false,
        },
        .resolved = resolved,
        ._db_path = null,
        ._cache_db_path = null,
        ._engine = null,
        ._allocator = allocator,
    };

    const context = try loadContextWithRuntime(allocator, &rt, "привет", null, test_recall_params);
    defer allocator.free(context);
    try std.testing.expectEqualStrings("", context);
}

test "loadContextWithRuntime with session_id includes global entries but not other sessions" {
    const allocator = std.testing.allocator;

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("sess_a_fact", "session A favorite", .core, "sess-a");
    try mem.store("global_fact", "global favorite", .core, null);
    try mem.store("sess_b_fact", "session B favorite", .core, "sess-b");

    const resolved = memory_mod.ResolvedConfig{
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
    var rt = memory_mod.MemoryRuntime{
        .memory = mem,
        .session_store = null,
        .response_cache = null,
        .capabilities = .{
            .supports_keyword_rank = false,
            .supports_session_store = false,
            .supports_transactions = false,
            .supports_outbox = false,
        },
        .resolved = resolved,
        ._db_path = null,
        ._cache_db_path = null,
        ._engine = null,
        ._allocator = allocator,
    };

    const context = try loadContextWithRuntime(allocator, &rt, "favorite", "sess-a", test_recall_params);
    defer allocator.free(context);

    try std.testing.expect(std.mem.indexOf(u8, context, "sess_a_fact") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "global_fact") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "sess_b_fact") == null);
}

test "loadContext skips globally preserved archive conversation entries" {
    const allocator = std.testing.allocator;

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("sess_a_fact", "session A favorite", .core, "sess-a");
    try mem.store("global_fact", "global favorite", .core, null);
    // Regression: globally scoped archive shards can leak unrelated legacy turns.
    try mem.store(
        "archive:conversation:autosave_user_1699999999000000000:chunk:0",
        "Archived conversation source: archive:conversation:autosave_user_1699999999000000000\nChunk: 1/1\n\nfavorite legacy transcript",
        .{ .custom = "archive" },
        null,
    );

    const context = try loadContext(allocator, mem, "favorite", "sess-a", test_recall_params);
    defer allocator.free(context);

    try std.testing.expect(std.mem.indexOf(u8, context, "sess_a_fact") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "global_fact") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "archive:conversation:autosave_user_1699999999000000000:chunk:0") == null);
}

test "loadContextWithRuntime skips globally preserved archive conversation entries" {
    const allocator = std.testing.allocator;

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("sess_a_fact", "session A favorite", .core, "sess-a");
    try mem.store("global_fact", "global favorite", .core, null);
    // Regression: globally scoped archive shards can leak unrelated legacy turns.
    try mem.store(
        "archive:conversation:autosave_user_1699999999000000000:chunk:0",
        "Archived conversation source: archive:conversation:autosave_user_1699999999000000000\nChunk: 1/1\n\nfavorite legacy transcript",
        .{ .custom = "archive" },
        null,
    );

    const resolved = memory_mod.ResolvedConfig{
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
    var rt = memory_mod.MemoryRuntime{
        .memory = mem,
        .session_store = null,
        .response_cache = null,
        .capabilities = .{
            .supports_keyword_rank = false,
            .supports_session_store = false,
            .supports_transactions = false,
            .supports_outbox = false,
        },
        .resolved = resolved,
        ._db_path = null,
        ._cache_db_path = null,
        ._engine = null,
        ._allocator = allocator,
    };

    const context = try loadContextWithRuntime(allocator, &rt, "favorite", "sess-a", test_recall_params);
    defer allocator.free(context);

    try std.testing.expect(std.mem.indexOf(u8, context, "sess_a_fact") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "global_fact") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "archive:conversation:autosave_user_1699999999000000000:chunk:0") == null);
}

test "loadContext prefers scoped facts when archive candidates fill recall window" {
    const allocator = std.testing.allocator;

    var mem_impl = memory_mod.InMemoryLruMemory.init(allocator, 32);
    defer mem_impl.deinit();
    const mem = mem_impl.memory();

    try mem.store("scoped_fact", "needle scoped answer", .core, "sess-a");
    var idx: usize = 0;
    while (idx < test_recall_params.recall_limit) : (idx += 1) {
        var key_buf: [96]u8 = undefined;
        const key = try std.fmt.bufPrint(
            &key_buf,
            "archive:conversation:autosave_user_1700000000000000000:chunk:{d}",
            .{idx},
        );
        try mem.store(key, "needle archived transcript", .{ .custom = "archive" }, "sess-a");
    }

    // Regression: archive chunks can fill the raw recall limit and hide a lower-ranked scoped fact.
    const context = try loadContext(allocator, mem, "needle", "sess-a", test_recall_params);
    defer allocator.free(context);

    const fact_pos = std.mem.indexOf(u8, context, "scoped_fact") orelse return error.TestUnexpectedResult;
    const archive_pos = std.mem.indexOf(u8, context, "archive:conversation:") orelse return error.TestUnexpectedResult;
    try std.testing.expect(fact_pos < archive_pos);
}

test "loadContextWithRuntime prefers scoped facts when engine candidates fill with archives" {
    const allocator = std.testing.allocator;

    var mem_impl = memory_mod.InMemoryLruMemory.init(allocator, 32);
    defer mem_impl.deinit();
    const mem = mem_impl.memory();

    try mem.store("scoped_fact", "needle scoped answer", .core, "sess-a");
    var idx: usize = 0;
    while (idx < test_recall_params.recall_limit) : (idx += 1) {
        var key_buf: [96]u8 = undefined;
        const key = try std.fmt.bufPrint(
            &key_buf,
            "archive:conversation:autosave_user_1700000000000000000:chunk:{d}",
            .{idx},
        );
        try mem.store(key, "needle archived transcript", .{ .custom = "archive" }, "sess-a");
    }

    var primary = memory_mod.PrimaryAdapter.init(mem);
    var engine = memory_mod.RetrievalEngine.init(allocator, .{ .max_results = test_recall_params.recall_limit });
    defer engine.deinit();
    try engine.addSource(primary.adapter());

    const resolved = memory_mod.ResolvedConfig{
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
    var rt = memory_mod.MemoryRuntime{
        .memory = mem,
        .session_store = null,
        .response_cache = null,
        .capabilities = .{
            .supports_keyword_rank = false,
            .supports_session_store = false,
            .supports_transactions = false,
            .supports_outbox = false,
        },
        .resolved = resolved,
        ._db_path = null,
        ._cache_db_path = null,
        ._engine = &engine,
        ._allocator = allocator,
    };

    // Regression: engine top_k can fill with archive chunks and hide a lower-ranked scoped fact.
    const context = try loadContextWithRuntime(allocator, &rt, "needle", "sess-a", test_recall_params);
    defer allocator.free(context);

    const fact_pos = std.mem.indexOf(u8, context, "scoped_fact") orelse return error.TestUnexpectedResult;
    const archive_pos = std.mem.indexOf(u8, context, "archive:conversation:") orelse return error.TestUnexpectedResult;
    try std.testing.expect(fact_pos < archive_pos);
}
