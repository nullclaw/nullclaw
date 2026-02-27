const std = @import("std");
const memory_mod = @import("../memory/root.zig");
const multimodal = @import("../multimodal.zig");
const Memory = memory_mod.Memory;
const MemoryEntry = memory_mod.MemoryEntry;
const MemoryRuntime = memory_mod.MemoryRuntime;

// ═══════════════════════════════════════════════════════════════════════════
// Memory Loader — inject relevant memory context into user messages
// ═══════════════════════════════════════════════════════════════════════════

/// Default number of memory entries to recall per query.
const DEFAULT_RECALL_LIMIT: usize = 5;
const GLOBAL_RECALL_CANDIDATE_LIMIT: usize = 64;

/// Maximum total bytes of memory context injected into a message.
/// Prevents a few large entries from blowing the token budget.
/// ~4000 chars ~ 1000 tokens — a safe ceiling for context injection.
const MAX_CONTEXT_BYTES: usize = 4_000;

/// Truncate a UTF-8 slice to at most `max_len` bytes without splitting
/// a multi-byte sequence. Backs up over trailing continuation bytes (0x80..0xBF).
fn truncateUtf8(s: []const u8, max_len: usize) []const u8 {
    if (s.len <= max_len) return s;
    var end: usize = max_len;
    while (end > 0 and s[end] & 0xC0 == 0x80) end -= 1;
    return s[0..end];
}

fn containsKey(entries: []const MemoryEntry, key: []const u8) bool {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return true;
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
) ![]const u8 {
    const scoped_entries = mem.recall(allocator, user_message, DEFAULT_RECALL_LIMIT, session_id) catch {
        return try allocator.dupe(u8, "");
    };
    defer memory_mod.freeEntries(allocator, scoped_entries);

    // When scoped recall is enabled, also include global (session_id = null) memory
    // so long-term facts from memory_store remain visible in session chats.
    var global_entries: ?[]MemoryEntry = null;
    if (session_id != null and scoped_entries.len < DEFAULT_RECALL_LIMIT) {
        global_entries = mem.recall(allocator, user_message, GLOBAL_RECALL_CANDIDATE_LIMIT, null) catch null;
    }
    defer if (global_entries) |entries| memory_mod.freeEntries(allocator, entries);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    var appended: usize = 0;
    var wrote_header = false;

    for (scoped_entries) |entry| {
        if (isInternalMemoryEntry(entry)) continue;
        if (!wrote_header) {
            try w.writeAll("[Memory context]\n");
            wrote_header = true;
        }
        // Truncate individual entry content to prevent a single large memory from blowing the budget
        const content = truncateUtf8(entry.content, MAX_CONTEXT_BYTES / 2);
        const sanitized = try sanitizeMemoryText(allocator, content);
        defer allocator.free(sanitized);
        try std.fmt.format(w, "- {s}: {s}\n", .{ entry.key, sanitized });
        appended += 1;
        if (appended >= DEFAULT_RECALL_LIMIT or buf.items.len >= MAX_CONTEXT_BYTES) break;
    }

    if (appended < DEFAULT_RECALL_LIMIT and buf.items.len < MAX_CONTEXT_BYTES and session_id != null) {
        if (global_entries) |entries| {
            for (entries) |entry| {
                if (entry.session_id != null) continue; // keep scoped isolation (no cross-session bleed)
                if (containsKey(scoped_entries, entry.key)) continue;
                if (isInternalMemoryEntry(entry)) continue;

                if (!wrote_header) {
                    try w.writeAll("[Memory context]\n");
                    wrote_header = true;
                }
                const content = truncateUtf8(entry.content, MAX_CONTEXT_BYTES / 2);
                const sanitized = try sanitizeMemoryText(allocator, content);
                defer allocator.free(sanitized);
                try std.fmt.format(w, "- {s}: {s}\n", .{ entry.key, sanitized });
                appended += 1;
                if (appended >= DEFAULT_RECALL_LIMIT or buf.items.len >= MAX_CONTEXT_BYTES) break;
            }
        }
    }

    if (!wrote_header) {
        return try allocator.dupe(u8, "");
    }
    try w.writeAll("\n");

    return try buf.toOwnedSlice(allocator);
}

/// Load context using the full retrieval pipeline (hybrid search, RRF, etc.)
/// when a MemoryRuntime is available.
pub fn loadContextWithRuntime(
    allocator: std.mem.Allocator,
    rt: *MemoryRuntime,
    user_message: []const u8,
    session_id: ?[]const u8,
) ![]const u8 {
    const candidates = rt.search(allocator, user_message, DEFAULT_RECALL_LIMIT, session_id) catch {
        return try allocator.dupe(u8, "");
    };
    defer memory_mod.retrieval.freeCandidates(allocator, candidates);

    if (candidates.len == 0) return try allocator.dupe(u8, "");

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    var wrote_header = false;

    for (candidates) |cand| {
        if (isInternalMemoryKey(cand.key)) continue;
        if (extractMarkdownMemoryKey(cand.snippet)) |extracted| {
            if (isInternalMemoryKey(extracted)) continue;
        }
        if (!wrote_header) {
            try w.writeAll("[Memory context]\n");
            wrote_header = true;
        }
        const snippet = truncateUtf8(cand.snippet, MAX_CONTEXT_BYTES / 2);
        const sanitized = try sanitizeMemoryText(allocator, snippet);
        defer allocator.free(sanitized);
        try std.fmt.format(w, "- {s}: {s}\n", .{ cand.key, sanitized });
        if (buf.items.len >= MAX_CONTEXT_BYTES) break;
    }
    if (!wrote_header) return try allocator.dupe(u8, "");
    try w.writeAll("\n");

    return try buf.toOwnedSlice(allocator);
}

/// Enrich a user message with memory context prepended.
/// If no context is available, returns an owned dupe of the original message.
pub fn enrichMessage(
    allocator: std.mem.Allocator,
    mem: Memory,
    user_message: []const u8,
    session_id: ?[]const u8,
) ![]const u8 {
    const context = try loadContext(allocator, mem, user_message, session_id);
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
) ![]const u8 {
    const context = if (mem_rt) |rt|
        try loadContextWithRuntime(allocator, rt, user_message, session_id)
    else
        try loadContext(allocator, mem, user_message, session_id);

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

test "loadContext returns empty for no-op memory" {
    const allocator = std.testing.allocator;
    var none_mem = memory_mod.NoneMemory.init();
    const mem = none_mem.memory();

    const context = try loadContext(allocator, mem, "hello", null);
    defer allocator.free(context);

    try std.testing.expectEqualStrings("", context);
}

test "enrichMessage with no context returns original" {
    const allocator = std.testing.allocator;
    var none_mem = memory_mod.NoneMemory.init();
    const mem = none_mem.memory();

    const enriched = try enrichMessage(allocator, mem, "hello", null);
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

    const context = try loadContext(allocator, mem, "favorite", "sess-a");
    defer allocator.free(context);

    try std.testing.expect(std.mem.indexOf(u8, context, "sess_a_fact") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "global_fact") != null);
    try std.testing.expect(std.mem.indexOf(u8, context, "sess_b_fact") == null);
}

test "truncateUtf8 does not split multi-byte sequences" {
    // ASCII-only: truncation at limit
    try std.testing.expectEqualStrings("abc", truncateUtf8("abcdef", 3));

    // Under limit: returns as-is
    try std.testing.expectEqualStrings("ab", truncateUtf8("ab", 10));

    // 2-byte char at boundary: "aaa" (3 bytes) + "Й" (D0 99 = 2 bytes)
    const s2 = "aaa\xd0\x99";
    // Limit 4: byte 4 is 0x99 (continuation), back up to 3 which is 0xD0 (leading) -> [0..3]
    try std.testing.expectEqualStrings("aaa", truncateUtf8(s2, 4));
    // Limit 5: full string fits exactly
    try std.testing.expectEqualStrings(s2, truncateUtf8(s2, 5));

    // 3-byte char "中" (E4 B8 AD) at boundary
    const s3 = "aa\xe4\xb8\xad";
    // Limit 3: byte 3 is 0xB8 (continuation), back to 2 -> 0xE4 (leading) -> [0..2]
    try std.testing.expectEqualStrings("aa", truncateUtf8(s3, 3));
    // Limit 4: byte 4 is 0xAD (continuation), back to 3 -> 0xB8 (continuation), back to 2 -> 0xE4 (leading) -> [0..2]
    try std.testing.expectEqualStrings("aa", truncateUtf8(s3, 4));

    // 4-byte emoji U+1F600 (F0 9F 98 80)
    const s4 = "a\xf0\x9f\x98\x80";
    // Limit 2: byte 2 is 0x9F (continuation), back to 1 -> 0xF0 (leading) -> [0..1]
    try std.testing.expectEqualStrings("a", truncateUtf8(s4, 2));

    // All results should be valid UTF-8
    try std.testing.expect(std.unicode.utf8ValidateSlice(truncateUtf8(s2, 4)));
    try std.testing.expect(std.unicode.utf8ValidateSlice(truncateUtf8(s3, 3)));
    try std.testing.expect(std.unicode.utf8ValidateSlice(truncateUtf8(s4, 2)));
}

test "enrichMessageWithRuntime with no memories returns original message" {
    const allocator = std.testing.allocator;
    var none_mem = memory_mod.NoneMemory.init();
    const mem = none_mem.memory();

    const enriched = try enrichMessageWithRuntime(allocator, mem, null, "hello world", null);
    defer allocator.free(enriched);

    try std.testing.expectEqualStrings("hello world", enriched);
}

test "enrichMessageWithRuntime with memories prepends context" {
    const allocator = std.testing.allocator;

    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    try mem.store("user_lang", "Zig is the favorite language", .core, null);

    const enriched = try enrichMessageWithRuntime(allocator, mem, null, "language", null);
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

    const context = try loadContext(allocator, mem, "русском", null);
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

    const context = try loadContext(allocator, mem, "User", null);
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

    const context = try loadContext(allocator, mem, "ship", null);
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

    const context = try loadContextWithRuntime(allocator, &rt, "привет", null);
    defer allocator.free(context);
    try std.testing.expectEqualStrings("", context);
}
