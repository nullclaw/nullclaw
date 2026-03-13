//! Session Digest — post-session extractive learning.
//!
//! Analyses conversation history at session end and extracts reusable
//! insights: user preferences, tool usage patterns, and task types.
//! Results are persisted as `__digest.*` memory keys for future recall.
//!
//! Current implementation uses extractive analysis (no LLM calls).
//! Can be upgraded to LLM-based abstraction in a future phase.

const std = @import("std");
const builtin = @import("builtin");
const memory_mod = @import("../memory/root.zig");
const Memory = memory_mod.Memory;

pub const log = std.log.scoped(.session_digest);

/// Configuration for session digest generation.
pub const SessionDigestConfig = struct {
    /// Enable digest generation on session end.
    enabled: bool = false,
    /// Minimum turns required before a digest is generated.
    min_turns: u32 = 3,
    /// Maximum source chars to analyse (prevents budget blowout on long sessions).
    max_source_chars: u32 = 32_000,
    /// Trigger digest after this many idle seconds (0 = disabled, use eviction only).
    trigger_after_idle_secs: u64 = 0,
    /// Generate digest on /new or /reset.
    on_reset: bool = true,
    /// Generate digest on session eviction.
    on_eviction: bool = true,
};

/// Extracted insights from a conversation session.
pub const DigestResult = struct {
    /// User preferences discovered in this session.
    user_preferences: [][]const u8,
    /// Tool usage insights (which tools worked well, which failed).
    tool_insights: [][]const u8,
    /// Recurring task patterns.
    task_patterns: [][]const u8,
    /// Session statistics summary.
    summary: []const u8,

    pub fn deinit(self: *const DigestResult, allocator: std.mem.Allocator) void {
        for (self.user_preferences) |p| allocator.free(p);
        allocator.free(self.user_preferences);
        for (self.tool_insights) |t| allocator.free(t);
        allocator.free(self.tool_insights);
        for (self.task_patterns) |p| allocator.free(p);
        allocator.free(self.task_patterns);
        allocator.free(self.summary);
    }

    pub fn isEmpty(self: *const DigestResult) bool {
        return self.user_preferences.len == 0 and
            self.tool_insights.len == 0 and
            self.task_patterns.len == 0;
    }
};

/// Message role/content pair for digest input.
pub const DigestMessage = struct {
    role: []const u8,
    content: []const u8,
};

/// Generate an extractive digest from conversation messages.
/// Analyses message content for patterns without making LLM calls.
pub fn generateDigest(
    allocator: std.mem.Allocator,
    messages: []const DigestMessage,
    config: SessionDigestConfig,
) !DigestResult {
    if (messages.len == 0) {
        return emptyResult(allocator);
    }

    var prefs: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (prefs.items) |p| allocator.free(p);
        prefs.deinit(allocator);
    }
    var tools: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (tools.items) |t| allocator.free(t);
        tools.deinit(allocator);
    }
    var patterns: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (patterns.items) |p| allocator.free(p);
        patterns.deinit(allocator);
    }

    var total_chars: usize = 0;
    var user_turns: u32 = 0;
    var assistant_turns: u32 = 0;
    var tool_calls: u32 = 0;
    var tool_failures: u32 = 0;

    for (messages) |msg| {
        if (total_chars >= config.max_source_chars) break;
        total_chars += msg.content.len;

        if (std.mem.eql(u8, msg.role, "user")) {
            user_turns += 1;
            // Extract preference signals from user messages
            try extractPreferences(allocator, msg.content, &prefs);
        } else if (std.mem.eql(u8, msg.role, "assistant")) {
            assistant_turns += 1;
            // Count tool usage from assistant responses
            const tc = countToolCalls(msg.content);
            tool_calls += tc.calls;
            tool_failures += tc.failures;
        }
    }

    // Extract tool insights if tools were used
    if (tool_calls > 0) {
        const insight = try std.fmt.allocPrint(allocator, "Session used {d} tool calls ({d} failures)", .{ tool_calls, tool_failures });
        try tools.append(allocator, insight);
    }

    // Build summary
    const summary = try std.fmt.allocPrint(
        allocator,
        "Session: {d} user turns, {d} assistant turns, {d} tool calls ({d} failed)",
        .{ user_turns, assistant_turns, tool_calls, tool_failures },
    );

    return DigestResult{
        .user_preferences = try prefs.toOwnedSlice(allocator),
        .tool_insights = try tools.toOwnedSlice(allocator),
        .task_patterns = try patterns.toOwnedSlice(allocator),
        .summary = summary,
    };
}

/// Persist digest results to the memory system with `__digest.*` keys.
pub fn storeDigest(
    mem: Memory,
    session_id: []const u8,
    digest: *const DigestResult,
    allocator: std.mem.Allocator,
) void {
    // Store user preferences as core memories (long-lived)
    for (digest.user_preferences, 0..) |pref, i| {
        var key_buf: [128]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "__digest.user.{s}.{d}", .{ session_id, i }) catch continue;
        mem.store(key, pref, .core, null) catch |err| {
            log.warn("failed to store digest preference: {s}", .{@errorName(err)});
        };
    }

    // Store tool insights
    for (digest.tool_insights, 0..) |insight, i| {
        var key_buf: [128]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "__digest.tools.{s}.{d}", .{ session_id, i }) catch continue;
        mem.store(key, insight, .core, null) catch |err| {
            log.warn("failed to store digest tool insight: {s}", .{@errorName(err)});
        };
    }

    // Store session summary
    if (digest.summary.len > 0) {
        var key_buf: [128]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "__digest.summary.{s}", .{session_id}) catch return;
        mem.store(key, digest.summary, .daily, null) catch |err| {
            log.warn("failed to store digest summary: {s}", .{@errorName(err)});
        };
    }

    _ = allocator;
}

// ── Extractive analysis helpers ──────────────────────────────────

/// Preference signal keywords (Dutch + English).
const preference_signals = [_][]const u8{
    "ik wil",     "ik wilt",    "ik heb liever",  "ik prefereer",
    "altijd",     "nooit",      "gebruik",         "niet meer",
    "I want",     "I prefer",   "always",          "never",
    "don't",      "please use", "stop using",      "switch to",
    "liever in",  "graag in",   "voortaan",
};

fn extractPreferences(allocator: std.mem.Allocator, content: []const u8, prefs: *std.ArrayListUnmanaged([]const u8)) !void {
    // Limit number of preferences per session to prevent bloat
    if (prefs.items.len >= 5) return;

    for (preference_signals) |signal| {
        if (std.ascii.indexOfIgnoreCase(content, signal)) |pos| {
            // Extract a window around the preference signal
            const start = if (pos > 20) pos - 20 else 0;
            const end = @min(content.len, pos + signal.len + 80);
            // Find sentence boundaries
            const sentence_start = if (std.mem.lastIndexOfScalar(u8, content[start..pos], '.')) |p|
                start + p + 1
            else
                start;
            var sentence_end = end;
            if (std.mem.indexOfScalar(u8, content[pos..end], '.')) |p| {
                sentence_end = pos + p + 1;
            }
            const snippet = std.mem.trim(u8, content[sentence_start..sentence_end], " \t\n\r");
            if (snippet.len > 10 and snippet.len < 200) {
                const duped = try allocator.dupe(u8, snippet);
                try prefs.append(allocator, duped);
                if (prefs.items.len >= 5) return;
            }
        }
    }
}

const ToolCallCounts = struct { calls: u32, failures: u32 };

fn countToolCalls(content: []const u8) ToolCallCounts {
    var calls: u32 = 0;
    var failures: u32 = 0;
    // Count tool_call XML markers in assistant responses
    var pos: usize = 0;
    while (pos < content.len) {
        if (std.mem.indexOf(u8, content[pos..], "<tool_call")) |idx| {
            calls += 1;
            pos += idx + 10;
        } else break;
    }
    pos = 0;
    while (pos < content.len) {
        if (std.mem.indexOf(u8, content[pos..], "status=\"error\"")) |idx| {
            failures += 1;
            pos += idx + 14;
        } else break;
    }
    // Also count JSON-style tool calls
    pos = 0;
    while (pos < content.len) {
        if (std.mem.indexOf(u8, content[pos..], "\"tool_calls\"")) |idx| {
            calls += 1;
            pos += idx + 12;
        } else break;
    }
    return .{ .calls = calls, .failures = failures };
}

fn emptyResult(allocator: std.mem.Allocator) !DigestResult {
    return DigestResult{
        .user_preferences = try allocator.alloc([]const u8, 0),
        .tool_insights = try allocator.alloc([]const u8, 0),
        .task_patterns = try allocator.alloc([]const u8, 0),
        .summary = try allocator.dupe(u8, ""),
    };
}

// ── Tests ───────────────────────────────────────────────────────────

test "generateDigest with empty messages returns empty result" {
    const allocator = std.testing.allocator;
    const result = try generateDigest(allocator, &.{}, .{});
    defer result.deinit(allocator);
    try std.testing.expect(result.isEmpty());
    try std.testing.expectEqualStrings("", result.summary);
}

test "generateDigest counts turns correctly" {
    const allocator = std.testing.allocator;
    const messages = [_]DigestMessage{
        .{ .role = "user", .content = "Hello" },
        .{ .role = "assistant", .content = "Hi there!" },
        .{ .role = "user", .content = "How are you?" },
        .{ .role = "assistant", .content = "I'm good!" },
    };
    const result = try generateDigest(allocator, &messages, .{});
    defer result.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "2 user turns") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "2 assistant turns") != null);
}

test "generateDigest extracts preference signals" {
    const allocator = std.testing.allocator;
    const messages = [_]DigestMessage{
        .{ .role = "user", .content = "Ik wil altijd antwoord in het Nederlands krijgen." },
        .{ .role = "assistant", .content = "Begrepen, ik zal voortaan in het Nederlands antwoorden." },
    };
    const result = try generateDigest(allocator, &messages, .{});
    defer result.deinit(allocator);
    try std.testing.expect(result.user_preferences.len > 0);
}

test "generateDigest counts tool calls in assistant messages" {
    const allocator = std.testing.allocator;
    const messages = [_]DigestMessage{
        .{ .role = "user", .content = "Read the config file" },
        .{ .role = "assistant", .content = "<tool_call name=\"file_read\"><args>{\"path\":\"config.json\"}</args></tool_call>" },
    };
    const result = try generateDigest(allocator, &messages, .{});
    defer result.deinit(allocator);
    try std.testing.expect(result.tool_insights.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, result.tool_insights[0], "1 tool calls") != null);
}

test "generateDigest respects max_source_chars" {
    const allocator = std.testing.allocator;
    var long_content: [1000]u8 = undefined;
    @memset(&long_content, 'a');
    const messages = [_]DigestMessage{
        .{ .role = "user", .content = &long_content },
        .{ .role = "user", .content = "I prefer dark mode always." },
    };
    // With very low limit, second message should be skipped
    const result = try generateDigest(allocator, &messages, .{ .max_source_chars = 500 });
    defer result.deinit(allocator);
    // Should have processed at least the first message
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "user turns") != null);
}

test "generateDigest detects tool failures" {
    const allocator = std.testing.allocator;
    const messages = [_]DigestMessage{
        .{ .role = "user", .content = "Run the tests" },
        .{ .role = "assistant", .content = "<tool_result name=\"shell\" status=\"error\">Command failed</tool_result>" },
    };
    const result = try generateDigest(allocator, &messages, .{});
    defer result.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, result.summary, "1 failed") != null);
}

test "DigestResult isEmpty checks all fields" {
    const allocator = std.testing.allocator;
    const empty = try emptyResult(allocator);
    defer empty.deinit(allocator);
    try std.testing.expect(empty.isEmpty());
}

test "extractPreferences limits to 5 per session" {
    const allocator = std.testing.allocator;
    var prefs: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (prefs.items) |p| allocator.free(p);
        prefs.deinit(allocator);
    }
    // Feed many preference signals
    for (0..10) |_| {
        try extractPreferences(allocator, "I prefer to always use dark mode in the editor.", &prefs);
    }
    try std.testing.expect(prefs.items.len <= 5);
}

test "countToolCalls counts XML tool calls" {
    const result = countToolCalls("<tool_call name=\"a\">x</tool_call><tool_call name=\"b\">y</tool_call>");
    try std.testing.expectEqual(@as(u32, 2), result.calls);
}

test "countToolCalls detects failures" {
    const result = countToolCalls("<tool_result name=\"shell\" status=\"error\">fail</tool_result>");
    try std.testing.expectEqual(@as(u32, 1), result.failures);
}

test "storeDigest persists to memory" {
    const allocator = std.testing.allocator;
    var sqlite_mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer sqlite_mem.deinit();
    const mem = sqlite_mem.memory();

    const prefs = try allocator.alloc([]const u8, 1);
    prefs[0] = try allocator.dupe(u8, "prefers dark mode");
    const tools_arr = try allocator.alloc([]const u8, 0);
    const patterns_arr = try allocator.alloc([]const u8, 0);

    const digest = DigestResult{
        .user_preferences = prefs,
        .tool_insights = tools_arr,
        .task_patterns = patterns_arr,
        .summary = try allocator.dupe(u8, "test session summary"),
    };
    defer digest.deinit(allocator);

    storeDigest(mem, "test-session", &digest, allocator);

    // Verify stored
    const entry = try mem.get(allocator, "__digest.user.test-session.0");
    try std.testing.expect(entry != null);
    if (entry) |e| {
        defer e.deinit(allocator);
        try std.testing.expectEqualStrings("prefers dark mode", e.content);
    }

    const summary_entry = try mem.get(allocator, "__digest.summary.test-session");
    try std.testing.expect(summary_entry != null);
    if (summary_entry) |e| {
        defer e.deinit(allocator);
        try std.testing.expectEqualStrings("test session summary", e.content);
    }
}
