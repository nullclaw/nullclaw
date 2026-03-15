//! Adaptive retrieval strategy selection.
//!
//! Analyzes query characteristics (token count, special chars, question words)
//! and recommends the optimal retrieval strategy: keyword-only, vector-only,
//! or hybrid. This avoids always running both search paths when a simpler
//! strategy would suffice.

const std = @import("std");

pub const RetrievalStrategy = enum {
    keyword_only,
    vector_only,
    hybrid,
};

pub const AdaptiveConfig = struct {
    enabled: bool = false,
    keyword_max_tokens: u32 = 3, // queries with <= this many tokens → keyword_only
    vector_min_tokens: u32 = 6, // queries with >= this many tokens → vector_only
    // Between keyword_max_tokens and vector_min_tokens → hybrid
};

pub const QueryAnalysis = struct {
    token_count: u32,
    has_special_chars: bool,
    is_question: bool,
    avg_token_length: f32,
    recommended_strategy: RetrievalStrategy,
};

/// Analyze a query and recommend a retrieval strategy.
/// Pure function — no allocations, no side effects.
pub fn analyzeQuery(query: []const u8, config: AdaptiveConfig) QueryAnalysis {
    // If adaptive is disabled, always return hybrid (let engine decide)
    if (!config.enabled) {
        return .{
            .token_count = 0,
            .has_special_chars = false,
            .is_question = false,
            .avg_token_length = 0.0,
            .recommended_strategy = .hybrid,
        };
    }

    // Tokenize on whitespace
    var token_count: u32 = 0;
    var total_char_len: u32 = 0;
    var has_special_chars = false;

    var it = std.mem.splitScalar(u8, query, ' ');
    while (it.next()) |token| {
        if (token.len == 0) continue;
        token_count += 1;
        total_char_len += @intCast(token.len);

        if (!has_special_chars) {
            for (token) |c| {
                if (c == '_' or c == '.' or c == '/' or c == '\\' or c == ':' or c == '-') {
                    has_special_chars = true;
                    break;
                }
            }
        }
    }

    // Empty query → keyword_only fallback
    if (token_count == 0) {
        return .{
            .token_count = 0,
            .has_special_chars = false,
            .is_question = false,
            .avg_token_length = 0.0,
            .recommended_strategy = .keyword_only,
        };
    }

    const avg_token_length: f32 = @as(f32, @floatFromInt(total_char_len)) / @as(f32, @floatFromInt(token_count));

    const is_question = isQuestionQuery(query);

    // Strategy rules (ordered by priority):
    // 1. Special chars (underscores, dots, slashes) → keyword_only (key lookup)
    // 2. Very short (<=keyword_max_tokens) → keyword_only
    // 3. Question + long (>=vector_min_tokens) → vector_only
    // 4. Long (>=vector_min_tokens) → hybrid
    // 5. Otherwise → hybrid
    const strategy: RetrievalStrategy = if (has_special_chars)
        .keyword_only
    else if (token_count <= config.keyword_max_tokens)
        .keyword_only
    else if (is_question and token_count >= config.vector_min_tokens)
        .vector_only
    else if (token_count >= config.vector_min_tokens)
        .hybrid
    else
        .hybrid;

    return .{
        .token_count = token_count,
        .has_special_chars = has_special_chars,
        .is_question = is_question,
        .avg_token_length = avg_token_length,
        .recommended_strategy = strategy,
    };
}

/// Check if query starts with a question word.
fn isQuestionQuery(query: []const u8) bool {
    const question_prefixes = [_][]const u8{
        "what ",  "how ", "why ",   "when ", "where ", "who ",
        "which ", "can ", "could ", "does ", "do ",    "is ",
        "are ",
    };

    // Build a lowercase prefix to compare (enough for the longest question word)
    var lower_buf: [8]u8 = undefined;
    const check_len = @min(query.len, lower_buf.len);
    for (query[0..check_len], 0..) |c, i| {
        lower_buf[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }
    const lower_prefix = lower_buf[0..check_len];

    for (question_prefixes) |prefix| {
        if (std.mem.startsWith(u8, lower_prefix, prefix)) return true;
    }

    return false;
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

const enabled_config = AdaptiveConfig{ .enabled = true };

test "keyword_only for key-like query with underscore" {
    const result = analyzeQuery("user_preferences", enabled_config);
    try testing.expectEqual(RetrievalStrategy.keyword_only, result.recommended_strategy);
    try testing.expect(result.has_special_chars);
    try testing.expectEqual(@as(u32, 1), result.token_count);
}

test "keyword_only for dotted path" {
    const result = analyzeQuery("config.memory.backend", enabled_config);
    try testing.expectEqual(RetrievalStrategy.keyword_only, result.recommended_strategy);
    try testing.expect(result.has_special_chars);
}

test "vector_only for long question" {
    const result = analyzeQuery("how does the authentication system work in this project", enabled_config);
    try testing.expectEqual(RetrievalStrategy.vector_only, result.recommended_strategy);
    try testing.expect(result.is_question);
    try testing.expectEqual(@as(u32, 9), result.token_count);
}

test "keyword_only for short query" {
    const result = analyzeQuery("Zig memory", enabled_config);
    try testing.expectEqual(RetrievalStrategy.keyword_only, result.recommended_strategy);
    try testing.expectEqual(@as(u32, 2), result.token_count);
    try testing.expect(!result.has_special_chars);
}

test "hybrid for moderate query" {
    const result = analyzeQuery("best practices for memory management", enabled_config);
    try testing.expectEqual(RetrievalStrategy.hybrid, result.recommended_strategy);
    try testing.expectEqual(@as(u32, 5), result.token_count);
}

test "keyword_only for single question word" {
    const result = analyzeQuery("what", enabled_config);
    try testing.expectEqual(RetrievalStrategy.keyword_only, result.recommended_strategy);
    try testing.expectEqual(@as(u32, 1), result.token_count);
}

test "keyword_only for empty query" {
    const result = analyzeQuery("", enabled_config);
    try testing.expectEqual(RetrievalStrategy.keyword_only, result.recommended_strategy);
    try testing.expectEqual(@as(u32, 0), result.token_count);
}

test "disabled config always returns hybrid" {
    const disabled = AdaptiveConfig{ .enabled = false };
    const result = analyzeQuery("user_preferences", disabled);
    try testing.expectEqual(RetrievalStrategy.hybrid, result.recommended_strategy);
}

test "keyword_only for path with slashes" {
    const result = analyzeQuery("src/memory/root.zig", enabled_config);
    try testing.expectEqual(RetrievalStrategy.keyword_only, result.recommended_strategy);
    try testing.expect(result.has_special_chars);
}

test "hybrid for long non-question" {
    const result = analyzeQuery("retrieval engine pipeline design patterns overview", enabled_config);
    try testing.expectEqual(RetrievalStrategy.hybrid, result.recommended_strategy);
    try testing.expectEqual(@as(u32, 6), result.token_count);
    try testing.expect(!result.is_question);
}

test "question detection is case-insensitive" {
    const result = analyzeQuery("How does the system handle large files efficiently", enabled_config);
    try testing.expectEqual(RetrievalStrategy.vector_only, result.recommended_strategy);
    try testing.expect(result.is_question);
}

test "special chars take priority over token count" {
    // 7 tokens but has underscores → keyword_only
    const result = analyzeQuery("my_key some_other thing here and more stuff", enabled_config);
    try testing.expectEqual(RetrievalStrategy.keyword_only, result.recommended_strategy);
    try testing.expect(result.has_special_chars);
}

test "avg_token_length computed correctly" {
    const result = analyzeQuery("ab cdef", enabled_config);
    // "ab" (2) + "cdef" (4) = 6 chars, 2 tokens → avg 3.0
    try testing.expectEqual(@as(f32, 3.0), result.avg_token_length);
}

test "multiple spaces between tokens handled" {
    const result = analyzeQuery("hello   world", enabled_config);
    try testing.expectEqual(@as(u32, 2), result.token_count);
    try testing.expectEqual(RetrievalStrategy.keyword_only, result.recommended_strategy);
}

test "custom config thresholds respected" {
    const config = AdaptiveConfig{
        .enabled = true,
        .keyword_max_tokens = 1,
        .vector_min_tokens = 3,
    };
    // 2 tokens: above keyword_max(1), below vector_min(3) → hybrid
    const result = analyzeQuery("Zig memory", config);
    try testing.expectEqual(RetrievalStrategy.hybrid, result.recommended_strategy);
}

test "whitespace-only query treated as empty" {
    const result = analyzeQuery("   ", enabled_config);
    try testing.expectEqual(RetrievalStrategy.keyword_only, result.recommended_strategy);
    try testing.expectEqual(@as(u32, 0), result.token_count);
}

test "hyphenated query detected as special chars" {
    const result = analyzeQuery("rate-limiter", enabled_config);
    try testing.expectEqual(RetrievalStrategy.keyword_only, result.recommended_strategy);
    try testing.expect(result.has_special_chars);
}
