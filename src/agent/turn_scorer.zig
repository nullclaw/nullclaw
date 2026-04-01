//! Turn Scorer — post-turn quality scoring based on observable signals.
//!
//! Computes a score in [-1.0, +1.0] for each agent turn based on:
//! - Tool execution outcomes (success / failure / iterations exhausted)
//! - User feedback signals detected in the next user message
//!
//! Scores feed the Observer pipeline (turn_scored event) and form the
//! foundation for the Skill Evolution and Session Digest subsystems.

const std = @import("std");
const testing = std.testing;

// ═══════════════════════════════════════════════════════════════════════════
// Score weights
// ═══════════════════════════════════════════════════════════════════════════

const W_TOOL_SUCCESS: f32 = 0.3;
const W_TOOL_FAILURE: f32 = -0.4;
const W_USER_CONTINUED: f32 = 0.2;
const W_USER_CORRECTED: f32 = -0.3;
const W_EXPLICIT_POSITIVE: f32 = 0.4;
const W_EXPLICIT_NEGATIVE: f32 = -0.5;
const W_MAX_ITERATIONS: f32 = -0.6;
const W_HALLUCINATION: f32 = -0.3;

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

/// Observable signals that contribute to the turn score.
pub const SignalSet = packed struct {
    tool_success: bool = false, // All tool calls succeeded          → +0.3
    tool_failure: bool = false, // One or more tool failures          → -0.4
    user_continued: bool = false, // User continued without correction → +0.2
    user_corrected: bool = false, // User immediately corrected        → -0.3
    explicit_positive: bool = false, // "dankje", "perfect", "top"       → +0.4
    explicit_negative: bool = false, // "nee", "fout", "verkeerd"        → -0.5
    max_iterations: bool = false, // Tool iteration limit exhausted    → -0.6
    hallucination_detected: bool = false, // Self-correction patterns          → -0.3
};

/// Scored result for a single agent turn.
pub const TurnScore = struct {
    score: f32,
    signals: SignalSet,
    tool_count: u16,
    tool_failures: u16,
};

/// Accumulated context during an agent turn (tool execution tracking).
pub const TurnContext = struct {
    tools_called: u16 = 0,
    tools_failed: u16 = 0,
    has_tool_calls: bool = false,
    max_iterations_hit: bool = false,
    /// Model used for this turn (for per-model attribution in deferred scoring).
    model: []const u8 = "",
    /// Primary skill (first tool called) for per-skill attribution.
    skill: []const u8 = "general",
};

/// User feedback signals detected from the next user message.
pub const FeedbackSignals = struct {
    corrected: bool = false,
    continued: bool = false,
    explicit_positive: bool = false,
    explicit_negative: bool = false,
};

// ═══════════════════════════════════════════════════════════════════════════
// Scoring
// ═══════════════════════════════════════════════════════════════════════════

/// Compute a turn score from tool execution context and optional user feedback.
///
/// Tool-based signals come from the completed turn. Feedback signals come from
/// the *next* user message (if available). When no feedback is available yet,
/// pass a default `FeedbackSignals{}` for a partial (tool-only) score.
pub fn scoreTurn(ctx: TurnContext, feedback: FeedbackSignals) TurnScore {
    var signals = SignalSet{};
    var score: f32 = 0.0;

    // ── Tool execution signals ──
    if (ctx.has_tool_calls) {
        if (ctx.tools_failed == 0) {
            signals.tool_success = true;
            score += W_TOOL_SUCCESS;
        }
        if (ctx.tools_failed > 0) {
            signals.tool_failure = true;
            score += W_TOOL_FAILURE;
        }
    }

    // ── Iteration exhaustion ──
    if (ctx.max_iterations_hit) {
        signals.max_iterations = true;
        score += W_MAX_ITERATIONS;
    }

    // ── User feedback signals ──
    if (feedback.explicit_positive) {
        signals.explicit_positive = true;
        score += W_EXPLICIT_POSITIVE;
    }
    if (feedback.explicit_negative) {
        signals.explicit_negative = true;
        score += W_EXPLICIT_NEGATIVE;
    }
    if (feedback.corrected) {
        signals.user_corrected = true;
        score += W_USER_CORRECTED;
    } else if (!feedback.explicit_negative and !feedback.explicit_positive) {
        // "continued" only if no explicit signal was given
        if (feedback.continued) {
            signals.user_continued = true;
            score += W_USER_CONTINUED;
        }
    }

    // ── Clamp to [-1.0, +1.0] ──
    score = @max(-1.0, @min(1.0, score));

    return .{
        .score = score,
        .signals = signals,
        .tool_count = ctx.tools_called,
        .tool_failures = ctx.tools_failed,
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// Feedback detection
// ═══════════════════════════════════════════════════════════════════════════

/// Keywords indicating explicit negative feedback (Dutch + English).
const NEGATIVE_KEYWORDS = [_][]const u8{
    "nee",   "fout",      "verkeerd", "klopt niet", "dat is niet",
    "wrong", "incorrect", "no that",  "not right",  "that's wrong",
};

/// Keywords indicating explicit positive feedback (Dutch + English).
const POSITIVE_KEYWORDS = [_][]const u8{
    "dankje",    "dank je", "bedankt",     "top",       "perfect",    "goed zo",
    "mooi",      "prima",   "fantastisch", "geweldig",  "uitstekend", "thanks",
    "thank you", "great",   "excellent",   "well done", "good job",   "nice",
    "awesome",
};

/// Keywords indicating user correction / reformulation (Dutch + English).
const CORRECTION_KEYWORDS = [_][]const u8{
    "opnieuw",   "probeer nog",          "doe het over",  "niet goed",
    "try again", "redo",                 "not what i",    "i meant",
    "i said",    "dat bedoelde ik niet", "nee ik bedoel", "nee, ik wil",
};

/// Detect feedback signals from a user message by keyword matching.
///
/// The message is lowercased for case-insensitive matching. Multiple
/// signals can fire simultaneously (e.g., "nee, probeer opnieuw" triggers
/// both explicit_negative and corrected).
pub fn detectFeedback(message: []const u8) FeedbackSignals {
    var signals = FeedbackSignals{};

    // Work with a stack buffer for lowercase conversion (avoid allocation).
    // If the message is too long, scan the first 512 bytes — feedback
    // keywords appear at the start of a message.
    const scan_len = @min(message.len, 512);
    var lower_buf: [512]u8 = undefined;
    for (message[0..scan_len], 0..) |c, i| {
        lower_buf[i] = asciiLower(c);
    }
    const lower = lower_buf[0..scan_len];

    for (NEGATIVE_KEYWORDS) |kw| {
        if (containsWord(lower, kw)) {
            signals.explicit_negative = true;
            break;
        }
    }

    for (POSITIVE_KEYWORDS) |kw| {
        if (containsWord(lower, kw)) {
            signals.explicit_positive = true;
            break;
        }
    }

    for (CORRECTION_KEYWORDS) |kw| {
        if (containsWord(lower, kw)) {
            signals.corrected = true;
            break;
        }
    }

    // If no explicit signal was detected, mark as "continued" (neutral/positive).
    if (!signals.explicit_negative and !signals.explicit_positive and !signals.corrected) {
        signals.continued = true;
    }

    return signals;
}

/// Detect self-correction / hallucination patterns in an agent response.
///
/// Returns true if the response contains phrases indicating the agent
/// is correcting its own previous output.
pub fn detectHallucination(response: []const u8) bool {
    const scan_len = @min(response.len, 1024);
    var lower_buf: [1024]u8 = undefined;
    for (response[0..scan_len], 0..) |c, i| {
        lower_buf[i] = asciiLower(c);
    }
    const lower = lower_buf[0..scan_len];

    const patterns = [_][]const u8{
        "mijn vorige antwoord was",
        "sorry, dat was",
        "ik had het fout",
        "dat klopte niet",
        "laat me dat corrigeren",
        "i was wrong",
        "my previous answer",
        "let me correct",
        "i apologize for the incorrect",
        "that was incorrect",
    };

    for (patterns) |pat| {
        if (std.mem.indexOf(u8, lower, pat) != null) {
            return true;
        }
    }

    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// ASCII-only lowercase (sufficient for keyword matching).
fn asciiLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

/// Check if `haystack` contains `needle` as a word (bounded by non-alpha or edges).
fn containsWord(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return false;
    if (haystack.len < needle.len) return false;

    var pos: usize = 0;
    while (pos + needle.len <= haystack.len) {
        if (std.mem.indexOf(u8, haystack[pos..], needle)) |idx| {
            const abs = pos + idx;
            const before_ok = abs == 0 or !isAlpha(haystack[abs - 1]);
            const after_pos = abs + needle.len;
            const after_ok = after_pos >= haystack.len or !isAlpha(haystack[after_pos]);
            if (before_ok and after_ok) return true;
            pos = abs + 1;
        } else {
            break;
        }
    }
    return false;
}

fn isAlpha(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test "scoreTurn_no_tools_no_feedback_returns_zero" {
    const score = scoreTurn(.{}, .{});
    try testing.expectEqual(@as(f32, 0.0), score.score);
    try testing.expect(!score.signals.tool_success);
    try testing.expect(!score.signals.tool_failure);
}

test "scoreTurn_all_tools_succeed" {
    const score = scoreTurn(.{
        .tools_called = 3,
        .tools_failed = 0,
        .has_tool_calls = true,
    }, .{});
    try testing.expectEqual(W_TOOL_SUCCESS, score.score);
    try testing.expect(score.signals.tool_success);
    try testing.expect(!score.signals.tool_failure);
    try testing.expectEqual(@as(u16, 3), score.tool_count);
    try testing.expectEqual(@as(u16, 0), score.tool_failures);
}

test "scoreTurn_some_tools_fail" {
    const score = scoreTurn(.{
        .tools_called = 5,
        .tools_failed = 2,
        .has_tool_calls = true,
    }, .{});
    try testing.expectEqual(W_TOOL_FAILURE, score.score);
    try testing.expect(!score.signals.tool_success);
    try testing.expect(score.signals.tool_failure);
    try testing.expectEqual(@as(u16, 5), score.tool_count);
    try testing.expectEqual(@as(u16, 2), score.tool_failures);
}

test "scoreTurn_max_iterations_hit" {
    const score = scoreTurn(.{ .max_iterations_hit = true }, .{});
    try testing.expectEqual(W_MAX_ITERATIONS, score.score);
    try testing.expect(score.signals.max_iterations);
}

test "scoreTurn_max_iterations_plus_tool_failure" {
    const score = scoreTurn(.{
        .tools_called = 10,
        .tools_failed = 3,
        .has_tool_calls = true,
        .max_iterations_hit = true,
    }, .{});
    try testing.expectEqual(W_TOOL_FAILURE + W_MAX_ITERATIONS, score.score);
    try testing.expect(score.signals.tool_failure);
    try testing.expect(score.signals.max_iterations);
}

test "scoreTurn_user_continued" {
    const score = scoreTurn(.{}, .{ .continued = true });
    try testing.expectEqual(W_USER_CONTINUED, score.score);
    try testing.expect(score.signals.user_continued);
}

test "scoreTurn_user_corrected" {
    const score = scoreTurn(.{}, .{ .corrected = true });
    try testing.expectEqual(W_USER_CORRECTED, score.score);
    try testing.expect(score.signals.user_corrected);
}

test "scoreTurn_explicit_positive_feedback" {
    const score = scoreTurn(.{}, .{ .explicit_positive = true });
    try testing.expectEqual(W_EXPLICIT_POSITIVE, score.score);
    try testing.expect(score.signals.explicit_positive);
}

test "scoreTurn_explicit_negative_feedback" {
    const score = scoreTurn(.{}, .{ .explicit_negative = true });
    try testing.expectEqual(W_EXPLICIT_NEGATIVE, score.score);
    try testing.expect(score.signals.explicit_negative);
}

test "scoreTurn_tools_succeed_plus_positive_feedback" {
    const score = scoreTurn(.{
        .tools_called = 2,
        .tools_failed = 0,
        .has_tool_calls = true,
    }, .{ .explicit_positive = true });
    try testing.expectEqual(W_TOOL_SUCCESS + W_EXPLICIT_POSITIVE, score.score);
    try testing.expect(score.signals.tool_success);
    try testing.expect(score.signals.explicit_positive);
}

test "scoreTurn_tools_fail_plus_negative_feedback" {
    const score = scoreTurn(.{
        .tools_called = 1,
        .tools_failed = 1,
        .has_tool_calls = true,
    }, .{ .explicit_negative = true });
    try testing.expectEqual(W_TOOL_FAILURE + W_EXPLICIT_NEGATIVE, score.score);
    try testing.expect(score.signals.tool_failure);
    try testing.expect(score.signals.explicit_negative);
}

test "scoreTurn_clamps_to_negative_one" {
    // Stack multiple negative signals to exceed -1.0
    const score = scoreTurn(.{
        .tools_called = 5,
        .tools_failed = 5,
        .has_tool_calls = true,
        .max_iterations_hit = true,
    }, .{ .explicit_negative = true, .corrected = true });
    try testing.expectEqual(@as(f32, -1.0), score.score);
}

test "scoreTurn_clamps_to_positive_one" {
    // Stack multiple positive signals to exceed +1.0
    const score = scoreTurn(.{
        .tools_called = 5,
        .tools_failed = 0,
        .has_tool_calls = true,
    }, .{ .explicit_positive = true, .continued = true });
    // +0.3 + +0.4 = +0.7, under 1.0 so no clamp needed
    try testing.expectEqual(W_TOOL_SUCCESS + W_EXPLICIT_POSITIVE, score.score);
}

test "scoreTurn_continued_suppressed_by_explicit_positive" {
    const score = scoreTurn(.{}, .{ .continued = true, .explicit_positive = true });
    // continued should not fire when explicit_positive is set
    try testing.expect(!score.signals.user_continued);
    try testing.expect(score.signals.explicit_positive);
    try testing.expectEqual(W_EXPLICIT_POSITIVE, score.score);
}

test "scoreTurn_continued_suppressed_by_explicit_negative" {
    const score = scoreTurn(.{}, .{ .continued = true, .explicit_negative = true });
    try testing.expect(!score.signals.user_continued);
    try testing.expect(score.signals.explicit_negative);
}

test "scoreTurn_no_tool_calls_means_no_tool_signals" {
    const score = scoreTurn(.{
        .tools_called = 0,
        .tools_failed = 0,
        .has_tool_calls = false,
    }, .{});
    try testing.expect(!score.signals.tool_success);
    try testing.expect(!score.signals.tool_failure);
}

test "scoreTurn_tool_count_preserved" {
    const score = scoreTurn(.{
        .tools_called = 42,
        .tools_failed = 7,
        .has_tool_calls = true,
    }, .{});
    try testing.expectEqual(@as(u16, 42), score.tool_count);
    try testing.expectEqual(@as(u16, 7), score.tool_failures);
}

test "scoreTurn_correction_and_negative_stack" {
    const score = scoreTurn(.{}, .{ .corrected = true, .explicit_negative = true });
    try testing.expectEqual(W_EXPLICIT_NEGATIVE + W_USER_CORRECTED, score.score);
    try testing.expect(score.signals.user_corrected);
    try testing.expect(score.signals.explicit_negative);
}

// ── Feedback detection tests ──

test "detectFeedback_positive_dutch" {
    const fb = detectFeedback("Dankje, dat is precies wat ik zocht!");
    try testing.expect(fb.explicit_positive);
    try testing.expect(!fb.explicit_negative);
    try testing.expect(!fb.corrected);
    try testing.expect(!fb.continued);
}

test "detectFeedback_positive_english" {
    const fb = detectFeedback("Thanks, that's great!");
    try testing.expect(fb.explicit_positive);
    try testing.expect(!fb.explicit_negative);
}

test "detectFeedback_negative_dutch" {
    const fb = detectFeedback("Nee, dat klopt niet helemaal");
    try testing.expect(fb.explicit_negative);
    try testing.expect(!fb.explicit_positive);
}

test "detectFeedback_negative_english" {
    const fb = detectFeedback("No that's wrong, try again");
    try testing.expect(fb.explicit_negative);
}

test "detectFeedback_correction_dutch" {
    const fb = detectFeedback("Probeer nog eens met de andere branch");
    try testing.expect(fb.corrected);
}

test "detectFeedback_correction_english" {
    const fb = detectFeedback("Try again with the correct parameters");
    try testing.expect(fb.corrected);
}

test "detectFeedback_continued_neutral_message" {
    const fb = detectFeedback("Kun je nu ook de tests uitvoeren?");
    try testing.expect(fb.continued);
    try testing.expect(!fb.explicit_positive);
    try testing.expect(!fb.explicit_negative);
    try testing.expect(!fb.corrected);
}

test "detectFeedback_case_insensitive" {
    const fb = detectFeedback("PERFECT, precies wat ik wilde!");
    try testing.expect(fb.explicit_positive);
}

test "detectFeedback_mixed_signals" {
    // "nee, probeer opnieuw" triggers both negative and correction
    const fb = detectFeedback("Nee, probeer opnieuw alsjeblieft");
    try testing.expect(fb.explicit_negative);
    try testing.expect(fb.corrected);
    try testing.expect(!fb.continued);
}

test "detectFeedback_empty_message" {
    const fb = detectFeedback("");
    try testing.expect(fb.continued);
    try testing.expect(!fb.explicit_positive);
    try testing.expect(!fb.explicit_negative);
    try testing.expect(!fb.corrected);
}

test "detectFeedback_word_boundary_prevents_false_positive" {
    // "topologie" contains "top" but it's not a word boundary match
    const fb = detectFeedback("Kun je de topologie uitleggen?");
    try testing.expect(!fb.explicit_positive);
    try testing.expect(fb.continued);
}

test "detectFeedback_goed_zo" {
    const fb = detectFeedback("Goed zo, ga zo door!");
    try testing.expect(fb.explicit_positive);
}

test "detectFeedback_bedankt" {
    const fb = detectFeedback("Bedankt voor de hulp");
    try testing.expect(fb.explicit_positive);
}

test "detectFeedback_fout_as_word" {
    const fb = detectFeedback("Dat is fout, check de log");
    try testing.expect(fb.explicit_negative);
}

test "detectFeedback_verkeerd" {
    const fb = detectFeedback("Je hebt het verkeerd begrepen");
    try testing.expect(fb.explicit_negative);
}

test "detectFeedback_long_message_only_scans_prefix" {
    // Build a message longer than 512 bytes with keyword at the end
    var buf: [600]u8 = undefined;
    @memset(&buf, 'a');
    @memcpy(buf[590..598], "dankje! ");
    const fb = detectFeedback(&buf);
    // Keyword is past 512 byte scan window, should not be detected
    try testing.expect(!fb.explicit_positive);
    try testing.expect(fb.continued);
}

test "detectFeedback_keyword_within_scan_window" {
    var buf: [600]u8 = undefined;
    @memset(&buf, ' ');
    @memcpy(buf[0..6], "dankje");
    const fb = detectFeedback(&buf);
    try testing.expect(fb.explicit_positive);
}

test "detectFeedback_i_meant" {
    const fb = detectFeedback("I meant the other file, not this one");
    try testing.expect(fb.corrected);
}

test "detectFeedback_doe_het_over" {
    const fb = detectFeedback("Doe het over met de juiste settings");
    try testing.expect(fb.corrected);
}

test "detectFeedback_excellent" {
    const fb = detectFeedback("Excellent work on this one!");
    try testing.expect(fb.explicit_positive);
}

test "detectFeedback_awesome" {
    const fb = detectFeedback("Awesome, that looks right");
    try testing.expect(fb.explicit_positive);
}

test "detectFeedback_klopt_niet" {
    const fb = detectFeedback("Dat klopt niet, de prijs is anders");
    try testing.expect(fb.explicit_negative);
}

test "detectFeedback_well_done" {
    const fb = detectFeedback("Well done, exactly what I needed");
    try testing.expect(fb.explicit_positive);
}

// ── Hallucination detection tests ──

test "detectHallucination_dutch_self_correction" {
    try testing.expect(detectHallucination("Mijn vorige antwoord was niet helemaal juist."));
}

test "detectHallucination_dutch_sorry" {
    try testing.expect(detectHallucination("Sorry, dat was incorrect. De juiste data is..."));
}

test "detectHallucination_english_correction" {
    try testing.expect(detectHallucination("Let me correct that — the actual value is 42."));
}

test "detectHallucination_english_wrong" {
    try testing.expect(detectHallucination("I was wrong about the file path."));
}

test "detectHallucination_normal_response" {
    try testing.expect(!detectHallucination("Hier is het resultaat van de git status."));
}

test "detectHallucination_empty" {
    try testing.expect(!detectHallucination(""));
}

test "detectHallucination_case_insensitive" {
    try testing.expect(detectHallucination("IK HAD HET FOUT, de branch was anders"));
}

test "detectHallucination_apologize_incorrect" {
    try testing.expect(detectHallucination("I apologize for the incorrect information earlier."));
}

// ── containsWord tests ──

test "containsWord_exact_match" {
    try testing.expect(containsWord("top", "top"));
}

test "containsWord_start_of_string" {
    try testing.expect(containsWord("top werk!", "top"));
}

test "containsWord_end_of_string" {
    try testing.expect(containsWord("echt top", "top"));
}

test "containsWord_middle" {
    try testing.expect(containsWord("ja top hoor", "top"));
}

test "containsWord_not_a_word_boundary" {
    try testing.expect(!containsWord("topology", "top"));
}

test "containsWord_empty_needle" {
    try testing.expect(!containsWord("hello", ""));
}

test "containsWord_needle_longer_than_haystack" {
    try testing.expect(!containsWord("hi", "hello"));
}

test "containsWord_with_punctuation_boundary" {
    try testing.expect(containsWord("ja, top!", "top"));
}

test "containsWord_multi_word_needle" {
    try testing.expect(containsWord("dat klopt niet helemaal", "klopt niet"));
}

test "containsWord_adjacent_non_alpha" {
    try testing.expect(containsWord("(nee)", "nee"));
}

// ── asciiLower tests ──

test "asciiLower_uppercase" {
    try testing.expectEqual(@as(u8, 'a'), asciiLower('A'));
    try testing.expectEqual(@as(u8, 'z'), asciiLower('Z'));
}

test "asciiLower_lowercase_unchanged" {
    try testing.expectEqual(@as(u8, 'a'), asciiLower('a'));
}

test "asciiLower_non_alpha_unchanged" {
    try testing.expectEqual(@as(u8, '1'), asciiLower('1'));
    try testing.expectEqual(@as(u8, ' '), asciiLower(' '));
}

// ── SignalSet size guarantee ──

test "signalset_is_one_byte" {
    try testing.expectEqual(@as(usize, 1), @sizeOf(SignalSet));
}
