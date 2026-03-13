//! Skill Router — keyword-based skill selection per turn.
//!
//! Scores skills against the current user message using keyword overlap
//! between the message and skill name + description. Returns the top-N
//! most relevant skills to load as Active Skills in the system prompt.
//!
//! Design: zero API calls, deterministic, instant. Vector-based boost
//! can be added later as an enhancement.

const std = @import("std");
const testing = std.testing;

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

/// Weight multiplier for matches against the skill name (vs description).
const NAME_WEIGHT: f32 = 3.0;

/// Minimum score to be considered a match (prevents noise from single stop-word overlaps).
const MIN_SCORE_THRESHOLD: f32 = 0.01;

/// Maximum number of tokens extracted from a single skill (name + description).
const MAX_SKILL_TOKENS: usize = 64;

/// Maximum number of tokens extracted from the user message.
const MAX_MESSAGE_TOKENS: usize = 128;

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

/// A skill score from the router.
pub const ScoredSkill = struct {
    index: usize,
    score: f32,
};

/// Pre-computed keyword index for a single skill.
const SkillKeywordEntry = struct {
    skill_index: usize,
    name_tokens: [][]const u8,
    desc_tokens: [][]const u8,
};

/// Skill router with pre-computed keyword indices.
pub const SkillRouter = struct {
    entries: []SkillKeywordEntry,
    allocator: std.mem.Allocator,

    /// Initialize the router by extracting keywords from all skills.
    /// Caller must call `deinit()` to free.
    pub fn init(
        allocator: std.mem.Allocator,
        skill_names: []const []const u8,
        skill_descriptions: []const []const u8,
    ) SkillRouter {
        std.debug.assert(skill_names.len == skill_descriptions.len);

        const entries = allocator.alloc(SkillKeywordEntry, skill_names.len) catch
            return .{ .entries = &.{}, .allocator = allocator };

        for (skill_names, skill_descriptions, 0..) |name, desc, i| {
            entries[i] = .{
                .skill_index = i,
                .name_tokens = tokenizeAndFilter(allocator, name),
                .desc_tokens = tokenizeAndFilter(allocator, desc),
            };
        }

        return .{ .entries = entries, .allocator = allocator };
    }

    pub fn deinit(self: *SkillRouter) void {
        for (self.entries) |entry| {
            freeTokens(self.allocator, entry.name_tokens);
            freeTokens(self.allocator, entry.desc_tokens);
        }
        self.allocator.free(self.entries);
        self.entries = &.{};
    }

    /// Score all skills against a user message and return the top-N indices.
    ///
    /// Returns a caller-owned slice of `ScoredSkill` sorted by descending score.
    /// Only skills above `MIN_SCORE_THRESHOLD` are included, capped at `limit`.
    pub fn route(
        self: *const SkillRouter,
        allocator: std.mem.Allocator,
        user_message: []const u8,
        limit: u32,
    ) []ScoredSkill {
        if (self.entries.len == 0 or limit == 0) return &.{};

        const msg_tokens = tokenizeAndFilter(allocator, user_message);
        defer freeTokens(allocator, msg_tokens);

        if (msg_tokens.len == 0) return &.{};

        // Score each skill
        var scores = allocator.alloc(ScoredSkill, self.entries.len) catch return &.{};
        defer allocator.free(scores);

        var count: usize = 0;
        for (self.entries) |entry| {
            const name_hits = countOverlap(msg_tokens, entry.name_tokens);
            const desc_hits = countOverlap(msg_tokens, entry.desc_tokens);

            const total_entry_tokens = entry.name_tokens.len + entry.desc_tokens.len;
            if (total_entry_tokens == 0) continue;

            // Weighted score normalized by total tokens
            const raw = (@as(f32, @floatFromInt(name_hits)) * NAME_WEIGHT +
                @as(f32, @floatFromInt(desc_hits))) /
                @as(f32, @floatFromInt(total_entry_tokens));

            if (raw >= MIN_SCORE_THRESHOLD) {
                scores[count] = .{ .index = entry.skill_index, .score = raw };
                count += 1;
            }
        }

        if (count == 0) return &.{};

        // Sort descending by score
        std.mem.sortUnstable(ScoredSkill, scores[0..count], {}, scoreCmp);

        // Return top-N (owned copy)
        const result_len = @min(count, limit);
        const result = allocator.alloc(ScoredSkill, result_len) catch return &.{};
        @memcpy(result, scores[0..result_len]);
        return result;
    }
};

fn scoreCmp(_: void, a: ScoredSkill, b: ScoredSkill) bool {
    return a.score > b.score;
}

// ═══════════════════════════════════════════════════════════════════════════
// Tokenization & matching
// ═══════════════════════════════════════════════════════════════════════════

/// Tokenize text into lowercase words, filtering stop words.
/// Returns a caller-owned slice of slices (pointing into a single backing buffer).
fn tokenizeAndFilter(allocator: std.mem.Allocator, text: []const u8) [][]const u8 {
    if (text.len == 0) return &.{};

    // Lowercase the text into a backing buffer
    const lower = allocator.alloc(u8, text.len) catch return &.{};
    for (text, 0..) |c, i| {
        lower[i] = asciiLower(c);
    }

    // Split into words and filter
    var tokens: std.ArrayListUnmanaged([]const u8) = .empty;

    var start: usize = 0;
    var in_word = false;
    for (lower, 0..) |c, i| {
        const is_word_char = isWordChar(c);
        if (is_word_char and !in_word) {
            start = i;
            in_word = true;
        } else if (!is_word_char and in_word) {
            const word = lower[start..i];
            if (word.len >= 2 and !isStopWord(word)) {
                tokens.append(allocator, word) catch break;
                if (tokens.items.len >= MAX_MESSAGE_TOKENS) break;
            }
            in_word = false;
        }
    }
    // Handle last word
    if (in_word) {
        const word = lower[start..];
        if (word.len >= 2 and !isStopWord(word)) {
            tokens.append(allocator, word) catch {};
        }
    }

    // Transfer ownership: we keep the lower buffer alive by NOT freeing it.
    // The caller frees the token slice; the backing buffer leaks intentionally
    // since tokens point into it. For the short-lived per-turn allocation this
    // is acceptable (freed by arena or turn scope).
    //
    // Actually, to avoid leaks in the test allocator, we need to be more careful.
    // Let's dupe each token and free the lower buffer.
    const result = allocator.alloc([]const u8, tokens.items.len) catch {
        tokens.deinit(allocator);
        allocator.free(lower);
        return &.{};
    };

    for (tokens.items, 0..) |tok, i| {
        result[i] = allocator.dupe(u8, tok) catch {
            // Clean up already duped tokens
            for (result[0..i]) |prev| allocator.free(prev);
            allocator.free(result);
            tokens.deinit(allocator);
            allocator.free(lower);
            return &.{};
        };
    }

    tokens.deinit(allocator);
    allocator.free(lower);
    return result;
}

/// Count how many tokens from `a` appear in `b`.
fn countOverlap(a: []const []const u8, b: []const []const u8) usize {
    var hits: usize = 0;
    for (a) |tok_a| {
        for (b) |tok_b| {
            if (std.mem.eql(u8, tok_a, tok_b)) {
                hits += 1;
                break;
            }
        }
    }
    return hits;
}

// ═══════════════════════════════════════════════════════════════════════════
// Stop words (Dutch + English, common in skill descriptions)
// ═══════════════════════════════════════════════════════════════════════════

fn isStopWord(word: []const u8) bool {
    const stops = [_][]const u8{
        // Dutch
        "de",  "het",  "een",  "en",   "van",  "in",  "is",   "op",
        "te",  "dat",  "die",  "voor", "met",  "zijn", "aan", "er",
        "als", "kan",  "naar", "om",   "dan",  "ook", "bij",  "nog",
        "uit", "maar", "niet", "wel",  "wat",  "dit", "door", "over",
        "je",  "ze",   "we",   "hij",  "hun",
        // English
        "the", "and",  "for",  "with", "from", "that", "this", "are",
        "was", "has",  "have", "will", "can",  "all",  "its",  "use",
        "via", "when", "how",  "you",  "your", "into", "such", "each",
        "been","any",  "may",  "than",
    };
    for (stops) |s| {
        if (std.mem.eql(u8, word, s)) return true;
    }
    return false;
}

fn isWordChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '_';
}

fn asciiLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

/// Free a token slice returned by tokenizeAndFilter.
pub fn freeTokens(allocator: std.mem.Allocator, tokens: [][]const u8) void {
    for (tokens) |tok| allocator.free(tok);
    allocator.free(tokens);
}

/// Free a ScoredSkill slice returned by SkillRouter.route.
pub fn freeScored(allocator: std.mem.Allocator, scored: []ScoredSkill) void {
    allocator.free(scored);
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test "tokenizeAndFilter_basic" {
    const alloc = testing.allocator;
    const tokens = tokenizeAndFilter(alloc, "Plan een afspraak in");
    defer freeTokens(alloc, tokens);
    // "een" and "in" are stop words → filtered out
    // "plan" and "afspraak" remain
    try testing.expectEqual(@as(usize, 2), tokens.len);
    try testing.expectEqualStrings("plan", tokens[0]);
    try testing.expectEqualStrings("afspraak", tokens[1]);
}

test "tokenizeAndFilter_empty" {
    const alloc = testing.allocator;
    const tokens = tokenizeAndFilter(alloc, "");
    defer freeTokens(alloc, tokens);
    try testing.expectEqual(@as(usize, 0), tokens.len);
}

test "tokenizeAndFilter_all_stop_words" {
    const alloc = testing.allocator;
    const tokens = tokenizeAndFilter(alloc, "de het een en van");
    defer freeTokens(alloc, tokens);
    try testing.expectEqual(@as(usize, 0), tokens.len);
}

test "tokenizeAndFilter_case_insensitive" {
    const alloc = testing.allocator;
    const tokens = tokenizeAndFilter(alloc, "MEETING Planner");
    defer freeTokens(alloc, tokens);
    try testing.expectEqual(@as(usize, 2), tokens.len);
    try testing.expectEqualStrings("meeting", tokens[0]);
    try testing.expectEqualStrings("planner", tokens[1]);
}

test "tokenizeAndFilter_splits_on_hyphens" {
    const alloc = testing.allocator;
    const tokens = tokenizeAndFilter(alloc, "rag-knowledge base");
    defer freeTokens(alloc, tokens);
    try testing.expectEqual(@as(usize, 3), tokens.len);
    try testing.expectEqualStrings("rag", tokens[0]);
    try testing.expectEqualStrings("knowledge", tokens[1]);
    try testing.expectEqualStrings("base", tokens[2]);
}

test "tokenizeAndFilter_single_char_filtered" {
    const alloc = testing.allocator;
    const tokens = tokenizeAndFilter(alloc, "a b cd ef");
    defer freeTokens(alloc, tokens);
    // "a" and "b" are <2 chars → filtered
    try testing.expectEqual(@as(usize, 2), tokens.len);
}

test "countOverlap_basic" {
    const a = &[_][]const u8{ "meeting", "planner", "afspraak" };
    const b = &[_][]const u8{ "meeting", "consultation", "appointments" };
    try testing.expectEqual(@as(usize, 1), countOverlap(a, b));
}

test "countOverlap_no_match" {
    const a = &[_][]const u8{ "email", "zoeken" };
    const b = &[_][]const u8{ "coding", "git", "project" };
    try testing.expectEqual(@as(usize, 0), countOverlap(a, b));
}

test "countOverlap_full_match" {
    const a = &[_][]const u8{ "coding", "git" };
    const b = &[_][]const u8{ "coding", "git", "project" };
    try testing.expectEqual(@as(usize, 2), countOverlap(a, b));
}

test "countOverlap_empty" {
    const a = &[_][]const u8{};
    const b = &[_][]const u8{ "coding" };
    try testing.expectEqual(@as(usize, 0), countOverlap(a, b));
}

test "isStopWord_dutch" {
    try testing.expect(isStopWord("de"));
    try testing.expect(isStopWord("het"));
    try testing.expect(isStopWord("een"));
}

test "isStopWord_english" {
    try testing.expect(isStopWord("the"));
    try testing.expect(isStopWord("and"));
    try testing.expect(isStopWord("for"));
}

test "isStopWord_non_stop" {
    try testing.expect(!isStopWord("meeting"));
    try testing.expect(!isStopWord("email"));
    try testing.expect(!isStopWord("deploy"));
}

test "SkillRouter_init_deinit" {
    const alloc = testing.allocator;
    const names = &[_][]const u8{ "meeting-planner", "coding-agent" };
    const descs = &[_][]const u8{
        "Manage consultation appointments via the OpenClaw API",
        "Run coding tasks via Claude Code in isolated directories",
    };
    var router = SkillRouter.init(alloc, names, descs);
    defer router.deinit();

    try testing.expectEqual(@as(usize, 2), router.entries.len);
}

test "SkillRouter_route_meeting_query" {
    const alloc = testing.allocator;
    const names = &[_][]const u8{ "meeting-planner", "coding-agent", "imap-email" };
    const descs = &[_][]const u8{
        "Manage consultation appointments via the OpenClaw API",
        "Run coding tasks via Claude Code in isolated directories",
        "Advanced email operations via the Python IMAP SMTP plugin",
    };
    var router = SkillRouter.init(alloc, names, descs);
    defer router.deinit();

    // "meeting" matches skill name "meeting-planner" (name weight 3x)
    const results = router.route(alloc, "Schedule a meeting with the client", 3);
    defer freeScored(alloc, results);

    try testing.expect(results.len >= 1);
    try testing.expectEqual(@as(usize, 0), results[0].index);
}

test "SkillRouter_route_coding_query" {
    const alloc = testing.allocator;
    const names = &[_][]const u8{ "meeting-planner", "coding-agent", "imap-email" };
    const descs = &[_][]const u8{
        "Manage consultation appointments via the OpenClaw API",
        "Run coding tasks via Claude Code in isolated directories",
        "Advanced email operations via the Python IMAP SMTP plugin",
    };
    var router = SkillRouter.init(alloc, names, descs);
    defer router.deinit();

    const results = router.route(alloc, "Deploy the coding project to production", 3);
    defer freeScored(alloc, results);

    try testing.expect(results.len >= 1);
    try testing.expectEqual(@as(usize, 1), results[0].index);
}

test "SkillRouter_route_email_query" {
    const alloc = testing.allocator;
    const names = &[_][]const u8{ "meeting-planner", "coding-agent", "imap-email" };
    const descs = &[_][]const u8{
        "Manage consultation appointments via the OpenClaw API",
        "Run coding tasks via Claude Code in isolated directories",
        "Advanced email operations via the Python IMAP SMTP plugin",
    };
    var router = SkillRouter.init(alloc, names, descs);
    defer router.deinit();

    const results = router.route(alloc, "Search through my email inbox", 3);
    defer freeScored(alloc, results);

    try testing.expect(results.len >= 1);
    try testing.expectEqual(@as(usize, 2), results[0].index);
}

test "SkillRouter_route_respects_limit" {
    const alloc = testing.allocator;
    const names = &[_][]const u8{ "skill-a", "skill-b", "skill-c", "skill-d" };
    const descs = &[_][]const u8{
        "tasks operations management",
        "tasks operations scheduling",
        "tasks operations reporting",
        "tasks operations monitoring",
    };
    var router = SkillRouter.init(alloc, names, descs);
    defer router.deinit();

    const results = router.route(alloc, "Show me the tasks operations status", 2);
    defer freeScored(alloc, results);

    try testing.expect(results.len <= 2);
}

test "SkillRouter_route_no_match_returns_empty" {
    const alloc = testing.allocator;
    const names = &[_][]const u8{ "meeting-planner" };
    const descs = &[_][]const u8{"Manage consultation appointments"};
    var router = SkillRouter.init(alloc, names, descs);
    defer router.deinit();

    const results = router.route(alloc, "Vertel me een grap", 3);
    defer freeScored(alloc, results);

    try testing.expectEqual(@as(usize, 0), results.len);
}

test "SkillRouter_route_empty_message" {
    const alloc = testing.allocator;
    const names = &[_][]const u8{"skill-a"};
    const descs = &[_][]const u8{"some description"};
    var router = SkillRouter.init(alloc, names, descs);
    defer router.deinit();

    const results = router.route(alloc, "", 3);
    defer freeScored(alloc, results);

    try testing.expectEqual(@as(usize, 0), results.len);
}

test "SkillRouter_route_name_match_weighs_more" {
    const alloc = testing.allocator;
    // skill-a has "email" in name, skill-b has "email" only in description
    const names = &[_][]const u8{ "imap-email", "other-tool" };
    const descs = &[_][]const u8{
        "Advanced operations via IMAP",
        "A tool that handles email forwarding",
    };
    var router = SkillRouter.init(alloc, names, descs);
    defer router.deinit();

    const results = router.route(alloc, "Check my email", 2);
    defer freeScored(alloc, results);

    try testing.expect(results.len >= 1);
    // imap-email should rank higher due to name match (3x weight)
    try testing.expectEqual(@as(usize, 0), results[0].index);
    if (results.len >= 2) {
        try testing.expect(results[0].score > results[1].score);
    }
}

test "SkillRouter_route_dutch_query" {
    const alloc = testing.allocator;
    const names = &[_][]const u8{ "rag-knowledge", "meeting-planner" };
    const descs = &[_][]const u8{
        "Search the Wellenberg knowledge base for cursussen workshops and practical info",
        "Manage consultation appointments via the OpenClaw API",
    };
    var router = SkillRouter.init(alloc, names, descs);
    defer router.deinit();

    const results = router.route(alloc, "Wat zijn de cursussen bij Wellenberg?", 2);
    defer freeScored(alloc, results);

    try testing.expect(results.len >= 1);
    try testing.expectEqual(@as(usize, 0), results[0].index);
}

test "SkillRouter_route_sorted_descending" {
    const alloc = testing.allocator;
    const names = &[_][]const u8{ "skill-a", "skill-b", "skill-c" };
    const descs = &[_][]const u8{
        "remote operations",
        "tasks operations management scheduling",
        "single task",
    };
    var router = SkillRouter.init(alloc, names, descs);
    defer router.deinit();

    const results = router.route(alloc, "Run the tasks operations management", 3);
    defer freeScored(alloc, results);

    // Verify sorted descending
    for (1..results.len) |i| {
        try testing.expect(results[i - 1].score >= results[i].score);
    }
}

test "SkillRouter_empty_skills" {
    const alloc = testing.allocator;
    var router = SkillRouter.init(alloc, &.{}, &.{});
    defer router.deinit();

    const results = router.route(alloc, "hello", 3);
    defer freeScored(alloc, results);
    try testing.expectEqual(@as(usize, 0), results.len);
}

test "SkillRouter_donna_full_skill_set" {
    const alloc = testing.allocator;
    // Simulate Donna's actual skill set
    const names = &[_][]const u8{
        "meeting-planner",
        "imap-email",
        "rag-knowledge",
        "coding-agent",
        "github-projects",
        "nas-documents",
        "docx-tool",
        "toggl-invoice",
        "agent-browser",
        "gh",
    };
    const descs = &[_][]const u8{
        "Manage Daisha's consultation appointments via the OpenClaw API",
        "Advanced email operations via the Python IMAP SMTP plugin",
        "Search the Wellenberg knowledge base for cursussen workshops and practical info",
        "Run coding tasks via Claude Code or Codex in isolated project directories",
        "Manage GitHub repositories issues and pull requests via the gh CLI",
        "Read write and organize documents on the Synology NAS",
        "Create and edit Word docx documents via a Python wrapper",
        "Fetch monthly time reports from Toggl Track and generate PDF invoice",
        "Browse websites and extract content using a headless browser",
        "GitHub CLI wrapper for repository operations",
    };
    var router = SkillRouter.init(alloc, names, descs);
    defer router.deinit();

    // Test 1: Appointment query → meeting-planner
    {
        const r = router.route(alloc, "Plan een afspraak bij Daisha", 3);
        defer freeScored(alloc, r);
        try testing.expect(r.len >= 1);
        try testing.expectEqual(@as(usize, 0), r[0].index); // meeting-planner
    }

    // Test 2: Email query → imap-email
    {
        const r = router.route(alloc, "Zoek in mijn email naar de factuur", 3);
        defer freeScored(alloc, r);
        try testing.expect(r.len >= 1);
        try testing.expectEqual(@as(usize, 1), r[0].index); // imap-email
    }

    // Test 3: Knowledge query → rag-knowledge
    {
        const r = router.route(alloc, "Welke cursussen biedt Wellenberg aan?", 3);
        defer freeScored(alloc, r);
        try testing.expect(r.len >= 1);
        try testing.expectEqual(@as(usize, 2), r[0].index); // rag-knowledge
    }

    // Test 4: Coding query → coding-agent
    {
        const r = router.route(alloc, "Fix the bug in the coding project", 3);
        defer freeScored(alloc, r);
        try testing.expect(r.len >= 1);
        try testing.expectEqual(@as(usize, 3), r[0].index); // coding-agent
    }

    // Test 5: NAS query → nas-documents
    {
        const r = router.route(alloc, "Sla dit document op de NAS", 3);
        defer freeScored(alloc, r);
        try testing.expect(r.len >= 1);
        try testing.expectEqual(@as(usize, 5), r[0].index); // nas-documents
    }

    // Test 6: Invoice query → toggl-invoice
    {
        const r = router.route(alloc, "Maak de maandelijkse Toggl invoice", 3);
        defer freeScored(alloc, r);
        try testing.expect(r.len >= 1);
        try testing.expectEqual(@as(usize, 7), r[0].index); // toggl-invoice
    }
}
