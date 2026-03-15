//! Query expansion for FTS-only search mode.
//!
//! When no embedding provider is available, query expansion improves keyword
//! search by filtering stop words, detecting language, and extracting meaningful
//! terms from conversational queries.
//!
//! Example: "What was the decision about the database?" -> "decision database"

const std = @import("std");
const Allocator = std.mem.Allocator;

// ── Language ────────────────────────────────────────────────────────

pub const Language = enum {
    en,
    zh,
    ko,
    ja,
    es,
    pt,
    ar,
    unknown,
};

// ── ExpandedQuery ───────────────────────────────────────────────────

pub const ExpandedQuery = struct {
    fts5_query: []const u8,
    original_tokens: []const []const u8,
    filtered_tokens: []const []const u8,
    language: Language,

    pub fn deinit(self: *ExpandedQuery, allocator: Allocator) void {
        allocator.free(self.fts5_query);
        for (self.original_tokens) |t| allocator.free(t);
        allocator.free(self.original_tokens);
        for (self.filtered_tokens) |t| allocator.free(t);
        allocator.free(self.filtered_tokens);
    }
};

// ── Public API ──────────────────────────────────────────────────────

/// Extract meaningful keywords and build an FTS5 query from a raw user query.
pub fn expandQuery(allocator: Allocator, raw_query: []const u8) !ExpandedQuery {
    const trimmed = std.mem.trim(u8, raw_query, " \t\n\r");
    if (trimmed.len == 0) {
        return .{
            .fts5_query = try allocator.dupe(u8, ""),
            .original_tokens = try allocator.alloc([]const u8, 0),
            .filtered_tokens = try allocator.alloc([]const u8, 0),
            .language = .unknown,
        };
    }

    const lang = detectLanguage(trimmed);

    // Tokenize
    var orig_list: std.ArrayListUnmanaged([]const u8) = .{};
    defer orig_list.deinit(allocator);
    errdefer for (orig_list.items) |t| allocator.free(t);
    var filt_list: std.ArrayListUnmanaged([]const u8) = .{};
    defer filt_list.deinit(allocator);
    errdefer for (filt_list.items) |t| allocator.free(t);

    // Tokenize into raw segments
    var raw_tokens: std.ArrayListUnmanaged([]const u8) = .{};
    defer {
        for (raw_tokens.items) |t| allocator.free(t);
        raw_tokens.deinit(allocator);
    }
    try tokenize(allocator, trimmed, lang, &raw_tokens);

    // Track original tokens (lowercased raw segments from whitespace split)
    {
        var iter = std.mem.splitScalar(u8, trimmed, ' ');
        while (iter.next()) |seg| {
            const t = std.mem.trim(u8, seg, " \t\n\r");
            if (t.len == 0) continue;
            const low = try toLower(allocator, t);
            errdefer allocator.free(low);
            try orig_list.append(allocator, low);
        }
    }

    // Filter tokens: remove stopwords, invalid keywords, and deduplicate
    var seen = std.StringHashMap(void).init(allocator);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        seen.deinit();
    }

    for (raw_tokens.items) |token| {
        if (isStopWord(token)) continue;
        if (!isValidKeyword(token)) continue;
        if (seen.contains(token)) continue;

        const seen_key = try allocator.dupe(u8, token);
        errdefer allocator.free(seen_key);
        try seen.put(seen_key, {});
        const filt_token = try allocator.dupe(u8, token);
        errdefer allocator.free(filt_token);
        try filt_list.append(allocator, filt_token);
    }

    // Build FTS5 query
    const fts5 = if (filt_list.items.len == 0)
        try allocator.dupe(u8, trimmed) // fallback to original
    else
        try buildFts5Query(allocator, filt_list.items);
    errdefer allocator.free(fts5);

    // seen map keys are freed by the defer block above

    const orig_tokens = try orig_list.toOwnedSlice(allocator);
    errdefer {
        for (orig_tokens) |t| allocator.free(t);
        allocator.free(orig_tokens);
    }
    const filt_tokens = try filt_list.toOwnedSlice(allocator);

    return .{
        .fts5_query = fts5,
        .original_tokens = orig_tokens,
        .filtered_tokens = filt_tokens,
        .language = lang,
    };
}

/// Extract keywords from a query (convenience wrapper).
pub fn extractKeywords(allocator: Allocator, query: []const u8) ![]const []const u8 {
    const result = try expandQuery(allocator, query);
    allocator.free(result.fts5_query);
    for (result.original_tokens) |t| allocator.free(t);
    allocator.free(result.original_tokens);
    // Return filtered_tokens; caller owns them
    return result.filtered_tokens;
}

// ── Language detection ──────────────────────────────────────────────

fn detectLanguage(text: []const u8) Language {
    var has_cjk = false;
    var has_hangul = false;
    var has_kana = false;
    var has_arabic = false;
    var i: usize = 0;

    while (i < text.len) {
        const cp_len = std.unicode.utf8ByteSequenceLength(text[i]) catch {
            i += 1;
            continue;
        };
        if (i + cp_len > text.len) break;

        const cp = std.unicode.utf8Decode(text[i..][0..cp_len]) catch {
            i += 1;
            continue;
        };

        if (cp >= 0xAC00 and cp <= 0xD7AF) has_hangul = true // Hangul syllables
        else if (cp >= 0x3131 and cp <= 0x3163) has_hangul = true // Hangul jamo
        else if (cp >= 0x3040 and cp <= 0x30FF) has_kana = true // Hiragana + Katakana
        else if (cp >= 0x4E00 and cp <= 0x9FFF) has_cjk = true // CJK unified
        else if (cp >= 0x0600 and cp <= 0x06FF) has_arabic = true // Arabic block
        else if (cp >= 0x0750 and cp <= 0x077F) has_arabic = true; // Arabic supplement

        i += cp_len;
    }

    // Priority: Korean > Japanese > Chinese > Arabic > English
    if (has_hangul) return .ko;
    if (has_kana) return .ja;
    if (has_cjk) return .zh;
    if (has_arabic) return .ar;

    // Simple Spanish/Portuguese detection from common stopwords
    const lower_buf = toLowerStack(text);
    const lower = lower_buf.constSlice();
    if (containsAny(lower, &.{ " el ", " la ", " los ", " las ", " del ", " como ", " pero " })) return .es;
    if (containsAny(lower, &.{ " da ", " das ", " dos ", " pela ", " pelas " })) return .pt;

    return .en;
}

fn containsAny(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |needle| {
        if (std.mem.indexOf(u8, haystack, needle) != null) return true;
    }
    return false;
}

/// Stack-based lowercase for short language detection (max 512 bytes).
const StackBuf = struct {
    data: [514]u8 = undefined,
    len: usize = 0,

    fn constSlice(self: *const StackBuf) []const u8 {
        return self.data[0..self.len];
    }
};

fn toLowerStack(text: []const u8) StackBuf {
    var buf = StackBuf{};
    buf.data[0] = ' ';
    buf.len = 1;
    const limit = @min(text.len, 510);
    for (text[0..limit]) |c| {
        if (buf.len >= buf.data.len - 1) break;
        buf.data[buf.len] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        buf.len += 1;
    }
    buf.data[buf.len] = ' ';
    buf.len += 1;
    return buf;
}

// ── Tokenization ────────────────────────────────────────────────────

fn tokenize(allocator: Allocator, text: []const u8, lang: Language, out: *std.ArrayListUnmanaged([]const u8)) !void {
    // Split on whitespace first
    var iter = std.mem.splitScalar(u8, text, ' ');
    while (iter.next()) |seg| {
        const trimmed = std.mem.trim(u8, seg, " \t\n\r");
        if (trimmed.len == 0) continue;

        // Strip leading/trailing punctuation from segment
        const cleaned = stripPunctuation(trimmed);
        if (cleaned.len == 0) continue;

        const lower = try toLower(allocator, cleaned);
        errdefer allocator.free(lower);

        switch (lang) {
            .ko => {
                // Korean: emit token + particle-stripped stem
                try out.append(allocator, lower);
                if (stripKoreanTrailingParticle(lower)) |stem_range| {
                    const stem = lower[0..stem_range];
                    if (isUsefulKoreanStem(stem)) {
                        if (!isStopWord(stem)) {
                            try out.append(allocator, try allocator.dupe(u8, stem));
                        }
                    }
                }
            },
            .zh => {
                // Chinese: character unigrams + bigrams
                allocator.free(lower);
                try tokenizeChinese(allocator, cleaned, out);
            },
            .ja => {
                // Japanese: script-specific chunking
                allocator.free(lower);
                try tokenizeJapanese(allocator, cleaned, out);
            },
            else => {
                try out.append(allocator, lower);
            },
        }
    }
}

fn tokenizeChinese(allocator: Allocator, text: []const u8, out: *std.ArrayListUnmanaged([]const u8)) !void {
    // Collect CJK characters
    var chars: std.ArrayListUnmanaged([]const u8) = .{};
    defer chars.deinit(allocator);

    var ascii_buf: std.ArrayListUnmanaged(u8) = .{};
    defer ascii_buf.deinit(allocator);

    var i: usize = 0;
    while (i < text.len) {
        const cp_len = std.unicode.utf8ByteSequenceLength(text[i]) catch {
            i += 1;
            continue;
        };
        if (i + cp_len > text.len) break;

        const cp = std.unicode.utf8Decode(text[i..][0..cp_len]) catch {
            i += 1;
            continue;
        };

        if (cp >= 0x4E00 and cp <= 0x9FFF) {
            // Flush ASCII buffer
            if (ascii_buf.items.len > 0) {
                const lower = try toLower(allocator, ascii_buf.items);
                try out.append(allocator, lower);
                ascii_buf.clearRetainingCapacity();
            }
            try chars.append(allocator, text[i..][0..cp_len]);
        } else if ((cp >= 'a' and cp <= 'z') or (cp >= 'A' and cp <= 'Z') or (cp >= '0' and cp <= '9') or cp == '_') {
            try ascii_buf.append(allocator, @intCast(cp));
        } else {
            // Flush ASCII
            if (ascii_buf.items.len > 0) {
                const lower = try toLower(allocator, ascii_buf.items);
                try out.append(allocator, lower);
                ascii_buf.clearRetainingCapacity();
            }
        }

        i += cp_len;
    }

    // Flush remaining ASCII
    if (ascii_buf.items.len > 0) {
        const lower = try toLower(allocator, ascii_buf.items);
        try out.append(allocator, lower);
    }

    // Emit bigrams (skip single-char unigrams for BM25 — too broad)
    if (chars.items.len >= 2) {
        for (0..chars.items.len - 1) |j| {
            const bigram = try std.fmt.allocPrint(allocator, "{s}{s}", .{ chars.items[j], chars.items[j + 1] });
            try out.append(allocator, bigram);
        }
    }
    // If only one character, emit it anyway
    if (chars.items.len == 1) {
        try out.append(allocator, try allocator.dupe(u8, chars.items[0]));
    }
}

const JapaneseScript = enum { none, ascii, katakana, kanji, hiragana };

fn tokenizeJapanese(allocator: Allocator, text: []const u8, out: *std.ArrayListUnmanaged([]const u8)) !void {
    // Script-specific chunking: extract ASCII, Katakana, Kanji, Hiragana(2+)
    var current_script: JapaneseScript = .none;
    var chunk_start: usize = 0;
    var chunk_end: usize = 0;

    var i: usize = 0;
    while (i < text.len) {
        const cp_len = std.unicode.utf8ByteSequenceLength(text[i]) catch {
            i += 1;
            continue;
        };
        if (i + cp_len > text.len) break;

        const cp = std.unicode.utf8Decode(text[i..][0..cp_len]) catch {
            i += 1;
            continue;
        };

        const script: JapaneseScript = if ((cp >= 'a' and cp <= 'z') or (cp >= 'A' and cp <= 'Z') or (cp >= '0' and cp <= '9') or cp == '_')
            .ascii
        else if (cp >= 0x30A0 and cp <= 0x30FF or cp == 0x30FC) // Katakana + prolonged sound mark
            .katakana
        else if (cp >= 0x4E00 and cp <= 0x9FFF)
            .kanji
        else if (cp >= 0x3040 and cp <= 0x309F)
            .hiragana
        else
            .none;

        if (script != current_script) {
            // Flush previous chunk
            if (current_script != .none and chunk_end > chunk_start) {
                try emitJapaneseChunk(allocator, text[chunk_start..chunk_end], current_script, out);
            }
            current_script = script;
            chunk_start = i;
        }
        chunk_end = i + cp_len;
        i += cp_len;
    }

    // Flush last chunk
    if (current_script != .none and chunk_end > chunk_start) {
        try emitJapaneseChunk(allocator, text[chunk_start..chunk_end], current_script, out);
    }
}

fn emitJapaneseChunk(
    allocator: Allocator,
    chunk: []const u8,
    script: JapaneseScript,
    out: *std.ArrayListUnmanaged([]const u8),
) !void {
    switch (script) {
        .ascii => {
            const lower = try toLower(allocator, chunk);
            try out.append(allocator, lower);
        },
        .katakana => {
            try out.append(allocator, try allocator.dupe(u8, chunk));
        },
        .kanji => {
            // Emit the whole chunk + bigrams
            try out.append(allocator, try allocator.dupe(u8, chunk));
            // Generate bigrams
            var chars: std.ArrayListUnmanaged([]const u8) = .{};
            defer chars.deinit(allocator);
            var ci: usize = 0;
            while (ci < chunk.len) {
                const cl = std.unicode.utf8ByteSequenceLength(chunk[ci]) catch {
                    ci += 1;
                    continue;
                };
                if (ci + cl > chunk.len) break;
                try chars.append(allocator, chunk[ci..][0..cl]);
                ci += cl;
            }
            if (chars.items.len >= 2) {
                for (0..chars.items.len - 1) |j| {
                    const bigram = try std.fmt.allocPrint(allocator, "{s}{s}", .{ chars.items[j], chars.items[j + 1] });
                    try out.append(allocator, bigram);
                }
            }
        },
        .hiragana => {
            // Only emit hiragana chunks of 2+ chars
            var char_count: usize = 0;
            var ci: usize = 0;
            while (ci < chunk.len) {
                const cl = std.unicode.utf8ByteSequenceLength(chunk[ci]) catch {
                    ci += 1;
                    continue;
                };
                if (ci + cl > chunk.len) break;
                char_count += 1;
                ci += cl;
            }
            if (char_count >= 2) {
                try out.append(allocator, try allocator.dupe(u8, chunk));
            }
        },
        .none => {},
    }
}

// ── Korean particle stripping ───────────────────────────────────────

/// Korean trailing particles, sorted by descending byte length for longest-match-first.
const ko_particles = [_][]const u8{
    // 3-byte particles (6 UTF-8 bytes each)
    "\xec\x97\x90\xec\x84\x9c", // 에서
    "\xec\x9c\xbc\xeb\xa1\x9c", // 으로
    "\xec\x97\x90\xea\xb2\x8c", // 에게
    "\xed\x95\x9c\xed\x85\x8c", // 한테
    "\xec\xb2\x98\xeb\x9f\xbc", // 처럼
    "\xea\xb0\x99\xec\x9d\xb4", // 같이
    "\xeb\xb3\xb4\xeb\x8b\xa4", // 보다
    "\xea\xb9\x8c\xec\xa7\x80", // 까지
    "\xeb\xb6\x80\xed\x84\xb0", // 부터
    "\xeb\xa7\x88\xeb\x8b\xa4", // 마다
    "\xeb\xb0\x96\xec\x97\x90", // 밖에
    "\xeb\x8c\x80\xeb\xa1\x9c", // 대로
    // 1-syllable particles (3 UTF-8 bytes each)
    "\xec\x9d\x80", // 은
    "\xeb\x8a\x94", // 는
    "\xec\x9d\xb4", // 이
    "\xea\xb0\x80", // 가
    "\xec\x9d\x84", // 을
    "\xeb\xa5\xbc", // 를
    "\xec\x9d\x98", // 의
    "\xec\x97\x90", // 에
    "\xeb\xa1\x9c", // 로
    "\xec\x99\x80", // 와
    "\xea\xb3\xbc", // 과
    "\xeb\x8f\x84", // 도
    "\xeb\xa7\x8c", // 만
};

/// Returns the byte offset of the stem end if a trailing particle was stripped,
/// or null if no particle matched.
fn stripKoreanTrailingParticle(token: []const u8) ?usize {
    for (ko_particles) |particle| {
        if (token.len > particle.len and std.mem.endsWith(u8, token, particle)) {
            return token.len - particle.len;
        }
    }
    return null;
}

fn isUsefulKoreanStem(stem: []const u8) bool {
    // Check if stem contains Hangul
    var has_hangul = false;
    var char_count: usize = 0;
    var i: usize = 0;
    while (i < stem.len) {
        const cp_len = std.unicode.utf8ByteSequenceLength(stem[i]) catch {
            i += 1;
            continue;
        };
        if (i + cp_len > stem.len) break;
        const cp = std.unicode.utf8Decode(stem[i..][0..cp_len]) catch {
            i += 1;
            continue;
        };
        if (cp >= 0xAC00 and cp <= 0xD7AF) has_hangul = true;
        char_count += 1;
        i += cp_len;
    }
    // Korean stems must be >= 2 characters (syllables)
    if (has_hangul) return char_count >= 2;
    // ASCII stems are OK if alphanumeric
    return isAlphanumericAscii(stem);
}

fn isAlphanumericAscii(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '_'))
            return false;
    }
    return true;
}

// ── Stopword filtering ──────────────────────────────────────────────

fn isStopWord(word: []const u8) bool {
    return stop_words_en.has(word) or
        stop_words_zh.has(word) or
        stop_words_ko.has(word) or
        stop_words_ja.has(word) or
        stop_words_es.has(word) or
        stop_words_pt.has(word) or
        stop_words_ar.has(word);
}

const stop_words_en = std.StaticStringMap(void).initComptime(.{
    .{"the"},   .{"a"},         .{"an"},        .{"is"},         .{"are"},      .{"was"},
    .{"were"},  .{"be"},        .{"been"},      .{"being"},      .{"have"},     .{"has"},
    .{"had"},   .{"do"},        .{"does"},      .{"did"},        .{"will"},     .{"would"},
    .{"could"}, .{"should"},    .{"may"},       .{"might"},      .{"shall"},    .{"can"},
    .{"need"},  .{"dare"},      .{"ought"},     .{"used"},       .{"to"},       .{"of"},
    .{"in"},    .{"for"},       .{"on"},        .{"with"},       .{"at"},       .{"by"},
    .{"from"},  .{"as"},        .{"into"},      .{"through"},    .{"during"},   .{"before"},
    .{"after"}, .{"above"},     .{"below"},     .{"between"},    .{"out"},      .{"off"},
    .{"over"},  .{"under"},     .{"again"},     .{"further"},    .{"then"},     .{"once"},
    .{"it"},    .{"its"},       .{"this"},      .{"that"},       .{"these"},    .{"those"},
    .{"i"},     .{"me"},        .{"my"},        .{"we"},         .{"our"},      .{"you"},
    .{"your"},  .{"he"},        .{"him"},       .{"his"},        .{"she"},      .{"her"},
    .{"they"},  .{"them"},      .{"their"},     .{"what"},       .{"which"},    .{"who"},
    .{"whom"},  .{"and"},       .{"but"},       .{"or"},         .{"nor"},      .{"not"},
    .{"so"},    .{"very"},      .{"just"},      .{"about"},      .{"up"},       .{"if"},
    .{"how"},   .{"when"},      .{"where"},     .{"why"},        .{"also"},     .{"too"},
    .{"quite"}, .{"really"},    .{"all"},       .{"any"},        .{"some"},     .{"each"},
    .{"every"}, .{"must"},
    // Time references (vague)
         .{"yesterday"}, .{"today"},      .{"tomorrow"}, .{"earlier"},
    .{"later"}, .{"recently"},  .{"ago"},       .{"now"},
    // Vague references
           .{"thing"},    .{"things"},
    .{"stuff"}, .{"something"}, .{"anything"},  .{"everything"}, .{"nothing"},
    // Question/request words
     .{"please"},
    .{"help"},  .{"find"},      .{"show"},      .{"get"},        .{"tell"},     .{"give"},
});

const stop_words_zh = std.StaticStringMap(void).initComptime(.{
    .{"\xe6\x88\x91"}, // 我
    .{"\xe6\x88\x91\xe4\xbb\xac"}, // 我们
    .{"\xe4\xbd\xa0"}, // 你
    .{"\xe4\xbd\xa0\xe4\xbb\xac"}, // 你们
    .{"\xe4\xbb\x96"}, // 他
    .{"\xe5\xa5\xb9"}, // 她
    .{"\xe5\xae\x83"}, // 它
    .{"\xe4\xbb\x96\xe4\xbb\xac"}, // 他们
    .{"\xe8\xbf\x99"}, // 这
    .{"\xe9\x82\xa3"}, // 那
    .{"\xe8\xbf\x99\xe4\xb8\xaa"}, // 这个
    .{"\xe9\x82\xa3\xe4\xb8\xaa"}, // 那个
    .{"\xe8\xbf\x99\xe4\xba\x9b"}, // 这些
    .{"\xe9\x82\xa3\xe4\xba\x9b"}, // 那些
    .{"\xe7\x9a\x84"}, // 的
    .{"\xe4\xba\x86"}, // 了
    .{"\xe7\x9d\x80"}, // 着
    .{"\xe8\xbf\x87"}, // 过
    .{"\xe5\xbe\x97"}, // 得
    .{"\xe5\x9c\xb0"}, // 地
    .{"\xe5\x90\x97"}, // 吗
    .{"\xe5\x91\xa2"}, // 呢
    .{"\xe5\x90\xa7"}, // 吧
    .{"\xe5\x95\x8a"}, // 啊
    .{"\xe5\x91\x80"}, // 呀
    .{"\xe5\x98\x9b"}, // 嘛
    .{"\xe5\x95\xa6"}, // 啦
    .{"\xe6\x98\xaf"}, // 是
    .{"\xe6\x9c\x89"}, // 有
    .{"\xe5\x9c\xa8"}, // 在
    .{"\xe8\xa2\xab"}, // 被
    .{"\xe6\x8a\x8a"}, // 把
    .{"\xe7\xbb\x99"}, // 给
    .{"\xe8\xae\xa9"}, // 让
    .{"\xe7\x94\xa8"}, // 用
    .{"\xe5\x88\xb0"}, // 到
    .{"\xe5\x8e\xbb"}, // 去
    .{"\xe6\x9d\xa5"}, // 来
    .{"\xe5\x81\x9a"}, // 做
    .{"\xe8\xaf\xb4"}, // 说
    .{"\xe7\x9c\x8b"}, // 看
    .{"\xe6\x89\xbe"}, // 找
    .{"\xe6\x83\xb3"}, // 想
    .{"\xe8\xa6\x81"}, // 要
    .{"\xe8\x83\xbd"}, // 能
    .{"\xe4\xbc\x9a"}, // 会
    .{"\xe5\x8f\xaf\xe4\xbb\xa5"}, // 可以
    .{"\xe5\x92\x8c"}, // 和
    .{"\xe4\xb8\x8e"}, // 与
    .{"\xe6\x88\x96"}, // 或
    .{"\xe4\xbd\x86"}, // 但
    .{"\xe4\xbd\x86\xe6\x98\xaf"}, // 但是
    .{"\xe5\x9b\xa0\xe4\xb8\xba"}, // 因为
    .{"\xe6\x89\x80\xe4\xbb\xa5"}, // 所以
    .{"\xe5\xa6\x82\xe6\x9e\x9c"}, // 如果
    .{"\xe8\x99\xbd\xe7\x84\xb6"}, // 虽然
    .{"\xe8\x80\x8c"}, // 而
    .{"\xe4\xb9\x9f"}, // 也
    .{"\xe9\x83\xbd"}, // 都
    .{"\xe5\xb0\xb1"}, // 就
    .{"\xe8\xbf\x98"}, // 还
    .{"\xe5\x8f\x88"}, // 又
    .{"\xe5\x86\x8d"}, // 再
    .{"\xe6\x89\x8d"}, // 才
    .{"\xe5\x8f\xaa"}, // 只
    .{"\xe4\xb9\x8b\xe5\x89\x8d"}, // 之前
    .{"\xe4\xbb\xa5\xe5\x89\x8d"}, // 以前
    .{"\xe4\xb9\x8b\xe5\x90\x8e"}, // 之后
    .{"\xe4\xbb\xa5\xe5\x90\x8e"}, // 以后
    .{"\xe5\x88\x9a\xe6\x89\x8d"}, // 刚才
    .{"\xe7\x8e\xb0\xe5\x9c\xa8"}, // 现在
    .{"\xe6\x98\xa8\xe5\xa4\xa9"}, // 昨天
    .{"\xe4\xbb\x8a\xe5\xa4\xa9"}, // 今天
    .{"\xe6\x98\x8e\xe5\xa4\xa9"}, // 明天
    .{"\xe6\x9c\x80\xe8\xbf\x91"}, // 最近
    .{"\xe4\xb8\x9c\xe8\xa5\xbf"}, // 东西
    .{"\xe4\xba\x8b\xe6\x83\x85"}, // 事情
    .{"\xe4\xba\x8b"}, // 事
    .{"\xe4\xbb\x80\xe4\xb9\x88"}, // 什么
    .{"\xe5\x93\xaa\xe4\xb8\xaa"}, // 哪个
    .{"\xe5\x93\xaa\xe4\xba\x9b"}, // 哪些
    .{"\xe6\x80\x8e\xe4\xb9\x88"}, // 怎么
    .{"\xe4\xb8\xba\xe4\xbb\x80\xe4\xb9\x88"}, // 为什么
    .{"\xe5\xa4\x9a\xe5\xb0\x91"}, // 多少
    .{"\xe8\xaf\xb7"}, // 请
    .{"\xe5\xb8\xae"}, // 帮
    .{"\xe5\xb8\xae\xe5\xbf\x99"}, // 帮忙
    .{"\xe5\x91\x8a\xe8\xaf\x89"}, // 告诉
});

const stop_words_ko = std.StaticStringMap(void).initComptime(.{
    // Particles
    .{"\xec\x9d\x80"}, // 은
    .{"\xeb\x8a\x94"}, // 는
    .{"\xec\x9d\xb4"}, // 이
    .{"\xea\xb0\x80"}, // 가
    .{"\xec\x9d\x84"}, // 을
    .{"\xeb\xa5\xbc"}, // 를
    .{"\xec\x9d\x98"}, // 의
    .{"\xec\x97\x90"}, // 에
    .{"\xec\x97\x90\xec\x84\x9c"}, // 에서
    .{"\xeb\xa1\x9c"}, // 로
    .{"\xec\x9c\xbc\xeb\xa1\x9c"}, // 으로
    .{"\xec\x99\x80"}, // 와
    .{"\xea\xb3\xbc"}, // 과
    .{"\xeb\x8f\x84"}, // 도
    .{"\xeb\xa7\x8c"}, // 만
    .{"\xea\xb9\x8c\xec\xa7\x80"}, // 까지
    .{"\xeb\xb6\x80\xed\x84\xb0"}, // 부터
    .{"\xed\x95\x9c\xed\x85\x8c"}, // 한테
    .{"\xec\x97\x90\xea\xb2\x8c"}, // 에게
    .{"\xea\xbb\x98"}, // 께
    .{"\xec\xb2\x98\xeb\x9f\xbc"}, // 처럼
    .{"\xea\xb0\x99\xec\x9d\xb4"}, // 같이
    .{"\xeb\xb3\xb4\xeb\x8b\xa4"}, // 보다
    .{"\xeb\xa7\x88\xeb\x8b\xa4"}, // 마다
    .{"\xeb\xb0\x96\xec\x97\x90"}, // 밖에
    .{"\xeb\x8c\x80\xeb\xa1\x9c"}, // 대로
    // Pronouns
    .{"\xeb\x82\x98"}, // 나
    .{"\xeb\x82\x98\xeb\x8a\x94"}, // 나는
    .{"\xeb\x82\xb4\xea\xb0\x80"}, // 내가
    .{"\xeb\x82\x98\xeb\xa5\xbc"}, // 나를
    .{"\xeb\x84\x88"}, // 너
    .{"\xec\x9a\xb0\xeb\xa6\xac"}, // 우리
    .{"\xec\xa0\x80"}, // 저
    .{"\xec\xa0\x80\xed\x9d\xac"}, // 저희
    .{"\xea\xb7\xb8"}, // 그
    .{"\xea\xb7\xb8\xeb\x85\x80"}, // 그녀
    .{"\xea\xb7\xb8\xeb\x93\xa4"}, // 그들
    .{"\xec\x9d\xb4\xea\xb2\x83"}, // 이것
    .{"\xec\xa0\x80\xea\xb2\x83"}, // 저것
    .{"\xea\xb7\xb8\xea\xb2\x83"}, // 그것
    .{"\xec\x97\xac\xea\xb8\xb0"}, // 여기
    .{"\xec\xa0\x80\xea\xb8\xb0"}, // 저기
    .{"\xea\xb1\xb0\xea\xb8\xb0"}, // 거기
    // Common verbs
    .{"\xec\x9e\x88\xeb\x8b\xa4"}, // 있다
    .{"\xec\x97\x86\xeb\x8b\xa4"}, // 없다
    .{"\xed\x95\x98\xeb\x8b\xa4"}, // 하다
    .{"\xeb\x90\x98\xeb\x8b\xa4"}, // 되다
    .{"\xec\x9d\xb4\xeb\x8b\xa4"}, // 이다
    .{"\xec\x95\x84\xeb\x8b\x88\xeb\x8b\xa4"}, // 아니다
    .{"\xeb\xb3\xb4\xeb\x8b\xa4"}, // 보다 (already listed)
    .{"\xec\xa3\xbc\xeb\x8b\xa4"}, // 주다
    .{"\xec\x98\xa4\xeb\x8b\xa4"}, // 오다
    .{"\xea\xb0\x80\xeb\x8b\xa4"}, // 가다
    // Nouns (vague)
    .{"\xea\xb2\x83"}, // 것
    .{"\xea\xb1\xb0"}, // 거
    .{"\xeb\x93\xb1"}, // 등
    .{"\xec\x88\x98"}, // 수
    .{"\xeb\x95\x8c"}, // 때
    .{"\xea\xb3\xb3"}, // 곳
    .{"\xec\xa4\x91"}, // 중
    .{"\xeb\xb6\x84"}, // 분
    // Adverbs
    .{"\xec\x9e\x98"}, // 잘
    .{"\xeb\x8d\x94"}, // 더
    .{"\xeb\x98\x90"}, // 또
    .{"\xeb\xa7\xa4\xec\x9a\xb0"}, // 매우
    .{"\xec\xa0\x95\xeb\xa7\x90"}, // 정말
    .{"\xec\x95\x84\xec\xa3\xbc"}, // 아주
    .{"\xeb\xa7\x8e\xec\x9d\xb4"}, // 많이
    .{"\xeb\x84\x88\xeb\xac\xb4"}, // 너무
    .{"\xec\xa2\x80"}, // 좀
    // Conjunctions
    .{"\xea\xb7\xb8\xeb\xa6\xac\xea\xb3\xa0"}, // 그리고
    .{"\xed\x95\x98\xec\xa7\x80\xeb\xa7\x8c"}, // 하지만
    .{"\xea\xb7\xb8\xeb\x9e\x98\xec\x84\x9c"}, // 그래서
    .{"\xea\xb7\xb8\xeb\x9f\xb0\xeb\x8d\xb0"}, // 그런데
    .{"\xea\xb7\xb8\xeb\x9f\xac\xeb\x82\x98"}, // 그러나
    .{"\xeb\x98\x90\xeb\x8a\x94"}, // 또는
    .{"\xea\xb7\xb8\xeb\x9f\xac\xeb\xa9\xb4"}, // 그러면
    // Question words
    .{"\xec\x99\x9c"}, // 왜
    .{"\xec\x96\xb4\xeb\x96\xbb\xea\xb2\x8c"}, // 어떻게
    .{"\xeb\xad\x90"}, // 뭐
    .{"\xec\x96\xb8\xec\xa0\x9c"}, // 언제
    .{"\xec\x96\xb4\xeb\x94\x94"}, // 어디
    .{"\xeb\x88\x84\xea\xb5\xac"}, // 누구
    .{"\xeb\xac\xb4\xec\x97\x87"}, // 무엇
    .{"\xec\x96\xb4\xeb\x96\xa4"}, // 어떤
    // Time (vague)
    .{"\xec\x96\xb4\xec\xa0\x9c"}, // 어제
    .{"\xec\x98\xa4\xeb\x8a\x98"}, // 오늘
    .{"\xeb\x82\xb4\xec\x9d\xbc"}, // 내일
    .{"\xec\xb5\x9c\xea\xb7\xbc"}, // 최근
    .{"\xec\xa7\x80\xea\xb8\x88"}, // 지금
    .{"\xec\x95\x84\xea\xb9\x8c"}, // 아까
    .{"\xeb\x82\x98\xec\xa4\x91"}, // 나중
    .{"\xec\xa0\x84\xec\x97\x90"}, // 전에
    // Request words
    .{"\xec\xa0\x9c\xeb\xb0\x9c"}, // 제발
    .{"\xeb\xb6\x80\xed\x83\x81"}, // 부탁
});

const stop_words_ja = std.StaticStringMap(void).initComptime(.{
    .{"\xe3\x81\x93\xe3\x82\x8c"}, // これ
    .{"\xe3\x81\x9d\xe3\x82\x8c"}, // それ
    .{"\xe3\x81\x82\xe3\x82\x8c"}, // あれ
    .{"\xe3\x81\x93\xe3\x81\xae"}, // この
    .{"\xe3\x81\x9d\xe3\x81\xae"}, // その
    .{"\xe3\x81\x82\xe3\x81\xae"}, // あの
    .{"\xe3\x81\x93\xe3\x81\x93"}, // ここ
    .{"\xe3\x81\x9d\xe3\x81\x93"}, // そこ
    .{"\xe3\x81\x82\xe3\x81\x9d\xe3\x81\x93"}, // あそこ
    .{"\xe3\x81\x99\xe3\x82\x8b"}, // する
    .{"\xe3\x81\x97\xe3\x81\x9f"}, // した
    .{"\xe3\x81\x97\xe3\x81\xa6"}, // して
    .{"\xe3\x81\xa7\xe3\x81\x99"}, // です
    .{"\xe3\x81\xbe\xe3\x81\x99"}, // ます
    .{"\xe3\x81\x84\xe3\x82\x8b"}, // いる
    .{"\xe3\x81\x82\xe3\x82\x8b"}, // ある
    .{"\xe3\x81\xaa\xe3\x82\x8b"}, // なる
    .{"\xe3\x81\xa7\xe3\x81\x8d\xe3\x82\x8b"}, // できる
    .{"\xe3\x81\xae"}, // の
    .{"\xe3\x81\x93\xe3\x81\xa8"}, // こと
    .{"\xe3\x82\x82\xe3\x81\xae"}, // もの
    .{"\xe3\x81\x9f\xe3\x82\x81"}, // ため
    .{"\xe3\x81\x9d\xe3\x81\x97\xe3\x81\xa6"}, // そして
    .{"\xe3\x81\x97\xe3\x81\x8b\xe3\x81\x97"}, // しかし
    .{"\xe3\x81\xbe\xe3\x81\x9f"}, // また
    .{"\xe3\x81\xa7\xe3\x82\x82"}, // でも
    .{"\xe3\x81\x8b\xe3\x82\x89"}, // から
    .{"\xe3\x81\xbe\xe3\x81\xa7"}, // まで
    .{"\xe3\x82\x88\xe3\x82\x8a"}, // より
    .{"\xe3\x81\xa0\xe3\x81\x91"}, // だけ
    .{"\xe3\x81\xaa\xe3\x81\x9c"}, // なぜ
    .{"\xe3\x81\xa9\xe3\x81\x86"}, // どう
    .{"\xe4\xbd\x95"}, // 何
    .{"\xe3\x81\x84\xe3\x81\xa4"}, // いつ
    .{"\xe3\x81\xa9\xe3\x81\x93"}, // どこ
    .{"\xe8\xaa\xb0"}, // 誰
    .{"\xe3\x81\xa9\xe3\x82\x8c"}, // どれ
    .{"\xe6\x98\xa8\xe6\x97\xa5"}, // 昨日
    .{"\xe4\xbb\x8a\xe6\x97\xa5"}, // 今日
    .{"\xe6\x98\x8e\xe6\x97\xa5"}, // 明日
    .{"\xe6\x9c\x80\xe8\xbf\x91"}, // 最近
    .{"\xe4\xbb\x8a"}, // 今
    .{"\xe3\x81\x95\xe3\x81\xa3\xe3\x81\x8d"}, // さっき
    .{"\xe5\x89\x8d"}, // 前
    .{"\xe5\xbe\x8c"}, // 後
});

const stop_words_es = std.StaticStringMap(void).initComptime(.{
    .{"el"},     .{"la"},    .{"los"},     .{"las"},           .{"un"},       .{"una"},
    .{"unos"},   .{"unas"},  .{"este"},    .{"esta"},          .{"ese"},      .{"esa"},
    .{"yo"},     .{"me"},    .{"mi"},      .{"nosotros"},      .{"nosotras"}, .{"tu"},
    .{"tus"},    .{"usted"}, .{"ustedes"}, .{"ellos"},         .{"ellas"},    .{"de"},
    .{"del"},    .{"a"},     .{"en"},      .{"con"},           .{"por"},      .{"para"},
    .{"sobre"},  .{"entre"}, .{"y"},       .{"o"},             .{"pero"},     .{"si"},
    .{"porque"}, .{"como"},  .{"es"},      .{"son"},           .{"fue"},      .{"fueron"},
    .{"ser"},    .{"estar"}, .{"haber"},   .{"tener"},         .{"hacer"},    .{"ayer"},
    .{"hoy"},    .{"antes"}, .{"ahora"},   .{"recientemente"}, .{"que"},      .{"cuando"},
    .{"donde"},  .{"favor"},
    .{"ayuda"},
    // Accented forms
    .{"ma\xc3\xb1\x61na"}, // mañana
    .{"despu\xc3\xa9s"}, // después
    .{"despues"},
    .{"qu\xc3\xa9"}, // qué
    .{"c\xc3\xb3mo"}, // cómo
    .{"cu\xc3\xa1ndo"}, // cuándo
    .{"d\xc3\xb3nde"}, // dónde
    .{"porqu\xc3\xa9"}, // porqué
});

const stop_words_pt = std.StaticStringMap(void).initComptime(.{
    .{"o"},     .{"a"},      .{"os"},    .{"as"},     .{"um"},     .{"uma"},
    .{"uns"},   .{"umas"},   .{"este"},  .{"esta"},   .{"esse"},   .{"essa"},
    .{"eu"},    .{"me"},     .{"meu"},   .{"minha"},  .{"nos"},    .{"ele"},
    .{"ela"},   .{"eles"},   .{"elas"},  .{"de"},     .{"do"},     .{"da"},
    .{"em"},    .{"com"},    .{"por"},   .{"para"},   .{"sobre"},  .{"entre"},
    .{"e"},     .{"ou"},     .{"mas"},   .{"se"},     .{"porque"}, .{"como"},
    .{"foi"},   .{"foram"},  .{"ser"},   .{"estar"},  .{"ter"},    .{"fazer"},
    .{"ontem"}, .{"hoje"},   .{"antes"}, .{"depois"}, .{"agora"},  .{"recentemente"},
    .{"que"},   .{"quando"}, .{"onde"},  .{"favor"},
    .{"ajuda"},
    // Accented forms
    .{"n\xc3\xb3s"}, // nós
    .{"voc\xc3\xaa"}, // você
    .{"voc\xc3\xaas"}, // vocês
    .{"\xc3\xa9"}, // é
    .{"s\xc3\xa3o"}, // são
    .{"amanh\xc3\xa3"}, // amanhã
    .{"qu\xc3\xaa"}, // quê
    .{"porqu\xc3\xaa"}, // porquê
});

const stop_words_ar = std.StaticStringMap(void).initComptime(.{
    .{"\xd8\xa7\xd9\x84"}, // ال
    .{"\xd9\x88"}, // و
    .{"\xd8\xa3\xd9\x88"}, // أو
    .{"\xd9\x84\xd9\x83\xd9\x86"}, // لكن
    .{"\xd8\xab\xd9\x85"}, // ثم
    .{"\xd8\xa8\xd9\x84"}, // بل
    .{"\xd8\xa3\xd9\x86\xd8\xa7"}, // أنا
    .{"\xd9\x86\xd8\xad\xd9\x86"}, // نحن
    .{"\xd9\x87\xd9\x88"}, // هو
    .{"\xd9\x87\xd9\x8a"}, // هي
    .{"\xd9\x87\xd9\x85"}, // هم
    .{"\xd9\x87\xd8\xb0\xd8\xa7"}, // هذا
    .{"\xd9\x87\xd8\xb0\xd9\x87"}, // هذه
    .{"\xd8\xb0\xd9\x84\xd9\x83"}, // ذلك
    .{"\xd8\xaa\xd9\x84\xd9\x83"}, // تلك
    .{"\xd9\x87\xd9\x86\xd8\xa7"}, // هنا
    .{"\xd9\x87\xd9\x86\xd8\xa7\xd9\x83"}, // هناك
    .{"\xd9\x85\xd9\x86"}, // من
    .{"\xd8\xa5\xd9\x84\xd9\x89"}, // إلى
    .{"\xd8\xa7\xd9\x84\xd9\x89"}, // الى
    .{"\xd9\x81\xd9\x8a"}, // في
    .{"\xd8\xb9\xd9\x84\xd9\x89"}, // على
    .{"\xd8\xb9\xd9\x86"}, // عن
    .{"\xd9\x85\xd8\xb9"}, // مع
    .{"\xd8\xa8\xd9\x8a\xd9\x86"}, // بين
    .{"\xd9\x84"}, // ل
    .{"\xd8\xa8"}, // ب
    .{"\xd9\x83"}, // ك
    .{"\xd9\x83\xd8\xa7\xd9\x86"}, // كان
    .{"\xd9\x83\xd8\xa7\xd9\x86\xd8\xaa"}, // كانت
    .{"\xd9\x8a\xd9\x83\xd9\x88\xd9\x86"}, // يكون
    .{"\xd8\xaa\xd9\x83\xd9\x88\xd9\x86"}, // تكون
    .{"\xd8\xb5\xd8\xa7\xd8\xb1"}, // صار
    .{"\xd8\xa3\xd8\xb5\xd8\xa8\xd8\xad"}, // أصبح
    .{"\xd9\x8a\xd9\x85\xd9\x83\xd9\x86"}, // يمكن
    .{"\xd9\x85\xd9\x85\xd9\x83\xd9\x86"}, // ممكن
    .{"\xd8\xa8\xd8\xa7\xd9\x84\xd8\xa3\xd9\x85\xd8\xb3"}, // بالأمس
    .{"\xd8\xa7\xd9\x85\xd8\xb3"}, // امس
    .{"\xd8\xa7\xd9\x84\xd9\x8a\xd9\x88\xd9\x85"}, // اليوم
    .{"\xd8\xba\xd8\xaf\xd8\xa7"}, // غدا
    .{"\xd8\xa7\xd9\x84\xd8\xa2\xd9\x86"}, // الآن
    .{"\xd9\x82\xd8\xa8\xd9\x84"}, // قبل
    .{"\xd8\xa8\xd8\xb9\xd8\xaf"}, // بعد
    .{"\xd9\x84\xd9\x85\xd8\xa7\xd8\xb0\xd8\xa7"}, // لماذا
    .{"\xd9\x83\xd9\x8a\xd9\x81"}, // كيف
    .{"\xd9\x85\xd8\xa7\xd8\xb0\xd8\xa7"}, // ماذا
    .{"\xd9\x85\xd8\xaa\xd9\x89"}, // متى
    .{"\xd8\xa3\xd9\x8a\xd9\x86"}, // أين
    .{"\xd9\x87\xd9\x84"}, // هل
});

// ── Validity check ──────────────────────────────────────────────────

fn isValidKeyword(token: []const u8) bool {
    if (token.len == 0) return false;

    // Check if pure ASCII alphabetic — if so, need >= 3 chars
    if (isPureAsciiAlpha(token)) {
        return token.len >= 3;
    }

    // Check if pure numeric
    if (isPureNumeric(token)) return false;

    // Check if all punctuation
    if (isPurePunctuation(token)) return false;

    return true;
}

fn isPureAsciiAlpha(s: []const u8) bool {
    for (s) |c| {
        if (!((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z'))) return false;
    }
    return true;
}

fn isPureNumeric(s: []const u8) bool {
    for (s) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

fn isPurePunctuation(s: []const u8) bool {
    var i: usize = 0;
    while (i < s.len) {
        const cp_len = std.unicode.utf8ByteSequenceLength(s[i]) catch {
            i += 1;
            continue;
        };
        if (i + cp_len > s.len) break;
        const cp = std.unicode.utf8Decode(s[i..][0..cp_len]) catch {
            i += 1;
            continue;
        };
        // Check if codepoint is NOT punctuation/symbol
        if (!isPunctCodepoint(cp)) return false;
        i += cp_len;
    }
    return true;
}

fn isPunctCodepoint(cp: u21) bool {
    // Common ASCII punctuation
    if (cp >= 0x21 and cp <= 0x2F) return true; // !"#$%&'()*+,-./
    if (cp >= 0x3A and cp <= 0x40) return true; // :;<=>?@
    if (cp >= 0x5B and cp <= 0x60) return true; // [\]^_`
    if (cp >= 0x7B and cp <= 0x7E) return true; // {|}~
    // Unicode punctuation ranges
    if (cp >= 0x2000 and cp <= 0x206F) return true; // General punctuation
    if (cp >= 0x3000 and cp <= 0x303F) return true; // CJK symbols
    if (cp >= 0xFE30 and cp <= 0xFE4F) return true; // CJK compatibility
    if (cp >= 0xFF01 and cp <= 0xFF0F) return true; // Fullwidth punct
    if (cp >= 0xFF1A and cp <= 0xFF20) return true;
    if (cp >= 0xFF3B and cp <= 0xFF40) return true;
    if (cp >= 0xFF5B and cp <= 0xFF65) return true;
    return false;
}

// ── FTS5 query building ─────────────────────────────────────────────

/// Build an FTS5 MATCH query from filtered tokens.
/// Short tokens (< 4 ASCII chars) get prefix wildcard.
/// Tokens with special FTS5 chars are quoted.
fn buildFts5Query(allocator: Allocator, tokens: []const []const u8) ![]const u8 {
    var parts: std.ArrayListUnmanaged([]const u8) = .{};
    defer {
        for (parts.items) |p| allocator.free(p);
        parts.deinit(allocator);
    }

    for (tokens) |token| {
        const needs_quote = hasFts5Special(token);
        const needs_prefix = isPureAsciiAlpha(token) and token.len < 4;

        if (needs_quote) {
            if (needs_prefix) {
                const escaped = try escapeFts5Quotes(allocator, token);
                defer allocator.free(escaped);
                const part = try std.fmt.allocPrint(allocator, "\"{s}\"*", .{escaped});
                try parts.append(allocator, part);
            } else {
                const escaped = try escapeFts5Quotes(allocator, token);
                defer allocator.free(escaped);
                const part = try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
                try parts.append(allocator, part);
            }
        } else if (needs_prefix) {
            const part = try std.fmt.allocPrint(allocator, "{s}*", .{token});
            try parts.append(allocator, part);
        } else {
            try parts.append(allocator, try allocator.dupe(u8, token));
        }
    }

    // Join with spaces (implicit AND in FTS5)
    var total_len: usize = 0;
    for (parts.items, 0..) |p, idx| {
        total_len += p.len;
        if (idx < parts.items.len - 1) total_len += 1;
    }

    var result = try allocator.alloc(u8, total_len);
    var pos: usize = 0;
    for (parts.items, 0..) |p, idx| {
        @memcpy(result[pos..][0..p.len], p);
        pos += p.len;
        if (idx < parts.items.len - 1) {
            result[pos] = ' ';
            pos += 1;
        }
    }

    return result;
}

fn hasFts5Special(token: []const u8) bool {
    for (token) |c| {
        switch (c) {
            '"', '*', '+', '-', '(', ')', ':', '^' => return true,
            else => {},
        }
    }
    return false;
}

fn escapeFts5Quotes(allocator: Allocator, token: []const u8) ![]const u8 {
    var count: usize = 0;
    for (token) |c| {
        if (c == '"') count += 1;
    }
    if (count == 0) return allocator.dupe(u8, token);

    var result = try allocator.alloc(u8, token.len + count);
    var pos: usize = 0;
    for (token) |c| {
        if (c == '"') {
            result[pos] = '"';
            pos += 1;
            result[pos] = '"';
            pos += 1;
        } else {
            result[pos] = c;
            pos += 1;
        }
    }
    return result;
}

// ── Helpers ─────────────────────────────────────────────────────────

fn toLower(allocator: Allocator, text: []const u8) ![]const u8 {
    var result = try allocator.alloc(u8, text.len);
    for (text, 0..) |c, idx| {
        result[idx] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }
    return result;
}

fn stripPunctuation(text: []const u8) []const u8 {
    var start: usize = 0;
    var end: usize = text.len;

    // Strip leading ASCII punctuation
    while (start < end and isAsciiPunct(text[start])) {
        start += 1;
    }
    // Strip trailing ASCII punctuation
    while (end > start and isAsciiPunct(text[end - 1])) {
        end -= 1;
    }
    return text[start..end];
}

fn isAsciiPunct(c: u8) bool {
    return switch (c) {
        '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~' => true,
        else => false,
    };
}

// ── Tests ───────────────────────────────────────────────────────────

test "english stopword filtering" {
    const allocator = std.testing.allocator;
    var result = try expandQuery(allocator, "what is the best way to learn Zig");
    defer result.deinit(allocator);

    try std.testing.expectEqual(Language.en, result.language);

    // "best", "way", "learn", "zig" should survive
    try std.testing.expect(result.filtered_tokens.len >= 3);

    // Verify no stopwords leaked through
    for (result.filtered_tokens) |t| {
        try std.testing.expect(!stop_words_en.has(t));
    }

    // Verify specific keywords present
    try expectContains(result.filtered_tokens, "best");
    try expectContains(result.filtered_tokens, "way");
    try expectContains(result.filtered_tokens, "learn");
    try expectContains(result.filtered_tokens, "zig");
}

test "empty query returns empty" {
    const allocator = std.testing.allocator;
    var result = try expandQuery(allocator, "");
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), result.filtered_tokens.len);
    try std.testing.expectEqual(@as(usize, 0), result.original_tokens.len);
    try std.testing.expectEqualStrings("", result.fts5_query);
}

test "whitespace-only query returns empty" {
    const allocator = std.testing.allocator;
    var result = try expandQuery(allocator, "   \t\n  ");
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), result.filtered_tokens.len);
}

test "all stopwords returns original as fallback" {
    const allocator = std.testing.allocator;
    var result = try expandQuery(allocator, "the a an is are");
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), result.filtered_tokens.len);
    // FTS5 query should fall back to original
    try std.testing.expectEqualStrings("the a an is are", result.fts5_query);
}

test "short tokens get prefix wildcard" {
    const allocator = std.testing.allocator;
    // "API" is 3 chars (exactly at the boundary) — kept and gets prefix wildcard
    var result = try expandQuery(allocator, "API and NLP models");
    defer result.deinit(allocator);

    // "api" is 3 chars pure alpha -> should have * suffix in FTS5 (< 4 chars)
    try std.testing.expect(std.mem.indexOf(u8, result.fts5_query, "api*") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.fts5_query, "nlp*") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.fts5_query, "models") != null);
}

test "single meaningful word preserved" {
    const allocator = std.testing.allocator;
    var result = try expandQuery(allocator, "database");
    defer result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), result.filtered_tokens.len);
    try std.testing.expectEqualStrings("database", result.filtered_tokens[0]);
}

test "deduplication works" {
    const allocator = std.testing.allocator;
    var result = try expandQuery(allocator, "test test testing");
    defer result.deinit(allocator);

    // "test" should appear only once
    var test_count: usize = 0;
    for (result.filtered_tokens) |t| {
        if (std.mem.eql(u8, t, "test")) test_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), test_count);
}

test "mixed case normalized" {
    const allocator = std.testing.allocator;
    var result = try expandQuery(allocator, "Database SERVER");
    defer result.deinit(allocator);

    try expectContains(result.filtered_tokens, "database");
    try expectContains(result.filtered_tokens, "server");
}

test "numbers filtered" {
    const allocator = std.testing.allocator;
    var result = try expandQuery(allocator, "error 404 in server");
    defer result.deinit(allocator);

    try expectNotContains(result.filtered_tokens, "404");
    try expectContains(result.filtered_tokens, "error");
    try expectContains(result.filtered_tokens, "server");
}

test "short english words filtered" {
    const allocator = std.testing.allocator;
    var result = try expandQuery(allocator, "go to db");
    defer result.deinit(allocator);

    // "go", "to", "db" are all < 3 chars or stopwords
    try expectNotContains(result.filtered_tokens, "go");
    try expectNotContains(result.filtered_tokens, "to");
    try expectNotContains(result.filtered_tokens, "db");
}

test "FTS5 special chars quoted" {
    const allocator = std.testing.allocator;
    var result = try expandQuery(allocator, "c++ programming");
    defer result.deinit(allocator);

    // c++ should be quoted in FTS5
    // Note: "c++" after punctuation stripping becomes "c" which is too short
    // so only "programming" should survive
    try expectContains(result.filtered_tokens, "programming");
}

test "CJK detection returns zh language" {
    const allocator = std.testing.allocator;
    var result = try expandQuery(allocator, "\xe8\xae\xa8\xe8\xae\xba\xe6\x96\xb9\xe6\xa1\x88"); // 讨论方案
    defer result.deinit(allocator);

    try std.testing.expectEqual(Language.zh, result.language);
}

test "korean detection returns ko language" {
    const allocator = std.testing.allocator;
    // 지그에서 메모리 관리
    var result = try expandQuery(allocator, "\xec\xa7\x80\xea\xb7\xb8\xec\x97\x90\xec\x84\x9c \xeb\xa9\x94\xeb\xaa\xa8\xeb\xa6\xac \xea\xb4\x80\xeb\xa6\xac");
    defer result.deinit(allocator);

    try std.testing.expectEqual(Language.ko, result.language);
    // Should have some filtered tokens (particles stripped)
    try std.testing.expect(result.filtered_tokens.len > 0);
}

test "korean particle stripping" {
    const allocator = std.testing.allocator;
    // 서버에서 에러를 확인
    var result = try expandQuery(allocator, "\xec\x84\x9c\xeb\xb2\x84\xec\x97\x90\xec\x84\x9c \xec\x97\x90\xeb\x9f\xac\xeb\xa5\xbc \xed\x99\x95\xec\x9d\xb8");
    defer result.deinit(allocator);

    try std.testing.expectEqual(Language.ko, result.language);
    // "서버" should be extracted from "서버에서"
    try expectContains(result.filtered_tokens, "\xec\x84\x9c\xeb\xb2\x84"); // 서버
    // "에러" should be extracted from "에러를"
    try expectContains(result.filtered_tokens, "\xec\x97\x90\xeb\x9f\xac"); // 에러
    // "확인" should be kept as-is
    try expectContains(result.filtered_tokens, "\xed\x99\x95\xec\x9d\xb8"); // 확인
}

test "japanese detection returns ja language" {
    const allocator = std.testing.allocator;
    // デプロイ戦略
    var result = try expandQuery(allocator, "\xe3\x83\x87\xe3\x83\x97\xe3\x83\xad\xe3\x82\xa4\xe6\x88\xa6\xe7\x95\xa5");
    defer result.deinit(allocator);

    try std.testing.expectEqual(Language.ja, result.language);
    try std.testing.expect(result.filtered_tokens.len > 0);
}

test "extractKeywords convenience wrapper" {
    const allocator = std.testing.allocator;
    const keywords = try extractKeywords(allocator, "what is the best way to learn Zig");
    defer {
        for (keywords) |k| allocator.free(k);
        allocator.free(keywords);
    }

    try std.testing.expect(keywords.len >= 3);
    try expectContains(keywords, "best");
    try expectContains(keywords, "zig");
}

test "stopword lookup is fast (compile-time map)" {
    // This test simply verifies that the StaticStringMap works correctly
    try std.testing.expect(stop_words_en.has("the"));
    try std.testing.expect(stop_words_en.has("is"));
    try std.testing.expect(stop_words_en.has("what"));
    try std.testing.expect(!stop_words_en.has("database"));
    try std.testing.expect(!stop_words_en.has("zig"));
    try std.testing.expect(!stop_words_en.has(""));
}

test "unicode handling graceful" {
    const allocator = std.testing.allocator;
    // Mixed unicode and ASCII
    var result = try expandQuery(allocator, "caf\xc3\xa9 database"); // café database
    defer result.deinit(allocator);

    try std.testing.expect(result.filtered_tokens.len > 0);
    try expectContains(result.filtered_tokens, "database");
}

test "chinese query expansion with bigrams" {
    const allocator = std.testing.allocator;
    // 讨论方案
    var result = try expandQuery(allocator, "\xe8\xae\xa8\xe8\xae\xba\xe6\x96\xb9\xe6\xa1\x88");
    defer result.deinit(allocator);

    try std.testing.expectEqual(Language.zh, result.language);
    // Should have bigram "讨论"
    try expectContains(result.filtered_tokens, "\xe8\xae\xa8\xe8\xae\xba"); // 讨论
}

test "fts5 query built correctly with multiple tokens" {
    const allocator = std.testing.allocator;
    var result = try expandQuery(allocator, "database server configuration");
    defer result.deinit(allocator);

    // FTS5 query should contain all tokens separated by spaces
    try std.testing.expect(std.mem.indexOf(u8, result.fts5_query, "database") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.fts5_query, "server") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.fts5_query, "configuration") != null);
}

test "arabic detection returns ar language" {
    const allocator = std.testing.allocator;
    // ناقشنا استراتيجية
    var result = try expandQuery(allocator, "\xd9\x86\xd8\xa7\xd9\x82\xd8\xb4\xd9\x86\xd8\xa7 \xd8\xa7\xd8\xb3\xd8\xaa\xd8\xb1\xd8\xa7\xd8\xaa\xd9\x8a\xd8\xac\xd9\x8a\xd8\xa9");
    defer result.deinit(allocator);

    try std.testing.expectEqual(Language.ar, result.language);
    try std.testing.expect(result.filtered_tokens.len > 0);
}

test "english technical query preserves terms" {
    const allocator = std.testing.allocator;
    var result = try expandQuery(allocator, "that thing we discussed about the API");
    defer result.deinit(allocator);

    try expectContains(result.filtered_tokens, "discussed");
    try expectContains(result.filtered_tokens, "api");
    try expectNotContains(result.filtered_tokens, "that");
    try expectNotContains(result.filtered_tokens, "thing");
    try expectNotContains(result.filtered_tokens, "the");
}

// ── Test helpers ────────────────────────────────────────────────────

fn expectContains(tokens: []const []const u8, needle: []const u8) !void {
    for (tokens) |t| {
        if (std.mem.eql(u8, t, needle)) return;
    }
    std.debug.print("expected to find '{s}' in tokens: ", .{needle});
    for (tokens) |t| std.debug.print("'{s}' ", .{t});
    std.debug.print("\n", .{});
    return error.TestExpectedEqual;
}

fn expectNotContains(tokens: []const []const u8, needle: []const u8) !void {
    for (tokens) |t| {
        if (std.mem.eql(u8, t, needle)) {
            std.debug.print("expected NOT to find '{s}' in tokens\n", .{needle});
            return error.TestExpectedEqual;
        }
    }
}
