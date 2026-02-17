const std = @import("std");

// RAG -- Retrieval-Augmented Generation for hardware datasheets.
//
// Mirrors ZeroClaw's rag module: datasheet chunk indexing,
// pin alias parsing, keyword-based retrieval.

// ── DatasheetChunk ──────────────────────────────────────────────

/// A chunk of datasheet content with board metadata.
pub const DatasheetChunk = struct {
    /// Board this chunk applies to (e.g. "nucleo-f401re"), or null for generic.
    board: ?[]const u8,
    /// Source file path.
    source: []const u8,
    /// Chunk content.
    content: []const u8,
};

// ── Pin Aliases ─────────────────────────────────────────────────

/// Pin alias: human-readable name to pin number.
pub const PinAlias = struct {
    alias: []const u8,
    pin: u32,
};

/// Parse pin aliases from markdown content.
/// Looks for a `## Pin Aliases` section with `alias: pin` lines
/// or markdown table `| alias | pin |` rows.
pub fn parsePinAliases(allocator: std.mem.Allocator, content: []const u8) ![]PinAlias {
    var aliases: std.ArrayList(PinAlias) = .empty;
    errdefer aliases.deinit(allocator);

    // Find ## Pin Aliases section (case-insensitive search)
    const lower = try std.ascii.allocLowerString(allocator, content);
    defer allocator.free(lower);

    const markers = [_][]const u8{ "## pin aliases", "## pin alias", "## pins" };
    var section_start: ?usize = null;
    for (markers) |marker| {
        if (std.mem.indexOf(u8, lower, marker)) |pos| {
            section_start = pos + marker.len;
            break;
        }
    }

    const start = section_start orelse return try aliases.toOwnedSlice(allocator);

    // Find end of section (next ## heading or EOF)
    const rest = content[start..];
    const section_end = if (std.mem.indexOf(u8, rest, "\n## ")) |i| start + i else content.len;
    const section = content[start..section_end];

    var line_iter = std.mem.splitScalar(u8, section, '\n');
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;

        // Table row: | alias | pin |
        if (line[0] == '|') {
            if (parseTableRow(line)) |alias| {
                try aliases.append(allocator, alias);
            }
            continue;
        }

        // Key: value or key = value
        if (parseKeyValue(line)) |alias| {
            try aliases.append(allocator, alias);
        }
    }

    return try aliases.toOwnedSlice(allocator);
}

fn parseTableRow(line: []const u8) ?PinAlias {
    // Split by '|' and extract cells
    var parts_iter = std.mem.splitScalar(u8, line, '|');
    _ = parts_iter.next(); // skip leading empty
    const alias_raw = parts_iter.next() orelse return null;
    const pin_raw = parts_iter.next() orelse return null;

    const alias = std.mem.trim(u8, alias_raw, " \t");
    const pin_str = std.mem.trim(u8, pin_raw, " \t");

    // Skip header and separator rows
    if (std.mem.eql(u8, alias, "alias") or std.mem.eql(u8, alias, "pin")) return null;
    if (std.mem.indexOf(u8, alias, "---") != null) return null;
    if (std.mem.indexOf(u8, pin_str, "---") != null) return null;
    if (std.mem.eql(u8, pin_str, "pin")) return null;
    if (alias.len == 0) return null;

    const pin = std.fmt.parseInt(u32, pin_str, 10) catch return null;
    return .{ .alias = alias, .pin = pin };
}

fn parseKeyValue(line: []const u8) ?PinAlias {
    // Try colon separator first, then equals
    const sep_pos = std.mem.indexOfScalar(u8, line, ':') orelse
        std.mem.indexOfScalar(u8, line, '=') orelse
        return null;

    const alias = std.mem.trim(u8, line[0..sep_pos], " \t");
    const pin_str = std.mem.trim(u8, line[sep_pos + 1 ..], " \t");

    if (alias.len == 0) return null;
    const pin = std.fmt.parseInt(u32, pin_str, 10) catch return null;
    return .{ .alias = alias, .pin = pin };
}

// ── Board inference ─────────────────────────────────────────────

/// Infer board tag from a file path. "nucleo-f401re.md" -> "nucleo-f401re".
/// Returns null for "generic" or "_generic" paths.
pub fn inferBoardFromPath(path: []const u8) ?[]const u8 {
    // Get the filename without extension
    const basename = std.fs.path.basename(path);
    const stem = if (std.mem.lastIndexOfScalar(u8, basename, '.')) |dot| basename[0..dot] else basename;

    if (stem.len == 0) return null;
    if (std.mem.eql(u8, stem, "generic")) return null;
    if (std.mem.startsWith(u8, stem, "generic_")) return null;

    // Check if parent dir is _generic
    const dir = std.fs.path.dirname(path) orelse "";
    const dir_base = std.fs.path.basename(dir);
    if (std.mem.eql(u8, dir_base, "_generic")) return null;

    return stem;
}

// ── HardwareRag ─────────────────────────────────────────────────

/// Hardware RAG index -- stores datasheet chunks and pin aliases.
pub const HardwareRag = struct {
    chunks: []DatasheetChunk,
    pin_aliases: std.StringHashMap([]PinAlias),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) HardwareRag {
        return .{
            .chunks = &.{},
            .pin_aliases = std.StringHashMap([]PinAlias).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HardwareRag) void {
        if (self.chunks.len > 0) {
            self.allocator.free(self.chunks);
        }
        var it = self.pin_aliases.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.pin_aliases.deinit();
    }

    /// Number of indexed chunks.
    pub fn len(self: *const HardwareRag) usize {
        return self.chunks.len;
    }

    /// True if no chunks are indexed.
    pub fn isEmpty(self: *const HardwareRag) bool {
        return self.chunks.len == 0;
    }

    /// Get pin aliases for a board.
    pub fn pinAliasesForBoard(self: *const HardwareRag, board: []const u8) ?[]PinAlias {
        return self.pin_aliases.get(board);
    }

    /// Retrieve chunks relevant to the query and boards.
    /// Uses keyword matching and board filter.
    pub fn retrieve(
        self: *const HardwareRag,
        allocator: std.mem.Allocator,
        query: []const u8,
        boards: []const []const u8,
        limit: usize,
    ) ![]const *const DatasheetChunk {
        if (self.chunks.len == 0 or limit == 0) return &.{};

        const query_lower = try std.ascii.allocLowerString(allocator, query);
        defer allocator.free(query_lower);

        // Tokenize query into terms (> 2 chars)
        var terms: std.ArrayList([]const u8) = .empty;
        defer terms.deinit(allocator);
        var term_iter = std.mem.splitScalar(u8, query_lower, ' ');
        while (term_iter.next()) |term| {
            if (term.len > 2) try terms.append(allocator, term);
        }

        // Score each chunk
        const ScoredChunk = struct { chunk: *const DatasheetChunk, score: f32 };
        var scored: std.ArrayList(ScoredChunk) = .empty;
        defer scored.deinit(allocator);

        for (self.chunks) |*chunk| {
            const content_lower = try std.ascii.allocLowerString(allocator, chunk.content);
            defer allocator.free(content_lower);

            var score: f32 = 0.0;
            for (terms.items) |term| {
                if (std.mem.indexOf(u8, content_lower, term) != null) {
                    score += 1.0;
                }
            }

            if (score > 0.0) {
                // Board match bonus
                if (chunk.board) |board| {
                    for (boards) |b| {
                        if (std.mem.eql(u8, board, b)) {
                            score += 2.0;
                            break;
                        }
                    }
                }
                try scored.append(allocator, .{ .chunk = chunk, .score = score });
            }
        }

        // Sort by score descending
        std.mem.sort(ScoredChunk, scored.items, {}, struct {
            fn cmp(_: void, a: ScoredChunk, b: ScoredChunk) bool {
                return a.score > b.score;
            }
        }.cmp);

        const result_count = @min(limit, scored.items.len);
        const result = try allocator.alloc(*const DatasheetChunk, result_count);
        for (0..result_count) |i| {
            result[i] = scored.items[i].chunk;
        }
        return result;
    }
};

// ── Tests ───────────────────────────────────────────────────────

test "parsePinAliases key-value format" {
    const md =
        \\## Pin Aliases
        \\red_led: 13
        \\builtin_led: 13
        \\user_led: 5
    ;
    const aliases = try parsePinAliases(std.testing.allocator, md);
    defer std.testing.allocator.free(aliases);

    try std.testing.expectEqual(@as(usize, 3), aliases.len);
    try std.testing.expectEqualStrings("red_led", aliases[0].alias);
    try std.testing.expectEqual(@as(u32, 13), aliases[0].pin);
    try std.testing.expectEqualStrings("builtin_led", aliases[1].alias);
    try std.testing.expectEqual(@as(u32, 13), aliases[1].pin);
    try std.testing.expectEqualStrings("user_led", aliases[2].alias);
    try std.testing.expectEqual(@as(u32, 5), aliases[2].pin);
}

test "parsePinAliases table format" {
    const md =
        \\## Pin Aliases
        \\| alias | pin |
        \\|-------|-----|
        \\| red_led | 13 |
        \\| builtin_led | 13 |
    ;
    const aliases = try parsePinAliases(std.testing.allocator, md);
    defer std.testing.allocator.free(aliases);

    try std.testing.expectEqual(@as(usize, 2), aliases.len);
    try std.testing.expectEqualStrings("red_led", aliases[0].alias);
    try std.testing.expectEqual(@as(u32, 13), aliases[0].pin);
}

test "parsePinAliases empty when no section" {
    const aliases = try parsePinAliases(std.testing.allocator, "No aliases here");
    defer std.testing.allocator.free(aliases);
    try std.testing.expectEqual(@as(usize, 0), aliases.len);
}

test "parsePinAliases equals separator" {
    const md =
        \\## Pin Aliases
        \\led = 13
        \\button = 2
    ;
    const aliases = try parsePinAliases(std.testing.allocator, md);
    defer std.testing.allocator.free(aliases);
    try std.testing.expectEqual(@as(usize, 2), aliases.len);
    try std.testing.expectEqualStrings("led", aliases[0].alias);
    try std.testing.expectEqual(@as(u32, 13), aliases[0].pin);
}

test "parsePinAliases ignores non-numeric values" {
    const md =
        \\## Pin Aliases
        \\name: test
        \\led: 13
    ;
    const aliases = try parsePinAliases(std.testing.allocator, md);
    defer std.testing.allocator.free(aliases);
    try std.testing.expectEqual(@as(usize, 1), aliases.len);
}

test "parsePinAliases stops at next heading" {
    const md =
        \\## Pin Aliases
        \\led: 13
        \\## GPIO
        \\something: 99
    ;
    const aliases = try parsePinAliases(std.testing.allocator, md);
    defer std.testing.allocator.free(aliases);
    try std.testing.expectEqual(@as(usize, 1), aliases.len);
}

test "inferBoardFromPath basic" {
    try std.testing.expectEqualStrings("nucleo-f401re", inferBoardFromPath("datasheets/nucleo-f401re.md").?);
}

test "inferBoardFromPath generic returns null" {
    try std.testing.expect(inferBoardFromPath("datasheets/generic.md") == null);
}

test "inferBoardFromPath generic prefix returns null" {
    try std.testing.expect(inferBoardFromPath("datasheets/generic_notes.md") == null);
}

test "inferBoardFromPath _generic dir returns null" {
    try std.testing.expect(inferBoardFromPath("datasheets/_generic/notes.md") == null);
}

test "inferBoardFromPath txt extension" {
    try std.testing.expectEqualStrings("rpi-gpio", inferBoardFromPath("ds/rpi-gpio.txt").?);
}

test "HardwareRag init and deinit" {
    var rag = HardwareRag.init(std.testing.allocator);
    defer rag.deinit();
    try std.testing.expect(rag.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), rag.len());
}

test "HardwareRag pinAliasesForBoard returns null when empty" {
    var rag = HardwareRag.init(std.testing.allocator);
    defer rag.deinit();
    try std.testing.expect(rag.pinAliasesForBoard("test") == null);
}

test "HardwareRag retrieve returns empty when no chunks" {
    var rag = HardwareRag.init(std.testing.allocator);
    defer rag.deinit();
    const results = try rag.retrieve(std.testing.allocator, "led", &.{"test-board"}, 5);
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "DatasheetChunk defaults" {
    const chunk = DatasheetChunk{
        .board = null,
        .source = "test.md",
        .content = "test content",
    };
    try std.testing.expect(chunk.board == null);
    try std.testing.expectEqualStrings("test.md", chunk.source);
}
