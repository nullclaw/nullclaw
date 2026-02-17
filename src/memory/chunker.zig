//! Line-based markdown chunker — splits documents into semantic chunks.
//!
//! Splits on markdown headings and paragraph boundaries, respecting
//! a max token limit per chunk. Preserves heading context.

const std = @import("std");

/// A single chunk of text with metadata.
pub const Chunk = struct {
    index: usize,
    content: []const u8,
    heading: ?[]const u8,
};

/// Split markdown text into chunks, each under `max_tokens` approximate tokens.
///
/// Strategy:
/// 1. Split on `## ` and `# ` headings (keeps heading with its content)
/// 2. If a section exceeds max_tokens, split on blank lines (paragraphs)
/// 3. If a paragraph still exceeds, split on line boundaries
///
/// Token estimation: ~4 chars per token (rough English average).
/// Caller owns the returned slices and must free them with freeChunks.
pub fn chunkMarkdown(allocator: std.mem.Allocator, text: []const u8, max_tokens: usize) ![]Chunk {
    const trimmed = std.mem.trim(u8, text, " \t\n\r");
    if (trimmed.len == 0) {
        return allocator.alloc(Chunk, 0);
    }

    const max_chars = if (max_tokens == 0) 0 else max_tokens * 4;

    var chunks: std.ArrayList(Chunk) = .empty;
    errdefer {
        for (chunks.items) |chunk| {
            allocator.free(chunk.content);
            if (chunk.heading) |h| allocator.free(h);
        }
        chunks.deinit(allocator);
    }

    const sections = try splitOnHeadings(allocator, text);
    defer {
        for (sections) |sec| {
            if (sec.heading) |h| allocator.free(h);
            allocator.free(sec.body);
        }
        allocator.free(sections);
    }

    for (sections) |section| {
        const full = if (section.heading) |h|
            try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ h, section.body })
        else
            try allocator.dupe(u8, section.body);

        const full_trimmed = std.mem.trim(u8, full, " \t\n\r");

        if (max_chars == 0 or full_trimmed.len <= max_chars) {
            const content = try allocator.dupe(u8, full_trimmed);
            const heading = if (section.heading) |h| try allocator.dupe(u8, h) else null;
            try chunks.append(allocator, .{
                .index = chunks.items.len,
                .content = content,
                .heading = heading,
            });
            allocator.free(full);
        } else {
            allocator.free(full);

            const paragraphs = try splitOnBlankLines(allocator, section.body);
            defer {
                for (paragraphs) |p| allocator.free(p);
                allocator.free(paragraphs);
            }

            var current: std.ArrayList(u8) = .empty;
            defer current.deinit(allocator);

            if (section.heading) |h| {
                try current.appendSlice(allocator, h);
                try current.append(allocator, '\n');
            }

            for (paragraphs) |para| {
                if (current.items.len + para.len > max_chars and std.mem.trim(u8, current.items, " \t\n\r").len > 0) {
                    const content = try allocator.dupe(u8, std.mem.trim(u8, current.items, " \t\n\r"));
                    const heading = if (section.heading) |h| try allocator.dupe(u8, h) else null;
                    try chunks.append(allocator, .{
                        .index = chunks.items.len,
                        .content = content,
                        .heading = heading,
                    });
                    current.clearRetainingCapacity();
                    if (section.heading) |h| {
                        try current.appendSlice(allocator, h);
                        try current.append(allocator, '\n');
                    }
                }

                if (para.len > max_chars) {
                    if (std.mem.trim(u8, current.items, " \t\n\r").len > 0) {
                        const content = try allocator.dupe(u8, std.mem.trim(u8, current.items, " \t\n\r"));
                        const heading = if (section.heading) |h| try allocator.dupe(u8, h) else null;
                        try chunks.append(allocator, .{
                            .index = chunks.items.len,
                            .content = content,
                            .heading = heading,
                        });
                        current.clearRetainingCapacity();
                        if (section.heading) |h| {
                            try current.appendSlice(allocator, h);
                            try current.append(allocator, '\n');
                        }
                    }

                    const line_chunks = try splitOnLines(allocator, para, max_chars);
                    defer {
                        for (line_chunks) |lc| allocator.free(lc);
                        allocator.free(line_chunks);
                    }
                    for (line_chunks) |lc| {
                        const content = try allocator.dupe(u8, std.mem.trim(u8, lc, " \t\n\r"));
                        const heading = if (section.heading) |h| try allocator.dupe(u8, h) else null;
                        try chunks.append(allocator, .{
                            .index = chunks.items.len,
                            .content = content,
                            .heading = heading,
                        });
                    }
                } else {
                    try current.appendSlice(allocator, para);
                    try current.append(allocator, '\n');
                }
            }

            if (std.mem.trim(u8, current.items, " \t\n\r").len > 0) {
                const content = try allocator.dupe(u8, std.mem.trim(u8, current.items, " \t\n\r"));
                const heading = if (section.heading) |h| try allocator.dupe(u8, h) else null;
                try chunks.append(allocator, .{
                    .index = chunks.items.len,
                    .content = content,
                    .heading = heading,
                });
            }
        }
    }

    // Filter out empty chunks
    var filtered: std.ArrayList(Chunk) = .empty;
    for (chunks.items) |chunk| {
        if (chunk.content.len > 0) {
            try filtered.append(allocator, chunk);
        } else {
            allocator.free(chunk.content);
            if (chunk.heading) |h| allocator.free(h);
        }
    }
    chunks.deinit(allocator);

    // Re-index
    for (filtered.items, 0..) |*chunk, i| {
        chunk.index = i;
    }

    return filtered.toOwnedSlice(allocator);
}

pub fn freeChunks(allocator: std.mem.Allocator, chunks_slice: []Chunk) void {
    for (chunks_slice) |chunk| {
        allocator.free(chunk.content);
        if (chunk.heading) |h| allocator.free(h);
    }
    allocator.free(chunks_slice);
}

// ── Internal helpers ───────────────────────────────────────────────

const Section = struct {
    heading: ?[]const u8,
    body: []const u8,
};

fn splitOnHeadings(allocator: std.mem.Allocator, text: []const u8) ![]Section {
    var sections: std.ArrayList(Section) = .empty;
    errdefer {
        for (sections.items) |sec| {
            if (sec.heading) |h| allocator.free(h);
            allocator.free(sec.body);
        }
        sections.deinit(allocator);
    }

    var current_heading: ?[]u8 = null;
    var current_body: std.ArrayList(u8) = .empty;
    defer current_body.deinit(allocator);

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const is_heading = std.mem.startsWith(u8, line, "# ") or
            std.mem.startsWith(u8, line, "## ") or
            std.mem.startsWith(u8, line, "### ");

        if (is_heading) {
            if (std.mem.trim(u8, current_body.items, " \t\n\r").len > 0 or current_heading != null) {
                const body = try allocator.dupe(u8, current_body.items);
                try sections.append(allocator, .{ .heading = current_heading, .body = body });
                current_heading = null;
                current_body.clearRetainingCapacity();
            } else if (current_heading) |h| {
                allocator.free(h);
            }
            current_heading = try allocator.dupe(u8, line);
        } else {
            try current_body.appendSlice(allocator, line);
            try current_body.append(allocator, '\n');
        }
    }

    if (std.mem.trim(u8, current_body.items, " \t\n\r").len > 0 or current_heading != null) {
        const body = try allocator.dupe(u8, current_body.items);
        try sections.append(allocator, .{ .heading = current_heading, .body = body });
    } else if (current_heading) |h| {
        allocator.free(h);
    }

    return sections.toOwnedSlice(allocator);
}

fn splitOnBlankLines(allocator: std.mem.Allocator, text: []const u8) ![][]u8 {
    var paragraphs: std.ArrayList([]u8) = .empty;
    errdefer {
        for (paragraphs.items) |p| allocator.free(p);
        paragraphs.deinit(allocator);
    }

    var current: std.ArrayList(u8) = .empty;
    defer current.deinit(allocator);

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const line_trimmed = std.mem.trim(u8, line, " \t\r");
        if (line_trimmed.len == 0) {
            if (std.mem.trim(u8, current.items, " \t\n\r").len > 0) {
                try paragraphs.append(allocator, try allocator.dupe(u8, current.items));
                current.clearRetainingCapacity();
            }
        } else {
            try current.appendSlice(allocator, line);
            try current.append(allocator, '\n');
        }
    }

    if (std.mem.trim(u8, current.items, " \t\n\r").len > 0) {
        try paragraphs.append(allocator, try allocator.dupe(u8, current.items));
    }

    return paragraphs.toOwnedSlice(allocator);
}

fn splitOnLines(allocator: std.mem.Allocator, text: []const u8, max_chars: usize) ![][]u8 {
    var result: std.ArrayList([]u8) = .empty;
    errdefer {
        for (result.items) |item| allocator.free(item);
        result.deinit(allocator);
    }

    var current: std.ArrayList(u8) = .empty;
    defer current.deinit(allocator);

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (max_chars > 0 and current.items.len + line.len + 1 > max_chars and current.items.len > 0) {
            try result.append(allocator, try allocator.dupe(u8, current.items));
            current.clearRetainingCapacity();
        }
        try current.appendSlice(allocator, line);
        try current.append(allocator, '\n');
    }

    if (current.items.len > 0) {
        try result.append(allocator, try allocator.dupe(u8, current.items));
    }

    return result.toOwnedSlice(allocator);
}

// ── Tests ──────────────────────────────────────────────────────────

test "empty text" {
    const chunks_slice = try chunkMarkdown(std.testing.allocator, "", 512);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expectEqual(@as(usize, 0), chunks_slice.len);
}

test "whitespace only" {
    const chunks_slice = try chunkMarkdown(std.testing.allocator, "   \n\n\n  ", 512);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expectEqual(@as(usize, 0), chunks_slice.len);
}

test "single short paragraph" {
    const chunks_slice = try chunkMarkdown(std.testing.allocator, "Hello world", 512);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expectEqual(@as(usize, 1), chunks_slice.len);
    try std.testing.expectEqualStrings("Hello world", chunks_slice[0].content);
    try std.testing.expect(chunks_slice[0].heading == null);
}

test "heading sections" {
    const text = "# Title\nSome intro.\n\n## Section A\nContent A.\n\n## Section B\nContent B.";
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text, 512);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expect(chunks_slice.len >= 3);
}

test "indexes are sequential" {
    const text = "# A\nContent A\n\n# B\nContent B\n\n# C\nContent C";
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text, 512);
    defer freeChunks(std.testing.allocator, chunks_slice);
    for (chunks_slice, 0..) |chunk, i| {
        try std.testing.expectEqual(i, chunk.index);
    }
}

test "single heading no content" {
    const text = "# Just a heading";
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text, 512);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expectEqual(@as(usize, 1), chunks_slice.len);
    try std.testing.expect(chunks_slice[0].heading != null);
    try std.testing.expectEqualStrings("# Just a heading", chunks_slice[0].heading.?);
}

test "max tokens zero does not crash" {
    const chunks_slice = try chunkMarkdown(std.testing.allocator, "Hello world", 0);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expect(chunks_slice.len > 0);
}

test "respects max tokens" {
    var text_builder: std.ArrayList(u8) = .empty;
    defer text_builder.deinit(std.testing.allocator);

    for (0..200) |i| {
        const line = try std.fmt.allocPrint(std.testing.allocator, "This is sentence number {d} with extra words.\n", .{i});
        defer std.testing.allocator.free(line);
        try text_builder.appendSlice(std.testing.allocator, line);
    }

    const chunks_slice = try chunkMarkdown(std.testing.allocator, text_builder.items, 50);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expect(chunks_slice.len > 1);
}

test "no content loss" {
    const text = "# A\nContent A line 1\nContent A line 2\n\n## B\nContent B\n\n## C\nContent C";
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text, 512);
    defer freeChunks(std.testing.allocator, chunks_slice);

    var all_content: std.ArrayList(u8) = .empty;
    defer all_content.deinit(std.testing.allocator);
    for (chunks_slice) |chunk| {
        try all_content.appendSlice(std.testing.allocator, chunk.content);
        try all_content.append(std.testing.allocator, ' ');
    }

    const words = [_][]const u8{ "Content", "line", "1", "2" };
    for (words) |word| {
        try std.testing.expect(std.mem.indexOf(u8, all_content.items, word) != null);
    }
}

test "headings only no body" {
    const text = "# Title\n## Section A\n## Section B\n### Subsection";
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text, 512);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expect(chunks_slice.len > 0);
}

test "deeply nested headings stay with parent" {
    // #### and deeper are NOT treated as heading splits
    const text = "# Top\nIntro\n#### Deep heading\nDeep content";
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text, 512);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expect(chunks_slice.len > 0);
    var all_content: std.ArrayList(u8) = .empty;
    defer all_content.deinit(std.testing.allocator);
    for (chunks_slice) |chunk| {
        try all_content.appendSlice(std.testing.allocator, chunk.content);
    }
    try std.testing.expect(std.mem.indexOf(u8, all_content.items, "Deep heading") != null);
    try std.testing.expect(std.mem.indexOf(u8, all_content.items, "Deep content") != null);
}

test "very long single line no newlines" {
    // One giant line with no newlines
    var text_builder: std.ArrayList(u8) = .empty;
    defer text_builder.deinit(std.testing.allocator);
    for (0..5000) |_| {
        try text_builder.appendSlice(std.testing.allocator, "word ");
    }
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text_builder.items, 50);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expect(chunks_slice.len > 0);
}

test "max tokens one aggressive splitting" {
    const text = "Line one\nLine two\nLine three";
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text, 1);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expect(chunks_slice.len > 0);
}

test "unicode content preserved" {
    const text = "# \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\n\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf\xe4\xb8\x96\xe7\x95\x8c\n\n## Emojis\nZig is great";
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text, 512);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expect(chunks_slice.len > 0);
    var all_content: std.ArrayList(u8) = .empty;
    defer all_content.deinit(std.testing.allocator);
    for (chunks_slice) |chunk| {
        try all_content.appendSlice(std.testing.allocator, chunk.content);
    }
    try std.testing.expect(std.mem.indexOf(u8, all_content.items, "\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf") != null);
}

test "fts5 special chars in content" {
    const text = "Content with \"quotes\" and (parentheses) and * asterisks *";
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text, 512);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expectEqual(@as(usize, 1), chunks_slice.len);
    try std.testing.expect(std.mem.indexOf(u8, chunks_slice[0].content, "\"quotes\"") != null);
}

test "multiple blank lines between paragraphs" {
    const text = "Paragraph one.\n\n\n\n\nParagraph two.\n\n\n\nParagraph three.";
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text, 512);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expectEqual(@as(usize, 1), chunks_slice.len);
    try std.testing.expect(std.mem.indexOf(u8, chunks_slice[0].content, "Paragraph one") != null);
    try std.testing.expect(std.mem.indexOf(u8, chunks_slice[0].content, "Paragraph three") != null);
}

test "heading at end of text" {
    const text = "Some content\n# Trailing Heading";
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text, 512);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expect(chunks_slice.len > 0);
}

test "preserves heading in split sections" {
    var text_builder: std.ArrayList(u8) = .empty;
    defer text_builder.deinit(std.testing.allocator);
    try text_builder.appendSlice(std.testing.allocator, "## Big Section\n");
    for (0..100) |i| {
        const line = try std.fmt.allocPrint(std.testing.allocator, "Line {d} with some content here.\n\n", .{i});
        defer std.testing.allocator.free(line);
        try text_builder.appendSlice(std.testing.allocator, line);
    }
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text_builder.items, 50);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expect(chunks_slice.len > 1);
    for (chunks_slice) |chunk| {
        if (chunk.heading) |h| {
            try std.testing.expectEqualStrings("## Big Section", h);
        }
    }
}

test "chunk count reasonable for small doc" {
    const text = "Hello world. This is a test document.";
    const chunks_slice = try chunkMarkdown(std.testing.allocator, text, 512);
    defer freeChunks(std.testing.allocator, chunks_slice);
    try std.testing.expectEqual(@as(usize, 1), chunks_slice.len);
}
