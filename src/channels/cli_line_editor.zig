const std = @import("std");

pub const MAX_LINE_BYTES: usize = 4096;
const MAX_ESCAPE_BYTES: usize = 8;

pub const FeedResult = enum {
    unchanged,
    pending,
    changed,
    full,
};

pub const LineEditor = struct {
    buf: [MAX_LINE_BYTES]u8 = undefined,
    len: usize = 0,
    cursor_pos: usize = 0,
    draft: [MAX_LINE_BYTES]u8 = undefined,
    draft_len: usize = 0,
    history: []const []const u8,
    history_index: ?usize = null,
    escape_buf: [MAX_ESCAPE_BYTES]u8 = undefined,
    escape_len: usize = 0,
    utf8_buf: [4]u8 = undefined,
    utf8_len: usize = 0,
    utf8_expected: usize = 0,
    overflowed: bool = false,

    pub fn init(history: []const []const u8) LineEditor {
        return .{ .history = history };
    }

    pub fn line(self: *const LineEditor) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn cursor(self: *const LineEditor) usize {
        return self.cursor_pos;
    }

    pub fn hasPendingEscape(self: *const LineEditor) bool {
        return self.escape_len > 0;
    }

    pub fn cancelPendingEscape(self: *LineEditor) void {
        self.escape_len = 0;
    }

    pub fn cancelPendingInput(self: *LineEditor) void {
        self.escape_len = 0;
        self.utf8_len = 0;
        self.utf8_expected = 0;
    }

    pub fn hasOverflowed(self: *const LineEditor) bool {
        return self.overflowed;
    }

    /// Consume one byte from the terminal without performing nested reads.
    /// Escape sequences and UTF-8 scalars are accumulated until complete so
    /// callers only redraw after an atomic edit.
    pub fn feedInput(self: *LineEditor, byte: u8) FeedResult {
        if (self.utf8_len > 0) return self.feedUtf8Byte(byte);
        if (self.escape_len > 0) return self.feedEscapeByte(byte);

        if (byte == 0x1b) {
            self.escape_buf[0] = byte;
            self.escape_len = 1;
            return .pending;
        }

        if (byte >= 0x80) {
            const expected: usize = std.unicode.utf8ByteSequenceLength(byte) catch return .unchanged;
            if (expected <= 1 or expected > self.utf8_buf.len) return .unchanged;
            self.utf8_buf[0] = byte;
            self.utf8_len = 1;
            self.utf8_expected = expected;
            return .pending;
        }

        return self.feedPlainByte(byte);
    }

    fn feedPlainByte(self: *LineEditor, byte: u8) FeedResult {
        switch (byte) {
            0x7f, 0x08 => return if (self.backspace()) .changed else .unchanged,
            0x01 => return if (self.moveHome()) .changed else .unchanged,
            0x05 => return if (self.moveEnd()) .changed else .unchanged,
            0x04 => return if (self.deleteForward()) .changed else .unchanged,
            0x15 => return if (self.clearLine()) .changed else .unchanged,
            0x17 => return if (self.deletePreviousWord()) .changed else .unchanged,
            0x09 => {
                var scalar = [1]u8{byte};
                return self.insertSlice(&scalar);
            },
            0x00, 0x02...0x03, 0x06...0x07, 0x0a...0x14, 0x16, 0x18...0x1f => return .unchanged,
            else => {
                var scalar = [1]u8{byte};
                return self.insertSlice(&scalar);
            },
        }
    }

    fn feedUtf8Byte(self: *LineEditor, byte: u8) FeedResult {
        if (!isUtf8Continuation(byte)) {
            self.utf8_len = 0;
            self.utf8_expected = 0;
            return self.feedInput(byte);
        }

        if (self.utf8_len >= self.utf8_buf.len) {
            self.utf8_len = 0;
            self.utf8_expected = 0;
            return .unchanged;
        }

        self.utf8_buf[self.utf8_len] = byte;
        self.utf8_len += 1;
        if (self.utf8_len < self.utf8_expected) return .pending;

        const scalar = self.utf8_buf[0..self.utf8_len];
        self.utf8_len = 0;
        self.utf8_expected = 0;
        _ = std.unicode.utf8Decode(scalar) catch return .unchanged;
        return self.insertSlice(scalar);
    }

    fn feedEscapeByte(self: *LineEditor, byte: u8) FeedResult {
        if (self.escape_len == 1) {
            if (byte != '[' and byte != 'O' and byte != 'b' and byte != 'f') {
                self.escape_len = 0;
                return self.feedInput(byte);
            }
        }

        if (self.escape_len >= self.escape_buf.len) {
            self.escape_len = 0;
            return .unchanged;
        }
        self.escape_buf[self.escape_len] = byte;
        self.escape_len += 1;

        const complete = (self.escape_len == 2 and (byte == 'b' or byte == 'f')) or
            (self.escape_len >= 3 and isEscapeTerminator(byte));
        if (complete) {
            const sequence = self.escape_buf[0..self.escape_len];
            self.escape_len = 0;
            return self.feedEscapeSequence(sequence);
        }
        if (self.escape_len == self.escape_buf.len) {
            self.escape_len = 0;
            return .unchanged;
        }
        return .pending;
    }

    pub fn feedEscapeSequence(self: *LineEditor, seq: []const u8) FeedResult {
        if (std.mem.eql(u8, seq, "\x1b[A")) {
            self.historyUp();
        } else if (std.mem.eql(u8, seq, "\x1b[B")) {
            self.historyDown();
        } else if (std.mem.eql(u8, seq, "\x1b[C") or std.mem.eql(u8, seq, "\x1bOC")) {
            _ = self.cursorRight();
        } else if (std.mem.eql(u8, seq, "\x1b[D") or std.mem.eql(u8, seq, "\x1bOD")) {
            _ = self.cursorLeft();
        } else if (std.mem.eql(u8, seq, "\x1bOA")) {
            self.historyUp();
        } else if (std.mem.eql(u8, seq, "\x1bOB")) {
            self.historyDown();
        } else if (std.mem.eql(u8, seq, "\x1b[H") or std.mem.eql(u8, seq, "\x1bOH") or
            std.mem.eql(u8, seq, "\x1b[1~"))
        {
            _ = self.moveHome();
        } else if (std.mem.eql(u8, seq, "\x1b[F") or std.mem.eql(u8, seq, "\x1bOF") or
            std.mem.eql(u8, seq, "\x1b[4~"))
        {
            _ = self.moveEnd();
        } else if (std.mem.eql(u8, seq, "\x1bb") or std.mem.eql(u8, seq, "\x1b[1;3D") or
            std.mem.eql(u8, seq, "\x1b[1;5D") or std.mem.eql(u8, seq, "\x1b[1;9D"))
        {
            self.wordLeft();
        } else if (std.mem.eql(u8, seq, "\x1bf") or std.mem.eql(u8, seq, "\x1b[1;3C") or
            std.mem.eql(u8, seq, "\x1b[1;5C") or std.mem.eql(u8, seq, "\x1b[1;9C"))
        {
            self.wordRight();
        } else if (std.mem.eql(u8, seq, "\x1b[3~")) {
            _ = self.deleteForward();
        } else {
            return .unchanged;
        }
        return .changed;
    }

    fn insertSlice(self: *LineEditor, bytes: []const u8) FeedResult {
        if (bytes.len == 0) return .unchanged;
        if (bytes.len > self.buf.len - self.len) {
            self.overflowed = true;
            return .full;
        }
        if (self.cursor_pos < self.len) {
            std.mem.copyBackwards(
                u8,
                self.buf[self.cursor_pos + bytes.len .. self.len + bytes.len],
                self.buf[self.cursor_pos..self.len],
            );
        }
        @memcpy(self.buf[self.cursor_pos .. self.cursor_pos + bytes.len], bytes);
        self.cursor_pos += bytes.len;
        self.len += bytes.len;
        self.history_index = null;
        self.overflowed = false;
        return .changed;
    }

    fn backspace(self: *LineEditor) bool {
        if (self.cursor_pos == 0) return false;
        const start = previousCodepointStart(self.buf[0..self.len], self.cursor_pos);
        const removed = self.cursor_pos - start;
        std.mem.copyForwards(u8, self.buf[start .. self.len - removed], self.buf[self.cursor_pos..self.len]);
        self.cursor_pos = start;
        self.len -= removed;
        self.history_index = null;
        self.overflowed = false;
        return true;
    }

    fn deleteForward(self: *LineEditor) bool {
        if (self.cursor_pos >= self.len) return false;
        const end = nextCodepointEnd(self.buf[0..self.len], self.cursor_pos);
        const removed = end - self.cursor_pos;
        std.mem.copyForwards(u8, self.buf[self.cursor_pos .. self.len - removed], self.buf[end..self.len]);
        self.len -= removed;
        self.history_index = null;
        self.overflowed = false;
        return true;
    }

    fn clearLine(self: *LineEditor) bool {
        if (self.len == 0) return false;
        self.len = 0;
        self.cursor_pos = 0;
        self.history_index = null;
        self.overflowed = false;
        return true;
    }

    fn deletePreviousWord(self: *LineEditor) bool {
        if (self.cursor_pos == 0) return false;

        var start = self.cursor_pos;
        while (start > 0) {
            const previous = previousCodepointStart(self.buf[0..self.len], start);
            if (!isWordSeparator(self.buf[previous])) break;
            start = previous;
        }
        while (start > 0) {
            const previous = previousCodepointStart(self.buf[0..self.len], start);
            if (isWordSeparator(self.buf[previous])) break;
            start = previous;
        }

        const removed = self.cursor_pos - start;
        std.mem.copyForwards(u8, self.buf[start .. self.len - removed], self.buf[self.cursor_pos..self.len]);
        self.cursor_pos = start;
        self.len -= removed;
        self.history_index = null;
        self.overflowed = false;
        return true;
    }

    fn cursorLeft(self: *LineEditor) bool {
        if (self.cursor_pos == 0) return false;
        self.cursor_pos = previousCodepointStart(self.buf[0..self.len], self.cursor_pos);
        return true;
    }

    fn cursorRight(self: *LineEditor) bool {
        if (self.cursor_pos >= self.len) return false;
        self.cursor_pos = nextCodepointEnd(self.buf[0..self.len], self.cursor_pos);
        return true;
    }

    fn moveHome(self: *LineEditor) bool {
        if (self.cursor_pos == 0) return false;
        self.cursor_pos = 0;
        return true;
    }

    fn moveEnd(self: *LineEditor) bool {
        if (self.cursor_pos == self.len) return false;
        self.cursor_pos = self.len;
        return true;
    }

    fn wordLeft(self: *LineEditor) void {
        while (self.cursor_pos > 0) {
            const previous = previousCodepointStart(self.buf[0..self.len], self.cursor_pos);
            if (!isWordSeparator(self.buf[previous])) break;
            self.cursor_pos = previous;
        }
        while (self.cursor_pos > 0) {
            const previous = previousCodepointStart(self.buf[0..self.len], self.cursor_pos);
            if (isWordSeparator(self.buf[previous])) break;
            self.cursor_pos = previous;
        }
    }

    fn wordRight(self: *LineEditor) void {
        while (self.cursor_pos < self.len and !isWordSeparator(self.buf[self.cursor_pos])) {
            self.cursor_pos = nextCodepointEnd(self.buf[0..self.len], self.cursor_pos);
        }
        while (self.cursor_pos < self.len and isWordSeparator(self.buf[self.cursor_pos])) {
            self.cursor_pos = nextCodepointEnd(self.buf[0..self.len], self.cursor_pos);
        }
    }

    fn historyUp(self: *LineEditor) void {
        if (self.history.len == 0) return;
        if (self.history_index == null) {
            self.draft_len = @min(self.len, self.draft.len);
            @memcpy(self.draft[0..self.draft_len], self.buf[0..self.draft_len]);
            self.history_index = self.history.len - 1;
        } else if (self.history_index.? > 0) {
            self.history_index.? -= 1;
        }
        self.replaceLine(self.history[self.history_index.?]);
    }

    fn historyDown(self: *LineEditor) void {
        const index = self.history_index orelse return;
        if (index + 1 < self.history.len) {
            self.history_index = index + 1;
            self.replaceLine(self.history[self.history_index.?]);
            return;
        }
        self.history_index = null;
        self.replaceLine(self.draft[0..self.draft_len]);
    }

    fn replaceLine(self: *LineEditor, text: []const u8) void {
        self.len = 0;
        self.cursor_pos = 0;
        self.cancelPendingInput();
        self.overflowed = false;

        var index: usize = 0;
        while (index < text.len) {
            const byte = text[index];
            if (byte < 0x80) {
                index += 1;
                if ((byte < 0x20 and byte != '\t') or byte == 0x7f) continue;
                if (!self.appendHistoryScalar(text[index - 1 .. index])) break;
                continue;
            }

            const scalar_len: usize = std.unicode.utf8ByteSequenceLength(byte) catch {
                index += 1;
                continue;
            };
            if (index + scalar_len > text.len) break;
            const scalar = text[index .. index + scalar_len];
            _ = std.unicode.utf8Decode(scalar) catch {
                index += 1;
                continue;
            };
            if (!self.appendHistoryScalar(scalar)) break;
            index += scalar_len;
        }
        self.cursor_pos = self.len;
    }

    fn appendHistoryScalar(self: *LineEditor, scalar: []const u8) bool {
        if (scalar.len > self.buf.len - self.len) {
            self.overflowed = true;
            return false;
        }
        @memcpy(self.buf[self.len .. self.len + scalar.len], scalar);
        self.len += scalar.len;
        return true;
    }
};

fn isUtf8Continuation(byte: u8) bool {
    return byte & 0xc0 == 0x80;
}

fn previousCodepointStart(text: []const u8, cursor: usize) usize {
    if (cursor == 0) return 0;
    var start = cursor - 1;
    while (start > 0 and isUtf8Continuation(text[start])) start -= 1;
    const scalar_len: usize = std.unicode.utf8ByteSequenceLength(text[start]) catch return cursor - 1;
    if (start + scalar_len != cursor) return cursor - 1;
    _ = std.unicode.utf8Decode(text[start..cursor]) catch return cursor - 1;
    return start;
}

fn nextCodepointEnd(text: []const u8, cursor: usize) usize {
    if (cursor >= text.len) return text.len;
    const scalar_len: usize = std.unicode.utf8ByteSequenceLength(text[cursor]) catch return cursor + 1;
    const end = cursor + scalar_len;
    if (end > text.len) return cursor + 1;
    _ = std.unicode.utf8Decode(text[cursor..end]) catch return cursor + 1;
    return end;
}

fn isEscapeTerminator(byte: u8) bool {
    return (byte >= 'A' and byte <= 'Z') or
        (byte >= 'a' and byte <= 'z') or
        byte == '~';
}

fn isWordSeparator(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '/' or byte == '-' or byte == '_' or byte == '.';
}

/// Draw the prompt on a clean physical row. Line refreshes use a horizontal
/// viewport so neither the prompt nor later edits depend on saved cursor rows.
pub fn renderPrompt(writer: *std.Io.Writer, prompt: []const u8) !void {
    try writer.print("\r\x1b[2K{s}", .{prompt});
}

pub fn renderLineRefresh(
    writer: *std.Io.Writer,
    prompt: []const u8,
    line: []const u8,
    cursor_pos: usize,
    terminal_columns: usize,
) !void {
    const cursor = cursorBoundary(line, cursor_pos);
    const prompt_width = displayWidth(prompt);
    // Leave one physical column unused. Some terminals defer wrapping until
    // the next printable byte, while others wrap immediately in the last cell.
    const usable_columns = terminal_columns -| 1;
    const content_columns = usable_columns -| prompt_width;
    const viewport = lineViewport(line, cursor, content_columns);

    try writer.print("\r\x1b[2K{s}{s}", .{ prompt, line[viewport.start..viewport.end] });
    if (cursor < viewport.end) {
        // Replaying the visible prefix lets the terminal place wide and
        // combining Unicode scalars without relying on byte counts.
        try writer.print("\r{s}{s}", .{ prompt, line[viewport.start..cursor] });
    }
}

const LineViewport = struct {
    start: usize,
    end: usize,
};

fn lineViewport(line: []const u8, cursor: usize, max_columns: usize) LineViewport {
    var viewport: LineViewport = .{ .start = cursor, .end = cursor };
    var used_columns: usize = 0;

    // Keep the scalar under the cursor visible before spending the remaining
    // space on the prefix. This makes forward-delete behavior unambiguous.
    if (cursor < line.len) {
        const next = nextCodepointEnd(line, cursor);
        const width = scalarDisplayWidth(line[cursor..next]);
        if (width <= max_columns) {
            viewport.end = next;
            used_columns = width;
        }
    }

    while (viewport.start > 0) {
        const previous = previousCodepointStart(line, viewport.start);
        const width = scalarDisplayWidth(line[previous..viewport.start]);
        if (width > max_columns -| used_columns) break;
        viewport.start = previous;
        used_columns += width;
    }

    while (viewport.end < line.len) {
        const next = nextCodepointEnd(line, viewport.end);
        const width = scalarDisplayWidth(line[viewport.end..next]);
        if (width > max_columns -| used_columns) break;
        viewport.end = next;
        used_columns += width;
    }
    return viewport;
}

fn displayWidth(text: []const u8) usize {
    var width: usize = 0;
    var index: usize = 0;
    while (index < text.len) {
        const scalar_len: usize = std.unicode.utf8ByteSequenceLength(text[index]) catch 1;
        const end = @min(index + scalar_len, text.len);
        width += scalarDisplayWidth(text[index..end]);
        index = end;
    }
    return width;
}

fn scalarDisplayWidth(scalar: []const u8) usize {
    if (scalar.len == 0) return 0;
    // The real tab advance depends on the terminal's current column. Eight is
    // its maximum on conventional tab stops and keeps the viewport conservative.
    if (scalar.len == 1 and scalar[0] == '\t') return 8;
    if (scalar[0] < 0x20 or scalar[0] == 0x7f) return 0;
    // Printable ASCII occupies one cell. Treat every non-ASCII scalar as two
    // cells: conservative for combining characters, correct for common CJK
    // and emoji, and therefore safe against accidental terminal wrapping.
    return if (scalar.len == 1) 1 else 2;
}

fn cursorBoundary(line: []const u8, requested: usize) usize {
    var cursor = @min(requested, line.len);
    while (cursor > 0 and cursor < line.len and isUtf8Continuation(line[cursor])) {
        cursor -= 1;
    }
    return cursor;
}

fn feedText(editor: *LineEditor, text: []const u8) void {
    for (text) |byte| _ = editor.feedInput(byte);
}

fn feedTerminalSequence(editor: *LineEditor, sequence: []const u8) void {
    for (sequence) |byte| _ = editor.feedInput(byte);
}

test "cli line editor handles arrow-key history navigation" {
    // Regression: #865 — arrows must navigate history instead of becoming text.
    const history = [_][]const u8{ "first prompt", "second prompt" };
    var editor = LineEditor.init(history[0..]);

    feedText(&editor, "new");
    try std.testing.expectEqualStrings("new", editor.line());

    feedTerminalSequence(&editor, "\x1b[A");
    try std.testing.expectEqualStrings("second prompt", editor.line());

    feedTerminalSequence(&editor, "\x1bOA");
    try std.testing.expectEqualStrings("first prompt", editor.line());

    feedTerminalSequence(&editor, "\x1b[B");
    try std.testing.expectEqualStrings("second prompt", editor.line());

    feedTerminalSequence(&editor, "\x1bOB");
    try std.testing.expectEqualStrings("new", editor.line());
}

test "cli line editor handles left right and insertion" {
    var editor = LineEditor.init(&.{});

    feedText(&editor, "helo");
    _ = editor.feedEscapeSequence("\x1b[D");
    _ = editor.feedInput('l');

    try std.testing.expectEqualStrings("hello", editor.line());
    try std.testing.expectEqual(@as(usize, 4), editor.cursor());

    _ = editor.feedEscapeSequence("\x1bOC");
    try std.testing.expectEqual(@as(usize, 5), editor.cursor());
}

test "cli line editor handles backspace and delete" {
    var editor = LineEditor.init(&.{});

    feedText(&editor, "helo");
    _ = editor.feedEscapeSequence("\x1b[D");
    _ = editor.feedInput(0x7f);
    try std.testing.expectEqualStrings("heo", editor.line());

    _ = editor.feedEscapeSequence("\x1b[3~");
    try std.testing.expectEqualStrings("he", editor.line());
}

test "cli line editor handles home end and word navigation" {
    var editor = LineEditor.init(&.{});

    feedText(&editor, "alpha beta/gamma");
    _ = editor.feedInput(0x01);
    try std.testing.expectEqual(@as(usize, 0), editor.cursor());

    _ = editor.feedInput(0x05);
    try std.testing.expectEqual(@as(usize, 16), editor.cursor());

    _ = editor.feedEscapeSequence("\x1bb");
    try std.testing.expectEqual(@as(usize, 11), editor.cursor());

    _ = editor.feedEscapeSequence("\x1b[1;9D");
    try std.testing.expectEqual(@as(usize, 6), editor.cursor());

    _ = editor.feedEscapeSequence("\x1b[H");
    try std.testing.expectEqual(@as(usize, 0), editor.cursor());

    _ = editor.feedEscapeSequence("\x1b[1;9C");
    try std.testing.expectEqual(@as(usize, 6), editor.cursor());

    _ = editor.feedEscapeSequence("\x1b[F");
    try std.testing.expectEqual(@as(usize, 16), editor.cursor());
}

test "cli line editor parses escape sequences incrementally" {
    // Regression: #865 — a standalone Escape must not block or consume the next key.
    var editor = LineEditor.init(&.{});
    try std.testing.expectEqual(FeedResult.pending, editor.feedInput(0x1b));
    try std.testing.expect(editor.hasPendingEscape());
    editor.cancelPendingEscape();
    try std.testing.expectEqual(FeedResult.changed, editor.feedInput('x'));
    try std.testing.expectEqualStrings("x", editor.line());

    try std.testing.expectEqual(FeedResult.pending, editor.feedInput(0x1b));
    try std.testing.expectEqual(FeedResult.changed, editor.feedInput('y'));
    try std.testing.expectEqualStrings("xy", editor.line());
}

test "cli line editor inserts and edits complete UTF-8 scalars" {
    // Regression: byte-wise cursor movement corrupted Cyrillic, CJK, and emoji input.
    var editor = LineEditor.init(&.{});
    const e_acute = "é";
    try std.testing.expectEqual(FeedResult.pending, editor.feedInput(e_acute[0]));
    try std.testing.expectEqualStrings("", editor.line());
    try std.testing.expectEqual(FeedResult.changed, editor.feedInput(e_acute[1]));

    feedText(&editor, "中🙂b");
    try std.testing.expect(std.unicode.utf8ValidateSlice(editor.line()));
    _ = editor.feedEscapeSequence("\x1b[D");
    _ = editor.feedEscapeSequence("\x1b[D");
    feedText(&editor, "X");
    try std.testing.expectEqualStrings("é中X🙂b", editor.line());

    _ = editor.feedInput(0x7f);
    _ = editor.feedInput(0x7f);
    try std.testing.expectEqualStrings("é🙂b", editor.line());
    try std.testing.expect(std.unicode.utf8ValidateSlice(editor.line()));

    _ = editor.feedInput(0x04);
    try std.testing.expectEqualStrings("éb", editor.line());
    try std.testing.expect(std.unicode.utf8ValidateSlice(editor.line()));
}

test "cli line editor ignores unbound control bytes" {
    var editor = LineEditor.init(&.{});
    feedText(&editor, "safe");
    const unbound_controls = [_]u8{ 0x00, 0x02, 0x06, 0x07, 0x0b, 0x0c, 0x0e, 0x13, 0x1a, 0x1c, 0x1f };
    for (unbound_controls) |byte| {
        try std.testing.expectEqual(FeedResult.unchanged, editor.feedInput(byte));
    }
    try std.testing.expectEqualStrings("safe", editor.line());
}

test "cli line editor preserves tabs in input and recalled history" {
    const history = [_][]const u8{"history\tvalue"};
    var editor = LineEditor.init(&history);

    feedText(&editor, "input\tvalue");
    try std.testing.expectEqualStrings("input\tvalue", editor.line());
    _ = editor.feedEscapeSequence("\x1b[A");
    try std.testing.expectEqualStrings("history\tvalue", editor.line());
}

test "cli line editor restores canonical kill bindings" {
    var editor = LineEditor.init(&.{});
    feedText(&editor, "alpha beta  ");

    try std.testing.expectEqual(FeedResult.changed, editor.feedInput(0x17));
    try std.testing.expectEqualStrings("alpha ", editor.line());
    try std.testing.expectEqual(FeedResult.changed, editor.feedInput(0x15));
    try std.testing.expectEqualStrings("", editor.line());
}

test "cli line editor reports capacity without corrupting the line" {
    var editor = LineEditor.init(&.{});
    for (0..MAX_LINE_BYTES) |_| {
        try std.testing.expectEqual(FeedResult.changed, editor.feedInput('a'));
    }
    try std.testing.expectEqual(FeedResult.full, editor.feedInput('b'));
    try std.testing.expect(editor.hasOverflowed());
    try std.testing.expectEqual(@as(usize, MAX_LINE_BYTES), editor.line().len);

    // Regression: correcting an oversized paste must make the line valid again.
    try std.testing.expectEqual(FeedResult.changed, editor.feedInput(0x7f));
    try std.testing.expect(!editor.hasOverflowed());
    try std.testing.expectEqual(FeedResult.changed, editor.feedInput('c'));
    try std.testing.expectEqual(@as(usize, MAX_LINE_BYTES), editor.line().len);
}

test "cli line editor truncates long history at a UTF-8 boundary" {
    var long_history: [MAX_LINE_BYTES + 1]u8 = undefined;
    @memset(long_history[0 .. MAX_LINE_BYTES - 1], 'a');
    @memcpy(long_history[MAX_LINE_BYTES - 1 ..], "é");
    const history = [_][]const u8{&long_history};
    var editor = LineEditor.init(&history);

    _ = editor.feedEscapeSequence("\x1b[A");
    try std.testing.expect(editor.hasOverflowed());
    try std.testing.expectEqual(@as(usize, MAX_LINE_BYTES - 1), editor.line().len);
    try std.testing.expect(std.unicode.utf8ValidateSlice(editor.line()));
}

test "cli line editor keeps long and UTF-8 input in one-row viewport" {
    var buf: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);

    try renderPrompt(&writer, "> ");
    try renderLineRefresh(&writer, "> ", "abcdef", 3, 8);
    try renderLineRefresh(&writer, "> ", "a中b🙂c", "a中".len, 8);

    try std.testing.expectEqualStrings(
        "\r\x1b[2K> \r\x1b[2K> abcde\r> abc\r\x1b[2K> a中b\r> a中",
        writer.buffered(),
    );
}
