const std = @import("std");

const MAX_LINE_BYTES: usize = 4096;

pub const LineEditor = struct {
    buf: [MAX_LINE_BYTES]u8 = undefined,
    len: usize = 0,
    cursor_pos: usize = 0,
    draft: [MAX_LINE_BYTES]u8 = undefined,
    draft_len: usize = 0,
    history: []const []const u8,
    history_index: ?usize = null,

    pub fn init(history: []const []const u8) LineEditor {
        return .{ .history = history };
    }

    pub fn line(self: *const LineEditor) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn cursor(self: *const LineEditor) usize {
        return self.cursor_pos;
    }

    pub fn feed(self: *LineEditor, byte: u8) !void {
        switch (byte) {
            0x7f, 0x08 => self.backspace(),
            0x01 => self.cursor_pos = 0,
            0x05 => self.cursor_pos = self.len,
            '\r', '\n' => {},
            0x1b => {},
            else => try self.insertByte(byte),
        }
    }

    pub fn feedEscapeSequence(self: *LineEditor, seq: []const u8) !void {
        if (std.mem.eql(u8, seq, "\x1b[A")) {
            self.historyUp();
        } else if (std.mem.eql(u8, seq, "\x1b[B")) {
            self.historyDown();
        } else if (std.mem.eql(u8, seq, "\x1b[C")) {
            self.cursorRight();
        } else if (std.mem.eql(u8, seq, "\x1b[D")) {
            self.cursorLeft();
        } else if (std.mem.eql(u8, seq, "\x1b[H") or std.mem.eql(u8, seq, "\x1bOH") or
            std.mem.eql(u8, seq, "\x1b[1~"))
        {
            self.cursor_pos = 0;
        } else if (std.mem.eql(u8, seq, "\x1b[F") or std.mem.eql(u8, seq, "\x1bOF") or
            std.mem.eql(u8, seq, "\x1b[4~"))
        {
            self.cursor_pos = self.len;
        } else if (std.mem.eql(u8, seq, "\x1bb") or std.mem.eql(u8, seq, "\x1b[1;3D") or
            std.mem.eql(u8, seq, "\x1b[1;5D") or std.mem.eql(u8, seq, "\x1b[1;9D"))
        {
            self.wordLeft();
        } else if (std.mem.eql(u8, seq, "\x1bf") or std.mem.eql(u8, seq, "\x1b[1;3C") or
            std.mem.eql(u8, seq, "\x1b[1;5C") or std.mem.eql(u8, seq, "\x1b[1;9C"))
        {
            self.wordRight();
        } else if (std.mem.eql(u8, seq, "\x1b[3~")) {
            self.deleteForward();
        }
    }

    fn insertByte(self: *LineEditor, byte: u8) !void {
        if (self.len >= self.buf.len) return error.LineTooLong;
        if (self.cursor_pos < self.len) {
            std.mem.copyBackwards(u8, self.buf[self.cursor_pos + 1 .. self.len + 1], self.buf[self.cursor_pos..self.len]);
        }
        self.buf[self.cursor_pos] = byte;
        self.cursor_pos += 1;
        self.len += 1;
        self.history_index = null;
    }

    fn backspace(self: *LineEditor) void {
        if (self.cursor_pos == 0) return;
        std.mem.copyForwards(u8, self.buf[self.cursor_pos - 1 .. self.len - 1], self.buf[self.cursor_pos..self.len]);
        self.cursor_pos -= 1;
        self.len -= 1;
        self.history_index = null;
    }

    fn deleteForward(self: *LineEditor) void {
        if (self.cursor_pos >= self.len) return;
        std.mem.copyForwards(u8, self.buf[self.cursor_pos .. self.len - 1], self.buf[self.cursor_pos + 1 .. self.len]);
        self.len -= 1;
        self.history_index = null;
    }

    fn cursorLeft(self: *LineEditor) void {
        if (self.cursor_pos > 0) self.cursor_pos -= 1;
    }

    fn cursorRight(self: *LineEditor) void {
        if (self.cursor_pos < self.len) self.cursor_pos += 1;
    }

    fn wordLeft(self: *LineEditor) void {
        while (self.cursor_pos > 0 and isWordSeparator(self.buf[self.cursor_pos - 1])) {
            self.cursor_pos -= 1;
        }
        while (self.cursor_pos > 0 and !isWordSeparator(self.buf[self.cursor_pos - 1])) {
            self.cursor_pos -= 1;
        }
    }

    fn wordRight(self: *LineEditor) void {
        while (self.cursor_pos < self.len and !isWordSeparator(self.buf[self.cursor_pos])) {
            self.cursor_pos += 1;
        }
        while (self.cursor_pos < self.len and isWordSeparator(self.buf[self.cursor_pos])) {
            self.cursor_pos += 1;
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
        self.len = @min(text.len, self.buf.len);
        @memcpy(self.buf[0..self.len], text[0..self.len]);
        self.cursor_pos = self.len;
    }
};

fn isWordSeparator(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '/' or byte == '-' or byte == '_' or byte == '.';
}

pub fn renderLineRefresh(writer: *std.Io.Writer, prompt: []const u8, line: []const u8, cursor_pos: usize) !void {
    try writer.print("\r{s}{s}\x1b[K", .{ prompt, line });
    const cursor_from_end = line.len - @min(cursor_pos, line.len);
    if (cursor_from_end > 0) {
        try writer.print("\x1b[{d}D", .{cursor_from_end});
    }
}

test "cli line editor handles arrow-key history navigation" {
    const history = [_][]const u8{ "first prompt", "second prompt" };
    var editor = LineEditor.init(history[0..]);

    try editor.feed('n');
    try editor.feed('e');
    try editor.feed('w');
    try std.testing.expectEqualStrings("new", editor.line());

    try editor.feedEscapeSequence("\x1b[A");
    try std.testing.expectEqualStrings("second prompt", editor.line());

    try editor.feedEscapeSequence("\x1b[A");
    try std.testing.expectEqualStrings("first prompt", editor.line());

    try editor.feedEscapeSequence("\x1b[B");
    try std.testing.expectEqualStrings("second prompt", editor.line());

    try editor.feedEscapeSequence("\x1b[B");
    try std.testing.expectEqualStrings("new", editor.line());
}

test "cli line editor handles left right and insertion" {
    var editor = LineEditor.init(&.{});

    for ("helo") |byte| try editor.feed(byte);
    try editor.feedEscapeSequence("\x1b[D");
    try editor.feed('l');

    try std.testing.expectEqualStrings("hello", editor.line());
    try std.testing.expectEqual(@as(usize, 4), editor.cursor());

    try editor.feedEscapeSequence("\x1b[C");
    try std.testing.expectEqual(@as(usize, 5), editor.cursor());
}

test "cli line editor handles backspace and delete" {
    var editor = LineEditor.init(&.{});

    for ("helo") |byte| try editor.feed(byte);
    try editor.feedEscapeSequence("\x1b[D");
    try editor.feed(0x7f);
    try std.testing.expectEqualStrings("heo", editor.line());

    try editor.feedEscapeSequence("\x1b[3~");
    try std.testing.expectEqualStrings("he", editor.line());
}

test "cli line editor handles home end and word navigation" {
    var editor = LineEditor.init(&.{});

    for ("alpha beta/gamma") |byte| try editor.feed(byte);
    try editor.feed(0x01);
    try std.testing.expectEqual(@as(usize, 0), editor.cursor());

    try editor.feed(0x05);
    try std.testing.expectEqual(@as(usize, 16), editor.cursor());

    try editor.feedEscapeSequence("\x1bb");
    try std.testing.expectEqual(@as(usize, 11), editor.cursor());

    try editor.feedEscapeSequence("\x1b[1;9D");
    try std.testing.expectEqual(@as(usize, 6), editor.cursor());

    try editor.feedEscapeSequence("\x1b[H");
    try std.testing.expectEqual(@as(usize, 0), editor.cursor());

    try editor.feedEscapeSequence("\x1b[1;9C");
    try std.testing.expectEqual(@as(usize, 6), editor.cursor());

    try editor.feedEscapeSequence("\x1b[F");
    try std.testing.expectEqual(@as(usize, 16), editor.cursor());
}

test "cli line editor renders refreshed prompt and cursor position" {
    var buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);

    try renderLineRefresh(&writer, "> ", "hello", 3);

    try std.testing.expectEqualStrings("\r> hello\x1b[K\x1b[2D", writer.buffered());
}
