const providers = @import("providers/root.zig");

pub const OutboundStage = enum {
    chunk,
    final,
};

pub const Event = struct {
    stage: OutboundStage,
    text: []const u8 = "",
};

pub const Sink = struct {
    callback: *const fn (ctx: *anyopaque, event: Event) void,
    ctx: *anyopaque,

    pub fn emit(self: Sink, event: Event) void {
        self.callback(self.ctx, event);
    }

    pub fn emitChunk(self: Sink, text: []const u8) void {
        if (text.len == 0) return;
        self.emit(.{
            .stage = .chunk,
            .text = text,
        });
    }

    pub fn emitFinal(self: Sink) void {
        self.emit(.{ .stage = .final });
    }
};

pub fn eventFromProviderChunk(chunk: providers.StreamChunk) ?Event {
    if (chunk.is_final) return .{ .stage = .final };
    if (chunk.delta.len == 0) return null;
    return .{
        .stage = .chunk,
        .text = chunk.delta,
    };
}

pub fn forwardProviderChunk(sink: Sink, chunk: providers.StreamChunk) void {
    if (eventFromProviderChunk(chunk)) |event| {
        sink.emit(event);
    }
}

// ---------------------------------------------------------------------------
// TagFilter – state-machine that strips tool-control blocks from a stream of
// chunks before forwarding to an inner Sink.
// ---------------------------------------------------------------------------

/// What `TagFilter` does with `<think>…</think>` blocks.
pub const ThinkMode = enum {
    /// Drop the block and its tags, so reasoning never leaves the agent.
    strip,
    /// Forward the tags and the body untouched so a channel draft can render
    /// the reasoning live. Used when `reasoning_mode == .stream` and the
    /// outbound channel knows how to display it. Tool-call markup is still
    /// stripped in both modes.
    passthrough,
};

pub const TagFilter = struct {
    inner: Sink,
    think: ThinkMode = .strip,
    state: State = .passthrough,
    /// Nesting depth of the provider tool marker currently being suppressed.
    opaque_depth: u8 = 0,
    /// True when the marker being eaten is a closer (`</\u{FF5C}...`).
    opaque_closer: bool = false,
    buf: [max_buf_len]u8 = undefined,
    buf_len: u8 = 0,

    const State = enum {
        passthrough,
        maybe_open, // buffering after '<', checking if prefix matches
        skip_to_angle_close, // prefix matched, eating until '>'
        inside_tag, // inside tag body, suppressing output
        maybe_close, // buffering after '<', checking if close tag matches
        inside_think, // passthrough mode: inside <think>, body flows verbatim
        opaque_marker, // provider tool marker: eat bytes up to its closing '>'
        opaque_body, // inside a suppressed marker body
        opaque_body_maybe_open, // inside a suppressed body, buffering after '<'
    };

    // Opening tag prefixes. After matching, skip until '>'.
    // Handles canonical XML tags plus provider-specific *_begin wrappers.
    const open_prefixes = [_][]const u8{
        "<tool_call",
        "<tool_result",
        "<tool_call_begin",
        "<tool_result_begin",
        "<|tool_call_begin|",
        "<|tool_result_begin|",
        "<think",
    };

    // Closing tags (fixed match).
    const close_tags = [_][]const u8{
        "</tool_call>",
        "</tool_result>",
        "<tool_call_end>",
        "<tool_result_end>",
        "<|tool_call_end|>",
        "<|tool_result_end|>",
        "</think>",
    };

    // Used by `ThinkMode.passthrough`, which forwards the reasoning close tag
    // instead of swallowing it.
    const close_tag_think = "</think>";

    // Provider tool-protocol markers that are neither `<tool_call>` nor user
    // text. When a model falls back to its own text tool protocol the gateway
    // can surface those bytes in the content stream - DeepSeek emits
    // `<\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} calls>` /
    // `<\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} invoke ...>` - and they must
    // never reach a channel. The markers nest (`calls` wraps `invoke` wraps
    // `parameter`), so the body is suppressed until the matching closer, in
    // both think modes: it is tool markup, not reasoning and not an answer.
    const opaque_marker_prefixes = [_][]const u8{
        "<\u{FF5C}",
        "</\u{FF5C}",
    };

    // Standalone control tokens that should be stripped, but do not wrap body text.
    const standalone_tags = [_][]const u8{
        "<tool_calls_section_begin>",
        "<tool_calls_section_end>",
        "<tool_calls_section_end|>",
        "<|tool_calls_section_begin|>",
        "<|tool_calls_section_end|>",
        "<tool_call_argument_begin>",
        "<|tool_call_argument_begin|>",
    };

    fn maxLen(comptime tags: []const []const u8) comptime_int {
        var longest: usize = 0;
        for (tags) |tag| {
            if (tag.len > longest) longest = tag.len;
        }
        return longest;
    }

    const max_prefix_len = maxLen(&open_prefixes);
    const max_tag_len = maxLen(&close_tags);
    const max_standalone_len = maxLen(&standalone_tags);
    const max_buf_len = @max(@max(max_prefix_len + 1, max_tag_len), max_standalone_len);

    pub fn init(inner: Sink) TagFilter {
        return .{ .inner = inner };
    }

    /// Like `init`, but forwards `<think>` blocks to the inner sink instead of
    /// dropping them.
    pub fn initWithThinkMode(inner: Sink, think: ThinkMode) TagFilter {
        return .{ .inner = inner, .think = think };
    }

    /// Return a Sink whose callback routes through this filter.
    pub fn sink(self: *TagFilter) Sink {
        return .{
            .callback = filterCallback,
            .ctx = @ptrCast(self),
        };
    }

    fn filterCallback(ctx: *anyopaque, event: Event) void {
        const self: *TagFilter = @ptrCast(@alignCast(ctx));
        if (event.stage == .final) {
            // Flush any pending buffer as-is (incomplete tag at end of stream).
            self.flushBuf();
            self.inner.emit(event);
            return;
        }
        self.process(event.text);
    }

    fn process(self: *TagFilter, text: []const u8) void {
        var clean_start: usize = 0;
        for (text, 0..) |b, i| {
            switch (self.state) {
                .passthrough => {
                    if (b == '<') {
                        // Flush clean text accumulated so far.
                        if (i > clean_start)
                            self.inner.emitChunk(text[clean_start..i]);
                        self.buf[0] = b;
                        self.buf_len = 1;
                        self.state = .maybe_open;
                    }
                },
                .maybe_open => {
                    self.buf[self.buf_len] = b;
                    self.buf_len += 1;
                    const prefix = self.buf[0..self.buf_len];
                    if (matchesAny(prefix, &standalone_tags)) |_| {
                        self.buf_len = 0;
                        self.state = .passthrough;
                        clean_start = i + 1;
                        continue;
                    }
                    // Check if the bytes before this one match a full open prefix
                    // and this byte is a delimiter ('>' closes the tag, ' ' starts attrs).
                    if (self.buf_len > 1 and (b == '>' or b == ' ') and
                        matchesAnyPrefix(prefix[0 .. self.buf_len - 1], &open_prefixes))
                    {
                        const forward_think = self.think == .passthrough and b == '>' and
                            std.mem.eql(u8, prefix, "<think>");
                        self.buf_len = 0;
                        if (forward_think) {
                            self.inner.emitChunk("<think>");
                            self.state = .inside_think;
                        } else if (b == '>') {
                            self.state = .inside_tag;
                        } else {
                            self.state = .skip_to_angle_close;
                        }
                        clean_start = i + 1;
                        continue;
                    }
                    // Still a valid prefix of some open tag — keep buffering.
                    if (prefixOfAny(prefix, &open_prefixes) or prefixOfAny(prefix, &standalone_tags)) {
                        clean_start = i + 1;
                        continue;
                    }
                    // Provider tool marker (`<\u{FF5C}...` / `</\u{FF5C}...`): buffer
                    // the opening bytes, then eat the marker and, for an opener,
                    // suppress its body too.
                    if (prefixOfAny(prefix, &opaque_marker_prefixes)) {
                        if (matchesAnyPrefix(prefix, &opaque_marker_prefixes)) {
                            self.opaque_closer = prefix.len > 1 and prefix[1] == '/';
                            self.buf_len = 0;
                            self.state = .opaque_marker;
                        }
                        clean_start = i + 1;
                        continue;
                    }
                    // Not a prefix of any tag — flush buffer and resume passthrough.
                    self.inner.emitChunk(self.buf[0..self.buf_len]);
                    self.buf_len = 0;
                    self.state = .passthrough;
                    clean_start = i + 1;
                },
                .skip_to_angle_close => {
                    clean_start = i + 1;
                    if (b == '>') {
                        self.state = .inside_tag;
                    }
                },
                .inside_tag => {
                    clean_start = i + 1;
                    if (b == '<') {
                        self.buf[0] = b;
                        self.buf_len = 1;
                        self.state = .maybe_close;
                    }
                },
                .maybe_close => {
                    clean_start = i + 1;
                    self.buf[self.buf_len] = b;
                    self.buf_len += 1;
                    const prefix = self.buf[0..self.buf_len];
                    if (matchesAny(prefix, &close_tags)) |_| {
                        // Complete close tag matched — back to passthrough.
                        self.buf_len = 0;
                        self.state = .passthrough;
                        clean_start = i + 1;
                        continue;
                    }
                    if (!prefixOfAny(prefix, &close_tags) or self.buf_len >= max_tag_len) {
                        // Not a close tag — stay inside, discard buffer.
                        self.buf_len = 0;
                        self.state = .inside_tag;
                        continue;
                    }
                    // Still a valid prefix of a close tag — keep buffering.
                },
                .opaque_marker => {
                    // Drop the marker itself; the body is handled by the state
                    // the closing '>' selects.
                    clean_start = i + 1;
                    if (b != '>') continue;
                    if (self.opaque_closer) {
                        if (self.opaque_depth > 0) self.opaque_depth -= 1;
                    } else {
                        self.opaque_depth +|= 1;
                    }
                    self.state = if (self.opaque_depth > 0) .opaque_body else .passthrough;
                },
                .opaque_body => {
                    clean_start = i + 1;
                    if (b == '<') {
                        self.buf[0] = b;
                        self.buf_len = 1;
                        self.state = .opaque_body_maybe_open;
                    }
                },
                .opaque_body_maybe_open => {
                    clean_start = i + 1;
                    self.buf[self.buf_len] = b;
                    self.buf_len += 1;
                    const prefix = self.buf[0..self.buf_len];
                    if (matchesAnyPrefix(prefix, &opaque_marker_prefixes)) {
                        self.opaque_closer = prefix[1] == '/';
                        self.buf_len = 0;
                        self.state = .opaque_marker;
                        continue;
                    }
                    if (prefixOfAny(prefix, &opaque_marker_prefixes)) continue;
                    // Ordinary text inside the suppressed body — keep dropping.
                    self.buf_len = 0;
                    self.state = .opaque_body;
                },
                .inside_think => {
                    // Passthrough mode: the body is user-visible reasoning, so
                    // forward it verbatim. The close tag is matched against the
                    // caller's slice, which keeps the emitted bytes valid for
                    // the whole call and needs no replay buffer.
                    if (b != '<') continue;
                    if (std.mem.startsWith(u8, text[i..], close_tag_think)) {
                        if (i > clean_start) self.inner.emitChunk(text[clean_start..i]);
                        self.inner.emitChunk(close_tag_think);
                        self.state = .passthrough;
                        // Skip the rest of the tag: none of its bytes is '<'.
                        clean_start = i + close_tag_think.len;
                    } else {
                        // Not a close tag here (either ordinary '<' text or the
                        // start of one split across chunks). Emitting it as
                        // literal text yields the same bytes either way.
                        if (i > clean_start) self.inner.emitChunk(text[clean_start..i]);
                        self.inner.emitChunk(text[i .. i + 1]);
                        clean_start = i + 1;
                    }
                },
            }
        }
        // Flush remaining clean text in passthrough mode.
        if ((self.state == .passthrough or self.state == .inside_think) and clean_start < text.len)
            self.inner.emitChunk(text[clean_start..]);
    }

    fn flushBuf(self: *TagFilter) void {
        if (self.buf_len > 0 and self.state == .maybe_open) {
            // Incomplete open tag at end of stream — not a real tag, flush it.
            self.inner.emitChunk(self.buf[0..self.buf_len]);
        }
        self.buf_len = 0;
        self.opaque_depth = 0;
        self.opaque_closer = false;
        self.state = .passthrough;
    }

    /// Returns the index if `text` exactly matches any entry in `tags`.
    fn matchesAny(text: []const u8, tags: []const []const u8) ?usize {
        for (tags, 0..) |tag, i| {
            if (std.mem.eql(u8, text, tag)) return i;
        }
        return null;
    }

    /// Returns true if `text` exactly matches any entry in `prefixes`.
    fn matchesAnyPrefix(text: []const u8, prefixes: []const []const u8) bool {
        for (prefixes) |p| {
            if (std.mem.eql(u8, text, p)) return true;
        }
        return false;
    }

    /// Returns true if `text` is a valid prefix of at least one entry in `tags`.
    fn prefixOfAny(text: []const u8, tags: []const []const u8) bool {
        for (tags) |tag| {
            if (text.len <= tag.len and std.mem.eql(u8, text, tag[0..text.len]))
                return true;
        }
        return false;
    }
};

const std = @import("std");

// ---------------------------------------------------------------------------
// ThinkPassthroughFilter — replaces <think>…</think> with a visible block
// instead of stripping it. Used when reasoning_mode == .stream so that
// thinking content appears live in the CLI.
// ---------------------------------------------------------------------------

/// Header emitted in place of `<think>` tag.
pub const THINK_HEADER = "\n💭 Thinking:\n";
/// Footer emitted in place of `</think>` tag.
pub const THINK_FOOTER = "\n---\n";

pub const ThinkPassthroughFilter = struct {
    inner: Sink,
    state: State = .passthrough,
    buf: [max_buf_len]u8 = undefined,
    buf_len: usize = 0,

    const State = enum {
        passthrough, // normal text — pass through verbatim
        maybe_open, // saw '<', buffering to check for '<think>'
        inside_think, // inside <think>…</think>, pass body through
        maybe_close, // inside think, saw '<', buffering for '</think>'
    };

    const open_tag = "<think>";
    const close_tag = "</think>";
    const max_buf_len = close_tag.len + 1;

    pub fn init(inner: Sink) ThinkPassthroughFilter {
        return .{ .inner = inner };
    }

    pub fn sink(self: *ThinkPassthroughFilter) Sink {
        return .{
            .callback = filterCallback,
            .ctx = @ptrCast(self),
        };
    }

    fn filterCallback(ctx: *anyopaque, event: Event) void {
        const self: *ThinkPassthroughFilter = @ptrCast(@alignCast(ctx));
        if (event.stage == .final) {
            self.flushBuf();
            self.inner.emit(event);
            return;
        }
        self.process(event.text);
    }

    fn process(self: *ThinkPassthroughFilter, text: []const u8) void {
        var clean_start: usize = 0;
        for (text, 0..) |b, i| {
            switch (self.state) {
                .passthrough => {
                    if (b == '<') {
                        if (i > clean_start)
                            self.inner.emitChunk(text[clean_start..i]);
                        self.buf[0] = b;
                        self.buf_len = 1;
                        self.state = .maybe_open;
                    }
                },
                .maybe_open => {
                    self.buf[self.buf_len] = b;
                    self.buf_len += 1;
                    const prefix = self.buf[0..self.buf_len];
                    if (std.mem.eql(u8, prefix, open_tag)) {
                        // Matched <think> — emit header, enter think body.
                        self.buf_len = 0;
                        self.state = .inside_think;
                        self.inner.emitChunk(THINK_HEADER);
                        clean_start = i + 1;
                        continue;
                    }
                    if (std.mem.startsWith(u8, open_tag, prefix)) {
                        // Still a valid prefix of <think> — keep buffering.
                        clean_start = i + 1;
                        continue;
                    }
                    // Not a <think> prefix — flush the buffer as normal text.
                    self.inner.emitChunk(self.buf[0..self.buf_len]);
                    self.buf_len = 0;
                    self.state = .passthrough;
                    clean_start = i + 1;
                },
                .inside_think => {
                    if (b == '<') {
                        if (i > clean_start)
                            self.inner.emitChunk(text[clean_start..i]);
                        self.buf[0] = b;
                        self.buf_len = 1;
                        self.state = .maybe_close;
                        clean_start = i + 1;
                    }
                },
                .maybe_close => {
                    self.buf[self.buf_len] = b;
                    self.buf_len += 1;
                    const prefix = self.buf[0..self.buf_len];
                    if (std.mem.eql(u8, prefix, close_tag)) {
                        // Matched </think> — emit footer, return to passthrough.
                        self.buf_len = 0;
                        self.state = .passthrough;
                        self.inner.emitChunk(THINK_FOOTER);
                        clean_start = i + 1;
                        continue;
                    }
                    if (std.mem.startsWith(u8, close_tag, prefix)) {
                        // Still a valid prefix — keep buffering.
                        clean_start = i + 1;
                        continue;
                    }
                    // Not a </think> close — emit the buffer as think-body text.
                    self.inner.emitChunk(self.buf[0..self.buf_len]);
                    self.buf_len = 0;
                    self.state = .inside_think;
                    clean_start = i + 1;
                },
            }
        }
        // Flush remaining passthrough or inside_think text.
        switch (self.state) {
            .passthrough => {
                if (clean_start < text.len)
                    self.inner.emitChunk(text[clean_start..]);
            },
            .inside_think => {
                if (clean_start < text.len)
                    self.inner.emitChunk(text[clean_start..]);
            },
            else => {}, // buffering — don't flush mid-tag
        }
    }

    fn flushBuf(self: *ThinkPassthroughFilter) void {
        if (self.buf_len > 0) {
            // Incomplete tag at end of stream — emit as-is.
            self.inner.emitChunk(self.buf[0..self.buf_len]);
        }
        self.buf_len = 0;
        self.state = .passthrough;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn collectChunks(comptime max: usize) type {
    return struct {
        chunks: [max][]const u8 = undefined,
        count: usize = 0,
        got_final: bool = false,

        fn callback(ctx: *anyopaque, event: Event) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (event.stage == .final) {
                self.got_final = true;
                return;
            }
            if (self.count < max) {
                self.chunks[self.count] = event.text;
                self.count += 1;
            }
        }

        fn joined(self: *const @This(), buf: []u8) []const u8 {
            var pos: usize = 0;
            for (self.chunks[0..self.count]) |c| {
                @memcpy(buf[pos..][0..c.len], c);
                pos += c.len;
            }
            return buf[0..pos];
        }

        fn sink(self: *@This()) Sink {
            return .{ .callback = callback, .ctx = @ptrCast(self) };
        }
    };
}

test "TagFilter passthrough without tags" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("Hello ");
    s.emitChunk("world!");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Hello world!", col.joined(&buf));
    try std.testing.expect(col.got_final);
}

test "TagFilter strips think blocks by default" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("<think>private</think>Visible");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Visible", col.joined(&buf));
}

test "TagFilter think passthrough forwards reasoning to the inner sink" {
    var col = collectChunks(16){};
    var filter = TagFilter.initWithThinkMode(col.sink(), .passthrough);
    const s = filter.sink();
    s.emitChunk("<think>private</think>Visible");
    s.emitFinal();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("<think>private</think>Visible", col.joined(&buf));
}

test "TagFilter think passthrough survives a split tag" {
    var col = collectChunks(16){};
    var filter = TagFilter.initWithThinkMode(col.sink(), .passthrough);
    const s = filter.sink();
    s.emitChunk("<thi");
    s.emitChunk("nk>hi</thi");
    s.emitChunk("nk>done");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("<think>hi</think>done", col.joined(&buf));
}

test "TagFilter think passthrough keeps angle brackets inside reasoning" {
    var col = collectChunks(16){};
    var filter = TagFilter.initWithThinkMode(col.sink(), .passthrough);
    const s = filter.sink();
    s.emitChunk("<think>a < b and c > d</think>ok");
    s.emitFinal();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("<think>a < b and c > d</think>ok", col.joined(&buf));
}

test "TagFilter think passthrough still strips tool call markup" {
    var col = collectChunks(16){};
    var filter = TagFilter.initWithThinkMode(col.sink(), .passthrough);
    const s = filter.sink();
    s.emitChunk("<think>thinking</think>A<tool_call>{\"name\":\"x\"}</tool_call>B");
    s.emitFinal();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("<think>thinking</think>AB", col.joined(&buf));
}

test "TagFilter strips DeepSeek DSML tool markup" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk(
        "<\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} calls>" ++
            "<\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} invoke name=\"shell\">" ++
            "<\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} parameter name=\"command\">ls -la" ++
            "</\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} parameter>" ++
            "</\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} invoke>" ++
            "</\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} calls>Answer",
    );
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Answer", col.joined(&buf));
}

test "TagFilter strips DSML markup in think passthrough mode" {
    var col = collectChunks(16){};
    var filter = TagFilter.initWithThinkMode(col.sink(), .passthrough);
    const s = filter.sink();
    s.emitChunk(
        "<think>plan</think><\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} calls>" ++
            "<\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} invoke name=\"shell\">" ++
            "</\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} invoke>" ++
            "</\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} calls>Done",
    );
    s.emitFinal();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("<think>plan</think>Done", col.joined(&buf));
}

test "TagFilter strips a DSML marker split across chunks" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("A<\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} ca");
    s.emitChunk("lls>secret</\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} calls>B");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("AB", col.joined(&buf));
}

test "TagFilter drops a stray DSML closer but keeps the answer" {
    // Regression: a draft that only caught the tail of a marker still showed
    // the raw `</|DSML| calls>` text ahead of the answer.
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("</\u{FF5C}\u{FF5C}DSML\u{FF5C}\u{FF5C} calls>Answer");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Answer", col.joined(&buf));
}

test "TagFilter strips complete tool_call in single chunk" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("Hi <tool_call>{\"name\":\"x\",\"arguments\":{}}</tool_call> bye");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Hi  bye", col.joined(&buf));
}

test "TagFilter strips tool_result with attributes" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("A<tool_result name=\"shell\" status=\"success\">output</tool_result>B");
    s.emitFinal();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("AB", col.joined(&buf));
}

test "TagFilter strips tool_result without attributes" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("A<tool_result>output</tool_result>B");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("AB", col.joined(&buf));
}

test "TagFilter tag split across chunks" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("Hello <tool_c");
    s.emitChunk("all>{\"name\":\"x\"}</tool_call> world");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Hello  world", col.joined(&buf));
}

test "TagFilter close tag split across chunks" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("<tool_call>body</tool_");
    s.emitChunk("call>after");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("after", col.joined(&buf));
}

test "TagFilter false positive angle bracket" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("a < b > c");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("a < b > c", col.joined(&buf));
}

test "TagFilter multiple tool calls" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("A<tool_call>1</tool_call>B<tool_call>2</tool_call>C");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("ABC", col.joined(&buf));
}

test "TagFilter incomplete open tag at end flushes on final" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("end<tool_c");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("end<tool_c", col.joined(&buf));
    try std.testing.expect(col.got_final);
}

test "TagFilter strips pipe-delimited tool_call control block" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("Before <|tool_call_begin|>{\"name\":\"shell\"}<|tool_call_end|> after");
    s.emitFinal();
    var buf: [96]u8 = undefined;
    try std.testing.expectEqualStrings("Before  after", col.joined(&buf));
}

test "TagFilter strips pipe-delimited tool_result block split across chunks" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("A<|tool_result_be");
    s.emitChunk("gin|>hidden");
    s.emitChunk("<|tool_result_end|>B");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("AB", col.joined(&buf));
}

test "TagFilter strips pipe-delimited tool_calls section wrapper" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("Before <|tool_calls_section_begin|>");
    s.emitChunk("<|tool_call_begin|>{\"name\":\"shell\"}");
    s.emitChunk("<|tool_call_end|><|tool_calls_section_end|> after");
    s.emitFinal();
    var buf: [96]u8 = undefined;
    try std.testing.expectEqualStrings("Before  after", col.joined(&buf));
}

test "TagFilter strips begin-style tool_call without pipe delimiters" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("A<tool_call_begin>{\"name\":\"shell\"}</tool_call>B");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("AB", col.joined(&buf));
}

test "TagFilter strips section wrapper with mixed pipe-delimited close tag" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("A<tool_calls_section_begin>");
    s.emitChunk("<tool_call_begin> functions.shell:5<{\"command\":\"pwd\"}</tool_call>");
    s.emitChunk("<tool_calls_section_end|>B");
    s.emitFinal();
    var buf: [96]u8 = undefined;
    try std.testing.expectEqualStrings("AB", col.joined(&buf));
}

test "TagFilter strips think blocks split across chunks" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("Before <th");
    s.emitChunk("ink>private");
    s.emitChunk("</think> after");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Before  after", col.joined(&buf));
}

test "ThinkPassthroughFilter passthrough without think tags" {
    var col = collectChunks(16){};
    var filter = ThinkPassthroughFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("Hello world!");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Hello world!", col.joined(&buf));
    try std.testing.expect(col.got_final);
}

test "ThinkPassthroughFilter replaces think block with header and footer" {
    var col = collectChunks(16){};
    var filter = ThinkPassthroughFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("Before <think>reasoning here</think> after");
    s.emitFinal();
    var buf: [256]u8 = undefined;
    const expected = "Before " ++ THINK_HEADER ++ "reasoning here" ++ THINK_FOOTER ++ " after";
    try std.testing.expectEqualStrings(expected, col.joined(&buf));
}

test "ThinkPassthroughFilter think tag split across chunks" {
    var col = collectChunks(16){};
    var filter = ThinkPassthroughFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("Before <th");
    s.emitChunk("ink>private");
    s.emitChunk("</think> after");
    s.emitFinal();
    var buf: [256]u8 = undefined;
    const expected = "Before " ++ THINK_HEADER ++ "private" ++ THINK_FOOTER ++ " after";
    try std.testing.expectEqualStrings(expected, col.joined(&buf));
}

test "ThinkPassthroughFilter close tag split across chunks" {
    var col = collectChunks(16){};
    var filter = ThinkPassthroughFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("<think>body</thi");
    s.emitChunk("nk>after");
    s.emitFinal();
    var buf: [256]u8 = undefined;
    const expected = THINK_HEADER ++ "body" ++ THINK_FOOTER ++ "after";
    try std.testing.expectEqualStrings(expected, col.joined(&buf));
}

test "ThinkPassthroughFilter false positive angle bracket passes through" {
    var col = collectChunks(16){};
    var filter = ThinkPassthroughFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("a < b > c");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("a < b > c", col.joined(&buf));
}

test "ThinkPassthroughFilter emits final on stream end" {
    var col = collectChunks(16){};
    var filter = ThinkPassthroughFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("text");
    s.emitFinal();
    try std.testing.expect(col.got_final);
}
