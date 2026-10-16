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
//
// One filter serves every user-visible surface (CLI, Telegram, Slack, Max,
// A2A, ...). It tracks the current *region* – the normal answer text vs. a
// streamed `<think>` reasoning block – and strips tool-call markup (the tags
// AND the JSON/argument body between them) in both regions. Reasoning text
// itself is still forwarded when the caller asked for render, so the live
// thinking keeps streaming.
// ---------------------------------------------------------------------------

/// What `TagFilter` does with `<think>…</think>` blocks.
pub const ThinkMode = enum {
    /// Drop the block and its tags, so reasoning never leaves the agent.
    strip,
    /// Replace the tags with a visible header/footer instead of the raw
    /// `<think>`/`</think>` bytes, so the reasoning streams live. Used by the
    /// CLI, which prints reasoning live with `THINK_HEADER`/`THINK_FOOTER`.
    /// Tool-call markup is stripped in both regions.
    render,
};

/// Header emitted in place of the `<think>` tag in `.render` mode.
pub const THINK_HEADER = "\n💭 Thinking:\n";
/// Footer emitted in place of the `</think>` tag in `.render` mode.
pub const THINK_FOOTER = "\n---\n";

/// Size of the inline buffer for a suppressed tool-call body (the open tag plus
/// its body). The body is kept so an *unterminated* block can be released and a
/// call the dispatcher would execute can be recognised at end of stream; the
/// close tag is scanned for independently of it, so a close that arrives always
/// ends the block however far into the body it is. A body past this size spills
/// to a heap buffer (`body_heap`) so a large text tool call is still recognised
/// — a fixed cap used to release it verbatim, leaking the very call the
/// dispatcher executes.
const tool_body_max = 16384;

/// Safety cap on a spilled block body. Past it the extra bytes are dropped and
/// the block is released verbatim at end of stream, rather than growing without
/// bound on a malformed stream.
const tool_body_hard_max = 1 << 20;

/// What `TagFilter` does with an *orphan* reasoning closer: a `</think>`-family
/// tag (plain, namespaced or pipe) that has no opener, which a reasoning
/// gateway leaks into the content stream.
pub const OrphanThinkCloser = enum {
    /// Forward the tag. A channel draft presenter re-renders a snapshot of the
    /// bytes it received (`quoteThinkBlocks`), so it needs the closer to drop
    /// the leaked reasoning draft that precedes it.
    release,
    /// Drop the tag. An append-only sink (the CLI's stdout, an A2A SSE stream)
    /// has no way to retract the draft, so showing the raw `</ifm|think>` would
    /// only leak the tag itself.
    suppress,
};

pub const TagFilter = struct {
    inner: Sink = undefined,
    think: ThinkMode = .strip,
    /// How an orphan reasoning closer is handled (see `OrphanThinkCloser`).
    orphan_think_closer: OrphanThinkCloser = .release,
    /// Which region of the turn the next byte belongs to.
    region: Region = .text,
    state: State = .normal,
    /// Open tag plus body of the tool block currently being suppressed, kept so
    /// an unterminated block can be released and a dispatcher-executable call
    /// recognised at end of stream. Small blocks live in this inline buffer; a
    /// body past `tool_body_max` spills to `body_heap` (see `appendBodyByte`).
    body: [tool_body_max]u8 = undefined,
    body_len: usize = 0,
    body_heap: ?std.ArrayListUnmanaged(u8) = null,
    /// True when the current tool block opened inside a reasoning region, so a
    /// `</think>` is allowed to end it (and the reasoning region).
    tool_in_think: bool = false,
    /// True when the open tag was one of the exact markers the dispatcher
    /// recognises (`<tool_call>`, `[tool_call]`, `[TOOL_CALL]`). Only such a
    /// block ends on a mismatched/any-case close tag, matching `parseXmlToolCalls`.
    dispatcher_block: bool = false,
    /// True when the block uses the bracket dialect, so its close delimiter is `]`.
    dispatcher_bracket: bool = false,
    /// Offset into `body` where the fallback close tag being scanned began.
    close_start: usize = 0,
    buf: [max_buf_len]u8 = undefined,
    buf_len: u8 = 0,
    allocator: std.mem.Allocator = std.heap.page_allocator,

    const Region = enum { text, think };

    const State = enum {
        normal, // forwarding the current region's bytes
        lt, // saw '<', buffering to classify the tag
        tool_body, // suppressing a tool block body
        tool_lt, // saw '<' in a tool body, buffering for a close tag
        tool_close_scan, // scanning a dispatcher fallback close tag to its delimiter
        close_tag, // eating a close tag's attributes up to '>'
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
        "[tool_call",
        "[TOOL_CALL",
        "<think",
        // OpenAI/Anthropic-style text tool markup. A model that falls back to
        // this dialect can degenerate into a loop of `</function>` closers that
        // must never reach a channel (OpenClaw's `TOOL_CALL_TAG_NAMES`).
        "<function",
        "<function_calls",
        "<tool_calls",
        "<invoke",
        "<parameter",
    };

    // Closing tag *names*, without the trailing delimiter. A close is matched
    // exactly like an open: the name must match and the next byte must be `>`
    // or whitespace, so a model that drops the `>` (`</tool_call >`) still
    // closes the block instead of leaking the whole call verbatim. The bracket
    // dialect the dispatcher's XML fallback accepts is matched with its `]`
    // delimiter (see `delimiterOk`).
    const close_names = [_][]const u8{
        "</tool_call",
        "</tool_result",
        "<tool_call_end",
        "<tool_result_end",
        "<|tool_call_end|",
        "<|tool_result_end|",
        "[/tool_call",
        "[/TOOL_CALL",
        "</function",
        "</function_calls",
        "</tool_calls",
        "</invoke",
        "</parameter",
    };

    // Name only — `isCloseTag` treats the trailing `>`/whitespace as delimiter.
    const think_close_names = [_][]const u8{"</think"};

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

    // The same tokens as *names* (no trailing delimiter). Like close tags a
    // standalone token is matched as name + `>`/whitespace, so a model that
    // drops the `>` (`<tool_calls_section_begin >`) still has the token
    // stripped instead of leaked verbatim.
    const standalone_names = [_][]const u8{
        "<tool_calls_section_begin",
        "<tool_calls_section_end",
        "<tool_calls_section_end|",
        "<|tool_calls_section_begin|",
        "<|tool_calls_section_end|",
        "<tool_call_argument_begin",
        "<|tool_call_argument_begin|",
    };

    fn maxLen(comptime tags: []const []const u8) comptime_int {
        var longest: usize = 0;
        for (tags) |tag| {
            if (tag.len > longest) longest = tag.len;
        }
        return longest;
    }

    const max_open_len = maxLen(&open_prefixes);
    const max_close_len = maxLen(&close_names) + 1; // name plus its delimiter
    const max_standalone_len = maxLen(&standalone_tags);
    // A namespaced reasoning tag (`</ifm|think>`) can be longer than any fixed
    // tool tag, and the `.lt` buffer must hold one whole tag plus the byte that
    // completes it before `scanThinkTag` can classify it.
    const max_think_len = providers.helpers.max_think_tag_len;
    const max_buf_len = @max(
        max_think_len + 1,
        @max(@max(max_open_len + 1, max_close_len), max_standalone_len),
    ) + 1;

    pub fn init(inner: Sink) TagFilter {
        return .{ .inner = inner };
    }

    /// Like `init`, but selects how `<think>` blocks are handled.
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

    pub fn deinit(self: *TagFilter) void {
        self.resetBody();
    }

    fn filterCallback(ctx: *anyopaque, event: Event) void {
        const self: *TagFilter = @ptrCast(@alignCast(ctx));
        if (event.stage == .final) {
            self.flushBuf();
            self.inner.emit(event);
            return;
        }
        self.process(event.text);
    }

    /// Emit `bytes` only when the current region is user-visible.
    fn emitRegion(self: *TagFilter, bytes: []const u8) void {
        if (bytes.len == 0) return;
        if (self.region == .think and self.think == .strip) return;
        self.inner.emitChunk(bytes);
    }

    fn emitThinkOpen(self: *TagFilter) void {
        switch (self.think) {
            .strip => {},
            .render => self.inner.emitChunk(THINK_HEADER),
        }
    }

    fn emitThinkClose(self: *TagFilter) void {
        switch (self.think) {
            .strip => {},
            .render => self.inner.emitChunk(THINK_FOOTER),
        }
    }

    fn process(self: *TagFilter, text: []const u8) void {
        var clean_start: usize = 0;
        for (text, 0..) |b, i| {
            switch (self.state) {
                .normal => {
                    if (b != '<' and b != '[') continue;
                    // Flush the visible run accumulated so far.
                    self.emitRegion(text[clean_start..i]);
                    self.buf[0] = b;
                    self.buf_len = 1;
                    self.state = .lt;
                    clean_start = i + 1;
                },
                .lt => {
                    self.buf[self.buf_len] = b;
                    self.buf_len += 1;
                    const prefix = self.buf[0..self.buf_len];
                    clean_start = i + 1;

                    // A reasoning closer inside a reasoning region closes it:
                    // the literal `</think` (delimiter `>` or whitespace) or a
                    // namespaced / pipe variant like `</ifm|think>`.
                    if (self.region == .think and isThinkCloseTag(prefix)) {
                        self.buf_len = 0;
                        self.region = .text;
                        self.emitThinkClose();
                        self.state = if (isTerminator(b)) .normal else .close_tag;
                        continue;
                    }
                    // Standalone control tokens never wrap body text. Matched
                    // like close tags (name + `>`/whitespace) so a model that
                    // drops the `>` still has the token stripped.
                    if (isStandaloneTag(prefix)) {
                        self.buf_len = 0;
                        self.state = if (isTerminator(b)) .normal else .close_tag;
                        continue;
                    }
                    // A reasoning tag: plain (`<thinking>`) or the namespaced /
                    // pipe variants a gateway leaks for a non-OpenAI reasoning
                    // model (`<ifm|think>`, `<|think|>`). An opener enters the
                    // reasoning region; a closer ends it. An *orphan* closer (no
                    // opener) is released verbatim by default: a channel draft
                    // presenter re-renders a snapshot of the bytes it received
                    // (`quoteThinkBlocks`) and uses the closer as the boundary
                    // that drops the leaked draft before it. An append-only sink
                    // (`.suppress`) has no way to retract the draft, so it drops
                    // the tag instead of showing it.
                    switch (providers.helpers.scanThinkTag(prefix)) {
                        .partial => continue,
                        .complete => |tag| {
                            if (!tag.close) {
                                if (self.region == .text) {
                                    self.buf_len = 0;
                                    self.region = .think;
                                    self.state = .normal;
                                    self.emitThinkOpen();
                                } else {
                                    // Nested opener inside reasoning is literal.
                                    self.emitRegion(prefix);
                                    self.buf_len = 0;
                                    self.state = .normal;
                                }
                                continue;
                            }
                            // An orphan closer (the reasoning-region closer was
                            // handled above). Release or suppress it.
                            if (self.orphan_think_closer == .suppress) {
                                self.buf_len = 0;
                                self.state = if (isTerminator(b)) .normal else .close_tag;
                                continue;
                            }
                        },
                        .none => {},
                    }
                    // Block open: the tag name matched and this byte (`>` or any
                    // whitespace) delimits it. A whitespace delimiter means the
                    // model omitted the `>` before the body, so the body starts
                    // right here; any attributes are part of the suppressed body
                    // and cost nothing.
                    if (self.buf_len > 1 and delimiterOk(prefix[0 .. self.buf_len - 1], b) and
                        matchesAnyPrefix(prefix[0 .. self.buf_len - 1], &open_prefixes))
                    {
                        // `<think` is only a reasoning opener with the `>`
                        // delimiter (handled above by `scanThinkTag`); with a
                        // whitespace delimiter it is a word in a sentence and
                        // must not open a region. (matches `scanThinkTag`)
                        if (std.mem.eql(u8, prefix[0 .. self.buf_len - 1], "<think")) {
                            self.emitRegion(prefix);
                            self.buf_len = 0;
                            self.state = .normal;
                        } else {
                            // Buffer the whole open tag so an unterminated block
                            // can be released, then suppress the body.
                            self.resetBody();
                            self.close_start = 0;
                            self.tool_in_think = self.region == .think;
                            self.dispatcher_block = std.mem.eql(u8, prefix, "<tool_call>") or
                                std.mem.eql(u8, prefix, "[tool_call]") or
                                std.mem.eql(u8, prefix, "[TOOL_CALL]");
                            self.dispatcher_bracket = prefix.len > 0 and prefix[0] == '[';
                            self.appendBody(prefix);
                            self.buf_len = 0;
                            self.state = .tool_body;
                        }
                        continue;
                    }
                    // A stray block close tag is tool markup, not text. A
                    // whitespace delimiter means the `>` is still coming, so eat
                    // the rest of the tag.
                    if (isCloseTag(prefix, &close_names)) {
                        self.buf_len = 0;
                        self.state = if (isTerminator(b)) .normal else .close_tag;
                        continue;
                    }
                    // Still a valid prefix of some tag — keep buffering.
                    if (prefixOfAny(prefix, &open_prefixes) or
                        prefixOfAny(prefix, &standalone_tags) or
                        prefixOfAny(prefix, &close_names) or
                        (self.region == .think and prefixOfAny(prefix, &think_close_names)))
                    {
                        continue;
                    }
                    // The buffered bytes cannot continue any known tag. If what
                    // we held before this byte was a complete tag *name* and
                    // this byte opens a new token, that name was an
                    // unterminated tag (the model dropped its `>`): drop the
                    // partial token and reprocess this `<` so a following
                    // `</think>` or opener is still recognised.
                    if ((b == '<' or b == '[') and self.isTagName(prefix[0 .. self.buf_len - 1])) {
                        self.reprocessLt(b);
                        continue;
                    }
                    // Otherwise it is ordinary text — flush it.
                    self.emitRegion(self.buf[0..self.buf_len]);
                    self.buf_len = 0;
                    self.state = .normal;
                },
                .tool_body => {
                    clean_start = i + 1;
                    if (b == '<' or b == '[') {
                        self.buf[0] = b;
                        self.buf_len = 1;
                        self.appendBodyByte(b);
                        self.state = .tool_lt;
                    } else {
                        self.appendBodyByte(b);
                        // A block whose close tag never arrives must not swallow
                        // the answer, but a body is *not* ruled out by a
                        // paragraph break or by size: multi-line tool arguments
                        // (a command or script) are common and a close tag that
                        // arrives ends the block however far in it is. Keep
                        // buffering (overflow is dropped past the cap) until the
                        // close tag; an opener that never closes is released at
                        // end of stream unless the dispatcher would execute it.
                    }
                },
                .tool_lt => {
                    clean_start = i + 1;
                    self.buf[self.buf_len] = b;
                    self.buf_len += 1;
                    self.appendBodyByte(b);
                    const prefix = self.buf[0..self.buf_len];

                    // A reasoning closer - the literal `</think>` or a
                    // namespaced / pipe variant like `</ifm|think>` - always
                    // ends a block that opened inside the reasoning region, and
                    // ends the region itself.
                    if (self.tool_in_think and isThinkCloseTag(prefix)) {
                        self.resetBody();
                        self.buf_len = 0;
                        self.region = .text;
                        self.emitThinkClose();
                        self.state = if (isTerminator(b)) .normal else .close_tag;
                        continue;
                    }
                    if (isCloseTag(prefix, &close_names)) {
                        // A real close tag ends the block. A block the
                        // dispatcher would execute (or whose payload could be a
                        // call at all) is hidden; a block whose payload is prose
                        // that merely *names* the markers is released verbatim,
                        // so the answer is not swallowed. The decision is the
                        // shared `hidesDispatcherBlock`, the same predicate the
                        // batch scanner uses.
                        if (self.dispatcher_block and !self.tool_in_think and
                            !providers.helpers.hidesDispatcherBlock(self.allocator, self.bodyBytes()))
                        {
                            self.emitRegion(self.bodyBytes());
                        }
                        self.resetBody();
                        self.buf_len = 0;
                        self.state = if (isTerminator(b)) .normal else .close_tag;
                        continue;
                    }
                    const still_close = prefixOfAny(prefix, &close_names) or
                        (self.tool_in_think and isThinkTagPrefix(prefix));
                    if (!still_close or self.buf_len >= max_close_len) {
                        // A dispatcher-opened block also ends on a close tag of
                        // *any* name (the dispatcher's fallback close), so scan
                        // the rest of this tag and decide at its delimiter.
                        const close_open: u8 = if (self.dispatcher_bracket) '[' else '<';
                        if (self.dispatcher_block and self.buf_len >= 2 and
                            self.buf[0] == close_open and self.buf[1] == '/')
                        {
                            self.close_start = self.body_len - self.buf_len;
                            self.buf_len = 0;
                            self.state = .tool_close_scan;
                            continue;
                        }
                        // The bytes we buffered cannot start a close tag, but
                        // this byte might: restart the candidate. Without this a
                        // stray `<` in the body (e.g. `…<` immediately before
                        // `</think>`) ate the close tag's own `<` and swallowed
                        // the reasoning terminator.
                        if (b == '<' or b == '[') {
                            self.buf[0] = b;
                            self.buf_len = 1;
                            continue;
                        }
                        self.buf_len = 0;
                        self.state = .tool_body;
                        continue;
                    }
                },
                .tool_close_scan => {
                    clean_start = i + 1;
                    self.appendBodyByte(b);
                    const open_ch: u8 = if (self.dispatcher_bracket) '[' else '<';
                    const close_ch: u8 = if (self.dispatcher_bracket) ']' else '>';
                    if (b == open_ch) {
                        // The close tag never got its delimiter: re-seed the
                        // candidate at this byte and keep scanning for a close
                        // (or `</think>`), exactly like `.tool_lt` does.
                        self.buf[0] = b;
                        self.buf_len = 1;
                        self.state = .tool_lt;
                        continue;
                    }
                    if (b != close_ch) continue;
                    // The tag is complete. A close whose name contains
                    // "tool_call" (any case) ends the block here, exactly like
                    // parseXmlToolCalls' strict close. Any other close is only a
                    // *fallback* close: the dispatcher may pick a later one, so
                    // the block stays open and the shared parse decides at end
                    // of stream (see flushBuf).
                    if (providers.helpers.containsIgnoreCase(self.closeTagContent(), "tool_call")) {
                        self.resetBody();
                        self.buf_len = 0;
                        self.state = .normal;
                        continue;
                    }
                    self.state = .tool_body;
                },
                .close_tag => {
                    clean_start = i + 1;
                    // A `<` (or `[`) before the closing delimiter means the
                    // close/standalone token was unterminated: drop it and
                    // reprocess the token from the current region's normal
                    // state, so a following `</think>`, opener or text is
                    // handled correctly.
                    if (b == '<' or b == '[') {
                        // A close tag that ends a dispatcher block opened in the
                        // answer region runs to its `>` delimiter: the
                        // dispatcher scans the whole tag, so a `<` inside it
                        // (e.g. `</tool_call </think>`) is part of the tag, not
                        // a new token. A block opened inside reasoning instead
                        // ends at `</think>`, so its `<` is still reprocessed.
                        if (self.dispatcher_block and !self.tool_in_think) continue;
                        self.reprocessLt(b);
                        continue;
                    }
                    if (isTerminator(b)) self.state = .normal;
                },
            }
        }
        // Flush the trailing visible run.
        if (self.state == .normal) self.emitRegion(text[clean_start..]);
    }

    fn flushBuf(self: *TagFilter) void {
        if (self.state == .lt) {
            // An unterminated tag token at end of stream. A complete tag *name*
            // is dropped; a partial prefix was never a tag, so flush it.
            if (self.buf_len > 0 and !self.isTagName(self.buf[0..self.buf_len])) {
                self.emitRegion(self.buf[0..self.buf_len]);
            }
        } else if (self.state == .tool_body or self.state == .tool_lt or self.state == .tool_close_scan) {
            // Unterminated tool block at end of stream. A block opened by an
            // exact dispatcher marker is decided by the one shared parse: the
            // text it returns is exactly what the agent would show, so a call it
            // executes never reaches a user-visible surface and a prose opener
            // is still released. Any other opener (attributes, a `_begin`
            // wrapper) is not a dispatcher marker, so it is ordinary text.
            const body = self.bodyBytes();
            if (self.dispatcher_block) {
                if (providers.parseDispatcherXmlToolCalls(self.allocator, body)) |result| {
                    defer {
                        self.allocator.free(result.text);
                        for (result.calls) |call| {
                            self.allocator.free(call.name);
                            self.allocator.free(call.arguments_json);
                        }
                        self.allocator.free(result.calls);
                        self.allocator.free(result.blocks);
                    }
                    // Only when the parse actually found a call is the markup
                    // hidden; otherwise the opener was prose and the whole
                    // buffered block is released, so the answer is not lost.
                    if (result.calls.len > 0) {
                        self.emitRegion(result.text);
                    } else {
                        self.emitRegion(body);
                    }
                } else |_| {
                    self.emitRegion(body);
                }
            } else {
                self.emitRegion(body);
            }
        }
        self.buf_len = 0;
        self.resetBody();
        self.tool_in_think = false;
        self.dispatcher_block = false;
        self.dispatcher_bracket = false;
        self.close_start = 0;
        self.state = .normal;
        self.region = .text;
    }

    fn appendBodyByte(self: *TagFilter, b: u8) void {
        if (self.body_heap) |*heap| {
            // Past the safety cap the extra bytes are dropped (the block is
            // released verbatim at end of stream).
            if (heap.items.len >= tool_body_hard_max) return;
            heap.append(self.allocator, b) catch {};
            return;
        }
        if (self.body_len < tool_body_max) {
            self.body[self.body_len] = b;
            self.body_len += 1;
            return;
        }
        // Spill the inline bytes to the heap and keep growing there, so a text
        // tool call larger than the inline window is still fully recognised.
        var heap: std.ArrayListUnmanaged(u8) = .empty;
        heap.appendSlice(self.allocator, self.body[0..self.body_len]) catch return;
        heap.append(self.allocator, b) catch {
            heap.deinit(self.allocator);
            return;
        };
        self.body_heap = heap;
        self.body_len += 1;
    }

    fn appendBody(self: *TagFilter, bytes: []const u8) void {
        for (bytes) |b| self.appendBodyByte(b);
    }

    /// The buffered block body, inline or spilled.
    fn bodyBytes(self: *const TagFilter) []const u8 {
        if (self.body_heap) |heap| return heap.items;
        return self.body[0..self.body_len];
    }

    /// Drop the buffered block body, freeing any spilled buffer.
    fn resetBody(self: *TagFilter) void {
        if (self.body_heap) |*heap| {
            heap.deinit(self.allocator);
            self.body_heap = null;
        }
        self.body_len = 0;
    }

    /// The name bytes of the fallback close tag just completed, between its
    /// `</` (or `[/`) and its delimiter, clamped to the buffered body.
    fn closeTagContent(self: *const TagFilter) []const u8 {
        const body = self.bodyBytes();
        const start = self.close_start + 2;
        const end = if (body.len > 0) body.len - 1 else 0;
        if (start >= end) return "";
        return body[start..end];
    }

    fn isWhitespace(b: u8) bool {
        return b == ' ' or b == '\t' or b == '\n' or b == '\r' or b == 0x0b or b == 0x0c;
    }

    /// True when `b` may delimit a tag whose name is `name`. Angle tags (`<…`)
    /// are delimited by `>` or whitespace (a model may drop the `>`); the
    /// bracket dialect (`[tool_call]`, which the dispatcher's XML fallback also
    /// accepts) requires its `]`.
    fn delimiterOk(name: []const u8, b: u8) bool {
        if (name.len > 0 and name[0] == '[') return b == ']';
        return b == '>' or isWhitespace(b);
    }

    /// True when `b` ends a tag token (`>` or the bracket dialect's `]`).
    fn isTerminator(b: u8) bool {
        return b == '>' or b == ']';
    }

    /// Begin a fresh tag token at the byte just consumed (`<`), classified from
    /// the current region's normal state. Used when the tag token being
    /// consumed turns out to be unterminated — a `<` arrives before its `>`.
    fn reprocessLt(self: *TagFilter, b: u8) void {
        self.buf[0] = b;
        self.buf_len = 1;
        self.state = .lt;
    }

    /// True when `text` is a complete tag *name* — it only lacks its `>`
    /// delimiter. Tells an unterminated tag token (dropped) from a partial
    /// prefix that was never a tag (emitted as ordinary text).
    fn isTagName(self: *const TagFilter, text: []const u8) bool {
        if (matchesAnyPrefix(text, &open_prefixes)) return true;
        if (matchesAnyPrefix(text, &close_names)) return true;
        if (matchesAnyPrefix(text, &standalone_names)) return true;
        if (self.region == .think and matchesAnyPrefix(text, &think_close_names)) return true;
        return false;
    }

    /// True when `prefix` is a complete reasoning *close* tag: the literal
    /// `</think>` (or its whitespace-delimited form) or a namespaced / pipe
    /// variant such as `</ifm|think>` or `</|thinking|>`. Used where a block or
    /// marker that opened inside a reasoning region must end on that region's
    /// closer, however the gateway spelled it.
    fn isThinkCloseTag(prefix: []const u8) bool {
        if (isCloseTag(prefix, &think_close_names)) return true;
        return switch (providers.helpers.scanThinkTag(prefix)) {
            .complete => |tag| tag.close,
            else => false,
        };
    }

    /// True when `prefix` could still grow into a reasoning tag (opener or
    /// closer) - a partial `<ifm|think` run, say - so a buffering caller keeps
    /// it instead of treating the bytes as body text.
    fn isThinkTagPrefix(prefix: []const u8) bool {
        if (prefixOfAny(prefix, &think_close_names)) return true;
        return switch (providers.helpers.scanThinkTag(prefix)) {
            .partial => true,
            else => false,
        };
    }

    /// True when `prefix` is a complete close tag: a close *name* (last byte
    /// excluded) followed by `>` or any whitespace. Mirrors how opens are
    /// matched, so a model that omits the `>` (`</tool_call >`) still closes.
    fn isCloseTag(prefix: []const u8, names: []const []const u8) bool {
        if (prefix.len < 2) return false;
        const name = prefix[0 .. prefix.len - 1];
        if (!delimiterOk(name, prefix[prefix.len - 1])) return false;
        return matchesAnyPrefix(name, names);
    }

    /// True when `prefix` is a standalone control token: a token *name* (last
    /// byte excluded) followed by `>` or any whitespace. Mirrors `isCloseTag`,
    /// so `<tool_calls_section_begin >` is stripped like the exact form.
    fn isStandaloneTag(prefix: []const u8) bool {
        if (prefix.len < 2) return false;
        const name = prefix[0 .. prefix.len - 1];
        if (!delimiterOk(name, prefix[prefix.len - 1])) return false;
        return matchesAnyPrefix(name, &standalone_names);
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
// ThinkPassthroughFilter — thin compatibility wrapper around `TagFilter`'s
// `.render` mode. Kept for the CLI, which prints reasoning live with a
// header/footer. Tool-call markup (including markup inside the reasoning) is
// stripped by the shared `TagFilter`.
// ---------------------------------------------------------------------------

pub const ThinkPassthroughFilter = struct {
    filter: TagFilter = .{},

    pub fn init(inner: Sink) ThinkPassthroughFilter {
        return .{ .filter = TagFilter.initWithThinkMode(inner, .render) };
    }

    pub fn sink(self: *ThinkPassthroughFilter) Sink {
        return self.filter.sink();
    }

    pub fn deinit(self: *ThinkPassthroughFilter) void {
        self.filter.deinit();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn collectChunks(comptime max: usize) type {
    return struct {
        // The filter emits slices of its own reuse buffer, so the collector must
        // copy each chunk before the next one overwrites it.
        storage: [max * 256]u8 = undefined,
        storage_len: usize = 0,
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
                const start = self.storage_len;
                @memcpy(self.storage[start..][0..event.text.len], event.text);
                self.storage_len += event.text.len;
                self.chunks[self.count] = self.storage[start..self.storage_len];
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

test "TagFilter treats a namespaced think opener and closer as a reasoning region" {
    // Regression: only the plain `<think>` spelling was recognised, so a
    // namespaced reasoning region streamed to the user verbatim.
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("<ifm|think>private</ifm|think>Visible");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Visible", col.joined(&buf));
}

test "TagFilter recognizes a namespaced think tag split across chunks" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("<ifm|thi");
    s.emitChunk("nk>private</ifm|think>Visible");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Visible", col.joined(&buf));
}

test "TagFilter releases an orphan namespaced think closer for the batch scanner" {
    // No opener (the gateway swallowed it), so the draft before the closer is
    // reasoning. The filter must not swallow the closer: the batch scanner
    // (`scanThinkContent`) uses it as the boundary that drops the draft.
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("Draft answer.</ifm|think>Real answer.");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Draft answer.</ifm|think>Real answer.", col.joined(&buf));
}

test "TagFilter suppresses an orphan think closer for an append-only sink" {
    // The CLI prints chunks straight to a terminal and can never retract the
    // leaked draft, so the tag itself must not reach the user.
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    filter.orphan_think_closer = .suppress;
    const s = filter.sink();
    s.emitChunk("Draft answer.</ifm|think>Real answer.");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Draft answer.Real answer.", col.joined(&buf));
}

test "TagFilter suppresses an orphan closer split across chunks" {
    var col = collectChunks(16){};
    var filter = TagFilter.initWithThinkMode(col.sink(), .render);
    filter.orphan_think_closer = .suppress;
    const s = filter.sink();
    s.emitChunk("Draft.</ifm");
    s.emitChunk("|think>Answer.");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Draft.Answer.", col.joined(&buf));
}

test "TagFilter keeps prose containing '<think ' as ordinary text" {
    // Regression: `<think` opened a reasoning region on any delimiter, so
    // "<think twice before you answer>" swallowed the rest of the reply.
    // `<think` only opens a region with a `>` delimiter.
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("Please <think twice before you answer> ok.");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Please <think twice before you answer> ok.", col.joined(&buf));
}

test "TagFilter ends a tool block inside namespaced reasoning at the namespaced closer" {
    // Regression: inside `.tool_lt` only the literal `</think>` ended a block
    // that opened inside the reasoning region, so an unterminated tool call
    // inside `<ifm|think>...` ate the namespaced closer and the answer.
    const input = "<ifm|think>x<tool_result>payload</ifm|think>Visible answer";
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk(input);
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Visible answer", col.joined(&buf));
}

test "TagFilter drops a stray function close tag" {
    // Regression: the XML `function` dialect was not in the tag set, so a
    // degenerate loop of `</function>` closers streamed to the user verbatim.
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("Answer</function></function></function>");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Answer", col.joined(&buf));
}

test "TagFilter strips a function_calls block" {
    var col = collectChunks(16){};
    var filter = TagFilter.init(col.sink());
    const s = filter.sink();
    s.emitChunk("A<function_calls><invoke name=\"shell\"></invoke></function_calls>B");
    s.emitFinal();
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("AB", col.joined(&buf));
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

// ---------------------------------------------------------------------------
// Regression: K2 emits a text tool call in the *content* stream (or inside a
// streamed reasoning block) as
//   <tool_call>\n{"name": "shell", "arguments": {...}}\n</tool_call>
// with arbitrary chunk boundaries. No mode may leak the tags or the JSON body.
// ---------------------------------------------------------------------------

/// K2's exact captured content, verbatim.
const k2_text_tool_call =
    "<tool_call>\n{\"name\": \"shell\", \"arguments\": {\"command\": \"echo leakcheck-5\"}}\n</tool_call>";

fn assertFilteredEquals(comptime mode: ThinkMode, chunks: []const []const u8, expected: []const u8) !void {
    var col = collectChunks(64){};
    var filter = TagFilter.initWithThinkMode(col.sink(), mode);
    const s = filter.sink();
    for (chunks) |c| s.emitChunk(c);
    s.emitFinal();
    var buf: [512]u8 = undefined;
    try std.testing.expectEqualStrings(expected, col.joined(&buf));
}

test "TagFilter hides the K2 text tool call at every chunk boundary in all modes" {
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        var split: usize = 0;
        while (split <= k2_text_tool_call.len) : (split += 1) {
            try assertFilteredEquals(
                mode,
                &.{ k2_text_tool_call[0..split], k2_text_tool_call[split..] },
                "",
            );
        }
    }
}

test "TagFilter keeps surrounding text while hiding the K2 tool call at every boundary" {
    const full = "Let me check." ++ k2_text_tool_call ++ "Done.";
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        var split: usize = 0;
        while (split <= full.len) : (split += 1) {
            try assertFilteredEquals(mode, &.{ full[0..split], full[split..] }, "Let me check.Done.");
        }
    }
}

test "TagFilter hides the K2 tool call inside streamed reasoning at every boundary" {
    const reasoning = "<think>I will call:\n" ++ k2_text_tool_call ++ "\ndone</think>";
    const render_expected = THINK_HEADER ++ "I will call:\n\ndone" ++ THINK_FOOTER;

    var split: usize = 0;
    while (split <= reasoning.len) : (split += 1) {
        try assertFilteredEquals(.strip, &.{ reasoning[0..split], reasoning[split..] }, "");
    }
    split = 0;
    while (split <= reasoning.len) : (split += 1) {
        try assertFilteredEquals(.render, &.{ reasoning[0..split], reasoning[split..] }, render_expected);
    }
}

test "TagFilter strip does not end a think block on an inner tool close tag" {
    // Regression: an inner `</tool_call>` used to close the reasoning
    // suppression early and leak the reasoning tail plus a literal `</think>`.
    try assertFilteredEquals(
        .strip,
        &.{"<think>hidden <tool_call>{\"name\":\"shell\"}</tool_call> tail</think>Visible answer"},
        "Visible answer",
    );
}

test "TagFilter keeps prose and code that only name tool_call" {
    const text = "Call the `tool_call` helper, or use the [tool_call] section.";
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        try assertFilteredEquals(mode, &.{text}, text);
    }
}

test "TagFilter render mode strips tool markup while rendering reasoning" {
    var col = collectChunks(64){};
    var filter = TagFilter.initWithThinkMode(col.sink(), .render);
    const s = filter.sink();
    s.emitChunk("<think>plan\n" ++ k2_text_tool_call ++ "\nend</think>Answer");
    s.emitFinal();
    var buf: [512]u8 = undefined;
    try std.testing.expectEqualStrings(THINK_HEADER ++ "plan\n\nend" ++ THINK_FOOTER ++ "Answer", col.joined(&buf));
}

test "TagFilter ends an unterminated tool block at </think> and keeps the answer" {
    // Regression: once a `<tool_call>` opened inside the reasoning region the
    // machine stayed in the tool body, ate the `</think>` and every visible
    // byte after it, and the answer was lost.
    const input = "<think>reasoning <tool_call>{\"name\":\"shell\"} </think>Visible answer";
    try assertFilteredEquals(.strip, &.{input}, "Visible answer");
    try assertFilteredEquals(.render, &.{input}, THINK_HEADER ++ "reasoning " ++ THINK_FOOTER ++ "Visible answer");
}

test "TagFilter recognises a tool open tag followed by a newline" {
    // Regression: the block-open test only accepted `>` or a space after the
    // tag name, so `<tool_call\n{...}` streamed verbatim.
    const block = "<tool_call\n{\"name\": \"shell\", \"arguments\": {\"command\": \"echo x\"}}\n</tool_call>";
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        try assertFilteredEquals(mode, &.{block}, "");
        try assertFilteredEquals(mode, &.{"Before " ++ block ++ " after"}, "Before  after");
    }
}

test "TagFilter swallows a standalone tool close tag in every mode and region" {
    // Regression: a stray `</tool_call>` with no opener leaked verbatim because
    // close tags were not part of the buffering prefix set.
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        try assertFilteredEquals(mode, &.{"A</tool_call>B"}, "AB");
    }
    try assertFilteredEquals(.strip, &.{"<think>A</tool_call>B</think>"}, "");
    try assertFilteredEquals(.render, &.{"<think>A</tool_call>B</think>"}, THINK_HEADER ++ "AB" ++ THINK_FOOTER);
}

test "TagFilter releases an unmatched tool open tag at a paragraph break" {
    // Regression: an unmatched `<tool_call>` in prose swallowed everything to
    // the end of the stream. The opener is now released as ordinary text.
    const input = "intro <tool_call> not really a call\n\nsecond paragraph";
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        try assertFilteredEquals(mode, &.{input}, input);
    }
}

test "TagFilter releases an unmatched tool open tag at end of stream" {
    const input = "intro <tool_call> trailing prose with no close";
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        try assertFilteredEquals(mode, &.{input}, input);
    }
}

test "TagFilter ends a think-region tool body whose last body byte is '<'" {
    // Regression: with a stray `<` as the final body byte before `</think>` the
    // body's `<` moved to .tool_lt and the `</think>`'s own `<` then arrived as
    // `<<`; the machine bailed back to the body and ate the reasoning
    // terminator plus the whole visible answer.
    const input = "<think>r<tool_call>{\"a\":<</think>Answer";
    const strip_expected = "Answer";
    const render_expected = THINK_HEADER ++ "r" ++ THINK_FOOTER ++ "Answer";

    try assertFilteredEquals(.strip, &.{input}, strip_expected);
    try assertFilteredEquals(.render, &.{input}, render_expected);

    // The same bytes must behave identically at every chunk boundary.
    var split: usize = 0;
    while (split <= input.len) : (split += 1) {
        try assertFilteredEquals(.strip, &.{ input[0..split], input[split..] }, strip_expected);
        try assertFilteredEquals(.render, &.{ input[0..split], input[split..] }, render_expected);
    }
}

test "TagFilter ends a tool block on a whitespace-delimited close tag" {
    // Regression: opens accepted a whitespace delimiter (`<tool_call >`) but
    // closes were matched exactly, so a model that symmetrically dropped the
    // `>` leaked the whole call (tags and JSON body) verbatim in every mode.
    const cases = [_][]const u8{
        "A<tool_call >{\"x\":1}</tool_call >B",
        "A<tool_call>{\"x\":1}</tool_call\n>B",
        "A<tool_call >{\"x\":1}</tool_call>B",
    };
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        for (cases) |input| {
            try assertFilteredEquals(mode, &.{input}, "AB");
            var split: usize = 0;
            while (split <= input.len) : (split += 1) {
                try assertFilteredEquals(mode, &.{ input[0..split], input[split..] }, "AB");
            }
        }
    }
}

test "TagFilter strips a tool block whose body contains a blank line" {
    // Regression: the paragraph-break heuristic released a well-formed tool
    // block (open tag and all) as ordinary text the moment the body contained a
    // blank line, so the tags and the JSON reached the user. Multi-line tool
    // arguments are common and the body is buffered anyway, so the release must
    // wait for the close tag (or the buffer cap).
    const cases = [_][]const u8{
        "A<tool_call>{\"x\":1}\n\nstill body</tool_call>B",
        "A<tool_call>b\r\n\r\nc</tool_call>B",
    };
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        for (cases) |input| {
            try assertFilteredEquals(mode, &.{input}, "AB");
            var split: usize = 0;
            while (split <= input.len) : (split += 1) {
                try assertFilteredEquals(mode, &.{ input[0..split], input[split..] }, "AB");
            }
        }
    }
}

test "TagFilter strips a blank-line tool body inside reasoning" {
    // Regression: the blank line in the body released `<tool_call>a\n\nb` into
    // the streamed reasoning (render put it inside the THINK block). The whole
    // block must vanish.
    const input = "<think>x<tool_call>a\n\nb</tool_call></think>Ans";
    const strip_expected = "Ans";
    const render_expected = THINK_HEADER ++ "x" ++ THINK_FOOTER ++ "Ans";
    try assertFilteredEquals(.strip, &.{input}, strip_expected);
    try assertFilteredEquals(.render, &.{input}, render_expected);
    var split: usize = 0;
    while (split <= input.len) : (split += 1) {
        try assertFilteredEquals(.strip, &.{ input[0..split], input[split..] }, strip_expected);
        try assertFilteredEquals(.render, &.{ input[0..split], input[split..] }, render_expected);
    }
}

test "TagFilter strips standalone control tokens with an omitted delimiter" {
    // Regression: standalone tokens were matched exactly, so the same 'model
    // omits the >' class that close tags already tolerated leaked the whole
    // token verbatim in every mode and region.
    const cases = [_][]const u8{
        "A<tool_calls_section_begin >B",
        "A<tool_calls_section_end >B",
        "A<tool_calls_section_end\n>B",
        "A<tool_calls_section_end| >B",
        "A<|tool_calls_section_begin| >B",
        "A<|tool_calls_section_end| >B",
        "A<tool_call_argument_begin >B",
        "A<|tool_call_argument_begin| >B",
    };
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        for (cases) |input| {
            try assertFilteredEquals(mode, &.{input}, "AB");
            var split: usize = 0;
            while (split <= input.len) : (split += 1) {
                try assertFilteredEquals(mode, &.{ input[0..split], input[split..] }, "AB");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Regression: an *unterminated* tag token — a tag name with no `>` — must be
// dropped and the following `<` reprocessed, in every ThinkMode and at every
// chunk boundary. The streaming filter and the batch `stripToolCallMarkup` must
// agree (parity).
// ---------------------------------------------------------------------------

/// The batch mirror of the streaming filter's strip mode is the shared
/// `stripToolCallMarkup` (tool markup) followed by `stripThinkBlocks` (the
/// `<think>` block itself). Assert the streaming filter agrees with that
/// composition over `chunks`.
fn assertBatchParity(chunks: []const []const u8, input: []const u8) !void {
    var col = collectChunks(64){};
    var filter = TagFilter.initWithThinkMode(col.sink(), .strip);
    const s = filter.sink();
    for (chunks) |c| s.emitChunk(c);
    s.emitFinal();
    var buf: [512]u8 = undefined;
    const streamed = col.joined(&buf);

    const no_markup = try providers.stripToolCallMarkup(std.testing.allocator, input);
    defer std.testing.allocator.free(no_markup);
    const batch = try providers.stripThinkBlocks(std.testing.allocator, no_markup);
    defer std.testing.allocator.free(batch);
    try std.testing.expectEqualStrings(batch, streamed);
}

/// Assert `input` filters to the same result in both modes at every 2-way and
/// every 3-way chunk split, and that the streaming strip mode stays in step
/// with the batch `stripToolCallMarkup` + `stripThinkBlocks`.
fn assertEverySplit(
    input: []const u8,
    expected_strip: []const u8,
    expected_render: []const u8,
) !void {
    var a: usize = 0;
    while (a <= input.len) : (a += 1) {
        const two = [_][]const u8{ input[0..a], input[a..] };
        try assertFilteredEquals(.strip, &two, expected_strip);
        try assertFilteredEquals(.render, &two, expected_render);
        try assertBatchParity(&two, input);

        var b: usize = a;
        while (b <= input.len) : (b += 1) {
            const three = [_][]const u8{ input[0..a], input[a..b], input[b..] };
            try assertFilteredEquals(.strip, &three, expected_strip);
            try assertFilteredEquals(.render, &three, expected_render);
            try assertBatchParity(&three, input);
        }
    }
}

/// Assert the batch strip's forward-scan work stays linear in the input size.
/// A quadratic strip re-walks the remaining text once per marker, so its step
/// count is orders of magnitude past this bound; asserting work instead of wall
/// time keeps the check independent of the CI runner's speed.
fn expectStripWorkLinear(input_len: usize) !void {
    try std.testing.expect(providers.helpers.scan_work < 8 * input_len);
}

test "TagFilter drops an unterminated close tag before </think>" {
    // Regression: a close tag that omits its `>` (whitespace delimiter) right
    // before `</think>` entered `.close_tag`, ate up to the `>` of `</think>`,
    // so the reasoning region never closed and strip mode dropped the whole
    // answer.
    const cases = [_][]const u8{
        "<think>x</tool_call </think>Ans",
        "<think>x</tool_call\n</think>Ans",
        "<think>x<tool_call>body</tool_call </think>Ans",
    };
    const strip_expected = "Ans";
    const render_expected = THINK_HEADER ++ "x" ++ THINK_FOOTER ++ "Ans";
    for (cases) |input| {
        try assertEverySplit(input, strip_expected, render_expected);
    }
}

test "TagFilter drops an unterminated standalone token before a tool block" {
    // Regression: a standalone control token with its `>` omitted
    // over-consumed up to the `>` of the following `<tool_call>` opener, so the
    // tool body leaked. The unterminated token must be dropped and the opener
    // reprocessed.
    const cases = [_][]const u8{
        "A<tool_calls_section_begin <tool_call>{\"n\":1}</tool_call>B",
        "A<tool_calls_section_end <tool_call>{\"n\":1}</tool_call>B",
        "A<tool_call_argument_begin <tool_call>{\"n\":1}</tool_call>B",
        "A<|tool_calls_section_begin| <tool_call>{\"n\":1}</tool_call>B",
        "A</tool_call <tool_call>{\"n\":1}</tool_call>B",
    };
    for (cases) |input| {
        try assertEverySplit(input, "AB", "AB");
    }
}

test "TagFilter drops an incomplete close tag immediately before </think>" {
    // Regression: an incomplete close tag `</tool_call` immediately followed by
    // `<` was flushed (including the `<`) by the `.lt` fallback, so the
    // following `</think>` was never recognised.
    const input = "<think>x</tool_call</think>Ans";
    try assertEverySplit(input, "Ans", THINK_HEADER ++ "x" ++ THINK_FOOTER ++ "Ans");
}

// ---------------------------------------------------------------------------
// Regression: the tool-body window. A well-formed text tool call whose body is
// larger than the old 4096-byte window leaked the open tag and the entire JSON
// body in the live stream, and the streaming/batch boundaries disagreed by one
// byte. The window is now large enough for a realistic multi-KiB command and
// both implementations share the same inclusive boundary.
// ---------------------------------------------------------------------------

test "TagFilter hides a K2 tool call whose JSON body exceeds the old 4 KiB window" {
    const body = "x" ** 5000;
    const call = "<tool_call>\n{\"name\": \"shell\", \"arguments\": {\"command\": \"" ++ body ++ "\"}}\n</tool_call>";
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        try assertFilteredEquals(mode, &.{call}, "");
        // Every 2-way split (a full 3-way sweep over a 5 KiB body is O(n^2)).
        var split: usize = 0;
        while (split <= call.len) : (split += 1) {
            try assertFilteredEquals(mode, &.{ call[0..split], call[split..] }, "");
        }
        // Representative 3-way splits, inside the tag and inside the body.
        try assertFilteredEquals(mode, &.{ call[0..3], call[3..2500], call[2500..] }, "");
        try assertFilteredEquals(mode, &.{ call[0..20], call[20..4999], call[4999..] }, "");
    }
    // The batch scanner must strip the very same bytes at these splits.
    try assertBatchParity(&.{call}, call);
    try assertBatchParity(&.{ call[0..7], call[7..] }, call);
    try assertBatchParity(&.{ call[0..3000], call[3000..] }, call);
    try assertBatchParity(&.{ call[0..3], call[3..2500], call[2500..] }, call);
}

/// Collector for outputs larger than `collectChunks` can hold.
const BigCollector = struct {
    buf: [tool_body_max + 256]u8 = undefined,
    len: usize = 0,

    fn callback(ctx: *anyopaque, event: Event) void {
        if (event.stage == .final) return;
        const self: *@This() = @ptrCast(@alignCast(ctx));
        @memcpy(self.buf[self.len..][0..event.text.len], event.text);
        self.len += event.text.len;
    }

    fn sink(self: *@This()) Sink {
        return .{ .callback = callback, .ctx = @ptrCast(self) };
    }
};

test "TagFilter hides a closed tool call whose body exceeds the tool-body window" {
    // Regression: the window was a *size* guard, so a well-formed call whose
    // close tag arrived past `tool_body_max` was released verbatim (tags and
    // JSON) even though the dispatcher executes it. A close that arrived is a
    // close: the cap only bounds the streaming buffer, and the batch scanner no
    // longer rejects a present close for size.
    const open = "<tool_call>";
    const close = "</tool_call>";
    const limit = tool_body_max - open.len;
    var buf: [tool_body_max + 256]u8 = undefined;

    inline for (.{ limit - 1, limit, limit + 1, limit + 8, limit + 64 }) |body_len| {
        @memcpy(buf[0..open.len], open);
        @memset(buf[open.len..][0..body_len], 'a');
        @memcpy(buf[open.len + body_len ..][0..close.len], close);
        const call = buf[0 .. open.len + body_len + close.len];

        inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
            // A full split sweep over a ~16 KiB body would be O(n^2), so sample
            // a spread of 2-way splits plus one 3-way split; split-independence
            // is swept exhaustively by the smaller regression inputs.
            var split: usize = 0;
            while (split <= call.len) : (split += 1 + call.len / 8) {
                var col = BigCollector{};
                var filter = TagFilter.initWithThinkMode(col.sink(), mode);
                const s = filter.sink();
                s.emitChunk(call[0..split]);
                s.emitChunk(call[split..]);
                s.emitFinal();
                try std.testing.expectEqualStrings("", col.buf[0..col.len]);
            }
            var col = BigCollector{};
            var filter = TagFilter.initWithThinkMode(col.sink(), mode);
            const s = filter.sink();
            const mid = call.len / 2;
            s.emitChunk(call[0..5]);
            s.emitChunk(call[5..mid]);
            s.emitChunk(call[mid..]);
            s.emitFinal();
            try std.testing.expectEqualStrings("", col.buf[0..col.len]);
        }

        // Batch parity: the batch scanner hides the very same bytes.
        var col = BigCollector{};
        var filter = TagFilter.initWithThinkMode(col.sink(), .strip);
        const s = filter.sink();
        s.emitChunk(call);
        s.emitFinal();
        const batch = try providers.stripToolCallMarkup(std.testing.allocator, call);
        defer std.testing.allocator.free(batch);
        try std.testing.expectEqualStrings("", batch);
        try std.testing.expectEqualStrings(batch, col.buf[0..col.len]);
    }
}

test "TagFilter hides an unclosed executable tool call whose body fills the buffer" {
    // The same-size *unclosed* call is a text tool call the dispatcher executes
    // (its JSON object is closed), so both display paths must hide it. The
    // streaming filter used to release it once the body passed the window while
    // the batch scanner still hid it.
    const open = "<tool_call>";
    const json_open = "{\"name\":\"shell\",\"arguments\":{\"command\":\"";
    const json_close = "\"}}";
    const fill = "a" ** (tool_body_max + 1 - open.len - json_open.len - json_close.len);
    const call = open ++ json_open ++ fill ++ json_close;
    try std.testing.expectEqual(@as(usize, tool_body_max + 1), call.len);

    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        var split: usize = 0;
        while (split <= call.len) : (split += 1 + call.len / 8) {
            var col = BigCollector{};
            var filter = TagFilter.initWithThinkMode(col.sink(), mode);
            const s = filter.sink();
            s.emitChunk(call[0..split]);
            s.emitChunk(call[split..]);
            s.emitFinal();
            try std.testing.expectEqualStrings("", col.buf[0..col.len]);
        }
    }

    var col = BigCollector{};
    var filter = TagFilter.initWithThinkMode(col.sink(), .strip);
    const s = filter.sink();
    s.emitChunk(call);
    s.emitFinal();
    const batch = try providers.stripToolCallMarkup(std.testing.allocator, call);
    defer std.testing.allocator.free(batch);
    try std.testing.expectEqualStrings("", batch);
    try std.testing.expectEqualStrings(batch, col.buf[0..col.len]);
}

test "TagFilter hides a large unterminated text tool call at every sampled split" {
    // Regression: the end-of-stream executability check parsed under a fixed
    // ~32 KiB scratch, so a >12 KiB payload failed to parse, the predicate
    // returned false, and the whole call leaked. It now falls back to a real
    // allocator, exactly like the batch `stripToolCallMarkup`.
    const content = "x" ** 12200;
    const sample = "<tool_call>{\"name\":\"file_write\",\"arguments\":{\"path\":\"f\",\"content\":\"" ++ content ++ "ZQ9LEAK\"}}";
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        var split: usize = 0;
        while (split <= sample.len) : (split += 1 + sample.len / 16) {
            try assertFilteredEquals(mode, &.{ sample[0..split], sample[split..] }, "");
        }
    }
    try assertBatchParity(&.{sample}, sample);
    try assertBatchParity(&.{ sample[0..7], sample[7..] }, sample);
    try assertBatchParity(&.{ sample[0 .. sample.len / 2], sample[sample.len / 2 ..] }, sample);
}

test "TagFilter hides a fallback-closed tool call the way the dispatcher does" {
    // (a) a strict close after an early non-strict close: the dispatcher ends
    // the block at the strict close, so the whole tail must be hidden.
    try assertEverySplit(
        "<tool_call>{\"name\":\"a\",\"arguments\":{}}</arg_value>{\"name\":\"b\",\"arguments\":{\"c\":\"x\"}}</tool_call>",
        "",
        "",
    );
    // (b) only fallback closes: the dispatcher ends at the LAST parseable one.
    try assertEverySplit(
        "<tool_call>{\"name\":\"a\",\"arguments\":{}}</arg_value>{\"name\":\"b\",\"arguments\":{\"c\":\"x\"}}</arg_value>",
        "",
        "",
    );
    // (c) bracket dialect: the strict close ends the block; PROSE is body.
    try assertEverySplit(
        "A[tool_call]{\"name\":\"a\",\"arguments\":{}}[/arg]PROSE[/tool_call]B",
        "AB",
        "AB",
    );
}

// ---------------------------------------------------------------------------
// Regression: an *unterminated* text tool call. K2 sometimes streams the exact
// 75-byte `<tool_call>\n{json}` with no closing tag (tool_calls=0). The agent's
// dispatcher executes it, so no user-visible surface may show the tags or the
// JSON. The "never lose text" fallback must still release an opener that is
// prose. The predicate mirrors the dispatcher's unclosed recovery: it accepts a
// JSON object the dispatcher can repair (trailing comma / unbalanced brace /
// unbalanced quote) or a `name{...}` prefix.
// ---------------------------------------------------------------------------

test "TagFilter hides the unclosed K2 text tool call at every chunk boundary in all modes" {
    // The exact 75-byte sample from the production leak (`echo leakcheck-7`).
    const sample = "<tool_call>\n{\"name\": \"shell\", \"arguments\": {\"command\": \"echo leakcheck-7\"}}";
    try std.testing.expectEqual(@as(usize, 75), sample.len);
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        var split: usize = 0;
        while (split <= sample.len) : (split += 1) {
            try assertFilteredEquals(mode, &.{ sample[0..split], sample[split..] }, "");
        }
    }
}

test "TagFilter hides an unclosed repairable tool call in every mode and split" {
    const cases = [_][]const u8{
        "<tool_call>{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\",}}",
        "<tool_call>{\"name\":\"shell\",}",
        "<tool_call>{\"name\":\"shell\",\"arguments\":{\"command\":\"ls\"}",
        "<tool_call>{\"name\":\"shell\",\"arguments\":{\"command\":\"ls}",
        "<tool_call>memory_list{\"limit\":10,}",
        "<tool_call>shell{",
    };
    for (cases) |input| {
        try assertEverySplit(input, "", "");
    }
}

test "TagFilter releases an unclosed tool opener that is prose" {
    // The opener may be an ordinary mention; only an executable payload is
    // dropped, so the tail of the answer is never lost.
    const cases = [_][]const u8{
        "intro <tool_call> trailing prose with no close",
        "<tool_call>{\"not\":\"a call\"}",
        "<tool_call>{\"name\":\"shell\",\"arguments\":{}} trailing prose",
    };
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        for (cases) |input| {
            try assertFilteredEquals(mode, &.{input}, input);
        }
    }
}

test "TagFilter hides the bracket tool-call dialect the dispatcher accepts" {
    const unclosed = [_][]const u8{
        "[tool_call]\n{\"name\": \"shell\", \"arguments\": {\"command\": \"echo leakcheck-7\"}}",
        "[TOOL_CALL]\n{\"name\": \"shell\", \"arguments\": {\"command\": \"echo leakcheck-7\"}}",
    };
    for (unclosed) |input| {
        try assertEverySplit(input, "", "");
    }
    // A closed bracket block is stripped and the surrounding text survives.
    try assertEverySplit("A[tool_call]{\"name\":\"shell\"}[/tool_call]B", "AB", "AB");
    try assertEverySplit("A[TOOL_CALL]{\"name\":\"shell\"}[/TOOL_CALL]B", "AB", "AB");
}

test "TagFilter keeps prose and code that only name the bracket marker" {
    const text = "Call the `tool_call` helper, or use the [tool_call] section.";
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        try assertFilteredEquals(mode, &.{text}, text);
    }
}

// ---------------------------------------------------------------------------
// Regression: the dispatcher's `parseXmlToolCalls` accepts the first `</X>` as a
// fallback close and matches "tool_call" case-insensitively, but the streaming
// filter only knew a fixed close-name list, so these blocks leaked their tags
// and JSON into live drafts. The close rule is now derived from the dispatcher's
// own scan (shared via `providers.helpers`) and mirrored by
// `stripToolCallMarkup`.
// ---------------------------------------------------------------------------

test "TagFilter hides a tool call closed by a mismatched or any-case close tag in every mode and split" {
    const cases = [_][]const u8{
        "<tool_call>{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"}}</arg_value>",
        "<tool_call>{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"}}</function>",
        "<tool_call>{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"}}</TOOL_CALL>",
        "<tool_call>{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"}}</Tool_Call>",
        "<tool_call>memory_list{\"limit\": 10, \"include_content\": true}</arg_value>",
        "<tool_call>file_write{\"path\":\"index.html\",\"content\":\"</html>\"}</arg_value>",
    };
    for (cases) |input| {
        try assertEverySplit(input, "", "");
    }
}

test "TagFilter hides a bracket tool call closed by a mismatched close tag" {
    // The dispatcher's bracket dialect closes on the first `[/X]` (any name).
    try assertEverySplit("A[tool_call]{\"name\":\"shell\"}[/xyz]B", "AB", "AB");
    try assertEverySplit("A[TOOL_CALL]{\"name\":\"shell\"}[/XYZ]B", "AB", "AB");
}

test "TagFilter keeps prose that only mentions a mismatched close tag" {
    // The tag names appear, but there is no executable call between them, so
    // every byte stays visible (in all modes and at every split).
    const text = "Call the tool with <tool_call> then close it with </arg_value>.";
    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        try assertFilteredEquals(mode, &.{text}, text);
    }
}

// TEMP REPRO - remove before final
// ---------------------------------------------------------------------------
// Regression: the review reproductions for hiding text tool calls.
// ---------------------------------------------------------------------------

test "TagFilter hides a >16KiB tool call closed by a fallback tag" {
    // The buffered body was capped at 16 KiB; a larger payload made the
    // end-of-stream completeness test fail and the whole call leaked verbatim.
    // The body now grows on demand and the shared dispatcher parse decides.
    const a = std.testing.allocator;
    var input: std.ArrayListUnmanaged(u8) = .empty;
    defer input.deinit(a);
    try input.appendSlice(a, "<tool_call>{\"name\":\"shell\",\"arguments\":{\"command\":\"");
    try input.appendNTimes(a, 'a', 20000);
    try input.appendSlice(a, "\"}}</FUNCTION>AFTER");

    inline for (.{ ThinkMode.strip, ThinkMode.render }) |mode| {
        try assertFilteredEquals(mode, &.{input.items}, "AFTER");
    }

    // A chunk boundary inside the tag, inside the oversized body, or at the
    // fallback close must not change the result, and the batch scanner must
    // agree. A full sweep over 20 KB would be O(n^2), so sample a spread.
    var split: usize = 0;
    while (split <= input.items.len) : (split += 37) {
        const two = [_][]const u8{ input.items[0..split], input.items[split..] };
        try assertFilteredEquals(.strip, &two, "AFTER");
        try assertFilteredEquals(.render, &two, "AFTER");
        try assertBatchParity(&two, input.items);
    }
}

test "TagFilter keeps prose that only names the tool markers" {
    // Chinese prose that *names* the markers (`<tool_call>` ... `</tool_call>`)
    // with no call between them: the dispatcher executes nothing, so the whole
    // sentence — markers included — must pass through untouched in every mode
    // and at every split, in step with `stripToolCallMarkup`.
    const input = "文档中 <tool_call> 是调用开始标记，调用使用 </tool_call> 结束。";
    try assertEverySplit(input, input, input);
}

test "TagFilter hides a call closed by a whitespace-delimited close tag" {
    // `</tool_call ` (its `>` omitted) followed by `</think>`: the dispatcher
    // scans the whole close tag to its `>`, so it consumes `</tool_call
    // </think>` and executes the call. The display must agree instead of
    // reprocessing the inner `<` and leaking `</think>`.
    const input = "<tool_call>{\"name\":\"shell\",\"arguments\":{}}</tool_call </think>AFTER";
    try assertEverySplit(input, "AFTER", "AFTER");
}

test "TagFilter strips a large multi-marker stream in one pass" {
    // Regression: the batch stripper re-ran the whole dispatcher parse for every
    // marker (O(N^2)). It now parses once and walks the block spans.
    const a = std.testing.allocator;
    var input: std.ArrayListUnmanaged(u8) = .empty;
    defer input.deinit(a);
    while (input.items.len < 60 * 1024) {
        try input.appendSlice(a, "text <tool_call>{\"name\":\"shell\",\"arguments\":{\"command\":\"ls -la\"}}</tool_call> more ");
    }

    providers.helpers.scan_work = 0;
    const batch = try providers.stripToolCallMarkup(a, input.items);
    defer a.free(batch);

    try std.testing.expect(std.mem.indexOf(u8, batch, "<tool_call>") == null);
    try std.testing.expect(std.mem.indexOf(u8, batch, "more") != null);
    try expectStripWorkLinear(input.items.len);
}

test "TagFilter strips a dense run of unclosed openers in one pass" {
    // Regression: the batch stripper scanned forward to end-of-string at every
    // unclosed opener (`dispatcherBlockReleaseEnd`/`skipToolCallBlock`), so a
    // run of `<tool_call>literal ` repeated was O(N^2) — 60 KiB took over a
    // second and 1 MiB extrapolated to minutes. The forward close scans are now
    // cached and resume where they left off, so the strip is linear.
    const a = std.testing.allocator;
    var input: std.ArrayListUnmanaged(u8) = .empty;
    defer input.deinit(a);
    while (input.items.len < 120 * 1024) {
        try input.appendSlice(a, "<tool_call>literal ");
    }

    providers.helpers.scan_work = 0;
    const batch = try providers.stripToolCallMarkup(a, input.items);
    defer a.free(batch);

    // No opener here closes and none is a call the dispatcher would execute, so
    // every byte is released verbatim.
    try std.testing.expectEqualStrings(input.items, batch);
    try expectStripWorkLinear(input.items.len);
}

test "TagFilter keeps a dense run of unclosed openers in step with the batch strip" {
    // The same dense input at a size that can be split at every boundary: the
    // streaming filter and the batch stripper must still agree, so the linear
    // scan did not change the bytes either surface shows.
    const a = std.testing.allocator;
    var input: std.ArrayListUnmanaged(u8) = .empty;
    defer input.deinit(a);
    for (0..12) |_| try input.appendSlice(a, "<tool_call>literal ");
    try assertEverySplit(input.items, input.items, input.items);
}

test "TagFilter strips a large dense run of closed calls in one pass" {
    // Regression: the shared dispatcher parse searched for every marker on the
    // whole shrinking tail at each call, so a dense run of *closed* calls was
    // O(N^2) — 1 MiB took ~5 s. The marker scan now advances a single cursor, so
    // the parse (and the strip) stay linear.
    const a = std.testing.allocator;
    var input: std.ArrayListUnmanaged(u8) = .empty;
    defer input.deinit(a);
    while (input.items.len < 240 * 1024) {
        try input.appendSlice(a, "A<tool_call>{\"name\":\"shell\",\"arguments\":{}}</tool_call>B");
    }

    providers.helpers.scan_work = 0;
    const batch = try providers.stripToolCallMarkup(a, input.items);
    defer a.free(batch);

    // Every block is a call the dispatcher executes, so only the `A`/`B` text
    // survives.
    try std.testing.expect(std.mem.indexOf(u8, batch, "<tool_call>") == null);
    try std.testing.expect(std.mem.indexOf(u8, batch, "AB") != null);
    try expectStripWorkLinear(input.items.len);
}

test "TagFilter keeps a dense run of closed calls in step with the batch strip" {
    const a = std.testing.allocator;
    var input: std.ArrayListUnmanaged(u8) = .empty;
    defer input.deinit(a);
    var expected: std.ArrayListUnmanaged(u8) = .empty;
    defer expected.deinit(a);
    for (0..8) |_| {
        try input.appendSlice(a, "A<tool_call>{\"name\":\"shell\",\"arguments\":{}}</tool_call>B");
        try expected.appendSlice(a, "AB");
    }
    try assertEverySplit(input.items, expected.items, expected.items);
}

test "TagFilter hides a quoted-colon salvaged call" {
    // The dispatcher salvages a tool name mangled as `"name":": "x"`. The
    // display must hide the same block so the malformed call is never shown.
    const input = "A<tool_call>{\"name\":\": \"memory_recall\", \"arguments\": {\"query\": \"q\"}}</tool_call>B";
    try assertEverySplit(input, "AB", "AB");
}

test "TagFilter deinit frees spilled body_heap when stream is dropped without final" {
    const Noop = struct {
        fn callback(_: *anyopaque, _: Event) void {}
    };
    var filter = TagFilter.init(.{ .callback = Noop.callback, .ctx = undefined });
    filter.allocator = std.testing.allocator;
    defer filter.deinit();

    const sink = filter.sink();
    sink.emitChunk("<tool_call>{\"name\":\"shell\",\"arguments\":{\"cmd\":\"");
    const chunk = "a" ** 1000;
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        sink.emitChunk(chunk);
    }
    try std.testing.expect(filter.body_heap != null);
}

test "TagFilter deinit is safe after emitFinal" {
    const Noop = struct {
        fn callback(_: *anyopaque, _: Event) void {}
    };
    var filter = TagFilter.init(.{ .callback = Noop.callback, .ctx = undefined });
    filter.allocator = std.testing.allocator;
    defer filter.deinit();

    const sink = filter.sink();
    sink.emitChunk("<tool_call>{\"name\":\"shell\",\"arguments\":{\"cmd\":\"");
    const chunk = "a" ** 1000;
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        sink.emitChunk(chunk);
    }
    try std.testing.expect(filter.body_heap != null);
    sink.emitFinal();
    try std.testing.expect(filter.body_heap == null);
}
