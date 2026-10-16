const std = @import("std");
const builtin = @import("builtin");
const std_compat = @import("compat");
const json_util = @import("../json_util.zig");
const http_util = @import("../http_util.zig");
const root = @import("root.zig");
const ToolSpec = root.ToolSpec;

// ── Think-block parsing ───────────────────────────────────────────────────

const think_open_tag = "<think>";
const think_close_tag = "</think>";

// ── Reasoning-tag recognition ─────────────────────────────────────────────
//
// The plain `<think>`/`</think>` forms are only one spelling. Reasoning
// gateways for non-OpenAI models wrap the same region in a namespaced or
// pipe-delimited tag — the IFM K2 gateway leaks `</ifm|think>` into the content
// stream with no opener — and OpenClaw recognises `antml:*`/`mm:*` namespaced
// tags plus `<|…|>` control tokens. A single scanner classifies them so the
// streaming `TagFilter` and the batch helpers agree.

/// Longest reasoning tag the scanner will accept (`</namespace|thinking>`), so
/// an incremental caller can keep a bounded buffer.
pub const max_think_tag_len = 32;

fn isTagNameByte(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
        (c >= '0' and c <= '9') or c == '_' or c == '-';
}

fn isThinkLeaf(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "think") or std.ascii.eqlIgnoreCase(name, "thinking");
}

fn isThinkLeafPrefix(name: []const u8) bool {
    const target = "thinking";
    if (name.len > target.len) return false;
    return std.ascii.eqlIgnoreCase(target[0..name.len], name);
}

/// A recognised reasoning (think) tag.
pub const ThinkTag = struct {
    /// True for a closing tag (`</…>`).
    close: bool,
    /// Total byte length, including `<`, `</` and the terminating `>`.
    len: usize,
    /// True for a namespaced or pipe-delimited spelling (`</ifm|think>`,
    /// `<mm:think>`, `<|think|>`) — a gateway artifact that is never prose,
    /// unlike the plain `<think>`/`</think>` a reply may name literally.
    namespaced: bool,
};

/// How a `<`-prefixed byte run classifies as a reasoning tag.
pub const ThinkTagScan = union(enum) {
    /// Not a reasoning tag, and no extension can make it one.
    none,
    /// Still a valid prefix of a reasoning tag — an incremental caller buffers.
    partial,
    /// A complete reasoning tag; `len` is its length.
    complete: ThinkTag,
};

/// Classify a byte run starting at `<` (which must be `text[0]`) as a reasoning
/// tag. Recognises `<think>`/`<thinking>` and their closers plus the namespaced
/// and pipe-delimited spellings gateways leak: `<ifm|think>`, `</ifm|think>`,
/// `<mm:think>`, `<|think|>`, `</|thinking|>`. Bytes after the tag are ignored,
/// so the same scanner serves a bounded stream buffer and a whole response.
pub fn scanThinkTag(text: []const u8) ThinkTagScan {
    if (text.len == 0 or text[0] != '<') return .none;
    var i: usize = 1;
    var close = false;
    if (i < text.len and text[i] == '/') {
        close = true;
        i += 1;
    }
    // Optional namespace, then `:` or `|`, then the `think` leaf. Without a
    // separator the whole name is the leaf (`<think>`).
    const first_start = i;
    while (i < text.len and isTagNameByte(text[i])) i += 1;
    if (i > max_think_tag_len) return .none;
    const first = text[first_start..i];
    var leaf = first;
    var had_sep = false;
    if (i < text.len and (text[i] == ':' or text[i] == '|')) {
        had_sep = true;
        i += 1;
        const leaf_start = i;
        while (i < text.len and isTagNameByte(text[i])) i += 1;
        if (i > max_think_tag_len) return .none;
        leaf = text[leaf_start..i];
    }
    // A pipe-token closer (`<|think|>`).
    if (i < text.len and text[i] == '|') i += 1;
    if (i < text.len and text[i] == '>') {
        i += 1;
        if (!isThinkLeaf(leaf)) return .none;
        return .{ .complete = .{ .close = close, .len = i, .namespaced = had_sep } };
    }
    if (i >= text.len) {
        // Incomplete: valid iff the leaf can still become think/thinking, or
        // (before any separator) the run can still gain `|`/`:` and a leaf.
        if (isThinkLeafPrefix(leaf)) return .partial;
        if (!had_sep and first.len > 0) return .partial;
    }
    return .none;
}

/// The reasoning tag starting at `text[start]`, or null. Whole-text callers use
/// this; the streaming `TagFilter` uses `scanThinkTag` directly so it can also
/// observe `.partial`.
fn matchThinkTag(text: []const u8, start: usize) ?ThinkTag {
    if (start >= text.len or text[start] != '<') return null;
    return switch (scanThinkTag(text[start..])) {
        .complete => |tag| tag,
        else => null,
    };
}

/// True when `text` contains any reasoning tag (opener or closer).
fn hasThinkTag(text: []const u8) bool {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, text, i, '<')) |lt| {
        if (matchThinkTag(text, lt) != null) return true;
        i = lt + 1;
    }
    return false;
}

/// True when a stray reasoning closer separates two non-empty visible runs —
/// i.e. the text before it is a leaked reasoning draft, not the answer.
/// Mirrors OpenClaw's `hasOrphanReasoningCloseBoundary`.
pub fn hasOrphanReasoningCloseBoundary(before: []const u8, after: []const u8) bool {
    return std.mem.trim(u8, before, " \t\r\n").len > 0 and
        std.mem.trim(u8, after, " \t\r\n").len > 0;
}

// ── Markdown code regions ────────────────────────────────────────────────
//
// The XML `function` tool dialect can appear literally in a fenced block or an
// inline code span (a documented XML sample, a discussion of the dialect). A
// sample is not markup: it must be preserved verbatim by the batch stripper and
// must not blank the whole reply in `containsToolCallMarkup`. OpenClaw guards
// the same way (`isInsideCode` over `findMarkdownCodeRegions`).

pub const CodeRegion = struct { start: usize, end: usize };

/// True when `pos` is inside one of the sorted, non-overlapping `regions`.
pub fn isInsideCode(regions: []const CodeRegion, pos: usize) bool {
    var lo: usize = 0;
    var hi: usize = regions.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const region = regions[mid];
        if (pos < region.start) {
            hi = mid;
        } else if (pos >= region.end) {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    return false;
}

fn codeRunLen(text: []const u8, start: usize) usize {
    const ch = text[start];
    var i = start;
    while (i < text.len and text[i] == ch) i += 1;
    return i - start;
}

/// Byte ranges of Markdown code in `text`: fenced blocks (``` / ~~~, opened by
/// a run of three or more at the start of a line) and inline code spans (a
/// backtick run closed by an equal run). Caller frees the returned slice.
pub fn findCodeRegions(allocator: std.mem.Allocator, text: []const u8) ![]CodeRegion {
    return findCodeRegionsInternal(allocator, text, true);
}

/// Like `findCodeRegions` but does not treat a trailing *unterminated* fence as
/// code. The tool-call-markup scanners use this so a model that opens a fence
/// and then degenerates into a garbled text tool call (a reply that promised a
/// comparison table, opened ``` and then emitted a lone `</function>`) still
/// has that closer scanned as visible text. A fence that actually closes is
/// still code, so a documented sample inside it is preserved.
pub fn findCodeRegionsForToolMarkup(allocator: std.mem.Allocator, text: []const u8) ![]CodeRegion {
    return findCodeRegionsInternal(allocator, text, false);
}

fn findCodeRegionsInternal(
    allocator: std.mem.Allocator,
    text: []const u8,
    unterminated_fence_is_code: bool,
) ![]CodeRegion {
    var regions: std.ArrayListUnmanaged(CodeRegion) = .empty;
    errdefer regions.deinit(allocator);

    var i: usize = 0;
    var at_line_start = true;
    var fence_ch: u8 = 0;
    var fence_len: usize = 0;
    var fence_start: usize = 0;
    var span_len: usize = 0;
    var span_start: usize = 0;
    while (i < text.len) {
        if (at_line_start) {
            at_line_start = false;
            var j = i;
            var indent: usize = 0;
            while (j < text.len and text[j] == ' ' and indent < 4) : (indent += 1) j += 1;
            if (indent <= 3 and j < text.len and (text[j] == '`' or text[j] == '~')) {
                const run = codeRunLen(text, j);
                if (fence_ch == 0 and run >= 3) {
                    fence_ch = text[j];
                    fence_len = run;
                    fence_start = i;
                    i = j + run;
                    continue;
                }
                if (fence_ch == text[j] and run >= fence_len) {
                    try regions.append(allocator, .{ .start = fence_start, .end = j + run });
                    fence_ch = 0;
                    i = j + run;
                    continue;
                }
            }
            if (fence_ch != 0) {
                // Inside a fence every byte is code until the next line start,
                // where a closing fence can appear.
                while (i < text.len and text[i] != '\n') i += 1;
                if (i < text.len) {
                    i += 1;
                    at_line_start = true;
                }
                continue;
            }
        }
        const b = text[i];
        if (b == '\n') {
            at_line_start = true;
            i += 1;
            continue;
        }
        if (b == '`') {
            const run = codeRunLen(text, i);
            if (span_len == 0) {
                span_len = run;
                span_start = i;
            } else if (run == span_len) {
                try regions.append(allocator, .{ .start = span_start, .end = i + run });
                span_len = 0;
            }
            i += run;
            continue;
        }
        i += 1;
    }
    // An unterminated fence runs to the end of the text (mid-stream). Callers
    // that scan for tool-call markup opt out (see `findCodeRegionsForToolMarkup`)
    // so an unclosed fence cannot hide a trailing garbled closer.
    if (fence_ch != 0 and unterminated_fence_is_code) {
        try regions.append(allocator, .{ .start = fence_start, .end = text.len });
    }
    return regions.toOwnedSlice(allocator);
}

/// Result of splitting a response text at <think>…</think> blocks.
pub const SplitThinkContent = struct {
    /// Text outside think blocks (the user-visible answer).
    visible: []const u8,
    /// Concatenated content of all think blocks, or null if none were present.
    reasoning: ?[]const u8,
};

// Tool-call markup, stripped from any non-streamed string this module renders
// (e.g. the reasoning quote in `composeFinalReply`). Mirrors the streaming
// `TagFilter` so the same bytes are hidden whether or not the turn streamed.
const tool_call_open_tags = [_][]const u8{
    "<tool_call",
    "<tool_result",
    "<tool_call_begin",
    "<tool_result_begin",
    "<|tool_call_begin|",
    "<|tool_result_begin|",
    // Anthropic-style text tool markup and OpenAI's XML `function` dialect.
    // A model that falls back to one of these can degenerate into a loop of
    // `</function>` closers; they are tool markup, not an answer (OpenClaw's
    // `TOOL_CALL_TAG_NAMES` covers the same set).
    "<function",
    "<function_calls",
    "<tool_calls",
    "<invoke",
    "<parameter",
};
// Close tag *names*, without the trailing delimiter. Like the opens above, a
// close is matched with either a `>` or a whitespace delimiter, so a model that
// drops the `>` (`</tool_call >`) still ends the block.
const tool_call_close_names = [_][]const u8{
    "</tool_call",
    "</tool_result",
    "<tool_call_end",
    "<tool_result_end",
    "<|tool_call_end|",
    "<|tool_result_end|",
    "</function",
    "</function_calls",
    "</tool_calls",
    "</invoke",
    "</parameter",
};
const tool_call_standalone_names = [_][]const u8{
    "<tool_calls_section_begin",
    "<tool_calls_section_end",
    "<tool_calls_section_end|",
    "<|tool_calls_section_begin|",
    "<|tool_calls_section_end|",
    "<tool_call_argument_begin",
    "<|tool_call_argument_begin|",
};

// Bracket tool-call dialect. The dispatcher's XML fallback accepts it as a
// first-class grammar (`[TOOL_CALL]` / `[tool_call]`, `marker_len == 11`, `[`/`]`),
// so the batch stripper must recognise it too. Unlike the `<...` tags above these
// are exact literals and are matched whole.
const bracket_tool_call_markers = [_][]const u8{
    "[tool_call]",
    "[TOOL_CALL]",
    "[/tool_call]",
    "[/TOOL_CALL]",
};

pub fn hasToolCallMarkup(text: []const u8) bool {
    for (tool_call_open_tags) |t| {
        if (std.mem.indexOf(u8, text, t) != null) return true;
    }
    for (tool_call_close_names) |t| {
        if (std.mem.indexOf(u8, text, t) != null) return true;
    }
    for (tool_call_standalone_names) |t| {
        if (std.mem.indexOf(u8, text, t) != null) return true;
    }
    for (bracket_tool_call_markers) |t| {
        if (std.mem.indexOf(u8, text, t) != null) return true;
    }
    return false;
}

/// Length (past its delimiter) of an XML `function`-dialect close tag at
/// `start`, or null. Used only to spot a runaway repetition.
fn toolFunctionCloseLenAt(text: []const u8, start: usize) ?usize {
    // Longest first: `</function` is a prefix of `</function_calls`, so the
    // shorter name would match first and then fail its delimiter check (`_`),
    // hiding the longer name and missing a `</function_calls>` run.
    const run_names = [_][]const u8{
        "</function_calls", "</tool_calls", "</parameter", "</function", "</invoke",
    };
    if (text[start] != '<') return null;
    for (run_names) |name| {
        if (std.mem.startsWith(u8, text[start..], name)) {
            const after = start + name.len;
            if (after >= text.len) return null;
            if (text[after] == '>') return name.len + 1;
            if (!std.ascii.isWhitespace(text[after])) return null;
            // A whitespace delimiter may be followed by the `>` the model
            // dropped (`</function >`). Consume the run of whitespace and an
            // optional `>`, so the whole tag advances and a whitespace-delimited
            // runaway still counts as a run rather than resetting on the `>`.
            var end = after;
            while (end < text.len and std.ascii.isWhitespace(text[end])) end += 1;
            if (end < text.len and text[end] == '>') end += 1;
            return end - start;
        }
    }
    return null;
}

/// True when `text` holds a run of three or more dangling XML `function`-dialect
/// close tags (`</function>`, `</function_calls>`, `</tool_calls>`, `</invoke>`,
/// `</parameter>`), optionally whitespace-separated. That run is the shape a
/// model degenerates into when it loops until the output cap, so the display
/// path hides it; a lone mention is prose or a documented sample. A run inside a
/// fenced block or inline code span is a sample too, so code regions are skipped
/// (otherwise a documented three-closer sample would blank the whole reply).
pub fn hasRepetitiveToolCloseRun(allocator: std.mem.Allocator, text: []const u8) bool {
    const code = findCodeRegionsForToolMarkup(allocator, text) catch return false;
    defer allocator.free(code);
    var i: usize = 0;
    var run: usize = 0;
    while (i < text.len) {
        if (isInsideCode(code, i)) {
            run = 0;
            i += 1;
            continue;
        }
        if (std.ascii.isWhitespace(text[i])) {
            i += 1;
            continue;
        }
        if (toolFunctionCloseLenAt(text, i)) |len| {
            run += 1;
            if (run >= 3) return true;
            i += len;
            continue;
        }
        run = 0;
        i += 1;
    }
    return false;
}

// The exact open markers the dispatcher's unclosed recovery keys on. A text tool
// call the agent would execute can only start with one of these; a payload after
// any other opener (attributes, a whitespace delimiter, a `_begin` wrapper) is
// prose, because `parseXmlToolCalls` looks for these literals verbatim.
const dispatcher_marker_tags = [_][]const u8{ "<tool_call>", "[tool_call]", "[TOOL_CALL]" };

/// Case-insensitive substring test, matching the dispatcher's strict-close rule
/// (`containsIgnoreCase(tag_content, "tool_call")` in `parseXmlToolCalls`).
pub fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i <= haystack.len - needle.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

/// A close tag found by `nextToolCallClose`.
pub const ToolCallClose = struct {
    /// Offset of the close tag's `<`/`[` within the scanned body.
    start: usize,
    /// Length of the close tag including its delimiter.
    len: usize,
    /// True when the tag name contains "tool_call" (case-insensitive), which the
    /// dispatcher prefers over any other close.
    strict: bool,
};

/// The next close tag at or after `from` in `body` (the bytes after the open
/// marker), or null. Mirrors `parseXmlToolCalls`' scan: a close is `open_char`
/// then `/` then any bytes up to the next `close_char`. `stop_at_open` selects
/// the display's stricter reading, where an `open_char` before the delimiter
/// means the tag was never terminated (the model dropped its `>`), so it is
/// skipped and the scan resumes at that opener instead of swallowing it.
pub fn nextToolCallClose(
    body: []const u8,
    from: usize,
    open_char: u8,
    close_char: u8,
    stop_at_open: bool,
) ?ToolCallClose {
    var idx = from;
    while (idx < body.len) {
        noteScan();
        const rel = std.mem.indexOfScalar(u8, body[idx..], open_char) orelse return null;
        const abs_open = idx + rel;
        if (abs_open + 1 >= body.len or body[abs_open + 1] != '/') {
            idx = abs_open + 1;
            continue;
        }
        var j = abs_open + 2;
        var delim: ?usize = null;
        while (j < body.len) : (j += 1) {
            if (body[j] == close_char) {
                delim = j;
                break;
            }
            if (stop_at_open and body[j] == open_char) break;
        }
        if (delim) |d| {
            return .{
                .start = abs_open,
                .len = d - abs_open + 1,
                .strict = containsIgnoreCase(body[abs_open + 2 .. d], "tool_call"),
            };
        }
        // The dispatcher scans the whole body for its delimiter, so a missing one
        // ends its search; the display instead resumes at the opener that cut the
        // token short (or stops at end of body).
        if (!stop_at_open) return null;
        if (j >= body.len) return null;
        idx = j;
    }
    return null;
}

/// Test-only count of the forward-scan steps taken by the shared text
/// tool-call parser and the batch strip. A linear strip examines each byte a
/// bounded number of times; the O(N^2) scans this guards against re-walked the
/// whole remaining text once per opener, so this count grew quadratically. The
/// complexity regression tests assert a linear bound on it instead of timing
/// the strip, which made them fail on a slow CI runner.
pub var scan_work: usize = 0;

/// Bump the test-only scan-work counter (see `scan_work`). A no-op outside
/// tests, so the production scans pay nothing.
inline fn noteScan() void {
    if (comptime builtin.is_test) scan_work += 1;
}

/// A single text tool call the dispatcher would execute, extracted by the
/// shared `parseDispatcherXmlToolCalls`. These are the agent dispatcher's own
/// inner-call parsers, moved here verbatim so the display paths and the
/// dispatcher accept the *same* bytes.
pub const DispatcherCall = struct {
    name: []const u8,
    arguments_json: []const u8,
};

/// Strip trailing XML tags (e.g. </arg_value>, </tool_call>) from a string.
fn stripTrailingXml(input: []const u8) []const u8 {
    const trimmed_right = std.mem.trimEnd(u8, input, " \t\r\n");
    if (trimmed_right.len == 0 or trimmed_right[trimmed_right.len - 1] != '>') return input;

    const end_tag = trimmed_right.len - 1;
    const start_tag = std.mem.lastIndexOfScalar(u8, trimmed_right[0..end_tag], '<') orelse return input;
    if (start_tag + 1 >= trimmed_right.len) return input;

    const tag_head = trimmed_right[start_tag + 1];
    const looks_like_tag = (tag_head == '/') or
        (tag_head >= 'a' and tag_head <= 'z') or
        (tag_head >= 'A' and tag_head <= 'Z');
    if (!looks_like_tag) return input;

    const tag_body = trimmed_right[start_tag + 1 .. end_tag];
    if (std.mem.indexOfScalar(u8, tag_body, '"') != null or std.mem.indexOfScalar(u8, tag_body, '\'') != null) {
        return input;
    }

    // Found what looks like a trailing tag <...> at end-of-string.
    return std.mem.trimEnd(u8, trimmed_right[0..start_tag], " \t\r\n");
}

fn isToolNameChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => true,
        else => false,
    };
}

fn isPlausibleToolName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (!isToolNameChar(c)) return false;
    }
    return true;
}

fn hasMalformedQuotedColonToolName(raw_json: []const u8) bool {
    const name_key = "\"name\"";
    const name_idx = std.mem.indexOf(u8, raw_json, name_key) orelse return false;

    var remaining = std.mem.trimStart(u8, raw_json[name_idx + name_key.len ..], " \t\r\n");
    if (remaining.len == 0 or remaining[0] != ':') return false;

    remaining = std.mem.trimStart(u8, remaining[1..], " \t\r\n");
    if (remaining.len < 2 or remaining[0] != '"') return false;

    remaining = remaining[1..];
    if (remaining.len == 0 or remaining[0] != ':') return false;

    remaining = std.mem.trimStart(u8, remaining[1..], " \t\r\n");
    return remaining.len > 0 and remaining[0] == '"';
}

fn recoverToolNameFromRawJson(raw_json: []const u8) ?[]const u8 {
    const name_key = "\"name\"";
    const arguments_key = "\"arguments\"";

    const name_idx = std.mem.indexOf(u8, raw_json, name_key) orelse return null;
    const after_name = raw_json[name_idx + name_key.len ..];
    const colon_idx = std.mem.indexOfScalar(u8, after_name, ':') orelse return null;
    const after_colon = after_name[colon_idx + 1 ..];

    const window = if (std.mem.indexOf(u8, after_colon, arguments_key)) |args_idx|
        after_colon[0..args_idx]
    else
        after_colon;

    var i: usize = 0;
    while (i < window.len) : (i += 1) {
        if (!isToolNameChar(window[i])) continue;

        const start = i;
        var end = i + 1;
        while (end < window.len and isToolNameChar(window[end])) : (end += 1) {}

        const candidate = window[start..end];
        if (!std.mem.eql(u8, candidate, "name") and !std.mem.eql(u8, candidate, "arguments")) {
            return candidate;
        }

        i = end;
    }

    return null;
}

fn extractRawArgumentsJson(raw_json: []const u8) ?[]const u8 {
    const arguments_key = "\"arguments\"";
    const args_idx = std.mem.indexOf(u8, raw_json, arguments_key) orelse return null;
    const after_args = raw_json[args_idx + arguments_key.len ..];
    const colon_idx = std.mem.indexOfScalar(u8, after_args, ':') orelse return null;
    return json_util.extractJsonObject(after_args[colon_idx + 1 ..]);
}

fn normalizeSalvagedArgumentsJson(allocator: std.mem.Allocator, raw_json: []const u8) ![]u8 {
    const args_src = extractRawArgumentsJson(raw_json) orelse return allocator.dupe(u8, "{}");
    var parsed_args = std.json.parseFromSlice(std.json.Value, allocator, args_src, .{}) catch blk: {
        const repaired = json_util.repairJson(allocator, args_src) catch return allocator.dupe(u8, "{}");
        defer allocator.free(repaired);
        break :blk std.json.parseFromSlice(std.json.Value, allocator, repaired, .{}) catch return allocator.dupe(u8, "{}");
    };
    defer parsed_args.deinit();

    return try std.json.Stringify.valueAlloc(allocator, parsed_args.value, .{});
}

fn salvageMalformedToolCallJson(allocator: std.mem.Allocator, raw_json: []const u8) !?DispatcherCall {
    if (!hasMalformedQuotedColonToolName(raw_json)) return null;

    const recovered_name = recoverToolNameFromRawJson(raw_json) orelse return null;
    if (!isPlausibleToolName(recovered_name)) return null;

    const args_json = try normalizeSalvagedArgumentsJson(allocator, raw_json);
    errdefer allocator.free(args_json);

    return .{
        .name = try allocator.dupe(u8, recovered_name),
        .arguments_json = args_json,
    };
}

fn repairMalformedParsedToolName(
    allocator: std.mem.Allocator,
    raw_json: []const u8,
    call: *DispatcherCall,
) !void {
    if (!hasMalformedQuotedColonToolName(raw_json)) return;
    if (isPlausibleToolName(call.name)) return;

    const recovered_name = recoverToolNameFromRawJson(raw_json) orelse return;
    if (!isPlausibleToolName(recovered_name)) return;

    allocator.free(call.name);
    call.name = try allocator.dupe(u8, recovered_name);
}

fn parseInnerToolCall(allocator: std.mem.Allocator, inner: []const u8) !?DispatcherCall {
    const malformed_quoted_colon_name = hasMalformedQuotedColonToolName(inner);
    if (malformed_quoted_colon_name) {
        if (try salvageMalformedToolCallJson(allocator, inner)) |recovered| {
            return recovered;
        }
    }
    if (json_util.extractJsonObject(inner)) |json_slice| {
        if (parseToolCallJson(allocator, json_slice)) |call| {
            if (malformed_quoted_colon_name and !isPlausibleToolName(call.name)) {
                if (try salvageMalformedToolCallJson(allocator, inner)) |recovered| {
                    allocator.free(call.name);
                    allocator.free(call.arguments_json);
                    return recovered;
                }
            }
            return call;
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {},
        }
    }
    if (parseFunctionTagCall(allocator, inner)) |call| {
        return call;
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {},
    }
    if (parseInvokeTagCall(allocator, inner)) |call| {
        return call;
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {},
    }
    if (parseHybridTagCall(allocator, inner)) |call| {
        return call;
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {},
    }
    if (parseNamePrefixedJsonCall(allocator, inner)) |call| {
        return call;
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {},
    }

    return null;
}

/// Parse a JSON tool call object: {"name": "...", "arguments": {...}}
/// Tries to parse as-is first, then applies JSON repair as fallback.
fn parseToolCallJson(allocator: std.mem.Allocator, json_str: []const u8) !DispatcherCall {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch blk: {
        // JSON parse failed — try repair
        const repaired = json_util.repairJson(allocator, json_str) catch return error.InvalidToolCallFormat;
        defer allocator.free(repaired);
        break :blk std.json.parseFromSlice(std.json.Value, allocator, repaired, .{}) catch {
            if (try salvageMalformedToolCallJson(allocator, json_str)) |call| return call;
            return error.InvalidToolCallFormat;
        };
    };
    var call = try parseToolCallJsonInner(allocator, parsed);
    errdefer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try repairMalformedParsedToolName(allocator, json_str, &call);

    // Fail closed on implausible names (e.g. ":") and make one last
    // attempt to recover from malformed quoted-colon payloads.
    if (!isPlausibleToolName(call.name)) {
        if (try salvageMalformedToolCallJson(allocator, json_str)) |recovered| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
            call = recovered;
        }
    }

    if (!isPlausibleToolName(call.name)) {
        return error.InvalidToolName;
    }

    return call;
}

fn parseToolCallJsonInner(allocator: std.mem.Allocator, parsed: std.json.Parsed(std.json.Value)) !DispatcherCall {
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidToolCallFormat,
    };

    // Extract name
    const name_val = obj.get("name") orelse return error.MissingToolName;
    const name_str = switch (name_val) {
        .string => |s| s,
        else => return error.InvalidToolName,
    };

    // Robustness: strip trailing XML tags and handle JSON-in-JSON hallucinations.
    const resolved_name_src = stripTrailingXml(std.mem.trim(u8, name_str, " \t\r\n"));
    var resolved_name_owned: ?[]u8 = null;

    if (std.mem.startsWith(u8, resolved_name_src, "{")) {
        const inner_parsed = std.json.parseFromSlice(std.json.Value, allocator, resolved_name_src, .{}) catch null;
        if (inner_parsed) |p| {
            defer p.deinit();
            if (p.value == .object) {
                if (p.value.object.get("name")) |n| {
                    if (n == .string) {
                        resolved_name_owned = try allocator.dupe(u8, std.mem.trim(u8, n.string, " \t\r\n"));
                    }
                }
            }
        }
    }

    const resolved_name = resolved_name_owned orelse try allocator.dupe(u8, resolved_name_src);
    errdefer allocator.free(resolved_name);

    if (resolved_name.len == 0) return error.EmptyToolName;

    // Extract arguments — re-serialize to JSON string
    const args_json = if (obj.get("arguments")) |args_val| blk: {
        switch (args_val) {
            .string => |s| {
                // Arguments is a string (possibly a JSON string) — use as-is
                break :blk try allocator.dupe(u8, s);
            },
            else => {
                // Arguments is an object/value — serialize it
                break :blk try std.json.Stringify.valueAlloc(allocator, args_val, .{});
            },
        }
    } else try allocator.dupe(u8, "{}");
    errdefer allocator.free(args_json);

    return .{
        .name = resolved_name,
        .arguments_json = args_json,
    };
}

/// Parse `<function=NAME><parameter=KEY>VALUE</parameter>...</function>` format.
///
/// Some open-source LLMs (Llama, Qwen, etc.) emit this XML-based format
/// instead of JSON inside `<tool_call>` tags. Extracts function name and
/// parameter key-value pairs, returning a `DispatcherCall` with serialized
/// JSON arguments.
fn parseFunctionTagCall(allocator: std.mem.Allocator, inner: []const u8) !DispatcherCall {
    // Expect: <function=NAME> ... </function>
    const func_prefix = "<function=";
    const func_start = std.mem.indexOf(u8, inner, func_prefix) orelse return error.NoFunctionTag;
    const after_prefix = inner[func_start + func_prefix.len ..];
    const name_end = std.mem.indexOfScalar(u8, after_prefix, '>') orelse return error.NoFunctionTag;
    const func_name = std.mem.trim(u8, after_prefix[0..name_end], " \t\r\n");
    if (func_name.len == 0) return error.EmptyFunctionName;

    // Validate function name: only alphanumeric, underscore, dash, dot allowed
    for (func_name) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => {},
            else => return error.InvalidFunctionName,
        }
    }

    // Collect <parameter=KEY>VALUE</parameter> pairs — bounded by </function>
    const full_body = after_prefix[name_end + 1 ..];
    const body = if (std.mem.indexOf(u8, full_body, "</function>")) |fc|
        full_body[0..fc]
    else
        full_body;

    var args_buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer args_buf.deinit(allocator);
    var args_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &args_buf);
    const w = &args_writer.writer;
    try w.writeByte('{');

    var remaining = body;
    var first = true;
    const param_prefix = "<parameter=";
    const param_close = "</parameter>";

    while (std.mem.indexOf(u8, remaining, param_prefix)) |ps| {
        const after_param = remaining[ps + param_prefix.len ..];
        const key_end = std.mem.indexOfScalar(u8, after_param, '>') orelse break;
        const key = std.mem.trim(u8, after_param[0..key_end], " \t\r\n");
        if (key.len == 0) break;

        const value_start = after_param[key_end + 1 ..];
        const value_end_pos = std.mem.indexOf(u8, value_start, param_close) orelse break;
        const value = std.mem.trim(u8, value_start[0..value_end_pos], " \t\r\n");

        if (!first) try w.writeByte(',');
        first = false;

        // Write "key": "value" with JSON string escaping via Stringify.valueAlloc
        const key_json = try std.json.Stringify.valueAlloc(allocator, key, .{});
        defer allocator.free(key_json);
        const val_json = try std.json.Stringify.valueAlloc(allocator, value, .{});
        defer allocator.free(val_json);
        try w.writeAll(key_json);
        try w.writeByte(':');
        try w.writeAll(val_json);

        remaining = value_start[value_end_pos + param_close.len ..];
    }

    try w.writeByte('}');

    args_buf = args_writer.toArrayList();
    const args_json = try args_buf.toOwnedSlice(allocator);
    errdefer allocator.free(args_json);
    return .{
        .name = try allocator.dupe(u8, func_name),
        .arguments_json = args_json,
    };
}

/// Parse `<invoke name=NAME><parameter name=KEY>VALUE</parameter>...</invoke>` format.
///
/// This is the tool-calling format typically used by MiniMax models.
fn parseInvokeTagCall(allocator: std.mem.Allocator, inner: []const u8) !DispatcherCall {
    // Expect: <invoke name="NAME"> ... </invoke>
    const invoke_prefix = "<invoke name=";
    const invoke_start = std.mem.indexOf(u8, inner, invoke_prefix) orelse return error.NoInvokeTag;
    const after_prefix = inner[invoke_start + invoke_prefix.len ..];

    // Tool name is usually in quotes: "name"
    const name_quote = if (after_prefix.len > 0) after_prefix[0] else ' ';
    if (name_quote != '"' and name_quote != '\'') return error.InvalidInvokeFormat;

    const name_end = std.mem.indexOfScalar(u8, after_prefix[1..], name_quote) orelse return error.InvalidInvokeFormat;
    const tool_name = std.mem.trim(u8, after_prefix[1 .. name_end + 1], " \t\r\n");
    if (tool_name.len == 0) return error.EmptyToolName;
    if (!isPlausibleToolName(tool_name)) return error.InvalidToolName;

    const invoke_close_tag = "</invoke>";
    // Look for the '>' that closes the <invoke ...> tag.
    // It might not be immediately after the name (e.g. models sometimes insert a comma or space).
    // Robustness: if we find "<parameter" before ">", then the ">" was missing entirely.
    const invoke_tag_end_pos = blk: {
        const next_gt = std.mem.indexOfScalar(u8, after_prefix[name_end + 1 ..], '>');
        const next_param = std.mem.indexOf(u8, after_prefix[name_end + 1 ..], "<parameter");
        if (next_gt) |gt_pos| {
            if (next_param) |p_pos| {
                if (p_pos < gt_pos) break :blk name_end; // missing '>', started param
            }
            break :blk name_end + 1 + gt_pos;
        }
        break :blk name_end;
    };

    const full_invoke_content = after_prefix[invoke_tag_end_pos + 1 ..];
    const invoke_body = if (std.mem.indexOf(u8, full_invoke_content, invoke_close_tag)) |ic|
        full_invoke_content[0..ic]
    else
        full_invoke_content;

    var args_buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer args_buf.deinit(allocator);
    var args_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &args_buf);
    const w = &args_writer.writer;
    try w.writeByte('{');

    var remaining = invoke_body;
    var first = true;
    const param_close = "</parameter>";

    while (remaining.len > 0) {
        const ps = std.mem.indexOf(u8, remaining, "parameter name=") orelse break;
        // Find the '<' before 'parameter'
        var tag_start = ps;
        while (tag_start > 0 and remaining[tag_start] != '<') tag_start -= 1;
        if (remaining[tag_start] != '<') {
            remaining = if (ps + 15 < remaining.len) remaining[ps + 15 ..] else "";
            continue;
        }

        const after_param = remaining[ps + 15 ..];
        const p_name_quote = if (after_param.len > 0) after_param[0] else ' ';
        if (p_name_quote != '"' and p_name_quote != '\'') break;

        const p_name_end = std.mem.indexOfScalar(u8, after_param[1..], p_name_quote) orelse break;
        const key = std.mem.trim(u8, after_param[1 .. p_name_end + 1], " \t\r\n");
        if (key.len == 0) break;

        const p_tag_end = std.mem.indexOfScalar(u8, after_param[p_name_end + 1 ..], '>') orelse break;
        const value_start = after_param[p_name_end + 1 + p_tag_end + 1 ..];
        const value_end_pos = std.mem.indexOf(u8, value_start, param_close) orelse break;
        const value = std.mem.trim(u8, value_start[0..value_end_pos], " \t\r\n");

        if (!first) try w.writeByte(',');
        first = false;

        const key_json = try std.json.Stringify.valueAlloc(allocator, key, .{});
        defer allocator.free(key_json);
        const val_json = try std.json.Stringify.valueAlloc(allocator, value, .{});
        defer allocator.free(val_json);
        try w.writeAll(key_json);
        try w.writeByte(':');
        try w.writeAll(val_json);

        remaining = value_start[value_end_pos + param_close.len ..];
    }

    try w.writeByte('}');

    args_buf = args_writer.toArrayList();
    const args_json = try args_buf.toOwnedSlice(allocator);
    errdefer allocator.free(args_json);
    return .{
        .name = try allocator.dupe(u8, tool_name),
        .arguments_json = args_json,
    };
}

/// Parse mixed/hybrid formats like: {"name": "shell", <parameter name="command">ls</parameter>}
/// This is a "greedy" fallback parser for highly malformed or mixed LLM output.
fn parseHybridTagCall(allocator: std.mem.Allocator, inner: []const u8) !DispatcherCall {
    // 1. Greedy Name Extraction
    const tool_name: []const u8 = blk: {
        // Try JSON-style name
        if (std.mem.indexOf(u8, inner, "\"name\":")) |idx| {
            const after = inner[idx + 7 ..];
            if (std.mem.indexOfScalar(u8, after, '"')) |q1| {
                if (std.mem.indexOfScalar(u8, after[q1 + 1 ..], '"')) |q2| {
                    break :blk std.mem.trim(u8, after[q1 + 1 .. q1 + 1 + q2], " \t\r\n");
                }
            }
        }
        // Try Invoke-style name
        if (std.mem.indexOf(u8, inner, "<invoke name=")) |idx| {
            const after = inner[idx + 13 ..];
            if (after.len > 0) {
                const quote = after[0];
                if (quote == '"' or quote == '\'') {
                    if (std.mem.indexOfScalar(u8, after[1..], quote)) |q_end| {
                        break :blk std.mem.trim(u8, after[1 .. q_end + 1], " \t\r\n");
                    }
                }
            }
        }
        // Try Function-style name
        if (std.mem.indexOf(u8, inner, "<function=")) |idx| {
            const after = inner[idx + 10 ..];
            if (std.mem.indexOfScalar(u8, after, '>')) |end| {
                break :blk std.mem.trim(u8, after[0..end], " \t\r\n");
            }
        }
        // Try <tool name="..."> style
        if (std.mem.indexOf(u8, inner, "<tool name=")) |idx| {
            const after = inner[idx + 11 ..];
            if (after.len > 0) {
                const quote = after[0];
                if (quote == '"' or quote == '\'') {
                    if (std.mem.indexOfScalar(u8, after[1..], quote)) |q_end| {
                        break :blk std.mem.trim(u8, after[1 .. q_end + 1], " \t\r\n");
                    }
                }
            }
        }
        return error.NoToolNameFound;
    };

    if (tool_name.len == 0) return error.EmptyToolName;
    if (!isPlausibleToolName(tool_name)) return error.InvalidToolName;

    // 2. Greedy Parameter Collection
    var args_buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer args_buf.deinit(allocator);
    var args_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &args_buf);
    const w = &args_writer.writer;
    try w.writeByte('{');

    var first = true;
    var remaining = inner;

    // Track keys we've already found to avoid duplicates
    var found_keys = std.StringHashMap(void).init(allocator);
    defer found_keys.deinit();

    // Look for XML parameters
    const p_close = "</parameter>";
    var search_idx: usize = 0;
    while (search_idx < remaining.len) {
        const ps = std.mem.indexOf(u8, remaining[search_idx..], "parameter name=") orelse break;
        const absolute_ps = search_idx + ps;
        // Find the '<' before 'parameter'
        var tag_start = absolute_ps;
        while (tag_start > 0 and remaining[tag_start] != '<') tag_start -= 1;
        if (remaining[tag_start] != '<') {
            search_idx = absolute_ps + 15;
            continue;
        }

        const after_param = remaining[absolute_ps + 15 ..];
        if (after_param.len == 0) {
            search_idx = absolute_ps + 15;
            continue;
        }
        const quote = after_param[0];
        if (quote != '"' and quote != '\'') {
            search_idx = absolute_ps + 15;
            continue;
        }
        if (std.mem.indexOfScalar(u8, after_param[1..], quote)) |q_end| {
            const key = std.mem.trim(u8, after_param[1 .. q_end + 1], " \t\r\n");
            if (std.mem.indexOfScalar(u8, after_param[q_end + 1 ..], '>')) |tag_end| {
                const val_start = after_param[q_end + 1 + tag_end + 1 ..];
                if (std.mem.indexOf(u8, val_start, p_close)) |val_end| {
                    const value = std.mem.trim(u8, val_start[0..val_end], " \t\r\n");

                    if (!found_keys.contains(key)) {
                        if (!first) try w.writeByte(',');
                        first = false;
                        const key_json = try std.json.Stringify.valueAlloc(allocator, key, .{});
                        defer allocator.free(key_json);
                        const val_json = try std.json.Stringify.valueAlloc(allocator, value, .{});
                        defer allocator.free(val_json);
                        try w.writeAll(key_json);
                        try w.writeByte(':');
                        try w.writeAll(val_json);
                        try found_keys.put(key, {});
                    }
                    search_idx = absolute_ps + 15 + q_end + 1 + tag_end + 1 + val_end + p_close.len;
                    continue;
                }
            }
        }
        search_idx = absolute_ps + 15;
    }

    // Look for JSON-style simple key-value pairs (only strings for now as greedy fallback)
    // Pattern: "key": "value"
    search_idx = 0;
    while (std.mem.indexOfScalar(u8, remaining[search_idx..], '"')) |q1| {
        const absolute_q1 = search_idx + q1;
        const after_q1 = remaining[absolute_q1 + 1 ..];
        if (std.mem.indexOfScalar(u8, after_q1, '"')) |q2| {
            const key = after_q1[0..q2];
            const after_key = after_q1[q2 + 1 ..];
            // Look for ':' and then another string
            var i: usize = 0;
            while (i < after_key.len and (after_key[i] == ' ' or after_key[i] == ':')) i += 1;
            if (i < after_key.len and after_key[i] == '"') {
                const val_start = after_key[i + 1 ..];
                if (std.mem.indexOfScalar(u8, val_start, '"')) |val_q_end| {
                    const value = val_start[0..val_q_end];
                    if (!found_keys.contains(key) and !std.mem.eql(u8, key, "name") and !std.mem.eql(u8, key, "arguments")) {
                        if (!first) try w.writeByte(',');
                        first = false;
                        const key_json = try std.json.Stringify.valueAlloc(allocator, key, .{});
                        defer allocator.free(key_json);
                        const val_json = try std.json.Stringify.valueAlloc(allocator, value, .{});
                        defer allocator.free(val_json);
                        try w.writeAll(key_json);
                        try w.writeByte(':');
                        try w.writeAll(val_json);
                        try found_keys.put(key, {});
                    }
                    search_idx = absolute_q1 + 1 + q2 + 1 + i + 1 + val_q_end + 1;
                    continue;
                }
            }
        }
        search_idx = absolute_q1 + 1;
    }

    try w.writeByte('}');

    args_buf = args_writer.toArrayList();
    const args_json = try args_buf.toOwnedSlice(allocator);
    errdefer allocator.free(args_json);
    return .{
        .name = try allocator.dupe(u8, tool_name),
        .arguments_json = args_json,
    };
}

/// Parse compact tool-call format: `tool_name{...json arguments...}`.
///
/// Some compatible providers occasionally emit this form inside `<tool_call>`
/// when they fail to produce the strict JSON envelope.
fn parseNamePrefixedJsonCall(allocator: std.mem.Allocator, inner: []const u8) !DispatcherCall {
    const cleaned = std.mem.trim(u8, stripTrailingXml(inner), " \t\r\n");
    const obj_start = std.mem.indexOfScalar(u8, cleaned, '{') orelse return error.NoPrefixedJsonCall;
    if (obj_start == 0) return error.NoPrefixedJsonCall;

    const name = std.mem.trim(u8, cleaned[0..obj_start], " \t\r\n:");
    if (name.len == 0) return error.EmptyToolName;
    for (name) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => {},
            else => return error.InvalidToolName,
        }
    }

    const args_src = std.mem.trim(u8, cleaned[obj_start..], " \t\r\n");
    var parsed_args = std.json.parseFromSlice(std.json.Value, allocator, args_src, .{}) catch blk: {
        const repaired = json_util.repairJson(allocator, args_src) catch return error.InvalidToolArguments;
        defer allocator.free(repaired);
        break :blk std.json.parseFromSlice(std.json.Value, allocator, repaired, .{}) catch return error.InvalidToolArguments;
    };
    defer parsed_args.deinit();

    if (parsed_args.value != .object) return error.InvalidToolArguments;

    const args_json = try std.json.Stringify.valueAlloc(allocator, parsed_args.value, .{});
    errdefer allocator.free(args_json);
    return .{
        .name = try allocator.dupe(u8, name),
        .arguments_json = args_json,
    };
}

/// Parse the text tool calls out of a response, exactly like
/// the agent dispatcher's `parseXmlToolCalls`. Returns the
/// joined visible text, the extracted calls, and the byte
/// span of every dispatcher-marker block (closed or
/// unclosed) the scan swallowed. This is the single
/// authority for "is this a text tool call the agent would
/// execute", shared by the dispatcher, the streaming
/// `TagFilter`, and the batch `stripToolCallMarkup`, so
/// what the agent runs and what the display hides are
/// decided by the same code.
///
/// Only the XML text-tool-call grammar is handled here; the
/// native OpenAI JSON format is the dispatcher's own entry
/// point (`dispatcher.parseToolCalls`) and is out of scope
/// for the display paths, which strip text markup, not
/// provider-native payloads.
pub const DispatcherXmlResult = struct {
    text: []const u8,
    calls: []DispatcherCall,
    /// Byte spans (start, end) of every dispatcher-marker
    /// block the scan swallowed, in document order. `end`
    /// is just past the close tag for a closed block, or
    /// `text.len` for an unclosed block the dispatcher
    /// would execute.
    blocks: []BlockSpan,
};

pub const BlockSpan = struct {
    start: usize,
    end: usize,
};

pub fn parseDispatcherXmlToolCalls(
    allocator: std.mem.Allocator,
    response: []const u8,
) !DispatcherXmlResult {
    var text_parts: std.ArrayListUnmanaged([]const u8) = .empty;
    defer text_parts.deinit(allocator);

    var calls: std.ArrayListUnmanaged(DispatcherCall) = .empty;
    errdefer {
        for (calls.items) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        calls.deinit(allocator);
    }

    var blocks: std.ArrayListUnmanaged(BlockSpan) = .empty;
    defer blocks.deinit(allocator);

    var remaining = response;
    var base: usize = 0;
    while (true) {
        const marker_info: ?struct { start: usize, end: usize, open_char: u8, close_char: u8 } = blk: {
            // Only `<` and `[` can start a dispatcher marker, so one
            // vectorized scan for either finds the next candidate; the
            // candidate is checked against the marker list and, when it is
            // not one, the scan resumes just past it. Every byte of the
            // response is therefore examined a constant number of times,
            // even when no marker of a given dialect occurs at all.
            var search_pos: usize = 0;
            while (search_pos < remaining.len) {
                noteScan();
                const p = std.mem.indexOfAnyPos(u8, remaining, search_pos, "<[") orelse break;
                for (dispatcher_marker_tags) |m| {
                    if (std.mem.startsWith(u8, remaining[p..], m)) {
                        break :blk .{
                            .start = p,
                            .end = p + m.len,
                            .open_char = m[0],
                            .close_char = if (m[0] == '[') ']' else '>',
                        };
                    }
                }
                search_pos = p + 1;
            }
            break :blk null;
        };

        if (marker_info == null) break;
        const info = marker_info.?;
        const start = base + info.start;

        const after_open = remaining[info.end..];
        // Flexible closing tag: prefer tags whose name
        // contains "tool_call"; fall back to the first
        // closing tag (handles malformed outputs like a bare
        // `</x>` close). The scan is shared with the
        // dispatcher (see `nextToolCallClose`).
        var strict_end: ?usize = null;
        var strict_end_tag_len: usize = 0;
        var fallback_first_end: ?usize = null;
        var fallback_first_end_tag_len: usize = 0;
        var fallback_last_end: ?usize = null;
        var fallback_last_end_tag_len: usize = 0;
        var scan_from: usize = 0;
        while (nextToolCallClose(after_open, scan_from, info.open_char, info.close_char, false)) |close| {
            if (fallback_first_end == null) {
                fallback_first_end = close.start;
                fallback_first_end_tag_len = close.len;
            }
            fallback_last_end = close.start;
            fallback_last_end_tag_len = close.len;
            if (close.strict) {
                strict_end = close.start;
                strict_end_tag_len = close.len;
                break;
            }
            scan_from = close.start + close.len;
        }

        const found_end = strict_end orelse fallback_first_end;
        var end_tag_len = if (strict_end != null) strict_end_tag_len else fallback_first_end_tag_len;

        if (found_end) |end| {
            const before = std.mem.trim(u8, remaining[0..info.start], " \t\r\n");
            if (before.len > 0) {
                try text_parts.append(allocator, before);
            }

            var selected_end = end;
            var parsed_call: ?DispatcherCall = null;

            // If we only have malformed close-tags (no
            // strict </tool_call>), prefer the last
            // close-tag first.
            if (strict_end == null) {
                if (fallback_last_end) |last_end| {
                    if (last_end != selected_end) {
                        const last_inner = std.mem.trim(u8, after_open[0..last_end], " \t\r\n");
                        parsed_call = try parseInnerToolCall(allocator, last_inner);
                        if (parsed_call != null) {
                            selected_end = last_end;
                            end_tag_len = fallback_last_end_tag_len;
                        }
                    }
                }
            }

            if (parsed_call == null) {
                const inner = std.mem.trim(u8, after_open[0..selected_end], " \t\r\n");
                parsed_call = try parseInnerToolCall(allocator, inner);
            }

            if (parsed_call) |call| {
                errdefer {
                    allocator.free(call.name);
                    allocator.free(call.arguments_json);
                }
                try calls.append(allocator, call);
            }
            // A block is only a block the *display* must hide when the
            // dispatcher would execute a call from it. Markup around a block
            // whose payload is not a call is left to the ordinary tag
            // handling, so a stray `<tool_call>` in prose is released. This is
            // outside the per-call `errdefer` so a failed append does not free
            // a call that is already in `calls`.
            if (parsed_call != null) {
                try blocks.append(allocator, .{
                    .start = start,
                    .end = start + (info.end - info.start) + selected_end + end_tag_len,
                });
            }

            remaining = after_open[selected_end + end_tag_len ..];
            base = start + (info.end - info.start) + selected_end + end_tag_len;
        } else {
            const inner_unclosed = std.mem.trim(u8, after_open, " \t\r\n");
            var recovered = false;

            if (inner_unclosed.len > 0) {
                if (inner_unclosed[0] == '{' and inner_unclosed[inner_unclosed.len - 1] == '}') {
                    if (parseToolCallJson(allocator, inner_unclosed)) |call| {
                        errdefer {
                            allocator.free(call.name);
                            allocator.free(call.arguments_json);
                        }
                        const before = std.mem.trim(u8, remaining[0..info.start], " \t\r\n");
                        if (before.len > 0) try text_parts.append(allocator, before);
                        try calls.append(allocator, call);
                        recovered = true;
                    } else |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => {},
                    }
                }

                if (!recovered) {
                    if (parseNamePrefixedJsonCall(allocator, inner_unclosed)) |call| {
                        errdefer {
                            allocator.free(call.name);
                            allocator.free(call.arguments_json);
                        }
                        const before = std.mem.trim(u8, remaining[0..info.start], " \t\r\n");
                        if (before.len > 0) try text_parts.append(allocator, before);
                        try calls.append(allocator, call);
                        recovered = true;
                    } else |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => {},
                    }
                }
            }

            if (!recovered) {
                const unresolved = std.mem.trim(u8, remaining, " \t\r\n");
                if (unresolved.len > 0) {
                    try text_parts.append(allocator, unresolved);
                }
            }

            // Only a block the dispatcher would *execute* swallows the rest
            // of the text. An unclosed opener whose payload is prose is
            // released as ordinary text (`parseXmlToolCalls` appends it to
            // `text_parts`), so it is not a block at all.
            if (recovered) {
                try blocks.append(allocator, .{ .start = start, .end = response.len });
            }

            remaining = "";
            break;
        }
    }

    const trailing = std.mem.trim(u8, remaining, " \t\r\n");
    if (trailing.len > 0) {
        try text_parts.append(allocator, trailing);
    }

    const text = if (text_parts.items.len == 0)
        try allocator.dupe(u8, "")
    else
        try std.mem.join(allocator, "\n", text_parts.items);
    errdefer allocator.free(text);

    const calls_slice = try calls.toOwnedSlice(allocator);
    errdefer {
        for (calls_slice) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(calls_slice);
    }
    const blocks_slice = try blocks.toOwnedSlice(allocator);

    return .{
        .text = text,
        .calls = calls_slice,
        .blocks = blocks_slice,
    };
}

/// Byte offset just past the close tag starting at `start`, or null when the
/// bytes there are not a close tag. Mirrors the streaming `TagFilter`: the name
/// may be delimited by `>` or any whitespace (`</tool_call >`); the `>` that
/// ends the tag is consumed either way, and a `<` seen before it means the
/// token was unterminated (see `scanTagTokenEnd`). `eof_drops` selects the
/// end-of-text behaviour: a delimiter-less close name at the very end is an
/// unterminated token that the top level drops (`text.len`), while a tool body
/// simply stays open (null).
fn matchToolCallClose(text: []const u8, start: usize, eof_drops: bool) ?usize {
    for (tool_call_close_names) |name| {
        if (!std.mem.startsWith(u8, text[start..], name)) continue;
        const after = start + name.len;
        if (after >= text.len) return if (eof_drops) text.len else null;
        if (text[after] != '>' and !std.ascii.isWhitespace(text[after])) continue;
        return scanTagTokenEnd(text, after);
    }
    return null;
}

/// Offset just past the `>` that ends a tag token whose name already matched at
/// `from`, or the offset of a `<` seen first. Mirrors the streaming `TagFilter`:
/// a `<` before the token's `>` means the token was unterminated, so it is
/// dropped and the caller reprocesses from that `<`. A token with no `>` before
/// the end of `text` is unterminated too, so `text.len` is returned.
fn scanTagTokenEnd(text: []const u8, from: usize) usize {
    var i = from;
    while (i < text.len) : (i += 1) {
        if (text[i] == '>') return i + 1;
        if (text[i] == '<') return i;
    }
    return text.len;
}

/// Length of a complete tag *name* at `start` that is immediately followed by
/// `<` (the model dropped the tag's `>`), or null. Mirrors the streaming
/// `TagFilter`'s `.lt` fallback: the unterminated name is dropped and the `<`
/// is reprocessed.
fn unterminatedTagNameLen(text: []const u8, start: usize) ?usize {
    return nameFollowedByLt(text, start, &tool_call_open_tags) orelse
        nameFollowedByLt(text, start, &tool_call_close_names) orelse
        nameFollowedByLt(text, start, &tool_call_standalone_names);
}

fn nameFollowedByLt(text: []const u8, start: usize, names: []const []const u8) ?usize {
    for (names) |name| {
        if (!std.mem.startsWith(u8, text[start..], name)) continue;
        const after = start + name.len;
        if (after < text.len and text[after] == '<') return name.len;
    }
    return null;
}

/// Byte offset just past the tool-call block opened at `start`, or null when no
/// block open tag starts there or the block never closes. Mirrors the streaming
/// `TagFilter`: the open tag may carry attributes, or the model may omit the
/// `>` so the body starts right after the tag name; and a block whose close tag
/// never arrives is left alone (released by the caller), so a stray
/// `<tool_call>` in prose cannot swallow the rest of the text.
fn skipToolCallBlock(text: []const u8, start: usize, scanner: *CloseScanner) ?usize {
    // Longest matching open tag wins, so `<tool_call_begin` beats `<tool_call`.
    var open_len: usize = 0;
    for (tool_call_open_tags) |open| {
        if (open.len <= open_len) continue;
        if (!std.mem.startsWith(u8, text[start..], open)) continue;
        const after = start + open.len;
        // A delimiter-less open name at the end of the text is an unterminated
        // token: the remainder is dropped, exactly like the streaming filter.
        if (after >= text.len) return text.len;
        if (text[after] != '>' and !std.ascii.isWhitespace(text[after])) continue;
        open_len = open.len;
    }
    if (open_len == 0) return null;

    // The scanner answers the suffix search from its cache, so an opener that
    // never closes (the adversarial case) is not re-scanned to end-of-string
    // for every opener.
    const close = scanner.nextMatchClose(start + open_len) orelse return null;
    return close.end;
}
fn skipToolCallStandalone(text: []const u8, start: usize) ?usize {
    for (tool_call_standalone_names) |name| {
        if (!std.mem.startsWith(u8, text[start..], name)) continue;
        const after = start + name.len;
        // A delimiter-less token at the end of the text is unterminated and is
        // dropped, exactly like the streaming filter.
        if (after >= text.len) return text.len;
        if (text[after] != '>' and !std.ascii.isWhitespace(text[after])) continue;
        return scanTagTokenEnd(text, after);
    }
    return null;
}

/// Byte offset just past a `[tool_call]` / `[TOOL_CALL]` block starting at
/// `start`, or null when the bytes there are not such a marker. A stray close
/// marker is dropped on its own. A closed block is normally covered by the
/// shared parse's block spans; this only mops up a stray `[/tool_call]` the
/// parse did not claim. Mirrors the streaming `TagFilter`.
fn skipBracketToolCall(text: []const u8, start: usize) ?usize {
    const rest = text[start..];
    const open: []const u8 = if (std.mem.startsWith(u8, rest, "[tool_call]"))
        "[tool_call]"
    else if (std.mem.startsWith(u8, rest, "[TOOL_CALL]"))
        "[TOOL_CALL]"
    else if (std.mem.startsWith(u8, rest, "[/tool_call]"))
        "[/tool_call]"
    else if (std.mem.startsWith(u8, rest, "[/TOOL_CALL]"))
        "[/TOOL_CALL]"
    else
        return null;

    if (open[1] == '/') return start + open.len; // stray close marker

    const payload_start = start + open.len;
    var close_end: ?usize = null;
    for ([_][]const u8{ "[/tool_call]", "[/TOOL_CALL]" }) |close| {
        if (std.mem.indexOf(u8, text[payload_start..], close)) |rel| {
            const abs = payload_start + rel + close.len;
            if (close_end == null or abs < close_end.?) close_end = abs;
        }
    }
    return close_end;
}

/// True when `text` contains one of the exact dispatcher open markers, so the
/// shared parse has something to find.
fn containsDispatcherMarker(text: []const u8) bool {
    for (dispatcher_marker_tags) |m| {
        if (std.mem.indexOf(u8, text, m) != null) return true;
    }
    return false;
}

/// True when an exact dispatcher open marker starts at `start`. Such a marker is
/// never prose, so the code-region guard still strips it inside a fence.
fn isDispatcherMarkerAt(text: []const u8, start: usize) bool {
    for (dispatcher_marker_tags) |m| {
        if (std.mem.startsWith(u8, text[start..], m)) return true;
    }
    return false;
}

/// True when a dispatcher-marker block (`marker + body + close tag`, exactly as
/// the streaming `TagFilter` buffers it) must be hidden from the display.
///
/// A tool-call payload is JSON (`{...}`) or a tool name, both ASCII, so a block
/// whose body begins with anything else (e.g. CJK prose) is text that merely
/// *names* the markers: the dispatcher executes no call from it and the display
/// must release it rather than swallow it. When the body could be a payload the
/// shared dispatcher parse decides, so the display hides exactly the calls the
/// agent would execute.
pub fn hidesDispatcherBlock(allocator: std.mem.Allocator, block: []const u8) bool {
    var marker_len: usize = 0;
    for (dispatcher_marker_tags) |m| {
        if (std.mem.startsWith(u8, block, m)) {
            marker_len = m.len;
            break;
        }
    }
    if (marker_len == 0) return true;
    if (bodyLooksLikeCallPayload(block[marker_len..])) return true;

    const result = parseDispatcherXmlToolCalls(allocator, block) catch return true;
    defer {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
        allocator.free(result.blocks);
    }
    return result.calls.len > 0;
}

/// True when `body` (the bytes after an open marker) begins like a tool-call
/// payload: `{` or an ASCII word character (a tool name). A payload is ASCII, so
/// a body that begins otherwise cannot be a call the dispatcher would execute.
fn bodyLooksLikeCallPayload(body: []const u8) bool {
    const t = std.mem.trimStart(u8, body, " \t\r\n");
    if (t.len == 0) return false;
    const c = t[0];
    return c == '{' or c == '_' or std.ascii.isAlphanumeric(c);
}

/// A forward-only close-tag scanner for the batch strip loop.
///
/// The strip loop asks the same two suffix questions at every opener: where is
/// the next dispatcher-dialect close (`</...>` / `[/...]`) after this one, and
/// where is the next `matchToolCallClose` hit. The answer for a later opener is
/// never behind the answer for an earlier one, so caching the last answer (and
/// resuming from it) turns the repeated scans that used to walk to
/// end-of-string into a single linear pass. That is what keeps
/// `stripToolCallMarkup` linear on text dense with unclosed openers — the
/// O(N^2) case the review found.
const CloseScanner = struct {
    text: []const u8,
    /// True once a dispatcher-dialect close scan has run for the current
    /// dialect. `dispatcher_close` is then the first close at or after
    /// `dispatcher_from` (null when none exists there), in `text` coordinates.
    dispatcher_valid: bool = false,
    dispatcher_from: usize = 0,
    dispatcher_close: ?ToolCallClose = null,
    dispatcher_open_ch: u8 = '<',
    dispatcher_close_ch: u8 = '>',
    /// True once a `matchToolCallClose` scan has run. `match_start` is then the
    /// first hit at or after `match_from` (null when none exists there).
    match_valid: bool = false,
    match_from: usize = 0,
    match_start: ?usize = null,
    match_end: usize = 0,

    fn init(text: []const u8) CloseScanner {
        return .{ .text = text };
    }

    /// The first dispatcher-dialect close at or after `body_start` (the byte
    /// after an opener), in coordinates relative to `body_start`.
    fn nextDispatcherClose(self: *CloseScanner, body_start: usize, open_ch: u8, close_ch: u8) ?ToolCallClose {
        const dialect_changed = self.dispatcher_open_ch != open_ch or self.dispatcher_close_ch != close_ch;
        if (!dialect_changed and self.dispatcher_valid and body_start >= self.dispatcher_from) {
            if (self.dispatcher_close) |close| {
                const abs = self.dispatcher_from + close.start;
                if (abs >= body_start) {
                    return .{ .start = abs - body_start, .len = close.len, .strict = close.strict };
                }
            } else {
                // No close exists at or after `dispatcher_from`, and
                // `body_start >= dispatcher_from`, so none exists here either.
                return null;
            }
        }
        // (Re)scan from `body_start` for this dialect.
        self.dispatcher_open_ch = open_ch;
        self.dispatcher_close_ch = close_ch;
        self.dispatcher_from = body_start;
        self.dispatcher_valid = true;
        self.dispatcher_close = nextToolCallClose(self.text[body_start..], 0, open_ch, close_ch, false);
        return self.dispatcher_close;
    }

    /// The first `matchToolCallClose` hit at or after `from`, as an absolute
    /// span. Close names all start with `<`, so the scan jumps `<` to `<`.
    fn nextMatchClose(self: *CloseScanner, from: usize) ?struct { start: usize, end: usize } {
        if (self.match_valid and from >= self.match_from) {
            if (self.match_start) |s| {
                if (s >= from) return .{ .start = s, .end = self.match_end };
            } else {
                return null;
            }
        }
        var p = from;
        while (std.mem.indexOfScalarPos(u8, self.text, p, '<')) |lt| {
            noteScan();
            if (matchToolCallClose(self.text, lt, false)) |end| {
                self.match_valid = true;
                self.match_from = from;
                self.match_start = lt;
                self.match_end = end;
                return .{ .start = lt, .end = end };
            }
            p = lt + 1;
        }
        self.match_valid = true;
        self.match_from = from;
        self.match_start = null;
        return null;
    }
};

/// When the exact dispatcher-marker block at `start` is prose (so the display
/// must release it verbatim), return the end of the block — just past its close
/// tag. Returns null when `start` is not such a block, so the caller keeps the
/// ordinary (hide) handling.
fn dispatcherBlockReleaseEnd(
    allocator: std.mem.Allocator,
    text: []const u8,
    start: usize,
    scanner: *CloseScanner,
) ?usize {
    var marker_len: usize = 0;
    for (dispatcher_marker_tags) |m| {
        if (std.mem.startsWith(u8, text[start..], m)) {
            marker_len = m.len;
            break;
        }
    }
    if (marker_len == 0) return null;

    const open_ch: u8 = if (text[start] == '[') '[' else '<';
    const close_ch: u8 = if (text[start] == '[') ']' else '>';
    const close = scanner.nextDispatcherClose(start + marker_len, open_ch, close_ch) orelse
        return null;
    const end = start + marker_len + close.start + close.len;
    if (hidesDispatcherBlock(allocator, text[start..end])) return null;
    return end;
}

/// Strip tool-call markup (the tags and the JSON/argument body between them)
/// from `text`. Returns a caller-owned slice.
///
/// The output is derived from the one shared dispatcher parse
/// (`parseDispatcherXmlToolCalls`): every dispatcher-marker block the agent
/// would execute — and the markup around a block whose payload is not a call,
/// which the dispatcher drops too — is removed using the parse's block spans,
/// computed once for the whole string. A bare opener in prose (no dispatcher
/// marker) is ordinary text and is kept. Provider markup (DSML, `_begin`
/// wrappers, standalone tokens, stray closes) is handled here as before; the
/// `<think>` tags are preserved verbatim.
/// The two forward close scans (the dispatcher-block release check and the
/// tool-block skip) share a `CloseScanner` whose cursor only advances, so the
/// strip stays linear on text dense with unclosed openers.
pub fn stripToolCallMarkup(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    if (!hasToolCallMarkup(text)) return allocator.dupe(u8, text);

    var blocks: []const BlockSpan = &.{};
    var parsed: ?DispatcherXmlResult = null;
    if (containsDispatcherMarker(text)) {
        parsed = parseDispatcherXmlToolCalls(allocator, text) catch null;
        if (parsed) |result| blocks = result.blocks;
    }
    defer if (parsed) |result| {
        allocator.free(result.text);
        for (result.calls) |call| {
            allocator.free(call.name);
            allocator.free(call.arguments_json);
        }
        allocator.free(result.calls);
        allocator.free(result.blocks);
    };

    // Forward-only close scans: both the dispatcher-block release check and the
    // tool-block skip ask suffix questions, so caching the last answer keeps the
    // strip linear even when the text is dense with unclosed openers.
    var scanner = CloseScanner.init(text);

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    // Track `<think>` nesting so an unterminated provider marker inside a
    // reasoning region ends at `</think>` instead of swallowing the terminator
    // and the answer (parity with the streaming `TagFilter`). The tags
    // themselves are preserved verbatim, exactly as before.
    var think_depth: usize = 0;
    var block_idx: usize = 0;
    var i: usize = 0;
    // A `<function>`/`</function>`/`<parameter>` tag inside a code fence or
    // inline span is a literal sample, not markup (OpenClaw's `isInsideCode`).
    // The dispatcher's own markers are still stripped inside code: they are
    // never prose. An *unterminated* fence does not count as code here
    // (`findCodeRegionsForToolMarkup`): a garbled closer after an unclosed fence
    // is markup, not a sample.
    const code = try findCodeRegionsForToolMarkup(allocator, text);
    defer allocator.free(code);
    while (i < text.len) {
        // A dispatcher-marker block the shared parse swallowed: skip its whole
        // span (tags and body) in one step.
        while (block_idx < blocks.len and blocks[block_idx].start < i) block_idx += 1;
        if (block_idx < blocks.len and blocks[block_idx].start == i) {
            i = blocks[block_idx].end;
            block_idx += 1;
            continue;
        }
        // A non-dispatcher tag byte inside a code region is a literal sample:
        // copy it verbatim rather than running the markup scan over it.
        if ((text[i] == '<' or text[i] == '[') and isInsideCode(code, i) and
            !isDispatcherMarkerAt(text, i))
        {
            try out.append(allocator, text[i]);
            i += 1;
            continue;
        }
        if (text[i] == '<') {
            if (std.mem.startsWith(u8, text[i..], think_open_tag)) {
                think_depth += 1;
                try out.appendSlice(allocator, think_open_tag);
                i += think_open_tag.len;
                continue;
            }
            if (std.mem.startsWith(u8, text[i..], think_close_tag)) {
                if (think_depth > 0) think_depth -= 1;
                try out.appendSlice(allocator, think_close_tag);
                i += think_close_tag.len;
                continue;
            }
            // An unterminated tag name (`<tool_call<`, ...): drop the name and
            // reprocess the `<`, exactly like the streaming `TagFilter`.
            if (unterminatedTagNameLen(text, i)) |len| {
                i += len;
                continue;
            }
            // An exact dispatcher-marker block whose payload is prose (no call
            // the dispatcher would execute) is released verbatim — tags and
            // body — matching the streaming `TagFilter`. Inside a reasoning
            // region a block is always hidden, again matching the filter.
            if (think_depth == 0) {
                if (dispatcherBlockReleaseEnd(allocator, text, i, &scanner)) |end| {
                    try out.appendSlice(allocator, text[i..end]);
                    i = end;
                    continue;
                }
            }
            if (skipToolCallBlock(text, i, &scanner)) |end| {
                i = end;
                continue;
            }
            if (skipToolCallStandalone(text, i)) |end| {
                i = end;
                continue;
            }
            // A stray close tag with no opener is still tool markup, exactly as
            // the streaming `TagFilter` treats it.
            if (matchToolCallClose(text, i, true)) |end| {
                i = end;
                continue;
            }
        } else if (text[i] == '[') {
            if (think_depth == 0) {
                if (dispatcherBlockReleaseEnd(allocator, text, i, &scanner)) |end| {
                    try out.appendSlice(allocator, text[i..end]);
                    i = end;
                    continue;
                }
            }
            if (skipBracketToolCall(text, i)) |end| {
                i = end;
                continue;
            }
        }
        try out.append(allocator, text[i]);
        i += 1;
    }
    return out.toOwnedSlice(allocator);
}
fn scanThinkContent(
    allocator: std.mem.Allocator,
    text: []const u8,
    visible_out: *std.ArrayListUnmanaged(u8),
    reasoning_out: ?*std.ArrayListUnmanaged(u8),
) !void {
    var i: usize = 0;
    var depth: usize = 0;
    // Offset in `visible_out` at the last reasoning-tag boundary, so an orphan
    // closer's "before" is the run since that tag (OpenClaw's `beforeTag`),
    // while the reset still drops every accumulated draft byte.
    var seg_start: usize = 0;
    while (i < text.len) {
        if (text[i] == '<') {
            if (matchThinkTag(text, i)) |tag| {
                if (tag.close) {
                    if (depth > 0) {
                        depth -= 1;
                    } else if (tag.namespaced and
                        hasOrphanReasoningCloseBoundary(visible_out.items[seg_start..], text[i + tag.len ..]))
                    {
                        // A stray *namespaced* reasoning closer (`</ifm|think>`):
                        // the visible text before it was leaked reasoning (a draft
                        // the model wrote as thinking), not the answer. Drop it
                        // and keep only what follows, matching OpenClaw's
                        // orphan-close rule. The plain `</think>` is excluded: a
                        // reply may name that tag in prose ("the closing tag is
                        // </think>."), and OpenClaw's batch splitter keeps the
                        // preceding text there instead of losing it.
                        visible_out.clearRetainingCapacity();
                        seg_start = 0;
                    }
                } else {
                    depth += 1;
                }
                i += tag.len;
                seg_start = visible_out.items.len;
                continue;
            }
        }
        if (depth == 0) {
            try visible_out.append(allocator, text[i]);
        } else if (reasoning_out) |reasoning_buf| {
            try reasoning_buf.append(allocator, text[i]);
        }
        i += 1;
    }
}

/// Split `text` into visible content and reasoning extracted from <think>…</think> blocks.
/// Both returned slices are caller-owned (allocated with `allocator`).
pub fn splitThinkContent(allocator: std.mem.Allocator, text: []const u8) !SplitThinkContent {
    if (!hasThinkTag(text)) {
        return .{
            .visible = try allocator.dupe(u8, text),
            .reasoning = null,
        };
    }

    var visible_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer visible_buf.deinit(allocator);
    var reasoning_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer reasoning_buf.deinit(allocator);

    try scanThinkContent(allocator, text, &visible_buf, &reasoning_buf);

    const visible_trimmed = std.mem.trim(u8, visible_buf.items, " \t\r\n");
    const visible = try allocator.dupe(u8, visible_trimmed);
    errdefer allocator.free(visible);

    const reasoning_trimmed = std.mem.trim(u8, reasoning_buf.items, " \t\r\n");
    const reasoning = if (reasoning_trimmed.len > 0) try allocator.dupe(u8, reasoning_trimmed) else null;

    return .{ .visible = visible, .reasoning = reasoning };
}

/// Strip all <think>…</think> blocks from `text`. Returns caller-owned slice.
pub fn stripThinkBlocks(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    if (!hasThinkTag(text)) {
        return allocator.dupe(u8, text);
    }

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try scanThinkContent(allocator, text, &out, null);

    const cleaned = try out.toOwnedSlice(allocator);
    const trimmed = std.mem.trim(u8, cleaned, " \t\r\n");
    if (trimmed.ptr == cleaned.ptr and trimmed.len == cleaned.len) return cleaned;
    defer allocator.free(cleaned);
    return allocator.dupe(u8, trimmed);
}

fn appendReasoningDetailText(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    detail: std.json.Value,
) !void {
    if (detail != .object) return;
    const obj = detail.object;

    if (obj.get("type")) |type_val| {
        if (type_val == .string and std.mem.eql(u8, type_val.string, "reasoning.encrypted")) return;
    }

    const text = blk: {
        if (obj.get("text")) |value| {
            if (value == .string and value.string.len > 0) break :blk value.string;
        }
        if (obj.get("summary")) |value| {
            if (value == .string and value.string.len > 0) break :blk value.string;
        }
        break :blk null;
    } orelse return;

    if (out.items.len > 0) try out.append(allocator, '\n');
    try out.appendSlice(allocator, text);
}

/// Extract plain-text reasoning from OpenRouter/OpenAI-style `reasoning_details`.
/// Encrypted detail variants are intentionally ignored.
pub fn extractReasoningTextFromDetails(allocator: std.mem.Allocator, details: std.json.Value) !?[]const u8 {
    if (details != .array) return null;

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(allocator);

    for (details.array.items) |detail| {
        try appendReasoningDetailText(&out, allocator, detail);
    }

    const trimmed = std.mem.trim(u8, out.items, " \t\r\n");
    if (trimmed.len == 0) return null;
    const owned = try allocator.dupe(u8, trimmed);
    return owned;
}

/// Append OpenAI-compatible request extras:
/// - `user` sourced from the upstream session_id
/// - arbitrary top-level JSON fields from `extra_body_params`
///
/// `extra_body_params` is expected to be a compact JSON object string such as
/// `{"seed":123,"metadata":{"tier":"pro"}}`. Parsing happens at config-load
/// time; request builders only splice the already-validated object body.
pub fn appendOpenAiBodyExtraParams(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    session_id: ?[]const u8,
    extra_body_params: ?[]const u8,
) !void {
    if (session_id) |sid| {
        try buf.appendSlice(allocator, ",\"user\":");
        try json_util.appendJsonString(buf, allocator, sid);
    }

    if (extra_body_params) |extra| {
        const trimmed = std.mem.trim(u8, extra, " \t\r\n");
        if (trimmed.len < 2 or trimmed[0] != '{' or trimmed[trimmed.len - 1] != '}') return;

        const inner = std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t\r\n");
        if (inner.len == 0) return;

        try buf.append(allocator, ',');
        try buf.appendSlice(allocator, inner);
    }
}

/// Check if a model name indicates an OpenAI reasoning model
/// (o1, o3, o4-mini, gpt-5*, codex-mini).
pub fn isReasoningModel(model: []const u8) bool {
    return std.mem.startsWith(u8, model, "gpt-5") or
        std.mem.startsWith(u8, model, "o1") or
        std.mem.startsWith(u8, model, "o3") or
        std.mem.startsWith(u8, model, "o4-mini") or
        std.mem.startsWith(u8, model, "codex-mini");
}

/// Append model-specific generation controls to a JSON request body buffer:
/// - non-reasoning: `temperature` + optional `max_tokens`
/// - reasoning + reasoning_effort=="none": `temperature` + `max_completion_tokens`
/// - reasoning (otherwise): `max_completion_tokens` only (no temperature)
/// Always emits normalized `reasoning_effort` when set on a reasoning model.
/// OpenAI-compatible reasoning values are normalized as:
/// - `minimal` -> `low`
/// - `xhigh` -> `high`
pub fn appendGenerationFields(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    model: []const u8,
    temperature: f64,
    max_tokens: ?u32,
    reasoning_effort: ?[]const u8,
) !void {
    if (!isReasoningModel(model)) {
        // Non-reasoning model: temperature + max_tokens
        try buf.appendSlice(allocator, ",\"temperature\":");
        var temp_buf: [16]u8 = undefined;
        const temp_str = std.fmt.bufPrint(&temp_buf, "{d:.2}", .{temperature}) catch return error.FormatError;
        try buf.appendSlice(allocator, temp_str);

        if (max_tokens) |max_tok| {
            try buf.appendSlice(allocator, ",\"max_tokens\":");
            var max_buf: [16]u8 = undefined;
            const max_str = std.fmt.bufPrint(&max_buf, "{d}", .{max_tok}) catch return error.FormatError;
            try buf.appendSlice(allocator, max_str);
        }
        return;
    }

    const normalized_effort = normalizeOpenAiReasoningEffort(reasoning_effort);

    // Reasoning model: temperature only if reasoning_effort == "none"
    const effort_is_none = if (normalized_effort) |re| std.mem.eql(u8, re, "none") else false;
    if (effort_is_none) {
        try buf.appendSlice(allocator, ",\"temperature\":");
        var temp_buf: [16]u8 = undefined;
        const temp_str = std.fmt.bufPrint(&temp_buf, "{d:.2}", .{temperature}) catch return error.FormatError;
        try buf.appendSlice(allocator, temp_str);
    }

    // Reasoning model: always use max_completion_tokens instead of max_tokens
    if (max_tokens) |max_tok| {
        try buf.appendSlice(allocator, ",\"max_completion_tokens\":");
        var max_buf: [16]u8 = undefined;
        const max_str = std.fmt.bufPrint(&max_buf, "{d}", .{max_tok}) catch return error.FormatError;
        try buf.appendSlice(allocator, max_str);
    }

    // Emit reasoning_effort when set (JSON-escaped for safety)
    if (normalized_effort) |re| {
        try buf.appendSlice(allocator, ",\"reasoning_effort\":");
        try json_util.appendJsonString(buf, allocator, re);
    }
}

pub fn normalizeOpenAiReasoningEffort(reasoning_effort: ?[]const u8) ?[]const u8 {
    const raw = reasoning_effort orelse return null;
    if (std.ascii.eqlIgnoreCase(raw, "none")) return "none";
    if (std.ascii.eqlIgnoreCase(raw, "minimal")) return "low";
    if (std.ascii.eqlIgnoreCase(raw, "low")) return "low";
    if (std.ascii.eqlIgnoreCase(raw, "medium")) return "medium";
    if (std.ascii.eqlIgnoreCase(raw, "high") or std.ascii.eqlIgnoreCase(raw, "xhigh")) return "high";
    return raw;
}

const GeminiReasoningEffort = enum {
    none,
    minimal,
    low,
    medium,
    high,
    xhigh,
};

const GeminiThinkingProfile = union(enum) {
    level: []const u8,
    budget: u32,
};

const GeminiThinkingTarget = enum {
    gemini_api,
    vertex_ai,
};

fn parseGeminiReasoningEffort(reasoning_effort: ?[]const u8) ?GeminiReasoningEffort {
    const raw = reasoning_effort orelse return null;
    if (std.ascii.eqlIgnoreCase(raw, "off") or std.ascii.eqlIgnoreCase(raw, "none")) return .none;
    if (std.ascii.eqlIgnoreCase(raw, "minimal")) return .minimal;
    if (std.ascii.eqlIgnoreCase(raw, "low")) return .low;
    if (std.ascii.eqlIgnoreCase(raw, "medium")) return .medium;
    if (std.ascii.eqlIgnoreCase(raw, "high")) return .high;
    if (std.ascii.eqlIgnoreCase(raw, "xhigh")) return .xhigh;
    return null;
}

fn geminiThinkingProfile(model: []const u8, reasoning_effort: ?[]const u8) ?GeminiThinkingProfile {
    const effort = parseGeminiReasoningEffort(reasoning_effort) orelse return null;

    var lower_buf: [160]u8 = undefined;
    const lower_len = @min(model.len, lower_buf.len);
    for (model[0..lower_len], 0..) |c, idx| {
        lower_buf[idx] = std.ascii.toLower(c);
    }
    const lower = lower_buf[0..lower_len];

    const is_gemini_3 = std.mem.indexOf(u8, lower, "gemini-3") != null;
    const is_gemini_25 = std.mem.indexOf(u8, lower, "gemini-2.5") != null;
    const is_flash = std.mem.indexOf(u8, lower, "flash") != null;
    const is_pro = std.mem.indexOf(u8, lower, "pro") != null;

    // Gemini 3 family: use thinking levels.
    // Gemini 3 Pro supports only low/high, while Flash supports minimal/low/medium/high.
    if (is_gemini_3) {
        if (is_flash) {
            return .{
                .level = switch (effort) {
                    .none => "minimal",
                    .minimal => "minimal",
                    .low => "low",
                    .medium => "medium",
                    .high, .xhigh => "high",
                },
            };
        }
        return .{
            .level = switch (effort) {
                .high, .xhigh => "high",
                .none, .minimal, .low, .medium => "low",
            },
        };
    }

    // Gemini 2.5 family: use thinking budget.
    if (is_gemini_25) {
        return switch (effort) {
            .none => if (is_pro) null else .{ .budget = 0 },
            .minimal, .low => .{ .budget = 1024 },
            .medium => .{ .budget = 8192 },
            .high, .xhigh => .{ .budget = 24576 },
        };
    }

    return null;
}

/// Append Gemini/Vertex thinking controls under generationConfig when reasoning effort is set.
/// Mapping:
/// - Gemini 3 models => `thinkingConfig.thinkingLevel`
/// - Gemini 2.5 models => `thinkingConfig.thinkingBudget`
pub fn appendGeminiThinkingConfig(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    model: []const u8,
    reasoning_effort: ?[]const u8,
) !void {
    return appendThinkingConfigForTarget(buf, allocator, model, reasoning_effort, .gemini_api);
}

/// Append Vertex thinking controls under generationConfig when reasoning effort is set.
/// Vertex expects enum-style uppercase values for `thinkingLevel`.
pub fn appendVertexThinkingConfig(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    model: []const u8,
    reasoning_effort: ?[]const u8,
) !void {
    return appendThinkingConfigForTarget(buf, allocator, model, reasoning_effort, .vertex_ai);
}

fn normalizeVertexThinkingLevel(level: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(level, "minimal")) return "MINIMAL";
    if (std.ascii.eqlIgnoreCase(level, "low")) return "LOW";
    if (std.ascii.eqlIgnoreCase(level, "medium")) return "MEDIUM";
    return "HIGH";
}

fn appendThinkingConfigForTarget(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    model: []const u8,
    reasoning_effort: ?[]const u8,
    target: GeminiThinkingTarget,
) !void {
    const profile = geminiThinkingProfile(model, reasoning_effort) orelse return;

    try buf.appendSlice(allocator, ",\"thinkingConfig\":{\"includeThoughts\":true,");
    switch (profile) {
        .level => |level| {
            try buf.appendSlice(allocator, "\"thinkingLevel\":");
            const out_level = switch (target) {
                .gemini_api => level,
                .vertex_ai => normalizeVertexThinkingLevel(level),
            };
            try json_util.appendJsonString(buf, allocator, out_level);
        },
        .budget => |budget| {
            try buf.appendSlice(allocator, "\"thinkingBudget\":");
            var budget_buf: [16]u8 = undefined;
            const budget_str = std.fmt.bufPrint(&budget_buf, "{d}", .{budget}) catch return error.FormatError;
            try buf.appendSlice(allocator, budget_str);
        },
    }
    try buf.append(allocator, '}');
}

/// Serialize a single message's content field (plain string or multimodal content parts array).
/// OpenAI format: text → {"type":"text","text":"..."}, image_url → {"type":"image_url","image_url":{"url":"...","detail":"..."}},
/// image_base64 → {"type":"image_url","image_url":{"url":"data:mime;base64,..."}}.
/// Used by OpenAI, OpenRouter, and Compatible providers.
/// Serialize a single content part (text, image_url, or image_base64) to a JSON string.
pub fn serializeContentPart(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, part: root.ContentPart) !void {
    switch (part) {
        .text => |text| {
            try buf.appendSlice(allocator, "{\"type\":\"text\",\"text\":");
            try json_util.appendJsonString(buf, allocator, text);
            try buf.append(allocator, '}');
        },
        .image_url => |img| {
            try buf.appendSlice(allocator, "{\"type\":\"image_url\",\"image_url\":{\"url\":");
            try json_util.appendJsonString(buf, allocator, img.url);
            try buf.appendSlice(allocator, ",\"detail\":\"");
            try buf.appendSlice(allocator, img.detail.toSlice());
            try buf.appendSlice(allocator, "\"}}");
        },
        .image_base64 => |img| {
            // OpenAI accepts base64 images as data URIs in image_url
            // Build data URI with escaped media_type
            try buf.appendSlice(allocator, "{\"type\":\"image_url\",\"image_url\":{\"url\":\"data:");
            // media_type is from detectMimeType (e.g. "image/png") — safe,
            // but escape for defense-in-depth
            for (img.media_type) |c| {
                switch (c) {
                    '"' => try buf.appendSlice(allocator, "\\\""),
                    '\\' => try buf.appendSlice(allocator, "\\\\"),
                    else => try buf.append(allocator, c),
                }
            }
            try buf.appendSlice(allocator, ";base64,");
            try buf.appendSlice(allocator, img.data);
            try buf.appendSlice(allocator, "\"}}");
        },
    }
}

pub fn serializeMessageContent(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, msg: root.ChatMessage) !void {
    if (msg.content_parts) |parts| {
        try buf.append(allocator, '[');
        for (parts, 0..) |part, j| {
            if (j > 0) try buf.append(allocator, ',');
            try serializeContentPart(buf, allocator, part);
        }
        try buf.append(allocator, ']');
    } else {
        try json_util.appendJsonString(buf, allocator, msg.content);
    }
}

/// Serialize tool definitions into an OpenAI-format JSON array, appending directly into `buf`.
/// Format: [{"type":"function","function":{"name":"...","description":"...","parameters":{...}}}]
pub fn convertToolsOpenAI(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, tools: []const ToolSpec) !void {
    if (tools.len == 0) {
        try buf.appendSlice(allocator, "[]");
        return;
    }
    try buf.append(allocator, '[');
    for (tools, 0..) |tool, i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.appendSlice(allocator, "{\"type\":\"function\",\"function\":{\"name\":");
        try json_util.appendJsonString(buf, allocator, tool.name);
        try buf.appendSlice(allocator, ",\"description\":");
        try json_util.appendJsonString(buf, allocator, tool.description);
        try buf.appendSlice(allocator, ",\"parameters\":");
        try buf.appendSlice(allocator, tool.parameters_json);
        try buf.appendSlice(allocator, "}}");
    }
    try buf.append(allocator, ']');
}

/// Serialize tool definitions into an Anthropic-format JSON array, appending directly into `buf`.
/// Format: [{"name":"...","description":"...","input_schema":{...}}]
pub fn convertToolsAnthropic(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, tools: []const ToolSpec) !void {
    if (tools.len == 0) {
        try buf.appendSlice(allocator, "[]");
        return;
    }
    try buf.append(allocator, '[');
    for (tools, 0..) |tool, i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.appendSlice(allocator, "{\"name\":");
        try json_util.appendJsonString(buf, allocator, tool.name);
        try buf.appendSlice(allocator, ",\"description\":");
        try json_util.appendJsonString(buf, allocator, tool.description);
        try buf.appendSlice(allocator, ",\"input_schema\":");
        try buf.appendSlice(allocator, tool.parameters_json);
        try buf.append(allocator, '}');
    }
    try buf.append(allocator, ']');
}

/// Serialize tool definitions into a Responses-API-format JSON array, appending directly into `buf`.
/// Format: [{"type":"function","name":"...","description":"...","parameters":{...}}]
/// Note: flat format — no nested "function" wrapper (unlike OpenAI format).
pub fn convertToolsResponses(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, tools: []const ToolSpec) !void {
    if (tools.len == 0) {
        try buf.appendSlice(allocator, "[]");
        return;
    }
    try buf.append(allocator, '[');
    for (tools, 0..) |tool, i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.appendSlice(allocator, "{\"type\":\"function\",\"name\":");
        try json_util.appendJsonString(buf, allocator, tool.name);
        try buf.appendSlice(allocator, ",\"description\":");
        try json_util.appendJsonString(buf, allocator, tool.description);
        try buf.appendSlice(allocator, ",\"parameters\":");
        try buf.appendSlice(allocator, tool.parameters_json);
        try buf.append(allocator, '}');
    }
    try buf.append(allocator, ']');
}

/// HTTP POST with optional LLM timeout (seconds). 0 = no limit.
/// Automatically reads proxy from HTTPS_PROXY, HTTP_PROXY, or ALL_PROXY environment variables.
fn curlTimeoutArg(buf: *[32]u8, timeout_secs: u64) ?[]const u8 {
    if (timeout_secs == 0) return null;
    return std.fmt.bufPrint(buf, "{d}", .{timeout_secs}) catch unreachable;
}

fn curlPostTypedTimed(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    content_type: []const u8,
    timeout_secs: u64,
) ![]u8 {
    const resolve_entry = http_util.buildSafeResolveEntryForRemoteUrl(allocator, url) catch |err| switch (err) {
        error.InvalidUrl, error.HostResolutionFailed, error.LocalAddressBlocked => return err,
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer if (resolve_entry) |entry| allocator.free(entry);

    var timeout_buf: [32]u8 = undefined;
    const response = try http_util.curlRequestWithStatusAndHeaders(allocator, .{
        .method = .POST,
        .url = url,
        .body = body,
        .headers = headers,
        .content_type = content_type,
        .max_time = curlTimeoutArg(&timeout_buf, timeout_secs),
        .resolve_entry = resolve_entry,
        .accept_compression = true,
        .std_http_defaults = true,
    });
    allocator.free(response.headers);
    errdefer allocator.free(response.body);
    if (response.status_code < 200 or response.status_code >= 300) return error.HttpStatusError;
    return response.body;
}

pub fn curlPostTimed(allocator: std.mem.Allocator, url: []const u8, body: []const u8, headers: []const []const u8, timeout_secs: u64) ![]u8 {
    return curlPostTypedTimed(allocator, url, body, headers, "application/json", timeout_secs);
}

/// HTTP POST (application/x-www-form-urlencoded) with optional timeout.
/// Automatically reads proxy from HTTPS_PROXY, HTTP_PROXY, or ALL_PROXY environment variables.
pub fn curlPostFormTimed(allocator: std.mem.Allocator, url: []const u8, body: []const u8, timeout_secs: u64) ![]u8 {
    return curlPostTypedTimed(allocator, url, body, &.{}, "application/x-www-form-urlencoded", timeout_secs);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "provider curl timeout argument preserves zero and finite values" {
    var buf: [32]u8 = undefined;
    try std.testing.expect(curlTimeoutArg(&buf, 0) == null);
    try std.testing.expectEqualStrings("300", curlTimeoutArg(&buf, 300).?);
}

test "convertToolsOpenAI produces valid JSON" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const tools = &[_]ToolSpec{
        .{
            .name = "shell",
            .description = "Run a \"shell\" command",
            .parameters_json = "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}}}",
        },
        .{
            .name = "file_read",
            .description = "Read a file",
            .parameters_json = "{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}}}",
        },
    };
    try convertToolsOpenAI(&buf, alloc, tools);
    const json = buf.items;

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;
    try std.testing.expectEqual(@as(usize, 2), arr.items.len);

    const t0 = arr.items[0].object;
    try std.testing.expectEqualStrings("function", t0.get("type").?.string);
    const f0 = t0.get("function").?.object;
    try std.testing.expectEqualStrings("shell", f0.get("name").?.string);
    // Description with quotes should be properly escaped
    try std.testing.expect(std.mem.indexOf(u8, f0.get("description").?.string, "\"shell\"") != null);
    try std.testing.expect(f0.get("parameters").? == .object);

    const f1 = arr.items[1].object.get("function").?.object;
    try std.testing.expectEqualStrings("file_read", f1.get("name").?.string);
}

test "convertToolsOpenAI empty tools" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    try convertToolsOpenAI(&buf, alloc, &.{});
    try std.testing.expectEqualStrings("[]", buf.items);
}

test "convertToolsAnthropic produces valid JSON" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const tools = &[_]ToolSpec{
        .{
            .name = "shell",
            .description = "Run a command",
            .parameters_json = "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}}}",
        },
    };
    try convertToolsAnthropic(&buf, alloc, tools);
    const json = buf.items;

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;
    try std.testing.expectEqual(@as(usize, 1), arr.items.len);

    const t0 = arr.items[0].object;
    try std.testing.expectEqualStrings("shell", t0.get("name").?.string);
    try std.testing.expectEqualStrings("Run a command", t0.get("description").?.string);
    try std.testing.expect(t0.get("input_schema").? == .object);
}

test "convertToolsAnthropic empty tools" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    try convertToolsAnthropic(&buf, alloc, &.{});
    try std.testing.expectEqualStrings("[]", buf.items);
}

test "convertToolsResponses produces flat format" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const tools = &[_]ToolSpec{
        .{
            .name = "shell",
            .description = "Run a shell command",
            .parameters_json = "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}}}",
        },
        .{
            .name = "file_read",
            .description = "Read a file",
            .parameters_json = "{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}}}",
        },
    };
    try convertToolsResponses(&buf, alloc, tools);
    const json = buf.items;

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;
    try std.testing.expectEqual(@as(usize, 2), arr.items.len);

    // Verify flat format: "name" at top level, no nested "function" key
    const t0 = arr.items[0].object;
    try std.testing.expectEqualStrings("function", t0.get("type").?.string);
    try std.testing.expect(t0.get("function") == null); // Must NOT have nested "function"
    try std.testing.expectEqualStrings("shell", t0.get("name").?.string);
    try std.testing.expectEqualStrings("Run a shell command", t0.get("description").?.string);
    try std.testing.expect(t0.get("parameters").? == .object);

    const t1 = arr.items[1].object;
    try std.testing.expectEqualStrings("file_read", t1.get("name").?.string);
}

test "convertToolsResponses empty tools" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    try convertToolsResponses(&buf, alloc, &.{});
    try std.testing.expectEqualStrings("[]", buf.items);
}

test "serializeMessageContent plain text" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const msg = root.ChatMessage.user("Hello world");
    try serializeMessageContent(&buf, alloc, msg);
    try std.testing.expectEqualStrings("\"Hello world\"", buf.items);
}

test "serializeMessageContent with content_parts text" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const parts = &[_]root.ContentPart{
        .{ .text = "Describe this" },
    };
    const msg = root.ChatMessage{
        .role = .user,
        .content = "Describe this",
        .content_parts = parts,
    };
    try serializeMessageContent(&buf, alloc, msg);
    // Should produce an array with a text part
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;
    try std.testing.expectEqual(@as(usize, 1), arr.items.len);
    try std.testing.expectEqualStrings("text", arr.items[0].object.get("type").?.string);
    try std.testing.expectEqualStrings("Describe this", arr.items[0].object.get("text").?.string);
}

test "serializeMessageContent with image_base64 part" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const parts = &[_]root.ContentPart{
        .{ .text = "What is this?" },
        .{ .image_base64 = .{ .data = "iVBOR", .media_type = "image/png" } },
    };
    const msg = root.ChatMessage{
        .role = .user,
        .content = "What is this?",
        .content_parts = parts,
    };
    try serializeMessageContent(&buf, alloc, msg);
    // Verify it produces valid JSON with data URI
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "data:image/png;base64,iVBOR") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"type\":\"image_url\"") != null);
}

test "serializeMessageContent with image_url part" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);
    const parts = &[_]root.ContentPart{
        .{ .image_url = .{ .url = "https://example.com/cat.jpg" } },
    };
    const msg = root.ChatMessage{
        .role = .user,
        .content = "",
        .content_parts = parts,
    };
    try serializeMessageContent(&buf, alloc, msg);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const arr = parsed.value.array;
    try std.testing.expectEqual(@as(usize, 1), arr.items.len);
    const img_obj = arr.items[0].object.get("image_url").?.object;
    try std.testing.expectEqualStrings("https://example.com/cat.jpg", img_obj.get("url").?.string);
    try std.testing.expectEqualStrings("auto", img_obj.get("detail").?.string);
}

test "appendGenerationFields normalizes minimal reasoning effort for gpt-5" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"model\":\"gpt-5\"");
    try appendGenerationFields(&buf, alloc, "gpt-5", 0.2, 4096, "minimal");
    try buf.append(alloc, '}');

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("low", obj.get("reasoning_effort").?.string);
    try std.testing.expect(obj.get("temperature") == null);
    try std.testing.expectEqual(@as(i64, 4096), obj.get("max_completion_tokens").?.integer);
}

test "appendGenerationFields normalizes xhigh reasoning effort for gpt-5" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"model\":\"gpt-5\"");
    try appendGenerationFields(&buf, alloc, "gpt-5", 0.2, 2048, "xhigh");
    try buf.append(alloc, '}');

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("high", obj.get("reasoning_effort").?.string);
    try std.testing.expect(obj.get("temperature") == null);
    try std.testing.expectEqual(@as(i64, 2048), obj.get("max_completion_tokens").?.integer);
}

test "appendGeminiThinkingConfig uses thinkingLevel for gemini-3 flash" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"generationConfig\":{\"maxOutputTokens\":1024");
    try appendGeminiThinkingConfig(&buf, alloc, "gemini-3.1-flash", "medium");
    try buf.appendSlice(alloc, "}}");

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const cfg = parsed.value.object.get("generationConfig").?.object;
    const thinking = cfg.get("thinkingConfig").?.object;
    try std.testing.expectEqualStrings("medium", thinking.get("thinkingLevel").?.string);
    try std.testing.expect(thinking.get("includeThoughts").?.bool == true);
}

test "appendGeminiThinkingConfig maps unsupported gemini-3 pro medium to low level" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"generationConfig\":{\"maxOutputTokens\":1024");
    try appendGeminiThinkingConfig(&buf, alloc, "gemini-3.1-pro-preview", "medium");
    try buf.appendSlice(alloc, "}}");

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const cfg = parsed.value.object.get("generationConfig").?.object;
    const thinking = cfg.get("thinkingConfig").?.object;
    try std.testing.expectEqualStrings("low", thinking.get("thinkingLevel").?.string);
}

test "appendGeminiThinkingConfig uses thinkingBudget for gemini-2.5 flash" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"generationConfig\":{\"maxOutputTokens\":1024");
    try appendGeminiThinkingConfig(&buf, alloc, "gemini-2.5-flash", "high");
    try buf.appendSlice(alloc, "}}");

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const cfg = parsed.value.object.get("generationConfig").?.object;
    const thinking = cfg.get("thinkingConfig").?.object;
    try std.testing.expectEqual(@as(i64, 24576), thinking.get("thinkingBudget").?.integer);
    try std.testing.expect(thinking.get("includeThoughts").?.bool == true);
}

test "appendGeminiThinkingConfig omits none budget for gemini-2.5 pro" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"generationConfig\":{\"maxOutputTokens\":1024");
    try appendGeminiThinkingConfig(&buf, alloc, "gemini-2.5-pro", "none");
    try buf.appendSlice(alloc, "}}");

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const cfg = parsed.value.object.get("generationConfig").?.object;
    try std.testing.expect(cfg.get("thinkingConfig") == null);
}

test "appendVertexThinkingConfig uses uppercase thinkingLevel for gemini-3 flash" {
    const alloc = std.testing.allocator;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    try buf.appendSlice(alloc, "{\"generationConfig\":{\"maxOutputTokens\":1024");
    try appendVertexThinkingConfig(&buf, alloc, "gemini-3.1-flash", "medium");
    try buf.appendSlice(alloc, "}}");

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{});
    defer parsed.deinit();
    const cfg = parsed.value.object.get("generationConfig").?.object;
    const thinking = cfg.get("thinkingConfig").?.object;
    try std.testing.expectEqualStrings("MEDIUM", thinking.get("thinkingLevel").?.string);
    try std.testing.expect(thinking.get("includeThoughts").?.bool == true);
}

test "scanThinkTag recognizes plain, namespaced and pipe reasoning tags" {
    const tags = [_][]const u8{
        "<think>",     "</think>",
        "<thinking>",  "</thinking>",
        "<ifm|think>", "</ifm|think>",
        "<mm:think>",  "</mm:thinking>",
        "<|think|>",   "</|think|>",
    };
    for (tags) |tag| {
        switch (scanThinkTag(tag)) {
            .complete => |t| {
                try std.testing.expectEqual(tag.len, t.len);
                try std.testing.expectEqual(tag[1] == '/', t.close);
            },
            else => return error.TestUnexpectedResult,
        }
    }
}

test "scanThinkTag rejects ordinary tags and partial prefixes" {
    try std.testing.expect(scanThinkTag("<div>") == .none);
    try std.testing.expect(scanThinkTag("<tool_call>") == .none);
    try std.testing.expect(scanThinkTag("<ifm|answer>") == .none);
    try std.testing.expect(scanThinkTag("<b") == .partial);
    try std.testing.expect(scanThinkTag("<think") == .partial);
    try std.testing.expect(scanThinkTag("<ifm|think") == .partial);
}

test "splitThinkContent drops the leaked draft before an orphan namespaced closer" {
    // Regression: before `scanThinkTag`, only `<think>`/`</think>` were
    // recognised, so the namespaced closer stayed ordinary text and the leaked
    // draft before it was returned as the visible answer.
    const a = std.testing.allocator;
    // The prod shape: the gateway leaks a complete draft answer as content,
    // then the model's own closing reasoning tag (no opener), then the answer.
    const input = "Draft answer A.\n</ifm|think>\nThe real answer B.";
    const split = try splitThinkContent(a, input);
    defer a.free(split.visible);
    defer if (split.reasoning) |r| a.free(r);
    try std.testing.expectEqualStrings("The real answer B.", split.visible);
    try std.testing.expect(split.reasoning == null);
}

test "splitThinkContent keeps text after an orphan closer only when it is non-empty" {
    const a = std.testing.allocator;
    const split = try splitThinkContent(a, "answer</ifm|think>");
    defer a.free(split.visible);
    defer if (split.reasoning) |r| a.free(r);
    try std.testing.expectEqualStrings("answer", split.visible);
}

test "splitThinkContent extracts a namespaced reasoning block" {
    // Regression: a namespaced reasoning block used to be returned verbatim in
    // `visible` with no reasoning split.
    const a = std.testing.allocator;
    const split = try splitThinkContent(a, "<ifm|think>reasoning</ifm|think>Answer");
    defer a.free(split.visible);
    defer if (split.reasoning) |r| a.free(r);
    try std.testing.expectEqualStrings("Answer", split.visible);
    try std.testing.expectEqualStrings("reasoning", split.reasoning.?);
}

test "stripThinkBlocks drops the leaked draft before an orphan namespaced closer" {
    // Regression: the leaked draft was returned because the namespaced closer
    // was not a recognised reasoning tag.
    const a = std.testing.allocator;
    const out = try stripThinkBlocks(a, "Draft answer A.\n</ifm|think>\nThe real answer B.");
    defer a.free(out);
    try std.testing.expectEqualStrings("The real answer B.", out);
}

test "stripToolCallMarkup drops stray function close tags" {
    // Regression: the XML `function` dialect was not in the tag set, so a
    // degenerate loop of `</function>` closers reached the user verbatim.
    const a = std.testing.allocator;
    const out = try stripToolCallMarkup(a, "Answer</function></function></function>");
    defer a.free(out);
    try std.testing.expectEqualStrings("Answer", out);
}

test "stripToolCallMarkup hides a function_calls block" {
    const a = std.testing.allocator;
    const out = try stripToolCallMarkup(a, "A<function_calls><invoke name=\"shell\"></invoke></function_calls>B");
    defer a.free(out);
    try std.testing.expectEqualStrings("AB", out);
}

test "hasToolCallMarkup detects the function dialect" {
    try std.testing.expect(hasToolCallMarkup("</function>"));
    try std.testing.expect(hasToolCallMarkup("<function_calls>"));
    try std.testing.expect(!hasToolCallMarkup("plain answer"));
}

test "hasRepetitiveToolCloseRun detects the function-dialect runaway" {
    // Regression: `</function` is a prefix of `</function_calls`, and the run
    // tag names were tested shortest-first, so a `</function_calls>` run went
    // undetected.
    const a = std.testing.allocator;
    try std.testing.expect(hasRepetitiveToolCloseRun(a, "</function></function></function>"));
    try std.testing.expect(hasRepetitiveToolCloseRun(a, "</function>\n</function>\n</function>"));
    try std.testing.expect(hasRepetitiveToolCloseRun(a, "</function_calls></function_calls></function_calls>"));
    try std.testing.expect(hasRepetitiveToolCloseRun(a, "</tool_calls></tool_calls></tool_calls>"));
    // Regression: a whitespace-delimited runaway (`</function >`, the model
    // dropped the `>`) advanced only past the space, so the trailing `>` reset
    // the run counter and the loop went undetected.
    try std.testing.expect(hasRepetitiveToolCloseRun(a, "</function ></function ></function >"));
    try std.testing.expect(hasRepetitiveToolCloseRun(a, "</function >\n</function >\n</function >"));
    try std.testing.expect(!hasRepetitiveToolCloseRun(a, "</function></function>"));
    try std.testing.expect(!hasRepetitiveToolCloseRun(a, "<function_calls><invoke name=\"x\"></invoke></function_calls>"));
    // Regression: a run inside a code fence is a documented sample, but it was
    // counted as a runaway, which blanked the whole reply.
    try std.testing.expect(!hasRepetitiveToolCloseRun(a, "```xml\n</function></function></function>\n```"));
}

test "stripToolCallMarkup removes the K2 tool call and keeps surrounding text" {
    const allocator = std.testing.allocator;
    const input = "Before <tool_call>\n{\"name\": \"shell\", \"arguments\": {\"command\": \"echo leakcheck-5\"}}\n</tool_call> after";
    const out = try stripToolCallMarkup(allocator, input);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("Before  after", out);
}

test "stripToolCallMarkup leaves prose and code naming tool_call untouched" {
    const allocator = std.testing.allocator;
    const input = "Call the `tool_call` helper, or the [tool_call] section.";
    const out = try stripToolCallMarkup(allocator, input);
    defer allocator.free(out);
    try std.testing.expectEqualStrings(input, out);
}

test "stripToolCallMarkup removes begin-style tool blocks" {
    // Regression: `<tool_call` matched before `<tool_call_begin`, and the
    // delimiter check rejected the `_`, so begin blocks were never stripped.
    const allocator = std.testing.allocator;
    const input = "A<tool_call_begin>{\"name\":\"shell\"}</tool_call>B";
    const out = try stripToolCallMarkup(allocator, input);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("AB", out);
}

test "stripToolCallMarkup removes pipe-delimited begin blocks" {
    const allocator = std.testing.allocator;
    const input = "A<|tool_call_begin|>{\"name\":\"shell\"}<|tool_call_end|>B";
    const out = try stripToolCallMarkup(allocator, input);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("AB", out);
}

test "stripToolCallMarkup does not swallow text after an unmatched tool open tag" {
    // Regression: an unmatched `<tool_call>` in prose ate the rest of the text.
    const allocator = std.testing.allocator;
    const input = "See the <tool_call> docs for details.";
    const out = try stripToolCallMarkup(allocator, input);
    defer allocator.free(out);
    try std.testing.expectEqualStrings(input, out);
}

test "stripToolCallMarkup removes blocks with a whitespace-delimited close tag" {
    // Regression: opens accepted a whitespace delimiter (`<tool_call >`) but
    // closes were matched exactly, so a symmetric omission of the `>` leaked the
    // whole call verbatim. Mirrors the streaming TagFilter.
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "A<tool_call >{\"x\":1}</tool_call >B",
        "A<tool_call>{\"x\":1}</tool_call\n>B",
        "A<tool_call >{\"x\":1}</tool_call>B",
    };
    for (cases) |input| {
        const out = try stripToolCallMarkup(allocator, input);
        defer allocator.free(out);
        try std.testing.expectEqualStrings("AB", out);
    }
}

test "stripToolCallMarkup removes a tool block whose body contains a blank line" {
    // Regression: the paragraph-break bail-out left a well-formed block (open
    // tag, body and close tag) in the text as soon as the body contained a blank
    // line. Mirrors the streaming TagFilter.
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "A<tool_call>{\"x\":1}\n\nstill body</tool_call>B",
        "A<tool_call>b\r\n\r\nc</tool_call>B",
    };
    for (cases) |input| {
        const out = try stripToolCallMarkup(allocator, input);
        defer allocator.free(out);
        try std.testing.expectEqualStrings("AB", out);
    }
}

test "stripToolCallMarkup removes standalone tokens with an omitted delimiter" {
    // Regression: standalone tokens were matched exactly, so `<..._section_begin >`
    // (and the other `>`-omitted forms) leaked verbatim. Mirrors the streaming
    // TagFilter.
    const allocator = std.testing.allocator;
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
    for (cases) |input| {
        const out = try stripToolCallMarkup(allocator, input);
        defer allocator.free(out);
        try std.testing.expectEqualStrings("AB", out);
    }
}

test "stripToolCallMarkup drops an unterminated close tag before </think>" {
    // Regression: a close tag with its `>` omitted right before `</think>` used
    // to eat up to the `>` of `</think>`. Mirrors the streaming TagFilter.
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "<think>x</tool_call </think>Ans",
        "<think>x</tool_call\n</think>Ans",
        "<think>x<tool_call>body</tool_call </think>Ans",
    };
    for (cases) |input| {
        const out = try stripToolCallMarkup(allocator, input);
        defer allocator.free(out);
        try std.testing.expectEqualStrings("<think>x</think>Ans", out);
    }
}

test "stripToolCallMarkup drops an unterminated standalone token before a tool block" {
    // Regression: a standalone token with its `>` omitted over-consumed up to
    // the `>` of the following `<tool_call>` opener, leaking the body. Mirrors
    // the streaming TagFilter.
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "A<tool_calls_section_begin <tool_call>{\"n\":1}</tool_call>B",
        "A<tool_calls_section_end <tool_call>{\"n\":1}</tool_call>B",
        "A<tool_call_argument_begin <tool_call>{\"n\":1}</tool_call>B",
        "A<|tool_calls_section_begin| <tool_call>{\"n\":1}</tool_call>B",
        "A</tool_call <tool_call>{\"n\":1}</tool_call>B",
    };
    for (cases) |input| {
        const out = try stripToolCallMarkup(allocator, input);
        defer allocator.free(out);
        try std.testing.expectEqualStrings("AB", out);
    }
}

test "stripToolCallMarkup drops an incomplete close tag immediately before </think>" {
    // Regression: `</tool_call` immediately followed by `<` was emitted, so a
    // following `</think>` was kept as text. Mirrors the streaming TagFilter.
    const allocator = std.testing.allocator;
    const out = try stripToolCallMarkup(allocator, "<think>x</tool_call</think>Ans");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("<think>x</think>Ans", out);
}

test "stripToolCallMarkup drops a stray close tag like the streaming filter" {
    // Regression: a stray close tag with no opener was swallowed by the
    // streaming TagFilter but left verbatim here, and this output is
    // user-visible via the `Reasoning:` quote in composeFinalReply.
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "A</tool_call>B",
        "A</tool_call >B",
        "A</tool_result>B",
    };
    for (cases) |input| {
        const out = try stripToolCallMarkup(allocator, input);
        defer allocator.free(out);
        try std.testing.expectEqualStrings("AB", out);
    }
}

test "stripToolCallMarkup strips a tool call whose body exceeds the old 4 KiB window" {
    // Regression: a well-formed text tool call with a multi-KiB body used to be
    // left verbatim once the body outgrew the 4096-byte window. Mirrors the
    // streaming TagFilter window.
    const allocator = std.testing.allocator;
    const body = "x" ** 5000;
    const call = "<tool_call>\n{\"name\": \"shell\", \"arguments\": {\"command\": \"" ++ body ++ "\"}}\n</tool_call>";
    const out = try stripToolCallMarkup(allocator, call);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("", out);
}

test "stripToolCallMarkup hides an unterminated tool call the dispatcher would execute" {
    // Regression: K2 streams `<tool_call>\n{json}` with no close tag; the agent's
    // parseXmlToolCalls still executes it, but stripToolCallMarkup left the tags
    // and JSON verbatim, so the `Reasoning:` quote in composeFinalReply leaked
    // them. The dispatcher accepts the raw JSON, or a repaired body (trailing
    // comma / unbalanced brace / unbalanced quote), or a `name{...}` prefix.
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "<tool_call>\n{\"name\": \"shell\", \"arguments\": {\"command\": \"echo leakcheck-7\"}}",
        "<tool_call>{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\",}}",
        "<tool_call>{\"name\":\"shell\",}",
        "<tool_call>{\"name\":\"shell\",\"arguments\":{\"command\":\"ls\"}",
        "<tool_call>{\"name\":\"shell\",\"arguments\":{\"command\":\"ls}",
        "<tool_call>memory_list{\"limit\":10,}",
        "<tool_call>shell{",
    };
    for (cases) |input| {
        const out = try stripToolCallMarkup(allocator, input);
        defer allocator.free(out);
        try std.testing.expectEqualStrings("", out);
    }
}

test "stripToolCallMarkup releases an unterminated tool opener that is prose" {
    // Only an executable payload is dropped; an opener that is an ordinary
    // mention is kept verbatim so no visible text is lost.
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "intro <tool_call> trailing prose with no close",
        "<tool_call>{\"not\":\"a call\"}",
        "<tool_call>{\"name\":\"shell\",\"arguments\":{}} trailing prose",
    };
    for (cases) |input| {
        const out = try stripToolCallMarkup(allocator, input);
        defer allocator.free(out);
        try std.testing.expectEqualStrings(input, out);
    }
}

test "stripToolCallMarkup hides the bracket tool-call dialect the dispatcher accepts" {
    const allocator = std.testing.allocator;
    const unclosed = [_][]const u8{
        "[tool_call]\n{\"name\": \"shell\", \"arguments\": {\"command\": \"echo leakcheck-7\"}}",
        "[TOOL_CALL]\n{\"name\": \"shell\", \"arguments\": {\"command\": \"echo leakcheck-7\"}}",
    };
    for (unclosed) |input| {
        const out = try stripToolCallMarkup(allocator, input);
        defer allocator.free(out);
        try std.testing.expectEqualStrings("", out);
    }
    // A closed bracket block is stripped and the surrounding text survives.
    const closed = "A[tool_call]{\"name\":\"shell\"}[/tool_call]B";
    const out = try stripToolCallMarkup(allocator, closed);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("AB", out);
}

test "stripToolCallMarkup hides a tool call closed by a mismatched or any-case close tag" {
    // Regression: the dispatcher's `parseXmlToolCalls` accepts the first `</X>`
    // as a fallback close (matching "tool_call" case-insensitively), but the
    // batch stripper only knew a fixed close-name list, so the tags and JSON were
    // shown verbatim in the non-streamed `Reasoning:` quote.
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "<tool_call>{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"}}</arg_value>",
        "<tool_call>{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"}}</function>",
        "<tool_call>{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"}}</TOOL_CALL>",
        "<tool_call>{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"}}</Tool_Call>",
        "<tool_call>memory_list{\"limit\": 10, \"include_content\": true}</arg_value>",
        "<tool_call>file_write{\"path\":\"index.html\",\"content\":\"</html>\"}</arg_value>",
    };
    for (cases) |input| {
        const out = try stripToolCallMarkup(allocator, input);
        defer allocator.free(out);
        try std.testing.expectEqualStrings("", out);
    }
    // A `</…>` embedded in a JSON string is not the close; the block runs on to
    // the real fallback close, exactly as the dispatcher does.
    const html = try stripToolCallMarkup(allocator, "A<tool_call>file_write{\"path\":\"i.html\",\"content\":\"</html>\"}</arg_value>B");
    defer allocator.free(html);
    try std.testing.expectEqualStrings("AB", html);
    // The bracket dialect closes on the first `[/X]` (any name).
    const bracket = try stripToolCallMarkup(allocator, "A[tool_call]{\"name\":\"shell\"}[/xyz]B");
    defer allocator.free(bracket);
    try std.testing.expectEqualStrings("AB", bracket);
}

test "stripToolCallMarkup keeps prose that only mentions a mismatched close tag" {
    const allocator = std.testing.allocator;
    const text = "Call the tool with <tool_call> then close it with </arg_value>.";
    const out = try stripToolCallMarkup(allocator, text);
    defer allocator.free(out);
    try std.testing.expectEqualStrings(text, out);
}

// ---------------------------------------------------------------------------
// Regression: the same review reproductions for the batch stripper.
// ---------------------------------------------------------------------------

test "stripToolCallMarkup hides a >16KiB tool call closed by a fallback tag" {
    const a = std.testing.allocator;
    var input: std.ArrayListUnmanaged(u8) = .empty;
    defer input.deinit(a);
    try input.appendSlice(a, "<tool_call>[\"name\":\"shell\",\"arguments\":{\"command\":\"");
    try input.appendNTimes(a, 'a', 20000);
    try input.appendSlice(a, "\"}}</think>AFTER");
    const out = try stripToolCallMarkup(a, input.items);
    defer a.free(out);
    try std.testing.expectEqualStrings("AFTER", out);
}

test "stripToolCallMarkup keeps prose that mentions mismatched think tags" {
    const a = std.testing.allocator;
    const input = "文档中</think>[ 是调用开始标记，调用使用</think> 结束。";
    const out = try stripToolCallMarkup(a, input);
    defer a.free(out);
    try std.testing.expectEqualStrings(input, out);
}

test "stripToolCallMarkup hides a call closed by a mismatched fallback tag" {
    const a = std.testing.allocator;
    const input = "<tool_call>[\"name\":\"shell\",\"arguments\":{}}</think>AFTER";
    const out = try stripToolCallMarkup(a, input);
    defer a.free(out);
    try std.testing.expectEqualStrings("AFTER", out);
}

// ── Inner-call parser tests (moved with the parsers) ─────────────────────

test "parseFunctionTagCall single parameter" {
    const allocator = std.testing.allocator;
    const inner = "<function=shell><parameter=command>ps aux | grep nullclaw</parameter></function>";
    const call = try parseFunctionTagCall(allocator, inner);
    defer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", call.name);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "ps aux | grep nullclaw") != null);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "command") != null);
}
test "parseFunctionTagCall multiple parameters" {
    const allocator = std.testing.allocator;
    const inner = "<function=file_write><parameter=path>/tmp/test.txt</parameter><parameter=content>hello world</parameter></function>";
    const call = try parseFunctionTagCall(allocator, inner);
    defer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try std.testing.expectEqualStrings("file_write", call.name);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "path") != null);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "/tmp/test.txt") != null);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "content") != null);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "hello world") != null);
}
test "parseFunctionTagCall with whitespace and newlines" {
    const allocator = std.testing.allocator;
    const inner =
        \\<function=shell>
        \\<parameter=command>
        \\ls -la
        \\</parameter>
        \\</function>
    ;
    const call = try parseFunctionTagCall(allocator, inner);
    defer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", call.name);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "ls -la") != null);
}
test "parseFunctionTagCall no function tag returns error" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.NoFunctionTag, parseFunctionTagCall(allocator, "just plain text"));
}
test "parseFunctionTagCall value with quotes is JSON-escaped" {
    const allocator = std.testing.allocator;
    const inner = "<function=shell><parameter=command>echo \"hello world\"</parameter></function>";
    const call = try parseFunctionTagCall(allocator, inner);
    defer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", call.name);
    // Verify the JSON is valid by parsing it
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, call.arguments_json, .{});
    defer parsed.deinit();
    const cmd = parsed.value.object.get("command").?.string;
    try std.testing.expectEqualStrings("echo \"hello world\"", cmd);
}

// ── Native tool dispatcher tests ────────────────────────────────
test "parseToolCallJson with trailing comma repair" {
    const allocator = std.testing.allocator;
    const result = try parseToolCallJson(allocator, "{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"},}");
    defer {
        allocator.free(result.name);
        allocator.free(result.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", result.name);
}
test "parseToolCallJson with unclosed brace repair" {
    const allocator = std.testing.allocator;
    const result = try parseToolCallJson(allocator, "{\"name\": \"shell\", \"arguments\": {\"command\": \"ls\"}");
    defer {
        allocator.free(result.name);
        allocator.free(result.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", result.name);
}
test "parseToolCallJson robustness" {
    const allocator = std.testing.allocator;

    // Case 1: JSON-in-JSON (name field is a whole JSON object)
    const json1 = "{\"name\": \"{\\\"name\\\": \\\"shell\\\", \\\"arguments\\\": {}}\", \"arguments\": {}}";
    const res1 = try parseToolCallJson(allocator, json1);
    defer {
        allocator.free(res1.name);
        allocator.free(res1.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", res1.name);

    // Case 2: Trailing XML tag in name (from logs)
    const json2 = "{\"name\": \"shell</arg_value>\", \"arguments\": {\"command\": \"ls\"}}";
    const res2 = try parseToolCallJson(allocator, json2);
    defer {
        allocator.free(res2.name);
        allocator.free(res2.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", res2.name);

    // Case 3: JSON-like name without nested "name" is rejected as invalid tool name.
    const json3 = "{\"name\": \"{\\\"tool\\\":\\\"shell\\\"}\", \"arguments\": {}}";
    try std.testing.expectError(error.InvalidToolName, parseToolCallJson(allocator, json3));
}
test "parseToolCallJson salvages malformed quoted colon tool name" {
    const allocator = std.testing.allocator;
    const raw = "{\"name\":\": \"memory_recall\", \"arguments\": {\"query\": \"Traumforschung kulturwissenschaftlich\"}}";

    const result = try parseToolCallJson(allocator, raw);
    defer {
        allocator.free(result.name);
        allocator.free(result.arguments_json);
    }

    try std.testing.expectEqualStrings("memory_recall", result.name);

    const parsed_args = try std.json.parseFromSlice(std.json.Value, allocator, result.arguments_json, .{});
    defer parsed_args.deinit();
    try std.testing.expectEqualStrings("Traumforschung kulturwissenschaftlich", parsed_args.value.object.get("query").?.string);
}
test "parseToolCallJson salvages malformed quoted colon tool name with repaired arguments" {
    const allocator = std.testing.allocator;
    const raw = "{\"name\" : \": \"memory_recall\", \"arguments\" : {\"query\": \"hello\",}}";

    const result = try parseToolCallJson(allocator, raw);
    defer {
        allocator.free(result.name);
        allocator.free(result.arguments_json);
    }

    try std.testing.expectEqualStrings("memory_recall", result.name);

    const parsed_args = try std.json.parseFromSlice(std.json.Value, allocator, result.arguments_json, .{});
    defer parsed_args.deinit();
    try std.testing.expectEqualStrings("hello", parsed_args.value.object.get("query").?.string);
}
test "parseFunctionTagCall parameters bounded by </function>" {
    const allocator = std.testing.allocator;
    // Two function blocks concatenated — second block's params must NOT leak into first
    const inner = "<function=shell><parameter=command>echo hi</parameter></function><function=file_read><parameter=path>/etc/passwd</parameter></function>";
    const call = try parseFunctionTagCall(allocator, inner);
    defer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try std.testing.expectEqualStrings("shell", call.name);
    // Only "command" parameter should be present, not "path"
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "echo hi") != null);
    try std.testing.expect(std.mem.indexOf(u8, call.arguments_json, "/etc/passwd") == null);
}
test "parseFunctionTagCall rejects invalid function name with special chars" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidFunctionName,
        parseFunctionTagCall(allocator, "<function=shell\"><parameter=x>y</parameter></function>"),
    );
    try std.testing.expectError(
        error.InvalidFunctionName,
        parseFunctionTagCall(allocator, "<function=she<ll><parameter=x>y</parameter></function>"),
    );
    try std.testing.expectError(
        error.InvalidFunctionName,
        parseFunctionTagCall(allocator, "<function=she ll><parameter=x>y</parameter></function>"),
    );
}
test "parseFunctionTagCall accepts valid names with dots dashes underscores" {
    const allocator = std.testing.allocator;
    const call = try parseFunctionTagCall(allocator, "<function=my-tool_v2.0><parameter=key>val</parameter></function>");
    defer {
        allocator.free(call.name);
        allocator.free(call.arguments_json);
    }
    try std.testing.expectEqualStrings("my-tool_v2.0", call.name);
}

test "stripToolCallMarkup hides a quoted-colon salvaged call" {
    const a = std.testing.allocator;
    const input = "A<tool_call>{\"name\":\": \"memory_recall\", \"arguments\": {\"query\": \"q\"}}</tool_call>B";
    const out = try stripToolCallMarkup(a, input);
    defer a.free(out);
    try std.testing.expectEqualStrings("AB", out);
}

test "findCodeRegionsForToolMarkup excludes a trailing unterminated fence" {
    const a = std.testing.allocator;
    // A fence that closes is a code region.
    const closed = try findCodeRegionsForToolMarkup(a, "x\n```\ncode\n```\ny");
    defer a.free(closed);
    try std.testing.expectEqual(@as(usize, 1), closed.len);
    try std.testing.expect(isInsideCode(closed, 8));
    try std.testing.expect(!isInsideCode(closed, 0));
    // An unterminated fence is not, so a garbled closer after it stays visible.
    const open = try findCodeRegionsForToolMarkup(a, "x\n```\ncode");
    defer a.free(open);
    try std.testing.expectEqual(@as(usize, 0), open.len);
    // `findCodeRegions` does treat the trailing fence as code (reasoning scan).
    const trailing = try findCodeRegions(a, "x\n```\ncode");
    defer a.free(trailing);
    try std.testing.expectEqual(@as(usize, 1), trailing.len);
}

test "stripToolCallMarkup keeps a function sample inside a code fence" {
    // Regression: without code-region awareness the batch stripper removed a
    // documented `function_calls` sample from the reply.
    const a = std.testing.allocator;
    const doc = "Example:\n```xml\n<function_calls><invoke name=\"shell\"></invoke></function_calls>\n```\ndone";
    const out = try stripToolCallMarkup(a, doc);
    defer a.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "<function_calls>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "</function_calls>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "done") != null);
}

test "stripToolCallMarkup drops a lone closer after an unclosed fence" {
    // An unterminated fence must not hide the trailing garbled closer from the
    // strip (the prod reply promised a table, opened ``` and emitted a closer).
    const a = std.testing.allocator;
    const cases = [_][]const u8{ "answer\n```\n</function>", "answer\n~~~\n</function>" };
    for (cases) |input| {
        const out = try stripToolCallMarkup(a, input);
        defer a.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "</function") == null);
    }
}

test "splitThinkContent keeps prose that names a plain reasoning closer" {
    // Regression: an orphan plain `</think>` cleared the visible buffer, so a
    // reply that named the tag lost its prose. Only the namespaced/pipe gateway
    // forms mark a leaked draft in the batch path.
    const a = std.testing.allocator;
    const split = try splitThinkContent(a, "The closing tag is </think>.");
    defer a.free(split.visible);
    defer if (split.reasoning) |r| a.free(r);
    try std.testing.expectEqualStrings("The closing tag is .", split.visible);
    try std.testing.expect(split.reasoning == null);
}

test "stripThinkBlocks keeps prose that names a plain reasoning closer" {
    // Regression: an orphan plain `</think>` cleared the visible buffer, so a
    // draft preview that named the tag lost its prose.
    const a = std.testing.allocator;
    const out = try stripThinkBlocks(a, "The closing tag is </think>.");
    defer a.free(out);
    try std.testing.expectEqualStrings("The closing tag is .", out);
}
