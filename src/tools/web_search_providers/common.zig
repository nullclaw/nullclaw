const std = @import("std");
const builtin = @import("builtin");
const root = @import("../root.zig");
const http_util = @import("../../http_util.zig");
const search_base_url = @import("../../search_base_url.zig");
const url_percent = @import("../../url_percent.zig");

const log = std.log.scoped(.web_search);

pub const ToolResult = root.ToolResult;

pub const ProviderSearchError = error{
    InvalidProvider,
    InvalidSearchBaseUrl,
    MissingApiKey,
    ProviderUnavailable,
    RequestFailed,
    InvalidResponse,
};

pub const ResultEntry = struct {
    title: []const u8,
    url: []const u8,
    description: []const u8,
};

const NO_WEB_RESULTS_MESSAGE = "No web results found.";

pub const ParsedJsonObject = struct {
    parsed: std.json.Parsed(std.json.Value),
    object: std.json.ObjectMap,

    pub fn deinit(self: *ParsedJsonObject) void {
        self.parsed.deinit();
    }
};

pub fn logRequestError(provider: []const u8, query: []const u8, err: anytype) void {
    if (builtin.is_test) return;
    log.err("web_search ({s}) request failed for '{s}': {}", .{ provider, query, err });
}

pub fn curlGet(
    allocator: std.mem.Allocator,
    url: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
) (ProviderSearchError || error{OutOfMemory})![]u8 {
    if (builtin.is_test) return error.RequestFailed;

    return http_util.curlGet(allocator, url, headers, timeout_secs) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            log.err("curl GET failed: {s} (timeout={s}s)", .{ @errorName(err), timeout_secs });
            return error.RequestFailed;
        },
    };
}

pub fn curlPostJson(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
) (ProviderSearchError || error{OutOfMemory})![]u8 {
    if (builtin.is_test) return error.RequestFailed;

    return http_util.curlPostWithProxy(allocator, url, body, headers, null, timeout_secs) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            log.err("curl POST failed: {s} (timeout={s}s)", .{ @errorName(err), timeout_secs });
            return error.RequestFailed;
        },
    };
}

pub fn timeoutToString(allocator: std.mem.Allocator, timeout_secs: u64) ![]u8 {
    const default_timeout_secs: u64 = 30;
    const effective_timeout = if (timeout_secs == 0) default_timeout_secs else timeout_secs;
    return std.fmt.allocPrint(allocator, "{d}", .{effective_timeout});
}

pub fn parseJsonObject(
    allocator: std.mem.Allocator,
    body: []const u8,
) (ProviderSearchError || error{OutOfMemory})!ParsedJsonObject {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.InvalidResponse;
    const object = switch (parsed.value) {
        .object => |o| o,
        else => {
            parsed.deinit();
            return error.InvalidResponse;
        },
    };
    return .{
        .parsed = parsed,
        .object = object,
    };
}

pub fn requireArrayField(
    object: std.json.ObjectMap,
    key: []const u8,
) (ProviderSearchError || error{OutOfMemory})![]const std.json.Value {
    const value = object.get(key) orelse return error.InvalidResponse;
    return switch (value) {
        .array => |items| items.items,
        else => error.InvalidResponse,
    };
}

pub fn buildSearxngSearchUrl(
    allocator: std.mem.Allocator,
    base_url: []const u8,
    encoded_query: []const u8,
    count: usize,
) ![]u8 {
    const endpoint = search_base_url.normalizeEndpoint(allocator, base_url) catch |err| switch (err) {
        error.InvalidSearchBaseUrl => return error.InvalidSearchBaseUrl,
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer allocator.free(endpoint);

    return std.fmt.allocPrint(
        allocator,
        "{s}?q={s}&format=json&language=all&safesearch=0&categories=general&count={d}",
        .{ endpoint, encoded_query, count },
    );
}

pub fn urlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    for (input) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try buf.append(allocator, c);
        } else if (c == ' ') {
            try buf.append(allocator, '+');
        } else {
            try buf.appendSlice(allocator, &.{ '%', hexDigit(c >> 4), hexDigit(c & 0x0f) });
        }
    }
    return buf.toOwnedSlice(allocator);
}

pub fn urlEncodePath(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    return url_percent.encode(allocator, input);
}

fn hexDigit(v: u8) u8 {
    return "0123456789ABCDEF"[v & 0x0f];
}

pub fn formatJinaPlainText(allocator: std.mem.Allocator, text: []const u8, query: []const u8) !ToolResult {
    const trimmed = std.mem.trim(u8, text, " \t\n\r");
    if (trimmed.len == 0) return noWebResults(allocator);

    const output = try std.fmt.allocPrint(allocator, "Results for: {s}\n\n{s}", .{ query, trimmed });
    return ToolResult{ .success = true, .output = output };
}

pub fn urlDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const h1 = std.fmt.charToDigit(input[i + 1], 16) catch {
                try buf.append(allocator, input[i]);
                i += 1;
                continue;
            };
            const h2 = std.fmt.charToDigit(input[i + 2], 16) catch {
                try buf.append(allocator, input[i]);
                i += 1;
                continue;
            };
            try buf.append(allocator, @as(u8, @intCast(h1 << 4 | h2)));
            i += 3;
        } else if (input[i] == '+') {
            try buf.append(allocator, ' ');
            i += 1;
        } else {
            try buf.append(allocator, input[i]);
            i += 1;
        }
    }
    return buf.toOwnedSlice(allocator);
}

pub fn stripTags(allocator: std.mem.Allocator, html: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    var i: usize = 0;
    while (i < html.len) {
        if (html[i] == '<') {
            const end = std.mem.indexOfScalarPos(u8, html, i + 1, '>') orelse {
                try buf.append(allocator, html[i]);
                i += 1;
                continue;
            };
            i = end + 1;
        } else if (html[i] == '&') {
            const end = std.mem.indexOfScalarPos(u8, html, i + 1, ';') orelse {
                try buf.append(allocator, html[i]);
                i += 1;
                continue;
            };
            const entity = html[i .. end + 1];
            if (std.mem.eql(u8, entity, "&quot;")) {
                try buf.append(allocator, '"');
            } else if (std.mem.eql(u8, entity, "&amp;")) {
                try buf.append(allocator, '&');
            } else if (std.mem.eql(u8, entity, "&#39;")) {
                try buf.append(allocator, '\'');
            } else if (std.mem.eql(u8, entity, "&lt;")) {
                try buf.append(allocator, '<');
            } else if (std.mem.eql(u8, entity, "&gt;")) {
                try buf.append(allocator, '>');
            } else if (std.mem.eql(u8, entity, "&nbsp;")) {
                try buf.append(allocator, ' ');
            } else if (std.mem.eql(u8, entity, "&rsquo;") or std.mem.eql(u8, entity, "&lsquo;")) {
                try buf.append(allocator, '\'');
            } else if (std.mem.eql(u8, entity, "&ldquo;") or std.mem.eql(u8, entity, "&rdquo;")) {
                try buf.append(allocator, '"');
            } else {
                try buf.appendSlice(allocator, entity);
            }
            i = end + 1;
        } else {
            try buf.append(allocator, html[i]);
            i += 1;
        }
    }
    return buf.toOwnedSlice(allocator);
}

pub fn noWebResults(allocator: std.mem.Allocator) !ToolResult {
    return .{ .success = true, .output = try allocator.dupe(u8, NO_WEB_RESULTS_MESSAGE) };
}

pub fn formatResultEntries(allocator: std.mem.Allocator, query: []const u8, entries: []const ResultEntry) !ToolResult {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.print(allocator, "Results for: {s}\n\n", .{query});

    for (entries, 0..) |entry, i| {
        const title = if (entry.title.len > 0) entry.title else "(no title)";
        const url = if (entry.url.len > 0) entry.url else "(no url)";

        try buf.print(allocator, "{d}. {s}\n   {s}\n", .{ i + 1, title, url });
        if (entry.description.len > 0) {
            try buf.print(allocator, "   {s}\n", .{entry.description});
        }
        try buf.append(allocator, '\n');
    }

    return ToolResult.ok(try buf.toOwnedSlice(allocator));
}

pub fn formatResultsArray(
    allocator: std.mem.Allocator,
    items: []const std.json.Value,
    query: []const u8,
    preferred_desc_key: []const u8,
    secondary_desc_key: ?[]const u8,
) !ToolResult {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.print(allocator, "Results for: {s}\n\n", .{query});

    var out_idx: usize = 0;
    for (items) |item| {
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };

        const title = extractString(obj, "title") orelse "(no title)";
        const url = extractString(obj, "url") orelse extractString(obj, "link") orelse "(no url)";
        const desc = blk: {
            if (extractString(obj, preferred_desc_key)) |d| break :blk d;
            if (secondary_desc_key) |key| {
                if (extractString(obj, key)) |d| break :blk d;
            }
            if (extractString(obj, "description")) |d| break :blk d;
            break :blk "";
        };

        out_idx += 1;
        try buf.print(allocator, "{d}. {s}\n   {s}\n", .{ out_idx, title, url });
        if (desc.len > 0) {
            try buf.print(allocator, "   {s}\n", .{desc});
        }
        try buf.append(allocator, '\n');
    }

    if (out_idx == 0) {
        return noWebResults(allocator);
    }

    return ToolResult.ok(try buf.toOwnedSlice(allocator));
}

pub fn extractString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

pub fn duckduckgoTitleFromText(text: []const u8) []const u8 {
    if (std.mem.indexOf(u8, text, " - ")) |idx| {
        if (idx > 0) return text[0..idx];
    }
    if (std.mem.indexOf(u8, text, " — ")) |idx| {
        if (idx > 0) return text[0..idx];
    }
    return text;
}

test "parseJsonObject returns object root" {
    var parsed = try parseJsonObject(std.testing.allocator, "{\"results\":[]}");
    defer parsed.deinit();

    try std.testing.expect(parsed.object.get("results") != null);
}

test "parseJsonObject rejects non-object root" {
    try std.testing.expectError(error.InvalidResponse, parseJsonObject(std.testing.allocator, "[]"));
}

test "requireArrayField returns array items" {
    var parsed = try parseJsonObject(std.testing.allocator, "{\"results\":[{\"title\":\"A\"}]}");
    defer parsed.deinit();

    const items = try requireArrayField(parsed.object, "results");
    try std.testing.expectEqual(@as(usize, 1), items.len);
}

test "requireArrayField rejects missing field" {
    var parsed = try parseJsonObject(std.testing.allocator, "{\"data\":[]}");
    defer parsed.deinit();

    try std.testing.expectError(error.InvalidResponse, requireArrayField(parsed.object, "results"));
}

test "stripTags" {
    const html = "Hello <b>World</b> &amp; &quot;Quotes&quot; &rsquo; &ldquo;Test&rdquo;";
    const stripped = try stripTags(std.testing.allocator, html);
    defer std.testing.allocator.free(stripped);
    try std.testing.expectEqualStrings("Hello World & \"Quotes\" ' \"Test\"", stripped);
}

test "urlDecode" {
    const input = "https%3A%2F%2Fexample.com%2F%3Fq%3Dfoo%2Bbar+baz%20qux";
    const decoded = try urlDecode(std.testing.allocator, input);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("https://example.com/?q=foo+bar baz qux", decoded);
}
