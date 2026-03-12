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
    if (trimmed.len == 0) return ToolResult.ok("No web results found.");

    const output = try std.fmt.allocPrint(allocator, "Results for: {s}\n\n{s}", .{ query, trimmed });
    return ToolResult{ .success = true, .output = output };
}

pub fn formatResultEntries(allocator: std.mem.Allocator, query: []const u8, entries: []const ResultEntry) !ToolResult {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try std.fmt.format(buf.writer(allocator), "Results for: {s}\n\n", .{query});

    for (entries, 0..) |entry, i| {
        const title = if (entry.title.len > 0) entry.title else "(no title)";
        const url = if (entry.url.len > 0) entry.url else "(no url)";

        try std.fmt.format(buf.writer(allocator), "{d}. {s}\n   {s}\n", .{ i + 1, title, url });
        if (entry.description.len > 0) {
            try std.fmt.format(buf.writer(allocator), "   {s}\n", .{entry.description});
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

    try std.fmt.format(buf.writer(allocator), "Results for: {s}\n\n", .{query});

    var out_idx: usize = 0;
    for (items) |item| {
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };

        const title = extractString(obj, "title") orelse "(no title)";
        const url = extractString(obj, "url") orelse "(no url)";
        const desc = blk: {
            if (extractString(obj, preferred_desc_key)) |d| break :blk d;
            if (secondary_desc_key) |key| {
                if (extractString(obj, key)) |d| break :blk d;
            }
            if (extractString(obj, "description")) |d| break :blk d;
            break :blk "";
        };

        out_idx += 1;
        try std.fmt.format(buf.writer(allocator), "{d}. {s}\n   {s}\n", .{ out_idx, title, url });
        if (desc.len > 0) {
            try std.fmt.format(buf.writer(allocator), "   {s}\n", .{desc});
        }
        try buf.append(allocator, '\n');
    }

    if (out_idx == 0) {
        return ToolResult.ok("No web results found.");
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
