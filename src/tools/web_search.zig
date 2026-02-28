//! Web Search Tool — internet search via Brave Search API or SearXNG.
//!
//! Backend selection:
//! 1) If `searxng_base_url` is configured, use SearXNG JSON API.
//! 2) Otherwise, fallback to Brave Search API via BRAVE_API_KEY.

const std = @import("std");
const root = @import("root.zig");
const platform = @import("../platform.zig");
const http_util = @import("../http_util.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;

const log = std.log.scoped(.web_search);

/// Maximum number of search results.
const MAX_RESULTS: usize = 10;
/// Default number of search results.
const DEFAULT_COUNT: usize = 5;
/// Default request timeout for backend HTTP calls.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Web search tool supporting Brave Search API and SearXNG.
pub const WebSearchTool = struct {
    /// Optional SearXNG base URL (e.g. https://searx.example.com or .../search).
    searxng_base_url: ?[]const u8 = null,
    timeout_secs: u64 = DEFAULT_TIMEOUT_SECS,

    pub const tool_name = "web_search";
    pub const tool_description = "Search the web. Uses configured SearXNG first, otherwise Brave Search (BRAVE_API_KEY). Returns titles, URLs, and descriptions.";
    pub const tool_params =
        \\{"type":"object","properties":{"query":{"type":"string","minLength":1,"description":"Search query"},"count":{"type":"integer","minimum":1,"maximum":10,"default":5,"description":"Number of results (1-10)"}},"required":["query"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *WebSearchTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *WebSearchTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const query = root.getString(args, "query") orelse
            return ToolResult.fail("Missing required 'query' parameter");

        if (std.mem.trim(u8, query, " \t\n\r").len == 0)
            return ToolResult.fail("'query' must not be empty");

        const count = parseCount(args);

        // Prefer explicit SearXNG config when present.
        if (self.searxng_base_url) |base_url| {
            const trimmed = std.mem.trim(u8, base_url, " \t\n\r");
            if (trimmed.len > 0) {
                return executeSearxngSearch(allocator, query, count, trimmed, self.timeout_secs);
            }
        }

        // Fallback to Brave when API key is available.
        if (platform.getEnvOrNull(allocator, "BRAVE_API_KEY")) |api_key| {
            defer allocator.free(api_key);
            if (std.mem.trim(u8, api_key, " \t\n\r").len > 0) {
                return executeBraveSearch(allocator, query, count, api_key, self.timeout_secs);
            }
        }

        return ToolResult.fail("web_search is not configured. Set BRAVE_API_KEY or http_request.search_base_url (SearXNG).");
    }
};

fn executeBraveSearch(
    allocator: std.mem.Allocator,
    query: []const u8,
    count: usize,
    api_key: []const u8,
    timeout_secs: u64,
) !ToolResult {
    // URL-encode query
    const encoded_query = try urlEncode(allocator, query);
    defer allocator.free(encoded_query);

    // Build URL
    const url_str = try std.fmt.allocPrint(
        allocator,
        "https://api.search.brave.com/res/v1/web/search?q={s}&count={d}",
        .{ encoded_query, count },
    );
    defer allocator.free(url_str);

    const timeout_str = try timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    // Make HTTP request via curl subprocess
    const auth_header = try std.fmt.allocPrint(allocator, "X-Subscription-Token: {s}", .{api_key});
    defer allocator.free(auth_header);
    const headers = [_][]const u8{
        auth_header,
        "Accept: application/json",
    };

    const body = http_util.curlGet(
        allocator,
        url_str,
        &headers,
        timeout_str,
    ) catch |err| {
        log.err("web_search (brave) request failed for '{s}': {}", .{ query, err });
        const msg = try std.fmt.allocPrint(allocator, "Search request failed: {}", .{err});
        return ToolResult{ .success = false, .output = "", .error_msg = msg };
    };
    defer allocator.free(body);

    return formatBraveResults(allocator, body, query);
}

fn executeSearxngSearch(
    allocator: std.mem.Allocator,
    query: []const u8,
    count: usize,
    base_url: []const u8,
    timeout_secs: u64,
) !ToolResult {
    const encoded_query = try urlEncode(allocator, query);
    defer allocator.free(encoded_query);

    const url_str = buildSearxngSearchUrl(allocator, base_url, encoded_query, count) catch {
        return ToolResult.fail("Invalid http_request.search_base_url; expected https://host[/search]");
    };
    defer allocator.free(url_str);

    const timeout_str = try timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    const headers = [_][]const u8{
        "Accept: application/json",
        "User-Agent: nullclaw/0.1 (web_search)",
    };

    const body = http_util.curlGet(
        allocator,
        url_str,
        &headers,
        timeout_str,
    ) catch |err| {
        log.err("web_search (searxng) request failed for '{s}': {}", .{ query, err });
        const msg = try std.fmt.allocPrint(allocator, "Search request failed: {}", .{err});
        return ToolResult{ .success = false, .output = "", .error_msg = msg };
    };
    defer allocator.free(body);

    return formatSearxngResults(allocator, body, query);
}

fn timeoutToString(allocator: std.mem.Allocator, timeout_secs: u64) ![]u8 {
    const effective_timeout = if (timeout_secs == 0) DEFAULT_TIMEOUT_SECS else timeout_secs;
    return std.fmt.allocPrint(allocator, "{d}", .{effective_timeout});
}

fn buildSearxngSearchUrl(
    allocator: std.mem.Allocator,
    base_url: []const u8,
    encoded_query: []const u8,
    count: usize,
) ![]u8 {
    var trimmed = std.mem.trim(u8, base_url, " \t\n\r");
    if (trimmed.len == 0) return error.InvalidSearchUrl;
    while (trimmed.len > 0 and trimmed[trimmed.len - 1] == '/') {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }
    if (!std.mem.startsWith(u8, trimmed, "https://")) {
        return error.InvalidSearchUrl;
    }
    if (std.mem.indexOfScalar(u8, trimmed, '?') != null) {
        return error.InvalidSearchUrl;
    }

    const endpoint = if (std.mem.endsWith(u8, trimmed, "/search"))
        try allocator.dupe(u8, trimmed)
    else
        try std.fmt.allocPrint(allocator, "{s}/search", .{trimmed});
    defer allocator.free(endpoint);

    return std.fmt.allocPrint(
        allocator,
        "{s}?q={s}&format=json&language=all&safesearch=0&categories=general&count={d}",
        .{ endpoint, encoded_query, count },
    );
}

/// Parse count from args ObjectMap. Returns DEFAULT_COUNT if not found or invalid.
fn parseCount(args: JsonObjectMap) usize {
    const val_i64 = root.getInt(args, "count") orelse return DEFAULT_COUNT;
    if (val_i64 < 1) return 1;
    const val: usize = if (val_i64 > @as(i64, @intCast(MAX_RESULTS))) MAX_RESULTS else @intCast(val_i64);
    return val;
}

/// URL-encode a string (percent-encoding).
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

fn hexDigit(v: u8) u8 {
    return "0123456789ABCDEF"[v & 0x0f];
}

/// Parse Brave Search JSON and format as text results.
pub fn formatBraveResults(allocator: std.mem.Allocator, json_body: []const u8, query: []const u8) !ToolResult {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_body, .{}) catch
        return ToolResult.fail("Failed to parse search response JSON");
    defer parsed.deinit();

    const root_val = switch (parsed.value) {
        .object => |o| o,
        else => return ToolResult.fail("Unexpected search response format"),
    };

    const web = root_val.get("web") orelse
        return ToolResult.ok("No web results found.");

    const web_obj = switch (web) {
        .object => |o| o,
        else => return ToolResult.ok("No web results found."),
    };

    const results = web_obj.get("results") orelse
        return ToolResult.ok("No web results found.");

    const results_arr = switch (results) {
        .array => |a| a,
        else => return ToolResult.ok("No web results found."),
    };

    if (results_arr.items.len == 0)
        return ToolResult.ok("No web results found.");

    return formatResultsArray(allocator, results_arr.items, query, "description");
}

/// Parse SearXNG JSON and format as text results.
pub fn formatSearxngResults(allocator: std.mem.Allocator, json_body: []const u8, query: []const u8) !ToolResult {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_body, .{}) catch
        return ToolResult.fail("Failed to parse search response JSON");
    defer parsed.deinit();

    const root_val = switch (parsed.value) {
        .object => |o| o,
        else => return ToolResult.fail("Unexpected search response format"),
    };

    const results = root_val.get("results") orelse
        return ToolResult.ok("No web results found.");

    const results_arr = switch (results) {
        .array => |a| a,
        else => return ToolResult.ok("No web results found."),
    };

    if (results_arr.items.len == 0)
        return ToolResult.ok("No web results found.");

    return formatResultsArray(allocator, results_arr.items, query, "content");
}

fn formatResultsArray(
    allocator: std.mem.Allocator,
    items: []const std.json.Value,
    query: []const u8,
    preferred_desc_key: []const u8,
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
        const desc = extractString(obj, preferred_desc_key) orelse extractString(obj, "description") orelse "";

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

fn extractString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

// ══════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════

const testing = std.testing;

test "WebSearchTool name and description" {
    var wst = WebSearchTool{};
    const t = wst.tool();
    try testing.expectEqualStrings("web_search", t.name());
    try testing.expect(t.description().len > 0);
    try testing.expect(t.parametersJson()[0] == '{');
}

test "WebSearchTool missing query fails" {
    var wst = WebSearchTool{};
    const parsed = try root.parseTestArgs("{\"count\":5}");
    defer parsed.deinit();
    const result = try wst.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expectEqualStrings("Missing required 'query' parameter", result.error_msg.?);
}

test "WebSearchTool empty query fails" {
    var wst = WebSearchTool{};
    const parsed = try root.parseTestArgs("{\"query\":\"  \"}");
    defer parsed.deinit();
    const result = try wst.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expectEqualStrings("'query' must not be empty", result.error_msg.?);
}

test "WebSearchTool without backend config fails with helpful message" {
    // This test relies on BRAVE_API_KEY not being set in test env.
    if (platform.getEnvOrNull(testing.allocator, "BRAVE_API_KEY")) |k| {
        testing.allocator.free(k);
        return;
    }
    var wst = WebSearchTool{};
    const parsed = try root.parseTestArgs("{\"query\":\"zig programming\"}");
    defer parsed.deinit();
    const result = try wst.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expect(std.mem.indexOf(u8, result.error_msg.?, "search_base_url") != null);
}

test "parseCount defaults to 5" {
    const p1 = try root.parseTestArgs("{}");
    defer p1.deinit();
    try testing.expectEqual(@as(usize, DEFAULT_COUNT), parseCount(p1.value.object));
    const p2 = try root.parseTestArgs("{\"query\":\"test\"}");
    defer p2.deinit();
    try testing.expectEqual(@as(usize, DEFAULT_COUNT), parseCount(p2.value.object));
}

test "parseCount clamps to range" {
    const p1 = try root.parseTestArgs("{\"count\":0}");
    defer p1.deinit();
    try testing.expectEqual(@as(usize, 1), parseCount(p1.value.object));
    const p2 = try root.parseTestArgs("{\"count\":100}");
    defer p2.deinit();
    try testing.expectEqual(@as(usize, MAX_RESULTS), parseCount(p2.value.object));
    const p3 = try root.parseTestArgs("{\"count\":3}");
    defer p3.deinit();
    try testing.expectEqual(@as(usize, 3), parseCount(p3.value.object));
}

test "urlEncode basic" {
    const encoded = try urlEncode(testing.allocator, "hello world");
    defer testing.allocator.free(encoded);
    try testing.expectEqualStrings("hello+world", encoded);
}

test "urlEncode special chars" {
    const encoded = try urlEncode(testing.allocator, "a&b=c");
    defer testing.allocator.free(encoded);
    try testing.expectEqualStrings("a%26b%3Dc", encoded);
}

test "urlEncode passthrough" {
    const encoded = try urlEncode(testing.allocator, "simple-test_123.txt~");
    defer testing.allocator.free(encoded);
    try testing.expectEqualStrings("simple-test_123.txt~", encoded);
}

test "buildSearxngSearchUrl normalizes base URLs" {
    const encoded_query = "zig+lang";

    const from_root = try buildSearxngSearchUrl(testing.allocator, "https://searx.example.com/", encoded_query, 3);
    defer testing.allocator.free(from_root);
    try testing.expect(std.mem.indexOf(u8, from_root, "https://searx.example.com/search?") != null);

    const from_search = try buildSearxngSearchUrl(testing.allocator, "https://searx.example.com/search", encoded_query, 3);
    defer testing.allocator.free(from_search);
    try testing.expect(std.mem.indexOf(u8, from_search, "https://searx.example.com/search?") != null);
}

test "formatBraveResults parses valid JSON" {
    const json =
        \\{"web":{"results":[
        \\  {"title":"Zig Language","url":"https://ziglang.org","description":"Zig is a systems language."},
        \\  {"title":"Zig GitHub","url":"https://github.com/ziglang/zig","description":"Source code."}
        \\]}}
    ;
    const result = try formatBraveResults(testing.allocator, json, "zig programming");
    defer testing.allocator.free(result.output);
    try testing.expect(result.success);
    try testing.expect(std.mem.indexOf(u8, result.output, "Results for: zig programming") != null);
    try testing.expect(std.mem.indexOf(u8, result.output, "1. Zig Language") != null);
    try testing.expect(std.mem.indexOf(u8, result.output, "https://ziglang.org") != null);
    try testing.expect(std.mem.indexOf(u8, result.output, "2. Zig GitHub") != null);
}

test "formatSearxngResults parses valid JSON" {
    const json =
        \\{"results":[
        \\  {"title":"SearXNG","url":"https://docs.searxng.org","content":"Privacy-respecting metasearch."},
        \\  {"title":"Zig","url":"https://ziglang.org","content":"General-purpose programming language."}
        \\]}
    ;
    const result = try formatSearxngResults(testing.allocator, json, "zig privacy search");
    defer testing.allocator.free(result.output);
    try testing.expect(result.success);
    try testing.expect(std.mem.indexOf(u8, result.output, "Results for: zig privacy search") != null);
    try testing.expect(std.mem.indexOf(u8, result.output, "1. SearXNG") != null);
    try testing.expect(std.mem.indexOf(u8, result.output, "https://docs.searxng.org") != null);
}

test "formatBraveResults empty results" {
    const json = "{\"web\":{\"results\":[]}}";
    const result = try formatBraveResults(testing.allocator, json, "nothing");
    try testing.expect(result.success);
    try testing.expectEqualStrings("No web results found.", result.output);
}

test "formatSearxngResults empty results" {
    const json = "{\"results\":[]}";
    const result = try formatSearxngResults(testing.allocator, json, "nothing");
    try testing.expect(result.success);
    try testing.expectEqualStrings("No web results found.", result.output);
}

test "formatBraveResults invalid JSON" {
    const result = try formatBraveResults(testing.allocator, "not json", "q");
    try testing.expect(!result.success);
}

test "formatSearxngResults invalid JSON" {
    const result = try formatSearxngResults(testing.allocator, "not json", "q");
    try testing.expect(!result.success);
}
