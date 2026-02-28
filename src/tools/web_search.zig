//! Web Search Tool — internet search across multiple providers.
//!
//! Supported providers:
//!   - searxng
//!   - duckduckgo (ddg)
//!   - brave
//!   - firecrawl
//!   - tavily
//!   - perplexity
//!   - exa
//!   - jina
//!
//! Provider selection:
//! 1) `provider = "auto"` (default): tries a built-in chain.
//! 2) Explicit provider via config (`http_request.search_provider`) or tool arg (`provider`).
//! 3) Optional fallback chain (`http_request.search_fallback_providers`).

const std = @import("std");
const root = @import("root.zig");
const platform = @import("../platform.zig");
const search_providers = @import("web_search_providers/root.zig");
const search_common = search_providers.common;
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;

/// Maximum number of search results.
const MAX_RESULTS: usize = 10;
/// Default number of search results.
const DEFAULT_COUNT: usize = 5;
/// Default request timeout for backend HTTP calls.
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Upper bound for provider chain size (primary + fallbacks + auto expansions).
const MAX_PROVIDER_CHAIN: usize = 16;

const SearchProvider = enum {
    auto,
    searxng,
    duckduckgo,
    brave,
    firecrawl,
    tavily,
    perplexity,
    exa,
    jina,
};

const ProviderSearchError = search_common.ProviderSearchError;

/// Web search tool supporting multiple providers.
pub const WebSearchTool = struct {
    /// Optional SearXNG base URL (e.g. https://searx.example.com or .../search).
    searxng_base_url: ?[]const u8 = null,
    /// Primary provider ("auto" by default).
    provider: []const u8 = "auto",
    /// Fallback providers tried in order when primary fails.
    fallback_providers: []const []const u8 = &.{},
    timeout_secs: u64 = DEFAULT_TIMEOUT_SECS,

    pub const tool_name = "web_search";
    pub const tool_description = "Search the web. Providers: searxng, duckduckgo(ddg), brave, firecrawl, tavily, perplexity, exa, jina. Configure via http_request.search_provider/search_fallback_providers and API key env vars.";
    pub const tool_params =
        \\{"type":"object","properties":{"query":{"type":"string","minLength":1,"description":"Search query"},"count":{"type":"integer","minimum":1,"maximum":10,"default":5,"description":"Number of results (1-10)"},"provider":{"type":"string","description":"Optional provider override (auto,searxng,duckduckgo,ddg,brave,firecrawl,tavily,perplexity,exa,jina)"}},"required":["query"]}
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
        const provider_raw = root.getString(args, "provider") orelse self.provider;

        var chain_buf: [MAX_PROVIDER_CHAIN]SearchProvider = undefined;
        const chain = buildProviderChain(self, provider_raw, &chain_buf) catch |err| switch (err) {
            error.InvalidProvider => return ToolResult.fail("Invalid web_search provider. Supported: auto, searxng, duckduckgo(ddg), brave, firecrawl, tavily, perplexity, exa, jina."),
            else => return err,
        };

        var failures: std.ArrayList(u8) = .empty;
        defer failures.deinit(allocator);

        for (chain) |provider| {
            const result = executeWithProvider(self, allocator, provider, query, count) catch |err| {
                if (err == error.InvalidSearchBaseUrl) {
                    return ToolResult.fail("Invalid http_request.search_base_url; expected https://host[/search]");
                }

                if (failures.items.len > 0) {
                    try failures.appendSlice(allocator, " | ");
                }
                try std.fmt.format(failures.writer(allocator), "{s}:{s}", .{ providerName(provider), @errorName(err) });
                continue;
            };
            return result;
        }

        if (failures.items.len == 0) {
            return ToolResult.fail("web_search has no providers configured.");
        }

        const msg = try std.fmt.allocPrint(allocator, "All web_search providers failed: {s}", .{failures.items});
        return ToolResult{ .success = false, .output = "", .error_msg = msg };
    }
};

fn parseProvider(raw: []const u8) ?SearchProvider {
    const trimmed = std.mem.trim(u8, raw, " \t\n\r");
    if (std.ascii.eqlIgnoreCase(trimmed, "auto")) return .auto;
    if (std.ascii.eqlIgnoreCase(trimmed, "searxng")) return .searxng;
    if (std.ascii.eqlIgnoreCase(trimmed, "duckduckgo") or std.ascii.eqlIgnoreCase(trimmed, "ddg")) return .duckduckgo;
    if (std.ascii.eqlIgnoreCase(trimmed, "brave")) return .brave;
    if (std.ascii.eqlIgnoreCase(trimmed, "firecrawl")) return .firecrawl;
    if (std.ascii.eqlIgnoreCase(trimmed, "tavily")) return .tavily;
    if (std.ascii.eqlIgnoreCase(trimmed, "perplexity")) return .perplexity;
    if (std.ascii.eqlIgnoreCase(trimmed, "exa")) return .exa;
    if (std.ascii.eqlIgnoreCase(trimmed, "jina")) return .jina;
    return null;
}

fn providerName(provider: SearchProvider) []const u8 {
    return switch (provider) {
        .auto => "auto",
        .searxng => "searxng",
        .duckduckgo => "duckduckgo",
        .brave => "brave",
        .firecrawl => "firecrawl",
        .tavily => "tavily",
        .perplexity => "perplexity",
        .exa => "exa",
        .jina => "jina",
    };
}

fn appendProviderUnique(chain: []SearchProvider, len: *usize, provider: SearchProvider) void {
    for (chain[0..len.*]) |existing| {
        if (existing == provider) return;
    }
    if (len.* < chain.len) {
        chain[len.*] = provider;
        len.* += 1;
    }
}

fn buildProviderChain(
    self: *WebSearchTool,
    primary_raw: []const u8,
    chain_buf: *[MAX_PROVIDER_CHAIN]SearchProvider,
) ProviderSearchError![]const SearchProvider {
    var len: usize = 0;

    const primary = parseProvider(primary_raw) orelse return error.InvalidProvider;
    if (primary == .auto) {
        if (self.searxng_base_url) |base_url| {
            if (std.mem.trim(u8, base_url, " \t\n\r").len > 0) {
                appendProviderUnique(chain_buf, &len, .searxng);
            }
        }
        appendProviderUnique(chain_buf, &len, .brave);
        appendProviderUnique(chain_buf, &len, .firecrawl);
        appendProviderUnique(chain_buf, &len, .tavily);
        appendProviderUnique(chain_buf, &len, .perplexity);
        appendProviderUnique(chain_buf, &len, .exa);
        appendProviderUnique(chain_buf, &len, .jina);
        appendProviderUnique(chain_buf, &len, .duckduckgo);
    } else {
        appendProviderUnique(chain_buf, &len, primary);
    }

    for (self.fallback_providers) |raw| {
        const fallback = parseProvider(raw) orelse return error.InvalidProvider;
        if (fallback == .auto) return error.InvalidProvider;
        appendProviderUnique(chain_buf, &len, fallback);
    }

    return chain_buf[0..len];
}

fn executeWithProvider(
    self: *WebSearchTool,
    allocator: std.mem.Allocator,
    provider: SearchProvider,
    query: []const u8,
    count: usize,
) (ProviderSearchError || error{OutOfMemory})!ToolResult {
    switch (provider) {
        .auto => return error.InvalidProvider,
        .searxng => {
            const base_url = self.searxng_base_url orelse return error.ProviderUnavailable;
            const trimmed = std.mem.trim(u8, base_url, " \t\n\r");
            if (trimmed.len == 0) return error.ProviderUnavailable;
            return search_providers.searxng.execute(allocator, query, count, trimmed, self.timeout_secs);
        },
        .duckduckgo => return search_providers.duckduckgo.execute(allocator, query, count, self.timeout_secs),
        .brave => {
            const api_key = tryApiKeyFromEnvOrNull(allocator, &.{"BRAVE_API_KEY"}) orelse return error.MissingApiKey;
            defer allocator.free(api_key);
            return search_providers.brave.execute(allocator, query, count, api_key, self.timeout_secs);
        },
        .firecrawl => {
            const api_key = tryApiKeyFromEnvOrNull(allocator, &.{ "FIRECRAWL_API_KEY", "WEB_SEARCH_API_KEY" }) orelse return error.MissingApiKey;
            defer allocator.free(api_key);
            return search_providers.firecrawl.execute(allocator, query, count, api_key, self.timeout_secs);
        },
        .tavily => {
            const api_key = tryApiKeyFromEnvOrNull(allocator, &.{ "TAVILY_API_KEY", "WEB_SEARCH_API_KEY" }) orelse return error.MissingApiKey;
            defer allocator.free(api_key);
            return search_providers.tavily.execute(allocator, query, count, api_key, self.timeout_secs);
        },
        .perplexity => {
            const api_key = tryApiKeyFromEnvOrNull(allocator, &.{ "PERPLEXITY_API_KEY", "WEB_SEARCH_API_KEY" }) orelse return error.MissingApiKey;
            defer allocator.free(api_key);
            return search_providers.perplexity.execute(allocator, query, count, api_key, self.timeout_secs);
        },
        .exa => {
            const api_key = tryApiKeyFromEnvOrNull(allocator, &.{ "EXA_API_KEY", "WEB_SEARCH_API_KEY" }) orelse return error.MissingApiKey;
            defer allocator.free(api_key);
            return search_providers.exa.execute(allocator, query, count, api_key, self.timeout_secs);
        },
        .jina => {
            const api_key = tryApiKeyFromEnvOrNull(allocator, &.{ "JINA_API_KEY", "WEB_SEARCH_API_KEY" }) orelse return error.MissingApiKey;
            defer allocator.free(api_key);
            return search_providers.jina.execute(allocator, query, api_key, self.timeout_secs);
        },
    }
}

fn tryApiKeyFromEnvOrNull(allocator: std.mem.Allocator, names: []const []const u8) ?[]const u8 {
    for (names) |name| {
        const key = platform.getEnvOrNull(allocator, name) orelse continue;
        if (std.mem.trim(u8, key, " \t\n\r").len == 0) {
            allocator.free(key);
            continue;
        }
        return key;
    }
    return null;
}

fn parseCount(args: JsonObjectMap) usize {
    const val_i64 = root.getInt(args, "count") orelse return DEFAULT_COUNT;
    if (val_i64 < 1) return 1;
    const val: usize = if (val_i64 > @as(i64, @intCast(MAX_RESULTS))) MAX_RESULTS else @intCast(val_i64);
    return val;
}

pub fn urlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    return search_common.urlEncode(allocator, input);
}

fn urlEncodePath(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    return search_common.urlEncodePath(allocator, input);
}

fn buildSearxngSearchUrl(
    allocator: std.mem.Allocator,
    base_url: []const u8,
    encoded_query: []const u8,
    count: usize,
) ![]u8 {
    return search_common.buildSearxngSearchUrl(allocator, base_url, encoded_query, count);
}

pub fn formatBraveResults(allocator: std.mem.Allocator, json_body: []const u8, query: []const u8) !ToolResult {
    return search_providers.brave.formatResults(allocator, json_body, query);
}

pub fn formatSearxngResults(allocator: std.mem.Allocator, json_body: []const u8, query: []const u8) !ToolResult {
    return search_providers.searxng.formatResults(allocator, json_body, query);
}

fn formatDuckDuckGoResults(allocator: std.mem.Allocator, json_body: []const u8, query: []const u8, count: usize) !ToolResult {
    return search_providers.duckduckgo.formatResults(allocator, json_body, query, count);
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

test "WebSearchTool without working provider chain returns aggregate error" {
    var wst = WebSearchTool{};
    const parsed = try root.parseTestArgs("{\"query\":\"zig programming\"}");
    defer parsed.deinit();
    const result = try wst.execute(testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| testing.allocator.free(e);
    try testing.expect(!result.success);
    try testing.expect(std.mem.indexOf(u8, result.error_msg.?, "All web_search providers failed") != null);
}

test "WebSearchTool invalid searxng URL reports config error" {
    var wst = WebSearchTool{ .searxng_base_url = "https://searx.example.com?bad=1", .provider = "searxng" };
    const parsed = try root.parseTestArgs("{\"query\":\"zig\"}");
    defer parsed.deinit();
    const result = try wst.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Invalid http_request.search_base_url") != null);
}

test "parseProvider accepts aliases" {
    try testing.expectEqual(SearchProvider.duckduckgo, parseProvider("ddg").?);
    try testing.expectEqual(SearchProvider.duckduckgo, parseProvider("duckduckgo").?);
    try testing.expectEqual(SearchProvider.brave, parseProvider("BRAVE").?);
    try testing.expect(parseProvider("google") == null);
}

test "buildProviderChain auto includes searxng when configured" {
    const fallbacks = [_][]const u8{"duckduckgo"};
    var wst = WebSearchTool{
        .searxng_base_url = "https://searx.example.com",
        .provider = "auto",
        .fallback_providers = &fallbacks,
    };

    var chain_buf: [MAX_PROVIDER_CHAIN]SearchProvider = undefined;
    const chain = try buildProviderChain(&wst, "auto", &chain_buf);
    try testing.expect(chain.len > 0);
    try testing.expectEqual(SearchProvider.searxng, chain[0]);
}

test "buildProviderChain rejects invalid fallback provider" {
    const fallbacks = [_][]const u8{"unknown"};
    var wst = WebSearchTool{ .fallback_providers = &fallbacks };
    var chain_buf: [MAX_PROVIDER_CHAIN]SearchProvider = undefined;
    try testing.expectError(error.InvalidProvider, buildProviderChain(&wst, "auto", &chain_buf));
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

test "urlEncodePath encodes spaces as percent" {
    const encoded = try urlEncodePath(testing.allocator, "hello world");
    defer testing.allocator.free(encoded);
    try testing.expectEqualStrings("hello%20world", encoded);
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

test "buildSearxngSearchUrl rejects query and fragment" {
    try testing.expectError(
        error.InvalidSearchBaseUrl,
        buildSearxngSearchUrl(testing.allocator, "https://searx.example.com?x=1", "zig", 3),
    );
    try testing.expectError(
        error.InvalidSearchBaseUrl,
        buildSearxngSearchUrl(testing.allocator, "https://searx.example.com#frag", "zig", 3),
    );
    try testing.expectError(
        error.InvalidSearchBaseUrl,
        buildSearxngSearchUrl(testing.allocator, "https://searx.example.com/custom", "zig", 3),
    );
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

test "formatDuckDuckGoResults parses related topics" {
    const json =
        \\{
        \\  "Heading": "Zig",
        \\  "AbstractText": "",
        \\  "AbstractURL": "",
        \\  "RelatedTopics": [
        \\    {"Text": "Zig - Programming language", "FirstURL": "https://ziglang.org"},
        \\    {"Topics": [
        \\      {"Text": "Ziglang docs - Official docs", "FirstURL": "https://ziglang.org/documentation/master/"}
        \\    ]}
        \\  ]
        \\}
    ;
    const result = try formatDuckDuckGoResults(testing.allocator, json, "zig", 5);
    defer testing.allocator.free(result.output);
    try testing.expect(result.success);
    try testing.expect(std.mem.indexOf(u8, result.output, "1. Zig") != null);
    try testing.expect(std.mem.indexOf(u8, result.output, "https://ziglang.org") != null);
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
