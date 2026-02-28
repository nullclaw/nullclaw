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
const builtin = @import("builtin");
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

const ProviderSearchError = error{
    InvalidProvider,
    InvalidSearchBaseUrl,
    MissingApiKey,
    ProviderUnavailable,
    RequestFailed,
    InvalidResponse,
};

const ResultEntry = struct {
    title: []const u8,
    url: []const u8,
    description: []const u8,
};

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
                // Invalid base URL is a configuration error: fail hard.
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

fn logRequestError(provider: []const u8, query: []const u8, err: anytype) void {
    if (builtin.is_test) return;
    log.err("web_search ({s}) request failed for '{s}': {}", .{ provider, query, err });
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
            return executeSearxngSearch(allocator, query, count, trimmed, self.timeout_secs);
        },
        .duckduckgo => return executeDuckDuckGoSearch(allocator, query, count, self.timeout_secs),
        .brave => {
            const api_key = tryApiKeyFromEnvOrNull(allocator, &.{"BRAVE_API_KEY"}) orelse return error.MissingApiKey;
            defer allocator.free(api_key);
            return executeBraveSearch(allocator, query, count, api_key, self.timeout_secs);
        },
        .firecrawl => {
            const api_key = tryApiKeyFromEnvOrNull(allocator, &.{ "FIRECRAWL_API_KEY", "WEB_SEARCH_API_KEY" }) orelse return error.MissingApiKey;
            defer allocator.free(api_key);
            return executeFirecrawlSearch(allocator, query, count, api_key, self.timeout_secs);
        },
        .tavily => {
            const api_key = tryApiKeyFromEnvOrNull(allocator, &.{ "TAVILY_API_KEY", "WEB_SEARCH_API_KEY" }) orelse return error.MissingApiKey;
            defer allocator.free(api_key);
            return executeTavilySearch(allocator, query, count, api_key, self.timeout_secs);
        },
        .perplexity => {
            const api_key = tryApiKeyFromEnvOrNull(allocator, &.{ "PERPLEXITY_API_KEY", "WEB_SEARCH_API_KEY" }) orelse return error.MissingApiKey;
            defer allocator.free(api_key);
            return executePerplexitySearch(allocator, query, count, api_key, self.timeout_secs);
        },
        .exa => {
            const api_key = tryApiKeyFromEnvOrNull(allocator, &.{ "EXA_API_KEY", "WEB_SEARCH_API_KEY" }) orelse return error.MissingApiKey;
            defer allocator.free(api_key);
            return executeExaSearch(allocator, query, count, api_key, self.timeout_secs);
        },
        .jina => {
            const api_key = tryApiKeyFromEnvOrNull(allocator, &.{ "JINA_API_KEY", "WEB_SEARCH_API_KEY" });
            defer if (api_key) |key| allocator.free(key);
            return executeJinaSearch(allocator, query, api_key, self.timeout_secs);
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

fn executeBraveSearch(
    allocator: std.mem.Allocator,
    query: []const u8,
    count: usize,
    api_key: []const u8,
    timeout_secs: u64,
) (ProviderSearchError || error{OutOfMemory})!ToolResult {
    const encoded_query = try urlEncode(allocator, query);
    defer allocator.free(encoded_query);

    const url_str = try std.fmt.allocPrint(
        allocator,
        "https://api.search.brave.com/res/v1/web/search?q={s}&count={d}",
        .{ encoded_query, count },
    );
    defer allocator.free(url_str);

    const timeout_str = try timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    const auth_header = try std.fmt.allocPrint(allocator, "X-Subscription-Token: {s}", .{api_key});
    defer allocator.free(auth_header);
    const headers = [_][]const u8{
        auth_header,
        "Accept: application/json",
    };

    const body = curlGet(allocator, url_str, &headers, timeout_str) catch |err| {
        logRequestError("brave", query, err);
        return err;
    };
    defer allocator.free(body);

    const result = try formatBraveResults(allocator, body, query);
    if (!result.success) return error.InvalidResponse;
    return result;
}

fn executeFirecrawlSearch(
    allocator: std.mem.Allocator,
    query: []const u8,
    count: usize,
    api_key: []const u8,
    timeout_secs: u64,
) (ProviderSearchError || error{OutOfMemory})!ToolResult {
    const timeout_str = try timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    const endpoint = "https://api.firecrawl.dev/v1/search";
    const auth_header = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{api_key});
    defer allocator.free(auth_header);

    const payload = .{
        .query = query,
        .limit = count,
        .timeout = timeout_secs * 1000,
    };
    const body_json = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(body_json);

    const headers = [_][]const u8{
        auth_header,
        "Content-Type: application/json",
        "Accept: application/json",
    };

    const body = curlPostJson(allocator, endpoint, body_json, &headers, timeout_str) catch |err| {
        logRequestError("firecrawl", query, err);
        return err;
    };
    defer allocator.free(body);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.InvalidResponse;
    defer parsed.deinit();

    const root_val = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidResponse,
    };

    if (root_val.get("success")) |success_val| {
        if (success_val != .bool or !success_val.bool) return error.RequestFailed;
    }

    const results = root_val.get("data") orelse return error.InvalidResponse;
    const results_arr = switch (results) {
        .array => |a| a,
        else => return error.InvalidResponse,
    };

    if (results_arr.items.len == 0) return ToolResult.ok("No web results found.");
    return formatResultsArray(allocator, results_arr.items, query, "description", null);
}

fn executeTavilySearch(
    allocator: std.mem.Allocator,
    query: []const u8,
    count: usize,
    api_key: []const u8,
    timeout_secs: u64,
) (ProviderSearchError || error{OutOfMemory})!ToolResult {
    const timeout_str = try timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    const endpoint = "https://api.tavily.com/search";
    const payload = .{
        .api_key = api_key,
        .query = query,
        .max_results = count,
        .search_depth = "basic",
        .include_answer = false,
        .include_raw_content = false,
        .include_images = false,
    };
    const body_json = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(body_json);

    const headers = [_][]const u8{
        "Content-Type: application/json",
        "Accept: application/json",
    };

    const body = curlPostJson(allocator, endpoint, body_json, &headers, timeout_str) catch |err| {
        logRequestError("tavily", query, err);
        return err;
    };
    defer allocator.free(body);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.InvalidResponse;
    defer parsed.deinit();

    const root_val = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidResponse,
    };

    if (root_val.get("error")) |_| return error.RequestFailed;

    const results = root_val.get("results") orelse return error.InvalidResponse;
    const results_arr = switch (results) {
        .array => |a| a,
        else => return error.InvalidResponse,
    };

    if (results_arr.items.len == 0) return ToolResult.ok("No web results found.");
    return formatResultsArray(allocator, results_arr.items, query, "content", null);
}

fn executePerplexitySearch(
    allocator: std.mem.Allocator,
    query: []const u8,
    count: usize,
    api_key: []const u8,
    timeout_secs: u64,
) (ProviderSearchError || error{OutOfMemory})!ToolResult {
    const timeout_str = try timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    const endpoint = "https://api.perplexity.ai/search";
    const auth_header = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{api_key});
    defer allocator.free(auth_header);

    const payload = .{
        .query = query,
        .max_results = count,
    };
    const body_json = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(body_json);

    const headers = [_][]const u8{
        auth_header,
        "Content-Type: application/json",
        "Accept: application/json",
    };

    const body = curlPostJson(allocator, endpoint, body_json, &headers, timeout_str) catch |err| {
        logRequestError("perplexity", query, err);
        return err;
    };
    defer allocator.free(body);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.InvalidResponse;
    defer parsed.deinit();

    const root_val = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidResponse,
    };

    const results = root_val.get("results") orelse return error.InvalidResponse;
    const results_arr = switch (results) {
        .array => |a| a,
        else => return error.InvalidResponse,
    };

    if (results_arr.items.len == 0) return ToolResult.ok("No web results found.");
    return formatResultsArray(allocator, results_arr.items, query, "snippet", null);
}

fn executeExaSearch(
    allocator: std.mem.Allocator,
    query: []const u8,
    count: usize,
    api_key: []const u8,
    timeout_secs: u64,
) (ProviderSearchError || error{OutOfMemory})!ToolResult {
    const timeout_str = try timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    const endpoint = "https://api.exa.ai/search";
    const key_header = try std.fmt.allocPrint(allocator, "x-api-key: {s}", .{api_key});
    defer allocator.free(key_header);

    const payload = .{
        .query = query,
        .numResults = count,
    };
    const body_json = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(body_json);

    const headers = [_][]const u8{
        key_header,
        "Content-Type: application/json",
        "Accept: application/json",
    };

    const body = curlPostJson(allocator, endpoint, body_json, &headers, timeout_str) catch |err| {
        logRequestError("exa", query, err);
        return err;
    };
    defer allocator.free(body);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.InvalidResponse;
    defer parsed.deinit();

    const root_val = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidResponse,
    };

    const results = root_val.get("results") orelse return error.InvalidResponse;
    const results_arr = switch (results) {
        .array => |a| a,
        else => return error.InvalidResponse,
    };

    if (results_arr.items.len == 0) return ToolResult.ok("No web results found.");
    return formatResultsArray(allocator, results_arr.items, query, "summary", "text");
}

fn executeJinaSearch(
    allocator: std.mem.Allocator,
    query: []const u8,
    api_key: ?[]const u8,
    timeout_secs: u64,
) (ProviderSearchError || error{OutOfMemory})!ToolResult {
    const encoded_query = try urlEncodePath(allocator, query);
    defer allocator.free(encoded_query);

    const url_str = try std.fmt.allocPrint(allocator, "https://s.jina.ai/{s}", .{encoded_query});
    defer allocator.free(url_str);

    const timeout_str = try timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    if (api_key) |key| {
        const auth_header = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{key});
        defer allocator.free(auth_header);
        const x_key_header = try std.fmt.allocPrint(allocator, "x-api-key: {s}", .{key});
        defer allocator.free(x_key_header);

        const headers = [_][]const u8{
            "Accept: text/plain",
            auth_header,
            x_key_header,
        };

        const body = curlGet(allocator, url_str, &headers, timeout_str) catch |err| {
            logRequestError("jina", query, err);
            return err;
        };
        defer allocator.free(body);

        return formatJinaPlainText(allocator, body, query);
    }

    const headers = [_][]const u8{"Accept: text/plain"};
    const body = curlGet(allocator, url_str, &headers, timeout_str) catch |err| {
        logRequestError("jina", query, err);
        return err;
    };
    defer allocator.free(body);

    return formatJinaPlainText(allocator, body, query);
}

fn formatJinaPlainText(allocator: std.mem.Allocator, text: []const u8, query: []const u8) !ToolResult {
    const trimmed = std.mem.trim(u8, text, " \t\n\r");
    if (trimmed.len == 0) return ToolResult.ok("No web results found.");

    const output = try std.fmt.allocPrint(allocator, "Results for: {s}\n\n{s}", .{ query, trimmed });
    return ToolResult{ .success = true, .output = output };
}

fn executeDuckDuckGoSearch(
    allocator: std.mem.Allocator,
    query: []const u8,
    count: usize,
    timeout_secs: u64,
) (ProviderSearchError || error{OutOfMemory})!ToolResult {
    const encoded_query = try urlEncode(allocator, query);
    defer allocator.free(encoded_query);

    const url_str = try std.fmt.allocPrint(
        allocator,
        "https://api.duckduckgo.com/?q={s}&format=json&no_html=1&skip_disambig=1",
        .{encoded_query},
    );
    defer allocator.free(url_str);

    const timeout_str = try timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    const headers = [_][]const u8{
        "Accept: application/json",
    };

    const body = curlGet(allocator, url_str, &headers, timeout_str) catch |err| {
        logRequestError("duckduckgo", query, err);
        return err;
    };
    defer allocator.free(body);

    const result = try formatDuckDuckGoResults(allocator, body, query, count);
    if (!result.success) return error.InvalidResponse;
    return result;
}

fn executeSearxngSearch(
    allocator: std.mem.Allocator,
    query: []const u8,
    count: usize,
    base_url: []const u8,
    timeout_secs: u64,
) (ProviderSearchError || error{OutOfMemory})!ToolResult {
    const encoded_query = try urlEncode(allocator, query);
    defer allocator.free(encoded_query);

    const url_str = buildSearxngSearchUrl(allocator, base_url, encoded_query, count) catch |err| switch (err) {
        error.InvalidSearchBaseUrl => return error.InvalidSearchBaseUrl,
        else => return err,
    };
    defer allocator.free(url_str);

    const timeout_str = try timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    const headers = [_][]const u8{
        "Accept: application/json",
        "User-Agent: nullclaw/0.1 (web_search)",
    };

    const body = curlGet(allocator, url_str, &headers, timeout_str) catch |err| {
        logRequestError("searxng", query, err);
        return err;
    };
    defer allocator.free(body);

    const result = try formatSearxngResults(allocator, body, query);
    if (!result.success) return error.InvalidResponse;
    return result;
}

fn curlGet(
    allocator: std.mem.Allocator,
    url: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
) (ProviderSearchError || error{OutOfMemory})![]u8 {
    if (builtin.is_test) return error.RequestFailed;

    return http_util.curlGet(allocator, url, headers, timeout_secs) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.RequestFailed,
    };
}

fn curlPostJson(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    headers: []const []const u8,
    timeout_secs: []const u8,
) (ProviderSearchError || error{OutOfMemory})![]u8 {
    if (builtin.is_test) return error.RequestFailed;

    return http_util.curlPostWithProxy(allocator, url, body, headers, null, timeout_secs) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.RequestFailed,
    };
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
    if (trimmed.len == 0) return error.InvalidSearchBaseUrl;
    while (trimmed.len > 0 and trimmed[trimmed.len - 1] == '/') {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }
    if (!std.mem.startsWith(u8, trimmed, "https://")) return error.InvalidSearchBaseUrl;
    if (std.mem.indexOfAny(u8, trimmed, "?#") != null) {
        return error.InvalidSearchBaseUrl;
    }
    const after_scheme = trimmed["https://".len..];
    if (after_scheme.len == 0 or after_scheme[0] == '/') {
        return error.InvalidSearchBaseUrl;
    }
    const authority_end = std.mem.indexOfScalar(u8, after_scheme, '/') orelse after_scheme.len;
    const authority = after_scheme[0..authority_end];
    if (authority.len == 0 or std.mem.indexOfAny(u8, authority, " \t\r\n") != null) {
        return error.InvalidSearchBaseUrl;
    }
    if (authority_end < after_scheme.len) {
        const path = after_scheme[authority_end..];
        if (!std.mem.eql(u8, path, "/search")) {
            return error.InvalidSearchBaseUrl;
        }
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

/// URL-encode a string for query components.
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

/// URL-encode a string for path components.
fn urlEncodePath(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    for (input) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try buf.append(allocator, c);
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

    return formatResultsArray(allocator, results_arr.items, query, "description", null);
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

    return formatResultsArray(allocator, results_arr.items, query, "content", null);
}

fn formatDuckDuckGoResults(allocator: std.mem.Allocator, json_body: []const u8, query: []const u8, count: usize) !ToolResult {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_body, .{}) catch
        return ToolResult.fail("Failed to parse search response JSON");
    defer parsed.deinit();

    const root_val = switch (parsed.value) {
        .object => |o| o,
        else => return ToolResult.fail("Unexpected search response format"),
    };

    var entries: [MAX_RESULTS]ResultEntry = undefined;
    var entry_len: usize = 0;

    const heading = extractString(root_val, "Heading") orelse "";
    const abstract_text = extractString(root_val, "AbstractText") orelse "";
    const abstract_url = extractString(root_val, "AbstractURL") orelse "";

    if (abstract_url.len > 0 and abstract_text.len > 0 and entry_len < count) {
        const title = if (heading.len > 0) heading else duckduckgoTitleFromText(abstract_text);
        entries[entry_len] = .{
            .title = title,
            .url = abstract_url,
            .description = abstract_text,
        };
        entry_len += 1;
    }

    if (root_val.get("RelatedTopics")) |related_topics| {
        if (related_topics == .array) {
            collectDuckDuckGoTopics(related_topics.array.items, &entries, &entry_len, count);
        }
    }

    if (entry_len == 0) return ToolResult.ok("No web results found.");
    return formatResultEntries(allocator, query, entries[0..entry_len]);
}

fn collectDuckDuckGoTopics(
    topics: []const std.json.Value,
    entries: *[MAX_RESULTS]ResultEntry,
    entry_len: *usize,
    max_results: usize,
) void {
    for (topics) |topic| {
        if (entry_len.* >= max_results) return;

        const topic_obj = switch (topic) {
            .object => |o| o,
            else => continue,
        };

        const text = extractString(topic_obj, "Text");
        const first_url = extractString(topic_obj, "FirstURL");

        if (text != null and first_url != null and text.?.len > 0 and first_url.?.len > 0) {
            entries[entry_len.*] = .{
                .title = duckduckgoTitleFromText(text.?),
                .url = first_url.?,
                .description = text.?,
            };
            entry_len.* += 1;
            continue;
        }

        if (topic_obj.get("Topics")) |nested_topics| {
            if (nested_topics == .array) {
                collectDuckDuckGoTopics(nested_topics.array.items, entries, entry_len, max_results);
            }
        }
    }
}

fn duckduckgoTitleFromText(text: []const u8) []const u8 {
    if (std.mem.indexOf(u8, text, " - ")) |idx| {
        if (idx > 0) return text[0..idx];
    }
    if (std.mem.indexOf(u8, text, " — ")) |idx| {
        if (idx > 0) return text[0..idx];
    }
    return text;
}

fn formatResultEntries(allocator: std.mem.Allocator, query: []const u8, entries: []const ResultEntry) !ToolResult {
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

fn formatResultsArray(
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
