const std = @import("std");
const platform = @import("../platform.zig");
const root = @import("root.zig");
const error_classify = @import("error_classify.zig");
const config_types = @import("../config_types.zig");
const http_util = @import("../http_util.zig");
const sse = @import("sse.zig");

const Provider = root.Provider;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;
const OAUTH_REFRESH_TIMEOUT_SECS: u64 = 20;

fn parseExpiresIn(v: std.json.Value) ?i64 {
    return switch (v) {
        .integer => |i| if (i > 0) i else null,
        .float => |f| blk: {
            if (!std.math.isFinite(f) or f <= 0) break :blk null;
            if (f > @as(f64, @floatFromInt(std.math.maxInt(i64)))) break :blk null;
            break :blk @intFromFloat(f);
        },
        else => null,
    };
}

fn parseTokenCount(v: std.json.Value) ?u32 {
    return switch (v) {
        .integer => |i| blk: {
            if (i < 0) break :blk null;
            break :blk std.math.cast(u32, i) orelse std.math.maxInt(u32);
        },
        .float => |f| blk: {
            if (!std.math.isFinite(f) or f < 0) break :blk null;
            const max_u32_f = @as(f64, @floatFromInt(std.math.maxInt(u32)));
            if (f > max_u32_f) break :blk std.math.maxInt(u32);
            break :blk @intFromFloat(f);
        },
        else => null,
    };
}

fn normalizeTokenUsage(usage: *root.TokenUsage) void {
    if (usage.total_tokens == 0 and (usage.prompt_tokens > 0 or usage.completion_tokens > 0)) {
        usage.total_tokens = usage.prompt_tokens +| usage.completion_tokens;
    }
    if (usage.completion_tokens == 0 and usage.total_tokens > usage.prompt_tokens) {
        usage.completion_tokens = usage.total_tokens - usage.prompt_tokens;
    }
}

fn parseUsageMetadataValue(v: std.json.Value) ?root.TokenUsage {
    if (v != .object) return null;
    const usage_obj = v.object;

    var usage = root.TokenUsage{};
    var found = false;

    if (usage_obj.get("promptTokenCount")) |count| {
        if (parseTokenCount(count)) |parsed| {
            usage.prompt_tokens = parsed;
            found = true;
        }
    }
    if (usage_obj.get("candidatesTokenCount")) |count| {
        if (parseTokenCount(count)) |parsed| {
            usage.completion_tokens = parsed;
            found = true;
        }
    }
    if (usage_obj.get("totalTokenCount")) |count| {
        if (parseTokenCount(count)) |parsed| {
            usage.total_tokens = parsed;
            found = true;
        }
    }

    if (!found) return null;
    normalizeTokenUsage(&usage);
    return usage;
}

pub fn extractGeminiUsageMetadata(allocator: std.mem.Allocator, json_str: []const u8) !?root.TokenUsage {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch
        return error.InvalidSseJson;
    defer parsed.deinit();

    const usage_val = parsed.value.object.get("usageMetadata") orelse return null;
    return parseUsageMetadataValue(usage_val);
}

fn extractGeminiUsageFromSseLine(allocator: std.mem.Allocator, line: []const u8) !?root.TokenUsage {
    const trimmed = std.mem.trimRight(u8, line, "\r");
    if (trimmed.len == 0 or trimmed[0] == ':') return null;

    const prefix = "data: ";
    if (!std.mem.startsWith(u8, trimmed, prefix)) return null;
    const data = trimmed[prefix.len..];

    return try extractGeminiUsageMetadata(allocator, data);
}

fn isFormUrlencodedUnreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
}

fn appendFormUrlencodedValue(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    value: []const u8,
) !void {
    const HEX = "0123456789ABCDEF";
    for (value) |c| {
        if (isFormUrlencodedUnreserved(c)) {
            try buf.append(allocator, c);
        } else if (c == ' ') {
            try buf.append(allocator, '+');
        } else {
            try buf.append(allocator, '%');
            try buf.append(allocator, HEX[(c >> 4) & 0x0F]);
            try buf.append(allocator, HEX[c & 0x0F]);
        }
    }
}

fn appendFormField(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    key: []const u8,
    value: []const u8,
) !void {
    if (buf.items.len > 0) try buf.append(allocator, '&');
    try appendFormUrlencodedValue(buf, allocator, key);
    try buf.append(allocator, '=');
    try appendFormUrlencodedValue(buf, allocator, value);
}

fn buildRefreshFormBody(
    allocator: std.mem.Allocator,
    refresh_token: []const u8,
    client_id: []const u8,
    client_secret: []const u8,
) ![]u8 {
    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);

    try appendFormField(&body, allocator, "grant_type", "refresh_token");
    try appendFormField(&body, allocator, "refresh_token", refresh_token);
    try appendFormField(&body, allocator, "client_id", client_id);
    try appendFormField(&body, allocator, "client_secret", client_secret);

    return try body.toOwnedSlice(allocator);
}

/// Credentials loaded from the Gemini CLI OAuth token file (~/.gemini/oauth_creds.json).
pub const GeminiCliCredentials = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8,
    expires_at: ?i64,

    /// Returns true if the token is expired (or within 5 minutes of expiring).
    /// If expires_at is null, the token is treated as never-expiring.
    pub fn isExpired(self: GeminiCliCredentials) bool {
        const expiry = self.expires_at orelse return false;
        const now = std.time.timestamp();
        const buffer_seconds: i64 = 5 * 60; // 5-minute safety buffer
        return now >= (expiry - buffer_seconds);
    }
};

/// Parse Gemini CLI credentials from a JSON byte slice.
/// Returns null if the JSON is invalid or missing the required `access_token` field.
pub fn parseCredentialsJson(allocator: std.mem.Allocator, json_bytes: []const u8) ?GeminiCliCredentials {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return null;
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return null,
    };

    // access_token is required
    const access_token_val = root_obj.get("access_token") orelse return null;
    const access_token_str = switch (access_token_val) {
        .string => |s| s,
        else => return null,
    };
    if (access_token_str.len == 0) return null;

    // Dupe access_token so it survives parsed.deinit()
    const access_token = allocator.dupe(u8, access_token_str) catch return null;

    // refresh_token is optional
    const refresh_token: ?[]const u8 = if (root_obj.get("refresh_token")) |rt_val| blk: {
        switch (rt_val) {
            .string => |s| {
                if (s.len > 0) {
                    break :blk allocator.dupe(u8, s) catch null;
                }
                break :blk null;
            },
            else => break :blk null,
        }
    } else null;

    // expires_at is optional (unix timestamp)
    const expires_at: ?i64 = if (root_obj.get("expires_at")) |ea_val| blk: {
        switch (ea_val) {
            .integer => |i| break :blk i,
            .float => |f| break :blk @intFromFloat(f),
            else => break :blk null,
        }
    } else null;

    return .{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .expires_at = expires_at,
    };
}

/// OAuth token refresh response from Google.
const RefreshResponse = struct {
    access_token: []const u8,
    expires_in: i64,
};

/// Parse OAuth token refresh response from Google's JSON.
/// Returns null if JSON is invalid or missing required fields.
/// Returned access_token is duped and owned by caller.
pub fn parseRefreshResponse(allocator: std.mem.Allocator, json_bytes: []const u8) ?RefreshResponse {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return null;
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return null,
    };

    if (root_obj.get("error")) |_| return null;

    const access_token_val = root_obj.get("access_token") orelse return null;
    const access_token_str = switch (access_token_val) {
        .string => |s| s,
        else => return null,
    };
    if (access_token_str.len == 0) return null;

    const expires_in_val = root_obj.get("expires_in") orelse return null;
    const expires_in = parseExpiresIn(expires_in_val) orelse return null;

    // Dupe access_token so it survives parsed.deinit()
    const access_token = allocator.dupe(u8, access_token_str) catch return null;

    return .{
        .access_token = access_token,
        .expires_in = expires_in,
    };
}

/// Refresh an OAuth token using Google's OAuth2 endpoint.
/// Returns the refresh response (access token owned by caller) or error.
/// Uses builtin.is_test guard to skip actual HTTP calls in tests.
pub fn refreshOAuthToken(allocator: std.mem.Allocator, refresh_token: []const u8) !RefreshResponse {
    if (@import("builtin").is_test) {
        return .{
            .access_token = try allocator.dupe(u8, "test-refreshed-token"),
            .expires_in = 3600,
        };
    }

    // Public client credentials from the Gemini CLI (not secret)
    const client_id = "936475272427.apps.googleusercontent.com";
    const client_secret = "KWaLJfKpIyrGyVOIF2t66XCO";

    const body = try buildRefreshFormBody(allocator, refresh_token, client_id, client_secret);
    defer allocator.free(body);

    const url = "https://oauth2.googleapis.com/token";

    const resp_body = root.curlPostFormTimed(
        allocator,
        url,
        body,
        OAUTH_REFRESH_TIMEOUT_SECS,
    ) catch return error.RefreshFailed;
    defer allocator.free(resp_body);

    return parseRefreshResponse(allocator, resp_body) orelse return error.RefreshFailed;
}

/// Write credentials back to ~/.gemini/oauth_creds.json.
pub fn writeCredentialsJson(allocator: std.mem.Allocator, creds: GeminiCliCredentials, path: []const u8) !void {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"access_token\":");
    try root.appendJsonString(&buf, allocator, creds.access_token);

    if (creds.refresh_token) |rt| {
        try buf.appendSlice(allocator, ",\"refresh_token\":");
        try root.appendJsonString(&buf, allocator, rt);
    }

    if (creds.expires_at) |exp| {
        try buf.appendSlice(allocator, ",\"expires_at\":");
        var num_buf: [24]u8 = undefined;
        const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{exp}) catch return error.FormatError;
        try buf.appendSlice(allocator, num_str);
    }

    try buf.append(allocator, '}');

    const file = std.fs.createFileAbsolute(path, .{ .mode = 0o600 }) catch return error.FileWriteError;
    defer file.close();
    try file.writeAll(buf.items);
}

/// Try to load Gemini CLI OAuth credentials from ~/.gemini/oauth_creds.json.
/// If token is expired but refresh_token is available, attempts to refresh.
/// Returns null on any error (file not found, parse failure, refresh failed, etc.).
pub fn tryLoadGeminiCliToken(allocator: std.mem.Allocator) ?GeminiCliCredentials {
    // Keep tests deterministic and side-effect free: never read or write real
    // ~/.gemini credentials while running under std.testing.
    if (@import("builtin").is_test) return null;

    const home = platform.getHomeDir(allocator) catch return null;
    defer allocator.free(home);

    const path = std.fs.path.join(allocator, &.{ home, ".gemini", "oauth_creds.json" }) catch return null;
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();

    const json_bytes = file.readToEndAlloc(allocator, 1024 * 1024) catch return null;
    defer allocator.free(json_bytes);

    const creds = parseCredentialsJson(allocator, json_bytes) orelse return null;

    // Check expiration
    if (creds.isExpired()) {
        // Attempt refresh if refresh_token is available
        if (creds.refresh_token) |rt| {
            if (refreshOAuthToken(allocator, rt)) |refreshed_resp| {
                // Build refreshed credentials
                const now = std.time.timestamp();
                const ttl: i64 = if (refreshed_resp.expires_in > 0) refreshed_resp.expires_in else 3600;
                const new_expires_at = std.math.add(i64, now, ttl) catch std.math.maxInt(i64);

                const refreshed = GeminiCliCredentials{
                    .access_token = refreshed_resp.access_token,
                    .refresh_token = allocator.dupe(u8, rt) catch {
                        allocator.free(refreshed_resp.access_token);
                        allocator.free(creds.access_token);
                        if (creds.refresh_token) |r| allocator.free(r);
                        return null;
                    },
                    .expires_at = new_expires_at,
                };

                // Persist refreshed token (non-fatal on failure)
                writeCredentialsJson(allocator, refreshed, path) catch {};

                // Clean up original creds
                allocator.free(creds.access_token);
                if (creds.refresh_token) |r| allocator.free(r);

                return refreshed;
            } else |_| {}
        }

        // Refresh unavailable or failed — clean up and return null
        allocator.free(creds.access_token);
        if (creds.refresh_token) |rt| allocator.free(rt);
        return null;
    }

    return creds;
}

/// Authentication method for Gemini.
pub const GeminiAuth = union(enum) {
    /// Explicit API key from config: sent as `?key=` query parameter.
    explicit_key: []const u8,
    /// API key from `GEMINI_API_KEY` env var.
    env_gemini_key: []const u8,
    /// API key from `GOOGLE_API_KEY` env var.
    env_google_key: []const u8,
    /// OAuth access token from `GEMINI_OAUTH_TOKEN` env var.
    env_oauth_token: []const u8,
    /// OAuth access token from Gemini CLI: sent as `Authorization: Bearer`.
    oauth_token: []const u8,

    pub fn isApiKey(self: GeminiAuth) bool {
        return switch (self) {
            .explicit_key, .env_gemini_key, .env_google_key => true,
            .env_oauth_token, .oauth_token => false,
        };
    }

    pub fn credential(self: GeminiAuth) []const u8 {
        return switch (self) {
            .explicit_key => |v| v,
            .env_gemini_key => |v| v,
            .env_google_key => |v| v,
            .env_oauth_token => |v| v,
            .oauth_token => |v| v,
        };
    }

    pub fn source(self: GeminiAuth) []const u8 {
        return switch (self) {
            .explicit_key => "config",
            .env_gemini_key => "GEMINI_API_KEY env var",
            .env_google_key => "GOOGLE_API_KEY env var",
            .env_oauth_token => "GEMINI_OAUTH_TOKEN env var",
            .oauth_token => "Gemini CLI OAuth",
        };
    }
};

/// Google Gemini provider with support for:
/// - Direct API key (`GEMINI_API_KEY` env var or config)
/// - Gemini CLI OAuth tokens (reuse existing ~/.gemini/ authentication)
/// - Google Cloud ADC (`GOOGLE_APPLICATION_CREDENTIALS`)
pub const GeminiProvider = struct {
    auth: ?GeminiAuth,
    allocator: std.mem.Allocator,

    const BASE_URL = "https://generativelanguage.googleapis.com/v1beta";
    const DEFAULT_MAX_OUTPUT_TOKENS: u32 = config_types.DEFAULT_MODEL_MAX_TOKENS;

    pub fn init(allocator: std.mem.Allocator, api_key: ?[]const u8) GeminiProvider {
        var auth: ?GeminiAuth = null;

        // 1. Explicit key
        if (api_key) |key| {
            const trimmed = std.mem.trim(u8, key, " \t\r\n");
            if (trimmed.len > 0) {
                auth = .{ .explicit_key = trimmed };
            }
        }

        // 2. Environment variables (only if no explicit key)
        if (auth == null) {
            if (loadNonEmptyEnv(allocator, "GEMINI_API_KEY")) |value| {
                auth = .{ .env_gemini_key = value };
                // Note: value is NOT freed — ownership transfers to auth
            }
        }

        if (auth == null) {
            if (loadNonEmptyEnv(allocator, "GOOGLE_API_KEY")) |value| {
                auth = .{ .env_google_key = value };
                // Note: value is NOT freed — ownership transfers to auth
            }
        }

        // 2b. GEMINI_OAUTH_TOKEN env var (explicit OAuth token)
        if (auth == null) {
            if (loadNonEmptyEnv(allocator, "GEMINI_OAUTH_TOKEN")) |value| {
                auth = .{ .env_oauth_token = value };
                // Note: value is NOT freed — ownership transfers to auth
            }
        }

        // 3. Gemini CLI OAuth token (~/.gemini/oauth_creds.json) as final fallback
        if (auth == null) {
            if (tryLoadGeminiCliToken(allocator)) |creds| {
                auth = .{ .oauth_token = creds.access_token };
                // Note: refresh_token and expires_at are not stored in GeminiAuth,
                // they are only used for the initial validity check.
                // Free refresh_token if it was allocated — we only keep access_token.
                if (creds.refresh_token) |rt| allocator.free(rt);
            }
        }

        return .{
            .auth = auth,
            .allocator = allocator,
        };
    }

    fn loadNonEmptyEnv(allocator: std.mem.Allocator, name: []const u8) ?[]u8 {
        if (std.process.getEnvVarOwned(allocator, name)) |value| {
            defer allocator.free(value);
            const trimmed = std.mem.trim(u8, value, " \t\r\n");
            if (trimmed.len > 0) {
                return allocator.dupe(u8, trimmed) catch null;
            }
            return null;
        } else |_| {
            return null;
        }
    }

    /// Get authentication source description for diagnostics.
    pub fn authSource(self: GeminiProvider) []const u8 {
        if (self.auth) |auth| {
            return auth.source();
        }
        return "none";
    }

    /// Format a model name, prepending "models/" if not already present.
    pub fn formatModelName(model: []const u8) FormatModelResult {
        if (std.mem.startsWith(u8, model, "models/")) {
            return .{ .formatted = model, .needs_free = false };
        }
        return .{ .formatted = model, .needs_free = false, .needs_prefix = true };
    }

    pub const FormatModelResult = struct {
        formatted: []const u8,
        needs_free: bool,
        needs_prefix: bool = false,
    };

    /// Build the generateContent URL.
    pub fn buildUrl(allocator: std.mem.Allocator, model: []const u8, auth: GeminiAuth) ![]const u8 {
        const model_name = if (std.mem.startsWith(u8, model, "models/"))
            model
        else
            try std.fmt.allocPrint(allocator, "models/{s}", .{model});

        if (auth.isApiKey()) {
            const url = try std.fmt.allocPrint(
                allocator,
                "{s}/{s}:generateContent?key={s}",
                .{ BASE_URL, model_name, auth.credential() },
            );
            if (!std.mem.startsWith(u8, model, "models/")) {
                allocator.free(@constCast(model_name));
            }
            return url;
        } else {
            const url = try std.fmt.allocPrint(
                allocator,
                "{s}/{s}:generateContent",
                .{ BASE_URL, model_name },
            );
            if (!std.mem.startsWith(u8, model, "models/")) {
                allocator.free(@constCast(model_name));
            }
            return url;
        }
    }

    /// Build the streamGenerateContent URL for SSE streaming.
    pub fn buildStreamUrl(allocator: std.mem.Allocator, model: []const u8, auth: GeminiAuth) ![]const u8 {
        const model_name = if (std.mem.startsWith(u8, model, "models/"))
            model
        else
            try std.fmt.allocPrint(allocator, "models/{s}", .{model});

        if (auth.isApiKey()) {
            const url = try std.fmt.allocPrint(
                allocator,
                "{s}/{s}:streamGenerateContent?key={s}&alt=sse",
                .{ BASE_URL, model_name, auth.credential() },
            );
            if (!std.mem.startsWith(u8, model, "models/")) {
                allocator.free(@constCast(model_name));
            }
            return url;
        } else {
            const url = try std.fmt.allocPrint(
                allocator,
                "{s}/{s}:streamGenerateContent?alt=sse",
                .{ BASE_URL, model_name },
            );
            if (!std.mem.startsWith(u8, model, "models/")) {
                allocator.free(@constCast(model_name));
            }
            return url;
        }
    }

    /// Build a Gemini generateContent request body.
    pub fn buildRequestBody(
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        temperature: f64,
    ) ![]const u8 {
        if (system_prompt) |sys| {
            return std.fmt.allocPrint(allocator,
                \\{{"contents":[{{"role":"user","parts":[{{"text":"{s}"}}]}}],"system_instruction":{{"parts":[{{"text":"{s}"}}]}},"generationConfig":{{"temperature":{d:.2},"maxOutputTokens":{d}}}}}
            , .{ message, sys, temperature, DEFAULT_MAX_OUTPUT_TOKENS });
        } else {
            return std.fmt.allocPrint(allocator,
                \\{{"contents":[{{"role":"user","parts":[{{"text":"{s}"}}]}}],"generationConfig":{{"temperature":{d:.2},"maxOutputTokens":{d}}}}}
            , .{ message, temperature, DEFAULT_MAX_OUTPUT_TOKENS });
        }
    }

    /// Parse text and token usage from a Gemini generateContent response.
    pub fn parseChatResponse(allocator: std.mem.Allocator, body: []const u8) !ChatResponse {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
        defer parsed.deinit();
        const root_obj = parsed.value.object;

        // Check for error first
        if (error_classify.classifyKnownApiError(root_obj)) |kind| {
            const mapped_err = error_classify.kindToError(kind);
            var summary_buf: [1024]u8 = undefined;
            const summary = error_classify.summarizeKnownApiError(root_obj, &summary_buf) orelse @errorName(mapped_err);
            const sanitized = root.sanitizeApiError(allocator, summary) catch null;
            defer if (sanitized) |s| allocator.free(s);
            root.setLastApiErrorDetail("gemini", sanitized orelse summary);
            return mapped_err;
        }

        var usage = root.TokenUsage{};
        if (root_obj.get("usageMetadata")) |usage_val| {
            if (parseUsageMetadataValue(usage_val)) |parsed_usage| {
                usage = parsed_usage;
            }
        }

        // Extract text and thinking from candidates.
        // Parts with "thought": true are reasoning traces; all others are visible content.
        if (root_obj.get("candidates")) |candidates| {
            if (candidates.array.items.len > 0) {
                const candidate = candidates.array.items[0].object;
                if (candidate.get("content")) |content| {
                    if (content.object.get("parts")) |parts| {
                        var text_buf: std.ArrayListUnmanaged(u8) = .empty;
                        defer text_buf.deinit(allocator);
                        var thought_buf: std.ArrayListUnmanaged(u8) = .empty;
                        defer thought_buf.deinit(allocator);

                        for (parts.array.items) |part_val| {
                            const part = part_val.object;
                            const is_thought = if (part.get("thought")) |t| (t == .bool and t.bool) else false;
                            if (part.get("text")) |text| {
                                if (text == .string and text.string.len > 0) {
                                    const buf = if (is_thought) &thought_buf else &text_buf;
                                    if (buf.items.len > 0) try buf.append(allocator, '\n');
                                    try buf.appendSlice(allocator, text.string);
                                }
                            }
                        }

                        if (text_buf.items.len == 0 and thought_buf.items.len == 0)
                            return error.NoResponseContent;

                        return .{
                            .content = if (text_buf.items.len > 0) try text_buf.toOwnedSlice(allocator) else null,
                            .reasoning_content = if (thought_buf.items.len > 0) try thought_buf.toOwnedSlice(allocator) else null,
                            .usage = usage,
                        };
                    }
                }
            }
        }

        return error.NoResponseContent;
    }

    /// Parse text content from a Gemini generateContent response.
    pub fn parseResponse(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
        const parsed = try parseChatResponse(allocator, body);
        return parsed.content orelse error.NoResponseContent;
    }

    /// Result of parsing a single Gemini SSE line.
    pub const GeminiSseResult = union(enum) {
        /// Text delta content (owned, caller frees).
        delta: []const u8,
        /// Stream is complete (connection closed).
        done: void,
        /// Line should be skipped (empty, comment, or no content).
        skip: void,
    };

    /// Parse a single SSE line in Gemini streaming format.
    ///
    /// Handles:
    /// - `data: {JSON}` → extracts `candidates[0].content.parts[0].text` → `.delta`
    /// - Empty lines, comments (`:`) → `.skip`
    /// - No `[DONE]` sentinel - stream ends when connection closes
    pub fn parseGeminiSseLine(allocator: std.mem.Allocator, line: []const u8) !GeminiSseResult {
        const trimmed = std.mem.trimRight(u8, line, "\r");

        if (trimmed.len == 0) return .skip;
        if (trimmed[0] == ':') return .skip;

        const prefix = "data: ";
        if (!std.mem.startsWith(u8, trimmed, prefix)) return .skip;

        const data = trimmed[prefix.len..];

        const content = try extractGeminiDelta(allocator, data) orelse return .skip;
        return .{ .delta = content };
    }

    /// Extract `candidates[0].content.parts[0].text` from a Gemini SSE JSON payload.
    /// Returns owned slice or null if no content found.
    pub fn extractGeminiDelta(allocator: std.mem.Allocator, json_str: []const u8) !?[]const u8 {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch
            return error.InvalidSseJson;
        defer parsed.deinit();

        const obj = parsed.value.object;
        const candidates = obj.get("candidates") orelse return null;
        if (candidates != .array or candidates.array.items.len == 0) return null;

        const first = candidates.array.items[0];
        if (first != .object) return null;

        const content = first.object.get("content") orelse return null;
        if (content != .object) return null;

        const parts = content.object.get("parts") orelse return null;
        if (parts != .array or parts.array.items.len == 0) return null;

        const first_part = parts.array.items[0];
        if (first_part != .object) return null;

        const text = first_part.object.get("text") orelse return null;
        if (text != .string) return null;
        if (text.string.len == 0) return null;

        return try allocator.dupe(u8, text.string);
    }

    /// Run curl in SSE streaming mode for Gemini and parse output line by line.
    ///
    /// Spawns `curl -s --no-buffer` with the strongest supported fail-fast
    /// flag: `--fail-with-body` on curl >= 7.76.0, otherwise `-f`.
    /// For each SSE delta, calls `callback(ctx, chunk)`.
    /// Returns accumulated result after stream completes.
    /// Stream ends when curl connection closes (no [DONE] sentinel).
    pub fn curlStreamGemini(
        allocator: std.mem.Allocator,
        url: []const u8,
        body: []const u8,
        headers: []const []const u8,
        timeout_secs: u64,
        callback: root.StreamCallback,
        ctx: *anyopaque,
    ) !root.StreamChatResult {
        // Build argv on stack (max 32 args)
        var argv_buf: [32][]const u8 = undefined;
        var argc: usize = 0;

        argv_buf[argc] = "curl";
        argc += 1;
        argv_buf[argc] = "-s";
        argc += 1;
        argv_buf[argc] = "--no-buffer";
        argc += 1;
        argv_buf[argc] = sse.curlFailFastArg(allocator);
        argc += 1;

        var timeout_buf: [32]u8 = undefined;
        if (timeout_secs > 0) {
            const timeout_str = std.fmt.bufPrint(&timeout_buf, "{d}", .{timeout_secs}) catch return error.GeminiApiError;
            argv_buf[argc] = "--max-time";
            argc += 1;
            argv_buf[argc] = timeout_str;
            argc += 1;
        }

        argv_buf[argc] = "-X";
        argc += 1;
        argv_buf[argc] = "POST";
        argc += 1;
        argv_buf[argc] = "-H";
        argc += 1;
        argv_buf[argc] = "Content-Type: application/json";
        argc += 1;

        // Add proxy from environment if set
        const proxy = http_util.getProxyFromEnv(allocator) catch null;
        defer if (proxy) |p| allocator.free(p);

        if (proxy) |p| {
            argv_buf[argc] = "--proxy";
            argc += 1;
            argv_buf[argc] = p;
            argc += 1;
        }

        for (headers) |hdr| {
            argv_buf[argc] = "-H";
            argc += 1;
            argv_buf[argc] = hdr;
            argc += 1;
        }

        argv_buf[argc] = "--data-binary";
        argc += 1;
        argv_buf[argc] = "@-";
        argc += 1;
        argv_buf[argc] = url;
        argc += 1;

        var child = std.process.Child.init(argv_buf[0..argc], allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        try child.spawn();

        if (child.stdin) |stdin_file| {
            stdin_file.writeAll(body) catch {
                stdin_file.close();
                child.stdin = null;
                _ = child.kill() catch {};
                _ = child.wait() catch {};
                return error.GeminiApiError;
            };
            stdin_file.close();
            child.stdin = null;
        } else {
            _ = child.kill() catch {};
            _ = child.wait() catch {};
            return error.GeminiApiError;
        }

        // Read stdout line by line, parse SSE events
        var accumulated: std.ArrayListUnmanaged(u8) = .empty;
        defer accumulated.deinit(allocator);

        var line_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer line_buf.deinit(allocator);

        var stream_usage = root.TokenUsage{};
        const file = child.stdout.?;
        var read_buf: [4096]u8 = undefined;

        while (true) {
            const n = file.read(&read_buf) catch break;
            if (n == 0) break;

            for (read_buf[0..n]) |byte| {
                if (byte == '\n') {
                    if (extractGeminiUsageFromSseLine(allocator, line_buf.items) catch null) |usage| {
                        stream_usage = usage;
                    }
                    const result = parseGeminiSseLine(allocator, line_buf.items) catch {
                        line_buf.clearRetainingCapacity();
                        continue;
                    };
                    line_buf.clearRetainingCapacity();
                    switch (result) {
                        .delta => |text| {
                            defer allocator.free(text);
                            try accumulated.appendSlice(allocator, text);
                            callback(ctx, root.StreamChunk.textDelta(text));
                        },
                        .done => break,
                        .skip => {},
                    }
                } else {
                    try line_buf.append(allocator, byte);
                }
            }
        }

        // Parse trailing line if stream ended without final newline.
        if (line_buf.items.len > 0) {
            if (extractGeminiUsageFromSseLine(allocator, line_buf.items) catch null) |usage| {
                stream_usage = usage;
            }
            const trailing = parseGeminiSseLine(allocator, line_buf.items) catch null;
            line_buf.clearRetainingCapacity();
            if (trailing) |result| {
                switch (result) {
                    .delta => |text| {
                        defer allocator.free(text);
                        try accumulated.appendSlice(allocator, text);
                        callback(ctx, root.StreamChunk.textDelta(text));
                    },
                    .done => {},
                    .skip => {},
                }
            }
        }

        // Drain remaining stdout to prevent deadlock on wait()
        while (true) {
            const n = file.read(&read_buf) catch break;
            if (n == 0) break;
        }

        const term = child.wait() catch return error.CurlWaitError;
        switch (term) {
            .Exited => |code| if (code != 0) return error.CurlFailed,
            else => return error.CurlFailed,
        }

        // Signal completion only after successful process exit.
        callback(ctx, root.StreamChunk.finalChunk());

        const content = if (accumulated.items.len > 0)
            try allocator.dupe(u8, accumulated.items)
        else
            null;

        if (stream_usage.prompt_tokens == 0 and stream_usage.completion_tokens == 0 and stream_usage.total_tokens == 0) {
            stream_usage.completion_tokens = @intCast((accumulated.items.len + 3) / 4);
            stream_usage.total_tokens = stream_usage.completion_tokens;
        } else {
            normalizeTokenUsage(&stream_usage);
        }

        return .{
            .content = content,
            .usage = stream_usage,
            .model = "",
        };
    }

    /// Create a Provider interface from this GeminiProvider.
    pub fn provider(self: *GeminiProvider) Provider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Provider.VTable{
        .chatWithSystem = chatWithSystemImpl,
        .chat = chatImpl,
        .supportsNativeTools = supportsNativeToolsImpl,
        .supports_vision = supportsVisionImpl,
        .getName = getNameImpl,
        .deinit = deinitImpl,
        .stream_chat = streamChatImpl,
        .supports_streaming = supportsStreamingImpl,
    };

    fn chatWithSystemImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
    ) anyerror![]const u8 {
        const self: *GeminiProvider = @ptrCast(@alignCast(ptr));
        const auth = self.auth orelse return error.CredentialsNotSet;

        const url = try buildUrl(allocator, model, auth);
        defer allocator.free(url);

        const body = try buildRequestBody(allocator, system_prompt, message, temperature);
        defer allocator.free(body);

        const resp_body = if (auth.isApiKey())
            root.curlPostTimed(allocator, url, body, &.{}, 0) catch return error.GeminiApiError
        else blk: {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{auth.credential()}) catch return error.GeminiApiError;
            break :blk root.curlPostTimed(allocator, url, body, &.{auth_hdr}, 0) catch return error.GeminiApiError;
        };
        defer allocator.free(resp_body);

        return parseResponse(allocator, resp_body);
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
    ) anyerror!ChatResponse {
        const self: *GeminiProvider = @ptrCast(@alignCast(ptr));
        const auth = self.auth orelse return error.CredentialsNotSet;

        const url = try buildUrl(allocator, model, auth);
        defer allocator.free(url);

        const body = try buildChatRequestBody(allocator, request, model, temperature);
        defer allocator.free(body);

        const resp_body = if (auth.isApiKey())
            root.curlPostTimed(allocator, url, body, &.{}, request.timeout_secs) catch return error.GeminiApiError
        else blk: {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{auth.credential()}) catch return error.GeminiApiError;
            break :blk root.curlPostTimed(allocator, url, body, &.{auth_hdr}, request.timeout_secs) catch return error.GeminiApiError;
        };
        defer allocator.free(resp_body);

        return try parseChatResponse(allocator, resp_body);
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return false;
    }

    fn supportsVisionImpl(_: *anyopaque) bool {
        return true;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "Gemini";
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *GeminiProvider = @ptrCast(@alignCast(ptr));
        if (self.auth) |auth| {
            switch (auth) {
                .env_gemini_key => |key| self.allocator.free(key),
                .env_google_key => |key| self.allocator.free(key),
                .env_oauth_token => |tok| self.allocator.free(tok),
                .oauth_token => |tok| self.allocator.free(tok),
                else => {},
            }
        }
        self.auth = null;
    }

    fn supportsStreamingImpl(_: *anyopaque) bool {
        return true;
    }

    fn streamChatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
        callback: root.StreamCallback,
        callback_ctx: *anyopaque,
    ) anyerror!root.StreamChatResult {
        const self: *GeminiProvider = @ptrCast(@alignCast(ptr));
        const auth = self.auth orelse return error.CredentialsNotSet;

        const url = try buildStreamUrl(allocator, model, auth);
        defer allocator.free(url);

        const body = try buildChatRequestBody(allocator, request, model, temperature);
        defer allocator.free(body);

        if (auth.isApiKey()) {
            return curlStreamGemini(allocator, url, body, &.{}, request.timeout_secs, callback, callback_ctx);
        } else {
            var auth_hdr_buf: [512]u8 = undefined;
            const auth_hdr = std.fmt.bufPrint(&auth_hdr_buf, "Authorization: Bearer {s}", .{auth.credential()}) catch return error.GeminiApiError;
            const headers = [_][]const u8{auth_hdr};
            return curlStreamGemini(allocator, url, body, &headers, request.timeout_secs, callback, callback_ctx);
        }
    }
};

/// Build a full chat request JSON body from a ChatRequest (Gemini format).
/// Gemini uses "contents" array with roles "user"/"model", system goes in "system_instruction".
fn buildChatRequestBody(
    allocator: std.mem.Allocator,
    request: ChatRequest,
    model: []const u8,
    temperature: f64,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Extract system prompt
    var system_prompt: ?[]const u8 = null;
    for (request.messages) |msg| {
        if (msg.role == .system) {
            system_prompt = msg.content;
            break;
        }
    }

    try buf.appendSlice(allocator, "{\"contents\":[");
    var count: usize = 0;
    for (request.messages) |msg| {
        if (msg.role == .system) continue;
        if (count > 0) try buf.append(allocator, ',');
        count += 1;
        // Gemini uses "user" and "model" (not "assistant")
        const role_str: []const u8 = switch (msg.role) {
            .user, .tool => "user",
            .assistant => "model",
            .system => unreachable,
        };
        try buf.appendSlice(allocator, "{\"role\":\"");
        try buf.appendSlice(allocator, role_str);
        try buf.appendSlice(allocator, "\",\"parts\":[");
        if (msg.content_parts) |parts| {
            for (parts, 0..) |part, j| {
                if (j > 0) try buf.append(allocator, ',');
                switch (part) {
                    .text => |text| {
                        try buf.appendSlice(allocator, "{\"text\":");
                        try root.appendJsonString(&buf, allocator, text);
                        try buf.append(allocator, '}');
                    },
                    .image_base64 => |img| {
                        try buf.appendSlice(allocator, "{\"inlineData\":{\"mimeType\":");
                        try root.appendJsonString(&buf, allocator, img.media_type);
                        try buf.appendSlice(allocator, ",\"data\":\"");
                        try buf.appendSlice(allocator, img.data);
                        try buf.appendSlice(allocator, "\"}}");
                    },
                    .image_url => |img| {
                        // Gemini doesn't support direct URLs; include as escaped text reference
                        try buf.appendSlice(allocator, "{\"text\":");
                        var text_buf: std.ArrayListUnmanaged(u8) = .empty;
                        defer text_buf.deinit(allocator);
                        try text_buf.appendSlice(allocator, "[Image: ");
                        try text_buf.appendSlice(allocator, img.url);
                        try text_buf.appendSlice(allocator, "]");
                        try root.appendJsonString(&buf, allocator, text_buf.items);
                        try buf.append(allocator, '}');
                    },
                }
            }
        } else {
            try buf.appendSlice(allocator, "{\"text\":");
            try root.appendJsonString(&buf, allocator, msg.content);
            try buf.append(allocator, '}');
        }
        try buf.appendSlice(allocator, "]}");
    }
    try buf.append(allocator, ']');

    if (system_prompt) |sys| {
        try buf.appendSlice(allocator, ",\"system_instruction\":{\"parts\":[{\"text\":");
        try root.appendJsonString(&buf, allocator, sys);
        try buf.appendSlice(allocator, "}]}");
    }

    try buf.appendSlice(allocator, ",\"generationConfig\":{\"temperature\":");
    var temp_buf: [16]u8 = undefined;
    const temp_str = std.fmt.bufPrint(&temp_buf, "{d:.2}", .{temperature}) catch return error.GeminiApiError;
    try buf.appendSlice(allocator, temp_str);
    try buf.appendSlice(allocator, ",\"maxOutputTokens\":");
    const max_output_tokens = request.max_tokens orelse GeminiProvider.DEFAULT_MAX_OUTPUT_TOKENS;
    var max_buf: [16]u8 = undefined;
    const max_str = std.fmt.bufPrint(&max_buf, "{d}", .{max_output_tokens}) catch return error.GeminiApiError;
    try buf.appendSlice(allocator, max_str);

    try root.appendGeminiThinkingConfig(&buf, allocator, model, request.reasoning_effort);
    try buf.appendSlice(allocator, "}}");

    return try buf.toOwnedSlice(allocator);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "provider creates without key" {
    const p = GeminiProvider.init(std.testing.allocator, null);
    defer if (p.auth) |a| switch (a) {
        .env_gemini_key => |key| std.testing.allocator.free(key),
        .env_google_key => |key| std.testing.allocator.free(key),
        .env_oauth_token => |tok| std.testing.allocator.free(tok),
        .oauth_token => |tok| std.testing.allocator.free(tok),
        else => {},
    };
    _ = p.authSource();
}

test "provider creates with key" {
    const p = GeminiProvider.init(std.testing.allocator, "test-api-key");
    try std.testing.expect(p.auth != null);
    try std.testing.expectEqualStrings("config", p.authSource());
}

test "provider rejects empty key" {
    const p = GeminiProvider.init(std.testing.allocator, "");
    defer if (p.auth) |a| switch (a) {
        .env_gemini_key => |key| std.testing.allocator.free(key),
        .env_google_key => |key| std.testing.allocator.free(key),
        .env_oauth_token => |tok| std.testing.allocator.free(tok),
        .oauth_token => |tok| std.testing.allocator.free(tok),
        else => {},
    };
    // Empty key must not be accepted as an explicit key — auth source must
    // NOT be "config". It may fall back to env vars, OAuth, or remain unset
    // depending on the host environment.
    const src = p.authSource();
    try std.testing.expect(!std.mem.eql(u8, src, "config"));
}

test "api key url includes key query param" {
    const auth = GeminiAuth{ .explicit_key = "api-key-123" };
    const url = try GeminiProvider.buildUrl(std.testing.allocator, "gemini-2.0-flash", auth);
    defer std.testing.allocator.free(url);
    try std.testing.expect(std.mem.indexOf(u8, url, ":generateContent?key=api-key-123") != null);
}

test "oauth url omits key query param" {
    const auth = GeminiAuth{ .oauth_token = "ya29.test-token" };
    const url = try GeminiProvider.buildUrl(std.testing.allocator, "gemini-2.0-flash", auth);
    defer std.testing.allocator.free(url);
    try std.testing.expect(std.mem.endsWith(u8, url, ":generateContent"));
    try std.testing.expect(std.mem.indexOf(u8, url, "?key=") == null);
}

test "model name formatting" {
    const auth = GeminiAuth{ .explicit_key = "key" };

    const url1 = try GeminiProvider.buildUrl(std.testing.allocator, "gemini-2.0-flash", auth);
    defer std.testing.allocator.free(url1);
    try std.testing.expect(std.mem.indexOf(u8, url1, "models/gemini-2.0-flash") != null);

    const url2 = try GeminiProvider.buildUrl(std.testing.allocator, "models/gemini-1.5-pro", auth);
    defer std.testing.allocator.free(url2);
    try std.testing.expect(std.mem.indexOf(u8, url2, "models/gemini-1.5-pro") != null);
    // Ensure no double "models/" prefix
    try std.testing.expect(std.mem.indexOf(u8, url2, "models/models/") == null);
}

test "buildRequestBody with system" {
    const body = try GeminiProvider.buildRequestBody(std.testing.allocator, "Be helpful", "Hello", 0.7);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"role\":\"user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "Hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "system_instruction") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "maxOutputTokens") != null);
}

test "buildRequestBody without system" {
    const body = try GeminiProvider.buildRequestBody(std.testing.allocator, null, "Hello", 0.7);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "system_instruction") == null);
}

test "parseResponse extracts text" {
    const body =
        \\{"candidates":[{"content":{"parts":[{"text":"Hello there!"}]}}]}
    ;
    const result = try GeminiProvider.parseResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Hello there!", result);
}

test "parseChatResponse extracts usageMetadata token counts" {
    const body =
        \\{"candidates":[{"content":{"parts":[{"text":"Hello there!"}]}}],"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":34,"totalTokenCount":46}}
    ;
    const response = try GeminiProvider.parseChatResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(response.content.?);
    try std.testing.expectEqualStrings("Hello there!", response.content.?);
    try std.testing.expectEqual(@as(u32, 12), response.usage.prompt_tokens);
    try std.testing.expectEqual(@as(u32, 34), response.usage.completion_tokens);
    try std.testing.expectEqual(@as(u32, 46), response.usage.total_tokens);
}

test "extractGeminiUsageMetadata derives missing total from prompt and completion" {
    const json =
        \\{"usageMetadata":{"promptTokenCount":7,"candidatesTokenCount":5}}
    ;
    const usage = (try extractGeminiUsageMetadata(std.testing.allocator, json)).?;
    try std.testing.expectEqual(@as(u32, 7), usage.prompt_tokens);
    try std.testing.expectEqual(@as(u32, 5), usage.completion_tokens);
    try std.testing.expectEqual(@as(u32, 12), usage.total_tokens);
}

test "parseResponse error response" {
    const body =
        \\{"error":{"message":"Invalid API key"}}
    ;
    root.clearLastApiErrorDetail();
    try std.testing.expectError(error.ApiError, GeminiProvider.parseResponse(std.testing.allocator, body));
    const detail = (try root.snapshotLastApiErrorDetail(std.testing.allocator)).?;
    defer std.testing.allocator.free(detail);
    try std.testing.expect(std.mem.indexOf(u8, detail, "gemini:") != null);
    try std.testing.expect(std.mem.indexOf(u8, detail, "message=Invalid API key") != null);
}

test "parseResponse classifies rate-limit errors" {
    const body =
        \\{"error":{"code":429,"message":"Too many requests"}}
    ;
    try std.testing.expectError(error.RateLimited, GeminiProvider.parseResponse(std.testing.allocator, body));
}

test "GeminiAuth isApiKey" {
    const key = GeminiAuth{ .explicit_key = "key" };
    try std.testing.expect(key.isApiKey());

    const oauth = GeminiAuth{ .oauth_token = "ya29.token" };
    try std.testing.expect(!oauth.isApiKey());
}

test "GeminiAuth credential returns raw value" {
    const key = GeminiAuth{ .explicit_key = "my-api-key" };
    try std.testing.expectEqualStrings("my-api-key", key.credential());

    const oauth = GeminiAuth{ .oauth_token = "ya29.token" };
    try std.testing.expectEqualStrings("ya29.token", oauth.credential());
}

test "GeminiAuth source labels" {
    try std.testing.expectEqualStrings("config", (GeminiAuth{ .explicit_key = "k" }).source());
    try std.testing.expectEqualStrings("GEMINI_API_KEY env var", (GeminiAuth{ .env_gemini_key = "k" }).source());
    try std.testing.expectEqualStrings("GOOGLE_API_KEY env var", (GeminiAuth{ .env_google_key = "k" }).source());
    try std.testing.expectEqualStrings("Gemini CLI OAuth", (GeminiAuth{ .oauth_token = "t" }).source());
}

test "parseResponse empty candidates fails" {
    const body =
        \\{"candidates":[]}
    ;
    try std.testing.expectError(error.NoResponseContent, GeminiProvider.parseResponse(std.testing.allocator, body));
}

test "parseResponse no text field fails" {
    const body =
        \\{"candidates":[{"content":{"parts":[{}]}}]}
    ;
    try std.testing.expectError(error.NoResponseContent, GeminiProvider.parseResponse(std.testing.allocator, body));
}

test "parseResponse multiple parts concatenates visible text" {
    const body =
        \\{"candidates":[{"content":{"parts":[{"text":"First"},{"text":"Second"}]}}]}
    ;
    const result = try GeminiProvider.parseResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("First\nSecond", result);
}

test "parseChatResponse separates thought parts into reasoning_content" {
    const body =
        \\{"candidates":[{"content":{"parts":[{"thought":true,"text":"My reasoning trace"},{"text":"Visible answer"}]}}]}
    ;
    const alloc = std.testing.allocator;
    const response = try GeminiProvider.parseChatResponse(alloc, body);
    defer {
        if (response.content) |c| alloc.free(c);
        if (response.reasoning_content) |rc| alloc.free(rc);
        alloc.free(response.tool_calls);
        alloc.free(response.model);
    }
    try std.testing.expectEqualStrings("Visible answer", response.content.?);
    try std.testing.expectEqualStrings("My reasoning trace", response.reasoning_content.?);
}

test "parseChatResponse thought only leaves content null" {
    const body =
        \\{"candidates":[{"content":{"parts":[{"thought":true,"text":"only thinking"}]}}]}
    ;
    const alloc = std.testing.allocator;
    const response = try GeminiProvider.parseChatResponse(alloc, body);
    defer {
        if (response.content) |c| alloc.free(c);
        if (response.reasoning_content) |rc| alloc.free(rc);
        alloc.free(response.tool_calls);
        alloc.free(response.model);
    }
    try std.testing.expect(response.content == null);
    try std.testing.expectEqualStrings("only thinking", response.reasoning_content.?);
}

test "provider rejects whitespace key" {
    const p = GeminiProvider.init(std.testing.allocator, "   ");
    defer if (p.auth) |a| switch (a) {
        .env_gemini_key => |key| std.testing.allocator.free(key),
        .env_google_key => |key| std.testing.allocator.free(key),
        .env_oauth_token => |tok| std.testing.allocator.free(tok),
        .oauth_token => |tok| std.testing.allocator.free(tok),
        else => {},
    };
    // Whitespace-only key must not be accepted as an explicit key — auth
    // source must NOT be "config". It may fall back to env vars, OAuth,
    // or remain unset depending on the host environment.
    const src = p.authSource();
    try std.testing.expect(!std.mem.eql(u8, src, "config"));
}

test "provider getName returns Gemini" {
    var p = GeminiProvider.init(std.testing.allocator, "key");
    const prov = p.provider();
    try std.testing.expectEqualStrings("Gemini", prov.getName());
}

test "buildUrl with models prefix does not double prefix" {
    const auth = GeminiAuth{ .explicit_key = "key" };
    const url = try GeminiProvider.buildUrl(std.testing.allocator, "models/gemini-1.5-pro", auth);
    defer std.testing.allocator.free(url);
    try std.testing.expect(std.mem.indexOf(u8, url, "models/models/") == null);
    try std.testing.expect(std.mem.indexOf(u8, url, "models/gemini-1.5-pro") != null);
}

// ════════════════════════════════════════════════════════════════════════════
// Streaming Tests
// ════════════════════════════════════════════════════════════════════════════

test "vtable stream_chat is not null" {
    try std.testing.expect(GeminiProvider.vtable.stream_chat != null);
}

test "vtable supports_streaming is not null" {
    try std.testing.expect(GeminiProvider.vtable.supports_streaming != null);
}

test "buildStreamUrl with api key" {
    const auth = GeminiAuth{ .explicit_key = "api-key-123" };
    const url = try GeminiProvider.buildStreamUrl(std.testing.allocator, "gemini-2.0-flash", auth);
    defer std.testing.allocator.free(url);
    try std.testing.expect(std.mem.indexOf(u8, url, ":streamGenerateContent?key=api-key-123&alt=sse") != null);
}

test "buildStreamUrl with oauth" {
    const auth = GeminiAuth{ .oauth_token = "ya29.test-token" };
    const url = try GeminiProvider.buildStreamUrl(std.testing.allocator, "gemini-2.0-flash", auth);
    defer std.testing.allocator.free(url);
    try std.testing.expect(std.mem.endsWith(u8, url, ":streamGenerateContent?alt=sse"));
    try std.testing.expect(std.mem.indexOf(u8, url, "?key=") == null);
}

test "parseGeminiSseLine valid delta" {
    const allocator = std.testing.allocator;
    const result = try GeminiProvider.parseGeminiSseLine(allocator, "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hello\"}]}}]}");
    switch (result) {
        .delta => |text| {
            defer allocator.free(text);
            try std.testing.expectEqualStrings("Hello", text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "extractGeminiUsageFromSseLine parses usageMetadata" {
    const line = "data: {\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":9,\"totalTokenCount\":12}}";
    const usage = (try extractGeminiUsageFromSseLine(std.testing.allocator, line)).?;
    try std.testing.expectEqual(@as(u32, 3), usage.prompt_tokens);
    try std.testing.expectEqual(@as(u32, 9), usage.completion_tokens);
    try std.testing.expectEqual(@as(u32, 12), usage.total_tokens);
}

test "parseGeminiSseLine empty line" {
    const result = try GeminiProvider.parseGeminiSseLine(std.testing.allocator, "");
    try std.testing.expect(result == .skip);
}

test "parseGeminiSseLine invalid json returns error" {
    try std.testing.expectError(
        error.InvalidSseJson,
        GeminiProvider.parseGeminiSseLine(std.testing.allocator, "data: not-json"),
    );
}

test "streamChatImpl fails without credentials" {
    // Construct directly with auth=null to avoid picking up env vars or CLI tokens
    var p = GeminiProvider{ .auth = null, .allocator = std.testing.allocator };

    const prov = p.provider();
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test")};
    const req = ChatRequest{ .messages = &msgs, .model = "test-model" };

    const DummyCallback = struct {
        fn cb(_: *anyopaque, _: root.StreamChunk) void {}
    };
    var dummy_ctx: u8 = 0;

    try std.testing.expectError(error.CredentialsNotSet, prov.streamChat(std.testing.allocator, req, "test-model", 0.7, &DummyCallback.cb, @ptrCast(&dummy_ctx)));
}

// ════════════════════════════════════════════════════════════════════════════
// Gemini CLI OAuth Token Discovery Tests
// ════════════════════════════════════════════════════════════════════════════

test "GeminiCliCredentials isExpired with future timestamp returns false" {
    const future: i64 = std.time.timestamp() + 3600; // 1 hour from now
    const creds = GeminiCliCredentials{
        .access_token = "ya29.test-token",
        .refresh_token = null,
        .expires_at = future,
    };
    try std.testing.expect(!creds.isExpired());
}

test "GeminiCliCredentials isExpired with past timestamp returns true" {
    const past: i64 = std.time.timestamp() - 3600; // 1 hour ago
    const creds = GeminiCliCredentials{
        .access_token = "ya29.test-token",
        .refresh_token = null,
        .expires_at = past,
    };
    try std.testing.expect(creds.isExpired());
}

test "GeminiCliCredentials isExpired with null expires_at returns false" {
    const creds = GeminiCliCredentials{
        .access_token = "ya29.test-token",
        .refresh_token = null,
        .expires_at = null,
    };
    try std.testing.expect(!creds.isExpired());
}

test "GeminiCliCredentials isExpired with 5-min buffer edge case" {
    // Token expires in exactly 4 minutes — within the 5-minute buffer, so should be expired
    const almost_expired: i64 = std.time.timestamp() + 4 * 60;
    const creds_soon = GeminiCliCredentials{
        .access_token = "ya29.test-token",
        .refresh_token = null,
        .expires_at = almost_expired,
    };
    try std.testing.expect(creds_soon.isExpired());

    // Token expires in exactly 6 minutes — outside the 5-minute buffer, so should NOT be expired
    const still_valid: i64 = std.time.timestamp() + 6 * 60;
    const creds_valid = GeminiCliCredentials{
        .access_token = "ya29.test-token",
        .refresh_token = null,
        .expires_at = still_valid,
    };
    try std.testing.expect(!creds_valid.isExpired());
}

test "tryLoadGeminiCliToken is side-effect free in test mode" {
    // In test mode we always return null to avoid touching real ~/.gemini
    // credentials on developer machines.
    const result = tryLoadGeminiCliToken(std.testing.allocator);
    try std.testing.expect(result == null);
}

test "parseCredentialsJson valid JSON with all fields" {
    const json =
        \\{"access_token":"ya29.a0ARrdaM","refresh_token":"1//0eHIDK","expires_at":1999999999}
    ;
    const creds = parseCredentialsJson(std.testing.allocator, json) orelse {
        try std.testing.expect(false); // should not be null
        return;
    };
    defer std.testing.allocator.free(creds.access_token);
    defer if (creds.refresh_token) |rt| std.testing.allocator.free(rt);

    try std.testing.expectEqualStrings("ya29.a0ARrdaM", creds.access_token);
    try std.testing.expectEqualStrings("1//0eHIDK", creds.refresh_token.?);
    try std.testing.expect(creds.expires_at.? == 1999999999);
}

test "parseCredentialsJson valid JSON with only access_token" {
    const json =
        \\{"access_token":"ya29.token-only"}
    ;
    const creds = parseCredentialsJson(std.testing.allocator, json) orelse {
        try std.testing.expect(false);
        return;
    };
    defer std.testing.allocator.free(creds.access_token);

    try std.testing.expectEqualStrings("ya29.token-only", creds.access_token);
    try std.testing.expect(creds.refresh_token == null);
    try std.testing.expect(creds.expires_at == null);
}

test "parseCredentialsJson missing access_token returns null" {
    const json =
        \\{"refresh_token":"1//0eHIDK","expires_at":1999999999}
    ;
    const result = parseCredentialsJson(std.testing.allocator, json);
    try std.testing.expect(result == null);
}

test "parseCredentialsJson empty object returns null" {
    const json =
        \\{}
    ;
    const result = parseCredentialsJson(std.testing.allocator, json);
    try std.testing.expect(result == null);
}

test "parseCredentialsJson empty access_token returns null" {
    const json =
        \\{"access_token":""}
    ;
    const result = parseCredentialsJson(std.testing.allocator, json);
    try std.testing.expect(result == null);
}

test "parseCredentialsJson invalid JSON returns null" {
    const result = parseCredentialsJson(std.testing.allocator, "not json at all");
    try std.testing.expect(result == null);
}

test "gemini buildChatRequestBody plain text" {
    const alloc = std.testing.allocator;
    var msgs = [_]root.ChatMessage{
        root.ChatMessage.user("Hello"),
    };
    const body = try buildChatRequestBody(alloc, .{ .messages = &msgs }, "gemini-2.5-flash", 0.7);
    defer alloc.free(body);
    // Verify valid JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    const contents = parsed.value.object.get("contents").?.array;
    try std.testing.expectEqual(@as(usize, 1), contents.items.len);
    const parts = contents.items[0].object.get("parts").?.array;
    try std.testing.expectEqual(@as(usize, 1), parts.items.len);
    try std.testing.expectEqualStrings("Hello", parts.items[0].object.get("text").?.string);
}

test "gemini buildChatRequestBody honors request max_tokens override" {
    const alloc = std.testing.allocator;
    var msgs = [_]root.ChatMessage{
        root.ChatMessage.user("Hello"),
    };
    const body = try buildChatRequestBody(alloc, .{
        .messages = &msgs,
        .max_tokens = 2048,
    }, "gemini-2.5-flash", 0.7);
    defer alloc.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    const generation_config = parsed.value.object.get("generationConfig").?.object;
    const max_output = generation_config.get("maxOutputTokens").?;
    try std.testing.expect(max_output == .integer);
    try std.testing.expectEqual(@as(i64, 2048), max_output.integer);
}

test "gemini buildChatRequestBody maps reasoning_effort to thinkingLevel on gemini-3 flash" {
    const alloc = std.testing.allocator;
    var msgs = [_]root.ChatMessage{
        root.ChatMessage.user("Hello"),
    };
    const body = try buildChatRequestBody(alloc, .{
        .messages = &msgs,
        .reasoning_effort = "medium",
    }, "gemini-3.1-flash", 0.7);
    defer alloc.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    const generation_config = parsed.value.object.get("generationConfig").?.object;
    const thinking = generation_config.get("thinkingConfig").?.object;
    try std.testing.expectEqualStrings("medium", thinking.get("thinkingLevel").?.string);
}

test "gemini buildChatRequestBody maps reasoning_effort to thinkingBudget on gemini-2.5" {
    const alloc = std.testing.allocator;
    var msgs = [_]root.ChatMessage{
        root.ChatMessage.user("Hello"),
    };
    const body = try buildChatRequestBody(alloc, .{
        .messages = &msgs,
        .reasoning_effort = "high",
    }, "gemini-2.5-pro", 0.7);
    defer alloc.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    const generation_config = parsed.value.object.get("generationConfig").?.object;
    const thinking = generation_config.get("thinkingConfig").?.object;
    try std.testing.expectEqual(@as(i64, 24576), thinking.get("thinkingBudget").?.integer);
}

test "gemini buildChatRequestBody with content_parts inlineData" {
    const alloc = std.testing.allocator;
    const cp = &[_]root.ContentPart{
        .{ .text = "What is this?" },
        .{ .image_base64 = .{ .data = "iVBOR", .media_type = "image/png" } },
    };
    var msgs = [_]root.ChatMessage{
        .{ .role = .user, .content = "What is this?", .content_parts = cp },
    };
    const body = try buildChatRequestBody(alloc, .{ .messages = &msgs }, "gemini-2.5-flash", 0.7);
    defer alloc.free(body);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    const contents = parsed.value.object.get("contents").?.array;
    const parts = contents.items[0].object.get("parts").?.array;
    try std.testing.expectEqual(@as(usize, 2), parts.items.len);
    // First part: text
    try std.testing.expectEqualStrings("What is this?", parts.items[0].object.get("text").?.string);
    // Second part: inlineData
    const inline_data = parts.items[1].object.get("inlineData").?.object;
    try std.testing.expectEqualStrings("image/png", inline_data.get("mimeType").?.string);
    try std.testing.expectEqualStrings("iVBOR", inline_data.get("data").?.string);
}

test "gemini buildChatRequestBody with image_url special chars" {
    const alloc = std.testing.allocator;
    const cp = &[_]root.ContentPart{
        .{ .image_url = .{ .url = "https://example.com/img?a=1&b=\"quote\"" } },
    };
    var msgs = [_]root.ChatMessage{
        .{ .role = .user, .content = "", .content_parts = cp },
    };
    const body = try buildChatRequestBody(alloc, .{ .messages = &msgs }, "gemini-2.5-flash", 0.7);
    defer alloc.free(body);
    // Must produce valid JSON despite special chars in URL
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    const contents = parsed.value.object.get("contents").?.array;
    const parts = contents.items[0].object.get("parts").?.array;
    try std.testing.expectEqual(@as(usize, 1), parts.items.len);
    const text = parts.items[0].object.get("text").?.string;
    try std.testing.expect(std.mem.indexOf(u8, text, "\"quote\"") != null);
}

// ════════════════════════════════════════════════════════════════════════════
// OAuth Refresh Tests
// ════════════════════════════════════════════════════════════════════════════

test "parseRefreshResponse extracts access token" {
    const alloc = std.testing.allocator;
    const json =
        \\{"access_token":"new-token-abc","expires_in":3600,"token_type":"Bearer"}
    ;
    const result = parseRefreshResponse(alloc, json) orelse return error.TestUnexpectedResult;
    defer alloc.free(result.access_token);
    try std.testing.expectEqualStrings("new-token-abc", result.access_token);
    try std.testing.expect(result.expires_in == 3600);
}

test "parseRefreshResponse handles error response" {
    const json =
        \\{"error":"invalid_grant","error_description":"Bad Request"}
    ;
    const result = parseRefreshResponse(std.testing.allocator, json);
    try std.testing.expect(result == null);
}

test "parseRefreshResponse handles empty access token" {
    const json =
        \\{"access_token":"","expires_in":3600}
    ;
    const result = parseRefreshResponse(std.testing.allocator, json);
    try std.testing.expect(result == null);
}

test "parseRefreshResponse handles missing fields" {
    const json =
        \\{"access_token":"token-123"}
    ;
    const result = parseRefreshResponse(std.testing.allocator, json);
    try std.testing.expect(result == null);
}

test "parseRefreshResponse rejects invalid expires_in float" {
    const json =
        \\{"access_token":"new-token-abc","expires_in":"not-a-number"}
    ;
    const result = parseRefreshResponse(std.testing.allocator, json);
    try std.testing.expect(result == null);
}

test "parseRefreshResponse rejects non-positive expires_in" {
    const json_zero =
        \\{"access_token":"new-token-abc","expires_in":0}
    ;
    const json_neg =
        \\{"access_token":"new-token-abc","expires_in":-5}
    ;
    try std.testing.expect(parseRefreshResponse(std.testing.allocator, json_zero) == null);
    try std.testing.expect(parseRefreshResponse(std.testing.allocator, json_neg) == null);
}

test "refreshOAuthToken returns test token in test mode" {
    const alloc = std.testing.allocator;
    const resp = try refreshOAuthToken(alloc, "test-refresh-token");
    defer alloc.free(resp.access_token);
    try std.testing.expectEqualStrings("test-refreshed-token", resp.access_token);
    try std.testing.expectEqual(@as(i64, 3600), resp.expires_in);
}

test "buildRefreshFormBody percent-encodes reserved chars" {
    const alloc = std.testing.allocator;
    const body = try buildRefreshFormBody(
        alloc,
        "a+b/c= d?e&f",
        "client:abc/123",
        "sec+ret&x=y",
    );
    defer alloc.free(body);

    try std.testing.expectEqualStrings(
        "grant_type=refresh_token&refresh_token=a%2Bb%2Fc%3D+d%3Fe%26f&client_id=client%3Aabc%2F123&client_secret=sec%2Bret%26x%3Dy",
        body,
    );
}

test "GeminiAuth env_oauth_token is not api key" {
    const auth = GeminiAuth{ .env_oauth_token = "ya29.test" };
    try std.testing.expect(!auth.isApiKey());
    try std.testing.expectEqualStrings("ya29.test", auth.credential());
    try std.testing.expectEqualStrings("GEMINI_OAUTH_TOKEN env var", auth.source());
}

test "provider deinit frees env_oauth_token" {
    const alloc = std.testing.allocator;
    var p = GeminiProvider{
        .auth = .{ .env_oauth_token = try alloc.dupe(u8, "ya29.token") },
        .allocator = alloc,
    };
    const prov = p.provider();
    prov.deinit();
    try std.testing.expect(p.auth == null);
}

test "provider deinit frees oauth_token" {
    const alloc = std.testing.allocator;
    var p = GeminiProvider{
        .auth = .{ .oauth_token = try alloc.dupe(u8, "ya29.token") },
        .allocator = alloc,
    };
    const prov = p.provider();
    prov.deinit();
    try std.testing.expect(p.auth == null);
}

test "writeCredentialsJson produces valid JSON" {
    const alloc = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    // Create placeholder file so realpathAlloc works
    const tmp_file = try temp_dir.dir.createFile("creds.json", .{});
    tmp_file.close();

    const path = try temp_dir.dir.realpathAlloc(alloc, "creds.json");
    defer alloc.free(path);

    const creds = GeminiCliCredentials{
        .access_token = "test-access-token",
        .refresh_token = "test-refresh-token",
        .expires_at = 1999999999,
    };

    try writeCredentialsJson(alloc, creds, path);

    // Read back and verify valid JSON
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(alloc, 4096);
    defer alloc.free(content);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, content, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("test-access-token", obj.get("access_token").?.string);
    try std.testing.expectEqualStrings("test-refresh-token", obj.get("refresh_token").?.string);
    try std.testing.expect(obj.get("expires_at").?.integer == 1999999999);

    if (@import("builtin").os.tag != .windows and @import("builtin").os.tag != .wasi) {
        const stat = try file.stat();
        const mode = stat.mode & 0o777;
        // Respect process umask: require owner rw and forbid executable bits.
        try std.testing.expect((mode & 0o600) == 0o600);
        try std.testing.expect((mode & 0o111) == 0);
    }
}

test "writeCredentialsJson without refresh token" {
    const alloc = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const tmp_file = try temp_dir.dir.createFile("creds2.json", .{});
    tmp_file.close();

    const path = try temp_dir.dir.realpathAlloc(alloc, "creds2.json");
    defer alloc.free(path);

    const creds = GeminiCliCredentials{
        .access_token = "token-only",
        .refresh_token = null,
        .expires_at = null,
    };

    try writeCredentialsJson(alloc, creds, path);

    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(alloc, 4096);
    defer alloc.free(content);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, content, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("token-only", obj.get("access_token").?.string);
    try std.testing.expect(obj.get("refresh_token") == null);
    try std.testing.expect(obj.get("expires_at") == null);
}

test "writeCredentialsJson escapes token strings" {
    const alloc = std.testing.allocator;
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const tmp_file = try temp_dir.dir.createFile("creds-escaped.json", .{});
    tmp_file.close();

    const path = try temp_dir.dir.realpathAlloc(alloc, "creds-escaped.json");
    defer alloc.free(path);

    const access_token = "tok\"en\\line\nbreak";
    const refresh_token = "ref\twith\rcontrol";
    const creds = GeminiCliCredentials{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .expires_at = null,
    };

    try writeCredentialsJson(alloc, creds, path);

    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(alloc, 4096);
    defer alloc.free(content);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, content, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings(access_token, obj.get("access_token").?.string);
    try std.testing.expectEqualStrings(refresh_token, obj.get("refresh_token").?.string);
}
