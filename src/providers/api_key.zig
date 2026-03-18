const std = @import("std");
const builtin = @import("builtin");
const auth = @import("../auth.zig");
const config_mod = @import("../config_types.zig");
const json_util = @import("../json_util.zig");
const platform = @import("../platform.zig");
const provider_names = @import("../provider_names.zig");

pub const QwenCliCredentials = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    token_type: []const u8,
    expiry_date_ms: ?i64 = null,
    resource_url: ?[]const u8 = null,
    id_token: ?[]const u8 = null,

    pub fn deinit(self: QwenCliCredentials, allocator: std.mem.Allocator) void {
        allocator.free(self.access_token);
        allocator.free(self.token_type);
        if (self.refresh_token) |value| allocator.free(value);
        if (self.resource_url) |value| allocator.free(value);
        if (self.id_token) |value| allocator.free(value);
    }

    pub fn isExpired(self: QwenCliCredentials) bool {
        const expiry_date_ms = self.expiry_date_ms orelse return false;
        const refresh_buffer_ms: i64 = 30 * 1000;
        return std.time.milliTimestamp() >= expiry_date_ms - refresh_buffer_ms;
    }
};

const QWEN_OAUTH_TOKEN_ENDPOINT = "https://chat.qwen.ai/api/v1/oauth2/token";
const QWEN_OAUTH_CLIENT_ID = "f0304373b74a44d2b584a3fb70ca9e56";

/// Resolve API key for a provider from config and environment variables.
///
/// Resolution order:
/// 1. Explicitly provided `api_key` parameter (trimmed, filtered if empty)
/// 2. For `qwen-portal` only: `QWEN_OAUTH_TOKEN`, then `~/.qwen/oauth_creds.json`
/// 3. Provider-specific environment variable
/// 4. Generic fallback variables (`NULLCLAW_API_KEY`, `API_KEY`)
pub fn resolveApiKey(
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    api_key: ?[]const u8,
) !?[]u8 {
    // 1. Explicit key
    if (api_key) |key| {
        const trimmed = std.mem.trim(u8, key, " \t\r\n");
        if (trimmed.len > 0) {
            return try allocator.dupe(u8, trimmed);
        }
    }

    // 2. Qwen OAuth env/file resolution for the qwen-portal provider only.
    if (std.ascii.eqlIgnoreCase(provider_name, "qwen-portal")) {
        if (try loadNonEmptyEnv(allocator, "QWEN_OAUTH_TOKEN")) |value| {
            return value;
        }
        if (tryLoadQwenCliToken(allocator)) |creds| {
            defer creds.deinit(allocator);
            const access_token = try allocator.dupe(u8, creds.access_token);
            return access_token;
        }
    }

    // 3. Provider-specific env vars
    const env_candidates = providerEnvCandidates(provider_name);
    for (env_candidates) |env_var| {
        if (env_var.len == 0) break;
        if (try loadNonEmptyEnv(allocator, env_var)) |value| {
            return value;
        }
    }

    // 4. Generic fallbacks
    const fallbacks = [_][]const u8{ "NULLCLAW_API_KEY", "API_KEY" };
    for (fallbacks) |env_var| {
        if (try loadNonEmptyEnv(allocator, env_var)) |value| {
            return value;
        }
    }

    return null;
}

fn loadNonEmptyEnv(allocator: std.mem.Allocator, name: []const u8) !?[]u8 {
    const value = std.process.getEnvVarOwned(allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return err,
    };
    defer allocator.free(value);

    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0) return null;
    return try allocator.dupe(u8, trimmed);
}

fn dupeTrimmedString(allocator: std.mem.Allocator, value: []const u8) !?[]const u8 {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0) return null;
    return try allocator.dupe(u8, trimmed);
}

fn parseEpochMilliseconds(value: std.json.Value) ?i64 {
    const threshold_seconds: i64 = 10_000_000_000;

    const raw_value: i64 = switch (value) {
        .integer => |i| i,
        .float => |f| blk: {
            if (!std.math.isFinite(f) or f <= 0) return null;
            const max_i64 = @as(f64, @floatFromInt(std.math.maxInt(i64)));
            if (f > max_i64) return null;
            break :blk @intFromFloat(f);
        },
        else => return null,
    };

    if (raw_value <= 0) return null;
    if (raw_value < threshold_seconds) {
        return std.math.mul(i64, raw_value, std.time.ms_per_s) catch null;
    }
    return raw_value;
}

pub fn parseQwenCredentialsJson(allocator: std.mem.Allocator, json_bytes: []const u8) ?QwenCliCredentials {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return null;
    defer parsed.deinit();

    const root_obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return null,
    };

    const access_token_val = root_obj.get("access_token") orelse return null;
    const access_token = switch (access_token_val) {
        .string => |value| (dupeTrimmedString(allocator, value) catch return null) orelse return null,
        else => return null,
    };
    var cleanup = true;
    defer if (cleanup) allocator.free(access_token);

    const refresh_token: ?[]const u8 = if (root_obj.get("refresh_token")) |refresh_token_val| switch (refresh_token_val) {
        .string => |value| dupeTrimmedString(allocator, value) catch return null,
        else => null,
    } else null;
    defer if (cleanup) if (refresh_token) |value| allocator.free(value);

    const token_type: []const u8 = if (root_obj.get("token_type")) |token_type_val| switch (token_type_val) {
        .string => |value| (dupeTrimmedString(allocator, value) catch return null) orelse (allocator.dupe(u8, "Bearer") catch return null),
        else => return null,
    } else allocator.dupe(u8, "Bearer") catch return null;
    defer if (cleanup) allocator.free(token_type);

    const resource_url: ?[]const u8 = if (root_obj.get("resource_url")) |resource_url_val| switch (resource_url_val) {
        .string => |value| dupeTrimmedString(allocator, value) catch return null,
        else => null,
    } else null;
    defer if (cleanup) if (resource_url) |value| allocator.free(value);

    const id_token: ?[]const u8 = if (root_obj.get("id_token")) |id_token_val| switch (id_token_val) {
        .string => |value| dupeTrimmedString(allocator, value) catch return null,
        else => null,
    } else null;
    defer if (cleanup) if (id_token) |value| allocator.free(value);

    const expiry_date_ms: ?i64 = if (root_obj.get("expiry_date")) |expiry_date_val|
        parseEpochMilliseconds(expiry_date_val)
    else
        null;

    cleanup = false;
    return .{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .token_type = token_type,
        .expiry_date_ms = expiry_date_ms,
        .resource_url = resource_url,
        .id_token = id_token,
    };
}

fn writeQwenCredentialsJson(
    allocator: std.mem.Allocator,
    creds: QwenCliCredentials,
    path: []const u8,
) !void {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.append(allocator, '{');
    try json_util.appendJsonKeyValue(&buf, allocator, "access_token", creds.access_token);

    if (creds.refresh_token) |refresh_token| {
        try buf.append(allocator, ',');
        try json_util.appendJsonKeyValue(&buf, allocator, "refresh_token", refresh_token);
    }

    try buf.append(allocator, ',');
    try json_util.appendJsonKeyValue(&buf, allocator, "token_type", creds.token_type);

    if (creds.id_token) |id_token| {
        try buf.append(allocator, ',');
        try json_util.appendJsonKeyValue(&buf, allocator, "id_token", id_token);
    }

    if (creds.resource_url) |resource_url| {
        try buf.append(allocator, ',');
        try json_util.appendJsonKeyValue(&buf, allocator, "resource_url", resource_url);
    }

    if (creds.expiry_date_ms) |expiry_date_ms| {
        try buf.append(allocator, ',');
        try json_util.appendJsonInt(&buf, allocator, "expiry_date", expiry_date_ms);
    }

    try buf.append(allocator, '}');

    const file = std.fs.createFileAbsolute(path, .{ .mode = 0o600 }) catch return error.FileWriteError;
    defer file.close();
    try file.writeAll(buf.items);
}

fn refreshQwenCliCredentials(
    allocator: std.mem.Allocator,
    creds: QwenCliCredentials,
    path: []const u8,
) ?QwenCliCredentials {
    const refresh_token = creds.refresh_token orelse return null;

    var refreshed_token = auth.refreshAccessToken(
        allocator,
        QWEN_OAUTH_TOKEN_ENDPOINT,
        QWEN_OAUTH_CLIENT_ID,
        refresh_token,
    ) catch return null;
    errdefer refreshed_token.deinit(allocator);

    const resource_url: ?[]const u8 = if (creds.resource_url) |value|
        allocator.dupe(u8, value) catch return null
    else
        null;
    errdefer if (resource_url) |value| allocator.free(value);

    const id_token: ?[]const u8 = if (creds.id_token) |value|
        allocator.dupe(u8, value) catch return null
    else
        null;
    errdefer if (id_token) |value| allocator.free(value);

    const refreshed = QwenCliCredentials{
        .access_token = refreshed_token.access_token,
        .refresh_token = refreshed_token.refresh_token,
        .token_type = refreshed_token.token_type,
        .expiry_date_ms = std.math.mul(i64, refreshed_token.expires_at, std.time.ms_per_s) catch std.math.maxInt(i64),
        .resource_url = resource_url,
        .id_token = id_token,
    };

    writeQwenCredentialsJson(allocator, refreshed, path) catch {};
    return refreshed;
}

pub fn tryLoadQwenCliToken(allocator: std.mem.Allocator) ?QwenCliCredentials {
    if (builtin.is_test) return null;

    const home = platform.getHomeDir(allocator) catch return null;
    defer allocator.free(home);

    const path = std.fs.path.join(allocator, &.{ home, ".qwen", "oauth_creds.json" }) catch return null;
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();

    const json_bytes = file.readToEndAlloc(allocator, 1024 * 1024) catch return null;
    defer allocator.free(json_bytes);

    const creds = parseQwenCredentialsJson(allocator, json_bytes) orelse return null;
    if (!creds.isExpired()) return creds;

    const refreshed = refreshQwenCliCredentials(allocator, creds, path) orelse {
        creds.deinit(allocator);
        return null;
    };
    creds.deinit(allocator);
    return refreshed;
}

fn providerEnvCandidates(name: []const u8) [3][]const u8 {
    const canonical = provider_names.canonicalProviderNameIgnoreCase(name);
    const map = std.StaticStringMap([3][]const u8).initComptime(.{
        .{ "anthropic", .{ "ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "" } },
        .{ "openrouter", .{ "OPENROUTER_API_KEY", "", "" } },
        .{ "openai", .{ "OPENAI_API_KEY", "", "" } },
        .{ "azure", .{ "AZURE_OPENAI_API_KEY", "", "" } },
        .{ "gemini", .{ "GEMINI_API_KEY", "GOOGLE_API_KEY", "" } },
        .{ "vertex", .{ "VERTEX_API_KEY", "VERTEX_OAUTH_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN" } },
        .{ "groq", .{ "GROQ_API_KEY", "", "" } },
        .{ "mistral", .{ "MISTRAL_API_KEY", "", "" } },
        .{ "deepseek", .{ "DEEPSEEK_API_KEY", "", "" } },
        .{ "z.ai", .{ "ZAI_API_KEY", "", "" } },
        .{ "zai", .{ "ZAI_API_KEY", "", "" } },
        .{ "glm", .{ "ZHIPU_API_KEY", "", "" } },
        .{ "zhipu", .{ "ZHIPU_API_KEY", "", "" } },
        .{ "xai", .{ "XAI_API_KEY", "", "" } },
        .{ "grok", .{ "XAI_API_KEY", "", "" } },
        .{ "together", .{ "TOGETHER_API_KEY", "", "" } },
        .{ "together-ai", .{ "TOGETHER_API_KEY", "", "" } },
        .{ "fireworks", .{ "FIREWORKS_API_KEY", "", "" } },
        .{ "fireworks-ai", .{ "FIREWORKS_API_KEY", "", "" } },
        .{ "synthetic", .{ "SYNTHETIC_API_KEY", "", "" } },
        .{ "opencode", .{ "OPENCODE_API_KEY", "", "" } },
        .{ "opencode-zen", .{ "OPENCODE_API_KEY", "", "" } },
        .{ "minimax", .{ "MINIMAX_API_KEY", "", "" } },
        .{ "qwen", .{ "DASHSCOPE_API_KEY", "", "" } },
        .{ "dashscope", .{ "DASHSCOPE_API_KEY", "", "" } },
        .{ "qwen-portal", .{ "QWEN_OAUTH_TOKEN", "", "" } },
        .{ "qianfan", .{ "QIANFAN_ACCESS_KEY", "", "" } },
        .{ "baidu", .{ "QIANFAN_ACCESS_KEY", "", "" } },
        .{ "perplexity", .{ "PERPLEXITY_API_KEY", "", "" } },
        .{ "cohere", .{ "COHERE_API_KEY", "", "" } },
        .{ "venice", .{ "VENICE_API_KEY", "", "" } },
        .{ "poe", .{ "POE_API_KEY", "", "" } },
        .{ "moonshot", .{ "MOONSHOT_API_KEY", "", "" } },
        .{ "kimi", .{ "MOONSHOT_API_KEY", "", "" } },
        .{ "bedrock", .{ "AWS_ACCESS_KEY_ID", "", "" } },
        .{ "aws-bedrock", .{ "AWS_ACCESS_KEY_ID", "", "" } },
        .{ "cloudflare", .{ "CLOUDFLARE_API_TOKEN", "", "" } },
        .{ "cloudflare-ai", .{ "CLOUDFLARE_API_TOKEN", "", "" } },
        .{ "vercel-ai", .{ "VERCEL_API_KEY", "", "" } },
        .{ "vercel", .{ "VERCEL_API_KEY", "", "" } },
        .{ "copilot", .{ "GITHUB_TOKEN", "", "" } },
        .{ "github-copilot", .{ "GITHUB_TOKEN", "", "" } },
        .{ "nvidia", .{ "NVIDIA_API_KEY", "", "" } },
        .{ "nvidia-nim", .{ "NVIDIA_API_KEY", "", "" } },
        .{ "build.nvidia.com", .{ "NVIDIA_API_KEY", "", "" } },
        .{ "astrai", .{ "ASTRAI_API_KEY", "", "" } },
        .{ "ollama", .{ "API_KEY", "", "" } },
        .{ "lmstudio", .{ "API_KEY", "", "" } },
        .{ "lm-studio", .{ "API_KEY", "", "" } },
        .{ "claude-cli", .{ "ANTHROPIC_API_KEY", "", "" } },
        .{ "codex-cli", .{ "OPENAI_API_KEY", "", "" } },
    });
    return map.get(canonical) orelse .{ "", "", "" };
}

/// Resolve API key with config providers as first priority, then env vars:
///   1. providers[].api_key from config
///   2. Provider-specific env var (GROQ_API_KEY, etc.)
///   3. Generic fallbacks (NULLCLAW_API_KEY, API_KEY)
pub fn resolveApiKeyFromConfig(
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    providers: []const config_mod.ProviderEntry,
) !?[]u8 {
    for (providers) |e| {
        if (provider_names.providerNamesMatch(e.name, provider_name)) {
            if (e.api_key) |k| return try allocator.dupe(u8, k);
        }
    }
    return resolveApiKey(allocator, provider_name, null);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "NVIDIA_API_KEY env resolves nvidia credential" {
    const allocator = std.testing.allocator;
    // providerEnvCandidates returns NVIDIA_API_KEY for nvidia
    const candidates = providerEnvCandidates("nvidia");
    try std.testing.expectEqualStrings("NVIDIA_API_KEY", candidates[0]);
    // Also check aliases
    const candidates_nim = providerEnvCandidates("nvidia-nim");
    try std.testing.expectEqualStrings("NVIDIA_API_KEY", candidates_nim[0]);
    const candidates_build = providerEnvCandidates("build.nvidia.com");
    try std.testing.expectEqualStrings("NVIDIA_API_KEY", candidates_build[0]);
    _ = allocator;
}

test "astrai env candidate is ASTRAI_API_KEY" {
    const candidates = providerEnvCandidates("astrai");
    try std.testing.expectEqualStrings("ASTRAI_API_KEY", candidates[0]);
}

test "vertex env candidate is VERTEX_API_KEY" {
    const candidates = providerEnvCandidates("vertex");
    try std.testing.expectEqualStrings("VERTEX_API_KEY", candidates[0]);
}

test "qwen uses dashscope api key env candidate" {
    const candidates = providerEnvCandidates("qwen");
    try std.testing.expectEqualStrings("DASHSCOPE_API_KEY", candidates[0]);
}

test "qwen-portal env candidate uses oauth token" {
    const candidates = providerEnvCandidates("qwen-portal");
    try std.testing.expectEqualStrings("QWEN_OAUTH_TOKEN", candidates[0]);
}

test "azure aliases share Azure env candidate" {
    try std.testing.expectEqualStrings("AZURE_OPENAI_API_KEY", providerEnvCandidates("azure")[0]);
    try std.testing.expectEqualStrings("AZURE_OPENAI_API_KEY", providerEnvCandidates("azure-openai")[0]);
    try std.testing.expectEqualStrings("AZURE_OPENAI_API_KEY", providerEnvCandidates("azure_openai")[0]);
}

test "providerEnvCandidates includes onboarding env hints" {
    const onboard = @import("../onboard.zig");

    for (onboard.known_providers) |provider| {
        if (provider.env_var.len == 0) continue;
        const candidates = providerEnvCandidates(provider.key);

        var matched = false;
        for (candidates) |candidate| {
            if (candidate.len == 0) break;
            if (std.mem.eql(u8, candidate, provider.env_var)) {
                matched = true;
                break;
            }
        }

        try std.testing.expect(matched);
    }
}

test "resolveApiKeyFromConfig finds key from providers" {
    const entries = [_]config_mod.ProviderEntry{
        .{ .name = "openrouter", .api_key = "sk-or-test" },
        .{ .name = "groq", .api_key = "gsk_test" },
    };
    const result = try resolveApiKeyFromConfig(std.testing.allocator, "groq", &entries);
    defer if (result) |r| std.testing.allocator.free(r);
    try std.testing.expectEqualStrings("gsk_test", result.?);
}

test "resolveApiKeyFromConfig matches provider aliases" {
    const entries = [_]config_mod.ProviderEntry{
        .{ .name = "azure", .api_key = "azure-test" },
    };
    const result = try resolveApiKeyFromConfig(std.testing.allocator, "azure-openai", &entries);
    defer if (result) |r| std.testing.allocator.free(r);
    try std.testing.expectEqualStrings("azure-test", result.?);
}

test "resolveApiKeyFromConfig falls through to env for missing provider" {
    const entries = [_]config_mod.ProviderEntry{
        .{ .name = "openrouter", .api_key = "sk-or-test" },
    };
    // Falls through to env-based resolution (may or may not find a key)
    const result = try resolveApiKeyFromConfig(std.testing.allocator, "nonexistent", &entries);
    if (result) |r| std.testing.allocator.free(r);
}

test "parseQwenCredentialsJson parses access token" {
    const creds = parseQwenCredentialsJson(std.testing.allocator, "{\"access_token\":\"test-token\"}").?;
    defer creds.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("test-token", creds.access_token);
    try std.testing.expectEqualStrings("Bearer", creds.token_type);
    try std.testing.expect(creds.refresh_token == null);
}

test "parseQwenCredentialsJson parses refresh metadata" {
    const creds = parseQwenCredentialsJson(
        std.testing.allocator,
        "{\"access_token\":\"test-token\",\"refresh_token\":\"refresh-token\",\"token_type\":\"Bearer\",\"expiry_date\":1735689600000,\"resource_url\":\"https://portal.qwen.ai/v1\",\"id_token\":\"id-token\"}",
    ).?;
    defer creds.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("test-token", creds.access_token);
    try std.testing.expectEqualStrings("refresh-token", creds.refresh_token.?);
    try std.testing.expectEqualStrings("Bearer", creds.token_type);
    try std.testing.expectEqual(@as(i64, 1735689600000), creds.expiry_date_ms.?);
    try std.testing.expectEqualStrings("https://portal.qwen.ai/v1", creds.resource_url.?);
    try std.testing.expectEqualStrings("id-token", creds.id_token.?);
}

test "parseQwenCredentialsJson normalizes seconds expiry timestamps" {
    const creds = parseQwenCredentialsJson(
        std.testing.allocator,
        "{\"access_token\":\"test-token\",\"expiry_date\":1735689600}",
    ).?;
    defer creds.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(i64, 1735689600000), creds.expiry_date_ms.?);
}

test "parseQwenCredentialsJson rejects missing access token" {
    try std.testing.expect(parseQwenCredentialsJson(std.testing.allocator, "{\"refresh_token\":\"x\"}") == null);
}

test "parseQwenCredentialsJson rejects empty access token" {
    try std.testing.expect(parseQwenCredentialsJson(std.testing.allocator, "{\"access_token\":\"  \"}") == null);
}

test "parseQwenCredentialsJson rejects invalid json" {
    try std.testing.expect(parseQwenCredentialsJson(std.testing.allocator, "{") == null);
}

test "parseQwenCredentialsJson cleans up on invalid token type" {
    try std.testing.expect(
        parseQwenCredentialsJson(std.testing.allocator, "{\"access_token\":\"test-token\",\"token_type\":123}") == null,
    );
}

test "tryLoadQwenCliToken disabled during tests" {
    try std.testing.expect(tryLoadQwenCliToken(std.testing.allocator) == null);
}

test "QwenCliCredentials isExpired uses expiry_date with refresh buffer" {
    const now_ms = std.time.milliTimestamp();
    const expired = QwenCliCredentials{
        .access_token = "token",
        .token_type = "Bearer",
        .expiry_date_ms = now_ms + 10_000,
    };
    try std.testing.expect(expired.isExpired());

    const valid = QwenCliCredentials{
        .access_token = "token",
        .token_type = "Bearer",
        .expiry_date_ms = now_ms + 120_000,
    };
    try std.testing.expect(!valid.isExpired());
}

test "writeQwenCredentialsJson preserves qwen oauth fields" {
    var temp_dir = std.testing.tmpDir(.{});
    defer temp_dir.cleanup();

    const temp_dir_path = try temp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(temp_dir_path);

    const file_path = try std.fs.path.join(std.testing.allocator, &.{ temp_dir_path, "oauth_creds.json" });
    defer std.testing.allocator.free(file_path);

    const creds = QwenCliCredentials{
        .access_token = "access-token",
        .refresh_token = "refresh-token",
        .token_type = "Bearer",
        .expiry_date_ms = 1735689600000,
        .resource_url = "https://portal.qwen.ai/v1",
        .id_token = "id-token",
    };

    try writeQwenCredentialsJson(std.testing.allocator, creds, file_path);

    const file = try std.fs.openFileAbsolute(file_path, .{});
    defer file.close();

    const json_bytes = try file.readToEndAlloc(std.testing.allocator, 1024 * 1024);
    defer std.testing.allocator.free(json_bytes);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_bytes, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("access-token", obj.get("access_token").?.string);
    try std.testing.expectEqualStrings("refresh-token", obj.get("refresh_token").?.string);
    try std.testing.expectEqualStrings("Bearer", obj.get("token_type").?.string);
    try std.testing.expectEqualStrings("id-token", obj.get("id_token").?.string);
    try std.testing.expectEqualStrings("https://portal.qwen.ai/v1", obj.get("resource_url").?.string);
    try std.testing.expectEqual(@as(i64, 1735689600000), obj.get("expiry_date").?.integer);
}

test "resolveApiKey qwen-portal prefers oauth env over dashscope key" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const c = @cImport({
        @cInclude("stdlib.h");
    });

    const oauth_key_z = try std.testing.allocator.dupeZ(u8, "QWEN_OAUTH_TOKEN");
    defer std.testing.allocator.free(oauth_key_z);
    const oauth_value_z = try std.testing.allocator.dupeZ(u8, "oauth-token");
    defer std.testing.allocator.free(oauth_value_z);
    try std.testing.expectEqual(@as(c_int, 0), c.setenv(oauth_key_z.ptr, oauth_value_z.ptr, 1));
    defer _ = c.unsetenv(oauth_key_z.ptr);

    const api_key_z = try std.testing.allocator.dupeZ(u8, "DASHSCOPE_API_KEY");
    defer std.testing.allocator.free(api_key_z);
    const api_value_z = try std.testing.allocator.dupeZ(u8, "dashscope-key");
    defer std.testing.allocator.free(api_value_z);
    try std.testing.expectEqual(@as(c_int, 0), c.setenv(api_key_z.ptr, api_value_z.ptr, 1));
    defer _ = c.unsetenv(api_key_z.ptr);

    const result = try resolveApiKey(std.testing.allocator, "qwen-portal", null);
    defer if (result) |value| std.testing.allocator.free(value);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("oauth-token", result.?);
}
