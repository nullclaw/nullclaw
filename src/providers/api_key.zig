const std = @import("std");
const config_mod = @import("../config_types.zig");

/// Resolve API key for a provider from config and environment variables.
///
/// Resolution order:
/// 1. Explicitly provided `api_key` parameter (trimmed, filtered if empty)
/// 2. Provider-specific environment variable
/// 3. Generic fallback variables (`NULLCLAW_API_KEY`, `API_KEY`)
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

    // 2. Provider-specific env vars
    const env_candidates = providerEnvCandidates(provider_name);
    for (env_candidates) |env_var| {
        if (env_var.len == 0) break;
        if (std.process.getEnvVarOwned(allocator, env_var)) |value| {
            const trimmed = std.mem.trim(u8, value, " \t\r\n");
            if (trimmed.len > 0) {
                if (trimmed.ptr != value.ptr or trimmed.len != value.len) {
                    const duped = try allocator.dupe(u8, trimmed);
                    allocator.free(value);
                    return duped;
                }
                return value;
            }
            allocator.free(value);
        } else |_| {}
    }

    // 3. Generic fallbacks
    const fallbacks = [_][]const u8{ "NULLCLAW_API_KEY", "API_KEY" };
    for (fallbacks) |env_var| {
        if (std.process.getEnvVarOwned(allocator, env_var)) |value| {
            const trimmed = std.mem.trim(u8, value, " \t\r\n");
            if (trimmed.len > 0) {
                if (trimmed.ptr != value.ptr or trimmed.len != value.len) {
                    const duped = try allocator.dupe(u8, trimmed);
                    allocator.free(value);
                    return duped;
                }
                return value;
            }
            allocator.free(value);
        } else |_| {}
    }

    return null;
}

fn providerEnvCandidates(name: []const u8) [3][]const u8 {
    const map = std.StaticStringMap([3][]const u8).initComptime(.{
        .{ "anthropic", .{ "ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "" } },
        .{ "openrouter", .{ "OPENROUTER_API_KEY", "", "" } },
        .{ "openai", .{ "OPENAI_API_KEY", "", "" } },
        .{ "gemini", .{ "GEMINI_API_KEY", "GOOGLE_API_KEY", "" } },
        .{ "google", .{ "GEMINI_API_KEY", "GOOGLE_API_KEY", "" } },
        .{ "google-gemini", .{ "GEMINI_API_KEY", "GOOGLE_API_KEY", "" } },
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
    });
    return map.get(name) orelse .{ "", "", "" };
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
        if (std.mem.eql(u8, e.name, provider_name)) {
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

test "providerEnvCandidates includes onboarding env hints" {
    const onboard = @import("../onboard.zig");

    for (onboard.known_providers) |provider| {
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

test "resolveApiKeyFromConfig falls through to env for missing provider" {
    const entries = [_]config_mod.ProviderEntry{
        .{ .name = "openrouter", .api_key = "sk-or-test" },
    };
    // Falls through to env-based resolution (may or may not find a key)
    const result = try resolveApiKeyFromConfig(std.testing.allocator, "nonexistent", &entries);
    if (result) |r| std.testing.allocator.free(r);
}
