//! Max-token resolution for generation limits.
//!
//! Follows the runtime fallback chain:
//!   1) explicit config override
//!   2) best-effort lookup by model/provider id
//!   3) default fallback

const std = @import("std");
const config_types = @import("../config_types.zig");

pub const DEFAULT_MODEL_MAX_TOKENS: u32 = config_types.DEFAULT_MODEL_MAX_TOKENS;

const MaxTokensEntry = struct {
    key: []const u8,
    tokens: u32,
};

// High-signal model defaults used in onboarding/catalog flows.
const MODEL_MAX_TOKENS = [_]MaxTokensEntry{
    .{ .key = "gpt-4", .tokens = 4_096 },
    .{ .key = "gpt-4-32k", .tokens = 4_096 },
    .{ .key = "claude-opus-4-6", .tokens = 8192 },
    .{ .key = "claude-opus-4.6", .tokens = 8192 },
    .{ .key = "claude-sonnet-4-6", .tokens = 8192 },
    .{ .key = "claude-sonnet-4.6", .tokens = 8192 },
    .{ .key = "claude-haiku-4-5", .tokens = 8192 },
    .{ .key = "gpt-5.2", .tokens = 8192 },
    .{ .key = "gpt-5.2-codex", .tokens = 8192 },
    .{ .key = "gpt-4.5-preview", .tokens = 8192 },
    .{ .key = "gpt-4.1", .tokens = 8192 },
    .{ .key = "gpt-4.1-mini", .tokens = 8192 },
    .{ .key = "gpt-4o", .tokens = 8192 },
    .{ .key = "gpt-4o-mini", .tokens = 8192 },
    .{ .key = "o3-mini", .tokens = 8192 },
    .{ .key = "gemini-2.5-pro", .tokens = 8192 },
    .{ .key = "gemini-2.5-flash", .tokens = 8192 },
    .{ .key = "gemini-2.0-flash", .tokens = 8192 },
    .{ .key = "deepseek-v3.2", .tokens = 8192 },
    .{ .key = "deepseek-chat", .tokens = 8192 },
    .{ .key = "deepseek-reasoner", .tokens = 8192 },
    .{ .key = "llama-4-70b-instruct", .tokens = 8192 },
    .{ .key = "k2p5", .tokens = 32_768 },
};

// Provider-level fallbacks aligned with current runtime defaults.
const PROVIDER_MAX_TOKENS = [_]MaxTokensEntry{
    .{ .key = "anthropic", .tokens = 8192 },
    .{ .key = "openai", .tokens = 8192 },
    .{ .key = "google", .tokens = 8192 },
    .{ .key = "gemini", .tokens = 8192 },
    .{ .key = "openrouter", .tokens = 8192 },
    .{ .key = "minimax", .tokens = 8192 },
    .{ .key = "xiaomi", .tokens = 8192 },
    .{ .key = "moonshot", .tokens = 8192 },
    .{ .key = "kimi", .tokens = 8192 },
    .{ .key = "kimi-coding", .tokens = 32_768 },
    .{ .key = "qwen", .tokens = 8192 },
    .{ .key = "qwen-portal", .tokens = 8192 },
    .{ .key = "ollama", .tokens = 8192 },
    .{ .key = "vllm", .tokens = 8192 },
    .{ .key = "github-copilot", .tokens = 8192 },
    .{ .key = "qianfan", .tokens = 32_768 },
    .{ .key = "nvidia", .tokens = 4096 },
    .{ .key = "byteplus", .tokens = 4096 },
    .{ .key = "doubao", .tokens = 4096 },
    .{ .key = "cloudflare-ai-gateway", .tokens = 64_000 },
};

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[0..prefix.len], prefix);
}

fn endsWithIgnoreCase(haystack: []const u8, suffix: []const u8) bool {
    if (haystack.len < suffix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[haystack.len - suffix.len ..], suffix);
}

fn isAllDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |ch| {
        if (ch < '0' or ch > '9') return false;
    }
    return true;
}

fn stripDateSuffix(model_id: []const u8) []const u8 {
    const last_dash = std.mem.lastIndexOfScalar(u8, model_id, '-') orelse return model_id;
    const suffix = model_id[last_dash + 1 ..];
    if (suffix.len == 8 and isAllDigits(suffix)) {
        return model_id[0..last_dash];
    }
    return model_id;
}

fn stripKnownSuffix(model_id: []const u8) []const u8 {
    if (endsWithIgnoreCase(model_id, "-latest")) {
        return model_id[0 .. model_id.len - "-latest".len];
    }
    return model_id;
}

fn isLegacyGpt4Model(model_id: []const u8) bool {
    return std.ascii.eqlIgnoreCase(model_id, "gpt-4") or
        std.ascii.eqlIgnoreCase(model_id, "gpt-4-0314") or
        std.ascii.eqlIgnoreCase(model_id, "gpt-4-0613");
}

fn lookupTable(table: []const MaxTokensEntry, key: []const u8) ?u32 {
    for (table) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key, key)) return entry.tokens;
    }
    return null;
}

fn splitProviderModel(model_ref: []const u8) struct { provider: ?[]const u8, model: []const u8 } {
    const slash = std.mem.indexOfScalar(u8, model_ref, '/') orelse {
        return .{ .provider = null, .model = model_ref };
    };
    return .{
        .provider = model_ref[0..slash],
        .model = model_ref[slash + 1 ..],
    };
}

fn inferFromModelPattern(model_id: []const u8) ?u32 {
    if (startsWithIgnoreCase(model_id, "gpt-4-32k")) return 4_096;

    // Keep strict legacy ceilings without penalizing turbo/preview descendants.
    if (isLegacyGpt4Model(model_id)) {
        return 4_096;
    }

    if (std.mem.indexOf(u8, model_id, "k2p5") != null) return 32_768;

    if (startsWithIgnoreCase(model_id, "kimi-coding") or startsWithIgnoreCase(model_id, "kimi-k2")) {
        return 32_768;
    }

    if (startsWithIgnoreCase(model_id, "nvidia/")) return 4096;

    if (startsWithIgnoreCase(model_id, "claude-") or
        startsWithIgnoreCase(model_id, "gpt-") or
        startsWithIgnoreCase(model_id, "o1") or
        startsWithIgnoreCase(model_id, "o3") or
        startsWithIgnoreCase(model_id, "gemini-") or
        startsWithIgnoreCase(model_id, "deepseek-"))
    {
        return 8192;
    }

    return null;
}

fn lookupModelCandidates(model_id_raw: []const u8) ?u32 {
    const no_latest = stripKnownSuffix(model_id_raw);
    const no_date = stripDateSuffix(no_latest);

    if (lookupTable(&MODEL_MAX_TOKENS, model_id_raw)) |n| return n;
    if (!std.mem.eql(u8, no_latest, model_id_raw)) {
        if (lookupTable(&MODEL_MAX_TOKENS, no_latest)) |n| return n;
    }
    if (!std.mem.eql(u8, no_date, no_latest)) {
        if (lookupTable(&MODEL_MAX_TOKENS, no_date)) |n| return n;
    }

    return inferFromModelPattern(no_date) orelse inferFromModelPattern(no_latest) orelse inferFromModelPattern(model_id_raw);
}

pub fn lookupModelMaxTokens(model_ref_raw: []const u8) ?u32 {
    const model_ref = std.mem.trim(u8, model_ref_raw, " \t\r\n");
    if (model_ref.len == 0) return null;

    if (lookupModelCandidates(model_ref)) |n| return n;

    const split = splitProviderModel(model_ref);
    if (lookupModelCandidates(split.model)) |n| return n;

    // Support nested refs like openrouter/anthropic/claude-sonnet-4.6.
    if (std.mem.indexOfScalar(u8, split.model, '/')) |nested_sep| {
        const nested_provider = split.model[0..nested_sep];
        const nested_model = split.model[nested_sep + 1 ..];
        if (lookupModelCandidates(nested_model)) |n| return n;
        if (lookupTable(&PROVIDER_MAX_TOKENS, nested_provider)) |n| return n;
    }
    if (std.mem.lastIndexOfScalar(u8, split.model, '/')) |last_sep| {
        const leaf_model = split.model[last_sep + 1 ..];
        if (lookupModelCandidates(leaf_model)) |n| return n;
    }

    if (split.provider) |provider| {
        if (lookupTable(&PROVIDER_MAX_TOKENS, provider)) |n| return n;
    }

    return null;
}

pub fn resolveMaxTokens(max_tokens_override: ?u32, model_ref: []const u8) u32 {
    return max_tokens_override orelse lookupModelMaxTokens(model_ref) orelse DEFAULT_MODEL_MAX_TOKENS;
}

test "resolveMaxTokens honors explicit override first" {
    const resolved = resolveMaxTokens(512, "openai/gpt-4.1-mini");
    try std.testing.expectEqual(@as(u32, 512), resolved);
}

test "lookupModelMaxTokens resolves model and nested provider refs" {
    try std.testing.expectEqual(@as(?u32, 4_096), lookupModelMaxTokens("openai/gpt-4"));
    try std.testing.expectEqual(@as(?u32, 4_096), lookupModelMaxTokens("openai/gpt-4-32k"));
    try std.testing.expectEqual(@as(?u32, 8192), lookupModelMaxTokens("openai/gpt-4.1-mini"));
    try std.testing.expectEqual(@as(?u32, 8192), lookupModelMaxTokens("openai/gpt-4-turbo"));
    try std.testing.expectEqual(@as(?u32, 8192), lookupModelMaxTokens("openrouter/anthropic/claude-sonnet-4.6"));
    try std.testing.expectEqual(@as(?u32, 32_768), lookupModelMaxTokens("qianfan/custom-model"));
}

test "lookupModelMaxTokens keeps legacy and turbo gpt-4 variants distinct" {
    try std.testing.expectEqual(@as(?u32, 4_096), lookupModelMaxTokens("openai/gpt-4-0613"));
    try std.testing.expectEqual(@as(?u32, 8192), lookupModelMaxTokens("openai/gpt-4-turbo-preview"));
}

test "lookupModelMaxTokens strips date suffixes and latest aliases" {
    try std.testing.expectEqual(@as(?u32, 8192), lookupModelMaxTokens("anthropic/claude-sonnet-4.6-20260219"));
    try std.testing.expectEqual(@as(?u32, 8192), lookupModelMaxTokens("openai/gpt-4.1-latest"));
}

test "lookupModelMaxTokens provider fallback handles lower ceilings" {
    try std.testing.expectEqual(@as(?u32, 4096), lookupModelMaxTokens("nvidia/custom-model"));
}

test "resolveMaxTokens falls back to global default" {
    const resolved = resolveMaxTokens(null, "unknown-provider/unknown-model");
    try std.testing.expectEqual(DEFAULT_MODEL_MAX_TOKENS, resolved);
}
