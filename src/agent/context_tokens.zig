//! Context-token resolution for agent compaction.
//!
//! Follows the runtime fallback chain:
//!   1) explicit config override
//!   2) best-effort lookup by model id
//!   3) default fallback

const std = @import("std");
const config_types = @import("../config_types.zig");

pub const DEFAULT_CONTEXT_TOKENS: u64 = config_types.DEFAULT_AGENT_TOKEN_LIMIT;

const ContextWindowEntry = struct {
    key: []const u8,
    tokens: u64,
};

// Model-specific defaults for high-signal IDs used by onboarding/catalog flows.
const MODEL_WINDOWS = [_]ContextWindowEntry{
    .{ .key = "gpt-4", .tokens = 8_192 },
    .{ .key = "gpt-4-32k", .tokens = 32_768 },
    .{ .key = "claude-opus-4-6", .tokens = 200_000 },
    .{ .key = "claude-opus-4.6", .tokens = 200_000 },
    .{ .key = "claude-sonnet-4-6", .tokens = 200_000 },
    .{ .key = "claude-sonnet-4.6", .tokens = 200_000 },
    .{ .key = "claude-haiku-4-5", .tokens = 200_000 },
    .{ .key = "gpt-5.2", .tokens = 128_000 },
    .{ .key = "gpt-5.2-codex", .tokens = 128_000 },
    .{ .key = "gpt-4.5-preview", .tokens = 128_000 },
    .{ .key = "gpt-4.1", .tokens = 128_000 },
    .{ .key = "gpt-4.1-mini", .tokens = 128_000 },
    .{ .key = "o3-mini", .tokens = 128_000 },
    .{ .key = "gemini-2.5-pro", .tokens = 200_000 },
    .{ .key = "gemini-2.5-flash", .tokens = 200_000 },
    .{ .key = "gemini-2.0-flash", .tokens = 200_000 },
    .{ .key = "deepseek-v3.2", .tokens = 128_000 },
    .{ .key = "deepseek-chat", .tokens = 128_000 },
    .{ .key = "deepseek-reasoner", .tokens = 128_000 },
    .{ .key = "llama-4-70b-instruct", .tokens = 128_000 },
    .{ .key = "llama-3.3-70b-versatile", .tokens = 128_000 },
    .{ .key = "llama-3.1-8b-instant", .tokens = 128_000 },
    .{ .key = "mixtral-8x7b-32768", .tokens = 32_768 },
};

// Provider-level fallbacks aligned with current runtime defaults where available.
const PROVIDER_WINDOWS = [_]ContextWindowEntry{
    .{ .key = "openrouter", .tokens = 200_000 },
    .{ .key = "minimax", .tokens = 200_000 },
    .{ .key = "openai-codex", .tokens = 200_000 },
    .{ .key = "moonshot", .tokens = 256_000 },
    .{ .key = "kimi", .tokens = 262_144 },
    .{ .key = "kimi-coding", .tokens = 262_144 },
    .{ .key = "xiaomi", .tokens = 262_144 },
    .{ .key = "ollama", .tokens = 128_000 },
    .{ .key = "qwen", .tokens = 128_000 },
    .{ .key = "vllm", .tokens = 128_000 },
    .{ .key = "github-copilot", .tokens = 128_000 },
    .{ .key = "qianfan", .tokens = 98_304 },
    .{ .key = "nvidia", .tokens = 131_072 },
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

fn lookupTable(table: []const ContextWindowEntry, key: []const u8) ?u64 {
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

fn inferFromModelPattern(model_id: []const u8) ?u64 {
    if (startsWithIgnoreCase(model_id, "gpt-4-32k")) return 32_768;

    // Keep strict legacy ceilings without penalizing turbo/preview descendants.
    if (isLegacyGpt4Model(model_id)) {
        return 8_192;
    }

    if (std.mem.indexOf(u8, model_id, "32768") != null) return 32_768;

    if (startsWithIgnoreCase(model_id, "claude-")) return 200_000;

    if (startsWithIgnoreCase(model_id, "gpt-") or
        startsWithIgnoreCase(model_id, "o1") or
        startsWithIgnoreCase(model_id, "o3"))
    {
        return 128_000;
    }

    if (startsWithIgnoreCase(model_id, "gemini-")) return 200_000;
    if (startsWithIgnoreCase(model_id, "deepseek-")) return 128_000;
    if (startsWithIgnoreCase(model_id, "llama") or startsWithIgnoreCase(model_id, "mixtral-")) return 128_000;

    return null;
}

fn lookupModelCandidates(model_id_raw: []const u8) ?u64 {
    const no_latest = stripKnownSuffix(model_id_raw);
    const no_date = stripDateSuffix(no_latest);

    if (lookupTable(&MODEL_WINDOWS, model_id_raw)) |n| return n;
    if (!std.mem.eql(u8, no_latest, model_id_raw)) {
        if (lookupTable(&MODEL_WINDOWS, no_latest)) |n| return n;
    }
    if (!std.mem.eql(u8, no_date, no_latest)) {
        if (lookupTable(&MODEL_WINDOWS, no_date)) |n| return n;
    }

    return inferFromModelPattern(no_date) orelse inferFromModelPattern(no_latest) orelse inferFromModelPattern(model_id_raw);
}

pub fn lookupContextTokens(model_ref_raw: []const u8) ?u64 {
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
        if (lookupTable(&PROVIDER_WINDOWS, nested_provider)) |n| return n;
    }
    if (std.mem.lastIndexOfScalar(u8, split.model, '/')) |last_sep| {
        const leaf_model = split.model[last_sep + 1 ..];
        if (lookupModelCandidates(leaf_model)) |n| return n;
    }

    if (split.provider) |provider| {
        if (lookupTable(&PROVIDER_WINDOWS, provider)) |n| return n;
    }

    return null;
}

pub fn resolveContextTokens(token_limit_override: ?u64, model_ref: []const u8) u64 {
    return token_limit_override orelse lookupContextTokens(model_ref) orelse DEFAULT_CONTEXT_TOKENS;
}

test "resolveContextTokens honors explicit override first" {
    const resolved = resolveContextTokens(42_000, "openai/gpt-4.1-mini");
    try std.testing.expectEqual(@as(u64, 42_000), resolved);
}

test "lookupContextTokens resolves known model ids" {
    try std.testing.expectEqual(@as(?u64, 8_192), lookupContextTokens("openai/gpt-4"));
    try std.testing.expectEqual(@as(?u64, 32_768), lookupContextTokens("openai/gpt-4-32k"));
    try std.testing.expectEqual(@as(?u64, 128_000), lookupContextTokens("openai/gpt-4.1-mini"));
    try std.testing.expectEqual(@as(?u64, 128_000), lookupContextTokens("openai/gpt-4-turbo"));
    try std.testing.expectEqual(@as(?u64, 200_000), lookupContextTokens("claude-sonnet-4.6"));
    try std.testing.expectEqual(@as(?u64, 32_768), lookupContextTokens("mixtral-8x7b-32768"));
}

test "lookupContextTokens keeps legacy and turbo gpt-4 variants distinct" {
    try std.testing.expectEqual(@as(?u64, 8_192), lookupContextTokens("openai/gpt-4-0613"));
    try std.testing.expectEqual(@as(?u64, 128_000), lookupContextTokens("openai/gpt-4-turbo-preview"));
}

test "lookupContextTokens handles nested provider refs" {
    try std.testing.expectEqual(
        @as(?u64, 200_000),
        lookupContextTokens("openrouter/anthropic/claude-sonnet-4.6"),
    );
}

test "lookupContextTokens strips date suffixes" {
    try std.testing.expectEqual(
        @as(?u64, 200_000),
        lookupContextTokens("anthropic/claude-sonnet-4.6-20260219"),
    );
}

test "lookupContextTokens falls back to provider defaults" {
    try std.testing.expectEqual(@as(?u64, 98_304), lookupContextTokens("qianfan/custom-model"));
    try std.testing.expectEqual(@as(?u64, 200_000), lookupContextTokens("openrouter/inception/mercury"));
}

test "resolveContextTokens falls back to global default" {
    const resolved = resolveContextTokens(null, "unknown-provider/unknown-model");
    try std.testing.expectEqual(DEFAULT_CONTEXT_TOKENS, resolved);
}
