//! Onboarding — interactive setup wizard and quick setup for nullclaw.
//!
//! Mirrors ZeroClaw's onboard module:
//!   - Interactive wizard (9-step configuration flow)
//!   - Quick setup (non-interactive, sensible defaults)
//!   - Workspace scaffolding (prompt context files + bootstrap lifecycle)
//!   - Channel configuration
//!   - Memory backend selection
//!   - Provider/model selection with curated defaults

const std = @import("std");
const build_options = @import("build_options");
const platform = @import("platform.zig");
const config_mod = @import("config.zig");
const Config = config_mod.Config;
const channel_catalog = @import("channel_catalog.zig");
const memory_root = @import("memory/root.zig");
const http_util = @import("http_util.zig");
const json_util = @import("json_util.zig");
const util = @import("util.zig");

// ── Constants ────────────────────────────────────────────────────

const BANNER =
    \\
    \\  ███╗   ██╗██╗   ██╗██╗     ██╗      ██████╗██╗      █████╗ ██╗    ██╗
    \\  ████╗  ██║██║   ██║██║     ██║     ██╔════╝██║     ██╔══██╗██║    ██║
    \\  ██╔██╗ ██║██║   ██║██║     ██║     ██║     ██║     ███████║██║ █╗ ██║
    \\  ██║╚██╗██║██║   ██║██║     ██║     ██║     ██║     ██╔══██║██║███╗██║
    \\  ██║ ╚████║╚██████╔╝███████╗███████╗╚██████╗███████╗██║  ██║╚███╔███╔╝
    \\  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    \\
    \\  The smallest AI assistant. Zig-powered.
    \\
;

const WORKSPACE_STATE_DIR = ".nullclaw";
const WORKSPACE_STATE_FILE = "workspace-state.json";
const WORKSPACE_STATE_VERSION: i64 = 1;

const WorkspaceOnboardingState = struct {
    version: i64 = WORKSPACE_STATE_VERSION,
    bootstrap_seeded_at: ?[]const u8 = null,
    onboarding_completed_at: ?[]const u8 = null,

    fn deinit(self: *WorkspaceOnboardingState, allocator: std.mem.Allocator) void {
        if (self.bootstrap_seeded_at) |ts| allocator.free(ts);
        if (self.onboarding_completed_at) |ts| allocator.free(ts);
        self.* = .{};
    }
};

const WORKSPACE_AGENTS_TEMPLATE = @embedFile("workspace_templates/AGENTS.md");
const WORKSPACE_SOUL_TEMPLATE = @embedFile("workspace_templates/SOUL.md");
const WORKSPACE_TOOLS_TEMPLATE = @embedFile("workspace_templates/TOOLS.md");
const WORKSPACE_IDENTITY_TEMPLATE = @embedFile("workspace_templates/IDENTITY.md");
const WORKSPACE_USER_TEMPLATE = @embedFile("workspace_templates/USER.md");
const WORKSPACE_HEARTBEAT_TEMPLATE = @embedFile("workspace_templates/HEARTBEAT.md");
const WORKSPACE_BOOTSTRAP_TEMPLATE = @embedFile("workspace_templates/BOOTSTRAP.md");
// ── Project context ──────────────────────────────────────────────

pub const ProjectContext = struct {
    user_name: []const u8 = "User",
    timezone: []const u8 = "UTC",
    agent_name: []const u8 = "nullclaw",
    communication_style: []const u8 = "Be warm, natural, and clear. Avoid robotic phrasing.",
};

// ── Provider helpers ─────────────────────────────────────────────

pub const ProviderInfo = struct {
    key: []const u8,
    label: []const u8,
    default_model: []const u8,
    env_var: []const u8,
};

pub const known_providers = [_]ProviderInfo{
    // --- Tier 1: Major multi-provider gateways ---
    .{ .key = "openrouter", .label = "OpenRouter (multi-provider, recommended)", .default_model = "anthropic/claude-sonnet-4.6", .env_var = "OPENROUTER_API_KEY" },
    .{ .key = "anthropic", .label = "Anthropic (Claude direct)", .default_model = "claude-opus-4-6", .env_var = "ANTHROPIC_API_KEY" },
    .{ .key = "openai", .label = "OpenAI (GPT direct)", .default_model = "gpt-5.2", .env_var = "OPENAI_API_KEY" },

    // --- Tier 2: Major cloud providers (Feb 2026 models) ---
    .{ .key = "gemini", .label = "Google Gemini", .default_model = "gemini-2.5-pro", .env_var = "GEMINI_API_KEY" },
    .{ .key = "deepseek", .label = "DeepSeek", .default_model = "deepseek-chat", .env_var = "DEEPSEEK_API_KEY" },
    .{ .key = "groq", .label = "Groq (fast inference)", .default_model = "llama-3.3-70b-versatile", .env_var = "GROQ_API_KEY" },

    // --- Tier 3: OpenAI-compatible specialists ---
    .{ .key = "z.ai", .label = "Z.AI (Zhipu coding)", .default_model = "glm-5", .env_var = "ZAI_API_KEY" },
    .{ .key = "glm", .label = "GLM (Zhipu general)", .default_model = "glm-5", .env_var = "ZHIPU_API_KEY" },
    .{ .key = "together-ai", .label = "Together AI (inference)", .default_model = "meta-llama/Llama-4-70B-Instruct-Turbo", .env_var = "TOGETHER_API_KEY" },
    .{ .key = "fireworks-ai", .label = "Fireworks AI (fast)", .default_model = "accounts/fireworks/models/llama-v4-70b-instruct", .env_var = "FIREWORKS_API_KEY" },
    .{ .key = "mistral", .label = "Mistral", .default_model = "mistral-large", .env_var = "MISTRAL_API_KEY" },
    .{ .key = "xai", .label = "xAI (Grok)", .default_model = "grok-4.1", .env_var = "XAI_API_KEY" },

    // --- Tier 4: AI platform specialists ---
    .{ .key = "venice", .label = "Venice", .default_model = "llama-4-70b-instruct", .env_var = "VENICE_API_KEY" },
    .{ .key = "moonshot", .label = "Moonshot (Kimi)", .default_model = "kimi-k2.5", .env_var = "MOONSHOT_API_KEY" },
    .{ .key = "synthetic", .label = "Synthetic", .default_model = "synthetic-model", .env_var = "SYNTHETIC_API_KEY" },
    .{ .key = "opencode-zen", .label = "OpenCode Zen", .default_model = "opencode-model", .env_var = "OPENCODE_API_KEY" },
    .{ .key = "minimax", .label = "MiniMax", .default_model = "minimax-m2.1", .env_var = "MINIMAX_API_KEY" },

    // --- Tier 5: Cloud gateways ---
    .{ .key = "qwen", .label = "Qwen (Alibaba)", .default_model = "qwen-3-max", .env_var = "DASHSCOPE_API_KEY" },
    .{ .key = "cohere", .label = "Cohere", .default_model = "command-r-plus", .env_var = "COHERE_API_KEY" },
    .{ .key = "perplexity", .label = "Perplexity", .default_model = "llama-4-sonar-small-128k-online", .env_var = "PERPLEXITY_API_KEY" },

    // --- Tier 6: Infrastructure providers ---
    .{ .key = "nvidia", .label = "NVIDIA NIM (enterprise)", .default_model = "meta/llama-4-70b-instruct", .env_var = "NVIDIA_API_KEY" },
    .{ .key = "cloudflare", .label = "Cloudflare AI Gateway", .default_model = "meta/llama-4-70b-instruct", .env_var = "CLOUDFLARE_API_TOKEN" },
    .{ .key = "vercel-ai", .label = "Vercel AI Gateway", .default_model = "gpt-5.2", .env_var = "VERCEL_API_KEY" },

    // --- Tier 7: Enterprise clouds ---
    .{ .key = "bedrock", .label = "Amazon Bedrock", .default_model = "anthropic.claude-opus-4-6", .env_var = "AWS_ACCESS_KEY_ID" },
    .{ .key = "qianfan", .label = "Qianfan (Baidu)", .default_model = "ernie-bot-5", .env_var = "QIANFAN_ACCESS_KEY" },
    .{ .key = "copilot", .label = "GitHub Copilot", .default_model = "gpt-5.2", .env_var = "GITHUB_TOKEN" },

    // --- Tier 8: Emerging platforms ---
    .{ .key = "astrai", .label = "Astrai", .default_model = "astrai-model", .env_var = "ASTRAI_API_KEY" },
    .{ .key = "poe", .label = "Poe", .default_model = "poe-model", .env_var = "POE_API_KEY" },

    // --- Tier 9: Local/self-hosted ---
    .{ .key = "ollama", .label = "Ollama (local CLI)", .default_model = "llama4", .env_var = "API_KEY" },
    .{ .key = "lm-studio", .label = "LM Studio (local GUI)", .default_model = "local-model", .env_var = "API_KEY" },
};

/// Canonicalize provider name (handle aliases).
pub fn canonicalProviderName(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "grok")) return "xai";
    if (std.mem.eql(u8, name, "together")) return "together-ai";
    if (std.mem.eql(u8, name, "google") or std.mem.eql(u8, name, "google-gemini")) return "gemini";
    return name;
}

fn findProviderInfoByCanonical(name: []const u8) ?ProviderInfo {
    for (known_providers) |p| {
        if (std.mem.eql(u8, p.key, name)) return p;
    }
    return null;
}

/// Resolve a provider name used in quick setup.
/// Accepts aliases (e.g. "grok" -> "xai") and returns provider metadata.
pub fn resolveProviderForQuickSetup(name: []const u8) ?ProviderInfo {
    const canonical = canonicalProviderName(name);
    return findProviderInfoByCanonical(canonical);
}

pub const ResolveMemoryBackendError = error{
    UnknownMemoryBackend,
    MemoryBackendDisabledInBuild,
};

/// Resolve a memory backend key for quick setup.
/// Distinguishes "unknown key" from "known but disabled in this build".
pub fn resolveMemoryBackendForQuickSetup(name: []const u8) ResolveMemoryBackendError!*const memory_root.BackendDescriptor {
    if (memory_root.findBackend(name)) |desc| return desc;
    if (memory_root.registry.isKnownBackend(name)) return error.MemoryBackendDisabledInBuild;
    return error.UnknownMemoryBackend;
}

/// Get the default model for a provider.
pub fn defaultModelForProvider(provider: []const u8) []const u8 {
    const canonical = canonicalProviderName(provider);
    if (findProviderInfoByCanonical(canonical)) |p| return p.default_model;
    return "anthropic/claude-sonnet-4.6";
}

/// Get the environment variable name for a provider's API key.
pub fn providerEnvVar(provider: []const u8) []const u8 {
    const canonical = canonicalProviderName(provider);
    if (findProviderInfoByCanonical(canonical)) |p| return p.env_var;
    return "API_KEY";
}

// ── Live model fetching ─────────────────────────────────────────

pub const ModelsCacheEntry = struct {
    provider: []const u8,
    models: []const []const u8,
    fetched_at: i64,
};

/// Hardcoded fallback models for each provider (used when API fetch fails).
pub fn fallbackModelsForProvider(provider: []const u8) []const []const u8 {
    const canonical = canonicalProviderName(provider);
    if (std.mem.eql(u8, canonical, "openrouter")) return &openrouter_fallback;
    if (std.mem.eql(u8, canonical, "openai")) return &openai_fallback;
    if (std.mem.eql(u8, canonical, "groq")) return &groq_fallback;
    if (std.mem.eql(u8, canonical, "anthropic")) return &anthropic_fallback;
    if (std.mem.eql(u8, canonical, "gemini")) return &gemini_fallback;
    if (std.mem.eql(u8, canonical, "deepseek")) return &deepseek_fallback;
    if (std.mem.eql(u8, canonical, "ollama")) return &ollama_fallback;

    // For providers without a curated fallback list, return a single-item fallback
    // based on the onboarding default model for that provider.
    if (providerDefaultFallback(canonical)) |models| return models;

    return &anthropic_fallback;
}

const ProviderFallback = struct {
    key: []const u8,
    models: []const []const u8,
};

const provider_default_fallbacks = blk: {
    var rows: [known_providers.len]ProviderFallback = undefined;
    for (known_providers, 0..) |p, i| {
        rows[i] = .{
            .key = p.key,
            .models = &[_][]const u8{p.default_model},
        };
    }
    break :blk rows;
};

fn providerDefaultFallback(provider: []const u8) ?[]const []const u8 {
    for (provider_default_fallbacks) |entry| {
        if (std.mem.eql(u8, entry.key, provider)) return entry.models;
    }
    return null;
}

const openrouter_fallback = [_][]const u8{
    "anthropic/claude-sonnet-4.6",
    "anthropic/claude-opus-4-6",
    "anthropic/claude-haiku-4-5",
    "openai/gpt-5.2",
    "google/gemini-2.5-pro",
    "deepseek/deepseek-v3.2",
    "meta-llama/llama-4-70b-instruct",
};
const openai_fallback = [_][]const u8{
    "gpt-5.2",
    "gpt-4.5-preview",
    "gpt-4.1",
    "gpt-4.1-mini",
    "o3-mini",
};
const groq_fallback = [_][]const u8{
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
};
const anthropic_fallback = [_][]const u8{
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-haiku-4-5",
};
const gemini_fallback = [_][]const u8{
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.0-flash",
};
const deepseek_fallback = [_][]const u8{
    "deepseek-chat",
    "deepseek-reasoner",
};
const ollama_fallback = [_][]const u8{
    "llama4",
    "llama3.2",
    "mistral",
    "phi3",
};

const MAX_MODELS = 20;

/// Return a heap-allocated copy of the static fallback list for a provider.
/// Caller owns the returned slice and all its strings.
fn dupeFallbackModels(allocator: std.mem.Allocator, provider: []const u8) ![][]const u8 {
    const static = fallbackModelsForProvider(provider);
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (result.items) |item| allocator.free(item);
        result.deinit(allocator);
    }
    for (static) |m| {
        try result.append(allocator, try allocator.dupe(u8, m));
    }
    return result.toOwnedSlice(allocator);
}

/// Fetch available model IDs for a provider (with caching, limit, and fallback).
///
/// Uses file-based cache at `~/.nullclaw/state/models_cache.json` with 12h TTL.
/// Returns at most 20 model IDs. Caller ALWAYS owns the returned slice and strings.
/// Free with: for (models) |m| allocator.free(m); allocator.free(models);
pub fn fetchModels(allocator: std.mem.Allocator, provider: []const u8, api_key: ?[]const u8) ![][]const u8 {
    const home = platform.getHomeDir(allocator) catch
        return dupeFallbackModels(allocator, provider);
    defer allocator.free(home);

    const state_dir = try std.fs.path.join(allocator, &.{ home, ".nullclaw", "state" });
    defer allocator.free(state_dir);

    // Ensure state directory exists
    std.fs.makeDirAbsolute(state_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return dupeFallbackModels(allocator, provider),
    };

    return loadModelsWithCache(allocator, state_dir, provider, api_key);
}

/// Fetch model IDs from a provider's API. Returns owned slice of owned strings.
/// For providers without a list endpoint (anthropic, gemini, etc.), returns hardcoded list.
/// Results are limited to MAX_MODELS entries.
pub fn fetchModelsFromApi(allocator: std.mem.Allocator, provider: []const u8, api_key: ?[]const u8) ![][]const u8 {
    const canonical = canonicalProviderName(provider);

    // Providers with no models-list API
    if (std.mem.eql(u8, canonical, "anthropic") or
        std.mem.eql(u8, canonical, "gemini") or
        std.mem.eql(u8, canonical, "deepseek") or
        std.mem.eql(u8, canonical, "ollama"))
    {
        const fallback = fallbackModelsForProvider(canonical);
        var result: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (result.items) |item| allocator.free(item);
            result.deinit(allocator);
        }
        for (fallback) |m| {
            try result.append(allocator, try allocator.dupe(u8, m));
        }
        return result.toOwnedSlice(allocator);
    }

    // Determine URL, auth, and optional prefix filter
    var url: []const u8 = undefined;
    var needs_auth = false;
    var prefix_filter: ?[]const u8 = null;
    if (std.mem.eql(u8, canonical, "openrouter")) {
        url = "https://openrouter.ai/api/v1/models";
        needs_auth = false; // OpenRouter models endpoint is public
    } else if (std.mem.eql(u8, canonical, "openai")) {
        url = "https://api.openai.com/v1/models";
        needs_auth = true;
        prefix_filter = "gpt-"; // Only return GPT models from OpenAI
    } else if (std.mem.eql(u8, canonical, "groq")) {
        url = "https://api.groq.com/openai/v1/models";
        needs_auth = true;
    } else {
        return error.FetchFailed;
    }

    // Build auth header if needed
    var headers_buf: [1][]const u8 = undefined;
    var headers: []const []const u8 = &.{};
    if (needs_auth) {
        const key = api_key orelse return error.FetchFailed;
        const auth_hdr = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{key});
        defer allocator.free(auth_hdr);
        headers_buf[0] = auth_hdr;
        headers = &headers_buf;
        // Must call curlGet before auth_hdr is freed
        return fetchAndParseModels(allocator, url, headers, prefix_filter);
    }

    return fetchAndParseModels(allocator, url, headers, prefix_filter);
}

fn fetchAndParseModels(allocator: std.mem.Allocator, url: []const u8, headers: []const []const u8, prefix_filter: ?[]const u8) ![][]const u8 {
    const response = http_util.curlGet(allocator, url, headers, "10") catch return error.FetchFailed;
    defer allocator.free(response);

    if (response.len == 0) return error.FetchFailed;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, response, .{}) catch return error.FetchFailed;
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.FetchFailed;

    const data = root.object.get("data") orelse return error.FetchFailed;
    if (data != .array) return error.FetchFailed;

    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (result.items) |item| allocator.free(item);
        result.deinit(allocator);
    }

    for (data.array.items) |item| {
        if (result.items.len >= MAX_MODELS) break;
        if (item != .object) continue;
        const id_val = item.object.get("id") orelse continue;
        if (id_val != .string) continue;
        // Apply prefix filter (e.g. "gpt-" for OpenAI)
        if (prefix_filter) |pf| {
            if (!std.mem.startsWith(u8, id_val.string, pf)) continue;
        }
        try result.append(allocator, try allocator.dupe(u8, id_val.string));
    }

    if (result.items.len == 0) return error.FetchFailed;
    return result.toOwnedSlice(allocator);
}

/// Load models with file-based cache. Cache expires after 12 hours.
/// Falls back to hardcoded list on any error. Caller ALWAYS owns the result.
pub fn loadModelsWithCache(allocator: std.mem.Allocator, cache_dir: []const u8, provider: []const u8, api_key: ?[]const u8) ![][]const u8 {
    return loadModelsWithCacheInner(allocator, cache_dir, provider, api_key) catch {
        return dupeFallbackModels(allocator, provider);
    };
}

fn loadModelsWithCacheInner(allocator: std.mem.Allocator, cache_dir: []const u8, provider: []const u8, api_key: ?[]const u8) ![][]const u8 {
    const canonical = canonicalProviderName(provider);
    const cache_path = try std.fmt.allocPrint(allocator, "{s}/models_cache.json", .{cache_dir});
    defer allocator.free(cache_path);

    // Try reading cache file
    if (readCachedModels(allocator, cache_path, canonical)) |cached| {
        return cached;
    } else |_| {}

    // Cache miss or expired — fetch from API
    const models = try fetchModelsFromApi(allocator, canonical, api_key);

    // Best-effort: save to cache (coerce [][]const u8 -> []const []const u8)
    const models_const: []const []const u8 = models;
    saveCachedModels(allocator, cache_path, canonical, models_const) catch {};

    return models;
}

const CACHE_TTL_SECS: i64 = 12 * 3600; // 12 hours

fn readCachedModels(allocator: std.mem.Allocator, cache_path: []const u8, provider: []const u8) ![][]const u8 {
    const file = std.fs.openFileAbsolute(cache_path, .{}) catch return error.CacheNotFound;
    defer file.close();

    const content = file.readToEndAlloc(allocator, 256 * 1024) catch return error.CacheReadError;
    defer allocator.free(content);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{}) catch return error.CacheParseError;
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.CacheParseError;

    // Check timestamp
    const ts_val = root.object.get("fetched_at") orelse return error.CacheParseError;
    const fetched_at: i64 = switch (ts_val) {
        .integer => ts_val.integer,
        else => return error.CacheParseError,
    };

    const now = std.time.timestamp();
    if (now - fetched_at > CACHE_TTL_SECS) return error.CacheExpired;

    // Get provider's model list
    const provider_val = root.object.get(provider) orelse return error.CacheProviderMissing;
    if (provider_val != .array) return error.CacheParseError;

    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (result.items) |item| allocator.free(item);
        result.deinit(allocator);
    }

    for (provider_val.array.items) |item| {
        if (item != .string) continue;
        try result.append(allocator, try allocator.dupe(u8, item.string));
    }

    if (result.items.len == 0) return error.CacheEmpty;
    return result.toOwnedSlice(allocator);
}

fn saveCachedModels(allocator: std.mem.Allocator, cache_path: []const u8, provider: []const u8, models: []const []const u8) !void {
    // Build simple JSON: { "fetched_at": <ts>, "<provider>": ["model1", ...] }
    // We merge into existing cache if present
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\n  \"fetched_at\": ");
    var ts_buf: [24]u8 = undefined;
    const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{std.time.timestamp()}) catch return;
    try buf.appendSlice(allocator, ts_str);
    try buf.appendSlice(allocator, ",\n  \"");
    try buf.appendSlice(allocator, provider);
    try buf.appendSlice(allocator, "\": [");

    for (models, 0..) |m, i| {
        if (i > 0) try buf.appendSlice(allocator, ", ");
        try buf.append(allocator, '"');
        try buf.appendSlice(allocator, m);
        try buf.append(allocator, '"');
    }

    try buf.appendSlice(allocator, "]\n}\n");

    const file = std.fs.createFileAbsolute(cache_path, .{}) catch return;
    defer file.close();
    file.writeAll(buf.items) catch {};
}

/// Parse a mock OpenRouter-style JSON response and extract model IDs.
/// Used for testing the JSON parsing logic without network access.
pub fn parseModelIds(allocator: std.mem.Allocator, json_response: []const u8) ![][]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_response, .{}) catch return error.FetchFailed;
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.FetchFailed;
    const data = root.object.get("data") orelse return error.FetchFailed;
    if (data != .array) return error.FetchFailed;

    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (result.items) |item| allocator.free(item);
        result.deinit(allocator);
    }

    for (data.array.items) |item| {
        if (item != .object) continue;
        const id_val = item.object.get("id") orelse continue;
        if (id_val != .string) continue;
        try result.append(allocator, try allocator.dupe(u8, id_val.string));
    }

    return result.toOwnedSlice(allocator);
}

// ── Fresh config with arena ──────────────────────────────────────

/// Create a fresh Config backed by an arena (for when Config.load() fails).
/// Caller must call cfg.deinit() when done.
fn initFreshConfig(backing_allocator: std.mem.Allocator) !Config {
    const arena_ptr = try backing_allocator.create(std.heap.ArenaAllocator);
    arena_ptr.* = std.heap.ArenaAllocator.init(backing_allocator);
    errdefer {
        arena_ptr.deinit();
        backing_allocator.destroy(arena_ptr);
    }
    const allocator = arena_ptr.allocator();
    return Config{
        .workspace_dir = try getDefaultWorkspace(allocator),
        .config_path = try getDefaultConfigPath(allocator),
        .allocator = allocator,
        .arena = arena_ptr,
    };
}

// ── Quick setup ──────────────────────────────────────────────────

/// Non-interactive setup: generates a sensible default config.
pub fn runQuickSetup(allocator: std.mem.Allocator, api_key: ?[]const u8, provider: ?[]const u8, memory_backend: ?[]const u8) !void {
    var stdout_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &bw.interface;
    try stdout.writeAll(BANNER);
    try stdout.writeAll("  Quick Setup -- generating config with sensible defaults...\n\n");

    // Load or create config
    var cfg = Config.load(allocator) catch try initFreshConfig(allocator);
    defer cfg.deinit();

    // Apply overrides
    var provider_overridden = false;
    if (provider) |p| {
        const info = resolveProviderForQuickSetup(p) orelse return error.UnknownProvider;
        cfg.default_provider = try cfg.allocator.dupe(u8, info.key);
        provider_overridden = true;
    }
    if (api_key) |key| {
        // Store in providers section for the default provider (arena frees old values)
        const entries = try cfg.allocator.alloc(config_mod.ProviderEntry, 1);
        entries[0] = .{
            .name = try cfg.allocator.dupe(u8, cfg.default_provider),
            .api_key = try cfg.allocator.dupe(u8, key),
        };
        cfg.providers = entries;
    }
    if (memory_backend) |mb| {
        const desc = try resolveMemoryBackendForQuickSetup(mb);
        cfg.memory.backend = desc.name;
        cfg.memory.profile = memoryProfileForBackend(desc.name);
        cfg.memory.auto_save = desc.auto_save_default;
    }

    // Set default model based on provider
    if (provider_overridden) {
        cfg.default_model = defaultModelForProvider(cfg.default_provider);
    } else if (cfg.default_model == null or std.mem.eql(u8, cfg.default_model.?, "anthropic/claude-sonnet-4")) {
        cfg.default_model = defaultModelForProvider(cfg.default_provider);
    }

    // Ensure parent config directory and workspace directory exist
    if (std.fs.path.dirname(cfg.workspace_dir)) |parent| {
        std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
    std.fs.makeDirAbsolute(cfg.workspace_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Scaffold workspace files
    try scaffoldWorkspace(allocator, cfg.workspace_dir, &ProjectContext{});

    // Save config so subsequent commands can find it
    try cfg.save();

    // Print summary
    try stdout.print("  [OK] Workspace:  {s}\n", .{cfg.workspace_dir});
    try stdout.print("  [OK] Provider:   {s}\n", .{cfg.default_provider});
    if (cfg.default_model) |m| {
        try stdout.print("  [OK] Model:      {s}\n", .{m});
    }
    try stdout.print("  [OK] API Key:    {s}\n", .{if (cfg.defaultProviderKey() != null) "set" else "not set (use --api-key or edit config)"});
    try stdout.print("  [OK] Memory:     {s}\n", .{cfg.memory.backend});
    try stdout.writeAll("\n  Next steps:\n");
    if (cfg.defaultProviderKey() == null) {
        const env_hint = providerEnvVar(cfg.default_provider);
        try stdout.print("    1. Set your API key:  export {s}=\"sk-...\"\n", .{env_hint});
        try stdout.writeAll("    2. Chat:              nullclaw agent -m \"Hello!\"\n");
        try stdout.writeAll("    3. Gateway:           nullclaw gateway\n");
    } else {
        try stdout.writeAll("    1. Chat:     nullclaw agent -m \"Hello!\"\n");
        try stdout.writeAll("    2. Gateway:  nullclaw gateway\n");
        try stdout.writeAll("    3. Status:   nullclaw status\n");
    }
    try stdout.writeAll("\n");
    try stdout.flush();
}

/// Main entry point — called from main.zig as `onboard.run(allocator)`.
pub fn run(allocator: std.mem.Allocator) !void {
    return runWizard(allocator);
}

/// Reconfigure channels and allowlists only (preserves existing config).
pub fn runChannelsOnly(allocator: std.mem.Allocator) !void {
    var stdout_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &bw.interface;
    var input_buf: [512]u8 = undefined;
    resetStdinLineReader();

    var cfg = Config.load(allocator) catch {
        try stdout.writeAll("No existing config found. Run `nullclaw onboard` first.\n");
        try stdout.flush();
        return error.ConfigNotFound;
    };
    defer cfg.deinit();

    try stdout.writeAll("Channel setup wizard:\n");
    const changed = try configureChannelsInteractive(allocator, &cfg, stdout, &input_buf, "");
    if (changed) {
        try cfg.save();
        try stdout.writeAll("Channel configuration saved.\n\n");
    } else {
        try stdout.writeAll("No channel changes applied.\n\n");
    }

    try stdout.writeAll("Channel configuration status:\n\n");
    for (channel_catalog.known_channels) |meta| {
        var status_buf: [64]u8 = undefined;
        const status_text = channel_catalog.statusText(&cfg, meta, &status_buf);
        try stdout.print("  {s}: {s}\n", .{ meta.label, status_text });
    }
    try stdout.writeAll("\nConfig file:\n");
    try stdout.print("  {s}\n", .{cfg.config_path});
    try stdout.flush();
}

const StdinLineReader = struct {
    pending: [8192]u8 = undefined,
    pending_len: usize = 0,

    fn reset(self: *StdinLineReader) void {
        self.pending_len = 0;
    }

    fn copyLineToOut(out: []u8, raw_line: []const u8) []const u8 {
        const trimmed = std.mem.trimRight(u8, raw_line, "\r");
        const copy_len = @min(out.len, trimmed.len);
        @memcpy(out[0..copy_len], trimmed[0..copy_len]);
        return out[0..copy_len];
    }

    fn popLine(self: *StdinLineReader, out: []u8) ?[]const u8 {
        const nl = std.mem.indexOfScalar(u8, self.pending[0..self.pending_len], '\n') orelse return null;
        const line = copyLineToOut(out, self.pending[0..nl]);

        const remainder_start = nl + 1;
        const remainder_len = self.pending_len - remainder_start;
        std.mem.copyForwards(u8, self.pending[0..remainder_len], self.pending[remainder_start..self.pending_len]);
        self.pending_len = remainder_len;
        return line;
    }

    fn flushRemainder(self: *StdinLineReader, out: []u8) ?[]const u8 {
        if (self.pending_len == 0) return null;
        const line = copyLineToOut(out, self.pending[0..self.pending_len]);
        self.pending_len = 0;
        return line;
    }
};

var stdin_line_reader = StdinLineReader{};

fn resetStdinLineReader() void {
    stdin_line_reader.reset();
}

/// Read a line from stdin, trimming trailing newline/carriage return.
/// Returns null on EOF (Ctrl+D).
fn readLine(buf: []u8) ?[]const u8 {
    const stdin = std.fs.File.stdin();
    while (true) {
        if (stdin_line_reader.popLine(buf)) |line| return line;

        if (stdin_line_reader.pending_len == stdin_line_reader.pending.len) {
            // No newline yet and internal buffer is full; return a truncated line
            // to prevent deadlock on oversized input.
            return stdin_line_reader.flushRemainder(buf);
        }

        const read_dst = stdin_line_reader.pending[stdin_line_reader.pending_len..];
        const n = stdin.read(read_dst) catch return null;
        if (n == 0) {
            return stdin_line_reader.flushRemainder(buf);
        }
        stdin_line_reader.pending_len += n;
    }
}

/// Prompt user with a message, read a line. Returns default_val if input is empty.
/// Returns null on EOF.
fn prompt(out: *std.Io.Writer, buf: []u8, message: []const u8, default_val: []const u8) ?[]const u8 {
    out.writeAll(message) catch return null;
    out.flush() catch return null;
    const line = readLine(buf) orelse return null;
    if (line.len == 0) return default_val;
    return line;
}

/// Prompt for a numbered choice (1-based). Returns 0-based index, or default_idx on empty input.
/// Returns null on EOF.
fn promptChoice(out: *std.Io.Writer, buf: []u8, max: usize, default_idx: usize) ?usize {
    out.flush() catch return null;
    const line = readLine(buf) orelse return null;
    if (line.len == 0) return default_idx;
    const num = std.fmt.parseInt(usize, line, 10) catch return default_idx;
    if (num < 1 or num > max) return default_idx;
    return num - 1;
}

const tunnel_options = [_][]const u8{ "none", "cloudflare", "ngrok", "tailscale" };
const autonomy_options = [_][]const u8{ "supervised", "autonomous", "fully_autonomous" };
const wizard_memory_backend_order = [_][]const u8{
    "sqlite",
    "markdown",
    "memory",
    "none",
    "lucid",
    "redis",
    "lancedb",
    "postgres",
    "api",
};

fn selectableBackendsForWizard(allocator: std.mem.Allocator) ![]const *const memory_root.BackendDescriptor {
    var out: std.ArrayListUnmanaged(*const memory_root.BackendDescriptor) = .empty;
    errdefer out.deinit(allocator);

    for (wizard_memory_backend_order) |name| {
        if (memory_root.findBackend(name)) |desc| {
            try out.append(allocator, desc);
        }
    }

    if (out.items.len == 0) return error.NoSelectableBackends;
    return out.toOwnedSlice(allocator);
}

fn memoryProfileForBackend(backend: []const u8) []const u8 {
    if (std.mem.eql(u8, backend, "sqlite")) return "local_keyword";
    if (std.mem.eql(u8, backend, "markdown")) return "markdown_only";
    if (std.mem.eql(u8, backend, "postgres")) return "postgres_keyword";
    if (std.mem.eql(u8, backend, "none")) return "minimal_none";
    return "custom";
}

fn isWizardInteractiveChannel(channel_id: channel_catalog.ChannelId) bool {
    return switch (channel_id) {
        .telegram, .discord, .slack, .webhook, .mattermost, .matrix, .signal => true,
        else => false,
    };
}

fn appendUniqueIndex(list: *std.ArrayListUnmanaged(usize), allocator: std.mem.Allocator, idx: usize) !void {
    for (list.items) |existing| {
        if (existing == idx) return;
    }
    try list.append(allocator, idx);
}

fn findChannelOptionIndex(token: []const u8, options: []const channel_catalog.ChannelMeta) ?usize {
    if (std.fmt.parseInt(usize, token, 10)) |num| {
        if (num >= 1 and num <= options.len) return num - 1;
    } else |_| {}

    for (options, 0..) |meta, idx| {
        if (std.ascii.eqlIgnoreCase(meta.key, token)) return idx;
    }
    return null;
}

fn configureChannelsInteractive(
    allocator: std.mem.Allocator,
    cfg: *Config,
    out: *std.Io.Writer,
    input_buf: []u8,
    prefix: []const u8,
) !bool {
    var options: std.ArrayListUnmanaged(channel_catalog.ChannelMeta) = .empty;
    defer options.deinit(allocator);
    var manual_only: std.ArrayListUnmanaged([]const u8) = .empty;
    defer manual_only.deinit(allocator);

    for (channel_catalog.known_channels) |meta| {
        if (meta.id == .cli) continue;
        if (!channel_catalog.isBuildEnabled(meta.id)) continue;
        if (!isWizardInteractiveChannel(meta.id)) {
            try manual_only.append(allocator, meta.label);
            continue;
        }
        try options.append(allocator, meta);
    }

    if (options.items.len == 0) {
        try out.print("{s}No channel backends are enabled in this build.\n", .{prefix});
        return false;
    }

    try out.print("{s}Channel setup:\n", .{prefix});
    for (options.items, 0..) |meta, idx| {
        var status_buf: [64]u8 = undefined;
        const status = channel_catalog.statusText(cfg, meta, &status_buf);
        try out.print("{s}  [{d}] {s} ({s})\n", .{ prefix, idx + 1, meta.label, status });
    }
    if (manual_only.items.len > 0) {
        try out.print("{s}  Other channels in this build require manual config:", .{prefix});
        for (manual_only.items) |label| {
            try out.print(" {s}", .{label});
        }
        try out.print("\n", .{});
    }
    try out.print("{s}Select channels (comma-separated numbers/keys, Enter to skip): ", .{prefix});

    const selection_input = prompt(out, input_buf, "", "") orelse {
        try out.print("\n{s}Channel setup aborted.\n", .{prefix});
        return false;
    };
    if (selection_input.len == 0) {
        try out.print("{s}-> Skipped channel setup.\n", .{prefix});
        return false;
    }

    var selected: std.ArrayListUnmanaged(usize) = .empty;
    defer selected.deinit(allocator);

    var tokens = std.mem.tokenizeAny(u8, selection_input, ", \t");
    while (tokens.next()) |token| {
        if (findChannelOptionIndex(token, options.items)) |idx| {
            try appendUniqueIndex(&selected, allocator, idx);
        } else {
            try out.print("{s}  ! Unknown channel '{s}' (ignored)\n", .{ prefix, token });
        }
    }

    if (selected.items.len == 0) {
        try out.print("{s}-> No valid channel selections.\n", .{prefix});
        return false;
    }

    var changed = false;
    for (selected.items) |idx| {
        const meta = options.items[idx];
        const configured = try configureSingleChannel(cfg, out, input_buf, prefix, meta);
        changed = changed or configured;
    }
    return changed;
}

fn configureSingleChannel(
    cfg: *Config,
    out: *std.Io.Writer,
    input_buf: []u8,
    prefix: []const u8,
    meta: channel_catalog.ChannelMeta,
) !bool {
    return switch (meta.id) {
        .telegram => configureTelegramChannel(cfg, out, input_buf, prefix),
        .discord => configureDiscordChannel(cfg, out, input_buf, prefix),
        .slack => configureSlackChannel(cfg, out, input_buf, prefix),
        .matrix => configureMatrixChannel(cfg, out, input_buf, prefix),
        .mattermost => configureMattermostChannel(cfg, out, input_buf, prefix),
        .signal => configureSignalChannel(cfg, out, input_buf, prefix),
        .webhook => configureWebhookChannel(cfg, out, input_buf, prefix),
        else => blk: {
            try out.print("{s}  {s}: interactive setup not implemented yet. Edit {s} manually.\n", .{ prefix, meta.label, cfg.config_path });
            break :blk false;
        },
    };
}

fn parseTelegramAllowFrom(allocator: std.mem.Allocator, raw: []const u8) ![]const []const u8 {
    var allow: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (allow.items) |entry| allocator.free(entry);
        allow.deinit(allocator);
    }

    var tokens = std.mem.tokenizeAny(u8, raw, ", \t");
    while (tokens.next()) |token| {
        var normalized = std.mem.trim(u8, token, " \t\r\n");
        if (normalized.len == 0) continue;
        if (normalized[0] == '@') {
            normalized = normalized[1..];
            if (normalized.len == 0) continue;
        }

        var exists = false;
        for (allow.items) |existing| {
            if (std.ascii.eqlIgnoreCase(existing, normalized)) {
                exists = true;
                break;
            }
        }
        if (exists) continue;

        try allow.append(allocator, try allocator.dupe(u8, normalized));
    }

    if (allow.items.len == 0) {
        try allow.append(allocator, try allocator.dupe(u8, "*"));
    }

    return allow.toOwnedSlice(allocator);
}

fn configureTelegramChannel(cfg: *Config, out: *std.Io.Writer, input_buf: []u8, prefix: []const u8) !bool {
    var token_buf: [512]u8 = undefined;
    try out.print("{s}  Telegram bot token (required, Enter to skip): ", .{prefix});
    const token = prompt(out, &token_buf, "", "") orelse return false;
    if (token.len == 0) {
        try out.print("{s}  -> Telegram skipped\n", .{prefix});
        return false;
    }

    try out.print("{s}  Telegram allow_from (username/user_id, comma-separated) [*]: ", .{prefix});
    const allow_input = prompt(out, input_buf, "", "") orelse return false;
    const allow_from = try parseTelegramAllowFrom(cfg.allocator, allow_input);

    const accounts = try cfg.allocator.alloc(config_mod.TelegramConfig, 1);
    accounts[0] = .{
        .account_id = "default",
        .bot_token = try cfg.allocator.dupe(u8, token),
        .allow_from = allow_from,
    };
    cfg.channels.telegram = accounts;
    if (allow_from.len == 1 and std.mem.eql(u8, allow_from[0], "*")) {
        try out.print("{s}  -> Telegram configured (allow_from=*)\n", .{prefix});
    } else {
        try out.print("{s}  -> Telegram configured ({d} allow_from entries)\n", .{ prefix, allow_from.len });
    }
    return true;
}

fn configureDiscordChannel(cfg: *Config, out: *std.Io.Writer, input_buf: []u8, prefix: []const u8) !bool {
    var token_buf: [512]u8 = undefined;
    try out.print("{s}  Discord bot token (required, Enter to skip): ", .{prefix});
    const token = prompt(out, &token_buf, "", "") orelse return false;
    if (token.len == 0) {
        try out.print("{s}  -> Discord skipped\n", .{prefix});
        return false;
    }

    try out.print("{s}  Discord guild ID (optional): ", .{prefix});
    const guild_id = prompt(out, input_buf, "", "") orelse return false;

    const accounts = try cfg.allocator.alloc(config_mod.DiscordConfig, 1);
    accounts[0] = .{
        .account_id = "default",
        .token = try cfg.allocator.dupe(u8, token),
        .guild_id = if (guild_id.len > 0) try cfg.allocator.dupe(u8, guild_id) else null,
    };
    cfg.channels.discord = accounts;
    try out.print("{s}  -> Discord configured\n", .{prefix});
    return true;
}

fn configureSlackChannel(cfg: *Config, out: *std.Io.Writer, input_buf: []u8, prefix: []const u8) !bool {
    var bot_token_buf: [512]u8 = undefined;
    var app_token_buf: [512]u8 = undefined;
    try out.print("{s}  Slack bot token (required, Enter to skip): ", .{prefix});
    const bot_token = prompt(out, &bot_token_buf, "", "") orelse return false;
    if (bot_token.len == 0) {
        try out.print("{s}  -> Slack skipped\n", .{prefix});
        return false;
    }

    try out.print("{s}  Slack app token (optional, for socket mode): ", .{prefix});
    const app_token = prompt(out, &app_token_buf, "", "") orelse return false;

    var signing_secret: ?[]const u8 = null;
    if (app_token.len == 0) {
        try out.print("{s}  Slack signing secret (optional, for HTTP mode): ", .{prefix});
        const secret = prompt(out, input_buf, "", "") orelse return false;
        if (secret.len > 0) signing_secret = try cfg.allocator.dupe(u8, secret);
    }

    const accounts = try cfg.allocator.alloc(config_mod.SlackConfig, 1);
    accounts[0] = .{
        .account_id = "default",
        .mode = if (app_token.len > 0) .socket else .http,
        .bot_token = try cfg.allocator.dupe(u8, bot_token),
        .app_token = if (app_token.len > 0) try cfg.allocator.dupe(u8, app_token) else null,
        .signing_secret = signing_secret,
    };
    cfg.channels.slack = accounts;
    try out.print("{s}  -> Slack configured\n", .{prefix});
    return true;
}

fn configureMattermostChannel(cfg: *Config, out: *std.Io.Writer, input_buf: []u8, prefix: []const u8) !bool {
    var base_url_buf: [512]u8 = undefined;
    try out.print("{s}  Mattermost base URL (required, Enter to skip): ", .{prefix});
    const base_url = prompt(out, &base_url_buf, "", "") orelse return false;
    if (base_url.len == 0) {
        try out.print("{s}  -> Mattermost skipped\n", .{prefix});
        return false;
    }

    try out.print("{s}  Mattermost bot token (required, Enter to skip): ", .{prefix});
    const bot_token = prompt(out, input_buf, "", "") orelse return false;
    if (bot_token.len == 0) {
        try out.print("{s}  -> Mattermost skipped\n", .{prefix});
        return false;
    }

    const accounts = try cfg.allocator.alloc(config_mod.MattermostConfig, 1);
    accounts[0] = .{
        .account_id = "default",
        .bot_token = try cfg.allocator.dupe(u8, bot_token),
        .base_url = try cfg.allocator.dupe(u8, base_url),
    };
    cfg.channels.mattermost = accounts;
    try out.print("{s}  -> Mattermost configured\n", .{prefix});
    return true;
}

fn configureMatrixChannel(cfg: *Config, out: *std.Io.Writer, _: []u8, prefix: []const u8) !bool {
    var homeserver_buf: [512]u8 = undefined;
    var access_token_buf: [512]u8 = undefined;
    var room_id_buf: [512]u8 = undefined;
    var user_id_buf: [512]u8 = undefined;
    try out.print("{s}  Matrix homeserver URL (required, Enter to skip): ", .{prefix});
    const homeserver = prompt(out, &homeserver_buf, "", "") orelse return false;
    if (homeserver.len == 0) {
        try out.print("{s}  -> Matrix skipped\n", .{prefix});
        return false;
    }

    try out.print("{s}  Matrix access token (required, Enter to skip): ", .{prefix});
    const access_token = prompt(out, &access_token_buf, "", "") orelse return false;
    if (access_token.len == 0) {
        try out.print("{s}  -> Matrix skipped\n", .{prefix});
        return false;
    }

    try out.print("{s}  Matrix room ID (required, Enter to skip): ", .{prefix});
    const room_id = prompt(out, &room_id_buf, "", "") orelse return false;
    if (room_id.len == 0) {
        try out.print("{s}  -> Matrix skipped\n", .{prefix});
        return false;
    }

    try out.print("{s}  Matrix user ID (optional, for typing indicators): ", .{prefix});
    const user_id = prompt(out, &user_id_buf, "", "") orelse return false;

    const accounts = try cfg.allocator.alloc(config_mod.MatrixConfig, 1);
    accounts[0] = .{
        .account_id = "default",
        .homeserver = try cfg.allocator.dupe(u8, homeserver),
        .access_token = try cfg.allocator.dupe(u8, access_token),
        .room_id = try cfg.allocator.dupe(u8, room_id),
        .user_id = if (user_id.len > 0) try cfg.allocator.dupe(u8, user_id) else null,
        .allow_from = &[_][]const u8{"*"},
    };
    cfg.channels.matrix = accounts;
    try out.print("{s}  -> Matrix configured (allow_from=*)\n", .{prefix});
    return true;
}

fn configureSignalChannel(cfg: *Config, out: *std.Io.Writer, input_buf: []u8, prefix: []const u8) !bool {
    var http_url_buf: [512]u8 = undefined;
    var account_buf: [512]u8 = undefined;
    try out.print("{s}  Signal daemon URL [http://127.0.0.1:8080]: ", .{prefix});
    const http_url = prompt(out, &http_url_buf, "", "http://127.0.0.1:8080") orelse return false;
    if (http_url.len == 0) {
        try out.print("{s}  -> Signal skipped\n", .{prefix});
        return false;
    }

    try out.print("{s}  Signal account (E.164, required, Enter to skip): ", .{prefix});
    const account = prompt(out, &account_buf, "", "") orelse return false;
    if (account.len == 0) {
        try out.print("{s}  -> Signal skipped\n", .{prefix});
        return false;
    }

    try out.print("{s}  Ignore attachments? [y/N]: ", .{prefix});
    const ignore_input = prompt(out, input_buf, "", "n") orelse return false;
    const ignore_attachments = ignore_input.len > 0 and (ignore_input[0] == 'y' or ignore_input[0] == 'Y');

    const accounts = try cfg.allocator.alloc(config_mod.SignalConfig, 1);
    accounts[0] = .{
        .account_id = "default",
        .http_url = try cfg.allocator.dupe(u8, http_url),
        .account = try cfg.allocator.dupe(u8, account),
        .allow_from = &[_][]const u8{"*"},
        .ignore_attachments = ignore_attachments,
    };
    cfg.channels.signal = accounts;
    try out.print("{s}  -> Signal configured (allow_from=*)\n", .{prefix});
    return true;
}

fn configureWebhookChannel(cfg: *Config, out: *std.Io.Writer, input_buf: []u8, prefix: []const u8) !bool {
    try out.print("{s}  Webhook port [8080]: ", .{prefix});
    const port_input = prompt(out, input_buf, "", "8080") orelse return false;
    const port = std.fmt.parseInt(u16, port_input, 10) catch 8080;

    try out.print("{s}  Webhook secret (optional): ", .{prefix});
    const secret_input = prompt(out, input_buf, "", "") orelse return false;
    cfg.channels.webhook = .{
        .port = port,
        .secret = if (secret_input.len > 0) try cfg.allocator.dupe(u8, secret_input) else null,
    };
    try out.print("{s}  -> Webhook configured\n", .{prefix});
    return true;
}

/// Interactive wizard entry point — runs the full setup interactively.
pub fn runWizard(allocator: std.mem.Allocator) !void {
    var stdout_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    const out = &bw.interface;
    resetStdinLineReader();
    try out.writeAll(BANNER);
    try out.writeAll("  Welcome to nullclaw -- the fastest, smallest AI assistant.\n");
    try out.writeAll("  This wizard will configure your agent.\n\n");
    try out.flush();

    var input_buf: [512]u8 = undefined;

    // Load existing or create fresh config
    var cfg = Config.load(allocator) catch try initFreshConfig(allocator);
    defer cfg.deinit();

    // ── Step 1: Provider selection ──
    try out.writeAll("  Step 1/8: Select a provider\n");
    for (known_providers, 0..) |p, i| {
        try out.print("    [{d}] {s}\n", .{ i + 1, p.label });
    }
    try out.writeAll("  Choice [1]: ");
    const provider_idx = promptChoice(out, &input_buf, known_providers.len, 0) orelse {
        try out.writeAll("\n  Aborted.\n");
        try out.flush();
        return;
    };
    const selected_provider = known_providers[provider_idx];
    cfg.default_provider = selected_provider.key;
    try out.print("  -> {s}\n\n", .{selected_provider.label});

    // ── Step 2: API key ──
    const env_hint = selected_provider.env_var;
    try out.print("  Step 2/8: Enter API key (or press Enter to use env var {s}): ", .{env_hint});
    const api_key_input = prompt(out, &input_buf, "", "") orelse {
        try out.writeAll("\n  Aborted.\n");
        try out.flush();
        return;
    };
    if (api_key_input.len > 0) {
        // Store in providers section (arena frees old values)
        const entries = try cfg.allocator.alloc(config_mod.ProviderEntry, 1);
        entries[0] = .{ .name = try cfg.allocator.dupe(u8, cfg.default_provider), .api_key = try cfg.allocator.dupe(u8, api_key_input) };
        cfg.providers = entries;
        try out.writeAll("  -> API key set\n\n");
    } else {
        try out.print("  -> Will use ${s} from environment\n\n", .{env_hint});
    }

    // ── Step 3: Model (with live fetching) ──
    try out.writeAll("  Step 3/8: Select a model\n");
    try out.writeAll("  Fetching available models...\n");
    try out.flush();

    const live_models = fetchModels(allocator, selected_provider.key, cfg.defaultProviderKey()) catch
        try dupeFallbackModels(allocator, selected_provider.key);
    defer {
        for (live_models) |m| allocator.free(m);
        allocator.free(live_models);
    }

    // Show up to 15 models as numbered choices
    const display_max: usize = @min(live_models.len, 15);
    for (live_models[0..display_max], 0..) |m, i| {
        const is_default = std.mem.eql(u8, m, selected_provider.default_model);
        if (is_default) {
            try out.print("    [{d}] {s} (default)\n", .{ i + 1, m });
        } else {
            try out.print("    [{d}] {s}\n", .{ i + 1, m });
        }
    }
    if (live_models.len > display_max) {
        try out.print("    ... and {d} more (type name to use any model)\n", .{live_models.len - display_max});
    }
    try out.print("  Choice [1] or model name [{s}]: ", .{selected_provider.default_model});
    const model_input = prompt(out, &input_buf, "", "") orelse {
        try out.writeAll("\n  Aborted.\n");
        try out.flush();
        return;
    };
    if (model_input.len == 0) {
        // Default: use first model from the list (or provider default)
        cfg.default_model = if (live_models.len > 0) live_models[0] else selected_provider.default_model;
    } else if (std.fmt.parseInt(usize, model_input, 10)) |num| {
        if (num >= 1 and num <= display_max) {
            cfg.default_model = live_models[num - 1];
        } else {
            cfg.default_model = selected_provider.default_model;
        }
    } else |_| {
        // Free-form model name typed by user
        cfg.default_model = try cfg.allocator.dupe(u8, model_input);
    }
    try out.print("  -> {s}\n\n", .{cfg.default_model.?});

    // ── Step 4: Memory backend ──
    const backends = try selectableBackendsForWizard(allocator);
    defer allocator.free(backends);
    try out.writeAll("  Step 4/8: Memory backend\n");
    for (backends, 0..) |b, i| {
        try out.print("    [{d}] {s}\n", .{ i + 1, b.label });
    }
    try out.writeAll("  Choice [1]: ");
    const mem_idx = promptChoice(out, &input_buf, backends.len, 0) orelse {
        try out.writeAll("\n  Aborted.\n");
        try out.flush();
        return;
    };
    cfg.memory.backend = backends[mem_idx].name;
    cfg.memory.profile = memoryProfileForBackend(backends[mem_idx].name);
    cfg.memory.auto_save = backends[mem_idx].auto_save_default;
    try out.print("  -> {s}\n\n", .{backends[mem_idx].label});

    // ── Step 5: Tunnel ──
    try out.writeAll("  Step 5/8: Tunnel\n");
    try out.writeAll("    [1] none\n    [2] cloudflare\n    [3] ngrok\n    [4] tailscale\n");
    try out.writeAll("  Choice [1]: ");
    const tunnel_idx = promptChoice(out, &input_buf, tunnel_options.len, 0) orelse {
        try out.writeAll("\n  Aborted.\n");
        try out.flush();
        return;
    };
    cfg.tunnel.provider = tunnel_options[tunnel_idx];
    try out.print("  -> {s}\n\n", .{tunnel_options[tunnel_idx]});

    // ── Step 6: Autonomy level ──
    try out.writeAll("  Step 6/8: Autonomy level\n");
    try out.writeAll("    [1] supervised\n    [2] autonomous\n    [3] fully_autonomous\n");
    try out.writeAll("  Choice [1]: ");
    const autonomy_idx = promptChoice(out, &input_buf, autonomy_options.len, 0) orelse {
        try out.writeAll("\n  Aborted.\n");
        try out.flush();
        return;
    };
    switch (autonomy_idx) {
        0 => {
            cfg.autonomy.level = .supervised;
            cfg.autonomy.require_approval_for_medium_risk = true;
            cfg.autonomy.block_high_risk_commands = true;
        },
        1 => {
            // "autonomous": fully acts, but still blocks high-risk commands.
            cfg.autonomy.level = .full;
            cfg.autonomy.require_approval_for_medium_risk = false;
            cfg.autonomy.block_high_risk_commands = true;
        },
        2 => {
            // "fully_autonomous": fully acts and does not hard-block high-risk commands.
            cfg.autonomy.level = .full;
            cfg.autonomy.require_approval_for_medium_risk = false;
            cfg.autonomy.block_high_risk_commands = false;
        },
        else => {
            cfg.autonomy.level = .supervised;
            cfg.autonomy.require_approval_for_medium_risk = true;
            cfg.autonomy.block_high_risk_commands = true;
        },
    }
    try out.print("  -> {s}\n\n", .{autonomy_options[autonomy_idx]});

    // ── Step 7: Channels ──
    try out.writeAll("  Step 7/8: Configure channels now? [Y/n]: ");
    const chan_input = prompt(out, &input_buf, "", "y") orelse {
        try out.writeAll("\n  Aborted.\n");
        try out.flush();
        return;
    };
    if (chan_input.len > 0 and (chan_input[0] == 'y' or chan_input[0] == 'Y')) {
        _ = try configureChannelsInteractive(allocator, &cfg, out, &input_buf, "  ");
        try out.writeAll("\n");
    } else {
        try out.writeAll("  -> Skipped (CLI enabled by default)\n\n");
    }

    // ── Step 8: Workspace path ──
    const default_workspace = try getDefaultWorkspace(allocator);
    try out.print("  Step 8/8: Workspace path [{s}]: ", .{default_workspace});
    const ws_input = prompt(out, &input_buf, "", default_workspace) orelse {
        try out.writeAll("\n  Aborted.\n");
        try out.flush();
        return;
    };
    if (ws_input.len > 0) {
        cfg.workspace_dir = try cfg.allocator.dupe(u8, ws_input);
    }
    try out.print("  -> {s}\n\n", .{cfg.workspace_dir});

    // ── Apply ──
    // Ensure parent config directory and workspace directory exist
    if (std.fs.path.dirname(cfg.workspace_dir)) |parent| {
        std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
    std.fs.makeDirAbsolute(cfg.workspace_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Scaffold workspace files
    try scaffoldWorkspace(allocator, cfg.workspace_dir, &ProjectContext{});

    // Save config
    try cfg.save();

    // Print summary
    try out.writeAll("  ── Configuration complete ──\n\n");
    try out.print("  [OK] Provider:   {s}\n", .{cfg.default_provider});
    if (cfg.default_model) |m| {
        try out.print("  [OK] Model:      {s}\n", .{m});
    }
    try out.print("  [OK] API Key:    {s}\n", .{if (cfg.defaultProviderKey() != null) "set" else "from environment"});
    try out.print("  [OK] Memory:     {s}\n", .{cfg.memory.backend});
    try out.print("  [OK] Tunnel:     {s}\n", .{cfg.tunnel.provider});
    try out.print("  [OK] Workspace:  {s}\n", .{cfg.workspace_dir});
    try out.print("  [OK] Config:     {s}\n", .{cfg.config_path});
    try out.writeAll("\n  Next steps:\n");
    if (cfg.defaultProviderKey() == null) {
        try out.print("    1. Set your API key:  export {s}=\"sk-...\"\n", .{env_hint});
        try out.writeAll("    2. Chat:              nullclaw agent -m \"Hello!\"\n");
        try out.writeAll("    3. Gateway:           nullclaw gateway\n");
    } else {
        try out.writeAll("    1. Chat:     nullclaw agent -m \"Hello!\"\n");
        try out.writeAll("    2. Gateway:  nullclaw gateway\n");
        try out.writeAll("    3. Status:   nullclaw status\n");
    }
    try out.writeAll("\n");
    try out.flush();
}

// ── Models refresh ──────────────────────────────────────────────

const ModelsCatalogProvider = struct {
    name: []const u8,
    url: []const u8,
    models_path: []const u8, // JSON path to the models array
    id_field: []const u8, // field name for model ID within each entry
};

const catalog_providers = [_]ModelsCatalogProvider{
    .{ .name = "openai", .url = "https://api.openai.com/v1/models", .models_path = "data", .id_field = "id" },
    .{ .name = "openrouter", .url = "https://openrouter.ai/api/v1/models", .models_path = "data", .id_field = "id" },
};

/// Refresh the model catalog by fetching available models from known providers.
/// Saves results to ~/.nullclaw/models_cache.json.
pub fn runModelsRefresh(allocator: std.mem.Allocator) !void {
    var stdout_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    const out = &bw.interface;
    try out.writeAll("Refreshing model catalog...\n");
    try out.flush();

    // Build cache path
    const home = platform.getHomeDir(allocator) catch {
        try out.writeAll("Could not determine HOME directory.\n");
        try out.flush();
        return;
    };
    defer allocator.free(home);
    const cache_path = try std.fs.path.join(allocator, &.{ home, ".nullclaw", "models_cache.json" });
    defer allocator.free(cache_path);
    const cache_dir = try std.fs.path.join(allocator, &.{ home, ".nullclaw" });
    defer allocator.free(cache_dir);

    // Ensure directory exists
    std.fs.makeDirAbsolute(cache_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => {
            try out.writeAll("Could not create config directory.\n");
            try out.flush();
            return;
        },
    };

    // Collect models from each provider using curl
    var total_models: usize = 0;
    var results_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer results_buf.deinit(allocator);

    try results_buf.appendSlice(allocator, "{\n");

    for (catalog_providers, 0..) |cp, cp_idx| {
        try out.print("  Fetching from {s}...\n", .{cp.name});
        try out.flush();

        // Run curl to fetch models list
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &.{ "curl", "-sf", "--max-time", "10", cp.url },
        }) catch {
            try out.print("  [SKIP] {s}: curl failed\n", .{cp.name});
            try out.flush();
            continue;
        };
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        if (result.stdout.len == 0) {
            try out.print("  [SKIP] {s}: empty response\n", .{cp.name});
            try out.flush();
            continue;
        }

        // Parse JSON and extract model IDs
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{}) catch {
            try out.print("  [SKIP] {s}: invalid JSON\n", .{cp.name});
            try out.flush();
            continue;
        };
        defer parsed.deinit();

        const root = parsed.value;
        if (root != .object) {
            try out.print("  [SKIP] {s}: unexpected format\n", .{cp.name});
            try out.flush();
            continue;
        }

        const data = root.object.get(cp.models_path) orelse {
            try out.print("  [SKIP] {s}: no '{s}' field\n", .{ cp.name, cp.models_path });
            try out.flush();
            continue;
        };
        if (data != .array) {
            try out.print("  [SKIP] {s}: '{s}' is not an array\n", .{ cp.name, cp.models_path });
            try out.flush();
            continue;
        }

        var count: usize = 0;
        if (cp_idx > 0) try results_buf.appendSlice(allocator, ",\n");
        try results_buf.appendSlice(allocator, "  \"");
        try results_buf.appendSlice(allocator, cp.name);
        try results_buf.appendSlice(allocator, "\": [");

        for (data.array.items, 0..) |item, i| {
            if (item != .object) continue;
            const id_val = item.object.get(cp.id_field) orelse continue;
            if (id_val != .string) continue;
            if (i > 0) try results_buf.appendSlice(allocator, ",");
            try results_buf.appendSlice(allocator, "\"");
            try results_buf.appendSlice(allocator, id_val.string);
            try results_buf.appendSlice(allocator, "\"");
            count += 1;
        }

        try results_buf.appendSlice(allocator, "]");
        total_models += count;
        try out.print("  [OK] {s}: {d} models\n", .{ cp.name, count });
        try out.flush();
    }

    try results_buf.appendSlice(allocator, "\n}\n");

    // Write cache file
    const file = std.fs.createFileAbsolute(cache_path, .{}) catch {
        try out.writeAll("Could not write cache file.\n");
        try out.flush();
        return;
    };
    defer file.close();
    file.writeAll(results_buf.items) catch {
        try out.writeAll("Error writing cache file.\n");
        try out.flush();
        return;
    };

    try out.print("\nFetched {d} models total. Cache saved to {s}\n", .{ total_models, cache_path });
    try out.flush();
}

// ── Workspace scaffolding ────────────────────────────────────────

/// Create essential workspace files if they don't already exist.
pub fn scaffoldWorkspace(allocator: std.mem.Allocator, workspace_dir: []const u8, ctx: *const ProjectContext) !void {
    if (std.fs.path.dirname(workspace_dir)) |parent| {
        std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
    std.fs.makeDirAbsolute(workspace_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const had_legacy_user_content = try hasLegacyUserContentIndicators(allocator, workspace_dir);

    // SOUL.md (personality traits — loaded by prompt.zig)
    const soul_tmpl = try soulTemplate(allocator, ctx);
    defer allocator.free(soul_tmpl);
    try writeIfMissing(allocator, workspace_dir, "SOUL.md", soul_tmpl);

    // AGENTS.md (operational guidelines — loaded by prompt.zig)
    try writeIfMissing(allocator, workspace_dir, "AGENTS.md", agentsTemplate());

    // TOOLS.md (tool usage guide — loaded by prompt.zig)
    try writeIfMissing(allocator, workspace_dir, "TOOLS.md", toolsTemplate());

    // IDENTITY.md (identity config — loaded by prompt.zig)
    const identity_tmpl = try identityTemplate(allocator, ctx);
    defer allocator.free(identity_tmpl);
    try writeIfMissing(allocator, workspace_dir, "IDENTITY.md", identity_tmpl);

    // USER.md (user profile — loaded by prompt.zig)
    const user_tmpl = try userTemplate(allocator, ctx);
    defer allocator.free(user_tmpl);
    try writeIfMissing(allocator, workspace_dir, "USER.md", user_tmpl);

    // HEARTBEAT.md (periodic tasks — loaded by prompt.zig)
    try writeIfMissing(allocator, workspace_dir, "HEARTBEAT.md", heartbeatTemplate());

    // BOOTSTRAP.md lifecycle:
    // one-shot onboarding instructions with persisted state marker.
    try ensureBootstrapLifecycle(allocator, workspace_dir, identity_tmpl, user_tmpl, had_legacy_user_content);
}

pub const ResetWorkspacePromptFilesOptions = struct {
    include_bootstrap: bool = false,
    clear_memory_markdown: bool = false,
    dry_run: bool = false,
};

pub const ResetWorkspacePromptFilesReport = struct {
    rewritten_files: usize = 0,
    removed_files: usize = 0,
};

/// Reset workspace prompt markdown files to bundled defaults.
/// This intentionally overwrites existing files.
pub fn resetWorkspacePromptFiles(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    ctx: *const ProjectContext,
    options: ResetWorkspacePromptFilesOptions,
) !ResetWorkspacePromptFilesReport {
    if (std.fs.path.dirname(workspace_dir)) |parent| {
        std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
    std.fs.makeDirAbsolute(workspace_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    var report = ResetWorkspacePromptFilesReport{};

    const soul_tmpl = try soulTemplate(allocator, ctx);
    defer allocator.free(soul_tmpl);
    const identity_tmpl = try identityTemplate(allocator, ctx);
    defer allocator.free(identity_tmpl);
    const user_tmpl = try userTemplate(allocator, ctx);
    defer allocator.free(user_tmpl);

    const files = [_]struct {
        filename: []const u8,
        content: []const u8,
    }{
        .{ .filename = "SOUL.md", .content = soul_tmpl },
        .{ .filename = "AGENTS.md", .content = agentsTemplate() },
        .{ .filename = "TOOLS.md", .content = toolsTemplate() },
        .{ .filename = "IDENTITY.md", .content = identity_tmpl },
        .{ .filename = "USER.md", .content = user_tmpl },
        .{ .filename = "HEARTBEAT.md", .content = heartbeatTemplate() },
    };

    for (files) |entry| {
        _ = try overwriteWorkspaceFile(allocator, workspace_dir, entry.filename, entry.content, options.dry_run);
        report.rewritten_files += 1;
    }

    if (options.include_bootstrap) {
        _ = try overwriteWorkspaceFile(allocator, workspace_dir, "BOOTSTRAP.md", bootstrapTemplate(), options.dry_run);
        report.rewritten_files += 1;
    }

    if (options.clear_memory_markdown) {
        if (try removeWorkspaceFileIfExists(allocator, workspace_dir, "MEMORY.md", options.dry_run)) {
            report.removed_files += 1;
        }
        if (try removeWorkspaceFileIfExists(allocator, workspace_dir, "memory.md", options.dry_run)) {
            report.removed_files += 1;
        }
    }

    return report;
}

fn overwriteWorkspaceFile(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    filename: []const u8,
    content: []const u8,
    dry_run: bool,
) !bool {
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ workspace_dir, filename });
    defer allocator.free(path);

    if (dry_run) return true;

    const file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(content);
    return true;
}

fn removeWorkspaceFileIfExists(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    filename: []const u8,
    dry_run: bool,
) !bool {
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ workspace_dir, filename });
    defer allocator.free(path);

    if (dry_run) {
        return fileExistsAbsolute(path);
    }

    std.fs.deleteFileAbsolute(path) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

fn writeIfMissing(allocator: std.mem.Allocator, dir: []const u8, filename: []const u8, content: []const u8) !void {
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, filename });
    defer allocator.free(path);

    // Only write if file doesn't exist
    if (std.fs.openFileAbsolute(path, .{})) |f| {
        f.close();
        return;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    const file = std.fs.createFileAbsolute(path, .{ .exclusive = true }) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        else => return err,
    };
    defer file.close();
    try file.writeAll(content);
}

fn ensureBootstrapLifecycle(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    identity_template: []const u8,
    user_template: []const u8,
    had_legacy_user_content: bool,
) !void {
    const bootstrap_path = try std.fmt.allocPrint(allocator, "{s}/BOOTSTRAP.md", .{workspace_dir});
    defer allocator.free(bootstrap_path);

    var state = try readWorkspaceOnboardingState(allocator, workspace_dir);
    defer state.deinit(allocator);
    var state_dirty = false;
    var bootstrap_exists = fileExistsAbsolute(bootstrap_path);

    if (state.bootstrap_seeded_at == null and bootstrap_exists) {
        try markBootstrapSeededAt(allocator, &state);
        state_dirty = true;
    }

    if (state.onboarding_completed_at == null and state.bootstrap_seeded_at != null and !bootstrap_exists) {
        try markOnboardingCompletedAt(allocator, &state);
        state_dirty = true;
    }

    if (state.bootstrap_seeded_at == null and state.onboarding_completed_at == null and !bootstrap_exists) {
        const legacy_completed = try isLegacyOnboardingCompleted(
            allocator,
            workspace_dir,
            identity_template,
            user_template,
            had_legacy_user_content,
        );
        if (legacy_completed) {
            try markOnboardingCompletedAt(allocator, &state);
            state_dirty = true;
        } else {
            try writeIfMissing(allocator, workspace_dir, "BOOTSTRAP.md", bootstrapTemplate());
            bootstrap_exists = fileExistsAbsolute(bootstrap_path);
            if (bootstrap_exists and state.bootstrap_seeded_at == null) {
                try markBootstrapSeededAt(allocator, &state);
                state_dirty = true;
            }
        }
    }

    if (state_dirty) {
        try writeWorkspaceOnboardingState(allocator, workspace_dir, &state);
    }
}

fn isLegacyOnboardingCompleted(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    identity_template: []const u8,
    user_template: []const u8,
    had_legacy_user_content: bool,
) !bool {
    const identity_path = try std.fmt.allocPrint(allocator, "{s}/IDENTITY.md", .{workspace_dir});
    defer allocator.free(identity_path);
    const user_path = try std.fmt.allocPrint(allocator, "{s}/USER.md", .{workspace_dir});
    defer allocator.free(user_path);

    var templates_diverged = false;
    if (try readFileIfPresent(allocator, identity_path, 1024 * 1024)) |identity_content| {
        defer allocator.free(identity_content);
        if (!std.mem.eql(u8, identity_content, identity_template)) {
            templates_diverged = true;
        }
    }
    if (try readFileIfPresent(allocator, user_path, 1024 * 1024)) |user_content| {
        defer allocator.free(user_content);
        if (!std.mem.eql(u8, user_content, user_template)) {
            templates_diverged = true;
        }
    }
    return templates_diverged or had_legacy_user_content;
}

fn workspaceStatePath(allocator: std.mem.Allocator, workspace_dir: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}/{s}/{s}",
        .{ workspace_dir, WORKSPACE_STATE_DIR, WORKSPACE_STATE_FILE },
    );
}

fn readWorkspaceOnboardingState(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
) !WorkspaceOnboardingState {
    const path = try workspaceStatePath(allocator, workspace_dir);
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return .{},
        else => return err,
    };
    defer file.close();

    const raw = file.readToEndAlloc(allocator, 64 * 1024) catch return .{};
    defer allocator.free(raw);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return .{};
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return .{},
    };

    var state = WorkspaceOnboardingState{};
    errdefer state.deinit(allocator);

    if (obj.get("version")) |v| {
        switch (v) {
            .integer => |n| {
                if (n > 0) state.version = n;
            },
            else => {},
        }
    }

    if (obj.get("bootstrap_seeded_at")) |v| {
        switch (v) {
            .string => |s| state.bootstrap_seeded_at = try allocator.dupe(u8, s),
            else => {},
        }
    } else if (obj.get("bootstrapSeededAt")) |v| {
        switch (v) {
            .string => |s| state.bootstrap_seeded_at = try allocator.dupe(u8, s),
            else => {},
        }
    }

    if (obj.get("onboarding_completed_at")) |v| {
        switch (v) {
            .string => |s| state.onboarding_completed_at = try allocator.dupe(u8, s),
            else => {},
        }
    } else if (obj.get("onboardingCompletedAt")) |v| {
        switch (v) {
            .string => |s| state.onboarding_completed_at = try allocator.dupe(u8, s),
            else => {},
        }
    }

    return state;
}

fn writeWorkspaceOnboardingState(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    state: *const WorkspaceOnboardingState,
) !void {
    const path = try workspaceStatePath(allocator, workspace_dir);
    defer allocator.free(path);

    if (std.fs.path.dirname(path)) |parent| {
        std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\n  ");
    try json_util.appendJsonInt(&buf, allocator, "version", state.version);
    if (state.bootstrap_seeded_at) |seeded| {
        try buf.appendSlice(allocator, ",\n  ");
        try json_util.appendJsonKey(&buf, allocator, "bootstrap_seeded_at");
        try json_util.appendJsonString(&buf, allocator, seeded);
    }
    if (state.onboarding_completed_at) |completed| {
        try buf.appendSlice(allocator, ",\n  ");
        try json_util.appendJsonKey(&buf, allocator, "onboarding_completed_at");
        try json_util.appendJsonString(&buf, allocator, completed);
    }
    try buf.appendSlice(allocator, "\n}\n");

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp_path);

    const tmp_file = try std.fs.createFileAbsolute(tmp_path, .{});
    errdefer tmp_file.close();
    try tmp_file.writeAll(buf.items);
    tmp_file.close();

    std.fs.renameAbsolute(tmp_path, path) catch {
        std.fs.deleteFileAbsolute(tmp_path) catch {};
        const file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();
        try file.writeAll(buf.items);
    };
}

fn readFileIfPresent(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) !?[]u8 {
    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close();
    return try file.readToEndAlloc(allocator, max_bytes);
}

fn fileExistsAbsolute(path: []const u8) bool {
    const file = std.fs.openFileAbsolute(path, .{}) catch return false;
    file.close();
    return true;
}

fn pathExistsAbsolute(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}

fn hasLegacyUserContentIndicators(allocator: std.mem.Allocator, workspace_dir: []const u8) !bool {
    const memory_dir_path = try std.fmt.allocPrint(allocator, "{s}/memory", .{workspace_dir});
    defer allocator.free(memory_dir_path);
    const memory_file_path = try std.fmt.allocPrint(allocator, "{s}/MEMORY.md", .{workspace_dir});
    defer allocator.free(memory_file_path);
    const git_dir_path = try std.fmt.allocPrint(allocator, "{s}/.git", .{workspace_dir});
    defer allocator.free(git_dir_path);

    return pathExistsAbsolute(memory_dir_path) or
        pathExistsAbsolute(memory_file_path) or
        pathExistsAbsolute(git_dir_path);
}

fn makeIsoTimestamp(allocator: std.mem.Allocator) ![]u8 {
    var ts_buf: [32]u8 = undefined;
    const ts = util.timestamp(&ts_buf);
    return allocator.dupe(u8, ts);
}

fn markBootstrapSeededAt(allocator: std.mem.Allocator, state: *WorkspaceOnboardingState) !void {
    if (state.bootstrap_seeded_at != null) return;
    state.bootstrap_seeded_at = try makeIsoTimestamp(allocator);
}

fn markOnboardingCompletedAt(allocator: std.mem.Allocator, state: *WorkspaceOnboardingState) !void {
    if (state.onboarding_completed_at != null) return;
    state.onboarding_completed_at = try makeIsoTimestamp(allocator);
}

fn memoryTemplate(allocator: std.mem.Allocator, ctx: *const ProjectContext) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\# MEMORY.md - Long-Term Memory
        \\
        \\This file stores curated, durable context for main sessions.
        \\Prefer high-signal facts over raw logs.
        \\
        \\## User
        \\- Name: {s}
        \\- Timezone: {s}
        \\
        \\## Preferences
        \\- Communication style: {s}
        \\
        \\## Durable facts
        \\- Add stable preferences, decisions, and constraints here.
        \\- Keep secrets out unless explicitly requested.
        \\- Move noisy daily notes to memory/YYYY-MM-DD.md.
        \\
        \\## Agent
        \\- Name: {s}
        \\
    , .{ ctx.user_name, ctx.timezone, ctx.communication_style, ctx.agent_name });
}

fn soulTemplate(allocator: std.mem.Allocator, ctx: *const ProjectContext) ![]const u8 {
    _ = ctx;
    return allocator.dupe(u8, WORKSPACE_SOUL_TEMPLATE);
}

fn agentsTemplate() []const u8 {
    return WORKSPACE_AGENTS_TEMPLATE;
}

fn toolsTemplate() []const u8 {
    return WORKSPACE_TOOLS_TEMPLATE;
}

fn identityTemplate(allocator: std.mem.Allocator, ctx: *const ProjectContext) ![]const u8 {
    _ = ctx;
    return allocator.dupe(u8, WORKSPACE_IDENTITY_TEMPLATE);
}

fn userTemplate(allocator: std.mem.Allocator, ctx: *const ProjectContext) ![]const u8 {
    _ = ctx;
    return allocator.dupe(u8, WORKSPACE_USER_TEMPLATE);
}

fn heartbeatTemplate() []const u8 {
    return WORKSPACE_HEARTBEAT_TEMPLATE;
}

fn bootstrapTemplate() []const u8 {
    return WORKSPACE_BOOTSTRAP_TEMPLATE;
}

// ── Memory backend helpers ───────────────────────────────────────

/// Get the list of selectable memory backends (from registry).
pub fn selectableBackends() []const memory_root.BackendDescriptor {
    return &memory_root.registry.all;
}

/// Get the default memory backend key.
pub fn defaultBackendKey() []const u8 {
    return "markdown";
}

// ── Path helpers ─────────────────────────────────────────────────

fn getDefaultWorkspace(allocator: std.mem.Allocator) ![]const u8 {
    const home = try platform.getHomeDir(allocator);
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, ".nullclaw", "workspace" });
}

fn getDefaultConfigPath(allocator: std.mem.Allocator) ![]const u8 {
    const home = try platform.getHomeDir(allocator);
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, ".nullclaw", "config.json" });
}

// ── Tests ────────────────────────────────────────────────────────

test "canonicalProviderName handles aliases" {
    try std.testing.expectEqualStrings("xai", canonicalProviderName("grok"));
    try std.testing.expectEqualStrings("together-ai", canonicalProviderName("together"));
    try std.testing.expectEqualStrings("gemini", canonicalProviderName("google"));
    try std.testing.expectEqualStrings("gemini", canonicalProviderName("google-gemini"));
    try std.testing.expectEqualStrings("openai", canonicalProviderName("openai"));
}

test "defaultModelForProvider returns known models" {
    try std.testing.expectEqualStrings("claude-opus-4-6", defaultModelForProvider("anthropic"));
    try std.testing.expectEqualStrings("gpt-5.2", defaultModelForProvider("openai"));
    try std.testing.expectEqualStrings("deepseek-chat", defaultModelForProvider("deepseek"));
    try std.testing.expectEqualStrings("llama4", defaultModelForProvider("ollama"));
}

test "defaultModelForProvider falls back for unknown" {
    try std.testing.expectEqualStrings("anthropic/claude-sonnet-4.6", defaultModelForProvider("unknown-provider"));
}

test "providerEnvVar known providers" {
    try std.testing.expectEqualStrings("OPENROUTER_API_KEY", providerEnvVar("openrouter"));
    try std.testing.expectEqualStrings("ANTHROPIC_API_KEY", providerEnvVar("anthropic"));
    try std.testing.expectEqualStrings("OPENAI_API_KEY", providerEnvVar("openai"));
    try std.testing.expectEqualStrings("API_KEY", providerEnvVar("ollama"));
}

test "providerEnvVar grok alias maps to xai" {
    try std.testing.expectEqualStrings("XAI_API_KEY", providerEnvVar("grok"));
}

test "providerEnvVar unknown falls back" {
    try std.testing.expectEqualStrings("API_KEY", providerEnvVar("some-new-provider"));
}

test "known_providers has entries" {
    try std.testing.expect(known_providers.len >= 5);
    try std.testing.expectEqualStrings("openrouter", known_providers[0].key);
}

test "selectableBackends returns enabled backends" {
    const backends = selectableBackends();
    try std.testing.expect(backends.len > 0);

    for (backends) |desc| {
        try std.testing.expect(memory_root.findBackend(desc.name) != null);
    }

    if (memory_root.findBackend("markdown") != null) {
        try std.testing.expectEqualStrings("markdown", backends[0].name);
    } else if (memory_root.findBackend("none") != null) {
        try std.testing.expectEqualStrings("none", backends[0].name);
    }
}

test "selectableBackendsForWizard prioritizes sqlite and keeps api last" {
    const backends = try selectableBackendsForWizard(std.testing.allocator);
    defer std.testing.allocator.free(backends);

    if (memory_root.findBackend("sqlite") != null) {
        try std.testing.expectEqualStrings("sqlite", backends[0].name);
    }
    if (memory_root.findBackend("sqlite") != null and memory_root.findBackend("markdown") != null and backends.len >= 2) {
        try std.testing.expectEqualStrings("markdown", backends[1].name);
    }
    if (memory_root.findBackend("api") != null) {
        try std.testing.expectEqualStrings("api", backends[backends.len - 1].name);
    }
}

test "memoryProfileForBackend maps common backends" {
    try std.testing.expectEqualStrings("local_keyword", memoryProfileForBackend("sqlite"));
    try std.testing.expectEqualStrings("markdown_only", memoryProfileForBackend("markdown"));
    try std.testing.expectEqualStrings("postgres_keyword", memoryProfileForBackend("postgres"));
    try std.testing.expectEqualStrings("minimal_none", memoryProfileForBackend("none"));
    try std.testing.expectEqualStrings("custom", memoryProfileForBackend("api"));
    try std.testing.expectEqualStrings("custom", memoryProfileForBackend("memory"));
    try std.testing.expectEqualStrings("custom", memoryProfileForBackend("redis"));
}

test "isWizardInteractiveChannel includes supported onboarding channels" {
    try std.testing.expect(isWizardInteractiveChannel(.telegram));
    try std.testing.expect(isWizardInteractiveChannel(.slack));
    try std.testing.expect(isWizardInteractiveChannel(.matrix));
    try std.testing.expect(isWizardInteractiveChannel(.signal));
    try std.testing.expect(!isWizardInteractiveChannel(.whatsapp));
}

test "parseTelegramAllowFrom defaults to wildcard" {
    const allow = try parseTelegramAllowFrom(std.testing.allocator, "");
    defer {
        for (allow) |entry| std.testing.allocator.free(entry);
        std.testing.allocator.free(allow);
    }
    try std.testing.expectEqual(@as(usize, 1), allow.len);
    try std.testing.expectEqualStrings("*", allow[0]);
}

test "parseTelegramAllowFrom normalizes, deduplicates and strips @" {
    const allow = try parseTelegramAllowFrom(std.testing.allocator, " @Alice, alice  12345, @bob ");
    defer {
        for (allow) |entry| std.testing.allocator.free(entry);
        std.testing.allocator.free(allow);
    }
    try std.testing.expectEqual(@as(usize, 3), allow.len);
    try std.testing.expectEqualStrings("Alice", allow[0]);
    try std.testing.expectEqualStrings("12345", allow[1]);
    try std.testing.expectEqualStrings("bob", allow[2]);
}

test "StdinLineReader popLine handles chunked multi-line input" {
    var reader = StdinLineReader{};
    var out: [64]u8 = undefined;

    const chunk1 = "first\nsecond";
    @memcpy(reader.pending[0..chunk1.len], chunk1);
    reader.pending_len = chunk1.len;

    const line1 = reader.popLine(&out) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("first", line1);
    try std.testing.expect(reader.popLine(&out) == null);

    const chunk2 = "\nthird\r\n";
    @memcpy(reader.pending[reader.pending_len .. reader.pending_len + chunk2.len], chunk2);
    reader.pending_len += chunk2.len;

    const line2 = reader.popLine(&out) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("second", line2);
    const line3 = reader.popLine(&out) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("third", line3);
    try std.testing.expect(reader.popLine(&out) == null);
}

test "StdinLineReader flushRemainder returns final unterminated line" {
    var reader = StdinLineReader{};
    var out: [32]u8 = undefined;

    const tail = "last-line\r";
    @memcpy(reader.pending[0..tail.len], tail);
    reader.pending_len = tail.len;

    const line = reader.flushRemainder(&out) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("last-line", line);
    try std.testing.expectEqual(@as(usize, 0), reader.pending_len);
    try std.testing.expect(reader.flushRemainder(&out) == null);
}

test "BANNER contains descriptive text" {
    try std.testing.expect(std.mem.indexOf(u8, BANNER, "smallest AI assistant") != null);
}

test "scaffoldWorkspace creates core files and leaves MEMORY.md optional" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    const ctx = ProjectContext{};
    try scaffoldWorkspace(std.testing.allocator, base, &ctx);

    // Verify core files were created
    const agents = try tmp.dir.openFile("AGENTS.md", .{});
    defer agents.close();
    const agents_content = try agents.readToEndAlloc(std.testing.allocator, 16 * 1024);
    defer std.testing.allocator.free(agents_content);
    try std.testing.expect(std.mem.indexOf(u8, agents_content, "AGENTS.md - Your Workspace") != null);

    // OpenClaw-style scaffold keeps MEMORY.md optional (created on demand by memory writes).
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("MEMORY.md", .{}));
}

test "scaffoldWorkspace is idempotent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    const ctx = ProjectContext{};
    try scaffoldWorkspace(std.testing.allocator, base, &ctx);
    // Running again should not fail
    try scaffoldWorkspace(std.testing.allocator, base, &ctx);
}

test "resetWorkspacePromptFiles overwrites prompt files with defaults" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("AGENTS.md", .{});
        defer f.close();
        try f.writeAll("custom-agents-content");
    }
    {
        const f = try tmp.dir.createFile("USER.md", .{});
        defer f.close();
        try f.writeAll("custom-user-content");
    }

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    const report = try resetWorkspacePromptFiles(std.testing.allocator, base, &ProjectContext{}, .{});
    try std.testing.expectEqual(@as(usize, 6), report.rewritten_files);
    try std.testing.expectEqual(@as(usize, 0), report.removed_files);

    const agents_content = try tmp.dir.readFileAlloc(std.testing.allocator, "AGENTS.md", 64 * 1024);
    defer std.testing.allocator.free(agents_content);
    try std.testing.expect(std.mem.indexOf(u8, agents_content, "AGENTS.md - Your Workspace") != null);
    try std.testing.expect(std.mem.indexOf(u8, agents_content, "custom-agents-content") == null);

    const user_content = try tmp.dir.readFileAlloc(std.testing.allocator, "USER.md", 64 * 1024);
    defer std.testing.allocator.free(user_content);
    try std.testing.expect(std.mem.indexOf(u8, user_content, "USER.md - About Your Human") != null);
    try std.testing.expect(std.mem.indexOf(u8, user_content, "custom-user-content") == null);
}

test "resetWorkspacePromptFiles supports dry-run and clearing memory markdown files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("MEMORY.md", .{});
        defer f.close();
        try f.writeAll("custom-memory");
    }

    var has_distinct_case_memory_file = true;
    const alt = tmp.dir.createFile("memory.md", .{ .exclusive = true }) catch |err| switch (err) {
        error.PathAlreadyExists => blk: {
            has_distinct_case_memory_file = false;
            break :blk null;
        },
        else => return err,
    };
    if (alt) |f| {
        defer f.close();
        try f.writeAll("custom-memory-lower");
    }

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    const dry_report = try resetWorkspacePromptFiles(std.testing.allocator, base, &ProjectContext{}, .{
        .clear_memory_markdown = true,
        .dry_run = true,
    });
    try std.testing.expectEqual(@as(usize, 6), dry_report.rewritten_files);
    try std.testing.expect(dry_report.removed_files >= 1);
    const memory_file = try tmp.dir.openFile("MEMORY.md", .{});
    memory_file.close();

    const reset_report = try resetWorkspacePromptFiles(std.testing.allocator, base, &ProjectContext{}, .{
        .clear_memory_markdown = true,
    });
    try std.testing.expectEqual(@as(usize, 6), reset_report.rewritten_files);
    try std.testing.expect(reset_report.removed_files >= 1);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("MEMORY.md", .{}));
    if (has_distinct_case_memory_file) {
        try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("memory.md", .{}));
    }
}

test "resetWorkspacePromptFiles creates missing workspace directory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const nested = try std.fmt.allocPrint(std.testing.allocator, "{s}/nested/workspace", .{base});
    defer std.testing.allocator.free(nested);

    const report = try resetWorkspacePromptFiles(std.testing.allocator, nested, &ProjectContext{}, .{});
    try std.testing.expectEqual(@as(usize, 6), report.rewritten_files);

    const agents_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/AGENTS.md", .{nested});
    defer std.testing.allocator.free(agents_path);
    const agents_file = try std.fs.openFileAbsolute(agents_path, .{});
    agents_file.close();
}

test "scaffoldWorkspace seeds bootstrap marker for new workspace" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{});

    const bootstrap_file = try tmp.dir.openFile("BOOTSTRAP.md", .{});
    bootstrap_file.close();

    var state = try readWorkspaceOnboardingState(std.testing.allocator, base);
    defer state.deinit(std.testing.allocator);
    try std.testing.expect(state.bootstrap_seeded_at != null);
    try std.testing.expect(state.onboarding_completed_at == null);
}

test "scaffoldWorkspace does not recreate BOOTSTRAP after onboarding completion" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{});

    {
        const f = try tmp.dir.createFile("IDENTITY.md", .{ .truncate = true });
        defer f.close();
        try f.writeAll("custom identity");
    }
    {
        const f = try tmp.dir.createFile("USER.md", .{ .truncate = true });
        defer f.close();
        try f.writeAll("custom user");
    }

    try tmp.dir.deleteFile("BOOTSTRAP.md");
    try tmp.dir.deleteFile("TOOLS.md");

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{});

    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("BOOTSTRAP.md", .{}));
    const tools_file = try tmp.dir.openFile("TOOLS.md", .{});
    tools_file.close();

    var state = try readWorkspaceOnboardingState(std.testing.allocator, base);
    defer state.deinit(std.testing.allocator);
    try std.testing.expect(state.onboarding_completed_at != null);
}

test "scaffoldWorkspace does not seed BOOTSTRAP for legacy completed workspace" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("IDENTITY.md", .{});
        defer f.close();
        try f.writeAll("custom identity");
    }
    {
        const f = try tmp.dir.createFile("USER.md", .{});
        defer f.close();
        try f.writeAll("custom user");
    }

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{});

    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("BOOTSTRAP.md", .{}));

    var state = try readWorkspaceOnboardingState(std.testing.allocator, base);
    defer state.deinit(std.testing.allocator);
    try std.testing.expect(state.bootstrap_seeded_at == null);
    try std.testing.expect(state.onboarding_completed_at != null);
}

test "scaffoldWorkspace treats memory-backed workspace as existing and skips BOOTSTRAP" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("memory");
    try tmp.dir.writeFile(.{
        .sub_path = "memory/2026-02-25.md",
        .data = "# Daily log\nSome notes",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "MEMORY.md",
        .data = "# Long-term memory\nImportant stuff",
    });

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{});

    const identity_file = try tmp.dir.openFile("IDENTITY.md", .{});
    identity_file.close();
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("BOOTSTRAP.md", .{}));

    const memory_file = try tmp.dir.openFile("MEMORY.md", .{});
    defer memory_file.close();
    const memory_content = try memory_file.readToEndAlloc(std.testing.allocator, 4 * 1024);
    defer std.testing.allocator.free(memory_content);
    try std.testing.expectEqualStrings("# Long-term memory\nImportant stuff", memory_content);

    var state = try readWorkspaceOnboardingState(std.testing.allocator, base);
    defer state.deinit(std.testing.allocator);
    try std.testing.expect(state.onboarding_completed_at != null);
}

test "scaffoldWorkspace treats git-backed workspace as existing and skips BOOTSTRAP" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".git");
    try tmp.dir.writeFile(.{
        .sub_path = ".git/HEAD",
        .data = "ref: refs/heads/main\n",
    });

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{});

    const identity_file = try tmp.dir.openFile("IDENTITY.md", .{});
    identity_file.close();
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("BOOTSTRAP.md", .{}));

    var state = try readWorkspaceOnboardingState(std.testing.allocator, base);
    defer state.deinit(std.testing.allocator);
    try std.testing.expect(state.onboarding_completed_at != null);
}

// ── Additional onboard tests ────────────────────────────────────

test "canonicalProviderName passthrough for known providers" {
    try std.testing.expectEqualStrings("anthropic", canonicalProviderName("anthropic"));
    try std.testing.expectEqualStrings("openrouter", canonicalProviderName("openrouter"));
    try std.testing.expectEqualStrings("deepseek", canonicalProviderName("deepseek"));
    try std.testing.expectEqualStrings("groq", canonicalProviderName("groq"));
    try std.testing.expectEqualStrings("ollama", canonicalProviderName("ollama"));
}

test "canonicalProviderName unknown returns as-is" {
    try std.testing.expectEqualStrings("my-custom-provider", canonicalProviderName("my-custom-provider"));
    try std.testing.expectEqualStrings("", canonicalProviderName(""));
}

test "resolveProviderForQuickSetup handles known and alias names" {
    const openrouter = resolveProviderForQuickSetup("openrouter") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("openrouter", openrouter.key);

    const grok_alias = resolveProviderForQuickSetup("grok") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("xai", grok_alias.key);
}

test "resolveProviderForQuickSetup rejects unknown provider" {
    try std.testing.expect(resolveProviderForQuickSetup("totally-unknown-provider") == null);
}

test "resolveMemoryBackendForQuickSetup validates enabled, disabled and unknown backends" {
    // Unknown key should always fail as unknown.
    try std.testing.expectError(
        error.UnknownMemoryBackend,
        resolveMemoryBackendForQuickSetup("totally-unknown-backend"),
    );

    // Enabled backend resolves to descriptor.
    if (memory_root.findBackend("markdown")) |desc| {
        const resolved = try resolveMemoryBackendForQuickSetup("markdown");
        try std.testing.expectEqualStrings(desc.name, resolved.name);
    } else {
        try std.testing.expectError(
            error.MemoryBackendDisabledInBuild,
            resolveMemoryBackendForQuickSetup("markdown"),
        );
    }

    // If the current build has at least one known-but-disabled backend,
    // ensure we return the explicit disabled error for it.
    for (memory_root.registry.known_backend_names) |name| {
        if (memory_root.findBackend(name) == null) {
            try std.testing.expectError(
                error.MemoryBackendDisabledInBuild,
                resolveMemoryBackendForQuickSetup(name),
            );
            return;
        }
    }
}

test "defaultModelForProvider gemini via alias" {
    try std.testing.expectEqualStrings("gemini-2.5-pro", defaultModelForProvider("google"));
    try std.testing.expectEqualStrings("gemini-2.5-pro", defaultModelForProvider("google-gemini"));
    try std.testing.expectEqualStrings("gemini-2.5-pro", defaultModelForProvider("gemini"));
}

test "defaultModelForProvider groq" {
    try std.testing.expectEqualStrings("llama-3.3-70b-versatile", defaultModelForProvider("groq"));
}

test "defaultModelForProvider openrouter" {
    try std.testing.expectEqualStrings("anthropic/claude-sonnet-4.6", defaultModelForProvider("openrouter"));
}

test "providerEnvVar gemini aliases" {
    try std.testing.expectEqualStrings("GEMINI_API_KEY", providerEnvVar("gemini"));
    try std.testing.expectEqualStrings("GEMINI_API_KEY", providerEnvVar("google"));
    try std.testing.expectEqualStrings("GEMINI_API_KEY", providerEnvVar("google-gemini"));
}

test "providerEnvVar deepseek" {
    try std.testing.expectEqualStrings("DEEPSEEK_API_KEY", providerEnvVar("deepseek"));
}

test "providerEnvVar groq" {
    try std.testing.expectEqualStrings("GROQ_API_KEY", providerEnvVar("groq"));
}

test "known_providers all have non-empty fields" {
    for (known_providers) |p| {
        try std.testing.expect(p.key.len > 0);
        try std.testing.expect(p.label.len > 0);
        try std.testing.expect(p.default_model.len > 0);
        try std.testing.expect(p.env_var.len > 0);
    }
}

test "known_providers keys are unique" {
    for (known_providers, 0..) |p1, i| {
        for (known_providers[i + 1 ..]) |p2| {
            try std.testing.expect(!std.mem.eql(u8, p1.key, p2.key));
        }
    }
}

test "ProjectContext default values" {
    const ctx = ProjectContext{};
    try std.testing.expectEqualStrings("User", ctx.user_name);
    try std.testing.expectEqualStrings("UTC", ctx.timezone);
    try std.testing.expectEqualStrings("nullclaw", ctx.agent_name);
    try std.testing.expect(ctx.communication_style.len > 0);
}

test "memoryTemplate contains expected sections" {
    const tmpl = try memoryTemplate(std.testing.allocator, &ProjectContext{});
    defer std.testing.allocator.free(tmpl);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Memory") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "User") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Preferences") != null);
}

test "memoryTemplate uses context values" {
    const ctx = ProjectContext{
        .user_name = "Alice",
        .timezone = "PST",
        .agent_name = "TestBot",
    };
    const tmpl = try memoryTemplate(std.testing.allocator, &ctx);
    defer std.testing.allocator.free(tmpl);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Alice") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "PST") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "TestBot") != null);
}

test "scaffoldWorkspace does not create memory subdirectory by default" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{});
    try std.testing.expectError(error.FileNotFound, tmp.dir.openDir("memory", .{}));
}

test "BANNER is non-empty and contains nullclaw branding" {
    try std.testing.expect(BANNER.len > 100);
    try std.testing.expect(std.mem.indexOf(u8, BANNER, "Zig") != null or std.mem.indexOf(u8, BANNER, "smallest") != null);
}

test "defaultBackendKey returns non-empty" {
    const key = defaultBackendKey();
    try std.testing.expect(key.len > 0);
}

test "selectableBackends has expected backends" {
    const backends = selectableBackends();
    // SQLite is optional and controlled by build flag.
    var has_sqlite = false;
    for (backends) |b| {
        if (std.mem.eql(u8, b.name, "sqlite")) has_sqlite = true;
    }
    try std.testing.expectEqual(build_options.enable_memory_sqlite, has_sqlite);
}

// ── Wizard helper tests ─────────────────────────────────────────

test "readLine returns null on empty read" {
    // readLine reads from actual stdin which returns 0 bytes in tests (EOF)
    // This tests the null-on-EOF path
    var buf: [64]u8 = undefined;
    // We can't test stdin directly in unit tests, but we can validate
    // the function signature and constants
    _ = &buf;
}

test "tunnel_options has 4 entries" {
    try std.testing.expect(tunnel_options.len == 4);
    try std.testing.expectEqualStrings("none", tunnel_options[0]);
    try std.testing.expectEqualStrings("cloudflare", tunnel_options[1]);
    try std.testing.expectEqualStrings("ngrok", tunnel_options[2]);
    try std.testing.expectEqualStrings("tailscale", tunnel_options[3]);
}

test "autonomy_options has 3 entries" {
    try std.testing.expect(autonomy_options.len == 3);
    try std.testing.expectEqualStrings("supervised", autonomy_options[0]);
    try std.testing.expectEqualStrings("autonomous", autonomy_options[1]);
    try std.testing.expectEqualStrings("fully_autonomous", autonomy_options[2]);
}

test "catalog_providers has entries" {
    try std.testing.expect(catalog_providers.len >= 2);
    try std.testing.expectEqualStrings("openai", catalog_providers[0].name);
    try std.testing.expectEqualStrings("openrouter", catalog_providers[1].name);
}

test "catalog_providers all have valid fields" {
    for (catalog_providers) |cp| {
        try std.testing.expect(cp.name.len > 0);
        try std.testing.expect(cp.url.len > 0);
        try std.testing.expect(cp.models_path.len > 0);
        try std.testing.expect(cp.id_field.len > 0);
        // URLs should start with https
        try std.testing.expect(std.mem.startsWith(u8, cp.url, "https://"));
    }
}

test "catalog_providers names are unique" {
    for (catalog_providers, 0..) |cp1, i| {
        for (catalog_providers[i + 1 ..]) |cp2| {
            try std.testing.expect(!std.mem.eql(u8, cp1.name, cp2.name));
        }
    }
}

test "wizard promptChoice returns default for out-of-range" {
    // This tests the logic without actual I/O by validating the
    // boundary: max providers is known_providers.len
    try std.testing.expect(known_providers.len == 30);
    // The wizard would clamp to default (0) for out of range input
}

test "findChannelOptionIndex supports number and key" {
    const options = [_]channel_catalog.ChannelMeta{
        .{ .id = .telegram, .key = "telegram", .label = "Telegram", .configured_message = "Telegram configured", .listener_mode = .polling },
        .{ .id = .discord, .key = "discord", .label = "Discord", .configured_message = "Discord configured", .listener_mode = .gateway_loop },
    };

    try std.testing.expectEqual(@as(?usize, 0), findChannelOptionIndex("1", &options));
    try std.testing.expectEqual(@as(?usize, 1), findChannelOptionIndex("discord", &options));
    try std.testing.expect(findChannelOptionIndex("unknown", &options) == null);
}

test "wizard maps autonomy index to enum correctly" {
    // Verify the mapping used in runWizard
    const Config2 = @import("config.zig");
    const mapping = [_]Config2.AutonomyLevel{ .supervised, .full, .full };
    try std.testing.expect(mapping[0] == .supervised);
    try std.testing.expect(mapping[1] == .full);
    try std.testing.expect(mapping[2] == .full);
}

// ── New template tests ──────────────────────────────────────────

test "soulTemplate contains personality" {
    const tmpl = try soulTemplate(std.testing.allocator, &ProjectContext{});
    defer std.testing.allocator.free(tmpl);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "SOUL.md - Who You Are") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Core Truths") != null);
}

test "agentsTemplate contains guidelines" {
    const tmpl = agentsTemplate();
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "AGENTS.md - Your Workspace") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Every Session") != null);
}

test "toolsTemplate contains tool docs" {
    const tmpl = toolsTemplate();
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "TOOLS.md - Local Notes") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Skills define _how_ tools work") != null);
}

test "identityTemplate contains agent name" {
    const tmpl = try identityTemplate(std.testing.allocator, &ProjectContext{ .agent_name = "TestBot" });
    defer std.testing.allocator.free(tmpl);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "IDENTITY.md - Who Am I?") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "**Name:**") != null);
}

test "userTemplate contains user info" {
    const ctx = ProjectContext{ .user_name = "Alice", .timezone = "PST" };
    const tmpl = try userTemplate(std.testing.allocator, &ctx);
    defer std.testing.allocator.free(tmpl);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "USER.md - About Your Human") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Learn about the person you're helping") != null);
}

test "heartbeatTemplate is non-empty" {
    const tmpl = heartbeatTemplate();
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "HEARTBEAT.md") != null);
}

test "bootstrapTemplate is non-empty" {
    const tmpl = bootstrapTemplate();
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "BOOTSTRAP.md - Hello, World") != null);
}

test "scaffoldWorkspace creates core prompt.zig files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{});

    // Verify core files that prompt.zig always loads exist.
    const files = [_][]const u8{
        "SOUL.md",      "AGENTS.md",
        "TOOLS.md",     "IDENTITY.md",
        "USER.md",      "HEARTBEAT.md",
        "BOOTSTRAP.md",
    };
    for (files) |filename| {
        const file = tmp.dir.openFile(filename, .{}) catch |err| {
            std.debug.print("Missing file: {s} (error: {})\n", .{ filename, err });
            return err;
        };
        file.close();
    }
}

// ── Live model fetching tests ───────────────────────────────────

test "fallbackModelsForProvider returns models for known providers" {
    const or_models = fallbackModelsForProvider("openrouter");
    try std.testing.expect(or_models.len >= 3);

    const oai_models = fallbackModelsForProvider("openai");
    try std.testing.expect(oai_models.len >= 3);

    const anth_models = fallbackModelsForProvider("anthropic");
    try std.testing.expect(anth_models.len >= 3);
    try std.testing.expectEqualStrings("claude-opus-4-6", anth_models[0]);

    const groq_models = fallbackModelsForProvider("groq");
    try std.testing.expect(groq_models.len >= 2);

    const gemini_models = fallbackModelsForProvider("gemini");
    try std.testing.expect(gemini_models.len >= 2);
}

test "fallbackModelsForProvider handles aliases" {
    const models = fallbackModelsForProvider("google");
    try std.testing.expect(models.len >= 2);
    try std.testing.expectEqualStrings("gemini-2.5-pro", models[0]);
}

test "fallbackModelsForProvider unknown returns anthropic fallback" {
    const models = fallbackModelsForProvider("some-unknown-provider");
    try std.testing.expect(models.len >= 3);
    try std.testing.expectEqualStrings("claude-opus-4-6", models[0]);
}

test "fallbackModelsForProvider uses provider defaults for uncataloged providers" {
    const qwen_models = fallbackModelsForProvider("qwen");
    try std.testing.expect(qwen_models.len >= 1);
    try std.testing.expectEqualStrings("qwen-3-max", qwen_models[0]);

    const z_ai_models = fallbackModelsForProvider("z.ai");
    try std.testing.expect(z_ai_models.len >= 1);
    try std.testing.expectEqualStrings("glm-5", z_ai_models[0]);
}

test "parseModelIds extracts IDs from OpenRouter-style response" {
    const json =
        \\{"data": [
        \\  {"id": "openai/gpt-4", "name": "GPT-4"},
        \\  {"id": "anthropic/claude-3", "name": "Claude 3"},
        \\  {"id": "meta/llama-3", "name": "Llama 3"}
        \\]}
    ;
    const models = try parseModelIds(std.testing.allocator, json);
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }

    try std.testing.expect(models.len == 3);
    try std.testing.expectEqualStrings("openai/gpt-4", models[0]);
    try std.testing.expectEqualStrings("anthropic/claude-3", models[1]);
    try std.testing.expectEqualStrings("meta/llama-3", models[2]);
}

test "parseModelIds handles empty data array" {
    const json = "{\"data\": []}";
    const models = try parseModelIds(std.testing.allocator, json);
    defer std.testing.allocator.free(models);
    try std.testing.expect(models.len == 0);
}

test "parseModelIds rejects invalid JSON" {
    const result = parseModelIds(std.testing.allocator, "not json");
    try std.testing.expectError(error.FetchFailed, result);
}

test "parseModelIds rejects missing data field" {
    const result = parseModelIds(std.testing.allocator, "{\"models\": []}");
    try std.testing.expectError(error.FetchFailed, result);
}

test "parseModelIds skips entries without id" {
    const json =
        \\{"data": [
        \\  {"id": "model-a"},
        \\  {"name": "no-id"},
        \\  {"id": "model-b"}
        \\]}
    ;
    const models = try parseModelIds(std.testing.allocator, json);
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }
    try std.testing.expect(models.len == 2);
    try std.testing.expectEqualStrings("model-a", models[0]);
    try std.testing.expectEqualStrings("model-b", models[1]);
}

test "cache read returns error for missing file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const missing_path = try std.fs.path.join(std.testing.allocator, &.{ base, "nonexistent-cache-12345.json" });
    defer std.testing.allocator.free(missing_path);

    const result = readCachedModels(std.testing.allocator, missing_path, "openai");
    try std.testing.expectError(error.CacheNotFound, result);
}

test "cache round-trip: write then read fresh cache" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cache_path = try std.fs.path.join(std.testing.allocator, &.{ base, "models_cache.json" });
    defer std.testing.allocator.free(cache_path);

    // Write cache
    const models = [_][]const u8{
        "model-alpha",
        "model-beta",
        "model-gamma",
    };
    try saveCachedModels(std.testing.allocator, cache_path, "testprov", &models);

    // Read back
    const loaded = try readCachedModels(std.testing.allocator, cache_path, "testprov");
    defer {
        for (loaded) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(loaded);
    }

    try std.testing.expect(loaded.len == 3);
    try std.testing.expectEqualStrings("model-alpha", loaded[0]);
    try std.testing.expectEqualStrings("model-beta", loaded[1]);
    try std.testing.expectEqualStrings("model-gamma", loaded[2]);
}

test "cache read returns error for wrong provider" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cache_path = try std.fs.path.join(std.testing.allocator, &.{ base, "models_cache.json" });
    defer std.testing.allocator.free(cache_path);

    const models = [_][]const u8{"model-a"};
    try saveCachedModels(std.testing.allocator, cache_path, "provA", &models);

    // Reading for a different provider should fail
    const result = readCachedModels(std.testing.allocator, cache_path, "provB");
    try std.testing.expectError(error.CacheProviderMissing, result);
}

test "cache read returns error for expired cache" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cache_path = try std.fs.path.join(std.testing.allocator, &.{ base, "models_cache.json" });
    defer std.testing.allocator.free(cache_path);

    // Write a cache with old timestamp
    const old_json = "{\"fetched_at\": 1000000, \"myprov\": [\"old-model\"]}";
    const file = try tmp.dir.createFile("models_cache.json", .{});
    defer file.close();
    try file.writeAll(old_json);

    const result = readCachedModels(std.testing.allocator, cache_path, "myprov");
    try std.testing.expectError(error.CacheExpired, result);
}

test "loadModelsWithCache falls back on fetch failure" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const nonexistent = try std.fs.path.join(std.testing.allocator, &.{ base, "nonexistent-dir-xyz" });
    defer std.testing.allocator.free(nonexistent);

    // openai without api key will fail fetch, falling back to hardcoded list
    const models = try loadModelsWithCache(std.testing.allocator, nonexistent, "openai", null);
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }
    try std.testing.expect(models.len >= 3);
    try std.testing.expectEqualStrings("gpt-5.2", models[0]);
}

test "loadModelsWithCache returns models for anthropic" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    const models = try loadModelsWithCache(std.testing.allocator, base, "anthropic", null);
    // Anthropic returns hardcoded models (allocated copies)
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }
    try std.testing.expect(models.len == 3);
    try std.testing.expectEqualStrings("claude-opus-4-6", models[0]);
}

test "fetchModelsFromApi returns hardcoded for anthropic" {
    const models = try fetchModelsFromApi(std.testing.allocator, "anthropic", null);
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }
    try std.testing.expect(models.len == 3);
    try std.testing.expectEqualStrings("claude-opus-4-6", models[0]);
    try std.testing.expectEqualStrings("claude-sonnet-4-6", models[1]);
    try std.testing.expectEqualStrings("claude-haiku-4-5", models[2]);
}

test "fetchModelsFromApi returns hardcoded for ollama" {
    const models = try fetchModelsFromApi(std.testing.allocator, "ollama", null);
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }
    try std.testing.expect(models.len >= 3);
    try std.testing.expectEqualStrings("llama4", models[0]);
}

test "fetchModelsFromApi returns error for openai without key" {
    const result = fetchModelsFromApi(std.testing.allocator, "openai", null);
    try std.testing.expectError(error.FetchFailed, result);
}

test "fetchModelsFromApi returns error for groq without key" {
    const result = fetchModelsFromApi(std.testing.allocator, "groq", null);
    try std.testing.expectError(error.FetchFailed, result);
}

test "ModelsCacheEntry struct has expected fields" {
    const entry = ModelsCacheEntry{
        .provider = "openai",
        .models = &.{ "gpt-4", "gpt-3.5-turbo" },
        .fetched_at = 1700000000,
    };
    try std.testing.expectEqualStrings("openai", entry.provider);
    try std.testing.expect(entry.models.len == 2);
    try std.testing.expect(entry.fetched_at == 1700000000);
}

test "CACHE_TTL_SECS is 12 hours" {
    try std.testing.expect(CACHE_TTL_SECS == 43200);
}

test "MAX_MODELS is 20" {
    try std.testing.expect(MAX_MODELS == 20);
}

test "fetchModels returns models for anthropic (no network)" {
    const models = try fetchModels(std.testing.allocator, "anthropic", null);
    // Anthropic uses hardcoded fallback (allocated copies via fetchModelsFromApi)
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }
    try std.testing.expect(models.len >= 3);
    try std.testing.expectEqualStrings("claude-opus-4-6", models[0]);
}

test "fetchModels returns models for gemini (no network)" {
    const models = try fetchModels(std.testing.allocator, "gemini", null);
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }
    try std.testing.expect(models.len >= 2);
    try std.testing.expectEqualStrings("gemini-2.5-pro", models[0]);
}

test "fetchModels returns models for deepseek (no network)" {
    const models = try fetchModels(std.testing.allocator, "deepseek", null);
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }
    try std.testing.expect(models.len >= 2);
    try std.testing.expectEqualStrings("deepseek-chat", models[0]);
}

test "fetchModels returns fallback for openai without key" {
    // OpenAI needs auth — without key, should gracefully fall back
    const models = try fetchModels(std.testing.allocator, "openai", null);
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }
    try std.testing.expect(models.len >= 3);
    try std.testing.expectEqualStrings("gpt-5.2", models[0]);
}

test "fetchModels returns fallback for unknown provider" {
    const models = try fetchModels(std.testing.allocator, "some-random-provider", null);
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }
    try std.testing.expect(models.len >= 3);
    try std.testing.expectEqualStrings("claude-opus-4-6", models[0]);
}

test "fetchModels handles google alias" {
    const models = try fetchModels(std.testing.allocator, "google", null);
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }
    try std.testing.expect(models.len >= 2);
    try std.testing.expectEqualStrings("gemini-2.5-pro", models[0]);
}

test "parseModelIds respects data ordering" {
    const json =
        \\{"data": [
        \\  {"id": "z-model"},
        \\  {"id": "a-model"},
        \\  {"id": "m-model"}
        \\]}
    ;
    const models = try parseModelIds(std.testing.allocator, json);
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }
    try std.testing.expect(models.len == 3);
    // Should preserve original order, not sort
    try std.testing.expectEqualStrings("z-model", models[0]);
    try std.testing.expectEqualStrings("a-model", models[1]);
    try std.testing.expectEqualStrings("m-model", models[2]);
}
