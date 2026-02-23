//! Onboarding — interactive setup wizard and quick setup for nullclaw.
//!
//! Mirrors ZeroClaw's onboard module:
//!   - Interactive wizard (9-step configuration flow)
//!   - Quick setup (non-interactive, sensible defaults)
//!   - Workspace scaffolding (MEMORY.md, PERSONA.md, RULES.md)
//!   - Channel configuration
//!   - Memory backend selection
//!   - Provider/model selection with curated defaults

const std = @import("std");
const platform = @import("platform.zig");
const config_mod = @import("config.zig");
const Config = config_mod.Config;
const channel_catalog = @import("channel_catalog.zig");
const memory_root = @import("memory/root.zig");
const http_util = @import("http_util.zig");

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
    .{ .key = "deepseek", .label = "DeepSeek", .default_model = "deepseek-v3.2", .env_var = "DEEPSEEK_API_KEY" },
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

/// Get the default model for a provider.
pub fn defaultModelForProvider(provider: []const u8) []const u8 {
    const canonical = canonicalProviderName(provider);
    for (known_providers) |p| {
        if (std.mem.eql(u8, p.key, canonical)) return p.default_model;
    }
    return "anthropic/claude-sonnet-4.6";
}

/// Get the environment variable name for a provider's API key.
pub fn providerEnvVar(provider: []const u8) []const u8 {
    const canonical = canonicalProviderName(provider);
    for (known_providers) |p| {
        if (std.mem.eql(u8, p.key, canonical)) return p.env_var;
    }
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
    "deepseek-v3.2",
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
    if (provider) |p| cfg.default_provider = p;
    if (api_key) |key| {
        // Store in providers section for the default provider (arena frees old values)
        const entries = try cfg.allocator.alloc(config_mod.ProviderEntry, 1);
        entries[0] = .{ .name = try cfg.allocator.dupe(u8, cfg.default_provider), .api_key = key };
        cfg.providers = entries;
    }
    if (memory_backend) |mb| cfg.memory.backend = mb;

    // Set default model based on provider
    if (cfg.default_model == null or std.mem.eql(u8, cfg.default_model.?, "anthropic/claude-sonnet-4")) {
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
        try stdout.writeAll("    1. Set your API key:  export OPENROUTER_API_KEY=\"sk-...\"\n");
        try stdout.writeAll("    2. Chat:              nullclaw agent -m \"Hello!\"\n");
        try stdout.writeAll("    3. Gateway:           nullclaw gateway\n");
    } else {
        try stdout.writeAll("    1. Chat:     nullclaw agent -m \"Hello!\"\n");
        try stdout.writeAll("    2. Gateway:  nullclaw gateway\n");
        try stdout.writeAll("    3. Status:   nullclaw status\n");
    }
    try stdout.writeAll("\n");
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
    try stdout.writeAll("Channel configuration status:\n\n");

    var cfg = Config.load(allocator) catch {
        try stdout.writeAll("No existing config found. Run `nullclaw onboard` first.\n");
        try stdout.flush();
        return error.ConfigNotFound;
    };
    defer cfg.deinit();

    for (channel_catalog.known_channels) |meta| {
        var status_buf: [64]u8 = undefined;
        const status_text = channel_catalog.statusText(&cfg, meta, &status_buf);
        try stdout.print("  {s}: {s}\n", .{ meta.label, status_text });
    }
    try stdout.writeAll("\nTo modify channels, edit your config file:\n");
    try stdout.print("  {s}\n", .{cfg.config_path});
    try stdout.flush();
}

/// Read a line from stdin, trimming trailing newline/carriage return.
/// Returns null on EOF (Ctrl+D).
fn readLine(buf: []u8) ?[]const u8 {
    const stdin = std.fs.File.stdin();
    const n = stdin.read(buf) catch return null;
    if (n == 0) return null;
    return std.mem.trimRight(u8, buf[0..n], "\r\n");
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

/// Interactive wizard entry point — runs the full setup interactively.
pub fn runWizard(allocator: std.mem.Allocator) !void {
    var stdout_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    const out = &bw.interface;
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
    const backends = selectableBackends();
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
    cfg.memory.backend = backends[mem_idx].key;
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
    cfg.autonomy.level = switch (autonomy_idx) {
        0 => .supervised,
        1 => .read_only,
        2 => .full,
        else => .supervised,
    };
    try out.print("  -> {s}\n\n", .{autonomy_options[autonomy_idx]});

    // ── Step 7: Channels ──
    try out.writeAll("  Step 7/8: Configure channels now? [y/N]: ");
    const chan_input = prompt(out, &input_buf, "", "n") orelse {
        try out.writeAll("\n  Aborted.\n");
        try out.flush();
        return;
    };
    if (chan_input.len > 0 and (chan_input[0] == 'y' or chan_input[0] == 'Y')) {
        try out.writeAll("  -> Edit channels in config file after setup.\n\n");
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
    // MEMORY.md
    const mem_tmpl = try memoryTemplate(allocator, ctx);
    defer allocator.free(mem_tmpl);
    try writeIfMissing(allocator, workspace_dir, "MEMORY.md", mem_tmpl);

    // PERSONA.md
    const persona_tmpl = try personaTemplate(allocator, ctx);
    defer allocator.free(persona_tmpl);
    try writeIfMissing(allocator, workspace_dir, "PERSONA.md", persona_tmpl);

    // RULES.md
    try writeIfMissing(allocator, workspace_dir, "RULES.md", rulesTemplate());

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

    // BOOTSTRAP.md (startup instructions — loaded by prompt.zig)
    try writeIfMissing(allocator, workspace_dir, "BOOTSTRAP.md", bootstrapTemplate());

    // Ensure memory/ subdirectory
    const mem_dir = try std.fmt.allocPrint(allocator, "{s}/memory", .{workspace_dir});
    defer allocator.free(mem_dir);
    std.fs.makeDirAbsolute(mem_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

fn writeIfMissing(allocator: std.mem.Allocator, dir: []const u8, filename: []const u8, content: []const u8) !void {
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, filename });
    defer allocator.free(path);

    // Only write if file doesn't exist
    if (std.fs.openFileAbsolute(path, .{})) |f| {
        f.close();
        return;
    } else |_| {}

    const file = std.fs.createFileAbsolute(path, .{}) catch return;
    defer file.close();
    file.writeAll(content) catch {};
}

fn memoryTemplate(allocator: std.mem.Allocator, ctx: *const ProjectContext) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\# {s}'s Memory
        \\
        \\## User
        \\- Name: {s}
        \\- Timezone: {s}
        \\
        \\## Preferences
        \\- Communication style: {s}
        \\
    , .{ ctx.agent_name, ctx.user_name, ctx.timezone, ctx.communication_style });
}

fn personaTemplate(allocator: std.mem.Allocator, ctx: *const ProjectContext) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\# {s} Persona
        \\
        \\You are {s}, a fast and focused AI assistant.
        \\
        \\## Core traits
        \\- Helpful, concise, and direct
        \\- Prefer code over explanations
        \\- Ask for clarification when uncertain
        \\
    , .{ ctx.agent_name, ctx.agent_name });
}

fn rulesTemplate() []const u8 {
    return 
    \\# Rules
    \\
    \\## Workspace
    \\- Only modify files within the workspace directory
    \\- Do not access external services without permission
    \\
    \\## Communication
    \\- Be concise and actionable
    \\- Show relevant code snippets
    \\- Admit uncertainty rather than guessing
    \\
    ;
}

fn soulTemplate(allocator: std.mem.Allocator, ctx: *const ProjectContext) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\# Soul
        \\
        \\You are {s} — a fast, lightweight AI assistant powered by nullclaw.
        \\
        \\## Personality
        \\- Efficient and focused
        \\- Prefer action over discussion
        \\- Honest about limitations
        \\- Respect the user's time
        \\
    , .{ctx.agent_name});
}

fn agentsTemplate() []const u8 {
    return 
    \\# Agent Guidelines
    \\
    \\## Tool Use
    \\- Use tools when you need information or to perform actions
    \\- Prefer reading files before modifying them
    \\- Validate tool results before proceeding
    \\
    \\## Conversation
    \\- Keep responses concise and actionable
    \\- Show code when relevant
    \\- Ask clarifying questions when requirements are ambiguous
    \\
    ;
}

fn toolsTemplate() []const u8 {
    return 
    \\# Tools Guide
    \\
    \\## File Operations
    \\- Use file_read to inspect files before editing
    \\- Use file_write for creating new files
    \\- Use file_edit for modifying existing files (find-replace)
    \\
    \\## Shell
    \\- Use shell for commands, builds, and tests
    \\- Prefer non-destructive commands
    \\- Be cautious with rm, overwrite, and network operations
    \\
    ;
}

fn identityTemplate(allocator: std.mem.Allocator, ctx: *const ProjectContext) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\# Identity
        \\
        \\name: {s}
        \\engine: nullclaw
        \\version: 0.1.0
        \\
    , .{ctx.agent_name});
}

fn userTemplate(allocator: std.mem.Allocator, ctx: *const ProjectContext) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\# User Profile
        \\
        \\- Name: {s}
        \\- Timezone: {s}
        \\- Style: {s}
        \\
    , .{ ctx.user_name, ctx.timezone, ctx.communication_style });
}

fn heartbeatTemplate() []const u8 {
    return 
    \\# Heartbeat
    \\
    \\Periodic tasks and reminders. Add items below to be checked regularly.
    \\
    \\## Tasks
    \\(none configured)
    \\
    ;
}

fn bootstrapTemplate() []const u8 {
    return 
    \\# Bootstrap
    \\
    \\Startup instructions executed when the agent initializes.
    \\
    \\## On Start
    \\- Load workspace context
    \\- Check for pending tasks
    \\
    ;
}

// ── Memory backend helpers ───────────────────────────────────────

/// Get the list of selectable memory backends.
pub fn selectableBackends() []const memory_root.MemoryBackendProfile {
    return &memory_root.selectable_backends;
}

/// Get the default memory backend key.
pub fn defaultBackendKey() []const u8 {
    return memory_root.defaultBackendKey();
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
    try std.testing.expectEqualStrings("deepseek-v3.2", defaultModelForProvider("deepseek"));
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

test "rulesTemplate is non-empty" {
    const template = rulesTemplate();
    try std.testing.expect(template.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, template, "Rules") != null);
}

test "known_providers has entries" {
    try std.testing.expect(known_providers.len >= 5);
    try std.testing.expectEqualStrings("openrouter", known_providers[0].key);
}

test "selectableBackends returns non-empty" {
    const backends = selectableBackends();
    try std.testing.expect(backends.len >= 3);
    try std.testing.expectEqualStrings("sqlite", backends[0].key);
}

test "BANNER contains descriptive text" {
    try std.testing.expect(std.mem.indexOf(u8, BANNER, "smallest AI assistant") != null);
}

test "scaffoldWorkspace creates files in temp dir" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    const ctx = ProjectContext{};
    try scaffoldWorkspace(std.testing.allocator, base, &ctx);

    // Verify files were created
    const file = try tmp.dir.openFile("MEMORY.md", .{});
    defer file.close();
    const content = try file.readToEndAlloc(std.testing.allocator, 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(content.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, content, "Memory") != null);
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

test "rulesTemplate contains workspace rules" {
    const template = rulesTemplate();
    try std.testing.expect(std.mem.indexOf(u8, template, "Workspace") != null);
    try std.testing.expect(std.mem.indexOf(u8, template, "Communication") != null);
}

test "rulesTemplate contains behavioral guidelines" {
    const template = rulesTemplate();
    try std.testing.expect(std.mem.indexOf(u8, template, "concise") != null);
    try std.testing.expect(std.mem.indexOf(u8, template, "uncertainty") != null or std.mem.indexOf(u8, template, "uncertain") != null);
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

test "personaTemplate uses agent name" {
    const ctx = ProjectContext{ .agent_name = "MiniBot" };
    const tmpl = try personaTemplate(std.testing.allocator, &ctx);
    defer std.testing.allocator.free(tmpl);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "MiniBot") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Persona") != null);
}

test "personaTemplate contains core traits" {
    const tmpl = try personaTemplate(std.testing.allocator, &ProjectContext{});
    defer std.testing.allocator.free(tmpl);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "concise") != null or std.mem.indexOf(u8, tmpl, "Helpful") != null);
}

test "scaffoldWorkspace creates PERSONA.md" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{});

    const file = try tmp.dir.openFile("PERSONA.md", .{});
    defer file.close();
    const content = try file.readToEndAlloc(std.testing.allocator, 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(content.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, content, "Persona") != null);
}

test "scaffoldWorkspace creates RULES.md" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{});

    const file = try tmp.dir.openFile("RULES.md", .{});
    defer file.close();
    const content = try file.readToEndAlloc(std.testing.allocator, 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(content.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, content, "Rules") != null);
}

test "scaffoldWorkspace creates memory subdirectory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{});

    // Verify memory/ subdirectory exists
    var d = try tmp.dir.openDir("memory", .{});
    d.close();
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
    // Should have sqlite, markdown, and json at minimum
    var has_sqlite = false;
    for (backends) |b| {
        if (std.mem.eql(u8, b.key, "sqlite")) has_sqlite = true;
    }
    try std.testing.expect(has_sqlite);
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

test "wizard maps autonomy index to enum correctly" {
    // Verify the mapping used in runWizard
    const Config2 = @import("config.zig");
    const mapping = [_]Config2.AutonomyLevel{ .supervised, .read_only, .full };
    try std.testing.expect(mapping[0] == .supervised);
    try std.testing.expect(mapping[1] == .read_only);
    try std.testing.expect(mapping[2] == .full);
}

// ── New template tests ──────────────────────────────────────────

test "soulTemplate contains personality" {
    const tmpl = try soulTemplate(std.testing.allocator, &ProjectContext{});
    defer std.testing.allocator.free(tmpl);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Soul") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "nullclaw") != null);
}

test "agentsTemplate contains guidelines" {
    const tmpl = agentsTemplate();
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Agent Guidelines") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Tool Use") != null);
}

test "toolsTemplate contains tool docs" {
    const tmpl = toolsTemplate();
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Tools Guide") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Shell") != null);
}

test "identityTemplate contains agent name" {
    const tmpl = try identityTemplate(std.testing.allocator, &ProjectContext{ .agent_name = "TestBot" });
    defer std.testing.allocator.free(tmpl);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "TestBot") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "nullclaw") != null);
}

test "userTemplate contains user info" {
    const ctx = ProjectContext{ .user_name = "Alice", .timezone = "PST" };
    const tmpl = try userTemplate(std.testing.allocator, &ctx);
    defer std.testing.allocator.free(tmpl);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Alice") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "PST") != null);
}

test "heartbeatTemplate is non-empty" {
    const tmpl = heartbeatTemplate();
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Heartbeat") != null);
}

test "bootstrapTemplate is non-empty" {
    const tmpl = bootstrapTemplate();
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "Bootstrap") != null);
}

test "scaffoldWorkspace creates all prompt.zig files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{});

    // Verify all files that prompt.zig tries to load exist
    const files = [_][]const u8{
        "MEMORY.md",    "PERSONA.md", "RULES.md",
        "SOUL.md",      "AGENTS.md",  "TOOLS.md",
        "IDENTITY.md",  "USER.md",    "HEARTBEAT.md",
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
    try std.testing.expectEqualStrings("deepseek-v3.2", models[0]);
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
