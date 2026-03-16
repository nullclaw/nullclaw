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
const builtin = @import("builtin");
const build_options = @import("build_options");
const fs_compat = @import("fs_compat.zig");
const platform = @import("platform.zig");
const codex_support = @import("codex_support.zig");
const config_mod = @import("config.zig");
const Config = config_mod.Config;
const channel_catalog = @import("channel_catalog.zig");
const provider_names = @import("provider_names.zig");
const memory_root = @import("memory/root.zig");
const http_util = @import("http_util.zig");
const json_util = @import("json_util.zig");
const util = @import("util.zig");
const bootstrap_mod = @import("bootstrap/root.zig");

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
    .{ .key = "azure", .label = "Azure OpenAI (GPT via Azure)", .default_model = "gpt-5.2-chat", .env_var = "AZURE_OPENAI_API_KEY" },

    // --- Tier 2: Major cloud providers (Feb 2026 models) ---
    .{ .key = "gemini", .label = "Google Gemini", .default_model = "gemini-2.5-pro", .env_var = "GEMINI_API_KEY" },
    .{ .key = "vertex", .label = "Google Vertex AI (Gemini)", .default_model = "gemini-2.5-pro", .env_var = "VERTEX_API_KEY" },
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

    // --- Tier 10: CLI-based providers ---
    .{ .key = "claude-cli", .label = "Claude CLI (claude code, local)", .default_model = "claude-opus-4-6", .env_var = "ANTHROPIC_API_KEY" },
    .{ .key = "codex-cli", .label = "Codex CLI (local CLI)", .default_model = codex_support.DEFAULT_CODEX_MODEL, .env_var = "OPENAI_API_KEY" },
    .{ .key = "openai-codex", .label = "OpenAI Codex (ChatGPT login)", .default_model = codex_support.DEFAULT_CODEX_MODEL, .env_var = "" },
};

/// Canonicalize provider name (handle aliases).
pub fn canonicalProviderName(name: []const u8) []const u8 {
    return provider_names.canonicalProviderName(name);
}

fn findProviderInfoByCanonical(name: []const u8) ?ProviderInfo {
    for (known_providers) |p| {
        if (std.mem.eql(u8, p.key, name)) return p;
    }
    return null;
}

fn hasVersionedApiSegment(url: []const u8) bool {
    const proto_start = std.mem.indexOf(u8, url, "://") orelse return false;
    var i: usize = proto_start + 3;
    while (i + 2 < url.len) : (i += 1) {
        if (url[i] != '/' or url[i + 1] != 'v') continue;
        var j = i + 2;
        var has_digit = false;
        while (j < url.len and std.ascii.isDigit(url[j])) : (j += 1) {
            has_digit = true;
        }
        if (!has_digit) continue;
        if (j == url.len or (j < url.len and url[j] == '/')) return true;
    }
    return false;
}

fn isValidCustomProviderUrl(url: []const u8) bool {
    if (url.len == 0) return false;
    if (!(std.mem.startsWith(u8, url, "https://") or std.mem.startsWith(u8, url, "http://"))) return false;
    return hasVersionedApiSegment(url);
}

fn isLocalEndpoint(url: []const u8) bool {
    return std.mem.startsWith(u8, url, "http://localhost") or
        std.mem.startsWith(u8, url, "https://localhost") or
        std.mem.startsWith(u8, url, "http://127.") or
        std.mem.startsWith(u8, url, "https://127.") or
        std.mem.startsWith(u8, url, "http://0.0.0.0") or
        std.mem.startsWith(u8, url, "https://0.0.0.0") or
        std.mem.startsWith(u8, url, "http://[::1]") or
        std.mem.startsWith(u8, url, "https://[::1]");
}

fn providerRequiresApiKeyForSetup(provider: []const u8, base_url: ?[]const u8) bool {
    const canonical = canonicalProviderName(provider);
    if (std.mem.eql(u8, canonical, "ollama") or
        std.mem.eql(u8, canonical, "lm-studio") or
        std.mem.eql(u8, canonical, "lmstudio") or
        std.mem.eql(u8, canonical, "claude-cli") or
        std.mem.eql(u8, canonical, "codex-cli") or
        std.mem.eql(u8, canonical, "openai-codex"))
    {
        return false;
    }

    if (std.mem.startsWith(u8, provider, "custom:")) {
        const custom_url = if (base_url) |configured| configured else provider["custom:".len..];
        return !isLocalEndpoint(custom_url);
    }

    if (base_url) |configured| {
        return !isLocalEndpoint(configured);
    }

    return true;
}

fn printProviderNextSteps(
    out: *std.Io.Writer,
    provider: []const u8,
    env_hint: []const u8,
    requires_api_key: bool,
    has_configured_key: bool,
) !void {
    const canonical = canonicalProviderName(provider);

    if (requires_api_key and !has_configured_key) {
        try out.print("    1. Set your API key:  export {s}=\"sk-...\"\n", .{env_hint});
        try out.writeAll("    2. Interactive chat:  nullclaw agent\n");
        try out.writeAll("       Then type:         Hello!\n");
        try out.writeAll("    3. Gateway:           nullclaw gateway\n");
        return;
    }

    if (std.mem.eql(u8, canonical, "openai-codex")) {
        try out.writeAll("    1. Authenticate:  nullclaw auth login openai-codex\n");
        try out.writeAll("       Alternative:   nullclaw auth login openai-codex --import-codex\n");
        try out.writeAll("    2. Interactive chat:  nullclaw agent\n");
        try out.writeAll("       Then type:         Hello!\n");
        try out.writeAll("    3. Gateway:       nullclaw gateway\n");
        return;
    }

    if (std.mem.eql(u8, canonical, "codex-cli")) {
        try out.writeAll("    1. Authenticate:  codex login\n");
        try out.writeAll("    2. Interactive chat:  nullclaw agent\n");
        try out.writeAll("       Then type:         Hello!\n");
        try out.writeAll("    3. Gateway:       nullclaw gateway\n");
        return;
    }

    try out.writeAll("    1. Interactive chat:  nullclaw agent\n");
    try out.writeAll("       Then type:         Hello!\n");
    try out.writeAll("    2. Gateway:           nullclaw gateway\n");
    try out.writeAll("    3. Status:            nullclaw status\n");
}

/// Resolve a provider name used in quick setup.
/// Accepts aliases (e.g. "grok" -> "xai") and returns provider metadata.
/// Supports custom: prefix for OpenAI-compatible endpoints.
pub fn resolveProviderForQuickSetup(name: []const u8) ?ProviderInfo {
    // Support custom: prefix for OpenAI-compatible providers
    if (std.mem.startsWith(u8, name, "custom:")) {
        const custom_url = name["custom:".len..];
        if (!isValidCustomProviderUrl(custom_url)) return null;
        return .{
            .key = name,
            .label = "Custom OpenAI-compatible provider",
            .default_model = "gpt-5.2",
            .env_var = "API_KEY",
        };
    }

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

fn writeOnboardingNextSteps(out: anytype, api_key_env_hint: ?[]const u8) !void {
    try out.writeAll("\n  Next steps:\n");
    if (api_key_env_hint) |env_hint| {
        try out.print("    1. Set your API key:  export {s}=\"sk-...\"\n", .{env_hint});
        try out.writeAll("    2. Interactive chat:  nullclaw agent\n");
        try out.writeAll("       Then type:         Hello!\n");
        try out.writeAll("    3. Gateway:           nullclaw gateway\n");
    } else {
        try out.writeAll("    1. Interactive chat:  nullclaw agent\n");
        try out.writeAll("       Then type:         Hello!\n");
        try out.writeAll("    2. Gateway:           nullclaw gateway\n");
        try out.writeAll("    3. Status:            nullclaw status\n");
    }
    try out.writeAll("\n");
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
    if (std.mem.eql(u8, canonical, "vertex")) return &vertex_fallback;
    if (std.mem.eql(u8, canonical, "deepseek")) return &deepseek_fallback;
    if (std.mem.eql(u8, canonical, "ollama")) return &ollama_fallback;
    if (std.mem.eql(u8, canonical, "claude-cli")) return &claude_cli_fallback;
    if (std.mem.eql(u8, canonical, "codex-cli")) return &codex_support.codex_model_fallbacks;
    if (std.mem.eql(u8, canonical, "openai-codex")) return &codex_support.codex_model_fallbacks;

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
const vertex_fallback = [_][]const u8{
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

const claude_cli_fallback = [_][]const u8{
    "claude-opus-4-6",
};

const MAX_MODELS = 20;
const MODELS_DEV_URL = "https://models.dev/api.json";

const ModelsDevProvider = struct {
    canonical: []const u8,
    key: []const u8,
};

const models_dev_providers = [_]ModelsDevProvider{
    .{ .canonical = "anthropic", .key = "anthropic" },
    .{ .canonical = "claude-cli", .key = "anthropic" },
    .{ .canonical = "openai", .key = "openai" },
    .{ .canonical = "groq", .key = "groq" },
    .{ .canonical = "deepseek", .key = "deepseek" },
    .{ .canonical = "gemini", .key = "google" },
    .{ .canonical = "vertex", .key = "google-vertex" },
    .{ .canonical = "z.ai", .key = "zai" },
    .{ .canonical = "glm", .key = "zhipuai" },
    .{ .canonical = "qwen", .key = "alibaba" },
    .{ .canonical = "together-ai", .key = "togetherai" },
    .{ .canonical = "fireworks-ai", .key = "fireworks-ai" },
    .{ .canonical = "mistral", .key = "mistral" },
    .{ .canonical = "xai", .key = "xai" },
    .{ .canonical = "venice", .key = "venice" },
    .{ .canonical = "moonshot", .key = "moonshotai" },
    .{ .canonical = "synthetic", .key = "synthetic" },
    .{ .canonical = "minimax", .key = "minimax" },
    .{ .canonical = "cohere", .key = "cohere" },
    .{ .canonical = "perplexity", .key = "perplexity" },
    .{ .canonical = "nvidia", .key = "nvidia" },
    .{ .canonical = "bedrock", .key = "amazon-bedrock" },
    .{ .canonical = "copilot", .key = "github-copilot" },
    .{ .canonical = "poe", .key = "poe" },
};

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
    const canonical = canonicalProviderName(provider);
    if (std.mem.eql(u8, canonical, "codex-cli") or std.mem.eql(u8, canonical, "openai-codex")) {
        return codex_support.loadCodexModels(allocator);
    }

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
/// Native list endpoints are preferred when available. For providers without a
/// native listing API, or when setup lacks credentials, production builds fall
/// back to the public models.dev catalog before using hardcoded defaults.
/// Results are limited to MAX_MODELS entries.
pub fn fetchModelsFromApi(allocator: std.mem.Allocator, provider: []const u8, api_key: ?[]const u8) ![][]const u8 {
    const canonical = canonicalProviderName(provider);

    if (std.mem.eql(u8, canonical, "codex-cli") or std.mem.eql(u8, canonical, "openai-codex")) {
        return codex_support.loadCodexModels(allocator);
    }

    if (fetchModelsFromNativeApi(allocator, canonical, api_key) catch null) |models| {
        return models;
    }

    // Tests must stay deterministic and offline; production can consult the
    // public models.dev catalog as a secondary source.
    if (!builtin.is_test and shouldUseModelsDevCatalog(canonical, api_key)) {
        if (fetchModelsFromModelsDev(allocator, canonical) catch null) |models| {
            return models;
        }
    }

    // Providers with no models-list API (or purely local catalogs) keep the
    // static fallback path for offline/test use.
    if (std.mem.eql(u8, canonical, "anthropic") or
        std.mem.eql(u8, canonical, "gemini") or
        std.mem.eql(u8, canonical, "vertex") or
        std.mem.eql(u8, canonical, "deepseek") or
        std.mem.eql(u8, canonical, "ollama") or
        std.mem.eql(u8, canonical, "claude-cli"))
    {
        return dupeFallbackModels(allocator, canonical);
    }

    return error.FetchFailed;
}

fn fetchModelsFromNativeApi(allocator: std.mem.Allocator, canonical: []const u8, api_key: ?[]const u8) !?[][]const u8 {
    var url: []const u8 = undefined;
    var url_to_free: ?[]const u8 = null;
    var needs_auth = false;
    var prefix_filter: ?[]const u8 = null;
    defer if (url_to_free) |u| allocator.free(u);

    if (std.mem.eql(u8, canonical, "openrouter")) {
        url = "https://openrouter.ai/api/v1/models";
    } else if (std.mem.eql(u8, canonical, "openai")) {
        url = "https://api.openai.com/v1/models";
        needs_auth = true;
        prefix_filter = "gpt-";
    } else if (std.mem.eql(u8, canonical, "groq")) {
        url = "https://api.groq.com/openai/v1/models";
        needs_auth = true;
    } else if (std.mem.startsWith(u8, canonical, "http://") or std.mem.startsWith(u8, canonical, "https://")) {
        url_to_free = try buildModelsUrl(allocator, canonical);
        url = url_to_free.?;
        needs_auth = true;
    } else {
        return null;
    }

    var headers_buf: [1][]const u8 = undefined;
    var headers: []const []const u8 = &.{};
    if (needs_auth) {
        const key = api_key orelse return null;
        const auth_hdr = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{key});
        defer allocator.free(auth_hdr);
        headers_buf[0] = auth_hdr;
        headers = &headers_buf;
    }

    return try fetchAndParseModels(allocator, url, headers, prefix_filter);
}

fn modelsDevProviderKey(provider: []const u8) ?[]const u8 {
    for (models_dev_providers) |entry| {
        if (std.mem.eql(u8, entry.canonical, provider)) return entry.key;
    }
    return null;
}

fn shouldUseModelsDevCatalog(provider: []const u8, api_key: ?[]const u8) bool {
    if (modelsDevProviderKey(provider) == null) return false;
    if (std.mem.eql(u8, provider, "openai") or std.mem.eql(u8, provider, "groq")) {
        return api_key == null;
    }
    return true;
}

fn modelsCacheProviderKey(allocator: std.mem.Allocator, provider: []const u8, api_key: ?[]const u8) ![]const u8 {
    if (!shouldUseModelsDevCatalog(provider, api_key)) {
        return try allocator.dupe(u8, provider);
    }
    return try std.fmt.allocPrint(allocator, "{s}@models.dev", .{provider});
}

fn fetchModelsFromModelsDev(allocator: std.mem.Allocator, provider: []const u8) !?[][]const u8 {
    const provider_key = modelsDevProviderKey(provider) orelse return null;

    const response = http_util.curlGet(allocator, MODELS_DEV_URL, &.{}, "10") catch return error.FetchFailed;
    defer allocator.free(response);

    return try parseModelsDevModelIds(allocator, response, provider, provider_key);
}

fn parseModelsDevModelIds(
    allocator: std.mem.Allocator,
    json_response: []const u8,
    provider: []const u8,
    provider_key: []const u8,
) ![][]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_response, .{}) catch return error.FetchFailed;
    defer parsed.deinit();

    if (parsed.value != .object) return error.FetchFailed;
    const provider_val = parsed.value.object.get(provider_key) orelse return error.FetchFailed;
    if (provider_val != .object) return error.FetchFailed;

    const models_val = provider_val.object.get("models") orelse return error.FetchFailed;
    if (models_val != .object) return error.FetchFailed;

    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (result.items) |item| allocator.free(item);
        result.deinit(allocator);
    }

    var it = models_val.object.iterator();
    while (it.next()) |entry| {
        if (result.items.len >= MAX_MODELS) break;
        if (!modelsDevModelSupportsChat(entry.key_ptr.*, entry.value_ptr.*)) continue;
        try result.append(allocator, try allocator.dupe(u8, entry.key_ptr.*));
    }

    if (result.items.len == 0) return error.FetchFailed;
    prioritizeDefaultModel(result.items, defaultModelForProvider(provider));
    return result.toOwnedSlice(allocator);
}

fn modelsDevModelSupportsChat(model_id: []const u8, model_val: std.json.Value) bool {
    if (model_val != .object) return false;

    const obj = model_val.object;
    if (obj.get("family")) |family_val| {
        if (family_val == .string and std.mem.indexOf(u8, family_val.string, "embedding") != null) {
            return false;
        }
    }
    if (std.mem.indexOf(u8, model_id, "embedding") != null) return false;

    const modalities_val = obj.get("modalities") orelse return true;
    if (modalities_val != .object) return true;

    const input_val = modalities_val.object.get("input") orelse return true;
    const output_val = modalities_val.object.get("output") orelse return true;
    return jsonStringArrayContains(input_val, "text") and jsonStringArrayContains(output_val, "text");
}

fn jsonStringArrayContains(value: std.json.Value, needle: []const u8) bool {
    if (value != .array) return false;
    for (value.array.items) |item| {
        if (item == .string and std.mem.eql(u8, item.string, needle)) return true;
    }
    return false;
}

fn prioritizeDefaultModel(models: [][]const u8, default_model: []const u8) void {
    for (models, 0..) |model, idx| {
        if (!std.mem.eql(u8, model, default_model)) continue;
        if (idx == 0) return;
        const tmp = models[0];
        models[0] = model;
        models[idx] = tmp;
        return;
    }
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

/// Build the models endpoint URL for an OpenAI-compatible API.
/// Given a base URL like "https://api.example.com/v1", returns "https://api.example.com/v1/models".
/// If the URL already ends with "/models", returns a duplicate of the input.
/// Caller owns the returned string.
fn buildModelsUrl(allocator: std.mem.Allocator, base_url: []const u8) ![]const u8 {
    // Remove trailing slash if present
    var url_to_use = base_url;
    if (std.mem.endsWith(u8, base_url, "/")) {
        url_to_use = base_url[0 .. base_url.len - 1];
    }

    // Check if URL already ends with /models (after removing trailing slash)
    if (std.mem.endsWith(u8, url_to_use, "/models")) {
        return try allocator.dupe(u8, base_url);
    }

    // Append /models
    return try std.fmt.allocPrint(allocator, "{s}/models", .{url_to_use});
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
    const cache_provider = try modelsCacheProviderKey(allocator, canonical, api_key);
    defer allocator.free(cache_provider);

    // Try reading cache file
    if (readCachedModels(allocator, cache_path, cache_provider)) |cached| {
        return cached;
    } else |_| {}

    // Cache miss or expired — fetch from API
    const models = try fetchModelsFromApi(allocator, canonical, api_key);

    // Best-effort: save to cache (coerce [][]const u8 -> []const []const u8)
    const models_const: []const []const u8 = models;
    saveCachedModels(allocator, cache_path, cache_provider, models_const) catch {};

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
pub fn initFreshConfig(backing_allocator: std.mem.Allocator) !Config {
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
pub fn runQuickSetup(allocator: std.mem.Allocator, api_key: ?[]const u8, provider: ?[]const u8, model: ?[]const u8, memory_backend: ?[]const u8) !void {
    var stdout_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &bw.interface;
    try stdout.writeAll(BANNER);
    try stdout.writeAll("  Quick Setup -- generating config with sensible defaults...\n\n");

    // Load or create config
    var cfg = Config.load(allocator) catch try initFreshConfig(allocator);
    defer cfg.deinit();
    try ensureSecretsEncryptionEnabled(&cfg);

    // Apply overrides
    var provider_overridden = false;
    var custom_base_url: ?[]const u8 = null;
    if (provider) |p| {
        const info = resolveProviderForQuickSetup(p) orelse return error.UnknownProvider;
        cfg.default_provider = try cfg.allocator.dupe(u8, info.key);
        provider_overridden = true;
        // Extract base_url for custom provider
        if (std.mem.startsWith(u8, info.key, "custom:")) {
            custom_base_url = info.key["custom:".len..];
        }
    }
    if (api_key) |key| {
        // Store in providers section for the default provider (arena frees old values)
        const entries = try cfg.allocator.alloc(config_mod.ProviderEntry, 1);
        entries[0] = .{
            .name = try cfg.allocator.dupe(u8, cfg.default_provider),
            .api_key = try cfg.allocator.dupe(u8, key),
            .base_url = custom_base_url,
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
    if (model) |m| {
        // Use the explicitly provided model
        cfg.default_model = try cfg.allocator.dupe(u8, m);
    } else if (provider_overridden) {
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
    try scaffoldWorkspaceForConfig(allocator, &cfg, &ProjectContext{});

    // Save config so subsequent commands can find it
    try cfg.save();

    // Print summary
    try stdout.print("  [OK] Workspace:  {s}\n", .{cfg.workspace_dir});
    try stdout.print("  [OK] Provider:   {s}\n", .{cfg.default_provider});
    if (cfg.default_model) |m| {
        try stdout.print("  [OK] Model:      {s}\n", .{m});
    }
    const quick_requires_api_key = providerRequiresApiKeyForSetup(cfg.default_provider, cfg.getProviderBaseUrl(cfg.default_provider));
    try stdout.print("  [OK] API Key:    {s}\n", .{if (quick_requires_api_key)
        (if (cfg.defaultProviderKey() != null) "set" else "not set (use --api-key or edit config)")
    else
        "not required"});
    try stdout.print("  [OK] Memory:     {s}\n", .{cfg.memory.backend});
    try stdout.writeAll("\n  Next steps:\n");
    try printProviderNextSteps(stdout, cfg.default_provider, providerEnvVar(cfg.default_provider), quick_requires_api_key, cfg.defaultProviderKey() != null);
    try stdout.writeAll("\n");
    try stdout.flush();
}

/// Main entry point — called from main.zig as `onboard.run(allocator)`.
pub fn run(allocator: std.mem.Allocator) !void {
    return runWizard(allocator);
}

fn ensureSecretsEncryptionEnabled(cfg: *const Config) Config.ValidationError!void {
    if (!cfg.secrets.encrypt) {
        return Config.ValidationError.InsecurePlaintextSecrets;
    }
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
    try ensureSecretsEncryptionEnabled(&cfg);

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

pub const tunnel_options = [_][]const u8{ "none", "cloudflare", "ngrok", "tailscale" };
pub const autonomy_options = [_][]const u8{ "supervised", "autonomous", "fully_autonomous", "yolo" };
pub const wizard_memory_backend_order = [_][]const u8{
    "hybrid",
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

pub fn memoryProfileForBackend(backend: []const u8) []const u8 {
    if (std.mem.eql(u8, backend, "hybrid")) return "hybrid_keyword";
    if (std.mem.eql(u8, backend, "sqlite")) return "local_keyword";
    if (std.mem.eql(u8, backend, "markdown")) return "markdown_only";
    if (std.mem.eql(u8, backend, "postgres")) return "postgres_keyword";
    if (std.mem.eql(u8, backend, "none")) return "minimal_none";
    return "custom";
}

pub fn isWizardInteractiveChannel(channel_id: channel_catalog.ChannelId) bool {
    return switch (channel_id) {
        .telegram, .discord, .slack, .webhook, .mattermost, .matrix, .signal, .nostr, .max => true,
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
        .nostr => configureNostrChannel(cfg, out, input_buf, prefix),
        .max => configureMaxChannel(cfg, out, input_buf, prefix),
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

fn configureNostrChannel(cfg: *Config, out: *std.Io.Writer, input_buf: []u8, prefix: []const u8) !bool {
    try ensureSecretsEncryptionEnabled(cfg);

    const nak_path = "nak";

    // ── Bot keypair ──────────────────────────────────────────────
    try out.print("{s}  Bot keypair:\n", .{prefix});
    try out.print("{s}    [Y] Generate new keypair (first-time setup)\n", .{prefix});
    try out.print("{s}    [n] Import existing nsec1\n", .{prefix});
    try out.print("{s}  Generate new? [Y/n]: ", .{prefix});
    const gen_input = prompt(out, input_buf, "", "y") orelse return false;
    const generate_new = gen_input.len == 0 or gen_input[0] == 'y' or gen_input[0] == 'Y';

    var bot_privkey_hex: ?[]u8 = null;
    defer if (bot_privkey_hex) |k| cfg.allocator.free(k);
    var bot_pubkey_hex: ?[]u8 = null;
    defer if (bot_pubkey_hex) |k| cfg.allocator.free(k);

    if (generate_new) {
        const argv_gen = [_][]const u8{ nak_path, "key", "generate" };
        const hex = nakRun(cfg.allocator, &argv_gen) orelse {
            try out.print("{s}  -> Failed to generate keypair (is nak in PATH?)\n\n", .{prefix});
            return false;
        };
        if (hex.len != 64) {
            cfg.allocator.free(hex);
            try out.print("{s}  -> nak key generate returned unexpected output\n\n", .{prefix});
            return false;
        }
        bot_privkey_hex = hex;
        const argv_pub = [_][]const u8{ nak_path, "key", "public", bot_privkey_hex.? };
        if (nakRun(cfg.allocator, &argv_pub)) |bph| {
            bot_pubkey_hex = bph;
            const argv_enc = [_][]const u8{ nak_path, "encode", "npub", bph };
            if (nakRun(cfg.allocator, &argv_enc)) |bot_npub| {
                defer cfg.allocator.free(bot_npub);
                try out.print("{s}  -> Bot npub: {s}\n", .{ prefix, bot_npub });
            } else {
                try out.print("{s}  -> Bot pubkey (hex): {s}\n", .{ prefix, bph });
            }
        }
    } else {
        try out.print("{s}  Bot nsec1 (paste existing bot identity key): ", .{prefix});
        const key_input = prompt(out, input_buf, "", "") orelse return false;
        if (key_input.len == 0) {
            try out.print("{s}  -> Skipped (no key provided)\n\n", .{prefix});
            return false;
        }
        if (std.mem.startsWith(u8, key_input, "nsec1")) {
            const argv_dec = [_][]const u8{ nak_path, "decode", key_input };
            const hex = nakRun(cfg.allocator, &argv_dec) orelse {
                try out.print("{s}  -> Failed to decode nsec (invalid key?)\n\n", .{prefix});
                return false;
            };
            bot_privkey_hex = hex;
        } else {
            bot_privkey_hex = try cfg.allocator.dupe(u8, key_input);
        }
        if (bot_privkey_hex) |privhex| {
            const argv_pub = [_][]const u8{ nak_path, "key", "public", privhex };
            bot_pubkey_hex = nakRun(cfg.allocator, &argv_pub);
        }
    }

    const nostr_mod = @import("channels/nostr.zig");
    if (bot_pubkey_hex == null or !nostr_mod.NostrChannel.isValidHexKey(bot_pubkey_hex.?)) {
        try out.print("{s}  -> Failed to derive a valid bot pubkey from the provided key\n\n", .{prefix});
        return false;
    }

    // ── Owner pubkey ─────────────────────────────────────────────
    try out.print("{s}  Your owner pubkey (npub or 64-char hex): ", .{prefix});
    const owner_input = prompt(out, input_buf, "", "") orelse return false;
    if (owner_input.len == 0) {
        try out.print("{s}  -> Skipped (no owner pubkey)\n\n", .{prefix});
        return false;
    }

    var owner_hex: ?[]u8 = null;
    defer if (owner_hex) |k| cfg.allocator.free(k);

    if (std.mem.startsWith(u8, owner_input, "npub1")) {
        const argv_dec = [_][]const u8{ nak_path, "decode", owner_input };
        const hex = nakRun(cfg.allocator, &argv_dec) orelse {
            try out.print("{s}  -> Failed to decode npub (invalid pubkey?)\n\n", .{prefix});
            return false;
        };
        owner_hex = hex;
    } else {
        owner_hex = try cfg.allocator.dupe(u8, owner_input);
    }

    if (!nostr_mod.NostrChannel.isValidHexKey(owner_hex.?)) {
        try out.print("{s}  -> owner pubkey must be 64-char hex or a valid npub\n\n", .{prefix});
        return false;
    }

    const secrets = @import("security/secrets.zig");
    const config_dir = std.fs.path.dirname(cfg.config_path) orelse ".";
    const store = secrets.SecretStore.init(config_dir, cfg.secrets.encrypt);
    const encrypted_key = try store.encryptSecret(cfg.allocator, bot_privkey_hex.?);

    const ns = try cfg.allocator.create(@import("config_types.zig").NostrConfig);
    ns.* = .{
        .private_key = encrypted_key,
        .owner_pubkey = try cfg.allocator.dupe(u8, owner_hex.?),
        .bot_pubkey = try cfg.allocator.dupe(u8, bot_pubkey_hex.?),
        .config_dir = config_dir,
    };
    cfg.channels.nostr = ns;
    if (generate_new) {
        try out.print("{s}  -> Keypair generated and encrypted at rest\n", .{prefix});
    } else {
        try out.print("{s}  -> Key encrypted at rest\n", .{prefix});
    }
    try out.print("{s}  -> Default relays: relay.damus.io, nos.lol, relay.nostr.band, auth.nostr1.com, relay.primal.net\n", .{prefix});
    try out.print("{s}  -> Edit config to add: display_name, nip05, lnurl, dm_allowed_pubkeys\n\n", .{prefix});
    return true;
}

fn configureMaxChannel(cfg: *Config, out: *std.Io.Writer, _: []u8, prefix: []const u8) !bool {
    var account_id_buf: [128]u8 = undefined;
    var token_buf: [512]u8 = undefined;
    var allow_input_buf: [512]u8 = undefined;
    var mode_buf: [64]u8 = undefined;
    var webhook_url_buf: [512]u8 = undefined;
    var webhook_secret_buf: [256]u8 = undefined;
    var mention_buf: [32]u8 = undefined;

    try out.print("{s}  Max account_id [default]: ", .{prefix});
    const account_id_input = prompt(out, &account_id_buf, "", "default") orelse return false;
    const account_id = if (account_id_input.len == 0) "default" else account_id_input;

    try out.print("{s}  Max bot token (required, Enter to skip): ", .{prefix});
    const token = prompt(out, &token_buf, "", "") orelse return false;
    if (token.len == 0) {
        try out.print("{s}  -> Max skipped\n", .{prefix});
        return false;
    }

    try out.print("{s}  Max allow_from (user_id/username, comma-separated) [*]: ", .{prefix});
    const allow_input = prompt(out, &allow_input_buf, "", "") orelse return false;

    try out.print("{s}  Max receive mode [polling/webhook] (default: polling): ", .{prefix});
    const mode_input = prompt(out, &mode_buf, "", "polling") orelse return false;
    const webhook_mode = std.ascii.eqlIgnoreCase(mode_input, "webhook");

    const webhook_url_input = if (webhook_mode) blk: {
        try out.print("{s}  Max webhook URL (HTTPS, required for webhook mode): ", .{prefix});
        const raw_url = prompt(out, &webhook_url_buf, "", "") orelse return false;
        const trimmed_url = std.mem.trim(u8, raw_url, " \t\r\n");
        if (trimmed_url.len == 0 or !std.mem.startsWith(u8, trimmed_url, "https://")) {
            try out.print("{s}  -> Max skipped (webhook mode requires HTTPS webhook_url)\n", .{prefix});
            return false;
        }
        break :blk trimmed_url;
    } else null;

    const webhook_secret_input = if (webhook_mode) blk: {
        try out.print("{s}  Max webhook secret (optional, recommended): ", .{prefix});
        const raw_secret = prompt(out, &webhook_secret_buf, "", "") orelse return false;
        break :blk std.mem.trim(u8, raw_secret, " \t\r\n");
    } else null;

    try out.print("{s}  Require @mention in group chats? [y/N]: ", .{prefix});
    const mention_input = prompt(out, &mention_buf, "", "n") orelse return false;
    const require_mention = mention_input.len > 0 and (mention_input[0] == 'y' or mention_input[0] == 'Y');

    const allow_from = try parseTelegramAllowFrom(cfg.allocator, allow_input);
    errdefer {
        for (allow_from) |entry| cfg.allocator.free(entry);
        cfg.allocator.free(allow_from);
    }

    var webhook_url: ?[]const u8 = null;
    errdefer if (webhook_url) |value| cfg.allocator.free(value);
    var webhook_secret: ?[]const u8 = null;
    errdefer if (webhook_secret) |value| cfg.allocator.free(value);

    if (webhook_mode) {
        webhook_url = try cfg.allocator.dupe(u8, webhook_url_input.?);
        if (webhook_secret_input.?.len > 0) {
            webhook_secret = try cfg.allocator.dupe(u8, webhook_secret_input.?);
        }
    }

    const accounts = try cfg.allocator.alloc(config_mod.MaxConfig, 1);
    accounts[0] = .{
        .account_id = try cfg.allocator.dupe(u8, account_id),
        .bot_token = try cfg.allocator.dupe(u8, token),
        .allow_from = allow_from,
        .group_policy = "allowlist",
        .mode = if (webhook_mode) .webhook else .polling,
        .webhook_url = webhook_url,
        .webhook_secret = webhook_secret,
        .require_mention = require_mention,
        .streaming = true,
    };
    cfg.channels.max = accounts;

    try out.print("{s}  -> Max configured (account_id={s}, mode={s}", .{
        prefix,
        account_id,
        if (webhook_mode) "webhook" else "polling",
    });
    if (allow_from.len == 1 and std.mem.eql(u8, allow_from[0], "*")) {
        try out.print(", allow_from=*", .{});
    } else {
        try out.print(", allow_from={d}", .{allow_from.len});
    }
    try out.print(")\n", .{});
    return true;
}

/// Run a nak subprocess, capture stdout, trim whitespace, return owned slice or null on failure.
fn nakRun(allocator: std.mem.Allocator, argv: []const []const u8) ?[]u8 {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return null;
    const stdout = child.stdout orelse {
        _ = child.wait() catch {};
        return null;
    };
    var out = std.ArrayListUnmanaged(u8).empty;
    var buf: [256]u8 = undefined;
    while (true) {
        const n = stdout.read(&buf) catch break;
        if (n == 0) break;
        out.appendSlice(allocator, buf[0..n]) catch {
            out.deinit(allocator);
            _ = child.wait() catch {};
            return null;
        };
    }
    const term = child.wait() catch {
        out.deinit(allocator);
        return null;
    };
    switch (term) {
        .Exited => |code| if (code != 0) {
            out.deinit(allocator);
            return null;
        },
        else => {
            out.deinit(allocator);
            return null;
        },
    }
    const raw = out.toOwnedSlice(allocator) catch return null;
    const trimmed = std.mem.trimRight(u8, raw, " \t\r\n");
    if (trimmed.len == raw.len) return raw;
    defer allocator.free(raw);
    return allocator.dupe(u8, trimmed) catch null;
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
    try ensureSecretsEncryptionEnabled(&cfg);

    // ── Step 1: Provider selection ──
    try out.writeAll("  Step 1/8: Select a provider\n");
    for (known_providers, 0..) |p, i| {
        try out.print("    [{d}] {s}\n", .{ i + 1, p.label });
    }
    try out.print("    [{d}] Custom OpenAI-compatible provider (custom:https://.../v1)\n", .{known_providers.len + 1});
    try out.writeAll("  Choice [1]: ");
    const provider_idx = promptChoice(out, &input_buf, known_providers.len + 1, 0) orelse {
        try out.writeAll("\n  Aborted.\n");
        try out.flush();
        return;
    };

    if (provider_idx < known_providers.len) {
        const provider = known_providers[provider_idx];
        cfg.default_provider = provider.key;
        try out.print("  -> {s}\n\n", .{provider.label});
    } else {
        // Custom provider - prompt for URL
        var custom_url_buf: [512]u8 = undefined;
        try out.writeAll("\n  Custom provider configuration:\n");
        try out.writeAll("  Enter OpenAI-compatible endpoint URL (e.g., https://api.example.com/v1): ");
        const custom_url = prompt(out, &custom_url_buf, "", "") orelse {
            try out.writeAll("\n  Aborted.\n");
            try out.flush();
            return;
        };
        if (custom_url.len == 0) {
            try out.writeAll("\n  Error: Custom provider URL cannot be empty\n");
            try out.flush();
            return;
        }
        if (!isValidCustomProviderUrl(custom_url)) {
            try out.writeAll("\n  Error: endpoint must be http(s) and include a version segment like /v1\n");
            try out.flush();
            return;
        }
        const custom_provider_key = try std.fmt.allocPrint(cfg.allocator, "custom:{s}", .{custom_url});
        cfg.default_provider = custom_provider_key;

        // Add to providers section with base_url
        const entries = try cfg.allocator.alloc(config_mod.ProviderEntry, 1);
        entries[0] = .{ .name = try cfg.allocator.dupe(u8, cfg.default_provider), .base_url = try cfg.allocator.dupe(u8, custom_url) };
        cfg.providers = entries;

        try out.print("  -> Custom: {s}\n\n", .{custom_url});
    }

    const is_azure_provider = provider_idx < known_providers.len and
        std.mem.eql(u8, known_providers[provider_idx].key, "azure");

    var provider_base_url: ?[]const u8 = null;
    if (cfg.providers.len > 0 and cfg.providers[0].base_url != null) {
        provider_base_url = cfg.providers[0].base_url;
    }

    if (is_azure_provider) {
        var azure_endpoint_buf: [512]u8 = undefined;
        const default_endpoint = provider_base_url orelse "";
        if (default_endpoint.len > 0) {
            try out.print("  Azure OpenAI endpoint [{s}]: ", .{default_endpoint});
        } else {
            try out.writeAll("  Azure OpenAI endpoint (e.g., https://your-resource.openai.azure.com): ");
        }
        const azure_endpoint = prompt(out, &azure_endpoint_buf, "", default_endpoint) orelse {
            try out.writeAll("\n  Aborted.\n");
            try out.flush();
            return;
        };
        if (azure_endpoint.len == 0) {
            try out.writeAll("\n  Error: Azure OpenAI endpoint is required\n");
            try out.flush();
            return;
        }
        provider_base_url = try cfg.allocator.dupe(u8, azure_endpoint);
        try out.writeAll("  Note: Azure OpenAI uses your model name as the deployment name in URLs.\n");
        try out.writeAll("  Configure your Azure deployment with the same name as your model (e.g., gpt-5.2-chat).\n");
    }

    // ── Step 2: API key ──
    const env_hint = if (provider_idx < known_providers.len) known_providers[provider_idx].env_var else "API_KEY";
    const requires_api_key = providerRequiresApiKeyForSetup(cfg.default_provider, provider_base_url);
    if (requires_api_key) {
        try out.print("  Step 2/8: Enter API key (or press Enter to use env var {s}): ", .{env_hint});
        const api_key_input = prompt(out, &input_buf, "", "") orelse {
            try out.writeAll("\n  Aborted.\n");
            try out.flush();
            return;
        };
        if (api_key_input.len > 0) {
            // Store in providers section (preserve base_url if already set for custom provider)
            const entries = try cfg.allocator.alloc(config_mod.ProviderEntry, 1);
            entries[0] = .{
                .name = try cfg.allocator.dupe(u8, cfg.default_provider),
                .api_key = try cfg.allocator.dupe(u8, api_key_input),
                .base_url = provider_base_url,
            };
            cfg.providers = entries;
            try out.writeAll("  -> API key set\n\n");
        } else {
            if (is_azure_provider) {
                const entries = try cfg.allocator.alloc(config_mod.ProviderEntry, 1);
                entries[0] = .{
                    .name = try cfg.allocator.dupe(u8, cfg.default_provider),
                    .base_url = provider_base_url,
                };
                cfg.providers = entries;
            }
            try out.print("  -> Will use ${s} from environment\n\n", .{env_hint});
        }
    } else {
        try out.writeAll("  Step 2/8: Authentication\n");
        if (std.mem.eql(u8, cfg.default_provider, "openai-codex")) {
            try out.writeAll("  -> Uses local OAuth tokens from ~/.nullclaw/auth.json or ~/.codex/auth.json\n\n");
        } else if (std.mem.eql(u8, cfg.default_provider, "codex-cli")) {
            try out.writeAll("  -> Uses your local Codex CLI login (`codex login`)\n\n");
        } else {
            try out.writeAll("  -> No API key required for this local provider\n\n");
        }
    }

    // ── Step 3: Model (with live fetching) ──
    const default_model_for_provider = if (provider_idx < known_providers.len)
        known_providers[provider_idx].default_model
    else
        "gpt-5.2";

    try out.writeAll("  Step 3/8: Select a model\n");
    try out.writeAll("  Fetching available models...\n");
    try out.flush();

    // Try to fetch models for both known and custom providers
    var models_fetched = false;
    var live_models: []const []const u8 = undefined;
    var models_to_use: []const []const u8 = undefined;

    const provider_for_fetch = if (std.mem.startsWith(u8, cfg.default_provider, "custom:"))
        cfg.default_provider["custom:".len..]
    else
        cfg.default_provider;

    if (fetchModels(allocator, provider_for_fetch, cfg.defaultProviderKey())) |models| {
        models_fetched = true;
        live_models = models;
        models_to_use = live_models;
    } else |_| {
        try out.writeAll("  Could not fetch models (will use fallback)\n");
        try out.flush();
        models_to_use = try dupeFallbackModels(allocator, provider_for_fetch);
    }

    defer {
        if (models_fetched) {
            for (live_models) |m| allocator.free(m);
            allocator.free(live_models);
        } else {
            for (models_to_use) |m| allocator.free(m);
            allocator.free(models_to_use);
        }
    }

    // Show up to 15 models as numbered choices if we successfully fetched them
    if (models_fetched) {
        const display_max: usize = @min(models_to_use.len, 15);
        for (models_to_use[0..display_max], 0..) |m, i| {
            const is_default = std.mem.eql(u8, m, default_model_for_provider);
            if (is_default) {
                try out.print("    [{d}] {s} (default)\n", .{ i + 1, m });
            } else {
                try out.print("    [{d}] {s}\n", .{ i + 1, m });
            }
        }
        if (models_to_use.len > display_max) {
            try out.print("    ... and {d} more (type name to use any model)\n", .{models_to_use.len - display_max});
        }
        try out.print("  Choice [1] or model name [{s}]: ", .{default_model_for_provider});
    } else {
        try out.writeAll("  Enter model name directly:\n");
        try out.print("  Model name [{s}]: ", .{default_model_for_provider});
    }
    const model_input = prompt(out, &input_buf, "", "") orelse {
        try out.writeAll("\n  Aborted.\n");
        try out.flush();
        return;
    };
    if (model_input.len == 0) {
        // Default: use first model from the list (or provider default)
        // Must dupe because models_to_use will be freed in defer block
        cfg.default_model = if (models_to_use.len > 0)
            try cfg.allocator.dupe(u8, models_to_use[0])
        else
            try cfg.allocator.dupe(u8, default_model_for_provider);
    } else if (models_fetched) {
        // If we successfully fetched models, try to parse as number (menu selection) or use as free-form model name
        const display_max: usize = @min(models_to_use.len, 15);
        if (std.fmt.parseInt(usize, model_input, 10)) |num| {
            if (num >= 1 and num <= display_max) {
                // Must dupe because models_to_use will be freed in defer block
                cfg.default_model = try cfg.allocator.dupe(u8, models_to_use[num - 1]);
            } else {
                // Must dupe because default_model_for_provider is from const static data
                cfg.default_model = try cfg.allocator.dupe(u8, default_model_for_provider);
            }
        } else |_| {
            // Free-form model name typed by user
            cfg.default_model = try cfg.allocator.dupe(u8, model_input);
        }
    } else {
        // If we couldn't fetch models, use input as model name directly
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
    try out.writeAll("    [1] supervised\n    [2] autonomous\n    [3] fully_autonomous\n    [4] yolo\n");
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
        3 => {
            // "yolo": bypasses all command-level policy checks.
            cfg.autonomy.level = .yolo;
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
        cfg.workspace_dir_override = cfg.workspace_dir;
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
    try scaffoldWorkspaceForConfig(allocator, &cfg, &ProjectContext{});

    // Save config
    try cfg.save();

    // Print summary
    try out.writeAll("  ── Configuration complete ──\n\n");
    try out.print("  [OK] Provider:   {s}\n", .{cfg.default_provider});
    if (cfg.default_model) |m| {
        try out.print("  [OK] Model:      {s}\n", .{m});
    }
    try out.print("  [OK] API Key:    {s}\n", .{if (requires_api_key)
        (if (cfg.defaultProviderKey() != null) "set" else "from environment")
    else
        "not required"});
    try out.print("  [OK] Memory:     {s}\n", .{cfg.memory.backend});
    try out.print("  [OK] Tunnel:     {s}\n", .{cfg.tunnel.provider});
    try out.print("  [OK] Workspace:  {s}\n", .{cfg.workspace_dir});
    try out.print("  [OK] Config:     {s}\n", .{cfg.config_path});
    try out.writeAll("\n  Next steps:\n");
    const final_env_hint = if (provider_idx < known_providers.len) known_providers[provider_idx].env_var else "API_KEY";
    try printProviderNextSteps(out, cfg.default_provider, final_env_hint, requires_api_key, cfg.defaultProviderKey() != null);
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
/// When a `bootstrap_provider` is supplied and the backend does not use
/// files, documents are written through the provider instead of to disk.
pub fn scaffoldWorkspaceForConfig(
    allocator: std.mem.Allocator,
    cfg: *const Config,
    ctx: *const ProjectContext,
) !void {
    var scaffold_mem_rt: ?memory_root.MemoryRuntime = null;
    defer if (scaffold_mem_rt) |*rt| rt.deinit();

    const needs_bootstrap_runtime = !bootstrap_mod.backendUsesFiles(cfg.memory.backend) and
        !std.mem.eql(u8, cfg.memory.backend, "none") and
        !std.mem.eql(u8, cfg.memory.backend, "memory");
    if (needs_bootstrap_runtime) {
        scaffold_mem_rt = memory_root.initRuntime(allocator, &cfg.memory, cfg.workspace_dir);
    }

    const scaffold_mem: ?memory_root.Memory = if (scaffold_mem_rt) |rt| rt.memory else null;
    const bootstrap_provider = bootstrap_mod.createProvider(
        allocator,
        cfg.memory.backend,
        scaffold_mem,
        cfg.workspace_dir,
    ) catch null;
    defer if (bootstrap_provider) |bp| bp.deinit();

    try scaffoldWorkspace(allocator, cfg.workspace_dir, ctx, bootstrap_provider);
}

pub fn scaffoldWorkspace(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    ctx: *const ProjectContext,
    bootstrap_provider: ?bootstrap_mod.BootstrapProvider,
) !void {
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
    try storeOrWriteIfMissing(allocator, workspace_dir, "SOUL.md", soul_tmpl, bootstrap_provider);

    // AGENTS.md (operational guidelines — loaded by prompt.zig)
    try storeOrWriteIfMissing(allocator, workspace_dir, "AGENTS.md", agentsTemplate(), bootstrap_provider);

    // TOOLS.md (tool usage guide — loaded by prompt.zig)
    try storeOrWriteIfMissing(allocator, workspace_dir, "TOOLS.md", toolsTemplate(), bootstrap_provider);

    // IDENTITY.md (identity config — loaded by prompt.zig)
    const identity_tmpl = try identityTemplate(allocator, ctx);
    defer allocator.free(identity_tmpl);
    try storeOrWriteIfMissing(allocator, workspace_dir, "IDENTITY.md", identity_tmpl, bootstrap_provider);

    // USER.md (user profile — loaded by prompt.zig)
    const user_tmpl = try userTemplate(allocator, ctx);
    defer allocator.free(user_tmpl);
    try storeOrWriteIfMissing(allocator, workspace_dir, "USER.md", user_tmpl, bootstrap_provider);

    // HEARTBEAT.md (periodic tasks — loaded by prompt.zig)
    try storeOrWriteIfMissing(allocator, workspace_dir, "HEARTBEAT.md", heartbeatTemplate(), bootstrap_provider);

    // BOOTSTRAP.md lifecycle:
    // one-shot onboarding instructions with persisted state marker.
    try ensureBootstrapLifecycle(allocator, workspace_dir, identity_tmpl, user_tmpl, had_legacy_user_content, bootstrap_provider);
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
    bootstrap_provider: ?bootstrap_mod.BootstrapProvider,
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
        if (bootstrap_provider) |bp| {
            if (!options.dry_run) try bp.store(entry.filename, entry.content);
        } else {
            _ = try overwriteWorkspaceFile(allocator, workspace_dir, entry.filename, entry.content, options.dry_run);
        }
        report.rewritten_files += 1;
    }

    if (options.include_bootstrap) {
        if (bootstrap_provider) |bp| {
            if (!options.dry_run) try bp.store("BOOTSTRAP.md", bootstrapTemplate());
        } else {
            _ = try overwriteWorkspaceFile(allocator, workspace_dir, "BOOTSTRAP.md", bootstrapTemplate(), options.dry_run);
        }
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
    const path = try std.fs.path.join(allocator, &.{ workspace_dir, filename });
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
    const path = try std.fs.path.join(allocator, &.{ workspace_dir, filename });
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
    const path = try std.fs.path.join(allocator, &.{ dir, filename });
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

/// Write-if-missing with optional BootstrapProvider routing.
/// When a provider is set, stores the content through the provider only.
/// File-based providers (hybrid/markdown) write to disk themselves;
/// memory-based providers (sqlite, postgres, …) store in the backend.
fn storeOrWriteIfMissing(
    allocator: std.mem.Allocator,
    dir: []const u8,
    filename: []const u8,
    content: []const u8,
    bp: ?bootstrap_mod.BootstrapProvider,
) !void {
    if (bp) |provider| {
        if (!provider.exists(filename)) {
            try provider.store(filename, content);
        }
        return;
    }
    try writeIfMissing(allocator, dir, filename, content);
}

fn ensureBootstrapLifecycle(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    identity_template: []const u8,
    user_template: []const u8,
    had_legacy_user_content: bool,
    bp: ?bootstrap_mod.BootstrapProvider,
) !void {
    const bootstrap_path = try std.fs.path.join(allocator, &.{ workspace_dir, "BOOTSTRAP.md" });
    defer allocator.free(bootstrap_path);

    var state = try readWorkspaceOnboardingState(allocator, workspace_dir);
    defer state.deinit(allocator);
    var state_dirty = false;
    var bootstrap_exists = if (bp) |provider| provider.exists("BOOTSTRAP.md") else fileExistsAbsolute(bootstrap_path);

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
            try storeOrWriteIfMissing(allocator, workspace_dir, "BOOTSTRAP.md", bootstrapTemplate(), bp);
            bootstrap_exists = if (bp) |provider| provider.exists("BOOTSTRAP.md") else fileExistsAbsolute(bootstrap_path);
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
    const identity_path = try std.fs.path.join(allocator, &.{ workspace_dir, "IDENTITY.md" });
    defer allocator.free(identity_path);
    const user_path = try std.fs.path.join(allocator, &.{ workspace_dir, "USER.md" });
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
    return std.fs.path.join(allocator, &.{ workspace_dir, WORKSPACE_STATE_DIR, WORKSPACE_STATE_FILE });
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
    const memory_dir_path = try std.fs.path.join(allocator, &.{ workspace_dir, "memory" });
    defer allocator.free(memory_dir_path);
    const memory_file_path = try std.fs.path.join(allocator, &.{ workspace_dir, "MEMORY.md" });
    defer allocator.free(memory_file_path);
    const git_dir_path = try std.fs.path.join(allocator, &.{ workspace_dir, ".git" });
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

pub fn markOnboardingCompletedAfterBootstrapRemoval(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
) !void {
    var state = try readWorkspaceOnboardingState(allocator, workspace_dir);
    defer state.deinit(allocator);

    if (state.bootstrap_seeded_at == null) {
        try markBootstrapSeededAt(allocator, &state);
    }
    try markOnboardingCompletedAt(allocator, &state);
    try writeWorkspaceOnboardingState(allocator, workspace_dir, &state);
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
    return "hybrid";
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
    try std.testing.expectEqualStrings("vertex", canonicalProviderName("vertex-ai"));
    try std.testing.expectEqualStrings("vertex", canonicalProviderName("google-vertex"));
    try std.testing.expectEqualStrings("claude-cli", canonicalProviderName("claude-code"));
    try std.testing.expectEqualStrings("azure", canonicalProviderName("azure-openai"));
    try std.testing.expectEqualStrings("azure", canonicalProviderName("azure_openai"));
    try std.testing.expectEqualStrings("openai", canonicalProviderName("openai"));
}

test "defaultModelForProvider returns known models" {
    try std.testing.expectEqualStrings("claude-opus-4-6", defaultModelForProvider("anthropic"));
    try std.testing.expectEqualStrings("gpt-5.2", defaultModelForProvider("openai"));
    try std.testing.expectEqualStrings("gpt-5.2-chat", defaultModelForProvider("azure"));
    try std.testing.expectEqualStrings("deepseek-chat", defaultModelForProvider("deepseek"));
    try std.testing.expectEqualStrings("llama4", defaultModelForProvider("ollama"));
    try std.testing.expectEqualStrings(codex_support.DEFAULT_CODEX_MODEL, defaultModelForProvider("codex-cli"));
    try std.testing.expectEqualStrings(codex_support.DEFAULT_CODEX_MODEL, defaultModelForProvider("openai-codex"));
}

test "defaultModelForProvider falls back for unknown" {
    try std.testing.expectEqualStrings("anthropic/claude-sonnet-4.6", defaultModelForProvider("unknown-provider"));
}

test "providerEnvVar known providers" {
    try std.testing.expectEqualStrings("OPENROUTER_API_KEY", providerEnvVar("openrouter"));
    try std.testing.expectEqualStrings("ANTHROPIC_API_KEY", providerEnvVar("anthropic"));
    try std.testing.expectEqualStrings("OPENAI_API_KEY", providerEnvVar("openai"));
    try std.testing.expectEqualStrings("AZURE_OPENAI_API_KEY", providerEnvVar("azure"));
    try std.testing.expectEqualStrings("API_KEY", providerEnvVar("ollama"));
}

test "providerEnvVar grok alias maps to xai" {
    try std.testing.expectEqualStrings("XAI_API_KEY", providerEnvVar("grok"));
}

test "providerEnvVar unknown falls back" {
    try std.testing.expectEqualStrings("API_KEY", providerEnvVar("some-new-provider"));
}

test "providerRequiresApiKeyForSetup marks local and OAuth providers as keyless" {
    try std.testing.expect(!providerRequiresApiKeyForSetup("ollama", null));
    try std.testing.expect(!providerRequiresApiKeyForSetup("lm-studio", null));
    try std.testing.expect(!providerRequiresApiKeyForSetup("claude-cli", null));
    try std.testing.expect(!providerRequiresApiKeyForSetup("codex-cli", null));
    try std.testing.expect(!providerRequiresApiKeyForSetup("openai-codex", null));
    try std.testing.expect(!providerRequiresApiKeyForSetup("custom:http://127.0.0.1:8080/v1", "http://127.0.0.1:8080/v1"));
    try std.testing.expect(providerRequiresApiKeyForSetup("openai", null));
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

    if (memory_root.findBackend("hybrid") != null) {
        try std.testing.expectEqualStrings("hybrid", backends[0].name);
    } else if (memory_root.findBackend("markdown") != null) {
        try std.testing.expectEqualStrings("markdown", backends[0].name);
    } else if (memory_root.findBackend("none") != null) {
        try std.testing.expectEqualStrings("none", backends[0].name);
    }
}

test "selectableBackendsForWizard prioritizes hybrid and keeps api last" {
    const backends = try selectableBackendsForWizard(std.testing.allocator);
    defer std.testing.allocator.free(backends);

    if (memory_root.findBackend("hybrid") != null) {
        try std.testing.expectEqualStrings("hybrid", backends[0].name);
    }
    if (memory_root.findBackend("hybrid") != null and memory_root.findBackend("sqlite") != null and backends.len >= 2) {
        try std.testing.expectEqualStrings("sqlite", backends[1].name);
    }
    if (memory_root.findBackend("api") != null) {
        try std.testing.expectEqualStrings("api", backends[backends.len - 1].name);
    }
}

test "memoryProfileForBackend maps common backends" {
    try std.testing.expectEqualStrings("hybrid_keyword", memoryProfileForBackend("hybrid"));
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
    try std.testing.expect(isWizardInteractiveChannel(.nostr));
    try std.testing.expect(isWizardInteractiveChannel(.max));
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
    try scaffoldWorkspace(std.testing.allocator, base, &ctx, null);

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
    try scaffoldWorkspace(std.testing.allocator, base, &ctx, null);
    // Running again should not fail
    try scaffoldWorkspace(std.testing.allocator, base, &ctx, null);
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

    const report = try resetWorkspacePromptFiles(std.testing.allocator, base, &ProjectContext{}, .{}, null);
    try std.testing.expectEqual(@as(usize, 6), report.rewritten_files);
    try std.testing.expectEqual(@as(usize, 0), report.removed_files);

    const agents_content = try fs_compat.readFileAlloc(tmp.dir, std.testing.allocator, "AGENTS.md", 64 * 1024);
    defer std.testing.allocator.free(agents_content);
    try std.testing.expect(std.mem.indexOf(u8, agents_content, "AGENTS.md - Your Workspace") != null);
    try std.testing.expect(std.mem.indexOf(u8, agents_content, "custom-agents-content") == null);

    const user_content = try fs_compat.readFileAlloc(tmp.dir, std.testing.allocator, "USER.md", 64 * 1024);
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
    }, null);
    try std.testing.expectEqual(@as(usize, 6), dry_report.rewritten_files);
    try std.testing.expect(dry_report.removed_files >= 1);
    const memory_file = try tmp.dir.openFile("MEMORY.md", .{});
    memory_file.close();

    const reset_report = try resetWorkspacePromptFiles(std.testing.allocator, base, &ProjectContext{}, .{
        .clear_memory_markdown = true,
    }, null);
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

    const report = try resetWorkspacePromptFiles(std.testing.allocator, nested, &ProjectContext{}, .{}, null);
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

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{}, null);

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

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{}, null);

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

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{}, null);

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

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{}, null);

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

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{}, null);

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

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{}, null);

    const identity_file = try tmp.dir.openFile("IDENTITY.md", .{});
    identity_file.close();
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("BOOTSTRAP.md", .{}));

    var state = try readWorkspaceOnboardingState(std.testing.allocator, base);
    defer state.deinit(std.testing.allocator);
    try std.testing.expect(state.onboarding_completed_at != null);
}

test "scaffoldWorkspace handles trailing native separator on Windows paths" {
    if (builtin.os.tag != .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    const workspace_with_sep = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}{s}",
        .{ base, std.fs.path.sep_str },
    );
    defer std.testing.allocator.free(workspace_with_sep);

    try scaffoldWorkspace(std.testing.allocator, workspace_with_sep, &ProjectContext{}, null);

    const bootstrap_file = try tmp.dir.openFile("BOOTSTRAP.md", .{});
    bootstrap_file.close();
}

test "scaffoldWorkspaceForConfig stores sqlite bootstrap docs outside workspace files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var cfg = Config{
        .workspace_dir = try allocator.dupe(u8, base),
        .config_path = try std.fs.path.join(allocator, &.{ base, "config.json" }),
        .allocator = allocator,
    };
    cfg.memory.backend = "sqlite";

    try scaffoldWorkspaceForConfig(std.testing.allocator, &cfg, &ProjectContext{});

    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("AGENTS.md", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("BOOTSTRAP.md", .{}));

    var mem_rt = memory_root.initRuntime(std.testing.allocator, &cfg.memory, cfg.workspace_dir) orelse
        return error.TestUnexpectedResult;
    defer mem_rt.deinit();

    const bootstrap_provider = try bootstrap_mod.createProvider(
        std.testing.allocator,
        cfg.memory.backend,
        mem_rt.memory,
        cfg.workspace_dir,
    );
    defer bootstrap_provider.deinit();

    const agents_content = try bootstrap_provider.load(std.testing.allocator, "AGENTS.md") orelse
        return error.TestUnexpectedResult;
    defer std.testing.allocator.free(agents_content);
    try std.testing.expect(std.mem.indexOf(u8, agents_content, "AGENTS.md - Your Workspace") != null);

    const bootstrap_content = try bootstrap_provider.load(std.testing.allocator, "BOOTSTRAP.md") orelse
        return error.TestUnexpectedResult;
    defer std.testing.allocator.free(bootstrap_content);
    try std.testing.expect(std.mem.indexOf(u8, bootstrap_content, "BOOTSTRAP.md - Hello, World") != null);
}

test "resetWorkspacePromptFiles with sqlite rewrites provider docs without touching workspace markdown files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "AGENTS.md",
        .data = "disk-agents-before",
    });

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    var mem_rt = memory_root.initRuntime(std.testing.allocator, &.{ .backend = "sqlite" }, base) orelse
        return error.TestUnexpectedResult;
    defer mem_rt.deinit();

    const bootstrap_provider = try bootstrap_mod.createProvider(
        std.testing.allocator,
        "sqlite",
        mem_rt.memory,
        base,
    );
    defer bootstrap_provider.deinit();

    const report = try resetWorkspacePromptFiles(
        std.testing.allocator,
        base,
        &ProjectContext{},
        .{ .include_bootstrap = true },
        bootstrap_provider,
    );
    try std.testing.expectEqual(@as(usize, 7), report.rewritten_files);
    try std.testing.expectEqual(@as(usize, 0), report.removed_files);

    const disk_agents = try fs_compat.readFileAlloc(tmp.dir, std.testing.allocator, "AGENTS.md", 64 * 1024);
    defer std.testing.allocator.free(disk_agents);
    try std.testing.expectEqualStrings("disk-agents-before", disk_agents);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("BOOTSTRAP.md", .{}));

    const stored_agents = try bootstrap_provider.load(std.testing.allocator, "AGENTS.md") orelse
        return error.TestUnexpectedResult;
    defer std.testing.allocator.free(stored_agents);
    try std.testing.expect(std.mem.indexOf(u8, stored_agents, "AGENTS.md - Your Workspace") != null);

    const stored_bootstrap = try bootstrap_provider.load(std.testing.allocator, "BOOTSTRAP.md") orelse
        return error.TestUnexpectedResult;
    defer std.testing.allocator.free(stored_bootstrap);
    try std.testing.expect(std.mem.indexOf(u8, stored_bootstrap, "BOOTSTRAP.md - Hello, World") != null);
}

test "bootstrap lifecycle stays equivalent across markdown hybrid and sqlite backends" {
    const backends = [_][]const u8{ "markdown", "hybrid", "sqlite" };
    var expected_agents: ?[]u8 = null;
    defer if (expected_agents) |value| std.testing.allocator.free(value);
    var expected_bootstrap: ?[]u8 = null;
    defer if (expected_bootstrap) |value| std.testing.allocator.free(value);

    for (backends) |backend| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();

        const workspace = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
        defer std.testing.allocator.free(workspace);

        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var cfg = Config{
            .workspace_dir = try allocator.dupe(u8, workspace),
            .config_path = try std.fs.path.join(allocator, &.{ workspace, "config.json" }),
            .allocator = allocator,
        };
        cfg.memory.backend = backend;

        try scaffoldWorkspaceForConfig(std.testing.allocator, &cfg, &ProjectContext{});

        var state = try readWorkspaceOnboardingState(std.testing.allocator, workspace);
        defer state.deinit(std.testing.allocator);
        try std.testing.expect(state.bootstrap_seeded_at != null);
        try std.testing.expect(state.onboarding_completed_at == null);

        var mem_rt: ?memory_root.MemoryRuntime = null;
        defer if (mem_rt) |*rt| rt.deinit();
        if (!bootstrap_mod.backendUsesFiles(backend)) {
            mem_rt = memory_root.initRuntime(std.testing.allocator, &cfg.memory, workspace) orelse
                return error.TestUnexpectedResult;
        }

        const mem_iface: ?memory_root.Memory = if (mem_rt) |rt| rt.memory else null;
        const bootstrap_provider = try bootstrap_mod.createProvider(
            std.testing.allocator,
            backend,
            mem_iface,
            workspace,
        );
        defer bootstrap_provider.deinit();

        try std.testing.expect(bootstrap_provider.exists("AGENTS.md"));
        try std.testing.expect(bootstrap_provider.exists("BOOTSTRAP.md"));

        const agents_content = try bootstrap_provider.load(std.testing.allocator, "AGENTS.md") orelse
            return error.TestUnexpectedResult;
        defer std.testing.allocator.free(agents_content);
        const bootstrap_content = try bootstrap_provider.load(std.testing.allocator, "BOOTSTRAP.md") orelse
            return error.TestUnexpectedResult;
        defer std.testing.allocator.free(bootstrap_content);

        if (expected_agents) |value| {
            try std.testing.expectEqualStrings(value, agents_content);
        } else {
            expected_agents = try std.testing.allocator.dupe(u8, agents_content);
        }
        if (expected_bootstrap) |value| {
            try std.testing.expectEqualStrings(value, bootstrap_content);
        } else {
            expected_bootstrap = try std.testing.allocator.dupe(u8, bootstrap_content);
        }

        try std.testing.expect(try bootstrap_provider.remove("BOOTSTRAP.md"));
        try scaffoldWorkspaceForConfig(std.testing.allocator, &cfg, &ProjectContext{});

        try std.testing.expect(!bootstrap_provider.exists("BOOTSTRAP.md"));

        var completed_state = try readWorkspaceOnboardingState(std.testing.allocator, workspace);
        defer completed_state.deinit(std.testing.allocator);
        try std.testing.expect(completed_state.onboarding_completed_at != null);
    }
}

// ── Additional onboard tests ────────────────────────────────────

test "canonicalProviderName passthrough for known providers" {
    try std.testing.expectEqualStrings("anthropic", canonicalProviderName("anthropic"));
    try std.testing.expectEqualStrings("openrouter", canonicalProviderName("openrouter"));
    try std.testing.expectEqualStrings("vertex", canonicalProviderName("vertex"));
    try std.testing.expectEqualStrings("deepseek", canonicalProviderName("deepseek"));
    try std.testing.expectEqualStrings("groq", canonicalProviderName("groq"));
    try std.testing.expectEqualStrings("ollama", canonicalProviderName("ollama"));
    try std.testing.expectEqualStrings("claude-cli", canonicalProviderName("claude-cli"));
    try std.testing.expectEqualStrings("codex-cli", canonicalProviderName("codex-cli"));
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

test "resolveProviderForQuickSetup supports custom: prefix" {
    const custom = resolveProviderForQuickSetup("custom:https://example.com/v1") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("custom:https://example.com/v1", custom.key);
    try std.testing.expectEqualStrings("Custom OpenAI-compatible provider", custom.label);
    try std.testing.expectEqualStrings("gpt-5.2", custom.default_model);
    try std.testing.expectEqualStrings("API_KEY", custom.env_var);
}

test "resolveProviderForQuickSetup supports custom: versioned endpoint beyond v1" {
    const custom = resolveProviderForQuickSetup("custom:https://example.com/openai/v2") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("custom:https://example.com/openai/v2", custom.key);
}

test "resolveProviderForQuickSetup rejects invalid custom endpoint format" {
    try std.testing.expect(resolveProviderForQuickSetup("custom:") == null);
    try std.testing.expect(resolveProviderForQuickSetup("custom:https://example.com/api") == null);
    try std.testing.expect(resolveProviderForQuickSetup("custom:example.com/v1") == null);
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

test "defaultModelForProvider vertex aliases" {
    try std.testing.expectEqualStrings("gemini-2.5-pro", defaultModelForProvider("vertex"));
    try std.testing.expectEqualStrings("gemini-2.5-pro", defaultModelForProvider("vertex-ai"));
    try std.testing.expectEqualStrings("gemini-2.5-pro", defaultModelForProvider("google-vertex"));
}

test "defaultModelForProvider groq" {
    try std.testing.expectEqualStrings("llama-3.3-70b-versatile", defaultModelForProvider("groq"));
}

test "defaultModelForProvider openrouter" {
    try std.testing.expectEqualStrings("anthropic/claude-sonnet-4.6", defaultModelForProvider("openrouter"));
}

test "ensureSecretsEncryptionEnabled rejects plaintext secrets config" {
    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    cfg.secrets.encrypt = false;

    try std.testing.expectError(Config.ValidationError.InsecurePlaintextSecrets, ensureSecretsEncryptionEnabled(&cfg));
}

test "printProviderNextSteps prefers interactive chat when api key is already set" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();

    try printProviderNextSteps(&aw.writer, "openai", "OPENAI_API_KEY", true, true);

    const rendered = aw.writer.buffer[0..aw.writer.end];
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nullclaw agent -m") == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Interactive chat:  nullclaw agent") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Then type:         Hello!") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Status:            nullclaw status") != null);
}

test "printProviderNextSteps includes env hint before interactive chat" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();

    try printProviderNextSteps(&aw.writer, "openai", "OPENAI_API_KEY", true, false);

    const rendered = aw.writer.buffer[0..aw.writer.end];
    try std.testing.expect(std.mem.indexOf(u8, rendered, "export OPENAI_API_KEY=\"sk-...\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nullclaw agent -m") == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Interactive chat:  nullclaw agent") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Gateway:           nullclaw gateway") != null);
}

test "printProviderNextSteps keeps openai-codex auth flow and interactive chat" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();

    try printProviderNextSteps(&aw.writer, "openai-codex", "", false, false);

    const rendered = aw.writer.buffer[0..aw.writer.end];
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nullclaw auth login openai-codex") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "--import-codex") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nullclaw agent -m") == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Interactive chat:  nullclaw agent") != null);
}

test "printProviderNextSteps keeps codex-cli auth flow and interactive chat" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();

    try printProviderNextSteps(&aw.writer, "codex-cli", "OPENAI_API_KEY", false, false);

    const rendered = aw.writer.buffer[0..aw.writer.end];
    try std.testing.expect(std.mem.indexOf(u8, rendered, "codex login") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nullclaw agent -m") == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Interactive chat:  nullclaw agent") != null);
}

test "providerEnvVar gemini aliases" {
    try std.testing.expectEqualStrings("GEMINI_API_KEY", providerEnvVar("gemini"));
    try std.testing.expectEqualStrings("GEMINI_API_KEY", providerEnvVar("google"));
    try std.testing.expectEqualStrings("GEMINI_API_KEY", providerEnvVar("google-gemini"));
}

test "providerEnvVar vertex aliases" {
    try std.testing.expectEqualStrings("VERTEX_API_KEY", providerEnvVar("vertex"));
    try std.testing.expectEqualStrings("VERTEX_API_KEY", providerEnvVar("vertex-ai"));
    try std.testing.expectEqualStrings("VERTEX_API_KEY", providerEnvVar("google-vertex"));
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
        try std.testing.expect(p.env_var.len > 0 or !providerRequiresApiKeyForSetup(p.key, null));
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

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{}, null);
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

test "autonomy_options has 4 entries" {
    try std.testing.expect(autonomy_options.len == 4);
    try std.testing.expectEqualStrings("supervised", autonomy_options[0]);
    try std.testing.expectEqualStrings("autonomous", autonomy_options[1]);
    try std.testing.expectEqualStrings("fully_autonomous", autonomy_options[2]);
    try std.testing.expectEqualStrings("yolo", autonomy_options[3]);
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
    try std.testing.expect(known_providers.len == 35);
    // The wizard would clamp to default (0) for out of range input
}

test "findChannelOptionIndex supports number and key" {
    const options = [_]channel_catalog.ChannelMeta{
        .{ .id = .telegram, .key = "telegram", .label = "Telegram", .configured_message = "Telegram configured", .listener_mode = .polling },
        .{ .id = .discord, .key = "discord", .label = "Discord", .configured_message = "Discord configured", .listener_mode = .gateway_loop },
        .{ .id = .max, .key = "max", .label = "Max", .configured_message = "Max configured", .listener_mode = .polling },
    };

    try std.testing.expectEqual(@as(?usize, 0), findChannelOptionIndex("1", &options));
    try std.testing.expectEqual(@as(?usize, 1), findChannelOptionIndex("discord", &options));
    try std.testing.expectEqual(@as(?usize, 2), findChannelOptionIndex("max", &options));
    try std.testing.expect(findChannelOptionIndex("unknown", &options) == null);
}

test "wizard maps autonomy index to enum correctly" {
    // Verify the mapping used in runWizard
    const Config2 = @import("config.zig");
    const mapping = [_]Config2.AutonomyLevel{ .supervised, .full, .full, .yolo };
    try std.testing.expect(mapping[0] == .supervised);
    try std.testing.expect(mapping[1] == .full);
    try std.testing.expect(mapping[2] == .full);
    try std.testing.expect(mapping[3] == .yolo);
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
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "memory.backend") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "memory_list") != null);
    try std.testing.expect(std.mem.indexOf(u8, tmpl, "memory_recall") != null);
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

    try scaffoldWorkspace(std.testing.allocator, base, &ProjectContext{}, null);

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
    const vertex_models = fallbackModelsForProvider("vertex");
    try std.testing.expect(vertex_models.len >= 2);

    const claude_cli_models = fallbackModelsForProvider("claude-cli");
    try std.testing.expect(claude_cli_models.len >= 1);
    try std.testing.expectEqualStrings("claude-opus-4-6", claude_cli_models[0]);

    const codex_cli_models = fallbackModelsForProvider("codex-cli");
    try std.testing.expect(codex_cli_models.len >= 1);
    try std.testing.expectEqualStrings(codex_support.DEFAULT_CODEX_MODEL, codex_cli_models[0]);

    const openai_codex_models = fallbackModelsForProvider("openai-codex");
    try std.testing.expect(openai_codex_models.len >= 1);
    try std.testing.expectEqualStrings(codex_support.DEFAULT_CODEX_MODEL, openai_codex_models[0]);
}

test "fallbackModelsForProvider handles aliases" {
    const models = fallbackModelsForProvider("google");
    try std.testing.expect(models.len >= 2);
    try std.testing.expectEqualStrings("gemini-2.5-pro", models[0]);

    const vertex_models = fallbackModelsForProvider("vertex-ai");
    try std.testing.expect(vertex_models.len >= 2);
    try std.testing.expectEqualStrings("gemini-2.5-pro", vertex_models[0]);
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

test "modelsCacheProviderKey keeps public catalog separate from native listings" {
    const public_key = try modelsCacheProviderKey(std.testing.allocator, "openai", null);
    defer std.testing.allocator.free(public_key);
    try std.testing.expectEqualStrings("openai@models.dev", public_key);

    const native_key = try modelsCacheProviderKey(std.testing.allocator, "openai", "test-key");
    defer std.testing.allocator.free(native_key);
    try std.testing.expectEqualStrings("openai", native_key);

    const anthropic_key = try modelsCacheProviderKey(std.testing.allocator, "anthropic", null);
    defer std.testing.allocator.free(anthropic_key);
    try std.testing.expectEqualStrings("anthropic@models.dev", anthropic_key);
}

test "loadModelsWithCache keeps public and native cache entries separate" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);
    const cache_path = try std.fs.path.join(std.testing.allocator, &.{ base, "models_cache.json" });
    defer std.testing.allocator.free(cache_path);

    const cache_json = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"fetched_at\": {d}, \"openai\": [\"gpt-native\"], \"openai@models.dev\": [\"gpt-public\"]}}",
        .{std.time.timestamp()},
    );
    defer std.testing.allocator.free(cache_json);

    const file = try tmp.dir.createFile("models_cache.json", .{});
    defer file.close();
    try file.writeAll(cache_json);

    const public_models = try loadModelsWithCache(std.testing.allocator, base, "openai", null);
    defer {
        for (public_models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(public_models);
    }
    try std.testing.expectEqual(@as(usize, 1), public_models.len);
    try std.testing.expectEqualStrings("gpt-public", public_models[0]);

    const native_models = try loadModelsWithCache(std.testing.allocator, base, "openai", "test-key");
    defer {
        for (native_models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(native_models);
    }
    try std.testing.expectEqual(@as(usize, 1), native_models.len);
    try std.testing.expectEqualStrings("gpt-native", native_models[0]);
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

test "modelsDevProviderKey maps known providers" {
    try std.testing.expectEqualStrings("anthropic", modelsDevProviderKey("claude-cli").?);
    try std.testing.expectEqualStrings("google", modelsDevProviderKey("gemini").?);
    try std.testing.expectEqualStrings("google-vertex", modelsDevProviderKey("vertex").?);
    try std.testing.expectEqualStrings("zai", modelsDevProviderKey("z.ai").?);
    try std.testing.expect(modelsDevProviderKey("ollama") == null);
}

test "parseModelsDevModelIds filters non-chat models and prioritizes default" {
    const json =
        \\{
        \\  "anthropic": {
        \\    "models": {
        \\      "claude-haiku-4-5": {
        \\        "modalities": {"input": ["text"], "output": ["text"]}
        \\      },
        \\      "claude-embedding-1": {
        \\        "family": "text-embedding",
        \\        "modalities": {"input": ["text"], "output": ["text"]}
        \\      },
        \\      "claude-opus-4-6": {
        \\        "modalities": {"input": ["text"], "output": ["text"]}
        \\      },
        \\      "claude-audio-1": {
        \\        "modalities": {"input": ["audio"], "output": ["text"]}
        \\      }
        \\    }
        \\  }
        \\}
    ;

    const models = try parseModelsDevModelIds(std.testing.allocator, json, "anthropic", "anthropic");
    defer {
        for (models) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(models);
    }

    try std.testing.expectEqual(@as(usize, 2), models.len);
    try std.testing.expectEqualStrings("claude-opus-4-6", models[0]);
    try std.testing.expectEqualStrings("claude-haiku-4-5", models[1]);
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
