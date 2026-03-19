const std = @import("std");
const root = @import("root.zig");
const Provider = root.Provider;
const anthropic = @import("anthropic.zig");
const openai = @import("openai.zig");
const ollama = @import("ollama.zig");
const gemini = @import("gemini.zig");
const vertex = @import("vertex.zig");
const openrouter = @import("openrouter.zig");
const compatible = @import("compatible.zig");
const claude_cli = @import("claude_cli.zig");
const codex_cli = @import("codex_cli.zig");
const openai_codex = @import("openai_codex.zig");
const provider_names = @import("../provider_names.zig");

pub const ProviderKind = enum {
    anthropic_provider,
    openai_provider,
    azure_openai_provider,
    openrouter_provider,
    ollama_provider,
    gemini_provider,
    vertex_provider,
    compatible_provider,
    claude_cli_provider,
    codex_cli_provider,
    openai_codex_provider,
    unknown,
};

// ════════════════════════════════════════════════════════════════════════════
// Single source of truth for all OpenAI-compatible providers.
// To add a new provider, add ONE entry here.
// ════════════════════════════════════════════════════════════════════════════

const CompatProvider = struct {
    name: []const u8,
    url: []const u8,
    display: []const u8,
    /// When true, disable the /v1/responses fallback on 404.
    no_responses_fallback: bool = false,
    /// When true, merge system messages into first user message.
    merge_system_into_user: bool = false,
    /// Authentication style (default: Bearer token).
    auth_style: compatible.AuthStyle = .bearer,
    /// Whether this provider supports native OpenAI-style tool_calls.
    native_tools: bool = true,
    /// When set, cap max_tokens in non-streaming requests to this value.
    /// Fireworks rejects max_tokens > 4096 when stream=false.
    max_tokens_non_streaming: ?u32 = null,
    /// When true, include `"thinking":{"type":"enabled"}` in request bodies
    /// when reasoning_effort is set. Required by Z.AI/GLM thinking models.
    thinking_param: bool = false,
    /// When true, include `"enable_thinking":true` in request bodies
    /// when reasoning_effort is set. Required by Qwen (DashScope compatible mode).
    enable_thinking_param: bool = false,
    /// When true, include `"reasoning_split":true` in request bodies
    /// when reasoning_effort is set. Used by MiniMax to separate reasoning output.
    reasoning_split_param: bool = false,
};

const compat_providers = [_]CompatProvider{
    // ── Major Cloud Providers ─────────────────────────────────────────────
    .{ .name = "groq", .url = "https://api.groq.com/openai/v1", .display = "Groq" },
    .{ .name = "mistral", .url = "https://api.mistral.ai/v1", .display = "Mistral" },
    .{ .name = "deepseek", .url = "https://api.deepseek.com", .display = "DeepSeek" },
    .{ .name = "xai", .url = "https://api.x.ai", .display = "xAI" },
    .{ .name = "grok", .url = "https://api.x.ai", .display = "xAI" },
    .{ .name = "cerebras", .url = "https://api.cerebras.ai/v1", .display = "Cerebras" },
    .{ .name = "perplexity", .url = "https://api.perplexity.ai", .display = "Perplexity" },
    .{ .name = "cohere", .url = "https://api.cohere.com/compatibility", .display = "Cohere" },
    .{ .name = "telnyx", .url = "https://api.telnyx.com/v2/ai", .display = "Telnyx" },

    // ── Gateways & Aggregators ────────────────────────────────────────────
    .{ .name = "venice", .url = "https://api.venice.ai", .display = "Venice" },
    .{ .name = "vercel", .url = "https://ai-gateway.vercel.sh/v1", .display = "Vercel AI Gateway" },
    .{ .name = "vercel-ai", .url = "https://ai-gateway.vercel.sh/v1", .display = "Vercel AI Gateway" },
    .{ .name = "together", .url = "https://api.together.xyz", .display = "Together AI" },
    .{ .name = "together-ai", .url = "https://api.together.xyz", .display = "Together AI" },
    .{ .name = "fireworks", .url = "https://api.fireworks.ai/inference/v1", .display = "Fireworks AI", .max_tokens_non_streaming = 4096 },
    .{ .name = "fireworks-ai", .url = "https://api.fireworks.ai/inference/v1", .display = "Fireworks AI", .max_tokens_non_streaming = 4096 },
    .{ .name = "huggingface", .url = "https://router.huggingface.co/v1", .display = "Hugging Face" },
    .{ .name = "aihubmix", .url = "https://aihubmix.com/v1", .display = "AIHubMix" },
    .{ .name = "siliconflow", .url = "https://api.siliconflow.cn/v1", .display = "SiliconFlow" },
    .{ .name = "shengsuanyun", .url = "https://router.shengsuanyun.com/api/v1", .display = "ShengSuanYun" },
    .{ .name = "chutes", .url = "https://chutes.ai/api/v1", .display = "Chutes" },
    .{ .name = "synthetic", .url = "https://api.synthetic.new/openai/v1", .display = "Synthetic" },
    .{ .name = "opencode", .url = "https://opencode.ai/zen/v1", .display = "OpenCode Zen" },
    .{ .name = "opencode-zen", .url = "https://opencode.ai/zen/v1", .display = "OpenCode Zen" },
    .{ .name = "astrai", .url = "https://as-trai.com/v1", .display = "Astrai" },
    .{ .name = "poe", .url = "https://api.poe.com/v1", .display = "Poe" },

    // ── China Providers — general ─────────────────────────────────────────
    .{ .name = "moonshot", .url = "https://api.moonshot.cn/v1", .display = "Moonshot" },
    .{ .name = "kimi", .url = "https://api.moonshot.cn/v1", .display = "Moonshot" },
    .{ .name = "glm", .url = "https://api.z.ai/api/paas/v4", .display = "GLM", .no_responses_fallback = true, .native_tools = false, .thinking_param = true },
    .{ .name = "zhipu", .url = "https://api.z.ai/api/paas/v4", .display = "GLM", .no_responses_fallback = true, .native_tools = false, .thinking_param = true },
    .{ .name = "zai", .url = "https://api.z.ai/api/coding/paas/v4", .display = "Z.AI", .native_tools = false, .thinking_param = true },
    .{ .name = "z.ai", .url = "https://api.z.ai/api/coding/paas/v4", .display = "Z.AI", .native_tools = false, .thinking_param = true },
    .{ .name = "minimax", .url = "https://api.minimax.io/v1", .display = "MiniMax", .no_responses_fallback = true, .merge_system_into_user = true, .native_tools = false, .reasoning_split_param = true },
    .{ .name = "qwen", .url = "https://dashscope.aliyuncs.com/compatible-mode/v1", .display = "Qwen", .enable_thinking_param = true },
    .{ .name = "dashscope", .url = "https://dashscope.aliyuncs.com/compatible-mode/v1", .display = "Qwen", .enable_thinking_param = true },
    .{ .name = "qianfan", .url = "https://aip.baidubce.com", .display = "Qianfan" },
    .{ .name = "baidu", .url = "https://aip.baidubce.com", .display = "Qianfan" },
    .{ .name = "doubao", .url = "https://ark.cn-beijing.volces.com/api/v3", .display = "Doubao" },
    .{ .name = "volcengine", .url = "https://ark.cn-beijing.volces.com/api/v3", .display = "Doubao" },
    .{ .name = "ark", .url = "https://ark.cn-beijing.volces.com/api/v3", .display = "Doubao" },

    // ── China Providers — CN endpoints ────────────────────────────────────
    .{ .name = "moonshot-cn", .url = "https://api.moonshot.cn/v1", .display = "Moonshot" },
    .{ .name = "kimi-cn", .url = "https://api.moonshot.cn/v1", .display = "Moonshot" },
    .{ .name = "glm-cn", .url = "https://open.bigmodel.cn/api/paas/v4", .display = "GLM", .no_responses_fallback = true, .native_tools = false, .thinking_param = true },
    .{ .name = "zhipu-cn", .url = "https://open.bigmodel.cn/api/paas/v4", .display = "GLM", .no_responses_fallback = true, .native_tools = false, .thinking_param = true },
    .{ .name = "bigmodel", .url = "https://open.bigmodel.cn/api/paas/v4", .display = "GLM", .no_responses_fallback = true, .native_tools = false, .thinking_param = true },
    .{ .name = "zai-cn", .url = "https://open.bigmodel.cn/api/coding/paas/v4", .display = "Z.AI", .native_tools = false, .thinking_param = true },
    .{ .name = "z.ai-cn", .url = "https://open.bigmodel.cn/api/coding/paas/v4", .display = "Z.AI", .native_tools = false, .thinking_param = true },
    .{ .name = "minimax-cn", .url = "https://api.minimaxi.com/v1", .display = "MiniMax", .no_responses_fallback = true, .merge_system_into_user = true, .native_tools = false, .reasoning_split_param = true },
    .{ .name = "minimaxi", .url = "https://api.minimaxi.com/v1", .display = "MiniMax", .no_responses_fallback = true, .merge_system_into_user = true, .native_tools = false, .reasoning_split_param = true },

    // ── International variants ────────────────────────────────────────────
    .{ .name = "moonshot-intl", .url = "https://api.moonshot.ai/v1", .display = "Moonshot" },
    .{ .name = "moonshot-global", .url = "https://api.moonshot.ai/v1", .display = "Moonshot" },
    .{ .name = "kimi-intl", .url = "https://api.moonshot.ai/v1", .display = "Moonshot" },
    .{ .name = "kimi-global", .url = "https://api.moonshot.ai/v1", .display = "Moonshot" },
    .{ .name = "glm-global", .url = "https://api.z.ai/api/paas/v4", .display = "GLM", .no_responses_fallback = true, .native_tools = false, .thinking_param = true },
    .{ .name = "zhipu-global", .url = "https://api.z.ai/api/paas/v4", .display = "GLM", .no_responses_fallback = true, .native_tools = false, .thinking_param = true },
    .{ .name = "zai-global", .url = "https://api.z.ai/api/coding/paas/v4", .display = "Z.AI", .native_tools = false, .thinking_param = true },
    .{ .name = "z.ai-global", .url = "https://api.z.ai/api/coding/paas/v4", .display = "Z.AI", .native_tools = false, .thinking_param = true },
    .{ .name = "minimax-intl", .url = "https://api.minimax.io/v1", .display = "MiniMax", .no_responses_fallback = true, .merge_system_into_user = true, .native_tools = false, .reasoning_split_param = true },
    .{ .name = "minimax-io", .url = "https://api.minimax.io/v1", .display = "MiniMax", .no_responses_fallback = true, .merge_system_into_user = true, .native_tools = false, .reasoning_split_param = true },
    .{ .name = "minimax-global", .url = "https://api.minimax.io/v1", .display = "MiniMax", .no_responses_fallback = true, .merge_system_into_user = true, .native_tools = false, .reasoning_split_param = true },
    .{ .name = "qwen-intl", .url = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", .display = "Qwen", .enable_thinking_param = true },
    .{ .name = "dashscope-intl", .url = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", .display = "Qwen", .enable_thinking_param = true },
    .{ .name = "qwen-us", .url = "https://dashscope-us.aliyuncs.com/compatible-mode/v1", .display = "Qwen", .enable_thinking_param = true },
    .{ .name = "dashscope-us", .url = "https://dashscope-us.aliyuncs.com/compatible-mode/v1", .display = "Qwen", .enable_thinking_param = true },
    .{ .name = "byteplus", .url = "https://ark.ap-southeast.bytepluses.com/api/v3", .display = "BytePlus" },

    // ── Coding-specific endpoints ─────────────────────────────────────────
    .{ .name = "kimi-code", .url = "https://api.kimi.com/coding/v1", .display = "Kimi Code" },
    .{ .name = "kimi_coding", .url = "https://api.kimi.com/coding/v1", .display = "Kimi Code" },
    .{ .name = "volcengine-plan", .url = "https://ark.cn-beijing.volces.com/api/coding/v3", .display = "Doubao" },
    .{ .name = "byteplus-plan", .url = "https://ark.ap-southeast.bytepluses.com/api/coding/v3", .display = "BytePlus" },
    .{ .name = "qwen-portal", .url = "https://portal.qwen.ai/v1", .display = "Qwen Portal", .enable_thinking_param = true },

    // ── Infrastructure & Cloud ────────────────────────────────────────────
    .{ .name = "bedrock", .url = "https://bedrock-runtime.us-east-1.amazonaws.com", .display = "Amazon Bedrock" },
    .{ .name = "aws-bedrock", .url = "https://bedrock-runtime.us-east-1.amazonaws.com", .display = "Amazon Bedrock" },
    .{ .name = "cloudflare", .url = "https://gateway.ai.cloudflare.com/v1", .display = "Cloudflare AI Gateway" },
    .{ .name = "cloudflare-ai", .url = "https://gateway.ai.cloudflare.com/v1", .display = "Cloudflare AI Gateway" },
    .{ .name = "copilot", .url = "https://api.githubcopilot.com", .display = "GitHub Copilot" },
    .{ .name = "github-copilot", .url = "https://api.githubcopilot.com", .display = "GitHub Copilot" },
    .{ .name = "nvidia", .url = "https://integrate.api.nvidia.com/v1", .display = "NVIDIA NIM" },
    .{ .name = "nvidia-nim", .url = "https://integrate.api.nvidia.com/v1", .display = "NVIDIA NIM" },
    .{ .name = "build.nvidia.com", .url = "https://integrate.api.nvidia.com/v1", .display = "NVIDIA NIM" },
    .{ .name = "ovhcloud", .url = "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1", .display = "OVHcloud" },
    .{ .name = "ovh", .url = "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1", .display = "OVHcloud" },
    .{ .name = "novita", .url = "https://api.novita.ai/openai/v1", .display = "Novita" },
    .{ .name = "novita-ai", .url = "https://api.novita.ai/openai/v1", .display = "Novita" },

    // ── Local Servers ─────────────────────────────────────────────────────
    .{ .name = "lmstudio", .url = "http://localhost:1234/v1", .display = "LM Studio" },
    .{ .name = "lm-studio", .url = "http://localhost:1234/v1", .display = "LM Studio" },
    .{ .name = "vllm", .url = "http://localhost:8000/v1", .display = "vLLM" },
    .{ .name = "llamacpp", .url = "http://localhost:8080/v1", .display = "llama.cpp" },
    .{ .name = "llama.cpp", .url = "http://localhost:8080/v1", .display = "llama.cpp" },
    .{ .name = "sglang", .url = "http://localhost:30000/v1", .display = "SGLang" },
    .{ .name = "osaurus", .url = "http://localhost:1337/v1", .display = "Osaurus" },
    .{ .name = "litellm", .url = "http://localhost:4000", .display = "LiteLLM" },
};

// Comptime check: no duplicate names in the compat_providers table.
comptime {
    @setEvalBranchQuota(100_000);
    for (compat_providers, 0..) |a, i| {
        for (compat_providers[i + 1 ..]) |b| {
            if (std.mem.eql(u8, a.name, b.name)) {
                @compileError("duplicate compat_providers name: " ++ a.name);
            }
        }
    }
}

/// Look up a compatible provider entry by name.
fn findCompatProvider(name: []const u8) ?CompatProvider {
    for (&compat_providers) |*p| {
        if (std.mem.eql(u8, p.name, name)) return p.*;
    }
    return null;
}

const AZURE_DEFAULT_BASE_URL = "https://your-resource.openai.azure.com";
const AZURE_DEFAULT_COMPAT_BASE_URL = "https://your-resource.openai.azure.com/openai/v1";

fn trimTrailingSlash(s: []const u8) []const u8 {
    if (s.len > 0 and s[s.len - 1] == '/') {
        return s[0 .. s.len - 1];
    }
    return s;
}

fn normalizeAzureBaseUrlOwned(allocator: std.mem.Allocator, base_url: ?[]const u8) ![]u8 {
    const raw = trimTrailingSlash(base_url orelse AZURE_DEFAULT_BASE_URL);

    if (std.mem.endsWith(u8, raw, "/chat/completions") or std.mem.endsWith(u8, raw, "/openai/v1")) {
        return allocator.dupe(u8, raw);
    }

    if (std.mem.endsWith(u8, raw, "/responses")) {
        return allocator.dupe(u8, raw[0 .. raw.len - "/responses".len]);
    }

    if (std.mem.endsWith(u8, raw, "/openai")) {
        return std.fmt.allocPrint(allocator, "{s}/v1", .{raw});
    }

    return std.fmt.allocPrint(allocator, "{s}/openai/v1", .{raw});
}

/// Core (non-compatible) providers that have their own dedicated implementations.
const core_providers = std.StaticStringMap(ProviderKind).initComptime(.{
    .{ "anthropic", .anthropic_provider },
    .{ "openai", .openai_provider },
    .{ "azure", .azure_openai_provider },
    .{ "azure-openai", .azure_openai_provider },
    .{ "azure_openai", .azure_openai_provider },
    .{ "openrouter", .openrouter_provider },
    .{ "ollama", .ollama_provider },
    .{ "gemini", .gemini_provider },
    .{ "google", .gemini_provider },
    .{ "google-gemini", .gemini_provider },
    .{ "vertex", .vertex_provider },
    .{ "vertex-ai", .vertex_provider },
    .{ "google-vertex", .vertex_provider },
    .{ "claude-cli", .claude_cli_provider },
    .{ "codex-cli", .codex_cli_provider },
    .{ "openai-codex", .openai_codex_provider },
});

/// Determine which provider to create from a name string.
pub fn classifyProvider(name: []const u8) ProviderKind {
    const canonical = provider_names.canonicalProviderName(name);

    // Check core (non-compatible) providers first.
    if (core_providers.get(canonical)) |kind| return kind;

    // Check compatible providers table.
    if (findCompatProvider(canonical) != null or findCompatProvider(name) != null) return .compatible_provider;

    // custom: prefix
    if (std.mem.startsWith(u8, name, "custom:")) return .compatible_provider;

    // anthropic-custom: prefix
    if (std.mem.startsWith(u8, name, "anthropic-custom:")) return .anthropic_provider;

    return .unknown;
}

/// Auto-detect provider kind from an API key prefix.
pub fn detectProviderByApiKey(key: []const u8) ProviderKind {
    if (key.len < 3) return .unknown;
    if (std.mem.startsWith(u8, key, "sk-or-")) return .openrouter_provider;
    if (std.mem.startsWith(u8, key, "sk-ant-")) return .anthropic_provider;
    if (std.mem.startsWith(u8, key, "sk-")) return .openai_provider;
    if (std.mem.startsWith(u8, key, "gsk_")) return .compatible_provider;
    if (std.mem.startsWith(u8, key, "xai-")) return .compatible_provider;
    if (std.mem.startsWith(u8, key, "pplx-")) return .compatible_provider;
    if (std.mem.startsWith(u8, key, "AKIA")) return .compatible_provider;
    if (std.mem.startsWith(u8, key, "AIza")) return .gemini_provider;
    if (std.mem.startsWith(u8, key, "ya29.")) return .vertex_provider;
    return .unknown;
}

/// Get the base URL for an OpenAI-compatible provider by name.
pub fn compatibleProviderUrl(name: []const u8) ?[]const u8 {
    if (findCompatProvider(name)) |p| return p.url;
    return null;
}

/// Get the display name for an OpenAI-compatible provider.
pub fn compatibleProviderDisplayName(name: []const u8) []const u8 {
    if (findCompatProvider(name)) |p| return p.display;
    return "Custom";
}

/// Tagged union so the concrete provider struct lives alongside the caller
/// (stack or heap) and its vtable pointer remains stable.
pub const ProviderHolder = union(enum) {
    openrouter: openrouter.OpenRouterProvider,
    anthropic: anthropic.AnthropicProvider,
    openai: openai.OpenAiProvider,
    gemini: gemini.GeminiProvider,
    vertex: vertex.VertexProvider,
    ollama: ollama.OllamaProvider,
    compatible: compatible.OpenAiCompatibleProvider,
    claude_cli: claude_cli.ClaudeCliProvider,
    codex_cli: codex_cli.CodexCliProvider,
    openai_codex: openai_codex.OpenAiCodexProvider,

    /// Obtain the vtable-based Provider interface from whichever variant is active.
    pub fn provider(self: *ProviderHolder) Provider {
        return switch (self.*) {
            .openrouter => |*p| p.provider(),
            .anthropic => |*p| p.provider(),
            .openai => |*p| p.provider(),
            .gemini => |*p| p.provider(),
            .vertex => |*p| p.provider(),
            .ollama => |*p| p.provider(),
            .compatible => |*p| p.provider(),
            .claude_cli => |*p| p.provider(),
            .codex_cli => |*p| p.provider(),
            .openai_codex => |*p| p.provider(),
        };
    }

    /// Release any resources owned by the active provider variant.
    pub fn deinit(self: *ProviderHolder) void {
        self.provider().deinit();
    }

    /// Create a ProviderHolder from a provider name string and optional API key.
    /// Uses `classifyProvider` to route to the correct concrete provider.
    pub fn fromConfig(
        allocator: std.mem.Allocator,
        provider_name: []const u8,
        api_key: ?[]const u8,
        base_url: ?[]const u8,
        native_tools: bool,
        user_agent: ?[]const u8,
    ) ProviderHolder {
        const kind = classifyProvider(provider_name);
        return switch (kind) {
            .anthropic_provider => .{ .anthropic = anthropic.AnthropicProvider.init(
                allocator,
                api_key,
                if (std.mem.startsWith(u8, provider_name, "anthropic-custom:"))
                    provider_name["anthropic-custom:".len..]
                else
                    base_url,
            ) },
            .openai_provider => .{ .openai = openai.OpenAiProvider.init(allocator, api_key, user_agent) },
            .azure_openai_provider => blk: {
                const azure_url = normalizeAzureBaseUrlOwned(allocator, base_url) catch null;
                var prov = compatible.OpenAiCompatibleProvider.init(
                    allocator,
                    provider_name,
                    if (azure_url) |url| url else AZURE_DEFAULT_COMPAT_BASE_URL,
                    api_key,
                    .custom,
                    user_agent,
                );
                prov.owned_base_url = azure_url;
                prov.custom_header = "api-key";
                if (!native_tools) prov.native_tools = false;
                break :blk .{ .compatible = prov };
            },
            .gemini_provider => .{ .gemini = gemini.GeminiProvider.init(allocator, api_key) },
            .vertex_provider => .{ .vertex = vertex.VertexProvider.init(allocator, api_key, base_url) },
            .ollama_provider => blk: {
                var prov = ollama.OllamaProvider.init(allocator, base_url);
                prov.native_tools = native_tools;
                break :blk .{ .ollama = prov };
            },
            .openrouter_provider => .{ .openrouter = openrouter.OpenRouterProvider.init(allocator, api_key) },
            .compatible_provider => blk: {
                // Config base_url overrides built-in URL table and custom: prefix
                const url = base_url orelse
                    if (std.mem.startsWith(u8, provider_name, "custom:"))
                        provider_name["custom:".len..]
                    else
                        compatibleProviderUrl(provider_name) orelse "https://openrouter.ai/api/v1";

                const cp = findCompatProvider(provider_name);

                var prov = compatible.OpenAiCompatibleProvider.init(
                    allocator,
                    provider_name,
                    url,
                    api_key,
                    if (cp) |c| c.auth_style else .bearer,
                    user_agent,
                );

                // Apply flags from the compat_providers table.
                if (cp) |c| {
                    if (c.no_responses_fallback) prov.supports_responses_fallback = false;
                    if (c.merge_system_into_user) prov.merge_system_into_user = true;
                    if (!c.native_tools) prov.native_tools = false;
                    if (c.max_tokens_non_streaming) |cap| prov.max_tokens_non_streaming = cap;
                    if (c.thinking_param) prov.thinking_param = true;
                    if (c.enable_thinking_param) prov.enable_thinking_param = true;
                    if (c.reasoning_split_param) prov.reasoning_split_param = true;
                }

                // Apply config-level native_tools override (can only force to false).
                if (!native_tools) prov.native_tools = false;

                break :blk .{ .compatible = prov };
            },
            .claude_cli_provider => if (claude_cli.ClaudeCliProvider.init(allocator, null)) |p|
                .{ .claude_cli = p }
            else |_|
                .{ .openrouter = openrouter.OpenRouterProvider.init(allocator, api_key) },
            .codex_cli_provider => if (codex_cli.CodexCliProvider.init(allocator, null)) |p|
                .{ .codex_cli = p }
            else |_|
                .{ .openrouter = openrouter.OpenRouterProvider.init(allocator, api_key) },
            .openai_codex_provider => .{ .openai_codex = openai_codex.OpenAiCodexProvider.init(allocator, null) },
            // Unknown provider: if base_url is configured, treat as OpenAI-compatible;
            // otherwise fall back to OpenRouter.
            .unknown => if (base_url) |url| blk: {
                var prov = compatible.OpenAiCompatibleProvider.init(
                    allocator,
                    provider_name,
                    url,
                    api_key,
                    .bearer,
                    user_agent,
                );
                prov.native_tools = native_tools;
                break :blk .{ .compatible = prov };
            } else .{ .openrouter = openrouter.OpenRouterProvider.init(allocator, api_key) },
        };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "classifyProvider identifies known providers" {
    try std.testing.expect(classifyProvider("anthropic") == .anthropic_provider);
    try std.testing.expect(classifyProvider("openai") == .openai_provider);
    try std.testing.expect(classifyProvider("azure") == .azure_openai_provider);
    try std.testing.expect(classifyProvider("azure-openai") == .azure_openai_provider);
    try std.testing.expect(classifyProvider("azure_openai") == .azure_openai_provider);
    try std.testing.expect(classifyProvider("openrouter") == .openrouter_provider);
    try std.testing.expect(classifyProvider("ollama") == .ollama_provider);
    try std.testing.expect(classifyProvider("gemini") == .gemini_provider);
    try std.testing.expect(classifyProvider("google") == .gemini_provider);
    try std.testing.expect(classifyProvider("vertex") == .vertex_provider);
    try std.testing.expect(classifyProvider("vertex-ai") == .vertex_provider);
    try std.testing.expect(classifyProvider("google-vertex") == .vertex_provider);
    try std.testing.expect(classifyProvider("groq") == .compatible_provider);
    try std.testing.expect(classifyProvider("mistral") == .compatible_provider);
    try std.testing.expect(classifyProvider("deepseek") == .compatible_provider);
    try std.testing.expect(classifyProvider("venice") == .compatible_provider);
    try std.testing.expect(classifyProvider("poe") == .compatible_provider);
    try std.testing.expect(classifyProvider("custom:https://example.com") == .compatible_provider);
    try std.testing.expect(classifyProvider("openai-codex") == .openai_codex_provider);
    try std.testing.expect(classifyProvider("nonexistent") == .unknown);
}

test "classifyProvider new providers" {
    try std.testing.expect(classifyProvider("doubao") == .compatible_provider);
    try std.testing.expect(classifyProvider("volcengine") == .compatible_provider);
    try std.testing.expect(classifyProvider("ark") == .compatible_provider);
    try std.testing.expect(classifyProvider("cerebras") == .compatible_provider);
    try std.testing.expect(classifyProvider("vllm") == .compatible_provider);
    try std.testing.expect(classifyProvider("llamacpp") == .compatible_provider);
    try std.testing.expect(classifyProvider("llama.cpp") == .compatible_provider);
    try std.testing.expect(classifyProvider("sglang") == .compatible_provider);
    try std.testing.expect(classifyProvider("osaurus") == .compatible_provider);
    try std.testing.expect(classifyProvider("litellm") == .compatible_provider);
    try std.testing.expect(classifyProvider("huggingface") == .compatible_provider);
    try std.testing.expect(classifyProvider("aihubmix") == .compatible_provider);
    try std.testing.expect(classifyProvider("siliconflow") == .compatible_provider);
    try std.testing.expect(classifyProvider("shengsuanyun") == .compatible_provider);
    try std.testing.expect(classifyProvider("ovhcloud") == .compatible_provider);
    try std.testing.expect(classifyProvider("ovh") == .compatible_provider);
    try std.testing.expect(classifyProvider("byteplus") == .compatible_provider);
    try std.testing.expect(classifyProvider("chutes") == .compatible_provider);
    try std.testing.expect(classifyProvider("kimi-code") == .compatible_provider);
    try std.testing.expect(classifyProvider("minimax-cn") == .compatible_provider);
    try std.testing.expect(classifyProvider("minimax-intl") == .compatible_provider);
    try std.testing.expect(classifyProvider("moonshot-intl") == .compatible_provider);
    try std.testing.expect(classifyProvider("glm-cn") == .compatible_provider);
    try std.testing.expect(classifyProvider("bigmodel") == .compatible_provider);
    try std.testing.expect(classifyProvider("qwen-portal") == .compatible_provider);
}

test "compatibleProviderUrl returns correct URLs" {
    try std.testing.expectEqualStrings("https://api.venice.ai", compatibleProviderUrl("venice").?);
    try std.testing.expectEqualStrings("https://api.groq.com/openai/v1", compatibleProviderUrl("groq").?);
    try std.testing.expectEqualStrings("https://api.deepseek.com", compatibleProviderUrl("deepseek").?);
    try std.testing.expectEqualStrings("https://api.poe.com/v1", compatibleProviderUrl("poe").?);
    try std.testing.expect(compatibleProviderUrl("nonexistent") == null);
}

test "compatibleProviderUrl fixed URLs" {
    // These 5 URLs were corrected from the original values.
    try std.testing.expectEqualStrings("https://api.moonshot.cn/v1", compatibleProviderUrl("moonshot").?);
    try std.testing.expectEqualStrings("https://api.moonshot.cn/v1", compatibleProviderUrl("kimi").?);
    try std.testing.expectEqualStrings("https://api.synthetic.new/openai/v1", compatibleProviderUrl("synthetic").?);
    try std.testing.expectEqualStrings("https://ai-gateway.vercel.sh/v1", compatibleProviderUrl("vercel").?);
    try std.testing.expectEqualStrings("https://opencode.ai/zen/v1", compatibleProviderUrl("opencode").?);
    try std.testing.expectEqualStrings("https://api.mistral.ai/v1", compatibleProviderUrl("mistral").?);
    try std.testing.expectEqualStrings("https://api.minimax.io/v1", compatibleProviderUrl("minimax").?);
}

test "compatibleProviderUrl new providers" {
    try std.testing.expectEqualStrings("https://ark.cn-beijing.volces.com/api/v3", compatibleProviderUrl("doubao").?);
    try std.testing.expectEqualStrings("https://api.cerebras.ai/v1", compatibleProviderUrl("cerebras").?);
    try std.testing.expectEqualStrings("http://localhost:8000/v1", compatibleProviderUrl("vllm").?);
    try std.testing.expectEqualStrings("http://localhost:8080/v1", compatibleProviderUrl("llamacpp").?);
    try std.testing.expectEqualStrings("http://localhost:30000/v1", compatibleProviderUrl("sglang").?);
    try std.testing.expectEqualStrings("http://localhost:1337/v1", compatibleProviderUrl("osaurus").?);
    try std.testing.expectEqualStrings("http://localhost:4000", compatibleProviderUrl("litellm").?);
    try std.testing.expectEqualStrings("https://router.huggingface.co/v1", compatibleProviderUrl("huggingface").?);
    try std.testing.expectEqualStrings("https://aihubmix.com/v1", compatibleProviderUrl("aihubmix").?);
    try std.testing.expectEqualStrings("https://api.siliconflow.cn/v1", compatibleProviderUrl("siliconflow").?);
    try std.testing.expectEqualStrings("https://router.shengsuanyun.com/api/v1", compatibleProviderUrl("shengsuanyun").?);
    try std.testing.expectEqualStrings("https://oai.endpoints.kepler.ai.cloud.ovh.net/v1", compatibleProviderUrl("ovhcloud").?);
    try std.testing.expectEqualStrings("https://api.novita.ai/openai/v1", compatibleProviderUrl("novita").?);
    try std.testing.expectEqualStrings("https://api.novita.ai/openai/v1", compatibleProviderUrl("novita-ai").?);
    try std.testing.expectEqualStrings("https://ark.ap-southeast.bytepluses.com/api/v3", compatibleProviderUrl("byteplus").?);
    try std.testing.expectEqualStrings("https://chutes.ai/api/v1", compatibleProviderUrl("chutes").?);
    try std.testing.expectEqualStrings("https://api.kimi.com/coding/v1", compatibleProviderUrl("kimi-code").?);
    try std.testing.expectEqualStrings("https://portal.qwen.ai/v1", compatibleProviderUrl("qwen-portal").?);
    try std.testing.expectEqualStrings("https://api.telnyx.com/v2/ai", compatibleProviderUrl("telnyx").?);
}

test "normalizeAzureBaseUrlOwned appends openai v1 path" {
    const alloc = std.testing.allocator;

    const plain = try normalizeAzureBaseUrlOwned(alloc, "https://resource.openai.azure.com");
    defer alloc.free(plain);
    try std.testing.expectEqualStrings("https://resource.openai.azure.com/openai/v1", plain);

    const openai_only = try normalizeAzureBaseUrlOwned(alloc, "https://resource.openai.azure.com/openai/");
    defer alloc.free(openai_only);
    try std.testing.expectEqualStrings("https://resource.openai.azure.com/openai/v1", openai_only);

    const v1 = try normalizeAzureBaseUrlOwned(alloc, "https://resource.openai.azure.com/openai/v1/");
    defer alloc.free(v1);
    try std.testing.expectEqualStrings("https://resource.openai.azure.com/openai/v1", v1);
}

test "normalizeAzureBaseUrlOwned strips terminal responses endpoint" {
    const alloc = std.testing.allocator;

    const responses = try normalizeAzureBaseUrlOwned(alloc, "https://resource.openai.azure.com/openai/v1/responses/");
    defer alloc.free(responses);
    try std.testing.expectEqualStrings("https://resource.openai.azure.com/openai/v1", responses);
}

test "compatibleProviderUrl CN/intl variants" {
    try std.testing.expectEqualStrings("https://api.moonshot.cn/v1", compatibleProviderUrl("moonshot-cn").?);
    try std.testing.expectEqualStrings("https://api.moonshot.ai/v1", compatibleProviderUrl("moonshot-intl").?);
    try std.testing.expectEqualStrings("https://open.bigmodel.cn/api/paas/v4", compatibleProviderUrl("glm-cn").?);
    try std.testing.expectEqualStrings("https://api.z.ai/api/paas/v4", compatibleProviderUrl("glm-global").?);
    try std.testing.expectEqualStrings("https://api.minimaxi.com/v1", compatibleProviderUrl("minimax-cn").?);
    try std.testing.expectEqualStrings("https://api.minimax.io/v1", compatibleProviderUrl("minimax-intl").?);
}

test "nvidia resolves to correct URL" {
    try std.testing.expectEqualStrings("https://integrate.api.nvidia.com/v1", compatibleProviderUrl("nvidia").?);
}

test "lm-studio resolves to localhost:1234" {
    try std.testing.expectEqualStrings("http://localhost:1234/v1", compatibleProviderUrl("lm-studio").?);
}

test "astrai resolves to astrai API URL" {
    try std.testing.expectEqualStrings("https://as-trai.com/v1", compatibleProviderUrl("astrai").?);
}

test "anthropic-custom prefix classifies as anthropic provider" {
    try std.testing.expect(classifyProvider("anthropic-custom:https://my-api.example.com") == .anthropic_provider);
}

test "new providers display names" {
    try std.testing.expectEqualStrings("NVIDIA NIM", compatibleProviderDisplayName("nvidia"));
    try std.testing.expectEqualStrings("NVIDIA NIM", compatibleProviderDisplayName("nvidia-nim"));
    try std.testing.expectEqualStrings("NVIDIA NIM", compatibleProviderDisplayName("build.nvidia.com"));
    try std.testing.expectEqualStrings("LM Studio", compatibleProviderDisplayName("lmstudio"));
    try std.testing.expectEqualStrings("LM Studio", compatibleProviderDisplayName("lm-studio"));
    try std.testing.expectEqualStrings("Astrai", compatibleProviderDisplayName("astrai"));
    try std.testing.expectEqualStrings("Cerebras", compatibleProviderDisplayName("cerebras"));
    try std.testing.expectEqualStrings("Doubao", compatibleProviderDisplayName("doubao"));
    try std.testing.expectEqualStrings("Hugging Face", compatibleProviderDisplayName("huggingface"));
    try std.testing.expectEqualStrings("vLLM", compatibleProviderDisplayName("vllm"));
    try std.testing.expectEqualStrings("OVHcloud", compatibleProviderDisplayName("ovhcloud"));
    try std.testing.expectEqualStrings("Novita", compatibleProviderDisplayName("novita"));
    try std.testing.expectEqualStrings("Novita", compatibleProviderDisplayName("novita-ai"));
    try std.testing.expectEqualStrings("Custom", compatibleProviderDisplayName("nonexistent"));
    try std.testing.expectEqualStrings("Telnyx", compatibleProviderDisplayName("telnyx"));
}

test "new providers classify as compatible" {
    try std.testing.expect(classifyProvider("nvidia") == .compatible_provider);
    try std.testing.expect(classifyProvider("nvidia-nim") == .compatible_provider);
    try std.testing.expect(classifyProvider("build.nvidia.com") == .compatible_provider);
    try std.testing.expect(classifyProvider("lmstudio") == .compatible_provider);
    try std.testing.expect(classifyProvider("lm-studio") == .compatible_provider);
    try std.testing.expect(classifyProvider("astrai") == .compatible_provider);
    try std.testing.expect(classifyProvider("telnyx") == .compatible_provider);
    try std.testing.expect(classifyProvider("novita") == .compatible_provider);
    try std.testing.expect(classifyProvider("novita-ai") == .compatible_provider);
}

test "findCompatProvider returns correct flags" {
    // GLM has no_responses_fallback and thinking_param
    const glm = findCompatProvider("glm").?;
    try std.testing.expect(glm.no_responses_fallback);
    try std.testing.expect(!glm.merge_system_into_user);
    try std.testing.expect(glm.thinking_param);

    // MiniMax has both flags
    const minimax = findCompatProvider("minimax").?;
    try std.testing.expect(minimax.no_responses_fallback);
    try std.testing.expect(minimax.merge_system_into_user);
    try std.testing.expect(minimax.reasoning_split_param);

    // Qwen requires enable_thinking in compatible mode.
    const qwen = findCompatProvider("qwen").?;
    try std.testing.expect(qwen.enable_thinking_param);

    // Groq has no special flags
    const groq_p = findCompatProvider("groq").?;
    try std.testing.expect(!groq_p.no_responses_fallback);
    try std.testing.expect(!groq_p.merge_system_into_user);

    // minimax-cn also has both flags
    const minimax_cn = findCompatProvider("minimax-cn").?;
    try std.testing.expect(minimax_cn.no_responses_fallback);
    try std.testing.expect(minimax_cn.merge_system_into_user);
    try std.testing.expect(minimax_cn.reasoning_split_param);

    // Fireworks has non-streaming max_tokens cap.
    const fireworks = findCompatProvider("fireworks").?;
    try std.testing.expectEqual(@as(?u32, 4096), fireworks.max_tokens_non_streaming);
}

test "fromConfig applies no_responses_fallback flag" {
    const alloc = std.testing.allocator;
    var h = ProviderHolder.fromConfig(alloc, "glm", "key", null, true, null);
    defer h.deinit();
    try std.testing.expect(h == .compatible);
    try std.testing.expect(!h.compatible.supports_responses_fallback);
}

test "fromConfig applies thinking_param flag for GLM" {
    const alloc = std.testing.allocator;
    var h = ProviderHolder.fromConfig(alloc, "glm", "key", null, true, null);
    defer h.deinit();
    try std.testing.expect(h == .compatible);
    try std.testing.expect(h.compatible.thinking_param);
}

test "fromConfig thinking_param false for non-GLM providers" {
    const alloc = std.testing.allocator;
    var h = ProviderHolder.fromConfig(alloc, "groq", "key", null, true, null);
    defer h.deinit();
    try std.testing.expect(h == .compatible);
    try std.testing.expect(!h.compatible.thinking_param);
}

test "fromConfig applies enable_thinking_param for Qwen" {
    const alloc = std.testing.allocator;
    var h = ProviderHolder.fromConfig(alloc, "qwen", "key", null, true, null);
    defer h.deinit();
    try std.testing.expect(h == .compatible);
    try std.testing.expect(h.compatible.enable_thinking_param);
}

test "fromConfig applies reasoning_split_param for MiniMax" {
    const alloc = std.testing.allocator;
    var h = ProviderHolder.fromConfig(alloc, "minimax", "key", null, true, null);
    defer h.deinit();
    try std.testing.expect(h == .compatible);
    try std.testing.expect(h.compatible.reasoning_split_param);
}

test "fromConfig applies merge_system_into_user flag" {
    const alloc = std.testing.allocator;
    var h = ProviderHolder.fromConfig(alloc, "minimax", "key", null, true, null);
    defer h.deinit();
    try std.testing.expect(h == .compatible);
    try std.testing.expect(h.compatible.merge_system_into_user);
    try std.testing.expect(!h.compatible.supports_responses_fallback);
}

test "fromConfig inherits native_tools=false from table" {
    const alloc = std.testing.allocator;
    // minimax has native_tools = false in table
    var h = ProviderHolder.fromConfig(alloc, "minimax", "key", null, true, null);
    defer h.deinit();
    try std.testing.expect(h == .compatible);
    try std.testing.expect(!h.compatible.native_tools);
}

test "fromConfig applies native_tools override for ollama" {
    const alloc = std.testing.allocator;
    var h = ProviderHolder.fromConfig(alloc, "ollama", null, null, false, null);
    defer h.deinit();
    try std.testing.expect(h == .ollama);
    try std.testing.expect(!h.provider().supportsNativeTools());
}

test "fromConfig applies max_tokens_non_streaming from table" {
    const alloc = std.testing.allocator;
    var h = ProviderHolder.fromConfig(alloc, "fireworks", "key", null, true, null);
    defer h.deinit();
    try std.testing.expect(h == .compatible);
    try std.testing.expectEqual(@as(?u32, 4096), h.compatible.max_tokens_non_streaming);
}

test "detectProviderByApiKey openrouter" {
    try std.testing.expect(detectProviderByApiKey("sk-or-v1-abc123") == .openrouter_provider);
}

test "detectProviderByApiKey anthropic" {
    try std.testing.expect(detectProviderByApiKey("sk-ant-api03-abc123") == .anthropic_provider);
}

test "detectProviderByApiKey openai" {
    try std.testing.expect(detectProviderByApiKey("sk-proj-abc123") == .openai_provider);
}

test "detectProviderByApiKey groq" {
    try std.testing.expect(detectProviderByApiKey("gsk_abc123def456") == .compatible_provider);
}

test "detectProviderByApiKey xai" {
    try std.testing.expect(detectProviderByApiKey("xai-abc123") == .compatible_provider);
}

test "detectProviderByApiKey perplexity" {
    try std.testing.expect(detectProviderByApiKey("pplx-abc123") == .compatible_provider);
}

test "detectProviderByApiKey aws" {
    try std.testing.expect(detectProviderByApiKey("AKIAIOSFODNN7EXAMPLE") == .compatible_provider);
}

test "detectProviderByApiKey gemini" {
    try std.testing.expect(detectProviderByApiKey("AIzaSyAbc123") == .gemini_provider);
}

test "detectProviderByApiKey vertex oauth token" {
    try std.testing.expect(detectProviderByApiKey("ya29.a0AfH6SMD-abc123") == .vertex_provider);
}

test "detectProviderByApiKey unknown" {
    try std.testing.expect(detectProviderByApiKey("random-key") == .unknown);
}

test "detectProviderByApiKey short key" {
    try std.testing.expect(detectProviderByApiKey("ab") == .unknown);
}

test "ProviderHolder tagged union has all expected fields" {
    try std.testing.expect(@hasField(ProviderHolder, "openrouter"));
    try std.testing.expect(@hasField(ProviderHolder, "anthropic"));
    try std.testing.expect(@hasField(ProviderHolder, "openai"));
    try std.testing.expect(@hasField(ProviderHolder, "gemini"));
    try std.testing.expect(@hasField(ProviderHolder, "vertex"));
    try std.testing.expect(@hasField(ProviderHolder, "ollama"));
    try std.testing.expect(@hasField(ProviderHolder, "compatible"));
    try std.testing.expect(@hasField(ProviderHolder, "claude_cli"));
    try std.testing.expect(@hasField(ProviderHolder, "codex_cli"));
    try std.testing.expect(@hasField(ProviderHolder, "openai_codex"));
}

test "ProviderHolder.fromConfig routes to correct variant" {
    const alloc = std.testing.allocator;
    // anthropic
    var h1 = ProviderHolder.fromConfig(alloc, "anthropic", "sk-test", null, true, null);
    defer h1.deinit();
    try std.testing.expect(h1 == .anthropic);
    // openai
    var h2 = ProviderHolder.fromConfig(alloc, "openai", "sk-test", null, true, null);
    defer h2.deinit();
    try std.testing.expect(h2 == .openai);
    // azure openai
    var h2a = ProviderHolder.fromConfig(alloc, "azure", "test-key", "https://test.openai.azure.com", true, null);
    defer h2a.deinit();
    try std.testing.expect(h2a == .compatible);
    try std.testing.expectEqualStrings("https://test.openai.azure.com/openai/v1", h2a.compatible.base_url);
    try std.testing.expect(h2a.compatible.auth_style == .custom);
    try std.testing.expectEqualStrings("api-key", h2a.compatible.custom_header.?);
    // gemini
    var h3 = ProviderHolder.fromConfig(alloc, "gemini", "key", null, true, null);
    defer h3.deinit();
    try std.testing.expect(h3 == .gemini);
    // vertex
    var h3b = ProviderHolder.fromConfig(alloc, "vertex", "ya29.token", "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/google/models", true, null);
    defer h3b.deinit();
    try std.testing.expect(h3b == .vertex);
    // ollama
    var h4 = ProviderHolder.fromConfig(alloc, "ollama", null, null, true, null);
    defer h4.deinit();
    try std.testing.expect(h4 == .ollama);
    // openrouter
    var h5 = ProviderHolder.fromConfig(alloc, "openrouter", "sk-or-test", null, true, null);
    defer h5.deinit();
    try std.testing.expect(h5 == .openrouter);
    // compatible (groq)
    var h6 = ProviderHolder.fromConfig(alloc, "groq", "gsk_test", null, true, null);
    defer h6.deinit();
    try std.testing.expect(h6 == .compatible);
    // compatible (telnyx from built-in table URL)
    var h6b = ProviderHolder.fromConfig(alloc, "telnyx", "test-key", null, true, null);
    defer h6b.deinit();
    try std.testing.expect(h6b == .compatible);
    try std.testing.expectEqualStrings("https://api.telnyx.com/v2/ai", h6b.compatible.base_url);
    // openai-codex
    var h7 = ProviderHolder.fromConfig(alloc, "openai-codex", null, null, true, null);
    defer h7.deinit();
    try std.testing.expect(h7 == .openai_codex);
    // unknown falls back to openrouter
    var h8 = ProviderHolder.fromConfig(alloc, "nonexistent", "key", null, true, null);
    defer h8.deinit();
    try std.testing.expect(h8 == .openrouter);
    // anthropic-custom prefix
    var h9 = ProviderHolder.fromConfig(alloc, "anthropic-custom:https://my-api.example.com", "sk-test", null, true, null);
    defer h9.deinit();
    try std.testing.expect(h9 == .anthropic);
}

test "compat_providers table count" {
    // Verify we have the expected number of entries (guard against accidental deletions).
    try std.testing.expect(compat_providers.len >= 89);
}
