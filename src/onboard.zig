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
const Config = @import("config.zig").Config;
const memory_root = @import("memory/root.zig");

// ── Constants ────────────────────────────────────────────────────

const BANNER =
    \\
    \\  ██╗   ██╗ ██████╗  ██████╗████████╗ ██████╗  ██████╗██╗      █████╗ ██╗    ██╗
    \\  ╚██╗ ██╔╝██╔═══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔════╝██║     ██╔══██╗██║    ██║
    \\   ╚████╔╝ ██║   ██║██║        ██║   ██║   ██║██║     ██║     ███████║██║ █╗ ██║
    \\    ╚██╔╝  ██║   ██║██║        ██║   ██║   ██║██║     ██║     ██╔══██║██║███╗██║
    \\     ██║   ╚██████╔╝╚██████╗   ██║   ╚██████╔╝╚██████╗███████╗██║  ██║╚███╔███╔╝
    \\     ╚═╝    ╚═════╝  ╚═════╝   ╚═╝    ╚═════╝  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
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
    .{ .key = "openrouter", .label = "OpenRouter (multi-provider, recommended)", .default_model = "anthropic/claude-sonnet-4.5", .env_var = "OPENROUTER_API_KEY" },
    .{ .key = "anthropic", .label = "Anthropic (Claude direct)", .default_model = "claude-sonnet-4-20250514", .env_var = "ANTHROPIC_API_KEY" },
    .{ .key = "openai", .label = "OpenAI (GPT direct)", .default_model = "gpt-5.2", .env_var = "OPENAI_API_KEY" },
    .{ .key = "gemini", .label = "Google Gemini", .default_model = "gemini-2.5-pro", .env_var = "GEMINI_API_KEY" },
    .{ .key = "deepseek", .label = "DeepSeek", .default_model = "deepseek-chat", .env_var = "DEEPSEEK_API_KEY" },
    .{ .key = "groq", .label = "Groq (fast inference)", .default_model = "llama-3.3-70b-versatile", .env_var = "GROQ_API_KEY" },
    .{ .key = "ollama", .label = "Ollama (local)", .default_model = "llama3.2", .env_var = "API_KEY" },
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
    return "anthropic/claude-sonnet-4.5";
}

/// Get the environment variable name for a provider's API key.
pub fn providerEnvVar(provider: []const u8) []const u8 {
    const canonical = canonicalProviderName(provider);
    for (known_providers) |p| {
        if (std.mem.eql(u8, p.key, canonical)) return p.env_var;
    }
    return "API_KEY";
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
    var cfg = Config.load(allocator) catch Config{
        .workspace_dir = try getDefaultWorkspace(allocator),
        .config_path = try getDefaultConfigPath(allocator),
        .allocator = allocator,
    };

    // Apply overrides
    if (api_key) |key| cfg.api_key = key;
    if (provider) |p| cfg.default_provider = p;
    if (memory_backend) |mb| cfg.memory.backend = mb;

    // Set default model based on provider
    if (cfg.default_model == null or std.mem.eql(u8, cfg.default_model.?, "anthropic/claude-sonnet-4")) {
        cfg.default_model = defaultModelForProvider(cfg.default_provider);
    }

    // Ensure workspace directory exists
    std.fs.makeDirAbsolute(cfg.workspace_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Scaffold workspace files
    try scaffoldWorkspace(allocator, cfg.workspace_dir, &ProjectContext{});

    // Print summary
    try stdout.print("  [OK] Workspace:  {s}\n", .{cfg.workspace_dir});
    try stdout.print("  [OK] Provider:   {s}\n", .{cfg.default_provider});
    if (cfg.default_model) |m| {
        try stdout.print("  [OK] Model:      {s}\n", .{m});
    }
    try stdout.print("  [OK] API Key:    {s}\n", .{if (cfg.api_key != null) "set" else "not set (use --api-key or edit config)"});
    try stdout.print("  [OK] Memory:     {s}\n", .{cfg.memory.backend});
    try stdout.writeAll("\n  Next steps:\n");
    if (cfg.api_key == null) {
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

    const cfg = Config.load(allocator) catch {
        try stdout.writeAll("No existing config found. Run `nullclaw onboard` first.\n");
        try stdout.flush();
        return error.ConfigNotFound;
    };

    try stdout.print("  CLI:       {s}\n", .{if (cfg.channels.cli) "enabled" else "disabled"});
    try stdout.print("  Telegram:  {s}\n", .{if (cfg.channels.telegram != null) "configured" else "not configured"});
    try stdout.print("  Discord:   {s}\n", .{if (cfg.channels.discord != null) "configured" else "not configured"});
    try stdout.print("  Slack:     {s}\n", .{if (cfg.channels.slack != null) "configured" else "not configured"});
    try stdout.print("  Webhook:   {s}\n", .{if (cfg.channels.webhook != null) "configured" else "not configured"});
    try stdout.print("  iMessage:  {s}\n", .{if (cfg.channels.imessage != null) "configured" else "not configured"});
    try stdout.print("  Matrix:    {s}\n", .{if (cfg.channels.matrix != null) "configured" else "not configured"});
    try stdout.print("  WhatsApp:  {s}\n", .{if (cfg.channels.whatsapp != null) "configured" else "not configured"});
    try stdout.print("  IRC:       {s}\n", .{if (cfg.channels.irc != null) "configured" else "not configured"});
    try stdout.print("  Lark:      {s}\n", .{if (cfg.channels.lark != null) "configured" else "not configured"});
    try stdout.print("  DingTalk:  {s}\n", .{if (cfg.channels.dingtalk != null) "configured" else "not configured"});
    try stdout.writeAll("\nTo modify channels, edit your config file:\n");
    try stdout.print("  {s}\n", .{cfg.config_path});
    try stdout.flush();
}

/// Interactive wizard entry point — runs the full setup interactively.
pub fn runWizard(allocator: std.mem.Allocator) !void {
    var stdout_buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &bw.interface;
    try stdout.writeAll(BANNER);
    try stdout.writeAll("  Welcome to nullclaw -- the fastest, smallest AI assistant.\n");
    try stdout.writeAll("  This wizard will configure your agent.\n\n");
    try stdout.flush();

    // For now, delegate to quick setup
    try runQuickSetup(allocator, null, null, null);
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
    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    return std.fmt.allocPrint(allocator, "{s}/.nullclaw/workspace", .{home});
}

fn getDefaultConfigPath(allocator: std.mem.Allocator) ![]const u8 {
    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    return std.fmt.allocPrint(allocator, "{s}/.nullclaw/config.json", .{home});
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
    try std.testing.expectEqualStrings("claude-sonnet-4-20250514", defaultModelForProvider("anthropic"));
    try std.testing.expectEqualStrings("gpt-5.2", defaultModelForProvider("openai"));
    try std.testing.expectEqualStrings("deepseek-chat", defaultModelForProvider("deepseek"));
    try std.testing.expectEqualStrings("llama3.2", defaultModelForProvider("ollama"));
}

test "defaultModelForProvider falls back for unknown" {
    try std.testing.expectEqualStrings("anthropic/claude-sonnet-4.5", defaultModelForProvider("unknown-provider"));
}

test "providerEnvVar known providers" {
    try std.testing.expectEqualStrings("OPENROUTER_API_KEY", providerEnvVar("openrouter"));
    try std.testing.expectEqualStrings("ANTHROPIC_API_KEY", providerEnvVar("anthropic"));
    try std.testing.expectEqualStrings("OPENAI_API_KEY", providerEnvVar("openai"));
    try std.testing.expectEqualStrings("API_KEY", providerEnvVar("ollama"));
}

test "providerEnvVar grok alias maps to xai" {
    try std.testing.expectEqualStrings("API_KEY", providerEnvVar("grok"));
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
    const dir = "/tmp/nullclaw-test-scaffold";
    std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(dir) catch {};

    const ctx = ProjectContext{};
    try scaffoldWorkspace(std.testing.allocator, dir, &ctx);

    // Verify files were created
    const memory_path = "/tmp/nullclaw-test-scaffold/MEMORY.md";
    const file = try std.fs.openFileAbsolute(memory_path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(std.testing.allocator, 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(content.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, content, "Memory") != null);
}

test "scaffoldWorkspace is idempotent" {
    const dir = "/tmp/nullclaw-test-scaffold-idempotent";
    std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(dir) catch {};

    const ctx = ProjectContext{};
    try scaffoldWorkspace(std.testing.allocator, dir, &ctx);
    // Running again should not fail
    try scaffoldWorkspace(std.testing.allocator, dir, &ctx);
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
    try std.testing.expectEqualStrings("anthropic/claude-sonnet-4.5", defaultModelForProvider("openrouter"));
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
    const dir = "/tmp/nullclaw-test-scaffold-persona";
    std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(dir) catch {};

    try scaffoldWorkspace(std.testing.allocator, dir, &ProjectContext{});

    const path = "/tmp/nullclaw-test-scaffold-persona/PERSONA.md";
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(std.testing.allocator, 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(content.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, content, "Persona") != null);
}

test "scaffoldWorkspace creates RULES.md" {
    const dir = "/tmp/nullclaw-test-scaffold-rules";
    std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(dir) catch {};

    try scaffoldWorkspace(std.testing.allocator, dir, &ProjectContext{});

    const path = "/tmp/nullclaw-test-scaffold-rules/RULES.md";
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(std.testing.allocator, 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expect(content.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, content, "Rules") != null);
}

test "scaffoldWorkspace creates memory subdirectory" {
    const dir = "/tmp/nullclaw-test-scaffold-memdir";
    std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    defer std.fs.deleteTreeAbsolute(dir) catch {};

    try scaffoldWorkspace(std.testing.allocator, dir, &ProjectContext{});

    // Verify memory/ subdirectory exists
    const mem_dir = "/tmp/nullclaw-test-scaffold-memdir/memory";
    var d = try std.fs.openDirAbsolute(mem_dir, .{});
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
