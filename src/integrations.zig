const std = @import("std");

// Integrations -- integration registry and status tracking.
//
// Mirrors ZeroClaw's integrations module: categories, status,
// and the full catalog of supported integrations.

// ── Integration Status ──────────────────────────────────────────

pub const IntegrationStatus = enum {
    available,
    active,
    coming_soon,
};

// ── Integration Category ────────────────────────────────────────

pub const IntegrationCategory = enum {
    chat,
    ai_model,
    productivity,
    music_audio,
    smart_home,
    tools_automation,
    media_creative,
    social,
    platform,

    pub fn label(self: IntegrationCategory) []const u8 {
        return switch (self) {
            .chat => "Chat Providers",
            .ai_model => "AI Models",
            .productivity => "Productivity",
            .music_audio => "Music & Audio",
            .smart_home => "Smart Home",
            .tools_automation => "Tools & Automation",
            .media_creative => "Media & Creative",
            .social => "Social",
            .platform => "Platforms",
        };
    }

    pub fn all() []const IntegrationCategory {
        return &.{
            .chat,
            .ai_model,
            .productivity,
            .music_audio,
            .smart_home,
            .tools_automation,
            .media_creative,
            .social,
            .platform,
        };
    }
};

// ── Integration Entry ───────────────────────────────────────────

pub const IntegrationEntry = struct {
    name: []const u8,
    description: []const u8,
    category: IntegrationCategory,
    status: IntegrationStatus,
};

// ── Registry ────────────────────────────────────────────────────

/// Returns the full catalog of integrations.
/// Status is resolved statically (no config dependency in Zig port).
pub fn allIntegrations() []const IntegrationEntry {
    return &all_integrations_list;
}

const all_integrations_list = [_]IntegrationEntry{
    // Chat Providers
    .{ .name = "Telegram", .description = "Bot API -- long-polling", .category = .chat, .status = .available },
    .{ .name = "Discord", .description = "Servers, channels & DMs", .category = .chat, .status = .available },
    .{ .name = "Slack", .description = "Workspace apps via Web API", .category = .chat, .status = .available },
    .{ .name = "Webhooks", .description = "HTTP endpoint for triggers", .category = .chat, .status = .available },
    .{ .name = "WhatsApp", .description = "Meta Cloud API via webhook", .category = .chat, .status = .available },
    .{ .name = "Signal", .description = "Privacy-focused via signal-cli", .category = .chat, .status = .coming_soon },
    .{ .name = "iMessage", .description = "macOS AppleScript bridge", .category = .chat, .status = .available },
    .{ .name = "Microsoft Teams", .description = "Enterprise chat support", .category = .chat, .status = .coming_soon },
    .{ .name = "Matrix", .description = "Matrix protocol (Element)", .category = .chat, .status = .available },
    .{ .name = "Nostr", .description = "Decentralized DMs (NIP-04)", .category = .chat, .status = .coming_soon },
    .{ .name = "WebChat", .description = "Browser-based chat UI", .category = .chat, .status = .coming_soon },
    .{ .name = "Nextcloud Talk", .description = "Self-hosted Nextcloud chat", .category = .chat, .status = .coming_soon },
    .{ .name = "Zalo", .description = "Zalo Bot API", .category = .chat, .status = .coming_soon },
    .{ .name = "DingTalk", .description = "DingTalk Stream Mode", .category = .chat, .status = .available },
    .{ .name = "IRC", .description = "IRC servers (Libera, MeshRelay, etc.)", .category = .chat, .status = .available },
    // AI Models
    .{ .name = "OpenRouter", .description = "200+ models, 1 API key", .category = .ai_model, .status = .available },
    .{ .name = "Anthropic", .description = "Claude 3.5/4 Sonnet & Opus", .category = .ai_model, .status = .available },
    .{ .name = "OpenAI", .description = "GPT-4o, GPT-5, o1", .category = .ai_model, .status = .available },
    .{ .name = "Google", .description = "Gemini 2.5 Pro/Flash", .category = .ai_model, .status = .available },
    .{ .name = "DeepSeek", .description = "DeepSeek V3 & R1", .category = .ai_model, .status = .available },
    .{ .name = "xAI", .description = "Grok 3 & 4", .category = .ai_model, .status = .available },
    .{ .name = "Mistral", .description = "Mistral Large & Codestral", .category = .ai_model, .status = .available },
    .{ .name = "Ollama", .description = "Local models (Llama, etc.)", .category = .ai_model, .status = .available },
    .{ .name = "Perplexity", .description = "Search-augmented AI", .category = .ai_model, .status = .available },
    .{ .name = "Hugging Face", .description = "Open-source models", .category = .ai_model, .status = .coming_soon },
    .{ .name = "LM Studio", .description = "Local model server", .category = .ai_model, .status = .coming_soon },
    .{ .name = "Venice", .description = "Privacy-first inference", .category = .ai_model, .status = .available },
    .{ .name = "Vercel AI", .description = "Vercel AI Gateway", .category = .ai_model, .status = .available },
    .{ .name = "Cloudflare AI", .description = "Cloudflare AI Gateway", .category = .ai_model, .status = .available },
    .{ .name = "Moonshot", .description = "Kimi & Kimi Coding", .category = .ai_model, .status = .available },
    .{ .name = "Synthetic", .description = "Synthetic AI models", .category = .ai_model, .status = .available },
    .{ .name = "OpenCode Zen", .description = "Code-focused AI models", .category = .ai_model, .status = .available },
    .{ .name = "Z.AI", .description = "Z.AI inference", .category = .ai_model, .status = .available },
    .{ .name = "GLM", .description = "ChatGLM / Zhipu models", .category = .ai_model, .status = .available },
    .{ .name = "MiniMax", .description = "MiniMax AI models", .category = .ai_model, .status = .available },
    .{ .name = "Amazon Bedrock", .description = "AWS managed model access", .category = .ai_model, .status = .available },
    .{ .name = "Qianfan", .description = "Baidu AI models", .category = .ai_model, .status = .available },
    .{ .name = "Groq", .description = "Ultra-fast LPU inference", .category = .ai_model, .status = .available },
    .{ .name = "Together AI", .description = "Open-source model hosting", .category = .ai_model, .status = .available },
    .{ .name = "Fireworks AI", .description = "Fast open-source inference", .category = .ai_model, .status = .available },
    .{ .name = "Cohere", .description = "Command R+ & embeddings", .category = .ai_model, .status = .available },
    // Productivity
    .{ .name = "GitHub", .description = "Code, issues, PRs", .category = .productivity, .status = .coming_soon },
    .{ .name = "Notion", .description = "Workspace & databases", .category = .productivity, .status = .coming_soon },
    .{ .name = "Apple Notes", .description = "Native macOS/iOS notes", .category = .productivity, .status = .coming_soon },
    .{ .name = "Apple Reminders", .description = "Task management", .category = .productivity, .status = .coming_soon },
    .{ .name = "Obsidian", .description = "Knowledge graph notes", .category = .productivity, .status = .coming_soon },
    .{ .name = "Things 3", .description = "GTD task manager", .category = .productivity, .status = .coming_soon },
    .{ .name = "Bear Notes", .description = "Markdown notes", .category = .productivity, .status = .coming_soon },
    .{ .name = "Trello", .description = "Kanban boards", .category = .productivity, .status = .coming_soon },
    .{ .name = "Linear", .description = "Issue tracking", .category = .productivity, .status = .coming_soon },
    // Music & Audio
    .{ .name = "Spotify", .description = "Music playback control", .category = .music_audio, .status = .coming_soon },
    .{ .name = "Sonos", .description = "Multi-room audio", .category = .music_audio, .status = .coming_soon },
    .{ .name = "Shazam", .description = "Song recognition", .category = .music_audio, .status = .coming_soon },
    // Smart Home
    .{ .name = "Home Assistant", .description = "Home automation hub", .category = .smart_home, .status = .coming_soon },
    .{ .name = "Philips Hue", .description = "Smart lighting", .category = .smart_home, .status = .coming_soon },
    .{ .name = "8Sleep", .description = "Smart mattress", .category = .smart_home, .status = .coming_soon },
    // Tools & Automation
    .{ .name = "Browser", .description = "Chrome/Chromium control", .category = .tools_automation, .status = .active },
    .{ .name = "Shell", .description = "Terminal command execution", .category = .tools_automation, .status = .active },
    .{ .name = "File System", .description = "Read/write files", .category = .tools_automation, .status = .active },
    .{ .name = "Cron", .description = "Scheduled tasks", .category = .tools_automation, .status = .available },
    .{ .name = "Voice", .description = "Voice wake + talk mode", .category = .tools_automation, .status = .coming_soon },
    .{ .name = "Gmail", .description = "Email triggers & send", .category = .tools_automation, .status = .coming_soon },
    .{ .name = "1Password", .description = "Secure credentials", .category = .tools_automation, .status = .coming_soon },
    .{ .name = "Weather", .description = "Forecasts & conditions", .category = .tools_automation, .status = .coming_soon },
    .{ .name = "Canvas", .description = "Visual workspace + A2UI", .category = .tools_automation, .status = .coming_soon },
    // Media & Creative
    .{ .name = "Image Gen", .description = "AI image generation", .category = .media_creative, .status = .coming_soon },
    .{ .name = "GIF Search", .description = "Find the perfect GIF", .category = .media_creative, .status = .coming_soon },
    .{ .name = "Screen Capture", .description = "Screenshot & screen control", .category = .media_creative, .status = .coming_soon },
    .{ .name = "Camera", .description = "Photo/video capture", .category = .media_creative, .status = .coming_soon },
    // Social
    .{ .name = "Twitter/X", .description = "Tweet, reply, search", .category = .social, .status = .coming_soon },
    .{ .name = "Email", .description = "IMAP/SMTP email channel", .category = .social, .status = .available },
    // Platforms
    .{ .name = "macOS", .description = "Native support + AppleScript", .category = .platform, .status = .active },
    .{ .name = "Linux", .description = "Native support", .category = .platform, .status = .available },
    .{ .name = "Windows", .description = "WSL2 recommended", .category = .platform, .status = .available },
    .{ .name = "iOS", .description = "Chat via Telegram/Discord", .category = .platform, .status = .available },
    .{ .name = "Android", .description = "Chat via Telegram/Discord", .category = .platform, .status = .available },
};

/// Look up an integration by name (case-insensitive).
pub fn findIntegration(name: []const u8) ?*const IntegrationEntry {
    for (&all_integrations_list) |*entry| {
        if (eqlIgnoreCase(entry.name, name)) return entry;
    }
    return null;
}

/// Count integrations in a given category.
pub fn countByCategory(category: IntegrationCategory) usize {
    var count: usize = 0;
    for (allIntegrations()) |entry| {
        if (entry.category == category) count += 1;
    }
    return count;
}

/// Count integrations with a given status.
pub fn countByStatus(status: IntegrationStatus) usize {
    var count: usize = 0;
    for (allIntegrations()) |entry| {
        if (entry.status == status) count += 1;
    }
    return count;
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

// ── Tests ───────────────────────────────────────────────────────

test "allIntegrations returns at least 50 entries" {
    const entries = allIntegrations();
    try std.testing.expect(entries.len >= 50);
}

test "all categories represented" {
    for (IntegrationCategory.all()) |cat| {
        try std.testing.expect(countByCategory(cat) > 0);
    }
}

test "no empty names or descriptions" {
    for (allIntegrations()) |entry| {
        try std.testing.expect(entry.name.len > 0);
        try std.testing.expect(entry.description.len > 0);
    }
}

test "no duplicate names" {
    const entries = allIntegrations();
    for (entries, 0..) |entry, i| {
        for (entries[i + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, entry.name, other.name));
        }
    }
}

test "category all includes every variant once" {
    const all = IntegrationCategory.all();
    try std.testing.expectEqual(@as(usize, 9), all.len);
}

test "findIntegration finds Telegram" {
    const entry = findIntegration("Telegram");
    try std.testing.expect(entry != null);
    try std.testing.expectEqualStrings("Telegram", entry.?.name);
    try std.testing.expectEqual(IntegrationCategory.chat, entry.?.category);
}

test "findIntegration is case-insensitive" {
    const entry = findIntegration("telegram");
    try std.testing.expect(entry != null);
    try std.testing.expectEqualStrings("Telegram", entry.?.name);
}

test "findIntegration returns null for unknown" {
    try std.testing.expect(findIntegration("definitely-not-a-real-integration") == null);
}

test "Shell and File System are always active" {
    const shell = findIntegration("Shell");
    try std.testing.expect(shell != null);
    try std.testing.expectEqual(IntegrationStatus.active, shell.?.status);

    const fs = findIntegration("File System");
    try std.testing.expect(fs != null);
    try std.testing.expectEqual(IntegrationStatus.active, fs.?.status);
}

test "coming soon integrations" {
    const signal = findIntegration("Signal");
    try std.testing.expect(signal != null);
    try std.testing.expectEqual(IntegrationStatus.coming_soon, signal.?.status);

    const nostr = findIntegration("Nostr");
    try std.testing.expect(nostr != null);
    try std.testing.expectEqual(IntegrationStatus.coming_soon, nostr.?.status);

    const spotify = findIntegration("Spotify");
    try std.testing.expect(spotify != null);
    try std.testing.expectEqual(IntegrationStatus.coming_soon, spotify.?.status);

    const ha = findIntegration("Home Assistant");
    try std.testing.expect(ha != null);
    try std.testing.expectEqual(IntegrationStatus.coming_soon, ha.?.status);
}

test "chat category has at least 5 entries" {
    try std.testing.expect(countByCategory(.chat) >= 5);
}

test "ai_model category has at least 5 entries" {
    try std.testing.expect(countByCategory(.ai_model) >= 5);
}

test "countByStatus returns non-zero for available" {
    try std.testing.expect(countByStatus(.available) > 0);
}

test "countByStatus returns non-zero for active" {
    try std.testing.expect(countByStatus(.active) > 0);
}

test "countByStatus returns non-zero for coming_soon" {
    try std.testing.expect(countByStatus(.coming_soon) > 0);
}

test "macOS integration is active" {
    const macos = findIntegration("macOS");
    try std.testing.expect(macos != null);
    try std.testing.expectEqual(IntegrationStatus.active, macos.?.status);
}
