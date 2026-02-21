//! Channel Loop — extracted polling loops for daemon-supervised channels.
//!
//! Contains `ChannelRuntime` (shared dependencies for message processing)
//! and `runTelegramLoop` (the polling thread function spawned by the
//! daemon supervisor).

const std = @import("std");
const Config = @import("config.zig").Config;
const telegram = @import("channels/telegram.zig");
const session_mod = @import("session.zig");
const providers = @import("providers/root.zig");
const memory_mod = @import("memory/root.zig");
const observability = @import("observability.zig");
const tools_mod = @import("tools/root.zig");
const mcp = @import("mcp.zig");
const voice = @import("voice.zig");
const health = @import("health.zig");
const daemon = @import("daemon.zig");

const log = std.log.scoped(.channel_loop);

// ════════════════════════════════════════════════════════════════════════════
// TelegramLoopState — shared state between supervisor and polling thread
// ════════════════════════════════════════════════════════════════════════════

pub const TelegramLoopState = struct {
    /// Updated after each pollUpdates() — epoch seconds.
    last_activity: std.atomic.Value(i64),
    /// Supervisor sets this to ask the polling thread to stop.
    stop_requested: std.atomic.Value(bool),
    /// Thread handle for join().
    thread: ?std.Thread = null,

    pub fn init() TelegramLoopState {
        return .{
            .last_activity = std.atomic.Value(i64).init(std.time.timestamp()),
            .stop_requested = std.atomic.Value(bool).init(false),
        };
    }
};

// Re-export centralized ProviderHolder from providers module.
pub const ProviderHolder = providers.ProviderHolder;

// ════════════════════════════════════════════════════════════════════════════
// ChannelRuntime — container for polling-thread dependencies
// ════════════════════════════════════════════════════════════════════════════

pub const ChannelRuntime = struct {
    allocator: std.mem.Allocator,
    session_mgr: session_mod.SessionManager,
    provider_holder: *ProviderHolder,
    tools: []const tools_mod.Tool,
    mem: ?memory_mod.Memory,
    noop_obs: *observability.NoopObserver,

    /// Initialize the runtime from config — mirrors main.zig:702-786 setup.
    pub fn init(allocator: std.mem.Allocator, config: *const Config) !*ChannelRuntime {
        // Provider — heap-allocated for vtable pointer stability
        const holder = try allocator.create(ProviderHolder);
        errdefer allocator.destroy(holder);

        const api_key = providers.resolveApiKeyFromConfig(
            allocator,
            config.default_provider,
            config.providers,
            config.allowEnvApiKeys(),
        ) catch null;
        holder.* = ProviderHolder.fromConfig(allocator, config.default_provider, api_key);

        const provider_i = holder.provider();

        // MCP tools
        const mcp_tools: ?[]const tools_mod.Tool = if (config.mcp_servers.len > 0)
            mcp.initMcpTools(allocator, config.mcp_servers) catch |err| blk: {
                log.warn("MCP init failed: {}", .{err});
                break :blk null;
            }
        else
            null;

        // Tools
        const tools = tools_mod.allTools(allocator, config.workspace_dir, .{
            .http_enabled = config.http_request.enabled,
            .browser_enabled = config.browser.enabled,
            .screenshot_enabled = true,
            .mcp_tools = mcp_tools,
            .agents = config.agents,
            .fallback_api_key = config.defaultProviderKey(),
            .tools_config = config.tools,
        }) catch &.{};
        errdefer if (tools.len > 0) allocator.free(tools);

        // Optional memory backend
        var mem_opt: ?memory_mod.Memory = null;
        const db_path = std.fs.path.joinZ(allocator, &.{ config.workspace_dir, "memory.db" }) catch null;
        defer if (db_path) |p| allocator.free(p);
        if (db_path) |p| {
            if (memory_mod.createMemory(allocator, config.memory.backend, p)) |mem| {
                mem_opt = mem;
            } else |_| {}
        }

        // Noop observer (heap for vtable stability)
        const noop_obs = try allocator.create(observability.NoopObserver);
        errdefer allocator.destroy(noop_obs);
        noop_obs.* = .{};
        const obs = noop_obs.observer();

        // Session manager
        const session_mgr = session_mod.SessionManager.init(allocator, config, provider_i, tools, mem_opt, obs);

        // Self — heap-allocated so pointers remain stable
        const self = try allocator.create(ChannelRuntime);
        self.* = .{
            .allocator = allocator,
            .session_mgr = session_mgr,
            .provider_holder = holder,
            .tools = tools,
            .mem = mem_opt,
            .noop_obs = noop_obs,
        };
        return self;
    }

    pub fn deinit(self: *ChannelRuntime) void {
        const alloc = self.allocator;
        self.session_mgr.deinit();
        if (self.tools.len > 0) alloc.free(self.tools);
        alloc.destroy(self.noop_obs);
        alloc.destroy(self.provider_holder);
        alloc.destroy(self);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// runTelegramLoop — polling thread function
// ════════════════════════════════════════════════════════════════════════════

/// Thread-entry function for the Telegram polling loop.
/// Mirrors main.zig:793-866 but checks `loop_state.stop_requested` and
/// `daemon.isShutdownRequested()` for graceful shutdown.
pub fn runTelegramLoop(
    allocator: std.mem.Allocator,
    config: *const Config,
    runtime: *ChannelRuntime,
    loop_state: *TelegramLoopState,
) void {
    const telegram_config = config.channels.telegram orelse return;

    // Heap-alloc TelegramChannel for vtable pointer stability
    const tg_ptr = allocator.create(telegram.TelegramChannel) catch return;
    defer allocator.destroy(tg_ptr);
    tg_ptr.* = telegram.TelegramChannel.init(allocator, telegram_config.bot_token, telegram_config.allow_from);
    tg_ptr.proxy = telegram_config.proxy;

    // Set up transcription — key comes from providers.{audio_media.provider}
    const trans = config.audio_media;
    if (config.getProviderKey(trans.provider)) |key| {
        const wt = allocator.create(voice.WhisperTranscriber) catch {
            log.warn("Failed to allocate WhisperTranscriber", .{});
            return;
        };
        wt.* = .{
            .endpoint = voice.resolveTranscriptionEndpoint(trans.provider, trans.base_url),
            .api_key = key,
            .model = trans.model,
            .language = trans.language,
        };
        tg_ptr.transcriber = wt.transcriber();
    }

    // Register bot commands and skip stale messages
    tg_ptr.setMyCommands();
    tg_ptr.dropPendingUpdates();

    var typing = telegram.TypingIndicator.init(tg_ptr);
    var evict_counter: u32 = 0;

    const model = config.default_model orelse "anthropic/claude-sonnet-4";

    // Update activity timestamp at start
    loop_state.last_activity.store(std.time.timestamp(), .release);

    while (!loop_state.stop_requested.load(.acquire) and !daemon.isShutdownRequested()) {
        const messages = tg_ptr.pollUpdates(allocator) catch |err| {
            log.warn("Telegram poll error: {}", .{err});
            loop_state.last_activity.store(std.time.timestamp(), .release);
            std.Thread.sleep(5 * std.time.ns_per_s);
            continue;
        };

        // Update activity after each poll (even if no messages)
        loop_state.last_activity.store(std.time.timestamp(), .release);

        for (messages) |msg| {
            // Handle /start command
            const trimmed = std.mem.trim(u8, msg.content, " \t\r\n");
            if (std.mem.eql(u8, trimmed, "/start")) {
                var greeting_buf: [512]u8 = undefined;
                const name = msg.first_name orelse msg.id;
                const greeting = std.fmt.bufPrint(&greeting_buf, "Hello, {s}! I'm nullClaw.\n\nModel: {s}\nType /help for available commands.", .{ name, model }) catch "Hello! I'm nullClaw. Type /help for commands.";
                tg_ptr.sendMessageWithReply(msg.sender, greeting, msg.message_id) catch |err| log.err("failed to send /start reply: {}", .{err});
                continue;
            }

            // Reply-to logic
            const use_reply_to = msg.is_group or telegram_config.reply_in_private;
            const reply_to_id: ?i64 = if (use_reply_to) msg.message_id else null;

            // Session key
            var key_buf: [128]u8 = undefined;
            const session_key = std.fmt.bufPrint(&key_buf, "telegram:{s}", .{msg.sender}) catch msg.sender;

            // Typing indicator
            typing.start(msg.sender);

            const reply = runtime.session_mgr.processMessage(session_key, msg.content) catch |err| {
                typing.stop();
                log.err("Agent error: {}", .{err});
                const err_msg: []const u8 = switch (err) {
                    error.CurlFailed, error.CurlReadError, error.CurlWaitError => "Network error. Please try again.",
                    error.OutOfMemory => "Out of memory.",
                    else => "An error occurred. Try again or /new for a fresh session.",
                };
                tg_ptr.sendMessageWithReply(msg.sender, err_msg, reply_to_id) catch |send_err| log.err("failed to send error reply: {}", .{send_err});
                continue;
            };
            defer allocator.free(reply);

            typing.stop();

            tg_ptr.sendMessageWithReply(msg.sender, reply, reply_to_id) catch |err| {
                log.warn("Send error: {}", .{err});
            };
        }

        if (messages.len > 0) {
            for (messages) |msg| {
                msg.deinit(allocator);
            }
            allocator.free(messages);
        }

        // Periodic session eviction
        evict_counter += 1;
        if (evict_counter >= 100) {
            evict_counter = 0;
            _ = runtime.session_mgr.evictIdle(config.agent.session_idle_timeout_secs);
        }

        health.markComponentOk("telegram");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "TelegramLoopState init defaults" {
    const state = TelegramLoopState.init();
    try std.testing.expect(!state.stop_requested.load(.acquire));
    try std.testing.expect(state.thread == null);
    try std.testing.expect(state.last_activity.load(.acquire) > 0);
}

test "TelegramLoopState stop_requested toggle" {
    var state = TelegramLoopState.init();
    try std.testing.expect(!state.stop_requested.load(.acquire));
    state.stop_requested.store(true, .release);
    try std.testing.expect(state.stop_requested.load(.acquire));
}

test "TelegramLoopState last_activity update" {
    var state = TelegramLoopState.init();
    const before = state.last_activity.load(.acquire);
    std.Thread.sleep(10 * std.time.ns_per_ms);
    state.last_activity.store(std.time.timestamp(), .release);
    const after = state.last_activity.load(.acquire);
    try std.testing.expect(after >= before);
}

test "ProviderHolder tagged union fields" {
    // Compile-time check that ProviderHolder has expected variants
    try std.testing.expect(@hasField(ProviderHolder, "openrouter"));
    try std.testing.expect(@hasField(ProviderHolder, "anthropic"));
    try std.testing.expect(@hasField(ProviderHolder, "openai"));
    try std.testing.expect(@hasField(ProviderHolder, "gemini"));
    try std.testing.expect(@hasField(ProviderHolder, "ollama"));
    try std.testing.expect(@hasField(ProviderHolder, "compatible"));
    try std.testing.expect(@hasField(ProviderHolder, "openai_codex"));
}
