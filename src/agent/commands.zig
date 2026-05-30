const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const providers = @import("../providers/root.zig");
const Tool = @import("../tools/root.zig").Tool;
const skills_mod = @import("../skills.zig");
const spawn_tool_mod = @import("../tools/spawn.zig");
const subagent_mod = @import("../subagent.zig");
const memory_mod = @import("../memory/root.zig");
const config_types = @import("../config_types.zig");
const config_module = @import("../config.zig");
const config_paths = @import("../config_paths.zig");
const capabilities_mod = @import("../capabilities.zig");
const config_mutator = @import("../config_mutator.zig");
const interaction_choices = @import("../interactions/choices.zig");
const onboard = @import("../onboard.zig");
const context_tokens = @import("context_tokens.zig");
const max_tokens_resolver = @import("max_tokens.zig");
const control_plane = @import("../control_plane.zig");
const model_refs = @import("../model_refs.zig");
const provider_names = @import("../provider_names.zig");
const version = @import("../version.zig");
const command_summary = @import("../command_summary.zig");
const util = @import("../util.zig");
const cost_mod = @import("../cost.zig");
const log = std.log.scoped(.agent);

const SlashCommand = control_plane.SlashCommand;
const parseSlashCommand = control_plane.parseSlashCommand;
const isSlashName = control_plane.isSlashName;

pub const BARE_SESSION_RESET_PROMPT =
    "A new session was started via /new or /reset. Execute your Session Startup sequence now - read the required files before responding to the user. Then greet the user in your configured persona, if one is provided. Be yourself - use your defined voice, mannerisms, and mood. Keep it to 1-3 sentences and ask what they want to do. If the runtime model differs from default_model in the system prompt, mention the default model. Do not mention internal steps, files, tools, or reasoning.";

const MODEL_MENU_PAGE_SIZE: usize = 10;

pub fn bareSessionResetPrompt(message: []const u8) ?[]const u8 {
    const cmd = parseSlashCommand(message) orelse return null;
    if (!(isSlashName(cmd, "new") or isSlashName(cmd, "reset"))) return null;
    if (cmd.arg.len != 0) return null;
    return BARE_SESSION_RESET_PROMPT;
}

pub const TurnInputPlan = struct {
    clear_session: bool = false,
    invoke_local_handler: bool = false,
    llm_user_message: ?[]const u8 = null,
};

const SlashCommandKind = enum {
    new_reset,
    restart,
    help,
    status,
    whoami,
    model,
    think,
    verbose,
    reasoning,
    exec,
    queue,
    usage,
    tts,
    stop,
    compact,
    allowlist,
    approve,
    context,
    export_session,
    session,
    subagents,
    agents,
    focus,
    unfocus,
    kill,
    steer,
    tell,
    config,
    capabilities,
    debug,
    dock_telegram,
    dock_discord,
    dock_slack,
    activation,
    send,
    elevated,
    bash,
    poll,
    skill,
    doctor,
    memory,
    cost,
    unknown,
};

fn classifySlashCommand(cmd: SlashCommand) SlashCommandKind {
    if (isSlashName(cmd, "new") or isSlashName(cmd, "reset")) return .new_reset;
    if (isSlashName(cmd, "restart")) return .restart;
    if (isSlashName(cmd, "help") or isSlashName(cmd, "commands") or isSlashName(cmd, "menu")) return .help;
    if (isSlashName(cmd, "status")) return .status;
    if (isSlashName(cmd, "whoami") or isSlashName(cmd, "id")) return .whoami;
    if (isSlashName(cmd, "model") or isSlashName(cmd, "models")) return .model;
    if (isSlashName(cmd, "think") or isSlashName(cmd, "thinking") or isSlashName(cmd, "t")) return .think;
    if (isSlashName(cmd, "verbose") or isSlashName(cmd, "v")) return .verbose;
    if (isSlashName(cmd, "reasoning") or isSlashName(cmd, "reason")) return .reasoning;
    if (isSlashName(cmd, "exec")) return .exec;
    if (isSlashName(cmd, "queue")) return .queue;
    if (isSlashName(cmd, "usage")) return .usage;
    if (isSlashName(cmd, "tts") or isSlashName(cmd, "voice")) return .tts;
    if (isSlashName(cmd, "stop") or isSlashName(cmd, "abort")) return .stop;
    if (isSlashName(cmd, "compact")) return .compact;
    if (isSlashName(cmd, "allowlist")) return .allowlist;
    if (isSlashName(cmd, "approve")) return .approve;
    if (isSlashName(cmd, "context")) return .context;
    if (isSlashName(cmd, "export-session") or isSlashName(cmd, "export")) return .export_session;
    if (isSlashName(cmd, "session")) return .session;
    if (isSlashName(cmd, "subagents") or isSlashName(cmd, "tasks")) return .subagents;
    if (isSlashName(cmd, "agents")) return .agents;
    if (isSlashName(cmd, "focus")) return .focus;
    if (isSlashName(cmd, "unfocus")) return .unfocus;
    if (isSlashName(cmd, "kill")) return .kill;
    if (isSlashName(cmd, "steer")) return .steer;
    if (isSlashName(cmd, "tell")) return .tell;
    if (isSlashName(cmd, "config")) return .config;
    if (isSlashName(cmd, "capabilities")) return .capabilities;
    if (isSlashName(cmd, "debug")) return .debug;
    if (isSlashName(cmd, "dock-telegram") or isSlashName(cmd, "dock_telegram")) return .dock_telegram;
    if (isSlashName(cmd, "dock-discord") or isSlashName(cmd, "dock_discord")) return .dock_discord;
    if (isSlashName(cmd, "dock-slack") or isSlashName(cmd, "dock_slack")) return .dock_slack;
    if (isSlashName(cmd, "activation")) return .activation;
    if (isSlashName(cmd, "send")) return .send;
    if (isSlashName(cmd, "elevated") or isSlashName(cmd, "elev")) return .elevated;
    if (isSlashName(cmd, "bash")) return .bash;
    if (isSlashName(cmd, "poll")) return .poll;
    if (isSlashName(cmd, "skill") or isSlashName(cmd, "skills") or isSlashName(cmd, "iskill")) return .skill;
    if (isSlashName(cmd, "doctor")) return .doctor;
    if (isSlashName(cmd, "memory") or isSlashName(cmd, "mem")) return .memory;
    if (isSlashName(cmd, "cost") or isSlashName(cmd, "costs") or isSlashName(cmd, "pricing")) return .cost;
    return .unknown;
}

fn slashCommandClearsSession(kind: SlashCommandKind) bool {
    return kind == .new_reset or kind == .restart;
}

pub fn planTurnInput(message: []const u8) TurnInputPlan {
    const cmd = parseSlashCommand(message) orelse return .{ .llm_user_message = message };
    const kind = classifySlashCommand(cmd);
    const clear_session = slashCommandClearsSession(kind);

    if (bareSessionResetPrompt(message)) |fresh_prompt| {
        return .{
            .clear_session = clear_session,
            .invoke_local_handler = true,
            .llm_user_message = fresh_prompt,
        };
    }

    if (kind != .unknown) {
        return .{
            .clear_session = clear_session,
            .invoke_local_handler = true,
            .llm_user_message = null,
        };
    }

    return .{ .llm_user_message = message };
}

pub fn persistedRuntimeCommand(message: []const u8) ?[]const u8 {
    const cmd = parseSlashCommand(message) orelse return null;
    const kind = classifySlashCommand(cmd);
    const arg = std.mem.trim(u8, cmd.arg, " \t");
    const first = firstToken(arg);

    return switch (kind) {
        .think, .verbose, .reasoning, .usage, .activation, .send, .elevated => blk: {
            if (first.len == 0 or std.ascii.eqlIgnoreCase(first, "status")) break :blk null;
            break :blk message;
        },
        .exec, .tts => blk: {
            if (arg.len == 0 or std.ascii.eqlIgnoreCase(arg, "status")) break :blk null;
            break :blk message;
        },
        .queue => blk: {
            if (arg.len == 0 or std.ascii.eqlIgnoreCase(arg, "status")) break :blk null;
            break :blk message;
        },
        .skill => skillRuntimeCommand(message, cmd),
        .session => blk: {
            if (!std.ascii.eqlIgnoreCase(first, "ttl")) break :blk null;
            const tail = splitFirstToken(arg).tail;
            if (firstToken(tail).len == 0) break :blk null;
            break :blk message;
        },
        .focus, .unfocus, .dock_telegram, .dock_discord, .dock_slack => message,
        .debug => blk: {
            if (std.ascii.eqlIgnoreCase(arg, "reset")) break :blk message;
            break :blk null;
        },
        else => null,
    };
}

fn skillRuntimeCommand(message: []const u8, cmd: SlashCommand) ?[]const u8 {
    if (isSlashName(cmd, "skills")) return null;

    const parsed = splitFirstToken(cmd.arg);
    const head = parsed.head;
    const tail = std.mem.trim(u8, parsed.tail, " \t");
    if (head.len == 0) return null;

    if (std.ascii.eqlIgnoreCase(head, "status") or
        std.ascii.eqlIgnoreCase(head, "list") or
        std.ascii.eqlIgnoreCase(head, "reload") or
        std.ascii.eqlIgnoreCase(head, "refresh"))
    {
        return null;
    }

    if (std.ascii.eqlIgnoreCase(head, "clear") or std.ascii.eqlIgnoreCase(head, "off")) {
        return message;
    }

    if (isSlashName(cmd, "iskill")) {
        if (tail.len != 0) return null;
        return message;
    }

    if (tail.len == 0) return message;
    return null;
}

fn firstToken(arg: []const u8) []const u8 {
    var it = std.mem.tokenizeAny(u8, arg, " \t");
    return it.next() orelse "";
}

fn parsePositiveUsize(raw: []const u8) ?usize {
    const n = std.fmt.parseInt(usize, raw, 10) catch return null;
    if (n == 0) return null;
    return n;
}

fn interactiveModelMenuChannel(session_id: ?[]const u8, context_channel: ?[]const u8) ?[]const u8 {
    if (context_channel) |channel| {
        if (provider_names.providerNamesMatchIgnoreCase(channel, "telegram")) return "telegram";
        if (provider_names.providerNamesMatchIgnoreCase(channel, "discord")) return "discord";
        if (provider_names.providerNamesMatchIgnoreCase(channel, "slack")) return "slack";
        if (provider_names.providerNamesMatchIgnoreCase(channel, "lark")) return "lark";
    }
    const sid = session_id orelse return null;

    if (std.mem.startsWith(u8, sid, "agent:")) {
        const after_agent = sid["agent:".len..];
        const agent_sep = std.mem.indexOfScalar(u8, after_agent, ':') orelse return null;
        const routed = after_agent[agent_sep + 1 ..];
        if (std.mem.startsWith(u8, routed, "telegram:")) return "telegram";
        if (std.mem.startsWith(u8, routed, "discord:")) return "discord";
        if (std.mem.startsWith(u8, routed, "slack:")) return "slack";
        if (std.mem.startsWith(u8, routed, "lark:")) return "lark";
    }

    if (std.mem.startsWith(u8, sid, "telegram:")) return "telegram";
    if (std.mem.startsWith(u8, sid, "discord:")) return "discord";
    if (std.mem.startsWith(u8, sid, "slack:")) return "slack";
    if (std.mem.startsWith(u8, sid, "lark:")) return "lark";
    return null;
}

fn modelMenuChoiceLabel(allocator: std.mem.Allocator, model_id: []const u8, is_current: bool) ![]u8 {
    const prefix = if (is_current) "* " else "";
    const max_model_len = interaction_choices.MAX_LABEL_LEN - prefix.len;
    const visible_model = if (model_id.len <= max_model_len) model_id else model_id[0..max_model_len];
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ prefix, visible_model });
}

fn freeOwnedStringSlice(allocator: std.mem.Allocator, items: [][]const u8) void {
    for (items) |item| allocator.free(item);
    allocator.free(items);
}

fn providerMenuChoiceLabel(allocator: std.mem.Allocator, provider_name: []const u8, is_current: bool) ![]u8 {
    const prefix = if (is_current) "* " else "";
    const max_provider_len = interaction_choices.MAX_LABEL_LEN - prefix.len;
    const visible_provider = if (provider_name.len <= max_provider_len) provider_name else provider_name[0..max_provider_len];
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ prefix, visible_provider });
}

fn appendUniqueOwnedString(
    allocator: std.mem.Allocator,
    items: *std.ArrayListUnmanaged([]const u8),
    value: []const u8,
) !void {
    for (items.items) |existing| {
        if (provider_names.providerNamesMatchIgnoreCase(existing, value)) return;
    }
    try items.append(allocator, try allocator.dupe(u8, value));
}

fn collectInteractiveProviderNames(self: anytype, allocator: std.mem.Allocator) ![][]const u8 {
    var items: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer freeOwnedStringSlice(allocator, items.items);

    if (@hasField(@TypeOf(self.*), "default_provider") and self.default_provider.len > 0) {
        try appendUniqueOwnedString(allocator, &items, self.default_provider);
    }
    if (@hasField(@TypeOf(self.*), "configured_providers")) {
        for (self.configured_providers) |entry| {
            if (entry.name.len == 0) continue;
            try appendUniqueOwnedString(allocator, &items, entry.name);
        }
    }
    return try items.toOwnedSlice(allocator);
}

fn renderInteractiveProviderMenuFromProviders(
    allocator: std.mem.Allocator,
    current_provider: []const u8,
    current_model: []const u8,
    page_number: usize,
    providers_list: []const []const u8,
) !?[]u8 {
    if (providers_list.len == 0) return null;

    const total_pages = @max(@as(usize, 1), std.math.divCeil(usize, providers_list.len, MODEL_MENU_PAGE_SIZE) catch 1);
    const clamped_page = @min(@max(page_number, 1), total_pages);
    const start = (clamped_page - 1) * MODEL_MENU_PAGE_SIZE;
    const end = @min(start + MODEL_MENU_PAGE_SIZE, providers_list.len);

    const ChoiceDraft = struct {
        id: []const u8,
        label: []const u8,
        submit_text: []const u8,
    };

    var options: [interaction_choices.MAX_OPTIONS]ChoiceDraft = undefined;
    var option_id_bufs: [interaction_choices.MAX_OPTIONS][interaction_choices.MAX_ID_LEN]u8 = undefined;
    var submit_text_bufs: [interaction_choices.MAX_OPTIONS][interaction_choices.MAX_SUBMIT_TEXT_LEN]u8 = undefined;
    var option_count: usize = 0;
    var labels_to_free: [interaction_choices.MAX_OPTIONS]?[]u8 = .{null} ** interaction_choices.MAX_OPTIONS;
    defer {
        for (labels_to_free) |label_opt| {
            if (label_opt) |label| allocator.free(label);
        }
    }

    for (providers_list[start..end], 0..) |provider_name, idx| {
        const label = try providerMenuChoiceLabel(allocator, provider_name, provider_names.providerNamesMatchIgnoreCase(provider_name, current_provider));
        labels_to_free[option_count] = label;
        const submit_text = try std.fmt.bufPrint(&submit_text_bufs[option_count], "/model provider {s}", .{provider_name});
        const option_id = try std.fmt.bufPrint(&option_id_bufs[option_count], "p{d}", .{idx + 1});
        options[option_count] = .{
            .id = option_id,
            .label = label,
            .submit_text = submit_text,
        };
        option_count += 1;
    }

    if (clamped_page > 1 and option_count < interaction_choices.MAX_OPTIONS) {
        const submit_text = try std.fmt.bufPrint(&submit_text_bufs[option_count], "/model page {d}", .{clamped_page - 1});
        options[option_count] = .{ .id = "prev", .label = "Prev", .submit_text = submit_text };
        option_count += 1;
    }
    if (clamped_page < total_pages and option_count < interaction_choices.MAX_OPTIONS) {
        const submit_text = try std.fmt.bufPrint(&submit_text_bufs[option_count], "/model page {d}", .{clamped_page + 1});
        options[option_count] = .{ .id = "next", .label = "Next", .submit_text = submit_text };
        option_count += 1;
    }

    if (option_count < interaction_choices.MIN_OPTIONS) return null;

    const visible = try std.fmt.allocPrint(
        allocator,
        "Current model: {s}\nProvider: {s}\nChoose a provider (page {d}/{d}).",
        .{ current_model, current_provider, clamped_page, total_pages },
    );
    defer allocator.free(visible);

    return try interaction_choices.renderAssistantChoices(allocator, visible, options[0..option_count]);
}
fn renderInteractiveModelMenuFromModels(
    allocator: std.mem.Allocator,
    provider: []const u8,
    current_model: []const u8,
    page_number: usize,
    models: []const []const u8,
) !?[]u8 {
    if (models.len == 0) return null;

    const total_pages = @max(@as(usize, 1), std.math.divCeil(usize, models.len, MODEL_MENU_PAGE_SIZE) catch 1);
    const clamped_page = @min(@max(page_number, 1), total_pages);
    const start = (clamped_page - 1) * MODEL_MENU_PAGE_SIZE;
    const end = @min(start + MODEL_MENU_PAGE_SIZE, models.len);

    const ChoiceDraft = struct {
        id: []const u8,
        label: []const u8,
        submit_text: []const u8,
    };

    var options: [interaction_choices.MAX_OPTIONS]ChoiceDraft = undefined;
    var option_id_bufs: [interaction_choices.MAX_OPTIONS][interaction_choices.MAX_ID_LEN]u8 = undefined;
    var submit_text_bufs: [interaction_choices.MAX_OPTIONS][interaction_choices.MAX_SUBMIT_TEXT_LEN]u8 = undefined;
    var option_count: usize = 0;
    var labels_to_free: [interaction_choices.MAX_OPTIONS]?[]u8 = .{null} ** interaction_choices.MAX_OPTIONS;
    defer {
        for (labels_to_free) |label_opt| {
            if (label_opt) |label| allocator.free(label);
        }
    }

    for (models[start..end], 0..) |model_id, idx| {
        const label = try modelMenuChoiceLabel(allocator, model_id, std.mem.eql(u8, model_id, current_model));
        labels_to_free[option_count] = label;
        const submit_text = try std.fmt.bufPrint(&submit_text_bufs[option_count], "/model {s}/{s}", .{ provider, model_id });
        const option_id = try std.fmt.bufPrint(&option_id_bufs[option_count], "m{d}", .{idx + 1});

        options[option_count] = .{
            .id = option_id,
            .label = label,
            .submit_text = submit_text,
        };
        option_count += 1;
    }

    if (clamped_page > 1) {
        const submit_text = try std.fmt.bufPrint(&submit_text_bufs[option_count], "/model provider {s} page {d}", .{ provider, clamped_page - 1 });
        options[option_count] = .{
            .id = "prev",
            .label = "Prev",
            .submit_text = submit_text,
        };
        option_count += 1;
    }
    if (clamped_page < total_pages) {
        const submit_text = try std.fmt.bufPrint(&submit_text_bufs[option_count], "/model provider {s} page {d}", .{ provider, clamped_page + 1 });
        options[option_count] = .{
            .id = "next",
            .label = "Next",
            .submit_text = submit_text,
        };
        option_count += 1;
    }

    if (option_count < interaction_choices.MIN_OPTIONS) return null;

    const visible = try std.fmt.allocPrint(
        allocator,
        "Current model: {s}\nProvider: {s}\nChoose a model (page {d}/{d}).",
        .{ current_model, provider, clamped_page, total_pages },
    );
    defer allocator.free(visible);

    return try interaction_choices.renderAssistantChoices(allocator, visible, options[0..option_count]);
}

fn renderInteractiveProviderMenu(self: anytype, page_number: usize) !?[]u8 {
    const context_channel = if (@hasField(@TypeOf(self.*), "conversation_context"))
        if (self.conversation_context) |ctx| ctx.channel else null
    else
        null;
    if (interactiveModelMenuChannel(if (@hasField(@TypeOf(self.*), "memory_session_id")) self.memory_session_id else null, context_channel) == null) {
        return null;
    }
    if (!@hasField(@TypeOf(self.*), "default_provider")) return null;
    if (!@hasField(@TypeOf(self.*), "model_name")) return null;

    const providers_list = try collectInteractiveProviderNames(self, self.allocator);
    defer freeOwnedStringSlice(self.allocator, providers_list);

    if (providers_list.len == 1) {
        return renderInteractiveModelMenu(self, providers_list[0], page_number);
    }

    return renderInteractiveProviderMenuFromProviders(
        self.allocator,
        self.default_provider,
        self.model_name,
        page_number,
        providers_list,
    );
}

fn renderInteractiveModelMenu(self: anytype, provider_name: []const u8, page_number: usize) !?[]u8 {
    const context_channel = if (@hasField(@TypeOf(self.*), "conversation_context"))
        if (self.conversation_context) |ctx| ctx.channel else null
    else
        null;
    if (interactiveModelMenuChannel(if (@hasField(@TypeOf(self.*), "memory_session_id")) self.memory_session_id else null, context_channel) == null) {
        return null;
    }
    if (!@hasField(@TypeOf(self.*), "default_provider")) return null;
    if (!@hasField(@TypeOf(self.*), "model_name")) return null;

    var cfg_opt: ?config_module.Config = if (builtin.is_test) null else config_module.Config.load(self.allocator) catch null;
    defer if (cfg_opt) |*cfg| cfg.deinit();

    const api_key = if (cfg_opt) |*cfg| cfg.getProviderKey(provider_name) else null;
    const models = onboard.fetchModels(self.allocator, provider_name, api_key) catch return null;
    defer freeOwnedStringSlice(self.allocator, models);

    return renderInteractiveModelMenuFromModels(
        self.allocator,
        provider_name,
        self.model_name,
        page_number,
        models,
    );
}

test "interactiveModelMenuChannel enables supported interactive channels" {
    try std.testing.expectEqualStrings("telegram", interactiveModelMenuChannel("telegram:chat-1", null).?);
    try std.testing.expectEqualStrings("telegram", interactiveModelMenuChannel("telegram:main:chat-1", null).?);
    try std.testing.expectEqualStrings("discord", interactiveModelMenuChannel("discord:dm-1", null).?);
    try std.testing.expectEqualStrings("slack", interactiveModelMenuChannel("slack:main:C123", null).?);
    try std.testing.expectEqualStrings("lark", interactiveModelMenuChannel("lark:main:oc_123", null).?);
    try std.testing.expectEqualStrings("telegram", interactiveModelMenuChannel("agent:main:telegram:group:42", null).?);
    try std.testing.expectEqualStrings("discord", interactiveModelMenuChannel("agent:main:discord:direct:42", null).?);
    try std.testing.expectEqualStrings("telegram", interactiveModelMenuChannel("agent:tg-ops:main", "telegram").?);
    try std.testing.expectEqualStrings("discord", interactiveModelMenuChannel("agent:discord-ops:main", "discord").?);
    try std.testing.expectEqualStrings("slack", interactiveModelMenuChannel("agent:slack-ops:main", "slack").?);
    try std.testing.expectEqualStrings("lark", interactiveModelMenuChannel("agent:lark-ops:main", "lark").?);
    try std.testing.expect(interactiveModelMenuChannel("cli", null) == null);
    try std.testing.expect(interactiveModelMenuChannel(null, null) == null);
}

test "renderInteractiveModelMenuFromModels builds first page with next button" {
    const allocator = std.testing.allocator;
    const models = [_][]const u8{
        "alpha",
        "beta",
        "gamma",
        "theta",
        "zeta",
        "eta",
        "iota",
        "kappa",
        "lambda",
        "mu",
        "nu",
    };

    const rendered = (try renderInteractiveModelMenuFromModels(allocator, "anthropic", "beta", 1, &models)).?;
    defer allocator.free(rendered);

    try std.testing.expect(std.mem.indexOf(u8, rendered, interaction_choices.START_TAG) != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "page 1/2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"label\":\"* beta\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"submit_text\":\"/model provider anthropic page 2\"") != null);
}

test "renderInteractiveModelMenuFromModels builds later page with prev button" {
    const allocator = std.testing.allocator;
    const models = [_][]const u8{
        "alpha",
        "beta",
        "gamma",
        "theta",
        "zeta",
        "eta",
        "iota",
        "kappa",
        "lambda",
        "mu",
        "nu",
    };

    const rendered = (try renderInteractiveModelMenuFromModels(allocator, "anthropic", "nu", 2, &models)).?;
    defer allocator.free(rendered);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "page 2/2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"submit_text\":\"/model provider anthropic page 1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"submit_text\":\"/model anthropic/nu\"") != null);
}

test "renderInteractiveModelMenuFromModels prefixes provider for namespaced model ids" {
    const allocator = std.testing.allocator;
    const models = [_][]const u8{
        "qwen/qwen3-32b",
        "zai-org/GLM-5.1-FP8",
    };

    const rendered = (try renderInteractiveModelMenuFromModels(allocator, "atlas-cloud", "qwen/qwen3-32b", 1, &models)).?;
    defer allocator.free(rendered);

    // Regression: Atlas Cloud model IDs can start with another provider namespace
    // such as qwen/. The interactive action must keep Atlas Cloud as provider.
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"submit_text\":\"/model atlas-cloud/qwen/qwen3-32b\"") != null);
}

test "renderInteractiveProviderMenuFromProviders builds provider page with next button" {
    const allocator = std.testing.allocator;
    const providers_list = [_][]const u8{
        "anthropic", "openai",   "openrouter", "moonshot-intl", "groq",
        "mistral",   "deepseek", "vertex",     "gemini",        "ollama",
        "qwen",
    };

    const rendered = (try renderInteractiveProviderMenuFromProviders(allocator, "openrouter", "claude-sonnet-4-6", 1, &providers_list)).?;
    defer allocator.free(rendered);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "Choose a provider (page 1/2)") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"label\":\"* openrouter\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"submit_text\":\"/model provider anthropic\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"submit_text\":\"/model page 2\"") != null);
}
fn isInternalMemoryEntryKeyOrContent(key: []const u8, content: []const u8) bool {
    return memory_mod.isInternalMemoryEntryKeyOrContent(key, content);
}

fn memoryRuntimePtr(self: anytype) ?*memory_mod.MemoryRuntime {
    return if (@hasField(@TypeOf(self.*), "mem_rt")) self.mem_rt else null;
}

fn setModelName(self: anytype, model: []const u8) !void {
    const owned_model = try self.allocator.dupe(u8, model);
    if (self.model_name_owned) self.allocator.free(self.model_name);
    self.model_name = owned_model;
    self.model_name_owned = true;

    if (@hasField(@TypeOf(self.*), "token_limit")) {
        const token_limit_override: ?u64 = if (@hasField(@TypeOf(self.*), "token_limit_override"))
            self.token_limit_override
        else
            null;
        self.token_limit = context_tokens.resolveContextTokens(token_limit_override, self.model_name);
    }

    if (@hasField(@TypeOf(self.*), "max_tokens")) {
        const max_tokens_override: ?u32 = if (@hasField(@TypeOf(self.*), "max_tokens_override"))
            self.max_tokens_override
        else
            null;
        var resolved_max_tokens = max_tokens_resolver.resolveMaxTokens(max_tokens_override, self.model_name);
        if (@hasField(@TypeOf(self.*), "token_limit")) {
            const token_limit_cap: u32 = @intCast(@min(self.token_limit, @as(u64, std.math.maxInt(u32))));
            resolved_max_tokens = @min(resolved_max_tokens, token_limit_cap);
        }
        self.max_tokens = resolved_max_tokens;
    }
}

fn setDefaultProvider(self: anytype, provider_name: []const u8) !void {
    if (!@hasField(@TypeOf(self.*), "default_provider")) return;
    const owned_provider = try self.allocator.dupe(u8, provider_name);
    if (@hasField(@TypeOf(self.*), "default_provider_owned")) {
        if (self.default_provider_owned) self.allocator.free(self.default_provider);
        self.default_provider_owned = true;
    }
    self.default_provider = owned_provider;
}

fn setProfileSystemPrompt(self: anytype, prompt: ?[]const u8) !void {
    if (!@hasField(@TypeOf(self.*), "profile_system_prompt")) return;

    const owned_prompt = if (prompt) |value|
        try self.allocator.dupe(u8, value)
    else
        null;

    if (@hasField(@TypeOf(self.*), "profile_system_prompt_owned")) {
        if (self.profile_system_prompt_owned and self.profile_system_prompt != null) {
            self.allocator.free(self.profile_system_prompt.?);
        }
        self.profile_system_prompt_owned = false;
    }

    self.profile_system_prompt = owned_prompt;
    if (@hasField(@TypeOf(self.*), "profile_system_prompt_owned")) {
        self.profile_system_prompt_owned = owned_prompt != null;
    }
}

fn activeRuntimeProviderName(self: anytype) ?[]const u8 {
    if (@hasField(@TypeOf(self.*), "provider")) {
        return self.provider.getName();
    }
    if (@hasField(@TypeOf(self.*), "default_provider")) {
        return self.default_provider;
    }
    return null;
}

fn isConfiguredProviderName(self: anytype, provider_name: []const u8) bool {
    if (!@hasField(@TypeOf(self.*), "configured_providers")) return false;
    for (self.configured_providers) |entry| {
        if (provider_names.providerNamesMatchIgnoreCase(entry.name, provider_name)) return true;
    }
    return false;
}

const PrimaryModelSelectionRef = struct {
    provider: []const u8,
    model: []const u8,
};

fn updateExplicitProviderMatch(
    model_ref: []const u8,
    provider_name: []const u8,
    best_provider: *?[]const u8,
    best_model: *[]const u8,
    best_provider_len: *usize,
) void {
    const split = model_refs.matchExplicitProviderPrefix(model_ref, provider_name) orelse return;
    const provider = split.provider orelse return;
    if (provider.len <= best_provider_len.*) return;

    best_provider.* = provider;
    best_model.* = split.model;
    best_provider_len.* = provider.len;
}

fn splitExplicitProviderModelForSelf(self: anytype, model_ref: []const u8) ?PrimaryModelSelectionRef {
    var best_provider: ?[]const u8 = null;
    var best_model: []const u8 = undefined;
    var best_provider_len: usize = 0;

    if (@hasField(@TypeOf(self.*), "configured_providers")) {
        for (self.configured_providers) |entry| {
            updateExplicitProviderMatch(model_ref, entry.name, &best_provider, &best_model, &best_provider_len);
        }
    }

    if (@hasField(@TypeOf(self.*), "model_routes")) {
        for (self.model_routes) |route| {
            updateExplicitProviderMatch(model_ref, route.provider, &best_provider, &best_model, &best_provider_len);
        }
    }

    if (@hasField(@TypeOf(self.*), "fallback_providers")) {
        for (self.fallback_providers) |provider_name| {
            updateExplicitProviderMatch(model_ref, provider_name, &best_provider, &best_model, &best_provider_len);
        }
    }

    if (best_provider) |provider| {
        return .{
            .provider = provider,
            .model = best_model,
        };
    }
    return null;
}

fn splitPrimaryModelRefForSelf(self: anytype, primary: []const u8) ?PrimaryModelSelectionRef {
    if (splitExplicitProviderModelForSelf(self, primary)) |split| return split;
    if (config_module.splitPrimaryModelRef(primary)) |split| {
        return .{
            .provider = split.provider,
            .model = split.model,
        };
    }
    return null;
}

fn hasExplicitProviderPrefix(self: anytype, model: []const u8) bool {
    if (splitExplicitProviderModelForSelf(self, model) != null) return true;

    const split = model_refs.splitProviderModel(model) orelse return false;
    const provider_candidate = split.provider orelse return false;
    if (providers.classifyProvider(provider_candidate) != .unknown) return true;

    var lower_buf: [128]u8 = undefined;
    if (provider_candidate.len <= lower_buf.len) {
        _ = std.ascii.lowerString(lower_buf[0..provider_candidate.len], provider_candidate);
        if (providers.classifyProvider(lower_buf[0..provider_candidate.len]) != .unknown) return true;
    }

    return isConfiguredProviderName(self, provider_candidate);
}

fn configPrimaryModelForSelection(self: anytype, model: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, model, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidPath;

    if (hasExplicitProviderPrefix(self, trimmed)) {
        return try self.allocator.dupe(u8, trimmed);
    }

    const provider = if (@hasField(@TypeOf(self.*), "default_provider") and self.default_provider.len > 0)
        self.default_provider
    else
        "openrouter";
    return try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ provider, trimmed });
}

fn primaryModelProviderObjectJson(
    allocator: std.mem.Allocator,
    provider: []const u8,
    model: []const u8,
) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var model_obj: std.json.ObjectMap = .empty;
    try model_obj.put(arena.allocator(), "provider", .{ .string = provider });
    try model_obj.put(arena.allocator(), "primary", .{ .string = model });
    return try std.json.Stringify.valueAlloc(allocator, std.json.Value{ .object = model_obj }, .{});
}

fn configPrimaryModelMutationValue(self: anytype, model: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, model, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidPath;

    if (hasExplicitProviderPrefix(self, trimmed)) {
        if (splitPrimaryModelRefForSelf(self, trimmed)) |split| {
            if (config_module.shouldSerializeDefaultModelProviderField(split.provider)) {
                return try primaryModelProviderObjectJson(self.allocator, split.provider, split.model);
            }
        }
        return try self.allocator.dupe(u8, trimmed);
    }

    const provider = if (@hasField(@TypeOf(self.*), "default_provider") and self.default_provider.len > 0)
        self.default_provider
    else
        "openrouter";
    if (config_module.shouldSerializeDefaultModelProviderField(provider)) {
        return try primaryModelProviderObjectJson(self.allocator, provider, trimmed);
    }
    return try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ provider, trimmed });
}

fn persistSelectedModelToConfig(self: anytype, model: []const u8) !void {
    if (builtin.is_test) return;

    const value_raw = try configPrimaryModelMutationValue(self, model);
    defer self.allocator.free(value_raw);

    var result = try config_mutator.mutateDefaultConfig(
        self.allocator,
        .set,
        "agents.defaults.model.primary",
        value_raw,
        .{ .apply = true },
    );
    defer config_mutator.freeMutationResult(self.allocator, &result);
}

fn invalidateSystemPromptCache(self: anytype) void {
    if (@hasField(@TypeOf(self.*), "has_system_prompt")) {
        self.has_system_prompt = false;
    }
    if (@hasField(@TypeOf(self.*), "system_prompt_has_conversation_context")) {
        self.system_prompt_has_conversation_context = false;
    }
    if (@hasField(@TypeOf(self.*), "workspace_prompt_fingerprint")) {
        self.workspace_prompt_fingerprint = null;
    }
    if (@hasField(@TypeOf(self.*), "system_prompt_conversation_context_fingerprint")) {
        self.system_prompt_conversation_context_fingerprint = null;
    }
    if (@hasField(@TypeOf(self.*), "system_prompt_model_name")) {
        if (self.system_prompt_model_name) |model_name| self.allocator.free(model_name);
        self.system_prompt_model_name = null;
    }
}

test "configPrimaryModelForSelection treats unknown leading segment as model for default provider" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        default_provider: []const u8,
        configured_providers: []const config_types.ProviderEntry,
    }{
        .allocator = allocator,
        .default_provider = "openrouter",
        .configured_providers = &.{},
    };

    const primary = try configPrimaryModelForSelection(&dummy, "inception/mercury");
    defer allocator.free(primary);
    try std.testing.expectEqualStrings("openrouter/inception/mercury", primary);
}

test "configPrimaryModelForSelection keeps explicit known provider prefix" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        default_provider: []const u8,
        configured_providers: []const config_types.ProviderEntry,
    }{
        .allocator = allocator,
        .default_provider = "openrouter",
        .configured_providers = &.{},
    };

    const primary = try configPrimaryModelForSelection(&dummy, "openrouter/inception/mercury");
    defer allocator.free(primary);
    try std.testing.expectEqualStrings("openrouter/inception/mercury", primary);
}

test "configPrimaryModelForSelection treats known provider prefix case-insensitively" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        default_provider: []const u8,
        configured_providers: []const config_types.ProviderEntry,
    }{
        .allocator = allocator,
        .default_provider = "openrouter",
        .configured_providers = &.{},
    };

    const primary = try configPrimaryModelForSelection(&dummy, "OpenRouter/inception/mercury");
    defer allocator.free(primary);
    try std.testing.expectEqualStrings("OpenRouter/inception/mercury", primary);
}

test "configPrimaryModelForSelection keeps explicit configured custom provider prefix" {
    const allocator = std.testing.allocator;
    const configured = [_]config_types.ProviderEntry{
        .{ .name = "customgw", .base_url = "https://example.com/v1" },
    };
    var dummy = struct {
        allocator: std.mem.Allocator,
        default_provider: []const u8,
        configured_providers: []const config_types.ProviderEntry,
    }{
        .allocator = allocator,
        .default_provider = "openrouter",
        .configured_providers = &configured,
    };

    const primary = try configPrimaryModelForSelection(&dummy, "customgw/model-a");
    defer allocator.free(primary);
    try std.testing.expectEqualStrings("customgw/model-a", primary);
}

test "configPrimaryModelForSelection keeps explicit custom url provider ref" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        default_provider: []const u8,
        configured_providers: []const config_types.ProviderEntry,
    }{
        .allocator = allocator,
        .default_provider = "openrouter",
        .configured_providers = &.{},
    };

    const primary = try configPrimaryModelForSelection(&dummy, "custom:https://gateway.example.com/proxy/v1/openai/v2/qianfan/custom-model");
    defer allocator.free(primary);
    try std.testing.expectEqualStrings("custom:https://gateway.example.com/proxy/v1/openai/v2/qianfan/custom-model", primary);
}

test "configPrimaryModelForSelection keeps versionless custom url provider ref" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        default_provider: []const u8,
        configured_providers: []const config_types.ProviderEntry,
    }{
        .allocator = allocator,
        .default_provider = "openrouter",
        .configured_providers = &.{},
    };

    const primary = try configPrimaryModelForSelection(&dummy, "custom:https://example.com/gpt-4o");
    defer allocator.free(primary);
    try std.testing.expectEqualStrings("custom:https://example.com/gpt-4o", primary);
}

test "configPrimaryModelMutationValue serializes versionless custom defaults as object" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        default_provider: []const u8,
        configured_providers: []const config_types.ProviderEntry,
    }{
        .allocator = allocator,
        .default_provider = "custom:https://example.com/api",
        .configured_providers = &.{},
    };

    const value_raw = try configPrimaryModelMutationValue(&dummy, "meta-llama/Llama-4-70B-Instruct");
    defer allocator.free(value_raw);

    try std.testing.expectEqualStrings(
        "{\"provider\":\"custom:https://example.com/api\",\"primary\":\"meta-llama/Llama-4-70B-Instruct\"}",
        value_raw,
    );
}

test "configPrimaryModelForSelection keeps configured versionless custom url namespace ref" {
    const allocator = std.testing.allocator;
    const configured = [_]config_types.ProviderEntry{
        .{ .name = "custom:https://gateway.example.com" },
    };
    var dummy = struct {
        allocator: std.mem.Allocator,
        default_provider: []const u8,
        configured_providers: []const config_types.ProviderEntry,
    }{
        .allocator = allocator,
        .default_provider = "openrouter",
        .configured_providers = &configured,
    };

    const primary = try configPrimaryModelForSelection(&dummy, "custom:https://gateway.example.com/qianfan/custom-model");
    defer allocator.free(primary);
    try std.testing.expectEqualStrings("custom:https://gateway.example.com/qianfan/custom-model", primary);
}

test "bareSessionResetPrompt returns prompt for bare /new" {
    const prompt = bareSessionResetPrompt("/new") orelse return error.TestExpectedEqual;
    try std.testing.expect(std.mem.indexOf(u8, prompt, "Execute your Session Startup sequence now") != null);
}

test "bareSessionResetPrompt returns prompt for bare /reset with mention" {
    const prompt = bareSessionResetPrompt("/reset@nullclaw_bot:") orelse return error.TestExpectedEqual;
    try std.testing.expect(std.mem.indexOf(u8, prompt, "A new session was started via /new or /reset") != null);
}

test "bareSessionResetPrompt ignores /reset with argument" {
    try std.testing.expect(bareSessionResetPrompt("/reset gpt-4o-mini") == null);
}

test "planTurnInput routes bare reset through local clear and llm prompt" {
    const plan = planTurnInput("/reset@nullclaw_bot:");
    try std.testing.expect(plan.clear_session);
    try std.testing.expect(plan.invoke_local_handler);
    try std.testing.expectEqualStrings(BARE_SESSION_RESET_PROMPT, plan.llm_user_message.?);
}

test "planTurnInput keeps unknown slash-prefixed text on llm path" {
    const plan = planTurnInput("/etc/hosts");
    try std.testing.expect(!plan.clear_session);
    try std.testing.expect(!plan.invoke_local_handler);
    try std.testing.expectEqualStrings("/etc/hosts", plan.llm_user_message.?);
}

test "planTurnInput keeps known slash commands local-only" {
    const plan = planTurnInput("/help");
    try std.testing.expect(!plan.clear_session);
    try std.testing.expect(plan.invoke_local_handler);
    try std.testing.expect(plan.llm_user_message == null);
}

test "planTurnInput keeps /menu on local-only path" {
    const plan = planTurnInput("/menu");
    try std.testing.expect(!plan.clear_session);
    try std.testing.expect(plan.invoke_local_handler);
    try std.testing.expect(plan.llm_user_message == null);
}

test "planTurnInput keeps interactive skill activation local-only" {
    // Regression: /iskill must stay on the local handler path so it can arm an
    // interactive session skill instead of being treated as unknown slash text.
    const plan = planTurnInput("/iskill news-digest");
    try std.testing.expect(!plan.clear_session);
    try std.testing.expect(plan.invoke_local_handler);
    try std.testing.expect(plan.llm_user_message == null);
}

test "hotApplyConfigChange updates model primary as provider plus model" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
    }{
        .allocator = allocator,
        .model_name = "old-model",
        .model_name_owned = false,
        .default_provider = "old-provider",
        .default_provider_owned = false,
        .default_model = "old-model",
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);

    const applied = try hotApplyConfigChange(
        &dummy,
        .set,
        "agents.defaults.model.primary",
        "\"openrouter/inception/mercury\"",
    );
    try std.testing.expect(applied);
    try std.testing.expectEqualStrings("inception/mercury", dummy.model_name);
    try std.testing.expectEqualStrings("inception/mercury", dummy.default_model);
    try std.testing.expectEqualStrings("openrouter", dummy.default_provider);
}

test "hotApplyConfigChange handles split custom provider reload payload" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
    }{
        .allocator = allocator,
        .model_name = "old-model",
        .model_name_owned = false,
        .default_provider = "old-provider",
        .default_provider_owned = false,
        .default_model = "old-model",
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);

    const cfg = config_module.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_provider = "custom:https://example.com/api",
        .default_model = "meta-llama/Llama-4-70B-Instruct",
        .allocator = allocator,
    };

    const value_json = try hotReloadValueJson(allocator, &cfg, "agents.defaults.model.primary");
    defer allocator.free(value_json);

    // Regression: hot reload must preserve split custom providers instead of truncating at the first slash.
    const applied = try hotApplyConfigChange(
        &dummy,
        .set,
        "agents.defaults.model.primary",
        value_json,
    );
    try std.testing.expect(applied);
    try std.testing.expectEqualStrings("meta-llama/Llama-4-70B-Instruct", dummy.model_name);
    try std.testing.expectEqualStrings("meta-llama/Llama-4-70B-Instruct", dummy.default_model);
    try std.testing.expectEqualStrings("custom:https://example.com/api", dummy.default_provider);
}

test "hotApplyConfigChange rejects malformed model primary" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
    }{
        .allocator = allocator,
        .model_name = "stable-model",
        .model_name_owned = false,
        .default_provider = "openrouter",
        .default_provider_owned = false,
        .default_model = "stable-model",
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);

    const applied = try hotApplyConfigChange(
        &dummy,
        .set,
        "agents.defaults.model.primary",
        "\"malformed\"",
    );
    try std.testing.expect(!applied);
    try std.testing.expectEqualStrings("stable-model", dummy.model_name);
    try std.testing.expectEqualStrings("openrouter", dummy.default_provider);
}

test "hotApplyConfigChange model primary refreshes token and max token limits" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
        token_limit: u64,
        token_limit_override: ?u64,
        max_tokens: u32,
        max_tokens_override: ?u32,
    }{
        .allocator = allocator,
        .model_name = "old-model",
        .model_name_owned = false,
        .default_provider = "old-provider",
        .default_provider_owned = false,
        .default_model = "old-model",
        .token_limit = 1024,
        .token_limit_override = null,
        .max_tokens = 128,
        .max_tokens_override = null,
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);

    const applied = try hotApplyConfigChange(
        &dummy,
        .set,
        "agents.defaults.model.primary",
        "\"openrouter/gpt-4o\"",
    );
    try std.testing.expect(applied);
    try std.testing.expectEqualStrings("gpt-4o", dummy.model_name);
    try std.testing.expectEqualStrings("gpt-4o", dummy.default_model);
    try std.testing.expectEqualStrings("openrouter", dummy.default_provider);
    try std.testing.expectEqual(@as(u64, 128_000), dummy.token_limit);
    try std.testing.expectEqual(@as(u32, 8192), dummy.max_tokens);
}

test "hotApplyConfigChange updates custom url model primary" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
        token_limit: u64,
        token_limit_override: ?u64,
        max_tokens: u32,
        max_tokens_override: ?u32,
    }{
        .allocator = allocator,
        .model_name = "old-model",
        .model_name_owned = false,
        .default_provider = "old-provider",
        .default_provider_owned = false,
        .default_model = "old-model",
        .token_limit = 1024,
        .token_limit_override = null,
        .max_tokens = 128,
        .max_tokens_override = null,
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);

    const applied = try hotApplyConfigChange(
        &dummy,
        .set,
        "agents.defaults.model.primary",
        "\"custom:https://api.example.com/openai/v2/qianfan/custom-model\"",
    );
    try std.testing.expect(applied);
    try std.testing.expectEqualStrings("qianfan/custom-model", dummy.model_name);
    try std.testing.expectEqualStrings("qianfan/custom-model", dummy.default_model);
    try std.testing.expectEqualStrings("custom:https://api.example.com/openai/v2", dummy.default_provider);
    try std.testing.expectEqual(@as(u64, 98_304), dummy.token_limit);
    try std.testing.expectEqual(@as(u32, 32_768), dummy.max_tokens);
}

test "hotApplyConfigChange updates configured versionless custom url model primary" {
    const allocator = std.testing.allocator;
    const configured = [_]config_types.ProviderEntry{
        .{ .name = "custom:https://gateway.example.com" },
    };
    var dummy = struct {
        allocator: std.mem.Allocator,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
        token_limit: u64,
        token_limit_override: ?u64,
        max_tokens: u32,
        max_tokens_override: ?u32,
        configured_providers: []const config_types.ProviderEntry,
    }{
        .allocator = allocator,
        .model_name = "old-model",
        .model_name_owned = false,
        .default_provider = "old-provider",
        .default_provider_owned = false,
        .default_model = "old-model",
        .token_limit = 1024,
        .token_limit_override = null,
        .max_tokens = 128,
        .max_tokens_override = null,
        .configured_providers = &configured,
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);

    const applied = try hotApplyConfigChange(
        &dummy,
        .set,
        "agents.defaults.model.primary",
        "\"custom:https://gateway.example.com/qianfan/custom-model\"",
    );
    try std.testing.expect(applied);
    try std.testing.expectEqualStrings("qianfan/custom-model", dummy.model_name);
    try std.testing.expectEqualStrings("qianfan/custom-model", dummy.default_model);
    try std.testing.expectEqualStrings("custom:https://gateway.example.com", dummy.default_provider);
    try std.testing.expectEqual(@as(u64, 98_304), dummy.token_limit);
    try std.testing.expectEqual(@as(u32, 32_768), dummy.max_tokens);
}

test "hotApplyConfigChange updates route-only custom url model primary" {
    // Regression: hot reload must preserve explicit providers that exist only in model_routes.
    const allocator = std.testing.allocator;
    const routes = [_]config_types.ModelRouteConfig{
        .{
            .hint = "fast",
            .provider = "custom:https://route.example.com/qianfan",
            .model = "custom-model",
        },
    };
    var dummy = struct {
        allocator: std.mem.Allocator,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
        token_limit: u64,
        token_limit_override: ?u64,
        max_tokens: u32,
        max_tokens_override: ?u32,
        model_routes: []const config_types.ModelRouteConfig,
    }{
        .allocator = allocator,
        .model_name = "old-model",
        .model_name_owned = false,
        .default_provider = "old-provider",
        .default_provider_owned = false,
        .default_model = "old-model",
        .token_limit = 1024,
        .token_limit_override = null,
        .max_tokens = 128,
        .max_tokens_override = null,
        .model_routes = &routes,
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);

    const applied = try hotApplyConfigChange(
        &dummy,
        .set,
        "agents.defaults.model.primary",
        "\"custom:https://route.example.com/qianfan/custom-model\"",
    );
    try std.testing.expect(applied);
    try std.testing.expectEqualStrings("custom-model", dummy.model_name);
    try std.testing.expectEqualStrings("custom-model", dummy.default_model);
    try std.testing.expectEqualStrings("custom:https://route.example.com/qianfan", dummy.default_provider);
}

test "hotApplyConfigChange updates fallback-only custom url model primary" {
    // Regression: hot reload must preserve explicit providers that exist only in reliability fallbacks.
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
        token_limit: u64,
        token_limit_override: ?u64,
        max_tokens: u32,
        max_tokens_override: ?u32,
        fallback_providers: []const []const u8,
    }{
        .allocator = allocator,
        .model_name = "old-model",
        .model_name_owned = false,
        .default_provider = "old-provider",
        .default_provider_owned = false,
        .default_model = "old-model",
        .token_limit = 1024,
        .token_limit_override = null,
        .max_tokens = 128,
        .max_tokens_override = null,
        .fallback_providers = &.{"custom:https://fb.example.com/qianfan"},
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);

    const applied = try hotApplyConfigChange(
        &dummy,
        .set,
        "agents.defaults.model.primary",
        "\"custom:https://fb.example.com/qianfan/custom-model\"",
    );
    try std.testing.expect(applied);
    try std.testing.expectEqualStrings("custom-model", dummy.model_name);
    try std.testing.expectEqualStrings("custom-model", dummy.default_model);
    try std.testing.expectEqualStrings("custom:https://fb.example.com/qianfan", dummy.default_provider);
}

test "hotApplyConfigChange updates agent status_show_emojis" {
    const allocator = std.testing.allocator;
    var dummy = struct {
        allocator: std.mem.Allocator,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
        status_show_emojis: bool,
    }{
        .allocator = allocator,
        .model_name = "stable-model",
        .model_name_owned = false,
        .default_provider = "openrouter",
        .default_provider_owned = false,
        .default_model = "stable-model",
        .status_show_emojis = true,
    };

    const applied = try hotApplyConfigChange(
        &dummy,
        .set,
        "agent.status_show_emojis",
        "false",
    );
    try std.testing.expect(applied);
    try std.testing.expect(!dummy.status_show_emojis);
}

test "applyHotReloadConfig restores resolved defaults and invalidates prompt cache" {
    const allocator = std.testing.allocator;

    var dummy = struct {
        allocator: std.mem.Allocator,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
        temperature: f64,
        max_tool_iterations: u32,
        max_history_messages: u32,
        message_timeout_secs: u64,
        status_show_emojis: bool,
        has_system_prompt: bool,
        system_prompt_has_conversation_context: bool,
        workspace_prompt_fingerprint: ?u64,
        system_prompt_model_name: ?[]u8,
    }{
        .allocator = allocator,
        .model_name = "stale-model",
        .model_name_owned = false,
        .default_provider = "stale-provider",
        .default_provider_owned = false,
        .default_model = "stale-model",
        .temperature = 1.5,
        .max_tool_iterations = 1,
        .max_history_messages = 2,
        .message_timeout_secs = 3,
        .status_show_emojis = false,
        .has_system_prompt = true,
        .system_prompt_has_conversation_context = true,
        .workspace_prompt_fingerprint = 1234,
        .system_prompt_model_name = try allocator.dupe(u8, "stale-model"),
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);
    defer if (dummy.system_prompt_model_name) |model_name| allocator.free(model_name);

    var cfg = config_module.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_provider = "openrouter",
        .default_model = "gpt-4o",
        .allocator = allocator,
    };
    cfg.agent.max_tool_iterations = 1000;
    cfg.agent.max_history_messages = 100;
    cfg.agent.message_timeout_secs = 600;
    cfg.agent.status_show_emojis = true;

    const summary = try applyHotReloadConfig(&dummy, &cfg);
    try std.testing.expectEqual(@as(usize, 6), summary.attempted);
    try std.testing.expectEqual(@as(usize, 6), summary.applied);
    try std.testing.expectEqual(@as(usize, 0), summary.skipped);
    try std.testing.expectEqual(@as(usize, 0), summary.failed);

    try std.testing.expectEqualStrings("gpt-4o", dummy.model_name);
    try std.testing.expectEqualStrings("gpt-4o", dummy.default_model);
    try std.testing.expectEqualStrings("openrouter", dummy.default_provider);
    try std.testing.expectEqual(@as(f64, 0.7), dummy.temperature);
    try std.testing.expectEqual(@as(u32, 1000), dummy.max_tool_iterations);
    try std.testing.expectEqual(@as(u32, 100), dummy.max_history_messages);
    try std.testing.expectEqual(@as(u64, 600), dummy.message_timeout_secs);
    try std.testing.expect(dummy.status_show_emojis);
    try std.testing.expect(!dummy.has_system_prompt);
    try std.testing.expect(!dummy.system_prompt_has_conversation_context);
    try std.testing.expect(dummy.workspace_prompt_fingerprint == null);
    try std.testing.expect(dummy.system_prompt_model_name == null);
}

const HotReloadProviderStub = struct {
    name: []const u8,

    fn provider(self: *@This()) providers.Provider {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    fn chatWithSystem(
        _: *anyopaque,
        allocator: std.mem.Allocator,
        _: ?[]const u8,
        _: []const u8,
        _: []const u8,
        _: f64,
    ) anyerror![]const u8 {
        return allocator.dupe(u8, "");
    }

    fn chat(
        _: *anyopaque,
        allocator: std.mem.Allocator,
        _: providers.ChatRequest,
        _: []const u8,
        _: f64,
    ) anyerror!providers.ChatResponse {
        return .{
            .content = try allocator.dupe(u8, ""),
            .tool_calls = &.{},
            .usage = .{},
            .model = try allocator.dupe(u8, "test-model"),
        };
    }

    fn supportsNativeTools(_: *anyopaque) bool {
        return false;
    }

    fn getName(ptr: *anyopaque) []const u8 {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        return self.name;
    }

    fn deinitFn(_: *anyopaque) void {}

    const vtable = providers.Provider.VTable{
        .chatWithSystem = chatWithSystem,
        .chat = chat,
        .supportsNativeTools = supportsNativeTools,
        .getName = getName,
        .deinit = deinitFn,
    };
};

test "applyHotReloadConfig updates active profile overrides when runtime provider matches" {
    const allocator = std.testing.allocator;

    var provider_stub = HotReloadProviderStub{ .name = "ollama" };
    var dummy = struct {
        allocator: std.mem.Allocator,
        provider: providers.Provider,
        profile_name: ?[]const u8,
        profile_system_prompt: ?[]const u8,
        profile_system_prompt_owned: bool,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
        temperature: f64,
        has_system_prompt: bool,
        system_prompt_has_conversation_context: bool,
        workspace_prompt_fingerprint: ?u64,
        system_prompt_model_name: ?[]u8,
    }{
        .allocator = allocator,
        .provider = provider_stub.provider(),
        .profile_name = "coder",
        .profile_system_prompt = "Old profile prompt",
        .profile_system_prompt_owned = false,
        .model_name = "qwen2.5-coder:7b",
        .model_name_owned = false,
        .default_provider = "ollama",
        .default_provider_owned = false,
        .default_model = "qwen2.5-coder:7b",
        .temperature = 0.2,
        .has_system_prompt = true,
        .system_prompt_has_conversation_context = true,
        .workspace_prompt_fingerprint = 99,
        .system_prompt_model_name = try allocator.dupe(u8, "old-model"),
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);
    defer if (dummy.profile_system_prompt_owned and dummy.profile_system_prompt != null) allocator.free(dummy.profile_system_prompt.?);
    defer if (dummy.system_prompt_model_name) |model_name| allocator.free(model_name);

    const agents = [_]config_types.NamedAgentConfig{
        .{
            .name = "coder",
            .provider = "ollama",
            .model = "qwen2.5-coder:14b",
            .system_prompt = "New profile prompt",
            .temperature = 0.4,
        },
    };
    const cfg = config_module.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_provider = "openrouter",
        .default_model = "gpt-4o",
        .default_temperature = 0.7,
        .agents = &agents,
        .allocator = allocator,
    };

    const summary = try applyHotReloadConfig(&dummy, &cfg);
    try std.testing.expectEqual(@as(usize, 8), summary.attempted);
    try std.testing.expectEqual(@as(usize, 4), summary.applied);
    try std.testing.expectEqual(@as(usize, 5), summary.skipped);
    try std.testing.expectEqual(@as(usize, 0), summary.failed);

    try std.testing.expectEqualStrings("qwen2.5-coder:14b", dummy.model_name);
    try std.testing.expectEqualStrings("qwen2.5-coder:14b", dummy.default_model);
    try std.testing.expectEqualStrings("ollama", dummy.default_provider);
    try std.testing.expectEqualStrings("New profile prompt", dummy.profile_system_prompt.?);
    try std.testing.expect(dummy.profile_system_prompt_owned);
    try std.testing.expectEqual(@as(f64, 0.4), dummy.temperature);
    try std.testing.expect(!dummy.has_system_prompt);
    try std.testing.expect(!dummy.system_prompt_has_conversation_context);
    try std.testing.expect(dummy.workspace_prompt_fingerprint == null);
    try std.testing.expect(dummy.system_prompt_model_name == null);
}

test "applyHotReloadConfig clears removed profile overrides and skips provider rebuilds" {
    const allocator = std.testing.allocator;

    var provider_stub = HotReloadProviderStub{ .name = "ollama" };
    var dummy = struct {
        allocator: std.mem.Allocator,
        provider: providers.Provider,
        profile_name: ?[]const u8,
        profile_system_prompt: ?[]const u8,
        profile_system_prompt_owned: bool,
        model_name: []const u8,
        model_name_owned: bool,
        default_provider: []const u8,
        default_provider_owned: bool,
        default_model: []const u8,
        temperature: f64,
    }{
        .allocator = allocator,
        .provider = provider_stub.provider(),
        .profile_name = "coder",
        .profile_system_prompt = try allocator.dupe(u8, "Old profile prompt"),
        .profile_system_prompt_owned = true,
        .model_name = "qwen2.5-coder:7b",
        .model_name_owned = false,
        .default_provider = "ollama",
        .default_provider_owned = false,
        .default_model = "qwen2.5-coder:7b",
        .temperature = 0.2,
    };
    defer if (dummy.model_name_owned) allocator.free(dummy.model_name);
    defer if (dummy.default_provider_owned) allocator.free(dummy.default_provider);
    defer if (dummy.profile_system_prompt_owned and dummy.profile_system_prompt != null) allocator.free(dummy.profile_system_prompt.?);

    const agents = [_]config_types.NamedAgentConfig{
        .{
            .name = "coder",
            .provider = "openai",
            .model = "gpt-4.1-mini",
            .system_prompt = null,
            .temperature = null,
        },
    };
    const cfg = config_module.Config{
        .workspace_dir = "/tmp/nullclaw-test",
        .config_path = "/tmp/nullclaw-test/config.json",
        .default_provider = "openrouter",
        .default_model = "gpt-4o",
        .default_temperature = 0.7,
        .agents = &agents,
        .allocator = allocator,
    };

    // Regression: profile reload must not free borrowed prompt memory or fake a provider switch
    // when the session would still be bound to the old provider runtime.
    const summary = try applyHotReloadConfig(&dummy, &cfg);
    try std.testing.expectEqual(@as(usize, 6), summary.attempted);
    try std.testing.expectEqual(@as(usize, 2), summary.applied);
    try std.testing.expectEqual(@as(usize, 7), summary.skipped);
    try std.testing.expectEqual(@as(usize, 0), summary.failed);

    try std.testing.expectEqualStrings("qwen2.5-coder:7b", dummy.model_name);
    try std.testing.expectEqualStrings("qwen2.5-coder:7b", dummy.default_model);
    try std.testing.expectEqualStrings("ollama", dummy.default_provider);
    try std.testing.expect(dummy.profile_system_prompt == null);
    try std.testing.expect(!dummy.profile_system_prompt_owned);
    try std.testing.expectEqual(@as(f64, 0.7), dummy.temperature);
}

test "splitPrimaryModelRef parses provider model format" {
    const parsed = config_module.splitPrimaryModelRef("openrouter/inception/mercury") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("openrouter", parsed.provider);
    try std.testing.expectEqualStrings("inception/mercury", parsed.model);
}

test "splitPrimaryModelRef parses versioned custom provider model format" {
    const parsed = config_module.splitPrimaryModelRef(
        "custom:https://example.com/v2/meta-llama/Llama-4-70B-Instruct",
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("custom:https://example.com/v2", parsed.provider);
    try std.testing.expectEqualStrings("meta-llama/Llama-4-70B-Instruct", parsed.model);
}

test "splitPrimaryModelRef parses versionless custom provider model format" {
    const parsed = config_module.splitPrimaryModelRef(
        "custom:https://example.com/api/qianfan/custom-model",
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("custom:https://example.com/api", parsed.provider);
    try std.testing.expectEqualStrings("qianfan/custom-model", parsed.model);
}

test "splitPrimaryModelRef preserves custom url endpoint suffixes" {
    const parsed = config_module.splitPrimaryModelRef(
        "custom:https://my-api.example.com/api/v2/responses/my-model",
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("custom:https://my-api.example.com/api/v2/responses", parsed.provider);
    try std.testing.expectEqualStrings("my-model", parsed.model);
}

test "splitPrimaryModelRef rejects malformed values" {
    try std.testing.expect(config_module.splitPrimaryModelRef("noslash") == null);
    try std.testing.expect(config_module.splitPrimaryModelRef("/model-only") == null);
    try std.testing.expect(config_module.splitPrimaryModelRef("provider/") == null);
    try std.testing.expect(config_module.splitPrimaryModelRef("custom:https://api.example.com/v1/") == null);
}

fn setExecNodeId(self: anytype, value: ?[]const u8) !void {
    if (self.exec_node_id_owned and self.exec_node_id != null) {
        self.allocator.free(self.exec_node_id.?);
    }
    self.exec_node_id_owned = false;
    self.exec_node_id = null;
    if (value) |v| {
        self.exec_node_id = try self.allocator.dupe(u8, v);
        self.exec_node_id_owned = true;
    }
}

fn setTtsProvider(self: anytype, value: ?[]const u8) !void {
    if (self.tts_provider_owned and self.tts_provider != null) {
        self.allocator.free(self.tts_provider.?);
    }
    self.tts_provider_owned = false;
    self.tts_provider = null;
    if (value) |v| {
        self.tts_provider = try self.allocator.dupe(u8, v);
        self.tts_provider_owned = true;
    }
}

fn setFocusTarget(self: anytype, value: ?[]const u8) !void {
    if (self.focus_target_owned and self.focus_target != null) {
        self.allocator.free(self.focus_target.?);
    }
    self.focus_target_owned = false;
    self.focus_target = null;
    if (value) |v| {
        self.focus_target = try self.allocator.dupe(u8, v);
        self.focus_target_owned = true;
    }
}

fn setDockTarget(self: anytype, value: ?[]const u8) !void {
    if (self.dock_target_owned and self.dock_target != null) {
        self.allocator.free(self.dock_target.?);
    }
    self.dock_target_owned = false;
    self.dock_target = null;
    if (value) |v| {
        self.dock_target = try self.allocator.dupe(u8, v);
        self.dock_target_owned = true;
    }
}

fn clearPendingExecCommand(self: anytype) void {
    if (self.pending_exec_command_owned and self.pending_exec_command != null) {
        self.allocator.free(self.pending_exec_command.?);
    }
    self.pending_exec_command = null;
    self.pending_exec_command_owned = false;
}

fn setPendingExecCommand(self: anytype, command: []const u8) !void {
    clearPendingExecCommand(self);
    self.pending_exec_command = try self.allocator.dupe(u8, command);
    self.pending_exec_command_owned = true;
    self.pending_exec_id += 1;
    if (self.pending_exec_id == 0) self.pending_exec_id = 1;
}

fn splitFirstToken(arg: []const u8) struct { head: []const u8, tail: []const u8 } {
    const trimmed = std.mem.trim(u8, arg, " \t");
    if (trimmed.len == 0) return .{ .head = "", .tail = "" };

    var i: usize = 0;
    while (i < trimmed.len and trimmed[i] != ' ' and trimmed[i] != '\t') : (i += 1) {}

    if (i >= trimmed.len) return .{ .head = trimmed, .tail = "" };
    return .{
        .head = trimmed[0..i],
        .tail = std.mem.trim(u8, trimmed[i + 1 ..], " \t"),
    };
}

fn isSkillNameSeparator(ch: u8) bool {
    return ch == '-' or ch == '_' or std.ascii.isWhitespace(ch);
}

fn nextSkillNameToken(name: []const u8, index: *usize) ?[]const u8 {
    while (index.* < name.len and isSkillNameSeparator(name[index.*])) : (index.* += 1) {}
    if (index.* >= name.len) return null;

    const start = index.*;
    while (index.* < name.len and !isSkillNameSeparator(name[index.*])) : (index.* += 1) {}
    return name[start..index.*];
}

fn skillNamesEqualNormalized(left: []const u8, right: []const u8) bool {
    var i: usize = 0;
    var j: usize = 0;

    while (true) {
        const left_token = nextSkillNameToken(left, &i);
        const right_token = nextSkillNameToken(right, &j);

        if (left_token == null or right_token == null) {
            return left_token == null and right_token == null;
        }
        if (!std.ascii.eqlIgnoreCase(left_token.?, right_token.?)) return false;
    }
}

const SkillLookup = union(enum) {
    not_found,
    ambiguous,
    unique: *const skills_mod.Skill,
};

fn findSkillByExactName(skills: []const skills_mod.Skill, name: []const u8) ?*const skills_mod.Skill {
    for (skills) |*skill| {
        if (std.ascii.eqlIgnoreCase(skill.name, name)) return skill;
    }
    return null;
}

fn findSkillByNameNormalized(skills: []const skills_mod.Skill, name: []const u8) SkillLookup {
    if (findSkillByExactName(skills, name)) |skill| {
        return .{ .unique = skill };
    }

    var match: ?*const skills_mod.Skill = null;
    for (skills) |*skill| {
        if (!skillNamesEqualNormalized(skill.name, name)) continue;
        if (match != null) return .ambiguous;
        match = skill;
    }

    if (match) |skill| return .{ .unique = skill };
    return .not_found;
}

fn formatAmbiguousSkillName(self: anytype, name: []const u8) ![]const u8 {
    return try std.fmt.allocPrint(self.allocator, "Ambiguous skill name: {s}", .{name});
}

const DirectSkillCommandMatch = struct {
    skill: *const skills_mod.Skill,
    user_input: []const u8,
};

const SkillLaunchMode = enum {
    one_shot,
    session_active,
};

const SkillMenuCommandChoice = struct {
    label: []const u8,
    submit_text: []const u8,
};

const SkillAffixKind = enum {
    prefix,
    suffix,
};

const SkillAffixEntry = struct {
    token: []const u8,
    count: usize,
};

const SkillLetterGroup = struct {
    label: []const u8,
    command: []const u8,
};

const SKILL_MENU_PAGE_SIZE: usize = 10;
const SKILL_MENU_COLUMNS: u8 = 3;

fn registerDirectSkillCommandMatch(
    match: *?DirectSkillCommandMatch,
    skill: *const skills_mod.Skill,
    user_input: []const u8,
) bool {
    if (match.*) |existing| {
        if (existing.skill != skill) return false;
        return true;
    }
    match.* = .{
        .skill = skill,
        .user_input = user_input,
    };
    return true;
}

fn clearActiveSkillSession(self: anytype) void {
    if (!@hasField(@TypeOf(self.*), "active_skill_name")) return;

    if (self.active_skill_name_owned and self.active_skill_name != null) self.allocator.free(self.active_skill_name.?);
    if (self.active_skill_description_owned and self.active_skill_description != null) self.allocator.free(self.active_skill_description.?);
    if (self.active_skill_instructions_owned and self.active_skill_instructions != null) self.allocator.free(self.active_skill_instructions.?);
    if (self.active_skill_path_owned and self.active_skill_path != null) self.allocator.free(self.active_skill_path.?);

    self.active_skill_name = null;
    self.active_skill_name_owned = false;
    self.active_skill_description = null;
    self.active_skill_description_owned = false;
    self.active_skill_instructions = null;
    self.active_skill_instructions_owned = false;
    self.active_skill_path = null;
    self.active_skill_path_owned = false;
    self.active_skill_interactive = false;
}

fn setActiveSkillSession(self: anytype, skill: *const skills_mod.Skill, interactive: bool) !void {
    const owned_name = try self.allocator.dupe(u8, skill.name);
    errdefer self.allocator.free(owned_name);

    const owned_description = if (skill.description.len > 0)
        try self.allocator.dupe(u8, skill.description)
    else
        null;
    errdefer if (owned_description) |value| self.allocator.free(value);

    const owned_instructions = if (skill.instructions.len > 0)
        try self.allocator.dupe(u8, skill.instructions)
    else
        null;
    errdefer if (owned_instructions) |value| self.allocator.free(value);

    const owned_path = if (skill.path.len > 0)
        try self.allocator.dupe(u8, skill.path)
    else
        null;
    errdefer if (owned_path) |value| self.allocator.free(value);

    clearActiveSkillSession(self);
    self.active_skill_name = owned_name;
    self.active_skill_name_owned = true;
    self.active_skill_description = owned_description;
    self.active_skill_description_owned = owned_description != null;
    self.active_skill_instructions = owned_instructions;
    self.active_skill_instructions_owned = owned_instructions != null;
    self.active_skill_path = owned_path;
    self.active_skill_path_owned = owned_path != null;
    self.active_skill_interactive = interactive;
}

/// Activate a skill session by name. Returns true when found and activated,
/// false when no skill with that name exists.
pub fn activateSkillByName(self: anytype, name: []const u8) !bool {
    const skills = try skills_mod.listSkills(self.allocator, self.workspace_dir, self.observer);
    defer skills_mod.freeSkills(self.allocator, skills);
    switch (findSkillByNameNormalized(skills, name)) {
        .unique => |skill| {
            try setActiveSkillSession(self, skill, false);
            return true;
        },
        else => return false,
    }
}

fn activeSkillModeLabel(interactive: bool) []const u8 {
    return if (interactive) "interactive" else "non-interactive";
}

fn appendSkillLaunchContextBody(
    self: anytype,
    writer: anytype,
    skill_name: []const u8,
    skill_description: ?[]const u8,
    skill_path: ?[]const u8,
    interactive: bool,
    launch_mode: SkillLaunchMode,
) !void {
    try writer.writeAll("- Launcher: nullclaw\n");
    try writer.print("- Launch mode: {s}\n", .{switch (launch_mode) {
        .one_shot => "one-off request",
        .session_active => "session-bound",
    }});
    try writer.print("- Skill: {s}\n", .{skill_name});
    if (skill_description) |value| {
        if (value.len > 0) try writer.print("- Skill description: {s}\n", .{value});
    }
    if (skill_path) |value| {
        if (value.len > 0) try writer.print("- Skill directory: {s}\n", .{value});
    }
    if (@hasField(@TypeOf(self.*), "workspace_dir")) {
        try writer.print("- Agent workspace: {s}\n", .{self.workspace_dir});
    }
    try writer.print("- Interaction mode: {s}\n", .{activeSkillModeLabel(interactive)});

    if (@hasField(@TypeOf(self.*), "conversation_context")) {
        if (self.conversation_context) |ctx| {
            if (ctx.channel) |value| try writer.print("- Channel: {s}\n", .{value});
            if (ctx.account_id) |value| try writer.print("- Account ID: {s}\n", .{value});
            if (ctx.peer_id) |value| try writer.print("- Peer ID: {s}\n", .{value});
            if (ctx.group_id) |value| try writer.print("- Group ID: {s}\n", .{value});
            if (ctx.is_group) |is_group| {
                try writer.print("- Chat type: {s}\n", .{if (is_group) "group" else "direct"});
            }
        }
    }

    try writer.writeAll("\nOperational rules:\n");
    try writer.writeAll("- This skill is running inside the current nullclaw agent session, not as a standalone CLI process.\n");
    if (interactive) {
        try writer.writeAll("- Interactive mode is ON. On Telegram and other supported channels, prefer `<nc_choices>...</nc_choices>` instead of `AskUserQuestion` or `mcp_question`.\n");
    } else {
        try writer.writeAll("- Interactive mode is OFF. Avoid clarification loops; choose sane defaults unless missing data truly blocks progress.\n");
    }
    if (launch_mode == .session_active) {
        try writer.writeAll("- This skill remains active for later messages in the current session until `/skill clear` is used.\n");
    }
}

fn buildSkillInvocationPrompt(
    self: anytype,
    skill: *const skills_mod.Skill,
    user_input: []const u8,
    interactive: bool,
) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const writer = &out_writer.writer;

    try writer.print("Apply the skill `{s}`.\n\n", .{skill.name});
    try writer.writeAll("## Skill Launch Context\n\n");
    try appendSkillLaunchContextBody(
        self,
        writer,
        skill.name,
        if (skill.description.len > 0) skill.description else null,
        if (skill.path.len > 0) skill.path else null,
        interactive,
        .one_shot,
    );
    if (skill.instructions.len > 0) {
        try writer.writeAll("\n\n## Skill Instructions\n\n");
        try writer.writeAll(skill.instructions);
    }
    try writer.writeAll("\n\n## Task\n\n");
    try writer.writeAll(user_input);
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

pub fn buildActiveSkillPromptSection(self: anytype) !?[]const u8 {
    if (!@hasField(@TypeOf(self.*), "active_skill_name")) return null;
    const skill_name = self.active_skill_name orelse return null;

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const writer = &out_writer.writer;

    try writer.writeAll("## Active Skill Session\n\n");
    try writer.writeAll("An operator armed a session-scoped skill for this conversation. Treat subsequent user messages as work for that skill unless they explicitly clear or replace it.\n\n");
    try appendSkillLaunchContextBody(
        self,
        writer,
        skill_name,
        self.active_skill_description,
        self.active_skill_path,
        self.active_skill_interactive,
        .session_active,
    );
    if (self.active_skill_instructions) |instructions| {
        if (instructions.len > 0) {
            try writer.writeAll("\n\n## Active Skill Instructions\n\n");
            try writer.writeAll(instructions);
        }
    }

    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn shouldRenderSkillChoices(self: anytype) bool {
    if (!@hasField(@TypeOf(self.*), "conversation_context")) return false;
    const ctx = self.conversation_context orelse return false;
    const channel = ctx.channel orelse return false;
    return std.ascii.eqlIgnoreCase(channel, "telegram");
}

fn appendJsonString(writer: anytype, value: []const u8) !void {
    try writer.print("{f}", .{std.json.fmt(value, .{})});
}

fn appendSkillCommandChoices(
    self: anytype,
    writer: anytype,
    choices: []const SkillMenuCommandChoice,
    columns: u8,
) !void {
    _ = self;
    if (choices.len < interaction_choices.MIN_OPTIONS or choices.len > interaction_choices.MAX_OPTIONS) return;
    const safe_columns: u8 = @max(@as(u8, 1), @min(columns, interaction_choices.MAX_COLUMNS));

    try writer.writeAll("\n");
    try writer.writeAll(interaction_choices.START_TAG);
    try writer.print("{{\"v\":1,\"columns\":{d},\"options\":[", .{safe_columns});

    var first = true;
    for (choices, 0..) |choice, idx| {
        if (!first) try writer.writeAll(",");
        first = false;

        var id_buf: [16]u8 = undefined;
        const option_id = try std.fmt.bufPrint(&id_buf, "s{d}", .{idx + 1});
        const label = if (choice.label.len > interaction_choices.MAX_LABEL_LEN)
            choice.label[0..interaction_choices.MAX_LABEL_LEN]
        else
            choice.label;

        try writer.writeAll("{\"id\":");
        try appendJsonString(writer, option_id);
        try writer.writeAll(",\"label\":");
        try appendJsonString(writer, label);
        try writer.writeAll(",\"submit_text\":");
        try appendJsonString(writer, choice.submit_text);
        try writer.writeAll("}");
    }
    try writer.writeAll("]}");
    try writer.writeAll(interaction_choices.END_TAG);
}

fn appendSkillActionChoices(
    self: anytype,
    writer: anytype,
    include_clear: bool,
) !void {
    if (!shouldRenderSkillChoices(self)) return;

    const choices = if (include_clear)
        [_]SkillMenuCommandChoice{
            .{ .label = "Skills", .submit_text = "/skills" },
            .{ .label = "Clear skill", .submit_text = "/skill clear" },
        }
    else
        [_]SkillMenuCommandChoice{
            .{ .label = "Skills", .submit_text = "/skills" },
            .{ .label = "Skill status", .submit_text = "/skill status" },
        };
    try appendSkillCommandChoices(self, writer, &choices, 2);
}

fn countAvailableSkills(skills: []const skills_mod.Skill) usize {
    var count: usize = 0;
    for (skills) |skill| {
        if (skill.available) count += 1;
    }
    return count;
}

fn unavailableSkillCount(skills: []const skills_mod.Skill) usize {
    var count: usize = 0;
    for (skills) |skill| {
        if (!skill.available) count += 1;
    }
    return count;
}

fn parseSkillMenuPageIndex(arg: []const u8) usize {
    const trimmed = std.mem.trim(u8, arg, " \t");
    if (trimmed.len == 0) return 0;
    const parsed = std.fmt.parseInt(usize, trimmed, 10) catch return 0;
    if (parsed == 0) return 0;
    return parsed - 1;
}

fn collectSortedSkillRefs(
    allocator: std.mem.Allocator,
    skills: []const skills_mod.Skill,
    available_only: bool,
) ![]*const skills_mod.Skill {
    var refs: std.ArrayList(*const skills_mod.Skill) = .empty;
    errdefer refs.deinit(allocator);

    for (skills) |*skill| {
        if (available_only and !skill.available) continue;
        try refs.append(allocator, skill);
    }

    std.mem.sort(*const skills_mod.Skill, refs.items, {}, struct {
        fn lessThan(_: void, left: *const skills_mod.Skill, right: *const skills_mod.Skill) bool {
            return std.mem.lessThan(u8, left.name, right.name);
        }
    }.lessThan);

    return try refs.toOwnedSlice(allocator);
}

fn skillPrefixToken(name: []const u8) ?[]const u8 {
    const sep = std.mem.indexOfScalar(u8, name, '-') orelse return null;
    if (sep == 0 or sep + 1 >= name.len) return null;
    return name[0..sep];
}

fn skillSuffixToken(name: []const u8) ?[]const u8 {
    const sep = std.mem.lastIndexOfScalar(u8, name, '-') orelse return null;
    if (sep == 0 or sep + 1 >= name.len) return null;
    return name[sep + 1 ..];
}

fn skillBaseName(name: []const u8) []const u8 {
    const sep = std.mem.indexOfScalar(u8, name, '-') orelse return name;
    if (sep + 1 >= name.len) return name;
    return name[sep + 1 ..];
}

fn firstSkillBrowseLetter(name: []const u8) ?u8 {
    for (name) |ch| {
        if (std.ascii.isAlphabetic(ch)) return std.ascii.toLower(ch);
    }
    return null;
}

fn skillMatchesLetter(skill: *const skills_mod.Skill, letter: u8) bool {
    if (firstSkillBrowseLetter(skill.name)) |value| {
        if (value == letter) return true;
    }

    const prefix = skillPrefixToken(skill.name) orelse return false;
    _ = prefix;
    if (firstSkillBrowseLetter(skillBaseName(skill.name))) |value| {
        return value == letter;
    }
    return false;
}

fn parseSkillLetterGroup(group: []const u8) ?SkillLetterGroup {
    if (std.ascii.eqlIgnoreCase(group, "a-f")) return .{ .label = "A-F", .command = "/skills letters a-f" };
    if (std.ascii.eqlIgnoreCase(group, "g-l")) return .{ .label = "G-L", .command = "/skills letters g-l" };
    if (std.ascii.eqlIgnoreCase(group, "m-r")) return .{ .label = "M-R", .command = "/skills letters m-r" };
    if (std.ascii.eqlIgnoreCase(group, "s-z")) return .{ .label = "S-Z", .command = "/skills letters s-z" };
    return null;
}

fn skillLetterInGroup(letter: u8, group: []const u8) bool {
    const normalized = std.ascii.toLower(letter);
    if (normalized < 'a' or normalized > 'z') return false;
    if (std.ascii.eqlIgnoreCase(group, "a-f")) return normalized >= 'a' and normalized <= 'f';
    if (std.ascii.eqlIgnoreCase(group, "g-l")) return normalized >= 'g' and normalized <= 'l';
    if (std.ascii.eqlIgnoreCase(group, "m-r")) return normalized >= 'm' and normalized <= 'r';
    if (std.ascii.eqlIgnoreCase(group, "s-z")) return normalized >= 's' and normalized <= 'z';
    return false;
}

fn skillLetterGroupCommand(letter: u8) []const u8 {
    const normalized = std.ascii.toLower(letter);
    return if (normalized >= 'a' and normalized <= 'f')
        "/skills letters a-f"
    else if (normalized >= 'g' and normalized <= 'l')
        "/skills letters g-l"
    else if (normalized >= 'm' and normalized <= 'r')
        "/skills letters m-r"
    else
        "/skills letters s-z";
}

fn collectSkillAffixEntries(
    allocator: std.mem.Allocator,
    refs: []const *const skills_mod.Skill,
    kind: SkillAffixKind,
) ![]SkillAffixEntry {
    var counts = std.StringHashMap(usize).init(allocator);
    defer counts.deinit();

    for (refs) |skill| {
        const token = switch (kind) {
            .prefix => skillPrefixToken(skill.name),
            .suffix => skillSuffixToken(skill.name),
        } orelse continue;

        const gop = try counts.getOrPut(token);
        if (gop.found_existing) {
            gop.value_ptr.* += 1;
        } else {
            gop.value_ptr.* = 1;
        }
    }

    const entries = try allocator.alloc(SkillAffixEntry, counts.count());
    errdefer allocator.free(entries);

    var idx: usize = 0;
    var it = counts.iterator();
    while (it.next()) |entry| : (idx += 1) {
        entries[idx] = .{
            .token = entry.key_ptr.*,
            .count = entry.value_ptr.*,
        };
    }

    std.mem.sort(SkillAffixEntry, entries, {}, struct {
        fn lessThan(_: void, left: SkillAffixEntry, right: SkillAffixEntry) bool {
            return std.mem.lessThan(u8, left.token, right.token);
        }
    }.lessThan);

    return entries;
}

fn collectSkillRefsByLetter(
    allocator: std.mem.Allocator,
    refs: []const *const skills_mod.Skill,
    letter: u8,
) ![]*const skills_mod.Skill {
    var filtered: std.ArrayList(*const skills_mod.Skill) = .empty;
    errdefer filtered.deinit(allocator);

    const normalized = std.ascii.toLower(letter);
    for (refs) |skill| {
        if (skillMatchesLetter(skill, normalized)) try filtered.append(allocator, skill);
    }
    return try filtered.toOwnedSlice(allocator);
}

fn collectSkillRefsByAffix(
    allocator: std.mem.Allocator,
    refs: []const *const skills_mod.Skill,
    kind: SkillAffixKind,
    token: []const u8,
) ![]*const skills_mod.Skill {
    var filtered: std.ArrayList(*const skills_mod.Skill) = .empty;
    errdefer filtered.deinit(allocator);

    for (refs) |skill| {
        const candidate = switch (kind) {
            .prefix => skillPrefixToken(skill.name),
            .suffix => skillSuffixToken(skill.name),
        } orelse continue;
        if (!std.ascii.eqlIgnoreCase(candidate, token)) continue;
        try filtered.append(allocator, skill);
    }
    return try filtered.toOwnedSlice(allocator);
}

fn formatSkillBrowserRoot(self: anytype, skills: []const skills_mod.Skill) ![]const u8 {
    if (!shouldRenderSkillChoices(self)) {
        return try formatSkillListText(self, skills);
    }
    if (skills.len == 0) {
        return try formatSkillInactiveReply(self, "No skills found in workspace.");
    }

    const available_total = countAvailableSkills(skills);
    if (available_total == 0) {
        return try std.fmt.allocPrint(
            self.allocator,
            "No available skills found in workspace. Unavailable skills: {d}.",
            .{unavailableSkillCount(skills)},
        );
    }

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const writer = &out_writer.writer;

    try writer.print("Skill browser: {d} available skill(s).\n", .{available_total});
    if (@hasField(@TypeOf(self.*), "active_skill_name")) {
        if (self.active_skill_name) |name| {
            try writer.print("Current active skill: {s} ({s}).\n", .{
                name,
                activeSkillModeLabel(self.active_skill_interactive),
            });
        }
    }
    const hidden_unavailable = unavailableSkillCount(skills);
    if (hidden_unavailable > 0) {
        try writer.print("Unavailable skills hidden: {d}.\n", .{hidden_unavailable});
    }
    try writer.writeAll("Choose a letter range, prefix, suffix, or open the full sorted list. Letter filters match both the raw skill name and the base name after the first prefix.");

    var choices = [_]SkillMenuCommandChoice{
        .{ .label = "A-F", .submit_text = "/skills letters a-f" },
        .{ .label = "G-L", .submit_text = "/skills letters g-l" },
        .{ .label = "M-R", .submit_text = "/skills letters m-r" },
        .{ .label = "S-Z", .submit_text = "/skills letters s-z" },
        .{ .label = "Prefixes", .submit_text = "/skills prefixes" },
        .{ .label = "Suffixes", .submit_text = "/skills suffixes" },
        .{ .label = "All skills", .submit_text = "/skills all" },
        .{ .label = "Skill status", .submit_text = "/skill status" },
    };
    try appendSkillCommandChoices(self, writer, &choices, SKILL_MENU_COLUMNS);
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn formatSkillListText(self: anytype, skills: []const skills_mod.Skill) ![]const u8 {
    if (skills.len == 0) {
        return try formatSkillInactiveReply(self, "No skills found in workspace.");
    }

    const refs = try collectSortedSkillRefs(self.allocator, skills, false);
    defer self.allocator.free(refs);

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const writer = &out_writer.writer;

    try writer.writeAll("Available skills:\n");
    for (refs) |skill| {
        try writer.print("  - {s}", .{skill.name});
        if (skill.description.len > 0) try writer.print(": {s}", .{skill.description});
        if (!skill.available) try writer.print(" (unavailable: {s})", .{skill.missing_deps});
        if (@hasField(@TypeOf(self.*), "active_skill_name") and self.active_skill_name != null and
            std.mem.eql(u8, self.active_skill_name.?, skill.name))
        {
            try writer.print(" [active: {s}]", .{activeSkillModeLabel(self.active_skill_interactive)});
        }
        try writer.writeAll("\n");
    }

    if (@hasField(@TypeOf(self.*), "active_skill_name")) {
        if (self.active_skill_name) |name| {
            try writer.print("\nCurrent active skill: {s} ({s})\n", .{
                name,
                activeSkillModeLabel(self.active_skill_interactive),
            });
        }
    }

    try writer.writeAll("\nUse `/skill <name>` to arm a non-interactive session skill, `/iskill <name>` for an interactive session skill, or `/skill <name> <task>` for a one-off skill task.");
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn formatSkillRefListPage(
    self: anytype,
    title: []const u8,
    refs: []const *const skills_mod.Skill,
    page_index: usize,
    next_prefix: []const u8,
    back_submit: []const u8,
) ![]const u8 {
    if (refs.len == 0) {
        return try formatSkillInactiveReply(self, "No matching skills found.");
    }

    if (!shouldRenderSkillChoices(self)) {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
        const writer = &out_writer.writer;
        try writer.print("{s}:\n", .{title});
        for (refs) |skill| {
            try writer.print("  - {s}", .{skill.name});
            if (skill.description.len > 0) try writer.print(": {s}", .{skill.description});
            try writer.writeAll("\n");
        }
        out = out_writer.toArrayList();
        return try out.toOwnedSlice(self.allocator);
    }

    const safe_page_index = @min(page_index, (refs.len - 1) / SKILL_MENU_PAGE_SIZE);
    const start = safe_page_index * SKILL_MENU_PAGE_SIZE;
    const end = @min(start + SKILL_MENU_PAGE_SIZE, refs.len);

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const writer = &out_writer.writer;

    try writer.print("{s}: showing {d}-{d} of {d}.\n", .{
        title,
        start + 1,
        end,
        refs.len,
    });
    try writer.writeAll("Tap a skill to activate it in interactive mode. Use /skill <name> for non-interactive mode.");

    var choices_buf: [interaction_choices.MAX_OPTIONS]SkillMenuCommandChoice = undefined;
    var choices_len: usize = 0;

    for (refs[start..end]) |skill| {
        const submit_text = try std.fmt.allocPrint(self.allocator, "/iskill {s}", .{skill.name});
        errdefer self.allocator.free(submit_text);
        choices_buf[choices_len] = .{
            .label = skill.name,
            .submit_text = submit_text,
        };
        choices_len += 1;
    }

    if (end < refs.len and choices_len < interaction_choices.MAX_OPTIONS) {
        const next_submit = try std.fmt.allocPrint(self.allocator, "{s} {d}", .{ next_prefix, safe_page_index + 2 });
        errdefer self.allocator.free(next_submit);
        choices_buf[choices_len] = .{
            .label = "More",
            .submit_text = next_submit,
        };
        choices_len += 1;
    }

    if (choices_len < interaction_choices.MAX_OPTIONS) {
        choices_buf[choices_len] = .{
            .label = "Back",
            .submit_text = back_submit,
        };
        choices_len += 1;
    }

    defer {
        for (choices_buf[0 .. end - start]) |choice| {
            self.allocator.free(choice.submit_text);
        }
        if (end < refs.len) {
            self.allocator.free(choices_buf[end - start].submit_text);
        }
    }

    try appendSkillCommandChoices(self, writer, choices_buf[0..choices_len], SKILL_MENU_COLUMNS);
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn formatSkillLetterGroupMenu(
    self: anytype,
    refs: []const *const skills_mod.Skill,
    group: []const u8,
) ![]const u8 {
    const parsed_group = parseSkillLetterGroup(group) orelse return try formatSkillInactiveReply(self, "Unknown letter range.");

    if (!shouldRenderSkillChoices(self)) {
        return try self.allocator.dupe(u8, "Letter menus are optimized for Telegram. Use /skills there to browse interactively.");
    }

    var present: [26]bool = [_]bool{false} ** 26;
    for (refs) |skill| {
        if (firstSkillBrowseLetter(skill.name)) |letter| {
            if (skillLetterInGroup(letter, group)) present[letter - 'a'] = true;
        }
        if (firstSkillBrowseLetter(skillBaseName(skill.name))) |letter| {
            if (skillLetterInGroup(letter, group)) present[letter - 'a'] = true;
        }
    }

    var choices_buf: [interaction_choices.MAX_OPTIONS]SkillMenuCommandChoice = undefined;
    var choices_len: usize = 0;
    for (present, 0..) |is_present, idx| {
        if (!is_present) continue;
        const letter = @as(u8, @intCast(idx)) + 'a';
        const submit_text = try std.fmt.allocPrint(self.allocator, "/skills letter {c}", .{letter});
        errdefer self.allocator.free(submit_text);
        const label = try std.fmt.allocPrint(self.allocator, "{c}", .{std.ascii.toUpper(letter)});
        errdefer self.allocator.free(label);
        choices_buf[choices_len] = .{
            .label = label,
            .submit_text = submit_text,
        };
        choices_len += 1;
    }

    if (choices_len == 0) {
        return try formatSkillInactiveReply(self, "No matching letters found for this range.");
    }

    choices_buf[choices_len] = .{
        .label = "Back",
        .submit_text = "/skills",
    };
    choices_len += 1;

    defer {
        for (choices_buf[0..choices_len]) |choice| {
            if (choice.label.len == 1 and std.ascii.isAlphabetic(choice.label[0])) self.allocator.free(choice.label);
            if (std.mem.startsWith(u8, choice.submit_text, "/skills ")) self.allocator.free(choice.submit_text);
        }
    }

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const writer = &out_writer.writer;
    try writer.print("Letter range {s}. Choose a starting letter.\n", .{parsed_group.label});
    try writer.writeAll("Matches include both the raw skill name and the base name after the first prefix.");
    try appendSkillCommandChoices(self, writer, choices_buf[0..choices_len], SKILL_MENU_COLUMNS);
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn formatSkillAffixMenu(
    self: anytype,
    refs: []const *const skills_mod.Skill,
    kind: SkillAffixKind,
    page_index: usize,
) ![]const u8 {
    const entries = try collectSkillAffixEntries(self.allocator, refs, kind);
    defer self.allocator.free(entries);

    if (entries.len == 0) {
        return try formatSkillInactiveReply(self, "No skill prefixes or suffixes found.");
    }

    if (!shouldRenderSkillChoices(self)) {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
        const writer = &out_writer.writer;
        try writer.print("{s}:\n", .{if (kind == .prefix) "Skill prefixes" else "Skill suffixes"});
        for (entries) |entry| {
            if (kind == .prefix) {
                try writer.print("  - {s}- ({d})\n", .{ entry.token, entry.count });
            } else {
                try writer.print("  - -{s} ({d})\n", .{ entry.token, entry.count });
            }
        }
        out = out_writer.toArrayList();
        return try out.toOwnedSlice(self.allocator);
    }

    const safe_page_index = @min(page_index, (entries.len - 1) / SKILL_MENU_PAGE_SIZE);
    const start = safe_page_index * SKILL_MENU_PAGE_SIZE;
    const end = @min(start + SKILL_MENU_PAGE_SIZE, entries.len);
    const next_prefix = if (kind == .prefix) "/skills prefixes" else "/skills suffixes";

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const writer = &out_writer.writer;
    try writer.print("{s}: showing {d}-{d} of {d}.\n", .{
        if (kind == .prefix) "Skill prefixes" else "Skill suffixes",
        start + 1,
        end,
        entries.len,
    });
    try writer.writeAll("Choose an affix to narrow the skill list.");

    var choices_buf: [interaction_choices.MAX_OPTIONS]SkillMenuCommandChoice = undefined;
    var choices_len: usize = 0;

    for (entries[start..end]) |entry| {
        const submit_text = switch (kind) {
            .prefix => try std.fmt.allocPrint(self.allocator, "/skills prefix {s}", .{entry.token}),
            .suffix => try std.fmt.allocPrint(self.allocator, "/skills suffix {s}", .{entry.token}),
        };
        errdefer self.allocator.free(submit_text);
        const label = switch (kind) {
            .prefix => try std.fmt.allocPrint(self.allocator, "{s}- ({d})", .{ entry.token, entry.count }),
            .suffix => try std.fmt.allocPrint(self.allocator, "-{s} ({d})", .{ entry.token, entry.count }),
        };
        errdefer self.allocator.free(label);
        choices_buf[choices_len] = .{
            .label = label,
            .submit_text = submit_text,
        };
        choices_len += 1;
    }

    if (end < entries.len and choices_len < interaction_choices.MAX_OPTIONS) {
        const next_submit = try std.fmt.allocPrint(self.allocator, "{s} {d}", .{ next_prefix, safe_page_index + 2 });
        errdefer self.allocator.free(next_submit);
        choices_buf[choices_len] = .{
            .label = "More",
            .submit_text = next_submit,
        };
        choices_len += 1;
    }

    choices_buf[choices_len] = .{
        .label = "Back",
        .submit_text = "/skills",
    };
    choices_len += 1;

    defer {
        for (choices_buf[0..choices_len]) |choice| {
            if (std.mem.startsWith(u8, choice.label, "-") or std.mem.indexOfScalar(u8, choice.label, '(') != null) self.allocator.free(choice.label);
            if (std.mem.startsWith(u8, choice.submit_text, "/skills ")) self.allocator.free(choice.submit_text);
        }
    }

    try appendSkillCommandChoices(self, writer, choices_buf[0..choices_len], SKILL_MENU_COLUMNS);
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn formatSkillList(self: anytype, skills: []const skills_mod.Skill, arg: []const u8) ![]const u8 {
    if (skills.len == 0) {
        return try formatSkillInactiveReply(self, "No skills found in workspace.");
    }

    const available_total = countAvailableSkills(skills);
    if (available_total == 0) {
        return try std.fmt.allocPrint(
            self.allocator,
            "No available skills found in workspace. Unavailable skills: {d}.",
            .{unavailableSkillCount(skills)},
        );
    }

    const available_refs = try collectSortedSkillRefs(self.allocator, skills, true);
    defer self.allocator.free(available_refs);

    const trimmed = std.mem.trim(u8, arg, " \t");
    if (trimmed.len == 0) {
        return try formatSkillBrowserRoot(self, skills);
    }

    if (parsePositiveUsize(trimmed)) |page_num| {
        return try formatSkillRefListPage(self, "All skills", available_refs, page_num - 1, "/skills all", "/skills");
    }

    const parsed = splitFirstToken(trimmed);
    const head = parsed.head;
    const tail = std.mem.trim(u8, parsed.tail, " \t");

    if (std.ascii.eqlIgnoreCase(head, "all")) {
        return try formatSkillRefListPage(self, "All skills", available_refs, parseSkillMenuPageIndex(tail), "/skills all", "/skills");
    }

    if (std.ascii.eqlIgnoreCase(head, "letters")) {
        return try formatSkillLetterGroupMenu(self, available_refs, tail);
    }

    if (std.ascii.eqlIgnoreCase(head, "letter")) {
        const letter_arg = splitFirstToken(tail);
        if (letter_arg.head.len != 1 or !std.ascii.isAlphabetic(letter_arg.head[0])) {
            return try formatSkillInactiveReply(self, "Usage: /skills letter <a-z>");
        }
        const letter = std.ascii.toLower(letter_arg.head[0]);
        const filtered = try collectSkillRefsByLetter(self.allocator, available_refs, letter);
        defer self.allocator.free(filtered);

        const title = try std.fmt.allocPrint(self.allocator, "Skills for letter {c}", .{std.ascii.toUpper(letter)});
        defer self.allocator.free(title);
        const next_prefix = try std.fmt.allocPrint(self.allocator, "/skills letter {c}", .{letter});
        defer self.allocator.free(next_prefix);

        return try formatSkillRefListPage(
            self,
            title,
            filtered,
            parseSkillMenuPageIndex(letter_arg.tail),
            next_prefix,
            skillLetterGroupCommand(letter),
        );
    }

    if (std.ascii.eqlIgnoreCase(head, "prefixes")) {
        return try formatSkillAffixMenu(self, available_refs, .prefix, parseSkillMenuPageIndex(tail));
    }

    if (std.ascii.eqlIgnoreCase(head, "suffixes")) {
        return try formatSkillAffixMenu(self, available_refs, .suffix, parseSkillMenuPageIndex(tail));
    }

    if (std.ascii.eqlIgnoreCase(head, "prefix") or std.ascii.eqlIgnoreCase(head, "suffix")) {
        const token_arg = splitFirstToken(tail);
        if (token_arg.head.len == 0) {
            return try formatSkillInactiveReply(
                self,
                if (std.ascii.eqlIgnoreCase(head, "prefix")) "Usage: /skills prefix <name>" else "Usage: /skills suffix <name>",
            );
        }

        const kind: SkillAffixKind = if (std.ascii.eqlIgnoreCase(head, "prefix")) .prefix else .suffix;
        const filtered = try collectSkillRefsByAffix(self.allocator, available_refs, kind, token_arg.head);
        defer self.allocator.free(filtered);

        const title = switch (kind) {
            .prefix => try std.fmt.allocPrint(self.allocator, "Skills with prefix {s}-", .{token_arg.head}),
            .suffix => try std.fmt.allocPrint(self.allocator, "Skills with suffix -{s}", .{token_arg.head}),
        };
        defer self.allocator.free(title);

        const next_prefix = switch (kind) {
            .prefix => try std.fmt.allocPrint(self.allocator, "/skills prefix {s}", .{token_arg.head}),
            .suffix => try std.fmt.allocPrint(self.allocator, "/skills suffix {s}", .{token_arg.head}),
        };
        defer self.allocator.free(next_prefix);
        const back_submit = if (kind == .prefix)
            try self.allocator.dupe(u8, "/skills prefixes")
        else
            try self.allocator.dupe(u8, "/skills suffixes");
        defer self.allocator.free(back_submit);

        return try formatSkillRefListPage(
            self,
            title,
            filtered,
            parseSkillMenuPageIndex(token_arg.tail),
            next_prefix,
            back_submit,
        );
    }

    return try formatSkillBrowserRoot(self, skills);
}

fn formatSkillActivatedReply(
    self: anytype,
    skill: *const skills_mod.Skill,
    interactive: bool,
) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const writer = &out_writer.writer;

    try writer.print("Active skill set to `{s}` ({s}).\n", .{
        skill.name,
        activeSkillModeLabel(interactive),
    });
    if (skill.path.len > 0) {
        try writer.print("Skill directory: {s}\n", .{skill.path});
    }
    try writer.writeAll("Send your next message to continue in this skill. Use /skill clear to leave it.");
    try appendSkillActionChoices(self, writer, true);
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn formatSkillInactiveReply(self: anytype, text: []const u8) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const writer = &out_writer.writer;

    try writer.writeAll(text);
    try appendSkillActionChoices(self, writer, false);
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn formatSkillUnknownReply(self: anytype, name: []const u8) ![]const u8 {
    const text = try std.fmt.allocPrint(self.allocator, "Skill not found: {s}", .{name});
    defer self.allocator.free(text);
    return try formatSkillInactiveReply(self, text);
}

fn formatSkillAmbiguousReply(self: anytype, name: []const u8) ![]const u8 {
    const text = try formatAmbiguousSkillName(self, name);
    defer self.allocator.free(text);
    return try formatSkillInactiveReply(self, text);
}

fn formatActiveSkillStatus(self: anytype) ![]const u8 {
    if (!@hasField(@TypeOf(self.*), "active_skill_name") or self.active_skill_name == null) {
        return try formatSkillInactiveReply(self, "No active skill session. Use /skills to browse or /skill <name> to activate one.");
    }

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const writer = &out_writer.writer;

    try writer.print("Active skill: {s}\n", .{self.active_skill_name.?});
    try writer.print("Mode: {s}\n", .{activeSkillModeLabel(self.active_skill_interactive)});
    if (self.active_skill_description) |value| {
        if (value.len > 0) try writer.print("Description: {s}\n", .{value});
    }
    if (self.active_skill_path) |value| {
        if (value.len > 0) try writer.print("Skill directory: {s}\n", .{value});
    }
    if (@hasField(@TypeOf(self.*), "conversation_context")) {
        if (self.conversation_context) |ctx| {
            if (ctx.channel) |value| try writer.print("Channel: {s}\n", .{value});
            if (ctx.account_id) |value| try writer.print("Account: {s}\n", .{value});
            if (ctx.peer_id) |value| try writer.print("Peer: {s}\n", .{value});
        }
    }
    try writer.writeAll("Use /skill clear to leave this skill session.");
    try appendSkillActionChoices(self, writer, true);
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn executeSkillInvocation(
    self: anytype,
    skill: *const skills_mod.Skill,
    user_input: []const u8,
    interactive: bool,
) ![]const u8 {
    if (!skill.available) {
        return try std.fmt.allocPrint(
            self.allocator,
            "Skill {s} is unavailable: {s}",
            .{ skill.name, skill.missing_deps },
        );
    }

    if (user_input.len == 0) {
        if (skill.instructions.len > 0) {
            return try std.fmt.allocPrint(
                self.allocator,
                "Skill {s}: {s}\nUsage: /skill {s} <task>",
                .{ skill.name, if (skill.description.len > 0) skill.description else "no description", skill.name },
            );
        }
        return try std.fmt.allocPrint(
            self.allocator,
            "Skill {s} has no instructions. Usage: /skill {s} <task>",
            .{ skill.name, skill.name },
        );
    }

    const composed = try buildSkillInvocationPrompt(self, skill, user_input, interactive);
    defer self.allocator.free(composed);

    if (findSubagentManager(self) != null) {
        return try spawnSubagentTask(self, composed, skill.name, null);
    }
    return try std.fmt.allocPrint(
        self.allocator,
        "Skill prompt prepared for `{s}` (spawn tool is disabled):\n{s}",
        .{ skill.name, composed },
    );
}

fn tryHandleDirectSkillCommand(self: anytype, cmd: SlashCommand) !?[]const u8 {
    const skills = skills_mod.listSkills(self.allocator, self.workspace_dir, self.observer) catch return null;
    defer skills_mod.freeSkills(self.allocator, skills);

    var resolved: ?DirectSkillCommandMatch = null;

    switch (findSkillByNameNormalized(skills, cmd.name)) {
        .unique => |skill| {
            if (!registerDirectSkillCommandMatch(&resolved, skill, cmd.arg)) {
                return try formatAmbiguousSkillName(self, cmd.name);
            }
        },
        .ambiguous => return try formatAmbiguousSkillName(self, cmd.name),
        .not_found => {},
    }

    var composite = std.ArrayListUnmanaged(u8).empty;
    defer composite.deinit(self.allocator);
    try composite.appendSlice(self.allocator, cmd.name);

    var remaining = cmd.arg;
    while (true) {
        const parsed_arg = splitFirstToken(remaining);
        if (parsed_arg.head.len == 0) break;

        try composite.append(self.allocator, ' ');
        try composite.appendSlice(self.allocator, parsed_arg.head);

        switch (findSkillByNameNormalized(skills, composite.items)) {
            .unique => |skill| {
                if (!registerDirectSkillCommandMatch(&resolved, skill, parsed_arg.tail)) {
                    return try formatAmbiguousSkillName(self, composite.items);
                }
            },
            .ambiguous => return try formatAmbiguousSkillName(self, composite.items),
            .not_found => {},
        }

        remaining = parsed_arg.tail;
    }

    if (resolved) |match| {
        return try executeSkillInvocation(self, match.skill, match.user_input, false);
    }
    return null;
}

const SUBAGENTS_SPAWN_USAGE = "Usage: /subagents spawn [--agent <name>|--agent=<name>] <task>";

const SubagentSpawnRequest = struct {
    task: []const u8,
    agent_name: ?[]const u8 = null,
};

fn parseSubagentSpawnRequest(arg: []const u8) ?SubagentSpawnRequest {
    const trimmed = std.mem.trim(u8, arg, " \t\r\n");
    if (trimmed.len == 0) return null;

    if (std.mem.startsWith(u8, trimmed, "--agent")) {
        var i: usize = "--agent".len;
        if (std.mem.startsWith(u8, trimmed, "--agent=")) {
            i = "--agent=".len;
        } else if (trimmed.len == "--agent".len or std.ascii.isWhitespace(trimmed[i])) {
            while (i < trimmed.len and std.ascii.isWhitespace(trimmed[i])) : (i += 1) {}
        } else {
            return .{ .task = trimmed };
        }

        if (i >= trimmed.len) return null;

        const agent_start = i;
        while (i < trimmed.len and !std.ascii.isWhitespace(trimmed[i])) : (i += 1) {}
        const agent_name = trimmed[agent_start..i];
        if (agent_name.len == 0) return null;

        while (i < trimmed.len and std.ascii.isWhitespace(trimmed[i])) : (i += 1) {}
        if (i >= trimmed.len) return null;

        const task = std.mem.trim(u8, trimmed[i..], " \t\r\n");
        if (task.len == 0) return null;
        return .{ .task = task, .agent_name = agent_name };
    }

    return .{ .task = trimmed };
}

test "parseSubagentSpawnRequest parses plain task" {
    const parsed = parseSubagentSpawnRequest("run quick check") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("run quick check", parsed.task);
    try std.testing.expect(parsed.agent_name == null);
}

test "parseSubagentSpawnRequest parses --agent form" {
    const parsed = parseSubagentSpawnRequest("--agent researcher gather references") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("researcher", parsed.agent_name.?);
    try std.testing.expectEqualStrings("gather references", parsed.task);
}

test "parseSubagentSpawnRequest parses --agent= form" {
    const parsed = parseSubagentSpawnRequest("--agent=researcher gather references") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("researcher", parsed.agent_name.?);
    try std.testing.expectEqualStrings("gather references", parsed.task);
}

test "parseSubagentSpawnRequest rejects invalid input" {
    try std.testing.expect(parseSubagentSpawnRequest("") == null);
    try std.testing.expect(parseSubagentSpawnRequest("--agent researcher") == null);
    try std.testing.expect(parseSubagentSpawnRequest("--agent=") == null);
}

test "parseSubagentSpawnRequest parses newline-separated agent and task" {
    const parsed = parseSubagentSpawnRequest("--agent researcher\ncheck logs") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("researcher", parsed.agent_name.?);
    try std.testing.expectEqualStrings("check logs", parsed.task);
}

fn testSubagentRunnerEcho(allocator: std.mem.Allocator, request: subagent_mod.TaskRunRequest) ![]const u8 {
    _ = request;
    return allocator.dupe(u8, "ok");
}

test "handleSubagentsCommand spawn with named agent reports profile usage" {
    const agents = [_]config_module.NamedAgentConfig{.{
        .name = "researcher",
        .provider = "openrouter",
        .model = "anthropic/claude-sonnet-4",
    }};
    const cfg = config_module.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
        .agents = &agents,
    };
    var manager = subagent_mod.SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    manager.task_runner = testSubagentRunnerEcho;
    defer manager.deinit();

    var spawn_tool = spawn_tool_mod.SpawnTool{ .manager = &manager };
    const tools = [_]Tool{spawn_tool.tool()};
    var harness = struct {
        allocator: std.mem.Allocator,
        tools: []const Tool,
        memory_session_id: ?[]const u8 = null,
    }{
        .allocator = std.testing.allocator,
        .tools = tools[0..],
    };

    const response = try handleSubagentsCommand(&harness, "spawn --agent researcher gather references");
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "Spawned subagent task #") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "using agent 'researcher'") != null);
}

test "handleSubagentsCommand spawn with unknown named agent reports clear error" {
    const cfg = config_module.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var manager = subagent_mod.SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer manager.deinit();

    var spawn_tool = spawn_tool_mod.SpawnTool{ .manager = &manager };
    const tools = [_]Tool{spawn_tool.tool()};
    var harness = struct {
        allocator: std.mem.Allocator,
        tools: []const Tool,
        memory_session_id: ?[]const u8 = null,
    }{
        .allocator = std.testing.allocator,
        .tools = tools[0..],
    };

    const response = try handleSubagentsCommand(&harness, "spawn --agent missing do task");
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "Unknown named agent profile: missing") != null);
}

test "handleSubagentsCommand spawn supports multiline task after --agent" {
    const agents = [_]config_module.NamedAgentConfig{.{
        .name = "researcher",
        .provider = "openrouter",
        .model = "anthropic/claude-sonnet-4",
    }};
    const cfg = config_module.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
        .agents = &agents,
    };
    var manager = subagent_mod.SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    manager.task_runner = testSubagentRunnerEcho;
    defer manager.deinit();

    var spawn_tool = spawn_tool_mod.SpawnTool{ .manager = &manager };
    const tools = [_]Tool{spawn_tool.tool()};
    var harness = struct {
        allocator: std.mem.Allocator,
        tools: []const Tool,
        memory_session_id: ?[]const u8 = null,
    }{
        .allocator = std.testing.allocator,
        .tools = tools[0..],
    };

    const response = try handleSubagentsCommand(&harness, "spawn --agent researcher\ncheck logs");
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "using agent 'researcher'") != null);
}

test "handleSubagentsCommand help documents both agent flag forms" {
    var harness = struct {
        allocator: std.mem.Allocator,
        tools: []const Tool,
        memory_session_id: ?[]const u8 = null,
    }{
        .allocator = std.testing.allocator,
        .tools = &.{},
    };

    const response = try handleSubagentsCommand(&harness, "help");
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "--agent <name>") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "--agent=<name>") != null);
}

test "refreshSubagentToolContext uses conversation origin route" {
    var spawn_tool = spawn_tool_mod.SpawnTool{};
    const tools = [_]Tool{spawn_tool.tool()};
    var harness = struct {
        allocator: std.mem.Allocator,
        tools: []const Tool,
        memory_session_id: ?[]const u8 = "agent:main:discord:direct:user-42",
        conversation_context: ?struct {
            channel: ?[]const u8 = null,
            account_id: ?[]const u8 = null,
            delivery_chat_id: ?[]const u8 = null,
            peer_id: ?[]const u8 = null,
        } = .{
            .channel = "discord",
            .account_id = "discord-main",
            .delivery_chat_id = "dm-channel-42",
            .peer_id = "user-42",
        },
    }{
        .allocator = std.testing.allocator,
        .tools = tools[0..],
    };

    refreshSubagentToolContext(&harness);

    try std.testing.expectEqualStrings("discord", spawn_tool.default_channel.?);
    try std.testing.expectEqualStrings("discord-main", spawn_tool.default_account_id.?);
    try std.testing.expectEqualStrings("dm-channel-42", spawn_tool.default_chat_id.?);
    try std.testing.expectEqualStrings("agent:main:discord:direct:user-42", spawn_tool.default_session_key.?);
}

test "handleSubagentsCommand spawn stores conversation origin route" {
    const cfg = config_module.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var manager = subagent_mod.SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    manager.task_runner = testSubagentRunnerEcho;
    defer manager.deinit();

    var spawn_tool = spawn_tool_mod.SpawnTool{ .manager = &manager };
    const tools = [_]Tool{spawn_tool.tool()};
    var harness = struct {
        allocator: std.mem.Allocator,
        tools: []const Tool,
        memory_session_id: ?[]const u8 = "agent:main:discord:direct:user-42",
        conversation_context: ?struct {
            channel: ?[]const u8 = null,
            account_id: ?[]const u8 = null,
            delivery_chat_id: ?[]const u8 = null,
            peer_id: ?[]const u8 = null,
        } = .{
            .channel = "discord",
            .account_id = "discord-main",
            .delivery_chat_id = "dm-channel-42",
            .peer_id = "user-42",
        },
    }{
        .allocator = std.testing.allocator,
        .tools = tools[0..],
    };

    // Regression: #849 also applies to slash-command subagent spawns, not only
    // LLM tool-call spawns.
    const response = try handleSubagentsCommand(&harness, "spawn check route");
    defer std.testing.allocator.free(response);

    manager.mutex.lock();
    defer manager.mutex.unlock();
    const state = manager.tasks.get(1) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("discord", state.origin_channel);
    try std.testing.expectEqualStrings("discord-main", state.origin_account_id.?);
    try std.testing.expectEqualStrings("dm-channel-42", state.origin_chat_id);
    try std.testing.expectEqualStrings("agent:main:discord:direct:user-42", state.session_key.?);
}

fn parseTaskId(raw: []const u8) ?u64 {
    if (raw.len == 0) return null;
    return std.fmt.parseInt(u64, raw, 10) catch null;
}

fn findSpawnTool(self: anytype) ?*spawn_tool_mod.SpawnTool {
    for (self.tools) |t| {
        if (!std.ascii.eqlIgnoreCase(t.name(), "spawn")) continue;
        return @ptrCast(@alignCast(t.ptr));
    }
    return null;
}

fn findSubagentManager(self: anytype) ?*subagent_mod.SubagentManager {
    const spawn_tool = findSpawnTool(self) orelse return null;
    return spawn_tool.manager;
}

const SubagentOriginRoute = struct {
    channel: []const u8,
    account_id: ?[]const u8,
    chat_id: []const u8,
    session_key: []const u8,
};

fn resolveSubagentOriginRoute(self: anytype) SubagentOriginRoute {
    var route_channel: []const u8 = "agent";
    var route_chat_id: []const u8 = self.memory_session_id orelse "agent";
    var route_account_id: ?[]const u8 = null;

    if (@hasField(@TypeOf(self.*), "conversation_context")) {
        if (self.conversation_context) |ctx| {
            if (ctx.channel) |channel| route_channel = channel;
            route_account_id = ctx.account_id;
            if (ctx.delivery_chat_id) |delivery_chat_id| {
                route_chat_id = delivery_chat_id;
            } else if (ctx.peer_id) |peer_id| {
                route_chat_id = peer_id;
            }
        }
    }

    return .{
        .channel = route_channel,
        .account_id = route_account_id,
        .chat_id = route_chat_id,
        .session_key = self.memory_session_id orelse route_chat_id,
    };
}

pub fn refreshSubagentToolContext(self: anytype) void {
    const spawn_tool = findSpawnTool(self) orelse return;
    const route = resolveSubagentOriginRoute(self);
    spawn_tool.default_channel = route.channel;
    spawn_tool.default_account_id = route.account_id;
    spawn_tool.default_chat_id = route.chat_id;
    spawn_tool.default_session_key = route.session_key;
}

fn findShellTool(self: anytype) ?Tool {
    for (self.tools) |t| {
        if (std.ascii.eqlIgnoreCase(t.name(), "shell")) return t;
    }
    return null;
}

fn clearSessionState(self: anytype) void {
    self.clearHistory();
    clearPendingExecCommand(self);
    clearActiveSkillSession(self);
    if (@hasField(@TypeOf(self.*), "total_tokens")) {
        self.total_tokens = 0;
    }
    if (@hasField(@TypeOf(self.*), "last_turn_usage")) {
        self.last_turn_usage = .{};
    }

    if (self.session_store) |store| {
        store.clearAutoSaved(self.memory_session_id) catch {};
    }
}

fn formatWhoAmI(self: anytype) ![]const u8 {
    const session_id = self.memory_session_id orelse "unknown";
    const profile_name = if (@hasField(@TypeOf(self.*), "profile_name"))
        self.profile_name orelse "default"
    else
        "default";
    return try std.fmt.allocPrint(
        self.allocator,
        "Session: {s}\nAgent profile: {s}\nModel: {s}",
        .{ session_id, profile_name, self.model_name },
    );
}

fn parseReasoningEffort(raw: []const u8) ?[]const u8 {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return "";
    if (std.ascii.eqlIgnoreCase(raw, "on")) return "medium";
    if (std.ascii.eqlIgnoreCase(raw, "minimal")) return "minimal";
    if (std.ascii.eqlIgnoreCase(raw, "low")) return "low";
    if (std.ascii.eqlIgnoreCase(raw, "medium")) return "medium";
    if (std.ascii.eqlIgnoreCase(raw, "high")) return "high";
    if (std.ascii.eqlIgnoreCase(raw, "xhigh")) return "xhigh";
    return null;
}

fn parseVerboseLevel(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "on")) return .on;
    if (std.ascii.eqlIgnoreCase(raw, "full")) return .full;
    return null;
}

fn parseReasoningMode(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "on")) return .on;
    if (std.ascii.eqlIgnoreCase(raw, "stream")) return .stream;
    return null;
}

fn parseUsageMode(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "tokens")) return .tokens;
    if (std.ascii.eqlIgnoreCase(raw, "full")) return .full;
    if (std.ascii.eqlIgnoreCase(raw, "cost")) return .cost;
    return null;
}

fn parseExecHost(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "sandbox")) return .sandbox;
    if (std.ascii.eqlIgnoreCase(raw, "gateway")) return .gateway;
    if (std.ascii.eqlIgnoreCase(raw, "node")) return .node;
    return null;
}

fn parseExecSecurity(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "deny")) return .deny;
    if (std.ascii.eqlIgnoreCase(raw, "allowlist")) return .allowlist;
    if (std.ascii.eqlIgnoreCase(raw, "full")) return .full;
    return null;
}

fn parseExecAsk(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "on-miss") or std.ascii.eqlIgnoreCase(raw, "on_miss")) return .on_miss;
    if (std.ascii.eqlIgnoreCase(raw, "always")) return .always;
    return null;
}

fn parseQueueMode(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "serial")) return .serial;
    if (std.ascii.eqlIgnoreCase(raw, "latest")) return .latest;
    if (std.ascii.eqlIgnoreCase(raw, "debounce")) return .debounce;
    return null;
}

fn parseQueueDrop(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "summarize")) return .summarize;
    if (std.ascii.eqlIgnoreCase(raw, "oldest")) return .oldest;
    if (std.ascii.eqlIgnoreCase(raw, "newest")) return .newest;
    return null;
}

fn parseTtsMode(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "always")) return .always;
    if (std.ascii.eqlIgnoreCase(raw, "inbound")) return .inbound;
    if (std.ascii.eqlIgnoreCase(raw, "tagged")) return .tagged;
    return null;
}

fn parseActivationMode(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "mention")) return .mention;
    if (std.ascii.eqlIgnoreCase(raw, "always")) return .always;
    return null;
}

fn parseSendMode(comptime T: type, raw: []const u8) ?T {
    if (std.ascii.eqlIgnoreCase(raw, "on")) return .on;
    if (std.ascii.eqlIgnoreCase(raw, "off")) return .off;
    if (std.ascii.eqlIgnoreCase(raw, "inherit")) return .inherit;
    return null;
}

fn parseDurationMs(raw: []const u8) ?u32 {
    if (raw.len == 0) return null;
    if (std.mem.endsWith(u8, raw, "ms")) {
        const base = raw[0 .. raw.len - 2];
        return std.fmt.parseInt(u32, base, 10) catch null;
    }
    if (std.mem.endsWith(u8, raw, "s")) {
        const base = raw[0 .. raw.len - 1];
        const seconds = std.fmt.parseInt(u32, base, 10) catch return null;
        return std.math.mul(u32, seconds, 1000) catch null;
    }
    if (std.mem.endsWith(u8, raw, "m")) {
        const base = raw[0 .. raw.len - 1];
        const minutes = std.fmt.parseInt(u32, base, 10) catch return null;
        return std.math.mul(u32, minutes, 60_000) catch null;
    }
    if (std.mem.endsWith(u8, raw, "h")) {
        const base = raw[0 .. raw.len - 1];
        const hours = std.fmt.parseInt(u32, base, 10) catch return null;
        return std.math.mul(u32, hours, 3_600_000) catch null;
    }
    return std.fmt.parseInt(u32, raw, 10) catch null;
}

fn parseDurationSeconds(raw: []const u8) ?u64 {
    const ms = parseDurationMs(raw) orelse return null;
    return @as(u64, @intCast(ms)) / 1000;
}

fn resetRuntimeCommandState(self: anytype) void {
    self.reasoning_effort = null;
    self.verbose_level = .off;
    self.reasoning_mode = .off;
    self.usage_mode = .off;
    self.exec_host = .gateway;
    self.exec_security = self.default_exec_security;
    self.exec_ask = self.default_exec_ask;
    if (self.exec_node_id_owned and self.exec_node_id != null) self.allocator.free(self.exec_node_id.?);
    self.exec_node_id = null;
    self.exec_node_id_owned = false;
    self.queue_mode = .off;
    self.queue_debounce_ms = 0;
    self.queue_cap = 0;
    self.queue_drop = .summarize;
    self.tts_mode = .off;
    if (self.tts_provider_owned and self.tts_provider != null) self.allocator.free(self.tts_provider.?);
    self.tts_provider = null;
    self.tts_provider_owned = false;
    self.tts_limit_chars = 0;
    self.tts_summary = false;
    self.tts_audio = false;
    clearPendingExecCommand(self);
    self.session_ttl_secs = null;
    if (self.focus_target_owned and self.focus_target != null) self.allocator.free(self.focus_target.?);
    self.focus_target = null;
    self.focus_target_owned = false;
    if (self.dock_target_owned and self.dock_target != null) self.allocator.free(self.dock_target.?);
    self.dock_target = null;
    self.dock_target_owned = false;
    self.activation_mode = .mention;
    self.send_mode = .inherit;
}

fn formatStatus(self: anytype) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const w = &out_writer.writer;

    const show_emojis = if (@hasField(@TypeOf(self.*), "status_show_emojis")) self.status_show_emojis else true;
    const title_prefix = if (show_emojis) "🌊 " else "";
    const model_label = if (show_emojis) "🧠 Model" else "Model";
    const history_label = if (show_emojis) "💬 History" else "History";
    const tokens_label = if (show_emojis) "🧮 Tokens used" else "Tokens used";
    const tools_label = if (show_emojis) "🔧 Tools" else "Tools";
    const thinking_label = if (show_emojis) "💭 Thinking" else "Thinking";
    const verbose_label = if (show_emojis) "📢 Verbose" else "Verbose";
    const reasoning_label = if (show_emojis) "🧩 Reasoning" else "Reasoning";
    const usage_label = if (show_emojis) "📈 Usage" else "Usage";
    const exec_label = if (show_emojis) "⚙️ Exec" else "Exec";
    const queue_label = if (show_emojis) "🪢 Queue" else "Queue";
    const tts_label = if (show_emojis) "🔊 TTS" else "TTS";
    const activation_label = if (show_emojis) "📡 Activation" else "Activation";
    const send_label = if (show_emojis) "📤 Send" else "Send";
    const ttl_label = if (show_emojis) "⏰ Session TTL" else "Session TTL";
    const tasks_label = if (show_emojis) "🧵 Tasks" else "Tasks";
    const skill_label = if (show_emojis) "🪄 Skill" else "Skill";

    try w.print("{s}NullClaw {s}\n", .{ title_prefix, version.string });
    if (@hasField(@TypeOf(self.*), "profile_name")) {
        try w.print("Agent profile: {s}\n", .{self.profile_name orelse "default"});
    }
    try w.print("{s}: {s}\n", .{ model_label, self.model_name });
    if (@hasField(@TypeOf(self.*), "active_skill_name") and self.active_skill_name != null) {
        try w.print(
            "{s}: {s} ({s})\n",
            .{ skill_label, self.active_skill_name.?, activeSkillModeLabel(self.active_skill_interactive) },
        );
    } else {
        try w.print("{s}: off\n", .{skill_label});
    }
    try w.print("{s}: {d} messages\n", .{ history_label, self.history.items.len });
    try w.print("{s}: {d}\n", .{ tokens_label, self.total_tokens });
    try w.print("{s}: {d} available\n", .{ tools_label, self.tools.len });
    try w.print("{s}: {s}\n", .{ thinking_label, self.reasoning_effort orelse "off" });
    try w.print("{s}: {s}\n", .{ verbose_label, self.verbose_level.toSlice() });
    try w.print("{s}: {s}\n", .{ reasoning_label, self.reasoning_mode.toSlice() });
    try w.print("{s}: {s}\n", .{ usage_label, self.usage_mode.toSlice() });
    try w.print(
        "{s}: host={s} security={s} ask={s}",
        .{ exec_label, self.exec_host.toSlice(), self.exec_security.toSlice(), self.exec_ask.toSlice() },
    );
    if (self.exec_node_id) |id| try w.print(" node={s}", .{id});
    try w.writeAll("\n");
    try w.print(
        "{s}: mode={s} debounce={d}ms cap={d} drop={s}\n",
        .{ queue_label, self.queue_mode.toSlice(), self.queue_debounce_ms, self.queue_cap, self.queue_drop.toSlice() },
    );
    try w.print("{s}: mode={s} provider={s}\n", .{ tts_label, self.tts_mode.toSlice(), self.tts_provider orelse "default" });
    try w.print("{s}: {s}\n", .{ activation_label, self.activation_mode.toSlice() });
    try w.print("{s}: {s}\n", .{ send_label, self.send_mode.toSlice() });
    if (self.session_ttl_secs) |ttl| {
        try w.print("{s}: {d}s\n", .{ ttl_label, ttl });
    } else {
        try w.print("{s}: off\n", .{ttl_label});
    }
    if (findSubagentManager(self)) |manager| {
        manager.mutex.lock();
        defer manager.mutex.unlock();

        var running: u32 = 0;
        var completed: u32 = 0;
        var failed: u32 = 0;
        var visible: u32 = 0;

        var it = manager.tasks.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr.*;
            if (!taskBelongsToCurrentSession(self, state)) continue;
            visible += 1;
            switch (state.status) {
                .running => running += 1,
                .completed => completed += 1,
                .failed => failed += 1,
            }
        }

        if (visible > 0) {
            try w.print(
                "{s}: running={d} completed={d} failed={d}\n",
                .{ tasks_label, running, completed, failed },
            );
        }
    }
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn handleThinkCommand(self: anytype, arg: []const u8) ![]const u8 {
    const level = firstToken(arg);
    if (level.len == 0 or std.ascii.eqlIgnoreCase(level, "status")) {
        return try std.fmt.allocPrint(self.allocator, "Thinking: {s}", .{self.reasoning_effort orelse "off"});
    }

    const parsed = parseReasoningEffort(level) orelse
        return try self.allocator.dupe(u8, "Invalid /think value. Use: off|minimal|low|medium|high|xhigh");

    self.reasoning_effort = if (parsed.len == 0) null else parsed;
    return try std.fmt.allocPrint(self.allocator, "Thinking set to: {s}", .{self.reasoning_effort orelse "off"});
}

fn handleVerboseCommand(self: anytype, arg: []const u8) ![]const u8 {
    const level = firstToken(arg);
    if (level.len == 0 or std.ascii.eqlIgnoreCase(level, "status")) {
        return try std.fmt.allocPrint(self.allocator, "Verbose: {s}", .{self.verbose_level.toSlice()});
    }

    const parsed = parseVerboseLevel(@TypeOf(self.verbose_level), level) orelse
        return try self.allocator.dupe(u8, "Invalid /verbose value. Use: on|full|off");
    self.verbose_level = parsed;
    return try std.fmt.allocPrint(self.allocator, "Verbose set to: {s}", .{self.verbose_level.toSlice()});
}

fn handleReasoningCommand(self: anytype, arg: []const u8) ![]const u8 {
    const mode = firstToken(arg);
    if (mode.len == 0 or std.ascii.eqlIgnoreCase(mode, "status")) {
        return try std.fmt.allocPrint(self.allocator, "Reasoning output: {s}", .{self.reasoning_mode.toSlice()});
    }

    const parsed = parseReasoningMode(@TypeOf(self.reasoning_mode), mode) orelse
        return try self.allocator.dupe(u8, "Invalid /reasoning value. Use: on|off|stream");
    self.reasoning_mode = parsed;
    return try std.fmt.allocPrint(self.allocator, "Reasoning output set to: {s}", .{self.reasoning_mode.toSlice()});
}

fn handleExecCommand(self: anytype, arg: []const u8) ![]const u8 {
    if (arg.len == 0 or std.ascii.eqlIgnoreCase(arg, "status")) {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
        const w = &out_writer.writer;
        try w.print(
            "Exec: host={s} security={s} ask={s}",
            .{ self.exec_host.toSlice(), self.exec_security.toSlice(), self.exec_ask.toSlice() },
        );
        if (self.exec_node_id) |id| {
            try w.print(" node={s}", .{id});
        }
        out = out_writer.toArrayList();
        return try out.toOwnedSlice(self.allocator);
    }

    var it = std.mem.tokenizeAny(u8, arg, " \t");
    while (it.next()) |tok| {
        const eq = std.mem.indexOfScalar(u8, tok, '=') orelse
            return try self.allocator.dupe(u8, "Invalid /exec argument. Use host=<...> security=<...> ask=<...> node=<id>");
        const key = tok[0..eq];
        const value = tok[eq + 1 ..];
        if (value.len == 0) {
            return try self.allocator.dupe(u8, "Invalid /exec argument: empty value");
        }
        if (std.ascii.eqlIgnoreCase(key, "host")) {
            self.exec_host = parseExecHost(@TypeOf(self.exec_host), value) orelse
                return try self.allocator.dupe(u8, "Invalid host. Use: sandbox|gateway|node");
        } else if (std.ascii.eqlIgnoreCase(key, "security")) {
            self.exec_security = parseExecSecurity(@TypeOf(self.exec_security), value) orelse
                return try self.allocator.dupe(u8, "Invalid security. Use: deny|allowlist|full");
        } else if (std.ascii.eqlIgnoreCase(key, "ask")) {
            self.exec_ask = parseExecAsk(@TypeOf(self.exec_ask), value) orelse
                return try self.allocator.dupe(u8, "Invalid ask. Use: off|on-miss|always");
        } else if (std.ascii.eqlIgnoreCase(key, "node")) {
            try setExecNodeId(self, value);
        } else {
            return try std.fmt.allocPrint(self.allocator, "Unknown /exec key: {s}", .{key});
        }
    }

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const w = &out_writer.writer;
    try w.print(
        "Exec set: host={s} security={s} ask={s}",
        .{ self.exec_host.toSlice(), self.exec_security.toSlice(), self.exec_ask.toSlice() },
    );
    if (self.exec_node_id) |id| {
        try w.print(" node={s}", .{id});
    }
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn handleQueueCommand(self: anytype, arg: []const u8) ![]const u8 {
    if (arg.len == 0 or std.ascii.eqlIgnoreCase(arg, "status")) {
        return try std.fmt.allocPrint(
            self.allocator,
            "Queue: mode={s} debounce={d}ms cap={d} drop={s}",
            .{ self.queue_mode.toSlice(), self.queue_debounce_ms, self.queue_cap, self.queue_drop.toSlice() },
        );
    }

    if (std.ascii.eqlIgnoreCase(arg, "reset")) {
        self.queue_mode = .off;
        self.queue_debounce_ms = 0;
        self.queue_cap = 0;
        self.queue_drop = .summarize;
        return try self.allocator.dupe(u8, "Queue settings reset.");
    }

    var it = std.mem.tokenizeAny(u8, arg, " \t");
    while (it.next()) |tok| {
        if (parseQueueMode(@TypeOf(self.queue_mode), tok)) |mode| {
            self.queue_mode = mode;
            continue;
        }

        const sep = std.mem.indexOfScalar(u8, tok, ':') orelse
            return try self.allocator.dupe(u8, "Invalid /queue argument. Use mode plus debounce:<dur> cap:<n> drop:<summarize|oldest|newest>");
        const key = tok[0..sep];
        const value = tok[sep + 1 ..];

        if (std.ascii.eqlIgnoreCase(key, "debounce")) {
            self.queue_debounce_ms = parseDurationMs(value) orelse
                return try self.allocator.dupe(u8, "Invalid debounce duration");
            continue;
        }
        if (std.ascii.eqlIgnoreCase(key, "cap")) {
            self.queue_cap = std.fmt.parseInt(u32, value, 10) catch
                return try self.allocator.dupe(u8, "Invalid queue cap");
            continue;
        }
        if (std.ascii.eqlIgnoreCase(key, "drop")) {
            self.queue_drop = parseQueueDrop(@TypeOf(self.queue_drop), value) orelse
                return try self.allocator.dupe(u8, "Invalid drop mode");
            continue;
        }

        return try std.fmt.allocPrint(self.allocator, "Unknown /queue option: {s}", .{key});
    }

    return try std.fmt.allocPrint(
        self.allocator,
        "Queue set: mode={s} debounce={d}ms cap={d} drop={s}",
        .{ self.queue_mode.toSlice(), self.queue_debounce_ms, self.queue_cap, self.queue_drop.toSlice() },
    );
}

fn handleUsageCommand(self: anytype, arg: []const u8) ![]const u8 {
    const mode = firstToken(arg);
    if (mode.len == 0 or std.ascii.eqlIgnoreCase(mode, "status")) {
        const turn_cost = @import("../cost.zig").TokenUsage.fromProviders(self.model_name, self.last_turn_usage).cost();
        return try std.fmt.allocPrint(
            self.allocator,
            "Usage: {s}\nLast turn: prompt={d} completion={d} total={d} (${d:.4})\nSession total: {d} tokens, ${d:.4} total",
            .{
                self.usage_mode.toSlice(),
                self.last_turn_usage.prompt_tokens,
                self.last_turn_usage.completion_tokens,
                self.last_turn_usage.total_tokens,
                turn_cost,
                self.total_tokens,
                self.total_cost_usd,
            },
        );
    }

    self.usage_mode = parseUsageMode(@TypeOf(self.usage_mode), mode) orelse
        return try self.allocator.dupe(u8, "Invalid /usage value. Use: off|tokens|full|cost");
    return try std.fmt.allocPrint(self.allocator, "Usage mode set to: {s}", .{self.usage_mode.toSlice()});
}

fn handleToggleCostCommand(self: anytype, arg: []const u8) ![]const u8 {
    if (arg.len > 0) {
        // If argument is provided, behave like /usage
        return try handleUsageCommand(self, arg);
    }

    // Toggle logic: off -> full, anything else -> off
    const new_mode: @TypeOf(self.usage_mode) = if (self.usage_mode == .off) .full else .off;
    self.usage_mode = new_mode;

    return try std.fmt.allocPrint(
        self.allocator,
        "Cost display {s}.",
        .{if (new_mode == .off) "disabled" else "enabled"},
    );
}

fn handleTtsCommand(self: anytype, arg: []const u8) ![]const u8 {
    if (arg.len == 0 or std.ascii.eqlIgnoreCase(arg, "status")) {
        return try std.fmt.allocPrint(
            self.allocator,
            "TTS: mode={s} provider={s} limit={d} summary={s} audio={s}",
            .{
                self.tts_mode.toSlice(),
                self.tts_provider orelse "default",
                self.tts_limit_chars,
                if (self.tts_summary) "on" else "off",
                if (self.tts_audio) "on" else "off",
            },
        );
    }

    var it = std.mem.tokenizeAny(u8, arg, " \t");
    while (it.next()) |tok| {
        if (parseTtsMode(@TypeOf(self.tts_mode), tok)) |mode| {
            self.tts_mode = mode;
            continue;
        }
        if (std.ascii.eqlIgnoreCase(tok, "status")) continue;

        if (std.mem.startsWith(u8, tok, "provider=")) {
            const value = tok["provider=".len..];
            if (value.len == 0) return try self.allocator.dupe(u8, "Invalid provider value");
            try setTtsProvider(self, value);
            continue;
        }
        if (std.ascii.eqlIgnoreCase(tok, "provider")) {
            const value = it.next() orelse return try self.allocator.dupe(u8, "Missing provider value");
            try setTtsProvider(self, value);
            continue;
        }

        if (std.mem.startsWith(u8, tok, "limit=")) {
            const value = tok["limit=".len..];
            self.tts_limit_chars = std.fmt.parseInt(u32, value, 10) catch
                return try self.allocator.dupe(u8, "Invalid TTS limit");
            continue;
        }
        if (std.ascii.eqlIgnoreCase(tok, "limit")) {
            const value = it.next() orelse return try self.allocator.dupe(u8, "Missing limit value");
            self.tts_limit_chars = std.fmt.parseInt(u32, value, 10) catch
                return try self.allocator.dupe(u8, "Invalid TTS limit");
            continue;
        }

        if (std.ascii.eqlIgnoreCase(tok, "summary")) {
            const value = it.next() orelse return try self.allocator.dupe(u8, "Missing summary value");
            if (std.ascii.eqlIgnoreCase(value, "on")) {
                self.tts_summary = true;
            } else if (std.ascii.eqlIgnoreCase(value, "off")) {
                self.tts_summary = false;
            } else {
                return try self.allocator.dupe(u8, "Invalid summary value. Use on|off");
            }
            continue;
        }

        if (std.ascii.eqlIgnoreCase(tok, "audio")) {
            const value = it.next() orelse return try self.allocator.dupe(u8, "Missing audio value");
            if (std.ascii.eqlIgnoreCase(value, "on")) {
                self.tts_audio = true;
            } else if (std.ascii.eqlIgnoreCase(value, "off")) {
                self.tts_audio = false;
            } else {
                return try self.allocator.dupe(u8, "Invalid audio value. Use on|off");
            }
            continue;
        }

        return try std.fmt.allocPrint(self.allocator, "Unknown /tts option: {s}", .{tok});
    }

    return try std.fmt.allocPrint(
        self.allocator,
        "TTS set: mode={s} provider={s} limit={d} summary={s} audio={s}",
        .{
            self.tts_mode.toSlice(),
            self.tts_provider orelse "default",
            self.tts_limit_chars,
            if (self.tts_summary) "on" else "off",
            if (self.tts_audio) "on" else "off",
        },
    );
}

fn handleAllowlistCommand(self: anytype, arg: []const u8) ![]const u8 {
    _ = arg;
    if (self.policy) |pol| {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
        const w = &out_writer.writer;
        try w.writeAll("Allowlisted commands:\n");
        for (pol.allowed_commands) |cmd| {
            try w.print("  - {s}\n", .{cmd});
        }
        out = out_writer.toArrayList();
        return try out.toOwnedSlice(self.allocator);
    }
    return try self.allocator.dupe(u8, "No runtime allowlist policy attached.");
}

fn handleContextCommand(self: anytype, arg: []const u8) ![]const u8 {
    const mode = firstToken(arg);
    if (std.ascii.eqlIgnoreCase(mode, "json")) {
        return try std.fmt.allocPrint(
            self.allocator,
            "{{\"model\":\"{s}\",\"history_messages\":{d},\"token_estimate\":{d},\"tools\":{d}}}",
            .{ self.model_name, self.history.items.len, self.tokenEstimate(), self.tools.len },
        );
    }

    if (std.ascii.eqlIgnoreCase(mode, "detail")) {
        var sys: usize = 0;
        var usr: usize = 0;
        var asst: usize = 0;
        var tool: usize = 0;
        for (self.history.items) |entry| {
            switch (entry.role) {
                .system => sys += 1,
                .user => usr += 1,
                .assistant => asst += 1,
                .tool => tool += 1,
            }
        }
        return try std.fmt.allocPrint(
            self.allocator,
            "Context detail:\n  model: {s}\n  messages: {d}\n  token_estimate: {d}\n  tools: {d}\n  by_role: system={d} user={d} assistant={d} tool={d}",
            .{ self.model_name, self.history.items.len, self.tokenEstimate(), self.tools.len, sys, usr, asst, tool },
        );
    }

    return try std.fmt.allocPrint(
        self.allocator,
        "Context: messages={d}, token_estimate={d}, tools={d}",
        .{ self.history.items.len, self.tokenEstimate(), self.tools.len },
    );
}

fn handleExportSessionCommand(self: anytype, arg: []const u8) ![]const u8 {
    const raw_path = firstToken(arg);
    const path = if (raw_path.len == 0)
        try std.fmt.allocPrint(self.allocator, "{s}/session-{d}.md", .{ self.workspace_dir, std_compat.time.timestamp() })
    else if (std_compat.fs.path.isAbsolute(raw_path))
        try self.allocator.dupe(u8, raw_path)
    else
        try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.workspace_dir, raw_path });
    defer self.allocator.free(path);

    const file = if (std_compat.fs.path.isAbsolute(path))
        try std_compat.fs.createFileAbsolute(path, .{ .truncate = true, .read = false })
    else
        try std_compat.fs.cwd().createFile(path, .{ .truncate = true, .read = false });
    defer file.close();
    var out_buf: [4096]u8 = undefined;
    var bw = file.writer(&out_buf);
    const w = &bw.interface;
    try w.print("# Session export\n\nModel: `{s}`\n\n", .{self.model_name});
    for (self.history.items) |entry| {
        const role = switch (entry.role) {
            .system => "system",
            .user => "user",
            .assistant => "assistant",
            .tool => "tool",
        };
        try w.print("## {s}\n\n{s}\n\n", .{ role, entry.content });
    }
    try w.flush();

    return try std.fmt.allocPrint(self.allocator, "Session exported to: {s}", .{path});
}

fn handleSessionCommand(self: anytype, arg: []const u8) ![]const u8 {
    var it = std.mem.tokenizeAny(u8, arg, " \t");
    const sub = it.next() orelse return try std.fmt.allocPrint(self.allocator, "Session TTL: {s}", .{if (self.session_ttl_secs) |_| "set" else "off"});
    if (std.ascii.eqlIgnoreCase(sub, "ttl")) {
        const ttl = it.next() orelse {
            if (self.session_ttl_secs) |v| {
                return try std.fmt.allocPrint(self.allocator, "Session TTL: {d}s", .{v});
            }
            return try self.allocator.dupe(u8, "Session TTL: off");
        };
        if (std.ascii.eqlIgnoreCase(ttl, "off")) {
            self.session_ttl_secs = null;
            return try self.allocator.dupe(u8, "Session TTL disabled.");
        }
        self.session_ttl_secs = parseDurationSeconds(ttl) orelse
            return try self.allocator.dupe(u8, "Invalid TTL duration.");
        return try std.fmt.allocPrint(self.allocator, "Session TTL set to {d}s.", .{self.session_ttl_secs.?});
    }
    return try self.allocator.dupe(u8, "Unknown /session command. Use: /session ttl <duration|off>");
}

fn handleFocusCommand(self: anytype, arg: []const u8) ![]const u8 {
    const target = std.mem.trim(u8, arg, " \t");
    if (target.len == 0) {
        return try self.allocator.dupe(u8, "Missing focus target.");
    }
    try setFocusTarget(self, target);
    return try std.fmt.allocPrint(self.allocator, "Focused on: {s}", .{target});
}

fn handleUnfocusCommand(self: anytype) ![]const u8 {
    try setFocusTarget(self, null);
    return try self.allocator.dupe(u8, "Focus cleared.");
}

fn handleDockCommand(self: anytype, channel: []const u8) ![]const u8 {
    try setDockTarget(self, channel);
    return try std.fmt.allocPrint(self.allocator, "Dock target set to: {s}", .{channel});
}

fn handleActivationCommand(self: anytype, arg: []const u8) ![]const u8 {
    const mode = firstToken(arg);
    if (mode.len == 0 or std.ascii.eqlIgnoreCase(mode, "status")) {
        return try std.fmt.allocPrint(self.allocator, "Activation mode: {s}", .{self.activation_mode.toSlice()});
    }
    self.activation_mode = parseActivationMode(@TypeOf(self.activation_mode), mode) orelse
        return try self.allocator.dupe(u8, "Invalid activation mode. Use: mention|always");
    return try std.fmt.allocPrint(self.allocator, "Activation mode set to: {s}", .{self.activation_mode.toSlice()});
}

fn handleSendCommand(self: anytype, arg: []const u8) ![]const u8 {
    const mode = firstToken(arg);
    if (mode.len == 0 or std.ascii.eqlIgnoreCase(mode, "status")) {
        return try std.fmt.allocPrint(self.allocator, "Send mode: {s}", .{self.send_mode.toSlice()});
    }
    self.send_mode = parseSendMode(@TypeOf(self.send_mode), mode) orelse
        return try self.allocator.dupe(u8, "Invalid send mode. Use: on|off|inherit");
    return try std.fmt.allocPrint(self.allocator, "Send mode set to: {s}", .{self.send_mode.toSlice()});
}

fn handleElevatedCommand(self: anytype, arg: []const u8) ![]const u8 {
    const mode = firstToken(arg);
    if (mode.len == 0 or std.ascii.eqlIgnoreCase(mode, "status")) {
        return try std.fmt.allocPrint(
            self.allocator,
            "Elevated policy: security={s} ask={s}",
            .{ self.exec_security.toSlice(), self.exec_ask.toSlice() },
        );
    }

    if (std.ascii.eqlIgnoreCase(mode, "full")) {
        self.exec_security = .full;
        self.exec_ask = .off;
    } else if (std.ascii.eqlIgnoreCase(mode, "ask")) {
        self.exec_security = .allowlist;
        self.exec_ask = .on_miss;
    } else if (std.ascii.eqlIgnoreCase(mode, "on")) {
        self.exec_security = .allowlist;
        self.exec_ask = .on_miss;
    } else if (std.ascii.eqlIgnoreCase(mode, "off")) {
        self.exec_security = .deny;
        self.exec_ask = .off;
    } else {
        return try self.allocator.dupe(u8, "Invalid /elevated value. Use: on|off|ask|full");
    }

    return try std.fmt.allocPrint(
        self.allocator,
        "Elevated policy set: security={s} ask={s}",
        .{ self.exec_security.toSlice(), self.exec_ask.toSlice() },
    );
}

fn parseApproveDecision(raw: []const u8) ?enum { allow_once, allow_always, deny } {
    if (std.ascii.eqlIgnoreCase(raw, "allow") or
        std.ascii.eqlIgnoreCase(raw, "once") or
        std.ascii.eqlIgnoreCase(raw, "allow-once") or
        std.ascii.eqlIgnoreCase(raw, "allowonce"))
    {
        return .allow_once;
    }
    if (std.ascii.eqlIgnoreCase(raw, "always") or
        std.ascii.eqlIgnoreCase(raw, "allow-always") or
        std.ascii.eqlIgnoreCase(raw, "allowalways"))
    {
        return .allow_always;
    }
    if (std.ascii.eqlIgnoreCase(raw, "deny") or
        std.ascii.eqlIgnoreCase(raw, "reject") or
        std.ascii.eqlIgnoreCase(raw, "block"))
    {
        return .deny;
    }
    return null;
}

fn runShellCommand(self: anytype, command: []const u8, skip_approval_gate: bool) ![]const u8 {
    if (self.exec_host == .node) {
        return try self.allocator.dupe(u8, "Exec blocked: host=node is not available in this runtime");
    }
    if (self.exec_security == .deny) {
        return try self.allocator.dupe(u8, "Exec blocked by /exec security=deny");
    }
    if (!skip_approval_gate and self.exec_ask == .always) {
        try setPendingExecCommand(self, command);
        return try std.fmt.allocPrint(
            self.allocator,
            "Exec approval required (id={d}). Use /approve {d} allow-once|allow-always|deny",
            .{ self.pending_exec_id, self.pending_exec_id },
        );
    }
    if (self.exec_security == .allowlist) {
        if (self.policy) |pol| {
            if (!pol.isCommandAllowed(command)) {
                const summary = command_summary.summarizeBlockedCommand(command);
                log.warn("exec blocked by allowlist policy: head={s} bytes={d} assignments={d}", .{
                    summary.head,
                    summary.byte_len,
                    summary.assignment_count,
                });
                return try self.allocator.dupe(u8, "Exec blocked by allowlist policy");
            }
        }
    }

    const shell_tool = findShellTool(self) orelse
        return try self.allocator.dupe(u8, "Shell tool is not enabled.");

    var arena_impl = std.heap.ArenaAllocator.init(self.allocator);
    defer arena_impl.deinit();
    const arena = arena_impl.allocator();

    var args: std.json.ObjectMap = .empty;
    try args.put(arena, "command", .{ .string = command });

    const result = shell_tool.execute(arena, args) catch |err| {
        return try std.fmt.allocPrint(self.allocator, "Bash failed: {s}", .{@errorName(err)});
    };

    const text = if (result.success) result.output else (result.error_msg orelse result.output);
    return try self.allocator.dupe(u8, text);
}

fn handleApproveCommand(self: anytype, arg: []const u8) ![]const u8 {
    const pending_command = self.pending_exec_command orelse
        return try self.allocator.dupe(u8, "No pending approval requests.");

    const trimmed = std.mem.trim(u8, arg, " \t");
    if (trimmed.len == 0) {
        return try std.fmt.allocPrint(
            self.allocator,
            "Pending approval id={d} for command: {s}\nUse /approve {d} allow-once|allow-always|deny",
            .{ self.pending_exec_id, pending_command, self.pending_exec_id },
        );
    }

    var requested_id: ?u64 = null;
    var decision_token: []const u8 = firstToken(trimmed);

    const first = splitFirstToken(trimmed);
    if (parseTaskId(first.head)) |id| {
        requested_id = id;
        decision_token = firstToken(first.tail);
    }

    const decision = parseApproveDecision(decision_token) orelse
        return try self.allocator.dupe(u8, "Usage: /approve <id?> allow-once|allow-always|deny");

    if (requested_id) |id| {
        if (id != self.pending_exec_id) {
            return try std.fmt.allocPrint(
                self.allocator,
                "Approval id mismatch. Pending id is {d}.",
                .{self.pending_exec_id},
            );
        }
    }

    if (decision == .deny) {
        clearPendingExecCommand(self);
        return try self.allocator.dupe(u8, "Exec request denied.");
    }

    const command_to_run = pending_command;
    defer clearPendingExecCommand(self);

    if (decision == .allow_always) {
        self.exec_ask = .off;
    }

    const output = try runShellCommand(self, command_to_run, true);
    defer self.allocator.free(output);
    return try std.fmt.allocPrint(
        self.allocator,
        "Approved exec (id={d}).\n{s}",
        .{ self.pending_exec_id, output },
    );
}

fn taskStatusLabel(status: subagent_mod.TaskStatus) []const u8 {
    return switch (status) {
        .running => "running",
        .completed => "completed",
        .failed => "failed",
    };
}

fn currentSubagentSessionKey(self: anytype) []const u8 {
    return self.memory_session_id orelse "agent";
}

fn taskBelongsToCurrentSession(self: anytype, state: *const subagent_mod.TaskState) bool {
    const task_session = state.session_key orelse return false;
    return std.mem.eql(u8, task_session, currentSubagentSessionKey(self));
}

fn freeSubagentTaskState(manager: *subagent_mod.SubagentManager, state: *subagent_mod.TaskState) void {
    if (state.thread) |thread| {
        thread.join();
    }
    if (state.result) |r| manager.allocator.free(r);
    if (state.error_msg) |e| manager.allocator.free(e);
    manager.allocator.free(state.origin_channel);
    manager.allocator.free(state.origin_chat_id);
    if (state.origin_account_id) |aid| manager.allocator.free(aid);
    if (state.session_key) |sk| manager.allocator.free(sk);
    manager.allocator.free(state.label);
    manager.allocator.destroy(state);
}

fn formatSubagentList(self: anytype, include_details: bool) ![]const u8 {
    const manager = findSubagentManager(self) orelse
        return try self.allocator.dupe(u8, "Subagent manager is not enabled.");

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const w = &out_writer.writer;

    manager.mutex.lock();
    defer manager.mutex.unlock();

    var running: u32 = 0;
    var completed: u32 = 0;
    var failed: u32 = 0;
    var visible_count: u32 = 0;

    var it = manager.tasks.iterator();
    while (it.next()) |entry| {
        const task_id = entry.key_ptr.*;
        const state = entry.value_ptr.*;
        if (!taskBelongsToCurrentSession(self, state)) continue;
        visible_count += 1;
        switch (state.status) {
            .running => running += 1,
            .completed => completed += 1,
            .failed => failed += 1,
        }

        try w.print("#{d} {s} [{s}]", .{ task_id, state.label, taskStatusLabel(state.status) });
        if (include_details and state.status == .failed and state.error_msg != null) {
            try w.print(" error={s}", .{state.error_msg.?});
        }
        try w.writeAll("\n");
    }

    if (visible_count == 0) {
        try w.writeAll("No subagents tracked in this session.");
        out = out_writer.toArrayList();
        return try out.toOwnedSlice(self.allocator);
    }

    try w.print("Totals: running={d}, completed={d}, failed={d}", .{ running, completed, failed });
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn spawnSubagentTask(self: anytype, task: []const u8, label: []const u8, agent_name: ?[]const u8) ![]const u8 {
    const trimmed_task = std.mem.trim(u8, task, " \t");
    if (trimmed_task.len == 0) {
        return try self.allocator.dupe(u8, SUBAGENTS_SPAWN_USAGE);
    }

    const manager = findSubagentManager(self) orelse
        return try self.allocator.dupe(u8, "Spawn tool is not enabled.");

    const route = resolveSubagentOriginRoute(self);
    const task_id = manager.spawnWithAgent(trimmed_task, label, route.channel, route.chat_id, route.account_id, route.session_key, agent_name) catch |err| {
        return switch (err) {
            error.TooManyConcurrentSubagents => try self.allocator.dupe(u8, "Too many concurrent subagents. Wait for a task to finish."),
            error.UnknownAgent => if (agent_name) |name|
                try std.fmt.allocPrint(self.allocator, "Unknown named agent profile: {s}", .{name})
            else
                try self.allocator.dupe(u8, "Unknown named agent profile"),
            else => try std.fmt.allocPrint(self.allocator, "Failed to spawn subagent: {s}", .{@errorName(err)}),
        };
    };

    if (agent_name) |name| {
        return try std.fmt.allocPrint(
            self.allocator,
            "Spawned subagent task #{d} ({s}) using agent '{s}'.",
            .{ task_id, label, name },
        );
    }

    return try std.fmt.allocPrint(
        self.allocator,
        "Spawned subagent task #{d} ({s}).",
        .{ task_id, label },
    );
}

fn handleAgentsCommand(self: anytype) ![]const u8 {
    const manager = findSubagentManager(self) orelse
        return try self.allocator.dupe(u8, "Active agents: 1 (current session). Subagents are not enabled.");

    manager.mutex.lock();
    defer manager.mutex.unlock();
    var tracked: u32 = 0;
    var running: u32 = 0;

    var it = manager.tasks.iterator();
    while (it.next()) |entry| {
        const state = entry.value_ptr.*;
        if (!taskBelongsToCurrentSession(self, state)) continue;
        tracked += 1;
        if (state.status == .running) running += 1;
    }

    return try std.fmt.allocPrint(
        self.allocator,
        "Active agents: 1 main + {d} running subagents ({d} tracked tasks).",
        .{ running, tracked },
    );
}

fn handleKillCommand(self: anytype, arg: []const u8) ![]const u8 {
    const manager = findSubagentManager(self) orelse
        return try self.allocator.dupe(u8, "Subagent manager is not enabled.");

    const target = firstToken(arg);
    if (target.len == 0) {
        return try self.allocator.dupe(u8, "Usage: /kill <id|all>");
    }

    if (std.ascii.eqlIgnoreCase(target, "all")) {
        var ids: std.ArrayListUnmanaged(u64) = .empty;
        defer ids.deinit(self.allocator);

        manager.mutex.lock();
        defer manager.mutex.unlock();

        var running: u32 = 0;
        var it = manager.tasks.iterator();
        while (it.next()) |entry| {
            const task_id = entry.key_ptr.*;
            const state = entry.value_ptr.*;
            if (!taskBelongsToCurrentSession(self, state)) continue;
            if (state.status == .running) {
                running += 1;
            } else {
                try ids.append(self.allocator, task_id);
            }
        }

        var removed: u32 = 0;
        for (ids.items) |task_id| {
            if (manager.tasks.fetchRemove(task_id)) |kv| {
                freeSubagentTaskState(manager, kv.value);
                removed += 1;
            }
        }

        if (running > 0) {
            return try std.fmt.allocPrint(
                self.allocator,
                "Removed {d} completed tasks; {d} running tasks cannot be interrupted in this runtime.",
                .{ removed, running },
            );
        }
        return try std.fmt.allocPrint(self.allocator, "Removed {d} completed tasks.", .{removed});
    }

    const task_id = parseTaskId(target) orelse
        return try self.allocator.dupe(u8, "Usage: /kill <id|all>");

    manager.mutex.lock();
    defer manager.mutex.unlock();

    const state = manager.tasks.get(task_id) orelse
        return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
    if (!taskBelongsToCurrentSession(self, state)) {
        return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
    }
    if (state.status == .running) {
        return try std.fmt.allocPrint(
            self.allocator,
            "Task #{d} is running and cannot be interrupted in this runtime.",
            .{task_id},
        );
    }

    if (manager.tasks.fetchRemove(task_id)) |kv| {
        freeSubagentTaskState(manager, kv.value);
        return try std.fmt.allocPrint(self.allocator, "Task #{d} removed.", .{task_id});
    }
    return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
}

fn handleSubagentsCommand(self: anytype, arg: []const u8) ![]const u8 {
    const parsed = splitFirstToken(arg);
    const action = parsed.head;

    if (action.len == 0 or std.ascii.eqlIgnoreCase(action, "list") or std.ascii.eqlIgnoreCase(action, "status")) {
        return try formatSubagentList(self, false);
    }
    if (std.ascii.eqlIgnoreCase(action, "help")) {
        return try self.allocator.dupe(u8,
            \\Usage:
            \\  /subagents
            \\  /subagents list
            \\  /subagents spawn [--agent <name>|--agent=<name>] <task>
            \\  /subagents info <id>
            \\  /subagents kill <id|all>
        );
    }
    if (std.ascii.eqlIgnoreCase(action, "spawn")) {
        const spawn_req = parseSubagentSpawnRequest(parsed.tail) orelse
            return try self.allocator.dupe(u8, SUBAGENTS_SPAWN_USAGE);
        return try spawnSubagentTask(self, spawn_req.task, "subagent", spawn_req.agent_name);
    }
    if (std.ascii.eqlIgnoreCase(action, "info")) {
        const id_text = firstToken(parsed.tail);
        const task_id = parseTaskId(id_text) orelse
            return try self.allocator.dupe(u8, "Usage: /subagents info <id>");

        const manager = findSubagentManager(self) orelse
            return try self.allocator.dupe(u8, "Subagent manager is not enabled.");
        manager.mutex.lock();
        defer manager.mutex.unlock();

        const state = manager.tasks.get(task_id) orelse
            return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
        if (!taskBelongsToCurrentSession(self, state)) {
            return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
        }

        if (state.status == .running) {
            return try std.fmt.allocPrint(
                self.allocator,
                "Task #{d}: {s} [{s}]",
                .{ task_id, state.label, taskStatusLabel(state.status) },
            );
        }
        if (state.error_msg) |err_msg| {
            return try std.fmt.allocPrint(
                self.allocator,
                "Task #{d}: {s} [{s}]\nError: {s}",
                .{ task_id, state.label, taskStatusLabel(state.status), err_msg },
            );
        }
        if (state.result) |result| {
            return try std.fmt.allocPrint(
                self.allocator,
                "Task #{d}: {s} [{s}]\nResult:\n{s}",
                .{ task_id, state.label, taskStatusLabel(state.status), result },
            );
        }
        return try std.fmt.allocPrint(
            self.allocator,
            "Task #{d}: {s} [{s}]",
            .{ task_id, state.label, taskStatusLabel(state.status) },
        );
    }
    if (std.ascii.eqlIgnoreCase(action, "kill")) {
        return try handleKillCommand(self, parsed.tail);
    }

    return try self.allocator.dupe(u8, "Unknown /subagents action. Use /subagents help.");
}

test "handleKillCommand frees completed subagent origin route" {
    const cfg = config_module.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var manager = subagent_mod.SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer manager.deinit();

    var spawn_tool = spawn_tool_mod.SpawnTool{ .manager = &manager };
    const tools = [_]Tool{spawn_tool.tool()};
    var harness = struct {
        allocator: std.mem.Allocator,
        tools: []const Tool,
        memory_session_id: ?[]const u8 = "session:42",
    }{
        .allocator = std.testing.allocator,
        .tools = tools[0..],
    };

    const state = try std.testing.allocator.create(subagent_mod.TaskState);
    state.* = .{
        .status = .completed,
        .label = try std.testing.allocator.dupe(u8, "done-task"),
        .origin_channel = try std.testing.allocator.dupe(u8, "telegram"),
        .origin_chat_id = try std.testing.allocator.dupe(u8, "chat-42"),
        .origin_account_id = try std.testing.allocator.dupe(u8, "primary"),
        .session_key = try std.testing.allocator.dupe(u8, "session:42"),
        .result = try std.testing.allocator.dupe(u8, "done"),
        .started_at = std_compat.time.milliTimestamp(),
        .completed_at = std_compat.time.milliTimestamp(),
    };
    try manager.tasks.put(std.testing.allocator, 1, state);

    // Regression: #849 made origin route fields owned by TaskState; /kill must
    // free them when it removes completed tasks.
    const response = try handleKillCommand(&harness, "1");
    defer std.testing.allocator.free(response);
    try std.testing.expectEqual(@as(usize, 0), manager.tasks.count());
    try std.testing.expect(std.mem.indexOf(u8, response, "removed") != null);
}

fn handleSteerCommand(self: anytype, arg: []const u8) ![]const u8 {
    const parsed = splitFirstToken(arg);
    const id_text = parsed.head;
    const message = parsed.tail;
    const task_id = parseTaskId(id_text) orelse
        return try self.allocator.dupe(u8, "Usage: /steer <id> <message>");
    if (message.len == 0) return try self.allocator.dupe(u8, "Usage: /steer <id> <message>");

    if (findSubagentManager(self)) |manager| {
        manager.mutex.lock();
        defer manager.mutex.unlock();
        const state = manager.tasks.get(task_id) orelse
            return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
        if (!taskBelongsToCurrentSession(self, state)) {
            return try std.fmt.allocPrint(self.allocator, "Task #{d} not found.", .{task_id});
        }
    }

    const follow_up = try std.fmt.allocPrint(
        self.allocator,
        "Follow up for task #{d}: {s}",
        .{ task_id, message },
    );
    defer self.allocator.free(follow_up);

    const spawned = try spawnSubagentTask(self, follow_up, "steer", null);
    defer self.allocator.free(spawned);
    return try std.fmt.allocPrint(
        self.allocator,
        "Steer for task #{d} created as a new subagent.\n{s}",
        .{ task_id, spawned },
    );
}

fn handleTellCommand(self: anytype, arg: []const u8) ![]const u8 {
    return try spawnSubagentTask(self, arg, "tell", null);
}

fn handlePollCommand(self: anytype) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const w = &out_writer.writer;

    var wrote_any = false;
    if (self.pending_exec_command) |cmd| {
        wrote_any = true;
        try w.print("Pending approval id={d}: {s}\n", .{ self.pending_exec_id, cmd });
    }

    if (findSubagentManager(self)) |manager| {
        manager.mutex.lock();
        defer manager.mutex.unlock();
        var running: u32 = 0;
        var completed: u32 = 0;
        var failed: u32 = 0;
        var visible: u32 = 0;

        var it = manager.tasks.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr.*;
            if (!taskBelongsToCurrentSession(self, state)) continue;
            visible += 1;
            switch (state.status) {
                .running => running += 1,
                .completed => completed += 1,
                .failed => failed += 1,
            }
        }
        if (visible > 0) {
            wrote_any = true;
            try w.print(
                "Subagent tasks: running={d}, completed={d}, failed={d}\n",
                .{ running, completed, failed },
            );
        }
    }

    if (!wrote_any) {
        return try self.allocator.dupe(u8, "No pending approvals or background tasks.");
    }
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn handleStopCommand(self: anytype) ![]const u8 {
    var cleared_pending = false;
    if (self.pending_exec_command != null) {
        clearPendingExecCommand(self);
        cleared_pending = true;
    }

    if (findSubagentManager(self)) |manager| {
        var running: u32 = 0;
        manager.mutex.lock();
        {
            var it = manager.tasks.iterator();
            while (it.next()) |entry| {
                const state = entry.value_ptr.*;
                if (!taskBelongsToCurrentSession(self, state)) continue;
                if (state.status == .running) running += 1;
            }
        }
        manager.mutex.unlock();
        if (running > 0) {
            if (cleared_pending) {
                return try std.fmt.allocPrint(
                    self.allocator,
                    "Cleared pending exec approval. {d} running subagent tasks cannot be interrupted in this runtime.",
                    .{running},
                );
            }
            return try std.fmt.allocPrint(
                self.allocator,
                "{d} running subagent tasks cannot be interrupted in this runtime.",
                .{running},
            );
        }
    }

    if (cleared_pending) {
        return try self.allocator.dupe(u8, "Cleared pending exec approval.");
    }
    return try self.allocator.dupe(u8, "No active background task to stop.");
}

fn parseJsonStringOwned(allocator: std.mem.Allocator, raw: []const u8) !?[]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .string) return null;
    return try allocator.dupe(u8, parsed.value.string);
}

fn parseJsonF64(raw: []const u8) ?f64 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const parsed = std.json.parseFromSlice(std.json.Value, arena.allocator(), raw, .{}) catch return null;
    return switch (parsed.value) {
        .float => |v| v,
        .integer => |v| @floatFromInt(v),
        else => null,
    };
}

fn parseJsonU32(raw: []const u8) ?u32 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const parsed = std.json.parseFromSlice(std.json.Value, arena.allocator(), raw, .{}) catch return null;
    return switch (parsed.value) {
        .integer => |v| blk: {
            if (v < 0 or v > std.math.maxInt(u32)) break :blk null;
            break :blk @intCast(v);
        },
        else => null,
    };
}

fn parseJsonU64(raw: []const u8) ?u64 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const parsed = std.json.parseFromSlice(std.json.Value, arena.allocator(), raw, .{}) catch return null;
    return switch (parsed.value) {
        .integer => |v| blk: {
            if (v < 0 or v > std.math.maxInt(u64)) break :blk null;
            break :blk @intCast(v);
        },
        else => null,
    };
}

fn parseJsonBool(raw: []const u8) ?bool {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const parsed = std.json.parseFromSlice(std.json.Value, arena.allocator(), raw, .{}) catch return null;
    return switch (parsed.value) {
        .bool => |v| v,
        else => null,
    };
}

fn parseHotReloadPrimaryModelRef(
    self: anytype,
    allocator: std.mem.Allocator,
    raw: []const u8,
) !?config_module.PrimaryModelRef {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return null;
    return switch (parsed.value) {
        .string => |primary| if (splitPrimaryModelRefForSelf(self, primary)) |split|
            config_module.PrimaryModelRef{
                .provider = split.provider,
                .model = split.model,
            }
        else
            null,
        .object => |obj| blk: {
            const provider_val = obj.get("provider") orelse break :blk null;
            const primary_val = obj.get("primary") orelse break :blk null;
            if (provider_val != .string or primary_val != .string) break :blk null;
            break :blk .{
                .provider = provider_val.string,
                .model = primary_val.string,
            };
        },
        else => null,
    };
}

const hot_reload_paths = [_][]const u8{
    "agents.defaults.model.primary",
    "default_temperature",
    "agent.max_tool_iterations",
    "agent.max_history_messages",
    "agent.message_timeout_secs",
    "agent.status_show_emojis",
};

const HotReloadSummary = struct {
    attempted: usize = 0,
    applied: usize = 0,
    skipped: usize = 0,
    failed: usize = 0,
};

fn hotApplyConfigChange(
    self: anytype,
    action: config_mutator.MutationAction,
    path: []const u8,
    new_value_json: []const u8,
) !bool {
    if (action == .unset) return false;

    if (std.mem.eql(u8, path, "agents.defaults.model.primary")) {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const parsed = try parseHotReloadPrimaryModelRef(self, arena.allocator(), new_value_json) orelse return false;
        try setModelName(self, parsed.model);
        try setDefaultProvider(self, parsed.provider);
        if (@hasField(@TypeOf(self.*), "default_model")) {
            self.default_model = self.model_name;
        }
        return true;
    }

    if (std.mem.eql(u8, path, "default_temperature")) {
        const temp = parseJsonF64(new_value_json) orelse return false;
        if (@hasField(@TypeOf(self.*), "temperature")) {
            self.temperature = temp;
            return true;
        }
        return false;
    }

    if (std.mem.eql(u8, path, "agent.max_tool_iterations")) {
        const v = parseJsonU32(new_value_json) orelse return false;
        if (@hasField(@TypeOf(self.*), "max_tool_iterations")) {
            self.max_tool_iterations = v;
            return true;
        }
        return false;
    }

    if (std.mem.eql(u8, path, "agent.max_history_messages")) {
        const v = parseJsonU32(new_value_json) orelse return false;
        if (@hasField(@TypeOf(self.*), "max_history_messages")) {
            self.max_history_messages = v;
            return true;
        }
        return false;
    }

    if (std.mem.eql(u8, path, "agent.message_timeout_secs")) {
        const v = parseJsonU64(new_value_json) orelse return false;
        if (@hasField(@TypeOf(self.*), "message_timeout_secs")) {
            self.message_timeout_secs = v;
            return true;
        }
        return false;
    }

    if (std.mem.eql(u8, path, "agent.status_show_emojis")) {
        const v = parseJsonBool(new_value_json) orelse return false;
        if (@hasField(@TypeOf(self.*), "status_show_emojis")) {
            self.status_show_emojis = v;
            return true;
        }
        return false;
    }

    return false;
}

fn loadHotReloadConfig(backing_allocator: std.mem.Allocator) !config_module.Config {
    const arena_ptr = try backing_allocator.create(std.heap.ArenaAllocator);
    arena_ptr.* = std.heap.ArenaAllocator.init(backing_allocator);
    errdefer {
        arena_ptr.deinit();
        backing_allocator.destroy(arena_ptr);
    }
    const allocator = arena_ptr.allocator();

    const config_path = try config_mutator.defaultConfigPath(allocator);
    const config_dir = std_compat.fs.path.dirname(config_path) orelse return error.InvalidPath;
    const default_workspace_dir = try config_paths.defaultWorkspaceDirFromConfigDir(allocator, config_dir);

    var cfg = config_module.Config{
        .workspace_dir = default_workspace_dir,
        .config_path = config_path,
        .allocator = allocator,
        .arena = arena_ptr,
    };

    if (std_compat.fs.openFileAbsolute(config_path, .{})) |file| {
        defer file.close();
        const content = try file.readToEndAlloc(allocator, 1024 * 64);
        try cfg.parseJson(content);
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    if (cfg.workspace_dir_override != null) {
        cfg.workspace_dir = cfg.workspace_dir_override.?;
    }

    if (cfg.channels.nostr) |ns| {
        ns.config_dir = std_compat.fs.path.dirname(config_path) orelse ".";
    }
    {
        const dir = std_compat.fs.path.dirname(config_path) orelse ".";
        const teams_mut = @constCast(cfg.channels.teams);
        for (teams_mut) |*tc| {
            tc.config_dir = dir;
        }
    }

    cfg.applyEnvOverrides();
    cfg.syncFlatFields();
    return cfg;
}

fn hotReloadValueJson(
    allocator: std.mem.Allocator,
    cfg: *const config_module.Config,
    path: []const u8,
) ![]u8 {
    if (std.mem.eql(u8, path, "agents.defaults.model.primary")) {
        const model = cfg.default_model orelse return allocator.dupe(u8, "null");
        if (config_module.shouldSerializeDefaultModelProviderField(cfg.default_provider)) {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            var model_obj: std.json.ObjectMap = .empty;
            try model_obj.put(arena.allocator(), "provider", .{ .string = cfg.default_provider });
            try model_obj.put(arena.allocator(), "primary", .{ .string = model });
            return try std.json.Stringify.valueAlloc(allocator, std.json.Value{ .object = model_obj }, .{});
        }

        const primary = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cfg.default_provider, model });
        defer allocator.free(primary);
        return try std.json.Stringify.valueAlloc(allocator, std.json.Value{ .string = primary }, .{});
    }

    if (std.mem.eql(u8, path, "default_temperature")) {
        return try std.fmt.allocPrint(allocator, "{d}", .{cfg.default_temperature});
    }

    if (std.mem.eql(u8, path, "agent.max_tool_iterations")) {
        return try std.fmt.allocPrint(allocator, "{d}", .{cfg.agent.max_tool_iterations});
    }

    if (std.mem.eql(u8, path, "agent.max_history_messages")) {
        return try std.fmt.allocPrint(allocator, "{d}", .{cfg.agent.max_history_messages});
    }

    if (std.mem.eql(u8, path, "agent.message_timeout_secs")) {
        return try std.fmt.allocPrint(allocator, "{d}", .{cfg.agent.message_timeout_secs});
    }

    if (std.mem.eql(u8, path, "agent.status_show_emojis")) {
        return try allocator.dupe(u8, if (cfg.agent.status_show_emojis) "true" else "false");
    }

    return error.InvalidPath;
}

fn applyHotReloadConfig(self: anytype, cfg: *const config_module.Config) !HotReloadSummary {
    var summary = HotReloadSummary{};
    const has_active_profile = @hasField(@TypeOf(self.*), "profile_name") and self.profile_name != null;

    for (hot_reload_paths) |path| {
        if (has_active_profile and std.mem.eql(u8, path, "agents.defaults.model.primary")) {
            summary.skipped += 1;
            continue;
        }

        const value_json = hotReloadValueJson(self.allocator, cfg, path) catch {
            summary.failed += 1;
            continue;
        };
        defer self.allocator.free(value_json);

        if (std.mem.eql(u8, std.mem.trim(u8, value_json, " \t\r\n"), "null")) {
            summary.skipped += 1;
            continue;
        }

        summary.attempted += 1;
        const hot_applied = hotApplyConfigChange(self, .set, path, value_json) catch {
            summary.failed += 1;
            continue;
        };
        if (hot_applied) {
            summary.applied += 1;
        } else {
            summary.skipped += 1;
        }
    }

    // Profile-aware reload: only hot-apply profile settings that can be reconciled
    // with the current runtime provider. Provider swaps still require a fresh session.
    if (@hasField(@TypeOf(self.*), "profile_name")) {
        if (self.profile_name) |pname| {
            for (cfg.agents) |*acfg| {
                if (std.mem.eql(u8, acfg.name, pname)) {
                    const runtime_provider_name = activeRuntimeProviderName(self) orelse "";
                    const provider_matches_runtime = provider_names.providerNamesMatchIgnoreCase(
                        runtime_provider_name,
                        acfg.provider,
                    );

                    if (@hasField(@TypeOf(self.*), "default_provider") and
                        !provider_names.providerNamesMatchIgnoreCase(self.default_provider, acfg.provider))
                    {
                        if (provider_matches_runtime) {
                            summary.attempted += 1;
                            const provider_updated = blk: {
                                setDefaultProvider(self, acfg.provider) catch |err| {
                                    summary.failed += 1;
                                    log.warn("Hot reload profile provider metadata update failed: {}", .{err});
                                    break :blk false;
                                };
                                break :blk true;
                            };
                            if (provider_updated) summary.applied += 1;
                        } else {
                            summary.skipped += 1;
                            log.warn(
                                "Hot reload skipped profile provider change for {s}: runtime provider {s} requires a fresh session to switch to {s}",
                                .{ pname, runtime_provider_name, acfg.provider },
                            );
                        }
                    }

                    if (!std.mem.eql(u8, self.model_name, acfg.model)) {
                        if (!provider_matches_runtime) {
                            summary.skipped += 1;
                            log.warn(
                                "Hot reload skipped profile model update for {s}: provider switch to {s} was not applied",
                                .{ pname, acfg.provider },
                            );
                        } else {
                            summary.attempted += 1;
                            const model_updated = blk: {
                                setModelName(self, acfg.model) catch |err| {
                                    summary.failed += 1;
                                    log.warn("Hot reload profile model update failed: {}", .{err});
                                    break :blk false;
                                };
                                break :blk true;
                            };
                            if (model_updated) {
                                if (@hasField(@TypeOf(self.*), "default_model")) {
                                    self.default_model = self.model_name;
                                }
                                summary.applied += 1;
                            }
                        }
                    }

                    if (@hasField(@TypeOf(self.*), "profile_system_prompt")) {
                        const old_prompt = self.profile_system_prompt orelse "";
                        const new_prompt = acfg.system_prompt orelse "";
                        if (!std.mem.eql(u8, old_prompt, new_prompt)) {
                            summary.attempted += 1;
                            const prompt_updated = blk: {
                                setProfileSystemPrompt(self, if (new_prompt.len > 0) new_prompt else null) catch |err| {
                                    summary.failed += 1;
                                    log.warn("Hot reload profile system prompt update failed: {}", .{err});
                                    break :blk false;
                                };
                                break :blk true;
                            };
                            if (prompt_updated) summary.applied += 1;
                        }
                    }

                    const new_temp = acfg.temperature orelse cfg.default_temperature;
                    if (self.temperature != new_temp) {
                        summary.attempted += 1;
                        self.temperature = new_temp;
                        summary.applied += 1;
                    }
                    break;
                }
            }
        }
    }

    if (summary.applied > 0) {
        invalidateSystemPromptCache(self);
    }

    return summary;
}

fn formatConfigMutationResponse(
    allocator: std.mem.Allocator,
    action: config_mutator.MutationAction,
    result: *const config_mutator.MutationResult,
    dry_run: bool,
    hot_applied: bool,
) ![]const u8 {
    const action_name = switch (action) {
        .set => "set",
        .unset => "unset",
    };
    const mode = if (dry_run) "preview" else "applied";
    const restart_text = if (result.requires_restart) "true" else "false";
    const hot_text = if (hot_applied) "true" else "false";
    const backup = result.backup_path orelse "(none)";

    return try std.fmt.allocPrint(
        allocator,
        "Config {s} ({s}):\\n" ++
            "  action: {s}\\n" ++
            "  path: {s}\\n" ++
            "  old: {s}\\n" ++
            "  new: {s}\\n" ++
            "  requires_restart: {s}\\n" ++
            "  hot_applied: {s}\\n" ++
            "  backup: {s}\\n",
        .{
            action_name,
            mode,
            action_name,
            result.path,
            result.old_value_json,
            result.new_value_json,
            restart_text,
            hot_text,
            backup,
        },
    );
}

fn handleCapabilitiesCommand(self: anytype, arg: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, arg, " \t");
    const as_json = std.mem.eql(u8, trimmed, "--json") or std.ascii.eqlIgnoreCase(trimmed, "json");

    var cfg_opt: ?config_module.Config = config_module.Config.load(self.allocator) catch null;
    defer if (cfg_opt) |*cfg| cfg.deinit();
    const cfg_ptr: ?*const config_module.Config = if (cfg_opt) |*cfg| cfg else null;

    const runtime_tools: ?[]const Tool = if (@hasField(@TypeOf(self.*), "tools"))
        self.tools
    else
        null;

    if (as_json) {
        return capabilities_mod.buildManifestJson(self.allocator, cfg_ptr, runtime_tools);
    }
    return capabilities_mod.buildSummaryText(self.allocator, cfg_ptr, runtime_tools);
}

fn handleConfigCommand(self: anytype, arg: []const u8) ![]const u8 {
    const parsed = splitFirstToken(arg);
    const action = parsed.head;

    if (action.len == 0 or std.ascii.eqlIgnoreCase(action, "show") or std.ascii.eqlIgnoreCase(action, "status")) {
        return try std.fmt.allocPrint(
            self.allocator,
            "Runtime config:\n  model={s}\n  workspace={s}\n  exec.host={s}\n  exec.security={s}\n  exec.ask={s}\n  queue.mode={s}\n  tts.mode={s}\n  activation={s}\n  send={s}",
            .{
                self.model_name,
                self.workspace_dir,
                self.exec_host.toSlice(),
                self.exec_security.toSlice(),
                self.exec_ask.toSlice(),
                self.queue_mode.toSlice(),
                self.tts_mode.toSlice(),
                self.activation_mode.toSlice(),
                self.send_mode.toSlice(),
            },
        );
    }

    if (std.ascii.eqlIgnoreCase(action, "get")) {
        const key = std.mem.trim(u8, parsed.tail, " \t");
        if (key.len == 0) return try self.allocator.dupe(u8, "Usage: /config get <path>");
        return config_mutator.getPathValueJson(self.allocator, key) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Config get failed: {s}", .{@errorName(err)});
        };
    }

    if (std.ascii.eqlIgnoreCase(action, "validate")) {
        config_mutator.validateCurrentConfig(self.allocator) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Config validation failed: {s}", .{@errorName(err)});
        };
        return try self.allocator.dupe(u8, "Config validation: OK");
    }

    if (std.ascii.eqlIgnoreCase(action, "reload") or std.ascii.eqlIgnoreCase(action, "refresh")) {
        if (std.mem.trim(u8, parsed.tail, " \t").len > 0) {
            return try self.allocator.dupe(u8, "Usage: /config reload");
        }

        var validation_failed = false;
        config_mutator.validateCurrentConfig(self.allocator) catch {
            validation_failed = true;
        };

        var summary = HotReloadSummary{};
        if (validation_failed) {
            summary.failed = 1;
        } else {
            var cfg = loadHotReloadConfig(self.allocator) catch {
                summary.failed = 1;
                return try std.fmt.allocPrint(
                    self.allocator,
                    "Config hot reload complete: attempted={d} applied={d} skipped={d} failed={d} validation_failed={s}",
                    .{ summary.attempted, summary.applied, summary.skipped, summary.failed, "false" },
                );
            };
            defer cfg.deinit();

            summary = try applyHotReloadConfig(self, &cfg);
        }

        return try std.fmt.allocPrint(
            self.allocator,
            "Config hot reload complete: attempted={d} applied={d} skipped={d} failed={d} validation_failed={s}",
            .{ summary.attempted, summary.applied, summary.skipped, summary.failed, if (validation_failed) "true" else "false" },
        );
    }

    if (std.ascii.eqlIgnoreCase(action, "set")) {
        const path_and_value = splitFirstToken(parsed.tail);
        const path = path_and_value.head;
        const value_raw = std.mem.trim(u8, path_and_value.tail, " \t");
        if (path.len == 0 or value_raw.len == 0) {
            return try self.allocator.dupe(u8, "Usage: /config set <path> <value> (dry-run preview)");
        }

        var result = config_mutator.mutateDefaultConfig(self.allocator, .set, path, value_raw, .{ .apply = false }) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Config set preview failed: {s}", .{@errorName(err)});
        };
        defer config_mutator.freeMutationResult(self.allocator, &result);

        const response = try formatConfigMutationResponse(self.allocator, .set, &result, true, false);
        return response;
    }

    if (std.ascii.eqlIgnoreCase(action, "unset")) {
        const path = std.mem.trim(u8, parsed.tail, " \t");
        if (path.len == 0) {
            return try self.allocator.dupe(u8, "Usage: /config unset <path> (dry-run preview)");
        }

        var result = config_mutator.mutateDefaultConfig(self.allocator, .unset, path, null, .{ .apply = false }) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Config unset preview failed: {s}", .{@errorName(err)});
        };
        defer config_mutator.freeMutationResult(self.allocator, &result);

        const response = try formatConfigMutationResponse(self.allocator, .unset, &result, true, false);
        return response;
    }

    if (std.ascii.eqlIgnoreCase(action, "apply")) {
        const apply_parsed = splitFirstToken(parsed.tail);
        const apply_action = apply_parsed.head;
        const apply_rest = apply_parsed.tail;

        if (std.ascii.eqlIgnoreCase(apply_action, "set")) {
            const path_and_value = splitFirstToken(apply_rest);
            const path = path_and_value.head;
            const value_raw = std.mem.trim(u8, path_and_value.tail, " \t");
            if (path.len == 0 or value_raw.len == 0) {
                return try self.allocator.dupe(u8, "Usage: /config apply set <path> <value>");
            }

            var result = config_mutator.mutateDefaultConfig(self.allocator, .set, path, value_raw, .{ .apply = true }) catch |err| {
                return try std.fmt.allocPrint(self.allocator, "Config apply set failed: {s}", .{@errorName(err)});
            };
            defer config_mutator.freeMutationResult(self.allocator, &result);

            var hot_applied = false;
            if (result.applied and !result.requires_restart) {
                hot_applied = hotApplyConfigChange(self, .set, result.path, result.new_value_json) catch false;
            }
            const response = try formatConfigMutationResponse(self.allocator, .set, &result, false, hot_applied);
            return response;
        }

        if (std.ascii.eqlIgnoreCase(apply_action, "unset")) {
            const path = std.mem.trim(u8, apply_rest, " \t");
            if (path.len == 0) {
                return try self.allocator.dupe(u8, "Usage: /config apply unset <path>");
            }

            var result = config_mutator.mutateDefaultConfig(self.allocator, .unset, path, null, .{ .apply = true }) catch |err| {
                return try std.fmt.allocPrint(self.allocator, "Config apply unset failed: {s}", .{@errorName(err)});
            };
            defer config_mutator.freeMutationResult(self.allocator, &result);

            const response = try formatConfigMutationResponse(self.allocator, .unset, &result, false, false);
            return response;
        }

        return try self.allocator.dupe(u8, "Usage: /config apply <set|unset> ...");
    }

    return try self.allocator.dupe(
        u8,
        "Usage:\n" ++
            "  /config [show]\n" ++
            "  /config get <path>\n" ++
            "  /config set <path> <value>            (dry-run preview)\n" ++
            "  /config unset <path>                  (dry-run preview)\n" ++
            "  /config apply set <path> <value>\n" ++
            "  /config apply unset <path>\n" ++
            "  /config reload                        (hot reload supported keys)\n" ++
            "  /config validate",
    );
}

fn handleSkillCommand(self: anytype, command_name: []const u8, arg: []const u8) ![]const u8 {
    const parsed = splitFirstToken(arg);
    const action_or_name = parsed.head;
    const interactive_session = std.ascii.eqlIgnoreCase(command_name, "iskill");

    if (std.ascii.eqlIgnoreCase(command_name, "skills")) {
        const skills = skills_mod.listSkills(self.allocator, self.workspace_dir, self.observer) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Failed to load skills: {s}", .{@errorName(err)});
        };
        defer skills_mod.freeSkills(self.allocator, skills);
        return try formatSkillList(self, skills, arg);
    }

    if (std.ascii.eqlIgnoreCase(action_or_name, "reload") or std.ascii.eqlIgnoreCase(action_or_name, "refresh")) {
        if (std.mem.trim(u8, parsed.tail, " \t").len > 0) {
            return try self.allocator.dupe(u8, "Usage: /skill reload");
        }
        if (@hasField(@TypeOf(self.*), "active_skill_name")) {
            if (self.active_skill_name) |active_name| {
                const interactive = self.active_skill_interactive;
                const skills = skills_mod.listSkills(self.allocator, self.workspace_dir, self.observer) catch |err| {
                    return try std.fmt.allocPrint(self.allocator, "Failed to load skills: {s}", .{@errorName(err)});
                };
                defer skills_mod.freeSkills(self.allocator, skills);

                switch (findSkillByNameNormalized(skills, active_name)) {
                    .unique => |skill| try setActiveSkillSession(self, skill, interactive),
                    else => clearActiveSkillSession(self),
                }
            }
        }
        invalidateSystemPromptCache(self);
        return try self.allocator.dupe(u8, "Skills reloaded for this session. Updated skill instructions will apply on the next turn.");
    }

    const skills = skills_mod.listSkills(self.allocator, self.workspace_dir, self.observer) catch |err| {
        return try std.fmt.allocPrint(self.allocator, "Failed to load skills: {s}", .{@errorName(err)});
    };
    defer skills_mod.freeSkills(self.allocator, skills);

    if (action_or_name.len == 0 or std.ascii.eqlIgnoreCase(action_or_name, "list")) {
        return try formatSkillList(self, skills, parsed.tail);
    }

    if (std.ascii.eqlIgnoreCase(action_or_name, "status")) {
        return try formatActiveSkillStatus(self);
    }

    if (std.ascii.eqlIgnoreCase(action_or_name, "clear") or std.ascii.eqlIgnoreCase(action_or_name, "off")) {
        if (!@hasField(@TypeOf(self.*), "active_skill_name") or self.active_skill_name == null) {
            return try formatSkillInactiveReply(self, "No active skill session.");
        }
        clearActiveSkillSession(self);
        invalidateSystemPromptCache(self);
        return try formatSkillInactiveReply(self, "Active skill session cleared.");
    }

    switch (findSkillByNameNormalized(skills, action_or_name)) {
        .unique => |skill| {
            const remaining = std.mem.trim(u8, parsed.tail, " \t");
            if (remaining.len == 0) {
                try setActiveSkillSession(self, skill, interactive_session);
                invalidateSystemPromptCache(self);
                return try formatSkillActivatedReply(self, skill, interactive_session);
            }
            return try executeSkillInvocation(self, skill, remaining, interactive_session);
        },
        .ambiguous => return try formatSkillAmbiguousReply(self, action_or_name),
        .not_found => return try formatSkillUnknownReply(self, action_or_name),
    }
}

fn handleBashCommand(self: anytype, arg: []const u8) ![]const u8 {
    const command = std.mem.trim(u8, arg, " \t");
    if (command.len == 0) {
        return try self.allocator.dupe(u8, "Usage: /bash <command>");
    }
    if (std.ascii.eqlIgnoreCase(command, "poll")) {
        return try self.allocator.dupe(u8, "No background command output is available.");
    }
    if (std.ascii.eqlIgnoreCase(command, "stop")) {
        return try self.allocator.dupe(u8, "No background command is running.");
    }
    return try runShellCommand(self, command, false);
}

pub fn isExecToolName(tool_name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(tool_name, "shell");
}

pub fn execBlockMessage(self: anytype, args: std.json.ObjectMap) ?[]const u8 {
    if (self.exec_host == .node) {
        return "Exec blocked: host=node is not available in this runtime";
    }
    if (self.exec_security == .deny) {
        return "Exec blocked by /exec security=deny";
    }
    if (self.exec_ask == .always) {
        if (args.get("command")) |v| {
            if (v == .string) {
                _ = setPendingExecCommand(self, v.string) catch {};
            }
        }
        return "Exec blocked: approval required. Use /approve allow-once|allow-always|deny";
    }

    if (self.exec_security == .allowlist and self.exec_ask == .on_miss) {
        if (args.get("command")) |v| {
            if (v == .string) {
                const command = v.string;
                if (self.policy) |pol| {
                    if (!pol.isCommandAllowed(command)) {
                        const summary = command_summary.summarizeBlockedCommand(command);
                        log.warn("tool exec blocked by allowlist policy: head={s} bytes={d} assignments={d}", .{
                            summary.head,
                            summary.byte_len,
                            summary.assignment_count,
                        });
                        return "Exec blocked by allowlist policy";
                    }
                }
            }
        }
    }

    return null;
}

pub fn composeFinalReply(
    self: anytype,
    base_text: []const u8,
    reasoning_content: ?[]const u8,
    usage: providers.TokenUsage,
) ![]const u8 {
    // For reasoning_mode == .stream the thinking content is already printed
    // live during streaming via ThinkPassthroughFilter, so we must not
    // prepend it again here. Only .on mode shows the post-turn block.
    const show_reasoning = self.reasoning_mode == .on and reasoning_content != null and reasoning_content.?.len > 0;
    if (!show_reasoning and self.usage_mode == .off) {
        return try self.allocator.dupe(u8, base_text);
    }

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(self.allocator);
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
    const w = &out_writer.writer;

    if (show_reasoning) {
        try w.writeAll("Reasoning:\n");
        var lines = std.mem.splitScalar(u8, reasoning_content.?, '\n');
        while (lines.next()) |line| {
            try w.writeAll("> ");
            try w.writeAll(line);
            try w.writeAll("\n");
        }
        try w.writeAll("\n\n");
    }
    try w.writeAll(base_text);

    switch (self.usage_mode) {
        .off => {},
        .tokens => try w.print("\n\n[usage] total_tokens={d}", .{usage.total_tokens}),
        .full => try w.print(
            "\n\n[usage] prompt={d} completion={d} total={d} session_total={d}",
            .{ usage.prompt_tokens, usage.completion_tokens, usage.total_tokens, self.total_tokens },
        ),
        .cost => {
            const model_name = if (comptime @hasField(@TypeOf(self.*), "model_name")) self.model_name else "";
            const turn_cost = cost_mod.TokenUsage.fromProviders(model_name, usage).cost();
            if (comptime @hasField(@TypeOf(self.*), "total_cost_usd")) {
                try w.print(
                    "\n\n[usage] prompt={d} completion={d} total={d} cost=${d:.4} session_cost=${d:.4}",
                    .{ usage.prompt_tokens, usage.completion_tokens, usage.total_tokens, turn_cost, self.total_cost_usd },
                );
            } else {
                try w.print(
                    "\n\n[usage] prompt={d} completion={d} total={d} cost=${d:.4}",
                    .{ usage.prompt_tokens, usage.completion_tokens, usage.total_tokens, turn_cost },
                );
            }
        },
    }

    out = out_writer.toArrayList();
    return try out.toOwnedSlice(self.allocator);
}

fn handleDoctorCommand(self: anytype) ![]const u8 {
    const rt: ?*memory_mod.MemoryRuntime = if (@hasField(@TypeOf(self.*), "mem_rt")) self.mem_rt else null;
    if (rt) |mem_rt| {
        const report = memory_mod.diagnostics.diagnose(mem_rt);
        return memory_mod.diagnostics.formatReport(report, self.allocator);
    }
    return try self.allocator.dupe(u8, "Memory runtime not available. Diagnostics require a configured memory backend.");
}

pub fn handleSlashCommand(self: anytype, message: []const u8) !?[]const u8 {
    const cmd = parseSlashCommand(message) orelse return null;
    switch (classifySlashCommand(cmd)) {
        .new_reset => {
            clearSessionState(self);
            if (cmd.arg.len > 0) {
                try setModelName(self, cmd.arg);
                if (@hasField(@TypeOf(self.*), "model_pinned_by_user")) {
                    self.model_pinned_by_user = true;
                }
                invalidateSystemPromptCache(self);
                return try std.fmt.allocPrint(self.allocator, "Session cleared. Switched to model: {s}", .{cmd.arg});
            }
            return try self.allocator.dupe(u8, "Session cleared.");
        },
        .restart => {
            clearSessionState(self);
            resetRuntimeCommandState(self);
            if (cmd.arg.len > 0) {
                try setModelName(self, cmd.arg);
                if (@hasField(@TypeOf(self.*), "model_pinned_by_user")) {
                    self.model_pinned_by_user = true;
                }
                invalidateSystemPromptCache(self);
                return try std.fmt.allocPrint(self.allocator, "Session restarted. Switched to model: {s}", .{cmd.arg});
            }
            return try self.allocator.dupe(u8, "Session restarted.");
        },
        .help => return try self.allocator.dupe(u8, control_plane.HELP_TEXT),
        .status => return try formatStatus(self),
        .whoami => return try formatWhoAmI(self),
        .model => {
            const first = firstToken(cmd.arg);
            if (std.ascii.eqlIgnoreCase(first, "page")) {
                const page_raw = std.mem.trim(u8, splitFirstToken(cmd.arg).tail, " \t");
                const page_number = parsePositiveUsize(page_raw) orelse 1;
                if (try renderInteractiveProviderMenu(self, page_number)) |menu| {
                    return menu;
                }
                return try self.formatModelStatus();
            }
            if (std.ascii.eqlIgnoreCase(first, "provider")) {
                const provider_tail = splitFirstToken(cmd.arg).tail;
                const provider_name = firstToken(provider_tail);
                if (provider_name.len == 0) {
                    if (try renderInteractiveProviderMenu(self, 1)) |menu| {
                        return menu;
                    }
                    return try self.formatModelStatus();
                }

                const remainder = splitFirstToken(provider_tail).tail;
                const page_number = if (std.ascii.eqlIgnoreCase(firstToken(remainder), "page"))
                    parsePositiveUsize(std.mem.trim(u8, splitFirstToken(remainder).tail, " \t")) orelse 1
                else
                    1;

                if (try renderInteractiveModelMenu(self, provider_name, page_number)) |menu| {
                    return menu;
                }
                return try std.fmt.allocPrint(self.allocator, "No models available for provider: {s}", .{provider_name});
            }
            if (cmd.arg.len == 0 or
                std.ascii.eqlIgnoreCase(cmd.arg, "list") or
                std.ascii.eqlIgnoreCase(cmd.arg, "status"))
            {
                if (try renderInteractiveProviderMenu(self, 1)) |menu| {
                    return menu;
                }
                return try self.formatModelStatus();
            }
            if (std.ascii.eqlIgnoreCase(cmd.arg, "auto")) {
                if (@hasField(@TypeOf(self.*), "model_pinned_by_user")) {
                    self.model_pinned_by_user = false;
                }
                if (@hasDecl(@TypeOf(self.*), "clearLastRouteTrace")) {
                    self.clearLastRouteTrace();
                }
                if (@hasField(@TypeOf(self.*), "default_model")) {
                    try setModelName(self, self.default_model);
                }
                invalidateSystemPromptCache(self);
                if (@hasField(@TypeOf(self.*), "model_routes") and self.model_routes.len == 0) {
                    return try std.fmt.allocPrint(
                        self.allocator,
                        "Automatic model routing is not configured. Reverted to the configured default model: {s}",
                        .{self.model_name},
                    );
                }
                return try std.fmt.allocPrint(
                    self.allocator,
                    "Automatic model routing enabled. Reverted to the configured default model: {s}",
                    .{self.model_name},
                );
            }
            if (splitPrimaryModelRefForSelf(self, cmd.arg)) |parsed| {
                try setDefaultProvider(self, parsed.provider);
            }
            try setModelName(self, cmd.arg);
            if (@hasField(@TypeOf(self.*), "model_pinned_by_user")) {
                self.model_pinned_by_user = true;
            }
            if (@hasDecl(@TypeOf(self.*), "clearLastRouteTrace")) {
                self.clearLastRouteTrace();
            }
            if (@hasField(@TypeOf(self.*), "default_model")) {
                self.default_model = self.model_name;
            }
            invalidateSystemPromptCache(self);
            persistSelectedModelToConfig(self, cmd.arg) catch |err| {
                return try std.fmt.allocPrint(
                    self.allocator,
                    "Switched to model: {s}\nWarning: could not persist model to config.json ({s})",
                    .{ cmd.arg, @errorName(err) },
                );
            };
            return try std.fmt.allocPrint(self.allocator, "Switched to model: {s}", .{cmd.arg});
        },
        .think => return try handleThinkCommand(self, cmd.arg),
        .verbose => return try handleVerboseCommand(self, cmd.arg),
        .reasoning => return try handleReasoningCommand(self, cmd.arg),
        .exec => return try handleExecCommand(self, cmd.arg),
        .queue => return try handleQueueCommand(self, cmd.arg),
        .usage => return try handleUsageCommand(self, cmd.arg),
        .tts => return try handleTtsCommand(self, cmd.arg),
        .stop => return try handleStopCommand(self),
        .compact => {
            if (self.forceCompressHistory()) {
                return try self.allocator.dupe(u8, "Context compacted.");
            }
            return try self.allocator.dupe(u8, "Nothing to compact.");
        },
        .allowlist => return try handleAllowlistCommand(self, cmd.arg),
        .approve => return try handleApproveCommand(self, cmd.arg),
        .context => return try handleContextCommand(self, cmd.arg),
        .export_session => return try handleExportSessionCommand(self, cmd.arg),
        .session => return try handleSessionCommand(self, cmd.arg),
        .subagents => return try handleSubagentsCommand(self, cmd.arg),
        .agents => return try handleAgentsCommand(self),
        .focus => return try handleFocusCommand(self, cmd.arg),
        .unfocus => return try handleUnfocusCommand(self),
        .kill => return try handleKillCommand(self, cmd.arg),
        .steer => return try handleSteerCommand(self, cmd.arg),
        .tell => return try handleTellCommand(self, cmd.arg),
        .config => return try handleConfigCommand(self, cmd.arg),
        .capabilities => return try handleCapabilitiesCommand(self, cmd.arg),
        .cost => return try handleToggleCostCommand(self, cmd.arg),
        .debug => {
            if (std.ascii.eqlIgnoreCase(cmd.arg, "show") or cmd.arg.len == 0) return try formatStatus(self);
            if (std.ascii.eqlIgnoreCase(cmd.arg, "reset")) {
                resetRuntimeCommandState(self);
                return try self.allocator.dupe(u8, "Runtime debug state reset.");
            }
            return try self.allocator.dupe(u8, "Supported: /debug show|reset");
        },
        .dock_telegram => return try handleDockCommand(self, "telegram"),
        .dock_discord => return try handleDockCommand(self, "discord"),
        .dock_slack => return try handleDockCommand(self, "slack"),
        .activation => return try handleActivationCommand(self, cmd.arg),
        .send => return try handleSendCommand(self, cmd.arg),
        .elevated => return try handleElevatedCommand(self, cmd.arg),
        .bash => return try handleBashCommand(self, cmd.arg),
        .poll => return try handlePollCommand(self),
        .skill => return try handleSkillCommand(self, cmd.name, cmd.arg),
        .doctor => return try handleDoctorCommand(self),
        .memory => return try handleMemoryCommand(self, cmd.arg),
        .unknown => {
            if (try tryHandleDirectSkillCommand(self, cmd)) |response| return response;
            return null;
        },
    }
}

fn handleMemoryCommand(self: anytype, arg: []const u8) ![]const u8 {
    const usage =
        "Usage: /memory <stats|status|reindex|count|search|get|list|drain-outbox>\n" ++
        "  /memory search <query> [--limit N]\n" ++
        "  /memory get <key>\n" ++
        "  /memory list [--category C] [--limit N] [--include-internal]";

    const parsed = splitFirstToken(arg);
    const sub = parsed.head;
    const rest = parsed.tail;

    if (sub.len == 0) return try self.allocator.dupe(u8, usage);

    if (std.mem.eql(u8, sub, "doctor") or std.mem.eql(u8, sub, "status")) {
        return try handleDoctorCommand(self);
    }

    const mem_rt = memoryRuntimePtr(self) orelse {
        return try self.allocator.dupe(u8, "Memory runtime not available.");
    };

    if (std.mem.eql(u8, sub, "stats")) {
        const r = mem_rt.resolved;
        const report = mem_rt.diagnose();
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
        const w = &out_writer.writer;
        try w.print("Memory resolved config:\n", .{});
        try w.print("  backend: {s}\n", .{r.primary_backend});
        try w.print("  retrieval: {s}\n", .{r.retrieval_mode});
        try w.print("  vector: {s}\n", .{r.vector_mode});
        try w.print("  embedding: {s}\n", .{r.embedding_provider});
        try w.print("  rollout: {s}\n", .{r.rollout_mode});
        try w.print("  sync: {s}\n", .{r.vector_sync_mode});
        try w.print("  sources: {d}\n", .{r.source_count});
        try w.print("  fallback: {s}\n", .{r.fallback_policy});
        try w.print("  entries: {d}\n", .{report.entry_count});
        if (report.vector_entry_count) |n| {
            try w.print("  vector_entries: {d}\n", .{n});
        } else {
            try w.print("  vector_entries: n/a\n", .{});
        }
        if (report.outbox_pending) |n| {
            try w.print("  outbox_pending: {d}\n", .{n});
        } else {
            try w.print("  outbox_pending: n/a\n", .{});
        }
        out = out_writer.toArrayList();
        return try out.toOwnedSlice(self.allocator);
    }

    if (std.mem.eql(u8, sub, "count")) {
        const count = mem_rt.memory.count() catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Memory count failed: {s}", .{@errorName(err)});
        };
        return try std.fmt.allocPrint(self.allocator, "{d}", .{count});
    }

    if (std.mem.eql(u8, sub, "reindex")) {
        const count = mem_rt.reindex(self.allocator);
        if (std.mem.eql(u8, mem_rt.resolved.vector_mode, "none")) {
            return try self.allocator.dupe(u8, "Vector plane is disabled; reindex skipped (0 entries).");
        }
        return try std.fmt.allocPrint(self.allocator, "Reindex complete: {d} entries reindexed.", .{count});
    }

    if (std.mem.eql(u8, sub, "drain-outbox") or std.mem.eql(u8, sub, "drain_outbox")) {
        const drained = mem_rt.drainOutbox(self.allocator);
        return try std.fmt.allocPrint(self.allocator, "Outbox drain complete: {d} operation(s) processed.", .{drained});
    }

    if (std.mem.eql(u8, sub, "get")) {
        const key = std.mem.trim(u8, rest, " \t");
        if (key.len == 0) return try self.allocator.dupe(u8, "Usage: /memory get <key>");
        const entry = mem_rt.memory.getScoped(self.allocator, key, self.memory_session_id) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Memory get failed: {s}", .{@errorName(err)});
        };
        if (entry) |e| {
            defer e.deinit(self.allocator);
            return try std.fmt.allocPrint(
                self.allocator,
                "key: {s}\ncategory: {s}\ntimestamp: {s}\ncontent:\n{s}",
                .{ e.key, e.category.toString(), e.timestamp, e.content },
            );
        }
        return try std.fmt.allocPrint(self.allocator, "Not found: {s}", .{key});
    }

    if (std.mem.eql(u8, sub, "search")) {
        var limit: usize = 6;
        var query_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer query_buf.deinit(self.allocator);

        var it = std.mem.tokenizeAny(u8, rest, " \t");
        while (it.next()) |tok| {
            if (std.mem.eql(u8, tok, "--limit")) {
                const next = it.next() orelse return try self.allocator.dupe(u8, "Usage: /memory search <query> [--limit N]");
                limit = parsePositiveUsize(next) orelse return try std.fmt.allocPrint(self.allocator, "Invalid --limit value: {s}", .{next});
                continue;
            }
            if (query_buf.items.len > 0) try query_buf.append(self.allocator, ' ');
            try query_buf.appendSlice(self.allocator, tok);
        }

        const query = std.mem.trim(u8, query_buf.items, " \t");
        if (query.len == 0) return try self.allocator.dupe(u8, "Usage: /memory search <query> [--limit N]");

        const results = mem_rt.search(self.allocator, query, limit, self.memory_session_id) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Memory search failed: {s}", .{@errorName(err)});
        };
        defer memory_mod.retrieval.freeCandidates(self.allocator, results);

        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
        const w = &out_writer.writer;
        try w.print("Search results: {d}\n", .{results.len});
        for (results, 0..) |c, idx| {
            try w.print("  {d}. {s} [{s}] score={d:.4}", .{ idx + 1, c.key, c.category.toString(), c.final_score });
            if (c.vector_score) |vs| {
                try w.print(" vector_score={d:.4}", .{vs});
            } else {
                try w.print(" vector_score=n/a", .{});
            }
            try w.print(" source={s}\n", .{c.source});
            const preview = util.previewUtf8(c.snippet, 140);
            try w.print("     {s}{s}\n", .{ preview.slice, if (preview.truncated) "..." else "" });
        }
        out = out_writer.toArrayList();
        return try out.toOwnedSlice(self.allocator);
    }

    if (std.mem.eql(u8, sub, "list")) {
        var limit: usize = 20;
        var category_opt: ?memory_mod.MemoryCategory = null;
        var include_internal = false;
        var it = std.mem.tokenizeAny(u8, rest, " \t");
        while (it.next()) |tok| {
            if (std.mem.eql(u8, tok, "--limit")) {
                const next = it.next() orelse return try self.allocator.dupe(u8, "Usage: /memory list [--category C] [--limit N] [--include-internal]");
                limit = parsePositiveUsize(next) orelse return try std.fmt.allocPrint(self.allocator, "Invalid --limit value: {s}", .{next});
                continue;
            }
            if (std.mem.eql(u8, tok, "--category")) {
                const next = it.next() orelse return try self.allocator.dupe(u8, "Usage: /memory list [--category C] [--limit N] [--include-internal]");
                category_opt = memory_mod.MemoryCategory.fromString(next);
                continue;
            }
            if (std.mem.eql(u8, tok, "--include-internal")) {
                include_internal = true;
                continue;
            }
            return try std.fmt.allocPrint(self.allocator, "Unknown option for /memory list: {s}", .{tok});
        }

        const entries = mem_rt.memory.list(self.allocator, category_opt, null) catch |err| {
            return try std.fmt.allocPrint(self.allocator, "Memory list failed: {s}", .{@errorName(err)});
        };
        defer memory_mod.freeEntries(self.allocator, entries);

        var filtered_total: usize = 0;
        for (entries) |entry| {
            if (!include_internal and isInternalMemoryEntryKeyOrContent(entry.key, entry.content)) continue;
            filtered_total += 1;
        }

        if (filtered_total == 0) {
            return try self.allocator.dupe(u8, "No memory entries found.");
        }

        const shown = @min(limit, filtered_total);
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);
        var out_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &out);
        const w = &out_writer.writer;
        try w.print("Memory entries: showing {d}/{d}\n", .{ shown, filtered_total });
        var written: usize = 0;
        for (entries) |e| {
            if (!include_internal and isInternalMemoryEntryKeyOrContent(e.key, e.content)) continue;
            if (written >= shown) break;
            const preview = util.previewUtf8(e.content, 120);
            try w.print("  {d}. {s} [{s}] {s}\n", .{ written + 1, e.key, e.category.toString(), e.timestamp });
            try w.print("     {s}{s}\n", .{ preview.slice, if (preview.truncated) "..." else "" });
            written += 1;
        }
        out = out_writer.toArrayList();
        return try out.toOwnedSlice(self.allocator);
    }

    return try self.allocator.dupe(u8, usage);
}

test "activateSkillByName activates matching skill" {
    const allocator = std.testing.allocator;
    const fs_compat = @import("compat").fs;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try fs_compat.Dir.wrap(tmp.dir).makePath("skills/news-digest");
    {
        const f = try fs_compat.Dir.wrap(tmp.dir).createFile("skills/news-digest/skill.json", .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "name": "news-digest",
            \\  "description": "Build a digest",
            \\  "version": "1.0.0",
            \\  "author": "test"
            \\}
        );
    }
    {
        const f = try fs_compat.Dir.wrap(tmp.dir).createFile("skills/news-digest/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Collect news.");
    }

    const workspace = try fs_compat.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(workspace);

    var harness = struct {
        allocator: std.mem.Allocator,
        workspace_dir: []const u8,
        observer: ?@import("../observability.zig").Observer = null,
        active_skill_name: ?[]const u8 = null,
        active_skill_name_owned: bool = false,
        active_skill_description: ?[]const u8 = null,
        active_skill_description_owned: bool = false,
        active_skill_instructions: ?[]const u8 = null,
        active_skill_instructions_owned: bool = false,
        active_skill_path: ?[]const u8 = null,
        active_skill_path_owned: bool = false,
        active_skill_interactive: bool = false,
    }{
        .allocator = allocator,
        .workspace_dir = workspace,
    };
    defer {
        if (harness.active_skill_name_owned) if (harness.active_skill_name) |v| allocator.free(v);
        if (harness.active_skill_description_owned) if (harness.active_skill_description) |v| allocator.free(v);
        if (harness.active_skill_instructions_owned) if (harness.active_skill_instructions) |v| allocator.free(v);
        if (harness.active_skill_path_owned) if (harness.active_skill_path) |v| allocator.free(v);
    }

    const found = try activateSkillByName(&harness, "news-digest");
    try std.testing.expect(found);
    try std.testing.expectEqualStrings("news-digest", harness.active_skill_name.?);
}

test "activateSkillByName returns false when skill not found" {
    const allocator = std.testing.allocator;
    const fs_compat = @import("compat").fs;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const workspace = try fs_compat.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(workspace);

    var harness = struct {
        allocator: std.mem.Allocator,
        workspace_dir: []const u8,
        observer: ?@import("../observability.zig").Observer = null,
        active_skill_name: ?[]const u8 = null,
        active_skill_name_owned: bool = false,
        active_skill_description: ?[]const u8 = null,
        active_skill_description_owned: bool = false,
        active_skill_instructions: ?[]const u8 = null,
        active_skill_instructions_owned: bool = false,
        active_skill_path: ?[]const u8 = null,
        active_skill_path_owned: bool = false,
        active_skill_interactive: bool = false,
    }{
        .allocator = allocator,
        .workspace_dir = workspace,
    };

    const found = try activateSkillByName(&harness, "ghost-skill");
    try std.testing.expect(!found);
    try std.testing.expect(harness.active_skill_name == null);
}

// ── composeFinalReply ────────────────────────────────────────────────────────

// Local enum mirrors for testing: composeFinalReply uses `anytype` so it only
// needs structural compatibility — the values .off / .on / .stream are matched
// by name, not by type identity.
const FakeReasoningMode = enum { off, on, stream };
const FakeUsageMode = enum { off, tokens, full, cost };

const FakeAgent = struct {
    allocator: std.mem.Allocator,
    reasoning_mode: FakeReasoningMode = .off,
    usage_mode: FakeUsageMode = .off,
    model_name: []const u8 = "gpt-4o",
    total_tokens: u64 = 0,
    total_cost_usd: f64 = 0.0,
};

test "composeFinalReply off mode returns base text unchanged" {
    const allocator = std.testing.allocator;
    var agent = FakeAgent{ .allocator = allocator, .reasoning_mode = .off };
    const usage = providers.TokenUsage{};
    const result = try composeFinalReply(&agent, "Hello", "secret thinking", usage);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello", result);
}

test "composeFinalReply on mode prepends reasoning block" {
    const allocator = std.testing.allocator;
    var agent = FakeAgent{ .allocator = allocator, .reasoning_mode = .on };
    const usage = providers.TokenUsage{};
    const result = try composeFinalReply(&agent, "Answer", "step by step", usage);
    defer allocator.free(result);
    try std.testing.expect(std.mem.startsWith(u8, result, "Reasoning:\n> step by step\n"));
    try std.testing.expect(std.mem.endsWith(u8, result, "Answer"));
}

test "composeFinalReply stream mode does not prepend reasoning block" {
    // Regression: .stream mode used to show the block twice — once live during
    // streaming and again via composeFinalReply. Now only .on shows the block.
    const allocator = std.testing.allocator;
    var agent = FakeAgent{ .allocator = allocator, .reasoning_mode = .stream };
    const usage = providers.TokenUsage{};
    const result = try composeFinalReply(&agent, "Answer", "private chain", usage);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Answer", result);
}

test "composeFinalReply on mode with null reasoning_content returns base text" {
    const allocator = std.testing.allocator;
    var agent = FakeAgent{ .allocator = allocator, .reasoning_mode = .on };
    const usage = providers.TokenUsage{};
    const result = try composeFinalReply(&agent, "Answer", null, usage);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Answer", result);
}

test "composeFinalReply on mode with empty reasoning_content returns base text" {
    const allocator = std.testing.allocator;
    var agent = FakeAgent{ .allocator = allocator, .reasoning_mode = .on };
    const usage = providers.TokenUsage{};
    const result = try composeFinalReply(&agent, "Answer", "", usage);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Answer", result);
}

test "composeFinalReply appends token usage when usage_mode is tokens" {
    const allocator = std.testing.allocator;
    var agent = FakeAgent{ .allocator = allocator, .reasoning_mode = .off, .usage_mode = .tokens };
    const usage = providers.TokenUsage{ .total_tokens = 42 };
    const result = try composeFinalReply(&agent, "Hi", null, usage);
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "total_tokens=42") != null);
}

test "composeFinalReply cost mode appends estimated cost" {
    const allocator = std.testing.allocator;
    var agent = FakeAgent{
        .allocator = allocator,
        .reasoning_mode = .off,
        .usage_mode = .cost,
        .total_cost_usd = 0.0123,
    };
    const usage = providers.TokenUsage{ .prompt_tokens = 1000, .completion_tokens = 500, .total_tokens = 1500 };
    const result = try composeFinalReply(&agent, "Hi", null, usage);
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "cost=$0.0075") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "session_cost=$0.0123") != null);
}
