const std = @import("std");
const agent_mod = @import("agent/root.zig");
const config_mod = @import("config.zig");
const config_types = @import("config_types.zig");
const observability = @import("observability.zig");
const provider_names = @import("provider_names.zig");
const providers = @import("providers/root.zig");
const security = @import("security/policy.zig");
const subagent_mod = @import("subagent.zig");
const tools_mod = @import("tools/root.zig");
const memory_mod = @import("memory/root.zig");
const bootstrap_mod = @import("bootstrap/root.zig");

fn findProviderEntry(
    provider_name: []const u8,
    entries: []const config_types.ProviderEntry,
) ?config_types.ProviderEntry {
    for (entries) |entry| {
        if (provider_names.providerNamesMatchIgnoreCase(entry.name, provider_name)) return entry;
    }
    return null;
}

fn buildSubagentSystemPrompt(
    allocator: std.mem.Allocator,
    system_prompt: []const u8,
    workspace_dir: []const u8,
    tools: []const tools_mod.Tool,
    observer: ?observability.Observer,
) ![]const u8 {
    const tool_instructions = try agent_mod.prompt.buildToolInstructions(allocator, tools);
    defer allocator.free(tool_instructions);

    const skills_section = try agent_mod.prompt.buildSkillsSection(allocator, workspace_dir, observer);
    defer allocator.free(skills_section);

    if (skills_section.len > 0) {
        return std.fmt.allocPrint(
            allocator,
            "{s}\n\n{s}{s}",
            .{ system_prompt, skills_section, tool_instructions },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "{s}\n\n{s}",
        .{ system_prompt, tool_instructions },
    );
}

/// Execute a spawned subagent task with the full agent tool loop, constrained
/// to the restricted `subagentTools` tool set.
pub fn runTaskWithTools(
    allocator: std.mem.Allocator,
    request: subagent_mod.TaskRunRequest,
) ![]const u8 {
    const provider_entry = findProviderEntry(request.default_provider, request.configured_providers);
    const provider_base_url = if (provider_entry) |entry| entry.base_url else null;
    const provider_native_tools = if (provider_entry) |entry| entry.native_tools else true;
    const provider_user_agent = if (provider_entry) |entry| entry.user_agent else null;
    const provider_api_mode = if (provider_entry) |entry| entry.api_mode else .chat_completions;
    const provider_max_streaming_prompt_bytes = if (provider_entry) |entry| entry.max_streaming_prompt_bytes else null;
    const provider_extra_body_params = if (provider_entry) |entry| entry.extra_body_params else null;

    var provider_holder = providers.ProviderHolder.fromConfigWithApiMode(
        allocator,
        request.default_provider,
        request.api_key,
        provider_base_url,
        provider_native_tools,
        provider_user_agent,
        provider_api_mode,
        provider_max_streaming_prompt_bytes,
        if (provider_entry) |entry| entry.chat_template_enable_thinking_param else false,
        provider_extra_body_params,
    );
    defer provider_holder.deinit();

    var tracker = security.RateTracker.init(allocator, request.max_actions_per_hour);
    defer tracker.deinit();
    var policy = security.SecurityPolicy{
        .autonomy = request.autonomy,
        .workspace_dir = request.workspace_dir,
        .workspace_only = request.workspace_only,
        .allowed_commands = security.resolveAllowedCommands(request.autonomy, request.allowed_commands),
        .max_actions_per_hour = request.max_actions_per_hour,
        .require_approval_for_medium_risk = request.require_approval_for_medium_risk,
        .block_high_risk_commands = request.block_high_risk_commands,
        .allow_raw_url_chars = request.allow_raw_url_chars,
        .tracker = &tracker,
    };

    var mem_rt = memory_mod.initRuntime(allocator, &request.memory_config, request.workspace_dir);
    defer if (mem_rt) |*rt| rt.deinit();
    const mem_opt: ?memory_mod.Memory = if (mem_rt) |rt| rt.memory else null;

    const bootstrap_provider: ?bootstrap_mod.BootstrapProvider = bootstrap_mod.createProvider(
        allocator,
        request.memory_config.backend,
        mem_opt,
        request.workspace_dir,
    ) catch null;
    defer if (bootstrap_provider) |bp| bp.deinit();

    const tools = try tools_mod.subagentTools(allocator, request.workspace_dir, .{
        .http_enabled = request.http_enabled,
        .http_allowed_domains = request.http_allowed_domains,
        .http_max_response_size = request.http_max_response_size,
        .http_timeout_secs = request.http_timeout_secs,
        .allowed_paths = request.allowed_paths,
        .policy = &policy,
        .tools_config = request.tools_config,
        .bootstrap_provider = bootstrap_provider,
        .backend_name = request.memory_config.backend,
    });
    defer tools_mod.deinitTools(allocator, tools);

    const effective_model = request.default_model orelse "anthropic/claude-sonnet-4";
    var cfg = config_mod.Config{
        .workspace_dir = request.workspace_dir,
        .config_path = "/tmp/nullclaw-subagent.json",
        .allocator = allocator,
        .default_provider = request.default_provider,
        .default_model = effective_model,
        .default_temperature = request.temperature,
        .providers = request.configured_providers,
        .memory = request.memory_config,
        .memory_backend = request.memory_config.backend,
        .agent = .{
            .max_tool_iterations = request.max_tool_iterations,
        },
        .autonomy = .{
            .level = request.autonomy,
            .workspace_only = request.workspace_only,
            .max_actions_per_hour = request.max_actions_per_hour,
            .require_approval_for_medium_risk = request.require_approval_for_medium_risk,
            .block_high_risk_commands = request.block_high_risk_commands,
            .allow_raw_url_chars = request.allow_raw_url_chars,
            .allowed_commands = request.allowed_commands,
            .allowed_paths = request.allowed_paths,
        },
        .http_request = .{
            .enabled = request.http_enabled,
            .allowed_domains = request.http_allowed_domains,
            .max_response_size = request.http_max_response_size,
            .timeout_secs = request.http_timeout_secs,
        },
        .tools = request.tools_config,
    };

    var noop_obs = observability.NoopObserver{};
    const obs = request.observer orelse noop_obs.observer();
    var agent = try agent_mod.Agent.fromConfig(
        allocator,
        &cfg,
        provider_holder.provider(),
        tools,
        mem_opt,
        obs,
    );
    defer agent.deinit();
    agent.policy = &policy;

    const full_system = try buildSubagentSystemPrompt(
        allocator,
        request.system_prompt,
        request.workspace_dir,
        tools,
        obs,
    );
    // After append, ownership transfers to agent.history; agent.deinit() frees it.
    // Use catch to free only if append itself fails (avoids double-free with deinit).
    agent.history.append(allocator, .{
        .role = .system,
        .content = full_system,
    }) catch |err| {
        allocator.free(full_system);
        return err;
    };
    agent.has_system_prompt = true;
    agent.system_prompt_has_conversation_context = false;
    agent.system_prompt_conversation_context_fingerprint = null;
    agent.workspace_prompt_fingerprint = agent_mod.prompt.workspacePromptFingerprint(allocator, request.workspace_dir, agent.bootstrap, null) catch null;

    return agent.turn(request.task);
}

test "findProviderEntry matches case-insensitively" {
    const entries = [_]config_types.ProviderEntry{
        .{ .name = "CustomGW", .base_url = "https://example.com/v1" },
    };
    const found = findProviderEntry("customgw", &entries) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("https://example.com/v1", found.base_url.?);
}

test "findProviderEntry matches provider aliases" {
    const entries = [_]config_types.ProviderEntry{
        .{ .name = "azure", .base_url = "https://resource.openai.azure.com/openai/v1" },
    };
    const found = findProviderEntry("AZURE-OPENAI", &entries) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("https://resource.openai.azure.com/openai/v1", found.base_url.?);
}

test "findProviderEntry threads max_streaming_prompt_bytes from entry" {
    // GAP-20a: findProviderEntry must return the full ProviderEntry including
    // max_streaming_prompt_bytes so runTaskWithTools can thread it to the holder.
    const entries = [_]config_types.ProviderEntry{
        .{ .name = "groq", .api_key = "gsk_test", .max_streaming_prompt_bytes = 65536 },
    };
    const found = findProviderEntry("groq", &entries) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?usize, 65536), found.max_streaming_prompt_bytes);
}

test "findProviderEntry returns null max_streaming_prompt_bytes when not configured" {
    // GAP-20b: When the provider entry does not set max_streaming_prompt_bytes
    // the field must default to null (no limit, always stream).
    const entries = [_]config_types.ProviderEntry{
        .{ .name = "openai", .api_key = "sk-test" },
    };
    const found = findProviderEntry("openai", &entries) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?usize, null), found.max_streaming_prompt_bytes);
}

test "findProviderEntry threads api_mode from entry" {
    const entries = [_]config_types.ProviderEntry{
        .{ .name = "sub2api", .api_key = "sk-test", .api_mode = .responses },
    };
    const found = findProviderEntry("sub2api", &entries) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(config_types.ProviderEntry.ApiMode.responses, found.api_mode);
}

test "findProviderEntry threads chat_template_enable_thinking_param from entry" {
    const entries = [_]config_types.ProviderEntry{
        .{ .name = "custom:https://example.com/v1", .api_key = "sk-test", .chat_template_enable_thinking_param = true },
    };
    const found = findProviderEntry("custom:https://example.com/v1", &entries) orelse return error.TestUnexpectedResult;
    try std.testing.expect(found.chat_template_enable_thinking_param);
}

test "findProviderEntry threads extra_body_params from entry" {
    const entries = [_]config_types.ProviderEntry{
        .{ .name = "groq", .api_key = "sk-test", .extra_body_params = "{\"seed\":42}" },
    };
    const found = findProviderEntry("groq", &entries) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("{\"seed\":42}", found.extra_body_params.?);
}

test "findProviderEntry returns null when provider not in list" {
    // GAP-20c: When no entry matches, findProviderEntry returns null and
    // runTaskWithTools falls back to null for max_streaming_prompt_bytes,
    // meaning no streaming limit is applied.
    const entries = [_]config_types.ProviderEntry{
        .{ .name = "openai", .api_key = "sk-test" },
    };
    try std.testing.expect(findProviderEntry("anthropic", &entries) == null);
}

test "buildSubagentSystemPrompt includes installed skills before tool instructions" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try @import("compat").fs.Dir.wrap(tmp.dir).makePath("skills/commit");

    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/commit/skill.json", .{});
        defer f.close();
        try f.writeAll("{\"name\": \"commit\", \"description\": \"Git commit helper\", \"always\": true}");
    }
    {
        const f = try @import("compat").fs.Dir.wrap(tmp.dir).createFile("skills/commit/SKILL.md", .{});
        defer f.close();
        try f.writeAll("Always stage before committing.");
    }

    const workspace_dir = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(workspace_dir);

    const no_tools = [_]tools_mod.Tool{};
    const prompt = try buildSubagentSystemPrompt(
        allocator,
        "You are a background subagent.",
        workspace_dir,
        no_tools[0..],
        null,
    );
    defer allocator.free(prompt);

    const skills_idx = std.mem.indexOf(u8, prompt, "## Skills") orelse return error.TestUnexpectedResult;
    const tools_idx = std.mem.indexOf(u8, prompt, "## Tool Use Protocol") orelse return error.TestUnexpectedResult;

    try std.testing.expect(std.mem.indexOf(u8, prompt, "Always stage before committing.") != null);
    try std.testing.expect(skills_idx < tools_idx);
}
