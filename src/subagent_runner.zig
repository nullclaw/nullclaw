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

    var provider_holder = providers.ProviderHolder.fromConfig(
        allocator,
        request.default_provider,
        request.api_key,
        provider_base_url,
        provider_native_tools,
        provider_user_agent,
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

    const tool_instructions = try agent_mod.prompt.buildToolInstructions(allocator, tools);
    defer allocator.free(tool_instructions);

    const full_system = try std.fmt.allocPrint(
        allocator,
        "{s}\n\n{s}",
        .{ request.system_prompt, tool_instructions },
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
