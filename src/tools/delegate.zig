const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const Config = @import("../config.zig").Config;
const NamedAgentConfig = @import("../config.zig").NamedAgentConfig;
const ProviderEntry = @import("../config_types.zig").ProviderEntry;
const provider_names = @import("../provider_names.zig");
const providers = @import("../providers/root.zig");

const TestCompleteFn = *const fn (
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    api_key: ?[]const u8,
    base_url: ?[]const u8,
    native_tools: bool,
    user_agent: ?[]const u8,
    model: []const u8,
    system_prompt: []const u8,
    prompt: []const u8,
    temperature: f64,
) anyerror![]const u8;

var test_complete_agent_prompt_override: ?TestCompleteFn = null;

/// Delegate tool — delegates a subtask to a named sub-agent with a different
/// provider/model configuration. Supports depth enforcement to prevent
/// infinite delegation chains.
pub const DelegateTool = struct {
    /// Named agent configs from the global config (lookup by name).
    agents: []const NamedAgentConfig = &.{},
    /// Provider entries from config for API key/base URL/runtime option lookup.
    configured_providers: []const ProviderEntry = &.{},
    /// Fallback API key if agent-specific key is not set.
    fallback_api_key: ?[]const u8 = null,
    /// Current delegation depth. Incremented for sub-delegates.
    depth: u32 = 0,

    pub const tool_name = "delegate";
    pub const tool_description = "Delegate a subtask to a specialized agent. Use when a task benefits from a different model.";
    pub const tool_params =
        \\{"type":"object","properties":{"agent":{"type":"string","minLength":1,"description":"Name of the agent to delegate to"},"prompt":{"type":"string","minLength":1,"description":"The task/prompt to send to the sub-agent"},"context":{"type":"string","description":"Optional context to prepend"}},"required":["agent","prompt"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *DelegateTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *DelegateTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const agent_name = root.getString(args, "agent") orelse
            return ToolResult.fail("Missing 'agent' parameter");

        const trimmed_agent = std.mem.trim(u8, agent_name, " \t\n");
        if (trimmed_agent.len == 0) {
            return ToolResult.fail("'agent' parameter must not be empty");
        }

        const prompt = root.getString(args, "prompt") orelse
            return ToolResult.fail("Missing 'prompt' parameter");

        const trimmed_prompt = std.mem.trim(u8, prompt, " \t\n");
        if (trimmed_prompt.len == 0) {
            return ToolResult.fail("'prompt' parameter must not be empty");
        }

        const context: ?[]const u8 = root.getString(args, "context");

        // Look up agent config if agents are configured
        const agent_cfg = self.findAgent(trimmed_agent);

        // Depth enforcement: check against agent's max_depth
        if (agent_cfg) |ac| {
            if (self.depth >= ac.max_depth) {
                const msg = std.fmt.allocPrint(
                    allocator,
                    "Delegation depth limit reached ({d}/{d}) for agent '{s}'",
                    .{ self.depth, ac.max_depth, trimmed_agent },
                ) catch return ToolResult.fail("Delegation depth limit reached");
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            }
        } else {
            // No agent config — use default max_depth of 3
            if (self.depth >= 3) {
                return ToolResult.fail("Delegation depth limit reached (default max_depth=3)");
            }
        }

        // Build the full prompt with optional context
        const full_prompt = if (context) |ctx|
            std.fmt.allocPrint(allocator, "Context: {s}\n\n{s}", .{ ctx, trimmed_prompt }) catch
                return ToolResult.fail("Failed to build prompt")
        else
            trimmed_prompt;
        defer if (context != null) allocator.free(full_prompt);

        // Determine system prompt, API key, provider, model from agent config or defaults
        if (agent_cfg) |ac| {
            const resolved_provider_api_key = if (ac.api_key == null)
                try providers.resolveApiKeyFromConfig(allocator, ac.provider, self.configured_providers)
            else
                null;
            defer if (resolved_provider_api_key) |key| allocator.free(key);

            const provider_entry = self.findProviderEntry(ac.provider);
            const api_key = ac.api_key orelse resolved_provider_api_key orelse self.fallback_api_key;
            const sys_prompt = ac.system_prompt orelse "You are a helpful assistant. Respond concisely.";
            const response = completeAgentPrompt(
                allocator,
                ac.provider,
                api_key,
                if (provider_entry) |entry| entry.base_url else null,
                if (provider_entry) |entry| entry.native_tools else true,
                if (provider_entry) |entry| entry.user_agent else null,
                ac.model,
                sys_prompt,
                full_prompt,
                ac.temperature orelse @as(f64, 0.7),
            ) catch |err| {
                const msg = std.fmt.allocPrint(
                    allocator,
                    "Delegation to agent '{s}' failed: {s}",
                    .{ trimmed_agent, @errorName(err) },
                ) catch return ToolResult.fail("Delegation failed");
                return ToolResult{ .success = false, .output = "", .error_msg = msg };
            };

            return ToolResult{ .success = true, .output = response };
        }

        // Fallback: no agent config found — load global config
        var cfg = Config.load(allocator) catch {
            return ToolResult.fail("Failed to load config — run `nullclaw onboard` first");
        };
        defer cfg.deinit();

        const agent_prompt = std.fmt.allocPrint(
            allocator,
            "[System: You are agent '{s}'. Respond concisely and helpfully.]\n\n{s}",
            .{ trimmed_agent, full_prompt },
        ) catch return ToolResult.fail("Failed to build agent prompt");
        defer allocator.free(agent_prompt);

        const response = providers.complete(allocator, &cfg, agent_prompt) catch |err| {
            const msg = std.fmt.allocPrint(
                allocator,
                "Delegation to agent '{s}' failed: {s}",
                .{ trimmed_agent, @errorName(err) },
            ) catch return ToolResult.fail("Delegation failed");
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };

        return ToolResult{ .success = true, .output = response };
    }

    fn findAgent(self: *DelegateTool, name: []const u8) ?NamedAgentConfig {
        for (self.agents) |ac| {
            if (std.mem.eql(u8, ac.name, name)) return ac;
        }
        return null;
    }

    fn findProviderEntry(self: *const DelegateTool, provider_name: []const u8) ?ProviderEntry {
        for (self.configured_providers) |entry| {
            if (provider_names.providerNamesMatch(entry.name, provider_name)) return entry;
        }
        return null;
    }

    fn completeAgentPrompt(
        allocator: std.mem.Allocator,
        provider_name: []const u8,
        api_key: ?[]const u8,
        base_url: ?[]const u8,
        native_tools: bool,
        user_agent: ?[]const u8,
        model: []const u8,
        system_prompt: []const u8,
        prompt: []const u8,
        temperature: f64,
    ) ![]const u8 {
        if (builtin.is_test) {
            if (test_complete_agent_prompt_override) |override| {
                return override(allocator, provider_name, api_key, base_url, native_tools, user_agent, model, system_prompt, prompt, temperature);
            }
        }
        var provider_holder = providers.ProviderHolder.fromConfig(
            allocator,
            provider_name,
            api_key,
            base_url,
            native_tools,
            user_agent,
            null, // max_streaming_prompt_bytes: no limit for delegate calls
        );
        defer provider_holder.deinit();
        return provider_holder.provider().chatWithSystem(
            allocator,
            system_prompt,
            prompt,
            model,
            temperature,
        );
    }
};

// ── Tests ───────────────────────────────────────────────────────────
var test_expected_provider_name: ?[]const u8 = null;
var test_expected_api_key: ?[]const u8 = null;
var test_expected_base_url: ?[]const u8 = null;
var test_expected_native_tools: ?bool = null;
var test_expected_user_agent: ?[]const u8 = null;
var test_expected_model_name: ?[]const u8 = null;
var test_expected_system_prompt: ?[]const u8 = null;
var test_expected_prompt: ?[]const u8 = null;

fn testCompleteAgentPrompt(
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    api_key: ?[]const u8,
    base_url: ?[]const u8,
    native_tools: bool,
    user_agent: ?[]const u8,
    model: []const u8,
    system_prompt: []const u8,
    prompt: []const u8,
    temperature: f64,
) ![]const u8 {
    try std.testing.expectApproxEqAbs(@as(f64, 0.7), temperature, 0.000001);
    if (test_expected_provider_name) |expected| {
        try std.testing.expectEqualStrings(expected, provider_name);
    }
    if (test_expected_api_key) |expected| {
        try std.testing.expect(api_key != null);
        try std.testing.expectEqualStrings(expected, api_key.?);
    }
    if (test_expected_base_url) |expected| {
        try std.testing.expect(base_url != null);
        try std.testing.expectEqualStrings(expected, base_url.?);
    }
    if (test_expected_native_tools) |expected| {
        try std.testing.expectEqual(expected, native_tools);
    }
    if (test_expected_user_agent) |expected| {
        try std.testing.expect(user_agent != null);
        try std.testing.expectEqualStrings(expected, user_agent.?);
    }
    if (test_expected_model_name) |expected| {
        try std.testing.expectEqualStrings(expected, model);
    }
    if (test_expected_system_prompt) |expected| {
        try std.testing.expectEqualStrings(expected, system_prompt);
    }
    if (test_expected_prompt) |expected| {
        try std.testing.expectEqualStrings(expected, prompt);
    }
    return allocator.dupe(u8, "delegate-ok");
}

test "delegate tool name" {
    var dt = DelegateTool{};
    const t = dt.tool();
    try std.testing.expectEqualStrings("delegate", t.name());
}

test "delegate schema has agent and prompt" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "agent") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "prompt") != null);
}

test "delegate executes gracefully without config" {
    const agents = [_]NamedAgentConfig{.{
        .name = "researcher",
        .provider = "test",
        .model = "test",
    }};
    var dt = DelegateTool{ .agents = &agents };
    const t = dt.tool();
    const parsed = try root.parseTestArgs("{\"agent\": \"researcher\", \"prompt\": \"test\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| if (e.len > 0) std.testing.allocator.free(e);
    if (!result.success) {
        try std.testing.expect(result.error_msg != null);
    }
}

test "delegate missing agent" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const parsed = try root.parseTestArgs("{\"prompt\": \"test\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "delegate missing prompt" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const parsed = try root.parseTestArgs("{\"agent\": \"researcher\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "delegate blank agent rejected" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const parsed = try root.parseTestArgs("{\"agent\": \"  \", \"prompt\": \"test\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "must not be empty") != null);
}

test "delegate blank prompt rejected" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const parsed = try root.parseTestArgs("{\"agent\": \"researcher\", \"prompt\": \"  \"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "must not be empty") != null);
}

test "delegate with valid params handles missing provider gracefully" {
    const agents = [_]NamedAgentConfig{.{
        .name = "coder",
        .provider = "test",
        .model = "test",
    }};
    var dt = DelegateTool{ .agents = &agents };
    const t = dt.tool();
    const parsed = try root.parseTestArgs("{\"agent\": \"coder\", \"prompt\": \"Write a function\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| if (e.len > 0) std.testing.allocator.free(e);
    if (!result.success) {
        try std.testing.expect(result.error_msg != null);
    }
}

test "delegate schema has context field" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "context") != null);
}

test "delegate schema has required array" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "required") != null);
}

test "delegate empty JSON rejected" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "delegate with context field handles missing provider gracefully" {
    const agents = [_]NamedAgentConfig{.{
        .name = "coder",
        .provider = "test",
        .model = "test",
    }};
    var dt = DelegateTool{ .agents = &agents };
    const t = dt.tool();
    const parsed = try root.parseTestArgs("{\"agent\": \"coder\", \"prompt\": \"fix bug\", \"context\": \"file.zig\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| if (e.len > 0) std.testing.allocator.free(e);
    if (!result.success) {
        try std.testing.expect(result.error_msg != null);
    }
}

// ── Depth enforcement tests ─────────────────────────────────────

test "delegate depth limit enforced" {
    const agents = [_]NamedAgentConfig{.{
        .name = "researcher",
        .provider = "openrouter",
        .model = "test",
        .max_depth = 3,
    }};
    var dt = DelegateTool{
        .agents = &agents,
        .depth = 3,
    };
    const t = dt.tool();
    const parsed = try root.parseTestArgs("{\"agent\": \"researcher\", \"prompt\": \"test\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| if (e.len > 0) std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "depth limit") != null);
}

test "delegate depth within limit proceeds" {
    const agents = [_]NamedAgentConfig{.{
        .name = "researcher",
        .provider = "openrouter",
        .model = "test",
        .max_depth = 5,
    }};
    var dt = DelegateTool{
        .agents = &agents,
        .depth = 2,
    };
    const t = dt.tool();
    // Will proceed past depth check but fail at provider level (no API key)
    const parsed = try root.parseTestArgs("{\"agent\": \"researcher\", \"prompt\": \"test\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| if (e.len > 0) std.testing.allocator.free(e);
    // Should fail at provider level, not depth
    if (!result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "depth") == null);
    }
}

test "delegate default depth limit at 3" {
    var dt = DelegateTool{
        .depth = 3,
    };
    const t = dt.tool();
    const parsed = try root.parseTestArgs("{\"agent\": \"unknown\", \"prompt\": \"test\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "depth limit") != null);
}

test "delegate per-agent max_depth" {
    const agents = [_]NamedAgentConfig{
        .{ .name = "shallow", .provider = "openrouter", .model = "test", .max_depth = 1 },
        .{ .name = "deep", .provider = "openrouter", .model = "test", .max_depth = 10 },
    };
    var dt = DelegateTool{
        .agents = &agents,
        .depth = 1,
    };
    const t = dt.tool();

    // "shallow" at depth=1 should be blocked (max_depth=1)
    const p1 = try root.parseTestArgs("{\"agent\": \"shallow\", \"prompt\": \"test\"}");
    defer p1.deinit();
    const r1 = try t.execute(std.testing.allocator, p1.value.object);
    defer if (r1.error_msg) |e| if (e.len > 0) std.testing.allocator.free(e);
    try std.testing.expect(!r1.success);
    try std.testing.expect(std.mem.indexOf(u8, r1.error_msg.?, "depth limit") != null);

    // "deep" at depth=1 should proceed (max_depth=10)
    const p2 = try root.parseTestArgs("{\"agent\": \"deep\", \"prompt\": \"test\"}");
    defer p2.deinit();
    const r2 = try t.execute(std.testing.allocator, p2.value.object);
    defer if (r2.output.len > 0) std.testing.allocator.free(r2.output);
    defer if (r2.error_msg) |e| if (e.len > 0) std.testing.allocator.free(e);
    if (!r2.success) {
        // Should fail for provider reasons, not depth
        try std.testing.expect(std.mem.indexOf(u8, r2.error_msg.?, "depth") == null);
    }
}

test "delegate agents config stored" {
    const agents = [_]NamedAgentConfig{.{
        .name = "test",
        .provider = "anthropic",
        .model = "claude",
    }};
    var dt = DelegateTool{
        .agents = &agents,
        .fallback_api_key = "sk-test",
        .depth = 1,
    };
    try std.testing.expectEqual(@as(usize, 1), dt.agents.len);
    try std.testing.expectEqualStrings("test", dt.agents[0].name);
    try std.testing.expectEqualStrings("sk-test", dt.fallback_api_key.?);
    try std.testing.expectEqual(@as(u32, 1), dt.depth);
    _ = dt.tool(); // ensure tool() works
}

test "delegate uses parsed agent model.primary provider ref" {
    const allocator = std.testing.allocator;
    test_complete_agent_prompt_override = testCompleteAgentPrompt;
    defer test_complete_agent_prompt_override = null;
    test_expected_provider_name = "custom:http://127.0.0.1:11434/v1";
    test_expected_model_name = "mock-model";
    test_expected_system_prompt = "You are a coder.";
    test_expected_prompt = "Fix it";
    defer {
        test_expected_provider_name = null;
        test_expected_model_name = null;
        test_expected_system_prompt = null;
        test_expected_prompt = null;
    }

    const json =
        \\{"agents":{"list":[{"id":"coder","model":{"primary":"custom:http://127.0.0.1:11434/v1/mock-model"},"system_prompt":"You are a coder."}]}}
    ;

    var cfg = Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = allocator,
    };
    try cfg.parseJson(json);
    defer {
        if (cfg.agents.len > 0) {
            allocator.free(cfg.agents[0].name);
            allocator.free(cfg.agents[0].provider);
            allocator.free(cfg.agents[0].model);
            if (cfg.agents[0].system_prompt) |sp| allocator.free(sp);
            allocator.free(cfg.agents);
        }
    }

    try std.testing.expectEqual(@as(usize, 1), cfg.agents.len);
    try std.testing.expectEqualStrings("coder", cfg.agents[0].name);
    try std.testing.expectEqualStrings(test_expected_provider_name.?, cfg.agents[0].provider);
    try std.testing.expectEqualStrings("mock-model", cfg.agents[0].model);

    var dt = DelegateTool{ .agents = cfg.agents };
    const tool = dt.tool();
    const parsed = try root.parseTestArgs("{\"agent\":\"coder\",\"prompt\":\"Fix it\"}");
    defer parsed.deinit();

    const result = try tool.execute(allocator, parsed.value.object);
    defer if (result.output.len > 0) allocator.free(result.output);
    defer if (result.error_msg) |e| if (e.len > 0) allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("delegate-ok", result.output);
}

test "delegate uses configured provider entry for key and base_url" {
    const allocator = std.testing.allocator;
    test_complete_agent_prompt_override = testCompleteAgentPrompt;
    defer test_complete_agent_prompt_override = null;
    test_expected_provider_name = "ollama";
    test_expected_api_key = "ollama-key";
    test_expected_base_url = "http://192.168.1.12:11434";
    test_expected_native_tools = false;
    test_expected_user_agent = "nullclaw-test";
    test_expected_model_name = "qwen3.5:cloud";
    test_expected_system_prompt = "You are a coder.";
    test_expected_prompt = "Fix it";
    defer {
        test_expected_provider_name = null;
        test_expected_api_key = null;
        test_expected_base_url = null;
        test_expected_native_tools = null;
        test_expected_user_agent = null;
        test_expected_model_name = null;
        test_expected_system_prompt = null;
        test_expected_prompt = null;
    }

    const agents = [_]NamedAgentConfig{
        .{
            .name = "coder",
            .provider = "ollama",
            .model = "qwen3.5:cloud",
            .system_prompt = "You are a coder.",
        },
    };
    const provider_entries = [_]ProviderEntry{
        .{
            .name = "ollama",
            .api_key = "ollama-key",
            .base_url = "http://192.168.1.12:11434",
            .native_tools = false,
            .user_agent = "nullclaw-test",
        },
    };

    var dt = DelegateTool{
        .agents = &agents,
        .configured_providers = &provider_entries,
        .fallback_api_key = "default-key",
    };
    const tool = dt.tool();
    const parsed = try root.parseTestArgs("{\"agent\":\"coder\",\"prompt\":\"Fix it\"}");
    defer parsed.deinit();

    const result = try tool.execute(allocator, parsed.value.object);
    defer if (result.output.len > 0) allocator.free(result.output);
    defer if (result.error_msg) |e| if (e.len > 0) allocator.free(e);

    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("delegate-ok", result.output);
}
