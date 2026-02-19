const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const Config = @import("../config.zig").Config;
const NamedAgentConfig = @import("../config.zig").NamedAgentConfig;
const providers = @import("../providers/root.zig");

/// Delegate tool — delegates a subtask to a named sub-agent with a different
/// provider/model configuration. Supports depth enforcement to prevent
/// infinite delegation chains.
pub const DelegateTool = struct {
    /// Named agent configs from the global config (lookup by name).
    agents: []const NamedAgentConfig = &.{},
    /// Fallback API key if agent-specific key is not set.
    fallback_api_key: ?[]const u8 = null,
    /// Current delegation depth. Incremented for sub-delegates.
    depth: u32 = 0,

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *DelegateTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args: JsonObjectMap) anyerror!ToolResult {
        const self: *DelegateTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "delegate";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Delegate a subtask to a specialized agent. Use when a task benefits from a different model.";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"agent":{"type":"string","minLength":1,"description":"Name of the agent to delegate to"},"prompt":{"type":"string","minLength":1,"description":"The task/prompt to send to the sub-agent"},"context":{"type":"string","description":"Optional context to prepend"}},"required":["agent","prompt"]}
        ;
    }

    fn execute(self: *DelegateTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
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
                return ToolResult.fail(msg);
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
            // Use agent-specific config via completeWithSystem
            const api_key = ac.api_key orelse self.fallback_api_key;
            const sys_prompt = ac.system_prompt orelse "You are a helpful assistant. Respond concisely.";

            const cfg = .{
                .api_key = api_key,
                .default_provider = ac.provider,
                .default_model = @as(?[]const u8, ac.model),
                .temperature = ac.temperature orelse @as(f64, 0.7),
                .max_tokens = @as(?u64, null),
            };

            const response = providers.completeWithSystem(allocator, &cfg, sys_prompt, full_prompt) catch |err| {
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
        var cfg_arena = std.heap.ArenaAllocator.init(allocator);
        defer cfg_arena.deinit();
        const cfg = Config.load(cfg_arena.allocator()) catch {
            return ToolResult.fail("Failed to load config — run `nullclaw onboard` first");
        };

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
};

// ── Tests ───────────────────────────────────────────────────────────

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
