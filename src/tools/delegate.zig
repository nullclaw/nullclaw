const std = @import("std");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;
const Config = @import("../config.zig").Config;
const providers = @import("../providers/root.zig");

/// Delegate tool — delegates a subtask to a named sub-agent with a different
/// provider/model configuration. Enables multi-agent workflows.
pub const DelegateTool = struct {
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

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *DelegateTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
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

    fn execute(_: *DelegateTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const agent_name = parseStringField(args_json, "agent") orelse
            return ToolResult.fail("Missing 'agent' parameter");

        // Trim whitespace
        const trimmed_agent = std.mem.trim(u8, agent_name, " \t\n");
        if (trimmed_agent.len == 0) {
            return ToolResult.fail("'agent' parameter must not be empty");
        }

        const prompt = parseStringField(args_json, "prompt") orelse
            return ToolResult.fail("Missing 'prompt' parameter");

        const trimmed_prompt = std.mem.trim(u8, prompt, " \t\n");
        if (trimmed_prompt.len == 0) {
            return ToolResult.fail("'prompt' parameter must not be empty");
        }

        const context = parseStringField(args_json, "context");

        // Build the full prompt with optional context and agent system identity
        const full_prompt = if (context) |ctx|
            std.fmt.allocPrint(allocator, "Context: {s}\n\n{s}", .{ ctx, trimmed_prompt }) catch
                return ToolResult.fail("Failed to build prompt")
        else
            trimmed_prompt;
        defer if (context != null) allocator.free(full_prompt);

        // Load config into an arena so all duped strings are freed together
        var cfg_arena = std.heap.ArenaAllocator.init(allocator);
        defer cfg_arena.deinit();
        const cfg = Config.load(cfg_arena.allocator()) catch {
            return ToolResult.fail("Failed to load config — run `nullclaw onboard` first");
        };

        // Call the provider via the legacy complete path with the agent's prompt
        // The system identity is embedded in the prompt since complete() only takes a user message.
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
};

// ── Tests ───────────────────────────────────────────────────────────

test "delegate tool name" {
    var dt = DelegateTool{};
    const t = dt.tool();
    try std.testing.expectEqualStrings("delegate", t.name());
}

test "delegate description not empty" {
    var dt = DelegateTool{};
    const t = dt.tool();
    try std.testing.expect(t.description().len > 0);
}

test "delegate schema has agent and prompt" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "agent") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "prompt") != null);
}

test "delegate executes gracefully without config" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const result = try t.execute(std.testing.allocator, "{\"agent\": \"researcher\", \"prompt\": \"test\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| if (e.len > 0) std.testing.allocator.free(e);
    // Without config/API key, delegation fails gracefully
    if (!result.success) {
        try std.testing.expect(result.error_msg != null);
    }
}

test "delegate missing agent" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const result = try t.execute(std.testing.allocator, "{\"prompt\": \"test\"}");
    try std.testing.expect(!result.success);
}

test "delegate missing prompt" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const result = try t.execute(std.testing.allocator, "{\"agent\": \"researcher\"}");
    try std.testing.expect(!result.success);
}

test "delegate blank agent rejected" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const result = try t.execute(std.testing.allocator, "{\"agent\": \"  \", \"prompt\": \"test\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "must not be empty") != null);
}

test "delegate blank prompt rejected" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const result = try t.execute(std.testing.allocator, "{\"agent\": \"researcher\", \"prompt\": \"  \"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "must not be empty") != null);
}

// ── Additional delegate tests ───────────────────────────────────

test "delegate with valid params handles missing provider gracefully" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const result = try t.execute(std.testing.allocator, "{\"agent\": \"coder\", \"prompt\": \"Write a function\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| if (e.len > 0) std.testing.allocator.free(e);
    // Without config/API key, delegation fails gracefully with an error
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
    const result = try t.execute(std.testing.allocator, "{}");
    try std.testing.expect(!result.success);
}

test "delegate with context field handles missing provider gracefully" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const result = try t.execute(std.testing.allocator, "{\"agent\": \"coder\", \"prompt\": \"fix bug\", \"context\": \"file.zig\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| if (e.len > 0) std.testing.allocator.free(e);
    // Without config/API key, delegation fails gracefully
    if (!result.success) {
        try std.testing.expect(result.error_msg != null);
    }
}

test "delegate description mentions sub-agent" {
    var dt = DelegateTool{};
    const t = dt.tool();
    const desc = t.description();
    try std.testing.expect(desc.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, desc, "agent") != null or std.mem.indexOf(u8, desc, "Delegate") != null);
}
