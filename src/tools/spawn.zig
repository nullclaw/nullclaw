const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const SubagentManager = @import("../subagent.zig").SubagentManager;

/// Spawn tool — launches a background subagent to work on a task asynchronously.
/// Returns a task ID immediately. Results are delivered as system messages.
pub const SpawnTool = struct {
    manager: ?*SubagentManager = null,
    default_channel: ?[]const u8 = null,
    default_chat_id: ?[]const u8 = null,

    pub const tool_name = "spawn";
    pub const tool_description = "Spawn a background subagent to work on a task asynchronously. Returns a task ID immediately. Results are delivered as system messages when complete.";
    pub const tool_params =
        \\{"type":"object","properties":{"task":{"type":"string","minLength":1,"description":"The task/prompt for the subagent"},"label":{"type":"string","description":"Optional human-readable label for tracking"},"agent":{"type":"string","description":"Optional named agent profile from agents.list for provider/model override"}},"required":["task"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *SpawnTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *SpawnTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const task = root.getString(args, "task") orelse
            return ToolResult.fail("Missing 'task' parameter");

        const trimmed_task = std.mem.trim(u8, task, " \t\n");
        if (trimmed_task.len == 0) {
            return ToolResult.fail("'task' must not be empty");
        }

        const label = root.getString(args, "label") orelse "subagent";
        const agent_name = if (root.getString(args, "agent")) |raw| blk: {
            const trimmed = std.mem.trim(u8, raw, " \t\n");
            if (trimmed.len == 0) {
                return ToolResult.fail("'agent' must not be empty");
            }
            break :blk trimmed;
        } else null;

        const manager = self.manager orelse
            return ToolResult.fail("Spawn tool not connected to SubagentManager");

        const channel = self.default_channel orelse "system";
        const chat_id = self.default_chat_id orelse "agent";

        const task_id = manager.spawnWithAgent(trimmed_task, label, channel, chat_id, agent_name) catch |err| {
            return switch (err) {
                error.TooManyConcurrentSubagents => ToolResult.fail("Too many concurrent subagents. Wait for some to complete."),
                error.UnknownAgent => ToolResult.fail("Unknown named agent profile"),
                else => ToolResult.fail("Failed to spawn subagent"),
            };
        };

        const msg = std.fmt.allocPrint(
            allocator,
            "Subagent '{s}' spawned with task_id={d}. Results will be delivered as system messages.",
            .{ label, task_id },
        ) catch return ToolResult.ok("Subagent spawned");

        return ToolResult{ .success = true, .output = msg };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "spawn tool name" {
    var st = SpawnTool{};
    const t = st.tool();
    try std.testing.expectEqualStrings("spawn", t.name());
}

test "spawn tool description" {
    var st = SpawnTool{};
    const t = st.tool();
    try std.testing.expect(t.description().len > 0);
}

test "spawn tool schema has task" {
    var st = SpawnTool{};
    const t = st.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "task") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "label") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "agent") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "required") != null);
}

test "spawn missing task parameter" {
    var st = SpawnTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"label\": \"test\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "task") != null);
}

test "spawn empty task rejected" {
    var st = SpawnTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"task\": \"  \"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "empty") != null);
}

test "spawn blank agent rejected" {
    var st = SpawnTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"task\": \"do something\", \"agent\": \"   \"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "must not be empty") != null);
}

test "spawn without manager fails" {
    var st = SpawnTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"task\": \"do something\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "SubagentManager") != null);
}

test "spawn empty JSON rejected" {
    var st = SpawnTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "spawn with unknown named agent fails" {
    const subagent = @import("../subagent.zig");
    const config = @import("../config.zig");

    const cfg = config.Config{
        .workspace_dir = "/tmp/yc",
        .config_path = "/tmp/yc/config.json",
        .allocator = std.testing.allocator,
    };
    var manager = subagent.SubagentManager.init(std.testing.allocator, &cfg, null, .{});
    defer manager.deinit();

    var st = SpawnTool{ .manager = &manager };
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"task\": \"do something\", \"agent\": \"missing\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown") != null);
}
