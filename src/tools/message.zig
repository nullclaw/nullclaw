//! Message Tool — proactive channel routing.
//!
//! Allows the agent to send messages to any channel, not just reply
//! to the current one. Used for cross-channel routing, cron delivery,
//! subagent announcements.

const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const bus = @import("../bus.zig");

/// Message tool — sends a message to a specific channel/chat via the bus.
pub const MessageTool = struct {
    event_bus: ?*bus.Bus = null,
    /// Default channel (set per-turn by agent loop).
    default_channel: ?[]const u8 = null,
    /// Default chat_id (set per-turn by agent loop).
    default_chat_id: ?[]const u8 = null,
    /// Tracks whether a message was sent during the current agent turn.
    sent_in_round: bool = false,
    allocator: std.mem.Allocator = undefined,

    pub const tool_name = "message";
    pub const tool_description = "Send a message to a channel. If channel/chat_id are omitted, sends to the current conversation. Content supports attachment markers like [FILE:/abs/path], [DOCUMENT:/abs/path], [IMAGE:/abs/path] on marker-aware channels.";
    pub const tool_params =
        \\{"type":"object","properties":{"content":{"type":"string","minLength":1,"description":"Message text to send"},"channel":{"type":"string","description":"Target channel (telegram, discord, slack, etc.). Defaults to current."},"chat_id":{"type":"string","description":"Target chat/room ID. Defaults to current."}},"required":["content"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *MessageTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    /// Set the context for the current turn (called before agent.turn).
    pub fn setContext(self: *MessageTool, channel: ?[]const u8, chat_id: ?[]const u8) void {
        self.default_channel = channel;
        self.default_chat_id = chat_id;
        self.sent_in_round = false;
    }

    /// Check if a message was sent during this round.
    pub fn hasMessageBeenSent(self: *const MessageTool) bool {
        return self.sent_in_round;
    }

    pub fn execute(self: *MessageTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const content = root.getString(args, "content") orelse
            return ToolResult.fail("Missing required 'content' parameter");

        if (std.mem.trim(u8, content, " \t\n\r").len == 0)
            return ToolResult.fail("'content' must not be empty");

        const channel = root.getString(args, "channel") orelse
            (self.default_channel orelse
                return ToolResult.fail("No channel specified and no default channel set"));

        const chat_id = root.getString(args, "chat_id") orelse
            (self.default_chat_id orelse
                return ToolResult.fail("No chat_id specified and no default chat_id set"));

        const event_bus = self.event_bus orelse
            return ToolResult.fail("Message tool not connected to event bus");

        const msg = bus.makeOutbound(allocator, channel, chat_id, content) catch
            return ToolResult.fail("Failed to create outbound message");

        event_bus.publishOutbound(msg) catch {
            msg.deinit(allocator);
            return ToolResult.fail("Bus is closed, cannot send message");
        };

        self.sent_in_round = true;

        const result = std.fmt.allocPrint(
            allocator,
            "Message sent to {s}:{s} ({d} chars)",
            .{ channel, chat_id, content.len },
        ) catch return ToolResult.ok("Message sent");

        return ToolResult{ .success = true, .output = result };
    }
};

// ══════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════

const testing = std.testing;

test "MessageTool name and description" {
    var mt = MessageTool{};
    const t = mt.tool();
    try testing.expectEqualStrings("message", t.name());
    try testing.expect(t.description().len > 0);
    try testing.expect(t.parametersJson()[0] == '{');
}

test "MessageTool execute without bus fails" {
    var mt = MessageTool{};
    const parsed = try root.parseTestArgs("{\"content\":\"hello\",\"channel\":\"tg\",\"chat_id\":\"c1\"}");
    defer parsed.deinit();
    const result = try mt.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expectEqualStrings("Message tool not connected to event bus", result.error_msg.?);
}

test "MessageTool execute without content fails" {
    var event_bus = bus.Bus.init();
    defer event_bus.close();
    var mt = MessageTool{ .event_bus = &event_bus };
    const parsed = try root.parseTestArgs("{\"channel\":\"tg\",\"chat_id\":\"c1\"}");
    defer parsed.deinit();
    const result = try mt.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expectEqualStrings("Missing required 'content' parameter", result.error_msg.?);
}

test "MessageTool execute with empty content fails" {
    var event_bus = bus.Bus.init();
    defer event_bus.close();
    var mt = MessageTool{ .event_bus = &event_bus };
    const parsed = try root.parseTestArgs("{\"content\":\"  \",\"channel\":\"tg\",\"chat_id\":\"c1\"}");
    defer parsed.deinit();
    const result = try mt.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expectEqualStrings("'content' must not be empty", result.error_msg.?);
}

test "MessageTool execute without channel uses default" {
    var event_bus = bus.Bus.init();
    defer event_bus.close();
    var mt = MessageTool{
        .event_bus = &event_bus,
        .default_channel = "telegram",
        .default_chat_id = "chat42",
    };
    const parsed = try root.parseTestArgs("{\"content\":\"hello\"}");
    defer parsed.deinit();
    const result = try mt.execute(testing.allocator, parsed.value.object);
    try testing.expect(result.success);
    try testing.expect(std.mem.indexOf(u8, result.output, "telegram") != null);
    // Free the allocated output
    testing.allocator.free(result.output);

    // Consume and free the bus message
    var msg = event_bus.consumeOutbound().?;
    msg.deinit(testing.allocator);
}

test "MessageTool execute with explicit channel overrides default" {
    var event_bus = bus.Bus.init();
    defer event_bus.close();
    var mt = MessageTool{
        .event_bus = &event_bus,
        .default_channel = "telegram",
        .default_chat_id = "chat42",
    };
    const parsed = try root.parseTestArgs("{\"content\":\"hi\",\"channel\":\"discord\",\"chat_id\":\"room1\"}");
    defer parsed.deinit();
    const result = try mt.execute(testing.allocator, parsed.value.object);
    try testing.expect(result.success);
    try testing.expect(std.mem.indexOf(u8, result.output, "discord") != null);
    testing.allocator.free(result.output);

    var msg = event_bus.consumeOutbound().?;
    defer msg.deinit(testing.allocator);
    try testing.expectEqualStrings("discord", msg.channel);
    try testing.expectEqualStrings("room1", msg.chat_id);
    try testing.expectEqualStrings("hi", msg.content);
}

test "MessageTool setContext and hasMessageBeenSent" {
    var mt = MessageTool{};
    try testing.expect(!mt.hasMessageBeenSent());

    mt.setContext("telegram", "c1");
    try testing.expectEqualStrings("telegram", mt.default_channel.?);
    try testing.expectEqualStrings("c1", mt.default_chat_id.?);
    try testing.expect(!mt.hasMessageBeenSent());
}

test "MessageTool sent_in_round is set after successful send" {
    var event_bus = bus.Bus.init();
    defer event_bus.close();
    var mt = MessageTool{
        .event_bus = &event_bus,
        .default_channel = "tg",
        .default_chat_id = "c1",
    };

    try testing.expect(!mt.hasMessageBeenSent());
    const parsed = try root.parseTestArgs("{\"content\":\"ping\"}");
    defer parsed.deinit();
    const result = try mt.execute(testing.allocator, parsed.value.object);
    try testing.expect(result.success);
    testing.allocator.free(result.output);
    try testing.expect(mt.hasMessageBeenSent());

    // Reset on setContext
    mt.setContext("discord", "c2");
    try testing.expect(!mt.hasMessageBeenSent());

    // Consume bus message
    var msg = event_bus.consumeOutbound().?;
    msg.deinit(testing.allocator);
}

test "MessageTool no channel and no default fails" {
    var event_bus = bus.Bus.init();
    defer event_bus.close();
    var mt = MessageTool{ .event_bus = &event_bus };
    const parsed = try root.parseTestArgs("{\"content\":\"hello\"}");
    defer parsed.deinit();
    const result = try mt.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expectEqualStrings("No channel specified and no default channel set", result.error_msg.?);
}

test "MessageTool closed bus fails gracefully" {
    var event_bus = bus.Bus.init();
    event_bus.close();
    var mt = MessageTool{
        .event_bus = &event_bus,
        .default_channel = "tg",
        .default_chat_id = "c1",
    };
    const parsed = try root.parseTestArgs("{\"content\":\"hello\"}");
    defer parsed.deinit();
    const result = try mt.execute(testing.allocator, parsed.value.object);
    try testing.expect(!result.success);
    try testing.expectEqualStrings("Bus is closed, cannot send message", result.error_msg.?);
}
