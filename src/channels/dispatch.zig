const std = @import("std");
const root = @import("root.zig");

/// Message dispatch — routes incoming ChannelMessages to the agent,
/// routes agent responses back to the originating channel.
///
/// This module replaces the Rust channels/mod.rs orchestration:
/// - start_channels, process_channel_message, build_system_prompt
///
/// Zig doesn't have async/await, so channels will be started
/// synchronously or via thread spawning.
pub const ChannelRegistry = struct {
    allocator: std.mem.Allocator,
    channels: std.ArrayListUnmanaged(root.Channel),

    pub fn init(allocator: std.mem.Allocator) ChannelRegistry {
        return .{
            .allocator = allocator,
            .channels = .empty,
        };
    }

    pub fn deinit(self: *ChannelRegistry) void {
        self.channels.deinit(self.allocator);
    }

    pub fn register(self: *ChannelRegistry, ch: root.Channel) !void {
        try self.channels.append(self.allocator, ch);
    }

    pub fn count(self: *const ChannelRegistry) usize {
        return self.channels.items.len;
    }

    /// Find a channel by name.
    pub fn findByName(self: *const ChannelRegistry, channel_name: []const u8) ?root.Channel {
        for (self.channels.items) |ch| {
            if (std.mem.eql(u8, ch.name(), channel_name)) return ch;
        }
        return null;
    }

    /// Start all registered channels.
    pub fn startAll(self: *ChannelRegistry) !void {
        for (self.channels.items) |ch| {
            try ch.start();
        }
    }

    /// Stop all registered channels.
    pub fn stopAll(self: *ChannelRegistry) void {
        for (self.channels.items) |ch| {
            ch.stop();
        }
    }

    /// Run health checks on all channels.
    pub fn healthCheckAll(self: *const ChannelRegistry) HealthReport {
        var healthy: usize = 0;
        var unhealthy: usize = 0;
        for (self.channels.items) |ch| {
            if (ch.healthCheck()) {
                healthy += 1;
            } else {
                unhealthy += 1;
            }
        }
        return .{ .healthy = healthy, .unhealthy = unhealthy, .total = self.channels.items.len };
    }

    /// Get names of all registered channels.
    pub fn channelNames(self: *const ChannelRegistry, allocator: std.mem.Allocator) ![][]const u8 {
        var names: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer names.deinit(allocator);
        for (self.channels.items) |ch| {
            try names.append(allocator, ch.name());
        }
        return names.toOwnedSlice(allocator);
    }
};

pub const HealthReport = struct {
    healthy: usize,
    unhealthy: usize,
    total: usize,

    pub fn allHealthy(self: HealthReport) bool {
        return self.unhealthy == 0 and self.total > 0;
    }
};

/// Build a system prompt with channel context.
pub fn buildSystemPrompt(
    allocator: std.mem.Allocator,
    base_prompt: []const u8,
    channel_name: []const u8,
    identity_name: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}\n\nYou are {s}. You are responding on the {s} channel.",
        .{ base_prompt, identity_name, channel_name },
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "channel registry init and count" {
    const allocator = std.testing.allocator;
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try std.testing.expectEqual(@as(usize, 0), reg.count());
}

test "channel registry register and find" {
    const allocator = std.testing.allocator;
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();

    var cli_ch = @import("cli.zig").CliChannel.init(allocator);
    try reg.register(cli_ch.channel());

    try std.testing.expectEqual(@as(usize, 1), reg.count());
    try std.testing.expect(reg.findByName("cli") != null);
    try std.testing.expect(reg.findByName("nonexistent") == null);
}

test "channel registry health check all" {
    const allocator = std.testing.allocator;
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();

    var cli_ch = @import("cli.zig").CliChannel.init(allocator);
    try reg.register(cli_ch.channel());

    const report = reg.healthCheckAll();
    try std.testing.expectEqual(@as(usize, 1), report.healthy);
    try std.testing.expectEqual(@as(usize, 0), report.unhealthy);
    try std.testing.expect(report.allHealthy());
}

test "channel registry channel names" {
    const allocator = std.testing.allocator;
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();

    var cli_ch = @import("cli.zig").CliChannel.init(allocator);
    try reg.register(cli_ch.channel());

    const names = try reg.channelNames(allocator);
    defer allocator.free(names);
    try std.testing.expectEqual(@as(usize, 1), names.len);
    try std.testing.expectEqualStrings("cli", names[0]);
}

test "health report all healthy" {
    const report = HealthReport{ .healthy = 3, .unhealthy = 0, .total = 3 };
    try std.testing.expect(report.allHealthy());
}

test "health report not all healthy" {
    const report = HealthReport{ .healthy = 2, .unhealthy = 1, .total = 3 };
    try std.testing.expect(!report.allHealthy());
}

test "health report empty is not healthy" {
    const report = HealthReport{ .healthy = 0, .unhealthy = 0, .total = 0 };
    try std.testing.expect(!report.allHealthy());
}

test "build system prompt" {
    const allocator = std.testing.allocator;
    const prompt = try buildSystemPrompt(allocator, "Be helpful.", "telegram", "nullclaw");
    defer allocator.free(prompt);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "Be helpful.") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "nullclaw") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "telegram") != null);
}
