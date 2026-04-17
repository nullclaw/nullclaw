const std = @import("std");
const std_compat = @import("compat");
const Allocator = std.mem.Allocator;
const root = @import("root.zig");
const bus = @import("../bus.zig");
const channel_outbox = @import("outbox.zig");
const outbound = @import("../outbound.zig");
const Atomic = @import("../portable_atomic.zig").Atomic;
const thread_stacks = @import("../thread_stacks.zig");
const builtin = @import("builtin");

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
    channels: std.ArrayListUnmanaged(ChannelEntry),

    const ChannelEntry = struct {
        channel: root.Channel,
        account_id: []const u8 = "default",
    };

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
        try self.channels.append(self.allocator, .{ .channel = ch });
    }

    pub fn registerWithAccount(self: *ChannelRegistry, ch: root.Channel, account_id: []const u8) !void {
        try self.channels.append(self.allocator, .{
            .channel = ch,
            .account_id = account_id,
        });
    }

    pub fn count(self: *const ChannelRegistry) usize {
        return self.channels.items.len;
    }

    /// Find a channel by name.
    pub fn findByName(self: *const ChannelRegistry, channel_name: []const u8) ?root.Channel {
        for (self.channels.items) |entry| {
            if (std.mem.eql(u8, entry.channel.name(), channel_name)) return entry.channel;
        }
        return null;
    }

    pub fn findByNameAccount(self: *const ChannelRegistry, channel_name: []const u8, account_id: []const u8) ?root.Channel {
        for (self.channels.items) |entry| {
            if (std.mem.eql(u8, entry.channel.name(), channel_name) and
                std.mem.eql(u8, entry.account_id, account_id))
            {
                return entry.channel;
            }
        }
        return null;
    }

    /// Start all registered channels.
    pub fn startAll(self: *ChannelRegistry) !void {
        for (self.channels.items) |entry| {
            try entry.channel.start();
        }
    }

    /// Stop all registered channels.
    pub fn stopAll(self: *ChannelRegistry) void {
        for (self.channels.items) |entry| {
            entry.channel.stop();
        }
    }

    /// Run health checks on all channels.
    pub fn healthCheckAll(self: *const ChannelRegistry) HealthReport {
        var healthy: usize = 0;
        var unhealthy: usize = 0;
        for (self.channels.items) |entry| {
            if (entry.channel.healthCheck()) {
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
        for (self.channels.items) |entry| {
            try names.append(allocator, entry.channel.name());
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
// Outbound Dispatch Loop
// ════════════════════════════════════════════════════════════════════════════

/// Counters for the outbound dispatch loop (all atomic for thread safety).
pub const DispatchStats = struct {
    dispatched: Atomic(u64) = Atomic(u64).init(0),
    errors: Atomic(u64) = Atomic(u64).init(0),
    channel_not_found: Atomic(u64) = Atomic(u64).init(0),

    pub fn getDispatched(self: *const DispatchStats) u64 {
        return self.dispatched.load(.monotonic);
    }

    pub fn getErrors(self: *const DispatchStats) u64 {
        return self.errors.load(.monotonic);
    }

    pub fn getChannelNotFound(self: *const DispatchStats) u64 {
        return self.channel_not_found.load(.monotonic);
    }
};

const DraftMessageState = struct {
    key: []u8,
    buffer: std.ArrayListUnmanaged(u8) = .empty,
    message_ref: ?root.Channel.MessageRef = null,

    fn deinit(self: *DraftMessageState, allocator: Allocator) void {
        if (self.message_ref) |message_ref| message_ref.deinit(allocator);
        self.buffer.deinit(allocator);
        allocator.free(self.key);
    }
};

const DraftMessageMap = std.StringHashMapUnmanaged(DraftMessageState);

pub fn supportsDraftStreaming(channel: root.Channel) bool {
    return channel.supportsTrackedDrafts();
}

/// Run the outbound dispatch loop. Blocks until the bus is closed.
/// Consumes messages from `bus.consumeOutbound()` and routes them to the
/// appropriate channel via `registry.findByName(msg.channel)`.
///
/// Designed to run in a dedicated thread:
///   `std.Thread.spawn(.{}, runOutboundDispatcher, .{ alloc, &bus, &registry, &stats })`
///
/// The loop exits when `bus.close()` is called and the outbound queue is drained.
pub fn runOutboundDispatcher(
    allocator: Allocator,
    event_bus: *bus.Bus,
    registry: *const ChannelRegistry,
    stats: *DispatchStats,
) void {
    runOutboundDispatcherWithOutbox(allocator, event_bus, registry, stats, null);
}

pub fn runOutboundDispatcherWithOutbox(
    allocator: Allocator,
    event_bus: *bus.Bus,
    registry: *const ChannelRegistry,
    stats: *DispatchStats,
    delivery_outbox: ?*channel_outbox.DeliveryOutbox,
) void {
    var draft_messages: DraftMessageMap = .empty;
    defer deinitDraftMessages(allocator, &draft_messages);

    while (event_bus.consumeOutbound()) |msg| {
        defer msg.deinit(allocator);

        const channel_opt = if (msg.account_id) |aid|
            registry.findByNameAccount(msg.channel, aid)
        else
            registry.findByName(msg.channel);

        if (channel_opt) |channel| {
            if (delivery_outbox) |outbox| {
                if (shouldPersistFinalOutbound(msg)) {
                    if (outbox.enqueueFinal(msg)) |_| {
                        _ = stats.dispatched.fetchAdd(1, .monotonic);
                        continue;
                    } else |_| {
                        // Fall back to the legacy direct path so a persistence
                        // failure does not drop the final reply entirely.
                    }
                }
            }
            dispatchOutboundMessageWithRetry(allocator, channel, msg, &draft_messages) catch {
                _ = stats.errors.fetchAdd(1, .monotonic);
                continue;
            };
            _ = stats.dispatched.fetchAdd(1, .monotonic);
        } else {
            _ = stats.channel_not_found.fetchAdd(1, .monotonic);
        }
    }
}

const OUTBOX_IDLE_POLL_MS: u64 = if (builtin.is_test) 1 else 250;

const DeliveryFailureClass = enum {
    transient,
    permanent,
};

const MAX_FINAL_SEND_ATTEMPTS: usize = 3;
const FINAL_SEND_RETRY_BACKOFF_MS = if (builtin.is_test)
    [_]u64{ 0, 0 }
else
    [_]u64{ 250, 1000 };

fn classifyOutboundFailure(err: anyerror) DeliveryFailureClass {
    return switch (err) {
        error.NotSupported,
        error.InvalidTarget,
        error.InvalidMessageRef,
        => .permanent,
        else => .transient,
    };
}

fn shouldRetryOutboundMessage(channel: root.Channel, msg: bus.OutboundMessage, err: anyerror) bool {
    return msg.stage == .final and
        !shouldUseTrackedDraftDispatch(channel, msg) and
        classifyOutboundFailure(err) == .transient;
}

fn dispatchOutboundMessageWithRetry(
    allocator: Allocator,
    channel: root.Channel,
    msg: bus.OutboundMessage,
    draft_messages: *DraftMessageMap,
) !void {
    var attempt: usize = 1;
    while (true) {
        dispatchOutboundMessage(allocator, channel, msg, draft_messages) catch |err| {
            if (!shouldRetryOutboundMessage(channel, msg, err) or attempt >= MAX_FINAL_SEND_ATTEMPTS) return err;
            const backoff_idx = @min(attempt - 1, FINAL_SEND_RETRY_BACKOFF_MS.len - 1);
            const backoff_ms = FINAL_SEND_RETRY_BACKOFF_MS[backoff_idx];
            if (backoff_ms > 0) std_compat.thread.sleep(backoff_ms * std.time.ns_per_ms);
            attempt += 1;
            continue;
        };
        return;
    }
}

pub fn runDurableOutboundWorker(
    allocator: Allocator,
    delivery_outbox: *channel_outbox.DeliveryOutbox,
    registry: *const ChannelRegistry,
) void {
    while (!delivery_outbox.isClosed()) {
        const processed = drainDurableOutboundOutboxOnce(allocator, delivery_outbox, registry) catch false;
        if (!processed) std_compat.thread.sleep(OUTBOX_IDLE_POLL_MS * std.time.ns_per_ms);
    }
}

pub fn drainDurableOutboundOutboxOnce(
    allocator: Allocator,
    delivery_outbox: *channel_outbox.DeliveryOutbox,
    registry: *const ChannelRegistry,
) !bool {
    if (try delivery_outbox.purgePersistedDelivered() > 0) return true;

    const now_ns: i64 = @intCast(std_compat.time.nanoTimestamp());
    var claimed = (try delivery_outbox.claimNextReady(allocator, now_ns)) orelse return false;
    defer claimed.deinit(allocator);

    const channel = if (claimed.account_id) |account_id|
        registry.findByNameAccount(claimed.channel, account_id)
    else
        registry.findByName(claimed.channel);

    if (channel) |resolved_channel| {
        dispatchClaimedOutboundDirect(resolved_channel, claimed) catch |err| {
            try delivery_outbox.recordFailure(claimed.id, @errorName(err), now_ns);
            return true;
        };
        try delivery_outbox.recordDelivered(claimed.id, now_ns);
        try delivery_outbox.purgeDelivered(claimed.id);
        return true;
    }

    try delivery_outbox.recordFailure(claimed.id, "ChannelNotFound", now_ns);
    return true;
}

fn deinitDraftMessages(allocator: Allocator, draft_messages: *DraftMessageMap) void {
    var it = draft_messages.valueIterator();
    while (it.next()) |state| state.deinit(allocator);
    draft_messages.deinit(allocator);
}

fn shouldUseTrackedDraftDispatch(channel: root.Channel, msg: bus.OutboundMessage) bool {
    return msg.draft_id != 0 and
        !channel.supportsStreamingOutbound() and
        supportsDraftStreaming(channel);
}

fn draftMessageKey(allocator: Allocator, msg: bus.OutboundMessage) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}\x1f{s}\x1f{s}\x1f{d}", .{
        msg.channel,
        msg.account_id orelse "",
        msg.chat_id,
        msg.draft_id,
    });
}

fn getOrPutDraftState(
    allocator: Allocator,
    draft_messages: *DraftMessageMap,
    msg: bus.OutboundMessage,
) !*DraftMessageState {
    const key = try draftMessageKey(allocator, msg);
    errdefer allocator.free(key);

    const gop = try draft_messages.getOrPut(allocator, key);
    if (!gop.found_existing) {
        gop.key_ptr.* = key;
        gop.value_ptr.* = .{ .key = key };
    } else {
        allocator.free(key);
    }
    return gop.value_ptr;
}

fn removeDraftState(
    allocator: Allocator,
    draft_messages: *DraftMessageMap,
    key: []const u8,
) void {
    if (draft_messages.fetchRemove(key)) |entry| {
        var state = entry.value;
        state.deinit(allocator);
    }
}

fn dispatchOutboundMessage(
    allocator: Allocator,
    channel: root.Channel,
    msg: bus.OutboundMessage,
    draft_messages: *DraftMessageMap,
) !void {
    if (shouldUseTrackedDraftDispatch(channel, msg)) {
        switch (msg.stage) {
            .chunk => return dispatchDraftChunk(allocator, channel, msg, draft_messages),
            .final => {
                if (try dispatchDraftFinal(allocator, channel, msg, draft_messages)) return;
            },
        }
    }

    return dispatchOutboundDirect(channel, msg);
}

fn dispatchDraftChunk(
    allocator: Allocator,
    channel: root.Channel,
    msg: bus.OutboundMessage,
    draft_messages: *DraftMessageMap,
) !void {
    if (msg.content.len == 0) return;

    const state = try getOrPutDraftState(allocator, draft_messages, msg);
    try state.buffer.appendSlice(allocator, msg.content);

    if (state.message_ref == null) {
        state.message_ref = (channel.sendTracked(msg.chat_id, state.buffer.items) catch |err| {
            removeDraftState(allocator, draft_messages, state.key);
            return err;
        }) orelse {
            removeDraftState(allocator, draft_messages, state.key);
            return error.InvalidMessageRef;
        };
        return;
    }

    try channel.editMessage(.{
        .target = state.message_ref.?.target,
        .message_id = state.message_ref.?.message_id,
        .payload = .{ .text = state.buffer.items },
    });
}

fn dispatchDraftFinal(
    allocator: Allocator,
    channel: root.Channel,
    msg: bus.OutboundMessage,
    draft_messages: *DraftMessageMap,
) !bool {
    const key = try draftMessageKey(allocator, msg);
    defer allocator.free(key);

    const state = draft_messages.getPtr(key) orelse return false;
    const message_ref = state.message_ref orelse return false;
    defer removeDraftState(allocator, draft_messages, key);

    if (msg.content.len == 0 and msg.media.len == 0 and msg.choices.len == 0) {
        try channel.deleteMessage(message_ref);
        return true;
    }

    if (msg.media.len > 0 or outbound.has_legacy_attachment_markers(msg.content)) {
        channel.deleteMessage(message_ref) catch {};
        try dispatchOutboundDirect(channel, msg);
        return true;
    }

    channel.editMessage(.{
        .target = message_ref.target,
        .message_id = message_ref.message_id,
        .payload = .{
            .text = msg.content,
            .choices = msg.choices,
        },
    }) catch |err| switch (err) {
        error.NotSupported => {
            channel.deleteMessage(message_ref) catch {};
            try dispatchOutboundDirect(channel, msg);
            return true;
        },
        else => return err,
    };
    return true;
}

fn dispatchOutboundDirect(channel: root.Channel, msg: bus.OutboundMessage) !void {
    if (msg.stage == .final and
        msg.media.len == 0 and
        msg.choices.len > 0 and
        !outbound.has_legacy_attachment_markers(msg.content))
    {
        channel.sendRich(msg.chat_id, .{
            .text = msg.content,
            .choices = msg.choices,
        }) catch |err| switch (err) {
            error.NotSupported => return channel.sendEvent(msg.chat_id, msg.content, &.{}, .final),
            else => return err,
        };
        return;
    }
    return channel.sendEvent(msg.chat_id, msg.content, msg.media, msg.stage);
}

fn dispatchClaimedOutboundDirect(channel: root.Channel, job: channel_outbox.DeliveryOutbox.ClaimedJob) !void {
    if (job.media.len == 0 and
        job.choices.len > 0 and
        !outbound.has_legacy_attachment_markers(job.content))
    {
        channel.sendRich(job.chat_id, .{
            .text = job.content,
            .choices = job.choices,
        }) catch |err| switch (err) {
            error.NotSupported => return channel.sendEvent(job.chat_id, job.content, &.{}, .final),
            else => return err,
        };
        return;
    }
    return channel.sendEvent(job.chat_id, job.content, job.media, .final);
}

fn shouldPersistFinalOutbound(msg: bus.OutboundMessage) bool {
    return msg.stage == .final and msg.draft_id == 0;
}

/// Get names of all enabled (registered) channels.
pub fn getEnabledChannelNames(registry: *const ChannelRegistry, allocator: Allocator) ![][]const u8 {
    return registry.channelNames(allocator);
}

// ════════════════════════════════════════════════════════════════════════════
// Channel Supervisor
// ════════════════════════════════════════════════════════════════════════════

/// Wraps a Channel with supervision state: restart counting, exponential
/// backoff, and a circuit-breaker that gives up after `max_restarts`.
pub const SupervisedChannel = struct {
    channel: root.Channel,
    state: State = .idle,
    restart_count: u32 = 0,
    max_restarts: u32 = 5,
    backoff_ms: u64 = 1000,
    max_backoff_ms: u64 = 60000,
    backoff_factor: u64 = 2,

    pub const State = enum {
        idle,
        running,
        restarting,
        gave_up,
    };

    /// Record a channel failure. Increments the restart counter, computes
    /// exponential backoff, and transitions to `restarting` or `gave_up`.
    pub fn recordFailure(self: *SupervisedChannel) void {
        self.restart_count += 1;
        if (self.restart_count >= self.max_restarts) {
            self.state = .gave_up;
        } else {
            self.state = .restarting;
        }
        // Compute exponential backoff: initial * factor^(restart_count - 1)
        var delay: u64 = self.backoff_ms;
        var i: u32 = 1;
        while (i < self.restart_count) : (i += 1) {
            delay = @min(delay * self.backoff_factor, self.max_backoff_ms);
        }
        self.backoff_ms = @min(delay, self.max_backoff_ms);
    }

    /// Record a successful start / recovery. Resets restart count and
    /// backoff to initial values, sets state to `running`.
    pub fn recordSuccess(self: *SupervisedChannel) void {
        self.restart_count = 0;
        self.backoff_ms = 1000;
        self.state = .running;
    }

    /// Returns the current backoff delay in milliseconds.
    pub fn currentBackoffMs(self: *const SupervisedChannel) u64 {
        return self.backoff_ms;
    }

    /// Returns true if the supervisor should attempt a restart (state is
    /// `restarting`, not `gave_up`).
    pub fn shouldRestart(self: *const SupervisedChannel) bool {
        return self.state == .restarting;
    }
};

/// Create a SupervisedChannel wrapping the given Channel.
pub fn spawnSupervisedChannel(channel: root.Channel, max_restarts: u32) SupervisedChannel {
    return .{
        .channel = channel,
        .max_restarts = max_restarts,
    };
}

/// Wrap an array of Channels into heap-allocated SupervisedChannels.
pub fn startAllSupervised(allocator: Allocator, channels: []const root.Channel) ![]SupervisedChannel {
    const supervised = try allocator.alloc(SupervisedChannel, channels.len);
    for (channels, 0..) |ch, i| {
        supervised[i] = spawnSupervisedChannel(ch, 5);
    }
    return supervised;
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

// ════════════════════════════════════════════════════════════════════════════
// Outbound Dispatch Tests
// ════════════════════════════════════════════════════════════════════════════

/// Mock channel for dispatch tests.
const MockChannel = struct {
    name_str: []const u8,
    sent_count: Atomic(u64) = Atomic(u64).init(0),
    chunk_count: Atomic(u64) = Atomic(u64).init(0),
    should_fail: bool = false,
    fail_first_final: bool = false,
    final_attempts: Atomic(u64) = Atomic(u64).init(0),

    const vtable = root.Channel.VTable{
        .start = mockStart,
        .stop = mockStop,
        .send = mockSend,
        .sendEvent = mockSendEvent,
        .name = mockName,
        .healthCheck = mockHealthCheck,
    };

    fn channel(self: *MockChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn mockStart(_: *anyopaque) anyerror!void {}
    fn mockStop(_: *anyopaque) void {}
    fn mockSend(ctx: *anyopaque, _: []const u8, _: []const u8, _: []const []const u8) anyerror!void {
        const self: *MockChannel = @ptrCast(@alignCast(ctx));
        if (self.should_fail) return error.SendFailed;
        const attempt = self.final_attempts.fetchAdd(1, .monotonic) + 1;
        if (self.fail_first_final and attempt == 1) return error.SendFailed;
        _ = self.sent_count.fetchAdd(1, .monotonic);
    }
    fn mockSendEvent(
        ctx: *anyopaque,
        _: []const u8,
        _: []const u8,
        _: []const []const u8,
        stage: root.Channel.OutboundStage,
    ) anyerror!void {
        const self: *MockChannel = @ptrCast(@alignCast(ctx));
        if (self.should_fail) return error.SendFailed;
        switch (stage) {
            .chunk => _ = self.chunk_count.fetchAdd(1, .monotonic),
            .final => {
                const attempt = self.final_attempts.fetchAdd(1, .monotonic) + 1;
                if (self.fail_first_final and attempt == 1) return error.SendFailed;
                _ = self.sent_count.fetchAdd(1, .monotonic);
            },
        }
    }
    fn mockName(ctx: *anyopaque) []const u8 {
        const self: *const MockChannel = @ptrCast(@alignCast(ctx));
        return self.name_str;
    }
    fn mockHealthCheck(_: *anyopaque) bool {
        return true;
    }
};

const MockRichChannel = struct {
    name_str: []const u8,
    sent_count: Atomic(u64) = Atomic(u64).init(0),
    rich_count: Atomic(u64) = Atomic(u64).init(0),

    const vtable = root.Channel.VTable{
        .start = mockStart,
        .stop = mockStop,
        .send = mockSend,
        .sendRich = mockSendRich,
        .name = mockName,
        .healthCheck = mockHealthCheck,
    };

    fn channel(self: *MockRichChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn mockStart(_: *anyopaque) anyerror!void {}
    fn mockStop(_: *anyopaque) void {}
    fn mockSend(ctx: *anyopaque, _: []const u8, _: []const u8, _: []const []const u8) anyerror!void {
        const self: *MockRichChannel = @ptrCast(@alignCast(ctx));
        _ = self.sent_count.fetchAdd(1, .monotonic);
    }
    fn mockSendRich(ctx: *anyopaque, _: []const u8, _: root.Channel.OutboundPayload) anyerror!void {
        const self: *MockRichChannel = @ptrCast(@alignCast(ctx));
        _ = self.rich_count.fetchAdd(1, .monotonic);
    }
    fn mockName(ctx: *anyopaque) []const u8 {
        const self: *const MockRichChannel = @ptrCast(@alignCast(ctx));
        return self.name_str;
    }
    fn mockHealthCheck(_: *anyopaque) bool {
        return true;
    }
};

const MockDraftChannel = struct {
    allocator: Allocator,
    name_str: []const u8,
    supports_drafts: bool = true,
    fail_first_delete: bool = false,
    sent_count: Atomic(u64) = Atomic(u64).init(0),
    tracked_count: Atomic(u64) = Atomic(u64).init(0),
    edit_count: Atomic(u64) = Atomic(u64).init(0),
    delete_count: Atomic(u64) = Atomic(u64).init(0),
    delete_attempts: Atomic(u64) = Atomic(u64).init(0),
    last_tracked_text: ?[]u8 = null,
    last_edit_text: ?[]u8 = null,

    fn deinit(self: *MockDraftChannel) void {
        if (self.last_tracked_text) |text| self.allocator.free(text);
        if (self.last_edit_text) |text| self.allocator.free(text);
    }

    const vtable = root.Channel.VTable{
        .start = mockStart,
        .stop = mockStop,
        .send = mockSend,
        .sendTracked = mockSendTracked,
        .editMessage = mockEditMessage,
        .deleteMessage = mockDeleteMessage,
        .name = mockName,
        .healthCheck = mockHealthCheck,
        .supportsTrackedDrafts = mockSupportsTrackedDrafts,
    };

    fn channel(self: *MockDraftChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn mockStart(_: *anyopaque) anyerror!void {}
    fn mockStop(_: *anyopaque) void {}
    fn mockSend(ctx: *anyopaque, _: []const u8, _: []const u8, _: []const []const u8) anyerror!void {
        const self: *MockDraftChannel = @ptrCast(@alignCast(ctx));
        _ = self.sent_count.fetchAdd(1, .monotonic);
    }
    fn mockSendTracked(ctx: *anyopaque, target: []const u8, message: []const u8) anyerror!?root.Channel.MessageRef {
        const self: *MockDraftChannel = @ptrCast(@alignCast(ctx));
        _ = self.tracked_count.fetchAdd(1, .monotonic);
        if (self.last_tracked_text) |text| self.allocator.free(text);
        self.last_tracked_text = try self.allocator.dupe(u8, message);

        const target_copy = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(target_copy);
        const id_copy = try self.allocator.dupe(u8, "draft-1");
        return .{
            .target = target_copy,
            .message_id = id_copy,
        };
    }
    fn mockEditMessage(ctx: *anyopaque, edit: root.Channel.MessageEdit) anyerror!void {
        const self: *MockDraftChannel = @ptrCast(@alignCast(ctx));
        _ = self.edit_count.fetchAdd(1, .monotonic);
        if (self.last_edit_text) |text| self.allocator.free(text);
        self.last_edit_text = try self.allocator.dupe(u8, edit.payload.text);
    }
    fn mockDeleteMessage(ctx: *anyopaque, _: root.Channel.MessageRef) anyerror!void {
        const self: *MockDraftChannel = @ptrCast(@alignCast(ctx));
        const attempt = self.delete_attempts.fetchAdd(1, .monotonic) + 1;
        if (self.fail_first_delete and attempt == 1) return error.SendFailed;
        _ = self.delete_count.fetchAdd(1, .monotonic);
    }
    fn mockName(ctx: *anyopaque) []const u8 {
        const self: *const MockDraftChannel = @ptrCast(@alignCast(ctx));
        return self.name_str;
    }
    fn mockHealthCheck(_: *anyopaque) bool {
        return true;
    }
    fn mockSupportsTrackedDrafts(ctx: *anyopaque) bool {
        const self: *const MockDraftChannel = @ptrCast(@alignCast(ctx));
        return self.supports_drafts;
    }
};

test "DispatchStats init all zero" {
    const stats = DispatchStats{};
    try std.testing.expectEqual(@as(u64, 0), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 0), stats.getErrors());
    try std.testing.expectEqual(@as(u64, 0), stats.getChannelNotFound());
}

test "dispatcher routes message to correct channel" {
    const allocator = std.testing.allocator;

    var mock_tg = MockChannel{ .name_str = "telegram" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_tg.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    // Publish a message, then close bus so dispatcher exits
    const msg = try bus.makeOutbound(allocator, "telegram", "chat1", "hello");
    try event_bus.publishOutbound(msg);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 1), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 0), stats.getErrors());
    try std.testing.expectEqual(@as(u64, 0), stats.getChannelNotFound());
    try std.testing.expectEqual(@as(u64, 1), mock_tg.sent_count.load(.monotonic));
}

test "dispatcher routes chunk stage via sendEvent" {
    const allocator = std.testing.allocator;

    var mock_web = MockChannel{ .name_str = "web" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_web.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    const msg = try bus.makeOutboundChunk(allocator, "web", "chat1", "hel");
    try event_bus.publishOutbound(msg);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 1), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 1), mock_web.chunk_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_web.sent_count.load(.monotonic));
}

test "dispatcher falls back to sendEvent when structured choices are not supported" {
    const allocator = std.testing.allocator;
    const choices = [_]root.Channel.OutboundChoice{
        .{ .id = "yes", .label = "Yes", .submit_text = "yes" },
        .{ .id = "no", .label = "No", .submit_text = "no" },
    };

    var mock_tg = MockChannel{ .name_str = "telegram" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_tg.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    const msg = try bus.makeOutboundWithChoices(allocator, "telegram", "chat1", "hello", &choices);
    try event_bus.publishOutbound(msg);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 1), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 1), mock_tg.sent_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_tg.chunk_count.load(.monotonic));
}

test "dispatcher prefers sendRich for final messages with structured choices" {
    const allocator = std.testing.allocator;
    const choices = [_]root.Channel.OutboundChoice{
        .{ .id = "yes", .label = "Yes", .submit_text = "yes" },
        .{ .id = "no", .label = "No", .submit_text = "no" },
    };

    var mock_tg = MockRichChannel{ .name_str = "telegram" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_tg.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    const msg = try bus.makeOutboundWithChoices(allocator, "telegram", "chat1", "hello", &choices);
    try event_bus.publishOutbound(msg);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 1), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 1), mock_tg.rich_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_tg.sent_count.load(.monotonic));
}

test "dispatcher keeps legacy attachment-marker payloads on sendEvent path" {
    const allocator = std.testing.allocator;
    const choices = [_]root.Channel.OutboundChoice{
        .{ .id = "yes", .label = "Yes", .submit_text = "yes" },
        .{ .id = "no", .label = "No", .submit_text = "no" },
    };

    var mock_tg = MockRichChannel{ .name_str = "telegram" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_tg.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    const msg = try bus.makeOutboundWithChoices(
        allocator,
        "telegram",
        "chat1",
        "See this\n[IMAGE:/tmp/photo.png]",
        &choices,
    );
    try event_bus.publishOutbound(msg);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 1), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 0), mock_tg.rich_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), mock_tg.sent_count.load(.monotonic));
}

test "dispatcher routes to matching account when channel has multiple accounts" {
    const allocator = std.testing.allocator;

    var main_tg = MockChannel{ .name_str = "telegram" };
    var backup_tg = MockChannel{ .name_str = "telegram" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.registerWithAccount(main_tg.channel(), "main");
    try reg.registerWithAccount(backup_tg.channel(), "backup");

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    const msg = try bus.makeOutboundWithAccount(allocator, "telegram", "backup", "chat1", "hello");
    try event_bus.publishOutbound(msg);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 1), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 0), stats.getErrors());
    try std.testing.expectEqual(@as(u64, 0), stats.getChannelNotFound());
    try std.testing.expectEqual(@as(u64, 0), main_tg.sent_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), backup_tg.sent_count.load(.monotonic));
}

test "dispatcher tracks chunk drafts via sendTracked and editMessage" {
    const allocator = std.testing.allocator;

    var mock_external = MockDraftChannel{
        .allocator = allocator,
        .name_str = "external",
    };
    defer mock_external.deinit();

    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_external.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    var first_chunk = try bus.makeOutboundChunk(allocator, "external", "chat1", "Hel");
    first_chunk.draft_id = 1;
    try event_bus.publishOutbound(first_chunk);

    var second_chunk = try bus.makeOutboundChunk(allocator, "external", "chat1", "lo");
    second_chunk.draft_id = 1;
    try event_bus.publishOutbound(second_chunk);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 2), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 1), mock_external.tracked_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), mock_external.edit_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_external.delete_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_external.sent_count.load(.monotonic));
    try std.testing.expectEqualStrings("Hel", mock_external.last_tracked_text.?);
    try std.testing.expectEqualStrings("Hello", mock_external.last_edit_text.?);
}

test "dispatcher deletes tracked draft on empty final" {
    const allocator = std.testing.allocator;

    var mock_external = MockDraftChannel{
        .allocator = allocator,
        .name_str = "external",
    };
    defer mock_external.deinit();

    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_external.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    var chunk = try bus.makeOutboundChunk(allocator, "external", "chat1", "Hello");
    chunk.draft_id = 2;
    try event_bus.publishOutbound(chunk);

    var final = try bus.makeOutbound(allocator, "external", "chat1", "");
    final.draft_id = 2;
    try event_bus.publishOutbound(final);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 2), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 1), mock_external.tracked_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_external.edit_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), mock_external.delete_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_external.sent_count.load(.monotonic));
}

// Regression: retry logic must not turn a failed tracked-draft delete into a fresh outbound send.
test "dispatcher does not retry tracked draft final delete failures" {
    const allocator = std.testing.allocator;

    var mock_external = MockDraftChannel{
        .allocator = allocator,
        .name_str = "external",
        .fail_first_delete = true,
    };
    defer mock_external.deinit();

    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_external.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    var chunk = try bus.makeOutboundChunk(allocator, "external", "chat1", "Hello");
    chunk.draft_id = 22;
    try event_bus.publishOutbound(chunk);

    var final = try bus.makeOutbound(allocator, "external", "chat1", "");
    final.draft_id = 22;
    try event_bus.publishOutbound(final);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 1), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 1), stats.getErrors());
    try std.testing.expectEqual(@as(u64, 1), mock_external.tracked_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), mock_external.delete_attempts.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_external.delete_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_external.sent_count.load(.monotonic));
}

test "dispatcher falls back to plain final send after deleting tracked draft for legacy attachments" {
    const allocator = std.testing.allocator;

    var mock_external = MockDraftChannel{
        .allocator = allocator,
        .name_str = "external",
    };
    defer mock_external.deinit();

    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_external.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    var chunk = try bus.makeOutboundChunk(allocator, "external", "chat1", "Hello");
    chunk.draft_id = 3;
    try event_bus.publishOutbound(chunk);

    var final = try bus.makeOutbound(allocator, "external", "chat1", "See [IMAGE:/tmp/photo.png]");
    final.draft_id = 3;
    try event_bus.publishOutbound(final);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 2), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 1), mock_external.tracked_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_external.edit_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), mock_external.delete_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), mock_external.sent_count.load(.monotonic));
}

test "dispatcher keeps tracked draft isolated from unrelated outbound sends" {
    const allocator = std.testing.allocator;

    var mock_external = MockDraftChannel{
        .allocator = allocator,
        .name_str = "external",
    };
    defer mock_external.deinit();

    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_external.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    var chunk = try bus.makeOutboundChunk(allocator, "external", "chat1", "Hello");
    chunk.draft_id = 41;
    try event_bus.publishOutbound(chunk);

    try event_bus.publishOutbound(try bus.makeOutbound(allocator, "external", "chat1", "Independent"));

    var final = try bus.makeOutbound(allocator, "external", "chat1", "Done");
    final.draft_id = 41;
    try event_bus.publishOutbound(final);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 3), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 1), mock_external.tracked_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), mock_external.edit_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_external.delete_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), mock_external.sent_count.load(.monotonic));
    try std.testing.expectEqualStrings("Done", mock_external.last_edit_text.?);
}

test "dispatcher clears failed tracked draft state before later sends" {
    const allocator = std.testing.allocator;

    const FailingDraftChannel = struct {
        allocator: Allocator,
        tracked_calls: u32 = 0,
        sent_count: Atomic(u64) = Atomic(u64).init(0),
        tracked_count: Atomic(u64) = Atomic(u64).init(0),
        edit_count: Atomic(u64) = Atomic(u64).init(0),
        last_tracked_text: ?[]u8 = null,
        last_edit_text: ?[]u8 = null,

        fn deinit(self: *@This()) void {
            if (self.last_tracked_text) |text| self.allocator.free(text);
            if (self.last_edit_text) |text| self.allocator.free(text);
        }

        const vtable = root.Channel.VTable{
            .start = mockStart,
            .stop = mockStop,
            .send = mockSend,
            .sendTracked = mockSendTracked,
            .editMessage = mockEditMessage,
            .deleteMessage = mockDeleteMessage,
            .name = mockName,
            .healthCheck = mockHealthCheck,
            .supportsTrackedDrafts = mockSupportsTrackedDrafts,
        };

        fn channel(self: *@This()) root.Channel {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        fn mockStart(_: *anyopaque) anyerror!void {}
        fn mockStop(_: *anyopaque) void {}
        fn mockSend(ctx: *anyopaque, _: []const u8, _: []const u8, _: []const []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = self.sent_count.fetchAdd(1, .monotonic);
        }
        fn mockSendTracked(ctx: *anyopaque, target: []const u8, message: []const u8) anyerror!?root.Channel.MessageRef {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.tracked_calls += 1;
            if (self.tracked_calls == 1) return error.TransientFailure;

            _ = self.tracked_count.fetchAdd(1, .monotonic);
            if (self.last_tracked_text) |text| self.allocator.free(text);
            self.last_tracked_text = try self.allocator.dupe(u8, message);

            const target_copy = try self.allocator.dupe(u8, target);
            errdefer self.allocator.free(target_copy);
            const id_copy = try self.allocator.dupe(u8, "draft-2");
            return .{
                .target = target_copy,
                .message_id = id_copy,
            };
        }
        fn mockEditMessage(ctx: *anyopaque, edit: root.Channel.MessageEdit) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = self.edit_count.fetchAdd(1, .monotonic);
            if (self.last_edit_text) |text| self.allocator.free(text);
            self.last_edit_text = try self.allocator.dupe(u8, edit.payload.text);
        }
        fn mockDeleteMessage(_: *anyopaque, _: root.Channel.MessageRef) anyerror!void {}
        fn mockName(_: *anyopaque) []const u8 {
            return "external";
        }
        fn mockHealthCheck(_: *anyopaque) bool {
            return true;
        }
        fn mockSupportsTrackedDrafts(_: *anyopaque) bool {
            return true;
        }
    };

    var mock_external = FailingDraftChannel{ .allocator = allocator };
    defer mock_external.deinit();

    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_external.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    var failed_chunk = try bus.makeOutboundChunk(allocator, "external", "chat1", "Bad");
    failed_chunk.draft_id = 11;
    try event_bus.publishOutbound(failed_chunk);

    var fallback_final = try bus.makeOutbound(allocator, "external", "chat1", "Recovered");
    fallback_final.draft_id = 11;
    try event_bus.publishOutbound(fallback_final);

    var next_chunk = try bus.makeOutboundChunk(allocator, "external", "chat1", "New");
    next_chunk.draft_id = 12;
    try event_bus.publishOutbound(next_chunk);

    var next_final = try bus.makeOutbound(allocator, "external", "chat1", "Complete");
    next_final.draft_id = 12;
    try event_bus.publishOutbound(next_final);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 3), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 1), stats.getErrors());
    try std.testing.expectEqual(@as(u64, 1), mock_external.sent_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), mock_external.tracked_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), mock_external.edit_count.load(.monotonic));
    try std.testing.expectEqualStrings("New", mock_external.last_tracked_text.?);
    try std.testing.expectEqualStrings("Complete", mock_external.last_edit_text.?);
}

test "dispatcher ignores tracked draft flow when channel does not advertise it" {
    const allocator = std.testing.allocator;

    var mock_external = MockDraftChannel{
        .allocator = allocator,
        .name_str = "external",
        .supports_drafts = false,
    };
    defer mock_external.deinit();

    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_external.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    try event_bus.publishOutbound(try bus.makeOutboundChunk(allocator, "external", "chat1", "Hello"));
    try event_bus.publishOutbound(try bus.makeOutbound(allocator, "external", "chat1", "Done"));
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 2), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 0), mock_external.tracked_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_external.edit_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_external.delete_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), mock_external.sent_count.load(.monotonic));
}

test "dispatcher does not fallback to wrong account when account_id is unknown" {
    const allocator = std.testing.allocator;

    var main_tg = MockChannel{ .name_str = "telegram" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.registerWithAccount(main_tg.channel(), "main");

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    const msg = try bus.makeOutboundWithAccount(allocator, "telegram", "missing", "chat1", "hello");
    try event_bus.publishOutbound(msg);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 0), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 0), stats.getErrors());
    try std.testing.expectEqual(@as(u64, 1), stats.getChannelNotFound());
    try std.testing.expectEqual(@as(u64, 0), main_tg.sent_count.load(.monotonic));
}

test "dispatcher increments channel_not_found for unknown channel" {
    const allocator = std.testing.allocator;

    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    // Empty registry — no channels registered

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    const msg = try bus.makeOutbound(allocator, "nonexistent", "chat1", "hi");
    try event_bus.publishOutbound(msg);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 0), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 1), stats.getChannelNotFound());
}

test "dispatcher increments errors on channel.send failure" {
    const allocator = std.testing.allocator;

    var mock_fail = MockChannel{ .name_str = "failing", .should_fail = true };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_fail.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    const msg = try bus.makeOutbound(allocator, "failing", "c1", "boom");
    try event_bus.publishOutbound(msg);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 0), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 1), stats.getErrors());
    try std.testing.expectEqual(@as(u64, 0), stats.getChannelNotFound());
}

// Regression: transient final-send failures must not drop the reply permanently.
test "dispatcher retries transient final send once" {
    const allocator = std.testing.allocator;

    var mock_retry = MockChannel{ .name_str = "qq", .fail_first_final = true };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_retry.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    const msg = try bus.makeOutbound(allocator, "qq", "c1", "hello");
    try event_bus.publishOutbound(msg);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 1), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 0), stats.getErrors());
    try std.testing.expectEqual(@as(u64, 1), mock_retry.sent_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 2), mock_retry.final_attempts.load(.monotonic));
}

test "dispatcher classifies permanent and transient outbound failures" {
    try std.testing.expectEqual(DeliveryFailureClass.permanent, classifyOutboundFailure(error.InvalidTarget));
    try std.testing.expectEqual(DeliveryFailureClass.permanent, classifyOutboundFailure(error.NotSupported));
    try std.testing.expectEqual(DeliveryFailureClass.transient, classifyOutboundFailure(error.QQApiError));
    try std.testing.expectEqual(DeliveryFailureClass.transient, classifyOutboundFailure(error.SendFailed));
}

test "dispatcher can enqueue final outbound into durable outbox" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const outbox_path = try std_compat.fs.path.join(allocator, &.{ tmp_root, "delivery.json" });
    defer allocator.free(outbox_path);

    var outbox = try channel_outbox.DeliveryOutbox.init(allocator, outbox_path);
    defer outbox.deinit();

    var mock_tg = MockChannel{ .name_str = "telegram" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_tg.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};
    const msg = try bus.makeOutbound(allocator, "telegram", "chat1", "hello");
    try event_bus.publishOutbound(msg);
    event_bus.close();

    runOutboundDispatcherWithOutbox(allocator, &event_bus, &reg, &stats, &outbox);

    try std.testing.expectEqual(@as(u64, 1), stats.getDispatched());
    try std.testing.expectEqual(@as(usize, 1), outbox.pendingCount());
    try std.testing.expectEqual(@as(u64, 0), mock_tg.sent_count.load(.monotonic));
}

// Regression: a durable enqueue failure must not drop the final reply.
test "dispatcher falls back to direct send when durable enqueue fails" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const outbox_path = try std_compat.fs.path.join(allocator, &.{ tmp_root, "missing", "delivery.json" });
    defer allocator.free(outbox_path);

    var outbox = try channel_outbox.DeliveryOutbox.init(allocator, outbox_path);
    defer outbox.deinit();

    var mock_tg = MockChannel{ .name_str = "telegram" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_tg.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    const msg = try bus.makeOutbound(allocator, "telegram", "chat1", "hello");
    try event_bus.publishOutbound(msg);
    event_bus.close();

    runOutboundDispatcherWithOutbox(allocator, &event_bus, &reg, &stats, &outbox);

    try std.testing.expectEqual(@as(u64, 1), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 0), stats.getErrors());
    try std.testing.expectEqual(@as(usize, 0), outbox.pendingCount());
    try std.testing.expectEqual(@as(u64, 1), mock_tg.sent_count.load(.monotonic));
}

test "durable outbound worker retries persisted final delivery" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const outbox_path = try std_compat.fs.path.join(allocator, &.{ tmp_root, "delivery.json" });
    defer allocator.free(outbox_path);

    var outbox = try channel_outbox.DeliveryOutbox.init(allocator, outbox_path);
    defer outbox.deinit();

    var mock_tg = MockChannel{
        .name_str = "telegram",
        .fail_first_final = true,
    };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_tg.channel());

    var msg = try bus.makeOutbound(allocator, "telegram", "chat1", "hello");
    defer msg.deinit(allocator);
    _ = try outbox.enqueueFinal(msg);

    try std.testing.expect(try drainDurableOutboundOutboxOnce(allocator, &outbox, &reg));
    try std.testing.expectEqual(@as(usize, 1), outbox.pendingCount());
    try std.testing.expectEqual(@as(u64, 1), mock_tg.final_attempts.load(.monotonic));

    try std.testing.expect(try drainDurableOutboundOutboxOnce(allocator, &outbox, &reg));
    try std.testing.expectEqual(@as(usize, 0), outbox.pendingCount());
    try std.testing.expectEqual(@as(u64, 2), mock_tg.final_attempts.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), mock_tg.sent_count.load(.monotonic));
}

// Regression: if the process crashes after send success but before durable cleanup,
// the restarted worker must purge the acknowledged job instead of redelivering it.
test "durable outbound worker purges acknowledged persisted delivery without resend" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_root);
    const outbox_path = try std_compat.fs.path.join(allocator, &.{ tmp_root, "delivery.json" });
    defer allocator.free(outbox_path);

    var outbox = try channel_outbox.DeliveryOutbox.init(allocator, outbox_path);
    defer outbox.deinit();

    var msg = try bus.makeOutbound(allocator, "telegram", "chat1", "hello");
    defer msg.deinit(allocator);
    const id = try outbox.enqueueFinal(msg);

    var claimed = (try outbox.claimNextReady(allocator, 0)).?;
    claimed.deinit(allocator);
    try outbox.recordDelivered(id, 42);

    var mock_tg = MockChannel{ .name_str = "telegram" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_tg.channel());

    try std.testing.expect(try drainDurableOutboundOutboxOnce(allocator, &outbox, &reg));
    try std.testing.expectEqual(@as(usize, 0), outbox.pendingCount());
    try std.testing.expectEqual(@as(u64, 0), mock_tg.final_attempts.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), mock_tg.sent_count.load(.monotonic));
}

test "dispatcher handles multiple messages" {
    const allocator = std.testing.allocator;

    var mock_tg = MockChannel{ .name_str = "telegram" };
    var mock_dc = MockChannel{ .name_str = "discord" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_tg.channel());
    try reg.register(mock_dc.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    // 3 to telegram, 2 to discord
    for (0..3) |_| {
        const msg = try bus.makeOutbound(allocator, "telegram", "c1", "msg");
        try event_bus.publishOutbound(msg);
    }
    for (0..2) |_| {
        const msg = try bus.makeOutbound(allocator, "discord", "c2", "msg");
        try event_bus.publishOutbound(msg);
    }
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 5), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 3), mock_tg.sent_count.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 2), mock_dc.sent_count.load(.monotonic));
}

test "dispatcher mixed: found, not_found, error" {
    const allocator = std.testing.allocator;

    var mock_ok = MockChannel{ .name_str = "telegram" };
    var mock_fail = MockChannel{ .name_str = "broken", .should_fail = true };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_ok.channel());
    try reg.register(mock_fail.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    // 1 ok, 1 error, 1 not found
    const m1 = try bus.makeOutbound(allocator, "telegram", "c1", "ok");
    try event_bus.publishOutbound(m1);
    const m2 = try bus.makeOutbound(allocator, "broken", "c2", "fail");
    try event_bus.publishOutbound(m2);
    const m3 = try bus.makeOutbound(allocator, "ghost", "c3", "where");
    try event_bus.publishOutbound(m3);
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 1), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 1), stats.getErrors());
    try std.testing.expectEqual(@as(u64, 1), stats.getChannelNotFound());
}

test "dispatcher empty bus returns immediately" {
    const allocator = std.testing.allocator;

    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};
    event_bus.close();

    runOutboundDispatcher(allocator, &event_bus, &reg, &stats);

    try std.testing.expectEqual(@as(u64, 0), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 0), stats.getErrors());
    try std.testing.expectEqual(@as(u64, 0), stats.getChannelNotFound());
}

test "dispatcher runs in a separate thread" {
    const allocator = std.testing.allocator;

    var mock_tg = MockChannel{ .name_str = "telegram" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_tg.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    // Spawn dispatcher thread
    const thread = try std.Thread.spawn(.{ .stack_size = thread_stacks.COORDINATION_STACK_SIZE }, runOutboundDispatcher, .{
        allocator, &event_bus, &reg, &stats,
    });

    // Publish from main thread
    const msg = try bus.makeOutbound(allocator, "telegram", "c1", "threaded");
    try event_bus.publishOutbound(msg);

    // Small delay then close bus to let dispatcher process
    std_compat.thread.sleep(10 * std.time.ns_per_ms);
    event_bus.close();
    thread.join();

    try std.testing.expectEqual(@as(u64, 1), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, 1), mock_tg.sent_count.load(.monotonic));
}

test "dispatcher concurrent producers + single dispatcher" {
    const allocator = std.testing.allocator;

    var mock_ch = MockChannel{ .name_str = "test" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock_ch.channel());

    var event_bus = bus.Bus.init();
    var stats = DispatchStats{};

    const num_producers = 4;
    const msgs_per_producer = 25;
    const total = num_producers * msgs_per_producer;

    // Spawn dispatcher
    const dispatcher = try std.Thread.spawn(.{ .stack_size = thread_stacks.COORDINATION_STACK_SIZE }, runOutboundDispatcher, .{
        allocator, &event_bus, &reg, &stats,
    });

    // Spawn producers
    var producers: [num_producers]std.Thread = undefined;
    for (0..num_producers) |i| {
        producers[i] = try std.Thread.spawn(.{ .stack_size = thread_stacks.COORDINATION_STACK_SIZE }, struct {
            fn run(b: *bus.Bus, a: Allocator) void {
                for (0..msgs_per_producer) |_| {
                    const m = bus.makeOutbound(a, "test", "c", "x") catch return;
                    b.publishOutbound(m) catch return;
                }
            }
        }.run, .{ &event_bus, allocator });
    }

    // Wait for all producers, then close bus
    for (&producers) |*p| p.join();
    // Small delay for dispatcher to drain
    std_compat.thread.sleep(20 * std.time.ns_per_ms);
    event_bus.close();
    dispatcher.join();

    try std.testing.expectEqual(@as(u64, total), stats.getDispatched());
    try std.testing.expectEqual(@as(u64, total), mock_ch.sent_count.load(.monotonic));
}

test "getEnabledChannelNames returns registered names" {
    const allocator = std.testing.allocator;

    var mock1 = MockChannel{ .name_str = "telegram" };
    var mock2 = MockChannel{ .name_str = "discord" };
    var reg = ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(mock1.channel());
    try reg.register(mock2.channel());

    const names = try getEnabledChannelNames(&reg, allocator);
    defer allocator.free(names);

    try std.testing.expectEqual(@as(usize, 2), names.len);
    try std.testing.expectEqualStrings("telegram", names[0]);
    try std.testing.expectEqualStrings("discord", names[1]);
}

// ════════════════════════════════════════════════════════════════════════════
// Channel Supervisor Tests
// ════════════════════════════════════════════════════════════════════════════

test "supervised channel initial state" {
    var mock = MockChannel{ .name_str = "test" };
    const sc = spawnSupervisedChannel(mock.channel(), 5);
    try std.testing.expectEqual(SupervisedChannel.State.idle, sc.state);
    try std.testing.expectEqual(@as(u32, 0), sc.restart_count);
    try std.testing.expectEqual(@as(u64, 1000), sc.currentBackoffMs());
    try std.testing.expectEqual(@as(u32, 5), sc.max_restarts);
    try std.testing.expect(!sc.shouldRestart());
}

test "supervised channel recordFailure increments and sets restarting" {
    var mock = MockChannel{ .name_str = "test" };
    var sc = spawnSupervisedChannel(mock.channel(), 5);

    sc.recordFailure();
    try std.testing.expectEqual(@as(u32, 1), sc.restart_count);
    try std.testing.expectEqual(SupervisedChannel.State.restarting, sc.state);
    try std.testing.expect(sc.shouldRestart());

    sc.recordFailure();
    try std.testing.expectEqual(@as(u32, 2), sc.restart_count);
    try std.testing.expectEqual(SupervisedChannel.State.restarting, sc.state);
    // Backoff should have doubled
    try std.testing.expect(sc.currentBackoffMs() > 1000);
}

test "supervised channel backoff capped at max_backoff_ms" {
    var mock = MockChannel{ .name_str = "test" };
    var sc = spawnSupervisedChannel(mock.channel(), 100);
    // Override to make the cap easy to test
    sc.max_backoff_ms = 5000;

    // Record many failures to push backoff beyond the cap
    for (0..20) |_| {
        sc.recordFailure();
    }
    try std.testing.expect(sc.currentBackoffMs() <= 5000);
}

test "supervised channel gave_up after max_restarts" {
    var mock = MockChannel{ .name_str = "test" };
    var sc = spawnSupervisedChannel(mock.channel(), 3);

    sc.recordFailure(); // 1 — restarting
    sc.recordFailure(); // 2 — restarting
    sc.recordFailure(); // 3 — gave_up (restart_count == max_restarts)

    try std.testing.expectEqual(SupervisedChannel.State.gave_up, sc.state);
    try std.testing.expect(!sc.shouldRestart());
    try std.testing.expectEqual(@as(u32, 3), sc.restart_count);
}

test "supervised channel recordSuccess resets state" {
    var mock = MockChannel{ .name_str = "test" };
    var sc = spawnSupervisedChannel(mock.channel(), 5);

    // Fail a couple of times
    sc.recordFailure();
    sc.recordFailure();
    try std.testing.expectEqual(@as(u32, 2), sc.restart_count);
    try std.testing.expect(sc.currentBackoffMs() > 1000);

    // Successful recovery
    sc.recordSuccess();
    try std.testing.expectEqual(SupervisedChannel.State.running, sc.state);
    try std.testing.expectEqual(@as(u32, 0), sc.restart_count);
    try std.testing.expectEqual(@as(u64, 1000), sc.currentBackoffMs());
}

test "startAllSupervised wraps channel array" {
    const allocator = std.testing.allocator;

    var mock1 = MockChannel{ .name_str = "telegram" };
    var mock2 = MockChannel{ .name_str = "discord" };
    const channels = [_]root.Channel{ mock1.channel(), mock2.channel() };

    const supervised = try startAllSupervised(allocator, &channels);
    defer allocator.free(supervised);

    try std.testing.expectEqual(@as(usize, 2), supervised.len);
    try std.testing.expectEqual(SupervisedChannel.State.idle, supervised[0].state);
    try std.testing.expectEqual(SupervisedChannel.State.idle, supervised[1].state);
    try std.testing.expectEqualStrings("telegram", supervised[0].channel.name());
    try std.testing.expectEqualStrings("discord", supervised[1].channel.name());
}
