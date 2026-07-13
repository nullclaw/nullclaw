const std = @import("std");
const commands = @import("commands.zig");
const memory_mod = @import("../memory/root.zig");
const Agent = @import("root.zig").Agent;

pub const TurnPersistenceState = struct {
    history: []const Agent.OwnedMessage,
    total_tokens: u64,
};

pub const APPROVAL_PAUSE_CHECKPOINT =
    "An approval boundary was reached. Calls recorded before this checkpoint may have completed and must not be repeated automatically. The approval-gated call and every later call did not run. No approval capability is persisted; after restart the gated action must be requested again.";
pub const APPROVAL_EXECUTION_INTENT_CHECKPOINT =
    "Approval was accepted and the gated tool may have executed. Never repeat it automatically after restart; wait for or inspect a later result.";
pub const TOOL_TURN_WRITE_AHEAD_CHECKPOINT = memory_mod.TOOL_TURN_WRITE_AHEAD_CHECKPOINT;
pub const TOOL_TURN_COMPLETION_CHECKPOINT = memory_mod.TOOL_TURN_COMPLETION_CHECKPOINT;
pub const TOOL_TURN_CHECKPOINT_ROLE = memory_mod.TOOL_TURN_CHECKPOINT_ROLE;
pub const ToolTurnCompletion = memory_mod.ToolTurnCompletion;

fn persistedAssistantReply(history: []const Agent.OwnedMessage, response: []const u8) []const u8 {
    if (history.len == 0) return response;
    const last = history[history.len - 1];
    if (last.role != .assistant) return response;
    return last.content;
}

/// Apply reset semantics independently of message serialization. Callers that
/// redact before writing must invoke this before redaction so an allocation
/// failure cannot resurrect the transcript that /new or /reset already
/// cleared from the live Agent.
pub fn applySessionReset(
    store: memory_mod.SessionStore,
    session_key: []const u8,
    content: []const u8,
) bool {
    if (!commands.planTurnInput(content).clear_session) return true;
    store.clearMessages(session_key) catch return false;
    store.clearAutoSaved(session_key) catch return false;
    return true;
}

pub fn persistTurn(
    store: memory_mod.SessionStore,
    state: TurnPersistenceState,
    session_key: []const u8,
    content: []const u8,
    response: []const u8,
) void {
    const turn_input = commands.planTurnInput(content);
    if (!applySessionReset(store, session_key, content)) return;

    if (commands.persistedRuntimeCommand(content)) |runtime_command| {
        store.saveMessage(session_key, memory_mod.RUNTIME_COMMAND_ROLE, runtime_command) catch {};
    }

    if (turn_input.llm_user_message) |persisted_user| {
        // Persist canonical conversation history.
        // Local-only slash commands are skipped, but any input that
        // reached the LLM must persist with the exact same routing
        // decision used by Agent.turn().
        // When the turn ends with an assistant history message, prefer
        // that canonical text over the rendered reply so restored
        // sessions do not replay /usage footers or reasoning blocks.
        // Some degraded turns return a fallback response without
        // appending a final assistant history entry; in that case we
        // must persist the actual response instead of stale tool-step
        // assistant text from earlier in the turn.
        const persisted_assistant = persistedAssistantReply(state.history, response);
        store.saveMessage(session_key, "user", persisted_user) catch {};
        store.saveMessage(session_key, "assistant", persisted_assistant) catch {};
        store.saveUsage(session_key, state.total_tokens) catch {};
    }
}

/// Persist a closed representation of a turn paused at an approval boundary.
/// The bearer request id and pending tool call are deliberately omitted. When
/// earlier calls completed, their canceled-prefix assistant and result receipt
/// are stored before the generic waiting marker.
pub fn persistApprovalPauseCheckpoint(
    allocator: std.mem.Allocator,
    store: memory_mod.SessionStore,
    session_key: []const u8,
    content: []const u8,
    base_checkpointed: bool,
    assistant_prefix: ?[]const u8,
    completed_results: ?[]const u8,
    total_tokens: u64,
) bool {
    if (completed_results != null and assistant_prefix == null) return false;

    const original_user: ?[]const u8 = if (!base_checkpointed) blk: {
        const turn_input = commands.planTurnInput(content);
        break :blk turn_input.llm_user_message orelse return false;
    } else null;

    // One row is the transaction boundary available on every SessionStore.
    // Embedding the safe prefix and terminal fence in that row prevents a
    // crash between independent INSERTs from restoring a dangling tool call.
    const checkpoint = std.fmt.allocPrint(
        allocator,
        "{s}\nOriginal routed user message (JSON): {f}\nCompleted assistant prefix (JSON): {f}\nCompleted tool results (JSON): {f}",
        .{
            APPROVAL_PAUSE_CHECKPOINT,
            std.json.fmt(original_user, .{}),
            std.json.fmt(assistant_prefix, .{}),
            std.json.fmt(completed_results, .{}),
        },
    ) catch return false;
    defer allocator.free(checkpoint);

    if (!base_checkpointed) {
        if (!applySessionReset(store, session_key, content)) return false;
    }
    store.saveMessage(session_key, "assistant", checkpoint) catch return false;
    store.saveUsage(session_key, total_tokens) catch {};
    return true;
}

/// Establish a closed durable fence before the first tool batch can dispatch.
/// A single row makes every later side effect conservative across process
/// death even when the richer pause/result checkpoint is never reached.
pub fn persistToolTurnWriteAheadCheckpoint(
    allocator: std.mem.Allocator,
    store: memory_mod.SessionStore,
    session_key: []const u8,
    original_user: ?[]const u8,
    total_tokens: u64,
) bool {
    const checkpoint = std.fmt.allocPrint(
        allocator,
        "{s}\nOriginal routed user message (JSON): {f}",
        .{ TOOL_TURN_WRITE_AHEAD_CHECKPOINT, std.json.fmt(original_user, .{}) },
    ) catch return false;
    defer allocator.free(checkpoint);

    store.saveMessage(session_key, TOOL_TURN_CHECKPOINT_ROLE, checkpoint) catch return false;
    store.saveUsage(session_key, total_tokens) catch {};
    return true;
}

/// Close a successful write-ahead-protected turn with an atomic projection of
/// its canonical user/assistant pair. Restore code can then collapse the
/// conservative pre-effect fence instead of exposing recovery text in every
/// clean transcript.
pub fn persistToolTurnCompletionCheckpoint(
    allocator: std.mem.Allocator,
    store: memory_mod.SessionStore,
    session_key: []const u8,
    original_user: ?[]const u8,
    assistant_response: []const u8,
    total_tokens: u64,
) bool {
    const checkpoint = std.fmt.allocPrint(
        allocator,
        "{s}\n{f}",
        .{
            TOOL_TURN_COMPLETION_CHECKPOINT,
            std.json.fmt(ToolTurnCompletion{
                .original_user = original_user,
                .assistant_response = assistant_response,
            }, .{}),
        },
    ) catch return false;
    defer allocator.free(checkpoint);

    store.saveMessage(session_key, TOOL_TURN_CHECKPOINT_ROLE, checkpoint) catch return false;
    store.saveUsage(session_key, total_tokens) catch {};
    return true;
}

/// Checkpoint the safe approval result before the fallible provider
/// continuation. The caller must first establish the complete pause prefix.
pub fn persistApprovalResultCheckpoint(
    store: memory_mod.SessionStore,
    session_key: []const u8,
    tool_result: []const u8,
    total_tokens: u64,
) bool {
    store.saveMessage(session_key, "user", tool_result) catch return false;
    store.saveUsage(session_key, total_tokens) catch {};
    return true;
}

/// Write-ahead receipt stored after the one-shot response is validated but
/// before an approved external side effect may start. Its conservative wording
/// remains safe across a crash on either side of the execution boundary.
pub fn persistApprovalExecutionIntentCheckpoint(
    store: memory_mod.SessionStore,
    session_key: []const u8,
    total_tokens: u64,
) bool {
    store.saveMessage(session_key, "user", APPROVAL_EXECUTION_INTENT_CHECKPOINT) catch return false;
    store.saveUsage(session_key, total_tokens) catch {};
    return true;
}

/// Append the final assistant reply to an already checkpointed logical turn.
pub fn persistAssistantCheckpoint(
    store: memory_mod.SessionStore,
    state: TurnPersistenceState,
    session_key: []const u8,
    response: []const u8,
) bool {
    const persisted_assistant = persistedAssistantReply(state.history, response);
    store.saveMessage(session_key, "assistant", persisted_assistant) catch return false;
    store.saveUsage(session_key, state.total_tokens) catch {};
    return true;
}

test "persistTurn stores user and assistant messages in session history" {
    const allocator = std.testing.allocator;
    var mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();

    const store = mem.sessionStore();
    var history: std.ArrayListUnmanaged(Agent.OwnedMessage) = .empty;
    defer {
        for (history.items) |msg| msg.deinit(allocator);
        history.deinit(allocator);
    }

    try history.append(allocator, .{
        .role = .assistant,
        .content = try allocator.dupe(u8, "pong"),
    });

    persistTurn(store, .{ .history = history.items, .total_tokens = 42 }, "test-cli-session", "ping", "pong");

    const sessions = try store.listSessions(allocator, 10, 0);
    defer memory_mod.freeSessionInfos(allocator, sessions);
    try std.testing.expectEqual(@as(usize, 1), sessions.len);
    try std.testing.expectEqualStrings("test-cli-session", sessions[0].session_id);
    try std.testing.expectEqual(@as(u64, 2), sessions[0].message_count);

    const detailed = try store.loadMessagesDetailed(allocator, "test-cli-session", 10, 0);
    defer memory_mod.freeDetailedMessages(allocator, detailed);
    try std.testing.expectEqual(@as(usize, 2), detailed.len);
    try std.testing.expectEqualStrings("user", detailed[0].role);
    try std.testing.expectEqualStrings("ping", detailed[0].content);
    try std.testing.expectEqualStrings("assistant", detailed[1].role);
    try std.testing.expectEqualStrings("pong", detailed[1].content);
    try std.testing.expectEqual(@as(?u64, 42), try store.loadUsage("test-cli-session"));
}

test "approval checkpoints persist closed prefix and approved result before continuation" {
    // Regression: a process/provider failure after an approved side effect
    // must leave a durable receipt without storing a dangling tool call or its
    // bearer request id.
    const allocator = std.testing.allocator;
    var mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();
    const store = mem.sessionStore();

    try std.testing.expect(persistApprovalPauseCheckpoint(
        allocator,
        store,
        "approval-checkpoint",
        "run guarded action",
        false,
        "completed prefix",
        "<tool_results>prefix receipt</tool_results>",
        7,
    ));
    try std.testing.expect(persistApprovalExecutionIntentCheckpoint(
        store,
        "approval-checkpoint",
        7,
    ));
    try std.testing.expect(persistApprovalResultCheckpoint(
        store,
        "approval-checkpoint",
        "approved execution receipt",
        8,
    ));

    var history: std.ArrayListUnmanaged(Agent.OwnedMessage) = .empty;
    defer {
        for (history.items) |msg| msg.deinit(allocator);
        history.deinit(allocator);
    }
    try history.append(allocator, .{
        .role = .assistant,
        .content = try allocator.dupe(u8, "final continuation"),
    });
    try std.testing.expect(persistAssistantCheckpoint(
        store,
        .{ .history = history.items, .total_tokens = 9 },
        "approval-checkpoint",
        "rendered final continuation",
    ));

    const detailed = try store.loadMessagesDetailed(allocator, "approval-checkpoint", 20, 0);
    defer memory_mod.freeDetailedMessages(allocator, detailed);
    try std.testing.expectEqual(@as(usize, 4), detailed.len);
    try std.testing.expectEqualStrings("assistant", detailed[0].role);
    try std.testing.expect(std.mem.indexOf(u8, detailed[0].content, APPROVAL_PAUSE_CHECKPOINT) != null);
    try std.testing.expect(std.mem.indexOf(u8, detailed[0].content, "run guarded action") != null);
    try std.testing.expect(std.mem.indexOf(u8, detailed[0].content, "completed prefix") != null);
    try std.testing.expect(std.mem.indexOf(u8, detailed[0].content, "prefix receipt") != null);
    try std.testing.expectEqualStrings("user", detailed[1].role);
    try std.testing.expectEqualStrings(APPROVAL_EXECUTION_INTENT_CHECKPOINT, detailed[1].content);
    try std.testing.expectEqualStrings("user", detailed[2].role);
    try std.testing.expectEqualStrings("approved execution receipt", detailed[2].content);
    try std.testing.expectEqualStrings("assistant", detailed[3].role);
    try std.testing.expectEqualStrings("final continuation", detailed[3].content);
    try std.testing.expectEqual(@as(?u64, 9), try store.loadUsage("approval-checkpoint"));
}

test "tool turn completion checkpoint stores canonical outcome projection" {
    // Regression: slash /approve returns directly without appending Agent
    // history. Its durable outcome must be the returned execution result, not
    // an assistant message left over from an earlier turn.
    const allocator = std.testing.allocator;
    var mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();
    const store = mem.sessionStore();

    try std.testing.expect(persistToolTurnWriteAheadCheckpoint(
        allocator,
        store,
        "local-approval-outcome",
        null,
        3,
    ));
    try std.testing.expect(persistToolTurnCompletionCheckpoint(
        allocator,
        store,
        "local-approval-outcome",
        null,
        "Approved exec completed safely",
        4,
    ));

    const detailed = try store.loadMessagesDetailed(allocator, "local-approval-outcome", 10, 0);
    defer memory_mod.freeDetailedMessages(allocator, detailed);
    try std.testing.expectEqual(@as(usize, 2), detailed.len);
    try std.testing.expect(std.mem.indexOf(u8, detailed[0].content, TOOL_TURN_WRITE_AHEAD_CHECKPOINT) != null);
    try std.testing.expect(std.mem.startsWith(u8, detailed[1].content, TOOL_TURN_COMPLETION_CHECKPOINT));
    try std.testing.expect(std.mem.indexOf(u8, detailed[1].content, "Approved exec completed safely") != null);
    try std.testing.expectEqual(@as(?u64, 4), try store.loadUsage("local-approval-outcome"));
}

test "approval pause checkpoint is one atomic store record" {
    // Regression: multiple independent saveMessage calls could crash after a
    // completed tool prefix but before the terminal pause fence was durable.
    const FaultStore = struct {
        allocator: std.mem.Allocator,
        fail_next: bool = true,
        save_calls: usize = 0,
        saved_role: ?[]u8 = null,
        saved_content: ?[]u8 = null,

        fn deinit(self: *@This()) void {
            if (self.saved_role) |value| self.allocator.free(value);
            if (self.saved_content) |value| self.allocator.free(value);
        }

        fn sessionStore(self: *@This()) memory_mod.SessionStore {
            return .{ .ptr = @ptrCast(self), .vtable = &vtable };
        }

        fn saveMessage(ptr: *anyopaque, _: []const u8, role: []const u8, content: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.save_calls += 1;
            if (self.fail_next) {
                self.fail_next = false;
                return error.InjectedStoreFailure;
            }
            const owned_role = try self.allocator.dupe(u8, role);
            errdefer self.allocator.free(owned_role);
            const owned_content = try self.allocator.dupe(u8, content);
            if (self.saved_role) |value| self.allocator.free(value);
            if (self.saved_content) |value| self.allocator.free(value);
            self.saved_role = owned_role;
            self.saved_content = owned_content;
        }

        fn loadMessages(_: *anyopaque, allocator: std.mem.Allocator, _: []const u8) anyerror![]memory_mod.MessageEntry {
            return allocator.alloc(memory_mod.MessageEntry, 0);
        }

        fn clearMessages(ptr: *anyopaque, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.saved_role) |value| self.allocator.free(value);
            if (self.saved_content) |value| self.allocator.free(value);
            self.saved_role = null;
            self.saved_content = null;
        }

        fn clearAutoSaved(_: *anyopaque, _: ?[]const u8) anyerror!void {}

        const vtable = memory_mod.SessionStore.VTable{
            .saveMessage = saveMessage,
            .loadMessages = loadMessages,
            .clearMessages = clearMessages,
            .clearAutoSaved = clearAutoSaved,
        };
    };

    const allocator = std.testing.allocator;
    var fault_store = FaultStore{ .allocator = allocator };
    defer fault_store.deinit();
    const store = fault_store.sessionStore();

    try std.testing.expect(!persistApprovalPauseCheckpoint(
        allocator,
        store,
        "atomic-approval",
        "original request",
        false,
        "completed prefix",
        "completed result",
        1,
    ));
    try std.testing.expectEqual(@as(usize, 1), fault_store.save_calls);
    try std.testing.expect(fault_store.saved_content == null);

    try std.testing.expect(persistApprovalPauseCheckpoint(
        allocator,
        store,
        "atomic-approval",
        "original request",
        false,
        "completed prefix",
        "completed result",
        1,
    ));
    try std.testing.expectEqual(@as(usize, 2), fault_store.save_calls);
    try std.testing.expectEqualStrings("assistant", fault_store.saved_role.?);
    try std.testing.expect(std.mem.indexOf(u8, fault_store.saved_content.?, APPROVAL_PAUSE_CHECKPOINT) != null);
    try std.testing.expect(std.mem.indexOf(u8, fault_store.saved_content.?, "original request") != null);
    try std.testing.expect(std.mem.indexOf(u8, fault_store.saved_content.?, "completed prefix") != null);
    try std.testing.expect(std.mem.indexOf(u8, fault_store.saved_content.?, "completed result") != null);
}

test "persistTurn clears prior session history on reset" {
    const allocator = std.testing.allocator;
    var mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();

    const store = mem.sessionStore();
    try store.saveMessage("test-cli-session", "user", "old");
    try store.saveMessage("test-cli-session", "assistant", "history");

    var history: std.ArrayListUnmanaged(Agent.OwnedMessage) = .empty;
    defer {
        for (history.items) |msg| msg.deinit(allocator);
        history.deinit(allocator);
    }

    try history.append(allocator, .{
        .role = .assistant,
        .content = try allocator.dupe(u8, "fresh reply"),
    });

    // Regression: CLI turns with explicit session ids must update the session-store
    // history tables, not just the memories table, so `history list/show` stays populated.
    persistTurn(store, .{ .history = history.items, .total_tokens = 7 }, "test-cli-session", "/reset", "fresh reply");

    const detailed = try store.loadMessagesDetailed(allocator, "test-cli-session", 10, 0);
    defer memory_mod.freeDetailedMessages(allocator, detailed);
    try std.testing.expectEqual(@as(usize, 2), detailed.len);
    try std.testing.expectEqualStrings("user", detailed[0].role);
    try std.testing.expectEqualStrings(commands.BARE_SESSION_RESET_PROMPT, detailed[0].content);
    try std.testing.expectEqualStrings("assistant", detailed[1].role);
    try std.testing.expectEqualStrings("fresh reply", detailed[1].content);
}

test "applySessionReset clears persisted state before fallible serialization" {
    // Regression: persistence redaction can fail after a successful /new. The
    // old transcript and autosaves must still be cleared even when no new
    // messages can be serialized safely.
    const allocator = std.testing.allocator;
    var mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();

    const store = mem.sessionStore();
    try store.saveMessage("reset-before-redaction", "user", "old request");
    try mem.memory().store(
        "autosave_user_1",
        "old autosave",
        .conversation,
        "reset-before-redaction",
    );

    try std.testing.expect(applySessionReset(store, "reset-before-redaction", "/new"));

    const detailed = try store.loadMessagesDetailed(allocator, "reset-before-redaction", 10, 0);
    defer memory_mod.freeDetailedMessages(allocator, detailed);
    try std.testing.expectEqual(@as(usize, 0), detailed.len);
    const autosave = try mem.memory().get(allocator, "autosave_user_1");
    try std.testing.expect(autosave == null);
}

test "persistTurn falls back to rendered response when assistant history is absent" {
    const allocator = std.testing.allocator;
    var mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();

    const store = mem.sessionStore();
    var history: std.ArrayListUnmanaged(Agent.OwnedMessage) = .empty;
    defer history.deinit(allocator);

    // Regression: degraded turns can return a response without appending a final
    // assistant history message, so persistence must keep the rendered reply.
    persistTurn(store, .{ .history = history.items, .total_tokens = 9 }, "fallback-session", "hello", "fallback reply");

    const detailed = try store.loadMessagesDetailed(allocator, "fallback-session", 10, 0);
    defer memory_mod.freeDetailedMessages(allocator, detailed);
    try std.testing.expectEqual(@as(usize, 2), detailed.len);
    try std.testing.expectEqualStrings("assistant", detailed[1].role);
    try std.testing.expectEqualStrings("fallback reply", detailed[1].content);
}

test "persistTurn does not persist system prompt history entries" {
    const allocator = std.testing.allocator;
    var mem = try memory_mod.SqliteMemory.init(allocator, ":memory:");
    defer mem.deinit();

    const store = mem.sessionStore();
    var history: std.ArrayListUnmanaged(Agent.OwnedMessage) = .empty;
    defer {
        for (history.items) |msg| msg.deinit(allocator);
        history.deinit(allocator);
    }

    try history.append(allocator, .{
        .role = .system,
        .content = try allocator.dupe(u8, "ops contact admin@example.com token=sk-system-secret"),
    });
    try history.append(allocator, .{
        .role = .assistant,
        .content = try allocator.dupe(u8, "ok"),
    });

    persistTurn(store, .{ .history = history.items, .total_tokens = 1 }, "system-history-session", "hello", "ok");

    const detailed = try store.loadMessagesDetailed(allocator, "system-history-session", 10, 0);
    defer memory_mod.freeDetailedMessages(allocator, detailed);
    try std.testing.expectEqual(@as(usize, 2), detailed.len);
    for (detailed) |message| {
        try std.testing.expect(!std.mem.eql(u8, message.role, "system"));
        try std.testing.expect(std.mem.indexOf(u8, message.content, "admin@example.com") == null);
        try std.testing.expect(std.mem.indexOf(u8, message.content, "sk-system-secret") == null);
    }
}
