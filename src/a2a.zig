//! A2A (Agent-to-Agent) protocol support for nullclaw.
//!
//! Implements Google's Agent-to-Agent protocol v0.3.0 over JSON-RPC 2.0:
//!   - GET /.well-known/agent-card.json -> Agent Card discovery
//!   - POST /a2a -> JSON-RPC dispatch (message/send, message/stream, tasks/get, tasks/cancel,
//!     tasks/list, tasks/resubscribe)
//!
//! Task state machine: submitted -> working -> completed | failed | canceled | rejected | input-required | auth-required

const std = @import("std");
const builtin = @import("builtin");
const Config = @import("config.zig").Config;
const gateway = @import("gateway.zig");
const ConversationContext = @import("agent/prompt.zig").ConversationContext;
const buildConversationContext = @import("agent/prompt.zig").buildConversationContext;
const streaming = @import("streaming.zig");

/// Maximum number of tasks kept in the registry before eviction.
const MAX_TASKS: usize = 1000;
const A2A_PROTOCOL_VERSION = "0.3.0";

// ── Task State ──────────────────────────────────────────────────

pub const TaskState = enum {
    submitted,
    working,
    completed,
    failed,
    canceled,
    input_required,
    rejected,
    auth_required,
    unknown,

    pub fn jsonName(self: TaskState) []const u8 {
        return switch (self) {
            .submitted => "submitted",
            .working => "working",
            .completed => "completed",
            .failed => "failed",
            .canceled => "canceled",
            .input_required => "input-required",
            .rejected => "rejected",
            .auth_required => "auth-required",
            .unknown => "unknown",
        };
    }
};

// ── Task Record ─────────────────────────────────────────────────

pub const TaskRecord = struct {
    id: []u8,
    context_id: []u8,
    session_key: []u8,
    state: TaskState,
    created_at: i64,
    updated_at: i64,
    user_text: []u8,
    agent_text: []u8,
};

pub const TaskSnapshot = struct {
    id: []u8,
    context_id: []u8,
    session_key: []u8,
    state: TaskState,
    created_at: i64,
    updated_at: i64,
    user_text: []u8,
    agent_text: []u8,

    pub fn deinit(self: *TaskSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.context_id);
        allocator.free(self.session_key);
        allocator.free(self.user_text);
        allocator.free(self.agent_text);
    }
};

fn deinitTaskSnapshots(allocator: std.mem.Allocator, tasks: []TaskSnapshot) void {
    for (tasks) |*task| task.deinit(allocator);
    allocator.free(tasks);
}

fn isTerminalState(state: TaskState) bool {
    return switch (state) {
        .completed, .failed, .canceled, .rejected => true,
        else => false,
    };
}

fn taskOrdinal(task_id: []const u8) u64 {
    const prefix = "task-";
    if (!std.mem.startsWith(u8, task_id, prefix)) return 0;
    return std.fmt.parseInt(u64, task_id[prefix.len..], 10) catch 0;
}

fn isTaskSnapshotMoreRecent(current: TaskSnapshot, previous: TaskSnapshot) bool {
    if (current.updated_at != previous.updated_at) {
        return current.updated_at > previous.updated_at;
    }
    return taskOrdinal(current.id) > taskOrdinal(previous.id);
}

fn sortTaskSnapshotsByRecency(tasks: []TaskSnapshot) void {
    var i: usize = 1;
    while (i < tasks.len) : (i += 1) {
        const current = tasks[i];
        var j = i;
        while (j > 0) : (j -= 1) {
            const prev = tasks[j - 1];
            const more_recent = isTaskSnapshotMoreRecent(current, prev);
            if (!more_recent) break;
            tasks[j] = prev;
        }
        tasks[j] = current;
    }
}

// ── Task Registry ───────────────────────────────────────────────

pub const TaskRegistry = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    tasks: std.StringHashMapUnmanaged(*TaskRecord) = .empty,
    next_id: u64 = 1,

    pub fn init(allocator: std.mem.Allocator) TaskRegistry {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *TaskRegistry) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = self.tasks.iterator();
        while (iter.next()) |entry| {
            self.freeTask(entry.value_ptr.*);
        }
        self.tasks.deinit(self.allocator);
    }

    pub fn createTask(self: *TaskRegistry, allocator: std.mem.Allocator, user_text: []const u8, context_id: ?[]const u8) !TaskSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Evict the least-recently-updated terminal task. If all tasks are active,
        // reject the new task to keep the registry strictly capped.
        if (self.tasks.count() >= MAX_TASKS) {
            if (!self.evictOldestTerminalLocked()) {
                return error.TaskRegistryFull;
            }
        }

        const id_num = self.next_id;
        self.next_id += 1;

        const task_id = try std.fmt.allocPrint(self.allocator, "task-{d}", .{id_num});
        errdefer self.allocator.free(task_id);

        const owned_context_id = if (context_id) |value|
            try self.allocator.dupe(u8, value)
        else
            try std.fmt.allocPrint(self.allocator, "ctx-{d}", .{id_num});
        errdefer self.allocator.free(owned_context_id);

        const session_key = try std.fmt.allocPrint(self.allocator, "a2a:{s}", .{owned_context_id});
        errdefer self.allocator.free(session_key);

        const owned_text = try self.allocator.dupe(u8, user_text);
        errdefer self.allocator.free(owned_text);

        const empty_agent = try self.allocator.dupe(u8, "");
        errdefer self.allocator.free(empty_agent);

        const now = std.time.timestamp();

        const task = try self.allocator.create(TaskRecord);
        errdefer self.allocator.destroy(task);

        task.* = .{
            .id = task_id,
            .context_id = owned_context_id,
            .session_key = session_key,
            .state = .submitted,
            .created_at = now,
            .updated_at = now,
            .user_text = owned_text,
            .agent_text = empty_agent,
        };

        try self.tasks.put(self.allocator, task_id, task);
        errdefer {
            if (self.tasks.fetchRemove(task_id)) |removed| {
                self.freeTask(removed.value);
            }
        }

        return self.snapshotLocked(allocator, task);
    }

    pub fn getTaskSnapshot(self: *TaskRegistry, allocator: std.mem.Allocator, task_id: []const u8) !?TaskSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        const task = self.tasks.get(task_id) orelse return null;
        return try self.snapshotLocked(allocator, task);
    }

    pub fn taskCount(self: *TaskRegistry) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.tasks.count();
    }

    pub fn setTaskState(self: *TaskRegistry, task_id: []const u8, new_state: TaskState) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const task = self.tasks.get(task_id) orelse return false;
        if (isTerminalState(task.state) and task.state != new_state) return false;
        task.state = new_state;
        task.updated_at = std.time.timestamp();
        return true;
    }

    pub fn finalizeTask(
        self: *TaskRegistry,
        allocator: std.mem.Allocator,
        task_id: []const u8,
        final_state: TaskState,
        agent_text: ?[]const u8,
    ) !?TaskSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        const task = self.tasks.get(task_id) orelse return null;
        if (task.state == .canceled and final_state != .canceled) {
            return try self.snapshotLocked(allocator, task);
        }

        if (agent_text) |text| {
            const new_agent_text = try self.allocator.dupe(u8, text);
            errdefer self.allocator.free(new_agent_text);
            self.allocator.free(task.agent_text);
            task.agent_text = new_agent_text;
        }

        task.state = final_state;
        task.updated_at = std.time.timestamp();
        return try self.snapshotLocked(allocator, task);
    }

    pub fn cancelTask(self: *TaskRegistry, allocator: std.mem.Allocator, task_id: []const u8) !?TaskSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        const task = self.tasks.get(task_id) orelse return null;
        if (!isTerminalState(task.state)) {
            task.state = .canceled;
            task.updated_at = std.time.timestamp();
        }
        return try self.snapshotLocked(allocator, task);
    }

    /// List tasks with optional filtering. Returns owned task snapshots sorted by recency.
    /// Caller must free the returned slice with `deinitTaskSnapshots`.
    pub fn listTasks(
        self: *TaskRegistry,
        allocator: std.mem.Allocator,
        filter_state: ?TaskState,
        filter_context_id: ?[]const u8,
        max_results: usize,
    ) ![]TaskSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result: std.ArrayListUnmanaged(TaskSnapshot) = .empty;
        errdefer {
            for (result.items) |*task| task.deinit(allocator);
            result.deinit(allocator);
        }

        var iter = self.tasks.iterator();
        while (iter.next()) |entry| {
            const task = entry.value_ptr.*;
            if (filter_state) |s| {
                if (task.state != s) continue;
            }
            if (filter_context_id) |ctx| {
                if (!std.mem.eql(u8, task.context_id, ctx)) continue;
            }
            try result.append(allocator, try self.snapshotLocked(allocator, task));
        }

        sortTaskSnapshotsByRecency(result.items);
        if (result.items.len > max_results) {
            var i = max_results;
            while (i < result.items.len) : (i += 1) {
                result.items[i].deinit(allocator);
            }
            result.items.len = max_results;
        }
        return result.toOwnedSlice(allocator);
    }

    /// Evict the least-recently-updated terminal task. Must be called with mutex held.
    fn evictOldestTerminalLocked(self: *TaskRegistry) bool {
        var oldest_key: ?[]const u8 = null;
        var oldest_time: i64 = std.math.maxInt(i64);
        var oldest_ordinal: u64 = std.math.maxInt(u64);

        var iter = self.tasks.iterator();
        while (iter.next()) |entry| {
            const task = entry.value_ptr.*;
            const ordinal = taskOrdinal(task.id);
            if (isTerminalState(task.state) and
                (task.updated_at < oldest_time or
                    (task.updated_at == oldest_time and ordinal < oldest_ordinal)))
            {
                oldest_time = task.updated_at;
                oldest_ordinal = ordinal;
                oldest_key = entry.key_ptr.*;
            }
        }

        if (oldest_key) |key| {
            if (self.tasks.fetchRemove(key)) |kv| {
                self.freeTask(kv.value);
                return true;
            }
        }
        return false;
    }

    fn freeTask(self: *TaskRegistry, task: *TaskRecord) void {
        self.allocator.free(task.id);
        self.allocator.free(task.context_id);
        self.allocator.free(task.session_key);
        self.allocator.free(task.user_text);
        self.allocator.free(task.agent_text);
        self.allocator.destroy(task);
    }

    fn snapshotLocked(self: *TaskRegistry, allocator: std.mem.Allocator, task: *const TaskRecord) !TaskSnapshot {
        _ = self;
        const id = try allocator.dupe(u8, task.id);
        errdefer allocator.free(id);
        const context_id = try allocator.dupe(u8, task.context_id);
        errdefer allocator.free(context_id);
        const session_key = try allocator.dupe(u8, task.session_key);
        errdefer allocator.free(session_key);
        const user_text = try allocator.dupe(u8, task.user_text);
        errdefer allocator.free(user_text);
        const agent_text = try allocator.dupe(u8, task.agent_text);
        errdefer allocator.free(agent_text);

        return .{
            .id = id,
            .context_id = context_id,
            .session_key = session_key,
            .state = task.state,
            .created_at = task.created_at,
            .updated_at = task.updated_at,
            .user_text = user_text,
            .agent_text = agent_text,
        };
    }
};

// ── A2A Response ────────────────────────────────────────────────

pub const A2aResponse = struct {
    status: []const u8 = "200 OK",
    body: []const u8,
    content_type: []const u8 = "application/json",
    allocated: bool = true,
};

// ── Handler: Agent Card ─────────────────────────────────────────

pub fn handleAgentCard(allocator: std.mem.Allocator, cfg: *const Config) A2aResponse {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    const endpoint_url = buildEndpointUrl(allocator, cfg.a2a.url) catch return errorResponse();
    defer allocator.free(endpoint_url);

    const w = buf.writer(allocator);
    w.writeAll("{\"name\":\"") catch return errorResponse();
    gateway.jsonEscapeInto(w, cfg.a2a.name) catch return errorResponse();
    w.writeAll("\",\"description\":\"") catch return errorResponse();
    gateway.jsonEscapeInto(w, cfg.a2a.description) catch return errorResponse();
    w.writeAll("\",\"protocolVersion\":\"") catch return errorResponse();
    w.writeAll(A2A_PROTOCOL_VERSION) catch return errorResponse();
    w.writeAll("\",\"version\":\"") catch return errorResponse();
    gateway.jsonEscapeInto(w, cfg.a2a.version) catch return errorResponse();
    // url field for backward compatibility with older A2A clients.
    w.writeAll("\",\"url\":\"") catch return errorResponse();
    gateway.jsonEscapeInto(w, endpoint_url) catch return errorResponse();
    // supported_interfaces per latest spec (required).
    w.writeAll("\",\"supportedInterfaces\":[{\"url\":\"") catch return errorResponse();
    gateway.jsonEscapeInto(w, endpoint_url) catch return errorResponse();
    w.writeAll("\",\"protocolBinding\":\"JSONRPC\",\"protocolVersion\":\"") catch return errorResponse();
    w.writeAll(A2A_PROTOCOL_VERSION) catch return errorResponse();
    w.writeAll("\"}],\"preferredTransport\":\"JSONRPC\"") catch return errorResponse();
    w.writeAll(",\"provider\":{\"organization\":\"") catch return errorResponse();
    gateway.jsonEscapeInto(w, cfg.a2a.name) catch return errorResponse();
    w.writeAll("\",\"url\":\"") catch return errorResponse();
    if (cfg.a2a.url.len > 0) {
        gateway.jsonEscapeInto(w, cfg.a2a.url) catch return errorResponse();
    } else {
        w.writeAll("https://github.com/nullclaw/nullclaw") catch return errorResponse();
    }
    w.writeAll("\"}") catch return errorResponse();
    w.writeAll(",\"capabilities\":{\"streaming\":true}") catch return errorResponse();
    w.writeAll(",\"securitySchemes\":{\"bearerAuth\":{\"type\":\"http\",\"scheme\":\"bearer\",\"description\":\"Use a pairing token from /pair as the bearer token.\"}}") catch return errorResponse();
    w.writeAll(",\"security\":[{\"bearerAuth\":[]}]") catch return errorResponse();
    w.writeAll(",\"defaultInputModes\":[\"text/plain\"],\"defaultOutputModes\":[\"text/plain\"]") catch return errorResponse();
    w.writeAll(",\"skills\":[{\"id\":\"chat\",\"name\":\"General Chat\",\"description\":\"General-purpose AI assistant\",\"tags\":[\"chat\",\"general\"]}]") catch return errorResponse();
    w.writeAll("}") catch return errorResponse();

    const body = buf.toOwnedSlice(allocator) catch return errorResponse();
    return .{ .body = body };
}

// ── Handler: JSON-RPC Dispatch ──────────────────────────────────

pub fn handleJsonRpc(
    allocator: std.mem.Allocator,
    body: []const u8,
    registry: *TaskRegistry,
    session_mgr: anytype,
) A2aResponse {
    const method = extractJsonRpcMethod(body) orelse {
        const err_body = buildJsonRpcError(allocator, "null", -32600, "Missing method") catch
            return errorResponse();
        return .{ .body = err_body };
    };

    // Extract JSON-RPC id — may be a string or number.
    const request_id = extractJsonRpcId(body) orelse "null";

    if (std.mem.eql(u8, method, "message/send") or
        std.mem.eql(u8, method, "message/stream") or
        std.mem.eql(u8, method, "SendMessage") or
        std.mem.eql(u8, method, "SendStreamingMessage"))
    {
        return handleSendMessage(allocator, body, request_id, registry, session_mgr);
    } else if (std.mem.eql(u8, method, "tasks/get") or std.mem.eql(u8, method, "GetTask")) {
        return handleGetTask(allocator, body, request_id, registry);
    } else if (std.mem.eql(u8, method, "tasks/cancel") or std.mem.eql(u8, method, "CancelTask")) {
        return handleCancelTask(allocator, body, request_id, registry, session_mgr);
    } else if (std.mem.eql(u8, method, "tasks/list") or std.mem.eql(u8, method, "ListTasks")) {
        return handleListTasks(allocator, body, request_id, registry);
    } else if (std.mem.startsWith(u8, method, "tasks/pushNotificationConfig/") or
        std.mem.eql(u8, method, "CreateTaskPushNotificationConfig") or
        std.mem.eql(u8, method, "GetTaskPushNotificationConfig") or
        std.mem.eql(u8, method, "ListTaskPushNotificationConfigs") or
        std.mem.eql(u8, method, "DeleteTaskPushNotificationConfig"))
    {
        const err_body = buildJsonRpcError(allocator, request_id, -32003, "Push notifications not supported") catch
            return errorResponse();
        return .{ .body = err_body };
    } else if (std.mem.eql(u8, method, "agent/getAuthenticatedExtendedCard") or std.mem.eql(u8, method, "GetExtendedAgentCard")) {
        const err_body = buildJsonRpcError(allocator, request_id, -32004, "Extended agent card not supported") catch
            return errorResponse();
        return .{ .body = err_body };
    } else {
        const err_body = buildJsonRpcError(allocator, request_id, -32601, "Method not found") catch
            return errorResponse();
        return .{ .body = err_body };
    }
}

// ── SSE Streaming ───────────────────────────────────────────────

/// Check if a JSON-RPC body contains a streaming method.
/// Used by the gateway to decide between normal and SSE response paths.
pub fn isStreamingMethod(body: []const u8) bool {
    const method = extractJsonRpcMethod(body) orelse return false;
    return std.mem.eql(u8, method, "message/stream") or
        std.mem.eql(u8, method, "tasks/resubscribe") or
        std.mem.eql(u8, method, "SendStreamingMessage") or
        std.mem.eql(u8, method, "SubscribeToTask");
}

/// SSE Sink context — writes JSON-RPC SSE events to a raw TCP stream.
pub const SseStreamCtx = struct {
    stream: *std.net.Stream,
    allocator: std.mem.Allocator,
    request_id: []const u8,
    task_id: []const u8,
    context_id: []const u8,
    filter: streaming.TagFilter = undefined,

    /// Write an SSE "data:" line with the given JSON payload.
    fn writeSseEvent(self: *SseStreamCtx, json_data: []const u8) void {
        self.stream.writeAll("data: ") catch return;
        self.stream.writeAll(json_data) catch return;
        self.stream.writeAll("\n\n") catch return;
    }

    /// Build and emit an SSE event with a working status and text delta.
    fn emitChunkEvent(self: *SseStreamCtx, text: []const u8) void {
        const data = buildArtifactUpdateEvent(self.allocator, self.request_id, self.task_id, self.context_id, text, false) catch return;
        defer self.allocator.free(data);
        self.writeSseEvent(data);
    }

    fn sseCallback(ctx: *anyopaque, event: streaming.Event) void {
        const self: *SseStreamCtx = @ptrCast(@alignCast(ctx));
        switch (event.stage) {
            .chunk => {
                if (event.text.len > 0) self.emitChunkEvent(event.text);
            },
            .final => {}, // Final event is handled after processMessageStreaming returns.
        }
    }

    pub fn makeSink(self: *SseStreamCtx) streaming.Sink {
        const raw_sink = streaming.Sink{
            .callback = sseCallback,
            .ctx = @ptrCast(self),
        };
        self.filter = streaming.TagFilter.init(raw_sink);
        return self.filter.sink();
    }
};

/// Handle a streaming JSON-RPC request by writing SSE events directly to the TCP stream.
/// This bypasses the normal request/response cycle and writes directly.
/// The caller must NOT call writeJsonResponse after this.
pub fn handleStreamingRpc(
    allocator: std.mem.Allocator,
    body: []const u8,
    stream: *std.net.Stream,
    registry: *TaskRegistry,
    session_mgr: anytype,
) void {
    const request_id = extractJsonRpcId(body) orelse "null";

    // Handle tasks/resubscribe: resume SSE for an existing task.
    const method = extractJsonRpcMethod(body) orelse "message/stream";
    if (std.mem.eql(u8, method, "tasks/resubscribe") or std.mem.eql(u8, method, "SubscribeToTask")) {
        handleResubscribeStreaming(allocator, body, stream, request_id, registry);
        return;
    }

    const text = extractMessageText(body) orelse {
        writeSseError(allocator, stream, request_id, -32602, "Missing message text");
        return;
    };

    // v0.3.0: messageId is required on Message.
    if (extractMessageMessageId(body) == null) {
        writeSseError(allocator, stream, request_id, -32602, "Missing messageId");
        return;
    }

    const context_id = extractMessageContextId(body);

    var task = registry.createTask(allocator, text, context_id) catch {
        writeSseError(allocator, stream, request_id, -32603, "Failed to create task");
        return;
    };
    defer task.deinit(allocator);

    // Write SSE headers.
    stream.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n") catch return;

    const initial_task_json = buildTaskJson(allocator, &task, null) catch return;
    defer allocator.free(initial_task_json);
    const initial_event = buildJsonRpcResult(allocator, request_id, initial_task_json) catch return;
    defer allocator.free(initial_event);
    stream.writeAll("data: ") catch return;
    stream.writeAll(initial_event) catch return;
    stream.writeAll("\n\n") catch return;

    // Mark as working after emitting the initial submitted task.
    if (!registry.setTaskState(task.id, .working)) {
        var current_task = registry.getTaskSnapshot(allocator, task.id) catch return;
        defer if (current_task) |*snapshot| snapshot.deinit(allocator);
        const current_snapshot = current_task orelse return;
        if (current_snapshot.state == .canceled) {
            const final_event = buildStatusUpdateEvent(allocator, request_id, current_snapshot.id, current_snapshot.context_id, current_snapshot.state, current_snapshot.updated_at, true) catch return;
            defer allocator.free(final_event);
            stream.writeAll("data: ") catch return;
            stream.writeAll(final_event) catch return;
            stream.writeAll("\n\n") catch return;
        }
        return;
    }

    // Create SSE sink context.
    var sse_ctx = SseStreamCtx{
        .stream = stream,
        .allocator = allocator,
        .request_id = request_id,
        .task_id = task.id,
        .context_id = task.context_id,
    };
    const sink = sse_ctx.makeSink();

    const context: ConversationContext = buildConversationContext(.{ .channel = "a2a" }).?;
    const response = session_mgr.processMessageStreaming(task.session_key, text, context, sink) catch {
        var failed_task = registry.finalizeTask(allocator, task.id, .failed, null) catch null;
        defer if (failed_task) |*snapshot| snapshot.deinit(allocator);
        if (failed_task) |snapshot| {
            if (snapshot.state == .canceled) {
                const final_event = buildStatusUpdateEvent(allocator, request_id, snapshot.id, snapshot.context_id, snapshot.state, snapshot.updated_at, true) catch return;
                defer allocator.free(final_event);
                sse_ctx.writeSseEvent(final_event);
            } else {
                writeSseErrorEvent(allocator, &sse_ctx, -32603, "Agent processing failed");
            }
        } else {
            writeSseErrorEvent(allocator, &sse_ctx, -32603, "Agent processing failed");
        }
        return;
    };
    defer freeSessionResponse(session_mgr, response);

    var final_task = registry.finalizeTask(allocator, task.id, .completed, response) catch return;
    defer if (final_task) |*snapshot| snapshot.deinit(allocator);
    const final_snapshot = final_task orelse return;

    const final_event = buildStatusUpdateEvent(allocator, request_id, final_snapshot.id, final_snapshot.context_id, final_snapshot.state, final_snapshot.updated_at, true) catch return;
    defer allocator.free(final_event);
    sse_ctx.writeSseEvent(final_event);
}

/// Handle tasks/resubscribe: emit the current task state as SSE, then close.
fn handleResubscribeStreaming(
    allocator: std.mem.Allocator,
    body: []const u8,
    stream: *std.net.Stream,
    request_id: []const u8,
    registry: *TaskRegistry,
) void {
    const task_id = extractParamsId(body) orelse {
        writeSseError(allocator, stream, request_id, -32602, "Missing task id");
        return;
    };

    var task = registry.getTaskSnapshot(allocator, task_id) catch {
        writeSseError(allocator, stream, request_id, -32603, "Internal error");
        return;
    };
    defer if (task) |*snapshot| snapshot.deinit(allocator);
    const snapshot = task orelse {
        writeSseError(allocator, stream, request_id, -32001, "Task not found");
        return;
    };

    // Write SSE headers.
    stream.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n") catch return;

    // buildResubscribeStatusEvent already returns a JSON-RPC envelope; write it directly.
    const status_event = buildResubscribeStatusEvent(allocator, request_id, snapshot.id, snapshot.context_id, snapshot.state, snapshot.updated_at) catch return;
    defer allocator.free(status_event);
    stream.writeAll("data: ") catch return;
    stream.writeAll(status_event) catch return;
    stream.writeAll("\n\n") catch return;
}

/// Write an SSE error event to the stream context.
fn writeSseErrorEvent(allocator: std.mem.Allocator, sse_ctx: *SseStreamCtx, code: i32, message: []const u8) void {
    const err_json = buildJsonRpcError(allocator, sse_ctx.request_id, code, message) catch return;
    defer allocator.free(err_json);
    sse_ctx.writeSseEvent(err_json);
}

/// Write SSE headers and a single error event for pre-streaming failures.
fn writeSseError(allocator: std.mem.Allocator, stream: *std.net.Stream, request_id: []const u8, code: i32, message: []const u8) void {
    stream.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n") catch return;
    const err_json = buildJsonRpcError(allocator, request_id, code, message) catch return;
    defer allocator.free(err_json);
    stream.writeAll("data: ") catch return;
    stream.writeAll(err_json) catch return;
    stream.writeAll("\n\n") catch return;
}

// ── Internal: Send Message ──────────────────────────────────────

fn handleSendMessage(
    allocator: std.mem.Allocator,
    body: []const u8,
    request_id: []const u8,
    registry: *TaskRegistry,
    session_mgr: anytype,
) A2aResponse {
    const text = extractMessageText(body) orelse {
        const err_body = buildJsonRpcError(allocator, request_id, -32602, "Missing message text") catch
            return errorResponse();
        return .{ .body = err_body };
    };

    // v0.3.0: messageId is required on Message.
    if (extractMessageMessageId(body) == null) {
        const err_body = buildJsonRpcError(allocator, request_id, -32602, "Missing messageId") catch
            return errorResponse();
        return .{ .body = err_body };
    }

    const context_id = extractMessageContextId(body);

    // Parse optional configuration.
    const config = parseSendMessageConfiguration(body);

    if (config.history_length) |history_length| {
        if (history_length < 0) {
            const err_body = buildJsonRpcError(allocator, request_id, -32602, "historyLength must be non-negative") catch
                return errorResponse();
            return .{ .body = err_body };
        }
    }

    // Check acceptedOutputModes: if specified, must include text/plain.
    if (config.has_accepted_output_modes and !config.accepts_text_plain) {
        const err_body = buildJsonRpcError(allocator, request_id, -32005, "Incompatible content types") catch
            return errorResponse();
        return .{ .body = err_body };
    }

    var task = registry.createTask(allocator, text, context_id) catch {
        const err_body = buildJsonRpcError(allocator, request_id, -32603, "Failed to create task") catch
            return errorResponse();
        return .{ .body = err_body };
    };
    defer task.deinit(allocator);

    // Update state to working.
    _ = registry.setTaskState(task.id, .working);

    const context: ConversationContext = buildConversationContext(.{ .channel = "a2a" }).?;
    const response = session_mgr.processMessage(task.session_key, text, context) catch {
        _ = registry.finalizeTask(allocator, task.id, .failed, null) catch null;
        const err_body = buildJsonRpcError(allocator, request_id, -32603, "Agent processing failed") catch
            return errorResponse();
        return .{ .body = err_body };
    };
    defer freeSessionResponse(session_mgr, response);

    var completed_task = registry.finalizeTask(allocator, task.id, .completed, response) catch {
        const err_body = buildJsonRpcError(allocator, request_id, -32603, "Out of memory") catch
            return errorResponse();
        return .{ .body = err_body };
    };
    defer if (completed_task) |*snapshot| snapshot.deinit(allocator);
    const task_snapshot = completed_task orelse {
        const err_body = buildJsonRpcError(allocator, request_id, -32603, "Failed to build response") catch
            return errorResponse();
        return .{ .body = err_body };
    };

    const task_json = buildTaskJson(allocator, &task_snapshot, config.history_length) catch {
        const err_body = buildJsonRpcError(allocator, request_id, -32603, "Failed to build response") catch
            return errorResponse();
        return .{ .body = err_body };
    };
    defer allocator.free(task_json);

    const result = buildJsonRpcResult(allocator, request_id, task_json) catch
        return errorResponse();
    return .{ .body = result };
}

// ── Internal: Get Task ──────────────────────────────────────────

fn handleGetTask(
    allocator: std.mem.Allocator,
    body: []const u8,
    request_id: []const u8,
    registry: *TaskRegistry,
) A2aResponse {
    const task_id = extractParamsId(body) orelse {
        const err_body = buildJsonRpcError(allocator, request_id, -32602, "Missing task id") catch
            return errorResponse();
        return .{ .body = err_body };
    };

    // Parse optional historyLength from params.
    const params_section = extractParamsObject(body) orelse "{}";
    const history_length = extractObjectIntField(params_section, "historyLength");
    if (history_length) |value| {
        if (value < 0) {
            const err_body = buildJsonRpcError(allocator, request_id, -32602, "historyLength must be non-negative") catch
                return errorResponse();
            return .{ .body = err_body };
        }
    }

    var task = registry.getTaskSnapshot(allocator, task_id) catch return errorResponse();
    defer if (task) |*snapshot| snapshot.deinit(allocator);
    const task_snapshot = task orelse {
        const err_body = buildJsonRpcError(allocator, request_id, -32001, "Task not found") catch
            return errorResponse();
        return .{ .body = err_body };
    };

    const task_json = buildTaskJson(allocator, &task_snapshot, history_length) catch {
        const err_body = buildJsonRpcError(allocator, request_id, -32603, "Failed to build response") catch
            return errorResponse();
        return .{ .body = err_body };
    };
    defer allocator.free(task_json);

    const result = buildJsonRpcResult(allocator, request_id, task_json) catch
        return errorResponse();
    return .{ .body = result };
}

// ── Internal: Cancel Task ───────────────────────────────────────

fn handleCancelTask(
    allocator: std.mem.Allocator,
    body: []const u8,
    request_id: []const u8,
    registry: *TaskRegistry,
    session_mgr: anytype,
) A2aResponse {
    const task_id = extractParamsId(body) orelse {
        const err_body = buildJsonRpcError(allocator, request_id, -32602, "Missing task id") catch
            return errorResponse();
        return .{ .body = err_body };
    };

    var current_task = registry.getTaskSnapshot(allocator, task_id) catch return errorResponse();
    defer if (current_task) |*snapshot| snapshot.deinit(allocator);
    const task = current_task orelse {
        const err_body = buildJsonRpcError(allocator, request_id, -32001, "Task not found") catch
            return errorResponse();
        return .{ .body = err_body };
    };

    if (isTerminalState(task.state)) {
        const err_body = buildJsonRpcError(allocator, request_id, -32002, "Task already in terminal state") catch
            return errorResponse();
        return .{ .body = err_body };
    }

    // Request interruption if working.
    if (task.state == .working) {
        var result = session_mgr.requestTurnInterrupt(task.session_key);
        freeInterruptRequestResult(session_mgr, &result);
    }

    var canceled_task = registry.cancelTask(allocator, task_id) catch return errorResponse();
    defer if (canceled_task) |*snapshot| snapshot.deinit(allocator);
    const task_snapshot = canceled_task orelse {
        const err_body = buildJsonRpcError(allocator, request_id, -32001, "Task not found") catch
            return errorResponse();
        return .{ .body = err_body };
    };
    if (task_snapshot.state != .canceled) {
        const err_body = buildJsonRpcError(allocator, request_id, -32002, "Task already in terminal state") catch
            return errorResponse();
        return .{ .body = err_body };
    }

    const task_json = buildTaskJson(allocator, &task_snapshot, null) catch {
        const err_body = buildJsonRpcError(allocator, request_id, -32603, "Failed to build response") catch
            return errorResponse();
        return .{ .body = err_body };
    };
    defer allocator.free(task_json);

    const result = buildJsonRpcResult(allocator, request_id, task_json) catch
        return errorResponse();
    return .{ .body = result };
}

// ── Internal: List Tasks ────────────────────────────────────────

fn handleListTasks(
    allocator: std.mem.Allocator,
    body: []const u8,
    request_id: []const u8,
    registry: *TaskRegistry,
) A2aResponse {
    // Parse optional filters from params.
    const params_section = extractParamsObject(body) orelse "{}";

    const filter_state: ?TaskState = blk: {
        const has_status_filter = extractObjectFieldRaw(params_section, "status") != null or
            extractObjectFieldRaw(params_section, "state") != null;
        if (!has_status_filter) break :blk null;

        const state_str = extractObjectStringField(params_section, "status") orelse
            extractObjectStringField(params_section, "state") orelse {
            const err_body = buildJsonRpcError(allocator, request_id, -32602, "Invalid task status") catch
                return errorResponse();
            return .{ .body = err_body };
        };

        const parsed_state = parseTaskState(state_str) orelse {
            const err_body = buildJsonRpcError(allocator, request_id, -32602, "Invalid task status") catch
                return errorResponse();
            return .{ .body = err_body };
        };
        break :blk parsed_state;
    };

    // Optional context_id filter.
    const filter_context_id = extractObjectStringField(params_section, "contextId");

    const history_length = extractObjectIntField(params_section, "historyLength");
    if (history_length) |value| {
        if (value < 0) {
            const err_body = buildJsonRpcError(allocator, request_id, -32602, "historyLength must be non-negative") catch
                return errorResponse();
            return .{ .body = err_body };
        }
    }

    // Page size (default 50, max 100).
    const page_size: usize = blk: {
        const val = extractObjectIntField(params_section, "pageSize") orelse break :blk 50;
        if (val < 1) break :blk 1;
        if (val > 100) break :blk 100;
        break :blk @intCast(val);
    };

    const tasks = registry.listTasks(allocator, filter_state, filter_context_id, page_size) catch {
        const err_body = buildJsonRpcError(allocator, request_id, -32603, "Failed to list tasks") catch
            return errorResponse();
        return .{ .body = err_body };
    };
    defer deinitTaskSnapshots(allocator, tasks);

    // Build result JSON: {"tasks":[...], "nextPageToken":"", "pageSize":N, "totalSize":N}
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    w.writeAll("{\"tasks\":[") catch return errorResponse();
    for (tasks, 0..) |*task, i| {
        if (i > 0) w.writeByte(',') catch return errorResponse();
        const task_json = buildTaskJson(allocator, task, history_length) catch return errorResponse();
        defer allocator.free(task_json);
        w.writeAll(task_json) catch return errorResponse();
    }
    w.writeAll("],\"nextPageToken\":\"\",\"pageSize\":") catch return errorResponse();
    std.fmt.format(w, "{d}", .{page_size}) catch return errorResponse();
    w.writeAll(",\"totalSize\":") catch return errorResponse();
    std.fmt.format(w, "{d}", .{registry.taskCount()}) catch return errorResponse();
    w.writeByte('}') catch return errorResponse();

    const list_json = buf.toOwnedSlice(allocator) catch return errorResponse();
    defer allocator.free(list_json);

    const result = buildJsonRpcResult(allocator, request_id, list_json) catch
        return errorResponse();
    return .{ .body = result };
}

// ── JSON Builder Helpers ────────────────────────────────────────

/// Build a JSON-RPC result response. `request_id` is a raw JSON token (e.g. `"1"` or `1`).
fn buildJsonRpcResult(allocator: std.mem.Allocator, request_id: []const u8, result_json: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try w.writeAll(request_id);
    try w.writeAll(",\"result\":");
    try w.writeAll(result_json);
    try w.writeByte('}');

    return buf.toOwnedSlice(allocator);
}

/// Build a JSON-RPC error response. `request_id` is a raw JSON token (e.g. `"1"` or `1`).
fn buildJsonRpcError(allocator: std.mem.Allocator, request_id: []const u8, code: i32, message: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try w.writeAll(request_id);
    try w.writeAll(",\"error\":{\"code\":");
    try std.fmt.format(w, "{d}", .{code});
    try w.writeAll(",\"message\":\"");
    try gateway.jsonEscapeInto(w, message);
    try w.writeAll("\"}}");

    return buf.toOwnedSlice(allocator);
}

fn buildTaskJson(allocator: std.mem.Allocator, task: *const TaskSnapshot, max_history: ?i64) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    // Format timestamp as ISO 8601 from unix epoch seconds.
    var ts_buf: [32]u8 = undefined;
    const timestamp = formatTimestamp(&ts_buf, task.updated_at);

    try w.writeAll("{\"id\":\"");
    try gateway.jsonEscapeInto(w, task.id);
    try w.writeAll("\",\"kind\":\"task\",\"contextId\":\"");
    try gateway.jsonEscapeInto(w, task.context_id);
    try w.writeAll("\",\"status\":{\"state\":\"");
    try w.writeAll(task.state.jsonName());
    try w.writeAll("\",\"timestamp\":\"");
    try w.writeAll(timestamp);
    try w.writeAll("\"},\"metadata\":{}");

    // Include artifacts and history when agent_text is non-empty.
    if (task.agent_text.len > 0) {
        try w.writeAll(",\"artifacts\":[{\"artifactId\":\"artifact-");
        try gateway.jsonEscapeInto(w, task.id);
        try w.writeAll("\",\"parts\":[{\"kind\":\"text\",\"text\":\"");
        try gateway.jsonEscapeInto(w, task.agent_text);
        try w.writeAll("\"}]}]");

        // Respect historyLength: null = all, 0 = omit, 1 = latest only, 2+ = all (we have 2 max).
        const history_limit: i64 = max_history orelse 2;
        if (history_limit >= 2) {
            // Both user and agent messages.
            try w.writeAll(",\"history\":[{\"kind\":\"message\",\"role\":\"user\",\"messageId\":\"msg-user-");
            try gateway.jsonEscapeInto(w, task.id);
            try w.writeAll("\",\"taskId\":\"");
            try gateway.jsonEscapeInto(w, task.id);
            try w.writeAll("\",\"contextId\":\"");
            try gateway.jsonEscapeInto(w, task.context_id);
            try w.writeAll("\",\"parts\":[{\"kind\":\"text\",\"text\":\"");
            try gateway.jsonEscapeInto(w, task.user_text);
            try w.writeAll("\"}]},{\"kind\":\"message\",\"role\":\"agent\",\"messageId\":\"msg-agent-");
            try gateway.jsonEscapeInto(w, task.id);
            try w.writeAll("\",\"taskId\":\"");
            try gateway.jsonEscapeInto(w, task.id);
            try w.writeAll("\",\"contextId\":\"");
            try gateway.jsonEscapeInto(w, task.context_id);
            try w.writeAll("\",\"parts\":[{\"kind\":\"text\",\"text\":\"");
            try gateway.jsonEscapeInto(w, task.agent_text);
            try w.writeAll("\"}]}]");
        } else if (history_limit == 1) {
            // Only the most recent message (agent response).
            try w.writeAll(",\"history\":[{\"kind\":\"message\",\"role\":\"agent\",\"messageId\":\"msg-agent-");
            try gateway.jsonEscapeInto(w, task.id);
            try w.writeAll("\",\"taskId\":\"");
            try gateway.jsonEscapeInto(w, task.id);
            try w.writeAll("\",\"contextId\":\"");
            try gateway.jsonEscapeInto(w, task.context_id);
            try w.writeAll("\",\"parts\":[{\"kind\":\"text\",\"text\":\"");
            try gateway.jsonEscapeInto(w, task.agent_text);
            try w.writeAll("\"}]}]");
        }
        // history_limit <= 0: omit history entirely.
    }

    try w.writeByte('}');

    return buf.toOwnedSlice(allocator);
}

/// Format a unix timestamp (seconds since epoch) as ISO 8601 UTC.
fn formatTimestamp(buf: *[32]u8, epoch_secs: i64) []const u8 {
    const epoch_day = @divFloor(epoch_secs, 86400);
    const day_secs: u32 = @intCast(@mod(epoch_secs, 86400));
    const hours = day_secs / 3600;
    const mins = (day_secs % 3600) / 60;
    const secs = day_secs % 60;

    // Civil date from epoch day (algorithm from Howard Hinnant).
    const z: i64 = epoch_day + 719468;
    const era: i64 = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: u32 = @intCast(z - era * 146097);
    const yoe: u32 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy: u32 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp: u32 = (5 * doy + 2) / 153;
    const d: u32 = doy - (153 * mp + 2) / 5 + 1;
    const m: u32 = if (mp < 10) mp + 3 else mp - 9;
    const year: i64 = if (m <= 2) y + 1 else y;

    const result = std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        @as(u32, @intCast(year)), m, d, hours, mins, secs,
    }) catch "1970-01-01T00:00:00Z";
    return result;
}

fn buildEndpointUrl(allocator: std.mem.Allocator, base_url: []const u8) ![]u8 {
    if (base_url.len == 0) {
        return allocator.dupe(u8, "/a2a");
    }
    if (std.mem.endsWith(u8, base_url, "/a2a")) {
        return allocator.dupe(u8, base_url);
    }
    if (base_url.len > 0 and base_url[base_url.len - 1] == '/') {
        return std.fmt.allocPrint(allocator, "{s}a2a", .{base_url});
    }
    return std.fmt.allocPrint(allocator, "{s}/a2a", .{base_url});
}

// ── Text Extraction Helpers ─────────────────────────────────────

fn skipJsonWhitespace(json: []const u8, start: usize) usize {
    var i = start;
    while (i < json.len and (json[i] == ' ' or json[i] == '\t' or json[i] == '\n' or json[i] == '\r')) : (i += 1) {}
    return i;
}

fn scanJsonStringEnd(json: []const u8, start: usize) ?usize {
    if (start >= json.len or json[start] != '"') return null;

    var i = start + 1;
    while (i < json.len) : (i += 1) {
        if (json[i] == '\\') {
            if (i + 1 >= json.len) return null;
            i += 1;
            continue;
        }
        if (json[i] == '"') return i + 1;
    }
    return null;
}

fn scanJsonCompositeEnd(json: []const u8, start: usize, open: u8, close: u8) ?usize {
    if (start >= json.len or json[start] != open) return null;

    var depth: usize = 0;
    var in_string = false;
    var escaped = false;
    var i = start;
    while (i < json.len) : (i += 1) {
        const c = json[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (in_string) {
            if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }
        if (c == '"') {
            in_string = true;
            continue;
        }
        if (c == open) {
            depth += 1;
            continue;
        }
        if (c == close) {
            if (depth == 0) return null;
            depth -= 1;
            if (depth == 0) return i + 1;
        }
    }
    return null;
}

fn scanJsonNumberEnd(json: []const u8, start: usize) ?usize {
    if (start >= json.len) return null;

    var i = start;
    if (json[i] == '-') i += 1;

    var saw_digits = false;
    while (i < json.len and json[i] >= '0' and json[i] <= '9') : (i += 1) {
        saw_digits = true;
    }
    if (!saw_digits) return null;

    if (i < json.len and json[i] == '.') {
        i += 1;
        var saw_fraction = false;
        while (i < json.len and json[i] >= '0' and json[i] <= '9') : (i += 1) {
            saw_fraction = true;
        }
        if (!saw_fraction) return null;
    }

    if (i < json.len and (json[i] == 'e' or json[i] == 'E')) {
        i += 1;
        if (i < json.len and (json[i] == '+' or json[i] == '-')) i += 1;
        var saw_exponent = false;
        while (i < json.len and json[i] >= '0' and json[i] <= '9') : (i += 1) {
            saw_exponent = true;
        }
        if (!saw_exponent) return null;
    }

    return i;
}

fn scanJsonLiteralEnd(json: []const u8, start: usize, literal: []const u8) ?usize {
    if (start + literal.len > json.len) return null;
    if (!std.mem.eql(u8, json[start .. start + literal.len], literal)) return null;
    return start + literal.len;
}

fn scanJsonValueEnd(json: []const u8, start: usize) ?usize {
    const i = skipJsonWhitespace(json, start);
    if (i >= json.len) return null;

    return switch (json[i]) {
        '"' => scanJsonStringEnd(json, i),
        '{' => scanJsonCompositeEnd(json, i, '{', '}'),
        '[' => scanJsonCompositeEnd(json, i, '[', ']'),
        't' => scanJsonLiteralEnd(json, i, "true"),
        'f' => scanJsonLiteralEnd(json, i, "false"),
        'n' => scanJsonLiteralEnd(json, i, "null"),
        '-', '0'...'9' => scanJsonNumberEnd(json, i),
        else => null,
    };
}

fn extractObjectFieldRaw(object_json: []const u8, key: []const u8) ?[]const u8 {
    var i = skipJsonWhitespace(object_json, 0);
    if (i >= object_json.len or object_json[i] != '{') return null;
    i += 1;

    while (true) {
        i = skipJsonWhitespace(object_json, i);
        if (i >= object_json.len) return null;
        if (object_json[i] == '}') return null;

        const key_end = scanJsonStringEnd(object_json, i) orelse return null;
        const object_key = object_json[i + 1 .. key_end - 1];

        i = skipJsonWhitespace(object_json, key_end);
        if (i >= object_json.len or object_json[i] != ':') return null;
        i = skipJsonWhitespace(object_json, i + 1);

        const value_start = i;
        const value_end = scanJsonValueEnd(object_json, i) orelse return null;
        if (std.mem.eql(u8, object_key, key)) {
            return object_json[value_start..value_end];
        }

        i = skipJsonWhitespace(object_json, value_end);
        if (i >= object_json.len) return null;
        if (object_json[i] == ',') {
            i += 1;
            continue;
        }
        if (object_json[i] == '}') return null;
        return null;
    }
}

fn extractObjectStringField(object_json: []const u8, key: []const u8) ?[]const u8 {
    const raw = extractObjectFieldRaw(object_json, key) orelse return null;
    if (raw.len < 2 or raw[0] != '"') return null;
    const end = scanJsonStringEnd(raw, 0) orelse return null;
    if (end != raw.len) return null;
    return raw[1 .. raw.len - 1];
}

fn extractObjectIntField(object_json: []const u8, key: []const u8) ?i64 {
    const raw = extractObjectFieldRaw(object_json, key) orelse return null;
    return std.fmt.parseInt(i64, raw, 10) catch null;
}

fn extractObjectObjectField(object_json: []const u8, key: []const u8) ?[]const u8 {
    const raw = extractObjectFieldRaw(object_json, key) orelse return null;
    const start = skipJsonWhitespace(raw, 0);
    if (start >= raw.len or raw[start] != '{') return null;
    return raw[start..];
}

fn extractObjectArrayField(object_json: []const u8, key: []const u8) ?[]const u8 {
    const raw = extractObjectFieldRaw(object_json, key) orelse return null;
    const start = skipJsonWhitespace(raw, 0);
    if (start >= raw.len or raw[start] != '[') return null;
    return raw[start..];
}

fn extractArrayObjectStringField(array_json: []const u8, key: []const u8) ?[]const u8 {
    var i = skipJsonWhitespace(array_json, 0);
    if (i >= array_json.len or array_json[i] != '[') return null;
    i += 1;

    while (true) {
        i = skipJsonWhitespace(array_json, i);
        if (i >= array_json.len) return null;
        if (array_json[i] == ']') return null;

        const value_start = i;
        const value_end = scanJsonValueEnd(array_json, i) orelse return null;
        if (extractObjectStringField(array_json[value_start..value_end], key)) |value| {
            return value;
        }

        i = skipJsonWhitespace(array_json, value_end);
        if (i >= array_json.len) return null;
        if (array_json[i] == ',') {
            i += 1;
            continue;
        }
        if (array_json[i] == ']') return null;
        return null;
    }
}

/// Extract the user's message text from A2A params.message.parts[0].text.
fn extractMessageText(body: []const u8) ?[]const u8 {
    const params = extractParamsObject(body) orelse return null;
    const message = extractObjectObjectField(params, "message") orelse return null;
    const parts = extractObjectArrayField(message, "parts") orelse return null;
    return extractArrayObjectStringField(parts, "text");
}

fn extractMessageContextId(body: []const u8) ?[]const u8 {
    const params = extractParamsObject(body) orelse return null;
    const message = extractObjectObjectField(params, "message") orelse return null;
    return extractObjectStringField(message, "contextId");
}

fn extractJsonRpcMethod(body: []const u8) ?[]const u8 {
    return extractObjectStringField(body, "method");
}

/// Extract the JSON-RPC "id" field as a raw JSON token (string including quotes, number, or null).
fn extractJsonRpcId(body: []const u8) ?[]const u8 {
    return extractObjectFieldRaw(body, "id");
}

fn extractParamsObject(body: []const u8) ?[]const u8 {
    return extractObjectObjectField(body, "params");
}

/// Extract task ID from params.id in the JSON-RPC body.
fn extractParamsId(body: []const u8) ?[]const u8 {
    const params = extractParamsObject(body) orelse return null;
    return extractObjectStringField(params, "id");
}

/// Extract messageId from params.message.messageId.
fn extractMessageMessageId(body: []const u8) ?[]const u8 {
    const params = extractParamsObject(body) orelse return null;
    const message = extractObjectObjectField(params, "message") orelse return null;
    return extractObjectStringField(message, "messageId");
}

fn parseTaskState(state_str: []const u8) ?TaskState {
    if (std.mem.eql(u8, state_str, "submitted")) return .submitted;
    if (std.mem.eql(u8, state_str, "working")) return .working;
    if (std.mem.eql(u8, state_str, "completed")) return .completed;
    if (std.mem.eql(u8, state_str, "failed")) return .failed;
    if (std.mem.eql(u8, state_str, "canceled")) return .canceled;
    if (std.mem.eql(u8, state_str, "input-required") or std.mem.eql(u8, state_str, "input_required")) return .input_required;
    if (std.mem.eql(u8, state_str, "rejected")) return .rejected;
    if (std.mem.eql(u8, state_str, "auth-required") or std.mem.eql(u8, state_str, "auth_required")) return .auth_required;
    if (std.mem.eql(u8, state_str, "unknown")) return .unknown;
    return null;
}

/// Parsed SendMessageConfiguration fields.
const SendMessageConfiguration = struct {
    history_length: ?i64 = null,
    has_accepted_output_modes: bool = false,
    accepts_text_plain: bool = false,
};

/// Parse configuration from params.configuration in a SendMessageRequest.
fn parseSendMessageConfiguration(body: []const u8) SendMessageConfiguration {
    var result = SendMessageConfiguration{};
    const params = extractParamsObject(body) orelse return result;
    const config = extractObjectObjectField(params, "configuration") orelse return result;

    result.history_length = extractObjectIntField(config, "historyLength");

    // Check acceptedOutputModes array for text/plain compatibility.
    const modes = extractObjectArrayField(config, "acceptedOutputModes") orelse return result;
    result.has_accepted_output_modes = true;
    // Scan the array for "text/plain" or "text/*" or "*/*".
    if (std.mem.indexOf(u8, modes, "\"text/plain\"") != null or
        std.mem.indexOf(u8, modes, "\"text/*\"") != null or
        std.mem.indexOf(u8, modes, "\"*/*\"") != null)
    {
        result.accepts_text_plain = true;
    }

    return result;
}

fn buildResubscribeStatusEvent(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    task_id: []const u8,
    context_id: []const u8,
    state: TaskState,
    updated_at: i64,
) ![]u8 {
    return buildStatusUpdateEvent(
        allocator,
        request_id,
        task_id,
        context_id,
        state,
        updated_at,
        isTerminalState(state),
    );
}

fn buildArtifactUpdateEvent(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    task_id: []const u8,
    context_id: []const u8,
    text: []const u8,
    last_chunk: bool,
) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);

    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try w.writeAll(request_id);
    try w.writeAll(",\"result\":{\"kind\":\"artifact-update\",\"taskId\":\"");
    try gateway.jsonEscapeInto(w, task_id);
    try w.writeAll("\",\"contextId\":\"");
    try gateway.jsonEscapeInto(w, context_id);
    try w.writeAll("\",\"artifact\":{\"artifactId\":\"artifact-");
    try gateway.jsonEscapeInto(w, task_id);
    try w.writeAll("\",\"parts\":[{\"kind\":\"text\",\"text\":\"");
    try gateway.jsonEscapeInto(w, text);
    try w.writeAll("\"}]},\"append\":true,\"lastChunk\":");
    try w.writeAll(if (last_chunk) "true" else "false");
    try w.writeAll("}}");

    return buf.toOwnedSlice(allocator);
}

fn buildStatusUpdateEvent(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    task_id: []const u8,
    context_id: []const u8,
    state: TaskState,
    updated_at: i64,
    final: bool,
) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    const w = buf.writer(allocator);
    var ts_buf: [32]u8 = undefined;
    const timestamp = formatTimestamp(&ts_buf, updated_at);

    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try w.writeAll(request_id);
    try w.writeAll(",\"result\":{\"kind\":\"status-update\",\"taskId\":\"");
    try gateway.jsonEscapeInto(w, task_id);
    try w.writeAll("\",\"contextId\":\"");
    try gateway.jsonEscapeInto(w, context_id);
    try w.writeAll("\",\"status\":{\"state\":\"");
    try w.writeAll(state.jsonName());
    try w.writeAll("\",\"timestamp\":\"");
    try w.writeAll(timestamp);
    try w.writeAll("\"},\"final\":");
    try w.writeAll(if (final) "true" else "false");
    try w.writeAll("}}");

    return buf.toOwnedSlice(allocator);
}

fn freeInterruptRequestResult(session_mgr: anytype, result: anytype) void {
    const session_mgr_type = @TypeOf(session_mgr.*);
    if (comptime @hasField(session_mgr_type, "allocator")) {
        result.deinit(session_mgr.allocator);
    } else {
        result.deinit({});
    }
}

fn freeSessionResponse(session_mgr: anytype, response: []const u8) void {
    const session_mgr_type = @TypeOf(session_mgr.*);
    if (comptime @hasField(session_mgr_type, "allocator")) {
        session_mgr.allocator.free(response);
    }
}

// ── Fallback Error Response ─────────────────────────────────────

fn errorResponse() A2aResponse {
    return .{
        .status = "500 Internal Server Error",
        .body = "{\"error\":\"internal server error\"}",
        .allocated = false,
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

const testing = std.testing;

const MockSessionManager = struct {
    response: []const u8 = "mock response",
    interrupt_tool: ?[]const u8 = null,
    allocator: std.mem.Allocator = testing.allocator,

    pub fn processMessage(self: *MockSessionManager, _: []const u8, _: []const u8, _: anytype) ![]const u8 {
        return self.allocator.dupe(u8, self.response);
    }

    pub fn processMessageStreaming(self: *MockSessionManager, session_key: []const u8, content: []const u8, conversation_context: anytype, sink: ?streaming.Sink) ![]const u8 {
        // Emit chunks if a sink is provided.
        if (sink) |s| {
            s.emitChunk(self.response);
            s.emitFinal();
        }
        return self.processMessage(session_key, content, conversation_context);
    }

    pub fn requestTurnInterrupt(self: *MockSessionManager, _: []const u8) struct {
        requested: bool,
        active_tool: ?[]u8,

        pub fn deinit(s: *@This(), allocator: std.mem.Allocator) void {
            if (s.active_tool) |name| allocator.free(name);
            s.active_tool = null;
        }
    } {
        return .{
            .requested = self.interrupt_tool != null,
            .active_tool = if (self.interrupt_tool) |tool|
                self.allocator.dupe(u8, tool) catch null
            else
                null,
        };
    }
};

fn testConfig() Config {
    return .{
        .workspace_dir = "/tmp/a2a_test",
        .config_path = "/tmp/a2a_test/config.json",
        .default_model = "test/mock-model",
        .allocator = testing.allocator,
        .a2a = .{
            .enabled = true,
            .name = "TestAgent",
            .description = "A test agent",
            .url = "http://localhost:3000",
            .version = "1.0.0",
        },
    };
}

fn mutateStoredTask(
    registry: *TaskRegistry,
    task_id: []const u8,
    state: ?TaskState,
    agent_text: ?[]const u8,
    updated_at: ?i64,
) !void {
    registry.mutex.lock();
    defer registry.mutex.unlock();

    const task = registry.tasks.get(task_id) orelse return error.TestUnexpectedResult;
    if (state) |value| task.state = value;
    if (agent_text) |text| {
        testing.allocator.free(task.agent_text);
        task.agent_text = try testing.allocator.dupe(u8, text);
    }
    if (updated_at) |timestamp| task.updated_at = timestamp;
}

fn getTaskSnapshotOrFail(registry: *TaskRegistry, task_id: []const u8) !TaskSnapshot {
    return (try registry.getTaskSnapshot(testing.allocator, task_id)) orelse error.TestUnexpectedResult;
}

test "TaskState jsonName returns correct strings" {
    try testing.expectEqualStrings("submitted", TaskState.submitted.jsonName());
    try testing.expectEqualStrings("working", TaskState.working.jsonName());
    try testing.expectEqualStrings("completed", TaskState.completed.jsonName());
    try testing.expectEqualStrings("failed", TaskState.failed.jsonName());
    try testing.expectEqualStrings("canceled", TaskState.canceled.jsonName());
    try testing.expectEqualStrings("input-required", TaskState.input_required.jsonName());
    try testing.expectEqualStrings("rejected", TaskState.rejected.jsonName());
    try testing.expectEqualStrings("auth-required", TaskState.auth_required.jsonName());
    try testing.expectEqualStrings("unknown", TaskState.unknown.jsonName());
}

test "TaskRegistry createTask and getTaskSnapshot" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "hello world", null);
    defer task.deinit(testing.allocator);

    try testing.expectEqualStrings("task-1", task.id);
    try testing.expectEqualStrings("ctx-1", task.context_id);
    try testing.expectEqualStrings("a2a:ctx-1", task.session_key);
    try testing.expectEqualStrings("hello world", task.user_text);
    try testing.expect(task.state == .submitted);
    try testing.expectEqual(@as(usize, 0), task.agent_text.len);

    var found = try registry.getTaskSnapshot(testing.allocator, "task-1");
    defer if (found) |*snapshot| snapshot.deinit(testing.allocator);
    try testing.expect(found != null);
    try testing.expectEqualStrings("task-1", found.?.id);

    const not_found = try registry.getTaskSnapshot(testing.allocator, "task-999");
    try testing.expect(not_found == null);
    try testing.expectEqual(@as(usize, 1), registry.taskCount());
}

test "TaskRegistry returns TaskRegistryFull when capped by active tasks" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var i: usize = 0;
    while (i < MAX_TASKS) : (i += 1) {
        var task = try registry.createTask(testing.allocator, "x", null);
        try testing.expect(registry.setTaskState(task.id, .working));
        task.deinit(testing.allocator);
    }

    try testing.expectEqual(MAX_TASKS, registry.taskCount());
    try testing.expectError(error.TaskRegistryFull, registry.createTask(testing.allocator, "overflow", null));
}

test "TaskRegistry evicts oldest completed tasks by recency" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var i: usize = 0;
    while (i < MAX_TASKS) : (i += 1) {
        var task = try registry.createTask(testing.allocator, "filler", null);
        try mutateStoredTask(&registry, task.id, .completed, null, @as(i64, @intCast(i)));
        task.deinit(testing.allocator);
    }

    var newest = try registry.createTask(testing.allocator, "new task", null);
    defer newest.deinit(testing.allocator);

    try testing.expectEqual(MAX_TASKS, registry.taskCount());

    var oldest = try registry.getTaskSnapshot(testing.allocator, "task-1");
    defer if (oldest) |*snapshot| snapshot.deinit(testing.allocator);
    try testing.expect(oldest == null);

    var found_newest = try getTaskSnapshotOrFail(&registry, newest.id);
    defer found_newest.deinit(testing.allocator);
    try testing.expectEqualStrings(newest.id, found_newest.id);
}

test "handleAgentCard returns valid JSON" {
    const cfg = testConfig();
    const resp = handleAgentCard(testing.allocator, &cfg);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqualStrings("200 OK", resp.status);
    try testing.expectEqualStrings("application/json", resp.content_type);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"name\":\"TestAgent\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"description\":\"A test agent\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"protocolVersion\":\"0.3.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"version\":\"1.0.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"url\":\"http://localhost:3000/a2a\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"supportedInterfaces\":[") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"protocolBinding\":\"JSONRPC\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"securitySchemes\":{\"bearerAuth\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"provider\":{\"organization\":\"TestAgent\",\"url\":\"http://localhost:3000\"}") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"streaming\":true") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"defaultInputModes\":[\"text/plain\"]") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"skills\":[") != null);
}

test "handleJsonRpc dispatches message/send with string id" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-1","method":"message/send","params":{"message":{"messageId":"msg-1","role":"user","parts":[{"type":"text","text":"Hello agent"}]}}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqualStrings("200 OK", resp.status);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"result\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"id\":\"req-1\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"state\":\"completed\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "mock response") != null);
    try testing.expectEqual(@as(usize, 1), registry.taskCount());
}

test "handleJsonRpc dispatches message/send" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":42,"method":"message/send","params":{"message":{"messageId":"msg-2","role":"user","parts":[{"type":"text","text":"Hello via message/send"}]}}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqualStrings("200 OK", resp.status);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"id\":42") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"state\":\"completed\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "mock response") != null);
}

test "handleJsonRpc dispatches tasks/get" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "test input", null);
    defer task.deinit(testing.allocator);
    var completed = (try registry.finalizeTask(testing.allocator, task.id, .completed, "test output")).?;
    defer completed.deinit(testing.allocator);

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-2","method":"tasks/get","params":{"id":"task-1"}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqualStrings("200 OK", resp.status);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"result\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"id\":\"req-2\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"state\":\"completed\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "test output") != null);
}

test "handleJsonRpc returns error for unknown method" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-3","method":"unknown/method","params":{}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32601") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "Method not found") != null);
}

test "handleJsonRpc returns error for missing method" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-4","params":{}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32600") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "Missing method") != null);
}

test "buildTaskJson escapes special characters" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "hello \"world\"", null);
    defer task.deinit(testing.allocator);
    var completed = (try registry.finalizeTask(testing.allocator, task.id, .completed, "line1\nline2\ttab")).?;
    defer completed.deinit(testing.allocator);

    const json = try buildTaskJson(testing.allocator, &completed, null);
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "hello \\\"world\\\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "line1\\nline2\\ttab") != null);
}

test "extractMessageText finds text in parts" {
    const body =
        \\{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"messageId":"msg-1","role":"user","parts":[{"type":"text","text":"Hello there"}]}}}
    ;
    const text = extractMessageText(body);
    try testing.expect(text != null);
    try testing.expectEqualStrings("Hello there", text.?);
}

test "extractMessageText returns null for missing parts" {
    const body =
        \\{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"role":"user"}}}
    ;
    try testing.expect(extractMessageText(body) == null);
}

test "handleJsonRpc dispatches tasks/cancel" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "cancel me", null);
    defer task.deinit(testing.allocator);
    try testing.expect(registry.setTaskState(task.id, .working));

    var mock = MockSessionManager{ .interrupt_tool = "shell" };
    const body =
        \\{"jsonrpc":"2.0","id":"req-5","method":"tasks/cancel","params":{"id":"task-1"}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqualStrings("200 OK", resp.status);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"state\":\"canceled\"") != null);

    var canceled = try getTaskSnapshotOrFail(&registry, task.id);
    defer canceled.deinit(testing.allocator);
    try testing.expect(canceled.state == .canceled);
}

test "handleJsonRpc cancel returns error for completed task" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "done", null);
    defer task.deinit(testing.allocator);
    var completed = (try registry.finalizeTask(testing.allocator, task.id, .completed, "done")).?;
    defer completed.deinit(testing.allocator);

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-6","method":"tasks/cancel","params":{"id":"task-1"}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32002") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "terminal") != null);
}

test "handleJsonRpc tasks/get returns error for nonexistent task" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-7","method":"tasks/get","params":{"id":"task-nonexistent"}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32001") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "Task not found") != null);
}

test "handleJsonRpc returns error for removed tasks/send method" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-8","method":"tasks/send","params":{"message":{"role":"user","parts":[{"type":"text","text":"Legacy test"}]}}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32601") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "Method not found") != null);
}

test "handleJsonRpc returns error for push notification config methods" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-pn","method":"tasks/pushNotificationConfig/set","params":{"taskId":"task-1"}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32003") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "Push notification") != null);
}

test "handleJsonRpc returns error for GetExtendedAgentCard" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-ec","method":"GetExtendedAgentCard","params":{}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32004") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "not supported") != null);
}

test "buildTaskJson omits artifacts and history when agent_text is empty" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "test input", null);
    defer task.deinit(testing.allocator);

    const json = try buildTaskJson(testing.allocator, &task, null);
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"artifacts\"") == null);
    try testing.expect(std.mem.indexOf(u8, json, "\"history\"") == null);
    try testing.expect(std.mem.indexOf(u8, json, "\"status\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"contextId\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"kind\":\"task\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"metadata\":{}") != null);
}

test "buildTaskJson includes contextId artifactId messageId and message kind" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "test", "conversation-1");
    defer task.deinit(testing.allocator);
    var completed = (try registry.finalizeTask(testing.allocator, task.id, .completed, "reply")).?;
    defer completed.deinit(testing.allocator);

    const json = try buildTaskJson(testing.allocator, &completed, null);
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"contextId\":\"conversation-1\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"artifactId\":\"artifact-task-1\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"messageId\":\"msg-user-task-1\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"messageId\":\"msg-agent-task-1\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"taskId\":\"task-1\"") != null);
    // v0.3.0: history messages must include kind:"message" discriminator.
    try testing.expect(std.mem.indexOf(u8, json, "\"kind\":\"message\",\"role\":\"user\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"kind\":\"message\",\"role\":\"agent\"") != null);
}

test "extractJsonRpcId handles string numeric and reordered ids" {
    const string_body =
        \\{"jsonrpc":"2.0","id":"req-1","method":"tasks/send"}
    ;
    try testing.expectEqualStrings("\"req-1\"", extractJsonRpcId(string_body).?);

    const numeric_body =
        \\{"jsonrpc":"2.0","id":42,"method":"tasks/send"}
    ;
    try testing.expectEqualStrings("42", extractJsonRpcId(numeric_body).?);

    const reordered_body =
        \\{"jsonrpc":"2.0","params":{"id":"task-1"},"id":"req-7","method":"tasks/get"}
    ;
    try testing.expectEqualStrings("\"req-7\"", extractJsonRpcId(reordered_body).?);

    const missing_body =
        \\{"jsonrpc":"2.0","method":"tasks/send"}
    ;
    try testing.expect(extractJsonRpcId(missing_body) == null);
}

test "extractParamsId finds id in params only" {
    const body =
        \\{"jsonrpc":"2.0","params":{"id":"task-42"},"id":"req-1","method":"tasks/get"}
    ;
    try testing.expectEqualStrings("task-42", extractParamsId(body).?);
}

test "extractMessageContextId finds context id in message" {
    const body =
        \\{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"messageId":"msg-1","contextId":"chat-42","role":"user","parts":[{"type":"text","text":"hello"}]}}}
    ;
    try testing.expectEqualStrings("chat-42", extractMessageContextId(body).?);
}

test "multiple tasks get unique IDs" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var t1 = try registry.createTask(testing.allocator, "first", null);
    defer t1.deinit(testing.allocator);
    var t2 = try registry.createTask(testing.allocator, "second", null);
    defer t2.deinit(testing.allocator);
    var t3 = try registry.createTask(testing.allocator, "third", null);
    defer t3.deinit(testing.allocator);

    try testing.expectEqualStrings("task-1", t1.id);
    try testing.expectEqualStrings("task-2", t2.id);
    try testing.expectEqualStrings("task-3", t3.id);
    try testing.expectEqual(@as(usize, 3), registry.taskCount());
}

test "handleJsonRpc dispatches tasks/list" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var t1 = try registry.createTask(testing.allocator, "first", null);
    defer t1.deinit(testing.allocator);
    var t2 = try registry.createTask(testing.allocator, "second", "shared-context");
    defer t2.deinit(testing.allocator);
    var completed = (try registry.finalizeTask(testing.allocator, t1.id, .completed, "reply1")).?;
    defer completed.deinit(testing.allocator);
    try testing.expect(registry.setTaskState(t2.id, .working));

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-list","method":"tasks/list","params":{}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqualStrings("200 OK", resp.status);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"result\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"tasks\":[") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"totalSize\":2") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"pageSize\":50") != null);
}

test "handleListTasks filters by state" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var t1 = try registry.createTask(testing.allocator, "first", null);
    defer t1.deinit(testing.allocator);
    var t2 = try registry.createTask(testing.allocator, "second", null);
    defer t2.deinit(testing.allocator);
    var completed = (try registry.finalizeTask(testing.allocator, t1.id, .completed, "done")).?;
    defer completed.deinit(testing.allocator);

    const body =
        \\{"jsonrpc":"2.0","id":"req-f","method":"tasks/list","params":{"state":"completed"}}
    ;
    var mock = MockSessionManager{};
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqualStrings("200 OK", resp.status);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"state\":\"completed\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"state\":\"submitted\"") == null);
}

test "handleListTasks accepts input-required filter" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "needs input", null);
    defer task.deinit(testing.allocator);
    try mutateStoredTask(&registry, task.id, .input_required, null, 50);

    const body =
        \\{"jsonrpc":"2.0","id":"req-ir","method":"tasks/list","params":{"state":"input-required"}}
    ;
    var mock = MockSessionManager{};
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"state\":\"input-required\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"state\":\"submitted\"") == null);
}

test "listTasks returns empty slice when no tasks match" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "hello", null);
    defer task.deinit(testing.allocator);

    const tasks = try registry.listTasks(testing.allocator, .canceled, null, 50);
    defer deinitTaskSnapshots(testing.allocator, tasks);

    try testing.expectEqual(@as(usize, 0), tasks.len);
}

test "isStreamingMethod detects streaming methods only" {
    try testing.expect(isStreamingMethod(
        \\{"jsonrpc":"2.0","id":1,"method":"message/stream","params":{"message":{"role":"user","parts":[{"type":"text","text":"hi"}]}}}
    ));
    try testing.expect(isStreamingMethod(
        \\{"jsonrpc":"2.0","id":"1","method":"tasks/resubscribe","params":{"id":"task-1"}}
    ));
    try testing.expect(isStreamingMethod(
        \\{"jsonrpc":"2.0","id":"1","method":"SendStreamingMessage","params":{"message":{"messageId":"msg-1","role":"user","parts":[{"type":"text","text":"hi"}]}}}
    ));
    try testing.expect(isStreamingMethod(
        \\{"jsonrpc":"2.0","id":"1","method":"SubscribeToTask","params":{"id":"task-1"}}
    ));
    try testing.expect(!isStreamingMethod(
        \\{"jsonrpc":"2.0","id":"1","method":"tasks/get","params":{}}
    ));
    try testing.expect(!isStreamingMethod(
        \\{"jsonrpc":"2.0","id":"1","method":"message/send","params":{}}
    ));
}

test "listTasks respects max_results and recency order" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var t1 = try registry.createTask(testing.allocator, "a", null);
    defer t1.deinit(testing.allocator);
    var t2 = try registry.createTask(testing.allocator, "b", null);
    defer t2.deinit(testing.allocator);
    var t3 = try registry.createTask(testing.allocator, "c", null);
    defer t3.deinit(testing.allocator);

    try mutateStoredTask(&registry, t1.id, .submitted, null, 10);
    try mutateStoredTask(&registry, t2.id, .submitted, null, 30);
    try mutateStoredTask(&registry, t3.id, .submitted, null, 20);

    const tasks = try registry.listTasks(testing.allocator, null, null, 2);
    defer deinitTaskSnapshots(testing.allocator, tasks);

    try testing.expectEqual(@as(usize, 2), tasks.len);
    try testing.expectEqualStrings("task-2", tasks[0].id);
    try testing.expectEqualStrings("task-3", tasks[1].id);
}

test "handleJsonRpc reuses provided contextId for follow-up turns" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-ctx","method":"message/send","params":{"message":{"messageId":"msg-1","contextId":"conversation-9","role":"user","parts":[{"type":"text","text":"Hello via context"}]}}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    var task = try getTaskSnapshotOrFail(&registry, "task-1");
    defer task.deinit(testing.allocator);
    try testing.expectEqualStrings("conversation-9", task.context_id);
    try testing.expectEqualStrings("a2a:conversation-9", task.session_key);
}

test "listTasks filters by provided context id" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var first = try registry.createTask(testing.allocator, "first", "conversation-a");
    defer first.deinit(testing.allocator);
    var second = try registry.createTask(testing.allocator, "second", "conversation-b");
    defer second.deinit(testing.allocator);

    const tasks = try registry.listTasks(testing.allocator, null, "conversation-b", 10);
    defer deinitTaskSnapshots(testing.allocator, tasks);

    try testing.expectEqual(@as(usize, 1), tasks.len);
    try testing.expectEqualStrings("conversation-b", tasks[0].context_id);
}

test "finalizeTask preserves canceled state and setTaskState does not revive it" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "cancel race", null);
    defer task.deinit(testing.allocator);
    try testing.expect(registry.setTaskState(task.id, .working));

    var canceled = (try registry.cancelTask(testing.allocator, task.id)).?;
    defer canceled.deinit(testing.allocator);
    try testing.expect(canceled.state == .canceled);
    try testing.expect(!registry.setTaskState(task.id, .working));

    var finalized = (try registry.finalizeTask(testing.allocator, task.id, .completed, "should not win")).?;
    defer finalized.deinit(testing.allocator);
    try testing.expect(finalized.state == .canceled);
    try testing.expectEqual(@as(usize, 0), finalized.agent_text.len);
}

test "rejected state is terminal" {
    try testing.expect(isTerminalState(.rejected));
    try testing.expect(!isTerminalState(.auth_required));
    try testing.expect(!isTerminalState(.unknown));
}

test "handleListTasks filters by rejected state" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "bad request", null);
    defer task.deinit(testing.allocator);
    try mutateStoredTask(&registry, task.id, .rejected, null, 50);

    const body =
        \\{"jsonrpc":"2.0","id":"req-rej","method":"tasks/list","params":{"state":"rejected"}}
    ;
    var mock = MockSessionManager{};
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"state\":\"rejected\"") != null);
}

test "handleListTasks filters by auth-required state" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "needs auth", null);
    defer task.deinit(testing.allocator);
    try mutateStoredTask(&registry, task.id, .auth_required, null, 50);

    const body =
        \\{"jsonrpc":"2.0","id":"req-ar","method":"tasks/list","params":{"state":"auth-required"}}
    ;
    var mock = MockSessionManager{};
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"state\":\"auth-required\"") != null);
}

test "handleListTasks accepts status filter alias" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "done", null);
    defer task.deinit(testing.allocator);
    var completed = (try registry.finalizeTask(testing.allocator, task.id, .completed, "ok")).?;
    defer completed.deinit(testing.allocator);

    const body =
        \\{"jsonrpc":"2.0","id":"req-status","method":"ListTasks","params":{"status":"completed"}}
    ;
    var mock = MockSessionManager{};
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqualStrings("200 OK", resp.status);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"state\":\"completed\"") != null);
}

test "handleListTasks rejects invalid status filter" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    const body =
        \\{"jsonrpc":"2.0","id":"req-bad-status","method":"ListTasks","params":{"status":"not-a-state"}}
    ;
    var mock = MockSessionManager{};
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32602") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "Invalid task status") != null);
}

test "handleSendMessage rejects missing messageId" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-no-mid","method":"message/send","params":{"message":{"role":"user","parts":[{"type":"text","text":"No messageId"}]}}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32602") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "messageId") != null);
}

test "handleSendMessage rejects incompatible acceptedOutputModes" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-modes","method":"message/send","params":{"message":{"messageId":"msg-1","role":"user","parts":[{"type":"text","text":"hello"}]},"configuration":{"acceptedOutputModes":["image/png"]}}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32005") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "content types") != null);
}

test "handleSendMessage accepts text/plain in acceptedOutputModes" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-ok","method":"message/send","params":{"message":{"messageId":"msg-1","role":"user","parts":[{"type":"text","text":"hello"}]},"configuration":{"acceptedOutputModes":["text/plain","image/png"]}}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqualStrings("200 OK", resp.status);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"result\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"state\":\"completed\"") != null);
}

test "handleSendMessage rejects negative historyLength" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-bad-history","method":"message/send","params":{"message":{"messageId":"msg-1","role":"user","parts":[{"type":"text","text":"hello"}]},"configuration":{"historyLength":-1}}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32602") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "historyLength") != null);
}

test "handleGetTask respects historyLength parameter" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "input", null);
    defer task.deinit(testing.allocator);
    var completed = (try registry.finalizeTask(testing.allocator, task.id, .completed, "output")).?;
    defer completed.deinit(testing.allocator);

    var mock = MockSessionManager{};

    // historyLength=0: no history in response.
    const body_0 =
        \\{"jsonrpc":"2.0","id":"req-h0","method":"tasks/get","params":{"id":"task-1","historyLength":0}}
    ;
    const resp_0 = handleJsonRpc(testing.allocator, body_0, &registry, &mock);
    defer if (resp_0.allocated) testing.allocator.free(resp_0.body);
    try testing.expect(std.mem.indexOf(u8, resp_0.body, "\"history\"") == null);
    try testing.expect(std.mem.indexOf(u8, resp_0.body, "\"artifacts\"") != null);

    // historyLength=1: only agent message.
    const body_1 =
        \\{"jsonrpc":"2.0","id":"req-h1","method":"tasks/get","params":{"id":"task-1","historyLength":1}}
    ;
    const resp_1 = handleJsonRpc(testing.allocator, body_1, &registry, &mock);
    defer if (resp_1.allocated) testing.allocator.free(resp_1.body);
    try testing.expect(std.mem.indexOf(u8, resp_1.body, "\"history\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp_1.body, "\"role\":\"agent\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp_1.body, "\"role\":\"user\"") == null);

    // No historyLength: full history.
    const body_full =
        \\{"jsonrpc":"2.0","id":"req-hf","method":"tasks/get","params":{"id":"task-1"}}
    ;
    const resp_full = handleJsonRpc(testing.allocator, body_full, &registry, &mock);
    defer if (resp_full.allocated) testing.allocator.free(resp_full.body);
    try testing.expect(std.mem.indexOf(u8, resp_full.body, "\"role\":\"user\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp_full.body, "\"role\":\"agent\"") != null);
}

test "handleGetTask rejects negative historyLength" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "input", null);
    defer task.deinit(testing.allocator);
    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-neg","method":"tasks/get","params":{"id":"task-1","historyLength":-1}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32602") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "historyLength") != null);
}

test "handleListTasks rejects negative historyLength" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    const body =
        \\{"jsonrpc":"2.0","id":"req-list-neg","method":"ListTasks","params":{"historyLength":-1}}
    ;
    var mock = MockSessionManager{};
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32602") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "historyLength") != null);
}

test "buildTaskJson historyLength limits history output" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "test", null);
    defer task.deinit(testing.allocator);
    var completed = (try registry.finalizeTask(testing.allocator, task.id, .completed, "reply")).?;
    defer completed.deinit(testing.allocator);

    // max_history=0: no history.
    const json_0 = try buildTaskJson(testing.allocator, &completed, 0);
    defer testing.allocator.free(json_0);
    try testing.expect(std.mem.indexOf(u8, json_0, "\"history\"") == null);
    try testing.expect(std.mem.indexOf(u8, json_0, "\"artifacts\"") != null);

    // max_history=1: only agent message.
    const json_1 = try buildTaskJson(testing.allocator, &completed, 1);
    defer testing.allocator.free(json_1);
    try testing.expect(std.mem.indexOf(u8, json_1, "\"history\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_1, "\"role\":\"agent\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_1, "\"role\":\"user\"") == null);

    // max_history=null: full history.
    const json_full = try buildTaskJson(testing.allocator, &completed, null);
    defer testing.allocator.free(json_full);
    try testing.expect(std.mem.indexOf(u8, json_full, "\"role\":\"user\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_full, "\"role\":\"agent\"") != null);
}

test "handleCancelTask rejects rejected task" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var task = try registry.createTask(testing.allocator, "already rejected", null);
    defer task.deinit(testing.allocator);
    try mutateStoredTask(&registry, task.id, .rejected, null, 50);

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-cancel-rejected","method":"tasks/cancel","params":{"id":"task-1"}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32002") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "terminal") != null);
}

test "buildResubscribeStatusEvent emits direct status update envelope" {
    const event = try buildResubscribeStatusEvent(
        testing.allocator,
        "\"req-sub\"",
        "task-1",
        "ctx-1",
        .working,
        123,
    );
    defer testing.allocator.free(event);

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, event, .{});
    defer parsed.deinit();

    const result = parsed.value.object.get("result") orelse return error.TestUnexpectedResult;
    try testing.expect(result == .object);
    try testing.expectEqualStrings("status-update", result.object.get("kind").?.string);
    try testing.expectEqualStrings("working", result.object.get("status").?.object.get("state").?.string);
    try testing.expectEqual(false, result.object.get("final").?.bool);
}

test "handleJsonRpc dispatches SendMessage alias" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-alias","method":"SendMessage","params":{"message":{"messageId":"msg-1","role":"user","parts":[{"type":"text","text":"Hello alias"}]}}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqualStrings("200 OK", resp.status);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"result\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "\"state\":\"completed\"") != null);
}

test "handleJsonRpc returns error for CreateTaskPushNotificationConfig alias" {
    var registry = TaskRegistry.init(testing.allocator);
    defer registry.deinit();

    var mock = MockSessionManager{};
    const body =
        \\{"jsonrpc":"2.0","id":"req-pn-alias","method":"CreateTaskPushNotificationConfig","params":{"taskId":"task-1"}}
    ;
    const resp = handleJsonRpc(testing.allocator, body, &registry, &mock);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "-32003") != null);
}
