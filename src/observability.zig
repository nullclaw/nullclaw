const std = @import("std");

/// Events the observer can record.
pub const ObserverEvent = union(enum) {
    agent_start: struct { provider: []const u8, model: []const u8 },
    llm_request: struct { provider: []const u8, model: []const u8, messages_count: usize },
    llm_response: struct { provider: []const u8, model: []const u8, duration_ms: u64, success: bool, error_message: ?[]const u8 },
    agent_end: struct { duration_ms: u64, tokens_used: ?u64 },
    tool_call_start: struct { tool: []const u8 },
    tool_call: struct { tool: []const u8, duration_ms: u64, success: bool },
    turn_complete: void,
    channel_message: struct { channel: []const u8, direction: []const u8 },
    heartbeat_tick: void,
    err: struct { component: []const u8, message: []const u8 },
};

/// Numeric metrics.
pub const ObserverMetric = union(enum) {
    request_latency_ms: u64,
    tokens_used: u64,
    active_sessions: u64,
    queue_depth: u64,
};

/// Core observability interface — Zig vtable pattern.
pub const Observer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        record_event: *const fn (ptr: *anyopaque, event: *const ObserverEvent) void,
        record_metric: *const fn (ptr: *anyopaque, metric: *const ObserverMetric) void,
        flush: *const fn (ptr: *anyopaque) void,
        name: *const fn (ptr: *anyopaque) []const u8,
    };

    pub fn recordEvent(self: Observer, event: *const ObserverEvent) void {
        self.vtable.record_event(self.ptr, event);
    }

    pub fn recordMetric(self: Observer, metric: *const ObserverMetric) void {
        self.vtable.record_metric(self.ptr, metric);
    }

    pub fn flush(self: Observer) void {
        self.vtable.flush(self.ptr);
    }

    pub fn getName(self: Observer) []const u8 {
        return self.vtable.name(self.ptr);
    }
};

// ── NoopObserver ─────────────────────────────────────────────────────

/// Zero-overhead observer — all methods are no-ops.
pub const NoopObserver = struct {
    const vtable = Observer.VTable{
        .record_event = noopRecordEvent,
        .record_metric = noopRecordMetric,
        .flush = noopFlush,
        .name = noopName,
    };

    pub fn observer(self: *NoopObserver) Observer {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn noopRecordEvent(_: *anyopaque, _: *const ObserverEvent) void {}
    fn noopRecordMetric(_: *anyopaque, _: *const ObserverMetric) void {}
    fn noopFlush(_: *anyopaque) void {}
    fn noopName(_: *anyopaque) []const u8 {
        return "noop";
    }
};

// ── LogObserver ──────────────────────────────────────────────────────

/// Log-based observer — uses std.log for all output.
pub const LogObserver = struct {
    const vtable = Observer.VTable{
        .record_event = logRecordEvent,
        .record_metric = logRecordMetric,
        .flush = logFlush,
        .name = logName,
    };

    pub fn observer(self: *LogObserver) Observer {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn logRecordEvent(_: *anyopaque, event: *const ObserverEvent) void {
        switch (event.*) {
            .agent_start => |e| std.log.info("agent.start provider={s} model={s}", .{ e.provider, e.model }),
            .llm_request => |e| std.log.info("llm.request provider={s} model={s} messages={d}", .{ e.provider, e.model, e.messages_count }),
            .llm_response => |e| std.log.info("llm.response provider={s} model={s} duration_ms={d} success={}", .{ e.provider, e.model, e.duration_ms, e.success }),
            .agent_end => |e| std.log.info("agent.end duration_ms={d}", .{e.duration_ms}),
            .tool_call_start => |e| std.log.info("tool.start tool={s}", .{e.tool}),
            .tool_call => |e| std.log.info("tool.call tool={s} duration_ms={d} success={}", .{ e.tool, e.duration_ms, e.success }),
            .turn_complete => std.log.info("turn.complete", .{}),
            .channel_message => |e| std.log.info("channel.message channel={s} direction={s}", .{ e.channel, e.direction }),
            .heartbeat_tick => std.log.info("heartbeat.tick", .{}),
            .err => |e| std.log.info("error component={s} message={s}", .{ e.component, e.message }),
        }
    }

    fn logRecordMetric(_: *anyopaque, metric: *const ObserverMetric) void {
        switch (metric.*) {
            .request_latency_ms => |v| std.log.info("metric.request_latency latency_ms={d}", .{v}),
            .tokens_used => |v| std.log.info("metric.tokens_used tokens={d}", .{v}),
            .active_sessions => |v| std.log.info("metric.active_sessions sessions={d}", .{v}),
            .queue_depth => |v| std.log.info("metric.queue_depth depth={d}", .{v}),
        }
    }

    fn logFlush(_: *anyopaque) void {}
    fn logName(_: *anyopaque) []const u8 {
        return "log";
    }
};

// ── VerboseObserver ──────────────────────────────────────────────────

/// Human-readable progress observer for interactive CLI sessions.
pub const VerboseObserver = struct {
    const vtable = Observer.VTable{
        .record_event = verboseRecordEvent,
        .record_metric = verboseRecordMetric,
        .flush = verboseFlush,
        .name = verboseName,
    };

    pub fn observer(self: *VerboseObserver) Observer {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn verboseRecordEvent(_: *anyopaque, event: *const ObserverEvent) void {
        var buf: [4096]u8 = undefined;
        var bw = std.fs.File.stderr().writer(&buf);
        const stderr = &bw.interface;
        switch (event.*) {
            .llm_request => |e| {
                stderr.print("> Thinking\n", .{}) catch {};
                stderr.print("> Send (provider={s}, model={s}, messages={d})\n", .{ e.provider, e.model, e.messages_count }) catch {};
            },
            .llm_response => |e| {
                stderr.print("< Receive (success={}, duration_ms={d})\n", .{ e.success, e.duration_ms }) catch {};
            },
            .tool_call_start => |e| {
                stderr.print("> Tool {s}\n", .{e.tool}) catch {};
            },
            .tool_call => |e| {
                stderr.print("< Tool {s} (success={}, duration_ms={d})\n", .{ e.tool, e.success, e.duration_ms }) catch {};
            },
            .turn_complete => {
                stderr.print("< Complete\n", .{}) catch {};
            },
            else => {},
        }
    }

    fn verboseRecordMetric(_: *anyopaque, _: *const ObserverMetric) void {}
    fn verboseFlush(_: *anyopaque) void {}
    fn verboseName(_: *anyopaque) []const u8 {
        return "verbose";
    }
};

// ── MultiObserver ────────────────────────────────────────────────────

/// Fan-out observer — distributes events to multiple backends.
pub const MultiObserver = struct {
    observers: []Observer,

    const vtable = Observer.VTable{
        .record_event = multiRecordEvent,
        .record_metric = multiRecordMetric,
        .flush = multiFlush,
        .name = multiName,
    };

    pub fn observer(s: *MultiObserver) Observer {
        return .{
            .ptr = @ptrCast(s),
            .vtable = &vtable,
        };
    }

    fn resolve(ptr: *anyopaque) *MultiObserver {
        return @ptrCast(@alignCast(ptr));
    }

    fn multiRecordEvent(ptr: *anyopaque, event: *const ObserverEvent) void {
        for (resolve(ptr).observers) |obs| {
            obs.vtable.record_event(obs.ptr, event);
        }
    }

    fn multiRecordMetric(ptr: *anyopaque, metric: *const ObserverMetric) void {
        for (resolve(ptr).observers) |obs| {
            obs.vtable.record_metric(obs.ptr, metric);
        }
    }

    fn multiFlush(ptr: *anyopaque) void {
        for (resolve(ptr).observers) |obs| {
            obs.vtable.flush(obs.ptr);
        }
    }

    fn multiName(_: *anyopaque) []const u8 {
        return "multi";
    }
};

// ── FileObserver ─────────────────────────────────────────────────────

/// Appends events as JSONL to a log file.
pub const FileObserver = struct {
    path: []const u8,

    const vtable_impl = Observer.VTable{
        .record_event = fileRecordEvent,
        .record_metric = fileRecordMetric,
        .flush = fileFlush,
        .name = fileName,
    };

    pub fn observer(self: *FileObserver) Observer {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable_impl,
        };
    }

    fn resolve(ptr: *anyopaque) *FileObserver {
        return @ptrCast(@alignCast(ptr));
    }

    fn appendToFile(self: *FileObserver, line: []const u8) void {
        const file = std.fs.cwd().openFile(self.path, .{ .mode = .write_only }) catch {
            // Try creating the file if it doesn't exist
            const new_file = std.fs.cwd().createFile(self.path, .{ .truncate = false }) catch return;
            defer new_file.close();
            new_file.seekFromEnd(0) catch return;
            new_file.writeAll(line) catch {};
            new_file.writeAll("\n") catch {};
            return;
        };
        defer file.close();
        file.seekFromEnd(0) catch return;
        file.writeAll(line) catch {};
        file.writeAll("\n") catch {};
    }

    fn fileRecordEvent(ptr: *anyopaque, event: *const ObserverEvent) void {
        const self = resolve(ptr);
        var buf: [2048]u8 = undefined;
        const line = switch (event.*) {
            .agent_start => |e| std.fmt.bufPrint(&buf, "{{\"event\":\"agent_start\",\"provider\":\"{s}\",\"model\":\"{s}\"}}", .{ e.provider, e.model }) catch return,
            .llm_request => |e| std.fmt.bufPrint(&buf, "{{\"event\":\"llm_request\",\"provider\":\"{s}\",\"model\":\"{s}\",\"messages_count\":{d}}}", .{ e.provider, e.model, e.messages_count }) catch return,
            .llm_response => |e| std.fmt.bufPrint(&buf, "{{\"event\":\"llm_response\",\"provider\":\"{s}\",\"model\":\"{s}\",\"duration_ms\":{d},\"success\":{}}}", .{ e.provider, e.model, e.duration_ms, e.success }) catch return,
            .agent_end => |e| std.fmt.bufPrint(&buf, "{{\"event\":\"agent_end\",\"duration_ms\":{d}}}", .{e.duration_ms}) catch return,
            .tool_call_start => |e| std.fmt.bufPrint(&buf, "{{\"event\":\"tool_call_start\",\"tool\":\"{s}\"}}", .{e.tool}) catch return,
            .tool_call => |e| std.fmt.bufPrint(&buf, "{{\"event\":\"tool_call\",\"tool\":\"{s}\",\"duration_ms\":{d},\"success\":{}}}", .{ e.tool, e.duration_ms, e.success }) catch return,
            .turn_complete => std.fmt.bufPrint(&buf, "{{\"event\":\"turn_complete\"}}", .{}) catch return,
            .channel_message => |e| std.fmt.bufPrint(&buf, "{{\"event\":\"channel_message\",\"channel\":\"{s}\",\"direction\":\"{s}\"}}", .{ e.channel, e.direction }) catch return,
            .heartbeat_tick => std.fmt.bufPrint(&buf, "{{\"event\":\"heartbeat_tick\"}}", .{}) catch return,
            .err => |e| std.fmt.bufPrint(&buf, "{{\"event\":\"error\",\"component\":\"{s}\",\"message\":\"{s}\"}}", .{ e.component, e.message }) catch return,
        };
        self.appendToFile(line);
    }

    fn fileRecordMetric(ptr: *anyopaque, metric: *const ObserverMetric) void {
        const self = resolve(ptr);
        var buf: [512]u8 = undefined;
        const line = switch (metric.*) {
            .request_latency_ms => |v| std.fmt.bufPrint(&buf, "{{\"metric\":\"request_latency_ms\",\"value\":{d}}}", .{v}) catch return,
            .tokens_used => |v| std.fmt.bufPrint(&buf, "{{\"metric\":\"tokens_used\",\"value\":{d}}}", .{v}) catch return,
            .active_sessions => |v| std.fmt.bufPrint(&buf, "{{\"metric\":\"active_sessions\",\"value\":{d}}}", .{v}) catch return,
            .queue_depth => |v| std.fmt.bufPrint(&buf, "{{\"metric\":\"queue_depth\",\"value\":{d}}}", .{v}) catch return,
        };
        self.appendToFile(line);
    }

    fn fileFlush(_: *anyopaque) void {
        // File writes are unbuffered (each event appends directly)
    }

    fn fileName(_: *anyopaque) []const u8 {
        return "file";
    }
};

/// Factory: create observer from config backend string.
pub fn createObserver(backend: []const u8) []const u8 {
    if (std.mem.eql(u8, backend, "log")) return "log";
    if (std.mem.eql(u8, backend, "verbose")) return "verbose";
    if (std.mem.eql(u8, backend, "file")) return "file";
    if (std.mem.eql(u8, backend, "multi")) return "multi";
    if (std.mem.eql(u8, backend, "none") or std.mem.eql(u8, backend, "noop")) return "noop";
    return "noop"; // fallback
}

// ── Tests ────────────────────────────────────────────────────────────

test "NoopObserver name" {
    var noop = NoopObserver{};
    const obs = noop.observer();
    try std.testing.expectEqualStrings("noop", obs.getName());
}

test "NoopObserver does not panic on events" {
    var noop = NoopObserver{};
    const obs = noop.observer();
    const event = ObserverEvent{ .heartbeat_tick = {} };
    obs.recordEvent(&event);
    const metric = ObserverMetric{ .tokens_used = 42 };
    obs.recordMetric(&metric);
    obs.flush();
}

test "LogObserver name" {
    var log_obs = LogObserver{};
    const obs = log_obs.observer();
    try std.testing.expectEqualStrings("log", obs.getName());
}

test "LogObserver does not panic on events" {
    var log_obs = LogObserver{};
    const obs = log_obs.observer();

    const events = [_]ObserverEvent{
        .{ .agent_start = .{ .provider = "openrouter", .model = "claude" } },
        .{ .llm_request = .{ .provider = "openrouter", .model = "claude", .messages_count = 2 } },
        .{ .llm_response = .{ .provider = "openrouter", .model = "claude", .duration_ms = 250, .success = true, .error_message = null } },
        .{ .agent_end = .{ .duration_ms = 500, .tokens_used = 100 } },
        .{ .tool_call_start = .{ .tool = "shell" } },
        .{ .tool_call = .{ .tool = "shell", .duration_ms = 10, .success = false } },
        .{ .turn_complete = {} },
        .{ .channel_message = .{ .channel = "telegram", .direction = "outbound" } },
        .{ .heartbeat_tick = {} },
        .{ .err = .{ .component = "provider", .message = "timeout" } },
    };

    for (&events) |*event| {
        obs.recordEvent(event);
    }

    const metrics = [_]ObserverMetric{
        .{ .request_latency_ms = 2000 },
        .{ .tokens_used = 0 },
        .{ .active_sessions = 1 },
        .{ .queue_depth = 999 },
    };
    for (&metrics) |*metric| {
        obs.recordMetric(metric);
    }
}

test "VerboseObserver name" {
    var verbose = VerboseObserver{};
    const obs = verbose.observer();
    try std.testing.expectEqualStrings("verbose", obs.getName());
}

test "MultiObserver name" {
    var multi = MultiObserver{ .observers = &.{} };
    const obs = multi.observer();
    try std.testing.expectEqualStrings("multi", obs.getName());
}

test "MultiObserver empty does not panic" {
    var multi = MultiObserver{ .observers = @constCast(&[_]Observer{}) };
    const obs = multi.observer();
    const event = ObserverEvent{ .heartbeat_tick = {} };
    obs.recordEvent(&event);
    const metric = ObserverMetric{ .tokens_used = 10 };
    obs.recordMetric(&metric);
    obs.flush();
}

test "MultiObserver fans out events" {
    var noop1 = NoopObserver{};
    var noop2 = NoopObserver{};
    var observers_arr = [_]Observer{ noop1.observer(), noop2.observer() };
    var multi = MultiObserver{ .observers = &observers_arr };
    const obs = multi.observer();

    const event = ObserverEvent{ .heartbeat_tick = {} };
    obs.recordEvent(&event);
    obs.recordEvent(&event);
    obs.recordEvent(&event);
    // No panic = success (NoopObserver doesn't count but we verify fan-out doesn't crash)
}

test "createObserver factory" {
    try std.testing.expectEqualStrings("log", createObserver("log"));
    try std.testing.expectEqualStrings("verbose", createObserver("verbose"));
    try std.testing.expectEqualStrings("file", createObserver("file"));
    try std.testing.expectEqualStrings("multi", createObserver("multi"));
    try std.testing.expectEqualStrings("noop", createObserver("none"));
    try std.testing.expectEqualStrings("noop", createObserver("noop"));
    try std.testing.expectEqualStrings("noop", createObserver("unknown_backend"));
    try std.testing.expectEqualStrings("noop", createObserver(""));
}

test "FileObserver name" {
    var file_obs = FileObserver{ .path = "/tmp/nullclaw_test_obs.jsonl" };
    const obs = file_obs.observer();
    try std.testing.expectEqualStrings("file", obs.getName());
}

test "FileObserver does not panic on events" {
    var file_obs = FileObserver{ .path = "/tmp/nullclaw_test_obs.jsonl" };
    const obs = file_obs.observer();
    const event = ObserverEvent{ .heartbeat_tick = {} };
    obs.recordEvent(&event);
    const metric = ObserverMetric{ .tokens_used = 42 };
    obs.recordMetric(&metric);
    obs.flush();
}

test "FileObserver handles all event types" {
    var file_obs = FileObserver{ .path = "/tmp/nullclaw_test_obs2.jsonl" };
    const obs = file_obs.observer();
    const events = [_]ObserverEvent{
        .{ .agent_start = .{ .provider = "test", .model = "test" } },
        .{ .llm_request = .{ .provider = "test", .model = "test", .messages_count = 1 } },
        .{ .llm_response = .{ .provider = "test", .model = "test", .duration_ms = 100, .success = true, .error_message = null } },
        .{ .agent_end = .{ .duration_ms = 1000, .tokens_used = 500 } },
        .{ .tool_call_start = .{ .tool = "shell" } },
        .{ .tool_call = .{ .tool = "shell", .duration_ms = 50, .success = true } },
        .{ .turn_complete = {} },
        .{ .channel_message = .{ .channel = "cli", .direction = "inbound" } },
        .{ .heartbeat_tick = {} },
        .{ .err = .{ .component = "test", .message = "error" } },
    };
    for (&events) |*event| {
        obs.recordEvent(event);
    }
}

// ── Additional observability tests ──────────────────────────────

test "VerboseObserver does not panic on events" {
    var verbose = VerboseObserver{};
    const obs = verbose.observer();
    const event = ObserverEvent{ .heartbeat_tick = {} };
    obs.recordEvent(&event);
    const metric = ObserverMetric{ .tokens_used = 42 };
    obs.recordMetric(&metric);
    obs.flush();
}

test "VerboseObserver handles all event types" {
    var verbose = VerboseObserver{};
    const obs = verbose.observer();
    const events = [_]ObserverEvent{
        .{ .llm_request = .{ .provider = "test", .model = "test", .messages_count = 1 } },
        .{ .llm_response = .{ .provider = "test", .model = "test", .duration_ms = 100, .success = true, .error_message = null } },
        .{ .tool_call_start = .{ .tool = "shell" } },
        .{ .tool_call = .{ .tool = "shell", .duration_ms = 50, .success = true } },
        .{ .turn_complete = {} },
        .{ .agent_start = .{ .provider = "test", .model = "test" } },
        .{ .agent_end = .{ .duration_ms = 1000, .tokens_used = 500 } },
        .{ .channel_message = .{ .channel = "cli", .direction = "inbound" } },
        .{ .heartbeat_tick = {} },
        .{ .err = .{ .component = "test", .message = "error" } },
    };
    for (&events) |*event| {
        obs.recordEvent(event);
    }
}

test "MultiObserver fans out metrics" {
    var noop1 = NoopObserver{};
    var noop2 = NoopObserver{};
    var observers_arr = [_]Observer{ noop1.observer(), noop2.observer() };
    var multi = MultiObserver{ .observers = &observers_arr };
    const obs = multi.observer();

    const metric = ObserverMetric{ .request_latency_ms = 500 };
    obs.recordMetric(&metric);
    obs.recordMetric(&metric);
    // No panic = success
}

test "MultiObserver fans out flush" {
    var noop1 = NoopObserver{};
    var noop2 = NoopObserver{};
    var observers_arr = [_]Observer{ noop1.observer(), noop2.observer() };
    var multi = MultiObserver{ .observers = &observers_arr };
    const obs = multi.observer();

    obs.flush();
    obs.flush();
    // No panic = success
}

test "ObserverEvent agent_start fields" {
    const event = ObserverEvent{ .agent_start = .{ .provider = "openrouter", .model = "claude-sonnet" } };
    switch (event) {
        .agent_start => |e| {
            try std.testing.expectEqualStrings("openrouter", e.provider);
            try std.testing.expectEqualStrings("claude-sonnet", e.model);
        },
        else => unreachable,
    }
}

test "ObserverEvent agent_end fields" {
    const event = ObserverEvent{ .agent_end = .{ .duration_ms = 1500, .tokens_used = 250 } };
    switch (event) {
        .agent_end => |e| {
            try std.testing.expectEqual(@as(u64, 1500), e.duration_ms);
            try std.testing.expectEqual(@as(?u64, 250), e.tokens_used);
        },
        else => unreachable,
    }
}

test "ObserverEvent err fields" {
    const event = ObserverEvent{ .err = .{ .component = "gateway", .message = "connection refused" } };
    switch (event) {
        .err => |e| {
            try std.testing.expectEqualStrings("gateway", e.component);
            try std.testing.expectEqualStrings("connection refused", e.message);
        },
        else => unreachable,
    }
}

test "ObserverMetric variants" {
    const m1 = ObserverMetric{ .request_latency_ms = 100 };
    const m2 = ObserverMetric{ .tokens_used = 50 };
    const m3 = ObserverMetric{ .active_sessions = 3 };
    const m4 = ObserverMetric{ .queue_depth = 10 };
    switch (m1) {
        .request_latency_ms => |v| try std.testing.expectEqual(@as(u64, 100), v),
        else => unreachable,
    }
    switch (m2) {
        .tokens_used => |v| try std.testing.expectEqual(@as(u64, 50), v),
        else => unreachable,
    }
    switch (m3) {
        .active_sessions => |v| try std.testing.expectEqual(@as(u64, 3), v),
        else => unreachable,
    }
    switch (m4) {
        .queue_depth => |v| try std.testing.expectEqual(@as(u64, 10), v),
        else => unreachable,
    }
}

test "LogObserver handles failed llm_response" {
    var log_obs = LogObserver{};
    const obs = log_obs.observer();
    const event = ObserverEvent{ .llm_response = .{
        .provider = "test",
        .model = "test",
        .duration_ms = 0,
        .success = false,
        .error_message = "timeout",
    } };
    obs.recordEvent(&event);
    // No panic = success
}

test "NoopObserver all metrics no-op" {
    var noop = NoopObserver{};
    const obs = noop.observer();
    const metrics = [_]ObserverMetric{
        .{ .request_latency_ms = 0 },
        .{ .tokens_used = std.math.maxInt(u64) },
        .{ .active_sessions = 0 },
        .{ .queue_depth = 0 },
    };
    for (&metrics) |*metric| {
        obs.recordMetric(metric);
    }
}

test "MultiObserver with single observer" {
    var noop = NoopObserver{};
    var observers_arr = [_]Observer{noop.observer()};
    var multi = MultiObserver{ .observers = &observers_arr };
    const obs = multi.observer();
    try std.testing.expectEqualStrings("multi", obs.getName());
    const event = ObserverEvent{ .turn_complete = {} };
    obs.recordEvent(&event);
}

test "createObserver case sensitive" {
    try std.testing.expectEqualStrings("noop", createObserver("Log"));
    try std.testing.expectEqualStrings("noop", createObserver("VERBOSE"));
    try std.testing.expectEqualStrings("noop", createObserver("NONE"));
    try std.testing.expectEqualStrings("noop", createObserver("FILE"));
}

test "Observer interface dispatches correctly" {
    // Verify the vtable pattern works through the Observer interface
    var noop = NoopObserver{};
    var log_obs = LogObserver{};
    var verbose = VerboseObserver{};
    var file_obs = FileObserver{ .path = "/tmp/nullclaw_dispatch_test.jsonl" };

    const observers = [_]Observer{ noop.observer(), log_obs.observer(), verbose.observer(), file_obs.observer() };
    const expected_names = [_][]const u8{ "noop", "log", "verbose", "file" };

    for (observers, expected_names) |obs, name| {
        try std.testing.expectEqualStrings(name, obs.getName());
    }
}
