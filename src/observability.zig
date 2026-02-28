const std = @import("std");

/// Events the observer can record.
pub const ObserverEvent = union(enum) {
    agent_start: struct { provider: []const u8, model: []const u8 },
    llm_request: struct { provider: []const u8, model: []const u8, messages_count: usize },
    llm_response: struct { provider: []const u8, model: []const u8, duration_ms: u64, success: bool, error_message: ?[]const u8 },
    agent_end: struct { duration_ms: u64, tokens_used: ?u64 },
    tool_call_start: struct { tool: []const u8 },
    tool_call: struct { tool: []const u8, duration_ms: u64, success: bool, detail: ?[]const u8 = null },
    tool_iterations_exhausted: struct { iterations: u32 },
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

const MAX_TOOL_CALL_DETAIL_LEN: usize = 256;

fn detailForObserver(detail: ?[]const u8) ?[]const u8 {
    const raw = detail orelse return null;
    if (raw.len == 0) return null;
    if (raw.len <= MAX_TOOL_CALL_DETAIL_LEN) return raw;
    return raw[0..MAX_TOOL_CALL_DETAIL_LEN];
}

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
            .tool_call => |e| {
                if (detailForObserver(e.detail)) |detail| {
                    std.log.info("tool.call tool={s} duration_ms={d} success={} detail={s}", .{ e.tool, e.duration_ms, e.success, detail });
                } else {
                    std.log.info("tool.call tool={s} duration_ms={d} success={}", .{ e.tool, e.duration_ms, e.success });
                }
            },
            .tool_iterations_exhausted => |e| std.log.info("tool.iterations_exhausted iterations={d}", .{e.iterations}),
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
                if (detailForObserver(e.detail)) |detail| {
                    stderr.print("< Tool {s} (success={}, duration_ms={d}, detail={s})\n", .{ e.tool, e.success, e.duration_ms, detail }) catch {};
                } else {
                    stderr.print("< Tool {s} (success={}, duration_ms={d})\n", .{ e.tool, e.success, e.duration_ms }) catch {};
                }
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
            .tool_call => |e| blk: {
                if (detailForObserver(e.detail)) |detail| {
                    break :blk std.fmt.bufPrint(
                        &buf,
                        "{{\"event\":\"tool_call\",\"tool\":\"{s}\",\"duration_ms\":{d},\"success\":{},\"detail\":{f}}}",
                        .{ e.tool, e.duration_ms, e.success, std.json.fmt(detail, .{}) },
                    ) catch return;
                }
                break :blk std.fmt.bufPrint(&buf, "{{\"event\":\"tool_call\",\"tool\":\"{s}\",\"duration_ms\":{d},\"success\":{}}}", .{ e.tool, e.duration_ms, e.success }) catch return;
            },
            .tool_iterations_exhausted => |e| std.fmt.bufPrint(&buf, "{{\"event\":\"tool_iterations_exhausted\",\"iterations\":{d}}}", .{e.iterations}) catch return,
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
fn createObserver(backend: []const u8) []const u8 {
    if (std.mem.eql(u8, backend, "log")) return "log";
    if (std.mem.eql(u8, backend, "verbose")) return "verbose";
    if (std.mem.eql(u8, backend, "file")) return "file";
    if (std.mem.eql(u8, backend, "multi")) return "multi";
    if (std.mem.eql(u8, backend, "otel") or std.mem.eql(u8, backend, "otlp")) return "otel";
    if (std.mem.eql(u8, backend, "none") or std.mem.eql(u8, backend, "noop")) return "noop";
    return "noop"; // fallback
}

// ── OtelObserver ─────────────────────────────────────────────────────

/// OpenTelemetry key-value attribute.
pub const OtelAttribute = struct {
    key: []const u8,
    value: []const u8,
};

/// A single OTLP span with timing and attributes.
pub const OtelSpan = struct {
    trace_id: [32]u8,
    span_id: [16]u8,
    name: []const u8,
    start_ns: u64,
    end_ns: u64,
    attributes: std.ArrayListUnmanaged(OtelAttribute),

    pub fn deinit(self: *OtelSpan, allocator: std.mem.Allocator) void {
        for (self.attributes.items) |attr| {
            allocator.free(attr.key);
            allocator.free(attr.value);
        }
        self.attributes.deinit(allocator);
    }
};

const http_util = @import("http_util.zig");

/// OpenTelemetry OTLP/HTTP observer — batches spans and exports via JSON.
pub const OtelObserver = struct {
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    service_name: []const u8,
    spans: std.ArrayListUnmanaged(OtelSpan),
    mutex: std.Thread.Mutex,
    current_trace_id: [32]u8,
    current_start_ns: u64,
    requests_total: std.atomic.Value(u64),
    errors_total: std.atomic.Value(u64),

    const max_batch_size: usize = 10;

    const vtable_impl = Observer.VTable{
        .record_event = otelRecordEvent,
        .record_metric = otelRecordMetric,
        .flush = otelFlush,
        .name = otelName,
    };

    pub fn init(allocator: std.mem.Allocator, endpoint: ?[]const u8, service_name: ?[]const u8) OtelObserver {
        return .{
            .allocator = allocator,
            .endpoint = endpoint orelse "http://localhost:4318",
            .service_name = service_name orelse "nullclaw",
            .spans = .empty,
            .mutex = .{},
            .current_trace_id = .{0} ** 32,
            .current_start_ns = 0,
            .requests_total = std.atomic.Value(u64).init(0),
            .errors_total = std.atomic.Value(u64).init(0),
        };
    }

    pub fn observer(self: *OtelObserver) Observer {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable_impl,
        };
    }

    pub fn deinit(self: *OtelObserver) void {
        for (self.spans.items) |*span| {
            span.deinit(self.allocator);
        }
        self.spans.deinit(self.allocator);
    }

    fn resolve(ptr: *anyopaque) *OtelObserver {
        return @ptrCast(@alignCast(ptr));
    }

    /// Generate random hex ID into a buffer.
    fn randomHex(buf: []u8) void {
        var raw: [16]u8 = undefined;
        const needed = buf.len / 2;
        std.crypto.random.bytes(raw[0..needed]);
        const hex = "0123456789abcdef";
        for (0..needed) |i| {
            buf[i * 2] = hex[raw[i] >> 4];
            buf[i * 2 + 1] = hex[raw[i] & 0x0f];
        }
    }

    fn nowNs() u64 {
        return @intCast(std.time.nanoTimestamp());
    }

    fn addSpan(self: *OtelObserver, name: []const u8, start_ns: u64, end_ns: u64, attrs: []const OtelAttribute) void {
        var span_id: [16]u8 = undefined;
        randomHex(&span_id);

        var attributes: std.ArrayListUnmanaged(OtelAttribute) = .empty;
        for (attrs) |attr| {
            const key_owned = self.allocator.dupe(u8, attr.key) catch break;
            const value_owned = self.allocator.dupe(u8, attr.value) catch {
                self.allocator.free(key_owned);
                break;
            };
            attributes.append(self.allocator, .{
                .key = key_owned,
                .value = value_owned,
            }) catch {
                self.allocator.free(value_owned);
                self.allocator.free(key_owned);
                break;
            };
        }

        self.spans.append(self.allocator, .{
            .trace_id = self.current_trace_id,
            .span_id = span_id,
            .name = name,
            .start_ns = start_ns,
            .end_ns = end_ns,
            .attributes = attributes,
        }) catch {
            for (attributes.items) |attr| {
                self.allocator.free(attr.key);
                self.allocator.free(attr.value);
            }
            attributes.deinit(self.allocator);
            return;
        };

        if (self.spans.items.len >= max_batch_size) {
            self.flushLocked();
        }
    }

    fn otelRecordEvent(ptr: *anyopaque, event: *const ObserverEvent) void {
        const self = resolve(ptr);
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = nowNs();

        switch (event.*) {
            .agent_start => |e| {
                randomHex(&self.current_trace_id);
                self.current_start_ns = now;
                self.addSpan("agent.start", now, now, &.{
                    .{ .key = "provider", .value = e.provider },
                    .{ .key = "model", .value = e.model },
                });
            },
            .agent_end => |e| {
                const start = if (self.current_start_ns > 0) self.current_start_ns else now;
                var dur_buf: [20]u8 = undefined;
                const dur_str = std.fmt.bufPrint(&dur_buf, "{d}", .{e.duration_ms}) catch "0";
                self.addSpan("agent.end", start, now, &.{
                    .{ .key = "duration_ms", .value = dur_str },
                });
            },
            .llm_request => |e| {
                _ = self.requests_total.fetchAdd(1, .monotonic);
                self.addSpan("llm.request", now, now, &.{
                    .{ .key = "provider", .value = e.provider },
                    .{ .key = "model", .value = e.model },
                });
            },
            .llm_response => |e| {
                if (!e.success) {
                    _ = self.errors_total.fetchAdd(1, .monotonic);
                }
                var dur_buf: [20]u8 = undefined;
                const dur_str = std.fmt.bufPrint(&dur_buf, "{d}", .{e.duration_ms}) catch "0";
                self.addSpan("llm.response", now -| (e.duration_ms * 1_000_000), now, &.{
                    .{ .key = "provider", .value = e.provider },
                    .{ .key = "model", .value = e.model },
                    .{ .key = "duration_ms", .value = dur_str },
                    .{ .key = "success", .value = if (e.success) "true" else "false" },
                });
            },
            .tool_call_start => |e| {
                self.addSpan("tool.start", now, now, &.{
                    .{ .key = "tool", .value = e.tool },
                });
            },
            .tool_call => |e| {
                var dur_buf: [20]u8 = undefined;
                const dur_str = std.fmt.bufPrint(&dur_buf, "{d}", .{e.duration_ms}) catch "0";
                if (detailForObserver(e.detail)) |detail| {
                    self.addSpan("tool.call", now -| (e.duration_ms * 1_000_000), now, &.{
                        .{ .key = "tool", .value = e.tool },
                        .{ .key = "duration_ms", .value = dur_str },
                        .{ .key = "success", .value = if (e.success) "true" else "false" },
                        .{ .key = "detail", .value = detail },
                    });
                } else {
                    self.addSpan("tool.call", now -| (e.duration_ms * 1_000_000), now, &.{
                        .{ .key = "tool", .value = e.tool },
                        .{ .key = "duration_ms", .value = dur_str },
                        .{ .key = "success", .value = if (e.success) "true" else "false" },
                    });
                }
            },
            .tool_iterations_exhausted => |e| {
                var iter_buf: [20]u8 = undefined;
                const iter_str = std.fmt.bufPrint(&iter_buf, "{d}", .{e.iterations}) catch "0";
                self.addSpan("tool.iterations_exhausted", now, now, &.{
                    .{ .key = "iterations", .value = iter_str },
                });
            },
            .turn_complete => {
                self.addSpan("turn.complete", now, now, &.{});
            },
            .channel_message => |e| {
                self.addSpan("channel.message", now, now, &.{
                    .{ .key = "channel", .value = e.channel },
                    .{ .key = "direction", .value = e.direction },
                });
            },
            .heartbeat_tick => {
                self.addSpan("heartbeat.tick", now, now, &.{});
            },
            .err => |e| {
                _ = self.errors_total.fetchAdd(1, .monotonic);
                self.addSpan("error", now, now, &.{
                    .{ .key = "component", .value = e.component },
                    .{ .key = "message", .value = e.message },
                });
            },
        }
    }

    fn otelRecordMetric(ptr: *anyopaque, metric: *const ObserverMetric) void {
        const self = resolve(ptr);
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = nowNs();

        switch (metric.*) {
            .request_latency_ms => |v| {
                var buf: [20]u8 = undefined;
                const s = std.fmt.bufPrint(&buf, "{d}", .{v}) catch return;
                self.addSpan("metric.request_latency_ms", now, now, &.{
                    .{ .key = "value", .value = s },
                });
            },
            .tokens_used => |v| {
                var buf: [20]u8 = undefined;
                const s = std.fmt.bufPrint(&buf, "{d}", .{v}) catch return;
                self.addSpan("metric.tokens_used", now, now, &.{
                    .{ .key = "value", .value = s },
                });
            },
            .active_sessions => |v| {
                var buf: [20]u8 = undefined;
                const s = std.fmt.bufPrint(&buf, "{d}", .{v}) catch return;
                self.addSpan("metric.active_sessions", now, now, &.{
                    .{ .key = "value", .value = s },
                });
            },
            .queue_depth => |v| {
                var buf: [20]u8 = undefined;
                const s = std.fmt.bufPrint(&buf, "{d}", .{v}) catch return;
                self.addSpan("metric.queue_depth", now, now, &.{
                    .{ .key = "value", .value = s },
                });
            },
        }
    }

    /// Serialize all pending spans as OTLP/HTTP JSON payload.
    pub fn serializeSpans(self: *OtelObserver) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);

        try w.writeAll("{\"resourceSpans\":[{\"resource\":{\"attributes\":[{\"key\":\"service.name\",\"value\":{\"stringValue\":\"");
        try w.writeAll(self.service_name);
        try w.writeAll("\"}}]},\"scopeSpans\":[{\"spans\":[");

        for (self.spans.items, 0..) |span, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeAll("{\"traceId\":\"");
            try w.writeAll(&span.trace_id);
            try w.writeAll("\",\"spanId\":\"");
            try w.writeAll(&span.span_id);
            try w.writeAll("\",\"name\":\"");
            try w.writeAll(span.name);
            try w.writeAll("\",\"startTimeUnixNano\":\"");
            try w.print("{d}", .{span.start_ns});
            try w.writeAll("\",\"endTimeUnixNano\":\"");
            try w.print("{d}", .{span.end_ns});
            try w.writeAll("\",\"attributes\":[");

            for (span.attributes.items, 0..) |attr, j| {
                if (j > 0) try w.writeByte(',');
                try w.print(
                    "{{\"key\":{f},\"value\":{{\"stringValue\":{f}}}}}",
                    .{ std.json.fmt(attr.key, .{}), std.json.fmt(attr.value, .{}) },
                );
            }

            try w.writeAll("],\"status\":{\"code\":1}}");
        }

        try w.writeAll("]}]}]}");

        return buf.toOwnedSlice(self.allocator);
    }

    /// Flush pending spans to the OTLP endpoint. Caller must hold the mutex.
    fn flushLocked(self: *OtelObserver) void {
        if (self.spans.items.len == 0) return;

        const payload = self.serializeSpans() catch return;
        defer self.allocator.free(payload);

        const url_buf = std.fmt.allocPrint(self.allocator, "{s}/v1/traces", .{self.endpoint}) catch return;
        defer self.allocator.free(url_buf);

        // Best-effort send; free response if successful
        if (http_util.curlPost(self.allocator, url_buf, payload, &.{})) |curl_resp| {
            self.allocator.free(curl_resp);
        } else |_| {}

        // Clear spans regardless of delivery success to prevent unbounded growth
        for (self.spans.items) |*span| {
            span.deinit(self.allocator);
        }
        self.spans.clearRetainingCapacity();
    }

    fn otelFlush(ptr: *anyopaque) void {
        const self = resolve(ptr);
        self.mutex.lock();
        defer self.mutex.unlock();
        self.flushLocked();
    }

    fn otelName(_: *anyopaque) []const u8 {
        return "otel";
    }
};

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
    try std.testing.expectEqualStrings("otel", createObserver("otel"));
    try std.testing.expectEqualStrings("otel", createObserver("otlp"));
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

test "FileObserver tool_call detail is persisted as JSON string" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base);
    const path = try std.fmt.allocPrint(allocator, "{s}/obs_tool_detail.jsonl", .{base});
    defer allocator.free(path);

    var file_obs = FileObserver{ .path = path };
    const obs = file_obs.observer();
    const event = ObserverEvent{ .tool_call = .{
        .tool = "shell",
        .duration_ms = 7,
        .success = false,
        .detail = "exit code 1: \"permission denied\"",
    } };
    obs.recordEvent(&event);

    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 4096);
    defer allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "\"event\":\"tool_call\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"detail\":\"exit code 1: \\\"permission denied\\\"\"") != null);
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

test "ObserverEvent tool_call detail defaults to null" {
    const event = ObserverEvent{ .tool_call = .{ .tool = "shell", .duration_ms = 42, .success = true } };
    switch (event) {
        .tool_call => |e| {
            try std.testing.expectEqualStrings("shell", e.tool);
            try std.testing.expectEqual(@as(u64, 42), e.duration_ms);
            try std.testing.expect(e.success);
            try std.testing.expect(e.detail == null);
        },
        else => unreachable,
    }
}

test "ObserverEvent tool_call detail carries failure context" {
    const event = ObserverEvent{ .tool_call = .{ .tool = "shell", .duration_ms = 10, .success = false, .detail = "exit code 1" } };
    switch (event) {
        .tool_call => |e| {
            try std.testing.expect(!e.success);
            try std.testing.expectEqualStrings("exit code 1", e.detail.?);
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

// ── OtelObserver tests ──────────────────────────────────────────

test "OtelObserver name" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();
    try std.testing.expectEqualStrings("otel", obs.getName());
}

test "OtelObserver init defaults" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    try std.testing.expectEqualStrings("http://localhost:4318", otel.endpoint);
    try std.testing.expectEqualStrings("nullclaw", otel.service_name);
    try std.testing.expectEqual(@as(usize, 0), otel.spans.items.len);
}

test "OtelObserver init custom endpoint" {
    var otel = OtelObserver.init(std.testing.allocator, "http://otel:4318", "myservice");
    defer otel.deinit();
    try std.testing.expectEqualStrings("http://otel:4318", otel.endpoint);
    try std.testing.expectEqualStrings("myservice", otel.service_name);
}

test "OtelObserver span building on agent_start" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    const event = ObserverEvent{ .agent_start = .{ .provider = "openrouter", .model = "claude" } };
    obs.recordEvent(&event);

    try std.testing.expectEqual(@as(usize, 1), otel.spans.items.len);
    try std.testing.expectEqualStrings("agent.start", otel.spans.items[0].name);
    // trace_id should be set (not all zeros)
    var all_zero = true;
    for (otel.current_trace_id) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "OtelObserver span building on all event types" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    // Record 9 events (under batch threshold of 10) to verify all types produce spans
    const events = [_]ObserverEvent{
        .{ .agent_start = .{ .provider = "test", .model = "test" } },
        .{ .llm_request = .{ .provider = "test", .model = "test", .messages_count = 1 } },
        .{ .llm_response = .{ .provider = "test", .model = "test", .duration_ms = 100, .success = true, .error_message = null } },
        .{ .tool_call_start = .{ .tool = "shell" } },
        .{ .tool_call = .{ .tool = "shell", .duration_ms = 50, .success = true } },
        .{ .turn_complete = {} },
        .{ .channel_message = .{ .channel = "cli", .direction = "inbound" } },
        .{ .heartbeat_tick = {} },
        .{ .err = .{ .component = "test", .message = "oops" } },
    };
    for (&events) |*event| {
        obs.recordEvent(event);
    }

    try std.testing.expectEqual(@as(usize, 9), otel.spans.items.len);
    try std.testing.expectEqualStrings("agent.start", otel.spans.items[0].name);
    try std.testing.expectEqualStrings("llm.request", otel.spans.items[1].name);
    try std.testing.expectEqualStrings("llm.response", otel.spans.items[2].name);
    try std.testing.expectEqualStrings("tool.start", otel.spans.items[3].name);
    try std.testing.expectEqualStrings("tool.call", otel.spans.items[4].name);
    try std.testing.expectEqualStrings("turn.complete", otel.spans.items[5].name);
    try std.testing.expectEqualStrings("channel.message", otel.spans.items[6].name);
    try std.testing.expectEqualStrings("heartbeat.tick", otel.spans.items[7].name);
    try std.testing.expectEqualStrings("error", otel.spans.items[8].name);

    // Verify agent_end works too (10th event triggers batch flush)
    const end_event = ObserverEvent{ .agent_end = .{ .duration_ms = 1000, .tokens_used = 500 } };
    obs.recordEvent(&end_event);
    // After flush, spans are cleared
    try std.testing.expect(otel.spans.items.len < 10);
}

test "OtelObserver span attributes" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    const event = ObserverEvent{ .agent_start = .{ .provider = "openrouter", .model = "claude" } };
    obs.recordEvent(&event);

    const span = otel.spans.items[0];
    try std.testing.expectEqual(@as(usize, 2), span.attributes.items.len);
    try std.testing.expectEqualStrings("provider", span.attributes.items[0].key);
    try std.testing.expectEqualStrings("openrouter", span.attributes.items[0].value);
    try std.testing.expectEqualStrings("model", span.attributes.items[1].key);
    try std.testing.expectEqualStrings("claude", span.attributes.items[1].value);
}

test "OtelObserver tool_call includes detail attribute" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    const event = ObserverEvent{ .tool_call = .{
        .tool = "shell",
        .duration_ms = 12,
        .success = false,
        .detail = "permission denied",
    } };
    obs.recordEvent(&event);

    try std.testing.expectEqual(@as(usize, 1), otel.spans.items.len);
    const span = otel.spans.items[0];
    try std.testing.expectEqualStrings("tool.call", span.name);

    var found_detail = false;
    for (span.attributes.items) |attr| {
        if (std.mem.eql(u8, attr.key, "detail")) {
            found_detail = true;
            try std.testing.expectEqualStrings("permission denied", attr.value);
        }
    }
    try std.testing.expect(found_detail);
}

test "OtelObserver spans keep independent attribute values" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    const first = ObserverEvent{ .tool_call = .{
        .tool = "shell",
        .duration_ms = 111,
        .success = false,
        .detail = "first detail",
    } };
    const second = ObserverEvent{ .tool_call = .{
        .tool = "shell",
        .duration_ms = 222,
        .success = false,
        .detail = "second detail",
    } };
    obs.recordEvent(&first);
    obs.recordEvent(&second);

    try std.testing.expectEqual(@as(usize, 2), otel.spans.items.len);

    const first_span = otel.spans.items[0];
    const second_span = otel.spans.items[1];

    var first_duration: ?[]const u8 = null;
    var second_duration: ?[]const u8 = null;
    var first_detail: ?[]const u8 = null;
    var second_detail: ?[]const u8 = null;

    for (first_span.attributes.items) |attr| {
        if (std.mem.eql(u8, attr.key, "duration_ms")) first_duration = attr.value;
        if (std.mem.eql(u8, attr.key, "detail")) first_detail = attr.value;
    }
    for (second_span.attributes.items) |attr| {
        if (std.mem.eql(u8, attr.key, "duration_ms")) second_duration = attr.value;
        if (std.mem.eql(u8, attr.key, "detail")) second_detail = attr.value;
    }

    try std.testing.expect(first_duration != null);
    try std.testing.expect(second_duration != null);
    try std.testing.expect(first_detail != null);
    try std.testing.expect(second_detail != null);
    try std.testing.expectEqualStrings("111", first_duration.?);
    try std.testing.expectEqualStrings("222", second_duration.?);
    try std.testing.expectEqualStrings("first detail", first_detail.?);
    try std.testing.expectEqualStrings("second detail", second_detail.?);
}

test "OtelObserver JSON serialization escapes tool_call detail" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    const start = ObserverEvent{ .agent_start = .{ .provider = "openrouter", .model = "claude" } };
    const event = ObserverEvent{ .tool_call = .{
        .tool = "shell",
        .duration_ms = 5,
        .success = false,
        .detail = "exit code 1: \"denied\"\nline2",
    } };
    obs.recordEvent(&start);
    obs.recordEvent(&event);

    const json = try otel.serializeSpans();
    defer std.testing.allocator.free(json);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();

    try std.testing.expect(std.mem.indexOf(u8, json, "\\\"denied\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\\nline2") != null);
}

test "OtelObserver JSON serialization" {
    var otel = OtelObserver.init(std.testing.allocator, null, "test-svc");
    defer otel.deinit();
    const obs = otel.observer();

    const event = ObserverEvent{ .agent_start = .{ .provider = "test", .model = "m1" } };
    obs.recordEvent(&event);

    const json = try otel.serializeSpans();
    defer std.testing.allocator.free(json);

    // Verify overall structure
    try std.testing.expect(std.mem.startsWith(u8, json, "{\"resourceSpans\":[{\"resource\":{\"attributes\":[{\"key\":\"service.name\",\"value\":{\"stringValue\":\"test-svc\"}}]}"));
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"agent.start\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"traceId\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"spanId\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"startTimeUnixNano\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"endTimeUnixNano\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"key\":\"provider\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"stringValue\":\"test\"") != null);
    try std.testing.expect(std.mem.endsWith(u8, json, "]}]}]}"));
}

test "OtelObserver JSON multiple spans" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    const e1 = ObserverEvent{ .agent_start = .{ .provider = "a", .model = "b" } };
    obs.recordEvent(&e1);
    const e2 = ObserverEvent{ .turn_complete = {} };
    obs.recordEvent(&e2);

    const json = try otel.serializeSpans();
    defer std.testing.allocator.free(json);

    // Two spans separated by comma
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"agent.start\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"turn.complete\"") != null);
}

test "OtelObserver batch flush at 10 spans" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    // Record 9 events — should not flush
    for (0..9) |_| {
        const event = ObserverEvent{ .heartbeat_tick = {} };
        obs.recordEvent(&event);
    }
    try std.testing.expectEqual(@as(usize, 9), otel.spans.items.len);

    // 10th event triggers flush attempt (curl fails, spans get cleared anyway)
    const event = ObserverEvent{ .heartbeat_tick = {} };
    obs.recordEvent(&event);
    // After flush attempt (curl fails), spans are cleared
    try std.testing.expect(otel.spans.items.len < 10);
}

test "OtelObserver metrics create spans" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    const m1 = ObserverMetric{ .request_latency_ms = 42 };
    obs.recordMetric(&m1);
    const m2 = ObserverMetric{ .tokens_used = 100 };
    obs.recordMetric(&m2);
    const m3 = ObserverMetric{ .active_sessions = 3 };
    obs.recordMetric(&m3);
    const m4 = ObserverMetric{ .queue_depth = 7 };
    obs.recordMetric(&m4);

    try std.testing.expectEqual(@as(usize, 4), otel.spans.items.len);
    try std.testing.expectEqualStrings("metric.request_latency_ms", otel.spans.items[0].name);
    try std.testing.expectEqualStrings("metric.tokens_used", otel.spans.items[1].name);
    try std.testing.expectEqualStrings("metric.active_sessions", otel.spans.items[2].name);
    try std.testing.expectEqualStrings("metric.queue_depth", otel.spans.items[3].name);
}

test "OtelObserver flush empty is noop" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();
    // Flush with no spans should not panic or leak
    obs.flush();
}

test "OtelObserver randomHex produces valid hex" {
    var buf: [32]u8 = undefined;
    OtelObserver.randomHex(&buf);
    for (buf) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "OtelObserver span timing" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    const event = ObserverEvent{ .heartbeat_tick = {} };
    obs.recordEvent(&event);

    const span = otel.spans.items[0];
    try std.testing.expect(span.start_ns > 0);
    try std.testing.expect(span.end_ns >= span.start_ns);
}

test "OtelObserver llm_response has duration-adjusted start" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    const event = ObserverEvent{ .llm_response = .{
        .provider = "p",
        .model = "m",
        .duration_ms = 100,
        .success = true,
        .error_message = null,
    } };
    obs.recordEvent(&event);

    const span = otel.spans.items[0];
    // start should be earlier than end by ~100ms
    try std.testing.expect(span.end_ns >= span.start_ns);
    try std.testing.expect(span.end_ns - span.start_ns >= 50_000_000); // at least 50ms delta
}

test "OtelObserver vtable through Observer interface" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    // Verify it works through the generic Observer interface
    try std.testing.expectEqualStrings("otel", obs.getName());
    const event = ObserverEvent{ .heartbeat_tick = {} };
    obs.recordEvent(&event);
    const metric = ObserverMetric{ .tokens_used = 10 };
    obs.recordMetric(&metric);
    obs.flush(); // flush attempt (curl fails silently)
}

test "OtelObserver requests_total counter" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    try std.testing.expectEqual(@as(u64, 0), otel.requests_total.load(.monotonic));

    const e1 = ObserverEvent{ .llm_request = .{ .provider = "p", .model = "m", .messages_count = 1 } };
    obs.recordEvent(&e1);
    try std.testing.expectEqual(@as(u64, 1), otel.requests_total.load(.monotonic));

    obs.recordEvent(&e1);
    obs.recordEvent(&e1);
    try std.testing.expectEqual(@as(u64, 3), otel.requests_total.load(.monotonic));

    // Non-request events should not increment requests_total
    const e2 = ObserverEvent{ .heartbeat_tick = {} };
    obs.recordEvent(&e2);
    try std.testing.expectEqual(@as(u64, 3), otel.requests_total.load(.monotonic));
}

test "OtelObserver errors_total counter on failed response" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    try std.testing.expectEqual(@as(u64, 0), otel.errors_total.load(.monotonic));

    // Successful response should not increment errors
    const ok = ObserverEvent{ .llm_response = .{ .provider = "p", .model = "m", .duration_ms = 50, .success = true, .error_message = null } };
    obs.recordEvent(&ok);
    try std.testing.expectEqual(@as(u64, 0), otel.errors_total.load(.monotonic));

    // Failed response should increment errors
    const fail = ObserverEvent{ .llm_response = .{ .provider = "p", .model = "m", .duration_ms = 50, .success = false, .error_message = "timeout" } };
    obs.recordEvent(&fail);
    try std.testing.expectEqual(@as(u64, 1), otel.errors_total.load(.monotonic));
}

test "OtelObserver errors_total counter on error event" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    const e1 = ObserverEvent{ .err = .{ .component = "provider", .message = "connection refused" } };
    obs.recordEvent(&e1);
    obs.recordEvent(&e1);
    try std.testing.expectEqual(@as(u64, 2), otel.errors_total.load(.monotonic));
}

test "OtelObserver JSON includes status code" {
    var otel = OtelObserver.init(std.testing.allocator, null, "svc");
    defer otel.deinit();
    const obs = otel.observer();

    const event = ObserverEvent{ .heartbeat_tick = {} };
    obs.recordEvent(&event);

    const json = try otel.serializeSpans();
    defer std.testing.allocator.free(json);

    // Each span should have status code 1 (OK)
    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":{\"code\":1}") != null);
}

test "OtelObserver counters combined scenario" {
    var otel = OtelObserver.init(std.testing.allocator, null, null);
    defer otel.deinit();
    const obs = otel.observer();

    // 3 requests, 1 failed response, 2 errors
    const req = ObserverEvent{ .llm_request = .{ .provider = "p", .model = "m", .messages_count = 1 } };
    obs.recordEvent(&req);
    obs.recordEvent(&req);
    obs.recordEvent(&req);

    const fail = ObserverEvent{ .llm_response = .{ .provider = "p", .model = "m", .duration_ms = 10, .success = false, .error_message = "err" } };
    obs.recordEvent(&fail);

    const err_evt = ObserverEvent{ .err = .{ .component = "net", .message = "dns" } };
    obs.recordEvent(&err_evt);
    obs.recordEvent(&err_evt);

    try std.testing.expectEqual(@as(u64, 3), otel.requests_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 3), otel.errors_total.load(.monotonic)); // 1 failed response + 2 error events
}
