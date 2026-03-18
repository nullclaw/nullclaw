const std = @import("std");
const json_util = @import("../json_util.zig");

const log = std.log.scoped(.stdio_jsonrpc);

const MAX_JSONRPC_LINE_BYTES: usize = 256 * 1024;
const MAX_PENDING_NOTIFICATION_LINES: usize = 256;

pub const ProcessEnvEntry = struct {
    key: []const u8,
    value: []const u8,
};

pub const ProcessConfig = struct {
    command: []const u8,
    args: []const []const u8 = &.{},
    env: []const ProcessEnvEntry = &.{},
};

pub const NotificationHandler = *const fn (ctx: *anyopaque, method: []const u8, params: std.json.Value) anyerror!void;

pub const StdioJsonRpc = struct {
    allocator: std.mem.Allocator,
    child: ?std.process.Child = null,
    reader_thread: ?std.Thread = null,
    notification_thread: ?std.Thread = null,
    reader_alive: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    notification_ctx: ?*anyopaque = null,
    notification_handler: ?NotificationHandler = null,
    request_state: RequestState = .{},
    notification_state: NotificationState = .{},

    const Self = @This();

    const RequestState = struct {
        mutex: std.Thread.Mutex = .{},
        cond: std.Thread.Condition = .{},
        next_id: u32 = 1,
        pending_id: ?u32 = null,
        response_line: ?[]u8 = null,
        closed: bool = false,
    };

    const NotificationState = struct {
        mutex: std.Thread.Mutex = .{},
        cond: std.Thread.Condition = .{},
        queue: std.ArrayListUnmanaged([]u8) = .empty,
        closed: bool = false,
    };

    pub const Error = error{
        ClientAlreadyRunning,
        ClientNotRunning,
        ClientClosed,
        MissingPluginStdout,
        MissingPluginStdin,
        RequestTimeout,
        ResponseTooLarge,
        InvalidPluginMessage,
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
        };
    }

    pub fn start(self: *Self, process_config: ProcessConfig, notification_ctx: ?*anyopaque, notification_handler: ?NotificationHandler) !void {
        if (self.child != null) return Error.ClientAlreadyRunning;

        var argv: std.ArrayListUnmanaged([]const u8) = .empty;
        defer argv.deinit(self.allocator);
        try argv.append(self.allocator, process_config.command);
        for (process_config.args) |arg| {
            try argv.append(self.allocator, arg);
        }

        var child = std.process.Child.init(argv.items, self.allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Inherit;

        if (process_config.env.len > 0) {
            var env = std.process.EnvMap.init(self.allocator);
            defer env.deinit();

            const inherit_vars = [_][]const u8{
                "PATH",        "HOME",    "TERM",         "LANG",   "LC_ALL",
                "LC_CTYPE",    "USER",    "SHELL",        "TMPDIR", "NODE_PATH",
                "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP",   "TMP",
                "SYSTEMROOT",  "COMSPEC", "PROGRAMFILES", "WINDIR",
            };
            for (&inherit_vars) |key| {
                if (std.process.getEnvVarOwned(self.allocator, key)) |value| {
                    defer self.allocator.free(value);
                    try env.put(key, value);
                } else |_| {}
            }
            for (process_config.env) |entry| {
                try env.put(entry.key, entry.value);
            }
            child.env_map = &env;
            try child.spawn();
        } else {
            try child.spawn();
        }

        const stdout_file = child.stdout orelse {
            _ = child.kill() catch {};
            _ = child.wait() catch {};
            return Error.MissingPluginStdout;
        };

        self.child = child;
        self.notification_ctx = notification_ctx;
        self.notification_handler = notification_handler;
        self.resetRequestState();
        self.resetNotificationState();
        if (notification_handler != null) {
            self.notification_thread = std.Thread.spawn(.{}, notificationThreadMain, .{self}) catch |err| {
                self.stop();
                return err;
            };
        }
        self.reader_thread = std.Thread.spawn(.{}, readerThreadMain, .{ self, stdout_file }) catch |err| {
            self.stop();
            return err;
        };
    }

    pub fn stop(self: *Self) void {
        self.signalClosed();
        self.closeNotificationQueue(true);

        if (self.child) |*child| {
            if (child.stdin) |stdin_file| {
                stdin_file.close();
                child.stdin = null;
            }
            _ = child.kill() catch {};
        }

        if (self.reader_thread) |thread| {
            thread.join();
            self.reader_thread = null;
        }
        if (self.notification_thread) |thread| {
            thread.join();
            self.notification_thread = null;
        }

        if (self.child) |*child| {
            _ = child.wait() catch {};
        }
        self.child = null;
        self.reader_alive.store(false, .release);
        self.notification_ctx = null;
        self.notification_handler = null;
        self.clearPendingResponse();
        self.deinitNotificationState();
    }

    pub fn request(self: *Self, method: []const u8, params_json: []const u8, timeout_ms: u32) ![]u8 {
        const child = if (self.child) |*child| child else return Error.ClientNotRunning;
        const stdin_file = child.stdin orelse return Error.MissingPluginStdin;

        const request_id = blk: {
            self.request_state.mutex.lock();
            defer self.request_state.mutex.unlock();
            if (self.request_state.closed) return Error.ClientClosed;
            if (self.request_state.response_line) |line| {
                self.allocator.free(line);
                self.request_state.response_line = null;
            }
            const id = self.request_state.next_id;
            self.request_state.next_id += 1;
            self.request_state.pending_id = id;
            break :blk id;
        };

        const request_line = try buildJsonRpcRequest(self.allocator, request_id, method, params_json);
        defer self.allocator.free(request_line);

        stdin_file.writeAll(request_line) catch |err| {
            self.signalClosed();
            return err;
        };
        stdin_file.writeAll("\n") catch |err| {
            self.signalClosed();
            return err;
        };

        const deadline_ns: i128 = std.time.nanoTimestamp() +
            (@as(i128, @intCast(timeout_ms)) * std.time.ns_per_ms);
        self.request_state.mutex.lock();
        defer self.request_state.mutex.unlock();
        while (!self.request_state.closed and self.request_state.pending_id != null and self.request_state.response_line == null) {
            const remaining_ns = remainingRequestTimeoutNs(deadline_ns);
            if (remaining_ns == 0) {
                self.request_state.pending_id = null;
                return Error.RequestTimeout;
            }
            self.request_state.cond.timedWait(&self.request_state.mutex, remaining_ns) catch |err| switch (err) {
                error.Timeout => {
                    if (!self.request_state.closed and self.request_state.pending_id != null and self.request_state.response_line == null) {
                        self.request_state.pending_id = null;
                        return Error.RequestTimeout;
                    }
                },
            };
        }
        if (self.request_state.response_line) |line| {
            self.request_state.response_line = null;
            return line;
        }
        return Error.ClientClosed;
    }

    pub fn isReaderAlive(self: *const Self) bool {
        return self.reader_alive.load(.acquire);
    }

    pub fn hasChild(self: *const Self) bool {
        return self.child != null;
    }

    fn resetRequestState(self: *Self) void {
        self.request_state.mutex.lock();
        defer self.request_state.mutex.unlock();
        self.request_state.next_id = 1;
        self.request_state.pending_id = null;
        if (self.request_state.response_line) |line| {
            self.allocator.free(line);
            self.request_state.response_line = null;
        }
        self.request_state.closed = false;
    }

    fn resetNotificationState(self: *Self) void {
        self.notification_state.mutex.lock();
        defer self.notification_state.mutex.unlock();
        self.freeQueuedNotificationsLocked();
        self.notification_state.queue.deinit(self.allocator);
        self.notification_state.queue = .empty;
        self.notification_state.closed = false;
    }

    fn clearPendingResponse(self: *Self) void {
        self.request_state.mutex.lock();
        defer self.request_state.mutex.unlock();
        if (self.request_state.response_line) |line| {
            self.allocator.free(line);
            self.request_state.response_line = null;
        }
        self.request_state.pending_id = null;
    }

    fn deinitNotificationState(self: *Self) void {
        self.notification_state.mutex.lock();
        defer self.notification_state.mutex.unlock();
        self.freeQueuedNotificationsLocked();
        self.notification_state.queue.deinit(self.allocator);
        self.notification_state.queue = .empty;
        self.notification_state.closed = false;
    }

    fn signalClosed(self: *Self) void {
        self.request_state.mutex.lock();
        defer self.request_state.mutex.unlock();
        self.request_state.closed = true;
        self.request_state.pending_id = null;
        self.request_state.cond.broadcast();
    }

    fn closeNotificationQueue(self: *Self, drop_pending: bool) void {
        self.notification_state.mutex.lock();
        defer self.notification_state.mutex.unlock();
        self.notification_state.closed = true;
        if (drop_pending) {
            self.freeQueuedNotificationsLocked();
            self.notification_state.queue.items.len = 0;
        }
        self.notification_state.cond.broadcast();
    }

    fn readerThreadMain(self: *Self, stdout_file: std.fs.File) void {
        var stdout = stdout_file;
        self.reader_alive.store(true, .release);
        defer {
            self.reader_alive.store(false, .release);
            self.signalClosed();
            self.closeNotificationQueue(false);
        }

        while (true) {
            const line = readJsonRpcLine(self.allocator, &stdout) catch |err| switch (err) {
                error.EndOfStream => return,
                else => {
                    log.warn("stdio json-rpc reader failed: {}", .{err});
                    return;
                },
            };
            if (line.len == 0) {
                self.allocator.free(line);
                continue;
            }
            self.handleIncomingLine(line);
        }
    }

    fn notificationThreadMain(self: *Self) void {
        while (self.dequeueNotificationLine()) |line| {
            self.dispatchNotificationLine(line);
        }
    }

    fn handleIncomingLine(self: *Self, line: []u8) void {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, line, .{}) catch {
            self.allocator.free(line);
            return;
        };
        defer parsed.deinit();

        if (parsed.value != .object) {
            self.allocator.free(line);
            return;
        }
        const obj = parsed.value.object;

        if (obj.get("id")) |id_value| {
            if (id_value == .integer) {
                const response_id: u32 = std.math.cast(u32, id_value.integer) orelse {
                    self.allocator.free(line);
                    return;
                };
                self.requestStateHandleResponse(response_id, line);
                return;
            }
        }

        const method_value = obj.get("method") orelse {
            self.allocator.free(line);
            return;
        };
        const params_value = obj.get("params") orelse {
            self.allocator.free(line);
            return;
        };
        if (method_value != .string) {
            self.allocator.free(line);
            return;
        }
        _ = params_value;

        if (self.notification_handler == null or self.notification_ctx == null) {
            self.allocator.free(line);
            return;
        }

        self.enqueueNotificationLine(line) catch |err| switch (err) {
            error.NotificationQueueClosed => self.allocator.free(line),
            error.NotificationQueueOverflow, error.OutOfMemory => {
                log.warn("stdio json-rpc notification queue failure ({}); closing client", .{err});
                self.allocator.free(line);
                self.signalClosed();
                self.closeNotificationQueue(true);
            },
        };
    }

    fn requestStateHandleResponse(self: *Self, response_id: u32, line: []u8) void {
        self.request_state.mutex.lock();
        defer self.request_state.mutex.unlock();

        if (self.request_state.pending_id == null or self.request_state.pending_id.? != response_id) {
            self.allocator.free(line);
            return;
        }
        if (self.request_state.response_line) |old_line| {
            self.allocator.free(old_line);
        }
        self.request_state.response_line = line;
        self.request_state.pending_id = null;
        self.request_state.cond.signal();
    }

    fn enqueueNotificationLine(self: *Self, line: []u8) !void {
        self.notification_state.mutex.lock();
        defer self.notification_state.mutex.unlock();
        if (self.notification_state.closed) return error.NotificationQueueClosed;
        if (self.notification_state.queue.items.len >= MAX_PENDING_NOTIFICATION_LINES) {
            return error.NotificationQueueOverflow;
        }
        try self.notification_state.queue.append(self.allocator, line);
        self.notification_state.cond.signal();
    }

    fn dequeueNotificationLine(self: *Self) ?[]u8 {
        self.notification_state.mutex.lock();
        defer self.notification_state.mutex.unlock();

        while (self.notification_state.queue.items.len == 0 and !self.notification_state.closed) {
            self.notification_state.cond.wait(&self.notification_state.mutex);
        }
        if (self.notification_state.queue.items.len == 0) return null;

        const line = self.notification_state.queue.items[0];
        const len = self.notification_state.queue.items.len;
        if (len > 1) {
            std.mem.copyForwards([]u8, self.notification_state.queue.items[0 .. len - 1], self.notification_state.queue.items[1..len]);
        }
        self.notification_state.queue.items.len -= 1;
        return line;
    }

    fn dispatchNotificationLine(self: *Self, line: []u8) void {
        defer self.allocator.free(line);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, line, .{}) catch return;
        defer parsed.deinit();

        if (parsed.value != .object) return;
        const obj = parsed.value.object;

        const method_value = obj.get("method") orelse return;
        const params_value = obj.get("params") orelse return;
        if (method_value != .string) return;

        const handler = self.notification_handler orelse return;
        const ctx = self.notification_ctx orelse return;
        handler(ctx, method_value.string, params_value) catch |err| {
            log.warn("notification handler failed for method '{s}': {}", .{ method_value.string, err });
        };
    }

    fn freeQueuedNotificationsLocked(self: *Self) void {
        for (self.notification_state.queue.items) |line| {
            self.allocator.free(line);
        }
    }
};

fn readJsonRpcLine(allocator: std.mem.Allocator, file: *std.fs.File) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    var buf: [1]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) {
            if (out.items.len == 0) return error.EndOfStream;
            break;
        }
        if (buf[0] == '\n') break;
        if (buf[0] == '\r') continue;
        if (out.items.len >= MAX_JSONRPC_LINE_BYTES) return StdioJsonRpc.Error.ResponseTooLarge;
        try out.append(allocator, buf[0]);
    }

    return out.toOwnedSlice(allocator);
}

fn buildJsonRpcRequest(allocator: std.mem.Allocator, request_id: u32, method: []const u8, params_json: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    const writer = buf.writer(allocator);
    try writer.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writer.print("{d}", .{request_id});
    try writer.writeAll(",\"method\":");
    try json_util.appendJsonString(&buf, allocator, method);
    try writer.writeAll(",\"params\":");
    try writer.writeAll(params_json);
    try writer.writeAll("}");

    return buf.toOwnedSlice(allocator);
}

fn remainingRequestTimeoutNs(deadline_ns: i128) u64 {
    const remaining_ns = deadline_ns - std.time.nanoTimestamp();
    if (remaining_ns <= 0) return 0;
    return @intCast(remaining_ns);
}
