const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const root = @import("root.zig");

const Provider = root.Provider;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;
const ChatMessage = root.ChatMessage;

const log = std.log.scoped(.gemini_cli);

/// Provider that delegates to the `gemini` CLI (Google Gemini).
///
/// Implements a Lazy Persistent Singleton:
/// 1. Spawns `gemini --experimental-acp` on first use.
/// 2. Performs a JSON-RPC 2.0 handshake to create a session.
/// 3. Keeps the process alive for subsequent requests.
/// 4. Communicates via JSON-RPC 2.0 over stdio.
pub const GeminiCliProvider = struct {
    allocator: std.mem.Allocator,
    model: []const u8,

    /// Persistent state
    child: ?*std_compat.process.Child = null,
    child_argv: ?[][]const u8 = null,
    mutex: std_compat.sync.Mutex = .{},
    session_id: ?[]const u8 = null,
    next_id: u32 = 1,
    read_buffer: std.ArrayListUnmanaged(u8) = .empty,
    read_offset: usize = 0,

    const DEFAULT_MODEL = "gemini-2.0-flash";
    const CLI_NAME = "gemini";
    const ACP_PROTOCOL_VERSION: u32 = 1;

    pub fn init(allocator: std.mem.Allocator, model: ?[]const u8) !GeminiCliProvider {
        // Just verify CLI is in PATH, don't start it yet.
        try checkCliVersion(allocator, CLI_NAME);
        return .{
            .allocator = allocator,
            .model = model orelse DEFAULT_MODEL,
        };
    }

    /// Create a Provider vtable interface.
    pub fn provider(self: *GeminiCliProvider) Provider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Provider.VTable{
        .chatWithSystem = chatWithSystemImpl,
        .chat = chatImpl,
        .supportsNativeTools = supportsNativeToolsImpl,
        .getName = getNameImpl,
        .deinit = deinitImpl,
        .supports_vision = supportsVisionImpl,
    };

    fn chatWithSystemImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        _: f64,
    ) anyerror![]const u8 {
        const self: *GeminiCliProvider = @ptrCast(@alignCast(ptr));
        const effective_model = if (model.len > 0) model else self.model;

        // Combine system prompt with message
        const prompt = if (system_prompt) |sys|
            try std.fmt.allocPrint(allocator, "{s}\n\n{s}", .{ sys, message })
        else
            try allocator.dupe(u8, message);
        defer allocator.free(prompt);

        return self.sendPrompt(allocator, prompt, effective_model);
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        _: f64,
    ) anyerror!ChatResponse {
        const self: *GeminiCliProvider = @ptrCast(@alignCast(ptr));
        const effective_model = if (model.len > 0) model else self.model;

        const prompt = extractLastUserMessage(request.messages) orelse return error.NoUserMessage;
        const content = try self.sendPrompt(allocator, prompt, effective_model);
        return ChatResponse{ .content = content, .model = try allocator.dupe(u8, effective_model) };
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return false;
    }

    fn supportsVisionImpl(_: *anyopaque) bool {
        return false;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "gemini-cli";
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *GeminiCliProvider = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stopInternal();
        self.read_buffer.deinit(self.allocator);
    }

    fn stopInternal(self: *GeminiCliProvider) void {
        if (self.child) |child| {
            if (child.stdin) |stdin| stdin.close();
            _ = child.kill() catch {};
            _ = child.wait() catch {};
            self.allocator.destroy(child);
            self.child = null;
        }
        self.resetConnectionState();
    }

    fn cleanupStartupFailure(self: *GeminiCliProvider, child: ?*std_compat.process.Child, child_spawned: bool) void {
        if (child) |allocated_child| {
            if (child_spawned) {
                self.child = allocated_child;
                self.stopInternal();
                return;
            }

            self.allocator.destroy(allocated_child);
        }

        self.child = null;
        self.resetConnectionState();
    }

    fn resetConnectionState(self: *GeminiCliProvider) void {
        if (self.child_argv) |argv| {
            for (argv) |arg| self.allocator.free(arg);
            self.allocator.free(argv);
            self.child_argv = null;
        }
        if (self.session_id) |sid| {
            self.allocator.free(sid);
            self.session_id = null;
        }
        self.read_buffer.clearRetainingCapacity();
        self.read_offset = 0;
    }

    /// Ensure the gemini agent process is running and a session is created.
    fn ensureStarted(self: *GeminiCliProvider) !void {
        if (self.child != null and self.session_id != null) return;
        log.debug("starting process...", .{});

        // Clean up any stale state
        self.stopInternal();

        var argv_list: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (argv_list.items) |arg| self.allocator.free(arg);
            argv_list.deinit(self.allocator);
        }
        try argv_list.append(self.allocator, try self.allocator.dupe(u8, CLI_NAME));
        try argv_list.append(self.allocator, try self.allocator.dupe(u8, "--experimental-acp"));
        try argv_list.append(self.allocator, try self.allocator.dupe(u8, "--approval-mode"));
        // NOTE: "yolo" mode is used here to allow the gemini-cli agent to perform
        // its internal tool calls (like reading workspace context) without
        // interactive approval, which is required for non-interactive ACP sessions.
        // Higher-level security is enforced by nullclaw's own tool approval logic.
        try argv_list.append(self.allocator, try self.allocator.dupe(u8, "yolo"));
        self.child_argv = try argv_list.toOwnedSlice(self.allocator);

        var child: ?*std_compat.process.Child = null;
        var child_spawned = false;
        errdefer self.cleanupStartupFailure(child, child_spawned);
        child = try self.allocator.create(std_compat.process.Child);
        child.?.* = std_compat.process.Child.init(self.child_argv.?, self.allocator);
        child.?.stdin_behavior = .Pipe;
        child.?.stdout_behavior = .Pipe;
        child.?.stderr_behavior = .Inherit;

        try child.?.spawn();
        child_spawned = true;
        self.child = child.?;
        const pid: i64 = if (builtin.os.tag == .windows) @intCast(@intFromPtr(self.child.?.id)) else self.child.?.id;
        log.debug("process spawned (pid={d})", .{pid});

        try self.initializeSession();
    }

    fn initializeSession(self: *GeminiCliProvider) !void {
        const init_id = self.next_id;
        self.next_id += 1;

        const init_req = try buildInitializeRequest(self.allocator, init_id);
        defer self.allocator.free(init_req);

        log.debug("sending initialize handshake...", .{});
        try self.sendJsonRpcLine(init_req);

        try self.readInitializeResponse(init_id);

        const cwd = try std_compat.fs.cwd().realpathAlloc(self.allocator, ".");
        defer self.allocator.free(cwd);

        const session_id = self.next_id;
        self.next_id += 1;

        const session_req = try buildSessionNewRequest(self.allocator, session_id, cwd);
        defer self.allocator.free(session_req);

        log.debug("sending session/new handshake...", .{});
        try self.sendJsonRpcLine(session_req);

        self.session_id = try self.readSessionNewResponse(session_id);
        log.debug("handshake complete, sessionId={s}", .{self.session_id.?});
    }

    fn sendJsonRpcLine(self: *GeminiCliProvider, line: []const u8) !void {
        try self.child.?.stdin.?.writeAll(line);
        try self.child.?.stdin.?.writeAll("\n");
    }

    fn readInitializeResponse(self: *GeminiCliProvider, id: u32) !void {
        while (true) {
            const line = try self.readLine(self.allocator);
            defer self.allocator.free(line);

            const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, line, .{}) catch {
                continue;
            };
            defer parsed.deinit();

            if (parsed.value != .object) continue;
            const obj = parsed.value.object;

            if (!responseIdMatches(obj.get("id"), id)) continue;

            const result = obj.get("result") orelse {
                recordJsonRpcError("Gemini ACP initialize", line, obj.get("error"));
                return error.InvalidHandshake;
            };
            if (result != .object) {
                log.err("Gemini ACP initialize failed: result is not an object. Response: {s}", .{line});
                return error.InvalidHandshake;
            }

            const protocol_version = result.object.get("protocolVersion") orelse {
                log.err("Gemini ACP initialize failed: result object missing protocolVersion. Response: {s}", .{line});
                return error.InvalidHandshake;
            };

            switch (protocol_version) {
                .integer, .float => {},
                else => {
                    log.err("Gemini ACP initialize failed: protocolVersion is not numeric. Response: {s}", .{line});
                    return error.InvalidHandshake;
                },
            }

            return;
        }
    }

    fn readSessionNewResponse(self: *GeminiCliProvider, id: u32) ![]const u8 {
        while (true) {
            const line = try self.readLine(self.allocator);
            defer self.allocator.free(line);

            const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, line, .{}) catch {
                continue;
            };
            defer parsed.deinit();

            if (parsed.value != .object) continue;
            const obj = parsed.value.object;

            if (!responseIdMatches(obj.get("id"), id)) continue;

            const result = obj.get("result") orelse {
                recordJsonRpcError("Gemini ACP session/new", line, obj.get("error"));
                return error.InvalidHandshake;
            };
            if (result != .object) {
                log.err("Gemini ACP session/new failed: result is not an object. Response: {s}", .{line});
                return error.InvalidHandshake;
            }
            const sid = result.object.get("sessionId") orelse {
                log.err("Gemini ACP session/new failed: result object missing sessionId. Response: {s}", .{line});
                return error.InvalidHandshake;
            };
            if (sid != .string) {
                log.err("Gemini ACP session/new failed: sessionId is not a string. Response: {s}", .{line});
                return error.InvalidHandshake;
            }

            return try self.allocator.dupe(u8, sid.string);
        }
    }

    fn sendPrompt(self: *GeminiCliProvider, allocator: std.mem.Allocator, prompt: []const u8, model: []const u8) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.ensureStarted();

        const id = self.next_id;
        self.next_id += 1;

        const msg = try std.json.Stringify.valueAlloc(allocator, .{
            .jsonrpc = "2.0",
            .id = id,
            .method = "session/prompt",
            .params = .{
                .sessionId = self.session_id.?,
                .model = model,
                .prompt = &[_]struct { type: []const u8, text: []const u8 }{
                    .{ .type = "text", .text = prompt },
                },
            },
        }, .{});
        defer allocator.free(msg);

        try self.sendJsonRpcLine(msg);

        // Accumulate output
        var result_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer result_buf.deinit(allocator);

        while (true) {
            const line = try self.readLine(self.allocator);
            defer self.allocator.free(line);

            const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch {
                continue;
            };
            defer parsed.deinit();

            if (parsed.value != .object) {
                continue;
            }
            const obj = parsed.value.object;

            // session/update notifications
            if (obj.get("method")) |method| {
                if (method == .string and std.mem.eql(u8, method.string, "session/update")) {
                    const params = if (obj.get("params")) |p| if (p == .object) p.object else continue else continue;
                    const update = if (params.get("update")) |u| if (u == .object) u.object else continue else continue;
                    const content = if (update.get("content")) |c| if (c == .object) c.object else continue else continue;
                    if (content.get("text")) |text_val| {
                        if (text_val == .string) {
                            try result_buf.appendSlice(allocator, text_val.string);
                        }
                    }
                    continue;
                }
            }

            // Final result response
            if (!responseIdMatches(obj.get("id"), id)) continue;

            if (obj.get("result")) |res| {
                if (res == .object) {
                    if (res.object.get("content")) |c| {
                        if (c == .string) {
                            if (c.string.len > 0) {
                                result_buf.clearRetainingCapacity();
                                try result_buf.appendSlice(allocator, c.string);
                            }
                        }
                    }
                }
            } else if (obj.get("error")) |err_val| {
                log.err("Gemini ACP prompt failed with error: {any}", .{err_val});

                // Record detailed error message if available
                if (err_val == .object) {
                    if (lookupErrorMessage(err_val.object)) |err_msg| {
                        root.setLastApiErrorDetail("gemini-cli", err_msg);
                    }
                }

                return error.ApiError;
            }

            break;
        }

        if (result_buf.items.len == 0) return error.NoResultInOutput;
        return try result_buf.toOwnedSlice(allocator);
    }

    fn lookupErrorMessage(obj: std.json.ObjectMap) ?[]const u8 {
        if (obj.get("message")) |value| {
            if (value == .string) return value.string;
        }
        if (obj.get("msg")) |value| {
            if (value == .string) return value.string;
        }
        return null;
    }

    fn readLine(self: *GeminiCliProvider, allocator: std.mem.Allocator) ![]const u8 {
        const stdout = self.child.?.stdout.?;

        while (true) {
            // Check if we already have a full line in the buffer
            const search_slice = self.read_buffer.items[self.read_offset..];
            if (std.mem.indexOfScalar(u8, search_slice, '\n')) |pos| {
                const line_end = self.read_offset + pos;
                const line = try allocator.dupe(u8, self.read_buffer.items[self.read_offset..line_end]);
                errdefer allocator.free(line);

                self.read_offset = line_end + 1;

                // Strip non-JSON prefixes
                const trimmed = std.mem.trim(u8, line, " \t\r");
                if (trimmed.len > 0 and (trimmed[0] == '{' or trimmed[0] == '[')) {
                    return line;
                }
                allocator.free(line);
                continue;
            }

            // No newline found, compact and read more data
            if (self.read_offset > 0) {
                const remaining = self.read_buffer.items.len - self.read_offset;
                std.mem.copyForwards(u8, self.read_buffer.items[0..remaining], self.read_buffer.items[self.read_offset..]);
                self.read_buffer.items.len = remaining;
                self.read_offset = 0;
            }

            // Read more data from stdout
            var buf: [4096]u8 = undefined;
            const amt = try stdout.read(&buf);
            if (amt == 0) return error.EndOfStream;
            try self.read_buffer.appendSlice(self.allocator, buf[0..amt]);
        }
    }

    /// Fetch available model names by running `gemini -p \"/model\" -o stream-json`.
    pub fn fetchModels(allocator: std.mem.Allocator) [][]const u8 {
        if (builtin.is_test) return &.{};
        return fetchModelsInternal(allocator) catch &.{};
    }

    fn fetchModelsInternal(allocator: std.mem.Allocator) ![][]const u8 {
        const argv = &[_][]const u8{
            CLI_NAME,
            "-p",
            "/model",
            "-o",
            "stream-json",
        };

        var child = std_compat.process.Child.init(argv, allocator);
        child.stdin_behavior = .Close;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        try child.spawn();

        const max_output: usize = 64 * 1024;
        const out = child.stdout.?.readToEndAlloc(allocator, max_output) catch |err| {
            _ = child.wait() catch {};
            return err;
        };
        defer allocator.free(out);

        const term = try child.wait();
        switch (term) {
            .exited => |code| {
                if (code == 0) {
                    return try parseModelsJson(allocator, out);
                }
            },
            else => {},
        }

        return error.CliProcessFailed;
    }
};

fn buildInitializeRequest(allocator: std.mem.Allocator, id: u32) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"jsonrpc\":\"2.0\",\"id\":");
    {
        var id_buf: [24]u8 = undefined;
        const id_text = try std.fmt.bufPrint(&id_buf, "{d}", .{id});
        try buf.appendSlice(allocator, id_text);
    }
    try buf.appendSlice(allocator, ",\"method\":\"initialize\",\"params\":{\"protocolVersion\":");
    {
        var protocol_buf: [24]u8 = undefined;
        const protocol_text = try std.fmt.bufPrint(&protocol_buf, "{d}", .{GeminiCliProvider.ACP_PROTOCOL_VERSION});
        try buf.appendSlice(allocator, protocol_text);
    }
    try buf.appendSlice(allocator, ",\"clientCapabilities\":{}}}");
    return buf.toOwnedSlice(allocator);
}

fn buildSessionNewRequest(allocator: std.mem.Allocator, id: u32, cwd: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"jsonrpc\":\"2.0\",\"id\":");
    {
        var id_buf: [24]u8 = undefined;
        const id_text = try std.fmt.bufPrint(&id_buf, "{d}", .{id});
        try buf.appendSlice(allocator, id_text);
    }
    try buf.appendSlice(allocator, ",\"method\":\"session/new\",\"params\":{\"cwd\":");
    try root.appendJsonString(&buf, allocator, cwd);
    try buf.appendSlice(allocator, ",\"mcpServers\":[]}}");
    return buf.toOwnedSlice(allocator);
}

fn responseIdMatches(resp_id: ?std.json.Value, id: u32) bool {
    const value = resp_id orelse return false;
    return switch (value) {
        .integer => |vid| vid >= 0 and vid <= std.math.maxInt(u32) and @as(u32, @intCast(vid)) == id,
        .float => |vid| floatResponseIdMatches(vid, id),
        .string => |vid| blk: {
            const parsed = std.fmt.parseUnsigned(u32, vid, 10) catch break :blk false;
            break :blk parsed == id;
        },
        else => false,
    };
}

fn floatResponseIdMatches(resp_id: f64, id: u32) bool {
    if (!std.math.isFinite(resp_id)) return false;
    if (resp_id < 0) return false;
    if (resp_id > @as(f64, @floatFromInt(std.math.maxInt(u32)))) return false;
    if (@floor(resp_id) != resp_id) return false;
    return @as(u32, @intFromFloat(resp_id)) == id;
}

fn recordJsonRpcError(prefix: []const u8, line: []const u8, err_val: ?std.json.Value) void {
    if (err_val) |err_obj| {
        // Tests assert detail propagation on this path; skip stderr side effects
        // there because Zig treats unexpected test logs as failures.
        if (!builtin.is_test) {
            log.err("{s} failed with error: {any}", .{ prefix, err_obj });
        }
        if (err_obj == .object) {
            if (GeminiCliProvider.lookupErrorMessage(err_obj.object)) |message| {
                root.setLastApiErrorDetail("gemini-cli", message);
            }
        }
    } else {
        if (!builtin.is_test) {
            log.err("{s} failed: no result or error field. Response: {s}", .{ prefix, line });
        }
    }
}

fn parseModelsJson(allocator: std.mem.Allocator, out: []const u8) ![][]const u8 {
    // Extract tokens that look like Gemini model IDs ("gemini-*").
    var models: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (models.items) |m| allocator.free(m);
        models.deinit(allocator);
    }

    var line_iter = std.mem.splitScalar(u8, out, '\n');
    while (line_iter.next()) |line| {
        if (line.len == 0) continue;
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch continue;
        defer parsed.deinit();
        if (parsed.value != .object) continue;
        const obj = parsed.value.object;
        const type_val = obj.get("type") orelse continue;
        if (type_val != .string) continue;

        var text: ?[]const u8 = null;
        if (std.mem.eql(u8, type_val.string, "message") or
            std.mem.eql(u8, type_val.string, "output") or
            std.mem.eql(u8, type_val.string, "content"))
        {
            if (obj.get("content")) |c| if (c == .string) {
                text = c.string;
            };
        }
        if (text) |t| {
            var token_iter = std.mem.tokenizeScalar(u8, t, ' ');
            while (token_iter.next()) |tok| {
                const clean = std.mem.trim(u8, tok, " \t\r,;:");
                if (clean.len > "gemini-".len and std.mem.startsWith(u8, clean, "gemini-")) {
                    try models.append(allocator, try allocator.dupe(u8, clean));
                }
            }
        }
    }

    return models.toOwnedSlice(allocator);
}

/// Run `<cli> --version` and verify exit code 0.
fn checkCliVersion(allocator: std.mem.Allocator, cli_name: []const u8) !void {
    const argv = [_][]const u8{ cli_name, "--version" };
    var child = std_compat.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Close;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return error.CliNotFound;
    const out = child.stdout.?.readToEndAlloc(allocator, 4096) catch {
        _ = child.wait() catch {};
        return error.CliNotFound;
    };
    allocator.free(out);
    const term = child.wait() catch return error.CliNotFound;
    switch (term) {
        .exited => |code| {
            if (code == 0) return;
        },
        else => {},
    }
    return error.CliNotFound;
}

fn extractLastUserMessage(messages: []const ChatMessage) ?[]const u8 {
    var i = messages.len;
    while (i > 0) {
        i -= 1;
        if (messages[i].role == .user) return messages[i].content;
    }
    return null;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "GeminiCliProvider.getNameImpl returns gemini-cli" {
    const vt = GeminiCliProvider.vtable;
    var dummy: u8 = 0;
    try std.testing.expectEqualStrings("gemini-cli", vt.getName(@ptrCast(&dummy)));
}

test "GeminiCliProvider vtable has correct function pointers" {
    const vt = GeminiCliProvider.vtable;
    var dummy: u8 = 0;
    try std.testing.expectEqualStrings("gemini-cli", vt.getName(@ptrCast(&dummy)));
    try std.testing.expect(!vt.supportsNativeTools(@ptrCast(&dummy)));
    try std.testing.expect(vt.supports_vision != null);
    try std.testing.expect(!vt.supports_vision.?(@ptrCast(&dummy)));
}

test "GeminiCliProvider supportsNativeTools returns false" {
    const vt = GeminiCliProvider.vtable;
    var dummy: u8 = 0;
    try std.testing.expect(!vt.supportsNativeTools(@ptrCast(&dummy)));
}

test "extractLastUserMessage finds last user" {
    const msgs = [_]ChatMessage{
        ChatMessage.system("Be helpful"),
        ChatMessage.user("first"),
        ChatMessage.assistant("ok"),
        ChatMessage.user("second"),
    };
    const result = extractLastUserMessage(&msgs);
    try std.testing.expectEqualStrings("second", result.?);
}

test "extractLastUserMessage returns null for no user" {
    const msgs = [_]ChatMessage{
        ChatMessage.system("Be helpful"),
        ChatMessage.assistant("ok"),
    };
    try std.testing.expect(extractLastUserMessage(&msgs) == null);
}

test "extractLastUserMessage empty messages" {
    const msgs = [_]ChatMessage{};
    try std.testing.expect(extractLastUserMessage(&msgs) == null);
}

test "GeminiCliProvider.lookupErrorMessage handles message and msg fields" {
    const message_body = "{\"message\":\"request failed\"}";
    const parsed_message = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, message_body, .{});
    defer parsed_message.deinit();
    try std.testing.expectEqualStrings("request failed", GeminiCliProvider.lookupErrorMessage(parsed_message.value.object).?);

    const msg_body = "{\"msg\":\"request failed\"}";
    const parsed_msg = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, msg_body, .{});
    defer parsed_msg.deinit();
    try std.testing.expectEqualStrings("request failed", GeminiCliProvider.lookupErrorMessage(parsed_msg.value.object).?);
}

test "recordJsonRpcError stores message and msg detail" {
    root.clearLastApiErrorDetail();
    defer root.clearLastApiErrorDetail();

    const message_body = "{\"error\":{\"message\":\"request failed\"}}";
    const parsed_message = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, message_body, .{});
    defer parsed_message.deinit();

    recordJsonRpcError("Gemini ACP initialize", message_body, parsed_message.value.object.get("error"));

    const message_snapshot = (try root.snapshotLastApiErrorDetail(std.testing.allocator)).?;
    defer std.testing.allocator.free(message_snapshot);
    try std.testing.expectEqualStrings("gemini-cli: request failed", message_snapshot);

    root.clearLastApiErrorDetail();

    const msg_body = "{\"error\":{\"msg\":\"handshake failed\"}}";
    const parsed_msg = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, msg_body, .{});
    defer parsed_msg.deinit();

    recordJsonRpcError("Gemini ACP initialize", msg_body, parsed_msg.value.object.get("error"));

    const msg_snapshot = (try root.snapshotLastApiErrorDetail(std.testing.allocator)).?;
    defer std.testing.allocator.free(msg_snapshot);
    try std.testing.expectEqualStrings("gemini-cli: handshake failed", msg_snapshot);
}

test "checkCliVersion returns CliNotFound for missing binary" {
    const result = checkCliVersion(std.testing.allocator, "nonexistent_binary_xyzzy_gemini_99999");
    try std.testing.expectError(error.CliNotFound, result);
}

test "buildInitializeRequest uses numeric protocolVersion" {
    const req = try buildInitializeRequest(std.testing.allocator, 7);
    defer std.testing.allocator.free(req);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, req, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqual(@as(i64, 7), obj.get("id").?.integer);
    try std.testing.expectEqualStrings("initialize", obj.get("method").?.string);

    const params = obj.get("params").?.object;
    try std.testing.expect(params.get("protocolVersion").? == .integer);
    try std.testing.expectEqual(@as(i64, GeminiCliProvider.ACP_PROTOCOL_VERSION), params.get("protocolVersion").?.integer);
    try std.testing.expect(params.get("clientCapabilities").? == .object);
}

test "buildSessionNewRequest includes cwd and mcpServers" {
    const req = try buildSessionNewRequest(std.testing.allocator, 9, "/tmp/workspace");
    defer std.testing.allocator.free(req);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, req, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqual(@as(i64, 9), obj.get("id").?.integer);
    try std.testing.expectEqualStrings("session/new", obj.get("method").?.string);

    const params = obj.get("params").?.object;
    try std.testing.expectEqualStrings("/tmp/workspace", params.get("cwd").?.string);
    try std.testing.expect(params.get("mcpServers").? == .array);
    try std.testing.expectEqual(@as(usize, 0), params.get("mcpServers").?.array.items.len);
}

test "responseIdMatches handles integer ids" {
    try std.testing.expect(responseIdMatches(.{ .integer = 42 }, 42));
    try std.testing.expect(!responseIdMatches(.{ .integer = 41 }, 42));
    try std.testing.expect(!responseIdMatches(null, 42));
}

test "responseIdMatches accepts numeric float and string ids" {
    try std.testing.expect(responseIdMatches(.{ .float = 42.0 }, 42));
    try std.testing.expect(!responseIdMatches(.{ .float = 42.5 }, 42));
    try std.testing.expect(responseIdMatches(.{ .string = "42" }, 42));
    try std.testing.expect(!responseIdMatches(.{ .string = "forty-two" }, 42));
}

test "cleanupStartupFailure clears provider state" {
    var provider = GeminiCliProvider{
        .allocator = std.testing.allocator,
        .model = GeminiCliProvider.DEFAULT_MODEL,
    };
    defer provider.read_buffer.deinit(std.testing.allocator);

    provider.child_argv = try std.testing.allocator.alloc([]const u8, 2);
    provider.child_argv.?[0] = try std.testing.allocator.dupe(u8, "gemini");
    provider.child_argv.?[1] = try std.testing.allocator.dupe(u8, "--experimental-acp");
    provider.session_id = try std.testing.allocator.dupe(u8, "session-123");
    try provider.read_buffer.appendSlice(std.testing.allocator, "partial");
    provider.read_offset = 3;

    const child = try std.testing.allocator.create(std_compat.process.Child);
    child.* = std_compat.process.Child.init(provider.child_argv.?, std.testing.allocator);
    provider.child = child;

    // Regression: handshake failures in ensureStarted() must not leave provider
    // state pointing at a freed child or stale argv/session data.
    provider.cleanupStartupFailure(child, false);

    try std.testing.expect(provider.child == null);
    try std.testing.expect(provider.child_argv == null);
    try std.testing.expect(provider.session_id == null);
    try std.testing.expectEqual(@as(usize, 0), provider.read_buffer.items.len);
    try std.testing.expectEqual(@as(usize, 0), provider.read_offset);
}

test "cleanupStartupFailure clears provider state before child allocation" {
    var provider = GeminiCliProvider{
        .allocator = std.testing.allocator,
        .model = GeminiCliProvider.DEFAULT_MODEL,
    };
    defer provider.read_buffer.deinit(std.testing.allocator);

    provider.child_argv = try std.testing.allocator.alloc([]const u8, 2);
    provider.child_argv.?[0] = try std.testing.allocator.dupe(u8, "gemini");
    provider.child_argv.?[1] = try std.testing.allocator.dupe(u8, "--experimental-acp");
    provider.session_id = try std.testing.allocator.dupe(u8, "session-123");
    try provider.read_buffer.appendSlice(std.testing.allocator, "partial");
    provider.read_offset = 3;

    // Regression: allocation failures after taking ownership of child_argv but
    // before creating the Child must still release all startup state.
    provider.cleanupStartupFailure(null, false);

    try std.testing.expect(provider.child == null);
    try std.testing.expect(provider.child_argv == null);
    try std.testing.expect(provider.session_id == null);
    try std.testing.expectEqual(@as(usize, 0), provider.read_buffer.items.len);
    try std.testing.expectEqual(@as(usize, 0), provider.read_offset);
}
