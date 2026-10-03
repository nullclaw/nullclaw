const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const build_options = @import("build_options");

const PROTOCOL_VERSION: i64 = 1;
const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_CHILD_OUTPUT: usize = 4 * 1024 * 1024;

const Options = struct {
    provider: ?[]const u8 = null,
    model: ?[]const u8 = null,
    temperature: ?[]const u8 = null,
    agent_name: ?[]const u8 = null,
    skill_name: ?[]const u8 = null,
};

const ParseOptionsResult = union(enum) {
    serve: Options,
    help,
    version,
};

const Session = struct {
    id: []const u8,
    cwd: []const u8,

    fn deinit(self: Session, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.cwd);
    }
};

const EmptyObject = struct {};

const Server = struct {
    allocator: std.mem.Allocator,
    options: Options,
    sessions: std.StringHashMap(Session),
    next_session: u64 = 1,
    initialized: bool = false,

    fn init(allocator: std.mem.Allocator, options: Options) Server {
        return .{
            .allocator = allocator,
            .options = options,
            .sessions = std.StringHashMap(Session).init(allocator),
        };
    }

    fn deinit(self: *Server) void {
        var it = self.sessions.valueIterator();
        while (it.next()) |session| session.deinit(self.allocator);
        self.sessions.deinit();
    }

    fn handleLine(self: *Server, out: anytype, raw_line: []const u8) !void {
        const line = std.mem.trim(u8, raw_line, " \t\r\n");
        if (line.len == 0) return;

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, line, .{}) catch {
            try writeErrorNull(self.allocator, out, -32700, "Parse error");
            return;
        };
        defer parsed.deinit();

        const root = switch (parsed.value) {
            .object => |object| object,
            else => {
                try writeErrorNull(self.allocator, out, -32600, "Invalid request");
                return;
            },
        };

        const id = root.get("id");
        const jsonrpc = getStringField(root, "jsonrpc") orelse {
            if (id) |request_id| try writeError(self.allocator, out, request_id, -32600, "Missing jsonrpc");
            return;
        };
        if (!std.mem.eql(u8, jsonrpc, "2.0")) {
            if (id) |request_id| try writeError(self.allocator, out, request_id, -32600, "Invalid jsonrpc");
            return;
        }

        const method = getStringField(root, "method") orelse {
            if (id) |request_id| try writeError(self.allocator, out, request_id, -32600, "Missing method");
            return;
        };
        const params = root.get("params");

        if (std.mem.eql(u8, method, "initialize")) {
            if (id) |request_id| try self.handleInitialize(out, request_id, params);
            return;
        }

        if (!self.initialized) {
            if (id) |request_id| try writeError(self.allocator, out, request_id, -32002, "Connection not initialized");
            return;
        }

        if (std.mem.eql(u8, method, "session/new")) {
            if (id) |request_id| try self.handleSessionNew(out, request_id, params);
            return;
        }
        if (std.mem.eql(u8, method, "session/prompt")) {
            if (id) |request_id| try self.handleSessionPrompt(out, request_id, params);
            return;
        }
        if (std.mem.eql(u8, method, "session/cancel")) {
            if (id) |request_id| try writeResult(self.allocator, out, request_id, @as(?[]const u8, null));
            return;
        }

        if (id) |request_id| try writeError(self.allocator, out, request_id, -32601, "Method not found");
    }

    fn handleInitialize(self: *Server, out: anytype, id: std.json.Value, params: ?std.json.Value) !void {
        _ = readProtocolVersion(params) catch |err| switch (err) {
            error.MissingProtocolVersion => {
                try writeError(self.allocator, out, id, -32602, "Missing protocolVersion");
                return;
            },
            error.InvalidProtocolVersion => {
                try writeError(self.allocator, out, id, -32602, "Invalid protocolVersion");
                return;
            },
        };

        self.initialized = true;
        const result = .{
            .protocolVersion = PROTOCOL_VERSION,
            .agentCapabilities = .{
                .loadSession = false,
                .promptCapabilities = .{
                    .image = false,
                    .audio = false,
                    .embeddedContext = true,
                },
                .mcpCapabilities = .{
                    .http = false,
                    .sse = false,
                },
                .sessionCapabilities = EmptyObject{},
            },
            .agentInfo = .{
                .name = "nullclaw",
                .title = "NullClaw ACP",
                .version = build_options.version,
            },
            .authMethods = [_][]const u8{},
        };
        try writeResult(self.allocator, out, id, result);
    }

    fn handleSessionNew(self: *Server, out: anytype, id: std.json.Value, params: ?std.json.Value) !void {
        const cwd = readNewSessionCwd(params) catch |err| switch (err) {
            error.MissingParams => {
                try writeError(self.allocator, out, id, -32602, "Missing params");
                return;
            },
            error.InvalidParams => {
                try writeError(self.allocator, out, id, -32602, "Invalid params");
                return;
            },
            error.MissingCwd => {
                try writeError(self.allocator, out, id, -32602, "Missing cwd");
                return;
            },
            error.RelativeCwd => {
                try writeError(self.allocator, out, id, -32602, "cwd must be absolute");
                return;
            },
        };

        const session_id = try std.fmt.allocPrint(self.allocator, "acp-{d}", .{self.next_session});
        self.next_session += 1;

        const owned_cwd = self.allocator.dupe(u8, cwd) catch |err| {
            self.allocator.free(session_id);
            return err;
        };
        const session = Session{ .id = session_id, .cwd = owned_cwd };
        self.sessions.put(session_id, session) catch |err| {
            session.deinit(self.allocator);
            return err;
        };

        try writeResult(self.allocator, out, id, .{ .sessionId = session_id });
    }

    fn handleSessionPrompt(self: *Server, out: anytype, id: std.json.Value, params: ?std.json.Value) !void {
        const params_obj = switch (params orelse {
            try writeError(self.allocator, out, id, -32602, "Missing params");
            return;
        }) {
            .object => |object| object,
            else => {
                try writeError(self.allocator, out, id, -32602, "Invalid params");
                return;
            },
        };

        const session_id = getStringField(params_obj, "sessionId") orelse {
            try writeError(self.allocator, out, id, -32602, "Missing sessionId");
            return;
        };
        const session = self.sessions.get(session_id) orelse {
            try writeError(self.allocator, out, id, -32602, "Unknown sessionId");
            return;
        };
        const prompt_value = params_obj.get("prompt") orelse {
            try writeError(self.allocator, out, id, -32602, "Missing prompt");
            return;
        };
        const prompt = promptToText(self.allocator, prompt_value) catch |err| switch (err) {
            error.InvalidPromptPayload => {
                try writeError(self.allocator, out, id, -32602, "Invalid prompt");
                return;
            },
            else => return err,
        };
        defer self.allocator.free(prompt);

        try self.sendPlan(out, session_id);
        try self.sendToolCall(out, session_id, "nullclaw-agent-invoke", "Run nullclaw agent turn", "pending");
        try self.sendToolCallUpdate(out, session_id, "nullclaw-agent-invoke", "in_progress", "Running `nullclaw agent invoke --json`");

        const invoked = invokeNullclaw(self.allocator, self.options, session, prompt) catch |err| {
            const msg = try std.fmt.allocPrint(self.allocator, "nullclaw invocation failed: {s}", .{@errorName(err)});
            defer self.allocator.free(msg);
            try self.sendToolCallUpdate(out, session_id, "nullclaw-agent-invoke", "failed", msg);
            try self.sendAgentText(out, session_id, msg);
            try writeResult(self.allocator, out, id, .{ .stopReason = "refusal" });
            return;
        };
        defer invoked.deinit(self.allocator);

        if (invoked.ok) {
            try self.sendToolCallUpdate(out, session_id, "nullclaw-agent-invoke", "completed", "nullclaw turn completed");
            try self.sendAgentText(out, session_id, invoked.response);
            try writeResult(self.allocator, out, id, .{ .stopReason = "end_turn" });
        } else {
            try self.sendToolCallUpdate(out, session_id, "nullclaw-agent-invoke", "failed", invoked.response);
            try self.sendAgentText(out, session_id, invoked.response);
            try writeResult(self.allocator, out, id, .{ .stopReason = "refusal" });
        }
    }

    fn sendPlan(self: *Server, out: anytype, session_id: []const u8) !void {
        try writeNotification(self.allocator, out, .{
            .jsonrpc = "2.0",
            .method = "session/update",
            .params = .{
                .sessionId = session_id,
                .update = .{
                    .sessionUpdate = "plan",
                    .entries = .{
                        .{ .content = "Translate ACP prompt into a nullclaw turn", .priority = "high", .status = "completed" },
                        .{ .content = "Invoke the local nullclaw runtime", .priority = "high", .status = "in_progress" },
                        .{ .content = "Return the response through ACP updates", .priority = "medium", .status = "pending" },
                    },
                },
            },
        });
    }

    fn sendToolCall(self: *Server, out: anytype, session_id: []const u8, tool_call_id: []const u8, title: []const u8, status: []const u8) !void {
        try writeNotification(self.allocator, out, .{
            .jsonrpc = "2.0",
            .method = "session/update",
            .params = .{
                .sessionId = session_id,
                .update = .{
                    .sessionUpdate = "tool_call",
                    .toolCallId = tool_call_id,
                    .title = title,
                    .kind = "execute",
                    .status = status,
                },
            },
        });
    }

    fn sendToolCallUpdate(self: *Server, out: anytype, session_id: []const u8, tool_call_id: []const u8, status: []const u8, text: []const u8) !void {
        try writeNotification(self.allocator, out, .{
            .jsonrpc = "2.0",
            .method = "session/update",
            .params = .{
                .sessionId = session_id,
                .update = .{
                    .sessionUpdate = "tool_call_update",
                    .toolCallId = tool_call_id,
                    .status = status,
                    .content = .{
                        .{
                            .type = "content",
                            .content = .{ .type = "text", .text = text },
                        },
                    },
                },
            },
        });
    }

    fn sendAgentText(self: *Server, out: anytype, session_id: []const u8, text: []const u8) !void {
        try writeNotification(self.allocator, out, .{
            .jsonrpc = "2.0",
            .method = "session/update",
            .params = .{
                .sessionId = session_id,
                .update = .{
                    .sessionUpdate = "agent_message_chunk",
                    .content = .{
                        .type = "text",
                        .text = text,
                    },
                },
            },
        });
    }
};

const InvokeResult = struct {
    ok: bool,
    response: []const u8,
    stdout: []const u8,
    stderr: []const u8,

    fn deinit(self: InvokeResult, allocator: std.mem.Allocator) void {
        allocator.free(self.response);
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const parsed_options = parseOptions(args) catch |err| {
        try printOptionError(err);
        std_compat.process.exit(1);
    };

    switch (parsed_options) {
        .help => {
            try printUsage(std_compat.fs.File.stdout());
            return;
        },
        .version => {
            try printVersion(std_compat.fs.File.stdout());
            return;
        },
        .serve => |options| {
            var server = Server.init(allocator, options);
            defer server.deinit();
            try serveStdio(allocator, &server);
        },
    }
}

fn serveStdio(allocator: std.mem.Allocator, server: *Server) !void {
    var out_buffer: [64 * 1024]u8 = undefined;
    var stdout = std_compat.fs.File.stdout().writerStreaming(&out_buffer);
    const out = &stdout.interface;

    var pending: std.ArrayListUnmanaged(u8) = .empty;
    defer pending.deinit(allocator);

    var read_buffer: [16 * 1024]u8 = undefined;
    const stdin = std_compat.fs.File.stdin();
    while (true) {
        const n = try stdin.read(&read_buffer);
        if (n == 0) break;

        if (pending.items.len > MAX_LINE_BYTES or n > MAX_LINE_BYTES - pending.items.len) return error.RequestTooLarge;
        try pending.appendSlice(allocator, read_buffer[0..n]);

        var start: usize = 0;
        while (std.mem.indexOfScalar(u8, pending.items[start..], '\n')) |relative_pos| {
            const pos = start + relative_pos;
            try server.handleLine(out, pending.items[start..pos]);
            start = pos + 1;
        }
        if (start > 0) {
            const remaining = pending.items[start..];
            std.mem.copyForwards(u8, pending.items[0..remaining.len], remaining);
            pending.items.len = remaining.len;
        }
    }

    if (std.mem.trim(u8, pending.items, " \t\r\n").len > 0) {
        try server.handleLine(out, pending.items);
    }

    try out.flush();
}

fn parseOptions(args: []const []const u8) !ParseOptionsResult {
    var options = Options{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--provider")) {
            i += 1;
            if (i >= args.len) return error.MissingProvider;
            options.provider = args[i];
        } else if (std.mem.eql(u8, arg, "--model")) {
            i += 1;
            if (i >= args.len) return error.MissingModel;
            options.model = args[i];
        } else if (std.mem.eql(u8, arg, "--temperature")) {
            i += 1;
            if (i >= args.len) return error.MissingTemperature;
            options.temperature = args[i];
        } else if (std.mem.eql(u8, arg, "--agent")) {
            i += 1;
            if (i >= args.len) return error.MissingAgent;
            options.agent_name = args[i];
        } else if (std.mem.eql(u8, arg, "--skill")) {
            i += 1;
            if (i >= args.len) return error.MissingSkill;
            options.skill_name = args[i];
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return .help;
        } else if (std.mem.eql(u8, arg, "--version")) {
            return .version;
        } else {
            return error.UnknownOption;
        }
    }
    return .{ .serve = options };
}

fn printOptionError(err: anyerror) !void {
    var buffer: [512]u8 = undefined;
    var writer = std_compat.fs.File.stderr().writerStreaming(&buffer);
    const message = switch (err) {
        error.MissingProvider => "Missing value for --provider",
        error.MissingModel => "Missing value for --model",
        error.MissingTemperature => "Missing value for --temperature",
        error.MissingAgent => "Missing value for --agent",
        error.MissingSkill => "Missing value for --skill",
        error.UnknownOption => "Unknown option for nullclaw acp",
        else => @errorName(err),
    };
    try writer.interface.print("{s}\n\n", .{message});
    try writer.interface.flush();
    try printUsage(std_compat.fs.File.stderr());
}

fn printUsage(file: std_compat.fs.File) !void {
    var buffer: [2048]u8 = undefined;
    var writer = file.writerStreaming(&buffer);
    try writer.interface.writeAll(
        \\Usage: nullclaw acp [--provider PROVIDER] [--model MODEL] [--temperature TEMP] [--agent NAME] [--skill NAME]
        \\
        \\Runs an Agent Client Protocol server over newline-delimited JSON-RPC on stdio.
        \\Editors can launch this command as their local ACP agent.
        \\
    );
    try writer.interface.flush();
}

fn printVersion(file: std_compat.fs.File) !void {
    var buffer: [256]u8 = undefined;
    var writer = file.writerStreaming(&buffer);
    try writer.interface.print("nullclaw acp {s}\n", .{build_options.version});
    try writer.interface.flush();
}

fn invokeNullclaw(
    allocator: std.mem.Allocator,
    options: Options,
    session: Session,
    prompt: []const u8,
) !InvokeResult {
    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer argv.deinit(allocator);

    const exe_path = try std_compat.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe_path);

    try argv.append(allocator, exe_path);
    try argv.append(allocator, "agent");
    try argv.append(allocator, "invoke");
    try argv.append(allocator, "--message");
    try argv.append(allocator, prompt);
    try argv.append(allocator, "--session");
    try argv.append(allocator, session.id);
    try argv.append(allocator, "--workspace");
    try argv.append(allocator, session.cwd);
    if (options.provider) |provider| {
        try argv.append(allocator, "--provider");
        try argv.append(allocator, provider);
    }
    if (options.model) |model| {
        try argv.append(allocator, "--model");
        try argv.append(allocator, model);
    }
    if (options.temperature) |temperature| {
        try argv.append(allocator, "--temperature");
        try argv.append(allocator, temperature);
    }
    if (options.agent_name) |agent_name| {
        try argv.append(allocator, "--agent");
        try argv.append(allocator, agent_name);
    }
    if (options.skill_name) |skill_name| {
        try argv.append(allocator, "--skill");
        try argv.append(allocator, skill_name);
    }
    try argv.append(allocator, "--json");

    const result = try std_compat.process.Child.run(.{
        .allocator = allocator,
        .argv = argv.items,
        .cwd = session.cwd,
        .max_output_bytes = MAX_CHILD_OUTPUT,
    });
    errdefer allocator.free(result.stdout);
    errdefer allocator.free(result.stderr);

    const ok = switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
    const response = if (ok)
        try parseNullclawResponse(allocator, result.stdout)
    else
        try childFailureText(allocator, result.stderr, result.stdout);

    return .{
        .ok = ok,
        .response = response,
        .stdout = result.stdout,
        .stderr = result.stderr,
    };
}

fn parseNullclawResponse(allocator: std.mem.Allocator, stdout: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, stdout, " \t\r\n");
    if (trimmed.len == 0) return try allocator.dupe(u8, "");

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch {
        return try allocator.dupe(u8, trimmed);
    };
    defer parsed.deinit();

    const object = switch (parsed.value) {
        .object => |object| object,
        else => return try allocator.dupe(u8, trimmed),
    };
    if (getStringField(object, "response")) |response| return try allocator.dupe(u8, response);
    return try allocator.dupe(u8, trimmed);
}

fn childFailureText(allocator: std.mem.Allocator, stderr: []const u8, stdout: []const u8) ![]const u8 {
    const err_text = std.mem.trim(u8, stderr, " \t\r\n");
    if (err_text.len > 0) return try allocator.dupe(u8, err_text);
    const out_text = std.mem.trim(u8, stdout, " \t\r\n");
    if (out_text.len > 0) return try allocator.dupe(u8, out_text);
    return try allocator.dupe(u8, "nullclaw exited without output");
}

fn promptToText(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    switch (value) {
        .array => |array| {
            for (array.items, 0..) |item, index| {
                if (index > 0) try out.appendSlice(allocator, "\n\n");
                try appendContentBlock(allocator, &out, item);
            }
        },
        else => return error.InvalidPromptPayload,
    }

    return try out.toOwnedSlice(allocator);
}

fn readProtocolVersion(params: ?std.json.Value) !i64 {
    const value = params orelse return error.MissingProtocolVersion;
    const object = switch (value) {
        .object => |object| object,
        else => return error.InvalidProtocolVersion,
    };
    const version = object.get("protocolVersion") orelse return error.MissingProtocolVersion;
    return switch (version) {
        .integer => |number| number,
        else => error.InvalidProtocolVersion,
    };
}

fn readNewSessionCwd(params: ?std.json.Value) ![]const u8 {
    const value = params orelse return error.MissingParams;
    const object = switch (value) {
        .object => |object| object,
        else => return error.InvalidParams,
    };
    const cwd = getStringField(object, "cwd") orelse return error.MissingCwd;
    if (!std_compat.fs.path.isAbsolute(cwd)) return error.RelativeCwd;
    return cwd;
}

fn appendContentBlock(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), item: std.json.Value) !void {
    const object = switch (item) {
        .object => |object| object,
        else => return error.InvalidPromptPayload,
    };
    const kind = getStringField(object, "type") orelse return error.InvalidPromptPayload;

    if (std.mem.eql(u8, kind, "text")) {
        const text = getStringField(object, "text") orelse return error.InvalidPromptPayload;
        try out.appendSlice(allocator, text);
        return;
    }

    if (std.mem.eql(u8, kind, "resource")) {
        const resource = object.get("resource") orelse return error.InvalidPromptPayload;
        const resource_object = switch (resource) {
            .object => |nested| nested,
            else => return error.InvalidPromptPayload,
        };
        const uri = getStringField(resource_object, "uri") orelse return error.InvalidPromptPayload;
        try out.print(allocator, "Context from {s}:\n", .{uri});
        if (getStringField(resource_object, "text")) |text| {
            try out.appendSlice(allocator, text);
        } else {
            try out.appendSlice(allocator, "(binary or unsupported resource content omitted)");
        }
        return;
    }

    if (std.mem.eql(u8, kind, "resource_link")) {
        const uri = getStringField(object, "uri") orelse return error.InvalidPromptPayload;
        try out.print(allocator, "Resource link: {s}", .{uri});
        return;
    }

    try out.print(allocator, "Unsupported ACP content block: {s}", .{kind});
}

fn getStringField(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .string => |text| text,
        else => null,
    };
}

fn writeResult(allocator: std.mem.Allocator, out: anytype, id: std.json.Value, result: anytype) !void {
    const body = try std.json.Stringify.valueAlloc(allocator, .{
        .jsonrpc = "2.0",
        .id = id,
        .result = result,
    }, .{});
    defer allocator.free(body);
    try out.writeAll(body);
    try out.writeAll("\n");
    try out.flush();
}

fn writeNotification(allocator: std.mem.Allocator, out: anytype, value: anytype) !void {
    const body = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(body);
    try out.writeAll(body);
    try out.writeAll("\n");
    try out.flush();
}

fn writeError(allocator: std.mem.Allocator, out: anytype, id: std.json.Value, code: i64, message: []const u8) !void {
    const body = try std.json.Stringify.valueAlloc(allocator, .{
        .jsonrpc = "2.0",
        .id = id,
        .@"error" = .{
            .code = code,
            .message = message,
        },
    }, .{});
    defer allocator.free(body);
    try out.writeAll(body);
    try out.writeAll("\n");
    try out.flush();
}

fn writeErrorNull(allocator: std.mem.Allocator, out: anytype, code: i64, message: []const u8) !void {
    const body = try std.json.Stringify.valueAlloc(allocator, .{
        .jsonrpc = "2.0",
        .id = @as(?[]const u8, null),
        .@"error" = .{
            .code = code,
            .message = message,
        },
    }, .{});
    defer allocator.free(body);
    try out.writeAll(body);
    try out.writeAll("\n");
    try out.flush();
}

test "parseOptions accepts ACP forwarding flags" {
    const parsed = try parseOptions(&.{ "--provider", "openai", "--model", "gpt-x", "--temperature", "0.2", "--agent", "coder", "--skill", "review" });
    const options = switch (parsed) {
        .serve => |value| value,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqualStrings("openai", options.provider.?);
    try std.testing.expectEqualStrings("gpt-x", options.model.?);
    try std.testing.expectEqualStrings("0.2", options.temperature.?);
    try std.testing.expectEqualStrings("coder", options.agent_name.?);
    try std.testing.expectEqualStrings("review", options.skill_name.?);
}

test "handleLine rejects requests before initialize" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator, .{});
    defer server.deinit();

    const out = try handleLineForTest(
        allocator,
        &server,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"session/prompt\",\"params\":{}}\n",
    );
    defer allocator.free(out);

    try std.testing.expect(std.mem.indexOf(u8, out, "\"id\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"code\":-32002") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Connection not initialized") != null);
}

test "handleLine initializes and creates session with absolute cwd" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator, .{});
    defer server.deinit();

    const cwd = if (builtin.os.tag == .windows) "C:\\tmp\\project" else "/tmp/project";
    const session_req = try std.json.Stringify.valueAlloc(allocator, .{
        .jsonrpc = "2.0",
        .id = 2,
        .method = "session/new",
        .params = .{ .cwd = cwd },
    }, .{});
    defer allocator.free(session_req);

    const initialized = try handleLineForTest(
        allocator,
        &server,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":1}}\n",
    );
    defer allocator.free(initialized);
    const session_out = try handleLineForTest(allocator, &server, session_req);
    defer allocator.free(session_out);

    try std.testing.expect(server.initialized);
    try std.testing.expectEqual(@as(usize, 1), server.sessions.count());
    try std.testing.expect(std.mem.indexOf(u8, initialized, "\"protocolVersion\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, session_out, "\"sessionId\":\"acp-1\"") != null);
    const stored = server.sessions.get("acp-1").?;
    try std.testing.expectEqualStrings(cwd, stored.cwd);
}

test "promptToText extracts text and embedded resources" {
    const allocator = std.testing.allocator;
    const json =
        \\[
        \\  {"type":"text","text":"Review this"},
        \\  {"type":"resource","resource":{"uri":"file:///tmp/a.zig","text":"const x = 1;"}},
        \\  {"type":"resource_link","uri":"file:///tmp/b.zig"}
        \\]
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    const text = try promptToText(allocator, parsed.value);
    defer allocator.free(text);

    try std.testing.expect(std.mem.indexOf(u8, text, "Review this") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "file:///tmp/a.zig") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "const x = 1;") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "file:///tmp/b.zig") != null);
}

fn handleLineForTest(allocator: std.mem.Allocator, server: *Server, line: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    var out_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &out);
    defer out_writer.deinit();

    try server.handleLine(&out_writer.writer, line);
    out = out_writer.toArrayList();
    return out.toOwnedSlice(allocator);
}

test "parseNullclawResponse extracts response field" {
    const allocator = std.testing.allocator;
    const text = try parseNullclawResponse(allocator, "{\"session\":\"s\",\"response\":\"hello\",\"turn_count\":1}\n");
    defer allocator.free(text);
    try std.testing.expectEqualStrings("hello", text);
}

test "promptToText rejects non-array prompt payloads" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"type\":\"text\",\"text\":\"hello\"}", .{});
    defer parsed.deinit();

    try std.testing.expectError(error.InvalidPromptPayload, promptToText(allocator, parsed.value));
}

test "readProtocolVersion reads initialize params" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"protocolVersion\":1}", .{});
    defer parsed.deinit();

    try std.testing.expectEqual(@as(i64, 1), try readProtocolVersion(parsed.value));
}

test "readProtocolVersion rejects missing or invalid initialize params" {
    const allocator = std.testing.allocator;
    var missing = try std.json.parseFromSlice(std.json.Value, allocator, "{}", .{});
    defer missing.deinit();
    var invalid = try std.json.parseFromSlice(std.json.Value, allocator, "{\"protocolVersion\":\"1\"}", .{});
    defer invalid.deinit();

    try std.testing.expectError(error.MissingProtocolVersion, readProtocolVersion(missing.value));
    try std.testing.expectError(error.InvalidProtocolVersion, readProtocolVersion(invalid.value));
}

test "readNewSessionCwd requires absolute cwd" {
    const allocator = std.testing.allocator;
    const cwd = if (builtin.os.tag == .windows) "C:\\tmp\\project" else "/tmp/project";
    const valid_json = try std.json.Stringify.valueAlloc(allocator, .{ .cwd = cwd }, .{});
    defer allocator.free(valid_json);

    var valid = try std.json.parseFromSlice(std.json.Value, allocator, valid_json, .{});
    defer valid.deinit();
    var relative = try std.json.parseFromSlice(std.json.Value, allocator, "{\"cwd\":\".\"}", .{});
    defer relative.deinit();
    var missing = try std.json.parseFromSlice(std.json.Value, allocator, "{}", .{});
    defer missing.deinit();

    try std.testing.expectEqualStrings(cwd, try readNewSessionCwd(valid.value));
    try std.testing.expectError(error.RelativeCwd, readNewSessionCwd(relative.value));
    try std.testing.expectError(error.MissingCwd, readNewSessionCwd(missing.value));
}

test "promptToText rejects malformed content blocks" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, "[{\"type\":\"text\"}]", .{});
    defer parsed.deinit();

    try std.testing.expectError(error.InvalidPromptPayload, promptToText(allocator, parsed.value));
}
