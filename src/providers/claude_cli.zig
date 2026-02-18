const std = @import("std");
const root = @import("root.zig");

const Provider = root.Provider;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;
const ChatMessage = root.ChatMessage;

/// Provider that delegates to the `claude` CLI (Claude Code).
///
/// Runs `claude -p <prompt> --output-format stream-json --model <model>`
/// and parses the stream-json output for a `type: "result"` event.
pub const ClaudeCliProvider = struct {
    allocator: std.mem.Allocator,
    model: []const u8,

    const DEFAULT_MODEL = "claude-opus-4-6";
    const CLI_NAME = "claude";
    const TIMEOUT_NS: u64 = 120 * std.time.ns_per_s;

    pub fn init(allocator: std.mem.Allocator, model: ?[]const u8) !ClaudeCliProvider {
        // Verify CLI is in PATH
        try checkCliAvailable(allocator, CLI_NAME);
        return .{
            .allocator = allocator,
            .model = model orelse DEFAULT_MODEL,
        };
    }

    /// Create a Provider vtable interface.
    pub fn provider(self: *ClaudeCliProvider) Provider {
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
    };

    fn chatWithSystemImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        _: f64,
    ) anyerror![]const u8 {
        const self: *ClaudeCliProvider = @ptrCast(@alignCast(ptr));
        const effective_model = if (model.len > 0) model else self.model;

        // Combine system prompt with message if provided
        const prompt = if (system_prompt) |sys|
            try std.fmt.allocPrint(allocator, "{s}\n\n{s}", .{ sys, message })
        else
            try allocator.dupe(u8, message);
        defer allocator.free(prompt);

        return runClaude(allocator, prompt, effective_model);
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        _: f64,
    ) anyerror!ChatResponse {
        const self: *ClaudeCliProvider = @ptrCast(@alignCast(ptr));
        const effective_model = if (model.len > 0) model else self.model;

        // Extract last user message as prompt
        const prompt = extractLastUserMessage(request.messages) orelse return error.NoUserMessage;
        const content = try runClaude(allocator, prompt, effective_model);
        return ChatResponse{ .content = content, .model = try allocator.dupe(u8, effective_model) };
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return false;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "claude-cli";
    }

    fn deinitImpl(_: *anyopaque) void {}

    /// Run the claude CLI and parse stream-json output.
    fn runClaude(allocator: std.mem.Allocator, prompt: []const u8, model: []const u8) ![]const u8 {
        const argv = [_][]const u8{
            CLI_NAME,
            "-p",
            prompt,
            "--output-format",
            "stream-json",
            "--model",
            model,
        };

        var child = std.process.Child.init(&argv, allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        try child.spawn();

        // Read all stdout
        const max_output: usize = 4 * 1024 * 1024; // 4 MB
        const stdout_result = child.stdout.?.readToEndAlloc(allocator, max_output) catch |err| {
            _ = child.wait() catch {};
            return err;
        };
        defer allocator.free(stdout_result);

        const term = try child.wait();
        switch (term) {
            .Exited => |code| {
                if (code != 0) return error.CliProcessFailed;
            },
            else => return error.CliProcessFailed,
        }

        // Parse stream-json: each line is a JSON object, find type="result"
        return parseStreamJson(allocator, stdout_result);
    }

    /// Parse claude stream-json output lines for a result event.
    fn parseStreamJson(allocator: std.mem.Allocator, output: []const u8) ![]const u8 {
        var lines = std.mem.splitScalar(u8, output, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;

            const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch continue;
            defer parsed.deinit();

            if (parsed.value != .object) continue;
            const obj = parsed.value.object;

            // Look for type: "result"
            if (obj.get("type")) |type_val| {
                if (type_val == .string and std.mem.eql(u8, type_val.string, "result")) {
                    if (obj.get("result")) |result_val| {
                        if (result_val == .string) {
                            return try allocator.dupe(u8, result_val.string);
                        }
                    }
                }
            }
        }
        return error.NoResultInOutput;
    }

    /// Health check: run `claude --version` and verify exit code 0.
    pub fn healthCheck(allocator: std.mem.Allocator) !void {
        try checkCliVersion(allocator, CLI_NAME);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Shared helpers
// ════════════════════════════════════════════════════════════════════════════

/// Check if a CLI tool is available in PATH using `which`.
fn checkCliAvailable(allocator: std.mem.Allocator, cli_name: []const u8) !void {
    const argv = [_][]const u8{ "which", cli_name };
    var child = std.process.Child.init(&argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    const out = child.stdout.?.readToEndAlloc(allocator, 4096) catch {
        _ = child.wait() catch {};
        return error.CliNotFound;
    };
    allocator.free(out);
    const term = try child.wait();
    switch (term) {
        .Exited => |code| {
            if (code != 0) return error.CliNotFound;
        },
        else => return error.CliNotFound,
    }
}

/// Run `<cli> --version` and verify exit code 0.
fn checkCliVersion(allocator: std.mem.Allocator, cli_name: []const u8) !void {
    const argv = [_][]const u8{ cli_name, "--version" };
    var child = std.process.Child.init(&argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    const out = child.stdout.?.readToEndAlloc(allocator, 4096) catch {
        _ = child.wait() catch {};
        return error.CliNotFound;
    };
    allocator.free(out);
    const term = try child.wait();
    switch (term) {
        .Exited => |code| {
            if (code != 0) return error.CliNotFound;
        },
        else => return error.CliNotFound,
    }
}

/// Extract the content of the last user message from a message slice.
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

test "ClaudeCliProvider.getNameImpl returns claude-cli" {
    const vtable = ClaudeCliProvider.vtable;
    var dummy: u8 = 0;
    try std.testing.expectEqualStrings("claude-cli", vtable.getName(@ptrCast(&dummy)));
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

test "parseStreamJson extracts result" {
    const input =
        \\{"type":"start","session_id":"abc123"}
        \\{"type":"content","content":"partial"}
        \\{"type":"result","result":"Hello from Claude CLI!"}
    ;
    const result = try ClaudeCliProvider.parseStreamJson(std.testing.allocator, input);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("Hello from Claude CLI!", result);
}

test "parseStreamJson no result returns error" {
    const input =
        \\{"type":"start","session_id":"abc123"}
        \\{"type":"content","content":"partial"}
    ;
    const result = ClaudeCliProvider.parseStreamJson(std.testing.allocator, input);
    try std.testing.expectError(error.NoResultInOutput, result);
}

test "parseStreamJson handles empty input" {
    const result = ClaudeCliProvider.parseStreamJson(std.testing.allocator, "");
    try std.testing.expectError(error.NoResultInOutput, result);
}

test "parseStreamJson handles invalid json lines gracefully" {
    const input =
        \\not json at all
        \\{"type":"result","result":"found it"}
    ;
    const result = try ClaudeCliProvider.parseStreamJson(std.testing.allocator, input);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("found it", result);
}

test "parseStreamJson skips result with non-string value" {
    const input =
        \\{"type":"result","result":42}
    ;
    const result = ClaudeCliProvider.parseStreamJson(std.testing.allocator, input);
    try std.testing.expectError(error.NoResultInOutput, result);
}

test "ClaudeCliProvider vtable has correct function pointers" {
    const vtable = ClaudeCliProvider.vtable;
    var dummy: u8 = 0;
    try std.testing.expectEqualStrings("claude-cli", vtable.getName(@ptrCast(&dummy)));
    try std.testing.expect(!vtable.supportsNativeTools(@ptrCast(&dummy)));
}

test "ClaudeCliProvider.init returns CliNotFound for missing binary" {
    const result = checkCliAvailable(std.testing.allocator, "nonexistent_binary_xyzzy_12345");
    try std.testing.expectError(error.CliNotFound, result);
}

test "ClaudeCliProvider default model is claude-opus-4-6" {
    try std.testing.expectEqualStrings("claude-opus-4-6", ClaudeCliProvider.DEFAULT_MODEL);
}
