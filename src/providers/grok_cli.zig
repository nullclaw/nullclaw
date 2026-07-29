const std = @import("std");
const std_compat = @import("compat");
const root = @import("root.zig");

const Provider = root.Provider;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;
const ChatMessage = root.ChatMessage;

/// Provider that delegates to the local `grok` CLI (xAI Grok).
///
/// Runs `grok -p <prompt>` non-interactively and captures the response
/// from stdout. Uses `--single` mode for single-turn completions.
pub const GrokCliProvider = struct {
    allocator: std.mem.Allocator,
    model: []const u8,

    pub const DEFAULT_MODEL = "grok-4.5";
    const CLI_NAME = "grok";

    pub fn init(allocator: std.mem.Allocator, model: ?[]const u8) !GrokCliProvider {
        try checkCliVersion(allocator);
        return .{
            .allocator = allocator,
            .model = model orelse DEFAULT_MODEL,
        };
    }

    /// Create a Provider vtable interface.
    pub fn provider(self: *GrokCliProvider) Provider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Provider.VTable{
        .chatWithSystem = chatWithSystemImpl,
        .chat = chatImpl,
        .supportsNativeTools = supportsNativeToolsImpl,
        .supports_vision = supportsVisionImpl,
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
        const self: *GrokCliProvider = @ptrCast(@alignCast(ptr));
        const prompt = if (system_prompt) |sys|
            try std.fmt.allocPrint(allocator, "{s}\n\n{s}", .{ sys, message })
        else
            try allocator.dupe(u8, message);
        defer allocator.free(prompt);

        return runGrok(allocator, effectiveModel(model, self.model), prompt);
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        _: f64,
    ) anyerror!ChatResponse {
        const self: *GrokCliProvider = @ptrCast(@alignCast(ptr));
        const prompt = extractLastUserMessage(request.messages) orelse return error.NoUserMessage;
        const resolved_model = effectiveModel(model, self.model);
        const content = try runGrok(allocator, resolved_model, prompt);
        return ChatResponse{ .content = content, .model = try allocator.dupe(u8, resolved_model) };
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return false;
    }

    fn supportsVisionImpl(_: *anyopaque) bool {
        return false;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "grok-cli";
    }

    fn deinitImpl(_: *anyopaque) void {}

    /// Run `grok -p <prompt>` in single-turn mode and return the response.
    fn runGrok(allocator: std.mem.Allocator, model: []const u8, prompt: []const u8) ![]const u8 {
        const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

        const argv = [_][]const u8{
            CLI_NAME,
            "-p",
            prompt,
            "--model",
            model,
            "--output-format",
            "plain",
            "--no-subagents",
            "--no-plan",
            "--verbatim",
        };

        var child = std_compat.process.Child.init(&argv, allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        try child.spawn();

        const stdout_result = try child.stdout.?.readToEndAlloc(allocator, MAX_OUTPUT_BYTES);
        defer allocator.free(stdout_result);

        const stderr_result = child.stderr.?.readToEndAlloc(allocator, 4096) catch null;

        const term = try child.wait();
        switch (term) {
            .exited => |code| {
                if (code != 0) {
                    if (stderr_result) |s| {
                        std.log.err("runGrok: {s} exited with code {}, stderr: \"{s}\"", .{ CLI_NAME, code, std.mem.trim(u8, s, " \t\r\n") });
                        allocator.free(s);
                    } else {
                        std.log.err("runGrok: {s} exited with code {}, no stderr", .{ CLI_NAME, code });
                    }
                    std.log.err("runGrok: stdout was: \"{s}\"", .{std.mem.trim(u8, stdout_result, " \t\r\n")});
                    return error.CliProcessFailed;
                }
                if (stderr_result) |s| allocator.free(s);
            },
            else => {
                if (stderr_result) |s| allocator.free(s);
                std.log.err("runGrok: {s} terminated abnormally", .{CLI_NAME});
                return error.CliProcessFailed;
            },
        }

        // Trim trailing whitespace
        const trimmed = std_compat.mem.trimRight(u8, stdout_result, " \t\r\n");
        if (trimmed.len == stdout_result.len) {
            return stdout_result;
        }
        const duped = try allocator.dupe(u8, trimmed);
        allocator.free(stdout_result);
        return duped;
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Shared helpers
// ════════════════════════════════════════════════════════════════════════════

/// Run `grok --version` and verify exit code 0.
fn checkCliVersion(allocator: std.mem.Allocator) !void {
    const argv = [_][]const u8{ GrokCliProvider.CLI_NAME, "--version" };
    var child = std_compat.process.Child.init(&argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    const out = child.stdout.?.readToEndAlloc(allocator, 4096) catch {
        _ = child.wait() catch {};
        return error.CliNotFound;
    };
    allocator.free(out);
    const term = try child.wait();
    switch (term) {
        .exited => |code| {
            if (code != 0) return error.CliNotFound;
        },
        else => return error.CliNotFound,
    }
}

fn effectiveModel(requested_model: []const u8, configured_model: []const u8) []const u8 {
    const requested = std.mem.trim(u8, requested_model, " \t\r\n");
    if (requested.len > 0) return requested;

    const configured = std.mem.trim(u8, configured_model, " \t\r\n");
    if (configured.len > 0) return configured;

    return GrokCliProvider.DEFAULT_MODEL;
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

test "GrokCliProvider getNameImpl returns grok-cli" {
    const vtable = GrokCliProvider.vtable;
    var dummy: u8 = 0;
    try std.testing.expectEqualStrings("grok-cli", vtable.getName(@ptrCast(&dummy)));
}

test "GrokCliProvider vtable has correct function pointers" {
    const vtable = GrokCliProvider.vtable;
    var dummy: u8 = 0;
    try std.testing.expectEqualStrings("grok-cli", vtable.getName(@ptrCast(&dummy)));
    try std.testing.expect(!vtable.supportsNativeTools(@ptrCast(&dummy)));
    try std.testing.expect(vtable.supports_vision != null);
    try std.testing.expect(!vtable.supports_vision.?(@ptrCast(&dummy)));
}

test "GrokCliProvider supportsNativeTools returns false" {
    const vtable = GrokCliProvider.vtable;
    var dummy: u8 = 0;
    try std.testing.expect(!vtable.supportsNativeTools(@ptrCast(&dummy)));
}

test "effectiveModel prefers explicit override" {
    try std.testing.expectEqualStrings("grok-4", effectiveModel("grok-4", "grok-4.5"));
}

test "effectiveModel falls back to configured model" {
    try std.testing.expectEqualStrings("grok-4.5", effectiveModel("", "grok-4.5"));
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

test "GrokCliProvider default model is grok-4.5" {
    try std.testing.expectEqualStrings("grok-4.5", GrokCliProvider.DEFAULT_MODEL);
}
