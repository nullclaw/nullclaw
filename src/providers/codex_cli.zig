const std = @import("std");
const std_compat = @import("compat");
const platform = @import("../platform.zig");
const codex_support = @import("../codex_support.zig");
const root = @import("root.zig");

const Provider = root.Provider;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;
const ChatMessage = root.ChatMessage;

/// Provider that delegates to the local `codex` CLI.
///
/// Runs `codex exec` non-interactively and reads the final assistant message
/// from the `--output-last-message` file.
pub const CodexCliProvider = struct {
    allocator: std.mem.Allocator,
    model: []const u8,

    pub const DEFAULT_MODEL = codex_support.DEFAULT_CODEX_MODEL;
    const TIMEOUT_NS: u64 = 120 * std.time.ns_per_s;

    pub fn init(allocator: std.mem.Allocator, model: ?[]const u8) !CodexCliProvider {
        try checkCliAvailable(allocator);
        return .{
            .allocator = allocator,
            .model = model orelse DEFAULT_MODEL,
        };
    }

    /// Create a Provider vtable interface.
    pub fn provider(self: *CodexCliProvider) Provider {
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
        const self: *CodexCliProvider = @ptrCast(@alignCast(ptr));
        const prompt = if (system_prompt) |sys|
            try std.fmt.allocPrint(allocator, "{s}\n\n{s}", .{ sys, message })
        else
            try allocator.dupe(u8, message);
        defer allocator.free(prompt);

        return runCodex(allocator, effectiveModel(model, self.model), prompt);
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        _: f64,
    ) anyerror!ChatResponse {
        const self: *CodexCliProvider = @ptrCast(@alignCast(ptr));
        const prompt = extractLastUserMessage(request.messages) orelse return error.NoUserMessage;
        const resolved_model = effectiveModel(model, self.model);
        const content = try runCodex(allocator, resolved_model, prompt);
        return ChatResponse{ .content = content, .model = try allocator.dupe(u8, resolved_model) };
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return false;
    }

    fn supportsVisionImpl(_: *anyopaque) bool {
        return false;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "codex-cli";
    }

    fn deinitImpl(_: *anyopaque) void {}

    /// Run `codex exec` and return the final assistant message as plain text.
    fn runCodex(allocator: std.mem.Allocator, model: []const u8, prompt: []const u8) ![]const u8 {
        const cli_path = codex_support.resolveCodexCommand(allocator) orelse return error.CliNotFound;
        defer allocator.free(cli_path);

        const output_path = try makeOutputPath(allocator);
        defer {
            std_compat.fs.deleteFileAbsolute(output_path) catch {};
            allocator.free(output_path);
        }

        const argv = [_][]const u8{
            cli_path,
            "exec",
            "--skip-git-repo-check",
            "--color",
            "never",
            "-m",
            model,
            "-o",
            output_path,
            prompt,
        };

        var child = std_compat.process.Child.init(&argv, allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;

        try child.spawn();

        const term = try child.wait();
        switch (term) {
            .exited => |code| {
                if (code != 0) {
                    return error.CliProcessFailed;
                }
            },
            else => {
                return error.CliProcessFailed;
            },
        }

        const file = try std_compat.fs.openFileAbsolute(output_path, .{});
        defer file.close();

        const max_output: usize = 4 * 1024 * 1024;
        const stdout_result = try file.readToEndAlloc(allocator, max_output);

        // Trim trailing whitespace
        const trimmed = std_compat.mem.trimRight(u8, stdout_result, " \t\r\n");
        if (trimmed.len == stdout_result.len) {
            return stdout_result;
        }
        const duped = try allocator.dupe(u8, trimmed);
        allocator.free(stdout_result);
        return duped;
    }

    /// Health check: run `codex --version` and verify exit code 0.
    fn healthCheck(allocator: std.mem.Allocator) !void {
        try checkCliVersion(allocator);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Shared helpers
// ════════════════════════════════════════════════════════════════════════════

/// Resolve the codex CLI and ensure it exists.
fn checkCliAvailable(allocator: std.mem.Allocator) !void {
    const cli_path = codex_support.resolveCodexCommand(allocator) orelse return error.CliNotFound;
    allocator.free(cli_path);
}

/// Run `codex --version` and verify exit code 0.
fn checkCliVersion(allocator: std.mem.Allocator) !void {
    const cli_path = codex_support.resolveCodexCommand(allocator) orelse return error.CliNotFound;
    defer allocator.free(cli_path);

    const argv = [_][]const u8{ cli_path, "--version" };
    var child = std_compat.process.Child.init(&argv, allocator);
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

    return CodexCliProvider.DEFAULT_MODEL;
}

fn makeOutputPath(allocator: std.mem.Allocator) ![]u8 {
    const tmp_dir = try platform.getTempDir(allocator);
    defer allocator.free(tmp_dir);

    const filename = try std.fmt.allocPrint(allocator, "nullclaw_codex_{d}_{x}.txt", .{
        std_compat.time.milliTimestamp(),
        std_compat.crypto.random.int(u64),
    });
    defer allocator.free(filename);

    return std_compat.fs.path.join(allocator, &.{ tmp_dir, filename });
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

test "CodexCliProvider.getNameImpl returns codex-cli" {
    const vtable = CodexCliProvider.vtable;
    var dummy: u8 = 0;
    try std.testing.expectEqualStrings("codex-cli", vtable.getName(@ptrCast(&dummy)));
}

test "CodexCliProvider vtable has correct function pointers" {
    const vtable = CodexCliProvider.vtable;
    var dummy: u8 = 0;
    try std.testing.expectEqualStrings("codex-cli", vtable.getName(@ptrCast(&dummy)));
    try std.testing.expect(!vtable.supportsNativeTools(@ptrCast(&dummy)));
    try std.testing.expect(vtable.supports_vision != null);
    try std.testing.expect(!vtable.supports_vision.?(@ptrCast(&dummy)));
}

test "CodexCliProvider supportsNativeTools returns false" {
    const vtable = CodexCliProvider.vtable;
    var dummy: u8 = 0;
    try std.testing.expect(!vtable.supportsNativeTools(@ptrCast(&dummy)));
}

test "effectiveModel prefers explicit override" {
    try std.testing.expectEqualStrings("gpt-5.2-codex", effectiveModel("gpt-5.2-codex", "gpt-5.4"));
}

test "effectiveModel falls back to configured model" {
    try std.testing.expectEqualStrings("gpt-5.4", effectiveModel("", "gpt-5.4"));
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

test "CodexCliProvider default model is gpt-5.4" {
    try std.testing.expectEqualStrings(codex_support.DEFAULT_CODEX_MODEL, CodexCliProvider.DEFAULT_MODEL);
}
