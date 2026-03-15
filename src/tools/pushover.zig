const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const fs_compat = @import("../fs_compat.zig");
const urlEncode = @import("web_search_providers/common.zig").urlEncode;
const http_util = @import("../http_util.zig");

const PUSHOVER_API_URL = "https://api.pushover.net/1/messages.json";

/// Pushover push notification tool.
/// Sends notifications via the Pushover API. Requires PUSHOVER_TOKEN and
/// PUSHOVER_USER_KEY in the workspace .env file.
pub const PushoverTool = struct {
    workspace_dir: []const u8,

    pub const tool_name = "pushover";
    pub const tool_description = "Send a push notification via Pushover. Requires PUSHOVER_TOKEN and PUSHOVER_USER_KEY in .env file.";
    pub const tool_params =
        \\{"type":"object","properties":{"message":{"type":"string","description":"The notification message"},"title":{"type":"string","description":"Optional title"},"priority":{"type":"integer","description":"Priority -2..2 (default 0)"},"sound":{"type":"string","description":"Optional sound name"}},"required":["message"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *PushoverTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *PushoverTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const message = root.getString(args, "message") orelse
            return ToolResult.fail("Missing required 'message' parameter");

        if (message.len == 0)
            return ToolResult.fail("Missing required 'message' parameter");

        const title = root.getString(args, "title");
        const sound = root.getString(args, "sound");

        // Validate priority if provided
        const priority = root.getInt(args, "priority");
        if (priority) |p| {
            if (p < -2 or p > 2) {
                return ToolResult.fail("Invalid 'priority': expected integer in range -2..=2");
            }
        }

        // Load credentials from .env
        const creds = getCredentials(self, allocator) catch
            return ToolResult.fail("Failed to load Pushover credentials from .env file");
        defer allocator.free(creds.token);
        defer allocator.free(creds.user_key);

        // Build form body with percent-encoded values
        var body_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer body_buf.deinit(allocator);

        // Base fields (token and user_key are hex strings — safe to append raw)
        try body_buf.appendSlice(allocator, "token=");
        try body_buf.appendSlice(allocator, creds.token);
        try body_buf.appendSlice(allocator, "&user=");
        try body_buf.appendSlice(allocator, creds.user_key);

        const encoded_message = try urlEncode(allocator, message);
        defer allocator.free(encoded_message);
        try body_buf.appendSlice(allocator, "&message=");
        try body_buf.appendSlice(allocator, encoded_message);

        if (title) |t| {
            const encoded_title = try urlEncode(allocator, t);
            defer allocator.free(encoded_title);
            try body_buf.appendSlice(allocator, "&title=");
            try body_buf.appendSlice(allocator, encoded_title);
        }

        if (priority) |p| {
            const pstr = try std.fmt.allocPrint(allocator, "&priority={d}", .{p});
            defer allocator.free(pstr);
            try body_buf.appendSlice(allocator, pstr);
        }

        if (sound) |s| {
            const encoded_sound = try urlEncode(allocator, s);
            defer allocator.free(encoded_sound);
            try body_buf.appendSlice(allocator, "&sound=");
            try body_buf.appendSlice(allocator, encoded_sound);
        }

        // Send via http_util form POST (pipes body via stdin to avoid argv length limits).
        // Skipped in tests to avoid real network calls (AGENTS.md §3.6).
        if (builtin.is_test) return ToolResult.ok("Notification sent successfully");
        const response = http_util.curlPostForm(allocator, PUSHOVER_API_URL, body_buf.items) catch
            return ToolResult.fail("Failed to send Pushover request via curl");
        defer allocator.free(response);

        // Check for {"status":1} in response
        if (std.mem.indexOf(u8, response, "\"status\":1") != null) {
            return ToolResult.ok("Notification sent successfully");
        }

        // API error
        return ToolResult.fail("Pushover API returned an error");
    }

    /// Parse a raw .env value: strip whitespace, quotes, export prefix, inline comments.
    fn parseEnvValue(raw: []const u8) []const u8 {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0) return trimmed;

        // Strip surrounding quotes
        const unquoted = if (trimmed.len >= 2 and
            ((trimmed[0] == '"' and trimmed[trimmed.len - 1] == '"') or
                (trimmed[0] == '\'' and trimmed[trimmed.len - 1] == '\'')))
            trimmed[1 .. trimmed.len - 1]
        else
            trimmed;

        // Strip inline comment (unquoted only): "value # comment"
        if (std.mem.indexOf(u8, unquoted, " #")) |pos| {
            return std.mem.trim(u8, unquoted[0..pos], " \t");
        }

        return std.mem.trim(u8, unquoted, " \t");
    }

    fn getCredentials(self: *const PushoverTool, allocator: std.mem.Allocator) !struct { token: []const u8, user_key: []const u8 } {
        // Build path to .env
        const env_path = try std.fmt.allocPrint(allocator, "{s}/.env", .{self.workspace_dir});
        defer allocator.free(env_path);

        const content = fs_compat.readFileAlloc(std.fs.cwd(), allocator, env_path, 1_048_576) catch
            return error.EnvFileNotFound;
        defer allocator.free(content);

        var token: ?[]u8 = null;
        var user_key: ?[]u8 = null;
        // Free any partially allocated values on error exit
        errdefer if (token) |t| allocator.free(t);
        errdefer if (user_key) |u| allocator.free(u);

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |raw_line| {
            var line = std.mem.trim(u8, raw_line, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;

            // Strip "export " prefix
            if (std.mem.startsWith(u8, line, "export ")) {
                line = std.mem.trim(u8, line["export ".len..], " \t");
            }

            if (std.mem.indexOf(u8, line, "=")) |eq_pos| {
                const key = std.mem.trim(u8, line[0..eq_pos], " \t");
                const value = parseEnvValue(line[eq_pos + 1 ..]);

                if (std.mem.eql(u8, key, "PUSHOVER_TOKEN")) {
                    // Null before free so errdefer does not double-free on OOM in dupe.
                    const old = token;
                    token = null;
                    if (old) |o| allocator.free(o);
                    token = try allocator.dupe(u8, value);
                } else if (std.mem.eql(u8, key, "PUSHOVER_USER_KEY")) {
                    const old = user_key;
                    user_key = null;
                    if (old) |o| allocator.free(o);
                    user_key = try allocator.dupe(u8, value);
                }
            }
        }

        const t = token orelse return error.MissingPushoverToken;
        const u = user_key orelse return error.MissingPushoverUserKey;

        return .{ .token = t, .user_key = u };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "pushover tool name" {
    var pt = PushoverTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    try std.testing.expectEqualStrings("pushover", t.name());
}

test "pushover schema has message required" {
    var pt = PushoverTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "\"message\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "\"required\"") != null);
}

test "pushover execute missing message" {
    var pt = PushoverTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "message") != null);
}

test "pushover execute empty message" {
    var pt = PushoverTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{\"message\": \"\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "message") != null);
}

test "pushover priority -3 rejected" {
    var pt = PushoverTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{\"message\": \"hello\", \"priority\": -3}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "priority") != null or
        std.mem.indexOf(u8, result.error_msg.?, "-2..=2") != null);
}

test "pushover priority 5 rejected" {
    var pt = PushoverTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{\"message\": \"hello\", \"priority\": 5}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "priority") != null or
        std.mem.indexOf(u8, result.error_msg.?, "-2..=2") != null);
}

test "pushover priority 2 accepted (credential error expected)" {
    var pt = PushoverTool{ .workspace_dir = "/tmp/nonexistent_pushover_test_dir" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{\"message\": \"hello\", \"priority\": 2}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    // Should fail on credentials, not on priority validation
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "priority") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "credential") != null);
}

test "pushover priority -2 accepted (credential error expected)" {
    var pt = PushoverTool{ .workspace_dir = "/tmp/nonexistent_pushover_test_dir" };
    const t = pt.tool();
    const parsed = try root.parseTestArgs("{\"message\": \"hello\", \"priority\": -2}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "priority") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "credential") != null);
}

test "parseEnvValue strips export prefix" {
    // parseEnvValue doesn't strip export itself — that's done in getCredentials.
    // But it does strip quotes and inline comments.
    // For this test, we test what parseEnvValue does with the value portion.
    const result = PushoverTool.parseEnvValue("  myvalue  ");
    try std.testing.expectEqualStrings("myvalue", result);
}

test "parseEnvValue strips quotes" {
    const dq = PushoverTool.parseEnvValue("\"quotedvalue\"");
    try std.testing.expectEqualStrings("quotedvalue", dq);
    const sq = PushoverTool.parseEnvValue("'singlequoted'");
    try std.testing.expectEqualStrings("singlequoted", sq);
}

test "parseEnvValue strips inline comment" {
    const result = PushoverTool.parseEnvValue("myvalue # this is a comment");
    try std.testing.expectEqualStrings("myvalue", result);
}

test "pushover schema has priority and sound" {
    var pt = PushoverTool{ .workspace_dir = "/tmp" };
    const t = pt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "priority") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "sound") != null);
}

test "getCredentials reads token and user_key from .env file" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = ".env", .data = 
        \\PUSHOVER_TOKEN=test-token-abc
        \\PUSHOVER_USER_KEY=test-user-key-xyz
    });

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs_path = try tmp_dir.dir.realpath(".", &path_buf);

    var pt = PushoverTool{ .workspace_dir = abs_path };
    const creds = try pt.getCredentials(std.testing.allocator);
    defer std.testing.allocator.free(creds.token);
    defer std.testing.allocator.free(creds.user_key);

    try std.testing.expectEqualStrings("test-token-abc", creds.token);
    try std.testing.expectEqualStrings("test-user-key-xyz", creds.user_key);
}

test "getCredentials reads exported and quoted values" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = ".env", .data = 
        \\export PUSHOVER_TOKEN="quoted-token"
        \\export PUSHOVER_USER_KEY='single-quoted-key'
    });

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs_path = try tmp_dir.dir.realpath(".", &path_buf);

    var pt = PushoverTool{ .workspace_dir = abs_path };
    const creds = try pt.getCredentials(std.testing.allocator);
    defer std.testing.allocator.free(creds.token);
    defer std.testing.allocator.free(creds.user_key);

    try std.testing.expectEqualStrings("quoted-token", creds.token);
    try std.testing.expectEqualStrings("single-quoted-key", creds.user_key);
}

test "getCredentials missing token returns error" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = ".env", .data = "PUSHOVER_USER_KEY=only-user-key\n" });

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs_path = try tmp_dir.dir.realpath(".", &path_buf);

    var pt = PushoverTool{ .workspace_dir = abs_path };
    const result = pt.getCredentials(std.testing.allocator);
    try std.testing.expectError(error.MissingPushoverToken, result);
}

test "getCredentials missing user_key returns error" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.writeFile(.{ .sub_path = ".env", .data = "PUSHOVER_TOKEN=only-token\n" });

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs_path = try tmp_dir.dir.realpath(".", &path_buf);

    var pt = PushoverTool{ .workspace_dir = abs_path };
    const result = pt.getCredentials(std.testing.allocator);
    try std.testing.expectError(error.MissingPushoverUserKey, result);
}

test "getCredentials missing .env returns error" {
    var pt = PushoverTool{ .workspace_dir = "/tmp/nonexistent_pushover_test_dir_xyz" };
    const result = pt.getCredentials(std.testing.allocator);
    try std.testing.expectError(error.EnvFileNotFound, result);
}
