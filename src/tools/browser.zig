const std = @import("std");
const builtin = @import("builtin");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;

/// Maximum response body size for the "read" action (8 KB).
const MAX_READ_BYTES: usize = 8192;
/// Maximum raw fetch size passed to curl (64 KB, then truncated to MAX_READ_BYTES).
const MAX_FETCH_BYTES: usize = 65536;

/// Browser tool — opens URLs in the system browser and fetches page content.
/// Supports "open" (launch URL), "read" (fetch body via curl), and returns
/// informative errors for CDP-only actions (click, type, scroll, screenshot).
pub const BrowserTool = struct {
    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *BrowserTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *BrowserTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "browser";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Browse web pages. Actions: open, screenshot, click, type, scroll, read.";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"action":{"type":"string","enum":["open","screenshot","click","type","scroll","read"],"description":"Browser action to perform"},"url":{"type":"string","description":"URL to open"},"selector":{"type":"string","description":"CSS selector for click/type"},"text":{"type":"string","description":"Text to type"}},"required":["action"]}
        ;
    }

    fn execute(_: *BrowserTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const action = parseStringField(args_json, "action") orelse
            return ToolResult.fail("Missing 'action' parameter");

        if (std.mem.eql(u8, action, "open")) {
            return executeOpen(allocator, args_json);
        } else if (std.mem.eql(u8, action, "read")) {
            return executeRead(allocator, args_json);
        } else if (std.mem.eql(u8, action, "screenshot")) {
            return ToolResult.fail("Use the screenshot tool instead");
        } else if (std.mem.eql(u8, action, "click") or
            std.mem.eql(u8, action, "type") or
            std.mem.eql(u8, action, "scroll"))
        {
            const msg = try std.fmt.allocPrint(
                allocator,
                "Browser action '{s}' requires CDP (Chrome DevTools Protocol) which is not available. Use 'open' to launch in system browser or 'read' to fetch page content.",
                .{action},
            );
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        } else {
            const msg = try std.fmt.allocPrint(allocator, "Unknown browser action '{s}'", .{action});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }
    }

    /// "open" — launch URL in the platform's default browser.
    fn executeOpen(allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const url = parseStringField(args_json, "url") orelse
            return ToolResult.fail("Missing 'url' parameter for open action");

        if (!std.mem.startsWith(u8, url, "https://")) {
            return ToolResult.fail("Only https:// URLs are supported for security");
        }

        // In test mode, skip actual browser spawn to avoid opening windows during CI/tests.
        if (builtin.is_test) {
            const msg = try std.fmt.allocPrint(allocator, "Opened {s} in system browser", .{url});
            return ToolResult{ .success = true, .output = msg };
        }

        const open_cmd = comptime if (builtin.os.tag == .macos)
            "open"
        else if (builtin.os.tag == .linux)
            "xdg-open"
        else
            @compileError("unsupported OS for browser open");

        var child = std.process.Child.init(
            &.{ open_cmd, url },
            allocator,
        );
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch {
            return ToolResult.fail("Failed to spawn browser open command");
        };

        // Drain pipes so the child doesn't block.
        _ = child.stdout.?.readToEndAlloc(allocator, 4096) catch "";
        _ = child.stderr.?.readToEndAlloc(allocator, 4096) catch "";

        const term = child.wait() catch {
            return ToolResult.fail("Failed to wait for browser open command");
        };

        if (term.Exited != 0) {
            const msg = try std.fmt.allocPrint(allocator, "Browser open command exited with code {d}", .{term.Exited});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        const msg = try std.fmt.allocPrint(allocator, "Opened {s} in system browser", .{url});
        return ToolResult{ .success = true, .output = msg };
    }

    /// "read" — fetch URL content via curl and return body text (truncated to 8 KB).
    fn executeRead(allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const url = parseStringField(args_json, "url") orelse
            return ToolResult.fail("Missing 'url' parameter for read action");

        // Use curl to fetch the page. Flags:
        //   -sS  silent but show errors
        //   -L   follow redirects
        //   -m 10  timeout 10 seconds
        //   --max-filesize 65536  abort if body exceeds 64 KB
        const max_size_str = std.fmt.comptimePrint("{d}", .{MAX_FETCH_BYTES});
        var child = std.process.Child.init(
            &.{ "curl", "-sS", "-L", "-m", "10", "--max-filesize", max_size_str, url },
            allocator,
        );
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch {
            return ToolResult.fail("Failed to spawn curl — is curl installed?");
        };

        const raw_body = child.stdout.?.readToEndAlloc(allocator, MAX_FETCH_BYTES) catch |err| {
            const msg = try std.fmt.allocPrint(allocator, "Failed to read curl output: {s}", .{@errorName(err)});
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        };
        defer allocator.free(raw_body);

        const stderr_out = child.stderr.?.readToEndAlloc(allocator, 4096) catch "";
        defer if (stderr_out.len > 0) allocator.free(stderr_out);

        const term = child.wait() catch {
            return ToolResult.fail("Failed to wait for curl process");
        };

        if (term.Exited != 0) {
            const detail = if (stderr_out.len > 0) stderr_out else "curl request failed";
            const msg = try std.fmt.allocPrint(allocator, "curl exited with code {d}: {s}", .{ term.Exited, detail });
            return ToolResult{ .success = false, .output = "", .error_msg = msg };
        }

        if (raw_body.len == 0) {
            const msg = try allocator.dupe(u8, "Page returned empty response");
            return ToolResult{ .success = true, .output = msg };
        }

        // Truncate to MAX_READ_BYTES
        const truncated = raw_body.len > MAX_READ_BYTES;
        const body_len = if (truncated) MAX_READ_BYTES else raw_body.len;
        const suffix: []const u8 = if (truncated) "\n\n[Content truncated to 8 KB]" else "";

        const output = try std.fmt.allocPrint(allocator, "{s}{s}", .{ raw_body[0..body_len], suffix });
        return ToolResult{ .success = true, .output = output };
    }
};

// ── Tests ───────────────────────────────────────────────────────────

test "browser tool name" {
    var bt = BrowserTool{};
    const t = bt.tool();
    try std.testing.expectEqualStrings("browser", t.name());
}

test "browser description not empty" {
    var bt = BrowserTool{};
    const t = bt.tool();
    try std.testing.expect(t.description().len > 0);
}

test "browser schema has action" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "action") != null);
}

test "browser open launches system browser" {
    var bt = BrowserTool{};
    const t = bt.tool();
    // In test mode, spawn is skipped; verify the output message is correct.
    const result = try t.execute(std.testing.allocator, "{\"action\": \"open\", \"url\": \"https://example.com\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "stub") == null);
}

test "browser open rejects http" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"open\", \"url\": \"http://example.com\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "https") != null);
}

test "browser screenshot redirects to screenshot tool" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"screenshot\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "screenshot tool") != null);
}

// ── Additional browser tests ────────────────────────────────────

test "browser missing action parameter" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const result = try t.execute(std.testing.allocator, "{}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "action") != null);
}

test "browser open missing url" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"open\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "url") != null);
}

test "browser click action requires CDP" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"click\", \"selector\": \"#btn\"}");
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "CDP") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "click") != null);
}

test "browser type action requires CDP" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"type\", \"selector\": \"input\", \"text\": \"hi\"}");
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "CDP") != null);
}

test "browser scroll action requires CDP" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"scroll\"}");
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "CDP") != null);
}

test "browser read missing url" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const result = try t.execute(std.testing.allocator, "{\"action\": \"read\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "url") != null);
}

test "browser open returns output with URL" {
    var bt = BrowserTool{};
    const t = bt.tool();
    // In test mode, spawn is skipped; verify the "Opened ..." message format.
    const result = try t.execute(std.testing.allocator, "{\"action\": \"open\", \"url\": \"https://docs.example.com/api\"}");
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "docs.example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "Opened") != null);
}

test "browser schema has url property" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "url") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "selector") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "text") != null);
}

test "browser schema has enum values" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "screenshot") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "open") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "click") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "scroll") != null);
}

test "browser description mentions browse" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const desc = t.description();
    try std.testing.expect(std.mem.indexOf(u8, desc, "Browse") != null or std.mem.indexOf(u8, desc, "browse") != null or std.mem.indexOf(u8, desc, "web") != null);
}

test "browser tool schema has url" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "url") != null);
}

test "browser tool schema has action" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "action") != null);
}

test "browser tool execute with empty json" {
    var bt = BrowserTool{};
    const t = bt.tool();
    const result = try t.execute(std.testing.allocator, "{}");
    try std.testing.expect(!result.success);
}
