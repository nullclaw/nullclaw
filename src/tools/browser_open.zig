const std = @import("std");
const builtin = @import("builtin");
const Tool = @import("root.zig").Tool;
const ToolResult = @import("root.zig").ToolResult;
const parseStringField = @import("shell.zig").parseStringField;

/// Browser open tool — opens an approved HTTPS URL in the default browser.
/// macOS: `open URL`
/// Linux: `xdg-open URL`
/// Validates URL against an allowlist of domains.
pub const BrowserOpenTool = struct {
    allowed_domains: []const []const u8,

    const vtable = Tool.VTable{
        .execute = &vtableExecute,
        .name = &vtableName,
        .description = &vtableDesc,
        .parameters_json = &vtableParams,
    };

    pub fn tool(self: *BrowserOpenTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn vtableExecute(ptr: *anyopaque, allocator: std.mem.Allocator, args_json: []const u8) anyerror!ToolResult {
        const self: *BrowserOpenTool = @ptrCast(@alignCast(ptr));
        return self.execute(allocator, args_json);
    }

    fn vtableName(_: *anyopaque) []const u8 {
        return "browser_open";
    }

    fn vtableDesc(_: *anyopaque) []const u8 {
        return "Open an approved HTTPS URL in the default browser. Only allowlisted domains are permitted.";
    }

    fn vtableParams(_: *anyopaque) []const u8 {
        return 
        \\{"type":"object","properties":{"url":{"type":"string","description":"HTTPS URL to open in browser"}},"required":["url"]}
        ;
    }

    fn execute(self: *BrowserOpenTool, allocator: std.mem.Allocator, args_json: []const u8) !ToolResult {
        const url = parseStringField(args_json, "url") orelse
            return ToolResult.fail("Missing 'url' parameter");

        // Validate URL
        if (!std.mem.startsWith(u8, url, "https://")) {
            return ToolResult.fail("Only https:// URLs are allowed");
        }

        // Extract host from URL
        const rest = url["https://".len..];
        const host_end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
        const authority = rest[0..host_end];

        if (authority.len == 0) {
            return ToolResult.fail("URL must include a host");
        }

        // Strip port
        const host = if (std.mem.indexOf(u8, authority, ":")) |colon|
            authority[0..colon]
        else
            authority;

        // Block localhost and private IPs
        if (isLocalOrPrivate(host)) {
            return ToolResult.fail("Blocked local/private host");
        }

        // Check allowlist
        if (self.allowed_domains.len == 0) {
            return ToolResult.fail("No allowed_domains configured for browser_open");
        }

        if (!hostMatchesAllowlist(host, self.allowed_domains)) {
            return ToolResult.fail("Host is not in browser allowed_domains");
        }

        // Open URL using platform command
        const argv: []const []const u8 = switch (comptime builtin.os.tag) {
            .macos => &.{ "open", url },
            .linux => &.{ "xdg-open", url },
            else => {
                return ToolResult.fail("browser_open not supported on this platform");
            },
        };

        var child = std.process.Child.init(argv, allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch {
            return ToolResult.fail("Failed to spawn browser command");
        };

        const term = child.wait() catch {
            return ToolResult.fail("Failed to wait for browser command");
        };

        if (term.Exited == 0) {
            const msg = try std.fmt.allocPrint(allocator, "Opened in browser: {s}", .{url});
            return ToolResult{ .success = true, .output = msg };
        } else {
            return ToolResult.fail("Browser command failed");
        }
    }
};

fn isLocalOrPrivate(host: []const u8) bool {
    if (std.mem.eql(u8, host, "localhost")) return true;
    if (std.mem.endsWith(u8, host, ".localhost")) return true;
    if (std.mem.endsWith(u8, host, ".local")) return true;
    if (std.mem.eql(u8, host, "::1")) return true;

    // Check common private IPv4 ranges
    if (std.mem.startsWith(u8, host, "10.")) return true;
    if (std.mem.startsWith(u8, host, "127.")) return true;
    if (std.mem.startsWith(u8, host, "192.168.")) return true;
    if (std.mem.startsWith(u8, host, "169.254.")) return true;

    return false;
}

fn hostMatchesAllowlist(host: []const u8, allowed: []const []const u8) bool {
    for (allowed) |domain| {
        if (std.mem.eql(u8, host, domain)) return true;
        // Check subdomain: host ends with domain and has '.' before it
        if (host.len > domain.len) {
            const prefix_len = host.len - domain.len;
            if (std.mem.eql(u8, host[prefix_len..], domain) and host[prefix_len - 1] == '.') {
                return true;
            }
        }
    }
    return false;
}

// ── Tests ───────────────────────────────────────────────────────────

test "browser_open tool name" {
    var bo = BrowserOpenTool{ .allowed_domains = &.{} };
    const t = bo.tool();
    try std.testing.expectEqualStrings("browser_open", t.name());
}

test "browser_open tool description not empty" {
    var bo = BrowserOpenTool{ .allowed_domains = &.{} };
    const t = bo.tool();
    try std.testing.expect(t.description().len > 0);
}

test "browser_open tool schema has url" {
    var bo = BrowserOpenTool{ .allowed_domains = &.{} };
    const t = bo.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "url") != null);
}

test "browser_open missing url returns error" {
    const domains = [_][]const u8{"example.com"};
    var bo = BrowserOpenTool{ .allowed_domains = &domains };
    const t = bo.tool();
    const result = try t.execute(std.testing.allocator, "{}");
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
}

test "browser_open rejects http" {
    const domains = [_][]const u8{"example.com"};
    var bo = BrowserOpenTool{ .allowed_domains = &domains };
    const t = bo.tool();
    const result = try t.execute(std.testing.allocator, "{\"url\": \"http://example.com\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "https") != null);
}

test "browser_open rejects empty allowlist" {
    var bo = BrowserOpenTool{ .allowed_domains = &.{} };
    const t = bo.tool();
    const result = try t.execute(std.testing.allocator, "{\"url\": \"https://example.com\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "allowed_domains") != null);
}

test "browser_open rejects non-allowlisted domain" {
    const domains = [_][]const u8{"example.com"};
    var bo = BrowserOpenTool{ .allowed_domains = &domains };
    const t = bo.tool();
    const result = try t.execute(std.testing.allocator, "{\"url\": \"https://evil.com/path\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "allowed_domains") != null);
}

test "browser_open rejects localhost" {
    const domains = [_][]const u8{"localhost"};
    var bo = BrowserOpenTool{ .allowed_domains = &domains };
    const t = bo.tool();
    const result = try t.execute(std.testing.allocator, "{\"url\": \"https://localhost:8080/api\"}");
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "local") != null or std.mem.indexOf(u8, result.error_msg.?, "private") != null);
}

test "browser_open rejects private ip" {
    const domains = [_][]const u8{"192.168.1.1"};
    var bo = BrowserOpenTool{ .allowed_domains = &domains };
    const t = bo.tool();
    const result = try t.execute(std.testing.allocator, "{\"url\": \"https://192.168.1.1\"}");
    try std.testing.expect(!result.success);
}

test "isLocalOrPrivate detects localhost" {
    try std.testing.expect(isLocalOrPrivate("localhost"));
    try std.testing.expect(isLocalOrPrivate("sub.localhost"));
    try std.testing.expect(isLocalOrPrivate("host.local"));
    try std.testing.expect(isLocalOrPrivate("127.0.0.1"));
    try std.testing.expect(isLocalOrPrivate("10.0.0.1"));
    try std.testing.expect(isLocalOrPrivate("192.168.1.1"));
    try std.testing.expect(isLocalOrPrivate("169.254.0.1"));
    try std.testing.expect(!isLocalOrPrivate("example.com"));
    try std.testing.expect(!isLocalOrPrivate("google.com"));
}

test "hostMatchesAllowlist exact and subdomain" {
    const domains = [_][]const u8{"example.com"};
    try std.testing.expect(hostMatchesAllowlist("example.com", &domains));
    try std.testing.expect(hostMatchesAllowlist("api.example.com", &domains));
    try std.testing.expect(!hostMatchesAllowlist("notexample.com", &domains));
    try std.testing.expect(!hostMatchesAllowlist("evil.com", &domains));
}

test "browser_open tool spec" {
    var bo = BrowserOpenTool{ .allowed_domains = &.{} };
    const t = bo.tool();
    const s = t.spec();
    try std.testing.expectEqualStrings("browser_open", s.name);
    try std.testing.expect(s.parameters_json[0] == '{');
}
