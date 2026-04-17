const std = @import("std");
const builtin = @import("builtin");
const net_security = @import("../net_security.zig");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;

/// Browser open tool — opens an approved HTTPS URL in the default browser.
/// macOS: `open URL`
/// Linux: `xdg-open URL`
/// Validates URL against an allowlist of domains.
pub const BrowserOpenTool = struct {
    allowed_domains: []const []const u8,

    pub const tool_name = "browser_open";
    pub const tool_description = "Open an approved HTTPS URL in the default browser. Only allowlisted domains are permitted.";
    pub const tool_params =
        \\{"type":"object","properties":{"url":{"type":"string","description":"HTTPS URL to open in browser"}},"required":["url"]}
    ;

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *BrowserOpenTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *BrowserOpenTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const url = root.getString(args, "url") orelse
            return ToolResult.fail("Missing 'url' parameter");

        // Validate URL
        if (!std.mem.startsWith(u8, url, "https://")) {
            return ToolResult.fail("Only https:// URLs are allowed");
        }

        const host = net_security.extractHost(url) orelse {
            return ToolResult.fail("URL must include a host");
        };

        // Block localhost and private IPs
        if (net_security.isLocalHost(host)) {
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

        const proc = @import("process_util.zig");
        const result = proc.run(allocator, argv, .{}) catch {
            return ToolResult.fail("Failed to spawn browser command");
        };
        result.deinit(allocator);

        if (result.success) {
            const msg = try std.fmt.allocPrint(allocator, "Opened in browser: {s}", .{url});
            return ToolResult{ .success = true, .output = msg };
        }
        return ToolResult.fail("Browser command failed");
    }
};

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
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(result.error_msg != null);
}

test "browser_open rejects http" {
    const domains = [_][]const u8{"example.com"};
    var bo = BrowserOpenTool{ .allowed_domains = &domains };
    const t = bo.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"http://example.com\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "https") != null);
}

test "browser_open rejects empty allowlist" {
    var bo = BrowserOpenTool{ .allowed_domains = &.{} };
    const t = bo.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"https://example.com\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "allowed_domains") != null);
}

test "browser_open rejects non-allowlisted domain" {
    const domains = [_][]const u8{"example.com"};
    var bo = BrowserOpenTool{ .allowed_domains = &domains };
    const t = bo.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"https://evil.com/path\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "allowed_domains") != null);
}

test "browser_open rejects localhost" {
    const domains = [_][]const u8{"localhost"};
    var bo = BrowserOpenTool{ .allowed_domains = &domains };
    const t = bo.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"https://localhost:8080/api\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "local") != null or std.mem.indexOf(u8, result.error_msg.?, "private") != null);
}

test "browser_open rejects private ip" {
    const domains = [_][]const u8{"192.168.1.1"};
    var bo = BrowserOpenTool{ .allowed_domains = &domains };
    const t = bo.tool();
    const parsed = try root.parseTestArgs("{\"url\": \"https://192.168.1.1\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "browser_open rejects shared and ipv6 local addresses" {
    const tailscale_domains = [_][]const u8{"100.64.0.1"};
    var tailscale = BrowserOpenTool{ .allowed_domains = &tailscale_domains };
    const tailscale_tool = tailscale.tool();
    const tailscale_args = try root.parseTestArgs("{\"url\": \"https://100.64.0.1\"}");
    defer tailscale_args.deinit();
    const tailscale_result = try tailscale_tool.execute(std.testing.allocator, tailscale_args.value.object);
    try std.testing.expect(!tailscale_result.success);

    // Regression: browser_open must share the same local-host blocking as net_security.
    const ipv6_domains = [_][]const u8{"[fd00::1]"};
    var ipv6 = BrowserOpenTool{ .allowed_domains = &ipv6_domains };
    const ipv6_tool = ipv6.tool();
    const ipv6_args = try root.parseTestArgs("{\"url\": \"https://[fd00::1]\"}");
    defer ipv6_args.deinit();
    const ipv6_result = try ipv6_tool.execute(std.testing.allocator, ipv6_args.value.object);
    try std.testing.expect(!ipv6_result.success);
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
