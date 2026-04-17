const std = @import("std");
const net_security = @import("net_security.zig");

pub const Error = std.mem.Allocator.Error || error{InvalidSearchBaseUrl};

pub fn isValid(raw: []const u8) bool {
    return validated(raw) != null;
}

pub fn normalizeEndpoint(allocator: std.mem.Allocator, raw: []const u8) Error![]u8 {
    const base_url = validated(raw) orelse return error.InvalidSearchBaseUrl;
    if (std.mem.endsWith(u8, base_url, "/search")) {
        return allocator.dupe(u8, base_url);
    }
    return std.fmt.allocPrint(allocator, "{s}/search", .{base_url});
}

fn validated(raw: []const u8) ?[]const u8 {
    var trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return null;

    while (trimmed.len > 0 and trimmed[trimmed.len - 1] == '/') {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }

    const uri = std.Uri.parse(trimmed) catch return null;
    if (uri.query != null or uri.fragment != null) return null;

    const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    const is_http = std.ascii.eqlIgnoreCase(uri.scheme, "http");
    if (!is_https and !is_http) return null;

    const host_component = uri.host orelse return null;
    const host = switch (host_component) {
        .raw => |h| h,
        .percent_encoded => |h| blk: {
            if (std.mem.indexOfScalar(u8, h, '%') != null) return null;
            break :blk h;
        },
    };
    if (host.len == 0) return null;
    if (host[0] == ':') return null;
    if (std.mem.indexOfAny(u8, host, " \t\r\n") != null) return null;

    if (host[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host, ']') orelse return null;
        if (close != host.len - 1) return null;
    }

    if (uri.port) |port| {
        if (port == 0) return null;
    }

    if (is_http and !net_security.isLocalHost(host)) return null;

    const path = switch (uri.path) {
        .raw => |p| p,
        .percent_encoded => |p| p,
    };
    if (path.len > 0 and !std.mem.eql(u8, path, "/search")) return null;

    return trimmed;
}

test "normalizeEndpoint appends /search when missing" {
    const allocator = std.testing.allocator;
    const result = try normalizeEndpoint(allocator, "https://example.com");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("https://example.com/search", result);
}

test "normalizeEndpoint trims whitespace and trailing slash" {
    const allocator = std.testing.allocator;
    const result = try normalizeEndpoint(allocator, " \n\thttps://example.com/search/\r\n");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("https://example.com/search", result);
}

test "normalizeEndpoint appends /search for private http hosts" {
    const allocator = std.testing.allocator;

    const lan_result = try normalizeEndpoint(allocator, "http://192.168.1.10:8888/");
    defer allocator.free(lan_result);
    try std.testing.expectEqualStrings("http://192.168.1.10:8888/search", lan_result);

    const local_tld_result = try normalizeEndpoint(allocator, "http://searx.local");
    defer allocator.free(local_tld_result);
    try std.testing.expectEqualStrings("http://searx.local/search", local_tld_result);
}

test "normalizeEndpoint preserves canonical local endpoint" {
    const allocator = std.testing.allocator;
    const result = try normalizeEndpoint(allocator, "http://[::1]:8888/search");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("http://[::1]:8888/search", result);
}

test "normalizeEndpoint returns error for invalid URL" {
    try std.testing.expectError(error.InvalidSearchBaseUrl, normalizeEndpoint(std.testing.allocator, ""));
    try std.testing.expectError(error.InvalidSearchBaseUrl, normalizeEndpoint(std.testing.allocator, "ftp://bad"));
    try std.testing.expectError(error.InvalidSearchBaseUrl, normalizeEndpoint(std.testing.allocator, "http://searx.example.com/search"));
    try std.testing.expectError(error.InvalidSearchBaseUrl, normalizeEndpoint(std.testing.allocator, "https://example.com/custom"));
}
