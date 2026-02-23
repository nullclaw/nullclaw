//! SSRF protection utilities.
//!
//! Extracted from `src/tools/http_request.zig` to be shared across modules.
//! Provides host extraction, localhost detection, and allowlist matching.

const std = @import("std");

/// Extract the hostname from an HTTP(S) URL, stripping port, path, query, fragment.
pub fn extractHost(url: []const u8) ?[]const u8 {
    const uri = std.Uri.parse(url) catch return null;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "http") and
        !std.ascii.eqlIgnoreCase(uri.scheme, "https"))
    {
        return null;
    }

    const host_component = uri.host orelse return null;
    const host = switch (host_component) {
        .raw => |h| h,
        .percent_encoded => |h| {
            // Percent-encoded hostnames are suspicious (e.g. %31%32%37.0.0.1
            // to smuggle 127.0.0.1). Reject any host that actually contains a
            // percent-escape; pass through those that the parser tagged as
            // percent_encoded but contain no '%' (std.Uri does this sometimes).
            if (std.mem.indexOfScalar(u8, h, '%') != null) return null;
            return h;
        },
    };
    if (host.len == 0) return null;
    if (host[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host, ']') orelse return null;
        if (close != host.len - 1) return null;
    }
    return host;
}

/// Check if a host matches the allowlist.
/// Supports exact match and wildcard subdomain patterns ("*.example.com").
pub fn hostMatchesAllowlist(host: []const u8, allowed: []const []const u8) bool {
    if (allowed.len == 0) return true; // empty allowlist = allow all
    for (allowed) |pattern| {
        // Exact match
        if (std.mem.eql(u8, host, pattern)) return true;
        // Wildcard subdomain: "*.example.com" matches "api.example.com"
        if (std.mem.startsWith(u8, pattern, "*.")) {
            const domain = pattern[2..]; // strip "*."
            if (std.mem.endsWith(u8, host, domain)) {
                const prefix_len = host.len - domain.len;
                if (prefix_len > 0 and host[prefix_len - 1] == '.') return true;
            }
        }
        // Also allow implicit subdomain match (like browser_open does)
        if (host.len > pattern.len) {
            const offset = host.len - pattern.len;
            if (std.mem.eql(u8, host[offset..], pattern) and host[offset - 1] == '.') {
                return true;
            }
        }
    }
    return false;
}

/// SSRF: check if host is localhost or a private/reserved IP.
pub fn isLocalHost(host: []const u8) bool {
    // Strip brackets from IPv6 addresses like [::1]
    const bare = if (std.mem.startsWith(u8, host, "[") and std.mem.endsWith(u8, host, "]"))
        host[1 .. host.len - 1]
    else
        host;

    // Drop IPv6 zone id suffix (e.g. "fe80::1%lo0" or "fe80::1%25lo0").
    const unscoped = if (std.mem.indexOfScalar(u8, bare, '%')) |pct| bare[0..pct] else bare;
    if (unscoped.len == 0) return true;

    if (std.mem.eql(u8, unscoped, "localhost")) return true;
    if (std.mem.endsWith(u8, unscoped, ".localhost")) return true;
    // .local TLD
    if (std.mem.endsWith(u8, unscoped, ".local")) return true;

    // Try to parse as IPv4
    if (parseIpv4(unscoped)) |octets| {
        return isNonGlobalV4(octets);
    }

    // Try to parse as IPv6
    if (parseIpv6(unscoped)) |segments| {
        return isNonGlobalV6(segments);
    }

    return false;
}

pub const ResolveConnectHostError = std.mem.Allocator.Error || error{
    HostResolutionFailed,
    LocalAddressBlocked,
};

/// Resolve host and return a concrete connect target (IP literal) that is
/// guaranteed to be globally routable. If any resolved address is local/private,
/// reject to prevent mixed-record SSRF bypasses.
pub fn resolveConnectHost(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
) ResolveConnectHostError![]u8 {
    const bare = stripHostBrackets(host);
    const unscoped = stripIpv6ZoneId(bare);

    // Fast-path literal hosts before DNS resolution to avoid platform-specific
    // resolver differences for numeric aliases (e.g. 2130706433 on Windows).
    if (parseIpv4(bare)) |octets| {
        if (isNonGlobalV4(octets)) return error.LocalAddressBlocked;
        return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
            octets[0],
            octets[1],
            octets[2],
            octets[3],
        });
    }
    if (parseIpv4IntegerAlias(bare)) |octets| {
        if (isNonGlobalV4(octets)) return error.LocalAddressBlocked;
        return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
            octets[0],
            octets[1],
            octets[2],
            octets[3],
        });
    }
    if (parseIpv6(unscoped)) |segs| {
        if (isNonGlobalV6(segs)) return error.LocalAddressBlocked;
        return std.fmt.allocPrint(allocator, "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}", .{
            segs[0],
            segs[1],
            segs[2],
            segs[3],
            segs[4],
            segs[5],
            segs[6],
            segs[7],
        });
    }

    const addr_list = std.net.getAddressList(allocator, bare, port) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.HostResolutionFailed,
    };
    defer addr_list.deinit();

    var saw_addr = false;
    var selected_v4: ?[4]u8 = null;
    var selected_v6: ?[16]u8 = null;

    for (addr_list.addrs) |addr| {
        switch (addr.any.family) {
            std.posix.AF.INET => {
                const octets: *const [4]u8 = @ptrCast(&addr.in.sa.addr);
                if (isNonGlobalV4(octets.*)) return error.LocalAddressBlocked;
                if (!saw_addr) {
                    selected_v4 = octets.*;
                    saw_addr = true;
                }
            },
            std.posix.AF.INET6 => {
                const bytes = addr.in6.sa.addr;
                const segs = [8]u16{
                    (@as(u16, bytes[0]) << 8) | bytes[1],
                    (@as(u16, bytes[2]) << 8) | bytes[3],
                    (@as(u16, bytes[4]) << 8) | bytes[5],
                    (@as(u16, bytes[6]) << 8) | bytes[7],
                    (@as(u16, bytes[8]) << 8) | bytes[9],
                    (@as(u16, bytes[10]) << 8) | bytes[11],
                    (@as(u16, bytes[12]) << 8) | bytes[13],
                    (@as(u16, bytes[14]) << 8) | bytes[15],
                };
                if (isNonGlobalV6(segs)) return error.LocalAddressBlocked;
                if (!saw_addr) {
                    selected_v6 = bytes;
                    saw_addr = true;
                }
            },
            else => {},
        }
    }

    if (!saw_addr) return error.HostResolutionFailed;

    if (selected_v4) |octets| {
        return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
            octets[0],
            octets[1],
            octets[2],
            octets[3],
        });
    }

    if (selected_v6) |bytes| {
        const segs = [8]u16{
            (@as(u16, bytes[0]) << 8) | bytes[1],
            (@as(u16, bytes[2]) << 8) | bytes[3],
            (@as(u16, bytes[4]) << 8) | bytes[5],
            (@as(u16, bytes[6]) << 8) | bytes[7],
            (@as(u16, bytes[8]) << 8) | bytes[9],
            (@as(u16, bytes[10]) << 8) | bytes[11],
            (@as(u16, bytes[12]) << 8) | bytes[13],
            (@as(u16, bytes[14]) << 8) | bytes[15],
        };
        return std.fmt.allocPrint(allocator, "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}", .{
            segs[0],
            segs[1],
            segs[2],
            segs[3],
            segs[4],
            segs[5],
            segs[6],
            segs[7],
        });
    }

    return error.HostResolutionFailed;
}

/// Resolve hostname and reject if any resolved IP is local/private/reserved.
/// This closes SSRF bypasses via numeric host aliases (e.g. 2130706433) and
/// DNS rebinding-style domains that resolve to loopback/private addresses.
pub fn hostResolvesToLocal(allocator: std.mem.Allocator, host: []const u8, port: u16) bool {
    const bare = stripHostBrackets(host);
    const unscoped = stripIpv6ZoneId(bare);

    if (parseIpv4(bare)) |octets| return isNonGlobalV4(octets);
    if (parseIpv4IntegerAlias(bare)) |octets| return isNonGlobalV4(octets);
    if (parseIpv6(unscoped)) |segs| return isNonGlobalV6(segs);

    // Fail closed: if we cannot verify DNS resolution safety, treat host as local.
    const addr_list = std.net.getAddressList(allocator, bare, port) catch return true;
    defer addr_list.deinit();

    for (addr_list.addrs) |addr| {
        switch (addr.any.family) {
            std.posix.AF.INET => {
                const octets: *const [4]u8 = @ptrCast(&addr.in.sa.addr);
                if (isNonGlobalV4(octets.*)) return true;
            },
            std.posix.AF.INET6 => {
                const bytes = addr.in6.sa.addr;
                const segs = [8]u16{
                    (@as(u16, bytes[0]) << 8) | bytes[1],
                    (@as(u16, bytes[2]) << 8) | bytes[3],
                    (@as(u16, bytes[4]) << 8) | bytes[5],
                    (@as(u16, bytes[6]) << 8) | bytes[7],
                    (@as(u16, bytes[8]) << 8) | bytes[9],
                    (@as(u16, bytes[10]) << 8) | bytes[11],
                    (@as(u16, bytes[12]) << 8) | bytes[13],
                    (@as(u16, bytes[14]) << 8) | bytes[15],
                };
                if (isNonGlobalV6(segs)) return true;
            },
            else => {},
        }
    }
    return false;
}

fn stripHostBrackets(host: []const u8) []const u8 {
    if (std.mem.startsWith(u8, host, "[") and std.mem.endsWith(u8, host, "]")) {
        return host[1 .. host.len - 1];
    }
    return host;
}

fn stripIpv6ZoneId(host: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, host, '%')) |pct| return host[0..pct];
    return host;
}

/// Returns true if the IPv4 address is not globally routable.
fn isNonGlobalV4(addr: [4]u8) bool {
    const a = addr[0];
    const b = addr[1];
    const c = addr[2];
    // 127.0.0.0/8 (loopback)
    if (a == 127) return true;
    // 10.0.0.0/8 (private)
    if (a == 10) return true;
    // 172.16.0.0/12 (private)
    if (a == 172 and b >= 16 and b <= 31) return true;
    // 192.168.0.0/16 (private)
    if (a == 192 and b == 168) return true;
    // 0.0.0.0/8 (unspecified)
    if (a == 0) return true;
    // 169.254.0.0/16 (link-local)
    if (a == 169 and b == 254) return true;
    // 224.0.0.0/4 (multicast) through 255.255.255.255 (broadcast)
    if (a >= 224) return true;
    // 100.64.0.0/10 (shared address space, RFC 6598)
    if (a == 100 and b >= 64 and b <= 127) return true;
    // 192.0.2.0/24 (documentation, TEST-NET-1, RFC 5737)
    if (a == 192 and b == 0 and c == 2) return true;
    // 198.51.100.0/24 (documentation, TEST-NET-2, RFC 5737)
    if (a == 198 and b == 51 and c == 100) return true;
    // 203.0.113.0/24 (documentation, TEST-NET-3, RFC 5737)
    if (a == 203 and b == 0 and c == 113) return true;
    // 198.18.0.0/15 (benchmarking, RFC 2544)
    if (a == 198 and (b == 18 or b == 19)) return true;
    // 192.0.0.0/24 (IETF protocol assignments)
    if (a == 192 and b == 0 and c == 0) return true;
    return false;
}

/// Returns true if the IPv6 address is not globally routable.
fn isNonGlobalV6(segs: [8]u16) bool {
    // ::1 (loopback)
    if (segs[0] == 0 and segs[1] == 0 and segs[2] == 0 and segs[3] == 0 and
        segs[4] == 0 and segs[5] == 0 and segs[6] == 0 and segs[7] == 1)
        return true;
    // :: (unspecified)
    if (segs[0] == 0 and segs[1] == 0 and segs[2] == 0 and segs[3] == 0 and
        segs[4] == 0 and segs[5] == 0 and segs[6] == 0 and segs[7] == 0)
        return true;
    // ff00::/8 (multicast)
    if (segs[0] & 0xff00 == 0xff00) return true;
    // fc00::/7 (unique local: fc00:: - fdff::)
    if (segs[0] & 0xfe00 == 0xfc00) return true;
    // fe80::/10 (link-local)
    if (segs[0] & 0xffc0 == 0xfe80) return true;
    // 2001:db8::/32 (documentation)
    if (segs[0] == 0x2001 and segs[1] == 0x0db8) return true;
    // ::ffff:0:0/96 (IPv4-mapped) — check the IPv4 part
    if (segs[0] == 0 and segs[1] == 0 and segs[2] == 0 and segs[3] == 0 and
        segs[4] == 0 and segs[5] == 0xffff)
    {
        const ipv4 = [4]u8{
            @truncate(segs[6] >> 8),
            @truncate(segs[6] & 0xff),
            @truncate(segs[7] >> 8),
            @truncate(segs[7] & 0xff),
        };
        return isNonGlobalV4(ipv4);
    }
    return false;
}

/// Parse a dotted-decimal IPv4 address string into 4 octets.
fn parseIpv4(s: []const u8) ?[4]u8 {
    var octets: [4]u8 = undefined;
    var count: u8 = 0;
    var start: usize = 0;

    for (s, 0..) |c, i| {
        if (c == '.') {
            if (count >= 3) return null;
            octets[count] = std.fmt.parseInt(u8, s[start..i], 10) catch return null;
            count += 1;
            start = i + 1;
        } else if (c < '0' or c > '9') {
            return null;
        }
    }
    if (count != 3) return null;
    octets[3] = std.fmt.parseInt(u8, s[start..], 10) catch return null;
    return octets;
}

/// Parse single-integer IPv4 aliases into octets.
/// Supports decimal and 0x-prefixed hex notation.
fn parseIpv4IntegerAlias(s: []const u8) ?[4]u8 {
    if (s.len == 0) return null;
    if (std.mem.indexOfScalar(u8, s, '.') != null) return null;
    if (std.mem.indexOfScalar(u8, s, ':') != null) return null;

    const value: u32 = blk: {
        if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) {
            if (s.len <= 2) return null;
            break :blk std.fmt.parseInt(u32, s[2..], 16) catch return null;
        }
        for (s) |c| {
            if (c < '0' or c > '9') return null;
        }
        break :blk std.fmt.parseInt(u32, s, 10) catch return null;
    };

    return .{
        @as(u8, @truncate(value >> 24)),
        @as(u8, @truncate(value >> 16)),
        @as(u8, @truncate(value >> 8)),
        @as(u8, @truncate(value)),
    };
}

/// Parse an IPv6 address string into 8 segments.
/// Supports :: abbreviation and mixed IPv4 notation (::ffff:1.2.3.4).
fn parseIpv6(s: []const u8) ?[8]u16 {
    if (s.len == 0) return null;

    // Check for :: and split around it
    const double_colon = std.mem.indexOf(u8, s, "::");

    var segs: [8]u16 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
    var seg_count: usize = 0;

    if (double_colon) |dc_pos| {
        // Parse segments before ::
        if (dc_pos > 0) {
            seg_count = parseIpv6Groups(s[0..dc_pos], &segs, 0) orelse return null;
        }
        // Parse segments after ::
        const after = s[dc_pos + 2 ..];
        if (after.len > 0) {
            // Check if the tail contains an IPv4 address (for ::ffff:x.x.x.x)
            if (std.mem.indexOfScalar(u8, after, '.') != null) {
                // Find last colon to separate groups from IPv4
                if (std.mem.lastIndexOfScalar(u8, after, ':')) |last_colon| {
                    const groups_part = after[0..last_colon];
                    const ipv4_part = after[last_colon + 1 ..];
                    // Parse IPv6 groups in the tail
                    var tail_segs: [8]u16 = undefined;
                    const tail_count = parseIpv6Groups(groups_part, &tail_segs, 0) orelse return null;
                    // Parse IPv4
                    const ipv4 = parseIpv4(ipv4_part) orelse return null;
                    // Total segments = seg_count + tail_count + 2 (for IPv4)
                    const total = seg_count + tail_count + 2;
                    if (total > 8) return null;
                    const gap = 8 - total;
                    // Place tail segments
                    for (0..tail_count) |i| {
                        segs[seg_count + gap + i] = tail_segs[i];
                    }
                    // Place IPv4 as last 2 segments
                    segs[6] = (@as(u16, ipv4[0]) << 8) | ipv4[1];
                    segs[7] = (@as(u16, ipv4[2]) << 8) | ipv4[3];
                } else {
                    // Just IPv4 after ::
                    const ipv4 = parseIpv4(after) orelse return null;
                    segs[6] = (@as(u16, ipv4[0]) << 8) | ipv4[1];
                    segs[7] = (@as(u16, ipv4[2]) << 8) | ipv4[3];
                }
            } else {
                var tail_segs: [8]u16 = undefined;
                const tail_count = parseIpv6Groups(after, &tail_segs, 0) orelse return null;
                if (seg_count + tail_count > 8) return null;
                const gap = 8 - seg_count - tail_count;
                for (0..tail_count) |i| {
                    segs[seg_count + gap + i] = tail_segs[i];
                }
            }
        }
        // Middle is filled with zeros (already initialized)
    } else {
        // No :: — must have exactly 8 groups (or 6 groups + IPv4)
        if (std.mem.indexOfScalar(u8, s, '.') != null) {
            // Mixed notation: groups:groups:...:x.x.x.x
            if (std.mem.lastIndexOfScalar(u8, s, ':')) |last_colon| {
                const groups_part = s[0..last_colon];
                const ipv4_part = s[last_colon + 1 ..];
                seg_count = parseIpv6Groups(groups_part, &segs, 0) orelse return null;
                if (seg_count != 6) return null;
                const ipv4 = parseIpv4(ipv4_part) orelse return null;
                segs[6] = (@as(u16, ipv4[0]) << 8) | ipv4[1];
                segs[7] = (@as(u16, ipv4[2]) << 8) | ipv4[3];
            } else return null;
        } else {
            seg_count = parseIpv6Groups(s, &segs, 0) orelse return null;
            if (seg_count != 8) return null;
        }
    }
    return segs;
}

/// Parse colon-separated hex groups into segments array starting at offset.
/// Returns number of segments parsed, or null on error.
fn parseIpv6Groups(s: []const u8, segs: []u16, start_idx: usize) ?usize {
    var idx = start_idx;
    var seg_start: usize = 0;
    for (s, 0..) |c, i| {
        if (c == ':') {
            if (idx >= segs.len) return null;
            segs[idx] = std.fmt.parseInt(u16, s[seg_start..i], 16) catch return null;
            idx += 1;
            seg_start = i + 1;
        }
    }
    // Last segment
    if (seg_start <= s.len) {
        if (idx >= segs.len) return null;
        segs[idx] = std.fmt.parseInt(u16, s[seg_start..], 16) catch return null;
        idx += 1;
    }
    return idx - start_idx;
}

// ── Tests ───────────────────────────────────────────────────────────

test "extractHost basic" {
    try std.testing.expectEqualStrings("example.com", extractHost("https://example.com/path").?);
    try std.testing.expectEqualStrings("example.com", extractHost("http://example.com").?);
    try std.testing.expectEqualStrings("api.example.com", extractHost("https://api.example.com/v1").?);
}

test "extractHost with port" {
    try std.testing.expectEqualStrings("localhost", extractHost("http://localhost:8080/api").?);
}

test "extractHost strips userinfo safely" {
    try std.testing.expectEqualStrings("127.0.0.1", extractHost("http://user:pass@127.0.0.1/admin").?);
    try std.testing.expectEqualStrings("example.com", extractHost("https://user@example.com/path").?);
}

test "extractHost handles bracketed ipv6" {
    try std.testing.expectEqualStrings("[::1]", extractHost("http://[::1]:8080/api").?);
    try std.testing.expectEqualStrings("[2607:f8b0::1]", extractHost("https://[2607:f8b0::1]/").?);
}

test "extractHost parses unbracketed ipv6 authority with port" {
    try std.testing.expectEqualStrings("::1", extractHost("http://::1:8080/api").?);
}

test "extractHost rejects invalid bracketed authority" {
    try std.testing.expect(extractHost("http://[::1") == null);
}

test "extractHost rejects percent-encoded host bypass" {
    // %31%32%37%2e%30%2e%30%2e%31 = 127.0.0.1
    try std.testing.expect(extractHost("http://%31%32%37%2e%30%2e%30%2e%31/secret") == null);
    // %6c%6f%63%61%6c%68%6f%73%74 = localhost
    try std.testing.expect(extractHost("http://%6c%6f%63%61%6c%68%6f%73%74/admin") == null);
}

test "extractHost returns null for non-http scheme" {
    try std.testing.expect(extractHost("ftp://example.com") == null);
    try std.testing.expect(extractHost("file:///etc/passwd") == null);
}

test "extractHost returns null for empty host" {
    try std.testing.expect(extractHost("http:///path") == null);
    try std.testing.expect(extractHost("https:///") == null);
}

test "extractHost handles query and fragment" {
    try std.testing.expectEqualStrings("example.com", extractHost("https://example.com?q=1").?);
    try std.testing.expectEqualStrings("example.com", extractHost("https://example.com#frag").?);
    try std.testing.expectEqualStrings("example.com", extractHost("https://example.com/path?q=1#frag").?);
}

test "isLocalHost detects localhost" {
    try std.testing.expect(isLocalHost("localhost"));
    try std.testing.expect(isLocalHost("foo.localhost"));
    try std.testing.expect(isLocalHost("127.0.0.1"));
    try std.testing.expect(isLocalHost("0.0.0.0"));
    try std.testing.expect(isLocalHost("::1"));
}

test "isLocalHost detects private ranges" {
    try std.testing.expect(isLocalHost("10.0.0.1"));
    try std.testing.expect(isLocalHost("192.168.1.1"));
    try std.testing.expect(isLocalHost("172.16.0.1"));
}

test "isLocalHost allows public" {
    try std.testing.expect(!isLocalHost("8.8.8.8"));
    try std.testing.expect(!isLocalHost("example.com"));
    try std.testing.expect(!isLocalHost("1.1.1.1"));
}

test "isLocalHost detects bracketed IPv6" {
    try std.testing.expect(isLocalHost("[::1]"));
}

test "isLocalHost detects 172.16-31 range" {
    try std.testing.expect(isLocalHost("172.16.0.1"));
    try std.testing.expect(isLocalHost("172.31.255.255"));
    try std.testing.expect(!isLocalHost("172.15.0.1"));
    try std.testing.expect(!isLocalHost("172.32.0.1"));
}

test "isLocalHost detects 127.x.x.x range" {
    try std.testing.expect(isLocalHost("127.0.0.1"));
    try std.testing.expect(isLocalHost("127.0.0.2"));
    try std.testing.expect(isLocalHost("127.255.255.255"));
}

test "isLocalHost detects .local TLD" {
    try std.testing.expect(isLocalHost("myhost.local"));
}

test "isNonGlobalV4 blocks 169.254.x.x link-local" {
    try std.testing.expect(isNonGlobalV4(.{ 169, 254, 1, 1 }));
    try std.testing.expect(isNonGlobalV4(.{ 169, 254, 0, 0 }));
}

test "isNonGlobalV4 blocks 100.64.0.1 shared address space" {
    try std.testing.expect(isNonGlobalV4(.{ 100, 64, 0, 1 }));
    try std.testing.expect(isNonGlobalV4(.{ 100, 127, 255, 255 }));
    try std.testing.expect(!isNonGlobalV4(.{ 100, 63, 0, 1 }));
    try std.testing.expect(!isNonGlobalV4(.{ 100, 128, 0, 1 }));
}

test "isNonGlobalV4 blocks multicast" {
    try std.testing.expect(isNonGlobalV4(.{ 224, 0, 0, 1 }));
    try std.testing.expect(isNonGlobalV4(.{ 239, 255, 255, 255 }));
}

test "isNonGlobalV4 allows public" {
    try std.testing.expect(!isNonGlobalV4(.{ 8, 8, 8, 8 }));
    try std.testing.expect(!isNonGlobalV4(.{ 1, 1, 1, 1 }));
    try std.testing.expect(!isNonGlobalV4(.{ 93, 184, 216, 34 }));
}

test "isNonGlobalV4 blocks broadcast" {
    try std.testing.expect(isNonGlobalV4(.{ 255, 255, 255, 255 }));
}

test "isNonGlobalV4 blocks documentation ranges" {
    try std.testing.expect(isNonGlobalV4(.{ 192, 0, 2, 1 }));
    try std.testing.expect(isNonGlobalV4(.{ 198, 51, 100, 1 }));
    try std.testing.expect(isNonGlobalV4(.{ 203, 0, 113, 1 }));
}

test "isNonGlobalV4 blocks benchmarking range" {
    try std.testing.expect(isNonGlobalV4(.{ 198, 18, 0, 1 }));
    try std.testing.expect(isNonGlobalV4(.{ 198, 19, 255, 255 }));
}

test "isNonGlobalV6 blocks loopback" {
    try std.testing.expect(isNonGlobalV6(.{ 0, 0, 0, 0, 0, 0, 0, 1 }));
}

test "isNonGlobalV6 blocks unique local" {
    try std.testing.expect(isNonGlobalV6(.{ 0xfc00, 0, 0, 0, 0, 0, 0, 1 }));
    try std.testing.expect(isNonGlobalV6(.{ 0xfd00, 0, 0, 0, 0, 0, 0, 1 }));
}

test "isNonGlobalV6 blocks link-local" {
    try std.testing.expect(isNonGlobalV6(.{ 0xfe80, 0, 0, 0, 0, 0, 0, 1 }));
}

test "isNonGlobalV6 blocks documentation" {
    try std.testing.expect(isNonGlobalV6(.{ 0x2001, 0x0db8, 0, 0, 0, 0, 0, 1 }));
}

test "isNonGlobalV6 blocks unspecified" {
    try std.testing.expect(isNonGlobalV6(.{ 0, 0, 0, 0, 0, 0, 0, 0 }));
}

test "isNonGlobalV6 blocks multicast" {
    try std.testing.expect(isNonGlobalV6(.{ 0xff02, 0, 0, 0, 0, 0, 0, 1 }));
}

test "isNonGlobalV6 blocks IPv4-mapped private" {
    try std.testing.expect(isNonGlobalV6(.{ 0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001 }));
    try std.testing.expect(isNonGlobalV6(.{ 0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101 }));
}

test "isNonGlobalV6 allows public" {
    try std.testing.expect(!isNonGlobalV6(.{ 0x2607, 0xf8b0, 0x4004, 0x0800, 0, 0, 0, 0x200e }));
}

test "isLocalHost blocks IPv6 loopback" {
    try std.testing.expect(isLocalHost("::1"));
    try std.testing.expect(isLocalHost("[::1]"));
}

test "isLocalHost blocks IPv6 unique-local" {
    try std.testing.expect(isLocalHost("fd00::1"));
}

test "isLocalHost blocks IPv6 link-local" {
    try std.testing.expect(isLocalHost("fe80::1"));
}

test "isLocalHost blocks IPv6 with zone id suffix" {
    try std.testing.expect(isLocalHost("fe80::1%lo0"));
    try std.testing.expect(isLocalHost("fe80::1%25lo0"));
    try std.testing.expect(isLocalHost("[fe80::1%25lo0]"));
}

test "isLocalHost blocks IPv6 documentation" {
    try std.testing.expect(isLocalHost("2001:db8::1"));
}

test "isLocalHost blocks IPv6 multicast" {
    try std.testing.expect(isLocalHost("ff02::1"));
}

test "hostMatchesAllowlist exact match works" {
    const domains = [_][]const u8{"example.com"};
    try std.testing.expect(hostMatchesAllowlist("example.com", &domains));
}

test "hostMatchesAllowlist wildcard subdomain match works" {
    const domains = [_][]const u8{"*.example.com"};
    try std.testing.expect(hostMatchesAllowlist("api.example.com", &domains));
    try std.testing.expect(hostMatchesAllowlist("deep.sub.example.com", &domains));
}

test "hostMatchesAllowlist wildcard does not match wrong domain" {
    const domains = [_][]const u8{"*.example.com"};
    try std.testing.expect(!hostMatchesAllowlist("evil.com", &domains));
    try std.testing.expect(!hostMatchesAllowlist("notexample.com", &domains));
}

test "hostMatchesAllowlist empty allowlist allows all" {
    const empty: []const []const u8 = &.{};
    try std.testing.expect(hostMatchesAllowlist("anything.com", empty));
}

test "hostMatchesAllowlist implicit subdomain match" {
    const domains = [_][]const u8{"example.com"};
    try std.testing.expect(hostMatchesAllowlist("api.example.com", &domains));
    try std.testing.expect(!hostMatchesAllowlist("notexample.com", &domains));
}

test "parseIpv4 basic" {
    const octets = parseIpv4("192.168.1.1").?;
    try std.testing.expectEqual(@as(u8, 192), octets[0]);
    try std.testing.expectEqual(@as(u8, 168), octets[1]);
    try std.testing.expectEqual(@as(u8, 1), octets[2]);
    try std.testing.expectEqual(@as(u8, 1), octets[3]);
}

test "parseIpv4 rejects invalid" {
    try std.testing.expect(parseIpv4("not-an-ip") == null);
    try std.testing.expect(parseIpv4("256.1.1.1") == null);
    try std.testing.expect(parseIpv4("1.2.3") == null);
}

test "parseIpv4IntegerAlias parses decimal and hex" {
    const dec = parseIpv4IntegerAlias("2130706433").?;
    try std.testing.expectEqual(@as(u8, 127), dec[0]);
    try std.testing.expectEqual(@as(u8, 0), dec[1]);
    try std.testing.expectEqual(@as(u8, 0), dec[2]);
    try std.testing.expectEqual(@as(u8, 1), dec[3]);

    const hex = parseIpv4IntegerAlias("0x7f000001").?;
    try std.testing.expectEqual(@as(u8, 127), hex[0]);
    try std.testing.expectEqual(@as(u8, 0), hex[1]);
    try std.testing.expectEqual(@as(u8, 0), hex[2]);
    try std.testing.expectEqual(@as(u8, 1), hex[3]);
}

test "parseIpv4IntegerAlias rejects invalid" {
    try std.testing.expect(parseIpv4IntegerAlias("example.com") == null);
    try std.testing.expect(parseIpv4IntegerAlias("0x") == null);
    try std.testing.expect(parseIpv4IntegerAlias("0xgg") == null);
}

test "parseIpv6 loopback" {
    const segs = parseIpv6("::1").?;
    try std.testing.expectEqual(@as(u16, 0), segs[0]);
    try std.testing.expectEqual(@as(u16, 1), segs[7]);
}

test "parseIpv6 link-local" {
    const segs = parseIpv6("fe80::1").?;
    try std.testing.expectEqual(@as(u16, 0xfe80), segs[0]);
    try std.testing.expectEqual(@as(u16, 1), segs[7]);
}

test "parseIpv6 unique-local" {
    const segs = parseIpv6("fd00::1").?;
    try std.testing.expectEqual(@as(u16, 0xfd00), segs[0]);
}

test "parseIpv6 full address" {
    const segs = parseIpv6("2607:f8b0:4004:0800:0000:0000:0000:200e").?;
    try std.testing.expectEqual(@as(u16, 0x2607), segs[0]);
    try std.testing.expectEqual(@as(u16, 0x200e), segs[7]);
}

test "URL extraction works correctly" {
    try std.testing.expectEqualStrings("example.com", extractHost("https://example.com").?);
    try std.testing.expectEqualStrings("example.com", extractHost("https://example.com:443/path").?);
    try std.testing.expectEqualStrings("sub.example.com", extractHost("http://sub.example.com/").?);
    try std.testing.expect(extractHost("ftp://nope.com") == null);
    try std.testing.expect(extractHost("https:///") == null);
}

test "hostResolvesToLocal blocks decimal and hex loopback aliases" {
    try std.testing.expect(hostResolvesToLocal(std.testing.allocator, "2130706433", 80));
    try std.testing.expect(hostResolvesToLocal(std.testing.allocator, "0x7f000001", 80));
}

test "resolveConnectHost rejects loopback aliases" {
    try std.testing.expectError(error.LocalAddressBlocked, resolveConnectHost(std.testing.allocator, "2130706433", 80));
    try std.testing.expectError(error.LocalAddressBlocked, resolveConnectHost(std.testing.allocator, "0x7f000001", 80));
}

test "hostResolvesToLocal fails closed on resolution error" {
    try std.testing.expect(hostResolvesToLocal(std.testing.allocator, "bad host", 80));
}

test "resolveConnectHost fails on unresolvable host" {
    try std.testing.expectError(error.HostResolutionFailed, resolveConnectHost(std.testing.allocator, "bad host", 80));
}

test "resolveConnectHost returns literal for global ipv4" {
    const resolved = try resolveConnectHost(std.testing.allocator, "8.8.8.8", 443);
    defer std.testing.allocator.free(resolved);
    try std.testing.expectEqualStrings("8.8.8.8", resolved);
}
