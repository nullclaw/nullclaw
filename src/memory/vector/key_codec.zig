const std = @import("std");

pub const DecodedVectorKey = struct {
    logical_key: []const u8,
    session_id: ?[]const u8,
    is_legacy: bool,
};

pub fn encode(allocator: std.mem.Allocator, logical_key: []const u8, session_id: ?[]const u8) ![]u8 {
    if (session_id) |sid| {
        return std.fmt.allocPrint(allocator, "s:{d}:{s}:{s}", .{ sid.len, sid, logical_key });
    }
    return std.fmt.allocPrint(allocator, "g:{s}", .{logical_key});
}

pub fn decode(stored_key: []const u8) DecodedVectorKey {
    if (std.mem.startsWith(u8, stored_key, "g:")) {
        return .{
            .logical_key = stored_key[2..],
            .session_id = null,
            .is_legacy = false,
        };
    }
    if (!std.mem.startsWith(u8, stored_key, "s:")) {
        return .{
            .logical_key = stored_key,
            .session_id = null,
            .is_legacy = true,
        };
    }

    const rest = stored_key[2..];
    const len_sep = std.mem.indexOfScalar(u8, rest, ':') orelse {
        return .{
            .logical_key = stored_key,
            .session_id = null,
            .is_legacy = true,
        };
    };
    const sid_len = std.fmt.parseInt(usize, rest[0..len_sep], 10) catch {
        return .{
            .logical_key = stored_key,
            .session_id = null,
            .is_legacy = true,
        };
    };
    const sid_start = 2 + len_sep + 1;
    const key_start = sid_start + sid_len;
    if (sid_len == 0 or key_start >= stored_key.len or stored_key[key_start] != ':') {
        return .{
            .logical_key = stored_key,
            .session_id = null,
            .is_legacy = true,
        };
    }

    return .{
        .logical_key = stored_key[key_start + 1 ..],
        .session_id = stored_key[sid_start..key_start],
        .is_legacy = false,
    };
}

test "vector key codec round-trips global key" {
    const allocator = std.testing.allocator;
    const encoded = try encode(allocator, "pref.theme", null);
    defer allocator.free(encoded);

    try std.testing.expectEqualStrings("g:pref.theme", encoded);
    const decoded = decode(encoded);
    try std.testing.expectEqualStrings("pref.theme", decoded.logical_key);
    try std.testing.expect(decoded.session_id == null);
    try std.testing.expect(!decoded.is_legacy);
}

test "vector key codec round-trips scoped key" {
    const allocator = std.testing.allocator;
    const encoded = try encode(allocator, "pref.theme", "agent:coder");
    defer allocator.free(encoded);

    const decoded = decode(encoded);
    try std.testing.expectEqualStrings("pref.theme", decoded.logical_key);
    try std.testing.expect(decoded.session_id != null);
    try std.testing.expectEqualStrings("agent:coder", decoded.session_id.?);
    try std.testing.expect(!decoded.is_legacy);
}

test "vector key codec treats unknown format as legacy" {
    const decoded = decode("pref.theme");
    try std.testing.expectEqualStrings("pref.theme", decoded.logical_key);
    try std.testing.expect(decoded.session_id == null);
    try std.testing.expect(decoded.is_legacy);
}
