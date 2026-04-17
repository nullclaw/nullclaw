const std = @import("std");

pub fn isUnreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
}

pub fn appendPercentEncodedWriter(writer: anytype, text: []const u8) !void {
    var out = writer;
    for (text) |c| {
        if (isUnreserved(c)) {
            try out.writeByte(c);
        } else {
            const upper = "0123456789ABCDEF";
            var esc: [3]u8 = .{
                '%',
                upper[(c >> 4) & 0x0F],
                upper[c & 0x0F],
            };
            try out.writeAll(&esc);
        }
    }
}

pub fn appendPercentEncodedList(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    text: []const u8,
) !void {
    for (text) |c| {
        if (isUnreserved(c)) {
            try buf.append(allocator, c);
        } else {
            const upper = "0123456789ABCDEF";
            try buf.appendSlice(allocator, &.{ '%', upper[(c >> 4) & 0x0F], upper[c & 0x0F] });
        }
    }
}

pub fn encode(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    try appendPercentEncodedList(&buf, allocator, text);
    return buf.toOwnedSlice(allocator);
}

test "url_percent encode leaves unreserved as-is" {
    const alloc = std.testing.allocator;
    const encoded = try encode(alloc, "hello-world_2.0~test");
    defer alloc.free(encoded);
    try std.testing.expectEqualStrings("hello-world_2.0~test", encoded);
}

test "url_percent encode percent-encodes reserved bytes" {
    const alloc = std.testing.allocator;
    const encoded = try encode(alloc, "a b/c?");
    defer alloc.free(encoded);
    try std.testing.expectEqualStrings("a%20b%2Fc%3F", encoded);
}

test "url_percent appendPercentEncodedWriter percent-encodes bytes" {
    var out: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    try appendPercentEncodedWriter(&writer, "x/y z");
    try std.testing.expectEqualStrings("x%2Fy%20z", writer.buffered());
}
