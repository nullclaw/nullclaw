const std = @import("std");
const std_compat = @import("compat");

pub fn writeStdoutBytes(text: []const u8) !void {
    try std_compat.fs.File.stdout().writeAll(text);
}

pub fn renderBytes(
    allocator: std.mem.Allocator,
    comptime render_fn: anytype,
    args: anytype,
) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    var out_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &out);
    try @call(.auto, render_fn, .{&out_writer.writer} ++ args);
    out = out_writer.toArrayList();
    return try out.toOwnedSlice(allocator);
}

pub fn writeRendered(
    allocator: std.mem.Allocator,
    comptime render_fn: anytype,
    args: anytype,
) !void {
    const rendered = try renderBytes(allocator, render_fn, args);
    defer allocator.free(rendered);
    try writeStdoutBytes(rendered);
}

pub fn writeRenderedLine(
    allocator: std.mem.Allocator,
    comptime render_fn: anytype,
    args: anytype,
) !void {
    try writeRendered(allocator, render_fn, args);
    try writeStdoutBytes("\n");
}

test "renderBytes scales past fixed stack buffers" {
    const allocator = std.testing.allocator;

    const rendered = try renderBytes(allocator, struct {
        fn render(out: anytype, count: usize) !void {
            for (0..count) |_| {
                try out.writeByte('x');
            }
        }
    }.render, .{80_000});
    defer allocator.free(rendered);

    try std.testing.expectEqual(@as(usize, 80_000), rendered.len);
    try std.testing.expect(rendered[0] == 'x');
    try std.testing.expect(rendered[rendered.len - 1] == 'x');
}
