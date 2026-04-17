const std = @import("std");
const builtin = @import("builtin");

pub const Io = std.Io;
pub const Allocator = std.mem.Allocator;

var fallback_threaded: Io.Threaded = .init_single_threaded;
var process_io: ?Io = null;
var process_args: ?std.process.Args = null;
var process_environ: ?std.process.Environ = null;

pub fn initProcess(init: std.process.Init) void {
    process_io = init.io;
    process_args = init.minimal.args;
    process_environ = init.minimal.environ;
}

pub fn initProcessMinimal(init: std.process.Init.Minimal) void {
    process_args = init.args;
    process_environ = init.environ;
}

pub fn io() Io {
    if (builtin.is_test) return std.testing.io;
    if (process_io) |current| return current;
    return fallback_threaded.io();
}

pub fn environ() std.process.Environ {
    if (process_environ) |env| return env;
    return switch (builtin.os.tag) {
        .windows, .freestanding, .other => .{ .block = .global },
        .wasi, .emscripten => if (builtin.link_libc) blk: {
            const c_environ = std.c.environ;
            var env_count: usize = 0;
            while (c_environ[env_count] != null) : (env_count += 1) {}
            break :blk .{ .block = .{ .slice = c_environ[0..env_count :null] } };
        } else .{ .block = .global },
        else => blk: {
            const c_environ = std.c.environ;
            var env_count: usize = 0;
            while (c_environ[env_count] != null) : (env_count += 1) {}
            break :blk .{ .block = .{ .slice = c_environ[0..env_count :null] } };
        },
    };
}

pub fn argsAlloc(allocator: Allocator) ![]const [:0]const u8 {
    const args = process_args orelse return error.MissingProcessContext;
    var iter = try args.iterateAllocator(allocator);
    defer iter.deinit();

    var list: std.ArrayList([:0]const u8) = .empty;
    errdefer {
        for (list.items) |arg| allocator.free(arg);
        list.deinit(allocator);
    }

    while (iter.next()) |arg| {
        try list.append(allocator, try allocator.dupeZ(u8, arg));
    }

    return try list.toOwnedSlice(allocator);
}

pub fn argsFree(allocator: Allocator, args: []const [:0]const u8) void {
    for (args) |arg| allocator.free(arg);
    allocator.free(args);
}
