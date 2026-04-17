const std = @import("std");
const builtin = @import("builtin");
const shared = @import("compat/shared.zig");

const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn initProcess(init: std.process.Init) void {
    shared.initProcess(init);
}

pub fn initProcessMinimal(init: std.process.Init.Minimal) void {
    shared.initProcessMinimal(init);
}

pub fn io() Io {
    return shared.io();
}

fn environ() std.process.Environ {
    return shared.environ();
}

pub const fs = @import("compat/fs.zig");

pub const process = struct {
    pub const EnvMap = std.process.Environ.Map;
    pub const ArgIteratorWindows = std.process.Args.Iterator.Windows;
    pub const GetEnvVarOwnedError = error{
        EnvironmentVariableNotFound,
    } || Allocator.Error || error{ InvalidWtf8, Unexpected };

    pub fn exit(code: u8) noreturn {
        std.process.exit(code);
    }

    pub fn getEnvVarOwned(allocator: Allocator, name: []const u8) GetEnvVarOwnedError![]u8 {
        return environ().getAlloc(allocator, name) catch |err| switch (err) {
            error.EnvironmentVariableMissing => error.EnvironmentVariableNotFound,
            else => |e| e,
        };
    }

    pub fn argsAlloc(allocator: Allocator) ![]const [:0]const u8 {
        return shared.argsAlloc(allocator);
    }

    pub fn argsFree(allocator: Allocator, args: []const [:0]const u8) void {
        shared.argsFree(allocator, args);
    }

    pub const Child = struct {
        allocator: Allocator,
        argv: []const []const u8,
        env_map: ?*const EnvMap = null,
        cwd: ?[]const u8 = null,
        stdin_behavior: StdIo = .Inherit,
        stdout_behavior: StdIo = .Inherit,
        stderr_behavior: StdIo = .Inherit,
        request_resource_usage_statistics: bool = false,
        pgid: ?std.posix.pid_t = null,
        create_no_window: bool = true,
        id: Id = undefined,
        thread_handle: if (builtin.os.tag == .windows) std.os.windows.HANDLE else void = if (builtin.os.tag == .windows) undefined else {},
        stdin: ?fs.File = null,
        stdout: ?fs.File = null,
        stderr: ?fs.File = null,
        term: ?Term = null,

        pub const Id = std.process.Child.Id;
        pub const Term = std.process.Child.Term;
        pub const ResourceUsageStatistics = std.process.Child.ResourceUsageStatistics;
        pub const WindowsExtension = enum { bat, cmd, com, exe };
        pub const StdIo = enum { Inherit, Ignore, Pipe, Close };

        pub const RunResult = std.process.RunResult;
        pub const RunOptions = struct {
            allocator: Allocator,
            argv: []const []const u8,
            max_output_bytes: usize = 50 * 1024,
            cwd: ?[]const u8 = null,
            env_map: ?*const EnvMap = null,
            expand_arg0: std.process.ArgExpansion = .no_expand,
            create_no_window: bool = true,
            disable_aslr: bool = false,
        };

        pub fn init(argv: []const []const u8, allocator: Allocator) Child {
            return .{
                .allocator = allocator,
                .argv = argv,
            };
        }

        fn mapStdIo(kind: StdIo) std.process.SpawnOptions.StdIo {
            return switch (kind) {
                .Inherit => .inherit,
                .Ignore => .ignore,
                .Pipe => .pipe,
                .Close => .close,
            };
        }

        fn spawnCwd(self: *const Child) std.process.Child.Cwd {
            return if (self.cwd) |path_value| .{ .path = path_value } else .inherit;
        }

        fn toInner(self: *const Child) std.process.Child {
            return .{
                .id = self.id,
                .thread_handle = self.thread_handle,
                .stdin = if (self.stdin) |file| file.toInner() else null,
                .stdout = if (self.stdout) |file| file.toInner() else null,
                .stderr = if (self.stderr) |file| file.toInner() else null,
                .resource_usage_statistics = .{},
                .request_resource_usage_statistics = self.request_resource_usage_statistics,
            };
        }

        fn syncFromInner(self: *Child, inner: std.process.Child) void {
            self.stdin = if (inner.stdin) |file| fs.File.wrap(file) else null;
            self.stdout = if (inner.stdout) |file| fs.File.wrap(file) else null;
            self.stderr = if (inner.stderr) |file| fs.File.wrap(file) else null;
        }

        pub fn spawn(self: *Child) !void {
            const inner = try std.process.spawn(io(), .{
                .argv = self.argv,
                .cwd = self.spawnCwd(),
                .environ_map = self.env_map,
                .stdin = mapStdIo(self.stdin_behavior),
                .stdout = mapStdIo(self.stdout_behavior),
                .stderr = mapStdIo(self.stderr_behavior),
                .request_resource_usage_statistics = self.request_resource_usage_statistics,
                .pgid = self.pgid,
                .create_no_window = self.create_no_window,
            });
            self.id = inner.id.?;
            self.thread_handle = inner.thread_handle;
            self.syncFromInner(inner);
            self.term = null;
        }

        pub fn wait(self: *Child) !Term {
            if (self.term) |term| return term;

            var inner = self.toInner();
            const term = try inner.wait(io());
            self.syncFromInner(inner);
            self.term = term;
            return term;
        }

        pub fn kill(self: *Child) !Term {
            if (self.term) |term| return term;

            var inner = self.toInner();
            inner.kill(io());
            self.syncFromInner(inner);

            const term: Term = if (builtin.os.tag == .windows)
                .{ .exited = 1 }
            else
                .{ .signal = std.posix.SIG.KILL };

            self.term = term;
            return term;
        }

        pub fn spawnAndWait(self: *Child) !Term {
            try self.spawn();
            return try self.wait();
        }

        pub fn run(options: RunOptions) !RunResult {
            return try std.process.run(options.allocator, io(), .{
                .argv = options.argv,
                .stdout_limit = .limited(options.max_output_bytes),
                .stderr_limit = .limited(options.max_output_bytes),
                .cwd = if (options.cwd) |path_value| .{ .path = path_value } else .inherit,
                .environ_map = options.env_map,
                .expand_arg0 = options.expand_arg0,
                .create_no_window = options.create_no_window,
                .disable_aslr = options.disable_aslr,
            });
        }
    };
};

pub const time = struct {
    fn nowNanoseconds() i128 {
        return switch (builtin.os.tag) {
            .windows => blk: {
                const epoch_ns = std.time.epoch.windows * std.time.ns_per_s;
                break :blk @as(i128, std.os.windows.ntdll.RtlGetSystemTimePrecise()) * 100 + epoch_ns;
            },
            .wasi => blk: {
                var ts: std.os.wasi.timestamp_t = undefined;
                if (std.os.wasi.clock_time_get(.REALTIME, 1, &ts) == .SUCCESS) {
                    break :blk @intCast(ts);
                }
                break :blk 0;
            },
            else => blk: {
                var ts: std.posix.timespec = undefined;
                switch (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts))) {
                    .SUCCESS => break :blk @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec,
                    else => break :blk 0,
                }
            },
        };
    }

    pub fn timestamp() i64 {
        return @intCast(@divTrunc(nowNanoseconds(), std.time.ns_per_s));
    }

    pub fn milliTimestamp() i64 {
        return @intCast(@divTrunc(nowNanoseconds(), std.time.ns_per_ms));
    }

    pub fn microTimestamp() i64 {
        return @intCast(@divTrunc(nowNanoseconds(), std.time.ns_per_us));
    }

    pub fn nanoTimestamp() i128 {
        return nowNanoseconds();
    }
};

pub const thread = struct {
    pub fn sleep(nanoseconds: u64) void {
        std.Io.sleep(io(), .fromNanoseconds(@intCast(nanoseconds)), .awake) catch {};
    }
};

pub const crypto = struct {
    pub const random = struct {
        pub fn bytes(buffer: []u8) void {
            std.Io.randomSecure(io(), buffer) catch std.Io.random(io(), buffer);
        }

        pub fn int(comptime T: type) T {
            var bytes_buf: [@sizeOf(T)]u8 = undefined;
            bytes(&bytes_buf);
            return std.mem.readInt(T, &bytes_buf, .little);
        }
    };
};

pub const mem = struct {
    pub fn trimLeft(comptime T: type, slice: []const T, values_to_strip: []const T) []const T {
        return std.mem.trimStart(T, slice, values_to_strip);
    }

    pub fn trimRight(comptime T: type, slice: []const T, values_to_strip: []const T) []const T {
        return std.mem.trimEnd(T, slice, values_to_strip);
    }
};

pub const net = @import("compat/net.zig");

pub const sync = struct {
    pub const Mutex = struct {
        inner: std.Io.Mutex = .init,

        pub fn tryLock(self: *Mutex) bool {
            return self.inner.tryLock();
        }

        pub fn lock(self: *Mutex) void {
            self.inner.lockUncancelable(io());
        }

        pub fn unlock(self: *Mutex) void {
            self.inner.unlock(io());
        }
    };

    pub const Condition = struct {
        inner: std.Io.Condition = .init,

        pub fn wait(self: *Condition, mutex: *Mutex) void {
            self.inner.waitUncancelable(io(), &mutex.inner);
        }

        pub fn signal(self: *Condition) void {
            self.inner.signal(io());
        }

        pub fn broadcast(self: *Condition) void {
            self.inner.broadcast(io());
        }
    };
};
