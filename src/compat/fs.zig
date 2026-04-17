const std = @import("std");
const builtin = @import("builtin");
const shared = @import("shared.zig");

const Io = std.Io;
const Allocator = std.mem.Allocator;

fn modeFromPermissions(perms: std.Io.File.Permissions) File.Mode {
    if (@hasDecl(@TypeOf(perms), "toMode")) {
        return perms.toMode();
    }
    return 0;
}

pub fn permissionsFromMode(mode: File.Mode) std.Io.File.Permissions {
    return if (@hasDecl(std.Io.File.Permissions, "fromMode"))
        std.Io.File.Permissions.fromMode(mode)
    else
        .default_file;
}

pub const path = struct {
    pub const basename = std.fs.path.basename;
    pub const delimiter = std.fs.path.delimiter;
    pub const dirname = std.fs.path.dirname;
    pub const dirnamePosix = std.fs.path.dirnamePosix;
    pub const dirnameWindows = std.fs.path.dirnameWindows;
    pub const extension = std.fs.path.extension;
    pub const isAbsolute = std.fs.path.isAbsolute;
    pub const isSep = std.fs.path.isSep;
    pub const join = std.fs.path.join;
    pub const joinZ = std.fs.path.joinZ;
    pub const resolve = std.fs.path.resolve;
    pub const sep = std.fs.path.sep;
    pub const sep_str = std.fs.path.sep_str;

    pub fn relative(allocator: Allocator, from: []const u8, to: []const u8) ![]u8 {
        return try std.fs.path.relative(allocator, from, null, from, to);
    }
};

pub const max_path_bytes = std.Io.Dir.max_path_bytes;
pub const has_executable_bit = std.Io.File.Permissions.has_executable_bit;

pub const File = struct {
    handle: std.Io.File.Handle,
    flags: std.Io.File.Flags,

    pub const Handle = std.Io.File.Handle;
    pub const Flags = std.Io.File.Flags;
    pub const Kind = std.Io.File.Kind;
    pub const Mode = if (builtin.os.tag == .windows) u32 else std.posix.mode_t;
    pub const Permissions = std.Io.File.Permissions;
    pub const StatError = std.Io.File.StatError;
    pub const SetTimestampsError = std.Io.File.SetTimestampsError;
    pub const Reader = std.Io.File.Reader;
    pub const Writer = std.Io.File.Writer;

    pub const Stat = struct {
        inode: std.Io.File.INode,
        nlink: std.Io.File.NLink,
        size: u64,
        mode: Mode,
        kind: Kind,
        atime: ?i128,
        mtime: i128,
        ctime: i128,
        block_size: std.Io.File.BlockSize,
    };

    pub fn wrap(inner: std.Io.File) File {
        return .{
            .handle = inner.handle,
            .flags = inner.flags,
        };
    }

    pub fn toInner(self: File) std.Io.File {
        return .{
            .handle = self.handle,
            .flags = self.flags,
        };
    }

    fn convertStat(inner: std.Io.File.Stat) Stat {
        return .{
            .inode = inner.inode,
            .nlink = inner.nlink,
            .size = inner.size,
            .mode = modeFromPermissions(inner.permissions),
            .kind = inner.kind,
            .atime = if (inner.atime) |ts| ts.nanoseconds else null,
            .mtime = inner.mtime.nanoseconds,
            .ctime = inner.ctime.nanoseconds,
            .block_size = inner.block_size,
        };
    }

    pub fn stdout() File {
        return wrap(std.Io.File.stdout());
    }

    pub fn stderr() File {
        return wrap(std.Io.File.stderr());
    }

    pub fn stdin() File {
        return wrap(std.Io.File.stdin());
    }

    pub fn close(self: File) void {
        self.toInner().close(shared.io());
    }

    pub fn isTty(self: File) bool {
        return self.toInner().isTty(shared.io()) catch false;
    }

    pub fn stat(self: File) StatError!Stat {
        return convertStat(try self.toInner().stat(shared.io()));
    }

    pub fn sync(self: File) std.Io.File.SyncError!void {
        try self.toInner().sync(shared.io());
    }

    pub fn seekTo(self: File, offset: u64) std.Io.File.SeekError!void {
        try shared.io().vtable.fileSeekTo(shared.io().userdata, self.toInner(), offset);
    }

    pub fn seekBy(self: File, offset: i64) std.Io.File.SeekError!void {
        try shared.io().vtable.fileSeekBy(shared.io().userdata, self.toInner(), offset);
    }

    pub fn seekFromEnd(self: File, offset: i64) !void {
        const file_stat = try self.stat();
        const end_offset = @as(i128, @intCast(file_stat.size)) + offset;
        if (end_offset < 0) return error.Unseekable;
        try self.seekTo(@intCast(end_offset));
    }

    pub fn chmod(self: File, mode: Mode) std.Io.File.SetPermissionsError!void {
        try self.toInner().setPermissions(shared.io(), permissionsFromMode(mode));
    }

    pub fn writer(self: File, buffer: []u8) Writer {
        return self.toInner().writer(shared.io(), buffer);
    }

    pub fn reader(self: File, buffer: []u8) Reader {
        return self.toInner().reader(shared.io(), buffer);
    }

    pub fn read(self: File, buffer: []u8) std.Io.File.ReadStreamingError!usize {
        return self.toInner().readStreaming(shared.io(), &.{buffer}) catch |err| switch (err) {
            error.EndOfStream => 0,
            else => |e| return e,
        };
    }

    pub fn readAll(self: File, buffer: []u8) std.Io.File.ReadStreamingError!usize {
        var filled: usize = 0;
        while (filled < buffer.len) {
            const amt = try self.read(buffer[filled..]);
            if (amt == 0) break;
            filled += amt;
        }
        return filled;
    }

    pub fn writeAll(self: File, bytes: []const u8) std.Io.File.Writer.Error!void {
        try self.toInner().writeStreamingAll(shared.io(), bytes);
    }

    pub fn readToEndAlloc(self: File, allocator: Allocator, max_bytes: usize) ![]u8 {
        var stream_buf: [4096]u8 = undefined;
        var file_reader = self.toInner().readerStreaming(shared.io(), &stream_buf);
        return try file_reader.interface.allocRemaining(allocator, .limited(max_bytes));
    }

    pub fn updateTimes(self: File, access_ns: i128, modify_ns: i128) SetTimestampsError!void {
        try self.toInner().setTimestamps(shared.io(), .{
            .access_timestamp = .{ .new = .fromNanoseconds(@intCast(access_ns)) },
            .modify_timestamp = .{ .new = .fromNanoseconds(@intCast(modify_ns)) },
        });
    }
};

pub const Dir = struct {
    handle: std.Io.Dir.Handle,

    pub const Handle = std.Io.Dir.Handle;
    pub const OpenDirOptions = std.Io.Dir.OpenOptions;
    pub const OpenFileOptions = std.Io.Dir.OpenFileOptions;
    pub const CreateFileOptions = std.Io.Dir.CreateFileOptions;
    pub const WriteFileOptions = std.Io.Dir.WriteFileOptions;
    pub const AccessOptions = std.Io.Dir.AccessOptions;
    pub const CopyFileOptions = std.Io.Dir.CopyFileOptions;
    pub const Permissions = std.Io.Dir.Permissions;
    pub const SymLinkFlags = std.Io.Dir.SymLinkFlags;
    pub const Entry = std.Io.Dir.Entry;
    pub const Iterator = struct {
        inner: std.Io.Dir.Iterator,

        pub fn next(self: *Iterator) std.Io.Dir.Iterator.Error!?Entry {
            return self.inner.next(shared.io());
        }
    };

    pub fn wrap(inner: std.Io.Dir) Dir {
        return .{ .handle = inner.handle };
    }

    fn toInner(self: Dir) std.Io.Dir {
        return .{ .handle = self.handle };
    }

    pub fn cwd() Dir {
        return wrap(std.Io.Dir.cwd());
    }

    pub fn close(self: Dir) void {
        self.toInner().close(shared.io());
    }

    pub fn iterate(self: Dir) Iterator {
        return .{ .inner = self.toInner().iterate() };
    }

    pub fn openDir(self: Dir, sub_path: []const u8, options: OpenDirOptions) std.Io.Dir.OpenError!Dir {
        return wrap(try self.toInner().openDir(shared.io(), sub_path, options));
    }

    pub fn openFile(self: Dir, sub_path: []const u8, options: OpenFileOptions) std.Io.File.OpenError!File {
        return File.wrap(try self.toInner().openFile(shared.io(), sub_path, options));
    }

    pub fn createFile(self: Dir, sub_path: []const u8, options: CreateFileOptions) std.Io.File.OpenError!File {
        return File.wrap(try self.toInner().createFile(shared.io(), sub_path, options));
    }

    pub fn writeFile(self: Dir, options: WriteFileOptions) std.Io.Dir.WriteFileError!void {
        try self.toInner().writeFile(shared.io(), options);
    }

    pub fn copyFile(
        self: Dir,
        source_path: []const u8,
        dest_dir: Dir,
        dest_path: []const u8,
        options: CopyFileOptions,
    ) std.Io.Dir.CopyFileError!void {
        try self.toInner().copyFile(source_path, dest_dir.toInner(), dest_path, shared.io(), options);
    }

    pub fn readFileAlloc(self: Dir, allocator: Allocator, sub_path: []const u8, max_bytes: usize) ![]u8 {
        return try self.toInner().readFileAlloc(shared.io(), sub_path, allocator, .limited(max_bytes));
    }

    pub fn access(self: Dir, sub_path: []const u8, options: AccessOptions) std.Io.Dir.AccessError!void {
        try self.toInner().access(shared.io(), sub_path, options);
    }

    pub fn makeDir(self: Dir, sub_path: []const u8) std.Io.Dir.CreateDirError!void {
        try self.toInner().createDir(shared.io(), sub_path, .default_dir);
    }

    pub fn deleteFile(self: Dir, sub_path: []const u8) std.Io.Dir.DeleteFileError!void {
        try self.toInner().deleteFile(shared.io(), sub_path);
    }

    pub fn deleteTree(self: Dir, sub_path: []const u8) std.Io.Dir.DeleteTreeError!void {
        try self.toInner().deleteTree(shared.io(), sub_path);
    }

    pub fn rename(self: Dir, old_sub_path: []const u8, new_sub_path: []const u8) std.Io.Dir.RenameError!void {
        try self.toInner().rename(old_sub_path, self.toInner(), new_sub_path, shared.io());
    }

    pub fn readLink(self: Dir, sub_path: []const u8, buffer: []u8) std.Io.Dir.ReadLinkError![]const u8 {
        const n = try self.toInner().readLink(shared.io(), sub_path, buffer);
        return buffer[0..n];
    }

    pub fn symLink(self: Dir, target_path: []const u8, sym_link_path: []const u8, flags: SymLinkFlags) std.Io.Dir.SymLinkError!void {
        try self.toInner().symLink(shared.io(), target_path, sym_link_path, flags);
    }

    pub fn hardLink(
        self: Dir,
        old_sub_path: []const u8,
        new_dir: Dir,
        new_sub_path: []const u8,
        options: std.Io.Dir.HardLinkOptions,
    ) std.Io.Dir.HardLinkError!void {
        try self.toInner().hardLink(old_sub_path, new_dir.toInner(), new_sub_path, shared.io(), options);
    }

    pub fn realpathAlloc(self: Dir, allocator: Allocator, sub_path: []const u8) std.Io.Dir.RealPathFileAllocError![]u8 {
        const path_z = try self.toInner().realPathFileAlloc(shared.io(), sub_path, allocator);
        defer allocator.free(path_z);
        return try allocator.dupe(u8, path_z);
    }

    pub fn realpath(self: Dir, sub_path: []const u8, buffer: []u8) std.Io.Dir.RealPathFileError![]const u8 {
        const n = try self.toInner().realPathFile(shared.io(), sub_path, buffer);
        return buffer[0..n];
    }

    pub fn statFile(self: Dir, sub_path: []const u8) !File.Stat {
        const inner = try self.toInner().statFile(shared.io(), sub_path, .{});
        return File.convertStat(inner);
    }

    pub fn makePath(self: Dir, sub_path: []const u8) !void {
        if (sub_path.len == 0) return;
        if (path.isAbsolute(sub_path)) {
            makeDirAbsolute(sub_path) catch |err| switch (err) {
                error.PathAlreadyExists => return,
                else => |e| return e,
            };
            return;
        }

        var cursor = self;
        var opened: ?Dir = null;
        defer if (opened) |dir| dir.close();

        var index: usize = 0;
        while (index < sub_path.len) {
            while (index < sub_path.len and path.isSep(sub_path[index])) : (index += 1) {}
            if (index >= sub_path.len) break;

            const start = index;
            while (index < sub_path.len and !path.isSep(sub_path[index])) : (index += 1) {}
            const component = sub_path[start..index];
            if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
            if (std.mem.eql(u8, component, "..")) return error.BadPathName;

            cursor.makeDir(component) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => |e| return e,
            };

            const next = try cursor.openDir(component, .{});
            if (opened) |dir| dir.close();
            opened = next;
            cursor = next;
        }
    }
};

pub fn wrapDir(dir: std.Io.Dir) Dir {
    return Dir.wrap(dir);
}

pub fn cwd() Dir {
    return Dir.cwd();
}

pub fn openDirAbsolute(absolute_path: []const u8, options: Dir.OpenDirOptions) std.Io.Dir.OpenError!Dir {
    return Dir.wrap(try std.Io.Dir.openDirAbsolute(shared.io(), absolute_path, options));
}

pub fn openFileAbsolute(absolute_path: []const u8, options: Dir.OpenFileOptions) std.Io.File.OpenError!File {
    return File.wrap(try std.Io.Dir.openFileAbsolute(shared.io(), absolute_path, options));
}

pub fn accessAbsolute(absolute_path: []const u8, options: Dir.AccessOptions) std.Io.Dir.AccessError!void {
    try std.Io.Dir.accessAbsolute(shared.io(), absolute_path, options);
}

pub fn createFileAbsolute(absolute_path: []const u8, options: Dir.CreateFileOptions) std.Io.File.OpenError!File {
    return File.wrap(try std.Io.Dir.createFileAbsolute(shared.io(), absolute_path, options));
}

pub fn makeDirAbsolute(absolute_path: []const u8) std.Io.Dir.CreateDirError!void {
    try std.Io.Dir.createDirAbsolute(shared.io(), absolute_path, .default_dir);
}

pub fn deleteFileAbsolute(absolute_path: []const u8) std.Io.Dir.DeleteFileError!void {
    try std.Io.Dir.deleteFileAbsolute(shared.io(), absolute_path);
}

pub fn deleteDirAbsolute(absolute_path: []const u8) std.Io.Dir.DeleteDirError!void {
    try std.Io.Dir.deleteDirAbsolute(shared.io(), absolute_path);
}

pub fn deleteTreeAbsolute(absolute_path: []const u8) (std.Io.Dir.DeleteTreeError || error{FileNotFound})!void {
    const dir_path = path.dirname(absolute_path) orelse return error.FileNotFound;
    const base_name = path.basename(absolute_path);
    var dir = try openDirAbsolute(dir_path, .{});
    defer dir.close();
    try dir.deleteTree(base_name);
}

pub fn renameAbsolute(old_path: []const u8, new_path: []const u8) std.Io.Dir.RenameError!void {
    try std.Io.Dir.renameAbsolute(old_path, new_path, shared.io());
}

pub fn hardLinkAbsolute(
    old_path: []const u8,
    new_path: []const u8,
    options: std.Io.Dir.HardLinkOptions,
) std.Io.Dir.HardLinkError!void {
    const cwd_dir = std.Io.Dir.cwd();
    try cwd_dir.hardLink(old_path, cwd_dir, new_path, shared.io(), options);
}

fn resolveSelfExeInto(out_buffer: []u8) (error{OperationUnsupported} || std.Io.Dir.RealPathFileError || std.Io.Dir.ReadLinkError)!usize {
    return switch (builtin.os.tag) {
        .driverkit,
        .ios,
        .maccatalyst,
        .macos,
        .tvos,
        .visionos,
        .watchos,
        => blk: {
            if (!builtin.link_libc) return error.OperationUnsupported;
            var symlink_path_buf: [std.posix.PATH_MAX + 1]u8 = undefined;
            var n: u32 = symlink_path_buf.len;
            if (std.c._NSGetExecutablePath(&symlink_path_buf, &n) != 0) return error.NameTooLong;
            const symlink_path = std.mem.sliceTo(&symlink_path_buf, 0);
            break :blk try std.Io.Dir.realPathFileAbsolute(shared.io(), symlink_path, out_buffer);
        },
        .linux, .serenity => try std.Io.Dir.readLinkAbsolute(shared.io(), "/proc/self/exe", out_buffer),
        .illumos => try std.Io.Dir.readLinkAbsolute(shared.io(), "/proc/self/path/a.out", out_buffer),
        .windows => blk: {
            const image_path = std.os.windows.peb().ProcessParameters.ImagePathName.sliceZ();
            const len = std.unicode.calcWtf8Len(image_path);
            if (len > out_buffer.len) return error.NameTooLong;
            break :blk std.unicode.wtf16LeToWtf8(out_buffer, image_path);
        },
        else => error.OperationUnsupported,
    };
}

fn resolveArg0FallbackAlloc(allocator: Allocator) ![]u8 {
    const args = shared.argsAlloc(allocator) catch |err| switch (err) {
        error.MissingProcessContext => return error.FileNotFound,
        else => |e| return e,
    };
    defer shared.argsFree(allocator, args);

    if (args.len == 0) return error.FileNotFound;
    const arg0 = args[0];
    if (arg0.len == 0) return error.FileNotFound;

    if (path.isAbsolute(arg0) or std.mem.indexOfAny(u8, arg0, "/\\") != null) {
        return try realpathAlloc(allocator, arg0);
    }

    const env_path = shared.environ().getAlloc(allocator, "PATH") catch |err| switch (err) {
        error.EnvironmentVariableMissing => return error.FileNotFound,
        else => |e| return e,
    };
    defer allocator.free(env_path);

    var path_iter = std.mem.tokenizeScalar(u8, env_path, path.delimiter);
    while (path_iter.next()) |dir_name| {
        const candidate = try path.join(allocator, &.{ dir_name, arg0 });
        defer allocator.free(candidate);

        return realpathAlloc(allocator, candidate) catch |err| switch (err) {
            error.AccessDenied,
            error.BadPathName,
            error.FileNotFound,
            error.InputOutput,
            error.NameTooLong,
            error.NotDir,
            error.OperationUnsupported,
            error.SymLinkLoop,
            => continue,
            else => |e| return e,
        };
    }

    return error.FileNotFound;
}

pub fn selfExePathAlloc(allocator: Allocator) ![]u8 {
    if (builtin.is_test) {
        // Keep tests deterministic; runtime code still uses the real OS-backed path.
        return try allocator.dupe(u8, "zig-out/bin/nullclaw");
    }

    var out_buffer: [max_path_bytes]u8 = undefined;
    if (resolveSelfExeInto(&out_buffer)) |n| {
        return try allocator.dupe(u8, out_buffer[0..n]);
    } else |err| switch (err) {
        error.OperationUnsupported => return resolveArg0FallbackAlloc(allocator),
        else => return err,
    }
}

pub fn selfExePath(out_buffer: []u8) ![]u8 {
    const exe_path = try selfExePathAlloc(std.heap.page_allocator);
    defer std.heap.page_allocator.free(exe_path);
    if (exe_path.len > out_buffer.len) return error.NameTooLong;
    @memcpy(out_buffer[0..exe_path.len], exe_path);
    return out_buffer[0..exe_path.len];
}

pub fn realpathAlloc(allocator: Allocator, file_path: []const u8) ![]u8 {
    if (path.isAbsolute(file_path)) {
        const path_z = try std.Io.Dir.realPathFileAbsoluteAlloc(shared.io(), file_path, allocator);
        defer allocator.free(path_z);
        return try allocator.dupe(u8, path_z);
    }
    return try cwd().realpathAlloc(allocator, file_path);
}

test "compat fs resolves argv0 through PATH fallback" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    const exe_name = "nullclaw-test";
    const exe_path = try path.join(std.testing.allocator, &.{ base, exe_name });
    defer std.testing.allocator.free(exe_path);

    const file = try createFileAbsolute(exe_path, .{});
    file.close();

    const resolved = try resolveArg0FallbackAllocForTest(std.testing.allocator, exe_name, base);
    defer std.testing.allocator.free(resolved);

    try std.testing.expectEqualStrings(exe_path, resolved);
}

fn resolveArg0FallbackAllocForTest(allocator: Allocator, arg0: []const u8, env_path: []const u8) ![]u8 {
    if (path.isAbsolute(arg0) or std.mem.indexOfAny(u8, arg0, "/\\") != null) {
        return try realpathAlloc(allocator, arg0);
    }

    var path_iter = std.mem.tokenizeScalar(u8, env_path, path.delimiter);
    while (path_iter.next()) |dir_name| {
        const candidate = try path.join(allocator, &.{ dir_name, arg0 });
        defer allocator.free(candidate);

        return realpathAlloc(allocator, candidate) catch |err| switch (err) {
            error.AccessDenied,
            error.BadPathName,
            error.FileNotFound,
            error.InputOutput,
            error.NameTooLong,
            error.NotDir,
            error.OperationUnsupported,
            error.SymLinkLoop,
            => continue,
            else => |e| return e,
        };
    }

    return error.FileNotFound;
}
