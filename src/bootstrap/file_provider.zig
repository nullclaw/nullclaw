// src/bootstrap/file_provider.zig
const std = @import("std");
const provider = @import("provider.zig");
const BootstrapProvider = provider.BootstrapProvider;
const isBootstrapFilename = provider.isBootstrapFilename;
const memory_root = @import("../memory/root.zig");

pub const Error = error{NotBootstrapFile};

/// Disk-based BootstrapProvider for hybrid/markdown backends.
/// Stores bootstrap documents as files in the workspace directory.
pub const FileBootstrapProvider = struct {
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    owns_self: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, workspace_dir: []const u8) Self {
        return .{
            .allocator = allocator,
            .workspace_dir = workspace_dir,
        };
    }

    pub fn provider(self: *Self) BootstrapProvider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = BootstrapProvider.VTable{
        .load = load,
        .load_excerpt = load_excerpt,
        .store = store,
        .remove = remove,
        .exists = exists,
        .list = list,
        .fingerprint = fingerprint,
        .deinit = deinitFn,
    };

    fn load(ptr: *anyopaque, allocator: std.mem.Allocator, filename: []const u8) anyerror!?[]const u8 {
        const self = castSelf(ptr);
        if (!isBootstrapFilename(filename)) return Error.NotBootstrapFile;

        const path = try std.fs.path.join(allocator, &.{ self.workspace_dir, filename });
        defer allocator.free(path);

        var file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer file.close();

        return try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    }

    fn load_excerpt(ptr: *anyopaque, allocator: std.mem.Allocator, filename: []const u8, max_bytes: usize) anyerror!?[]const u8 {
        const self = castSelf(ptr);
        if (!isBootstrapFilename(filename)) return Error.NotBootstrapFile;

        const path = try std.fs.path.join(allocator, &.{ self.workspace_dir, filename });
        defer allocator.free(path);

        var file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer file.close();

        return try read_file_excerpt(allocator, &file, max_bytes);
    }

    fn store(ptr: *anyopaque, filename: []const u8, content: []const u8) anyerror!void {
        const self = castSelf(ptr);
        if (!isBootstrapFilename(filename)) return Error.NotBootstrapFile;

        const path = try std.fs.path.join(self.allocator, &.{ self.workspace_dir, filename });
        defer self.allocator.free(path);

        const file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
        defer file.close();

        try file.writeAll(content);
    }

    fn remove(ptr: *anyopaque, filename: []const u8) anyerror!bool {
        const self = castSelf(ptr);
        if (!isBootstrapFilename(filename)) return Error.NotBootstrapFile;

        const path = try std.fs.path.join(self.allocator, &.{ self.workspace_dir, filename });
        defer self.allocator.free(path);

        std.fs.deleteFileAbsolute(path) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        return true;
    }

    fn exists(ptr: *anyopaque, filename: []const u8) bool {
        const self = castSelf(ptr);
        if (!isBootstrapFilename(filename)) return false;

        const path = std.fs.path.join(self.allocator, &.{ self.workspace_dir, filename }) catch return false;
        defer self.allocator.free(path);

        std.fs.accessAbsolute(path, .{}) catch return false;
        return true;
    }

    fn list(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]const []const u8 {
        const self = castSelf(ptr);
        var result = std.ArrayListUnmanaged([]const u8).empty;

        for (memory_root.prompt_bootstrap_docs) |doc| {
            const path = try std.fs.path.join(allocator, &.{ self.workspace_dir, doc.filename });
            defer allocator.free(path);

            std.fs.accessAbsolute(path, .{}) catch continue;
            try result.append(allocator, try allocator.dupe(u8, doc.filename));
        }

        return try result.toOwnedSlice(allocator);
    }

    fn fingerprint(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror!u64 {
        const self = castSelf(ptr);
        var hasher = std.hash.Fnv1a_64.init();

        for (memory_root.prompt_bootstrap_docs) |doc| {
            hasher.update(doc.filename);
            hasher.update("\n");

            const path = try std.fs.path.join(allocator, &.{ self.workspace_dir, doc.filename });
            defer allocator.free(path);

            const file = std.fs.openFileAbsolute(path, .{}) catch {
                hasher.update("missing");
                continue;
            };
            defer file.close();

            const content = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
            defer allocator.free(content);

            hasher.update("present");
            hasher.update(content);
        }

        return hasher.final();
    }

    fn deinitFn(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        if (self.owns_self) {
            self.allocator.destroy(self);
        }
    }

    fn castSelf(ptr: *anyopaque) *Self {
        return @ptrCast(@alignCast(ptr));
    }
};

fn read_file_excerpt(allocator: std.mem.Allocator, file: *std.fs.File, max_bytes: usize) ![]const u8 {
    const buf = try allocator.alloc(u8, max_bytes);
    errdefer allocator.free(buf);

    const read_len = try file.readAll(buf);
    return shrink_alloc(allocator, buf, read_len);
}

fn shrink_alloc(allocator: std.mem.Allocator, slice: []u8, new_len: usize) ![]u8 {
    if (new_len >= slice.len) return slice;
    return allocator.realloc(slice, new_len) catch blk: {
        const fresh = try allocator.alloc(u8, new_len);
        @memcpy(fresh, slice[0..new_len]);
        allocator.free(slice);
        break :blk fresh;
    };
}

// --- Tests ---

const testing = std.testing;

fn setupTestProvider(tmp: *std.testing.TmpDir) !struct { provider: FileBootstrapProvider, workspace: []const u8 } {
    const workspace = try tmp.dir.realpathAlloc(testing.allocator, ".");
    return .{
        .provider = .{
            .allocator = testing.allocator,
            .workspace_dir = workspace,
        },
        .workspace = workspace,
    };
}

test "store then load returns content" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = try setupTestProvider(&tmp);
    defer testing.allocator.free(ctx.workspace);

    var bp = ctx.provider.provider();

    try bp.store("AGENTS.md", "hello world");
    const content = try bp.load(testing.allocator, "AGENTS.md");
    defer if (content) |c| testing.allocator.free(c);

    try testing.expectEqualStrings("hello world", content.?);
}

test "load missing returns null" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = try setupTestProvider(&tmp);
    defer testing.allocator.free(ctx.workspace);

    var bp = ctx.provider.provider();

    const content = try bp.load(testing.allocator, "SOUL.md");
    try testing.expect(content == null);
}

test "load_excerpt returns prefix for oversized file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = try setupTestProvider(&tmp);
    defer testing.allocator.free(ctx.workspace);

    var bp = ctx.provider.provider();

    try bp.store("SOUL.md", "abcdef");
    const excerpt = try bp.load_excerpt(testing.allocator, "SOUL.md", 3);
    defer if (excerpt) |c| testing.allocator.free(c);

    try testing.expectEqualStrings("abc", excerpt.?);
}

test "remove deletes file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = try setupTestProvider(&tmp);
    defer testing.allocator.free(ctx.workspace);

    var bp = ctx.provider.provider();

    try bp.store("TOOLS.md", "tool content");
    try testing.expect(bp.exists("TOOLS.md"));

    const removed = try bp.remove("TOOLS.md");
    try testing.expect(removed);
    try testing.expect(!bp.exists("TOOLS.md"));

    // Removing again returns false
    const removed_again = try bp.remove("TOOLS.md");
    try testing.expect(!removed_again);
}

test "fingerprint changes after store" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = try setupTestProvider(&tmp);
    defer testing.allocator.free(ctx.workspace);

    var bp = ctx.provider.provider();

    const fp_before = try bp.fingerprint(testing.allocator);

    try bp.store("IDENTITY.md", "identity content");

    const fp_after = try bp.fingerprint(testing.allocator);
    try testing.expect(fp_before != fp_after);
}

test "store overwrites existing content" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = try setupTestProvider(&tmp);
    defer testing.allocator.free(ctx.workspace);

    var bp = ctx.provider.provider();

    try bp.store("USER.md", "version 1");
    try bp.store("USER.md", "version 2");

    const content = try bp.load(testing.allocator, "USER.md");
    defer if (content) |c| testing.allocator.free(c);

    try testing.expectEqualStrings("version 2", content.?);
}

test "rejects non-bootstrap filenames with NotBootstrapFile" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = try setupTestProvider(&tmp);
    defer testing.allocator.free(ctx.workspace);

    var bp = ctx.provider.provider();

    // store
    const store_result = bp.store("evil.md", "bad");
    try testing.expectError(Error.NotBootstrapFile, store_result);

    // load
    const load_result = bp.load(testing.allocator, "evil.md");
    try testing.expectError(Error.NotBootstrapFile, load_result);

    // remove
    const remove_result = bp.remove("evil.md");
    try testing.expectError(Error.NotBootstrapFile, remove_result);

    // exists returns false (no error)
    try testing.expect(!bp.exists("evil.md"));
}

test "list returns only existing files" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = try setupTestProvider(&tmp);
    defer testing.allocator.free(ctx.workspace);

    var bp = ctx.provider.provider();

    // Initially empty
    const empty = try bp.list(testing.allocator);
    defer testing.allocator.free(empty);
    try testing.expectEqual(@as(usize, 0), empty.len);

    // Store some files
    try bp.store("AGENTS.md", "a");
    try bp.store("SOUL.md", "s");

    const files = try bp.list(testing.allocator);
    defer {
        for (files) |f| testing.allocator.free(f);
        testing.allocator.free(files);
    }

    try testing.expectEqual(@as(usize, 2), files.len);
    try testing.expectEqualStrings("AGENTS.md", files[0]);
    try testing.expectEqualStrings("SOUL.md", files[1]);
}

test "exists returns true after store false after remove" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var ctx = try setupTestProvider(&tmp);
    defer testing.allocator.free(ctx.workspace);

    var bp = ctx.provider.provider();

    try testing.expect(!bp.exists("HEARTBEAT.md"));

    try bp.store("HEARTBEAT.md", "hb");
    try testing.expect(bp.exists("HEARTBEAT.md"));

    _ = try bp.remove("HEARTBEAT.md");
    try testing.expect(!bp.exists("HEARTBEAT.md"));
}
