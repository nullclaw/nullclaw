const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const Sandbox = @import("sandbox.zig").Sandbox;
const NoopSandbox = @import("sandbox.zig").NoopSandbox;
const LandlockSandbox = @import("landlock.zig").LandlockSandbox;
const FirejailSandbox = @import("firejail.zig").FirejailSandbox;
const BubblewrapSandbox = @import("bubblewrap.zig").BubblewrapSandbox;
const docker = @import("docker.zig");
const DockerSandbox = docker.DockerSandbox;
const createDockerSandbox = docker.createDockerSandbox;

/// Sandbox backend preference.
pub const SandboxBackend = enum {
    auto,
    none,
    landlock,
    firejail,
    bubblewrap,
    docker,
};

/// Detect and create the best available sandbox backend.
///
/// Priority on Linux: firejail > bubblewrap > docker > noop
/// Priority on macOS: docker > noop
/// Landlock is not surfaced until rule installation is implemented.
pub fn createSandbox(
    allocator: std.mem.Allocator,
    backend: SandboxBackend,
    workspace_dir: []const u8,
    /// Caller-provided storage for sandbox backend structs.
    /// Must remain valid for the lifetime of the returned Sandbox.
    storage: *SandboxStorage,
) Sandbox {
    switch (backend) {
        .none => {
            storage.noop = .{};
            return storage.noop.sandbox();
        },
        .landlock => {
            storage.landlock = .{ .workspace_dir = workspace_dir };
            if (storage.landlock.sandbox().isAvailable()) {
                return storage.landlock.sandbox();
            }
            storage.noop = .{};
            return storage.noop.sandbox();
        },
        .firejail => {
            storage.firejail = .{ .workspace_dir = workspace_dir };
            if (storage.firejail.sandbox().isAvailable()) {
                return storage.firejail.sandbox();
            }
            storage.noop = .{};
            return storage.noop.sandbox();
        },
        .bubblewrap => {
            storage.bubblewrap = .{ .workspace_dir = workspace_dir };
            if (storage.bubblewrap.sandbox().isAvailable()) {
                return storage.bubblewrap.sandbox();
            }
            storage.noop = .{};
            return storage.noop.sandbox();
        },
        .docker => {
            storage.docker = createDockerSandbox(allocator, workspace_dir, null);
            return storage.docker.sandbox();
        },
        .auto => {
            return detectBest(allocator, workspace_dir, storage);
        },
    }
}

/// Storage for sandbox backend instances (union-like, only one is active).
pub const SandboxStorage = struct {
    noop: NoopSandbox = .{},
    landlock: LandlockSandbox = .{ .workspace_dir = "" },
    firejail: FirejailSandbox = .{ .workspace_dir = "" },
    bubblewrap: BubblewrapSandbox = .{ .workspace_dir = "" },
    docker: DockerSandbox = .{ .allocator = undefined, .workspace_dir = "", .image = DockerSandbox.default_image },
};

/// Auto-detect the best available sandbox backend.
fn detectBest(allocator: std.mem.Allocator, workspace_dir: []const u8, storage: *SandboxStorage) Sandbox {
    if (comptime builtin.os.tag == .linux) {
        // Keep landlock hidden from auto mode until rule installation exists.
        storage.landlock = .{ .workspace_dir = workspace_dir };
        if (storage.landlock.sandbox().isAvailable()) {
            return storage.landlock.sandbox();
        }

        // Try Firejail first
        storage.firejail = .{ .workspace_dir = workspace_dir };
        if (storage.firejail.sandbox().isAvailable()) {
            return storage.firejail.sandbox();
        }

        // Try Bubblewrap second
        storage.bubblewrap = .{ .workspace_dir = workspace_dir };
        if (storage.bubblewrap.sandbox().isAvailable()) {
            return storage.bubblewrap.sandbox();
        }
    }

    // Docker works on any platform when the client can reach a daemon.
    storage.docker = createDockerSandbox(allocator, workspace_dir, null);
    if (storage.docker.sandbox().isAvailable()) {
        return storage.docker.sandbox();
    }

    // Fallback: no sandboxing
    storage.noop = .{};
    return storage.noop.sandbox();
}

/// Check which sandbox backends are available on the current system.
/// Returns a struct with boolean flags for each backend.
pub const AvailableBackends = struct {
    landlock: bool,
    firejail: bool,
    bubblewrap: bool,
    docker: bool,
};

pub fn detectAvailable(allocator: std.mem.Allocator, workspace_dir: []const u8) AvailableBackends {
    var storage: SandboxStorage = .{};

    storage.landlock = .{ .workspace_dir = workspace_dir };
    const ll_avail = storage.landlock.sandbox().isAvailable();

    storage.firejail = .{ .workspace_dir = workspace_dir };
    const fj_avail = storage.firejail.sandbox().isAvailable();

    storage.bubblewrap = .{ .workspace_dir = workspace_dir };
    const bw_avail = storage.bubblewrap.sandbox().isAvailable();

    storage.docker = createDockerSandbox(allocator, workspace_dir, null);
    const dk_avail = storage.docker.sandbox().isAvailable();

    return .{
        .landlock = ll_avail,
        .firejail = fj_avail,
        .bubblewrap = bw_avail,
        .docker = dk_avail,
    };
}

// ── Tests ──────────────────────────────────────────────────────────────

test "detect available returns struct" {
    const avail = detectAvailable(std.testing.allocator, "/tmp/workspace");
    try std.testing.expect(!avail.landlock);
    // On macOS, firejail/bubblewrap should be false
    if (comptime builtin.os.tag != .linux) {
        try std.testing.expect(!avail.firejail);
        try std.testing.expect(!avail.bubblewrap);
    }
    // Docker availability is runtime-dependent (not available on all CI machines)
    _ = avail.docker;
}

test "create sandbox with none returns noop" {
    var storage: SandboxStorage = .{};
    const sb = createSandbox(std.testing.allocator, .none, "/tmp/workspace", &storage);
    try std.testing.expectEqualStrings("none", sb.name());
    try std.testing.expect(sb.isAvailable());
}

test "create sandbox with landlock falls back to noop until implemented" {
    var storage: SandboxStorage = .{};
    const sb = createSandbox(std.testing.allocator, .landlock, "/tmp/workspace", &storage);
    try std.testing.expectEqualStrings("none", sb.name());
}

test "create sandbox with auto returns something" {
    var storage: SandboxStorage = .{};
    const sb = createSandbox(std.testing.allocator, .auto, "/tmp/workspace", &storage);
    // Should always return at least some sandbox
    try std.testing.expect(sb.name().len > 0);
    try std.testing.expect(!std.mem.eql(u8, sb.name(), "landlock"));
}

test "create sandbox with docker returns docker" {
    var storage: SandboxStorage = .{};
    const sb = createSandbox(std.testing.allocator, .docker, "/tmp/workspace", &storage);
    try std.testing.expectEqualStrings("docker", sb.name());
}

test "create sandbox with docker prebuilds mount arg" {
    var storage: SandboxStorage = .{};
    _ = createSandbox(std.testing.allocator, .docker, "/tmp/workspace", &storage);

    // Regression: detect.zig must use the Docker sandbox factory so wrapCommand
    // never passes an empty -v argument to docker.
    try std.testing.expectEqualStrings("/tmp/workspace:/tmp/workspace", storage.docker.mount_arg_buf[0..storage.docker.mount_arg_len]);
}

test "sandbox storage default initialization" {
    const storage = SandboxStorage{};
    try std.testing.expectEqualStrings("", storage.landlock.workspace_dir);
    try std.testing.expectEqualStrings("", storage.firejail.workspace_dir);
    try std.testing.expectEqualStrings(DockerSandbox.default_image, storage.docker.image);
}

test "auto detect skips version-only linux sandbox shims" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;

    const platform = @import("../platform.zig");
    const c = @cImport({
        @cInclude("stdlib.h");
    });

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const shim =
        \\#!/bin/sh
        \\if [ "$1" = "--version" ]; then
        \\  exit 0
        \\fi
        \\exit 9
        \\
    ;

    inline for (.{ "firejail", "bwrap" }) |name| {
        try std_compat.fs.Dir.wrap(tmp_dir.dir).writeFile(.{
            .sub_path = name,
            .data = shim,
            .flags = .{ .permissions = std_compat.fs.permissionsFromMode(0o755) },
        });
    }

    const tmp_path = try std_compat.fs.Dir.wrap(tmp_dir.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const key_z = try std.testing.allocator.dupeZ(u8, "PATH");
    defer std.testing.allocator.free(key_z);

    const old_path = platform.getEnvOrNull(std.testing.allocator, "PATH");
    defer if (old_path) |path| std.testing.allocator.free(path);

    const old_path_z = if (old_path) |path| try std.testing.allocator.dupeZ(u8, path) else null;
    defer if (old_path_z) |path| std.testing.allocator.free(path);

    const effective_path = if (old_path) |path|
        try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}{c}{s}",
            .{ tmp_path, std_compat.fs.path.delimiter, path },
        )
    else
        try std.testing.allocator.dupe(u8, tmp_path);
    defer std.testing.allocator.free(effective_path);

    const tmp_path_z = try std.testing.allocator.dupeZ(u8, effective_path);
    defer std.testing.allocator.free(tmp_path_z);

    defer {
        if (old_path_z) |path| {
            _ = c.setenv(key_z.ptr, path.ptr, 1);
        } else {
            _ = c.unsetenv(key_z.ptr);
        }
    }

    try std.testing.expectEqual(@as(c_int, 0), c.setenv(key_z.ptr, tmp_path_z.ptr, 1));

    // Regression for #791: do not treat shims that only answer `--version`
    // as runnable Linux sandbox backends in auto-detect.
    const avail = detectAvailable(std.testing.allocator, "/tmp/workspace");
    try std.testing.expect(!avail.firejail);
    try std.testing.expect(!avail.bubblewrap);

    var storage: SandboxStorage = .{};
    const sandbox = createSandbox(std.testing.allocator, .auto, "/tmp/workspace", &storage);
    try std.testing.expect(!std.mem.eql(u8, sandbox.name(), "firejail"));
    try std.testing.expect(!std.mem.eql(u8, sandbox.name(), "bubblewrap"));
}
