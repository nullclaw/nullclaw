const std = @import("std");
const builtin = @import("builtin");
const Sandbox = @import("sandbox.zig").Sandbox;
const NoopSandbox = @import("sandbox.zig").NoopSandbox;
const LandlockSandbox = @import("landlock.zig").LandlockSandbox;
const FirejailSandbox = @import("firejail.zig").FirejailSandbox;
const BubblewrapSandbox = @import("bubblewrap.zig").BubblewrapSandbox;
const DockerSandbox = @import("docker.zig").DockerSandbox;

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
/// Priority on Linux: landlock > firejail > bubblewrap > docker > noop
/// Priority on macOS: docker > noop
/// Explicit backend selection overrides auto-detection.
pub fn createSandbox(
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
            storage.docker = .{ .workspace_dir = workspace_dir, .image = DockerSandbox.default_image };
            return storage.docker.sandbox();
        },
        .auto => {
            return detectBest(workspace_dir, storage);
        },
    }
}

/// Storage for sandbox backend instances (union-like, only one is active).
pub const SandboxStorage = struct {
    noop: NoopSandbox = .{},
    landlock: LandlockSandbox = .{ .workspace_dir = "" },
    firejail: FirejailSandbox = .{ .workspace_dir = "" },
    bubblewrap: BubblewrapSandbox = .{ .workspace_dir = "" },
    docker: DockerSandbox = .{ .workspace_dir = "", .image = DockerSandbox.default_image },
};

/// Auto-detect the best available sandbox backend.
fn detectBest(workspace_dir: []const u8, storage: *SandboxStorage) Sandbox {
    if (comptime builtin.os.tag == .linux) {
        // Try Landlock first (native, no external dependencies)
        storage.landlock = .{ .workspace_dir = workspace_dir };
        if (storage.landlock.sandbox().isAvailable()) {
            return storage.landlock.sandbox();
        }

        // Try Firejail second
        storage.firejail = .{ .workspace_dir = workspace_dir };
        if (storage.firejail.sandbox().isAvailable()) {
            return storage.firejail.sandbox();
        }

        // Try Bubblewrap third
        storage.bubblewrap = .{ .workspace_dir = workspace_dir };
        if (storage.bubblewrap.sandbox().isAvailable()) {
            return storage.bubblewrap.sandbox();
        }
    }

    // Docker works on any platform if installed
    storage.docker = .{ .workspace_dir = workspace_dir, .image = DockerSandbox.default_image };
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

pub fn detectAvailable(workspace_dir: []const u8) AvailableBackends {
    var storage: SandboxStorage = .{};

    storage.landlock = .{ .workspace_dir = workspace_dir };
    const ll_avail = storage.landlock.sandbox().isAvailable();

    storage.firejail = .{ .workspace_dir = workspace_dir };
    const fj_avail = storage.firejail.sandbox().isAvailable();

    storage.bubblewrap = .{ .workspace_dir = workspace_dir };
    const bw_avail = storage.bubblewrap.sandbox().isAvailable();

    storage.docker = .{ .workspace_dir = workspace_dir, .image = DockerSandbox.default_image };
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
    const avail = detectAvailable("/tmp/workspace");
    // On macOS, landlock/firejail/bubblewrap should be false
    if (comptime builtin.os.tag != .linux) {
        try std.testing.expect(!avail.landlock);
        try std.testing.expect(!avail.firejail);
        try std.testing.expect(!avail.bubblewrap);
    }
    // docker.isAvailable() returns true unconditionally (runtime check would need spawn)
    try std.testing.expect(avail.docker);
}

test "create sandbox with none returns noop" {
    var storage: SandboxStorage = .{};
    const sb = createSandbox(.none, "/tmp/workspace", &storage);
    try std.testing.expectEqualStrings("none", sb.name());
    try std.testing.expect(sb.isAvailable());
}

test "create sandbox with auto returns something" {
    var storage: SandboxStorage = .{};
    const sb = createSandbox(.auto, "/tmp/workspace", &storage);
    // Should always return at least some sandbox
    try std.testing.expect(sb.name().len > 0);
}

test "create sandbox with docker returns docker" {
    var storage: SandboxStorage = .{};
    const sb = createSandbox(.docker, "/tmp/workspace", &storage);
    try std.testing.expectEqualStrings("docker", sb.name());
}

test "create sandbox with landlock on non-linux falls back to noop" {
    if (comptime builtin.os.tag == .linux) return;
    var storage: SandboxStorage = .{};
    const sb = createSandbox(.landlock, "/tmp/workspace", &storage);
    try std.testing.expectEqualStrings("none", sb.name());
}

test "create sandbox with firejail on non-linux falls back to noop" {
    if (comptime builtin.os.tag == .linux) return;
    var storage: SandboxStorage = .{};
    const sb = createSandbox(.firejail, "/tmp/workspace", &storage);
    try std.testing.expectEqualStrings("none", sb.name());
}

test "create sandbox with bubblewrap on non-linux falls back to noop" {
    if (comptime builtin.os.tag == .linux) return;
    var storage: SandboxStorage = .{};
    const sb = createSandbox(.bubblewrap, "/tmp/workspace", &storage);
    try std.testing.expectEqualStrings("none", sb.name());
}

test "sandbox storage default initialization" {
    const storage = SandboxStorage{};
    try std.testing.expectEqualStrings("", storage.landlock.workspace_dir);
    try std.testing.expectEqualStrings("", storage.firejail.workspace_dir);
    try std.testing.expectEqualStrings(DockerSandbox.default_image, storage.docker.image);
}
