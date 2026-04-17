const std = @import("std");
const std_compat = @import("compat");
const probe = @import("probe.zig");
const Sandbox = @import("sandbox.zig").Sandbox;

/// Maximum supported workspace path length for the mount argument buffer.
const MAX_WORKSPACE_LEN = 2048;

/// Docker sandbox backend.
/// Wraps commands with `docker run` for container isolation.
/// The workspace directory is bind-mounted into the container at the same path.
pub const DockerSandbox = struct {
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    image: []const u8,
    /// Pre-built "workspace_dir:workspace_dir" string for the -v flag.
    /// Stored inline to avoid allocation in wrapCommand.
    mount_arg_buf: [MAX_WORKSPACE_LEN * 2 + 1]u8 = undefined,
    mount_arg_len: usize = 0,

    pub const default_image = "alpine:latest";

    pub const sandbox_vtable = Sandbox.VTable{
        .wrapCommand = wrapCommand,
        .isAvailable = isAvailable,
        .name = getName,
        .description = getDescription,
    };

    pub fn sandbox(self: *DockerSandbox) Sandbox {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &sandbox_vtable,
        };
    }

    fn resolve(ptr: *anyopaque) *DockerSandbox {
        return @ptrCast(@alignCast(ptr));
    }

    fn wrapCommand(ptr: *anyopaque, argv: []const []const u8, buf: [][]const u8) anyerror![]const []const u8 {
        const self = resolve(ptr);
        if (self.workspace_dir.len == 0 or self.mount_arg_len == 0) return error.EmptyWorkspaceDir;
        // docker run --rm --memory 512m --cpus 1.0 --network none -v WORKSPACE:WORKSPACE -w WORKSPACE IMAGE <argv...>
        const prefix = [_][]const u8{
            "docker",   "run",       "--rm",
            "--memory", "512m",      "--cpus",
            "1.0",      "--network", "none",
            "-v",
        };
        // We need: prefix (10) + mount_arg (1) + -w (1) + workspace (1) + image (1) + argv.len
        const prefix_len = prefix.len;
        const total = prefix_len + 4 + argv.len;

        if (buf.len < total) return error.BufferTooSmall;

        for (prefix, 0..) |p, i| {
            buf[i] = p;
        }
        buf[prefix_len] = self.mount_arg_buf[0..self.mount_arg_len];
        buf[prefix_len + 1] = "-w";
        buf[prefix_len + 2] = self.workspace_dir;
        buf[prefix_len + 3] = self.image;
        for (argv, 0..) |arg, i| {
            buf[prefix_len + 4 + i] = arg;
        }
        return buf[0..total];
    }

    fn isAvailable(_: *anyopaque) bool {
        // Probe daemon reachability without pulling the configured image.
        return probe.runQuietCommand(&.{ "docker", "info" });
    }

    fn getName(_: *anyopaque) []const u8 {
        return "docker";
    }

    fn getDescription(_: *anyopaque) []const u8 {
        return "Docker container isolation (requires docker)";
    }
};

pub fn createDockerSandbox(allocator: std.mem.Allocator, workspace_dir: []const u8, image: ?[]const u8) DockerSandbox {
    var ds = DockerSandbox{
        .allocator = allocator,
        .workspace_dir = workspace_dir,
        .image = image orelse DockerSandbox.default_image,
    };
    // Pre-build "workspace_dir:workspace_dir" mount argument
    const wd = workspace_dir;
    const max = @min(wd.len, MAX_WORKSPACE_LEN);
    @memcpy(ds.mount_arg_buf[0..max], wd[0..max]);
    ds.mount_arg_buf[max] = ':';
    @memcpy(ds.mount_arg_buf[max + 1 ..][0..max], wd[0..max]);
    ds.mount_arg_len = max * 2 + 1;
    return ds;
}

// ── Workspace Mount Validation ─────────────────────────────────────────

/// Result of validating a workspace mount path for Docker container use.
pub const ValidationResult = enum {
    /// Path is safe to use as a workspace mount
    valid,
    /// Path is empty
    empty,
    /// Path is not absolute (does not start with `/`)
    not_absolute,
    /// Path is the filesystem root `/`
    is_root,
    /// Path contains `..` traversal components
    traversal,
    /// Path targets a dangerous system mount point
    dangerous_mount,
    /// Path contains null bytes
    null_bytes,
    /// Path is not under any of the allowed workspace roots
    not_in_allowed_roots,

    pub fn isValid(self: ValidationResult) bool {
        return self == .valid;
    }

    pub fn toString(self: ValidationResult) []const u8 {
        return switch (self) {
            .valid => "valid",
            .empty => "path is empty",
            .not_absolute => "path must be absolute (start with /)",
            .is_root => "cannot mount filesystem root",
            .traversal => "path contains '..' traversal",
            .dangerous_mount => "path targets a dangerous system directory",
            .null_bytes => "path contains null bytes",
            .not_in_allowed_roots => "path is not under any allowed workspace root",
        };
    }
};

/// System directories that must never be mounted as Docker workspaces.
/// These are bare mount points — `/etc` is blocked but `/etc/myapp` is also blocked
/// because it starts with a dangerous prefix.
const dangerous_mounts = [_][]const u8{
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/var",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/root",
};

/// Validate a path for use as a Docker workspace mount.
///
/// Checks performed (in order):
/// 1. Path must not be empty
/// 2. Path must not contain null bytes
/// 3. Path must be absolute (starts with `/`)
/// 4. Path must not be the root directory `/`
/// 5. Path must not contain `..` traversal components
/// 6. Path must not target dangerous system directories
/// 7. Bare `/home` is rejected (but `/home/user/...` is allowed)
///
/// If `allowed_roots` is provided (non-null, non-empty), the path must also
/// be under one of those roots.
pub fn validateWorkspaceMount(path: []const u8, allowed_roots: ?[]const []const u8) ValidationResult {
    // 1. Empty check
    if (path.len == 0) return .empty;

    // 2. Null byte check
    if (std.mem.indexOfScalar(u8, path, 0) != null) return .null_bytes;

    // 3. Absolute path check
    if (path[0] != '/') return .not_absolute;

    // 4. Root check — normalize trailing slashes: treat "///" the same as "/"
    const trimmed = std_compat.mem.trimRight(u8, path, "/");
    if (trimmed.len == 0) return .is_root;

    // 5. Traversal check — look for ".." as a path component
    if (containsTraversal(path)) return .traversal;

    // 6. Dangerous mount check
    if (isDangerousMount(trimmed)) return .dangerous_mount;

    // 7. Bare /home check — "/home" alone is dangerous, but "/home/user" is fine
    if (std.mem.eql(u8, trimmed, "/home")) return .dangerous_mount;

    // 8. Allowed roots check (optional)
    if (allowed_roots) |roots| {
        if (roots.len > 0) {
            for (roots) |root| {
                if (isUnderRoot(trimmed, root)) return .valid;
            }
            return .not_in_allowed_roots;
        }
    }

    return .valid;
}

/// Check if path contains ".." as a path component.
fn containsTraversal(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return true;
    }
    return false;
}

/// Check if the trimmed path is a dangerous system mount or under one.
fn isDangerousMount(trimmed: []const u8) bool {
    for (dangerous_mounts) |mount| {
        if (std.mem.eql(u8, trimmed, mount)) return true;
        // Also block subdirectories: "/etc/passwd", "/var/lib/..." etc.
        if (trimmed.len > mount.len and
            std.mem.startsWith(u8, trimmed, mount) and
            trimmed[mount.len] == '/')
        {
            return true;
        }
    }
    return false;
}

/// Check if `path` is equal to or under `root`.
fn isUnderRoot(path: []const u8, root: []const u8) bool {
    const trimmed_root = std_compat.mem.trimRight(u8, root, "/");
    if (trimmed_root.len == 0) return false; // don't allow root "/" as an allowed root
    if (std.mem.eql(u8, path, trimmed_root)) return true;
    if (path.len > trimmed_root.len and
        std.mem.startsWith(u8, path, trimmed_root) and
        path[trimmed_root.len] == '/')
    {
        return true;
    }
    return false;
}

// ── Tests ──────────────────────────────────────────────────────────────

test "docker sandbox name" {
    var dk = createDockerSandbox(std.testing.allocator, "/tmp/workspace", null);
    const sb = dk.sandbox();
    try std.testing.expectEqualStrings("docker", sb.name());
}

test "docker sandbox isAvailable returns bool" {
    var dk = createDockerSandbox(std.testing.allocator, "/tmp/workspace", null);
    const sb = dk.sandbox();
    // isAvailable now checks Docker daemon reachability; result depends on environment.
    _ = sb.isAvailable();
}

test "docker sandbox wrap command prepends docker run" {
    var dk = createDockerSandbox(std.testing.allocator, "/tmp/workspace", null);
    const sb = dk.sandbox();

    const argv = [_][]const u8{ "echo", "hello" };
    var buf: [32][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);

    try std.testing.expectEqualStrings("docker", result[0]);
    try std.testing.expectEqualStrings("run", result[1]);
    try std.testing.expectEqualStrings("--rm", result[2]);
    try std.testing.expectEqualStrings("--network", result[7]);
    try std.testing.expectEqualStrings("none", result[8]);
    // Volume mount flag
    try std.testing.expectEqualStrings("-v", result[9]);
    // Mount arg: workspace_dir:workspace_dir
    try std.testing.expectEqualStrings("/tmp/workspace:/tmp/workspace", result[10]);
    try std.testing.expectEqualStrings("-w", result[11]);
    // Regression: preserve the shell tool's default workspace cwd inside the container.
    try std.testing.expectEqualStrings("/tmp/workspace", result[12]);
    // Image
    try std.testing.expectEqualStrings("alpine:latest", result[13]);
    // Original command
    try std.testing.expectEqualStrings("echo", result[14]);
    try std.testing.expectEqualStrings("hello", result[15]);
    try std.testing.expectEqual(@as(usize, 16), result.len);
}

test "docker sandbox wrap with custom image" {
    var dk = createDockerSandbox(std.testing.allocator, "/tmp/workspace", "ubuntu:22.04");
    const sb = dk.sandbox();

    const argv = [_][]const u8{"ls"};
    var buf: [32][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);

    try std.testing.expectEqualStrings("-v", result[9]);
    try std.testing.expectEqualStrings("/tmp/workspace:/tmp/workspace", result[10]);
    try std.testing.expectEqualStrings("-w", result[11]);
    try std.testing.expectEqualStrings("/tmp/workspace", result[12]);
    try std.testing.expectEqualStrings("ubuntu:22.04", result[13]);
    try std.testing.expectEqualStrings("ls", result[14]);
}

test "docker sandbox wrap empty argv" {
    var dk = createDockerSandbox(std.testing.allocator, "/tmp/workspace", null);
    const sb = dk.sandbox();

    const argv = [_][]const u8{};
    var buf: [32][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);

    // prefix (10) + mount_arg (1) + -w (1) + workspace (1) + image (1)
    try std.testing.expectEqual(@as(usize, 14), result.len);
}

test "docker buffer too small returns error" {
    var dk = createDockerSandbox(std.testing.allocator, "/tmp/workspace", null);
    const sb = dk.sandbox();

    const argv = [_][]const u8{ "echo", "test" };
    var buf: [5][]const u8 = undefined;
    const result = sb.wrapCommand(&argv, &buf);
    try std.testing.expectError(error.BufferTooSmall, result);
}

test "docker wrap rejects empty workspace state" {
    var dk = DockerSandbox{
        .allocator = std.testing.allocator,
        .workspace_dir = "",
        .image = DockerSandbox.default_image,
    };
    const sb = dk.sandbox();

    const argv = [_][]const u8{"echo"};
    var buf: [16][]const u8 = undefined;
    const result = sb.wrapCommand(&argv, &buf);
    try std.testing.expectError(error.EmptyWorkspaceDir, result);
}

test "docker sandbox workspace is mounted correctly" {
    var dk = createDockerSandbox(std.testing.allocator, "/home/user/myproject", null);
    const sb = dk.sandbox();

    const argv = [_][]const u8{"bash"};
    var buf: [32][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);

    try std.testing.expectEqualStrings("-v", result[9]);
    try std.testing.expectEqualStrings("/home/user/myproject:/home/user/myproject", result[10]);
}

// ── Workspace Mount Validation Tests ───────────────────────────────────

test "mount validation: valid path /home/user/project" {
    const result = validateWorkspaceMount("/home/user/project", null);
    try std.testing.expectEqual(ValidationResult.valid, result);
    try std.testing.expect(result.isValid());
}

test "mount validation: valid path /opt/workspace" {
    const result = validateWorkspaceMount("/opt/workspace", null);
    try std.testing.expectEqual(ValidationResult.valid, result);
}

test "mount validation: root path rejected" {
    try std.testing.expectEqual(ValidationResult.is_root, validateWorkspaceMount("/", null));
    // Multiple slashes still treated as root
    try std.testing.expectEqual(ValidationResult.is_root, validateWorkspaceMount("///", null));
}

test "mount validation: relative path rejected" {
    try std.testing.expectEqual(ValidationResult.not_absolute, validateWorkspaceMount("home/user/project", null));
    try std.testing.expectEqual(ValidationResult.not_absolute, validateWorkspaceMount("./workspace", null));
    try std.testing.expectEqual(ValidationResult.not_absolute, validateWorkspaceMount("workspace", null));
}

test "mount validation: path with traversal rejected" {
    try std.testing.expectEqual(ValidationResult.traversal, validateWorkspaceMount("/home/user/../etc/shadow", null));
    try std.testing.expectEqual(ValidationResult.traversal, validateWorkspaceMount("/home/../root", null));
    try std.testing.expectEqual(ValidationResult.traversal, validateWorkspaceMount("/../escape", null));
}

test "mount validation: /etc rejected" {
    try std.testing.expectEqual(ValidationResult.dangerous_mount, validateWorkspaceMount("/etc", null));
    try std.testing.expectEqual(ValidationResult.dangerous_mount, validateWorkspaceMount("/etc/passwd", null));
}

test "mount validation: /usr rejected" {
    try std.testing.expectEqual(ValidationResult.dangerous_mount, validateWorkspaceMount("/usr", null));
    try std.testing.expectEqual(ValidationResult.dangerous_mount, validateWorkspaceMount("/usr/local/bin", null));
}

test "mount validation: /bin rejected" {
    try std.testing.expectEqual(ValidationResult.dangerous_mount, validateWorkspaceMount("/bin", null));
    try std.testing.expectEqual(ValidationResult.dangerous_mount, validateWorkspaceMount("/sbin", null));
}

test "mount validation: bare /home rejected but /home/user allowed" {
    try std.testing.expectEqual(ValidationResult.dangerous_mount, validateWorkspaceMount("/home", null));
    try std.testing.expectEqual(ValidationResult.valid, validateWorkspaceMount("/home/user", null));
    try std.testing.expectEqual(ValidationResult.valid, validateWorkspaceMount("/home/user/workspace", null));
}

test "mount validation: /var rejected including subdirectories" {
    try std.testing.expectEqual(ValidationResult.dangerous_mount, validateWorkspaceMount("/var", null));
    try std.testing.expectEqual(ValidationResult.dangerous_mount, validateWorkspaceMount("/var/lib/workspace", null));
}

test "mount validation: empty path rejected" {
    const result = validateWorkspaceMount("", null);
    try std.testing.expectEqual(ValidationResult.empty, result);
    try std.testing.expect(!result.isValid());
}

test "mount validation: path with null bytes rejected" {
    const result = validateWorkspaceMount("/home/user\x00/project", null);
    try std.testing.expectEqual(ValidationResult.null_bytes, result);
}

test "mount validation: allowed roots enforcement" {
    const roots = [_][]const u8{ "/opt/workspaces", "/srv/projects" };
    // Path under allowed root passes
    try std.testing.expectEqual(
        ValidationResult.valid,
        validateWorkspaceMount("/opt/workspaces/myapp", &roots),
    );
    // Exact match of allowed root passes
    try std.testing.expectEqual(
        ValidationResult.valid,
        validateWorkspaceMount("/srv/projects", &roots),
    );
    // Path outside allowed roots rejected
    try std.testing.expectEqual(
        ValidationResult.not_in_allowed_roots,
        validateWorkspaceMount("/tmp/workspace", &roots),
    );
    // Empty allowed roots list means no restriction
    const empty_roots = [_][]const u8{};
    try std.testing.expectEqual(
        ValidationResult.valid,
        validateWorkspaceMount("/tmp/workspace", &empty_roots),
    );
}

test "mount validation: ValidationResult.toString returns descriptive strings" {
    try std.testing.expectEqualStrings("valid", ValidationResult.valid.toString());
    try std.testing.expectEqualStrings("path is empty", ValidationResult.empty.toString());
    try std.testing.expectEqualStrings("path must be absolute (start with /)", ValidationResult.not_absolute.toString());
    try std.testing.expectEqualStrings("cannot mount filesystem root", ValidationResult.is_root.toString());
    try std.testing.expectEqualStrings("path contains '..' traversal", ValidationResult.traversal.toString());
    try std.testing.expectEqualStrings("path targets a dangerous system directory", ValidationResult.dangerous_mount.toString());
    try std.testing.expectEqualStrings("path contains null bytes", ValidationResult.null_bytes.toString());
    try std.testing.expectEqualStrings("path is not under any allowed workspace root", ValidationResult.not_in_allowed_roots.toString());
}
