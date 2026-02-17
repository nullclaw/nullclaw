const std = @import("std");
const Sandbox = @import("sandbox.zig").Sandbox;

/// Docker sandbox backend.
/// Wraps commands with `docker run` for container isolation.
pub const DockerSandbox = struct {
    workspace_dir: []const u8,
    image: []const u8,

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
        // docker run --rm --memory 512m --cpus 1.0 --network none -v WORKSPACE:/workspace IMAGE <argv...>
        const prefix = [_][]const u8{
            "docker",   "run",       "--rm",
            "--memory", "512m",      "--cpus",
            "1.0",      "--network", "none",
        };
        // We need: prefix (9) + image (1) + argv.len
        const prefix_len = prefix.len;
        const total = prefix_len + 1 + argv.len;

        if (buf.len < total) return error.BufferTooSmall;

        for (prefix, 0..) |p, i| {
            buf[i] = p;
        }
        buf[prefix_len] = self.image;
        for (argv, 0..) |arg, i| {
            buf[prefix_len + 1 + i] = arg;
        }
        return buf[0..total];
    }

    fn isAvailable(_: *anyopaque) bool {
        // Check if docker binary is actually reachable
        var child = std.process.Child.init(&.{ "docker", "--version" }, std.heap.page_allocator);
        child.stderr_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stdin_behavior = .Ignore;
        child.spawn() catch return false;
        const term = child.wait() catch return false;
        return term == .Exited and term.Exited == 0;
    }

    fn getName(_: *anyopaque) []const u8 {
        return "docker";
    }

    fn getDescription(_: *anyopaque) []const u8 {
        return "Docker container isolation (requires docker)";
    }
};

pub fn createDockerSandbox(workspace_dir: []const u8, image: ?[]const u8) DockerSandbox {
    return .{
        .workspace_dir = workspace_dir,
        .image = image orelse DockerSandbox.default_image,
    };
}

// ── Tests ──────────────────────────────────────────────────────────────

test "docker sandbox name" {
    var dk = createDockerSandbox("/tmp/workspace", null);
    const sb = dk.sandbox();
    try std.testing.expectEqualStrings("docker", sb.name());
}

test "docker sandbox default image" {
    const dk = createDockerSandbox("/tmp/workspace", null);
    try std.testing.expectEqualStrings("alpine:latest", dk.image);
}

test "docker sandbox custom image" {
    const dk = createDockerSandbox("/tmp/workspace", "ubuntu:latest");
    try std.testing.expectEqualStrings("ubuntu:latest", dk.image);
}

test "docker sandbox description mentions docker" {
    var dk = createDockerSandbox("/tmp/workspace", null);
    const sb = dk.sandbox();
    const desc = sb.description();
    try std.testing.expect(std.mem.indexOf(u8, desc, "Docker") != null or std.mem.indexOf(u8, desc, "docker") != null);
}

test "docker sandbox isAvailable returns bool" {
    var dk = createDockerSandbox("/tmp/workspace", null);
    const sb = dk.sandbox();
    // isAvailable now checks for real docker binary; result depends on environment
    _ = sb.isAvailable();
}

test "docker sandbox wrap command prepends docker run" {
    var dk = createDockerSandbox("/tmp/workspace", null);
    const sb = dk.sandbox();

    const argv = [_][]const u8{ "echo", "hello" };
    var buf: [32][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);

    try std.testing.expectEqualStrings("docker", result[0]);
    try std.testing.expectEqualStrings("run", result[1]);
    try std.testing.expectEqualStrings("--rm", result[2]);
    try std.testing.expectEqualStrings("--network", result[7]);
    try std.testing.expectEqualStrings("none", result[8]);
    // Image
    try std.testing.expectEqualStrings("alpine:latest", result[9]);
    // Original command
    try std.testing.expectEqualStrings("echo", result[10]);
    try std.testing.expectEqualStrings("hello", result[11]);
    try std.testing.expectEqual(@as(usize, 12), result.len);
}

test "docker sandbox wrap with custom image" {
    var dk = createDockerSandbox("/tmp/workspace", "ubuntu:22.04");
    const sb = dk.sandbox();

    const argv = [_][]const u8{"ls"};
    var buf: [32][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);

    try std.testing.expectEqualStrings("ubuntu:22.04", result[9]);
    try std.testing.expectEqualStrings("ls", result[10]);
}

test "docker sandbox wrap empty argv" {
    var dk = createDockerSandbox("/tmp/workspace", null);
    const sb = dk.sandbox();

    const argv = [_][]const u8{};
    var buf: [32][]const u8 = undefined;
    const result = try sb.wrapCommand(&argv, &buf);

    // prefix (9) + image (1)
    try std.testing.expectEqual(@as(usize, 10), result.len);
}

test "docker buffer too small returns error" {
    var dk = createDockerSandbox("/tmp/workspace", null);
    const sb = dk.sandbox();

    const argv = [_][]const u8{ "echo", "test" };
    var buf: [5][]const u8 = undefined;
    const result = sb.wrapCommand(&argv, &buf);
    try std.testing.expectError(error.BufferTooSmall, result);
}

test "docker sandbox vtable consistent" {
    var dk = createDockerSandbox("/tmp/workspace", null);
    const sb = dk.sandbox();
    try std.testing.expect(sb.vtable == &DockerSandbox.sandbox_vtable);
}
