//! Self-update command for nullclaw.
//!
//! Checks GitHub releases for updates and provides an automated
//! update path for binary installations.

const std = @import("std");
const builtin = @import("builtin");

const log = std.log.scoped(.update);

// ── Public API ───────────────────────────────────────────────────────

pub const Options = struct {
    check_only: bool = false,
    yes: bool = false,
};

pub fn run(allocator: std.mem.Allocator, opts: Options) !void {
    // Get current version
    const current_version = @import("version.zig").string;

    // Detect install method
    const install_method = detectInstallMethod() catch |err| {
        std.debug.print("Failed to detect install method: {}\n", .{err});
        return err;
    };

    // For package managers, just print instructions
    if (install_method == .nix or install_method == .homebrew or install_method == .docker) {
        try printPackageManagerUpdate(install_method);
        return;
    }

    // For dev installs, print git instructions
    if (install_method == .dev) {
        std.debug.print("Development installation detected.\n", .{});
        std.debug.print("To update, run:\n  git pull && zig build\n", .{});
        return;
    }

    // For binary installs, check for updates
    const latest = try getLatestRelease(allocator);
    defer latest.deinit(allocator);

    // Compare versions
    const current_clean = stripV(current_version);
    const latest_clean = stripV(latest.tag_name);

    if (std.mem.eql(u8, current_clean, latest_clean)) {
        std.debug.print("Already up to date: {s}\n", .{current_version});
        return;
    }

    // Update available
    std.debug.print("Current version: {s}\n", .{current_version});
    std.debug.print("Latest version:  {s}\n", .{latest.tag_name});
    std.debug.print("\n", .{});

    // Show release notes (first few lines)
    if (latest.body.len > 0) {
        std.debug.print("Release notes:\n", .{});
        var lines = std.mem.splitScalar(u8, latest.body, '\n');
        var line_count: usize = 0;
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "##")) continue;
            std.debug.print("  {s}\n", .{line});
            line_count += 1;
            if (line_count >= 5) break;
        }
        std.debug.print("\n", .{});
    }

    std.debug.print("Release: {s}\n", .{latest.html_url});
    std.debug.print("\n", .{});

    if (opts.check_only) {
        return;
    }

    // Get current platform
    const target = getCurrentPlatform() orelse {
        std.debug.print("Unsupported platform for auto-update.\n", .{});
        std.debug.print("Please download manually from: {s}\n", .{latest.html_url});
        return error.UnsupportedPlatform;
    };

    // Find matching asset
    const asset_name = target.assetName();
    const download_url = findAssetUrl(allocator, asset_name) orelse {
        std.debug.print("No release asset found for platform: {s}\n", .{asset_name});
        std.debug.print("Please download manually from: {s}\n", .{latest.html_url});
        return error.NoAssetFound;
    };
    defer allocator.free(download_url);

    // Confirm update
    if (!opts.yes) {
        std.debug.print("Download and install {s}? [y/N] ", .{latest.tag_name});
        const response = try readLine(allocator);
        defer allocator.free(response);
        if (!std.mem.eql(u8, response, "y") and !std.mem.eql(u8, response, "Y")) {
            std.debug.print("Update cancelled.\n", .{});
            return;
        }
    }

    // Get executable path
    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = try std.fs.selfExePath(&exe_buf);

    // Download and install
    try downloadAndInstall(allocator, download_url, exe_path, asset_name);

    std.debug.print("\nUpdated: {s} → {s}\n", .{ current_version, latest.tag_name });
    std.debug.print("Restart nullclaw to use the new version.\n", .{});
}

// ── Install Detection ─────────────────────────────────────────────────

pub const InstallMethod = enum {
    nix,
    homebrew,
    docker,
    binary,
    dev,
    unknown,
};

pub fn detectInstallMethod() !InstallMethod {
    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = try std.fs.selfExePath(&exe_buf);

    // Check for nix
    if (std.mem.indexOf(u8, exe_path, "/nix/store/") != null) {
        return .nix;
    }

    // Check for homebrew
    if (std.mem.indexOf(u8, exe_path, "/homebrew/") != null or
        std.mem.indexOf(u8, exe_path, "/Cellar/") != null)
    {
        return .homebrew;
    }

    // Check for docker
    if (std.mem.eql(u8, exe_path, "/nullclaw")) {
        return .docker;
    }

    // Check for dev/build
    if (std.mem.indexOf(u8, exe_path, "zig-out") != null) {
        return .dev;
    }

    return .binary;
}

fn printPackageManagerUpdate(method: InstallMethod) !void {
    const name = switch (method) {
        .nix => "Nix",
        .homebrew => "Homebrew",
        .docker => "Docker",
        else => unreachable,
    };

    const cmd = switch (method) {
        .nix => "nix-channel --update && nix-env -iA nixpkgs.nullclaw",
        .homebrew => "brew upgrade nullclaw",
        .docker => "docker pull ghcr.io/nullclaw/nullclaw:latest",
        else => unreachable,
    };

    std.debug.print("Detected installation via: {s}\n", .{name});
    std.debug.print("To update, run:\n  {s}\n", .{cmd});
}

// ── GitHub API ────────────────────────────────────────────────────────

pub const ReleaseInfo = struct {
    tag_name: []const u8,
    html_url: []const u8,
    published_at: []const u8,
    body: []const u8,

    pub fn deinit(self: *const ReleaseInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.tag_name);
        allocator.free(self.html_url);
        allocator.free(self.published_at);
        allocator.free(self.body);
    }
};

pub fn getLatestRelease(allocator: std.mem.Allocator) !ReleaseInfo {
    const url = "https://api.github.com/repos/nullclaw/nullclaw/releases/latest";

    // Use curl subprocess approach (from http_util pattern)
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "curl", "-sf", "--max-time", "30", url },
        .max_output_bytes = 10 * 1024 * 1024,
    }) catch |err| {
        log.err("curl failed: {}", .{err});
        return error.CurlFailed;
    };
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    if (result.stdout.len == 0) {
        return error.EmptyResponse;
    }

    // Parse JSON
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{}) catch |err| {
        log.err("JSON parse failed: {}", .{err});
        return error.InvalidJson;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidJson;

    const tag_name_val = root.object.get("tag_name") orelse return error.MissingField;
    const html_url_val = root.object.get("html_url") orelse return error.MissingField;
    const published_at_val = root.object.get("published_at") orelse return error.MissingField;
    const body_val = root.object.get("body") orelse return error.MissingField;

    if (tag_name_val != .string) return error.InvalidFieldType;
    if (html_url_val != .string) return error.InvalidFieldType;
    if (published_at_val != .string) return error.InvalidFieldType;
    if (body_val != .string) return error.InvalidFieldType;

    return ReleaseInfo{
        .tag_name = try allocator.dupe(u8, tag_name_val.string),
        .html_url = try allocator.dupe(u8, html_url_val.string),
        .published_at = try allocator.dupe(u8, published_at_val.string),
        .body = try allocator.dupe(u8, body_val.string),
    };
}

// ── Version Comparison ────────────────────────────────────────────────

fn stripV(v: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, v, "v")) v[1..] else v;
}

// ── Platform Detection ────────────────────────────────────────────────

pub const PlatformTarget = enum {
    linux_x86_64,
    linux_aarch64,
    macos_aarch64,
    macos_x86_64,
    windows_x86_64,

    pub fn assetName(self: PlatformTarget) []const u8 {
        return switch (self) {
            .linux_x86_64 => "nullclaw-linux-x86_64.bin",
            .linux_aarch64 => "nullclaw-linux-aarch64.bin",
            .macos_aarch64 => "nullclaw-macos-aarch64.bin",
            .macos_x86_64 => "nullclaw-macos-x86_64.bin",
            .windows_x86_64 => "nullclaw-windows-x86_64.exe",
        };
    }
};

fn platformFromParts(os: std.Target.Os.Tag, arch: std.Target.Cpu.Arch) ?PlatformTarget {
    if (os == .linux) {
        if (arch == .x86_64) return .linux_x86_64;
        if (arch == .aarch64) return .linux_aarch64;
    } else if (os == .macos) {
        if (arch == .aarch64) return .macos_aarch64;
        if (arch == .x86_64) return .macos_x86_64;
    } else if (os == .windows) {
        if (arch == .x86_64) return .windows_x86_64;
    }
    return null;
}

pub fn getCurrentPlatform() ?PlatformTarget {
    return platformFromParts(builtin.os.tag, builtin.cpu.arch);
}

// ── Asset URL Finding ─────────────────────────────────────────────────

fn findAssetUrl(allocator: std.mem.Allocator, asset_name: []const u8) ?[]const u8 {
    // Construct the download URL directly
    const base_url = "https://github.com/nullclaw/nullclaw/releases/latest/download/";

    var buf: [256]u8 = undefined;
    const url = std.fmt.bufPrint(&buf, "{s}{s}", .{ base_url, asset_name }) catch return null;
    return allocator.dupe(u8, url) catch null;
}

// ── Download & Install ────────────────────────────────────────────────

fn downloadAndInstall(
    allocator: std.mem.Allocator,
    url: []const u8,
    exe_path: []const u8,
    asset_name: []const u8,
) !void {
    std.debug.print("Downloading {s}...\n", .{asset_name});

    // Create temp file first
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.partial", .{exe_path});
    defer allocator.free(tmp_path);

    var tmp_file = try std.fs.createFileAbsolute(tmp_path, .{ .read = true });
    var tmp_closed = false;
    defer if (!tmp_closed) tmp_file.close();
    errdefer {
        if (!tmp_closed) {
            tmp_file.close();
            tmp_closed = true;
        }
        std.fs.deleteFileAbsolute(tmp_path) catch {};
    }

    // Download directly to file (streaming, no memory buffer limit)
    const bytes_downloaded = downloadToFile(allocator, url, &tmp_file) catch |err| {
        log.err("Download failed: {}", .{err});
        return error.DownloadFailed;
    };

    if (bytes_downloaded == 0) {
        return error.EmptyDownload;
    }

    std.debug.print("Downloaded {d} bytes\n", .{bytes_downloaded});

    // Set executable permissions (Unix only)
    if (comptime builtin.os.tag != .windows) {
        tmp_file.chmod(0o755) catch |err| {
            log.warn("Failed to set executable permissions: {}", .{err});
        };
    }

    // Close handle before rename/replacement (required on Windows).
    tmp_file.close();
    tmp_closed = true;

    // Atomic replacement
    try atomicReplace(tmp_path, exe_path);

    std.debug.print("Installed successfully.\n", .{});
}

/// Download a URL directly to a file using curl.
/// Streams the data to avoid memory buffer limits.
/// Returns the number of bytes downloaded.
fn downloadToFile(allocator: std.mem.Allocator, url: []const u8, file: *std.fs.File) !usize {
    const argv = &[_][]const u8{ "curl", "-sfL", "--max-time", "60", url };
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    child.spawn() catch |err| {
        log.err("curl spawn failed: {}", .{err});
        return error.CurlFailed;
    };

    const stdout = child.stdout.?;

    const BUF_SIZE = 64 * 1024;
    var buffer: [BUF_SIZE]u8 = undefined;
    var total_bytes: usize = 0;

    while (true) {
        const bytes_read = stdout.read(&buffer) catch |err| {
            log.err("curl read failed: {}", .{err});
            _ = child.kill() catch {};
            _ = child.wait() catch {};
            return error.CurlFailed;
        };

        if (bytes_read == 0) break;

        file.writeAll(buffer[0..bytes_read]) catch |err| {
            log.err("download write failed: {}", .{err});
            _ = child.kill() catch {};
            _ = child.wait() catch {};
            return err;
        };
        total_bytes += bytes_read;
    }

    const term = child.wait() catch |err| {
        log.err("curl wait failed: {}", .{err});
        return error.CurlFailed;
    };

    switch (term) {
        .Exited => |code| if (code != 0) {
            log.err("curl exited with code: {}", .{code});
            return error.CurlFailed;
        },
        else => return error.CurlFailed,
    }

    return total_bytes;
}

fn atomicReplace(tmp_path: []const u8, exe_path: []const u8) !void {
    if (comptime builtin.os.tag == .windows) {
        // Windows: can't replace running binary, rename old first
        const old_path = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.old", .{exe_path});
        defer std.heap.page_allocator.free(old_path);

        std.fs.deleteFileAbsolute(old_path) catch {};
        std.fs.renameAbsolute(exe_path, old_path) catch {};

        try std.fs.renameAbsolute(tmp_path, exe_path);
        std.fs.deleteFileAbsolute(old_path) catch {};
    } else {
        // Unix: atomic rename on same filesystem
        try std.fs.renameAbsolute(tmp_path, exe_path);
    }
}

// ── User Input ────────────────────────────────────────────────────────

fn readLine(allocator: std.mem.Allocator) ![]const u8 {
    const stdin = std.fs.File.stdin();

    var buffer: [256]u8 = undefined;
    var pos: usize = 0;
    while (pos < buffer.len) {
        const n = try stdin.read(buffer[pos .. pos + 1]);
        if (n == 0) return error.EndOfStream; // EOF
        if (buffer[pos] == '\n') break;
        pos += 1;
    }

    // Trim newline
    const trimmed = std.mem.trimRight(u8, buffer[0..pos], "\r");
    return allocator.dupe(u8, trimmed);
}

// ── Tests ────────────────────────────────────────────────────────────

test "detectInstallMethod" {
    const method = try detectInstallMethod();
    // Should at least not crash
    _ = method;
}

test "getCurrentPlatform" {
    const platform = getCurrentPlatform();
    // Should return null or a valid platform for this system
    if (platform) |p| {
        _ = p.assetName();
    }
}

test "stripV" {
    try std.testing.expectEqualStrings("2026.2.21", stripV("v2026.2.21"));
    try std.testing.expectEqualStrings("2026.2.21", stripV("2026.2.21"));
}

test "PlatformTarget.assetName covers all release assets" {
    try std.testing.expectEqualStrings("nullclaw-linux-x86_64.bin", PlatformTarget.linux_x86_64.assetName());
    try std.testing.expectEqualStrings("nullclaw-linux-aarch64.bin", PlatformTarget.linux_aarch64.assetName());
    try std.testing.expectEqualStrings("nullclaw-macos-aarch64.bin", PlatformTarget.macos_aarch64.assetName());
    try std.testing.expectEqualStrings("nullclaw-macos-x86_64.bin", PlatformTarget.macos_x86_64.assetName());
    try std.testing.expectEqualStrings("nullclaw-windows-x86_64.exe", PlatformTarget.windows_x86_64.assetName());
}

test "platformFromParts maps supported and unsupported targets" {
    try std.testing.expectEqual(PlatformTarget.linux_x86_64, platformFromParts(.linux, .x86_64).?);
    try std.testing.expectEqual(PlatformTarget.linux_aarch64, platformFromParts(.linux, .aarch64).?);
    try std.testing.expectEqual(PlatformTarget.macos_aarch64, platformFromParts(.macos, .aarch64).?);
    try std.testing.expectEqual(PlatformTarget.macos_x86_64, platformFromParts(.macos, .x86_64).?);
    try std.testing.expectEqual(PlatformTarget.windows_x86_64, platformFromParts(.windows, .x86_64).?);

    try std.testing.expect(platformFromParts(.windows, .aarch64) == null);
    try std.testing.expect(platformFromParts(.freebsd, .x86_64) == null);
}

test "downloadToFile streams from local file URL" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const src_name = "src.bin";
    const dst_name = "dst.bin";
    const payload = "hello-streaming-download";

    var src_file = try tmp_dir.dir.createFile(src_name, .{});
    defer src_file.close();
    try src_file.writeAll(payload);
    try src_file.sync();

    const src_abs = try tmp_dir.dir.realpathAlloc(allocator, src_name);
    defer allocator.free(src_abs);

    const file_url = try std.fmt.allocPrint(allocator, "file://{s}", .{src_abs});
    defer allocator.free(file_url);

    var dst_file = try tmp_dir.dir.createFile(dst_name, .{ .read = true });
    defer dst_file.close();

    const bytes_downloaded = downloadToFile(
        allocator,
        file_url,
        &dst_file,
    ) catch |err| {
        if (err == error.CurlFailed) return error.SkipZigTest;
        return err;
    };

    try std.testing.expectEqual(payload.len, bytes_downloaded);

    try dst_file.seekTo(0);
    const content = try dst_file.readToEndAlloc(allocator, payload.len + 1);
    defer allocator.free(content);
    try std.testing.expectEqualStrings(payload, content);
}
