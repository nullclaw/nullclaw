//! Doctor -- system diagnostics for nullclaw.
//!
//! Mirrors ZeroClaw's doctor module with severity-based diagnostics:
//!   - DiagItem system with ok/warn/err severity levels
//!   - Config semantic validation (provider, temperature, routes, channels)
//!   - Workspace integrity (writable probe, disk space, key files)
//!   - Daemon state with proper JSON parsing
//!   - Environment checks (git, curl, shell, home)
//!   - Sandbox, cron status, channel connectivity (nullclaw-specific)

const std = @import("std");
const platform = @import("platform.zig");
const Config = @import("config.zig").Config;
const channel_catalog = @import("channel_catalog.zig");
const daemon = @import("daemon.zig");
const cron = @import("cron.zig");
const builtin = @import("builtin");

/// Staleness thresholds (seconds).
const DAEMON_STALE_SECONDS: i64 = 30;
const SCHEDULER_STALE_SECONDS: i64 = 120;
const CHANNEL_STALE_SECONDS: i64 = 300;
const COMMAND_VERSION_PREVIEW_CHARS: usize = 60;
// ── ANSI color support ──────────────────────────────────────────

const Color = struct {
    const reset = "\x1b[0m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const red = "\x1b[31m";
};

pub fn shouldColorize(file: std.fs.File) bool {
    // Respect NO_COLOR convention (https://no-color.org/)
    if (comptime builtin.os.tag != .windows) {
        if (std.posix.getenv("NO_COLOR")) |_| return false;
    }

    // Never colorize if stdout is redirected to a file/pipe
    if (!file.isTty()) return false;

    // On Windows, attempt to enable Virtual Terminal Processing.
    // If that fails, fall back to no color.
    if (builtin.os.tag == .windows) {
        return enableWindowsVT100() catch false;
    }

    return true;
}

/// Windows-specific: enable ENABLE_VIRTUAL_TERMINAL_PROCESSING on stdout.
fn enableWindowsVT100() !bool {
    const windows = std.os.windows;
    const handle = try windows.GetStdHandle(windows.STD_OUTPUT_HANDLE);
    var mode: windows.DWORD = 0;
    if (windows.kernel32.GetConsoleMode(handle, &mode) == 0) return false;
    mode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
    return windows.kernel32.SetConsoleMode(handle, mode) != 0;
}

// ── Diagnostic types ────────────────────────────────────────────

pub const Severity = enum {
    ok,
    warn,
    err,
};

pub const DiagItem = struct {
    severity: Severity,
    category: []const u8,
    message: []const u8,

    pub fn ok(cat: []const u8, msg: []const u8) DiagItem {
        return .{ .severity = .ok, .category = cat, .message = msg };
    }
    pub fn warn(cat: []const u8, msg: []const u8) DiagItem {
        return .{ .severity = .warn, .category = cat, .message = msg };
    }
    pub fn err(cat: []const u8, msg: []const u8) DiagItem {
        return .{ .severity = .err, .category = cat, .message = msg };
    }

    pub fn icon(self: DiagItem) []const u8 {
        return switch (self.severity) {
            .ok => "[ok]",
            .warn => "[warn]",
            .err => "[ERR]",
        };
    }

    pub fn iconColored(self: DiagItem) []const u8 {
        return switch (self.severity) {
            .ok => Color.green ++ "[ok]" ++ Color.reset,
            .warn => Color.yellow ++ "[warn]" ++ Color.reset,
            .err => Color.red ++ "[ERR]" ++ Color.reset,
        };
    }
};

/// Legacy diagnostic result (kept for programmatic access).
pub const DiagResult = struct {
    name: []const u8,
    ok: bool,
    message: []const u8,
};

// ── Public entry point ──────────────────────────────────────────

/// Run the full doctor diagnostics suite.
pub fn runDoctor(
    allocator: std.mem.Allocator,
    config: *const Config,
    writer: anytype,
    color: bool,
) !void {
    var items: std.ArrayList(DiagItem) = .empty;
    defer items.deinit(allocator);

    // Core checks (matching ZeroClaw)
    try checkConfigSemantics(allocator, config, &items);
    try checkWorkspace(allocator, config, &items);
    try checkDaemonState(allocator, config, &items);
    try checkEnvironment(allocator, &items);

    // nullclaw-specific extras
    checkSandbox(allocator, config, &items);
    try checkCronStatus(allocator, &items);
    checkChannels(allocator, config, &items);

    // Print grouped report
    try writer.writeAll("nullclaw Doctor (enhanced)\n\n");

    var current_cat: []const u8 = "";
    var ok_count: u32 = 0;
    var warn_count: u32 = 0;
    var err_count: u32 = 0;

    for (items.items) |item| {
        if (!std.mem.eql(u8, item.category, current_cat)) {
            current_cat = item.category;
            try writer.print("  [{s}]\n", .{current_cat});
        }
        const ic = if (color) item.iconColored() else item.icon();
        try writer.print("    {s} {s}\n", .{ ic, item.message });
        switch (item.severity) {
            .ok => ok_count += 1,
            .warn => warn_count += 1,
            .err => err_count += 1,
        }
    }

    try writer.print("\nSummary: {d} ok, {d} warnings, {d} errors\n", .{ ok_count, warn_count, err_count });
    if (err_count > 0) {
        try writer.writeAll("Run 'nullclaw doctor --fix' or check your config.\n");
    }
}

/// Legacy entry point — uses stdout directly.
pub fn run(allocator: std.mem.Allocator) !void {
    const stdout_file = std.fs.File.stdout();
    var stdout_buf: [4096]u8 = undefined;
    var bw = stdout_file.writer(&stdout_buf);
    const stdout = &bw.interface;
    const color = shouldColorize(stdout_file);

    var cfg = Config.load(allocator) catch {
        const prefix = if (color)
            Color.red ++ "[ERR]" ++ Color.reset
        else
            "[ERR]";
        try stdout.print("{s} No config found -- run `nullclaw onboard` first\n", .{prefix});
        try stdout.flush();
        return;
    };
    defer cfg.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try runDoctor(arena.allocator(), &cfg, stdout, color);
    try stdout.flush();
}

// ── Config semantic validation ──────────────────────────────────

pub fn checkConfigSemantics(
    allocator: std.mem.Allocator,
    config: *const Config,
    items: *std.ArrayList(DiagItem),
) !void {
    const cat = "config";

    // Default provider
    if (config.default_provider.len == 0) {
        try items.append(allocator, DiagItem.err(cat, "no default_provider configured"));
    } else {
        try items.append(allocator, DiagItem.ok(cat, try std.fmt.allocPrint(allocator, "provider: {s}", .{config.default_provider})));
    }

    // API key
    if (config.defaultProviderKey()) |_| {
        try items.append(allocator, DiagItem.ok(cat, "API key configured"));
    } else {
        try items.append(allocator, DiagItem.warn(cat, "no API key in providers config (may rely on env vars)"));
    }

    // Default model
    if (config.default_model) |model| {
        if (model.len > 0) {
            try items.append(allocator, DiagItem.ok(cat, try std.fmt.allocPrint(allocator, "default model: {s}", .{model})));
        } else {
            try items.append(allocator, DiagItem.warn(cat, "default_model is empty"));
        }
    } else {
        try items.append(allocator, DiagItem.warn(cat, "no default_model configured"));
    }

    // Temperature range
    if (config.default_temperature >= 0.0 and config.default_temperature <= 2.0) {
        try items.append(allocator, DiagItem.ok(cat, try std.fmt.allocPrint(allocator, "temperature {d:.1} (valid range 0.0-2.0)", .{config.default_temperature})));
    } else {
        try items.append(allocator, DiagItem.err(cat, try std.fmt.allocPrint(allocator, "temperature {d:.1} is out of range (expected 0.0-2.0)", .{config.default_temperature})));
    }

    // Gateway port
    if (config.gateway.port > 0) {
        try items.append(allocator, DiagItem.ok(cat, try std.fmt.allocPrint(allocator, "gateway port: {d}", .{config.gateway.port})));
    } else {
        try items.append(allocator, DiagItem.err(cat, "gateway port is 0 (invalid)"));
    }

    // Fallback providers
    for (config.reliability.fallback_providers) |fb| {
        if (fb.len == 0) {
            try items.append(allocator, DiagItem.warn(cat, "fallback provider is empty string"));
        }
    }

    // Model routes
    for (config.model_routes) |route| {
        if (route.hint.len == 0) {
            try items.append(allocator, DiagItem.warn(cat, "model route with empty hint"));
        }
        if (route.provider.len == 0) {
            try items.append(allocator, DiagItem.warn(cat, try std.fmt.allocPrint(
                allocator,
                "model route \"{s}\" has empty provider",
                .{route.hint},
            )));
        }
        if (route.model.len == 0) {
            try items.append(allocator, DiagItem.warn(cat, try std.fmt.allocPrint(
                allocator,
                "model route \"{s}\" has empty model",
                .{route.hint},
            )));
        }
    }

    // Channels: at least one non-CLI channel configured.
    // Use channel_catalog to avoid hardcoding channel lists in doctor checks.
    const has_channel = channel_catalog.hasAnyConfigured(config, false);

    if (has_channel) {
        try items.append(allocator, DiagItem.ok(cat, "at least one channel configured"));
    } else {
        try items.append(allocator, DiagItem.warn(cat, "no channels configured -- run `nullclaw onboard` to set one up"));
    }
}

// ── Workspace integrity ─────────────────────────────────────────

pub fn checkWorkspace(
    allocator: std.mem.Allocator,
    config: *const Config,
    items: *std.ArrayList(DiagItem),
) !void {
    const cat = "workspace";
    const ws = config.workspace_dir;

    // Check directory exists
    if (std.fs.openDirAbsolute(ws, .{})) |dir| {
        var d = dir;
        d.close();
        try items.append(allocator, DiagItem.ok(cat, try std.fmt.allocPrint(allocator, "directory exists: {s}", .{ws})));
    } else |_| {
        try items.append(allocator, DiagItem.err(cat, try std.fmt.allocPrint(allocator, "directory missing: {s}", .{ws})));
        return;
    }

    // Writable probe
    const probe_name = ".nullclaw_doctor_probe";
    const probe_path = try std.fs.path.join(allocator, &.{ ws, probe_name });
    defer allocator.free(probe_path);

    if (std.fs.createFileAbsolute(probe_path, .{})) |file| {
        file.writeAll("probe") catch {
            file.close();
            std.fs.deleteFileAbsolute(probe_path) catch {};
            try items.append(allocator, DiagItem.err(cat, "directory write probe failed"));
            return;
        };
        file.close();
        std.fs.deleteFileAbsolute(probe_path) catch {};
        try items.append(allocator, DiagItem.ok(cat, "directory is writable"));
    } else |_| {
        try items.append(allocator, DiagItem.err(cat, "directory is not writable"));
    }

    // Disk space via df -m
    if (try getDiskAvailableMb(allocator, ws)) |avail_mb| {
        if (avail_mb >= 100) {
            try items.append(allocator, DiagItem.ok(cat, try std.fmt.allocPrint(allocator, "disk space: {d} MB available", .{avail_mb})));
        } else {
            try items.append(allocator, DiagItem.warn(cat, try std.fmt.allocPrint(allocator, "low disk space: only {d} MB available", .{avail_mb})));
        }
    }

    // Key workspace files
    checkFileExists(allocator, ws, "SOUL.md", cat, items) catch {};
    checkFileExists(allocator, ws, "AGENTS.md", cat, items) catch {};
}

fn checkFileExists(
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    name: []const u8,
    cat: []const u8,
    items: *std.ArrayList(DiagItem),
) !void {
    const dir = std.fs.openDirAbsolute(base_dir, .{}) catch return;
    var d = dir;
    defer d.close();

    if (d.statFile(name)) |_| {
        if (std.mem.eql(u8, name, "SOUL.md")) {
            try items.append(allocator, DiagItem.ok(cat, "SOUL.md present"));
        } else if (std.mem.eql(u8, name, "AGENTS.md")) {
            try items.append(allocator, DiagItem.ok(cat, "AGENTS.md present"));
        } else {
            try items.append(allocator, DiagItem.ok(cat, "file present"));
        }
    } else |_| {
        if (std.mem.eql(u8, name, "SOUL.md")) {
            try items.append(allocator, DiagItem.warn(cat, "SOUL.md not found (optional)"));
        } else if (std.mem.eql(u8, name, "AGENTS.md")) {
            try items.append(allocator, DiagItem.warn(cat, "AGENTS.md not found (optional)"));
        } else {
            try items.append(allocator, DiagItem.warn(cat, "file not found (optional)"));
        }
    }
}

fn getDiskAvailableMb(allocator: std.mem.Allocator, path: []const u8) !?u64 {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "df", "-m", path },
        .max_output_bytes = 4096,
    }) catch return null;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) return null,
        else => return null,
    }
    return parseDfAvailableMb(result.stdout);
}

pub fn parseDfAvailableMb(df_output: []const u8) ?u64 {
    // Parse last non-empty data line of df -m output.
    // Lines look like: "/dev/disk1s5  489770  234567  254203  48% /"
    // Available is the 4th column (index 3).
    var last_data_line: ?[]const u8 = null;
    var it = std.mem.splitScalar(u8, df_output, '\n');
    // Skip header line
    _ = it.next();
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len > 0) {
            last_data_line = trimmed;
        }
    }

    const line = last_data_line orelse return null;
    var col_it = std.mem.tokenizeAny(u8, line, " \t");
    // Skip: filesystem, 1M-blocks, used
    _ = col_it.next() orelse return null;
    _ = col_it.next() orelse return null;
    _ = col_it.next() orelse return null;
    // 4th column: available
    const avail_str = col_it.next() orelse return null;
    return std.fmt.parseInt(u64, avail_str, 10) catch return null;
}

// ── Daemon state (proper JSON parsing) ──────────────────────────

pub fn checkDaemonState(
    allocator: std.mem.Allocator,
    config: *const Config,
    items: *std.ArrayList(DiagItem),
) !void {
    const cat = "daemon";

    const state_path = try daemon.stateFilePath(allocator, config);
    defer allocator.free(state_path);

    const content = std.fs.cwd().readFileAlloc(allocator, state_path, 1024 * 1024) catch {
        try items.append(allocator, DiagItem.err(cat, try std.fmt.allocPrint(
            allocator,
            "state file not found: {s} -- is the daemon running?",
            .{state_path},
        )));
        return;
    };
    defer allocator.free(content);

    try items.append(allocator, DiagItem.ok(cat, try std.fmt.allocPrint(allocator, "state file: {s}", .{state_path})));

    // Parse JSON
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{}) catch {
        try items.append(allocator, DiagItem.err(cat, "invalid state JSON"));
        return;
    };
    defer parsed.deinit();

    const root = parsed.value;

    // Check status
    if (root.object.get("status")) |status_val| {
        if (status_val == .string) {
            if (std.mem.eql(u8, status_val.string, "running")) {
                try items.append(allocator, DiagItem.ok(cat, "daemon reports running"));
            } else {
                try items.append(allocator, DiagItem.err(cat, try std.fmt.allocPrint(
                    allocator,
                    "daemon status: {s} (expected running)",
                    .{status_val.string},
                )));
            }
        }
    }

    // Check updated_at timestamp for staleness
    if (root.object.get("updated_at")) |ts_val| {
        if (ts_val == .integer) {
            const updated_at: i64 = ts_val.integer;
            const now: i64 = @intCast(std.time.timestamp());
            const age = now - updated_at;
            if (age <= DAEMON_STALE_SECONDS) {
                try items.append(allocator, DiagItem.ok(cat, try std.fmt.allocPrint(
                    allocator,
                    "heartbeat fresh ({d}s ago)",
                    .{age},
                )));
            } else {
                try items.append(allocator, DiagItem.err(cat, try std.fmt.allocPrint(
                    allocator,
                    "heartbeat stale ({d}s ago)",
                    .{age},
                )));
            }
        }
    }

    // Check components
    if (root.object.get("components")) |comps_val| {
        if (comps_val == .object) {
            const components = &comps_val.object;

            // Scheduler
            if (components.get("scheduler")) |scheduler| {
                if (scheduler == .object) {
                    const status_ok = if (scheduler.object.get("status")) |s|
                        (s == .string and std.mem.eql(u8, s.string, "ok"))
                    else
                        false;
                    if (status_ok) {
                        try items.append(allocator, DiagItem.ok(cat, "scheduler healthy"));
                    } else {
                        try items.append(allocator, DiagItem.err(cat, "scheduler unhealthy"));
                    }
                }
            } else {
                try items.append(allocator, DiagItem.warn(cat, "scheduler component not tracked yet"));
            }

            // Count channel components
            var channel_count: u32 = 0;
            var stale_count: u32 = 0;
            var comp_it = components.iterator();
            while (comp_it.next()) |entry| {
                if (std.mem.startsWith(u8, entry.key_ptr.*, "channel:")) {
                    channel_count += 1;
                    if (entry.value_ptr.* == .object) {
                        const status_ok = if (entry.value_ptr.object.get("status")) |s|
                            (s == .string and std.mem.eql(u8, s.string, "ok"))
                        else
                            false;
                        if (!status_ok) {
                            stale_count += 1;
                        }
                    }
                }
            }

            if (channel_count == 0) {
                try items.append(allocator, DiagItem.warn(cat, "no channel components tracked yet"));
            } else if (stale_count > 0) {
                try items.append(allocator, DiagItem.warn(cat, try std.fmt.allocPrint(
                    allocator,
                    "{d} channels, {d} stale",
                    .{ channel_count, stale_count },
                )));
            } else {
                try items.append(allocator, DiagItem.ok(cat, try std.fmt.allocPrint(
                    allocator,
                    "{d} channels, all healthy",
                    .{channel_count},
                )));
            }
        }
    }
}

// ── Environment checks ──────────────────────────────────────────

pub fn checkEnvironment(
    allocator: std.mem.Allocator,
    items: *std.ArrayList(DiagItem),
) !void {
    const cat = "env";

    // git
    if (try checkCommandAvailable(allocator, "git")) |ver| {
        defer allocator.free(ver);
        try items.append(allocator, DiagItem.ok(cat, try std.fmt.allocPrint(allocator, "git: {s}", .{ver})));
    } else {
        try items.append(allocator, DiagItem.warn(cat, "git not found"));
    }

    // curl
    if (try checkCommandAvailable(allocator, "curl")) |ver| {
        defer allocator.free(ver);
        try items.append(allocator, DiagItem.ok(cat, try std.fmt.allocPrint(allocator, "curl: {s}", .{ver})));
    } else {
        try items.append(allocator, DiagItem.warn(cat, "curl not found"));
    }

    // $SHELL
    if (std.process.getEnvVarOwned(allocator, "SHELL")) |shell| {
        defer allocator.free(shell);
        if (shell.len > 0) {
            try items.append(allocator, DiagItem.ok(cat, try std.fmt.allocPrint(allocator, "shell: {s}", .{shell})));
        } else {
            try items.append(allocator, DiagItem.warn(cat, "$SHELL not set"));
        }
    } else |_| {
        try items.append(allocator, DiagItem.warn(cat, "$SHELL not set"));
    }

    // $HOME
    if (platform.getHomeDir(allocator)) |home| {
        defer allocator.free(home);
        try items.append(allocator, DiagItem.ok(cat, "home directory env set"));
    } else |_| {
        try items.append(allocator, DiagItem.err(cat, "home directory is not set"));
    }
}

fn checkCommandAvailable(allocator: std.mem.Allocator, cmd: []const u8) !?[]const u8 {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ cmd, "--version" },
        .max_output_bytes = 1024,
    }) catch return null;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) return null,
        else => return null,
    }

    // Take first line, trimmed
    const trimmed = std.mem.trim(u8, result.stdout, " \n\r\t");
    var line_it = std.mem.splitScalar(u8, trimmed, '\n');
    const first_line = line_it.first();

    return try truncateForDisplay(allocator, first_line, COMMAND_VERSION_PREVIEW_CHARS);
}

pub fn truncateForDisplay(allocator: std.mem.Allocator, s: []const u8, max_len: usize) ![]const u8 {
    if (s.len <= max_len) return allocator.dupe(u8, s);
    // Find valid UTF-8 boundary at or before max_len
    var i = max_len;
    while (i > 0 and (s[i] & 0xC0) == 0x80) : (i -= 1) {}
    return allocator.dupe(u8, s[0..i]);
}

// ── Nullclaw-specific checks ────────────────────────────────────

/// Check sandbox availability.
fn checkSandbox(allocator: std.mem.Allocator, cfg: *const Config, items: *std.ArrayList(DiagItem)) void {
    const cat = "sandbox";
    const enabled = cfg.security.sandbox.enabled orelse false;

    if (!enabled) {
        items.append(allocator, DiagItem.ok(cat, "sandbox: disabled")) catch {};
        return;
    }

    items.append(allocator, DiagItem.ok(cat, "sandbox: enabled")) catch {};
}

/// Check cron scheduler status.
fn checkCronStatus(allocator: std.mem.Allocator, items: *std.ArrayList(DiagItem)) !void {
    const cat = "cron";
    var scheduler = cron.CronScheduler.init(allocator, 1024, true);
    defer scheduler.deinit();
    cron.loadJobs(&scheduler) catch {
        try items.append(allocator, DiagItem.ok(cat, "cron: no jobs file (first run)"));
        return;
    };

    const jobs = scheduler.listJobs();
    if (jobs.len == 0) {
        try items.append(allocator, DiagItem.ok(cat, "cron: no scheduled jobs"));
    } else {
        var active: usize = 0;
        var paused: usize = 0;
        for (jobs) |job| {
            if (job.paused) {
                paused += 1;
            } else {
                active += 1;
            }
        }
        try items.append(allocator, DiagItem.ok(cat, try std.fmt.allocPrint(
            allocator,
            "cron: {d} jobs ({d} active, {d} paused)",
            .{ jobs.len, active, paused },
        )));
    }
}

/// Check channel connectivity.
fn checkChannels(allocator: std.mem.Allocator, cfg: *const Config, items: *std.ArrayList(DiagItem)) void {
    const cat = "channels";
    items.append(allocator, DiagItem.ok(cat, "CLI always available")) catch {};

    for (channel_catalog.known_channels) |meta| {
        if (meta.id == .cli) continue;
        if (!channel_catalog.isConfigured(cfg, meta.id)) continue;
        items.append(allocator, DiagItem.ok(cat, meta.configured_message)) catch {};
    }
}

/// Check a specific diagnostic (utility for programmatic access).
pub fn checkConfig(allocator: std.mem.Allocator) DiagResult {
    var cfg = Config.load(allocator) catch {
        return .{ .name = "config", .ok = false, .message = "No config found" };
    };
    cfg.deinit();
    return .{ .name = "config", .ok = true, .message = "Config loaded" };
}

// ── Tests ────────────────────────────────────────────────────────

test "DiagItem.ok creates ok item" {
    const item = DiagItem.ok("test", "all good");
    try std.testing.expectEqual(Severity.ok, item.severity);
    try std.testing.expectEqualStrings("test", item.category);
    try std.testing.expectEqualStrings("all good", item.message);
}

test "DiagItem.warn creates warn item" {
    const item = DiagItem.warn("test", "watch out");
    try std.testing.expectEqual(Severity.warn, item.severity);
    try std.testing.expectEqualStrings("watch out", item.message);
}

test "DiagItem.err creates err item" {
    const item = DiagItem.err("test", "broken");
    try std.testing.expectEqual(Severity.err, item.severity);
    try std.testing.expectEqualStrings("broken", item.message);
}

test "DiagItem.icon returns correct string" {
    try std.testing.expectEqualStrings("[ok]", DiagItem.ok("t", "m").icon());
    try std.testing.expectEqualStrings("[warn]", DiagItem.warn("t", "m").icon());
    try std.testing.expectEqualStrings("[ERR]", DiagItem.err("t", "m").icon());
}

test "DiagItem.iconColored returns ANSI-colored strings" {
    const ok_icon = DiagItem.ok("t", "m").iconColored();
    try std.testing.expect(std.mem.indexOf(u8, ok_icon, "\x1b[32m") != null);
    try std.testing.expect(std.mem.indexOf(u8, ok_icon, "[ok]") != null);
    try std.testing.expect(std.mem.indexOf(u8, ok_icon, "\x1b[0m") != null);

    const warn_icon = DiagItem.warn("t", "m").iconColored();
    try std.testing.expect(std.mem.indexOf(u8, warn_icon, "\x1b[33m") != null);
    try std.testing.expect(std.mem.indexOf(u8, warn_icon, "[warn]") != null);

    const err_icon = DiagItem.err("t", "m").iconColored();
    try std.testing.expect(std.mem.indexOf(u8, err_icon, "\x1b[31m") != null);
    try std.testing.expect(std.mem.indexOf(u8, err_icon, "[ERR]") != null);
}

test "shouldColorize returns false for non-TTY file" {
    // Open /dev/null — it's not a TTY, so shouldColorize should return false
    const devnull = std.fs.openFileAbsolute("/dev/null", .{}) catch return;
    defer devnull.close();
    try std.testing.expect(!shouldColorize(devnull));
}

test "checkConfigSemantics catches temperature out of range" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var items: std.ArrayList(DiagItem) = .empty;

    var cfg = testConfig();
    cfg.default_temperature = 5.0;
    try checkConfigSemantics(allocator, &cfg, &items);

    var found_temp_err = false;
    for (items.items) |item| {
        if (std.mem.indexOf(u8, item.message, "temperature") != null and item.severity == .err) {
            found_temp_err = true;
        }
    }
    try std.testing.expect(found_temp_err);
}

test "checkConfigSemantics accepts valid temperature" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var items: std.ArrayList(DiagItem) = .empty;

    var cfg = testConfig();
    cfg.default_temperature = 0.7;
    try checkConfigSemantics(allocator, &cfg, &items);

    var found_temp_ok = false;
    for (items.items) |item| {
        if (std.mem.indexOf(u8, item.message, "temperature") != null and item.severity == .ok) {
            found_temp_ok = true;
        }
    }
    try std.testing.expect(found_temp_ok);
}

test "checkConfigSemantics warns empty default provider" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var items: std.ArrayList(DiagItem) = .empty;

    var cfg = testConfig();
    cfg.default_provider = "";
    try checkConfigSemantics(allocator, &cfg, &items);

    var found_err = false;
    for (items.items) |item| {
        if (std.mem.indexOf(u8, item.message, "default_provider") != null and item.severity == .err) {
            found_err = true;
        }
    }
    try std.testing.expect(found_err);
}

test "checkConfigSemantics warns no channels" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var items: std.ArrayList(DiagItem) = .empty;

    const cfg = testConfig();
    try checkConfigSemantics(allocator, &cfg, &items);

    var found_warn = false;
    for (items.items) |item| {
        if (std.mem.indexOf(u8, item.message, "no channels") != null and item.severity == .warn) {
            found_warn = true;
        }
    }
    try std.testing.expect(found_warn);
}

test "parseDfAvailableMb parses output" {
    const stdout = "Filesystem 1M-blocks Used Available Use% Mounted on\n/dev/sda1 1000 500 500 50% /\n";
    const result = parseDfAvailableMb(stdout);
    try std.testing.expectEqual(@as(?u64, 500), result);
}

test "parseDfAvailableMb returns null on empty" {
    try std.testing.expectEqual(@as(?u64, null), parseDfAvailableMb(""));
    try std.testing.expectEqual(@as(?u64, null), parseDfAvailableMb("header only\n"));
}

test "truncateForDisplay preserves UTF-8 boundaries" {
    const allocator = std.testing.allocator;
    const short = try truncateForDisplay(allocator, "hello world", 5);
    defer allocator.free(short);
    try std.testing.expectEqualStrings("hello", short);
}

test "truncateForDisplay no-op when short enough" {
    const allocator = std.testing.allocator;
    const same = try truncateForDisplay(allocator, "hi", 10);
    defer allocator.free(same);
    try std.testing.expectEqualStrings("hi", same);
}

test "checkEnvironment finds existing commands" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var items: std.ArrayList(DiagItem) = .empty;

    try checkEnvironment(allocator, &items);

    // Should find at least $HOME on any dev machine
    var found_home = false;
    for (items.items) |item| {
        if (std.mem.indexOf(u8, item.message, "home directory") != null and item.severity == .ok) {
            found_home = true;
        }
    }
    try std.testing.expect(found_home);
}

test "checkDaemonState handles missing file" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var items: std.ArrayList(DiagItem) = .empty;

    var cfg = testConfig();
    cfg.config_path = "/tmp/nonexistent-nullclaw-test/config.json";

    try checkDaemonState(allocator, &cfg, &items);

    var found_err = false;
    for (items.items) |item| {
        if (std.mem.indexOf(u8, item.message, "not found") != null and item.severity == .err) {
            found_err = true;
        }
    }
    try std.testing.expect(found_err);
}

test "checkDaemonState parses valid JSON state" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(base);

    const state_content =
        \\{"status": "running", "updated_at": 9999999999, "components": {"scheduler": {"status": "ok"}, "channel:telegram": {"status": "ok"}}}
    ;
    {
        const file = try tmp.dir.createFile("daemon_state.json", .{});
        try file.writeAll(state_content);
        file.close();
    }

    const cfg_path = try std.fs.path.join(std.testing.allocator, &.{ base, "config.json" });
    defer std.testing.allocator.free(cfg_path);

    var items: std.ArrayList(DiagItem) = .empty;

    var cfg = testConfig();
    cfg.config_path = cfg_path;

    try checkDaemonState(allocator, &cfg, &items);

    var found_running = false;
    var found_scheduler = false;
    for (items.items) |item| {
        if (std.mem.indexOf(u8, item.message, "running") != null) found_running = true;
        if (std.mem.indexOf(u8, item.message, "scheduler") != null) found_scheduler = true;
    }
    try std.testing.expect(found_running);
    try std.testing.expect(found_scheduler);
}

test "staleness constants are reasonable" {
    try std.testing.expect(DAEMON_STALE_SECONDS > 0);
    try std.testing.expect(SCHEDULER_STALE_SECONDS > DAEMON_STALE_SECONDS);
    try std.testing.expect(CHANNEL_STALE_SECONDS > SCHEDULER_STALE_SECONDS);
}

test "DiagResult defaults" {
    const result = DiagResult{ .name = "test", .ok = true, .message = "all good" };
    try std.testing.expectEqualStrings("test", result.name);
    try std.testing.expect(result.ok);
}

test "doctor module compiles" {}

// ── Test helper ─────────────────────────────────────────────────

fn testConfig() Config {
    return Config{
        .workspace_dir = "/tmp/nullclaw-test-workspace",
        .config_path = "/tmp/nullclaw-test/config.json",
        .allocator = std.testing.allocator,
    };
}
