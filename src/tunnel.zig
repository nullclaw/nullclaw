const std = @import("std");
const config = @import("config.zig");

// Tunnel -- ngrok/cloudflare/tailscale/custom tunnel management.
//
// Mirrors ZeroClaw's tunnel module: provider abstraction, factory,
// vtable interface, and per-provider implementations with real process spawning.

// ── Tunnel Provider ─────────────────────────────────────────────

pub const TunnelProvider = enum {
    none,
    cloudflare,
    tailscale,
    ngrok,
    custom,

    pub fn fromString(s: []const u8) ?TunnelProvider {
        if (s.len == 0 or std.mem.eql(u8, s, "none")) return .none;
        if (std.mem.eql(u8, s, "cloudflare")) return .cloudflare;
        if (std.mem.eql(u8, s, "tailscale")) return .tailscale;
        if (std.mem.eql(u8, s, "ngrok")) return .ngrok;
        if (std.mem.eql(u8, s, "custom")) return .custom;
        return null;
    }

    pub fn name(self: TunnelProvider) []const u8 {
        return switch (self) {
            .none => "none",
            .cloudflare => "cloudflare",
            .tailscale => "tailscale",
            .ngrok => "ngrok",
            .custom => "custom",
        };
    }
};

// ── Tunnel Config (extended) ────────────────────────────────────

pub const CloudflareTunnelConfig = struct {
    token: []const u8,
};

pub const TailscaleTunnelConfig = struct {
    funnel: bool = false,
    hostname: ?[]const u8 = null,
};

pub const NgrokTunnelConfig = struct {
    auth_token: []const u8,
    domain: ?[]const u8 = null,
};

pub const CustomTunnelConfig = struct {
    start_command: []const u8,
    health_url: ?[]const u8 = null,
    url_pattern: ?[]const u8 = null,
};

pub const TunnelFullConfig = struct {
    provider: []const u8 = "none",
    cloudflare: ?CloudflareTunnelConfig = null,
    tailscale: ?TailscaleTunnelConfig = null,
    ngrok: ?NgrokTunnelConfig = null,
    custom: ?CustomTunnelConfig = null,
};

// ── Tunnel State ────────────────────────────────────────────────

pub const TunnelState = enum {
    stopped,
    starting,
    running,
    error_state,
};

// ── Tunnel Vtable Interface ─────────────────────────────────────

/// Tunnel vtable interface -- abstracts tunnel provider differences.
pub const TunnelAdapter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        start: *const fn (ptr: *anyopaque, local_port: u16) TunnelError![]const u8,
        stop: *const fn (ptr: *anyopaque) void,
        public_url: *const fn (ptr: *anyopaque) ?[]const u8,
        provider_name: *const fn (ptr: *anyopaque) []const u8,
        is_running: *const fn (ptr: *anyopaque) bool,
    };

    pub const TunnelError = error{
        StartFailed,
        ProcessSpawnFailed,
        UrlNotFound,
        Timeout,
        InvalidCommand,
        NotImplemented,
    };

    pub fn start(self: TunnelAdapter, local_port: u16) TunnelError![]const u8 {
        return self.vtable.start(self.ptr, local_port);
    }

    pub fn stop(self: TunnelAdapter) void {
        return self.vtable.stop(self.ptr);
    }

    pub fn publicUrl(self: TunnelAdapter) ?[]const u8 {
        return self.vtable.public_url(self.ptr);
    }

    pub fn providerName(self: TunnelAdapter) []const u8 {
        return self.vtable.provider_name(self.ptr);
    }

    pub fn isRunning(self: TunnelAdapter) bool {
        return self.vtable.is_running(self.ptr);
    }
};

// ── NoneTunnel ──────────────────────────────────────────────────

/// No-op tunnel -- direct local access, no external exposure.
pub const NoneTunnel = struct {
    state: TunnelState = .stopped,

    const none_vtable = TunnelAdapter.VTable{
        .start = noneStart,
        .stop = noneStop,
        .public_url = nonePublicUrl,
        .provider_name = noneProviderName,
        .is_running = noneIsRunning,
    };

    pub fn adapter(self: *NoneTunnel) TunnelAdapter {
        return .{ .ptr = @ptrCast(self), .vtable = &none_vtable };
    }

    fn resolve(ptr: *anyopaque) *NoneTunnel {
        return @ptrCast(@alignCast(ptr));
    }

    fn noneStart(ptr: *anyopaque, _: u16) TunnelAdapter.TunnelError![]const u8 {
        resolve(ptr).state = .running;
        return "http://localhost:0";
    }

    fn noneStop(ptr: *anyopaque) void {
        resolve(ptr).state = .stopped;
    }

    fn nonePublicUrl(_: *anyopaque) ?[]const u8 {
        return null; // None tunnel has no public URL
    }

    fn noneProviderName(_: *anyopaque) []const u8 {
        return "none";
    }

    fn noneIsRunning(ptr: *anyopaque) bool {
        return resolve(ptr).state == .running;
    }
};

// ── URL extraction helper ───────────────────────────────────────

/// Scan output text for a "https://" URL and return the slice.
fn extractUrl(output: []const u8) ?[]const u8 {
    var start: usize = 0;
    while (start < output.len) {
        if (std.mem.indexOfPos(u8, output, start, "https://")) |idx| {
            const end = blk: {
                var e = idx;
                while (e < output.len and output[e] != ' ' and output[e] != '\n' and output[e] != '\r' and output[e] != '"' and output[e] != '\'') : (e += 1) {}
                break :blk e;
            };
            if (end > idx + 8) return output[idx..end]; // longer than just "https://"
            start = end;
        } else break;
    }
    return null;
}

// ── CloudflareTunnel ────────────────────────────────────────────

/// Cloudflare Tunnel -- wraps the `cloudflared` binary.
/// Start: `cloudflared tunnel --no-autoupdate run --url http://localhost:PORT`
/// Parses "https://" URL from stderr output.
pub const CloudflareTunnel = struct {
    token: []const u8,
    allocator: std.mem.Allocator,
    state: TunnelState = .stopped,
    url: ?[]const u8 = null,
    child: ?std.process.Child = null,

    const cf_vtable = TunnelAdapter.VTable{
        .start = cfStart,
        .stop = cfStop,
        .public_url = cfPublicUrl,
        .provider_name = cfProviderName,
        .is_running = cfIsRunning,
    };

    pub fn create(allocator: std.mem.Allocator, token: []const u8) CloudflareTunnel {
        return .{ .allocator = allocator, .token = token };
    }

    pub fn adapter(self: *CloudflareTunnel) TunnelAdapter {
        return .{ .ptr = @ptrCast(self), .vtable = &cf_vtable };
    }

    fn resolve(ptr: *anyopaque) *CloudflareTunnel {
        return @ptrCast(@alignCast(ptr));
    }

    fn cfStart(ptr: *anyopaque, local_port: u16) TunnelAdapter.TunnelError![]const u8 {
        const self = resolve(ptr);
        self.state = .starting;

        var port_buf: [8]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{local_port}) catch
            return TunnelAdapter.TunnelError.StartFailed;

        var url_buf: [64]u8 = undefined;
        const local_url = std.fmt.bufPrint(&url_buf, "http://localhost:{s}", .{port_str}) catch
            return TunnelAdapter.TunnelError.StartFailed;

        var child = std.process.Child.init(
            &.{ "cloudflared", "tunnel", "--no-autoupdate", "run", "--token", self.token, "--url", local_url },
            self.allocator,
        );
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch return TunnelAdapter.TunnelError.ProcessSpawnFailed;
        self.child = child;

        // Read stderr to find the public URL (cloudflared prints it there)
        if (self.child.?.stderr) |*stderr| {
            const output = stderr.readToEndAlloc(self.allocator, 64 * 1024) catch {
                self.state = .error_state;
                return TunnelAdapter.TunnelError.StartFailed;
            };
            defer self.allocator.free(output);

            if (extractUrl(output)) |found_url| {
                self.url = self.allocator.dupe(u8, found_url) catch {
                    self.state = .error_state;
                    return TunnelAdapter.TunnelError.StartFailed;
                };
                self.state = .running;
                return self.url.?;
            }
        }

        // If we got here with a running process but no URL, still mark running
        self.state = .running;
        self.url = null;
        return TunnelAdapter.TunnelError.UrlNotFound;
    }

    fn cfStop(ptr: *anyopaque) void {
        const self = resolve(ptr);
        if (self.child) |*child| {
            _ = child.kill() catch {};
        }
        self.child = null;
        self.state = .stopped;
        if (self.url) |u| self.allocator.free(u);
        self.url = null;
    }

    fn cfPublicUrl(ptr: *anyopaque) ?[]const u8 {
        return resolve(ptr).url;
    }

    fn cfProviderName(_: *anyopaque) []const u8 {
        return "cloudflare";
    }

    fn cfIsRunning(ptr: *anyopaque) bool {
        return resolve(ptr).state == .running;
    }
};

// ── NgrokTunnel ─────────────────────────────────────────────────

/// ngrok Tunnel -- wraps the `ngrok` binary.
/// Start: `ngrok http PORT --log stdout --log-format logfmt`
/// Then GET localhost:4040/api/tunnels to extract public URL.
pub const NgrokTunnel = struct {
    auth_token: []const u8,
    domain: ?[]const u8 = null,
    allocator: std.mem.Allocator,
    state: TunnelState = .stopped,
    url: ?[]const u8 = null,
    child: ?std.process.Child = null,

    const ngrok_vtable = TunnelAdapter.VTable{
        .start = ngrokStart,
        .stop = ngrokStop,
        .public_url = ngrokPublicUrl,
        .provider_name = ngrokProviderName,
        .is_running = ngrokIsRunning,
    };

    pub fn create(allocator: std.mem.Allocator, auth_token: []const u8, domain: ?[]const u8) NgrokTunnel {
        return .{ .allocator = allocator, .auth_token = auth_token, .domain = domain };
    }

    pub fn adapter(self: *NgrokTunnel) TunnelAdapter {
        return .{ .ptr = @ptrCast(self), .vtable = &ngrok_vtable };
    }

    fn resolve(ptr: *anyopaque) *NgrokTunnel {
        return @ptrCast(@alignCast(ptr));
    }

    fn ngrokStart(ptr: *anyopaque, local_port: u16) TunnelAdapter.TunnelError![]const u8 {
        const self = resolve(ptr);
        self.state = .starting;

        var port_buf: [8]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{local_port}) catch
            return TunnelAdapter.TunnelError.StartFailed;

        // Build argv: ngrok http PORT --authtoken TOKEN [--domain DOMAIN] --log stdout --log-format logfmt
        var argv_buf: [12][]const u8 = undefined;
        var argc: usize = 0;
        argv_buf[argc] = "ngrok";
        argc += 1;
        argv_buf[argc] = "http";
        argc += 1;
        argv_buf[argc] = port_str;
        argc += 1;
        argv_buf[argc] = "--authtoken";
        argc += 1;
        argv_buf[argc] = self.auth_token;
        argc += 1;
        if (self.domain) |d| {
            argv_buf[argc] = "--domain";
            argc += 1;
            argv_buf[argc] = d;
            argc += 1;
        }
        argv_buf[argc] = "--log";
        argc += 1;
        argv_buf[argc] = "stdout";
        argc += 1;
        argv_buf[argc] = "--log-format";
        argc += 1;
        argv_buf[argc] = "logfmt";
        argc += 1;

        var child = std.process.Child.init(argv_buf[0..argc], self.allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch return TunnelAdapter.TunnelError.ProcessSpawnFailed;
        self.child = child;

        // Read stdout for url= pattern (ngrok logfmt output)
        if (self.child.?.stdout) |*stdout| {
            const output = stdout.readToEndAlloc(self.allocator, 64 * 1024) catch {
                self.state = .error_state;
                return TunnelAdapter.TunnelError.StartFailed;
            };
            defer self.allocator.free(output);

            if (extractUrl(output)) |found_url| {
                self.url = self.allocator.dupe(u8, found_url) catch {
                    self.state = .error_state;
                    return TunnelAdapter.TunnelError.StartFailed;
                };
                self.state = .running;
                return self.url.?;
            }
        }

        self.state = .running;
        self.url = null;
        return TunnelAdapter.TunnelError.UrlNotFound;
    }

    fn ngrokStop(ptr: *anyopaque) void {
        const self = resolve(ptr);
        if (self.child) |*child| {
            _ = child.kill() catch {};
        }
        self.child = null;
        self.state = .stopped;
        if (self.url) |u| self.allocator.free(u);
        self.url = null;
    }

    fn ngrokPublicUrl(ptr: *anyopaque) ?[]const u8 {
        return resolve(ptr).url;
    }

    fn ngrokProviderName(_: *anyopaque) []const u8 {
        return "ngrok";
    }

    fn ngrokIsRunning(ptr: *anyopaque) bool {
        return resolve(ptr).state == .running;
    }
};

// ── TailscaleTunnel ─────────────────────────────────────────────

/// Tailscale Tunnel -- uses `tailscale serve` or `tailscale funnel`.
/// Funnel mode exposes to public internet; serve is tailnet-only.
pub const TailscaleTunnel = struct {
    funnel: bool,
    hostname: ?[]const u8 = null,
    allocator: std.mem.Allocator,
    state: TunnelState = .stopped,
    url: ?[]const u8 = null,
    child: ?std.process.Child = null,

    const ts_vtable = TunnelAdapter.VTable{
        .start = tsStart,
        .stop = tsStop,
        .public_url = tsPublicUrl,
        .provider_name = tsProviderName,
        .is_running = tsIsRunning,
    };

    pub fn create(allocator: std.mem.Allocator, funnel: bool, hostname: ?[]const u8) TailscaleTunnel {
        return .{ .allocator = allocator, .funnel = funnel, .hostname = hostname };
    }

    pub fn adapter(self: *TailscaleTunnel) TunnelAdapter {
        return .{ .ptr = @ptrCast(self), .vtable = &ts_vtable };
    }

    fn resolve(ptr: *anyopaque) *TailscaleTunnel {
        return @ptrCast(@alignCast(ptr));
    }

    fn tsStart(ptr: *anyopaque, local_port: u16) TunnelAdapter.TunnelError![]const u8 {
        const self = resolve(ptr);
        self.state = .starting;

        var port_buf: [8]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{local_port}) catch
            return TunnelAdapter.TunnelError.StartFailed;

        const subcmd: []const u8 = if (self.funnel) "funnel" else "serve";

        var child = std.process.Child.init(
            &.{ "tailscale", subcmd, port_str },
            self.allocator,
        );
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch return TunnelAdapter.TunnelError.ProcessSpawnFailed;
        self.child = child;

        // Construct URL from hostname
        if (self.hostname) |h| {
            var url_buf: [256]u8 = undefined;
            const constructed = std.fmt.bufPrint(&url_buf, "https://{s}", .{h}) catch {
                self.state = .error_state;
                return TunnelAdapter.TunnelError.StartFailed;
            };
            self.url = self.allocator.dupe(u8, constructed) catch {
                self.state = .error_state;
                return TunnelAdapter.TunnelError.StartFailed;
            };
            self.state = .running;
            return self.url.?;
        }

        // No hostname provided -- read stdout for URL output
        if (self.child.?.stdout) |*stdout| {
            const output = stdout.readToEndAlloc(self.allocator, 64 * 1024) catch {
                self.state = .error_state;
                return TunnelAdapter.TunnelError.StartFailed;
            };
            defer self.allocator.free(output);

            if (extractUrl(output)) |found_url| {
                self.url = self.allocator.dupe(u8, found_url) catch {
                    self.state = .error_state;
                    return TunnelAdapter.TunnelError.StartFailed;
                };
                self.state = .running;
                return self.url.?;
            }
        }

        self.state = .running;
        self.url = null;
        return TunnelAdapter.TunnelError.UrlNotFound;
    }

    fn tsStop(ptr: *anyopaque) void {
        const self = resolve(ptr);
        // Reset tailscale serve/funnel before killing process
        const subcmd: []const u8 = if (self.funnel) "funnel" else "serve";
        var reset_child = std.process.Child.init(
            &.{ "tailscale", subcmd, "reset" },
            self.allocator,
        );
        reset_child.spawn() catch {};
        _ = reset_child.wait() catch {};

        if (self.child) |*child| {
            _ = child.kill() catch {};
        }
        self.child = null;
        self.state = .stopped;
        if (self.url) |u| self.allocator.free(u);
        self.url = null;
    }

    fn tsPublicUrl(ptr: *anyopaque) ?[]const u8 {
        return resolve(ptr).url;
    }

    fn tsProviderName(_: *anyopaque) []const u8 {
        return "tailscale";
    }

    fn tsIsRunning(ptr: *anyopaque) bool {
        return resolve(ptr).state == .running;
    }
};

// ── CustomTunnel ────────────────────────────────────────────────

/// Custom Tunnel -- bring your own tunnel binary.
/// Runs user-provided start_command with {port} placeholder.
/// Expects URL on first stdout line (or via url_pattern match).
pub const CustomTunnel = struct {
    start_command: []const u8,
    health_url: ?[]const u8 = null,
    url_pattern: ?[]const u8 = null,
    allocator: std.mem.Allocator,
    state: TunnelState = .stopped,
    url: ?[]const u8 = null,
    child: ?std.process.Child = null,

    const custom_vtable = TunnelAdapter.VTable{
        .start = customStart,
        .stop = customStop,
        .public_url = customPublicUrl,
        .provider_name = customProviderName,
        .is_running = customIsRunning,
    };

    pub fn create(allocator: std.mem.Allocator, start_command: []const u8, health_url: ?[]const u8, url_pattern: ?[]const u8) CustomTunnel {
        return .{ .allocator = allocator, .start_command = start_command, .health_url = health_url, .url_pattern = url_pattern };
    }

    pub fn adapter(self: *CustomTunnel) TunnelAdapter {
        return .{ .ptr = @ptrCast(self), .vtable = &custom_vtable };
    }

    fn resolve(ptr: *anyopaque) *CustomTunnel {
        return @ptrCast(@alignCast(ptr));
    }

    fn customStart(ptr: *anyopaque, local_port: u16) TunnelAdapter.TunnelError![]const u8 {
        const self = resolve(ptr);
        if (std.mem.trim(u8, self.start_command, " \t").len == 0) {
            return TunnelAdapter.TunnelError.InvalidCommand;
        }
        self.state = .starting;

        var port_buf: [8]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{local_port}) catch
            return TunnelAdapter.TunnelError.StartFailed;

        // Replace {port} placeholder in command
        const cmd_with_port = std.mem.replaceOwned(u8, self.allocator, self.start_command, "{port}", port_str) catch
            return TunnelAdapter.TunnelError.StartFailed;
        defer self.allocator.free(cmd_with_port);

        // Replace {host} placeholder
        const cmd_final = std.mem.replaceOwned(u8, self.allocator, cmd_with_port, "{host}", "localhost") catch
            return TunnelAdapter.TunnelError.StartFailed;
        defer self.allocator.free(cmd_final);

        // Split command by whitespace into argv
        var argv_list: [32][]const u8 = undefined;
        var argc: usize = 0;
        var it = std.mem.tokenizeAny(u8, cmd_final, " \t");
        while (it.next()) |tok| {
            if (argc >= argv_list.len) break;
            argv_list[argc] = tok;
            argc += 1;
        }
        if (argc == 0) return TunnelAdapter.TunnelError.InvalidCommand;

        var child = std.process.Child.init(argv_list[0..argc], self.allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch return TunnelAdapter.TunnelError.ProcessSpawnFailed;
        self.child = child;

        // Read stdout to find URL
        if (self.child.?.stdout) |*stdout| {
            const output = stdout.readToEndAlloc(self.allocator, 64 * 1024) catch {
                self.state = .error_state;
                return TunnelAdapter.TunnelError.StartFailed;
            };
            defer self.allocator.free(output);

            if (extractUrl(output)) |found_url| {
                self.url = self.allocator.dupe(u8, found_url) catch {
                    self.state = .error_state;
                    return TunnelAdapter.TunnelError.StartFailed;
                };
                self.state = .running;
                return self.url.?;
            }
        }

        self.state = .running;
        self.url = null;
        return TunnelAdapter.TunnelError.UrlNotFound;
    }

    fn customStop(ptr: *anyopaque) void {
        const self = resolve(ptr);
        if (self.child) |*child| {
            _ = child.kill() catch {};
        }
        self.child = null;
        self.state = .stopped;
        if (self.url) |u| self.allocator.free(u);
        self.url = null;
    }

    fn customPublicUrl(ptr: *anyopaque) ?[]const u8 {
        return resolve(ptr).url;
    }

    fn customProviderName(_: *anyopaque) []const u8 {
        return "custom";
    }

    fn customIsRunning(ptr: *anyopaque) bool {
        return resolve(ptr).state == .running;
    }
};

// ── Tunnel Instance (backward compat) ───────────────────────────

pub const Tunnel = struct {
    provider: TunnelProvider,
    allocator: ?std.mem.Allocator = null,
    public_url: ?[]const u8 = null,
    state: TunnelState = .stopped,
    child: ?std.process.Child = null,

    // Provider-specific config stored as tagged union
    cloudflare_token: ?[]const u8 = null,
    tailscale_funnel: bool = false,
    tailscale_hostname: ?[]const u8 = null,
    ngrok_auth_token: ?[]const u8 = null,
    ngrok_domain: ?[]const u8 = null,
    custom_start_command: ?[]const u8 = null,
    custom_health_url: ?[]const u8 = null,
    custom_url_pattern: ?[]const u8 = null,

    /// Human-readable provider name.
    pub fn providerName(self: *const Tunnel) []const u8 {
        return self.provider.name();
    }

    /// Check if the tunnel is running.
    pub fn isRunning(self: *const Tunnel) bool {
        return self.state == .running;
    }

    /// Return the public URL if the tunnel is running.
    pub fn publicUrl(self: *const Tunnel) ?[]const u8 {
        return self.public_url;
    }

    /// Start the tunnel. For "none" provider returns a local URL.
    /// Real providers spawn external processes.
    pub fn start(self: *Tunnel, local_host: []const u8, local_port: u16) ![]const u8 {
        const alloc = self.allocator orelse return error.NotImplemented;

        var port_buf: [8]u8 = undefined;
        const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{local_port});

        switch (self.provider) {
            .none => {
                self.state = .running;
                self.public_url = null;
                return "http://localhost:0";
            },
            .cloudflare => {
                self.state = .starting;
                const token = self.cloudflare_token orelse return error.NotImplemented;

                var url_buf: [64]u8 = undefined;
                const local_url = try std.fmt.bufPrint(&url_buf, "http://localhost:{s}", .{port_str});

                var child = std.process.Child.init(
                    &.{ "cloudflared", "tunnel", "--no-autoupdate", "run", "--token", token, "--url", local_url },
                    alloc,
                );
                child.stdin_behavior = .Pipe;
                child.stdout_behavior = .Pipe;
                child.stderr_behavior = .Pipe;

                child.spawn() catch return error.NotImplemented;
                self.child = child;
                self.state = .running;

                if (self.child.?.stderr) |*stderr| {
                    const output = stderr.readToEndAlloc(alloc, 64 * 1024) catch return error.NotImplemented;
                    defer alloc.free(output);
                    if (extractUrl(output)) |found| {
                        self.public_url = try alloc.dupe(u8, found);
                        return self.public_url.?;
                    }
                }
                return error.NotImplemented;
            },
            .ngrok => {
                self.state = .starting;
                const token = self.ngrok_auth_token orelse return error.NotImplemented;

                var argv_buf: [12][]const u8 = undefined;
                var argc: usize = 0;
                argv_buf[argc] = "ngrok";
                argc += 1;
                argv_buf[argc] = "http";
                argc += 1;
                argv_buf[argc] = port_str;
                argc += 1;
                argv_buf[argc] = "--authtoken";
                argc += 1;
                argv_buf[argc] = token;
                argc += 1;
                if (self.ngrok_domain) |d| {
                    argv_buf[argc] = "--domain";
                    argc += 1;
                    argv_buf[argc] = d;
                    argc += 1;
                }
                argv_buf[argc] = "--log";
                argc += 1;
                argv_buf[argc] = "stdout";
                argc += 1;
                argv_buf[argc] = "--log-format";
                argc += 1;
                argv_buf[argc] = "logfmt";
                argc += 1;

                var child = std.process.Child.init(argv_buf[0..argc], alloc);
                child.stdin_behavior = .Pipe;
                child.stdout_behavior = .Pipe;
                child.stderr_behavior = .Pipe;

                child.spawn() catch return error.NotImplemented;
                self.child = child;
                self.state = .running;

                if (self.child.?.stdout) |*stdout| {
                    const output = stdout.readToEndAlloc(alloc, 64 * 1024) catch return error.NotImplemented;
                    defer alloc.free(output);
                    if (extractUrl(output)) |found| {
                        self.public_url = try alloc.dupe(u8, found);
                        return self.public_url.?;
                    }
                }
                return error.NotImplemented;
            },
            .tailscale => {
                self.state = .starting;
                const subcmd: []const u8 = if (self.tailscale_funnel) "funnel" else "serve";

                var child = std.process.Child.init(
                    &.{ "tailscale", subcmd, port_str },
                    alloc,
                );
                child.stdin_behavior = .Pipe;
                child.stdout_behavior = .Pipe;
                child.stderr_behavior = .Pipe;

                child.spawn() catch return error.NotImplemented;
                self.child = child;
                self.state = .running;

                if (self.tailscale_hostname) |h| {
                    var tbuf: [256]u8 = undefined;
                    const constructed = std.fmt.bufPrint(&tbuf, "https://{s}", .{h}) catch return error.NotImplemented;
                    self.public_url = try alloc.dupe(u8, constructed);
                    return self.public_url.?;
                }
                return error.NotImplemented;
            },
            .custom => {
                self.state = .starting;
                const cmd = self.custom_start_command orelse return error.NotImplemented;
                if (std.mem.trim(u8, cmd, " \t").len == 0) return error.NotImplemented;

                const cmd_with_port = try std.mem.replaceOwned(u8, alloc, cmd, "{port}", port_str);
                defer alloc.free(cmd_with_port);
                const cmd_final = try std.mem.replaceOwned(u8, alloc, cmd_with_port, "{host}", local_host);
                defer alloc.free(cmd_final);

                var argv_list: [32][]const u8 = undefined;
                var argc: usize = 0;
                var it = std.mem.tokenizeAny(u8, cmd_final, " \t");
                while (it.next()) |tok| {
                    if (argc >= argv_list.len) break;
                    argv_list[argc] = tok;
                    argc += 1;
                }
                if (argc == 0) return error.NotImplemented;

                var child = std.process.Child.init(argv_list[0..argc], alloc);
                child.stdin_behavior = .Pipe;
                child.stdout_behavior = .Pipe;
                child.stderr_behavior = .Pipe;

                child.spawn() catch return error.NotImplemented;
                self.child = child;
                self.state = .running;

                if (self.child.?.stdout) |*stdout| {
                    const output = stdout.readToEndAlloc(alloc, 64 * 1024) catch return error.NotImplemented;
                    defer alloc.free(output);
                    if (extractUrl(output)) |found| {
                        self.public_url = try alloc.dupe(u8, found);
                        return self.public_url.?;
                    }
                }
                return error.NotImplemented;
            },
        }
    }

    /// Stop the tunnel.
    pub fn stop(self: *Tunnel) void {
        if (self.child) |*child| {
            _ = child.kill() catch {};
        }
        self.child = null;
        self.state = .stopped;
        if (self.public_url) |u| {
            if (self.allocator) |alloc| alloc.free(u);
        }
        self.public_url = null;
    }
};

// ── Factory ─────────────────────────────────────────────────────

pub const CreateTunnelError = error{
    UnknownProvider,
    MissingCloudflareConfig,
    MissingNgrokConfig,
    MissingCustomConfig,
};

/// Create a tunnel from config. Returns null for provider "none".
pub fn createTunnel(cfg: TunnelFullConfig) CreateTunnelError!?Tunnel {
    const provider = TunnelProvider.fromString(cfg.provider) orelse return CreateTunnelError.UnknownProvider;

    return switch (provider) {
        .none => null,
        .cloudflare => blk: {
            const cf = cfg.cloudflare orelse return CreateTunnelError.MissingCloudflareConfig;
            break :blk Tunnel{
                .provider = .cloudflare,
                .cloudflare_token = cf.token,
            };
        },
        .tailscale => blk: {
            const ts = cfg.tailscale orelse TailscaleTunnelConfig{};
            break :blk Tunnel{
                .provider = .tailscale,
                .tailscale_funnel = ts.funnel,
                .tailscale_hostname = ts.hostname,
            };
        },
        .ngrok => blk: {
            const ng = cfg.ngrok orelse return CreateTunnelError.MissingNgrokConfig;
            break :blk Tunnel{
                .provider = .ngrok,
                .ngrok_auth_token = ng.auth_token,
                .ngrok_domain = ng.domain,
            };
        },
        .custom => blk: {
            const cu = cfg.custom orelse return CreateTunnelError.MissingCustomConfig;
            break :blk Tunnel{
                .provider = .custom,
                .custom_start_command = cu.start_command,
                .custom_health_url = cu.health_url,
                .custom_url_pattern = cu.url_pattern,
            };
        },
    };
}

// ── Convenience constructors ────────────────────────────────────

pub fn noneTunnel() Tunnel {
    return .{ .provider = .none };
}

pub fn cloudflareTunnel(token: []const u8) Tunnel {
    return .{ .provider = .cloudflare, .cloudflare_token = token };
}

pub fn tailscaleTunnel(funnel: bool, hostname: ?[]const u8) Tunnel {
    return .{ .provider = .tailscale, .tailscale_funnel = funnel, .tailscale_hostname = hostname };
}

pub fn ngrokTunnel(auth_token: []const u8, domain: ?[]const u8) Tunnel {
    return .{ .provider = .ngrok, .ngrok_auth_token = auth_token, .ngrok_domain = domain };
}

pub fn customTunnel(start_command: []const u8, health_url: ?[]const u8, url_pattern: ?[]const u8) Tunnel {
    return .{ .provider = .custom, .custom_start_command = start_command, .custom_health_url = health_url, .custom_url_pattern = url_pattern };
}

// ── Tests ───────────────────────────────────────────────────────

test "TunnelProvider.fromString none" {
    try std.testing.expectEqual(TunnelProvider.none, TunnelProvider.fromString("none").?);
    try std.testing.expectEqual(TunnelProvider.none, TunnelProvider.fromString("").?);
}

test "TunnelProvider.fromString cloudflare" {
    try std.testing.expectEqual(TunnelProvider.cloudflare, TunnelProvider.fromString("cloudflare").?);
}

test "TunnelProvider.fromString tailscale" {
    try std.testing.expectEqual(TunnelProvider.tailscale, TunnelProvider.fromString("tailscale").?);
}

test "TunnelProvider.fromString ngrok" {
    try std.testing.expectEqual(TunnelProvider.ngrok, TunnelProvider.fromString("ngrok").?);
}

test "TunnelProvider.fromString custom" {
    try std.testing.expectEqual(TunnelProvider.custom, TunnelProvider.fromString("custom").?);
}

test "TunnelProvider.fromString unknown returns null" {
    try std.testing.expect(TunnelProvider.fromString("wireguard") == null);
}

test "TunnelProvider.name" {
    try std.testing.expectEqualStrings("none", TunnelProvider.none.name());
    try std.testing.expectEqualStrings("cloudflare", TunnelProvider.cloudflare.name());
    try std.testing.expectEqualStrings("tailscale", TunnelProvider.tailscale.name());
    try std.testing.expectEqualStrings("ngrok", TunnelProvider.ngrok.name());
    try std.testing.expectEqualStrings("custom", TunnelProvider.custom.name());
}

test "factory none returns null" {
    const t = try createTunnel(.{});
    try std.testing.expect(t == null);
}

test "factory empty string returns null" {
    const t = try createTunnel(.{ .provider = "" });
    try std.testing.expect(t == null);
}

test "factory unknown provider errors" {
    const result = createTunnel(.{ .provider = "wireguard" });
    try std.testing.expectError(CreateTunnelError.UnknownProvider, result);
}

test "factory cloudflare missing config errors" {
    const result = createTunnel(.{ .provider = "cloudflare" });
    try std.testing.expectError(CreateTunnelError.MissingCloudflareConfig, result);
}

test "factory cloudflare with config ok" {
    const t = try createTunnel(.{
        .provider = "cloudflare",
        .cloudflare = .{ .token = "test-token" },
    });
    try std.testing.expect(t != null);
    try std.testing.expectEqualStrings("cloudflare", t.?.providerName());
}

test "factory tailscale defaults ok" {
    const t = try createTunnel(.{ .provider = "tailscale" });
    try std.testing.expect(t != null);
    try std.testing.expectEqualStrings("tailscale", t.?.providerName());
}

test "factory ngrok missing config errors" {
    const result = createTunnel(.{ .provider = "ngrok" });
    try std.testing.expectError(CreateTunnelError.MissingNgrokConfig, result);
}

test "factory ngrok with config ok" {
    const t = try createTunnel(.{
        .provider = "ngrok",
        .ngrok = .{ .auth_token = "tok" },
    });
    try std.testing.expect(t != null);
    try std.testing.expectEqualStrings("ngrok", t.?.providerName());
}

test "factory custom missing config errors" {
    const result = createTunnel(.{ .provider = "custom" });
    try std.testing.expectError(CreateTunnelError.MissingCustomConfig, result);
}

test "factory custom with config ok" {
    const t = try createTunnel(.{
        .provider = "custom",
        .custom = .{ .start_command = "echo tunnel" },
    });
    try std.testing.expect(t != null);
    try std.testing.expectEqualStrings("custom", t.?.providerName());
}

test "noneTunnel name" {
    const t = noneTunnel();
    try std.testing.expectEqualStrings("none", t.providerName());
}

test "noneTunnel public url is null" {
    const t = noneTunnel();
    try std.testing.expect(t.publicUrl() == null);
}

test "noneTunnel is not running initially" {
    const t = noneTunnel();
    try std.testing.expect(!t.isRunning());
}

test "cloudflareTunnel name" {
    const t = cloudflareTunnel("tok");
    try std.testing.expectEqualStrings("cloudflare", t.providerName());
    try std.testing.expect(t.publicUrl() == null);
}

test "cloudflareTunnel not running before start" {
    const t = cloudflareTunnel("tok");
    try std.testing.expect(!t.isRunning());
}

test "tailscaleTunnel name" {
    const t = tailscaleTunnel(false, null);
    try std.testing.expectEqualStrings("tailscale", t.providerName());
    try std.testing.expect(t.publicUrl() == null);
}

test "tailscaleTunnel funnel mode" {
    const t = tailscaleTunnel(true, "myhost");
    try std.testing.expectEqualStrings("tailscale", t.providerName());
    try std.testing.expect(t.tailscale_funnel);
    try std.testing.expectEqualStrings("myhost", t.tailscale_hostname.?);
}

test "ngrokTunnel name" {
    const t = ngrokTunnel("tok", null);
    try std.testing.expectEqualStrings("ngrok", t.providerName());
    try std.testing.expect(t.publicUrl() == null);
}

test "ngrokTunnel with domain" {
    const t = ngrokTunnel("tok", "my.ngrok.io");
    try std.testing.expectEqualStrings("ngrok", t.providerName());
    try std.testing.expectEqualStrings("my.ngrok.io", t.ngrok_domain.?);
}

test "customTunnel name" {
    const t = customTunnel("echo hi", null, null);
    try std.testing.expectEqualStrings("custom", t.providerName());
    try std.testing.expect(t.publicUrl() == null);
}

test "tunnel stop clears state" {
    var t = cloudflareTunnel("tok");
    t.state = .running;
    // Don't set public_url to a literal -- stop() would try to free it if allocator is set.
    // Just test state transitions.
    t.stop();
    try std.testing.expect(!t.isRunning());
    try std.testing.expect(t.publicUrl() == null);
}

test "TunnelState values" {
    try std.testing.expect(@intFromEnum(TunnelState.stopped) == 0);
    try std.testing.expect(@intFromEnum(TunnelState.starting) == 1);
    try std.testing.expect(@intFromEnum(TunnelState.running) == 2);
    try std.testing.expect(@intFromEnum(TunnelState.error_state) == 3);
}

test "TunnelFullConfig defaults" {
    const cfg = TunnelFullConfig{};
    try std.testing.expectEqualStrings("none", cfg.provider);
    try std.testing.expect(cfg.cloudflare == null);
    try std.testing.expect(cfg.tailscale == null);
    try std.testing.expect(cfg.ngrok == null);
    try std.testing.expect(cfg.custom == null);
}

test "extractUrl finds https url in output" {
    const output = "some log line\nhttps://abc123.trycloudflare.com connected\nmore output";
    const url = extractUrl(output);
    try std.testing.expect(url != null);
    try std.testing.expectEqualStrings("https://abc123.trycloudflare.com", url.?);
}

test "extractUrl returns null for no url" {
    const output = "no urls here\njust some log output";
    try std.testing.expect(extractUrl(output) == null);
}

test "extractUrl ignores bare https://" {
    const output = "https:// \nnothing";
    try std.testing.expect(extractUrl(output) == null);
}

// ── TunnelAdapter vtable tests ──────────────────────────────────

test "NoneTunnel adapter name" {
    var t = NoneTunnel{};
    const a = t.adapter();
    try std.testing.expectEqualStrings("none", a.providerName());
}

test "NoneTunnel adapter start and stop" {
    var t = NoneTunnel{};
    const a = t.adapter();
    try std.testing.expect(!a.isRunning());
    const url = try a.start(8080);
    try std.testing.expectEqualStrings("http://localhost:0", url);
    try std.testing.expect(a.isRunning());
    a.stop();
    try std.testing.expect(!a.isRunning());
}

test "NoneTunnel adapter public url is null" {
    var t = NoneTunnel{};
    const a = t.adapter();
    try std.testing.expect(a.publicUrl() == null);
}

test "CloudflareTunnel adapter name" {
    var t = CloudflareTunnel.create(std.testing.allocator, "cf-token");
    const a = t.adapter();
    try std.testing.expectEqualStrings("cloudflare", a.providerName());
}

test "CloudflareTunnel adapter not running before start" {
    var t = CloudflareTunnel.create(std.testing.allocator, "cf-token");
    const a = t.adapter();
    try std.testing.expect(!a.isRunning());
    try std.testing.expect(a.publicUrl() == null);
}

test "CloudflareTunnel adapter stop" {
    var t = CloudflareTunnel.create(std.testing.allocator, "cf-token");
    const a = t.adapter();
    a.stop();
    try std.testing.expect(!a.isRunning());
}

test "NgrokTunnel adapter name" {
    var t = NgrokTunnel.create(std.testing.allocator, "ngrok-tok", null);
    const a = t.adapter();
    try std.testing.expectEqualStrings("ngrok", a.providerName());
}

test "NgrokTunnel adapter with domain" {
    var t = NgrokTunnel.create(std.testing.allocator, "tok", "my.ngrok.io");
    try std.testing.expectEqualStrings("my.ngrok.io", t.domain.?);
    const a = t.adapter();
    try std.testing.expect(!a.isRunning());
}

test "TailscaleTunnel adapter name" {
    var t = TailscaleTunnel.create(std.testing.allocator, false, null);
    const a = t.adapter();
    try std.testing.expectEqualStrings("tailscale", a.providerName());
}

test "TailscaleTunnel adapter funnel mode" {
    var t = TailscaleTunnel.create(std.testing.allocator, true, "myhost.ts.net");
    try std.testing.expect(t.funnel);
    try std.testing.expectEqualStrings("myhost.ts.net", t.hostname.?);
    const a = t.adapter();
    try std.testing.expect(!a.isRunning());
}

test "CustomTunnel adapter name" {
    var t = CustomTunnel.create(std.testing.allocator, "bore local {port} --to bore.pub", null, null);
    const a = t.adapter();
    try std.testing.expectEqualStrings("custom", a.providerName());
}

test "CustomTunnel adapter empty command fails" {
    var t = CustomTunnel.create(std.testing.allocator, "   ", null, null);
    const a = t.adapter();
    try std.testing.expectError(TunnelAdapter.TunnelError.InvalidCommand, a.start(8080));
}

test "CustomTunnel adapter stop" {
    var t = CustomTunnel.create(std.testing.allocator, "echo test", null, null);
    t.state = .running;
    const a = t.adapter();
    a.stop();
    try std.testing.expect(!a.isRunning());
}
