const std = @import("std");

/// Runtime adapter interface -- abstracts platform differences.
/// Mirrors ZeroClaw's RuntimeAdapter trait.
pub const RuntimeAdapter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        name: *const fn (ptr: *anyopaque) []const u8,
        has_shell_access: *const fn (ptr: *anyopaque) bool,
        has_filesystem_access: *const fn (ptr: *anyopaque) bool,
        storage_path: *const fn (ptr: *anyopaque) []const u8,
        supports_long_running: *const fn (ptr: *anyopaque) bool,
        memory_budget: *const fn (ptr: *anyopaque) u64,
    };

    pub fn getName(self: RuntimeAdapter) []const u8 {
        return self.vtable.name(self.ptr);
    }

    pub fn hasShellAccess(self: RuntimeAdapter) bool {
        return self.vtable.has_shell_access(self.ptr);
    }

    pub fn hasFilesystemAccess(self: RuntimeAdapter) bool {
        return self.vtable.has_filesystem_access(self.ptr);
    }

    pub fn storagePath(self: RuntimeAdapter) []const u8 {
        return self.vtable.storage_path(self.ptr);
    }

    pub fn supportsLongRunning(self: RuntimeAdapter) bool {
        return self.vtable.supports_long_running(self.ptr);
    }

    pub fn memoryBudget(self: RuntimeAdapter) u64 {
        return self.vtable.memory_budget(self.ptr);
    }
};

// ── NativeRuntime ────────────────────────────────────────────────────

/// Native runtime -- full access, runs on Mac/Linux/Docker/Raspberry Pi.
pub const NativeRuntime = struct {
    const vtable = RuntimeAdapter.VTable{
        .name = nativeName,
        .has_shell_access = nativeShell,
        .has_filesystem_access = nativeFs,
        .storage_path = nativeStorage,
        .supports_long_running = nativeLongRunning,
        .memory_budget = nativeMemBudget,
    };

    pub fn adapter(self: *NativeRuntime) RuntimeAdapter {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    fn nativeName(_: *anyopaque) []const u8 {
        return "native";
    }

    fn nativeShell(_: *anyopaque) bool {
        return true;
    }

    fn nativeFs(_: *anyopaque) bool {
        return true;
    }

    fn nativeStorage(_: *anyopaque) []const u8 {
        return ".nullclaw";
    }

    fn nativeLongRunning(_: *anyopaque) bool {
        return true;
    }

    fn nativeMemBudget(_: *anyopaque) u64 {
        return 0; // unlimited
    }
};

// ── DockerRuntime ────────────────────────────────────────────────────

/// Docker runtime -- container-isolated execution.
pub const DockerRuntime = struct {
    image: []const u8,
    network: []const u8,
    memory_limit_mb: ?u64,
    mount_workspace: bool,

    const vtable = RuntimeAdapter.VTable{
        .name = dockerName,
        .has_shell_access = dockerShell,
        .has_filesystem_access = dockerFs,
        .storage_path = dockerStorage,
        .supports_long_running = dockerLongRunning,
        .memory_budget = dockerMemBudget,
    };

    pub fn init(image: []const u8, network: []const u8, memory_limit_mb: ?u64, mount_workspace: bool) DockerRuntime {
        return .{
            .image = image,
            .network = network,
            .memory_limit_mb = memory_limit_mb,
            .mount_workspace = mount_workspace,
        };
    }

    pub fn adapter(s: *DockerRuntime) RuntimeAdapter {
        return .{
            .ptr = @ptrCast(s),
            .vtable = &vtable,
        };
    }

    fn resolve(ptr: *anyopaque) *DockerRuntime {
        return @ptrCast(@alignCast(ptr));
    }

    fn dockerName(_: *anyopaque) []const u8 {
        return "docker";
    }

    fn dockerShell(_: *anyopaque) bool {
        return true;
    }

    fn dockerFs(ptr: *anyopaque) bool {
        return resolve(ptr).mount_workspace;
    }

    fn dockerStorage(ptr: *anyopaque) []const u8 {
        if (resolve(ptr).mount_workspace) {
            return "/workspace/.nullclaw";
        } else {
            return "/tmp/.nullclaw";
        }
    }

    fn dockerLongRunning(_: *anyopaque) bool {
        return false;
    }

    fn dockerMemBudget(ptr: *anyopaque) u64 {
        if (resolve(ptr).memory_limit_mb) |mb| {
            return mb *| (1024 * 1024);
        }
        return 0;
    }
};

// ── WasmRuntime ─────────────────────────────────────────────────────

/// Result of executing a WASM module.
pub const WasmExecutionResult = struct {
    stdout: []const u8,
    stderr: []const u8,
    exit_code: i32,
    fuel_consumed: u64,
};

/// Capabilities granted to a WASM module.
pub const WasmCapabilities = struct {
    has_wasi: bool = false,
    max_fuel: u64 = 1_000_000,
    max_memory_bytes: usize = 64 * 1024 * 1024,
    allow_workspace_read: bool = false,
    allow_workspace_write: bool = false,
};

/// WASM runtime configuration.
pub const WasmRuntimeConfig = struct {
    fuel_limit: u64 = 1_000_000,
    memory_limit_mb: u64 = 64,
    tools_dir: []const u8 = "tools/wasm",
    allow_workspace_read: bool = false,
    allow_workspace_write: bool = false,
};

/// WASM sandbox runtime -- executes tool modules via `wasmtime run`.
/// Provides fuel-limited, memory-capped isolation without Docker.
pub const WasmRuntime = struct {
    wasm_config: WasmRuntimeConfig,

    const wasm_vtable = RuntimeAdapter.VTable{
        .name = wasmName,
        .has_shell_access = wasmShell,
        .has_filesystem_access = wasmFs,
        .storage_path = wasmStorage,
        .supports_long_running = wasmLongRunning,
        .memory_budget = wasmMemBudget,
    };

    pub fn init(wasm_config: WasmRuntimeConfig) WasmRuntime {
        return .{ .wasm_config = wasm_config };
    }

    pub fn adapter(self: *WasmRuntime) RuntimeAdapter {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &wasm_vtable,
        };
    }

    fn resolve(ptr: *anyopaque) *WasmRuntime {
        return @ptrCast(@alignCast(ptr));
    }

    fn wasmName(_: *anyopaque) []const u8 {
        return "wasm";
    }

    fn wasmShell(_: *anyopaque) bool {
        return false; // WASM sandbox does NOT provide shell access
    }

    fn wasmFs(ptr: *anyopaque) bool {
        const self = resolve(ptr);
        return self.wasm_config.allow_workspace_read or self.wasm_config.allow_workspace_write;
    }

    fn wasmStorage(_: *anyopaque) []const u8 {
        return ".nullclaw/wasm";
    }

    fn wasmLongRunning(_: *anyopaque) bool {
        return false; // WASM modules are short-lived
    }

    fn wasmMemBudget(ptr: *anyopaque) u64 {
        const self = resolve(ptr);
        return self.wasm_config.memory_limit_mb *| (1024 * 1024);
    }

    /// Get the effective fuel limit for an invocation.
    pub fn effectiveFuel(self: *const WasmRuntime, caps: WasmCapabilities) u64 {
        if (caps.max_fuel > 0 and caps.max_fuel != 1_000_000) {
            return caps.max_fuel;
        }
        return self.wasm_config.fuel_limit;
    }

    /// Get the effective memory limit in bytes.
    pub fn effectiveMemoryBytes(self: *const WasmRuntime, caps: WasmCapabilities) u64 {
        if (caps.max_memory_bytes > 0 and caps.max_memory_bytes != 64 * 1024 * 1024) {
            return @as(u64, @intCast(caps.max_memory_bytes));
        }
        return self.wasm_config.memory_limit_mb *| (1024 * 1024);
    }

    /// Build default capabilities from config.
    pub fn defaultCapabilities(self: *const WasmRuntime) WasmCapabilities {
        return .{
            .has_wasi = true,
            .max_fuel = self.wasm_config.fuel_limit,
            .max_memory_bytes = @intCast(self.wasm_config.memory_limit_mb *| (1024 * 1024)),
            .allow_workspace_read = self.wasm_config.allow_workspace_read,
            .allow_workspace_write = self.wasm_config.allow_workspace_write,
        };
    }

    /// Validate the WASM config.
    pub fn validateConfig(self: *const WasmRuntime) !void {
        if (self.wasm_config.memory_limit_mb == 0) {
            return error.ZeroMemoryLimit;
        }
        if (self.wasm_config.memory_limit_mb > 4096) {
            return error.ExcessiveMemoryLimit;
        }
        if (self.wasm_config.tools_dir.len == 0) {
            return error.EmptyToolsDir;
        }
        if (std.mem.indexOf(u8, self.wasm_config.tools_dir, "..") != null) {
            return error.PathTraversal;
        }
    }

    /// Execute a WASM module via `wasmtime run`.
    /// Returns the captured stdout, stderr, exit code, and estimated fuel consumed.
    pub fn executeModule(
        self: *const WasmRuntime,
        allocator: std.mem.Allocator,
        module_path: []const u8,
        caps: WasmCapabilities,
    ) !WasmExecutionResult {
        if (module_path.len == 0) {
            return error.EmptyModulePath;
        }

        const fuel = self.effectiveFuel(caps);
        const max_mem = self.effectiveMemoryBytes(caps);
        const max_mem_pages = max_mem / (64 * 1024); // WASM pages are 64KB

        // Build fuel string
        var fuel_buf: [32]u8 = undefined;
        const fuel_str = std.fmt.bufPrint(&fuel_buf, "{d}", .{fuel}) catch return error.FormatError;

        // Build memory string
        var mem_buf: [32]u8 = undefined;
        const mem_str = std.fmt.bufPrint(&mem_buf, "{d}", .{max_mem_pages}) catch return error.FormatError;

        // Build argv: wasmtime run --fuel LIMIT --max-memory-size SIZE MODULE
        var child = std.process.Child.init(.{
            .argv = &.{
                "wasmtime",
                "run",
                "--fuel",
                fuel_str,
                "--max-memory-size",
                mem_str,
                module_path,
            },
            .allocator = allocator,
        }, allocator);

        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        try child.spawn();

        const stdout = try child.stdout.?.reader().readAllAlloc(allocator, 1024 * 1024);
        errdefer allocator.free(stdout);
        const stderr = try child.stderr.?.reader().readAllAlloc(allocator, 1024 * 1024);
        errdefer allocator.free(stderr);

        const term = try child.wait();
        const exit_code: i32 = switch (term) {
            .exited => |code| @as(i32, @intCast(code)),
            else => -1,
        };

        return WasmExecutionResult{
            .stdout = stdout,
            .stderr = stderr,
            .exit_code = exit_code,
            .fuel_consumed = fuel, // approximate: real wasmtime reports via stderr
        };
    }
};

// ── CloudflareRuntime ────────────────────────────────────────────────

/// Cloudflare Workers runtime descriptor — serverless V8 isolate environment.
/// No shell or filesystem access; 128 MB memory cap; short-lived invocations.
/// Storage is provided via Cloudflare KV/D1, not a local path.
pub const CloudflareRuntime = struct {
    const cf_vtable = RuntimeAdapter.VTable{
        .name = cfName,
        .has_shell_access = cfShell,
        .has_filesystem_access = cfFs,
        .storage_path = cfStorage,
        .supports_long_running = cfLongRunning,
        .memory_budget = cfMemBudget,
    };

    pub fn adapter(self: *CloudflareRuntime) RuntimeAdapter {
        return .{ .ptr = @ptrCast(self), .vtable = &cf_vtable };
    }

    fn cfName(_: *anyopaque) []const u8 {
        return "cloudflare";
    }

    fn cfShell(_: *anyopaque) bool {
        return false; // Workers have no shell access
    }

    fn cfFs(_: *anyopaque) bool {
        return false; // Workers have no local filesystem; use KV / D1 / R2
    }

    fn cfStorage(_: *anyopaque) []const u8 {
        return ""; // Storage is remote (KV/D1), not a local path
    }

    fn cfLongRunning(_: *anyopaque) bool {
        return false; // Workers have a CPU time limit (50 ms free, 30 s paid)
    }

    fn cfMemBudget(_: *anyopaque) u64 {
        return 128 * 1024 * 1024; // 128 MB limit per Cloudflare Workers docs
    }
};

/// Factory: create the right runtime from a kind string.
pub fn createRuntime(kind: []const u8) !RuntimeKind {
    if (std.mem.eql(u8, kind, "native")) return .native;
    if (std.mem.eql(u8, kind, "docker")) return .docker;
    if (std.mem.eql(u8, kind, "wasm")) return .wasm;
    if (std.mem.eql(u8, kind, "cloudflare")) return .cloudflare;
    if (kind.len == 0 or std.mem.trim(u8, kind, " \t").len == 0) return error.EmptyRuntimeKind;
    return error.UnknownRuntimeKind;
}

pub const RuntimeKind = enum {
    native,
    docker,
    wasm,
    cloudflare,
};

// ── Tests ────────────────────────────────────────────────────────────

test "NativeRuntime name" {
    var native = NativeRuntime{};
    const rt = native.adapter();
    try std.testing.expectEqualStrings("native", rt.getName());
}

test "NativeRuntime has shell access" {
    var native = NativeRuntime{};
    const rt = native.adapter();
    try std.testing.expect(rt.hasShellAccess());
}

test "NativeRuntime has filesystem access" {
    var native = NativeRuntime{};
    const rt = native.adapter();
    try std.testing.expect(rt.hasFilesystemAccess());
}

test "NativeRuntime supports long running" {
    var native = NativeRuntime{};
    const rt = native.adapter();
    try std.testing.expect(rt.supportsLongRunning());
}

test "NativeRuntime memory budget unlimited" {
    var native = NativeRuntime{};
    const rt = native.adapter();
    try std.testing.expectEqual(@as(u64, 0), rt.memoryBudget());
}

test "NativeRuntime storage path contains nullclaw" {
    var native = NativeRuntime{};
    const rt = native.adapter();
    try std.testing.expect(std.mem.indexOf(u8, rt.storagePath(), "nullclaw") != null);
}

test "DockerRuntime name" {
    var docker = DockerRuntime.init("alpine:3.20", "none", null, false);
    const rt = docker.adapter();
    try std.testing.expectEqualStrings("docker", rt.getName());
}

test "DockerRuntime memory budget" {
    var docker = DockerRuntime.init("alpine:3.20", "none", 256, false);
    const rt = docker.adapter();
    try std.testing.expectEqual(@as(u64, 256 * 1024 * 1024), rt.memoryBudget());
}

test "DockerRuntime memory budget none" {
    var docker = DockerRuntime.init("alpine:3.20", "none", null, false);
    const rt = docker.adapter();
    try std.testing.expectEqual(@as(u64, 0), rt.memoryBudget());
}

test "DockerRuntime shell access" {
    var docker = DockerRuntime.init("alpine:3.20", "none", null, false);
    const rt = docker.adapter();
    try std.testing.expect(rt.hasShellAccess());
}

test "DockerRuntime filesystem with mount" {
    var docker = DockerRuntime.init("alpine:3.20", "none", null, true);
    const rt = docker.adapter();
    try std.testing.expect(rt.hasFilesystemAccess());
    try std.testing.expectEqualStrings("/workspace/.nullclaw", rt.storagePath());
}

test "DockerRuntime filesystem without mount" {
    var docker = DockerRuntime.init("alpine:3.20", "none", null, false);
    const rt = docker.adapter();
    try std.testing.expect(!rt.hasFilesystemAccess());
    try std.testing.expectEqualStrings("/tmp/.nullclaw", rt.storagePath());
}

test "DockerRuntime does not support long running" {
    var docker = DockerRuntime.init("alpine:3.20", "none", null, false);
    const rt = docker.adapter();
    try std.testing.expect(!rt.supportsLongRunning());
}

test "createRuntime native" {
    const kind = try createRuntime("native");
    try std.testing.expect(kind == .native);
}

test "createRuntime docker" {
    const kind = try createRuntime("docker");
    try std.testing.expect(kind == .docker);
}

test "createRuntime wasm" {
    const kind = try createRuntime("wasm");
    try std.testing.expect(kind == .wasm);
}

test "createRuntime cloudflare" {
    const kind = try createRuntime("cloudflare");
    try std.testing.expect(kind == .cloudflare);
}

test "CloudflareRuntime name" {
    var cf = CloudflareRuntime{};
    const rt = cf.adapter();
    try std.testing.expectEqualStrings("cloudflare", rt.getName());
}

test "CloudflareRuntime has no shell or filesystem" {
    var cf = CloudflareRuntime{};
    const rt = cf.adapter();
    try std.testing.expect(!rt.hasShellAccess());
    try std.testing.expect(!rt.hasFilesystemAccess());
    try std.testing.expect(!rt.supportsLongRunning());
}

test "CloudflareRuntime memory budget 128 MB" {
    var cf = CloudflareRuntime{};
    const rt = cf.adapter();
    try std.testing.expectEqual(@as(u64, 128 * 1024 * 1024), rt.memoryBudget());
}

test "createRuntime unknown" {
    try std.testing.expectError(error.UnknownRuntimeKind, createRuntime("wasm-edge"));
}

test "createRuntime empty" {
    try std.testing.expectError(error.EmptyRuntimeKind, createRuntime(""));
}

// ── Additional runtime tests ─────────────────────────────────────

test "createRuntime whitespace-only" {
    try std.testing.expectError(error.EmptyRuntimeKind, createRuntime("   "));
}

test "createRuntime tab whitespace" {
    try std.testing.expectError(error.EmptyRuntimeKind, createRuntime("\t"));
}

test "NativeRuntime storage path" {
    var native = NativeRuntime{};
    const rt = native.adapter();
    try std.testing.expectEqualStrings(".nullclaw", rt.storagePath());
}

test "NativeRuntime memory budget is zero (unlimited)" {
    var native = NativeRuntime{};
    const rt = native.adapter();
    try std.testing.expectEqual(@as(u64, 0), rt.memoryBudget());
}

test "DockerRuntime init stores all fields" {
    var docker = DockerRuntime.init("ubuntu:24.04", "bridge", 512, true);
    const rt = docker.adapter();
    try std.testing.expectEqualStrings("docker", rt.getName());
    try std.testing.expect(rt.hasFilesystemAccess());
    try std.testing.expectEqual(@as(u64, 512 * 1024 * 1024), rt.memoryBudget());
}

test "DockerRuntime different images" {
    var d1 = DockerRuntime.init("alpine:3.20", "none", null, false);
    var d2 = DockerRuntime.init("ubuntu:24.04", "host", 1024, true);
    const rt1 = d1.adapter();
    const rt2 = d2.adapter();

    // Both report as "docker" runtime
    try std.testing.expectEqualStrings("docker", rt1.getName());
    try std.testing.expectEqualStrings("docker", rt2.getName());

    // Different filesystem access
    try std.testing.expect(!rt1.hasFilesystemAccess());
    try std.testing.expect(rt2.hasFilesystemAccess());

    // Different memory budgets
    try std.testing.expectEqual(@as(u64, 0), rt1.memoryBudget());
    try std.testing.expectEqual(@as(u64, 1024 * 1024 * 1024), rt2.memoryBudget());
}

test "DockerRuntime storage path with workspace mount" {
    var docker = DockerRuntime.init("alpine:3.20", "none", null, true);
    const rt = docker.adapter();
    try std.testing.expect(std.mem.indexOf(u8, rt.storagePath(), "workspace") != null);
}

test "DockerRuntime storage path without workspace mount" {
    var docker = DockerRuntime.init("alpine:3.20", "none", null, false);
    const rt = docker.adapter();
    try std.testing.expect(std.mem.indexOf(u8, rt.storagePath(), "tmp") != null);
}

test "DockerRuntime does not support long running with mount" {
    var docker = DockerRuntime.init("alpine:3.20", "none", null, true);
    const rt = docker.adapter();
    try std.testing.expect(!rt.supportsLongRunning());
}

test "DockerRuntime has shell access" {
    var docker = DockerRuntime.init("alpine:3.20", "none", null, false);
    const rt = docker.adapter();
    try std.testing.expect(rt.hasShellAccess());
}

test "RuntimeAdapter vtable dispatch for NativeRuntime" {
    var native = NativeRuntime{};
    const rt = native.adapter();
    // Verify all vtable methods work via the adapter interface
    try std.testing.expect(rt.getName().len > 0);
    _ = rt.hasShellAccess();
    _ = rt.hasFilesystemAccess();
    _ = rt.storagePath();
    _ = rt.supportsLongRunning();
    _ = rt.memoryBudget();
}

test "RuntimeAdapter vtable dispatch for DockerRuntime" {
    var docker = DockerRuntime.init("test:latest", "none", 64, true);
    const rt = docker.adapter();
    // Verify all vtable methods work via the adapter interface
    try std.testing.expect(rt.getName().len > 0);
    _ = rt.hasShellAccess();
    _ = rt.hasFilesystemAccess();
    _ = rt.storagePath();
    _ = rt.supportsLongRunning();
    _ = rt.memoryBudget();
}

test "DockerRuntime memory budget with large value" {
    var docker = DockerRuntime.init("alpine:3.20", "none", 4096, false);
    const rt = docker.adapter();
    try std.testing.expectEqual(@as(u64, 4096 * 1024 * 1024), rt.memoryBudget());
}

test "DockerRuntime memory budget saturating mul" {
    // Test with a very large value to ensure no overflow
    var docker = DockerRuntime.init("alpine:3.20", "none", std.math.maxInt(u64), false);
    const rt = docker.adapter();
    // Should use saturating mul, result should be maxInt(u64)
    try std.testing.expectEqual(std.math.maxInt(u64), rt.memoryBudget());
}

test "createRuntime case sensitive" {
    // Only exact matches should work
    try std.testing.expectError(error.UnknownRuntimeKind, createRuntime("Native"));
    try std.testing.expectError(error.UnknownRuntimeKind, createRuntime("DOCKER"));
}

test "NativeRuntime full capabilities" {
    var native = NativeRuntime{};
    const rt = native.adapter();
    try std.testing.expect(rt.hasShellAccess());
    try std.testing.expect(rt.hasFilesystemAccess());
    try std.testing.expect(rt.supportsLongRunning());
    try std.testing.expectEqual(@as(u64, 0), rt.memoryBudget());
}

test "RuntimeKind enum values" {
    const n: RuntimeKind = .native;
    const d: RuntimeKind = .docker;
    const w: RuntimeKind = .wasm;
    try std.testing.expect(n == .native);
    try std.testing.expect(d == .docker);
    try std.testing.expect(w == .wasm);
    try std.testing.expect(n != d);
    try std.testing.expect(d != w);
}

// ── WASM Runtime tests ──────────────────────────────────────────────

test "WasmRuntime name" {
    var wasm = WasmRuntime.init(.{});
    const rt = wasm.adapter();
    try std.testing.expectEqualStrings("wasm", rt.getName());
}

test "WasmRuntime no shell access" {
    var wasm = WasmRuntime.init(.{});
    const rt = wasm.adapter();
    try std.testing.expect(!rt.hasShellAccess());
}

test "WasmRuntime no filesystem by default" {
    var wasm = WasmRuntime.init(.{});
    const rt = wasm.adapter();
    try std.testing.expect(!rt.hasFilesystemAccess());
}

test "WasmRuntime filesystem when read enabled" {
    var wasm = WasmRuntime.init(.{ .allow_workspace_read = true });
    const rt = wasm.adapter();
    try std.testing.expect(rt.hasFilesystemAccess());
}

test "WasmRuntime filesystem when write enabled" {
    var wasm = WasmRuntime.init(.{ .allow_workspace_write = true });
    const rt = wasm.adapter();
    try std.testing.expect(rt.hasFilesystemAccess());
}

test "WasmRuntime no long running" {
    var wasm = WasmRuntime.init(.{});
    const rt = wasm.adapter();
    try std.testing.expect(!rt.supportsLongRunning());
}

test "WasmRuntime memory budget" {
    var wasm = WasmRuntime.init(.{});
    const rt = wasm.adapter();
    try std.testing.expectEqual(@as(u64, 64 * 1024 * 1024), rt.memoryBudget());
}

test "WasmRuntime memory budget custom" {
    var wasm = WasmRuntime.init(.{ .memory_limit_mb = 128 });
    const rt = wasm.adapter();
    try std.testing.expectEqual(@as(u64, 128 * 1024 * 1024), rt.memoryBudget());
}

test "WasmRuntime storage path" {
    var wasm = WasmRuntime.init(.{});
    const rt = wasm.adapter();
    try std.testing.expect(std.mem.indexOf(u8, rt.storagePath(), "nullclaw") != null);
}

test "WasmRuntime validate rejects zero memory" {
    const wasm = WasmRuntime.init(.{ .memory_limit_mb = 0 });
    try std.testing.expectError(error.ZeroMemoryLimit, wasm.validateConfig());
}

test "WasmRuntime validate rejects excessive memory" {
    const wasm = WasmRuntime.init(.{ .memory_limit_mb = 8192 });
    try std.testing.expectError(error.ExcessiveMemoryLimit, wasm.validateConfig());
}

test "WasmRuntime validate rejects empty tools dir" {
    const wasm = WasmRuntime.init(.{ .tools_dir = "" });
    try std.testing.expectError(error.EmptyToolsDir, wasm.validateConfig());
}

test "WasmRuntime validate rejects path traversal" {
    const wasm = WasmRuntime.init(.{ .tools_dir = "../../../etc" });
    try std.testing.expectError(error.PathTraversal, wasm.validateConfig());
}

test "WasmRuntime validate accepts valid config" {
    const wasm = WasmRuntime.init(.{});
    try wasm.validateConfig();
}

test "WasmRuntime validate accepts max memory" {
    const wasm = WasmRuntime.init(.{ .memory_limit_mb = 4096 });
    try wasm.validateConfig();
}

test "WasmRuntime effective fuel uses config default" {
    const wasm = WasmRuntime.init(.{});
    const caps = WasmCapabilities{};
    try std.testing.expectEqual(@as(u64, 1_000_000), wasm.effectiveFuel(caps));
}

test "WasmRuntime effective fuel respects override" {
    const wasm = WasmRuntime.init(.{});
    const caps = WasmCapabilities{ .max_fuel = 500 };
    try std.testing.expectEqual(@as(u64, 500), wasm.effectiveFuel(caps));
}

test "WasmRuntime effective memory uses config default" {
    const wasm = WasmRuntime.init(.{});
    const caps = WasmCapabilities{};
    try std.testing.expectEqual(@as(u64, 64 * 1024 * 1024), wasm.effectiveMemoryBytes(caps));
}

test "WasmRuntime effective memory respects override" {
    const wasm = WasmRuntime.init(.{});
    const caps = WasmCapabilities{ .max_memory_bytes = 128 * 1024 * 1024 };
    try std.testing.expectEqual(@as(u64, 128 * 1024 * 1024), wasm.effectiveMemoryBytes(caps));
}

test "WasmRuntime default capabilities match config" {
    const wasm = WasmRuntime.init(.{ .allow_workspace_read = true, .fuel_limit = 500_000 });
    const caps = wasm.defaultCapabilities();
    try std.testing.expect(caps.has_wasi);
    try std.testing.expect(caps.allow_workspace_read);
    try std.testing.expect(!caps.allow_workspace_write);
    try std.testing.expectEqual(@as(u64, 500_000), caps.max_fuel);
}

test "WasmCapabilities defaults are locked down" {
    const caps = WasmCapabilities{};
    try std.testing.expect(!caps.has_wasi);
    try std.testing.expect(!caps.allow_workspace_read);
    try std.testing.expect(!caps.allow_workspace_write);
    try std.testing.expectEqual(@as(u64, 1_000_000), caps.max_fuel);
    try std.testing.expectEqual(@as(usize, 64 * 1024 * 1024), caps.max_memory_bytes);
}

test "WasmExecutionResult fields" {
    const result = WasmExecutionResult{
        .stdout = "hello",
        .stderr = "",
        .exit_code = 0,
        .fuel_consumed = 42,
    };
    try std.testing.expectEqualStrings("hello", result.stdout);
    try std.testing.expectEqual(@as(i32, 0), result.exit_code);
    try std.testing.expectEqual(@as(u64, 42), result.fuel_consumed);
}

test "WasmRuntimeConfig defaults" {
    const cfg = WasmRuntimeConfig{};
    try std.testing.expectEqual(@as(u64, 1_000_000), cfg.fuel_limit);
    try std.testing.expectEqual(@as(u64, 64), cfg.memory_limit_mb);
    try std.testing.expectEqualStrings("tools/wasm", cfg.tools_dir);
    try std.testing.expect(!cfg.allow_workspace_read);
    try std.testing.expect(!cfg.allow_workspace_write);
}

test "WasmRuntime memory budget saturating" {
    var wasm = WasmRuntime.init(.{ .memory_limit_mb = std.math.maxInt(u64) });
    const rt = wasm.adapter();
    try std.testing.expectEqual(std.math.maxInt(u64), rt.memoryBudget());
}

test "WasmRuntime vtable dispatch" {
    var wasm = WasmRuntime.init(.{});
    const rt = wasm.adapter();
    try std.testing.expect(rt.getName().len > 0);
    _ = rt.hasShellAccess();
    _ = rt.hasFilesystemAccess();
    _ = rt.storagePath();
    _ = rt.supportsLongRunning();
    _ = rt.memoryBudget();
}
