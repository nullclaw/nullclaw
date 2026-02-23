const std = @import("std");
const Config = @import("config.zig").Config;
const version = @import("version.zig");
const channel_catalog = @import("channel_catalog.zig");

pub fn run(allocator: std.mem.Allocator) !void {
    var buf: [4096]u8 = undefined;
    var bw = std.fs.File.stdout().writer(&buf);
    const w = &bw.interface;

    var cfg = Config.load(allocator) catch {
        try w.print("nullclaw Status (no config found -- run `nullclaw onboard` first)\n", .{});
        try w.print("\nVersion: {s}\n", .{version.string});
        try w.flush();
        return;
    };
    defer cfg.deinit();

    try w.print("nullclaw Status\n\n", .{});
    try w.print("Version:     {s}\n", .{version.string});
    try w.print("Workspace:   {s}\n", .{cfg.workspace_dir});
    try w.print("Config:      {s}\n", .{cfg.config_path});
    try w.print("\n", .{});
    try w.print("Provider:    {s}\n", .{cfg.default_provider});
    try w.print("Model:       {s}\n", .{cfg.default_model orelse "(default)"});
    try w.print("Temperature: {d:.1}\n", .{cfg.temperature});
    try w.print("\n", .{});
    try w.print("Memory:      {s} (auto-save: {s})\n", .{
        cfg.memory_backend,
        if (cfg.memory_auto_save) "on" else "off",
    });
    try w.print("Heartbeat:   {s}\n", .{
        if (cfg.heartbeat_enabled) "enabled" else "disabled",
    });
    try w.print("Security:    workspace_only={s}, max_actions/hr={d}\n", .{
        if (cfg.workspace_only) "yes" else "no",
        cfg.max_actions_per_hour,
    });
    try w.print("\n", .{});

    // Diagnostics
    try w.print("Diagnostics:   {s}\n", .{cfg.diagnostics.backend});

    // Runtime
    try w.print("Runtime:     {s}\n", .{cfg.runtime.kind});

    // Gateway
    try w.print("Gateway:     {s}:{d}\n", .{ cfg.gateway_host, cfg.gateway_port });

    // Scheduler
    try w.print("Scheduler:   {s} (max_tasks={d}, max_concurrent={d})\n", .{
        if (cfg.scheduler.enabled) "enabled" else "disabled",
        cfg.scheduler.max_tasks,
        cfg.scheduler.max_concurrent,
    });

    // Cost tracking
    try w.print("Cost:        {s}\n", .{
        if (cfg.cost.enabled) "tracking enabled" else "disabled",
    });

    // Hardware
    try w.print("Hardware:    {s}\n", .{
        if (cfg.hardware.enabled) "enabled" else "disabled",
    });

    // Peripherals
    try w.print("Peripherals: {s} ({d} boards)\n", .{
        if (cfg.peripherals.enabled) "enabled" else "disabled",
        cfg.peripherals.boards.len,
    });

    // Sandbox
    try w.print("Sandbox:     {s}\n", .{
        if (cfg.security.sandbox.enabled orelse false) "enabled" else "disabled",
    });

    // Audit
    try w.print("Audit:       {s}\n", .{
        if (cfg.security.audit.enabled) "enabled" else "disabled",
    });

    try w.print("\n", .{});

    // Channels
    try w.print("Channels:\n", .{});
    for (channel_catalog.known_channels) |meta| {
        var status_buf: [64]u8 = undefined;
        const status_text = if (meta.id == .cli)
            "always"
        else
            channel_catalog.statusText(&cfg, meta, &status_buf);
        try w.print("  {s}: {s}\n", .{ meta.label, status_text });
    }

    try w.flush();
}
