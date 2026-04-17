/// --list-models subcommand: output available models for a provider as JSON array.
///
/// Used by nullhub to populate the dynamic model selector during onboarding.
/// Delegates to onboard.fetchModels which handles caching, fallbacks, and API calls.
const std = @import("std");
const std_compat = @import("compat");
const onboard = @import("onboard.zig");

fn writeModelsJson(out: *std.Io.Writer, models: []const []const u8) !void {
    try out.writeByte('[');
    for (models, 0..) |model, idx| {
        if (idx > 0) try out.writeByte(',');
        try out.print("{f}", .{std.json.fmt(model, .{})});
    }
    try out.writeAll("]\n");
}

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var provider: ?[]const u8 = null;
    var api_key: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--provider") and i + 1 < args.len) {
            provider = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--api-key") and i + 1 < args.len) {
            api_key = args[i + 1];
            i += 1;
        }
    }

    if (provider == null) {
        std.debug.print("error: --provider is required\n", .{});
        std_compat.process.exit(1);
    }

    const provider_info = onboard.resolveProviderForQuickSetup(provider.?) orelse {
        std.debug.print("error: unknown provider '{s}'\n", .{provider.?});
        std_compat.process.exit(1);
    };

    // Use onboard's fetchModels (handles caching, fallbacks, API calls)
    const models = onboard.fetchModels(allocator, provider_info.key, api_key) catch |err| {
        std.debug.print("error fetching models: {}\n", .{err});
        std_compat.process.exit(1);
    };
    defer {
        for (models) |m| allocator.free(m);
        allocator.free(models);
    }

    // Output as JSON array to stdout
    var stdout_buf: [65536]u8 = undefined;
    var bw = std_compat.fs.File.stdout().writer(&stdout_buf);
    const out = &bw.interface;
    try writeModelsJson(out, models);
    try bw.interface.flush();
}

test "run requires --provider flag" {
    // Cannot easily test process.exit in-process; just verify the function signature compiles.
    // The real integration test is: nullclaw --list-models --provider anthropic
}

test "writeModelsJson escapes model identifiers" {
    var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer aw.deinit();

    const models = [_][]const u8{
        "ok-model",
        "bad\"model",
        "back\\slash",
        "line\nbreak",
    };

    try writeModelsJson(&aw.writer, &models);
    const rendered = aw.writer.buffer[0..aw.writer.end];
    try std.testing.expectEqualStrings("[\"ok-model\",\"bad\\\"model\",\"back\\\\slash\",\"line\\nbreak\"]\n", rendered);
}
