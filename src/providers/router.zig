const std = @import("std");
const root = @import("root.zig");

const Provider = root.Provider;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;

/// A single route: maps a task hint to a provider + model combo.
pub const Route = struct {
    provider_name: []const u8,
    model: []const u8,
};

/// Multi-model router -- routes requests to different provider+model combos
/// based on a task hint encoded in the model parameter.
///
/// The model parameter can be:
/// - A regular model name (e.g. "anthropic/claude-sonnet-4") -> uses default provider
/// - A hint-prefixed string (e.g. "hint:reasoning") -> resolves via route table
pub const RouterProvider = struct {
    /// Resolved routes: hint -> (provider_index, model).
    routes: std.StringHashMap(ResolvedRoute),
    /// Provider names (matching indexes).
    provider_names: []const []const u8,
    default_index: usize,
    default_model: []const u8,

    pub const ResolvedRoute = struct {
        provider_index: usize,
        model: []const u8,
    };

    /// Create a new router.
    ///
    /// `provider_names` is a list of provider names (first is default).
    /// `routes` maps hint names to Route structs.
    pub fn init(
        allocator: std.mem.Allocator,
        provider_names: []const []const u8,
        routes: []const RouteEntry,
        default_model: []const u8,
    ) !RouterProvider {
        // Build name -> index lookup
        var name_to_index = std.StringHashMap(usize).init(allocator);
        defer name_to_index.deinit();
        for (provider_names, 0..) |name, i| {
            try name_to_index.put(name, i);
        }

        // Resolve routes
        var resolved = std.StringHashMap(ResolvedRoute).init(allocator);
        for (routes) |entry| {
            if (name_to_index.get(entry.route.provider_name)) |idx| {
                try resolved.put(entry.hint, .{
                    .provider_index = idx,
                    .model = entry.route.model,
                });
            }
            // Silently skip routes referencing unknown providers
        }

        return .{
            .routes = resolved,
            .provider_names = provider_names,
            .default_index = 0,
            .default_model = default_model,
        };
    }

    pub fn deinit(self: *RouterProvider) void {
        self.routes.deinit();
    }

    pub const RouteEntry = struct {
        hint: []const u8,
        route: Route,
    };

    /// Resolve a model parameter to a (provider_index, actual_model) pair.
    ///
    /// If the model starts with "hint:", look up the hint in the route table.
    /// Otherwise, use the default provider with the given model name.
    pub fn resolve(self: RouterProvider, model: []const u8) struct { usize, []const u8 } {
        if (std.mem.startsWith(u8, model, "hint:")) {
            const hint = model["hint:".len..];
            if (self.routes.get(hint)) |resolved| {
                return .{ resolved.provider_index, resolved.model };
            }
        }

        // Not a hint or hint not found — use default
        return .{ self.default_index, model };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "resolve preserves model for non-hints" {
    const provider_names = [_][]const u8{"default"};
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &.{},
        "default-model",
    );
    defer router.deinit();

    const result = router.resolve("gpt-4o");
    try std.testing.expect(result[0] == 0);
    try std.testing.expectEqualStrings("gpt-4o", result[1]);
}

test "resolve strips hint prefix" {
    const provider_names = [_][]const u8{ "fast", "smart" };
    const routes = [_]RouterProvider.RouteEntry{
        .{ .hint = "reasoning", .route = .{ .provider_name = "smart", .model = "claude-opus" } },
    };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &routes,
        "default-model",
    );
    defer router.deinit();

    const result = router.resolve("hint:reasoning");
    try std.testing.expect(result[0] == 1);
    try std.testing.expectEqualStrings("claude-opus", result[1]);
}

test "unknown hint falls back to default" {
    const provider_names = [_][]const u8{ "default", "other" };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &.{},
        "default-model",
    );
    defer router.deinit();

    const result = router.resolve("hint:nonexistent");
    try std.testing.expect(result[0] == 0);
    try std.testing.expectEqualStrings("hint:nonexistent", result[1]);
}

test "non-hint model uses default provider" {
    const provider_names = [_][]const u8{ "primary", "secondary" };
    const routes = [_]RouterProvider.RouteEntry{
        .{ .hint = "code", .route = .{ .provider_name = "secondary", .model = "codellama" } },
    };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &routes,
        "default-model",
    );
    defer router.deinit();

    const result = router.resolve("anthropic/claude-sonnet-4-20250514");
    try std.testing.expect(result[0] == 0);
    try std.testing.expectEqualStrings("anthropic/claude-sonnet-4-20250514", result[1]);
}

test "skips routes with unknown provider" {
    const provider_names = [_][]const u8{"default"};
    const routes = [_]RouterProvider.RouteEntry{
        .{ .hint = "broken", .route = .{ .provider_name = "nonexistent", .model = "model" } },
    };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &routes,
        "default-model",
    );
    defer router.deinit();

    // Route should not exist
    try std.testing.expect(router.routes.get("broken") == null);
}

test "multiple routes resolve correctly" {
    const provider_names = [_][]const u8{ "fast", "smart", "local" };
    const routes = [_]RouterProvider.RouteEntry{
        .{ .hint = "fast", .route = .{ .provider_name = "fast", .model = "llama-3-70b" } },
        .{ .hint = "reasoning", .route = .{ .provider_name = "smart", .model = "claude-opus" } },
        .{ .hint = "local", .route = .{ .provider_name = "local", .model = "mistral" } },
    };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &routes,
        "default-model",
    );
    defer router.deinit();

    const fast = router.resolve("hint:fast");
    try std.testing.expect(fast[0] == 0);
    try std.testing.expectEqualStrings("llama-3-70b", fast[1]);

    const reasoning = router.resolve("hint:reasoning");
    try std.testing.expect(reasoning[0] == 1);
    try std.testing.expectEqualStrings("claude-opus", reasoning[1]);

    const local = router.resolve("hint:local");
    try std.testing.expect(local[0] == 2);
    try std.testing.expectEqualStrings("mistral", local[1]);
}

test "empty providers list creates router" {
    const provider_names = [_][]const u8{};
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &.{},
        "default-model",
    );
    defer router.deinit();
    try std.testing.expect(router.default_index == 0);
}

test "resolve plain model name preserves it" {
    const provider_names = [_][]const u8{"p1"};
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &.{},
        "default-model",
    );
    defer router.deinit();

    const result = router.resolve("anthropic/claude-sonnet-4-20250514");
    try std.testing.expect(result[0] == 0);
    try std.testing.expectEqualStrings("anthropic/claude-sonnet-4-20250514", result[1]);
}

test "resolve empty model" {
    const provider_names = [_][]const u8{"default"};
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &.{},
        "default-model",
    );
    defer router.deinit();

    const result = router.resolve("");
    try std.testing.expect(result[0] == 0);
    try std.testing.expectEqualStrings("", result[1]);
}

test "resolve hint: prefix with no suffix" {
    const provider_names = [_][]const u8{"default"};
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &.{},
        "default-model",
    );
    defer router.deinit();

    const result = router.resolve("hint:");
    try std.testing.expect(result[0] == 0);
    // Falls back with "hint:" as model because "" hint not found
    try std.testing.expectEqualStrings("hint:", result[1]);
}

test "default model stored" {
    const provider_names = [_][]const u8{"p1"};
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &.{},
        "my-default-model",
    );
    defer router.deinit();
    try std.testing.expectEqualStrings("my-default-model", router.default_model);
}
