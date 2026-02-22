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
///
/// This wraps multiple pre-created providers and selects the right one per request.
pub const RouterProvider = struct {
    /// Resolved routes: hint -> (provider_index, model).
    routes: std.StringHashMap(ResolvedRoute),
    /// Provider vtable interfaces (matching indexes in provider_names).
    providers: []const Provider,
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
    /// `providers` is a list of Provider vtable interfaces (same order as names).
    /// `routes` maps hint names to Route structs.
    pub fn init(
        allocator: std.mem.Allocator,
        provider_names: []const []const u8,
        providers: []const Provider,
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
            .providers = providers,
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

    /// Create a Provider vtable interface from this RouterProvider.
    pub fn provider(self: *RouterProvider) Provider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Provider.VTable{
        .chatWithSystem = chatWithSystemImpl,
        .chat = chatImpl,
        .supportsNativeTools = supportsNativeToolsImpl,
        .supports_vision = supportsVisionImpl,
        .supports_vision_for_model = supportsVisionForModelImpl,
        .getName = getNameImpl,
        .deinit = deinitImpl,
    };

    fn chatWithSystemImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
    ) anyerror![]const u8 {
        const self: *RouterProvider = @ptrCast(@alignCast(ptr));
        const resolved = self.resolve(model);
        const provider_idx = resolved[0];
        const resolved_model = resolved[1];

        if (provider_idx >= self.providers.len) return error.NoProvider;
        const target = self.providers[provider_idx];
        return target.chatWithSystem(allocator, system_prompt, message, resolved_model, temperature);
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
    ) anyerror!ChatResponse {
        const self: *RouterProvider = @ptrCast(@alignCast(ptr));
        const resolved = self.resolve(model);
        const provider_idx = resolved[0];
        const resolved_model = resolved[1];

        if (provider_idx >= self.providers.len) return error.NoProvider;
        const target = self.providers[provider_idx];
        return target.chat(allocator, request, resolved_model, temperature);
    }

    fn supportsNativeToolsImpl(ptr: *anyopaque) bool {
        const self: *RouterProvider = @ptrCast(@alignCast(ptr));
        if (self.default_index >= self.providers.len) return false;
        return self.providers[self.default_index].supportsNativeTools();
    }

    fn supportsVisionImpl(ptr: *anyopaque) bool {
        const self: *RouterProvider = @ptrCast(@alignCast(ptr));
        return supportsVisionForModelImpl(ptr, self.default_model);
    }

    fn supportsVisionForModelImpl(ptr: *anyopaque, model: []const u8) bool {
        const self: *RouterProvider = @ptrCast(@alignCast(ptr));
        const resolved = self.resolve(model);
        const provider_idx = resolved[0];
        const resolved_model = resolved[1];
        if (provider_idx >= self.providers.len) return false;
        return self.providers[provider_idx].supportsVisionForModel(resolved_model);
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "router";
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *RouterProvider = @ptrCast(@alignCast(ptr));
        self.routes.deinit();
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Mock provider for tests
// ════════════════════════════════════════════════════════════════════════════

const MockProvider = struct {
    response: []const u8,
    native_tools: bool,
    supports_vision: bool = true,
    last_model: []const u8,

    fn init(response: []const u8, native_tools: bool) MockProvider {
        return .{
            .response = response,
            .native_tools = native_tools,
            .last_model = "",
        };
    }

    fn initWithVision(response: []const u8, native_tools: bool, supports_vision: bool) MockProvider {
        return .{
            .response = response,
            .native_tools = native_tools,
            .supports_vision = supports_vision,
            .last_model = "",
        };
    }

    fn provider(self: *MockProvider) Provider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &mock_vtable,
        };
    }

    const mock_vtable = Provider.VTable{
        .chatWithSystem = mockChatWithSystem,
        .chat = mockChat,
        .supportsNativeTools = mockSupportsNativeTools,
        .supports_vision = mockSupportsVision,
        .getName = mockGetName,
        .deinit = mockDeinit,
    };

    fn mockChatWithSystem(
        ptr: *anyopaque,
        _: std.mem.Allocator,
        _: ?[]const u8,
        _: []const u8,
        model: []const u8,
        _: f64,
    ) anyerror![]const u8 {
        const self: *MockProvider = @ptrCast(@alignCast(ptr));
        self.last_model = model;
        return self.response;
    }

    fn mockChat(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        _: ChatRequest,
        model: []const u8,
        _: f64,
    ) anyerror!ChatResponse {
        const self: *MockProvider = @ptrCast(@alignCast(ptr));
        self.last_model = model;
        return ChatResponse{ .content = try allocator.dupe(u8, self.response) };
    }

    fn mockSupportsNativeTools(ptr: *anyopaque) bool {
        const self: *MockProvider = @ptrCast(@alignCast(ptr));
        return self.native_tools;
    }

    fn mockSupportsVision(ptr: *anyopaque) bool {
        const self: *MockProvider = @ptrCast(@alignCast(ptr));
        return self.supports_vision;
    }

    fn mockGetName(_: *anyopaque) []const u8 {
        return "mock";
    }

    fn mockDeinit(_: *anyopaque) void {}
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "resolve preserves model for non-hints" {
    const provider_names = [_][]const u8{"default"};
    var mock = MockProvider.init("ok", false);
    const providers = [_]Provider{mock.provider()};
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
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
    var mock_fast = MockProvider.init("fast", false);
    var mock_smart = MockProvider.init("smart", false);
    const providers = [_]Provider{ mock_fast.provider(), mock_smart.provider() };
    const routes = [_]RouterProvider.RouteEntry{
        .{ .hint = "reasoning", .route = .{ .provider_name = "smart", .model = "claude-opus" } },
    };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
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
    var mock_a = MockProvider.init("a", false);
    var mock_b = MockProvider.init("b", false);
    const providers = [_]Provider{ mock_a.provider(), mock_b.provider() };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
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
    var mock_a = MockProvider.init("a", false);
    var mock_b = MockProvider.init("b", false);
    const providers = [_]Provider{ mock_a.provider(), mock_b.provider() };
    const routes = [_]RouterProvider.RouteEntry{
        .{ .hint = "code", .route = .{ .provider_name = "secondary", .model = "codellama" } },
    };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
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
    var mock = MockProvider.init("ok", false);
    const providers = [_]Provider{mock.provider()};
    const routes = [_]RouterProvider.RouteEntry{
        .{ .hint = "broken", .route = .{ .provider_name = "nonexistent", .model = "model" } },
    };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
        &routes,
        "default-model",
    );
    defer router.deinit();

    // Route should not exist
    try std.testing.expect(router.routes.get("broken") == null);
}

test "multiple routes resolve correctly" {
    const provider_names = [_][]const u8{ "fast", "smart", "local" };
    var mock_fast = MockProvider.init("fast", false);
    var mock_smart = MockProvider.init("smart", false);
    var mock_local = MockProvider.init("local", false);
    const providers = [_]Provider{ mock_fast.provider(), mock_smart.provider(), mock_local.provider() };
    const routes = [_]RouterProvider.RouteEntry{
        .{ .hint = "fast", .route = .{ .provider_name = "fast", .model = "llama-3-70b" } },
        .{ .hint = "reasoning", .route = .{ .provider_name = "smart", .model = "claude-opus" } },
        .{ .hint = "local", .route = .{ .provider_name = "local", .model = "mistral" } },
    };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
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
        &.{},
        "default-model",
    );
    defer router.deinit();
    try std.testing.expect(router.default_index == 0);
}

// ════════════════════════════════════════════════════════════════════════════
// Provider vtable tests
// ════════════════════════════════════════════════════════════════════════════

test "vtable getName returns router" {
    const provider_names = [_][]const u8{"default"};
    var mock = MockProvider.init("ok", false);
    const providers = [_]Provider{mock.provider()};
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
        &.{},
        "default-model",
    );
    const prov = router.provider();
    defer prov.deinit();

    try std.testing.expectEqualStrings("router", prov.getName());
}

test "vtable chatWithSystem delegates to correct provider" {
    const provider_names = [_][]const u8{ "fast", "smart" };
    var mock_fast = MockProvider.init("fast-response", false);
    var mock_smart = MockProvider.init("smart-response", false);
    const providers = [_]Provider{ mock_fast.provider(), mock_smart.provider() };
    const routes = [_]RouterProvider.RouteEntry{
        .{ .hint = "reasoning", .route = .{ .provider_name = "smart", .model = "claude-opus" } },
    };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
        &routes,
        "default-model",
    );
    const prov = router.provider();
    defer prov.deinit();

    const result = try prov.chatWithSystem(std.testing.allocator, "system", "hello", "hint:reasoning", 0.5);
    try std.testing.expectEqualStrings("smart-response", result);
    try std.testing.expectEqualStrings("claude-opus", mock_smart.last_model);
}

test "vtable chatWithSystem uses default for non-hint" {
    const provider_names = [_][]const u8{ "default", "other" };
    var mock_default = MockProvider.init("default-response", false);
    var mock_other = MockProvider.init("other-response", false);
    const providers = [_]Provider{ mock_default.provider(), mock_other.provider() };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
        &.{},
        "default-model",
    );
    const prov = router.provider();
    defer prov.deinit();

    const result = try prov.chatWithSystem(std.testing.allocator, null, "hello", "gpt-4o", 0.7);
    try std.testing.expectEqualStrings("default-response", result);
    try std.testing.expectEqualStrings("gpt-4o", mock_default.last_model);
}

test "vtable chat delegates with hint routing" {
    const provider_names = [_][]const u8{ "fast", "smart" };
    var mock_fast = MockProvider.init("fast-chat", false);
    var mock_smart = MockProvider.init("smart-chat", true);
    const providers = [_]Provider{ mock_fast.provider(), mock_smart.provider() };
    const routes = [_]RouterProvider.RouteEntry{
        .{ .hint = "code", .route = .{ .provider_name = "smart", .model = "codellama" } },
    };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
        &routes,
        "default-model",
    );
    const prov = router.provider();
    defer prov.deinit();

    const msgs = [_]root.ChatMessage{root.ChatMessage.user("write code")};
    const request = ChatRequest{ .messages = &msgs };
    const result = try prov.chat(std.testing.allocator, request, "hint:code", 0.5);
    defer if (result.content) |c| std.testing.allocator.free(c);
    try std.testing.expectEqualStrings("smart-chat", result.contentOrEmpty());
    try std.testing.expectEqualStrings("codellama", mock_smart.last_model);
}

test "vtable supportsNativeTools delegates to default" {
    const provider_names = [_][]const u8{ "default", "other" };
    var mock_default = MockProvider.init("ok", true);
    var mock_other = MockProvider.init("ok", false);
    const providers = [_]Provider{ mock_default.provider(), mock_other.provider() };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
        &.{},
        "default-model",
    );
    const prov = router.provider();
    defer prov.deinit();

    try std.testing.expect(prov.supportsNativeTools());
}

test "vtable supportsNativeTools false when default does not support" {
    const provider_names = [_][]const u8{"default"};
    var mock = MockProvider.init("ok", false);
    const providers = [_]Provider{mock.provider()};
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
        &.{},
        "default-model",
    );
    const prov = router.provider();
    defer prov.deinit();

    try std.testing.expect(!prov.supportsNativeTools());
}

test "vtable supportsNativeTools false when no providers" {
    var router = try RouterProvider.init(
        std.testing.allocator,
        &.{},
        &.{},
        &.{},
        "default-model",
    );
    const prov = router.provider();
    defer prov.deinit();

    try std.testing.expect(!prov.supportsNativeTools());
}

test "vtable supportsVisionForModel follows hint routing" {
    const provider_names = [_][]const u8{ "default", "vision" };
    var mock_default = MockProvider.initWithVision("ok", false, false);
    var mock_vision = MockProvider.initWithVision("ok", false, true);
    const providers = [_]Provider{ mock_default.provider(), mock_vision.provider() };
    const routes = [_]RouterProvider.RouteEntry{
        .{ .hint = "img", .route = .{ .provider_name = "vision", .model = "vision-model" } },
    };
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
        &routes,
        "default-model",
    );
    const prov = router.provider();
    defer prov.deinit();

    try std.testing.expect(!prov.supportsVisionForModel("default-model"));
    try std.testing.expect(prov.supportsVisionForModel("hint:img"));
}

test "vtable supportsVision uses default model resolution" {
    const provider_names = [_][]const u8{"default"};
    var mock_default = MockProvider.initWithVision("ok", false, false);
    const providers = [_]Provider{mock_default.provider()};
    var router = try RouterProvider.init(
        std.testing.allocator,
        &provider_names,
        &providers,
        &.{},
        "default-model",
    );
    const prov = router.provider();
    defer prov.deinit();

    try std.testing.expect(!prov.supportsVision());
}

test "vtable chatWithSystem returns error with no providers" {
    var router = try RouterProvider.init(
        std.testing.allocator,
        &.{},
        &.{},
        &.{},
        "default-model",
    );
    const prov = router.provider();
    defer prov.deinit();

    const result = prov.chatWithSystem(std.testing.allocator, null, "hello", "model", 0.5);
    try std.testing.expectError(error.NoProvider, result);
}

test "vtable chat returns error with no providers" {
    var router = try RouterProvider.init(
        std.testing.allocator,
        &.{},
        &.{},
        &.{},
        "default-model",
    );
    const prov = router.provider();
    defer prov.deinit();

    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const request = ChatRequest{ .messages = &msgs };
    const result = prov.chat(std.testing.allocator, request, "model", 0.5);
    try std.testing.expectError(error.NoProvider, result);
}
