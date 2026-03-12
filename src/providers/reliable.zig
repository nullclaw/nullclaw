const std = @import("std");
const root = @import("root.zig");

const Provider = root.Provider;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;

/// Check if an error message indicates a non-retryable client error (4xx except 429/408).
pub fn isNonRetryable(err_msg: []const u8) bool {
    // Look for 4xx status codes
    var i: usize = 0;
    while (i < err_msg.len) {
        // Find a digit sequence
        if (std.ascii.isDigit(err_msg[i])) {
            var end = i;
            while (end < err_msg.len and std.ascii.isDigit(err_msg[end])) {
                end += 1;
            }
            if (end - i == 3) {
                const code = std.fmt.parseInt(u16, err_msg[i..end], 10) catch {
                    i = end;
                    continue;
                };
                if (code >= 400 and code < 500) {
                    return code != 429 and code != 408;
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
    return false;
}

/// Check if an error message indicates context window exhaustion.
pub fn isContextExhausted(err_msg: []const u8) bool {
    // Case-insensitive match against common patterns from LLM providers.
    var lower_buf: [512]u8 = undefined;
    const check_len = @min(err_msg.len, lower_buf.len);
    for (err_msg[0..check_len], 0..) |c, idx| {
        lower_buf[idx] = std.ascii.toLower(c);
    }
    const lower = lower_buf[0..check_len];

    const has_context = std.mem.indexOf(u8, lower, "context") != null;
    const has_token = std.mem.indexOf(u8, lower, "token") != null;
    if (has_context and (std.mem.indexOf(u8, lower, "length") != null or
        std.mem.indexOf(u8, lower, "maximum") != null or
        std.mem.indexOf(u8, lower, "window") != null or
        std.mem.indexOf(u8, lower, "exceed") != null))
        return true;
    if (has_token and (std.mem.indexOf(u8, lower, "limit") != null or
        std.mem.indexOf(u8, lower, "too many") != null or
        std.mem.indexOf(u8, lower, "maximum") != null or
        std.mem.indexOf(u8, lower, "exceed") != null))
        return true;
    if (std.mem.indexOf(u8, lower, "413") != null and std.mem.indexOf(u8, lower, "too large") != null) return true;
    return false;
}

/// Check if an error message indicates a rate-limit (429) error.
pub fn isRateLimited(err_msg: []const u8) bool {
    var lower_buf: [512]u8 = undefined;
    const check_len = @min(err_msg.len, lower_buf.len);
    for (err_msg[0..check_len], 0..) |c, idx| {
        lower_buf[idx] = std.ascii.toLower(c);
    }
    const lower = lower_buf[0..check_len];

    if (std.mem.indexOf(u8, lower, "ratelimited") != null or
        std.mem.indexOf(u8, lower, "rate limited") != null or
        std.mem.indexOf(u8, lower, "rate_limit") != null or
        std.mem.indexOf(u8, lower, "too many requests") != null or
        std.mem.indexOf(u8, lower, "quota exceeded") != null or
        std.mem.indexOf(u8, lower, "throttle") != null)
    {
        return true;
    }

    return std.mem.indexOf(u8, lower, "429") != null and
        (std.mem.indexOf(u8, lower, "rate") != null or
            std.mem.indexOf(u8, lower, "limit") != null or
            std.mem.indexOf(u8, lower, "too many") != null);
}

/// Try to extract a Retry-After value (in milliseconds) from an error message.
pub fn parseRetryAfterMs(err_msg: []const u8) ?u64 {
    const prefixes = [_][]const u8{
        "retry-after:",
        "retry_after:",
        "retry-after ",
        "retry_after ",
    };

    // Case-insensitive search
    var lower_buf: [4096]u8 = undefined;
    const check_len = @min(err_msg.len, lower_buf.len);
    for (err_msg[0..check_len], 0..) |c, idx| {
        lower_buf[idx] = std.ascii.toLower(c);
    }
    const lower = lower_buf[0..check_len];

    for (prefixes) |prefix| {
        if (std.mem.indexOf(u8, lower, prefix)) |pos| {
            const after_start = pos + prefix.len;
            if (after_start >= check_len) continue;

            // Skip whitespace
            var start = after_start;
            while (start < check_len and (err_msg[start] == ' ' or err_msg[start] == '\t')) {
                start += 1;
            }

            // Parse number
            var end = start;
            var has_dot = false;
            while (end < check_len) {
                if (std.ascii.isDigit(err_msg[end])) {
                    end += 1;
                } else if (err_msg[end] == '.' and !has_dot) {
                    has_dot = true;
                    end += 1;
                } else {
                    break;
                }
            }

            if (end > start) {
                const num_str = err_msg[start..end];
                if (std.fmt.parseFloat(f64, num_str)) |secs| {
                    if (std.math.isFinite(secs) and secs >= 0.0) {
                        const millis = @as(u64, @intFromFloat(secs * 1000.0));
                        return millis;
                    }
                } else |_| {}
            }
        }
    }

    return null;
}

/// A named provider entry for the fallback chain.
pub const ProviderEntry = struct {
    name: []const u8,
    provider: Provider,
};

/// A model fallback mapping: when `model` fails, try `fallbacks` in order.
pub const ModelFallbackEntry = struct {
    model: []const u8,
    fallbacks: []const []const u8,
};

const ResolvedProviderTarget = struct {
    provider: Provider,
    model: []const u8,
    explicit: bool,
};

/// Provider wrapper with retry, multi-provider fallback, and model failover.
///
/// Wraps a primary inner provider and optional extra providers as a fallback chain.
/// Retries on transient errors with exponential backoff. Skips retries for
/// non-retryable client errors (4xx except 429/408). On rate-limit errors,
/// rotates API keys if available. Supports per-model fallback chains.
pub const ReliableProvider = struct {
    /// The wrapped primary inner provider to delegate calls to.
    inner: Provider,
    /// Additional fallback providers (empty by default for backward compat).
    extras: []const ProviderEntry = &.{},
    /// Per-model fallback chains.
    model_fallbacks: []const ModelFallbackEntry = &.{},
    /// List of provider names (for diagnostics/logging).
    provider_names: []const []const u8,
    max_retries: u32,
    base_backoff_ms: u64,
    /// Extra API keys for rotation on rate-limit errors.
    api_keys: []const []const u8,
    key_index: usize,
    /// Last error message from failed attempt (for retry-after parsing).
    last_error_msg: [256]u8,
    last_error_len: usize,

    pub fn init(
        provider_names: []const []const u8,
        max_retries: u32,
        base_backoff_ms: u64,
    ) ReliableProvider {
        return .{
            .inner = undefined,
            .provider_names = provider_names,
            .max_retries = max_retries,
            .base_backoff_ms = @max(base_backoff_ms, 50),
            .api_keys = &.{},
            .key_index = 0,
            .last_error_msg = undefined,
            .last_error_len = 0,
        };
    }

    /// Initialize with an inner provider to wrap.
    pub fn initWithProvider(
        inner: Provider,
        max_retries: u32,
        base_backoff_ms: u64,
    ) ReliableProvider {
        return .{
            .inner = inner,
            .provider_names = &.{},
            .max_retries = max_retries,
            .base_backoff_ms = @max(base_backoff_ms, 50),
            .api_keys = &.{},
            .key_index = 0,
            .last_error_msg = undefined,
            .last_error_len = 0,
        };
    }

    pub fn withApiKeys(self: *ReliableProvider, keys: []const []const u8) *ReliableProvider {
        self.api_keys = keys;
        return self;
    }

    /// Set the inner provider to wrap.
    pub fn withInner(self: *ReliableProvider, inner: Provider) *ReliableProvider {
        self.inner = inner;
        return self;
    }

    /// Set additional fallback providers.
    pub fn withExtras(self: ReliableProvider, extras: []const ProviderEntry) ReliableProvider {
        var r = self;
        r.extras = extras;
        return r;
    }

    /// Set per-model fallback chains.
    pub fn withModelFallbacks(self: ReliableProvider, fallbacks: []const ModelFallbackEntry) ReliableProvider {
        var r = self;
        r.model_fallbacks = fallbacks;
        return r;
    }

    /// Returns the model chain for a given model: [model, fallback1, fallback2, ...].
    /// If no fallbacks configured for this model, returns a single-element slice.
    /// Caller must free the returned slice.
    pub fn modelChain(self: *const ReliableProvider, allocator: std.mem.Allocator, model: []const u8) ![]const []const u8 {
        // Find fallbacks for this model
        for (self.model_fallbacks) |entry| {
            if (std.mem.eql(u8, entry.model, model)) {
                // Build chain: [model] ++ fallbacks
                const chain = try allocator.alloc([]const u8, 1 + entry.fallbacks.len);
                chain[0] = model;
                for (entry.fallbacks, 0..) |fb, i| {
                    chain[1 + i] = fb;
                }
                return chain;
            }
        }
        // No fallbacks: single-element slice
        const chain = try allocator.alloc([]const u8, 1);
        chain[0] = model;
        return chain;
    }

    fn splitProviderModel(model_ref: []const u8) struct { provider: ?[]const u8, model: []const u8 } {
        const slash = std.mem.indexOfScalar(u8, model_ref, '/') orelse {
            return .{ .provider = null, .model = model_ref };
        };
        if (slash == 0 or slash + 1 >= model_ref.len) {
            return .{ .provider = null, .model = model_ref };
        }
        return .{
            .provider = model_ref[0..slash],
            .model = model_ref[slash + 1 ..],
        };
    }

    fn matchesProvider(provider_name: []const u8, requested: []const u8) bool {
        return std.ascii.eqlIgnoreCase(provider_name, requested);
    }

    fn resolveProviderTarget(self: *const ReliableProvider, model_ref: []const u8) ResolvedProviderTarget {
        const split = splitProviderModel(model_ref);
        if (std.mem.eql(u8, self.inner.getName(), "router")) {
            return .{
                .provider = self.inner,
                .model = model_ref,
                .explicit = split.provider != null,
            };
        }
        if (split.provider) |requested_provider| {
            for (self.extras) |entry| {
                if (matchesProvider(entry.name, requested_provider) or
                    matchesProvider(entry.provider.getName(), requested_provider))
                {
                    return .{
                        .provider = entry.provider,
                        .model = split.model,
                        .explicit = true,
                    };
                }
            }
            if (matchesProvider(self.inner.getName(), requested_provider)) {
                return .{
                    .provider = self.inner,
                    .model = split.model,
                    .explicit = true,
                };
            }
        }

        return .{
            .provider = self.inner,
            .model = model_ref,
            .explicit = false,
        };
    }

    /// Advance to the next API key (round-robin) and return it.
    pub fn rotateKey(self: *ReliableProvider) ?[]const u8 {
        if (self.api_keys.len == 0) return null;
        const idx = self.key_index % self.api_keys.len;
        self.key_index += 1;
        return self.api_keys[idx];
    }

    /// Compute backoff duration, respecting Retry-After if present.
    pub fn computeBackoff(_: ReliableProvider, base: u64, err_msg: []const u8) u64 {
        if (parseRetryAfterMs(err_msg)) |retry_after| {
            // Cap at 30s
            return @max(@min(retry_after, 30_000), base);
        }
        return base;
    }

    /// Store an error name for retry-after inspection.
    fn storeErrorName(self: *ReliableProvider, err: anyerror) void {
        const name = @errorName(err);
        const copy_len = @min(name.len, self.last_error_msg.len);
        @memcpy(self.last_error_msg[0..copy_len], name[0..copy_len]);
        self.last_error_len = copy_len;
    }

    /// Get the last stored error message.
    fn lastErrorSlice(self: *const ReliableProvider) []const u8 {
        return self.last_error_msg[0..self.last_error_len];
    }

    fn maybeRecordFallbackErrorDetail(prov: Provider, err: anyerror) void {
        if (err == error.ApiError or
            err == error.RateLimited or
            err == error.ContextLengthExceeded or
            err == error.ProviderDoesNotSupportVision)
        {
            return;
        }
        root.setLastApiErrorDetail(prov.getName(), @errorName(err));
    }

    fn finalFailureError(self: *const ReliableProvider) anyerror {
        const err_slice = self.lastErrorSlice();
        if (isContextExhausted(err_slice)) return error.ContextLengthExceeded;
        if (isRateLimited(err_slice)) return error.RateLimited;
        if (std.mem.eql(u8, err_slice, "ProviderDoesNotSupportVision")) return error.ProviderDoesNotSupportVision;
        return error.AllProvidersFailed;
    }

    // ── Provider vtable implementation ──

    const vtable_impl = Provider.VTable{
        .chatWithSystem = chatWithSystemImpl,
        .chat = chatImpl,
        .supportsNativeTools = supportsNativeToolsImpl,
        .supports_vision = supportsVisionImpl,
        .supports_vision_for_model = supportsVisionForModelImpl,
        .supports_streaming = supportsStreamingImpl,
        .stream_chat = streamChatImpl,
        .getName = getNameImpl,
        .deinit = deinitImpl,
        .warmup = warmupImpl,
    };

    /// Create a Provider interface from this ReliableProvider.
    pub fn provider(self: *ReliableProvider) Provider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable_impl,
        };
    }

    /// Try a single provider with retries for chatWithSystem.
    fn tryChatWithSystemProvider(
        self: *ReliableProvider,
        prov: Provider,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        current_model: []const u8,
    ) ?[]const u8 {
        var backoff_ms = self.base_backoff_ms;
        var attempt: u32 = 0;
        while (attempt <= self.max_retries) : (attempt += 1) {
            root.clearLastApiErrorDetail();
            if (prov.chatWithSystem(allocator, system_prompt, message, current_model, 0.7)) |result| {
                return result;
            } else |err| {
                maybeRecordFallbackErrorDetail(prov, err);
                self.storeErrorName(err);
                const err_slice = self.lastErrorSlice();

                if (isNonRetryable(err_slice)) break;

                if (isRateLimited(err_slice)) {
                    if (self.extras.len > 0) break;
                    _ = self.rotateKey();
                }

                if (attempt < self.max_retries) {
                    const wait = self.computeBackoff(backoff_ms, err_slice);
                    std.Thread.sleep(wait * std.time.ns_per_ms);
                    backoff_ms = @min(backoff_ms *| 2, 10_000);
                }
            }
        }
        return null;
    }

    /// Try a single provider with retries for chat.
    fn tryChatProvider(
        self: *ReliableProvider,
        prov: Provider,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        current_model: []const u8,
    ) ?ChatResponse {
        var backoff_ms = self.base_backoff_ms;
        var attempt: u32 = 0;
        while (attempt <= self.max_retries) : (attempt += 1) {
            root.clearLastApiErrorDetail();
            var resolved_request = request;
            resolved_request.model = current_model;
            if (prov.chat(allocator, resolved_request, current_model, request.temperature)) |result| {
                var annotated = result;
                if (annotated.provider.len == 0) {
                    annotated.provider = allocator.dupe(u8, prov.getName()) catch "";
                }
                if (annotated.model.len == 0) {
                    annotated.model = allocator.dupe(u8, current_model) catch "";
                }
                return annotated;
            } else |err| {
                maybeRecordFallbackErrorDetail(prov, err);
                self.storeErrorName(err);
                const err_slice = self.lastErrorSlice();

                if (isNonRetryable(err_slice)) break;

                if (isRateLimited(err_slice)) {
                    if (self.extras.len > 0) break;
                    _ = self.rotateKey();
                }

                if (attempt < self.max_retries) {
                    const wait = self.computeBackoff(backoff_ms, err_slice);
                    std.Thread.sleep(wait * std.time.ns_per_ms);
                    backoff_ms = @min(backoff_ms *| 2, 10_000);
                }
            }
        }
        return null;
    }

    fn chatWithSystemImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        system_prompt: ?[]const u8,
        message: []const u8,
        model: []const u8,
        temperature: f64,
    ) anyerror![]const u8 {
        const self: *ReliableProvider = @ptrCast(@alignCast(ptr));
        _ = temperature;
        root.clearLastApiErrorDetail();

        const models = try self.modelChain(allocator, model);
        defer allocator.free(models);

        for (models) |current_model| {
            const target = self.resolveProviderTarget(current_model);

            if (target.explicit) {
                if (self.tryChatWithSystemProvider(
                    target.provider,
                    allocator,
                    system_prompt,
                    message,
                    target.model,
                )) |result| {
                    return result;
                }
                continue;
            }

            // Try primary provider
            if (self.tryChatWithSystemProvider(
                self.inner,
                allocator,
                system_prompt,
                message,
                current_model,
            )) |result| {
                return result;
            }

            // Try extra providers
            for (self.extras) |entry| {
                if (self.tryChatWithSystemProvider(
                    entry.provider,
                    allocator,
                    system_prompt,
                    message,
                    current_model,
                )) |result| {
                    return result;
                }
            }
        }

        return self.finalFailureError();
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
    ) anyerror!ChatResponse {
        const self: *ReliableProvider = @ptrCast(@alignCast(ptr));
        _ = temperature;
        root.clearLastApiErrorDetail();

        const needs_vision = hasImageParts(request);
        var attempted_vision_provider = false;
        const models = try self.modelChain(allocator, model);
        defer allocator.free(models);

        for (models) |current_model| {
            const target = self.resolveProviderTarget(current_model);

            if (target.explicit) {
                if (!needs_vision or target.provider.supportsVisionForModel(target.model)) {
                    if (needs_vision) attempted_vision_provider = true;
                    if (self.tryChatProvider(
                        target.provider,
                        allocator,
                        request,
                        target.model,
                    )) |result| {
                        return result;
                    }
                }
                continue;
            }

            // Try primary provider (skip if it lacks vision and request needs it)
            if (!needs_vision or self.inner.supportsVisionForModel(current_model)) {
                if (needs_vision) attempted_vision_provider = true;
                if (self.tryChatProvider(
                    self.inner,
                    allocator,
                    request,
                    current_model,
                )) |result| {
                    return result;
                }
            }

            // Try extra providers
            for (self.extras) |entry| {
                if (!needs_vision or entry.provider.supportsVisionForModel(current_model)) {
                    if (needs_vision) attempted_vision_provider = true;
                    if (self.tryChatProvider(
                        entry.provider,
                        allocator,
                        request,
                        current_model,
                    )) |result| {
                        return result;
                    }
                }
            }
        }

        // Defensive: if we skipped everything due to vision, return a clear error.
        // Normally caught upstream by buildProviderMessages, but handled here for
        // callers that invoke chatImpl directly (e.g. tests, gateway).
        if (needs_vision and !attempted_vision_provider) {
            return error.ProviderDoesNotSupportVision;
        }

        return self.finalFailureError();
    }

    fn supportsStreamingImpl(ptr: *anyopaque) bool {
        const self: *ReliableProvider = @ptrCast(@alignCast(ptr));
        if (self.inner.supportsStreaming()) return true;
        for (self.extras) |entry| {
            if (entry.provider.supportsStreaming()) return true;
        }
        return false;
    }

    fn streamChatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: root.ChatRequest,
        model: []const u8,
        temperature: f64,
        callback: root.StreamCallback,
        callback_ctx: *anyopaque,
    ) anyerror!root.StreamChatResult {
        const self: *ReliableProvider = @ptrCast(@alignCast(ptr));
        const needs_vision = hasImageParts(request);
        const target = self.resolveProviderTarget(model);

        if (target.explicit) {
            if (needs_vision and !target.provider.supportsVisionForModel(target.model)) {
                return error.ProviderDoesNotSupportVision;
            }
            var resolved_request = request;
            resolved_request.model = target.model;
            return target.provider.streamChat(allocator, resolved_request, target.model, temperature, callback, callback_ctx);
        }

        // Streaming cannot recover mid-stream (doing so would require buffering the
        // entire response, defeating the purpose of streaming). Provider selection is
        // therefore proactive: pick the first vision-capable provider before starting.
        // Note: model-chain fallback is not supported in the streaming path — this is
        // a pre-existing limitation and is not regressed by this change.
        if (!needs_vision or self.inner.supportsVisionForModel(model)) {
            return self.inner.streamChat(allocator, request, model, temperature, callback, callback_ctx);
        }
        for (self.extras) |entry| {
            if (entry.provider.supportsVisionForModel(model)) {
                return entry.provider.streamChat(allocator, request, model, temperature, callback, callback_ctx);
            }
        }
        return error.ProviderDoesNotSupportVision;
    }

    fn supportsNativeToolsImpl(ptr: *anyopaque) bool {
        const self: *ReliableProvider = @ptrCast(@alignCast(ptr));
        if (self.inner.supportsNativeTools()) return true;
        for (self.extras) |entry| {
            if (entry.provider.supportsNativeTools()) return true;
        }
        return false;
    }

    fn supportsVisionImpl(ptr: *anyopaque) bool {
        const self: *ReliableProvider = @ptrCast(@alignCast(ptr));
        if (self.inner.supportsVision()) return true;
        for (self.extras) |entry| {
            if (entry.provider.supportsVision()) return true;
        }
        return false;
    }

    fn supportsVisionForModelImpl(ptr: *anyopaque, model: []const u8) bool {
        const self: *ReliableProvider = @ptrCast(@alignCast(ptr));
        const target = self.resolveProviderTarget(model);
        if (target.explicit) return target.provider.supportsVisionForModel(target.model);
        if (self.inner.supportsVisionForModel(model)) return true;
        for (self.extras) |entry| {
            if (entry.provider.supportsVisionForModel(model)) return true;
        }
        return false;
    }

    fn getNameImpl(ptr: *anyopaque) []const u8 {
        const self: *ReliableProvider = @ptrCast(@alignCast(ptr));
        return self.inner.getName();
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *ReliableProvider = @ptrCast(@alignCast(ptr));
        self.inner.deinit();
        for (self.extras) |entry| {
            entry.provider.deinit();
        }
    }

    fn warmupImpl(ptr: *anyopaque) void {
        const self: *ReliableProvider = @ptrCast(@alignCast(ptr));
        self.inner.warmup();
        for (self.extras) |entry| {
            entry.provider.warmup();
        }
    }
};

/// Returns true if any message in the request has image content_parts
/// (image_url or image_base64), indicating vision capability is required.
fn hasImageParts(request: ChatRequest) bool {
    for (request.messages) |msg| {
        const parts = msg.content_parts orelse continue;
        for (parts) |part| {
            switch (part) {
                .image_url, .image_base64 => return true,
                .text => {},
            }
        }
    }
    return false;
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "isContextExhausted detects common patterns" {
    try std.testing.expect(isContextExhausted("context length exceeded"));
    try std.testing.expect(isContextExhausted("maximum context length"));
    try std.testing.expect(isContextExhausted("token limit exceeded"));
    try std.testing.expect(isContextExhausted("ContextLengthExceeded"));
    try std.testing.expect(isContextExhausted("too many tokens in context"));
    try std.testing.expect(isContextExhausted("maximum token limit"));
    try std.testing.expect(isContextExhausted("HTTP 413 Payload Too Large"));
    try std.testing.expect(!isContextExhausted("500 Internal Server Error"));
    try std.testing.expect(!isContextExhausted("connection reset"));
    try std.testing.expect(!isContextExhausted(""));
}

test "isNonRetryable detects common patterns" {
    try std.testing.expect(isNonRetryable("400 Bad Request"));
    try std.testing.expect(isNonRetryable("401 Unauthorized"));
    try std.testing.expect(isNonRetryable("403 Forbidden"));
    try std.testing.expect(isNonRetryable("404 Not Found"));
    try std.testing.expect(!isNonRetryable("429 Too Many Requests"));
    try std.testing.expect(!isNonRetryable("408 Request Timeout"));
    try std.testing.expect(!isNonRetryable("500 Internal Server Error"));
    try std.testing.expect(!isNonRetryable("502 Bad Gateway"));
    try std.testing.expect(!isNonRetryable("timeout"));
    try std.testing.expect(!isNonRetryable("connection reset"));
}

test "isRateLimited detection" {
    try std.testing.expect(isRateLimited("429 Too Many Requests"));
    try std.testing.expect(isRateLimited("HTTP 429 rate limit exceeded"));
    try std.testing.expect(isRateLimited("RateLimited"));
    try std.testing.expect(!isRateLimited("401 Unauthorized"));
    try std.testing.expect(!isRateLimited("500 Internal Server Error"));
}

test "parseRetryAfterMs integer" {
    try std.testing.expect(parseRetryAfterMs("429 Too Many Requests, Retry-After: 5").? == 5000);
}

test "parseRetryAfterMs float" {
    try std.testing.expect(parseRetryAfterMs("Rate limited. retry_after: 2.5 seconds").? == 2500);
}

test "parseRetryAfterMs missing" {
    try std.testing.expect(parseRetryAfterMs("500 Internal Server Error") == null);
}

test "ReliableProvider computeBackoff uses retry-after" {
    const prov = ReliableProvider.init(&.{}, 0, 500);
    try std.testing.expect(prov.computeBackoff(500, "429 Retry-After: 3") == 3000);
}

test "ReliableProvider computeBackoff caps at 30s" {
    const prov = ReliableProvider.init(&.{}, 0, 500);
    try std.testing.expect(prov.computeBackoff(500, "429 Retry-After: 120") == 30_000);
}

test "ReliableProvider computeBackoff falls back to base" {
    const prov = ReliableProvider.init(&.{}, 0, 500);
    try std.testing.expect(prov.computeBackoff(500, "500 Server Error") == 500);
}

test "ReliableProvider auth rotation cycles keys" {
    const keys = [_][]const u8{ "key-a", "key-b", "key-c" };
    var prov = ReliableProvider.init(&.{}, 0, 1);
    _ = prov.withApiKeys(&keys);

    // Rotate 5 times, verify round-robin
    try std.testing.expectEqualStrings("key-a", prov.rotateKey().?);
    try std.testing.expectEqualStrings("key-b", prov.rotateKey().?);
    try std.testing.expectEqualStrings("key-c", prov.rotateKey().?);
    try std.testing.expectEqualStrings("key-a", prov.rotateKey().?);
    try std.testing.expectEqualStrings("key-b", prov.rotateKey().?);
}

test "ReliableProvider auth rotation returns null when empty" {
    var prov = ReliableProvider.init(&.{}, 0, 1);
    try std.testing.expect(prov.rotateKey() == null);
}

test "isNonRetryable embedded in longer message" {
    try std.testing.expect(isNonRetryable("Error: got 401 from upstream API"));
    try std.testing.expect(!isNonRetryable("Server returned 500 error"));
}

test "isRateLimited requires both 429 and keyword" {
    // Just "429" alone without rate/limit/Too Many should be false
    try std.testing.expect(!isRateLimited("error code 429"));
    // With proper keywords
    try std.testing.expect(isRateLimited("429 rate exceeded"));
    try std.testing.expect(isRateLimited("429 limit reached"));
}

test "isRateLimited empty string" {
    try std.testing.expect(!isRateLimited(""));
}

test "parseRetryAfterMs with underscore separator" {
    try std.testing.expect(parseRetryAfterMs("retry_after: 10").? == 10000);
}

test "parseRetryAfterMs with space separator" {
    try std.testing.expect(parseRetryAfterMs("retry-after 7").? == 7000);
}

test "parseRetryAfterMs zero value" {
    try std.testing.expect(parseRetryAfterMs("Retry-After: 0").? == 0);
}

test "parseRetryAfterMs case insensitive" {
    try std.testing.expect(parseRetryAfterMs("RETRY-AFTER: 3").? == 3000);
    try std.testing.expect(parseRetryAfterMs("Retry-After: 3").? == 3000);
}

test "parseRetryAfterMs ignores non-numeric" {
    try std.testing.expect(parseRetryAfterMs("Retry-After: abc") == null);
}

test "ReliableProvider init enforces min backoff 50ms" {
    const prov = ReliableProvider.init(&.{}, 0, 10);
    try std.testing.expect(prov.base_backoff_ms == 50);
}

test "ReliableProvider computeBackoff uses base when retry-after is smaller" {
    const prov = ReliableProvider.init(&.{}, 0, 5000);
    // Retry-After: 1 second = 1000ms, but base is 5000ms -> max(1000, 5000) = 5000
    try std.testing.expect(prov.computeBackoff(5000, "429 Retry-After: 1") == 5000);
}

// ════════════════════════════════════════════════════════════════════════════
// Mock provider for vtable retry tests
// ════════════════════════════════════════════════════════════════════════════

const MockInnerProvider = struct {
    call_count: u32,
    fail_until: u32,
    fail_error: anyerror = error.ProviderError,
    supports_tools: bool,
    supports_vision: bool = true,
    warmed_up: bool = false,

    const vtable_mock = Provider.VTable{
        .chatWithSystem = mockChatWithSystem,
        .chat = mockChat,
        .supportsNativeTools = mockSupportsNativeTools,
        .supports_vision = mockSupportsVision,
        .getName = mockGetName,
        .deinit = mockDeinit,
        .warmup = mockWarmup,
    };

    fn toProvider(self: *MockInnerProvider) Provider {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable_mock };
    }

    fn mockChatWithSystem(
        ptr: *anyopaque,
        _: std.mem.Allocator,
        _: ?[]const u8,
        _: []const u8,
        _: []const u8,
        _: f64,
    ) anyerror![]const u8 {
        const self: *MockInnerProvider = @ptrCast(@alignCast(ptr));
        self.call_count += 1;
        if (self.call_count <= self.fail_until) {
            return self.fail_error;
        }
        return "mock response";
    }

    fn mockChat(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        _: ChatRequest,
        _: []const u8,
        _: f64,
    ) anyerror!ChatResponse {
        const self: *MockInnerProvider = @ptrCast(@alignCast(ptr));
        self.call_count += 1;
        if (self.call_count <= self.fail_until) {
            return self.fail_error;
        }
        return ChatResponse{ .content = try allocator.dupe(u8, "mock chat") };
    }

    fn mockSupportsNativeTools(ptr: *anyopaque) bool {
        const self: *MockInnerProvider = @ptrCast(@alignCast(ptr));
        return self.supports_tools;
    }

    fn mockSupportsVision(ptr: *anyopaque) bool {
        const self: *MockInnerProvider = @ptrCast(@alignCast(ptr));
        return self.supports_vision;
    }

    fn mockGetName(_: *anyopaque) []const u8 {
        return "MockProvider";
    }

    fn mockDeinit(_: *anyopaque) void {}

    fn mockWarmup(ptr: *anyopaque) void {
        const self: *MockInnerProvider = @ptrCast(@alignCast(ptr));
        self.warmed_up = true;
    }
};

/// Mock that records which model was used for each call.
const ModelAwareMock = struct {
    call_count: u32 = 0,
    models_seen_buf: [16][]const u8 = undefined,
    models_seen_len: usize = 0,
    fail_models_buf: [8][]const u8 = undefined,
    fail_models_len: usize = 0,
    response: []const u8 = "ok",
    supports_tools: bool = false,
    supports_vision: bool = true,

    const vtable_model = Provider.VTable{
        .chatWithSystem = modelChatWithSystem,
        .chat = modelChat,
        .supportsNativeTools = modelSupportsNativeTools,
        .supports_vision = modelSupportsVision,
        .getName = modelGetName,
        .deinit = modelDeinit,
    };

    fn toProvider(self: *ModelAwareMock) Provider {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable_model };
    }

    fn initWithFailModels(fail_models: []const []const u8, response: []const u8) ModelAwareMock {
        var mock = ModelAwareMock{
            .response = response,
        };
        const copy_len = @min(fail_models.len, mock.fail_models_buf.len);
        for (fail_models[0..copy_len], 0..) |m, i| {
            mock.fail_models_buf[i] = m;
        }
        mock.fail_models_len = copy_len;
        return mock;
    }

    fn failsModel(self: *const ModelAwareMock, model: []const u8) bool {
        for (self.fail_models_buf[0..self.fail_models_len]) |m| {
            if (std.mem.eql(u8, m, model)) return true;
        }
        return false;
    }

    fn recordModel(self: *ModelAwareMock, model: []const u8) void {
        if (self.models_seen_len < self.models_seen_buf.len) {
            self.models_seen_buf[self.models_seen_len] = model;
            self.models_seen_len += 1;
        }
    }

    fn modelsSeen(self: *const ModelAwareMock) []const []const u8 {
        return self.models_seen_buf[0..self.models_seen_len];
    }

    fn modelChatWithSystem(
        ptr: *anyopaque,
        _: std.mem.Allocator,
        _: ?[]const u8,
        _: []const u8,
        model: []const u8,
        _: f64,
    ) anyerror![]const u8 {
        const self: *ModelAwareMock = @ptrCast(@alignCast(ptr));
        self.call_count += 1;
        self.recordModel(model);
        if (self.failsModel(model)) {
            return error.ModelUnavailable;
        }
        return self.response;
    }

    fn modelChat(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        _: ChatRequest,
        model: []const u8,
        _: f64,
    ) anyerror!ChatResponse {
        const self: *ModelAwareMock = @ptrCast(@alignCast(ptr));
        self.call_count += 1;
        self.recordModel(model);
        if (self.failsModel(model)) {
            return error.ModelUnavailable;
        }
        return ChatResponse{ .content = try allocator.dupe(u8, self.response) };
    }

    fn modelSupportsNativeTools(ptr: *anyopaque) bool {
        const self: *ModelAwareMock = @ptrCast(@alignCast(ptr));
        return self.supports_tools;
    }

    fn modelSupportsVision(ptr: *anyopaque) bool {
        const self: *ModelAwareMock = @ptrCast(@alignCast(ptr));
        return self.supports_vision;
    }

    fn modelGetName(_: *anyopaque) []const u8 {
        return "ModelAwareMock";
    }

    fn modelDeinit(_: *anyopaque) void {}
};

const VisionByModelMock = struct {
    call_count: u32 = 0,
    vision_model: []const u8,

    const vtable = Provider.VTable{
        .chatWithSystem = chatWithSystem,
        .chat = chat,
        .supportsNativeTools = supportsNativeTools,
        .supports_vision = supportsVision,
        .supports_vision_for_model = supportsVisionForModel,
        .getName = getName,
        .deinit = deinit,
    };

    fn toProvider(self: *VisionByModelMock) Provider {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    fn chatWithSystem(
        ptr: *anyopaque,
        _: std.mem.Allocator,
        _: ?[]const u8,
        _: []const u8,
        _: []const u8,
        _: f64,
    ) anyerror![]const u8 {
        const self: *VisionByModelMock = @ptrCast(@alignCast(ptr));
        self.call_count += 1;
        return "vision by model";
    }

    fn chat(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        _: ChatRequest,
        _: []const u8,
        _: f64,
    ) anyerror!ChatResponse {
        const self: *VisionByModelMock = @ptrCast(@alignCast(ptr));
        self.call_count += 1;
        return ChatResponse{ .content = try allocator.dupe(u8, "vision by model") };
    }

    fn supportsNativeTools(_: *anyopaque) bool {
        return false;
    }

    fn supportsVision(_: *anyopaque) bool {
        return true;
    }

    fn supportsVisionForModel(ptr: *anyopaque, model: []const u8) bool {
        const self: *VisionByModelMock = @ptrCast(@alignCast(ptr));
        return std.mem.eql(u8, model, self.vision_model);
    }

    fn getName(_: *anyopaque) []const u8 {
        return "VisionByModelMock";
    }

    fn deinit(_: *anyopaque) void {}
};

test "ReliableProvider vtable succeeds without retry" {
    var mock = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = true };
    var reliable = ReliableProvider.initWithProvider(mock.toProvider(), 3, 50);
    const prov = reliable.provider();

    const result = try prov.chatWithSystem(std.testing.allocator, null, "hello", "test-model", 0.7);
    try std.testing.expectEqualStrings("mock response", result);
    try std.testing.expect(mock.call_count == 1);
}

test "ReliableProvider vtable retries then recovers" {
    var mock = MockInnerProvider{ .call_count = 0, .fail_until = 2, .supports_tools = false };
    var reliable = ReliableProvider.initWithProvider(mock.toProvider(), 3, 50);
    const prov = reliable.provider();

    const result = try prov.chatWithSystem(std.testing.allocator, "system", "hello", "model", 0.5);
    try std.testing.expectEqualStrings("mock response", result);
    // Should have been called 3 times: 2 failures + 1 success
    try std.testing.expect(mock.call_count == 3);
}

test "ReliableProvider vtable exhausts retries and returns error" {
    var mock = MockInnerProvider{ .call_count = 0, .fail_until = 100, .supports_tools = false };
    var reliable = ReliableProvider.initWithProvider(mock.toProvider(), 2, 50);
    const prov = reliable.provider();

    const result = prov.chatWithSystem(std.testing.allocator, null, "hello", "model", 0.5);
    try std.testing.expectError(error.AllProvidersFailed, result);
    // max_retries=2 means 3 attempts (0, 1, 2)
    try std.testing.expect(mock.call_count == 3);
}

test "ReliableProvider records fallback detail for non-classified errors" {
    root.clearLastApiErrorDetail();
    defer root.clearLastApiErrorDetail();

    var mock = MockInnerProvider{
        .call_count = 0,
        .fail_until = 100,
        .fail_error = error.ProviderError,
        .supports_tools = false,
    };
    var reliable = ReliableProvider.initWithProvider(mock.toProvider(), 0, 50);
    const prov = reliable.provider();

    const result = prov.chatWithSystem(std.testing.allocator, null, "hello", "model", 0.5);
    try std.testing.expectError(error.AllProvidersFailed, result);

    const detail = (try root.snapshotLastApiErrorDetail(std.testing.allocator)).?;
    defer std.testing.allocator.free(detail);
    try std.testing.expectEqualStrings("MockProvider: ProviderError", detail);
}

test "ReliableProvider propagates context errors for recovery" {
    var mock = MockInnerProvider{
        .call_count = 0,
        .fail_until = 100,
        .fail_error = error.ContextLengthExceeded,
        .supports_tools = false,
    };
    var reliable = ReliableProvider.initWithProvider(mock.toProvider(), 1, 50);
    const prov = reliable.provider();

    const result = prov.chatWithSystem(std.testing.allocator, null, "hello", "model", 0.5);
    try std.testing.expectError(error.ContextLengthExceeded, result);
}

test "ReliableProvider vtable chat retries then recovers" {
    var mock = MockInnerProvider{ .call_count = 0, .fail_until = 1, .supports_tools = true };
    var reliable = ReliableProvider.initWithProvider(mock.toProvider(), 2, 50);
    const prov = reliable.provider();

    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const request = ChatRequest{ .messages = &msgs };
    const result = try prov.chat(std.testing.allocator, request, "model", 0.5);
    defer if (result.content) |c| std.testing.allocator.free(c);
    defer if (result.provider.len > 0) std.testing.allocator.free(result.provider);
    defer if (result.model.len > 0) std.testing.allocator.free(result.model);
    try std.testing.expectEqualStrings("mock chat", result.content.?);
    try std.testing.expectEqualStrings("MockProvider", result.provider);
    try std.testing.expectEqualStrings("model", result.model);
    try std.testing.expect(mock.call_count == 2);
}

test "ReliableProvider vtable delegates supportsNativeTools" {
    var mock_yes = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = true };
    var reliable_yes = ReliableProvider.initWithProvider(mock_yes.toProvider(), 0, 50);
    try std.testing.expect(reliable_yes.provider().supportsNativeTools() == true);

    var mock_no = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false };
    var reliable_no = ReliableProvider.initWithProvider(mock_no.toProvider(), 0, 50);
    try std.testing.expect(reliable_no.provider().supportsNativeTools() == false);
}

test "ReliableProvider supportsVision checks full provider chain" {
    var inner = MockInnerProvider{
        .call_count = 0,
        .fail_until = 0,
        .supports_tools = false,
        .supports_vision = false,
    };
    var extra = MockInnerProvider{
        .call_count = 0,
        .fail_until = 0,
        .supports_tools = false,
        .supports_vision = true,
    };
    const extras = [_]ProviderEntry{
        .{ .name = "extra", .provider = extra.toProvider() },
    };

    var reliable = ReliableProvider.initWithProvider(inner.toProvider(), 0, 50).withExtras(&extras);
    const prov = reliable.provider();
    try std.testing.expect(prov.supportsVision());
    try std.testing.expect(prov.supportsVisionForModel("any-model"));
}

test "ReliableProvider vtable delegates getName" {
    var mock = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false };
    var reliable = ReliableProvider.initWithProvider(mock.toProvider(), 0, 50);
    try std.testing.expectEqualStrings("MockProvider", reliable.provider().getName());
}

test "ReliableProvider vtable zero retries fails immediately" {
    var mock = MockInnerProvider{ .call_count = 0, .fail_until = 100, .supports_tools = false };
    var reliable = ReliableProvider.initWithProvider(mock.toProvider(), 0, 50);
    const prov = reliable.provider();

    const result = prov.chatWithSystem(std.testing.allocator, null, "hello", "model", 0.5);
    try std.testing.expectError(error.AllProvidersFailed, result);
    // With 0 retries, only 1 attempt
    try std.testing.expect(mock.call_count == 1);
}

// ════════════════════════════════════════════════════════════════════════════
// New tests: model fallback chain
// ════════════════════════════════════════════════════════════════════════════

test "modelChain with no fallbacks returns single element" {
    const reliable = ReliableProvider.init(&.{}, 0, 50);
    const chain = try reliable.modelChain(std.testing.allocator, "claude-opus");
    defer std.testing.allocator.free(chain);

    try std.testing.expect(chain.len == 1);
    try std.testing.expectEqualStrings("claude-opus", chain[0]);
}

test "modelChain with fallbacks returns full chain" {
    const fallbacks = [_]ModelFallbackEntry{
        .{ .model = "claude-opus", .fallbacks = &.{ "claude-sonnet", "claude-haiku" } },
    };
    const reliable = ReliableProvider.init(&.{}, 0, 50).withModelFallbacks(&fallbacks);
    const chain = try reliable.modelChain(std.testing.allocator, "claude-opus");
    defer std.testing.allocator.free(chain);

    try std.testing.expect(chain.len == 3);
    try std.testing.expectEqualStrings("claude-opus", chain[0]);
    try std.testing.expectEqualStrings("claude-sonnet", chain[1]);
    try std.testing.expectEqualStrings("claude-haiku", chain[2]);
}

test "modelChain with unrelated model returns single element" {
    const fallbacks = [_]ModelFallbackEntry{
        .{ .model = "claude-opus", .fallbacks = &.{"claude-sonnet"} },
    };
    const reliable = ReliableProvider.init(&.{}, 0, 50).withModelFallbacks(&fallbacks);
    const chain = try reliable.modelChain(std.testing.allocator, "gpt-4");
    defer std.testing.allocator.free(chain);

    try std.testing.expect(chain.len == 1);
    try std.testing.expectEqualStrings("gpt-4", chain[0]);
}

test "withModelFallbacks builder preserves other fields" {
    const fallbacks = [_]ModelFallbackEntry{
        .{ .model = "m1", .fallbacks = &.{"m2"} },
    };
    const reliable = ReliableProvider.init(&.{}, 3, 200).withModelFallbacks(&fallbacks);
    try std.testing.expect(reliable.max_retries == 3);
    try std.testing.expect(reliable.base_backoff_ms == 200);
    try std.testing.expect(reliable.model_fallbacks.len == 1);
}

test "withExtras builder preserves other fields" {
    var mock = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false };
    const extras = [_]ProviderEntry{
        .{ .name = "fallback", .provider = mock.toProvider() },
    };
    var reliable = ReliableProvider.initWithProvider(mock.toProvider(), 2, 100).withExtras(&extras);
    try std.testing.expect(reliable.max_retries == 2);
    try std.testing.expect(reliable.base_backoff_ms == 100);
    try std.testing.expect(reliable.extras.len == 1);
    try std.testing.expectEqualStrings("fallback", reliable.extras[0].name);
    _ = &reliable;
}

test "warmup calls inner and extras" {
    var inner_mock = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false };
    var extra_mock = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false };

    const extras = [_]ProviderEntry{
        .{ .name = "extra", .provider = extra_mock.toProvider() },
    };
    var reliable = ReliableProvider.initWithProvider(inner_mock.toProvider(), 0, 50).withExtras(&extras);
    const prov = reliable.provider();
    prov.warmup();

    try std.testing.expect(inner_mock.warmed_up);
    try std.testing.expect(extra_mock.warmed_up);
}

test "multi-provider fallback: primary fails, extra succeeds" {
    var primary = MockInnerProvider{ .call_count = 0, .fail_until = 100, .supports_tools = false };
    var fallback = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = true };

    const extras = [_]ProviderEntry{
        .{ .name = "fallback", .provider = fallback.toProvider() },
    };
    var reliable = ReliableProvider.initWithProvider(primary.toProvider(), 0, 50).withExtras(&extras);
    const prov = reliable.provider();

    const result = try prov.chatWithSystem(std.testing.allocator, null, "hello", "model", 0.7);
    try std.testing.expectEqualStrings("mock response", result);
    // Primary tried once (0 retries), then fallback succeeded on first try
    try std.testing.expect(primary.call_count == 1);
    try std.testing.expect(fallback.call_count == 1);
}

test "model failover tries fallback model" {
    const fail_models = [_][]const u8{"claude-opus"};
    var mock = ModelAwareMock.initWithFailModels(&fail_models, "ok from sonnet");
    const fb = [_]ModelFallbackEntry{
        .{ .model = "claude-opus", .fallbacks = &.{"claude-sonnet"} },
    };
    var reliable = ReliableProvider.initWithProvider(mock.toProvider(), 0, 50).withModelFallbacks(&fb);
    const prov = reliable.provider();

    const result = try prov.chatWithSystem(std.testing.allocator, null, "hello", "claude-opus", 0.7);
    try std.testing.expectEqualStrings("ok from sonnet", result);

    const seen = mock.modelsSeen();
    try std.testing.expect(seen.len == 2);
    try std.testing.expectEqualStrings("claude-opus", seen[0]);
    try std.testing.expectEqualStrings("claude-sonnet", seen[1]);
}

test "model failover all models fail returns error" {
    const fail_models = [_][]const u8{ "model-a", "model-b", "model-c" };
    var mock = ModelAwareMock.initWithFailModels(&fail_models, "never");
    const fb = [_]ModelFallbackEntry{
        .{ .model = "model-a", .fallbacks = &.{ "model-b", "model-c" } },
    };
    var reliable = ReliableProvider.initWithProvider(mock.toProvider(), 0, 50).withModelFallbacks(&fb);
    const prov = reliable.provider();

    const result = prov.chatWithSystem(std.testing.allocator, null, "hello", "model-a", 0.7);
    try std.testing.expectError(error.AllProvidersFailed, result);

    const seen = mock.modelsSeen();
    try std.testing.expect(seen.len == 3);
}

test "supportsNativeTools returns true if any extra supports it" {
    var inner_mock = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false };
    var extra_mock = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = true };

    const extras = [_]ProviderEntry{
        .{ .name = "extra", .provider = extra_mock.toProvider() },
    };
    var reliable = ReliableProvider.initWithProvider(inner_mock.toProvider(), 0, 50).withExtras(&extras);
    try std.testing.expect(reliable.provider().supportsNativeTools() == true);
}

test "multi-provider chat fallback" {
    var primary = MockInnerProvider{ .call_count = 0, .fail_until = 100, .supports_tools = false };
    var fallback = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = true };

    const extras = [_]ProviderEntry{
        .{ .name = "fallback", .provider = fallback.toProvider() },
    };
    var reliable = ReliableProvider.initWithProvider(primary.toProvider(), 0, 50).withExtras(&extras);
    const prov = reliable.provider();

    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const request = ChatRequest{ .messages = &msgs };
    const result = try prov.chat(std.testing.allocator, request, "model", 0.5);
    defer if (result.content) |c| std.testing.allocator.free(c);
    defer if (result.provider.len > 0) std.testing.allocator.free(result.provider);
    defer if (result.model.len > 0) std.testing.allocator.free(result.model);
    try std.testing.expectEqualStrings("mock chat", result.content.?);
    try std.testing.expect(result.provider.len > 0);
    try std.testing.expectEqualStrings("model", result.model);
    try std.testing.expect(primary.call_count == 1);
    try std.testing.expect(fallback.call_count == 1);
}

// ════════════════════════════════════════════════════════════════════════════
// Vision routing tests
// ════════════════════════════════════════════════════════════════════════════

test "hasImageParts returns false with no content_parts" {
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const request = ChatRequest{ .messages = &msgs };
    try std.testing.expect(!hasImageParts(request));
}

test "hasImageParts returns false with text-only content_parts" {
    const parts = [_]root.ContentPart{.{ .text = "some text" }};
    const msgs = [_]root.ChatMessage{.{
        .role = .user,
        .content = "some text",
        .content_parts = &parts,
    }};
    const request = ChatRequest{ .messages = &msgs };
    try std.testing.expect(!hasImageParts(request));
}

test "hasImageParts returns true with image_url part" {
    const parts = [_]root.ContentPart{
        .{ .text = "look at this" },
        .{ .image_url = .{ .url = "https://example.com/cat.png" } },
    };
    const msgs = [_]root.ChatMessage{.{
        .role = .user,
        .content = "look at this",
        .content_parts = &parts,
    }};
    const request = ChatRequest{ .messages = &msgs };
    try std.testing.expect(hasImageParts(request));
}

test "hasImageParts returns true with image_base64 part" {
    const parts = [_]root.ContentPart{
        .{ .image_base64 = .{ .data = "abc123", .media_type = "image/png" } },
    };
    const msgs = [_]root.ChatMessage{.{
        .role = .user,
        .content = "",
        .content_parts = &parts,
    }};
    const request = ChatRequest{ .messages = &msgs };
    try std.testing.expect(hasImageParts(request));
}

test "chatImpl skips non-vision inner and routes image request to vision-capable extra" {
    var inner = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false, .supports_vision = false };
    var vision_extra = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false, .supports_vision = true };
    const extras = [_]ProviderEntry{
        .{ .name = "vision-extra", .provider = vision_extra.toProvider() },
    };
    var reliable = ReliableProvider.initWithProvider(inner.toProvider(), 0, 50).withExtras(&extras);
    const prov = reliable.provider();

    const parts = [_]root.ContentPart{.{ .image_base64 = .{ .data = "abc", .media_type = "image/png" } }};
    const msgs = [_]root.ChatMessage{.{ .role = .user, .content = "", .content_parts = &parts }};
    const request = ChatRequest{ .messages = &msgs };
    const result = try prov.chat(std.testing.allocator, request, "codex", 0.7);
    defer if (result.content) |c| std.testing.allocator.free(c);
    defer if (result.provider.len > 0) std.testing.allocator.free(result.provider);
    defer if (result.model.len > 0) std.testing.allocator.free(result.model);

    try std.testing.expect(inner.call_count == 0);
    try std.testing.expect(vision_extra.call_count == 1);
}

test "chatImpl non-image request routes to inner even if inner lacks vision" {
    var inner = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false, .supports_vision = false };
    var reliable = ReliableProvider.initWithProvider(inner.toProvider(), 0, 50);
    const prov = reliable.provider();

    const msgs = [_]root.ChatMessage{root.ChatMessage.user("plain text, no image")};
    const request = ChatRequest{ .messages = &msgs };
    const result = try prov.chat(std.testing.allocator, request, "codex", 0.7);
    defer if (result.content) |c| std.testing.allocator.free(c);
    defer if (result.provider.len > 0) std.testing.allocator.free(result.provider);
    defer if (result.model.len > 0) std.testing.allocator.free(result.model);

    try std.testing.expect(inner.call_count == 1);
}

test "chatImpl returns ProviderDoesNotSupportVision when all providers lack vision" {
    var inner = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false, .supports_vision = false };
    var extra = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false, .supports_vision = false };
    const extras = [_]ProviderEntry{.{ .name = "also-no-vision", .provider = extra.toProvider() }};
    var reliable = ReliableProvider.initWithProvider(inner.toProvider(), 0, 50).withExtras(&extras);
    const prov = reliable.provider();

    const parts = [_]root.ContentPart{.{ .image_url = .{ .url = "https://example.com/img.png" } }};
    const msgs = [_]root.ChatMessage{.{ .role = .user, .content = "", .content_parts = &parts }};
    const request = ChatRequest{ .messages = &msgs };

    try std.testing.expectError(error.ProviderDoesNotSupportVision, prov.chat(std.testing.allocator, request, "codex", 0.7));
    try std.testing.expect(inner.call_count == 0);
    try std.testing.expect(extra.call_count == 0);
}

test "chatImpl returns ProviderDoesNotSupportVision when vision exists only for other models" {
    var inner = VisionByModelMock{ .vision_model = "vision-model" };
    var reliable = ReliableProvider.initWithProvider(inner.toProvider(), 0, 50);
    const prov = reliable.provider();

    const parts = [_]root.ContentPart{.{ .image_base64 = .{ .data = "abc", .media_type = "image/png" } }};
    const msgs = [_]root.ChatMessage{.{ .role = .user, .content = "", .content_parts = &parts }};
    const request = ChatRequest{ .messages = &msgs };

    try std.testing.expectError(
        error.ProviderDoesNotSupportVision,
        prov.chat(std.testing.allocator, request, "text-model", 0.7),
    );
    try std.testing.expect(inner.call_count == 0);
}

test "streamChatImpl routes image request to vision-capable extra, skips inner" {
    var inner = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false, .supports_vision = false };
    var vision_extra = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false, .supports_vision = true };
    const extras = [_]ProviderEntry{.{ .name = "vision-extra", .provider = vision_extra.toProvider() }};
    var reliable = ReliableProvider.initWithProvider(inner.toProvider(), 0, 50).withExtras(&extras);
    const prov = reliable.provider();

    const parts = [_]root.ContentPart{.{ .image_url = .{ .url = "https://example.com/img.png" } }};
    const msgs = [_]root.ChatMessage{.{ .role = .user, .content = "", .content_parts = &parts }};
    const request = ChatRequest{ .messages = &msgs };

    const NoopCtx = struct {
        fn cb(_: *anyopaque, _: root.StreamChunk) void {}
    };
    var dummy: u8 = 0;
    const sr = try prov.streamChat(std.testing.allocator, request, "codex", 0.7, NoopCtx.cb, &dummy);
    defer if (sr.content) |c| std.testing.allocator.free(c);
    defer if (sr.model.len > 0) std.testing.allocator.free(sr.model);

    try std.testing.expect(inner.call_count == 0);
    try std.testing.expect(vision_extra.call_count == 1);
}

test "streamChatImpl returns ProviderDoesNotSupportVision when all providers lack vision" {
    var inner = MockInnerProvider{ .call_count = 0, .fail_until = 0, .supports_tools = false, .supports_vision = false };
    var reliable = ReliableProvider.initWithProvider(inner.toProvider(), 0, 50);
    const prov = reliable.provider();

    const parts = [_]root.ContentPart{.{ .image_base64 = .{ .data = "abc", .media_type = "image/png" } }};
    const msgs = [_]root.ChatMessage{.{ .role = .user, .content = "", .content_parts = &parts }};
    const request = ChatRequest{ .messages = &msgs };

    const NoopCtx = struct {
        fn cb(_: *anyopaque, _: root.StreamChunk) void {}
    };
    var dummy: u8 = 0;
    try std.testing.expectError(
        error.ProviderDoesNotSupportVision,
        prov.streamChat(std.testing.allocator, request, "codex", 0.7, NoopCtx.cb, &dummy),
    );
    try std.testing.expect(inner.call_count == 0);
}
