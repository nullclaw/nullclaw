const std = @import("std");
const root = @import("root.zig");
const gemini = @import("gemini.zig");
const config_types = @import("../config_types.zig");
const platform = @import("../platform.zig");

const Provider = root.Provider;
const ChatRequest = root.ChatRequest;
const ChatResponse = root.ChatResponse;

const ServiceAccountCredentials = struct {
    project_id: []const u8,
    client_email: []const u8,
    private_key: []const u8,
    token_uri: []const u8,

    fn deinit(self: ServiceAccountCredentials, allocator: std.mem.Allocator) void {
        allocator.free(self.project_id);
        allocator.free(self.client_email);
        allocator.free(self.private_key);
        allocator.free(self.token_uri);
    }
};

/// Authentication method for Vertex AI.
pub const VertexAuth = union(enum) {
    /// Token from config models.providers.vertex.api_key.
    explicit_token: []const u8,
    /// Service account JSON from config models.providers.vertex.api_key.
    explicit_service_account: ServiceAccountCredentials,
    /// Token from VERTEX_API_KEY env var.
    env_vertex_api_key: []const u8,
    /// Service account JSON from VERTEX_API_KEY env var.
    env_vertex_api_key_service_account: ServiceAccountCredentials,
    /// Token from VERTEX_OAUTH_TOKEN env var.
    env_vertex_oauth_token: []const u8,
    /// Token from GOOGLE_OAUTH_ACCESS_TOKEN env var.
    env_google_oauth_access_token: []const u8,

    pub fn source(self: VertexAuth) []const u8 {
        return switch (self) {
            .explicit_token => "config",
            .explicit_service_account => "config service account JSON",
            .env_vertex_api_key => "VERTEX_API_KEY env var",
            .env_vertex_api_key_service_account => "VERTEX_API_KEY env var (service account JSON)",
            .env_vertex_oauth_token => "VERTEX_OAUTH_TOKEN env var",
            .env_google_oauth_access_token => "GOOGLE_OAUTH_ACCESS_TOKEN env var",
        };
    }
};

const VertexBase = union(enum) {
    /// models.providers.vertex.base_url (unowned)
    config: []const u8,
    /// VERTEX_BASE_URL (owned)
    env: []const u8,
    /// Built from VERTEX_PROJECT_ID + VERTEX_LOCATION (owned)
    derived: []const u8,

    pub fn value(self: VertexBase) []const u8 {
        return switch (self) {
            .config => |v| v,
            .env => |v| v,
            .derived => |v| v,
        };
    }

    pub fn source(self: VertexBase) []const u8 {
        return switch (self) {
            .config => "base_url config",
            .env => "VERTEX_BASE_URL env var",
            .derived => "derived project/location",
        };
    }
};

/// Vertex AI Gemini provider.
///
/// Endpoint resolution order:
/// 1. models.providers.vertex.base_url
/// 2. VERTEX_BASE_URL
/// 3. Build from VERTEX_PROJECT_ID (+ optional VERTEX_LOCATION, default: global)
/// 4. Build from service-account `project_id` (+ optional VERTEX_LOCATION, default: global)
pub const VertexProvider = struct {
    auth: ?VertexAuth,
    base: ?VertexBase,
    cached_service_account_token: ?[]u8 = null,
    cached_service_account_expiry: i64 = 0,
    allocator: std.mem.Allocator,

    const DEFAULT_MAX_OUTPUT_TOKENS: u32 = config_types.DEFAULT_MODEL_MAX_TOKENS;
    const DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";
    const OAUTH_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
    const SERVICE_ACCOUNT_TOKEN_REFRESH_SAFETY_SECONDS: i64 = 120;
    const SERVICE_ACCOUNT_JWT_TTL_SECONDS: i64 = 3600;
    const SERVICE_ACCOUNT_TOKEN_TIMEOUT_SECS: u64 = 20;

    pub fn init(allocator: std.mem.Allocator, api_key: ?[]const u8, base_url: ?[]const u8) VertexProvider {
        const auth = resolveAuth(allocator, api_key);
        var base = resolveBase(allocator, base_url);

        if (base == null) {
            if (auth) |resolved_auth| {
                if (serviceAccountProjectId(resolved_auth)) |project_id| {
                    const location_owned = loadNonEmptyEnv(allocator, "VERTEX_LOCATION");
                    defer if (location_owned) |loc| allocator.free(loc);
                    const location = if (location_owned) |loc| loc else "global";

                    const built = buildDefaultBase(allocator, project_id, location) catch null;
                    if (built) |url| {
                        base = .{ .derived = url };
                    }
                }
            }
        }

        return .{
            .auth = auth,
            .base = base,
            .allocator = allocator,
        };
    }

    fn resolveAuth(allocator: std.mem.Allocator, api_key: ?[]const u8) ?VertexAuth {
        if (api_key) |key| {
            const trimmed = std.mem.trim(u8, key, " \t\r\n");
            if (trimmed.len > 0) {
                if (parseServiceAccountCredentials(allocator, trimmed)) |creds| {
                    return .{ .explicit_service_account = creds };
                }
                return .{ .explicit_token = trimmed };
            }
        }

        if (loadNonEmptyEnv(allocator, "VERTEX_API_KEY")) |value| {
            defer allocator.free(value);
            if (parseServiceAccountCredentials(allocator, value)) |creds| {
                return .{ .env_vertex_api_key_service_account = creds };
            }
            const owned = allocator.dupe(u8, value) catch return null;
            return .{ .env_vertex_api_key = owned };
        }
        if (loadNonEmptyEnv(allocator, "VERTEX_OAUTH_TOKEN")) |value| {
            return .{ .env_vertex_oauth_token = value };
        }
        if (loadNonEmptyEnv(allocator, "GOOGLE_OAUTH_ACCESS_TOKEN")) |value| {
            return .{ .env_google_oauth_access_token = value };
        }

        return null;
    }

    fn resolveBase(allocator: std.mem.Allocator, base_url: ?[]const u8) ?VertexBase {
        if (base_url) |raw| {
            const trimmed = std.mem.trim(u8, raw, " \t\r\n");
            if (trimmed.len > 0) {
                return .{ .config = trimmed };
            }
        }

        if (loadNonEmptyEnv(allocator, "VERTEX_BASE_URL")) |env_base| {
            return .{ .env = env_base };
        }

        const project = loadNonEmptyEnv(allocator, "VERTEX_PROJECT_ID") orelse return null;
        defer allocator.free(project);

        const location_owned = loadNonEmptyEnv(allocator, "VERTEX_LOCATION");
        defer if (location_owned) |loc| allocator.free(loc);
        const location = if (location_owned) |loc| loc else "global";

        const built = buildDefaultBase(allocator, project, location) catch return null;
        return .{ .derived = built };
    }

    fn buildDefaultBase(allocator: std.mem.Allocator, project_id: []const u8, location: []const u8) ![]u8 {
        var host_owned: ?[]u8 = null;
        defer if (host_owned) |h| allocator.free(h);

        const host: []const u8 = if (std.mem.eql(u8, location, "global"))
            "https://aiplatform.googleapis.com"
        else blk: {
            const h = try std.fmt.allocPrint(allocator, "https://{s}-aiplatform.googleapis.com", .{location});
            host_owned = h;
            break :blk h;
        };

        return std.fmt.allocPrint(
            allocator,
            "{s}/v1/projects/{s}/locations/{s}/publishers/google/models",
            .{ host, project_id, location },
        );
    }

    fn loadNonEmptyEnv(allocator: std.mem.Allocator, name: []const u8) ?[]u8 {
        if (std.process.getEnvVarOwned(allocator, name)) |value| {
            defer allocator.free(value);
            const trimmed = std.mem.trim(u8, value, " \t\r\n");
            if (trimmed.len > 0) {
                return allocator.dupe(u8, trimmed) catch null;
            }
            return null;
        } else |_| {
            return null;
        }
    }

    fn serviceAccountProjectId(auth: VertexAuth) ?[]const u8 {
        return switch (auth) {
            .explicit_service_account => |creds| creds.project_id,
            .env_vertex_api_key_service_account => |creds| creds.project_id,
            else => null,
        };
    }

    fn buildAuthHeader(self: *VertexProvider, allocator: std.mem.Allocator) ![]u8 {
        const token = try self.resolveBearerToken(allocator);
        return std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{token});
    }

    fn resolveBearerToken(self: *VertexProvider, allocator: std.mem.Allocator) ![]const u8 {
        const auth = self.auth orelse return error.CredentialsNotSet;
        return switch (auth) {
            .explicit_token => |token| token,
            .env_vertex_api_key => |token| token,
            .env_vertex_oauth_token => |token| token,
            .env_google_oauth_access_token => |token| token,
            .explicit_service_account => |creds| try self.serviceAccountAccessToken(allocator, creds),
            .env_vertex_api_key_service_account => |creds| try self.serviceAccountAccessToken(allocator, creds),
        };
    }

    fn serviceAccountAccessToken(
        self: *VertexProvider,
        allocator: std.mem.Allocator,
        creds: ServiceAccountCredentials,
    ) ![]const u8 {
        const now = std.time.timestamp();
        if (self.cached_service_account_token) |token| {
            if (self.cached_service_account_expiry == 0 or
                now + SERVICE_ACCOUNT_TOKEN_REFRESH_SAFETY_SECONDS < self.cached_service_account_expiry)
            {
                return token;
            }
        }

        const refreshed = try requestServiceAccountAccessToken(allocator, creds);
        defer allocator.free(refreshed.access_token);

        if (self.cached_service_account_token) |old| {
            self.allocator.free(old);
            self.cached_service_account_token = null;
        }

        self.cached_service_account_token = try self.allocator.dupe(u8, refreshed.access_token);
        const expires_in = if (refreshed.expires_in > 0) refreshed.expires_in else SERVICE_ACCOUNT_JWT_TTL_SECONDS;
        self.cached_service_account_expiry = std.time.timestamp() + expires_in;
        return self.cached_service_account_token.?;
    }

    pub fn authSource(self: VertexProvider) []const u8 {
        if (self.auth) |auth| return auth.source();
        return "none";
    }

    pub fn endpointSource(self: VertexProvider) []const u8 {
        if (self.base) |b| return b.source();
        return "none";
    }

    pub fn provider(self: *VertexProvider) Provider {
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
        .supports_streaming = supportsStreamingImpl,
        .stream_chat = streamChatImpl,
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
        const self: *VertexProvider = @ptrCast(@alignCast(ptr));
        _ = self.auth orelse return error.CredentialsNotSet;
        const base = self.base orelse return error.VertexBaseUrlNotSet;

        const url = try buildGenerateUrl(allocator, base.value(), model);
        defer allocator.free(url);

        const body = try buildSimpleRequestBody(allocator, system_prompt, message, temperature);
        defer allocator.free(body);

        const auth_hdr = try self.buildAuthHeader(allocator);
        defer allocator.free(auth_hdr);

        const resp_body = root.curlPostTimed(allocator, url, body, &.{auth_hdr}, 0) catch return error.VertexApiError;
        defer allocator.free(resp_body);

        return gemini.GeminiProvider.parseResponse(allocator, resp_body);
    }

    fn chatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
    ) anyerror!ChatResponse {
        const self: *VertexProvider = @ptrCast(@alignCast(ptr));
        _ = self.auth orelse return error.CredentialsNotSet;
        const base = self.base orelse return error.VertexBaseUrlNotSet;

        const url = try buildGenerateUrl(allocator, base.value(), model);
        defer allocator.free(url);

        const body = try buildChatRequestBody(allocator, request, model, temperature);
        defer allocator.free(body);

        const auth_hdr = try self.buildAuthHeader(allocator);
        defer allocator.free(auth_hdr);

        const resp_body = root.curlPostTimed(allocator, url, body, &.{auth_hdr}, request.timeout_secs) catch return error.VertexApiError;
        defer allocator.free(resp_body);

        return try gemini.GeminiProvider.parseChatResponse(allocator, resp_body);
    }

    fn streamChatImpl(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: ChatRequest,
        model: []const u8,
        temperature: f64,
        callback: root.StreamCallback,
        callback_ctx: *anyopaque,
    ) anyerror!root.StreamChatResult {
        const self: *VertexProvider = @ptrCast(@alignCast(ptr));
        _ = self.auth orelse return error.CredentialsNotSet;
        const base = self.base orelse return error.VertexBaseUrlNotSet;

        const url = try buildStreamUrl(allocator, base.value(), model);
        defer allocator.free(url);

        const body = try buildChatRequestBody(allocator, request, model, temperature);
        defer allocator.free(body);

        const auth_hdr = try self.buildAuthHeader(allocator);
        defer allocator.free(auth_hdr);
        const headers = [_][]const u8{auth_hdr};

        return gemini.GeminiProvider.curlStreamGemini(
            allocator,
            url,
            body,
            &headers,
            request.timeout_secs,
            callback,
            callback_ctx,
        );
    }

    fn supportsNativeToolsImpl(_: *anyopaque) bool {
        return false;
    }

    fn supportsVisionImpl(_: *anyopaque) bool {
        return true;
    }

    fn supportsStreamingImpl(_: *anyopaque) bool {
        return true;
    }

    fn getNameImpl(_: *anyopaque) []const u8 {
        return "Vertex";
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *VertexProvider = @ptrCast(@alignCast(ptr));

        if (self.auth) |auth| {
            switch (auth) {
                .explicit_service_account => |creds| creds.deinit(self.allocator),
                .env_vertex_api_key => |token| self.allocator.free(token),
                .env_vertex_api_key_service_account => |creds| creds.deinit(self.allocator),
                .env_vertex_oauth_token => |token| self.allocator.free(token),
                .env_google_oauth_access_token => |token| self.allocator.free(token),
                else => {},
            }
        }

        if (self.base) |base| {
            switch (base) {
                .env => |url| self.allocator.free(url),
                .derived => |url| self.allocator.free(url),
                else => {},
            }
        }

        if (self.cached_service_account_token) |token| {
            self.allocator.free(token);
        }

        self.auth = null;
        self.base = null;
        self.cached_service_account_token = null;
        self.cached_service_account_expiry = 0;
    }
};

const ServiceAccountAccessToken = struct {
    access_token: []u8,
    expires_in: i64,
};

fn jsonNonEmptyString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    return switch (value) {
        .string => |s| if (s.len > 0) s else null,
        else => null,
    };
}

fn parseExpiresIn(v: std.json.Value) ?i64 {
    return switch (v) {
        .integer => |i| if (i > 0) i else null,
        .float => |f| blk: {
            if (!std.math.isFinite(f) or f <= 0) break :blk null;
            if (f > @as(f64, @floatFromInt(std.math.maxInt(i64)))) break :blk null;
            break :blk @intFromFloat(f);
        },
        else => null,
    };
}

fn parseServiceAccountCredentials(allocator: std.mem.Allocator, raw: []const u8) ?ServiceAccountCredentials {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return null;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return null,
    };

    const project_id_raw = jsonNonEmptyString(obj, "project_id") orelse return null;
    const client_email_raw = jsonNonEmptyString(obj, "client_email") orelse return null;
    const private_key_raw = jsonNonEmptyString(obj, "private_key") orelse return null;
    const token_uri_raw = jsonNonEmptyString(obj, "token_uri") orelse VertexProvider.DEFAULT_TOKEN_URI;
    if (!std.mem.startsWith(u8, token_uri_raw, "https://")) return null;

    const project_id = allocator.dupe(u8, project_id_raw) catch return null;
    errdefer allocator.free(project_id);
    const client_email = allocator.dupe(u8, client_email_raw) catch return null;
    errdefer allocator.free(client_email);
    const private_key = allocator.dupe(u8, private_key_raw) catch return null;
    errdefer allocator.free(private_key);
    const token_uri = allocator.dupe(u8, token_uri_raw) catch return null;

    return .{
        .project_id = project_id,
        .client_email = client_email,
        .private_key = private_key,
        .token_uri = token_uri,
    };
}

fn base64UrlEncodeAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const Encoder = std.base64.url_safe_no_pad.Encoder;
    const out_len = Encoder.calcSize(input.len);
    const out = try allocator.alloc(u8, out_len);
    _ = Encoder.encode(out, input);
    return out;
}

fn appendServiceAccountJwtClaimPayload(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    creds: ServiceAccountCredentials,
    now: i64,
) !void {
    var iat_buf: [32]u8 = undefined;
    const iat_str = std.fmt.bufPrint(&iat_buf, "{d}", .{now}) catch return error.VertexApiError;
    var exp_buf: [32]u8 = undefined;
    const exp_str = std.fmt.bufPrint(&exp_buf, "{d}", .{now + VertexProvider.SERVICE_ACCOUNT_JWT_TTL_SECONDS}) catch return error.VertexApiError;

    try buf.appendSlice(allocator, "{\"iss\":");
    try root.appendJsonString(buf, allocator, creds.client_email);
    try buf.appendSlice(allocator, ",\"scope\":");
    try root.appendJsonString(buf, allocator, VertexProvider.OAUTH_SCOPE);
    try buf.appendSlice(allocator, ",\"aud\":");
    try root.appendJsonString(buf, allocator, creds.token_uri);
    try buf.appendSlice(allocator, ",\"exp\":");
    try buf.appendSlice(allocator, exp_str);
    try buf.appendSlice(allocator, ",\"iat\":");
    try buf.appendSlice(allocator, iat_str);
    try buf.append(allocator, '}');
}

fn signRsaSha256WithOpenSsl(
    allocator: std.mem.Allocator,
    private_key_pem: []const u8,
    message: []const u8,
) ![]u8 {
    const temp_dir = try platform.getTempDir(allocator);
    defer allocator.free(temp_dir);

    const filename = try std.fmt.allocPrint(allocator, "nullclaw-vertex-sa-{x}.pem", .{std.crypto.random.int(u64)});
    defer allocator.free(filename);

    const key_path = try std.fs.path.join(allocator, &.{ temp_dir, filename });
    defer allocator.free(key_path);
    defer std.fs.deleteFileAbsolute(key_path) catch {};

    var key_file = std.fs.createFileAbsolute(key_path, .{ .mode = 0o600 }) catch return error.VertexApiError;
    key_file.writeAll(private_key_pem) catch {
        key_file.close();
        return error.VertexApiError;
    };
    key_file.close();

    var child = std.process.Child.init(
        &[_][]const u8{ "openssl", "dgst", "-sha256", "-sign", key_path, "-binary" },
        allocator,
    );
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    child.spawn() catch |err| {
        if (err == error.FileNotFound) return error.OpenSslNotFound;
        return error.VertexApiError;
    };
    var waited = false;
    errdefer if (!waited) {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
    };

    if (child.stdin) |stdin_file| {
        stdin_file.writeAll(message) catch return error.VertexApiError;
        stdin_file.close();
        child.stdin = null;
    } else {
        return error.VertexApiError;
    }

    const signature = child.stdout.?.readToEndAlloc(allocator, 16 * 1024) catch return error.VertexApiError;
    errdefer allocator.free(signature);
    const stderr_text = child.stderr.?.readToEndAlloc(allocator, 8 * 1024) catch return error.VertexApiError;
    defer allocator.free(stderr_text);

    const term = child.wait() catch return error.VertexApiError;
    waited = true;
    switch (term) {
        .Exited => |code| {
            if (code != 0 or signature.len == 0) return error.VertexApiError;
        },
        else => return error.VertexApiError,
    }

    return signature;
}

fn buildServiceAccountAssertion(allocator: std.mem.Allocator, creds: ServiceAccountCredentials) ![]u8 {
    const header_json = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    const now = std.time.timestamp();

    var payload_json: std.ArrayListUnmanaged(u8) = .empty;
    defer payload_json.deinit(allocator);
    try appendServiceAccountJwtClaimPayload(&payload_json, allocator, creds, now);

    const header_b64 = try base64UrlEncodeAlloc(allocator, header_json);
    defer allocator.free(header_b64);
    const payload_b64 = try base64UrlEncodeAlloc(allocator, payload_json.items);
    defer allocator.free(payload_b64);

    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_b64, payload_b64 });
    defer allocator.free(signing_input);

    const signature = try signRsaSha256WithOpenSsl(allocator, creds.private_key, signing_input);
    defer allocator.free(signature);

    const signature_b64 = try base64UrlEncodeAlloc(allocator, signature);
    defer allocator.free(signature_b64);

    return std.fmt.allocPrint(allocator, "{s}.{s}", .{ signing_input, signature_b64 });
}

fn isFormUrlencodedUnreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
}

fn appendFormUrlencodedValue(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    value: []const u8,
) !void {
    const HEX = "0123456789ABCDEF";
    for (value) |c| {
        if (isFormUrlencodedUnreserved(c)) {
            try buf.append(allocator, c);
        } else if (c == ' ') {
            try buf.append(allocator, '+');
        } else {
            try buf.append(allocator, '%');
            try buf.append(allocator, HEX[(c >> 4) & 0x0F]);
            try buf.append(allocator, HEX[c & 0x0F]);
        }
    }
}

fn appendFormField(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    key: []const u8,
    value: []const u8,
) !void {
    if (buf.items.len > 0) try buf.append(allocator, '&');
    try appendFormUrlencodedValue(buf, allocator, key);
    try buf.append(allocator, '=');
    try appendFormUrlencodedValue(buf, allocator, value);
}

fn parseServiceAccountAccessTokenResponse(
    allocator: std.mem.Allocator,
    response_body: []const u8,
) ?ServiceAccountAccessToken {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, response_body, .{}) catch return null;
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return null,
    };

    if (obj.get("error")) |_| return null;
    const token_raw = jsonNonEmptyString(obj, "access_token") orelse return null;
    const expires_in = if (obj.get("expires_in")) |v| parseExpiresIn(v) orelse VertexProvider.SERVICE_ACCOUNT_JWT_TTL_SECONDS else VertexProvider.SERVICE_ACCOUNT_JWT_TTL_SECONDS;

    return .{
        .access_token = allocator.dupe(u8, token_raw) catch return null,
        .expires_in = expires_in,
    };
}

fn requestServiceAccountAccessToken(
    allocator: std.mem.Allocator,
    creds: ServiceAccountCredentials,
) !ServiceAccountAccessToken {
    if (@import("builtin").is_test) {
        return .{
            .access_token = try allocator.dupe(u8, "test-vertex-service-account-token"),
            .expires_in = VertexProvider.SERVICE_ACCOUNT_JWT_TTL_SECONDS,
        };
    }

    const assertion = try buildServiceAccountAssertion(allocator, creds);
    defer allocator.free(assertion);

    var form: std.ArrayListUnmanaged(u8) = .empty;
    defer form.deinit(allocator);
    try appendFormField(&form, allocator, "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
    try appendFormField(&form, allocator, "assertion", assertion);

    const response = root.curlPostFormTimed(
        allocator,
        creds.token_uri,
        form.items,
        VertexProvider.SERVICE_ACCOUNT_TOKEN_TIMEOUT_SECS,
    ) catch return error.VertexApiError;
    defer allocator.free(response);

    return parseServiceAccountAccessTokenResponse(allocator, response) orelse return error.VertexApiError;
}

fn trimTrailingSlash(url: []const u8) []const u8 {
    return std.mem.trimRight(u8, url, "/");
}

fn normalizeModelName(model: []const u8) []const u8 {
    if (std.mem.startsWith(u8, model, "models/")) {
        return model["models/".len..];
    }

    const publisher_prefix = "publishers/google/models/";
    if (std.mem.startsWith(u8, model, publisher_prefix)) {
        return model[publisher_prefix.len..];
    }

    const resource_marker = "/publishers/google/models/";
    if (std.mem.indexOf(u8, model, resource_marker)) |idx| {
        return model[idx + resource_marker.len ..];
    }

    return model;
}

pub fn buildGenerateUrl(allocator: std.mem.Allocator, base: []const u8, model: []const u8) ![]u8 {
    const root_url = trimTrailingSlash(base);
    const model_name = normalizeModelName(model);
    return std.fmt.allocPrint(allocator, "{s}/{s}:generateContent", .{ root_url, model_name });
}

pub fn buildStreamUrl(allocator: std.mem.Allocator, base: []const u8, model: []const u8) ![]u8 {
    const root_url = trimTrailingSlash(base);
    const model_name = normalizeModelName(model);
    return std.fmt.allocPrint(allocator, "{s}/{s}:streamGenerateContent?alt=sse", .{ root_url, model_name });
}

pub fn buildSimpleRequestBody(
    allocator: std.mem.Allocator,
    system_prompt: ?[]const u8,
    message: []const u8,
    temperature: f64,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":");
    try root.appendJsonString(&buf, allocator, message);
    try buf.appendSlice(allocator, "}]}]");

    if (system_prompt) |sys| {
        try buf.appendSlice(allocator, ",\"system_instruction\":{\"parts\":[{\"text\":");
        try root.appendJsonString(&buf, allocator, sys);
        try buf.appendSlice(allocator, "}]}");
    }

    try buf.appendSlice(allocator, ",\"generationConfig\":{\"temperature\":");

    var temp_buf: [16]u8 = undefined;
    const temp_str = std.fmt.bufPrint(&temp_buf, "{d:.2}", .{temperature}) catch return error.VertexApiError;
    try buf.appendSlice(allocator, temp_str);
    try buf.appendSlice(allocator, ",\"maxOutputTokens\":");

    var max_buf: [16]u8 = undefined;
    const max_str = std.fmt.bufPrint(&max_buf, "{d}", .{VertexProvider.DEFAULT_MAX_OUTPUT_TOKENS}) catch return error.VertexApiError;
    try buf.appendSlice(allocator, max_str);
    try buf.appendSlice(allocator, "}}");

    return try buf.toOwnedSlice(allocator);
}

fn buildChatRequestBody(
    allocator: std.mem.Allocator,
    request: ChatRequest,
    model: []const u8,
    temperature: f64,
) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    var system_prompt: ?[]const u8 = null;
    for (request.messages) |msg| {
        if (msg.role == .system) {
            system_prompt = msg.content;
            break;
        }
    }

    try buf.appendSlice(allocator, "{\"contents\":[");
    var count: usize = 0;

    for (request.messages) |msg| {
        if (msg.role == .system) continue;
        if (count > 0) try buf.append(allocator, ',');
        count += 1;

        const role_str: []const u8 = switch (msg.role) {
            .user, .tool => "user",
            .assistant => "model",
            .system => unreachable,
        };

        try buf.appendSlice(allocator, "{\"role\":\"");
        try buf.appendSlice(allocator, role_str);
        try buf.appendSlice(allocator, "\",\"parts\":[");

        if (msg.content_parts) |parts| {
            for (parts, 0..) |part, j| {
                if (j > 0) try buf.append(allocator, ',');
                switch (part) {
                    .text => |text| {
                        try buf.appendSlice(allocator, "{\"text\":");
                        try root.appendJsonString(&buf, allocator, text);
                        try buf.append(allocator, '}');
                    },
                    .image_base64 => |img| {
                        try buf.appendSlice(allocator, "{\"inlineData\":{\"mimeType\":");
                        try root.appendJsonString(&buf, allocator, img.media_type);
                        try buf.appendSlice(allocator, ",\"data\":\"");
                        try buf.appendSlice(allocator, img.data);
                        try buf.appendSlice(allocator, "\"}}");
                    },
                    .image_url => |img| {
                        try buf.appendSlice(allocator, "{\"text\":");
                        var text_buf: std.ArrayListUnmanaged(u8) = .empty;
                        defer text_buf.deinit(allocator);
                        try text_buf.appendSlice(allocator, "[Image: ");
                        try text_buf.appendSlice(allocator, img.url);
                        try text_buf.appendSlice(allocator, "]");
                        try root.appendJsonString(&buf, allocator, text_buf.items);
                        try buf.append(allocator, '}');
                    },
                }
            }
        } else {
            try buf.appendSlice(allocator, "{\"text\":");
            try root.appendJsonString(&buf, allocator, msg.content);
            try buf.append(allocator, '}');
        }

        try buf.appendSlice(allocator, "]}");
    }

    try buf.append(allocator, ']');

    if (system_prompt) |sys| {
        try buf.appendSlice(allocator, ",\"system_instruction\":{\"parts\":[{\"text\":");
        try root.appendJsonString(&buf, allocator, sys);
        try buf.appendSlice(allocator, "}]}");
    }

    try buf.appendSlice(allocator, ",\"generationConfig\":{\"temperature\":");
    var temp_buf: [16]u8 = undefined;
    const temp_str = std.fmt.bufPrint(&temp_buf, "{d:.2}", .{temperature}) catch return error.VertexApiError;
    try buf.appendSlice(allocator, temp_str);
    try buf.appendSlice(allocator, ",\"maxOutputTokens\":");

    const max_output_tokens = request.max_tokens orelse VertexProvider.DEFAULT_MAX_OUTPUT_TOKENS;
    var max_buf: [16]u8 = undefined;
    const max_str = std.fmt.bufPrint(&max_buf, "{d}", .{max_output_tokens}) catch return error.VertexApiError;
    try buf.appendSlice(allocator, max_str);
    try root.appendVertexThinkingConfig(&buf, allocator, model, request.reasoning_effort);
    try buf.appendSlice(allocator, "}}");

    return try buf.toOwnedSlice(allocator);
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "buildGenerateUrl normalizes model forms" {
    const alloc = std.testing.allocator;
    const base = "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/google/models/";

    const url1 = try buildGenerateUrl(alloc, base, "gemini-2.5-pro");
    defer alloc.free(url1);
    try std.testing.expectEqualStrings(
        "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/google/models/gemini-2.5-pro:generateContent",
        url1,
    );

    const url2 = try buildGenerateUrl(alloc, base, "models/gemini-2.5-flash");
    defer alloc.free(url2);
    try std.testing.expect(std.mem.indexOf(u8, url2, "models/gemini-2.5-flash:generateContent") != null);

    const url3 = try buildGenerateUrl(alloc, base, "publishers/google/models/gemini-2.0-flash");
    defer alloc.free(url3);
    try std.testing.expect(std.mem.indexOf(u8, url3, "models/gemini-2.0-flash:generateContent") != null);
}

test "buildStreamUrl appends alt=sse" {
    const alloc = std.testing.allocator;
    const base = "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/google/models";
    const url = try buildStreamUrl(alloc, base, "gemini-2.5-pro");
    defer alloc.free(url);
    try std.testing.expect(std.mem.endsWith(u8, url, ":streamGenerateContent?alt=sse"));
}

test "buildDefaultBase global endpoint" {
    const alloc = std.testing.allocator;
    const base = try VertexProvider.buildDefaultBase(alloc, "proj-1", "global");
    defer alloc.free(base);
    try std.testing.expectEqualStrings(
        "https://aiplatform.googleapis.com/v1/projects/proj-1/locations/global/publishers/google/models",
        base,
    );
}

test "buildDefaultBase regional endpoint" {
    const alloc = std.testing.allocator;
    const base = try VertexProvider.buildDefaultBase(alloc, "proj-2", "us-central1");
    defer alloc.free(base);
    try std.testing.expectEqualStrings(
        "https://us-central1-aiplatform.googleapis.com/v1/projects/proj-2/locations/us-central1/publishers/google/models",
        base,
    );
}

test "provider creates with explicit token and base_url" {
    const p = VertexProvider.init(std.testing.allocator, "ya29.token", "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/google/models");
    try std.testing.expect(p.auth != null);
    try std.testing.expect(p.base != null);
    try std.testing.expectEqualStrings("config", p.authSource());
    try std.testing.expectEqualStrings("base_url config", p.endpointSource());
}

test "buildAuthHeader uses explicit bearer token" {
    const alloc = std.testing.allocator;
    var p = VertexProvider.init(alloc, "ya29.explicit", "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/google/models");
    defer VertexProvider.deinitImpl(@ptrCast(&p));

    const auth_header = try p.buildAuthHeader(alloc);
    defer alloc.free(auth_header);
    try std.testing.expectEqualStrings("Authorization: Bearer ya29.explicit", auth_header);
}

test "parseServiceAccountCredentials extracts required fields" {
    const alloc = std.testing.allocator;
    const raw =
        \\{"type":"service_account","project_id":"proj-vertex","client_email":"svc@proj-vertex.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n","token_uri":"https://oauth2.googleapis.com/token"}
    ;
    const creds = parseServiceAccountCredentials(alloc, raw) orelse return error.TestExpectedEqual;
    defer creds.deinit(alloc);

    try std.testing.expectEqualStrings("proj-vertex", creds.project_id);
    try std.testing.expectEqualStrings("svc@proj-vertex.iam.gserviceaccount.com", creds.client_email);
    try std.testing.expect(std.mem.indexOf(u8, creds.private_key, "BEGIN PRIVATE KEY") != null);
    try std.testing.expectEqualStrings("https://oauth2.googleapis.com/token", creds.token_uri);
}

test "parseServiceAccountCredentials rejects non-https token_uri" {
    const alloc = std.testing.allocator;
    const raw =
        \\{"project_id":"proj-vertex","client_email":"svc@proj-vertex.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n","token_uri":"http://oauth2.googleapis.com/token"}
    ;
    try std.testing.expect(parseServiceAccountCredentials(alloc, raw) == null);
}

test "buildAuthHeader uses service-account oauth2 token exchange path" {
    const alloc = std.testing.allocator;
    const raw =
        \\{"project_id":"proj-oauth2","client_email":"svc@proj-oauth2.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"}
    ;
    var p = VertexProvider.init(alloc, raw, null);
    defer VertexProvider.deinitImpl(@ptrCast(&p));

    const auth_header = try p.buildAuthHeader(alloc);
    defer alloc.free(auth_header);

    try std.testing.expectEqualStrings("Authorization: Bearer test-vertex-service-account-token", auth_header);
    try std.testing.expect(p.cached_service_account_token != null);
    try std.testing.expectEqualStrings("derived project/location", p.endpointSource());
}

test "resolveAuth accepts config service account json" {
    const alloc = std.testing.allocator;
    const raw =
        \\{"project_id":"proj-sa","client_email":"svc@proj-sa.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"}
    ;

    const auth = VertexProvider.resolveAuth(alloc, raw) orelse return error.TestExpectedEqual;
    defer switch (auth) {
        .explicit_service_account => |creds| creds.deinit(alloc),
        else => {},
    };

    switch (auth) {
        .explicit_service_account => |creds| {
            try std.testing.expectEqualStrings("proj-sa", creds.project_id);
            try std.testing.expectEqualStrings("config service account JSON", auth.source());
        },
        else => return error.TestExpectedEqual,
    }
}

test "service-account project id can build default base url" {
    const alloc = std.testing.allocator;
    const raw =
        \\{"project_id":"proj-build-base","client_email":"svc@proj-build-base.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"}
    ;
    const auth = VertexProvider.resolveAuth(alloc, raw) orelse return error.TestExpectedEqual;
    defer switch (auth) {
        .explicit_service_account => |creds| creds.deinit(alloc),
        else => {},
    };

    const project_id = VertexProvider.serviceAccountProjectId(auth) orelse return error.TestExpectedEqual;
    const base = try VertexProvider.buildDefaultBase(alloc, project_id, "global");
    defer alloc.free(base);
    try std.testing.expectEqualStrings(
        "https://aiplatform.googleapis.com/v1/projects/proj-build-base/locations/global/publishers/google/models",
        base,
    );
}

test "provider rejects whitespace explicit token" {
    const p = VertexProvider.init(std.testing.allocator, "   ", "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/google/models");
    const src = p.authSource();
    try std.testing.expect(!std.mem.eql(u8, src, "config"));
}

test "provider getName returns Vertex" {
    var p = VertexProvider.init(std.testing.allocator, "ya29.token", "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/google/models");
    const prov = p.provider();
    try std.testing.expectEqualStrings("Vertex", prov.getName());
}

test "streaming support is enabled" {
    try std.testing.expect(VertexProvider.vtable.supports_streaming != null);
    try std.testing.expect(VertexProvider.vtable.stream_chat != null);
}

test "streamChatImpl fails without credentials" {
    var p = VertexProvider{
        .auth = null,
        .base = .{ .config = "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/google/models" },
        .allocator = std.testing.allocator,
    };

    const prov = p.provider();
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("test")};
    const req = ChatRequest{ .messages = &msgs, .model = "gemini-2.5-pro" };

    const DummyCallback = struct {
        fn cb(_: *anyopaque, _: root.StreamChunk) void {}
    };
    var ctx: u8 = 0;

    try std.testing.expectError(
        error.CredentialsNotSet,
        prov.streamChat(std.testing.allocator, req, "gemini-2.5-pro", 0.7, &DummyCallback.cb, @ptrCast(&ctx)),
    );
}

test "chatWithSystem fails without endpoint base" {
    var p = VertexProvider{
        .auth = .{ .explicit_token = "ya29.token" },
        .base = null,
        .allocator = std.testing.allocator,
    };

    const prov = p.provider();
    try std.testing.expectError(
        error.VertexBaseUrlNotSet,
        prov.chatWithSystem(std.testing.allocator, null, "hi", "gemini-2.5-pro", 0.7),
    );
}

test "buildChatRequestBody plain text" {
    const alloc = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const body = try buildChatRequestBody(alloc, .{ .messages = &msgs }, "gemini-2.5-flash", 0.7);
    defer alloc.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();

    const contents = parsed.value.object.get("contents").?.array;
    try std.testing.expectEqual(@as(usize, 1), contents.items.len);
    try std.testing.expectEqualStrings("user", contents.items[0].object.get("role").?.string);
}

test "buildChatRequestBody honors max_tokens" {
    const alloc = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const body = try buildChatRequestBody(alloc, .{ .messages = &msgs, .max_tokens = 1234 }, "gemini-2.5-flash", 0.2);
    defer alloc.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();

    const gen = parsed.value.object.get("generationConfig").?.object;
    try std.testing.expectEqual(@as(i64, 1234), gen.get("maxOutputTokens").?.integer);
}

test "buildChatRequestBody maps reasoning_effort to thinkingLevel for gemini-3 flash" {
    const alloc = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const body = try buildChatRequestBody(alloc, .{
        .messages = &msgs,
        .reasoning_effort = "medium",
    }, "gemini-3.1-flash", 0.2);
    defer alloc.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();

    const gen = parsed.value.object.get("generationConfig").?.object;
    const thinking = gen.get("thinkingConfig").?.object;
    try std.testing.expectEqualStrings("MEDIUM", thinking.get("thinkingLevel").?.string);
}

test "buildChatRequestBody maps reasoning_effort to thinkingBudget for gemini-2.5" {
    const alloc = std.testing.allocator;
    const msgs = [_]root.ChatMessage{root.ChatMessage.user("hello")};
    const body = try buildChatRequestBody(alloc, .{
        .messages = &msgs,
        .reasoning_effort = "high",
    }, "gemini-2.5-pro", 0.2);
    defer alloc.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();

    const gen = parsed.value.object.get("generationConfig").?.object;
    const thinking = gen.get("thinkingConfig").?.object;
    try std.testing.expectEqual(@as(i64, 24576), thinking.get("thinkingBudget").?.integer);
}

test "buildChatRequestBody with image base64" {
    const alloc = std.testing.allocator;
    const parts = [_]root.ContentPart{root.makeBase64ImagePart("QUJD", "image/png")};
    const msg = root.ChatMessage{
        .role = .user,
        .content = "",
        .content_parts = &parts,
    };
    const msgs = [_]root.ChatMessage{msg};

    const body = try buildChatRequestBody(alloc, .{ .messages = &msgs }, "gemini-2.5-flash", 0.7);
    defer alloc.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();

    const inline_data = parsed.value.object.get("contents").?.array.items[0]
        .object.get("parts").?.array.items[0]
        .object.get("inlineData").?.object;
    try std.testing.expectEqualStrings("image/png", inline_data.get("mimeType").?.string);
    try std.testing.expectEqualStrings("QUJD", inline_data.get("data").?.string);
}

test "parse Gemini-style response via shared parser" {
    const body =
        \\{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}
    ;
    const text = try gemini.GeminiProvider.parseResponse(std.testing.allocator, body);
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings("ok", text);
}

test "parseServiceAccountAccessTokenResponse parses token payload" {
    const alloc = std.testing.allocator;
    const payload = "{\"access_token\":\"ya29.service-account\",\"expires_in\":3599,\"token_type\":\"Bearer\"}";
    const parsed = parseServiceAccountAccessTokenResponse(alloc, payload) orelse return error.TestExpectedEqual;
    defer alloc.free(parsed.access_token);
    try std.testing.expectEqualStrings("ya29.service-account", parsed.access_token);
    try std.testing.expectEqual(@as(i64, 3599), parsed.expires_in);
}

test "deinit frees owned env allocations" {
    const alloc = std.testing.allocator;
    var p = VertexProvider{
        .auth = .{ .env_vertex_oauth_token = try alloc.dupe(u8, "ya29.token") },
        .base = .{ .env = try alloc.dupe(u8, "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/google/models") },
        .allocator = alloc,
    };

    VertexProvider.deinitImpl(@ptrCast(&p));
    try std.testing.expect(p.auth == null);
    try std.testing.expect(p.base == null);
}

test "deinit frees explicit service-account credentials and cached token" {
    const alloc = std.testing.allocator;
    var p = VertexProvider{
        .auth = .{ .explicit_service_account = .{
            .project_id = try alloc.dupe(u8, "proj-x"),
            .client_email = try alloc.dupe(u8, "svc@proj-x.iam.gserviceaccount.com"),
            .private_key = try alloc.dupe(u8, "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"),
            .token_uri = try alloc.dupe(u8, "https://oauth2.googleapis.com/token"),
        } },
        .base = .{ .derived = try alloc.dupe(u8, "https://aiplatform.googleapis.com/v1/projects/proj-x/locations/global/publishers/google/models") },
        .cached_service_account_token = try alloc.dupe(u8, "ya29.cached"),
        .cached_service_account_expiry = std.time.timestamp() + 1200,
        .allocator = alloc,
    };

    VertexProvider.deinitImpl(@ptrCast(&p));
    try std.testing.expect(p.auth == null);
    try std.testing.expect(p.base == null);
    try std.testing.expect(p.cached_service_account_token == null);
}
