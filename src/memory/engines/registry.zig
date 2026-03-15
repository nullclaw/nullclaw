//! Backend Registry — comptime descriptors for all memory backends.
//!
//! Each backend declares its name, capabilities, path requirements, and
//! factory function.  The path resolver (`resolvePaths`) centralises the
//! `joinZ` logic that was previously duplicated across 6 entry points.

const std = @import("std");
const build_options = @import("build_options");
const config_types = @import("../../config_types.zig");
const root = @import("../root.zig");
const memory_lru = @import("memory_lru.zig");
const pg = if (build_options.enable_postgres) @import("postgres.zig") else struct {};
const redis_engine = @import("redis.zig");
const lancedb_engine = @import("lancedb.zig");
const api_engine = @import("api.zig");
const clickhouse_engine = @import("clickhouse.zig");

// ── Capability & descriptor types ────────────────────────────────

pub const BackendCapabilities = struct {
    supports_keyword_rank: bool, // FTS5 BM25
    supports_session_store: bool, // saveMessage / loadMessages
    supports_transactions: bool, // BEGIN / COMMIT
    supports_outbox: bool, // durable vector-sync
};

pub const BackendDescriptor = struct {
    name: []const u8,
    label: []const u8,
    auto_save_default: bool,
    capabilities: BackendCapabilities,
    needs_db_path: bool, // sqlite, lucid → true
    needs_workspace: bool, // markdown, lucid → true
    create: *const fn (std.mem.Allocator, BackendConfig) anyerror!BackendInstance,
};

pub const BackendConfig = struct {
    db_path: ?[*:0]const u8,
    workspace_dir: []const u8,
    postgres_url: ?[*:0]const u8 = null,
    postgres_schema: []const u8 = "public",
    postgres_table: []const u8 = "memories",
    postgres_connect_timeout_secs: u32 = 30,
    redis_config: ?config_types.MemoryRedisConfig = null,
    api_config: ?config_types.MemoryApiConfig = null,
    clickhouse_config: ?config_types.MemoryClickHouseConfig = null,
    instance_id: []const u8 = "",
};

pub const BackendInstance = struct {
    memory: root.Memory,
    session_store: ?root.SessionStore,
};

// ── Comptime registry ────────────────────────────────────────────

const sqlite_backend = BackendDescriptor{
    .name = "sqlite",
    .label = "SQLite with FTS5 search (recommended)",
    .auto_save_default = true,
    .capabilities = .{ .supports_keyword_rank = true, .supports_session_store = true, .supports_transactions = true, .supports_outbox = true },
    .needs_db_path = true,
    .needs_workspace = false,
    .create = &createSqlite,
};

const markdown_backend = BackendDescriptor{
    .name = "markdown",
    .label = "Markdown files — simple, human-readable",
    .auto_save_default = true,
    .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = false, .supports_transactions = false, .supports_outbox = false },
    .needs_db_path = false,
    .needs_workspace = true,
    .create = &createMarkdown,
};

const lucid_backend = BackendDescriptor{
    .name = "lucid",
    .label = "Lucid — SQLite + cross-project memory sync via lucid CLI",
    .auto_save_default = true,
    .capabilities = .{ .supports_keyword_rank = true, .supports_session_store = true, .supports_transactions = true, .supports_outbox = true },
    .needs_db_path = true,
    .needs_workspace = true,
    .create = &createLucid,
};

const memory_backend = BackendDescriptor{
    .name = "memory",
    .label = "In-memory LRU — no persistence, ideal for testing",
    .auto_save_default = false,
    .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = false, .supports_transactions = false, .supports_outbox = false },
    .needs_db_path = false,
    .needs_workspace = false,
    .create = &createMemoryLru,
};

const redis_backend = BackendDescriptor{
    .name = "redis",
    .label = "Redis — distributed in-memory store with optional TTL",
    .auto_save_default = true,
    .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = false, .supports_transactions = false, .supports_outbox = false },
    .needs_db_path = false,
    .needs_workspace = false,
    .create = &createRedis,
};

const lancedb_backend = BackendDescriptor{
    .name = "lancedb",
    .label = "LanceDB — SQLite + vector-augmented recall",
    .auto_save_default = true,
    .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = false, .supports_transactions = false, .supports_outbox = false },
    .needs_db_path = true,
    .needs_workspace = false,
    .create = &createLanceDb,
};

const api_backend = BackendDescriptor{
    .name = "api",
    .label = "HTTP API — delegate to external REST service",
    .auto_save_default = true,
    .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = true, .supports_transactions = false, .supports_outbox = false },
    .needs_db_path = false,
    .needs_workspace = false,
    .create = &createApi,
};

const none_backend = BackendDescriptor{
    .name = "none",
    .label = "None — disable persistent memory",
    .auto_save_default = false,
    .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = false, .supports_transactions = false, .supports_outbox = false },
    .needs_db_path = false,
    .needs_workspace = false,
    .create = &createNone,
};

const hybrid_backends = if (build_options.enable_memory_sqlite) [_]BackendDescriptor{
    .{
        .name = "hybrid",
        .label = "Hybrid: SQLite + Markdown",
        .auto_save_default = true,
        .capabilities = .{
            .supports_keyword_rank = true,
            .supports_session_store = true,
            .supports_transactions = true,
            .supports_outbox = true,
        },
        .needs_db_path = true,
        .needs_workspace = true,
        .create = &createHybrid,
    },
} else [0]BackendDescriptor{};

const markdown_backends = if (build_options.enable_memory_markdown) [_]BackendDescriptor{
    markdown_backend,
} else [0]BackendDescriptor{};

const api_backends = if (build_options.enable_memory_api) [_]BackendDescriptor{
    api_backend,
} else [0]BackendDescriptor{};

const memory_backends = if (build_options.enable_memory_memory) [_]BackendDescriptor{
    memory_backend,
} else [0]BackendDescriptor{};

const none_backends = if (build_options.enable_memory_none) [_]BackendDescriptor{
    none_backend,
} else [0]BackendDescriptor{};

const sqlite_backends = if (build_options.enable_memory_sqlite) [_]BackendDescriptor{
    sqlite_backend,
} else [0]BackendDescriptor{};

const lucid_backends = if (build_options.enable_memory_lucid) [_]BackendDescriptor{
    lucid_backend,
} else [0]BackendDescriptor{};

const redis_backends = if (build_options.enable_memory_redis) [_]BackendDescriptor{
    redis_backend,
} else [0]BackendDescriptor{};

const lancedb_backends = if (build_options.enable_memory_lancedb) [_]BackendDescriptor{
    lancedb_backend,
} else [0]BackendDescriptor{};

const pg_backends = if (build_options.enable_postgres) [_]BackendDescriptor{.{
    .name = "postgres",
    .label = "PostgreSQL — remote/shared memory store",
    .auto_save_default = true,
    .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = true, .supports_transactions = true, .supports_outbox = true },
    .needs_db_path = false,
    .needs_workspace = false,
    .create = &createPostgres,
}} else [0]BackendDescriptor{};

const clickhouse_backends = if (build_options.enable_memory_clickhouse) [_]BackendDescriptor{.{
    .name = "clickhouse",
    .label = "ClickHouse — columnar analytics memory store",
    .auto_save_default = true,
    .capabilities = .{ .supports_keyword_rank = false, .supports_session_store = true, .supports_transactions = false, .supports_outbox = false },
    .needs_db_path = false,
    .needs_workspace = false,
    .create = &createClickHouse,
}} else [0]BackendDescriptor{};

pub const all = hybrid_backends ++ markdown_backends ++ api_backends ++ memory_backends ++ none_backends ++ sqlite_backends ++ lucid_backends ++ redis_backends ++ lancedb_backends ++ pg_backends ++ clickhouse_backends;
pub const known_backend_names = [_][]const u8{
    "hybrid",
    "none",
    "markdown",
    "memory",
    "api",
    "sqlite",
    "lucid",
    "redis",
    "lancedb",
    "postgres",
    "clickhouse",
};
pub const known_backends_csv = "hybrid, none, markdown, memory, api, sqlite, lucid, redis, lancedb, postgres, clickhouse";

// ── Lookup ───────────────────────────────────────────────────────

pub fn findBackend(name: []const u8) ?*const BackendDescriptor {
    for (&all) |*desc| {
        if (std.mem.eql(u8, desc.name, name)) return desc;
    }
    return null;
}

pub fn isKnownBackend(name: []const u8) bool {
    for (known_backend_names) |known| {
        if (std.mem.eql(u8, known, name)) return true;
    }
    return false;
}

pub fn engineTokenForBackend(name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, name, "hybrid")) return "sqlite";
    if (std.mem.eql(u8, name, "none")) return "none";
    if (std.mem.eql(u8, name, "markdown")) return "markdown";
    if (std.mem.eql(u8, name, "memory")) return "memory";
    if (std.mem.eql(u8, name, "api")) return "api";
    if (std.mem.eql(u8, name, "sqlite")) return "sqlite";
    if (std.mem.eql(u8, name, "lucid")) return "lucid";
    if (std.mem.eql(u8, name, "redis")) return "redis";
    if (std.mem.eql(u8, name, "lancedb")) return "lancedb";
    if (std.mem.eql(u8, name, "postgres")) return "postgres";
    if (std.mem.eql(u8, name, "clickhouse")) return "clickhouse";
    return null;
}

pub fn formatEnabledBackends(allocator: std.mem.Allocator) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    const w = out.writer(allocator);

    for (&all, 0..) |desc, i| {
        if (i != 0) try w.writeAll(", ");
        try w.writeAll(desc.name);
    }
    if (all.len == 0) {
        try w.writeAll("(none)");
    }
    return out.toOwnedSlice(allocator);
}

// ── Path resolver ────────────────────────────────────────────────

pub fn resolvePaths(
    allocator: std.mem.Allocator,
    desc: *const BackendDescriptor,
    workspace_dir: []const u8,
    postgres_cfg: ?config_types.MemoryPostgresConfig,
    redis_cfg: ?config_types.MemoryRedisConfig,
    api_cfg: ?config_types.MemoryApiConfig,
    clickhouse_cfg: ?config_types.MemoryClickHouseConfig,
) !BackendConfig {
    const db_path: ?[*:0]const u8 = if (desc.needs_db_path)
        try std.fs.path.joinZ(allocator, &.{ workspace_dir, "memory.db" })
    else
        null;
    errdefer if (db_path) |p| allocator.free(std.mem.span(p));

    var pg_url: ?[*:0]const u8 = null;
    var pg_schema: []const u8 = "public";
    var pg_table: []const u8 = "memories";
    var pg_connect_timeout_secs: u32 = 30;
    if (postgres_cfg) |pcfg| {
        if (pcfg.url.len > 0) {
            pg_url = try allocator.dupeZ(u8, pcfg.url);
        }
        pg_schema = pcfg.schema;
        pg_table = pcfg.table;
        pg_connect_timeout_secs = pcfg.connect_timeout_secs;
    }

    return .{
        .db_path = db_path,
        .workspace_dir = workspace_dir,
        .postgres_url = pg_url,
        .postgres_schema = pg_schema,
        .postgres_table = pg_table,
        .postgres_connect_timeout_secs = pg_connect_timeout_secs,
        .redis_config = redis_cfg,
        .api_config = api_cfg,
        .clickhouse_config = clickhouse_cfg,
    };
}

// ── Factory wrappers ─────────────────────────────────────────────

fn createHybrid(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    return createSqlite(allocator, cfg);
}

fn createSqlite(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    const impl_ = try allocator.create(root.SqliteMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try root.SqliteMemory.init(allocator, cfg.db_path.?);
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = impl_.sessionStore() };
}

fn createMarkdown(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    const impl_ = try allocator.create(root.MarkdownMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try root.MarkdownMemory.init(allocator, cfg.workspace_dir);
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = null };
}

fn createLucid(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    const impl_ = try allocator.create(root.LucidMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try root.LucidMemory.init(allocator, cfg.db_path.?, cfg.workspace_dir);
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = impl_.sessionStore() };
}

fn createMemoryLru(allocator: std.mem.Allocator, _: BackendConfig) !BackendInstance {
    const impl_ = try allocator.create(memory_lru.InMemoryLruMemory);
    impl_.* = memory_lru.InMemoryLruMemory.init(allocator, 1000);
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = null };
}

fn createRedis(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    const rcfg = cfg.redis_config orelse config_types.MemoryRedisConfig{};
    const impl_ = try allocator.create(redis_engine.RedisMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try redis_engine.RedisMemory.init(allocator, .{
        .host = rcfg.host,
        .port = rcfg.port,
        .password = if (rcfg.password.len > 0) rcfg.password else null,
        .db_index = rcfg.db_index,
        .key_prefix = rcfg.key_prefix,
        .ttl_seconds = if (rcfg.ttl_seconds > 0) rcfg.ttl_seconds else null,
        .instance_id = cfg.instance_id,
    });
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = null };
}

fn createLanceDb(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    const impl_ = try allocator.create(lancedb_engine.LanceDbMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try lancedb_engine.LanceDbMemory.init(allocator, cfg.db_path.?, null, .{});
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = null };
}

fn createApi(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    const api_cfg = cfg.api_config orelse return error.MissingApiConfig;
    const impl_ = try allocator.create(api_engine.ApiMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try api_engine.ApiMemory.init(allocator, api_cfg);
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = impl_.sessionStore() };
}

fn createNone(allocator: std.mem.Allocator, _: BackendConfig) !BackendInstance {
    const impl_ = try allocator.create(root.NoneMemory);
    impl_.* = root.NoneMemory.init();
    impl_.allocator = allocator;
    return .{ .memory = impl_.memory(), .session_store = null };
}

fn createPostgres(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    if (!build_options.enable_postgres) return error.PostgresNotEnabled;
    const url = cfg.postgres_url orelse return error.MissingPostgresUrl;

    const effective_url = try applyPostgresConnectTimeout(
        allocator,
        std.mem.span(url),
        cfg.postgres_connect_timeout_secs,
    );
    defer allocator.free(effective_url);

    const impl_ = try allocator.create(pg.PostgresMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try pg.PostgresMemory.init(allocator, effective_url.ptr, cfg.postgres_schema, cfg.postgres_table, cfg.instance_id);
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = impl_.sessionStore() };
}

fn createClickHouse(allocator: std.mem.Allocator, cfg: BackendConfig) !BackendInstance {
    if (!build_options.enable_memory_clickhouse) return error.ClickHouseNotEnabled;
    const ch_cfg = cfg.clickhouse_config orelse config_types.MemoryClickHouseConfig{};
    const impl_ = try allocator.create(clickhouse_engine.ClickHouseMemory);
    errdefer allocator.destroy(impl_);
    impl_.* = try clickhouse_engine.ClickHouseMemory.init(allocator, .{
        .host = ch_cfg.host,
        .port = ch_cfg.port,
        .database = ch_cfg.database,
        .table = ch_cfg.table,
        .user = ch_cfg.user,
        .password = ch_cfg.password,
        .use_https = ch_cfg.use_https,
        .instance_id = cfg.instance_id,
    });
    impl_.owns_self = true;
    return .{ .memory = impl_.memory(), .session_store = impl_.sessionStore() };
}

fn applyPostgresConnectTimeout(
    allocator: std.mem.Allocator,
    base_url: []const u8,
    timeout_secs: u32,
) ![:0]u8 {
    if (base_url.len == 0) return allocator.dupeZ(u8, base_url);
    if (timeout_secs == 0) return allocator.dupeZ(u8, base_url);
    if (std.mem.indexOf(u8, base_url, "connect_timeout=") != null) return allocator.dupeZ(u8, base_url);

    // URI form: postgresql://... or postgres://...
    if (std.mem.indexOf(u8, base_url, "://") != null) {
        const sep: u8 = if (std.mem.indexOfScalar(u8, base_url, '?') != null) '&' else '?';
        const out = try std.fmt.allocPrint(allocator, "{s}{c}connect_timeout={d}", .{ base_url, sep, timeout_secs });
        defer allocator.free(out);
        return allocator.dupeZ(u8, out);
    }

    // Keyword/value conninfo form.
    const out = try std.fmt.allocPrint(allocator, "{s} connect_timeout={d}", .{ base_url, timeout_secs });
    defer allocator.free(out);
    return allocator.dupeZ(u8, out);
}

// ── Tests ────────────────────────────────────────────────────────

test "registry length" {
    const expected: usize =
        @as(usize, @intFromBool(build_options.enable_memory_sqlite)) + // hybrid
        @as(usize, @intFromBool(build_options.enable_memory_markdown)) +
        @as(usize, @intFromBool(build_options.enable_memory_api)) +
        @as(usize, @intFromBool(build_options.enable_memory_memory)) +
        @as(usize, @intFromBool(build_options.enable_memory_none)) +
        @as(usize, @intFromBool(build_options.enable_memory_sqlite)) +
        @as(usize, @intFromBool(build_options.enable_memory_lucid)) +
        @as(usize, @intFromBool(build_options.enable_memory_redis)) +
        @as(usize, @intFromBool(build_options.enable_memory_lancedb)) +
        @as(usize, @intFromBool(build_options.enable_postgres)) +
        @as(usize, @intFromBool(build_options.enable_memory_clickhouse));
    try std.testing.expectEqual(expected, all.len);
}

test "findBackend sqlite" {
    if (!build_options.enable_memory_sqlite) {
        try std.testing.expect(findBackend("sqlite") == null);
        return;
    }
    const desc = findBackend("sqlite") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("sqlite", desc.name);
    try std.testing.expect(desc.capabilities.supports_keyword_rank);
    try std.testing.expect(desc.capabilities.supports_session_store);
    try std.testing.expect(desc.capabilities.supports_transactions);
    try std.testing.expect(desc.capabilities.supports_outbox);
    try std.testing.expect(desc.needs_db_path);
    try std.testing.expect(!desc.needs_workspace);
    try std.testing.expect(desc.auto_save_default);
}

test "findBackend markdown" {
    if (!build_options.enable_memory_markdown) {
        try std.testing.expect(findBackend("markdown") == null);
        return;
    }
    const desc = findBackend("markdown") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("markdown", desc.name);
    try std.testing.expect(!desc.capabilities.supports_keyword_rank);
    try std.testing.expect(!desc.capabilities.supports_session_store);
    try std.testing.expect(!desc.needs_db_path);
    try std.testing.expect(desc.needs_workspace);
    try std.testing.expect(desc.auto_save_default);
}

test "findBackend memory" {
    if (!build_options.enable_memory_memory) {
        try std.testing.expect(findBackend("memory") == null);
        return;
    }
    const desc = findBackend("memory") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("memory", desc.name);
    try std.testing.expect(!desc.capabilities.supports_keyword_rank);
    try std.testing.expect(!desc.capabilities.supports_session_store);
    try std.testing.expect(!desc.capabilities.supports_transactions);
    try std.testing.expect(!desc.capabilities.supports_outbox);
    try std.testing.expect(!desc.needs_db_path);
    try std.testing.expect(!desc.needs_workspace);
    try std.testing.expect(!desc.auto_save_default);
}

test "findBackend lucid" {
    if (!build_options.enable_memory_lucid) {
        try std.testing.expect(findBackend("lucid") == null);
        return;
    }
    const desc = findBackend("lucid") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("lucid", desc.name);
    try std.testing.expect(desc.capabilities.supports_keyword_rank);
    try std.testing.expect(desc.needs_db_path);
    try std.testing.expect(desc.needs_workspace);
    try std.testing.expect(desc.auto_save_default);
}

test "findBackend none" {
    if (!build_options.enable_memory_none) {
        try std.testing.expect(findBackend("none") == null);
        return;
    }
    const desc = findBackend("none") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("none", desc.name);
    try std.testing.expect(!desc.capabilities.supports_keyword_rank);
    try std.testing.expect(!desc.capabilities.supports_session_store);
    try std.testing.expect(!desc.needs_db_path);
    try std.testing.expect(!desc.needs_workspace);
    try std.testing.expect(!desc.auto_save_default);
}

test "findBackend redis" {
    if (!build_options.enable_memory_redis) {
        try std.testing.expect(findBackend("redis") == null);
        return;
    }
    const desc = findBackend("redis") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("redis", desc.name);
    try std.testing.expect(!desc.capabilities.supports_keyword_rank);
    try std.testing.expect(!desc.capabilities.supports_session_store);
    try std.testing.expect(!desc.needs_db_path);
    try std.testing.expect(!desc.needs_workspace);
    try std.testing.expect(desc.auto_save_default);
}

test "findBackend lancedb" {
    if (!build_options.enable_memory_lancedb) {
        try std.testing.expect(findBackend("lancedb") == null);
        return;
    }
    const desc = findBackend("lancedb") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("lancedb", desc.name);
    try std.testing.expect(!desc.capabilities.supports_keyword_rank);
    try std.testing.expect(!desc.capabilities.supports_session_store);
    try std.testing.expect(desc.needs_db_path);
    try std.testing.expect(!desc.needs_workspace);
    try std.testing.expect(desc.auto_save_default);
}

test "findBackend api" {
    if (!build_options.enable_memory_api) {
        try std.testing.expect(findBackend("api") == null);
        return;
    }
    const desc = findBackend("api") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("api", desc.name);
    try std.testing.expect(!desc.capabilities.supports_keyword_rank);
    try std.testing.expect(desc.capabilities.supports_session_store);
    try std.testing.expect(!desc.capabilities.supports_transactions);
    try std.testing.expect(!desc.capabilities.supports_outbox);
    try std.testing.expect(!desc.needs_db_path);
    try std.testing.expect(!desc.needs_workspace);
    try std.testing.expect(desc.auto_save_default);
}

test "findBackend clickhouse" {
    if (!build_options.enable_memory_clickhouse) {
        try std.testing.expect(findBackend("clickhouse") == null);
        return;
    }
    const desc = findBackend("clickhouse") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("clickhouse", desc.name);
    try std.testing.expect(!desc.capabilities.supports_keyword_rank);
    try std.testing.expect(desc.capabilities.supports_session_store);
    try std.testing.expect(!desc.capabilities.supports_transactions);
    try std.testing.expect(!desc.capabilities.supports_outbox);
    try std.testing.expect(!desc.needs_db_path);
    try std.testing.expect(!desc.needs_workspace);
    try std.testing.expect(desc.auto_save_default);
}

test "findBackend unknown returns null" {
    try std.testing.expect(findBackend("nonexistent") == null);
}

test "findBackend empty returns null" {
    try std.testing.expect(findBackend("") == null);
}

test "isKnownBackend validates canonical backend names" {
    for (known_backend_names) |name| {
        try std.testing.expect(isKnownBackend(name));
    }
    try std.testing.expect(!isKnownBackend("unknown_backend"));
}

test "engineTokenForBackend maps known names and rejects unknown" {
    try std.testing.expectEqualStrings("none", engineTokenForBackend("none").?);
    try std.testing.expectEqualStrings("markdown", engineTokenForBackend("markdown").?);
    try std.testing.expectEqualStrings("sqlite", engineTokenForBackend("sqlite").?);
    try std.testing.expectEqualStrings("postgres", engineTokenForBackend("postgres").?);
    try std.testing.expect(engineTokenForBackend("unknown_backend") == null);
}

test "formatEnabledBackends reflects compiled registry" {
    const rendered = try formatEnabledBackends(std.testing.allocator);
    defer std.testing.allocator.free(rendered);

    if (all.len == 0) {
        try std.testing.expectEqualStrings("(none)", rendered);
        return;
    }
    for (&all) |desc| {
        try std.testing.expect(std.mem.indexOf(u8, rendered, desc.name) != null);
    }
}

test "resolvePaths sqlite has db_path" {
    if (!build_options.enable_memory_sqlite) {
        try std.testing.expect(findBackend("sqlite") == null);
        return;
    }
    const desc = findBackend("sqlite") orelse return error.TestUnexpectedResult;
    const cfg = try resolvePaths(std.testing.allocator, desc, "/tmp/ws", null, null, null, null);
    defer if (cfg.db_path) |p| std.testing.allocator.free(std.mem.span(p));

    try std.testing.expect(cfg.db_path != null);
    const path_slice = std.mem.span(cfg.db_path.?);
    try std.testing.expect(std.mem.endsWith(u8, path_slice, "memory.db"));
    try std.testing.expectEqualStrings("/tmp/ws", cfg.workspace_dir);
}

test "resolvePaths markdown has no db_path" {
    if (!build_options.enable_memory_markdown) {
        try std.testing.expect(findBackend("markdown") == null);
        return;
    }
    const desc = findBackend("markdown") orelse return error.TestUnexpectedResult;
    const cfg = try resolvePaths(std.testing.allocator, desc, "/tmp/ws", null, null, null, null);

    try std.testing.expect(cfg.db_path == null);
    try std.testing.expectEqualStrings("/tmp/ws", cfg.workspace_dir);
}

test "resolvePaths none has no db_path" {
    if (!build_options.enable_memory_none) {
        try std.testing.expect(findBackend("none") == null);
        return;
    }
    const desc = findBackend("none") orelse return error.TestUnexpectedResult;
    const cfg = try resolvePaths(std.testing.allocator, desc, "/tmp/ws", null, null, null, null);

    try std.testing.expect(cfg.db_path == null);
    try std.testing.expectEqualStrings("/tmp/ws", cfg.workspace_dir);
}

test "createNone produces working memory" {
    if (!build_options.enable_memory_none) {
        try std.testing.expect(findBackend("none") == null);
        return;
    }
    const instance = try createNone(std.testing.allocator, .{
        .db_path = null,
        .workspace_dir = "/tmp",
    });
    defer instance.memory.deinit();

    try std.testing.expectEqualStrings("none", instance.memory.name());
    try std.testing.expectEqual(@as(usize, 0), try instance.memory.count());
    try std.testing.expect(instance.memory.healthCheck());
}

test "createNone returns session_store null" {
    if (!build_options.enable_memory_none) {
        try std.testing.expect(findBackend("none") == null);
        return;
    }
    const instance = try createNone(std.testing.allocator, .{
        .db_path = null,
        .workspace_dir = "/tmp",
    });
    defer instance.memory.deinit();

    try std.testing.expect(instance.session_store == null);
}

test "resolvePaths redis config is preserved" {
    if (!build_options.enable_memory_redis) {
        try std.testing.expect(findBackend("redis") == null);
        return;
    }
    const desc = findBackend("redis") orelse return error.TestUnexpectedResult;
    const cfg = try resolvePaths(std.testing.allocator, desc, "/tmp/ws", null, .{
        .host = "10.10.10.10",
        .port = 6380,
        .password = "pw",
        .db_index = 2,
        .key_prefix = "agent",
        .ttl_seconds = 120,
    }, null, null);

    try std.testing.expect(cfg.redis_config != null);
    try std.testing.expectEqualStrings("10.10.10.10", cfg.redis_config.?.host);
    try std.testing.expectEqual(@as(u16, 6380), cfg.redis_config.?.port);
    try std.testing.expectEqualStrings("pw", cfg.redis_config.?.password);
    try std.testing.expectEqual(@as(u8, 2), cfg.redis_config.?.db_index);
    try std.testing.expectEqualStrings("agent", cfg.redis_config.?.key_prefix);
    try std.testing.expectEqual(@as(u32, 120), cfg.redis_config.?.ttl_seconds);
}

test "applyPostgresConnectTimeout uri appends query parameter" {
    const out = try applyPostgresConnectTimeout(
        std.testing.allocator,
        "postgresql://db.example.com/memory",
        9,
    );
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("postgresql://db.example.com/memory?connect_timeout=9", out);
}

test "applyPostgresConnectTimeout uri appends with ampersand" {
    const out = try applyPostgresConnectTimeout(
        std.testing.allocator,
        "postgresql://db.example.com/memory?sslmode=require",
        9,
    );
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("postgresql://db.example.com/memory?sslmode=require&connect_timeout=9", out);
}

test "applyPostgresConnectTimeout keeps existing timeout unchanged" {
    const out = try applyPostgresConnectTimeout(
        std.testing.allocator,
        "postgresql://db.example.com/memory?connect_timeout=3",
        9,
    );
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("postgresql://db.example.com/memory?connect_timeout=3", out);
}
