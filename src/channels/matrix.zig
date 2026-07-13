const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const fs_compat = @import("../fs_compat.zig");
const url_percent = @import("../url_percent.zig");

const log = std.log.scoped(.matrix);

/// Matrix channel via Client-Server API.
///
/// - Inbound: long-poll /_matrix/client/v3/sync
/// - Outbound: PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}
/// - Typing: PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}
pub const MatrixChannel = struct {
    allocator: std.mem.Allocator,
    account_id: []const u8 = "default",
    homeserver: []const u8,
    access_token: []const u8,
    room_id: []const u8,
    user_id: ?[]const u8 = null,
    allow_from: []const []const u8,
    group_allow_from: []const []const u8,
    dm_policy: []const u8,
    group_policy: []const u8,
    require_mention: bool = false,
    /// Effective API endpoint: pantalaimon proxy URL when E2EE is enabled,
    /// otherwise equals homeserver. All Matrix API requests use this.
    effective_endpoint: []const u8 = "",
    running: bool = false,

    next_batch_buf: [MAX_NEXT_BATCH_LEN]u8 = undefined,
    next_batch_len: usize = 0,
    next_batch_dirty: bool = false,
    txn_counter: u64 = 0,

    pub const MAX_MESSAGE_LEN: usize = 4000;
    pub const MAX_NEXT_BATCH_LEN: usize = 1024;
    const NEXT_BATCH_STORE_VERSION: u32 = 1;
    const NEXT_BATCH_STORE_MAX_BYTES: usize = 16 * 1024;
    const NEXT_BATCH_FILE_STEM_MAX_LEN: usize = 48;

    const NextBatchStore = struct {
        version: u32,
        account_id: []const u8,
        homeserver: []const u8,
        user_id: ?[]const u8 = null,
        credential_fingerprint: []const u8,
        next_batch: []const u8,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        homeserver: []const u8,
        access_token: []const u8,
        room_id: []const u8,
        allow_from: []const []const u8,
    ) MatrixChannel {
        const hs = stripTrailingSlashes(homeserver);
        return .{
            .allocator = allocator,
            .homeserver = hs,
            .effective_endpoint = hs,
            .access_token = access_token,
            .room_id = room_id,
            .allow_from = allow_from,
            .group_allow_from = &.{},
            .dm_policy = "allowlist",
            .group_policy = "allowlist",
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.MatrixConfig) MatrixChannel {
        var ch = init(allocator, cfg.homeserver, cfg.access_token, cfg.room_id, cfg.allow_from);
        ch.account_id = cfg.account_id;
        ch.user_id = cfg.user_id;
        ch.group_allow_from = cfg.group_allow_from;
        ch.dm_policy = cfg.dm_policy;
        ch.group_policy = cfg.group_policy;
        ch.require_mention = cfg.require_mention;
        if (cfg.pantalaimon_proxy_url) |proxy| {
            ch.effective_endpoint = stripTrailingSlashes(proxy);
        }
        return ch;
    }

    pub fn channelName(_: *const MatrixChannel) []const u8 {
        return "matrix";
    }

    pub fn nextBatch(self: *const MatrixChannel) []const u8 {
        return self.next_batch_buf[0..self.next_batch_len];
    }

    fn setNextBatch(self: *MatrixChannel, token: []const u8) !void {
        if (token.len > self.next_batch_buf.len) return error.NextBatchTooLong;

        // Matrix /sync returns a fresh next_batch on every cycle, including
        // idle long-poll timeouts. Preserve a failed commit's dirty bit when
        // the same token is returned so persistence is retried by the loop.
        if (!self.nextBatchChanged(token)) return;

        if (token.len > 0) {
            @memcpy(self.next_batch_buf[0..token.len], token);
        }
        self.next_batch_len = token.len;
        self.next_batch_dirty = true;
    }

    /// True when `token` would change the buffered next_batch position.
    /// Extracted from setNextBatch so the short-circuit is unit-testable.
    fn nextBatchChanged(self: *const MatrixChannel, token: []const u8) bool {
        if (token.len != self.next_batch_len) return true;
        return !std.mem.eql(u8, self.next_batch_buf[0..token.len], token);
    }

    fn accountIdShortHash(account_id: []const u8) [32]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(account_id, &digest, .{});
        return std.fmt.bytesToHex(digest[0..16], .lower);
    }

    fn credentialFingerprint(access_token: []const u8) [64]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(access_token, &digest, .{});
        return std.fmt.bytesToHex(digest, .lower);
    }

    /// Build absolute path `<dir>/matrix-next-batch-<account>-<hash>.json`.
    /// The hash covers the full raw account id, preventing collisions caused by
    /// filename sanitization or truncation. Caller frees.
    fn nextBatchPath(allocator: std.mem.Allocator, dir: []const u8, account_id: []const u8) ![]u8 {
        var name_buf: [NEXT_BATCH_FILE_STEM_MAX_LEN]u8 = undefined;
        const safe = sanitizeAccountId(account_id, &name_buf);
        const account_hash = accountIdShortHash(account_id);
        const filename = try std.fmt.allocPrint(allocator, "matrix-next-batch-{s}-{s}.json", .{ safe, account_hash });
        defer allocator.free(filename);
        return std_compat.fs.path.join(allocator, &.{ dir, filename });
    }

    /// Replace any character that is not alphanumeric / `-` / `_` / `.` with
    /// `_` so a config-supplied account_id can never escape the state dir.
    fn sanitizeAccountId(account_id: []const u8, buf: []u8) []const u8 {
        const len = @min(account_id.len, buf.len);
        if (len == 0) {
            // Empty account_id would yield a dangling trailing dash; use a stable stem.
            const fallback = "default";
            const n = @min(fallback.len, buf.len);
            @memcpy(buf[0..n], fallback[0..n]);
            return buf[0..n];
        }
        for (account_id[0..len], 0..) |c, i| {
            buf[i] = if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.') c else '_';
        }
        return buf[0..len];
    }

    fn buildNextBatchStore(
        allocator: std.mem.Allocator,
        account_id: []const u8,
        homeserver: []const u8,
        user_id: ?[]const u8,
        access_token: []const u8,
        token: []const u8,
    ) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);

        const fingerprint = credentialFingerprint(access_token);
        try out.print(allocator, "{{\n  \"version\": {d},\n  \"account_id\": ", .{NEXT_BATCH_STORE_VERSION});
        try root.json_util.appendJsonString(&out, allocator, account_id);
        try out.appendSlice(allocator, ",\n  \"homeserver\": ");
        try root.json_util.appendJsonString(&out, allocator, homeserver);
        try out.appendSlice(allocator, ",\n  \"user_id\": ");
        if (user_id) |value| {
            try root.json_util.appendJsonString(&out, allocator, value);
        } else {
            try out.appendSlice(allocator, "null");
        }
        try out.appendSlice(allocator, ",\n  \"credential_fingerprint\": ");
        try root.json_util.appendJsonString(&out, allocator, &fingerprint);
        try out.appendSlice(allocator, ",\n  \"next_batch\": ");
        try root.json_util.appendJsonString(&out, allocator, token);
        try out.appendSlice(allocator, "\n}\n");
        return out.toOwnedSlice(allocator);
    }

    /// Atomically write a versioned cursor record, creating `dir` if needed.
    /// A unique 0600 temp file is synced and renamed in the same directory. On
    /// failure the previous committed record is left untouched.
    fn writeNextBatchFile(
        allocator: std.mem.Allocator,
        dir: []const u8,
        account_id: []const u8,
        homeserver: []const u8,
        user_id: ?[]const u8,
        access_token: []const u8,
        token: []const u8,
    ) !void {
        if (token.len == 0 or token.len > MAX_NEXT_BATCH_LEN) return error.InvalidNextBatch;
        try fs_compat.makePath(dir);

        const path = try nextBatchPath(allocator, dir, account_id);
        defer allocator.free(path);

        const body = try buildNextBatchStore(allocator, account_id, homeserver, user_id, access_token, token);
        defer allocator.free(body);
        if (body.len > NEXT_BATCH_STORE_MAX_BYTES) return error.NextBatchStoreTooLarge;

        var attempt: u8 = 0;
        while (attempt < 8) : (attempt += 1) {
            const tmp_path = try std.fmt.allocPrint(
                allocator,
                "{s}.tmp-{x}",
                .{ path, std_compat.crypto.random.int(u64) },
            );
            defer allocator.free(tmp_path);

            var tmp_file = std_compat.fs.createFileAbsolute(tmp_path, .{
                .exclusive = true,
                .permissions = std_compat.fs.permissionsFromMode(0o600),
            }) catch |err| switch (err) {
                error.PathAlreadyExists => continue,
                else => return err,
            };
            var file_open = true;
            errdefer {
                if (file_open) tmp_file.close();
                std_compat.fs.deleteFileAbsolute(tmp_path) catch {};
            }

            try tmp_file.writeAll(body);
            try tmp_file.sync();
            tmp_file.close();
            file_open = false;
            try std_compat.fs.renameAbsolute(tmp_path, path);
            return;
        }
        return error.TempFileCreateFailed;
    }

    /// Read a valid, identity-matching persisted token into `out_buf`. Missing
    /// or stale records return 0; malformed and oversized records are errors.
    fn readNextBatchFile(
        allocator: std.mem.Allocator,
        dir: []const u8,
        account_id: []const u8,
        homeserver: []const u8,
        user_id: ?[]const u8,
        access_token: []const u8,
        out_buf: []u8,
    ) !usize {
        const path = try nextBatchPath(allocator, dir, account_id);
        defer allocator.free(path);
        const file = std_compat.fs.openFileAbsolute(path, .{}) catch |err| {
            if (err == error.FileNotFound) return 0;
            return err;
        };
        defer file.close();

        const content = file.readToEndAlloc(allocator, NEXT_BATCH_STORE_MAX_BYTES) catch |err| switch (err) {
            error.StreamTooLong => return error.NextBatchStoreTooLarge,
            else => return err,
        };
        defer allocator.free(content);

        const parsed = std.json.parseFromSlice(NextBatchStore, allocator, content, .{
            .ignore_unknown_fields = true,
        }) catch return error.InvalidNextBatchStore;
        defer parsed.deinit();
        const record = parsed.value;

        const expected_fingerprint = credentialFingerprint(access_token);
        const user_identity_matches = if (user_id) |expected_user_id|
            record.user_id != null and std.mem.eql(u8, record.user_id.?, expected_user_id)
        else
            record.user_id == null and std.mem.eql(u8, record.credential_fingerprint, &expected_fingerprint);
        if (record.version != NEXT_BATCH_STORE_VERSION or
            !std.mem.eql(u8, record.account_id, account_id) or
            !std.mem.eql(u8, record.homeserver, homeserver) or
            !user_identity_matches)
        {
            return 0;
        }
        if (record.next_batch.len == 0 or record.next_batch.len > out_buf.len) {
            return error.InvalidNextBatchStore;
        }

        @memcpy(out_buf[0..record.next_batch.len], record.next_batch);
        return record.next_batch.len;
    }

    /// Resolve `<config dir>/state/matrix`, including relative config paths.
    /// Caller frees.
    pub fn stateDirFromConfigPath(allocator: std.mem.Allocator, config_path: []const u8) ![]u8 {
        const config_dir = std_compat.fs.path.dirname(config_path) orelse ".";
        const relative_path = try std_compat.fs.path.join(allocator, &.{ config_dir, "state", "matrix" });
        defer allocator.free(relative_path);

        if (std_compat.fs.path.isAbsolute(relative_path)) {
            return std_compat.fs.path.resolve(allocator, &.{relative_path});
        }

        const cwd = try std_compat.fs.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd);
        return std_compat.fs.path.resolve(allocator, &.{ cwd, relative_path });
    }

    fn commitNextBatchToDir(self: *MatrixChannel, dir: []const u8) !void {
        if (!self.next_batch_dirty or self.next_batch_len == 0) return;
        try writeNextBatchFile(
            self.allocator,
            dir,
            self.account_id,
            self.homeserver,
            self.user_id,
            self.access_token,
            self.nextBatch(),
        );
        self.next_batch_dirty = false;
    }

    /// Commit the cursor only after the caller has processed the entire batch.
    /// Failures remain dirty and are retried after the next successful poll.
    pub fn commitNextBatch(self: *MatrixChannel, dir: []const u8) void {
        self.commitNextBatchToDir(dir) catch |err| {
            log.warn("matrix: failed to persist next_batch: {}", .{err});
        };
    }

    /// Load a persisted next_batch token into the buffer so a restart resumes
    /// the sync stream at the last committed position rather than running a
    /// fresh initial sync (which silently drops all downtime messages).
    /// Best-effort. Identity mismatches intentionally behave like a fresh sync.
    pub fn loadPersistedNextBatch(self: *MatrixChannel, dir: []const u8) void {
        const n = readNextBatchFile(
            self.allocator,
            dir,
            self.account_id,
            self.homeserver,
            self.user_id,
            self.access_token,
            &self.next_batch_buf,
        ) catch |err| {
            log.warn("matrix: failed to load persisted next_batch: {}", .{err});
            return;
        };
        if (n > 0) {
            self.next_batch_len = n;
            self.next_batch_dirty = false;
            log.info("matrix: resumed sync from persisted next_batch ({d} bytes)", .{n});
        }
    }

    pub fn discardPersistedNextBatch(self: *MatrixChannel, dir: []const u8) void {
        const path = nextBatchPath(self.allocator, dir, self.account_id) catch return;
        defer self.allocator.free(path);
        std_compat.fs.deleteFileAbsolute(path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => log.warn("matrix: failed to discard stale next_batch: {}", .{err}),
        };
    }

    fn authHeader(self: *const MatrixChannel, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{self.access_token});
    }

    fn buildWhoAmIUrl(self: *const MatrixChannel, buf: []u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.writeAll(self.effective_endpoint);
        try w.writeAll("/_matrix/client/v3/account/whoami");
        return w.buffered();
    }

    fn buildSyncUrl(self: *const MatrixChannel, buf: []u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.writeAll(self.effective_endpoint);
        try w.writeAll("/_matrix/client/v3/sync?timeout=30000");
        if (self.next_batch_len > 0) {
            try w.writeAll("&since=");
            try appendUrlEncoded(&w, self.nextBatch());
        }
        return w.buffered();
    }

    fn buildSendUrl(self: *const MatrixChannel, buf: []u8, room_id: []const u8, txn_id: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.writeAll(self.effective_endpoint);
        try w.writeAll("/_matrix/client/v3/rooms/");
        try appendUrlEncoded(&w, room_id);
        try w.writeAll("/send/m.room.message/");
        try appendUrlEncoded(&w, txn_id);
        return w.buffered();
    }

    fn buildTypingUrl(self: *const MatrixChannel, buf: []u8, room_id: []const u8, user_id: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.writeAll(self.effective_endpoint);
        try w.writeAll("/_matrix/client/v3/rooms/");
        try appendUrlEncoded(&w, room_id);
        try w.writeAll("/typing/");
        try appendUrlEncoded(&w, user_id);
        return w.buffered();
    }

    fn buildJoinUrl(self: *const MatrixChannel, buf: []u8, room_id: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.writeAll(self.effective_endpoint);
        try w.writeAll("/_matrix/client/v3/rooms/");
        try appendUrlEncoded(&w, room_id);
        try w.writeAll("/join");
        return w.buffered();
    }

    fn nextTxnId(self: *MatrixChannel, buf: []u8) ![]const u8 {
        self.txn_counter += 1;
        return std.fmt.bufPrint(buf, "nullclaw-{s}-{d}-{d}", .{
            self.account_id,
            std_compat.time.timestamp(),
            self.txn_counter,
        });
    }

    fn normalizeTargetRoom(self: *const MatrixChannel, target: []const u8) ?[]const u8 {
        var t = std.mem.trim(u8, target, " \t\r\n");
        if (t.len == 0) t = self.room_id;
        if (t.len == 0) return null;

        if (std.mem.startsWith(u8, t, "matrix:")) t = std.mem.trim(u8, t["matrix:".len..], " \t\r\n");
        if (std.mem.startsWith(u8, t, "room:")) t = std.mem.trim(u8, t["room:".len..], " \t\r\n");
        if (std.mem.startsWith(u8, t, "channel:")) t = std.mem.trim(u8, t["channel:".len..], " \t\r\n");

        return if (t.len > 0) t else null;
    }

    fn sendMessageChunk(self: *MatrixChannel, room_id: []const u8, chunk: []const u8) !void {
        var txn_buf: [256]u8 = undefined;
        const txn_id = try self.nextTxnId(&txn_buf);

        var url_buf: [2048]u8 = undefined;
        const url = try self.buildSendUrl(&url_buf, room_id, txn_id);

        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);
        var body_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &body_list);
        const w = &body_writer.writer;
        try w.writeAll("{\"msgtype\":\"m.text\",\"body\":");
        try root.appendJsonStringW(w, chunk);
        try w.writeAll("}");
        body_list = body_writer.toArrayList();

        const auth_header = try self.authHeader(self.allocator);
        defer self.allocator.free(auth_header);

        const headers = [_][]const u8{auth_header};
        const resp = try root.http_util.curlPut(self.allocator, url, body_list.items, &headers);
        defer self.allocator.free(resp);

        if (std.mem.indexOf(u8, resp, "\"event_id\"") == null) {
            return error.MatrixSendFailed;
        }
    }

    pub fn sendMessage(self: *MatrixChannel, target: []const u8, message: []const u8) !void {
        const room_id = self.normalizeTargetRoom(target) orelse return error.InvalidTarget;

        const text = std.mem.trim(u8, message, " \t\r\n");
        if (text.len == 0) return;

        var it = root.splitMessage(text, MAX_MESSAGE_LEN);
        while (it.next()) |chunk| {
            const trimmed = std.mem.trim(u8, chunk, " \t\r\n");
            if (trimmed.len == 0) continue;
            try self.sendMessageChunk(room_id, trimmed);
        }
    }

    /// Send Matrix typing indicator (best-effort, errors ignored).
    pub fn sendTypingIndicator(self: *MatrixChannel, target: []const u8) void {
        if (builtin.is_test) return;

        const room_id = self.normalizeTargetRoom(target) orelse return;
        const uid = self.user_id orelse return;
        if (uid.len == 0) return;

        var url_buf: [4096]u8 = undefined;
        const url = self.buildTypingUrl(&url_buf, room_id, uid) catch return;

        const auth_header = self.authHeader(self.allocator) catch return;
        defer self.allocator.free(auth_header);
        const headers = [_][]const u8{auth_header};

        const resp = root.http_util.curlPut(
            self.allocator,
            url,
            "{\"typing\":true,\"timeout\":15000}",
            &headers,
        ) catch return;
        self.allocator.free(resp);
    }

    pub fn startTyping(self: *MatrixChannel, target: []const u8) !void {
        self.sendTypingIndicator(target);
    }

    pub fn stopTyping(_: *MatrixChannel, _: []const u8) !void {}

    pub fn healthCheck(self: *MatrixChannel) bool {
        if (builtin.is_test) return true;

        var url_buf: [1024]u8 = undefined;
        const url = self.buildWhoAmIUrl(&url_buf) catch return false;

        const auth_header = self.authHeader(self.allocator) catch return false;
        defer self.allocator.free(auth_header);
        const headers = [_][]const u8{auth_header};

        const resp = root.http_util.curlGet(self.allocator, url, &headers, "10") catch return false;
        defer self.allocator.free(resp);

        return std.mem.indexOf(u8, resp, "\"user_id\"") != null;
    }

    fn dmSenderAllowed(self: *const MatrixChannel, sender: []const u8) bool {
        if (std.mem.eql(u8, self.dm_policy, "disabled") or std.mem.eql(u8, self.dm_policy, "deny")) return false;
        if (std.mem.eql(u8, self.dm_policy, "open") or std.mem.eql(u8, self.dm_policy, "allow")) return true;
        if (self.allow_from.len == 0) return false;
        return root.isAllowed(self.allow_from, sender);
    }

    fn groupSenderAllowed(self: *const MatrixChannel, sender: []const u8, is_mention: bool) bool {
        if (std.mem.eql(u8, self.group_policy, "disabled")) return false;
        if (std.mem.eql(u8, self.group_policy, "mention_only")) return is_mention;
        if (self.require_mention and !is_mention) return false;
        if (std.mem.eql(u8, self.group_policy, "open")) return true;

        const effective = if (self.group_allow_from.len > 0) self.group_allow_from else self.allow_from;
        if (effective.len == 0) return false;
        return root.isAllowedScoped("matrix channel", effective, sender);
    }

    fn countUniqueMembers(
        allocator: std.mem.Allocator,
        events_val: std.json.Value,
        members: *std.StringHashMapUnmanaged(void),
    ) !void {
        if (events_val != .array) return;

        for (events_val.array.items) |event| {
            if (event != .object) continue;

            const type_val = event.object.get("type") orelse continue;
            if (type_val != .string or !std.mem.eql(u8, type_val.string, "m.room.member")) continue;

            const state_key_val = event.object.get("state_key") orelse continue;
            if (state_key_val != .string or state_key_val.string.len == 0) continue;

            const content_val = event.object.get("content") orelse continue;
            if (content_val != .object) continue;

            const membership_val = content_val.object.get("membership") orelse continue;
            if (membership_val != .string) continue;

            const membership = membership_val.string;
            if (!std.mem.eql(u8, membership, "join") and !std.mem.eql(u8, membership, "invite")) continue;

            try members.put(allocator, state_key_val.string, {});
        }
    }

    fn eventArrayLooksDirect(events_val: std.json.Value) bool {
        if (eventArrayHasDirectMemberFlag(events_val)) return true;

        var members: std.StringHashMapUnmanaged(void) = .empty;
        defer members.deinit(std.heap.page_allocator);

        countUniqueMembers(std.heap.page_allocator, events_val, &members) catch return false;
        return members.count() > 0 and members.count() <= 2;
    }

    fn inviteSenderForUser(events_val: std.json.Value, user_id: ?[]const u8) ?[]const u8 {
        const uid = user_id orelse return null;
        if (uid.len == 0) return null;
        if (events_val != .array) return null;

        for (events_val.array.items) |event| {
            if (event != .object) continue;

            const type_val = event.object.get("type") orelse continue;
            if (type_val != .string or !std.mem.eql(u8, type_val.string, "m.room.member")) continue;

            const state_key_val = event.object.get("state_key") orelse continue;
            if (state_key_val != .string or !std.mem.eql(u8, state_key_val.string, uid)) continue;

            const sender_val = event.object.get("sender") orelse continue;
            if (sender_val != .string or sender_val.string.len == 0) continue;

            const content_val = event.object.get("content") orelse continue;
            if (content_val != .object) continue;

            const membership_val = content_val.object.get("membership") orelse continue;
            if (membership_val != .string or !std.mem.eql(u8, membership_val.string, "invite")) continue;

            return sender_val.string;
        }

        return null;
    }

    fn groupInviteSenderAllowed(self: *const MatrixChannel, sender: []const u8) bool {
        if (std.mem.eql(u8, self.group_policy, "disabled")) return false;

        const effective = if (self.group_allow_from.len > 0) self.group_allow_from else self.allow_from;
        if (effective.len == 0) return false;
        return root.isAllowed(effective, sender);
    }

    fn extractAutoJoinInviteRoomIds(self: *const MatrixChannel, allocator: std.mem.Allocator, payload: []const u8) ![]const []const u8 {
        var rooms: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (rooms.items) |room_id| allocator.free(room_id);
            rooms.deinit(allocator);
        }

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return &.{};
        defer parsed.deinit();

        if (parsed.value != .object) return &.{};
        const rooms_val = parsed.value.object.get("rooms") orelse return &.{};
        if (rooms_val != .object) return &.{};

        const invite_val = rooms_val.object.get("invite") orelse return &.{};
        if (invite_val != .object) return &.{};

        var it = invite_val.object.iterator();
        while (it.next()) |entry| {
            const room_id = entry.key_ptr.*;
            if (room_id.len == 0) continue;

            if (self.room_id.len > 0 and std.mem.eql(u8, room_id, self.room_id)) {
                try rooms.append(allocator, try allocator.dupe(u8, room_id));
                continue;
            }

            const room = entry.value_ptr.*;
            if (room != .object) continue;

            const invite_state_val = room.object.get("invite_state") orelse continue;
            if (invite_state_val != .object) continue;

            const events_val = invite_state_val.object.get("events") orelse continue;
            const inviter = inviteSenderForUser(events_val, self.user_id) orelse continue;

            if (eventArrayLooksDirect(events_val)) {
                if (!self.dmSenderAllowed(inviter)) continue;
            } else {
                if (!self.groupInviteSenderAllowed(inviter)) continue;
            }

            try rooms.append(allocator, try allocator.dupe(u8, room_id));
        }

        return if (rooms.items.len == 0) &.{} else try rooms.toOwnedSlice(allocator);
    }

    fn acceptInvite(self: *MatrixChannel, room_id: []const u8) !void {
        if (builtin.is_test) return;

        var url_buf: [2048]u8 = undefined;
        const url = try self.buildJoinUrl(&url_buf, room_id);

        const auth_header = try self.authHeader(self.allocator);
        defer self.allocator.free(auth_header);

        const headers = [_][]const u8{auth_header};
        const resp = try root.http_util.curlPost(self.allocator, url, "{}", &headers);
        defer self.allocator.free(resp);
    }

    fn acceptInvitesFromSync(self: *MatrixChannel, allocator: std.mem.Allocator, payload: []const u8) !void {
        const invite_room_ids = try self.extractAutoJoinInviteRoomIds(allocator, payload);
        defer {
            for (invite_room_ids) |room_id| allocator.free(room_id);
            if (invite_room_ids.len > 0) allocator.free(invite_room_ids);
        }

        for (invite_room_ids) |room_id| {
            self.acceptInvite(room_id) catch |err| {
                log.warn("Matrix invite auto-join failed for {s}: {}", .{ room_id, err });
            };
        }
    }

    fn eventMentionsUser(self: *const MatrixChannel, content_obj: std.json.ObjectMap, body: []const u8) bool {
        const user_id = self.user_id orelse return false;
        if (user_id.len == 0) return false;

        if (content_obj.get("m.mentions")) |mentions_val| {
            if (mentions_val == .object) {
                if (mentions_val.object.get("user_ids")) |user_ids_val| {
                    if (user_ids_val == .array) {
                        for (user_ids_val.array.items) |item| {
                            if (item == .string and std.mem.eql(u8, item.string, user_id)) return true;
                        }
                    }
                }
            }
        }

        if (content_obj.get("formatted_body")) |formatted_val| {
            if (formatted_val == .string and std.mem.indexOf(u8, formatted_val.string, user_id) != null) return true;
        }

        if (std.mem.indexOf(u8, body, user_id) != null) return true;

        if (std.mem.startsWith(u8, user_id, "@")) {
            const colon_idx = std.mem.indexOfScalar(u8, user_id, ':') orelse user_id.len;
            if (colon_idx > 1) {
                const local = user_id[1..colon_idx];
                var mention_buf: [256]u8 = undefined;
                const handle = std.fmt.bufPrint(&mention_buf, "@{s}", .{local}) catch return false;
                if (std.ascii.indexOfIgnoreCase(body, handle) != null) return true;
            }
        }

        return false;
    }

    fn collectDirectRooms(
        allocator: std.mem.Allocator,
        root_obj: std.json.ObjectMap,
    ) !std.StringHashMapUnmanaged(void) {
        var direct_rooms: std.StringHashMapUnmanaged(void) = .empty;
        errdefer direct_rooms.deinit(allocator);

        const account_data_val = root_obj.get("account_data") orelse return direct_rooms;
        if (account_data_val != .object) return direct_rooms;

        const events_val = account_data_val.object.get("events") orelse return direct_rooms;
        if (events_val != .array) return direct_rooms;

        for (events_val.array.items) |event| {
            if (event != .object) continue;

            const type_val = event.object.get("type") orelse continue;
            if (type_val != .string or !std.mem.eql(u8, type_val.string, "m.direct")) continue;

            const content_val = event.object.get("content") orelse continue;
            if (content_val != .object) continue;

            var users_it = content_val.object.iterator();
            while (users_it.next()) |user_entry| {
                const rooms_val = user_entry.value_ptr.*;
                if (rooms_val != .array) continue;
                for (rooms_val.array.items) |room_id_val| {
                    if (room_id_val != .string or room_id_val.string.len == 0) continue;
                    try direct_rooms.put(allocator, room_id_val.string, {});
                }
            }
        }

        return direct_rooms;
    }

    fn eventArrayHasDirectMemberFlag(events_val: std.json.Value) bool {
        if (events_val != .array) return false;

        for (events_val.array.items) |event| {
            if (event != .object) continue;

            const type_val = event.object.get("type") orelse continue;
            if (type_val != .string or !std.mem.eql(u8, type_val.string, "m.room.member")) continue;

            const content_val = event.object.get("content") orelse continue;
            if (content_val != .object) continue;

            const is_direct_val = content_val.object.get("is_direct") orelse continue;
            if (is_direct_val == .bool and is_direct_val.bool) return true;
        }

        return false;
    }

    fn roomLooksDirect(
        room_id: []const u8,
        room: std.json.Value,
        direct_rooms: *const std.StringHashMapUnmanaged(void),
    ) bool {
        if (direct_rooms.contains(room_id)) return true;
        if (room != .object) return false;

        if (room.object.get("summary")) |summary_val| {
            if (summary_val == .object) {
                var total_members: usize = 0;
                var has_member_counts = false;

                if (summary_val.object.get("m.joined_member_count")) |joined_val| {
                    if (joined_val == .integer and joined_val.integer >= 0) {
                        total_members += @as(usize, @intCast(joined_val.integer));
                        has_member_counts = true;
                    }
                }
                if (summary_val.object.get("m.invited_member_count")) |invited_val| {
                    if (invited_val == .integer and invited_val.integer >= 0) {
                        total_members += @as(usize, @intCast(invited_val.integer));
                        has_member_counts = true;
                    }
                }

                if (has_member_counts and total_members > 0 and total_members <= 2) {
                    return true;
                }
            }
        }

        if (room.object.get("state")) |state_val| {
            if (state_val == .object) {
                if (state_val.object.get("events")) |state_events| {
                    if (eventArrayLooksDirect(state_events)) return true;
                }
            }
        }

        if (room.object.get("timeline")) |timeline_val| {
            if (timeline_val == .object) {
                if (timeline_val.object.get("events")) |timeline_events| {
                    if (eventArrayLooksDirect(timeline_events)) return true;
                }
            }
        }

        return false;
    }

    fn finishSyncResponse(
        self: *MatrixChannel,
        allocator: std.mem.Allocator,
        out: *std.ArrayListUnmanaged(root.ChannelMessage),
        pending_next_batch: ?[]const u8,
    ) ![]root.ChannelMessage {
        const messages = try toOwnedMessages(allocator, out);
        errdefer {
            for (messages) |*msg| msg.deinit(allocator);
            if (messages.len > 0) allocator.free(messages);
        }
        if (pending_next_batch) |token| try self.setNextBatch(token);
        return messages;
    }

    pub fn parseSyncResponse(self: *MatrixChannel, allocator: std.mem.Allocator, payload: []const u8) ![]root.ChannelMessage {
        var out: std.ArrayListUnmanaged(root.ChannelMessage) = .empty;
        errdefer {
            for (out.items) |*msg| msg.deinit(allocator);
            out.deinit(allocator);
        }

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => return &.{},
        };
        defer parsed.deinit();

        if (parsed.value != .object) return &.{};
        const root_obj = parsed.value.object;
        const pending_next_batch: ?[]const u8 = blk: {
            const value = root_obj.get("next_batch") orelse break :blk null;
            if (value != .string or value.string.len == 0) break :blk null;
            if (value.string.len > self.next_batch_buf.len) return error.NextBatchTooLong;
            break :blk value.string;
        };

        var direct_rooms = try collectDirectRooms(allocator, root_obj);
        defer direct_rooms.deinit(allocator);

        const rooms_val = root_obj.get("rooms") orelse
            return self.finishSyncResponse(allocator, &out, pending_next_batch);
        if (rooms_val != .object) return self.finishSyncResponse(allocator, &out, pending_next_batch);

        const join_val = rooms_val.object.get("join") orelse
            return self.finishSyncResponse(allocator, &out, pending_next_batch);
        if (join_val != .object) return self.finishSyncResponse(allocator, &out, pending_next_batch);

        var rooms_it = join_val.object.iterator();
        while (rooms_it.next()) |room_entry| {
            const room_id = room_entry.key_ptr.*;
            const room = room_entry.value_ptr.*;
            const room_is_direct = roomLooksDirect(room_id, room, &direct_rooms);

            if (self.room_id.len > 0 and !std.mem.eql(u8, room_id, self.room_id)) continue;
            if (room != .object) continue;

            const timeline_val = room.object.get("timeline") orelse continue;
            if (timeline_val != .object) continue;
            if (timeline_val.object.get("limited")) |limited_val| {
                if (limited_val == .bool and limited_val.bool) continue;
            }

            const events_val = timeline_val.object.get("events") orelse continue;
            if (events_val != .array) continue;

            for (events_val.array.items) |event| {
                if (event != .object) continue;

                const type_val = event.object.get("type") orelse continue;
                if (type_val != .string) continue;
                if (!std.mem.eql(u8, type_val.string, "m.room.message")) continue;

                const sender_val = event.object.get("sender") orelse continue;
                if (sender_val != .string) continue;
                const sender = sender_val.string;

                if (self.user_id) |uid| {
                    if (std.mem.eql(u8, uid, sender)) continue;
                }

                const content_val = event.object.get("content") orelse continue;
                if (content_val != .object) continue;

                const body_val = content_val.object.get("body") orelse continue;
                if (body_val != .string) continue;
                const body = std.mem.trim(u8, body_val.string, " \t\r\n");
                if (body.len == 0) continue;

                const is_mention = self.eventMentionsUser(content_val.object, body);
                if (room_is_direct) {
                    if (!self.dmSenderAllowed(sender)) continue;
                } else {
                    if (!self.groupSenderAllowed(sender, is_mention)) continue;
                }

                const event_id: []const u8 = blk: {
                    if (event.object.get("event_id")) |eid| {
                        if (eid == .string and eid.string.len > 0) break :blk eid.string;
                    }
                    break :blk "matrix-event";
                };

                const timestamp: u64 = blk: {
                    if (event.object.get("origin_server_ts")) |ts| {
                        if (ts == .integer and ts.integer > 0) {
                            break :blk @as(u64, @intCast(ts.integer)) / 1000;
                        }
                    }
                    break :blk root.nowEpochSecs();
                };

                const owned_id = try allocator.dupe(u8, event_id);
                errdefer allocator.free(owned_id);
                const owned_sender = try allocator.dupe(u8, sender);
                errdefer allocator.free(owned_sender);
                const owned_content = try allocator.dupe(u8, body);
                errdefer allocator.free(owned_content);
                const owned_reply_target = try allocator.dupe(u8, room_id);
                errdefer allocator.free(owned_reply_target);

                try out.append(allocator, .{
                    .id = owned_id,
                    .sender = owned_sender,
                    .content = owned_content,
                    .channel = "matrix",
                    .timestamp = timestamp,
                    .reply_target = owned_reply_target,
                    .is_group = !room_is_direct,
                });
            }
        }

        return self.finishSyncResponse(allocator, &out, pending_next_batch);
    }

    fn responseIndicatesExpiredPosition(allocator: std.mem.Allocator, payload: []const u8) bool {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return false;
        defer parsed.deinit();
        if (parsed.value != .object) return false;
        const errcode = parsed.value.object.get("errcode") orelse return false;
        if (errcode != .string) return false;
        if (std.mem.eql(u8, errcode.string, "M_UNKNOWN_POS")) return true;
        if (!std.mem.eql(u8, errcode.string, "M_UNKNOWN")) return false;
        const message = parsed.value.object.get("error") orelse return false;
        return message == .string and std.mem.startsWith(u8, message.string, "Invalid stream token");
    }

    pub fn pollMessages(self: *MatrixChannel, allocator: std.mem.Allocator) ![]root.ChannelMessage {
        if (builtin.is_test) return &.{};
        const is_initial_sync = self.next_batch_len == 0;

        var url_buf: [4096]u8 = undefined;
        const url = try self.buildSyncUrl(&url_buf);

        const auth_header = try self.authHeader(allocator);
        defer allocator.free(auth_header);
        const headers = [_][]const u8{auth_header};

        const resp = root.http_util.curlGetWithStatusAndTimeout(allocator, url, &headers, "35") catch |err| {
            log.warn("Matrix sync failed: {}", .{err});
            return err;
        };
        defer allocator.free(resp.body);

        if (resp.status_code < 200 or resp.status_code >= 300) {
            if (resp.status_code == 400 and self.next_batch_len > 0 and
                responseIndicatesExpiredPosition(allocator, resp.body))
            {
                // A persisted `since` token may expire server-side. Clear the
                // in-memory position; the loop removes the durable record and
                // performs one fresh sync instead of retrying forever.
                self.next_batch_len = 0;
                self.next_batch_dirty = false;
                return error.MatrixSyncPositionExpired;
            }
            log.warn("Matrix sync returned HTTP status {d}", .{resp.status_code});
            return error.MatrixSyncHttpError;
        }

        if (resp.body.len == 0) return &.{};
        try self.acceptInvitesFromSync(allocator, resp.body);

        const messages = try self.parseSyncResponse(allocator, resp.body);
        if (!is_initial_sync) return messages;

        for (messages) |*msg| msg.deinit(allocator);
        if (messages.len > 0) allocator.free(messages);
        return &.{};
    }

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *MatrixChannel = @ptrCast(@alignCast(ptr));
        self.running = true;
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *MatrixChannel = @ptrCast(@alignCast(ptr));
        self.running = false;
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, media: []const []const u8) anyerror!void {
        const self: *MatrixChannel = @ptrCast(@alignCast(ptr));

        if (message.len > 0) {
            try self.sendMessage(target, message);
        }

        for (media) |item| {
            try self.sendMessage(target, item);
        }
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *MatrixChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *MatrixChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    fn vtableStartTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *MatrixChannel = @ptrCast(@alignCast(ptr));
        try self.startTyping(recipient);
    }

    fn vtableStopTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *MatrixChannel = @ptrCast(@alignCast(ptr));
        try self.stopTyping(recipient);
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
        .startTyping = &vtableStartTyping,
        .stopTyping = &vtableStopTyping,
    };

    pub fn channel(self: *MatrixChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

fn stripTrailingSlashes(url: []const u8) []const u8 {
    var end = url.len;
    while (end > 0 and url[end - 1] == '/') : (end -= 1) {}
    return url[0..end];
}

fn appendUrlEncoded(writer: *std.Io.Writer, text: []const u8) !void {
    try url_percent.appendPercentEncodedWriter(writer, text);
}

fn toOwnedMessages(
    allocator: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(root.ChannelMessage),
) ![]root.ChannelMessage {
    if (list.items.len == 0) {
        list.deinit(allocator);
        return &.{};
    }
    return list.toOwnedSlice(allocator);
}

test "MatrixChannel initFromConfig maps account and policy fields" {
    const cfg = config_types.MatrixConfig{
        .account_id = "work",
        .homeserver = "https://matrix.example/",
        .access_token = "tok",
        .room_id = "!room:example",
        .user_id = "@bot:example",
        .allow_from = &.{"@alice:example"},
        .group_allow_from = &.{"@bob:example"},
        .dm_policy = "open",
        .group_policy = "open",
        .require_mention = true,
    };

    const ch = MatrixChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqualStrings("work", ch.account_id);
    try std.testing.expectEqualStrings("https://matrix.example", ch.homeserver);
    try std.testing.expectEqualStrings("@bot:example", ch.user_id.?);
    try std.testing.expectEqualStrings("open", ch.dm_policy);
    try std.testing.expectEqualStrings("open", ch.group_policy);
    try std.testing.expect(ch.require_mention);
    try std.testing.expectEqual(@as(usize, 1), ch.allow_from.len);
    try std.testing.expectEqual(@as(usize, 1), ch.group_allow_from.len);
    try std.testing.expectEqualStrings("https://matrix.example", ch.effective_endpoint);
}

test "MatrixChannel initFromConfig routes through pantalaimon when proxy is set" {
    const cfg = config_types.MatrixConfig{
        .homeserver = "https://matrix.example/",
        .access_token = "tok",
        .room_id = "!room:example",
        .allow_from = &.{"*"},
        .pantalaimon_proxy_url = "http://localhost:8008/",
    };
    const ch = MatrixChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqualStrings("https://matrix.example", ch.homeserver);
    try std.testing.expectEqualStrings("http://localhost:8008", ch.effective_endpoint);
}

test "MatrixChannel initFromConfig falls back to homeserver when proxy is null" {
    const cfg = config_types.MatrixConfig{
        .homeserver = "https://matrix.example/",
        .access_token = "tok",
        .room_id = "!room:example",
        .allow_from = &.{"*"},
        .pantalaimon_proxy_url = null,
    };
    const ch = MatrixChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqualStrings("https://matrix.example", ch.effective_endpoint);
}

test "MatrixChannel URL builders use effective_endpoint" {
    var ch = MatrixChannel.initFromConfig(std.testing.allocator, .{
        .homeserver = "https://matrix.example/",
        .access_token = "tok",
        .room_id = "!room:example",
        .allow_from = &.{"*"},
        .pantalaimon_proxy_url = "http://localhost:8008",
    });
    var buf: [512]u8 = undefined;

    // Regression: every Matrix Client-Server API URL must route through
    // Pantalaimon when the proxy endpoint is configured.
    const whoami_url = try ch.buildWhoAmIUrl(&buf);
    try std.testing.expect(std.mem.startsWith(u8, whoami_url, "http://localhost:8008/_matrix/"));

    const sync_url = try ch.buildSyncUrl(&buf);
    try std.testing.expect(std.mem.startsWith(u8, sync_url, "http://localhost:8008/_matrix/"));

    const send_url = try ch.buildSendUrl(&buf, "!room:example", "txn-1");
    try std.testing.expect(std.mem.startsWith(u8, send_url, "http://localhost:8008/_matrix/"));

    const typing_url = try ch.buildTypingUrl(&buf, "!room:example", "@bot:example");
    try std.testing.expect(std.mem.startsWith(u8, typing_url, "http://localhost:8008/_matrix/"));

    const join_url = try ch.buildJoinUrl(&buf, "!room:example");
    try std.testing.expect(std.mem.startsWith(u8, join_url, "http://localhost:8008/_matrix/"));
}

test "MatrixChannel buildTypingUrl encodes room and user ids" {
    var ch = MatrixChannel.init(
        std.testing.allocator,
        "https://matrix.example",
        "tok",
        "!room:example",
        &.{"*"},
    );
    ch.user_id = "@bot:example";

    var buf: [512]u8 = undefined;
    const url = try ch.buildTypingUrl(&buf, "!room:example", "@bot:example");
    try std.testing.expectEqualStrings(
        "https://matrix.example/_matrix/client/v3/rooms/%21room%3Aexample/typing/%40bot%3Aexample",
        url,
    );
}

test "MatrixChannel sendTypingIndicator is no-op in tests" {
    var ch = MatrixChannel.init(
        std.testing.allocator,
        "https://matrix.example",
        "tok",
        "!room:example",
        &.{"*"},
    );
    ch.user_id = "@bot:example";
    ch.sendTypingIndicator("!room:example");
}

test "MatrixChannel startTyping and stopTyping are safe in tests" {
    var ch = MatrixChannel.init(
        std.testing.allocator,
        "https://matrix.example",
        "tok",
        "!room:example",
        &.{"*"},
    );
    ch.user_id = "@bot:example";
    try ch.startTyping("!room:example");
    try ch.stopTyping("!room:example");
}

test "MatrixChannel parseSyncResponse extracts messages and next_batch" {
    const allocator = std.testing.allocator;

    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "!room:example",
        &.{"*"},
    );

    const payload =
        \\{
        \\  "next_batch": "s123",
        \\  "rooms": {
        \\    "join": {
        \\      "!room:example": {
        \\        "timeline": {
        \\          "events": [
        \\            {
        \\              "type": "m.room.message",
        \\              "sender": "@alice:example",
        \\              "event_id": "$evt1",
        \\              "origin_server_ts": 1700000000000,
        \\              "content": {
        \\                "msgtype": "m.text",
        \\                "body": "hello"
        \\              }
        \\            }
        \\          ]
        \\        }
        \\      },
        \\      "!other:example": {
        \\        "timeline": {
        \\          "events": [
        \\            {
        \\              "type": "m.room.message",
        \\              "sender": "@bob:example",
        \\              "event_id": "$evt2",
        \\              "origin_server_ts": 1700000000000,
        \\              "content": { "msgtype": "m.text", "body": "ignored" }
        \\            }
        \\          ]
        \\        }
        \\      }
        \\    }
        \\  }
        \\}
    ;

    const msgs = try ch.parseSyncResponse(allocator, payload);
    defer {
        for (msgs) |*m| m.deinit(allocator);
        if (msgs.len > 0) allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("$evt1", msgs[0].id);
    try std.testing.expectEqualStrings("@alice:example", msgs[0].sender);
    try std.testing.expectEqualStrings("hello", msgs[0].content);
    try std.testing.expectEqualStrings("!room:example", msgs[0].reply_target.?);
    try std.testing.expect(msgs[0].is_group);
    try std.testing.expectEqualStrings("s123", ch.nextBatch());
    // Regression: parsing stages the cursor but must not durably commit it
    // before the caller has processed every event in this batch.
    try std.testing.expect(ch.next_batch_dirty);
}

test "MatrixChannel parseSyncResponse marks m.direct rooms as direct chats" {
    const allocator = std.testing.allocator;

    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "!dm:example",
        &.{"@alice:example"},
    );

    const payload =
        \\{
        \\  "account_data": {
        \\    "events": [
        \\      {
        \\        "type": "m.direct",
        \\        "content": {
        \\          "@alice:example": ["!dm:example"]
        \\        }
        \\      }
        \\    ]
        \\  },
        \\  "rooms": {
        \\    "join": {
        \\      "!dm:example": {
        \\        "timeline": {
        \\          "events": [
        \\            {
        \\              "type": "m.room.message",
        \\              "sender": "@alice:example",
        \\              "event_id": "$evt-dm",
        \\              "content": { "msgtype": "m.text", "body": "hello dm" }
        \\            }
        \\          ]
        \\        }
        \\      }
        \\    }
        \\  }
        \\}
    ;

    const msgs = try ch.parseSyncResponse(allocator, payload);
    defer {
        for (msgs) |*m| m.deinit(allocator);
        if (msgs.len > 0) allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expect(!msgs[0].is_group);
    try std.testing.expectEqualStrings("!dm:example", msgs[0].reply_target.?);
}

test "MatrixChannel parseSyncResponse keeps quiet two-member room as direct chat" {
    const allocator = std.testing.allocator;

    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "!dm:example",
        &.{"@alice:example"},
    );

    const payload =
        \\{
        \\  "rooms": {
        \\    "join": {
        \\      "!dm:example": {
        \\        "summary": {
        \\          "m.joined_member_count": 2
        \\        },
        \\        "timeline": {
        \\          "events": [
        \\            {
        \\              "type": "m.room.message",
        \\              "sender": "@alice:example",
        \\              "event_id": "$evt-dm",
        \\              "content": { "msgtype": "m.text", "body": "hello dm" }
        \\            }
        \\          ]
        \\        }
        \\      }
        \\    }
        \\  }
        \\}
    ;

    const msgs = try ch.parseSyncResponse(allocator, payload);
    defer {
        for (msgs) |*m| m.deinit(allocator);
        if (msgs.len > 0) allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expect(!msgs[0].is_group);
}

test "MatrixChannel parseSyncResponse keeps invited three-member room as group chat" {
    const allocator = std.testing.allocator;

    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "!group:example",
        &.{"@alice:example"},
    );

    const payload =
        \\{
        \\  "rooms": {
        \\    "join": {
        \\      "!group:example": {
        \\        "summary": {
        \\          "m.joined_member_count": 2,
        \\          "m.invited_member_count": 1
        \\        },
        \\        "timeline": {
        \\          "events": [
        \\            {
        \\              "type": "m.room.message",
        \\              "sender": "@alice:example",
        \\              "event_id": "$evt-group",
        \\              "content": { "msgtype": "m.text", "body": "hello group" }
        \\            }
        \\          ]
        \\        }
        \\      }
        \\    }
        \\  }
        \\}
    ;

    const msgs = try ch.parseSyncResponse(allocator, payload);
    defer {
        for (msgs) |*m| m.deinit(allocator);
        if (msgs.len > 0) allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expect(msgs[0].is_group);
}

test "MatrixChannel parseSyncResponse allowlist and policy semantics" {
    const allocator = std.testing.allocator;

    var ch_allow = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "!room:example",
        &.{"@allowed:example"},
    );

    const payload_blocked =
        \\{
        \\  "rooms": { "join": { "!room:example": { "timeline": { "events": [
        \\    {"type":"m.room.message","sender":"@blocked:example","content":{"msgtype":"m.text","body":"x"}}
        \\  ]}}}}
        \\}
    ;
    const blocked = try ch_allow.parseSyncResponse(allocator, payload_blocked);
    defer {
        for (blocked) |*m| m.deinit(allocator);
        if (blocked.len > 0) allocator.free(blocked);
    }
    try std.testing.expectEqual(@as(usize, 0), blocked.len);

    var ch_open = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "!room:example",
        &.{},
    );
    ch_open.group_policy = "open";

    const payload_open =
        \\{
        \\  "rooms": { "join": { "!room:example": { "timeline": { "events": [
        \\    {"type":"m.room.message","sender":"@someone:example","content":{"msgtype":"m.text","body":"ok"}}
        \\  ]}}}}
        \\}
    ;
    const open_msgs = try ch_open.parseSyncResponse(allocator, payload_open);
    defer {
        for (open_msgs) |*m| m.deinit(allocator);
        if (open_msgs.len > 0) allocator.free(open_msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), open_msgs.len);
}

test "MatrixChannel parseSyncResponse mention_only requires mention in group rooms" {
    const allocator = std.testing.allocator;

    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "!room:example",
        &.{"*"},
    );
    ch.user_id = "@bot:example";
    ch.group_policy = "mention_only";

    const payload =
        \\{
        \\  "rooms": { "join": { "!room:example": { "timeline": { "events": [
        \\    {"type":"m.room.message","sender":"@alice:example","event_id":"$evt-a","content":{"msgtype":"m.text","body":"hello"}},
        \\    {"type":"m.room.message","sender":"@bob:example","event_id":"$evt-b","content":{"msgtype":"m.text","body":"ping","m.mentions":{"user_ids":["@bot:example"]}}}
        \\  ]}}}}
        \\}
    ;

    const msgs = try ch.parseSyncResponse(allocator, payload);
    defer {
        for (msgs) |*m| m.deinit(allocator);
        if (msgs.len > 0) allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("@bob:example", msgs[0].sender);
}

test "MatrixChannel parseSyncResponse dm_policy disabled blocks direct messages" {
    const allocator = std.testing.allocator;

    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "!dm:example",
        &.{"@alice:example"},
    );
    ch.dm_policy = "disabled";

    const payload =
        \\{
        \\  "account_data": {
        \\    "events": [
        \\      {
        \\        "type": "m.direct",
        \\        "content": {
        \\          "@alice:example": ["!dm:example"]
        \\        }
        \\      }
        \\    ]
        \\  },
        \\  "rooms": { "join": { "!dm:example": { "timeline": { "events": [
        \\    {"type":"m.room.message","sender":"@alice:example","content":{"msgtype":"m.text","body":"hello"}}
        \\  ]}}}}
        \\}
    ;

    const msgs = try ch.parseSyncResponse(allocator, payload);
    defer {
        for (msgs) |*m| m.deinit(allocator);
        if (msgs.len > 0) allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "MatrixChannel parseSyncResponse drops all when group_policy is disabled" {
    const allocator = std.testing.allocator;

    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "!room:example",
        &.{"*"},
    );
    ch.group_policy = "disabled";

    const payload =
        \\{
        \\  "rooms": { "join": { "!room:example": { "timeline": { "events": [
        \\    {"type":"m.room.message","sender":"@alice:example","content":{"msgtype":"m.text","body":"hello"}}
        \\  ]}}}}
        \\}
    ;

    const msgs = try ch.parseSyncResponse(allocator, payload);
    defer {
        for (msgs) |*m| m.deinit(allocator);
        if (msgs.len > 0) allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "MatrixChannel parseSyncResponse skips self and malformed payload safely" {
    const allocator = std.testing.allocator;

    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "!room:example",
        &.{"*"},
    );
    ch.user_id = "@bot:example";

    const payload =
        \\{
        \\  "rooms": {
        \\    "join": {
        \\      "!room:example": {
        \\        "timeline": {
        \\          "events": [
        \\            {"type":"m.room.message","sender":"@bot:example","content":{"msgtype":"m.text","body":"loop"}},
        \\            {"type":"m.room.message","sender":"@alice:example","content":"bad"},
        \\            {"type":"m.room.member","sender":"@alice:example","content":{}}
        \\          ]
        \\        }
        \\      }
        \\    }
        \\  }
        \\}
    ;

    const msgs = try ch.parseSyncResponse(allocator, payload);
    defer {
        for (msgs) |*m| m.deinit(allocator);
        if (msgs.len > 0) allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 0), msgs.len);

    const malformed = try ch.parseSyncResponse(allocator, "{not json");
    defer {
        for (malformed) |*m| m.deinit(allocator);
        if (malformed.len > 0) allocator.free(malformed);
    }
    try std.testing.expectEqual(@as(usize, 0), malformed.len);
}

test "MatrixChannel parseSyncResponse drops limited timelines as backlog" {
    const allocator = std.testing.allocator;

    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "!room:example",
        &.{"*"},
    );
    ch.group_policy = "open";

    const payload =
        \\{
        \\  "rooms": { "join": { "!room:example": { "timeline": {
        \\    "limited": true,
        \\    "events": [
        \\      {"type":"m.room.message","sender":"@alice:example","content":{"msgtype":"m.text","body":"old backlog"}}
        \\    ]
        \\  }}}}
        \\}
    ;

    const msgs = try ch.parseSyncResponse(allocator, payload);
    defer {
        for (msgs) |*m| m.deinit(allocator);
        if (msgs.len > 0) allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 0), msgs.len);
}

test "MatrixChannel extractAutoJoinInviteRoomIds includes configured room invites" {
    const allocator = std.testing.allocator;
    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "!room:example",
        &.{},
    );

    const payload =
        \\{
        \\  "rooms": {
        \\    "invite": {
        \\      "!room:example": {},
        \\      "!other:example": {}
        \\    }
        \\  }
        \\}
    ;

    const invite_room_ids = try ch.extractAutoJoinInviteRoomIds(allocator, payload);
    defer {
        for (invite_room_ids) |room_id| allocator.free(room_id);
        if (invite_room_ids.len > 0) allocator.free(invite_room_ids);
    }

    try std.testing.expectEqual(@as(usize, 1), invite_room_ids.len);
    try std.testing.expectEqualStrings("!room:example", invite_room_ids[0]);
}

test "MatrixChannel extractAutoJoinInviteRoomIds accepts allowlisted direct invite" {
    const allocator = std.testing.allocator;
    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "",
        &.{"@alice:example"},
    );
    ch.user_id = "@bot:example";

    const payload =
        \\{
        \\  "rooms": {
        \\    "invite": {
        \\      "!dm:example": {
        \\        "invite_state": {
        \\          "events": [
        \\            {"type":"m.room.member","sender":"@alice:example","state_key":"@bot:example","content":{"membership":"invite"}},
        \\            {"type":"m.room.member","sender":"@alice:example","state_key":"@alice:example","content":{"membership":"join","is_direct":true}}
        \\          ]
        \\        }
        \\      }
        \\    }
        \\  }
        \\}
    ;

    const invite_room_ids = try ch.extractAutoJoinInviteRoomIds(allocator, payload);
    defer {
        for (invite_room_ids) |room_id| allocator.free(room_id);
        if (invite_room_ids.len > 0) allocator.free(invite_room_ids);
    }

    try std.testing.expectEqual(@as(usize, 1), invite_room_ids.len);
    try std.testing.expectEqualStrings("!dm:example", invite_room_ids[0]);
}

test "MatrixChannel extractAutoJoinInviteRoomIds rejects unknown invite senders" {
    const allocator = std.testing.allocator;
    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "",
        &.{"@alice:example"},
    );
    ch.user_id = "@bot:example";

    const payload =
        \\{
        \\  "rooms": {
        \\    "invite": {
        \\      "!dm:example": {
        \\        "invite_state": {
        \\          "events": [
        \\            {"type":"m.room.member","sender":"@mallory:example","state_key":"@bot:example","content":{"membership":"invite"}},
        \\            {"type":"m.room.member","sender":"@mallory:example","state_key":"@mallory:example","content":{"membership":"join","is_direct":true}}
        \\          ]
        \\        }
        \\      }
        \\    }
        \\  }
        \\}
    ;

    const invite_room_ids = try ch.extractAutoJoinInviteRoomIds(allocator, payload);
    defer {
        for (invite_room_ids) |room_id| allocator.free(room_id);
        if (invite_room_ids.len > 0) allocator.free(invite_room_ids);
    }

    try std.testing.expectEqual(@as(usize, 0), invite_room_ids.len);
}

test "MatrixChannel parseSyncResponse group_allow_from overrides fallback allow_from" {
    const allocator = std.testing.allocator;

    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "!room:example",
        &.{"@alice:example"},
    );
    ch.group_allow_from = &.{"@bob:example"};
    ch.group_policy = "allowlist";

    const payload =
        \\{
        \\  "rooms": { "join": { "!room:example": { "timeline": { "events": [
        \\    {"type":"m.room.message","sender":"@alice:example","event_id":"$evt-a","content":{"msgtype":"m.text","body":"blocked"}},
        \\    {"type":"m.room.message","sender":"@bob:example","event_id":"$evt-b","content":{"msgtype":"m.text","body":"allowed"}}
        \\  ]}}}}
        \\}
    ;

    const msgs = try ch.parseSyncResponse(allocator, payload);
    defer {
        for (msgs) |*m| m.deinit(allocator);
        if (msgs.len > 0) allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    try std.testing.expectEqualStrings("@bob:example", msgs[0].sender);
    try std.testing.expectEqualStrings("allowed", msgs[0].content);
}

test "MatrixChannel parseSyncResponse with empty room_id accepts multiple rooms" {
    const allocator = std.testing.allocator;

    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "tok",
        "",
        &.{"*"},
    );
    ch.group_policy = "open";

    const payload =
        \\{
        \\  "rooms": {
        \\    "join": {
        \\      "!room-a:example": {
        \\        "timeline": {
        \\          "events": [
        \\            {"type":"m.room.message","sender":"@alice:example","event_id":"$evt-a","content":{"msgtype":"m.text","body":"from-a"}}
        \\          ]
        \\        }
        \\      },
        \\      "!room-b:example": {
        \\        "timeline": {
        \\          "events": [
        \\            {"type":"m.room.message","sender":"@bob:example","event_id":"$evt-b","content":{"msgtype":"m.text","body":"from-b"}}
        \\          ]
        \\        }
        \\      }
        \\    }
        \\  }
        \\}
    ;

    const msgs = try ch.parseSyncResponse(allocator, payload);
    defer {
        for (msgs) |*m| m.deinit(allocator);
        if (msgs.len > 0) allocator.free(msgs);
    }

    try std.testing.expectEqual(@as(usize, 2), msgs.len);

    var saw_a = false;
    var saw_b = false;
    for (msgs) |m| {
        if (std.mem.eql(u8, m.reply_target.?, "!room-a:example") and std.mem.eql(u8, m.content, "from-a")) {
            saw_a = true;
        }
        if (std.mem.eql(u8, m.reply_target.?, "!room-b:example") and std.mem.eql(u8, m.content, "from-b")) {
            saw_b = true;
        }
    }
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
}

test "MatrixChannel create + healthCheck + stop leaks zero bytes" {
    // MatrixChannel holds no heap allocations at init-time.  No deinit needed.
    var ch_struct = MatrixChannel.initFromConfig(std.testing.allocator, .{
        .homeserver = "https://matrix.example.com",
        .access_token = "test-access-token",
        .room_id = "!test-room:example.com",
    });

    const ch = ch_struct.channel();
    _ = ch.healthCheck();
    ch.stop();
}

test "MatrixChannel start + stop under is_test leaks zero bytes" {
    // vtableStart sets self.running = true only — no I/O, no thread.
    // Double stop must be idempotent per Channel contract.
    var ch_struct = MatrixChannel.initFromConfig(std.testing.allocator, .{
        .homeserver = "https://matrix.example.com",
        .access_token = "test-access-token",
        .room_id = "!test-room:example.com",
    });

    const ch = ch_struct.channel();
    try ch.start();
    ch.stop();
    // Double stop — must not double-free or crash.
    ch.stop();
}

test "MatrixChannel nextBatchChanged only flags actual position advances" {
    // Regression: Matrix /sync returns a fresh next_batch on every cycle,
    // including idle long-poll timeouts. Identical tokens must not cause an
    // unnecessary copy, while a failed durable commit remains dirty for retry.
    var ch = MatrixChannel.init(
        std.testing.allocator,
        "https://matrix.example",
        "tok",
        "!room:example",
        &.{"*"},
    );

    // Empty buffer → anything is a change.
    try std.testing.expect(ch.nextBatchChanged("abc"));

    try ch.setNextBatch("abc");
    try std.testing.expect(ch.next_batch_dirty);
    // Same token → no change (this is the idle /sync case).
    try std.testing.expect(!ch.nextBatchChanged("abc"));
    try ch.setNextBatch("abc");
    try std.testing.expect(ch.next_batch_dirty);
    // Different content → change.
    try std.testing.expect(ch.nextBatchChanged("abd"));
    // Different length → change.
    try std.testing.expect(ch.nextBatchChanged("ab"));
    try std.testing.expect(ch.nextBatchChanged("abcd"));

    // Opaque Matrix cursors must never be truncated into an invalid token.
    try std.testing.expectError(error.NextBatchTooLong, ch.setNextBatch("s" ++ "a" ** 2000));
    try std.testing.expectEqualStrings("abc", ch.nextBatch());
}

test "MatrixChannel next_batch persistence is identity-bound and roundtrips" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Resolve absolute path of the tmp dir.
    const dir = blk: {
        var buf: [4096]u8 = undefined;
        const path = try std_compat.fs.Dir.wrap(tmp.dir).realpath(".", &buf);
        break :blk try allocator.dupe(u8, path);
    };
    defer allocator.free(dir);

    // Write a token, read it back.
    try MatrixChannel.writeNextBatchFile(
        allocator,
        dir,
        "test-account",
        "https://matrix.example",
        null,
        "test-access-token",
        "s123456",
    );
    var read_buf: [1024]u8 = undefined;
    const n = try MatrixChannel.readNextBatchFile(
        allocator,
        dir,
        "test-account",
        "https://matrix.example",
        null,
        "test-access-token",
        &read_buf,
    );
    try std.testing.expectEqual(@as(usize, 7), n);
    try std.testing.expectEqualStrings("s123456", read_buf[0..n]);

    // Missing file → 0 (not an error).
    const n2 = try MatrixChannel.readNextBatchFile(
        allocator,
        dir,
        "nonexistent",
        "https://matrix.example",
        null,
        "test-access-token",
        &read_buf,
    );
    try std.testing.expectEqual(@as(usize, 0), n2);

    // A reused account id cannot consume a cursor from another server or token.
    const wrong_server = try MatrixChannel.readNextBatchFile(
        allocator,
        dir,
        "test-account",
        "https://other.example",
        null,
        "test-access-token",
        &read_buf,
    );
    try std.testing.expectEqual(@as(usize, 0), wrong_server);
    const wrong_credential = try MatrixChannel.readNextBatchFile(
        allocator,
        dir,
        "test-account",
        "https://matrix.example",
        null,
        "different-token",
        &read_buf,
    );
    try std.testing.expectEqual(@as(usize, 0), wrong_credential);

    // When a stable Matrix user id is configured, ordinary access-token
    // rotation must not invalidate that user's cursor.
    try MatrixChannel.writeNextBatchFile(
        allocator,
        dir,
        "configured-user",
        "https://matrix.example",
        "@bot:example",
        "old-access-token",
        "user-cursor",
    );
    const after_token_rotation = try MatrixChannel.readNextBatchFile(
        allocator,
        dir,
        "configured-user",
        "https://matrix.example",
        "@bot:example",
        "new-access-token",
        &read_buf,
    );
    try std.testing.expectEqualStrings("user-cursor", read_buf[0..after_token_rotation]);
    const wrong_user = try MatrixChannel.readNextBatchFile(
        allocator,
        dir,
        "configured-user",
        "https://matrix.example",
        "@other:example",
        "old-access-token",
        &read_buf,
    );
    try std.testing.expectEqual(@as(usize, 0), wrong_user);

    // Atomic replace → new value.
    try MatrixChannel.writeNextBatchFile(
        allocator,
        dir,
        "test-account",
        "https://matrix.example",
        null,
        "test-access-token",
        "s999",
    );
    const n3 = try MatrixChannel.readNextBatchFile(
        allocator,
        dir,
        "test-account",
        "https://matrix.example",
        null,
        "test-access-token",
        &read_buf,
    );
    try std.testing.expectEqual(@as(usize, 4), n3);
    try std.testing.expectEqualStrings("s999", read_buf[0..n3]);

    if (comptime builtin.os.tag != .windows) {
        const path = try MatrixChannel.nextBatchPath(allocator, dir, "test-account");
        defer allocator.free(path);
        const file = try std_compat.fs.openFileAbsolute(path, .{});
        defer file.close();
        const stat = try file.stat();
        try std.testing.expectEqual(@as(std_compat.fs.File.Mode, 0), stat.mode & 0o077);
    }

    const corrupt_path = try MatrixChannel.nextBatchPath(allocator, dir, "corrupt-account");
    defer allocator.free(corrupt_path);
    const corrupt_file = try std_compat.fs.createFileAbsolute(corrupt_path, .{});
    try corrupt_file.writeAll("not-json");
    corrupt_file.close();
    try std.testing.expectError(
        error.InvalidNextBatchStore,
        MatrixChannel.readNextBatchFile(
            allocator,
            dir,
            "corrupt-account",
            "https://matrix.example",
            null,
            "test-access-token",
            &read_buf,
        ),
    );

    const nested_dir = try std_compat.fs.path.join(allocator, &.{ dir, "nested", "state", "matrix" });
    defer allocator.free(nested_dir);
    try MatrixChannel.writeNextBatchFile(
        allocator,
        nested_dir,
        "nested-account",
        "https://matrix.example",
        null,
        "test-access-token",
        "nested-cursor",
    );
    const nested_n = try MatrixChannel.readNextBatchFile(
        allocator,
        nested_dir,
        "nested-account",
        "https://matrix.example",
        null,
        "test-access-token",
        &read_buf,
    );
    try std.testing.expectEqualStrings("nested-cursor", read_buf[0..nested_n]);

    const oversized_path = try MatrixChannel.nextBatchPath(allocator, dir, "oversized-account");
    defer allocator.free(oversized_path);
    const oversized_file = try std_compat.fs.createFileAbsolute(oversized_path, .{});
    const oversized_body: [MatrixChannel.NEXT_BATCH_STORE_MAX_BYTES + 1]u8 = @splat('x');
    try oversized_file.writeAll(&oversized_body);
    oversized_file.close();
    try std.testing.expectError(
        error.NextBatchStoreTooLarge,
        MatrixChannel.readNextBatchFile(
            allocator,
            dir,
            "oversized-account",
            "https://matrix.example",
            null,
            "test-access-token",
            &read_buf,
        ),
    );
    try std.testing.expectError(
        error.NextBatchStoreTooLarge,
        MatrixChannel.writeNextBatchFile(
            allocator,
            dir,
            "oversized-writer-account",
            "h" ** (MatrixChannel.NEXT_BATCH_STORE_MAX_BYTES + 1),
            null,
            "test-access-token",
            "cursor",
        ),
    );
}

test "MatrixChannel next_batch commit is delayed and retries after failure" {
    // Regression: persisting in parseSyncResponse could advance the durable
    // cursor before the corresponding events were processed, losing them on a
    // crash. A failed write must also remain dirty for a later retry.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const dir = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(dir);

    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "test-access-token",
        "!room:example",
        &.{"*"},
    );
    ch.account_id = "test-account";
    try ch.setNextBatch("s123456");
    try std.testing.expect(ch.next_batch_dirty);

    var read_buf: [MatrixChannel.MAX_NEXT_BATCH_LEN]u8 = undefined;
    const before_commit = try MatrixChannel.readNextBatchFile(
        allocator,
        dir,
        ch.account_id,
        ch.homeserver,
        ch.user_id,
        ch.access_token,
        &read_buf,
    );
    try std.testing.expectEqual(@as(usize, 0), before_commit);

    const blocking_file = try std_compat.fs.path.join(allocator, &.{ dir, "not-a-directory" });
    defer allocator.free(blocking_file);
    const file = try std_compat.fs.createFileAbsolute(blocking_file, .{});
    file.close();
    const invalid_dir = try std_compat.fs.path.join(allocator, &.{ blocking_file, "matrix" });
    defer allocator.free(invalid_dir);

    var failed = false;
    ch.commitNextBatchToDir(invalid_dir) catch {
        failed = true;
    };
    try std.testing.expect(failed);
    try std.testing.expect(ch.next_batch_dirty);

    try ch.commitNextBatchToDir(dir);
    try std.testing.expect(!ch.next_batch_dirty);

    var resumed = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "test-access-token",
        "!room:example",
        &.{"*"},
    );
    resumed.account_id = "test-account";
    resumed.loadPersistedNextBatch(dir);
    try std.testing.expectEqualStrings("s123456", resumed.nextBatch());
    try std.testing.expect(!resumed.next_batch_dirty);

    resumed.discardPersistedNextBatch(dir);
    const discarded = try MatrixChannel.readNextBatchFile(
        allocator,
        dir,
        resumed.account_id,
        resumed.homeserver,
        resumed.user_id,
        resumed.access_token,
        &read_buf,
    );
    try std.testing.expectEqual(@as(usize, 0), discarded);
}

test "MatrixChannel next_batch paths do not collide after sanitization" {
    const allocator = std.testing.allocator;
    const path_a = try MatrixChannel.nextBatchPath(allocator, "/tmp", "work/a");
    defer allocator.free(path_a);
    const path_b = try MatrixChannel.nextBatchPath(allocator, "/tmp", "work?a");
    defer allocator.free(path_b);
    try std.testing.expect(!std.mem.eql(u8, path_a, path_b));

    const long_a = "a" ** 80 ++ "x";
    const long_b = "a" ** 80 ++ "y";
    const long_path_a = try MatrixChannel.nextBatchPath(allocator, "/tmp", long_a);
    defer allocator.free(long_path_a);
    const long_path_b = try MatrixChannel.nextBatchPath(allocator, "/tmp", long_b);
    defer allocator.free(long_path_b);
    try std.testing.expect(!std.mem.eql(u8, long_path_a, long_path_b));
}

test "MatrixChannel state directory follows config path" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root_dir = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_dir);
    const config_path = try std_compat.fs.path.join(allocator, &.{ root_dir, "portable", "config.json" });
    defer allocator.free(config_path);
    const expected = try std_compat.fs.path.join(allocator, &.{ root_dir, "portable", "state", "matrix" });
    defer allocator.free(expected);

    const actual = try MatrixChannel.stateDirFromConfigPath(allocator, config_path);
    defer allocator.free(actual);
    try std.testing.expectEqualStrings(expected, actual);

    const cwd = try std_compat.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    const expected_relative = try std_compat.fs.path.resolve(allocator, &.{ cwd, "portable", "state", "matrix" });
    defer allocator.free(expected_relative);
    const actual_relative = try MatrixChannel.stateDirFromConfigPath(allocator, "portable/config.json");
    defer allocator.free(actual_relative);
    try std.testing.expectEqualStrings(expected_relative, actual_relative);
}

fn parseSyncResponseCursorAllocationTest(allocator: std.mem.Allocator) !void {
    var ch = MatrixChannel.init(
        allocator,
        "https://matrix.example",
        "test-access-token",
        "!room:example",
        &.{"*"},
    );
    try ch.setNextBatch("old-cursor");
    ch.next_batch_dirty = false;

    const payload =
        \\{
        \\  "next_batch": "new-cursor",
        \\  "rooms": {"join": {"!room:example": {"timeline": {"events": [
        \\    {"type":"m.room.message","sender":"@alice:example","event_id":"$evt","content":{"msgtype":"m.text","body":"hello"}}
        \\  ]}}}}
        \\}
    ;

    const messages = ch.parseSyncResponse(allocator, payload) catch |err| {
        // Regression: an OOM while materializing the batch must leave `since`
        // on the prior cursor so the same events are fetched again.
        try std.testing.expectEqualStrings("old-cursor", ch.nextBatch());
        try std.testing.expect(!ch.next_batch_dirty);
        return err;
    };
    defer {
        for (messages) |*message| message.deinit(allocator);
        if (messages.len > 0) allocator.free(messages);
    }

    try std.testing.expectEqualStrings("new-cursor", ch.nextBatch());
    try std.testing.expect(ch.next_batch_dirty);
}

test "MatrixChannel parseSyncResponse advances cursor only after successful materialization" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        parseSyncResponseCursorAllocationTest,
        .{},
    );
}

test "MatrixChannel recognizes expired sync position responses" {
    const allocator = std.testing.allocator;
    try std.testing.expect(MatrixChannel.responseIndicatesExpiredPosition(
        allocator,
        "{\"errcode\":\"M_UNKNOWN_POS\",\"error\":\"stale since\"}",
    ));
    try std.testing.expect(MatrixChannel.responseIndicatesExpiredPosition(
        allocator,
        "{\"errcode\":\"M_UNKNOWN\",\"error\":\"Invalid stream token 'stale'\"}",
    ));
    try std.testing.expect(!MatrixChannel.responseIndicatesExpiredPosition(
        allocator,
        "{\"errcode\":\"M_FORBIDDEN\"}",
    ));
    try std.testing.expect(!MatrixChannel.responseIndicatesExpiredPosition(
        allocator,
        "{\"errcode\":\"M_UNKNOWN\",\"error\":\"Different error\"}",
    ));
    try std.testing.expect(!MatrixChannel.responseIndicatesExpiredPosition(allocator, "not-json"));
}
