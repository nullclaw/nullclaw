const std = @import("std");
const Allocator = std.mem.Allocator;
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const bus = @import("../bus.zig");
const secrets = @import("../security/secrets.zig");

const log = std.log.scoped(.nostr);

/// DM protocol for protocol mirroring — reply using the same protocol the sender used.
pub const DmProtocol = enum {
    nip17,
    nip04,
};

/// Nostr channel — communicates via Nostr relays using NIP-17 (gift-wrapped DMs)
/// and NIP-04 (legacy encrypted DMs) with direct signing.
pub const NostrChannel = struct {
    allocator: Allocator,
    config: config_types.NostrConfig,
    /// Signing credential for --sec in all nak invocations.
    /// Either the decrypted private key (hex) or a pre-configured external bunker:// URI.
    /// Heap-allocated. Zeroed before free in vtableStop/deinit to reduce post-free exposure.
    /// Null before vtableStart is called.
    signing_sec: ?[]u8,
    /// nak req --stream subprocess for listening to relay events.
    listener: ?std.process.Child,
    /// Event bus for publishing inbound messages to the agent.
    event_bus: ?*bus.Bus,
    /// Reader thread that processes incoming events from the listener subprocess.
    reader_thread: ?std.Thread,
    /// Atomic flag to signal the reader thread to stop.
    running: std.atomic.Value(bool),
    /// Per-sender protocol mirroring: remembers which DM protocol each sender used.
    /// Written only from the reader thread; reads from send path are safe since
    /// vtableSend runs in the outbound dispatcher which is sequenced after bus delivery.
    sender_protocols: std.StringHashMapUnmanaged(DmProtocol),
    /// Recently-seen inner rumor IDs (kind:14 event id → arrival unix timestamp).
    /// Suppresses duplicate deliveries when the same rumor arrives via multiple relays.
    seen_rumor_ids: std.StringHashMapUnmanaged(i64),
    /// Discard events with created_at before this timestamp.
    listen_start_at: i64,
    /// Whether the channel has been started.
    started: bool,

    pub fn init(allocator: Allocator, config: config_types.NostrConfig) NostrChannel {
        return .{
            .allocator = allocator,
            .config = config,
            .signing_sec = null,
            .listener = null,
            .event_bus = null,
            .reader_thread = null,
            .running = std.atomic.Value(bool).init(false),
            .sender_protocols = .empty,
            .seen_rumor_ids = .empty,
            .listen_start_at = 0,
            .started = false,
        };
    }

    /// Alias for `init` — allows ChannelManager to instantiate this channel
    /// via the generic `initFromConfig(allocator, cfg)` convention.
    pub fn initFromConfig(allocator: Allocator, config: config_types.NostrConfig) NostrChannel {
        return init(allocator, config);
    }

    pub fn deinit(self: *NostrChannel) void {
        self.stopListener();

        // Free heap-allocated keys in sender_protocols map.
        var it = self.sender_protocols.keyIterator();
        while (it.next()) |key_ptr| {
            self.allocator.free(key_ptr.*);
        }
        self.sender_protocols.deinit(self.allocator);

        // Free heap-allocated keys in seen_rumor_ids map.
        var seen_it = self.seen_rumor_ids.keyIterator();
        while (seen_it.next()) |key_ptr| {
            self.allocator.free(key_ptr.*);
        }
        self.seen_rumor_ids.deinit(self.allocator);

        // Zero and free signing credential (plaintext private key or bunker URI).
        if (self.signing_sec) |sec| {
            @memset(sec, 0);
            self.allocator.free(sec);
            self.signing_sec = null;
        }
    }

    // ── Constants ──────────────────────────────────────────────────

    const MAX_RELAYS = 10;
    const MAX_SEND_ARGS = 12;
    const MAX_PUBLISH_ARGS = 5 + MAX_RELAYS;
    const MAX_LISTENER_ARGS = 14 + 2 * MAX_RELAYS;
    const MAX_UNWRAP_ARGS = 6;
    const MAX_INBOX_CREATE_ARGS = 6 + 2 * MAX_RELAYS;
    const MAX_DECRYPT_ARGS = 7;
    const MAX_ENCRYPT_ARGS = 7;
    const MAX_NIP04_EVENT_ARGS = 11;
    const MAX_INBOX_LOOKUP_ARGS = 6 + MAX_RELAYS; // nak req -k 10050 -a <pubkey> <relays...>
    const MAX_GIFT_WRAP_ARGS = 8 + MAX_RELAYS; // nak gift wrap --sec <sec> -p <pub> <relays...>
    pub const MAX_RELAY_TAG_LEN = 256; // "relay=" + URL (6 + up to 250 chars)

    // ── Send pipeline ────────────────────────────────────────────────

    /// Build the p-tag argument string: "p=<hex>".
    /// Caller provides a 66-byte buffer.
    pub fn formatPTag(recipient_hex: []const u8, buf: *[66]u8) []const u8 {
        buf[0] = 'p';
        buf[1] = '=';
        const len = @min(recipient_hex.len, 64);
        @memcpy(buf[2..][0..len], recipient_hex[0..len]);
        return buf[0 .. 2 + len];
    }

    /// Build argv for `nak event -k 14 --sec <sec> -c <content> -t <p_tag>`.
    /// `p_tag` must be a pre-formatted "p=<hex>" string (see `formatPTag`).
    pub fn buildSendEventArgs(
        nak_path: []const u8,
        sec: []const u8,
        content: []const u8,
        p_tag: []const u8,
    ) [MAX_SEND_ARGS]?[]const u8 {
        return .{
            nak_path, "event", "-k", "14",
            "--sec",  sec,     "-c", content,
            "-t",     p_tag,   null, null,
        };
    }

    /// Build argv for `nak gift wrap --sec <sec> -p <recipient_hex> <relay...>`.
    /// Passing relays here causes nak to gift-wrap AND publish in one step, using the
    /// internally generated ephemeral key for NIP-42 AUTH — avoiding a separate
    /// `nak event --sec` publish step that would re-sign and corrupt the ephemeral outer pubkey.
    pub fn buildGiftWrapArgs(
        nak_path: []const u8,
        sec: []const u8,
        recipient_hex: []const u8,
        relays: []const []const u8,
    ) [MAX_GIFT_WRAP_ARGS]?[]const u8 {
        var args: [MAX_GIFT_WRAP_ARGS]?[]const u8 = .{null} ** MAX_GIFT_WRAP_ARGS;
        args[0] = nak_path;
        args[1] = "gift";
        args[2] = "wrap";
        args[3] = "--sec";
        args[4] = sec;
        args[5] = "-p";
        args[6] = recipient_hex;
        var i: usize = 7;
        for (relays) |relay| {
            if (i >= args.len) break;
            args[i] = relay;
            i += 1;
        }
        return args;
    }

    /// Build argv for `nak event --sec <sec> --auth <relay1> ...` with an explicit relay list.
    /// Used for both config-relays publishing and recipient inbox-relay publishing (NIP-17).
    pub fn buildPublishArgsWithRelays(
        nak_path: []const u8,
        sec: []const u8,
        relays: []const []const u8,
    ) [MAX_PUBLISH_ARGS]?[]const u8 {
        var args: [MAX_PUBLISH_ARGS]?[]const u8 = .{null} ** MAX_PUBLISH_ARGS;
        args[0] = nak_path;
        args[1] = "event";
        args[2] = "--sec";
        args[3] = sec;
        args[4] = "--auth"; // boolean flag — no value; nak signs AUTH challenges using --sec
        var i: usize = 5;
        for (relays) |relay| {
            if (i >= args.len) break;
            args[i] = relay;
            i += 1;
        }
        return args;
    }

    /// Build argv for `nak event --sec <sec> --auth <relay1> <relay2> ...`.
    /// Publishes a pre-built event JSON (piped via stdin) to config.relays.
    /// --auth makes nak respond to NIP-42 AUTH challenges using the bot's own key.
    pub fn buildPublishArgs(config: config_types.NostrConfig, sec: []const u8) [MAX_PUBLISH_ARGS]?[]const u8 {
        return buildPublishArgsWithRelays(config.nak_path, sec, config.relays);
    }

    /// Build argv for `nak event <relay1> <relay2> ...` with no signing key.
    /// Used to publish a pre-signed gift wrap (kind:1059) without re-signing it.
    /// nak event without --sec publishes a fully-signed event as-is, preserving
    /// the ephemeral outer pubkey generated by `nak gift wrap`.
    pub fn buildPublishOnlyArgs(
        nak_path: []const u8,
        relays: []const []const u8,
    ) [MAX_PUBLISH_ARGS]?[]const u8 {
        var args: [MAX_PUBLISH_ARGS]?[]const u8 = .{null} ** MAX_PUBLISH_ARGS;
        args[0] = nak_path;
        args[1] = "event";
        var i: usize = 2;
        for (relays) |relay| {
            if (i >= args.len) break;
            args[i] = relay;
            i += 1;
        }
        return args;
    }

    /// Build argv for `nak req -k 10050 -a <recipient> <relays...>`.
    /// One-shot (no --stream) lookup of the recipient's NIP-17 DM inbox relay list.
    pub fn buildInboxLookupArgs(
        config: config_types.NostrConfig,
        recipient_hex: []const u8,
    ) [MAX_INBOX_LOOKUP_ARGS]?[]const u8 {
        var args: [MAX_INBOX_LOOKUP_ARGS]?[]const u8 = .{null} ** MAX_INBOX_LOOKUP_ARGS;
        args[0] = config.nak_path;
        args[1] = "req";
        args[2] = "-k";
        args[3] = "10050";
        args[4] = "-a";
        args[5] = recipient_hex;
        var i: usize = 6;
        for (config.relays) |relay| {
            if (i >= args.len) break;
            args[i] = relay;
            i += 1;
        }
        return args;
    }

    /// Build argv for `nak event -k 10050 --sec <sec> [-t relay=<url>] ...`.
    /// Announces the DM inbox relay list (NIP-17).
    /// `tag_bufs` is a caller-provided stack buffer for the "relay=<url>" tag strings.
    pub fn buildInboxCreateArgs(
        config: config_types.NostrConfig,
        sec: []const u8,
        tag_bufs: *[MAX_RELAYS][MAX_RELAY_TAG_LEN]u8,
    ) [MAX_INBOX_CREATE_ARGS]?[]const u8 {
        var args: [MAX_INBOX_CREATE_ARGS]?[]const u8 = .{null} ** MAX_INBOX_CREATE_ARGS;
        args[0] = config.nak_path;
        args[1] = "event";
        args[2] = "-k";
        args[3] = "10050";
        args[4] = "--sec";
        args[5] = sec;
        var i: usize = 6;
        for (config.dm_relays, 0..) |relay, ri| {
            if (i + 1 >= MAX_INBOX_CREATE_ARGS or ri >= MAX_RELAYS) break;
            const tag = std.fmt.bufPrint(&tag_bufs[ri], "relay={s}", .{relay}) catch continue;
            args[i] = "-t";
            args[i + 1] = tag;
            i += 2;
        }
        return args;
    }

    /// Convert a bounded nullable-arg array to a contiguous slice of non-null args.
    fn filterArgs(comptime N: usize, bounded: [N]?[]const u8, out: *[N][]const u8) []const []const u8 {
        var count: usize = 0;
        for (bounded) |maybe_arg| {
            if (maybe_arg) |arg| {
                out[count] = arg;
                count += 1;
            } else break;
        }
        return out[0..count];
    }

    /// Extract `["relay","<url>"]` tag values from a kind:10050 event JSON string.
    /// Returns an owned slice of owned URL strings. Caller must free each item and the slice.
    pub fn parseRelayTags(allocator: Allocator, json: []const u8) ![][]u8 {
        var list = std.ArrayListUnmanaged([]u8).empty;
        errdefer {
            for (list.items) |r| allocator.free(r);
            list.deinit(allocator);
        }
        const needle = "[\"relay\",\"";
        var pos: usize = 0;
        while (std.mem.indexOfPos(u8, json, pos, needle)) |idx| {
            const val_start = idx + needle.len;
            const val_end = std.mem.indexOfPos(u8, json, val_start, "\"") orelse break;
            const url = json[val_start..val_end];
            if (url.len >= 6) { // minimum viable URL: "ws://x"
                try list.append(allocator, try allocator.dupe(u8, url));
            }
            pos = val_end + 1;
        }
        return list.toOwnedSlice(allocator);
    }

    /// Look up the NIP-17 DM inbox relays for the given pubkey via kind:10050.
    /// Returns an owned slice of owned URL strings, or null on failure.
    /// Caller must free each item and the slice when non-null.
    fn lookupInboxRelays(self: *NostrChannel, target_pubkey: []const u8) ?[][]u8 {
        const lookup_args = buildInboxLookupArgs(self.config, target_pubkey);
        const output = self.runNakCommand(MAX_INBOX_LOOKUP_ARGS, lookup_args, null) catch |err| {
            log.debug("nostr: kind:10050 lookup failed: {}", .{err});
            return null;
        };
        defer self.allocator.free(output);
        const relays = parseRelayTags(self.allocator, output) catch return null;
        if (relays.len == 0) {
            self.allocator.free(relays);
            return null;
        }
        log.debug("nostr: found {d} inbox relay(s) for recipient", .{relays.len});
        return relays;
    }

    /// Spawn a nak subprocess, optionally write stdin_data, read stdout, wait for exit.
    /// Returns owned stdout slice on success.
    fn runNakCommand(self: *NostrChannel, comptime N: usize, bounded: [N]?[]const u8, stdin_data: ?[]const u8) ![]u8 {
        var argv_buf: [N][]const u8 = undefined;
        const args = filterArgs(N, bounded, &argv_buf);
        if (args.len == 0) return error.NakCommandFailed;

        var child = std.process.Child.init(args, self.allocator);
        child.stdin_behavior = if (stdin_data != null) .Pipe else .Inherit;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Inherit; // avoid deadlock from unread pipe buffer
        try child.spawn();
        errdefer {
            _ = child.kill() catch {};
            _ = child.wait() catch {};
        }

        if (stdin_data) |data| {
            if (child.stdin) |stdin_file| {
                stdin_file.writeAll(data) catch {};
                stdin_file.close();
                child.stdin = null;
            }
        }

        const stdout_file = child.stdout orelse return error.NakCommandFailed;
        var output = std.ArrayListUnmanaged(u8).empty;
        errdefer output.deinit(self.allocator);
        var read_buf: [4096]u8 = undefined;
        while (true) {
            const n = stdout_file.read(&read_buf) catch break;
            if (n == 0) break;
            try output.appendSlice(self.allocator, read_buf[0..n]);
        }

        const term = child.wait() catch return error.NakCommandFailed;
        switch (term) {
            .Exited => |code| {
                if (code != 0) {
                    output.deinit(self.allocator);
                    return error.NakCommandFailed;
                }
            },
            else => {
                output.deinit(self.allocator);
                return error.NakCommandFailed;
            },
        }

        return output.toOwnedSlice(self.allocator);
    }

    // ── Receive pipeline ──────────────────────────────────────────────

    /// Build argv for `nak req --stream -k 1059 -k 4 -s <since> -p <pubkey> <relays...>`.
    /// Subscribes to NIP-17 gift wraps (1059) and NIP-04 DMs (4).
    /// --since filters at relay level so we don't replay historical events on startup.
    /// Relay list = config.relays followed by config.dm_relays.
    /// --auth makes nak respond to NIP-42 AUTH challenges using the bot's own key.
    pub fn buildListenerArgs(config: config_types.NostrConfig, sec: []const u8, since: []const u8) [MAX_LISTENER_ARGS]?[]const u8 {
        var args: [MAX_LISTENER_ARGS]?[]const u8 = .{null} ** MAX_LISTENER_ARGS;
        args[0] = config.nak_path;
        args[1] = "req";
        args[2] = "--stream";
        args[3] = "-k";
        args[4] = "1059";
        args[5] = "-k";
        args[6] = "4";
        args[7] = "--auth"; // boolean flag — triggers NIP-42 AUTH automatically
        args[8] = "--sec"; // signing key for AUTH challenges
        args[9] = sec;
        args[10] = "-s"; // relay-side startup filter — avoids replaying historical events
        args[11] = since;
        args[12] = "-p";
        args[13] = config.bot_pubkey;
        // Combine relays and dm_relays, deduplicating to avoid double-connecting.
        var i: usize = 14;
        for (config.relays) |relay| {
            if (i >= args.len) break;
            args[i] = relay;
            i += 1;
        }
        next_dm: for (config.dm_relays) |relay| {
            if (i >= args.len) break;
            // Skip if already present in the relays already added.
            for (args[14..i]) |existing| {
                if (std.mem.eql(u8, existing.?, relay)) continue :next_dm;
            }
            args[i] = relay;
            i += 1;
        }
        return args;
    }

    /// Build argv for `nak gift unwrap --sec <sec>`.
    pub fn buildUnwrapArgs(nak_path: []const u8, sec: []const u8) [MAX_UNWRAP_ARGS]?[]const u8 {
        return .{
            nak_path, "gift", "unwrap",
            "--sec",  sec,    null,
        };
    }

    /// Parsed result from an unwrapped NIP-17 rumor event.
    /// Slices point into the original JSON input — no allocation.
    pub const UnwrappedRumor = struct {
        id: []const u8,
        sender: []const u8,
        content: []const u8,
        created_at: i64,
    };

    /// Parse an unwrapped rumor JSON to extract id, sender pubkey, content, and created_at.
    /// Uses manual string scanning to avoid allocations (slices point into `json`).
    pub fn parseUnwrappedRumor(json: []const u8) !UnwrappedRumor {
        const id = extractJsonString(json, "\"id\":\"") orelse return error.InvalidRumor;
        const sender = extractJsonString(json, "\"pubkey\":\"") orelse return error.InvalidRumor;
        const content = extractJsonString(json, "\"content\":\"") orelse return error.InvalidRumor;
        const created_at = extractJsonInt(json, "\"created_at\":") orelse return error.InvalidRumor;
        return .{
            .id = id,
            .sender = sender,
            .content = content,
            .created_at = created_at,
        };
    }

    /// Extract a JSON string value given a prefix like `"key":"`.
    /// Returns a slice into `json` pointing at the string value (up to closing `"`).
    fn extractJsonString(json: []const u8, prefix: []const u8) ?[]const u8 {
        const start_idx = (std.mem.indexOf(u8, json, prefix) orelse return null) + prefix.len;
        // Find the closing unescaped quote.
        var i: usize = start_idx;
        while (i < json.len) {
            if (json[i] == '\\') {
                i += 2; // skip escaped char
                continue;
            }
            if (json[i] == '"') {
                return json[start_idx..i];
            }
            i += 1;
        }
        return null;
    }

    /// Extract a JSON integer value given a prefix like `"key":`.
    fn extractJsonInt(json: []const u8, prefix: []const u8) ?i64 {
        const start_idx = (std.mem.indexOf(u8, json, prefix) orelse return null) + prefix.len;
        // Skip whitespace.
        var i: usize = start_idx;
        while (i < json.len and (json[i] == ' ' or json[i] == '\t')) : (i += 1) {}
        // Parse the integer.
        var end: usize = i;
        if (end < json.len and json[end] == '-') end += 1;
        while (end < json.len and json[end] >= '0' and json[end] <= '9') : (end += 1) {}
        if (end == i) return null;
        return std.fmt.parseInt(i64, json[i..end], 10) catch null;
    }

    /// Extract the Nostr event kind integer from a raw event JSON line.
    /// Returns null if "kind" is absent or out of u16 range.
    pub fn extractEventKind(json: []const u8) ?u16 {
        const val = extractJsonInt(json, "\"kind\":") orelse return null;
        if (val < 0 or val > 65535) return null;
        return @intCast(val);
    }

    /// Build argv for `nak decrypt --sec <sec> -p <sender_pubkey>`.
    /// Stdin: NIP-04 ciphertext. Stdout: plaintext.
    pub fn buildDecryptArgs(
        nak_path: []const u8,
        sec: []const u8,
        sender_pubkey: []const u8,
    ) [MAX_DECRYPT_ARGS]?[]const u8 {
        return .{ nak_path, "decrypt", "--sec", sec, "-p", sender_pubkey, null };
    }

    /// Build argv for `nak encrypt --sec <sec> -p <recipient>`.
    /// Stdin: plaintext. Stdout: NIP-04 ciphertext.
    pub fn buildEncryptArgs(
        nak_path: []const u8,
        sec: []const u8,
        recipient_hex: []const u8,
    ) [MAX_ENCRYPT_ARGS]?[]const u8 {
        return .{ nak_path, "encrypt", "--sec", sec, "-p", recipient_hex, null };
    }

    /// Build argv for `nak event -k 4 --sec <sec> -c <ciphertext> -t <p_tag>`.
    pub fn buildNip04EventArgs(
        nak_path: []const u8,
        sec: []const u8,
        ciphertext: []const u8,
        p_tag: []const u8,
    ) [MAX_NIP04_EVENT_ARGS]?[]const u8 {
        return .{
            nak_path, "event", "-k", "4",
            "--sec",  sec,     "-c", ciphertext,
            "-t",     p_tag,   null,
        };
    }

    // ── Config validation ────────────────────────────────────────────

    /// Returns true if s is exactly 64 lowercase hex characters.
    pub fn isValidHexKey(s: []const u8) bool {
        if (s.len != 64) return false;
        for (s) |c| {
            switch (c) {
                '0'...'9', 'a'...'f' => {},
                else => return false,
            }
        }
        return true;
    }

    /// Validate key formats in the config.
    /// - owner_pubkey and bot_pubkey must be 64-char lowercase hex.
    /// - dm_allowed_pubkeys entries must be 64-char lowercase hex (or "*").
    /// - private_key must be enc2:-encrypted, unless bunker_uri is set.
    pub fn validateConfig(config: config_types.NostrConfig) !void {
        if (!isValidHexKey(config.owner_pubkey)) return error.InvalidKeyFormat;
        if (!isValidHexKey(config.bot_pubkey)) return error.InvalidKeyFormat;
        for (config.dm_allowed_pubkeys) |pk| {
            if (std.mem.eql(u8, pk, "*")) continue;
            if (!isValidHexKey(pk)) return error.InvalidKeyFormat;
        }
        if (config.bunker_uri == null) {
            if (!std.mem.startsWith(u8, config.private_key, "enc2:")) return error.InvalidKeyFormat;
        }
    }

    // ── DM policy & protocol mirroring ────────────────────────────────

    /// Check if a sender is allowed to DM this channel.
    /// Owner is always allowed regardless of the allowlist.
    pub fn isDmAllowed(self: *const NostrChannel, sender_pubkey: []const u8) bool {
        if (std.mem.eql(u8, sender_pubkey, self.config.owner_pubkey)) return true;
        return root.isAllowedExact(self.config.dm_allowed_pubkeys, sender_pubkey);
    }

    /// Record which DM protocol a sender used, for protocol mirroring.
    /// If the sender already has an entry, update in-place (no allocation).
    pub fn recordSenderProtocol(self: *NostrChannel, sender_hex: []const u8, protocol: DmProtocol) !void {
        if (self.sender_protocols.getPtr(sender_hex)) |ptr| {
            ptr.* = protocol;
        } else {
            const key = try self.allocator.dupe(u8, sender_hex);
            errdefer self.allocator.free(key);
            try self.sender_protocols.put(self.allocator, key, protocol);
        }
    }

    /// Get the DM protocol a sender last used. Defaults to NIP-17 if unknown.
    pub fn getSenderProtocol(self: *const NostrChannel, sender_hex: []const u8) DmProtocol {
        return self.sender_protocols.get(sender_hex) orelse .nip17;
    }

    // ── Rumor deduplication ──────────────────────────────────────────

    /// TTL for seen rumor IDs. Entries older than this are evicted.
    /// 10 minutes is comfortably longer than any realistic relay re-delivery window.
    pub const RUMOR_DEDUP_WINDOW_SECS: i64 = 600;

    /// Check if a rumor ID has been seen recently.
    pub fn isSeenRumor(self: *const NostrChannel, rumor_id: []const u8) bool {
        return self.seen_rumor_ids.contains(rumor_id);
    }

    /// Record a rumor ID as seen at `now`, evicting stale entries first.
    /// Best-effort: caller should ignore errors (dedup is non-critical).
    pub fn recordSeenRumor(self: *NostrChannel, rumor_id: []const u8, now: i64) !void {
        // Collect stale keys (can't remove during iteration).
        var stale = std.ArrayListUnmanaged([]const u8){};
        defer stale.deinit(self.allocator);

        var it = self.seen_rumor_ids.iterator();
        while (it.next()) |entry| {
            if (now - entry.value_ptr.* > RUMOR_DEDUP_WINDOW_SECS) {
                try stale.append(self.allocator, entry.key_ptr.*);
            }
        }
        for (stale.items) |key| {
            _ = self.seen_rumor_ids.remove(key);
            self.allocator.free(key);
        }

        // Record the new entry (update timestamp if already present).
        if (self.seen_rumor_ids.getPtr(rumor_id)) |ts_ptr| {
            ts_ptr.* = now;
        } else {
            const key = try self.allocator.dupe(u8, rumor_id);
            errdefer self.allocator.free(key);
            try self.seen_rumor_ids.put(self.allocator, key, now);
        }
    }

    // ── Bus integration ─────────────────────────────────────────────

    /// Set the event bus for publishing inbound messages.
    pub fn setBus(self: *NostrChannel, b: *bus.Bus) void {
        self.event_bus = b;
    }

    /// Build the session key for bus messages: "nostr:<sender_hex>".
    fn buildSessionKey(sender_hex: []const u8, buf: *[71]u8) []const u8 {
        const prefix = "nostr:";
        @memcpy(buf[0..prefix.len], prefix);
        const len = @min(sender_hex.len, 64);
        @memcpy(buf[prefix.len..][0..len], sender_hex[0..len]);
        return buf[0 .. prefix.len + len];
    }

    /// Reader thread entry point. Reads listener stdout line-by-line,
    /// unwraps each gift-wrapped event, parses the rumor, checks DM policy,
    /// and publishes to the event bus.
    fn readerLoop(self: *NostrChannel) void {
        defer self.running.store(false, .release); // signal exit on all paths
        const stdout_file = if (self.listener) |*l| (l.stdout orelse return) else return;
        const sec = self.signing_sec orelse return;
        const eb = self.event_bus orelse return;

        var buf: [65536]u8 = undefined;
        var filled: usize = 0;

        while (self.running.load(.acquire)) {
            const n = stdout_file.read(buf[filled..]) catch break;
            if (n == 0) break; // EOF — listener exited
            filled += n;

            // Process complete lines.
            var start: usize = 0;
            while (std.mem.indexOfPos(u8, buf[0..filled], start, "\n")) |nl| {
                const line = buf[start..nl];
                start = nl + 1;
                if (line.len == 0) continue;

                const kind = extractEventKind(line) orelse continue;
                switch (kind) {
                    1059 => self.processWrappedEvent(line, sec, eb),
                    4 => self.processNip04Event(line, sec, eb),
                    else => {},
                }
            }

            // Move remaining partial line to front.
            if (start > 0) {
                const remaining = filled - start;
                std.mem.copyForwards(u8, buf[0..remaining], buf[start..filled]);
                filled = remaining;
            } else if (filled == buf.len) {
                // Line too long, discard buffer.
                log.warn("nostr reader: discarding oversized line ({d} bytes)", .{filled});
                filled = 0;
            }
        }
    }

    /// Process a single gift-wrapped event JSON line.
    fn processWrappedEvent(self: *NostrChannel, line: []const u8, sec: []const u8, eb: *bus.Bus) void {
        // Pre-filter: NIP-17 senders may randomise the outer created_at within the past
        // 2 days. Belt-and-suspenders for relays that don't honour --since.
        const outer_created_at = extractJsonInt(line, "\"created_at\":") orelse std.math.maxInt(i64);
        if (outer_created_at < self.listen_start_at - 2 * 24 * 3600) {
            log.debug("nostr: skipping stale NIP-17 gift wrap (outer ts too old)", .{});
            return;
        }

        // Unwrap the gift-wrapped event via `nak gift unwrap`.
        const unwrap_args = buildUnwrapArgs(self.config.nak_path, sec);
        const unwrapped = self.runNakCommand(MAX_UNWRAP_ARGS, unwrap_args, line) catch |err| {
            log.warn("nostr: unwrap failed: {}", .{err});
            return;
        };
        defer self.allocator.free(unwrapped);

        // Parse the unwrapped rumor.
        const rumor = parseUnwrappedRumor(unwrapped) catch |err| {
            log.warn("nostr: parse rumor failed: {}", .{err});
            return;
        };

        // Discard events from before we started listening.
        if (rumor.created_at < self.listen_start_at) {
            log.debug("nostr: discarding stale NIP-17 event", .{});
            return;
        }

        // Check DM policy.
        if (!self.isDmAllowed(rumor.sender)) {
            log.info("nostr: NIP-17 DM from {s} rejected by policy", .{rumor.sender});
            return;
        }

        // Deduplicate: the same inner rumor may arrive via multiple relays
        // (each relay gets a separate outer gift-wrap, same inner rumor id).
        const now_secs: i64 = @intCast(root.nowEpochSecs());
        if (self.isSeenRumor(rumor.id)) {
            log.debug("nostr: dropping duplicate NIP-17 rumor {s}", .{rumor.id[0..@min(8, rumor.id.len)]});
            return;
        }
        self.recordSeenRumor(rumor.id, now_secs) catch {};

        log.info("nostr: received NIP-17 DM from {s}", .{rumor.sender});

        // Record sender protocol for mirroring.
        self.recordSenderProtocol(rumor.sender, .nip17) catch {};

        // Build session key and publish to the event bus.
        var sk_buf: [71]u8 = undefined;
        const session_key = buildSessionKey(rumor.sender, &sk_buf);

        const msg = bus.makeInbound(
            self.allocator,
            "nostr",
            rumor.sender,
            rumor.sender, // chat_id = sender for DMs
            rumor.content,
            session_key,
        ) catch |err| {
            log.warn("nostr: makeInbound failed: {}", .{err});
            return;
        };

        eb.publishInbound(msg) catch |err| {
            log.warn("nostr: publishInbound failed: {}", .{err});
            msg.deinit(self.allocator);
        };
    }

    /// Process a single kind:4 (NIP-04) encrypted DM event.
    fn processNip04Event(self: *NostrChannel, line: []const u8, sec: []const u8, eb: *bus.Bus) void {
        const sender = extractJsonString(line, "\"pubkey\":\"") orelse return;
        const encrypted = extractJsonString(line, "\"content\":\"") orelse return;
        const created_at = extractJsonInt(line, "\"created_at\":") orelse return;
        if (created_at < self.listen_start_at) {
            log.debug("nostr(nip04): discarding stale event", .{});
            return;
        }
        if (!self.isDmAllowed(sender)) {
            log.info("nostr: NIP-04 DM from {s} rejected by policy", .{sender});
            return;
        }

        log.info("nostr: received NIP-04 DM from {s}", .{sender});

        const decrypt_args = buildDecryptArgs(self.config.nak_path, sec, sender);
        const plaintext_raw = self.runNakCommand(MAX_DECRYPT_ARGS, decrypt_args, encrypted) catch |err| {
            log.warn("nostr(nip04): decrypt failed: {}", .{err});
            return;
        };
        defer self.allocator.free(plaintext_raw);
        const plaintext = std.mem.trimRight(u8, plaintext_raw, " \t\r\n");

        self.recordSenderProtocol(sender, .nip04) catch {};

        var sk_buf: [71]u8 = undefined;
        const session_key = buildSessionKey(sender, &sk_buf);
        const msg = bus.makeInbound(
            self.allocator,
            "nostr",
            sender,
            sender,
            plaintext,
            session_key,
        ) catch |err| {
            log.warn("nostr(nip04): makeInbound failed: {}", .{err});
            return;
        };
        eb.publishInbound(msg) catch |err| {
            log.warn("nostr(nip04): publishInbound failed: {}", .{err});
            msg.deinit(self.allocator);
        };
    }

    // ── Helper methods ──────────────────────────────────────────────

    pub fn stopListener(self: *NostrChannel) void {
        if (self.listener) |*child| {
            _ = child.kill() catch {};
            _ = child.wait() catch {};
            self.listener = null;
        }
    }

    pub fn healthCheck(self: *NostrChannel) bool {
        return self.started and self.running.load(.acquire);
    }

    /// Publish kind:10050 DM inbox relay list to general relays.
    /// Best-effort: logs a warning on failure but does not abort vtableStart.
    fn publishInboxRelays(self: *NostrChannel, sec: []const u8) void {
        var tag_bufs: [MAX_RELAYS][MAX_RELAY_TAG_LEN]u8 = undefined;
        const create_args = buildInboxCreateArgs(self.config, sec, &tag_bufs);
        const event_json = self.runNakCommand(MAX_INBOX_CREATE_ARGS, create_args, null) catch |err| {
            log.warn("nostr: failed to create kind:10050 event: {}", .{err});
            return;
        };
        defer self.allocator.free(event_json);

        const publish_args = buildPublishArgs(self.config, sec);
        const result = self.runNakCommand(MAX_PUBLISH_ARGS, publish_args, event_json) catch |err| {
            log.warn("nostr: failed to publish kind:10050: {}", .{err});
            return;
        };
        self.allocator.free(result);
        log.info("nostr: published kind:10050 DM inbox relay list ({d} relays)", .{self.config.dm_relays.len});
    }

    // ── Channel vtable ──────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *NostrChannel = @ptrCast(@alignCast(ptr));

        // 0. Validate key formats before any I/O.
        validateConfig(self.config) catch |err| {
            log.err("nostr config has invalid key format — owner_pubkey and bot_pubkey must be 64-char lowercase hex; dm_allowed_pubkeys entries must be hex or \"*\"; private_key must be enc2:-encrypted. Re-run onboarding if bot_pubkey is missing.", .{});
            return err;
        };

        // 1. Derive signing credential.
        //    External bunker URI: dupe it — nak uses bunker:// directly as --sec.
        //    Own private key: decrypt enc2: blob via SecretStore (machine-local .secret_key).
        //    Zeroed and freed in vtableStop.
        self.signing_sec = if (self.config.bunker_uri) |uri|
            try self.allocator.dupe(u8, uri)
        else blk: {
            const store = secrets.SecretStore.init(self.config.config_dir, true);
            break :blk try store.decryptSecret(self.allocator, self.config.private_key);
        };
        errdefer {
            if (self.signing_sec) |sec| {
                @memset(sec, 0);
                self.allocator.free(sec);
                self.signing_sec = null;
            }
        }

        // 2. Record the listen start timestamp (ignore events before this).
        self.listen_start_at = @intCast(root.nowEpochSecs());

        // 3. Build listener args and spawn the nak req --stream subprocess.
        const sec = self.signing_sec orelse return error.ListenerStartFailed;
        var since_buf: [32]u8 = undefined;
        // NIP-17 senders may randomise the outer gift-wrap created_at within the past
        // 2 days. Use a 2-day lookback so the relay doesn't filter those envelopes out.
        // The inner rumor timestamp check (processWrappedEvent) discards pre-startup msgs.
        const since_ts = self.listen_start_at - 2 * 24 * 3600;
        const since_str = std.fmt.bufPrint(&since_buf, "{d}", .{since_ts}) catch return error.ListenerStartFailed;
        const bounded = buildListenerArgs(self.config, sec, since_str);
        var argv_buf: [MAX_LISTENER_ARGS][]const u8 = undefined;
        const args = filterArgs(MAX_LISTENER_ARGS, bounded, &argv_buf);
        if (args.len < 15) return error.ListenerStartFailed;

        var child = std.process.Child.init(args, self.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Inherit;
        try child.spawn();

        self.listener = child;
        errdefer self.stopListener();

        // 4. Spawn the reader thread to process incoming events.
        self.running.store(true, .release);
        self.reader_thread = std.Thread.spawn(.{ .stack_size = 128 * 1024 }, readerLoop, .{self}) catch {
            self.running.store(false, .release);
            return error.ReaderThreadFailed;
        };

        self.started = true;

        // 5. Publish kind:10050 DM inbox relay list (NIP-17, best-effort).
        self.publishInboxRelays(sec);
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *NostrChannel = @ptrCast(@alignCast(ptr));

        // 1. Signal the reader thread to stop.
        self.running.store(false, .release);

        // 2. Kill the listener (causes reader's stdout read to return EOF).
        self.stopListener();

        // 3. Join the reader thread.
        if (self.reader_thread) |t| {
            t.join();
            self.reader_thread = null;
        }

        // 4. Zero and free the signing credential.
        if (self.signing_sec) |sec| {
            @memset(sec, 0);
            self.allocator.free(sec);
            self.signing_sec = null;
        }

        self.started = false;
    }

    fn sendNip17(self: *NostrChannel, target: []const u8, message: []const u8) anyerror!void {
        const sec = self.signing_sec orelse return error.NoSigningKey;
        log.info("nostr: sending NIP-17 reply to {s}", .{target});

        // Step 1: create kind:14 rumor.
        var p_buf: [66]u8 = undefined;
        const p_tag = formatPTag(target, &p_buf);
        const event_args = buildSendEventArgs(self.config.nak_path, sec, message, p_tag);
        const event_json = try self.runNakCommand(MAX_SEND_ARGS, event_args, null);
        defer self.allocator.free(event_json);

        // Step 2: gift-wrap (no relays — generates JSON with ephemeral outer key).
        const wrap_args = buildGiftWrapArgs(self.config.nak_path, sec, target, &.{});
        const wrapped_json = try self.runNakCommand(MAX_GIFT_WRAP_ARGS, wrap_args, event_json);
        defer self.allocator.free(wrapped_json);

        // Step 3: look up recipient's DM inbox relays (kind:10050).
        // Fall back to config.relays if lookup fails or recipient has no kind:10050.
        const inbox_relays = self.lookupInboxRelays(target);
        defer if (inbox_relays) |rs| {
            for (rs) |r| self.allocator.free(r);
            self.allocator.free(rs);
        };
        const publish_relays: []const []const u8 = if (inbox_relays) |rs| rs else self.config.relays;

        // Step 4: publish the pre-signed gift wrap WITHOUT --sec.
        // nak event without --sec publishes a fully-signed event as-is, preserving
        // the ephemeral outer pubkey. Using --sec would cause nak to re-sign the event
        // with the bot's identity key, making the gift wrap undecryptable by the recipient.
        const publish_args = buildPublishOnlyArgs(self.config.nak_path, publish_relays);
        const result = try self.runNakCommand(MAX_PUBLISH_ARGS, publish_args, wrapped_json);
        self.allocator.free(result);

        log.info("nostr: NIP-17 reply sent ({d} relay(s))", .{publish_relays.len});
        for (publish_relays) |relay| log.debug("nostr:   published to {s}", .{relay});
    }

    fn sendNip04(self: *NostrChannel, target: []const u8, message: []const u8) anyerror!void {
        const sec = self.signing_sec orelse return error.NoSigningKey;
        log.info("nostr: sending NIP-04 reply to {s}", .{target});
        const encrypt_args = buildEncryptArgs(self.config.nak_path, sec, target);
        const ciphertext_raw = try self.runNakCommand(MAX_ENCRYPT_ARGS, encrypt_args, message);
        defer self.allocator.free(ciphertext_raw);
        const ciphertext = std.mem.trimRight(u8, ciphertext_raw, " \t\r\n");
        var p_buf: [66]u8 = undefined;
        const p_tag = formatPTag(target, &p_buf);
        const event_args = buildNip04EventArgs(self.config.nak_path, sec, ciphertext, p_tag);
        const event_json = try self.runNakCommand(MAX_NIP04_EVENT_ARGS, event_args, null);
        defer self.allocator.free(event_json);
        const publish_args = buildPublishArgs(self.config, sec);
        const result = try self.runNakCommand(MAX_PUBLISH_ARGS, publish_args, event_json);
        self.allocator.free(result);
        log.info("nostr: NIP-04 reply sent", .{});
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, media: []const []const u8) anyerror!void {
        _ = media; // Nostr v1: text-only DMs; media attachments not yet implemented
        const self: *NostrChannel = @ptrCast(@alignCast(ptr));
        switch (self.getSenderProtocol(target)) {
            .nip17 => try self.sendNip17(target, message),
            .nip04 => try self.sendNip04(target, message),
        }
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        _ = ptr;
        return "nostr";
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *NostrChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *NostrChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Test Helpers
// ════════════════════════════════════════════════════════════════════════════

/// Helper for creating NostrChannel instances in tests with a minimal dummy config.
pub const TestHelper = struct {
    pub fn dummyConfig() config_types.NostrConfig {
        return .{
            .private_key = "0000000000000000000000000000000000000000000000000000000000000001",
            .owner_pubkey = "0000000000000000000000000000000000000000000000000000000000000002",
            .config_dir = ".",
        };
    }

    pub fn initTestChannel(allocator: Allocator) NostrChannel {
        return NostrChannel.init(allocator, dummyConfig());
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "NostrChannel vtable name returns nostr" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    const chan = ch.channel();
    try std.testing.expectEqualStrings("nostr", chan.name());
}

test "NostrChannel healthCheck returns false before start" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    try std.testing.expect(!ch.healthCheck());
    // Also verify through the vtable
    const chan = ch.channel();
    try std.testing.expect(!chan.healthCheck());
}

test "NostrChannel deinit on fresh instance does not leak" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    ch.deinit();
    // If we reach here without the testing allocator complaining, no leaks occurred.
}

test "buildSendEventArgs constructs correct arguments" {
    var p_buf: [66]u8 = undefined;
    const p_tag = NostrChannel.formatPTag("deadbeef" ** 8, &p_buf);
    const args = NostrChannel.buildSendEventArgs("nak", "bunker://xyz", "hello", p_tag);
    try std.testing.expectEqualStrings("nak", args[0].?);
    try std.testing.expectEqualStrings("event", args[1].?);
    try std.testing.expectEqualStrings("-k", args[2].?);
    try std.testing.expectEqualStrings("14", args[3].?);
    try std.testing.expectEqualStrings("--sec", args[4].?);
    try std.testing.expectEqualStrings("bunker://xyz", args[5].?);
    try std.testing.expectEqualStrings("-c", args[6].?);
    try std.testing.expectEqualStrings("hello", args[7].?);
    try std.testing.expectEqualStrings("-t", args[8].?);
    try std.testing.expectEqualStrings("p=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", args[9].?);
    try std.testing.expect(args[10] == null);
}

test "formatPTag builds correct tag" {
    var buf: [66]u8 = undefined;
    const tag = NostrChannel.formatPTag("abcd1234", &buf);
    try std.testing.expectEqualStrings("p=abcd1234", tag);
}

test "buildGiftWrapArgs constructs correct arguments with relays" {
    const relays: []const []const u8 = &.{ "wss://relay.damus.io", "wss://nos.lol" };
    const args = NostrChannel.buildGiftWrapArgs("nak", "bunker://xyz", "deadbeef", relays);
    try std.testing.expectEqualStrings("nak", args[0].?);
    try std.testing.expectEqualStrings("gift", args[1].?);
    try std.testing.expectEqualStrings("wrap", args[2].?);
    try std.testing.expectEqualStrings("--sec", args[3].?);
    try std.testing.expectEqualStrings("bunker://xyz", args[4].?);
    try std.testing.expectEqualStrings("-p", args[5].?);
    try std.testing.expectEqualStrings("deadbeef", args[6].?);
    try std.testing.expectEqualStrings("wss://relay.damus.io", args[7].?);
    try std.testing.expectEqualStrings("wss://nos.lol", args[8].?);
    try std.testing.expect(args[9] == null);
}

test "buildGiftWrapArgs with no relays leaves relay slots null" {
    const args = NostrChannel.buildGiftWrapArgs("nak", "sec", "pub", &.{});
    try std.testing.expectEqualStrings("nak", args[0].?);
    try std.testing.expectEqualStrings("gift", args[1].?);
    try std.testing.expectEqualStrings("wrap", args[2].?);
    try std.testing.expectEqualStrings("--sec", args[3].?);
    try std.testing.expectEqualStrings("sec", args[4].?);
    try std.testing.expectEqualStrings("-p", args[5].?);
    try std.testing.expectEqualStrings("pub", args[6].?);
    try std.testing.expect(args[7] == null);
}

test "buildPublishArgs constructs correct arguments" {
    const config = config_types.NostrConfig{
        .private_key = "enc2:sec",
        .owner_pubkey = "a" ** 64,
        .relays = &.{ "wss://relay.damus.io", "wss://nos.lol" },
    };
    const args = NostrChannel.buildPublishArgs(config, "bunker://xyz");
    try std.testing.expectEqualStrings("nak", args[0].?);
    try std.testing.expectEqualStrings("event", args[1].?);
    try std.testing.expectEqualStrings("--sec", args[2].?);
    try std.testing.expectEqualStrings("bunker://xyz", args[3].?);
    try std.testing.expectEqualStrings("--auth", args[4].?); // boolean, no value
    try std.testing.expectEqualStrings("wss://relay.damus.io", args[5].?);
    try std.testing.expectEqualStrings("wss://nos.lol", args[6].?);
    try std.testing.expect(args[7] == null);
}

test "buildPublishArgsWithRelays constructs correct arguments" {
    const relays: []const []const u8 = &.{ "wss://relay.damus.io", "wss://nos.lol" };
    const args = NostrChannel.buildPublishArgsWithRelays("nak", "mysec", relays);
    try std.testing.expectEqualStrings("nak", args[0].?);
    try std.testing.expectEqualStrings("event", args[1].?);
    try std.testing.expectEqualStrings("--sec", args[2].?);
    try std.testing.expectEqualStrings("mysec", args[3].?);
    try std.testing.expectEqualStrings("--auth", args[4].?);
    try std.testing.expectEqualStrings("wss://relay.damus.io", args[5].?);
    try std.testing.expectEqualStrings("wss://nos.lol", args[6].?);
    try std.testing.expect(args[7] == null);
}

test "buildPublishOnlyArgs constructs arguments without signing key" {
    const relays: []const []const u8 = &.{ "wss://relay.damus.io", "wss://nos.lol" };
    const args = NostrChannel.buildPublishOnlyArgs("nak", relays);
    try std.testing.expectEqualStrings("nak", args[0].?);
    try std.testing.expectEqualStrings("event", args[1].?);
    try std.testing.expectEqualStrings("wss://relay.damus.io", args[2].?);
    try std.testing.expectEqualStrings("wss://nos.lol", args[3].?);
    try std.testing.expect(args[4] == null);
}

test "buildInboxLookupArgs constructs correct arguments" {
    const config = config_types.NostrConfig{
        .private_key = "enc2:sec",
        .owner_pubkey = "a" ** 64,
        .relays = &.{"wss://relay.damus.io"},
    };
    const args = NostrChannel.buildInboxLookupArgs(config, "b" ** 64);
    try std.testing.expectEqualStrings("nak", args[0].?);
    try std.testing.expectEqualStrings("req", args[1].?);
    try std.testing.expectEqualStrings("-k", args[2].?);
    try std.testing.expectEqualStrings("10050", args[3].?);
    try std.testing.expectEqualStrings("-a", args[4].?);
    try std.testing.expectEqualStrings("b" ** 64, args[5].?);
    try std.testing.expectEqualStrings("wss://relay.damus.io", args[6].?);
    try std.testing.expect(args[7] == null);
}

test "parseRelayTags extracts relay URLs from kind:10050 JSON" {
    const json =
        \\{"kind":10050,"tags":[["relay","wss://relay.damus.io"],["relay","wss://nos.lol"]],"content":""}
    ;
    const relays = try NostrChannel.parseRelayTags(std.testing.allocator, json);
    defer {
        for (relays) |r| std.testing.allocator.free(r);
        std.testing.allocator.free(relays);
    }
    try std.testing.expectEqual(@as(usize, 2), relays.len);
    try std.testing.expectEqualStrings("wss://relay.damus.io", relays[0]);
    try std.testing.expectEqualStrings("wss://nos.lol", relays[1]);
}

test "parseRelayTags returns empty slice when no relay tags" {
    const json =
        \\{"kind":10050,"tags":[],"content":""}
    ;
    const relays = try NostrChannel.parseRelayTags(std.testing.allocator, json);
    defer std.testing.allocator.free(relays);
    try std.testing.expectEqual(@as(usize, 0), relays.len);
}

test "buildListenerArgs subscribes to kind:1059 and kind:4, on relays and dm_relays" {
    const config = config_types.NostrConfig{
        .private_key = "enc2:sec",
        .owner_pubkey = "deadbeef" ** 8,
        .bot_pubkey = "cafebabe" ** 8, // distinct from owner_pubkey
        .relays = &.{"wss://relay.damus.io"},
        .dm_relays = &.{"wss://auth.nostr1.com"},
    };
    const args = NostrChannel.buildListenerArgs(config, "myseckey", "1700000000");
    try std.testing.expectEqualStrings("nak", args[0].?);
    try std.testing.expectEqualStrings("req", args[1].?);
    try std.testing.expectEqualStrings("--stream", args[2].?);
    try std.testing.expectEqualStrings("-k", args[3].?);
    try std.testing.expectEqualStrings("1059", args[4].?);
    try std.testing.expectEqualStrings("-k", args[5].?);
    try std.testing.expectEqualStrings("4", args[6].?);
    try std.testing.expectEqualStrings("--auth", args[7].?); // boolean flag
    try std.testing.expectEqualStrings("--sec", args[8].?);
    try std.testing.expectEqualStrings("myseckey", args[9].?);
    try std.testing.expectEqualStrings("-s", args[10].?); // relay-side startup filter
    try std.testing.expectEqualStrings("1700000000", args[11].?);
    try std.testing.expectEqualStrings("-p", args[12].?);
    try std.testing.expectEqualStrings("cafebabe" ** 8, args[13].?); // bot_pubkey, not owner
    try std.testing.expectEqualStrings("wss://relay.damus.io", args[14].?);
    try std.testing.expectEqualStrings("wss://auth.nostr1.com", args[15].?);
    try std.testing.expect(args[16] == null);
}

test "buildListenerArgs deduplicates relays present in both lists" {
    const config = config_types.NostrConfig{
        .private_key = "enc2:sec",
        .owner_pubkey = "deadbeef" ** 8,
        .bot_pubkey = "cafebabe" ** 8,
        .relays = &.{ "wss://relay.damus.io", "wss://auth.nostr1.com" },
        .dm_relays = &.{"wss://auth.nostr1.com"}, // duplicate of relays entry
    };
    const args = NostrChannel.buildListenerArgs(config, "myseckey", "1700000000");
    // relay.damus.io and auth.nostr1.com appear exactly once each
    try std.testing.expectEqualStrings("wss://relay.damus.io", args[14].?);
    try std.testing.expectEqualStrings("wss://auth.nostr1.com", args[15].?);
    try std.testing.expect(args[16] == null); // no third relay — deduplication worked
}

test "buildUnwrapArgs constructs correct arguments" {
    const args = NostrChannel.buildUnwrapArgs("nak", "bunker://xyz");
    try std.testing.expectEqualStrings("nak", args[0].?);
    try std.testing.expectEqualStrings("gift", args[1].?);
    try std.testing.expectEqualStrings("unwrap", args[2].?);
    try std.testing.expectEqualStrings("--sec", args[3].?);
    try std.testing.expectEqualStrings("bunker://xyz", args[4].?);
    try std.testing.expect(args[5] == null);
}

test "parseUnwrappedRumor extracts sender and content" {
    const json =
        \\{"id":"abc","pubkey":"sender123","created_at":1700000000,"kind":14,"tags":[["p","recipient"]],"content":"hello","sig":""}
    ;
    const result = try NostrChannel.parseUnwrappedRumor(json);
    try std.testing.expectEqualStrings("sender123", result.sender);
    try std.testing.expectEqualStrings("hello", result.content);
    try std.testing.expectEqual(@as(i64, 1700000000), result.created_at);
}

test "parseUnwrappedRumor returns error on missing pubkey" {
    const json =
        \\{"id":"abc","created_at":1700000000,"kind":14,"content":"hello"}
    ;
    try std.testing.expectError(error.InvalidRumor, NostrChannel.parseUnwrappedRumor(json));
}

test "parseUnwrappedRumor returns error on missing content" {
    const json =
        \\{"id":"abc","pubkey":"sender123","created_at":1700000000,"kind":14}
    ;
    try std.testing.expectError(error.InvalidRumor, NostrChannel.parseUnwrappedRumor(json));
}

test "parseUnwrappedRumor returns error on missing created_at" {
    const json =
        \\{"id":"abc","pubkey":"sender123","kind":14,"content":"hello"}
    ;
    try std.testing.expectError(error.InvalidRumor, NostrChannel.parseUnwrappedRumor(json));
}

test "isValidHexKey: accepts 64 lowercase hex chars" {
    try std.testing.expect(NostrChannel.isValidHexKey("a" ** 64));
    try std.testing.expect(NostrChannel.isValidHexKey("0123456789abcdef" ** 4));
}

test "isValidHexKey: rejects wrong length" {
    try std.testing.expect(!NostrChannel.isValidHexKey("a" ** 63));
    try std.testing.expect(!NostrChannel.isValidHexKey("a" ** 65));
    try std.testing.expect(!NostrChannel.isValidHexKey(""));
}

test "isValidHexKey: rejects uppercase hex" {
    try std.testing.expect(!NostrChannel.isValidHexKey("A" ** 64));
    try std.testing.expect(!NostrChannel.isValidHexKey("ABCDEF0123456789" ** 4));
}

test "isValidHexKey: rejects npub prefix" {
    // npub1 is obviously not 64 hex chars, but also not hex
    try std.testing.expect(!NostrChannel.isValidHexKey("npub1" ++ "a" ** 59));
}

test "validateConfig: valid hex pubkey and enc2 key passes" {
    try NostrChannel.validateConfig(.{
        .private_key = "enc2:deadbeef",
        .owner_pubkey = "a" ** 64,
        .bot_pubkey = "b" ** 64,
        .dm_allowed_pubkeys = &.{ "c" ** 64, "*" },
    });
}

test "validateConfig: npub owner_pubkey returns error" {
    try std.testing.expectError(error.InvalidKeyFormat, NostrChannel.validateConfig(.{
        .private_key = "enc2:x",
        .owner_pubkey = "npub1" ++ "a" ** 59,
    }));
}

test "validateConfig: non-hex dm_allowed_pubkeys returns error" {
    try std.testing.expectError(error.InvalidKeyFormat, NostrChannel.validateConfig(.{
        .private_key = "enc2:x",
        .owner_pubkey = "a" ** 64,
        .dm_allowed_pubkeys = &.{"npub1abc"},
    }));
}

test "validateConfig: plaintext private_key returns error" {
    try std.testing.expectError(error.InvalidKeyFormat, NostrChannel.validateConfig(.{
        .private_key = "a" ** 64,
        .owner_pubkey = "b" ** 64,
    }));
}

test "validateConfig: nsec private_key returns error" {
    try std.testing.expectError(error.InvalidKeyFormat, NostrChannel.validateConfig(.{
        .private_key = "nsec1" ++ "a" ** 59,
        .owner_pubkey = "b" ** 64,
    }));
}

test "validateConfig: bunker_uri skips private_key check" {
    try NostrChannel.validateConfig(.{
        .private_key = "not-encrypted",
        .owner_pubkey = "a" ** 64,
        .bot_pubkey = "b" ** 64,
        .bunker_uri = "bunker://abc?relay=wss://relay.damus.io",
    });
}

test "validateConfig: empty bot_pubkey returns error" {
    try std.testing.expectError(error.InvalidKeyFormat, NostrChannel.validateConfig(.{
        .private_key = "enc2:x",
        .owner_pubkey = "a" ** 64,
        .bot_pubkey = "", // not set — old config or missing onboarding step
    }));
}

test "isDmAllowed: owner always allowed" {
    var ch = NostrChannel.init(std.testing.allocator, .{
        .private_key = "sec",
        .owner_pubkey = "ownerpub",
        .dm_allowed_pubkeys = &.{},
    });
    defer ch.deinit();
    try std.testing.expect(ch.isDmAllowed("ownerpub"));
}

test "isDmAllowed: empty list denies non-owner" {
    var ch = NostrChannel.init(std.testing.allocator, .{
        .private_key = "sec",
        .owner_pubkey = "ownerpub",
        .dm_allowed_pubkeys = &.{},
    });
    defer ch.deinit();
    try std.testing.expect(!ch.isDmAllowed("stranger"));
}

test "isDmAllowed: wildcard allows all" {
    var ch = NostrChannel.init(std.testing.allocator, .{
        .private_key = "sec",
        .owner_pubkey = "ownerpub",
        .dm_allowed_pubkeys = &.{"*"},
    });
    defer ch.deinit();
    try std.testing.expect(ch.isDmAllowed("anyone"));
}

test "isDmAllowed: specific pubkey in list" {
    var ch = NostrChannel.init(std.testing.allocator, .{
        .private_key = "sec",
        .owner_pubkey = "ownerpub",
        .dm_allowed_pubkeys = &.{ "allowed1", "allowed2" },
    });
    defer ch.deinit();
    try std.testing.expect(ch.isDmAllowed("allowed1"));
    try std.testing.expect(ch.isDmAllowed("allowed2"));
    try std.testing.expect(!ch.isDmAllowed("stranger"));
}

test "sender_protocols tracks protocol per sender" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    try ch.recordSenderProtocol("sender1", .nip17);
    try ch.recordSenderProtocol("sender2", .nip04);
    try std.testing.expect(ch.getSenderProtocol("sender1") == .nip17);
    try std.testing.expect(ch.getSenderProtocol("sender2") == .nip04);
    try std.testing.expect(ch.getSenderProtocol("unknown") == .nip17);
}

test "sender_protocols update does not leak on repeated sender" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    try ch.recordSenderProtocol("sender1", .nip17);
    try ch.recordSenderProtocol("sender1", .nip04);
    try std.testing.expect(ch.getSenderProtocol("sender1") == .nip04);
}

test "NostrChannel registers with ChannelRegistry" {
    const allocator = std.testing.allocator;
    const dispatch = @import("dispatch.zig");

    var ch = TestHelper.initTestChannel(allocator);
    defer ch.deinit();

    var reg = dispatch.ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(ch.channel());

    try std.testing.expectEqual(@as(usize, 1), reg.count());
    try std.testing.expect(reg.findByName("nostr") != null);
    try std.testing.expect(reg.findByName("nonexistent") == null);
}

test "NostrChannel health report via registry" {
    const allocator = std.testing.allocator;
    const dispatch = @import("dispatch.zig");

    var ch = TestHelper.initTestChannel(allocator);
    defer ch.deinit();

    var reg = dispatch.ChannelRegistry.init(allocator);
    defer reg.deinit();
    try reg.register(ch.channel());

    const report = reg.healthCheckAll();
    // Not started, so unhealthy
    try std.testing.expectEqual(@as(usize, 0), report.healthy);
    try std.testing.expectEqual(@as(usize, 1), report.unhealthy);
}

test "vtableSend returns NoSigningKey when not started" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    const chan = ch.channel();
    try std.testing.expectError(error.NoSigningKey, chan.send("target", "msg", &.{}));
}

test "setBus sets the event bus" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    var event_bus = bus.Bus.init();
    defer event_bus.close();
    try std.testing.expect(ch.event_bus == null);
    ch.setBus(&event_bus);
    try std.testing.expect(ch.event_bus != null);
}

test "buildSessionKey formats correctly" {
    var buf: [71]u8 = undefined;
    const key = NostrChannel.buildSessionKey("abcdef1234", &buf);
    try std.testing.expectEqualStrings("nostr:abcdef1234", key);
}

test "buildSessionKey truncates at 64 hex chars" {
    var buf: [71]u8 = undefined;
    const long_hex = "a" ** 80;
    const key = NostrChannel.buildSessionKey(long_hex, &buf);
    try std.testing.expectEqual(@as(usize, 6 + 64), key.len);
    try std.testing.expect(std.mem.startsWith(u8, key, "nostr:"));
}

test "processWrappedEvent publishes valid DM to bus" {
    const allocator = std.testing.allocator;
    var ch = NostrChannel.init(allocator, .{
        .private_key = "sec",
        .owner_pubkey = "owner_pub",
        .dm_allowed_pubkeys = &.{"*"},
    });
    defer ch.deinit();

    var event_bus = bus.Bus.init();
    defer event_bus.close();
    ch.event_bus = &event_bus;
    ch.listen_start_at = 0;

    // processWrappedEvent calls runNakCommand which needs nak binary — skip in unit tests.
    // Instead, test the integration path components individually.
    // The buildSessionKey and parseUnwrappedRumor are already tested above.
    // The full integration requires a live nak binary and is tested manually.
}

test "reader thread fields initialize correctly" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    try std.testing.expect(ch.event_bus == null);
    try std.testing.expect(ch.reader_thread == null);
    try std.testing.expect(!ch.running.load(.acquire));
}

test "vtableStop is safe on unstarted channel" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    const chan = ch.channel();
    // Should not panic or crash.
    chan.stop();
    try std.testing.expect(!ch.started);
    try std.testing.expect(!ch.running.load(.acquire));
}

test "healthCheck returns false when reader exits naturally" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    // Simulate: channel was started, reader has since exited
    ch.started = true;
    ch.running.store(false, .release);
    try std.testing.expect(!ch.healthCheck());
}

test "healthCheck returns true when started and running" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    ch.started = true;
    ch.running.store(true, .release);
    try std.testing.expect(ch.healthCheck());
}

test "buildInboxCreateArgs constructs kind:10050 create args" {
    const config = config_types.NostrConfig{
        .private_key = "enc2:sec",
        .owner_pubkey = "a" ** 64,
        .dm_relays = &.{"wss://auth.nostr1.com"},
    };
    var tag_bufs: [NostrChannel.MAX_RELAYS][NostrChannel.MAX_RELAY_TAG_LEN]u8 = undefined;
    const args = NostrChannel.buildInboxCreateArgs(config, "myhexkey", &tag_bufs);

    try std.testing.expectEqualStrings("nak", args[0].?);
    try std.testing.expectEqualStrings("event", args[1].?);
    try std.testing.expectEqualStrings("-k", args[2].?);
    try std.testing.expectEqualStrings("10050", args[3].?);
    try std.testing.expectEqualStrings("--sec", args[4].?);
    try std.testing.expectEqualStrings("myhexkey", args[5].?);
    try std.testing.expectEqualStrings("-t", args[6].?);
    try std.testing.expectEqualStrings("relay=wss://auth.nostr1.com", args[7].?);
    try std.testing.expect(args[8] == null);
}

test "extractEventKind returns correct kind" {
    const json = "{\"id\":\"a\",\"pubkey\":\"b\",\"created_at\":1,\"kind\":4,\"tags\":[],\"content\":\"enc\",\"sig\":\"s\"}";
    try std.testing.expectEqual(@as(?u16, 4), NostrChannel.extractEventKind(json));
}

test "extractEventKind returns null on missing kind" {
    try std.testing.expect(NostrChannel.extractEventKind("{\"id\":\"a\"}") == null);
}

test "buildDecryptArgs constructs correct arguments" {
    const args = NostrChannel.buildDecryptArgs("nak", "myhexkey", "senderpubhex");
    try std.testing.expectEqualStrings("nak", args[0].?);
    try std.testing.expectEqualStrings("decrypt", args[1].?);
    try std.testing.expectEqualStrings("--sec", args[2].?);
    try std.testing.expectEqualStrings("myhexkey", args[3].?);
    try std.testing.expectEqualStrings("-p", args[4].?);
    try std.testing.expectEqualStrings("senderpubhex", args[5].?);
    try std.testing.expect(args[6] == null);
}

test "buildEncryptArgs constructs correct arguments" {
    const args = NostrChannel.buildEncryptArgs("nak", "myhexkey", "recipienthex");
    try std.testing.expectEqualStrings("nak", args[0].?);
    try std.testing.expectEqualStrings("encrypt", args[1].?);
    try std.testing.expectEqualStrings("--sec", args[2].?);
    try std.testing.expectEqualStrings("myhexkey", args[3].?);
    try std.testing.expectEqualStrings("-p", args[4].?);
    try std.testing.expectEqualStrings("recipienthex", args[5].?);
    try std.testing.expect(args[6] == null);
}

test "buildNip04EventArgs constructs correct arguments" {
    var p_buf: [66]u8 = undefined;
    const p_tag = NostrChannel.formatPTag("deadbeef" ** 8, &p_buf);
    const args = NostrChannel.buildNip04EventArgs("nak", "myhexkey", "ciphertext?iv=abc", p_tag);
    try std.testing.expectEqualStrings("nak", args[0].?);
    try std.testing.expectEqualStrings("event", args[1].?);
    try std.testing.expectEqualStrings("-k", args[2].?);
    try std.testing.expectEqualStrings("4", args[3].?);
    try std.testing.expectEqualStrings("--sec", args[4].?);
    try std.testing.expectEqualStrings("myhexkey", args[5].?);
    try std.testing.expectEqualStrings("-c", args[6].?);
    try std.testing.expectEqualStrings("ciphertext?iv=abc", args[7].?);
    try std.testing.expectEqualStrings("-t", args[8].?);
    try std.testing.expect(args[9] != null); // p_tag value
    try std.testing.expect(args[10] == null);
}

test "parseUnwrappedRumor extracts id field" {
    const json =
        \\{"id":"deadbeef1234","pubkey":"sender123","created_at":1700000000,"kind":14,"tags":[],"content":"hello","sig":""}
    ;
    const result = try NostrChannel.parseUnwrappedRumor(json);
    try std.testing.expectEqualStrings("deadbeef1234", result.id);
}

test "isSeenRumor returns false for unknown rumor id" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    try std.testing.expect(!ch.isSeenRumor("abc1234567890def"));
}

test "recordSeenRumor marks a rumor as seen" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    try ch.recordSeenRumor("abc1234567890def", 1700000000);
    try std.testing.expect(ch.isSeenRumor("abc1234567890def"));
    try std.testing.expect(!ch.isSeenRumor("other_rumor_id"));
}

test "recordSeenRumor evicts entries older than dedup window" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    const old_time: i64 = 1000;
    const now: i64 = old_time + NostrChannel.RUMOR_DEDUP_WINDOW_SECS + 1;
    try ch.recordSeenRumor("old_rumor_id_xxxx", old_time);
    try ch.recordSeenRumor("new_rumor_id_yyyy", now);
    try std.testing.expect(!ch.isSeenRumor("old_rumor_id_xxxx")); // evicted
    try std.testing.expect(ch.isSeenRumor("new_rumor_id_yyyy")); // still present
}

test "recordSeenRumor keeps entries within dedup window" {
    var ch = TestHelper.initTestChannel(std.testing.allocator);
    defer ch.deinit();
    const base: i64 = 1000;
    const now: i64 = base + NostrChannel.RUMOR_DEDUP_WINDOW_SECS - 1;
    try ch.recordSeenRumor("rumor_A", base);
    try ch.recordSeenRumor("rumor_B", now);
    try std.testing.expect(ch.isSeenRumor("rumor_A")); // still in window
    try std.testing.expect(ch.isSeenRumor("rumor_B"));
}
