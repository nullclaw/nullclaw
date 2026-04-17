const std = @import("std");
const std_compat = @import("compat");
const Allocator = std.mem.Allocator;
const bus = @import("../bus.zig");
const outbound = @import("../outbound.zig");
const json_util = @import("../json_util.zig");
const builtin = @import("builtin");

pub const MAX_DELIVERY_ATTEMPTS: u32 = 5;
const RETRY_BACKOFF_MS = if (builtin.is_test)
    [_]u64{ 0, 0, 0, 0, 0 }
else
    [_]u64{ 250, 1000, 5000, 15000, 30000 };

pub const DeliveryOutbox = struct {
    allocator: Allocator,
    path: []u8,
    mutex: std_compat.sync.Mutex = .{},
    jobs: std.ArrayListUnmanaged(Job) = .empty,
    next_id: u64 = 1,
    closed: bool = false,

    const Self = @This();

    pub const ClaimedJob = struct {
        id: u64,
        channel: []u8,
        account_id: ?[]u8 = null,
        chat_id: []u8,
        content: []u8,
        media: []const []const u8 = &.{},
        choices: []const outbound.Choice = &.{},

        pub fn deinit(self: *ClaimedJob, allocator: Allocator) void {
            if (self.account_id) |account_id| allocator.free(account_id);
            allocator.free(self.channel);
            allocator.free(self.chat_id);
            allocator.free(self.content);
            for (self.media) |item| allocator.free(item);
            if (self.media.len > 0) allocator.free(self.media);
            for (self.choices) |choice| choice.deinit(allocator);
            if (self.choices.len > 0) allocator.free(self.choices);
        }
    };

    const Job = struct {
        id: u64,
        channel: []u8,
        account_id: ?[]u8 = null,
        chat_id: []u8,
        content: []u8,
        media: []const []const u8 = &.{},
        choices: []const outbound.Choice = &.{},
        attempts: u32 = 0,
        next_attempt_ns: i64 = 0,
        last_error: ?[]u8 = null,
        in_flight: bool = false,
        delivered_at_ns: i64 = 0,

        fn deinit(self: *Job, allocator: Allocator) void {
            allocator.free(self.channel);
            if (self.account_id) |account_id| allocator.free(account_id);
            allocator.free(self.chat_id);
            allocator.free(self.content);
            for (self.media) |item| allocator.free(item);
            if (self.media.len > 0) allocator.free(self.media);
            for (self.choices) |choice| choice.deinit(allocator);
            if (self.choices.len > 0) allocator.free(self.choices);
            if (self.last_error) |last_error| allocator.free(last_error);
        }

        fn cloneForClaim(self: *const Job, allocator: Allocator) !ClaimedJob {
            const channel = try allocator.dupe(u8, self.channel);
            errdefer allocator.free(channel);
            const account_id = if (self.account_id) |account| try allocator.dupe(u8, account) else null;
            errdefer if (account_id) |account| allocator.free(account);
            const chat_id = try allocator.dupe(u8, self.chat_id);
            errdefer allocator.free(chat_id);
            const content = try allocator.dupe(u8, self.content);
            errdefer allocator.free(content);

            const media = if (self.media.len > 0) blk: {
                const duped = try allocator.alloc([]const u8, self.media.len);
                var i: usize = 0;
                errdefer {
                    for (duped[0..i]) |item| allocator.free(item);
                    allocator.free(duped);
                }
                while (i < self.media.len) : (i += 1) {
                    duped[i] = try allocator.dupe(u8, self.media[i]);
                }
                break :blk duped;
            } else &[_][]const u8{};
            errdefer if (media.len > 0) {
                for (media) |item| allocator.free(item);
                allocator.free(media);
            };

            const choices = if (self.choices.len > 0) blk: {
                const duped = try allocator.alloc(outbound.Choice, self.choices.len);
                var i: usize = 0;
                errdefer {
                    for (duped[0..i]) |choice| choice.deinit(allocator);
                    allocator.free(duped);
                }
                while (i < self.choices.len) : (i += 1) {
                    duped[i] = .{
                        .id = try allocator.dupe(u8, self.choices[i].id),
                        .label = try allocator.dupe(u8, self.choices[i].label),
                        .submit_text = try allocator.dupe(u8, self.choices[i].submit_text),
                    };
                }
                break :blk duped;
            } else &[_]outbound.Choice{};

            return .{
                .id = self.id,
                .channel = channel,
                .account_id = account_id,
                .chat_id = chat_id,
                .content = content,
                .media = media,
                .choices = choices,
            };
        }
    };

    pub fn init(allocator: Allocator, path: []const u8) !Self {
        var self = Self{
            .allocator = allocator,
            .path = try allocator.dupe(u8, path),
        };
        errdefer allocator.free(self.path);
        try self.load();
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.close();
        for (self.jobs.items) |*job| job.deinit(self.allocator);
        self.jobs.deinit(self.allocator);
        self.allocator.free(self.path);
    }

    pub fn close(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closed = true;
    }

    pub fn isClosed(self: *Self) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.closed;
    }

    pub fn enqueueFinal(self: *Self, msg: bus.OutboundMessage) !u64 {
        if (msg.stage != .final) return error.InvalidStage;
        if (msg.draft_id != 0) return error.InvalidDraftState;

        self.mutex.lock();
        defer self.mutex.unlock();

        var job = try self.jobFromOutboundLocked(msg);
        const job_id = job.id;
        self.jobs.append(self.allocator, job) catch |err| {
            job.deinit(self.allocator);
            return err;
        };

        const previous_next_id = self.next_id;
        errdefer {
            var removed = self.jobs.swapRemove(self.jobs.items.len - 1);
            removed.deinit(self.allocator);
            self.next_id = previous_next_id;
        }
        self.next_id += 1;
        try self.saveLocked();
        return job_id;
    }

    pub fn pendingCount(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        for (self.jobs.items) |job| {
            if (job.delivered_at_ns == 0 and job.attempts < MAX_DELIVERY_ATTEMPTS) count += 1;
        }
        return count;
    }

    pub fn claimNextReady(self: *Self, allocator: Allocator, now_ns: i64) !?ClaimedJob {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.jobs.items) |*job| {
            if (job.in_flight) continue;
            if (job.delivered_at_ns != 0) continue;
            if (job.attempts >= MAX_DELIVERY_ATTEMPTS) continue;
            if (job.next_attempt_ns > now_ns) continue;

            const claimed = try job.cloneForClaim(allocator);
            job.in_flight = true;
            return claimed;
        }
        return null;
    }

    pub fn recordDelivered(self: *Self, id: u64, now_ns: i64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = self.findJobIndexLocked(id) orelse return error.JobNotFound;
        var job = &self.jobs.items[index];
        job.in_flight = false;
        job.delivered_at_ns = now_ns;
        if (job.last_error) |last_error| {
            self.allocator.free(last_error);
            job.last_error = null;
        }
        try self.saveLocked();
    }

    pub fn purgeDelivered(self: *Self, id: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = self.findJobIndexLocked(id) orelse return error.JobNotFound;
        var removed = self.jobs.swapRemove(index);
        removed.deinit(self.allocator);
        try self.saveLocked();
    }

    pub fn purgePersistedDelivered(self: *Self) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var removed_count: usize = 0;
        var idx: usize = self.jobs.items.len;
        while (idx > 0) {
            idx -= 1;
            if (self.jobs.items[idx].delivered_at_ns == 0) continue;
            var removed = self.jobs.swapRemove(idx);
            removed.deinit(self.allocator);
            removed_count += 1;
        }
        if (removed_count > 0) try self.saveLocked();
        return removed_count;
    }

    pub fn recordFailure(self: *Self, id: u64, err_name: []const u8, now_ns: i64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = self.findJobIndexLocked(id) orelse return error.JobNotFound;
        var job = &self.jobs.items[index];
        job.in_flight = false;
        job.attempts += 1;
        if (job.last_error) |last_error| self.allocator.free(last_error);
        job.last_error = try self.allocator.dupe(u8, err_name);
        job.next_attempt_ns = now_ns + retryBackoffNs(job.attempts);
        try self.saveLocked();
    }

    fn findJobIndexLocked(self: *Self, id: u64) ?usize {
        for (self.jobs.items, 0..) |job, idx| {
            if (job.id == id) return idx;
        }
        return null;
    }

    fn jobFromOutboundLocked(self: *Self, msg: bus.OutboundMessage) !Job {
        const channel = try self.allocator.dupe(u8, msg.channel);
        errdefer self.allocator.free(channel);
        const account_id = if (msg.account_id) |account| try self.allocator.dupe(u8, account) else null;
        errdefer if (account_id) |account| self.allocator.free(account);
        const chat_id = try self.allocator.dupe(u8, msg.chat_id);
        errdefer self.allocator.free(chat_id);
        const content = try self.allocator.dupe(u8, msg.content);
        errdefer self.allocator.free(content);

        const media = if (msg.media.len > 0) blk: {
            const duped = try self.allocator.alloc([]const u8, msg.media.len);
            var i: usize = 0;
            errdefer {
                for (duped[0..i]) |item| self.allocator.free(item);
                self.allocator.free(duped);
            }
            while (i < msg.media.len) : (i += 1) {
                duped[i] = try self.allocator.dupe(u8, msg.media[i]);
            }
            break :blk duped;
        } else &[_][]const u8{};
        errdefer if (media.len > 0) {
            for (media) |item| self.allocator.free(item);
            self.allocator.free(media);
        };

        const choices = if (msg.choices.len > 0) blk: {
            const duped = try self.allocator.alloc(outbound.Choice, msg.choices.len);
            var i: usize = 0;
            errdefer {
                for (duped[0..i]) |choice| choice.deinit(self.allocator);
                self.allocator.free(duped);
            }
            while (i < msg.choices.len) : (i += 1) {
                duped[i] = .{
                    .id = try self.allocator.dupe(u8, msg.choices[i].id),
                    .label = try self.allocator.dupe(u8, msg.choices[i].label),
                    .submit_text = try self.allocator.dupe(u8, msg.choices[i].submit_text),
                };
            }
            break :blk duped;
        } else &[_]outbound.Choice{};

        return .{
            .id = self.next_id,
            .channel = channel,
            .account_id = account_id,
            .chat_id = chat_id,
            .content = content,
            .media = media,
            .choices = choices,
        };
    }

    fn retryBackoffNs(attempt: u32) i64 {
        const idx: usize = @intCast(@min(attempt - 1, RETRY_BACKOFF_MS.len - 1));
        return @as(i64, @intCast(RETRY_BACKOFF_MS[idx])) * std.time.ns_per_ms;
    }

    fn saveLocked(self: *Self) !void {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        defer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "{\n  \"next_id\": ");
        {
            var int_buf: [32]u8 = undefined;
            const text = try std.fmt.bufPrint(&int_buf, "{d}", .{self.next_id});
            try buf.appendSlice(self.allocator, text);
        }
        try buf.appendSlice(self.allocator, ",\n  \"jobs\": [");

        for (self.jobs.items, 0..) |job, idx| {
            if (idx != 0) try buf.appendSlice(self.allocator, ",");
            try buf.appendSlice(self.allocator, "\n    {");
            try json_util.appendJsonKeyValue(&buf, self.allocator, "channel", job.channel);
            try buf.appendSlice(self.allocator, ",");
            try json_util.appendJsonInt(&buf, self.allocator, "id", @intCast(job.id));
            try buf.appendSlice(self.allocator, ",");
            try appendOptionalJsonString(&buf, self.allocator, "account_id", job.account_id);
            try buf.appendSlice(self.allocator, ",");
            try json_util.appendJsonKeyValue(&buf, self.allocator, "chat_id", job.chat_id);
            try buf.appendSlice(self.allocator, ",");
            try json_util.appendJsonKeyValue(&buf, self.allocator, "content", job.content);
            try buf.appendSlice(self.allocator, ",");
            try appendJsonStringArray(&buf, self.allocator, "media", job.media);
            try buf.appendSlice(self.allocator, ",");
            try appendChoices(&buf, self.allocator, job.choices);
            try buf.appendSlice(self.allocator, ",");
            try json_util.appendJsonInt(&buf, self.allocator, "attempts", job.attempts);
            try buf.appendSlice(self.allocator, ",");
            try json_util.appendJsonInt(&buf, self.allocator, "next_attempt_ns", job.next_attempt_ns);
            try buf.appendSlice(self.allocator, ",");
            try appendOptionalJsonString(&buf, self.allocator, "last_error", job.last_error);
            try buf.appendSlice(self.allocator, ",");
            try json_util.appendJsonInt(&buf, self.allocator, "delivered_at_ns", job.delivered_at_ns);
            try buf.appendSlice(self.allocator, "\n    }");
        }

        try buf.appendSlice(self.allocator, "\n  ]\n}\n");

        const tmp_path = try std.fmt.allocPrint(self.allocator, "{s}.tmp", .{self.path});
        defer self.allocator.free(tmp_path);

        const tmp_file = try std_compat.fs.createFileAbsolute(tmp_path, .{});
        defer tmp_file.close();
        try tmp_file.writeAll(buf.items);

        std_compat.fs.renameAbsolute(tmp_path, self.path) catch {
            std_compat.fs.deleteFileAbsolute(tmp_path) catch {};
            const file = try std_compat.fs.createFileAbsolute(self.path, .{});
            defer file.close();
            try file.writeAll(buf.items);
        };
    }

    fn load(self: *Self) !void {
        const file = std_compat.fs.openFileAbsolute(self.path, .{}) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, content, .{}) catch return;
        defer parsed.deinit();

        const root_value = switch (parsed.value) {
            .object => |object| object,
            else => return,
        };
        if (root_value.get("next_id")) |value| {
            if (value == .integer and value.integer > 0) {
                self.next_id = @intCast(value.integer);
            }
        }
        const jobs_value = root_value.get("jobs") orelse return;
        if (jobs_value != .array) return;

        for (jobs_value.array.items) |job_value| {
            if (job_value != .object) continue;
            const object = job_value.object;

            const id_value = object.get("id") orelse continue;
            const channel = jsonString(object.get("channel")) orelse continue;
            const chat_id = jsonString(object.get("chat_id")) orelse continue;
            const content_value = jsonString(object.get("content")) orelse continue;

            var job = Job{
                .id = if (id_value == .integer) @intCast(id_value.integer) else continue,
                .channel = try self.allocator.dupe(u8, channel),
                .account_id = if (jsonString(object.get("account_id"))) |account_id| try self.allocator.dupe(u8, account_id) else null,
                .chat_id = try self.allocator.dupe(u8, chat_id),
                .content = try self.allocator.dupe(u8, content_value),
                .attempts = if (object.get("attempts")) |value| if (value == .integer and value.integer >= 0) @intCast(value.integer) else 0 else 0,
                .next_attempt_ns = if (object.get("next_attempt_ns")) |value| if (value == .integer) value.integer else 0 else 0,
                .last_error = if (jsonString(object.get("last_error"))) |last_error| try self.allocator.dupe(u8, last_error) else null,
                .delivered_at_ns = if (object.get("delivered_at_ns")) |value| if (value == .integer and value.integer >= 0) value.integer else 0 else 0,
            };
            errdefer job.deinit(self.allocator);

            job.media = try parseStringArray(self.allocator, object.get("media"));
            job.choices = try parseChoices(self.allocator, object.get("choices"));
            try self.jobs.append(self.allocator, job);
            if (job.id >= self.next_id) self.next_id = job.id + 1;
        }
    }
};

fn appendOptionalJsonString(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: Allocator,
    key: []const u8,
    value: ?[]const u8,
) !void {
    try json_util.appendJsonKey(buf, allocator, key);
    if (value) |slice| {
        try json_util.appendJsonString(buf, allocator, slice);
    } else {
        try buf.appendSlice(allocator, "null");
    }
}

fn appendJsonStringArray(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: Allocator,
    key: []const u8,
    values: []const []const u8,
) !void {
    try json_util.appendJsonKey(buf, allocator, key);
    try buf.append(allocator, '[');
    for (values, 0..) |value, idx| {
        if (idx != 0) try buf.append(allocator, ',');
        try json_util.appendJsonString(buf, allocator, value);
    }
    try buf.append(allocator, ']');
}

fn appendChoices(
    buf: *std.ArrayListUnmanaged(u8),
    allocator: Allocator,
    choices: []const outbound.Choice,
) !void {
    try json_util.appendJsonKey(buf, allocator, "choices");
    try buf.append(allocator, '[');
    for (choices, 0..) |choice, idx| {
        if (idx != 0) try buf.append(allocator, ',');
        try buf.append(allocator, '{');
        try json_util.appendJsonKeyValue(buf, allocator, "id", choice.id);
        try buf.append(allocator, ',');
        try json_util.appendJsonKeyValue(buf, allocator, "label", choice.label);
        try buf.append(allocator, ',');
        try json_util.appendJsonKeyValue(buf, allocator, "submit_text", choice.submit_text);
        try buf.append(allocator, '}');
    }
    try buf.append(allocator, ']');
}

fn jsonString(value: ?std.json.Value) ?[]const u8 {
    const v = value orelse return null;
    return if (v == .string) v.string else null;
}

fn parseStringArray(allocator: Allocator, value: ?std.json.Value) ![]const []const u8 {
    const array_value = value orelse return &.{};
    if (array_value != .array) return &.{};
    if (array_value.array.items.len == 0) return &.{};

    const duped = try allocator.alloc([]const u8, array_value.array.items.len);
    var count: usize = 0;
    errdefer {
        for (duped[0..count]) |item| allocator.free(item);
        allocator.free(duped);
    }

    for (array_value.array.items) |entry| {
        if (entry != .string) continue;
        duped[count] = try allocator.dupe(u8, entry.string);
        count += 1;
    }
    if (count == duped.len) return duped;
    if (count == 0) {
        allocator.free(duped);
        return &.{};
    }

    const trimmed = try allocator.alloc([]const u8, count);
    @memcpy(trimmed, duped[0..count]);
    allocator.free(duped);
    return trimmed;
}

fn parseChoices(allocator: Allocator, value: ?std.json.Value) ![]const outbound.Choice {
    const array_value = value orelse return &.{};
    if (array_value != .array) return &.{};
    if (array_value.array.items.len == 0) return &.{};

    const duped = try allocator.alloc(outbound.Choice, array_value.array.items.len);
    var count: usize = 0;
    errdefer {
        for (duped[0..count]) |choice| choice.deinit(allocator);
        allocator.free(duped);
    }

    for (array_value.array.items) |entry| {
        if (entry != .object) continue;
        const id = jsonString(entry.object.get("id")) orelse continue;
        const label = jsonString(entry.object.get("label")) orelse continue;
        const submit_text = jsonString(entry.object.get("submit_text")) orelse continue;
        duped[count] = .{
            .id = try allocator.dupe(u8, id),
            .label = try allocator.dupe(u8, label),
            .submit_text = try allocator.dupe(u8, submit_text),
        };
        count += 1;
    }

    if (count == duped.len) return duped;
    if (count == 0) {
        allocator.free(duped);
        return &.{};
    }

    const trimmed = try allocator.alloc(outbound.Choice, count);
    @memcpy(trimmed, duped[0..count]);
    allocator.free(duped);
    return trimmed;
}

test "delivery outbox persists and reloads final message" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_root = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);
    const path = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_root, "outbox.json" });
    defer std.testing.allocator.free(path);

    var outbox = try DeliveryOutbox.init(std.testing.allocator, path);
    defer outbox.deinit();

    const choices = [_]outbound.Choice{
        .{ .id = "1", .label = "One", .submit_text = "/one" },
    };
    var msg = try bus.makeOutboundWithChoices(std.testing.allocator, "qq", "chat-1", "hello", &choices);
    defer msg.deinit(std.testing.allocator);
    msg.account_id = try std.testing.allocator.dupe(u8, "main");

    _ = try outbox.enqueueFinal(msg);
    try std.testing.expectEqual(@as(usize, 1), outbox.pendingCount());

    var reopened = try DeliveryOutbox.init(std.testing.allocator, path);
    defer reopened.deinit();
    try std.testing.expectEqual(@as(usize, 1), reopened.pendingCount());

    var claimed = (try reopened.claimNextReady(std.testing.allocator, 0)).?;
    defer claimed.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("qq", claimed.channel);
    try std.testing.expectEqualStrings("main", claimed.account_id.?);
    try std.testing.expectEqualStrings("chat-1", claimed.chat_id);
    try std.testing.expectEqualStrings("hello", claimed.content);
    try std.testing.expectEqual(@as(usize, 1), claimed.choices.len);
}

// Regression: a failed save must not leave a phantom in-memory job behind.
test "delivery outbox rolls back failed enqueue persistence" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_root = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);
    const state_dir = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_root, "missing" });
    defer std.testing.allocator.free(state_dir);
    const path = try std_compat.fs.path.join(std.testing.allocator, &.{ state_dir, "outbox.json" });
    defer std.testing.allocator.free(path);

    var outbox = try DeliveryOutbox.init(std.testing.allocator, path);
    defer outbox.deinit();

    var msg = try bus.makeOutbound(std.testing.allocator, "qq", "chat-1", "hello");
    defer msg.deinit(std.testing.allocator);

    try std.testing.expectError(error.FileNotFound, outbox.enqueueFinal(msg));
    try std.testing.expectEqual(@as(usize, 0), outbox.pendingCount());
    try std.testing.expect((try outbox.claimNextReady(std.testing.allocator, 0)) == null);

    try std_compat.fs.makeDirAbsolute(state_dir);
    try std.testing.expectEqual(@as(u64, 1), try outbox.enqueueFinal(msg));
    try std.testing.expectEqual(@as(usize, 1), outbox.pendingCount());
}

test "delivery outbox failure keeps job durable for retry" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_root = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);
    const path = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_root, "outbox.json" });
    defer std.testing.allocator.free(path);

    var outbox = try DeliveryOutbox.init(std.testing.allocator, path);
    defer outbox.deinit();

    var msg = try bus.makeOutbound(std.testing.allocator, "qq", "chat-1", "hello");
    defer msg.deinit(std.testing.allocator);

    const id = try outbox.enqueueFinal(msg);
    var claimed = (try outbox.claimNextReady(std.testing.allocator, 0)).?;
    claimed.deinit(std.testing.allocator);

    try outbox.recordFailure(id, "QQApiError", 0);
    try std.testing.expectEqual(@as(usize, 1), outbox.pendingCount());

    var reopened = try DeliveryOutbox.init(std.testing.allocator, path);
    defer reopened.deinit();
    try std.testing.expectEqual(@as(usize, 1), reopened.pendingCount());
}

// Regression: a post-send crash must not cause the same durable job to become ready again.
test "delivery outbox persists delivered acknowledgement across restart" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_root = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_root);
    const path = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_root, "outbox.json" });
    defer std.testing.allocator.free(path);

    var outbox = try DeliveryOutbox.init(std.testing.allocator, path);
    defer outbox.deinit();

    var msg = try bus.makeOutbound(std.testing.allocator, "qq", "chat-1", "hello");
    defer msg.deinit(std.testing.allocator);

    const id = try outbox.enqueueFinal(msg);
    var claimed = (try outbox.claimNextReady(std.testing.allocator, 0)).?;
    claimed.deinit(std.testing.allocator);

    try outbox.recordDelivered(id, 1234);
    try std.testing.expectEqual(@as(usize, 0), outbox.pendingCount());
    try std.testing.expect((try outbox.claimNextReady(std.testing.allocator, 1234)) == null);

    var reopened = try DeliveryOutbox.init(std.testing.allocator, path);
    defer reopened.deinit();
    try std.testing.expectEqual(@as(usize, 0), reopened.pendingCount());
    try std.testing.expect((try reopened.claimNextReady(std.testing.allocator, 1234)) == null);

    try std.testing.expectEqual(@as(usize, 1), try reopened.purgePersistedDelivered());
    try std.testing.expectEqual(@as(usize, 0), reopened.pendingCount());
}
