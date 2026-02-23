const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const bus = @import("../bus.zig");

const log = std.log.scoped(.maixcam);

/// MaixCam Hardware Channel — TCP server for MaixCam vision devices.
///
/// Listens on a configurable port, accepts multiple device connections.
/// Each device sends newline-delimited JSON messages:
///   {"type": "person_detected", "confidence": 0.95, "device_id": "maixcam-01", "timestamp": 1234567890}
///   {"type": "message", "text": "...", "device_id": "maixcam-01"}
///
/// Events are converted to InboundMessages and published to the bus.
/// Outbound messages are broadcast as JSON to all connected devices.
pub const MaixCamChannel = struct {
    allocator: std.mem.Allocator,
    config: config_types.MaixCamConfig,
    event_bus: ?*bus.Bus = null,
    running: bool = false,
    clients: std.ArrayListUnmanaged(Client) = .empty,
    clients_mu: std.Thread.Mutex = .{},
    listener_thread: ?std.Thread = null,
    outbound_thread: ?std.Thread = null,

    pub const Client = struct {
        stream: std.net.Stream,
        device_id: ?[]const u8 = null,
    };

    pub fn init(allocator: std.mem.Allocator, config: config_types.MaixCamConfig) MaixCamChannel {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: config_types.MaixCamConfig) MaixCamChannel {
        return init(allocator, cfg);
    }

    pub fn setBus(self: *MaixCamChannel, b: *bus.Bus) void {
        self.event_bus = b;
    }

    pub fn deinit(self: *MaixCamChannel) void {
        self.closeAllClients();
        self.clients.deinit(self.allocator);
    }

    pub fn channelName(self: *MaixCamChannel) []const u8 {
        return self.config.name;
    }

    pub fn healthCheck(self: *MaixCamChannel) bool {
        return self.running;
    }

    /// Return the number of currently connected clients.
    pub fn clientCount(self: *MaixCamChannel) usize {
        self.clients_mu.lock();
        defer self.clients_mu.unlock();
        return self.clients.items.len;
    }

    // ── Device Allowlist ──────────────────────────────────────────

    /// Check if a device_id is permitted by the allowlist.
    /// If the allowlist is empty, all devices are allowed.
    pub fn isDeviceAllowed(self: *const MaixCamChannel, device_id: []const u8) bool {
        if (self.config.allow_from.len == 0) return true;
        for (self.config.allow_from) |allowed| {
            if (std.mem.eql(u8, allowed, "*")) return true;
            if (std.mem.eql(u8, allowed, device_id)) return true;
        }
        return false;
    }

    // ── JSON Message Parsing ──────────────────────────────────────

    /// Parsed device event from a JSON message.
    pub const DeviceEvent = struct {
        /// Owned by caller. Free with deinit().
        event_type: []const u8,
        /// Owned by caller. Free with deinit().
        device_id: []const u8,
        confidence: ?f64 = null,
        /// Owned by caller if non-null. Free with deinit().
        text: ?[]const u8 = null,
        timestamp: u64 = 0,

        pub fn deinit(self: DeviceEvent, allocator: std.mem.Allocator) void {
            allocator.free(self.event_type);
            allocator.free(self.device_id);
            if (self.text) |t| allocator.free(t);
        }
    };

    /// Parse a JSON message from a MaixCam device.
    /// Returns null if parsing fails or required fields are missing.
    /// Caller owns the returned DeviceEvent — call event.deinit(allocator) when done.
    pub fn parseDeviceMessage(allocator: std.mem.Allocator, data: []const u8) ?DeviceEvent {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, data, .{}) catch return null;
        defer parsed.deinit();
        const val = parsed.value;

        if (val != .object) return null;

        // Required: type
        const type_val = val.object.get("type") orelse return null;
        const event_type_raw = if (type_val == .string) type_val.string else return null;

        // Required: device_id
        const did_val = val.object.get("device_id") orelse return null;
        const device_id_raw = if (did_val == .string) did_val.string else return null;

        // Optional: confidence (float)
        var confidence: ?f64 = null;
        if (val.object.get("confidence")) |cv| {
            confidence = switch (cv) {
                .float => cv.float,
                .integer => @floatFromInt(cv.integer),
                else => null,
            };
        }

        // Optional: text
        var text_raw: ?[]const u8 = null;
        if (val.object.get("text")) |tv| {
            if (tv == .string) text_raw = tv.string;
        }

        // Optional: timestamp
        var timestamp: u64 = 0;
        if (val.object.get("timestamp")) |tv| {
            if (tv == .integer) {
                timestamp = if (tv.integer > 0) @intCast(tv.integer) else 0;
            }
        }

        // Dupe all strings before parsed.deinit() frees them
        const event_type = allocator.dupe(u8, event_type_raw) catch return null;
        const device_id = allocator.dupe(u8, device_id_raw) catch {
            allocator.free(event_type);
            return null;
        };
        const text: ?[]const u8 = if (text_raw) |t|
            (allocator.dupe(u8, t) catch {
                allocator.free(event_type);
                allocator.free(device_id);
                return null;
            })
        else
            null;

        return .{
            .event_type = event_type,
            .device_id = device_id,
            .confidence = confidence,
            .text = text,
            .timestamp = timestamp,
        };
    }

    /// Format a device event into a human-readable content string for the bus.
    pub fn formatEventContent(buf: []u8, event: DeviceEvent) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();

        if (std.mem.eql(u8, event.event_type, "person_detected")) {
            if (event.confidence) |conf| {
                try w.print("[Vision] Person detected (confidence: {d:.2})", .{conf});
            } else {
                try w.writeAll("[Vision] Person detected");
            }
        } else if (std.mem.eql(u8, event.event_type, "object_detected")) {
            if (event.text) |label| {
                if (event.confidence) |conf| {
                    try w.print("[Vision] Object detected: {s} (confidence: {d:.2})", .{ label, conf });
                } else {
                    try w.print("[Vision] Object detected: {s}", .{label});
                }
            } else {
                try w.writeAll("[Vision] Object detected");
            }
        } else if (std.mem.eql(u8, event.event_type, "message")) {
            if (event.text) |text| {
                try w.writeAll(text);
            } else {
                try w.writeAll("[MaixCam] (empty message)");
            }
        } else {
            try w.print("[MaixCam] {s}", .{event.event_type});
        }

        return fbs.getWritten();
    }

    // ── Outbound JSON ─────────────────────────────────────────────

    /// Build an outbound JSON message to send to devices.
    pub fn buildOutboundJson(buf: []u8, content: []const u8) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        try w.writeAll("{\"type\":\"response\",\"text\":");
        try root.appendJsonStringW(w, content);
        try w.writeAll("}\n");
        return fbs.getWritten();
    }

    /// Send a message to all connected clients.
    pub fn broadcast(self: *MaixCamChannel, data: []const u8) void {
        self.clients_mu.lock();
        defer self.clients_mu.unlock();

        var i: usize = 0;
        while (i < self.clients.items.len) {
            const client = &self.clients.items[i];
            client.stream.writeAll(data) catch {
                log.warn("client disconnected during broadcast, removing", .{});
                if (client.device_id) |did| self.allocator.free(did);
                client.stream.close();
                _ = self.clients.swapRemove(i);
                continue;
            };
            i += 1;
        }
    }

    /// Send a message to a specific device or broadcast to all.
    pub fn sendMessage(self: *MaixCamChannel, target: []const u8, text: []const u8) !void {
        var json_buf: [4096]u8 = undefined;
        const json = try buildOutboundJson(&json_buf, text);

        if (std.mem.eql(u8, target, "*") or target.len == 0) {
            self.broadcast(json);
        } else {
            self.sendToDevice(target, json);
        }
    }

    fn sendToDevice(self: *MaixCamChannel, device_id: []const u8, data: []const u8) void {
        self.clients_mu.lock();
        defer self.clients_mu.unlock();

        for (self.clients.items) |*client| {
            if (client.device_id) |did| {
                if (std.mem.eql(u8, did, device_id)) {
                    client.stream.writeAll(data) catch {
                        log.warn("send to device {s} failed", .{device_id});
                    };
                    return;
                }
            }
        }
        log.warn("device {s} not found", .{device_id});
    }

    fn closeAllClients(self: *MaixCamChannel) void {
        self.clients_mu.lock();
        defer self.clients_mu.unlock();
        for (self.clients.items) |*client| {
            if (client.device_id) |did| self.allocator.free(did);
            client.stream.close();
        }
        self.clients.clearRetainingCapacity();
    }

    // ── Client Connection Handler ─────────────────────────────────

    fn handleClient(self: *MaixCamChannel, stream: std.net.Stream) void {
        defer {
            self.removeClient(stream);
            stream.close();
        }

        var line_buf: [8192]u8 = undefined;
        var line_len: usize = 0;

        while (self.running) {
            const n = stream.read(line_buf[line_len..]) catch |err| {
                log.debug("client read error: {}", .{err});
                return;
            };
            if (n == 0) return; // EOF

            line_len += n;

            // Process complete lines
            while (std.mem.indexOf(u8, line_buf[0..line_len], "\n")) |newline_pos| {
                const line = line_buf[0..newline_pos];
                if (line.len > 0) {
                    self.processLine(stream, line);
                }
                // Shift remaining data
                const remaining = line_len - (newline_pos + 1);
                if (remaining > 0) {
                    std.mem.copyForwards(u8, &line_buf, line_buf[newline_pos + 1 .. line_len]);
                }
                line_len = remaining;
            }

            // Prevent buffer overflow
            if (line_len >= line_buf.len) {
                log.warn("client line too long, discarding", .{});
                line_len = 0;
            }
        }
    }

    fn processLine(self: *MaixCamChannel, stream: std.net.Stream, line: []const u8) void {
        const event = parseDeviceMessage(self.allocator, line) orelse {
            log.debug("failed to parse device message", .{});
            return;
        };
        defer event.deinit(self.allocator);

        // Check allowlist
        if (!self.isDeviceAllowed(event.device_id)) {
            log.warn("device {s} not in allowlist, ignoring", .{event.device_id});
            return;
        }

        // Update client device_id
        self.updateClientDeviceId(stream, event.device_id);

        // Format content
        var content_buf: [2048]u8 = undefined;
        const content = formatEventContent(&content_buf, event) catch {
            log.err("failed to format event content", .{});
            return;
        };

        // Build session key
        var sk_buf: [256]u8 = undefined;
        var sk_fbs = std.io.fixedBufferStream(&sk_buf);
        sk_fbs.writer().print("maixcam:{s}", .{event.device_id}) catch return;
        const session_key = sk_fbs.getWritten();

        // Publish to bus
        if (self.event_bus) |b| {
            var meta_buf: [128]u8 = undefined;
            var meta_fbs = std.io.fixedBufferStream(&meta_buf);
            const mw = meta_fbs.writer();
            mw.writeAll("{\"account_id\":") catch return;
            root.appendJsonStringW(mw, self.config.account_id) catch return;
            mw.writeByte('}') catch return;
            const metadata = meta_fbs.getWritten();

            const msg = bus.makeInboundFull(
                self.allocator,
                self.config.name,
                event.device_id,
                event.device_id,
                content,
                session_key,
                &.{},
                metadata,
            ) catch {
                log.err("failed to create inbound message", .{});
                return;
            };
            b.publishInbound(msg) catch {
                log.err("failed to publish inbound message", .{});
                msg.deinit(self.allocator);
            };
        }
    }

    fn updateClientDeviceId(self: *MaixCamChannel, stream: std.net.Stream, device_id: []const u8) void {
        self.clients_mu.lock();
        defer self.clients_mu.unlock();
        for (self.clients.items) |*client| {
            if (client.stream.handle == stream.handle) {
                if (client.device_id == null) {
                    client.device_id = self.allocator.dupe(u8, device_id) catch null;
                }
                return;
            }
        }
    }

    fn removeClient(self: *MaixCamChannel, stream: std.net.Stream) void {
        self.clients_mu.lock();
        defer self.clients_mu.unlock();
        for (self.clients.items, 0..) |*client, i| {
            if (client.stream.handle == stream.handle) {
                if (client.device_id) |did| self.allocator.free(did);
                _ = self.clients.swapRemove(i);
                return;
            }
        }
    }

    fn addClient(self: *MaixCamChannel, stream: std.net.Stream) !void {
        self.clients_mu.lock();
        defer self.clients_mu.unlock();
        try self.clients.append(self.allocator, .{ .stream = stream });
    }

    // ── Channel vtable ──────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *MaixCamChannel = @ptrCast(@alignCast(ptr));
        self.running = true;
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *MaixCamChannel = @ptrCast(@alignCast(ptr));
        self.running = false;
        self.closeAllClients();
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, _: []const []const u8) anyerror!void {
        const self: *MaixCamChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessage(target, message);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *MaixCamChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *MaixCamChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
    };

    pub fn channel(self: *MaixCamChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "maixcam config defaults" {
    const config = config_types.MaixCamConfig{};
    try std.testing.expectEqual(@as(u16, 7777), config.port);
    try std.testing.expectEqualStrings("0.0.0.0", config.host);
    try std.testing.expectEqual(@as(usize, 0), config.allow_from.len);
    try std.testing.expectEqualStrings("maixcam", config.name);
}

test "maixcam config custom values" {
    const allowlist = [_][]const u8{ "cam-01", "cam-02" };
    const config = config_types.MaixCamConfig{
        .port = 9999,
        .host = "192.168.1.100",
        .allow_from = &allowlist,
        .name = "vision",
    };
    try std.testing.expectEqual(@as(u16, 9999), config.port);
    try std.testing.expectEqualStrings("192.168.1.100", config.host);
    try std.testing.expectEqual(@as(usize, 2), config.allow_from.len);
    try std.testing.expectEqualStrings("vision", config.name);
}

test "maixcam channel name" {
    var ch = MaixCamChannel.init(std.testing.allocator, .{});
    try std.testing.expectEqualStrings("maixcam", ch.channelName());
}

test "maixcam channel name custom" {
    var ch = MaixCamChannel.init(std.testing.allocator, .{ .name = "vision_hub" });
    try std.testing.expectEqualStrings("vision_hub", ch.channelName());
}

test "maixcam health check false when not running" {
    var ch = MaixCamChannel.init(std.testing.allocator, .{});
    try std.testing.expect(!ch.healthCheck());
}

test "maixcam health check true when running" {
    var ch = MaixCamChannel.init(std.testing.allocator, .{});
    ch.running = true;
    try std.testing.expect(ch.healthCheck());
}

// ── Allowlist Tests ──────────────────────────────────────────────

test "maixcam allowlist empty allows all" {
    const ch = MaixCamChannel.init(std.testing.allocator, .{});
    try std.testing.expect(ch.isDeviceAllowed("anything"));
    try std.testing.expect(ch.isDeviceAllowed("cam-01"));
    try std.testing.expect(ch.isDeviceAllowed(""));
}

test "maixcam allowlist permits listed devices" {
    const allowlist = [_][]const u8{ "cam-01", "cam-02" };
    const ch = MaixCamChannel.init(std.testing.allocator, .{ .allow_from = &allowlist });
    try std.testing.expect(ch.isDeviceAllowed("cam-01"));
    try std.testing.expect(ch.isDeviceAllowed("cam-02"));
    try std.testing.expect(!ch.isDeviceAllowed("cam-03"));
    try std.testing.expect(!ch.isDeviceAllowed(""));
}

test "maixcam allowlist wildcard allows all" {
    const allowlist = [_][]const u8{"*"};
    const ch = MaixCamChannel.init(std.testing.allocator, .{ .allow_from = &allowlist });
    try std.testing.expect(ch.isDeviceAllowed("anything"));
    try std.testing.expect(ch.isDeviceAllowed("cam-99"));
}

test "maixcam allowlist exact match only" {
    const allowlist = [_][]const u8{"cam-01"};
    const ch = MaixCamChannel.init(std.testing.allocator, .{ .allow_from = &allowlist });
    try std.testing.expect(ch.isDeviceAllowed("cam-01"));
    try std.testing.expect(!ch.isDeviceAllowed("CAM-01"));
    try std.testing.expect(!ch.isDeviceAllowed("cam-01 "));
}

// ── JSON Parsing Tests ──────────────────────────────────────────

test "maixcam parse person_detected event" {
    const json =
        \\{"type":"person_detected","confidence":0.95,"device_id":"maixcam-01","timestamp":1234567890}
    ;
    const event = MaixCamChannel.parseDeviceMessage(std.testing.allocator, json).?;
    defer event.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("person_detected", event.event_type);
    try std.testing.expectEqualStrings("maixcam-01", event.device_id);
    try std.testing.expect(event.confidence.? > 0.94 and event.confidence.? < 0.96);
    try std.testing.expectEqual(@as(u64, 1234567890), event.timestamp);
    try std.testing.expect(event.text == null);
}

test "maixcam parse message event" {
    const json =
        \\{"type":"message","text":"Hello from camera","device_id":"cam-02"}
    ;
    const event = MaixCamChannel.parseDeviceMessage(std.testing.allocator, json).?;
    defer event.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("message", event.event_type);
    try std.testing.expectEqualStrings("cam-02", event.device_id);
    try std.testing.expectEqualStrings("Hello from camera", event.text.?);
    try std.testing.expect(event.confidence == null);
}

test "maixcam parse object_detected event" {
    const json =
        \\{"type":"object_detected","confidence":0.87,"device_id":"cam-03","text":"cat"}
    ;
    const event = MaixCamChannel.parseDeviceMessage(std.testing.allocator, json).?;
    defer event.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("object_detected", event.event_type);
    try std.testing.expectEqualStrings("cam-03", event.device_id);
    try std.testing.expectEqualStrings("cat", event.text.?);
    try std.testing.expect(event.confidence.? > 0.86 and event.confidence.? < 0.88);
}

test "maixcam parse missing type returns null" {
    const json =
        \\{"device_id":"cam-01","confidence":0.5}
    ;
    try std.testing.expect(MaixCamChannel.parseDeviceMessage(std.testing.allocator, json) == null);
}

test "maixcam parse missing device_id returns null" {
    const json =
        \\{"type":"person_detected","confidence":0.5}
    ;
    try std.testing.expect(MaixCamChannel.parseDeviceMessage(std.testing.allocator, json) == null);
}

test "maixcam parse invalid json returns null" {
    try std.testing.expect(MaixCamChannel.parseDeviceMessage(std.testing.allocator, "not json") == null);
    try std.testing.expect(MaixCamChannel.parseDeviceMessage(std.testing.allocator, "") == null);
    try std.testing.expect(MaixCamChannel.parseDeviceMessage(std.testing.allocator, "{}") == null);
}

test "maixcam parse integer confidence" {
    const json =
        \\{"type":"person_detected","confidence":1,"device_id":"cam-01"}
    ;
    const event = MaixCamChannel.parseDeviceMessage(std.testing.allocator, json).?;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event.confidence.? > 0.99 and event.confidence.? < 1.01);
}

test "maixcam parse zero timestamp" {
    const json =
        \\{"type":"message","text":"hi","device_id":"cam-01","timestamp":0}
    ;
    const event = MaixCamChannel.parseDeviceMessage(std.testing.allocator, json).?;
    defer event.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 0), event.timestamp);
}

// ── Event Formatting Tests ──────────────────────────────────────

test "maixcam format person_detected with confidence" {
    var buf: [512]u8 = undefined;
    const content = try MaixCamChannel.formatEventContent(&buf, .{
        .event_type = "person_detected",
        .device_id = "cam-01",
        .confidence = 0.95,
    });
    try std.testing.expectEqualStrings("[Vision] Person detected (confidence: 0.95)", content);
}

test "maixcam format person_detected without confidence" {
    var buf: [512]u8 = undefined;
    const content = try MaixCamChannel.formatEventContent(&buf, .{
        .event_type = "person_detected",
        .device_id = "cam-01",
    });
    try std.testing.expectEqualStrings("[Vision] Person detected", content);
}

test "maixcam format message with text" {
    var buf: [512]u8 = undefined;
    const content = try MaixCamChannel.formatEventContent(&buf, .{
        .event_type = "message",
        .device_id = "cam-01",
        .text = "Status: OK",
    });
    try std.testing.expectEqualStrings("Status: OK", content);
}

test "maixcam format message without text" {
    var buf: [512]u8 = undefined;
    const content = try MaixCamChannel.formatEventContent(&buf, .{
        .event_type = "message",
        .device_id = "cam-01",
    });
    try std.testing.expectEqualStrings("[MaixCam] (empty message)", content);
}

test "maixcam format object_detected with label and confidence" {
    var buf: [512]u8 = undefined;
    const content = try MaixCamChannel.formatEventContent(&buf, .{
        .event_type = "object_detected",
        .device_id = "cam-01",
        .confidence = 0.87,
        .text = "cat",
    });
    try std.testing.expectEqualStrings("[Vision] Object detected: cat (confidence: 0.87)", content);
}

test "maixcam format unknown event type" {
    var buf: [512]u8 = undefined;
    const content = try MaixCamChannel.formatEventContent(&buf, .{
        .event_type = "motion_start",
        .device_id = "cam-01",
    });
    try std.testing.expectEqualStrings("[MaixCam] motion_start", content);
}

// ── Outbound JSON Tests ─────────────────────────────────────────

test "maixcam build outbound json" {
    var buf: [512]u8 = undefined;
    const json = try MaixCamChannel.buildOutboundJson(&buf, "Hello device");
    try std.testing.expectEqualStrings("{\"type\":\"response\",\"text\":\"Hello device\"}\n", json);
}

test "maixcam build outbound json with special chars" {
    var buf: [512]u8 = undefined;
    const json = try MaixCamChannel.buildOutboundJson(&buf, "line1\nline2");
    try std.testing.expectEqualStrings("{\"type\":\"response\",\"text\":\"line1\\nline2\"}\n", json);
}

test "maixcam build outbound json with quotes" {
    var buf: [512]u8 = undefined;
    const json = try MaixCamChannel.buildOutboundJson(&buf, "say \"hello\"");
    try std.testing.expectEqualStrings("{\"type\":\"response\",\"text\":\"say \\\"hello\\\"\"}\n", json);
}

// ── Vtable Tests ────────────────────────────────────────────────

test "maixcam vtable compiles" {
    try std.testing.expect(@intFromPtr(MaixCamChannel.vtable.start) != 0);
    try std.testing.expect(@intFromPtr(MaixCamChannel.vtable.stop) != 0);
    try std.testing.expect(@intFromPtr(MaixCamChannel.vtable.send) != 0);
    try std.testing.expect(@intFromPtr(MaixCamChannel.vtable.name) != 0);
    try std.testing.expect(@intFromPtr(MaixCamChannel.vtable.healthCheck) != 0);
}

test "maixcam channel interface" {
    var ch = MaixCamChannel.init(std.testing.allocator, .{});
    const iface = ch.channel();
    try std.testing.expectEqualStrings("maixcam", iface.name());
}

test "maixcam channel start and stop" {
    var ch = MaixCamChannel.init(std.testing.allocator, .{});
    const iface = ch.channel();
    try iface.start();
    try std.testing.expect(ch.running);
    iface.stop();
    try std.testing.expect(!ch.running);
}

test "maixcam init stores config" {
    const allowlist = [_][]const u8{"cam-01"};
    const ch = MaixCamChannel.init(std.testing.allocator, .{
        .port = 8888,
        .host = "127.0.0.1",
        .allow_from = &allowlist,
        .name = "test_cam",
    });
    try std.testing.expectEqual(@as(u16, 8888), ch.config.port);
    try std.testing.expectEqualStrings("127.0.0.1", ch.config.host);
    try std.testing.expectEqual(@as(usize, 1), ch.config.allow_from.len);
    try std.testing.expectEqualStrings("test_cam", ch.config.name);
}

test "maixcam client count starts at zero" {
    var ch = MaixCamChannel.init(std.testing.allocator, .{});
    try std.testing.expectEqual(@as(usize, 0), ch.clientCount());
}
