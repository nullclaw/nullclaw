const std = @import("std");

pub const buffer = @import("buffer.zig");

pub const proto = @import("proto.zig");
pub const OpCode = proto.OpCode;
pub const Message = proto.Message;
pub const MessageType = Message.Type;
pub const MessageTextType = Message.TextType;

pub const Client = @import("client/client.zig").Client;

pub const server = @import("server/server.zig");
pub const testing = @import("testing.zig");

pub const Conn = server.Conn;
pub const Config = server.Config;
pub const Server = server.Server;
pub const blockingMode = server.blockingMode;
pub const Handshake = @import("server/handshake.zig").Handshake;

pub const Compression = struct {
    write_threshold: ?usize = null,
    retain_write_buffer: bool = true,
    // don't know how to support these with the Zig 0.15 changes. So, for now
    // we'll always require these to be true
    // client_no_context_takeover: bool = false,
    // server_no_context_takeover: bool = false,
};

pub fn bufferProvider(allocator: std.mem.Allocator, config: buffer.Config) !buffer.Provider {
    return buffer.Provider.init(allocator, config);
}

pub fn frameText(comptime msg: []const u8) [proto.calculateFrameLen(msg)]u8 {
    return proto.frame(.text, msg);
}

pub fn frameBin(comptime msg: []const u8) [proto.calculateFrameLen(msg)]u8 {
    return proto.frame(.binary, msg);
}

comptime {
    std.testing.refAllDecls(@This());
}

const t = @import("t.zig");
test "frameText" {
    {
        const framed = frameText("");
        try t.expectString(&[_]u8{ 129, 0 }, &framed);
    }

    {
        // short
        const framed = frameText("hello");
        try t.expectString(&[_]u8{ 129, 5, 'h', 'e', 'l', 'l', 'o' }, &framed);
    }

    {
        const msg = "A" ** 130;
        const framed = frameText(msg);

        try t.expectEqual(134, framed.len);

        // text type
        try t.expectEqual(129, framed[0]);

        // 2 byte length marker
        try t.expectEqual(126, framed[1]);

        try t.expectEqual(0, framed[2]);
        try t.expectEqual(130, framed[3]);

        // payload
        for (framed[4..]) |f| {
            try t.expectEqual('A', f);
        }
    }
}

test "frameBin" {
    {
        // short
        const framed = frameBin("hello");
        try t.expectString(&[_]u8{ 130, 5, 'h', 'e', 'l', 'l', 'o' }, &framed);
    }

    {
        const msg = "A" ** 130;
        const framed = frameBin(msg);

        try t.expectEqual(134, framed.len);

        // text type
        try t.expectEqual(130, framed[0]);

        // 2 byte length marker
        try t.expectEqual(126, framed[1]);

        try t.expectEqual(0, framed[2]);
        try t.expectEqual(130, framed[3]);

        // payload
        for (framed[4..]) |f| {
            try t.expectEqual('A', f);
        }
    }
}
