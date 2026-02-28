const providers = @import("providers/root.zig");

pub const OutboundStage = enum {
    chunk,
    final,
};

pub const Event = struct {
    stage: OutboundStage,
    text: []const u8 = "",
};

pub const Sink = struct {
    callback: *const fn (ctx: *anyopaque, event: Event) void,
    ctx: *anyopaque,

    pub fn emit(self: Sink, event: Event) void {
        self.callback(self.ctx, event);
    }

    pub fn emitChunk(self: Sink, text: []const u8) void {
        if (text.len == 0) return;
        self.emit(.{
            .stage = .chunk,
            .text = text,
        });
    }

    pub fn emitFinal(self: Sink) void {
        self.emit(.{ .stage = .final });
    }
};

pub fn eventFromProviderChunk(chunk: providers.StreamChunk) ?Event {
    if (chunk.is_final) return .{ .stage = .final };
    if (chunk.delta.len == 0) return null;
    return .{
        .stage = .chunk,
        .text = chunk.delta,
    };
}

pub fn forwardProviderChunk(sink: Sink, chunk: providers.StreamChunk) void {
    if (eventFromProviderChunk(chunk)) |event| {
        sink.emit(event);
    }
}
