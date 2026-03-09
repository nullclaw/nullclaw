const std = @import("std");

const Allocator = std.mem.Allocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;

// std.heap.StackFallbackAllocator is very specific. It's really _stack_ as it
// requires a comptime size. Also, it uses non-public calls from the FixedBufferAllocator.
// There should be a more generic FallbackAllocator that just takes 2 allocators...
// which is what this is.
pub const FallbackAllocator = struct {
    fixed: Allocator,
    fallback: Allocator,
    fba: *FixedBufferAllocator,

    pub fn allocator(self: *FallbackAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
                .remap = remap,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *FallbackAllocator = @ptrCast(@alignCast(ctx));
        return self.fixed.rawAlloc(len, alignment, ra) orelse self.fallback.rawAlloc(len, alignment, ra);
    }

    fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *FallbackAllocator = @ptrCast(@alignCast(ctx));
        if (self.fba.ownsPtr(buf.ptr)) {
            if (self.fixed.rawResize(buf, alignment, new_len, ra)) {
                return true;
            }
        }
        return self.fallback.rawResize(buf, alignment, new_len, ra);
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ra: usize) void {
        _ = ctx;
        _ = buf;
        _ = alignment;
        _ = ra;
        // hack.
        // Always noop since, in our specific usage, we know fallback is an arena.
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        if (resize(ctx, memory, alignment, new_len, ret_addr)) {
            return memory.ptr;
        }
        return null;
    }
};
