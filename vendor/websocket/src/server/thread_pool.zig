const std = @import("std");

const Thread = std.Thread;
const Allocator = std.mem.Allocator;

pub const Opts = struct {
    count: u16,
    backlog: u32,
    buffer_size: usize,
};

pub fn ThreadPool(comptime F: anytype) type {
    // When the worker thread calls F, it'll inject its static buffer.
    // So F would be: handle(server: *Server, conn: *Conn, buf: []u8)
    // and FullArgs would be our 3 args....
    const FullArgs = std.meta.ArgsTuple(@TypeOf(F));
    const full_fields = std.meta.fields(FullArgs);
    const ARG_COUNT = full_fields.len - 1;

    // Args will be FullArgs[0..len-1], so in the above example, args would be
    // (*Server, *Conn)
    // Args is what we expect the caller to pass to spawn. The worker thread
    // will convert an Args into FullArgs by injecting its static buffer as
    // the final argument.

    // TODO: We could verify that the last argument to FullArgs is, in fact, a
    // []u8. But this ThreadPool is private and being used for 2 specific cases
    // that we control.

    var fields: [ARG_COUNT]std.builtin.Type.StructField = undefined;
    inline for (full_fields[0..ARG_COUNT], 0..) |field, index| fields[index] = field;

    const Args = comptime @Type(.{
        .@"struct" = .{
            .layout = .auto,
            .is_tuple = true,
            .fields = &fields,
            .decls = &.{},
        },
    });

    return struct {
        stopped: bool,
        push: usize,
        pull: usize,
        pending: usize,
        queue: []Args,
        threads: []Thread,
        mutex: Thread.Mutex,
        pull_cond: Thread.Condition,
        push_cond: Thread.Condition,
        queue_end: usize,
        allocator: Allocator,

        const Self = @This();

        pub fn init(allocator: Allocator, opts: Opts) !*Self {
            const queue = try allocator.alloc(Args, opts.backlog);
            errdefer allocator.free(queue);

            const threads = try allocator.alloc(Thread, opts.count);
            errdefer allocator.free(threads);

            const thread_pool = try allocator.create(Self);
            errdefer allocator.destroy(thread_pool);

            thread_pool.* = .{
                .pull = 0,
                .push = 0,
                .pending = 0,
                .mutex = .{},
                .stopped = false,
                .queue = queue,
                .pull_cond = .{},
                .push_cond = .{},
                .threads = threads,
                .allocator = allocator,
                .queue_end = queue.len - 1,
            };

            var started: usize = 0;
            errdefer {
                thread_pool.stopped = true;
                thread_pool.pull_cond.broadcast();
                for (0..started) |i| {
                    threads[i].join();
                }
            }

            for (0..threads.len) |i| {
                // This becomes owned by the thread, it'll free it as it ends
                const buffer = try allocator.alloc(u8, opts.buffer_size);
                errdefer allocator.free(buffer);

                threads[i] = try Thread.spawn(.{}, Self.worker, .{ thread_pool, buffer });
                started += 1;
            }

            return thread_pool;
        }

        pub fn deinit(self: *Self) void {
            const allocator = self.allocator;
            self.stop();
            allocator.free(self.threads);
            allocator.free(self.queue);

            allocator.destroy(self);
        }

        pub fn stop(self: *Self) void {
            {
                self.mutex.lock();
                defer self.mutex.unlock();
                if (self.stopped == true) {
                    return;
                }
                self.stopped = true;
            }

            self.pull_cond.broadcast();
            for (self.threads) |thrd| {
                thrd.join();
            }
        }

        pub fn empty(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.pull == self.push;
        }

        pub fn spawn(self: *Self, args: Args) void {
            const queue = self.queue;
            const len = queue.len;

            self.mutex.lock();
            while (self.pending == len) {
                self.push_cond.wait(&self.mutex);
            }

            const push = self.push;
            self.queue[push] = args;
            self.push = if (push == self.queue_end) 0 else push + 1;
            self.pending += 1;
            self.mutex.unlock();

            self.pull_cond.signal();
        }

        fn worker(self: *Self, buffer: []u8) void {
            // Having a re-usable buffer per thread is the most efficient way
            // we can do any dynamic allocations. We'll pair this later with
            // a FallbackAllocator. The main issue is that some data must outlive
            // the worker thread (in nonblocking mode), but this isn't something
            // we need to worry about here. As far as this worker thread is
            // concerned, it has a chunk of memory (buffer) which it'll pass
            // to the callback function to do with as it wants.
            defer self.allocator.free(buffer);

            while (true) {
                self.mutex.lock();
                while (self.pending == 0) {
                    if (self.stopped) {
                        self.mutex.unlock();
                        return;
                    }
                    self.pull_cond.wait(&self.mutex);
                }
                const pull = self.pull;
                const args = self.queue[pull];
                self.pull = if (pull == self.queue_end) 0 else pull + 1;
                self.pending -= 1;
                self.mutex.unlock();
                self.push_cond.signal();

                // convert Args to FullArgs, i.e. inject buffer as the last argument
                var full_args: FullArgs = undefined;
                full_args[ARG_COUNT] = buffer;
                inline for (0..ARG_COUNT) |i| {
                    full_args[i] = args[i];
                }
                @call(.auto, F, full_args);
            }
        }
    };
}

const t = @import("../t.zig");
test "ThreadPool: small fuzz" {
    testSum = 0; // global defined near the end of this file
    var tp = try ThreadPool(testIncr).init(t.allocator, .{ .count = 3, .backlog = 3, .buffer_size = 512 });

    for (0..50_000) |_| {
        tp.spawn(.{1});
    }
    while (tp.empty() == false) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    tp.deinit();
    try t.expectEqual(50_000, testSum);
}

test "ThreadPool: large fuzz" {
    testSum = 0; // global defined near the end of this file
    var tp = try ThreadPool(testIncr).init(t.allocator, .{ .count = 50, .backlog = 1000, .buffer_size = 512 });

    for (0..50_000) |_| {
        tp.spawn(.{1});
    }
    while (tp.empty() == false) {
        std.Thread.sleep(std.time.ns_per_ms);
    }
    tp.deinit();
    try t.expectEqual(50_000, testSum);
}

var testSum: u64 = 0;
fn testIncr(c: u64, buf: []u8) void {
    std.debug.assert(buf.len == 512);
    _ = @atomicRmw(u64, &testSum, .Add, c, .monotonic);
    // let the threadpool queue get backed up
    std.Thread.sleep(std.time.ns_per_us * 100);
}
