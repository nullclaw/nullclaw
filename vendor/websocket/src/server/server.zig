const std = @import("std");
const builtin = @import("builtin");
const proto = @import("../proto.zig");
const buffer = @import("../buffer.zig");

const net = std.net;
const posix = std.posix;
const Thread = std.Thread;
const Allocator = std.mem.Allocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;

const log = std.log.scoped(.websocket);

const OpCode = proto.OpCode;
const Reader = proto.Reader;
const Message = proto.Message;
pub const Handshake = @import("handshake.zig").Handshake;
const Compression = @import("../websocket.zig").Compression;
const FallbackAllocator = @import("fallback_allocator.zig").FallbackAllocator;

const DEFAULT_MAX_CONN = 16_384;
const DEFAULT_BUFFER_SIZE = 2048;
const DEFAULT_MAX_MESSAGE_SIZE = 65_536;

const EMPTY_PONG = ([2]u8{ @intFromEnum(OpCode.pong), 0 })[0..];
// CLOSE, 2 length, code
const CLOSE_NORMAL = ([_]u8{ @intFromEnum(OpCode.close), 2, 3, 232 })[0..]; // code: 1000
const CLOSE_PROTOCOL_ERROR = ([_]u8{ @intFromEnum(OpCode.close), 2, 3, 234 })[0..]; //code: 1002

const force_blocking: bool = blk: {
    const build = @import("build");
    if (@hasDecl(build, "websocket_blocking")) {
        break :blk build.websocket_blocking;
    }
    break :blk false;
};

pub fn blockingMode() bool {
    if (force_blocking) {
        return true;
    }
    return switch (builtin.os.tag) {
        .linux, .macos, .ios, .tvos, .watchos, .freebsd, .netbsd, .dragonfly, .openbsd => false,
        else => true,
    };
}

pub const Config = struct {
    port: u16 = 9882,
    address: []const u8 = "127.0.0.1",
    unix_path: ?[]const u8 = null,

    worker_count: ?u8 = null,

    max_conn: ?usize = null,
    max_message_size: ?usize = null,

    handshake: Config.Handshake = .{},
    thread_pool: ThreadPool = .{},
    buffers: Config.Buffers = .{},
    compression: ?Compression = null,

    pub const ThreadPool = struct {
        count: ?u16 = null,
        backlog: ?u32 = null,
        buffer_size: ?usize = null,
    };

    pub const Handshake = struct {
        timeout: u32 = 10,
        max_size: ?u16 = null,
        max_headers: ?u16 = null,
        max_res_headers: ?u16 = null,
        count: ?u16 = null,
    };

    pub const Buffers = struct {
        small_size: ?usize = null,
        small_pool: ?usize = null,
        large_size: ?usize = null,
        large_pool: ?u16 = null,
    };

    fn workerCount(self: *const Config) usize {
        if (comptime blockingMode()) {
            return 1;
        }
        return self.worker_count orelse 1;
    }
};

pub fn Server(comptime H: type) type {
    return struct {
        config: Config,
        allocator: Allocator,

        _state: WorkerState,
        _signals: []posix.fd_t,
        _mut: Thread.Mutex,
        _cond: Thread.Condition,

        const Self = @This();

        pub fn init(allocator: Allocator, config: Config) !Self {
            if (blockingMode()) {
                if (config.buffers.small_pool) |p| {
                    if (p > 1) {
                        log.warn("blockingMode() cannot utilize a small buffer pool, using per-connection buffer instead", .{});
                    }
                }
            }

            if (config.compression != null) {
                log.err("Compression is disabled as part of the 0.15 upgrade. I do hope to re-enable it soon.", .{});
                return error.InvalidConfiguraion;
            }

            const signals = try allocator.alloc(posix.fd_t, config.workerCount());
            errdefer allocator.free(signals);

            var state = try WorkerState.init(allocator, config);
            errdefer state.deinit();

            return .{
                ._mut = .{},
                ._cond = .{},
                ._state = state,
                ._signals = signals,
                .config = config,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self._state.deinit();
            self.allocator.free(self._signals);
        }

        pub fn listenInNewThread(self: *Self, ctx: anytype) !Thread {
            self._mut.lock();
            defer self._mut.unlock();
            const thrd = try Thread.spawn(.{}, Self.listen, .{ self, ctx });

            // we don't return until listen() signals us that the server is up
            self._cond.wait(&self._mut);
            return thrd;
        }

        pub fn listen(self: *Self, ctx: anytype) !void {
            self._mut.lock();
            errdefer {
                self._cond.signal();
                self._mut.unlock();
            }

            const config = &self.config;

            var no_delay = true;
            const address = blk: {
                if (config.unix_path) |unix_path| {
                    if (comptime std.net.has_unix_sockets == false) {
                        return error.UnixPathNotSupported;
                    }
                    no_delay = false;
                    std.fs.deleteFileAbsolute(unix_path) catch {};
                    break :blk try net.Address.initUnix(unix_path);
                } else {
                    const listen_port = config.port;
                    const listen_address = config.address;
                    break :blk try net.Address.parseIp(listen_address, listen_port);
                }
            };

            const socket = blk: {
                var sock_flags: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
                if (blockingMode() == false) sock_flags |= posix.SOCK.NONBLOCK;

                const socket_proto = if (address.any.family == posix.AF.UNIX) @as(u32, 0) else posix.IPPROTO.TCP;
                break :blk try posix.socket(address.any.family, sock_flags, socket_proto);
            };

            if (no_delay) {
                // TODO: Broken on darwin:
                // https://github.com/ziglang/zig/issues/17260
                // if (@hasDecl(os.TCP, "NODELAY")) {
                //  try os.setsockopt(socket.sockfd.?, os.IPPROTO.TCP, os.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1)));
                // }
                try posix.setsockopt(socket, posix.IPPROTO.TCP, 1, &std.mem.toBytes(@as(c_int, 1)));
            }

            if (@hasDecl(posix.SO, "REUSEPORT_LB")) {
                try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEPORT_LB, &std.mem.toBytes(@as(c_int, 1)));
            } else if (@hasDecl(posix.SO, "REUSEPORT")) {
                try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEPORT, &std.mem.toBytes(@as(c_int, 1)));
            } else {
                try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
            }

            {
                const socklen = address.getOsSockLen();
                try posix.bind(socket, &address.any, socklen);
                try posix.listen(socket, 1024); // kernel backlog
            }

            const C = @TypeOf(ctx);

            if (comptime blockingMode()) {
                errdefer posix.close(socket);
                var w = try Blocking(H).init(self.allocator, &self._state);
                defer w.deinit();

                const thrd = try std.Thread.spawn(.{}, Blocking(H).run, .{ &w, socket, ctx });
                log.info("starting blocking worker to listen on {f}", .{address});

                // incase listenInNewThread was used and is waiting for us to start
                self._cond.signal();

                // this is what we'll shutdown when stop() is called
                self._signals[0] = socket;
                self._mut.unlock();
                thrd.join();
            } else {
                defer posix.close(socket);
                const W = NonBlocking(H, C);

                const allocator = self.allocator;

                var signals = self._signals;
                const worker_count = signals.len;
                const threads = try allocator.alloc(Thread, worker_count);
                const workers = try allocator.alloc(W, worker_count);

                var started: usize = 0;

                errdefer for (0..started) |i| {
                    // on success, these will be closed by a call to stop();
                    posix.close(signals[i]);
                };

                defer {
                    for (0..started) |i| {
                        workers[i].deinit();
                    }
                    allocator.free(threads);
                    allocator.free(workers);
                }

                for (0..worker_count) |i| {
                    const pipe = try posix.pipe2(.{ .NONBLOCK = true });
                    errdefer posix.close(pipe[1]);

                    workers[i] = try W.init(self.allocator, &self._state, ctx);
                    errdefer workers[i].deinit();

                    threads[i] = try Thread.spawn(.{}, W.run, .{ &workers[i], socket, pipe[0] });

                    signals[i] = pipe[1];
                    started += 1;
                }

                log.info("starting nonblocking worker to listen on {f}", .{address});

                // in case startInNewThread is waiting
                self._cond.signal();

                self._mut.unlock();

                for (threads) |thrd| {
                    thrd.join();
                }
            }
            self._cond.signal();
        }

        pub fn stop(self: *Self) void {
            self._mut.lock();
            defer self._mut.unlock();
            for (self._signals) |s| {
                if (blockingMode()) {
                    // necessary to unblock accept on linux
                    // (which might not be that necessary since, on Linux,
                    // NonBlocking should be used)
                    posix.shutdown(s, .recv) catch {};
                }
                posix.close(s);
            }
            self._cond.wait(&self._mut);
        }
    };
}

// This is our Blocking worker. It's very different than NonBlocking and much simpler.
pub fn Blocking(comptime H: type) type {
    return struct {
        allocator: Allocator,
        handshake_timeout: Timeout,
        connection_buffer_size: usize,
        conn_manager: ConnManager(H, false),
        handshake_pool: *Handshake.Pool,
        buffer_provider: *buffer.Provider,
        compression: ?Compression,

        const Timeout = struct {
            sec: u32,
            timeval: [@sizeOf(std.posix.timeval)]u8,

            // if sec is null, it means we want to cancel the timeout.
            fn init(sec: u32) Timeout {
                return .{
                    .sec = sec,
                    .timeval = std.mem.toBytes(posix.timeval{ .sec = @intCast(sec), .usec = 0 }),
                };
            }

            pub const none = std.mem.toBytes(posix.timeval{ .sec = 0, .usec = 0 });
        };

        const Self = @This();

        pub fn init(allocator: Allocator, state: *WorkerState) !Self {
            const config = &state.config;

            var conn_manager = try ConnManager(H, false).init(allocator, config.compression);
            errdefer conn_manager.deinit();

            return .{
                .conn_manager = conn_manager,
                .allocator = allocator,
                .compression = config.compression,
                .handshake_pool = state.handshake_pool,
                .buffer_provider = &state.buffer_provider,
                .handshake_timeout = Timeout.init(config.handshake.timeout),
                .connection_buffer_size = config.buffers.small_size orelse DEFAULT_BUFFER_SIZE,
            };
        }

        pub fn deinit(self: *Self) void {
            self.conn_manager.deinit();
        }

        pub fn run(self: *Self, listener: posix.socket_t, ctx: anytype) void {
            defer self.shutdown();
            while (true) {
                var address: net.Address = undefined;
                var address_len: posix.socklen_t = @sizeOf(net.Address);
                const socket = posix.accept(listener, &address.any, &address_len, posix.SOCK.CLOEXEC) catch |err| {
                    if (err == error.ConnectionAborted or err == error.SocketNotListening) {
                        log.info("received shutdown signal", .{});
                        return;
                    }
                    log.err("failed to accept socket: {}", .{err});
                    continue;
                };
                log.debug("({f}) connected", .{address});

                const thread = std.Thread.spawn(.{}, Self.handleConnection, .{ self, socket, address, ctx }) catch |err| {
                    posix.close(socket);
                    log.err("({f}) failed to spawn connection thread: {}", .{ address, err });
                    continue;
                };
                thread.detach();
            }
        }

        // Called in a thread started above in listen.
        // Wrapper around _handleConnection so that we can handle erros
        fn handleConnection(self: *Self, socket: posix.socket_t, address: net.Address, ctx: anytype) void {
            self._handleConnection(socket, address, ctx) catch |err| {
                log.err("({f}) uncaught error in connection handler: {}", .{ address, err });
            };
        }

        fn _handleConnection(self: *Self, socket: posix.socket_t, address: net.Address, ctx: anytype) !void {
            const conn_manager = &self.conn_manager;
            const hc = try conn_manager.create(socket, address, timestamp());

            {
                // Do our handshake
                errdefer self.cleanupConn(hc);
                const timeout = self.handshake_timeout;
                const deadline = timestamp() + timeout.sec;
                try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &timeout.timeval);

                while (true) {
                    const compression, const ok = handleHandshake(H, self, hc, ctx);
                    if (ok == false) {
                        self.cleanupConn(hc);
                        return;
                    }
                    if (hc.handler != null) {
                        // if we have a handler, the our handshake completed
                        if (compression) {
                            try conn_manager.setupCompression(hc);
                        }
                        break;
                    }
                    if (timestamp() > deadline) {
                        self.cleanupConn(hc);
                        return;
                    }
                }
            }

            return self.readLoop(hc);
        }

        // The readloop is extracted from _handleConnection so that it can be called
        // directly when integrating with an http server
        pub fn readLoop(self: *Self, hc: *HandlerConn(H)) !void {
            defer self.cleanupConn(hc);
            try posix.setsockopt(hc.socket, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &Timeout.none);

            // In BlockingMode, we always assign a reader for the duration of the connection
            // In scenarios where client rarely send data, this is going to use up an unecessary amount
            // of memory, but unlike nonblocking mode, we can't initialize the buffer just-in-time.
            const reader_buf = try self.allocator.alloc(u8, self.connection_buffer_size);
            defer self.allocator.free(reader_buf);

            hc.reader = Reader.init(reader_buf, self.buffer_provider, hc.compression);
            while (true) {
                if (handleClientData(H, hc, self.allocator, undefined) == false) {
                    break;
                }
            }
        }

        fn cleanupConn(self: *Self, hc: *HandlerConn(H)) void {
            hc.conn.closeSocket();
            self.conn_manager.cleanup(hc);
        }

        fn shutdown(self: *Self) void {
            var conn_manager = &self.conn_manager;
            conn_manager.shutdown(self);

            // wait up to 1 second for every connection to cleanly shutdown
            var i: usize = 0;
            while (i < 10) : (i += 1) {
                if (conn_manager.count() == 0) {
                    return;
                }
                std.Thread.sleep(std.time.ns_per_ms * 100);
            }
        }

        // called for each hc when shutting down
        fn shutdownCleanup(_: *Self, hc: *HandlerConn(H)) void {
            posix.shutdown(hc.socket, .recv) catch {};
        }
    };
}

fn NonBlocking(comptime H: type, comptime C: type) type {
    return struct {
        ctx: C,

        max_conn: usize,

        // KQueue or Epoll, depending on the platform
        loop: Loop,
        thread_pool: *ThreadPool,

        handshake_timeout: u32,
        handshake_pool: *Handshake.Pool,
        base: NonBlockingBase(H, true),
        compression: ?Compression,

        const Self = @This();
        const ThreadPool = @import("thread_pool.zig").ThreadPool(Self.dataAvailable);

        pub fn init(allocator: Allocator, state: *WorkerState, ctx: C) !Self {
            var base = try NonBlockingBase(H, true).init(allocator, state);
            errdefer base.deinit();

            const loop = try Loop.init();
            errdefer loop.deinit();

            const config = &state.config;
            var thread_pool = try ThreadPool.init(allocator, .{
                .count = config.thread_pool.count orelse 4,
                .backlog = config.thread_pool.backlog orelse 500,
                .buffer_size = config.thread_pool.buffer_size orelse if (needsAllocator(H)) 32_768 else 0,
            });
            errdefer thread_pool.deinit();

            return .{
                .ctx = ctx,
                .loop = loop,
                .base = base,
                .thread_pool = thread_pool,
                .compression = config.compression,
                .handshake_pool = state.handshake_pool,
                .handshake_timeout = state.config.handshake.timeout,
                .max_conn = config.max_conn orelse DEFAULT_MAX_CONN,
            };
        }

        pub fn deinit(self: *Self) void {
            self.loop.deinit();
            self.base.deinit();
            self.thread_pool.deinit();
        }

        fn run(self: *Self, listener: posix.socket_t, signal: posix.fd_t) void {
            self.loop.monitorAccept(listener) catch |err| {
                log.err("failed to add monitor to listening socket: {}", .{err});
                return;
            };

            self.loop.monitorSignal(signal) catch |err| {
                log.err("failed to add monitor to signal pipe: {}", .{err});
                return;
            };

            const thread_pool = self.thread_pool;
            const conn_manager = &self.base.conn_manager;
            const handshake_timeout = self.handshake_timeout;

            var now = timestamp();
            var oldest_pending_start_time: ?u32 = null;
            while (true) {
                const handshake_cutoff = now - handshake_timeout;
                const timeout = self.prepareToWait(handshake_cutoff) orelse blk: {
                    if (oldest_pending_start_time) |started| {
                        break :blk if (started < handshake_cutoff) 1 else @as(i32, @intCast(started - handshake_cutoff));
                    }
                    break :blk null;
                };

                var it = self.loop.wait(timeout) catch |err| {
                    log.err("failed to wait on events: {}", .{err});
                    std.Thread.sleep(std.time.ns_per_s);
                    continue;
                };

                now = timestamp();
                oldest_pending_start_time = null;
                while (it.next()) |data| {
                    if (data == 0) {
                        self.accept(listener, now) catch |err| {
                            log.err("accept error: {}", .{err});
                            std.Thread.sleep(std.time.ns_per_ms);
                        };
                        continue;
                    }

                    if (data == 1) {
                        self.base.shutdown();
                        return;
                    }

                    const hc: *HandlerConn(H) = @ptrFromInt(data);
                    if (hc.state == .handshake) {
                        // we need to get this out of the pending list, so that it doesn't
                        // cause a timeout while we're processing it.
                        // But we stll need to care about its timeout.
                        if (oldest_pending_start_time) |s| {
                            oldest_pending_start_time = @min(hc.conn.started, s);
                        } else {
                            oldest_pending_start_time = hc.conn.started;
                        }
                        conn_manager.activate(hc);
                    }
                    thread_pool.spawn(.{ self, hc });
                }
            }
        }

        // Enforces timeouts, and returns when the next timeout should be checked.
        fn prepareToWait(self: *Self, cutoff: u32) ?i32 {
            const cm = &self.base.conn_manager;

            // always ordered from oldest to newest, so once we find a conneciton
            // that isn't timed out, we can stop
            cm.lock.lock();
            defer cm.lock.unlock();

            var next_conn = cm.pending.head;
            while (next_conn) |hc| {
                const conn = &hc.conn;
                const started = conn.started;
                if (started > cutoff) {
                    // This is the first connection which hasn't timed out
                    // return the time until it times out.
                    return @intCast(started - cutoff);
                }

                next_conn = hc.next;

                // this connection has timed out. Don't use self.cleanup since there's
                // a bunch of stuff we can assume here..like there's no handler or reader
                conn.closeSocket();
                log.debug("({f}) handshake timeout", .{conn.address});
                if (hc.handshake) |h| {
                    h.release();
                }
                cm.pending.remove(hc);
                cm.pool.destroy(hc);
            }
            return null;
        }

        fn accept(self: *Self, listener: posix.fd_t, now: u32) !void {
            const max_conn = self.max_conn;
            const conn_manager = &self.base.conn_manager;

            while (conn_manager.count() < max_conn) {
                var address: net.Address = undefined;
                var address_len: posix.socklen_t = @sizeOf(net.Address);

                const socket = posix.accept(listener, &address.any, &address_len, posix.SOCK.CLOEXEC) catch |err| {
                    // When available, we use SO_REUSEPORT_LB or SO_REUSEPORT, so WouldBlock
                    // should not be possible in those cases, but if it isn't available
                    // this error should be ignored as it means another thread picked it up.
                    return if (err == error.WouldBlock) {} else err;
                };

                log.debug("({f}) connected", .{address});

                {
                    errdefer posix.close(socket);
                    // socket is _probably_ in NONBLOCKING mode (it inherits
                    // the flag from the listening socket).
                    const flags = try posix.fcntl(socket, posix.F.GETFL, 0);
                    const nonblocking = @as(u32, @bitCast(posix.O{ .NONBLOCK = true }));
                    if (flags & nonblocking == nonblocking) {
                        // Yup, it's in nonblocking mode. Disable that flag to
                        // put it in blocking mode.
                        _ = try posix.fcntl(socket, posix.F.SETFL, flags & ~nonblocking);
                    }
                }
                const hc = try self.base.newConn(socket, address, now);
                self.loop.monitorRead(hc, false) catch |err| {
                    self.base.cleanupConn(hc);
                    return err;
                };
            }
        }

        // Called in a thread-pool thread/
        // !! Access to self has to be synchronized !!
        // There can only be 1 dataAvailable executing per HC at any given time.
        // Access to HC *should not* need to be synchronized. Access to hc.conn
        // needs to be synchronized once &hc.conn is passed to the handler during
        // handshake (Conn is self-synchronized).
        // Shutdown throws a wrench in our synchronization model, since we could
        // be shutting down while we're processing data...but hopefully the way we
        // shutdown (by waiting for all the thread pools threads to end) solves this.
        // Else, we'll need to throw a bunch of locking around HC just to handle shutdown.
        fn dataAvailable(self: *Self, hc: *HandlerConn(H), thread_buf: []u8) void {
            var success = false;
            {
                hc.cleanup.lock();
                defer hc.cleanup.unlock();
                if (hc.handler == null) {
                    success = self.dataForHandshake(hc) catch |err| blk: {
                        log.err("({f}) error processing handshake: {}", .{ hc.conn.address, err });
                        break :blk false;
                    };
                } else {
                    success = self.base.dataAvailable(hc, thread_buf);
                }
            }

            var conn = &hc.conn;
            var closed: bool = undefined;
            if (success == false) {
                conn.closeSocket();
                closed = true;
            } else {
                closed = conn.isClosed();
            }

            if (closed) {
                self.base.cleanupConn(hc);
            } else {
                self.loop.monitorRead(hc, true) catch |err| {
                    log.debug("({f}) failed to add read event monitor: {}", .{ conn.address, err });
                    conn.closeSocket();
                    self.base.cleanupConn(hc);
                };
            }
        }

        fn dataForHandshake(self: *Self, hc: *HandlerConn(H)) !bool {
            var conn_manager = &self.base.conn_manager;
            const compression, const ok = handleHandshake(H, self, hc, self.ctx);
            if (ok == false) {
                return false;
            }

            if (hc.handler == null) {
                // still don't have a handshake
                conn_manager.inactive(hc);
            }

            if (compression) {
                try conn_manager.setupCompression(hc);
            }
            return true;
        }
    };
}

fn NonBlockingBase(comptime H: type, comptime MANAGE_HS: bool) type {
    return struct {
        allocator: Allocator,

        buffer_provider: *buffer.Provider,

        // App can configure the use of a "small" buffer pool. This is the difference
        // between assigning a buffer to the connection just-in-time per message, or always
        small_buffer_pool: ?buffer.Pool,
        connection_buffer_size: usize,

        conn_manager: ConnManager(H, MANAGE_HS),

        const Self = @This();

        fn init(allocator: Allocator, state: *WorkerState) !Self {
            const config = &state.config;

            var conn_manager = try ConnManager(H, MANAGE_HS).init(allocator, config.compression);
            errdefer conn_manager.deinit();

            const connection_buffer_size = config.buffers.small_size orelse DEFAULT_BUFFER_SIZE;
            var small_buffer_pool: ?buffer.Pool = null;
            if (config.buffers.small_pool) |pool_count| {
                small_buffer_pool = try buffer.Pool.init(allocator, pool_count, connection_buffer_size);
            }

            errdefer if (small_buffer_pool) |sbp| {
                sbp.deinit();
            };

            return .{
                .allocator = allocator,
                .conn_manager = conn_manager,
                .small_buffer_pool = small_buffer_pool,
                .buffer_provider = &state.buffer_provider,
                .connection_buffer_size = connection_buffer_size,
            };
        }

        fn deinit(self: *Self) void {
            self.conn_manager.deinit();
            if (self.small_buffer_pool) |*sbp| {
                sbp.deinit();
            }
        }

        fn newConn(self: *Self, socket: posix.socket_t, address: net.Address, time: u32) !*HandlerConn(H) {
            return self.conn_manager.create(socket, address, time);
        }

        pub fn dataAvailable(self: *Self, hc: *HandlerConn(H), thread_buf: []u8) bool {
            return self._dataAvailable(hc, thread_buf) catch |err| {
                log.err("({f}) error processing client message: {}", .{ hc.conn.address, err });
                return false;
            };
        }

        fn _dataAvailable(self: *Self, hc: *HandlerConn(H), thread_buf: []u8) !bool {
            if (hc.reader == null) {
                const reader_buf = if (self.small_buffer_pool) |*sbp| try sbp.acquireOrCreate() else try self.allocator.alloc(u8, self.connection_buffer_size);
                hc.reader = Reader.init(reader_buf, self.buffer_provider, hc.compression);
            }
            const reader = &hc.reader.?;

            var fba = FixedBufferAllocator.init(thread_buf);
            const ok = handleClientData(H, hc, self.allocator, &fba);

            if (self.small_buffer_pool) |*sbp| {
                if (reader.isEmpty()) {
                    sbp.release(reader.static);
                    hc.reader = null;
                }
            }

            return ok;
        }

        fn cleanupConn(self: *Self, hc: *HandlerConn(H)) void {
            {
                hc.cleanup.lock();
                defer hc.cleanup.unlock();
                if (hc.reader) |*reader| {
                    if (self.small_buffer_pool) |*sbp| {
                        sbp.release(reader.static);
                    } else {
                        self.allocator.free(reader.static);
                    }
                    hc.reader = null;
                }
            }
            self.conn_manager.cleanup(hc);
        }

        fn shutdown(self: *Self) void {
            log.info("received shutdown signal", .{});
            self.conn_manager.shutdown(self);
        }

        // called for each hc when shutting down
        fn shutdownCleanup(self: *Self, hc: *HandlerConn(H)) void {
            hc.cleanup.lock();
            defer hc.cleanup.unlock();
            if (hc.reader) |*reader| {
                if (self.small_buffer_pool == null) {
                    self.allocator.free(reader.static);
                }
                hc.reader = null;
            }
        }
    };
}

const Loop = switch (@import("builtin").os.tag) {
    .macos, .ios, .tvos, .watchos, .freebsd, .netbsd, .dragonfly, .openbsd => KQueue,
    .linux => EPoll,
    else => unreachable,
};

const KQueue = struct {
    q: i32,
    change_count: usize,
    change_buffer: [16]Kevent,
    event_list: [64]Kevent,

    const Kevent = posix.Kevent;

    fn init() !KQueue {
        return .{
            .q = try posix.kqueue(),
            .change_count = 0,
            .change_buffer = undefined,
            .event_list = undefined,
        };
    }

    fn deinit(self: KQueue) void {
        posix.close(self.q);
    }

    fn monitorAccept(self: *KQueue, fd: c_int) !void {
        try self.change(fd, 0, posix.system.EVFILT.READ, posix.system.EV.ADD);
    }

    fn monitorSignal(self: *KQueue, fd: c_int) !void {
        try self.change(fd, 1, posix.system.EVFILT.READ, posix.system.EV.ADD);
    }

    // Normally, we add the socket in the worker thread with rearm == false.
    // Because this is a DISPATCH, it'll only fire once until we rearm it which
    // we do by re-enabling it with rearm == true.
    // However, notice that the rearm path also has the EV.ADD flag. From the above
    // description, this should not be necessary.
    // But monitorRead where rearm == true is also used by our generic ServerLoop when
    // taking over a connection (say from httpz). Hence, we need the EV.ADD flag too.
    fn monitorRead(self: *KQueue, hc: anytype, comptime rearm: bool) !void {
        if (rearm == false) {
            return self.change(hc.socket, @intFromPtr(hc), posix.system.EVFILT.READ, posix.system.EV.ADD | posix.system.EV.ENABLE | posix.system.EV.DISPATCH);
        }
        const event = Kevent{
            .ident = @intCast(hc.socket),
            .filter = posix.system.EVFILT.READ,
            .flags = posix.system.EV.ADD | posix.system.EV.ENABLE | posix.system.EV.DISPATCH,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(hc),
        };
        _ = try posix.kevent(self.q, &.{event}, &[_]Kevent{}, null);
    }

    fn change(self: *KQueue, fd: posix.fd_t, data: usize, filter: i16, flags: u16) !void {
        var change_count = self.change_count;
        var change_buffer = &self.change_buffer;

        if (change_count == change_buffer.len) {
            // calling this with an empty event_list will return immediate
            _ = try posix.kevent(self.q, change_buffer, &[_]Kevent{}, null);
            change_count = 0;
        }
        change_buffer[change_count] = .{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = flags,
            .fflags = 0,
            .data = 0,
            .udata = data,
        };
        self.change_count = change_count + 1;
    }

    fn wait(self: *KQueue, timeout_sec: ?i32) !Iterator {
        const event_list = &self.event_list;
        const timeout: ?posix.timespec = if (timeout_sec) |ts| posix.timespec{ .sec = ts, .nsec = 0 } else null;
        const event_count = try posix.kevent(self.q, self.change_buffer[0..self.change_count], event_list, if (timeout) |ts| &ts else null);
        self.change_count = 0;

        return .{
            .index = 0,
            .events = event_list[0..event_count],
        };
    }

    const Iterator = struct {
        index: usize,
        events: []Kevent,

        fn next(self: *Iterator) ?usize {
            const index = self.index;
            const events = self.events;
            if (index == events.len) {
                return null;
            }
            self.index = index + 1;
            return self.events[index].udata;
        }
    };
};

const EPoll = struct {
    q: i32,
    event_list: [64]EpollEvent,

    const linux = std.os.linux;
    const EpollEvent = linux.epoll_event;

    fn init() !EPoll {
        return .{
            .event_list = undefined,
            .q = try posix.epoll_create1(0),
        };
    }

    fn deinit(self: EPoll) void {
        posix.close(self.q);
    }

    fn monitorAccept(self: *EPoll, fd: c_int) !void {
        var event = linux.epoll_event{ .events = linux.EPOLL.IN, .data = .{ .ptr = 0 } };
        return std.posix.epoll_ctl(self.q, linux.EPOLL.CTL_ADD, fd, &event);
    }

    fn monitorSignal(self: *EPoll, fd: c_int) !void {
        var event = linux.epoll_event{ .events = linux.EPOLL.IN, .data = .{ .ptr = 1 } };
        return std.posix.epoll_ctl(self.q, linux.EPOLL.CTL_ADD, fd, &event);
    }

    fn monitorRead(self: *EPoll, hc: anytype, comptime rearm: bool) !void {
        const op = if (rearm) linux.EPOLL.CTL_MOD else linux.EPOLL.CTL_ADD;
        var event = linux.epoll_event{ .events = linux.EPOLL.IN | linux.EPOLL.ONESHOT, .data = .{ .ptr = @intFromPtr(hc) } };
        return posix.epoll_ctl(self.q, op, hc.socket, &event);
    }

    fn wait(self: *EPoll, timeout_sec: ?i32) !Iterator {
        const event_list = &self.event_list;
        var timeout: i32 = -1;
        if (timeout_sec) |sec| {
            if (sec > 2147483) {
                // max supported timeout by epoll_wait.
                timeout = 2147483647;
            } else {
                timeout = sec * 1000;
            }
        }

        const event_count = posix.epoll_wait(self.q, event_list, timeout);
        return .{
            .index = 0,
            .events = event_list[0..event_count],
        };
    }

    const Iterator = struct {
        index: usize,
        events: []EpollEvent,

        fn next(self: *Iterator) ?usize {
            const index = self.index;
            const events = self.events;
            if (index == events.len) {
                return null;
            }
            self.index = index + 1;
            return self.events[index].data.ptr;
        }
    };
};

// We want to extract as much common logic as possible from the Blocking and
// NonBlockign workers. The code from this point on is meant to be used with
// both workers, independently from the blocking/nonblocking nonsense.

// Abstraction ontop of NonBlocking and Blocking. Exists solely for integration
// with httpz (or any other http library I guess.). Serves a similar purpose
// as Server, but doesn't accept/listen.
pub fn Worker(comptime H: type) type {
    return struct {
        worker: W,

        const Self = @This();
        const W = if (blockingMode()) Blocking(H) else NonBlockingBase(H, false);

        pub fn init(allocator: Allocator, state: *WorkerState) !Self {
            return .{
                .worker = try W.init(allocator, state),
            };
        }

        pub fn deinit(self: *Self) void {
            self.worker.deinit();
        }

        pub fn createConn(self: *Self, socket: posix.socket_t, address: net.Address, now: u32) !*HandlerConn(H) {
            return self.worker.conn_manager.create(socket, address, now);
        }

        pub fn cleanupConn(self: *Self, hc: *HandlerConn(H)) void {
            self.worker.cleanupConn(hc);
        }

        pub fn canCompress(self: *const Self) bool {
            return self.worker.conn_manager.compression != null;
        }

        pub fn setupConnection(
            self: *Self,
            hc: *HandlerConn(H),
        ) !void {
            return self.worker.conn_manager.setupCompression(hc);
        }

        pub fn shutdown(self: *Self) void {
            self.worker.shutdown();
        }
    };
}

// These are things that both the Blocking and NonBlocking workers need. Just cleaner
// to have a single place for it. This could used to be directly in Server(H), with
// Server(H) having handshake_pool and buffer_provider fields, but it was extracted
// into its own struct for integration with webservers (i.e. httpz). The goal is
// that a webserver can have websocket support without starting a full Server.
pub const WorkerState = struct {
    config: Config,
    handshake_pool: *Handshake.Pool,
    buffer_provider: buffer.Provider,

    pub fn init(allocator: Allocator, config: Config) !WorkerState {
        const handshake_pool_count = config.handshake.count orelse 32;
        const handshake_max_size = config.handshake.max_size orelse 1024;
        const handshake_max_headers = config.handshake.max_headers orelse 10;
        const handshake_max_res_headers = config.handshake.max_res_headers orelse 2;

        var handshake_pool = try Handshake.Pool.init(allocator, handshake_pool_count, handshake_max_size, handshake_max_headers, handshake_max_res_headers);
        errdefer handshake_pool.deinit();

        const max_message_size = config.max_message_size orelse DEFAULT_MAX_MESSAGE_SIZE;
        const large_buffer_pool = config.buffers.large_pool orelse 8;
        const large_buffer_size = config.buffers.large_size orelse @min((config.buffers.small_size orelse DEFAULT_BUFFER_SIZE) * 2, max_message_size);

        var buffer_provider = try buffer.Provider.init(allocator, .{
            .max = max_message_size,
            .size = large_buffer_size,
            .count = large_buffer_pool,
        });
        errdefer buffer_provider.deinit();

        return .{
            .config = config,
            .handshake_pool = handshake_pool,
            .buffer_provider = buffer_provider,
        };
    }

    pub fn deinit(self: *WorkerState) void {
        self.handshake_pool.deinit();
        self.buffer_provider.deinit();
    }
};

// In the Blocking worker, all the state could be stored on the spawn'd threads
// stack. The only reason we use a HandlerConn(H) in there is to be able to re-use
// code with the NonBlocking worker.
//
// For the NonBlocking worker, HandlerConn(H) is critical as it contains all the
// state for a connection. It lives on the heap, a pointer is registered into
// the event loop, and passed back when data is ready to read.
// * If handler is null, it means we haven't done our handshake yet.
// * If handler is null AND handshake is null, it means we havent' received
//   any data yet (we delay creating the handshake state until we at least have
//   some data ready).
pub fn HandlerConn(comptime H: type) type {
    return struct {
        state: State,
        conn: Conn,
        handler: ?H,
        reader: ?Reader,
        socket: posix.socket_t, // denormalization from conn.stream.handle
        handshake: ?*Handshake.State,
        cleanup: Thread.Mutex = .{},
        compression: ?Compression = null,
        next: ?*HandlerConn(H) = null,
        prev: ?*HandlerConn(H) = null,

        const State = enum {
            handshake,
            active,
        };
    };
}

pub fn ConnManager(comptime H: type, comptime MANAGE_HS: bool) type {
    return struct {
        lock: Thread.Mutex,
        allocator: Allocator,
        active: List(HandlerConn(H)),
        pending: List(HandlerConn(H)),
        pool: std.heap.MemoryPool(HandlerConn(H)),
        compression: ?Compression,
        compression_pool: std.heap.MemoryPool(Conn.Compression),

        const Self = @This();

        pub fn init(allocator: Allocator, compression: ?Compression) !Self {
            var pool = std.heap.MemoryPool(HandlerConn(H)).init(allocator);
            errdefer pool.deinit();

            var compression_pool = std.heap.MemoryPool(Conn.Compression).init(allocator);
            errdefer compression_pool.deinit();

            return .{
                .lock = .{},
                .pool = pool,
                .active = .{},
                .pending = .{},
                .allocator = allocator,
                .compression = compression,
                .compression_pool = compression_pool,
            };
        }

        pub fn deinit(self: *Self) void {
            self.pool.deinit();
            self.compression_pool.deinit();
        }

        pub fn count(self: *Self) usize {
            self.lock.lock();
            defer self.lock.unlock();
            if (MANAGE_HS == false) {
                return self.active.len;
            }
            return self.active.len + self.pending.len;
        }

        pub fn create(self: *Self, socket: posix.socket_t, address: net.Address, now: u32) !*HandlerConn(H) {
            errdefer posix.close(socket);

            self.lock.lock();
            defer self.lock.unlock();

            const hc = try self.pool.create();
            hc.* = .{
                .state = if (MANAGE_HS) .handshake else .active,
                .socket = socket,
                .handler = null,
                .handshake = null,
                .reader = null,
                .compression = null,
                .conn = .{
                    ._closed = false,
                    .started = now,
                    .address = address,
                    .stream = .{ .handle = socket },
                    .compression = null,
                },
            };

            if (comptime MANAGE_HS) {
                // Still waiting for a handshake. Only care about this with the full
                // NonBlocking worker
                self.pending.insert(hc);
            } else {
                self.active.insert(hc);
            }
            return hc;
        }

        pub fn activate(self: *Self, hc: *HandlerConn(H)) void {
            std.debug.assert(MANAGE_HS == true);

            // our caller made sute this was the case
            std.debug.assert(hc.state == .handshake);
            self.lock.lock();
            defer self.lock.unlock();
            self.pending.remove(hc);
            self.active.insert(hc);
            hc.state = .active;
        }

        pub fn inactive(self: *Self, hc: *HandlerConn(H)) void {
            std.debug.assert(MANAGE_HS == true);

            // this should only be called when we need more data to complete the handshake
            // which should only happen on an active connection
            std.debug.assert(hc.state == .active);
            hc.state = .handshake;

            self.lock.lock();
            defer self.lock.unlock();
            self.active.remove(hc);
            self.pending.insert(hc);
        }

        pub fn cleanup(self: *Self, hc: *HandlerConn(H)) void {
            if (hc.handshake) |h| {
                h.release();
            }

            if (hc.reader) |*r| {
                r.deinit();
            }

            if (hc.handler) |*h| {
                if (comptime std.meta.hasFn(H, "close")) {
                    h.close();
                }
                hc.handler = null;
            }

            if (hc.conn.compression) |c| {
                c.writer.deinit();
            }

            self.lock.lock();
            if (hc.state == .active) {
                self.active.remove(hc);
            } else {
                self.pending.remove(hc);
            }

            if (hc.conn.compression) |c| {
                self.compression_pool.destroy(c);
            }

            self.pool.destroy(hc);
            self.lock.unlock();
        }

        fn setupCompression(self: *Self, hc: *HandlerConn(H)) !void {
            const config = self.compression orelse return;

            hc.compression = config;

            if (config.write_threshold == null) {
                // if write_treshold is null, then we never want to compress
                // outgoing messages. We don't need to set the conn.compression
                // field.
                // We'll still [potentially] decompress incoming messages, but
                // that's set on the proto.
                return;
            }

            const compression = try self.compression_pool.create();
            errdefer self.compression_pool.destroy(compression);

            compression.* = .{
                .allocator = self.allocator,
                .write_treshold = config.write_threshold.?,
                .retain_writer = config.retain_write_buffer,
                .writer = std.Io.Writer.Allocating.init(self.allocator),
            };
            hc.conn.compression = compression;
        }

        pub fn shutdown(self: *Self, worker: anytype) void {
            self.lock.lock();
            defer self.lock.unlock();

            shutdownList(self.active.head, worker);
            shutdownList(self.pending.head, worker);
        }

        // This is sloppy and leaves things in an unrecoverable state. To keep
        // things clean, we should call self.cleanup(hc) on each entry in the list
        // but that does a bunch of things we don't need if we know that we're
        // shutting down - like returning data to the pools, and popping items
        // out of the list.
        fn shutdownList(head: ?*HandlerConn(H), worker: anytype) void {
            var next_node = head;
            while (next_node) |hc| {
                if (comptime std.meta.hasFn(H, "close")) {
                    hc.cleanup.lock();
                    defer hc.cleanup.unlock();
                    if (hc.handler) |*h| {
                        h.close();
                        hc.handler = null;
                    }
                }

                worker.shutdownCleanup(hc);
                const conn = &hc.conn;
                conn.closeSocket();
                next_node = hc.next;
            }
        }
    };
}

// This is what actually gets exposed to the app
pub const Conn = struct {
    _closed: bool,
    started: u32,
    stream: net.Stream,
    address: net.Address,
    lock: Thread.Mutex = .{},
    compression: ?*Conn.Compression = null,

    const Compression = struct {
        allocator: Allocator,
        retain_writer: bool,
        write_treshold: usize,
        writer: std.Io.Writer.Allocating,
    };

    pub fn isClosed(self: *Conn) bool {
        // don't use lock to protect _closed. `isClosed` is called from
        // the worker thread and we don't want that potentially blocked while
        // a write is going on.
        return @atomicLoad(bool, &self._closed, .monotonic);
    }

    pub fn writeBin(self: *Conn, data: []const u8) !void {
        return self.writeFrame(.binary, data);
    }

    pub fn writeText(self: *Conn, data: []const u8) !void {
        return self.writeFrame(.text, data);
    }

    pub fn write(self: *Conn, data: []const u8) !void {
        return self.writeFrame(.text, data);
    }

    pub fn writePing(self: *Conn, data: []u8) !void {
        return self.writeFrame(.ping, data);
    }

    pub fn writePong(self: *Conn, data: []u8) !void {
        return self.writeFrame(.pong, data);
    }

    const CloseOpts = struct {
        code: u16 = 1000,
        reason: []const u8 = "",
    };

    pub fn close(self: *Conn, opts: CloseOpts) !void {
        if (self.isClosed()) {
            return;
        }
        defer self.closeSocket();

        const reason = opts.reason;
        if (reason.len == 0) {
            var buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &buf, opts.code, .big);
            return self.writeFrame(.close, &buf);
        }

        if (reason.len > 123) {
            return error.ReasonTooLong;
        }

        var buf: [4]u8 = undefined;
        buf[0] = @intFromEnum(OpCode.close);
        buf[1] = @intCast(reason.len + 2);
        std.mem.writeInt(u16, buf[2..], opts.code, .big);

        var vec = [2]std.posix.iovec_const{
            .{ .len = buf.len, .base = &buf },
            .{ .len = reason.len, .base = reason.ptr },
        };

        try writeAllIOVec(self, &vec);
    }

    pub fn writeFrame(self: *Conn, op_code: OpCode, data: []const u8) !void {
        const payload = data;

        // Zig 0.15 compression disabled
        const compressed = false;
        // if (self.compression) |c| {
        //     if (data.len >= c.write_treshold) {
        //         compressed = true;
        //         var compressor = std.compress.flate.Compress.init(&c.writer.writer, &.{}, .{});
        //         try compressor.writer.writeAll(data);
        //         try compressor.writer.flush();
        //         const all = c.writer.written();
        //         payload = all[0 .. all.len - 4];
        //     }
        // }

        // defer if (compressed) {
        //     const c = self.compression.?;
        //     if (c.retain_writer) {
        //         c.writer.clearRetainingCapacity();
        //     } else {
        //         c.writer.deinit();
        //         c.writer = std.Io.Writer.Allocating.init(c.allocator);
        //     }
        // };

        // maximum possible prefix length. op_code + length_type + 8byte length
        var buf: [10]u8 = undefined;
        const header = proto.writeFrameHeader(&buf, op_code, payload.len, compressed);

        const stream = self.stream;

        if (payload.len == 0) {
            // no body, just write the header
            self.lock.lock();
            defer self.lock.unlock();
            return stream.writeAll(header);
        }

        var vec = [2]std.posix.iovec_const{
            .{ .len = header.len, .base = header.ptr },
            .{ .len = payload.len, .base = payload.ptr },
        };

        return self.writeAllIOVec(&vec);
    }

    pub fn writeFramed(self: *Conn, data: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();
        try self.stream.writeAll(data);
    }

    fn writeAllIOVec(self: *Conn, vec: []std.posix.iovec_const) !void {
        const socket = self.stream.handle;

        self.lock.lock();
        defer self.lock.unlock();

        var i: usize = 0;
        while (true) {
            var n = try std.posix.writev(socket, vec[i..]);
            while (n >= vec[i].len) {
                n -= vec[i].len;
                i += 1;
                if (i >= vec.len) return;
            }
            vec[i].base += n;
            vec[i].len -= n;
        }
    }

    pub fn writeBuffer(self: *Conn, allocator: Allocator, op_code: OpCode) Writer {
        return .{
            .conn = self,
            .buf = .empty,
            .op_code = op_code,
            .allocator = allocator,
            .interface = .{
                .vtable = &.{ .drain = Writer.drain },
                .buffer = &.{},
            },
        };
    }

    fn closeSocket(self: *Conn) void {
        if (@atomicRmw(bool, &self._closed, .Xchg, true, .monotonic) == false) {
            posix.close(self.stream.handle);
        }
    }

    pub const Writer = struct {
        conn: *Conn,
        op_code: OpCode,
        allocator: Allocator,
        buf: std.ArrayList(u8),
        interface: std.Io.Writer,

        pub const Error = Allocator.Error;

        pub fn deinit(self: *Writer) void {
            self.buf.deinit(self.allocator);
        }

        pub fn drain(io_w: *std.Io.Writer, data: []const []const u8, splat: usize) error{WriteFailed}!usize {
            _ = splat;
            const self: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
            self.buf.appendSlice(self.allocator, data[0]) catch return error.WriteFailed;
            return data[0].len;
        }

        pub fn send(self: *Writer) !void {
            return self.conn.writeFrame(self.op_code, self.buf.items) catch error.WriteFailed;
        }
    };
};

fn handleHandshake(comptime H: type, worker: anytype, hc: *HandlerConn(H), ctx: anytype) struct { bool, bool } {
    return _handleHandshake(H, worker, hc, ctx) catch |err| {
        log.warn("({f}) uncaugh error processing handshake: {}", .{ hc.conn.address, err });
        return .{ false, false };
    };
}

fn _handleHandshake(comptime H: type, worker: anytype, hc: *HandlerConn(H), ctx: anytype) !struct { bool, bool } {
    std.debug.assert(hc.handler == null);

    var state = hc.handshake orelse blk: {
        const s = try worker.handshake_pool.acquire();
        hc.handshake = s;
        break :blk s;
    };

    var buf = state.buf;
    var conn = &hc.conn;
    const len = state.len;

    if (len == buf.len) {
        log.warn("({f}) handshake request exceeded maximum configured size ({d})", .{ conn.address, buf.len });
        return .{ false, false };
    }

    const n = posix.recv(hc.socket, buf[len..], 0) catch |err| {
        if (err == error.ConnectionResetByPeer or
            (builtin.os.tag != .windows and err == error.BrokenPipe))
        {
            log.debug("({f}) handshake connection closed: {}", .{ conn.address, err });
        } else switch (err) {
            error.WouldBlock => {
                std.debug.assert(blockingMode());
                log.debug("({f}) handshake timeout", .{conn.address});
            },
            else => log.warn("({f}) handshake error reading from socket: {}", .{ conn.address, err }),
        }
        return .{ false, false };
    };

    if (n == 0) {
        log.debug("({f}) handshake connection closed", .{conn.address});
        return .{ false, false };
    }

    state.len = len + n;
    var handshake = Handshake.parse(state) catch |err| {
        log.debug("({f}) error parsing handshake: {}", .{ conn.address, err });
        respondToHandshakeError(conn, err);
        return .{ false, false };
    } orelse {
        // we need more data
        return .{ false, true };
    };

    const compression = handshake.compression != null and worker.compression != null;
    defer state.release();
    hc.handshake = null;

    // After this, the app has access to &hc.conn, so any access to the
    // conn has to be synchronized (which the conn does internally).

    const handler = H.init(&handshake, conn, ctx) catch |err| {
        if (comptime std.meta.hasFn(H, "handshakeErrorResponse")) {
            preHandOffWrite(H.handshakeErrorResponse(err));
        } else {
            respondToHandshakeError(conn, err);
        }
        log.debug("({f}) " ++ @typeName(H) ++ ".init rejected request {}", .{ conn.address, err });
        return .{ false, false };
    };

    hc.handler = handler;

    var reply_buf: [2048]u8 = undefined;
    const handshake_reply = try Handshake.createReply(handshake.key, handshake.res_headers, compression, &reply_buf);
    try conn.writeFramed(handshake_reply);

    if (comptime std.meta.hasFn(H, "afterInit")) {
        const params = @typeInfo(@TypeOf(H.afterInit)).@"fn".params;
        const res = if (params.len == 1) hc.handler.?.afterInit() else hc.handler.?.afterInit(ctx);
        res catch |err| {
            log.debug("({f}) " ++ @typeName(H) ++ ".afterInit error: {}", .{ conn.address, err });
            return .{ false, false };
        };
    }

    log.debug("({f}) connection successfully upgraded", .{conn.address});
    return .{ compression, true };
}

fn handleClientData(comptime H: type, hc: *HandlerConn(H), allocator: Allocator, fba: *FixedBufferAllocator) bool {
    std.debug.assert(hc.handshake == null);
    return _handleClientData(H, hc, allocator, fba) catch |err| {
        log.warn("({f}) uncaugh error handling incoming data: {}", .{ hc.conn.address, err });
        return false;
    };
}

fn _handleClientData(comptime H: type, hc: *HandlerConn(H), allocator: Allocator, fba: *FixedBufferAllocator) !bool {
    var conn = &hc.conn;
    var reader = &hc.reader.?;
    reader.fill(conn.stream) catch |err| {
        switch (err) {
            error.BrokenPipe, error.Closed, error.ConnectionResetByPeer => log.debug("({f}) connection closed: {}", .{ conn.address, err }),
            else => log.warn("({f}) error reading from connection: {}", .{ conn.address, err }),
        }
        return false;
    };

    const handler = &hc.handler.?;
    while (true) {
        const has_more, const message = reader.read() catch |err| {
            switch (err) {
                error.LargeControl => conn.writeFramed(CLOSE_PROTOCOL_ERROR) catch {},
                error.ReservedFlags => conn.writeFramed(CLOSE_PROTOCOL_ERROR) catch {},
                error.CompressionDisabled => conn.writeFramed(CLOSE_PROTOCOL_ERROR) catch {},
                error.CompressionError => conn.writeFramed(CLOSE_PROTOCOL_ERROR) catch {},
                else => {},
            }
            log.debug("({f}) invalid websocket packet: {}", .{ conn.address, err });
            return false;
        } orelse {
            // everything is fine, we just need more data
            return true;
        };

        const message_type = message.type;
        defer reader.done(message_type);

        log.debug("({f}) received {s} message", .{ hc.conn.address, @tagName(message_type) });
        switch (message_type) {
            .text, .binary => {
                const params = @typeInfo(@TypeOf(H.clientMessage)).@"fn".params;
                const needs_allocator = comptime needsAllocator(H);

                var arena: std.heap.ArenaAllocator = undefined;
                var fallback_allocator: FallbackAllocator = undefined;
                var aa: Allocator = undefined;

                if (comptime needs_allocator) {
                    arena = std.heap.ArenaAllocator.init(allocator);
                    if (comptime blockingMode()) {
                        aa = arena.allocator();
                    } else {
                        fallback_allocator = FallbackAllocator{
                            .fba = fba,
                            .fallback = arena.allocator(),
                            .fixed = fba.allocator(),
                        };
                        aa = fallback_allocator.allocator();
                    }
                }

                defer if (comptime needs_allocator) {
                    arena.deinit();
                };

                switch (comptime params.len) {
                    2 => handler.clientMessage(message.data) catch return false,
                    3 => if (needs_allocator) {
                        handler.clientMessage(aa, message.data) catch return false;
                    } else {
                        handler.clientMessage(message.data, if (message_type == .text) .text else .binary) catch return false;
                    },
                    4 => handler.clientMessage(aa, message.data, if (message_type == .text) .text else .binary) catch return false,
                    else => @compileError(@typeName(H) ++ ".clientMessage has invalid parameter count"),
                }
            },
            .pong => if (comptime std.meta.hasFn(H, "clientPong")) {
                try handler.clientPong(message.data);
            },
            .ping => {
                const data = message.data;
                if (comptime std.meta.hasFn(H, "clientPing")) {
                    try handler.clientPing(data);
                } else if (data.len == 0) {
                    try hc.conn.writeFramed(EMPTY_PONG);
                } else {
                    try hc.conn.writeFrame(.pong, data);
                }
            },
            .close => {
                const data = message.data;
                if (comptime std.meta.hasFn(H, "clientClose")) {
                    try handler.clientClose(data);
                    return false;
                }

                const l = data.len;
                if (l == 0) {
                    try conn.close(.{});
                    return false;
                }

                if (l == 1) {
                    // close with a payload always has to have at least a 2-byte payload,
                    // since a 2-byte code is required
                    try conn.writeFramed(CLOSE_PROTOCOL_ERROR);
                    return false;
                }

                const code = @as(u16, @intCast(data[1])) | (@as(u16, @intCast(data[0])) << 8);
                if (code < 1000 or code == 1004 or code == 1005 or code == 1006 or (code > 1013 and code < 3000)) {
                    try conn.writeFramed(CLOSE_PROTOCOL_ERROR);
                    return false;
                }

                if (l == 2) {
                    try conn.writeFramed(CLOSE_NORMAL);
                    return false;
                }

                const payload = data[2..];
                if (!std.unicode.utf8ValidateSlice(payload)) {
                    // if we have a payload, it must be UTF8 (why?!)
                    try conn.writeFramed(CLOSE_PROTOCOL_ERROR);
                } else {
                    try conn.close(.{});
                }
                return false;
            },
        }

        if (conn.isClosed()) {
            return false;
        }

        if (has_more == false) {
            // we don't have more data ready to be processed in our buffer
            // back to our caller for more data
            return true;
        }
    }
}

fn needsAllocator(comptime H: type) bool {
    const params = @typeInfo(@TypeOf(H.clientMessage)).@"fn".params;
    return comptime params[1].type == Allocator;
}

fn respondToHandshakeError(conn: *Conn, err: anyerror) void {
    const response = switch (err) {
        error.Close => return,
        error.RequestTooLarge => buildError(400, "too large"),
        error.Timeout, error.WouldBlock => buildError(400, "timeout"),
        error.InvalidProtocol => buildError(400, "invalid protocol"),
        error.InvalidRequestLine => buildError(400, "invalid requestline"),
        error.InvalidHeader => buildError(400, "invalid header"),
        error.InvalidUpgrade => buildError(400, "invalid upgrade"),
        error.InvalidVersion => buildError(400, "invalid version"),
        error.InvalidConnection => buildError(400, "invalid connection"),
        error.MissingHeaders => buildError(400, "missingheaders"),
        error.Empty => buildError(400, "invalid request"),
        else => buildError(400, "unknown"),
    };
    preHandOffWrite(conn, response);
}

fn buildError(comptime status: u16, comptime err: []const u8) []const u8 {
    return std.fmt.comptimePrint("HTTP/1.1 {d} \r\nConnection: Close\r\nError: {s}\r\nContent-Length: 0\r\n\r\n", .{ status, err });
}

fn preHandOffWrite(conn: *Conn, response: []const u8) void {
    // "preHandOff" means we haven't given the application handler a reference
    // to *Conn yet. In theory, this means we don't need to worry about thread-safety
    // However, it is possible for the worker to be stopped while we're doing this
    // which causes issues unless we lock
    conn.lock.lock();
    defer conn.lock.unlock();

    if (conn.isClosed()) {
        return;
    }

    const socket = conn.stream.handle;
    const timeout = std.mem.toBytes(posix.timeval{ .sec = 5, .usec = 0 });
    posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.SNDTIMEO, &timeout) catch return;

    var pos: usize = 0;
    while (pos < response.len) {
        const n = posix.write(socket, response[pos..]) catch return;
        if (n == 0) {
            // closed
            return;
        }
        pos += n;
    }
}

fn timestamp() u32 {
    if (comptime @hasDecl(posix, "CLOCK") == false or posix.CLOCK == void) {
        return @intCast(std.time.timestamp());
    }
    const ts = posix.clock_gettime(posix.CLOCK.REALTIME) catch unreachable;
    return @intCast(ts.sec);
}

// intrusive doubly-linked list with count, not thread safe
fn List(comptime T: type) type {
    return struct {
        len: usize = 0,
        head: ?*T = null,
        tail: ?*T = null,

        const Self = @This();

        pub fn insert(self: *Self, node: *T) void {
            if (self.tail) |tail| {
                tail.next = node;
                node.prev = tail;
                self.tail = node;
            } else {
                self.head = node;
                self.tail = node;
            }
            self.len += 1;
            node.next = null;
        }

        pub fn remove(self: *Self, node: *T) void {
            if (node.prev) |prev| {
                prev.next = node.next;
            } else {
                self.head = node.next;
            }

            if (node.next) |next| {
                next.prev = node.prev;
            } else {
                self.tail = node.prev;
            }
            node.prev = null;
            node.next = null;
            self.len -= 1;
        }
    };
}

const t = @import("../t.zig");

var test_thread: Thread = undefined;
var test_server: Server(TestHandler) = undefined;
var global_test_allocator = std.heap.GeneralPurposeAllocator(.{}){};

test "tests:beforeAll" {
    test_server = try Server(TestHandler).init(global_test_allocator.allocator(), .{
        .port = 9292,
        .address = "127.0.0.1",
    });
    test_thread = try test_server.listenInNewThread({});
}

test "tests:afterAll" {
    test_server.stop();
    test_thread.join();
    test_server.deinit();
    try t.expectEqual(false, global_test_allocator.detectLeaks());
}

test "Server: invalid handshake" {
    const stream = try testStream(false);
    defer stream.close();

    try stream.writeAll("GET / HTTP/1.1\r\n\r\n");
    var buf: [1024]u8 = undefined;
    var pos: usize = 0;
    while (pos < buf.len) {
        const n = try stream.read(buf[0..]);
        if (n == 0) {
            break;
        }
        pos += n;
    } else {
        unreachable;
    }

    try t.expectString("HTTP/1.1 400 \r\nConnection: Close\r\nError: missingheaders\r\nContent-Length: 0\r\n\r\n", buf[0..pos]);
}

test "Server: read and write" {
    const stream = try testStream(true);
    defer stream.close();

    try stream.writeAll(&proto.frame(.text, "over"));
    var buf: [12]u8 = undefined;
    _ = try stream.readAtLeast(&buf, 6);
    try t.expectSlice(u8, &.{ 129, 4, '9', '0', '0', '0' }, buf[0..6]);
}

test "Server: clientMessage allocator" {
    const stream = try testStream(true);
    defer stream.close();

    try stream.writeAll(&proto.frame(.text, "dyn"));
    var buf: [12]u8 = undefined;
    _ = try stream.readAtLeast(&buf, 12);
    try t.expectSlice(u8, &.{ 129, 10, 'o', 'v', 'e', 'r', ' ', '9', '0', '0', '0', '!' }, buf[0..12]);
}

test "Server: clientMessage writer" {
    const stream = try testStream(true);
    defer stream.close();

    try stream.writeAll(&proto.frame(.text, "writer"));
    var buf: [9]u8 = undefined;
    _ = try stream.readAtLeast(&buf, 9);
    try t.expectSlice(u8, &.{ 129, 7, '9', '0', '0', '0', '!', '!', '!' }, buf[0..9]);
}

// Same as above, but client doesn't shutdown the connection
// When afterAll is runs and things are shutdown, this should still be properly cleaned up
test "Server: dirty clientMessage allocator" {
    const stream = try testStream(true);

    try stream.writeAll(&proto.frame(.text, "dyn"));
    var buf: [12]u8 = undefined;
    _ = try stream.readAtLeast(&buf, 12);
    try t.expectSlice(u8, &.{ 129, 10, 'o', 'v', 'e', 'r', ' ', '9', '0', '0', '0', '!' }, buf[0..12]);
}

test "Conn: close" {
    {
        // plain close
        const stream = try testStream(true);
        defer stream.close();
        try stream.writeAll(&proto.frame(.text, "close1"));
        var buf: [4]u8 = undefined;
        _ = try stream.readAtLeast(&buf, 4);
        try t.expectSlice(u8, &.{ 136, 2, 3, 232 }, buf[0..4]);
    }

    {
        // close with code
        const stream = try testStream(true);
        defer stream.close();
        try stream.writeAll(&proto.frame(.text, "close2"));
        var buf: [4]u8 = undefined;
        _ = try stream.readAtLeast(&buf, 4);
        try t.expectSlice(u8, &.{ 136, 2, 0, 0x7b }, buf[0..4]);
    }

    {
        // close with reason
        const stream = try testStream(true);
        defer stream.close();
        try stream.writeAll(&proto.frame(.text, "close3"));
        var buf: [7]u8 = undefined;
        _ = try stream.readAtLeast(&buf, 7);
        try t.expectSlice(u8, &.{ 136, 5, 0, 0xea, 'b', 'y', 'e' }, buf[0..7]);
    }
}

fn testStream(handshake: bool) !net.Stream {
    const timeout = std.mem.toBytes(std.posix.timeval{ .sec = 0, .usec = 20_000 });
    const address = try std.net.Address.parseIp("127.0.0.1", 9292);
    const stream = try std.net.tcpConnectToAddress(address);
    try std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, &timeout);
    try std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, &timeout);

    if (handshake == false) {
        return stream;
    }

    try stream.writeAll("GET / HTTP/1.1\r\ncontent-length: 0\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nconnection: upgrade\r\nsec-websocket-key: my-key\r\n\r\n");
    var buf: [1024]u8 = undefined;
    var pos: usize = 0;
    while (pos < buf.len) {
        const n = try stream.read(buf[0..]);
        if (n == 0) break;

        pos += n;
        if (std.mem.endsWith(u8, buf[0..pos], "\r\n\r\n")) {
            break;
        }
    } else {
        unreachable;
    }

    try t.expectString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-Websocket-Accept: L8KGBs4w2MNLLzhfzlVoM0scCIE=\r\n\r\n", buf[0..pos]);

    return stream;
}

const TestHandler = struct {
    conn: *Conn,

    pub fn init(h: *const Handshake, conn: *Conn, _: void) !TestHandler {
        try t.expectString("upgrade", h.headers.get("connection").?);
        return .{
            .conn = conn,
        };
    }
    pub fn clientMessage(
        self: *TestHandler,
        allocator: Allocator,
        data: []const u8,
    ) !void {
        if (std.mem.eql(u8, data, "over")) {
            return self.conn.writeText("9000");
        }
        if (std.mem.eql(u8, data, "dyn")) {
            return self.conn.writeText(try std.fmt.allocPrint(allocator, "over {d}!", .{9000}));
        }
        if (std.mem.eql(u8, data, "writer")) {
            var wb = self.conn.writeBuffer(allocator, .text);
            try wb.interface.print("{d}!!!", .{9000});
            return wb.send();
        }
        if (std.mem.eql(u8, data, "ping")) {
            var buf = [_]u8{ 'a', '-', 'p', 'i', 'n', 'g' };
            return self.conn.writePing(&buf);
        }
        if (std.mem.eql(u8, data, "pong")) {
            var buf = [_]u8{ 'a', '-', 'p', 'o', 'n', 'g' };
            return self.conn.writePong(&buf);
        }
        if (std.mem.eql(u8, data, "close1")) {
            return self.conn.close(.{});
        }
        if (std.mem.eql(u8, data, "close2")) {
            return self.conn.close(.{ .code = 123 });
        }
        if (std.mem.eql(u8, data, "close3")) {
            return self.conn.close(.{ .code = 234, .reason = "bye" });
        }
    }
};

test "List" {
    var list = List(TestNode){};
    try expectList(&.{}, list);

    var n1 = TestNode{ .id = 1 };
    list.insert(&n1);
    try expectList(&.{1}, list);

    list.remove(&n1);
    try expectList(&.{}, list);

    var n2 = TestNode{ .id = 2 };
    list.insert(&n2);
    list.insert(&n1);
    try expectList(&.{ 2, 1 }, list);

    var n3 = TestNode{ .id = 3 };
    list.insert(&n3);
    try expectList(&.{ 2, 1, 3 }, list);

    list.remove(&n1);
    try expectList(&.{ 2, 3 }, list);

    list.insert(&n1);
    try expectList(&.{ 2, 3, 1 }, list);

    list.remove(&n2);
    try expectList(&.{ 3, 1 }, list);

    list.remove(&n1);
    try expectList(&.{3}, list);

    list.remove(&n3);
    try expectList(&.{}, list);
}

const TestNode = struct {
    id: i32,
    next: ?*TestNode = null,
    prev: ?*TestNode = null,
};

fn expectList(expected: []const i32, list: List(TestNode)) !void {
    if (expected.len == 0) {
        try t.expectEqual(null, list.head);
        try t.expectEqual(null, list.tail);
        return;
    }

    var i: usize = 0;
    var next = list.head;
    while (next) |node| {
        try t.expectEqual(expected[i], node.id);
        i += 1;
        next = node.next;
    }
    try t.expectEqual(expected.len, i);

    i = expected.len;
    var prev = list.tail;
    while (prev) |node| {
        i -= 1;
        try t.expectEqual(expected[i], node.id);
        prev = node.prev;
    }
    try t.expectEqual(0, i);
}
