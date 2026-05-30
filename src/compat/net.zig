const std = @import("std");
const builtin = @import("builtin");
const shared = @import("shared.zig");

const IoNet = std.Io.net;
const Allocator = std.mem.Allocator;
const posix = std.posix;

pub fn invalidHandle(comptime T: type) T {
    return switch (@typeInfo(T)) {
        .int => std.math.maxInt(T),
        .pointer => @ptrFromInt(std.math.maxInt(usize)),
        else => @compileError("unsupported socket handle type"),
    };
}

fn setSocketNonblocking(handle: IoNet.Socket.Handle, nonblocking: bool) !void {
    switch (builtin.os.tag) {
        .windows, .wasi => return,
        else => {},
    }

    const rc = posix.system.fcntl(handle, posix.F.GETFL, @as(usize, 0));
    const current_flags = switch (posix.errno(rc)) {
        .SUCCESS => @as(usize, @intCast(rc)),
        .AGAIN => return error.WouldBlock,
        else => |err| return posix.unexpectedErrno(err),
    };
    const nonblocking_flag = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
    const next_flags = if (nonblocking)
        current_flags | nonblocking_flag
    else
        current_flags & ~nonblocking_flag;
    if (next_flags == current_flags) return;

    switch (posix.errno(posix.system.fcntl(handle, posix.F.SETFL, next_flags))) {
        .SUCCESS => {},
        .AGAIN => return error.WouldBlock,
        .INVAL => |err| return posix.unexpectedErrno(err),
        else => |err| return posix.unexpectedErrno(err),
    }
}

fn setSocketCloseOnExec(handle: IoNet.Socket.Handle) !void {
    switch (builtin.os.tag) {
        .windows, .wasi => return,
        else => {},
    }

    while (true) {
        switch (posix.errno(posix.system.fcntl(handle, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC)))) {
            .SUCCESS => return,
            .INTR => continue,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

pub const has_unix_sockets = false;

pub const Stream = struct {
    handle: Handle,

    pub const Handle = IoNet.Socket.Handle;
    pub const Reader = IoNet.Stream.Reader;
    pub const Writer = IoNet.Stream.Writer;
    pub const ReadError = IoNet.Stream.Reader.Error || error{WouldBlock};
    pub const WriteError = IoNet.Stream.Writer.Error;

    fn toInner(self: Stream) IoNet.Stream {
        return .{
            .socket = .{
                .handle = self.handle,
                .address = .{ .ip4 = .loopback(0) },
            },
        };
    }

    pub fn close(self: Stream) void {
        self.toInner().close(shared.io());
    }

    pub fn reader(self: Stream, buffer: []u8) Reader {
        return self.toInner().reader(shared.io(), buffer);
    }

    pub fn writer(self: Stream, buffer: []u8) Writer {
        return self.toInner().writer(shared.io(), buffer);
    }

    pub fn read(self: Stream, buffer: []u8) ReadError!usize {
        if (buffer.len == 0) return 0;

        const io = shared.io();
        var data = [1][]u8{buffer};
        return io.vtable.netRead(io.userdata, self.handle, &data) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return err,
        };
    }

    pub fn write(self: Stream, bytes: []const u8) WriteError!usize {
        if (bytes.len == 0) return 0;

        const io = shared.io();
        var total: usize = 0;
        while (total < bytes.len) {
            var data = [1][]const u8{bytes[total..]};
            const n = try io.vtable.netWrite(io.userdata, self.handle, "", &data, 1);
            if (n == 0) return error.Unexpected;
            total += n;
        }
        return total;
    }

    pub fn writeAll(self: Stream, bytes: []const u8) WriteError!void {
        _ = try self.write(bytes);
    }

    pub fn shutdown(self: Stream, how: IoNet.ShutdownHow) IoNet.ShutdownError!void {
        try self.toInner().shutdown(shared.io(), how);
    }
};

pub const Ip4Address = extern struct {
    sa: posix.sockaddr.in,

    pub fn getPort(self: Ip4Address) u16 {
        return std.mem.bigToNative(u16, self.sa.port);
    }

    pub fn setPort(self: *Ip4Address, port: u16) void {
        self.sa.port = std.mem.nativeToBig(u16, port);
    }

    pub fn getOsSockLen(self: Ip4Address) posix.socklen_t {
        _ = self;
        return @sizeOf(posix.sockaddr.in);
    }
};

pub const Ip6Address = extern struct {
    sa: posix.sockaddr.in6,

    pub fn getPort(self: Ip6Address) u16 {
        return std.mem.bigToNative(u16, self.sa.port);
    }

    pub fn setPort(self: *Ip6Address, port: u16) void {
        self.sa.port = std.mem.nativeToBig(u16, port);
    }

    pub fn getOsSockLen(self: Ip6Address) posix.socklen_t {
        _ = self;
        return @sizeOf(posix.sockaddr.in6);
    }
};

fn ip4FromCurrent(ip4: IoNet.Ip4Address) Ip4Address {
    return .{
        .sa = .{
            .port = std.mem.nativeToBig(u16, ip4.port),
            .addr = @as(*align(1) const u32, @ptrCast(&ip4.bytes)).*,
        },
    };
}

fn ip4ToCurrent(ip4: Ip4Address) IoNet.Ip4Address {
    return .{
        .bytes = @bitCast(ip4.sa.addr),
        .port = ip4.getPort(),
    };
}

fn ip6FromCurrent(ip6: IoNet.Ip6Address) Ip6Address {
    return .{
        .sa = .{
            .port = std.mem.nativeToBig(u16, ip6.port),
            .flowinfo = ip6.flow,
            .addr = ip6.bytes,
            .scope_id = ip6.interface.index,
        },
    };
}

fn ip6ToCurrent(ip6: Ip6Address) IoNet.Ip6Address {
    return .{
        .port = ip6.getPort(),
        .bytes = ip6.sa.addr,
        .flow = ip6.sa.flowinfo,
        .interface = .{ .index = ip6.sa.scope_id },
    };
}

pub const Address = extern union {
    any: posix.sockaddr,
    in: Ip4Address,
    in6: Ip6Address,

    fn fromCurrent(addr: IoNet.IpAddress) Address {
        return switch (addr) {
            .ip4 => |ip4| .{ .in = ip4FromCurrent(ip4) },
            .ip6 => |ip6| .{ .in6 = ip6FromCurrent(ip6) },
        };
    }

    pub fn parseIp4(name: []const u8, port: u16) !Address {
        return fromCurrent(try IoNet.IpAddress.parseIp4(name, port));
    }

    pub fn parseIp6(name: []const u8, port: u16) !Address {
        return fromCurrent(try IoNet.IpAddress.parseIp6(name, port));
    }

    pub fn parseIp(name: []const u8, port: u16) !Address {
        return fromCurrent(try IoNet.IpAddress.parse(name, port));
    }

    pub fn initUnix(_: []const u8) !Address {
        return error.UnixSocketsNotSupported;
    }

    pub fn resolveIp(name: []const u8, port: u16) !Address {
        return fromCurrent(try IoNet.IpAddress.resolve(shared.io(), name, port));
    }

    pub fn toCurrent(self: Address) IoNet.IpAddress {
        return switch (self.any.family) {
            posix.AF.INET => .{ .ip4 = ip4ToCurrent(self.in) },
            posix.AF.INET6 => .{ .ip6 = ip6ToCurrent(self.in6) },
            else => unreachable,
        };
    }

    pub fn format(self: Address, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try self.toCurrent().format(writer);
    }

    pub fn getOsSockLen(self: Address) posix.socklen_t {
        return switch (self.any.family) {
            posix.AF.INET => self.in.getOsSockLen(),
            posix.AF.INET6 => self.in6.getOsSockLen(),
            else => @sizeOf(posix.sockaddr),
        };
    }

    pub const ListenOptions = struct {
        reuse_address: bool = false,
        force_nonblocking: bool = false,
    };

    pub fn listen(self: Address, options: ListenOptions) !Server {
        const current = self.toCurrent();
        var server = try current.listen(shared.io(), .{
            .reuse_address = options.reuse_address,
            .mode = .stream,
            .protocol = .tcp,
        });
        errdefer server.deinit(shared.io());
        try setSocketNonblocking(server.socket.handle, options.force_nonblocking);

        return .{
            .listen_address = Address.fromCurrent(server.socket.address),
            .stream = .{ .handle = server.socket.handle },
        };
    }
};

pub const Server = struct {
    listen_address: Address,
    stream: Stream,

    pub const Connection = struct {
        stream: Stream,
        address: Address,
    };

    pub fn deinit(self: *Server) void {
        self.stream.close();
        self.* = undefined;
    }

    pub const AcceptError = IoNet.Server.AcceptError;

    fn acceptPosixNonblocking(self: *Server) AcceptError!Connection {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            unreachable;
        }

        var address: Address = undefined;
        var address_len: posix.socklen_t = @sizeOf(Address);

        // accept4() with SOCK_CLOEXEC is preferred: it is atomic (no separate fcntl)
        // and it is the only accept variant allowed by Android's seccomp policy.
        // macOS/Haiku do not have accept4(), so fall back to accept() + fcntl there.
        const have_accept4 = comptime builtin.os.tag == .linux;

        while (true) {
            const rc = if (have_accept4)
                posix.system.accept4(self.stream.handle, &address.any, &address_len, posix.SOCK.CLOEXEC)
            else
                posix.system.accept(self.stream.handle, &address.any, &address_len);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    var stream: Stream = .{ .handle = @intCast(rc) };
                    errdefer stream.close();
                    if (!have_accept4) try setSocketCloseOnExec(stream.handle);
                    try setSocketNonblocking(stream.handle, false);
                    return .{
                        .stream = stream,
                        .address = address,
                    };
                },
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .CONNABORTED => return error.ConnectionAborted,
                .INVAL => return error.SocketNotListening,
                .MFILE => return error.ProcessFdQuotaExceeded,
                .NFILE => return error.SystemFdQuotaExceeded,
                .NETDOWN => return error.NetworkDown,
                .NOBUFS, .NOMEM => return error.SystemResources,
                .PERM => return error.BlockedByFirewall,
                .PROTO => return error.ProtocolFailure,
                else => |err| return posix.unexpectedErrno(err),
            }
        }
    }

    fn acceptViaIo(self: *Server) AcceptError!Connection {
        const accept_options: IoNet.Server.AcceptOptions = if (comptime IoNet.Server.AcceptOptions == void) {} else .{ .mode = .stream, .protocol = .tcp };
        var server: IoNet.Server = .{
            .socket = .{
                .handle = self.stream.handle,
                .address = self.listen_address.toCurrent(),
            },
            .options = accept_options,
        };
        var stream = try server.accept(shared.io());
        errdefer stream.close(shared.io());
        try setSocketNonblocking(stream.socket.handle, false);
        return .{
            .stream = .{ .handle = stream.socket.handle },
            .address = Address.fromCurrent(stream.socket.address),
        };
    }

    pub fn accept(self: *Server) AcceptError!Connection {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            return self.acceptViaIo();
        }

        if (socketIsNonblocking(self.stream.handle)) {
            return self.acceptPosixNonblocking();
        }

        return self.acceptViaIo();
    }
};

pub const AddressList = struct {
    arena: std.heap.ArenaAllocator,
    addrs: []Address,
    canon_name: ?[]u8 = null,

    pub fn deinit(self: *AddressList) void {
        var arena = self.arena;
        arena.deinit();
    }
};

pub const GetAddressListError = Allocator.Error || error{
    TemporaryNameServerFailure,
    NameServerFailure,
    AddressFamilyNotSupported,
    NameTooLong,
    UnknownHostName,
    ServiceUnavailable,
    Unexpected,
    SystemResources,
};

pub fn tcpConnectToAddress(address: Address) !Stream {
    var stream = try address.toCurrent().connect(shared.io(), .{
        .mode = .stream,
        .protocol = .tcp,
    });
    errdefer stream.close(shared.io());
    try setSocketNonblocking(stream.socket.handle, false);
    return .{ .handle = stream.socket.handle };
}

pub fn tcpConnectToHost(allocator: Allocator, host: []const u8, port: u16) !Stream {
    const addresses = try getAddressList(allocator, host, port);
    defer addresses.deinit();
    if (addresses.addrs.len == 0) return error.UnknownHostName;
    return tcpConnectToAddress(addresses.addrs[0]);
}

fn shouldUseWindowsLocalhostFallback(name: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, "localhost")) return true;

    const localhost_suffix = ".localhost";
    return name.len > localhost_suffix.len and std.ascii.endsWithIgnoreCase(name, localhost_suffix);
}

fn mapWindowsLookupError(err: anyerror) GetAddressListError {
    return switch (err) {
        error.UnknownHostName, error.NoAddressReturned => error.UnknownHostName,
        error.NameServerFailure,
        error.ResolvConfParseFailed,
        error.InvalidDnsARecord,
        error.InvalidDnsAAAARecord,
        error.InvalidDnsCnameRecord,
        error.DetectingNetworkConfigurationFailed,
        => error.NameServerFailure,
        error.SystemResources => error.SystemResources,
        else => error.Unexpected,
    };
}

fn getAddressListWindows(gpa: Allocator, name: []const u8, port: u16) GetAddressListError!*AddressList {
    const io = shared.io();
    const host_name = IoNet.HostName.init(name) catch |err| switch (err) {
        error.NameTooLong => return error.NameTooLong,
        error.InvalidHostName => return error.UnknownHostName,
    };

    const list = blk: {
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();

        const list = try arena.allocator().create(AddressList);
        list.* = .{
            .arena = arena,
            .addrs = undefined,
            .canon_name = null,
        };
        break :blk list;
    };
    errdefer list.deinit();

    const arena_allocator = list.arena.allocator();
    var addrs = std.ArrayList(Address).empty;
    defer addrs.deinit(arena_allocator);

    var canonical_name_buffer: [IoNet.HostName.max_len]u8 = undefined;
    var lookup_buffer: [16]IoNet.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(IoNet.HostName.LookupResult) = .init(&lookup_buffer);

    // HostName.lookup is async; use io.async so the Io runtime drives
    // DNS resolution and closes the queue.
    var lookup_future = io.async(IoNet.HostName.lookup, .{ host_name, io, &lookup_queue, .{
        .port = port,
        .canonical_name_buffer = &canonical_name_buffer,
    } });
    defer lookup_future.cancel(io) catch {};

    while (lookup_queue.getOne(io)) |resolved| {
        switch (resolved) {
            .address => |ip_address| try addrs.append(arena_allocator, Address.fromCurrent(ip_address)),
            .canonical_name => |canonical| {
                if (list.canon_name == null) {
                    list.canon_name = try arena_allocator.dupe(u8, canonical.bytes);
                }
            },
        }
    } else |err| switch (err) {
        error.Canceled, error.Closed => {
            // Queue closed or cancelled; lookup is done. Propagate any lookup-level error.
            _ = lookup_future.await(io) catch |lookup_err| return mapWindowsLookupError(lookup_err);
        },
    }

    if (addrs.items.len == 0) return error.UnknownHostName;
    list.addrs = try addrs.toOwnedSlice(arena_allocator);
    return list;
}

pub fn getAddressList(gpa: Allocator, name: []const u8, port: u16) GetAddressListError!*AddressList {
    if (name.len > IoNet.HostName.max_len) return error.NameTooLong;

    if (Address.resolveIp(name, port)) |addr| {
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();

        const list = try arena.allocator().create(AddressList);
        list.* = .{
            .arena = arena,
            .addrs = try arena.allocator().dupe(Address, &.{addr}),
            .canon_name = null,
        };
        return list;
    } else |_| {}

    if (builtin.os.tag == .windows) {
        if (shouldUseWindowsLocalhostFallback(name)) {
            const fallback_name = "127.0.0.1";
            const fallback_addr = Address.parseIp(fallback_name, port) catch unreachable;

            var arena = std.heap.ArenaAllocator.init(gpa);
            errdefer arena.deinit();

            const list = try arena.allocator().create(AddressList);
            list.* = .{
                .arena = arena,
                .addrs = try arena.allocator().dupe(Address, &.{fallback_addr}),
                .canon_name = try arena.allocator().dupe(u8, fallback_name),
            };
            return list;
        }

        return getAddressListWindows(gpa, name, port);
    }

    const result = blk: {
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();

        const list = try arena.allocator().create(AddressList);
        list.* = .{
            .arena = arena,
            .addrs = undefined,
            .canon_name = null,
        };
        break :blk list;
    };
    errdefer result.deinit();

    const arena = result.arena.allocator();

    var name_buffer: [IoNet.HostName.max_len:0]u8 = undefined;
    @memcpy(name_buffer[0..name.len], name);
    name_buffer[name.len] = 0;
    const name_c = name_buffer[0..name.len :0];

    var port_buffer: [8]u8 = undefined;
    const port_c = std.fmt.bufPrintZ(&port_buffer, "{d}", .{port}) catch unreachable;

    const hints: posix.addrinfo = .{
        .flags = .{ .CANONNAME = false, .NUMERICSERV = true },
        .family = posix.AF.UNSPEC,
        .socktype = posix.SOCK.STREAM,
        .protocol = posix.IPPROTO.TCP,
        .canonname = null,
        .addr = null,
        .addrlen = 0,
        .next = null,
    };
    var res: ?*posix.addrinfo = null;
    switch (posix.system.getaddrinfo(name_c.ptr, port_c.ptr, &hints, &res)) {
        @as(posix.system.EAI, @enumFromInt(0)) => {},
        .ADDRFAMILY, .FAMILY => return error.AddressFamilyNotSupported,
        .AGAIN => return error.TemporaryNameServerFailure,
        .FAIL => return error.NameServerFailure,
        .MEMORY => return error.SystemResources,
        .NODATA, .NONAME => return error.UnknownHostName,
        else => return error.Unexpected,
    }
    defer if (res) |some| posix.system.freeaddrinfo(some);

    var addrs = std.ArrayList(Address).empty;
    defer addrs.deinit(arena);

    var it = res;
    while (it) |info| : (it = info.next) {
        const addr = info.addr orelse continue;
        switch (addr.family) {
            posix.AF.INET => try addrs.append(arena, .{ .in = .{ .sa = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(addr))).* } }),
            posix.AF.INET6 => try addrs.append(arena, .{ .in6 = .{ .sa = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(addr))).* } }),
            else => {},
        }
    }

    result.addrs = try addrs.toOwnedSlice(arena);
    return result;
}

test "compat net oversized hostname fails fast" {
    const oversized = try std.testing.allocator.alloc(u8, IoNet.HostName.max_len + 1);
    defer std.testing.allocator.free(oversized);
    @memset(oversized, 'a');

    try std.testing.expectError(error.NameTooLong, getAddressList(std.testing.allocator, oversized, 443));
}

test "compat net windows localhost fallback helper is scoped" {
    // Regression: Windows getAddressList used to return UnknownHostName for
    // every non-localhost hostname because this fallback short-circuited DNS.
    // Keep the reserved .localhost zone local, but do not bypass DNS for
    // unrelated hostnames.
    try std.testing.expect(shouldUseWindowsLocalhostFallback("localhost"));
    try std.testing.expect(shouldUseWindowsLocalhostFallback("LOCALHOST"));
    try std.testing.expect(shouldUseWindowsLocalhostFallback("foo.localhost"));
    try std.testing.expect(shouldUseWindowsLocalhostFallback("FOO.LOCALHOST"));
    try std.testing.expect(!shouldUseWindowsLocalhostFallback("example.invalid"));
    try std.testing.expect(!shouldUseWindowsLocalhostFallback("localhost.example"));
}

test "compat net windows lookup errors map to address list errors" {
    try std.testing.expect(mapWindowsLookupError(error.UnknownHostName) == error.UnknownHostName);
    try std.testing.expect(mapWindowsLookupError(error.NoAddressReturned) == error.UnknownHostName);
    try std.testing.expect(mapWindowsLookupError(error.NameServerFailure) == error.NameServerFailure);
    try std.testing.expect(mapWindowsLookupError(error.ResolvConfParseFailed) == error.NameServerFailure);
    try std.testing.expect(mapWindowsLookupError(error.InvalidDnsARecord) == error.NameServerFailure);
    try std.testing.expect(mapWindowsLookupError(error.InvalidDnsAAAARecord) == error.NameServerFailure);
    try std.testing.expect(mapWindowsLookupError(error.InvalidDnsCnameRecord) == error.NameServerFailure);
    try std.testing.expect(mapWindowsLookupError(error.DetectingNetworkConfigurationFailed) == error.NameServerFailure);
    try std.testing.expect(mapWindowsLookupError(error.SystemResources) == error.SystemResources);
    try std.testing.expect(mapWindowsLookupError(error.Canceled) == error.Unexpected);
}

test "compat net normalizes listener and stream blocking mode" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    const addr = try Address.resolveIp("127.0.0.1", 0);
    var server = try addr.listen(.{ .force_nonblocking = true });
    defer server.deinit();

    try std.testing.expect(socketIsNonblocking(server.stream.handle));

    const client = try tcpConnectToAddress(server.listen_address);
    defer client.close();
    try std.testing.expect(!socketIsNonblocking(client.handle));

    var conn = server.accept() catch |err| switch (err) {
        error.WouldBlock => blk: {
            std.Io.sleep(shared.io(), .fromNanoseconds(10 * std.time.ns_per_ms), .awake) catch {};
            break :blk try server.accept();
        },
        else => return err,
    };
    defer conn.stream.close();

    try std.testing.expect(!socketIsNonblocking(conn.stream.handle));
}

test "compat net nonblocking listener accept reports WouldBlock when idle" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    const addr = try Address.resolveIp("127.0.0.1", 0);
    var server = try addr.listen(.{ .force_nonblocking = true });
    defer server.deinit();

    // Regression for #851: Zig 0.16 Threaded accept maps EAGAIN on externally
    // non-blocking listeners to Unexpected instead of WouldBlock.
    try std.testing.expectError(error.WouldBlock, server.accept());
}

test "compat net nonblocking listener accept4 accepted socket is blocking" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    // Regression: acceptPosixNonblocking used accept() which is blocked by Android
    // seccomp policy (SIGSYS). It must use accept4(SOCK_CLOEXEC) instead.
    // Verify that the path is exercised and the returned socket is blocking.
    const addr = try Address.resolveIp("127.0.0.1", 0);
    var server = try addr.listen(.{ .force_nonblocking = true });
    defer server.deinit();

    const client = try tcpConnectToAddress(server.listen_address);
    defer client.close();

    var conn = server.accept() catch |err| switch (err) {
        error.WouldBlock => blk: {
            std.Io.sleep(shared.io(), .fromNanoseconds(10 * std.time.ns_per_ms), .awake) catch {};
            break :blk try server.accept();
        },
        else => return err,
    };
    defer conn.stream.close();

    // Accepted socket must be blocking regardless of listener nonblocking mode.
    try std.testing.expect(!socketIsNonblocking(conn.stream.handle));
}

test "compat net stream read receives small socket payload" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    const addr = try Address.resolveIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();

    const client = try tcpConnectToAddress(server.listen_address);
    defer client.close();

    var conn = try server.accept();
    defer conn.stream.close();

    try conn.stream.writeAll("$-1\r\n");

    var buf: [8]u8 = undefined;
    var filled: usize = 0;
    while (filled < 5) {
        const n = try client.read(buf[filled..5]);
        if (n == 0) return error.TestUnexpectedResult;
        filled += n;
    }

    try std.testing.expectEqualStrings("$-1\r\n", buf[0..5]);
}

test "compat net stream write sends small socket payload" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    const addr = try Address.resolveIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();

    const client = try tcpConnectToAddress(server.listen_address);
    defer client.close();

    var conn = try server.accept();
    defer conn.stream.close();

    // Regression for #858: Stream.write must not create a one-off Io.Writer
    // with an empty buffer for each socket write.
    const payload = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    try std.testing.expectEqual(payload.len, try conn.stream.write(payload));

    var buf: [payload.len]u8 = undefined;
    var filled: usize = 0;
    while (filled < payload.len) {
        const n = try client.read(buf[filled..]);
        if (n == 0) return error.TestUnexpectedResult;
        filled += n;
    }

    try std.testing.expectEqualStrings(payload, &buf);
}

test "compat net stream zero length io is no-op" {
    const stream: Stream = .{ .handle = invalidHandle(Stream.Handle) };
    var empty: [0]u8 = .{};

    try std.testing.expectEqual(@as(usize, 0), try stream.read(&empty));
    try std.testing.expectEqual(@as(usize, 0), try stream.write(""));
    try stream.writeAll("");
}

test "compat net stream read returns zero after peer send shutdown" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    const addr = try Address.resolveIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();

    const client = try tcpConnectToAddress(server.listen_address);
    defer client.close();

    var conn = try server.accept();
    defer conn.stream.close();

    try client.shutdown(.send);

    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try conn.stream.read(&buf));
}

test "compat net stream write after send shutdown reports socket unconnected" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return;

    const addr = try Address.resolveIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();

    const client = try tcpConnectToAddress(server.listen_address);
    defer client.close();

    var conn = try server.accept();
    defer conn.stream.close();

    try conn.stream.shutdown(.send);

    try std.testing.expectError(error.SocketUnconnected, conn.stream.write("x"));
    try std.testing.expectError(error.SocketUnconnected, conn.stream.writeAll("x"));
}

fn socketIsNonblocking(handle: IoNet.Socket.Handle) bool {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return false;
    const rc = posix.system.fcntl(handle, posix.F.GETFL, @as(usize, 0));
    if (posix.errno(rc) != .SUCCESS) return false;
    const flags: usize = @intCast(rc);
    const nonblocking_flag = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
    return (flags & nonblocking_flag) != 0;
}

// Regression: nullclaw/nullclaw#890 -- Windows getAddressList was a localhost-only
// stub returning error.UnknownHostName for any name other than exact localhost.
// The .localhost suffix is reserved for loopback names, so resolve it locally
// instead of relying on runner-specific Windows DNS behavior.
test "compat net getAddressList resolves localhost subdomain on windows" {
    if (builtin.os.tag != .windows) return;
    const list = try getAddressList(std.testing.allocator, "foo.localhost", 443);
    defer list.deinit();
    try std.testing.expect(list.addrs.len > 0);
    try std.testing.expect(list.addrs[0].any.family == posix.AF.INET);
}

// Regression: nullclaw/nullclaw#890 -- Windows getAddressList was a localhost-only stub.
// This test guards the localhost string fast-path.
test "compat net getAddressList localhost fast-path on windows" {
    if (builtin.os.tag != .windows) return;
    const list = try getAddressList(std.testing.allocator, "localhost", 80);
    defer list.deinit();
    try std.testing.expect(list.addrs.len == 1);
    try std.testing.expect(list.addrs[0].any.family == posix.AF.INET);
}

// Regression: nullclaw/nullclaw#890 -- invalid hostnames must map to
// error.UnknownHostName, not surface as Unexpected or a silent success.
test "compat net getAddressList returns UnknownHostName for invalid hostname on windows" {
    if (builtin.os.tag != .windows) return;
    const result = getAddressList(std.testing.allocator, "bad host", 80);
    try std.testing.expectError(error.UnknownHostName, result);
}
