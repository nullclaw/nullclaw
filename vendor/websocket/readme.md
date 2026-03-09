# A zig websocket server.
The master branch targets the latest stable of Zig (0.15.1). The dev branch targets the latest version of Zig. If you're looking for an older version, look for an zig-X.YZ branches.

Skip to the [client section](#client).

If you're upgrading from a previous version, check out the [Server Migration](https://github.com/karlseguin/websocket.zig/wiki/Server-Migration) and [Client Migration](https://github.com/karlseguin/websocket.zig/wiki/Client-Migration) wikis.

# Server
```zig
const std = @import("std");
const ws = @import("websocket");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var server = try ws.Server(Handler).init(allocator, .{
        .port = 9224,
        .address = "127.0.0.1",
        .handshake = .{
            .timeout = 3,
            .max_size = 1024,
            // since we aren't using hanshake.headers
            // we can set this to 0 to save a few bytes.
            .max_headers = 0,
        },
    });

    // Arbitrary (application-specific) data to pass into each handler
    // Pass void ({}) into listen if you have none
    var app = App{};

    // this blocks
    try server.listen(&app);
}

// This is your application-specific wrapper around a websocket connection
const Handler = struct {
    app: *App,
    conn: *ws.Conn,

    // You must define a public init function which takes
    pub fn init(h: *ws.Handshake, conn: *ws.Conn, app: *App) !Handler {
        // `h` contains the initial websocket "handshake" request
        // It can be used to apply application-specific logic to verify / allow
        // the connection (e.g. valid url, query string parameters, or headers)

        _ = h; // we're not using this in our simple case

        return .{
            .app = app,
            .conn = conn,
        };
    }

    // You must defined a public clientMessage method
    pub fn clientMessage(self: *Handler, data: []const u8) !void {
        try self.conn.write(data); // echo the message back
    }
};

// This is application-specific you want passed into your Handler's
// init function.
const App = struct {
  // maybe a db pool
  // maybe a list of rooms
};
```

## Handler
When you create a `websocket.Server(Handler)`, the specified `Handler` is your structure which will receive messages. It must have a public `init` function and `clientMessage` method. Other methods, such as `close` can optionally be defined.

### init
The `init` method is called with a `*websocket.Handshake`, a `*websocket.Conn` and whatever app-specific value was passed into `Server(H).init`. 

When `init` is called, the handshake response has not yet been sent to the client (this allows your `init` method to return an error which will cause websocket.zig to send an error response and close the connection). As such, you should not use/write to the `*websocket.Conn` at this point. Instead, use the `afterInit` method, described next.

The websocket specification requires the initial "handshake" to contain certain headers and values. The library validates these headers. However applications may have additional requirements before allowing the connection to be "upgraded" to a websocket connection. For example, a one-time-use token could be required in the querystring. Applications should use the provided `websocket.Handshake` to apply any application-specific verification and optionally return an error to terminate the connection.

The `*websocket.Handshake` exposes the following fields:

* `url: []const u8` - URL of the request in its original casing
* `method: []const u8` - Method of the request in its original casing
* `raw_headers: []const u8` - The raw "key1: value1\r\nkey2: value2\r\n" headers. Keys are lowercase.

If you set the `max_headers` configuration value to > 0, then you can use `req.headers.get("HEADER_NAME")` to extract a header value from the given name:

If you set the `max_res_headers` configuration value to > 0, then you can set headers to be sent in the handshake response:

```zig
pub fn init(h: *ws.Handshake, conn: *ws.Conn, app: *App) !Handler {
    h.res_headers.add("set-cookie", "delicious")
    //...
}
```

Note that, currently, the total length of the headers added to `res_headers` should not exceed 1024 characters, else you will exeperience an out of bounds segfault.

```zig
// the last parameter, an *App in this case, is an application-specific
// value that you passed into server.listen()
pub fn init(h: *websocket.Handshake, conn: websocket.Conn, app: *App) !Handler {
    // get returns a ?[]const u8
    // the name is lowercase
    // the value is in its original case
    const token = handshake.headers.get("authorization") orelse {
        return error.NotAuthorized;
    }

    return .{
        .app = app,
        .conn = conn,
    };
}

```

You can iterate through all the headers:
```zig
var it = handshake.headers.iterator();
while (it.next) |kv| {
    std.debug.print("{s} = {s}\n", .{kv.key, kv.value});
}
```

Memory referenced by the `websocket.Handshake`, including headers from `handshake.headers` will be freed after the call to `init` completes. Application that need these values to exist beyond the call to `init` must make a copy.

### afterInit
If your handler defines a `afterInit(handler: *Handler) !void` method, the method is called after the handshake response has been sent. This is the first time the connection can safely be used.

`afterInit` supports two overloads:

```zig
pub fn afterInit(handler: *Handler) !void
pub fn afterInit(handler: *Handler, ctx: anytype) !void
```

The `ctx` is the same `ctx` passed into `init`. It is passed here for cases where the value is only needed once when the connection is established.

### clientMessage
The `clientMessage` method is called whenever a text or binary message is received.

The `clientMessage` method can take one of four shapes. The simplest, shown in the first example, is:

```zig
// simple clientMessage
clientMessage(h: *Handler, data: []u8) !void
```

The Websocket specific has a distinct message type for text and binary. Text messages must be valid UTF-8. Websocket.zig does not do this validation (it's expensive and most apps don't care). However, if you do care about the distinction, your `clientMessage` can take another parameter:

```zig
// clientMessage that accepts a tpe to differentiate between messages
// sent as `text` vs those sent as `binary`. Either way, Websocket.zig
// does not validate that text data is valid UTF-8.
clientMessage(h: *Handler, data: []u8, tpe: ws.MessageTextType) !void
```

Finally, `clientMessage` can take an optional `std.mem.Allocator`. If you need to dynamically allocate memory within `clientMessage`, consider using this allocator. It is a fast thread-local buffer that fallsback to an arena allocator. Allocations made with this allocator are freed after `clientMessage` returns:

```zig
// clientMessage that takes an allocator
clientMessage(h: *Handler, allocator: Allocator, data: []u8) !void

// cilentMessage that takes an allocator AND a MessageTextType
clientMessage(h: *Handler, allocator: Allocator, data: []u8, tpe: ws.MessageTextType) !void`
```

If `clientMessage` returns an error, the connection is closed. You can also call `conn.close()` within the method.

### close
If your handler defines a `close(handler: *Handler) void` method, the method is called whenever the connection is being closed. Guaranteed to be called exactly once, so it is safe to deinitialize the `handler` at this point. This is called no matter the reason for the closure (on shutdown, if the client closed the connection, if your code close the connection, ...)

The socket may or may not still be alive.

### clientClose
If your handler defines a `clientClose(handler: *Handler, data: []u8) !void` method, the function will be called whenever a `close` message is received from the client. 

You almost certainly *do not* want to define this method and instead want to use `close()`. When not defined, websocket.zig follows the websocket specific and replies with its own matching close message.

### clientPong
If your handler defines a `clientPong(handler: *Handler, data: []u8) !void` method, the function will be called whenever a `pong` message is received from the client. When not defined, no action is taken.

### clientPing
If your handler defines a `clientPing(handler: *Handler, data: []u8) !void` method, the function will be called whenever `ping` message is received from the client. When not defined, websocket.zig will write a corresponding `pong` reply.

## websocket.Conn
The call to `init` includes a `*websocket.Conn`. It is expected that handlers will keep a reference to it. The main purpose of the `*Conn` is to write data via `conn.write([]const u8)` and `conn.writeBin([]const u8)`. The websocket protocol differentiates between a "text" and "binary" message, with the only difference that "text" must be valid UTF-8. This library does not enforce this. Which you use really depends on what your client expects. For browsers, text messages appear as strings, and binary messages appear as a Blob or ArrayBuffer (depending on how the client is configured).

`conn.close(.{})` can also be called to close the connection. Calling `conn.close()` **will** result in the handler's `close` callback being called. 

`close` takes an optional value where you can specify the `code` and/or `reason`: `conn.close(.{.code = 4000, .reason = "bye bye"})` Refer to [RFC6455](https://datatracker.ietf.org/doc/html/rfc6455#section-7.4.1) for valid codes. The `reason` must be <= 123 bytes.

### Writer
It's possible to get a `*std.Io.Writer` from a `*Conn`. Because websocket messages are framed, the writter will buffer the message in memory and requires an explicit "send". Buffering requires an allocator. 

```zig
// .text or .binary
var wb = conn.writeBuffer(allocator, .text);
defer wb.deinit();
try wb.interface.print("it's over {d}!!!", .{9000});
try wb.send();
```

Consider using the `clientMessage` overload which accepts an allocator. Not only is this allocator fast (it's a thread-local buffer than fallsback to an arena), but it also eliminates the need to call `deinit`:

```zig
pub fn clientMessage(h: *Handler, allocator: Allocator, data: []const u8) !void {
    // Use the provided allocator.
    // It's faster and doesn't require `deinit` to be called

    var wb = conn.writeBuffer(allocator, .text);
    try std.fmt.format(wb.writer(), "it's over {d}!!!", .{9000});
    try wb.send();
}
```

## Thread Safety
Websocket.zig ensures that only 1 message per connection/handler is processed at a time. Therefore, you will never have concurrent calls to `clientMessage`, `clientPing`, `clientPong` or `clientClose`. Conversely, concurrent calls to methods of `*websocket.Conn` are allowed (i.e. `conn.write` and `conn.close`). 

## Config
The 2nd parameter to `Server(H).init` is a configuration object. 

```zig
pub const Config = struct {
    port: u16 = 9882,

    // Ignored if unix_path is set
    address: []const u8 = "127.0.0.1",

    // Not valid on windows
    unix_path: ?[]const u8 = null,

    // In nonblocking mode (Linux/Mac/BSD), sets the number of
    // listening threads. Defaults to 1.
    // In blocking mode, this is ignored and always set to 1.
    worker_count: ?u8 = null,

    // The maximum number of connections, per worker.
    // default: 16_384
    max_conn: ?usize = null,

    // The maximium allows message size. 
    // A websocket message can have up to 14 bytes of overhead/header
    // Default: 65_536
    max_message_size: ?usize = null,

    handshake: Config.Handshake = .{},
    thread_pool: ThreadPool = .{},
    buffers: Config.Buffers = .{},

    // compression is disabled by default
    compression: ?Compression = null,

    // In blocking mode the thread pool isn't used 
    pub const ThreadPool = struct {
        // Number of threads to process messages.
        // These threads are where your `clientXYZ` method will execute.
        // Default: 4.
        count: ?u16 = null,

        // The maximum number of pending requests that the thread pool will accept
        // This applies back pressure to worker and ensures that, under load
        // pending requests get precedence over processing new requests.
        // Default: 500.
        backlog: ?u32 = null,

        // Size of the static buffer to give each thread. Memory usage will be 
        // `count * buffer_size`.
        // If clientMessage isn't defined with an Allocator, this defaults to 0.
        // Else it default to 32768
        buffer_size: ?usize = null,
    };

    const Handshake = struct {
        // time, in seconds, to timeout the initial handshake request
        timeout: u32 = 10,

        // Max size, in bytes, allowed for the initial handshake request.
        // If you're expected a large handshake (many headers, large cookies, etc)
        // you'll need to set this larger.
        // Default: 1024
        max_size: ?u16 = null,

        // Max number of headers to capture. These become available as
        // handshake.headers.get(...).
        // Default: 0
        max_headers: ?u16 = null,

        // Count of handshake objects to keep in a pool. More are created
        // as needed.
        // Default: 32
        count: ?u16 = null,
    };

    const Buffers = struct {
        // The number of "small" buffers to keep pooled.
        //
        // When `null`, the small buffer pool is disabled and each connection
        // gets its own dedicated small buffer (of `size`). This is reasonable
        // when you expect most clients to be sending a steady stream of data.
        
        // When set > 0, a pool is created (of `size` buffers) and buffers are 
        // assigned as messages are received. This is reasonable when you expect
        // sporadic and messages from clients.
        //
        // Default: `null`
        small_pool: ?usize = null,

        // The size of each "small" buffer. Depending on the value of `pool`
        // this is either a per-connection buffer, or the size of pool buffers
        // shared between all connections
        // Default: 2048
        small_size: ?usize = null,

        // The number of large buffers to have in the pool.
        // Messages larger than `buffers.small_size` but smaller than `max_message_size`
        // will attempt to use a large buffer from the pool.
        // If the pool is empty, a dynamic buffer is created.
        // Default: 8
        large_pool: ?u16 = null,

        // The size of each large buffer.
        // Default: min(2 * buffers.small_size, max_message_size)
        large_size: ?usize = null,
    };

    // Compression is disabled by default, to enable it and accept the default
    // values, set it to a defautl struct: .{}
    const Compression = struct {
        // The mimimum size of data before messages will be compressed
        // null = message are never compressed when writing messages to the client
        // If you want to enable compression, 512 is a reasonable default
        write_threshold: ?usize = null,

        // When compression is enable, and write_treshold != null, every connection
        // gets an std.ArrayList(u8) to write the compressed message to. When this
        // is true, the memory allocated to the ArrayList is kept for subsequent
        // messages (i.e. it calls `clearRetainingCapacity`). When false, the memory
        // is freed after each message. 
        // true = more memory, but fewer allocations
        retain_write_buffer: bool = true,
    };
}
```

## Logging
websocket.zig uses Zig's built-in scope logging. You can control the log level by having an `std_options` decleration in your program's main file:

```zig
pub const std_options = std.Options{
    .log_scope_levels = &[_]std.log.ScopeLevel{
        .{ .scope = .websocket, .level = .err },
    }
};
```

## Advanced

### Pre-Framed Comptime Message
Websocket message have their own special framing. When you use `conn.write` or `conn.writeBin` the data you provide is "framed" into a correct websocket message. Framing is fast and cheap (e.g., it DOES NOT require an O(N) loop through the data). Nonetheless, there may be be cases where pre-framing messages at compile-time is desired. The `websocket.frameText` and `websocket.frameBin` can be used for this purpose:

```zig
const UNKNOWN_COMMAND = websocket.frameText("unknown command");
...

pub fn clientMessage(self: *Handler, data: []const u8) !void {
    if (std.mem.startsWith(u8, data, "join: ")) {
        self.handleJoin(data)
    } else if (std.mem.startsWith(u8, data, "leave: ")) {
        self.handleLead(data)
    } else {
        try self.conn.writeFramed(UNKNOWN_COMMAND);
    }
}
```

### Blocking Mode
kqueue (BSD, MacOS) or epoll (Linux) are used on supported platforms. On all other platforms (most notably Windows), a more naive thread-per-connection with blocking sockets is used.

The comptime-safe, `websocket.blockingMode() bool` function can be called to determine which mode websocket is running in (when it returns `true`, then you're running the simpler blocking mode).

### Per-Connection Buffers
In non-blocking mode, the `buffers.small_pool` and `buffers.small_size` should be set for your particular use case. When `buffers.small_pool == null`, each connection gets its own buffer of `buffers.small_size` bytes. This is a good option if you expect most of your clients to be sending a steady stream of data. While it might take more memory (# of connections * buffers.small_size), its faster and minimizes multi-threading overhead.

However, if you expect clients to only send messages sporadically, such as a chat application, enabling the pool can reduce memory usage at the cost of a bit of overhead.

In blocking mode, these settings are ignored and each connection always gets its own buffer (though there is still a shared large buffer pool).

### Stopping
`server.stop()` can be called to stop the webserver. It is safe to call this from a different thread (i.e. a `sigaction` handler).

## Testing
The library comes with some helpers for testing.

```zig
const wt = @import("websocket").testing;

test "handler: echo" {
    var wtt = wt.init(.{});
    defer wtt.deinit();

    // create an instance of your handler (however you want)
    // and use &tww.conn as the *ws.Conn field
    var handler = Handler{
        .conn = &wtt.conn,
    };

    // execute the methods of your handler
    try handler.clientMessage("hello world");

    // assert what the client should have received
    try wtt.expectMessage(.text, "hello world");
}
```

Besides `expectMessage` you can also call `expectClose()`.

Note that this testing is heavy-handed. It opens up a pair of sockets with one side listening on `127.0.0.1` and accepting a connection from the other. `wtt.conn` is the "server" side of the connection, and assertion happens on the client side.

# Client
The `*websocket.Client` can be used in one of two ways. At its simplest, after creating a client and initiating a handshake, you simply use <code>write</code> to send messages and <code>read</code> to receive them. First, we create the client and initiate the handshake:

```zig
pub fn main() !void {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  const allocator = gpa.allocator();

  // create the client
  var client = try websocket.Client.init(allocator, .{
    .port = 9224,
    .host = "localhost",
  });
  defer client.deinit();

  // send the initial handshake request
  const request_path = "/ws";
  try client.handshake(request_path, .{
    .timeout_ms = 1000,
    // Raw headers to send, if any. 
    // A lot of servers require a Host header.
    // Separate multiple headers using \r\n
    .headers = "Host: localhost:9224",
  });
}
```

We can then use `read` and `write`. By default, `read` blocks until a message is received (or an error occurs). We can make it return `null` by setting a timeout:

```zig
  // optional, read will return null after 1 second
  try client.readTimeout(std.time.ms_per_s * 1);

  // echo messages back to the server until the connection is closed
  while (true) {
    // since we didn't set a timeout, client.read() will either
    // return a message or an error (i.e. it won't return null)
    const message = (try client.read()) orelse {
        // no message after our 1 second
        std.debug.print(".", .{});
        continue;
    };

    // must be called once you're done processing the request
    defer client.done(message);

    switch (message.type) {
      .text, .binary => {
        std.debug.print("received: {s}\n", .{message.data});
        try client.write(message.data);
      },
      .ping => try client.writePong(message.data),
      .pong => {},
      .close => {
        try client.close(.{});
        break;
      }
    }
  }
}
```

### Config
When creating a Client, the 2nd parameter is a configuration object:

* `port` - The port to connect to. Required.
* `host` - The host/IP address to connect to. The Host:IP value IS NOT automatically put in the header of the handshake request. Required.
* `max_size` - Maximum incoming message size to allow. The library will dynamically allocate up to this much space per request. Default: `65536`.
* `buffer_size` - Size of the static buffer that's available for the client to process incoming messages. While there's other overhead, the minimal memory usage of the server will be `# of active clients * buffer_size`. Default: `4096`.
* `tls` - Whether or not to connect over TLS. Only TLS 1.3 is supported. Default: `false`.
* `ca_bundle` - Provide a custom `std.crypto.Certificate.Bundle`. Only meaningful when `tls = true`. Default: `null`.

Setting `max_size == buffer_size` is valid and will ensure that no dynamic memory allocation occurs once the connection is established.

Zig only supports TLS 1.3, so this library can only connect to hosts using TLS 1.3. If no `ca_bundle` is provided, the library will create a default bundle per connection.

### Handshake
`client.handshake()` takes two parameters. The first is the request path. The second is handshake configuration value:

* `timeout_ms` - Timeout, in milliseconds, for the handshake. Default: `10_000` (10 seconds).
* `headers` - Raw headers to include in the handshake. Multiple headers should be separated by by "\r\n". Many servers require a Host header. Example: `"Host: server\r\nAuthorization: Something"`. Defaul: `null`

### Custom Wrapper
In more advanced cases, you'll likely want to wrap a `*ws.Client` in your own type and use a background read loop with "callback" methods. Like in the above example, you'll first want to create a client and initialize a handshake:

```zig
const ws = @import("websocket");

const Handler = struct {
  client: ws.Client,

  fn init(allocator: std.mem.Allocator) !Handler {
    var client = try ws.Client.init(allocator, .{
      .port = 9224,
      .host = "localhost",
    });
    defer client.deinit();

     // send the initial handshake request
    const request_path = "/ws";
    try client.handshake(request_path, .{
      .timeout_ms = 1000,
      .headers = "host: localhost:9224\r\n",
    });

    return .{
      .client = client,
    };
  }
  ```

You can then call `client.readLoopInNewThread()` to start a background listener. Your handler must define a `serverMessage` method:

```zig
  pub fn startLoop(self: *Handler) !void {
    // use readLoop for a blocking version
    const thread = try self.client.readLoopInNewThread(self);
    thread.detach();
  }

  pub fn serverMessage(self: *Handler, data: []u8) !void {
    // echo back to server
    return self.client.write(data);
  }
}
```

Websockets have a number of different message types. `serverMessage` only receives text and binary messages. If you care about the distinction, you can use an overload:

```zig
pub fn serverMessage(self: *Handler, data: []u8, tpe: ws.MessageTextType) !void
```

where `tpe` will be either `.text` or `.binary`. Different callbacks are used for the other message types.

#### Optional Callbacks
In addition to the required `serverMessage`, you can define optional callbacks.

```zig
// Guaranteed to be called exactly once when the readLoop exits
pub fn close(self: *Handler) void

// If omitted, websocket.zig will automatically reply with a pong
pub fn serverPing(self: *Handler, data: []u8) !void

// If omitted, websocket.zig will ignore this  message
pub fn serverPong(self: *Handler) !void

// If omitted, websocket.zig will automatically reply with a close message
pub fn serverClose(self: *Handler) !void
```

You almost certainly **do not** want to define a `serverClose` method, but instead what do define a `close` method. In your `close` callback, you should call `client.close(.{})` (and optionally pass a code and reason).

## Client
Whether you're calling `client.read()` explicitly or using `client.readLoopInNewThread()` (or `client.readLoop()`), the `client` API is the same. In both cases, the various `write` methods, as well as `close()` are thread-safe.

### Writing
It may come as a surprise, but every variation of `write` expects a `[]u8`, not a `[]const u8`. Websocket payloads sent from a client need to be masked, which the websocket.zig library handles. It is obviously more efficient to mutate the given payload versus creating a copy. By taking a `[]u8`, applications with mutable buffers benefit from avoiding the clone. Applications that have immutable buffers will need to create a mutable clone.

```zig
// write a text message
pub fn write(self: *Client, data: []u8) !void

// write a text message (same as client.write(data))
pub fn writeText(self: *Client, data: []u8) !void

// write a binary message
pub fn writeBin(self: *Client, data: []u8) !void

// write a ping message
pub fn writePing(self: *Client, data: []u8) !void

// write a pong message
// if you don't define a handlePong message, websocket.zig
// will automatically answer any ping with a pong
pub fn writePong(self: *Client, data: []u8) !void

// lower-level, use by all of the above
pub fn writeFrame(self: *Client, op_code: proto.OpCode, data: []u8) !void
```

### Reading
As seen above, most applications will either chose to call `read()` explicitly or use a `readLoop`. It is **not safe* to call `read` while the read loop is running.

```zig
// Reads 1 message. Returns null on timeout
// Set a timeout using `client.readTimeout(ms)`
pub fn read(self: *Client) !?ws.Message


// Starts a readloop in the calling thread. 
// `@TypeOf(handler)` must define the `serverMessage` callback
// (and may define other optional callbacks)
pub fn readLoop(self: *Client, handler: anytype) !void

// Same as `readLoop` but starts the readLoop in a new thread
pub fn readLoopInNewThread(self: *Client, h: anytype) !std.Thread
```

### Closing
Use `try client.close(.{.code = 4000, .reason = "bye"})` to both send a close frame and close the connection. Noop if the connection is already known to be close. Thread safe.

Both `code` and `reason` are optional. Refer to [RFC6455](https://datatracker.ietf.org/doc/html/rfc6455#section-7.4.1) for valid codes. The `reason` must be <= 123 bytes.


### Performance Optimization 1 - CA Bundle
For a high number of connections, it might be beneficial to manage our own CA bundle:

```zig
// some global data
var ca_bundle = std.crypto.Certificate.Bundle{}
try ca_bundle.rescan(allocator);
defer ca_bundle.deinit(allocator);
```

And then assign this `ca_bundle` into the the configuration's `ca_bundle` field. This way the library does not have to create and scan the installed CA certificates for each client connection.

### Performance Optimization 2 - Buffer Provider
For a high nummber of connections a large buffer pool can be created and provided to each client:

```zig
// Create a buffer pool of 10 buffers, each being 32K
const buffer_provider = try websocket.bufferProvider(allocator, 10, 32768);
defer buffer_provider.deinit();


// create your client(s) using the above created buffer_provider
var client = try websocket.connect(allocator, "localhost", 9001, .{
    ...
    .buffer_provider = buffer_provider,
});
```

This allows each client to have a reasonable `buffer_size` that can accomodate most messages, while having an efficient fallback for the occasional large message. When `max_size` is greater than the large buffer pool size (32K in the above example) or when all pooled buffers are used, a dynamic buffer is created.
