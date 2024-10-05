var running: thread.ResetEvent = .{};

pub fn main() !void {
    var alloc = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (alloc.deinit() != .ok) @panic("memory leak");

    var dir = b: {
        const args = try std.process.argsAlloc(alloc.allocator());
        defer std.process.argsFree(alloc.allocator(), args);

        var arg_values = mem.window([]const u8, args, 2, 1);
        while (arg_values.next()) |arg_value| {
            if (mem.eql(u8, arg_value[0], "--directory")) {
                break :b try fs.openDirAbsolute(arg_value[1], .{});
            }
        }

        break :b null;
    };
    defer if (dir) |*d| d.close();

    const address = try net.Address.resolveIp("127.0.0.1", 4221);
    var listener = try address.listen(.{
        .reuse_address = true,
    });
    defer listener.deinit();

    var pool: thread.Pool = undefined;
    try pool.init(.{ .allocator = alloc.allocator() });
    defer pool.deinit();

    var server = try thread.spawn(.{}, main_server, .{ listener, dir, &pool, alloc.allocator() });
    server.detach();

    running.wait();

    log.debug("Shutting down...", .{});
}

fn main_server(server: net.Server, dir: ?fs.Dir, pool: *thread.Pool, alloc: Alloc) void {
    var listener = server;
    while (!running.isSet()) {
        const connection = listener.accept() catch continue;
        pool.spawn(handle_connection, .{ alloc, dir, connection }) catch {
            handle_connection(alloc, dir, connection);
        };
    }
}

fn handle_connection(alloc: Alloc, dir: ?fs.Dir, connection: net.Server.Connection) void {
    log.debug("client connected from {}!", .{connection.address});

    try_handle_request(alloc, dir, connection.stream) catch |err| {
        log.warn("Caught error: {s}", .{@errorName(err)});
        const error_response: Response = switch (err) {
            error.EndOfStream, error.MalformedRequest, error.PathAlreadyExists => .{ .status = .@"Bad Request" },
            error.NotFound, error.FileNotFound => .{ .status = .@"Not Found" },
            error.UnsupportedHttpVersion => .{ .status = .@"HTTP Version Not Supported" },
            error.UnknownMethod => .{ .status = .@"Method Not Allowed" },
            else => b: {
                log.err("Unhandled error: {s}", .{@errorName(err)});
                break :b .{ .status = .@"Internal Server Error" };
            },
        };
        log.debug("Sending error response: {any}", .{error_response});

        error_response.safe_send(connection.stream, .{});
    };
}

fn try_handle_request(alloc: Alloc, dir: ?fs.Dir, stream: net.Stream) !void {
    const req = try Request.parse(alloc, stream.reader());
    defer req.deinit(alloc);

    if (req.line.method == .post and mem.eql(u8, req.line.target, "/shutdown")) {
        running.set();
        req.line.respond(.OK, .{}).safe_send(stream, .{});
        return;
    }

    const route = Routes.match(req.line.target) orelse return error.NotFound;
    try route.handle(alloc, dir, req, stream);
}

const Routes = union(enum) {
    root,
    echo: []const u8,
    user_agent,
    file: []const u8,

    fn match(target: []const u8) ?Routes {
        inline for (std.meta.tags(std.meta.Tag(Routes))) |tag| switch (tag) {
            .root => if (mem.eql(u8, target, "/")) return .root,
            .echo => if (mem.startsWith(u8, target, "/echo/")) return .{ .echo = target[6..] },
            .user_agent => if (mem.eql(u8, target, "/user-agent")) return .user_agent,
            .file => if (mem.startsWith(u8, target, "/files/")) return .{ .file = target[7..] },
        };
        return null;
    }

    fn handle(route: @This(), alloc: Alloc, dir: ?fs.Dir, req: Request, stream: net.Stream) !void {
        switch (route) {
            .root => respond(req, .OK, stream, .{}),
            .echo => |text| {
                if (req.headers.accepts_encoding("gzip")) {
                    var content = try std.ArrayListUnmanaged(u8).initCapacity(alloc, 0);
                    defer content.deinit(alloc);
                    var fio = std.io.fixedBufferStream(text);
                    try std.compress.gzip.compress(fio.reader(), content.writer(alloc), .{});
                    respond(req, .OK, stream, .{ content.items, .{.{ "Content-Encoding", "gzip" }} });
                } else {
                    respond(req, .OK, stream, .{text});
                }
            },
            .user_agent => {
                const user_agent = req.headers.get("user-agent") orelse return error.MalformedRequest;
                respond(req, .OK, stream, .{user_agent});
            },
            .file => |file_name| {
                if (req.line.method == .get or req.line.method == .head) {
                    const root_dir = dir orelse fs.cwd();
                    const file_handle = try root_dir.openFile(file_name, .{});
                    defer file_handle.close();
                    const fs_stat = try file_handle.stat();
                    const file = Response.File{ .file = file_handle, .len = fs_stat.size };
                    respond(req, .OK, stream, .{file});
                } else if (req.line.method == .post) {
                    const content_length = try req.headers.content_length() orelse 0;
                    log.debug("Content-Length: {d}", .{content_length});
                    if (content_length == 0) return error.MalformedRequest;

                    const root_dir = dir orelse fs.cwd();
                    const file_handle = try root_dir.createFile(file_name, .{ .exclusive = true });
                    defer file_handle.close();

                    // reading to end if the input would block until the connection is closed
                    var limit_reader = std.io.limitedReader(stream.reader(), content_length);
                    var buf: [mem.page_size]u8 = undefined;
                    var len: u64 = content_length;

                    while (true) {
                        const read = try limit_reader.read(&buf);
                        log.debug("Read: {d}", .{read});
                        if (read == 0) break;

                        try file_handle.writeAll(buf[0..read]);
                        len -|= read;
                    }

                    respond(req, .Created, stream, .{});
                } else {
                    respond(req, .@"Method Not Allowed", stream, .{});
                }
            },
        }
    }

    fn respond(req: Request, status: Response.Status, stream: net.Stream, args: anytype) void {
        const response = req.line.respond(status, args);
        log.debug("Response: {}", .{response.status});
        response.safe_send(stream, if (args.len > 1) args[1] else .{});
    }
};

const Response = struct {
    status: Status,
    method: RequestLine.Method = .get,
    body: ?Content = null,

    const Self = @This();

    fn deinit(self: Self, alloc: Alloc) void {
        if (self.body) |body| {
            body.deinit(alloc);
        }
    }

    fn safe_send(self: Self, stream: net.Stream, headers: anytype) void {
        if (self.send(stream, headers)) {
            // stream.close();
        } else |err| switch (err) {
            error.BrokenPipe => {
                log.debug("Broken pipe", .{});
            },
            else => @panic("oops"),
        }
    }

    fn send(self: Self, stream: net.Stream, headers: anytype) !void {
        const writer = stream.writer();
        try writer.print("HTTP/1.1 {}\r\n", .{self.status});

        if (self.status == .@"Method Not Allowed") {
            try writer.print("Allow: GET, HEAD, POST\r\n", .{});
        }

        const len = if (self.body) |body| body.content_length() else 0;
        try writer.print("Content-Length: {}\r\n", .{len});

        if (self.body) |body| {
            try writer.print("Content-Type: {s}\r\n", .{body.content_type()});
        }

        inline for (headers) |header| {
            try writer.print("{s}: {s}\r\n", header);
        }

        try writer.print("\r\n", .{});

        if (self.method != .head) {
            if (self.body) |body| {
                try body.send(stream);
            }
        }
    }

    const Status = enum(u9) {
        Continue = 100,
        @"Switching Protocols" = 101,
        OK = 200,
        Created = 201,
        Accepted = 202,
        @"Non-Authoritative Information" = 203,
        @"No Content" = 204,
        @"Reset Content" = 205,
        @"Partial Content" = 206,
        @"Multiple Choices" = 300,
        @"Moved Permanently" = 301,
        Found = 302,
        @"See Other" = 303,
        @"Not Modified" = 304,
        @"Use Proxy" = 305,
        @"Temporary Redirect" = 307,
        @"Permanent Redirect" = 308,
        @"Bad Request" = 400,
        Unauthorized = 401,
        @"Payment Required" = 402,
        Forbidden = 403,
        @"Not Found" = 404,
        @"Method Not Allowed" = 405,
        @"Not Acceptable" = 406,
        @"Proxy Authentication Required" = 407,
        @"Request Timeout" = 408,
        Conflict = 409,
        Gone = 410,
        @"Length Required" = 411,
        @"Precondition Failed" = 412,
        @"Content Too Large" = 413,
        @"URI Too Long" = 414,
        @"Unsupported Media Type" = 415,
        @"Range Not Satisfiable" = 416,
        @"Expectation Failed" = 417,
        @"I'm a teapot" = 418,
        @"Misdirected Request" = 421,
        @"Unprocessable Content" = 422,
        @"Upgrade Required" = 426,
        @"Internal Server Error" = 500,
        @"Not Implemented" = 501,
        @"Bad Gateway" = 502,
        @"Service Unavailable" = 503,
        @"Gateway Timeout" = 504,
        @"HTTP Version Not Supported" = 505,

        pub fn format(self: @This(), comptime fmt: []const u8, args: anytype, writer: anytype) !void {
            _ = fmt;
            _ = args;
            try writer.print("{d} {s}", .{ @intFromEnum(self), @tagName(self) });
        }
    };

    const Content = union(enum) {
        text: []const u8,
        file: File,

        fn content_type(self: @This()) []const u8 {
            return switch (self) {
                .text => "text/plain",
                .file => "application/octet-stream",
            };
        }

        fn content_length(self: @This()) usize {
            switch (self) {
                .text => |text| return text.len,
                .file => |file| return file.len,
            }
        }

        fn send(self: @This(), out: net.Stream) !void {
            switch (self) {
                .text => |text| try out.writeAll(text),
                .file => |file| {
                    var offset: u64 = 0;
                    var len: u64 = file.len;

                    while (len > 0) {
                        const sent = try std.posix.sendfile(out.handle, file.file.handle, offset, len, &.{}, &.{}, 0);
                        offset +|= sent;
                        len -|= sent;
                    }
                },
            }
        }

        fn deinit(self: @This(), alloc: Alloc) void {
            switch (self) {
                .text, .zip => |text| alloc.free(text),
                .file => |file| file.file.close(),
            }
        }
    };

    const File = struct {
        file: fs.File,
        len: u64,
    };
};

const Request = struct {
    line: RequestLine,
    headers: Headers,

    const Self = @This();

    fn parse(alloc: Alloc, reader: anytype) !Self {
        const line = try RequestLine.parse(alloc, reader);
        errdefer line.deinit(alloc);

        const headers = try Headers.parse(alloc, reader);
        errdefer headers.deinit(alloc);

        log.debug("Request: {}", .{line});
        return .{ .line = line, .headers = headers };
    }

    fn deinit(self: @This(), alloc: Alloc) void {
        self.line.deinit(alloc);
        self.headers.deinit(alloc);
    }
};

const RequestLine = struct {
    method: Method,
    target: []const u8,

    const Method = enum { get, head, post, put, delete, connect, options, trace };

    fn deinit(self: @This(), alloc: Alloc) void {
        alloc.free(self.target);
    }

    fn parse(alloc: Alloc, reader: anytype) !@This() {
        const line = try read_line(reader);
        log.debug("Request Line: {s}", .{line});

        const Segments = struct { method: []const u8, target: []const u8, version: []const u8 };
        var segmented: Segments = undefined;

        var segments = mem.splitScalar(u8, line, ' ');
        inline for (std.meta.fields(Segments)) |field_info| {
            const segment = segments.next() orelse return error.MalformedRequest;
            @field(segmented, field_info.name) = segment;
        }
        log.debug("Parsed Request Line: method={s[method]}, path={s[path]}, version={s[version]}", segmented);

        if (!ascii.eqlIgnoreCase(segmented.version, "HTTP/1.1")) return error.UnsupportedHttpVersion;
        if (segmented.method.len > max_method_len) return error.UnknownMethod;

        var method_buf: [max_method_len]u8 = undefined;
        const method_str = ascii.lowerString(&method_buf, segmented.method);
        const method = std.meta.stringToEnum(Method, method_str) orelse return error.UnknownMethod;

        const target = try alloc.dupe(u8, segmented.target);

        return .{ .method = method, .target = target };
    }

    fn respond(req: @This(), status: Response.Status, args: anytype) Response {
        if (args.len == 0) {
            return .{ .status = status, .method = req.method };
        }
        const body: Response.Content = switch (@TypeOf(args[0])) {
            []const u8, []u8 => .{ .text = args[0] },
            Response.File => .{ .file = args[0] },
            else => @compileError("Invalid response type: " ++ @typeName(@TypeOf(args[0]))),
        };

        return .{ .status = status, .method = req.method, .body = body };
    }

    const max_method_len = @tagName(std.sort.max(Method, std.meta.tags(Method), {}, struct {
        fn cmp(_: void, lhs: Method, rhs: Method) bool {
            return mem.lessThan(u8, @tagName(lhs), @tagName(rhs));
        }
    }.cmp).?).len;
};

const Headers = struct {
    headers: []const Header,

    fn deinit(self: Self, alloc: Alloc) void {
        for (self.headers) |header| {
            header.deinit(alloc);
        }
        alloc.free(self.headers);
    }

    fn get(self: *const Self, name: []const u8) ?[]const u8 {
        for (self.headers) |header| {
            if (ascii.eqlIgnoreCase(header.name, name)) return header.value;
        }
        return null;
    }

    fn contains(self: *const Self, name: []const u8) bool {
        return self.get(name) != null;
    }

    fn content_length(self: *const Self) !?u64 {
        if (self.contains("transfer-encoding")) return null;
        const header = self.get("content-length") orelse return null;
        return std.fmt.parseInt(u64, header, 10) catch return error.MalformedRequest;
    }

    fn accepts_encoding(self: *const Self, encoding: []const u8) bool {
        if (self.get("accept-encoding")) |header| {
            var values = mem.splitScalar(u8, header, ',');
            while (values.next()) |value| {
                if (ascii.eqlIgnoreCase(mem.trim(u8, value, &ascii.whitespace), encoding)) return true;
            }
        }
        return false;
    }

    fn parse(alloc: Alloc, reader: anytype) !Self {
        var headers_buf = try std.ArrayListUnmanaged(Header).initCapacity(alloc, 64);
        errdefer {
            for (headers_buf.items) |header| {
                header.deinit(alloc);
            }
            headers_buf.deinit(alloc);
        }

        while (try parse_next(alloc, reader)) |header| {
            try headers_buf.append(alloc, header);
        }
        const headers = try headers_buf.toOwnedSlice(alloc);

        log.debug("Headers: {any}", .{headers});

        return .{ .headers = headers };
    }

    const Header = struct {
        name: []const u8,
        value: []const u8,

        pub fn format(self: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;

            try writer.print("{s}: {s}", .{ self.name, self.value });
        }

        fn deinit(self: @This(), alloc: Alloc) void {
            alloc.free(self.name);
            alloc.free(self.value);
        }
    };

    const Encoding = enum { none, gzip };

    fn parse_next(alloc: Alloc, reader: anytype) !?Header {
        const line = try read_line(reader);
        log.debug("Header Line: {s}", .{line});

        if (line.len == 0) return null;

        var header: Header = undefined;

        var segments = mem.splitScalar(u8, line, ':');
        inline for (std.meta.fields(Header)) |field_info| {
            const segment = segments.next() orelse return error.MalformedRequest;
            @field(header, field_info.name) = mem.trimLeft(u8, segment, &ascii.whitespace);
        }
        log.debug("Parsed Header Line: name={s[name]}, value={s[value]}", header);

        const name = try alloc.dupe(u8, header.name);
        errdefer alloc.free(name);

        const value = try alloc.dupe(u8, header.value);

        return .{ .name = name, .value = value };
    }

    const Self = @This();
};

var line_buf: [8001]u8 = undefined;
fn read_line(reader: anytype) ![]u8 {
    var fbs = std.io.fixedBufferStream(line_buf[0..]);
    try reader.streamUntilDelimiter(fbs.writer(), '\r', fbs.buffer.len);

    const next_byte = try reader.readByte();
    if (next_byte != '\n') return error.MalformedRequest;

    return fbs.getWritten();
}

const std = @import("std");
const Alloc = mem.Allocator;
const ascii = std.ascii;
const fs = std.fs;
const log = std.log;
const mem = std.mem;
const net = std.net;
const thread = std.Thread;
