const std = @import("std");
const net = std.net;

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    const ally = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer ally.deinit();

    // const alloc = ally.allocator();

    // Uncomment this block to pass the first stage
    const address = try net.Address.resolveIp("127.0.0.1", 4221);
    var listener = try address.listen(.{
        .reuse_address = true,
    });
    defer listener.deinit();

    const connection = try listener.accept();
    try stdout.print("client connected from {}!\n", .{connection.address});

    const req = Request.parse(connection.stream.reader());
    const res = handle_request(req);

    std.log.debug("Response: {any}", .{res});

    try res.send(connection.stream.writer());
    // connection.stream.close();
}

fn handle_request(req_try: anyerror!Request) Response {
    const req = req_try catch |err| switch (err) {
        error.EndOfStream, Error.MalformedRequest => return .{ .status = .@"Bad Request" },
        Error.UnsupportedHttpVersion => return .{ .status = .@"HTTP Version Not Supported" },
        Error.UnknownMethod => return .{ .status = .@"Method Not Allowed" },
        else => return .{ .status = .@"Internal Server Error" },
    };
    std.log.debug("Request: {}", .{req});

    if (req.method == .get and std.mem.eql(u8, req.target, "/")) {
        return .{ .status = .OK };
    } else {
        return .{ .status = .@"Not Found" };
    }
}

const Response = struct {
    status: Status,
    body: ?[]const u8 = null,

    const Self = @This();

    fn send(self: Self, writer: anytype) !void {
        try writer.print("HTTP/1.1 {d} {s}\r\n", .{ @intFromEnum(self.status), @tagName(self.status) });

        if (self.status == .@"Method Not Allowed") {
            try writer.print("Allow: GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE\r\n", .{});
        }
        if (self.body) |body| {
            try writer.print("Content-Length: {}\r\n", .{body.len});
            try writer.print("Content-Type: text/plain\r\n", .{});
        }
        try writer.print("\r\n", .{});

        if (self.body) |body| {
            try writer.writeAll(body);
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
    };
};

const Request = struct {
    method: Method,
    target: []const u8,

    const Method = enum { get, head, post, put, delete, connect, options, trace };
    const max_method_len = @tagName(std.sort.max(Method, std.meta.tags(Method), {}, struct {
        fn cmp(_: void, lhs: Method, rhs: Method) bool {
            return std.mem.lessThan(u8, @tagName(lhs), @tagName(rhs));
        }
    }.cmp).?).len;

    const Self = @This();

    var line_buf: [8001]u8 = undefined;

    fn parse(reader: anytype) !Self {
        const line = try read_line(reader, line_buf[0..]);
        std.log.debug("Request Line: {s}", .{line});

        const Segments = struct { method: []const u8, target: []const u8, version: []const u8 };
        var segmented: Segments = undefined;

        var segments = std.mem.splitScalar(u8, line, ' ');
        inline for (std.meta.fields(Segments)) |field_info| {
            const segment = segments.next() orelse return Error.MalformedRequest;
            @field(segmented, field_info.name) = segment;
        }
        std.log.debug("Parsed Request Line: method={s[method]}, path={s[path]}, version={s[version]}", segmented);

        if (!std.mem.eql(u8, segmented.version, "HTTP/1.1")) return Error.UnsupportedHttpVersion;
        if (segmented.method.len > max_method_len) return Error.UnknownMethod;

        var method_buf: [max_method_len]u8 = undefined;
        const method_str = std.ascii.lowerString(&method_buf, segmented.method);
        const method = std.meta.stringToEnum(Method, method_str) orelse return Error.UnknownMethod;

        return .{ .method = method, .target = segmented.target };
    }
};

const Error = error{
    UnsupportedHttpVersion,
    UnknownMethod,
    MalformedRequest,
};

fn read_line(reader: anytype, buf: []u8) ![]u8 {
    var fbs = std.io.fixedBufferStream(buf);
    try reader.streamUntilDelimiter(fbs.writer(), '\r', fbs.buffer.len);
    const next_byte = try reader.readByte();
    if (next_byte != '\n') return Error.MalformedRequest;
    const output = fbs.getWritten();
    return output;
}
