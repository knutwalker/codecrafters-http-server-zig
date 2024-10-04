pub fn main() !void {
    var alloc = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (alloc.deinit() != .ok) @panic("memory leak");

    const address = try net.Address.resolveIp("127.0.0.1", 4221);
    var listener = try address.listen(.{
        .reuse_address = true,
    });
    defer listener.deinit();


    while (true) {
        const ally = alloc.allocator();

        const connection = try listener.accept();
        log.debug("client connected from {}!", .{connection.address});

        const res = try handle_request(ally, connection.stream.reader());
        defer res.deinit(ally);
        log.debug("Response: {}", .{res.status});

        try res.send(connection.stream.writer());
        connection.stream.close();
    }
}

fn handle_request(alloc: Alloc, reader: anytype) !Response {
    const full_req = Request.parse(alloc, reader) catch |err| switch (err) {
        error.EndOfStream, Error.MalformedRequest => return .{ .status = .@"Bad Request" },
        Error.UnsupportedHttpVersion => return .{ .status = .@"HTTP Version Not Supported" },
        Error.UnknownMethod => return .{ .status = .@"Method Not Allowed" },
        else => return .{ .status = .@"Internal Server Error" },
    };
    defer full_req.deinit(alloc);

    const req = full_req.line;

    if (req.method != .get and req.method != .head) return .{ .status = .@"Method Not Allowed" };

    if (mem.eql(u8, req.target, "/")) return req.respond(.OK);

    if (mem.startsWith(u8, req.target, "/echo/")) {
        return req.respond_with(alloc, .OK, req.target[6..]);
    }

    return req.respond(.@"Not Found");
}

const Response = struct {
    status: Status,
    method: RequestLine.Method = .get,
    body: ?[]const u8 = null,

    const Self = @This();

    fn deinit(self: Self, alloc: Alloc) void {
        if (self.body) |body| {
            alloc.free(body);
        }
    }

    fn send(self: Self, writer: anytype) !void {
        try writer.print("HTTP/1.1 {}\r\n", .{self.status});

        if (self.status == .@"Method Not Allowed") {
            try writer.print("Allow: GET, HEAD\r\n", .{});
        }

        if (!(
        // A server MUST NOT send a Content-Length header field in any response with a status code of 1xx or 204
            @intFromEnum(self.status) / 100 == 1 or @intFromEnum(self.status) == 204
        // A server MUST NOT send a Content-Length header field in any 2xx response to a CONNECT request
        or (self.method == .connect and @intFromEnum(self.status) / 1 == 2))) {
            const len = if (self.body) |body| body.len else 0;
            try writer.print("Content-Length: {}\r\n", .{len});
        }

        if (self.body) |_| {
            try writer.print("Content-Type: text/plain\r\n", .{});
        }
        try writer.print("\r\n", .{});

        if (self.method != .head) {
            if (self.body) |body| {
                try writer.writeAll(body);
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
};

const Request = struct {
    line: RequestLine,
    headers: Headers,
    body: ?[]const u8 = null,

    const Self = @This();

    fn parse(alloc: Alloc, reader: anytype) !Self {
        const line = try RequestLine.parse(alloc, reader);
        errdefer line.deinit(alloc);

        const headers = try Headers.parse(alloc, reader);
        errdefer headers.deinit(alloc);

        const body_len = try headers.content_length();
        log.debug("Content-Length: {?d}", .{body_len});

        const body = if (body_len orelse 0 > 0) b: {
            const req_body = reader.readAllAlloc(alloc, body_len.?) catch |err| switch (err) {
                error.StreamTooLong => return Error.MalformedRequest,
                else => return err,
            };
            log.debug("Body: len={d} head={s}", .{ req_body.len, req_body[0..@min(42, req_body.len)] });
            break :b req_body;
        } else null;

        log.debug("Request: {}", .{line});
        return .{ .line = line, .headers = headers, .body = body };
    }

    fn deinit(self: @This(), alloc: Alloc) void {
        self.line.deinit(alloc);
        self.headers.deinit(alloc);
        if (self.body) |body| alloc.free(body);
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
            const segment = segments.next() orelse return Error.MalformedRequest;
            @field(segmented, field_info.name) = segment;
        }
        log.debug("Parsed Request Line: method={s[method]}, path={s[path]}, version={s[version]}", segmented);

        if (!mem.eql(u8, segmented.version, "HTTP/1.1")) return Error.UnsupportedHttpVersion;
        if (segmented.method.len > max_method_len) return Error.UnknownMethod;

        var method_buf: [max_method_len]u8 = undefined;
        const method_str = std.ascii.lowerString(&method_buf, segmented.method);
        const method = std.meta.stringToEnum(Method, method_str) orelse return Error.UnknownMethod;

        const target = try alloc.dupe(u8, segmented.target);

        return .{ .method = method, .target = target };
    }

    fn respond(self: @This(), status: Response.Status) Response {
        return .{ .status = status, .method = self.method };
    }

    fn respond_with(req: @This(), alloc: Alloc, status: Response.Status, body: []const u8) !Response {
        const owned_body = try alloc.dupe(u8, body);
        return .{ .status = status, .method = req.method, .body = owned_body };
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
            if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
        }
        return null;
    }

    fn contains(self: *const Self, name: []const u8) bool {
        return self.get(name) != null;
    }

    fn content_length(self: *const Self) Error!?usize {
        if (self.contains("transfer-encoding")) return null;
        const header = self.get("content-length") orelse return null;
        return std.fmt.parseInt(usize, header, 10) catch return Error.MalformedRequest;
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

    fn parse_next(alloc: Alloc, reader: anytype) !?Header {
        const line = try read_line(reader);
        log.debug("Header Line: {s}", .{line});

        if (line.len == 0) return null;

        var header: Header = undefined;

        var segments = mem.splitScalar(u8, line, ':');
        inline for (std.meta.fields(Header)) |field_info| {
            const segment = segments.next() orelse return Error.MalformedRequest;
            @field(header, field_info.name) = mem.trimLeft(u8, segment, &std.ascii.whitespace);
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
    if (next_byte != '\n') return Error.MalformedRequest;

    return fbs.getWritten();
}

const Error = error{
    UnsupportedHttpVersion,
    UnknownMethod,
    MalformedRequest,
};

const std = @import("std");
const Alloc = mem.Allocator;
const log = std.log;
const mem = std.mem;
const net = std.net;
