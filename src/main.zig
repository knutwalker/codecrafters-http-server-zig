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
    try stdout.print("client connected from {}!", .{connection.address});

    try connection.stream.writeAll("HTTP/1.1 200 OK\r\n\r\n");
}
