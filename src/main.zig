const std = @import("std");
const lib = @import("zig_smb_cifs_lib");

fn readFile(filename: []const u8, output: []u8) !usize {
    const cwd = std.fs.cwd();
    var output_dir = try cwd.openDir(".", .{});
    defer output_dir.close();

    const file = try output_dir.openFile(filename, .{ .mode = .read_only });
    defer file.close();

    return try file.read(output);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var buffer: [1024]u8 = undefined;
    const bufferLength = try readFile("resp.bin", buffer[0..]);
    const rawBytes = buffer[0..bufferLength];
    std.debug.print("{any}\n", .{rawBytes});

    const message = try lib.smb_cifs.SmbMessage.create(allocator);
    defer message.destroy();

    try message.deserialize(rawBytes);

    std.debug.print("Header: {any}\n", .{message.*.header});
    std.debug.print("Parameters: {any}\n", .{message.*.parameters});
    std.debug.print("Data: {any}\n", .{message.*.data.bytes[0..message.*.data.bytes_count]});
    message.debugHeader();
}
