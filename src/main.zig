const std = @import("std");
const lib = @import("zig_smb_cifs_lib");

fn readFile(filename: []const u8, output: [*]u8) !void {
const cwd = std.fs.cwd();
    var output_dir = try cwd.openDir(".", .{});
    defer output_dir.close();

    const file = try output_dir.openFile(filename, .{});
    defer file.close();

    var content = [_]u8{'A'} ** 64;
    // this should print out : `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
    std.debug.print("{s}\n", .{content});

    // okay, seems like a threat of violence is not the answer in this case
    // can you go here to find a way to read the content?
    // https://ziglang.org/documentation/master/std/#std.fs.File
    // hint: you might find two answers that are both valid in this case
    const bytes_read = try file.read(&content);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const rawBytes: []u8 = "";
    const message = try lib.smb_cifs.SmbMessage.deserialize(allocator, rawBytes);
    defer _ = message.destroy();

    std.debug.print("{any}\n", .{message});
}
