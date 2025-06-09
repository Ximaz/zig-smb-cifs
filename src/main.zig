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

pub fn main() !void {}
