const std = @import("std");
const lib = @import("zig_smb_cifs_lib");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var message = try lib.smb_cifs.SmbMessage.create(allocator);
    defer _ = message.destroy();

    message.header = .{ .command = lib.smb_cifs.SmbCom.SMB_COM_COPY, .flags = lib.smb_cifs.SmbFlags.SMB_FLAGS_BUF_AVAILABLE, .flags2 = lib.smb_cifs.SmbFlags2.SMB_FLAGS2_DFS, .mid = 0, .pid_high = 0, .pid_low = 0, .reserved = 0, .security_features = .{ 0, 0, 0, 0, 0, 0, 0, 0 }, .status = 0, .tid = 0, .uid = 0 };
    std.debug.print("{d} * 2 + {d}\n", .{ message.parameters.words_count, message.data.bytes_count });
    const serializedBytes = try message.serialize(allocator);
    defer allocator.free(serializedBytes);
    std.debug.print("{b}\n", .{serializedBytes});
}
