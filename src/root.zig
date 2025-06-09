//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");
const testing = std.testing;
pub const SmbMessage = @import("SmbMessage.zig");

test "SmbMessage.deserialize" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const bytes = [_]u8{ 255, 83, 77, 66, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 6, 0, 4, 102, 105, 108, 101, 0 };

    const message = try SmbMessage.create(allocator);
    defer message.destroy();

    try message.deserialize(&bytes);
    try std.testing.expect(std.mem.eql(u8, &message.header.protocol, &[4]u8{ 255, 83, 77, 66 }));
    try std.testing.expect(message.header.command == .SMB_COM_CREATE);
    try std.testing.expect(message.header.status == 0);
    try std.testing.expect(message.header.flags == .SMB_FLAGS_NONE);
    try std.testing.expect(message.header.flags2 == .SMB_FLAGS2_NONE);
    try std.testing.expect(message.header.pid_high == 0);
    try std.testing.expect(std.mem.eql(u8, &message.header.security_features, &[8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }));
    try std.testing.expect(message.header.reserved == 0);
    try std.testing.expect(message.header.tid == 2);
    try std.testing.expect(message.header.pid_low == 0);
    try std.testing.expect(message.header.uid == 1);
    try std.testing.expect(message.header.mid == 0);
}
