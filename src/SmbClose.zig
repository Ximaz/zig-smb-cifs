const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");

pub const SmbCloseRequest = struct {
    uid: SmbMessage.UID,
    fid: SmbMessage.FID,
    last_time_modified: SmbMessage.UTIME,

    pub fn deserialize(allocator: std.mem.Allocator, request: SmbCloseRequest) !*SmbMessage {
        const smbMessage = try SmbMessage.create(allocator);
        errdefer smbMessage.destroy();

        smbMessage.header.uid = request.uid;
        smbMessage.header.command = .SMB_COM_CLOSE;

        try smbMessage.reserveParameters(3);
        smbMessage.parameters.words[0] = @as(u16, @intCast(request.fid));
        std.mem.writeInt(SmbMessage.UTIME, @as(*[4]u8, @alignCast(@ptrCast(&smbMessage.parameters.words[1]))), request.last_time_modified, .little);

        return smbMessage;
    }

    pub fn serialize(request: *const SmbMessage) SmbCloseRequest {
        return .{ .uid = request.header.uid, .fid = @intCast(request.parameters.words[0]), .last_time_modified = std.mem.readInt(SmbMessage.UTIME, @as(*[4]u8, @alignCast(@ptrCast(&request.parameters.words[1]))), .little) };
    }
};

pub const SmbCloseResponse = struct {
    error_status: SmbMessage.SmbError,

    pub fn create(allocator: std.mem.Allocator, response: SmbCloseResponse) !*SmbMessage {
        const smbMessage = try SmbMessage.create(allocator);
        errdefer smbMessage.destroy();

        smbMessage.header.command = .SMB_COM_CLOSE;
        smbMessage.header.status = response.error_status;

        return smbMessage;
    }
};

test "SmbCloseRequest.create" {
    const request = SmbCloseRequest{ .fid = 5, .uid = 10, .last_time_modified = 0xFFAABB00 };
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const message = try SmbCloseRequest.deserialize(allocator, request);
    defer message.destroy();

    const requestMessage = SmbCloseRequest.serialize(message);
    try std.testing.expect(request.uid == requestMessage.uid);
    try std.testing.expect(request.fid == requestMessage.fid);
    try std.testing.expect(request.last_time_modified == requestMessage.last_time_modified);
}
