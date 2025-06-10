const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");

pub const SmbCloseRequest = struct {
    uid: SmbMessage.UID,
    fid: SmbMessage.FID,
    last_time_modified: SmbMessage.UTIME,

    pub fn deserialize(allocator: std.mem.Allocator, request: *const SmbCloseRequest) !SmbMessage {
        var smbMessage = SmbMessage{ .header = .{ .uid = request.uid, .command = .SMB_COM_CLOSE } };
        errdefer smbMessage.deinit(allocator);

        try smbMessage.reserveParameters(allocator, 3);
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

    pub fn deserialize(response: *const SmbCloseResponse) SmbMessage {
        return .{ .header = .{
            .command = .SMB_COM_CLOSE,
            .status = response.error_status,
        } };
    }

    pub fn serialize(response: *const SmbMessage) SmbCloseResponse {
        return .{ .error_status = response.header.status };
    }
};

test "SmbCloseRequest" {
    const request = SmbCloseRequest{ .fid = 5, .uid = 10, .last_time_modified = 0xFFAABB00 };
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var message = try SmbCloseRequest.deserialize(allocator, &request);
    defer message.deinit(allocator);

    const requestMessage = SmbCloseRequest.serialize(&message);
    try std.testing.expect(request.uid == requestMessage.uid);
    try std.testing.expect(request.fid == requestMessage.fid);
    try std.testing.expect(request.last_time_modified == requestMessage.last_time_modified);
}

test "SmbCloseReponse" {
    const response = SmbCloseResponse{ .error_status = .{
        .error_class = .ERRCLS_DOS,
        .error_code = .ERRDOS_BAD_FID,
    } };

    const message = SmbCloseResponse.deserialize(&response);

    const responseMessage = SmbCloseResponse.serialize(&message);
    try std.testing.expect(response.error_status.error_class == responseMessage.error_status.error_class);
    try std.testing.expect(response.error_status.error_code == responseMessage.error_status.error_code);
}
