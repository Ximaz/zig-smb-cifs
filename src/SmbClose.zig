const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");
const SmbMessageWriter = @import("SmbMessageWriter.zig");
const SmbMessageReader = @import("SmbMessageReader.zig");

pub const SmbCloseRequest = struct {
    uid: SmbMessage.UID,

    fid: SmbMessage.FID,
    last_time_modified: SmbMessage.UTIME,

    pub fn deserialize(request: *const SmbMessage) !SmbCloseRequest {
        var smb_message_reader = SmbMessageReader.init(request);

        const uid: SmbMessage.UID = request.header.uid;

        const fid: SmbMessage.FID = try smb_message_reader.readParameter(SmbMessage.FID);
        const last_time_modified: SmbMessage.UTIME = try smb_message_reader.readParameter(SmbMessage.UTIME);

        return .{ .uid = uid, .fid = fid, .last_time_modified = last_time_modified };
    }

    pub fn serialize(allocator: std.mem.Allocator, request: *const SmbCloseRequest) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_CLOSE,
            .uid = request.uid,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 3);
        try smb_message_writer.writeParameter(SmbMessage.FID, request.fid);
        try smb_message_writer.writeParameter(SmbMessage.UTIME, request.last_time_modified);

        return smb_message_writer.build();
    }
};

pub const SmbCloseResponse = struct {
    error_status: SmbMessage.SmbError,

    pub fn deserialize(response: *const SmbMessage) SmbCloseResponse {
        return .{ .error_status = response.header.status };
    }

    pub fn serialize(response: *const SmbCloseResponse) SmbMessage {
        return .{ .header = .{
            .command = .SMB_COM_CLOSE,
            .status = response.error_status,
        } };
    }
};

test "SmbCloseRequest" {
    const request = SmbCloseRequest{ .fid = 5, .uid = 10, .last_time_modified = 0xFFAABB00 };
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var message = try SmbCloseRequest.serialize(allocator, &request);
    defer message.deinit(allocator);

    const requestMessage = try SmbCloseRequest.deserialize(&message);
    try std.testing.expect(request.uid == requestMessage.uid);
    try std.testing.expect(requestMessage.uid == 10);
    try std.testing.expect(request.fid == requestMessage.fid);
    try std.testing.expect(requestMessage.fid == 5);
    try std.testing.expect(request.last_time_modified == requestMessage.last_time_modified);
    try std.testing.expect(requestMessage.last_time_modified == 0xFFAABB00);
}

test "SmbCloseReponse" {
    const response = SmbCloseResponse{ .error_status = .{
        .error_class = .ERRCLS_DOS,
        .error_code = .ERRDOS_BAD_FID,
    } };

    const message = SmbCloseResponse.serialize(&response);

    const responseMessage = SmbCloseResponse.deserialize(&message);
    try std.testing.expect(response.error_status.error_class == responseMessage.error_status.error_class);
    try std.testing.expect(response.error_status.error_code == responseMessage.error_status.error_code);
}
