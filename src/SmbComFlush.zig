const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");
const SmbMessageWriter = @import("SmbMessageWriter.zig");
const SmbMessageReader = @import("SmbMessageReader.zig");

pub const SmbComFlushRequest = struct {
    uid: SmbMessage.UID,

    fid: SmbMessage.FID,

    pub fn deserialize(request: *const SmbMessage) !SmbComFlushRequest {
        var smb_message_reader = SmbMessageReader.init(request);

        const uid: SmbMessage.UID = request.header.uid;

        const fid: SmbMessage.FID = try smb_message_reader.readParameter(SmbMessage.FID);

        return .{ .uid = uid, .fid = fid };
    }

    pub fn serialize(allocator: std.mem.Allocator, request: *const SmbComFlushRequest) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_FLUSH,
            .uid = request.uid,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 1);
        try smb_message_writer.writeParameter(SmbMessage.FID, request.fid);

        return smb_message_writer.build();
    }
};

pub const SmbComFlushResponse = struct {
    error_status: SmbMessage.SmbError,

    pub fn deserialize(response: *const SmbMessage) SmbComFlushResponse {
        return .{ .error_status = response.header.status };
    }

    pub fn serialize(response: *const SmbComFlushResponse) SmbMessage {
        return .{ .header = .{
            .command = .SMB_COM_FLUSH,
            .status = response.error_status,
        } };
    }
};

test "SmbComFlushRequest" {
    const request = SmbComFlushRequest{ .uid = 10, .fid = 5 };
    const allocator = std.testing.allocator;

    var message = try SmbComFlushRequest.serialize(allocator, &request);
    defer message.deinit(allocator);
    try std.testing.expect(message.header.command == .SMB_COM_FLUSH);
    try std.testing.expect(message.header.uid == 10);
    try std.testing.expect(message.parameters.words_count == 1);
    try std.testing.expect(message.data.bytes_count == 0);

    const requestMessage = try SmbComFlushRequest.deserialize(&message);
    try std.testing.expect(request.uid == requestMessage.uid);
    try std.testing.expect(requestMessage.uid == 10);
    try std.testing.expect(request.fid == requestMessage.fid);
    try std.testing.expect(requestMessage.fid == 5);
}

test "SmbComFlushReponse" {
    const response = SmbComFlushResponse{ .error_status = .{
        .error_class = .ERRCLS_DOS,
        .error_code = .ERRDOS_BAD_FID,
    } };

    const message = SmbComFlushResponse.serialize(&response);
    try std.testing.expect(message.header.command == .SMB_COM_FLUSH);
    try std.testing.expect(message.header.uid == 0x0000);
    try std.testing.expect(message.parameters.words_count == 0);
    try std.testing.expect(message.data.bytes_count == 0);

    const responseMessage = SmbComFlushResponse.deserialize(&message);
    try std.testing.expect(response.error_status.error_class == responseMessage.error_status.error_class);
    try std.testing.expect(response.error_status.error_code == responseMessage.error_status.error_code);
}
