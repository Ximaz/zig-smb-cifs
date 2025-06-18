const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");
const SmbMessageWriter = @import("SmbMessageWriter.zig");
const SmbMessageReader = @import("SmbMessageReader.zig");

pub const SmbComCreateDirectoryRequest = struct {
    tid: SmbMessage.TID,
    uid: SmbMessage.UID,

    pathname: []u8,

    pub fn deserialize(request: *const SmbMessage, allocator: std.mem.Allocator) !SmbComCreateDirectoryRequest {
        var smb_message_reader = SmbMessageReader.init(request);

        const tid: SmbMessage.TID = request.header.tid;
        const uid: SmbMessage.UID = request.header.uid;

        const pathname: []u8 = try smb_message_reader.readData(allocator);

        return .{ .tid = tid, .uid = uid, .pathname = pathname };
    }

    pub fn serialize(allocator: std.mem.Allocator, request: *const SmbComCreateDirectoryRequest) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_CREATE_DIRECTORY,
            .tid = request.tid,
            .uid = request.uid,
        });
        errdefer smb_message_writer.deinit(allocator);

        const data_bytes_count: u16 = @as(u16, @intCast(1 + request.pathname.len + 1));
        try smb_message_writer.reserveData(allocator, data_bytes_count);
        try smb_message_writer.writeData(SmbMessage.SmbDataBufferFormatCode.SMB_STRING, request.pathname);

        return smb_message_writer.build();
    }
};

pub const SmbComCreateDirectoryResponse = struct {
    error_status: SmbMessage.SmbError,

    pub fn deserialize(response: *const SmbMessage) SmbComCreateDirectoryResponse {
        return .{ .error_status = response.header.status };
    }

    pub fn serialize(response: *const SmbComCreateDirectoryResponse) SmbMessage {
        return .{ .header = .{
            .command = .SMB_COM_CREATE_DIRECTORY,
            .status = response.error_status,
        } };
    }
};

test "SmbComCreateDirectoryRequest" {
    // Here we're doing a constCast as the pathname is known at compile time
    // but the SmbComCreateDirectoryRequest would only happen with runtime values as its
    // purpose is to craft a request, involving compiletime unknown values.
    const pathname: []u8 = @constCast("my_dir");
    const request = SmbComCreateDirectoryRequest{ .tid = 10, .uid = 5, .pathname = pathname };
    const allocator = std.testing.allocator;

    var message = try SmbComCreateDirectoryRequest.serialize(allocator, &request);
    defer message.deinit(allocator);
    try std.testing.expect(message.header.command == .SMB_COM_CREATE_DIRECTORY);
    try std.testing.expect(message.header.tid == 10);
    try std.testing.expect(message.header.uid == 5);
    try std.testing.expect(message.parameters.words_count == 0);
    try std.testing.expect(message.data.bytes_count == 8);

    const requestMessage = try SmbComCreateDirectoryRequest.deserialize(&message, allocator);
    defer allocator.free(requestMessage.pathname);

    try std.testing.expect(request.uid == requestMessage.uid);
    try std.testing.expect(request.tid == requestMessage.tid);
    try std.testing.expect(std.mem.eql(u8, request.pathname, requestMessage.pathname));
}

test "SmbComCreateDirectoryReponse" {
    const response = SmbComCreateDirectoryResponse{ .error_status = .{ .error_class = .ERRCLS_DOS, .error_code = .ERRDOS_BAD_FID } };

    const message = SmbComCreateDirectoryResponse.serialize(&response);
    try std.testing.expect(message.header.command == .SMB_COM_CREATE_DIRECTORY);
    try std.testing.expect(message.header.tid == 0x0000);
    try std.testing.expect(message.header.uid == 0x0000);
    try std.testing.expect(message.parameters.words_count == 0);
    try std.testing.expect(message.data.bytes_count == 0);

    const responseMessage = SmbComCreateDirectoryResponse.deserialize(&message);
    try std.testing.expect(response.error_status.error_class == responseMessage.error_status.error_class);
    try std.testing.expect(response.error_status.error_code == responseMessage.error_status.error_code);
}
