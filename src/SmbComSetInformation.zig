const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");
const SmbMessageWriter = @import("SmbMessageWriter.zig");
const SmbMessageReader = @import("SmbMessageReader.zig");

pub const SmbComSetInformationRequest = struct {
    tid: SmbMessage.TID,
    uid: SmbMessage.UID,

    file_attributes: u16,
    last_write_time: SmbMessage.UTIME,
    _reserved: [5]u16 = .{ 0, 0, 0, 0, 0 },

    filename: []u8,

    pub fn deserialize(request: *const SmbMessage, allocator: std.mem.Allocator) !SmbComSetInformationRequest {
        var smb_message_reader = SmbMessageReader.init(request);

        const tid: SmbMessage.TID = request.header.tid;
        const uid: SmbMessage.UID = request.header.uid;

        const file_attributes: u16 = try smb_message_reader.readParameter(u16);
        const last_write_time: SmbMessage.UTIME = try smb_message_reader.readParameter(SmbMessage.UTIME);
        var _reserved: [5]u16 = .{ 0, 0, 0, 0, 0 };
        inline for (0..5) |index| {
            _reserved[index] = try smb_message_reader.readParameter(u16);
        }

        const filename = try smb_message_reader.readData(allocator);

        return .{ .tid = tid, .uid = uid, .file_attributes = file_attributes, .last_write_time = last_write_time, ._reserved = _reserved, .filename = filename };
    }

    pub fn serialize(allocator: std.mem.Allocator, request: *const SmbComSetInformationRequest) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_SET_INFORMATION,
            .tid = request.tid,
            .uid = request.uid,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 8);
        try smb_message_writer.writeParameter(u16, request.file_attributes);
        try smb_message_writer.writeParameter(SmbMessage.UTIME, request.last_write_time);
        inline for (0..5) |_| {
            try smb_message_writer.writeParameter(u16, 0x0000);
        }

        try smb_message_writer.reserveData(allocator, @intCast(1 + request.filename.len + 1));
        try smb_message_writer.writeData(SmbMessage.SmbDataBufferFormatCode.SMB_STRING, request.filename);

        return smb_message_writer.build();
    }
};

pub const SmbComSetInforationResponse = struct {
    error_status: SmbMessage.SmbError,

    pub fn deserialize(response: *const SmbMessage) SmbComSetInforationResponse {
        return .{ .error_status = response.header.status };
    }

    pub fn serialize(response: *const SmbComSetInforationResponse) SmbMessage {
        return .{ .header = .{
            .command = .SMB_COM_SET_INFORMATION,
            .status = response.error_status,
        } };
    }
};

test "SmbComSetInformationRequest" {
    // Here we're doing a constCast as the filename is known at compile time
    // but the SmbComSetInformationRequest would only happen with runtime
    // values as its purpose is to craft a request, involving compiletime
    // unknown values.
    const filename: []u8 = @constCast("Hello.txt");
    const request = SmbComSetInformationRequest{ .tid = 10, .uid = 5, .file_attributes = @intFromEnum(SmbMessage.SmbFileAttributes.SMB_FILE_ATTRIBUTE_NORMAL), .last_write_time = 0xFFAABB00, .filename = filename };
    const allocator = std.testing.allocator;

    var message = try SmbComSetInformationRequest.serialize(allocator, &request);
    defer message.deinit(allocator);
    try std.testing.expect(message.header.command == .SMB_COM_SET_INFORMATION);
    try std.testing.expect(message.header.tid == 10);
    try std.testing.expect(message.header.uid == 5);
    try std.testing.expect(message.parameters.words_count == 8);
    try std.testing.expect(message.data.bytes_count == 11);

    const requestMessage = try SmbComSetInformationRequest.deserialize(&message, allocator);
    defer allocator.free(requestMessage.filename);

    try std.testing.expect(request.tid == requestMessage.tid);
    try std.testing.expect(request.tid == 10);
    try std.testing.expect(request.uid == requestMessage.uid);
    try std.testing.expect(request.uid == 5);
    try std.testing.expect(request.file_attributes == requestMessage.file_attributes);
    try std.testing.expect(request.file_attributes == @intFromEnum(SmbMessage.SmbFileAttributes.SMB_FILE_ATTRIBUTE_NORMAL));
    try std.testing.expect(request.last_write_time == requestMessage.last_write_time);
    try std.testing.expect(request.last_write_time == 0xFFAABB00);
    try std.testing.expect(std.mem.eql(u16, request._reserved[0..5], requestMessage._reserved[0..5]));
    try std.testing.expect(std.mem.eql(u16, request._reserved[0..5], ([5]u16{ 0, 0, 0, 0, 0 })[0..5]));
    try std.testing.expect(std.mem.eql(u8, request.filename, requestMessage.filename));
    try std.testing.expect(std.mem.eql(u8, request.filename, filename));
}

test "SmbComSetInformationReponse" {
    const response = SmbComSetInforationResponse{ .error_status = .{ .error_class = .ERRCLS_DOS, .error_code = .ERRDOS_BAD_FID } };

    var message = SmbComSetInforationResponse.serialize(&response);
    try std.testing.expect(message.header.command == .SMB_COM_SET_INFORMATION);
    try std.testing.expect(message.header.tid == 0x0000);
    try std.testing.expect(message.header.uid == 0x0000);
    try std.testing.expect(message.parameters.words_count == 0);
    try std.testing.expect(message.data.bytes_count == 0);

    const responseMessage = SmbComSetInforationResponse.deserialize(&message);
    try std.testing.expect(response.error_status.error_class == responseMessage.error_status.error_class);
    try std.testing.expect(response.error_status.error_code == responseMessage.error_status.error_code);
}
