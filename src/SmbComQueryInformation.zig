const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");
const SmbMessageWriter = @import("SmbMessageWriter.zig");
const SmbMessageReader = @import("SmbMessageReader.zig");

pub const SmbComQueryInformationRequest = struct {
    tid: SmbMessage.TID,
    uid: SmbMessage.UID,

    filename: []u8,

    pub fn deserialize(request: *const SmbMessage, allocator: std.mem.Allocator) !SmbComQueryInformationRequest {
        var smb_message_reader = SmbMessageReader.init(request);

        const tid: SmbMessage.TID = request.header.tid;
        const uid: SmbMessage.UID = request.header.uid;

        const filename: []u8 = try smb_message_reader.readData(allocator);

        return .{ .tid = tid, .uid = uid, .filename = filename };
    }

    pub fn serialize(allocator: std.mem.Allocator, request: *const SmbComQueryInformationRequest) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_QUERY_INFORMATION,
            .tid = request.tid,
            .uid = request.uid,
        });
        errdefer smb_message_writer.deinit(allocator);

        const data_bytes_count: u16 = @as(u16, @intCast(1 + request.filename.len + 1));
        try smb_message_writer.reserveData(allocator, data_bytes_count);
        try smb_message_writer.writeData(SmbMessage.SmbDataBufferFormatCode.SMB_STRING, request.filename);

        return smb_message_writer.build();
    }
};

pub const SmbComQueryInformationResponse = struct {
    error_status: SmbMessage.SmbError,

    file_attributes: u16,
    last_write_time: SmbMessage.UTIME,
    file_size: u32,
    _reserved: [5]u16,

    pub fn deserialize(response: *const SmbMessage) !SmbComQueryInformationResponse {
        var smb_message_reader = SmbMessageReader.init(response);

        const file_attributes: u16 = try smb_message_reader.readParameter(u16);
        const last_write_time: SmbMessage.UTIME = try smb_message_reader.readParameter(SmbMessage.UTIME);
        const file_size: u32 = try smb_message_reader.readParameter(u32);
        var _reserved: [5]u16 = .{ 0, 0, 0, 0, 0 };
        inline for (0..5) |index| {
            _reserved[index] = try smb_message_reader.readParameter(u16);
        }

        return .{
            .error_status = response.header.status,
            .file_attributes = file_attributes,
            .last_write_time = last_write_time,
            .file_size = file_size,
            ._reserved = _reserved,
        };
    }

    pub fn serialize(allocator: std.mem.Allocator, response: *const SmbComQueryInformationResponse) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_QUERY_INFORMATION,
            .status = response.error_status,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 10);
        try smb_message_writer.writeParameter(u16, response.file_attributes);
        try smb_message_writer.writeParameter(SmbMessage.UTIME, response.last_write_time);
        try smb_message_writer.writeParameter(u32, response.file_size);
        inline for (0..5) |_| {
            try smb_message_writer.writeParameter(u16, 0x0000);
        }

        return smb_message_writer.build();
    }
};

test "SmbComQueryInformationRequest" {
    // Here we're doing a constCast as the filename is known at compile time
    // but the SmbComQueryInformationRequest would only happen with runtime
    // values as its purpose is to craft a request, involving compiletime
    // unknown values.
    const filename: []u8 = @constCast("Hello.txt");
    const request = SmbComQueryInformationRequest{ .tid = 10, .uid = 5, .filename = filename };
    const allocator = std.testing.allocator;

    var message = try SmbComQueryInformationRequest.serialize(allocator, &request);
    defer message.deinit(allocator);
    try std.testing.expect(message.header.command == .SMB_COM_QUERY_INFORMATION);
    try std.testing.expect(message.header.tid == 10);
    try std.testing.expect(message.header.uid == 5);
    try std.testing.expect(message.parameters.words_count == 0);
    try std.testing.expect(message.data.bytes_count == 11);

    const requestMessage = try SmbComQueryInformationRequest.deserialize(&message, allocator);
    defer allocator.free(requestMessage.filename);

    try std.testing.expect(request.tid == requestMessage.tid);
    try std.testing.expect(request.uid == requestMessage.uid);
    try std.testing.expect(std.mem.eql(u8, request.filename, requestMessage.filename));
}

test "SmbComQueryInformationReponse" {
    const response = SmbComQueryInformationResponse{ .error_status = .{ .error_class = .ERRCLS_DOS, .error_code = .ERRDOS_BAD_FID }, .file_attributes = 0 | (@intFromEnum(SmbMessage.SmbFileAttributes.SMB_FILE_ATTRIBUTE_NORMAL)), .file_size = 0xFFFFFFFE, .last_write_time = 0xFF00BBCC, ._reserved = .{ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 } };
    const allocator = std.testing.allocator;

    var message = try SmbComQueryInformationResponse.serialize(allocator, &response);
    defer message.deinit(allocator);
    try std.testing.expect(message.header.command == .SMB_COM_QUERY_INFORMATION);
    try std.testing.expect(message.header.tid == 0x0000);
    try std.testing.expect(message.header.uid == 0x0000);
    try std.testing.expect(message.parameters.words_count == 10);
    try std.testing.expect(message.data.bytes_count == 0);

    const responseMessage = try SmbComQueryInformationResponse.deserialize(&message);
    try std.testing.expect(response.error_status.error_class == responseMessage.error_status.error_class);
    try std.testing.expect(response.error_status.error_code == responseMessage.error_status.error_code);
    try std.testing.expect(response.file_attributes == responseMessage.file_attributes);
    try std.testing.expect(response.last_write_time == responseMessage.last_write_time);
    try std.testing.expect(response.file_size == responseMessage.file_size);
    try std.testing.expect(std.mem.eql(u16, response._reserved[0..5], responseMessage._reserved[0..5]));
}
