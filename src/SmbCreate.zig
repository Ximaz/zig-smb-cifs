const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");
const SmbMessageWriter = @import("SmbMessageWriter.zig");
const SmbMessageReader = @import("SmbMessageReader.zig");

pub const SmbCreateRequest = struct {
    tid: SmbMessage.TID,
    uid: SmbMessage.UID,

    file_attributes: SmbMessage.SmbFileAttributes,
    creation_time: SmbMessage.UTIME,

    pathname: []u8,

    pub fn deserialize(request: *const SmbMessage, allocator: std.mem.Allocator) !SmbCreateRequest {
        var smb_message_reader = SmbMessageReader.init(request);

        const tid: SmbMessage.TID = request.header.tid;
        const uid: SmbMessage.UID = request.header.uid;

        const file_attributes: SmbMessage.SmbFileAttributes = @enumFromInt(try smb_message_reader.readParameter(u16));
        const creation_time: SmbMessage.UTIME = try smb_message_reader.readParameter(SmbMessage.UTIME);

        const pathname = try smb_message_reader.readData(allocator);

        return .{ .tid = tid, .uid = uid, .file_attributes = file_attributes, .creation_time = creation_time, .pathname = pathname };
    }

    pub fn serialize(allocator: std.mem.Allocator, request: *const SmbCreateRequest) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_CREATE,
            .tid = request.tid,
            .uid = request.uid,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 3);
        try smb_message_writer.writeParameter(u16, @intFromEnum(request.file_attributes));
        try smb_message_writer.writeParameter(SmbMessage.UTIME, request.creation_time);

        const data_bytes_count: u16 = @as(u16, @intCast(1 + request.pathname.len + 1));
        try smb_message_writer.reserveData(allocator, data_bytes_count);
        try smb_message_writer.writeData(SmbMessage.SmbDataBufferFormatCode.SMB_STRING, request.pathname);

        return smb_message_writer.build();
    }
};

pub const SmbCreateResponse = struct {
    error_status: SmbMessage.SmbError,

    fid: SmbMessage.FID,

    pub fn deserialize(response: *const SmbMessage) !SmbCreateResponse {
        var smb_message_reader = SmbMessageReader.init(response);

        const fid: i16 = try smb_message_reader.readParameter(i16);
        return .{ .error_status = response.header.status, .fid = fid };
    }

    pub fn serialize(allocator: std.mem.Allocator, response: *const SmbCreateResponse) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_CLOSE,
            .status = response.error_status,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 1);
        try smb_message_writer.writeParameter(u16, @as(u16, @intCast(response.fid)));

        return smb_message_writer.build();
    }
};

test "SmbCreateRequest" {
    // Here we're doing a constCast as the pathname is known at compile time
    // but the SmbCreateRequest would only happen with runtime values as its
    // purpose is to craft a request, involving compiletime unknown values.
    const pathname: []u8 = @constCast("Hello.txt");
    const request = SmbCreateRequest{ .uid = 5, .tid = 10, .pathname = pathname, .file_attributes = .SMB_FILE_ATTRIBUTE_NORMAL, .creation_time = 0xFFAABB00 };
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var message = try SmbCreateRequest.serialize(allocator, &request);
    defer message.deinit(allocator);
    try std.testing.expect(message.data.bytes_count == 11);
    try std.testing.expect(std.mem.eql(u8, message.data.bytes[0..11], &[11]u8{ 0x04, 'H', 'e', 'l', 'l', 'o', '.', 't', 'x', 't', 0 }));

    const requestMessage = try SmbCreateRequest.deserialize(&message, allocator);
    defer allocator.free(requestMessage.pathname);

    try std.testing.expect(request.uid == requestMessage.uid);
    try std.testing.expect(request.tid == requestMessage.tid);
    try std.testing.expect(std.mem.eql(u8, request.pathname, requestMessage.pathname));
    try std.testing.expect(request.file_attributes == requestMessage.file_attributes);
    try std.testing.expect(request.creation_time == requestMessage.creation_time);
}

test "SmbCloseReponse" {
    const response = SmbCreateResponse{ .error_status = .{ .error_class = .ERRCLS_DOS, .error_code = .ERRDOS_BAD_FID }, .fid = 100 };
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var message = try SmbCreateResponse.serialize(allocator, &response);
    defer message.deinit(allocator);

    const responseMessage = try SmbCreateResponse.deserialize(&message);
    try std.testing.expect(response.error_status.error_class == responseMessage.error_status.error_class);
    try std.testing.expect(response.error_status.error_code == responseMessage.error_status.error_code);
    try std.testing.expect(response.fid == responseMessage.fid);
}
