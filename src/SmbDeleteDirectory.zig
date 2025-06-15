const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");
const SmbMessageWriter = @import("SmbMessageWriter.zig");
const SmbMessageReader = @import("SmbMessageReader.zig");

pub const SmbDeleteRequest = struct {
    /// Whether to set the SMB_FLAGS2_LONG_NAMES flag.
    long_names: bool,
    tid: SmbMessage.TID,
    uid: SmbMessage.UID,

    search_attributes: SmbMessage.SmbFileAttributes,

    filename: []u8,

    pub fn deserialize(request: *const SmbMessage, allocator: std.mem.Allocator) !SmbDeleteRequest {
        var smb_message_reader = SmbMessageReader.init(request);

        const long_names: bool = request.header.flags2 == .SMB_FLAGS2_LONG_NAMES;
        const tid: SmbMessage.TID = request.header.tid;
        const uid: SmbMessage.UID = request.header.uid;

        const search_attributes: SmbMessage.SmbFileAttributes = @enumFromInt(try smb_message_reader.readParameter(u16));

        const filename = try smb_message_reader.readData(allocator);

        return .{ .long_names = long_names, .tid = tid, .uid = uid, .search_attributes = search_attributes, .filename = filename };
    }

    pub fn serialize(allocator: std.mem.Allocator, request: *const SmbDeleteRequest) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_DELETE,
            .flags2 = if (request.long_names) .SMB_FLAGS2_LONG_NAMES else .SMB_FLAGS2_NONE,
            .tid = request.tid,
            .uid = request.uid,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 1);
        try smb_message_writer.writeParameter(u16, @intFromEnum(request.search_attributes));

        const data_bytes_count: u16 = @as(u16, @intCast(1 + request.filename.len + 1));
        try smb_message_writer.reserveData(allocator, data_bytes_count);
        try smb_message_writer.writeData(SmbMessage.SmbDataBufferFormatCode.SMB_STRING, request.filename);

        return smb_message_writer.build();
    }
};

pub const SmbDeleteResponse = struct {
    error_status: SmbMessage.SmbError,

    pub fn deserialize(response: *const SmbMessage) SmbDeleteResponse {
        return .{
            .error_status = response.header.status,
        };
    }

    pub fn serialize(response: *const SmbDeleteResponse) SmbMessage {
        return .{ .header = .{
            .command = .SMB_COM_DELETE,
            .status = response.error_status,
        } };
    }
};

test "SmbDeleteRequest" {
    // Here we're doing a constCast as the filename is known at compile time
    // but the SmbDeleteRequest would only happen with runtime values as its
    // purpose is to craft a request, involving compiletime unknown values.
    const filename: []u8 = @constCast("Hello.txt");
    const request = SmbDeleteRequest{ .long_names = true, .tid = 10, .uid = 5, .search_attributes = .SMB_FILE_ATTRIBUTE_NORMAL, .filename = filename };
    const allocator = std.testing.allocator;

    var message = try SmbDeleteRequest.serialize(allocator, &request);
    defer message.deinit(allocator);
    try std.testing.expect(message.header.command == .SMB_COM_DELETE);
    try std.testing.expect(message.header.flags2 == .SMB_FLAGS2_LONG_NAMES);
    try std.testing.expect(message.header.tid == 10);
    try std.testing.expect(message.header.uid == 5);
    try std.testing.expect(message.parameters.words_count == 1);
    try std.testing.expect(message.data.bytes_count == 11);

    const requestMessage = try SmbDeleteRequest.deserialize(&message, allocator);
    defer allocator.free(requestMessage.filename);

    try std.testing.expect(request.long_names == requestMessage.long_names);
    try std.testing.expect(request.tid == requestMessage.tid);
    try std.testing.expect(request.uid == requestMessage.uid);
    try std.testing.expect(request.search_attributes == requestMessage.search_attributes);
    try std.testing.expect(std.mem.eql(u8, request.filename, requestMessage.filename));
}

test "SmbDeleteReponse" {
    const response = SmbDeleteResponse{ .error_status = .{ .error_class = .ERRCLS_DOS, .error_code = .ERRDOS_BAD_FID } };

    const message = SmbDeleteResponse.serialize(&response);

    try std.testing.expect(message.header.command == .SMB_COM_DELETE);
    try std.testing.expect(message.header.tid == 0x0000);
    try std.testing.expect(message.header.uid == 0x0000);
    try std.testing.expect(message.parameters.words_count == 0);
    try std.testing.expect(message.data.bytes_count == 0);

    const responseMessage = SmbDeleteResponse.deserialize(&message);
    try std.testing.expect(response.error_status.error_class == responseMessage.error_status.error_class);
    try std.testing.expect(response.error_status.error_code == responseMessage.error_status.error_code);
}
