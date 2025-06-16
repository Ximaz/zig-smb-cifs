const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");
const SmbMessageWriter = @import("SmbMessageWriter.zig");
const SmbMessageReader = @import("SmbMessageReader.zig");

pub const SmbReadRequest = struct {
    /// Whether to set the SMB_FLAGS2_READ_IF_EXECUTE flag.
    read_if_execute: bool,
    uid: SmbMessage.UID,

    fid: SmbMessage.FID,
    count_of_bytes_to_read: u16,
    read_offset_in_bytes: u32,
    estimate_of_remaning_bytes_to_be_read: u16,

    pub fn deserialize(request: *const SmbMessage) !SmbReadRequest {
        var smb_message_reader = SmbMessageReader.init(request);

        const read_if_execute: bool = (request.header.flags2 & @intFromEnum(SmbMessage.SmbFlags2.SMB_FLAGS2_READ_IF_EXECUTE)) == @intFromEnum(SmbMessage.SmbFlags2.SMB_FLAGS2_READ_IF_EXECUTE);
        const uid: SmbMessage.UID = request.header.uid;

        const fid: SmbMessage.FID = try smb_message_reader.readParameter(SmbMessage.FID);
        const count_of_bytes_to_read: u16 = try smb_message_reader.readParameter(u16);
        const read_offset_in_bytes: u32 = try smb_message_reader.readParameter(u32);
        const estimate_of_remaning_bytes_to_be_read: u16 = try smb_message_reader.readParameter(u16);

        return .{
            .read_if_execute = read_if_execute,
            .uid = uid,
            .fid = fid,
            .count_of_bytes_to_read = count_of_bytes_to_read,
            .read_offset_in_bytes = read_offset_in_bytes,
            .estimate_of_remaning_bytes_to_be_read = estimate_of_remaning_bytes_to_be_read,
        };
    }

    pub fn serialize(allocator: std.mem.Allocator, request: *const SmbReadRequest) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .flags2 = 0 | (@intFromEnum(SmbMessage.SmbFlags2.SMB_FLAGS2_READ_IF_EXECUTE) * @intFromBool(request.read_if_execute)),
            .command = .SMB_COM_READ,
            .uid = request.uid,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 5);
        try smb_message_writer.writeParameter(SmbMessage.FID, request.fid);
        try smb_message_writer.writeParameter(u16, request.count_of_bytes_to_read);
        try smb_message_writer.writeParameter(u32, request.read_offset_in_bytes);
        try smb_message_writer.writeParameter(u16, request.estimate_of_remaning_bytes_to_be_read);

        return smb_message_writer.build();
    }
};

pub const SmbReadResponse = struct {
    error_status: SmbMessage.SmbError,

    count_of_bytes_read: u16,
    _reserved: [4]u16,

    bytes: []u8,

    pub fn deserialize(allocator: std.mem.Allocator, response: *const SmbMessage) !SmbReadResponse {
        var smb_message_reader = SmbMessageReader.init(response);

        const count_of_bytes_read: u16 = try smb_message_reader.readParameter(u16);
        var _reserved: [4]u16 = .{ 0, 0, 0, 0 };
        inline for (0..4) |index| {
            _reserved[index] = try smb_message_reader.readParameter(u16);
        }

        const bytes: []u8 = try smb_message_reader.readData(allocator);

        return .{
            .error_status = response.header.status,
            .count_of_bytes_read = count_of_bytes_read,
            ._reserved = _reserved,
            .bytes = bytes,
        };
    }

    pub fn serialize(allocator: std.mem.Allocator, response: *const SmbReadResponse) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_READ,
            .status = response.error_status,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 5);
        try smb_message_writer.writeParameter(u16, response.count_of_bytes_read);
        inline for (0..4) |_| {
            try smb_message_writer.writeParameter(u16, 0x0000);
        }

        try smb_message_writer.reserveData(allocator, 0x0003 + response.count_of_bytes_read);
        try smb_message_writer.writeData(.DATA_BUFFER, response.bytes[0..response.count_of_bytes_read]);

        return smb_message_writer.build();
    }
};

test "SmbReadRequest" {
    const request = SmbReadRequest{ .read_if_execute = true, .uid = 10, .fid = 5, .count_of_bytes_to_read = 5, .read_offset_in_bytes = 10, .estimate_of_remaning_bytes_to_be_read = 20 };
    const allocator = std.testing.allocator;

    var message = try SmbReadRequest.serialize(allocator, &request);
    defer message.deinit(allocator);
    try std.testing.expect((message.header.flags2 & @intFromEnum(SmbMessage.SmbFlags2.SMB_FLAGS2_READ_IF_EXECUTE)) == @intFromEnum(SmbMessage.SmbFlags2.SMB_FLAGS2_READ_IF_EXECUTE));
    try std.testing.expect(message.header.command == .SMB_COM_READ);
    try std.testing.expect(message.header.uid == 10);
    try std.testing.expect(message.parameters.words_count == 5);
    try std.testing.expect(message.data.bytes_count == 0);

    const requestMessage = try SmbReadRequest.deserialize(&message);
    try std.testing.expect(request.read_if_execute == requestMessage.read_if_execute);
    try std.testing.expect(requestMessage.read_if_execute == true);
    try std.testing.expect(request.uid == requestMessage.uid);
    try std.testing.expect(requestMessage.uid == 10);
    try std.testing.expect(request.fid == requestMessage.fid);
    try std.testing.expect(requestMessage.fid == 5);
    try std.testing.expect(request.count_of_bytes_to_read == requestMessage.count_of_bytes_to_read);
    try std.testing.expect(requestMessage.count_of_bytes_to_read == 5);
    try std.testing.expect(request.read_offset_in_bytes == requestMessage.read_offset_in_bytes);
    try std.testing.expect(requestMessage.read_offset_in_bytes == 10);
    try std.testing.expect(request.estimate_of_remaning_bytes_to_be_read == requestMessage.estimate_of_remaning_bytes_to_be_read);
    try std.testing.expect(requestMessage.estimate_of_remaning_bytes_to_be_read == 20);
}

test "SmbReadReponse" {
    // Here we're doing a constCast as the filename is known at compile time
    // but the SmBReadRequest would only happen with runtime values as its
    // purpose is to craft a request, involving compiletime unknown values.
    const bytes: []u8 = @ptrCast(@constCast("Hello"));
    const response = SmbReadResponse{ .error_status = .{
        .error_class = .ERRCLS_DOS,
        .error_code = .ERRDOS_BAD_FID,
    }, .count_of_bytes_read = bytes.len, ._reserved = .{ 0, 0, 0, 0 }, .bytes = bytes[0..] };

    const allocator = std.testing.allocator;

    var message = try SmbReadResponse.serialize(allocator, &response);
    defer message.deinit(allocator);
    try std.testing.expect(message.header.command == .SMB_COM_READ);
    try std.testing.expect(message.header.uid == 0x0000);
    try std.testing.expect(message.parameters.words_count == 5);
    try std.testing.expect(message.data.bytes_count == 8);

    const responseMessage = try SmbReadResponse.deserialize(allocator, &message);
    defer allocator.free(responseMessage.bytes);
    try std.testing.expect(response.error_status.error_class == responseMessage.error_status.error_class);
    try std.testing.expect(response.error_status.error_code == responseMessage.error_status.error_code);
    try std.testing.expect(response.count_of_bytes_read == responseMessage.count_of_bytes_read);
    try std.testing.expect(response.count_of_bytes_read == bytes.len);
    try std.testing.expect(std.mem.eql(u16, response._reserved[0..4], responseMessage._reserved[0..4]));
    try std.testing.expect(std.mem.eql(u16, response._reserved[0..4], ([4]u16{ 0, 0, 0, 0 })[0..4]));
    try std.testing.expect(std.mem.eql(u8, response.bytes, responseMessage.bytes));
    try std.testing.expect(std.mem.eql(u8, response.bytes, "Hello"));
}
