const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");
const SmbMessageWriter = @import("SmbMessageWriter.zig");
const SmbMessageReader = @import("SmbMessageReader.zig");

pub const SmbComWriteRequest = struct {
    uid: SmbMessage.UID,

    fid: SmbMessage.FID,
    count_of_bytes_to_write: u16,
    write_offset_in_bytes: u32,
    estimate_of_remaning_bytes_to_be_written: u16,

    bytes: []u8,

    pub fn deserialize(allocator: std.mem.Allocator, request: *const SmbMessage) !SmbComWriteRequest {
        var smb_message_reader = SmbMessageReader.init(request);

        const uid: SmbMessage.UID = request.header.uid;

        const fid: SmbMessage.FID = try smb_message_reader.readParameter(SmbMessage.FID);
        const count_of_bytes_to_write: u16 = try smb_message_reader.readParameter(u16);
        const write_offset_in_bytes: u32 = try smb_message_reader.readParameter(u32);
        const estimate_of_remaning_bytes_to_be_written: u16 = try smb_message_reader.readParameter(u16);

        const bytes = try smb_message_reader.readData(allocator);

        return .{
            .uid = uid,
            .fid = fid,
            .count_of_bytes_to_write = count_of_bytes_to_write,
            .write_offset_in_bytes = write_offset_in_bytes,
            .estimate_of_remaning_bytes_to_be_written = estimate_of_remaning_bytes_to_be_written,
            .bytes = bytes,
        };
    }

    pub fn serialize(allocator: std.mem.Allocator, request: *const SmbComWriteRequest) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_WRITE,
            .uid = request.uid,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 5);
        try smb_message_writer.writeParameter(SmbMessage.FID, request.fid);
        try smb_message_writer.writeParameter(u16, request.count_of_bytes_to_write);
        try smb_message_writer.writeParameter(u32, request.write_offset_in_bytes);
        try smb_message_writer.writeParameter(u16, request.estimate_of_remaning_bytes_to_be_written);

        try smb_message_writer.reserveData(allocator, @intCast(3 + request.bytes.len));
        try smb_message_writer.writeData(.DATA_BUFFER, request.bytes);

        return smb_message_writer.build();
    }

    pub fn deinit(self: *SmbComWriteRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
    }
};

pub const SmbComWriteResponse = struct {
    error_status: SmbMessage.SmbError,

    count_of_bytes_written: u16,

    pub fn deserialize(response: *const SmbMessage) !SmbComWriteResponse {
        var smb_message_reader = SmbMessageReader.init(response);

        const count_of_bytes_written: u16 = try smb_message_reader.readParameter(u16);

        return .{
            .error_status = response.header.status,
            .count_of_bytes_written = count_of_bytes_written,
        };
    }

    pub fn serialize(allocator: std.mem.Allocator, response: *const SmbComWriteResponse) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_WRITE,
            .status = response.error_status,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 1);
        try smb_message_writer.writeParameter(u16, response.count_of_bytes_written);

        return smb_message_writer.build();
    }
};

test "SmbComWriteRequest" {
    const bytes: []u8 = @constCast("Hello, World !");
    const request = SmbComWriteRequest{ .uid = 10, .fid = 5, .count_of_bytes_to_write = 14, .write_offset_in_bytes = 10, .estimate_of_remaning_bytes_to_be_written = 20, .bytes = bytes };
    const allocator = std.testing.allocator;

    var message = try SmbComWriteRequest.serialize(allocator, &request);
    defer message.deinit(allocator);
    try std.testing.expect(message.header.command == .SMB_COM_WRITE);
    try std.testing.expect(message.header.uid == 10);
    try std.testing.expect(message.parameters.words_count == 5);
    try std.testing.expect(message.data.bytes_count == 17);

    var requestMessage = try SmbComWriteRequest.deserialize(allocator, &message);
    defer requestMessage.deinit(allocator);

    try std.testing.expect(request.uid == requestMessage.uid);
    try std.testing.expect(requestMessage.uid == 10);
    try std.testing.expect(request.fid == requestMessage.fid);
    try std.testing.expect(requestMessage.fid == 5);
    try std.testing.expect(request.count_of_bytes_to_write == requestMessage.count_of_bytes_to_write);
    try std.testing.expect(requestMessage.count_of_bytes_to_write == 14);
    try std.testing.expect(request.write_offset_in_bytes == requestMessage.write_offset_in_bytes);
    try std.testing.expect(requestMessage.write_offset_in_bytes == 10);
    try std.testing.expect(request.estimate_of_remaning_bytes_to_be_written == requestMessage.estimate_of_remaning_bytes_to_be_written);
    try std.testing.expect(requestMessage.estimate_of_remaning_bytes_to_be_written == 20);
    try std.testing.expect(std.mem.eql(u8, request.bytes, requestMessage.bytes));
    try std.testing.expect(std.mem.eql(u8, requestMessage.bytes, bytes));
}

test "SmbComWriteReponse" {
    const response = SmbComWriteResponse{ .error_status = .{
        .error_class = .ERRCLS_DOS,
        .error_code = .ERRDOS_BAD_FID,
    }, .count_of_bytes_written = 14 };

    const allocator = std.testing.allocator;

    var message = try SmbComWriteResponse.serialize(allocator, &response);
    defer message.deinit(allocator);
    try std.testing.expect(message.header.command == .SMB_COM_WRITE);
    try std.testing.expect(message.header.uid == 0x0000);
    try std.testing.expect(message.parameters.words_count == 1);
    try std.testing.expect(message.data.bytes_count == 0);

    const responseMessage = try SmbComWriteResponse.deserialize(&message);
    try std.testing.expect(response.error_status.error_class == responseMessage.error_status.error_class);
    try std.testing.expect(response.error_status.error_code == responseMessage.error_status.error_code);
    try std.testing.expect(response.count_of_bytes_written == responseMessage.count_of_bytes_written);
    try std.testing.expect(response.count_of_bytes_written == 14);
}
