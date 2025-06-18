const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");
const SmbMessageWriter = @import("SmbMessageWriter.zig");
const SmbMessageReader = @import("SmbMessageReader.zig");

pub const SmbComRenameRequest = struct {
    /// Whether to set the SMB_FLAGS2_LONG_NAMES flag.
    long_names: bool,
    tid: SmbMessage.TID,
    uid: SmbMessage.UID,

    search_attributes: u16,

    old_filename: []u8,
    new_filename: []u8,

    pub fn deserialize(allocator: std.mem.Allocator, request: *const SmbMessage) !SmbComRenameRequest {
        var smb_message_reader = SmbMessageReader.init(request);

        const long_names: bool = (request.header.flags2 & @intFromEnum(SmbMessage.SmbFlags2.SMB_FLAGS2_LONG_NAMES)) == @intFromEnum(SmbMessage.SmbFlags2.SMB_FLAGS2_LONG_NAMES);
        const tid: SmbMessage.UID = request.header.tid;
        const uid: SmbMessage.UID = request.header.uid;

        const search_attributes: u16 = try smb_message_reader.readParameter(u16);

        const old_filename: []u8 = try smb_message_reader.readData(allocator);
        errdefer allocator.free(old_filename);

        const new_filename: []u8 = try smb_message_reader.readData(allocator);
        errdefer allocator.free(new_filename);

        return .{ .long_names = long_names, .tid = tid, .uid = uid, .search_attributes = search_attributes, .old_filename = old_filename, .new_filename = new_filename };
    }

    pub fn serialize(allocator: std.mem.Allocator, request: *const SmbComRenameRequest) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .flags2 = 0 | (@intFromEnum(SmbMessage.SmbFlags2.SMB_FLAGS2_LONG_NAMES) * @intFromBool(request.long_names)),
            .command = .SMB_COM_RENAME,
            .tid = request.tid,
            .uid = request.uid,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 1);
        try smb_message_writer.writeParameter(u16, request.search_attributes);

        try smb_message_writer.reserveData(allocator, @intCast(2 + 2 + request.old_filename.len + request.new_filename.len));
        try smb_message_writer.writeData(.SMB_STRING, request.old_filename);
        try smb_message_writer.writeData(.SMB_STRING, request.new_filename);

        return smb_message_writer.build();
    }

    pub fn deinit(self: *SmbComRenameRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.old_filename);
        allocator.free(self.new_filename);
    }
};

pub const SmbComRenameResponse = struct {
    error_status: SmbMessage.SmbError,

    pub fn deserialize(response: *const SmbMessage) SmbComRenameResponse {
        return .{
            .error_status = response.header.status,
        };
    }

    pub fn serialize(response: *const SmbComRenameResponse) SmbMessage {
        return .{
            .header = .{
                .command = .SMB_COM_RENAME,
                .status = response.error_status,
            },
        };
    }
};

test "SmbComRenameRequest" {
    const old_filename: []u8 = @constCast("old_name.txt");
    const new_filename: []u8 = @constCast("new_name.txt");

    const request = SmbComRenameRequest{ .long_names = true, .tid = 5, .uid = 10, .search_attributes = @intFromEnum(SmbMessage.SmbFileAttributes.SMB_FILE_ATTRIBUTE_NORMAL), .old_filename = old_filename, .new_filename = new_filename };
    const allocator = std.testing.allocator;

    var message = try SmbComRenameRequest.serialize(allocator, &request);
    defer message.deinit(allocator);
    try std.testing.expect((message.header.flags2 & @intFromEnum(SmbMessage.SmbFlags2.SMB_FLAGS2_LONG_NAMES)) == @intFromEnum(SmbMessage.SmbFlags2.SMB_FLAGS2_LONG_NAMES));
    try std.testing.expect(message.header.command == .SMB_COM_RENAME);
    try std.testing.expect(message.header.tid == 5);
    try std.testing.expect(message.header.uid == 10);
    try std.testing.expect(message.parameters.words_count == 1);
    try std.testing.expect(message.data.bytes_count == 28);

    var requestMessage = try SmbComRenameRequest.deserialize(allocator, &message);
    defer requestMessage.deinit(allocator);

    try std.testing.expect(request.long_names == requestMessage.long_names);
    try std.testing.expect(requestMessage.long_names == true);
    try std.testing.expect(request.tid == requestMessage.tid);
    try std.testing.expect(requestMessage.tid == 5);
    try std.testing.expect(request.uid == requestMessage.uid);
    try std.testing.expect(requestMessage.uid == 10);
    try std.testing.expect(request.search_attributes == requestMessage.search_attributes);
    try std.testing.expect(requestMessage.search_attributes == @intFromEnum(SmbMessage.SmbFileAttributes.SMB_FILE_ATTRIBUTE_NORMAL));
    try std.testing.expect(std.mem.eql(u8, request.old_filename, requestMessage.old_filename));
    try std.testing.expect(std.mem.eql(u8, request.old_filename, "old_name.txt"));
    try std.testing.expect(std.mem.eql(u8, request.new_filename, requestMessage.new_filename));
    try std.testing.expect(std.mem.eql(u8, request.new_filename, "new_name.txt"));
}

test "SmbComRenameReponse" {
    const response = SmbComRenameResponse{ .error_status = .{
        .error_class = .ERRCLS_DOS,
        .error_code = .ERRDOS_BAD_FID,
    } };

    const message = SmbComRenameResponse.serialize(&response);
    try std.testing.expect(message.header.command == .SMB_COM_RENAME);
    try std.testing.expect(message.header.tid == 0x0000);
    try std.testing.expect(message.header.uid == 0x0000);
    try std.testing.expect(message.parameters.words_count == 0);
    try std.testing.expect(message.data.bytes_count == 0);

    const responseMessage = SmbComRenameResponse.deserialize(&message);
    try std.testing.expect(response.error_status.error_class == responseMessage.error_status.error_class);
    try std.testing.expect(response.error_status.error_code == responseMessage.error_status.error_code);
}
