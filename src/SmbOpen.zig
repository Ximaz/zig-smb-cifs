const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");
const SmbMessageWriter = @import("SmbMessageWriter.zig");
const SmbMessageReader = @import("SmbMessageReader.zig");

pub const SmbOpenRequestError = error{
    /// This error is returned when the flag SMB_FLAGS_OPLOCK is not set but
    /// the flag SMB_FLAGS_OPBATCH is set.
    InvalidArgument,
};

pub const SmbOpenRequest = struct {
    /// Whether to set the SMB_FLAGS_OPLOCK flag.
    exclusive_opportunistic_lock: bool,
    /// Whether to set the SMB_FLAGS_OPBATCH flag.
    batch_exclusive_oplock: bool,
    tid: SmbMessage.TID,
    uid: SmbMessage.UID,

    access_mode: SmbMessage.SmbAccessMode,
    search_attributes: SmbMessage.SmbFileAttributes,

    filename: []u8,

    pub fn deserialize(request: *const SmbMessage, allocator: std.mem.Allocator) !SmbOpenRequest {
        var smb_message_reader = SmbMessageReader.init(request);

        const exclusive_opportunistic_lock: bool = (request.header.flags & @intFromEnum(SmbMessage.SmbFlags.SMB_FLAGS_OPLOCK)) == @intFromEnum(SmbMessage.SmbFlags.SMB_FLAGS_OPLOCK);
        const batch_exclusive_oplock: bool = (request.header.flags & @intFromEnum(SmbMessage.SmbFlags.SMB_FLAGS_OPBATCH)) == @intFromEnum(SmbMessage.SmbFlags.SMB_FLAGS_OPBATCH);
        const tid: SmbMessage.TID = request.header.tid;
        const uid: SmbMessage.UID = request.header.uid;

        const access_mode: SmbMessage.SmbAccessMode = @enumFromInt(try smb_message_reader.readParameter(u16));
        const search_attributes: SmbMessage.SmbFileAttributes = @enumFromInt(try smb_message_reader.readParameter(u16));

        const filename: []u8 = try smb_message_reader.readData(allocator);

        return .{ .exclusive_opportunistic_lock = exclusive_opportunistic_lock, .batch_exclusive_oplock = batch_exclusive_oplock, .tid = tid, .uid = uid, .access_mode = access_mode, .search_attributes = search_attributes, .filename = filename };
    }

    pub fn serialize(allocator: std.mem.Allocator, request: *const SmbOpenRequest) !SmbMessage {
        if (request.batch_exclusive_oplock and !request.exclusive_opportunistic_lock) {
            return SmbOpenRequestError.InvalidArgument;
        }

        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_OPEN,
            .flags = 0 | (@intFromEnum(SmbMessage.SmbFlags.SMB_FLAGS_OPLOCK) * @intFromBool(request.exclusive_opportunistic_lock)) | (@intFromEnum(SmbMessage.SmbFlags.SMB_FLAGS_OPBATCH) * @intFromBool(request.batch_exclusive_oplock)),
            .tid = request.tid,
            .uid = request.uid,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 2);
        try smb_message_writer.writeParameter(u16, @intFromEnum(request.access_mode));
        try smb_message_writer.writeParameter(u16, @intFromEnum(request.search_attributes));

        const data_bytes_count: u16 = @as(u16, @intCast(1 + request.filename.len + 1));
        try smb_message_writer.reserveData(allocator, data_bytes_count);
        try smb_message_writer.writeData(SmbMessage.SmbDataBufferFormatCode.SMB_STRING, request.filename);

        return smb_message_writer.build();
    }
};

pub const SmbOpenResponse = struct {
    error_status: SmbMessage.SmbError,

    fid: SmbMessage.FID,
    file_attributes: u16,
    last_time_modified: SmbMessage.UTIME,
    file_size: u32,
    access_mode: u16,

    pub fn deserialize(response: *const SmbMessage) !SmbOpenResponse {
        var smb_message_reader = SmbMessageReader.init(response);

        const fid: SmbMessage.FID = try smb_message_reader.readParameter(SmbMessage.FID);
        const file_attributes: u16 = try smb_message_reader.readParameter(u16);
        const last_time_modified: u32 = try smb_message_reader.readParameter(u32);
        const file_size: u32 = try smb_message_reader.readParameter(u32);
        const access_mode: u16 = try smb_message_reader.readParameter(u16);
        return .{ .error_status = response.header.status, .fid = fid, .file_attributes = file_attributes, .last_time_modified = last_time_modified, .file_size = file_size, .access_mode = access_mode };
    }

    pub fn serialize(allocator: std.mem.Allocator, response: *const SmbOpenResponse) !SmbMessage {
        var smb_message_writer = SmbMessageWriter.init(.{
            .command = .SMB_COM_OPEN,
            .status = response.error_status,
        });
        errdefer smb_message_writer.deinit(allocator);

        try smb_message_writer.reserveParameters(allocator, 7);
        try smb_message_writer.writeParameter(SmbMessage.FID, response.fid);
        try smb_message_writer.writeParameter(u16, response.file_attributes);
        try smb_message_writer.writeParameter(SmbMessage.UTIME, response.last_time_modified);
        try smb_message_writer.writeParameter(u32, response.file_size);
        try smb_message_writer.writeParameter(u16, response.access_mode);

        return smb_message_writer.build();
    }
};

test "SmbOpenRequest" {
    // Here we're doing a constCast as the filename is known at compile time
    // but the SmbOpenRequest would only happen with runtime values as its
    // purpose is to craft a request, involving compiletime unknown values.
    const filename: []u8 = @constCast("Hello.txt");
    const request = SmbOpenRequest{ .exclusive_opportunistic_lock = true, .batch_exclusive_oplock = true, .tid = 10, .uid = 5, .access_mode = .ACCESS_MODE_READWRITE, .search_attributes = .SMB_FILE_ATTRIBUTE_NORMAL, .filename = filename };
    const allocator = std.testing.allocator;

    var message = try SmbOpenRequest.serialize(allocator, &request);
    defer message.deinit(allocator);
    try std.testing.expect(message.header.command == .SMB_COM_OPEN);
    try std.testing.expect(message.header.flags == (0 | @intFromEnum(SmbMessage.SmbFlags.SMB_FLAGS_OPLOCK) | @intFromEnum(SmbMessage.SmbFlags.SMB_FLAGS_OPBATCH)));
    try std.testing.expect(message.header.tid == 10);
    try std.testing.expect(message.header.uid == 5);
    try std.testing.expect(message.parameters.words_count == 2);
    try std.testing.expect(message.data.bytes_count == 11);

    const requestMessage = try SmbOpenRequest.deserialize(&message, allocator);
    defer allocator.free(requestMessage.filename);

    try std.testing.expect(request.exclusive_opportunistic_lock == requestMessage.exclusive_opportunistic_lock);
    try std.testing.expect(request.batch_exclusive_oplock == requestMessage.batch_exclusive_oplock);
    try std.testing.expect(request.tid == requestMessage.tid);
    try std.testing.expect(request.uid == requestMessage.uid);
    try std.testing.expect(request.access_mode == requestMessage.access_mode);
    try std.testing.expect(request.search_attributes == requestMessage.search_attributes);
    try std.testing.expect(std.mem.eql(u8, request.filename, requestMessage.filename));
}

test "SmbOpenReponse" {
    const response = SmbOpenResponse{ .error_status = .{ .error_class = .ERRCLS_DOS, .error_code = .ERRDOS_BAD_FID }, .fid = 100, .last_time_modified = 0xFF00BBCC, .file_attributes = @intFromEnum(SmbMessage.SmbFileAttributes.SMB_FILE_ATTRIBUTE_NORMAL), .access_mode = @intFromEnum(SmbMessage.SmbAccessMode.ACCESS_MODE_READWRITE), .file_size = 0xFFFFFFFF };
    const allocator = std.testing.allocator;

    var message = try SmbOpenResponse.serialize(allocator, &response);
    defer message.deinit(allocator);

    try std.testing.expect(message.header.command == .SMB_COM_OPEN);
    try std.testing.expect(message.header.tid == 0x0000);
    try std.testing.expect(message.header.uid == 0x0000);
    try std.testing.expect(message.parameters.words_count == 7);
    try std.testing.expect(message.data.bytes_count == 0);

    const responseMessage = try SmbOpenResponse.deserialize(&message);
    try std.testing.expect(response.error_status.error_class == responseMessage.error_status.error_class);
    try std.testing.expect(response.error_status.error_code == responseMessage.error_status.error_code);
    try std.testing.expect(response.fid == responseMessage.fid);
    try std.testing.expect(response.fid == 100);
    try std.testing.expect(response.last_time_modified == responseMessage.last_time_modified);
    try std.testing.expect(response.last_time_modified == 0xFF00BBCC);
    try std.testing.expect(response.file_attributes == responseMessage.file_attributes);
    try std.testing.expect((response.file_attributes & @intFromEnum(SmbMessage.SmbFileAttributes.SMB_FILE_ATTRIBUTE_NORMAL)) == @intFromEnum(SmbMessage.SmbFileAttributes.SMB_FILE_ATTRIBUTE_NORMAL));
    try std.testing.expect(response.access_mode == responseMessage.access_mode);
    try std.testing.expect((response.access_mode & @intFromEnum(SmbMessage.SmbAccessMode.ACCESS_MODE_READWRITE)) == @intFromEnum(SmbMessage.SmbAccessMode.ACCESS_MODE_READWRITE));
    try std.testing.expect(response.file_size == responseMessage.file_size);
    try std.testing.expect(response.file_size == 0xFFFFFFFF);
}
