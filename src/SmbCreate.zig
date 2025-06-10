const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");

pub const SmbCreateRequest = struct {
    uid: SmbMessage.UID,
    tid: SmbMessage.TID,
    pathname: []const u8,
    file_attributes: SmbMessage.SmbFileAttributes,
    creation_time: SmbMessage.UTIME,

    pub fn deserialize(request: *const SmbMessage) SmbCreateRequest {
        const pathname_length = strlen: {
            var i: u16 = 0;
            while (request.data.bytes[1 + i] != 0) : (i += 1) {}
            break :strlen i;
        };
        return .{ .uid = request.header.uid, .tid = request.header.tid, .pathname = request.data.bytes[1 .. pathname_length + 1], .file_attributes = @enumFromInt(request.parameters.words[0]), .creation_time = std.mem.readInt(SmbMessage.UTIME, @as(*[4]u8, @alignCast(@ptrCast(&request.parameters.words[1]))), .little) };
    }

    pub fn serialize(allocator: std.mem.Allocator, request: *const SmbCreateRequest) !SmbMessage {
        var smbMessage = SmbMessage{ .header = .{ .uid = request.uid, .tid = request.tid, .command = .SMB_COM_CREATE } };
        errdefer smbMessage.deinit(allocator);

        try smbMessage.reserveParameters(allocator, 3);
        smbMessage.parameters.words[0] = @intFromEnum(request.file_attributes);
        std.mem.writeInt(SmbMessage.UTIME, @as(*[4]u8, @alignCast(@ptrCast(&smbMessage.parameters.words[1]))), request.creation_time, .little);

        const dataBytesCount: u16 = @as(u16, @intCast(1 + request.pathname.len + 1));
        try smbMessage.reserveData(allocator, dataBytesCount);
        smbMessage.data.bytes[0] = @intFromEnum(SmbMessage.SmbDataBufferFormatCode.SMB_STRING);
        std.mem.copyForwards(u8, smbMessage.data.bytes[1 .. @as(u16, @intCast(request.pathname.len)) + 1], request.pathname);
        smbMessage.data.bytes[1 + request.pathname.len] = 0;

        return smbMessage;
    }
};

pub const SmbCreateResponse = struct {
    error_status: SmbMessage.SmbError,
    fid: SmbMessage.FID,

    pub fn deserialize(response: *const SmbMessage) SmbCreateResponse {
        return .{ .error_status = response.header.status, .fid = @as(i16, @intCast(response.parameters.words[0])) };
    }

    pub fn serialize(allocator: std.mem.Allocator, response: *const SmbCreateResponse) !SmbMessage {
        var smbMessage: SmbMessage = .{ .header = .{
            .command = .SMB_COM_CLOSE,
            .status = response.error_status,
        } };
        errdefer smbMessage.deinit(allocator);

        try smbMessage.reserveParameters(allocator, 1);
        smbMessage.parameters.words[0] = @as(u16, @intCast(response.fid));

        return smbMessage;
    }
};

test "SmbCreateRequest" {
    const request = SmbCreateRequest{ .uid = 5, .tid = 10, .pathname = "Hello.txt", .file_attributes = .SMB_FILE_ATTRIBUTE_NORMAL, .creation_time = 0xFFAABB00 };
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var message = try SmbCreateRequest.serialize(allocator, &request);
    defer message.deinit(allocator);

    const requestMessage = SmbCreateRequest.deserialize(&message);
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

    const responseMessage = SmbCreateResponse.deserialize(&message);
    try std.testing.expect(response.error_status.error_class == responseMessage.error_status.error_class);
    try std.testing.expect(response.error_status.error_code == responseMessage.error_status.error_code);
    try std.testing.expect(response.fid == responseMessage.fid);
}
