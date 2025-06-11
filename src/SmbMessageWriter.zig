const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");

pub const SmbMessageWriterError = error{
    InvalidMemorySize,
    DataBytesOutOfMemory,
    ParametersWordsOutOfMemory,
};

pub const SmbMessageWriter = @This();

message: SmbMessage = .{},

data_cursor: u16 = 0,

parameters_cursor: u8 = 0,

pub fn init(header: SmbMessage.SmbMessageHeader) SmbMessageWriter {
    return .{ .message = .{ .header = header } };
}

pub fn reserveParameters(self: *SmbMessageWriter, allocator: std.mem.Allocator, words_count: u8) !void {
    if (words_count == 0) {
        return SmbMessageWriterError.InvalidMemorySize;
    }

    const parametersWords: []u16 = try allocator.alloc(u16, words_count);
    self.message.parameters.words_count = words_count;
    self.message.parameters.words = @ptrCast(parametersWords);
}

pub fn writeParameter(self: *SmbMessageWriter, comptime T: type, parameter: T) !void {
    const parameter_size = @divExact(@sizeOf(T), @sizeOf(u16));
    if (@as(u16, parameter_size + self.parameters_cursor) > self.message.parameters.words_count) {
        return SmbMessageWriterError.ParametersWordsOutOfMemory;
    }

    // Copy the actual words.
    const output: *[@sizeOf(T)]u8 = @ptrCast(self.message.parameters.words[self.parameters_cursor..]);
    std.mem.writeInt(T, output, parameter, .little);
    self.parameters_cursor += parameter_size;
}

pub fn reserveData(self: *SmbMessageWriter, allocator: std.mem.Allocator, bytes_count: u16) !void {
    if (bytes_count == 0) {
        return SmbMessageWriterError.InvalidMemorySize;
    }

    const dataBytes: []u8 = try allocator.alloc(u8, bytes_count);
    self.message.data.bytes_count = bytes_count;
    self.message.data.bytes = @ptrCast(dataBytes);
}

pub fn writeData(self: *SmbMessageWriter, data_type: SmbMessage.SmbDataBufferFormatCode, bytes: []const u8) !void {
    const data_size: usize = bytes.len + 1 + self.data_cursor + 1;
    if (data_size > self.message.data.bytes_count) {
        return SmbMessageWriterError.DataBytesOutOfMemory;
    }

    // Copy the type of the bytes.
    self.message.data.bytes[self.data_cursor] = @intFromEnum(data_type);
    self.data_cursor += 1;

    // Copy the actual bytes.
    std.mem.copyForwards(u8, @ptrCast(self.message.data.bytes[self.data_cursor..][0 .. bytes.len + 1]), bytes);
    self.data_cursor += @as(u16, @intCast(bytes.len));

    // Set the null-terminator byte.
    self.message.data.bytes[self.data_cursor] = 0;
    self.data_cursor += 1;
}

pub fn build(self: *const SmbMessageWriter) SmbMessage {
    return self.message;
}

pub fn deinit(self: *SmbMessageWriter, allocator: std.mem.Allocator) void {
    self.message.deinit(allocator);
}
