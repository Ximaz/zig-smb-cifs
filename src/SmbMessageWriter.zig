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

/// Instantiate the SmbMessageriter object.
pub fn init(header: SmbMessage.SmbMessageHeader) SmbMessageWriter {
    return .{ .message = .{ .header = header } };
}

/// Reserve `words_count` bytes inside the SmbMessage Parameters block for
/// future writing operations.
///
/// This method returns an error if the `words_count` value is 0, as it does
/// not make sense to allocate zero byte. It also might return an error if the
/// allocation itself failed.
///
/// The allocated bytes are managed by the SmbMessageWriter object, and the
/// caller is not responsible for freeing them, thus they are not returned.
///
/// If this method is used, the caller must not forget to call the `deinit`
/// method, which will free the allocated bytes.
pub fn reserveParameters(self: *SmbMessageWriter, allocator: std.mem.Allocator, words_count: u8) !void {
    if (words_count == 0) {
        return SmbMessageWriterError.InvalidMemorySize;
    }

    const parameters_words: []u16 = try allocator.alloc(u16, words_count);
    self.message.parameters.words_count = words_count;
    self.message.parameters.words = @ptrCast(parameters_words);
}

pub fn writeParameter(self: *SmbMessageWriter, comptime T: type, parameter: T) !void {
    const parameter_size = @divExact(@sizeOf(T), @sizeOf(u16));
    if (@as(u16, parameter_size + self.parameters_cursor) > self.message.parameters.words_count) {
        return SmbMessageWriterError.ParametersWordsOutOfMemory;
    }

    const output: *[@sizeOf(T)]u8 = @ptrCast(self.message.parameters.words[self.parameters_cursor..]);
    std.mem.writeInt(T, output, parameter, .little);
    self.parameters_cursor += parameter_size;
}

/// Reserve `bytes_count` bytes inside the SmbMessage Data block for future
/// writing operations.
///
/// This method returns an error if the `bytes_count` value is 0, as it does
/// not make sense to allocate zero byte. It also might return an error if the
/// allocation itself failed.
///
/// The allocated bytes are managed by the SmbMessageWriter object, and the
/// caller is not responsible for freeing them, thus they are not returned.
///
/// If this method is used, the caller must not forget to call the `deinit`
/// method, which will free the allocated bytes.
pub fn reserveData(self: *SmbMessageWriter, allocator: std.mem.Allocator, bytes_count: u16) !void {
    if (bytes_count == 0) {
        return SmbMessageWriterError.InvalidMemorySize;
    }

    const data_bytes: []u8 = try allocator.alloc(u8, bytes_count);
    self.message.data.bytes_count = bytes_count;
    self.message.data.bytes = @ptrCast(data_bytes);
}

pub fn writeData(self: *SmbMessageWriter, data_type: SmbMessage.SmbDataBufferFormatCode, bytes: []const u8) !void {
    const data_size: usize = bytes.len + 1 + self.data_cursor + 1;
    if (data_size > self.message.data.bytes_count) {
        return SmbMessageWriterError.DataBytesOutOfMemory;
    }

    self.message.data.bytes[self.data_cursor] = @intFromEnum(data_type);
    self.data_cursor += 1;

    std.mem.copyForwards(u8, @ptrCast(self.message.data.bytes[self.data_cursor..][0 .. bytes.len + 1]), bytes);
    self.data_cursor += @as(u16, @intCast(bytes.len));

    self.message.data.bytes[self.data_cursor] = 0;
    self.data_cursor += 1;
}

pub fn build(self: *const SmbMessageWriter) SmbMessage {
    return self.message;
}

pub fn deinit(self: *SmbMessageWriter, allocator: std.mem.Allocator) void {
    self.message.deinit(allocator);
}
