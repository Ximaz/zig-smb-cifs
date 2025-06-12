const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");

pub const SmbMessageReaderError = error{
    InvalidMemorySize,
    DataBytesOutOfMemory,
    ParametersWordsOutOfMemory,
    DataBufferFormatCodeUnknown,
};

pub const SmbMessageReader = @This();

message: *const SmbMessage,

data_cursor: u16 = 0,

parameters_cursor: u8 = 0,

pub fn init(message: *const SmbMessage) SmbMessageReader {
    return .{ .message = message };
}

pub fn readParameter(self: *SmbMessageReader, comptime T: type) !T {
    const parameter_size = @divExact(@sizeOf(T), @sizeOf(u16));
    if (@as(u16, parameter_size + self.parameters_cursor) > self.message.parameters.words_count) {
        return SmbMessageReaderError.ParametersWordsOutOfMemory;
    }

    // Read the actual words.
    const buffer: *[@sizeOf(T)]u8 = @ptrCast(self.message.parameters.words[self.parameters_cursor..]);
    defer self.parameters_cursor += parameter_size;
    return std.mem.readInt(T, buffer, .little);
}

fn strlen(bytes: [*]const u8) usize {
    var i: usize = 0;
    while (bytes[i] != 0) : (i += 1) {}
    return i;
}

pub fn readData(self: *SmbMessageReader, allocator: std.mem.Allocator) ![]u8 {
    if (self.data_cursor == self.message.data.bytes_count) {
        return SmbMessageReaderError.DataBytesOutOfMemory;
    }

    const data_type = @as(SmbMessage.SmbDataBufferFormatCode, @enumFromInt(self.message.data.bytes[self.data_cursor]));
    self.data_cursor += 1;

    return try switch (data_type) {
        .DATA_BUFFER, .VARIABLE_BLOCK => {
            const data_buffer_length: u16 = std.mem.readInt(u16, @ptrCast(self.message.data.bytes[self.data_cursor..]), .little);
            self.data_cursor += 2;

            const bytes = try allocator.alloc(u8, data_buffer_length);
            errdefer allocator.free(bytes);

            const source = self.message.data.bytes[self.data_cursor..][0..data_buffer_length];
            std.mem.copyForwards(u8, bytes, source);

            return bytes;
        },
        .DIALECT_STRING, .PATHNAME, .SMB_STRING => {
            const dialect_string_length: u16 = @intCast(strlen(self.message.data.bytes[self.data_cursor..]));

            const bytes = try allocator.alloc(u8, dialect_string_length);
            errdefer allocator.free(bytes);

            const source = self.message.data.bytes[self.data_cursor..][0..dialect_string_length];
            std.mem.copyForwards(u8, bytes, source);

            self.data_cursor += dialect_string_length + 1;
            return bytes;
        },
    };
}
