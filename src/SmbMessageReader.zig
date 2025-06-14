const std = @import("std");
const SmbMessage = @import("SmbMessage.zig");

pub const SmbMessageReaderError = error{
    /// Returned when all Data block has been read and the readData method is
    /// being called.
    DataBytesOutOfMemory,

    /// Returned when all Parameters block has been read and the readParameter
    /// method is being called.
    ParametersWordsOutOfMemory,
};

pub const SmbMessageReader = @This();

/// The SmbMessage to read data from.
message: *const SmbMessage,

/// The reading cursor of the Parameters block.
parameters_cursor: u8 = 0,

/// The reading cursor of the Data block.
data_cursor: u16 = 0,

/// Instantiate the SmbMessageReader object. None of the object's method must
/// modify the original message, thus marking it as const.
pub fn init(message: *const SmbMessage) SmbMessageReader {
    return .{ .message = message };
}

/// Read one or more words from the Parameters block and operate on them to
/// return the correct value.
///
/// For instance :
/// ```zig
/// const smb_message: SmbMessage = ...;
/// var smb_message_reader = SmbMessageReader.init(&smb_message);
///
/// // Read two words (u16 * 2) and craft a u32 based on that.
/// const value = try smb_message_reader.readParameter(u32);
/// ```
///
/// This method increments the `parameters_cursor` variable by the size of the
/// read value, so it is ready for a new `readParameter` call.
///
/// This method returns an error if `T`'s size of the value to be read exceeds
/// the number of bytes remaning in the Parameter's block.
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

/// Read a sequence of bytes based on the found `SmbDataBufferFormatCode` in
/// the Data block.
///
/// This method allocates a buffer using `allocator.alloc` method, which means
/// it is caller's responsibility to use the `allocator.free` method once the
/// allocated bytes are not needed anymore.
///
/// For instance, in the following example, let us assume the SmbMessage
/// contains a Data block with such bytes sequence :
///
/// ```zig
/// [_]u8{ 0x04, 'H', 'e', 'l', 'l', 'o', 0, ... }
/// ```
///
/// The bytes_count is then at least 7. The `0x04` byte indicates that the
/// sequence is expect to be a null-terminated string, thus the `0` at the end.
///
/// ```zig
/// const smb_message: SmbMessage = ...;
///
/// var smb_message_reader = SmbMessageReader.init(&smb_message);
///
/// var gpa = std.mem.Allocator(.{}){};
/// defer gpa.deinit();
/// const allocator = gpa.allocator();
///
/// var string = try smb_message_reader.readData(allocator);
/// defer allocator.free(string); // Do not forget to free the bytes.
///
/// try std.testing.expect(std.mem.eql(u8, string, "Hello")); // Pass
/// ```
///
/// This method increments the `data_cursor` variable by the length of the read
/// bytes, including the `SmbDataBufferFormatCode` byte, so it is ready for a
/// new `readData` call.
///
/// This method returns an error if the `data_cursor` is equal to the Data
/// bytes_count, indicating there is no more byte to read from the SmbMessage.
/// It also might return an error if the allocation itself failed.
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
