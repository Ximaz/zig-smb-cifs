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

/// Instantiate the SmbMessageWriter object.
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

/// Write a parameter value into the Parameter block. Depending on parameter's
/// size, it is rearranged to fit into u16 values.
///
/// For instance :
/// ```zig
/// const smb_message: SmbMessage = ...;
///
/// var gpa = std.heap.GeneralPurposeAllocator(.{}){};
/// defer gpa.deinit();
/// const allocator = gpa.allocator();
///
/// var smb_message_writer = SmbMessageWriter.init(&smb_message);
/// defer smb_message_writer.deinit(allocator);
///
/// // Reserve 2 * u16 bits (4 bytes) to then store a u32 into them.
/// try smb_message_writer.reserveParameters(allocator, 0x02);
///
/// // Write a u32 value as two words (u16 * 2).
/// try smb_message_reader.writeParameter(u32, 0xFF00BBCC);
/// ```
///
/// This methods increments the parameters_cursor by the number of bytes that
/// have been written to the Parameter block, based on the size of parameter's
/// value.
///
/// This methods returns an error if the given parameter would not fit in the
/// remaining slots of the Parameters block.
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

/// Write a sequence of bytes into the Data block.
///
/// For instance :
/// ```zig
/// const smb_message: SmbMessage = ...;
///
/// var gpa = std.heap.GeneralPurposeAllocator(.{}){};
/// defer gpa.deinit();
/// const allocator = gpa.allocator();
///
/// var smb_message_writer = SmbMessageWriter.init(&smb_message);
/// defer smb_message_writer.deinit(allocator);
///
/// // Reserve 7 * u8 bits (7 bytes), which includes enough space for :
/// // - the SmbDataBufferFormatCode (1 byte) ;
/// // - the bytes sequence (5 bytes) ;
/// // - the null-terminator byte (1 byte).
/// // Note that we include a null-terminator byte because we will store a
/// // value that requires it (SMB_STRING). Other buffer formats may not need
/// // such terminator.
/// try smb_message_writer.reserveData(allocator, 0x07);
///
/// // Write the bytes sequence.
/// const bytes: []u8 = {'H', 'e', 'l', 'l', 'o', 0};
/// try smb_message_writer.writeData(SmbDataBufferFormatCode.SMB_STRING, bytes);
/// ```
///
/// This methods increments the data_cursor by the number of bytes that have
/// been written to the Data block, including the SmbDataBufferFormatCode byte.
///
/// This methods returns an error if the given byte sequence would not fit in
/// the remaining slots of the Data block.
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

/// Returns the composed SmbMessage.
pub fn build(self: *const SmbMessageWriter) SmbMessage {
    return self.message;
}

/// Deinit the allocated memory upon SmbMessage build process.
///
/// The allocator must be the same as the one used for reserving either the
/// Parameters or Data block.
pub fn deinit(self: *SmbMessageWriter, allocator: std.mem.Allocator) void {
    self.message.deinit(allocator);
}
