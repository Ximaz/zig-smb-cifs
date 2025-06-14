//! SMB Messages are divisible into three parts:
//! - A fixed-length header
//! - A variable length parameter block
//! - A variable length data block
//! The header identifies the message as an SMB message, specifies the command
//! to be executed, and provides context. In a response message, the header
//! also includes status information that indicates whether (and how) the
//! command succeeded or failed.
//!
//! The parameter block is a short array of two-byte values (words), while the
//! data block is an array of up to 64 KB in size. The structure and contents
//! of these blocks are specific to each SMB message.
//!
//! SMB messages are structured this way because the protocol was originally
//! conceived of as a rudimentary remote procedure call system. The parameter
//! values were meant to represent the parameters passed into a function. The
//! data section would contain larger structures or data buffers, such as the
//! block of data to be written using an SMB_COM_WRITE command. Although the
//! protocol has evolved over time, this differentiation has been generally
//! maintained.
const std = @import("std");

// CONSTANTS

pub const SMB_GEA_ATTR_NAME_MAX_LEN = (1 << 8) - 1;

pub const SMB_FEA_ATTR_NAME_MAX_LEN = SMB_GEA_ATTR_NAME_MAX_LEN;

pub const SMB_FEA_ATTR_VALUE_MAX_LEN = (1 << 16) - 1;

pub const PROTOCOL: [4]u8 = .{ 0xFF, 'S', 'M', 'B' };

pub const SMB_PARAMETERS_MAX_WORDS = ((1 << 8) - 1);

pub const SMB_DATA_MAX_BYTES = ((1 << 16) - 1);

// TYPES

pub const SMB_EXT_FILE_ATTR = i32;

pub const SMB_NMPIPE_STATUS = u16;

pub const UTIME = u32;

/// File ID.
/// A file handle, representing an open file on the server. A FID returned from
/// an Open or Create operation MUST be unique within an SMB connection.
///
/// File IDs (FIDs) are generated on CIFS servers. The generation of FIDs MUST
/// satisfy the following constraints:
/// - The FID MUST be a 16-bit opaque value.
/// - The FID MUST be unique within a specified client/server SMB connection.
/// - The FID MUST remain valid for the lifetime of the SMB connection on which
///   the open request is performed, or until the client sends a request to the
///   server to close the FID.
/// - Once a FID has been closed, the value can be reused for another create or
///   open request.
/// - The value 0xFFFF MUST NOT be used as a valid FID. All other possible
///   values for FID, including zero (0x0000) are valid. The value 0xFFFF is
///   used to specify all FIDs or no FID, depending upon the context in which it
///   is used.
pub const FID = i16;

/// Multiplex ID.
/// The MID is assigned by the client. All messages include a MID along with a
/// PID (process ID, see below) to uniquely identify groups of commands
/// belonging to the same logical thread of operation on the client node. The
/// client MAY use the PID/MID pair to demultiplex command responses and to
/// identify outstanding requests that are pending on the server (see
/// SMB_COM_NT_CANCEL). In earlier SMB Protocol dialects, the MID was defined as
/// a number that uniquely identified a protocol request and response within a
/// process (see [SMB-LM1X]). In CIFS, except where noted, a client MAY have
/// multiple outstanding requests (within the limit set by the MaxMPXCount
/// connection value) with the same PID and MID values. Clients inform servers
/// of the creation of a new thread simply by introducing a new MID into the
/// dialog.
///
/// Multiplex IDs (MIDs) are generated on CIFS clients. The generation of MIDs
/// MUST satisfy the following constraints:
/// - The MID MUST be a 16-bit opaque value.
/// - The MID MUST be unique with respect to a valid client PID over a single
///   SMB connection.
/// - The PID/MID pair MUST remain valid as long as there are outstanding
///   requests on the server identified by that PID/MID pair.
/// - The value 0xFFFF MUST NOT be used as a valid MID. All other possible
///   values for MID, including zero (0x0000), are valid. The value 0xFFFF is
///   used in an OpLock Break Notification request, which is an
///   SMB_COM_LOCKING_ANDX Request sent from the server.
pub const MID = i16;

/// Process ID.
/// The PID is assigned by the client. The client SHOULD set this to a value
/// that identifies the process on the client node that initiated the request.
/// The server MUST return both the PID and the MID to the client in any
/// response to a client request. Clients inform servers of the creation of a
/// new process simply by introducing a new PID into the dialog. In CIFS, the
/// PID is a 32-bit value constructed by combining two 16-bit fields (PIDLow and
/// PIDHigh) in the SMB Header.
///
/// Process IDs (PIDs) are generated on the CIFS client. The generation of PIDs
/// MUST satisfy the following constraints:
/// - The PID MUST be a 32-bit opaque value. The PID value is transferred in two
///   fields (PIDHigh and PIDLow) in the SMB Header.
/// - The PID MUST be unique within a specified client/server SMB connection.
/// - The PID MUST remain valid as long as there are outstanding client requests
///   at the server.
/// - The value 0xFFFF MUST NOT be used as a valid PIDLow. All other possible
///   values for PID, including zero (0x0000), are valid. The PIDLow value
///   0xFFFF is used in an OpLock Break Notification request, which is an
///   SMB_COM_LOCKING_ANDX Request sent from the server.
///
/// In earlier dialects of the SMB Protocol, the PID value was a 16-bit unsigned
/// value. The NT LAN Manager dialect introduced the use of the PIDHigh header
/// field to extend the PID value to 32 bits.
pub const PID = i32;

/// Connection ID.
/// If a connectionless transport is in use, the Connection ID (CID) is
/// generated by the server and passed in the SMB Header of every subsequent SMB
/// message to identify the SMB connection to which the message belongs.
///
/// In order to support CIFS over connectionless transport, such as Direct IPX,
/// CIFS servers MUST support the generation of Connection IDs (CIDs). The
/// generation of CIDs MUST satisfy the following constraints:
/// - The CID MUST be a 16-bit opaque value.
/// - The CID MUST be unique across all SMB connections carried over
///   connectionless transports.
/// - The CID MUST remain valid for the lifetime of the SMB connection.
/// - Once the connection has been closed, the CID value can be reused for
///   another SMB connection.
/// - The values 0x0000 and 0xFFFF MUST NOT be used as valid CIDs. All other
///   possible values for CID are valid.
pub const CID = i32;

/// Search ID.
/// A search ID (also known as a SID) is similar to a FID. It identifies an open
/// directory search, the state of which is maintained on the server. Open SIDs
/// MUST be unique to the SMB connection.
///
/// Search IDs (SIDs) are generated on CIFS servers. The generation of SIDs MUST
/// satisfy the following constraints:
/// - The SID MUST be a 16-bit opaque value for a specific TRANS2_FIND_FIRST2
///   Request.
/// - The SID MUST be unique for a specified client/server SMB connection.
/// - The SID MUST remain valid for the lifetime of the SMB connection while the
///   search operation is being performed, or until the client sends a request
///   to the server to close the SID.
/// - Once a SID has been closed, the value can be reused by another
///   TRANS2_FIND_FIRST2 Request.
/// - The value 0xFFFF MUST NOT be used as a valid SID. All other possible
///   values for SID, including zero (0x0000), are valid. The value 0xFFFF is
///   reserved.
///
/// The acronym SID is also used to indicate a session ID. The two usages appear
/// in completely different contexts.
pub const SID = i32;

/// SessionKey.
/// A Session Key is returned in the SMB_COM_NEGOTIATE response received during
/// establishment of the SMB connection. This Session Key is used to logically
/// bind separate virtual circuits (VCs) together. This Session Key is not used
/// in any authentication or message signing. It is returned to the server in
/// the SMB_COM_SESSION_SETUP_ANDX request messages that are used to create SMB
/// sessions.
///
/// The term "Session Key" also refers to a cryptographic secret key used to
/// perform challenge/response authentication and is also used in the message
/// signing algorithm. For each SMB session, the Session Key is the LM or NTLM
/// password hash used in the generation of the response from the
/// server-supplied challenge. The Session Key used in the first successful user
/// authentication (non-anonymous, non-guest) becomes the signing Session Key
/// for the SMB connection.
///
/// The term session key, in this context, does not refer to the cryptographic
/// session keys used in authentication and message signing. Rather, it refers
/// to the SessionKey unique identifier sent by the server in the
/// SMB_COM_NEGOTIATE Response.
///
/// Virtual circuit session keys (SessionKeys) are generated on CIFS servers.
/// The generation of SessionKeys SHOULD satisfy the following constraints:
/// - The SessionKey MUST be a 32-bit opaque value generated by the CIFS server
///   for a particular SMB connection, and returned in the SMB_COM_NEGOTIATE
///   Response for that connection.
/// - The SessionKey MUST be unique for a specified client/server SMB
///   connection.
/// - The SessionKey MUST remain valid for the lifetime of the SMB connection.
/// - Once the SMB connection has been closed, the SessionKey value can be
///   reused.
/// - There are no restrictions on the permitted values of SessionKey. A value
///   of 0x00000000 suggests, but does not require, that the server ignore the
///   SessionKey.
pub const SESSION_KEY = i32;

/// Tree ID.
/// A TID represents an open connection to a share, otherwise known as a tree
/// connect. An open TID MUST be unique within an SMB connection.
///
/// Tree IDs (TIDs) are generated on CIFS servers. The generation of TIDs MUST
/// satisfy the following constraints:
/// - The TID MUST be a 16-bit opaque value.
/// - The TID MUST be unique within a specified client/server SMB connection.
/// - The TID MUST remain valid for the lifetime of the SMB connection on which
///   the tree connect request is performed, or until the client sends a request
///   to the server to close the TID.
/// - Once a TID has been closed, the value can be reused in the response to
///   another tree connect request.
/// - The value 0xFFFF MUST NOT be used as a valid TID. All other possible
///   values for TID, including zero (0x0000), are valid. The value 0xFFFF is
///   used to specify all TIDs or no TID, depending upon the context in which it
///   is used.
pub const TID = i16;

/// User ID.
/// A UID represents an authenticated SMB session (including those created using
/// anonymous or guest authentication). Some implementations refer to this value
/// as a Virtual User ID (VUID) to distinguish it from the user IDs used by the
/// underlying account management system.
///
/// User IDs (UIDs) are generated on CIFS servers. The generation of UIDs MUST
/// satisfy the following constraints:
/// - The UID MUST be a 16-bit opaque value.
/// - The UID MUST be unique for a specified client/server SMB connection.
/// - The UID MUST remain valid for the lifetime of the SMB connection on which
///   the authentication is performed, or until the client sends a request to
///   the server to close the UID (to log off the user).
/// - Once a UID has been closed, the value can be reused in the response to
///   another authentication request.
/// - The value 0xFFFE was declared reserved in the LAN Manager 1.0
///   documentation, so a value of 0xFFFE SHOULD NOT be used as a valid UID. All
///   other possible values for a UID, excluding zero (0x0000), are valid.
pub const UID = i16;
pub const VUID = UID;

pub const SMB_COM = u8;

pub const SMB_FLAGS = u8;

pub const SMB_FLAGS2 = u16;

/// SMB Messages are divisible into three parts:
/// - A fixed-length header
/// - A variable length parameter block
/// - A variable length data block
/// The header identifies the message as an SMB message, specifies the command
/// to be executed, and provides context. In a response message, the header also
/// includes status information that indicates whether (and how) the command
/// succeeded or failed.
/// The parameter block is a short array of two-byte values (words), while the
/// data block is an array of up to 64 KB in size. The structure and contents of
/// these blocks are specific to each SMB message.
/// SMB messages are structured this way because the protocol was originally
/// conceived of as a rudimentary remote procedure call system. The parameter
/// values were meant to represent the parameters passed into a function. The
/// data section would contain larger structures or data buffers, such as the
/// block of data to be written using an SMB_COM_WRITE command. Although the
/// protocol has evolved over time, this differentiation has been generally
/// maintained.
pub const SMB_MESSAGE = [*]u8;

// STRUCTS & ENUMS

/// The SMB_GEA data structure is used in Transaction2 subcommand
/// requests to request specific extended attribute (EA) name/value pairs by
/// name. This structure is used when the SMB_INFO_QUERY_EAS_FROM_LIST
/// information level is specified. "GEA" stands for "get extended attribute".
pub const SmbGea = extern struct {
    /// This field MUST contain the length, in bytes (excluding the
    /// trailing null padding byte), of the AttributeName field.
    ///
    /// @note The unit of measurement is the byte (b).
    attribute_name_length: u8,

    /// This field contains the name, in extended ASCII (OEM) characters,
    /// of an extended attribute. The length of the name MUST NOT exceed 255
    /// bytes. An additional byte is added to store a null padding byte. This
    /// field MAY be interpreted as an OEM_STRING.
    ///
    /// @note The unit of measurement is the byte (b).
    ///
    /// @warning When such structure is being sent over the wire, and even more
    /// when it gets concatenated in an SMB GEAList, all attribute names MUST BE
    /// trimmed of their remaning right zeroes that were stack allocated but not
    /// used.
    ///
    /// @note Maximum characters : SMB_GEA_ATTR_NAME_MAX_LEN
    attribute_name: [*]u8,
};

/// The SMB_GEA_LIST data structure is used to send a concatenated list
/// of SMB_GEA structures.
pub const SmbGeaList = extern struct {
    /// This field MUST contain the total size of the GEAList field, plus
    /// the size of the SizeOfListInBytes field (4 bytes).
    ///
    /// @note The unit of measurement is the byte (b).
    size_of_list: u64,

    /// A concatenated list of SMB_GEA structures.
    gea_list: [*]u8,
};

/// The SMB_FEA data structure is used in Transaction2 subcommands and in
/// the NT_TRANSACT_CREATE subcommand to encode an extended attribute (EA)
/// name/value pair. "FEA" stands for "full extended attribute".
pub const SmbFea = extern struct {
    /// This is a bit field. Only the 0x80 bit is defined.
    ///
    /// 0x7F : Reserved.
    ///
    /// 0x80 : If set (1), this bit indicates that extended attribute (EA)
    ///        support is required on this file. Otherwise, EA support is not
    ///        required. If this flag is set, the file to which the EA belongs
    ///        cannot be properly interpreted without understanding the
    ///        associated extended attributes.
    ///        A CIFS client that supports EAs can set this bit when adding an
    ///        EA to a file residing on a server that also supports EAs. The
    ///        server MUST NOT allow this bit to be set on an EA associated with
    ///        directories.
    ///        If this bit is set on any EA associated with a file on the
    ///        server, the server MUST reject client requests to open the file
    ///        (except to truncate the file) if the SMB_FLAGS2_EAS flag is not
    ///        set in the request header. In this case, the server SHOULD fail
    ///        this request with STATUS_ACCESS_DENIED (ERRDOS/ERRnoaccess) in
    ///        the Status field of the SMB Header in the server response.
    extended_attribute_flag: u8,

    /// This field MUST contain the length, in bytes, of the
    /// AttributeName field (excluding the trailing null byte).
    ///
    /// @note The unit of measurement is the byte (b).
    attribute_name_length: u8,

    /// This field MUST contain the length, in bytes, of the
    /// AttributeValue field.
    ///
    /// @note The unit of measurement is the byte (b).
    attribute_value_length: u16,

    /// This field contains the name, in extended ASCII (OEM) characters,
    /// of an extended attribute. The length of the name MUST NOT exceed 255
    /// bytes. An additional byte is added to store a null padding byte. This
    /// field MAY be interpreted as an OEM_STRING.
    ///
    /// @warning When such structure is being sent over the wire, and even more
    /// when it gets concatenated in an SMB FEAList, all attribute names MUST BE
    /// trimmed of their remaning right zeroes that were stack allocated but not
    /// used.
    ///
    /// @note Maximum characters : SMB_FEA_ATTR_NAME_MAX_LEN
    attribute_name: [*]u8,

    /// This field contains the value of an extended file attribute. The
    /// value is expressed as an array of extended ASCII (OEM) characters. This
    /// array MUST NOT be null-terminated, and its length MUST NOT exceed 65,535
    /// bytes.
    ///
    /// @warning When such structure is being sent over the wire, and even more
    /// when it gets concatenated in an SMB FEAList, all attribute names MUST BE
    /// trimmed of their remaning right zeroes that were stack allocated but not
    /// used.
    ///
    /// @note Maximum characters : SMB_FEA_ATTR_VALUE_MAX_LEN
    attribute_value: [*]u8,
};

/// The SMB_FEA_LIST data structure is used to send a concatenated list
/// of SMB_FEA structures.
pub const SmbFeaList = extern struct {
    /// This field MUST contain the total size of the FEAList field, plus
    /// the size of the SizeOfListInBytes field (4 bytes).
    size_of_list: u64,

    /// A concatenated list of SMB_FEA structures.
    fea_list: [*]u8,
};

/// A 32-bit field containing encoded file attribute values and file
/// access behavior flag values. The attribute and flag value names are for
/// reference purposes only. If ATTR_NORMAL (see following) is set as the
/// requested attribute value, it MUST be the only attribute value set.
/// Including any other attribute value causes the ATTR_NORMAL value to be
/// ignored. Any combination of the flag values (see following) is acceptable.
pub const SmbExtFileAttr = enum(u32) {
    /// The file is read only. Applications can read the file but cannot
    /// write to it or delete it.
    ATTR_READONLY = 0x00000001,

    /// The file is hidden. It is not to be included in an ordinary
    /// directory listing.
    ATTR_HIDDEN = 0x00000002,

    /// The file is part of or is used exclusively by the operating
    /// system.
    ATTR_SYSTEM = 0x00000004,

    /// The file is a directory.
    ATTR_DIRECTORY = 0x00000010,

    /// The file has not been archived since it was last modified.
    ATTR_ARCHIVE = 0x00000020,

    /// The file has no other attributes set. This attribute is valid
    /// only if used alone.
    ATTR_NORMAL = 0x00000080,

    /// The file is temporary. This is a hint to the cache manager that
    /// it does not need to flush the file to backing storage.
    ATTR_TEMPORARY = 0x00000100,

    /// The file or directory is compressed. For a file, this means that
    /// all of the data in the file is compressed. For a directory, this means
    /// that compression is the default for newly created files and
    /// subdirectories.
    ATTR_COMPRESSED = 0x00000800,

    /// Indicates that the file is to be accessed according to POSIX
    /// rules. This includes allowing multiple files with names differing only
    /// in case, for file systems that support such naming.
    POSIX_SEMANTICS = 0x01000000,

    /// Indicates that the file is being opened or created for a backup
    /// or restore operation. The server SHOULD allow the client to override
    /// normal file security checks, provided it has the necessary permission to
    /// do so.
    BACKUP_SEMANTICS = 0x02000000,

    /// Requests that the server delete the file immediately after all of
    /// its handles have been closed.
    DELETE_ON_CLOSE = 0x04000000,

    /// Indicates that the file is to be accessed sequentially from
    /// beginning to end.
    SEQUENTIAL_SCAN = 0x08000000,

    /// Indicates that the application is designed to access the file
    /// randomly. The server can use this flag to optimize file caching.
    RANDOM_ACCESS = 0x10000000,

    /// Requests that the server open the file with no intermediate
    /// buffering or caching; the server might not honor the request. The
    /// application MUST meet certain requirements when working with files
    /// opened with FILE_FLAG_NO_BUFFERING. File access MUST begin at offsets
    /// within the file that are integer multiples of the volume's sector size
    /// and MUST be for numbers of bytes that are integer multiples of the
    /// volume's sector size. For example, if the sector size is 512 bytes, an
    /// application can request reads and writes of 512, 1024, or 2048 bytes,
    /// but not of 335, 981, or 7171 bytes.
    NO_BUFFERING = 0x20000000,

    /// Instructs the operating system to write through any intermediate
    /// cache and go directly to the file. The operating system can still cache
    /// write operations, but cannot lazily flush them.
    WRITE_THROUGH = 0x80000000,
};

/// An unsigned 16-bit field that defines the basic file attributes
/// supported by the SMB Protocol. In addition, exclusive search attributes
/// (those Names prefixed with SMB_SEARCH_ATTRIBUTE) are defined for use when
/// searching for files within a directory.
pub const SmbFileAttributes = enum(u16) {
    /// Normal file.
    SMB_FILE_ATTRIBUTE_NORMAL = 0x0000,

    /// Read-only file.
    SMB_FILE_ATTRIBUTE_READONLY = 0x0001,

    /// Hidden file.
    SMB_FILE_ATTRIBUTE_HIDDEN = 0x0002,

    /// System file.
    SMB_FILE_ATTRIBUTE_SYSTEM = 0x0004,

    /// Volume Label.
    SMB_FILE_ATTRIBUTE_VOLUME = 0x0008,

    /// Directory file.
    SMB_FILE_ATTRIBUTE_DIRECTORY = 0x0010,

    /// File changed since last archive.
    SMB_FILE_ATTRIBUTE_ARCHIVE = 0x0020,

    /// Search for Read-only files.
    SMB_SEARCH_ATTRIBUTE_READONLY = 0x0100,

    /// Search for Hidden files.
    SMB_SEARCH_ATTRIBUTE_HIDDEN = 0x0200,

    /// Search for System files.
    SMB_SEARCH_ATTRIBUTE_SYSTEM = 0x0400,

    /// Search for Directory files.
    SMB_SEARCH_ATTRIBUTE_DIRECTORY = 0x1000,

    /// Search for files that have changed since they were last archived.
    SMB_SEARCH_ATTRIBUTE_ARCHIVE = 0x2000,

    /// Reserved.
    SMB_FILE_ATTRIBUTE_OTHER = 0xC8C0,
};

/// The SMB_NMPIPE_STATUS data type is a 16-bit field that encodes the
/// status of a named pipe. Any combination of the following flags MUST be
/// valid. The ReadMode and NamedPipeType bit fields are defined as 2-bit
/// integers. Subfields marked Reserved SHOULD be set to zero by the server and
/// MUST be ignored by the client.
pub const SmbNmpipeStatus = enum(u16) {
    /// An 8-bit unsigned integer that gives the maximum number of
    /// instances the named pipe can have.
    I_COUNT = 0x000FF,

    /// @brief
    /// 0 : This bit field indicates the client read mode for the named pipe.
    /// This bit field has no effect on writes to the named pipe. A value of
    /// zero indicates that the named pipe was opened in or set to byte mode by
    /// the client.
    ///
    /// 1 : A value of 1 indicates that the client opened or set the named pipe
    /// to message mode.
    ///
    /// 2, 3 : Reserved. Bit 0x0200 MUST be ignored.
    READ_MODE = 0x0300,

    /// @brief
    ///
    /// 0 : This bit field indicates the type of the named pipe when the named
    /// pipe was created by the server. A value of zero indicates that the named
    /// pipe was created as a byte mode pipe.
    ///
    /// 1 : The named pipe was created by the server as a message mode pipe.
    ///
    /// 2,3 : Reserved. Bit 0x0800 MUST be ignored.
    NAMED_PIPE_TYPE = 0x0C00,

    /// @brief
    ///
    /// 0 : Client-side end of the named pipe. The SMB server MUST clear the
    /// Endpoint bit (set it to zero) when responding to the client request
    /// because the CIFS client is a consumer requesting service from the named
    /// pipe. When this bit is clear, it indicates that the client is accessing
    /// the consumer endpoint.
    ///
    /// 1 : Indicates the server end of the pipe.
    ENDPOINT = 0x4000,

    /// @brief
    ///
    /// 0 : A named pipe read or raw read request will wait (block) until
    /// sufficient data to satisfy the read request becomes available, or until
    /// the request is canceled.
    /// A named pipe write or raw write request blocks until its data is
    /// consumed, if the write request length is greater than zero.
    ///
    /// 1 : A read or a raw read request returns all data available to be read
    /// from the named pipe, up to the maximum read size set in the request.
    /// Write operations return after writing data to named pipes without
    /// waiting for the data to be consumed.
    /// Named pipe non-blocking raw writes are not allowed. Raw writes MUST be
    /// performed in blocking mode.
    NONBLOCKING = 0x8000,
};

/// This is a 16-bit value in little-endian byte order used to encode a
/// date. An SMB_DATE value SHOULD be interpreted as follows. The date is
/// represented in the local time zone of the server. The following field names
/// are provided for reference only.
pub const SmbDate = enum(u16) {
    /// The year. Add 1980 to the resulting value to return the actual
    /// year.
    YEAR = 0xFE00,

    /// The month. Values range from 1 to 12.
    MONTH = 0x01E0,

    /// The date. Values range from 1 to 31.
    DAY = 0x001F,
};

/// This is a 16-bit value in little-endian byte order used to encode a
/// time of day. The SMB_TIME value is usually accompanied by an SMB_DATE value
/// that indicates what date corresponds with the specified time. An SMB_TIME
/// value SHOULD be interpreted as follows. The field names below are provided
/// for reference only. The time is represented in the local time zone of the server.
pub const SmbTime = enum(u16) {
    /// The hours. Values range from 0 to 23.
    HOUR = 0xF800,

    /// The minutes. Values range from 0 to 59.
    MINUTES = 0x07E0,

    /// The seconds. Values MUST represent two-second increments.
    SECONDS = 0x001F,
};

/// This is a 32-bit unsigned integer in little-endian byte order
/// indicating the number of seconds since Jan 1, 1970, 00:00:00.0.
pub const SmbErrorClass = enum(u8) {
    ERRCLS_SUCCESS = 0x00,
    ERRCLS_DOS = 0x01,
    ERRCLS_SRV = 0x02,
    ERRCLS_HRD = 0x03,
    ERRCLS_CMD = 0xFF,
};

pub const SmbErrorCode = enum(u16) {
    /// Everything worked, no problems.
    ERR_SUCCESS = 0x0000,

    /// Invalid Function.
    ERRDOS_BAD_FUNC = 0x0001,

    /// File not found.
    ERRDOS_BAD_FILE = 0x0002,

    /// A component in the path prefix is not a directory.
    ERRDOS_BAD_PATH = 0x0003,

    /// Too many open files. No FIDs are available.
    ERRDOS_NOFIDS = 0x0004,

    /// Access denied.
    ERRDOS_NOACCESS = 0x0005,

    /// Invalid FID.
    ERRDOS_BAD_FID = 0x0006,

    /// Memory Control Blocks were destroyed.
    ERRDOS_BAD_MCB = 0x0007,

    /// Insufficient server memory to perform the requested operation.
    ERRDOS_NOMEM = 0x0008,

    /// The server performed an invalid memory access (invalid address).
    ERRDOS_BAD_MEM = 0x0009,

    /// Invalid environment.
    ERRDOS_BAD_ENV = 0x000A,

    /// Invalid format.
    ERRDOS_BAD_FORMAT = 0x000B,

    /// Invalid open mode.
    ERRDOS_BAD_ACCESS = 0x000C,

    /// Bad data. (May be generated by IOCTL calls on the server.)
    ERRDOS_BAD_DATA = 0x000D,

    /// Invalid drive specified.
    ERRDOS_BAD_DRIVE = 0x000F,

    /// Remove of directory failed because it was not empty.
    ERRDOS_REMCD = 0x0010,

    /// A file system operation (such as a rename) across two devices was
    /// attempted.
    ERRDOS_DIFF_DEVICE = 0x0011,

    /// No (more) files found following a file search command.
    ERRDOS_NO_FILE = 0x0012,

    /// General error.
    ERRDOS_GENERAL = 0x001F,

    /// Sharing violation. A requested open mode conflicts with the
    /// sharing mode of an existing file handle.
    ERRDOS_BAD_SHARE = 0x0020,

    /// A lock request specified an invalid locking mode, or conflicted
    /// with an existing file lock.
    ERRDOS_LOCK = 0x0021,

    /// Attempted to read beyond the end of the file.
    ERRDOS_EOF = 0x0026,

    /// This command is not supported by the server.
    ERRDOS_UNSUP = 0x0032,

    /// An attempt to create a file or directory failed because an object
    /// with the same pathname already exists.
    ERRDOS_FILE_EXISTS = 0x0050,

    /// A parameter supplied with the message is invalid.
    ERRDOS_INVALID_PARAM = 0x0057,

    /// Invalid information level.
    ERRDOS_UNKNOWN_LEVEL = 0x007C,

    /// An attempt was made to seek to a negative absolute offset within
    /// a file.
    ERRDOS_INVALID_SEEK = 0x0083,

    /// The byte range specified in an unlock request was not locked.
    ERRDOS_NOT_LOCKED = 0x009E,

    /// Maximum number of searches has been exhausted.
    ERRDOS_NO_MORE_SEARCH_HANDLES = 0x0071,

    /// No lock request was outstanding for the supplied cancel region.
    ERRDOS_CANCEL_VIOLATION = 0x00AD,

    /// The file system does not support atomic changes to the lock type.
    ERRDOS_ATOMIC_LOCKS_NOT_SUPPORTED = 0x00AE,

    /// Invalid named pipe.
    ERRDOS_BAD_PIPE = 0x00E6,

    /// The copy functions cannot be used.
    ERRDOS_CANNOT_COPY = 0x010A,

    /// All instances of the designated named pipe are busy.
    ERRDOS_PIPE_BUSY = 0x00E7,

    /// The designated named pipe is in the process of being closed.
    ERRDOS_PIPE_CLOSING = 0x00E8,

    /// The designated named pipe exists, but there is no server process
    /// listening on the server side.
    ERRDOS_NOT_CONNECTED = 0x00E9,

    /// There is more data available to read on the designated named
    /// pipe.
    ERRDOS_MORE_DATA = 0x00EA,

    /// Inconsistent extended attribute list.
    ERRDOS_BAD_EA_LIST = 0x00FF,

    /// Either there are no extended attributes, or the available
    /// extended attributes did not fit into the response.
    ERRDOS_EAS_DIDNT_FIT = 0x0113,

    /// The server file system does not support Extended Attributes.
    ERRDOS_EAS_NOT_SUPPORTED = 0x011A,

    /// Access to the extended attribute was denied.
    ERRDOS_EA_ACCESS_DENIED = 0x03E2,

    /// More changes have occurred within the directory than will fit
    /// within the specified Change Notify response buffer.
    ERRDOS_NOTIFY_ENUM_DIR = 0x03FE,

    /// An unknown SMB command code was received by the server.
    ERRSRV_BAD_CMD = 0x0016,

    /// Print queue is full - too many queued items.
    ERRSRV_QUEUE_FULL = 0x0031,

    /// End Of File on print queue dump.
    ERRSRV_QUEUE_EOF = 0x0033,

    /// Invalid FID for print file.
    ERRSRV_INV_PRINT_FID = 0x0034,

    /// Unrecognized SMB command code.
    ERRSRV_SMB_CMD = 0x0040,

    /// Internal server error.
    ERRSRV_SRV_ERROR = 0x0041,

    /// The FID and pathname contain incompatible values.
    ERRSRV_FILE_SPECS = 0x0043,

    /// An invalid combination of access permissions for a file or
    /// directory was presented. The server cannot set the requested attributes.
    ERRSRV_BAD_PERMITS = 0x0045,

    /// The attribute mode presented in a set mode request was invalid.
    ERRSRV_SET_ATTR_MODE = 0x0047,

    /// Operation timed out.
    ERRSRV_TIMEOUT = 0x0058,

    /// No resources currently available for this SMB request.
    ERRSRV_NO_RESOURCE = 0x0059,

    /// Too many UIDs active for this SMB connection.
    ERRSRV_TOO_MANY_UIDS = 0x005A,

    /// The UID specified is not known as a valid ID on this server
    /// session.
    ERRSRV_BAD_UID = 0x005B,

    /// Temporarily unable to support RAW mode transfers. Use MPX mode.
    ERRSRV_USE_MPX = 0x00FA,

    /// Temporarily unable to support RAW or MPX mode transfers. Use
    /// standard read/write.
    ERRSRV_USE_STD = 0x00FB,

    /// Continue in MPX mode.
    ///
    /// @note This error code is reserved for future use.
    ERRSRV_CONT_MPX = 0x00FC,

    /// User account on the target machine is disabled or has expired.
    ERRSRV_ACCOUNT_EXPIRED = 0x08BF,

    /// The client does not have permission to access this server.
    ERRSRV_BAD_CLIENT = 0x08C0,

    /// Access to the server is not permitted at this time.
    ERRSRV_BAD_LOGON_TIME = 0x08C1,

    /// The user's password has expired.
    ERRSRV_PASSWORD_EXPIRED = 0x08C2,

    /// Function not supported by the server.
    ERRSRV_NO_SUPPORT = 0xFFFF,

    /// Attempt to modify a read-only file system.
    ERRHDR_NO_WRITE = 0x0013,

    /// Unknown unit.
    ERRHDR_BAD_UNIT = 0x0014,

    /// Drive not ready.
    ERRHDR_NOT_READY = 0x0015,

    /// Data error (incorrect CRC).
    ERRHDR_DATA = 0x0017,

    /// Bad request structure length.
    ERRHDR_BAD_REQUEST = 0x0018,

    /// Seek error.
    ERRHDR_SEEK = 0x0019,

    /// Unknown media type.
    ERRHDR_BAD_MEDIA = 0x001A,

    /// Sector not found.
    ERRHDR_BAD_SECTOR = 0x001B,

    /// Printer out of paper.
    ERRHDR_NO_PAPER = 0x001C,

    /// Write fault.
    ERRHDR_WRITE = 0x001D,

    /// Read fault.
    ERRHDR_READ = 0x001E,

    /// The wrong disk was found in a drive.
    ERRHDR_WRONG_DISK = 0x0022,

    /// No server-side File Control Blocks are available to process the
    /// request.
    ERRHDR_FCB_UNAVAILABLE = 0x0023,

    /// A sharing buffer has been exceeded.
    ERRHDR_SHARE_BUFFER_EXCEEDED = 0x0024,

    /// No space on file system.
    ERRHDR_DISK_FULL = 0x0027,

    /// Unspecified server error.
    pub const ERRSRV_ERROR: SmbErrorCode = .ERRDOS_BAD_FUNC;

    /// Invalid password.
    pub const ERRSRV_BAD_PW: SmbErrorCode = .ERRDOS_BAD_FILE;

    /// DFS pathname not on local server.
    pub const ERRSRV_BAD_PATH: SmbErrorCode = .ERRDOS_BAD_PATH;

    /// Access denied. The specified UID does not have permission to
    /// execute the requested command within the current context (TID).
    pub const ERRSRV_ACCESS: SmbErrorCode = .ERRDOS_NOFIDS;

    /// The TID specified in the command was invalid. Earlier
    /// documentation, with the exception of [SNIA], refers to this error code
    /// as ERRinvnid (Invalid Network Path Identifier). [SNIA] uses both names.
    pub const ERRSRV_INV_TID: SmbErrorCode = .ERRDOS_NOACCESS;

    /// Invalid server name in Tree Connect.
    pub const ERRSRV_INV_NET_NAME: SmbErrorCode = .ERRDOS_BAD_FID;

    /// A printer request was made to a non-printer device or,
    /// conversely, a non-printer request was made to a printer device.
    pub const ERRSRV_INV_DEVICE: SmbErrorCode = .ERRDOS_BAD_MCB;

    /// Invalid Connection ID (CID). This error code is only defined when
    /// the Direct IPX connectionless transport is in use.
    pub const ERRSRV_INV_SESSION: SmbErrorCode = .ERRDOS_REMCD;

    /// A command with matching MID or SequenceNumber is currently being
    /// processed. This error code is defined only when the Direct IPX
    /// connectionless transport is in use.
    pub const ERRSRV_WORKING: SmbErrorCode = .ERRDOS_DIFF_DEVICE;

    /// Incorrect NetBIOS Called Name when starting an SMB session over
    /// Direct IPX. This error code is only defined when the Direct IPX
    /// connectionless transport is in use.
    pub const ERRSRV_NOT_ME: SmbErrorCode = .ERRDOS_NO_FILE;

    /// Print queue is full - no space for queued item, or queued item
    /// too big.
    pub const ERRSRV_QUEUE_TOO_BIG: SmbErrorCode = .ERRDOS_UNSUP;

    /// Write to a named pipe with no reader.
    pub const ERRSRV_NOT_CONNECTED: SmbErrorCode = .ERRDOS_NOT_CONNECTED;

    /// Unknown command.
    pub const ERRHDR_BAD_CMD: SmbErrorCode = .ERRSRV_BAD_CMD;

    /// General hardware failure.
    pub const ERRHDR_GENERAL: SmbErrorCode = .ERRDOS_GENERAL;

    /// An attempted open operation conflicts with an existing open.
    pub const ERRHDR_BAD_SHARE: SmbErrorCode = .ERRDOS_BAD_SHARE;

    /// A lock request specified an invalid locking mode, or conflicted
    /// with an existing file lock.
    pub const ERRHDR_LOCK: SmbErrorCode = .ERRDOS_LOCK;
};

/// An SMB_ERROR MUST be interpreted in one of two ways, depending on the
/// capabilities negotiated between client and server: either as an NTSTATUS
/// value (a 32-bit value in little-endian byte order used to encode an error
/// message, as defined in [MS-ERREF] section 2.3), or as an SMBSTATUS value (as
/// defined following).
pub const SmbError = extern struct {
    /// An SMB error class code.
    error_class: SmbErrorClass = .ERRCLS_SUCCESS,

    /// This field is reserved and MUST be ignored by both server and
    /// client.
    _reserved: u8 = 0x00,

    /// An SMB error code.
    error_code: SmbErrorCode = .ERR_SUCCESS,
};

/// Following is a listing of all SMB commands used in CIFS and their
/// associated command codes.
pub const SmbCom = enum(u8) {
    /// Create a new directory.
    ///
    /// @note Deprecated.
    SMB_COM_CREATE_DIRECTORY = 0x00,

    /// Delete an empty directory.
    SMB_COM_DELETE_DIRECTORY = 0x01,

    /// Open a file.
    ///
    /// @note Deprecated.
    SMB_COM_OPEN = 0x02,

    /// Create or open a file.
    ///
    /// @note Deprecated.
    SMB_COM_CREATE = 0x03,

    /// Close a file.
    SMB_COM_CLOSE = 0x04,

    /// Flush data for a file, or all files associated with a client, PID
    /// pair.
    SMB_COM_FLUSH = 0x05,

    /// Delete a file.
    SMB_COM_DELETE = 0x06,

    /// Rename a file or set of files.
    SMB_COM_RENAME = 0x07,

    /// Get file attributes.
    ///
    /// @note Deprecated.
    SMB_COM_QUERY_INFORMATION = 0x08,

    /// Set file attributes.
    ///
    /// @note Deprecated.
    SMB_COM_SET_INFORMATION = 0x09,

    /// Read from a file.
    ///
    /// @note Deprecated.
    SMB_COM_READ = 0x0A,

    /// Write from a file.
    ///
    /// @note Deprecated.
    SMB_COM_WRITE = 0x0B,

    /// Request a byte-range lock on a file.
    ///
    /// @note Deprecated.
    SMB_COM_LOCK_BYTE_RANGE = 0x0C,

    /// Release a byte-range lock on a file.
    ///
    /// @note Deprecated.
    SMB_COM_UNLOCK_BYTE_RANGE = 0x0D,

    /// Create a temporary file.
    ///
    /// @note Obselescent.
    SMB_COM_CREATE_TEMPORARY = 0x0E,

    /// Create and open a new file.
    ///
    /// @note Deprecated.
    SMB_COM_CREATE_NEW = 0x0F,

    /// Verify that the specified pathname resolves to a directory.
    SMB_COM_CHECK_DIRECTORY = 0x10,

    /// Indicate process exit.
    ///
    /// @note Obselescent.
    SMB_COM_PROCESS_EXIT = 0x11,

    /// Set the current file pointer within a file.
    ///
    /// @note Obselescent.
    SMB_COM_SEEK = 0x12,

    /// Lock and read a byte-range within a file.
    ///
    /// @note Deprecated.
    SMB_COM_LOCK_AND_READ = 0x13,

    /// Write and unlock a byte-range within a file.
    ///
    /// @note Deprecated.
    SMB_COM_WRITE_AND_UNLOCK = 0x14,

    /// Read a block in raw mode.
    ///
    /// @note Deprecated.
    SMB_COM_READ_RAW = 0x1A,

    /// Multiplexed block read.
    ///
    /// @note Obselescent.
    SMB_COM_READ_MPX = 0x1B,

    /// Multiplexed block read, secondary request.
    ///
    /// @note Obselete.
    SMB_COM_READ_MPX_SECONDARY = 0x1C,

    /// Write a block in raw mode.
    ///
    /// @note Deprecated.
    SMB_COM_WRITE_RAW = 0x1D,

    /// Multiplexed block write.
    ///
    /// @note Obselescent.
    SMB_COM_WRITE_MPX = 0x1E,

    /// Multiplexed block write, secondary request.
    ///
    /// @note Obselete.
    SMB_COM_WRITE_MPX_SECONDARY = 0x1F,

    /// Raw block write, final response.
    ///
    /// @note Deprecated.
    SMB_COM_WRITE_COMPLETE = 0x20,

    /// Reserved, but not implemented.
    ///
    /// @note Not implemented.
    SMB_COM_QUERY_SERVER = 0x21,

    /// Set an extended set of file attributes.
    ///
    /// @note Deprecated.
    SMB_COM_SET_INFORMATION2 = 0x22,

    /// Get an extended set of file attributes.
    ///
    /// @note Deprecated.
    SMB_COM_QUERY_INFORMATION2 = 0x23,

    /// Lock multiple byte ranges; AndX chaining.
    SMB_COM_LOCKING_ANDX = 0x24,

    /// Transaction.
    SMB_COM_TRANSACTION = 0x25,

    /// Transaction secondary request.
    SMB_COM_TRANSACTION_SECONDARY = 0x26,

    /// Pass an I/O Control function request to the server.
    ///
    /// @note Obselescent.
    SMB_COM_IOCTL = 0x27,

    /// IOCTL secondary request.
    ///
    /// @note Not implemented.
    SMB_COM_IOCTL_SECONDARY = 0x28,

    /// Copy a file or directory.
    ///
    /// @note Obselete.
    SMB_COM_COPY = 0x29,

    /// Move a file or directory.
    ///
    /// @note Obselete.
    SMB_COM_MOVE = 0x2A,

    /// Echo request (ping).
    SMB_COM_ECHO = 0x2B,

    /// Write to and close a file.
    ///
    /// @note Deprecated.
    SMB_COM_WRITE_AND_CLOSE = 0x2C,

    /// Extended file open with AndX chaining.
    ///
    /// @note Deprecated.
    SMB_COM_OPEN_ANDX = 0x2D,

    /// Extended file read with AndX chaining.
    SMB_COM_READ_ANDX = 0x2E,

    /// Extended file write with AndX chaining.
    SMB_COM_WRITE_ANDX = 0x2F,

    /// Reserved, but not implemented.
    ///
    /// @note Not implemented.
    SMB_COM_NEW_FILE_SIZE = 0x30,

    /// Close an open file and tree disconnect.
    ///
    /// @note Not implemented.
    SMB_COM_CLOSE_AND_TREE_DISC = 0x31,

    /// Transaction 2 format request/response.
    SMB_COM_TRANSACTION2 = 0x32,

    /// Transaction 2 secondary request.
    SMB_COM_TRANSACTION2_SECONDARY = 0x33,

    /// Close an active search.
    SMB_COM_FIND_CLOSE2 = 0x34,

    /// Notification of the closure of an active search.
    ///
    /// @note Not implemented.
    SMB_COM_FIND_NOTIFY_CLOSE = 0x35,

    /// Tree connect.
    ///
    /// @note Deprecated.
    SMB_COM_TREE_CONNECT = 0x70,

    /// Tree disconnect.
    SMB_COM_TREE_DISCONNECT = 0x71,

    /// Negotiate protocol dialect.
    SMB_COM_NEGOTIATE = 0x72,

    /// Session Setup with AndX chaining.
    SMB_COM_SESSION_SETUP_ANDX = 0x73,

    /// User logoff with AndX chaining.
    SMB_COM_LOGOFF_ANDX = 0x74,

    /// Tree connect with AndX chaining.
    MB_COM_TREE_CONNECT_ANDX = 0x75,

    /// Negotiate security packages with AndX chaining.
    ///
    /// @note Not implemented.
    MB_COM_SECURITY_PACKAGE_ANDX = 0x7E,

    /// Retrieve file system information from the server.
    ///
    /// @note Deprecated.
    SMB_COM_QUERY_INFORMATION_DISK = 0x80,

    /// Directory wildcard search.
    ///
    /// @note Deprecated.
    SMB_COM_SEARCH = 0x81,

    /// Start or continue an extended wildcard directory search.
    ///
    /// @note Deprecated.
    SMB_COM_FIND = 0x82,

    /// Perform a one-time extended wildcard directory search.
    ///
    /// @note Deprecated.
    SMB_COM_FIND_UNIQUE = 0x83,

    /// End an extended wildcard directory search.
    ///
    /// @note Deprecated.
    SMB_COM_FIND_CLOSE = 0x84,

    /// NT format transaction request/response.
    SMB_COM_NT_TRANSACT = 0xA0,

    /// NT format transaction secondary request.
    SMB_COM_NT_TRANSACT_SECONDARY = 0xA1,

    /// Create or open a file or a directory.
    SMB_COM_NT_CREATE_ANDX = 0xA2,

    /// Cancel a request currently pending at the server.
    SMB_COM_NT_CANCEL = 0xA4,

    /// File rename with extended semantics.
    ///
    /// @note Obselescent.
    SMB_COM_NT_RENAME = 0xA5,

    /// Create a print queue spool file.
    SMB_COM_OPEN_PRINT_FILE = 0xC0,

    /// Write to a print queue spool file.
    ///
    /// @note Deprecated.
    SMB_COM_WRITE_PRINT_FILE = 0xC1,

    /// Close a print queue spool file.
    ///
    /// @note Deprecated.
    SMB_COM_CLOSE_PRINT_FILE = 0xC2,

    /// Request print queue information.
    ///
    /// @note Not implemented.
    SMB_COM_GET_PRINT_QUEUE = 0xC3,

    /// Reserved, but not implemented.
    ///
    /// @note Not implemented.
    SMB_COM_READ_BULK = 0xD8,

    /// Reserved, but not implemented.
    ///
    /// @note Not implemented.
    SMB_COM_WRITE_BULK = 0xD9,

    /// Reserved, but not implemented.
    ///
    /// @note Not implemented.
    SMB_COM_WRITE_BULK_DATA = 0xDA,

    /// As the name suggests, this command code is a designated invalid
    /// command and SHOULD NOT be used.
    SMB_COM_INVALID = 0xFE,

    /// Also known as the "NIL" command. It identifies the end of an AndX
    /// Chain, and is only valid in that context.
    SMB_COM_NO_ANDX_COMMAND = 0xFF,
};

/// Transaction Codes used with SMB_COM_TRANSACTION.
pub const SmbTrans = enum(u16) {
    /// Allows a client to write data to a specific mailslot on the
    /// server.
    TRANS_MAILSLOT_WRITE = 0x0001,

    /// Used to set the read mode and non-blocking mode of a specified
    /// named pipe.
    TRANS_SET_NMPIPE_STATE = 0x0001,

    /// Allows for a raw read of data from a named pipe. This method of
    /// reading data from a named pipe ignores message boundaries even if the
    /// pipe was set up as a message mode pipe.
    ///
    /// @note Deprecated.
    TRANS_RAW_READ_NMPIPE = 0x0011,

    /// Allows for a client to retrieve information about a specified
    /// named pipe.
    TRANS_QUERY_NMPIPE_STATE = 0x0021,

    /// Used to retrieve pipe information about a named pipe.
    TRANS_QUERY_NMPIPE_INFO = 0x0022,

    /// Used to copy data out of a named pipe without removing it from
    /// the named pipe.
    TRANS_PEEK_NMPIPE = 0x0023,

    /// Used to execute a transacted exchange against a named pipe. This
    /// transaction has a constraint that it can be used only on a duplex,
    /// message-type pipe.
    TRANS_TRANSACT_NMPIPE = 0x0026,

    /// Allows for a raw write of data to a named pipe. Raw writes to
    /// named pipes put bytes directly into a pipe, regardless of whether it is
    /// a message mode pipe or byte mode pipe.
    ///
    /// @note Deprecated.
    TRANS_RAW_WRITE_NMPIPE = 0x0031,

    /// Allows a client to read data from a named pipe.
    TRANS_READ_NMPIPE = 0x0036,

    /// Allows a client to write data to a named pipe.
    TRANS_WRITE_NMPIPE = 0x0037,

    /// Allows a client to be notified when the specified named pipe is
    /// available to be connected to.
    TRANS_WAIT_NMPIPE = 0x0053,

    /// Connect to a named pipe, issue a write to the named pipe, issue a
    /// read from the named pipe, and close the named pipe.
    TRANS_CALL_NMPIPE = 0x0054,
};

/// Transaction Codes used with SMB_COM_TRANSACTION2.
pub const SmbTrans2 = enum(u16) {
    /// Open or create a file and set extended attributes on the file.
    TRANS2_OPEN2 = 0x0000,

    /// Begin a search for files within a directory or for a directory.
    TRANS2_FIND_FIRST2 = 0x0001,

    /// Continue a search for files within a directory or for a
    /// directory.
    TRANS2_FIND_NEXT2 = 0x0002,

    /// Request information about a file system on the server.
    TRANS2_QUERY_FS_INFORMATION = 0x0003,

    /// Reserved.
    ///
    /// @note Not implemented.
    TRANS2_SET_FS_INFORMATION = 0x0004,

    /// Get information about a specific file or directory using a path.
    TRANS2_QUERY_PATH_INFORMATION = 0x0005,

    /// Set the standard and extended attribute information of a specific
    /// file or directory using a path.
    TRANS2_SET_PATH_INFORMATION = 0x0006,

    /// Get information about a specific file or directory using a FID.
    TRANS2_QUERY_FILE_INFORMATION = 0x0007,

    /// Set the standard and extended attribute information of a specific
    /// file or directory using a FID.
    TRANS2_SET_FILE_INFORMATION = 0x0008,

    /// Reserved.
    ///
    /// @note Not implemented.
    TRANS2_FSCTL = 0x0009,

    /// Reserved.
    ///
    /// @note Not implemented.
    TRANS2_IOCTL2 = 0x000A,

    /// Reserved.
    ///
    /// @note Obselete.
    TRANS2_FIND_NOTIFY_FIRST = 0x000B,

    /// Reserved.
    ///
    /// @note Obselete.
    TRANS2_FIND_NOTIFY_NEXT = 0x000C,

    /// Create a new directory and optionally set the extended attribute
    /// information.
    TRANS2_CREATE_DIRECTORY = 0x000D,

    /// Reserved.
    ///
    /// @note Not implemented.
    TRANS2_SESSION_SETUP = 0x000E,

    /// Request a DFS referral for a file or directory. See [MS-DFSC] for
    /// details.
    TRANS2_GET_DFS_REFERRAL = 0x0010,

    /// Reserved.
    ///
    /// @note Not implemented.
    TRANS2_REPORT_DFS_INCONSISTENCY = 0x0011,
};

/// Transaction codes used with SMB_COM_NT_TRANSACT.
pub const SmbNtTrans = enum(u16) {
    /// Used to create or open a file or directory when extended
    /// attributes (EAs) or a security descriptor (SD) are to be applied.
    NT_TRANSACT_CREATE = 0x0001,

    /// Allows device and file system control functions to be transferred
    /// transparently from client to server.
    NT_TRANSACT_IOCTL = 0x0002,

    /// Allows a client to change the security descriptor for a file.
    NT_TRANSACT_SET_SECURITY_DESC = 0x0003,

    /// Notifies the client when the directory specified by FID is
    /// modified. It also returns the names of any files that changed.
    NT_TRANSACT_NOTIFY_CHANGE = 0x0004,

    /// Reserved.
    ///
    /// @note Not implemented.
    NT_TRANSACT_RENAME = 0x0005,

    /// Allows a client to retrieve the security descriptor for a file.
    NT_TRANSACT_QUERY_SECURITY_DESC = 0x0006,
};

/// FIND information levels are used in TRANS2_FIND_FIRST2 and
/// TRANS2_FIND_NEXT2 subcommand requests to indicate the level of information
/// that a server MUST respond with for each file matching the request's search
/// criteria.
pub const SmbTrans2Find = enum(u16) {
    /// Return creation, access, and last write timestamps, size and file
    /// attributes along with the file name.
    SMB_FIND_INFO_STANDARD = 0x0001,

    /// Return the SMB_INFO_STANDARD data along with the size of a file's
    /// extended attributes (EAs).
    SMB_FIND_INFO_QUERY_EA_SIZE = 0x0002,

    /// Return the SMB_INFO_QUERY_EA_SIZE data along with a specific list
    /// of a file's EAs. The requested EAs are provided in the Trans2_Data block
    /// of the request.
    SMB_FIND_INFO_QUERY_EAS_FROM_LIST = 0x0003,

    /// Return 64-bit format versions of: creation, access, last write,
    /// and last attribute change timestamps; size. In addition, return extended
    /// file attributes and file name.
    SMB_FIND_FIND_FILE_DIRECTORY_INFO = 0x0101,

    /// Returns the SMB_FIND_FILE_DIRECTORY_INFO data along with the size
    /// of a file's EAs.
    SMB_FIND_FIND_FILE_FULL_DIRECTORY_INFO = 0x0102,

    /// Returns the name(s) of the file(s).
    SMB_FIND_FIND_FILE_NAMES_INFO = 0x0103,

    /// Returns a combination of the data from
    /// SMB_FIND_FILE_FULL_DIRECTORY_INFO and SMB_FIND_FILE_NAMES_INFO.
    SMB_FIND_FIND_FILE_BOTH_DIRECTORY_INFO = 0x0104,
};

/// QUERY_FS information levels are used in TRANS2_QUERY_FS_INFORMATION
/// subcommand requests to indicate the level of information that a server MUST
/// respond with for the underlying object store indicated in the request.
pub const SmbTrans2QueryFs = enum(u16) {
    /// Query file system allocation unit information.
    SMB_INFO_ALLOCATION = 0x0001,

    /// Query volume name and serial number.
    SMB_INFO_VOLUME = 0x0002,

    /// Query the creation timestamp, serial number, and Unicode-encoded
    /// volume label.
    SMB_QUERY_FS_VOLUME_INFO = 0x0102,

    /// Query 64-bit file system allocation unit information.
    SMB_QUERY_FS_SIZE_INFO = 0x0103,

    /// Query a file system's underlying device type and characteristics.
    SMB_QUERY_FS_DEVICE_INFO = 0x0104,

    /// Query file system attributes.
    SMB_QUERY_FS_ATTRIBUTE_INFO = 0x0105,
};

/// QUERY information levels are used in TRANS2_QUERY_PATH_INFORMATION
/// and TRANS2_QUERY_FILE_INFORMATION subcommand requests to indicate the level
/// of information that a server MUST respond with for the file or directory
/// indicated in the request.
pub const SmbTrans2Query = enum(u16) {
    /// Query creation, access, and last write timestamps, size and file
    /// attributes.
    SMB_TRANS2_QUERY_INFO_STANDARD = 0x0001,

    /// Query the SMB_INFO_STANDARD data along with the size of the
    /// file's extended attributes (EAs).
    SMB_TRANS2_QUERY_INFO_QUERY_EA_SIZE = 0x0002,

    /// Query a file's specific EAs by attribute name.
    SMB_TRANS2_QUERY_INFO_QUERY_EAS_FROM_LIST = 0x0003,

    /// Query all of a file's EAs.
    SMB_TRANS2_QUERY_INFO_QUERY_ALL_EAS = 0x0004,

    /// Validate the syntax of the path provided in the request. Not
    /// supported for TRANS2_QUERY_FILE_INFORMATION.
    SMB_TRANS2_QUERY_INFO_IS_NAME_VALID = 0x0006,

    /// Query 64-bit create, access, write, and change timestamps along
    /// with extended file attributes.
    SMB_TRANS2_QUERY_QUERY_FILE_BASIC_INFO = 0x0101,

    /// Query size, number of links, if a delete is pending, and if the
    /// path is a directory.
    SMB_TRANS2_QUERY_QUERY_FILE_STANDARD_INFO = 0x0102,

    /// Query the size of the file's EAs.
    SMB_TRANS2_QUERY_QUERY_FILE_EA_INFO = 0x0103,

    /// Query the long file name in Unicode format.
    SMB_TRANS2_QUERY_QUERY_FILE_NAME_INFO = 0x0104,

    /// Query the SMB_QUERY_FILE_BASIC_INFO,
    /// SMB_QUERY_FILE_STANDARD_INFO, SMB_QUERY_FILE_EA_INFO, and
    /// SMB_QUERY_FILE_NAME_INFO data as well as access flags, access mode, and
    /// alignment information in a single request.
    SMB_TRANS2_QUERY_QUERY_FILE_ALL_INFO = 0x0107,

    /// Query the 8.3 file name.
    SMB_TRANS2_QUERY_QUERY_FILE_ALT_NAME_INFO = 0x0108,

    /// Query file stream information.
    SMB_TRANS2_QUERY_QUERY_FILE_STREAM_INFO = 0x0109,

    /// Query file compression information.
    SMB_TRANS2_QUERY_QUERY_FILE_COMPRESSION_INFO = 0x010B,
};

/// SET information levels are used in TRANS2_SET_PATH_INFORMATION and
/// TRANS2_SET_FILE_INFORMATION subcommand requests to indicate what level of
/// information is being set on the file or directory in the request.
pub const SmbTrans2Set = enum(u16) {
    /// Set creation, access, and last write timestamps.
    SMB_INFO_STANDARD = 0x0001,

    /// Set a specific list of extended attributes (EAs).
    SMB_INFO_SET_EAS = 0x0002,

    /// Set 64-bit create, access, write, and change timestamps along
    /// with extended file attributes.
    SMB_SET_FILE_BASIC_INFO = 0x0101,

    /// Set whether or not the file is marked for deletion.
    SMB_SET_FILE_DISPOSITION_INFO = 0x0102,

    /// Set file allocation size.
    SMB_SET_FILE_ALLOCATION_INFO = 0x0103,

    /// Set file EOF offset.
    SMB_SET_FILE_END_OF_FILE_INFO = 0x0104,
};

/// Data buffer format codes are used to identify the type and format of
/// the fields that immediately follow them in the data block of SMB messages.
/// See section 2.2.3.3 for a description of the data block.
///
/// In Core Protocol commands, every field in the data block (following the
/// ByteCount field) is preceded by a one-byte buffer format field. Commands
/// introduced in dialects subsequent to the Core Protocol typically do not
/// include buffer format fields unless they are intended as an extension to an
/// existing command. For example, SMB_COM_FIND (section 2.2.4.59) was
/// introduced in the LAN Manager 1.0 dialect in order to improve the semantics
/// of the SMB_COM_SEARCH (section 2.2.4.58) Core Protocol command. Both
/// commands share the same request and response message structures, including
/// the buffer format fields.
pub const SmbDataBufferFormatCode = enum(u8) {
    /// A two-byte u16 value indicating the length of the data buffer.
    /// The data buffer follows immediately after the length field.
    DATA_BUFFER = 0x01,

    /// A null-terminated OEM_STRING.
    ///
    /// @note This format code is used only in the SMB_COM_NEGOTIATE command to
    /// identify SMB dialect strings.
    DIALECT_STRING = 0x02,

    /// A null-terminated string representing a file system path.
    ///
    /// @note In the NT LAN Manager dialect, the string is of type SMB_STRING
    /// unless otherwise specified.
    PATHNAME = 0x03,

    /// A null-terminated string.
    ///
    /// @note In the NT LAN Manager dialect, the string is of type SMB_STRING
    /// unless otherwise specified.
    SMB_STRING = 0x04,

    /// A two-byte u16 value indicating the length of the variable
    /// block. The variable block follows immediately after the length field.
    VARIABLE_BLOCK = 0x05,
};

/// An 8-bit field of 1-bit flags describing various features in effect
/// for the message.
pub const SmbFlags = enum(u8) {
    SMB_FLAGS_NONE = 0x0,

    /// This bit is set (1) in the SMB_COM_NEGOTIATE (0x72) Response if
    /// the server supports SMB_COM_LOCK_AND_READ (0x13) and
    /// SMB_COM_WRITE_AND_UNLOCK (0x14) commands.
    SMB_FLAGS_LOCK_AND_READ_OK = (1 << 0),

    /// When set (on an SMB request being sent to the server), the client
    /// guarantees that there is a receive buffer posted such that a send
    /// without acknowledgment can be used by the server to respond to the
    /// client's request. This behavior is specific to an obsolete transport.
    /// This bit MUST be set to zero by the client and MUST be ignored by the
    /// server.
    ///
    /// @note Obselete.
    SMB_FLAGS_BUF_AVAILABLE = (1 << 1),

    /// This flag MUST be set to zero by the client and MUST be ignored
    /// by the server.
    SMB_FLAGS_RESERVED_1 = (1 << 2),

    /// If this bit is set then all pathnames in the SMB SHOULD be
    /// treated as case-insensitive.
    ///
    /// @note Obselete.
    SMB_FLAGS_CASE_INSENSITIVE = (1 << 3),

    /// When set in session setup, this bit indicates that all paths sent
    /// to the server are already in canonical format. That is, all file and
    /// directory names are composed of valid file name characters in all
    /// upper-case, and that the path segments are separated by backslash
    /// characters ('\').
    ///
    /// @note Obselescent.
    SMB_FLAGS_CANONICALIZED_PATHS = (1 << 4),

    /// This bit has meaning only in the deprecated SMB_COM_OPEN (0x02)
    /// Request, SMB_COM_CREATE (0x03) Request, and SMB_COM_CREATE_NEW (0x0F)
    /// Request messages, where it is used to indicate that the client is
    /// requesting an Exclusive OpLock. It SHOULD be set to zero by the client,
    /// and ignored by the server, in all other SMB requests. If the server
    /// grants this OpLock request, then this bit SHOULD remain set in the
    /// corresponding response SMB to indicate to the client that the OpLock
    /// request was granted.
    ///
    /// @note Obselescent.
    SMB_FLAGS_OPLOCK = (1 << 5),

    /// This bit has meaning only in the deprecated SMB_COM_OPEN (0x02)
    /// Request, SMB_COM_CREATE (0x03) Request, and SMB_COM_CREATE_NEW (0x0F)
    /// Request messages, where it is used to indicate that the client is
    /// requesting a Batch OpLock. It SHOULD be set to zero by the client, and
    /// ignored by the server, in all other SMB requests. If the server grants
    /// this OpLock request, then this bit SHOULD remain set in the
    /// corresponding response SMB to indicate to the client that the OpLock
    /// request was granted. If the SMB_FLAGS_OPLOCK bit is clear (0), then the
    /// SMB_FLAGS_OPBATCH bit is ignored.
    ///
    /// @note Obselescent.
    SMB_FLAGS_OPBATCH = (1 << 6),

    /// When on, this message is being sent from the server in response
    /// to a client request. The Command field usually contains the same value
    /// in a protocol request from the client to the server as in the matching
    /// response from the server to the client. This bit unambiguously
    /// distinguishes the message as a server response.
    SMB_FLAGS_REPLY = (1 << 7),
};

/// A 16-bit field of 1-bit flags that represent various features in
/// effect for the message. Unspecified bits are reserved and MUST be zero.
pub const SmbFlags2 = enum(u16) {
    SMB_FLAGS2_NONE = 0x00,

    /// If the bit is set, the message MAY contain long file names.
    /// If the bit is clear then file names in the message MUST adhere to the
    /// 8.3 naming convention.
    /// If set in a client request for directory enumeration, the server MAY
    /// return long names (that is, names that are not 8.3 names) in the
    /// response to this request. If not set in a client request for directory
    /// enumeration, the server MUST return only 8.3 names in the response to
    /// this request. This flag indicates that in a direct enumeration request,
    /// paths returned by the server are not restricted to 8.3 names format.
    /// This bit field SHOULD be set to 1 when the negotiated dialect is
    /// LANMAN2.0 or later.
    SMB_FLAGS2_LONG_NAMES = (1 << 0),

    /// If the bit is set, the client is aware of extended
    /// attributes (EAs).
    /// The client MUST set this bit if the client is aware of extended
    /// attributes. In response to a client request with this flag set, a server
    /// MAY include extended attributes in the response. This bit field SHOULD
    /// be set to 1 when the negotiated dialect is LANMAN2.0 or later.
    SMB_FLAGS2_EAS = (1 << 1),

    /// If set by the client, the client is requesting signing (if signing
    /// is not yet active) or the message being sent is signed. This bit is used
    /// on the SMB header of an SMB_COM_SESSION_SETUP_ANDX client request to
    /// indicate that the client supports signing and that the server can choose
    /// to enforce signing on the connection based on its configuration.
    /// To turn on signing for a connection, the server MUST set this flag and
    /// also sign the SMB_COM_SESSION_SETUP_ANDX Response, after which all of
    /// the traffic on the connection (except for OpLock Break notifications)
    /// MUST be signed. In the SMB header of other CIFS client requests, the
    /// setting of this bit indicates that the packet has been signed. This bit
    /// field SHOULD be set to 1 when the negotiated dialect is NT LANMAN or
    /// later.
    SMB_FLAGS2_SMB_SECURITY_SIGNATURE = (1 << 2),

    /// Reserved but not implemented.
    ///
    /// @note Not implemented.
    SMB_FLAGS2_IS_LONG_NAME = (1 << 6),

    /// If the bit is set, any pathnames in this SMB SHOULD be resolved
    /// in the Distributed File System (DFS).
    SMB_FLAGS2_DFS = (1 << 12),

    /// This flag is useful only on a read request. If the bit is set,
    /// then the client MAY read the file if the client does not have read
    /// permission but does have execute permission. This bit field SHOULD be
    /// set to 1 when the negotiated dialect is LANMAN2.0 or later. This flag is
    /// also known as SMB_FLAGS2_READ_IF_EXECUTE.
    SMB_FLAGS2_PAGING_IO = (1 << 13),

    /// If this bit is set in a client request, the server MUST return
    /// errors as 32-bit NTSTATUS codes in the response. If it is clear, the
    /// server SHOULD return errors in SMBSTATUS format.
    /// If this bit is set in the server response, the Status field in the
    /// header is formatted as an NTSTATUS code; else, it is in SMBSTATUS
    /// format.
    SMB_FLAGS2_NT_STATUS = (1 << 14),

    /// If set in a client request or server response, each field that
    /// contains a string in this SMB message MUST be encoded as an array of
    /// 16-bit Unicode characters, unless otherwise specified.
    ///
    /// If this bit is clear, each of these fields MUST be encoded as an array
    /// of OEM characters. This bit field SHOULD be set to 1 when the negotiated
    /// dialect is NT LANMAN.
    SMB_FLAGS2_UNICODE = (1 << 15),

    pub const SMB_FLAGS2_READ_IF_EXECUTE: SmbFlags2 = .SMB_FLAGS2_PAGING_IO;
};

/// In the case that security signatures are negotiated :
pub const SmbComNegociateSecurityFeatures = extern struct {
    /// If SMB signing has been negotiated, this field MUST contain an
    /// 8-byte cryptographic message signature that can be used to detect
    /// whether the message was modified while in transit. The use of message
    /// signing is mutually exclusive with connectionless transport.
    security_signature: [8]u8 align(1),
};

/// In the case that CIFS is being transported over a connectionless
/// transport :
pub const SmbSecurityFeatures = extern struct {
    /// An encryption key used for validating messages over
    /// connectionless transports.
    key: u64 align(1),

    /// A connection identifier (CID).
    cid: CID align(1),

    /// A number used to identify the sequence of a message over
    /// connectionless transports.
    sequence_number: u16 align(1),
};

/// The SMB_Header structure is a fixed 32-bytes in length.
pub const SmbMessageHeader = extern struct {
    /// This field MUST contain the 4-byte literal string '\xFF', 'S',
    /// 'M', 'B', with the letters represented by their respective ASCII values
    /// in the order shown. In the earliest available SMB documentation, this
    /// field is defined as a one byte message type (0xFF) followed by a three
    /// byte server type identifier.
    protocol: [4]u8 align(1) = PROTOCOL,

    /// A one-byte command code.
    command: SmbCom align(1) = .SMB_COM_CREATE_DIRECTORY,

    /// A 32-bit field used to communicate error messages from the server
    /// to the client.
    status: SmbError align(1) = .{},

    /// An 8-bit field of 1-bit flags describing various features in
    /// effect for the message.
    flags: SmbFlags align(1) = .SMB_FLAGS_NONE,

    /// A 16-bit field of 1-bit flags that represent various features in
    /// effect for the message. Unspecified bits are reserved and MUST be zero.
    flags2: SmbFlags2 align(1) = .SMB_FLAGS2_NONE,

    /// If set to a nonzero value, this field represents the high-order
    /// bytes of a process identifier (PID). It is combined with the PIDLow
    /// field below to form a full PID.
    pid_high: u16 align(1) = 0x00,

    /// Neither an smb_com_negociate_security_features_t nor an
    /// smb_security_features_t context, so it MUST be set to zero by the client
    /// and MUST be ignored by the server.
    security_features: [8]u8 align(1) = .{ 0, 0, 0, 0, 0, 0, 0, 0 },

    /// This field is reserved and SHOULD be set to 0x0000.
    reserved: u16 align(1) = 0x0000,

    /// A tree identifier (TID).
    tid: TID align(1) = 0x00,

    /// The lower 16-bits of the PID.
    pid_low: u16 align(1) = 0x00,

    /// A user identifier (UID).
    uid: UID align(1) = 0x00,

    /// A multiplex identifier (MID).
    mid: MID align(1) = 0x00,
};

/// SMB was originally designed as a rudimentary remote procedure call
/// protocol, and the parameter block was defined as an array of "one word (two
/// byte) fields containing SMB command dependent parameters". In the CIFS
/// dialect, however, the SMB_Parameters.Words array can contain any arbitrary
/// structure. The format of the SMB_Parameters.Words structure is defined
/// individually for each command message. The size of the Words array is still
/// measured as a count of byte pairs.
/// The general format of the parameter block is as follows.
pub const SmbParameters = extern struct {
    /// The size, in two-byte words, of the Words field. This field can
    /// be zero, indicating that the Words field is empty. Note that the size of
    /// this field is one byte and comes after the fixed 32-byte SMB Header,
    /// which causes the Words field to be unaligned.
    words_count: u8 align(1) = 0x00,

    /// The message-specific parameters structure. The size of this field
    /// MUST be (2 x WordCount) bytes. If WordCount is 0x00, this field is not
    /// included.
    ///
    /// @note Maximum elements : SMB_PARAMETERS_MAX_WORDS
    words: [*]u16 align(1) = undefined,
};

/// The general structure of the data block is similar to that of the
/// Parameter block, except that the length of the buffer portion is measured in
/// bytes.
pub const SmbData = extern struct {
    /// The size, in bytes, of the Bytes field. This field can be 0x0000,
    /// indicating that the Bytes field is empty. Because the
    /// SMB_Parameters.Words field is unaligned and the SMB_Data.ByteCount field
    /// is two bytes in size, the first byte of SMB_Data.Bytes is also
    /// unaligned.
    bytes_count: u16 align(1) = 0x0000,

    /// The message-specific data structure. The size of this field MUST
    /// be ByteCount bytes. If ByteCount is 0x0000, this field is not included.
    ///
    /// @note Maximum elements : SMB_DATA_MAX_BYTES
    bytes: [*]u8 align(1) = undefined,
};

/// Batched messages using the AndX construct were introduced in the LAN
/// Manager 1.0 dialect. Batched messages reduce the number of messages required
/// to complete a series of commands by sending multiple command requests or
/// responses in a single message. SMB commands that apply the AndX construct
/// are known as "AndX Commands", and are identified by the NT LAN Manager
/// convention of appending "_ANDX" to the command name. Messages of this type
/// are known as AndX Messages.
/// In AndX Messages, only one SMB Header is sent. The header is then followed
/// by zero or more Parameter and Data block pairs, each corresponding to an
/// additional command request/response. There is no limit on the number of
/// block pairs in a message specifically, only on the total message size. The
/// total size of a Batched Message MUST NOT exceed the negotiated
/// MaxBufferSize. AndX Messages contain a construct, conceptually similar to a
/// linked-list, that is used to connect the batched block pairs. The resulting
/// list is referred to as an AndX Chain. The structure of this construct is
/// shown below.
pub const SmbAndX = extern struct {
    /// The command code associated with the next block pair in the AndX
    /// Chain.
    andx_command: SmbCom align(1),

    /// This field is reserved and MUST be 0x00.
    _andx_reserved: u8 align(1) = 0x00,

    /// The offset in bytes, relative to the start of the SMB Header, of
    /// the next Parameter block in the AndX Message. This offset is independent
    /// of any other size parameters or offsets within the command. This offset
    /// can point to a location past the end of the current block pair.
    andx_offset: u16 align(1),
};

/// A 16-bit field for encoding the requested access mode. See section
/// 3.2.4.5.1 for a discussion on sharing modes.
pub const SmbAccessMode = enum(u16) {
    // Access Mode (Bits [0-2], Mask 0x0007)

    ACCESS_MODE_READ = (0x00 << 0),
    ACCESS_MODE_WRITE = (0x01 << 0),
    ACCESS_MODE_READWRITE = (0x02 << 0),
    ACCESS_MODE_EXECUTE = (0x03 << 0),
    /// (Reserved)
    ACCESS_MODE_RESERVED_4 = (0x04 << 0),
    /// (Reserved)
    ACCESS_MODE_RESERVED_5 = (0x05 << 0),
    /// (Reserved)
    ACCESS_MODE_RESERVED_6 = (0x06 << 0),
    /// (Reserved)
    ACCESS_MODE_RESERVED_7 = (0x07 << 0),

    // Sharing Mode (Bits [4-6], Mask 0x0070)

    SHARING_MODE_COMPAT = (0x00 << 4),
    SHARING_MODE_DENY_ALL = (0x01 << 4),
    SHARING_MODE_DENY_WRITE = (0x02 << 4),
    SHARING_MODE_DENY_READ = (0x03 << 4),
    SHARING_MODE_DENY_NONE = (0x04 << 4),
    /// (Reserved)
    SHARING_MODE_RESERVED_5 = (0x05 << 4),
    /// (Reserved)
    SHARING_MODE_RESERVED_6 = (0x06 << 4),
    /// (Reserved)
    SHARING_MODE_RESERVED_7 = (0x07 << 4),

    // Reference Locality (Bits [8-10], Mask 0x0700)
    REF_LOCALITY_UNKNOWN = (0x00 << 8),
    REF_LOCALITY_SEQUENTIAL = (0x01 << 8),
    REF_LOCALITY_RANDOM_ACCESS = (0x02 << 8),
    REF_LOCALITY_RANDSEQ = (0x03 << 8),
    /// (Reserved)
    REF_LOCALITY_RESERVED_4 = (0x04 << 8),
    /// (Reserved)
    REF_LOCALITY_RESERVED_5 = (0x05 << 8),
    /// (Reserved)
    REF_LOCALITY_RESERVED_6 = (0x06 << 8),
    /// (Reserved)
    REF_LOCALITY_RESERVED_7 = (0x07 << 8),

    // Cache Mode (Bit 12, Mask 0x1000)
    CACHE_MODE_CACHED = (0x00 << 12),
    CACHE_MODE_NONCACHED = (0x01 << 12),

    // Writethrough Mode (Bit 14, Mask 0x4000)
    WRITETHROUGH_MODE_WRITEBACK = (0x00 << 14),
    WRITETHROUGH_MODE_WRITETHROUGH = (0x01 << 14),
};

const SmbMessage = @This();

/// The SMB_Header structure is a fixed 32-bytes in length.
header: SmbMessageHeader = .{},

/// The SMB_Parameters structure has a variable length.
parameters: SmbParameters = .{},

/// The SMB_Data structure has a variable length.
data: SmbData = .{},

pub fn deinit(self: *SmbMessage, allocator: std.mem.Allocator) void {
    if (self.parameters.words_count > 0)
        allocator.free(self.parameters.words[0..self.parameters.words_count]);
    if (self.data.bytes_count > 0)
        allocator.free(self.data.bytes[0..self.data.bytes_count]);
}

pub fn debugHeader(self: *const SmbMessage) void {
    var offset: usize = 0;
    inline for (@typeInfo(SmbMessageHeader).@"struct".fields) |field| {
        const fieldData = @field(self.header, field.name);
        const fieldSize = @sizeOf(@TypeOf(fieldData));
        std.debug.print("{s}: {any} (from byte {d} to byte {d}, {d} bytes)\n", .{ field.name, @field(self.header, field.name), offset, offset + fieldSize - 1, fieldSize });
        offset += fieldSize;
    }
}

pub fn deserialize(self: *SmbMessage, allocator: std.mem.Allocator, bytes: []const u8) !void {
    var offset: usize = 0;

    self.header = std.mem.bytesToValue(SmbMessageHeader, bytes[offset..][0..32]);
    offset += 32;

    self.parameters.words_count = bytes[offset];
    offset += 1;
    if (self.parameters.words_count > 0) {
        const parameters_words = try allocator.alloc(u16, self.parameters.words_count);
        errdefer allocator.free(parameters_words);

        const slice = bytes[offset..][0 .. self.parameters.words_count * 2];

        for (parameters_words, 0..) |*word, i| {
            const byte_pair = slice[i * 2 ..][0..2];
            word.* = std.mem.readInt(u16, byte_pair, .little);
        }

        self.parameters.words = @ptrCast(parameters_words);
        offset += self.parameters.words_count * 2;
    }

    self.data.bytes_count = std.mem.bytesToValue(u16, bytes[offset..][0..2]);
    offset += 2;
    if (self.data.bytes_count > 0) {
        const data_bytes = try allocator.alloc(u8, self.data.bytes_count);
        errdefer allocator.free(data_bytes);

        const slice = bytes[offset..][0..self.data.bytes_count];

        for (data_bytes, 0..) |*byte, i| {
            byte.* = slice[i];
        }

        self.data.bytes = @ptrCast(data_bytes);
        offset += self.data.bytes_count * 2;
    }
}

test "SmbMessage.deserialize" {
    const allocator = std.testing.allocator;

    const bytes = [_]u8{ 255, 83, 77, 66, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 6, 0, 4, 102, 105, 108, 101, 0 };

    var message = SmbMessage{};
    defer message.deinit(allocator);

    try message.deserialize(allocator, &bytes);
    try std.testing.expect(std.mem.eql(u8, &message.header.protocol, &[4]u8{ 255, 83, 77, 66 }));
    try std.testing.expect(message.header.command == .SMB_COM_CREATE);
    try std.testing.expect(message.header.status.error_class == .ERRCLS_SUCCESS);
    try std.testing.expect(message.header.status.error_code == .ERR_SUCCESS);
    try std.testing.expect(message.header.flags == .SMB_FLAGS_NONE);
    try std.testing.expect(message.header.flags2 == .SMB_FLAGS2_NONE);
    try std.testing.expect(message.header.pid_high == 0);
    try std.testing.expect(std.mem.eql(u8, &message.header.security_features, &[8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }));
    try std.testing.expect(message.header.reserved == 0);
    try std.testing.expect(message.header.tid == 2);
    try std.testing.expect(message.header.pid_low == 0);
    try std.testing.expect(message.header.uid == 1);
    try std.testing.expect(message.header.mid == 0);
}

pub fn serialize(self: *const SmbMessage, allocator: std.mem.Allocator) ![]u8 {
    const totalSize = 32 + 1 + self.parameters.words_count * 2 + 2 + self.data.bytes_count;
    const bytes: []u8 = try allocator.alloc(u8, totalSize);
    errdefer allocator.free(bytes);
    var offset: usize = 32;

    const headerBytes: *const [32]u8 = std.mem.asBytes(&self.header);
    std.mem.copyForwards(u8, bytes, headerBytes);

    std.mem.writeInt(u8, @ptrCast(bytes[offset..]), self.parameters.words_count, .little);
    offset += 1;
    if (self.parameters.words_count > 0) {
        for (0..self.parameters.words_count) |word_index| {
            const word = self.parameters.words[word_index];
            std.mem.writeInt(u16, @ptrCast(bytes[offset..][word_index * 2 ..]), word, .little);
        }
        offset += self.parameters.words_count * 2;
    }

    std.mem.writeInt(u16, bytes[offset..][0..2], self.data.bytes_count, .little);
    offset += 2;
    if (self.data.bytes_count > 0) {
        std.mem.copyForwards(u8, bytes[offset..], self.data.bytes[0..self.data.bytes_count]);
        offset += self.data.bytes_count;
    }

    return bytes;
}

test "SmbMessage.serialize" {
    const allocator = std.testing.allocator;

    const expectedBytes = [_]u8{ 255, 83, 77, 66, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 6, 0, 4, 102, 105, 108, 101, 0 };

    var message = SmbMessage{};
    defer message.deinit(allocator);

    try message.deserialize(allocator, &expectedBytes);
    try std.testing.expect(std.mem.eql(u8, &message.header.protocol, &[4]u8{ 255, 83, 77, 66 }));
    try std.testing.expect(message.header.command == .SMB_COM_CREATE);
    try std.testing.expect(message.header.status.error_class == .ERRCLS_SUCCESS);
    try std.testing.expect(message.header.status.error_code == .ERR_SUCCESS);
    try std.testing.expect(message.header.flags == .SMB_FLAGS_NONE);
    try std.testing.expect(message.header.flags2 == .SMB_FLAGS2_NONE);
    try std.testing.expect(message.header.pid_high == 0);
    try std.testing.expect(std.mem.eql(u8, &message.header.security_features, &[8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }));
    try std.testing.expect(message.header.reserved == 0);
    try std.testing.expect(message.header.tid == 2);
    try std.testing.expect(message.header.pid_low == 0);
    try std.testing.expect(message.header.uid == 1);
    try std.testing.expect(message.header.mid == 0);

    const serializedBytes = try message.serialize(allocator);
    defer allocator.free(serializedBytes);

    try std.testing.expect(std.mem.eql(u8, &expectedBytes, serializedBytes));
}
