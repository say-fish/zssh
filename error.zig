pub const Error = error{
    /// Invalid RFC-4251 integer
    MalformedInteger,
    /// Invalid RFC-4251 string
    MalformedString,
    /// Malformed RFC-4251 mpint
    MalformedMpInt, // TODO:
    /// Object specific invalid data
    InvalidLiteral,
    /// Data is invalid or corrupted
    InvalidData,
    /// The checksum for private keys is invalid, meaning either, decryption
    /// was not successful, or data is corrupted. This is **NOT** an auth form
    /// error.
    InvalidChecksum,
    /// Out of Memory.
    OutOfMemory,
    /// Invalid/Unsupported magic string
    InvalidMagicString,
    MessageTooShort,
    /// As per spec, repeated extension are not allowed.
    RepeatedExtension,
    UnkownExtension,
    InvalidFileFormat,
};
