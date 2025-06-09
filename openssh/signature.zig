const std = @import("std");

const zssh = @import("zssh");

const public = @import("public.zig");

const enc = zssh.enc;
const gen = zssh.sig;
const mem = zssh.mem;

pub const Cont = enc.Cont;
pub const Error = zssh.err.Error;
pub const BoxRef = mem.BoxRef;

/// The resulting signature is encoded as follows:
///
///     string   "rsa-sha2-256" / "rsa-sha2-512"
///     string    rsa_signature_blob
///
///   The value for 'rsa_signature_blob' is encoded as a string that contains
///   an octet string S (which is the output of RSASSA-PKCS1-v1_5) and that
///   has the same length (in octets) as the RSA modulus.  When S contains
///   leading zeros, there exist signers that will send a shorter encoding of
///   S that omits them.  A verifier MAY accept shorter encodings of S with
///   one or more leading zeros omitted.
pub const rfc8332 = struct {
    magic: Magic,
    blob: []const u8,

    const Self = @This();

    const Magic = gen.MakeMagic(enum {
        @"rsa-sha2-256",
        @"rsa-sha2-512",
    });

    fn from(src: []const u8) Error!Self {
        return try enc.parse(Self, src);
    }

    pub fn init(
        comptime tag: Magic.Value,
        value: []const u8,
    ) Self {
        return .{ .magic = .{ .value = tag }, .blob = value };
    }

    pub fn parse(src: []const u8) Error!Cont(Self) {
        const next, const sig = try enc.rfc4251.parse_string(src);

        return .{ next, try Self.from(sig) };
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        try enc.serialize_struct(Self, writer, self);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size_struct(Self, self);
    }
};

/// Signatures are encoded as follows:
///
///     string   "ecdsa-sha2-[identifier]"
///     string   ecdsa_signature_blob
///
///   The string [identifier] is the identifier of the elliptic curve
///   domain parameters.
///
///   The ecdsa_signature_blob value has the following specific encoding:
///
///     mpint    r
///     mpint    s
///
///   The integers r and s are the output of the ECDSA algorithm.
pub const rfc5656 = struct {
    magic: Magic,
    blob: struct {
        r: []const u8,
        s: []const u8,

        const Blob = @This();

        fn from(src: []const u8) Error!Blob {
            return try enc.parse(Blob, src);
        }

        pub fn parse(src: []const u8) Error!Cont(Blob) {
            const next, const blob = try enc.rfc4251.parse_string(src);

            return .{ next, try Blob.from(blob) };
        }

        pub fn serialize(
            self: *const Blob,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            try enc.serialize_struct(Blob, writer, self);
        }

        pub fn encoded_size(self: *const Blob) u32 {
            return enc.encoded_size_struct(Blob, self);
        }
    },

    const Self = @This();

    const Magic = gen.MakeMagic(enum {
        @"ecdsa-sha2-nistp256",
        @"ecdsa-sha2-nistp512",
    });

    fn from(src: []const u8) Error!Self {
        return try enc.parse(Self, src);
    }

    pub fn parse(src: []const u8) Error!Cont(Self) {
        const next, const sig = try enc.rfc4251.parse_string(src);

        return .{ next, try Self.from(sig) };
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        try enc.serialize_struct(Self, writer, self);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size_struct(Self, self);
    }
};

/// The EdDSA signature of a message M under a private key k is defined as the
/// PureEdDSA signature of PH(M). In other words, EdDSA simply uses PureEdDSA
/// to sign PH(M).
pub const rfc8032 = struct {
    magic: Magic,
    sm: []const u8,

    const Self = @This();

    pub const Magic = gen.MakeMagic(enum { @"ssh-ed25519" });

    fn from(src: []const u8) Error!Self {
        return try enc.parse(Self, src);
    }

    pub fn parse(src: []const u8) Error!Cont(Self) {
        const next, const sig = try enc.rfc4251.parse_string(src);

        return .{ next, try Self.from(sig) };
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        try enc.serialize_struct(Self, writer, self);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size_struct(Self, self);
    }
};

pub const Signature = union(enum(u2)) {
    rsa: rfc8332,
    ecdsa: rfc5656,
    ed: rfc8032,

    const Self = @This();

    pub const Magic = gen.MakeMagic(enum {
        @"rsa-sha2-256",
        @"rsa-sha2-512",
        @"ecdsa-sha2-nistp256",
        @"ecdsa-sha2-nistp512",
        @"ssh-ed25519",
    });

    pub fn init(comptime tag: std.meta.Tag(Self), value: std.meta.TagPayload(Self, tag)) Self {
        return @unionInit(Self, @tagName(tag), value);
    }

    pub fn parse(src: []const u8) Error!Cont(Signature) {
        const next, const key = try enc.rfc4251.parse_string(src);

        return .{ next, Self.from_bytes(key) catch return error.InvalidData };
    }

    pub fn from_bytes(src: []const u8) !Signature {
        _, const magic = try enc.rfc4251.parse_string(src);

        return switch (try Magic.from_slice(magic)) {
            .@"rsa-sha2-256", .@"rsa-sha2-512" => return .{
                .rsa = try rfc8332.from(src),
            },

            .@"ecdsa-sha2-nistp256", .@"ecdsa-sha2-nistp512" => return .{
                .ecdsa = try rfc5656.from(src),
            },

            .@"ssh-ed25519" => return .{
                .ed = try rfc8032.from(src),
            },
        };
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        return switch (self.*) {
            inline else => |value| value.serialize(writer),
        };
    }

    pub fn encoded_size(self: *const Self) u32 {
        return switch (self.*) {
            inline else => |value| enc.encoded_size(@TypeOf(value), value),
        };
    }
};

pub const SshSig = struct {
    /// Magic string, must be "SSHSIG"
    preamble: Preamble,
    /// Verifiers MUST reject signatures with versions greater than those
    /// they support.
    version: u32,
    publickey: public.Key,
    /// The purpose of the namespace value is to specify a unambiguous
    /// interpretation domain for the signature, e.g. file signing. This
    /// prevents cross-protocol attacks caused by signatures intended for
    /// one intended domain being accepted in another.
    ///
    /// The namespace value **MUST NOT** be the empty string.
    namespace: []const u8,
    /// The reserved value is present to encode future information (e.g.
    /// tags) into the signature. Implementations should ignore the
    /// reserved field if it is not empty.
    reserved: []const u8,
    /// The supported hash algorithms are "sha256" and "sha512".
    hash_algorithm: HashAlgorithm,
    /// The signature.
    signature: Signature,

    const Self = @This();

    pub const Pem = gen.MakePem(
        "BEGIN SSH SIGNATURE",
        "END SSH SIGNATURE",
        zssh.pem.base64.Decoder,
    );
    pub const Preamble = gen.MakePreamble(enum { SSHSIG });
    pub const HashAlgorithm = gen.MakeMagic(enum { sha256, sha512 });

    pub fn parse(src: []const u8) Error!Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }

    fn from(src: []const u8) !Self {
        return try enc.parse(Self, src);
    }

    pub fn from_bytes(src: []const u8) !Self {
        return try Self.from(src);
    }

    pub fn from_pem(
        allocator: std.mem.Allocator,
        encoded_pem: *const Pem,
    ) anyerror!BoxRef(Self, .sec) {
        var der = try encoded_pem.decode(allocator);
        errdefer der.deinit();

        return .{
            .allocator = allocator,
            .data = try Self.from_bytes(der.data),
            .ref = der.data,
        };
    }

    pub const Blob = struct {
        preamble: Preamble,
        namespace: []const u8,
        reserved: []const u8,
        hash_algorithm: HashAlgorithm,
        hmsg: []const u8,

        fn from(src: []const u8) !Blob {
            return try enc.parse(Blob, src);
        }

        pub fn from_bytes(src: []const u8) !Blob {
            return try Blob.from(src);
        }
    };

    pub fn get_signature_blob(
        self: *const Self,
        allocator: std.mem.Allocator,
        hmsg: []const u8,
    ) !mem.BoxRef(Blob, .sec) {
        const len = self.preamble.encoded_size() +
            enc.rfc4251.encoded_size(self.namespace) +
            enc.rfc4251.encoded_size(self.reserved) +
            self.hash_algorithm.encoded_size() +
            @sizeOf(u32) + hmsg.len;

        var writer = try mem.ArrayWriter.init(allocator, len);
        errdefer writer.deinit();

        try self.preamble.serialize(writer.writer().any());
        try enc.serialize_any([]const u8, writer.writer().any(), self.namespace);
        try enc.serialize_any([]const u8, writer.writer().any(), self.reserved);
        try self.hash_algorithm.serialize(writer.writer().any());
        try enc.serialize_any([]const u8, writer.writer().any(), hmsg);

        std.debug.assert(writer.head == len);

        return .{
            .data = try Blob.from_bytes(writer.mem),
            .allocator = allocator,
            .ref = writer.mem,
        };
    }

    pub fn encoded_size() u32 {
        @panic("TODO");
    }
};
