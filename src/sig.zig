const std = @import("std");
const builtin = @import("builtin");

const mem = @import("mem.zig");
const pem = @import("pem.zig");
const pk = @import("pk.zig");
const proto = @import("proto.zig");

// TODO: Error

fn MagicString(comptime T: type) type {
    return proto.GenericMagicString(
        T,
        proto.rfc4251.parse_string,
        proto.rfc4251.encoded_size,
    );
}

/// The resulting signature is encoded as follows:
///
///    string   "rsa-sha2-256" / "rsa-sha2-512"
///    string    rsa_signature_blob
///
///    The value for 'rsa_signature_blob' is encoded as a string that contains
///    an octet string S (which is the output of RSASSA-PKCS1-v1_5) and that
///    has the same length (in octets) as the RSA modulus.  When S contains
///    leading zeros, there exist signers that will send a shorter encoding of
///    S that omits them.  A verifier MAY accept shorter encodings of S with
///    one or more leading zeros omitted.
pub const rfc8332 = struct {
    magic: Magic,
    blob: []const u8,

    const Self = @This();

    const Magic = MagicString(enum(u1) {
        @"rsa-sha2-256",
        @"rsa-sha2-512",
    });

    fn from(src: []const u8) proto.Error!Self {
        return try proto.parse(Self, src);
    }

    pub fn parse(src: []const u8) proto.Error!proto.Cont(Self) {
        const next, const sig = try proto.rfc4251.parse_string(src);

        return .{ next, try Self.from(sig) };
    }
};

/// Signatures are encoded as follows:
///
///      string   "ecdsa-sha2-[identifier]"
///      string   ecdsa_signature_blob
///
///   The string [identifier] is the identifier of the elliptic curve
///   domain parameters.
///
///   The ecdsa_signature_blob value has the following specific encoding:
///
///      mpint    r
///      mpint    s
///
///   The integers r and s are the output of the ECDSA algorithm.
pub const rfc5656 = struct {
    magic: Magic,
    blob: struct {
        r: []const u8,
        s: []const u8,

        const Blob = @This();

        fn from(src: []const u8) proto.Error!Blob {
            return try proto.parse(Blob, src);
        }

        pub fn parse(src: []const u8) proto.Error!proto.Cont(Blob) {
            const next, const blob = try proto.rfc4251.parse_string(src);

            return .{ next, try Blob.from(blob) };
        }
    },

    const Self = @This();

    const Magic = MagicString(enum {
        @"ecdsa-sha2-nistp256",
        @"ecdsa-sha2-nistp512",
    });

    fn from(src: []const u8) proto.Error!Self {
        return try proto.parse(Self, src);
    }

    pub fn parse(src: []const u8) proto.Error!proto.Cont(Self) {
        const next, const sig = try proto.rfc4251.parse_string(src);

        return .{ next, try Self.from(sig) };
    }
};

/// The EdDSA signature of a message M under a private key k is defined as the
/// PureEdDSA signature of PH(M).  In other words, EdDSA simply uses PureEdDSA
/// to sign PH(M).
pub const rfc8032 = struct {
    magic: Magic,
    sm: []const u8,

    const Self = @This();

    pub const Magic = MagicString(enum(u1) { @"ssh-ed25519" });

    fn from(src: []const u8) proto.Error!Self {
        return try proto.parse(Self, src);
    }

    pub fn parse(src: []const u8) proto.Error!proto.Cont(Self) {
        const next, const sig = try proto.rfc4251.parse_string(src);

        return .{ next, try Self.from(sig) };
    }
};

pub const SshSig = struct {
    fn parse_fixed_string(src: []const u8) proto.Error!proto.Cont([6]u8) {
        if (src.len < 6) {
            return proto.Error.MalformedString;
        }

        return .{ 6, src[0..6].* };
    }

    fn fixed_string_encoded_size(_: anytype) u32 {
        return 6;
    }

    fn MagicPreamble(comptime T: type) type {
        return proto.GenericMagicString(
            T,
            parse_fixed_string,
            fixed_string_encoded_size,
        );
    }

    /// Magic string, must be "SSHSIG"
    magic: Magic,
    /// Verifiers MUST reject signatures with versions greater than those they
    /// support.
    version: u32,
    /// See: `zssh.pk.Pk`
    publickey: pk.Pk,
    /// The purpose of the namespace value is to specify a unambiguous
    /// interpretation domain for the signature, e.g. file signing. This
    /// prevents cross-protocol attacks caused by signatures intended for one
    /// intended domain being accepted in another.
    ///
    /// The namespace value **MUST NOT** be the empty string.
    namespace: []const u8,
    /// The reserved value is present to encode future information (e.g. tags)
    /// into the signature. Implementations should ignore the reserved field if
    /// it is not empty.
    reserved: []const u8,
    /// The supported hash algorithms are "sha256" and "sha512".
    hash_algorithm: HashAlgorithm,
    signature: Sig,

    const Self = @This();

    pub const Magic = MagicPreamble(enum { SSHSIG });

    pub const HashAlgorithm = MagicString(enum { sha256, sha512 });

    fn from(src: []const u8) !Self {
        return try proto.parse(Self, src);
    }

    pub fn from_bytes(src: []const u8) !Self {
        return try Self.from(src);
    }

    pub fn from_pem(
        allocator: std.mem.Allocator,
        encoded_pem: *const Pem,
    ) !mem.ManagedWithRef(Self) {
        var der = try encoded_pem.decode(allocator);
        errdefer der.deinit();

        return .{
            .allocator = allocator,
            .data = try Self.from_bytes(der.data),
            .ref = der.data,
        };
    }

    pub const Pem = struct {
        _prefix: pem.Literal(
            "BEGIN SSH SIGNATURE",
            std.mem.TokenIterator(u8, .sequence),
        ),
        der: []const u8,
        _posfix: pem.Literal(
            "END SSH SIGNATURE",
            std.mem.TokenIterator(u8, .sequence),
        ),

        pub fn tokenize(
            src: []const u8,
        ) std.mem.TokenIterator(u8, .sequence) {
            return std.mem.tokenizeSequence(u8, src, "-----");
        }

        pub fn parse(src: []const u8) !Pem {
            return try pem.parse(Pem, src);
        }

        pub fn decode(
            self: *const Pem,
            allocator: std.mem.Allocator,
        ) !mem.Managed([]u8) {
            return .{
                .allocator = allocator,
                .data = try pem.decode_with_total_size(
                    allocator,
                    pem.base64.Decoder,
                    self.der,
                ),
            };
        }
    };

    pub const Blob = struct {
        magic: Magic,
        namespace: []const u8,
        reserved: []const u8,
        hash_algorithm: HashAlgorithm,
        hmsg: []const u8,

        fn from(src: []const u8) !Blob {
            return try proto.parse(Blob, src);
        }

        pub fn from_bytes(src: []const u8) !Blob {
            return try Blob.from(src);
        }
    };

    pub fn get_signature_blob(
        self: *const Self,
        allocator: std.mem.Allocator,
        hmsg: []const u8,
    ) !mem.ManagedWithRef(Blob) {
        const len = self.magic.encoded_size() +
            proto.rfc4251.encoded_size(self.namespace) +
            proto.rfc4251.encoded_size(self.reserved) +
            self.hash_algorithm.encoded_size() +
            @sizeOf(u32) + hmsg.len;

        var fbw = try mem.FixedBufferWriter.init(allocator, len);
        errdefer fbw.deinit();

        try self.magic.serialize(fbw.writer());
        try proto.encode_value(fbw.writer(), self.namespace);
        try proto.encode_value(fbw.writer(), self.reserved);
        try self.hash_algorithm.serialize(fbw.writer());
        try proto.encode([]const u8, fbw.writer(), hmsg);

        std.debug.assert(fbw.head == len);

        return .{
            .data = try Blob.from_bytes(fbw.mem),
            .allocator = allocator,
            .ref = fbw.mem,
        };
    }

    pub fn encoded_size() u32 {
        @panic("TODO");
    }
};

pub const Sig = union(enum) {
    rsa: rfc8332,
    ecdsa: rfc5656,
    ed25519: rfc8032,

    const Self = @This();

    const Magic = MagicString(enum {
        @"rsa-sha2-256",
        @"rsa-sha2-512",
        @"ecdsa-sha2-nistp256",
        @"ecdsa-sha2-nistp512",
        @"ssh-ed25519",
    });

    pub fn parse(src: []const u8) proto.Error!proto.Cont(Sig) {
        const next, const key = try proto.rfc4251.parse_string(src);

        return .{ next, Self.from_bytes(key) catch return error.InvalidData };
    }

    pub fn from_bytes(src: []const u8) !Sig {
        _, const magic = try proto.rfc4251.parse_string(src);

        return switch (try Magic.from_slice(magic)) {
            .@"rsa-sha2-256",
            .@"rsa-sha2-512",
            => return .{ .rsa = try rfc8332.from(src) },

            .@"ecdsa-sha2-nistp256",
            .@"ecdsa-sha2-nistp512",
            => return .{ .ecdsa = try rfc5656.from(src) },

            .@"ssh-ed25519",
            => return .{ .ed25519 = try rfc8032.from(src) },
        };
    }
};
