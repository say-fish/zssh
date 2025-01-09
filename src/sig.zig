const std = @import("std");
const proto = @import("proto.zig");
const key = @import("key.zig");

// TODO: Error
//
fn Magic(comptime T: type) type {
    return proto.GenericMagicString(T, "", proto.rfc4251.parse_string);
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
    magic: Magic(enum(u1) {
        rsa_sha2_256,
        rsa_sha2_512,
    }),
    blob: []const u8,

    const Self = @This();

    fn from(src: []const u8) proto.Error!Self {
        return try proto.parse(Self, src);
    }

    pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Self) {
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
    magic: Magic(enum {
        ecdsa_sha2_nistp256,
        ecdsa_sha2_nistp512,
    }),
    blob: struct {
        r: []const u8,
        s: []const u8,

        const Blob = @This();

        fn from(src: []const u8) proto.Error!Blob {
            return try proto.parse(Blob, src);
        }

        pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Blob) {
            const next, const blob = try proto.rfc4251.parse_string(src);

            return .{ next, try Blob.from(blob) };
        }
    },

    const Self = @This();

    fn from(src: []const u8) proto.Error!Self {
        return try proto.parse(Self, src);
    }

    pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Self) {
        const next, const sig = try proto.rfc4251.parse_string(src);

        return .{ next, try Self.from(sig) };
    }
};

/// The EdDSA signature of a message M under a private key k is defined as the
/// PureEdDSA signature of PH(M).  In other words, EdDSA simply uses PureEdDSA
/// to sign PH(M).
pub const rfc8032 = struct {
    magic: Magic(enum(u1) { ssh_ed25519 }),
    sm: []const u8,

    const Self = @This();

    fn from(src: []const u8) proto.Error!Self {
        return try proto.parse(Self, src);
    }

    pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Self) {
        const next, const sig = try proto.rfc4251.parse_string(src);

        return .{ next, try Self.from(sig) };
    }
};

pub const sshsig = struct {
    fn MagicPreamble(comptime T: type) type {
        return proto.GenericMagicString(T, "", struct {
            fn parse_string_fixed(src: []const u8) proto.Error!proto.Cont([]const u8) {
                if (src.len < 6) {
                    return proto.Error.MalformedString;
                }

                return .{ 6, src[0..6] };
            }
        }.parse_string_fixed);
    }

    magic: MagicPreamble(enum(u1) { SSHSIG }),
    /// Verifiers MUST reject signatures with versions greater than those they
    /// support.
    version: u32,
    /// See: `sshcrypto.key.public.Pk`
    publickey: key.public.Pk,
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
    hash_algorithm: Magic(enum(u1) { sha256, sha512 }),
    signature: Sig,

    const Self = @This();

    fn from(src: []const u8) !Self {
        return try proto.parse(Self, src);
    }

    pub inline fn from_bytes(src: []const u8) !Self {
        return try Self.from(src);
    }

    pub inline fn from_pem(pem: Pem) !Self {
        return try Self.from(pem.der);
    }

    pub const Pem = struct {
        _prefix: proto.Literal("BEGIN SSH SIGNATURE"),
        der: []u8,
        _posfix: proto.Literal("END SSH SIGNATURE"),

        pub inline fn tokenize(
            src: []const u8,
        ) std.mem.TokenIterator(u8, .sequence) {
            return std.mem.tokenizeSequence(u8, src, "-----");
        }
    };
};

pub const Sig = union(enum) {
    rsa: rfc8332,
    ecdsa: rfc5656,
    ed25519: rfc8032,

    const Self = @This();

    pub fn parse(src: []const u8) proto.Error!proto.Cont(Sig) {
        const next, const pk = try proto.rfc4251.parse_string(src);

        return .{
            next,
            Self.from_bytes(pk) catch return error.InvalidData,
        };
    }

    pub fn from_bytes(src: []const u8) !Sig {
        _, const magic = try proto.rfc4251.parse_string(src);

        return switch (try Magic(enum {
            rsa_sha2_256,
            rsa_sha2_512,
            ecdsa_sha2_nistp256,
            ecdsa_sha2_nistp512,
            ssh_ed25519,
        }).from_slice(magic)) {
            .rsa_sha2_256,
            .rsa_sha2_512,
            => return .{ .rsa = try rfc8332.from(src) },

            .ecdsa_sha2_nistp256,
            .ecdsa_sha2_nistp512,
            => return .{ .ecdsa = try rfc5656.from(src) },

            .ssh_ed25519,
            => return .{ .ed25519 = try rfc8032.from(src) },
        };
    }
};
