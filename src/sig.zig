const std = @import("std");
const proto = @import("proto.zig");

// TODO: Error

pub const Magic = enum(u3) {
    rsa_sha2_256,
    rsa_sha2_512,
    ecdsa_sha2_nistp256,
    ecdsa_sha2_nistp512,
    ssh_ed25519,
    sshsig,

    const Self = @This();

    const strings = proto.enum_to_str(Self, "");

    pub inline fn as_string(self: *const Self) []const u8 {
        return strings[@intFromEnum(self.*)];
    }

    pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Magic) {
        const next, const magic = try proto.rfc4251.parse_string(src);

        inline for (comptime Self.strings, 0..) |s, i|
            if (std.mem.eql(u8, s, magic))
                return .{ next, @enumFromInt(i) };

        return proto.Error.InvalidData;
    }

    pub inline fn from_string(str: []const u8) !Magic {
        inline for (comptime Self.strings, 0..) |s, i|
            if (std.mem.eql(u8, s, str))
                return @enumFromInt(i);

        return error.InvalidMagicString;
    }
};

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
    magic: Magic,
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
    magic: Magic,
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
    // TODO:
};

pub const Sig = union(enum) {
    rsa: rfc8332,
    ecdsa: rfc5656,
    ed25519: rfc8032,
    sshsig: sshsig,

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

        return switch (try Magic.from_string(magic)) {
            .rsa_sha2_256,
            .rsa_sha2_512,
            => return .{ .rsa = try rfc8332.from(src) },

            .ecdsa_sha2_nistp256,
            .ecdsa_sha2_nistp512,
            => return .{ .ecdsa = try rfc5656.from(src) },

            .ssh_ed25519,
            => return .{ .ed25519 = try rfc8032.from(src) },

            .sshsig,
            => @panic("TODO: sshsig is not implemented"),
        };
    }
};
