// SPDX-License-Identifier: GPL-3.0-only

//! Generic SSH certificate.
//!
//! Support for parsing DER and PEM enconded SSH certificates. PEM decoding can
//! be done in place or not. All parsing is done in place, with zero
//! allocations, for this, the certificate data (DER) **MUST** outlive the
//! parsed certificate.

const std = @import("std");

const magic = @import("magic.zig");
const enc = @import("enc.zig");
const mem = @import("mem.zig");
const meta = @import("meta.zig");
const pem = @import("pem.zig");
const pk = @import("pk.zig");
const sig = @import("sig.zig");

pub const Error = error{
    /// This indicates, either, PEM corruption, or certificate corruption.
    InvalidMagicString,
    /// As per spec, repeated extension are not allowed.
    RepeatedExtension,
    UnkownExtension,
} || enc.Error;

const Box = mem.Box;
const BoxRef = mem.BoxRef;

const And = meta.And;

const I = std.mem.TokenIterator(u8, .any);

pub fn MagicString(comptime T: type) type {
    return magic.MakeMagic(
        T,
        I,
        enc.rfc4251.parse_string,
        enc.rfc4251.encoded_size,
    );
}

pub const Pem = struct {
    magic: []const u8, // FIXME: MagicString
    der: []const u8,
    comment: pem.Blob(TokenIterator),

    const Self = @This();
    pub const TokenIterator = I;

    pub inline fn tokenize(src: []const u8) TokenIterator {
        return std.mem.tokenizeAny(u8, src, " ");
    }

    pub fn parse(src: []const u8) !Self {
        return try pem.parse(Self, src);
    }

    pub fn decode(
        self: *const Self,
        allocator: std.mem.Allocator,
        decoder: std.base64.Base64Decoder,
    ) !Box([]u8, .plain) {
        const data = try pem.decode(allocator, decoder, self.der);

        return .{ .allocator = allocator, .data = data };
    }
};

pub const CertType = enum(u2) {
    user = 1,
    host = 2,

    const Self = @This();

    const Box = mem.Unmanaged(u8);

    pub fn parse(src: []const u8) enc.Error!enc.Cont(CertType) {
        const next, const val = try enc.rfc4251.parse_int(u32, src);

        return .{ next, @enumFromInt(val) };
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size(u32, @intFromEnum(self.*));
    }
};

/// The critical options section of the certificate specifies zero or more
/// options on the certificate's validity.
pub const Critical = struct {
    ref: []const u8 = undefined,

    const Self = @This();

    pub const Kind = enum {
        /// Specifies a command that is executed (replacing any the user
        /// specified on the ssh command-line) whenever this key is used for
        /// authentication.
        @"force-command",

        /// Comma-separated list of source addresses from which this
        /// certificate is accepted for authentication. Addresses are specified
        /// in CIDR format (nn.nn.nn.nn/nn or hhhh::hhhh/nn). If this option is
        /// not present, then certificates may be presented from any source
        /// address.
        @"source-address",

        /// Flag indicating that signatures made with this certificate must
        /// assert FIDO user verification (e.g. PIN or biometric). This option
        /// only makes sense for the U2F/FIDO security key types that support
        /// this feature in their signature formats.
        @"verify-required",

        pub const STRINGS = enc.enum_to_str(Kind);

        pub fn as_string(self: *const Kind) []const u8 {
            return Kind.STRINGS[@intFromEnum(self.*)];
        }

        // `stringToEnum` is slower that doing this dance
        pub fn from_slice(src: []const u8) !Kind {
            for (Kind.STRINGS, 0..) |s, i|
                if (std.mem.eql(u8, s, src))
                    return @enumFromInt(i);

            return error.InvalidData;
        }

        pub fn parse(src: []const u8) enc.Error!enc.Cont(Kind) {
            const next, const tag = try enc.rfc4251.parse_string(src);

            return .{ next, try Kind.from_slice(tag) };
        }
    };

    pub const Option = struct {
        kind: Kind,
        value: []const u8,

        pub fn parse(src: []const u8) enc.Error!enc.Cont(Option) {
            const next, const kind = try Kind.parse(src);

            const final, const buf = try enc.rfc4251.parse_string(src[next..]);

            _, const value = try enc.rfc4251.parse_string(buf);

            return .{ next + final, .{ .kind = kind, .value = value } };
        }
    };

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Critical) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size([]const u8, self.ref);
    }

    pub const Iterator = enc.GenericIterator(Option);
    pub fn iter(self: *const Self) Self.Iterator {
        return .{ .ref = self.ref };
    }

    inline fn parse_value(ref: []const u8, off: *usize, k: []const u8) ?Critical {
        const opt = Self.is_valid_option(k) orelse
            return null;

        const next, const buf = enc.rfc4251.parse_string(ref[off.*..]) catch
            return null;

        _, const value = enc.rfc4251.parse_string(buf) catch
            return null;

        off.* += next;

        return .{ .kind = opt, .value = value };
    }
};

/// The extensions section of the certificate specifies zero or more
/// non-critical certificate extensions.
pub const Extensions = struct {
    ref: []const u8,

    const Self = @This();

    pub const Iterator = enc.GenericIterator(Kind);
    pub const Kind = enum(u8) {
        /// Flag indicating that signatures made with this certificate need not
        /// assert FIDO user presence. This option only makes sense for the
        /// U2F/FIDO security key types that support this feature in their
        /// signature formats.
        @"no-touch-required" = 0x01 << 0,

        /// Flag indicating that X11 forwarding should be permitted. X11
        /// forwarding will be refused if this option is absent.
        @"permit-X11-forwarding" = 0x01 << 1,

        /// Flag indicating that agent forwarding should be allowed. Agent
        /// forwarding must not be permitted unless this option is present.
        @"permit-agent-forwarding" = 0x01 << 2,

        /// Flag indicating that port-forwarding should be allowed. If this
        /// option is not present, then no port forwarding will be allowed.
        @"permit-port-forwarding" = 0x01 << 3,

        /// Flag indicating that PTY allocation should be permitted. In the
        /// absence of this option PTY allocation will be disabled.
        @"permit-pty" = 0x01 << 4,

        /// Flag indicating that execution of ~/.ssh/rc should be permitted.
        /// Execution of this script will not be permitted if this option is
        /// not present.
        @"permit-user-rc" = 0x01 << 5,

        const STRINGS = enc.enum_to_str(Kind);

        pub inline fn as_string(self: *const Kind) []const u8 {
            return STRINGS[@ctz(@intFromEnum(self.*))];
        }

        // `stringToEnum` is slower that doing this dance
        pub fn from_slice(src: []const u8) !Kind {
            for (STRINGS, 0..) |s, i|
                if (std.mem.eql(u8, s, src))
                    return @enumFromInt(@shlExact(
                        @as(u8, 0x01),
                        @as(u3, @intCast(i)),
                    ));

            return error.InvalidData;
        }

        pub fn parse(src: []const u8) enc.Error!enc.Cont(Kind) {
            const next, const tag = try enc.rfc4251.parse_string(src);

            // XXX: Why is this null terminated?
            const final, const zero = try enc.rfc4251.parse_int(u32, src[next..]);

            if (zero != 0) {
                return error.InvalidData;
            }

            return .{ next + final, try Kind.from_slice(tag) };
        }
    };

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Extensions) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size([]const u8, self.ref);
    }

    pub fn iter(self: *const Self) Iterator {
        return .{ .ref = self.ref, .off = 0 };
    }

    /// Returns the extensions as bitflags, checking if they are valid.
    pub fn to_bitflags(self: *const Self) Error!u8 {
        var ret: u8 = 0;

        var it = self.iter();

        outer: while (try it.next()) |ext| {
            // This is ok since the iterator already checked the values
            const bit: u8 = @intFromEnum(ext);

            if (ret & bit != 0)
                return Error.RepeatedExtension;

            ret |= bit;

            continue :outer;
        }

        std.debug.assert(it.done());

        return ret;
    }
};

const Principals = struct {
    ref: []const u8,

    const Self = @This();

    pub const Principal = struct {
        value: []const u8,

        pub fn parse(src: []const u8) enc.Error!enc.Cont(Principal) {
            return try enc.parse_with_cont(Principal, src);
        }
    };

    pub const Iterator = enc.GenericIterator(Principal);

    pub fn iter(self: *const Self) Iterator {
        return .{ .ref = self.ref };
    }

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Principals) {
        const next, const ref = try enc.rfc4251.parse_string(src);

        return .{ next, .{ .ref = ref } };
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size([]const u8, self.ref);
    }
};

/// Generic type for a SSH certificate.
pub fn GenericCert(
    comptime M: type, // Magic preamble
    comptime T: type, // Type of the public_key
    comptime P: type, // Type of signature_key
    comptime S: type, // Type of signature
) type {
    // TODO: assert TYPES is a struct
    return struct {
        magic: M,
        nonce: []const u8,
        public_key: T,
        serial: u64,
        kind: CertType,
        key_id: []const u8,
        valid_principals: Principals,
        valid_after: u64,
        valid_before: u64,
        critical_options: Critical,
        extensions: Extensions,
        reserved: []const u8,
        signature_key: Pk,
        signature: Sig,

        const Self = @This();

        pub const Magic = M;
        pub const Pk = P;
        pub const Sig = S;

        fn from(src: []const u8) Error!Self {
            return try enc.parse(Self, src);
        }

        pub fn from_pem(
            allocator: std.mem.Allocator,
            decoder: std.base64.Base64Decoder,
            pem_enc: *const Pem,
        ) !BoxRef(Self, .plain) {
            var der = try pem_enc.decode(allocator, decoder);
            errdefer der.deinit();

            const cert = try Self.from_bytes(der.data);

            return .{ .allocator = allocator, .data = cert, .ref = der.data };
        }

        pub fn from_bytes(src: []const u8) Error!Self {
            return try Self.from(src);
        }

        pub fn enconded_sig_size(self: *const Self) u32 {
            var ret: u32 = 0;

            inline for (std.meta.fields(Self)) |field| {
                if (comptime !std.mem.eql(u8, "signature", field.name)) {
                    ret +=
                        enc.encoded_size(field.type, @field(self, field.name));
                }
            }

            return ret + @sizeOf(u32);
        }
    };
}
