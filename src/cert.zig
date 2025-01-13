//! SSH certificate parsing and verification.
//!
//! Support for parsing DER and PEM enconded SSH certificates. PEM decoding can
//! be done in place or not. All parsing is done in place, with zero
//! allocations, for this, the certificate data (DER) **MUST** outlive the
//! parsed certificate.

const std = @import("std");

const decoder = @import("decoder.zig");
const key = @import("key.zig");
const proto = @import("proto.zig");
const sig = @import("sig.zig");

pub const Error = error{
    /// This indicates, either, PEM corruption, or certificate corruption.
    InvalidMagicString,
    /// As per spec, repeated extension are not allowed.
    RepeatedExtension,
    UnkownExtension,
} || proto.Error;

fn MagicString(comptime T: type) type {
    return proto.GenericMagicString(
        T,
        proto.rfc4251.parse_string,
        proto.rfc4251.encoded_size,
    );
}

fn GenericIteratorImpl(comptime T: type, parse_value: anytype) type {
    return struct {
        ref: []const u8,
        off: usize,

        const Self = @This();

        pub fn next(self: *Self) T {
            if (self.done()) return null;

            const off, const ret = proto.rfc4251.parse_string(self.ref[self.off..]) catch
                return null;

            self.off += off;

            return parse_value(self.ref, &self.off, ret);
        }

        pub inline fn reset(self: *Self) void {
            self.off = 0;
        }

        pub inline fn done(self: *const Self) bool {
            return self.off == self.ref.len;
        }
    };
}

fn GenericIterator(comptime parse_value: anytype) type {
    const T = switch (@typeInfo(@TypeOf(parse_value))) {
        .@"fn" => |func| func.return_type.?,
        else => @compileError("Expected fn"),
    };

    return GenericIteratorImpl(T, parse_value);
}

pub const Pem = struct {
    magic: []const u8,
    der: []u8,
    comment: []const u8,

    pub inline fn tokenize(src: []const u8) std.mem.TokenIterator(u8, .any) {
        return std.mem.tokenizeAny(u8, src, " ");
    }
};

pub const CertType = enum(u2) {
    user = 1,
    host = 2,

    pub inline fn parse(src: []const u8) proto.Error!proto.Cont(CertType) {
        const next, const val = try proto.rfc4251.parse_int(u32, src);

        return .{ next, @enumFromInt(val) };
    }
};

/// The critical options section of the certificate specifies zero or more
/// options on the certificate's validity.
pub const CriticalOptions = struct {
    ref: []const u8 = undefined,

    const Self = @This();

    pub const Tags = enum {
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

        pub const strings = proto.enum_to_str(Self.Tags);

        pub fn as_string(self: *const Self.Tags) []const u8 {
            return Self.Tag.strings[self.*];
        }
    };

    pub inline fn parse(buf: []const u8) proto.Error!proto.Cont(CriticalOptions) {
        const next, const ref = try proto.rfc4251.parse_string(buf);

        return .{ next, .{ .ref = ref } };
    }

    pub fn iter(self: *const Self) Self.Iterator {
        return .{ .ref = self.ref, .off = 0 };
    }

    pub const Iterator = GenericIterator(
        struct {
            // FIXME: Should return an error
            inline fn parse_value(ref: []const u8, off: *usize, k: []const u8) ?CriticalOption {
                const opt = Self.is_valid_option(k) orelse
                    return null;

                const next, const buf = proto.rfc4251.parse_string(ref[off.*..]) catch
                    return null;

                _, const value = proto.rfc4251.parse_string(buf) catch
                    return null;

                off.* += next;

                return .{ .kind = opt, .value = value };
            }
        }.parse_value,
    );

    fn is_valid_option(opt: []const u8) ?CriticalOptions.Tags {
        for (Self.Tags.strings, 0..) |s, i|
            if (std.mem.eql(u8, s, opt))
                return @enumFromInt(i);

        return null;
    }
};

pub const CriticalOption = struct {
    kind: CriticalOptions.Tags,
    value: []const u8,
};

/// The extensions section of the certificate specifies zero or more
/// non-critical certificate extensions.
pub const Extensions = struct {
    ref: []const u8 = undefined,

    const Self = @This();

    pub const Tags = enum(u8) {
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

        const strings = proto.enum_to_str(Self.Tags);

        pub inline fn as_string(self: *const Self.Tags) []const u8 {
            return Self.strings[@intFromEnum(self.*)];
        }
    };

    pub inline fn parse(buf: []const u8) proto.Error!proto.Cont(Extensions) {
        const next, const ref = try proto.rfc4251.parse_string(buf);

        return .{ next, .{ .ref = ref } };
    }

    pub fn iter(self: *const Self) Self.Iterator {
        return .{ .ref = self.ref, .off = 0 };
    }

    pub const Iterator = GenericIterator(
        struct {
            inline fn parse_value(ref: []const u8, off: *usize, k: []const u8) ?[]const u8 {
                // Skip empty pair
                if (ref.len != off.*) off.* += @sizeOf(u32);

                return k;
            }
        }.parse_value,
    );

    /// Returns the extensions as bitflags, checking if they are valid.
    pub fn to_bitflags(self: *const Self) Error!u8 {
        var ret: u8 = 0;

        var it = self.iter();

        outer: while (it.next()) |ext| {
            for (Self.Tags.strings, 0..) |ext_str, j| {
                if (std.mem.eql(u8, ext, ext_str)) {
                    const bit: u8 = (@as(u8, 0x01) << @as(u3, @intCast(j)));

                    if (ret & bit != 0)
                        return Error.RepeatedExtension;

                    ret |= bit;

                    continue :outer;
                }
            }

            return Error.UnkownExtension;
        }

        return ret;
    }
};

const Principals = struct {
    ref: []const u8,

    const Self = @This();

    pub const Iterator = GenericIterator(Self.parse_value);

    pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Principals) {
        const next, const ref = try proto.rfc4251.parse_string(src);

        return .{ next, .{ .ref = ref } };
    }

    pub fn iter(self: *const Self) Self.Iterator {
        return .{ .ref = self.ref, .off = 0 };
    }

    inline fn parse_value(_: []const u8, _: *usize, k: []const u8) ?[]const u8 {
        return k;
    }
};

pub const Cert = union(enum) {
    rsa: Rsa,
    ecdsa: Ecdsa,
    ed25519: Ed25519,

    const Self = @This();

    pub const Magic = MagicString(enum {
        @"ssh-rsa-cert-v01@openssh.com",
        @"rsa-sha2-256-cert-v01@openssh.com",
        @"rsa-sha2-512-cert-v01@openssh.com",
        @"ecdsa-sha2-nistp256-cert-v01@openssh.com",
        @"ecdsa-sha2-nistp384-cert-v01@openssh.com",
        @"ecdsa-sha2-nistp521-cert-v01@openssh.com",
        @"ssh-ed25519-cert-v01@openssh.com",
    });

    // TODO: from bytes...

    pub fn from_pem(pem: *const Pem) Error!Self {
        const magic = try Magic.from_slice(pem.magic);

        return switch (magic) {
            .@"ssh-rsa-cert-v01@openssh.com",
            .@"rsa-sha2-256-cert-v01@openssh.com",
            .@"rsa-sha2-512-cert-v01@openssh.com",
            => .{ .rsa = try Rsa.from_pem(pem) },

            .@"ecdsa-sha2-nistp256-cert-v01@openssh.com",
            .@"ecdsa-sha2-nistp384-cert-v01@openssh.com",
            .@"ecdsa-sha2-nistp521-cert-v01@openssh.com",
            => .{ .ecdsa = try Ecdsa.from_pem(pem) },

            .@"ssh-ed25519-cert-v01@openssh.com",
            => .{ .ed25519 = try Ed25519.from_pem(pem) },
        };
    }
};

pub const CertDecoder = decoder.GenericDecoder(Pem, std.base64.Base64Decoder);

fn GenericCert(comptime M: type, comptime T: type) type {
    // TODO: assert T is a struct
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
        critical_options: CriticalOptions,
        extensions: Extensions,
        reserved: []const u8,
        signature_key: key.pk.Pk,
        signature: sig.Sig,

        const Self = @This();

        pub const Magic = M;

        fn from(src: []const u8) Error!Self {
            return try proto.parse(Self, src);
        }

        pub fn from_pem(pem: *const Pem) Error!Self {
            return try Self.from(pem.der);
        }

        pub fn from_bytes(src: []const u8) Error!Self {
            return try Self.from(src);
        }
    };
}

pub const Rsa = GenericCert(MagicString(enum {
    @"ssh-rsa-cert-v01@openssh.com",
    @"rsa-sha2-256-cert-v01@openssh.com",
    @"rsa-sha2-512-cert-v01@openssh.com",
}), struct {
    e: []const u8,
    n: []const u8,

    const Self = @This();

    pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Self) {
        const next, const e = try proto.rfc4251.parse_string(src);
        const last, const n = try proto.rfc4251.parse_string(src[next..]);

        return .{ next + last, .{ .e = e, .n = n } };
    }
});

pub const Ecdsa = GenericCert(MagicString(enum {
    @"ecdsa-sha2-nistp256-cert-v01@openssh.com",
    @"ecdsa-sha2-nistp384-cert-v01@openssh.com",
    @"ecdsa-sha2-nistp521-cert-v01@openssh.com",
}), struct {
    curve: []const u8,
    pk: []const u8,

    const Self = @This();

    pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Self) {
        const next, const curve = try proto.rfc4251.parse_string(src);
        const last, const pk = try proto.rfc4251.parse_string(src[next..]);

        return .{ next + last, .{ .curve = curve, .pk = pk } };
    }
});

pub const Ed25519 = GenericCert(MagicString(enum {
    @"ssh-ed25519-cert-v01@openssh.com",
}), struct {
    pk: []const u8,

    const Self = @This();

    pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Self) {
        const next, const pk = try proto.rfc4251.parse_string(src);

        return .{ next, .{ .pk = pk } };
    }
});
