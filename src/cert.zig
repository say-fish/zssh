//! SSH certificate parsing and verification.
//!
//! Support for parsing DER and PEM enconded SSH certificates. PEM decoding can
//! be done in place or not. All parsing is done in place, with zero
//! allocations, for this, the certificate data (DER) **MUST** outlive the
//! parsed certificate.

const std = @import("std");

const mem = @import("mem.zig");
const pem = @import("pem.zig");
const pk = @import("pk.zig");
const enc = @import("enc.zig");
const sig = @import("sig.zig");

pub const Error = error{
    /// This indicates, either, PEM corruption, or certificate corruption.
    InvalidMagicString,
    /// As per spec, repeated extension are not allowed.
    RepeatedExtension,
    UnkownExtension,
} || enc.Error;

fn MagicString(comptime T: type) type {
    return enc.GenericMagicString(
        T,
        enc.rfc4251.parse_string,
        enc.rfc4251.encoded_size,
    );
}

/// `parse_fn` should be of type:
/// ```zig
///     fn ([]const u8, *usize, []const u8) callconv(.@"inline") type
/// ```
///                                                              ~~~~
///                                                                ^
///                                                                |
///  +-------------------------------------------------------------+
///  |
///  v
///  Due to a limitation in Zig's type system, `type` cannot be infered as a
///  "non-comptime" value.
fn GenericIterator(comptime parse_fn: anytype) type {
    const T = switch (@typeInfo(@TypeOf(parse_fn))) {
        .@"fn" => |func| func.return_type.?,
        else => @compileError("Expected fn"),
    };

    return struct {
        ref: []const u8,
        off: usize,

        const Self = @This();

        pub fn next(self: *Self) T {
            if (self.done()) return null;

            const off, const ret = enc.rfc4251.parse_string(
                self.ref[self.off..],
            ) catch return null;

            self.off += off;

            return parse_fn(self.ref, &self.off, ret);
        }

        pub inline fn reset(self: *Self) void {
            self.off = 0;
        }

        pub inline fn done(self: *const Self) bool {
            return self.off == self.ref.len;
        }
    };
}

pub const Pem = struct {
    // FIXME: MagicString
    magic: []const u8,
    der: []const u8,
    comment: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) !Self {
        return try pem.parse(Self, src);
    }

    pub fn decode(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) !mem.Managed([]u8) {
        return .{
            .allocator = allocator,
            .data = try pem.decode_with_true_size(
                allocator,
                std.base64.standard.Decoder,
                self.der,
            ),
        };
    }

    pub inline fn tokenize(src: []const u8) std.mem.TokenIterator(u8, .any) {
        return std.mem.tokenizeAny(u8, src, " ");
    }
};

pub const CertType = enum(u2) {
    user = 1,
    host = 2,

    const Self = @This();

    pub inline fn parse(src: []const u8) enc.Error!enc.Cont(CertType) {
        const next, const val = try enc.rfc4251.parse_int(u32, src);

        return .{ next, @enumFromInt(val) };
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size(@as(u32, @intFromEnum(self.*)));
    }
};

/// The critical options section of the certificate specifies zero or more
/// options on the certificate's validity.
pub const Critical = struct {
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

        pub const strings = enc.enum_to_str(Tags);

        pub fn as_string(self: *const Tags) []const u8 {
            return Tags.strings[@intFromEnum(self.*)];
        }

        pub fn parse(src: []const u8) enc.Error!enc.Cont(Tags) {
            const next, const tag = try enc.rfc4251.parse_string(src);

            return .{ next, std.meta.stringToEnum(Tags, tag) orelse return error.InvalidData };
        }
    };

    pub const Option = struct {
        kind: Tags,
        values: []const u8,

        // FIXME: This if this is need
        const Value = struct {
            value: []const u8,

            pub fn parse(src: []const u8) enc.Error!enc.Cont(Value) {
                return try enc.parse_with_cont(Value, src);
            }
        };
        const Iterator = enc.GenericIterator(Value);

        pub fn iter(self: *const Option) Option.Iterator {
            return .{ .ref = self.values };
        }

        pub inline fn parse(src: []const u8) enc.Error!enc.Cont(Option) {
            return try enc.parse_with_cont(Option, src);
        }
    };

    pub inline fn parse(src: []const u8) enc.Error!enc.Cont(Critical) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size(self.ref);
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

    fn is_valid_option(opt: []const u8) ?Tags {
        for (Self.Tags.strings, 0..) |s, i|
            if (std.mem.eql(u8, s, opt))
                return @enumFromInt(i);

        return null;
    }
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

        const strings = enc.enum_to_str(Tags);

        pub inline fn as_string(self: *const Tags) []const u8 {
            return Self.strings[@intFromEnum(self.*)];
        }

        pub fn parse(src: []const u8) enc.Error!enc.Cont(Tags) {
            const next, const tag = try enc.rfc4251.parse_string(src);

            // FIXME: Why is this zero
            const final, _ = try enc.rfc4251.parse_int(u32, src);

            return .{ next + final, std.meta.stringToEnum(Tags, tag) orelse return error.InvalidData };
        }
    };
    pub const Iterator = enc.GenericIterator(Tags);

    pub inline fn parse(buf: []const u8) enc.Error!enc.Cont(Extensions) {
        const next, const ref = try enc.rfc4251.parse_string(buf);

        return .{ next, .{ .ref = ref } };
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size(self.ref);
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

    pub inline fn parse(src: []const u8) enc.Error!enc.Cont(Principals) {
        const next, const ref = try enc.rfc4251.parse_string(src);

        return .{ next, .{ .ref = ref } };
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size(self.ref);
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

    fn from(magic: Magic.Value, src: []const u8) !Self {
        return switch (magic) {
            .@"ssh-rsa-cert-v01@openssh.com",
            .@"rsa-sha2-256-cert-v01@openssh.com",
            .@"rsa-sha2-512-cert-v01@openssh.com",
            => .{ .rsa = try Rsa.from_bytes(src) },

            .@"ecdsa-sha2-nistp256-cert-v01@openssh.com",
            .@"ecdsa-sha2-nistp384-cert-v01@openssh.com",
            .@"ecdsa-sha2-nistp521-cert-v01@openssh.com",
            => .{ .ecdsa = try Ecdsa.from_bytes(src) },

            .@"ssh-ed25519-cert-v01@openssh.com",
            => .{ .ed25519 = try Ed25519.from_bytes(src) },
        };
    }

    pub fn from_bytes(src: []const u8) !Self {
        return Self.from((try Magic.from_bytes(src)).value, src);
    }

    pub fn from_pem(
        allocator: std.mem.Allocator,
        encoded_pem: *const Pem,
    ) !mem.ManagedWithRef(Self) {
        const magic = try Magic.from_slice(encoded_pem.magic);

        var der = try encoded_pem.decode(allocator);
        errdefer der.deinit();

        return .{
            .allocator = allocator,
            .data = try Self.from(magic, der.data),
            .ref = der.data,
        };
    }
};

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
        critical_options: Critical,
        extensions: Extensions,
        reserved: []const u8,
        signature_key: pk.Pk,
        signature: sig.Sig,

        const Self = @This();

        pub const Magic = M;

        fn from(src: []const u8) Error!Self {
            return try enc.parse(Self, src);
        }

        pub fn from_pem(
            allocator: std.mem.Allocator,
            encoded_pem: *const Pem,
        ) !mem.ManagedWithRef(Self) {
            var der = try encoded_pem.decode(allocator);
            errdefer der.deinit();

            return .{
                .allocator = allocator,
                // FIXME asssert T has `from_bytes`
                .data = try Self.from_bytes(der.data),
                .ref = der.data,
            };
        }

        pub fn from_bytes(src: []const u8) Error!Self {
            return try Self.from(src);
        }

        pub fn enconded_sig_size(self: *const Self) u32 {
            var ret: u32 = 0;

            inline for (std.meta.fields(Self)) |field| {
                if (comptime !std.mem.eql(u8, "signature", field.name)) {
                    ret += enc.encoded_size(@field(self, field.name));
                }
            }

            return ret + @sizeOf(u32);
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

    pub inline fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.struct_encoded_size(self);
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

    pub inline fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.struct_encoded_size(self);
    }
});

pub const Ed25519 = GenericCert(MagicString(enum {
    @"ssh-ed25519-cert-v01@openssh.com",
}), struct {
    pk: []const u8,

    const Self = @This();

    pub inline fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.struct_encoded_size(self);
    }
});
