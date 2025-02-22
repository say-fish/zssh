const std = @import("std");

const enc = @import("enc.zig");
const mem = @import("mem.zig");

pub const Box = mem.Box;

pub const Cont = enc.Cont;

pub const BoxRef = mem.BoxRef;

pub const Error = @import("error.zig").Error;

pub const cert = struct {
    const gen = @import("cert.zig");
    const pk = @import("pk.zig");
    const sig = @import("sig.zig");

    pub const Magic = gen.MakeMagic(enum {
        @"ssh-rsa-cert-v01@openssh.com",
        @"rsa-sha2-256-cert-v01@openssh.com",
        @"rsa-sha2-512-cert-v01@openssh.com",
        @"ecdsa-sha2-nistp256-cert-v01@openssh.com",
        @"ecdsa-sha2-nistp384-cert-v01@openssh.com",
        @"ecdsa-sha2-nistp521-cert-v01@openssh.com",
        @"ssh-ed25519-cert-v01@openssh.com",
    });

    // TODO: Move to another namespace
    fn OpenSSHCert(comptime MagicString: type, comptime PublicKey: type) type {
        return gen.MakeCert(
            MagicString,
            PublicKey,
            public.Key,
            signature.Signature,
        );
    }

    pub const Rsa = OpenSSHCert(gen.MakeMagic(enum {
        @"ssh-rsa-cert-v01@openssh.com",
        @"rsa-sha2-256-cert-v01@openssh.com",
        @"rsa-sha2-512-cert-v01@openssh.com",
    }), struct {
        e: []const u8,
        n: []const u8,

        const Self = @This();

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try enc.parse_with_cont(Self, src);
        }

        pub fn encode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) anyerror!Box(Self, .plain) {
            return enc.encode_value(Self, allocator, self, .plain);
        }

        pub fn encoded_size(self: *const Self) u32 {
            return enc.encoded_size_struct(Self, self);
        }
    });

    pub const Ecdsa = OpenSSHCert(gen.MakeMagic(enum {
        @"ecdsa-sha2-nistp256-cert-v01@openssh.com",
        @"ecdsa-sha2-nistp384-cert-v01@openssh.com",
        @"ecdsa-sha2-nistp521-cert-v01@openssh.com",
    }), struct {
        curve: []const u8,
        pk: []const u8,

        const Self = @This();

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try enc.parse_with_cont(Self, src);
        }

        pub fn encode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) anyerror!Box(Self, .plain) {
            return enc.encode_value(Self, allocator, self, .plain);
        }

        pub fn encoded_size(self: *const Self) u32 {
            return enc.encoded_size_struct(Self, self);
        }
    });

    pub const Ed25519 = OpenSSHCert(gen.MakeMagic(enum {
        @"ssh-ed25519-cert-v01@openssh.com",
    }), struct {
        pk: []const u8,

        const Self = @This();

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try enc.parse_with_cont(Self, src);
        }

        pub fn encode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) anyerror!Box(Self, .plain) {
            return enc.encode_value(Self, allocator, self, .plain);
        }

        pub fn encoded_size(self: *const Self) u32 {
            return enc.encoded_size_struct(Self, self);
        }
    });

    pub const Cert = union(enum) {
        rsa: Rsa,
        ecdsa: Ecdsa,
        ed: Ed25519,

        const Self = @This();

        pub const Pem = gen.MakePem(Magic, std.base64.standard.Decoder);

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
                => .{ .ed = try Ed25519.from_bytes(src) },
            };
        }

        pub fn from_bytes(src: []const u8) !Self {
            return Self.from((try Magic.from_bytes(src)).value, src);
        }

        pub fn from_pem(
            allocator: std.mem.Allocator,
            pem: *const Pem,
        ) Error!BoxRef(Self, .plain) {
            var der = try pem.decode(allocator);
            errdefer der.deinit();

            const cer = try Self.from(pem.magic.value, der.data);

            return .{ .allocator = allocator, .data = cer, .ref = der.data };
        }
    };
};

pub const public = struct {
    const gen = @import("pk.zig");

    pub const Rsa = struct {
        magic: Magic,
        e: []const u8, // TODO: mpint
        n: []const u8, // TODO: mpint

        const Self = @This();

        pub const Magic = gen.MakeMagic(enum { @"ssh-rsa" });

        fn from(src: []const u8) Error!Self {
            return try enc.parse(Self, src);
        }

        pub fn from_bytes(src: []const u8) Error!Self {
            return try Self.from(src);
        }

        pub fn encode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) anyerror!Box([]u8, .plain) {
            return try enc.encode_value(Self, allocator, self, .plain);
        }

        pub fn encoded_size(self: *const Self) u32 {
            return enc.encoded_size_struct(Self, self);
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            try enc.serialize_struct(Self, writer, self);
        }

        pub fn format(
            self: *const Self,
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            try writer.print(" magic: {s}\n", .{self.magic.as_string()});
            try writer.print("     e: {}\n", .{std.fmt.fmtSliceHexUpper(self.e)});
            try writer.print("     n: {}", .{std.fmt.fmtSliceHexUpper(self.n)});
        }

        // TODO: modes
        pub fn fingerprint(self: *const Self) !void {
            var sha = std.crypto.hash.sha2.Sha256.init(.{});
            const stdout = std.io.getStdOut().writer();

            try self.serialize(sha.writer().any());
            var out = std.mem.zeroes([std.crypto.hash.sha2.Sha256.digest_length]u8);

            sha.final(&out);

            try stdout.print("{} SHA256:", .{(self.n.len - 1) * 8}); // FIXME: MPINT
            try std.base64.standard_no_pad.Encoder.encodeWriter(stdout, &out);
            try stdout.print(" (RSA)", .{});
        }
    };

    pub const Ecdsa = struct {
        magic: Magic,
        curve: []const u8,
        pk: []const u8,

        const Self = @This();

        pub const Magic = gen.MakeMagic(enum {
            @"ecdsa-sha2-nistp256",
            @"ecdsa-sha2-nistp384",
            @"ecdsa-sha2-nistp521",
        });

        fn from(src: []const u8) Error!Self {
            return try enc.parse(Self, src);
        }

        pub fn from_bytes(src: []const u8) Error!Self {
            return try Self.from(src);
        }

        pub fn encode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) anyerror!Box([]u8, .plain) {
            return enc.encode_value(Self, allocator, self, .plain);
        }

        pub fn encoded_size(self: *const Self) u32 {
            return enc.encoded_size_struct(Self, self);
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            try enc.serialize_struct(Self, writer, self);
        }

        pub fn format(
            self: *const Self,
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            try writer.print(" magic: {s}\n", .{self.magic.as_string()});
            try writer.print(" curve: {}", .{std.fmt.fmtSliceHexUpper(self.curve)});
            try writer.print("    pk: {}", .{std.fmt.fmtSliceHexUpper(self.pk)});
        }
    };

    pub const Ed25519 = struct {
        magic: Magic,
        pk: []const u8,

        const Self = @This();

        pub const Magic = gen.MakeMagic(enum { @"ssh-ed25519" });

        fn from(src: []const u8) Error!Ed25519 {
            return try enc.parse(Self, src);
        }

        pub fn from_bytes(src: []const u8) Error!Ed25519 {
            return try Self.from(src);
        }

        pub fn encode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) anyerror!Box([]u8, .plain) {
            return enc.encode_value(Self, allocator, self, .plain);
        }

        pub fn encoded_size(self: *const Self) u32 {
            return enc.encoded_size_struct(Self, self);
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            try enc.serialize_struct(Self, writer, self);
        }

        pub fn format(
            self: *const Self,
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            try writer.print(" magic: {s}\n", .{self.magic.as_string()});
            try writer.print("    pk: {}", .{std.fmt.fmtSliceHexUpper(self.pk)});
        }
    };

    pub const Key = union(enum) {
        rsa: Rsa,
        ecdsa: Ecdsa,
        ed: Ed25519,

        const Self = @This();

        pub const Pem = gen.MakePem(Magic, std.base64.standard.Decoder);
        pub const Magic = gen.MakeMagic(enum {
            @"ssh-rsa",
            @"ecdsa-sha2-nistp256",
            @"ecdsa-sha2-nistp384",
            @"ecdsa-sha2-nistp521",
            @"ssh-ed25519",
        });

        pub fn parse(src: []const u8) Error!Cont(Key) {
            const next, const key = try enc.rfc4251.parse_string(src);

            return .{ next, Self.from_bytes(key) catch return Error.InvalidData };
        }

        pub fn from(magic: Magic.Value, src: []const u8) !Self {
            return switch (magic) {
                .@"ssh-rsa",
                => .{ .rsa = try Rsa.from_bytes(src) },

                .@"ecdsa-sha2-nistp256",
                .@"ecdsa-sha2-nistp384",
                .@"ecdsa-sha2-nistp521",
                => .{ .ecdsa = try Ecdsa.from_bytes(src) },

                .@"ssh-ed25519",
                => .{ .ed = try Ed25519.from_bytes(src) },
            };
        }

        pub fn from_bytes(src: []const u8) Error!Self {
            return Self.from((try Magic.from_bytes(src)).value, src);
        }

        pub fn from_pem(
            allocator: std.mem.Allocator,
            pem_enc: Pem,
        ) Error!BoxRef(Self, .plain) {
            const der = try pem_enc.decode(allocator);
            errdefer der.deinit();

            return .{
                .allocator = allocator,
                .data = try Self.from(pem_enc.magic.value, der.data),
                .ref = der.data,
            };
        }

        pub fn encode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) anyerror!Box([]u8, .plain) {
            return switch (self.*) {
                inline else => |value| value.encode(allocator),
            };
        }

        pub fn encoded_size(self: *const Self) u32 {
            return switch (self.*) {
                inline else => |value| enc.encoded_size(@TypeOf(value), value),
            };
        }

        pub fn format(
            self: *const Self,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            switch (self.*) {
                inline else => |k| try k.format(fmt, options, writer),
            }
        }

        pub fn fingerprint(self: *const Self) !void {
            switch (self.*) {
                .rsa => |k| try k.fingerprint(),
                else => @panic("die"),
            }
        }
    };
};

pub const signature = struct {
    const gen = @import("sig.zig");

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

        const Magic = gen.MakeMagic(enum(u1) {
            @"rsa-sha2-256",
            @"rsa-sha2-512",
        });

        fn from(src: []const u8) Error!Self {
            return try enc.parse(Self, src);
        }

        pub fn parse(src: []const u8) Error!Cont(Self) {
            const next, const sig = try enc.rfc4251.parse_string(src);

            return .{ next, try Self.from(sig) };
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
    };

    /// The EdDSA signature of a message M under a private key k is defined as the
    /// PureEdDSA signature of PH(M). In other words, EdDSA simply uses PureEdDSA
    /// to sign PH(M).
    pub const rfc8032 = struct {
        magic: Magic,
        sm: []const u8,

        const Self = @This();

        pub const Magic = gen.MakeMagic(enum(u1) { @"ssh-ed25519" });

        fn from(src: []const u8) Error!Self {
            return try enc.parse(Self, src);
        }

        pub fn parse(src: []const u8) Error!Cont(Self) {
            const next, const sig = try enc.rfc4251.parse_string(src);

            return .{ next, try Self.from(sig) };
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
            @import("pem.zig").base64.Decoder,
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
};

pub const private = struct {
    const gen = @import("sk.zig");

    pub const wire = struct {
        pub const Rsa = struct {
            kind: []const u8,
            // Public key parts
            n: []const u8,
            e: []const u8,
            // Private key parts
            d: []const u8,
            i: []const u8,
            p: []const u8,
            q: []const u8,

            const Self = @This();

            pub fn encode(
                self: *const Self,
                allocator: std.mem.Allocator,
            ) anyerror!Box([]u8, .sec) {
                return try enc.encode_value(Self, allocator, self, .sec);
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

        pub const Ecdsa = struct {
            kind: []const u8,
            // Public parts
            curve: []const u8,
            pk: []const u8,
            // Private parts
            sk: []const u8,

            const Self = @This();

            pub fn encode(
                self: *const Self,
                allocator: std.mem.Allocator,
            ) anyerror!Box([]u8, .sec) {
                return try enc.encode_value(Self, allocator, self, .sec);
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

        pub const Ed25519 = struct {
            kind: []const u8,
            // Public parts
            pk: []const u8,
            // Private parts
            sk: []const u8,

            const Self = @This();

            pub fn encode(
                self: *const Self,
                allocator: std.mem.Allocator,
            ) anyerror!Box([]u8, .sec) {
                return try enc.encode_value(Self, allocator, self, .sec);
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

        pub const Key = union(enum) {
            rsa: Rsa,
            ecdsa: Ecdsa,
            ed: Ed25519,

            const Self = @This();

            pub const Magic = public.Key.Magic;

            // FIXME: Add encode

            pub fn parse(src: []const u8) Error!Cont(Self) {
                const magic = Magic.from_bytes(src) catch
                    return error.InvalidData;

                switch (magic.value) {
                    .@"ssh-rsa",
                    => {
                        const next, const key =
                            try enc.parse_with_cont(Rsa, src);

                        return .{ next, .{ .rsa = key } };
                    },

                    .@"ecdsa-sha2-nistp256",
                    .@"ecdsa-sha2-nistp384",
                    .@"ecdsa-sha2-nistp521",
                    => {
                        const next, const key =
                            try enc.parse_with_cont(Ecdsa, src);

                        return .{ next, .{ .ecdsa = key } };
                    },

                    .@"ssh-ed25519",
                    => {
                        const next, const key =
                            try enc.parse_with_cont(Ed25519, src);

                        return .{ next, .{ .ed = key } };
                    },
                }
            }
        };
    };

    pub const KeyBlob = union(enum) {
        rsa: Rsa,
        ecdsa: Ecdsa,
        ed: Ed25519,

        const Self = @This();

        pub const Rsa = gen.MakeKeyBlob(wire.Rsa);
        pub const Ecdsa = gen.MakeKeyBlob(wire.Ecdsa);
        pub const Ed25519 = gen.MakeKeyBlob(wire.Ed25519);

        pub const Magic = public.Key.Magic;

        // FIXME: Return owned data
        pub fn get_wire(self: *const Self) wire.Key {
            switch (self.*) {
                .rsa => |*rsa| {
                    var ret: wire.Rsa = undefined;

                    mem.shallow_copy(wire.Rsa, &ret, Rsa, rsa);

                    return @unionInit(wire.Key, "rsa", ret);
                },

                .ecdsa => |*ecdsa| {
                    var ret: wire.Ecdsa = undefined;

                    mem.shallow_copy(wire.Ecdsa, &ret, Ecdsa, ecdsa);

                    return @unionInit(wire.Key, "ecdsa", ret);
                },

                .ed => |*ed| {
                    var ret: wire.Ed25519 = undefined;

                    mem.shallow_copy(wire.Ed25519, &ret, Ed25519, ed);

                    return @unionInit(wire.Key, "ed", ret);
                },
            }
        }

        pub fn from_bytes(src: []const u8) !Self {
            _, const ret = try parse(src);
            return ret;
        }

        pub fn parse(src: []const u8) Error!Cont(Self) {
            // FIXME: Double work
            const off, _ = try gen.Checksum.parse(src);
            // FIXME: Double work
            const magic = Magic.from_bytes(src[off..]) catch
                return error.InvalidData;

            switch (magic.value) {
                .@"ssh-rsa",
                => {
                    const next, const key =
                        try enc.parse_with_cont(Rsa, src);

                    return .{ next, .{ .rsa = key } };
                },

                .@"ecdsa-sha2-nistp256",
                .@"ecdsa-sha2-nistp384",
                .@"ecdsa-sha2-nistp521",
                => {
                    const next, const key =
                        try enc.parse_with_cont(Ecdsa, src);

                    return .{ next, .{ .ecdsa = key } };
                },

                .@"ssh-ed25519",
                => {
                    const next, const key =
                        try enc.parse_with_cont(Ed25519, src);

                    return .{ next, .{ .ed = key } };
                },
            }
        }
    };

    pub const Key = gen.MakeSk(
        gen.MakeMagic(enum { @"openssh-key-v1" }),
        gen.MakePem(
            "BEGIN OPENSSH PRIVATE KEY",
            "END OPENSSH PRIVATE KEY",
            @import("pem.zig").base64.Decoder,
        ),
        public.Key,
        KeyBlob,
    );
};

pub const agent = struct {
    const gen = @import("agent.zig");

    pub const Client = gen.MakeClient(
        public.Key,
        private.wire.Key,
        openssh_extensions.Extensions,
        openssh_extensions.Constraints,
    );

    pub const Agent = gen.MakeAgent(
        public.Key,
        signature.Signature,
        openssh_extensions.ExtensionResponse,
    );

    /// OpenSSH's extensions to the agent protocol.
    pub const openssh_extensions = struct {
        /// This extension allows a ssh client to bind an agent connection
        /// to a particular SSH session identifier as derived from the
        /// initial key exchange (as per RFC4253 section 7.2) and the host
        /// key used for that exchange. This binding is verifiable at the
        /// agent by including the initial KEX signature made by the host
        /// key.
        pub const SessionBind = struct {
            hostkey: public.Key,
            identifier: []const u8,
            signature: signature.Signature,
            is_forwarding: u8,

            const Self = @This();

            pub fn parse(src: []const u8) Error!Cont(Self) {
                return try enc.parse_with_cont(Self, src);
            }
        };

        /// Standard OpenSSH key constraints
        pub const Constraints = union(enum) {
            /// This key constraint extension supports destination- and
            /// forwarding path- restricted keys. It may be attached as a
            /// constraint when keys or smartcard keys are added to an agent.
            restrict_destination: RestrictDestination,

            /// This key constraint allows communication to an agent of the
            /// maximum number of signatures that may be made with an XMSS key.
            max_signatures: MaxSignatures,

            /// This key constraint extension allows certificates to be
            /// associated with private keys as they are loaded from a PKCS#11
            /// token.
            associated_certs: AssociatedCerts,

            const Self = @This();

            const RestrictDestination = struct {};
            const MaxSignatures = struct {};
            const AssociatedCerts = struct {};

            pub fn parse(_: []const u8) Error!Cont(Self) {
                @panic("TODO:");
                //return enc.parse(Constraints, src);
            }
        };

        pub const Extensions = union(enum) {
            query: Client.Query,
            @"session-bind@openssh.com": SessionBind,

            const Self = @This();

            pub fn parse(src: []const u8) Error!Cont(Self) {
                return try gen.decode_as_string(Self, src);
            }
        };

        pub const ExtensionResponse = union(enum) {
            query: Agent.Query,

            const Self = @This();

            pub fn parse(src: []const u8) Error!Cont(Self) {
                return try gen.decode_as_string(Self, src);
            }
        };
    };
};
