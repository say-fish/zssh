const std = @import("std");

const mem = @import("mem.zig");
const pem = @import("pem.zig");
const proto = @import("proto.zig");

pub const Error = error{
    /// This indicates, either: PEM corruption, DER corruption, or an
    /// unsupported magic string.
    InvalidMagicString,
    /// The checksum for private keys is invalid, meaning either, decryption
    /// was not successful, or data is corrupted. This is NOT an auth form
    /// error.
    InvalidChecksum,
} || proto.Error || std.mem.Allocator.Error;

// TODO: add support for FIDO2/U2F keys

pub const Pem = struct {
    magic: []const u8,
    der: []const u8,
    comment: pem.Blob(std.mem.TokenIterator(u8, .any)),

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

    pub fn tokenize(src: []const u8) std.mem.TokenIterator(u8, .any) {
        return std.mem.tokenizeAny(u8, src, " ");
    }
};

fn MagicString(comptime T: type) type {
    return proto.GenericMagicString(
        T,
        proto.rfc4251.parse_string,
        proto.rfc4251.encoded_size,
    );
}

pub const Rsa = struct {
    magic: Magic,
    e: []const u8, // TODO: mpint
    n: []const u8, // TODO: mpint

    const Self = @This();

    const Magic = MagicString(enum { @"ssh-rsa" });

    fn from(src: []const u8) Error!Rsa {
        return try proto.parse(Self, src);
    }

    pub fn from_bytes(src: []const u8) Error!Rsa {
        return try Self.from(src);
    }

    pub fn from_pem(encoded_pem: Pem) Error!Rsa {
        // FIXME:
        // XXX: Check if PEM magic matches what we got from the DER
        return try Self.from(encoded_pem.der);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return proto.struct_encoded_size(self);
    }
};

pub const Ecdsa = struct {
    magic: Magic,
    curve: []const u8,
    pk: []const u8,

    const Self = @This();

    const Magic = MagicString(enum {
        @"ecdsa-sha2-nistp256",
        @"ecdsa-sha2-nistp384",
        @"ecdsa-sha2-nistp521",
    });

    fn from(src: []const u8) Error!Ecdsa {
        return try proto.parse(Self, src);
    }

    pub fn from_bytes(src: []const u8) Error!Ecdsa {
        return try Self.from(src);
    }

    pub fn from_pem(encoded_pem: Pem) Error!Ecdsa {
        return try Self.from(encoded_pem.der);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return proto.struct_encoded_size(self);
    }
};

pub const Ed25519 = struct {
    magic: Magic,
    pk: []const u8,

    const Self = @This();

    pub const Magic = MagicString(enum { @"ssh-ed25519" });

    fn from(src: []const u8) Error!Ed25519 {
        return try proto.parse(Self, src);
    }

    pub fn from_bytes(src: []const u8) Error!Ed25519 {
        return try Self.from(src);
    }

    // FIXME:
    pub fn from_pem(encoded_pem: Pem) Error!Ed25519 {
        return try Self.from(encoded_pem.der);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return proto.struct_encoded_size(self);
    }
};

pub const Pk = union(enum) {
    rsa: Rsa,
    ecdsa: Ecdsa,
    ed25519: Ed25519,

    const Self = @This();

    pub const Magic = MagicString(enum {
        @"ssh-rsa",
        @"ecdsa-sha2-nistp256",
        @"ecdsa-sha2-nistp384",
        @"ecdsa-sha2-nistp521",
        @"ssh-ed25519",
    });

    pub inline fn parse(src: []const u8) proto.Error!proto.Cont(Pk) {
        const next, const key = try proto.rfc4251.parse_string(src);

        return .{ next, Self.from_bytes(key) catch return Error.InvalidData };
    }

    pub fn from_bytes(src: []const u8) !Self {
        _, const magic = try proto.rfc4251.parse_string(src);

        return switch (try Magic.from_slice(magic)) {
            .@"ssh-rsa",
            => .{ .rsa = try Rsa.from_bytes(src) },

            .@"ecdsa-sha2-nistp256",
            .@"ecdsa-sha2-nistp384",
            .@"ecdsa-sha2-nistp521",
            => .{ .ecdsa = try Ecdsa.from_bytes(src) },

            .@"ssh-ed25519",
            => .{ .ed25519 = try Ed25519.from_bytes(src) },
        };
    }

    pub fn encoded_size(self: *const Self) u32 {
        return switch (self.*) {
            .rsa => |value| proto.encoded_size(value),

            .ecdsa => |value| proto.encoded_size(value),

            .ed25519 => |value| proto.encoded_size(value),
        };
    }
};
