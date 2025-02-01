// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const enc = @import("enc.zig");
const mem = @import("mem.zig");
const pem = @import("pem.zig");

const Managed = mem.Managed;
const ManagedWithRef = mem.ManagedWithRef;

pub const Error = error{
    /// This indicates, either: PEM corruption, DER corruption, or an
    /// unsupported magic string.
    InvalidMagicString,
    /// The checksum for private keys is invalid, meaning either, decryption
    /// was not successful, or data is corrupted. This is NOT an auth form
    /// error.
    InvalidChecksum,
} || enc.Error || std.mem.Allocator.Error;

// TODO: add support for FIDO2/U2F keys

fn MagicString(comptime T: type) type {
    return enc.GenericMagicString(
        T,
        enc.rfc4251.parse_string,
        enc.rfc4251.encoded_size,
    );
}

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
    ) !Managed([]u8) {
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

pub const Rsa = struct {
    magic: Magic,
    e: []const u8, // TODO: mpint
    n: []const u8, // TODO: mpint

    const Self = @This();

    const Magic = MagicString(enum { @"ssh-rsa" });

    fn from(src: []const u8) Error!Rsa {
        return try enc.parse(Self, src);
    }

    pub fn from_bytes(src: []const u8) Error!Rsa {
        return try Self.from(src);
    }

    pub fn encode(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) !Managed([]u8) {
        return try enc.encode_value(Self, allocator, self);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size_struct(self);
    }

    pub fn serialize(self: *const Self, writer: anytype) !void {
        try enc.serialize_struct(Self, writer, self);
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
        return try enc.parse(Self, src);
    }

    pub fn from_bytes(src: []const u8) Error!Ecdsa {
        return try Self.from(src);
    }

    pub fn encode(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) !Managed([]u8) {
        return enc.encode_value(Self, allocator, self);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size_struct(self);
    }

    pub fn serialize(self: *const Self, writer: anytype) !void {
        try enc.serialize_struct(Self, writer, self);
    }
};

pub const Ed25519 = struct {
    magic: Magic,
    pk: []const u8,

    const Self = @This();

    pub const Magic = MagicString(enum { @"ssh-ed25519" });

    fn from(src: []const u8) Error!Ed25519 {
        return try enc.parse(Self, src);
    }

    pub fn from_bytes(src: []const u8) Error!Ed25519 {
        return try Self.from(src);
    }

    pub fn encode(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) !Managed([]u8) {
        return enc.encode_value(Self, allocator, self);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size_struct(self);
    }

    pub fn serialize(self: *const Self, writer: anytype) !void {
        try enc.serialize_struct(Self, writer, self);
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

    pub inline fn parse(src: []const u8) enc.Error!enc.Cont(Pk) {
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
            => .{ .ed25519 = try Ed25519.from_bytes(src) },
        };
    }

    pub fn from_bytes(src: []const u8) !Self {
        return Self.from((try Magic.from_bytes(src)).value, src);
    }

    pub fn from_pem(
        allocator: std.mem.Allocator,
        encoded_pem: Pem,
    ) !ManagedWithRef(Self) {
        const magic = try Magic.from_slice(encoded_pem.magic);

        const der = try encoded_pem.decode(allocator);
        errdefer der.deinit();

        return .{
            .allocator = allocator,
            .data = try Self.from(magic, der.data),
            .ref = der.data,
        };
    }

    pub fn encode(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) !Managed([]u8) {
        return switch (self.*) {
            inline else => |value| value.encode(allocator),
        };
    }

    pub fn encoded_size(self: *const Self) u32 {
        return switch (self.*) {
            inline else => |value| enc.encoded_size(value),
        };
    }
};
