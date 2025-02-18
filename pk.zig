// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const enc = @import("enc.zig");
const mem = @import("mem.zig");
const pem = @import("pem.zig");
const magic = @import("magic.zig");

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

const Box = mem.Box;
const BoxRef = mem.BoxRef;

const I = std.mem.TokenIterator(u8, .any);

pub fn MakeMagic(comptime T: type) type {
    return magic.MakeMagic(
        T,
        I,
        enc.rfc4251.parse_string,
        enc.rfc4251.encoded_size,
    );
}

pub fn Pem(comptime M: type) type {
    return struct {
        magic: M,
        der: []const u8,
        comment: pem.Blob(TokenIterator),

        const Self = @This();
        const Magic = M;
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
        ) !Box([]u8, .plain) {
            const data = try pem.decode(
                allocator,
                std.base64.standard.Decoder,
                self.der,
            );

            return .{ .allocator = allocator, .data = data };
        }
    };
}
