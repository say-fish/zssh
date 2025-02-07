// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const enc = @import("enc.zig");
const mem = @import("mem.zig");
const pem = @import("pem.zig");
const pk = @import("pk.zig");

// TODO: Error

const Box = mem.Box;
const BoxRef = mem.BoxRef;

const I = std.mem.TokenIterator(u8, .sequence);

fn fixed_string_encoded_size(_: anytype) u32 {
    return 6;
}

fn parse_fixed_string(src: []const u8) enc.Error!enc.Cont([6]u8) {
    if (src.len < 6) {
        return enc.Error.MalformedString;
    }

    return .{ 6, src[0..6].* };
}

pub fn Preamble(comptime T: type) type {
    return enc.GenericMagicString(
        T,
        I,
        parse_fixed_string,
        fixed_string_encoded_size,
    );
}

pub fn Magic(comptime T: type) type {
    return enc.GenericMagicString(
        T,
        I,
        enc.rfc4251.parse_string,
        enc.rfc4251.encoded_size,
    );
}

pub fn Pem(comptime P: []const u8, comptime S: []const u8) type {
    return struct {
        pre: pem.Literal(P, TokenIterator),
        der: []const u8,
        suf: pem.Literal(S, TokenIterator),

        const Self = @This();

        pub const TokenIterator = I;

        pub inline fn tokenize(src: []const u8) TokenIterator {
            return std.mem.tokenizeSequence(u8, src, "-----");
        }

        pub fn parse(src: []const u8) !Self {
            return try pem.parse(Self, undefined, src);
        }

        pub fn decode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) !Box([]u8, .sec) {
            const sig = try pem.decode_with_ignore(
                allocator,
                pem.base64.Decoder,
                self.der,
            );

            return .{ .allocator = allocator, .data = sig };
        }
    };
}
