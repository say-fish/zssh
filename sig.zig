// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const magic = @import("magic.zig");
const enc = @import("enc.zig");
const mem = @import("mem.zig");
const pem = @import("pem.zig");
const pk = @import("pk.zig");

const Box = mem.Box;
const BoxRef = mem.BoxRef;
const Error = @import("error.zig").Error;

inline fn parse_fixed_string(src: []const u8) Error!enc.Cont([6]u8) {
    if (src.len < 6) {
        return Error.MalformedString;
    }

    return .{ 6, src[0..6].* };
}

inline fn fixed_string_encoded_size(_: anytype) u32 {
    return 6;
}

pub fn MakePreamble(comptime T: type) type {
    return magic.MakeMagic(
        T,
        std.mem.TokenIterator(u8, .sequence),
        [6]u8,
        parse_fixed_string,
        fixed_string_encoded_size,
    );
}

pub fn MakeMagic(comptime T: type) type {
    return magic.MakeMagic(
        T,
        std.mem.TokenIterator(u8, .sequence),
        []const u8,
        enc.rfc4251.parse_string,
        enc.rfc4251.encoded_size,
    );
}

pub fn MakePem(
    comptime P: []const u8,
    comptime S: []const u8,
    decoder: anytype,
) type {
    return struct {
        pre: pem.Literal(P, TokenIterator),
        der: []const u8,
        suf: pem.Literal(S, TokenIterator),

        const Self = @This();

        pub const TokenIterator = std.mem.TokenIterator(u8, .sequence);

        pub inline fn tokenize(src: []const u8) TokenIterator {
            return std.mem.tokenizeSequence(u8, src, "-----");
        }

        pub fn parse(src: []const u8) !Self {
            return try pem.parse(Self, TokenIterator, src);
        }

        pub fn decode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) !Box([]u8, .sec) {
            const sig = try pem.decode_with_ignore(allocator, decoder, self.der);

            return .{ .allocator = allocator, .data = sig };
        }
    };
}
