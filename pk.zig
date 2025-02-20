// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const enc = @import("enc.zig");
const mem = @import("mem.zig");
const pem = @import("pem.zig");

const magic = @import("magic.zig");

const Box = mem.Box;

const Error = @import("error.zig").Error;

const BoxRef = mem.BoxRef;

pub fn MakeMagic(comptime T: type) type {
    return magic.MakeMagic(
        T,
        std.mem.TokenIterator(u8, .any),
        []const u8,
        enc.rfc4251.parse_string,
        enc.rfc4251.encoded_size,
    );
}

pub fn Pem(comptime Magic: type) type {
    return struct {
        magic: Magic,
        der: []const u8,
        comment: pem.Blob(TokenIterator),

        const Self = @This();
        pub const TokenIterator = std.mem.TokenIterator(u8, .any);

        pub inline fn tokenize(src: []const u8) TokenIterator {
            return std.mem.tokenizeAny(u8, src, " ");
        }

        pub fn parse(src: []const u8) !Self {
            return try pem.parse(Self, TokenIterator, src);
        }

        pub fn decode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) Error!Box([]u8, .plain) {
            const data = try pem.decode(
                allocator,
                std.base64.standard.Decoder,
                self.der,
            );

            return .{ .allocator = allocator, .data = data };
        }
    };
}
