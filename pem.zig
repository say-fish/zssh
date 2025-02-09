// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");
const builtin = @import("builtin");

const meta = @import("meta.zig");

const ForAll = meta.ForAll;
const Struct = meta.Struct;

pub const Error = error{
    InvalidFileFormat,
    InvalidLiteral,
};

pub fn FromIter(comptime T: type) type {
    if (@typeInfo(T) == .@"struct") {
        const decl_type = fn (*meta.member(T, "Iterator")) Error!T;

        return meta.has_decl(T, "from_iter", decl_type);
    }

    if (T == []const u8) return T;

    @compileError(@typeName(T) ++ " does not satisfy FromIter");
}

pub fn Tokenize(comptime T: type) type {
    const decl_type =
        fn ([]const u8) callconv(.@"inline") meta.member(T, "TokenIterator");

    return meta.has_decl(T, "tokenize", decl_type);
}

pub fn Literal(comptime L: []const u8, comptime I: type) type {
    return struct {
        const PREAMBLE = L;

        const Self = @This();
        pub const Iterator = I;

        pub fn from_iter(it: *I) Error!Self {
            const src = it.next() orelse
                return error.InvalidFileFormat;

            if (std.mem.eql(u8, src, L)) {
                return .{};
            }

            return error.InvalidLiteral;
        }
    };
}

pub fn Blob(comptime I: type) type {
    return struct {
        ref: []const u8,

        const Self = @This();
        pub const Iterator = I;

        pub fn from_iter(it: *I) Error!Self {
            const src = it.rest();

            return .{ .ref = src };
        }
    };
}

// TODO: AutoDecoder
pub fn parse(
    comptime T: type,
    _: ForAll(FromIter, Tokenize(Struct(T))),
    src: []const u8,
) !T {
    var it = T.tokenize(src);

    var ret: T = undefined;

    inline for (comptime std.meta.fields(T)) |field| {
        if (@typeInfo(field.type) == .@"struct") {
            @field(ret, field.name) = try field.type.from_iter(&it);

            continue;
        }

        const ref = it.next() orelse
            return error.InvalidFileFormat;

        @field(ret, field.name) = switch (field.type) {
            []const u8 => ref,
            else => @compileError(
                "cannot parse type " ++ @typeName(field.type),
            ),
        };
    }

    return ret;
}

pub fn decode(
    allocator: std.mem.Allocator,
    decoder: std.base64.Base64Decoder,
    src: []const u8,
) ![]u8 {
    const len = try decoder.calcSizeForSlice(src);

    const der = try allocator.alloc(u8, len);
    errdefer allocator.free(der);

    try decoder.decode(der, src);

    return der;
}

/// Since Zig's `Base64DecoderWithIgnore` does not support `calcSizeForSlice`
/// we need to alloc twice in order to get the actual decoded size.
pub fn decode_with_ignore(
    allocator: std.mem.Allocator,
    decoder: std.base64.Base64DecoderWithIgnore,
    src: []const u8,
) ![]u8 {
    const len = try decoder.calcSizeUpperBound(src.len);

    var der = try allocator.alloc(u8, len);
    defer allocator.free(der);

    const acc_len = try decoder.decode(der, src);

    const aux = try allocator.alloc(u8, acc_len);
    errdefer allocator.free(aux);

    std.mem.copyForwards(u8, aux, der[0..acc_len]);

    return aux;
}

pub const base64 = struct {
    pub const Decoder = std.base64.Base64DecoderWithIgnore.init(
        std.base64.standard.alphabet_chars,
        std.base64.standard.pad_char,
        &.{ '\n', '\r' },
    );
};
