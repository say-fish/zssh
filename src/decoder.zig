const std = @import("std");
const builtin = @import("builtin");

// TODO: AutoDecoder
pub fn parse(comptime T: type, src: []const u8) !T {
    if (@typeInfo(T) != .@"struct")
        @compileError("Expected struct, got: " ++ @typeName(T));

    if (!@hasDecl(T, "tokenize"))
        @compileError(@typeName(T) ++ " does not define `tokenize`");

    var it = T.tokenize(src);

    var ret: T = undefined;

    // FIXME: This turned out to be a not so elegant approach. But it
    // works for now.
    inline for (comptime std.meta.fields(T)) |field| {
        if (@typeInfo(field.type) == .@"struct" and
            @hasDecl(field.type, "blob"))
        {
            @field(ret, field.name) = field.type.blob(it.rest());

            continue;
        }

        const val = it.next() orelse
            return error.InvalidFileFormat;

        if (@typeInfo(field.type) == .@"struct" and
            @hasDecl(field.type, "parse"))
        {
            try field.type.parse(val);

            continue;
        }

        @field(ret, field.name) = switch (field.type) {
            []const u8 => val,
            else => @panic("Wrong type"),
        };
    }

    return ret;
}

pub fn decode_with_true_size(
    allocator: std.mem.Allocator,
    decoder: anytype,
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
pub fn decode_with_total_size(
    allocator: std.mem.Allocator,
    decoder: anytype,
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
    pub const pem = struct {
        pub const Decoder = std.base64.Base64DecoderWithIgnore.init(
            std.base64.standard.alphabet_chars,
            std.base64.standard.pad_char,
            &.{ '\n', '\r' },
        );
    };
};
