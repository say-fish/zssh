const std = @import("std");

const enc = @import("enc.zig");
const mem = @import("mem.zig");

const Error = error{
    /// Invalid/Unsupported magic string
    InvalidMagicString,
} || mem.Error || enc.Error;

/// Magic string of format T used by OpenSSH. Encoding is given by the return
/// type of f.
///
/// * T must be an `enum`, where each enumeration corresponds to a **VALID**
///   magic string for this given type.
///
/// * f must have this signature: `fn f([]const u8) Error!Cont(T)`.
pub fn MakeMagic(
    comptime T: type,
    comptime I: type,
    f: anytype,
    x: anytype,
) type {
    return struct {
        // TODO: Assert T is an enum
        // TODO: Assert F is what we want
        // TODO: assert X is what we want
        value: T,

        const Self = @This();

        pub const Box = mem.Box([]u8, .plain);
        pub const Iterator = I;
        pub const Value = T;

        const STRINGS = enc.enum_to_str(T);

        pub fn as_string(self: *const Self) []const u8 {
            return STRINGS[@intFromEnum(self.value)];
        }

        // FIXME:
        pub fn from_iter(it: *Iterator) @import("pem.zig").Error!Self {
            const src = it.next() orelse
                return error.InvalidFileFormat;

            const ret = Self.from_slice(src) catch
                return error.InvalidFileFormat;

            return .{ .value = ret };
        }

        pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
            const next, const magic = try f(src);
            // Small hack, otherwise zig complains
            const ref = switch (comptime @typeInfo(@TypeOf(magic))) {
                .array => &magic,
                else => magic,
            };

            return .{
                next, .{
                    .value = from_slice(ref) catch
                        return enc.Error.InvalidData, // FIXME:
                },
            };
        }

        pub fn from_slice(src: []const u8) Error!Value {
            // `stringToEnum` is slower that doing this dance
            // return std.meta.stringToEnum(Value, src) orelse
            //     return error.InvalidMagicString;
            for (Self.STRINGS, 0..) |s, i|
                if (std.mem.eql(u8, s, src))
                    return @enumFromInt(i);

            return Error.InvalidMagicString;
        }

        pub fn from_bytes(src: []const u8) enc.Error!Self {
            _, const magic = try Self.parse(src);

            return magic;
        }

        pub fn encode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) anyerror!Box {
            return enc.encode_value(Self, allocator, self, .plain);
        }

        pub fn encoded_size(self: *const Self) u32 {
            return @intCast(x(self.as_string()));
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            const F = @FieldType(
                @typeInfo(@typeInfo(@TypeOf(f)).@"fn".return_type.?).error_union.payload,
                "1",
            );
            // FIXME:
            const value: F = switch (F) {
                [:0]u8,
                [:0]const u8,
                => std.mem.span(@as([*c]const u8, self.as_string().ptr)),
                [6]u8 => self.as_string()[0..6].*,
                else => self.as_string(),
            };

            try enc.serialize_any(F, writer, value);
        }
    };
}

const expect_equal = std.testing.expectEqual;
const expect_equal_strings = std.testing.expectEqualStrings;

test "GenericMagicString `encoded_size`" {
    const magic = MakeMagic(
        enum { this_is_a_test_with_size_31 },
        std.mem.TokenIterator(u8, .any),
        enc.rfc4251.parse_string,
        enc.rfc4251.encoded_size,
    ){ .value = .this_is_a_test_with_size_31 };

    try expect_equal(31, magic.encoded_size());
}

test "GenericMagicString `encoded_size` (read_null_terminated)" {
    const magic = MakeMagic(
        enum { this_is_a_test_with_size_28 },
        std.mem.TokenIterator(u8, .any),
        enc.parse_null_terminated_str,
        enc.null_terminated_str_encoded_size,
    ){ .value = .this_is_a_test_with_size_28 };

    try expect_equal(28, magic.encoded_size());
}

test "serialize GenericMagicString" {
    const magic = MakeMagic(
        enum { this_is_a_test_with_size_42 },
        std.mem.TokenIterator(u8, .any),
        enc.rfc4251.parse_string,
        enc.rfc4251.encoded_size,
    ){ .value = .this_is_a_test_with_size_42 };

    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try magic.serialize(list.writer().any());
    try expect_equal(
        .this_is_a_test_with_size_42,
        (try @TypeOf(magic).from_bytes(list.items)).value,
    );
}
