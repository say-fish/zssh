const std = @import("std");

const enc = @import("enc.zig");
const mem = @import("mem.zig");

const meta = @import("meta.zig");

const Cont = enc.Cont;
const Enum = meta.Enum;

const Error = @import("error.zig").Error;

pub fn enum_to_str(
    comptime T: type,
    comptime E: type,
) [std.meta.fields(Enum(T)).len]E {
    if (@typeInfo(T) != .@"enum") @compileError("Expected enum");

    const fields = comptime std.meta.fields(T);

    comptime var ret: [fields.len]E = undefined;

    inline for (comptime fields, &ret) |field, *r| {
        r.* = if (comptime meta.is_array(E))
            field.name[0..meta.array_len(E)].*
        else
            field.name;
    }

    return ret;
}

/// Magic string of format T used by OpenSSH.
pub fn MakeMagic(
    comptime T: type,
    comptime I: type,
    comptime E: type,
    parse_fn: fn ([]const u8) callconv(.@"inline") Error!Cont(E),
    encoded_size_fn: fn (value: anytype) callconv(.@"inline") u32,
) type {
    return struct {
        value: T,

        const Self = @This();

        pub const Box = mem.Box([]u8, .plain);

        pub const Value = T;

        pub const Iterator = I;

        const STRINGS = enum_to_str(T, E);

        pub fn as_string(self: *const Self) E {
            return STRINGS[@intFromEnum(self.value)];
        }

        pub fn from_iter(it: *Iterator) Error!Self {
            const src = it.next() orelse
                return error.InvalidFileFormat;

            const ret = try from_slice(src);

            return .{ .value = ret };
        }

        pub fn parse(src: []const u8) Error!enc.Cont(Self) {
            const next, const magic = try parse_fn(src);

            return .{ next, .{
                .value = try from_slice(
                    if (comptime meta.is_array(E)) &magic else magic,
                ),
            } };
        }

        pub fn from_slice(src: []const u8) Error!Value {
            // `stringToEnum` is slower that doing this dance
            for (STRINGS, 0..) |s, i| {
                const ref = if (comptime meta.is_array(E)) &s else s;

                if (std.mem.eql(u8, ref, src)) {
                    return @enumFromInt(i);
                }
            }

            return Error.InvalidMagicString;
        }

        pub fn from_bytes(src: []const u8) Error!Self {
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
            return @intCast(encoded_size_fn(self.as_string()));
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            try enc.serialize_any(E, writer, self.as_string());
        }
    };
}

const expect_equal = std.testing.expectEqual;
const expect_equal_strings = std.testing.expectEqualStrings;

test enum_to_str {
    const TestEnum = enum { foo, bar, baz, @"this-is-a-test-string" };

    const strings = enum_to_str(TestEnum, []const u8);

    try expect_equal_strings("foo", strings[@intFromEnum(TestEnum.foo)]);
    try expect_equal_strings("bar", strings[@intFromEnum(TestEnum.bar)]);
    try expect_equal_strings("baz", strings[@intFromEnum(TestEnum.baz)]);
    try expect_equal_strings(
        "this-is-a-test-string",
        strings[@intFromEnum(TestEnum.@"this-is-a-test-string")],
    );
}

test "GenericMagicString `encoded_size`" {
    const magic = MakeMagic(
        enum { this_is_a_test_with_size_31 },
        std.mem.TokenIterator(u8, .any),
        []const u8,
        enc.rfc4251.parse_string,
        enc.rfc4251.encoded_size,
    ){ .value = .this_is_a_test_with_size_31 };

    try expect_equal(31, magic.encoded_size());
}

test "GenericMagicString `encoded_size` (read_null_terminated)" {
    const magic = MakeMagic(
        enum { this_is_a_test_with_size_28 },
        std.mem.TokenIterator(u8, .any),
        [:0]const u8,
        enc.parse_null_terminated_str,
        enc.null_terminated_str_encoded_size,
    ){ .value = .this_is_a_test_with_size_28 };

    try expect_equal(28, magic.encoded_size());
}

test "serialize GenericMagicString" {
    const magic = MakeMagic(
        enum { this_is_a_test_with_size_42 },
        std.mem.TokenIterator(u8, .any),
        []const u8,
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
