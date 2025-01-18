const std = @import("std");

pub const Error = error{
    /// Invalid RFC-4251 integer
    MalformedInteger,
    /// Invalid RFC-4251 string
    MalformedString,
    /// Malformed RFC-4251 MpInt
    MalformedMpInt, // TODO:
    /// Object specific invalid data
    InvalidLiteral,
    /// Invalid/Unsupported magic string
    InvalidMagicString,
    InvalidData,
    /// The checksum for private keys is invalid, meaning either, decryption
    /// was not successful, or data is corrupted. This is NOT an auth form
    /// error.
    InvalidChecksum,
};

pub fn enum_to_str(comptime T: type) [std.meta.fields(T).len][]const u8 {
    if (@typeInfo(T) != .@"enum") @compileError("Expected enum");

    const fields = comptime std.meta.fields(T);

    comptime var ret: [fields.len][]const u8 = undefined;

    inline for (comptime fields, &ret) |field, *r| {
        r.* = field.name;
    }

    return ret;
}

/// Magic string of format T used by OpenSSH. Encoding is given by the return
/// type of f.
///
/// * T must be an `enum`, where each enumeration corresponds to **VALID**
///   magic string for this given type.
///
/// * f must have this signature: `fn f([]const u8) Error!Cont(T)`.
pub fn GenericMagicString(
    comptime T: type,
    f: anytype,
    x: anytype,
) type {
    return struct {
        // TODO: Assert T is an enum
        // TODO: Assert F is what we want
        // TODO: assert X is what we want
        value: T,

        const Self = @This();
        pub const Value = T;

        const strings = enum_to_str(T);

        pub fn as_string(self: *const Self) []const u8 {
            return strings[@intFromEnum(self.value)];
        }

        pub fn parse(src: []const u8) Error!Cont(Self) {
            const next, const magic = try f(src);

            // Small hack, otherwise zig complains
            const ref = switch (comptime @typeInfo(@TypeOf(magic))) {
                .array => &magic,
                else => magic,
            };

            for (Self.strings, 0..) |s, i| {
                if (std.mem.eql(u8, s, ref)) {
                    return .{ next, .{ .value = @enumFromInt(i) } };
                }
            }

            return Error.InvalidMagicString;
        }

        pub fn from_slice(src: []const u8) Error!T {
            for (Self.strings, 0..) |s, i|
                if (std.mem.eql(u8, s, src))
                    return @enumFromInt(i);

            return Error.InvalidMagicString;
        }

        pub fn from_bytes(src: []const u8) Error!Self {
            _, const magic = try Self.parse(src);

            return magic;
        }

        pub fn encoded_size(self: *const Self) u32 {
            return @intCast(x(self.as_string()));
        }

        pub fn serialize(self: *const Self, writer: anytype) !void {
            const F = @FieldType(
                @typeInfo(@typeInfo(@TypeOf(f)).@"fn".return_type.?).error_union.payload,
                "1",
            );

            try encode(F, writer, self.as_string());
        }
    };
}

/// Parser continuation
pub fn Cont(comptime T: type) type {
    return struct { usize, T };
}

pub const rfc4251 = struct {
    inline fn read_int(comptime T: type, buf: []const u8) T {
        // XXX: We are doing unaligned reads here like crazy, even thought this
        // implementation explicitly does not do this, on x86_64 this gets
        // compiled to `movbe`...
        return std.mem.readVarInt(T, buf[0..@sizeOf(T)], std.builtin.Endian.big);
    }

    /// Parse a RFC-4251 encoded int
    pub inline fn parse_int(comptime T: type, buf: []const u8) Error!Cont(T) {
        if (buf.len < @sizeOf(T)) {
            @branchHint(.unlikely);

            return Error.InvalidData;
        }

        return .{ @sizeOf(T), read_int(T, buf) };
    }

    /// Parse a RFC-4251 encoded string:
    ///  +-----------+------------------+
    ///  | len (u32) | content (u8) ... |
    ///  +-----------+------------------+
    pub inline fn parse_string(buf: []const u8) Error!Cont([]const u8) {
        if (buf.len < @sizeOf(u32)) {
            @branchHint(.unlikely);

            return Error.InvalidData;
        }

        const len: usize = read_int(u32, buf) + @sizeOf(u32);

        if (len > buf.len) {
            @branchHint(.unlikely);

            return Error.MalformedString;
        }

        return .{ len, buf[@sizeOf(u32)..len] };
    }

    /// Returns the encoded size of a given value, the size is based on the
    /// `type` as per RFC-4251
    pub fn encoded_size(value: anytype) u32 {
        return switch (comptime @TypeOf(value)) {
            u32, u64 => |T| @sizeOf(T),

            []u8, []const u8 => @sizeOf(u32) + @as(u32, @intCast(value.len)),

            else => |T| @compileError(
                "Encoded size for type: " ++ @typeName(T) ++ "is not supported",
            ),
        };
    }
};

pub fn parse_null_terminated_str(src: []const u8) Error!Cont([:0]const u8) {
    const ret: [:0]const u8 = std.mem.span(@as([*c]const u8, src.ptr));

    return .{ ret.len + 1, ret };
}

// FIXME: might overflow
pub fn null_terminated_str_encoded_size(src: []const u8) u32 {
    return @intCast(src.len + 1);
}

pub const Padding = struct {
    _pad: []const u8,

    const Self = @This();

    /// Returns true if padding is valid, i.e., it's a sequence.
    pub fn verify(self: *const Self) bool {
        for (1.., self._pad) |i, pad| {
            if (i != pad) return false;
        }

        return true;
    }

    pub fn parse(src: []const u8) Error!Cont(Padding) {
        return .{ src.len, .{ ._pad = src } };
    }
};

pub fn Blob(comptime T: type) type {
    return struct {
        val: T,

        pub fn blob(val: T) @This() {
            return .{ .val = val };
        }
    };
}

pub fn Literal(comptime L: []const u8) type {
    return struct {
        pub fn parse(src: []const u8) Error!void {
            if (std.mem.eql(u8, src, L)) {
                return;
            }

            return Error.InvalidLiteral;
        }
    };
}

pub fn encode_value(writer: anytype, value: anytype) !void {
    try encode(@TypeOf(value), writer, value);
}

pub fn encode(comptime T: type, writer: anytype, value: anytype) !void {
    switch (comptime T) {
        u32, u64 => _ = try writer.writeInt(T, value, .big),

        []u8, []const u8 => {
            _ = try writer.writeInt(u32, @intCast(value.len), .big);
            _ = try writer.writeAll(value);
        },

        [:0]u8, [:0]const u8 => {
            _ = try writer.writeAll(value);
            _ = try writer.writeInt(u8, 0x00, .big);
        },

        else => switch (comptime @typeInfo(T)) {
            .@"struct", .@"enum" => value.encode(writer),

            // This is a special case for fixed size encoded strings
            .array => _ = try writer.writeAll(value),

            else => @compileError(
                "Cannot encode value of type: " ++ @typeName(T),
            ),
        },
    }
}

pub fn encoded_size(value: anytype) u32 {
    return switch (@TypeOf(value)) {
        u32, u64, []u8, []const u8 => rfc4251.encoded_size(value),

        [:0]u8, [:0]const u8 => null_terminated_str_encoded_size(value),

        else => |Type| switch (@typeInfo(Type)) {
            .@"enum",
            .@"struct",
            .@"union",
            => if (@hasDecl(Type, "encoded_size"))
                value.encoded_size()
            else
                @compileError(@typeName(Type) ++
                    " does not declare `encoded_size`"),

            .array => comptime value.len,

            else => @compileError(
                "Cannot get encoded size of type: " ++ @typeName(Type),
            ),
        },
    };
}

pub fn struct_encoded_size(self: anytype) u32 {
    var ret: u32 = 0;

    inline for (comptime std.meta.fields(@TypeOf(self.*))) |field| {
        ret += encoded_size(@field(self.*, field.name));
    }

    return ret;
}

pub fn serialize(comptime T: type, writer: anytype, value: T) !void {
    if (@typeInfo(T) != .@"struct") {
        @compileError("Expected `struct`, got:" ++ @typeName(T));
    }

    inline for (comptime std.meta.fields(T)) |f| {
        try encode(f.type, writer, @field(value, f.name));
    }
}

pub inline fn parse(comptime T: type, src: []const u8) Error!T {
    var ret: T = undefined;

    var i: usize = 0;

    inline for (comptime std.meta.fields(T)) |f| {
        const ref = src[i..];

        const next, const val = switch (comptime f.type) {
            []const u8 => try rfc4251.parse_string(ref),

            u64 => try rfc4251.parse_int(u64, ref),

            u32 => try rfc4251.parse_int(u32, ref),

            else => if (@hasDecl(f.type, "parse"))
                try f.type.parse(ref)
            else
                @compileError("Type: " ++
                    @typeName(f.type) ++ " does not declare `fn parse([]const u8) ...`"),
        };

        i += next;

        std.debug.assert(i <= src.len);

        @field(ret, f.name) = val;
    }

    std.debug.assert(i == src.len);

    return ret;
}

const expect_equal = std.testing.expectEqual;
const expect_equal_strings = std.testing.expectEqualStrings;

test "GenericMagicString `encoded_size`" {
    const magic = GenericMagicString(
        enum { this_is_a_test_with_size_31 },
        rfc4251.parse_string,
        rfc4251.encoded_size,
    ){ .value = .this_is_a_test_with_size_31 };

    try expect_equal(31, magic.encoded_size());
}

test "GenericMagicString `encoded_size` (read_null_terminated)" {
    const magic = GenericMagicString(
        enum { this_is_a_test_with_size_28 },
        parse_null_terminated_str,
        null_terminated_str_encoded_size,
    ){ .value = .this_is_a_test_with_size_28 };

    try expect_equal(28, magic.encoded_size());
}

test "encode u32" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const num: u32 = 10;

    try encode(u32, list.writer(), num);
    try expect_equal_strings(&[_]u8{ 0x00, 0x00, 0x00, 0x0A }, list.items);
}

test "encode u64" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const num: u64 = 10;

    try encode(u64, list.writer(), num);
    try expect_equal_strings(
        &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A },
        list.items,
    );
}

test "encode []const u8 (rfc4251 string)" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const string: []const u8 = "this is a rfc4251 string";

    try encode([]const u8, list.writer(), string);

    try expect_equal_strings(
        &[_]u8{ 0x00, 0x00, 0x00, 0x18 } ++ string,
        list.items,
    );
}

test "encode [:0]const u8 (null terminated string)" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const string: [:0]const u8 = "this is a null terminated string";

    try encode([:0]const u8, list.writer(), string);

    try expect_equal_strings(string ++ [_]u8{0x00}, list.items);
}

test "encode [6]u8 (fixed size string)" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const string = [6]u8{ 'S', 'S', 'H', 'S', 'I', 'G' };

    try encode([6]u8, list.writer(), &string);

    try expect_equal_strings(&string, list.items);
}

test "serialize GenericMagicString" {
    const magic = GenericMagicString(
        enum { this_is_a_test_with_size_42 },
        rfc4251.parse_string,
        rfc4251.encoded_size,
    ){ .value = .this_is_a_test_with_size_42 };

    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try magic.serialize(list.writer());
    try expect_equal(
        .this_is_a_test_with_size_42,
        (try @TypeOf(magic).from_bytes(list.items)).value,
    );
}

test enum_to_str {
    const Enum = enum {
        foo,
        bar,
        baz,
        @"this-is-a-test-string",
    };

    const strings = enum_to_str(Enum);

    try expect_equal_strings("foo", strings[@intFromEnum(Enum.foo)]);
    try expect_equal_strings("bar", strings[@intFromEnum(Enum.bar)]);
    try expect_equal_strings("baz", strings[@intFromEnum(Enum.baz)]);
    try expect_equal_strings(
        "this-is-a-test-string",
        strings[@intFromEnum(Enum.@"this-is-a-test-string")],
    );
}
test parse_null_terminated_str {
    const malformed: []const u8 = &[_]u8{ 0x72, 0x72, 0x72 };
    const str: []const u8 = &[_]u8{ 0x72, 0x72, 0x72, 0x00 };

    _, const a = try parse_null_terminated_str(str);
    _, const b = try parse_null_terminated_str(malformed);

    try expect_equal(3, a.len);
    try expect_equal(3, b.len);
    try expect_equal_strings(a, b);
}
