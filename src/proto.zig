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

pub fn enum_to_str(comptime T: type, sufix: []const u8) [std.meta.fields(T).len][]const u8 {
    if (@typeInfo(T) != .@"enum") @compileError("Expected enum");

    const fields = comptime std.meta.fields(T);

    comptime var ret: [fields.len][]const u8 = undefined;

    inline for (fields, &ret) |field, *r| {
        const U = [field.name.len]u8;

        comptime var name: U = std.mem.zeroes(U);

        inline for (field.name, &name) |c, *n| {
            n.* = if (c == '_') '-' else c;
        }

        r.* = name ++ sufix;
    }

    return ret;
}

/// Magic string format used by OpenSSH
pub fn GenericMagicString(
    comptime T: type,
    comptime sufix: []const u8,
    f: anytype,
    x: anytype,
) type {
    return struct {
        // TODO: Assert T is an enum
        // TODO: Assert F is what we want
        // TODO: assert X is what we want
        value: T,

        const Self = @This();

        const strings = enum_to_str(T, sufix);

        pub inline fn as_string(self: *const Self) []const u8 {
            return strings[@intFromEnum(self.value)];
        }

        pub inline fn parse(src: []const u8) Error!Cont(Self) {
            const next, const magic = try f(src);

            // Small hack, otherwise zig complains
            const ref = switch (comptime @typeInfo(@TypeOf(magic))) {
                .array => &magic,
                else => magic,
            };

            for (Self.strings, 0..) |s, i|
                if (std.mem.eql(u8, s, ref))
                    return .{ next, .{ .value = @enumFromInt(i) } };

            return Error.InvalidData;
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

        pub fn get_encoded_size(self: *const Self) u32 {
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

// Parser continuation
pub fn Cont(comptime T: type) type {
    return struct { usize, T };
}

pub const rfc4251 = struct {
    inline fn read_int(comptime T: type, buf: []const u8) T {
        return std.mem.readVarInt(T, buf[0..@sizeOf(T)], std.builtin.Endian.big);
    }

    pub inline fn parse_int(comptime T: type, buf: []const u8) Error!Cont(T) {
        if (buf.len < @sizeOf(T)) {
            @branchHint(.unlikely);

            return Error.InvalidData;
        }

        return .{ @sizeOf(T), read_int(T, buf) };
    }

    pub inline fn parse_string(buf: []const u8) Error!Cont([]const u8) {
        if (buf.len < @sizeOf(u32)) {
            @branchHint(.unlikely);

            return Error.InvalidData;
        }

        const size = @sizeOf(u32) + read_int(u32, buf);

        if (size > buf.len) {
            @branchHint(.unlikely);

            return Error.MalformedString;
        }

        return .{ size, buf[@sizeOf(u32)..size] };
    }

    pub inline fn encoded_size(value: anytype) u32 {
        return switch (comptime @TypeOf(value)) {
            u32 => @sizeOf(u32),
            u64 => @sizeOf(u64),
            []u8 => @sizeOf(u32) + @as(u32, @intCast(value.len)),
            []const u8 => @sizeOf(u32) + @as(u32, @intCast(value.len)),
            else => @panic("TODO:"),
        };
    }
};

pub fn read_null_terminated(src: []const u8) Error!Cont([:0]u8) {
    var i: u32 = 0;

    while (i != src.len) : (i += 1) {
        if (src[i] == 0x00) {
            return .{ i + 1, @constCast(@ptrCast(src[0..i])) };
        }
    }

    return Error.MalformedString;
}

pub fn null_terminated_encoded_size(src: []const u8) u32 {
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

    pub inline fn parse(src: []const u8) Error!Cont(Padding) {
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
        pub inline fn parse(src: []const u8) Error!void {
            if (std.mem.eql(u8, src, L)) {
                return;
            }

            return Error.InvalidLiteral;
        }
    };
}

pub inline fn encode_value(writer: anytype, value: anytype) !void {
    try encode(@TypeOf(value), writer, value);
}

pub inline fn encode(comptime T: type, writer: anytype, value: anytype) !void {
    switch (comptime T) {
        u32 => {
            _ = try writer.writeInt(u32, value, .big);
        },

        u64 => {
            _ = try writer.writeInt(u64, value, .big);
        },

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
            .array => _ = try writer.writeAll(value),
            else => @compileError("Cannot encode value of type: " ++ @typeName(T)),
        },
    }
}

pub fn serialize(comptime T: type, writer: anytype, value: T) !void {
    if (@typeInfo(T) != .@"struct") {
        @compileError("Expected `struct`, got:" ++ @typeName(T));
    }

    inline for (std.meta.fields(T)) |f| {
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
                @compileError("Type: " ++ @typeName(f.type) ++ " does not declare `fn parse([]const u8) ...`"),
        };

        i += next;

        std.debug.assert(i <= src.len);

        @field(ret, f.name) = val;
    }

    std.debug.assert(i == src.len);

    return ret;
}

test "GenericMagicString `get_encoded_size`" {
    const magic = GenericMagicString(
        enum { this_is_a_test_with_size_31 },
        "",
        rfc4251.parse_string,
        rfc4251.encoded_size,
    ){ .value = .this_is_a_test_with_size_31 };

    try std.testing.expectEqual(31, magic.get_encoded_size());
}

test "GenericMagicString with sufix `get_encoded_size`" {
    const magic = GenericMagicString(
        enum { this_is_a_test_with_size_42 },
        "_with_sufix",
        rfc4251.parse_string,
        rfc4251.encoded_size,
    ){ .value = .this_is_a_test_with_size_42 };

    try std.testing.expectEqual(42, magic.get_encoded_size());
}

test "GenericMagicString `get_encoded_size` (read_null_terminated)" {
    const magic = GenericMagicString(
        enum(u1) { this_is_a_test_with_size_39 },
        "_with_sufix",
        read_null_terminated,
        null_terminated_encoded_size,
    ){ .value = .this_is_a_test_with_size_39 };

    try std.testing.expectEqual(39, magic.get_encoded_size());
}

test "encode u32" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const num: u32 = 10;

    try encode(u32, list.writer(), num);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x00,
        0x00,
        0x00,
        0x0A,
    }, list.items);
}

test "encode u64" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const num: u64 = 10;

    try encode(u64, list.writer(), num);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x0A,
    }, list.items);
}

test "encode []const u8 (rfc4251 string)" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const string: []const u8 = "this is a rfc4251 string";

    try encode([]const u8, list.writer(), string);

    try std.testing.expectEqualStrings(&[_]u8{
        0x00,
        0x00,
        0x00,
        0x18,
    } ++ string, list.items);
}

test "encode [:0]const u8 (null terminated string)" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const string: [:0]const u8 = "this is a null terminated string";

    try encode([:0]const u8, list.writer(), string);

    try std.testing.expectEqualStrings(string ++ [_]u8{0x00}, list.items);
}

test "serialize GenericMagicString" {
    const magic = GenericMagicString(
        enum { this_is_a_test_with_size_42 },
        "_with_sufix",
        rfc4251.parse_string,
        rfc4251.encoded_size,
    ){ .value = .this_is_a_test_with_size_42 };

    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try magic.serialize(list.writer());
    try std.testing.expectEqual(
        .this_is_a_test_with_size_42,
        (try @TypeOf(magic).from_bytes(list.items)).value,
    );
}
