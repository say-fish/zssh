// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const mem = @import("mem.zig");

const meta = @import("meta.zig");

const Is = meta.Is;

const Enum = meta.Enum;
const Mode = mem.Mode;

const Error = @import("error.zig").Error;

const ForAll = meta.ForAll;

const Container = meta.Container;

pub fn Dec(comptime T: type) type {
    switch (T) {
        void, // For unit structs
        bool,
        u8,
        u32,
        u64,
        []u8,
        []const u8,
        [:0]u8,
        [:0]const u8,
        => return T,

        else => switch (@typeInfo(T)) {
            .@"struct", .@"enum", .@"union" => {
                const dec_type = fn ([]const u8) Error!Cont(T);

                return meta.has_decl(T, "parse", dec_type);
            },
            else => @compileError(@typeName(T) ++
                " does not satisfy Dec"),
        },
    }
}

pub fn EncSize(comptime T: type) type {
    @setEvalBranchQuota(2000);
    switch (T) {
        void, // For unit structs
        bool,
        u32,
        u64,
        []u8,
        []const u8,
        ?[]const u8,
        [:0]u8,
        [:0]const u8,
        => return T,

        else => switch (@typeInfo(T)) {
            .@"struct", .@"enum", .@"union" => {
                const encoded_size_type = fn (*const T) u32;

                return meta.has_decl(T, "encoded_size", encoded_size_type);
            },
            .array => return T,
            else => @compileError(@typeName(T) ++ " does not satisfy Enc"),
        },
    }
}

pub fn From(
    comptime name: []const u8,
    comptime F: type,
) fn (comptime type) type {
    return struct {
        fn Inner(comptime T: type) T {
            return meta.has_decl(T, "from_" ++ name, F);
        }
    }.Inner;
}

pub fn Ser(comptime T: type) type {
    switch (T) {
        void, // For unit structs
        bool,
        u32,
        u64,
        []u8,
        []const u8,
        ?[]const u8,
        [:0]u8,
        [:0]const u8,
        => return T,

        else => switch (@typeInfo(T)) {
            .@"struct", .@"enum", .@"union" => {
                const serialize_type =
                    fn (*const T, std.io.AnyWriter) anyerror!void;

                return meta.has_decl(T, "serialize", serialize_type);
            },
            .array => return T,
            else => @compileError(@typeName(T) ++ " does not satisfy Ser"),
        },
    }
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

    pub inline fn parse_bool(src: []const u8) Error!Cont(bool) {
        const next, const value = try parse_int(u8, src);

        return .{ next, value != 0 };
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
    pub inline fn encoded_size(value: anytype) u32 {
        return switch (comptime @TypeOf(value)) {
            u32, u64 => |T| @sizeOf(T),

            []u8, []const u8 => @sizeOf(u32) + @as(u32, @intCast(value.len)),

            else => |T| @compileError(
                "Encoded size for type: " ++ @typeName(T) ++ "is not supported",
            ),
        };
    }
};

pub inline fn parse_null_terminated_str(src: []const u8) Error!Cont([:0]const u8) {
    const i = std.mem.indexOfScalar(u8, src, 0x00) orelse
        return Error.InvalidData;

    return .{ i + 1, src[0..i :0] };
}

pub inline fn null_terminated_str_encoded_size(src: anytype) u32 {
    // FIXME: might overflow
    return @intCast(src.len + 1);
}

pub const Padding = struct {
    _pad: []const u8,

    const Self = @This();

    /// Returns true if padding is valid, i.e., it's a sequence.
    pub fn verify(self: *const Self) bool {
        var ret = true;

        for (1.., self._pad) |i, pad| {
            ret = i == pad;
        }

        return ret;
    }

    pub fn parse(src: []const u8) Error!Cont(Padding) {
        return .{ src.len, .{ ._pad = src } };
    }
};

pub fn serialize_any(
    comptime T: type,
    writer: std.io.AnyWriter,
    value: Ser(T),
) anyerror!void {
    switch (comptime T) {
        void => return,

        u32, u64 => _ = try writer.writeInt(T, value, .big),

        []u8, []const u8 => {
            _ = try writer.writeInt(u32, @intCast(value.len), .big);
            _ = try writer.writeAll(value);
        },

        ?[]const u8 => if (value) |v| {
            _ = try writer.writeInt(u32, @intCast(v.len), .big);
            _ = try writer.writeAll(v);
        } else {
            _ = try writer.writeInt(u8, 0, .big);
        },

        [:0]u8, [:0]const u8 => {
            _ = try writer.writeAll(value);
            _ = try writer.writeInt(u8, 0x00, .big);
        },

        else => switch (comptime @typeInfo(T)) {
            .@"struct", .@"enum", .@"union" => try value.serialize(writer),

            // This is a special case for fixed size encoded strings
            .array => _ = try writer.writeAll(&value),

            else => @compileError(
                "Cannot encode value of type: " ++ @typeName(T),
            ),
        },
    }
}

pub fn encode_value(
    comptime T: type,
    allocator: std.mem.Allocator,
    value: *const meta.And(T, .{ Ser, EncSize, Container }),
    comptime mode: Mode,
) anyerror!mem.Box([]u8, mode) {
    var writer = try mem.ArrayWriter.init(allocator, value.encoded_size());
    errdefer writer.deinit();

    try value.serialize(writer.writer().any());

    return .{ .allocator = allocator, .data = writer.mem };
}

pub fn encoded_size(comptime T: type, value: EncSize(T)) u32 {
    return switch (@TypeOf(value)) {
        void => 0,

        u32, u64, []u8, []const u8 => rfc4251.encoded_size(value),

        [:0]u8, [:0]const u8 => null_terminated_str_encoded_size(value),

        ?[]const u8 => if (value) |v| rfc4251.encoded_size(v) else 1,

        else => |Type| switch (@typeInfo(Type)) {
            .@"enum", .@"struct", .@"union" => value.encoded_size(),

            .array => comptime value.len,

            else => comptime unreachable,
        },
    };
}

pub fn encoded_size_struct(
    comptime T: type,
    value: *const ForAll(EncSize, Is(.@"struct", T)),
) u32 {
    var ret: u32 = 0;

    inline for (comptime std.meta.fields(T)) |field| {
        ret += encoded_size(field.type, @field(value.*, field.name));
    }

    return ret;
}

pub fn serialize_struct(
    comptime T: type,
    writer: std.io.AnyWriter,
    value: *const ForAll(Ser, Is(.@"struct", T)),
) !void {
    inline for (comptime std.meta.fields(T)) |f| {
        try serialize_any(f.type, writer, @field(value, f.name));
    }
}

pub fn serialize_union(
    comptime T: type,
    writer: std.io.AnyWriter,
    value: *const ForAll(Ser, Is(.@"union", (EncSize(T)))),
) !void {
    const encoded_size_msg = value.encoded_size();

    std.debug.assert(encoded_size_msg > @sizeOf(u32));
    // The encoded size will be the full encoded size of the message, we need
    // to subtract the msg len field size
    const encoded_size_content: u32 = encoded_size_msg - @sizeOf(u32);

    switch (value.*) {
        inline else => |e| {
            try writer.writeInt(u32, encoded_size_content, .big);
            try writer.writeInt(u8, @intFromEnum(std.meta.activeTag(value.*)), .big);

            try serialize_any(@TypeOf(e), writer, e);
        },
    }
}

pub inline fn parse(
    comptime T: type,
    src: []const u8,
) Error!ForAll(Dec, T) {
    const next, const ret = try parse_with_cont(T, src);

    std.debug.assert(next == src.len);

    return ret;
}

pub inline fn parse_with_cont(
    comptime T: type,
    src: []const u8,
) Error!Cont(ForAll(Dec, T)) {
    var ret: T = undefined;

    var i: usize = 0;

    inline for (comptime std.meta.fields(T)) |field| {
        const ref = src[i..];

        const next, const val = switch (comptime field.type) {
            bool => try rfc4251.parse_bool(ref),

            u8, u32, u64 => |U| try rfc4251.parse_int(U, ref),

            []const u8 => try rfc4251.parse_string(ref),

            else => try field.type.parse(ref),
        };

        i += next;

        std.debug.assert(i <= src.len);

        @field(ret, field.name) = val;
    }

    return .{ i, ret };
}

pub fn MakeIterator(comptime T: type) type {
    return struct {
        ref: []const u8,
        off: usize = 0,

        const Self = @This();

        pub fn next(self: *Self) !?Dec(Container(T)) {
            if (self.done()) return null;

            const off, const ret = try T.parse(self.ref[self.off..]);
            self.off += off;

            return ret;
        }

        pub inline fn reset(self: *Self) void {
            self.off = 0;
        }

        pub inline fn done(self: *const Self) bool {
            return self.off == self.ref.len;
        }
    };
}

pub fn Packaged(comptime T: type) type {
    return struct {
        inner: T,

        const Self = @This();

        pub fn init(value: T) Self {
            return .{ .inner = value };
        }

        pub fn parse(src: []const u8) Error!Cont(Self) {
            const next, const inner = try rfc4251.parse_string(src);

            const value = try T.from_bytes(inner);

            return .{ next, .init(value) };
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            const size = self.inner.encoded_size();

            try serialize_any(u32, writer, size);
            try serialize_struct(Self, writer, self);
        }

        pub fn encoded_size(self: *const Self) u32 {
            return self.inner.encoded_size() + @sizeOf(u32);
        }
    };
}

const expect_equal = std.testing.expectEqual;
const expect_equal_strings = std.testing.expectEqualStrings;

test "encode u32" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const num: u32 = 10;

    try serialize_any(u32, list.writer().any(), num);
    try expect_equal_strings(&[_]u8{ 0x00, 0x00, 0x00, 0x0A }, list.items);
}

test "encode u64" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const num: u64 = 10;

    try serialize_any(u64, list.writer().any(), num);
    try expect_equal_strings(
        &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A },
        list.items,
    );
}

test "encode []const u8 (rfc4251 string)" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const string: []const u8 = "this is a rfc4251 string";

    try serialize_any([]const u8, list.writer().any(), string);

    try expect_equal_strings(
        &[_]u8{ 0x00, 0x00, 0x00, 0x18 } ++ string,
        list.items,
    );
}

test "encode [:0]const u8 (null terminated string)" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const string: [:0]const u8 = "this is a null terminated string";

    try serialize_any([:0]const u8, list.writer().any(), string);

    try expect_equal_strings(string ++ [_]u8{0x00}, list.items);
}

test "encode [6]u8 (fixed size string)" {
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    const string = [6]u8{ 'S', 'S', 'H', 'S', 'I', 'G' };

    try serialize_any([6]u8, list.writer().any(), string);

    try expect_equal_strings(&string, list.items);
}

test parse_null_terminated_str {
    const str: []const u8 = &[_]u8{ 0x72, 0x72, 0x72, 0x00 };
    const malformed: []const u8 = &[_]u8{ 0x72, 0x72, 0x72 };

    _, const a = try parse_null_terminated_str(str);
    const b = parse_null_terminated_str(malformed);

    try expect_equal(3, a.len);
    try expect_equal(Error.InvalidData, b);
    try expect_equal_strings(a, "rrr");
}
