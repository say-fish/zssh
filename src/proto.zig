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
    InvalidMagicString,
    InvalidData,
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
) type {
    return struct {
        // TODO: Assert T is an enum
        // TODO: Assert F is what we want
        value: T,

        const Self = @This();

        const strings = enum_to_str(T, sufix);

        pub inline fn as_string(self: *const Self) []const u8 {
            return strings[@intFromEnum(self.value)];
        }

        pub inline fn parse(src: []const u8) Error!Cont(Self) {
            const next, const magic = try f(src);

            for (Self.strings, 0..) |s, i|
                if (std.mem.eql(u8, s, magic))
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
    };
}

// Parser continuation
pub fn Cont(comptime T: type) type {
    return struct {
        usize,
        T,
    };
}

pub const rfc4251 = struct {
    pub inline fn read_int(comptime T: type, buf: []const u8) Error!T {
        if (buf.len < @sizeOf(T)) {
            @branchHint(.unlikely);

            return Error.InvalidData;
        }

        return std.mem.readVarInt(T, buf[0..@sizeOf(T)], std.builtin.Endian.big);
    }

    pub inline fn parse_int(comptime T: type, buf: []const u8) Error!struct { usize, T } {
        return .{ @sizeOf(T), try read_int(T, buf) };
    }

    pub inline fn parse_string(buf: []const u8) Error!struct { usize, []const u8 } {
        const size = @sizeOf(u32) + try read_int(u32, buf);

        if (size > buf.len) {
            @branchHint(.unlikely);

            return Error.MalformedString;
        }

        return .{ size, buf[@sizeOf(u32)..size] };
    }
};

pub fn read_null_terminated(src: []const u8) Error!Cont([:0]u8) {
    var i: u32 = 0;

    while (i != src.len) : (i += 1) {
        if (src[i] == 0x00) break;
    }

    return .{ i + 1, @constCast(@ptrCast(src[0..i])) };
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

pub inline fn parse(comptime T: type, src: []const u8) Error!T {
    var ret: T = undefined;

    var i: usize = 0;

    // TODO: Skip magic, since we need to verify it anyways

    inline for (comptime std.meta.fields(T)) |f| {
        const ref = src[i..];

        const next, const val = switch (comptime f.type) {
            []const u8 => try rfc4251.parse_string(ref),

            u64 => try rfc4251.parse_int(u64, ref),

            u32 => try rfc4251.parse_int(u32, ref),

            else => if (@hasDecl(f.type, "parse"))
                try f.type.parse(ref)
            else
                // TODO: Improve this message
                @compileError("Type does not declare `fn parse([]const u8) Count!type` "),
        };

        i += next;

        @field(ret, f.name) = val;
    }

    std.debug.assert(i == src.len);

    return ret;
}
