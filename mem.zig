// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");
const builtin = @import("builtin");

pub const Error = error{
    /// Out of Memory
    OutOfMemory,
};

pub const ArrayWriter = struct {
    allocator: std.mem.Allocator,
    head: usize = 0,
    mem: []u8,

    const Self = @This();
    const Writer = std.io.Writer(
        *Self,
        std.mem.Allocator.Error,
        Self.write,
    );

    pub fn init(allocator: std.mem.Allocator, len: usize) !Self {
        return .{
            .allocator = allocator,
            .mem = try allocator.alloc(u8, len),
        };
    }

    pub inline fn writer(self: *Self) Writer {
        return .{ .context = self };
    }

    fn write(self: *Self, bytes: []const u8) std.mem.Allocator.Error!usize {
        if (bytes.len > self.mem.len - self.head) return error.OutOfMemory;

        @memcpy(self.mem[self.head..][0..bytes.len], bytes);

        self.head += bytes.len;

        return bytes.len;
    }

    pub fn reset(self: *Self) void {
        self.head = 0;
        std.crypto.secureZero(u8, self.mem);
    }

    pub fn deinit(self: *Self) void {
        std.crypto.secureZero(u8, self.mem);
        self.allocator.free(self.mem);
    }
};

pub const Mode = enum {
    plain,
    sec,
};

// TODO: For Managed* types, call deinit() if T has it.

pub fn Box(comptime T: type, comptime mode: Mode) type {
    return struct {
        allocator: std.mem.Allocator,
        data: T,

        const Self = @This();

        pub fn deinit(self: *const Self) void {
            if (comptime mode == .sec)
                std.crypto.secureZero(u8, self.data);
            self.allocator.free(self.data);
        }
    };
}

pub fn BoxRef(comptime T: type, comptime mode: Mode) type {
    return struct {
        allocator: std.mem.Allocator,
        data: T,
        ref: []u8,

        const Self = @This();

        pub fn deinit(self: *const Self) void {
            if (comptime mode == .sec)
                std.crypto.secureZero(u8, self.ref);
            self.allocator.free(self.ref);
        }
    };
}

/// Unmanaged data with references to data that *SHOULD* outlive it.
pub fn Unmanaged(comptime T: type) type {
    return struct { data: T };
}

pub fn shallow_copy(comptime T: type, dst: *T, comptime U: type, src: *const U) void {
    // TODO: Assert T and U are structs;
    inline for (comptime std.meta.fields(T)) |field| {
        @field(dst, field.name) = @field(src, field.name);
    }
}

pub fn print(src: []const u8) void {
    var it = std.mem.window(u8, src, 16, 16);

    var i: usize = 0;

    while (it.next()) |win| {
        std.debug.print(" {:05}:", .{i});
        i += 16;

        for (win) |b| {
            std.debug.print(" {X:02}", .{b});
        }

        for (0..16 - win.len) |_| {
            std.debug.print("   ", .{});
        }

        std.debug.print(" ", .{});

        for (win) |b| {
            std.debug.print("{c}", .{if (std.ascii.isAlphanumeric(b)) b else '.'});
        }

        std.debug.print("\n", .{});
    }
}

const expect_equal = std.testing.expectEqual;
const expect_equal_strings = std.testing.expectEqualStrings;

test ArrayWriter {
    var fbw = try ArrayWriter.init(std.testing.allocator, 32);
    defer fbw.deinit();

    try expect_equal(4, try fbw.writer().write("AAAA"));
    try expect_equal(4, fbw.head);
    try expect_equal_strings("AAAA", fbw.mem[0..4]);
}
