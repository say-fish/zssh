// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const builtin = @import("builtin");

pub const FixedBufferWriter = struct {
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

pub fn ManagedSecret(comptime T: type) type {
    return struct {
        allocator: std.mem.Allocator,
        data: T,
        ref: []u8,

        const Self = @This();

        pub fn deinit(self: *Self) void {
            std.crypto.secureZero(u8, self.ref);
            self.allocator.free(self.ref);
        }
    };
}

pub fn Managed(comptime T: type) type {
    return struct {
        allocator: std.mem.Allocator,
        data: T,

        const Self = @This();

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.data);
        }
    };
}

pub fn ManagedWithRef(comptime T: type) type {
    return struct {
        allocator: std.mem.Allocator,
        data: T,
        ref: []u8,

        const Self = @This();

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.ref);
        }
    };
}

/// Unmanaged data with references to data that *SHOULD* outlive it.
pub fn Unmanaged(comptime U: type) type {
    return struct {
        data: U,
    };
}

const expect_equal = std.testing.expectEqual;
const expect_equal_strings = std.testing.expectEqualStrings;

test FixedBufferWriter {
    var fbw = try FixedBufferWriter.init(std.testing.allocator, 32);
    defer fbw.deinit();

    try expect_equal(4, try fbw.writer().write("AAAA"));
    try expect_equal(4, fbw.head);
    try expect_equal_strings("AAAA", fbw.mem[0..4]);
}
