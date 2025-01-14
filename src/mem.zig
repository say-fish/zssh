const std = @import("std");

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
