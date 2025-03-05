const std = @import("std");
const builtin = @import("builtin");

const openssh = @import("zssh").openssh;

const DebugAllocator = std.heap.DebugAllocator(.{});

pub fn main() !void {
    const allocator, var is_dba: ?DebugAllocator = gpa: {
        if (builtin.os.tag == .wasi) break :gpa .{ std.heap.wasm_allocator, null };
        break :gpa switch (builtin.mode) {
            .Debug, .ReleaseSafe => {
                var dba: DebugAllocator = .init;
                break :gpa .{ dba.allocator(), dba };
            },
            .ReleaseFast, .ReleaseSmall => .{ std.heap.smp_allocator, null },
        };
    };
    defer if (is_dba) |*debug_allocator| {
        if (debug_allocator.deinit() == .leak) @panic("LEAK");
    };

    const stdout = std.io.getStdOut().writer();

    var args = try std.process.ArgIterator.initWithAllocator(allocator);
    defer args.deinit();

    _ = args.next();

    const file_name = args.next() orelse @panic("no argument");

    var file = try std.fs.cwd().openFile(file_name, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(contents);

    if (std.mem.endsWith(u8, file_name, ".pub")) {
        const pem = try openssh.public.Key.Pem.parse(contents);

        const key = try openssh.public.Key.from_pem(allocator, pem);
        defer key.deinit();

        try stdout.print("{s}\n", .{file_name});
        try stdout.print("{}\n", .{key.data});

        try key.data.fingerprint();
    } else {
        const pem = try openssh.private.Key.Pem.parse(contents);

        const key = try openssh.private.Key.from_pem(allocator, pem);
        defer key.deinit();

        try stdout.print("{s}\n", .{file_name});
        try stdout.print("private key: {any}\n", .{key.data});
    }
}
