const std = @import("std");

const openssh = @import("zssh").openssh;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("MEMORY LEAK");

    const stdout = std.io.getStdOut().writer();

    var args = try std.process.ArgIterator.initWithAllocator(gpa.allocator());
    defer args.deinit();

    _ = args.next();

    const file_name = args.next() orelse @panic("no argument");

    var file = try std.fs.cwd().openFile(file_name, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(gpa.allocator(), 1024 * 1024);
    defer gpa.allocator().free(contents);

    if (std.mem.endsWith(u8, file_name, ".pub")) {
        const pem = try openssh.public.Key.Pem.parse(contents);

        const key = try openssh.public.Key.from_pem(gpa.allocator(), pem);
        defer key.deinit();

        try stdout.print("{s}\n", .{file_name});
        try stdout.print("{}\n", .{key.data});

        try key.data.fingerprint();
    } else {
        const pem = try openssh.private.Key.Pem.parse(contents);

        const key = try openssh.private.Key.from_pem(gpa.allocator(), pem);
        defer key.deinit();

        try stdout.print("{s}\n", .{file_name});
        try stdout.print("private key: {any}\n", .{key.data});
    }
}
