const std = @import("std");

const zssh = @import("zssh");

const Ed25519 = zssh.sk.Ed25519;
const Pem = zssh.sk.Pem;

const MAX_RUNS: usize = 0x01 << 26;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();

    defer if (gpa.deinit() == .leak) @panic("LEAK");

    const pem = try Pem.parse(@embedFile("ed25519-key"));

    var der = try pem.decode(allocator);
    defer der.deinit();

    var buf = std.mem.zeroes([2048]u8);

    var fixed_allocator = std.heap.FixedBufferAllocator.init(&buf);

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const key = try Ed25519.from_bytes(der.data);

        var skey = try key.get_private_key(fixed_allocator.allocator(), null);
        defer skey.deinit();

        std.mem.doNotOptimizeAway(skey);
    }

    const elapsed = timer.read();

    std.debug.print("Parsed SSH private key, {} times\n", .{MAX_RUNS});
    std.debug.print(
        "`.from_bytes` + `.get_private_key` + `.deinit` took ~= {}ns ({} keys/s)\n",
        .{ elapsed / MAX_RUNS, 1000000000 / (@as(f64, @floatFromInt(elapsed)) / MAX_RUNS) },
    );
}
