const std = @import("std");

const zssh = @import("zssh");

const Pem = zssh.sk.Pem;
const Rsa = zssh.sk.Rsa;

const MAX_RUNS: usize = 0x01 << 30;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();

    defer if (gpa.deinit() == .leak) @panic("LEAK");

    const key = try Rsa.from_pem(allocator, try Pem.parse(@embedFile("rsa-key")));
    defer key.deinit();

    const buffer = try allocator.alloc(u8, key.ref.len);
    defer allocator.free(buffer);

    // Avoid benchmarking the gpa allocator
    var fba = std.heap.FixedBufferAllocator.init(buffer);

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const encoded = try key.data.encode(fba.allocator());
        defer fba.reset();

        std.mem.doNotOptimizeAway(encoded);
    }

    const elapsed = timer.read();

    std.debug.print("Parse SSHSIG\n\n", .{});

    std.debug.print("{s:>15}   #{:>14} times\n", .{ "iterations", MAX_RUNS });
    std.debug.print("{s:>15}   #{:>14} ns\n", .{ "average", elapsed / MAX_RUNS });
    std.debug.print("{s:>15}   #{d:>14.2} /sec\n", .{
        "per second",
        1000000000 / (@as(f64, @floatFromInt(elapsed)) / MAX_RUNS),
    });

    std.debug.print("\n\n", .{});
}
