// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const zssh = @import("zssh");

const Ed25519 = zssh.cert.Ed25519;
const Pem = zssh.cert.Pem;

const MAX_RUNS: usize = 0x01 << 26;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();

    defer if (gpa.deinit() == .leak) @panic("LEAK");

    const pem = try Pem.parse(@embedFile("ed25519-cert.pub"));

    var der = try pem.decode(allocator);
    defer der.deinit();

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const cert = try Ed25519.from_bytes(der.data);

        {
            var it = cert.critical_options.iter();

            while (try it.next()) |opt| {
                std.mem.doNotOptimizeAway(opt);
            }
        }
        {
            var it = cert.valid_principals.iter();

            while (try it.next()) |principal| {
                std.mem.doNotOptimizeAway(principal);
            }
        }

        std.mem.doNotOptimizeAway(try cert.extensions.to_bitflags());

        std.mem.doNotOptimizeAway(cert);
    }

    const elapsed = timer.read();

    std.debug.print("Parse SSH cert\n\n", .{});

    std.debug.print("{s:>15}   #{:>14} times\n", .{ "iterations", MAX_RUNS });
    std.debug.print("{s:>15}   #{:>14} ns\n", .{ "average", elapsed / MAX_RUNS });
    std.debug.print("{s:>15}   #{d:>14.2} /sec\n", .{
        "per second",
        1000000000 / (@as(f64, @floatFromInt(elapsed)) / MAX_RUNS),
    });

    std.debug.print("\n\n", .{});
}
