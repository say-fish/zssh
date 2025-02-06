// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const zssh = @import("zssh");
const perf = @import("perf.zig");

const Ed25519 = zssh.openssh.cert.Ed25519;
const Pem = zssh.openssh.cert.Pem;

const MAX_RUNS: usize = 0x01 << 26;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("LEAK");

    const allocator = gpa.allocator();

    const pem = try Pem.parse(@embedFile("ed25519-cert.pub"));
    const der = try pem.decode(allocator, std.base64.standard.Decoder);
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

    perf.results("Parse SSH cert", MAX_RUNS, timer.read());
}
