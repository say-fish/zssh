// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const zssh = @import("zssh");
const perf = @import("perf.zig");

const Ed25519 = zssh.openssh.public.Ed25519;
const Pem = zssh.openssh.public.Key.Pem;

const MAX_RUNS: usize = 0x01 << 32;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("LEAK");

    const allocator = gpa.allocator();

    const pem = try Pem.parse(@embedFile("ed25519-key.pub"));
    const der = try pem.decode(allocator);
    defer der.deinit();

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const pk = try Ed25519.from_bytes(der.data);

        std.mem.doNotOptimizeAway(pk);
    }

    perf.results("Parse SSH public key", MAX_RUNS, timer.read());
}
