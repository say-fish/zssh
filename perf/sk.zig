// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const zssh = @import("zssh");
const perf = @import("perf.zig");

const Key = zssh.openssh.private.Key;
const Pem = zssh.openssh.private.Key.Pem;

const MAX_RUNS: usize = 0x01 << 26;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("LEAK");
    const allocator = gpa.allocator();

    const pem = try Pem.parse(@embedFile("ed25519-key"));
    const der = try pem.decode(allocator);
    defer der.deinit();

    var buf = std.mem.zeroes([2048]u8);

    var fixed_allocator = std.heap.FixedBufferAllocator.init(&buf);

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const key = try Key.from_bytes(der.data);

        const sk = try key.get_private_key(fixed_allocator.allocator(), null);
        defer sk.deinit();

        std.mem.doNotOptimizeAway(sk);
    }

    perf.results("Parse SSH private key", MAX_RUNS, timer.read());
}
