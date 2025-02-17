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

    const key = try Key.from_pem(allocator, try Pem.parse(@embedFile("rsa-key")));
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

    perf.results("Encode RSA key", MAX_RUNS, timer.read());
}
