// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");
const builtin = @import("builtin");

const perf = @import("perf.zig");
const openssh = @import("openssh");

const Pem = openssh.public.Key.Pem;

const Ed25519 = openssh.public.Ed25519;

const DebugAllocator = std.heap.DebugAllocator(.{});

const MAX_RUNS: usize = 0x01 << 32;

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
