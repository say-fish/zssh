// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");
const builtin = @import("builtin");

const perf = @import("perf.zig");
const openssh = @import("openssh");

const Key = openssh.private.Key;
const Pem = openssh.private.Key.Pem;

const DebugAllocator = std.heap.DebugAllocator(.{});

const MAX_RUNS: usize = 0x01 << 26;

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
