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
