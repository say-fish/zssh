// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");
const builtin = @import("builtin");

const perf = @import("perf.zig");
const openssh = @import("openssh");

const Pem = openssh.cert.Cert.Pem;

const Ed25519 = openssh.cert.Ed25519;

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

    const pem = try Pem.parse(@embedFile("ed25519-cert.pub"));
    const der = try pem.decode(allocator);
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
