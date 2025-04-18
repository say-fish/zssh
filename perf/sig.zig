// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");
const builtin = @import("builtin");

const perf = @import("perf.zig");
const openssh = @import("openssh");

const Pem = openssh.signature.SshSig.Pem;

const Sha512 = std.crypto.hash.sha2.Sha512;
const SshSig = openssh.signature.SshSig;

const PublicKey = std.crypto.sign.Ed25519.PublicKey;
const Signature = std.crypto.sign.Ed25519.Signature;

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

    const pem = try Pem.parse(@embedFile("test.file.sig"));
    const der = try pem.decode(allocator);
    defer der.deinit();

    // Avoid benchmarking the gpa allocator
    var buf = std.mem.zeroes([4096]u8);
    var fba = std.heap.FixedBufferAllocator.init(&buf);

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const sshsig = try SshSig.from_bytes(der.data);

        var hash: [Sha512.digest_length]u8 = undefined;

        const blob = try sshsig.get_signature_blob(fba.allocator(), &hash);
        defer blob.deinit();

        std.mem.doNotOptimizeAway(blob);
    }

    perf.results("Parse SSHSIG", MAX_RUNS, timer.read());
}
