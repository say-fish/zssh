// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");
const builtin = @import("builtin");

const perf = @import("perf.zig");
const zssh = @import("zssh");

const Pem = zssh.openssh.signature.SshSig.Pem;

const Sha512 = std.crypto.hash.sha2.Sha512;
const SshSig = zssh.openssh.signature.SshSig;

const PublicKey = std.crypto.sign.Ed25519.PublicKey;
const Signature = std.crypto.sign.Ed25519.Signature;

const DebugAllocator = std.heap.DebugAllocator(.{});

const MAX_RUNS: usize = 0x01 << 16;

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

    var buf = std.mem.zeroes([4096]u8);
    var fba = std.heap.FixedBufferAllocator.init(&buf);

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const sshsig = try SshSig.from_bytes(der.data);

        var hash: [Sha512.digest_length]u8 = undefined;

        const signature = Signature.fromBytes(sshsig.signature.ed.sm[0..64].*);
        const pk = try PublicKey.fromBytes(sshsig.publickey.ed.pk[0..32].*);

        var sha = Sha512.init(.{});
        sha.update(@embedFile("test.file"));
        sha.final(&hash);

        const blob = try sshsig.get_signature_blob(fba.allocator(), &hash);
        defer blob.deinit();

        std.mem.doNotOptimizeAway(try signature.verify(blob.ref, pk));
    }

    perf.results("Verify SSHSIG", MAX_RUNS, timer.read());
}
