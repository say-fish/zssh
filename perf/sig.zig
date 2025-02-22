// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const zssh = @import("zssh");
const perf = @import("perf.zig");

const Pem = zssh.openssh.signature.SshSig.Pem;

const Sha512 = std.crypto.hash.sha2.Sha512;
const SshSig = zssh.openssh.signature.SshSig;

const PublicKey = std.crypto.sign.Ed25519.PublicKey;
const Signature = std.crypto.sign.Ed25519.Signature;

const MAX_RUNS: usize = 0x01 << 26;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("LEAK");

    const allocator = gpa.allocator();
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
