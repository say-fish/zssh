// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const zssh = @import("zssh");
const perf = @import("perf.zig");

const Pem = zssh.sig.SshSig.Pem;
const PublicKey = std.crypto.sign.Ed25519.PublicKey;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Signature = std.crypto.sign.Ed25519.Signature;
const SshSig = zssh.sig.SshSig;

const MAX_RUNS: usize = 0x01 << 16;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("LEAK");

    const allocator = gpa.allocator();

    const pem = try Pem.parse(@embedFile("test.file.sig"));
    const der = try pem.decode(allocator);
    defer der.deinit();

    var buf = std.mem.zeroes([4096]u8);
    var fba = std.heap.FixedBufferAllocator.init(&buf);

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const sshsig = try SshSig.from_bytes(der.data);

        var hash: [Sha512.digest_length]u8 = undefined;

        const signature = Signature.fromBytes(sshsig.signature.ed25519.sm[0..64].*);
        const pk = try PublicKey.fromBytes(sshsig.publickey.ed25519.pk[0..32].*);

        var sha = Sha512.init(.{});
        sha.update(@embedFile("test.file"));
        sha.final(&hash);

        const blob = try sshsig.get_signature_blob(fba.allocator(), &hash);
        defer blob.deinit();

        std.mem.doNotOptimizeAway(try signature.verify(blob.ref, pk));
    }

    perf.results("Verify SSHSIG", MAX_RUNS, timer.read());
}
