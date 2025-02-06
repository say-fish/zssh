// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const zssh = @import("zssh");
const perf = @import("perf.zig");

const Ed25519 = zssh.openssh.cert.Ed25519;
const Pem = zssh.openssh.cert.Pem;
const PublicKey = std.crypto.sign.Ed25519.PublicKey;
const Signature = std.crypto.sign.Ed25519.Signature;

const MAX_RUNS: usize = 0x01 << 16;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("LEAK");

    const allocator = gpa.allocator();

    const pem = try Pem.parse(@embedFile("ed25519-cert.pub"));
    const der = try pem.decode(allocator, std.base64.standard.Decoder);
    defer der.deinit();

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const cert = try Ed25519.from_bytes(der.data);

        const signature = Signature.fromBytes(cert.signature.ed.sm[0..64].*);
        const pk = try PublicKey.fromBytes(cert.signature_key.ed.pk[0..32].*);

        std.mem.doNotOptimizeAway(
            try signature.verify(der.data[0..cert.enconded_sig_size()], pk),
        );
    }

    perf.results("Verify SSH cert", MAX_RUNS, timer.read());
}
