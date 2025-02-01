// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const zssh = @import("zssh");

const Pem = zssh.sig.SshSig.Pem;
const PublicKey = std.crypto.sign.Ed25519.PublicKey;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Signature = std.crypto.sign.Ed25519.Signature;
const SshSig = zssh.sig.SshSig;

const MAX_RUNS: usize = 0x01 << 26;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();

    defer if (gpa.deinit() == .leak) @panic("LEAK");

    const pem = try Pem.parse(@embedFile("test.file.sig"));

    var der = try pem.decode(allocator);
    defer der.deinit();

    var buf = std.mem.zeroes([4096]u8);
    var fixed_allocator = std.heap.FixedBufferAllocator.init(&buf);

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const sshsig = try SshSig.from_bytes(der.data);

        var hash: [Sha512.digest_length]u8 = undefined;

        var blob = try sshsig.get_signature_blob(
            fixed_allocator.allocator(),
            &hash,
        );
        defer blob.deinit();

        std.mem.doNotOptimizeAway(blob);
    }

    const elapsed = timer.read();

    std.debug.print("Parsed SSHSIG\n\n", .{});

    std.debug.print("{s:>15}   #{:>14} times\n", .{ "iterations", MAX_RUNS });
    std.debug.print("{s:>15}   #{:>14} ns\n", .{ "average", elapsed / MAX_RUNS });
    std.debug.print("{s:>15}   #{d:>14.2} /sec\n", .{
        "per second",
        1000000000 / (@as(f64, @floatFromInt(elapsed)) / MAX_RUNS),
    });
}
