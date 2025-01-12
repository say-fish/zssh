const std = @import("std");

const sshcrypto = @import("sshcrypto");

const MAX_RUNS: usize = 0x01 << 16;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();

    defer if (gpa.deinit() == .leak) @panic("LEAK");

    var pem = try sshcrypto.cert.CertDecoder
        .init(allocator, std.base64.standard.Decoder)
        .decode(@embedFile("ed25519-cert.pub"));
    defer pem.deinit();

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const cert = try sshcrypto.cert.Ed25519.from_bytes(pem.data.der);

        const signature = std.crypto.sign.Ed25519.Signature.fromBytes(cert.signature.ed25519.sm[0..64].*);
        const pk = try std.crypto.sign.Ed25519.PublicKey.fromBytes(cert.signature_key.ed25519.pk[0..32].*);

        std.mem.doNotOptimizeAway(try signature.verify(pem.data.der[0 .. pem.data.der.len - 87], pk));
    }

    const elapsed = timer.read();

    std.debug.print("Parsed and verified Ed25519 SSH cert, {} times\n", .{MAX_RUNS});
    std.debug.print(
        "Verify took ~= {}ns ({} verifications/s)\n",
        .{ elapsed / MAX_RUNS, 1000000000 / (elapsed / MAX_RUNS) },
    );
}
