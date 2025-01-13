const std = @import("std");

const sshcrypto = @import("sshcrypto");

const SshSig = sshcrypto.sig.SshSig;

const Signature = std.crypto.sign.Ed25519.Signature;
const PublicKey = std.crypto.sign.Ed25519.PublicKey;
const Sha512 = std.crypto.hash.sha2.Sha512;

const MAX_RUNS: usize = 0x01 << 10;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();

    defer if (gpa.deinit() == .leak) @panic("LEAK");

    const pem = try SshSig.SshSigDecoder.init(allocator, sshcrypto.decoder.base64.pem.Decoder).decode(@embedFile("test.file.sig"));
    defer pem.deinit();

    // var buf = std.mem.zeroes([4096]u8);

    // var fixed_allocator = std.heap.FixedBufferAllocator.init(&buf);

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const sshsig = try SshSig.from_pem(pem.data);

        var hash: [Sha512.digest_length]u8 = undefined;

        var blob = try sshsig.get_signature_blob(
            allocator,
            &hash,
        );
        defer blob.deinit();
    }

    const elapsed = timer.read();

    std.debug.print("Parsed SSHSIG, {} times\n", .{MAX_RUNS});
    std.debug.print(
        "`.from_pem` + `.get_signature_blob` + `.deinit` took ~= {}ns ({} sigs/s)\n",
        .{ elapsed / MAX_RUNS, 1000000000 / (elapsed / MAX_RUNS) },
    );
}
