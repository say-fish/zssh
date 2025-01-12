const std = @import("std");
const builtin = @import("builtin");

const sshcrypto = @import("sshcrypto");

const sshsig_decoder = sshcrypto.decoder.pem.SshsigDecoder
    .init(std.testing.allocator, sshcrypto.decoder.base64.pem.Decoder);

test "parse SSHSIG" {
    const pem = try sshsig_decoder.decode(@embedFile("test.file.sig"));
    defer pem.deinit();

    const sshsig = try sshcrypto.sig.Sshsig.from_pem(pem.data);

    try std.testing.expectEqual(1, sshsig.version);
    try std.testing.expect(sshsig.namespace.len != 0);

    if (comptime builtin.os.tag != .windows) {
        switch (sshsig.publickey) {
            .ed25519 => |sig| {
                const signature = std.crypto.sign
                    .Ed25519.Signature.fromBytes(sshsig.signature.ed25519.sm[0..64].*);
                const pk = try std.crypto.sign
                    .Ed25519.PublicKey.fromBytes(sig.pk[0..32].*);

                var sha = std.crypto.hash.sha2.Sha512.init(.{});

                var hash: [512 / 8]u8 = undefined;

                sha.update(@embedFile("test.file"));
                sha.final(&hash);

                var blob = try sshsig.get_signature_blob(
                    std.testing.allocator,
                    &hash,
                );
                defer blob.deinit();

                try signature.verify(blob.ref, pk);
            },

            else => return error.InvalidSigType,
        }
    }
}
