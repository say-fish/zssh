const std = @import("std");
const builtin = @import("builtin");

const sshcrypto = @import("sshcrypto");
const sig = sshcrypto.sig;

const sshsig_decoder = sig.SshSig.SshSigDecoder
    .init(std.testing.allocator, sshcrypto.decoder.base64.pem.Decoder);

test "get SshSig signature Blob" {
    const pem = try sshsig_decoder.decode(@embedFile("test.file.sig"));
    defer pem.deinit();

    const sshsig = try sig.SshSig.from_pem(pem.data);

    var blob = try sshsig.get_signature_blob(std.testing.allocator, &[_]u8{0x00});
    defer blob.deinit();
}

test "parse and verify SshSig" {
    const pem = try sshsig_decoder.decode(@embedFile("test.file.sig"));
    defer pem.deinit();

    const sshsig = try sig.SshSig.from_pem(pem.data);

    try std.testing.expectEqual(1, sshsig.version);
    try std.testing.expect(sshsig.namespace.len != 0);

    if (comptime builtin.os.tag != .windows) {
        switch (sshsig.publickey) {
            .ed25519 => |s| {
                const signature = std.crypto.sign
                    .Ed25519.Signature.fromBytes(sshsig.signature.ed25519.sm[0..64].*);
                const pk = try std.crypto.sign
                    .Ed25519.PublicKey.fromBytes(s.pk[0..32].*);

                var sha = std.crypto.hash.sha2.Sha512.init(.{});

                var hash: [std.crypto.hash.sha2.Sha512.digest_length]u8 =
                    undefined;

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
