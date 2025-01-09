const std = @import("std");
const sshcrypto = @import("sshcrypto");

const sshsig_decoder = sshcrypto.pem.SshsigDecoder
    .init(std.testing.allocator, sshcrypto.base64.pem.Decoder);

test "parse SSHSIG" {
    const pem = try sshsig_decoder.decode(@embedFile("test.file.sig"));
    defer pem.deinit();

    const sshsig = try sshcrypto.sig.sshsig.from_pem(pem.data);

    try std.testing.expectEqual(1, sshsig.version);
    try std.testing.expect(sshsig.namespace.len != 0);
    switch (sshsig.publickey) {
        .ed25519 => |sig| {
            _ = sig;
            // TODO:
            // const signature = std.crypto.sign
            //     .Ed25519.Signature.fromBytes(sshsig.signature.ed25519.sm[0..64].*);
            // const pk = try std.crypto.sign
            //     .Ed25519.PublicKey.fromBytes(sig.pk[0..32].*);

            // try signature.verify(@embedFile("test.file"), pk);
        },

        else => return error.InvalidSigType,
    }
}
