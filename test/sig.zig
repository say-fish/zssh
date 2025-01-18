const std = @import("std");
const builtin = @import("builtin");

const zssh = @import("zssh");
const sig = zssh.sig;

const SshSig = zssh.sig.SshSig;
const Pem = SshSig.Pem;

const expect = std.testing.expect;
const expect_equal = std.testing.expectEqual;

test "get SshSig signature Blob" {
    const pem = try Pem.parse(@embedFile("test.file.sig"));

    var sshsig = try SshSig.from_pem(std.testing.allocator, &pem);
    defer sshsig.deinit();

    var blob = try sshsig.data.get_signature_blob(
        std.testing.allocator,
        &[_]u8{0x00},
    );
    defer blob.deinit();
}

test "parse and verify SshSig" {
    const pem = try Pem.parse(@embedFile("test.file.sig"));

    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const sshsig = try SshSig.from_bytes(der.data);

    try expect_equal(1, sshsig.version);
    try expect(sshsig.namespace.len != 0);

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
