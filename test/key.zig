const std = @import("std");

const sshcrypto = @import("sshcrypto");
const pk = sshcrypto.key.pk;
const sk = sshcrypto.key.sk;

test "decode in place" {
    const rodata = @embedFile("rsa-key.pub");

    const rsa_key = try std.testing.allocator.alloc(u8, rodata.len);
    defer std.testing.allocator.free(rsa_key);

    @memcpy(rsa_key, rodata);

    _ = try pk.PkDecoder.decode_in_place(
        std.base64.standard.Decoder,
        rsa_key,
    );
}

test "decode with allocator" {
    const key = try pk.PkDecoder
        .init(std.testing.allocator, std.base64.standard.Decoder)
        .decode(@embedFile("rsa-key.pub"));
    defer key.deinit();
}

const pk_decoder = sshcrypto.key.pk.PkDecoder
    .init(std.testing.allocator, std.base64.standard.Decoder);

test "Rsa public key" {
    const pem = try pk_decoder.decode(@embedFile("rsa-key.pub"));
    defer pem.deinit();

    _ = try pk.Rsa.from_pem(pem.data);
    // TODO: Check fields
}

test "Ecdsa public key" {
    const pem = try pk_decoder.decode(@embedFile("ecdsa-key.pub"));
    defer pem.deinit();

    _ = try pk.Ecdsa.from_pem(pem.data);
    // TODO: Check fields
}

test "ed25519 public key" {
    const pem = try pk_decoder.decode(@embedFile("ed25519-key.pub"));
    defer pem.deinit();

    _ = try pk.Ed25519.from_pem(pem.data);
    // TODO: Check fields
}

const sk_decoder = sshcrypto.key.sk.SkDecoder
    .init(std.testing.allocator, sshcrypto.decoder.base64.pem.Decoder);

test "Rsa private key: get_public_key" {
    const pem = try sk_decoder.decode(@embedFile("rsa-key"));
    defer pem.deinit();

    const key = try sshcrypto.key.sk.Rsa.from_pem(pem.data);

    _ = try key.get_public_key();
    // TODO: Check fields
}
test "Rsa private key: get_private_key" {
    const pem = try sk_decoder.decode(@embedFile("rsa-key"));
    defer pem.deinit();

    const key = try sk.Rsa.from_pem(pem.data);

    var skey = try key.get_private_key(std.testing.allocator, null);
    defer skey.deinit();

    try std.testing.expectEqualSlices(u8, skey.data.kind, "ssh-rsa");
    try std.testing.expectEqualSlices(u8, skey.data.comment, "root@locahost"); // FIXME: Fix typo

    // TODO: Check other fields
}

test "Rsa private key with passphrase" {
    const pem = try sk_decoder.decode(@embedFile("rsa-key-123"));
    defer pem.deinit();

    const key = try sshcrypto.key.sk.Rsa.from_pem(pem.data);

    var skey = try key.get_private_key(std.testing.allocator, "123");
    defer skey.deinit();

    try std.testing.expect(skey.data._pad.verify());

    try std.testing.expectEqualSlices(u8, skey.data.kind, "ssh-rsa");
    try std.testing.expectEqualSlices(u8, skey.data.comment, "root@locahost"); // FIXME: Fix typo
    // TODO: Check other fields
}

test "Rsa private key with wrong passphrase" {
    const pem = try sk_decoder.decode(@embedFile("rsa-key-123"));
    defer pem.deinit();

    const key = try sshcrypto.key.sk.Rsa.from_pem(pem.data);

    try std.testing.expectError(
        error.InvalidChecksum,
        key.get_private_key(std.testing.allocator, "wrong"),
    );
}

test "Ed25519 private key: get_private_key" {
    const pem = try sk_decoder.decode(@embedFile("ed25519-key"));
    defer pem.deinit();

    const key = try sshcrypto.key.sk.Ed25519.from_pem(pem.data);

    var skey = try key.get_private_key(std.testing.allocator, null);
    defer skey.deinit();

    try std.testing.expectEqualSlices(u8, skey.data.kind, "ssh-ed25519");
    try std.testing.expectEqualSlices(u8, skey.data.comment, "root@locahost");
    // TODO: check other fields
}

test "Ed25519 private key with passphrase: get_public_key" {
    const pem = try sk_decoder.decode(@embedFile("ed25519-key-123"));
    defer pem.deinit();

    const key = try sshcrypto.key.sk.Ed25519.from_pem(pem.data);

    _ = try key.get_public_key();
}

test "Ed25519 private key with passphrase: get_private_key" {
    const pem = try sk_decoder.decode(@embedFile("ed25519-key-123"));
    defer pem.deinit();

    const key = try sshcrypto.key.sk.Ed25519.from_pem(pem.data);

    var skey = try key.get_private_key(std.testing.allocator, "123");
    defer skey.deinit();

    try std.testing.expectEqualSlices(u8, skey.data.kind, "ssh-ed25519");
    try std.testing.expectEqualSlices(u8, skey.data.comment, "root@localhost");
}

test "ed25519 public key with long comment" {
    const pem = try pk_decoder.decode(@embedFile("ed25519-key-long-comment.pub"));
    defer pem.deinit();

    const expected = "This is a long comment with spaces in between, OpenSSH really does allow anything here...";

    try std.testing.expectEqualSlices(u8, expected, pem.data.comment.val);
}

test "ed25519 private key with long comment" {
    const pem = try sk_decoder.decode(@embedFile("ed25519-key-long-comment"));
    defer pem.deinit();

    const key = try sk.Ed25519.from_pem(pem.data);

    var skey = try key.get_private_key(std.testing.allocator, null);
    defer skey.deinit();

    const expected = "This is a long comment with spaces in between, OpenSSH really does allow anything here...";

    try std.testing.expectEqualSlices(u8, expected, skey.data.comment);
}

test "Ecdsa private key" {
    const pem = try sk_decoder.decode(@embedFile("ecdsa-key"));
    defer pem.deinit();

    const key = try sshcrypto.key.sk.Ecdsa.from_pem(pem.data);

    var skey = try key.get_private_key(std.testing.allocator, null);
    defer skey.deinit();

    try std.testing.expectEqualSlices(u8, skey.data.kind, "ecdsa-sha2-nistp256");
    try std.testing.expectEqualSlices(u8, skey.data.comment, "root@locahost");
    // TODO: check other fields
}

test "Ecdsa private key with passphrase" {
    const pem = try sk_decoder.decode(@embedFile("ecdsa-key-123"));
    defer pem.deinit();

    const key = try sshcrypto.key.sk.Ecdsa.from_pem(pem.data);

    var skey = try key.get_private_key(std.testing.allocator, "123");
    defer skey.deinit();

    try std.testing.expectEqualSlices(u8, skey.data.kind, "ecdsa-sha2-nistp256");
    try std.testing.expectEqualSlices(u8, skey.data.comment, "root@localhost");
    // TODO: check other fields
}

// test "supported chipers" {
//     for (sshcrypto.key.private.Cipher.get_supported_ciphers()) |cipher| {
//         std.debug.print("{s}\n", .{cipher});
//     }
// }
