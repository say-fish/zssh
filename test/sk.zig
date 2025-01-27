// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const zssh = @import("zssh");

const expect_equal_slices = std.testing.expectEqualSlices;
const expect_error = std.testing.expectError;

const Ecdsa = zssh.sk.Ecdsa;
const Ed25519 = zssh.sk.Ed25519;
const Pem = zssh.sk.Pem;
const Rsa = zssh.sk.Rsa;

test "parse Rsa private key: get_public_key" {
    const pem = try Pem.parse(@embedFile("rsa-key"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Rsa.from_bytes(der.data);

    _ = try key.get_public_key();
}
test "Rsa private key: get_private_key" {
    const pem = try Pem.parse(@embedFile("rsa-key"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Rsa.from_bytes(der.data);

    var skey = try key.get_private_key(std.testing.allocator, null);
    defer skey.deinit();

    try expect_equal_slices(u8, skey.data.kind, "ssh-rsa");
    // FIXME: Fix typo
    try expect_equal_slices(u8, skey.data.comment, "root@locahost");
    // TODO: Check other fields
}

test "Rsa private key with passphrase" {
    const pem = try Pem.parse(@embedFile("rsa-key-123"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Rsa.from_bytes(der.data);

    var skey = try key.get_private_key(std.testing.allocator, "123");
    defer skey.deinit();

    try std.testing.expect(skey.data._pad.verify());

    try std.testing.expectEqualSlices(u8, skey.data.kind, "ssh-rsa");
    try std.testing.expectEqualSlices(u8, skey.data.comment, "root@locahost"); // FIXME: Fix typo
    // TODO: Check other fields
}

test "Rsa private key with wrong passphrase" {
    const pem = try Pem.parse(@embedFile("rsa-key-123"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Rsa.from_bytes(der.data);

    try expect_error(
        error.InvalidChecksum,
        key.get_private_key(std.testing.allocator, "wrong"),
    );
}

test "Ed25519 private key: get_private_key" {
    const pem = try Pem.parse(@embedFile("ed25519-key"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Ed25519.from_bytes(der.data);

    var skey = try key.get_private_key(std.testing.allocator, null);
    defer skey.deinit();

    try expect_equal_slices(u8, skey.data.kind, "ssh-ed25519");
    // FIXME: Fix typo
    try expect_equal_slices(u8, skey.data.comment, "root@locahost");
    // TODO: check other fields
}

test "Ed25519 private key with passphrase: get_public_key" {
    const pem = try Pem.parse(@embedFile("ed25519-key-123"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Ed25519.from_bytes(der.data);

    _ = try key.get_public_key();
}

test "Ed25519 private key with passphrase: get_private_key" {
    const pem = try Pem.parse(@embedFile("ed25519-key-123"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Ed25519.from_bytes(der.data);

    var skey = try key.get_private_key(std.testing.allocator, "123");
    defer skey.deinit();

    try expect_equal_slices(u8, skey.data.kind, "ssh-ed25519");
    try expect_equal_slices(u8, skey.data.comment, "root@localhost");
}

test "ed25519 private key with long comment" {
    const pem = try Pem.parse(@embedFile("ed25519-key-long-comment"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Ed25519.from_bytes(der.data);

    var skey = try key.get_private_key(std.testing.allocator, null);
    defer skey.deinit();

    const expected =
        "This is a long comment with spaces in between, OpenSSH really does allow anything here...";

    try std.testing.expectEqualSlices(u8, expected, skey.data.comment);
}

test "Ecdsa private key" {
    const pem = try Pem.parse(@embedFile("ecdsa-key"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Ecdsa.from_bytes(der.data);

    var skey = try key.get_private_key(std.testing.allocator, null);
    defer skey.deinit();

    try std.testing.expectEqualSlices(u8, skey.data.kind, "ecdsa-sha2-nistp256");
    // FIXME: Typo
    try std.testing.expectEqualSlices(u8, skey.data.comment, "root@locahost");
    // TODO: check other fields
}

test "Ecdsa private key with passphrase" {
    const pem = try Pem.parse(@embedFile("ecdsa-key-123"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Ecdsa.from_bytes(der.data);

    var skey = try key.get_private_key(std.testing.allocator, "123");
    defer skey.deinit();

    try expect_equal_slices(u8, skey.data.kind, "ecdsa-sha2-nistp256");
    try expect_equal_slices(u8, skey.data.comment, "root@localhost");
    // TODO: check other fields
}

// test "supported chipers" {
//     for (zssh.key.private.Cipher.get_supported_ciphers()) |cipher| {
//         std.debug.print("{s}\n", .{cipher});
//     }
// }
