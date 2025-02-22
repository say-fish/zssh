// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const zssh = @import("zssh");

const Key = zssh.openssh.private.Key;
const Pem = zssh.openssh.private.Key.Pem;

const expect_equal = std.testing.expectEqual;
const expect_equal_slices = std.testing.expectEqualSlices;
const expect_error = std.testing.expectError;

test "parse Rsa private key: get_public_key" {
    const pem = try Pem.parse(@embedFile("rsa-key"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Key.from_bytes(der.data);

    _ = try key.get_public_key();
}

test "Rsa private key: get_private_key" {
    const pem = try Pem.parse(@embedFile("rsa-key"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Key.from_bytes(der.data);

    const sk = try key.get_private_key(std.testing.allocator, null);
    defer sk.deinit();

    try expect_equal_slices(u8, sk.data.rsa.kind, "ssh-rsa");
    // FIXME: Fix typo
    try expect_equal_slices(u8, sk.data.rsa.comment, "root@locahost");
    // TODO: Check other fields
}

test "Rsa private key with passphrase" {
    const pem = try Pem.parse(@embedFile("rsa-key-123"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Key.from_bytes(der.data);

    const sk = try key.get_private_key(std.testing.allocator, "123");
    defer sk.deinit();

    try std.testing.expect(sk.data.rsa.pad.verify());

    try std.testing.expectEqualSlices(u8, sk.data.rsa.kind, "ssh-rsa");
    try std.testing.expectEqualSlices(u8, sk.data.rsa.comment, "root@locahost"); // FIXME: Fix typo
    // TODO: Check other fields
}

test "Rsa private key with wrong passphrase" {
    const pem = try Pem.parse(@embedFile("rsa-key-123"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Key.from_bytes(der.data);

    try expect_error(
        error.InvalidChecksum,
        key.get_private_key(std.testing.allocator, "wrong"),
    );
}

test "Ed25519 private key: get_private_key" {
    const pem = try Pem.parse(@embedFile("ed25519-key"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Key.from_bytes(der.data);

    const sk = try key.get_private_key(std.testing.allocator, null);
    defer sk.deinit();

    try expect_equal_slices(u8, sk.data.ed.kind, "ssh-ed25519");
    // FIXME: Fix typo
    try expect_equal_slices(u8, sk.data.ed.comment, "root@locahost");
    // TODO: check other fields
}

test "Ed25519 private key with passphrase: get_public_key" {
    const pem = try Pem.parse(@embedFile("ed25519-key-123"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Key.from_bytes(der.data);

    _ = try key.get_public_key();
}

test "Ed25519 private key with passphrase: get_private_key" {
    const pem = try Pem.parse(@embedFile("ed25519-key-123"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Key.from_bytes(der.data);

    const sk = try key.get_private_key(std.testing.allocator, "123");
    defer sk.deinit();

    try expect_equal_slices(u8, sk.data.ed.kind, "ssh-ed25519");
    try expect_equal_slices(u8, sk.data.ed.comment, "root@localhost");
}

test "ed25519 private key with long comment" {
    const pem = try Pem.parse(@embedFile("ed25519-key-long-comment"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Key.from_bytes(der.data);

    const sk = try key.get_private_key(std.testing.allocator, null);
    defer sk.deinit();

    const expected =
        "This is a long comment with spaces in between, OpenSSH really does allow anything here...";

    try std.testing.expectEqualSlices(u8, expected, sk.data.ed.comment);
}

test "Ecdsa private key" {
    const pem = try Pem.parse(@embedFile("ecdsa-key"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Key.from_bytes(der.data);

    const sk = try key.get_private_key(std.testing.allocator, null);
    defer sk.deinit();

    try std.testing
        .expectEqualSlices(u8, sk.data.ecdsa.kind, "ecdsa-sha2-nistp256");
    // FIXME: Typo
    try std.testing
        .expectEqualSlices(u8, sk.data.ecdsa.comment, "root@locahost");
    // TODO: check other fields
}

test "Ecdsa private key with passphrase" {
    const pem = try Pem.parse(@embedFile("ecdsa-key-123"));
    const der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const key = try Key.from_bytes(der.data);

    const sk = try key.get_private_key(std.testing.allocator, "123");
    defer sk.deinit();

    try expect_equal_slices(u8, sk.data.ecdsa.kind, "ecdsa-sha2-nistp256");
    try expect_equal_slices(u8, sk.data.ecdsa.comment, "root@localhost");
    // TODO: check other fields
}

// test "supported ciphers" {
//     for (zssh.sk.Cipher.get_supported_ciphers()) |cipher| {
//         std.debug.print("{s}\n", .{cipher});
//     }
// }

test "encode Ed25519 private key (with passphrase)" {
    const pem = try Pem.parse(@embedFile("ed25519-key-123"));
    const key = try Key.from_pem(std.testing.allocator, pem);
    defer key.deinit();

    try expect_equal(290, key.data.encoded_size());

    const encoded = try key.data.encode(std.testing.allocator);
    defer encoded.deinit();

    try expect_equal(290, encoded.data.len);

    try expect_equal_slices(u8, key.ref, encoded.data);
}

test "encode Ed25519 private key" {
    const pem = try Pem.parse(@embedFile("ed25519-key"));
    const key = try Key.from_pem(std.testing.allocator, pem);
    defer key.deinit();

    const encoded = try key.data.encode(std.testing.allocator);
    defer encoded.deinit();

    try expect_equal(key.ref.len, encoded.data.len);
    try expect_equal_slices(u8, key.ref, encoded.data);
}

test "wire encode Ed25519 private key" {
    const pem = try Pem.parse(@embedFile("ed25519-key"));
    const key = try Key.from_pem(std.testing.allocator, pem);
    defer key.deinit();

    const sk = try key.data.get_private_key(std.testing.allocator, null);
    defer sk.deinit();
    // FIXME:
    const encoded = try sk.data.get_wire().ed.encode(
        std.testing.allocator,
    );
    defer encoded.deinit();
}

// test "fuzz" {
//     const Context = struct {
//         fn fuzz(_: @This(), input: []const u8) anyerror!void {
//             const pem = Pem.parse(input) catch return;
//             const key = Key.from_pem(std.testing.allocator, pem) catch return;
//
//             std.debug.print("input: {X}\n", .{input});
//             std.debug.print("key: {any}\n", .{key});
//
//             @panic("fuzz passed!!!");
//         }
//     };
//
//     try std.testing.fuzz(Context{}, Context.fuzz, .{});
// }
