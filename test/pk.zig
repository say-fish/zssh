const std = @import("std");

const zssh = @import("zssh");

const Ecdsa = zssh.pk.Ecdsa;
const Ed25519 = zssh.pk.Ed25519;
const Pem = zssh.pk.Pem;
const Rsa = zssh.pk.Rsa;

const expect_equal_slices = std.testing.expectEqualSlices;

// FIXME:
// test "decode in place" {
//     const rodata = @embedFile("rsa-key.pub");
//
//     const rsa_key = try std.testing.allocator.alloc(u8, rodata.len);
//     defer std.testing.allocator.free(rsa_key);
//
//     std.mem.copyForwards(u8, rsa_key, rodata);
//
//     _ = try pk.PkDecoder.decode_in_place(
//         std.base64.standard.Decoder,
//         rsa_key,
//     );
// }

test "decode with allocator" {
    const pem = try Pem.parse(@embedFile("rsa-key.pub"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();
}

test "parse Rsa public key" {
    const pem = try Pem.parse(@embedFile("rsa-key.pub"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    _ = try Rsa.from_bytes(der.data);
}

test "parse Ecdsa public key" {
    const pem = try Pem.parse(@embedFile("ecdsa-key.pub"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    _ = try Ecdsa.from_bytes(der.data);
}

test "parse ed25519 public key" {
    const pem = try Pem.parse(@embedFile("ed25519-key.pub"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    _ = try Ed25519.from_bytes(der.data);
}

test "ed25519 public key with long comment" {
    const pem = try Pem.parse(@embedFile("ed25519-key-long-comment.pub"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const expected =
        "This is a long comment with spaces in between, OpenSSH really does allow anything here...\n";

    try expect_equal_slices(u8, expected, pem.comment.ref);
}
