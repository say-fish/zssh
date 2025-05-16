// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const openssh = @import("openssh");

const Ecdsa = openssh.public.Ecdsa;
const Ed25519 = openssh.public.Ed25519;
const Key = openssh.public.Key;
const Pem = openssh.public.Key.Pem;
const Rsa = openssh.public.Rsa;

const expect_equal = std.testing.expectEqual;
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
    const der = try pem.decode(std.testing.allocator);
    defer der.deinit();
}

test "parse Rsa public key" {
    const pem = try Pem.parse(@embedFile("rsa-key.pub"));
    const der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    _ = try Rsa.from_bytes(der.data);
}

test "parse Ecdsa public key" {
    const pem = try Pem.parse(@embedFile("ecdsa-key.pub"));
    const der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    _ = try Ecdsa.from_bytes(der.data);
}

test "parse ed25519 public key" {
    const pem = try Pem.parse(@embedFile("ed25519-key.pub"));
    const der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    _ = try Ed25519.from_bytes(der.data);
}

test "ed25519 public key with long comment" {
    const pem = try Pem.parse(@embedFile("ed25519-key-long-comment.pub"));
    const der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const expected =
        "This is a long comment with spaces in between, OpenSSH really does allow anything here...\n";

    try expect_equal_slices(u8, expected, pem.comment.ref);
}

test "encode Ed25519" {
    const key = try Key.from_pem(
        std.testing.allocator,
        try Pem.parse(@embedFile("ed25519-key.pub")),
    );
    defer key.deinit();

    const encode_size = key.data.encoded_size();

    try expect_equal(51, encode_size);

    const encoded = try key.data.encode(std.testing.allocator);
    defer encoded.deinit();

    try expect_equal_slices(u8, key.ref, encoded.data);
}

test "encode rsa" {
    const key = try Key.from_pem(
        std.testing.allocator,
        try Pem.parse(@embedFile("rsa-key.pub")),
    );
    defer key.deinit();

    const encode_size = key.data.encoded_size();

    try expect_equal(407, encode_size);

    const encoded = try key.data.encode(std.testing.allocator);
    defer encoded.deinit();

    try expect_equal_slices(u8, key.ref, encoded.data);
}

test "fuzz public key" {
    const Context = struct {
        fn fuzz(_: @This(), input: []const u8) anyerror!void {
            const pem = Pem.parse(input) catch return;
            const key = Key.from_pem(std.testing.allocator, pem) catch return;

            std.debug.print("key: {any}\n", .{key});
            std.debug.print("input: {X}\n", .{input});

            @panic("fuzz passed!!!");
        }
    };

    try std.testing.fuzz(Context{}, Context.fuzz, .{});
}
