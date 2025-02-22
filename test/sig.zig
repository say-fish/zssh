// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");
const builtin = @import("builtin");

const zssh = @import("zssh");
const sig = zssh.openssh.sinature;

const SshSig = zssh.openssh.signature.SshSig;
const Pem = zssh.openssh.signature.SshSig.Pem;

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
            .ed => |s| {
                const signature = std.crypto.sign
                    .Ed25519.Signature.fromBytes(sshsig.signature.ed.sm[0..64].*);
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

test "fuzz" {
    const Context = struct {
        fn fuzz(_: @This(), input: []const u8) anyerror!void {
            const pem = SshSig.Pem.parse(input) catch return;
            const key = SshSig.from_pem(
                std.testing.allocator,
                &pem,
            ) catch return;

            std.debug.print("key: {any}\n", .{key});
            std.debug.print("input: {X}\n", .{input});

            @panic("fuzz passed!!!");
        }
    };

    try std.testing.fuzz(Context{}, Context.fuzz, .{});
}
