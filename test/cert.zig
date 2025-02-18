// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const zssh = @import("zssh");

const Pem = zssh.openssh.cert.Pem;
const Rsa = zssh.openssh.cert.Rsa;

const Cert = zssh.openssh.cert.Cert;

const Error = zssh.openssh.Error;

const expect = std.testing.expect;
const expect_equal = std.testing.expectEqual;
const expect_equal_strings = std.testing.expectEqualStrings;
const expect_error = std.testing.expectError;

fn verify_cert(cert: anytype) !void {
    try expect_equal(2, cert.serial);
    try expect_equal(.user, cert.kind);
    try expect_equal_strings("abc", cert.key_id);

    var it = cert.valid_principals.iter();
    try expect_equal_strings("root", (try it.next()).?.value);
    try expect(it.done());

    try expect_equal(0, cert.valid_after);
    try expect_equal(std.math.maxInt(u64), cert.valid_before);
}

test "parse Rsa cert" {
    var cert = try Cert.from_pem(
        std.testing.allocator,
        std.base64.standard.Decoder,
        &try Pem.parse(@embedFile("rsa-cert.pub")),
    );
    defer cert.deinit();

    switch (cert.data) {
        .rsa => |c| {
            try expect_equal(.@"ssh-rsa-cert-v01@openssh.com", c.magic.value);
            try verify_cert(c);
        },
        else => @panic("Expected rsa cert"),
    }
}

test "parse rsa cert bad cert" {
    const pem = try Pem.parse(@embedFile("rsa-cert.pub"));

    var der = try pem.decode(
        std.testing.allocator,
        std.base64.standard.Decoder,
    );
    // Save the len so deinit works
    const len = der.data.len;
    defer {
        der.data.len = len;
        der.deinit();
    }

    der.data.len = 100;

    const cert = Cert.from_bytes(der.data);

    try expect_error(Error.MalformedString, cert);
}

test "parse ecdsa cert" {
    const pem = try Pem.parse(@embedFile("ecdsa-cert.pub"));

    var der = try pem.decode(
        std.testing.allocator,
        std.base64.standard.Decoder,
    );
    defer der.deinit();

    switch (try Cert.from_bytes(der.data)) {
        .ecdsa => |cert| {
            try expect_equal(
                .@"ecdsa-sha2-nistp256-cert-v01@openssh.com",
                cert.magic.value,
            );
            try verify_cert(cert);
        },
        else => return error.wrong_certificate,
    }
}

test "parse ed25519 cert" {
    const pem = try Pem.parse(@embedFile("ed25519-cert.pub"));

    var der = try pem.decode(
        std.testing.allocator,
        std.base64.standard.Decoder,
    );
    defer der.deinit();

    switch (try Cert.from_bytes(der.data)) {
        .ed25519 => |cert| {
            try expect_equal(
                .@"ssh-ed25519-cert-v01@openssh.com",
                cert.magic.value,
            );
            try verify_cert(cert);
        },
        else => return error.wrong_certificate,
    }
}

const Ed25519 = zssh.openssh.cert.Ed25519;
const enconded_sig_size = zssh.cert.Ed25519.enconded_sig_size;

test enconded_sig_size {
    var cert = try Ed25519.from_pem(
        std.testing.allocator,
        std.base64.standard.Decoder,
        &try Pem.parse(@embedFile("ed25519-cert.pub")),
    );
    defer cert.deinit();

    try expect_equal(352, cert.data.enconded_sig_size());
}

test "verify ed25519 cert" {
    const Signature = std.crypto.sign.Ed25519.Signature;
    const PublicKey = std.crypto.sign.Ed25519.PublicKey;

    const pem = try Pem.parse(@embedFile("ed25519-cert.pub"));

    var der = try pem.decode(
        std.testing.allocator,
        std.base64.standard.Decoder,
    );
    defer der.deinit();

    switch (try Cert.from_bytes(der.data)) {
        .ed25519 => |cert| {
            const signature = Signature.fromBytes(
                cert.signature.ed.sm[0..64].*,
            );
            const pk = try PublicKey.fromBytes(
                cert.signature_key.ed.pk[0..32].*,
            );
            try signature.verify(der.data[0..cert.enconded_sig_size()], pk);
        },
        else => return error.wrong_certificate,
    }
}

test "extensions iterator" {
    // Reference
    const extensions = [_]zssh.cert.Extensions.Kind{
        .@"permit-X11-forwarding",
        .@"permit-agent-forwarding",
        .@"permit-port-forwarding",
        .@"permit-pty",
        .@"permit-user-rc",
    };

    const pem = try Pem.parse(@embedFile("rsa-cert.pub"));

    var der = try pem.decode(
        std.testing.allocator,
        std.base64.standard.Decoder,
    );
    defer der.deinit();

    const cert = try Rsa.from_bytes(der.data);

    var it = cert.extensions.iter();

    inline for (comptime extensions) |refrence| {
        try expect_equal(refrence, try it.next() orelse return error.Fail);
    }

    try expect(it.done());
}

test "extensions to bitflags" {
    const Kind = zssh.cert.Extensions.Kind;

    const pem = try Pem.parse(@embedFile("rsa-cert.pub"));

    var der = try pem.decode(
        std.testing.allocator,
        std.base64.standard.Decoder,
    );
    defer der.deinit();

    const cert = try Rsa.from_bytes(der.data);

    try expect_equal(
        @intFromEnum(Kind.@"permit-agent-forwarding") |
            @intFromEnum(Kind.@"permit-X11-forwarding") |
            @intFromEnum(Kind.@"permit-user-rc") |
            @intFromEnum(Kind.@"permit-port-forwarding") |
            @intFromEnum(Kind.@"permit-pty"),
        try cert.extensions.to_bitflags(),
    );
}

test "multiple valid principals iterator" {
    // Reference
    const valid_principals = [_][]const u8{
        "foo",
        "bar",
        "baz",
    };

    const pem = try Pem.parse(@embedFile("multiple-principals-cert.pub"));

    var der = try pem.decode(
        std.testing.allocator,
        std.base64.standard.Decoder,
    );
    defer der.deinit();

    const cert = try Rsa.from_bytes(der.data);

    var it = cert.valid_principals.iter();

    for (valid_principals) |reference| {
        const principal = try it.next() orelse return error.Fail;

        try expect_equal_strings(reference, principal.value);
    }

    try expect(it.done());
}

test "critical options iterator" {
    // Reference
    const critical_options = [_]zssh.cert.Critical.Option{.{
        .kind = .@"force-command",
        .value = "ls -la", // FIXME:
    }};

    const pem = try Pem.parse(@embedFile("force-command-cert.pub"));
    var der = try pem.decode(
        std.testing.allocator,
        std.base64.standard.Decoder,
    );
    defer der.deinit();

    const cert = try Rsa.from_bytes(der.data);

    var it = cert.critical_options.iter();

    inline for (comptime critical_options) |critical_option| {
        const opt = try it.next() orelse return error.Fail;

        try expect_equal(critical_option.kind, opt.kind);
        try expect_equal_strings(critical_option.value, opt.value);
    }

    try expect(it.done());
}

test "multiple critical options iterator" {
    // Reference
    const critical_options = [_]zssh.cert.Critical.Option{
        .{
            .kind = .@"force-command",
            .value = "ls -la",
        },
        .{
            .kind = .@"source-address",
            .value = "198.51.100.0/24,203.0.113.0/26",
        },
    };

    const pem = try Pem.parse(
        @embedFile("multiple-critical-options-cert.pub"),
    );
    var der = try pem.decode(
        std.testing.allocator,
        std.base64.standard.Decoder,
    );
    defer der.deinit();

    const cert = try Rsa.from_bytes(der.data);

    var it = cert.critical_options.iter();

    inline for (comptime critical_options) |reference| {
        const opt = try it.next() orelse return error.Fail;

        try expect_equal(reference.kind, opt.kind);
        try expect_equal_strings(reference.value, opt.value);
    }

    try expect(it.done());
}

test "parse ed25519 cert with wrong magic string" {
    const pem = try Pem.parse(@embedFile("ed25519-cert-wrong-magic-string.pub"));

    try expect_error(
        Error.InvalidMagicString,
        Cert.from_pem(std.testing.allocator, std.base64.standard.Decoder, &pem),
    );
}

// TODO: Add tets for other certs types
