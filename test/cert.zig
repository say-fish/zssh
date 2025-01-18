const std = @import("std");

const sshcrypto = @import("sshcrypto");
const Cert = sshcrypto.cert.Cert;
const Pem = sshcrypto.cert.Pem;

const expect = std.testing.expect;
const expect_equal = std.testing.expectEqual;
const expect_error = std.testing.expectError;
const expect_equal_strings = std.testing.expectEqualStrings;

fn verify_cert(cert: anytype) !void {
    try expect_equal(2, cert.serial);
    try expect_equal(.user, cert.kind);
    try expect_equal_strings("abc", cert.key_id);

    var it = cert.valid_principals.iter();
    try expect_equal_strings("root", it.next().?);
    try expect(it.done());

    try expect_equal(0, cert.valid_after);
    try expect_equal(std.math.maxInt(u64), cert.valid_before);
}

test "parse Rsa cert" {
    const pem = try Pem.parse(@embedFile("rsa-cert.pub"));

    var cert = try Cert.from_pem(std.testing.allocator, &pem);
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

    var der = try pem.decode(std.testing.allocator);
    // Save the len so deinit works
    const len = der.data.len;
    defer {
        der.data.len = len;
        der.deinit();
    }

    der.data.len = 100;

    const cert = Cert.from_bytes(der.data);

    try expect_error(sshcrypto.cert.Error.MalformedString, cert);
}

test "parse ecdsa cert" {
    const pem = try Pem.parse(@embedFile("ecdsa-cert.pub"));

    var der = try pem.decode(std.testing.allocator);
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

    var der = try pem.decode(std.testing.allocator);
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

const Ed25519 = sshcrypto.cert.Ed25519;
const enconded_sig_size = sshcrypto.cert.Ed25519.enconded_sig_size;

test enconded_sig_size {
    var cert = try Ed25519.from_pem(
        std.testing.allocator,
        &try Pem.parse(@embedFile("ed25519-cert.pub")),
    );
    defer cert.deinit();

    try expect_equal(352, cert.data.enconded_sig_size());
}

test "verify ed25519 cert" {
    const Signature = std.crypto.sign.Ed25519.Signature;
    const PublicKey = std.crypto.sign.Ed25519.PublicKey;

    const pem = try Pem.parse(@embedFile("ed25519-cert.pub"));

    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    switch (try Cert.from_bytes(der.data)) {
        .ed25519 => |cert| {
            const signature = Signature.fromBytes(
                cert.signature.ed25519.sm[0..64].*,
            );
            const pk = try PublicKey.fromBytes(
                cert.signature_key.ed25519.pk[0..32].*,
            );
            try signature.verify(der.data[0..cert.enconded_sig_size()], pk);
        },
        else => return error.wrong_certificate,
    }
}

test "extensions iterator" {
    // Reference
    const extensions = [_][]const u8{
        "permit-X11-forwarding",
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-pty",
        "permit-user-rc",
    };

    const Rsa = sshcrypto.cert.Rsa;

    const pem = try Pem.parse(@embedFile("rsa-cert.pub"));

    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const cert = try Rsa.from_bytes(der.data);

    var it = cert.extensions.iter();

    inline for (comptime extensions) |extension| {
        try expect_equal_strings(extension, it.next().?);
    }

    try expect(it.done());
}

test "extensions to bitflags" {
    const Ext = sshcrypto.cert.Extensions.Tags;
    const Rsa = sshcrypto.cert.Rsa;

    const pem = try Pem.parse(@embedFile("rsa-cert.pub"));

    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const cert = try Rsa.from_bytes(der.data);

    try expect_equal(
        @intFromEnum(Ext.@"permit-agent-forwarding") |
            @intFromEnum(Ext.@"permit-X11-forwarding") |
            @intFromEnum(Ext.@"permit-user-rc") |
            @intFromEnum(Ext.@"permit-port-forwarding") |
            @intFromEnum(Ext.@"permit-pty"),
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

    const Rsa = sshcrypto.cert.Rsa;

    const pem = try Pem.parse(@embedFile("multiple-principals-cert.pub"));

    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const cert = try Rsa.from_bytes(der.data);

    var it = cert.valid_principals.iter();

    for (valid_principals) |principal| {
        try expect(std.mem.eql(u8, principal, it.next().?));
    }

    try expect(it.done());
}

test "critical options iterator" {
    // Reference
    const critical_options = [_]sshcrypto.cert.CriticalOption{.{
        .kind = .@"force-command",
        .value = "ls -la",
    }};

    const Rsa = sshcrypto.cert.Rsa;

    const pem = try Pem.parse(@embedFile("force-command-cert.pub"));
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const cert = try Rsa.from_bytes(der.data);

    var it = cert.critical_options.iter();

    inline for (comptime critical_options) |critical_option| {
        const opt = it.next().?;

        try expect_equal(critical_option.kind, opt.kind);
        try expect_equal_strings(critical_option.value, opt.value);
    }

    try expect(it.done());
}

test "multiple critical options iterator" {
    // Reference
    const critical_options = [_]sshcrypto.cert.CriticalOption{
        .{
            .kind = .@"force-command",
            .value = "ls -la",
        },
        .{
            .kind = .@"source-address",
            .value = "198.51.100.0/24,203.0.113.0/26",
        },
    };

    const Rsa = sshcrypto.cert.Rsa;

    const pem = try Pem.parse(
        @embedFile("multiple-critical-options-cert.pub"),
    );
    var der = try pem.decode(std.testing.allocator);
    defer der.deinit();

    const cert = try Rsa.from_bytes(der.data);

    var it = cert.critical_options.iter();

    inline for (comptime critical_options) |critical_option| {
        const opt = it.next().?;

        try expect_equal(critical_option.kind, opt.kind);
        try expect_equal_strings(critical_option.value, opt.value);
    }

    try expect(it.done());
}

test "parse ed25519 cert with wrong magic string" {
    const pem = try Pem.parse(@embedFile("ed25519-cert-wrong-magic-string.pub"));

    try expect_error(error.InvalidMagicString, Cert.from_pem(std.testing.allocator, &pem));
}

// TODO: Add tets for other certs types
