const std = @import("std");

const sshcrypto = @import("sshcrypto");
const Cert = sshcrypto.cert.Cert;

const cert_decoder = sshcrypto.cert.CertDecoder
    .init(std.testing.allocator, std.base64.standard.Decoder);

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

test "parse rsa cert" {
    var pem = try cert_decoder.decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    switch (try Cert.from_pem(&pem.data)) {
        .rsa => |cert| {
            try expect_equal(.@"ssh-rsa-cert-v01@openssh.com", cert.magic.value);
            try verify_cert(cert);
        },
        else => @panic("Expected rsa cert"),
    }
}

test "parse rsa cert bad cert" {
    var pem = try cert_decoder.decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    const len = pem.data.der.len;
    pem.data.der.len = 100;

    const cert = Cert.from_pem(&pem.data);

    pem.data.der.len = len;

    try expect_error(sshcrypto.cert.Error.MalformedString, cert);
}

test "parse ecdsa cert" {
    var pem = try cert_decoder.decode(@embedFile("ecdsa-cert.pub"));
    defer pem.deinit();

    switch (try Cert.from_pem(&pem.data)) {
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
    var pem = try cert_decoder.decode(@embedFile("ed25519-cert.pub"));
    defer pem.deinit();

    switch (try Cert.from_pem(&pem.data)) {
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

test "verify ed25519 cert" {
    var pem = try cert_decoder.decode(@embedFile("ed25519-cert.pub"));
    defer pem.deinit();

    const Signature = std.crypto.sign.Ed25519.Signature;
    const PublicKey = std.crypto.sign.Ed25519.PublicKey;

    switch (try Cert.from_pem(&pem.data)) {
        .ed25519 => |cert| {
            const signature = Signature.fromBytes(
                cert.signature.ed25519.sm[0..64].*,
            );
            const pk = try PublicKey.fromBytes(
                cert.signature_key.ed25519.pk[0..32].*,
            );
            // FIXME:
            try signature.verify(pem.data.der[0 .. pem.data.der.len - 87], pk);
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

    var pem = try cert_decoder.decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    const cert = try Rsa.from_pem(&pem.data);

    var it = cert.extensions.iter();

    inline for (comptime extensions) |extension| {
        try expect_equal_strings(extension, it.next().?);
    }

    try expect(it.done());
}

test "extensions to bitflags" {
    const Ext = sshcrypto.cert.Extensions.Tags;
    const Rsa = sshcrypto.cert.Rsa;

    var pem = try cert_decoder.decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    const cert = try Rsa.from_pem(&pem.data);

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

    var pem = try cert_decoder.decode(@embedFile("multiple-principals-cert.pub"));
    defer pem.deinit();

    const cert = try Rsa.from_pem(&pem.data);

    var it = cert.valid_principals.iter();

    for (valid_principals) |principal| {
        try expect(std.mem.eql(u8, principal, it.next().?));
    }
}

test "critical options iterator" {
    // Reference
    const critical_options = [_]sshcrypto.cert.CriticalOption{.{
        .kind = .@"force-command",
        .value = "ls -la",
    }};

    const Rsa = sshcrypto.cert.Rsa;

    var pem = try cert_decoder.decode(@embedFile("force-command-cert.pub"));
    defer pem.deinit();

    const cert = try Rsa.from_pem(&pem.data);

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

    var pem = try cert_decoder.decode(
        @embedFile("multiple-critical-options-cert.pub"),
    );
    defer pem.deinit();

    const cert = try Rsa.from_pem(&pem.data);

    var it = cert.critical_options.iter();

    inline for (comptime critical_options) |critical_option| {
        const opt = it.next().?;

        try expect_equal(critical_option.kind, opt.kind);
        try expect_equal_strings(critical_option.value, opt.value);
    }

    try expect(it.done());
}

// TODO: Add tets for other certs types
