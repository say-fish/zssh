const std = @import("std");

const sshcrypto = @import("sshcrypto");
const cert = sshcrypto.cert;

const cert_decoder = cert.CertDecoder
    .init(std.testing.allocator, std.base64.standard.Decoder);

const expect = std.testing.expect;
const expect_equal = std.testing.expectEqual;
const expect_error = std.testing.expectError;

test "parse rsa cert" {
    var pem = try cert_decoder.decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    switch (try cert.Cert.from_pem(&pem.data)) {
        .rsa => |c| {
            try expect_equal(c.magic.value, .@"ssh-rsa-cert-v01@openssh.com");
            try expect_equal(c.serial, 2);
            try expect_equal(c.kind, .user);
            try expect(std.mem.eql(u8, c.key_id, "abc"));

            var it = c.valid_principals.iter();
            try expect(std.mem.eql(u8, it.next().?, "root"));
            try expect(it.done());

            try expect_equal(c.valid_after, 0);
            try expect_equal(c.valid_before, std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "parse rsa cert bad cert" {
    var pem = try cert_decoder.decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    const len = pem.data.der.len;
    pem.data.der.len = 100;

    const c = cert.Cert.from_pem(&pem.data);

    pem.data.der.len = len;

    try expect_error(cert.Error.MalformedString, c);
}

test "parse ecdsa cert" {
    var pem = try cert_decoder.decode(@embedFile("ecdsa-cert.pub"));
    defer pem.deinit();

    switch (try cert.Cert.from_pem(&pem.data)) {
        .ecdsa => |c| {
            try expect_equal(
                .@"ecdsa-sha2-nistp256-cert-v01@openssh.com",
                c.magic.value,
            );
            try expect_equal(c.serial, 2);
            try expect_equal(c.kind, .user);
            try expect(std.mem.eql(u8, c.key_id, "abc"));

            var it = c.valid_principals.iter();
            try expect(std.mem.eql(u8, it.next().?, "root"));
            try expect(it.done());

            try expect_equal(c.valid_after, 0);
            try expect_equal(c.valid_before, std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "parse ed25519 cert" {
    var pem = try cert_decoder.decode(@embedFile("ed25519-cert.pub"));
    defer pem.deinit();

    switch (try cert.Cert.from_pem(&pem.data)) {
        .ed25519 => |c| {
            try expect_equal(
                c.magic.value,
                .@"ssh-ed25519-cert-v01@openssh.com",
            );
            try expect_equal(c.serial, 2);
            try expect_equal(c.kind, .user);

            try expect(std.mem.eql(u8, c.key_id, "abc"));

            var it = c.valid_principals.iter();
            try expect(std.mem.eql(u8, it.next().?, "root"));
            try expect(it.done());

            try expect_equal(c.valid_after, 0);
            try expect_equal(c.valid_before, std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "verify ed25519 cert" {
    var pem = try cert_decoder.decode(@embedFile("ed25519-cert.pub"));
    defer pem.deinit();

    switch (try cert.Cert.from_pem(&pem.data)) {
        .ed25519 => |c| {
            const signature = std.crypto.sign.Ed25519.Signature.fromBytes(c.signature.ed25519.sm[0..64].*);
            const pk = try std.crypto.sign.Ed25519.PublicKey.fromBytes(c.signature_key.ed25519.pk[0..32].*);

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

    var pem = try cert_decoder.decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    const rsa = try cert.Rsa.from_pem(&pem.data);

    var it = rsa.extensions.iter();

    for (extensions) |extension| {
        try expect(std.mem.eql(u8, extension, it.next().?));
    }

    try expect(it.done());
}

test "extensions to bitflags" {
    const Ext = cert.Extensions.Tags;

    var pem = try cert_decoder.decode(@embedFile("rsa-cert.pub"));
    defer pem.deinit();

    const rsa = try cert.Rsa.from_pem(&pem.data);

    try expect_equal(
        try rsa.extensions.to_bitflags(),
        @intFromEnum(Ext.@"permit-agent-forwarding") |
            @intFromEnum(Ext.@"permit-X11-forwarding") |
            @intFromEnum(Ext.@"permit-user-rc") |
            @intFromEnum(Ext.@"permit-port-forwarding") |
            @intFromEnum(Ext.@"permit-pty"),
    );
}

test "multiple valid principals iterator" {
    // Reference
    const valid_principals = [_][]const u8{
        "foo",
        "bar",
        "baz",
    };

    var pem = try cert_decoder.decode(@embedFile("multiple-principals-cert.pub"));
    defer pem.deinit();

    const rsa = try cert.Rsa.from_pem(&pem.data);

    var it = rsa.valid_principals.iter();

    for (valid_principals) |principal|
        try expect(std.mem.eql(u8, principal, it.next().?));
}

test "critical options iterator" {
    // Reference
    const critical_options = [_]cert.CriticalOption{.{
        .kind = .@"force-command",
        .value = "ls -la",
    }};

    var pem = try cert_decoder.decode(@embedFile("force-command-cert.pub"));
    defer pem.deinit();

    const rsa = try cert.Rsa.from_pem(&pem.data);

    var it = rsa.critical_options.iter();

    for (critical_options) |critical_option| {
        const opt = it.next().?;

        try expect_equal(critical_option.kind, opt.kind);
        try expect(std.mem.eql(u8, critical_option.value, opt.value));
    }

    try expect(it.done());
}

test "multiple critical options iterator" {
    // Reference
    const critical_options = [_]cert.CriticalOption{
        .{
            .kind = .@"force-command",
            .value = "ls -la",
        },
        .{
            .kind = .@"source-address",
            .value = "198.51.100.0/24,203.0.113.0/26",
        },
    };

    var pem = try cert_decoder.decode(@embedFile("multiple-critical-options-cert.pub"));
    defer pem.deinit();

    const rsa = try cert.Rsa.from_pem(&pem.data);

    var it = rsa.critical_options.iter();

    for (critical_options) |critical_option| {
        const opt = it.next().?;

        try expect_equal(critical_option.kind, opt.kind);
        try expect(std.mem.eql(u8, critical_option.value, opt.value));
    }

    try expect(it.done());
}

// TODO: Add tets for other certs types
