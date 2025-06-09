const std = @import("std");

const zssh = @import("zssh");

const public = @import("public.zig");
const signature = @import("signature.zig");

const enc = zssh.enc;
const gen = zssh.cert;
const mem = zssh.mem;
const pk = zssh.pk;
const sig = zssh.sig;

const Box = mem.Box;
const BoxRef = mem.BoxRef;
const Cont = enc.Cont;
const Error = zssh.err.Error;

pub const Magic = gen.MakeMagic(enum {
    @"ssh-rsa-cert-v01@openssh.com",
    @"rsa-sha2-256-cert-v01@openssh.com",
    @"rsa-sha2-512-cert-v01@openssh.com",
    @"ecdsa-sha2-nistp256-cert-v01@openssh.com",
    @"ecdsa-sha2-nistp384-cert-v01@openssh.com",
    @"ecdsa-sha2-nistp521-cert-v01@openssh.com",
    @"ssh-ed25519-cert-v01@openssh.com",
});

// TODO: Move to another namespace
fn OpenSSHCert(comptime MagicString: type, comptime PublicKey: type) type {
    return gen.MakeCert(
        MagicString,
        PublicKey,
        public.Key,
        signature.Signature,
    );
}

pub const Rsa = OpenSSHCert(gen.MakeMagic(enum {
    @"ssh-rsa-cert-v01@openssh.com",
    @"rsa-sha2-256-cert-v01@openssh.com",
    @"rsa-sha2-512-cert-v01@openssh.com",
}), struct {
    e: []const u8,
    n: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) Error!Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn encode(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) anyerror!Box(Self, .plain) {
        return enc.encode_value(Self, allocator, self, .plain);
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        try enc.serialize_struct(Self, writer, self);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size_struct(Self, self);
    }
});

pub const Ecdsa = OpenSSHCert(gen.MakeMagic(enum {
    @"ecdsa-sha2-nistp256-cert-v01@openssh.com",
    @"ecdsa-sha2-nistp384-cert-v01@openssh.com",
    @"ecdsa-sha2-nistp521-cert-v01@openssh.com",
}), struct {
    curve: []const u8,
    pk: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) Error!Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn encode(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) anyerror!Box(Self, .plain) {
        return enc.encode_value(Self, allocator, self, .plain);
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        try enc.serialize_struct(Self, writer, self);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size_struct(Self, self);
    }
});

pub const Ed25519 = OpenSSHCert(gen.MakeMagic(enum {
    @"ssh-ed25519-cert-v01@openssh.com",
}), struct {
    pk: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) Error!Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn encode(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) anyerror!Box(Self, .plain) {
        return enc.encode_value(Self, allocator, self, .plain);
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        try enc.serialize_struct(Self, writer, self);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size_struct(Self, self);
    }
});

pub const Cert = union(enum) {
    rsa: Rsa,
    ecdsa: Ecdsa,
    ed: Ed25519,

    const Self = @This();

    pub const Pem = gen.MakePem(Magic, std.base64.standard.Decoder);

    fn from(magic: Magic.Value, src: []const u8) !Self {
        return switch (magic) {
            .@"ssh-rsa-cert-v01@openssh.com",
            .@"rsa-sha2-256-cert-v01@openssh.com",
            .@"rsa-sha2-512-cert-v01@openssh.com",
            => .{ .rsa = try Rsa.from_bytes(src) },

            .@"ecdsa-sha2-nistp256-cert-v01@openssh.com",
            .@"ecdsa-sha2-nistp384-cert-v01@openssh.com",
            .@"ecdsa-sha2-nistp521-cert-v01@openssh.com",
            => .{ .ecdsa = try Ecdsa.from_bytes(src) },

            .@"ssh-ed25519-cert-v01@openssh.com",
            => .{ .ed = try Ed25519.from_bytes(src) },
        };
    }

    pub fn from_bytes(src: []const u8) !Self {
        return Self.from((try Magic.from_bytes(src)).value, src);
    }

    pub fn from_pem(
        allocator: std.mem.Allocator,
        pem: *const Pem,
    ) Error!BoxRef(Self, .plain) {
        var der = try pem.decode(allocator);
        errdefer der.deinit();

        const cer = try Self.from(pem.magic.value, der.data);

        return .{ .allocator = allocator, .data = cer, .ref = der.data };
    }

    pub fn encoded_size(self: *const Self) u32 {
        return switch (self.*) {
            inline else => |value| enc.encoded_size(@TypeOf(value), value),
        };
    }

    pub fn encode(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) anyerror!Box([]u8, .plain) {
        return switch (self.*) {
            inline else => |value| value.encode(allocator),
        };
    }
};
