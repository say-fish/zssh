const std = @import("std");

const zssh = @import("zssh");

const public = @import("public.zig");

const enc = zssh.enc;
const gen = zssh.sk;
const mem = zssh.mem;

pub const Box = mem.Box;
pub const Cont = enc.Cont;
pub const Error = zssh.err.Error;

pub const wire = struct {
    pub const Rsa = struct {
        kind: []const u8,
        // Public key parts
        n: []const u8,
        e: []const u8,
        // Private key parts
        d: []const u8,
        i: []const u8,
        p: []const u8,
        q: []const u8,

        const Self = @This();

        pub fn encode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) anyerror!Box([]u8, .sec) {
            return try enc.encode_value(Self, allocator, self, .sec);
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
    };

    pub const Ecdsa = struct {
        kind: []const u8,
        // Public parts
        curve: []const u8,
        pk: []const u8,
        // Private parts
        sk: []const u8,

        const Self = @This();

        pub fn encode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) anyerror!Box([]u8, .sec) {
            return try enc.encode_value(Self, allocator, self, .sec);
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
    };

    pub const Ed25519 = struct {
        kind: []const u8,
        // Public parts
        pk: []const u8,
        // Private parts
        sk: []const u8,

        const Self = @This();

        pub fn encode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) anyerror!Box([]u8, .sec) {
            return try enc.encode_value(Self, allocator, self, .sec);
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
    };

    pub const Key = union(enum) {
        rsa: Rsa,
        ecdsa: Ecdsa,
        ed: Ed25519,

        const Self = @This();

        pub const Magic = public.Key.Magic;

        pub fn parse(src: []const u8) Error!Cont(Self) {
            const magic = Magic.from_bytes(src) catch
                return error.InvalidData;

            switch (magic.value) {
                .@"ssh-rsa",
                => {
                    const next, const key =
                        try enc.parse_with_cont(Rsa, src);

                    return .{ next, .{ .rsa = key } };
                },

                .@"ecdsa-sha2-nistp256",
                .@"ecdsa-sha2-nistp384",
                .@"ecdsa-sha2-nistp521",
                => {
                    const next, const key =
                        try enc.parse_with_cont(Ecdsa, src);

                    return .{ next, .{ .ecdsa = key } };
                },

                .@"ssh-ed25519",
                => {
                    const next, const key =
                        try enc.parse_with_cont(Ed25519, src);

                    return .{ next, .{ .ed = key } };
                },
            }
        }

        pub fn serialize(
            _: *const Self,
            _: std.io.AnyWriter,
        ) anyerror!void {
            @panic("TODO");
        }

        pub fn encoded_size(_: *const Self) u32 {
            @panic("TODO");
        }
    };
};

pub const KeyBlob = union(enum) {
    rsa: Rsa,
    ecdsa: Ecdsa,
    ed: Ed25519,

    const Self = @This();

    pub const Rsa = gen.MakeKeyBlob(wire.Rsa);
    pub const Ecdsa = gen.MakeKeyBlob(wire.Ecdsa);
    pub const Ed25519 = gen.MakeKeyBlob(wire.Ed25519);

    pub const Magic = public.Key.Magic;

    // FIXME: Return owned data
    pub fn get_wire(self: *const Self) wire.Key {
        switch (self.*) {
            .rsa => |*rsa| {
                var ret: wire.Rsa = undefined;

                mem.shallow_copy(wire.Rsa, &ret, Rsa, rsa);

                return @unionInit(wire.Key, "rsa", ret);
            },

            .ecdsa => |*ecdsa| {
                var ret: wire.Ecdsa = undefined;

                mem.shallow_copy(wire.Ecdsa, &ret, Ecdsa, ecdsa);

                return @unionInit(wire.Key, "ecdsa", ret);
            },

            .ed => |*ed| {
                var ret: wire.Ed25519 = undefined;

                mem.shallow_copy(wire.Ed25519, &ret, Ed25519, ed);

                return @unionInit(wire.Key, "ed", ret);
            },
        }
    }

    pub fn from_bytes(src: []const u8) !Self {
        _, const ret = try parse(src);
        return ret;
    }

    pub fn parse(src: []const u8) Error!Cont(Self) {
        // FIXME: Double work
        const off, _ = try gen.Checksum.parse(src);
        // FIXME: Double work
        const magic = Magic.from_bytes(src[off..]) catch
            return error.InvalidData;

        switch (magic.value) {
            .@"ssh-rsa",
            => {
                const next, const key =
                    try enc.parse_with_cont(Rsa, src);

                return .{ next, .{ .rsa = key } };
            },

            .@"ecdsa-sha2-nistp256",
            .@"ecdsa-sha2-nistp384",
            .@"ecdsa-sha2-nistp521",
            => {
                const next, const key =
                    try enc.parse_with_cont(Ecdsa, src);

                return .{ next, .{ .ecdsa = key } };
            },

            .@"ssh-ed25519",
            => {
                const next, const key =
                    try enc.parse_with_cont(Ed25519, src);

                return .{ next, .{ .ed = key } };
            },
        }
    }
};

pub const Key = gen.MakeSk(
    gen.MakeMagic(enum { @"openssh-key-v1" }),
    gen.MakePem(
        "BEGIN OPENSSH PRIVATE KEY",
        "END OPENSSH PRIVATE KEY",
        zssh.pem.base64.Decoder,
    ),
    public.Key,
    KeyBlob,
);
