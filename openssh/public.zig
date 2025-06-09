const std = @import("std");

const zssh = @import("zssh");

const enc = zssh.enc;
const gen = zssh.pk;
const mem = zssh.mem;

const Box = mem.Box;
const BoxRef = mem.BoxRef;
const Cont = enc.Cont;
const Error = zssh.err.Error;

pub const Rsa = struct {
    magic: Magic,
    e: []const u8, // TODO: mpint
    n: []const u8, // TODO: mpint

    const Self = @This();

    pub const Magic = gen.MakeMagic(enum { @"ssh-rsa" });

    fn from(src: []const u8) Error!Self {
        return try enc.parse(Self, src);
    }

    pub fn from_bytes(src: []const u8) Error!Self {
        return try Self.from(src);
    }

    pub fn encode(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) anyerror!Box([]u8, .plain) {
        return try enc.encode_value(Self, allocator, self, .plain);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size_struct(Self, self);
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        try enc.serialize_struct(Self, writer, self);
    }

    // TODO: modes
    pub fn fingerprint(self: *const Self) !void {
        var sha = std.crypto.hash.sha2.Sha256.init(.{});
        const stdout = std.io.getStdOut().writer();

        try self.serialize(sha.writer().any());
        var out = std.mem.zeroes([std.crypto.hash.sha2.Sha256.digest_length]u8);

        sha.final(&out);

        try stdout.print("{} SHA256:", .{(self.n.len - 1) * 8}); // FIXME: MPINT
        try std.base64.standard_no_pad.Encoder.encodeWriter(stdout, &out);
        try stdout.print(" (RSA)", .{});
    }
};

pub const Ecdsa = struct {
    magic: Magic,
    curve: []const u8,
    pk: []const u8,

    const Self = @This();

    pub const Magic = gen.MakeMagic(enum {
        @"ecdsa-sha2-nistp256",
        @"ecdsa-sha2-nistp384",
        @"ecdsa-sha2-nistp521",
    });

    fn from(src: []const u8) Error!Self {
        return try enc.parse(Self, src);
    }

    pub fn from_bytes(src: []const u8) Error!Self {
        return try Self.from(src);
    }

    pub fn encode(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) anyerror!Box([]u8, .plain) {
        return enc.encode_value(Self, allocator, self, .plain);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size_struct(Self, self);
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        try enc.serialize_struct(Self, writer, self);
    }

    pub fn format(
        self: *const Self,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print(" magic: {s}\n", .{self.magic.as_string()});
        try writer.print(" curve: {}", .{std.fmt.fmtSliceHexUpper(self.curve)});
        try writer.print("    pk: {}", .{std.fmt.fmtSliceHexUpper(self.pk)});
    }
};

pub const Ed25519 = struct {
    magic: Magic,
    pk: []const u8,

    const Self = @This();

    pub const Magic = gen.MakeMagic(enum { @"ssh-ed25519" });

    fn from(src: []const u8) Error!Ed25519 {
        return try enc.parse(Self, src);
    }

    pub fn from_bytes(src: []const u8) Error!Ed25519 {
        return try Self.from(src);
    }

    pub fn encode(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) anyerror!Box([]u8, .plain) {
        return enc.encode_value(Self, allocator, self, .plain);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size_struct(Self, self);
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        try enc.serialize_struct(Self, writer, self);
    }

    pub fn format(
        self: *const Self,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print(" magic: {s}\n", .{self.magic.as_string()});
        try writer.print("    pk: {}", .{std.fmt.fmtSliceHexUpper(self.pk)});
    }
};

pub const Key = union(enum) {
    rsa: Rsa,
    ecdsa: Ecdsa,
    ed: Ed25519,

    const Self = @This();

    pub const Pem = gen.MakePem(Magic, std.base64.standard.Decoder);
    pub const Magic = gen.MakeMagic(enum {
        @"ssh-rsa",
        @"ecdsa-sha2-nistp256",
        @"ecdsa-sha2-nistp384",
        @"ecdsa-sha2-nistp521",
        @"ssh-ed25519",
    });

    pub fn parse(src: []const u8) Error!Cont(Key) {
        // FIXME: We don't need this.
        const next, const key = try enc.rfc4251.parse_string(src);

        return .{ next, Self.from_bytes(key) catch return Error.InvalidData };
    }

    pub fn from(magic: Magic.Value, src: []const u8) !Self {
        return switch (magic) {
            .@"ssh-rsa",
            => .{ .rsa = try Rsa.from_bytes(src) },

            .@"ecdsa-sha2-nistp256",
            .@"ecdsa-sha2-nistp384",
            .@"ecdsa-sha2-nistp521",
            => .{ .ecdsa = try Ecdsa.from_bytes(src) },

            .@"ssh-ed25519",
            => .{ .ed = try Ed25519.from_bytes(src) },
        };
    }

    pub fn from_bytes(src: []const u8) Error!Self {
        return Self.from((try Magic.from_bytes(src)).value, src);
    }

    pub fn from_pem(
        allocator: std.mem.Allocator,
        pem_enc: Pem,
    ) Error!BoxRef(Self, .plain) {
        const der = try pem_enc.decode(allocator);
        errdefer der.deinit();

        return .{
            .allocator = allocator,
            .data = try Self.from(pem_enc.magic.value, der.data),
            .ref = der.data,
        };
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        return switch (self.*) {
            inline else => |value| value.serialize(writer),
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

    pub fn encoded_size(self: *const Self) u32 {
        return switch (self.*) {
            inline else => |value| enc.encoded_size(@TypeOf(value), value),
        };
    }

    pub fn fingerprint(self: *const Self) !void {
        switch (self.*) {
            .rsa => |k| try k.fingerprint(),
            else => @panic("die"),
        }
    }
};
