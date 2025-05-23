// SPDX-License-Identifier: GPL-3.0-only
const std = @import("std");

const enc = @import("enc.zig");
const magic = @import("magic.zig");
const mem = @import("mem.zig");
const meta = @import("meta.zig");
const pem = @import("pem.zig");
const pk = @import("pk.zig");

const Is = meta.Is;

const Box = mem.Box;

const From = enc.From;

const Error = @import("error.zig").Error;

const BoxRef = mem.BoxRef;
const Struct = meta.Struct;

pub fn MakeMagic(comptime T: type) type {
    return magic.MakeMagic(
        T,
        std.mem.TokenIterator(u8, .sequence),
        [:0]const u8,
        enc.parse_null_terminated_str,
        enc.null_terminated_str_encoded_size,
    );
}

pub fn decrypt_aes_256_ctr(
    allocator: std.mem.Allocator,
    private_key_blob: []const u8,
    kdf: *const ?Kdf,
    passphrase: []const u8,
) Error![]u8 {
    std.debug.assert(kdf.* != null);

    const KEYLEN: u32 = 32;
    const IVLEN: u32 = 16;

    const out = try allocator.alloc(u8, private_key_blob.len);
    errdefer allocator.free(out);

    var keyiv = std.mem.zeroes([KEYLEN + IVLEN]u8);
    defer std.crypto.secureZero(u8, &keyiv);

    std.crypto.pwhash.bcrypt.opensshKdf(
        passphrase,
        kdf.*.?.salt,
        &keyiv,
        kdf.*.?.rounds,
    ) catch return Error.InvalidData; // FIXME;

    const ctx = std.crypto.core.aes.Aes256.initEnc(keyiv[0..KEYLEN].*);
    std.crypto.core.modes.ctr(
        std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes256),
        ctx,
        out,
        private_key_blob,
        keyiv[KEYLEN..keyiv.len].*,
        .big,
    );

    return out;
}

pub fn decrypt_none(
    allocator: std.mem.Allocator,
    private_key_blob: []const u8,
    _: *const ?Kdf,
    _: []const u8,
) Error![]u8 {
    const out = try allocator.alloc(u8, private_key_blob.len);
    // errdefer allocator.free(out);

    @memcpy(out, private_key_blob);

    return out;
}

pub const Checksum = struct {
    value: u64,

    const Self = @This();

    pub inline fn check(value: u64) bool {
        return @as(u32, @truncate(std.math.shr(u64, value, @bitSizeOf(u32)))) ==
            @as(u32, @truncate(value));
    }

    pub fn parse(src: []const u8) Error!enc.Cont(Self) {
        const next, const checksum = try enc.rfc4251.parse_int(u64, src);

        // XXX: This is not realy great
        if (!check(checksum)) return Error.InvalidChecksum;

        return .{ next, .{ .value = checksum } };
    }
};

pub const Cipher = struct {
    name: []const u8,
    decrypt: *const fn (
        allocator: std.mem.Allocator,
        private_key_blob: []const u8,
        kdf: *const ?Kdf,
        passphrase: []const u8,
    ) Error![]u8,

    const Self = @This();

    pub const ciphers = [_]Self{
        // Taken from openssl-portable
        // TODO: Add OpenSSL ciphers
        // .{ "openssl-3des-cbc", 8, 24, 0, 0 },
        // .{ "openssl-aes128-cbc", 16, 16, 0, 0 },
        // .{ "openssl-aes192-cbc", 16, 24, 0, 0 },
        // .{ "openssl-aes256-cbc", 16, 32, 0, 0 },
        // .{ "openssl-aes128-ctr", 16, 16, 0, 0 },
        // .{ "openssl-aes192-ctr", 16, 24, 0, 0 },
        // .{ "openssl-aes256-ctr", 16, 32, 0, 0 },
        // .{ "openssl-aes128-gcm@openssh.com", 16, 16, 12, 16 },
        // .{ "openssl-aes256-gcm@openssh.com", 16, 32, 12, 16 },
        // .{ .name = "aes128-ctr", .block_size = 16, .key_len = 16, .iv_len = 0, .auth_len = 0 },
        // .{ .name = "aes192-ctr", .block_size = 16, .key_len = 24, .iv_len = 0, .auth_len = 0 },
        .{ .name = "aes256-ctr", .decrypt = &decrypt_aes_256_ctr },
        // .{ .name = "chacha20-poly1305@openssh.com", .block_size = 8, .key_len = 64, .iv_len = 0, .auth_len = 16 },
        .{ .name = "none", .decrypt = &decrypt_none },
    };

    pub fn get_supported_ciphers() [ciphers.len][]const u8 {
        comptime var ret: [ciphers.len][]const u8 = undefined;

        comptime var i = 0;
        inline for (comptime ciphers) |cipher| {
            ret[i] = cipher.name;

            i += 1;
        }

        return ret;
    }

    pub fn parse(src: []const u8) Error!enc.Cont(Cipher) {
        const next, const name = try enc.rfc4251.parse_string(src);

        inline for (comptime Self.ciphers) |cipher| {
            if (std.mem.eql(u8, name, cipher.name)) {
                return .{ next, cipher };
            }
        }

        return Error.InvalidData;
    }

    pub fn serialize(self: *const Self, writer: std.io.AnyWriter) anyerror!void {
        try enc.serialize_any([]const u8, writer, self.name);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size([]const u8, self.name);
    }
};

/// "Newer" OpenSSH private key format. Will NOT work with old PKCS #1 or SECG
/// keys.
pub fn MakePem(
    comptime pre: []const u8,
    comptime pos: []const u8,
    decoder: anytype,
) type {
    return struct {
        pre: pem.Literal(pre, TokenIterator),
        der: []const u8,
        suf: pem.Literal(pos, TokenIterator),

        const Self = @This();
        pub const TokenIterator = std.mem.TokenIterator(u8, .sequence);

        pub inline fn tokenize(src: []const u8) TokenIterator {
            return std.mem.tokenizeSequence(u8, src, "-----");
        }

        pub fn parse(src: []const u8) !Self {
            return try pem.parse(Self, TokenIterator, src);
        }

        pub fn decode(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) !Box([]u8, .sec) {
            const data = try pem
                .decode_with_ignore(allocator, decoder, self.der);

            return .{ .allocator = allocator, .data = data };
        }
    };
}

pub const Kdf = struct {
    salt: []const u8,
    rounds: u32,

    const Self = @This();

    pub fn parse(src: []const u8) Error!enc.Cont(Kdf) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn serialize(self: *const Self, writer: std.io.AnyWriter) anyerror!void {
        try enc.serialize_struct(Self, writer, self);
    }

    pub fn encoded_size(self: *const Self) u32 {
        return enc.encoded_size_struct(Self, self);
    }
};

pub fn MakeSk(
    comptime MagicType: type,
    comptime PemType: type,
    comptime Pk: type,
    comptime Kb: type,
) type {
    return struct {
        magic: Magic,
        cipher: Cipher,
        kdf_name: []const u8,
        kdf: Optional(Kdf),
        number_of_keys: u32,
        public_key_blob: []const u8,
        private_key_blob: []const u8,

        const Self = @This();
        pub const Pem = PemType;
        pub const Magic = MagicType;

        // FIXME:
        fn Optional(comptime T: type) type {
            return struct {
                opt: ?T,

                pub fn parse(src: []const u8) Error!enc.Cont(@This()) {
                    const next, const inner = try enc.rfc4251.parse_string(src);

                    if (inner.len == 0)
                        return .{ next, .{ .opt = null } };

                    _, const t = try T.parse(inner);

                    return .{ next, .{ .opt = t } };
                }

                pub fn serialize(
                    self: *const @This(),
                    writer: std.io.AnyWriter,
                ) anyerror!void {
                    if (self.opt) |*opt| {
                        const len = opt.encoded_size();

                        try enc.serialize_any(u32, writer, len);

                        try opt.serialize(writer);

                        return;
                    }

                    try enc.serialize_any(u32, writer, 0x00);
                }

                pub fn encoded_size(self: *const @This()) u32 {
                    if (self.opt) |*opt| {
                        return opt.encoded_size() + @sizeOf(u32);
                    }

                    return @sizeOf(u32);
                }
            };
        }

        /// Returns `true` if the `private_key_blob` is encrypted, i.e.,
        /// cipher.name != "none"
        pub inline fn is_encrypted(self: *const Self) bool {
            return !(std.mem.eql(u8, self.cipher.name, "none") and self.kdf.opt == null);
        }

        pub fn get_public_key(
            self: *const Self,
        ) Error!From("bytes", fn ([]const u8) Error!Pk)(Pk) {
            return Pk.from_bytes(self.public_key_blob);
        }

        pub fn get_private_key(
            self: *const Self,
            allocator: std.mem.Allocator,
            passphrase: ?[]const u8,
        ) !BoxRef(Kb, .sec) {
            if (self.is_encrypted() and passphrase == null)
                return error.MissingPassphrase;

            inline for (comptime Cipher.ciphers) |cipher| {
                if (std.mem.eql(u8, cipher.name, self.cipher.name)) {
                    const private_blob = try cipher.decrypt(
                        allocator,
                        self.private_key_blob,
                        &self.kdf.opt,
                        passphrase orelse undefined,
                    );
                    errdefer allocator.free(private_blob);

                    const key = try Kb.from_bytes(private_blob);

                    return .{
                        .allocator = allocator,
                        .ref = private_blob,
                        .data = key,
                    };
                }
            }

            unreachable;
        }

        fn from(src: []const u8) Error!Self {
            return try enc.parse(Self, src);
        }

        pub fn from_bytes(src: []const u8) Error!Self {
            return try from(src);
        }

        pub fn from_pem(
            allocator: std.mem.Allocator,
            encoded_pem: Pem,
        ) !BoxRef(Self, .sec) {
            const der = try encoded_pem.decode(allocator);
            errdefer der.deinit();

            return .{
                .allocator = allocator,
                .data = try from(der.data),
                .ref = der.data,
            };
        }

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
}

/// Creates a private key blob for a given key type T, where the return type is
/// of format:
///
/// ```zig
/// struct {
///     checksum: Checksum
///     // inlined fields of T
///     comment: []const u8,
///     pad: enc.Padding,
/// }
/// ```
///
/// T must be a struct.
pub fn MakeKeyBlob(comptime T: type) type {
    const B = struct { checksum: Checksum };

    const A = struct {
        comment: []const u8,
        pad: enc.Padding,
    };

    const fields =
        std.meta.fields(B) ++
        std.meta.fields(Is(.@"struct", T)) ++
        std.meta.fields(A);

    const ret: std.builtin.Type.Struct = .{
        .decls = &.{},
        .fields = fields,
        .is_tuple = false,
        .layout = .auto,
    };

    return @Type(@unionInit(std.builtin.Type, "struct", ret));
}
