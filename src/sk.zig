const std = @import("std");

const enc = @import("enc.zig");
const mem = @import("mem.zig");
const pem = @import("pem.zig");
const pk = @import("pk.zig");

pub const Error = error{
    /// This indicates, either: PEM corruption, DER corruption, or an
    /// unsupported magic string.
    InvalidMagicString,
    /// The checksum for private keys is invalid, meaning either, decryption
    /// was not successful, or data is corrupted. This is NOT an auth form
    /// error.
    InvalidChecksum,
} || enc.Error || std.mem.Allocator.Error;

fn MagicString(comptime T: type) type {
    return enc.GenericMagicString(
        T,
        enc.parse_null_terminated_str,
        enc.null_terminated_str_encoded_size,
    );
}

pub fn decrypt_aes_256_ctr(
    allocator: std.mem.Allocator,
    private_key_blob: []const u8,
    kdf: *const Kdf,
    passphrase: []const u8,
) Error![]u8 {
    const KEYLEN: u32 = 32;
    const IVLEN: u32 = 16;

    const out = try allocator.alloc(u8, private_key_blob.len);
    errdefer allocator.free(out);

    var keyiv = std.mem.zeroes([KEYLEN + IVLEN]u8);
    defer std.crypto.secureZero(u8, &keyiv);

    std.crypto.pwhash.bcrypt.opensshKdf(
        passphrase,
        kdf.salt,
        &keyiv,
        kdf.rounds,
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

pub fn decrypt_none(allocator: std.mem.Allocator, private_key_blob: []const u8, _: *const Kdf, _: []const u8) Error![]u8 {
    const out = try allocator.alloc(u8, private_key_blob.len);
    errdefer allocator.free(out);

    @memcpy(out, private_key_blob);

    return out;
}

pub const Checksum = struct {
    value: u64,

    const Self = @This();

    pub inline fn check_checksum(value: u64) bool {
        return @as(u32, @truncate(std.math.shr(u64, value, @bitSizeOf(u32)))) ==
            @as(u32, @truncate(value));
    }

    pub inline fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        const next, const checksum = try enc.rfc4251.parse_int(u64, src);

        // XXX: This is not realy great
        if (!Self.check_checksum(checksum))
            return Error.InvalidChecksum;

        return .{ next, .{ .value = checksum } };
    }
};

pub const Cipher = struct {
    name: []const u8,
    decrypt: *const fn (
        allocator: std.mem.Allocator,
        private_key_blob: []const u8,
        kdf: *const Kdf,
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

    pub inline fn parse(src: []const u8) enc.Error!enc.Cont(Cipher) {
        const next, const name = try enc.rfc4251.parse_string(src);

        inline for (comptime Self.ciphers) |cipher| {
            if (std.mem.eql(u8, name, cipher.name)) {
                return .{ next, cipher };
            }
        }

        return enc.Error.InvalidData;
    }
};

/// "Newer" OpenSSH private key format. Will NOT work with old PKCS #1 or SECG keys.
pub const Pem = struct {
    _prefix: pem.Literal(
        "BEGIN OPENSSH PRIVATE KEY",
        std.mem.TokenIterator(u8, .sequence),
    ),
    der: []const u8,
    _posfix: pem.Literal(
        "END OPENSSH PRIVATE KEY",
        std.mem.TokenIterator(u8, .sequence),
    ),

    const Self = @This();

    pub fn tokenize(src: []const u8) std.mem.TokenIterator(u8, .sequence) {
        return std.mem.tokenizeSequence(u8, src, "-----");
    }

    pub fn parse(src: []const u8) !Self {
        return try pem.parse(Self, src);
    }

    pub fn decode(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) !mem.Managed([]u8) {
        return .{
            .allocator = allocator,
            .data = try pem.decode_with_total_size(
                allocator,
                pem.base64.Decoder,
                self.der,
            ),
        };
    }
};

pub const Kdf = struct {
    salt: []const u8,
    rounds: u32,

    const Self = @This();

    pub inline fn parse(src: []const u8) enc.Error!enc.Cont(Kdf) {
        const next, const kdf = try enc.rfc4251.parse_string(src);

        if (kdf.len == 0)
            // FIXME: We should return an optional here, to do so need to
            // allow the generic parser to support optional types.
            return .{ next, undefined };

        return .{ next, try enc.parse(Self, kdf) };
    }
};

pub fn Sk(comptime Pub: type, comptime Pri: type) type {
    return struct {
        magic: Magic,
        cipher: Cipher,
        kdf_name: []const u8,
        kdf: Kdf, // TODO: Make this optional
        number_of_keys: u32,
        public_key_blob: []const u8,
        private_key_blob: []const u8,

        const Self = @This();

        const Pk = Pub;
        const Sk = MakeSk(Pri);

        fn MakeSk(comptime T: type) type {
            if (std.meta.declarations(T).len != 0)
                @compileError("Cannot flatten structs with declarations (see: #6709)");

            const A = struct { checksum: Checksum };

            const S = struct { comment: []const u8, _pad: enc.Padding };

            const fields = std.meta.fields(A) ++ std.meta.fields(T) ++ std.meta.fields(S);

            const ret: std.builtin.Type.Struct = .{
                .decls = &.{},
                .fields = fields,
                .is_tuple = false,
                .layout = .auto,
            };

            return @Type(@unionInit(std.builtin.Type, "struct", ret));
        }

        pub const Magic = MagicString(enum { @"openssh-key-v1" });

        /// Returns `true` if the `private_key_blob` is encrypted, i.e.,
        /// cipher.name != "none"
        pub inline fn is_encrypted(self: *const Self) bool {
            return !std.mem.eql(u8, self.cipher.name, "none");
        }

        pub fn get_public_key(self: *const Self) !Pk {
            if (!@hasDecl(Pub, "from_bytes"))
                @compileError("Type `Pub` does not declare `from_bytes([]const u8)`");

            return Pub.from_bytes(self.public_key_blob);
        }

        pub fn get_private_key(
            self: *const Self,
            allocator: std.mem.Allocator,
            passphrase: ?[]const u8,
        ) !mem.ManagedSecret(Self.Sk) {
            _ = Self.Sk;
            if (self.is_encrypted() and passphrase == null)
                return error.MissingPassphrase;

            inline for (comptime Cipher.ciphers) |cipher| {
                if (std.mem.eql(u8, cipher.name, self.cipher.name)) {
                    const private_blob = try cipher.decrypt(
                        allocator,
                        self.private_key_blob,
                        &self.kdf,
                        passphrase orelse undefined,
                    );
                    errdefer allocator.free(private_blob);

                    const key = try enc.parse(Self.Sk, private_blob);

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
            return try Self.from(src);
        }

        pub fn from_pem(encoded_pem: Pem) Error!Self {
            return try Self.from(encoded_pem.der);
        }
    };
}

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
    };

    pub const Ecdsa = struct {
        kind: []const u8,
        // Public parts
        curve: []const u8,
        pk: []const u8,
        // Private parts
        sk: []const u8,
    };

    pub const Ed25519 = struct {
        kind: []const u8,
        // Public parts
        pk: []const u8,
        // Private parts
        sk: []const u8,
    };
};

pub const Rsa = Sk(pk.Rsa, wire.Rsa);

pub const Ecdsa = Sk(pk.Ecdsa, wire.Ecdsa);

pub const Ed25519 = Sk(pk.Ed25519, wire.Ed25519);
