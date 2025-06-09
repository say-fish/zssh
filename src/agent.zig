// SPDX-License-Identifier: GPL-3.0-only

//! > [...] Protocol for interacting with an agent that holds private keys.
//! > Clients (and possibly servers) can invoke the agent via this protocol to
//! > perform operations using public and private keys held in the agent.
//!
//! See: https://datatracker.ietf.org/doc/html/draft-ietf-sshm-ssh-agent

const std = @import("std");

const enc = @import("enc.zig");
const meta = @import("meta.zig");
const pk = @import("pk.zig");
const sig = @import("sig.zig");
const sk = @import("sk.zig");

const Cont = enc.Cont;
const Dec = enc.Dec;
const EncSize = enc.EncSize;
const Error = @import("error.zig").Error;
const ForAll = meta.ForAll;
const Is = meta.Is;

fn static_encode(comptime T: type, comptime value: EncSize(T)) [value.encoded_size()]u8 {
    var arr = comptime std.BoundedArray(u8, value.encoded_size()).init(0) catch |err|
        @compileError(@errorName(err));

    value.serialize(arr.writer().any()) catch |err|
        @compileError(@errorName(err));

    return arr.buffer;
}

pub fn msg_from_bytes(comptime T: type, src: []const u8) Error!T {
    if (src.len < @sizeOf(u32))
        return Error.MessageTooShort;

    const msg_len = std.mem.readInt(u32, src[0..@sizeOf(u32)], .big);

    if (msg_len + @sizeOf(u32) != src.len)
        return Error.MsgLenMismatch;

    const decoded_len, const msg =
        try decode(T, src[@sizeOf(u32) .. @sizeOf(u32) + msg_len]);

    std.debug.assert(decoded_len == msg_len);

    return msg;
}

// TODO: 3.8.1. Query extension
pub fn MakeAgent(
    comptime Pk: type,
    comptime Sig: type,
    comptime ExtensionResponse: type,
) type {
    return union(enum(u8)) {
        /// The agent may reply with Failure for requests with unknown types or
        /// requests that failed.
        ///
        /// Protocol number: SSH_AGENT_FAILURE = 5,
        failure = 5,

        /// On success the agent may reply with or a request-specific success
        /// message.
        ///
        /// Protocol number: SSH_AGENT_SUCCESS = 6,
        success = 6,

        /// The agent shall reply with IdentitiesAnswer for RequestIdentities
        ///
        /// Protocol number: SSH_AGENT_IDENTITIES_ANSWER = 12,
        identities_answer: IdentitiesAnswer = 12,

        /// The signature format is specific to the algorithm of the key type in
        /// use. SSH protocol signature formats are defined in sig.Rrf4253 for
        /// "ssh-rsa", in sig.Rfc5656 for "ecdsa-sha2-*" keys and in sig.Rfc8709
        /// for "ssh-ed25519" and "ssh-ed448" keys.
        ///
        /// Protocol number: SSH_AGENT_SIGN_RESPONSE = 14,
        sign_response: SignResponse(Sig) = 14,

        /// The agent may reply with Failure for requests with unknown types or
        /// requests that failed.
        ///
        /// Protocol number: SSH_AGENT_EXTENSION_FAILURE = 28,
        extension_failure = 28,

        /// The contents of successful extension reply messages are specific to the
        /// extension type. Extension requests may return Success on success or the
        /// extension-specific response message.
        ///
        /// Protocl number: SSH_AGENT_EXTENSION_RESPONSE = 29,
        extension_response: Dec(ExtensionResponse) = 29,

        const Self = @This();

        pub const failure_encoded = static_encode(Self, .init(.failure, {}));
        pub const success_encoded = static_encode(Self, .init(.success, {}));
        pub const empty_identities_answer_encoded =
            static_encode(Self, .init(.identities_answer, .empty));
        pub const extension_failure_encoded =
            static_encode(Self, .init(.extension_failure, {}));

        pub const IdentitiesAnswer = MakeIdentitiesAnswer(Pk);

        pub const Query = struct {
            extensions: []const u8,

            pub fn parse(_: []const u8) Error!enc.Cont(Query) {
                return .{ 0, .{ .extensions = &.{} } };
            }
        };

        pub fn init(
            comptime tag: std.meta.Tag(Self),
            value: @FieldType(Self, @tagName(tag)),
        ) Self {
            return @unionInit(Self, @tagName(tag), value);
        }

        pub fn from_bytes(src: []const u8) Error!Self {
            return try msg_from_bytes(Self, src);
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            try enc.serialize_union(Self, writer, self);
        }

        pub fn encoded_size(self: *const Self) u32 {
            return switch (self.*) {
                inline else => |e| enc.encoded_size(@TypeOf(e), e),
            } + @sizeOf(u32) + @sizeOf(u8); // FIXME: Get the tag size since the tag could be encoded as a string
        }
    };
}

pub fn MakeIdentitiesAnswer(comptime Pk: type) type {
    return struct {
        nkeys: u32,
        keys: ?[]const u8,

        const Self = @This();

        pub const empty: Self = .{ .nkeys = 0, .keys = null };
        pub const empty_encoded: []const u8 = &static_encode(Self, .empty);

        pub const Identity = MakeIdentity(Pk);
        pub const Iterator = enc.MakeIterator(MakeIdentity(Pk));

        pub fn iter(self: *const Self) ?Iterator {
            return if (self.keys) |keys| .{ .ref = keys } else null;
        }

        pub fn parse(src: []const u8) Error!Cont(Self) {
            // No keys is explicit zero
            const next, const nkeys = try enc.rfc4251.parse_int(u32, src);

            return .{ src.len, .{
                .nkeys = nkeys,
                .keys = if (nkeys != 0) src[next..] else null,
            } };
        }

        pub fn encoded_size(self: *const Self) u32 {
            return @sizeOf(u32) + if (self.keys) |keys| @as(u32, @intCast(keys.len)) else @sizeOf(u8);
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            try enc.serialize_any(u32, writer, self.nkeys);

            if (self.keys) |keys| {
                _ = try writer.write(keys);
            } else {
                try enc.serialize_any(u8, writer, 0);
            }
        }

        pub fn is_empty(self: *const Self) bool {
            return self.nkeys == 0;
        }
    };
}

pub fn SignResponse(comptime Sig: type) type {
    return struct {
        signature: Is(.@"union", Sig),

        const Self = @This();

        pub fn init(
            comptime tag: std.meta.Tag(Sig),
            value: std.meta.TagPayload(Sig, tag),
        ) Self {
            return .{ .signature = @unionInit(Sig, @tagName(tag), value) };
        }

        pub fn parse(src: []const u8) Error!enc.Cont(Self) {
            return try enc.parse_with_cont(Self, src);
        }

        pub fn encoded_size(self: *const Self) u32 {
            return self.signature.encoded_size() + @sizeOf(u32); // XXX: Cleanup
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            const enc_size = self.signature.encoded_size(); 

            try enc.serialize_any(u32, writer, enc_size);

            try self.signature.serialize(writer);
        }
    };
}

pub fn MakeClient(
    comptime Pk: type, // A tagged union of all possible public key types
    comptime Sk: type, // A tagged union of all possible private key types
    comptime Ext: type,
    comptime ConstraintExt: type,
) type {
    return union(enum(u8)) {
        /// A client may request a list of keys from an agent using
        /// RequestIdentities.
        ///
        /// Protocol number: SSH_AGENTC_REQUEST_IDENTITIES = 11
        request_identities = 11,

        /// A client may request the agent perform a private key signature operation
        /// using SignRequest
        ///
        /// Protocol number: SSH_AGENTC_SIGN_REQUEST = 13
        sign_request: SignRequest = 13,

        /// Keys may be added to the agent using AddIdentiy.
        ///
        /// Protocol number: SSH_AGENTC_ADD_IDENTITY = 17
        add_identity: AddIdentity(Sk) = 17,

        /// A client may request for specific keys to be removed.
        ///
        /// Protocol number: SSH_AGENTC_REMOVE_IDENTITY = 18
        remove_identity: RemoveIdentity(Pk) = 18,

        /// A client may request that an agent remove all keys that it stores.
        ///
        /// Protocol number: SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19
        remove_all_identities = 19,

        /// Protocol number: SSH_AGENTC_ADD_SMARTCARD_KEY = 20
        add_smartcard_key: AddSmartCardKey = 20,

        /// Protocol number: SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21
        remove_smartcard_key: RemoveSmartcardKey = 21,

        /// The agent protocol supports requesting that an agent temporarily lock
        /// itself with a pass-phrase. When locked an agent should suspend
        /// processing of sensitive operations (private key signature operations at
        /// the very least) until it has been unlocked with the same pass-phrase.
        ///
        /// Protocol number: SSH_AGENTC_LOCK = 22
        lock: Lock = 22,

        /// Requests unlocking an agent.
        ///
        /// Protocol number: SSH_AGENTC_UNLOCK = 23
        unlock: Unlock = 23,

        /// Allows adding keys with optional constraints on their usage.
        ///
        /// Protocol number: SSH_AGENTC_ADD_ID_CONSTRAINED = 25
        add_id_constrained: AddIdConstrained(Sk, Constraints) = 25,

        /// Allows adding keys with optional constraints on their usage.
        ///
        /// Protocol number: SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26
        add_smartcard_key_constrained: AddSmartCardKeyConstrained(
            Sk,
            Constraints,
        ) = 26,

        /// The agent protocol includes an optional extension mechanism that allows
        /// vendor-specific and experimental messages to be sent via the agent
        /// protocol.
        ///
        /// Protocol number: SSH_AGENTC_EXTENSION = 27
        extension: Extension = 27,

        const Self = @This();

        pub const SignRequest = MakeSignRequest(Pk);
        pub const Constraints = MakeConstraints(ConstraintExt);
        pub const Extension = Ext;
        pub const Query = struct {
            pub fn parse(_: []const u8) Error!Cont(Query) {
                return .{ 0, .{} };
            }

            pub fn encoded_size(_: *const Query) u32 {
                @panic("TODO");
            }
        };

        pub const request_identities_encoded =
            static_encode(Self, .init(.request_identities, {}));
        pub const remove_all_identities_encoded =
            static_encode(
                Self,
                .init(.remove_all_identities, {}),
            );

        pub fn init(
            comptime tag: std.meta.Tag(Self),
            value: @FieldType(Self, @tagName(tag)),
        ) Self {
            return @unionInit(Self, @tagName(tag), value);
        }

        pub fn from_bytes(src: []const u8) !@This() {
            return try msg_from_bytes(@This(), src);
        }

        pub fn from_slice(src: []const u8) !@This() {
            _, const msg = try decode(@This(), src);
            return msg;
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            try enc.serialize_union(Self, writer, self);
        }

        pub fn encoded_size(self: *const Self) u32 {
            return switch (self.*) {
                inline else => |e| enc.encoded_size(@TypeOf(e), e),
            } + @sizeOf(u32) + @sizeOf(u8); // FIXME: Get the tag size since the tag could be encoded as a string
        }
    };
}

/// TODO: data
pub fn MakeSignRequest(comptime Pk: type) type {
    return struct {
        key: Is(.@"union", Pk),
        data: []const u8,
        flags: u32,

        const Self = @This();

        pub const Flags = enum(u32) {
            SSH_AGENT_RSA_SHA2_256 = 2,
            SSH_AGENT_RSA_SHA2_512 = 4,

            pub fn init(in: u32) !Flags {
                if (in != 2 and in != 4) {
                    return Error.InvalidRsaSignatureFlag;
                }

                return @enumFromInt(in);
            }
        };

        pub fn parse(src: []const u8) Error!enc.Cont(Self) {
            return try enc.parse_with_cont(Self, src);
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            _ = self;
            _ = writer;
            @panic("TODO");
        }

        pub fn encoded_size(self: *const Self) u32 {
            _ = self;
            @panic("TODO");
        }
    };
}

pub fn MakeIdentity(comptime Key: type) type {
    return struct {
        key: Is(.@"union", Key),
        comment: []const u8,

        const Self = @This();

        pub fn parse(src: []const u8) Error!enc.Cont(Self) {
            return try enc.parse_with_cont(Self, src);
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            const key_len = self.key.encoded_size();

            try enc.serialize_any(u32, writer, key_len);
            try self.key.serialize(writer);
            try enc.serialize_any([]const u8, writer, self.comment);

            // try enc.serialize_struct(Self, writer, self);
        }

        pub fn encoded_size(self: *const Self) u32 {
            return enc.encoded_size_struct(Self, self);
        }
    };
}

pub fn AddIdentity(comptime Sk: type) type {
    return MakeIdentity(Sk);
}

pub fn RemoveIdentity(comptime Pk: type) type {
    return struct {
        key: Is(.@"union", Pk),

        const Self = @This();

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try enc.parse_with_cont(Self, src);
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            _ = self;
            _ = writer;
            @panic("TODO");
        }

        pub fn encoded_size(self: *const Self) u32 {
            _ = self;
            @panic("TODO");
        }
    };
}

pub const RemoveSmartcardKey = struct {
    /// opaque identifier for the smartcard reader
    reader_id: []const u8,
    PIN: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) Error!Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        _ = self;
        _ = writer;
        @panic("TODO");
    }

    pub fn encoded_size(self: *const Self) u32 {
        _ = self;
        @panic("TODO");
    }
};

pub const AddSmartCardKey = struct {
    id: []const u8,
    pin: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) Error!Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        _ = self;
        _ = writer;
        @panic("TODO");
    }

    pub fn encoded_size(self: *const Self) u32 {
        _ = self;
        @panic("TODO");
    }
};

pub const Lock = struct {
    passphrase: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) Error!Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        _ = self;
        _ = writer;
        @panic("TODO");
    }

    pub fn encoded_size(self: *const Self) u32 {
        _ = self;
        @panic("TODO");
    }
};

pub const Unlock = struct {
    passphrase: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) Error!Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }

    pub fn serialize(
        self: *const Self,
        writer: std.io.AnyWriter,
    ) anyerror!void {
        _ = self;
        _ = writer;
        @panic("TODO");
    }

    pub fn encoded_size(self: *const Self) u32 {
        _ = self;
        @panic("TODO");
    }
};

pub fn MakeConstraint(comptime Extension: type) type {
    return union(enum(u8)) {
        lifetime: Lifetime = 1,
        confirm: Confirm = 2,
        max_signatures: MaxSignatures = 3,
        extension: Is(.@"union", Extension) = 255,

        const Self = @This();

        pub const Lifetime = struct {
            sec: u32,

            pub fn parse(src: []const u8) Error!Cont(Lifetime) {
                return try enc.parse_with_cont(Lifetime, src);
            }
        };

        pub const Confirm = struct {
            pub fn parse(src: []const u8) Error!Cont(Confirm) {
                std.debug.assert(src.len == 0);

                return .{ 0, .{} };
            }
        };

        /// This key constraint allows communication to an agent of the
        /// maximum number of signatures that may be made with an XMSS key.
        pub const MaxSignatures = struct {
            max: u32,

            pub fn parse(src: []const u8) Error!Cont(MaxSignatures) {
                return try enc.parse_with_cont(MaxSignatures, src);
            }
        };

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try decode(Self, src);
        }
    };
}

pub fn MakeConstraints(comptime Extension: type) type {
    return struct {
        ref: []const u8,

        const Self = @This();

        pub const Constraint = MakeConstraint(Extension);
        pub const Iterator = enc.MakeIterator(Constraint);

        pub fn iter(self: *const Self) Iterator {
            return .{ .ref = self.ref };
        }

        pub fn parse(src: []const u8) Error!enc.Cont(Self) {
            // TODO: Check for null
            return .{ src.len, .{ .ref = src } };
        }
    };
}

pub fn AddIdConstrained(comptime Sk: type, comptime Constraints: type) type {
    return struct {
        key: Is(.@"union", Sk),
        comment: []const u8,
        constraints: Constraints,

        const Self = @This();

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try enc.parse_with_cont(Self, src);
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            _ = self;
            _ = writer;
            @panic("TODO");
        }

        pub fn encoded_size(self: *const Self) u32 {
            _ = self;
            @panic("TODO");
        }
    };
}

pub fn AddSmartCardKeyConstrained(
    comptime Sk: type,
    comptime Constraints: type,
) type {
    return struct {
        key: Is(.@"union", Sk),
        pin: []const u8,
        constraint: Constraints,

        const Self = @This();

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try enc.parse_with_cont(Self, src);
        }

        pub fn serialize(
            self: *const Self,
            writer: std.io.AnyWriter,
        ) anyerror!void {
            _ = self;
            _ = writer;
            @panic("TODO");
        }

        pub fn encoded_size(self: *const Self) u32 {
            _ = self;
            @panic("TODO");
        }
    };
}

pub fn decode_as_string(comptime T: type, src: []const u8) Error!enc.Cont(T) {
    const Tag = comptime std.meta.Tag(T);

    const next, const kind = try enc.rfc4251.parse_string(src);

    const e = std.meta.stringToEnum(Tag, kind) orelse
        return error.InvalidData;

    @setEvalBranchQuota(5000);

    inline for (comptime std.meta.fields(T)) |field| {
        if (e == comptime std.meta.stringToEnum(Tag, field.name).?) {
            const final, const msg = if (comptime field.type != void)
                try field.type.parse(src[next..])
            else
                .{ 0, {} };

            return .{ next + final, @unionInit(T, field.name, msg) };
        }
    }

    // On all other cases we WILL fail on `intToEnum` but zig cannot prove that
    // this invariant holds.
    // comptime unreachable;
    unreachable;
}

// TODO: Move this to enc (with a decode tag)
pub fn decode(comptime T: type, src: []const u8) Error!Cont(ForAll(Dec, T)) {
    const Tag = comptime std.meta.Tag(T);

    const next, const kind = try enc.rfc4251.parse_int(u8, src);

    const e = std.meta.intToEnum(Tag, kind) catch
        return error.InvalidData;

    @setEvalBranchQuota(5000);

    inline for (comptime std.meta.fields(T)) |field| {
        if (e == comptime std.meta.stringToEnum(Tag, field.name).?) {
            const final, const msg = if (comptime field.type != void)
                try field.type.parse(src[next..])
            else
                .{ 0, {} };

            return .{ next + final, @unionInit(T, field.name, msg) };
        }
    }

    // On all other cases we WILL fail on `intToEnum` but zig cannot prove that
    // this invariant holds.
    // comptime unreachable;
    unreachable;
}
