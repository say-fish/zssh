// SPDX-License-Identifier: GPL-3.0-only

//! > [...] Protocol for interacting with an agent that holds private keys.
//! > Clients (and possibly servers) can invoke the agent via this protocol to
//! > perform operations using public and private keys held in the agent.
//!
//! See: https://datatracker.ietf.org/doc/html/draft-ietf-sshm-ssh-agent

const std = @import("std");

const pk = @import("pk.zig");
const sk = @import("sk.zig");

const enc = @import("enc.zig");
const sig = @import("sig.zig");

const meta = @import("meta.zig");

const Dec = enc.Dec;
const Cont = enc.Cont;
const Union = meta.Union;

const Error = @import("error.zig").Error;

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

pub const Query = struct {
    extensions: []const u8,

    pub fn parse(_: []const u8) Error!enc.Cont(Query) {
        return .{ 0, .{ .extensions = &.{} } };
    }
};

// TODO: 3.2.7. Key Constraints
// SSH_AGENT_CONSTRAIN_LIFETIME                    1
// SSH_AGENT_CONSTRAIN_CONFIRM                     2
// SSH_AGENT_CONSTRAIN_EXTENSION                   255

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
        identities_answer: IdentitiesAnswer(Pk) = 12,

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

        pub fn from_bytes(src: []const u8) !@This() {
            return try msg_from_bytes(@This(), src);
        }
    };
}

pub fn IdentitiesAnswer(comptime Pk: type) type {
    return struct {
        nkeys: u32,
        keys: ?[]const u8,

        const Self = @This();

        pub const Iterator = enc.GenericIterator(AddIdentity(Pk));

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
    };
}

pub fn SignResponse(comptime Sig: type) type {
    return struct {
        signature: Union(Sig),

        const Self = @This();

        pub fn parse(src: []const u8) Error!enc.Cont(Self) {
            return try enc.parse_with_cont(Self, src);
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
        sign_request: SignRequest(Pk) = 13,

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

        pub const Constraints = MakeConstraints(ConstraintExt);
        pub const Extension = Ext;

        pub fn from_bytes(src: []const u8) !@This() {
            return try msg_from_bytes(@This(), src);
        }
    };
}

/// TODO: data
pub fn SignRequest(comptime Pk: type) type {
    return struct {
        key: Union(Pk),
        data: []const u8,
        flags: u32,

        const Self = @This();

        pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
        pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

        pub fn parse(src: []const u8) Error!enc.Cont(Self) {
            return try enc.parse_with_cont(Self, src);
        }
    };
}

pub fn AddIdentity(comptime Sk: type) type {
    return struct {
        key: Union(Sk),
        comment: []const u8,

        const Self = @This();

        pub fn parse(src: []const u8) Error!enc.Cont(Self) {
            return try enc.parse_with_cont(Self, src);
        }
    };
}

pub fn RemoveIdentity(comptime Pk: type) type {
    return struct {
        key: Union(Pk),

        const Self = @This();

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try enc.parse_with_cont(Self, src);
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
};

pub const AddSmartCardKey = struct {
    id: []const u8,
    pin: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) Error!Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }
};

pub const Lock = struct {
    passphrase: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) Error!Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }
};

pub const Unlock = struct {
    passphrase: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) Error!Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }
};

pub fn MakeConstraint(comptime Extension: type) type {
    return union(enum(u8)) {
        lifetime: Lifetime = 1,
        confirm: Confirm = 2,
        extension: Union(Extension) = 255,

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
        pub const Iterator = enc.GenericIterator(Constraint);

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
        key: Union(Sk),
        comment: []const u8,
        constraints: Constraints,

        const Self = @This();

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try enc.parse_with_cont(Self, src);
        }
    };
}

pub fn AddSmartCardKeyConstrained(
    comptime Sk: type,
    comptime Constraints: type,
) type {
    return struct {
        key: Union(Sk),
        pin: []const u8,
        constraint: Constraints,

        const Self = @This();

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try enc.parse_with_cont(Self, src);
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
            const final, const msg = if (comptime field.type != void) field.type.parse(src[next..]) catch
                return error.InvalidData else .{ 0, {} };

            return .{ next + final, @unionInit(T, field.name, msg) };
        }
    }

    // On all other cases we WILL fail on `intToEnum` but zig cannot prove that
    // this invariant holds.
    // comptime unreachable;
    unreachable;
}

// TODO: Move this to enc (with a decode tag)
pub fn decode(comptime T: type, src: []const u8) Error!enc.Cont(T) {
    const Tag = comptime std.meta.Tag(T);

    // @compileLog(Tag);

    const next, const kind = try enc.rfc4251.parse_int(u8, src);

    const e = std.meta.intToEnum(Tag, kind) catch
        return error.InvalidData;

    @setEvalBranchQuota(5000);

    inline for (comptime std.meta.fields(T)) |field| {
        if (e == comptime std.meta.stringToEnum(Tag, field.name).?) {
            const final, const msg = if (comptime field.type != void) field.type.parse(src[next..]) catch
                return error.InvalidData else .{ 0, {} };

            return .{ next + final, @unionInit(T, field.name, msg) };
        }
    }

    // On all other cases we WILL fail on `intToEnum` but zig cannot prove that
    // this invariant holds.
    // comptime unreachable;
    unreachable;
}
