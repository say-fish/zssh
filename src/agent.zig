//! > [...] Protocol for interacting with an agent that holds private keys.
//! > Clients (and possibly servers) can invoke the agent via this protocol to
//! > perform operations using public and private keys held in the agent.
//!
//! See: https://datatracker.ietf.org/doc/html/draft-ietf-sshm-ssh-agent
//!      https://datatracker.ietf.org/doc/html/draft-ietf-sshm-ssh-agent#name-security-considerations

const std = @import("std");

const pk = @import("pk.zig");
const sk = @import("sk.zig");

const enc = @import("enc.zig");
const sig = @import("sig.zig");

fn msg_from_bytes(comptime T: type, src: []const u8) !T {
    if (src.len < @sizeOf(u32))
        return error.MessageTooShort;

    const msg_len = std.mem.readInt(u32, src[0..@sizeOf(u32)], .big);

    if (msg_len + @sizeOf(u32) != src.len)
        return error.MsgLenMismatch;

    const decoded_len, const msg =
        try decode(T, src[@sizeOf(u32) .. @sizeOf(u32) + msg_len]);

    std.debug.assert(decoded_len == msg_len);

    return msg;
}

// TODO: 3.2.7. Key Constraints
// SSH_AGENT_CONSTRAIN_LIFETIME                    1
// SSH_AGENT_CONSTRAIN_CONFIRM                     2
// SSH_AGENT_CONSTRAIN_EXTENSION                   255

// TODO: 3.8.1. Query extension
pub const Agent = union(enum(u8)) {
    /// SSH_AGENT_FAILURE = 5,
    failure: Failure = 5,
    /// SSH_AGENT_SUCCESS = 6,
    success: Success = 6,
    /// SSH_AGENT_IDENTITIES_ANSWER = 12,
    identities_answer: IdentitiesAnswer = 12,
    /// SSH_AGENT_SIGN_RESPONSE = 14,
    sign_response: SignResponse = 14,
    /// SSH_AGENT_EXTENSION_FAILURE = 28,
    extension_failure: ExtensionFailure = 28,
    /// SSH_AGENT_EXTENSION_RESPONSE = 29,
    extension_response: Extension = 29,

    const Self = @This();

    pub fn from_bytes(src: []const u8) !Self {
        return try msg_from_bytes(Self, src);
    }
};

pub const Client = union(enum(u8)) {
    /// SSH_AGENTC_REQUEST_IDENTITIES = 11
    request_identities: RequestIdentities = 11,
    /// SSH_AGENTC_SIGN_REQUEST = 13
    sign_request: SignRequest = 13,
    /// SSH_AGENTC_ADD_IDENTITY = 17
    add_identity: AddIdentity = 17,
    /// SSH_AGENTC_REMOVE_IDENTITY = 18
    remove_identity: RemoveIdentity = 18,
    /// SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19
    remove_all_identities: RemoveAllIdentities = 19,
    /// SSH_AGENTC_ADD_SMARTCARD_KEY = 20
    add_smartcard_key: AddSmartCardKey = 20,
    /// SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21
    remove_smartcard_key: RemoveSmartcardKey = 21,
    /// SSH_AGENTC_LOCK = 22
    lock: Lock = 22,
    /// SSH_AGENTC_UNLOCK = 23
    unlock: Unlock = 23,
    /// SSH_AGENTC_ADD_ID_CONSTRAINED = 25
    add_id_constrained: AddIdConstrained = 25,
    /// SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26
    add_smartcard_key_constrained: AddIdConstrained = 26,
    /// SSH_AGENTC_EXTENSION = 27
    extension: Extension = 27,

    const Self = @This();

    pub fn from_bytes(src: []const u8) !Self {
        return try msg_from_bytes(Self, src);
    }
};

/// OpenSSH's extensions to the agent protocol.
const openssh_extensions = struct {
    const Agent = union(enum) {
        /// This extension allows a ssh client to bind an agent connection to a
        /// particular SSH session identifier as derived from the initial key
        /// exchange (as per RFC4253 section 7.2) and the host key used for that
        /// exchange. This binding is verifiable at the agent by including the
        /// initial KEX signature made by the host key.
        session_bind: SessionBind,

        const SessionBind = struct {};
    };

    const Constraints = union(enum) {
        /// This key constraint extension supports destination- and forwarding path-
        /// restricted keys. It may be attached as a constraint when keys or
        /// smartcard keys are added to an agent.
        restrict_destination: RestrictDestination,

        /// This key constraint allows communication to an agent of the maximum
        /// number of signatures that may be made with an XMSS key.
        max_signatures: MaxSignatures,

        /// This key constraint extension allows certificates to be associated
        /// with private keys as they are loaded from a PKCS#11 token.
        associated_certs: AssociatedCerts,

        const Self = @This();

        const RestrictDestination = struct {};
        const MaxSignatures = struct {};
        const AssociatedCerts = struct {};

        pub fn parse(_: []const u8) enc.Error!enc.Cont(Self) {
            @panic("TODO:");
            //return enc.parse(Constraints, src);
        }
    };
};

pub const Sk = union(enum) {
    rsa: sk.wire.Rsa,
    ecdsa: sk.wire.Ecdsa,
    ed25519: sk.wire.Ed25519,

    const Self = @This();

    const Magic = pk.Pk.Magic;

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        const magic = Magic.from_bytes(src) catch return error.InvalidData;

        switch (magic.value) {
            .@"ssh-rsa",
            => {
                const next, const key =
                    try enc.parse_with_cont(sk.wire.Rsa, src);

                return .{ next, .{ .rsa = key } };
            },

            .@"ecdsa-sha2-nistp256",
            .@"ecdsa-sha2-nistp384",
            .@"ecdsa-sha2-nistp521",
            => {
                const next, const key =
                    try enc.parse_with_cont(sk.wire.Ecdsa, src);

                return .{ next, .{ .ecdsa = key } };
            },

            .@"ssh-ed25519",
            => {
                const next, const key =
                    try enc.parse_with_cont(sk.wire.Ed25519, src);

                return .{ next, .{ .ed25519 = key } };
            },
        }
    }
};

// TODO: Move this to enc
pub fn decode(comptime T: type, src: []const u8) enc.Error!enc.Cont(T) {
    const Tag = comptime std.meta.Tag(T);

    // @compileLog(Tag);

    const next, const kind = try enc.rfc4251.parse_int(u8, src);

    const e = std.meta.intToEnum(Tag, kind) catch
        return error.InvalidData;

    @setEvalBranchQuota(5000);

    inline for (comptime std.meta.fields(T)) |field| {
        if (e == comptime std.meta.stringToEnum(Tag, field.name).?) {
            const final, const msg = field.type.parse(src[next..]) catch return error.InvalidData;
            return .{ next + final, @unionInit(T, field.name, msg) };
        }
    }

    // On all other cases we WILL fail on `intToEnum` but zig cannot prove that
    // this invariant holds.
    // comptime unreachable;
    unreachable;
}

const ExtensionFailure = struct {
    const Self = @This();

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        std.debug.assert(src.len == 0);

        return .{ 0, .{} };
    }
};

const Failure = struct {
    const Self = @This();

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        std.debug.assert(src.len == 0);

        return .{ 0, .{} };
    }
};

const Success = struct {
    const Self = @This();

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        std.debug.assert(src.len == 0);

        return .{ 0, .{} };
    }
};

const RequestIdentities = struct {
    const Self = @This();

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        std.debug.assert(src.len == 0);

        return .{ 0, .{} };
    }
};

const AddIdentity = struct {
    key: Sk, // TODO:
    comment: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }
};

pub const AddIdConstrained = struct {
    key: Sk, // TODO:
    comment: []const u8,
    constraints: Constraints,

    const Self = @This();

    pub const Constraints = struct {
        ref: []const u8,

        pub fn parse(src: []const u8) enc.Error!enc.Cont(Constraints) {
            // TODO: Check for null
            return try .{ src.len, .{ .ref = src } };
        }

        pub const Iterator = enc.GenericIterator(Constraint);

        pub fn iter(self: *const Constraints) Iterator {
            return .{ .ref = self.ref };
        }
    };

    pub const Constraint = union(enum(u8)) {
        lifetime: Lifetime = 1,
        confirm: Confirm = 2,
        extension: openssh_extensions.Constraints = 255,

        pub fn parse(src: []const u8) enc.Error!enc.Cont(Constraint) {
            return try decode(Constraint, src);
        }
    };

    pub const Lifetime = struct {
        sec: u32,

        pub fn parse(src: []const u8) enc.Error!enc.Cont(Lifetime) {
            return try enc.parse_with_cont(Lifetime, src);
        }
    };

    pub const Confirm = struct {
        pub fn parse(src: []const u8) enc.Error!enc.Cont(Confirm) {
            std.debug.assert(src.len == 0);

            return .{ 0, .{} };
        }
    };

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }
};

pub const AddSmartCardKey = struct {
    id: []const u8,
    pin: []const u8,

    const Self = @This();

    pub fn parse(_: []const u8) enc.Error!enc.Cont(Self) {
        @panic("TODO: AddSmartCardKey is not implemented");
    }
};

pub const AddSmartCardKeyConstrained = struct {
    id: []const u8,
    pin: []const u8,
    constraint: []const u8, // TODO: Type

    const Self = @This();

    pub fn parse(_: []const u8) enc.Error!enc.Cont(Self) {
        @panic("TODO: AddSmartCardKeyConstrained is not implemented");
    }
};

pub const RemoveIdentity = struct {
    key: pk.Pk,

    const Self = @This();

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }
};

pub const RemoveAllIdentities = struct {
    const Self = @This();

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        std.debug.assert(src.len == 0);

        return .{ 0, .{} };
    }
};

pub const RemoveSmartcardKey = struct {
    /// opaque identifier for the smartcard reader
    reader_id: []const u8,
    PIN: []const u8,

    const Self = @This();

    pub fn parse(_: []const u8) enc.Error!enc.Cont(Self) {
        @panic("TODO: RemoveSmartcardKey is not implemented");
    }
};

pub const IdentitiesAnswer = struct {
    nkeys: u32,
    keys: ?[]const u8,

    const Self = @This();

    pub const Pk = struct {
        key: pk.Pk,
        comment: []const u8,

        pub fn parse(src: []const u8) enc.Error!enc.Cont(Pk) {
            return try enc.parse_with_cont(Pk, src);
        }
    };

    pub const Iterator = enc.GenericIterator(Pk);

    pub fn iter(self: *const Self) ?Iterator {
        return if (self.keys) |keys| .{ .ref = keys } else null;
    }

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        // No keys is explicit zero
        const next, const nkeys = try enc.rfc4251.parse_int(u32, src);

        return .{ src.len, .{
            .nkeys = nkeys,
            .keys = if (nkeys != 0) src[next..] else null,
        } };
    }
};

const SignRequest = struct {
    key: pk.Pk,
    data: []const u8,
    flags: u32,

    const Self = @This();

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }

    // TODO: 3.6.1. Signature flags
    // SSH_AGENT_RSA_SHA2_256                          2
    // SSH_AGENT_RSA_SHA2_512                          4
};

const SignResponse = struct {
    signature: sig.Sig,

    const Self = @This();

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }
};

const Lock = struct {
    passphrase: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }
};

const Unlock = struct {
    passphrase: []const u8,

    const Self = @This();

    pub fn parse(src: []const u8) enc.Error!enc.Cont(Self) {
        return try enc.parse_with_cont(Self, src);
    }
};

const Extension = struct {
    extension_type: []const u8,
    contents: []const u8,

    const Self = @This();

    pub fn parse(_: []const u8) enc.Error!enc.Cont(Self) {
        @panic("TODO: Extension is not implemented");
    }
};
