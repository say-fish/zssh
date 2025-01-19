//! > [...] Protocol for interacting with an agent that holds private keys.
//! > Clients (and possibly servers) can invoke the agent via this protocol to
//! > perform operations using public and private keys held in the agent.
//!
//! See: https://datatracker.ietf.org/doc/html/draft-ietf-sshm-ssh-agent
//!      https://datatracker.ietf.org/doc/html/draft-ietf-sshm-ssh-agent#name-security-considerations

const std = @import("std");

const pk = @import("pk.zig");
const enc = @import("enc.zig");

// TODO: 3.2.7. Key Constraints
// SSH_AGENT_CONSTRAIN_LIFETIME                    1
// SSH_AGENT_CONSTRAIN_CONFIRM                     2
// SSH_AGENT_CONSTRAIN_EXTENSION                   255
//
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
};

pub const Client = union(enum(u8)) {
    /// SSH_AGENTC_REQUEST_IDENTITIES = 11
    request_identities: RequestIdentities = 11,
    /// SSH_AGENTC_SIGN_REQUEST = 13
    sign_request: SignRequest = 13,
    /// SSH_AGENTC_ADD_IDENTITY = 17
    add_idntity: AddIdentity = 17,
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
};

pub fn decode(comptime K: type, src: []const u8) !K {
    const Tag = std.meta.Tag(K);

    const next, const kind = try enc.rfc4251.parse_int(u8, src);

    @setEvalBranchQuota(5000);

    inline for (comptime std.meta.fields(K)) |field| {
        const e = std.meta.intToEnum(Tag, kind) catch
            return error.InvalidMsgType;

        if (e == comptime std.meta.stringToEnum(Tag, field.name).?) {
            return @unionInit(K, field.name, field.type.from_bytes(src[next..]));
        }
    }

    unreachable;
}

const ExtensionFailure = struct {
    const Self = @This();

    pub fn from_bytes(src: []const u8) Self {
        std.debug.assert(src.len == 0);

        return .{};
    }
};

const Failure = struct {
    const Self = @This();

    pub fn from_bytes(src: []const u8) Self {
        std.debug.assert(src.len == 0);

        return .{};
    }
};

const Success = struct {
    const Self = @This();

    pub fn from_bytes(src: []const u8) Self {
        std.debug.assert(src.len == 0);

        return .{};
    }
};

const RequestIdentities = struct {
    const Self = @This();

    pub fn from_bytes(src: []const u8) Self {
        std.debug.assert(src.len == 0);

        return .{};
    }
};

const AddIdentity = struct {
    key: []const u8, // TODO:
    comment: []const u8,

    const Self = @This();

    pub fn from_bytes(_: []const u8) Self {
        return undefined;
    }
};

const AddIdConstrained = struct {
    key: []const u8, // TODO:
    comment: []const u8,
    constraint: []const u8, // TODO: Type

    const Self = @This();

    fn from_bytes(_: []const u8) Self {
        return undefined;
    }
};

const AddSmartCardKey = struct {
    id: []const u8,
    pin: []const u8,

    const Self = @This();

    fn from_bytes(_: []const u8) Self {
        return undefined;
    }
};

const AddSmartCardKeyConstrained = struct {
    id: []const u8,
    pin: []const u8,
    constraint: []const u8, // TODO: Type
};

const RemoveIdentity = struct {
    key: pk.Pk,

    const Self = @This();

    fn from_bytes(_: []const u8) Self {
        return undefined;
    }
};

const RemoveAllIdentities = struct {
    const Self = @This();

    pub fn from_bytes(src: []const u8) Self {
        std.debug.assert(src.len == 0);

        return .{};
    }
};

const RemoveSmartcardKey = struct {
    /// opaque identifier for the smartcard reader
    reader_id: []const u8,
    PIN: []const u8,

    const Self = @This();

    pub fn from_bytes(_: []const u8) Self {
        return undefined;
    }
};

const IdentitiesAnswer = struct {
    nkeys: u32,

    const Self = @This();

    pub fn from_bytes(_: []const u8) Self {
        return undefined;
    }

    // Where "nkeys" indicates the number of keys to follow. Following the preamble are zero or more keys, each encoded as:
    //
    //     string           key blob
    //     string           comment
    //
};

const SignRequest = struct {
    key: pk.Pk,
    data: []const u8,
    flags: u32,

    const Self = @This();

    pub fn from_bytes(_: []const u8) Self {
        return undefined;
    }

    // TODO: 3.6.1. Signature flags
    // SSH_AGENT_RSA_SHA2_256                          2
    // SSH_AGENT_RSA_SHA2_512                          4
};

const SignResponse = struct {
    signature: []const u8,

    const Self = @This();

    pub fn from_bytes(_: []const u8) Self {
        return undefined;
    }
};

const Lock = struct {
    passphrase: []const u8,

    const Self = @This();

    pub fn from_bytes(_: []const u8) Self {
        return undefined;
    }
};

const Unlock = struct {
    passphrase: []const u8,

    const Self = @This();

    pub fn from_bytes(_: []const u8) Self {
        return undefined;
    }
};

const Extension = struct {
    extension_type: []const u8,
    contents: []const u8,

    const Self = @This();

    pub fn from_bytes(_: []const u8) Self {
        return undefined;
    }
};
