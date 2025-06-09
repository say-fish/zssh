const std = @import("std");

const zssh = @import("zssh");

const private = @import("private.zig");
const public = @import("public.zig");
const signature = @import("signature.zig");

const gen = zssh.agent;
const enc = zssh.enc;

const Cont = enc.Cont;
const Error = zssh.err.Error;

pub const Client = gen.MakeClient(
    public.Key,
    private.wire.Key,
    openssh_extensions.Extensions,
    openssh_extensions.Constraints,
);

pub const Agent = gen.MakeAgent(
    public.Key,
    signature.Signature,
    openssh_extensions.ExtensionResponse,
);

/// OpenSSH's extensions to the agent protocol.
pub const openssh_extensions = struct {
    /// This extension allows a ssh client to bind an agent connection
    /// to a particular SSH session identifier as derived from the
    /// initial key exchange (as per RFC4253 section 7.2) and the host
    /// key used for that exchange. This binding is verifiable at the
    /// agent by including the initial KEX signature made by the host
    /// key.
    pub const SessionBind = struct {
        hostkey: public.Key,
        identifier: []const u8,
        signature: signature.Signature,
        is_forwarding: u8,

        const Self = @This();

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try enc.parse_with_cont(Self, src);
        }

        pub fn encoded_size(_: *const Self) u32 {
            @panic("TODO");
        }
    };

    /// Standard OpenSSH key constraints
    pub const Constraints = union(enum) {
        /// This key constraint extension supports destination- and
        /// forwarding path- restricted keys. It may be attached as a
        /// constraint when keys or smartcard keys are added to an agent.
        @"restrict-destination-v00@openssh.com": RestrictDestination,

        /// This key constraint extension allows certificates to be
        /// associated with private keys as they are loaded from a PKCS#11
        /// token.
        @"associated-certs-v00@openssh.com": AssociatedCerts,

        const Self = @This();

        const RestrictDestination = struct {
            constraints: []const u8,
            // TODO TYPE:
            //      string          from_username (must be empty)
            //      string          from_hostname
            //      string          reserved
            //      keyspec[]       from_hostkeys
            //      string          to_username
            //      string          to_hostname
            //      string          reserved
            //      keyspec[]       to_hostkeys
            //      string          reserved
            //
            // And a keyspec consists of:
            //
            //      string          keyblob
            //      bool            is_ca
            pub fn parse(src: []const u8) Error!Cont(RestrictDestination) {
                return try enc.parse_with_cont(RestrictDestination, src);
            }
        };

        const AssociatedCerts = struct {
            certs_only: bool,
            cert_blob: []const u8, // TODO: Iterator

            pub fn parse(src: []const u8) Error!Cont(AssociatedCerts) {
                return try enc.parse_with_cont(AssociatedCerts, src);
            }
        };

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try gen.decode_as_string(Self, src);
        }

        pub fn encoded_size(_: *const Self) u32 {
            @panic("TODO");
        }

        pub fn serialize(
            _: *const Self,
            _: std.io.AnyWriter,
        ) anyerror!void {
            @panic("TODO");
        }
    };

    pub const Extensions = union(enum) {
        query: Client.Query,
        @"session-bind@openssh.com": SessionBind,

        const Self = @This();

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try gen.decode_as_string(Self, src);
        }

        pub fn encoded_size(_: *const Self) u32 {
            @panic("TODO");
        }

        pub fn serialize(
            _: *const Self,
            _: std.io.AnyWriter,
        ) anyerror!void {
            @panic("TODO");
        }
    };

    pub const ExtensionResponse = union(enum) {
        query: Agent.Query,

        const Self = @This();

        pub fn parse(src: []const u8) Error!Cont(Self) {
            return try gen.decode_as_string(Self, src);
        }

        pub fn encoded_size(_: *const Self) u32 {
            @panic("TODO");
        }

        pub fn serialize(
            _: *const Self,
            _: std.io.AnyWriter,
        ) anyerror!void {
            @panic("TODO");
        }
    };
};
