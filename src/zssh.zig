// SPDX-License-Identifier: GPL-3.0-only

//! Freestanding implementation of the ssh protocol.
pub const agent = @import("agent.zig");
pub const cert = @import("cert.zig");
pub const enc = @import("enc.zig");
pub const mem = @import("mem.zig");
pub const pk = @import("pk.zig");
pub const sig = @import("sig.zig");
pub const sk = @import("sk.zig");
pub const err = @import("error.zig");
pub const pem = @import("pem.zig");

pub const Error = @import("error.zig").Error;

// TODO: With openssh support
// TODO: libzssh.a/.so

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
