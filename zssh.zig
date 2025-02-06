// SPDX-License-Identifier: GPL-3.0-only

//! Freestanding implementation of the ssh protocol.
pub const agent = @import("agent.zig");
pub const cert = @import("cert.zig");
pub const pk = @import("pk.zig");
pub const sig = @import("sig.zig");
pub const sk = @import("sk.zig");

// TODO: With openssh support
// TODO: libzssh.a/.so

pub const openssh = @import("openssh.zig");

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
