const std = @import("std");
const zssh = @import("zssh");

const Client = zssh.agent.Client;
const expect_equal = std.testing.expectEqual;
const expect_error = std.testing.expectError;

test "can parse SSH_AGENTC_REQUEST_IDENTITIES" {
    const bytes = [_]u8{ 0x00, 0x00, 0x00, 0x01, 0x0B };

    const msg_len = std.mem.readInt(u32, bytes[0..4], .big);

    const msg = try zssh.agent.decode(Client, bytes[4 .. 4 + msg_len]);

    try expect_equal(Client.request_identities, msg);
}

test "invalid client msg" {
    const bytes = [_]u8{ 0x00, 0x00, 0x00, 0x01, 0x0C };

    const msg_len = std.mem.readInt(u32, bytes[0..4], .big);

    try expect_error(
        error.InvalidMsgType,
        zssh.agent.decode(Client, bytes[4 .. 4 + msg_len]),
    );
}
