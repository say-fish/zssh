const std = @import("std");

const sshcrypto = @import("sshcrypto");

const sk = sshcrypto.key.sk;

const MAX_RUNS: usize = 0x01 << 16;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();

    defer if (gpa.deinit() == .leak) @panic("LEAK");

    var pem = try sshcrypto.key.sk.SkDecoder
        .init(allocator, sshcrypto.decoder.base64.pem.Decoder)
        .decode(@embedFile("ed25519-key"));
    defer pem.deinit();

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const key = try sk.Ed25519.from_bytes(pem.data.der);

        var skey = try key.get_private_key(allocator, null);

        std.mem.doNotOptimizeAway(skey);

        defer skey.deinit();
    }

    const elapsed = timer.read();

    std.debug.print("Parsed SSH private key, {} times\n", .{MAX_RUNS});
    std.debug.print(
        "`.from_bytes` + `.get_private_key` + `.deinit` took ~= {}ns ({} keys/s)\n",
        .{ elapsed / MAX_RUNS, 1000000000 / (elapsed / MAX_RUNS) },
    );
}
