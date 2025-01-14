const std = @import("std");

const sshcrypto = @import("sshcrypto");

const Ed25519 = sshcrypto.cert.Ed25519;
const Pem = sshcrypto.cert.Pem;

const MAX_RUNS: usize = 0x01 << 26;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();

    defer if (gpa.deinit() == .leak) @panic("LEAK");

    const pem = try Pem.parse(@embedFile("ed25519-cert.pub"));

    var der = try pem.decode(allocator);
    defer der.deinit();

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const cert = try sshcrypto.cert.Ed25519.from_bytes(der.data);

        std.mem.doNotOptimizeAway(cert);
    }

    const elapsed = timer.read();

    std.debug.print("Parsed SSH cert, {} times\n", .{MAX_RUNS});
    std.debug.print(
        "`.from_bytes` took ~= {}ns ({} certs/s)\n",
        .{ elapsed / MAX_RUNS, 1000000000 / (elapsed / MAX_RUNS) },
    );
}
