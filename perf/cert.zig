const std = @import("std");

const sshcrypto = @import("sshcrypto");

const MAX_RUNS: usize = 0x01 << 26;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();

    defer if (gpa.deinit() == .leak) @panic("LEAK");

    var pem = try sshcrypto.cert.CertDecoder
        .init(allocator, std.base64.standard.Decoder)
        .decode(@embedFile("ed25519-cert.pub"));
    defer pem.deinit();

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const cert = try sshcrypto.cert.Ed25519.from_bytes(pem.data.der);

        std.mem.doNotOptimizeAway(cert);
    }

    const elapsed = timer.read();

    std.debug.print("Parsed SSH cert, {} times\n", .{MAX_RUNS});
    std.debug.print(
        "`.from_bytes` took ~= {}ns ({} certs/s)\n",
        .{ elapsed / MAX_RUNS, 1000000000 / (elapsed / MAX_RUNS) },
    );
}
