const std = @import("std");

const zssh = @import("zssh");

const Pem = zssh.sig.SshSig.Pem;
const PublicKey = std.crypto.sign.Ed25519.PublicKey;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Signature = std.crypto.sign.Ed25519.Signature;
const SshSig = zssh.sig.SshSig;

const MAX_RUNS: usize = 0x01 << 26;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();

    defer if (gpa.deinit() == .leak) @panic("LEAK");

    const pem = try Pem.parse(@embedFile("test.file.sig"));

    var der = try pem.decode(allocator);
    defer der.deinit();

    var buf = std.mem.zeroes([4096]u8);
    var fixed_allocator = std.heap.FixedBufferAllocator.init(&buf);

    var timer = try std.time.Timer.start();

    for (0..MAX_RUNS) |_| {
        const sshsig = try SshSig.from_bytes(der.data);

        var hash: [Sha512.digest_length]u8 = undefined;

        var blob = try sshsig.get_signature_blob(
            fixed_allocator.allocator(),
            &hash,
        );
        defer blob.deinit();

        std.mem.doNotOptimizeAway(blob);
    }

    const elapsed = timer.read();

    std.debug.print("Parsed SSHSIG, {} times\n", .{MAX_RUNS});
    std.debug.print(
        "`.from_pem` + `.get_signature_blob` + `.deinit` took ~= {}ns ({} sigs/s)\n",
        .{ elapsed / MAX_RUNS, 1000000000 / (elapsed / MAX_RUNS) },
    );
}
