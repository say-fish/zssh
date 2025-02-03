const std = @import("std");

pub fn results(name: []const u8, max_runs: comptime_int, elapsed: u64) void {
    std.debug.print("{s}\n\n", .{name});

    std.debug.print("{s:>15}   #{:>14} times\n", .{ "iterations", max_runs });
    std.debug.print("{s:>15}   #{:>14} ns\n", .{ "average", elapsed / max_runs });
    std.debug.print("{s:>15}   #{d:>14.2} /sec\n", .{
        "per second",
        1000000000 / (@as(f64, @floatFromInt(elapsed)) / max_runs),
    });

    std.debug.print("\n\n", .{});
}
