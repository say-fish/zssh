const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "read-key",
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/main.zig"),
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    const pkg = b.dependency("zssh", .{
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("openssh", pkg.module("openssh"));

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
