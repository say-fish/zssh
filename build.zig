const std = @import("std");
const builtin = @import("builtin");

const panic = std.debug.panic;

const ArrayList = std.ArrayList;
const Tuple = std.meta.Tuple;

const Allocator = std.mem.Allocator;

const PERF_EVENTS: []const u8 = "cache-references,cache-misses,cycles,instructions,branches,faults,migrations";

// FIXME:
const TEST_ASSETS_PATH: []const u8 = "assets/";

const TestAssets = ArrayList(Tuple(&.{ []u8, []u8 }));

// TODO: Make this comptime
fn get_test_assets(allocator: std.mem.Allocator, path: []const u8) !TestAssets {
    var ret = ArrayList(Tuple(&.{ []u8, []u8 })).init(allocator);

    var assets = try std.fs.cwd().openDir(path, .{ .iterate = true });
    defer assets.close();

    var walker = try assets.walk(allocator);

    while (try walker.next()) |entry| {
        if (std.mem.endsWith(u8, ".sh", entry.basename)) continue;

        const basename = entry.basename[0..entry.basename.len];

        try ret.append(.{
            // This is fine for this use-case
            try allocator.dupe(u8, basename), // name
            try std.mem.concat(allocator, u8, &.{ // path
                path,
                basename,
            }),
        });
    }

    return ret;
}

const Test = struct {
    root_source_file: std.Build.LazyPath,

    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,

    mod: ?*std.Build.Module = null,
    mod_name: ?[]const u8 = null,

    use_lld: bool = true,
    use_llvm: bool = true,

    assets: ?*const TestAssets = null,
};

fn add_test(b: *std.Build, step: *std.Build.Step, t: Test) !void {
    const test_case = b.addTest(.{
        .root_source_file = t.root_source_file,
        .target = t.target,
        .optimize = t.optimize,
        .use_llvm = t.use_llvm,
        .use_lld = t.use_lld,
    });

    if (t.mod) |mod|
        test_case.root_module.addImport(t.mod_name.?, mod);

    if (t.assets) |assets| for (assets.items) |cert| {
        const name, const file = cert;
        test_case.root_module.addAnonymousImport(
            name,
            .{ .root_source_file = b.path(file) },
        );
    };

    const run_test_case = b.addRunArtifact(test_case);

    step.dependOn(&run_test_case.step);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const llvm = !(b.option(bool, "nollvm", "Don't use LLVM") orelse false);

    const lld = if (builtin.os.tag == .windows or builtin.os.tag == .macos)
        false
    else
        llvm;

    const mod = b.addModule("sshcrypto", .{
        .root_source_file = .{
            .src_path = .{
                .owner = b,
                .sub_path = b.pathFromRoot("src/sshcrypto.zig"),
            },
        },
        .target = target,
        .optimize = optimize,
    });

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    arena.deinit();

    const assets = get_test_assets(arena.allocator(), TEST_ASSETS_PATH) catch
        @panic("Fail to get test certs");

    const test_step = b.step("test", "Run unit tests");
    {
        add_test(b, test_step, .{
            .root_source_file = b.path("test/cert.zig"),
            .target = target,
            .optimize = optimize,
            .mod = mod,
            .mod_name = "sshcrypto",
            .use_lld = lld,
            .use_llvm = llvm,
            .assets = &assets,
        }) catch @panic("OOM");

        add_test(b, test_step, .{
            .root_source_file = b.path("test/sig.zig"),
            .target = target,
            .optimize = optimize,
            .mod = mod,
            .mod_name = "sshcrypto",
            .use_lld = lld,
            .use_llvm = llvm,
            .assets = &assets,
        }) catch @panic("OOM");

        add_test(b, test_step, .{
            .root_source_file = b.path("test/key.zig"),
            .target = target,
            .optimize = optimize,
            .mod = mod,
            .mod_name = "sshcrypto",
            .use_lld = lld,
            .use_llvm = llvm,
            .assets = &assets,
        }) catch @panic("OOM");

        add_test(b, test_step, .{
            .root_source_file = b.path("src/proto.zig"),
            .target = target,
            .optimize = optimize,
            .use_lld = lld,
            .use_llvm = llvm,
            .assets = &assets,
        }) catch @panic("OOM");
    }

    const docs_step = b.step("docs", "Build documentation");
    {
        const docs_obj = b.addObject(.{
            .name = "sshcrypto",
            .root_source_file = b.path("src/sshcrypto.zig"),
            .target = target,
            .optimize = optimize,
        });

        const install_docs = b.addInstallDirectory(.{
            .install_dir = .prefix,
            .install_subdir = "docs",
            .source_dir = docs_obj.getEmittedDocs(),
        });

        docs_step.dependOn(&docs_obj.step);
        docs_step.dependOn(&install_docs.step);
    }

    const perf_step = b.step("perf", "Perf record");
    {
        const Names = enum { @"verify-cert", cert, key, sig };

        const perf_name =
            b.option(Names, "perf", "Perf to run (default: key)") orelse .key;

        const perf_exe = b.addExecutable(.{
            .name = "perf",
            .root_source_file = b.path(
                b.fmt("perf/{s}.zig", .{@tagName(perf_name)}),
            ),
            .target = target,
            .use_lld = lld,
            .use_llvm = llvm,
            .optimize = .ReleaseFast,
        });

        perf_exe.root_module.addImport("sshcrypto", mod);

        for (assets.items) |cert| {
            const name, const file = cert;
            perf_exe.root_module.addAnonymousImport(
                name,
                .{ .root_source_file = b.path(file) },
            );
        }

        const run_perf =
            b.addSystemCommand(&.{ "perf", "record", "-e", PERF_EVENTS });

        run_perf.has_side_effects = true;
        run_perf.addArtifactArg(perf_exe);

        perf_step.dependOn(&run_perf.step);
    }

    const debug_step = b.step("debug", "Run test target with gdb");
    {
        const run_debug = b.addSystemCommand(&.{"gdb"});

        debug_step.dependOn(&run_debug.step);
    }
}
