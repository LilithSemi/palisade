const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const palisade = b.addModule("palisade", .{
        .root_source_file = b.path("lib/palisade.zig"),
        .target = target,
        .optimize = optimize,
    });

    const unit_tests = b.addTest(.{ .root_module = palisade });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    // A foreign target still compiles every test. Only the run is skipped.
    run_unit_tests.skip_foreign_checks = true;

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const test_sandbox_step = b.step("test-sandbox", "Run the probe and escape suite");

    const os_tag = target.result.os.tag;

    // Linux only: every escape test asserts on a Landlock rule, a seccomp
    // filter, a namespace, or a mount. None of those exist on another target.
    if (os_tag == .linux) {
        const probe = b.addExecutable(.{
            .name = "palisade-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/probe.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "palisade", .module = palisade },
                },
            }),
        });

        // A second, dynamically linked program, for the path record. The
        // static probe never runs a dynamic loader, so a path audit tested
        // only against it is tested against a program that opens nothing it
        // did not ask for.
        const dynamic_probe = b.addExecutable(.{
            .name = "palisade-dynamic-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/dynamic_probe.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });

        // Zig 0.16 removed the argv access a test would use to find the probe
        // path, and the default test runner panics on unknown argv. Embed the
        // paths as build time constants instead.
        const probe_path_options = b.addOptions();
        probe_path_options.addOptionPath("probe_path", probe.getEmittedBin());

        const dynamic_probe_path_options = b.addOptions();
        dynamic_probe_path_options.addOptionPath(
            "dynamic_probe_path",
            dynamic_probe.getEmittedBin(),
        );
        probe.root_module.addImport(
            "dynamic_probe_path",
            dynamic_probe_path_options.createModule(),
        );

        const escape_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/escape.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "probe_path", .module = probe_path_options.createModule() },
                    .{ .name = "palisade", .module = palisade },
                },
            }),
        });
        const run_escape_tests = b.addRunArtifact(escape_tests);
        run_escape_tests.skip_foreign_checks = true;
        test_sandbox_step.dependOn(&run_escape_tests.step);

        const channel_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/channel.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "probe_path", .module = probe_path_options.createModule() },
                    .{ .name = "palisade", .module = palisade },
                },
            }),
        });
        const run_channel_tests = b.addRunArtifact(channel_tests);
        run_channel_tests.skip_foreign_checks = true;
        test_sandbox_step.dependOn(&run_channel_tests.step);
    }

    // macOS only. The Darwin suite must run on a real Mac, so this run step
    // leaves skip_foreign_checks off: a cross build cannot pass by skipping it.
    if (os_tag == .macos) {
        const darwin_probe = b.addExecutable(.{
            .name = "palisade-darwin-probe",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/darwin_probe.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{.{ .name = "palisade", .module = palisade }},
            }),
        });

        const darwin_probe_path = b.addOptions();
        darwin_probe_path.addOptionPath("probe_path", darwin_probe.getEmittedBin());

        const darwin_escape_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/sandbox/darwin_escape.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
                .imports = &.{
                    .{ .name = "probe_path", .module = darwin_probe_path.createModule() },
                    .{ .name = "palisade", .module = palisade },
                },
            }),
        });
        test_sandbox_step.dependOn(&b.addRunArtifact(darwin_escape_tests).step);
    }
}
