//! End-to-end SELinux coverage for the Linux sandbox driver.

const std = @import("std");
const palisade = @import("palisade");
const sandbox = palisade.Sandbox;
const landlock = palisade.linux.landlock;
const namespace = palisade.linux.namespace;
const selinux = palisade.linux.selinux;
const linux = std.os.linux;

fn selfExePath(allocator: std.mem.Allocator) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const rc = linux.readlink("/proc/self/exe", &buffer, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.SelfPathUnavailable;
    return allocator.dupe(u8, buffer[0..rc]);
}

fn makeRoot(allocator: std.mem.Allocator) ![]const u8 {
    const root = try std.fmt.allocPrint(allocator, "/tmp/palisade-selinux-{d}", .{linux.getpid()});
    const root_z = try allocator.dupeSentinel(u8, root, 0);
    switch (linux.errno(linux.mkdir(root_z, 0o700))) {
        .SUCCESS => return root,
        .EXIST => return error.RootAlreadyExists,
        else => return error.RootCreationFailed,
    }
}

fn baseConfig(
    allocator: std.mem.Allocator,
    root: []const u8,
    probe: []const u8,
    context: []const u8,
) !sandbox.Config {
    const mounts = try allocator.dupe(namespace.Mount, &.{
        .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } },
        .{ .bind = .{ .source = probe, .target = "/probe", .read_only = true } },
        .{ .proc = .{} },
    });
    const rules = try allocator.dupe(sandbox.Rule, &.{
        .{ .path = "/nix/store", .access = landlock.AccessFs.read_only },
        .{ .path = "/probe", .access = landlock.AccessFs.read_only_file },
        .{ .path = "/proc", .access = landlock.AccessFs.read_only },
    });
    return .{
        .root = root,
        .cwd = "/",
        .env = &.{},
        .mounts = mounts,
        .rules = rules,
        .network = .none,
        .limits = .none,
        .selinux_context = context,
    };
}

fn expectRejectedContext(
    allocator: std.mem.Allocator,
    root: []const u8,
    probe: []const u8,
) !void {
    _ = sandbox.spawn(
        allocator,
        try baseConfig(allocator, root, probe, "not_a_valid_selinux_context"),
        &.{ "/probe", "child", "unused" },
        .{},
    ) catch |err| {
        if (err == error.SelinuxFailed) return;
        return err;
    };
    return error.InvalidContextAccepted;
}

fn child(target: []const u8) !u8 {
    var buffer: [4096]u8 = undefined;
    const current = try selinux.currentContext(&buffer, null);
    return if (std.mem.eql(u8, current, target)) 0 else 1;
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const args = try init.args.toSlice(allocator);
    if (args.len == 3 and std.mem.eql(u8, args[1], "child")) return child(args[2]);
    if (args.len != 2) return error.MissingTargetContext;

    const active = selinux.mode(null) catch |err| switch (err) {
        error.NotSupported => return 0,
        else => return err,
    };
    if (active != .enforcing) return error.SelinuxNotEnforcing;

    var current_buffer: [4096]u8 = undefined;
    const current = try selinux.currentContext(&current_buffer, null);
    if (std.mem.eql(u8, current, args[1])) return error.TargetAlreadyCurrent;

    const root = try makeRoot(allocator);
    const probe = try selfExePath(allocator);
    try expectRejectedContext(allocator, root, probe);

    const term = try sandbox.spawn(
        allocator,
        try baseConfig(allocator, root, probe, args[1]),
        &.{ "/probe", "child", args[1] },
        .{},
    );
    return switch (term) {
        .exited => |code| code,
        else => error.SandboxDidNotExit,
    };
}
