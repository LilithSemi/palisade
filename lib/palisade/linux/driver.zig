//! The Linux driver. `spawn` runs the sandboxed program through the layers in
//! a fixed order, set by `enterNamespaces`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const landlock = @import("landlock.zig");
const namespace = @import("namespace.zig");
const capabilities = @import("capabilities.zig");
const seccomp = @import("seccomp.zig");
const notify = @import("notify.zig");
const bpf = @import("bpf.zig");
const rlimits = @import("rlimits.zig");
const cgroup = @import("cgroup.zig");
const afterfork = @import("afterfork.zig");
const netns = @import("netns.zig");
const caps = @import("caps.zig");
const iface = @import("../Sandbox.zig");
const Config = iface.Config;
const SetupError = iface.SetupError;
const SpawnError = iface.SpawnError;
const LandlockReport = iface.LandlockReport;
const LimitsReport = iface.LimitsReport;

const fileno_stdin: i32 = 0;
const fileno_stdout: i32 = 1;
const fileno_stderr: i32 = 2;

var cgroup_seed: std.atomic.Value(u64) = .init(0);

pub const driver_name = caps.driver_name;
pub const guarantees = caps.guarantees;
pub const expresses = caps.expresses;

const SetupStep = enum(u8) {
    stdin_redirect,
    process_group,
    close_fds,
    cgroup_join,
    resource_limits,
    namespace,
    network,
    channel,
    helper,
    scratch_mount,
    mount_tree,
    pivot,
    capabilities,
    landlock_init,
    landlock_rule,
    landlock_restrict,
    session_keyring,
    seccomp_install,
    notify_handover,
    fork,
    pdeathsig_pidfd,
    pdeathsig_prctl,
    exec,
};

const setup_failure_magic: u32 = 0x31534C50;

const SetupFailureRecord = extern struct {
    magic: u32 = setup_failure_magic,
    step: u8,
    errno: i32,
};

fn seccompOptionsFor(base: seccomp.Options, config: Config) seccomp.Options {
    var options = base;
    options.block_connect = base.block_connect or iface.blocksConnect(config);
    return options;
}

const test_net: iface.Network = .{ .isolated = .{
    .device_name = "pal0",
    .address4 = .{ 10, 99, 0, 2 },
    .prefix4 = 24,
    .address6 = .{ 0xfd, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 },
    .prefix6 = 64,
} };

var test_state: u8 = 0;

fn testServe(_: *anyopaque, _: i32) iface.Channel.ServeResult {
    return .done;
}

fn testChannel(hands_host_descriptor: bool) iface.Channel {
    return .{
        .ptr = &test_state,
        .serve = .{ .call = testServe, .max_requests = 1 },
        .hands_host_descriptor = hands_host_descriptor,
    };
}

fn testConfig(network: iface.Network, channels: []const iface.Channel) Config {
    return .{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .network = network,
        .channels = channels,
    };
}

test "connect is taken away exactly when a channel hands a host descriptor to the child" {
    const hands = [_]iface.Channel{testChannel(true)};
    const keeps = [_]iface.Channel{testChannel(false)};

    try std.testing.expect(seccompOptionsFor(.{}, testConfig(test_net, &hands)).block_connect);
    try std.testing.expect(!seccompOptionsFor(.{}, testConfig(test_net, &keeps)).block_connect);
    try std.testing.expect(!seccompOptionsFor(.{}, testConfig(test_net, &.{})).block_connect);
    try std.testing.expect(!seccompOptionsFor(.{}, testConfig(.none, &.{})).block_connect);
    try std.testing.expect(!seccompOptionsFor(.{}, testConfig(.host, &.{})).block_connect);
}

test "a channel that hands a host descriptor blocks connect whatever the caller asked for" {
    const hands = [_]iface.Channel{ testChannel(true), testChannel(true) };
    const options = seccompOptionsFor(.{ .block_connect = false }, testConfig(test_net, &hands));
    try std.testing.expect(options.block_connect);

    const filter = try seccomp.build(std.testing.allocator, options);
    defer std.testing.allocator.free(filter);
    const plain = try seccomp.build(std.testing.allocator, .{});
    defer std.testing.allocator.free(plain);
    try std.testing.expect(filter.len > plain.len);
}

test "a caller that blocks connect keeps that, and the other options pass through" {
    const options = seccompOptionsFor(
        .{ .block_connect = true, .strict_wx = false },
        testConfig(.none, &.{}),
    );
    try std.testing.expect(options.block_connect);
    try std.testing.expect(!options.strict_wx);
}

test "the filter the default config gets is the filter a caller with no options gets" {
    const allocator = std.testing.allocator;

    const plain = try seccomp.build(allocator, .{});
    defer allocator.free(plain);

    const defaulted = try seccomp.build(allocator, seccompOptionsFor(.{}, testConfig(.none, &.{})));
    defer allocator.free(defaulted);

    try std.testing.expectEqualSlices(bpf.Insn, plain, defaulted);
}

fn placementIsPossible(kernel: rlimits.Release, containment: iface.Containment) bool {
    return switch (containment) {
        .best_effort => true,
        .supplied => kernel.atLeast(cgroup.clone_into_cgroup_since),
    };
}

test "a caller supplied cgroup is refused below 5.7, and a cgroup the driver makes is refused on no kernel" {
    const supplied = iface.Containment{ .supplied = .{ .fd = 7 } };

    try std.testing.expect(!placementIsPossible(.{ .major = 4, .minor = 19 }, supplied));
    try std.testing.expect(!placementIsPossible(.{ .major = 5, .minor = 3 }, supplied));
    try std.testing.expect(!placementIsPossible(.{ .major = 5, .minor = 6 }, supplied));
    try std.testing.expect(placementIsPossible(.{ .major = 5, .minor = 7 }, supplied));
    try std.testing.expect(placementIsPossible(.{ .major = 6, .minor = 18 }, supplied));

    try std.testing.expect(!placementIsPossible(.{ .major = 0, .minor = 0 }, supplied));

    for ([_]rlimits.Release{
        .{ .major = 0, .minor = 0 },
        .{ .major = 4, .minor = 19 },
        .{ .major = 5, .minor = 6 },
        .{ .major = 6, .minor = 18 },
    }) |kernel| {
        try std.testing.expect(placementIsPossible(kernel, .{ .best_effort = .{} }));
    }
}

const Pair = [2]i32;

const no_pair: Pair = .{ -1, -1 };

fn closePair(pair: *Pair) void {
    for (pair) |*fd| {
        if (fd.* < 0) continue;
        _ = linux.close(fd.*);
        fd.* = -1;
    }
}

fn closePairs(pairs: []Pair) void {
    for (pairs) |*pair| closePair(pair);
}

fn reapPid(pid: linux.pid_t) void {
    var status: i32 = undefined;
    var rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(pid, &status, 0);
}

pub fn spawn(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    run: iface.Run,
) SpawnError!std.process.Child.Term {
    try iface.validate(config);
    for (config.helpers) |helper| {
        for (helper.keep_fds) |fd| {
            if (linux.errno(linux.fcntl(fd, linux.F.GETFD, 0)) == .BADF) return error.HelperFdClosed;
        }
    }

    const kernel = rlimits.runningKernel();

    if (!placementIsPossible(kernel, config.containment)) return error.CgroupPlacementUnsupported;

    const abi = landlock.probeAbi() catch return error.LandlockUnavailable;
    if (run.reports.landlock) |report| report.* = .{ .abi = abi, .features = landlock.featuresFor(abi) };

    const seccomp_options = seccompOptionsFor(config.seccomp_options, config);

    var middle_options = seccomp_options;
    middle_options.traps = .empty;
    const insns = seccomp.build(allocator, middle_options) catch |err| return err;
    defer allocator.free(insns);

    const watching = seccomp_options.traps.count() != 0;
    const child_insns = if (watching)
        seccomp.build(allocator, seccomp_options) catch |err| return err
    else
        insns;
    defer if (watching) allocator.free(child_insns);

    const recording = watching and config.path_audit;
    const reader_insns = if (recording)
        seccomp.buildReader(allocator) catch |err| return err
    else
        &[_]bpf.Insn{};
    defer if (recording) allocator.free(reader_insns);

    const keeper_insns = seccomp.buildKeeper(allocator) catch |err| return err;
    defer allocator.free(keeper_insns);

    const granted: []const []const u8 = if (recording)
        iface.grantPrefixes(allocator, config) catch |err| return err
    else
        &.{};
    defer if (recording) allocator.free(granted);

    const helper_watches = try allocator.alloc(HelperWatch, config.helpers.len);
    defer allocator.free(helper_watches);

    var kept_total: usize = 0;
    for (config.helpers) |helper| kept_total += helper.keep_fds.len;
    const helper_kept = try allocator.alloc(i32, kept_total);
    defer allocator.free(helper_kept);
    {
        var at: usize = 0;
        for (config.helpers) |helper| {
            @memcpy(helper_kept[at..][0..helper.keep_fds.len], helper.keep_fds);
            at += helper.keep_fds.len;
        }
    }

    const helper_filters = try allocator.alloc([]bpf.Insn, config.helpers.len);
    defer allocator.free(helper_filters);
    var built_filters: usize = 0;
    defer for (helper_filters[0..built_filters]) |filter| allocator.free(filter);
    for (config.helpers, helper_filters) |helper, *slot| {
        slot.* = try helperFilter(allocator, helper);
        built_filters += 1;
    }

    var group: cgroup.Cgroup = switch (config.containment) {
        .best_effort => |best| if (config.limits.wantsCgroup())
            cgroup.Cgroup.create(
                best.name_prefix,
                config.limits.memory_bytes,
                config.limits.processes,
                cgroup_seed.fetchAdd(1, .monotonic),
            )
        else
            .{ .support = .off },
        .supplied => .{ .support = .supplied },
    };
    defer group.destroy();

    if (run.reports.limits) |report| report.* = .{
        .limits = config.limits,
        .cgroup = group.support,
        .nproc_applied = config.limits.processes != null and
            kernel.atLeast(rlimits.nproc_per_user_namespace_since),
    };

    var pipe_fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&pipe_fds, .{ .CLOEXEC = true })) != .SUCCESS) return error.Unexpected;
    const read_fd = pipe_fds[0];
    const write_fd = pipe_fds[1];

    var middle_pipe: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&middle_pipe, .{ .CLOEXEC = true })) != .SUCCESS) {
        _ = linux.close(read_fd);
        _ = linux.close(write_fd);
        return error.Unexpected;
    }
    const middle_read_fd = middle_pipe[0];
    const middle_write_fd = middle_pipe[1];

    var channel_pairs: [iface.max_channels]Pair = @splat(no_pair);
    const channel_count = config.channels.len;
    errdefer closePairs(&channel_pairs);
    for (channel_pairs[0..channel_count]) |*pair| {
        const pair_rc = linux.socketpair(
            linux.AF.UNIX,
            linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC,
            0,
            pair,
        );
        if (linux.errno(pair_rc) != .SUCCESS) {
            pair.* = no_pair;
            _ = linux.close(read_fd);
            _ = linux.close(write_fd);
            _ = linux.close(middle_read_fd);
            _ = linux.close(middle_write_fd);
            return error.ChannelFailed;
        }
    }

    const path_record: ?*notify.PathRecord = if (recording) mapPathRecord() else null;
    defer if (path_record) |record| unmapPathRecord(record);

    var map_fds: Pair = no_pair;
    errdefer closePair(&map_fds);
    if (config.hide_helpers) {
        const map_pair_rc = linux.socketpair(
            linux.AF.UNIX,
            linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
            0,
            &map_fds,
        );
        if (linux.errno(map_pair_rc) != .SUCCESS) {
            map_fds = no_pair;
            _ = linux.close(read_fd);
            _ = linux.close(write_fd);
            _ = linux.close(middle_read_fd);
            _ = linux.close(middle_write_fd);
            return error.Unexpected;
        }
    }

    const fork_rc = switch (config.containment) {
        .best_effort => linux.fork(),
        .supplied => |supplied| cgroup.forkInto(supplied.fd),
    };
    if (linux.errno(fork_rc) != .SUCCESS) {
        _ = linux.close(read_fd);
        _ = linux.close(write_fd);
        _ = linux.close(middle_read_fd);
        _ = linux.close(middle_write_fd);
        return switch (config.containment) {
            .best_effort => error.Unexpected,
            .supplied => error.CgroupPlacementRefused,
        };
    }
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        _ = linux.close(read_fd);
        _ = linux.close(middle_read_fd);

        var child_ends: [iface.max_channels]i32 = @splat(-1);
        for (channel_pairs[0..channel_count], child_ends[0..channel_count]) |*pair, *end| {
            _ = linux.close(pair[0]);
            pair[0] = -1;
            end.* = pair[1];
        }

        resetSignalState();
        newProcessGroup(write_fd, config.stderr_fd);

        switch (config.containment) {
            .best_effort => joinCgroup(&group, write_fd, config.stderr_fd),
            .supplied => {},
        }

        redirectStdinToDevNull(write_fd, config.stderr_fd);
        if (map_fds[0] >= 0) {
            _ = linux.close(map_fds[0]);
            map_fds[0] = -1;
        }
        enterNamespaces(
            config,
            write_fd,
            middle_write_fd,
            child_ends[0..channel_count],
            map_fds[1],
            helper_kept,
        );
        // askForMaps closes its end.
        map_fds[1] = -1;

        switch (config.network) {
            .isolated => |params| configureNetwork(params, write_fd, config.stderr_fd),
            .none, .host => {},
        }

        const areas = mountScratchAreas(config, write_fd);

        var notify_fds: [2]i32 = .{ -1, -1 };
        if (watching) {
            const pair_rc = linux.socketpair(
                linux.AF.UNIX,
                linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
                0,
                &notify_fds,
            );
            if (linux.errno(pair_rc) != .SUCCESS) {
                dieErrno(
                    write_fd,
                    config.stderr_fd,
                    .fork,
                    "socketpair for the notification handover",
                    linux.errno(pair_rc),
                );
            }
        }

        const middle_pidfd_rc = linux.pidfd_open(linux.getpid(), 0);
        if (linux.errno(middle_pidfd_rc) != .SUCCESS) {
            dieErrno(
                write_fd,
                config.stderr_fd,
                .pdeathsig_pidfd,
                "pidfd_open",
                linux.errno(middle_pidfd_rc),
            );
        }
        const middle_pidfd: i32 = @intCast(middle_pidfd_rc);

        var keeper_fds: [2]i32 = undefined;
        const keeper_pair_rc = linux.socketpair(
            linux.AF.UNIX,
            linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
            0,
            &keeper_fds,
        );
        if (linux.errno(keeper_pair_rc) != .SUCCESS) {
            dieErrno(
                write_fd,
                config.stderr_fd,
                .fork,
                "socketpair for the pid namespace keeper",
                linux.errno(keeper_pair_rc),
            );
        }

        const keeper_fork_rc = linux.fork();
        if (linux.errno(keeper_fork_rc) != .SUCCESS) {
            die(write_fd, config.stderr_fd, .fork, error.Unexpected);
        }
        const keeper_pid: linux.pid_t = @intCast(keeper_fork_rc);
        if (keeper_pid == 0) {
            _ = linux.close(keeper_fds[0]);
            runKeeper(
                keeper_fds[1],
                middle_pidfd,
                write_fd,
                config.stderr_fd,
                keeper_insns,
                config.hide_helpers,
            );
        }

        _ = linux.close(keeper_fds[1]);
        keeper_fds[1] = -1;
        var keeper_ready: [1]u8 = undefined;
        var keeper_read_rc = linux.read(keeper_fds[0], &keeper_ready, keeper_ready.len);
        while (linux.errno(keeper_read_rc) == .INTR) {
            keeper_read_rc = linux.read(keeper_fds[0], &keeper_ready, keeper_ready.len);
        }
        if (linux.errno(keeper_read_rc) != .SUCCESS or keeper_read_rc != keeper_ready.len or
            keeper_ready[0] != 1)
        {
            die(write_fd, config.stderr_fd, .fork, error.Unexpected);
        }

        for (config.helpers, helper_watches, helper_filters) |helper, *watch, filter| {
            watch.* = .{ .pid = -1 };
            var ready_fds: [2]i32 = undefined;
            const ready_pair_rc = linux.socketpair(
                linux.AF.UNIX,
                linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
                0,
                &ready_fds,
            );
            if (linux.errno(ready_pair_rc) != .SUCCESS) {
                dieErrno(
                    write_fd,
                    config.stderr_fd,
                    .helper,
                    "socketpair for a helper",
                    linux.errno(ready_pair_rc),
                );
            }

            const helper_fork_rc = linux.fork();
            if (linux.errno(helper_fork_rc) != .SUCCESS) {
                die(write_fd, config.stderr_fd, .helper, error.Unexpected);
            }
            if (helper_fork_rc == 0) {
                _ = linux.close(ready_fds[0]);
                _ = linux.close(keeper_fds[0]);
                if (notify_fds[0] >= 0) _ = linux.close(notify_fds[0]);
                if (notify_fds[1] >= 0) _ = linux.close(notify_fds[1]);
                if (path_record) |record| unmapPathRecord(record);
                const channel_end: i32 = if (helper.channel) |index| child_ends[index] else -1;
                runHelper(
                    helper,
                    filter,
                    channel_end,
                    ready_fds[1],
                    middle_pidfd,
                    write_fd,
                    config.stderr_fd,
                    config.hide_helpers,
                );
            }
            watch.pid = @intCast(helper_fork_rc);

            _ = linux.close(ready_fds[1]);
            var ready: [1]u8 = undefined;
            var ready_rc = linux.read(ready_fds[0], &ready, ready.len);
            while (linux.errno(ready_rc) == .INTR) {
                ready_rc = linux.read(ready_fds[0], &ready, ready.len);
            }
            _ = linux.close(ready_fds[0]);
            if (linux.errno(ready_rc) != .SUCCESS or ready_rc != ready.len or ready[0] != 1) {
                die(write_fd, config.stderr_fd, .helper, error.Unexpected);
            }
        }

        for (helper_kept) |fd| _ = linux.close(fd);

        const inner_fork_rc = linux.fork();
        if (linux.errno(inner_fork_rc) != .SUCCESS) {
            die(write_fd, config.stderr_fd, .fork, error.Unexpected);
        }
        const inner_pid: linux.pid_t = @intCast(inner_fork_rc);

        if (inner_pid == 0) {
            _ = linux.close(keeper_fds[0]);
            _ = linux.close(middle_write_fd);
            if (notify_fds[0] >= 0) _ = linux.close(notify_fds[0]);
            if (path_record) |record| unmapPathRecord(record);
            applyLayers(allocator, config, abi, child_insns, write_fd, notify_fds[1]);
            armPdeathsig(write_fd, config.stderr_fd, middle_pidfd);
            execute(allocator, config, argv, write_fd, child_ends[0..channel_count]);
            unreachable;
        }

        _ = linux.close(middle_pidfd);

        _ = linux.close(write_fd);

        for (child_ends[0..channel_count]) |end| _ = linux.close(end);

        if (config.stdout_fd != fileno_stdout) _ = linux.close(config.stdout_fd);
        if (config.stderr_fd != fileno_stderr and config.stderr_fd != config.stdout_fd)
            _ = linux.close(config.stderr_fd);
        if (config.stdin_fd) |fd| {
            if (fd > fileno_stderr and fd != config.stdout_fd and fd != config.stderr_fd)
                _ = linux.close(fd);
        }

        var listener: i32 = -1;
        var child_pidfd: i32 = -1;
        if (notify_fds[0] >= 0) {
            _ = linux.close(notify_fds[1]);
            notify_fds[1] = -1;
            const child_pidfd_rc = linux.pidfd_open(inner_pid, 0);
            if (linux.errno(child_pidfd_rc) == .SUCCESS) child_pidfd = @intCast(child_pidfd_rc);
            listener = notify.takeListener(notify_fds[0], child_pidfd);
            _ = linux.close(notify_fds[0]);
            notify_fds[0] = -1;
        }

        var reader_pid: linux.pid_t = -1;
        if (listener >= 0 and path_record != null) {
            const reader_rc = linux.fork();
            if (linux.errno(reader_rc) == .SUCCESS) {
                if (reader_rc == 0) runReader(
                    listener,
                    child_pidfd,
                    reader_insns,
                    path_record.?,
                    granted,
                );
                reader_pid = @intCast(reader_rc);
                _ = linux.close(listener);
                listener = -1;
            }
        }

        restrictMiddle(abi, insns, middle_write_fd);

        if (reader_pid >= 0) {} else if (listener >= 0) {
            var counts = notify.empty_counts;
            const outcome = notify.serve(listener, child_pidfd, &counts);
            _ = linux.close(listener);
            reportTraps(middle_write_fd, &counts);
            if (outcome == .fault) _ = linux.kill(inner_pid, .KILL);
        } else if (watching) {
            reportTraps(middle_write_fd, null);
        }
        if (child_pidfd >= 0) _ = linux.close(child_pidfd);

        waitAndRelay(inner_pid, keeper_pid, helper_watches, keeper_fds[0], &areas, middle_write_fd, if (reader_pid >= 0) .{
            .pid = reader_pid,
            .record = path_record.?,
        } else null);
        unreachable;
    }

    for (channel_pairs[0..channel_count]) |*pair| {
        _ = linux.close(pair[1]);
        pair[1] = -1;
    }

    if (run.handle) |handle| {
        const pidfd_rc = linux.pidfd_open(pid, 0);
        if (linux.errno(pidfd_rc) != .SUCCESS) {
            _ = linux.kill(pid, .KILL);
            reapPid(pid);
            _ = linux.close(read_fd);
            _ = linux.close(write_fd);
            _ = linux.close(middle_read_fd);
            _ = linux.close(middle_write_fd);
            return error.Unexpected;
        }
        handle.publish(pid, @intCast(pidfd_rc));
    }

    if (map_fds[0] >= 0) {
        _ = linux.close(map_fds[1]);
        map_fds[1] = -1;
        mapForChild(map_fds[0], pid);
        _ = linux.close(map_fds[0]);
        map_fds[0] = -1;
    }

    _ = linux.close(write_fd);
    _ = linux.close(middle_write_fd);

    const maybe_failure = readSetupReport(read_fd) catch |err| {
        _ = linux.close(read_fd);
        _ = linux.close(middle_read_fd);
        return err;
    };
    _ = linux.close(read_fd);

    if (maybe_failure) |record| {
        _ = linux.close(middle_read_fd);
        reapPid(pid);

        const step = std.enums.fromInt(SetupStep, record.step) orelse return error.UntrustedSetupReport;
        return setupErrorFor(step);
    }

    if (channel_count > 0) {
        serveChannels(pid, config.channels, channel_pairs[0..channel_count]) catch |err| {
            closePairs(&channel_pairs);
            _ = linux.close(middle_read_fd);
            _ = linux.kill(pid, .KILL);
            reapPid(pid);
            return err;
        };
        closePairs(&channel_pairs);
    }

    var status: i32 = undefined;
    var wait_rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(wait_rc) == .INTR) {
        wait_rc = linux.waitpid(pid, &status, 0);
    }
    if (linux.errno(wait_rc) != .SUCCESS) {
        _ = linux.close(middle_read_fd);
        return error.Unexpected;
    }

    const middle_report = readMiddleReport(middle_read_fd);
    _ = linux.close(middle_read_fd);

    if (run.reports.supervisor_audit) |audit| {
        inline for (comptime std.enums.values(iface.LayerName)) |layer| {
            if (comptime iface.failModeFor(.supervisor, layer) != null) {
                audit.record(layer, middle_report.layers.get(layer));
            }
        }
    }

    if (run.reports.syscall_audit) |audit| switch (middle_report.traps) {
        .unasked => {},
        .observed => audit.record(.{ .observed = middle_report.trap_counts }),
        .unobserved => audit.record(.unobserved),
    };

    if (run.reports.syscall_audit) |audit| {
        if (path_record) |record| audit.recordPaths(record);
    }

    const term: std.process.Child.Term = if (linux.W.IFSIGNALED(@bitCast(status)))
        .{ .signal = linux.W.TERMSIG(@bitCast(status)) }
    else
        .{ .exited = linux.W.EXITSTATUS(@bitCast(status)) };
    reportLimitOutcome(config, run.reports.limits, &group, term, middle_report.scratch_full);
    return term;
}

/// The highest real-time signal number.
const max_signal: u32 = 64;

pub fn signal(handle: *const iface.Handle, sig: u32) iface.SignalError!void {
    const fd = handle.fd() orelse return error.NoHandle;
    if (sig > max_signal) return error.Unexpected;
    const rc = linux.pidfd_send_signal(fd, @fromBackingInt(@intCast(sig)), null, 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        .SRCH => error.Gone,
        else => error.Unexpected,
    };
}

pub fn close(handle: *iface.Handle) void {
    const fd = handle.fd() orelse return;
    _ = linux.close(fd);
    @atomicStore(i32, &handle.raw_fd, -1, .release);
}

const PollKind = enum { serve, wakeup };

const PollSlot = struct {
    channel: usize,
    kind: PollKind,
};

fn dropChannel(
    channel: usize,
    pairs: []Pair,
    slots: []const PollSlot,
    fds: []linux.pollfd,
) void {
    if (pairs[channel][0] >= 0) _ = linux.close(pairs[channel][0]);
    pairs[channel][0] = -1;
    for (slots, fds[1..][0..slots.len]) |slot, *entry| {
        if (slot.channel == channel) entry.fd = -1;
    }
}

/// Answers the parent end of each channel until the sandboxed process ends.
/// The process descriptor stays at `fds[0]` for the whole loop: a channel that
/// is done only closes itself, and a wakeup-only channel is never done.
fn serveChannels(pid: linux.pid_t, channels: []const iface.Channel, pairs: []Pair) SpawnError!void {
    std.debug.assert(channels.len == pairs.len);
    std.debug.assert(channels.len <= iface.max_channels);

    const watch_rc = linux.pidfd_open(pid, 0);
    if (linux.errno(watch_rc) != .SUCCESS) return error.Unexpected;
    const watch: i32 = @intCast(watch_rc);
    defer _ = linux.close(watch);

    var fds: [1 + 2 * iface.max_channels]linux.pollfd = undefined;
    var slots: [2 * iface.max_channels]PollSlot = undefined;
    var served: [iface.max_channels]u32 = @splat(0);

    fds[0] = .{ .fd = watch, .events = linux.POLL.IN, .revents = 0 };
    var slot_count: usize = 0;
    for (channels, pairs, 0..) |channel, pair, index| {
        if (channel.serve != null) {
            fds[1 + slot_count] = .{ .fd = pair[0], .events = linux.POLL.IN, .revents = 0 };
            slots[slot_count] = .{ .channel = index, .kind = .serve };
            slot_count += 1;
        }
        if (channel.wakeup) |wakeup| {
            fds[1 + slot_count] = .{ .fd = wakeup.fd, .events = linux.POLL.IN, .revents = 0 };
            slots[slot_count] = .{ .channel = index, .kind = .wakeup };
            slot_count += 1;
        }
    }

    const gone = linux.POLL.HUP | linux.POLL.ERR | linux.POLL.NVAL;
    while (true) {
        const ready = linux.poll(&fds, 1 + slot_count, -1);
        switch (linux.errno(ready)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return,
        }

        for (slots[0..slot_count], 0..) |slot, k| {
            const entry = &fds[1 + k];
            if (entry.fd < 0) continue;
            const revents = entry.revents;
            if (revents == 0) continue;
            const channel = channels[slot.channel];
            const parent_fd = pairs[slot.channel][0];

            if (revents & linux.POLL.IN == 0) {
                if (revents & gone != 0) {
                    if (slot.kind == .serve and channel.wakeup == null) {
                        dropChannel(slot.channel, pairs, slots[0..slot_count], &fds);
                    } else {
                        entry.fd = -1;
                    }
                }
                continue;
            }

            switch (slot.kind) {
                .serve => {
                    const serve = channel.serve.?;
                    const result = serve.call(channel.ptr, parent_fd);
                    served[slot.channel] += 1;
                    if (result == .done) {
                        dropChannel(slot.channel, pairs, slots[0..slot_count], &fds);
                    } else if (served[slot.channel] >= serve.max_requests) {
                        if (channel.wakeup == null) {
                            dropChannel(slot.channel, pairs, slots[0..slot_count], &fds);
                        } else {
                            entry.fd = -1;
                        }
                    }
                },
                .wakeup => {
                    const wakeup = channel.wakeup.?;
                    const result = wakeup.drain(channel.ptr, parent_fd);
                    if (result == .done) {
                        dropChannel(slot.channel, pairs, slots[0..slot_count], &fds);
                    }
                },
            }
        }

        if (fds[0].revents != 0) return;
    }
}

/// Puts each channel end on its own number, `iface.channelFd(i)`, with
/// close-on-exec off. A descriptor that sits on a channel number but does not
/// belong there moves above the channel range and keeps close-on-exec. The
/// channel numbers never move, because the helper filters name them.
fn placeChannelFds(ends: []const i32, write_fd: *i32, others: []const *i32, report_fd: i32) void {
    std.debug.assert(ends.len <= iface.max_channels);
    var slots: [iface.max_channels]i32 = undefined;
    for (slots[0..ends.len], 0..) |*slot, index| slot.* = iface.channelFd(index);
    placeFds(ends, slots[0..ends.len], write_fd, others, report_fd);
}

fn placeFds(ends: []const i32, slots: []const i32, write_fd: *i32, others: []const *i32, report_fd: i32) void {
    std.debug.assert(ends.len == slots.len);
    if (ends.len == 0) return;

    const above = std.mem.max(i32, slots) + 1;

    var current: [iface.max_channels]i32 = undefined;
    @memcpy(current[0..ends.len], ends);

    if (std.mem.indexOfScalar(i32, slots, write_fd.*) != null) {
        write_fd.* = moveAbove(write_fd.*, above, write_fd.*, report_fd);
    }
    for (others) |other| {
        if (std.mem.indexOfScalar(i32, slots, other.*) != null) {
            other.* = moveAbove(other.*, above, write_fd.*, report_fd);
        }
    }
    for (current[0..ends.len], slots) |*end, target| {
        if (end.* != target and std.mem.indexOfScalar(i32, slots, end.*) != null) {
            end.* = moveAbove(end.*, above, write_fd.*, report_fd);
        }
    }

    for (current[0..ends.len], slots) |end, target| {
        if (end != target) {
            const dup_errno = linux.errno(linux.dup2(end, target));
            if (dup_errno != .SUCCESS) {
                dieErrno(write_fd.*, report_fd, .channel, "dup2 onto a channel descriptor", dup_errno);
            }
            _ = linux.close(end);
        }
        const flag_errno = linux.errno(linux.fcntl(target, linux.F.SETFD, 0));
        if (flag_errno != .SUCCESS) {
            dieErrno(
                write_fd.*,
                report_fd,
                .channel,
                "fcntl to clear close-on-exec on a channel descriptor",
                flag_errno,
            );
        }
    }
}

fn moveAbove(fd: i32, above: i32, write_fd: i32, report_fd: i32) i32 {
    const moved = linux.fcntl(fd, linux.F.DUPFD_CLOEXEC, @intCast(above));
    const moved_errno = linux.errno(moved);
    if (moved_errno != .SUCCESS) {
        dieErrno(write_fd, report_fd, .channel, "fcntl to move a descriptor off the channel range", moved_errno);
    }
    _ = linux.close(fd);
    return @intCast(moved);
}

const HelperWatch = struct {
    pid: linux.pid_t,
};

const helper_ready_fd = iface.helper_ready_fd;

/// The filter a helper gets. Palisade builds it, so the helper cannot widen it.
fn helperFilter(allocator: std.mem.Allocator, helper: iface.Helper) ![]bpf.Insn {
    var fds: [1 + iface.max_keep_fds]i32 = undefined;
    var count: usize = 0;
    if (helper.channel) |index| {
        fds[0] = iface.channelFd(index);
        count = 1;
    }
    for (helper.keep_fds) |fd| {
        fds[count] = fd;
        count += 1;
    }
    return seccomp.buildHelper(allocator, helper.allowed, fds[0..count], helper_ready_fd);
}

/// Runs in a forked helper. One byte on the ready descriptor tells the middle
/// process that the filter is on.
fn runHelper(
    helper: iface.Helper,
    filter: []const bpf.Insn,
    channel_end: i32,
    ready_fd_in: i32,
    middle_pidfd: i32,
    write_fd_in: i32,
    stderr_fd_in: i32,
    hide: bool,
) noreturn {
    var write_fd = write_fd_in;
    var stderr_fd = stderr_fd_in;

    armPdeathsig(write_fd, stderr_fd, middle_pidfd);

    var channel_number: ?i32 = null;
    var ends: [2]i32 = undefined;
    var slots: [2]i32 = undefined;
    var keep: [3 + iface.max_keep_fds]i32 = undefined;
    var count: usize = 0;
    if (helper.channel) |index| {
        const target = iface.channelFd(index);
        ends[count] = channel_end;
        slots[count] = target;
        count += 1;
        channel_number = target;
        keep[0] = target;
    }
    ends[count] = ready_fd_in;
    slots[count] = helper_ready_fd;
    count += 1;
    placeFds(ends[0..count], slots[0..count], &write_fd, &.{&stderr_fd}, stderr_fd);
    keep[count - 1] = helper_ready_fd;
    keep[count] = stderr_fd;
    var kept = count + 1;
    for (helper.keep_fds) |fd| {
        std.debug.assert(std.mem.indexOfScalar(i32, slots[0..count], fd) == null);
        keep[kept] = fd;
        kept += 1;
    }
    afterfork.keepOnlyDescriptors(keep[0..kept]);

    // The filter goes on last. It kills capset, setuid and setgid, which the steps before it need.
    becomeHelper(hide, stderr_fd);

    var cap_diag: ?capabilities.Diagnostic = null;
    const dropped = if (helper.keep_capability) |capability|
        capabilities.keepOnly(capability, &cap_diag)
    else
        capabilities.dropAll(&cap_diag);
    dropped catch linux.exit_group(1);
    seccomp.install(bpf.Prog.init(filter), null) catch linux.exit_group(1);

    const ready = [1]u8{1};
    const said = linux.write(helper_ready_fd, &ready, ready.len);
    if (linux.errno(said) != .SUCCESS or said != ready.len) linux.exit_group(1);
    if (linux.errno(linux.close(helper_ready_fd)) != .SUCCESS) linux.exit_group(1);

    linux.exit_group(helper.run(helper.ptr, channel_number));
}

const max_scratch_areas = 4;

const ScratchAreas = struct {
    fds: [max_scratch_areas]i32 = @splat(-1),
    count: usize = 0,

    fn anyFull(self: *const ScratchAreas) bool {
        for (self.fds[0..self.count]) |fd| {
            if (namespace.scratchIsFull(fd)) return true;
        }
        return false;
    }
};

fn mountScratchAreas(config: Config, write_fd: i32) ScratchAreas {
    var areas = ScratchAreas{};
    if (config.scratch.len > max_scratch_areas) {
        dieErrno(
            write_fd,
            config.stderr_fd,
            .scratch_mount,
            "too many scratch areas for one call",
            .@"2BIG",
        );
    }
    for (config.scratch) |area| {
        var diag: ?namespace.Diagnostic = null;
        const fd = namespace.mountScratch(
            config.root,
            area.target,
            config.limits.scratch_bytes,
            &diag,
        ) catch |err| dieNamespace(write_fd, config.stderr_fd, .scratch_mount, err, diag);
        areas.fds[areas.count] = fd;
        areas.count += 1;
    }
    return areas;
}

const record_bytes = 10;

const tag_scratch_full: u8 = 0xD1;

const tag_middle_layer: u8 = 0xD2;

const middle_layer_count: usize = blk: {
    var found: usize = 0;
    for (std.enums.values(iface.LayerName)) |layer| {
        if (iface.failModeFor(.supervisor, layer) != null) found += 1;
    }
    break :blk found;
};

const tag_traps_observed: u8 = 0xD3;

const tag_trap_count: u8 = 0xD4;

const TrapState = enum {
    unasked,
    observed,
    unobserved,
};

const MiddleReport = struct {
    scratch_full: bool = false,
    layers: std.EnumArray(iface.LayerName, iface.SupervisorAudit.Outcome) =
        .initFill(.unsaid),
    traps: TrapState = .unasked,
    trap_counts: notify.Counts = notify.empty_counts,
};

fn writeMiddleRecord(middle_write_fd: i32, tag: u8, slot: u8, value: u64) void {
    var record: [record_bytes]u8 = undefined;
    record[0] = tag;
    record[1] = slot;
    std.mem.writeInt(u64, record[2..record_bytes], value, .little);
    _ = linux.write(middle_write_fd, &record, record.len);
}

fn reportScratch(areas: *const ScratchAreas, middle_write_fd: i32) void {
    if (!areas.anyFull()) return;
    writeMiddleRecord(middle_write_fd, tag_scratch_full, 0, 1);
}

fn reportMiddleLayer(
    middle_write_fd: i32,
    layer: iface.LayerName,
    fault: ?iface.SupervisorAudit.Fault,
) void {
    const value: u8 = if (fault) |one| @backingInt(one) else 0;
    writeMiddleRecord(middle_write_fd, tag_middle_layer, @backingInt(layer), value);
}

fn reportTraps(middle_write_fd: i32, counts: ?*const notify.Counts) void {
    writeMiddleRecord(middle_write_fd, tag_traps_observed, 0, if (counts == null) 0 else 1);
    const seen = counts orelse return;
    for (seen, 0..) |count, slot| {
        if (count == 0) continue;
        writeMiddleRecord(middle_write_fd, tag_trap_count, @intCast(slot), count);
    }
}

fn filterFaultFor(err: seccomp.Error) iface.SupervisorAudit.Fault {
    return switch (err) {
        error.NotSupported => .not_supported,
        error.NoNewPrivsRefused => .no_new_privs_refused,
        error.NotPermitted => .not_permitted,
        error.Rejected => .rejected,
        error.Unexpected => .unexpected,
    };
}

fn landlockFaultFor(err: landlock.RulesetError) iface.SupervisorAudit.Fault {
    return switch (err) {
        error.NotSupported => .not_supported,
        error.Rejected,
        error.PathNotFound,
        error.AccessDenied,
        error.NotADirectory,
        error.PathTooLong,
        => .rejected,
        error.Unexpected => .unexpected,
    };
}

fn capabilitiesFaultFor(err: capabilities.Error) iface.SupervisorAudit.Fault {
    return switch (err) {
        error.Rejected => .rejected,
    };
}

fn outcomeFor(value: u8) iface.SupervisorAudit.Outcome {
    if (value == 0) return .on;
    const fault = std.enums.fromInt(iface.SupervisorAudit.Fault, value) orelse .unexpected;
    return .{ .off = fault };
}

fn readMiddleReport(middle_read_fd: i32) MiddleReport {
    var buffer: [record_bytes * 2 * (2 + middle_layer_count + notify.call_count)]u8 = undefined;
    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(middle_read_fd, buffer[filled..].ptr, buffer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        filled += rc;
    }

    var report = MiddleReport{};
    var at: usize = 0;
    while (at + record_bytes <= filled) : (at += record_bytes) {
        const slot = buffer[at + 1];
        const value = std.mem.readInt(u64, buffer[at + 2 ..][0..8], .little);
        switch (buffer[at]) {
            tag_scratch_full => report.scratch_full = value != 0,
            tag_middle_layer => if (std.enums.fromInt(iface.LayerName, slot)) |layer| {
                report.layers.set(layer, outcomeFor(@truncate(value)));
            },
            tag_traps_observed => report.traps = if (value != 0) .observed else .unobserved,
            tag_trap_count => if (slot < notify.call_count) {
                report.trap_counts[slot] = value;
            },
            else => {},
        }
    }
    return report;
}

fn reportLimitOutcome(
    config: Config,
    limits_report: ?*LimitsReport,
    group: *cgroup.Cgroup,
    term: std.process.Child.Term,
    scratch_full: bool,
) void {
    const events = group.readEvents();

    var killed_by: ?rlimits.Diagnostic.Which = null;
    switch (term) {
        .signal => |sig| {
            killed_by = rlimits.limitForSignal(sig);
            if (killed_by == null and events.oom_kills > 0) killed_by = .memory;
        },
        else => {},
    }

    if (killed_by == null and scratch_full and endedBadly(term)) killed_by = .scratch_space;

    const report = LimitsReport{
        .limits = config.limits,
        .cgroup = group.support,
        .nproc_applied = if (limits_report) |slot| slot.nproc_applied else false,
        .events = events,
        .scratch_full = scratch_full,
        .killed_by = killed_by,
    };
    if (limits_report) |slot| slot.* = report;

    var buffer: [256]u8 = undefined;
    if (report.killedText(&buffer)) |sentence| {
        var line: [320]u8 = undefined;
        writeStderr(fileno_stderr, std.fmt.bufPrint(&line, "sandbox: {s}\n", .{sentence}) catch
            "sandbox: a resource limit stopped the program\n");
        return;
    }
    if (events.fork_refusals > 0) {
        var line: [320]u8 = undefined;
        writeStderr(fileno_stderr, std.fmt.bufPrint(
            &line,
            "sandbox: {d} fork(s) were refused by the limit of {?d} processes\n",
            .{ events.fork_refusals, config.limits.processes },
        ) catch "sandbox: a fork was refused by the process limit\n");
    }
}

fn endedBadly(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code != 0,
        else => true,
    };
}

fn joinCgroup(group: *cgroup.Cgroup, write_fd: i32, stderr_fd: i32) void {
    if (group.join()) |join_errno| {
        dieErrno(write_fd, stderr_fd, .cgroup_join, "write to cgroup.procs", join_errno);
    }
    group.closeProcsFd();
}

fn readSetupReport(read_fd: i32) SpawnError!?SetupFailureRecord {
    var buffer: [@sizeOf(SetupFailureRecord)]u8 = undefined;
    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(read_fd, buffer[filled..].ptr, buffer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS) return error.Unexpected;
        if (rc == 0) break;
        filled += rc;
    }
    if (filled == 0) return null;
    if (filled != buffer.len) return error.UntrustedSetupReport;

    var extra: [1]u8 = undefined;
    while (true) {
        const rc = linux.read(read_fd, &extra, 1);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS) return error.Unexpected;
        if (rc != 0) return error.UntrustedSetupReport;
        break;
    }

    const record = std.mem.bytesToValue(SetupFailureRecord, &buffer);
    if (record.magic != setup_failure_magic) return error.UntrustedSetupReport;
    return record;
}

fn setupErrorFor(step: SetupStep) SetupError {
    return switch (step) {
        .stdin_redirect => error.StdinRedirectFailed,
        .process_group => error.ProcessGroupFailed,
        .close_fds => error.CloseFdsFailed,
        .cgroup_join => error.CgroupJoinFailed,
        .resource_limits => error.ResourceLimitFailed,
        .namespace => error.NamespaceFailed,
        .network => error.NamespaceFailed,
        .channel => error.ChannelFailed,
        .helper => error.HelperFailed,
        .scratch_mount => error.ScratchMountFailed,
        .mount_tree => error.MountTreeFailed,
        .pivot => error.PivotFailed,
        .capabilities => error.CapabilitiesFailed,
        .landlock_init => error.LandlockInitFailed,
        .landlock_rule => error.LandlockRuleFailed,
        .landlock_restrict => error.LandlockRestrictFailed,
        .session_keyring => error.SessionKeyringFailed,
        .seccomp_install => error.SeccompInstallFailed,
        .notify_handover => error.NotifyHandoverFailed,
        .fork => error.ForkFailed,
        .pdeathsig_pidfd, .pdeathsig_prctl => error.PdeathsigSetupFailed,
        .exec => error.ExecFailed,
    };
}

fn writeStderr(stderr_fd: i32, line: []const u8) void {
    _ = linux.write(stderr_fd, line.ptr, line.len);
}

fn printFault(stderr_fd: i32, err: anyerror) void {
    var buffer: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buffer, "sandbox: {s}\n", .{@errorName(err)}) catch
        "sandbox: an error occurred, and its name was too long to print\n";
    writeStderr(stderr_fd, line);
}

fn printDenyTargetSymlinkFault(stderr_fd: i32) void {
    writeStderr(
        stderr_fd,
        "sandbox: a denied path names a symbolic link, and it will not be followed. Name the real file, not a link to it.\n",
    );
}

fn printBindSourceSymlinkFault(stderr_fd: i32) void {
    writeStderr(
        stderr_fd,
        "sandbox: a bind mount source names a symbolic link, and it will not be followed. Name the real path, not a link to it.\n",
    );
}

fn printBindTargetSymlinkFault(stderr_fd: i32) void {
    writeStderr(
        stderr_fd,
        "sandbox: a bind mount target names a symbolic link, and it will not be followed. Name the real path, not a link to it.\n",
    );
}

fn printFaultErrno(stderr_fd: i32, comptime what: []const u8, err: linux.E) void {
    var buffer: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buffer, "sandbox: {s} failed: {s}\n", .{ what, @tagName(err) }) catch
        "sandbox: a step failed, and its name was too long to print\n";
    writeStderr(stderr_fd, line);
}

fn reportSetupFailure(write_fd: i32, step: SetupStep, errno_value: i32) void {
    const record = SetupFailureRecord{ .step = @backingInt(step), .errno = errno_value };
    const bytes = std.mem.asBytes(&record);
    _ = linux.write(write_fd, bytes.ptr, bytes.len);
}

fn die(write_fd: i32, stderr_fd: i32, step: SetupStep, err: anyerror) noreturn {
    reportSetupFailure(write_fd, step, 0);
    printFault(stderr_fd, err);
    std.process.exit(1);
}

fn dieNamespace(
    write_fd: i32,
    stderr_fd: i32,
    step: SetupStep,
    err: anyerror,
    diag: ?namespace.Diagnostic,
) noreturn {
    if (diag) |d| {
        reportSetupFailure(write_fd, step, @backingInt(d.errno));
        var buffer: [std.fs.max_path_bytes + 128]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "sandbox: {f}\n", .{d}) catch
            "sandbox: a mount failed, and the reason was too long to print\n";
        writeStderr(stderr_fd, line);
    } else if (err == error.DenyTargetIsSymlink) {
        reportSetupFailure(write_fd, step, 0);
        printDenyTargetSymlinkFault(stderr_fd);
    } else if (err == error.BindSourceIsSymlink) {
        reportSetupFailure(write_fd, step, 0);
        printBindSourceSymlinkFault(stderr_fd);
    } else if (err == error.BindTargetIsSymlink) {
        reportSetupFailure(write_fd, step, 0);
        printBindTargetSymlinkFault(stderr_fd);
    } else {
        reportSetupFailure(write_fd, step, 0);
        printFault(stderr_fd, err);
    }
    std.process.exit(1);
}

fn dieLandlock(
    write_fd: i32,
    stderr_fd: i32,
    step: SetupStep,
    err: anyerror,
    diag: ?landlock.Diagnostic,
) noreturn {
    if (diag) |d| {
        reportSetupFailure(write_fd, step, @backingInt(d.errno));
        var buffer: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "sandbox: {f}\n", .{d}) catch
            "sandbox: a landlock call failed, and the reason was too long to print\n";
        writeStderr(stderr_fd, line);
    } else {
        reportSetupFailure(write_fd, step, 0);
        printFault(stderr_fd, err);
    }
    std.process.exit(1);
}

fn dieCapabilities(
    write_fd: i32,
    stderr_fd: i32,
    err: anyerror,
    diag: ?capabilities.Diagnostic,
) noreturn {
    if (diag) |d| {
        reportSetupFailure(write_fd, .capabilities, @backingInt(d.errno));
        var buffer: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "sandbox: {f}\n", .{d}) catch
            "sandbox: dropping capabilities failed, and the reason was too long to print\n";
        writeStderr(stderr_fd, line);
    } else {
        reportSetupFailure(write_fd, .capabilities, 0);
        printFault(stderr_fd, err);
    }
    std.process.exit(1);
}

fn dieLimit(write_fd: i32, stderr_fd: i32, err: anyerror, diag: ?rlimits.Diagnostic) noreturn {
    if (diag) |d| {
        reportSetupFailure(write_fd, .resource_limits, @backingInt(d.errno));
        var buffer: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "sandbox: {f}\n", .{d}) catch
            "sandbox: a resource limit failed, and the reason was too long to print\n";
        writeStderr(stderr_fd, line);
    } else {
        reportSetupFailure(write_fd, .resource_limits, 0);
        printFault(stderr_fd, err);
    }
    std.process.exit(1);
}

fn dieSeccomp(write_fd: i32, stderr_fd: i32, err: anyerror, diag: ?seccomp.Diagnostic) noreturn {
    if (diag) |d| {
        reportSetupFailure(write_fd, .seccomp_install, d.errno);
        var buffer: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "sandbox: seccomp: {f}\n", .{d}) catch
            "sandbox: a seccomp call failed, and the reason was too long to print\n";
        writeStderr(stderr_fd, line);
    } else {
        reportSetupFailure(write_fd, .seccomp_install, 0);
        printFault(stderr_fd, err);
    }
    std.process.exit(1);
}

const missing_module_notice =
    "sandbox: this host cannot give a sandbox its own isolated network.\n" ++
    "sandbox: a kernel module it needs is not loaded, and a sandbox cannot load one.\n" ++
    "sandbox: load it on the host and run again:\n" ++
    "sandbox:   modprobe " ++ netns.kernel_module ++ "\n";

fn dieNetwork(write_fd: i32, stderr_fd: i32, err: anyerror, diag: ?netns.Diagnostic) noreturn {
    reportSetupFailure(write_fd, .network, if (diag) |d| d.errno else 0);
    if (err == error.KernelModuleMissing) {
        writeStderr(stderr_fd, missing_module_notice);
    } else if (diag) |d| {
        var buffer: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "sandbox: network: {f}\n", .{d}) catch
            "sandbox: a network call failed, and the reason was too long to print\n";
        writeStderr(stderr_fd, line);
    } else {
        printFault(stderr_fd, err);
    }
    std.process.exit(1);
}

fn configureNetwork(params: netns.Params, write_fd: i32, stderr_fd: i32) void {
    var diag: ?netns.Diagnostic = null;
    var session = netns.Session.open(&diag) catch |err|
        dieNetwork(write_fd, stderr_fd, err, diag);
    _ = session.configure(params, &diag) catch |err|
        dieNetwork(write_fd, stderr_fd, err, diag);
    session.close();
}

fn dieErrno(
    write_fd: i32,
    stderr_fd: i32,
    step: SetupStep,
    comptime what: []const u8,
    err: linux.E,
) noreturn {
    reportSetupFailure(write_fd, step, @backingInt(err));
    printFaultErrno(stderr_fd, what, err);
    std.process.exit(1);
}

fn dieWithErrno(write_fd: i32, stderr_fd: i32, step: SetupStep, errno: i32) noreturn {
    _ = stderr_fd;
    reportSetupFailure(write_fd, step, errno);
    std.process.exit(1);
}

fn dieRelay(err: anyerror) noreturn {
    printFault(fileno_stderr, err);
    std.process.exit(1);
}

fn dieRelayErrno(comptime what: []const u8, err: linux.E) noreturn {
    printFaultErrno(fileno_stderr, what, err);
    std.process.exit(1);
}

fn waitAndRelay(
    pid: linux.pid_t,
    keeper_pid: linux.pid_t,
    helpers: []const HelperWatch,
    keeper_fd: i32,
    areas: *const ScratchAreas,
    middle_write_fd: i32,
    reader: ?ReaderWatch,
) noreturn {
    var status: i32 = undefined;
    var wait_rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(wait_rc) == .INTR) {
        wait_rc = linux.waitpid(pid, &status, 0);
    }
    if (linux.errno(wait_rc) != .SUCCESS) {
        dieRelayErrno("waitpid on the sandboxed program", linux.errno(wait_rc));
    }

    if (reader) |watch| reapReader(watch, middle_write_fd);

    reapHelpers(helpers);

    _ = linux.close(keeper_fd);
    var keeper_status: i32 = undefined;
    var keeper_wait_rc = linux.waitpid(keeper_pid, &keeper_status, 0);
    while (linux.errno(keeper_wait_rc) == .INTR) {
        keeper_wait_rc = linux.waitpid(keeper_pid, &keeper_status, 0);
    }
    if (linux.errno(keeper_wait_rc) != .SUCCESS or !linux.W.IFEXITED(@bitCast(keeper_status)) or
        linux.W.EXITSTATUS(@bitCast(keeper_status)) != 0)
    {
        dieRelay(error.Unexpected);
    }

    reportScratch(areas, middle_write_fd);

    if (linux.W.IFSIGNALED(@bitCast(status))) {
        const sig = linux.W.TERMSIG(@bitCast(status));
        _ = linux.tkill(linux.gettid(), sig);
        dieRelay(error.Unexpected);
    }

    std.process.exit(linux.W.EXITSTATUS(@bitCast(status)));
}

const helper_drain_tries: usize = 500;
const helper_drain_step_ns: isize = 1_000_000;

/// Ends the helpers after the sandboxed program is gone. Each helper first
/// gets SIGTERM and a short time to leave. Then it gets SIGKILL.
fn reapHelpers(watches: []const HelperWatch) void {
    for (watches) |watch| {
        if (watch.pid <= 0) continue;
        const term_errno = linux.errno(linux.kill(watch.pid, .TERM));
        switch (term_errno) {
            .SUCCESS, .SRCH => {},
            else => dieRelayErrno("end a helper", term_errno),
        }
    }
    for (watches) |watch| {
        if (watch.pid <= 0) continue;
        reapHelper(watch.pid);
    }
}

fn reapHelper(pid: linux.pid_t) void {
    var status: i32 = undefined;
    var rc: usize = 0;
    var tries: usize = 0;
    while (tries < helper_drain_tries) : (tries += 1) {
        rc = linux.waitpid(pid, &status, linux.W.NOHANG);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc != 0) return,
            .INTR => continue,
            else => break,
        }
        var pause: linux.timespec = .{ .sec = 0, .nsec = helper_drain_step_ns };
        _ = linux.nanosleep(&pause, null);
    }

    const kill_errno = linux.errno(linux.kill(pid, .KILL));
    switch (kill_errno) {
        .SUCCESS, .SRCH => {},
        else => dieRelayErrno("end a helper", kill_errno),
    }
    rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(pid, &status, 0);
    if (linux.errno(rc) != .SUCCESS) {
        dieRelayErrno("waitpid on a helper", linux.errno(rc));
    }
}

fn askForMaps(fd: i32, write_fd: i32, stderr_fd: i32) void {
    const ask = [1]u8{1};
    var write_rc = linux.write(fd, &ask, ask.len);
    while (linux.errno(write_rc) == .INTR) write_rc = linux.write(fd, &ask, ask.len);
    if (linux.errno(write_rc) != .SUCCESS or write_rc != ask.len) {
        dieErrno(write_fd, stderr_fd, .namespace, "asking for the second user", linux.errno(write_rc));
    }

    var answer: [1]u8 = undefined;
    var read_rc = linux.read(fd, &answer, answer.len);
    while (linux.errno(read_rc) == .INTR) read_rc = linux.read(fd, &answer, answer.len);
    if (linux.errno(read_rc) != .SUCCESS or read_rc != answer.len or answer[0] != 1) {
        writeStderr(
            stderr_fd,
            "sandbox: the second user this call hides its helpers behind could not be mapped.\n",
        );
        dieErrno(write_fd, stderr_fd, .namespace, "waiting for the second user", linux.errno(read_rc));
    }
    _ = linux.close(fd);
}

fn mapForChild(fd: i32, pid: linux.pid_t) void {
    var asked: [1]u8 = undefined;
    var read_rc = linux.read(fd, &asked, asked.len);
    while (linux.errno(read_rc) == .INTR) read_rc = linux.read(fd, &asked, asked.len);
    if (linux.errno(read_rc) != .SUCCESS or read_rc != asked.len) return;

    var diag: ?namespace.Diagnostic = null;
    const ok = if (namespace.writeIdMapsFor(
        pid,
        linux.getuid(),
        linux.getgid(),
        true,
        &diag,
    )) |_| true else |_| false;

    const answer = [1]u8{if (ok) 1 else 0};
    var write_rc = linux.write(fd, &answer, answer.len);
    while (linux.errno(write_rc) == .INTR) write_rc = linux.write(fd, &answer, answer.len);
}

fn becomeHelper(hide: bool, stderr_fd: i32) void {
    if (!hide) return;
    var diag: ?capabilities.Diagnostic = null;
    capabilities.becomeUser(
        linux.getuid() + namespace.helper_id_offset,
        linux.getgid() + namespace.helper_id_offset,
        &diag,
    ) catch {
        writeStderr(stderr_fd, "sandbox: a helper could not become the user that hides it.\n");
        linux.exit(1);
    };
}

fn runKeeper(
    control_fd: i32,
    middle_pidfd: i32,
    write_fd: i32,
    stderr_fd: i32,
    insns: []const bpf.Insn,
    hide: bool,
) noreturn {
    armPdeathsig(write_fd, stderr_fd, middle_pidfd);
    keepOnlyDescriptors(control_fd, control_fd);

    becomeHelper(hide, stderr_fd);

    var cap_diag: ?capabilities.Diagnostic = null;
    capabilities.dropAll(&cap_diag) catch linux.exit(1);
    seccomp.install(bpf.Prog.init(insns), null) catch linux.exit(1);

    const ready = [1]u8{1};
    if (linux.errno(linux.write(control_fd, &ready, ready.len)) != .SUCCESS) linux.exit(1);

    var watched = [1]linux.pollfd{.{ .fd = control_fd, .events = linux.POLL.IN, .revents = 0 }};
    while (true) {
        var status: i32 = undefined;
        while (true) {
            const wait_rc = linux.waitpid(-1, &status, linux.W.NOHANG);
            switch (linux.errno(wait_rc)) {
                .SUCCESS => if (wait_rc == 0) break,
                .INTR => continue,
                .CHILD => break,
                else => linux.exit(1),
            }
        }

        watched[0].revents = 0;
        var pause: linux.timespec = .{ .sec = 0, .nsec = 10_000_000 };
        const poll_rc = linux.ppoll(&watched, watched.len, &pause, null);
        switch (linux.errno(poll_rc)) {
            .SUCCESS => if (watched[0].revents != 0) linux.exit(0),
            .INTR => {},
            else => linux.exit(1),
        }
    }
}

fn enterNamespaces(
    config: Config,
    write_fd: i32,
    middle_write_fd: i32,
    channel_fds: []const i32,
    map_fd: i32,
    kept_fds: []const i32,
) void {
    closeInheritedFds(
        write_fd,
        middle_write_fd,
        config.stdout_fd,
        config.stderr_fd,
        config.stdin_fd,
        channel_fds,
        map_fd,
        kept_fds,
    );

    var diag: ?namespace.Diagnostic = null;
    namespace.enter(.{
        .new_net = switch (config.network) {
            .none, .isolated => true,
            .host => false,
        },
        .mount = true,
        .helper_user = config.hide_helpers,
        .map_from_parent = config.hide_helpers,
    }, &diag) catch |err|
        dieNamespace(write_fd, config.stderr_fd, .namespace, err, diag);

    if (config.hide_helpers) askForMaps(map_fd, write_fd, config.stderr_fd);
}

const applied_by_b = [_]iface.LayerName{
    .mount_tree,
    .pivot_root,
    .capabilities,
    .landlock,
    .session_keyring,
    .seccomp,
};

fn applyLayers(
    allocator: std.mem.Allocator,
    config: Config,
    abi: i32,
    insns: []const bpf.Insn,
    write_fd: i32,
    notify_fd: i32,
) void {
    comptime {
        for (applied_by_b) |layer| {
            if (iface.failModeFor(.sandboxed, layer) != .closed) @compileError(
                "sandbox: applyLayers ends the process on every fault, so every layer it " ++
                    "applies must fail closed",
            );
        }
    }

    var diag: ?namespace.Diagnostic = null;
    namespace.buildRoot(
        allocator,
        config.root,
        config.mounts,
        config.hide_helpers,
        config.deny_notice,
        &diag,
    ) catch |err|
        dieNamespace(write_fd, config.stderr_fd, .mount_tree, err, diag);

    for (config.owned_directories) |owned| {
        _ = namespace.ownDirectory(allocator, config.root, owned, &diag) catch |err|
            dieNamespace(write_fd, config.stderr_fd, .mount_tree, err, diag);
    }

    namespace.substitute(allocator, config.root, config.substitutions, &diag) catch |err|
        dieNamespace(write_fd, config.stderr_fd, .mount_tree, err, diag);

    namespace.pivotInto(allocator, config.root, &diag) catch |err|
        dieNamespace(write_fd, config.stderr_fd, .pivot, err, diag);

    var cap_diag: ?capabilities.Diagnostic = null;
    capabilities.dropAll(&cap_diag) catch |err|
        dieCapabilities(write_fd, config.stderr_fd, err, cap_diag);

    var landlock_diag: ?landlock.Diagnostic = null;
    var ruleset = landlock.Ruleset.init(abi, &landlock_diag) catch |err|
        dieLandlock(write_fd, config.stderr_fd, .landlock_init, err, landlock_diag);
    defer ruleset.deinit();
    for (config.rules) |rule| {
        ruleset.allowPath(rule.path, rule.access, &landlock_diag) catch |err|
            dieLandlock(write_fd, config.stderr_fd, .landlock_rule, err, landlock_diag);
    }

    ruleset.restrictSelf(&landlock_diag) catch |err|
        dieLandlock(write_fd, config.stderr_fd, .landlock_restrict, err, landlock_diag);

    // Before the filter: keyctl is a blocked call.
    joinFreshSessionKeyring(config.stderr_fd) catch |err|
        die(write_fd, config.stderr_fd, .session_keyring, err);

    var filter_diag: ?seccomp.Diagnostic = null;
    if (notify_fd < 0) {
        seccomp.install(bpf.Prog.init(insns), &filter_diag) catch |err|
            dieSeccomp(write_fd, config.stderr_fd, err, filter_diag);
        return;
    }

    const listener = seccomp.installListening(bpf.Prog.init(insns), &filter_diag) catch |err|
        dieSeccomp(write_fd, config.stderr_fd, err, filter_diag);

    if (!notify.handOver(notify_fd, listener))
        die(write_fd, config.stderr_fd, .notify_handover, error.Unexpected);
}

const ReaderWatch = struct {
    pid: linux.pid_t,
    record: *notify.PathRecord,
};

fn mapPathRecord() ?*notify.PathRecord {
    const prot: linux.PROT = @bitCast(@as(u32, 0x1 | 0x2));
    const flags: linux.MAP = @bitCast(@as(u32, 0x01 | 0x20));
    const rc = linux.mmap(null, @sizeOf(notify.PathRecord), prot, flags, -1, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const record: *notify.PathRecord = @ptrFromInt(rc);
    record.* = .{};
    return record;
}

fn unmapPathRecord(record: *notify.PathRecord) void {
    _ = linux.munmap(@ptrCast(record), @sizeOf(notify.PathRecord));
}

fn reapReader(watch: ReaderWatch, middle_write_fd: i32) void {
    var status: i32 = undefined;
    const continue_errno = linux.errno(linux.kill(watch.pid, .CONT));
    switch (continue_errno) {
        .SUCCESS, .SRCH => {},
        else => dieRelayErrno("resume the path reader", continue_errno),
    }
    var rc: usize = 0;
    var tries: usize = 0;
    while (tries < 1000) : (tries += 1) {
        rc = linux.waitpid(watch.pid, &status, linux.W.NOHANG);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc != 0) break,
            .INTR => continue,
            else => break,
        }
        var pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&pause, null);
    }
    if (linux.errno(rc) == .SUCCESS and rc == 0) {
        const kill_errno = linux.errno(linux.kill(watch.pid, .KILL));
        switch (kill_errno) {
            .SUCCESS, .SRCH => {},
            else => dieRelayErrno("end the path reader", kill_errno),
        }
        rc = linux.waitpid(watch.pid, &status, 0);
        while (linux.errno(rc) == .INTR) rc = linux.waitpid(watch.pid, &status, 0);
    }

    const ending: ReaderEnd.Ending = if (linux.errno(rc) != .SUCCESS)
        .unknown
    else if (linux.W.IFSIGNALED(@bitCast(status)))
        .signalled
    else
        .{ .exited = linux.W.EXITSTATUS(@bitCast(status)) };
    if (!readerReported(.{
        .ready = watch.record.ready,
        .ended = watch.record.ended,
        .ending = ending,
    })) watch.record.reader_unreported = 1;

    reportTraps(middle_write_fd, &watch.record.counts);
}

pub const ReaderEnd = struct {
    ready: u32,
    ended: u32,
    ending: Ending,

    pub const Ending = union(enum) {
        exited: u32,
        signalled,
        unknown,
    };
};

pub fn readerReported(end: ReaderEnd) bool {
    if (end.ready == 0) return false;
    if (end.ended == 0) return false;
    return switch (end.ending) {
        .exited => |status| status == 0,
        .signalled => true,
        .unknown => false,
    };
}

fn runReader(
    listener: i32,
    child_pidfd: i32,
    reader_insns: []const bpf.Insn,
    record: *notify.PathRecord,
    granted: []const []const u8,
) noreturn {
    keepOnlyDescriptors(listener, child_pidfd);

    var cap_diag: ?capabilities.Diagnostic = null;
    capabilities.keepOnly(linux.CAP.SYS_PTRACE, &cap_diag) catch linux.exit(1);

    seccomp.install(bpf.Prog.init(reader_insns), null) catch linux.exit(1);

    record.ready = 1;
    const outcome = notify.serveRecording(listener, child_pidfd, record, granted);
    record.ended = 1;
    linux.exit(if (outcome == .fault) 1 else 0);
}

fn keepOnlyDescriptors(first: i32, second: i32) void {
    keepOnlyTheseDescriptors(&.{ first, second });
}

const keepOnlyTheseDescriptors = afterfork.keepOnlyDescriptors;

fn restrictMiddle(abi: i32, insns: []const bpf.Insn, middle_write_fd: i32) void {
    var cap_diag: ?capabilities.Diagnostic = null;
    if (capabilities.dropAll(&cap_diag)) |_| {
        middleLayerWent(.capabilities, middle_write_fd, null);
    } else |err| {
        printMiddleCapabilitiesFault(err, cap_diag);
        middleLayerWent(.capabilities, middle_write_fd, capabilitiesFaultFor(err));
    }

    var diag: ?landlock.Diagnostic = null;
    if (landlock.Ruleset.init(abi, &diag)) |ruleset| {
        var owned = ruleset;
        defer owned.deinit();
        if (owned.restrictSelf(&diag)) |_| {
            middleLayerWent(.landlock, middle_write_fd, null);
        } else |err| {
            printMiddleFault(err, diag);
            middleLayerWent(.landlock, middle_write_fd, landlockFaultFor(err));
        }
    } else |err| {
        printMiddleFault(err, diag);
        middleLayerWent(.landlock, middle_write_fd, landlockFaultFor(err));
    }

    if (seccomp.install(bpf.Prog.init(insns), null)) |_| {
        middleLayerWent(.seccomp, middle_write_fd, null);
    } else |err| {
        printMiddleFault(err, null);
        middleLayerWent(.seccomp, middle_write_fd, filterFaultFor(err));
    }
}

fn middleLayerWent(
    comptime layer: iface.LayerName,
    middle_write_fd: i32,
    fault: ?iface.SupervisorAudit.Fault,
) void {
    const mode = comptime iface.failModeFor(.supervisor, layer) orelse @compileError(
        "sandbox: the supervisor reports a layer the fail mode table says it never applies",
    );
    switch (comptime mode) {
        .open => reportMiddleLayer(middle_write_fd, layer, fault),
        .closed => {
            reportMiddleLayer(middle_write_fd, layer, fault);
            if (fault != null) dieRelay(error.Unexpected);
        },
    }
}

fn printMiddleCapabilitiesFault(err: anyerror, diag: ?capabilities.Diagnostic) void {
    var buffer: [256]u8 = undefined;
    const line = if (diag) |d|
        std.fmt.bufPrint(
            &buffer,
            "sandbox: the middle process could not drop its own capabilities: {f}\n",
            .{d},
        ) catch "sandbox: the middle process could not drop its own capabilities\n"
    else
        std.fmt.bufPrint(
            &buffer,
            "sandbox: the middle process could not drop its own capabilities: {s}\n",
            .{@errorName(err)},
        ) catch "sandbox: the middle process could not drop its own capabilities\n";
    writeStderr(fileno_stderr, line);
}

fn printMiddleFault(err: anyerror, diag: ?landlock.Diagnostic) void {
    var buffer: [256]u8 = undefined;
    const line = if (diag) |d|
        std.fmt.bufPrint(
            &buffer,
            "sandbox: the middle process could not restrict itself: {f}\n",
            .{d},
        ) catch "sandbox: the middle process could not restrict itself\n"
    else
        std.fmt.bufPrint(
            &buffer,
            "sandbox: the middle process could not restrict itself: {s}\n",
            .{@errorName(err)},
        ) catch "sandbox: the middle process could not restrict itself\n";
    writeStderr(fileno_stderr, line);
}

pub fn joinFreshSessionKeyring(stderr_fd: i32) iface.KeyringError!void {
    const keyctl_join_session_keyring: usize = 1;
    const rc = linux.syscall2(.keyctl, keyctl_join_session_keyring, 0);
    const join_errno = linux.errno(rc);
    if (join_errno != .SUCCESS) {
        printFaultErrno(stderr_fd, "keyctl(KEYCTL_JOIN_SESSION_KEYRING)", join_errno);
        return error.JoinFailed;
    }
}

const resetSignalState = afterfork.resetSignalState;

fn newProcessGroup(write_fd: i32, stderr_fd: i32) void {
    const rc = linux.setpgid(0, 0);
    const pgid_errno = linux.errno(rc);
    if (pgid_errno != .SUCCESS) {
        dieErrno(
            write_fd,
            stderr_fd,
            .process_group,
            "setpgid into a group of the sandbox's own",
            pgid_errno,
        );
    }
}

fn redirectStdinToDevNull(write_fd: i32, stderr_fd: i32) void {
    const fd_rc = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    const open_errno = linux.errno(fd_rc);
    if (open_errno != .SUCCESS) {
        dieErrno(write_fd, stderr_fd, .stdin_redirect, "open /dev/null for standard input", open_errno);
    }
    const fd: i32 = @intCast(fd_rc);

    const dup2_errno = linux.errno(linux.dup2(fd, fileno_stdin));
    if (dup2_errno != .SUCCESS) {
        dieErrno(write_fd, stderr_fd, .stdin_redirect, "dup2 /dev/null onto standard input", dup2_errno);
    }

    if (fd != fileno_stdin) _ = linux.close(fd);
}

fn closeInheritedFds(
    write_fd: i32,
    middle_write_fd: i32,
    stdout_fd: i32,
    stderr_fd: i32,
    stdin_fd: ?i32,
    channel_fds: []const i32,
    map_fd: i32,
    kept_fds: []const i32,
) void {
    const dir_rc = linux.open(
        "/proc/self/fd",
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    const dir_open_errno = linux.errno(dir_rc);
    if (dir_open_errno != .SUCCESS) {
        dieErrno(write_fd, stderr_fd, .close_fds, "open /proc/self/fd", dir_open_errno);
    }
    const dir_fd: i32 = @intCast(dir_rc);
    defer _ = linux.close(dir_fd);

    var buffer: [4096]u8 = undefined;
    while (true) {
        const nread = linux.getdents64(dir_fd, &buffer, buffer.len);
        const read_errno = linux.errno(nread);
        if (read_errno != .SUCCESS) {
            dieErrno(write_fd, stderr_fd, .close_fds, "read /proc/self/fd", read_errno);
        }
        if (nread == 0) break;

        var offset: usize = 0;
        while (offset < nread) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            const name_offset = offset + @offsetOf(linux.dirent64, "name");
            const name_ptr: [*:0]const u8 = @ptrCast(&buffer[name_offset]);
            const name = std.mem.sliceTo(name_ptr, 0);

            if (std.fmt.parseInt(i32, name, 10)) |fd| {
                if (fd > fileno_stderr and fd != dir_fd and fd != write_fd and
                    fd != middle_write_fd and std.mem.indexOfScalar(i32, channel_fds, fd) == null and
                    fd != map_fd and
                    std.mem.indexOfScalar(i32, kept_fds, fd) == null and
                    fd != stdout_fd and fd != stderr_fd and fd != (stdin_fd orelse -1))
                {
                    const close_errno = linux.errno(linux.close(fd));
                    if (close_errno != .SUCCESS) {
                        dieErrno(
                            write_fd,
                            stderr_fd,
                            .close_fds,
                            "close an inherited descriptor",
                            close_errno,
                        );
                    }
                }
            } else |_| {}

            std.debug.assert(entry.reclen > 0);
            offset += entry.reclen;
        }
    }
}

fn armPdeathsig(write_fd: i32, stderr_fd: i32, middle_pidfd: i32) void {
    const pr_rc = linux.prctl(@backingInt(linux.PR.SET_PDEATHSIG), @backingInt(linux.SIG.KILL), 0, 0, 0);
    const pr_errno = linux.errno(pr_rc);
    if (pr_errno != .SUCCESS) {
        dieErrno(write_fd, stderr_fd, .pdeathsig_prctl, "prctl(PR_SET_PDEATHSIG)", pr_errno);
    }

    var pfd = [1]linux.pollfd{.{ .fd = middle_pidfd, .events = linux.POLL.IN, .revents = 0 }};
    const poll_rc = linux.poll(&pfd, 1, 0);
    const middle_already_gone = linux.errno(poll_rc) == .SUCCESS and poll_rc > 0;
    _ = linux.close(middle_pidfd);

    if (middle_already_gone) {
        _ = linux.tkill(linux.gettid(), .KILL);
        std.process.exit(1);
    }
}

fn execute(
    allocator: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    write_fd_in: i32,
    channel_ends: []const i32,
) noreturn {
    std.debug.assert(argv.len > 0);

    var write_fd = write_fd_in;

    redirectStandardStreams(config, write_fd);

    const stderr_fd = fileno_stderr;

    const cwd_z = allocator.dupeSentinel(u8, config.cwd, 0) catch |err| die(write_fd, stderr_fd, .exec, err);
    const chdir_errno = linux.errno(linux.chdir(cwd_z));
    if (chdir_errno != .SUCCESS) dieErrno(write_fd, stderr_fd, .exec, "chdir", chdir_errno);

    const argv_z = allocator.allocSentinel(?[*:0]const u8, argv.len, null) catch |err|
        die(write_fd, stderr_fd, .exec, err);
    for (argv, 0..) |arg, i| {
        argv_z[i] = allocator.dupeSentinel(u8, arg, 0) catch |err| die(write_fd, stderr_fd, .exec, err);
    }

    const env_z = allocator.allocSentinel(?[*:0]const u8, config.env.len, null) catch |err|
        die(write_fd, stderr_fd, .exec, err);
    for (config.env, 0..) |item, i| {
        env_z[i] = allocator.dupeSentinel(u8, item, 0) catch |err| die(write_fd, stderr_fd, .exec, err);
    }

    placeChannelFds(channel_ends, &write_fd, &.{}, stderr_fd);

    var limit_diag: ?rlimits.Diagnostic = null;
    rlimits.apply(config.limits, rlimits.runningKernel(), &limit_diag) catch |err|
        dieLimit(write_fd, stderr_fd, err, limit_diag);

    const exec_rc = linux.execve(argv_z[0].?, argv_z, env_z);
    dieErrno(write_fd, stderr_fd, .exec, "execve", linux.errno(exec_rc));
}

fn redirectStandardStreams(config: Config, write_fd: i32) void {
    if (config.stdin_fd) |fd| {
        if (fd != fileno_stdin) {
            const dup2_errno = linux.errno(linux.dup2(fd, fileno_stdin));
            if (dup2_errno != .SUCCESS)
                dieErrno(write_fd, config.stderr_fd, .exec, "dup2 onto standard input", dup2_errno);
        }
    }
    if (config.stdout_fd != fileno_stdout) {
        const dup2_errno = linux.errno(linux.dup2(config.stdout_fd, fileno_stdout));
        if (dup2_errno != .SUCCESS)
            dieErrno(write_fd, config.stderr_fd, .exec, "dup2 onto standard output", dup2_errno);
    }
    if (config.stderr_fd != fileno_stderr) {
        const dup2_errno = linux.errno(linux.dup2(config.stderr_fd, fileno_stderr));
        if (dup2_errno != .SUCCESS)
            dieErrno(write_fd, config.stderr_fd, .exec, "dup2 onto standard error", dup2_errno);
    }

    var closed: [3]i32 = @splat(-1);
    var closed_count: usize = 0;
    for ([_]i32{ config.stdout_fd, config.stderr_fd, config.stdin_fd orelse -1 }) |fd| {
        if (fd <= fileno_stderr) continue;
        var seen = false;
        for (closed[0..closed_count]) |other| {
            if (other == fd) seen = true;
        }
        if (seen) continue;
        closed[closed_count] = fd;
        closed_count += 1;
        _ = linux.close(fd);
    }
}

fn absoluteDirPath(buffer: []u8, dir_fd: linux.fd_t) ![:0]u8 {
    var link_buffer: [64]u8 = undefined;
    const link = std.fmt.bufPrintSentinel(&link_buffer, "/proc/self/fd/{d}", .{dir_fd}, 0) catch unreachable;
    const rc = linux.readlink(link, buffer.ptr, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.ReadlinkFailed;
    const len: usize = @intCast(rc);
    buffer[len] = 0;
    return buffer[0..len :0];
}

test "the middle pipe carries the scratch fact and a layer fact, and a reader tells them apart" {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    defer _ = linux.close(fds[0]);

    reportMiddleLayer(fds[1], .seccomp, .no_new_privs_refused);
    writeMiddleRecord(fds[1], tag_scratch_full, 0, 1);
    _ = linux.close(fds[1]);

    const report = readMiddleReport(fds[0]);
    try std.testing.expect(report.scratch_full);
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome{ .off = .no_new_privs_refused },
        report.layers.get(.seccomp),
    );
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome.unsaid,
        report.layers.get(.landlock),
    );
}

test "each layer the supervisor puts on itself comes back under its own name" {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    defer _ = linux.close(fds[0]);

    reportMiddleLayer(fds[1], .capabilities, .rejected);
    reportMiddleLayer(fds[1], .landlock, .not_supported);
    reportMiddleLayer(fds[1], .seccomp, null);
    _ = linux.close(fds[1]);

    const report = readMiddleReport(fds[0]);
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome{ .off = .rejected },
        report.layers.get(.capabilities),
    );
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome{ .off = .not_supported },
        report.layers.get(.landlock),
    );
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome.on,
        report.layers.get(.seccomp),
    );
}

test "a supervisor that said nothing is not a supervisor that was confined" {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    defer _ = linux.close(fds[0]);
    _ = linux.close(fds[1]);

    const report = readMiddleReport(fds[0]);
    try std.testing.expect(!report.scratch_full);
    for (comptime std.enums.values(iface.LayerName)) |layer| {
        try std.testing.expectEqual(
            iface.SupervisorAudit.Outcome.unsaid,
            report.layers.get(layer),
        );
    }
}

test "every way the filter can be refused reaches the reader as its own fault" {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })));
    defer _ = linux.close(fds[0]);

    const errors = [_]seccomp.Error{
        error.NotSupported,
        error.NoNewPrivsRefused,
        error.NotPermitted,
        error.Rejected,
        error.Unexpected,
    };
    var seen: [errors.len]iface.SupervisorAudit.Fault = undefined;
    for (errors, 0..) |err, index| {
        reportMiddleLayer(fds[1], .seccomp, filterFaultFor(err));
        var record: [record_bytes]u8 = undefined;
        const rc = linux.read(fds[0], &record, record.len);
        try std.testing.expectEqual(.SUCCESS, linux.errno(rc));
        try std.testing.expectEqual(@as(usize, record_bytes), rc);
        try std.testing.expectEqual(tag_middle_layer, record[0]);

        try std.testing.expectEqual(
            @as(u8, @backingInt(iface.LayerName.seccomp)),
            record[1],
        );
        const value = std.mem.readInt(u64, record[2..record_bytes], .little);
        switch (outcomeFor(@truncate(value))) {
            .off => |fault| seen[index] = fault,
            .on, .unsaid => return error.TestUnexpectedResult,
        }
    }
    _ = linux.close(fds[1]);

    for (seen, 0..) |fault, index| {
        for (seen[index + 1 ..]) |other| try std.testing.expect(fault != other);
    }
}

test "a layer that went on is the only value byte that reads as confined" {
    try std.testing.expectEqual(iface.SupervisorAudit.Outcome.on, outcomeFor(0));
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome{ .off = .rejected },
        outcomeFor(@backingInt(iface.SupervisorAudit.Fault.rejected)),
    );
    try std.testing.expectEqual(
        iface.SupervisorAudit.Outcome{ .off = .unexpected },
        outcomeFor(200),
    );
}

test "closeInheritedFds closes every descriptor above stderr, and leaves stderr open" {
    const extra_a = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_a));
    const extra_b = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_b));
    defer _ = linux.close(@intCast(extra_a));
    defer _ = linux.close(@intCast(extra_b));

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        closeInheritedFds(-1, -1, -1, -1, null, &.{}, -1, &.{});

        const a_result = linux.fcntl(@intCast(extra_a), linux.F.GETFD, 0);
        const b_result = linux.fcntl(@intCast(extra_b), linux.F.GETFD, 0);
        const stderr_result = linux.fcntl(fileno_stderr, linux.F.GETFD, 0);
        const closed_the_extras = linux.errno(a_result) == .BADF and linux.errno(b_result) == .BADF;
        const kept_stderr = linux.errno(stderr_result) == .SUCCESS;
        std.process.exit(if (closed_the_extras and kept_stderr) 0 else 1);
    }

    var status: i32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(@bitCast(status)));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(@bitCast(status)));
}

test "closeInheritedFds keeps exactly the middle pipe's write end, and no other" {
    const extra_a = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_a));
    const extra_b = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_b));
    defer _ = linux.close(@intCast(extra_a));
    defer _ = linux.close(@intCast(extra_b));

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        closeInheritedFds(-1, @intCast(extra_b), -1, -1, null, &.{}, -1, &.{});

        const a_result = linux.fcntl(@intCast(extra_a), linux.F.GETFD, 0);
        const b_result = linux.fcntl(@intCast(extra_b), linux.F.GETFD, 0);
        const closed_the_other = linux.errno(a_result) == .BADF;
        const kept_the_middle_pipe = linux.errno(b_result) == .SUCCESS;
        std.process.exit(if (closed_the_other and kept_the_middle_pipe) 0 else 1);
    }

    var status: i32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(@bitCast(status)));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(@bitCast(status)));
}

test "closeInheritedFds keeps every channel child end, and no other" {
    var kept: [3]i32 = undefined;
    for (&kept) |*slot| {
        const rc = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
        try std.testing.expectEqual(.SUCCESS, linux.errno(rc));
        slot.* = @intCast(rc);
    }
    const stray_rc = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(stray_rc));
    const stray: i32 = @intCast(stray_rc);
    defer _ = linux.close(stray);
    defer for (kept) |fd| {
        _ = linux.close(fd);
    };

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        closeInheritedFds(-1, -1, -1, -1, null, &kept, -1, &.{});

        var every_channel_kept = true;
        for (kept) |fd| {
            if (linux.errno(linux.fcntl(fd, linux.F.GETFD, 0)) != .SUCCESS) every_channel_kept = false;
        }
        const closed_the_stray = linux.errno(linux.fcntl(stray, linux.F.GETFD, 0)) == .BADF;
        std.process.exit(if (every_channel_kept and closed_the_stray) 0 else 1);
    }

    var status: i32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(@bitCast(status)));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(@bitCast(status)));
}

const o_cloexec: u32 = @bitCast(linux.O{ .CLOEXEC = true });

fn channelPair() !Pair {
    var pair: Pair = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &pair);
    try std.testing.expectEqual(.SUCCESS, linux.errno(rc));
    return pair;
}

const Layout = struct {
    ends: [3]i32,
    write_fd: i32,
};

/// Channel 0's end sits on channel 1's number, channel 1's end on channel 0's,
/// and the setup pipe on channel 2's. Channel 2's end sits outside the range.
fn crossedLayout(pairs: *const [3]Pair, setup_write: i32) ?Layout {
    const low = iface.channelFd(0);
    const sources = [4]i32{ pairs[0][1], pairs[1][1], pairs[2][1], setup_write };
    const targets = [4]i32{ low + 1, low, 20, low + 2 };
    var staged: [4]i32 = undefined;
    for (sources, &staged, 0..) |source, *slot, index| {
        slot.* = 100 + @as(i32, @intCast(index));
        if (linux.errno(linux.dup3(source, slot.*, o_cloexec)) != .SUCCESS) return null;
    }
    for (staged, targets) |from, to| {
        if (linux.errno(linux.dup3(from, to, o_cloexec)) != .SUCCESS) return null;
        _ = linux.close(from);
    }
    return .{ .ends = .{ targets[0], targets[1], targets[2] }, .write_fd = targets[3] };
}

test "every channel end lands on its own number, even with the setup pipe and other ends in the way" {
    var setup: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&setup, .{ .CLOEXEC = true })));
    defer _ = linux.close(setup[0]);
    var pairs = [3]Pair{ try channelPair(), try channelPair(), try channelPair() };
    defer closePairs(&pairs);

    const tokens = [3][]const u8{ "channel-zero", "channel-one", "channel-two" };
    for (pairs, tokens) |pair, token| {
        try std.testing.expectEqual(token.len, linux.write(pair[0], token.ptr, token.len));
    }

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        for (pairs) |pair| _ = linux.close(pair[0]);
        const layout = crossedLayout(&pairs, setup[1]) orelse std.process.exit(10);
        var write_fd = layout.write_fd;

        placeChannelFds(&layout.ends, &write_fd, &.{}, fileno_stderr);

        const first = iface.channelFd(0);
        if (write_fd < first + 3) std.process.exit(11);
        var buffer: [32]u8 = undefined;
        for (tokens, 0..) |token, index| {
            const number = iface.channelFd(index);
            const got = linux.read(number, &buffer, buffer.len);
            if (linux.errno(got) != .SUCCESS or !std.mem.eql(u8, buffer[0..got], token)) {
                std.process.exit(12);
            }
            const flags = linux.fcntl(number, linux.F.GETFD, 0);
            if (linux.errno(flags) != .SUCCESS or flags != 0) std.process.exit(13);
        }
        const moved_flags = linux.fcntl(write_fd, linux.F.GETFD, 0);
        if (linux.errno(moved_flags) != .SUCCESS or (moved_flags & linux.FD_CLOEXEC) == 0) {
            std.process.exit(14);
        }
        const wrote = linux.write(write_fd, "p", 1);
        if (linux.errno(wrote) != .SUCCESS or wrote != 1) std.process.exit(15);
        std.process.exit(0);
    }

    _ = linux.close(setup[1]);
    var status: i32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(@bitCast(status)));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(@bitCast(status)));

    var one_byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), linux.read(setup[0], &one_byte, 1));
    try std.testing.expectEqual(@as(u8, 'p'), one_byte[0]);
}

test "a channel end that already sits on its own number stays there, with close-on-exec cleared" {
    var pair = try channelPair();
    defer closePair(&pair);

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        const zero = iface.channelFd(0);
        if (linux.errno(linux.dup3(pair[1], zero, o_cloexec)) != .SUCCESS) std.process.exit(10);
        var write_fd: i32 = -1;
        placeChannelFds(&.{zero}, &write_fd, &.{}, fileno_stderr);
        const flags = linux.fcntl(zero, linux.F.GETFD, 0);
        if (linux.errno(flags) != .SUCCESS or flags != 0) std.process.exit(11);
        std.process.exit(0);
    }

    var status: i32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(@bitCast(status)));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(@bitCast(status)));
}

const Probe = struct {
    calls: usize = 0,
    drains: usize = 0,
    wake_fd: i32 = -1,
    answer: iface.Channel.ServeResult = .more,

    fn serve(ptr: *anyopaque, fd: i32) iface.Channel.ServeResult {
        const self: *Probe = @ptrCast(@alignCast(ptr));
        var byte: [1]u8 = undefined;
        _ = linux.recvfrom(fd, &byte, byte.len, linux.MSG.DONTWAIT, null, null);
        self.calls += 1;
        return self.answer;
    }

    fn drain(ptr: *anyopaque, _: i32) iface.Channel.ServeResult {
        const self: *Probe = @ptrCast(@alignCast(ptr));
        var count: u64 = 0;
        _ = linux.read(self.wake_fd, std.mem.asBytes(&count), 8);
        self.drains += 1;
        if (self.drains < 5) {
            const one: u64 = 1;
            _ = linux.write(self.wake_fd, std.mem.asBytes(&one), 8);
        }
        return .more;
    }
};

/// A process that sends `messages` packets on `pair[1]`, waits, and exits.
fn forkSender(pair: *Pair, messages: usize) !linux.pid_t {
    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        _ = linux.close(pair[0]);
        for (0..messages) |_| _ = linux.write(pair[1], "x", 1);
        _ = linux.nanosleep(&.{ .sec = 0, .nsec = 300_000_000 }, null);
        std.process.exit(0);
    }
    _ = linux.close(pair[1]);
    pair[1] = -1;
    return @intCast(fork_rc);
}

test "a serve channel is answered up to its budget, then its parent end closes" {
    var pairs = [1]Pair{try channelPair()};
    defer closePairs(&pairs);
    var probe = Probe{};
    const channels = [_]iface.Channel{.{
        .ptr = &probe,
        .serve = .{ .call = Probe.serve, .max_requests = 2 },
        .hands_host_descriptor = false,
    }};

    const pid = try forkSender(&pairs[0], 3);
    try serveChannels(pid, &channels, &pairs);
    reapPid(pid);

    try std.testing.expectEqual(@as(usize, 2), probe.calls);
    try std.testing.expectEqual(@as(i32, -1), pairs[0][0]);
}

test "a channel that answers done is closed, and the loop still ends with the process" {
    var pairs = [1]Pair{try channelPair()};
    defer closePairs(&pairs);
    var probe = Probe{ .answer = .done };
    const channels = [_]iface.Channel{.{
        .ptr = &probe,
        .serve = .{ .call = Probe.serve, .max_requests = 5 },
        .hands_host_descriptor = false,
    }};

    const pid = try forkSender(&pairs[0], 3);
    try serveChannels(pid, &channels, &pairs);
    reapPid(pid);

    try std.testing.expectEqual(@as(usize, 1), probe.calls);
    try std.testing.expectEqual(@as(i32, -1), pairs[0][0]);
}

test "a wakeup is drained without being counted, and the parent end stays open for it" {
    var pairs = [1]Pair{try channelPair()};
    defer closePairs(&pairs);

    const wake_rc = linux.eventfd(1, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wake_rc));
    var probe = Probe{ .wake_fd = @intCast(wake_rc) };
    defer _ = linux.close(probe.wake_fd);
    const channels = [_]iface.Channel{.{
        .ptr = &probe,
        .serve = .{ .call = Probe.serve, .max_requests = 1 },
        .wakeup = .{ .fd = probe.wake_fd, .drain = Probe.drain },
        .hands_host_descriptor = false,
    }};

    const pid = try forkSender(&pairs[0], 3);
    try serveChannels(pid, &channels, &pairs);
    reapPid(pid);

    try std.testing.expectEqual(@as(usize, 1), probe.calls);
    try std.testing.expectEqual(@as(usize, 5), probe.drains);
    try std.testing.expect(pairs[0][0] >= 0);
}

test "a wakeup-only channel never ends the loop, the process does" {
    var pairs = [1]Pair{try channelPair()};
    defer closePairs(&pairs);

    const wake_rc = linux.eventfd(1, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wake_rc));
    var probe = Probe{ .wake_fd = @intCast(wake_rc) };
    defer _ = linux.close(probe.wake_fd);
    const channels = [_]iface.Channel{.{
        .ptr = &probe,
        .wakeup = .{ .fd = probe.wake_fd, .drain = Probe.drain },
        .hands_host_descriptor = false,
    }};

    const pid = try forkSender(&pairs[0], 0);
    try serveChannels(pid, &channels, &pairs);
    reapPid(pid);

    try std.testing.expectEqual(@as(usize, 5), probe.drains);
    try std.testing.expectEqual(@as(usize, 0), probe.calls);
}

fn rejectedFilterRun(_: *anyopaque, _: ?i32) u8 {
    return 0;
}

test "closeInheritedFds keeps the channel the second user is asked for on" {
    const extra_a = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_a));
    const extra_b = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_b));
    defer _ = linux.close(@intCast(extra_a));
    defer _ = linux.close(@intCast(extra_b));

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        closeInheritedFds(-1, -1, -1, -1, null, &.{}, @intCast(extra_b), &.{});

        const a_result = linux.fcntl(@intCast(extra_a), linux.F.GETFD, 0);
        const b_result = linux.fcntl(@intCast(extra_b), linux.F.GETFD, 0);
        const closed_the_other = linux.errno(a_result) == .BADF;
        const kept_the_map_fd = linux.errno(b_result) == .SUCCESS;
        std.process.exit(if (closed_the_other and kept_the_map_fd) 0 else 1);
    }

    var status: i32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(@bitCast(status)));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(@bitCast(status)));
}

test "closeInheritedFds keeps exactly the descriptor Config.stdin_fd names, and no other" {
    const extra_a = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_a));
    const extra_b = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(extra_b));
    defer _ = linux.close(@intCast(extra_a));
    defer _ = linux.close(@intCast(extra_b));

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);

    if (pid == 0) {
        closeInheritedFds(-1, -1, -1, -1, @intCast(extra_b), &.{}, -1, &.{});

        const a_result = linux.fcntl(@intCast(extra_a), linux.F.GETFD, 0);
        const b_result = linux.fcntl(@intCast(extra_b), linux.F.GETFD, 0);
        const closed_the_other = linux.errno(a_result) == .BADF;
        const kept_the_named_one = linux.errno(b_result) == .SUCCESS;
        std.process.exit(if (closed_the_other and kept_the_named_one) 0 else 1);
    }

    var status: i32 = undefined;
    const wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(@bitCast(status)));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(@bitCast(status)));
}

test "spawn reports the Landlock ABI and its features before it ever forks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    var report: LandlockReport = undefined;

    if (!namespace.probeAvailability().available()) return error.SkipZigTest;

    const devnull_rc = linux.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(devnull_rc));
    const devnull: i32 = @intCast(devnull_rc);
    defer _ = linux.close(devnull);

    const saved_stderr_rc = linux.dup(fileno_stderr);
    try std.testing.expectEqual(.SUCCESS, linux.errno(saved_stderr_rc));
    const saved_stderr: i32 = @intCast(saved_stderr_rc);
    defer _ = linux.close(saved_stderr);

    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.dup2(devnull, fileno_stderr)));
    defer _ = linux.dup2(saved_stderr, fileno_stderr);

    const err = spawn(std.testing.allocator, .{
        .root = root_z,
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
    }, &.{"/does-not-exist"}, .{ .reports = .{ .landlock = &report } });

    _ = linux.dup2(saved_stderr, fileno_stderr);

    if (err) |_| {
        return error.TestUnexpectedResult;
    } else |actual_err| {
        if (actual_err == error.LandlockUnavailable) return error.SkipZigTest;
        try std.testing.expectEqual(error.ExecFailed, actual_err);
    }

    try std.testing.expect(report.abi >= 1);
    try std.testing.expectEqual(landlock.featuresFor(report.abi), report.features);
}

test "a failed setup leaves every file under root alone" {
    if (!namespace.probeAvailability().available()) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    var file_path: [std.fs.max_path_bytes]u8 = undefined;
    const keep_z = try std.fmt.bufPrintSentinel(&file_path, "{s}/keep.txt", .{root_z}, 0);
    const contents = "still here";
    const create_rc = linux.open(keep_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0o600);
    try std.testing.expectEqual(.SUCCESS, linux.errno(create_rc));
    const create_fd: i32 = @intCast(create_rc);
    try std.testing.expectEqual(contents.len, linux.write(create_fd, contents, contents.len));
    _ = linux.close(create_fd);

    const devnull_rc = linux.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(devnull_rc));
    const devnull: i32 = @intCast(devnull_rc);
    defer _ = linux.close(devnull);

    const err = spawn(std.testing.allocator, .{
        .root = root_z,
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .stderr_fd = devnull,
    }, &.{"/does-not-exist"}, .{});
    if (err) |_| {
        return error.TestUnexpectedResult;
    } else |actual| {
        if (actual == error.LandlockUnavailable) return error.SkipZigTest;
        try std.testing.expectEqual(error.ExecFailed, actual);
    }

    const read_rc = linux.open(keep_z, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(read_rc));
    const read_fd: i32 = @intCast(read_rc);
    defer _ = linux.close(read_fd);
    var buffer: [32]u8 = undefined;
    const got = linux.read(read_fd, &buffer, buffer.len);
    try std.testing.expectEqualStrings(contents, buffer[0..got]);
}

test "a machine that refuses the user namespace says which call it refused, and with what errno" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{})));
    defer _ = linux.close(fds[0]);

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        var insns = [_]bpf.Insn{
            bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr),
            bpf.jump(bpf.JMP_JEQ_K, @backingInt(linux.SYS.unshare), 0, 1),
            bpf.stmt(bpf.RET_K, seccomp.RET_ERRNO_PERM),
            bpf.stmt(bpf.RET_K, seccomp.RET_ALLOW),
        };
        seccomp.install(bpf.Prog.init(&insns), null) catch std.process.exit(3);

        const err = spawn(std.heap.page_allocator, .{
            .root = root_z,
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
            .stderr_fd = fds[1],
        }, &.{"/does-not-exist"}, .{});
        if (err) |_| {
            std.process.exit(1);
        } else |actual| {
            if (actual == error.LandlockUnavailable) std.process.exit(4);
            if (actual != error.NamespaceFailed) std.process.exit(2);
            std.process.exit(0);
        }
    }

    _ = linux.close(fds[1]);
    var text: [256]u8 = undefined;
    var filled: usize = 0;
    while (filled < text.len) {
        const rc = linux.read(fds[0], text[filled..].ptr, text.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        filled += rc;
    }

    var status: i32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(@bitCast(status)));

    const code = linux.W.EXITSTATUS(@bitCast(status));
    if (code == 3 or code == 4) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), code);

    try std.testing.expectEqualStrings(
        "sandbox: the unshare that makes the namespaces failed: PERM\n",
        text[0..filled],
    );
}

test "a landlock errno travels the setup pipe, and is not lost with the layer" {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{})));
    const read_fd = fds[0];
    const write_fd = fds[1];
    defer _ = linux.close(read_fd);

    reportSetupFailure(write_fd, .landlock_restrict, @backingInt(linux.E.PERM));
    _ = linux.close(write_fd);

    const record = (try readSetupReport(read_fd)).?;
    try std.testing.expectEqual(@backingInt(SetupStep.landlock_restrict), record.step);
    try std.testing.expectEqual(@as(i32, @backingInt(linux.E.PERM)), record.errno);

    try std.testing.expectEqual(
        @as(SetupError, error.LandlockRestrictFailed),
        setupErrorFor(.landlock_restrict),
    );
}

test "a handle answers Gone once the process it names has been reaped" {
    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const pid: linux.pid_t = @intCast(fork_rc);
    if (pid == 0) {
        _ = linux.nanosleep(&.{ .sec = 30, .nsec = 0 }, null);
        std.process.exit(0);
    }

    var handle: iface.Handle = .{};
    const pidfd_rc = linux.pidfd_open(pid, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(pidfd_rc));
    handle.publish(pid, @intCast(pidfd_rc));
    const fd = handle.fd().?;

    const fd_flags = linux.fcntl(fd, linux.F.GETFD, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(fd_flags));
    try std.testing.expect((fd_flags & linux.FD_CLOEXEC) != 0);

    try signal(&handle, @backingInt(linux.SIG.KILL));

    var status: i32 = undefined;
    var wait_rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFSIGNALED(@bitCast(status)));
    try std.testing.expectEqual(linux.SIG.KILL, linux.W.TERMSIG(@bitCast(status)));

    try std.testing.expectError(error.Gone, signal(&handle, @backingInt(linux.SIG.KILL)));

    close(&handle);
    try std.testing.expectEqual(@as(?i32, null), handle.fd());
    try std.testing.expectError(error.NoHandle, signal(&handle, @backingInt(linux.SIG.KILL)));
    close(&handle);
}

test "a handle with no process published has nothing to signal" {
    var handle: iface.Handle = .{};
    try std.testing.expectError(error.NoHandle, signal(&handle, @backingInt(linux.SIG.KILL)));
    close(&handle);
}

test "a signal number the kernel cannot hold is refused before it is sent" {
    var handle: iface.Handle = .{};
    handle.publish(1, 0);
    defer handle.raw_pid = 0;
    try std.testing.expectError(error.Unexpected, signal(&handle, 1 << 20));
}

test "a reaped number really does name somebody else, and the handle still reaches nobody" {
    if (!namespace.probeAvailability().available()) return error.SkipZigTest;

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const outer: linux.pid_t = @intCast(fork_rc);

    if (outer == 0) {
        if (linux.errno(linux.unshare(linux.CLONE.NEWUSER | linux.CLONE.NEWPID)) != .SUCCESS) {
            std.process.exit(20);
        }

        const init_rc = linux.fork();
        if (linux.errno(init_rc) != .SUCCESS) std.process.exit(21);
        const init_pid: linux.pid_t = @intCast(init_rc);

        if (init_pid == 0) {
            const first_rc = linux.fork();
            if (linux.errno(first_rc) != .SUCCESS) std.process.exit(22);
            const first: linux.pid_t = @intCast(first_rc);
            if (first == 0) std.process.exit(0);

            const handle_rc = linux.pidfd_open(first, 0);
            if (linux.errno(handle_rc) != .SUCCESS) std.process.exit(23);
            const handle: i32 = @intCast(handle_rc);
            var probe: iface.Handle = .{};
            probe.publish(first, handle);

            var status: i32 = undefined;
            var wait_rc = linux.waitpid(first, &status, 0);
            while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(first, &status, 0);
            if (linux.errno(wait_rc) != .SUCCESS) std.process.exit(24);

            const counter = linux.open("/proc/sys/kernel/ns_last_pid", .{ .ACCMODE = .WRONLY }, 0);
            if (linux.errno(counter) != .SUCCESS) std.process.exit(25);
            const counter_fd: i32 = @intCast(counter);
            var want_buf: [16]u8 = undefined;
            const want = std.fmt.bufPrint(&want_buf, "{d}", .{first - 1}) catch unreachable;
            const written = linux.write(counter_fd, want.ptr, want.len);
            _ = linux.close(counter_fd);
            if (linux.errno(written) != .SUCCESS) std.process.exit(26);

            const second_rc = linux.fork();
            if (linux.errno(second_rc) != .SUCCESS) std.process.exit(27);
            const second: linux.pid_t = @intCast(second_rc);
            if (second == 0) {
                _ = linux.nanosleep(&.{ .sec = 30, .nsec = 0 }, null);
                std.process.exit(0);
            }
            if (second != first) {
                _ = linux.kill(second, .KILL);
                _ = linux.waitpid(second, &status, 0);
                std.process.exit(28);
            }

            if (linux.errno(linux.kill(first, @fromBackingInt(0))) != .SUCCESS) {
                std.process.exit(29);
            }

            if (signal(&probe, @backingInt(linux.SIG.KILL))) |_| {
                std.process.exit(30);
            } else |err| {
                if (err != error.Gone) std.process.exit(31);
            }

            _ = linux.nanosleep(&.{ .sec = 0, .nsec = 200_000_000 }, null);
            const nohang = linux.waitpid(second, &status, linux.W.NOHANG);
            if (nohang != 0) std.process.exit(32);

            _ = linux.kill(second, .KILL);
            _ = linux.waitpid(second, &status, 0);
            _ = linux.close(handle);
            std.process.exit(0);
        }

        var status: i32 = undefined;
        var wait_rc = linux.waitpid(init_pid, &status, 0);
        while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(init_pid, &status, 0);
        if (linux.errno(wait_rc) != .SUCCESS) std.process.exit(33);
        if (!linux.W.IFEXITED(@bitCast(status))) std.process.exit(34);
        std.process.exit(linux.W.EXITSTATUS(@bitCast(status)));
    }

    var status: i32 = undefined;
    var wait_rc = linux.waitpid(outer, &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(outer, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(@bitCast(status)));

    const code = linux.W.EXITSTATUS(@bitCast(status));
    if (code == 20 or code == 28) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u8, 0), code);
}

test "a supplied cgroup the kernel refuses is reported by name, and nothing is forked" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    const not_a_cgroup_rc = linux.open("/proc/self", .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(not_a_cgroup_rc));
    const not_a_cgroup: i32 = @intCast(not_a_cgroup_rc);
    defer _ = linux.close(not_a_cgroup);

    for ([_]i32{ not_a_cgroup, -1 }) |fd| {
        var handle: iface.Handle = .{};
        defer close(&handle);

        const err = spawn(std.testing.allocator, .{
            .root = root_z,
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
            .containment = .{ .supplied = .{ .fd = fd } },
        }, &.{"/does-not-exist"}, .{ .handle = &handle });

        if (err) |_| {
            return error.TestUnexpectedResult;
        } else |actual| {
            if (actual == error.LandlockUnavailable) return error.SkipZigTest;
            try std.testing.expectEqual(error.CgroupPlacementRefused, actual);
        }

        try std.testing.expectEqual(@as(?i32, null), handle.pid());
        try std.testing.expectEqual(@as(?i32, null), handle.fd());
    }
}

const TestCgroupPair = struct {
    parent_buffer: [std.fs.max_path_bytes]u8 = undefined,
    parent_len: usize = 0,
    target_buffer: [std.fs.max_path_bytes]u8 = undefined,
    target_len: usize = 0,

    fn parent(self: *const TestCgroupPair) []const u8 {
        return self.parent_buffer[0..self.parent_len];
    }

    fn target(self: *const TestCgroupPair) []const u8 {
        return self.target_buffer[0..self.target_len];
    }
};

const supplied_memory_max = "100663296";

const supplied_pids_max = "97";

test "spawn puts the sandboxed program in the caller's own cgroup at creation, and writes nothing into it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    if (!namespace.probeAvailability().available()) return error.SkipZigTest;

    var pair = TestCgroupPair{};
    if (!makeTestCgroupPair(&pair)) return error.SkipZigTest;
    defer removeTestCgroup(pair.parent());
    defer removeTestCgroup(pair.target());

    if (!writeTestCgroupFile(pair.target(), "memory.max", supplied_memory_max)) return error.SkipZigTest;
    if (!writeTestCgroupFile(pair.target(), "pids.max", supplied_pids_max)) return error.SkipZigTest;

    var target_z: [std.fs.max_path_bytes]u8 = undefined;
    const target_path = nullTerminate(&target_z, pair.target()) orelse return error.SkipZigTest;
    const target_fd_rc = linux.open(
        target_path.ptr,
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(target_fd_rc) != .SUCCESS) return error.SkipZigTest;
    const target_fd: i32 = @intCast(target_fd_rc);
    defer _ = linux.close(target_fd);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_z = try absoluteDirPath(&path_buffer, tmp.dir.handle);

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{})));
    defer _ = linux.close(fds[0]);

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        std.process.exit(measureSuppliedPlacement(&pair, target_fd, root_z));
    }

    _ = linux.close(fds[1]);
    var status: i32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(@bitCast(status)));

    const code = linux.W.EXITSTATUS(@bitCast(status));
    if (code == 10 or code == 11) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), code);

    var buffer: [4096]u8 = undefined;
    try std.testing.expectEqualStrings(
        supplied_memory_max,
        readTestCgroupFile(pair.target(), "memory.max", &buffer) orelse return error.SkipZigTest,
    );
    try std.testing.expectEqualStrings(
        supplied_pids_max,
        readTestCgroupFile(pair.target(), "pids.max", &buffer) orelse return error.SkipZigTest,
    );
    try std.testing.expectEqualStrings(
        "max",
        readTestCgroupFile(pair.target(), "memory.swap.max", &buffer) orelse return error.SkipZigTest,
    );
}

fn measureSuppliedPlacement(
    pair: *const TestCgroupPair,
    target_fd: i32,
    root_z: [:0]const u8,
) u8 {
    if (!writeTestCgroupFile(pair.parent(), "cgroup.procs", "0")) return 10;
    var buffer: [4096]u8 = undefined;
    const current = readTestCgroupFile(pair.parent(), "pids.current", &buffer) orelse return 10;
    if (!writeTestCgroupFile(pair.parent(), "pids.max", current)) return 10;

    const devnull_rc = linux.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
    if (linux.errno(devnull_rc) != .SUCCESS) return 10;
    const devnull: i32 = @intCast(devnull_rc);

    const base = Config{
        .root = root_z,
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .stderr_fd = devnull,
    };

    const best_effort = base;
    if (spawn(std.heap.page_allocator, best_effort, &.{"/does-not-exist"}, .{})) |_| {
        return 2;
    } else |err| {
        if (err == error.LandlockUnavailable) return 11;
        if (err != error.Unexpected) return 2;
    }

    var report: LimitsReport = undefined;
    var supplied = base;
    supplied.containment = .{ .supplied = .{ .fd = target_fd } };

    if (spawn(std.heap.page_allocator, supplied, &.{"/does-not-exist"}, .{ .reports = .{ .limits = &report } })) |_| {
        return 3;
    } else |err| {
        if (err == error.LandlockUnavailable) return 11;
        if (err != error.ExecFailed) return 3;
    }

    if (report.cgroup != .supplied) return 4;
    if (report.events.oom_kills != 0 or report.events.fork_refusals != 0) return 5;

    return 0;
}

fn makeTestCgroupPair(pair: *TestCgroupPair) bool {
    var probe = cgroup.Cgroup.create("palisade.", 1 << 30, 64, 0xC10E0);
    defer probe.destroy();
    if (!probe.support.applied()) return false;

    const ancestor = std.fs.path.dirname(probe.path()) orelse return false;

    pair.parent_len = makeTestCgroup(&pair.parent_buffer, ancestor, 0xC10E3) orelse return false;
    pair.target_len = makeTestCgroup(&pair.target_buffer, ancestor, 0xC10E4) orelse return false;
    return true;
}

fn makeTestCgroup(buffer: []u8, ancestor: []const u8, seq: u64) ?usize {
    const written = std.fmt.bufPrint(
        buffer,
        "{s}/palisade.test.{d}.{d}",
        .{ ancestor, linux.getpid(), seq },
    ) catch return null;
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, written) orelse return null;
    if (linux.errno(linux.mkdirat(linux.AT.FDCWD, zeroed, 0o755)) != .SUCCESS) return null;
    return written.len;
}

fn removeTestCgroup(path: []const u8) void {
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, path) orelse return;
    var attempt: usize = 0;
    while (attempt < 400) : (attempt += 1) {
        switch (linux.errno(linux.unlinkat(linux.AT.FDCWD, zeroed, linux.AT.REMOVEDIR))) {
            .SUCCESS, .NOENT => return,
            else => {},
        }
        const request = linux.timespec{ .sec = 0, .nsec = 500 * std.time.ns_per_us };
        _ = linux.nanosleep(&request, null);
    }
}

fn writeTestCgroupFile(dir: []const u8, name: []const u8, contents: []const u8) bool {
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const written = std.fmt.bufPrint(&full, "{s}/{s}", .{ dir, name }) catch return false;
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, written) orelse return false;

    const fd_rc = linux.open(zeroed, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    const rc = linux.write(fd, contents.ptr, contents.len);
    return linux.errno(rc) == .SUCCESS and rc == contents.len;
}

fn readTestCgroupFile(dir: []const u8, name: []const u8, buffer: []u8) ?[]const u8 {
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const written = std.fmt.bufPrint(&full, "{s}/{s}", .{ dir, name }) catch return null;
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, written) orelse return null;

    const fd_rc = linux.open(zeroed, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(fd, buffer[filled..].ptr, buffer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS) return null;
        if (rc == 0) break;
        filled += rc;
    }
    return std.mem.trim(u8, buffer[0..filled], " \n\r");
}

fn nullTerminate(buffer: []u8, text: []const u8) ?[:0]const u8 {
    if (text.len + 1 > buffer.len) return null;
    @memcpy(buffer[0..text.len], text);
    buffer[text.len] = 0;
    return buffer[0..text.len :0];
}

test "a reader killed after it reported is still a reader that reported" {
    try std.testing.expect(readerReported(.{
        .ready = 1,
        .ended = 1,
        .ending = .signalled,
    }));
    try std.testing.expect(readerReported(.{
        .ready = 1,
        .ended = 1,
        .ending = .{ .exited = 0 },
    }));
}

test "a reader that never started, never ended, or faulted reported nothing" {
    try std.testing.expect(!readerReported(.{
        .ready = 0,
        .ended = 0,
        .ending = .{ .exited = 0 },
    }));
    try std.testing.expect(!readerReported(.{
        .ready = 1,
        .ended = 0,
        .ending = .signalled,
    }));
    try std.testing.expect(!readerReported(.{
        .ready = 1,
        .ended = 1,
        .ending = .{ .exited = 1 },
    }));
    try std.testing.expect(!readerReported(.{
        .ready = 1,
        .ended = 1,
        .ending = .unknown,
    }));
}

test "a reader that only claims to have started has still reported nothing" {
    try std.testing.expect(!readerReported(.{
        .ready = 1,
        .ended = 0,
        .ending = .signalled,
    }));
}

test "the filter a helper gets is the one seccomp.buildHelper makes, so allowing ptrace opens nothing" {
    var dummy: u8 = 0;
    const helper: iface.Helper = .{
        .ptr = &dummy,
        .run = rejectedFilterRun,
        .allowed = &.{ .write, .ptrace },
        .channel = 0,
    };
    const got = try helperFilter(std.testing.allocator, helper);
    defer std.testing.allocator.free(got);
    const want = try seccomp.buildHelper(std.testing.allocator, helper.allowed, &.{iface.channelFd(0)}, helper_ready_fd);
    defer std.testing.allocator.free(want);
    try std.testing.expectEqualSlices(bpf.Insn, want, got);

    const without_channel: iface.Helper = .{ .ptr = &dummy, .run = rejectedFilterRun, .allowed = &.{.write} };
    const plain = try helperFilter(std.testing.allocator, without_channel);
    defer std.testing.allocator.free(plain);
    const plain_want = try seccomp.buildHelper(std.testing.allocator, &.{.write}, &.{}, helper_ready_fd);
    defer std.testing.allocator.free(plain_want);
    try std.testing.expectEqualSlices(bpf.Insn, plain_want, plain);
}

test "spawn refuses a helper whose keep fd is closed, before any child exists" {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe(&fds)));
    _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    const closed = fds[0];

    var dummy: u8 = 0;
    const helpers = [_]iface.Helper{.{
        .ptr = &dummy,
        .run = rejectedFilterRun,
        .allowed = &.{},
        .keep_fds = &.{closed},
    }};
    var config = testConfig(test_net, &.{});
    config.helpers = &helpers;
    try std.testing.expectError(
        error.HelperFdClosed,
        spawn(std.testing.allocator, config, &.{"/does-not-exist"}, .{}),
    );
}
