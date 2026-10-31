//! The Darwin driver. It applies Seatbelt, network and signal limits, and
//! resource limits, and refuses any config that needs a mount tree.

const std = @import("std");
const builtin = @import("builtin");
const iface = @import("../Sandbox.zig");
const landlock = @import("../linux/landlock.zig");
const seatbelt = @import("seatbelt.zig");
const limits = @import("limits.zig");
const afterfork = @import("afterfork.zig");
const caps = @import("caps.zig");

const Config = iface.Config;
const SpawnError = iface.SpawnError;

pub const driver_name = caps.driver_name;
pub const guarantees = caps.guarantees;
pub const expresses = caps.expresses;

const max_profile_bytes = 256 * 1024;

/// The highest signal number on macOS.
const max_signal: u32 = 31;

fn accessFor(rights: landlock.AccessFs) seatbelt.Access {
    return .{
        .read = rights.read_file or rights.read_dir or rights.execute,
        .write = rights.write_file or rights.truncate or rights.remove_file or
            rights.remove_dir or rights.make_char or rights.make_dir or
            rights.make_reg or rights.make_sock or rights.make_fifo or
            rights.make_block or rights.make_sym or rights.refer,
    };
}

fn optionsFor(allocator: std.mem.Allocator, config: Config) std.mem.Allocator.Error!seatbelt.Options {
    var rules: std.ArrayList(seatbelt.Rule) = .empty;
    errdefer rules.deinit(allocator);
    var deny: std.ArrayList(seatbelt.Rule) = .empty;
    errdefer deny.deinit(allocator);

    for (config.rules) |rule| try rules.append(allocator, .{
        .path = rule.path,
        .access = accessFor(rule.access),
    });

    for (config.mounts) |mount| switch (mount) {
        .bind => |bind| {
            try rules.append(allocator, .{
                .path = bind.source,
                .access = if (bind.read_only) .read_only else .read_write,
            });
            if (bind.read_only) try rules.append(allocator, .{
                .path = bind.source,
                .access = .{ .write = true },
                .verb = .deny,
            });
        },
        .deny => |denied| try deny.append(allocator, .{
            .path = denied.target,
            .access = .read_write,
            .reach = .literal,
        }),
        .overlay, .proc => unreachable, // `inexpressible` refused these already.
    };

    const owned_rules = try rules.toOwnedSlice(allocator);
    errdefer allocator.free(owned_rules);
    const owned_deny = try deny.toOwnedSlice(allocator);

    return .{
        .rules = owned_rules,
        .deny = owned_deny,
        .allow_network = config.network == .host,
    };
}

pub fn spawn(
    gpa: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    run: iface.Run,
) SpawnError!iface.Term {
    try iface.validate(config);
    if ((run.entry == null) == (argv.len == 0)) return error.Unexpected;

    switch (config.containment) {
        .best_effort => {},
        .supplied => return error.CgroupPlacementUnsupported,
    }

    if (iface.inexpressible(config) != null) return error.NoMountNamespace;

    if (builtin.os.tag == .macos) {
        return spawnDarwin(gpa, config, argv, run);
    } else {
        return error.NoMountNamespace;
    }
}

/// Everything the forked children need, built before the first fork so they never allocate.
const Prepared = struct {
    profile: [:0]const u8,
    cwd: [:0]const u8,
    argv: [:null]?[*:0]const u8,
    env: [:null]?[*:0]const u8,
};

fn prepare(
    arena: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
) SpawnError!Prepared {
    const options = try optionsFor(arena, config);
    const profile_buffer = try arena.alloc(u8, max_profile_bytes);
    var builder = seatbelt.Builder.init(profile_buffer);
    const profile = builder.finish(options) catch |err| switch (err) {
        error.ProfileTooLong, error.BadPath => return error.LandlockInitFailed,
    };

    const argv_z = try arena.allocSentinel(?[*:0]const u8, argv.len, null);
    for (argv, argv_z) |arg, *slot| slot.* = try arena.dupeSentinel(u8, arg, 0);
    const env_z = try arena.allocSentinel(?[*:0]const u8, config.env.len, null);
    for (config.env, env_z) |item, *slot| slot.* = try arena.dupeSentinel(u8, item, 0);

    return .{
        .profile = profile,
        .cwd = try arena.dupeSentinel(u8, config.cwd, 0),
        .argv = argv_z,
        .env = env_z,
    };
}

fn spawnDarwin(
    gpa: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    run: iface.Run,
) SpawnError!iface.Term {
    std.debug.assert((run.entry == null) != (argv.len == 0));
    const handle = run.handle;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const prepared = try prepare(arena_state.allocator(), config, argv);

    var setup_fds: [2]std.c.fd_t = undefined;
    if (std.c.pipe(&setup_fds) != 0) return error.Unexpected;
    setCloexec(setup_fds[0]);
    setCloexec(setup_fds[1]);

    var cancel_fds: [2]std.c.fd_t = .{ -1, -1 };
    if (handle != null) {
        if (std.c.pipe(&cancel_fds) != 0) {
            closePair(&setup_fds);
            return error.Unexpected;
        }
        setCloexec(cancel_fds[0]);
        setCloexec(cancel_fds[1]);
        _ = std.c.fcntl(cancel_fds[1], std.c.F.SETNOSIGPIPE, @as(c_int, 1));
    }

    const a_pid = std.c.fork();
    if (a_pid < 0) {
        closePair(&setup_fds);
        closePair(&cancel_fds);
        return error.Unexpected;
    }

    if (a_pid == 0) {
        _ = std.c.close(setup_fds[0]);
        if (cancel_fds[1] >= 0) _ = std.c.close(cancel_fds[1]);
        runMiddle(config, prepared, run.entry, setup_fds[1], cancel_fds[0]);
    }

    _ = std.c.close(setup_fds[1]);
    if (cancel_fds[0] >= 0) _ = std.c.close(cancel_fds[0]);

    if (handle) |slot| slot.publish(a_pid, cancel_fds[1]);

    const record = readSetupReport(setup_fds[0]) catch |err| {
        _ = std.c.close(setup_fds[0]);
        _ = std.c.kill(a_pid, std.c.SIG.KILL);
        var ignored: c_int = 0;
        _ = std.c.waitpid(a_pid, &ignored, 0);
        return err;
    };
    _ = std.c.close(setup_fds[0]);

    if (run.reports.limits) |report| {
        const applied = limits.darwinApplied(config.limits);
        report.* = .{ .limits = applied.limits, .unsupported = applied.unsupported, .cgroup = .off };
    }

    var status: c_int = 0;
    while (std.c.waitpid(a_pid, &status, 0) < 0) {
        if (std.c._errno().* != @backingInt(std.c.E.INTR)) return error.Unexpected;
    }

    if (record) |step| return setupErrorFor(step);
    return termFor(status);
}

const SetupStep = enum(u8) {
    stdin_redirect = 1,
    process_group,
    close_fds,
    resource_limits,
    confinement,
    fork,
    exec,
};

fn setupErrorFor(step: SetupStep) SpawnError {
    return switch (step) {
        .stdin_redirect => error.StdinRedirectFailed,
        .process_group => error.ProcessGroupFailed,
        .close_fds => error.CloseFdsFailed,
        .resource_limits => error.ResourceLimitFailed,
        .confinement => error.LandlockRestrictFailed,
        .fork => error.ForkFailed,
        .exec => error.ExecFailed,
    };
}

const setup_magic: u32 = 0x31534C50;

const SetupRecord = extern struct {
    magic: u32 = setup_magic,
    step: u8,
    errno: i32,
};

fn readSetupReport(read_fd: std.c.fd_t) SpawnError!?SetupStep {
    var record: SetupRecord = undefined;
    var filled: usize = 0;
    const bytes = std.mem.asBytes(&record);
    while (filled < bytes.len) {
        const n = std.c.read(read_fd, bytes[filled..].ptr, bytes.len - filled);
        if (n < 0) {
            if (std.c._errno().* == @backingInt(std.c.E.INTR)) continue;
            return error.Unexpected;
        }
        if (n == 0) break;
        filled += @intCast(n);
    }
    if (filled == 0) return null;
    if (filled != bytes.len or record.magic != setup_magic) return .exec;
    return std.enums.fromInt(SetupStep, record.step) orelse .exec;
}

fn setCloexec(fd: std.c.fd_t) void {
    _ = std.c.fcntl(fd, std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC));
}

fn closePair(fds: *[2]std.c.fd_t) void {
    for (fds) |*fd| {
        if (fd.* >= 0) _ = std.c.close(fd.*);
        fd.* = -1;
    }
}

fn termFor(status: c_int) iface.Term {
    const raw: c_uint = @bitCast(status);
    const signal_bits: u32 = raw & 0x7f;
    if (signal_bits == 0) return .{ .exited = @truncate((raw >> 8) & 0xff) };
    if (signal_bits == 0x7f) return .{ .stopped = @fromBackingInt(@intCast(@as(u8, @truncate((raw >> 8) & 0xff)))) };
    return .{ .signal = @fromBackingInt(@intCast(@as(u8, @truncate(signal_bits)))) };
}

fn writeRecord(write_fd: std.c.fd_t, step: SetupStep, errno: i32) void {
    const record = SetupRecord{ .step = @backingInt(step), .errno = errno };
    const bytes = std.mem.asBytes(&record);
    _ = std.c.write(write_fd, bytes.ptr, bytes.len);
}

fn writeLine(stderr_fd: std.c.fd_t, line: []const u8) void {
    _ = std.c.write(stderr_fd, line.ptr, line.len);
}

fn dieWith(write_fd: std.c.fd_t, stderr_fd: std.c.fd_t, step: SetupStep, errno: i32, what: []const u8) noreturn {
    writeRecord(write_fd, step, errno);
    writeLine(stderr_fd, "sandbox: ");
    writeLine(stderr_fd, what);
    writeLine(stderr_fd, "\n");
    std.c._exit(127);
}

fn die(write_fd: std.c.fd_t, stderr_fd: std.c.fd_t, step: SetupStep, what: []const u8) noreturn {
    dieWith(write_fd, stderr_fd, step, std.c._errno().*, what);
}

fn dieSeatbelt(write_fd: std.c.fd_t, stderr_fd: std.c.fd_t, diag: ?seatbelt.Diagnostic) noreturn {
    const found = diag orelse die(write_fd, stderr_fd, .confinement, "the sandbox profile was refused");
    var line: [320]u8 = undefined;
    const text = std.fmt.bufPrint(&line, "the sandbox profile was refused: {f}", .{found}) catch
        "the sandbox profile was refused";
    dieWith(write_fd, stderr_fd, .confinement, found.errno, text);
}

fn runMiddle(
    config: Config,
    prepared: Prepared,
    entry: ?iface.Entry,
    write_fd: std.c.fd_t,
    cancel_read_fd: std.c.fd_t,
) noreturn {
    afterfork.resetSignalState();

    if (std.c.setpgid(0, 0) != 0) die(write_fd, config.stderr_fd, .process_group, "could not make a process group");

    const b_pid = std.c.fork();
    if (b_pid < 0) die(write_fd, config.stderr_fd, .fork, "could not fork the sandboxed process");
    if (b_pid == 0) {
        if (cancel_read_fd >= 0) _ = std.c.close(cancel_read_fd);
        runProgram(config, prepared, entry, write_fd);
    }

    _ = std.c.close(write_fd);

    middleLoop(b_pid, cancel_read_fd);
}

fn middleLoop(b_pid: std.c.pid_t, cancel_read_fd: std.c.fd_t) noreturn {
    const kq = std.c.kqueue();
    if (kq < 0) {
        relay(b_pid);
    }

    var changes: [2]std.c.Kevent = undefined;
    var count: c_int = 1;
    changes[0] = .{
        .ident = @intCast(b_pid),
        .filter = std.c.EVFILT.PROC,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE,
        .fflags = std.c.NOTE.EXIT,
        .data = 0,
        .udata = 0,
    };
    if (cancel_read_fd >= 0) {
        changes[1] = .{
            .ident = @intCast(cancel_read_fd),
            .filter = std.c.EVFILT.READ,
            .flags = std.c.EV.ADD | std.c.EV.ENABLE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        };
        count = 2;
    }
    if (std.c.kevent(kq, &changes, count, undefined, 0, null) < 0) relay(b_pid);

    while (true) {
        var event: std.c.Kevent = undefined;
        const n = std.c.kevent(kq, undefined, 0, @ptrCast(&event), 1, null);
        if (n < 0) {
            if (std.c._errno().* == @backingInt(std.c.E.INTR)) continue;
            relay(b_pid);
        }
        if (n == 0) continue;
        if (event.filter == std.c.EVFILT.PROC) relay(b_pid);
        if (event.filter != std.c.EVFILT.READ) continue;

        var byte: [1]u8 = undefined;
        const read_n = std.c.read(cancel_read_fd, &byte, 1);
        if (read_n <= 0) {
            var only: [1]std.c.Kevent = .{.{
                .ident = @intCast(cancel_read_fd),
                .filter = std.c.EVFILT.READ,
                .flags = std.c.EV.DELETE,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            }};
            _ = std.c.kevent(kq, &only, 1, undefined, 0, null);
            continue;
        }
        if (byte[0] == 0 or byte[0] > max_signal) continue;
        const which: std.c.SIG = @fromBackingInt(@intCast(byte[0]));
        var ignore: std.c.Sigaction = undefined;
        @memset(std.mem.asBytes(&ignore), 0);
        ignore.handler = .{ .handler = std.c.SIG.IGN };
        _ = std.c.sigaction(which, &ignore, null);
        _ = std.c.kill(-std.c.getpid(), which);
    }
}

fn relay(b_pid: std.c.pid_t) noreturn {
    var status: c_int = 0;
    while (std.c.waitpid(b_pid, &status, 0) < 0) {
        if (std.c._errno().* != @backingInt(std.c.E.INTR)) std.c._exit(127);
    }
    switch (termFor(status)) {
        .exited => |code| std.c._exit(code),
        .signal => |signal_number| {
            _ = std.c.kill(std.c.getpid(), signal_number);
            std.c._exit(128 +% @as(u8, @truncate(@backingInt(signal_number))));
        },
        .stopped, .unknown => std.c._exit(127),
    }
}

fn runProgram(
    config: Config,
    prepared: Prepared,
    entry: ?iface.Entry,
    write_fd: std.c.fd_t,
) noreturn {
    redirectStdin(config, write_fd);
    closeInheritedFds(config, write_fd);
    redirectStandardStreams(config, write_fd);

    const stderr_fd: std.c.fd_t = 2;

    if (std.c.chdir(prepared.cwd) != 0) die(write_fd, stderr_fd, .exec, "chdir into the sandbox failed");

    const report = limits.apply(config.limits);
    for ([_]limits.Report.State{ report.cpu_time, report.file_size, report.open_files }) |state| {
        if (state == .unavailable) die(write_fd, stderr_fd, .resource_limits, "a resource limit could not be set");
    }

    var diag: ?seatbelt.Diagnostic = null;
    const support = seatbelt.apply(prepared.profile, &diag);
    if (!support.applied()) dieSeatbelt(write_fd, stderr_fd, diag);

    if (entry) |callback| {
        // Exec normally closes the setup pipe. A callback has no exec
        // boundary, so close it only after confinement is fully applied.
        if (std.c.close(write_fd) != 0) std.c._exit(127);
        std.c._exit(callback.run(callback.ptr));
    }

    _ = std.c.execve(prepared.argv[0].?, prepared.argv.ptr, prepared.env.ptr);
    die(write_fd, stderr_fd, .exec, "execve failed");
}

fn redirectStdin(config: Config, write_fd: std.c.fd_t) void {
    const null_fd = std.c.open("/dev/null", .{ .ACCMODE = .RDWR });
    if (null_fd < 0) die(write_fd, config.stderr_fd, .stdin_redirect, "could not open /dev/null");
    if (std.c.dup2(null_fd, 0) < 0) die(write_fd, config.stderr_fd, .stdin_redirect, "could not redirect standard input");
    if (null_fd > 2) _ = std.c.close(null_fd);
}

fn closeInheritedFds(config: Config, write_fd: std.c.fd_t) void {
    var keep: [7]i32 = undefined;
    var count: usize = 0;
    for ([_]i32{ 0, 1, 2, write_fd, config.stdout_fd, config.stderr_fd }) |fd| {
        keep[count] = fd;
        count += 1;
    }
    if (config.stdin_fd) |fd| {
        keep[count] = fd;
        count += 1;
    }
    afterfork.keepOnlyDescriptors(keep[0..count]);
}

fn redirectStandardStreams(config: Config, write_fd: std.c.fd_t) void {
    if (config.stdin_fd) |fd| {
        if (std.c.dup2(fd, 0) < 0) die(write_fd, config.stderr_fd, .stdin_redirect, "could not redirect standard input");
    }
    if (config.stdout_fd != 1) {
        if (std.c.dup2(config.stdout_fd, 1) < 0) die(write_fd, config.stderr_fd, .close_fds, "could not redirect standard output");
    }
    if (config.stderr_fd != 2) {
        if (std.c.dup2(config.stderr_fd, 2) < 0) die(write_fd, 2, .close_fds, "could not redirect standard error");
    }
    if (config.stdout_fd > 2) _ = std.c.close(config.stdout_fd);
    if (config.stderr_fd > 2 and config.stderr_fd != config.stdout_fd) _ = std.c.close(config.stderr_fd);
    if (config.stdin_fd) |fd| if (fd > 2) {
        _ = std.c.close(fd);
    };
}

pub fn signal(handle: *const iface.Handle, sig: u32) iface.SignalError!void {
    const fd = handle.fd() orelse return error.NoHandle;
    if (sig == 0 or sig > max_signal) return error.Unexpected;
    if (builtin.os.tag != .macos) return error.NoHandle;

    const byte: [1]u8 = .{@intCast(sig)};
    while (true) {
        const n = std.c.write(fd, &byte, 1);
        if (n == 1) return;
        const err = std.c._errno().*;
        if (err == @backingInt(std.c.E.INTR)) continue;
        if (err == @backingInt(std.c.E.PIPE)) return error.Gone;
        return error.Unexpected;
    }
}

pub fn close(handle: *iface.Handle) void {
    const fd = handle.fd() orelse return;
    if (builtin.os.tag == .macos) _ = std.c.close(fd);
    @atomicStore(i32, &handle.raw_fd, -1, .release);
}

pub fn joinFreshSessionKeyring(stderr_fd: i32) iface.KeyringError!void {
    _ = stderr_fd;
    return error.Refused;
}

const test_base: Config = .{ .root = "/", .mounts = &.{}, .rules = &.{}, .cwd = "/", .env = &.{} };

test "spawn never allocates and never forks before it refuses" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var config = test_base;
    config.root = "/does-not-exist-and-must-never-be-touched";
    const err = spawn(failing.allocator(), config, &.{"/bin/true"}, .{});
    try std.testing.expectError(error.NoMountNamespace, err);
    try std.testing.expectEqual(@as(usize, 0), failing.allocations);
}

test "spawn leaves the handle and the reports untouched when it refuses" {
    var handle: iface.Handle = .{};
    var report: iface.LandlockReport = .{ .abi = -1, .features = undefined };
    var config = test_base;
    config.root = "/does-not-matter";
    const err = spawn(std.testing.allocator, config, &.{"/bin/true"}, .{
        .handle = &handle,
        .reports = .{ .landlock = &report },
    });
    try std.testing.expectError(error.NoMountNamespace, err);
    try std.testing.expectEqual(@as(i32, -1), report.abi);
    try std.testing.expectEqual(@as(?i32, null), handle.pid());
    try std.testing.expectEqual(@as(?i32, null), handle.fd());
}

test "a cgroup the caller made is refused by name, and refused before every other check" {
    var placeable = test_base;
    placeable.containment = .{ .supplied = .{ .fd = 7 } };
    try std.testing.expectError(
        error.CgroupPlacementUnsupported,
        spawn(std.testing.allocator, placeable, &.{"/bin/true"}, .{}),
    );

    var also_unmountable = placeable;
    also_unmountable.root = "/somewhere-else";
    try std.testing.expectError(
        error.CgroupPlacementUnsupported,
        spawn(std.testing.allocator, also_unmountable, &.{"/bin/true"}, .{}),
    );
}

test "a capped scratch area is refused rather than quietly left out" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    var config = test_base;
    config.scratch = &.{.{ .target = "/run/palisade/scratch" }};
    try std.testing.expectError(error.NoMountNamespace, spawn(std.testing.allocator, config, &.{"/bin/true"}, .{}));
}

test "a channel is refused rather than quietly given no way out" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    var dummy: u8 = 0;
    const channel: iface.Channel = .{ .ptr = &dummy, .wakeup = .{ .fd = 0, .drain = testDrain }, .hands_host_descriptor = false };
    var config = test_base;
    config.network = .{ .isolated = isolated_params };
    config.channels = &.{channel};
    try std.testing.expectError(error.NoMountNamespace, spawn(std.testing.allocator, config, &.{"/bin/true"}, .{}));
}

const isolated_params: @import("../linux/netns.zig").Params = .{
    .device_name = "sbx0",
    .address4 = .{ 10, 0, 0, 1 },
    .prefix4 = 24,
    .address6 = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    .prefix6 = 64,
};

fn testDrain(_: *anyopaque, _: i32) iface.Channel.ServeResult {
    return .more;
}

test "signal refuses a handle nobody opened" {
    const handle: iface.Handle = .{};
    try std.testing.expectError(error.NoHandle, signal(&handle, 9));
}

test "close leaves no descriptor a second call could close twice" {
    var handle: iface.Handle = .{};
    handle.publish(7, -1);
    close(&handle);
    try std.testing.expectEqual(@as(?i32, null), handle.fd());
    close(&handle);
    try std.testing.expectEqual(@as(?i32, null), handle.fd());
}

test "the keyring join is refused" {
    try std.testing.expectError(error.Refused, joinFreshSessionKeyring(2));
}

test "the guarantees name only the layers a test really proves" {
    try std.testing.expect(guarantees.contains(.network_isolated));
    try std.testing.expect(guarantees.contains(.signal_isolated));
    try std.testing.expect(guarantees.contains(.ipc_isolated));
    try std.testing.expect(guarantees.contains(.path_restricted));
    try std.testing.expect(!guarantees.contains(.syscall_restricted));
    try std.testing.expect(!guarantees.contains(.bind_mounts));
    try std.testing.expectEqual(@as(usize, 4), guarantees.count());
}

test "a read only bind takes write away, and a later read write bind gives it back" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    var config = test_base;
    config.cwd = "/w";
    config.mounts = &.{
        .{ .bind = .{ .source = "/w", .target = "/w", .read_only = false } },
        .{ .bind = .{ .source = "/w/meta", .target = "/w/meta", .read_only = true } },
        .{ .bind = .{ .source = "/w/meta/index", .target = "/w/meta/index", .read_only = false } },
    };
    const options = try optionsFor(allocator, config);

    var buffer: [4096]u8 = undefined;
    var builder = seatbelt.Builder.init(&buffer);
    const profile = try builder.finish(options);

    const takes_write = std.mem.indexOf(u8, profile, "(deny file-write* (subpath \"/w/meta\"))").?;
    const gives_it_back = std.mem.indexOf(u8, profile, "(allow file-read* file-write* (subpath \"/w/meta/index\"))").?;
    try std.testing.expect(gives_it_back > takes_write);
    try std.testing.expect(std.mem.indexOf(u8, profile, "(allow file-read* (subpath \"/w/meta\"))") != null);
}

test "a rule is written before the mounts, so a mount is the last word" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    var config = test_base;
    config.cwd = "/w";
    config.mounts = &.{.{ .bind = .{ .source = "/w", .target = "/w", .read_only = true } }};
    config.rules = &.{.{ .path = "/w", .access = landlock.AccessFs.read_write }};
    const options = try optionsFor(allocator, config);

    var buffer: [4096]u8 = undefined;
    var builder = seatbelt.Builder.init(&buffer);
    const profile = try builder.finish(options);

    const from_the_rule = std.mem.indexOf(u8, profile, "(allow file-read* file-write* (subpath \"/w\"))").?;
    const from_the_mount = std.mem.indexOf(u8, profile, "(deny file-write* (subpath \"/w\"))").?;
    try std.testing.expect(from_the_mount > from_the_rule);
}

test "only a host network opens the network in the profile" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    var config = test_base;
    try std.testing.expect(!(try optionsFor(allocator, config)).allow_network);
    config.network = .{ .isolated = isolated_params };
    try std.testing.expect(!(try optionsFor(allocator, config)).allow_network);
    config.network = .host;
    try std.testing.expect((try optionsFor(allocator, config)).allow_network);
}

test "a rule set becomes the two rights seatbelt has" {
    try std.testing.expectEqual(seatbelt.Access{ .read = true }, accessFor(landlock.AccessFs.read_only));
    try std.testing.expectEqual(seatbelt.Access{ .read = true }, accessFor(.{ .execute = true }));
    try std.testing.expectEqual(seatbelt.Access{ .write = true }, accessFor(.{ .make_dir = true }));
    try std.testing.expectEqual(seatbelt.Access{}, accessFor(.{}));
}

test "prepare builds the profile and the exec arrays before any fork" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var config = test_base;
    config.cwd = "/work";
    config.env = &.{"A=1"};
    const prepared = try prepare(arena_state.allocator(), config, &.{ "/bin/echo", "hi" });
    try std.testing.expectEqualStrings("/work", prepared.cwd);
    try std.testing.expectEqual(@as(usize, 2), prepared.argv.len);
    try std.testing.expectEqual(@as(usize, 1), prepared.env.len);
    try std.testing.expect(std.mem.startsWith(u8, prepared.profile, "(version 1)\n(deny default)\n"));
}

test "a confined child runs a program and reports its exit status" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (seatbelt.confinedAlready()) return error.SkipZigTest;
    var config = test_base;
    config.rules = &.{.{ .path = "/", .access = landlock.AccessFs.read_only }};
    const term = try spawn(std.testing.allocator, config, &.{"/usr/bin/true"}, .{});
    try std.testing.expectEqual(iface.Term{ .exited = 0 }, term);
}

fn testEntry(ptr: *anyopaque) u8 {
    const status: *const u8 = @ptrCast(@alignCast(ptr));
    return status.*;
}

test "a confined child can enter inherited code without exec" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    if (seatbelt.confinedAlready()) return error.SkipZigTest;

    var status: u8 = 23;
    const term = try spawn(std.testing.allocator, test_base, &.{}, .{
        .entry = .{ .ptr = &status, .run = testEntry },
    });
    try std.testing.expectEqual(iface.Term{ .exited = 23 }, term);
}
