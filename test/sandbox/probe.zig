//! One dangerous operation per run. A test starts this program and reads the
//! exit status. A death by SIGSYS means the seccomp filter killed the process,
//! which is a pass for a call in `blocked_calls`.

const std = @import("std");
const palisade = @import("palisade");
const sandbox = palisade.Sandbox;
const namespace = palisade.linux.namespace;
const seccomp = palisade.linux.seccomp;
const bpf = palisade.linux.bpf;
const landlock = palisade.linux.landlock;
const netns = palisade.linux.netns;
const dynamic_probe_path = @import("dynamic_probe_path").dynamic_probe_path;
const linux = std.os.linux;

const stdin_pipe_token = "palisade-helper-request";

const opens_in_probe = 17;

const named_ungranted = "/etc/palisade-probe-secret";

const named_granted = "/nix/store";

const owned_host_contents = "host contents\n";
const owned_replacement = "127.0.0.1 sandbox\n";

/// Ends `spawned-kill-the-reader`. One system call, since this runs in a signal handler.
fn endOnAlarm(_: linux.SIG) callconv(.c) void {
    linux.exit(alarm_exit_status);
}

const alarm_exit_status = 9;

/// The keeper is process 1, the program is process 2, and the reader is process 3.
const reader_pid_in_namespace: linux.pid_t = 3;

fn endIfNothingMeasured(err: anyerror) void {
    if (err != error.NamespaceFailed) return;
    std.process.exit(namespace.nothing_measured_exit_status);
}

fn enterOrEndUnmeasured(options: namespace.Options) void {
    namespace.enter(options, null) catch {
        std.process.exit(namespace.nothing_measured_exit_status);
    };
}

fn enterTestRoot(arena: std.mem.Allocator, root: []const u8) !void {
    const work = try std.fs.path.join(arena, &.{ root, "work" });
    try makeTestDir(arena, work);

    const guarded = try std.fs.path.join(arena, &.{ work, "palisade.zon" });
    try writeTestFile(arena, guarded, ".{}\n");

    enterOrEndUnmeasured(.{ .new_net = true, .mount = true });
    try namespace.buildRoot(arena, root, &.{
        .{ .bind = .{ .source = work, .target = "/work", .read_only = false } },
        .{ .bind = .{ .source = guarded, .target = "/work/palisade.zon", .read_only = true } },
        .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } },
    }, false, namespace.default_deny_notice, null);
    try namespace.pivotInto(arena, root, null);
}

fn makeTestDir(arena: std.mem.Allocator, path: []const u8) !void {
    const path_z = try arena.dupeSentinel(u8, path, 0);
    switch (linux.errno(linux.mkdir(path_z.ptr, 0o755))) {
        .SUCCESS, .EXIST => {},
        else => return error.SetupFailed,
    }
}

fn writeTestFile(arena: std.mem.Allocator, path: []const u8, contents: []const u8) !void {
    const path_z = try arena.dupeSentinel(u8, path, 0);
    const fd_rc = linux.open(path_z.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (linux.errno(fd_rc) != .SUCCESS) return error.SetupFailed;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    const written = linux.write(fd, contents.ptr, contents.len);
    if (linux.errno(written) != .SUCCESS or written != contents.len) return error.SetupFailed;
}

/// A build time path from `addOptionPath` is relative to the build root.
fn absolutePath(arena: std.mem.Allocator, path: []const u8) ![]const u8 {
    if (path.len != 0 and path[0] == '/') return path;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const rc = linux.getcwd(&buffer, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.SetupFailed;
    // A cwd of `/` must not become `//path`.
    const cwd = std.mem.sliceTo(buffer[0..rc], 0);
    if (std.mem.eql(u8, cwd, "/")) return std.fmt.allocPrint(arena, "/{s}", .{path});
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ cwd, path });
}

/// `std.fs.selfExePathAlloc` does not exist in this Zig version.
fn selfExePath(arena: std.mem.Allocator) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const rc = linux.readlink("/proc/self/exe", &buffer, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.SetupFailed;
    return arena.dupe(u8, buffer[0..rc]);
}

fn readToEnd(fd: i32, buffer: []u8) []u8 {
    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(fd, buffer[filled..].ptr, buffer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        filled += rc;
    }
    return buffer[0..filled];
}

fn absentRoot(arena: std.mem.Allocator, root: []const u8) ![]const u8 {
    return std.fs.path.join(arena, &.{ root, "absent" });
}

fn baseEscapeConfig(arena: std.mem.Allocator) !struct {
    mounts: []const namespace.Mount,
    rules: []const sandbox.Rule,
} {
    const self_path = try selfExePath(arena);
    const mounts = try arena.dupe(namespace.Mount, &.{
        .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } },
        .{ .bind = .{ .source = self_path, .target = "/probe", .read_only = true } },
        .{ .proc = .{} },
        // `/dev/null` is also what makes `/dev` exist, which a Landlock rule needs to resolve.
        .{ .bind = .{ .source = "/dev/null", .target = "/dev/null", .read_only = false } },
    });
    const rules = try arena.dupe(sandbox.Rule, &.{
        .{ .path = "/nix/store", .access = landlock.AccessFs.read_only },
        // /probe is a file, so read_dir would give EINVAL.
        .{ .path = "/probe", .access = .{ .execute = true, .read_file = true } },
    });
    return .{ .mounts = mounts, .rules = rules };
}

const scratch_target = "/run/palisade/scratch";

fn diskEscapeConfig(arena: std.mem.Allocator) !struct {
    mounts: []const namespace.Mount,
    rules: []const sandbox.Rule,
    scratch: []const namespace.Scratch,
} {
    const base = try baseEscapeConfig(arena);
    const rules = try arena.alloc(sandbox.Rule, base.rules.len + 1);
    @memcpy(rules[0..base.rules.len], base.rules);
    rules[base.rules.len] = .{ .path = scratch_target, .access = landlock.AccessFs.read_write };

    const scratch = try arena.dupe(namespace.Scratch, &.{
        .{ .target = scratch_target },
    });
    return .{ .mounts = base.mounts, .rules = rules, .scratch = scratch };
}

const fork_bomb_cap: u8 = 64;
const fork_bomb_limit: u64 = 8;

/// 512 MiB in all, far past the limit the bounded run gets.
const mem_bomb_cap: u8 = 64;
/// One block, in bytes, touched rather than left mapped: `RLIMIT_AS` refuses an untouched mapping that `memory.max` lets by.
const mem_bomb_block_bytes: usize = 8 << 20;
const mem_bomb_limit: u64 = 128 << 20;

const fd_bomb_cap: u8 = 200;
const fd_bomb_limit: u64 = 32;

const disk_file_cap: u8 = 250;
/// Small on purpose: the attack is the number of files and not the size of any one, which `RLIMIT_FSIZE` cannot see.
const disk_file_bytes: usize = 4096;

const disk_file_limit: u64 = 512 << 10;

const disk_one_cap: u8 = 200;
const disk_one_block_bytes: usize = 64 << 10;
const disk_one_file_limit: u64 = 1 << 20;
const disk_one_scratch_limit: u64 = 64 << 20;

const LimitOutcome = enum(u8) {
    stopped_legibly = 10,
    stopped_quietly = 11,
    not_stopped = 12,
    unreadable = 13,
    no_cgroup = 14,
};

fn limitOutcome(term: std.process.Child.Term, cap: u8, named: bool) u8 {
    return @backingInt(switch (term) {
        .exited => |code| blk: {
            if (code >= cap) break :blk LimitOutcome.not_stopped;
            break :blk if (named) LimitOutcome.stopped_legibly else LimitOutcome.stopped_quietly;
        },
        .signal => if (named) LimitOutcome.stopped_legibly else LimitOutcome.stopped_quietly,
        else => LimitOutcome.unreadable,
    });
}

const open_fd_set_scan_limit: i32 = 1024;

fn fileTypeOf(fd: i32) u32 {
    var stx: linux.Statx = undefined;
    const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, linux.STATX.BASIC_STATS, &stx);
    if (linux.errno(rc) != .SUCCESS) return 0;
    return stx.mode & linux.S.IFMT;
}

const HarnessDescriptors = struct {
    log: i32,
    credential: i32,
    control: [2]i32,
    epoll: i32,
    ring: i32,
    upstream: i32,
    workspace: i32,

    fn open(arena: std.mem.Allocator, root: []const u8) !HarnessDescriptors {
        const log_path = try std.fs.path.joinZ(arena, &.{ root, "session.log" });
        const log_rc = linux.open(log_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        if (linux.errno(log_rc) != .SUCCESS) return error.SetupFailed;

        const credential_rc = linux.memfd_create("palisade-credential", 0);
        if (linux.errno(credential_rc) != .SUCCESS) return error.SetupFailed;

        var control: [2]i32 = undefined;
        const control_rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &control);
        if (linux.errno(control_rc) != .SUCCESS) return error.SetupFailed;

        const epoll_rc = linux.epoll_create1(0);
        if (linux.errno(epoll_rc) != .SUCCESS) return error.SetupFailed;

        var params: linux.io_uring_params = std.mem.zeroes(linux.io_uring_params);
        const ring_rc = linux.io_uring_setup(4, &params);
        const ring: i32 = if (linux.errno(ring_rc) == .SUCCESS) @intCast(ring_rc) else -1;

        const upstream_rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
        if (linux.errno(upstream_rc) != .SUCCESS) return error.SetupFailed;

        const workspace_rc = linux.open("/", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        if (linux.errno(workspace_rc) != .SUCCESS) return error.SetupFailed;

        return .{
            .log = @intCast(log_rc),
            .credential = @intCast(credential_rc),
            .control = control,
            .epoll = @intCast(epoll_rc),
            .ring = ring,
            .upstream = @intCast(upstream_rc),
            .workspace = @intCast(workspace_rc),
        };
    }

    fn openCount(self: HarnessDescriptors) usize {
        var count: usize = 0;
        for ([_]i32{
            self.log,
            self.credential,
            self.control[0],
            self.control[1],
            self.epoll,
            self.ring,
            self.upstream,
            self.workspace,
        }) |fd| {
            if (fd < 0) continue;
            if (linux.errno(linux.fcntl(fd, linux.F.GETFD, 0)) == .SUCCESS) count += 1;
        }
        return count;
    }
};

/// Seven of the eight, since `io_uring` is the one a machine may refuse.
const required_harness_descriptors: usize = 7;

fn reportChildTerm(term: std.process.Child.Term) u8 {
    switch (term) {
        .signal => |sig| {
            _ = linux.kill(linux.getpid(), (sig));
            return 1;
        },
        .exited => |code| return code,
        else => return 2,
    }
}

var caller_signal_seen: std.atomic.Value(bool) = .init(false);

fn onCallerSignal(_: linux.SIG) callconv(.c) void {
    caller_signal_seen.store(true, .monotonic);
}

fn catchSignal(sig: linux.SIG) void {
    const action = linux.Sigaction{
        .handler = .{ .handler = onCallerSignal },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(sig, &action, null);
}

const probe_wait_bound_ns: u64 = 10 * std.time.ns_per_s;
const probe_wait_step_ns: u64 = 1 * std.time.ns_per_ms;

fn pathExists(path: [:0]const u8) bool {
    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, path, 0, .{ .TYPE = true }, &stx);
    return linux.errno(rc) == .SUCCESS;
}

fn waitForPath(path: [:0]const u8) bool {
    var waited: u64 = 0;
    while (waited < probe_wait_bound_ns) : (waited += probe_wait_step_ns) {
        if (pathExists(path)) return true;
        _ = linux.nanosleep(&.{ .sec = 0, .nsec = @intCast(probe_wait_step_ns) }, null);
    }
    return pathExists(path);
}

/// `spawn` is synchronous, so a thread of its own is the only way to learn the pid it forked.
const ThreadedSpawn = struct {
    allocator: std.mem.Allocator,
    root: []const u8,
    mounts: []const namespace.Mount,
    rules: []const sandbox.Rule,
    argv: []const []const u8,
    middle: sandbox.Handle = .{},
    term: std.process.Child.Term = undefined,
    spawn_err: ?anyerror = null,
    /// Set with `.release` after `term` or `spawn_err` is written, so an `.acquire` load makes a plain read safe.
    done: std.atomic.Value(bool) = .init(false),

    fn run(self: *ThreadedSpawn) void {
        self.term = sandbox.spawn(self.allocator, .{
            .root = self.root,
            .mounts = self.mounts,
            .rules = self.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, self.argv, .{ .handle = &self.middle }) catch |err| {
            self.spawn_err = err;
            self.done.store(true, .release);
            return;
        };
        self.done.store(true, .release);
    }

    fn waitForMiddlePid(self: *ThreadedSpawn) linux.pid_t {
        var waited: u64 = 0;
        while (waited < probe_wait_bound_ns) : (waited += probe_wait_step_ns) {
            if (self.middle.pid()) |pid| return pid;
            if (self.done.load(.acquire)) return 0;
            _ = linux.nanosleep(&.{ .sec = 0, .nsec = @intCast(probe_wait_step_ns) }, null);
        }
        return self.middle.pid() orelse 0;
    }

    /// False when the bound ran out, which is a real answer: a `spawn` that never returns after a signal is a fault.
    fn waitForDone(self: *ThreadedSpawn) bool {
        var waited: u64 = 0;
        while (waited < probe_wait_bound_ns) : (waited += probe_wait_step_ns) {
            if (self.done.load(.acquire)) return true;
            _ = linux.nanosleep(&.{ .sec = 0, .nsec = @intCast(probe_wait_step_ns) }, null);
        }
        return self.done.load(.acquire);
    }

    /// Read in every branch that gives up on a bounded wait, since a sandbox that never came up makes those waits run out first.
    fn endIfSandboxRefused(self: *ThreadedSpawn) void {
        if (!self.done.load(.acquire)) return;
        if (self.spawn_err) |err| endIfNothingMeasured(err);
    }

    /// Through the handle, which reaches the middle process only and still ends the whole call.
    fn killCall(self: *ThreadedSpawn) void {
        if (self.middle.pid() == null) return;
        self.middle.signal(@backingInt(linux.SIG.KILL)) catch {};
    }

    /// Only after `spawn` has returned. See `sandbox.Handle`.
    fn closeHandle(self: *ThreadedSpawn) void {
        self.middle.close();
    }
};

/// `baseEscapeConfig` on its own gives no writable path.
fn workEscapeConfig(arena: std.mem.Allocator, root: []const u8) !struct {
    mounts: []const namespace.Mount,
    rules: []const sandbox.Rule,
} {
    const work = try std.fs.path.join(arena, &.{ root, "work" });
    try makeTestDir(arena, work);

    const base = try baseEscapeConfig(arena);
    const mounts = try std.mem.concat(arena, namespace.Mount, &.{
        base.mounts,
        &.{.{ .bind = .{ .source = work, .target = "/work", .read_only = false } }},
    });
    const rules = try std.mem.concat(arena, sandbox.Rule, &.{
        base.rules,
        &.{.{ .path = "/work", .access = landlock.AccessFs.read_write }},
    });
    return .{ .mounts = mounts, .rules = rules };
}

const file_over_file_content = "palisade file over file probe content\n";

/// Written into the root but named in no rule, so only a missing Landlock layer could let the read through.
const spawned_landlock_target = "/unguarded/marker";

fn enterFileOverFileTestRoot(arena: std.mem.Allocator, root: []const u8) !void {
    const source = try std.fs.path.join(arena, &.{ root, "source-file" });
    try writeTestFile(arena, source, file_over_file_content);

    enterOrEndUnmeasured(.{ .new_net = true, .mount = true });
    try namespace.buildRoot(arena, root, &.{
        .{ .bind = .{ .source = source, .target = "/marker", .read_only = false } },
    }, false, namespace.default_deny_notice, null);
    try namespace.pivotInto(arena, root, null);
}

/// The submount has to exist before buildRoot binds "guarded" onto itself: a bind mount carries only existing submounts.
fn enterSubmountTestRoot(arena: std.mem.Allocator, root: []const u8) !void {
    const guarded = try std.fs.path.join(arena, &.{ root, "guarded" });
    const sub = try std.fs.path.join(arena, &.{ guarded, "sub" });
    try makeTestDir(arena, guarded);

    enterOrEndUnmeasured(.{ .new_net = true, .mount = true });

    try makeTestDir(arena, sub);
    try mountTmpfs(arena, sub);

    try namespace.buildRoot(arena, root, &.{
        .{ .bind = .{ .source = guarded, .target = "/guarded", .read_only = true } },
    }, false, namespace.default_deny_notice, null);
    try namespace.pivotInto(arena, root, null);
}

fn mountTmpfs(arena: std.mem.Allocator, path: []const u8) !void {
    const path_z = try arena.dupeSentinel(u8, path, 0);
    if (linux.errno(linux.mount(null, path_z.ptr, "tmpfs", 0, 0)) != .SUCCESS) {
        return error.SetupFailed;
    }
}

fn createShmSegment() !usize {
    const ipc_private: usize = 0;
    const ipc_creat: usize = 0o1000;
    const size: usize = 4096;
    const shmid = linux.syscall3(.shmget, ipc_private, size, ipc_creat | 0o600);
    if (linux.errno(shmid) != .SUCCESS) return error.ShmgetFailed;
    return shmid;
}

/// IPC_RMID destroys a segment the moment it has zero attaches, so this must run after the shmat attempt.
fn removeShmSegment(shmid: usize) void {
    const ipc_rmid: usize = 0;
    _ = linux.syscall3(.shmctl, shmid, ipc_rmid, 0);
}

fn outsideDir(arena: std.mem.Allocator, root: []const u8) ![:0]const u8 {
    return std.fmt.allocPrintSentinel(arena, "{s}/outside", .{root}, 0);
}

fn enterLandlockWriteTestRoot(arena: std.mem.Allocator, root: []const u8) ![:0]const u8 {
    const inside = try std.fmt.allocPrintSentinel(arena, "{s}/inside", .{root}, 0);
    try makeTestDir(arena, inside);
    try makeTestDir(arena, try outsideDir(arena, root));

    const abi = try landlock.probeAbi();
    var ruleset = try landlock.Ruleset.init(abi, null);
    try ruleset.allowPath(inside, landlock.AccessFs.read_write, null);
    try ruleset.restrictSelf(null);
    ruleset.deinit();
    return inside;
}

fn enterLandlockTruncateTestRoot(arena: std.mem.Allocator, root: []const u8) !struct {
    inside_file: [:0]const u8,
    outside_file: [:0]const u8,
} {
    const inside = try std.fmt.allocPrintSentinel(arena, "{s}/inside", .{root}, 0);
    const inside_file = try std.fmt.allocPrintSentinel(arena, "{s}/file", .{inside}, 0);
    try makeTestDir(arena, inside);
    try writeTestFile(arena, inside_file, "palisade landlock truncate probe content\n");

    const outside_file = try std.fmt.allocPrintSentinel(arena, "{s}/truncate-file", .{try outsideDir(arena, root)}, 0);
    try makeTestDir(arena, try outsideDir(arena, root));
    try writeTestFile(arena, outside_file, "palisade landlock truncate probe content\n");

    const abi = try landlock.probeAbi();
    var ruleset = try landlock.Ruleset.init(abi, null);
    try ruleset.allowPath(inside, landlock.AccessFs.read_write, null);
    try ruleset.restrictSelf(null);
    ruleset.deinit();
    return .{ .inside_file = inside_file, .outside_file = outside_file };
}

/// 1 is the pass, and it means `EPERM`.
/// A channel that asks for nothing. It only has to exist.
fn serveNothing(_: *anyopaque, _: i32) sandbox.Channel.ServeResult {
    return .done;
}

/// Prints every open descriptor, one per line, except the one this listing reads.
fn printOpenFds() u8 {
    const dir_rc = linux.open("/proc/self/fd", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (linux.errno(dir_rc) != .SUCCESS) return 5;
    const dir_fd: i32 = @intCast(dir_rc);
    defer _ = linux.close(dir_fd);

    var buffer: [4096]u8 align(@alignOf(linux.dirent64)) = undefined;
    while (true) {
        const rc = linux.getdents64(dir_fd, &buffer, buffer.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return 5,
        }
        if (rc == 0) break;

        var offset: usize = 0;
        while (offset < rc) {
            const reclen = std.mem.readInt(u16, buffer[offset + 16 ..][0..2], .little);
            const name = std.mem.sliceTo(buffer[offset + 19 .. offset + reclen], 0);
            offset += reclen;
            const fd = std.fmt.parseInt(i32, name, 10) catch continue;
            if (fd == dir_fd) continue;
            var line: [16]u8 = undefined;
            const text = std.fmt.bufPrint(&line, "{d}\n", .{fd}) catch return 5;
            _ = linux.write(linux.STDOUT_FILENO, text.ptr, text.len);
        }
    }
    return 0;
}

fn ringRefusal(rc: usize) u8 {
    return switch (linux.errno(rc)) {
        .SUCCESS => 0,
        .PERM => 1,
        else => 4,
    };
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    return runOperation(init) catch |err| {
        if (err == error.NamespaceFailed) return namespace.nothing_measured_exit_status;
        return err;
    };
}

var channel_dummy: u8 = 0;

fn channelNetwork() sandbox.Network {
    return .{ .isolated = .{
        .device_name = "sbx0",
        .address4 = .{ 10, 0, 0, 1 },
        .prefix4 = 24,
        .address6 = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .prefix6 = 64,
    } };
}

fn spawnChannelProgram(
    arena: std.mem.Allocator,
    root: []const u8,
    channels: []const sandbox.Channel,
    helpers: []const sandbox.Helper,
    argv: []const []const u8,
) !std.process.Child.Term {
    const base = try baseEscapeConfig(arena);
    return sandbox.spawn(arena, .{
        .root = root,
        .mounts = base.mounts,
        .rules = base.rules,
        .cwd = "/",
        .env = &.{},
        .network = channelNetwork(),
        .channels = channels,
        .helpers = helpers,
    }, argv, .{});
}

fn writeStdout(bytes: []const u8) void {
    _ = linux.write(1, bytes.ptr, bytes.len);
}

/// Reads one request, writes it back, and keeps the channel open for the next one.
fn echoServe(_: *anyopaque, channel_fd: i32) sandbox.Channel.ServeResult {
    var buf: [16]u8 = undefined;
    const got = linux.read(channel_fd, &buf, buf.len);
    if (linux.errno(got) != .SUCCESS or got == 0) return .done;
    _ = linux.sendto(channel_fd, &buf, got, linux.MSG.NOSIGNAL, null, 0);
    return .more;
}

const Recorder = struct {
    bytes: [16]u8 = undefined,
    len: usize = 0,
};

fn recordServe(ptr: *anyopaque, channel_fd: i32) sandbox.Channel.ServeResult {
    const recorder: *Recorder = @ptrCast(@alignCast(ptr));
    const got = linux.read(channel_fd, &recorder.bytes, recorder.bytes.len);
    if (linux.errno(got) != .SUCCESS or got == 0) return .done;
    recorder.len = got;
    _ = linux.sendto(channel_fd, channel_ack, channel_ack.len, linux.MSG.NOSIGNAL, null, 0);
    return .done;
}

fn writeOkRun(_: *anyopaque, channel_fd: ?i32) u8 {
    const fd = channel_fd orelse return 1;
    const rc = linux.sendto(fd, "ok", 2, linux.MSG.NOSIGNAL, null, 0);
    return if (linux.errno(rc) == .SUCCESS) 0 else 1;
}

fn exitOnlyRun(_: *anyopaque, _: ?i32) u8 {
    return 0;
}

var kept_pipe_fd: i32 = -1;
var unkept_pipe_fd: i32 = -1;

fn keepFdRun(_: *anyopaque, _: ?i32) u8 {
    _ = linux.write(unkept_pipe_fd, "leak", 4);
    const rc = linux.write(kept_pipe_fd, "kept", 4);
    return if (linux.errno(rc) == .SUCCESS) 0 else 1;
}

fn outsideCallRun(_: *anyopaque, _: ?i32) u8 {
    _ = linux.getpid();
    return 0;
}

/// Writes the errno name, such as `PERM`, on standard output, and exits 0.
fn reportErrno(rc: usize) u8 {
    const name = @tagName(linux.errno(rc));
    var line: [32]u8 = undefined;
    const text = std.fmt.bufPrint(&line, "{s}\n", .{name}) catch return 5;
    writeStdout(text);
    return 0;
}

const channel_wait_tries: u32 = 10_000;
const channel_wait_step_ns: u64 = 1 * std.time.ns_per_ms;
const channel_ack = "ack";

fn runOperation(init: std.process.Init.Minimal) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("usage: probe <operation> [host-id]\n", .{});
        return 2;
    }
    // A filter installed here is inherited across the fork `sandbox.spawn` does and would kill its unshare.
    const builds_own_root = std.mem.eql(u8, args[1], "read-home") or
        std.mem.eql(u8, args[1], "write-readonly") or
        std.mem.eql(u8, args[1], "delete-mounted-file") or
        std.mem.eql(u8, args[1], "write-readonly-submount") or
        std.mem.eql(u8, args[1], "file-bind-content") or
        std.mem.eql(u8, args[1], "deny-symlink-outside") or
        std.mem.eql(u8, args[1], "bind-source-symlink") or
        std.mem.eql(u8, args[1], "deny-intermediate-symlink") or
        std.mem.eql(u8, args[1], "spawn-ptrace") or
        std.mem.eql(u8, args[1], "spawn-landlock-escape") or
        std.mem.eql(u8, args[1], "spawn-network-escape") or
        std.mem.eql(u8, args[1], "spawn-signal-host") or
        std.mem.eql(u8, args[1], "spawn-shm-attach") or
        std.mem.eql(u8, args[1], "spawn-report-pid") or
        std.mem.eql(u8, args[1], "spawn-default-signal") or
        std.mem.eql(u8, args[1], "spawn-keeper-reaps") or
        std.mem.eql(u8, args[1], "spawn-stdin-devnull") or
        std.mem.eql(u8, args[1], "spawn-owned-directory") or
        std.mem.eql(u8, args[1], "spawn-stdin-pipe") or
        std.mem.eql(u8, args[1], "spawn-proc-mask") or
        std.mem.eql(u8, args[1], "spawn-proc-live") or
        std.mem.eql(u8, args[1], "spawn-caps-drop") or
        std.mem.eql(u8, args[1], "spawn-open-fds") or
        std.mem.eql(u8, args[1], "spawn-open-fd-set") or
        std.mem.eql(u8, args[1], "spawn-supervisor-audit") or
        std.mem.eql(u8, args[1], "spawn-syscall-audit") or
        std.mem.eql(u8, args[1], "spawn-syscall-audit-off") or
        std.mem.eql(u8, args[1], "spawn-syscall-audit-daemon") or
        std.mem.eql(u8, args[1], "spawn-path-audit") or
        std.mem.eql(u8, args[1], "spawn-path-audit-off") or
        std.mem.eql(u8, args[1], "spawn-path-audit-dynamic") or
        std.mem.eql(u8, args[1], "spawn-path-audit-killed") or
        std.mem.eql(u8, args[1], "spawn-path-audit-stopped") or
        std.mem.eql(u8, args[1], "spawn-signal-middle-setsid") or
        std.mem.eql(u8, args[1], "spawn-memfd-exec") or
        std.mem.eql(u8, args[1], "spawn-handle-escape") or
        std.mem.eql(u8, args[1], "spawn-vsock") or
        std.mem.eql(u8, args[1], "spawn-proc-self-mem-write-landlock") or
        std.mem.eql(u8, args[1], "spawn-proc-self-mem-write-mount") or
        std.mem.eql(u8, args[1], "spawn-setns-proc1") or
        std.mem.eql(u8, args[1], "spawn-cgroup-remount") or
        std.mem.eql(u8, args[1], "cgroup-surface") or
        std.mem.eql(u8, args[1], "spawn-setup-fault-named-stderr") or
        std.mem.eql(u8, args[1], "spawn-setup-fault-default-stderr") or
        std.mem.eql(u8, args[1], "spawn-setup-fault-closed-stderr") or
        std.mem.eql(u8, args[1], "spawn-forge-exit") or
        std.mem.eql(u8, args[1], "spawn-signal-middle") or
        std.mem.eql(u8, args[1], "spawn-signal-middle-forked") or
        std.mem.eql(u8, args[1], "spawn-signal-middle-handled") or
        std.mem.eql(u8, args[1], "spawn-signal-group") or
        std.mem.eql(u8, args[1], "spawn-approval-socket") or
        std.mem.eql(u8, args[1], "spawn-group-press") or
        std.mem.eql(u8, args[1], "spawn-fork-bomb") or
        std.mem.eql(u8, args[1], "spawn-fork-bomb-unbounded") or
        std.mem.eql(u8, args[1], "spawn-mem-bomb") or
        std.mem.eql(u8, args[1], "spawn-mem-bomb-unbounded") or
        std.mem.eql(u8, args[1], "spawn-mem-bomb-cgroup") or
        std.mem.eql(u8, args[1], "spawn-fd-bomb") or
        std.mem.eql(u8, args[1], "spawn-fd-bomb-unbounded") or
        std.mem.startsWith(u8, args[1], "spawn-disk-") or
        std.mem.eql(u8, args[1], "channel-echo") or
        std.mem.eql(u8, args[1], "channel-reaim") or
        std.mem.eql(u8, args[1], "channel-helper") or
        std.mem.eql(u8, args[1], "channel-helper-exit-only") or
        std.mem.eql(u8, args[1], "channel-helper-outside-call") or
        std.mem.eql(u8, args[1], "channel-helper-keep") or
        std.mem.eql(u8, args[1], "connect-out-hands") or
        std.mem.eql(u8, args[1], "connect-out-keeps");

    const needs_scratch_root = builds_own_root or
        std.mem.eql(u8, args[1], "landlock-write-outside") or
        std.mem.eql(u8, args[1], "landlock-write-inside") or
        std.mem.eql(u8, args[1], "landlock-truncate-outside") or
        std.mem.eql(u8, args[1], "landlock-truncate-inside");

    const needs_id_arg = std.mem.eql(u8, args[1], "spawn-signal-host") or
        std.mem.eql(u8, args[1], "spawn-open-fds") or
        std.mem.eql(u8, args[1], "spawn-forge-exit") or
        std.mem.eql(u8, args[1], "spawned-forge-exit") or
        std.mem.eql(u8, args[1], "spawned-signal-host") or
        std.mem.eql(u8, args[1], "spawn-shm-attach") or
        std.mem.eql(u8, args[1], "spawned-shm-attach") or
        std.mem.eql(u8, args[1], "spawn-approval-socket") or
        std.mem.eql(u8, args[1], "spawned-approval-socket") or
        std.mem.eql(u8, args[1], "deny-symlink-outside") or
        std.mem.eql(u8, args[1], "bind-source-symlink") or
        std.mem.eql(u8, args[1], "deny-intermediate-symlink") or
        std.mem.eql(u8, args[1], "spawned-stdin-pipe") or
        std.mem.eql(u8, args[1], "session-keyring-fresh");

    const expected_args: usize = 2 +
        @as(usize, if (needs_scratch_root) 1 else 0) +
        @as(usize, if (needs_id_arg) 1 else 0);
    if (args.len != expected_args) {
        std.debug.print("usage: probe <operation> [root] [id]\n", .{});
        return 2;
    }
    var next_arg: usize = 2;
    const root_arg: []const u8 = blk: {
        if (!needs_scratch_root) break :blk "";
        const value = args[next_arg];
        next_arg += 1;
        break :blk value;
    };
    const id_arg: []const u8 = blk: {
        if (!needs_id_arg) break :blk "";
        const value = args[next_arg];
        next_arg += 1;
        break :blk value;
    };

    const spawned = std.mem.startsWith(u8, args[1], "spawned-");

    // A "netns-" operation enters the namespaces instead of installing the filter, since `unshare` is a blocked call.
    if (spawned) {
        // Nothing to set up. See the comment on `spawned` above.
    } else if (std.mem.startsWith(u8, args[1], "netns-")) {
        enterOrEndUnmeasured(.{});
    } else if (std.mem.eql(u8, args[1], "session-keyring-fresh")) {
        // No filter goes on, because the read back calls request_key, which is itself a blocked call.
    } else if (!builds_own_root) {
        // The relaxed filter gives up only the write and execute rule.
        const relaxed_wx = std.mem.endsWith(u8, args[1], "-relaxed");
        const insns = seccomp.build(arena, .{ .strict_wx = !relaxed_wx }) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        seccomp.install(bpf.Prog.init(insns), null) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
    }

    if (std.mem.eql(u8, args[1], "netns-connect")) {
        // This kernel prints zero bytes from /proc/net/route while `lo` is down.
        var route_buf: [4096]u8 = undefined;
        const route_fd = linux.open("/proc/net/route", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(route_fd) != .SUCCESS) {
            std.debug.print(
                "could not open /proc/net/route: {s}\n",
                .{@tagName(linux.errno(route_fd))},
            );
            return 4;
        }
        const route_handle: i32 = @intCast(route_fd);
        defer _ = linux.close(route_handle);

        const read_rc = linux.read(route_handle, &route_buf, route_buf.len);
        if (linux.errno(read_rc) != .SUCCESS) {
            std.debug.print(
                "could not read /proc/net/route: {s}\n",
                .{@tagName(linux.errno(read_rc))},
            );
            return 4;
        }
        var route_rows: usize = 0;
        var route_line_it = std.mem.splitScalar(u8, route_buf[0..read_rc], '\n');
        while (route_line_it.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "Iface")) continue;
            route_rows += 1;
        }
        if (route_rows != 0) {
            std.debug.print(
                "routing table has a route, the network namespace was not entered\n",
                .{},
            );
            return 4;
        }

        // From the connect side the failure must be ENETUNREACH.
        const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
        if (linux.errno(fd) != .SUCCESS) return 1;
        var addr = std.mem.zeroes(linux.sockaddr.in);
        addr.family = linux.AF.INET;
        addr.port = std.mem.nativeToBig(u16, 53);
        // 1.1.1.1
        addr.addr = std.mem.nativeToBig(u32, 0x01010101);
        const rc = linux.connect(@intCast(fd), @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
        const connect_errno = linux.errno(rc);
        if (connect_errno != .NETUNREACH) {
            std.debug.print(
                "connect did not fail with ENETUNREACH, got: {s}\n",
                .{@tagName(connect_errno)},
            );
            return 4;
        }
        return 1;
    }
    if (std.mem.eql(u8, args[1], "netns-loopback")) {
        // A network namespace must still permit a unix socket.
        const fd = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM, 0);
        return if (linux.errno(fd) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "netns-af-packet")) {
        // AF_PACKET moves whole link layer frames and answers to no route.
        const eth_p_all: u16 = 0x0003;
        const fd_rc = linux.socket(linux.AF.PACKET, linux.SOCK.RAW, std.mem.nativeToBig(u16, eth_p_all));
        if (linux.errno(fd_rc) != .SUCCESS) {
            std.debug.print("netns-af-packet: socket(AF_PACKET): {s}\n", .{@tagName(linux.errno(fd_rc))});
            return 4;
        }
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);

        var dev_buf: [4096]u8 = undefined;
        const dev_fd_rc = linux.open("/proc/net/dev", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(dev_fd_rc) != .SUCCESS) {
            std.debug.print("netns-af-packet: open /proc/net/dev: {s}\n", .{@tagName(linux.errno(dev_fd_rc))});
            return 4;
        }
        const dev_fd: i32 = @intCast(dev_fd_rc);
        defer _ = linux.close(dev_fd);
        const dev_read = linux.read(dev_fd, &dev_buf, dev_buf.len);
        if (linux.errno(dev_read) != .SUCCESS) {
            std.debug.print("netns-af-packet: read /proc/net/dev: {s}\n", .{@tagName(linux.errno(dev_read))});
            return 4;
        }
        var iface_count: usize = 0;
        var saw_lo = false;
        var dev_lines = std.mem.splitScalar(u8, dev_buf[0..dev_read], '\n');
        while (dev_lines.next()) |line| {
            // Both header lines carry a colon of their own kind.
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const name = std.mem.trim(u8, line[0..colon], " \t");
            if (name.len == 0 or std.mem.eql(u8, name, "Inter-|") or std.mem.eql(u8, name, "face")) continue;
            iface_count += 1;
            if (std.mem.eql(u8, name, "lo")) saw_lo = true;
        }
        if (!saw_lo or iface_count != 1) {
            std.debug.print(
                "netns-af-packet: expected only lo, found {d} interface(s)\n",
                .{iface_count},
            );
            return 4;
        }

        // `lo` is the one interface left, and namespace.enter leaves it down.
        var ifr: linux.ifreq = std.mem.zeroes(linux.ifreq);
        @memcpy(ifr.ifrn.name[0..2], "lo");
        const ioctl_rc = linux.ioctl(fd, linux.SIOCGIFINDEX, @intFromPtr(&ifr));
        if (linux.errno(ioctl_rc) != .SUCCESS) {
            std.debug.print("netns-af-packet: SIOCGIFINDEX lo: {s}\n", .{@tagName(linux.errno(ioctl_rc))});
            return 4;
        }
        const ifindex = ifr.ifru.ivalue;

        var sll = std.mem.zeroes(linux.sockaddr.ll);
        sll.family = linux.AF.PACKET;
        sll.ifindex = ifindex;
        sll.protocol = std.mem.nativeToBig(u16, eth_p_all);
        var frame = @as([32]u8, @splat(0));
        const send_rc = linux.sendto(fd, &frame, frame.len, 0, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll));
        const send_errno = linux.errno(send_rc);
        if (send_errno != .NETDOWN) {
            std.debug.print("netns-af-packet: sendto did not fail with ENETDOWN, got {s}\n", .{@tagName(send_errno)});
            return 4;
        }
        return 1;
    }

    if (std.mem.eql(u8, args[1], "session-keyring-fresh")) {
        // id_arg describes a key escape.zig planted in the session keyring. Finding it means the join failed.
        sandbox.native.joinFreshSessionKeyring(linux.STDERR_FILENO) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };

        const description_z = arena.dupeSentinel(u8, id_arg, 0) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        // "user" matches the type escape.zig used when it planted the key.
        const key_type = "user";
        const rc = linux.syscall4(
            .request_key,
            @intFromPtr(key_type.ptr),
            @intFromPtr(description_z.ptr),
            0,
            0,
        );
        const find_errno = linux.errno(rc);
        if (find_errno == .SUCCESS) return 0;
        return if (find_errno == .NOKEY) 1 else 5;
    }

    if (std.mem.eql(u8, args[1], "spawned-handle-escape")) {
        // `name_to_handle_at` turns a path into an opaque handle, and reopening it names no path for a rule to match.
        const target: [:0]const u8 = "/work/handle-target";
        const write_fd_rc = linux.open(target, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        if (linux.errno(write_fd_rc) != .SUCCESS) {
            std.debug.print("spawned-handle-escape: create /work/handle-target: {s}\n", .{@tagName(linux.errno(write_fd_rc))});
            return 5;
        }
        const write_fd: i32 = @intCast(write_fd_rc);
        _ = linux.write(write_fd, "handle\n", 7);
        _ = linux.close(write_fd);

        // `name_to_handle_at` encodes what a path lookup already reached.
        var raw: [136]u8 align(@alignOf(linux.file_handle)) = undefined;
        const handle: *linux.file_handle = @ptrCast(&raw);
        handle.handle_bytes = 128;
        var mount_id: i32 = undefined;
        const encode_rc = linux.name_to_handle_at(linux.AT.FDCWD, target, handle, &mount_id, 0);
        if (linux.errno(encode_rc) != .SUCCESS) {
            std.debug.print("spawned-handle-escape: name_to_handle_at: {s}\n", .{@tagName(linux.errno(encode_rc))});
            return 5;
        }

        // Not `O_PATH`: a path only descriptor carries no file operations.
        const mount_fd_rc = linux.open("/work", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        if (linux.errno(mount_fd_rc) != .SUCCESS) {
            std.debug.print("spawned-handle-escape: open /work: {s}\n", .{@tagName(linux.errno(mount_fd_rc))});
            return 5;
        }
        const mount_fd: i32 = @intCast(mount_fd_rc);

        const open_rc = linux.syscall3(
            .open_by_handle_at,
            @as(usize, @bitCast(@as(isize, mount_fd))),
            @intFromPtr(handle),
            0,
        );
        std.debug.print("spawned-handle-escape: open_by_handle_at: {s}\n", .{@tagName(linux.errno(open_rc))});
        return if (linux.errno(open_rc) == .SUCCESS) 0 else 6;
    }

    if (std.mem.eql(u8, args[1], "spawned-ptrace")) {
        const rc = linux.syscall4(.ptrace, 0, 0, 0, 0);
        // An installed filter kills this process before this line runs.
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "spawned-vsock")) {
        // The filter kills this on the domain argument alone.
        const rc = linux.socket(linux.AF.VSOCK, linux.SOCK.STREAM, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "spawned-setns-proc1")) {
        // A kernel can refuse the keeper's namespace fd once it drops capabilities, so this process's own fd is the control.
        var fd_rc = linux.open("/proc/1/ns/mnt", .{ .ACCMODE = .RDONLY }, 0);
        const init_errno = linux.errno(fd_rc);
        if (init_errno == .ACCES or init_errno == .PERM) {
            fd_rc = linux.open("/proc/self/ns/mnt", .{ .ACCMODE = .RDONLY }, 0);
        } else if (init_errno != .SUCCESS) {
            std.debug.print("spawned-setns-proc1: open /proc/1/ns/mnt: {s}\n", .{@tagName(init_errno)});
            return 5;
        }
        if (linux.errno(fd_rc) != .SUCCESS) {
            std.debug.print("spawned-setns-proc1: open control namespace: {s}\n", .{@tagName(linux.errno(fd_rc))});
            return 6;
        }
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);

        // setns sits on blocked_calls, so the filter kills the process before this line runs.
        const rc = linux.setns(fd, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "spawned-proc-self-mem-write-landlock")) {
        // This is open() and write() on a regular file. An O_WRONLY open meets the mount's read only mark first.
        const fd_rc = linux.open("/proc/self/mem", .{ .ACCMODE = .WRONLY }, 0);
        const open_errno = linux.errno(fd_rc);
        if (open_errno == .SUCCESS) {
            _ = linux.close(@intCast(fd_rc));
            return 0;
        }
        return if (open_errno == .ROFS) 1 else 5;
    }

    if (std.mem.eql(u8, args[1], "spawned-proc-self-mem-write-mount")) {
        // write_file is granted on /proc on purpose, so a refusal here cannot be Landlock's doing.
        const fd_rc = linux.open("/proc/self/mem", .{ .ACCMODE = .WRONLY }, 0);
        const open_errno = linux.errno(fd_rc);
        if (open_errno == .SUCCESS) {
            _ = linux.close(@intCast(fd_rc));
            return 0;
        }
        return if (open_errno == .ROFS) 1 else 5;
    }

    if (std.mem.eql(u8, args[1], "spawned-cgroup-remount")) {
        // namespace.enter never takes CLONE_NEWCGROUP, so a fresh "cgroup2" mount would see the whole host hierarchy.
        const rc = linux.mount("cgroup2", "/nonexistent-cgroup-mount", "cgroup2", 0, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "spawned-memfd-exec")) {
        const self_rc = linux.open("/probe", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(self_rc) != .SUCCESS) {
            std.debug.print("spawned-memfd-exec: open /probe: {s}\n", .{@tagName(linux.errno(self_rc))});
            return 5;
        }
        const self_fd: i32 = @intCast(self_rc);
        defer _ = linux.close(self_fd);

        var bytes: std.ArrayList(u8) = .empty;
        var chunk: [65536]u8 = undefined;
        while (true) {
            const n = linux.read(self_fd, &chunk, chunk.len);
            const read_errno = linux.errno(n);
            if (read_errno == .INTR) continue;
            if (read_errno != .SUCCESS) {
                std.debug.print("spawned-memfd-exec: read /probe: {s}\n", .{@tagName(read_errno)});
                return 5;
            }
            if (n == 0) break;
            bytes.appendSlice(arena, chunk[0..n]) catch return 5;
        }

        const disk_path: [:0]const u8 = "/work/payload";
        const disk_fd_rc = linux.open(disk_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o755);
        if (linux.errno(disk_fd_rc) != .SUCCESS) {
            std.debug.print("spawned-memfd-exec: create /work/payload: {s}\n", .{@tagName(linux.errno(disk_fd_rc))});
            return 5;
        }
        const disk_fd: i32 = @intCast(disk_fd_rc);
        {
            var written: usize = 0;
            while (written < bytes.items.len) {
                const n = linux.write(disk_fd, bytes.items.ptr + written, bytes.items.len - written);
                if (linux.errno(n) != .SUCCESS) {
                    std.debug.print("spawned-memfd-exec: write /work/payload: {s}\n", .{@tagName(linux.errno(n))});
                    _ = linux.close(disk_fd);
                    return 5;
                }
                written += n;
            }
        }
        _ = linux.close(disk_fd);

        const empty_envp = arena.allocSentinel(?[*:0]const u8, 0, null) catch return 5;
        const disk_argv = arena.allocSentinel(?[*:0]const u8, 2, null) catch return 5;
        disk_argv[0] = arena.dupeSentinel(u8, "probe", 0) catch return 5;
        disk_argv[1] = arena.dupeSentinel(u8, "spawned-memfd-direct-should-be-refused", 0) catch return 5;

        const direct_rc = linux.execve(disk_path, disk_argv, empty_envp);
        const direct_errno = linux.errno(direct_rc);
        if (direct_errno != .ACCES) {
            std.debug.print(
                "spawned-memfd-exec: on-disk execve did not fail with EACCES, got {s}\n",
                .{@tagName(direct_errno)},
            );
            return 5;
        }

        // memfd_create makes an anonymous file with no directory entry, so a path based rule has nothing to match.
        const memfd_name: [:0]const u8 = "palisade-probe-memfd";
        const memfd_rc = linux.memfd_create(memfd_name, 0);
        if (linux.errno(memfd_rc) != .SUCCESS) {
            std.debug.print("spawned-memfd-exec: memfd_create: {s}\n", .{@tagName(linux.errno(memfd_rc))});
            return 6;
        }
        const memfd: i32 = @intCast(memfd_rc);
        {
            var written: usize = 0;
            while (written < bytes.items.len) {
                const n = linux.write(memfd, bytes.items.ptr + written, bytes.items.len - written);
                if (linux.errno(n) != .SUCCESS) {
                    std.debug.print("spawned-memfd-exec: write memfd: {s}\n", .{@tagName(linux.errno(n))});
                    return 6;
                }
                written += n;
            }
        }

        const memfd_argv = arena.allocSentinel(?[*:0]const u8, 2, null) catch return 5;
        memfd_argv[0] = arena.dupeSentinel(u8, "memfd-probe", 0) catch return 5;
        memfd_argv[1] = arena.dupeSentinel(u8, "spawned-memfd-landed", 0) catch return 5;

        // `AT_EMPTY_PATH` lets `execveat` take an empty path relative to a descriptor, which is the flag the filter reads.
        const exec_rc = linux.execveat(memfd, "", memfd_argv, empty_envp, .{ .SYMLINK_NOFOLLOW = false, .EMPTY_PATH = true });
        std.debug.print("spawned-memfd-exec: execveat on the memfd: {s}\n", .{@tagName(linux.errno(exec_rc))});
        return 6;
    }

    if (std.mem.eql(u8, args[1], "spawned-memfd-landed")) {
        // Seccomp installs once and no execve can shed it.
        const rc = linux.syscall4(.ptrace, 0, 0, 0, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "spawned-landlock-read")) {
        const fd = linux.open(spawned_landlock_target, .{ .ACCMODE = .RDONLY }, 0);
        const open_errno = linux.errno(fd);
        if (open_errno == .SUCCESS) {
            _ = linux.close(@intCast(fd));
            return 0; // Opened a path no rule named. The ruleset never applied.
        }
        return if (open_errno == .ACCES) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "spawned-fork-bomb")) {
        // Every child blocks forever on a pipe nobody writes to, so it counts against `pids.max`.
        var fds: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return 3;

        var made: u8 = 0;
        while (made < fork_bomb_cap) {
            const rc = linux.fork();
            if (linux.errno(rc) != .SUCCESS) break;
            if (rc == 0) {
                var byte: [1]u8 = undefined;
                while (true) _ = linux.read(fds[0], &byte, 1);
            }
            made += 1;
        }
        return made;
    }
    if (std.mem.eql(u8, args[1], "spawned-mem-bomb")) {
        // Every block is written to, since `memory.max` counts resident pages.
        var touched: u8 = 0;
        while (touched < mem_bomb_cap) {
            const block = arena.alloc(u8, mem_bomb_block_bytes) catch break;
            @memset(block, 1);
            touched += 1;
        }
        return touched;
    }
    if (std.mem.eql(u8, args[1], "spawned-fd-bomb")) {
        var opened: u8 = 0;
        while (opened < fd_bomb_cap) {
            const rc = linux.open("/probe", .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(rc) != .SUCCESS) break;
            opened += 1;
        }
        return opened;
    }
    if (std.mem.eql(u8, args[1], "spawned-disk-file-bomb")) {
        var made: u8 = 0;
        while (made < disk_file_cap) {
            var name_buffer: [std.fs.max_path_bytes]u8 = undefined;
            const name = std.fmt.bufPrintSentinel(&name_buffer, "{s}/f{d}", .{ scratch_target, made }, 0) catch return 3;
            const fd_rc = linux.open(name.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
            if (linux.errno(fd_rc) != .SUCCESS) break;
            const fd: i32 = @intCast(fd_rc);
            const payload = @as([disk_file_bytes]u8, @splat('d'));
            const written = linux.write(fd, &payload, payload.len);
            _ = linux.close(fd);
            if (linux.errno(written) != .SUCCESS) break;
            made += 1;
        }
        return made;
    }
    if (std.mem.eql(u8, args[1], "spawned-disk-one-bomb")) {
        var name_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const name = std.fmt.bufPrintSentinel(&name_buffer, "{s}/one", .{scratch_target}, 0) catch return 3;
        const fd_rc = linux.open(name.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        if (linux.errno(fd_rc) != .SUCCESS) return 3;
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);

        var blocks: u8 = 0;
        while (blocks < disk_one_cap) {
            const payload = @as([disk_one_block_bytes]u8, @splat('o'));
            const written = linux.write(fd, &payload, payload.len);
            if (linux.errno(written) != .SUCCESS) break;
            if (written != payload.len) break;
            blocks += 1;
        }
        return blocks;
    }
    if (std.mem.eql(u8, args[1], "spawned-approval-socket")) {
        const path_z = arena.dupeSentinel(u8, id_arg, 0) catch return 3;
        const fd = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM, 0);
        if (linux.errno(fd) != .SUCCESS) return 5;
        var addr = std.mem.zeroes(linux.sockaddr.un);
        addr.family = linux.AF.UNIX;
        if (path_z.len >= addr.path.len) return 3;
        @memcpy(addr.path[0..path_z.len], path_z);
        const rc = linux.connect(@intCast(fd), @ptrCast(&addr), @sizeOf(linux.sockaddr.un));
        const connect_errno = linux.errno(rc);
        if (connect_errno == .SUCCESS) {
            _ = linux.close(@intCast(fd));
            return 0;
        }
        // The path is not in this mount tree, so the refusal must be ENOENT.
        if (connect_errno != .NOENT) {
            std.debug.print(
                "connect to the approval socket did not fail with ENOENT, got: {s}\n",
                .{@tagName(connect_errno)},
            );
            return 5;
        }
        return 1;
    }
    if (std.mem.eql(u8, args[1], "spawned-connect")) {
        const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
        if (linux.errno(fd) != .SUCCESS) return 5;
        var addr = std.mem.zeroes(linux.sockaddr.in);
        addr.family = linux.AF.INET;
        addr.port = std.mem.nativeToBig(u16, 53);
        // 1.1.1.1
        addr.addr = std.mem.nativeToBig(u32, 0x01010101);
        const rc = linux.connect(@intCast(fd), @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
        const connect_errno = linux.errno(rc);
        if (connect_errno == .SUCCESS) return 0; // Reached the host. The namespace never applied.
        return if (connect_errno == .NETUNREACH) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "spawned-signal-host")) {
        const target = std.fmt.parseInt(linux.pid_t, id_arg, 10) catch {
            std.debug.print("spawned-signal-host: bad pid argument\n", .{});
            return 5;
        };
        const rc = linux.kill(target, .KILL);
        const kill_errno = linux.errno(rc);
        if (kill_errno == .SUCCESS) return 0; // Reached the host process. The pid namespace never applied.
        return if (kill_errno == .SRCH) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "spawned-shm-attach")) {
        const shmid = std.fmt.parseInt(usize, id_arg, 10) catch {
            std.debug.print("spawned-shm-attach: bad shmid argument\n", .{});
            return 5;
        };
        const rc = linux.syscall3(.shmat, shmid, 0, 0);
        const shmat_errno = linux.errno(rc);
        if (shmat_errno == .SUCCESS) return 0; // Attached the host segment. The ipc namespace never applied.
        return if (shmat_errno == .INVAL) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "spawned-report-pid")) {
        var buffer: [16]u8 = undefined;
        const line = std.fmt.bufPrint(&buffer, "{d}\n", .{linux.getpid()}) catch unreachable;
        _ = linux.write(linux.STDOUT_FILENO, line.ptr, line.len);
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-hold-until-closed")) {
        var buffer: [8]u8 = undefined;
        while (true) {
            const n = linux.read(linux.STDIN_FILENO, &buffer, buffer.len);
            switch (linux.errno(n)) {
                .SUCCESS => if (n == 0) return 0,
                .INTR => continue,
                else => return 5,
            }
        }
    }
    if (std.mem.eql(u8, args[1], "spawned-default-signal")) {
        _ = linux.kill(linux.getpid(), .TERM);
        return 8;
    }
    if (std.mem.eql(u8, args[1], "spawned-keeper-reaps")) {
        var pipe: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })) != .SUCCESS) return 4;

        const parent_rc = linux.fork();
        if (linux.errno(parent_rc) != .SUCCESS) return 5;
        const parent_pid: linux.pid_t = @intCast(parent_rc);
        if (parent_pid == 0) {
            _ = linux.close(pipe[0]);
            const orphan_rc = linux.fork();
            if (linux.errno(orphan_rc) != .SUCCESS) linux.exit(6);
            const orphan_pid: linux.pid_t = @intCast(orphan_rc);
            if (orphan_pid == 0) linux.exit(0);
            const pid_bytes = std.mem.asBytes(&orphan_pid);
            if (linux.errno(linux.write(pipe[1], pid_bytes.ptr, pid_bytes.len)) != .SUCCESS) {
                linux.exit(7);
            }
            linux.exit(0);
        }

        _ = linux.close(pipe[1]);
        var orphan_pid: linux.pid_t = undefined;
        const pid_bytes = std.mem.asBytes(&orphan_pid);
        const read_rc = linux.read(pipe[0], pid_bytes.ptr, pid_bytes.len);
        _ = linux.close(pipe[0]);
        if (linux.errno(read_rc) != .SUCCESS or read_rc != @sizeOf(linux.pid_t)) return 8;

        var status: i32 = undefined;
        var wait_rc = linux.waitpid(parent_pid, &status, 0);
        while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(parent_pid, &status, 0);
        if (linux.errno(wait_rc) != .SUCCESS or !linux.W.IFEXITED(@bitCast(status)) or
            linux.W.EXITSTATUS(@bitCast(status)) != 0)
        {
            return 9;
        }

        var tries: usize = 0;
        while (tries < 2000) : (tries += 1) {
            const exists_rc = linux.kill(orphan_pid, @fromBackingInt(@intCast(0)));
            if (linux.errno(exists_rc) == .SRCH) return 0;
            if (linux.errno(exists_rc) != .SUCCESS) return 10;
            var pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
            _ = linux.nanosleep(&pause, null);
        }
        return 11;
    }
    if (std.mem.eql(u8, args[1], "spawned-count-opens")) {
        var made: usize = 0;
        while (made < opens_in_probe) : (made += 1) {
            const rc = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(rc) != .SUCCESS) return 5;
            _ = linux.close(@intCast(rc));
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-name-paths")) {
        var made: usize = 0;
        while (made < 3) : (made += 1) {
            const rc = linux.openat(linux.AT.FDCWD, named_ungranted, .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(rc) == .SUCCESS) _ = linux.close(@intCast(rc));
        }
        const second = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(second) != .SUCCESS) return 5;
        _ = linux.close(@intCast(second));

        const inside = linux.openat(linux.AT.FDCWD, named_granted, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(inside) == .SUCCESS) _ = linux.close(@intCast(inside));
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-kill-the-reader")) {
        const before = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(before) != .SUCCESS) return 5;
        _ = linux.close(@intCast(before));

        // A supervisor that kept its own copy of the descriptor would leave the next open held forever.
        const on_alarm = linux.Sigaction{
            .handler = .{ .handler = endOnAlarm },
            .mask = linux.sigemptyset(),
            .flags = 0,
        };
        if (linux.errno(linux.sigaction(.ALRM, &on_alarm, null)) != .SUCCESS) return 10;

        const alarm: linux.itimerspec = .{
            .it_interval = .{ .sec = 0, .nsec = 0 },
            .it_value = .{ .sec = 10, .nsec = 0 },
        };
        if (linux.errno(linux.setitimer(@backingInt(linux.ITIMER.REAL), &alarm, null)) != .SUCCESS)
            return 9;

        if (linux.errno(linux.kill(reader_pid_in_namespace, linux.SIG.KILL)) != .SUCCESS) return 6;

        var tries: usize = 0;
        while (tries < 1000) : (tries += 1) {
            const after = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
            switch (linux.errno(after)) {
                .SUCCESS => {
                    _ = linux.close(@intCast(after));
                    var pause: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
                    _ = linux.nanosleep(&pause, null);
                },
                .NOSYS => return 0,
                else => return 7,
            }
        }
        return 8;
    }
    if (std.mem.eql(u8, args[1], "spawned-stop-the-reader")) {
        // This trapped call cannot finish before R exists and serves it.
        const before = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(before) != .SUCCESS) return 5;
        _ = linux.close(@intCast(before));
        if (linux.errno(linux.kill(reader_pid_in_namespace, .STOP)) != .SUCCESS) return 6;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-leave-daemon")) {
        // The forked process still carries the filter, so a supervisor that waited for it would hold the tool call.
        const forked = linux.fork();
        if (linux.errno(forked) != .SUCCESS) return 5;
        if (forked == 0) {
            var pause: linux.timespec = .{ .sec = 0, .nsec = 250_000_000 };
            _ = linux.nanosleep(&pause, null);
            const opened = linux.openat(linux.AT.FDCWD, "/probe", .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(opened) == .SUCCESS) _ = linux.close(@intCast(opened));
            return 0;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-channel-echo")) {
        const channel = sandbox.channelFd(0);
        const sent = "ping";
        const wrote = linux.write(channel, sent, sent.len);
        if (linux.errno(wrote) != .SUCCESS or wrote != sent.len) return 5;
        var buf: [sent.len]u8 = undefined;
        const got = linux.read(channel, &buf, buf.len);
        if (linux.errno(got) != .SUCCESS or got != sent.len) return 1;
        return if (std.mem.eql(u8, &buf, sent)) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "spawned-channel-reaim")) {
        var addr = std.mem.zeroes(linux.sockaddr.un);
        addr.path[0] = '/';
        addr.path[1] = 'x';
        const rc = linux.connect(sandbox.channelFd(0), &addr, @sizeOf(linux.sockaddr.un));
        return reportErrno(rc);
    }
    if (std.mem.eql(u8, args[1], "spawned-connect-loopback")) {
        const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
        if (linux.errno(fd) != .SUCCESS) return 5;
        var addr = std.mem.zeroes(linux.sockaddr.in);
        addr.family = linux.AF.INET;
        addr.port = std.mem.nativeToBig(u16, 1);
        addr.addr = std.mem.nativeToBig(u32, 0x7f000001);
        const rc = linux.connect(@intCast(fd), @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
        return reportErrno(rc);
    }
    if (std.mem.eql(u8, args[1], "spawned-exit-zero")) return 0;
    if (std.mem.eql(u8, args[1], "spawned-channel-wait")) {
        // The host takes the helper's bytes, then answers `ack`. Peeking leaves the
        // bytes in place, so this only sees `ack` once the host has recorded them.
        const channel = sandbox.channelFd(0);
        var tries: u32 = 0;
        while (tries < channel_wait_tries) : (tries += 1) {
            var peek: [channel_ack.len]u8 = undefined;
            const peeked = linux.recvfrom(channel, &peek, peek.len, linux.MSG.PEEK | linux.MSG.DONTWAIT, null, null);
            if (linux.errno(peeked) == .SUCCESS and peeked == peek.len) {
                return if (std.mem.eql(u8, &peek, channel_ack)) 0 else 1;
            }
            var pause: linux.timespec = .{ .sec = 0, .nsec = @intCast(channel_wait_step_ns) };
            _ = linux.nanosleep(&pause, null);
        }
        return 1;
    }
    if (std.mem.eql(u8, args[1], "spawned-caps-drop")) {
        // `capget` would read the cleared effective/permitted/inheritable sets, not `CapBnd`, so this reads `PR_CAPBSET_READ` instead.
        var cap: usize = 0;
        while (cap <= linux.CAP.LAST_CAP) : (cap += 1) {
            const rc = linux.prctl(@backingInt(linux.PR.CAPBSET_READ), cap, 0, 0, 0);
            const cap_errno = linux.errno(rc);
            if (cap_errno == .INVAL) break; // A kernel older than CAP.LAST_CAP: nothing above this exists.
            if (cap_errno != .SUCCESS) return 5;
            if (rc != 0) return 1; // Still in the bounding set. The drop did not run, or did not finish.
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-owned-directory")) {
        for ([_][*:0]const u8{ "/etc/hosts", "/etc/resolv.conf" }) |path| {
            const fd_rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(fd_rc) != .SUCCESS) return 5;
            const fd: i32 = @intCast(fd_rc);
            defer _ = linux.close(fd);
            var buffer: [128]u8 = undefined;
            if (!std.mem.eql(u8, readToEnd(fd, &buffer), owned_replacement)) return 1;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-stdin-devnull")) {
        var stx: linux.Statx = undefined;
        const rc = linux.statx(linux.STDIN_FILENO, "", linux.AT.EMPTY_PATH, linux.STATX.BASIC_STATS, &stx);
        if (linux.errno(rc) != .SUCCESS) return 5;
        const is_char_device = (stx.mode & linux.S.IFMT) == linux.S.IFCHR;
        return if (is_char_device) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "spawned-stdin-pipe")) {
        var stx: linux.Statx = undefined;
        const stat_rc = linux.statx(linux.STDIN_FILENO, "", linux.AT.EMPTY_PATH, linux.STATX.BASIC_STATS, &stx);
        if (linux.errno(stat_rc) != .SUCCESS) return 5;

        // A pipe, where /dev/null and a terminal are character devices.
        if ((stx.mode & linux.S.IFMT) != linux.S.IFIFO) {
            std.debug.print("spawned-stdin-pipe: descriptor 0 is not a pipe\n", .{});
            return 1;
        }

        // Not a terminal: TIOCSTI needs descriptor 0 to be one, and a pipe answers ENOTTY.
        var termios: linux.termios = undefined;
        if (linux.errno(linux.tcgetattr(linux.STDIN_FILENO, &termios)) == .SUCCESS) {
            std.debug.print("spawned-stdin-pipe: descriptor 0 is a terminal\n", .{});
            return 1;
        }

        var buffer: [stdin_pipe_token.len]u8 = undefined;
        var filled: usize = 0;
        while (filled < buffer.len) {
            const rc = linux.read(linux.STDIN_FILENO, buffer[filled..].ptr, buffer.len - filled);
            const read_errno = linux.errno(rc);
            if (read_errno == .INTR) continue;
            if (read_errno != .SUCCESS) return 5;
            if (rc == 0) break;
            filled += rc;
        }
        if (!std.mem.eql(u8, buffer[0..filled], stdin_pipe_token)) {
            std.debug.print("spawned-stdin-pipe: descriptor 0 carried other bytes\n", .{});
            return 1;
        }

        var extra: [1]u8 = undefined;
        const eof_rc = linux.read(linux.STDIN_FILENO, &extra, 1);
        if (linux.errno(eof_rc) != .SUCCESS or eof_rc != 0) {
            std.debug.print("spawned-stdin-pipe: descriptor 0 never reached end of file\n", .{});
            return 1;
        }

        // The exemption is one descriptor wide: a directory descriptor on the host root must be gone.
        const escape_fd = std.fmt.parseInt(i32, id_arg, 10) catch return 5;
        if (linux.errno(linux.fcntl(escape_fd, linux.F.GETFD, 0)) != .BADF) {
            std.debug.print("spawned-stdin-pipe: an inherited descriptor survived\n", .{});
            return 1;
        }

        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-open-fds")) {
        return printOpenFds();
    }
    if (std.mem.eql(u8, args[1], "spawned-open-fd-set")) {
        var fd: i32 = 0;
        while (fd < open_fd_set_scan_limit) : (fd += 1) {
            const is_open = linux.errno(linux.fcntl(fd, linux.F.GETFD, 0)) == .SUCCESS;
            const belongs = fd <= linux.STDERR_FILENO;
            if (is_open == belongs) continue;
            if (is_open) {
                std.debug.print("spawned-open-fd-set: descriptor {d} crossed execve\n", .{fd});
            } else {
                std.debug.print("spawned-open-fd-set: descriptor {d} did not reach the program\n", .{fd});
            }
            return 1;
        }

        if (fileTypeOf(linux.STDIN_FILENO) != linux.S.IFCHR) {
            std.debug.print("spawned-open-fd-set: descriptor 0 is not a character device\n", .{});
            return 1;
        }

        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-proc-mask")) {
        // The list comes from `namespace.masked_proc_entries` itself, so a name added there is covered on the day it is added.
        var checked: usize = 0;
        for (namespace.masked_proc_entries) |name| {
            var path_buffer: [64]u8 = undefined;
            const path = std.fmt.bufPrintSentinel(&path_buffer, "/proc/{s}", .{name}, 0) catch return 5;

            const fd_rc = linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0);
            const open_errno = linux.errno(fd_rc);
            if (open_errno == .NOENT) continue;
            if (open_errno != .SUCCESS) {
                std.debug.print("spawned-proc-mask: open {s}: {s}\n", .{ path, @tagName(open_errno) });
                return 5;
            }
            const fd: i32 = @intCast(fd_rc);
            defer _ = linux.close(fd);

            var buffer: [256]u8 = undefined;
            const read_rc = linux.read(fd, &buffer, buffer.len);
            if (linux.errno(read_rc) != .SUCCESS) {
                std.debug.print("spawned-proc-mask: read {s}: {s}\n", .{ path, @tagName(linux.errno(read_rc)) });
                return 5;
            }
            if (read_rc != 0) {
                std.debug.print("spawned-proc-mask: {s} gave {d} bytes\n", .{ path, read_rc });
                return 1;
            }
            checked += 1;
        }
        // `cmdline`, `version` and `kallsyms` are in every kernel.
        if (checked < 3) {
            std.debug.print("spawned-proc-mask: only {d} entries existed to check\n", .{checked});
            return 5;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-proc-live")) {
        var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const link_rc = linux.readlink("/proc/self/exe", &link_buffer, link_buffer.len);
        if (linux.errno(link_rc) != .SUCCESS) {
            std.debug.print("spawned-proc-live: /proc/self/exe: {s}\n", .{@tagName(linux.errno(link_rc))});
            return 1;
        }
        if (!std.mem.eql(u8, link_buffer[0..link_rc], "/probe")) {
            std.debug.print("spawned-proc-live: /proc/self/exe gave {s}\n", .{link_buffer[0..link_rc]});
            return 1;
        }

        const fd_rc = linux.open("/proc/uptime", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(fd_rc) != .SUCCESS) {
            std.debug.print("spawned-proc-live: open /proc/uptime: {s}\n", .{@tagName(linux.errno(fd_rc))});
            return 5;
        }
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);
        var buffer: [256]u8 = undefined;
        const read_rc = linux.read(fd, &buffer, buffer.len);
        if (linux.errno(read_rc) != .SUCCESS) {
            std.debug.print("spawned-proc-live: read /proc/uptime: {s}\n", .{@tagName(linux.errno(read_rc))});
            return 5;
        }
        if (read_rc == 0) {
            std.debug.print("spawned-proc-live: /proc/uptime was empty\n", .{});
            return 5;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-forge-exit")) {
        // The status is the one the test asked for. The line on stdout shows the child ran.
        const status = std.fmt.parseInt(u8, id_arg, 10) catch return 5;
        _ = linux.write(linux.STDOUT_FILENO, "forged\n", 7);
        return status;
    }
    if (std.mem.eql(u8, args[1], "spawned-loop-write")) {
        // If PDEATHSIG never arms, this process orphans and keeps writing.
        while (true) {
            const fd = linux.open("/work/heartbeat.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o644);
            if (linux.errno(fd) == .SUCCESS) {
                const handle: i32 = @intCast(fd);
                _ = linux.write(handle, "x", 1);
                _ = linux.close(handle);
            }
            _ = linux.nanosleep(&.{ .sec = 0, .nsec = 5_000_000 }, null);
        }
    }

    if (std.mem.eql(u8, args[1], "spawned-fork-loop-write")) {
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) {
            std.debug.print("spawned-fork-loop-write: fork failed\n", .{});
            return 5;
        }

        if (@as(linux.pid_t, @intCast(child)) == 0) {
            while (true) {
                const fd = linux.open("/work/heartbeat.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o644);
                if (linux.errno(fd) == .SUCCESS) {
                    const handle: i32 = @intCast(fd);
                    _ = linux.write(handle, "x", 1);
                    _ = linux.close(handle);
                }
                _ = linux.nanosleep(&.{ .sec = 0, .nsec = 5_000_000 }, null);
            }
        }

        const marker = linux.open("/work/forked.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o644);
        if (linux.errno(marker) == .SUCCESS) {
            const handle: i32 = @intCast(marker);
            _ = linux.write(handle, "f", 1);
            _ = linux.close(handle);
        }

        while (true) _ = linux.nanosleep(&.{ .sec = 3600, .nsec = 0 }, null);
    }

    if (std.mem.eql(u8, args[1], "spawned-setsid-fork-loop-write")) {
        // `PR_SET_PDEATHSIG` fires on a death, and `cgroup.kill` on membership, so neither reads the process group setsid() left.
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) {
            std.debug.print("spawned-setsid-fork-loop-write: fork failed\n", .{});
            return 5;
        }

        if (@as(linux.pid_t, @intCast(child)) == 0) {
            // setsid fails with EPERM for a process that already leads a group.
            const setsid_rc = linux.setsid();
            if (linux.errno(setsid_rc) != .SUCCESS) {
                std.debug.print(
                    "spawned-setsid-fork-loop-write: setsid: {s}\n",
                    .{@tagName(linux.errno(setsid_rc))},
                );
                return 5;
            }
            writeTestFile(arena, "/work/setsid-ok", "ok\n") catch |err| {
                std.debug.print(
                    "spawned-setsid-fork-loop-write: could not write the setsid marker: {s}\n",
                    .{@errorName(err)},
                );
                return 5;
            };

            while (true) {
                const fd = linux.open("/work/heartbeat.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o644);
                if (linux.errno(fd) == .SUCCESS) {
                    const handle: i32 = @intCast(fd);
                    _ = linux.write(handle, "x", 1);
                    _ = linux.close(handle);
                }
                _ = linux.nanosleep(&.{ .sec = 0, .nsec = 5_000_000 }, null);
            }
        }

        const marker = linux.open("/work/forked.txt", .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o644);
        if (linux.errno(marker) == .SUCCESS) {
            const handle: i32 = @intCast(marker);
            _ = linux.write(handle, "f", 1);
            _ = linux.close(handle);
        }

        while (true) _ = linux.nanosleep(&.{ .sec = 3600, .nsec = 0 }, null);
    }

    if (std.mem.eql(u8, args[1], "spawned-signal-group")) {
        // `kill(0, sig)` names the caller's own process group, which a fresh pid namespace does not renumber.
        const rc = linux.kill(0, .USR1);
        const kill_errno = linux.errno(rc);
        if (kill_errno != .SUCCESS) {
            std.debug.print("spawned-signal-group: kill(0, USR1): {s}\n", .{@tagName(kill_errno)});
            return 5;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawned-group-press")) {
        // Catches the signal rather than dying, so arrival and death read apart.
        catchSignal(.USR1);
        writeTestFile(arena, "/work/started", "started\n") catch |err| {
            std.debug.print("spawned-group-press: could not write the marker: {s}\n", .{@errorName(err)});
            return 5;
        };

        if (!waitForPath("/work/go")) {
            std.debug.print("spawned-group-press: the caller never wrote /work/go\n", .{});
            return 4;
        }
        return if (caller_signal_seen.load(.monotonic)) 1 else 0;
    }

    if (std.mem.eql(u8, args[1], "read-home")) {
        enterTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        const fd = linux.open("/home", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        const open_errno = linux.errno(fd);
        if (open_errno == .SUCCESS) _ = linux.close(@intCast(fd));
        if (open_errno == .SUCCESS) return 0;
        return if (open_errno == .NOENT) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "cgroup-surface")) {
        enterTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        const fd = linux.open("/sys/fs/cgroup", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        const open_errno = linux.errno(fd);
        if (open_errno == .SUCCESS) _ = linux.close(@intCast(fd));
        if (open_errno == .SUCCESS) return 0;
        return if (open_errno == .NOENT) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "write-readonly")) {
        enterTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        const fd = linux.open(
            "/nix/store/palisade-probe",
            .{ .ACCMODE = .WRONLY, .CREAT = true },
            0o644,
        );
        const open_errno = linux.errno(fd);
        if (open_errno == .SUCCESS) _ = linux.close(@intCast(fd));
        if (open_errno == .SUCCESS) return 0;
        // A read only mount refuses a new file with EROFS, not EPERM or EACCES.
        return if (open_errno == .ROFS) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "write-readonly-submount")) {
        enterSubmountTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        const fd = linux.open(
            "/guarded/sub/palisade-probe",
            .{ .ACCMODE = .WRONLY, .CREAT = true },
            0o644,
        );
        const open_errno = linux.errno(fd);
        if (open_errno == .SUCCESS) _ = linux.close(@intCast(fd));
        if (open_errno == .SUCCESS) return 0;
        // The submount must answer the same EROFS a direct bind gives.
        return if (open_errno == .ROFS) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "delete-mounted-file")) {
        enterTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        // A file that is a mount point cannot be unlinked: EBUSY.
        const unlink_errno = linux.errno(linux.unlink("/work/palisade.zon"));
        if (unlink_errno == .SUCCESS) return 0;
        return if (unlink_errno == .BUSY) 1 else 5;
    }
    if (std.mem.eql(u8, args[1], "file-bind-content")) {
        enterFileOverFileTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };

        // The target must hold the source bytes and not an empty directory.
        var read_buffer: [64]u8 = undefined;
        var matched = false;
        const fd = linux.open("/marker", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(fd) == .SUCCESS) {
            const handle: i32 = @intCast(fd);
            const read_rc = linux.read(handle, &read_buffer, read_buffer.len);
            _ = linux.close(handle);
            if (linux.errno(read_rc) == .SUCCESS) {
                matched = std.mem.eql(u8, read_buffer[0..read_rc], file_over_file_content);
            }
        }

        return if (matched) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "deny-symlink-outside")) {
        // `id_arg` is a directory nothing in this mount tree names.
        const secret_content = "palisade outside secret content\n";
        const secret_path = try std.fs.path.join(arena, &.{ id_arg, "secret" });
        try writeTestFile(arena, secret_path, secret_content);
        const secret_z = try arena.dupeSentinel(u8, secret_path, 0);

        // `deny.zig`'s own `check` accepts this shape, since it never stats a link's target.
        const work = try std.fs.path.join(arena, &.{ root_arg, "work" });
        try makeTestDir(arena, work);
        const env_path = try std.fs.path.join(arena, &.{ work, ".env" });
        const env_z = try arena.dupeSentinel(u8, env_path, 0);
        if (linux.errno(linux.symlink(secret_z.ptr, env_z.ptr)) != .SUCCESS) return 3;

        enterOrEndUnmeasured(.{ .new_net = true, .mount = true });
        const build_result = namespace.buildRoot(arena, root_arg, &.{
            .{ .bind = .{ .source = work, .target = "/work", .read_only = false } },
            .{ .deny = .{ .target = "/work/.env" } },
        }, false, namespace.default_deny_notice, null);

        // Still reachable by that name, since `buildRoot` never pivots.
        var read_buffer: [namespace.default_deny_notice.len]u8 = undefined;
        var read_content: []const u8 = &.{};
        const read_fd = linux.open(secret_z.ptr, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(read_fd) == .SUCCESS) {
            const handle: i32 = @intCast(read_fd);
            const read_rc = linux.read(handle, &read_buffer, read_buffer.len);
            _ = linux.close(handle);
            if (linux.errno(read_rc) == .SUCCESS) read_content = read_buffer[0..read_rc];
        }
        const escaped = std.mem.eql(u8, read_content, namespace.default_deny_notice);

        // Exit 1 is the fault: the bind landed outside.
        if (escaped) return 1;
        if (build_result) |_| return 5 else |err| return if (err == error.DenyTargetIsSymlink) 0 else 5;
    }
    if (std.mem.eql(u8, args[1], "bind-source-symlink")) {
        // `ln -s <host path> palisade.zon` is this bind source.
        const secret_content = "palisade host secret via a symlinked bind source\n";
        const secret_path = try std.fs.path.join(arena, &.{ id_arg, "secret" });
        try writeTestFile(arena, secret_path, secret_content);
        const secret_z = try arena.dupeSentinel(u8, secret_path, 0);

        const link_path = try std.fs.path.join(arena, &.{ root_arg, "link-palisade-zon" });
        const link_z = try arena.dupeSentinel(u8, link_path, 0);
        if (linux.errno(linux.symlink(secret_z.ptr, link_z.ptr)) != .SUCCESS) return 3;

        enterOrEndUnmeasured(.{ .new_net = true, .mount = true });
        const build_result = namespace.buildRoot(arena, root_arg, &.{
            .{ .bind = .{ .source = link_path, .target = "/work/palisade.zon", .read_only = true } },
        }, false, namespace.default_deny_notice, null);

        // Still reachable by that absolute name, since `buildRoot` never pivots.
        const target_path = try std.fs.path.join(arena, &.{ root_arg, "work/palisade.zon" });
        const target_z = try arena.dupeSentinel(u8, target_path, 0);
        var read_buffer: [secret_content.len]u8 = undefined;
        var read_content: []const u8 = &.{};
        const read_fd = linux.open(target_z.ptr, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(read_fd) == .SUCCESS) {
            const handle: i32 = @intCast(read_fd);
            const read_rc = linux.read(handle, &read_buffer, read_buffer.len);
            _ = linux.close(handle);
            if (linux.errno(read_rc) == .SUCCESS) read_content = read_buffer[0..read_rc];
        }
        const escaped = std.mem.eql(u8, read_content, secret_content);

        // Exit 1 is the fault: the bind landed on the host secret.
        if (escaped) return 1;
        if (build_result) |_| return 5 else |err| return if (err == error.BindSourceIsSymlink) 0 else 5;
    }
    if (std.mem.eql(u8, args[1], "deny-intermediate-symlink")) {
        const work = try std.fs.path.join(arena, &.{ root_arg, "work" });
        try makeTestDir(arena, work);

        // `deny.zig`'s own `check` is a string check and cannot see that `link` is a link.
        const link_path = try std.fs.path.join(arena, &.{ work, "link" });
        const link_z = try arena.dupeSentinel(u8, link_path, 0);
        const outside_z = try arena.dupeSentinel(u8, id_arg, 0);
        if (linux.errno(linux.symlink(outside_z.ptr, link_z.ptr)) != .SUCCESS) return 3;

        enterOrEndUnmeasured(.{ .new_net = true, .mount = true });
        const build_result = namespace.buildRoot(arena, root_arg, &.{
            .{ .bind = .{ .source = work, .target = "/work", .read_only = false } },
            .{ .deny = .{ .target = "/work/link/creds/token" } },
        }, false, namespace.default_deny_notice, null);

        // Still reachable by that name, since `buildRoot` never pivots.
        const outside_token_path = try std.fs.path.join(arena, &.{ id_arg, "creds/token" });
        const outside_token_z = try arena.dupeSentinel(u8, outside_token_path, 0);
        var read_buffer: [namespace.default_deny_notice.len]u8 = undefined;
        var read_content: []const u8 = &.{};
        const read_fd = linux.open(outside_token_z.ptr, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(read_fd) == .SUCCESS) {
            const handle: i32 = @intCast(read_fd);
            const read_rc = linux.read(handle, &read_buffer, read_buffer.len);
            _ = linux.close(handle);
            if (linux.errno(read_rc) == .SUCCESS) read_content = read_buffer[0..read_rc];
        }
        const escaped = read_content.len > 0;

        // Exit 1 is the fault: a file was made outside the sandbox root.
        if (escaped) return 1;
        if (build_result) |_| return 5 else |err| return if (err == error.DenyTargetIsSymlink) 0 else 5;
    }

    // Every operation below runs with the filter and enters no namespace.
    if (std.mem.eql(u8, args[1], "ptrace")) {
        const rc = linux.syscall4(.ptrace, 0, 0, 0, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "umount-protected")) {
        // The path need not be a real mount point, since the filter kills the call first.
        const rc = linux.umount2("/work/palisade.zon", linux.MNT.DETACH);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "open-tree-attr-protected")) {
        // open_tree_attr is open_tree and mount_setattr in one call. Without OPEN_TREE_CLONE it acts on the live mount.
        const MountAttr = extern struct {
            attr_set: u64 = 0,
            attr_clr: u64 = 0,
            propagation: u64 = 0,
            userns_fd: u64 = 0,
        };
        const mount_attr_rdonly: u64 = 0x00000001;
        var attr = MountAttr{ .attr_clr = mount_attr_rdonly };
        const path: [*:0]const u8 = "/work/palisade.zon";
        const rc = linux.syscall5(
            .open_tree_attr,
            @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
            @intFromPtr(path),
            0,
            @intFromPtr(&attr),
            @sizeOf(MountAttr),
        );
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "userfaultfd")) {
        const rc = linux.syscall1(.userfaultfd, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "add-key")) {
        const key_type = "user";
        const description = "palisade-probe-add-key";
        const payload = "palisade-probe-payload";
        const key_spec_session_keyring: usize = @bitCast(@as(isize, -3));
        const rc = linux.syscall5(
            .add_key,
            @intFromPtr(key_type.ptr),
            @intFromPtr(description.ptr),
            @intFromPtr(payload.ptr),
            payload.len,
            key_spec_session_keyring,
        );
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "io-uring-setup")) {
        var params: linux.io_uring_params = std.mem.zeroes(linux.io_uring_params);
        const rc = linux.io_uring_setup(1, &params);
        return ringRefusal(rc);
    }
    if (std.mem.eql(u8, args[1], "io-uring-enter")) {
        // This probe holds no ring, so a handed over ring would stay usable if the filter did not refuse first.
        const rc = linux.syscall6(.io_uring_enter, @bitCast(@as(isize, -1)), 1, 0, 0, 0, 0);
        return ringRefusal(rc);
    }
    if (std.mem.eql(u8, args[1], "io-uring-register")) {
        const rc = linux.syscall4(.io_uring_register, @bitCast(@as(isize, -1)), 0, 0, 0);
        return ringRefusal(rc);
    }
    if (std.mem.eql(u8, args[1], "io-uring-then-work")) {
        var params: linux.io_uring_params = std.mem.zeroes(linux.io_uring_params);
        const rc = linux.io_uring_setup(1, &params);
        if (linux.errno(rc) != .PERM) return 4;
        if (linux.getpid() <= 0) return 4;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "getpid")) {
        _ = linux.getpid();
        return 0;
    }

    if (std.mem.eql(u8, args[1], "landlock-write-outside") or
        std.mem.eql(u8, args[1], "landlock-write-inside"))
    {
        const inside = enterLandlockWriteTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };

        const parent = if (std.mem.eql(u8, args[1], "landlock-write-inside"))
            inside
        else
            outsideDir(arena, root_arg) catch |err| {
                std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
                return 3;
            };
        const target = std.fmt.allocPrint(arena, "{s}/file", .{parent}) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        const target_z = arena.dupeSentinel(u8, target, 0) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };

        const fd = linux.open(target_z, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
        if (linux.errno(fd) != .SUCCESS) return 1;
        _ = linux.close(@intCast(fd));
        return 0;
    }
    if (std.mem.eql(u8, args[1], "landlock-truncate-outside") or
        std.mem.eql(u8, args[1], "landlock-truncate-inside"))
    {
        const paths = enterLandlockTruncateTestRoot(arena, root_arg) catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };

        const target = if (std.mem.eql(u8, args[1], "landlock-truncate-inside"))
            paths.inside_file
        else
            paths.outside_file;

        const rc = linux.syscall2(.truncate, @intFromPtr(target.ptr), 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "spawn-ptrace")) {
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-ptrace" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-vsock")) {
        // `.network = .none` on purpose: the domain check kills the call first.
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-vsock" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-setns-proc1")) {
        // /proc is mounted read only, so the target is really reachable.
        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, namespace.Mount, &.{
            base.mounts,
            &.{.{ .proc = .{} }},
        });
        const rules = try std.mem.concat(arena, sandbox.Rule, &.{
            base.rules,
            &.{.{ .path = "/proc", .access = landlock.AccessFs.read_only }},
        });
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-setns-proc1" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-proc-self-mem-write-landlock")) {
        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, namespace.Mount, &.{
            base.mounts,
            &.{.{ .proc = .{} }},
        });
        const rules = try std.mem.concat(arena, sandbox.Rule, &.{
            base.rules,
            &.{.{ .path = "/proc", .access = landlock.AccessFs.read_only }},
        });
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-proc-self-mem-write-landlock" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-proc-self-mem-write-mount")) {
        // /proc granted write under Landlock, so only the mount flag is left.
        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, namespace.Mount, &.{
            base.mounts,
            &.{.{ .proc = .{} }},
        });
        const rules = try std.mem.concat(arena, sandbox.Rule, &.{
            base.rules,
            &.{.{
                .path = "/proc",
                .access = .{ .execute = true, .write_file = true, .read_file = true, .read_dir = true },
            }},
        });
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-proc-self-mem-write-mount" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-cgroup-remount")) {
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-cgroup-remount" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-memfd-exec")) {
        // /work is granted every right except execute, for the control.
        const base = try baseEscapeConfig(arena);
        const work = try std.fs.path.join(arena, &.{ root_arg, "work" });
        try makeTestDir(arena, work);
        const mounts = try std.mem.concat(arena, namespace.Mount, &.{
            base.mounts,
            &.{.{ .bind = .{ .source = work, .target = "/work", .read_only = false } }},
        });
        const rules = try std.mem.concat(arena, sandbox.Rule, &.{
            base.rules,
            &.{.{
                .path = "/work",
                .access = .{ .write_file = true, .read_file = true, .read_dir = true, .make_reg = true },
            }},
        });
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-memfd-exec" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-handle-escape")) {
        const base = try baseEscapeConfig(arena);
        const work = try std.fs.path.join(arena, &.{ root_arg, "work" });
        try makeTestDir(arena, work);
        const mounts = try std.mem.concat(arena, namespace.Mount, &.{
            base.mounts,
            &.{.{ .bind = .{ .source = work, .target = "/work", .read_only = false } }},
        });
        const rules = try std.mem.concat(arena, sandbox.Rule, &.{
            base.rules,
            &.{.{
                .path = "/work",
                .access = .{ .write_file = true, .read_file = true, .read_dir = true, .make_reg = true },
            }},
        });
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-handle-escape" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.startsWith(u8, args[1], "spawn-fork-bomb") or
        std.mem.startsWith(u8, args[1], "spawn-mem-bomb") or
        std.mem.startsWith(u8, args[1], "spawn-fd-bomb"))
    {
        // Each operation has an `-unbounded` twin under `Limits.none` that `escape.zig` compares.
        const unbounded = std.mem.endsWith(u8, args[1], "-unbounded");
        // With `mapped_memory_bytes` off, only `memory.max` can stop the program, and it sends a bare SIGKILL.
        const cgroup_only = std.mem.endsWith(u8, args[1], "-cgroup");
        const base = try baseEscapeConfig(arena);

        const which: enum { fork, memory, files } = if (std.mem.startsWith(u8, args[1], "spawn-fork-bomb"))
            .fork
        else if (std.mem.startsWith(u8, args[1], "spawn-mem-bomb"))
            .memory
        else
            .files;

        const limits: sandbox.Limits = if (unbounded)
            sandbox.Limits.none
        else switch (which) {
            .fork => .{ .processes = fork_bomb_limit },
            // Both fields, since a machine with no cgroup v2 has no ceiling.
            .memory => .{
                .memory_bytes = mem_bomb_limit,
                .mapped_memory_bytes = if (cgroup_only) null else mem_bomb_limit,
            },
            .files => .{ .open_files = fd_bomb_limit },
        };

        const target = switch (which) {
            .fork => "spawned-fork-bomb",
            .memory => "spawned-mem-bomb",
            .files => "spawned-fd-bomb",
        };
        const cap = switch (which) {
            .fork => fork_bomb_cap,
            .memory => mem_bomb_cap,
            .files => fd_bomb_cap,
        };

        var report: sandbox.LimitsReport = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .limits = limits,
        }, &.{ "/probe", target }, .{ .reports = .{ .limits = &report } });

        // A machine with no cgroup v2 tree is one this project supports, so say so before reading the outcome.
        if (cgroup_only and !report.cgroup.applied()) {
            return @backingInt(LimitOutcome.no_cgroup);
        }

        const named = report.killed_by != null or report.events.fork_refusals > 0;
        return limitOutcome(term, cap, named);
    }
    if (std.mem.startsWith(u8, args[1], "spawn-disk-")) {
        // `RLIMIT_FSIZE` bounds one file, but ten thousand one byte files still fill a filesystem.
        const unbounded = std.mem.endsWith(u8, args[1], "-unbounded");
        const many_files = std.mem.startsWith(u8, args[1], "spawn-disk-files");
        const config = try diskEscapeConfig(arena);

        const limits: sandbox.Limits = if (unbounded)
            sandbox.Limits.none
        else if (many_files)
            .{ .scratch_bytes = disk_file_limit }
        else
            .{ .file_size_bytes = disk_one_file_limit, .scratch_bytes = disk_one_scratch_limit };

        const target = if (many_files) "spawned-disk-file-bomb" else "spawned-disk-one-bomb";
        const cap = if (many_files) disk_file_cap else disk_one_cap;

        var report: sandbox.LimitsReport = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = config.mounts,
            .rules = config.rules,
            .scratch = config.scratch,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .limits = limits,
        }, &.{ "/probe", target }, .{ .reports = .{ .limits = &report } });

        // Nothing in the kernel counts a full filesystem, so `killed_by` is what makes it read as a limit.
        const named = report.killed_by != null;
        return limitOutcome(term, cap, named);
    }
    if (std.mem.eql(u8, args[1], "spawn-approval-socket")) {
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-approval-socket", id_arg }, .{});

        return reportChildTerm(term);
    }

    if (std.mem.eql(u8, args[1], "spawn-landlock-escape")) {
        const unguarded = try std.fs.path.join(arena, &.{ root_arg, "unguarded" });
        try makeTestDir(arena, unguarded);
        const marker = try std.fs.path.join(arena, &.{ unguarded, "marker" });
        try writeTestFile(arena, marker, "palisade landlock escape probe content\n");

        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-landlock-read" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-network-escape")) {
        // `.network` is left off, so the default on Sandbox.Config decides.
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
        }, &.{ "/probe", "spawned-connect" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-signal-host")) {
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-signal-host", id_arg }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-shm-attach")) {
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-shm-attach", id_arg }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-report-pid")) {
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-report-pid" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-default-signal")) {
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-default-signal" }, .{});

        return switch (term) {
            .signal => |signal| if (signal == .TERM) 0 else 5,
            else => 6,
        };
    }
    if (std.mem.eql(u8, args[1], "spawn-keeper-reaps")) {
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-keeper-reaps" }, .{});
        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-supervisor-audit")) {
        // The install is best effort, so this reads the record back rather than trust it.
        const base = try baseEscapeConfig(arena);
        var audit: sandbox.SupervisorAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-report-pid" }, .{ .reports = .{ .supervisor_audit = &audit } });

        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }

        const watched = [_]sandbox.LayerName{ .capabilities, .landlock, .seccomp };
        for (watched, 0..) |layer, index| {
            const base_status: u8 = @intCast(10 + index * 4);
            const counts = audit.counts(layer);
            if (counts.unreported != 0) return base_status;
            if (counts.unconfined != 0) return base_status + 1;
            if (counts.confined != 1) return base_status + 2;
            if (counts.first_fault != null) return base_status + 3;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-syscall-audit-daemon")) {
        // The program leaves a process behind that still carries the filter, so this call comes back at once.
        const base = try baseEscapeConfig(arena);
        var audit: sandbox.SyscallAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .seccomp_options = .{ .traps = seccomp.TrapSet.full },
            .path_audit = true,
        }, &.{ "/probe", "spawned-leave-daemon" }, .{ .reports = .{ .syscall_audit = &audit } });

        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }
        if (audit.paths.readers_absent != 0 or audit.paths.readers_unreported != 0) return 5;
        const openat_slot = @backingInt(seccomp.TrapCall.openat);
        if (audit.counts().calls[openat_slot] != 0) return 6;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-path-audit") or
        std.mem.eql(u8, args[1], "spawn-path-audit-off"))
    {
        const auditing = std.mem.eql(u8, args[1], "spawn-path-audit");
        const base = try baseEscapeConfig(arena);
        var audit: sandbox.SyscallAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .seccomp_options = .{ .traps = seccomp.TrapSet.full },
            .path_audit = auditing,
        }, &.{ "/probe", "spawned-name-paths" }, .{ .reports = .{ .syscall_audit = &audit } });

        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }

        const slot = @backingInt(seccomp.TrapCall.openat);
        const seen = &audit.paths.seen;
        if (!auditing) {
            if (seen.kept != 0) return 5;
            if (seen.granted[slot] != 0 or seen.ungranted[slot] != 0) return 6;
            if (audit.paths.readers_unreported != 0 or audit.paths.readers_absent != 0) return 7;
            if (audit.counts().calls[slot] == 0) return 8;
            return 0;
        }

        if (audit.paths.readers_absent != 0) return 9;
        if (audit.paths.readers_unreported != 0) return 10;

        if (seen.granted[slot] == 0) return 11;

        var named_the_secret = false;
        var named_a_grant = false;
        var kept: u32 = 0;
        while (kept < seen.kept) : (kept += 1) {
            const name = seen.name(kept);
            if (std.mem.eql(u8, name, named_ungranted)) named_the_secret = true;
            if (std.mem.startsWith(u8, name, named_granted)) named_a_grant = true;
        }
        if (!named_the_secret) return 12;
        if (named_a_grant) return 13;
        if (seen.ungranted[slot] != 3) return 14;
        if (seen.kept != 1) return 15;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-path-audit-dynamic")) {
        const base = try baseEscapeConfig(arena);
        const mounts = try arena.alloc(namespace.Mount, base.mounts.len + 1);
        @memcpy(mounts[0..base.mounts.len], base.mounts);
        mounts[base.mounts.len] = .{ .bind = .{
            .source = try absolutePath(arena, dynamic_probe_path),
            .target = "/dynamic",
            .read_only = true,
        } };
        const rules = try arena.alloc(sandbox.Rule, base.rules.len + 1);
        @memcpy(rules[0..base.rules.len], base.rules);
        // A file and not a directory, so `read_only_file`: the kernel refuses a directory right over a file.
        rules[base.rules.len] = .{
            .path = "/dynamic",
            .access = landlock.AccessFs.read_only_file,
        };

        var audit: sandbox.SyscallAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .seccomp_options = .{ .traps = seccomp.TrapSet.full },
            .path_audit = true,
        }, &.{"/dynamic"}, .{ .reports = .{ .syscall_audit = &audit } });

        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }

        const slot = @backingInt(seccomp.TrapCall.openat);
        const seen = &audit.paths.seen;
        if (audit.paths.readers_absent != 0) return 5;
        if (audit.paths.readers_unreported != 0) return 6;

        if (seen.granted[slot] == 0) return 7;

        if (seen.kept != 1) return 8;
        if (!std.mem.eql(u8, seen.name(0), named_ungranted)) return 9;
        if (seen.name_call[0] != slot) return 10;
        if (seen.ungranted_unnamed[slot] != 0) return 11;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-path-audit-killed")) {
        const base = try baseEscapeConfig(arena);
        var audit: sandbox.SyscallAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .seccomp_options = .{ .traps = seccomp.TrapSet.full },
            .path_audit = true,
        }, &.{ "/probe", "spawned-kill-the-reader" }, .{ .reports = .{ .syscall_audit = &audit } });

        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }
        // The reader reached its loop, so it was killed and never absent.
        if (audit.paths.readers_absent != 0) return 5;
        // A reader that was killed wrote no report, and the session counts it.
        if (audit.paths.readers_unreported != 1) return 6;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-path-audit-stopped")) {
        const on_alarm = linux.Sigaction{
            .handler = .{ .handler = endOnAlarm },
            .mask = linux.sigemptyset(),
            .flags = 0,
        };
        if (linux.errno(linux.sigaction(.ALRM, &on_alarm, null)) != .SUCCESS) return 10;
        const alarm: linux.itimerspec = .{
            .it_interval = .{ .sec = 0, .nsec = 0 },
            .it_value = .{ .sec = 3, .nsec = 0 },
        };
        if (linux.errno(linux.setitimer(@backingInt(linux.ITIMER.REAL), &alarm, null)) != .SUCCESS)
            return 11;

        const base = try baseEscapeConfig(arena);
        var audit: sandbox.SyscallAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .seccomp_options = .{ .traps = seccomp.TrapSet.full },
            .path_audit = true,
        }, &.{ "/probe", "spawned-stop-the-reader" }, .{ .reports = .{ .syscall_audit = &audit } });

        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }
        if (audit.paths.readers_absent != 0) return 5;
        if (audit.paths.readers_unreported != 0) return 6;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-syscall-audit") or
        std.mem.eql(u8, args[1], "spawn-syscall-audit-off"))
    {
        const watching = std.mem.eql(u8, args[1], "spawn-syscall-audit");
        const base = try baseEscapeConfig(arena);
        var audit: sandbox.SyscallAudit = .{};
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .seccomp_options = .{
                .traps = if (watching)
                    seccomp.TrapSet.full
                else
                    seccomp.TrapSet.empty,
            },
        }, &.{ "/probe", "spawned-count-opens" }, .{ .reports = .{ .syscall_audit = &audit } });

        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }

        const counts = audit.counts();
        const opens = counts.calls[@backingInt(seccomp.TrapCall.openat)];
        const execs = counts.calls[@backingInt(seccomp.TrapCall.execve)];
        const dirs = counts.calls[@backingInt(seccomp.TrapCall.getdents64)];
        const connects = counts.calls[@backingInt(seccomp.TrapCall.connect)];

        if (!watching) {
            if (counts.observed != 0 or counts.unobserved != 0) return 5;
            if (opens != 0 or execs != 0 or dirs != 0 or connects != 0) return 6;
            return 0;
        }

        if (counts.unobserved != 0) return 7;
        if (counts.observed != 1) return 8;
        if (execs != 1) return 9;
        if (opens < opens_in_probe) return 10;
        if (dirs != 0 or connects != 0) return 11;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-open-fds")) {
        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, namespace.Mount, &.{
            base.mounts,
            &.{.{ .proc = .{} }},
        });
        const rules = try std.mem.concat(arena, sandbox.Rule, &.{
            base.rules,
            &.{.{ .path = "/proc", .access = landlock.AccessFs.read_only }},
        });

        var channel_state: u8 = 0;
        const one_channel = [_]sandbox.Channel{.{
            .ptr = &channel_state,
            .serve = .{ .call = serveNothing, .max_requests = 1 },
            .hands_host_descriptor = false,
        }};
        const channels: []const sandbox.Channel = if (std.mem.eql(u8, id_arg, "1")) &one_channel else &.{};
        const network: sandbox.Network = if (channels.len == 0) .none else .{ .isolated = .{
            .device_name = "sbx0",
            .address4 = .{ 10, 0, 0, 1 },
            .prefix4 = 24,
            .address6 = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
            .prefix6 = 64,
        } };

        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = network,
            .channels = channels,
        }, &.{ "/probe", "spawned-open-fds" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-open-fd-set")) {
        const base = try baseEscapeConfig(arena);
        const held = try HarnessDescriptors.open(arena, root_arg);
        if (held.openCount() < required_harness_descriptors) {
            std.debug.print("spawn-open-fd-set: this machine gave too few descriptors to check\n", .{});
            return 5;
        }

        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
        }, &.{ "/probe", "spawned-open-fd-set" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-caps-drop")) {
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-caps-drop" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-owned-directory")) {
        const host_dir = try std.fs.path.join(arena, &.{ root_arg, ".host-etc" });
        try makeTestDir(arena, host_dir);
        const host_file = try std.fs.path.join(arena, &.{ host_dir, "hosts" });
        try writeTestFile(arena, host_file, owned_host_contents);

        const base = try baseEscapeConfig(arena);
        const mounts = try arena.alloc(namespace.Mount, base.mounts.len + 1);
        @memcpy(mounts[0..base.mounts.len], base.mounts);
        mounts[base.mounts.len] = .{ .bind = .{ .source = host_dir, .target = "/etc", .read_only = true } };
        const rules = try arena.alloc(sandbox.Rule, base.rules.len + 1);
        @memcpy(rules[0..base.rules.len], base.rules);
        rules[base.rules.len] = .{ .path = "/etc", .access = landlock.AccessFs.read_only };

        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .substitutions = &.{
                .{ .text = .{ .target = "/etc/hosts", .contents = owned_replacement } },
                .{ .text = .{ .target = "/etc/resolv.conf", .contents = owned_replacement } },
            },
            .owned_directories = &.{.{ .target = "/etc", .remove = &.{"/etc/hosts"} }},
        }, &.{ "/probe", "spawned-owned-directory" }, .{});
        switch (term) {
            .exited => |code| if (code != 0) return 4,
            else => return 4,
        }

        const host_path = try arena.dupeSentinel(u8, host_file, 0);
        const fd_rc = linux.open(host_path.ptr, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(fd_rc) != .SUCCESS) return 5;
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);
        var buffer: [128]u8 = undefined;
        const kept = readToEnd(fd, &buffer);
        if (!std.mem.eql(u8, kept, owned_host_contents)) return 6;
        const extra = try std.fs.path.joinZ(arena, &.{ host_dir, "resolv.conf" });
        return if (linux.errno(linux.open(extra.ptr, .{ .ACCMODE = .RDONLY }, 0)) == .NOENT) 0 else 7;
    }
    if (std.mem.eql(u8, args[1], "spawn-stdin-devnull")) {
        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-stdin-devnull" }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-stdin-pipe")) {
        var pipe_fds: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&pipe_fds, .{})) != .SUCCESS) return 5;
        const read_fd = pipe_fds[0];
        const write_fd = pipe_fds[1];

        const written = linux.write(write_fd, stdin_pipe_token, stdin_pipe_token.len);
        if (linux.errno(written) != .SUCCESS or written != stdin_pipe_token.len) return 5;
        _ = linux.close(write_fd);

        const escape_rc = linux.open("/", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        if (linux.errno(escape_rc) != .SUCCESS) return 5;
        const escape_fd: i32 = @intCast(escape_rc);
        const escape_text = try std.fmt.allocPrint(arena, "{d}", .{escape_fd});

        const base = try baseEscapeConfig(arena);
        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
            .stdin_fd = read_fd,
        }, &.{ "/probe", "spawned-stdin-pipe", escape_text }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-setup-fault-named-stderr")) {
        var pipe_fds: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&pipe_fds, .{})) != .SUCCESS) return 5;
        const read_fd = pipe_fds[0];
        const write_fd = pipe_fds[1];

        const absent = try absentRoot(arena, root_arg);
        if (sandbox.spawn(arena, .{
            .root = absent,
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
            .stderr_fd = write_fd,
        }, &.{"/probe"}, .{})) |_| {
            return 5;
        } else |err| {
            endIfNothingMeasured(err);
            if (err != error.MountTreeFailed) return 5;
        }

        _ = linux.close(write_fd);
        var buffer: [512]u8 = undefined;
        const arrived = readToEnd(read_fd, &buffer);
        _ = linux.close(read_fd);

        const wrote = linux.write(linux.STDOUT_FILENO, arrived.ptr, arrived.len);
        if (linux.errno(wrote) != .SUCCESS or wrote != arrived.len) return 5;
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-setup-fault-closed-stderr")) {
        // Writing the reason answers `EPIPE` and raises `SIGPIPE`, which the middle process must meet.
        var pipe_fds: [2]i32 = undefined;
        if (linux.errno(linux.pipe2(&pipe_fds, .{})) != .SUCCESS) return 5;
        _ = linux.close(pipe_fds[0]);
        const write_fd = pipe_fds[1];

        if (sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
            .scratch = &.{
                .{ .target = "/run/palisade/one" },
                .{ .target = "/run/palisade/two" },
                .{ .target = "/run/palisade/three" },
                .{ .target = "/run/palisade/four" },
                .{ .target = "/run/palisade/five" },
            },
            .stderr_fd = write_fd,
        }, &.{"/probe"}, .{})) |_| {
            return 5;
        } else |err| {
            endIfNothingMeasured(err);
            if (err != error.ScratchMountFailed) return 5;
        }
        _ = linux.close(write_fd);
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-setup-fault-default-stderr")) {
        const absent = try absentRoot(arena, root_arg);
        if (sandbox.spawn(arena, .{
            .root = absent,
            .mounts = &.{},
            .rules = &.{},
            .cwd = "/",
            .env = &.{},
        }, &.{"/probe"}, .{})) |_| {
            return 5;
        } else |err| {
            endIfNothingMeasured(err);
            if (err != error.MountTreeFailed) return 5;
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "spawn-proc-mask") or std.mem.eql(u8, args[1], "spawn-proc-live")) {
        // Made by `buildRoot` inside spawn's own child. A procfs mounted anywhere else would be the host's.
        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, namespace.Mount, &.{
            base.mounts,
            &.{.{ .proc = .{} }},
        });
        const rules = try std.mem.concat(arena, sandbox.Rule, &.{
            base.rules,
            &.{.{ .path = "/proc", .access = landlock.AccessFs.read_only }},
        });

        const inner: []const u8 = if (std.mem.eql(u8, args[1], "spawn-proc-mask"))
            "spawned-proc-mask"
        else
            "spawned-proc-live";

        const term = try sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", inner }, .{});

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-forge-exit")) {
        const work = try std.fs.path.join(arena, &.{ root_arg, "work" });
        try makeTestDir(arena, work);

        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, namespace.Mount, &.{
            base.mounts,
            &.{.{ .bind = .{ .source = work, .target = "/work", .read_only = false } }},
        });
        const rules = try std.mem.concat(arena, sandbox.Rule, &.{
            base.rules,
            &.{.{ .path = "/work", .access = landlock.AccessFs.read_write }},
        });

        const term = sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-forge-exit", id_arg }, .{}) catch |err| {
            endIfNothingMeasured(err);
            std.debug.print("spawn-forge-exit: spawn reported a setup failure: {s}\n", .{@errorName(err)});
            return 3;
        };

        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "spawn-signal-middle") or
        std.mem.eql(u8, args[1], "spawn-signal-middle-forked") or
        std.mem.eql(u8, args[1], "spawn-signal-middle-setsid"))
    {
        const inner: []const u8 = if (std.mem.eql(u8, args[1], "spawn-signal-middle-forked"))
            "spawned-fork-loop-write"
        else if (std.mem.eql(u8, args[1], "spawn-signal-middle-setsid"))
            "spawned-setsid-fork-loop-write"
        else
            "spawned-loop-write";

        const work = try std.fs.path.join(arena, &.{ root_arg, "work" });
        try makeTestDir(arena, work);

        const base = try baseEscapeConfig(arena);
        const mounts = try std.mem.concat(arena, namespace.Mount, &.{
            base.mounts,
            &.{.{ .bind = .{ .source = work, .target = "/work", .read_only = false } }},
        });
        const rules = try std.mem.concat(arena, sandbox.Rule, &.{
            base.rules,
            &.{.{ .path = "/work", .access = landlock.AccessFs.read_write }},
        });

        const SpawnCtx = struct {
            allocator: std.mem.Allocator,
            root: []const u8,
            mounts: []const namespace.Mount,
            rules: []const sandbox.Rule,
            inner: []const u8,
            middle: sandbox.Handle = .{},
            term: std.process.Child.Term = undefined,
            spawn_err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.term = sandbox.spawn(self.allocator, .{
                    .root = self.root,
                    .mounts = self.mounts,
                    .rules = self.rules,
                    .cwd = "/",
                    .env = &.{},
                    .network = .none,
                }, &.{ "/probe", self.inner }, .{ .handle = &self.middle }) catch |err| {
                    self.spawn_err = err;
                    return;
                };
            }
        };
        var ctx = SpawnCtx{
            .allocator = arena,
            .root = root_arg,
            .mounts = mounts,
            .rules = rules,
            .inner = inner,
        };

        const thread = std.Thread.spawn(.{}, SpawnCtx.run, .{&ctx}) catch |err| {
            std.debug.print("{s}: could not start the spawn thread: {s}\n", .{ args[1], @errorName(err) });
            return 3;
        };

        var waited_ns: u64 = 0;
        while (ctx.middle.pid() == null and waited_ns < 2_000_000_000) : (waited_ns += 1_000_000) {
            _ = linux.nanosleep(&.{ .sec = 0, .nsec = 1_000_000 }, null);
        }
        if (ctx.middle.pid() == null) {
            thread.join();
            if (ctx.spawn_err) |err| endIfNothingMeasured(err);
            std.debug.print("{s}: never learned the middle process\n", .{args[1]});
            return 3;
        }

        var pid_line_buf: [16]u8 = undefined;
        const pid_line = std.fmt.bufPrint(&pid_line_buf, "{d}\n", .{ctx.middle.pid().?}) catch unreachable;
        _ = linux.write(linux.STDOUT_FILENO, pid_line.ptr, pid_line.len);

        thread.join();
        ctx.middle.close();
        if (ctx.spawn_err) |err| {
            endIfNothingMeasured(err);
            std.debug.print("{s}: spawn reported a setup failure: {s}\n", .{ args[1], @errorName(err) });
            return 3;
        }

        return reportChildTerm(ctx.term);
    }

    if (std.mem.eql(u8, args[1], "spawn-signal-group")) {
        if (linux.errno(linux.setpgid(0, 0)) != .SUCCESS) {
            std.debug.print("spawn-signal-group: setpgid failed\n", .{});
            return 3;
        }
        catchSignal(.USR1);

        // The handler has to be live before spawn forks.
        if (linux.errno(linux.kill(linux.getpid(), .USR1)) != .SUCCESS) {
            std.debug.print("spawn-signal-group: could not raise USR1\n", .{});
            return 3;
        }
        if (!caller_signal_seen.load(.monotonic)) {
            std.debug.print("spawn-signal-group: the handler never ran on a raise here\n", .{});
            return 3;
        }
        caller_signal_seen.store(false, .monotonic);

        const base = try baseEscapeConfig(arena);
        _ = sandbox.spawn(arena, .{
            .root = root_arg,
            .mounts = base.mounts,
            .rules = base.rules,
            .cwd = "/",
            .env = &.{},
            .network = .none,
        }, &.{ "/probe", "spawned-signal-group" }, .{}) catch |err| {
            endIfNothingMeasured(err);
            std.debug.print("spawn-signal-group: spawn reported a setup failure: {s}\n", .{@errorName(err)});
            return 3;
        };

        return if (caller_signal_seen.load(.monotonic)) 1 else 0;
    }

    if (std.mem.eql(u8, args[1], "spawn-group-press")) {
        if (linux.errno(linux.setpgid(0, 0)) != .SUCCESS) {
            std.debug.print("spawn-group-press: setpgid failed\n", .{});
            return 3;
        }
        catchSignal(.USR1);

        const config = try workEscapeConfig(arena, root_arg);
        var ctx = ThreadedSpawn{
            .allocator = arena,
            .root = root_arg,
            .mounts = config.mounts,
            .rules = config.rules,
            .argv = &.{ "/probe", "spawned-group-press" },
        };
        const thread = std.Thread.spawn(.{}, ThreadedSpawn.run, .{&ctx}) catch |err| {
            std.debug.print("spawn-group-press: could not start the spawn thread: {s}\n", .{@errorName(err)});
            return 3;
        };
        // Registered before the join, so it runs after it.
        defer ctx.closeHandle();
        defer thread.join();

        const started_path = try std.fmt.allocPrintSentinel(arena, "{s}/work/started", .{root_arg}, 0);
        const go_path = try std.fmt.allocPrintSentinel(arena, "{s}/work/go", .{root_arg}, 0);
        if (!waitForPath(started_path)) {
            ctx.endIfSandboxRefused();
            std.debug.print("spawn-group-press: the sandboxed program never started\n", .{});
            ctx.killCall();
            return 3;
        }

        if (linux.errno(linux.kill(0, .USR1)) != .SUCCESS) {
            std.debug.print("spawn-group-press: the press itself failed\n", .{});
            ctx.killCall();
            return 3;
        }

        writeTestFile(arena, go_path, "go\n") catch |err| {
            std.debug.print("spawn-group-press: could not write go: {s}\n", .{@errorName(err)});
            ctx.killCall();
            return 3;
        };

        if (!ctx.waitForDone()) {
            ctx.endIfSandboxRefused();
            std.debug.print("spawn-group-press: the call never finished\n", .{});
            ctx.killCall();
            return 3;
        }
        if (ctx.spawn_err) |err| {
            endIfNothingMeasured(err);
            std.debug.print("spawn-group-press: spawn reported a setup failure: {s}\n", .{@errorName(err)});
            return 3;
        }
        if (!caller_signal_seen.load(.monotonic)) {
            std.debug.print("spawn-group-press: the press reached nothing at all\n", .{});
            return 3;
        }

        switch (ctx.term) {
            .exited => |code| return if (code <= 1) code else 5,
            else => {
                std.debug.print("spawn-group-press: the call died: {any}\n", .{ctx.term});
                return 5;
            },
        }
    }

    if (std.mem.eql(u8, args[1], "spawn-signal-middle-handled")) {
        catchSignal(.TERM);

        if (linux.errno(linux.kill(linux.getpid(), .TERM)) != .SUCCESS) {
            std.debug.print("spawn-signal-middle-handled: could not raise TERM\n", .{});
            return 3;
        }
        if (!caller_signal_seen.load(.monotonic)) {
            std.debug.print("spawn-signal-middle-handled: the handler never ran on a raise here\n", .{});
            return 3;
        }
        caller_signal_seen.store(false, .monotonic);

        const config = try workEscapeConfig(arena, root_arg);
        var ctx = ThreadedSpawn{
            .allocator = arena,
            .root = root_arg,
            .mounts = config.mounts,
            .rules = config.rules,
            .argv = &.{ "/probe", "spawned-loop-write" },
        };
        const thread = std.Thread.spawn(.{}, ThreadedSpawn.run, .{&ctx}) catch |err| {
            std.debug.print("spawn-signal-middle-handled: could not start the spawn thread: {s}\n", .{@errorName(err)});
            return 3;
        };
        // Registered before the join, so it runs after it.
        defer ctx.closeHandle();
        defer thread.join();

        if (ctx.waitForMiddlePid() == 0) {
            ctx.endIfSandboxRefused();
            std.debug.print("spawn-signal-middle-handled: never learned the middle process\n", .{});
            return 3;
        }

        const heartbeat_path = try std.fmt.allocPrintSentinel(arena, "{s}/work/heartbeat.txt", .{root_arg}, 0);
        if (!waitForPath(heartbeat_path)) {
            ctx.endIfSandboxRefused();
            std.debug.print("spawn-signal-middle-handled: the sandboxed program never started\n", .{});
            ctx.killCall();
            return 3;
        }

        ctx.middle.signal(@backingInt(linux.SIG.TERM)) catch |err| {
            std.debug.print("spawn-signal-middle-handled: could not signal the middle process: {s}\n", .{@errorName(err)});
            ctx.killCall();
            return 3;
        };

        if (!ctx.waitForDone()) {
            ctx.endIfSandboxRefused();
            std.debug.print("spawn-signal-middle-handled: the call outlived its own cancellation\n", .{});
            ctx.killCall();
            return 1;
        }
        if (ctx.spawn_err) |err| {
            endIfNothingMeasured(err);
            std.debug.print("spawn-signal-middle-handled: spawn reported a setup failure: {s}\n", .{@errorName(err)});
            return 3;
        }

        switch (ctx.term) {
            .signal => |sig| {
                if (sig != .TERM) {
                    std.debug.print("spawn-signal-middle-handled: died from {s}\n", .{@tagName(sig)});
                    return 5;
                }
                return 0;
            },
            else => {
                std.debug.print("spawn-signal-middle-handled: ended as {any}\n", .{ctx.term});
                return 5;
            },
        }
    }

    // personality(READ_IMPLIES_EXEC) adds PROT_EXEC to every later mapping, after seccomp has read the prot argument.
    if (std.mem.eql(u8, args[1], "personality-rwx")) {
        const read_implies_exec: usize = 0x0400000;
        const rc = linux.syscall1(.personality, read_implies_exec);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    // 0xffffffff only reads the current personality and changes nothing.
    if (std.mem.eql(u8, args[1], "personality-read")) {
        const read_current: usize = 0xffffffff;
        const rc = linux.syscall1(.personality, read_current);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    const prot_read: u32 = 0x1;
    const prot_write: u32 = 0x2;
    const prot_exec: u32 = 0x4;
    const map_private_anon: u32 = 0x02 | 0x20;

    if (std.mem.eql(u8, args[1], "mmap-wx")) {
        const prot: linux.PROT = @bitCast(prot_write | prot_exec);
        const flags: linux.MAP = @bitCast(map_private_anon);
        const rc = linux.mmap(null, 4096, prot, flags, -1, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "ptrace-relaxed")) {
        // The relaxed setting turns off one rule, so this must still die.
        const rc = linux.syscall4(.ptrace, 0, 0, 0, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "io-uring-setup-relaxed")) {
        var params: linux.io_uring_params = std.mem.zeroes(linux.io_uring_params);
        const rc = linux.io_uring_setup(1, &params);
        return ringRefusal(rc);
    }
    if (std.mem.eql(u8, args[1], "mmap-wx-relaxed")) {
        const prot: linux.PROT = @bitCast(prot_write | prot_exec);
        const flags: linux.MAP = @bitCast(map_private_anon);
        const rc = linux.mmap(null, 4096, prot, flags, -1, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "mmap-then-exec")) {
        const rw: linux.PROT = @bitCast(prot_read | prot_write);
        const flags: linux.MAP = @bitCast(map_private_anon);
        const rc = linux.mmap(null, 4096, rw, flags, -1, 0);
        if (linux.errno(rc) != .SUCCESS) return 1;
        const addr: [*]u8 = @ptrFromInt(rc);
        addr[0] = 0xc0; // Write to the page while it is not executable.
        const rx: linux.PROT = @bitCast(prot_read | prot_exec);
        const rc2 = linux.mprotect(addr, 4096, rx);
        return if (linux.errno(rc2) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "pkey-wx")) {
        const rw: linux.PROT = @bitCast(prot_read | prot_write);
        const flags: linux.MAP = @bitCast(map_private_anon);
        const rc = linux.mmap(null, 4096, rw, flags, -1, 0);
        if (linux.errno(rc) != .SUCCESS) return 1;
        const rc2 = linux.syscall4(.pkey_mprotect, rc, 4096, prot_write | prot_exec, 0);
        return if (linux.errno(rc2) == .SUCCESS) 0 else 1;
    }

    // shmat has no prot argument, so SHM_EXEC in shmflg is the flag the filter must refuse.
    if (std.mem.eql(u8, args[1], "shmat-exec")) {
        const shmid = createShmSegment() catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        defer removeShmSegment(shmid);
        const shm_exec: usize = 0x8000;
        const rc = linux.syscall3(.shmat, shmid, 0, shm_exec);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }
    if (std.mem.eql(u8, args[1], "shmat-plain")) {
        const shmid = createShmSegment() catch |err| {
            std.debug.print("sandbox setup failed: {s}\n", .{@errorName(err)});
            return 3;
        };
        defer removeShmSegment(shmid);
        const rc = linux.syscall3(.shmat, shmid, 0, 0);
        return if (linux.errno(rc) == .SUCCESS) 0 else 1;
    }

    if (std.mem.eql(u8, args[1], "channel-echo")) {
        const channels = [_]sandbox.Channel{.{
            .ptr = &channel_dummy,
            .serve = .{ .call = echoServe, .max_requests = 4 },
            .hands_host_descriptor = false,
        }};
        const term = try spawnChannelProgram(arena, root_arg, &channels, &.{}, &.{ "/probe", "spawned-channel-echo" });
        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "channel-reaim")) {
        const channels = [_]sandbox.Channel{.{
            .ptr = &channel_dummy,
            .serve = .{ .call = serveNothing, .max_requests = 1 },
            .hands_host_descriptor = true,
        }};
        const term = try spawnChannelProgram(arena, root_arg, &channels, &.{}, &.{ "/probe", "spawned-channel-reaim" });
        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "connect-out-hands") or std.mem.eql(u8, args[1], "connect-out-keeps")) {
        const hands = std.mem.eql(u8, args[1], "connect-out-hands");
        const channels = [_]sandbox.Channel{.{
            .ptr = &channel_dummy,
            .serve = .{ .call = serveNothing, .max_requests = 1 },
            .hands_host_descriptor = hands,
        }};
        const term = try spawnChannelProgram(arena, root_arg, &channels, &.{}, &.{ "/probe", "spawned-connect-loopback" });
        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "channel-helper-keep")) {
        var kept: [2]i32 = undefined;
        var unkept: [2]i32 = undefined;
        if (linux.errno(linux.pipe(&kept)) != .SUCCESS) return 5;
        if (linux.errno(linux.pipe(&unkept)) != .SUCCESS) return 5;
        kept_pipe_fd = kept[1];
        unkept_pipe_fd = unkept[1];
        const keep = [_]i32{kept[1]};
        const helpers = [_]sandbox.Helper{.{
            .ptr = &channel_dummy,
            .run = keepFdRun,
            .allowed = &.{ .write, .exit_group },
            .keep_fds = &keep,
        }};
        const term = spawnChannelProgram(arena, root_arg, &.{}, &helpers, &.{ "/probe", "spawned-exit-zero" }) catch |err| {
            writeStdout(@errorName(err));
            writeStdout("\n");
            return 0;
        };
        _ = linux.close(kept[1]);
        _ = linux.close(unkept[1]);
        var buffer: [16]u8 = undefined;
        const got = linux.read(kept[0], &buffer, buffer.len);
        if (linux.errno(got) == .SUCCESS) writeStdout(buffer[0..got]);
        writeStdout("|");
        const leaked = linux.read(unkept[0], &buffer, buffer.len);
        if (linux.errno(leaked) == .SUCCESS) writeStdout(buffer[0..leaked]);
        return reportChildTerm(term);
    }
    if (std.mem.eql(u8, args[1], "channel-helper") or std.mem.eql(u8, args[1], "channel-helper-exit-only") or
        std.mem.eql(u8, args[1], "channel-helper-outside-call"))
    {
        const allowed: []const linux.SYS = if (std.mem.eql(u8, args[1], "channel-helper"))
            &.{ .sendto, .exit_group, .exit }
        else
            &.{.exit_group};
        const run: *const fn (*anyopaque, ?i32) u8 = if (std.mem.eql(u8, args[1], "channel-helper"))
            writeOkRun
        else if (std.mem.eql(u8, args[1], "channel-helper-exit-only"))
            exitOnlyRun
        else
            outsideCallRun;
        const program: []const []const u8 = if (std.mem.eql(u8, args[1], "channel-helper"))
            &.{ "/probe", "spawned-channel-wait" }
        else
            &.{ "/probe", "spawned-exit-zero" };
        var recorder: Recorder = .{};
        const channels = [_]sandbox.Channel{.{
            .ptr = &recorder,
            .serve = .{ .call = recordServe, .max_requests = 1 },
            .hands_host_descriptor = false,
        }};
        const helpers = [_]sandbox.Helper{.{
            .ptr = &channel_dummy,
            .run = run,
            .allowed = allowed,
            .channel = 0,
        }};
        const term = spawnChannelProgram(arena, root_arg, &channels, &helpers, program) catch |err| {
            writeStdout(@errorName(err));
            writeStdout("\n");
            return 0;
        };
        writeStdout(recorder.bytes[0..recorder.len]);
        return reportChildTerm(term);
    }

    std.debug.print("unknown operation: {s}\n", .{args[1]});
    return 2;
}
