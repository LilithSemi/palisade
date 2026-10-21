//! Tests that try to escape the sandbox. Each one must fail to escape.

const std = @import("std");
const linux = std.os.linux;

// The default test runner panics on an argv it does not know, so build.zig embeds the probe path.
const probe_path = @import("probe_path").probe_path;

const palisade = @import("palisade");

/// Skip when the probe answered that this machine would not give it a sandbox.
fn skipIfNothingMeasured(term: std.process.Child.Term) !void {
    const code = switch (term) {
        .exited => |c| c,
        else => return,
    };
    if (code == palisade.linux.namespace.nothing_measured_exit_status) return error.SkipZigTest;
}

/// Reads the absolute path of an open directory descriptor through /proc/self/fd,
/// since std.testing.tmpDir gives a relative one.
fn absoluteDirPath(buffer: []u8, dir_fd: linux.fd_t) ![:0]u8 {
    var link_buffer: [64]u8 = undefined;
    const link = std.fmt.bufPrintSentinel(&link_buffer, "/proc/self/fd/{d}", .{dir_fd}, 0) catch unreachable;
    const rc = linux.readlink(link, buffer.ptr, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.ReadlinkFailed;
    const len: usize = @intCast(rc);
    buffer[len] = 0;
    return buffer[0..len :0];
}

const ScratchRoot = struct {
    tmp: std.testing.TmpDir,
    path_buffer: [std.fs.max_path_bytes]u8 = undefined,
    path_len: usize = 0,

    fn path(self: *const ScratchRoot) []const u8 {
        return self.path_buffer[0..self.path_len];
    }

    /// Call only after the probe exits: its mounts keep the directory busy until then.
    fn cleanup(self: *ScratchRoot) void {
        self.tmp.cleanup();
    }
};

fn scratchRoot() !ScratchRoot {
    var result = ScratchRoot{ .tmp = std.testing.tmpDir(.{}) };
    const resolved = try absoluteDirPath(&result.path_buffer, result.tmp.dir.handle);
    result.path_len = resolved.len;
    return result;
}

fn runProbe(op: []const u8) !std.process.Child.Term {
    return runProbeArgv(&.{ probe_path, op });
}

fn runProbeWithRoot(op: []const u8, root: []const u8) !std.process.Child.Term {
    return runProbeArgv(&.{ probe_path, op, root });
}

/// Same as `runProbeWithRoot`, and it keeps standard error. Never `inherit`: a host
/// that refuses the namespaces writes on this binary's own standard error, which fails the build.
fn runProbeSayingWithRoot(op: []const u8, root: []const u8) !CaptureResult {
    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ probe_path, op, root },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    });

    var result = CaptureResult{ .term = undefined };
    result.err_len = readPipeToEnd(child.stderr.?.handle, &result.err_buffer);
    result.term = try child.wait(std.testing.io);
    try skipIfNothingMeasured(result.term);
    return result;
}

/// Assert the probe ended cleanly, as a failing comparison and not a printed line.
fn expectProbeSucceeded(result: CaptureResult) !void {
    switch (result.term) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    try std.testing.expectEqualStrings("", result.err());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
}

fn runProbeArgv(argv: []const []const u8) !std.process.Child.Term {
    var child = try std.process.spawn(std.testing.io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(std.testing.io);
    try skipIfNothingMeasured(term);
    return term;
}

fn fileSize(path: [:0]const u8) ?u64 {
    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, path, 0, .{ .SIZE = true }, &stx);
    if (linux.errno(rc) != .SUCCESS) return null;
    return stx.size;
}

const ReportPidResult = struct {
    term: std.process.Child.Term,
    buffer: [16]u8 = undefined,
    len: usize = 0,

    fn text(self: *const ReportPidResult) []const u8 {
        return self.buffer[0..self.len];
    }
};

fn runReportPid(root: []const u8) !ReportPidResult {
    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ probe_path, "spawn-report-pid", root },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });

    var result = ReportPidResult{ .term = undefined };
    const handle = child.stdout.?.handle;
    while (result.len < result.buffer.len) {
        const rc = linux.read(handle, result.buffer[result.len..].ptr, result.buffer.len - result.len);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        result.len += rc;
    }

    result.term = try child.wait(std.testing.io);
    try skipIfNothingMeasured(result.term);
    return result;
}

const CaptureResult = struct {
    term: std.process.Child.Term,
    out_buffer: [512]u8 = undefined,
    out_len: usize = 0,
    err_buffer: [512]u8 = undefined,
    err_len: usize = 0,

    fn out(self: *const CaptureResult) []const u8 {
        return self.out_buffer[0..self.out_len];
    }

    fn err(self: *const CaptureResult) []const u8 {
        return self.err_buffer[0..self.err_len];
    }
};

fn readPipeToEnd(handle: linux.fd_t, buffer: []u8) usize {
    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(handle, buffer[filled..].ptr, buffer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        filled += rc;
    }
    return filled;
}

fn runProbeCapturing(argv: []const []const u8) !CaptureResult {
    var child = try std.process.spawn(std.testing.io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });

    var result = CaptureResult{ .term = undefined };
    result.out_len = readPipeToEnd(child.stdout.?.handle, &result.out_buffer);
    result.err_len = readPipeToEnd(child.stderr.?.handle, &result.err_buffer);
    result.term = try child.wait(std.testing.io);
    try skipIfNothingMeasured(result.term);
    return result;
}

/// Like `runProbeCapturing`, but a status of 63 is returned to the caller and not skipped.
fn runProbeCapturingRaw(argv: []const []const u8) !CaptureResult {
    var child = try std.process.spawn(std.testing.io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });

    var result = CaptureResult{ .term = undefined };
    result.out_len = readPipeToEnd(child.stdout.?.handle, &result.out_buffer);
    result.err_len = readPipeToEnd(child.stderr.?.handle, &result.err_buffer);
    result.term = try child.wait(std.testing.io);
    return result;
}

const mount_setup_fault_line = "sandbox: the mount call failed: NOENT\n";

/// Signal 0 sends nothing. The kernel only checks that the process exists.
fn processIsAlive(pid: linux.pid_t) bool {
    const rc = linux.kill(pid, @fromBackingInt(@intCast(0)));
    return linux.errno(rc) == .SUCCESS;
}

const shm_secret = "SHARED-MEMORY-SECRET-FROM-HOST";

/// Builds a System V shared memory segment on the host, outside every namespace.
fn createHostShmSegment() !usize {
    const ipc_private: usize = 0;
    const ipc_creat: usize = 0o1000;
    const size: usize = 4096;
    const shmid = linux.syscall3(.shmget, ipc_private, size, ipc_creat | 0o600);
    if (linux.errno(shmid) != .SUCCESS) return error.ShmgetFailed;

    const addr_rc = linux.syscall3(.shmat, shmid, 0, 0);
    if (linux.errno(addr_rc) != .SUCCESS) return error.ShmatFailed;
    const addr: [*]u8 = @ptrFromInt(addr_rc);
    @memcpy(addr[0..shm_secret.len], shm_secret);
    _ = linux.syscall1(.shmdt, addr_rc);

    return shmid;
}

fn removeHostShmSegment(shmid: usize) void {
    const ipc_rmid: usize = 0;
    _ = linux.syscall3(.shmctl, shmid, ipc_rmid, 0);
}

const session_key_payload = "palisade-escape-session-key-payload";

/// Plants a key in this process's own session keyring, the one a child inherits across fork.
fn createHostSessionKey(description: [:0]const u8) !i32 {
    const key_type = "user";
    // KEY_SPEC_SESSION_KEYRING, a negative special value and not a real serial number.
    const key_spec_session_keyring: usize = @bitCast(@as(isize, -3));
    const rc = linux.syscall5(
        .add_key,
        @intFromPtr(key_type.ptr),
        @intFromPtr(description.ptr),
        @intFromPtr(session_key_payload.ptr),
        session_key_payload.len,
        key_spec_session_keyring,
    );
    if (linux.errno(rc) != .SUCCESS) return error.AddKeyFailed;
    return @intCast(rc);
}

fn removeHostSessionKey(key_id: i32) void {
    const keyctl_invalidate: usize = 21;
    _ = linux.syscall2(.keyctl, keyctl_invalidate, @as(usize, @bitCast(@as(isize, key_id))));
}

test "a filtered process that calls ptrace dies with SIGSYS" {
    const term = try runProbe("ptrace");
    try std.testing.expectEqual(std.process.Child.Term{ .signal = linux.SIG.SYS }, term);
}

test "a filtered process that calls umount2 dies with SIGSYS" {
    const term = try runProbe("umount-protected");
    try std.testing.expectEqual(std.process.Child.Term{ .signal = linux.SIG.SYS }, term);
}

test "a filtered process that calls open_tree_attr dies with SIGSYS" {
    // open_tree_attr can undo the read only bind mount that protects palisade.zon.
    const term = try runProbe("open-tree-attr-protected");
    try std.testing.expectEqual(std.process.Child.Term{ .signal = linux.SIG.SYS }, term);
}

test "a filtered process that calls userfaultfd dies with SIGSYS" {
    const term = try runProbe("userfaultfd");
    switch (term) {
        .signal => |sig| try std.testing.expectEqual(linux.SIG.SYS, sig),
        else => return error.TestUnexpectedResult,
    }
}

test "a filtered process that calls add_key dies with SIGSYS" {
    // A key added inside still lands in whichever session keyring this process has.
    const term = try runProbe("add-key");
    try std.testing.expectEqual(std.process.Child.Term{ .signal = linux.SIG.SYS }, term);
}

test "a filtered process that calls io_uring_setup is refused with EPERM and lives" {
    // EPERM and not a kill, because libuv probes for a ring before a Node program runs its own line.
    const term = try runProbe("io-uring-setup");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a filtered process that calls io_uring_enter is refused with EPERM and lives" {
    const term = try runProbe("io-uring-enter");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a filtered process that calls io_uring_register is refused with EPERM and lives" {
    const term = try runProbe("io-uring-register");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a program that meets the io_uring refusal carries on and exits cleanly" {
    // Each test above ends at the refusal. This one does work after it.
    const term = try runProbe("io-uring-then-work");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "the calls that are meant to kill still kill, so the io_uring change did not leak" {
    // A change that moved the whole blocked list to EPERM passes every test above and fails here.
    for ([_][]const u8{
        "ptrace",
        "umount-protected",
        "open-tree-attr-protected",
        "add-key",
    }) |op| {
        const term = try runProbe(op);
        try std.testing.expectEqual(std.process.Child.Term{ .signal = linux.SIG.SYS }, term);
    }
}

test "the filter is not a deny all, an ordinary call still works" {
    const term = try runProbe("getpid");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "mmap refuses a request for write and execute together" {
    // This pins only that mmap refuses PROT_WRITE | PROT_EXEC.
    const term = try runProbe("mmap-wx");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a project that asked for a just in time compiler gets the page, and keeps every other rule" {
    // The one policy setting that widens. By default `mmap-wx` gets EPERM.
    const relaxed = try runProbe("mmap-wx-relaxed");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, relaxed);

    const killed = try runProbe("ptrace-relaxed");
    try std.testing.expectEqual(std.process.Child.Term{ .signal = linux.SIG.SYS }, killed);
    const ring = try runProbe("io-uring-setup-relaxed");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, ring);
}

test "a two step change from read write to read execute succeeds" {
    const term = try runProbe("mmap-then-exec");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "pkey_mprotect refuses a request for write and execute together" {
    const term = try runProbe("pkey-wx");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "personality(READ_IMPLIES_EXEC) cannot be used to pass around the rule" {
    const term = try runProbe("personality-rwx");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "reading the current personality still works" {
    const term = try runProbe("personality-read");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "shmat with SHM_EXEC is refused" {
    // shmat has no prot argument, so only a rule on its own shmflg can refuse this.
    const term = try runProbe("shmat-exec");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "shmat with no SHM_EXEC still works" {
    const term = try runProbe("shmat-plain");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a process in a network namespace cannot connect to a remote host" {
    const term = try runProbe("netns-connect");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a network namespace still permits a unix socket" {
    const term = try runProbe("netns-loopback");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a process in the mount tree cannot read the home directory, with ENOENT" {
    // Exit 1 means the open failed with ENOENT exactly. See probe.zig's exit table.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("read-home", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a read only bind mount refuses a write, with EROFS" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("write-readonly", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a submount under a read only target also refuses a write, with EROFS" {
    // mount_setattr with AT_RECURSIVE is what makes a read only mark reach a submount.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("write-readonly-submount", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a file with a bind mount over it cannot be deleted, with EBUSY" {
    // Landlock cannot do this: a delete needs write permission on the parent.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("delete-mounted-file", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a file bound onto a target that did not exist yet carries the source's content" {
    // A file bind onto a target created as a directory fails with ENOTDIR.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("file-bind-content", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a deny_read entry that is a symlink cannot bind the notice onto its target" {
    // `outside` is never named in any mount the probe builds.
    var outside = try scratchRoot();
    defer outside.cleanup();

    var scratch = try scratchRoot();
    defer scratch.cleanup();

    const term = try runProbeArgv(&.{ probe_path, "deny-symlink-outside", scratch.path(), outside.path() });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a bind mount whose source is a symlink does not follow it onto the host" {
    // A repository can hold `ln -s <host path> palisade.zon`. `outside` must stay empty.
    var outside = try scratchRoot();
    defer outside.cleanup();

    var scratch = try scratchRoot();
    defer scratch.cleanup();

    const term = try runProbeArgv(&.{ probe_path, "bind-source-symlink", scratch.path(), outside.path() });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a deny_read entry with a symlinked intermediate component cannot write outside the sandbox root" {
    // `deny.zig` accepts `link/creds/token` and never sees that `link` is a symlink.
    var outside = try scratchRoot();
    defer outside.cleanup();

    var scratch = try scratchRoot();
    defer scratch.cleanup();

    const term = try runProbeArgv(&.{ probe_path, "deny-intermediate-symlink", scratch.path(), outside.path() });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a tool call inside the sandbox cannot reach the session's approval socket" {
    // This test connects to the socket first, or it would prove only that a missing path cannot be reached.
    var scratch = try scratchRoot();
    defer scratch.cleanup();

    // A directory of its own beside the root, so the socket is not carried in by the recursive bind of `root`.
    var session = try scratchRoot();
    defer session.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket_path = try std.fmt.bufPrint(&path_buffer, "{s}/s", .{session.path()});

    const address = try std.Io.net.UnixAddress.init(socket_path);
    var server = try address.listen(std.testing.io, .{ .kernel_backlog = 2 });
    defer server.deinit(std.testing.io);

    // The host reaches it, so everything below is about the sandbox.
    {
        const reached = try address.connect(std.testing.io);
        reached.close(std.testing.io);
    }

    const term = try runProbeArgv(&.{ probe_path, "spawn-approval-socket", scratch.path(), socket_path });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a Landlock rule refuses a write outside the directory it granted" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("landlock-write-outside", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a Landlock rule permits a write inside the directory it granted" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("landlock-write-inside", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a Landlock rule refuses a truncate outside the directory it granted" {
    // Landlock handles truncate as a right of its own, separate from open for write.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("landlock-truncate-outside", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a Landlock rule permits a truncate inside the directory it granted" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("landlock-truncate-inside", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "spawn applies every layer, and a spawned process cannot call ptrace" {
    // The probe does no setup of its own, so only spawn's applyLayers can kill it.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-ptrace", scratch.path());
    switch (term) {
        .signal => |sig| try std.testing.expectEqual(linux.SIG.SYS, sig),
        else => return error.TestUnexpectedResult,
    }
}

test "spawn applies every layer, and a spawned process cannot read outside its rules" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-landlock-escape", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "spawn applies every layer, and a spawned process cannot connect to a remote host" {
    // The Config leaves `.network` unset, so this also pins the default of `none`.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-network-escape", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "spawn gives the sandboxed process /dev/null on standard input, never a terminal" {
    // No terminal, so a password prompt fails fast. It also closes ioctl(0, TIOCSTI),
    // which no Landlock rule covers on a descriptor open before the sandbox existed.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-stdin-devnull", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "the sandboxed process holds no capability in its own user namespace, and none can come back across an exec" {
    // `execve` clears the effective, permitted and inheritable sets, so the bounding set is the one record worth reading.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-caps-drop", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a named stdin descriptor reaches the program as a pipe, and widens nothing else" {
    // Descriptor 0 must reach end of file, or a helper never learns it is finished.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-stdin-pipe", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "the only descriptors that cross execve are the standard streams" {
    // An already open descriptor bypasses Landlock and the mount namespace together:
    // path resolution happens once, when the descriptor is opened, and never again.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-open-fd-set", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "the supervisor says whether it could filter itself, and the answer leaves the process" {
    // The filter install is best effort: ending the supervisor would end the program.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-supervisor-audit", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "the supervisor counts what the sandboxed program asked the kernel for" {
    // `execve` is observed, so the kernel holds the program until the supervisor answers.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-syscall-audit", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a sandbox that was asked to watch nothing counts nothing and still runs" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-syscall-audit-off", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "the supervisor names the paths the sandboxed program asked for that nothing granted" {
    // The answer is CONTINUE, so a recorded path is what the program said and not proof.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-path-audit", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a dynamically linked program's loader opens are counted, not named" {
    // A dynamic loader opens dozens of files, so the record splits on what was granted.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-path-audit-dynamic", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a sandbox that was asked to record no path records none and still counts" {
    // The control. The counts still arrive, so the path audit changes only itself.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-path-audit-off", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a program that kills the reader watching it breaks its own opens" {
    // A filter whose listener nobody holds answers every held call ENOSYS.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-path-audit-killed", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a program that stops its reader cannot hold teardown" {
    // The outer probe has a three second alarm, so a missing reap fails and never hangs.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-path-audit-stopped", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a program that leaves a process behind does not hold the tool call open" {
    // Every process the program forks carries the filter, so the descriptor outlives it.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-syscall-audit-daemon", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a setup failure is written to the descriptor the caller named, and not to descriptor 2" {
    // Either check alone would pass with the fault still there.
    var scratch = try scratchRoot();
    defer scratch.cleanup();

    const result = try runProbeCapturing(
        &.{ probe_path, "spawn-setup-fault-named-stderr", scratch.path() },
    );
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try std.testing.expectEqualStrings(mount_setup_fault_line, result.out());
    try std.testing.expectEqualStrings("", result.err());
}

test "a setup failure with no descriptor named still lands on descriptor 2" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();

    const result = try runProbeCapturing(
        &.{ probe_path, "spawn-setup-fault-default-stderr", scratch.path() },
    );
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try std.testing.expectEqualStrings(mount_setup_fault_line, result.err());
    try std.testing.expectEqualStrings("", result.out());
}

test "a setup failure still reaches spawn when the descriptor the caller named cannot be written" {
    // End of file with no data on the setup pipe is how a successful `execve` reports itself.
    var scratch = try scratchRoot();
    defer scratch.cleanup();

    const term = try runProbeWithRoot("spawn-setup-fault-closed-stderr", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "the global files of /proc that describe the host read empty" {
    // A reduced surface and not a boundary: the next kernel adds a file nobody masked.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-proc-mask", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "the mask leaves /proc/self/exe working, and leaves the rest of /proc real" {
    // A mask that reached /proc/self brings back "unable to find zig self exe path".
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-proc-live", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a process cannot signal a process outside the sandbox, and does not kill it" {
    // A signal to an unused pid returns ESRCH anyway, so this builds a real victim first.
    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    const victim_pid: linux.pid_t = @intCast(fork_rc);

    if (victim_pid == 0) {
        while (true) _ = linux.pause();
    }

    defer {
        // Runs even if an assertion below fails, so no victim outlives the test.
        _ = linux.kill(victim_pid, .KILL);
        var reap_status: i32 = undefined;
        _ = linux.waitpid(victim_pid, &reap_status, 0);
    }

    var pid_buffer: [16]u8 = undefined;
    const pid_arg = try std.fmt.bufPrint(&pid_buffer, "{d}", .{victim_pid});

    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeArgv(&.{ probe_path, "spawn-signal-host", scratch.path(), pid_arg });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);

    try std.testing.expect(processIsAlive(victim_pid));
}

test "a process cannot attach to a System V shared memory segment made outside the sandbox" {
    // The segment has to be real, and outside every namespace, or a refusal proves nothing.
    const shmid = try createHostShmSegment();
    // Removed even if an assertion fails, so no segment is left behind.
    defer removeHostShmSegment(shmid);

    var shmid_buffer: [16]u8 = undefined;
    const shmid_arg = try std.fmt.bufPrint(&shmid_buffer, "{d}", .{shmid});

    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeArgv(&.{ probe_path, "spawn-shm-attach", scratch.path(), shmid_arg });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "the session keyring join gives the sandbox a keyring the host cannot see into" {
    // CLONE_NEWUSER covers the user keyring but not the session keyring.
    var desc_buffer: [64]u8 = undefined;
    const description = try std.fmt.bufPrintSentinel(&desc_buffer, "palisade-escape-session-key-{d}", .{linux.getpid()}, 0);

    const key_id = try createHostSessionKey(description);
    // Removed even if an assertion fails, so no key is left behind.
    defer removeHostSessionKey(key_id);

    const term = try runProbeArgv(&.{ probe_path, "session-keyring-fresh", description });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "the sandboxed process sees a fresh process id space, not the host's" {
    // The keeper is process 1 and the caller's program is process 2.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const result = try runReportPid(scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const text = std.mem.trimEnd(u8, result.text(), "\n");
    const pid = try std.fmt.parseInt(u32, text, 10);
    try std.testing.expectEqual(@as(u32, 2), pid);
}

test "the sandboxed program has ordinary default signal behavior" {
    // B is process 2, so the kernel applies the default SIGTERM action.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-default-signal", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "the pid namespace keeper reaps an adopted zombie" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-keeper-reaps", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

const forged_exit_statuses = [_]u8{ 0, 1, 63, 111, 127, 255 };
const root_marker_bytes = "the root keeps this file\n";

fn writeRootMarker(path: [:0]const u8) !void {
    const fd_rc = linux.open(path.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (linux.errno(fd_rc) != .SUCCESS) return error.OpenFailed;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);
    const rc = linux.write(fd, root_marker_bytes, root_marker_bytes.len);
    if (linux.errno(rc) != .SUCCESS or rc != root_marker_bytes.len) return error.WriteFailed;
}

fn rootMarkerIntact(path: [:0]const u8) bool {
    const fd_rc = linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);
    var buffer: [root_marker_bytes.len + 1]u8 = undefined;
    const filled = readPipeToEnd(fd, &buffer);
    return std.mem.eql(u8, buffer[0..filled], root_marker_bytes);
}

// The probe writes "forged" to stdout before it returns the status, so a status
// of 63 from a child that never ran cannot pass as the child's own answer.
test "a forged exit status is relayed as the child's own, and the root keeps its files" {
    for (forged_exit_statuses) |status| {
        var scratch = try scratchRoot();
        defer scratch.cleanup();

        var marker_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const marker = try std.fmt.bufPrintSentinel(&marker_buffer, "{s}/marker.txt", .{scratch.path()}, 0);
        try writeRootMarker(marker);

        var id_buffer: [4]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buffer, "{d}", .{status});
        const result = try runProbeCapturingRaw(&.{ probe_path, "spawn-forge-exit", scratch.path(), id });
        // A host that cannot nest answers 63 and writes nothing, which is the one case that skips.
        if (result.term == .exited and result.term.exited == 63 and result.out().len == 0) return error.SkipZigTest;

        try std.testing.expectEqualStrings("forged\n", result.out());
        try std.testing.expectEqual(std.process.Child.Term{ .exited = status }, result.term);
        try std.testing.expect(rootMarkerIntact(marker));
    }
}

/// Runs the probe's descriptor listing with `channel_count` channels and checks the set it reports.
fn expectOpenFds(root: []const u8, channel_count: []const u8, expected: []const i32) !void {
    const result = try runProbeCapturing(&.{ probe_path, "spawn-open-fds", root, channel_count });
    try expectProbeSucceeded(result);

    var seen: [16]i32 = undefined;
    var count: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, result.out(), '\n');
    while (lines.next()) |line| {
        if (count == seen.len) return error.TooManyDescriptors;
        seen[count] = try std.fmt.parseInt(i32, line, 10);
        count += 1;
    }
    std.mem.sort(i32, seen[0..count], {}, std.sort.asc(i32));
    try std.testing.expectEqualSlices(i32, expected, seen[0..count]);
}

test "a sandboxed process with no channel holds descriptors 0 to 2 and no other" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    try expectOpenFds(scratch.path(), "0", &.{ 0, 1, 2 });
}

test "a sandboxed process with one channel holds 0 to 2 and that channel's descriptor, and no other" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    try expectOpenFds(scratch.path(), "1", &.{ 0, 1, 2, palisade.Sandbox.channelFd(0) });
}

test "signalling the process spawn forked also ends the sandboxed program" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ probe_path, "spawn-signal-middle", scratch.path() },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });

    var pid_line_buf: [16]u8 = undefined;
    var pid_line_len: usize = 0;
    const handle = child.stdout.?.handle;
    while (pid_line_len < pid_line_buf.len) {
        var byte: [1]u8 = undefined;
        const rc = linux.read(handle, &byte, 1);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        if (byte[0] == '\n') break;
        pid_line_buf[pid_line_len] = byte[0];
        pid_line_len += 1;
    }
    // No pid line at all is an answer too: a machine with no sandbox prints nothing.
    if (pid_line_len == 0) {
        try skipIfNothingMeasured(try child.wait(std.testing.io));
        return error.TestUnexpectedResult;
    }
    const middle_pid = try std.fmt.parseInt(linux.pid_t, pid_line_buf[0..pid_line_len], 10);

    var heartbeat_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const heartbeat_path = try std.fmt.bufPrintSentinel(&heartbeat_path_buf, "{s}/work/heartbeat.txt", .{scratch.path()}, 0);

    var waited_ns: u64 = 0;
    var size_before_signal: u64 = 0;
    while (waited_ns < 2_000_000_000) : (waited_ns += 20_000_000) {
        _ = linux.nanosleep(&.{ .sec = 0, .nsec = 20_000_000 }, null);
        if (fileSize(heartbeat_path)) |size| {
            if (size > 0) {
                size_before_signal = size;
                break;
            }
        }
    }
    // `spawn` publishes the pid before it builds any layer, so no growth is an answer too.
    if (size_before_signal == 0) {
        try skipIfNothingMeasured(try child.wait(std.testing.io));
    }
    try std.testing.expect(size_before_signal > 0);

    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.kill(middle_pid, .TERM)));

    const term = try child.wait(std.testing.io);
    try std.testing.expectEqual(std.process.Child.Term{ .signal = linux.SIG.TERM }, term);

    _ = linux.nanosleep(&.{ .sec = 0, .nsec = 200_000_000 }, null);
    const size_after_wait_one = fileSize(heartbeat_path) orelse size_before_signal;
    _ = linux.nanosleep(&.{ .sec = 0, .nsec = 200_000_000 }, null);
    const size_after_wait_two = fileSize(heartbeat_path) orelse size_after_wait_one;
    try std.testing.expectEqual(size_after_wait_one, size_after_wait_two);
}

test "a cancelled call takes the processes it started with it, not only the one that was signalled" {
    // `PR_SET_PDEATHSIG` and `cgroup.kill` carry the rest. This pins the outcome and not either mechanism.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ probe_path, "spawn-signal-middle-forked", scratch.path() },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });

    var pid_line_buf: [16]u8 = undefined;
    var pid_line_len: usize = 0;
    const handle = child.stdout.?.handle;
    while (pid_line_len < pid_line_buf.len) {
        var byte: [1]u8 = undefined;
        const rc = linux.read(handle, &byte, 1);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        if (byte[0] == '\n') break;
        pid_line_buf[pid_line_len] = byte[0];
        pid_line_len += 1;
    }
    if (pid_line_len == 0) {
        try skipIfNothingMeasured(try child.wait(std.testing.io));
        return error.TestUnexpectedResult;
    }
    const middle_pid = try std.fmt.parseInt(linux.pid_t, pid_line_buf[0..pid_line_len], 10);

    var forked_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const forked_path = try std.fmt.bufPrintSentinel(&forked_path_buf, "{s}/work/forked.txt", .{scratch.path()}, 0);
    var heartbeat_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const heartbeat_path = try std.fmt.bufPrintSentinel(&heartbeat_path_buf, "{s}/work/heartbeat.txt", .{scratch.path()}, 0);

    var waited_ns: u64 = 0;
    var size_before_signal: u64 = 0;
    while (waited_ns < 5_000_000_000) : (waited_ns += 20_000_000) {
        _ = linux.nanosleep(&.{ .sec = 0, .nsec = 20_000_000 }, null);
        if (fileSize(heartbeat_path)) |size| {
            if (size > 0) {
                size_before_signal = size;
                break;
            }
        }
    }
    if (size_before_signal == 0) {
        try skipIfNothingMeasured(try child.wait(std.testing.io));
    }
    try std.testing.expect(size_before_signal > 0);
    try std.testing.expect((fileSize(forked_path) orelse 0) > 0);

    // A handle and never the number, as a caller of `Sandbox.spawn` holds one.
    const pidfd_rc = linux.pidfd_open(middle_pid, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(pidfd_rc));
    const middle_fd: i32 = @intCast(pidfd_rc);
    defer _ = linux.close(middle_fd);
    try std.testing.expectEqual(
        .SUCCESS,
        linux.errno(linux.pidfd_send_signal(middle_fd, .KILL, null, 0)),
    );

    const term = try child.wait(std.testing.io);
    try std.testing.expectEqual(std.process.Child.Term{ .signal = linux.SIG.KILL }, term);

    _ = linux.nanosleep(&.{ .sec = 0, .nsec = 200_000_000 }, null);
    const size_after_wait_one = fileSize(heartbeat_path) orelse size_before_signal;
    _ = linux.nanosleep(&.{ .sec = 0, .nsec = 200_000_000 }, null);
    const size_after_wait_two = fileSize(heartbeat_path) orelse size_after_wait_one;
    try std.testing.expectEqual(size_after_wait_one, size_after_wait_two);
}

test "a process cannot signal its caller's process group, which a pid namespace does not hide" {
    // kill(0, sig) names the caller's process group, which a pid namespace cannot renumber.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-signal-group", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a signal to the caller's process group leaves the running call alone, and the call finishes" {
    // Exit 0 means the press reached nothing inside the call, and the call ran to its end.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-group-press", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "a caller's own signal handler does not run in the process spawn forked, so a call can still be cancelled" {
    // The process spawn forks never execs, so it keeps the caller's own signal handlers.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-signal-middle-handled", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

const limit_stopped_legibly = 10;
const limit_stopped_quietly = 11;
const limit_not_stopped = 12;
const limit_no_cgroup = 14;

fn limitRun(op: []const u8, root: []const u8) !u8 {
    const term = try runProbeWithRoot(op, root);
    return switch (term) {
        .exited => |code| code,
        else => error.TestUnexpectedResult,
    };
}

test "a fork bomb inside the sandbox is stopped, and the same bomb with no limit is not" {
    // Nothing in the namespaces, in Landlock or in seccomp refuses a fork.
    var bounded_scratch = try scratchRoot();
    defer bounded_scratch.cleanup();
    const bounded = try limitRun("spawn-fork-bomb", bounded_scratch.path());

    var unbounded_scratch = try scratchRoot();
    defer unbounded_scratch.cleanup();
    const unbounded = try limitRun("spawn-fork-bomb-unbounded", unbounded_scratch.path());

    try std.testing.expect(bounded != unbounded);
    try std.testing.expectEqual(@as(u8, limit_not_stopped), unbounded);
    try std.testing.expect(bounded == limit_stopped_legibly or bounded == limit_stopped_quietly);
}

test "an allocation that never stops is stopped, and the same allocation with no limit is not" {
    // An untouched mapping is the case RLIMIT_AS refuses and `memory.max` permits.
    var bounded_scratch = try scratchRoot();
    defer bounded_scratch.cleanup();
    const bounded = try limitRun("spawn-mem-bomb", bounded_scratch.path());

    var unbounded_scratch = try scratchRoot();
    defer unbounded_scratch.cleanup();
    const unbounded = try limitRun("spawn-mem-bomb-unbounded", unbounded_scratch.path());

    try std.testing.expect(bounded != unbounded);
    try std.testing.expectEqual(@as(u8, limit_not_stopped), unbounded);
    try std.testing.expect(bounded == limit_stopped_legibly or bounded == limit_stopped_quietly);
}

test "descriptor exhaustion is stopped, and the same program with no limit is not" {
    // RLIMIT_NOFILE is per process, which is why the process count is bounded too.
    var bounded_scratch = try scratchRoot();
    defer bounded_scratch.cleanup();
    const bounded = try limitRun("spawn-fd-bomb", bounded_scratch.path());

    var unbounded_scratch = try scratchRoot();
    defer unbounded_scratch.cleanup();
    const unbounded = try limitRun("spawn-fd-bomb-unbounded", unbounded_scratch.path());

    try std.testing.expect(bounded != unbounded);
    try std.testing.expectEqual(@as(u8, limit_not_stopped), unbounded);
    try std.testing.expect(bounded == limit_stopped_legibly or bounded == limit_stopped_quietly);
}

test "a limit that killed the program says which limit it was, and not only that a signal arrived" {
    // `memory.max` kills with a bare SIGKILL, which a deadline cancel also looks like.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const bounded = try limitRun("spawn-mem-bomb-cgroup", scratch.path());

    if (bounded == limit_no_cgroup) {
        // No cgroup v2 tree here, so no kernel counter can name the limit.
        return error.SkipZigTest;
    }
    try std.testing.expectEqual(@as(u8, limit_stopped_legibly), bounded);
}

fn hostEntryCount(path: [:0]const u8) ?usize {
    const dir_rc = linux.open(path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(dir_rc) != .SUCCESS) return null;
    const dir_fd: linux.fd_t = @intCast(dir_rc);
    defer _ = linux.close(dir_fd);

    var count: usize = 0;
    var buffer: [4096]u8 = undefined;
    while (true) {
        const nread = linux.getdents64(dir_fd, &buffer, buffer.len);
        if (linux.errno(nread) != .SUCCESS) return null;
        if (nread == 0) return count;

        var offset: usize = 0;
        while (offset < nread) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            const name_ptr: [*:0]const u8 = @ptrCast(&buffer[offset + @offsetOf(linux.dirent64, "name")]);
            const name = std.mem.sliceTo(name_ptr, 0);
            offset += entry.reclen;
            // "." and ".." are in every directory and are not entries anybody wrote.
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            count += 1;
        }
    }
}

test "many small files are stopped, the same files with no cap are not, and neither run reaches the host disk" {
    // Every file is far under RLIMIT_FSIZE, so that limit never sees this attack.
    var bounded_scratch = try scratchRoot();
    defer bounded_scratch.cleanup();
    const bounded = try limitRun("spawn-disk-files", bounded_scratch.path());

    var unbounded_scratch = try scratchRoot();
    defer unbounded_scratch.cleanup();
    const unbounded = try limitRun("spawn-disk-files-unbounded", unbounded_scratch.path());

    try std.testing.expect(bounded != unbounded);
    try std.testing.expectEqual(@as(u8, limit_not_stopped), unbounded);
    try std.testing.expect(bounded == limit_stopped_legibly or bounded == limit_stopped_quietly);

    // The area is a tmpfs, so the directory it sat on must be empty on the real disk.
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const bounded_host = try std.fmt.bufPrintSentinel(&path_buffer, "{s}/run/palisade/scratch", .{bounded_scratch.path()}, 0);
    try std.testing.expectEqual(@as(?usize, 0), hostEntryCount(bounded_host));

    var unbounded_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const unbounded_host = try std.fmt.bufPrintSentinel(&unbounded_buffer, "{s}/run/palisade/scratch", .{unbounded_scratch.path()}, 0);
    try std.testing.expectEqual(@as(?usize, 0), hostEntryCount(unbounded_host));
}

test "one enormous file in a scratch area is still stopped, and the same file with no limit is not" {
    // A tmpfs is a filesystem this project had never put RLIMIT_FSIZE against.
    var bounded_scratch = try scratchRoot();
    defer bounded_scratch.cleanup();
    const bounded = try limitRun("spawn-disk-one", bounded_scratch.path());

    var unbounded_scratch = try scratchRoot();
    defer unbounded_scratch.cleanup();
    const unbounded = try limitRun("spawn-disk-one-unbounded", unbounded_scratch.path());

    try std.testing.expect(bounded != unbounded);
    try std.testing.expectEqual(@as(u8, limit_not_stopped), unbounded);
    try std.testing.expect(bounded == limit_stopped_legibly or bounded == limit_stopped_quietly);
}

test "a full scratch area names itself, and does not read as the machine's own disk being full" {
    // Nothing in the kernel counts a full filesystem the way `memory.events` counts a kill.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const bounded = try limitRun("spawn-disk-files", scratch.path());
    try std.testing.expectEqual(@as(u8, limit_stopped_legibly), bounded);
}

// Six red team primitives from vetto's src/redteam.rs.

test "a process that calls setsid still dies when the sandbox is torn down" {
    // setsid() succeeds. Teardown still reaches the child since pdeathsig follows the real parent.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ probe_path, "spawn-signal-middle-setsid", scratch.path() },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });

    var pid_line_buf: [16]u8 = undefined;
    var pid_line_len: usize = 0;
    const handle = child.stdout.?.handle;
    while (pid_line_len < pid_line_buf.len) {
        var byte: [1]u8 = undefined;
        const rc = linux.read(handle, &byte, 1);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        if (byte[0] == '\n') break;
        pid_line_buf[pid_line_len] = byte[0];
        pid_line_len += 1;
    }
    if (pid_line_len == 0) {
        try skipIfNothingMeasured(try child.wait(std.testing.io));
        return error.TestUnexpectedResult;
    }
    const middle_pid = try std.fmt.parseInt(linux.pid_t, pid_line_buf[0..pid_line_len], 10);

    var setsid_ok_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const setsid_ok_path = try std.fmt.bufPrintSentinel(&setsid_ok_path_buf, "{s}/work/setsid-ok", .{scratch.path()}, 0);
    var heartbeat_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const heartbeat_path = try std.fmt.bufPrintSentinel(&heartbeat_path_buf, "{s}/work/heartbeat.txt", .{scratch.path()}, 0);

    var waited_ns: u64 = 0;
    var size_before_signal: u64 = 0;
    while (waited_ns < 5_000_000_000) : (waited_ns += 20_000_000) {
        _ = linux.nanosleep(&.{ .sec = 0, .nsec = 20_000_000 }, null);
        if (fileSize(heartbeat_path)) |size| {
            if (size > 0) {
                size_before_signal = size;
                break;
            }
        }
    }
    if (size_before_signal == 0) {
        try skipIfNothingMeasured(try child.wait(std.testing.io));
    }
    try std.testing.expect(size_before_signal > 0);
    // The control: setsid really ran, so no fork failed in silence.
    try std.testing.expect((fileSize(setsid_ok_path) orelse 0) > 0);

    const pidfd_rc = linux.pidfd_open(middle_pid, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(pidfd_rc));
    const middle_fd: i32 = @intCast(pidfd_rc);
    defer _ = linux.close(middle_fd);
    try std.testing.expectEqual(
        .SUCCESS,
        linux.errno(linux.pidfd_send_signal(middle_fd, .KILL, null, 0)),
    );

    const term = try child.wait(std.testing.io);
    try std.testing.expectEqual(std.process.Child.Term{ .signal = linux.SIG.KILL }, term);

    _ = linux.nanosleep(&.{ .sec = 0, .nsec = 200_000_000 }, null);
    const size_after_wait_one = fileSize(heartbeat_path) orelse size_before_signal;
    _ = linux.nanosleep(&.{ .sec = 0, .nsec = 200_000_000 }, null);
    const size_after_wait_two = fileSize(heartbeat_path) orelse size_after_wait_one;
    try std.testing.expectEqual(size_after_wait_one, size_after_wait_two);
}

test "spawn applies every layer, and a spawned process cannot setns into /proc/1/ns/mnt" {
    // `setns` sits on `blocked_calls`, whatever fd or kind is named.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-setns-proc1", scratch.path());
    switch (term) {
        .signal => |sig| try std.testing.expectEqual(linux.SIG.SYS, sig),
        else => return error.TestUnexpectedResult,
    }
}

test "spawn applies every layer, and a spawned process cannot write /proc/self/mem, refused by the mount's own read only flag" {
    // The errno is EROFS and not EACCES: `buildProcMount` marks the whole procfs mount read only.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-proc-self-mem-write-landlock", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "spawn applies every layer, and a spawned process cannot write /proc/self/mem even granted write there, refused by the mount's own read only flag" {
    // Here Landlock grants write_file on /proc, so a refusal cannot be Landlock's doing.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-proc-self-mem-write-mount", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a network namespace with no route still confines an AF_PACKET socket, refused by ENETDOWN and not by the route table" {
    // A raw packet socket never reads a routing table. ENETDOWN is what stops the frame.
    const term = try runProbe("netns-af-packet");
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "a sandboxed process has no path to its own cgroup, so it can neither read nor raise memory.max, pids.max or memory.swap.max" {
    // The cgroup is never bound into the sandbox's mount tree, so the refusal is ENOENT.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("cgroup-surface", scratch.path());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, term);
}

test "spawn applies every layer, and a spawned process cannot mount a fresh view of the whole cgroup v2 tree" {
    // `namespace.enter` never asks for CLONE_NEWCGROUP, so a fresh mount shows every one.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-cgroup-remount", scratch.path());
    switch (term) {
        .signal => |sig| try std.testing.expectEqual(linux.SIG.SYS, sig),
        else => return error.TestUnexpectedResult,
    }
}

test "spawn applies every layer, and a spawned process cannot fexecve an anonymous memfd around the execute right Landlock refused it on disk" {
    // `memfd_create` plus `execveat` with AT_EMPTY_PATH leaves no path for a rule to match, so `seccomp.build` reads the flags instead.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-memfd-exec", scratch.path());
    switch (term) {
        .signal => |sig| try std.testing.expectEqual(linux.SIG.SYS, sig),
        else => return error.TestUnexpectedResult,
    }
}

test "spawn applies every layer, and a spawned process cannot reopen a file by handle once its path is gone" {
    // `open_by_handle_at` needs CAP_DAC_READ_SEARCH in the namespace that owns the superblock, which CLONE_NEWUSER never grants.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-handle-escape", scratch.path());
    switch (term) {
        .signal => |sig| try std.testing.expectEqual(linux.SIG.SYS, sig),
        else => return error.TestUnexpectedResult,
    }
}

test "spawn applies every layer, and a spawned process cannot open an AF_VSOCK socket, regardless of the network mode" {
    // A vsock address names a hypervisor CID, not a route in any network namespace.
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const term = try runProbeWithRoot("spawn-vsock", scratch.path());
    switch (term) {
        .signal => |sig| try std.testing.expectEqual(linux.SIG.SYS, sig),
        else => return error.TestUnexpectedResult,
    }
}
