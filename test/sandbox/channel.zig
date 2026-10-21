//! The Channel and Helper seams, driven through the probe. The probe spawns a
//! sandboxed program with a channel or a helper. The test reads what the probe
//! reports on standard output, or the exit status it ends with.

const std = @import("std");
const palisade = @import("palisade");
const linux = std.os.linux;
const probe_path = @import("probe_path").probe_path;

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

/// Every spawn gets its own root, so no two runs share a mount point.
fn scratchRoot() !ScratchRoot {
    var result = ScratchRoot{ .tmp = std.testing.tmpDir(.{}) };
    const resolved = try absoluteDirPath(&result.path_buffer, result.tmp.dir.handle);
    result.path_len = resolved.len;
    return result;
}

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

/// Never `inherit` standard error: a host that refuses the namespaces writes on
/// this binary's own standard error, which fails the build.
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

fn expectExitedWith(code: u8, result: CaptureResult) !void {
    try std.testing.expectEqualStrings("", result.err());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = code }, result.term);
}

test "a channel carries a request to the host and the reply back" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const result = try runProbeCapturing(&.{ probe_path, "channel-echo", scratch.path() });
    try expectExitedWith(0, result);
}

test "a channel that hands a host descriptor refuses connect with EPERM" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const result = try runProbeCapturing(&.{ probe_path, "channel-reaim", scratch.path() });
    try std.testing.expectEqualStrings("PERM\n", result.out());
    try expectExitedWith(0, result);
}

test "a helper writes its bytes to the host over its channel" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const result = try runProbeCapturing(&.{ probe_path, "channel-helper", scratch.path() });
    try std.testing.expectEqualStrings("ok", result.out());
    try expectExitedWith(0, result);
}

test "a helper that allows only exit_group still sends its ready byte and the spawn goes on" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const result = try runProbeCapturing(&.{ probe_path, "channel-helper-exit-only", scratch.path() });
    try std.testing.expectEqualStrings("", result.out());
    try expectExitedWith(0, result);
}

test "a helper that calls a syscall outside its allowed list is killed and the sandboxed program still finishes" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const result = try runProbeCapturing(&.{ probe_path, "channel-helper-outside-call", scratch.path() });
    try std.testing.expectEqualStrings("", result.out());
    try expectExitedWith(0, result);
}

test "connect from a program whose channel hands a host descriptor fails with EPERM" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const result = try runProbeCapturing(&.{ probe_path, "connect-out-hands", scratch.path() });
    try std.testing.expectEqualStrings("PERM\n", result.out());
    try expectExitedWith(0, result);
}

test "connect from a program whose channel keeps its descriptors reaches the stack" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const result = try runProbeCapturing(&.{ probe_path, "connect-out-keeps", scratch.path() });
    try std.testing.expectEqualStrings("CONNREFUSED\n", result.out());
    try expectExitedWith(0, result);
}

test "a helper writes to a descriptor it keeps and cannot reach one it did not keep" {
    var scratch = try scratchRoot();
    defer scratch.cleanup();
    const result = try runProbeCapturing(&.{ probe_path, "channel-helper-keep", scratch.path() });
    try std.testing.expectEqualStrings("kept|", result.out());
    try expectExitedWith(0, result);
}
