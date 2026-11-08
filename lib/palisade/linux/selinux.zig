//! SELinux process attributes used at an exec boundary.
//!
//! Palisade does not install policy. The host policy must permit the caller to
//! select `exec` and must define the requested transition.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const enforce_path = "/sys/fs/selinux/enforce";
// Process attributes are per-thread. `/proc/self/attr/*` addresses the thread
// group leader and is wrong when the caller is another thread; libselinux uses
// these thread-local paths for the same reason.
const current_path = "/proc/thread-self/attr/current";
const exec_path = "/proc/thread-self/attr/exec";

pub const Mode = enum {
    permissive,
    enforcing,
};

pub const Error = error{
    NotSupported,
    AccessDenied,
    InvalidContext,
    BufferTooSmall,
    Unexpected,
};

pub const Diagnostic = struct {
    operation: Operation,
    errno: linux.E,

    pub const Operation = enum {
        read_mode,
        read_current,
        read_exec,
        set_exec,

        pub fn text(self: Operation) []const u8 {
            return switch (self) {
                .read_mode => "read SELinux enforcement mode",
                .read_current => "read the current SELinux context",
                .read_exec => "read the SELinux exec context",
                .set_exec => "set the SELinux exec context",
            };
        }
    };

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("SELinux: could not {s}: {s}", .{
            self.operation.text(),
            @tagName(self.errno),
        });
    }
};

fn note(diag: ?*?Diagnostic, operation: Diagnostic.Operation, err: linux.E) void {
    const slot = diag orelse return;
    if (slot.* == null) slot.* = .{ .operation = operation, .errno = err };
}

fn errorFor(err: linux.E) Error {
    return switch (err) {
        .NOENT, .NODEV, .OPNOTSUPP => error.NotSupported,
        .ACCES, .PERM => error.AccessDenied,
        .INVAL => error.InvalidContext,
        else => error.Unexpected,
    };
}

fn open(path: [*:0]const u8, write: bool, operation: Diagnostic.Operation, diag: ?*?Diagnostic) Error!i32 {
    const flags: linux.O = if (write)
        .{ .ACCMODE = .WRONLY, .CLOEXEC = true }
    else
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true };
    const rc = linux.open(path, flags, 0);
    const call_errno = linux.errno(rc);
    if (call_errno == .SUCCESS) return @intCast(rc);
    note(diag, operation, call_errno);
    return errorFor(call_errno);
}

pub fn mode(diag: ?*?Diagnostic) Error!Mode {
    if (builtin.os.tag != .linux) return error.NotSupported;
    const fd = try open(enforce_path, false, .read_mode, diag);
    defer _ = linux.close(fd);

    var byte: [1]u8 = undefined;
    const rc = linux.read(fd, &byte, byte.len);
    const call_errno = linux.errno(rc);
    if (call_errno != .SUCCESS) {
        note(diag, .read_mode, call_errno);
        return errorFor(call_errno);
    }
    if (rc != 1) return error.Unexpected;
    return switch (byte[0]) {
        '0' => .permissive,
        '1' => .enforcing,
        else => error.Unexpected,
    };
}

fn readContext(
    path: [*:0]const u8,
    operation: Diagnostic.Operation,
    buffer: []u8,
    diag: ?*?Diagnostic,
) Error![]const u8 {
    if (buffer.len == 0) return error.BufferTooSmall;
    const fd = try open(path, false, operation, diag);
    defer _ = linux.close(fd);

    const rc = linux.read(fd, buffer.ptr, buffer.len);
    const call_errno = linux.errno(rc);
    if (call_errno != .SUCCESS) {
        note(diag, operation, call_errno);
        return errorFor(call_errno);
    }
    if (rc == buffer.len) return error.BufferTooSmall;

    var held: usize = rc;
    while (held > 0 and (buffer[held - 1] == 0 or buffer[held - 1] == '\n')) held -= 1;
    return buffer[0..held];
}

/// Returns a slice into `buffer`, without the kernel's trailing NUL or newline.
pub fn currentContext(buffer: []u8, diag: ?*?Diagnostic) Error![]const u8 {
    if (builtin.os.tag != .linux) return error.NotSupported;
    return readContext(current_path, .read_current, buffer, diag);
}

/// Returns the context selected for the next exec, or an empty slice when no
/// explicit context has been selected.
pub fn execContext(buffer: []u8, diag: ?*?Diagnostic) Error![]const u8 {
    if (builtin.os.tag != .linux) return error.NotSupported;
    return readContext(exec_path, .read_exec, buffer, diag);
}

/// Selects the context for the next `execve`. The SELinux policy decides
/// whether the requested transition is allowed.
pub fn setExecContext(context: []const u8, diag: ?*?Diagnostic) Error!void {
    if (builtin.os.tag != .linux) return error.NotSupported;
    // SELinux proc attributes accept at most one page. Keeping the temporary
    // bounded also makes this safe to call in Palisade's post-fork child.
    var encoded: [4096]u8 = undefined;
    if (context.len == 0 or context.len >= encoded.len or std.mem.indexOfScalar(u8, context, 0) != null) {
        return error.InvalidContext;
    }
    @memcpy(encoded[0..context.len], context);
    encoded[context.len] = 0;

    const fd = try open(exec_path, true, .set_exec, diag);
    defer _ = linux.close(fd);
    // The trailing NUL is part of the kernel ABI (and what setexeccon(3)
    // writes), even though reads expose the context as ordinary text.
    const encoded_len = context.len + 1;
    const rc = linux.write(fd, &encoded, encoded_len);
    const call_errno = linux.errno(rc);
    if (call_errno != .SUCCESS) {
        note(diag, .set_exec, call_errno);
        return errorFor(call_errno);
    }
    if (rc != encoded_len) return error.Unexpected;
}

test "mode reports a live SELinux kernel" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const active = mode(null) catch |err| switch (err) {
        error.NotSupported => return error.SkipZigTest,
        else => return err,
    };
    try std.testing.expect(active == .permissive or active == .enforcing);
}

test "currentContext returns the process SELinux context" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    _ = mode(null) catch return error.SkipZigTest;
    var buffer: [4096]u8 = undefined;
    const context = try currentContext(&buffer, null);
    try std.testing.expect(context.len > 0);
    try std.testing.expect(std.mem.count(u8, context, ":") >= 2);
}

test "setExecContext rejects strings the proc attribute cannot represent" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try std.testing.expectError(error.InvalidContext, setExecContext("", null));
    try std.testing.expectError(error.InvalidContext, setExecContext("a\x00b", null));
}

test "setExecContext selects the current domain for the next exec" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    _ = mode(null) catch return error.SkipZigTest;

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) return error.SkipZigTest;
    if (fork_rc == 0) {
        var current_buffer: [4096]u8 = undefined;
        const current = currentContext(&current_buffer, null) catch std.process.exit(1);
        setExecContext(current, null) catch std.process.exit(2);

        var exec_buffer: [4096]u8 = undefined;
        const selected = execContext(&exec_buffer, null) catch std.process.exit(3);
        std.process.exit(if (std.mem.eql(u8, current, selected)) 0 else 4);
    }

    var status: i32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) {
        wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    }
    try std.testing.expect(linux.errno(wait_rc) == .SUCCESS);
    try std.testing.expect(linux.W.IFEXITED(@bitCast(status)));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(@bitCast(status)));
}
