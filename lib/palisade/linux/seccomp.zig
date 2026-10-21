const std = @import("std");
const bpf = @import("bpf.zig");
const linux = std.os.linux;

pub const RET_ALLOW: u32 = 0x7fff0000;
pub const RET_KILL_PROCESS: u32 = 0x80000000;
pub const RET_ERRNO_PERM: u32 = 0x00050000 | @as(u32, @backingInt(linux.E.PERM));
pub const RET_USER_NOTIF: u32 = linux.SECCOMP.RET.USER_NOTIF;

pub const blocked_calls = [_]linux.SYS{
    .ptrace,
    .bpf,
    .userfaultfd,
    .unshare,
    .setns,
    .process_vm_readv,
    .process_vm_writev,
    .kexec_load,
    .kexec_file_load,
    .init_module,
    .finit_module,
    .delete_module,
    .mount,
    .umount2,
    .pivot_root,
    .move_mount,
    .open_tree,
    .fsopen,
    .fsmount,
    .fsconfig,
    .mount_setattr,
    .open_tree_attr,
    .fspick,
    .add_key,
    .keyctl,
    .request_key,
    .chroot,
    .syslog,
    .reboot,
    .sethostname,
    .open_by_handle_at,
};

pub const refused_calls = [_]linux.SYS{
    .io_uring_setup,
    .io_uring_enter,
    .io_uring_register,
};

const helper_refused_names = [_][]const u8{
    "unshare",
    "setns",
    "pivot_root",
    "name_to_handle_at",
    "open_by_handle_at",
    "bpf",
    "keyctl",
    "add_key",
    "request_key",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "capset",
    "setuid",
    "setgid",
    "setreuid",
    "setregid",
    "setresuid",
    "setresgid",
    "init_module",
    "finit_module",
    "delete_module",
    "userfaultfd",
    "perf_event_open",
    "kexec_load",
    "kexec_file_load",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "execve",
    "execveat",
    "chroot",
    "reboot",
    "setgroups",
    "setgroups32",
    "setfsuid",
    "setfsuid32",
    "setfsgid",
    "setfsgid32",
};

/// Calls no helper may make. With these gone, a helper cannot leave its namespaces,
/// gain privilege, or run another program.
pub const helper_refused_calls = blk: {
    var list: [helper_refused_names.len]linux.SYS = undefined;
    var count: usize = 0;
    for (helper_refused_names) |name| {
        if (@hasField(linux.SYS, name)) {
            list[count] = @field(linux.SYS, name);
            count += 1;
        }
    }
    const final = list[0..count].*;
    break :blk final;
};

fn listed(calls: []const linux.SYS, call: linux.SYS) bool {
    for (calls) |item| if (item == call) return true;
    return false;
}

/// The refused calls a helper filter answers with EPERM. A call in `helper_refused_calls` is killed instead.
const helper_eperm_calls = blk: {
    var list: [refused_calls.len]linux.SYS = undefined;
    var count: usize = 0;
    for (refused_calls) |call| {
        if (!listed(&helper_refused_calls, call)) {
            list[count] = call;
            count += 1;
        }
    }
    const final = list[0..count].*;
    break :blk final;
};

/// Append this to Helper.allowed for a helper that waits on fds. It differs by architecture.
pub const wait_calls: []const linux.SYS = if (@hasField(linux.SYS, "poll"))
    &.{ .ppoll, .poll }
else
    &.{.ppoll};

pub const TrapCall = enum {
    openat,
    execve,
    connect,
    getdents64,

    pub fn number(self: TrapCall) linux.SYS {
        return switch (self) {
            .openat => .openat,
            .execve => .execve,
            .connect => .connect,
            .getdents64 => .getdents64,
        };
    }

    pub fn pathArg(self: TrapCall) ?u2 {
        return switch (self) {
            .openat => 1,
            .execve => 0,
            .connect, .getdents64 => null,
        };
    }

    pub fn fromNumber(nr: i64) ?TrapCall {
        inline for (@typeInfo(TrapCall).@"enum".field_names, @typeInfo(TrapCall).@"enum".field_values) |_, field_value| {
            const call: TrapCall = @fromBackingInt(@intCast(field_value));
            if (@backingInt(call.number()) == nr) return call;
        }
        return null;
    }
};

pub const TrapSet = std.EnumSet(TrapCall);

pub const bootstrap_calls = [_]linux.SYS{ .read, .write, .close, .sendto };

comptime {
    for (@typeInfo(TrapCall).@"enum".field_names, @typeInfo(TrapCall).@"enum".field_values) |field_name, field_value| {
        const call: TrapCall = @fromBackingInt(@intCast(field_value));
        for (bootstrap_calls) |boot| {
            if (call.number() == boot) @compileError(
                "trapping " ++ field_name ++ " would stop the handover forever. See bootstrap_calls.",
            );
        }
        for (blocked_calls) |killed| {
            if (call.number() == killed) @compileError(
                "a killed call cannot also be an observed call: " ++ field_name,
            );
        }
        for (refused_calls) |refused| {
            if (call.number() == refused) @compileError(
                "a refused call cannot also be an observed call: " ++ field_name,
            );
        }
    }
}

pub const memory_calls = [_]linux.SYS{ .mmap, .mprotect, .pkey_mprotect };

/// The highest syscall number a person has classified. A new call past it fails the
/// test at the end of this file until someone reviews it. 471 is `rseq_slice_yield`,
/// which opens and changes nothing, so it stays allowed like `sched_yield`.
pub const classified_through: usize = 471;

fn nativeAuditArch() u32 {
    const bit_64: u32 = 0x80000000;
    const little_endian: u32 = 0x40000000;
    return switch (@import("builtin").cpu.arch) {
        .aarch64 => 183 | bit_64 | little_endian,
        .x86_64 => 62 | bit_64 | little_endian,
        .riscv64 => 243 | bit_64 | little_endian,
        else => @compileError("palisade has no audit arch for this target"),
    };
}

pub const Options = struct {
    strict_wx: bool = true,
    block_connect: bool = false,
    traps: TrapSet = .empty,
};

pub fn build(allocator: std.mem.Allocator, options: Options) ![]bpf.Insn {
    var insns: std.ArrayList(bpf.Insn) = .empty;
    errdefer insns.deinit(allocator);

    try appendPrologue(allocator, &insns, &blocked_calls, &refused_calls);

    if (options.block_connect) {
        const connect_number: u32 = @intCast(@backingInt(linux.SYS.connect));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, connect_number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
    }

    try appendExecveatRule(allocator, &insns);
    try appendVsockRule(allocator, &insns);
    if (options.strict_wx) try appendWriteExecRules(allocator, &insns);

    var traps = options.traps.iterator();
    while (traps.next()) |call| {
        const number: u32 = @intCast(@backingInt(call.number()));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_USER_NOTIF));
    }

    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ALLOW));
    return insns.toOwnedSlice(allocator);
}

fn appendPrologue(
    allocator: std.mem.Allocator,
    insns: *std.ArrayList(bpf.Insn),
    killed: []const linux.SYS,
    refused: []const linux.SYS,
) !void {
    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_arch));
    try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, nativeAuditArch(), 1, 0));
    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));

    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));

    if (@import("builtin").cpu.arch == .x86_64) {
        try insns.append(allocator, bpf.jump(bpf.JMP_JGE_K, 0x40000000, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
    }

    for (killed) |call| {
        const number: u32 = @intCast(@backingInt(call));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
    }

    for (refused) |call| {
        const number: u32 = @intCast(@backingInt(call));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
    }
}

fn appendExecveatRule(allocator: std.mem.Allocator, insns: *std.ArrayList(bpf.Insn)) !void {
    // AT_EMPTY_PATH lets execveat run a memfd_create file with no path to check.
    const execveat_number: u32 = @intCast(@backingInt(linux.SYS.execveat));
    const at_empty_path: u32 = 0x1000;
    try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, execveat_number, 0, 5));
    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(4)));
    try insns.append(allocator, bpf.stmt(bpf.ALU_AND_K, at_empty_path));
    try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, at_empty_path, 0, 1));
    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
}

fn appendVsockRule(allocator: std.mem.Allocator, insns: *std.ArrayList(bpf.Insn)) !void {
    const socket_number: u32 = @intCast(@backingInt(linux.SYS.socket));
    const af_vsock: u32 = 40;
    try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, socket_number, 0, 4));
    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(0)));
    try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, af_vsock, 0, 1));
    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
}

fn appendWriteExecRules(allocator: std.mem.Allocator, insns: *std.ArrayList(bpf.Insn)) !void {
    {
        const personality_number: u32 = @intCast(@backingInt(linux.SYS.personality));
        const read_implies_exec: u32 = 0x0400000;
        const read_current: u32 = 0xffffffff;
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, personality_number, 0, 6));
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(0)));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, read_current, 3, 0));
        try insns.append(allocator, bpf.stmt(bpf.ALU_AND_K, read_implies_exec));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, read_implies_exec, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
    }

    {
        const shmat_number: u32 = @intCast(@backingInt(linux.SYS.shmat));
        const shm_exec: u32 = 0x8000;
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, shmat_number, 0, 5));
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(2)));
        try insns.append(allocator, bpf.stmt(bpf.ALU_AND_K, shm_exec));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, shm_exec, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
    }

    const prot_write_exec: u32 = 0x2 | 0x4;
    for (memory_calls) |call| {
        const number: u32 = @intCast(@backingInt(call));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 6));
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(2)));
        try insns.append(allocator, bpf.stmt(bpf.ALU_AND_K, prot_write_exec));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, prot_write_exec, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ERRNO_PERM));
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
        try insns.append(allocator, bpf.stmt(bpf.JMP_JA, 0));
    }
}

pub const reader_calls = blk: {
    var list: []const linux.SYS = &.{
        .process_vm_readv,
        .ioctl,
        .ppoll,
        .exit_group,
        .exit,
        .rt_sigreturn,
        .restart_syscall,
    };
    if (@hasField(linux.SYS, "poll")) list = list ++ &[_]linux.SYS{.poll};
    break :blk list;
};

comptime {
    var reads_memory = false;
    for (reader_calls) |call| {
        if (call == .process_vm_readv) reads_memory = true;
    }
    if (!reads_memory) @compileError(
        "the path reader cannot read a path without process_vm_readv. See reader_calls.",
    );
}

pub fn buildReader(allocator: std.mem.Allocator) ![]bpf.Insn {
    return buildAllowlist(allocator, reader_calls);
}

pub const keeper_calls: []const linux.SYS = &.{
    .wait4,
    .ppoll,
    .write,
    .exit_group,
    .exit,
    .rt_sigreturn,
    .restart_syscall,
};

pub fn buildKeeper(allocator: std.mem.Allocator) ![]bpf.Insn {
    return buildAllowlist(allocator, keeper_calls);
}

/// A filter for a helper process. The blocked and refused calls, the execveat
/// empty-path rule, the vsock rule and the write and execute rules apply
/// whatever `allowed` holds. When `channel_fds` is not empty, sendmsg and
/// recvmsg only work on those descriptors. When `ready_fd` is set, write works on
/// that descriptor even if `allowed` lacks write.
pub fn buildHelper(
    allocator: std.mem.Allocator,
    allowed: []const linux.SYS,
    channel_fds: []const i32,
    ready_fd: ?i32,
) ![]bpf.Insn {
    std.debug.assert(channel_fds.len <= 16);

    var insns: std.ArrayList(bpf.Insn) = .empty;
    errdefer insns.deinit(allocator);

    try appendPrologue(allocator, &insns, &helper_refused_calls, &helper_eperm_calls);
    try appendExecveatRule(allocator, &insns);
    try appendVsockRule(allocator, &insns);
    try appendWriteExecRules(allocator, &insns);

    if (channel_fds.len > 0) {
        try appendChannelRule(allocator, &insns, .sendmsg, channel_fds);
        try appendChannelRule(allocator, &insns, .recvmsg, channel_fds);
    }

    if (ready_fd) |fd| try appendReadyRule(allocator, &insns, fd);

    for (allowed) |call| {
        const number: u32 = @intCast(@backingInt(call));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ALLOW));
    }

    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
    return insns.toOwnedSlice(allocator);
}

/// Allows write and close on `fd` only. Another descriptor falls through to the allowed list.
fn appendReadyRule(allocator: std.mem.Allocator, insns: *std.ArrayList(bpf.Insn), fd: i32) !void {
    for ([_]linux.SYS{ .write, .close }) |call| {
        const number: u32 = @intCast(@backingInt(call));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 4));
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(0)));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, @as(u32, @bitCast(fd)), 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ALLOW));
        try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
    }
}

/// One block for `call`. Its last instruction is RET_ALLOW, so the fd
/// checks jump past the kill and the block never falls through.
fn appendChannelRule(
    allocator: std.mem.Allocator,
    insns: *std.ArrayList(bpf.Insn),
    call: linux.SYS,
    channel_fds: []const i32,
) !void {
    const block_len = channel_fds.len + 4;
    const number: u32 = @intCast(@backingInt(call));
    try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, @intCast(block_len - 1)));
    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offsetOfArgLow(0)));
    for (channel_fds, 0..) |fd, i| {
        const to_allow: u8 = @intCast(channel_fds.len - i);
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, @as(u32, @bitCast(fd)), to_allow, 0));
    }
    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ALLOW));
}

/// A pure allowlist: listed calls are allowed and every other call kills the process.
/// For callers that confine their own subprocess outside Palisade.
pub fn buildAllowlist(allocator: std.mem.Allocator, calls: []const linux.SYS) ![]bpf.Insn {
    var insns: std.ArrayList(bpf.Insn) = .empty;
    errdefer insns.deinit(allocator);

    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_arch));
    try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, nativeAuditArch(), 1, 0));
    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));

    try insns.append(allocator, bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr));
    for (calls) |call| {
        const number: u32 = @intCast(@backingInt(call));
        try insns.append(allocator, bpf.jump(bpf.JMP_JEQ_K, number, 0, 1));
        try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_ALLOW));
    }

    try insns.append(allocator, bpf.stmt(bpf.RET_K, RET_KILL_PROCESS));
    return insns.toOwnedSlice(allocator);
}

pub const Error = error{
    NotSupported,
    NoNewPrivsRefused,
    NotPermitted,
    Rejected,
    Unexpected,
};

pub const Step = enum { no_new_privs, install, install_listening };

pub const Diagnostic = struct {
    step: Step,
    errno: i32,

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const name = std.enums.fromInt(linux.E, self.errno);
        if (name) |e| {
            try writer.print("{t} at the {t} step", .{ e, self.step });
        } else {
            try writer.print("errno {d} at the {t} step", .{ self.errno, self.step });
        }
    }
};

fn note(diag: ?*?Diagnostic, step: Step, errno: i32) void {
    if (diag) |slot| slot.* = .{ .step = step, .errno = errno };
}

pub fn install(prog: bpf.Prog, diag: ?*?Diagnostic) Error!void {
    _ = try setModeFilter(prog, 0, .install, diag);
}

pub fn installListening(prog: bpf.Prog, diag: ?*?Diagnostic) Error!i32 {
    const rc = try setModeFilter(prog, linux.SECCOMP.FILTER_FLAG.NEW_LISTENER, .install_listening, diag);
    return @intCast(rc);
}

pub const InstallProbe = union(enum) {
    ok,
    refused: Error,
    unknown,
};

pub fn probeInstall(prog: bpf.Prog) InstallProbe {
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS) return .unknown;

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return .unknown;
    }

    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        var answer: [1]u8 = .{0};
        if (install(prog, null)) |_| {} else |err| answer[0] = installFaultCode(err);
        _ = linux.write(fds[1], &answer, answer.len);
        std.process.exit(0);
    }

    _ = linux.close(fds[1]);
    var answer: [1]u8 = undefined;
    var filled: usize = 0;
    while (filled < answer.len) {
        const rc = linux.read(fds[0], answer[filled..].ptr, answer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        filled += rc;
    }
    _ = linux.close(fds[0]);

    var status: i32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);

    if (filled != answer.len) return .unknown;
    return installProbeFor(answer[0]);
}

fn installProbeFor(answer: u8) InstallProbe {
    if (answer == 0) return .ok;
    return switch (answer) {
        3 => .{ .refused = error.NotSupported },
        4 => .{ .refused = error.Rejected },
        5 => .{ .refused = error.NotPermitted },
        6 => .{ .refused = error.NoNewPrivsRefused },
        7 => .{ .refused = error.Unexpected },
        else => .unknown,
    };
}

fn setModeFilter(prog: bpf.Prog, flags: u32, step: Step, diag: ?*?Diagnostic) Error!usize {
    const pr = linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0);
    switch (linux.errno(pr)) {
        .SUCCESS => {},
        else => |err| {
            note(diag, .no_new_privs, @backingInt(err));
            return error.NoNewPrivsRefused;
        },
    }

    const rc = linux.seccomp(
        linux.SECCOMP.SET_MODE_FILTER,
        flags,
        @ptrCast(&prog),
    );
    const err = linux.errno(rc);
    if (err != .SUCCESS) note(diag, step, @backingInt(err));
    return switch (err) {
        .SUCCESS => rc,
        .NOSYS => error.NotSupported,
        .ACCES => error.NotPermitted,
        .INVAL => error.Rejected,
        else => error.Unexpected,
    };
}

test "the filter starts by refusing a foreign architecture" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    try std.testing.expectEqual(bpf.LD_W_ABS, prog[0].code);
    try std.testing.expectEqual(bpf.offset_of_arch, prog[0].k);
    try std.testing.expectEqual(bpf.JMP_JEQ_K, prog[1].code);
}

test "the filter ends with an allow" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    const last = prog[prog.len - 1];
    try std.testing.expectEqual(bpf.RET_K, last.code);
    try std.testing.expectEqual(@as(u32, RET_ALLOW), last.k);
}

test "the filter names every call that must be blocked" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    var missing: std.ArrayList(u8) = .empty;
    defer missing.deinit(allocator);

    for (blocked_calls) |call| {
        const number: u32 = @intCast(@backingInt(call));
        var found = false;
        for (prog) |insn| {
            if (insn.code == bpf.JMP_JEQ_K and insn.k == number) found = true;
        }
        if (!found) try missing.print(allocator, "the filter does not check {s}\n", .{@tagName(call)});
    }

    try std.testing.expectEqualStrings("", missing.items);
}

test "every instruction the builder emits is one the kernel accepts" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    try std.testing.expect(prog.len <= 4096);
    for (prog) |insn| {
        const known = insn.code == bpf.LD_W_ABS or insn.code == bpf.JMP_JEQ_K or
            insn.code == bpf.JMP_JGE_K or insn.code == bpf.JMP_JA or
            insn.code == bpf.ALU_AND_K or insn.code == bpf.RET_K;
        try std.testing.expect(known);
    }
}

test "the architecture mismatch branch returns RET_KILL_PROCESS" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    try std.testing.expectEqual(@as(u8, 0), prog[1].jf);
    try std.testing.expectEqual(bpf.RET_K, prog[2].code);
    try std.testing.expectEqual(@as(u32, RET_KILL_PROCESS), prog[2].k);
}

fn precededByArgumentLoad(prog: []const bpf.Insn, i: usize) bool {
    if (i == 0) return false;
    const before = prog[i - 1];
    return before.code == bpf.LD_W_ABS and before.k != bpf.offset_of_nr;
}

test "every blocked call comparison is followed by a kill instruction" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    var checked: usize = 0;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K) continue;
        if (precededByArgumentLoad(prog, i)) continue;
        var is_blocked_call = false;
        for (blocked_calls) |call| {
            if (insn.k == @as(u32, @intCast(@backingInt(call)))) is_blocked_call = true;
        }
        if (!is_blocked_call) continue;

        try std.testing.expectEqual(bpf.RET_K, prog[i + 1].code);
        try std.testing.expectEqual(@as(u32, RET_KILL_PROCESS), prog[i + 1].k);
        checked += 1;
    }
    try std.testing.expectEqual(blocked_calls.len, checked);
}

test "every blocked call comparison jumps so the kill is reachable and the skip clears it" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    var checked: usize = 0;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K) continue;
        if (precededByArgumentLoad(prog, i)) continue;
        var is_blocked_call = false;
        for (blocked_calls) |call| {
            if (insn.k == @as(u32, @intCast(@backingInt(call)))) is_blocked_call = true;
        }
        if (!is_blocked_call) continue;

        try std.testing.expectEqual(@as(u8, 0), insn.jt);
        try std.testing.expectEqual(@as(u8, 1), insn.jf);
        checked += 1;
    }
    try std.testing.expectEqual(blocked_calls.len, checked);
}

test "every refused call answers EPERM, and none of them kills" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    var checked: usize = 0;
    for (refused_calls) |call| {
        const number: u32 = @intCast(@backingInt(call));
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != number) continue;
            try std.testing.expectEqual(@as(u8, 0), insn.jt);
            try std.testing.expectEqual(@as(u8, 1), insn.jf);
            try std.testing.expectEqual(bpf.RET_K, prog[i + 1].code);
            try std.testing.expectEqual(RET_ERRNO_PERM, prog[i + 1].k);
            try std.testing.expect(prog[i + 1].k != RET_KILL_PROCESS);
            checked += 1;
        }
    }
    try std.testing.expectEqual(refused_calls.len, checked);
}

test "the two lists share no call, so nothing is both killed and refused" {
    for (refused_calls) |refused| {
        for (blocked_calls) |blocked| {
            try std.testing.expect(refused != blocked);
        }
    }

    try std.testing.expectEqualSlices(linux.SYS, &.{
        .io_uring_setup,
        .io_uring_enter,
        .io_uring_register,
    }, &refused_calls);
}

test "the refusal block adds only itself, and leaves the call number for the checks after it" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    for (refused_calls) |call| {
        const number: u32 = @intCast(@backingInt(call));
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != number) continue;
            try std.testing.expectEqual(bpf.RET_K, prog[i + 1].code);
            try std.testing.expect(prog[i + 2].code != bpf.LD_W_ABS);
        }
    }
}

test "strict_wx off makes a shorter filter that reads no protection flag, but still reads execveat's" {
    const allocator = std.testing.allocator;
    const strict = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(strict);
    const loose = try build(allocator, .{ .strict_wx = false });
    defer allocator.free(loose);

    try std.testing.expect(strict.len > loose.len);

    var loose_masks: usize = 0;
    for (loose) |insn| {
        if (insn.code != bpf.ALU_AND_K) continue;
        try std.testing.expectEqual(@as(u32, 0x1000), insn.k);
        loose_masks += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), loose_masks);
}

test "the write and execute rule refuses with EPERM and does not kill" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(prog);

    var checked: usize = 0;
    for (memory_calls) |call| {
        const number: u32 = @intCast(@backingInt(call));
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != number) continue;
            try std.testing.expectEqual(bpf.ALU_AND_K, prog[i + 2].code);
            try std.testing.expectEqual(bpf.JMP_JEQ_K, prog[i + 3].code);
            try std.testing.expectEqual(bpf.RET_K, prog[i + 4].code);
            try std.testing.expectEqual(RET_ERRNO_PERM, prog[i + 4].k);
            checked += 1;
        }
    }
    try std.testing.expectEqual(memory_calls.len, checked);
}

test "each write and execute block jumps over exactly its own six instructions" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(prog);

    var checked: usize = 0;
    for (memory_calls) |call| {
        const number: u32 = @intCast(@backingInt(call));
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != number) continue;
            try std.testing.expectEqual(@as(u8, 0), insn.jt);
            try std.testing.expectEqual(@as(u8, 6), insn.jf);

            const inner = prog[i + 3];
            try std.testing.expectEqual(bpf.JMP_JEQ_K, inner.code);
            try std.testing.expectEqual(@as(u8, 0), inner.jt);
            try std.testing.expectEqual(@as(u8, 1), inner.jf);
            checked += 1;
        }
    }
    try std.testing.expectEqual(memory_calls.len, checked);
}

test "the shmat rule refuses SHM_EXEC with EPERM and does not kill" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(prog);

    const shmat_number: u32 = @intCast(@backingInt(linux.SYS.shmat));
    var found = false;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K or insn.k != shmat_number) continue;
        try std.testing.expectEqual(bpf.LD_W_ABS, prog[i + 1].code);
        try std.testing.expectEqual(bpf.ALU_AND_K, prog[i + 2].code);
        try std.testing.expectEqual(bpf.JMP_JEQ_K, prog[i + 3].code);
        try std.testing.expectEqual(bpf.RET_K, prog[i + 4].code);
        try std.testing.expectEqual(RET_ERRNO_PERM, prog[i + 4].k);
        found = true;
    }
    try std.testing.expect(found);
}

test "the shmat rule jumps over exactly its own five instructions" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(prog);

    const shmat_number: u32 = @intCast(@backingInt(linux.SYS.shmat));
    var found = false;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K or insn.k != shmat_number) continue;
        try std.testing.expectEqual(@as(u8, 0), insn.jt);
        try std.testing.expectEqual(@as(u8, 5), insn.jf);

        const inner = prog[i + 3];
        try std.testing.expectEqual(bpf.JMP_JEQ_K, inner.code);
        try std.testing.expectEqual(@as(u8, 0), inner.jt);
        try std.testing.expectEqual(@as(u8, 1), inner.jf);
        found = true;
    }
    try std.testing.expect(found);
}

test "the execveat rule kills on AT_EMPTY_PATH and does not read strict_wx" {
    const allocator = std.testing.allocator;
    const execveat_number: u32 = @intCast(@backingInt(linux.SYS.execveat));
    const at_empty_path: u32 = 0x1000;

    inline for (.{ true, false }) |wx| {
        const prog = try build(allocator, .{ .strict_wx = wx });
        defer allocator.free(prog);

        var found = false;
        for (prog, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != execveat_number) continue;
            try std.testing.expectEqual(bpf.LD_W_ABS, prog[i + 1].code);
            try std.testing.expectEqual(bpf.offsetOfArgLow(4), prog[i + 1].k);
            try std.testing.expectEqual(bpf.ALU_AND_K, prog[i + 2].code);
            try std.testing.expectEqual(at_empty_path, prog[i + 2].k);
            try std.testing.expectEqual(bpf.JMP_JEQ_K, prog[i + 3].code);
            try std.testing.expectEqual(at_empty_path, prog[i + 3].k);
            try std.testing.expectEqual(bpf.RET_K, prog[i + 4].code);
            try std.testing.expectEqual(RET_KILL_PROCESS, prog[i + 4].k);
            found = true;
        }
        try std.testing.expect(found);
    }
}

test "the execveat rule jumps over exactly its own five instructions" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(prog);

    const execveat_number: u32 = @intCast(@backingInt(linux.SYS.execveat));
    var found = false;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K or insn.k != execveat_number) continue;
        try std.testing.expectEqual(@as(u8, 0), insn.jt);
        try std.testing.expectEqual(@as(u8, 5), insn.jf);

        const inner = prog[i + 3];
        try std.testing.expectEqual(bpf.JMP_JEQ_K, inner.code);
        try std.testing.expectEqual(@as(u8, 0), inner.jt);
        try std.testing.expectEqual(@as(u8, 1), inner.jf);
        found = true;
    }
    try std.testing.expect(found);
}

test "the socket rule kills on AF_VSOCK and does not read strict_wx or block_connect" {
    const allocator = std.testing.allocator;
    const socket_number: u32 = @intCast(@backingInt(linux.SYS.socket));
    const af_vsock: u32 = 40;

    inline for (.{ true, false }) |wx| {
        inline for (.{ true, false }) |connect| {
            const prog = try build(allocator, .{ .strict_wx = wx, .block_connect = connect });
            defer allocator.free(prog);

            var found = false;
            for (prog, 0..) |insn, i| {
                if (insn.code != bpf.JMP_JEQ_K or insn.k != socket_number) continue;
                try std.testing.expectEqual(bpf.LD_W_ABS, prog[i + 1].code);
                try std.testing.expectEqual(bpf.offsetOfArgLow(0), prog[i + 1].k);
                try std.testing.expectEqual(bpf.JMP_JEQ_K, prog[i + 2].code);
                try std.testing.expectEqual(af_vsock, prog[i + 2].k);
                try std.testing.expectEqual(bpf.RET_K, prog[i + 3].code);
                try std.testing.expectEqual(RET_KILL_PROCESS, prog[i + 3].k);
                found = true;
            }
            try std.testing.expect(found);
        }
    }
}

test "the socket rule jumps over exactly its own four instructions" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{ .strict_wx = true });
    defer allocator.free(prog);

    const socket_number: u32 = @intCast(@backingInt(linux.SYS.socket));
    var found = false;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K or insn.k != socket_number) continue;
        try std.testing.expectEqual(@as(u8, 0), insn.jt);
        try std.testing.expectEqual(@as(u8, 4), insn.jf);

        const inner = prog[i + 2];
        try std.testing.expectEqual(bpf.JMP_JEQ_K, inner.code);
        try std.testing.expectEqual(@as(u8, 0), inner.jt);
        try std.testing.expectEqual(@as(u8, 1), inner.jf);
        found = true;
    }
    try std.testing.expect(found);
}

test "connect is left alone by default, and the block_connect filter refuses it with EPERM" {
    const allocator = std.testing.allocator;
    const connect_number: u32 = @intCast(@backingInt(linux.SYS.connect));

    const default = try build(allocator, .{});
    defer allocator.free(default);
    for (default) |insn| {
        try std.testing.expect(!(insn.code == bpf.JMP_JEQ_K and insn.k == connect_number));
    }

    const filtered = try build(allocator, .{ .block_connect = true });
    defer allocator.free(filtered);
    var found: usize = 0;
    for (filtered, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K or insn.k != connect_number) continue;
        try std.testing.expectEqual(@as(u8, 0), insn.jt);
        try std.testing.expectEqual(@as(u8, 1), insn.jf);
        try std.testing.expectEqual(bpf.RET_K, filtered[i + 1].code);
        try std.testing.expectEqual(RET_ERRNO_PERM, filtered[i + 1].k);
        try std.testing.expect(filtered[i + 1].k != RET_KILL_PROCESS);
        found += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), found);
}

test "the connect rule adds only itself, and leaves the call number for the checks after it" {
    const allocator = std.testing.allocator;
    const without = try build(allocator, .{});
    defer allocator.free(without);
    const with = try build(allocator, .{ .block_connect = true });
    defer allocator.free(with);

    try std.testing.expectEqual(without.len + 2, with.len);

    var at: usize = 0;
    while (at < without.len and std.meta.eql(without[at], with[at])) : (at += 1) {}
    try std.testing.expect(at < without.len);
    try std.testing.expectEqualSlices(bpf.Insn, without[at..], with[at + 2 ..]);

    const connect_number: u32 = @intCast(@backingInt(linux.SYS.connect));
    try std.testing.expectEqual(bpf.JMP_JEQ_K, with[at].code);
    try std.testing.expectEqual(connect_number, with[at].k);
    try std.testing.expectEqual(bpf.RET_K, with[at + 1].code);
}

test "no syscall in std.os.linux.SYS is numbered past classified_through" {
    const allocator = std.testing.allocator;
    const info = @typeInfo(linux.SYS).@"enum";
    var found_new: std.ArrayList(u8) = .empty;
    defer found_new.deinit(allocator);

    inline for (info.field_names, info.field_values) |name, value| {
        if (value > classified_through) {
            try found_new.print(allocator, "{s} = {d}\n", .{ name, value });
        }
    }

    try std.testing.expectEqualStrings("", found_new.items);
}

fn waitForExitCode(pid: linux.pid_t) !u32 {
    var status: i32 = undefined;
    var rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(pid, &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(rc));
    try std.testing.expect(linux.W.IFEXITED(@bitCast(status)));
    return linux.W.EXITSTATUS(@bitCast(status));
}

fn chdirRefusedFilter() [4]bpf.Insn {
    return .{
        bpf.stmt(bpf.LD_W_ABS, bpf.offset_of_nr),
        bpf.jump(bpf.JMP_JEQ_K, @backingInt(linux.SYS.chdir), 0, 1),
        bpf.stmt(bpf.RET_K, RET_ERRNO_PERM),
        bpf.stmt(bpf.RET_K, RET_ALLOW),
    };
}

fn installFaultCode(err: Error) u8 {
    return switch (err) {
        error.NotSupported => 3,
        error.Rejected => 4,
        error.NotPermitted => 5,
        error.NoNewPrivsRefused => 6,
        error.Unexpected => 7,
    };
}

test "the install probe answers about the machine and never about a child that said nothing" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const insns = try build(allocator, .{});
    defer allocator.free(insns);

    try std.testing.expectEqual(InstallProbe.ok, probeInstall(bpf.Prog.init(insns)));

    try std.testing.expectEqual(InstallProbe.ok, installProbeFor(0));
    try std.testing.expectEqual(
        InstallProbe{ .refused = error.NotSupported },
        installProbeFor(3),
    );
    try std.testing.expectEqual(InstallProbe.unknown, installProbeFor(200));
}

test "install turns on no_new_privs, and does not rely on a caller to do it" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const runner_nnp = linux.prctl(@backingInt(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(runner_nnp));
    if (runner_nnp != 0) return error.SkipZigTest;

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        const before = linux.prctl(@backingInt(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0);
        if (linux.errno(before) != .SUCCESS) std.process.exit(11);
        if (before != 0) std.process.exit(10);

        var insns = chdirRefusedFilter();
        install(bpf.Prog.init(&insns), null) catch |err| std.process.exit(installFaultCode(err));

        const after = linux.prctl(@backingInt(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0);
        if (linux.errno(after) != .SUCCESS) std.process.exit(11);
        if (after != 1) std.process.exit(12);
        std.process.exit(0);
    }

    const code = try waitForExitCode(@intCast(fork_rc));
    if (code == 3) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), code);
}

test "the kernel enforces the filter that install returned success for" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        if (linux.errno(linux.chdir("/")) != .SUCCESS) std.process.exit(10);

        var insns = chdirRefusedFilter();
        install(bpf.Prog.init(&insns), null) catch |err| std.process.exit(installFaultCode(err));

        if (linux.errno(linux.chdir("/")) != .PERM) std.process.exit(12);
        std.process.exit(0);
    }

    const code = try waitForExitCode(@intCast(fork_rc));
    if (code == 3) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0), code);
}

test "a trap set puts a user notification return in the filter, and an empty one puts nothing" {
    const allocator = std.testing.allocator;

    const plain = try build(allocator, .{});
    defer allocator.free(plain);
    for (plain) |insn| {
        try std.testing.expect(!(insn.code == bpf.RET_K and insn.k == RET_USER_NOTIF));
    }

    const watching = try build(allocator, .{ .traps = TrapSet.initMany(&.{ .openat, .execve }) });
    defer allocator.free(watching);

    var observed: usize = 0;
    for (&[_]TrapCall{ .openat, .execve }) |call| {
        const wanted: u32 = @intCast(@backingInt(call.number()));
        for (watching, 0..) |insn, i| {
            if (insn.code != bpf.JMP_JEQ_K or insn.k != wanted) continue;
            try std.testing.expectEqual(@as(u8, 0), insn.jt);
            try std.testing.expectEqual(@as(u8, 1), insn.jf);
            try std.testing.expectEqual(bpf.RET_K, watching[i + 1].code);
            try std.testing.expectEqual(RET_USER_NOTIF, watching[i + 1].k);
            observed += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), observed);

    const connect_number: u32 = @intCast(@backingInt(linux.SYS.connect));
    for (watching) |insn| {
        try std.testing.expect(!(insn.code == bpf.JMP_JEQ_K and insn.k == connect_number));
    }
}

test "no call the handover makes can ever be trapped" {
    inline for (@typeInfo(TrapCall).@"enum".field_names, @typeInfo(TrapCall).@"enum".field_values) |_, field_value| {
        const call: TrapCall = @fromBackingInt(@intCast(field_value));
        for (bootstrap_calls) |boot| {
            try std.testing.expect(call.number() != boot);
        }
    }
}

test "nothing on the kill list and nothing on the refusal list can be trapped" {
    inline for (@typeInfo(TrapCall).@"enum".field_names, @typeInfo(TrapCall).@"enum".field_values) |_, field_value| {
        const call: TrapCall = @fromBackingInt(@intCast(field_value));
        for (blocked_calls) |killed| {
            try std.testing.expect(call.number() != killed);
        }
        for (refused_calls) |refused| {
            try std.testing.expect(call.number() != refused);
        }
    }
}

test "a trapped call is never reached by a filter that already kills or refuses it" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{
        .block_connect = true,
        .traps = TrapSet.initMany(&.{.connect}),
    });
    defer allocator.free(prog);

    const connect_number: u32 = @intCast(@backingInt(linux.SYS.connect));
    var first_answer: ?u32 = null;
    for (prog, 0..) |insn, i| {
        if (insn.code != bpf.JMP_JEQ_K or insn.k != connect_number) continue;
        if (first_answer == null) first_answer = prog[i + 1].k;
    }
    try std.testing.expectEqual(@as(?u32, RET_ERRNO_PERM), first_answer);
}

test "every syscall number a notification can carry maps back to the call it names" {
    inline for (@typeInfo(TrapCall).@"enum".field_names, @typeInfo(TrapCall).@"enum".field_values) |_, field_value| {
        const call: TrapCall = @fromBackingInt(@intCast(field_value));
        try std.testing.expectEqual(
            @as(?TrapCall, call),
            TrapCall.fromNumber(@intCast(@backingInt(call.number()))),
        );
    }
    try std.testing.expectEqual(
        @as(?TrapCall, null),
        TrapCall.fromNumber(@intCast(@backingInt(linux.SYS.getppid))),
    );
}

test "the reader's filter permits its own four calls and kills the rest" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const insns = try buildReader(allocator);
    defer allocator.free(insns);

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        install(bpf.Prog.init(insns), null) catch |err| std.process.exit(installFaultCode(err));

        var none: [0]linux.pollfd = .{};
        var instant: linux.timespec = .{ .sec = 0, .nsec = 0 };
        if (linux.errno(linux.ppoll(&none, 0, &instant, null)) != .SUCCESS) {
            std.process.exit(11);
        }

        _ = linux.openat(linux.AT.FDCWD, "/", .{ .ACCMODE = .RDONLY }, 0);
        std.process.exit(12);
    }

    var status: i32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    if (linux.W.IFEXITED(@bitCast(status)) and linux.W.EXITSTATUS(@bitCast(status)) == 3) return error.SkipZigTest;

    try std.testing.expect(linux.W.IFSIGNALED(@bitCast(status)));
    try std.testing.expectEqual(linux.SIG.SYS, linux.W.TERMSIG(@bitCast(status)));
}

test "the keeper filter permits reap wait and readiness calls" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const insns = try buildKeeper(allocator);
    defer allocator.free(insns);

    var pipe: [2]i32 = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })));

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        install(bpf.Prog.init(insns), null) catch |err| std.process.exit(installFaultCode(err));

        var status: i32 = undefined;
        const reap_rc = linux.waitpid(-1, &status, linux.W.NOHANG);
        if (linux.errno(reap_rc) != .CHILD) std.process.exit(11);

        var none: [0]linux.pollfd = .{};
        var instant: linux.timespec = .{ .sec = 0, .nsec = 0 };
        if (linux.errno(linux.ppoll(&none, 0, &instant, null)) != .SUCCESS) {
            std.process.exit(12);
        }

        const byte = [1]u8{1};
        if (linux.errno(linux.write(pipe[1], &byte, byte.len)) != .SUCCESS) {
            std.process.exit(13);
        }
        std.process.exit(0);
    }

    _ = linux.close(pipe[1]);

    var status: i32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    if (linux.W.IFEXITED(@bitCast(status)) and linux.W.EXITSTATUS(@bitCast(status)) == 3) return error.SkipZigTest;
    try std.testing.expect(linux.W.IFEXITED(@bitCast(status)));
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(@bitCast(status)));
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), linux.read(pipe[0], &byte, byte.len));
    _ = linux.close(pipe[0]);
}

test "the keeper filter kills a call outside its allowlist" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const insns = try buildKeeper(allocator);
    defer allocator.free(insns);

    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        install(bpf.Prog.init(insns), null) catch |err| std.process.exit(installFaultCode(err));
        _ = linux.openat(linux.AT.FDCWD, "/", .{ .ACCMODE = .RDONLY }, 0);
        std.process.exit(12);
    }

    var status: i32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    if (linux.W.IFEXITED(@bitCast(status)) and linux.W.EXITSTATUS(@bitCast(status)) == 3) return error.SkipZigTest;
    try std.testing.expect(linux.W.IFSIGNALED(@bitCast(status)));
    try std.testing.expectEqual(linux.SIG.SYS, linux.W.TERMSIG(@bitCast(status)));
}

fn evaluateWithArgs(insns: []const bpf.Insn, nr: linux.SYS, args: [6]u64) u32 {
    const endian = @import("builtin").cpu.arch.endian();
    var data: [64]u8 = @splat(0);
    std.mem.writeInt(u32, data[0..4], @intCast(@backingInt(nr)), endian);
    std.mem.writeInt(u32, data[4..8], nativeAuditArch(), endian);
    for (args, 0..) |arg, i| {
        std.mem.writeInt(u64, data[16 + i * 8 ..][0..8], arg, endian);
    }

    var acc: u32 = 0;
    var pc: usize = 0;
    for (0..insns.len) |_| {
        if (pc >= insns.len) @panic("the filter ran past its last instruction");
        const insn = insns[pc];
        switch (insn.code) {
            bpf.LD_W_ABS => {
                acc = std.mem.readInt(u32, data[insn.k..][0..4], endian);
                pc += 1;
            },
            bpf.ALU_AND_K => {
                acc &= insn.k;
                pc += 1;
            },
            bpf.JMP_JEQ_K => {
                const skip: usize = if (acc == insn.k) insn.jt else insn.jf;
                pc += 1 + skip;
            },
            bpf.JMP_JGE_K => {
                const skip: usize = if (acc >= insn.k) insn.jt else insn.jf;
                pc += 1 + skip;
            },
            bpf.JMP_JA => pc += 1 + @as(usize, insn.k),
            bpf.RET_K => return insn.k,
            else => @panic("unsupported opcode in test interpreter"),
        }
    }
    @panic("the filter has no return");
}

fn evaluate(insns: []const bpf.Insn, nr: linux.SYS) u32 {
    return evaluateWithArgs(insns, nr, @splat(0));
}

fn evaluateWithArg0(insns: []const bpf.Insn, nr: linux.SYS, arg0: u64) u32 {
    return evaluateWithArgs(insns, nr, .{ arg0, 0, 0, 0, 0, 0 });
}

test "the test interpreter agrees with the filter that build makes" {
    const allocator = std.testing.allocator;
    const prog = try build(allocator, .{});
    defer allocator.free(prog);

    try std.testing.expectEqual(RET_KILL_PROCESS, evaluate(prog, .ptrace));
    try std.testing.expectEqual(RET_ALLOW, evaluate(prog, .read));
}

test "buildHelper kills a blocked call even when the caller allows it" {
    const insns = try buildHelper(std.testing.allocator, &.{ .read, .ptrace }, &.{}, null);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluate(insns, .ptrace));
    try std.testing.expectEqual(RET_ALLOW, evaluate(insns, .read));
}

test "buildHelper allows sendmsg only on the named channel fd" {
    const insns = try buildHelper(std.testing.allocator, &.{}, &.{3}, null);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_ALLOW, evaluateWithArg0(insns, .sendmsg, 3));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluateWithArg0(insns, .sendmsg, 4));
    try std.testing.expectEqual(RET_ALLOW, evaluateWithArg0(insns, .recvmsg, 3));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluateWithArg0(insns, .recvmsg, 4));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluate(insns, .openat));
}

test "buildHelper kills a refused io_uring call, because helpers refuse the whole family" {
    const insns = try buildHelper(std.testing.allocator, &.{.read}, &.{}, null);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluate(insns, .io_uring_setup));
}

test "no entry in the allow list can open a call a helper may not make" {
    const allowed = helper_refused_calls ++ refused_calls;
    const insns = try buildHelper(std.testing.allocator, &allowed, &.{3}, null);
    defer std.testing.allocator.free(insns);

    for (helper_refused_calls) |call| {
        try std.testing.expectEqual(RET_KILL_PROCESS, evaluateWithArg0(insns, call, 3));
    }
    for (refused_calls) |call| {
        const want = if (listed(&helper_refused_calls, call)) RET_KILL_PROCESS else RET_ERRNO_PERM;
        try std.testing.expectEqual(want, evaluateWithArg0(insns, call, 3));
    }
}

test "buildHelper kills ptrace, unshare, setns and execve even when listed" {
    const insns = try buildHelper(std.testing.allocator, &.{ .ptrace, .unshare, .setns, .execve }, &.{}, null);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluate(insns, .ptrace));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluate(insns, .unshare));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluate(insns, .setns));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluate(insns, .execve));
}

test "buildHelper allows mount, umount2, mkdirat and mknodat when listed" {
    const insns = try buildHelper(std.testing.allocator, &.{ .mount, .umount2, .mkdirat, .mknodat }, &.{}, null);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_ALLOW, evaluate(insns, .mount));
    try std.testing.expectEqual(RET_ALLOW, evaluate(insns, .umount2));
    try std.testing.expectEqual(RET_ALLOW, evaluate(insns, .mkdirat));
    try std.testing.expectEqual(RET_ALLOW, evaluate(insns, .mknodat));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluate(insns, .move_mount));
}

test "an unlisted mount is killed in a helper filter" {
    const insns = try buildHelper(std.testing.allocator, &.{.read}, &.{}, null);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluate(insns, .mount));
}

test "the sandboxed program filter still kills every blocked call" {
    const insns = try build(std.testing.allocator, .{});
    defer std.testing.allocator.free(insns);
    for (blocked_calls) |call| try std.testing.expectEqual(RET_KILL_PROCESS, evaluate(insns, call));
}

test "wait_calls holds ppoll" {
    try std.testing.expect(listed(wait_calls, .ppoll));
}

test "buildAllowlist allows its calls and kills the rest" {
    const insns = try buildAllowlist(std.testing.allocator, &.{.read});
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_ALLOW, evaluate(insns, .read));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluate(insns, .write));
}

test "buildHelper allows write on the ready fd and kills write on another fd" {
    const insns = try buildHelper(std.testing.allocator, &.{.exit_group}, &.{}, 9);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_ALLOW, evaluateWithArg0(insns, .write, 9));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluateWithArg0(insns, .write, 4));
    try std.testing.expectEqual(RET_ALLOW, evaluate(insns, .exit_group));
}

test "buildHelper allows close on the ready fd only" {
    const insns = try buildHelper(std.testing.allocator, &.{.exit_group}, &.{}, 9);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_ALLOW, evaluateWithArg0(insns, .close, 9));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluateWithArg0(insns, .close, 4));
}

test "buildHelper allows sendmsg on a kept fd next to the channel fd" {
    const insns = try buildHelper(std.testing.allocator, &.{}, &.{ 3, 6 }, null);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_ALLOW, evaluateWithArg0(insns, .sendmsg, 6));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluateWithArg0(insns, .sendmsg, 7));
}

test "buildHelper lets write on another fd fall through to the allowed list" {
    const insns = try buildHelper(std.testing.allocator, &.{.write}, &.{}, 9);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_ALLOW, evaluateWithArg0(insns, .write, 4));
    try std.testing.expectEqual(RET_ALLOW, evaluateWithArg0(insns, .write, 2));
    try std.testing.expectEqual(RET_ALLOW, evaluateWithArg0(insns, .write, 9));
}

test "buildHelper kills a vsock socket even when the caller allows socket" {
    const insns = try buildHelper(std.testing.allocator, &.{.socket}, &.{}, null);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluateWithArg0(insns, .socket, 40));
    try std.testing.expectEqual(RET_ALLOW, evaluateWithArg0(insns, .socket, 1));
}

test "buildHelper kills execveat with AT_EMPTY_PATH even when the caller allows it" {
    const insns = try buildHelper(std.testing.allocator, &.{.execveat}, &.{}, null);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluateWithArgs(insns, .execveat, .{ 0, 0, 0, 0, 0x1000, 0 }));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluateWithArgs(insns, .execveat, .{ 0, 0, 0, 0, 0, 0 }));
}

test "buildHelper refuses writable and executable memory even when the caller allows mprotect" {
    const insns = try buildHelper(std.testing.allocator, &.{.mprotect}, &.{}, null);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_ERRNO_PERM, evaluateWithArgs(insns, .mprotect, .{ 0, 0, 0x6, 0, 0, 0 }));
    try std.testing.expectEqual(RET_ALLOW, evaluateWithArgs(insns, .mprotect, .{ 0, 0, 0x1, 0, 0, 0 }));
}

test "buildHelper allows sendmsg and recvmsg on each named fd and kills the rest" {
    const insns = try buildHelper(std.testing.allocator, &.{}, &.{ 3, 5 }, null);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_ALLOW, evaluateWithArg0(insns, .sendmsg, 3));
    try std.testing.expectEqual(RET_ALLOW, evaluateWithArg0(insns, .sendmsg, 5));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluateWithArg0(insns, .sendmsg, 4));
    try std.testing.expectEqual(RET_ALLOW, evaluateWithArg0(insns, .recvmsg, 5));
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluateWithArg0(insns, .recvmsg, 4));
}

test "buildHelper kills sendmsg on an unnamed fd even when the caller allows sendmsg" {
    const insns = try buildHelper(std.testing.allocator, &.{.sendmsg}, &.{3}, null);
    defer std.testing.allocator.free(insns);
    try std.testing.expectEqual(RET_KILL_PROCESS, evaluateWithArg0(insns, .sendmsg, 4));
}

test "Diagnostic names the step and the errno" {
    const diag: Diagnostic = .{ .step = .no_new_privs, .errno = @backingInt(linux.E.PERM) };
    var buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{diag});
    try std.testing.expectEqualStrings("PERM at the no_new_privs step", text);
}

test "helper_refused_calls holds the credential calls that change groups and filesystem ids" {
    inline for (.{ "setgroups", "setfsuid", "setfsgid", "setgroups32", "setfsuid32", "setfsgid32" }) |name| {
        if (@hasField(linux.SYS, name)) {
            try std.testing.expect(listed(&helper_refused_calls, @field(linux.SYS, name)));
        }
    }
}
