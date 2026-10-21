//! The things a forked child has to put right before it is confined, because
//! `fork` copies them from a parent that had other work.

const std = @import("std");
const linux = std.os.linux;

pub fn keepOnlyDescriptors(keep: []const i32) void {
    std.debug.assert(keep.len > 0 and keep.len <= 16);
    var sorted: [16]i32 = undefined;
    @memcpy(sorted[0..keep.len], keep);
    const held = sorted[0..keep.len];
    std.mem.sort(i32, held, {}, std.sort.asc(i32));

    const all: u32 = std.math.maxInt(u32);
    if (held[0] > 0) _ = linux.syscall3(.close_range, 0, @intCast(held[0] - 1), 0);
    for (held[1..], held[0 .. held.len - 1]) |high, low| {
        if (high > low + 1) {
            _ = linux.syscall3(.close_range, @intCast(low + 1), @intCast(high - 1), 0);
        }
    }
    _ = linux.syscall3(.close_range, @intCast(held[held.len - 1] + 1), all, 0);
}

const last_reset_signal: u32 = 31;

pub fn resetSignalState() void {
    // Every type here comes from std.os.linux. Its sigset_t has the size the
    // kernel expects.
    const to_default = linux.Sigaction{
        .handler = .{ .handler = linux.SIG.DFL },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    var number: u32 = 1;
    while (number <= last_reset_signal) : (number += 1) {
        const sig: linux.SIG = @fromBackingInt(@intCast(number));
        if (sig == .KILL or sig == .STOP) continue;
        _ = linux.sigaction(sig, &to_default, null);
    }

    const empty = std.mem.zeroes(linux.sigset_t);
    _ = linux.sigprocmask(linux.SIG.SETMASK, &empty, null);
}

test "a caught signal is back at its default after the reset" {
    const ignore = linux.Sigaction{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = linux.sigaction(.USR1, &ignore, null);
    resetSignalState();

    var current: linux.Sigaction = undefined;
    _ = linux.sigaction(.USR1, null, &current);
    try std.testing.expect(current.handler.handler == linux.SIG.DFL);
}
