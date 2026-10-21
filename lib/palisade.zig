//! Process sandboxing for Linux and macOS.

const builtin = @import("builtin");

pub const linux = struct {
    pub const bpf = @import("palisade/linux/bpf.zig");
    pub const rlimits = @import("palisade/linux/rlimits.zig");
    pub const landlock = @import("palisade/linux/landlock.zig");
    pub const seccomp = @import("palisade/linux/seccomp.zig");
    pub const notify = @import("palisade/linux/notify.zig");
    pub const namespace = @import("palisade/linux/namespace.zig");
    pub const netns = @import("palisade/linux/netns.zig");
    pub const capabilities = @import("palisade/linux/capabilities.zig");
    pub const cgroup = @import("palisade/linux/cgroup.zig");
};

pub const Sandbox = @import("palisade/Sandbox.zig");

pub const darwin = struct {
    pub const limits = @import("palisade/darwin/limits.zig");
    pub const seatbelt = @import("palisade/darwin/seatbelt.zig");
};

test {
    _ = Sandbox;
    _ = @import("palisade/grants.zig");
    _ = linux.bpf;
    _ = linux.rlimits;
    _ = linux.landlock;
    _ = linux.seccomp;
    _ = linux.notify;
    _ = linux.namespace;
    _ = linux.netns;
    _ = linux.capabilities;
    _ = linux.cgroup;
    _ = @import("palisade/linux/afterfork.zig");
    if (builtin.os.tag == .linux) _ = @import("palisade/linux/driver.zig");
    _ = darwin.limits;
    _ = darwin.seatbelt;
    _ = @import("palisade/darwin/driver.zig");
    _ = @import("palisade/darwin/afterfork.zig");
}
