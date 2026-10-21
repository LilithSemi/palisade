//! What the Linux driver promises, and what it can express.

const iface = @import("../Sandbox.zig");

pub const driver_name = "linux";

pub const guarantees: iface.Guarantees = iface.Guarantees.initMany(&.{
    .network_isolated,
    .signal_isolated,
    .ipc_isolated,
    .path_restricted,
    .syscall_restricted,
    .bind_mounts,
});

pub const expresses: iface.Expresses = .{
    .moved_paths = true,
    .scratch_area = true,
    .procfs = true,
    .cgroup_placement = true,
    .device_passthrough = true,
};
