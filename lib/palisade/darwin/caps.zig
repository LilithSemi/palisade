//! What the Darwin driver promises, and what it can express.

const iface = @import("../Sandbox.zig");

pub const driver_name = "darwin";

pub const guarantees: iface.Guarantees = iface.Guarantees.initMany(&.{
    .network_isolated,
    .signal_isolated,
    .ipc_isolated,
    .path_restricted,
});

pub const expresses: iface.Expresses = .{
    .moved_paths = false,
    .scratch_area = false,
    .procfs = false,
    .cgroup_placement = false,
    .device_passthrough = false,
};
