//! The public interface of palisade: one driver per way of sandboxing.

const std = @import("std");
const builtin = @import("builtin");
const landlock = @import("linux/landlock.zig");
const namespace = @import("linux/namespace.zig");
const seccomp = @import("linux/seccomp.zig");
const notify = @import("linux/notify.zig");
const rlimits = @import("linux/rlimits.zig");
const netns = @import("linux/netns.zig");
const cgroup = @import("linux/cgroup.zig");
const grants = @import("grants.zig");
const seatbelt = @import("darwin/seatbelt.zig");

pub const Term = std.process.Child.Term;
pub const Mount = namespace.Mount;
pub const Scratch = namespace.Scratch;
pub const Substitution = namespace.Substitution;

pub const Rule = struct {
    path: []const u8,
    access: landlock.AccessFs,
};

pub const Network = union(enum) {
    none,
    host,
    isolated: netns.Params,
};

pub const Containment = union(enum) {
    /// Palisade makes a cgroup named `<name_prefix><pid>.<seq>`. See cgroup.validPrefix for the prefix rules.
    best_effort: BestEffort,
    supplied: Supplied,

    pub const BestEffort = struct {
        name_prefix: []const u8 = "palisade.",
    };

    pub const Supplied = struct {
        /// A descriptor, not a path, so a rename cannot retarget the child.
        fd: i32,
    };
};

pub const Limits = rlimits.Limits;

/// A channel lives until the sandboxed process exits. `.done` from a callback only closes that channel early.
/// Callbacks run in the caller's process. Write to the channel with MSG_NOSIGNAL, or a closed peer raises SIGPIPE in the caller.
pub const Channel = struct {
    ptr: *anyopaque,
    /// Requests from the sandbox side. Null for a channel only the host writes to.
    serve: ?Serve = null,
    /// Host-initiated traffic: Palisade polls `fd` and calls `drain` when it is readable.
    /// Drains have no cap: the sandbox cannot drive their rate.
    wakeup: ?Wakeup = null,
    /// True when the channel passes a real host socket into the child. Then the
    /// child may not call connect, so it cannot aim that socket at a new
    /// address. No default: each channel must state it.
    hands_host_descriptor: bool,

    pub const Serve = struct {
        call: *const fn (ptr: *anyopaque, channel_fd: i32) ServeResult,
        /// Calls before Palisade closes the channel. Bounds what the sandbox can ask for.
        max_requests: u32,
    };

    pub const Wakeup = struct {
        fd: i32,
        drain: *const fn (ptr: *anyopaque, channel_fd: i32) ServeResult,
    };

    pub const ServeResult = enum { more, done };
};

pub const max_channels = 8;

pub const max_owned_directories = 8;

pub fn channelFd(index: usize) i32 {
    std.debug.assert(index < max_channels);
    return 3 + @as(i32, @intCast(index));
}

pub const Helper = struct {
    ptr: *anyopaque,
    /// Runs in a forked process inside the sandbox namespaces, before pivot_root and without Landlock.
    /// Its filter and its capabilities are its only limits. Palisade installs the filter after it sets
    /// the user and capabilities, then calls run. `run` returns the exit status.
    run: *const fn (ptr: *anyopaque, channel_fd: ?i32) u8,
    /// Palisade calls prepare after it closes the other descriptors and before it sets the user,
    /// capabilities and filter. So prepare runs with the namespace root's capabilities and `allowed`
    /// does not limit it. Descriptors it opens stay open into run. False makes the helper fail.
    prepare: ?*const fn (ptr: *anyopaque, channel_fd: ?i32) bool = null,
    /// Calls the helper may make. Palisade adds the blocked and refused calls and the other rules of
    /// seccomp.buildHelper, so this list cannot open them. Write and close on the ready descriptor
    /// are always allowed. Append seccomp.wait_calls for a helper that waits on fds.
    /// The mount family is not in the escape set, so a helper that lists mount calls may mount.
    /// With unshare, setns and pivot_root killed, it cannot leave its namespaces.
    /// sendmsg and recvmsg work only on the channel and keep_fds. Other calls in allowed, such as
    /// sendto or write, are not limited by descriptor.
    allowed: []const std.os.linux.SYS,
    /// Descriptors the caller opened that the helper needs. Before run, Palisade closes every
    /// descriptor in the helper except stderr, the helper's channel at channelFd(channel), and
    /// keep_fds. These stay open and at the same numbers when run starts.
    keep_fds: []const i32 = &.{},
    /// One capability the helper keeps inside the sandbox's user namespace, for example CAP_SYS_ADMIN
    /// to mount. Null drops all.
    keep_capability: ?u32 = null,
    /// Index into `Config.channels`.
    channel: ?usize = null,
};

pub const Config = struct {
    /// Palisade never deletes a tree under root. It removes only the single entry a Substitution
    /// link replaces, entries of a directory it owns, and its own .palisade-* files. A failed setup
    /// can leave empty mount-point directories and .palisade-* files. The caller owns that cleanup.
    root: []const u8,
    cwd: []const u8,
    env: []const []const u8,
    mounts: []const namespace.Mount,
    rules: []const Rule,
    scratch: []const namespace.Scratch = &.{},
    /// A substituted path needs a matching Landlock rule in `rules`, or the program cannot read it.
    substitutions: []const namespace.Substitution = &.{},
    /// Palisade puts a tmpfs overlay on each target before it applies substitutions, so writes to the target go to memory.
    /// A text substitution writes into the tree under root, so put its target in an owned directory when that tree is a bind of the host.
    owned_directories: []const namespace.OwnedDirectory = &.{},
    /// The bytes a reader gets from a `.deny` mount.
    deny_notice: []const u8 = namespace.default_deny_notice,
    network: Network = .none,
    channels: []const Channel = &.{},
    helpers: []const Helper = &.{},
    /// On macOS only cpu_seconds, file_size_bytes and open_files apply.
    /// LimitsReport.limits shows what applied.
    limits: Limits = .{},
    containment: Containment = .{ .best_effort = .{} },
    seccomp_options: seccomp.Options = .{},
    stdin_fd: ?i32 = null,
    stdout_fd: i32 = 1,
    stderr_fd: i32 = 2,
    hide_helpers: bool = false,
    path_audit: bool = false,

    /// Copies every string into `allocator`. Channels and helpers are copied as new slices, but their
    /// `ptr` targets are the caller's and must outlive the copy.
    pub fn copy(self: Config, allocator: std.mem.Allocator) std.mem.Allocator.Error!Config {
        var out = self;
        out.root = try allocator.dupe(u8, self.root);
        out.cwd = try allocator.dupe(u8, self.cwd);
        out.env = try copyStrings(allocator, self.env);
        out.deny_notice = try allocator.dupe(u8, self.deny_notice);

        const mounts = try allocator.alloc(namespace.Mount, self.mounts.len);
        for (self.mounts, mounts) |from, *to| {
            to.* = switch (from) {
                .bind => |bind| .{ .bind = .{
                    .source = try allocator.dupe(u8, bind.source),
                    .target = try allocator.dupe(u8, bind.target),
                    .read_only = bind.read_only,
                } },
                .overlay => |overlay| .{ .overlay = .{
                    .lower = try allocator.dupe(u8, overlay.lower),
                    .upper = try allocator.dupe(u8, overlay.upper),
                    .work = try allocator.dupe(u8, overlay.work),
                    .target = try allocator.dupe(u8, overlay.target),
                } },
                .proc => |proc| .{ .proc = .{ .target = try allocator.dupe(u8, proc.target) } },
                .deny => |deny| .{ .deny = .{ .target = try allocator.dupe(u8, deny.target) } },
            };
        }
        out.mounts = mounts;

        const rules = try allocator.alloc(Rule, self.rules.len);
        for (self.rules, rules) |from, *to| {
            to.* = .{ .path = try allocator.dupe(u8, from.path), .access = from.access };
        }
        out.rules = rules;

        const scratch = try allocator.alloc(namespace.Scratch, self.scratch.len);
        for (self.scratch, scratch) |from, *to| {
            to.* = .{ .target = try allocator.dupe(u8, from.target) };
        }
        out.scratch = scratch;

        const substitutions = try allocator.alloc(namespace.Substitution, self.substitutions.len);
        for (self.substitutions, substitutions) |from, *to| {
            to.* = switch (from) {
                .text => |text| .{ .text = .{
                    .target = try allocator.dupe(u8, text.target),
                    .contents = try allocator.dupe(u8, text.contents),
                } },
                .link => |link| .{ .link = .{
                    .target = try allocator.dupe(u8, link.target),
                    .link_to = try allocator.dupe(u8, link.link_to),
                } },
                .hide => |path| .{ .hide = try allocator.dupe(u8, path) },
            };
        }
        out.substitutions = substitutions;

        const owned_directories = try allocator.alloc(namespace.OwnedDirectory, self.owned_directories.len);
        for (self.owned_directories, owned_directories) |from, *to| {
            to.* = .{
                .target = try allocator.dupe(u8, from.target),
                .remove = try copyStrings(allocator, from.remove),
            };
        }
        out.owned_directories = owned_directories;

        out.network = switch (self.network) {
            .none, .host => self.network,
            .isolated => |params| blk: {
                var copied = params;
                copied.device_name = try allocator.dupe(u8, params.device_name);
                break :blk .{ .isolated = copied };
            },
        };

        out.containment = switch (self.containment) {
            .best_effort => |best| .{ .best_effort = .{
                .name_prefix = try allocator.dupe(u8, best.name_prefix),
            } },
            .supplied => self.containment,
        };

        out.channels = try allocator.dupe(Channel, self.channels);
        const helpers = try allocator.dupe(Helper, self.helpers);
        for (helpers) |*helper| {
            helper.allowed = try allocator.dupe(std.os.linux.SYS, helper.allowed);
            helper.keep_fds = try allocator.dupe(i32, helper.keep_fds);
        }
        out.helpers = helpers;
        return out;
    }
};

pub fn blocksConnect(config: Config) bool {
    for (config.channels) |channel| {
        if (channel.hands_host_descriptor) return true;
    }
    return false;
}

pub const ConfigError = error{
    TooManyChannels,
    ChannelWithoutIsolation,
    HelperChannelOutOfRange,
    InvalidCgroupPrefix,
    ChannelsDisagreeOnDescriptor,
    ChannelWithoutCallback,
    ChannelWithoutBudget,
    HelperAllowsEscape,
    HelperCapabilityInvalid,
    HelperFdInvalid,
    OwnedDirectoryInvalid,
};

pub const max_keep_fds = 8;

/// The descriptor a helper sends its ready byte on. It is fixed so the filter can name it
/// before the first fork.
pub const helper_ready_fd: i32 = 3 + @as(i32, max_channels);

fn keepFdsValid(helper: Helper, channel_count: usize) bool {
    if (helper.keep_fds.len > max_keep_fds) return false;
    for (helper.keep_fds, 0..) |fd, i| {
        if (fd < 3 or fd == helper_ready_fd) return false;
        for (0..channel_count) |index| if (fd == channelFd(index)) return false;
        if (std.mem.indexOfScalar(i32, helper.keep_fds[0..i], fd) != null) return false;
    }
    return true;
}

fn ownedPathValid(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/') return false;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| if (std.mem.eql(u8, part, "..")) return false;
    return true;
}

/// Refuses a config that no driver can run safely.
pub fn validate(config: Config) ConfigError!void {
    if (config.containment == .best_effort and
        !cgroup.validPrefix(config.containment.best_effort.name_prefix))
    {
        return error.InvalidCgroupPrefix;
    }
    if (config.channels.len > max_channels) return error.TooManyChannels;
    if (config.owned_directories.len > max_owned_directories) return error.OwnedDirectoryInvalid;
    for (config.owned_directories) |owned| {
        if (!ownedPathValid(owned.target) or std.mem.eql(u8, owned.target, "/")) return error.OwnedDirectoryInvalid;
        for (owned.remove) |name| {
            if (!ownedPathValid(name)) return error.OwnedDirectoryInvalid;
            if (name.len <= owned.target.len + 1 or
                !std.mem.startsWith(u8, name, owned.target) or
                name[owned.target.len] != '/') return error.OwnedDirectoryInvalid;
        }
    }
    if (config.channels.len > 0 or config.helpers.len > 0) {
        if (config.network != .isolated) return error.ChannelWithoutIsolation;
    }
    for (config.channels) |channel| {
        if (channel.hands_host_descriptor != config.channels[0].hands_host_descriptor) {
            return error.ChannelsDisagreeOnDescriptor;
        }
        if (channel.serve == null and channel.wakeup == null) return error.ChannelWithoutCallback;
        if (channel.serve) |serve| {
            if (serve.max_requests == 0) return error.ChannelWithoutBudget;
        }
    }
    for (config.helpers) |helper| {
        if (helper.channel) |index| {
            if (index >= config.channels.len) return error.HelperChannelOutOfRange;
        }
        if (!keepFdsValid(helper, config.channels.len)) return error.HelperFdInvalid;
        if (helper.keep_capability) |capability| {
            if (capability > std.os.linux.CAP.LAST_CAP) return error.HelperCapabilityInvalid;
        }
        for (helper.allowed) |call| {
            for (seccomp.helper_refused_calls) |refused| {
                if (call == refused) return error.HelperAllowsEscape;
            }
        }
    }
}

/// Where a `Config`'s mount list and rule list disagree about reach.
pub const LayerGap = union(enum) {
    rule_outside_mounts: []const u8,
    mount_without_rule: []const u8,

    pub fn path(self: LayerGap) []const u8 {
        return switch (self) {
            .rule_outside_mounts, .mount_without_rule => |value| value,
        };
    }

    pub fn format(self: LayerGap, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        return switch (self) {
            .rule_outside_mounts => |value| writer.print(
                "landlock rule {s} names a path the mount set does not hold",
                .{value},
            ),
            .mount_without_rule => |value| writer.print(
                "mount {s} has no landlock rule, so it is present and unreachable",
                .{value},
            ),
        };
    }
};

/// Does not report `config.root`, which only Landlock refuses.
pub fn firstGap(config: Config) ?LayerGap {
    for (config.rules) |rule| {
        if (!mountSetHolds(config, rule.path)) return .{ .rule_outside_mounts = rule.path };
    }
    for (config.mounts) |mount| {
        const target = mountTarget(mount) orelse continue;
        if (!ruleSetHolds(config, target)) return .{ .mount_without_rule = target };
    }
    for (config.scratch) |area| {
        if (!ruleSetHolds(config, area.target)) return .{ .mount_without_rule = area.target };
    }
    return null;
}

fn mountTarget(mount: namespace.Mount) ?[]const u8 {
    return switch (mount) {
        .bind => |bind| bind.target,
        .overlay => |overlay| overlay.target,
        .proc => |proc| proc.target,
        .deny => null,
    };
}

fn mountSetHolds(config: Config, target_path: []const u8) bool {
    for (config.mounts) |mount| {
        const target = mountTarget(mount) orelse continue;
        if (grants.holds(target, target_path)) return true;
    }
    for (config.scratch) |area| {
        if (grants.holds(area.target, target_path)) return true;
    }
    return false;
}

fn ruleSetHolds(config: Config, target_path: []const u8) bool {
    for (config.rules) |rule| {
        if (grants.holds(rule.path, target_path)) return true;
    }
    return false;
}

/// Deny targets are excluded, so a denial under a granted tree still holds.
pub fn grantPrefixes(
    allocator: std.mem.Allocator,
    config: Config,
) std.mem.Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(allocator);
    try out.ensureTotalCapacityPrecise(allocator, config.mounts.len + config.scratch.len);
    for (config.mounts) |mount| {
        const target = mountTarget(mount) orelse continue;
        out.appendAssumeCapacity(target);
    }
    for (config.scratch) |area| out.appendAssumeCapacity(area.target);
    return out.toOwnedSlice(allocator);
}

pub fn copyStrings(
    allocator: std.mem.Allocator,
    from: []const []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    const to = try allocator.alloc([]const u8, from.len);
    for (from, to) |one, *slot| slot.* = try allocator.dupe(u8, one);
    return to;
}

pub fn resolvedPath(io: std.Io, path: []const u8, buffer: []u8) []const u8 {
    if (expresses.moved_paths) return path;
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{}) catch return path;
    defer dir.close(io);
    const length = dir.realPath(io, buffer) catch return path;
    return buffer[0..length];
}

/// What a driver can express, as opposed to the Guarantee set it promises.
pub const Expresses = struct {
    moved_paths: bool,
    scratch_area: bool,
    procfs: bool,
    cgroup_placement: bool,
    device_passthrough: bool,
};

pub const expresses = struct {
    pub const moved_paths = native.expresses.moved_paths;

    pub const scratch_area = native.expresses.scratch_area;

    pub const procfs = native.expresses.procfs;

    pub const cgroup_placement = native.expresses.cgroup_placement;

    pub const device_passthrough = native.expresses.device_passthrough;
};

/// `memory.max` kills with `SIGKILL`, the same signal a cancelled call gets.
pub const Unsupported = rlimits.Unsupported;

pub const LimitsReport = struct {
    limits: Limits = .{},
    /// Limits the caller asked for that this platform cannot apply.
    unsupported: Unsupported = .{},
    cgroup: cgroup.Support = .off,
    /// False before kernel 5.14, where `RLIMIT_NPROC` counts all user processes.
    nproc_applied: bool = false,
    events: cgroup.Events = .{},
    /// Read from the filesystem itself: nothing in the kernel counts a full tmpfs.
    scratch_full: bool = false,
    /// Inferred: the kernel keeps no record of a full area.
    killed_by: ?rlimits.Diagnostic.Which = null,

    pub fn killedText(self: LimitsReport, buffer: []u8) ?[]const u8 {
        const which = self.killed_by orelse return null;

        if (which == .scratch_space) {
            if (self.limits.scratch_bytes) |number| {
                return std.fmt.bufPrint(
                    buffer,
                    "the program filled the sandbox's own scratch area, which is capped at {d} bytes. The machine's own disk is not full",
                    .{number},
                ) catch null;
            }
            return std.fmt.bufPrint(
                buffer,
                "the program filled the sandbox's own scratch area. The machine's own disk is not full",
                .{},
            ) catch null;
        }

        const value: ?u64 = switch (which) {
            .memory => self.limits.memory_bytes,
            .mapped_memory => self.limits.mapped_memory_bytes,
            .cpu_time => self.limits.cpu_seconds,
            .file_size => self.limits.file_size_bytes,
            .processes => self.limits.processes,
            .open_files => self.limits.open_files,
            .core_dump, .scratch_space => null,
        };
        const unit: []const u8 = switch (which) {
            .memory, .mapped_memory, .file_size => " bytes",
            .cpu_time => " seconds",
            else => "",
        };
        if (value) |number| {
            return std.fmt.bufPrint(
                buffer,
                "the program was stopped by the limit on {s}, which is {d}{s}",
                .{ which.text(), number, unit },
            ) catch null;
        }
        return std.fmt.bufPrint(
            buffer,
            "the program was stopped by the limit on {s}",
            .{which.text()},
        ) catch null;
    }
};

pub const LayerProcess = enum {
    sandboxed,
    supervisor,

    pub fn wireName(self: LayerProcess) []const u8 {
        return switch (self) {
            .sandboxed => "sandboxed",
            .supervisor => "supervisor",
        };
    }
};

pub const LayerName = enum {
    mount_tree,
    pivot_root,
    capabilities,
    landlock,
    session_keyring,
    seccomp,

    pub fn wireName(self: LayerName) []const u8 {
        return switch (self) {
            .mount_tree => "mount_tree",
            .pivot_root => "pivot_root",
            .capabilities => "capabilities",
            .landlock => "landlock",
            .session_keyring => "session_keyring",
            .seccomp => "seccomp",
        };
    }
};

pub const FailMode = enum {
    closed,
    open,
};

/// What happens when `layer` fails for `process`.
pub fn failModeFor(process: LayerProcess, layer: LayerName) ?FailMode {
    return switch (process) {
        .sandboxed => .closed,
        .supervisor => switch (layer) {
            .capabilities, .landlock, .seccomp => .open,
            .mount_tree, .pivot_root, .session_keyring => null,
        },
    };
}

pub const SupervisorAudit = struct {
    pub const process_name = LayerProcess.supervisor.wireName();

    layers: std.EnumArray(LayerName, Counters) = .initFill(.{}),

    pub const Counters = struct {
        confined: std.atomic.Value(u64) = .init(0),
        unconfined: std.atomic.Value(u64) = .init(0),
        /// Zero is not a claim, since a cancelled call can kill the supervisor first.
        unreported: std.atomic.Value(u64) = .init(0),
        first_fault: std.atomic.Value(u8) = .init(0),
    };

    pub const Fault = enum(u8) {
        /// The kernel answered the two processes differently for the same input.
        not_supported = 1,
        no_new_privs_refused = 2,
        not_permitted = 3,
        rejected = 4,
        unexpected = 5,
    };

    pub const Outcome = union(enum) {
        on,
        off: Fault,
        unsaid,
    };

    pub fn record(self: *SupervisorAudit, layer: LayerName, outcome: Outcome) void {
        const slot = self.layers.getPtr(layer);
        switch (outcome) {
            .on => _ = slot.confined.fetchAdd(1, .monotonic),
            .unsaid => _ = slot.unreported.fetchAdd(1, .monotonic),
            .off => |fault| {
                _ = slot.unconfined.fetchAdd(1, .monotonic);
                _ = slot.first_fault.cmpxchgStrong(0, @backingInt(fault), .monotonic, .monotonic);
            },
        }
    }

    pub fn counts(self: *const SupervisorAudit, layer: LayerName) Counts {
        const slot = self.layers.getPtrConst(layer);
        const raw = slot.first_fault.load(.monotonic);
        return .{
            .confined = slot.confined.load(.monotonic),
            .unconfined = slot.unconfined.load(.monotonic),
            .unreported = slot.unreported.load(.monotonic),
            .first_fault = std.enums.fromInt(Fault, raw),
        };
    }

    pub const Counts = struct {
        confined: u64,
        unconfined: u64,
        unreported: u64,
        first_fault: ?Fault,
    };
};

pub const SyscallAudit = struct {
    pub const mechanism_name = "seccomp_user_notif";

    observed: std.atomic.Value(u64) = .init(0),
    unobserved: std.atomic.Value(u64) = .init(0),
    calls: [notify.call_count]std.atomic.Value(u64) = @splat(.init(0)),

    paths: PathTotals = .{},

    pub const PathTotals = struct {
        lock: Lock = .{},
        readers_unreported: u64 = 0,
        readers_absent: u64 = 0,
        seen: notify.PathRecord = .{},
    };

    pub const Outcome = union(enum) {
        observed: notify.Counts,
        unobserved,
    };

    pub fn record(self: *SyscallAudit, outcome: Outcome) void {
        switch (outcome) {
            .unobserved => _ = self.unobserved.fetchAdd(1, .monotonic),
            .observed => |made| {
                _ = self.observed.fetchAdd(1, .monotonic);
                for (made, &self.calls) |count, *total| {
                    _ = total.fetchAdd(count, .monotonic);
                }
            },
        }
    }

    /// Plain atomics, not `std.Io.Mutex`: `spawn` has no `Io` to give it. Never held across a system call.
    pub const Lock = struct {
        held: std.atomic.Value(bool) = .init(false),

        fn lock(self: *Lock) void {
            while (self.held.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
                std.Thread.yield() catch std.atomic.spinLoopHint();
            }
        }

        fn unlock(self: *Lock) void {
            self.held.store(false, .release);
        }
    };

    /// Everything read out of `seen` is untrusted: a reader process wrote it.
    pub fn recordPaths(self: *SyscallAudit, seen: *const notify.PathRecord) void {
        self.paths.lock.lock();
        defer self.paths.lock.unlock();

        if (seen.reader_unreported != 0) self.paths.readers_unreported +|= 1;
        if (seen.ready == 0) self.paths.readers_absent +|= 1;

        const into = &self.paths.seen;
        for (0..notify.call_count) |slot| {
            into.granted[slot] +|= seen.granted[slot];
            into.ungranted[slot] +|= seen.ungranted[slot];
            into.ungranted_unnamed[slot] +|= seen.ungranted_unnamed[slot];
            into.relative[slot] +|= seen.relative[slot];
            into.unread[slot] +|= seen.unread[slot];
            into.truncated[slot] +|= seen.truncated[slot];
        }

        var slot: u32 = 0;
        while (slot < @min(seen.kept, notify.kept_path_cap)) : (slot += 1) {
            notify.keepName(into, seen.name_call[slot], seen.name(slot), seen.name_hits[slot]);
        }
    }

    pub fn counts(self: *const SyscallAudit) Counts {
        var out: Counts = .{
            .observed = self.observed.load(.monotonic),
            .unobserved = self.unobserved.load(.monotonic),
            .calls = notify.empty_counts,
        };
        for (&self.calls, &out.calls) |*total, *slot| slot.* = total.load(.monotonic);
        return out;
    }

    pub const Counts = struct {
        observed: u64,
        unobserved: u64,
        calls: notify.Counts,
    };

    pub const name_cap = notify.kept_path_cap;

    /// Names point into this audit's own storage, and a call in flight can still add one.
    pub fn pathCounts(self: *SyscallAudit) PathCounts {
        self.paths.lock.lock();
        defer self.paths.lock.unlock();

        const seen = &self.paths.seen;
        var out: PathCounts = .{
            .readers_unreported = self.paths.readers_unreported,
            .readers_absent = self.paths.readers_absent,
            .granted = seen.granted,
            .ungranted = seen.ungranted,
            .ungranted_unnamed = seen.ungranted_unnamed,
            .relative = seen.relative,
            .unread = seen.unread,
            .truncated = seen.truncated,
            .kept = @min(seen.kept, name_cap),
            .name_call = seen.name_call,
            .names = @splat(&.{}),
        };
        for (&out.names, 0..) |*slot, index| slot.* = seen.name(index);
        return out;
    }

    pub const PathCounts = struct {
        readers_unreported: u64,
        readers_absent: u64,
        granted: notify.Counts,
        ungranted: notify.Counts,
        ungranted_unnamed: notify.Counts,
        relative: notify.Counts,
        unread: notify.Counts,
        truncated: notify.Counts,
        kept: u32,
        name_call: [name_cap]u32,
        names: [name_cap][]const u8,

        pub fn empty(self: PathCounts) bool {
            if (self.kept != 0) return false;
            if (self.readers_unreported != 0 or self.readers_absent != 0) return false;
            for (0..notify.call_count) |slot| {
                if (self.granted[slot] != 0 or self.ungranted[slot] != 0) return false;
                if (self.ungranted_unnamed[slot] != 0 or self.relative[slot] != 0) return false;
                if (self.unread[slot] != 0 or self.truncated[slot] != 0) return false;
            }
            return true;
        }
    };
};

pub const Guarantee = enum {
    network_isolated,
    /// A PID namespace alone does not give this: `kill(0, sig)` can still reach a process outside it.
    signal_isolated,
    ipc_isolated,
    path_restricted,
    syscall_restricted,
    /// Darwin has none of this. The gap is permanent: macOS has no bind mount.
    bind_mounts,
};

pub const Guarantees = std.EnumSet(Guarantee);

pub const SetupError = error{
    StdinRedirectFailed,
    ProcessGroupFailed,
    CgroupJoinFailed,
    ResourceLimitFailed,
    CloseFdsFailed,
    NamespaceFailed,
    ScratchMountFailed,
    MountTreeFailed,
    PivotFailed,
    CapabilitiesFailed,
    LandlockInitFailed,
    LandlockRuleFailed,
    LandlockRestrictFailed,
    SessionKeyringFailed,
    SeccompInstallFailed,
    NotifyHandoverFailed,
    ForkFailed,
    PdeathsigSetupFailed,
    ExecFailed,
    HelperFailed,
    ChannelFailed,
};

pub const SpawnError = error{
    LandlockUnavailable,
    /// A descriptor named in `Helper.keep_fds` is not open.
    HelperFdClosed,
    UntrustedSetupReport,
    Unexpected,
    NoMountNamespace,
    /// Refused, never degraded: writing `cgroup.procs` after the fork leaves a window outside the cgroup.
    CgroupPlacementUnsupported,
    CgroupPlacementRefused,
    /// For a driver that runs the call off this host.
    RemoteRefused,
    /// For a driver that runs the call off this host.
    RemoteCannotPlacePath,
    /// For a driver that runs the call off this host.
    RemoteCannotExpress,
    /// For a driver that runs the call off this host.
    RemoteGone,
} || SetupError || ConfigError || std.mem.Allocator.Error;

/// A right is masked out of every rule, with no error, when the running kernel's ABI lacks it.
pub const LandlockReport = struct {
    abi: i32,
    features: landlock.Features,
};

pub const Reports = struct {
    landlock: ?*LandlockReport = null,
    limits: ?*LimitsReport = null,
    supervisor_audit: ?*SupervisorAudit = null,
    syscall_audit: ?*SyscallAudit = null,
};

pub const Run = struct {
    handle: ?*Handle = null,
    reports: Reports = .{},
};

/// Caller-owned. Its address must stay fixed from before `spawn` until
/// `spawn` returns. The driver stores pid and fd with release order while
/// `spawn` runs, so another thread can read them through `pid` and `fd`.
pub const Handle = struct {
    raw_pid: i32 = 0,
    raw_fd: i32 = -1,
    /// Set by `Driver.spawn` before the driver can publish a pid.
    driver: Driver = no_driver,

    /// A driver that runs the call off this host stores this pid.
    pub const elsewhere: i32 = -1;

    pub fn pid(self: *const Handle) ?i32 {
        const value = @atomicLoad(i32, &self.raw_pid, .acquire);
        return if (value == 0) null else value;
    }

    pub fn fd(self: *const Handle) ?i32 {
        if (self.pid() == null) return null;
        const value = @atomicLoad(i32, &self.raw_fd, .acquire);
        return if (value < 0) null else value;
    }

    /// The fd goes first and the pid last, so a reader that sees a nonzero pid also sees the fd.
    pub fn publish(self: *Handle, new_pid: i32, new_fd: i32) void {
        std.debug.assert(new_pid != 0);
        @atomicStore(i32, &self.raw_fd, new_fd, .release);
        @atomicStore(i32, &self.raw_pid, new_pid, .release);
    }

    pub fn signal(self: *const Handle, sig: u32) SignalError!void {
        _ = self.pid() orelse return error.NoHandle;
        return self.driver.signal(self, sig);
    }

    pub fn close(self: *Handle) void {
        if (self.pid() == null) return;
        self.driver.close(self);
    }
};

pub const SignalError = error{
    Gone,
    NoHandle,
    Unexpected,
};

pub const KeyringError = error{ JoinFailed, Refused };

/// A driver is a table of functions over one state pointer. Each driver names what it promises and what it can express.
pub const Driver = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    name: []const u8,
    guarantees: Guarantees,
    expresses: Expresses,

    pub const VTable = struct {
        spawn: *const fn (
            ptr: *anyopaque,
            gpa: std.mem.Allocator,
            config: Config,
            argv: []const []const u8,
            run: Run,
        ) SpawnError!Term,
        signal: *const fn (ptr: *anyopaque, handle: *const Handle, sig: u32) SignalError!void,
        close: *const fn (ptr: *anyopaque, handle: *Handle) void,
        joinFreshSessionKeyring: *const fn (ptr: *anyopaque, stderr_fd: i32) KeyringError!void,
        whyLast: *const fn (ptr: *anyopaque) ?[]const u8,
    };

    /// Validates the config, then records this driver on the handle before it can publish a pid.
    pub fn spawn(
        self: Driver,
        gpa: std.mem.Allocator,
        config: Config,
        argv: []const []const u8,
        run: Run,
    ) SpawnError!Term {
        try validate(config);
        if (run.handle) |handle| handle.driver = self;
        return self.vtable.spawn(self.ptr, gpa, config, argv, run);
    }

    pub fn signal(self: Driver, handle: *const Handle, sig: u32) SignalError!void {
        return self.vtable.signal(self.ptr, handle, sig);
    }

    pub fn close(self: Driver, handle: *Handle) void {
        return self.vtable.close(self.ptr, handle);
    }

    pub fn joinFreshSessionKeyring(self: Driver, stderr_fd: i32) KeyringError!void {
        return self.vtable.joinFreshSessionKeyring(self.ptr, stderr_fd);
    }

    pub fn whyLast(self: Driver) ?[]const u8 {
        return self.vtable.whyLast(self.ptr);
    }
};

var no_state: u8 = 0;

/// The driver of a handle that no spawn has filled.
const no_driver: Driver = .{
    .ptr = &no_state,
    .vtable = &NoDriver.table,
    .name = "none",
    .guarantees = Guarantees.initMany(&.{}),
    .expresses = .{
        .moved_paths = false,
        .scratch_area = false,
        .procfs = false,
        .cgroup_placement = false,
        .device_passthrough = false,
    },
};

const NoDriver = struct {
    fn spawnFn(ptr: *anyopaque, gpa: std.mem.Allocator, config: Config, argv: []const []const u8, run: Run) SpawnError!Term {
        _ = .{ ptr, gpa, config, argv, run };
        return error.Unexpected;
    }

    fn signalFn(ptr: *anyopaque, handle: *const Handle, sig: u32) SignalError!void {
        _ = .{ ptr, handle, sig };
        return error.NoHandle;
    }

    fn closeFn(ptr: *anyopaque, handle: *Handle) void {
        _ = .{ ptr, handle };
    }

    fn joinFn(ptr: *anyopaque, stderr_fd: i32) KeyringError!void {
        _ = .{ ptr, stderr_fd };
        return error.Refused;
    }

    fn whyFn(ptr: *anyopaque) ?[]const u8 {
        _ = ptr;
        return null;
    }

    const table: Driver.VTable = .{
        .spawn = spawnFn,
        .signal = signalFn,
        .close = closeFn,
        .joinFreshSessionKeyring = joinFn,
        .whyLast = whyFn,
    };
};

pub fn driverOf(comptime module: type) Driver {
    const wrapped = struct {
        fn spawn(
            ptr: *anyopaque,
            gpa: std.mem.Allocator,
            config: Config,
            argv: []const []const u8,
            run: Run,
        ) SpawnError!Term {
            _ = ptr;
            return module.spawn(gpa, config, argv, run);
        }

        fn signal(ptr: *anyopaque, handle: *const Handle, sig: u32) SignalError!void {
            _ = ptr;
            return module.signal(handle, sig);
        }

        fn close(ptr: *anyopaque, handle: *Handle) void {
            _ = ptr;
            module.close(handle);
        }

        fn joinFreshSessionKeyring(ptr: *anyopaque, stderr_fd: i32) KeyringError!void {
            _ = ptr;
            return module.joinFreshSessionKeyring(stderr_fd);
        }

        fn whyLast(ptr: *anyopaque) ?[]const u8 {
            _ = ptr;
            return null;
        }

        const table: Driver.VTable = .{
            .spawn = @This().spawn,
            .signal = @This().signal,
            .close = @This().close,
            .joinFreshSessionKeyring = @This().joinFreshSessionKeyring,
            .whyLast = @This().whyLast,
        };
    };
    return .{
        .ptr = &no_state,
        .vtable = &wrapped.table,
        .name = module.driver_name,
        .guarantees = module.guarantees,
        .expresses = module.expresses,
    };
}

const native_module = switch (builtin.os.tag) {
    .linux => @import("linux/driver.zig"),
    .macos => @import("darwin/driver.zig"),
    else => @compileError("palisade: no driver for target os " ++ @tagName(builtin.os.tag)),
};

pub const native: Driver = driverOf(native_module);

pub const Nesting = seatbelt.Nesting;
pub const default_mach_services = seatbelt.default_mach_services;

pub fn confinedAlready() bool {
    return seatbelt.confinedAlready();
}

pub fn nesting() Nesting {
    return seatbelt.nesting();
}

/// What a Config asks for that the running driver cannot give. Only macOS has gaps.
pub const Inexpressible = enum {
    root_is_not_the_real_root,
    bind_moves_a_path,
    overlay_mount,
    proc_mount,
    scratch_area,
    channels,
    substitution,
    owned_directory,

    pub fn text(self: Inexpressible) []const u8 {
        return switch (self) {
            .root_is_not_the_real_root => "a root of its own, and macos cannot pivot into one",
            .bind_moves_a_path => "a path to appear somewhere else, and macos has no bind mount",
            .overlay_mount => "an overlay filesystem, and macos has none",
            .proc_mount => "a procfs of its own, and macos has no procfs",
            .scratch_area => "a capped writable area, and an ordinary user on macos cannot mount a filesystem",
            .channels => "channels or helpers, and macos has no network namespace to give them",
            .substitution => "a file swapped for other content, and macos cannot mount over a path",
            .owned_directory => "a directory owned by the sandbox, and macos cannot mount over a path",
        };
    }
};

pub fn inexpressible(config: Config) ?Inexpressible {
    if (builtin.os.tag != .macos) return null;
    return inexpressibleOnDarwin(config);
}

/// What macOS would refuse, whatever the host is.
pub fn inexpressibleOnDarwin(config: Config) ?Inexpressible {
    if (!std.mem.eql(u8, config.root, "/")) return .root_is_not_the_real_root;
    if (config.scratch.len != 0) return .scratch_area;
    if (config.channels.len != 0 or config.helpers.len != 0) return .channels;
    if (config.substitutions.len != 0) return .substitution;
    if (config.owned_directories.len != 0) return .owned_directory;
    for (config.mounts) |mount| switch (mount) {
        .bind => |bind| if (!std.mem.eql(u8, bind.source, bind.target)) return .bind_moves_a_path,
        .overlay => return .overlay_mount,
        .proc => return .proc_mount,
        .deny => {},
    };
    return null;
}

pub const guarantees: Guarantees = native.guarantees;

pub fn spawn(
    gpa: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    run: Run,
) SpawnError!Term {
    return native.spawn(gpa, config, argv, run);
}

pub fn spawnWith(
    driver: Driver,
    gpa: std.mem.Allocator,
    config: Config,
    argv: []const []const u8,
    run: Run,
) SpawnError!Term {
    return driver.spawn(gpa, config, argv, run);
}

const test_params: netns.Params = .{
    .device_name = "sbx0",
    .address4 = .{ 10, 0, 0, 1 },
    .prefix4 = 24,
    .address6 = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    .prefix6 = 64,
};

fn testServe(_: *anyopaque, _: i32) Channel.ServeResult {
    return .done;
}

fn testRun(_: *anyopaque, _: ?i32) u8 {
    return 0;
}

fn testDrain(_: *anyopaque, _: i32) Channel.ServeResult {
    return .more;
}

test "validate refuses a channel without an isolated network" {
    var dummy: u8 = 0;
    const channel: Channel = .{ .ptr = &dummy, .serve = .{ .call = testServe, .max_requests = 1 }, .hands_host_descriptor = false };
    const config: Config = .{ .root = "/", .cwd = "/", .env = &.{}, .mounts = &.{}, .rules = &.{}, .channels = &.{channel} };
    try std.testing.expectError(error.ChannelWithoutIsolation, validate(config));
}

test "validate accepts a plain config" {
    const config: Config = .{ .root = "/", .cwd = "/", .env = &.{}, .mounts = &.{}, .rules = &.{} };
    try validate(config);
}

fn ownedConfig(owned: []const namespace.OwnedDirectory) Config {
    return .{ .root = "/", .cwd = "/", .env = &.{}, .mounts = &.{}, .rules = &.{}, .owned_directories = owned };
}

test "validate accepts an owned directory with removals under its target" {
    try validate(ownedConfig(&.{.{ .target = "/etc", .remove = &.{ "/etc/hosts", "/etc/ssl/certs" } }}));
}

test "validate refuses an owned directory target that is relative, the root, or has a parent component" {
    for ([_][]const u8{ "etc", "/", "/etc/../root", "/..", "" }) |target| {
        try std.testing.expectError(
            error.OwnedDirectoryInvalid,
            validate(ownedConfig(&.{.{ .target = target }})),
        );
    }
}

test "validate refuses a removal outside the target of its owned directory" {
    for ([_][]const u8{ "/etc", "/etcetera/hosts", "/var/hosts", "/etc/", "/etc/../hosts" }) |name| {
        try std.testing.expectError(
            error.OwnedDirectoryInvalid,
            validate(ownedConfig(&.{.{ .target = "/etc", .remove = &.{name} }})),
        );
    }
}

test "validate refuses more owned directories than max_owned_directories" {
    var many: [max_owned_directories + 1]namespace.OwnedDirectory = undefined;
    @memset(&many, .{ .target = "/etc" });
    try std.testing.expectError(error.OwnedDirectoryInvalid, validate(ownedConfig(&many)));
    try validate(ownedConfig(many[0..max_owned_directories]));
}

test "validate refuses a cgroup prefix that is empty or has no dot" {
    for ([_][]const u8{ "", "palisade" }) |prefix| {
        const config: Config = .{
            .root = "/",
            .cwd = "/",
            .env = &.{},
            .mounts = &.{},
            .rules = &.{},
            .containment = .{ .best_effort = .{ .name_prefix = prefix } },
        };
        try std.testing.expectError(error.InvalidCgroupPrefix, validate(config));
    }
}

test "validate refuses more channels than max_channels" {
    var dummy: u8 = 0;
    const channel: Channel = .{ .ptr = &dummy, .serve = .{ .call = testServe, .max_requests = 1 }, .hands_host_descriptor = false };
    var many: [max_channels + 1]Channel = undefined;
    @memset(&many, channel);
    const config: Config = .{
        .root = "/",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .network = .{ .isolated = test_params },
        .channels = &many,
    };
    try std.testing.expectError(error.TooManyChannels, validate(config));
}

test "validate refuses a helper that names a channel index out of range" {
    var dummy: u8 = 0;
    const channel: Channel = .{ .ptr = &dummy, .serve = .{ .call = testServe, .max_requests = 1 }, .hands_host_descriptor = false };
    const helper: Helper = .{ .ptr = &dummy, .run = testRun, .allowed = &.{}, .channel = 1 };
    const config: Config = .{
        .root = "/",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .network = .{ .isolated = test_params },
        .channels = &.{channel},
        .helpers = &.{helper},
    };
    try std.testing.expectError(error.HelperChannelOutOfRange, validate(config));
}

test "validate refuses a helper without an isolated network" {
    var dummy: u8 = 0;
    const helper: Helper = .{ .ptr = &dummy, .run = testRun, .allowed = &.{} };
    const config: Config = .{ .root = "/", .cwd = "/", .env = &.{}, .mounts = &.{}, .rules = &.{}, .helpers = &.{helper} };
    try std.testing.expectError(error.ChannelWithoutIsolation, validate(config));
}

test "validate refuses channels that disagree on handing a host descriptor" {
    var dummy: u8 = 0;
    const routed: Channel = .{ .ptr = &dummy, .serve = .{ .call = testServe, .max_requests = 1 }, .hands_host_descriptor = false };
    const brokered: Channel = .{ .ptr = &dummy, .serve = .{ .call = testServe, .max_requests = 1 }, .hands_host_descriptor = true };
    const config: Config = .{
        .root = "/",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .network = .{ .isolated = test_params },
        .channels = &.{ routed, brokered },
    };
    try std.testing.expectError(error.ChannelsDisagreeOnDescriptor, validate(config));
}

test "validate refuses a channel with neither serve nor wakeup" {
    var dummy: u8 = 0;
    const silent: Channel = .{ .ptr = &dummy, .hands_host_descriptor = false };
    const config: Config = .{
        .root = "/",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .network = .{ .isolated = test_params },
        .channels = &.{silent},
    };
    try std.testing.expectError(error.ChannelWithoutCallback, validate(config));
}

test "validate refuses a serve channel with no request budget" {
    var dummy: u8 = 0;
    const unbounded: Channel = .{
        .ptr = &dummy,
        .serve = .{ .call = testServe, .max_requests = 0 },
        .hands_host_descriptor = false,
    };
    const config: Config = .{
        .root = "/",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .network = .{ .isolated = test_params },
        .channels = &.{unbounded},
    };
    try std.testing.expectError(error.ChannelWithoutBudget, validate(config));
}

test "validate accepts a wakeup-only channel with no request budget" {
    var dummy: u8 = 0;
    const waker: Channel = .{
        .ptr = &dummy,
        .wakeup = .{ .fd = 9, .drain = testDrain },
        .hands_host_descriptor = false,
    };
    const config: Config = .{
        .root = "/",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .network = .{ .isolated = test_params },
        .channels = &.{waker},
    };
    try validate(config);
}

test "blocksConnect is true when any channel hands a host descriptor" {
    var dummy: u8 = 0;
    const routed: Channel = .{ .ptr = &dummy, .serve = .{ .call = testServe, .max_requests = 1 }, .hands_host_descriptor = false };
    const brokered: Channel = .{ .ptr = &dummy, .serve = .{ .call = testServe, .max_requests = 1 }, .hands_host_descriptor = true };
    var config: Config = .{ .root = "/", .cwd = "/", .env = &.{}, .mounts = &.{}, .rules = &.{}, .network = .{ .isolated = test_params } };
    config.channels = &.{routed};
    try std.testing.expect(!blocksConnect(config));
    config.channels = &.{ routed, brokered };
    try std.testing.expect(blocksConnect(config));
}

test "channelFd counts up from three" {
    try std.testing.expectEqual(@as(i32, 3), channelFd(0));
    try std.testing.expectEqual(@as(i32, 4), channelFd(1));
}

test "Handle reports no pid until publish" {
    var handle: Handle = .{};
    try std.testing.expectEqual(@as(?i32, null), handle.pid());
    handle.publish(42, 7);
    try std.testing.expectEqual(@as(?i32, 42), handle.pid());
    try std.testing.expectEqual(@as(?i32, 7), handle.fd());
}

test "a fresh handle has no process to signal" {
    var handle: Handle = .{};
    try std.testing.expectError(error.NoHandle, handle.signal(15));
}

test "spawnWith refuses an empty cgroup prefix before any driver runs" {
    var handle: Handle = .{};
    const config: Config = .{
        .root = "/",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .containment = .{ .best_effort = .{ .name_prefix = "" } },
    };
    try std.testing.expectError(
        error.InvalidCgroupPrefix,
        spawn(std.testing.allocator, config, &.{"/nonexistent"}, .{ .handle = &handle }),
    );
    try std.testing.expectEqual(@as(?i32, null), handle.pid());
}

test "Driver.spawn validates before any driver runs" {
    var handle: Handle = .{};
    const config: Config = .{
        .root = "/",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .containment = .{ .best_effort = .{ .name_prefix = "" } },
    };
    try std.testing.expectError(
        error.InvalidCgroupPrefix,
        native.spawn(std.testing.allocator, config, &.{"/nonexistent"}, .{ .handle = &handle }),
    );
    try std.testing.expectEqual(@as(?i32, null), handle.pid());
}

test "a counting driver is never reached when validation refuses the config" {
    CountingDriver.reset();
    const config: Config = .{
        .root = "/",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .containment = .{ .best_effort = .{ .name_prefix = "" } },
    };
    try std.testing.expectError(
        error.InvalidCgroupPrefix,
        CountingDriver.driver.spawn(std.testing.allocator, config, &.{"/nonexistent"}, .{}),
    );
    try std.testing.expectEqual(@as(usize, 0), CountingDriver.spawns);
}

test "a handle published without a spawn has no driver to signal through" {
    var handle: Handle = .{};
    handle.publish(5, 6);
    try std.testing.expectEqualStrings("none", handle.driver.name);
    try std.testing.expectError(error.NoHandle, handle.signal(15));
    handle.close();
}

test "spawnWith records the driver on the handle before the driver runs" {
    var handle: Handle = .{};
    const config: Config = .{ .root = "/", .cwd = "/", .env = &.{}, .mounts = &.{}, .rules = &.{} };
    CountingDriver.reset();
    _ = try spawnWith(
        CountingDriver.driver,
        std.testing.allocator,
        config,
        &.{"/nonexistent"},
        .{ .handle = &handle },
    );
    try std.testing.expectEqualStrings(CountingDriver.driver.name, handle.driver.name);
}

const CountingDriver = struct {
    var spawns: usize = 0;
    var signals: usize = 0;
    var closes: usize = 0;
    var joins: usize = 0;

    fn reset() void {
        spawns = 0;
        signals = 0;
        closes = 0;
        joins = 0;
    }

    fn spawnFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        config: Config,
        argv: []const []const u8,
        run: Run,
    ) SpawnError!Term {
        _ = ptr;
        _ = gpa;
        _ = config;
        _ = argv;
        _ = run;
        spawns += 1;
        return .{ .exited = 7 };
    }

    fn signalFn(ptr: *anyopaque, handle: *const Handle, sig: u32) SignalError!void {
        _ = ptr;
        _ = handle;
        _ = sig;
        signals += 1;
    }

    fn closeFn(ptr: *anyopaque, handle: *Handle) void {
        _ = ptr;
        _ = handle;
        closes += 1;
    }

    fn joinFn(ptr: *anyopaque, stderr_fd: i32) KeyringError!void {
        _ = ptr;
        _ = stderr_fd;
        joins += 1;
        return error.Refused;
    }

    fn whyFn(ptr: *anyopaque) ?[]const u8 {
        _ = ptr;
        return null;
    }

    const table: Driver.VTable = .{
        .spawn = spawnFn,
        .signal = signalFn,
        .close = closeFn,
        .joinFreshSessionKeyring = joinFn,
        .whyLast = whyFn,
    };

    const driver: Driver = .{
        .ptr = &no_state,
        .vtable = &table,
        .name = "counting",
        .guarantees = Guarantees.initMany(&.{.network_isolated}),
        .expresses = .{
            .moved_paths = false,
            .scratch_area = false,
            .procfs = false,
            .cgroup_placement = false,
            .device_passthrough = false,
        },
    };
};

test "spawnWith runs the named driver's table and records that driver on the handle" {
    CountingDriver.reset();

    const config = Config{ .root = "/", .mounts = &.{}, .rules = &.{}, .cwd = "/", .env = &.{} };
    var handle: Handle = .{};
    const term = try spawnWith(
        CountingDriver.driver,
        std.testing.allocator,
        config,
        &.{"/nonexistent"},
        .{ .handle = &handle },
    );

    try std.testing.expectEqual(@as(usize, 1), CountingDriver.spawns);
    try std.testing.expectEqual(@as(u8, 7), term.exited);
    try std.testing.expectEqualStrings("counting", handle.driver.name);

    try CountingDriver.driver.signal(&handle, 15);
    CountingDriver.driver.close(&handle);
    try std.testing.expectError(
        error.Refused,
        CountingDriver.driver.joinFreshSessionKeyring(-1),
    );
    try std.testing.expectEqual(@as(usize, 1), CountingDriver.signals);
    try std.testing.expectEqual(@as(usize, 1), CountingDriver.closes);
    try std.testing.expectEqual(@as(usize, 1), CountingDriver.joins);
}

test "the native driver's table answers exactly what its own module does" {
    try std.testing.expectEqualStrings(native_module.driver_name, native.name);
    try std.testing.expectEqual(native_module.guarantees, native.guarantees);
    try std.testing.expectEqual(guarantees, native.guarantees);
    try std.testing.expectEqual(native_module.expresses, native.expresses);
    try std.testing.expectEqual(@as(*anyopaque, @ptrCast(&no_state)), native.ptr);
}

test "the expresses constants are the native driver's own answer" {
    try std.testing.expectEqual(native.expresses.moved_paths, expresses.moved_paths);
    try std.testing.expectEqual(native.expresses.scratch_area, expresses.scratch_area);
    try std.testing.expectEqual(native.expresses.procfs, expresses.procfs);
    try std.testing.expectEqual(native.expresses.cgroup_placement, expresses.cgroup_placement);
    try std.testing.expectEqual(native.expresses.device_passthrough, expresses.device_passthrough);
}

test "blocksConnect is false without channels" {
    const config: Config = .{ .root = "/", .cwd = "/", .env = &.{}, .mounts = &.{}, .rules = &.{} };
    try std.testing.expect(!blocksConnect(config));
}

test "a path a rule will name is resolved where a mount cannot be" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var real_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const real_length = try tmp.dir.realPath(std.testing.io, &real_buffer);
    const real = real_buffer[0..real_length];

    const through_link = try std.fmt.allocPrint(std.testing.allocator, "{s}/link", .{real});
    defer std.testing.allocator.free(through_link);
    try tmp.dir.symLink(std.testing.io, real, "link", .{ .is_directory = true });

    var answer_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const answered = resolvedPath(std.testing.io, through_link, &answer_buffer);

    if (expresses.moved_paths) {
        try std.testing.expectEqualStrings(through_link, answered);
    } else {
        try std.testing.expectEqualStrings(real, answered);
    }

    var missing_buffer: [std.fs.max_path_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/no/such/directory/here",
        resolvedPath(std.testing.io, "/no/such/directory/here", &missing_buffer),
    );
}

test "a rule below a mount agrees, and a rule beside one does not" {
    const agreeing = Config{
        .root = "/root",
        .mounts = &.{.{ .bind = .{ .source = "/host/work", .target = "/work" } }},
        .rules = &.{
            .{ .path = "/work", .access = landlock.AccessFs.read_write },
            .{ .path = "/work/build.zig", .access = landlock.AccessFs.read_only_file },
        },
        .cwd = "/work",
        .env = &.{},
    };
    try std.testing.expectEqual(@as(?LayerGap, null), firstGap(agreeing));

    const extra_rule = Config{
        .root = "/root",
        .mounts = &.{.{ .bind = .{ .source = "/host/work", .target = "/work" } }},
        .rules = &.{
            .{ .path = "/work", .access = landlock.AccessFs.read_write },
            .{ .path = "/etc", .access = landlock.AccessFs.read_only },
        },
        .cwd = "/work",
        .env = &.{},
    };
    const gap = firstGap(extra_rule) orelse return error.TestExpectedGap;
    try std.testing.expectEqual(std.meta.Tag(LayerGap).rule_outside_mounts, std.meta.activeTag(gap));
    try std.testing.expectEqualStrings("/etc", gap.path());
}

test "a rule above every mount is a gap, because landlock rights reach downwards" {
    const too_wide = Config{
        .root = "/root",
        .mounts = &.{.{ .bind = .{ .source = "/host/work", .target = "/work" } }},
        .rules = &.{.{ .path = "/", .access = landlock.AccessFs.read_write }},
        .cwd = "/work",
        .env = &.{},
    };
    const gap = firstGap(too_wide) orelse return error.TestExpectedGap;
    try std.testing.expectEqualStrings("/", gap.path());

    const neighbour = Config{
        .root = "/root",
        .mounts = &.{.{ .bind = .{ .source = "/host/work", .target = "/work" } }},
        .rules = &.{.{ .path = "/workshop", .access = landlock.AccessFs.read_write }},
        .cwd = "/work",
        .env = &.{},
    };
    const neighbour_gap = firstGap(neighbour) orelse return error.TestExpectedGap;
    try std.testing.expectEqualStrings("/workshop", neighbour_gap.path());
}

test "a mount with no rule is a gap, and a denied path is not" {
    const unreachable_mount = Config{
        .root = "/root",
        .mounts = &.{
            .{ .bind = .{ .source = "/host/work", .target = "/work" } },
            .{ .bind = .{ .source = "/host/tool", .target = "/run/palisade/bin", .read_only = true } },
        },
        .rules = &.{.{ .path = "/work", .access = landlock.AccessFs.read_write }},
        .cwd = "/work",
        .env = &.{},
    };
    const gap = firstGap(unreachable_mount) orelse return error.TestExpectedGap;
    try std.testing.expectEqual(std.meta.Tag(LayerGap).mount_without_rule, std.meta.activeTag(gap));
    try std.testing.expectEqualStrings("/run/palisade/bin", gap.path());

    const denied = Config{
        .root = "/root",
        .mounts = &.{
            .{ .bind = .{ .source = "/host/work", .target = "/work" } },
            .{ .deny = .{ .target = "/work/.env" } },
        },
        .rules = &.{.{ .path = "/work", .access = landlock.AccessFs.read_write }},
        .cwd = "/work",
        .env = &.{},
    };
    try std.testing.expectEqual(@as(?LayerGap, null), firstGap(denied));
}

test "a capped scratch area is a mount the sandbox makes, and it needs a rule of its own" {
    const with_rule = Config{
        .root = "/root",
        .mounts = &.{.{ .bind = .{ .source = "/host/work", .target = "/work" } }},
        .rules = &.{
            .{ .path = "/work", .access = landlock.AccessFs.read_write },
            .{ .path = "/run/palisade/tmp", .access = landlock.AccessFs.read_write },
        },
        .scratch = &.{.{ .target = "/run/palisade/tmp" }},
        .cwd = "/work",
        .env = &.{},
    };
    try std.testing.expectEqual(@as(?LayerGap, null), firstGap(with_rule));

    const without_rule = Config{
        .root = "/root",
        .mounts = &.{.{ .bind = .{ .source = "/host/work", .target = "/work" } }},
        .rules = &.{.{ .path = "/work", .access = landlock.AccessFs.read_write }},
        .scratch = &.{.{ .target = "/run/palisade/tmp" }},
        .cwd = "/work",
        .env = &.{},
    };
    const gap = firstGap(without_rule) orelse return error.TestExpectedGap;
    try std.testing.expectEqualStrings("/run/palisade/tmp", gap.path());
}

test "a gap names the path and says which of the two lists is short" {
    var buffer: [160]u8 = undefined;
    try std.testing.expectEqualStrings(
        "landlock rule /etc names a path the mount set does not hold",
        try std.fmt.bufPrint(&buffer, "{f}", .{LayerGap{ .rule_outside_mounts = "/etc" }}),
    );
    try std.testing.expectEqualStrings(
        "mount /proc has no landlock rule, so it is present and unreachable",
        try std.fmt.bufPrint(&buffer, "{f}", .{LayerGap{ .mount_without_rule = "/proc" }}),
    );
}

test "the grant set is every mount target and every scratch area, and no denial" {
    const config = Config{
        .root = "/tmp/root",
        .mounts = &.{
            .{ .bind = .{ .source = "/host/work", .target = "/work" } },
            .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } },
            .{ .proc = .{ .target = "/proc" } },
            .{ .deny = .{ .target = "/work/.ssh" } },
        },
        .rules = &.{},
        .scratch = &.{.{ .target = "/run/palisade/scratch" }},
        .cwd = "/work",
        .env = &.{},
    };

    const set = try grantPrefixes(std.testing.allocator, config);
    defer std.testing.allocator.free(set);

    try std.testing.expectEqual(@as(usize, 4), set.len);
    try std.testing.expectEqualStrings("/work", set[0]);
    try std.testing.expectEqualStrings("/nix/store", set[1]);
    try std.testing.expectEqualStrings("/proc", set[2]);
    try std.testing.expectEqualStrings("/run/palisade/scratch", set[3]);

    try std.testing.expect(grants.setHolds(set, "/nix/store/abc-glibc/lib/libc.so.6"));
    try std.testing.expect(!grants.setHolds(set, "/etc/shadow"));
}

test "a copied config shares no memory with the original, scratch and substitutions included" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const original = Config{
        .root = "/tmp/root",
        .mounts = &.{.{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } }},
        .rules = &.{.{ .path = "/work", .access = .{ .read_file = true } }},
        .scratch = &.{ .{ .target = "/run/palisade/scratch" }, .{ .target = "/run/palisade/tasks" } },
        .substitutions = &.{.{ .text = .{ .target = "/etc/hosts", .contents = "127.0.0.1 localhost\n" } }},
        .owned_directories = &.{.{ .target = "/etc", .remove = &.{ "/etc/hosts", "/etc/resolv.conf" } }},
        .deny_notice = "denied\n",
        .network = .{ .isolated = test_params },
        .cwd = "/",
        .env = &.{"PATH=/bin"},
        .path_audit = true,
    };

    const copied = try original.copy(arena);

    try std.testing.expectEqual(true, copied.path_audit);
    try std.testing.expectEqualStrings(original.root, copied.root);
    try std.testing.expect(original.root.ptr != copied.root.ptr);
    try std.testing.expectEqualStrings(original.cwd, copied.cwd);
    try std.testing.expect(original.cwd.ptr != copied.cwd.ptr);
    try std.testing.expect(original.env.ptr != copied.env.ptr);
    try std.testing.expectEqualStrings(original.env[0], copied.env[0]);
    try std.testing.expect(original.env[0].ptr != copied.env[0].ptr);
    try std.testing.expect(original.mounts.ptr != copied.mounts.ptr);
    try std.testing.expectEqualStrings(
        original.mounts[0].bind.source,
        copied.mounts[0].bind.source,
    );
    try std.testing.expect(original.mounts[0].bind.source.ptr != copied.mounts[0].bind.source.ptr);
    try std.testing.expect(original.rules.ptr != copied.rules.ptr);
    try std.testing.expectEqualStrings(original.rules[0].path, copied.rules[0].path);
    try std.testing.expect(original.rules[0].path.ptr != copied.rules[0].path.ptr);

    try std.testing.expectEqual(original.scratch.len, copied.scratch.len);
    for (original.scratch, copied.scratch) |from, to| {
        try std.testing.expectEqualStrings(from.target, to.target);
        try std.testing.expect(from.target.ptr != to.target.ptr);
    }
    try std.testing.expect(original.scratch.ptr != copied.scratch.ptr);

    try std.testing.expectEqualStrings(original.substitutions[0].text.contents, copied.substitutions[0].text.contents);
    try std.testing.expect(original.substitutions[0].text.contents.ptr != copied.substitutions[0].text.contents.ptr);

    try std.testing.expect(original.owned_directories.ptr != copied.owned_directories.ptr);
    try std.testing.expectEqual(original.owned_directories.len, copied.owned_directories.len);
    for (original.owned_directories, copied.owned_directories) |from, to| {
        try std.testing.expectEqualStrings(from.target, to.target);
        try std.testing.expect(from.target.ptr != to.target.ptr);
        try std.testing.expect(from.remove.ptr != to.remove.ptr);
        for (from.remove, to.remove) |from_name, to_name| {
            try std.testing.expectEqualStrings(from_name, to_name);
            try std.testing.expect(from_name.ptr != to_name.ptr);
        }
    }

    try std.testing.expectEqualStrings(original.deny_notice, copied.deny_notice);
    try std.testing.expect(original.deny_notice.ptr != copied.deny_notice.ptr);

    try std.testing.expectEqualStrings(test_params.device_name, copied.network.isolated.device_name);
    try std.testing.expect(test_params.device_name.ptr != copied.network.isolated.device_name.ptr);

    const named = try (Config{
        .root = "/",
        .mounts = &.{},
        .rules = &.{},
        .cwd = "/",
        .env = &.{},
        .containment = .{ .best_effort = .{ .name_prefix = "work." } },
    }).copy(arena);
    try std.testing.expectEqualStrings("work.", named.containment.best_effort.name_prefix);

    try std.testing.expectEqual(original.limits, copied.limits);
}

test "one tool call's paths are added to the session's own, and a name with no room keeps its count" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const openat = @backingInt(seccomp.TrapCall.openat);

    var audit: SyscallAudit = .{};

    var first: notify.PathRecord = .{ .ready = 1 };
    var made: u32 = 0;
    while (made < notify.kept_path_cap) : (made += 1) {
        var buffer: [32]u8 = undefined;
        const path = try std.fmt.bufPrint(&buffer, "/etc/thing-{d}", .{made});
        first.ungranted[openat] += 1;
        notify.keepName(&first, openat, path, 1);
    }
    audit.recordPaths(&first);

    var second: notify.PathRecord = .{ .ready = 1 };
    second.ungranted[openat] = 500;
    second.relative[openat] = 7;
    second.granted[openat] = 11;
    notify.keepName(&second, openat, "/home/someone/.ssh/id_ed25519", 500);
    audit.recordPaths(&second);

    const counted = audit.pathCounts();
    try std.testing.expectEqual(@as(u32, notify.kept_path_cap), counted.kept);
    try std.testing.expectEqual(
        @as(u64, notify.kept_path_cap + 500),
        counted.ungranted[openat],
    );
    try std.testing.expectEqual(@as(u64, 500), counted.ungranted_unnamed[openat]);
    try std.testing.expectEqual(@as(u64, 7), counted.relative[openat]);
    try std.testing.expectEqual(@as(u64, 11), counted.granted[openat]);
    try std.testing.expectEqual(@as(u64, 0), counted.readers_unreported);
    try std.testing.expectEqual(@as(u64, 0), counted.readers_absent);
}

test "a reader that never started, and one that never reported, are counted apart" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var audit: SyscallAudit = .{};

    var never_started: notify.PathRecord = .{ .ready = 0 };
    audit.recordPaths(&never_started);
    var no_report: notify.PathRecord = .{ .ready = 1, .reader_unreported = 1 };
    audit.recordPaths(&no_report);
    var whole_way: notify.PathRecord = .{ .ready = 1, .ended = 1 };
    audit.recordPaths(&whole_way);

    const counted = audit.pathCounts();
    try std.testing.expectEqual(@as(u64, 1), counted.readers_absent);
    try std.testing.expectEqual(@as(u64, 1), counted.readers_unreported);
}

test "the audit counts each of the three answers apart, and keeps the first fault" {
    var audit: SupervisorAudit = .{};
    try std.testing.expectEqual(@as(?SupervisorAudit.Fault, null), audit.counts(.seccomp).first_fault);

    audit.record(.seccomp, .on);
    audit.record(.seccomp, .on);
    audit.record(.seccomp, .unsaid);
    audit.record(.seccomp, .{ .off = .not_supported });
    audit.record(.seccomp, .{ .off = .rejected });

    const counts = audit.counts(.seccomp);
    try std.testing.expectEqual(@as(u64, 2), counts.confined);
    try std.testing.expectEqual(@as(u64, 2), counts.unconfined);
    try std.testing.expectEqual(@as(u64, 1), counts.unreported);
    try std.testing.expectEqual(
        @as(?SupervisorAudit.Fault, .not_supported),
        counts.first_fault,
    );

    const paths = audit.counts(.landlock);
    try std.testing.expectEqual(@as(u64, 0), paths.confined);
    try std.testing.expectEqual(@as(u64, 0), paths.unconfined);
    try std.testing.expectEqual(@as(u64, 0), paths.unreported);
    try std.testing.expectEqual(@as(?SupervisorAudit.Fault, null), paths.first_fault);

    audit.record(.landlock, .{ .off = .rejected });
    try std.testing.expectEqual(@as(u64, 1), audit.counts(.landlock).unconfined);
    try std.testing.expectEqual(@as(u64, 2), audit.counts(.seccomp).unconfined);
}

test "a fresh audit claims nothing, so an absent answer is never a confined one" {
    const audit: SupervisorAudit = .{};
    for (std.enums.values(LayerName)) |layer| {
        const counts = audit.counts(layer);
        try std.testing.expectEqual(@as(u64, 0), counts.confined);
        try std.testing.expectEqual(@as(u64, 0), counts.unconfined);
        try std.testing.expectEqual(@as(u64, 0), counts.unreported);
        try std.testing.expectEqual(@as(?SupervisorAudit.Fault, null), counts.first_fault);
    }
}

test "inexpressible is null on linux, whatever the config asks for" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var dummy: u8 = 0;
    const channel: Channel = .{ .ptr = &dummy, .serve = .{ .call = testServe, .max_requests = 1 }, .hands_host_descriptor = false };
    const config: Config = .{
        .root = "/tmp/some/root",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{.{ .proc = .{} }},
        .rules = &.{},
        .network = .{ .isolated = test_params },
        .channels = &.{channel},
    };
    try std.testing.expectEqual(@as(?Inexpressible, null), inexpressible(config));
}

test "inexpressible names the first thing macos cannot give" {
    var dummy: u8 = 0;
    const channel: Channel = .{ .ptr = &dummy, .serve = .{ .call = testServe, .max_requests = 1 }, .hands_host_descriptor = false };
    const config: Config = .{
        .root = "/",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .network = .{ .isolated = test_params },
        .channels = &.{channel},
    };
    try std.testing.expectEqual(Inexpressible.channels, inexpressibleOnDarwin(config).?);
}

test "darwin guarantees lack bind_mounts" {
    const darwin_caps = @import("darwin/caps.zig");
    const linux_caps = @import("linux/caps.zig");
    try std.testing.expect(!darwin_caps.guarantees.contains(.bind_mounts));
    try std.testing.expect(linux_caps.guarantees.contains(.bind_mounts));
}

test "confinedAlready is false off macos" {
    if (builtin.os.tag == .macos) return error.SkipZigTest;
    try std.testing.expect(!confinedAlready());
    try std.testing.expectEqual(Nesting.free, nesting());
}

test "inexpressible names each layer macos has not got" {
    const base: Config = .{ .root = "/", .mounts = &.{}, .rules = &.{}, .cwd = "/", .env = &.{} };

    var moved = base;
    moved.mounts = &.{.{ .bind = .{ .source = "/work/checkout", .target = "/home/me/project" } }};
    try std.testing.expectEqual(Inexpressible.bind_moves_a_path, inexpressibleOnDarwin(moved).?);

    var overlaid = base;
    overlaid.mounts = &.{.{ .overlay = .{ .lower = "/l", .upper = "/u", .work = "/w", .target = "/t" } }};
    try std.testing.expectEqual(Inexpressible.overlay_mount, inexpressibleOnDarwin(overlaid).?);

    var procfs = base;
    procfs.mounts = &.{.{ .proc = .{} }};
    try std.testing.expectEqual(Inexpressible.proc_mount, inexpressibleOnDarwin(procfs).?);

    var rooted = base;
    rooted.root = "/tmp/some/root";
    try std.testing.expectEqual(Inexpressible.root_is_not_the_real_root, inexpressibleOnDarwin(rooted).?);

    var scratched = base;
    scratched.scratch = &.{.{ .target = "/run/palisade/scratch" }};
    try std.testing.expectEqual(Inexpressible.scratch_area, inexpressibleOnDarwin(scratched).?);

    var identity = base;
    identity.mounts = &.{.{ .bind = .{ .source = "/nix/store/x", .target = "/nix/store/x", .read_only = true } }};
    try std.testing.expectEqual(@as(?Inexpressible, null), inexpressibleOnDarwin(identity));
}

test "inexpressible stays null on linux for a config that swaps a file" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const config: Config = .{
        .root = "/tmp/some/root",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .substitutions = &.{.{ .hide = "/etc/secret" }},
    };
    try std.testing.expectEqual(@as(?Inexpressible, null), inexpressible(config));
    try std.testing.expectEqualStrings(
        "a file swapped for other content, and macos cannot mount over a path",
        Inexpressible.substitution.text(),
    );
}

test "inexpressible names a substitution on macos" {
    const config: Config = .{
        .root = "/",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .substitutions = &.{.{ .hide = "/etc/secret" }},
    };
    try std.testing.expectEqual(Inexpressible.substitution, inexpressibleOnDarwin(config).?);
}

test "inexpressible names an owned directory, and stays null on linux" {
    const config: Config = .{
        .root = "/",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .owned_directories = &.{.{ .target = "/etc" }},
    };
    try std.testing.expectEqual(Inexpressible.owned_directory, inexpressibleOnDarwin(config).?);
    if (builtin.os.tag == .linux) try std.testing.expectEqual(@as(?Inexpressible, null), inexpressible(config));
    try std.testing.expectEqualStrings(
        "a directory owned by the sandbox, and macos cannot mount over a path",
        Inexpressible.owned_directory.text(),
    );
}

test "inexpressibleOnDarwin is null for a plain config, and inexpressible follows the host" {
    const plain: Config = .{ .root = "/", .cwd = "/", .env = &.{}, .mounts = &.{}, .rules = &.{} };
    try std.testing.expectEqual(@as(?Inexpressible, null), inexpressibleOnDarwin(plain));
    try std.testing.expectEqual(@as(?Inexpressible, null), inexpressible(plain));
    if (builtin.os.tag == .linux) {
        var scratched = plain;
        scratched.scratch = &.{.{ .target = "/run/palisade/scratch" }};
        try std.testing.expectEqual(@as(?Inexpressible, null), inexpressible(scratched));
        try std.testing.expectEqual(Inexpressible.scratch_area, inexpressibleOnDarwin(scratched).?);
    }
}

test "Config.copy copies the allowed calls of a helper" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var dummy: u8 = 0;
    const allowed = [_]std.os.linux.SYS{ .write, .exit_group };
    const helper: Helper = .{ .ptr = &dummy, .run = testRun, .allowed = &allowed };
    const config: Config = .{ .root = "/", .cwd = "/", .env = &.{}, .mounts = &.{}, .rules = &.{}, .helpers = &.{helper} };
    const copied = try config.copy(arena_state.allocator());
    try std.testing.expect(copied.helpers[0].allowed.ptr != &allowed);
    try std.testing.expectEqualSlices(std.os.linux.SYS, &allowed, copied.helpers[0].allowed);
}

fn helperConfig(helpers: []const Helper, channels: []const Channel) Config {
    return .{
        .root = "/",
        .cwd = "/",
        .env = &.{},
        .mounts = &.{},
        .rules = &.{},
        .network = .{ .isolated = test_params },
        .channels = channels,
        .helpers = helpers,
    };
}

test "validate refuses a helper that allows a call that opens an escape" {
    var dummy: u8 = 0;
    const escapes = [_]std.os.linux.SYS{ .unshare, .setns, .execve, .ptrace, .setuid };
    for (escapes) |call| {
        const helper: Helper = .{ .ptr = &dummy, .run = testRun, .allowed = &.{call} };
        try std.testing.expectError(error.HelperAllowsEscape, validate(helperConfig(&.{helper}, &.{})));
    }
}

test "validate accepts a helper that allows mount, mkdir, mknod and message calls" {
    var dummy: u8 = 0;
    const calls = [_]std.os.linux.SYS{ .mount, .umount2, .mkdirat, .mknodat, .recvmsg, .accept4, .sendmsg, .read, .write };
    const helper: Helper = .{ .ptr = &dummy, .run = testRun, .allowed = &calls };
    try validate(helperConfig(&.{helper}, &.{}));
}

test "validate refuses a kept capability above the last one" {
    var dummy: u8 = 0;
    const ok: Helper = .{ .ptr = &dummy, .run = testRun, .allowed = &.{}, .keep_capability = std.os.linux.CAP.LAST_CAP };
    try validate(helperConfig(&.{ok}, &.{}));
    const bad: Helper = .{ .ptr = &dummy, .run = testRun, .allowed = &.{}, .keep_capability = std.os.linux.CAP.LAST_CAP + 1 };
    try std.testing.expectError(error.HelperCapabilityInvalid, validate(helperConfig(&.{bad}, &.{})));
}

test "validate refuses keep fds that are low, on a channel, on the ready fd, repeated or too many" {
    var dummy: u8 = 0;
    const channel: Channel = .{ .ptr = &dummy, .serve = .{ .call = testServe, .max_requests = 1 }, .hands_host_descriptor = false };
    const bad_lists = [_][]const i32{
        &.{2},
        &.{channelFd(0)},
        &.{helper_ready_fd},
        &.{ 20, 20 },
        &.{ 20, 21, 22, 23, 24, 25, 26, 27, 28 },
    };
    for (bad_lists) |list| {
        const helper: Helper = .{ .ptr = &dummy, .run = testRun, .allowed = &.{}, .keep_fds = list };
        try std.testing.expectError(error.HelperFdInvalid, validate(helperConfig(&.{helper}, &.{channel})));
    }
    const good: Helper = .{ .ptr = &dummy, .run = testRun, .allowed = &.{}, .keep_fds = &.{ 20, 21 } };
    try validate(helperConfig(&.{good}, &.{channel}));
}
