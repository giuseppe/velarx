// SPDX-License-Identifier: Apache-2.0
//! The files of a monitor's run directory and the types of its interface,
//! `org.velarx.Monitor` ([`super::iface`]).
//!
//! A monitor serves the interface on the socket [`SOCKET`] of its run
//! directory (varlink: `SOCK_STREAM`, one JSON message ended by a NUL, the
//! descriptors of a reply in the `SCM_RIGHTS` of the message that carries
//! it).

use serde::{Deserialize, Serialize};
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
pub use velarx_proto::health::{
    Health, HealthResult, HealthStatus, RestartPolicy, RestartSettings,
};

/// Name of the monitor's socket in its run directory.
pub const SOCKET: &str = "monitor.sock";
/// The exit status of the last run, written before the monitor ends.
pub const EXIT_FILE: &str = "exit";
/// The configuration the daemon writes for the monitor.
pub const CONFIG_FILE: &str = "monitor.json";
/// What the monitor could not report any other way.
pub const LOG_FILE: &str = "monitor.log";
/// The directory of the run directory that is mounted in the container with
/// the socket of the sd_notify protocol, and the name of the socket.
pub const NOTIFY_DIR: &str = "notify.d";
pub const NOTIFY_SOCKET: &str = "notify.sock";
/// Name of the file the PID of the container's init is written to.
pub const PID_FILE: &str = "pid";

/// What an attach client wants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct Attach {
    /// Send the client's input to the container (a stream for it).
    #[serde(default)]
    pub stdin: bool,
    /// The container's standard output (a stream for it; with a terminal,
    /// what the terminal shows).
    #[serde(default = "yes")]
    pub stdout: bool,
    /// The container's standard error (a stream for it).
    #[serde(default = "yes")]
    pub stderr: bool,
    /// The container is waiting for its first client before it starts.
    #[serde(default)]
    pub start: bool,
    /// Close the container's stdin when this client goes away.
    #[serde(default)]
    pub stdin_once: bool,
}

impl Default for Attach {
    fn default() -> Self {
        Self {
            stdin: false,
            stdout: true,
            stderr: true,
            start: false,
            stdin_once: false,
        }
    }
}

fn yes() -> bool {
    true
}

/// A command to run in the container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct ExecRequest {
    /// The program and its arguments.
    pub command: Vec<String>,
    /// `NAME=VALUE` added to the environment of the container.
    #[serde(default)]
    pub env: Vec<String>,
    /// The working directory, in the container.
    #[serde(default)]
    pub cwd: Option<String>,
    /// `USER[:GROUP]`, names or ids of the container's files.
    #[serde(default)]
    pub user: Option<String>,
    /// A terminal: one stream for the input, one for what it shows.
    #[serde(default)]
    pub tty: bool,
    /// A stream for the input of the command (without a terminal: the pipe
    /// of its input itself).
    #[serde(default)]
    pub stdin: bool,
    /// Kill the command (its process group) after this long.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// With `CAP_SYS_ADMIN`.
    #[serde(default)]
    pub privileged: bool,
    /// `exec -d`: the output of the command is dropped from the start (a
    /// command goes on when its client goes away in any case).
    #[serde(default)]
    pub detach: bool,
    /// A reply with `started` when the runtime started the command (it
    /// wrote its pid): the status of a session that ends without one is the
    /// runtime's.
    #[serde(default)]
    pub notify_start: bool,
    /// `--preserve-fds`: the command gets this many descriptors (at most
    /// 64) as 3, 4, ...; the call carries those that are not holes (at most
    /// 16).
    #[serde(default)]
    pub preserve_fds: u32,
    /// Which of them (0 is the command's 3) the command does not get: the
    /// gaps of `--preserve-fd`, a `/dev/null` of the monitor stands in for
    /// them.
    #[serde(default)]
    pub preserve_holes: Vec<u32>,
}

/// What happens at the exit for good.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct ExitPlan {
    /// The container goes with its exit (`--rm`); false: it stays (a
    /// restart, a pod stop, a checkpoint that keeps it)
    pub remove: bool,
    /// With `remove`: its anonymous volumes go too (`run --rm`, `rm -v`)
    #[serde(default)]
    pub volumes: bool,
}

/// Replace the restart policy: `policy` none is no policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct RestartUpdate {
    pub policy: Option<RestartSettings>,
}

/// Replace the health check: `check` none is no check.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct HealthUpdate {
    pub check: Option<velarx_proto::health::Healthcheck>,
    /// The directory of the results' file (`Healthcheck::log_dir`): its
    /// position among the descriptors of the call
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_dir: Option<u32>,
}

/// What `Update` changes: only what it names.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct MonitorUpdate {
    /// The restart policy from now on
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<RestartUpdate>,
    /// The health check from now on
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthUpdate>,
    /// A sealed memory file with the OCI `linux.resources` JSON, by its
    /// position among the descriptors of the call: the monitor gives it to
    /// the runtime's update
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<u32>,
    /// What happens at the exit for good
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<ExitPlan>,
}

/// What a restore of a checkpoint needs: the CRIU options the runtime passes
/// on, and the images.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct RestoreRequest {
    /// The directory of the images (the runtime writes its log there too),
    /// by its position among the descriptors of the call
    pub image_dir: u32,
    /// Restore its established TCP connections (`--tcp-established`)
    #[serde(default)]
    pub tcp_established: bool,
    /// Close its established TCP connections (`--tcp-close`)
    #[serde(default)]
    pub tcp_close: bool,
    /// Restore the file locks it held (`--file-locks`)
    #[serde(default)]
    pub file_locks: bool,
}

/// The first call of the boot connection, once: create the container with
/// the runtime, or restore it with `restore`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct CreateParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore: Option<RestoreRequest>,
}

/// What `Checkpoint` and a restore take: the CRIU options the runtime passes
/// on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct CheckpointRequest {
    /// The directory of the images, which the runtime writes: its position
    /// among the descriptors of the call
    pub image_dir: u32,
    /// The container goes on; else it ends, and its end is a checkpoint
    /// (no restart policy)
    #[serde(default)]
    pub leave_running: bool,
    /// Checkpoint its established TCP connections (`--tcp-established`)
    #[serde(default)]
    pub tcp_established: bool,
    /// Checkpoint the file locks it holds (`--file-locks`)
    #[serde(default)]
    pub file_locks: bool,
    /// Dump the memory only (`--pre-dump`): the container goes on
    #[serde(default)]
    pub pre_dump: bool,
    /// The images of a pre-dump to build on (`--parent-path`): a directory
    /// among the descriptors of the call, by its position
    #[serde(default)]
    pub parent_dir: Option<u32>,
}

/// Where the container is in its life.
/// Where the container is in its life, as the core says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core", rename_all = "snake_case")
)]
pub enum CoreState {
    /// The runtime created the container, the monitor waits for `Start`.
    Created,
    Running,
    /// The runtime froze the container.
    Paused,
    /// A stop is under way: the container runs and will not be restarted.
    Stopping,
    /// The container exited (a restart that waits is no exit for good, but
    /// the run did exit).
    Exited,
}

/// What every version of the monitor answers about its container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct CoreStatus {
    pub state: CoreState,
    /// The init of the container, on the host.
    pub pid: Option<i32>,
    /// The exit status of the last run that ended; 128 plus a signal.
    pub exit_code: Option<i32>,
    /// Nanoseconds since the epoch.
    pub finished_ns: Option<i64>,
    /// The exit is recorded in the store (the monitor answered).
    pub recorded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core", rename_all = "snake_case")
)]
pub enum RunState {
    /// The runtime created the container, the monitor waits for `Start`.
    Created,
    Running,
    /// The runtime froze the container (`Pause`).
    Paused,
    /// A stop is under way: the container runs and will not be restarted.
    Stopping,
    /// The container exited and its exit status is recorded.
    Exited,
    /// The container exited for good and the monitor removes it.
    Removing,
    /// The container is gone: its files and rows.
    Removed,
}

/// What the monitor knows about the container.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct Status {
    pub state: RunState,
    /// The init of the container, on the host.
    pub pid: Option<i32>,
    /// Nanoseconds since the epoch.
    pub started_ns: Option<i64>,
    /// How the last run ended.
    pub exit: Option<ExitInfo>,
    /// The kernel killed a process of the container for lack of memory.
    #[serde(default)]
    pub oom: bool,
    /// The health checks, if the container has any
    #[serde(default)]
    pub health: Option<Health>,
    /// The restarts made by the restart policy.
    #[serde(default)]
    pub restart_count: u32,
    /// The container exited and is going to be started again: how.
    #[serde(default)]
    pub restarting: Option<ExitInfo>,
    /// What happens at the exit for good.
    #[serde(default)]
    pub plan: ExitPlan,
    /// What the monitor did with the exit for good, once it did.
    #[serde(default)]
    pub settled: Option<Settled>,
}

/// What the monitor did with the exit for good: in the store, the network
/// released, and with the plan the container removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct Settled {
    /// The exit is in the store, with its `died` event.
    pub recorded: bool,
    /// The container is gone (the plan, or `Remove`).
    pub removed: bool,
    /// `--rmi`: what went of its image.
    #[serde(default)]
    pub image: Option<super::iface::ImageChange>,
    /// The step that failed and why; the engine's next command finishes it.
    #[serde(default)]
    pub failure: Option<velarx_proto::transfer::Failure>,
}

/// How a run of the container ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct ExitInfo {
    /// The exit status, 128 plus the signal that killed it.
    pub code: i32,
    /// Nanoseconds since the epoch.
    pub finished_ns: i64,
    /// The kernel killed a process of it for lack of memory.
    #[serde(default)]
    pub oom: bool,
    /// A health check asked for a restart.
    #[serde(default)]
    pub health_restart: bool,
    /// The container was stopped on purpose (by the user or the health
    /// check): the restart policy does not apply.
    #[serde(default)]
    pub stop_requested: bool,
    /// The container ran for the time limit it was given and was killed.
    #[serde(default)]
    pub timed_out: bool,
    /// The container was checkpointed: CRIU ended it.
    #[serde(default)]
    pub checkpointed: bool,
    /// When the run that ended started (nanoseconds since the epoch, as the
    /// `Started` event says): an exit is the one of that run only.  Absent
    /// for an end nobody saw.
    #[serde(default)]
    pub started_ns: Option<i64>,
    /// The plan the exit was made with, which the monitor follows:
    /// the container goes with its exit.
    #[serde(default)]
    pub remove: bool,
    /// With `remove`: its anonymous volumes go too
    #[serde(default)]
    pub volumes: bool,
}

/// What happens to the container, as the daemon hears it (`Subscribe`; the
/// form on the wire is [`super::iface::EventRecord`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Started {
        pid: i32,
        started_ns: i64,
        /// The restarts made by the restart policy.
        restart_count: u32,
        /// The monitor started it again after it exited.
        restarted: bool,
    },
    /// The container exited and its output is in the log.
    Exited(ExitInfo),
    /// The container exited and its restart policy starts it again: the
    /// monitor goes on and sends `Started` when it runs again.
    Restarting {
        exit: ExitInfo,
        /// The restarts made, this one included.
        restart_count: u32,
    },
    Health(Health),
    Oom,
    /// The monitor settled the exit for good: the store, the network, with
    /// the plan the removal and the image of `--rmi`.
    Settled(Settled),
}

/// The path to use for the socket `name` of the directory `dirfd`.
pub fn socket_path(dirfd: &OwnedFd, name: &str) -> PathBuf {
    velarx_sys::fd::proc_path(dirfd).join(name)
}

/// `poll` with a timeout in milliseconds (-1: forever); interrupted calls
/// are restarted with the whole timeout.
pub fn poll(fds: &mut [rustix::event::PollFd<'_>], timeout_ms: i32) -> io::Result<usize> {
    let timeout = (timeout_ms >= 0).then(|| rustix::event::Timespec {
        tv_sec: (timeout_ms / 1000) as i64,
        tv_nsec: (timeout_ms % 1000) as i64 * 1_000_000,
    });
    loop {
        match rustix::event::poll(fds, timeout.as_ref()) {
            Err(rustix::io::Errno::INTR) => continue,
            other => return other.map_err(Into::into),
        }
    }
}

/// Wait until `fd` is ready (or `timeout_ms` has passed: false).
pub fn wait_fd<Fd: AsFd>(
    fd: Fd,
    events: rustix::event::PollFlags,
    timeout_ms: i32,
) -> io::Result<bool> {
    let mut fds = [rustix::event::PollFd::new(&fd, events)];
    Ok(poll(&mut fds, timeout_ms)? > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wait_times_out_and_sees_a_readable_end() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(!wait_fd(&a, rustix::event::PollFlags::IN, 10).unwrap());
        drop(b);
        assert!(wait_fd(&a, rustix::event::PollFlags::IN, -1).unwrap());
    }
}
