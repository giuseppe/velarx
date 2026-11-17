// SPDX-License-Identifier: Apache-2.0
//! The interface `org.velarx.Monitor` of the monitor of a container: its
//! methods, their parameters and replies, its errors, and the parsing of a
//! call (what the monitor does with the bytes a client sends).
//!
//! The definition (`interfaces/org.velarx.Monitor.varlink`) is made from the
//! types of this module and of [`super::proto`] by the test
//! `the_interface_file_is_current` (`VELARX_WRITE_INTERFACES=1 cargo test -p
//! velarx-wire --lib monitor::iface` writes it); the monitor serves that text,
//! and both ends compare its digest ([`interface_digest`]) before anything
//! else: a monitor of another version that outlived an upgrade is refused
//! with a clear error, not misunderstood.

use serde::{Deserialize, Serialize};

use super::proto::{
    Attach, CheckpointRequest, CoreStatus, CreateParams, ExecRequest, ExitInfo, Health,
    MonitorUpdate, Status,
};
use crate::varlink::Method;
use crate::varlink::{call_parameters, parse_call, BadCall};

/// The name of the interface.
pub const INTERFACE: &str = "org.velarx.Monitor";

/// The definition of the interface, as the monitor serves it.
pub const DEFINITION: &str = include_str!("../../../../interfaces/org.velarx.Monitor.varlink");

/// The most bytes of one call: a command, its environment, a health check.
pub const MAX_CALL: usize = 256 * 1024;

/// The names of the methods of `org.varlink.service`, which every varlink
/// service has (the methods of this interface are the `impl Method`s below).
pub mod service {
    pub const GET_INFO: &str = "org.varlink.service.GetInfo";
    pub const GET_INTERFACE_DESCRIPTION: &str = "org.varlink.service.GetInterfaceDescription";
}

/// The version of the core of the interface (`GetInfo.core`): the methods
/// marked core in the definition mean the same in every version of the
/// monitor that answers this.
pub const CORE: u32 = 1;

/// The names of the errors.
pub mod error {
    /// The container does not run (exec, checkpoint, a health check).
    pub const NOT_RUNNING: &str = "org.velarx.Monitor.NotRunning";
    /// Not in the state the call needs (a start of a container that ran).
    pub const INVALID_STATE: &str = "org.velarx.Monitor.InvalidState";
    /// The container has no health check.
    pub const NO_HEALTH_CHECK: &str = "org.velarx.Monitor.NoHealthCheck";
    /// A value of the call that cannot be (an empty command, a signal out of
    /// range).
    pub const INVALID_ARGUMENT: &str = "org.velarx.Monitor.InvalidArgument";
    /// The runtime or the system failed.
    pub const FAILED: &str = "org.velarx.Monitor.Failed";
    /// The runtime could not be started for the command of an exec (a user
    /// it runs as that is not there, a runtime or a bundle that is gone):
    /// the engine's condition `NotStarted`.
    pub const NOT_STARTED: &str = "org.velarx.Monitor.NotStarted";
    pub const METHOD_NOT_FOUND: &str = "org.varlink.service.MethodNotFound";
    pub const INTERFACE_NOT_FOUND: &str = "org.varlink.service.InterfaceNotFound";
    pub const INVALID_PARAMETER: &str = "org.varlink.service.InvalidParameter";
    pub const EXPECTED_MORE: &str = "org.varlink.service.ExpectedMore";
}

/// The parameters of the errors of the interface.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Reason {
    pub reason: String,
}

/// The digest of a definition: FNV-1a of its text, in hex.
pub fn digest(text: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// The digest of the definition this build speaks.
pub fn interface_digest() -> String {
    digest(DEFINITION)
}

/// A call of no parameters, or a reply of none.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct Empty {}

/// Who the monitor is.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct Info {
    /// The version of velarx of the monitor.
    pub version: String,
    /// The commit it was built from.
    pub commit: String,
    /// The version of the core (1, [`CORE`]): `GetInfo`, `GetCoreStatus`,
    /// `Stop`, `Kill` and `Wait` mean the same in every version of the
    /// monitor that answers it.  0 (it is missing) is a monitor from before
    /// the core.
    #[serde(default)]
    pub core: u32,
    /// The FNV-1a (64 bits, hexadecimal) of the text of the definition
    /// the monitor serves: a client that speaks another one may make the
    /// core calls, not the others.
    pub digest: String,
    /// The id of the container.
    pub id: String,
}

/// A reply of `Subscribe`: the status first, then the events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct Subscribed {
    /// In the first reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// In the replies after the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<EventRecord>,
}

/// The status of the container.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct StatusReply {
    pub status: Status,
}

/// The status after a start: none for a start that waits for its client.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct StartReply {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

/// The health checks of the container.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct HealthReply {
    pub health: Health,
}

/// How to start the container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct StartParams {
    /// Wait for the first `Attach` with `start` to start the container, at
    /// most this long (it is started at that bound if no client came); 0:
    /// start now.
    #[serde(default)]
    pub attach_wait_ms: u64,
}

/// The parameters of `Stop`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct StopParams {
    /// The signal that asks the container to stop (none: the container's
    /// stop signal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    /// Milliseconds until SIGKILL (none: the container's stop timeout; 0:
    /// at once).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// The reply of `Stop`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct StopReply {
    pub status: CoreStatus,
    /// SIGKILL was needed.
    pub killed: bool,
}

/// The parameters of `Remove`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct RemoveParams {
    /// Stop a container that runs first (as `Stop` with `timeout_ms`; none:
    /// 0); else a running container is `InvalidState`.
    #[serde(default)]
    pub force: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Its anonymous volumes go too.
    #[serde(default)]
    pub volumes: bool,
}

/// A reply with the core status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct CoreStatusReply {
    pub status: CoreStatus,
}

/// The parameters of `Kill`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct KillParams {
    pub signal: i32,
}

/// The size of a terminal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct ResizeParams {
    pub rows: u16,
    pub cols: u16,
}

/// A signal, 1 to 64.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct SignalParams {
    pub signal: i32,
}

/// A pidfd of the init of the container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct InitReply {
    /// Its position among the descriptors of the reply.
    pub pidfd: u32,
}

/// Where a session (an attach, an exec) is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core", rename_all = "snake_case")
)]
pub enum SessionPhase {
    /// The first reply: the streams.
    #[default]
    Streams,
    /// The runtime started the command (an exec with `notify_start`).
    Started,
    /// The last reply: the session ended.
    Ended,
}

/// The streams of an attach session, then how it ended.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct AttachReply {
    /// Where the session is.
    #[serde(default)]
    pub phase: SessionPhase,
    /// In the first reply: the stream of the container's input (the client
    /// writes to it), by its position among the descriptors of the reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<u32>,
    /// In the first reply: the stream of its output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout: Option<u32>,
    /// In the first reply: the stream of its errors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr: Option<u32>,
    /// In the last reply: the exit status of the run; the streams are written
    /// out and closed before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
    /// In the last reply: the client did not read its output fast enough,
    /// its streams were closed early and the rest of the output dropped.
    #[serde(default)]
    pub output_dropped: bool,
}

/// Why an exec session ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core", rename_all = "snake_case")
)]
pub enum ExecReason {
    /// The command ended (or the runtime could not start it).
    #[default]
    Exited,
    /// Its time limit was over: it was killed.
    TimedOut,
    /// Its client went away: it was killed.
    Cancelled,
}

/// How an exec session ended.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct ExecExit {
    /// The exit status of the command; 126 or 127 when the runtime could
    /// not run it.
    pub code: i32,
    pub reason: ExecReason,
    /// The runtime started the command: else the status is the runtime's.
    pub started: bool,
}

/// The streams of an exec session, its start, then its end.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct ExecReply {
    /// Where the session is.
    #[serde(default)]
    pub phase: SessionPhase,
    /// In the first reply: the stream of the input (without a terminal, the
    /// pipe of the command's input itself).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<u32>,
    /// In the first reply: the stream of the output (with a
    /// terminal, what it shows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout: Option<u32>,
    /// In the first reply: the stream of the errors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr: Option<u32>,
    /// In the last reply; the streams are written out and closed before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<ExecExit>,
    /// In the last reply: the client did not read its output fast enough,
    /// its streams were closed early and the rest of the output dropped.
    #[serde(default)]
    pub output_dropped: bool,
}

/// The kind of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core", rename_all = "snake_case")
)]
pub enum EventKind {
    /// The container runs: `pid`, `started_ns`, `restart_count`, `restarted`.
    Started,
    /// It exited (`exit`).
    Exited,
    /// It exited (`exit`) and its restart policy starts it again
    /// (`restart_count`, this restart included).
    Restarting,
    /// The status of its health checks (`health`).
    Health,
    /// The kernel killed a process of it for lack of memory.
    Oom,
    /// The exit for good is settled (`settled`).
    Settled,
}

/// A name of an image: `repository:tag`, or `repository@digest` for the tag
/// `@digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct ImageName {
    pub repository: String,
    pub tag: String,
}

/// The image of a container the monitor removed, or untagged, as the
/// container went (`--rmi`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct ImageChange {
    /// The hex digest of its configuration.
    pub id: String,
    /// The names it lost.
    pub names: Vec<ImageName>,
    /// The image itself went, not only the names.
    pub removed: bool,
}

/// Something that happened to the container.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    test,
    derive(zlink_core::introspect::CustomType),
    zlink(crate = "zlink_core")
)]
pub struct EventRecord {
    pub kind: EventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    /// Nanoseconds since the epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_ns: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_count: Option<u32>,
    /// The restart policy started it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restarted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<ExitInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<Health>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled: Option<super::proto::Settled>,
}

impl From<&super::proto::Event> for EventRecord {
    fn from(e: &super::proto::Event) -> Self {
        use super::proto::Event;
        let mut r = EventRecord {
            kind: EventKind::Oom,
            pid: None,
            started_ns: None,
            restart_count: None,
            restarted: None,
            exit: None,
            health: None,
            settled: None,
        };
        match e {
            Event::Started {
                pid,
                started_ns,
                restart_count,
                restarted,
            } => {
                r.kind = EventKind::Started;
                r.pid = Some(*pid);
                r.started_ns = Some(*started_ns);
                r.restart_count = Some(*restart_count);
                r.restarted = Some(*restarted);
            }
            Event::Exited(info) => {
                r.kind = EventKind::Exited;
                r.exit = Some(info.clone());
            }
            Event::Restarting {
                exit,
                restart_count,
            } => {
                r.kind = EventKind::Restarting;
                r.exit = Some(exit.clone());
                r.restart_count = Some(*restart_count);
            }
            Event::Health(h) => {
                r.kind = EventKind::Health;
                r.health = Some(h.clone());
            }
            Event::Oom => {}
            Event::Settled(s) => {
                r.kind = EventKind::Settled;
                r.settled = Some(s.clone());
            }
        }
        r
    }
}

impl EventRecord {
    /// The event, if the record has what its kind needs.
    pub fn into_event(self) -> Option<super::proto::Event> {
        use super::proto::Event;
        Some(match self.kind {
            EventKind::Started => Event::Started {
                pid: self.pid?,
                started_ns: self.started_ns?,
                restart_count: self.restart_count.unwrap_or(0),
                restarted: self.restarted.unwrap_or(false),
            },
            EventKind::Exited => Event::Exited(self.exit?),
            EventKind::Restarting => Event::Restarting {
                exit: self.exit?,
                restart_count: self.restart_count?,
            },
            EventKind::Health => Event::Health(self.health?),
            EventKind::Oom => Event::Oom,
            EventKind::Settled => Event::Settled(self.settled?),
        })
    }
}

/// What `org.varlink.service.GetInterfaceDescription` is asked.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct InterfaceParams {
    #[serde(default)]
    pub interface: String,
}

/// A call of the interface as a type: [`Method`], and whether it is one of
/// the core, which a client makes whatever the digest of the monitor's
/// definition.
pub trait Rpc: Method {
    /// Core calls mean the same in every version of the monitor with
    /// `GetInfo.core` [`CORE`].
    const CORE: bool = false;
    /// The reply comes when something happens (the container exits), not
    /// within a bound.
    const WAITS: bool = false;
}

/// `impl Method` and `impl Rpc` of a request: the one place a method of the
/// interface is named.  The flags: `more` (the call answers more than once),
/// `core` (a core call), `waits` (the reply comes when something happens,
/// not within a bound: a stop, a wait).
macro_rules! call {
    ($ty:ident, $name:literal, $reply:ty $(, $flag:ident)*) => {
        impl Method for $ty {
            const INTERFACE: &'static str = INTERFACE;
            const NAME: &'static str = $name;
            $(call!(@method $flag);)*
            type Reply = $reply;
        }
        impl Rpc for $ty {
            $(call!(@call $flag);)*
        }
    };
    (@method more) => { const MORE: bool = true; };
    (@method core) => {};
    (@method waits) => {};
    (@call core) => { const CORE: bool = true; };
    (@call waits) => { const WAITS: bool = true; };
    (@call more) => {};
}

/// A call with no parameters.
macro_rules! bare {
    ($ty:ident, $name:literal, $reply:ty $(, $flag:ident)*) => {
        #[doc = concat!("The call `", $name, "`: no parameters.")]
        #[derive(Debug, Clone, Default, Serialize, Deserialize)]
        pub struct $ty {}
        call!($ty, $name, $reply $(, $flag)*);
    };
}

bare!(GetInfo, "GetInfo", Info, core);
bare!(GetCoreStatus, "GetCoreStatus", CoreStatusReply, core);
bare!(GetStatus, "GetStatus", StatusReply);
bare!(Wait, "Wait", CoreStatusReply, core, waits);
bare!(Pause, "Pause", StatusReply);
bare!(Resume, "Resume", StatusReply);
bare!(Quit, "Quit", Empty);
bare!(RunHealthCheck, "RunHealthCheck", HealthReply);
bare!(ReopenLog, "ReopenLog", Empty);
bare!(CloseStdin, "CloseStdin", Empty);
bare!(OpenInit, "OpenInit", InitReply);
bare!(Detach, "Detach", Empty);
bare!(Subscribe, "Subscribe", Subscribed, more);
call!(CreateParams, "Create", StatusReply);
call!(StartParams, "Start", StartReply);
call!(StopParams, "Stop", StopReply, core, waits);
call!(RemoveParams, "Remove", StatusReply, waits);
call!(KillParams, "Kill", Empty, core);
call!(CheckpointRequest, "Checkpoint", StatusReply);
call!(MonitorUpdate, "Update", Empty);
call!(Attach, "Attach", AttachReply, more);
call!(ExecRequest, "Exec", ExecReply, more);
call!(ResizeParams, "Resize", Empty);
call!(SignalParams, "Signal", Empty);

/// A call to the monitor, its parameters parsed.
#[derive(Debug)]
pub enum Request {
    GetInfo,
    Create(CreateParams),
    Subscribe,
    Status,
    Start(StartParams),
    Stop(StopParams),
    Remove(RemoveParams),
    Kill(KillParams),
    Wait,
    CoreStatus,
    Pause,
    Resume,
    Quit,
    Checkpoint(CheckpointRequest),
    Update(MonitorUpdate),
    RunHealthCheck,
    ReopenLog,
    Attach(Attach),
    Exec(ExecRequest),
    Resize(ResizeParams),
    Signal(SignalParams),
    CloseStdin,
    Detach,
    OpenInit,
    ServiceGetInfo,
    ServiceGetInterfaceDescription(InterfaceParams),
}

/// A call: what it asks (or why it cannot be done), and how it wants the
/// answer.
#[derive(Debug)]
pub struct Call {
    pub request: Result<Request, Refusal>,
    /// The caller takes several replies.
    pub more: bool,
    /// The caller takes no reply.
    pub oneway: bool,
}

/// Why a call is one the monitor cannot do.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A method the monitor does not have: `MethodNotFound`.
    MethodNotFound(String),
    /// Parameters that do not fit: `InvalidParameter`.
    InvalidParameter(String),
}

fn refusal(b: BadCall) -> Refusal {
    match b {
        BadCall::NotACall(m) | BadCall::InvalidParameter(m) => Refusal::InvalidParameter(m),
    }
}

/// Parse one message a client sent (the bytes before its NUL); an error is
/// a message that is no call at all (the connection ends).
pub fn parse_request(bytes: &[u8]) -> Result<Call, String> {
    let head = parse_call(bytes).map_err(|e| match e {
        BadCall::NotACall(m) | BadCall::InvalidParameter(m) => m,
    })?;
    let request = if head.upgrade {
        Err(Refusal::InvalidParameter("upgrade".into()))
    } else {
        request_of(&head.method, bytes)
    };
    Ok(Call {
        request,
        more: head.more,
        oneway: head.oneway,
    })
}

fn params<T: serde::de::DeserializeOwned + Default>(bytes: &[u8]) -> Result<T, Refusal> {
    call_parameters(bytes).map_err(refusal)
}

fn request_of(name: &str, bytes: &[u8]) -> Result<Request, Refusal> {
    let own = name
        .strip_prefix(INTERFACE)
        .and_then(|rest| rest.strip_prefix('.'));
    Ok(match (name, own) {
        (service::GET_INFO, _) => Request::ServiceGetInfo,
        (service::GET_INTERFACE_DESCRIPTION, _) => {
            Request::ServiceGetInterfaceDescription(params(bytes)?)
        }
        (_, Some(GetInfo::NAME)) => Request::GetInfo,
        (_, Some(CreateParams::NAME)) => Request::Create(params(bytes)?),
        (_, Some(Subscribe::NAME)) => Request::Subscribe,
        (_, Some(GetStatus::NAME)) => Request::Status,
        (_, Some(StartParams::NAME)) => Request::Start(params(bytes)?),
        (_, Some(StopParams::NAME)) => Request::Stop(params(bytes)?),
        (_, Some(RemoveParams::NAME)) => Request::Remove(params(bytes)?),
        (_, Some(KillParams::NAME)) => Request::Kill(params(bytes)?),
        (_, Some(Wait::NAME)) => Request::Wait,
        (_, Some(GetCoreStatus::NAME)) => Request::CoreStatus,
        (_, Some(Pause::NAME)) => Request::Pause,
        (_, Some(Resume::NAME)) => Request::Resume,
        (_, Some(Quit::NAME)) => Request::Quit,
        (_, Some(CheckpointRequest::NAME)) => Request::Checkpoint(params(bytes)?),
        (_, Some(MonitorUpdate::NAME)) => Request::Update(params(bytes)?),
        (_, Some(RunHealthCheck::NAME)) => Request::RunHealthCheck,
        (_, Some(ReopenLog::NAME)) => Request::ReopenLog,
        (_, Some(Attach::NAME)) => Request::Attach(params(bytes)?),
        (_, Some(ExecRequest::NAME)) => Request::Exec(params(bytes)?),
        (_, Some(ResizeParams::NAME)) => Request::Resize(params(bytes)?),
        (_, Some(SignalParams::NAME)) => Request::Signal(params(bytes)?),
        (_, Some(CloseStdin::NAME)) => Request::CloseStdin,
        (_, Some(Detach::NAME)) => Request::Detach,
        (_, Some(OpenInit::NAME)) => Request::OpenInit,
        _ => {
            return Err(Refusal::MethodNotFound(
                name.chars().take(256).collect::<String>(),
            ))
        }
    })
}

/// The reply of `org.varlink.service.GetInfo`.
#[derive(Debug, Serialize)]
pub struct ServiceInfo {
    pub vendor: &'static str,
    pub product: &'static str,
    pub version: &'static str,
    pub url: &'static str,
    pub interfaces: [&'static str; 2],
}

/// The reply of `org.varlink.service.GetInterfaceDescription`.
#[derive(Debug, Serialize)]
pub struct Description {
    pub description: &'static str,
}

/// The parameter of `InvalidParameter`.
#[derive(Debug, Serialize)]
pub struct InvalidParameter<'a> {
    pub parameter: &'a str,
}

/// The parameter of `MethodNotFound` and `ExpectedMore`.
#[derive(Debug, Serialize)]
pub struct MethodName<'a> {
    pub method: &'a str,
}

/// The parameter of `InterfaceNotFound`.
#[derive(Debug, Serialize)]
pub struct InterfaceName<'a> {
    pub interface: &'a str,
}

#[cfg(test)]
mod tests {
    use super::super::proto::{
        CoreState, ExitPlan, HealthResult, HealthStatus, HealthUpdate, RestartPolicy,
        RestartSettings, RestartUpdate, RestoreRequest, RunState, Settled,
    };
    use super::*;
    use zlink_core::idl;
    use zlink_core::introspect::CustomType;

    /// The fields of a parameter or reply struct, as the parameters of a
    /// method.
    fn fields<T: CustomType>() -> Vec<idl::Parameter<'static>> {
        match T::CUSTOM_TYPE {
            idl::CustomType::Object(o) => o.fields().cloned().collect(),
            idl::CustomType::Enum(_) => panic!("parameters are an object"),
        }
    }

    fn comments(text: &'static str) -> Vec<idl::Comment<'static>> {
        text.lines().map(idl::Comment::new).collect()
    }

    fn method<I: CustomType, O: CustomType>(
        name: &'static str,
        doc: &'static str,
    ) -> idl::Method<'static> {
        idl::Method::new_owned(name, fields::<I>(), fields::<O>(), comments(doc))
    }

    fn reason_error(name: &'static str, doc: &'static str) -> idl::Error<'static> {
        static REASON: idl::Field<'static> = idl::Field::new("reason", &idl::Type::String, &[]);
        idl::Error::new_owned(name, vec![REASON.clone()], comments(doc))
    }

    /// The definition, from the types.
    fn definition() -> String {
        let types = vec![
            RestoreRequest::CUSTOM_TYPE.clone(),
            CoreState::CUSTOM_TYPE.clone(),
            CoreStatus::CUSTOM_TYPE.clone(),
            ExitPlan::CUSTOM_TYPE.clone(),
            Settled::CUSTOM_TYPE.clone(),
            velarx_proto::transfer::Failure::CUSTOM_TYPE.clone(),
            velarx_proto::transfer::FailureClass::CUSTOM_TYPE.clone(),
            RestartUpdate::CUSTOM_TYPE.clone(),
            HealthUpdate::CUSTOM_TYPE.clone(),
            Status::CUSTOM_TYPE.clone(),
            RunState::CUSTOM_TYPE.clone(),
            ExitInfo::CUSTOM_TYPE.clone(),
            Health::CUSTOM_TYPE.clone(),
            HealthResult::CUSTOM_TYPE.clone(),
            HealthStatus::CUSTOM_TYPE.clone(),
            EventRecord::CUSTOM_TYPE.clone(),
            EventKind::CUSTOM_TYPE.clone(),
            ImageChange::CUSTOM_TYPE.clone(),
            ImageName::CUSTOM_TYPE.clone(),
            ExecExit::CUSTOM_TYPE.clone(),
            ExecReason::CUSTOM_TYPE.clone(),
            SessionPhase::CUSTOM_TYPE.clone(),
            RestartPolicy::CUSTOM_TYPE.clone(),
            RestartSettings::CUSTOM_TYPE.clone(),
            velarx_proto::health::Healthcheck::CUSTOM_TYPE.clone(),
            velarx_proto::health::StartupHealthcheck::CUSTOM_TYPE.clone(),
            velarx_proto::health::OnFailure::CUSTOM_TYPE.clone(),
        ];
        let methods = vec![
            method::<Empty, Info>(
                "GetInfo",
                "Who the monitor is.  (Core.)  `core`: the version of the core (1).  A\n\
                 client calls it first: it makes the core calls when `core` is the one it\n\
                 speaks, the others when `digest` is the one of the definition it speaks.",
            ),
            method::<Empty, CoreStatusReply>("GetCoreStatus", "(Core.)"),
            method::<StopParams, StopReply>(
                "Stop",
                "Stop the container (core): no restart for the exit that follows, a restart\n\
                 that waits is not made.  `signal` (none: the container's stop signal)\n\
                 through the pidfd of the init, then SIGKILL after `timeout_ms` (none: the\n\
                 container's stop timeout; 0: SIGKILL at once).  The monitor owns the\n\
                 deadline: a client that goes away does not stop it.  The reply comes when\n\
                 the container exited and its exit is recorded; a Stop of a container that\n\
                 exited already is answered at once, a Stop during a Stop joins it (the\n\
                 earlier deadline).  `killed`: SIGKILL was needed.  `InvalidState` for a\n\
                 container that was not started.",
            ),
            method::<RemoveParams, StatusReply>(
                "Remove",
                "Remove the container: with `force` a running one is stopped first (as\n\
                 `Stop` with `timeout_ms`; none: 0), else `InvalidState`; the plan becomes\n\
                 `remove` with `volumes`.  The reply comes once it is removed (its `status`\n\
                 says `settled`), or the removal failed (`Failed`: the container stays\n\
                 listed).  A container that was removed is answered at once.",
            ),
            method::<KillParams, Empty>(
                "Kill",
                "Send `signal` to the init through its pidfd (core).  The exit that follows\n\
                 is not restarted (a kill of a user is a stop).  `NotRunning` when it does\n\
                 not run.",
            ),
            method::<Empty, CoreStatusReply>(
                "Wait",
                "The reply comes when the container exited for good (no restart follows)\n\
                 and its exit is recorded; at once when that is so already.  (Core.)",
            ),
            method::<CreateParams, StatusReply>(
                "Create",
                "The first call of the boot connection (`--varlink-fd`), once: create the\n\
                 container with the runtime, or restore it with `restore` (`image_dir`: the\n\
                 directory of the images, among the descriptors of the call).  The reply is\n\
                 the result of the creation (`Failed` when the runtime failed, and the monitor\n\
                 ends).  After it the connection is an ordinary one.  `InvalidState` as any\n\
                 other call, or as a second one.",
            ),
            method::<Empty, Subscribed>(
                "Subscribe",
                "With `more`: the status of the container, then a reply for every\n\
                 event.  The monitor records them itself (its store, its events): a\n\
                 subscriber only observes.",
            ),
            method::<Empty, StatusReply>("GetStatus", "What the monitor knows of the container."),
            method::<StartParams, StartReply>(
                "Start",
                "Start the container the runtime created (`InvalidState` when it\n\
                 ran already); a container waiting to be restarted starts now.",
            ),
            method::<Empty, Empty>(
                "Quit",
                "End the monitor of a container that was created and not started;\n\
                 `InvalidState` in any other state.",
            ),
            method::<CheckpointRequest, StatusReply>(
                "Checkpoint",
                "Checkpoint the running container with the runtime (CRIU).",
            ),
            method::<MonitorUpdate, Empty>(
                "Update",
                "Change what is given: the restart policy, the health check, the\n\
                 resources (`resources`: a sealed memory file with the OCI\n\
                 `linux.resources` JSON, which the monitor gives the runtime's update; the\n\
                 runtime's refusal is `InvalidArgument`), the exit plan.",
            ),
            method::<Empty, StatusReply>(
                "Pause",
                "Freeze the container with the runtime (`InvalidState` when it does not\n\
                 run); the health checks wait while it is paused.",
            ),
            method::<Empty, StatusReply>(
                "Resume",
                "Thaw a paused container (`InvalidState` else).",
            ),
            method::<Empty, HealthReply>(
                "RunHealthCheck",
                "Run the health check now; the reply comes with its result.",
            ),
            method::<Empty, Empty>(
                "ReopenLog",
                "Open the log file again (it was rotated by somebody else).",
            ),
            method::<Attach, AttachReply>(
                "Attach",
                "With `more`: the streams of the container (first reply), its\n\
                 exit status (last reply).  `start` starts a container that waits for\n\
                 its first client.  Closing the connection detaches.",
            ),
            method::<ExecRequest, ExecReply>(
                "Exec",
                "With `more`: run a command in the container, its streams\n\
                 (first reply), its start (with `notify_start`), its end (last reply).\n\
                 Closing the connection detaches: the command goes on, its output dropped.",
            ),
            method::<ResizeParams, Empty>(
                "Resize",
                "The size of the terminal: `oneway` on the connection of an `Attach`\n\
                 or `Exec` (of that session), or alone (the container's);\n\
                 `InvalidState` without a terminal.",
            ),
            method::<SignalParams, Empty>(
                "Signal",
                "A signal to the command: `oneway` on the connection of an `Exec`.\n\
                 `InvalidState` elsewhere (a container gets `Kill`).",
            ),
            method::<Empty, Empty>(
                "CloseStdin",
                "`oneway` on the connection of an `Attach` or `Exec`: the input ends\n\
                 once its stream is read to its end (a stream closed without it is a client\n\
                 that went away).",
            ),
            method::<Empty, InitReply>(
                "OpenInit",
                "A pidfd of the init of the running container (`NotRunning` else):\n\
                 what is done to its process (its network namespace) is done to it,\n\
                 not to a process that got its number.",
            ),
            method::<Empty, Empty>(
                "Detach",
                "`oneway` on the connection of an `Exec`: its output is dropped from now\n\
                 on (the command goes on, as when the connection closes).",
            ),
        ];
        let errors = vec![
            reason_error(
                "NotRunning",
                "The container does not run (exec, checkpoint, a health check).",
            ),
            reason_error(
                "InvalidState",
                "The container is not in the state the call needs.",
            ),
            reason_error("NoHealthCheck", "The container has no health check."),
            reason_error(
                "InvalidArgument",
                "A value of the call that cannot be (an empty command, a signal out of\n\
                 range).",
            ),
            reason_error("Failed", "The runtime or the system failed."),
            reason_error(
                "NotStarted",
                "The runtime could not be started for the command of an exec (a user it runs\n\
                 as that is not there, a runtime or a bundle that is gone): the engine's\n\
                 condition NotStarted.",
            ),
        ];
        let header = "# SPDX-License-Identifier: Apache-2.0\n\
             #\n\
             # The interface org.velarx.Monitor: the monitor of one container\n\
             # (velarx-monitor), on the socket monitor.sock of the container's run\n\
             # directory; the engine is its client (and the attach of a process that is\n\
             # its own monitor).\n\
             # Generated from the Rust types (crates/wire/src/monitor/iface.rs and\n\
             # proto.rs) by the test `monitor::iface::tests::the_interface_file_is_current`:\n\
             # VELARX_WRITE_INTERFACES=1 cargo test -p velarx-wire --lib monitor::iface\n\
             # writes it.\n\
             #\n\
             # CORE.  GetInfo, GetCoreStatus, Stop, Kill and Wait, and the types CoreState\n\
             # and CoreStatus, have this definition in every version of the monitor whose\n\
             # GetInfo answers `core` 1.  A client may make them whatever the `digest`;\n\
             # every other call needs the `digest` of the definition it speaks.  A monitor\n\
             # lives as long as its container, across upgrades of the engine.\n\
             #\n\
             # The streams are one-way stream sockets (the input of a command without a\n\
             # terminal is the pipe of its input) whose descriptors cross in the\n\
             # SCM_RIGHTS of the first reply of Attach and Exec, named in the JSON by\n\
             # their position among them.  The call Exec carries in its SCM_RIGHTS the\n\
             # descriptors the command gets as 3, 4, ... (`preserve_fds` of them, less\n\
             # the `preserve_holes`).\n\
             #\n\
             # While a call with `more` is answered, the other calls on its connection\n\
             # are `oneway` (Resize, Signal, CloseStdin, Detach).  Closing the\n\
             # connection leaves the session: a command goes on (Signal ends it).\n\
             # Who may call: a peer of the same user or root (SO_PEERCRED); any\n\
             # accepted peer may make every call.\n\n";
        let interface = idl::Interface::new_owned(INTERFACE, methods, types, errors, Vec::new());
        format!("{header}{interface}\n")
    }

    /// The file is made from the types: when they change it changes.
    #[test]
    fn the_interface_file_is_current() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../interfaces/org.velarx.Monitor.varlink");
        let text = definition();
        if std::env::var_os("VELARX_WRITE_INTERFACES").is_some() {
            std::fs::write(&path, &text).unwrap();
        }
        assert!(
            DEFINITION == text,
            "{} is not what the types make; run VELARX_WRITE_INTERFACES=1 cargo test -p \
             velarx-wire --lib monitor::iface and commit it",
            path.display()
        );
    }

    /// Every method of the definition is one the monitor parses, and a
    /// method it does not know is told.
    #[test]
    fn every_method_parses() {
        for line in DEFINITION.lines() {
            let Some(rest) = line.strip_prefix("method ") else {
                continue;
            };
            let name = &rest[..rest.find('(').unwrap()];
            let call = format!("{{\"method\":\"{INTERFACE}.{name}\",\"parameters\":{{}}}}");
            let parsed = parse_request(call.as_bytes()).unwrap().request;
            match name {
                // (parameters without a default)
                "Kill" | "Checkpoint" | "Exec" | "Resize" | "Signal" => {
                    assert!(
                        matches!(parsed, Err(Refusal::InvalidParameter(_))),
                        "{name}: {parsed:?}"
                    )
                }
                _ => assert!(parsed.is_ok(), "{name}: {parsed:?}"),
            }
        }
        assert_eq!(
            parse_request(br#"{"method":"org.velarx.Monitor.Nope","oneway":true}"#)
                .unwrap()
                .request
                .unwrap_err(),
            Refusal::MethodNotFound("org.velarx.Monitor.Nope".into())
        );
        assert!(parse_request(b"{\"parameters\":{}}").is_err());
        assert!(parse_request(b"[1,2]").is_err());
        assert_eq!(
            parse_request(br#"{"method":"org.velarx.Monitor.Signal","parameters":{"signal":"x"}}"#)
                .unwrap()
                .request
                .unwrap_err(),
            Refusal::InvalidParameter("parameters".into())
        );
        assert_eq!(
            parse_request(br#"{"method":"org.velarx.Monitor.Status","upgrade":true}"#)
                .unwrap()
                .request
                .unwrap_err(),
            Refusal::InvalidParameter("upgrade".into())
        );
        let call = parse_request(
            br#"{"method":"org.velarx.Monitor.Exec","more":true,"parameters":{"command":["ls"],"tty":true}}"#,
        )
        .unwrap();
        assert!(call.more && !call.oneway);
        assert!(matches!(call.request, Ok(Request::Exec(r)) if r.command == ["ls"] && r.tty));
        let call =
            parse_request(br#"{"method":"org.velarx.Monitor.Resize","oneway":true,"parameters":{"rows":24,"cols":80}}"#)
                .unwrap();
        assert!(call.oneway);
        assert!(matches!(call.request, Ok(Request::Resize(r)) if (r.rows, r.cols) == (24, 80)));
    }

    /// Every method the interface defines has exactly one request type, with
    /// its parameters as fields; no request type is a method it does not
    /// define.
    #[test]
    fn every_method_has_one_request_with_its_parameters() {
        use std::collections::BTreeSet;
        fn of<M: Rpc>(m: &M) -> (&'static str, Vec<String>) {
            let value = serde_json::to_value(m).unwrap();
            let keys = value
                .as_object()
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default();
            (M::NAME, keys)
        }
        let served = vec![
            of(&GetInfo {}),
            of(&GetCoreStatus {}),
            of(&StopParams {
                signal: Some(1),
                timeout_ms: Some(1),
            }),
            of(&KillParams { signal: 1 }),
            of(&Wait {}),
            of(&CreateParams {
                restore: Some(Default::default()),
            }),
            of(&Subscribe {}),
            of(&GetStatus {}),
            of(&StartParams::default()),
            of(&Pause {}),
            of(&Resume {}),
            of(&RemoveParams {
                force: true,
                timeout_ms: Some(0),
                volumes: true,
            }),
            of(&Quit {}),
            of(&CheckpointRequest::default()),
            of(&MonitorUpdate {
                restart: Some(Default::default()),
                health: Some(Default::default()),
                resources: Some(0),
                plan: Some(Default::default()),
            }),
            of(&RunHealthCheck {}),
            of(&ReopenLog {}),
            of(&Attach::default()),
            of(&ExecRequest::default()),
            of(&ResizeParams::default()),
            of(&SignalParams::default()),
            of(&CloseStdin {}),
            of(&OpenInit {}),
            of(&Detach {}),
        ];
        let described = crate::varlink::described_methods(DEFINITION);
        for (name, params) in &described {
            let found: Vec<_> = served.iter().filter(|(n, _)| n == name).collect();
            assert_eq!(found.len(), 1, "{name} has {} request types", found.len());
            let have: BTreeSet<_> = found[0].1.iter().cloned().collect();
            let want: BTreeSet<_> = params.iter().cloned().collect();
            assert_eq!(have, want, "the fields of the request {name}");
        }
        for (name, _) in &served {
            assert!(described.iter().any(|(n, _)| n == name), "{name}");
        }
        // the core is what the header says it is
        const {
            assert!(<GetInfo as Rpc>::CORE && <GetCoreStatus as Rpc>::CORE);
            assert!(<StopParams as Rpc>::CORE && <KillParams as Rpc>::CORE && <Wait as Rpc>::CORE);
            assert!(!<GetStatus as Rpc>::CORE && !<Attach as Rpc>::CORE);
        }
    }

    /// An event goes through its record and back.
    #[test]
    fn events_round_trip() {
        use super::super::proto::Event;
        let exit = ExitInfo {
            code: 3,
            finished_ns: 9,
            oom: false,
            health_restart: false,
            stop_requested: true,
            timed_out: false,
            checkpointed: false,
            started_ns: Some(4),
            remove: false,
            volumes: false,
        };
        for e in [
            Event::Started {
                pid: 7,
                started_ns: 1,
                restart_count: 2,
                restarted: true,
            },
            Event::Exited(exit.clone()),
            Event::Restarting {
                exit,
                restart_count: 1,
            },
            Event::Health(Health::default()),
            Event::Oom,
            Event::Settled(Settled {
                recorded: true,
                removed: true,
                failure: None,
                image: Some(ImageChange {
                    id: "abc".into(),
                    names: vec![ImageName {
                        repository: "localhost/x".into(),
                        tag: "@sha256:1".into(),
                    }],
                    removed: true,
                }),
            }),
        ] {
            let text = serde_json::to_string(&EventRecord::from(&e)).unwrap();
            let back: EventRecord = serde_json::from_str(&text).unwrap();
            assert_eq!(back.into_event(), Some(e));
        }
        // a kind without what it needs is no event
        let r: EventRecord = serde_json::from_str(r#"{"kind":"exited"}"#).unwrap();
        assert_eq!(r.into_event(), None);
        let r: EventRecord = serde_json::from_str(r#"{"kind":"settled"}"#).unwrap();
        assert_eq!(r.into_event(), None);
    }

    #[test]
    fn the_digest_tells_definitions_apart() {
        assert_eq!(interface_digest(), digest(DEFINITION));
        assert_ne!(digest("interface a"), digest("interface b"));
        assert_eq!(digest("").len(), 16);
    }
}
