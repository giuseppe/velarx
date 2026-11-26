// SPDX-License-Identifier: Apache-2.0
//! Exec sessions: create, start (hijacked), inspect, resize, remove.
//!
//! The command runs through the monitor of the container; the streams of a
//! command with a client go to its frontend, which copies them.

use super::error::{ApiError, ApiResult, Kind};
use super::lifecycle;
use crate::api::AppState;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use velarx_core::services::ExecEvent;
use velarx_proto::engine::Condition;
use velarx_proto::stream::{Event, Out};
use velarx_proto::workload::{ExecRecord, ExecSpec, RunState};
use velarx_wire::monitor::proto::ExecRequest;

/// Signals and sizes of a session that wait for the command: a client
/// that sends more than this at once is refused (signals) or ignored (sizes).
const QUEUED: usize = 64;

/// Where a session is: made, taken by a start, running, or ended.
#[derive(Default)]
enum Phase {
    /// Made, or a start that did not get to run the command left it so
    #[default]
    Created,
    /// Taken by a start that checks the container
    Starting,
    Running {
        /// Where the size of the terminal of the session is changed.
        resize: Option<mpsc::Sender<(u16, u16)>>,
        /// Where a signal for the command of the session goes.
        signal: Option<mpsc::Sender<i32>>,
    },
    Exited {
        code: i32,
        at: std::time::Instant,
    },
}

#[derive(Default)]
struct ExecState {
    phase: Phase,
    /// Why the command could not be run (`errors_apart`).
    error: Option<String>,
}

impl ExecState {
    fn running(&self) -> bool {
        matches!(self.phase, Phase::Running { .. })
    }
}

pub struct Session {
    id: String,
    container: String,
    cmd: Vec<String>,
    env: Vec<String>,
    user: String,
    workdir: String,
    detach_keys: String,
    tty: bool,
    stdin: bool,
    stdout: bool,
    stderr: bool,
    privileged: bool,
    timeout_ms: Option<u64>,
    /// The reason it cannot be run is kept in the record, not written to
    /// the output.
    errors_apart: bool,
    /// The environment of the container sets TERM.
    container_term: bool,
    state: Mutex<ExecState>,
}

impl Session {
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The command ended at least `kept` ago.
    pub fn ended_before(&self, kept: std::time::Duration) -> bool {
        matches!(self.st().phase, Phase::Exited { at, .. } if at.elapsed() >= kept)
    }

    fn st(&self) -> std::sync::MutexGuard<'_, ExecState> {
        match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }
}

fn session(state: &AppState, id: &str) -> ApiResult<Arc<Session>> {
    state
        .podman
        .exec_session(id)
        .ok_or_else(|| ApiError::not_found(format!("no exec session with ID {id} found")))
}

/// Create the session of `spec`: its id.
pub async fn create_of(state: &Arc<AppState>, name: &str, spec: &ExecSpec) -> ApiResult<String> {
    let rec = lifecycle::resolve(state, name).await?;
    let status = lifecycle::status(state, &rec).await;
    if !status.alive() || status.state == RunState::Paused {
        return Err(ApiError::invalid_state(
            "can only create exec sessions on running containers: container state improper",
        )
        .with_cause("container state improper"));
    }
    let keys = spec.detach_keys.as_str();
    if !keys.is_empty() {
        velarx_proto::stream::parse_detach_keys(keys)
            .map_err(|_| ApiError::bad_request(format!("Invalid detach keys ({keys}) provided")))?;
    }
    let cmd = spec.command.clone();
    if cmd.is_empty() {
        return Err(ApiError::bad_request(
            "must provide a non-empty command to start an exec session",
        ));
    }
    let id = velarx_core::services::new_id();
    let sess = Arc::new(Session {
        id: id.clone(),
        container: rec.id.clone(),
        cmd,
        env: spec.env.iter().map(|(k, v)| format!("{k}={v}")).collect(),
        user: spec.user.clone(),
        workdir: spec.work_dir.clone(),
        detach_keys: spec.detach_keys.clone(),
        tty: spec.tty,
        stdin: spec.stdin,
        stdout: spec.stdout,
        stderr: spec.stderr,
        privileged: spec.privileged,
        timeout_ms: spec.timeout_ms.and_then(|t| u64::try_from(t).ok()),
        errors_apart: spec.errors_apart,
        container_term: lifecycle::config_of(&rec)?
            .env
            .iter()
            .any(|e| e.starts_with("TERM=")),
        state: Mutex::new(ExecState::default()),
    });
    state.podman.add_exec_session(sess);
    state.podman.events.emit(
        velarx_wire::events::container_event(&rec.id, &rec.name.unwrap_or_default(), "exec")
            .attr("execID", id.clone()),
    );
    Ok(id)
}

/// The record of an exec session, as the typed `ExecInspect` answers it.
pub fn record_of(state: &AppState, id: &str) -> ApiResult<ExecRecord> {
    Ok(session(state, id)?.record())
}

impl Session {
    fn record(&self) -> ExecRecord {
        let st = self.st();
        ExecRecord {
            id: self.id.clone(),
            container_id: self.container.clone(),
            running: st.running(),
            // (none until the command ended)
            exit_code: match st.phase {
                Phase::Exited { code, .. } => Some(i64::from(code)),
                _ => None,
            },
            // (the monitor does not tell it)
            pid: 0,
            command: self.cmd.clone(),
            user: self.user.clone(),
            tty: self.tty,
            stdin: self.stdin,
            stdout: self.stdout,
            stderr: self.stderr,
            privileged: self.privileged,
            detach_keys: self.detach_keys.clone(),
            error: st.error.clone(),
        }
    }
}

/// `detach`: the command outlives this service (podman's `Detach`).
fn exec_request(sess: &Session, stdin: bool, tty: bool, detach: bool) -> ExecRequest {
    let mut env = sess.env.clone();
    // a terminal has a type, as podman sets it, unless the container's
    // or the session's environment says it
    if tty && !sess.container_term && !env.iter().any(|e| e.starts_with("TERM=")) {
        env.push("TERM=xterm".into());
    }
    ExecRequest {
        command: sess.cmd.clone(),
        env,
        cwd: Some(sess.workdir.clone()).filter(|w| !w.is_empty()),
        user: Some(sess.user.clone()).filter(|u| !u.is_empty()),
        tty,
        stdin,
        timeout_ms: sess.timeout_ms,
        privileged: sess.privileged,
        detach,
        notify_start: false,
        ..Default::default()
    }
}

fn exec_error(e: velarx_core::services::ContainerError) -> ApiError {
    match e {
        velarx_core::services::ContainerError::NotRunning(id) => ApiError::invalid_state(format!(
            "cannot exec: container {id} is not running: container state improper"
        )),
        e @ (velarx_core::services::ContainerError::MonitorLost(_)
        | velarx_core::services::ContainerError::MonitorVersion { .. }) => e.into(),
        e => {
            let condition = e.condition();
            let error = ApiError::internal(format!("exec: {e}"));
            match condition {
                Some(c) => error.with_condition(c),
                None => error,
            }
        }
    }
}

/// Start the command of the session in its container.
async fn open(
    state: &Arc<AppState>,
    sess: &Session,
    stdin: bool,
    tty: bool,
    detach: bool,
) -> ApiResult<velarx_core::services::ExecStream> {
    state
        .container_service
        .exec_stream(&sess.container, &exec_request(sess, stdin, tty, detach))
        .await
        .map_err(exec_error)
}

/// The status a command gets when its session could not be followed to the
/// end: 127 when the monitor said the command is not there, else 126.
fn failed_status(condition: Option<Condition>) -> i32 {
    if condition == Some(Condition::CommandNotFound) {
        127
    } else {
        126
    }
}

/// Follow the command of the session until it ends, and record how.  Its
/// output is not read here: a client's frontend has the streams (`channel`
/// is its end of the session), and the output of a command nobody follows
/// is dropped by the monitor.  A client that detaches or goes away leaves
/// the command running, as podman's: it is followed to its end, its status
/// recorded.
async fn follow(
    sess: &Arc<Session>,
    mut stream: velarx_core::services::ExecStream,
    mut channel: Option<Out>,
    size: (u16, u16),
    busy: Option<velarx_content::activation::Busy>,
) {
    let mut busy = busy;
    if sess.tty && size.0 > 0 && size.1 > 0 {
        let _ = stream.resize(size.0, size.1).await;
    }
    let (resize_tx, mut resize_rx) = mpsc::channel::<(u16, u16)>(QUEUED);
    let (signal_tx, mut signal_rx) = mpsc::channel::<i32>(QUEUED);
    if let Phase::Running { resize, signal } = &mut sess.st().phase {
        *resize = sess.tty.then_some(resize_tx);
        *signal = Some(signal_tx);
    }
    let code = loop {
        tokio::select! {
            ev = stream.next() => {
                let mut condition = None;
                let said = match ev {
                    // (the status of a command the timeout killed is 124, as
                    // timeout(1) and podman's `exec --timeout` answer it)
                    Ok(Some(ExecEvent::Exit { code, timed_out, .. })) => {
                        break if timed_out { 124 } else { code };
                    }
                    Ok(Some(_)) => continue,
                    Ok(None) => "exec: the monitor went away".to_string(),
                    // (the monitor's words: an exit status it could not have)
                    Err(e) => {
                        condition = velarx_core::services::exec_condition_of(&e);
                        format!("exec: {e}")
                    }
                };
                if sess.errors_apart {
                    sess.st().error = Some(said.strip_prefix("exec: ").unwrap_or(&said).to_string());
                    break 125;
                }
                break match &channel {
                    Some(c) => {
                        let _ = c.send_text(&format!("{said}\n")).await;
                        failed_status(condition)
                    }
                    None => 125,
                };
            }
            ev = async {
                match &channel {
                    Some(c) => c.event().await,
                    None => std::future::pending().await,
                }
            } => match ev {
                Event::Detach | Event::Gone => {
                    // the command goes on: its output is dropped, its status
                    // kept for the inspect of the session
                    let _ = stream.detach().await;
                    channel = None;
                    busy = None;
                }
                Event::InputClosed => {
                    let _ = stream.close_stdin().await;
                }
            },
            Some((h, w)) = resize_rx.recv() => {
                let _ = stream.resize(h, w).await;
            }
            Some(sig) = signal_rx.recv() => {
                let _ = stream.signal(sig).await;
            }
        }
    };
    finish(sess, code);
    if let Some(channel) = channel {
        channel.end(Some(i64::from(code))).await;
    }
    drop(busy);
}

/// What starting a session did.
pub enum ExecStart {
    /// The command runs on its own (`Detach`)
    Detached,
    /// The command runs for the client that attaches
    Attached(AttachedExec),
}

/// A session started for a client: the command is opened when the
/// client's streams are there.
pub struct AttachedExec {
    state: Arc<AppState>,
    sess: Arc<Session>,
    size: (u16, u16),
    /// The descriptors the command gets as 3, 4, ... and the slots that
    /// get none
    preserved: Vec<std::os::fd::OwnedFd>,
    holes: Vec<u32>,
}

impl AttachedExec {
    /// What the frontend is told about the session once it is taken;
    /// `input`: the client can send input.
    pub fn opened(&self, input: bool) -> velarx_proto::engine::SessionOpened {
        let sess = &self.sess;
        // The detach keys of a session with a terminal (Docker's and
        // podman's default when it has none): the client leaves, the command
        // goes on.
        let keys = match sess.detach_keys.as_str() {
            "" => "ctrl-p,ctrl-q",
            k => k,
        };
        velarx_proto::engine::SessionOpened {
            session: String::new(),
            tty: sess.tty,
            stdin: self.takes_input(input),
            stdout: sess.tty || sess.stdout,
            stderr: sess.tty || sess.stderr,
            logs: None,
            detach_keys: if sess.tty {
                velarx_proto::stream::parse_detach_keys(keys).unwrap_or_default()
            } else {
                Vec::new()
            },
            keep_open: false,
        }
    }

    fn takes_input(&self, input: bool) -> bool {
        self.sess.tty || (self.sess.stdin && input)
    }

    /// Run the command and hand its streams to the frontend on `channel`;
    /// follow it until it ends (a client that goes away, even before it got
    /// the streams, leaves it running, as podman's).
    pub async fn drive(
        self,
        channel: Out,
        input: bool,
        busy: Option<velarx_content::activation::Busy>,
    ) {
        let stdin = self.takes_input(input);
        let Self {
            state,
            sess,
            size,
            preserved,
            holes,
        } = self;
        let opened = state
            .container_service
            .exec_handed(
                &sess.container,
                &ExecRequest {
                    preserve_fds: (preserved.len() + holes.len()) as u32,
                    preserve_holes: holes,
                    ..exec_request(&sess, stdin, sess.tty, false)
                },
                preserved,
            )
            .await
            .map_err(exec_error);
        let (stream, streams) = match opened {
            Ok(o) => o,
            Err(e) => {
                if sess.errors_apart {
                    sess.st().error = Some(
                        e.message
                            .strip_prefix("exec: ")
                            .unwrap_or(&e.message)
                            .to_string(),
                    );
                    finish(&sess, 125);
                    return;
                }
                let _ = channel.send_text(&format!("{}\n", e.message)).await;
                finish(&sess, failed_status(e.condition()));
                return;
            }
        };
        let sent = channel
            .send_streams(streams.stdin, streams.stdout, streams.stderr)
            .await;
        // (a frontend that is gone already: the command goes on unfollowed
        // by any client)
        let channel = sent.is_ok().then_some(channel);
        if channel.is_none() {
            let _ = stream.detach().await;
        }
        let busy = busy.filter(|_| channel.is_some());
        follow(&sess, stream, channel, size, busy).await;
    }
}

fn finish(sess: &Session, code: i32) {
    sess.st().phase = Phase::Exited {
        code,
        at: std::time::Instant::now(),
    };
}

/// The start of a session, taken by one caller: checked and taken at once,
/// so that of two starts one runs it.  Dropped before [`Started::run`] (a
/// start refused, or a client that went away meanwhile) it leaves the
/// session as it was: it may be started again.
struct Started<'a>(&'a Session);

impl<'a> Started<'a> {
    fn take(sess: &'a Session) -> ApiResult<Self> {
        let mut st = sess.st();
        if !matches!(st.phase, Phase::Created) {
            return Err(ApiError::invalid_state(format!(
                "exec session {} has already been started: exec session state improper",
                sess.id
            )));
        }
        st.phase = Phase::Starting;
        Ok(Self(sess))
    }

    /// The command runs: the session stays started.
    fn run(self) {
        self.0.st().phase = Phase::Running {
            resize: None,
            signal: None,
        };
    }
}

impl Drop for Started<'_> {
    fn drop(&mut self) {
        let mut st = self.0.st();
        if matches!(st.phase, Phase::Starting) {
            st.phase = Phase::Created;
        }
    }
}

/// Start the session: with `detach` the command runs on its own, else for
/// the client that attaches, with a terminal of `size` (rows, columns; 0:
/// not known).  The errors before the streams are the answer's.
pub async fn start_of(
    state: &Arc<AppState>,
    id: &str,
    detach: bool,
    size: (i64, i64),
    preserved: Vec<std::os::fd::OwnedFd>,
    holes: Vec<u32>,
) -> ApiResult<ExecStart> {
    if detach && (!preserved.is_empty() || !holes.is_empty()) {
        // (a detached command has no client to keep them for)
        return Err(ApiError::bad_request(
            "the descriptors to preserve need an attached session",
        ));
    }
    let sess = session(state, id)?;
    let started = Started::take(&sess)?;
    let checked = async {
        let rec = lifecycle::resolve(state, &sess.container)
            .await
            .map_err(|e| {
                if e.status == 404 {
                    ApiError::no_such(Kind::Container, e.message)
                } else {
                    e
                }
            })?;
        if !lifecycle::status(state, &rec).await.alive() {
            return Err(ApiError::invalid_state(format!(
                "cannot start exec session: container {} is not running: container state improper",
                rec.id
            )));
        }
        // (an answer before the stream is hijacked)
        state.container_service.check_monitor(&rec.id)?;
        Ok(())
    };
    checked.await?;
    let size = (size.0.clamp(0, 65535) as u16, size.1.clamp(0, 65535) as u16);
    started.run();
    if detach {
        // a command that cannot start is the answer's error, as podman's
        let mut stream = match open(state, &sess, false, sess.tty, true).await {
            Ok(st) => st,
            Err(e) => {
                finish(&sess, failed_status(e.condition()));
                return Err(e);
            }
        };
        if let Some((code, message)) = stream.failed_to_start().await {
            finish(&sess, code);
            return Err(ApiError::internal(message));
        }
        tokio::spawn(async move {
            follow(&sess, stream, None, size, None).await;
        });
        return Ok(ExecStart::Detached);
    }
    Ok(ExecStart::Attached(AttachedExec {
        state: state.clone(),
        sess,
        size,
        preserved,
        holes,
    }))
}

pub async fn resize_of(
    state: &Arc<AppState>,
    id: &str,
    h: i64,
    w: i64,
    running: bool,
) -> ApiResult<()> {
    let sess = session(state, id)?;
    // the container of the session must run, unless running (podman's
    // IgnoreNotRunning) says it does not matter
    if !running {
        let rec = super::lifecycle::resolve(state, &sess.container).await?;
        let st = super::lifecycle::status(state, &rec).await;
        if st.state != RunState::Running {
            return Err(ApiError::invalid_state(format!(
                "container {:?} in wrong state {:?}",
                sess.id,
                st.state.as_str()
            )));
        }
    }
    if h > 0 && w > 0 && h <= 65535 && w <= 65535 {
        if let Phase::Running {
            resize: Some(tx), ..
        } = &sess.st().phase
        {
            // (a full queue drops the newest size: the client sends another)
            let _ = tx.try_send((h as u16, w as u16));
        }
    }
    Ok(())
}

pub fn remove_of(state: &AppState, id: &str, force: bool) -> ApiResult<()> {
    let sess = session(state, id)?;
    if sess.st().running() && !force {
        return Err(ApiError::invalid_state(format!(
            "cannot remove exec session {} as it is running: exec session state improper",
            sess.id
        )));
    }
    state.podman.remove_exec_session(&sess.id);
    Ok(())
}

pub fn kill_of(state: &AppState, id: &str, name: &str) -> ApiResult<()> {
    let sess = session(state, id)?;
    let sig = super::lifecycle::parse_signal(name)
        .ok_or_else(|| ApiError::bad_request(format!("invalid signal: {name}")))?;
    let sent = match &sess.st().phase {
        Phase::Running {
            signal: Some(tx), ..
        } => match tx.try_send(sig) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(ApiError::new(
                    429,
                    format!("exec session {}: too many signals are waiting", sess.id),
                ))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        },
        _ => false,
    };
    if !sent {
        return Err(ApiError::invalid_state(format!(
            "exec session {} is not running: exec session state improper",
            sess.id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// The status of a session that could not be followed is the
    /// condition's, never the words that came with it.
    #[test]
    fn the_status_of_a_failed_session_comes_from_the_condition() {
        assert_eq!(failed_status(Some(Condition::CommandNotFound)), 127);
        assert_eq!(failed_status(Some(Condition::NotStarted)), 126);
        assert_eq!(failed_status(None), 126);
        let e = exec_error(velarx_core::services::ContainerError::Runtime(
            velarx_runtime::container::RuntimeError::NotStarted {
                command_missing: false,
                message: "no such file or directory".into(),
            },
        ));
        assert_eq!(failed_status(e.condition()), 126);
        let e = exec_error(velarx_core::services::ContainerError::Runtime(
            velarx_runtime::container::RuntimeError::NotStarted {
                command_missing: true,
                message: "words".into(),
            },
        ));
        assert_eq!(failed_status(e.condition()), 127);
    }

    fn session(id: &str) -> Arc<Session> {
        Arc::new(Session {
            id: id.to_string(),
            container: "c".into(),
            cmd: vec!["true".into()],
            env: Vec::new(),
            user: String::new(),
            workdir: String::new(),
            detach_keys: String::new(),
            tty: false,
            stdin: false,
            stdout: true,
            stderr: true,
            privileged: false,
            timeout_ms: None,
            errors_apart: false,
            container_term: false,
            state: Mutex::new(ExecState::default()),
        })
    }

    /// Of starts of one session at the same time, one takes it; a start
    /// that did not get to run the command (refused, or its client gone)
    /// leaves it to be started again, one that ran keeps it.
    #[test]
    fn one_start_of_a_session_runs_it() {
        let sess = session("s");
        let barrier = std::sync::Barrier::new(8);
        let (taken, refused) = std::thread::scope(|s| {
            let starts: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        barrier.wait();
                        // (the one taken is kept: the others see it)
                        Started::take(&sess).map(std::mem::forget).is_ok()
                    })
                })
                .collect();
            let got: Vec<bool> = starts.into_iter().map(|t| t.join().unwrap()).collect();
            (
                got.iter().filter(|g| **g).count(),
                got.iter().filter(|g| !**g).count(),
            )
        });
        assert_eq!((taken, refused), (1, 7));
        sess.st().phase = Phase::Created;
        drop(Started::take(&sess).unwrap());
        assert!(
            matches!(sess.st().phase, Phase::Created),
            "a start dropped before it ran"
        );
        Started::take(&sess).unwrap().run();
        assert!(sess.st().running());
        assert!(Started::take(&sess).is_err());
        assert!(sess.st().running(), "a refused start changes nothing");
    }

    /// A session has no exit code before its command ended, also while a
    /// start takes it.
    #[test]
    fn a_session_has_an_exit_code_when_its_command_ended() {
        let sess = session("s");
        assert_eq!(sess.record().exit_code, None, "created");
        let start = Started::take(&sess).unwrap();
        assert_eq!(sess.record().exit_code, None, "starting");
        assert!(!sess.record().running);
        start.run();
        let running = sess.record();
        assert_eq!((running.exit_code, running.running), (None, true));
        finish(&sess, 3);
        let ended = sess.record();
        assert_eq!((ended.exit_code, ended.running), (Some(3), false));
        assert!(Started::take(&sess).is_err(), "an ended session is started");
    }

    #[test]
    fn a_session_that_ended_long_ago_goes_when_another_is_made() {
        let podman = super::super::state::PodmanState::default();
        let (old, recent, running) = (session("old"), session("recent"), session("running"));
        finish(&old, 0);
        if let Some(at) = Instant::now().checked_sub(Duration::from_secs(6 * 60)) {
            old.st().phase = Phase::Exited { code: 0, at };
        }
        finish(&recent, 1);
        Started::take(&running).unwrap().run();
        // (each new one checks the others: the old one is the last here)
        for s in [recent, running, old] {
            podman.add_exec_session(s);
        }
        assert!(podman.exec_session("old").is_some());
        podman.add_exec_session(session("new"));
        assert!(podman.exec_session("old").is_none());
        for id in ["recent", "running", "new"] {
            assert!(podman.exec_session(id).is_some(), "{id}");
        }
    }
}
