// SPDX-License-Identifier: Apache-2.0
//! Commands run in containers, through the monitor of the container: the
//! monitor starts them, relays their streams, and kills the process group
//! of a command whose client goes away or whose time is over.

use super::container::{ContainerError, ContainerResult, ContainerService};
use super::lifecycle::conn::{Input, Session, Told};
use std::io;
use std::os::fd::OwnedFd;
use velarx_db::RecordState;
use velarx_proto::engine::Condition;
use velarx_wire::monitor::client;
use velarx_wire::monitor::iface::{error, ExecReason};
use velarx_wire::monitor::proto::ExecRequest;

/// The most output `exec` keeps for each stream.
const MAX_COLLECTED: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum ExecEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    /// The command ended; `timed_out` when the monitor killed it.
    Exit {
        code: i32,
        timed_out: bool,
        /// The runtime started the command (else the status is the
        /// runtime's: it could not).
        started: bool,
    },
}

/// A running command.  Dropping it before its end leaves the command
/// running (its output dropped), as podman's goes on without its client.
pub struct ExecStream {
    session: Session,
    /// The container, as it was named, to tell whose output was dropped.
    container: String,
}

impl ExecStream {
    /// The next event; `None` when the monitor hung up.
    pub async fn next(&mut self) -> io::Result<Option<ExecEvent>> {
        loop {
            return Ok(Some(match self.session.next().await? {
                None => return Ok(None),
                Some(Told::Started) => continue,
                Some(Told::Stdout(d)) => ExecEvent::Stdout(d),
                Some(Told::Stderr(d)) => ExecEvent::Stderr(d),
                Some(Told::End {
                    code,
                    reason,
                    started,
                    output_dropped,
                }) => {
                    if output_dropped {
                        tracing::warn!(
                            "the output of a command in {} was dropped: its reader did not read it \
                             fast enough",
                            self.container
                        );
                    }
                    ExecEvent::Exit {
                        code,
                        timed_out: reason == ExecReason::TimedOut,
                        started,
                    }
                }
            }));
        }
    }

    /// Whether the command could not start: the runtime ended without
    /// having started it, which the monitor tells (the runtime writes the pid
    /// of the command when it starts it).  The status (126, 127) and what
    /// the runtime said, in podman's words.  A command that started is not
    /// waited for.  What was said meanwhile is lost: for a command that
    /// nobody follows.
    pub async fn failed_to_start(&mut self) -> Option<(i32, String)> {
        let mut said = Vec::new();
        let ended = loop {
            match self.session.next().await {
                Ok(Some(Told::Stderr(d))) => said.extend(d),
                Ok(Some(Told::End { code, started, .. })) => break (!started).then_some(code),
                Ok(Some(Told::Started | Told::Stdout(_))) | Ok(None) | Err(_) => break None,
            }
        };
        let said = String::from_utf8_lossy(&said);
        match ended {
            // (the monitor says it in podman's words)
            Some(code @ (126 | 127)) => {
                let said = said.trim();
                Some((
                    code,
                    said.strip_prefix("Error: ").unwrap_or(said).to_string(),
                ))
            }
            _ => None,
        }
    }

    /// The input of the session (written while its output is read, see
    /// [`Input`]); `eof` ends it once that is written.
    pub fn input(&self) -> Input {
        self.session.input()
    }

    pub async fn eof(&self) -> io::Result<()> {
        self.session.eof().await
    }

    /// The input of a session whose streams were handed on ends.
    pub async fn close_stdin(&self) -> io::Result<()> {
        self.session.close_stdin().await
    }

    /// The command goes on without its client.
    pub async fn detach(&self) -> io::Result<()> {
        self.session.detach().await
    }

    pub async fn resize(&self, rows: u16, cols: u16) -> io::Result<()> {
        self.session.resize(rows, cols).await
    }

    pub async fn signal(&self, sig: i32) -> io::Result<()> {
        self.session.signal(sig).await
    }
}

/// The condition of the engine's interface an error of an exec session is,
/// when the monitor said it.
pub fn condition_of(e: &io::Error) -> Option<Condition> {
    client::monitor_error(e).and_then(|m| m.condition())
}

impl ContainerService {
    /// Start a command in a running container.
    pub async fn exec_stream(&self, id: &str, req: &ExecRequest) -> ContainerResult<ExecStream> {
        let opened = self.exec_session(id, req, Vec::new()).await?;
        Ok(ExecStream {
            session: Session::new(opened.conn, opened.streams, true, None)
                .map_err(ContainerError::Io)?,
            container: id.to_string(),
        })
    }

    /// Start a command in a running container and give its pipes (the input,
    /// the output and the errors) to the caller to pass on: the stream
    /// carries the start and the end of the command only.  `fds` are the
    /// descriptors the command gets as 3, 4, ... (`req` says how many slots
    /// there are and which have none).
    pub async fn exec_handed(
        &self,
        id: &str,
        req: &ExecRequest,
        fds: Vec<OwnedFd>,
    ) -> ContainerResult<(ExecStream, client::Streams)> {
        let opened = self.exec_session(id, req, fds).await?;
        let stream = ExecStream {
            session: Session::new(opened.conn, client::Streams::default(), true, None)
                .map_err(ContainerError::Io)?,
            container: id.to_string(),
        };
        Ok((stream, opened.streams))
    }

    async fn exec_session(
        &self,
        id: &str,
        req: &ExecRequest,
        fds: Vec<OwnedFd>,
    ) -> ContainerResult<client::ExecSession> {
        let container = self.db.get_container(id).await?;
        if container.state != RecordState::Running {
            return Err(ContainerError::NotRunning(id.to_string()));
        }
        self.check_monitor(&container.id)?;
        let dir = self.mon_dir(&container.id);
        let mut req = req.clone();
        // (`failed_to_start` waits for it)
        req.notify_start = true;
        let opened = tokio::task::spawn_blocking(move || client::open_exec_with(&dir, &fds, &req))
            .await
            .map_err(|e| ContainerError::Io(io::Error::other(e)))?;
        match opened {
            Ok(o) => Ok(o),
            Err(e) if client::is_error(&e, error::NOT_RUNNING) => {
                Err(ContainerError::NotRunning(id.to_string()))
            }
            // (the runtime could not be started for the command: a command
            // that is not there is the runtime's exit, not this)
            Err(e) if condition_of(&e) == Some(Condition::NotStarted) => Err(
                ContainerError::Runtime(crate::container::RuntimeError::NotStarted {
                    command_missing: false,
                    message: e.to_string(),
                }),
            ),
            Err(e) if client::monitor_error(&e).is_some() => Err(ContainerError::Io(e)),
            // No monitor: the container is not running any more, or its
            // process runs on without it (a process that does not follow
            // the monitor did not see it go)
            Err(_) => {
                let pid = container.pid.filter(|p| *p > 0);
                Err(
                    if pid.is_some_and(|p| std::path::Path::new(&format!("/proc/{p}")).exists()) {
                        ContainerError::MonitorLost(container.id)
                    } else {
                        ContainerError::NotRunning(id.to_string())
                    },
                )
            }
        }
    }

    /// Run a command in a container and return (exit_code, stdout, stderr).
    pub async fn exec(
        &self,
        id: &str,
        command: &[String],
        env: &[String],
        working_dir: Option<&str>,
        tty: bool,
    ) -> ContainerResult<(i32, Vec<u8>, Vec<u8>)> {
        self.exec_with(
            id,
            &ExecRequest {
                command: command.to_vec(),
                env: env.to_vec(),
                cwd: working_dir.map(str::to_string),
                tty,
                ..Default::default()
            },
        )
        .await
    }

    /// Run a command and collect its output.  A command that times out
    /// has the exit code 124.
    pub async fn exec_with(
        &self,
        id: &str,
        req: &ExecRequest,
    ) -> ContainerResult<(i32, Vec<u8>, Vec<u8>)> {
        let mut stream = self.exec_stream(id, req).await?;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let room = |v: &Vec<u8>, n: usize| MAX_COLLECTED.saturating_sub(v.len()).min(n);
        loop {
            match stream.next().await.map_err(ContainerError::Io)? {
                Some(ExecEvent::Stdout(d)) => {
                    let n = room(&out, d.len());
                    out.extend_from_slice(&d[..n]);
                }
                Some(ExecEvent::Stderr(d)) => {
                    let n = room(&err, d.len());
                    err.extend_from_slice(&d[..n]);
                }
                Some(ExecEvent::Exit {
                    code, timed_out, ..
                }) => {
                    return Ok((if timed_out { 124 } else { code }, out, err));
                }
                None => {
                    // (the monitor sends the status of every command whose
                    // client stays: say what came before, to tell why)
                    tracing::warn!(
                        "exec {:?} in {id}: the monitor closed the connection without a status \
                         ({} bytes of output, {} of errors)",
                        req.command,
                        out.len(),
                        err.len()
                    );
                    return Err(ContainerError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the monitor went away",
                    )));
                }
            }
        }
    }
}
