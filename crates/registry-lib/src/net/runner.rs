// SPDX-License-Identifier: Apache-2.0
//! The runner that resolves names for the front of the fetcher.
//!
//! The front is confined and opens no socket, and its pull workers may not
//! open the sockets the name service switch of a host asks for (the UNIX
//! socket of `systemd-resolved`, `sssd`, `avahi`).  So a process forked
//! before the front confines itself, as the one that runs the credential
//! helpers is, resolves for them with the sources of the host
//! ([`velarx_sandbox::resolver`] says what it still gives up), and answers
//! the front on a socket pair with the protocol of [`super::resolve`]: the
//! front only asks, and checks the questions of its workers before it does.

use super::resolve::{serve, Client, MAX_ADDRS, MAX_IN_FLIGHT};
use futures::future::BoxFuture;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream as StdStream;
use std::sync::Mutex;
use velarx_registry::netpolicy::Resolver;

/// The questions the runner resolves at once: those of several workers, so
/// that one that asks for names that take long to fail leaves room for the
/// others.
const IN_FLIGHT: usize = 4 * MAX_IN_FLIGHT;

/// The system's resolver, in this process: what a process that is not
/// confined resolves with.
pub struct System;

impl Resolver for System {
    fn lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            // (no more than the channel carries)
            let found = tokio::net::lookup_host((host, port)).await?;
            Ok(found.take(MAX_ADDRS).collect())
        })
    }
}

/// The runner, as the front holds it.
pub struct Runner {
    /// The socket, until the first question (a client needs a runtime)
    socket: Mutex<Option<StdStream>>,
    pid: i32,
    client: tokio::sync::OnceCell<Client>,
}

impl Runner {
    /// Fork the runner.  Call it before the confinement and before any
    /// thread is started: the runner starts threads of its own, which a
    /// child of a process with other threads cannot do safely (the start is
    /// refused then).  It ends with the front: it sees the end of the socket.
    pub fn start() -> Result<Self, String> {
        let (front, runner) = StdStream::pair()
            .map_err(|e| format!("cannot make the socket of the resolver runner: {e}"))?;
        front
            .set_nonblocking(true)
            .map_err(|e| format!("cannot set up the resolver runner: {e}"))?;
        match velarx_sys::process::fork_single_threaded("resolver runner") {
            Err(e) => Err(format!("cannot fork the resolver runner: {e}")),
            Ok(velarx_sys::process::Fork::Child(child)) => {
                drop(front);
                let code = std::panic::catch_unwind(move || run(child, OwnedFd::from(runner)))
                    .unwrap_or(70);
                velarx_sys::process::exit_now(code)
            }
            Ok(velarx_sys::process::Fork::Parent(pid)) => Ok(Self {
                socket: Mutex::new(Some(front)),
                pid,
                client: tokio::sync::OnceCell::new(),
            }),
        }
    }

    /// The process of the runner.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Returns when the runner is gone: it ended or broke the rules of its
    /// channel, and no lookup is answered any more.
    pub async fn gone(&self) {
        if let Ok(client) = self.client().await {
            client.gone().await;
        }
    }

    async fn client(&self) -> io::Result<&Client> {
        self.client
            .get_or_try_init(|| async {
                let socket = self
                    .socket
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                    .ok_or_else(|| io::Error::other("the resolver runner has no socket"))?;
                Ok(Client::new(tokio::net::UnixStream::from_std(socket)?))
            })
            .await
    }
}

impl Resolver for Runner {
    fn lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
        Box::pin(async move { self.client().await?.lookup(host, port).await })
    }
}

/// What the forked runner does; the code it ends with.
fn run(child: velarx_sys::spawn::InChild, socket: OwnedFd) -> i32 {
    // (what `ps` and /proc show of it)
    let _ = rustix::thread::set_name(c"resolver-runner");
    // nothing of the front but the socket (its credentials, its listener)
    let keep = socket.as_raw_fd();
    let null = rustix::fs::open(
        c"/dev/null",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    );
    if let Ok(null) = null {
        let _ = child.dup2(null.as_raw_fd(), 0);
    }
    child.close_range(3, (keep - 1).max(2) as u32);
    child.close_from(keep as u32 + 1);
    if let Err(e) = velarx_sandbox::resolver::enter() {
        eprintln!("the resolver runner cannot confine itself: {e}");
        return 1;
    }
    let served = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .and_then(|runtime| {
            runtime.block_on(async {
                let socket = StdStream::from(socket);
                socket.set_nonblocking(true)?;
                let socket = tokio::net::UnixStream::from_std(socket)?;
                serve(socket, std::sync::Arc::new(System), IN_FLIGHT).await
            })
        });
    match served {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("the resolver runner: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The runner of a process resolves with the system's sources and
    /// answers what the protocol allows.
    #[test]
    fn the_runner_resolves_for_its_front() {
        velarx_base::testing::in_child(|| {
            let runner = Runner::start().unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let found = runner.lookup("localhost", 8080).await.unwrap();
                assert!(found
                    .iter()
                    .any(|a| a.ip().is_loopback() && a.port() == 8080));
                assert!(runner.lookup("no-such-host.invalid", 80).await.is_err());
                // (a name that is not one never gets there)
                assert!(runner.lookup("a b", 80).await.is_err());
            });
        });
    }

    /// A runner that is killed is gone for the front, which is told at
    /// once and does not wait for a lookup to find out.
    #[test]
    fn the_front_is_told_that_its_runner_died() {
        velarx_base::testing::in_child(|| {
            let runner = Runner::start().unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                assert!(runner.lookup("localhost", 80).await.is_ok());
                rustix::process::kill_process(
                    rustix::process::Pid::from_raw(runner.pid()).unwrap(),
                    rustix::process::Signal::KILL,
                )
                .unwrap();
                runner.gone().await;
                let e = runner.lookup("localhost", 80).await.unwrap_err();
                assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
            });
        });
    }
}
