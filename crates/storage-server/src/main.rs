// SPDX-License-Identifier: Apache-2.0
//! `velarx-storage-server --socket PATH --root DIR`: the reference server of
//! `org.velarx.Storage`.

use std::path::PathBuf;
use std::time::Duration;
use velarx_storage_server::{parse_idle, Config, Server, DEFAULT_IDLE_SECS};

fn usage() -> ! {
    eprintln!(
        "usage: velarx-storage-server [--socket PATH] --root DIR [--timeout-secs N] [--decision-secs N] [--idle-secs N|off]\n\n\
         --socket PATH         the unix socket to listen on (made 0600); not needed when systemd\n\
                               passes the listening socket (LISTEN_FDS, descriptor 3), which is\n\
                               then served as it is\n\
         --root DIR            where the stores are kept: DIR/UID/STORE\n\
         --timeout-secs N      the idle deadline of the engine's calls, 30 by default; a long\n\
                               call sends progress every half of it\n\
         --decision-secs N     how long a staged pull waits for Commit or Abort, 600 by default\n\
         --idle-secs N|off     leave after this long with no connection and no pull holding\n\
                               claims, 300 by default; 0 or off never (also\n\
                               VELARX_STORAGE_IDLE_SECS; the flag wins)"
    );
    std::process::exit(2);
}

fn main() {
    let startup = velarx_sys::fd::Startup::take().expect("main is the first to take it");
    let (mut socket, mut root) = (None, None);
    let (mut timeout, mut decision) = (30u64, 600u64);
    // (NOTIFY_SOCKET is taken before any thread is started)
    velarx_wire::sdnotify::take_manager_env();
    let mut idle = match std::env::var("VELARX_STORAGE_IDLE_SECS") {
        Ok(v) => parse_idle(&v).unwrap_or_else(|| usage()),
        Err(_) => Some(Duration::from_secs(DEFAULT_IDLE_SECS)),
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match a.as_str() {
            "--socket" => socket = Some(PathBuf::from(value())),
            "--root" => root = Some(PathBuf::from(value())),
            "--timeout-secs" => timeout = value().parse().unwrap_or_else(|_| usage()),
            "--idle-secs" => idle = parse_idle(&value()).unwrap_or_else(|| usage()),
            "--decision-secs" => decision = value().parse().unwrap_or_else(|_| usage()),
            _ => usage(),
        }
    }
    // (the socket systemd passed, if it did: before any thread is started)
    let activated = velarx_content::activation::activated_listener(&startup);
    let Some(root) = root else { usage() };
    if socket.is_none() && activated.is_none() {
        usage()
    }
    let server = Server::new(Config {
        root,
        timeout: Duration::from_secs(timeout.max(2)),
        decision: Duration::from_secs(decision),
    })
    .unwrap_or_else(|e| {
        eprintln!("velarx-storage-server: {e}");
        std::process::exit(1);
    });
    let (running, name) = match (activated, socket) {
        (Some(Ok(listener)), socket) => {
            let name = socket.unwrap_or_else(|| PathBuf::from("the socket systemd passed"));
            (server.serve(listener, &name), name)
        }
        (Some(Err(e)), _) => {
            eprintln!("velarx-storage-server: {e}");
            std::process::exit(1);
        }
        (None, Some(socket)) => (server.listen(&socket), socket),
        (None, None) => usage(),
    };
    match running {
        Ok(running) => {
            // (the socket is listening: Type=notify units go on)
            velarx_wire::sdnotify::notify("READY=1");
            let Some(idle) = idle else {
                loop {
                    std::thread::park();
                }
            };
            running.wait_idle(idle);
            velarx_wire::sdnotify::notify("STOPPING=1");
            // (a socket systemd passed is left as it is, with the connections
            // queued on it, for the next server; one of the server's own is
            // removed, and what was queued on it is served first)
            running.leave();
            // (the accept thread is not joined: the exit ends it)
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("velarx-storage-server: {}: {e}", name.display());
            std::process::exit(1);
        }
    }
}
