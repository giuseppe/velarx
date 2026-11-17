// SPDX-License-Identifier: Apache-2.0
//! The HTTP side: accept connections on the listeners, serve the requests of
//! each with the router, leave when idle (a frontend started by its socket)
//! or when told to.

use crate::engine::Engine;
use axum::Router;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UnixListener};
use tracing::{debug, info, warn};
use velarx_base::ipc::{accept_failure, AcceptFailure, ACCEPT_WAIT};
use velarx_proto::bearer::Token;
use velarx_proto::request_line::FirstLine;
use velarx_proto::serving::{check_peer, Active, Activity, Peers};

/// A socket to accept connections on.
pub enum Listener {
    Unix(UnixListener),
    /// With TLS when a server configuration is given
    Tcp(TcpListener, Option<Arc<rustls::ServerConfig>>),
}

/// The router of the API.
pub fn router(engine: Engine) -> Router {
    Router::new()
        .fallback(crate::podman::dispatch)
        .with_state(engine)
}

/// Refuse the requests that do not carry the token.
async fn require_token(
    axum::extract::State(token): axum::extract::State<Arc<Token>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let given = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .map(|v| v.as_bytes());
    if token.accepts(given) {
        return next.run(request).await;
    }
    (
        axum::http::StatusCode::UNAUTHORIZED,
        [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
    )
        .into_response()
}

/// `router` answering only the requests that carry `token`.
pub fn with_token(router: Router, token: Arc<Token>) -> Router {
    router.layer(axum::middleware::from_fn_with_state(token, require_token))
}

/// Accept connections on `listener` until `stop` is done.
async fn accept_loop(
    listener: Listener,
    router: Router,
    peers: Peers,
    activity: Arc<Activity>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let socket = match &listener {
        Listener::Unix(l) => l.local_addr().ok().and_then(|a| {
            a.as_pathname()
                .map(|p| crate::podman::call::LocalSocket(Arc::new(p.to_path_buf())))
        }),
        Listener::Tcp(..) => None,
    };
    loop {
        let accepted = tokio::select! {
            accepted = accept(&listener, peers) => accepted,
            _ = stop.changed() => break,
        };
        match accepted {
            Ok(Accepted::Unix(stream)) => {
                // the clients of the users' API may be scripts
                let peer = peer_of(&stream);
                spawn_connection(
                    FirstLine::new(stream),
                    peer,
                    router.clone(),
                    activity.begin(),
                    &activity,
                    socket.clone(),
                );
            }
            Ok(Accepted::Tcp(stream, tls)) => {
                // the streams of attach and exec are interactive
                let _ = stream.set_nodelay(true);
                let peer = peer_of(&stream);
                let router = router.clone();
                let active = activity.begin();
                let activity = activity.clone();
                match tls {
                    None => spawn_connection(
                        FirstLine::new(stream),
                        peer,
                        router,
                        active,
                        &activity,
                        None,
                    ),
                    // (the handshake is not the accept loop's: a client that
                    // stalls in it holds only its own task, for a while)
                    Some(config) => {
                        tokio::spawn(async move {
                            let handshake = tokio_rustls::TlsAcceptor::from(config).accept(stream);
                            match tokio::time::timeout(TLS_HANDSHAKE, handshake).await {
                                Ok(Ok(stream)) => spawn_connection(
                                    FirstLine::new(stream),
                                    peer,
                                    router,
                                    active,
                                    &activity,
                                    None,
                                ),
                                Ok(Err(e)) => debug!("TLS handshake failed: {e}"),
                                Err(_) => debug!("TLS handshake timed out"),
                            }
                        });
                    }
                }
            }
            Ok(Accepted::Refused) => {}
            Err(e) => match accept_failure(&e) {
                AcceptFailure::Retry => {
                    debug!("a connection went away before it was accepted: {e}")
                }
                AcceptFailure::Wait => {
                    warn!("cannot accept a connection: {e}");
                    // (the connection stays queued: a descriptor is free
                    // once one that is served ends, or once another process
                    // gave back what the host was out of)
                    tokio::select! {
                        () = activity.one_ended() => {}
                        () = tokio::time::sleep(ACCEPT_WAIT) => {}
                        _ = stop.changed() => break,
                    }
                }
                AcceptFailure::Broken => return Err(format!("cannot accept a connection: {e}")),
            },
        }
    }
    Ok(())
}

enum Accepted {
    Unix(tokio::net::UnixStream),
    Tcp(tokio::net::TcpStream, Option<Arc<rustls::ServerConfig>>),
    /// Not served (said in the log)
    Refused,
}

async fn accept(listener: &Listener, peers: Peers) -> std::io::Result<Accepted> {
    Ok(match listener {
        Listener::Unix(l) => {
            let (stream, _) = l.accept().await?;
            match check_peer(&stream, peers) {
                Ok(()) => Accepted::Unix(stream),
                Err(e) => {
                    warn!("API: {e}");
                    Accepted::Refused
                }
            }
        }
        Listener::Tcp(l, tls) => {
            let (stream, peer) = l.accept().await?;
            debug!("API connection from tcp:{peer}");
            Accepted::Tcp(stream, tls.clone())
        }
    })
}

/// How long a TLS client has to finish its handshake.
const TLS_HANDSHAKE: Duration = Duration::from_secs(10);

/// A descriptor of its own for the connection of `stream`: the connection's
/// is in the event loop (and under TLS it is the socket below).
fn peer_of(stream: &impl std::os::fd::AsFd) -> Option<crate::podman::call::PeerFd> {
    stream
        .as_fd()
        .try_clone_to_owned()
        .ok()
        .map(|fd| crate::podman::call::PeerFd(Arc::new(fd)))
}

/// Serve the HTTP/1 requests of one connection, upgrades included.
fn spawn_connection<S>(
    stream: S,
    peer: Option<crate::podman::call::PeerFd>,
    router: Router,
    active: Active,
    activity: &Arc<Activity>,
    socket: Option<crate::podman::call::LocalSocket>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tower::Service;

    let io = TokioIo::new(stream);
    let activity_for_requests = activity.clone();
    let mut stopping = active.stopping();
    tokio::spawn(async move {
        let busy = activity_for_requests.clone();
        let service = service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
            let mut router = router.clone();
            // (a handler that takes the connection over holds the frontend
            // busy for as long as it splices: the connection is then no
            // longer counted)
            req.extensions_mut()
                .insert(crate::podman::call::Hold(Arc::new(busy.begin())));
            if let Some(peer) = &peer {
                req.extensions_mut().insert(peer.clone());
            }
            if let Some(socket) = &socket {
                req.extensions_mut().insert(socket.clone());
            }
            async move { router.call(req).await }
        });
        // Header names as Go writes them (`Api-Version`), which some
        // clients compare
        let conn = hyper::server::conn::http1::Builder::new()
            .title_case_headers(true)
            .serve_connection(io, service)
            .with_upgrades();
        tokio::pin!(conn);
        let result = loop {
            let stop = async {
                if *stopping.borrow() {
                    true
                } else {
                    stopping.changed().await.is_ok()
                }
            };
            tokio::select! {
                r = conn.as_mut() => break r,
                // the frontend stops: the request in progress is answered,
                // then the connection ends
                true = stop => conn.as_mut().graceful_shutdown(),
            }
        };
        if let Err(e) = result {
            debug!("error serving a connection: {e}");
        }
        drop(active);
    });
}

/// How the frontend is asked to stop.
pub enum Why {
    Signal,
    Idle,
    /// A listener cannot accept
    Failed(String),
}

/// The reason a listener stopped accepting; none once every one ended
/// (they only end when told to).
async fn listener_failed(tasks: &mut tokio::task::JoinSet<Result<(), String>>) -> Option<String> {
    loop {
        match tasks.join_next().await? {
            Ok(Err(reason)) => return Some(reason),
            Ok(Ok(())) => {}
            Err(e) => return Some(format!("an accept loop failed: {e}")),
        }
    }
}

/// Serve `listeners` until a signal says to stop, or (with `idle`) nothing
/// was served for that long.  The requests on the TCP ones carry `token`.
pub async fn serve(
    listeners: Vec<Listener>,
    engine: Engine,
    peers: Peers,
    idle: Option<Duration>,
    token: Option<Arc<Token>>,
) -> Why {
    use tokio::signal::unix::{signal, SignalKind};
    let activity = Arc::new(Activity::default());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let router = router(engine);
    let mut tasks = tokio::task::JoinSet::new();
    for listener in listeners {
        // (what comes over TCP carries the token: any local user can connect)
        let router = match (&listener, &token) {
            (Listener::Tcp(..), Some(token)) => with_token(router.clone(), token.clone()),
            _ => router.clone(),
        };
        tasks.spawn(accept_loop(
            listener,
            router,
            peers,
            activity.clone(),
            stop_rx.clone(),
        ));
    }
    let (mut sigint, mut sigterm) = match (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            warn!("cannot wait for signals: {e}");
            return Why::Signal;
        }
    };
    let leaving = async {
        let Some(limit) = idle else {
            return std::future::pending().await;
        };
        activity.idle(limit).await;
    };
    let why = tokio::select! {
        _ = sigint.recv() => Why::Signal,
        _ = sigterm.recv() => Why::Signal,
        () = leaving => {
            info!("idle, leaving");
            Why::Idle
        }
        Some(failed) = listener_failed(&mut tasks) => Why::Failed(failed),
    };
    // stop accepting; the requests in progress are answered
    stop_tx.send_replace(true);
    while tasks.join_next().await.is_some() {}
    activity.stop();
    if !activity.drained(Duration::from_secs(5)).await {
        warn!("{} connections still open: ended", activity.connections());
    }
    why
}
