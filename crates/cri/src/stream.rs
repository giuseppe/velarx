// SPDX-License-Identifier: Apache-2.0
//! The streaming server of exec, attach and port-forward: the CRI answers
//! with a URL, the kubelet connects to it, over WebSocket (the
//! `v5.channel.k8s.io` and `v4.channel.k8s.io` protocols of the Kubernetes
//! remotecommand and portforward streams) or SPDY/3.1 (`crate::spdy`).

use crate::engine::{Engine, ExecSpec, ExecStream};
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sha1::{Digest, Sha1};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const SESSION_TTL: Duration = Duration::from_secs(60);
const MAX_SESSIONS: usize = 1024;
/// The largest message (data frames joined) a client may send.
const MAX_MESSAGE: usize = 16 << 20;

#[derive(Debug, Clone)]
pub enum Session {
    Exec {
        container: String,
        spec: ExecSpec,
    },
    Attach {
        container: String,
        stdin: bool,
        stdin_once: bool,
        tty: bool,
        stdout: bool,
        stderr: bool,
    },
    PortForward {
        pod: String,
        ports: Vec<u16>,
    },
}

impl Session {
    fn kind(&self) -> &'static str {
        match self {
            Session::Exec { .. } => "exec",
            Session::Attach { .. } => "attach",
            Session::PortForward { .. } => "portforward",
        }
    }
}

/// The sessions a URL was given for; a token is good once.
#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<String, (Instant, Session)>>,
}

impl Sessions {
    pub fn add(&self, s: Session) -> String {
        let mut raw = [0u8; 16];
        // the token is the capability to run a command in a container
        rustix::rand::getrandom(&mut raw, rustix::rand::GetRandomFlags::empty())
            .expect("getrandom");
        let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        map.retain(|_, (t, _)| now.duration_since(*t) < SESSION_TTL);
        if map.len() >= MAX_SESSIONS {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, (t, _))| *t)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest);
            }
        }
        map.insert(token.clone(), (now, s));
        token
    }

    pub fn take(&self, token: &str) -> Option<Session> {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let (t, s) = map.remove(token)?;
        (Instant::now().duration_since(t) < SESSION_TTL).then_some(s)
    }
}

#[derive(Debug, PartialEq)]
pub struct Frame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

pub fn encode_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(0x80 | opcode);
    match payload.len() {
        n if n < 126 => out.push(n as u8),
        n if n <= 0xffff => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

/// The first frame of `buf` and the bytes it took.
pub fn parse_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, &'static str> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let fin = buf[0] & 0x80 != 0;
    let opcode = buf[0] & 0x0f;
    let masked = buf[1] & 0x80 != 0;
    let (len, mut at) = match buf[1] & 0x7f {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            let n = u64::from_be_bytes(buf[2..10].try_into().unwrap());
            if n > (16 << 20) {
                return Err("frame too large");
            }
            (n as usize, 10)
        }
        n => (n as usize, 2),
    };
    let mask = if masked {
        if buf.len() < at + 4 {
            return Ok(None);
        }
        let m = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
        at += 4;
        Some(m)
    } else {
        None
    };
    if buf.len() < at + len {
        return Ok(None);
    }
    let mut payload = buf[at..at + len].to_vec();
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i % 4];
        }
    }
    Ok(Some((
        Frame {
            fin,
            opcode,
            payload,
        },
        at + len,
    )))
}

pub fn accept_key(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// The protocol of the request we speak: v5 before v4.
pub fn choose_protocol(offered: &str) -> Option<&'static str> {
    let list: Vec<&str> = offered.split(',').map(str::trim).collect();
    ["v5.channel.k8s.io", "v4.channel.k8s.io"]
        .into_iter()
        .find(|p| list.contains(p))
}

/// What a message is for.
#[derive(Debug, PartialEq)]
pub enum Inbound {
    Data(Vec<u8>),
    Close,
}

/// Reads whole messages (data frames joined, pings answered through `pong`).
async fn read_messages<R: AsyncReadExt + Unpin>(
    mut rd: R,
    tx: mpsc::Sender<Inbound>,
    pong: mpsc::Sender<Vec<u8>>,
) {
    let mut buf: Vec<u8> = Vec::new();
    let mut msg: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        loop {
            match parse_frame(&buf) {
                Ok(Some((f, used))) => {
                    buf.drain(..used);
                    match f.opcode {
                        0x8 => {
                            let _ = tx.send(Inbound::Close).await;
                            return;
                        }
                        0x9 => {
                            let _ = pong.send(encode_frame(0xA, &f.payload)).await;
                        }
                        0xA => {}
                        _ => {
                            if msg.len() + f.payload.len() > MAX_MESSAGE {
                                let _ = tx.send(Inbound::Close).await;
                                return;
                            }
                            msg.extend_from_slice(&f.payload);
                            if f.fin
                                && tx
                                    .send(Inbound::Data(std::mem::take(&mut msg)))
                                    .await
                                    .is_err()
                            {
                                return;
                            }
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    let _ = tx.send(Inbound::Close).await;
                    return;
                }
            }
        }
        match rd.read(&mut chunk).await {
            Ok(0) | Err(_) => {
                let _ = tx.send(Inbound::Close).await;
                return;
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// The status the client reads at the end of a stream: the exit code of the
/// command, or the error that left it unknown (the kubelet's internal error).
fn status_message(exit: &Result<i32, String>) -> String {
    match exit {
        Ok(0) => r#"{"metadata":{},"status":"Success"}"#.to_string(),
        Ok(exit) => serde_json::json!({
            "metadata": {},
            "status": "Failure",
            "message": format!("command terminated with non-zero exit code: Error executing in container: exit code {exit}"),
            "reason": "NonZeroExitCode",
            "details": {"causes": [{"reason": "ExitCode", "message": exit.to_string()}]},
        })
        .to_string(),
        Err(e) => serde_json::json!({
            "metadata": {},
            "status": "Failure",
            "message": format!("Internal error occurred: {e}"),
            "reason": "InternalError",
            "details": {"causes": [{"message": e}]},
            "code": 500,
        })
        .to_string(),
    }
}

fn channel_frame(channel: u8, data: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(data.len() + 1);
    p.push(channel);
    p.extend_from_slice(data);
    encode_frame(0x2, &p)
}

fn error_response(code: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(msg.to_string())));
    *r.status_mut() = code;
    r
}

/// The connections the streaming server holds at once: the others wait in
/// the backlog of the listener.
pub const MAX_CONNECTIONS: usize = 1024;

/// The streaming server: one task per connection.
pub struct StreamServer<E: Engine> {
    pub engine: Arc<E>,
    pub sessions: Arc<Sessions>,
    /// A port-forward session with no connection open for this long is
    /// closed; zero: never.
    pub idle_timeout: Duration,
}

impl<E: Engine> StreamServer<E> {
    pub async fn serve(self: Arc<Self>, listener: tokio::net::TcpListener) {
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
        self.serve_limited(listener, slots).await
    }

    /// `serve`, with the places for connections that `slots` holds.
    pub async fn serve_limited(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
        slots: Arc<tokio::sync::Semaphore>,
    ) {
        loop {
            // (a connection is accepted when there is a place for it)
            let Ok(slot) = slots.clone().acquire_owned().await else {
                return;
            };
            let conn = match listener.accept().await {
                Ok((conn, _)) => conn,
                Err(e) => {
                    use velarx_base::ipc::{accept_failure, AcceptFailure, ACCEPT_WAIT};
                    match accept_failure(&e) {
                        AcceptFailure::Retry => {
                            tracing::debug!("a connection went away before it was accepted: {e}")
                        }
                        // (out of descriptors: the connection stays queued
                        // and is tried again after the wait of the API
                        // server, its own slot given back meanwhile)
                        AcceptFailure::Wait => {
                            tracing::warn!("cannot accept a connection: {e}");
                            drop(slot);
                            tokio::time::sleep(ACCEPT_WAIT).await;
                        }
                        AcceptFailure::Broken => {
                            tracing::warn!("cannot accept a connection: {e}");
                            return;
                        }
                    }
                    continue;
                }
            };
            let this = self.clone();
            tokio::spawn(async move {
                let _slot = slot;
                let svc = hyper::service::service_fn(move |req| {
                    let this = this.clone();
                    async move { Ok::<_, std::convert::Infallible>(this.handle(req).await) }
                });
                // (a connection that sends no request in the header timeout,
                // 30 seconds, gives its place back)
                let _ = hyper::server::conn::http1::Builder::new()
                    .timer(hyper_util::rt::TokioTimer::new())
                    .serve_connection(TokioIo::new(conn), svc)
                    .with_upgrades()
                    .await;
            });
        }
    }

    pub async fn handle(self: Arc<Self>, mut req: Request<Incoming>) -> Response<Full<Bytes>> {
        let path = req.uri().path().to_string();
        let mut parts = path.trim_matches('/').split('/');
        let (kind, token) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let Some(session) = self.sessions.take(token).filter(|s| s.kind() == kind) else {
            return error_response(
                StatusCode::NOT_FOUND,
                "unknown or expired streaming session",
            );
        };
        let upgrade = req
            .headers()
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if upgrade.starts_with("spdy/3") {
            return self.handle_spdy(req, session).await;
        }
        if upgrade != "websocket" {
            return error_response(
                StatusCode::NOT_IMPLEMENTED,
                "velarx-cri streams over SPDY/3.1 or WebSocket: the upgrade is neither",
            );
        }
        let Some(key) = req
            .headers()
            .get("sec-websocket-key")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
        else {
            return error_response(StatusCode::BAD_REQUEST, "no Sec-WebSocket-Key");
        };
        let offered = req
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        // port-forward also speaks SPDY inside the messages (what the Kubernetes
        // clients call "SPDY over WebSocket")
        let tunnel = matches!(session, Session::PortForward { .. })
            && offered
                .split(',')
                .any(|p| p.trim() == SPDY_TUNNEL_PORTFORWARD);
        let Some(proto) = tunnel
            .then_some(SPDY_TUNNEL_PORTFORWARD)
            .or_else(|| choose_protocol(&offered))
        else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "the WebSocket sub-protocol must be v5.channel.k8s.io or v4.channel.k8s.io",
            );
        };
        // errors the engine gives before the upgrade are HTTP answers
        let opened = match &session {
            Session::Exec { container, spec } => self
                .engine
                .exec_open(container, spec)
                .await
                .map(Opened::Stream),
            Session::Attach {
                container,
                stdin,
                stdin_once,
                tty,
                ..
            } => self
                .engine
                .attach_open(container, *stdin, *stdin_once, *tty)
                .await
                .map(Opened::Stream),
            Session::PortForward { pod, ports } if tunnel => {
                Ok(Opened::Forward(pod.clone(), ports.clone()))
            }
            Session::PortForward { pod, ports } => {
                let mut conns = Vec::new();
                for p in ports {
                    match self.engine.pod_dial(pod, *p).await {
                        Ok(c) => conns.push(c),
                        Err(e) => {
                            return error_response(StatusCode::NOT_IMPLEMENTED, &e.to_string())
                        }
                    }
                }
                Ok(Opened::Ports(ports.clone(), conns))
            }
        };
        let opened = match opened {
            Ok(o) => o,
            Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };
        let on_upgrade = hyper::upgrade::on(&mut req);
        let engine = self.engine.clone();
        let idle = self.idle_timeout;
        tokio::spawn(async move {
            let Ok(up) = on_upgrade.await else { return };
            let io = TokioIo::new(up);
            match (opened, session) {
                (Opened::Stream(es), Session::Exec { spec, .. }) => {
                    run_exec(
                        engine,
                        io,
                        es,
                        Channels {
                            stdin: spec.stdin,
                            stdout: spec.stdout,
                            stderr: spec.stderr,
                            input_ends: false,
                        },
                        true,
                    )
                    .await
                }
                (
                    Opened::Stream(es),
                    Session::Attach {
                        stdin,
                        stdout,
                        stderr,
                        stdin_once,
                        tty,
                        ..
                    },
                ) => {
                    run_exec(
                        engine,
                        io,
                        es,
                        Channels {
                            stdin,
                            stdout,
                            stderr: stderr && !tty,
                            input_ends: !stdin_once && !tty,
                        },
                        false,
                    )
                    .await
                }
                (Opened::Ports(ports, conns), _) => run_ports(io, ports, conns).await,
                (Opened::Forward(pod, ports), _) => {
                    run_ports_spdy(engine, ws_tunnel(io), pod, ports, idle).await
                }
                _ => {}
            }
        });
        let mut resp = Response::new(Full::new(Bytes::new()));
        *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        let h = resp.headers_mut();
        h.insert("upgrade", "websocket".parse().unwrap());
        h.insert("connection", "Upgrade".parse().unwrap());
        h.insert("sec-websocket-accept", accept_key(&key).parse().unwrap());
        h.insert("sec-websocket-protocol", proto.parse().unwrap());
        resp
    }
}

enum Opened {
    Stream(ExecStream),
    Ports(Vec<u16>, Vec<Box<dyn crate::engine::Io>>),
    /// Port-forward whose connections are made as streams open (SPDY)
    Forward(String, Vec<u16>),
}

/// The sub-protocol of SPDY inside WebSocket messages for port-forward.
const SPDY_TUNNEL_PORTFORWARD: &str = "SPDY/3.1+portforward.k8s.io";
/// The most port-forward connections one session (one URL of the CRI) holds
/// open at once.
pub const MAX_FORWARDS: usize = 64;
/// The most requests of a port-forward session that have only one of their
/// two streams yet.
pub const MAX_HALF_OPEN: usize = 2 * MAX_FORWARDS;

/// A byte stream over the messages of a WebSocket (each write is one binary
/// message, the messages read are joined): what SPDY runs on there.
fn ws_tunnel<T>(io: T) -> tokio::io::DuplexStream
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (inner, outer) = tokio::io::duplex(64 * 1024);
    let (ws_rd, ws_wr) = tokio::io::split(io);
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (in_tx, mut in_rx) = mpsc::channel::<Inbound>(64);
    tokio::spawn(writer_task(ws_wr, out_rx));
    tokio::spawn(read_messages(ws_rd, in_tx, out_tx.clone()));
    let (mut rd, mut wr) = tokio::io::split(inner);
    tokio::spawn(async move {
        while let Some(Inbound::Data(d)) = in_rx.recv().await {
            if wr.write_all(&d).await.is_err() {
                return;
            }
        }
        let _ = wr.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(n) = rd.read(&mut buf).await {
            if n == 0 || out_tx.send(encode_frame(0x2, &buf[..n])).await.is_err() {
                break;
            }
        }
        let _ = out_tx.send(encode_frame(0x8, &[0x03, 0xe8])).await;
    });
    outer
}

async fn writer_task<W: tokio::io::AsyncWrite + Unpin>(mut wr: W, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(frame) = rx.recv().await {
        if wr.write_all(&frame).await.is_err() {
            return;
        }
        // nothing follows the close frame
        if frame.first().is_some_and(|b| b & 0x0f == 0x8) {
            break;
        }
    }
    let _ = wr.shutdown().await;
}

#[derive(Debug, Clone, Copy)]
pub struct Channels {
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
    /// The session ends when the client's input ends, once what it sent is
    /// passed on (an attach without a terminal and without `stdin_once`:
    /// the container keeps its input open).
    pub input_ends: bool,
}

/// The new size of the terminal of an exec session, as the client sends it
/// (`{"Width": W, "Height": H}`).  The session goes on when the size is
/// not applied: the reason is logged (a session that ended meanwhile is no
/// reason).
async fn resize<E: Engine>(engine: &E, id: &str, size: &[u8]) {
    #[derive(serde::Deserialize)]
    struct Size {
        #[serde(rename = "Width")]
        w: u16,
        #[serde(rename = "Height")]
        h: u16,
    }
    let size = match serde_json::from_slice::<Size>(size) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("the terminal size of the exec session {id} cannot be read: {e}");
            return;
        }
    };
    match engine.exec_resize(id, size.w, size.h).await {
        Ok(()) | Err(crate::engine::EngineError::NotFound(_)) => {}
        Err(e) => tracing::warn!("cannot resize the terminal of the exec session {id}: {e}"),
    }
}

/// The stream of an exec session is over: its exit code when the command
/// ended, an error when it cannot be known.  When the client went away
/// first the command is killed, as the kubelet expects when it cancels the
/// stream (an attach, which has no session of its own, is left running).
async fn ended<E: Engine>(
    engine: &E,
    id: &str,
    client_gone: bool,
    exit_status: bool,
) -> Result<i32, String> {
    if id.is_empty() {
        return Ok(0);
    }
    if client_gone {
        if let Err(e) = engine.exec_kill(id).await {
            tracing::debug!("cannot kill the exec session {id}: {e}");
        }
        return Ok(0);
    }
    if !exit_status {
        return Ok(0);
    }
    engine.exec_exit_code(id).await.map_err(|e| {
        tracing::warn!("The exit status of the exec session {id}: {e}");
        e.to_string()
    })
}

/// Hand the input the client sent (`None`: its end) to the writer of the
/// command's input, once it has room.  A branch of the `select!` that reads
/// the command's output: a command may take its input only as its output is
/// read, so the output goes on while the input waits, and the client is
/// read for more once `held` is empty.  Cancel safe.
async fn pass_input(tx: &mpsc::Sender<Option<Vec<u8>>>, held: &mut VecDeque<Option<Vec<u8>>>) {
    match tx.reserve().await {
        Ok(permit) => {
            if let Some(m) = held.pop_front() {
                permit.send(m);
            }
        }
        // (the input of the command is closed)
        Err(_) => held.clear(),
    }
}

/// The exec or attach stream between the WebSocket `io` and the engine.
pub async fn run_exec<E: Engine, T>(
    engine: Arc<E>,
    io: T,
    es: ExecStream,
    channels: Channels,
    exit_status: bool,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (ws_rd, ws_wr) = tokio::io::split(io);
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (in_tx, mut in_rx) = mpsc::channel::<Inbound>(64);
    let writer = tokio::spawn(writer_task(ws_wr, out_rx));
    tokio::spawn(read_messages(ws_rd, in_tx, out_tx.clone()));
    let stdin = channels.stdin;
    for (used, ch) in [
        (channels.stdin, 0u8),
        (channels.stdout, 1),
        (channels.stderr, 2),
        (true, 3),
    ] {
        if used {
            let _ = out_tx.send(channel_frame(ch, &[])).await;
        }
    }
    let ExecStream { id, framed, io } = es;
    let (mut eng_rd, mut eng_wr) = tokio::io::split(io);
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Option<Vec<u8>>>(16);
    tokio::spawn(async move {
        while let Some(m) = stdin_rx.recv().await {
            match m {
                Some(d) => {
                    if eng_wr.write_all(&d).await.is_err() {
                        return;
                    }
                }
                None => {
                    let _ = eng_wr.shutdown().await;
                }
            }
        }
    });
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    let mut client_gone = false;
    let mut input_done = false;
    let mut held = VecDeque::new();
    loop {
        if input_done && held.is_empty() {
            break;
        }
        tokio::select! {
            r = pass_input(&stdin_tx, &mut held), if !held.is_empty() => r,
            msg = in_rx.recv(), if held.is_empty() => match msg {
                None | Some(Inbound::Close) => {
                    client_gone = true;
                    break;
                }
                Some(Inbound::Data(d)) => {
                    let Some((&ch, data)) = d.split_first() else { continue };
                    match ch {
                        0 if stdin => held.push_back(Some(data.to_vec())),
                        4 if !id.is_empty() => resize(&*engine, &id, data).await,
                        255 if data.first() == Some(&0) => {
                            held.push_back(None);
                            input_done = channels.input_ends;
                        }
                        _ => {}
                    }
                }
            },
            n = eng_rd.read(&mut chunk) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if framed {
                        pending.extend_from_slice(&chunk[..n]);
                        let (mut o, mut e) = (Vec::new(), Vec::new());
                        crate::engine::varlink::demux(&mut pending, &mut o, &mut e);
                        if !o.is_empty() { let _ = out_tx.send(channel_frame(1, &o)).await; }
                        if !e.is_empty() { let _ = out_tx.send(channel_frame(2, &e)).await; }
                    } else {
                        let _ = out_tx.send(channel_frame(1, &chunk[..n])).await;
                    }
                }
            },
        }
    }
    let code = ended(&*engine, &id, client_gone, exit_status).await;
    let _ = out_tx
        .send(channel_frame(3, status_message(&code).as_bytes()))
        .await;
    let _ = out_tx.send(encode_frame(0x8, &[0x03, 0xe8])).await;
    drop(out_tx);
    let _ = writer.await;
}

/// Port-forward: channel `2i` is the data of port `i`, `2i+1` its errors.
async fn run_ports<T>(io: T, ports: Vec<u16>, conns: Vec<Box<dyn crate::engine::Io>>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (ws_rd, ws_wr) = tokio::io::split(io);
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (in_tx, mut in_rx) = mpsc::channel::<Inbound>(64);
    let writer = tokio::spawn(writer_task(ws_wr, out_rx));
    tokio::spawn(read_messages(ws_rd, in_tx, out_tx.clone()));
    let mut to_conn = Vec::new();
    for (i, (port, conn)) in ports.iter().zip(conns).enumerate() {
        let (mut rd, mut wr) = tokio::io::split(conn);
        let _ = out_tx
            .send(channel_frame((2 * i) as u8, &port.to_le_bytes()))
            .await;
        let _ = out_tx
            .send(channel_frame((2 * i + 1) as u8, &port.to_le_bytes()))
            .await;
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);
        to_conn.push(tx);
        tokio::spawn(async move {
            while let Some(d) = rx.recv().await {
                if wr.write_all(&d).await.is_err() {
                    return;
                }
            }
            let _ = wr.shutdown().await;
        });
        let out = out_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(n) = rd.read(&mut buf).await {
                if n == 0
                    || out
                        .send(channel_frame((2 * i) as u8, &buf[..n]))
                        .await
                        .is_err()
                {
                    return;
                }
            }
        });
    }
    while let Some(Inbound::Data(d)) = in_rx.recv().await {
        let Some((&ch, data)) = d.split_first() else {
            continue;
        };
        if ch % 2 == 0 {
            if let Some(tx) = to_conn.get((ch / 2) as usize) {
                let _ = tx.send(data.to_vec()).await;
            }
        }
    }
    drop(out_tx);
    let _ = writer.await;
}

/// The value of the header `name` of a SPDY stream.
fn header<'a>(headers: &'a crate::spdy::Headers, name: &str) -> &'a str {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map_or("", |(_, v)| v.as_str())
}

impl<E: Engine> StreamServer<E> {
    /// The upgrade to SPDY/3.1 of `X-Stream-Protocol-Version`: exec and attach
    /// speak `v4.channel.k8s.io`, port-forward `portforward.k8s.io`.
    async fn handle_spdy(
        self: Arc<Self>,
        mut req: Request<Incoming>,
        session: Session,
    ) -> Response<Full<Bytes>> {
        let offered = req
            .headers()
            .get_all("x-stream-protocol-version")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(|v| v.trim().to_string())
            .collect::<Vec<_>>();
        let wanted = match session {
            Session::PortForward { .. } => "portforward.k8s.io",
            _ => "v4.channel.k8s.io",
        };
        if !offered.iter().any(|p| p == wanted) {
            return error_response(
                StatusCode::FORBIDDEN,
                &format!("the stream protocol must be {wanted}"),
            );
        }
        // errors the engine gives before the upgrade are HTTP answers
        let opened = match &session {
            Session::Exec { container, spec } => {
                self.engine.exec_open(container, spec).await.map(Some)
            }
            Session::Attach {
                container,
                stdin,
                stdin_once,
                tty,
                ..
            } => self
                .engine
                .attach_open(container, *stdin, *stdin_once, *tty)
                .await
                .map(Some),
            Session::PortForward { .. } => Ok(None),
        };
        let opened = match opened {
            Ok(o) => o,
            Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };
        let on_upgrade = hyper::upgrade::on(&mut req);
        let engine = self.engine.clone();
        let idle = self.idle_timeout;
        tokio::spawn(async move {
            let Ok(up) = on_upgrade.await else { return };
            let io = TokioIo::new(up);
            match (opened, session) {
                (Some(es), Session::Exec { spec, .. }) => {
                    let ch = Channels {
                        stdin: spec.stdin,
                        stdout: spec.stdout,
                        stderr: spec.stderr && !spec.tty,
                        input_ends: false,
                    };
                    run_exec_spdy(engine, io, es, ch, spec.tty, true).await
                }
                (
                    Some(es),
                    Session::Attach {
                        stdin,
                        stdout,
                        stderr,
                        stdin_once,
                        tty,
                        ..
                    },
                ) => {
                    let ch = Channels {
                        stdin,
                        stdout,
                        stderr: stderr && !tty,
                        input_ends: !stdin_once && !tty,
                    };
                    run_exec_spdy(engine, io, es, ch, tty, false).await
                }
                (None, Session::PortForward { pod, ports }) => {
                    run_ports_spdy(engine, io, pod, ports, idle).await
                }
                _ => {}
            }
        });
        let mut resp = Response::new(Full::new(Bytes::new()));
        *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        let h = resp.headers_mut();
        h.insert("upgrade", "SPDY/3.1".parse().unwrap());
        h.insert("connection", "Upgrade".parse().unwrap());
        h.insert("x-stream-protocol-version", wanted.parse().unwrap());
        resp
    }
}

/// How long a client has to open the streams of a command.
const STREAMS_WAIT: Duration = Duration::from_secs(30);

/// Exec or attach over SPDY (`v4.channel.k8s.io`): the client opens the
/// streams `error`, `stdin`, `stdout`, `stderr` and, with a terminal,
/// `resize`; the status of the command ends the `error` stream.
async fn run_exec_spdy<E: Engine, T>(
    engine: Arc<E>,
    io: T,
    es: ExecStream,
    channels: Channels,
    tty: bool,
    exit_status: bool,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (h, mut ev) = crate::spdy::serve(io);
    let mut want: Vec<&str> = vec!["error"];
    if channels.stdin {
        want.push("stdin");
    }
    if channels.stdout {
        want.push("stdout");
    }
    if channels.stderr {
        want.push("stderr");
    }
    if tty {
        want.push("resize");
    }
    let mut ids: HashMap<String, u32> = HashMap::new();
    let opened = tokio::time::timeout(STREAMS_WAIT, async {
        while ids.len() < want.len() {
            match ev.recv().await {
                Some(crate::spdy::Event::Stream { id, headers, .. }) => {
                    let kind = header(&headers, "streamtype").to_string();
                    if want.contains(&kind.as_str()) && !ids.contains_key(&kind) {
                        h.reply(id, Vec::new()).await;
                        ids.insert(kind, id);
                    } else {
                        h.reset(id).await;
                    }
                }
                Some(_) => {}
                None => return false,
            }
        }
        true
    })
    .await
    .unwrap_or(false);
    if !opened {
        h.finish().await;
        return;
    }
    let ExecStream { id, framed, io } = es;
    let (mut eng_rd, mut eng_wr) = tokio::io::split(io);
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Option<Vec<u8>>>(16);
    tokio::spawn(async move {
        while let Some(m) = stdin_rx.recv().await {
            match m {
                Some(d) => {
                    if eng_wr.write_all(&d).await.is_err() {
                        return;
                    }
                }
                None => {
                    let _ = eng_wr.shutdown().await;
                }
            }
        }
    });
    let stdin_id = ids.get("stdin").copied();
    let resize_id = ids.get("resize").copied();
    let (out_id, err_id) = (ids.get("stdout").copied(), ids.get("stderr").copied());
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    let mut client_gone = false;
    let mut input_done = false;
    let mut held = VecDeque::new();
    loop {
        if input_done && held.is_empty() {
            break;
        }
        tokio::select! {
            r = pass_input(&stdin_tx, &mut held), if !held.is_empty() => r,
            e = ev.recv(), if held.is_empty() => match e {
                None | Some(crate::spdy::Event::Closed) => {
                    client_gone = true;
                    break;
                }
                Some(crate::spdy::Event::Data { id: sid, data, fin }) => {
                    if Some(sid) == stdin_id {
                        if !data.is_empty() {
                            held.push_back(Some(data));
                        }
                        if fin {
                            held.push_back(None);
                            input_done = channels.input_ends;
                        }
                    } else if Some(sid) == resize_id && !id.is_empty() {
                        resize(&*engine, &id, &data).await;
                    }
                }
                Some(crate::spdy::Event::Reset { id: sid }) if Some(sid) == stdin_id => {
                    held.push_back(None);
                    input_done = channels.input_ends;
                }
                Some(_) => {}
            },
            n = eng_rd.read(&mut chunk) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if framed {
                        pending.extend_from_slice(&chunk[..n]);
                        let (mut o, mut e) = (Vec::new(), Vec::new());
                        crate::engine::varlink::demux(&mut pending, &mut o, &mut e);
                        if let (false, Some(sid)) = (o.is_empty(), out_id) { h.data(sid, &o, false).await; }
                        if let (false, Some(sid)) = (e.is_empty(), err_id) { h.data(sid, &e, false).await; }
                    } else if let Some(sid) = out_id {
                        h.data(sid, &chunk[..n], false).await;
                    }
                }
            },
        }
    }
    let code = ended(&*engine, &id, client_gone, exit_status).await;
    for sid in [out_id, err_id].into_iter().flatten() {
        h.data(sid, &[], true).await;
    }
    if let Some(sid) = ids.get("error") {
        h.data(*sid, status_message(&code).as_bytes(), true).await;
    }
    h.finish().await;
}

/// Port-forward over SPDY (`portforward.k8s.io`): for each request the client
/// opens an `error` and a `data` stream with the `port` and a `requestid`;
/// the port of the pod is dialed then and the bytes go both ways.
///
/// A session that has had no connection open (and no request half made) for
/// `idle` ends; zero: it does not.
pub async fn run_ports_spdy<E: Engine, T>(
    engine: Arc<E>,
    io: T,
    pod: String,
    allowed: Vec<u16>,
    idle: Duration,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use crate::spdy::Event;
    #[derive(Default)]
    struct Request {
        port: u16,
        error: Option<u32>,
        data: Option<u32>,
    }
    let (h, mut ev) = crate::spdy::serve(io);
    let mut requests: HashMap<String, Request> = HashMap::new();
    let mut routes: HashMap<u32, mpsc::Sender<Option<Vec<u8>>>> = HashMap::new();
    // a permit per connection open: given back when it ends
    let forwards = Arc::new(tokio::sync::Semaphore::new(MAX_FORWARDS));
    // told when a connection ends: the idle time counts from then
    let ended = Arc::new(tokio::sync::Notify::new());
    let mut idle_since = tokio::time::Instant::now();
    loop {
        let busy = forwards.available_permits() < MAX_FORWARDS || !requests.is_empty();
        if busy {
            idle_since = tokio::time::Instant::now();
        }
        // (a timeout too far to be an instant is no timeout)
        let deadline = idle_since.checked_add(idle).filter(|_| !idle.is_zero());
        let e = tokio::select! {
            e = ev.recv() => match e {
                Some(e) => e,
                None => break,
            },
            _ = ended.notified() => {
                idle_since = tokio::time::Instant::now();
                continue;
            }
            _ = tokio::time::sleep_until(deadline.unwrap_or(idle_since)), if !busy && deadline.is_some() => {
                tracing::debug!("the port-forward session of {pod} was idle for {idle:?}");
                break;
            }
        };
        match e {
            Event::Closed => break,
            Event::Stream { id, headers, .. } => {
                let kind = header(&headers, "streamtype").to_string();
                let port = header(&headers, "port").parse::<u16>();
                let request = header(&headers, "requestid").to_string();
                let Ok(port) = port else {
                    h.reset(id).await;
                    continue;
                };
                if !matches!(kind.as_str(), "error" | "data") {
                    h.reset(id).await;
                    continue;
                }
                if !requests.contains_key(&request) && requests.len() >= MAX_HALF_OPEN {
                    h.reset(id).await;
                    continue;
                }
                h.reply(id, Vec::new()).await;
                let r = requests.entry(request.clone()).or_default();
                r.port = port;
                if kind == "error" {
                    r.error = Some(id);
                } else {
                    r.data = Some(id);
                }
                let (Some(error), Some(data)) = (r.error, r.data) else {
                    continue;
                };
                requests.remove(&request);
                let permit = if !allowed.is_empty() && !allowed.contains(&port) {
                    Err(format!("port {port} is not one of the ports asked for"))
                } else {
                    forwards
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| "too many connections".to_string())
                };
                let permit = match permit {
                    Ok(p) => p,
                    Err(why) => {
                        h.data(error, why.as_bytes(), true).await;
                        h.data(data, &[], true).await;
                        continue;
                    }
                };
                // the routes of the connections that ended go
                routes.retain(|_, tx| !tx.is_closed());
                let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>(256);
                routes.insert(data, tx);
                let (engine, h, pod) = (engine.clone(), h.clone(), pod.clone());
                let ended = ended.clone();
                tokio::spawn(async move {
                    forward(engine, h, pod, port, error, data, rx).await;
                    // the place is given back when the connection ends
                    drop(permit);
                    ended.notify_one();
                });
            }
            Event::Data { id, data, fin } => {
                // a connection that does not drain its queue is reset, the
                // others of the session are not held up by it
                let full = routes.get(&id).is_some_and(|tx| {
                    (!data.is_empty() && tx.try_send(Some(data)).is_err())
                        || (fin && tx.try_send(None).is_err())
                });
                if full {
                    routes.remove(&id);
                    h.reset(id).await;
                }
            }
            Event::Reset { id } => {
                routes.remove(&id);
            }
        }
    }
    drop(routes);
    h.finish().await;
}

/// One forwarded connection: dial the port of the pod, copy.
async fn forward<E: Engine>(
    engine: Arc<E>,
    h: crate::spdy::Handle,
    pod: String,
    port: u16,
    error: u32,
    data: u32,
    mut from_client: mpsc::Receiver<Option<Vec<u8>>>,
) {
    let conn = match engine.pod_dial(&pod, port).await {
        Ok(c) => c,
        Err(e) => {
            h.data(
                error,
                format!("connecting to port {port}: {e}").as_bytes(),
                true,
            )
            .await;
            h.data(data, &[], true).await;
            return;
        }
    };
    let (mut rd, mut wr) = tokio::io::split(conn);
    let writer = tokio::spawn(async move {
        while let Some(m) = from_client.recv().await {
            match m {
                Some(d) => {
                    if wr.write_all(&d).await.is_err() {
                        return;
                    }
                }
                None => {
                    let _ = wr.shutdown().await;
                }
            }
        }
        let _ = wr.shutdown().await;
    });
    let mut buf = vec![0u8; 16 * 1024];
    while let Ok(n) = rd.read(&mut buf).await {
        if n == 0 {
            break;
        }
        h.data(data, &buf[..n], false).await;
    }
    h.data(data, &[], true).await;
    h.data(error, &[], true).await;
    writer.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept() {
        // RFC 6455 section 1.3
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn frames() {
        let f = encode_frame(0x2, b"hello");
        assert_eq!(parse_frame(&f).unwrap().unwrap().0.payload, b"hello");
        let big = vec![7u8; 70000];
        let f = encode_frame(0x2, &big);
        let (fr, used) = parse_frame(&f).unwrap().unwrap();
        assert_eq!((fr.payload.len(), used), (70000, f.len()));
        assert!(parse_frame(&f[..10]).unwrap().is_none());
        // masked, as clients send
        let mut m = vec![0x82, 0x83, 1, 2, 3, 4];
        m.extend([b'a' ^ 1, b'b' ^ 2, b'c' ^ 3]);
        assert_eq!(parse_frame(&m).unwrap().unwrap().0.payload, b"abc");
    }

    #[test]
    fn protocols() {
        assert_eq!(
            choose_protocol("v4.channel.k8s.io, v5.channel.k8s.io"),
            Some("v5.channel.k8s.io")
        );
        assert_eq!(
            choose_protocol("v4.channel.k8s.io"),
            Some("v4.channel.k8s.io")
        );
        assert_eq!(choose_protocol("base64.channel.k8s.io"), None);
    }

    #[test]
    fn sessions_are_one_shot() {
        let s = Sessions::default();
        let t = s.add(Session::PortForward {
            pod: "p".into(),
            ports: vec![80],
        });
        assert!(s.take(&t).is_some());
        assert!(s.take(&t).is_none());
    }

    /// An exit status that cannot be known is a failure, never a success.
    #[test]
    fn status() {
        assert!(status_message(&Ok(0)).contains("Success"));
        assert!(status_message(&Ok(3)).contains("\"message\":\"3\""));
        let unknown = status_message(&Err("no exit status".into()));
        assert!(unknown.contains("\"status\":\"Failure\""), "{unknown}");
        assert!(unknown.contains("InternalError"), "{unknown}");
        assert!(unknown.contains("no exit status"), "{unknown}");
    }
}
