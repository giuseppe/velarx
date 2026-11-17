// SPDX-License-Identifier: Apache-2.0
//! The streams of exec and attach: the engine answers a session and,
//! once the process is there, hands over its streams; this frontend copies them with
//! the client's connection (Docker's frames, or raw with a terminal, for the
//! output of the process, and the input of the client through the detach
//! keys), which it takes over when the client asked for it (`101 Switching
//! Protocols`), else the output is the body of a `200` response.

use super::call::Call;
use super::error::{ApiError, ApiResult};
use crate::engine::Hijacked;
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt};
use velarx_proto::stream;

/// The type of the stream of an attach or an exec: multiplexed without a
/// terminal for the clients of Docker's API 1.42 and libpod's 4.7 on, raw
/// otherwise (podman's writeHijackHeader).
fn content_type(call: &Call, tty: bool) -> &'static str {
    let multiplexed = if call.libpod {
        call.at_least(4, 7)
    } else {
        call.at_least(1, 42)
    };
    if !tty && multiplexed {
        "application/vnd.docker.multiplexed-stream"
    } else {
        "application/vnd.docker.raw-stream"
    }
}

/// Whether the engine is told that the client can send input.
pub fn upgraded(call: &Call) -> bool {
    call.wants_upgrade()
}

/// The answer to a request that attaches to a process.
pub fn respond(call: &mut Call, h: Hijacked) -> ApiResult<Response> {
    let session = h.0;
    let content_type = content_type(call, session.tty());
    if call.wants_upgrade() {
        let on_upgrade = call
            .take_upgrade()
            .ok_or_else(|| ApiError::internal("connection cannot be upgraded"))?;
        let hold = call.take_hold();
        let peer = call.peer.as_ref().and_then(|p| p.0.try_clone().ok());
        let mut res = Response::new(Body::empty());
        *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        let headers = res.headers_mut();
        headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("tcp"));
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        tokio::spawn(async move {
            // (the frontend does not leave while the connection is spliced)
            let _hold = hold;
            let upgraded = match on_upgrade.await {
                Ok(u) => u,
                Err(e) => {
                    tracing::debug!("upgrade failed: {e}");
                    return;
                }
            };
            let (reader, writer) = tokio::io::split(TokioIo::new(upgraded));
            let _ = stream::spawn(session, Some(Box::new(reader)), Box::new(writer), peer).await;
        });
        Ok(res)
    } else {
        // (no input: our end stays open as long as the client reads, and its
        // close is the client gone)
        let socket = stream::connect(session, false)
            .map_err(|e| ApiError::internal(format!("the streams of the engine: {e}")))?;
        let (r, w) = socket.into_split();
        let mut res = Response::new(reader_body(r, w));
        if let Ok(v) = HeaderValue::from_str(content_type) {
            res.headers_mut().insert(header::CONTENT_TYPE, v);
        }
        Ok(res)
    }
}

/// What the socket carries, as the body of a response, to its end; `keep`
/// lives as long as the body.
fn reader_body<R, K>(reader: R, keep: K) -> Body
where
    R: AsyncRead + Send + Unpin + 'static,
    K: Send + 'static,
{
    Body::from_stream(futures::stream::unfold(
        (reader, keep),
        |(mut r, k)| async move {
            let mut buf = bytes::BytesMut::with_capacity(32 * 1024);
            match r.read_buf(&mut buf).await {
                Ok(n) if n > 0 => Some((Ok::<Bytes, std::io::Error>(buf.freeze()), (r, k))),
                _ => None,
            }
        },
    ))
}
