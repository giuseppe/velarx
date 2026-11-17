// SPDX-License-Identifier: Apache-2.0
//! `POST /libpod/containers/{name}/connect?port=P` and
//! `/libpod/pods/{name}/connect`: the engine makes a TCP connection to the
//! port in the network namespace of the container (a pod's infra container)
//! and hands the socket over; this frontend relays it with the connection
//! the client upgraded (`Upgrade: tcp`).

use super::call::Call;
use super::error::{ApiError, ApiResult};
use super::{route, Route};
use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use hyper_util::rt::TokioIo;
use std::os::fd::OwnedFd;

/// Connections relayed at once.
const MAX_RELAYS: usize = 512;

static RELAYS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(MAX_RELAYS);

fn port_of(call: &Call) -> ApiResult<u16> {
    if let Some(p) = call
        .q("protocol")
        .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("tcp"))
    {
        return Err(ApiError::bad_request(format!(
            "cannot connect to a {p} port: only TCP is supported"
        )));
    }
    let p = call.q_i64("port", 0)?;
    u16::try_from(p).ok().filter(|p| *p != 0).ok_or_else(|| {
        ApiError::bad_request("the query parameter `port` is a number from 1 to 65535")
    })
}

/// Answer `101 Switching Protocols` and relay the upgraded connection and the
/// socket both ways.
fn relay(mut call: Call, fd: OwnedFd, permit: tokio::sync::SemaphorePermit<'static>) -> ApiResult {
    let on_upgrade = call
        .take_upgrade()
        .ok_or_else(|| ApiError::internal("connection cannot be upgraded"))?;
    let hold = call.take_hold();
    let tcp = std::net::TcpStream::from(fd);
    tcp.set_nonblocking(true)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut tcp =
        tokio::net::TcpStream::from_std(tcp).map_err(|e| ApiError::internal(e.to_string()))?;
    let mut res = axum::response::Response::new(Body::empty());
    *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let h = res.headers_mut();
    h.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    h.insert(header::UPGRADE, HeaderValue::from_static("tcp"));
    tokio::spawn(async move {
        // (the frontend does not leave while the connection is relayed)
        let _hold = hold;
        let _permit = permit;
        let upgraded = match on_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                tracing::debug!("upgrade failed: {e}");
                return;
            }
        };
        let mut client = TokioIo::new(upgraded);
        if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut tcp).await {
            tracing::debug!("connection to a port ended: {e}");
        }
    });
    Ok(res)
}

async fn connect(call: Call, pod: bool) -> ApiResult {
    if !call.wants_upgrade() {
        return Err(ApiError::bad_request(
            "connect needs `Connection: Upgrade` and `Upgrade: tcp`",
        ));
    }
    let port = port_of(&call)?;
    let permit = RELAYS.try_acquire().map_err(|_| {
        ApiError::new(
            503,
            format!("too many connections to ports relayed at once (the limit is {MAX_RELAYS})"),
        )
    })?;
    let fd = call.engine.connect_port(pod, call.param(0), port).await?;
    relay(call, fd, permit)
}

async fn container(call: Call) -> ApiResult {
    connect(call, false).await
}

async fn pod(call: Call) -> ApiResult {
    connect(call, true).await
}

pub(super) static ROUTES: &[Route] = &[
    route!(
        "POST",
        "/containers/{}/connect",
        LIBPOD,
        Container,
        container
    ),
    route!("POST", "/pods/{}/connect", LIBPOD, Pod, pod),
];
