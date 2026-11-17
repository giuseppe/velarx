// SPDX-License-Identifier: Apache-2.0
//! Response builders.

use axum::body::Body;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use serde::Serialize;

fn status(s: u16) -> StatusCode {
    StatusCode::from_u16(s).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// JSON as Go's encoding/json writes it: a trailing newline.
pub fn json(code: u16, v: &impl Serialize) -> Response {
    match serde_json::to_vec(v) {
        Ok(mut b) => {
            b.push(b'\n');
            with_type(code, "application/json", b)
        }
        Err(e) => {
            super::error::ApiError::internal(e.to_string()).into_response(super::error::Kind::None)
        }
    }
}

/// A JSON body the caller made, with the newline; `length` when it is not in
/// memory.
pub fn json_body(code: u16, body: Body, length: Option<u64>) -> Response {
    let r = with_type(code, "application/json", body);
    match length {
        Some(n) => header(r, "content-length", &n.to_string()),
        None => r,
    }
}

pub fn empty(code: u16) -> Response {
    let mut r = Response::new(Body::empty());
    *r.status_mut() = status(code);
    r
}

pub fn with_type(code: u16, content_type: &str, body: impl Into<Body>) -> Response {
    let mut r = Response::new(body.into());
    *r.status_mut() = status(code);
    if let Ok(v) = HeaderValue::from_str(content_type) {
        r.headers_mut().insert(header::CONTENT_TYPE, v);
    }
    r
}

pub fn text(code: u16, s: impl Into<String>) -> Response {
    with_type(code, "text/plain; charset=utf-8", s.into())
}

pub fn header(mut r: Response, name: &'static str, value: &str) -> Response {
    if let Ok(v) = HeaderValue::from_str(value) {
        r.headers_mut().insert(HeaderName::from_static(name), v);
    }
    r
}

/// podman's answer of a report a client may follow (`top`, `stats`): the
/// document `first`, or with `stream` a line of it, then a line of what
/// `next` answers every `every`, until it answers none (the object went,
/// the engine failed) or the client goes away.
pub fn reports<F, Fut>(
    first: serde_json::Value,
    stream: bool,
    every: std::time::Duration,
    mut next: F,
) -> Response
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Option<serde_json::Value>> + Send,
{
    if !stream {
        return json(200, &first);
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<std::io::Result<bytes::Bytes>>(1);
    tokio::spawn(async move {
        let mut report = first;
        loop {
            let mut line = report.to_string().into_bytes();
            line.push(b'\n');
            if tx.send(Ok(line.into())).await.is_err() {
                return;
            }
            tokio::select! {
                () = tokio::time::sleep(every) => {}
                () = tx.closed() => return,
            }
            report = match next().await {
                Some(r) => r,
                None => return,
            };
        }
    });
    let body = Body::from_stream(futures::stream::poll_fn(move |cx| rx.poll_recv(cx)));
    with_type(200, "application/json", body)
}
