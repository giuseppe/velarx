// SPDX-License-Identifier: Apache-2.0
//! The REST API: the `/libpod` routes and the Docker ones.
//!
//! A request is routed by [`dispatch`], which strips the `/v{version}` and
//! `/libpod` prefixes and runs the first route of the tables that matches.
//! A handler decodes the request (path, query, headers, body) into the
//! typed arguments of a call of the engine, makes it ([`crate::engine`]),
//! and encodes what the engine sends back.  Errors are podman's
//! `{"cause","message","response"}`.
//!
//! The routes are moved here from the engine's API server one group at a
//! time; a route that is not here yet answers 404 with no route.

mod archive;
mod artifacts;
pub(crate) mod build;
pub mod call;
mod connect;
mod containers;
pub mod error;
mod exec;
mod hijack;
mod images;
mod manifests;
pub(crate) mod multipart;
mod networks;
mod pods;
pub mod reply;
pub(crate) mod secrets;
mod stats;
pub mod system;
mod systemd;
mod update;
mod volumes;

use crate::engine::Engine;
use axum::extract::{Request, State};
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::response::Response;
use call::{decode, parse_query, Call};
use error::{ApiError, ApiResult, Kind};
use std::future::Future;
use std::pin::Pin;

use velarx_shape::system::{COMPAT_VERSION, LIBPOD_VERSION};

pub type HandlerFuture = Pin<Box<dyn Future<Output = ApiResult> + Send>>;

pub const LIBPOD: u8 = 1;
pub const COMPAT: u8 = 2;
pub const BOTH: u8 = LIBPOD | COMPAT;

pub struct Route {
    pub method: &'static str,
    /// After the `/v{version}` and `/libpod` prefixes: `{}` matches a
    /// segment, `{*}` one or more segments (image names).
    pub pattern: &'static str,
    pub flags: u8,
    pub kind: Kind,
    pub handler: fn(Call) -> HandlerFuture,
}

/// `route!("GET", "/containers/json", BOTH, Container, containers::list)`
macro_rules! route {
    ($m:literal, $p:literal, $f:ident, $k:ident, $h:path) => {
        $crate::podman::Route {
            method: $m,
            pattern: $p,
            flags: $crate::podman::$f,
            kind: $crate::podman::error::Kind::$k,
            handler: |c| Box::pin($h(c)),
        }
    };
}
pub(crate) use route;

/// Route tables, in the order they are tried.
fn tables() -> [&'static [Route]; 14] {
    [
        system::ROUTES,
        archive::ROUTES,
        systemd::ROUTES,
        connect::ROUTES,
        images::ROUTES,
        containers::ROUTES,
        exec::ROUTES,
        volumes::ROUTES,
        networks::ROUTES,
        secrets::ROUTES,
        pods::ROUTES,
        manifests::ROUTES,
        artifacts::ROUTES,
        build::ROUTES,
    ]
}

/// The `/v{version}` prefix: `v` and a digit start it; returns the version
/// and the rest of the path.
fn split_version(path: &str) -> (Option<(u32, u32)>, &str) {
    let b = path.as_bytes();
    if b.len() > 2 && b[0] == b'/' && b[1] == b'v' && b[2].is_ascii_digit() {
        let end = path[1..].find('/').map(|i| i + 1).unwrap_or(path.len());
        let v = &path[2..end];
        // the clients of this API send a version with a dot
        if !v.contains('.') {
            return (None, path);
        }
        let mut parts = v.split('.');
        let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        return (Some((major, minor)), &path[end..]);
    }
    (None, path)
}

fn split_libpod(path: &str) -> (bool, &str) {
    if path == "/libpod" {
        (true, "/")
    } else if let Some(rest) = path.strip_prefix("/libpod/") {
        // keep the leading slash of the rest
        (true, &path[path.len() - rest.len() - 1..])
    } else {
        (false, path)
    }
}

/// Match the segments of `path` against `pattern` (both after a `/`); the
/// `{}` and `{*}` parts are appended to `params`.
pub fn match_segments(pattern: &str, path: &str, params: &mut Vec<String>) -> bool {
    let (pseg, prest) = match pattern.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (pattern, None),
    };
    let last = prest.is_none();

    if pseg == "{*}" {
        if path.is_empty() {
            return false;
        }
        if last {
            params.push(path.to_string());
            return true;
        }
        // The longest name first: it may contain the next segment.
        let rest = prest.unwrap_or("");
        let idx: Vec<usize> = path.match_indices('/').map(|(i, _)| i).collect();
        for &k in idx.iter().rev() {
            if k == 0 {
                continue;
            }
            params.push(path[..k].to_string());
            if match_segments(rest, &path[k + 1..], params) {
                return true;
            }
            params.pop();
        }
        return false;
    }

    let (sseg, srest) = match path.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (path, None),
    };
    if sseg.is_empty() || srest.is_none() != last {
        return false;
    }
    let pushed = pseg == "{}";
    if pushed {
        params.push(sseg.to_string());
    } else if pseg != sseg {
        return false;
    }
    match (prest, srest) {
        (Some(pr), Some(sr)) => {
            if match_segments(pr, sr, params) {
                return true;
            }
            if pushed {
                params.pop();
            }
            false
        }
        _ => true,
    }
}

enum Found<'a> {
    Route(&'a Route, Vec<String>),
    WrongMethod,
    None,
}

fn find_route<'a>(tables: &[&'a [Route]], method: &Method, libpod: bool, path: &str) -> Found<'a> {
    let head = method == Method::HEAD;
    let mut other = false;
    let want = if libpod { LIBPOD } else { COMPAT };
    for t in tables {
        for r in t.iter() {
            if r.flags & want == 0 || !r.pattern.starts_with('/') || !path.starts_with('/') {
                continue;
            }
            let mut params = Vec::new();
            if !match_segments(&r.pattern[1..], &path[1..], &mut params) {
                continue;
            }
            if r.method == method.as_str() || (head && r.method == "GET") {
                return Found::Route(r, params);
            }
            other = true;
        }
    }
    if other {
        Found::WrongMethod
    } else {
        Found::None
    }
}

fn common_headers(res: &mut Response) {
    let h = res.headers_mut();
    h.insert(
        HeaderName::from_static("api-version"),
        HeaderValue::from_static(COMPAT_VERSION),
    );
    h.insert(
        HeaderName::from_static("libpod-api-version"),
        HeaderValue::from_static(LIBPOD_VERSION),
    );
    h.insert(
        header::SERVER,
        HeaderValue::from_static(concat!("velarx/", env!("CARGO_PKG_VERSION"), " (linux)")),
    );
}

/// The answer to a request no route takes.
fn no_route(method: &Method, path: &str) -> Response {
    ApiError::new(404, format!("no route for `{method} {path}`"))
        .with_cause("page not found")
        .into_response(Kind::None)
}

/// Every request: the route of the tables that takes it.
pub async fn dispatch(State(engine): State<Engine>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let upgrade = parts.extensions.remove::<hyper::upgrade::OnUpgrade>();
    let hold = parts.extensions.remove::<call::Hold>();
    let peer = parts.extensions.remove::<call::PeerFd>();
    let socket = parts.extensions.remove::<call::LocalSocket>();
    let raw_path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("").to_string();

    let (version, rest) = split_version(&raw_path);
    let (libpod, path) = split_libpod(rest);

    let tables = tables();
    let mut res = match find_route(&tables, &parts.method, libpod, path) {
        Found::Route(route, params) => {
            let mut call = Call::new(
                engine,
                parts.method.clone(),
                parts.headers,
                body,
                upgrade,
                hold,
            );
            call.peer = peer;
            call.socket = socket;
            call.set_route(route.kind, libpod, version);
            call.params = params.iter().map(|p| decode(p, false)).collect();
            call.query = parse_query(&query);
            call.target = parts.uri.to_string();
            tracing::debug!("api: {} {}?{}", parts.method, raw_path, query);
            match (route.handler)(call).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("api: error {e}");
                    e.into_response(route.kind)
                }
            }
        }
        Found::WrongMethod => {
            call::discard(body);
            ApiError::new(
                405,
                format!("method `{}` not allowed for `{}`", parts.method, raw_path),
            )
            .into_response(Kind::None)
        }
        Found::None => {
            call::discard(body);
            no_route(&parts.method, &raw_path)
        }
    };
    common_headers(&mut res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pattern: &str, path: &str) -> Option<Vec<String>> {
        let mut p = Vec::new();
        match_segments(&pattern[1..], &path[1..], &mut p).then_some(p)
    }

    /// The test of the engine that compares the routes with the API server's
    /// parses the `route!` entries of these sources: they are exactly the
    /// routes served (none in a table it would not see, none it sees that is
    /// not in a table).
    #[test]
    fn the_route_entries_of_the_sources_are_the_tables() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/podman");
        // (not written as one word: this line would count)
        let needle = ["route", "!("].concat();
        let mut entries = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                entries += text
                    .lines()
                    .filter(|l| !l.trim_start().starts_with("//"))
                    .map(|l| l.matches(&needle).count())
                    .sum::<usize>();
            }
        }
        let served: usize = tables().iter().map(|t| t.len()).sum();
        assert_eq!(entries, served);
    }

    #[test]
    fn the_prefixes_are_split_off() {
        assert_eq!(
            split_version("/v5.8.0/libpod/_ping"),
            (Some((5, 8)), "/libpod/_ping")
        );
        assert_eq!(
            split_version("/v1.41/containers/json"),
            (Some((1, 41)), "/containers/json")
        );
        assert_eq!(
            split_version("/v1/containers/json"),
            (None, "/v1/containers/json")
        );
        assert_eq!(
            split_libpod("/libpod/containers/json"),
            (true, "/containers/json")
        );
        assert_eq!(
            split_libpod("/containers/json"),
            (false, "/containers/json")
        );
    }

    #[test]
    fn patterns_match_segments_and_names() {
        assert_eq!(
            m("/containers/{}/json", "/containers/abc/json"),
            Some(vec!["abc".into()])
        );
        assert_eq!(m("/containers/{}/json", "/containers/abc/x"), None);
        assert_eq!(
            m("/images/{*}/json", "/images/quay.io/a/b:1/json"),
            Some(vec!["quay.io/a/b:1".into()])
        );
        assert_eq!(m("/_ping", "/_ping"), Some(vec![]));
    }
}
