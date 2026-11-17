// SPDX-License-Identifier: Apache-2.0
//! ping, the events, version, info, df, prune, check, auth.

use super::call::{Call, Filters};
use super::error::{ApiError, ApiResult};
use super::reply;
use super::{route, Route};
use crate::engine::engine_call;
use serde_json::{json, Value};
use velarx_proto::duration::parse_go_duration;
use velarx_proto::system::CheckSpec;
use velarx_proto::time::{parse_input_time, Toward};

/// `GET /_ping`: the engine answers, and the headers Docker clients look at.
async fn ping(call: Call) -> ApiResult {
    call.engine.ping().await?;
    let body = if call.head() { "" } else { "OK" };
    let mut r = reply::text(200, body);
    // HEAD has no body but the length of the GET
    if call.head() {
        r = reply::header(r, "content-length", "2");
    }
    for (k, v) in [
        ("buildkit-version", ""),
        ("builder-version", "1"),
        ("docker-experimental", "true"),
        ("cache-control", "no-cache"),
        ("ostype", "linux"),
        ("pragma", "no-cache"),
    ] {
        r = reply::header(r, k, v);
    }
    Ok(r)
}

/// `GET /events`: a JSON document each line (podman's or Docker's of the
/// engine's records), until the client goes away or `until`.  The
/// `since` and `until` of the query, else of the filters, are podman's
/// times.
async fn events(call: Call) -> ApiResult {
    let Filters(given) = call.filters()?;
    let stream = call.q_bool("stream", true)?;
    let (libpod, modern) = (call.libpod, !call.libpod && call.at_least(1, 52));
    let now = velarx_shape::time::now_ns();
    let time = |key: &str, toward: Toward| -> ApiResult<Option<i64>> {
        let filtered = given
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.first().map(String::as_str));
        match call.q(key).filter(|s| !s.is_empty()).or(filtered) {
            None => Ok(None),
            Some(s) => parse_input_time(s, now, toward, false)
                .map(Some)
                .ok_or_else(|| {
                    ApiError::bad_request(format!(
                        "failed to parse event filters: invalid {key} `{s}`"
                    ))
                }),
        }
    };
    let (since, until) = (time("since", Toward::Past)?, time("until", Toward::Future)?);
    let filters = Filters(
        given
            .into_iter()
            .filter(|(k, _)| k != "since" && k != "until")
            .collect(),
    );
    let mut rx = call
        .engine
        .event_list(&filters, since, until, stream)
        .await?;
    // (the first reply: of a follow that it was taken, else the first
    // event or the end; an error before the head is its status)
    let first = match rx.recv().await {
        Some(Err(e)) => return Err(e),
        Some(Ok(r)) => r.event,
        None => None,
    };
    let line = move |ev: &velarx_proto::workload::Event| {
        (!libpod || velarx_shape::event::libpod_shows(ev)).then(|| {
            let mut line = velarx_shape::event::document(ev, libpod, modern).to_string();
            line.push('\n');
            Ok::<_, std::io::Error>(axum::body::Bytes::from(line))
        })
    };
    let lines = futures::stream::unfold((first, rx), move |(mut next, mut rx)| async move {
        loop {
            if let Some(line) = next.take().as_ref().and_then(line) {
                return Some((line, (None, rx)));
            }
            next = match rx.recv().await? {
                Ok(r) => r.event,
                // (the head went: the stream ends)
                Err(_) => return None,
            };
        }
    });
    Ok(reply::with_type(
        200,
        "application/json",
        axum::body::Body::from_stream(lines),
    ))
}

/// `GET /version`
async fn version(call: Call) -> ApiResult {
    let v = engine_call!(call.engine, version_inspect())?.version;
    Ok(reply::json(200, &velarx_shape::system::version(&v)))
}

/// `GET /info`: podman's (`remoteSocket`: the socket of the request), or
/// Docker's.
async fn info(call: Call) -> ApiResult {
    let system = engine_call!(call.engine, system_inspect())?.system;
    let shown = if call.libpod {
        let socket = call.socket.as_ref().map(|s| s.0.as_path());
        let path = socket.map(|s| s.to_string_lossy().into_owned());
        let exists = socket.is_some_and(|s| s.exists());
        velarx_shape::system::libpod_info(&system, path.as_deref().map(|p| (p, exists)))
    } else {
        velarx_shape::system::docker_info(&system, call.version, velarx_shape::time::now_ns())
    };
    Ok(reply::json(200, &shown))
}

/// `GET /system/df`: podman's, or Docker's.
async fn df(call: Call) -> ApiResult {
    let usage = engine_call!(call.engine, disk_usage_inspect(false))?.usage;
    let shown = if call.libpod {
        velarx_shape::system::libpod_df(&usage)
    } else {
        velarx_shape::system::docker_df(&usage, call.version)
    };
    Ok(reply::json(200, &shown))
}

/// `POST /libpod/system/prune`
async fn prune(call: Call) -> ApiResult {
    let all = call.q_bool("all", false)?;
    let volumes = call.q_bool("volumes", false)?;
    let build = call.q_bool("build", false)?;
    let filters = call.filters()?;
    let report = call
        .engine
        .system_prune(all, volumes, build, &filters)
        .await?;
    Ok(reply::json(
        200,
        &velarx_shape::system::libpod_prune(&report),
    ))
}

/// `POST /libpod/system/check`
async fn check(call: Call) -> ApiResult {
    let quick = call.q_bool("quick", false)?;
    // (as podman, repair_lossy alone repairs nothing)
    let repair = call.q_bool("repair", false)?;
    let lossy = call.q_bool("repair_lossy", false)?;
    let max_age_ms = match call.q("unreferenced_layer_max_age").filter(|a| !a.is_empty()) {
        Some(a) => Some(
            parse_go_duration(a)
                .ok_or_else(|| {
                    ApiError::bad_request(format!(
                        "failed to parse unreferenced_layer_max_age parameter {a:?} for {}: time: invalid duration {a:?}",
                        call.target
                    ))
                })?
                .as_millis() as u64,
        ),
        None => None,
    };
    let spec = CheckSpec {
        quick,
        repair,
        repair_lossy: repair && lossy,
        timeout_ms: None,
        max_age_ms,
    };
    let report = engine_call!(call.engine, system_check(spec))?.report;
    Ok(reply::json(200, &velarx_shape::system::check(&report)))
}

/// `POST /auth`: a login to a registry, as podman answers it.
async fn auth(mut call: Call) -> ApiResult {
    let body: Value = call.json_value().await?.unwrap_or(Value::Null);
    let field = |k: &str| body.get(k).and_then(Value::as_str).unwrap_or("");
    let (user, pass) = (field("username"), field("password"));
    // podman answers a failed login with a 500 and only a message
    let failed = |status: &str| {
        let msg = format!(
            "login attempt to {} failed with status: {status}",
            field("serveraddress")
        );
        Ok(reply::json(500, &json!({"message": msg})))
    };
    // (podman's words: the server has no terminal to ask on)
    if user.is_empty() {
        return failed("cannot prompt for username without stdin");
    }
    if body.get("password").is_none() {
        return failed("reading password: inappropriate ioctl for device");
    }
    let server = match field("serveraddress") {
        "" => "docker.io",
        s => s,
    };
    let server = server.split_once("://").map_or(server, |(_, r)| r);
    let mut registry = server.split('/').next().unwrap_or("").to_string();
    if registry == "index.docker.io" || registry == "registry-1.docker.io" {
        registry = "docker.io".into();
    }
    if registry.is_empty()
        || !registry
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
    {
        return Err(ApiError::bad_request("invalid server address"));
    }
    let host = if registry == "docker.io" {
        "registry-1.docker.io".to_string()
    } else {
        registry
    };
    let login = call.engine.registry_login(&host, user, pass).await?;
    match login.failure {
        None => Ok(reply::json(
            200,
            &json!({"Status": "Login Succeeded", "IdentityToken": ""}),
        )),
        // (podman's status for a registry that refuses the credentials)
        Some(_) if login.unauthorized => failed("401 Unauthorized"),
        Some(failure) => failed(&failure),
    }
}

/// The swagger spec of the libpod API that `/libpod/swagger` serves (a
/// copy of podman's, in velarx's directory).
fn swagger_path() -> std::path::PathBuf {
    "/usr/share/velarx/swagger.yaml".into()
}

/// podman's spec of its API, opened before the frontend confines itself
/// (it reads no file after): the file, or why it is not there.
static SWAGGER: std::sync::OnceLock<Result<std::fs::File, String>> = std::sync::OnceLock::new();

/// Open podman's spec of its API, for `GET /libpod/swagger`: before the
/// frontend confines itself.
pub fn open_swagger() {
    let path = swagger_path();
    let opened = std::fs::File::open(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!(
                "swagger spec {:?} does not exist",
                path.display().to_string()
            )
        } else {
            e.to_string()
        }
    });
    let _ = SWAGGER.set(opened);
}

/// `GET /libpod/swagger`: podman's description of its API, as it is.
async fn swagger(_call: Call) -> ApiResult {
    let file = match SWAGGER.get() {
        Some(Ok(f)) => f
            .try_clone()
            .map_err(|e| ApiError::internal(e.to_string()))?,
        Some(Err(e)) => return Err(ApiError::internal(e.clone())),
        None => return Err(ApiError::internal("the swagger spec was not opened")),
    };
    let spec = tokio::task::spawn_blocking(move || {
        use std::os::unix::fs::FileExt;
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 << 10];
        loop {
            match file.read_at(&mut buf, out.len() as u64) {
                Ok(0) => return Ok(out),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(reply::with_type(200, "text/yaml", spec))
}

pub(super) static ROUTES: &[Route] = &[
    route!("GET", "/_ping", BOTH, None, ping),
    route!("GET", "/events", BOTH, None, events),
    route!("GET", "/version", BOTH, None, version),
    route!("GET", "/info", BOTH, None, info),
    route!("GET", "/system/df", BOTH, None, df),
    route!("POST", "/system/prune", LIBPOD, None, prune),
    route!("POST", "/system/check", LIBPOD, None, check),
    route!("POST", "/auth", BOTH, None, auth),
    route!("GET", "/swagger", LIBPOD, None, swagger),
];
