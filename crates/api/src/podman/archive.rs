// SPDX-License-Identifier: Apache-2.0
//! The files of containers: archives of paths (`cp`), the export of the
//! root file system, the changes, the mounts.

use super::call::Call;
use super::error::{ApiError, ApiResult};
use super::reply;
use super::{route, Route};
use crate::engine::{engine_call, raw_call};
use base64::Engine as _;
use serde_json::json;
use std::collections::HashMap;

/// The `path` of a request of the archive of a container.
fn query_path(call: &Call) -> ApiResult<&str> {
    call.q("path")
        .filter(|p| !p.is_empty())
        .ok_or_else(|| ApiError::bad_request("missing the path"))
}

/// Go's `FileMode` bits of a Unix `st_mode`: the permissions, the type
/// (a directory, a link) and the setuid, setgid and sticky bits.
fn go_mode(mode: u32) -> u32 {
    const TYPE: u32 = 0o170000;
    let mut m = mode & 0o777;
    match mode & TYPE {
        0o040000 => m |= 1 << 31,
        0o120000 => m |= 1 << 27,
        _ => {}
    }
    if mode & 0o4000 != 0 {
        m |= 1 << 23;
    }
    if mode & 0o2000 != 0 {
        m |= 1 << 22;
    }
    if mode & 0o1000 != 0 {
        m |= 1 << 20;
    }
    m
}

/// Go's filepath.Base: the last element without trailing separators, "/"
/// for the root.
fn go_base(path: &str) -> String {
    let t = path.trim_end_matches('/');
    if t.is_empty() {
        return if path.is_empty() {
            ".".into()
        } else {
            "/".into()
        };
    }
    t.rsplit('/').next().unwrap_or(t).to_string()
}

/// A time as Go's RFC3339Nano writes it (UTC, the nanoseconds without
/// their trailing zeros); "0001-01-01T00:00:00Z" for 0.
fn go_time(ns: i64) -> String {
    if ns <= 0 {
        return "0001-01-01T00:00:00Z".into();
    }
    velarx_proto::time::format_rfc3339(ns, velarx_proto::time::Fraction::Trimmed)
}

/// `X-Docker-Container-Path-Stat`: what is at the path, as JSON in base64
/// (libpod names a link by its target).
fn stat_header(stat: &velarx_proto::engine::PathStat, libpod: bool) -> String {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Shown<'a> {
        name: &'a str,
        size: i64,
        mode: u32,
        mtime: String,
        link_target: &'a str,
        is_dir: bool,
    }
    let name = if libpod {
        go_base(&stat.link_target)
    } else {
        stat.name.clone()
    };
    let shown = Shown {
        name: &name,
        size: stat.size,
        mode: go_mode(stat.mode),
        mtime: go_time(stat.mtime_ns),
        link_target: &stat.link_target,
        is_dir: stat.is_dir,
    };
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&shown).unwrap_or_default())
}

/// `GET` and `HEAD /containers/{name}/archive?path=`: the tar of the path,
/// and what it is in the header.
async fn archive_get(call: Call) -> ApiResult {
    let path = query_path(&call)?;
    let content = !call.head();
    let (stat, body) = call
        .engine
        .container_archive_get(call.param(0), path, content)
        .await?;
    let res = reply::with_type(200, "application/x-tar", body.unwrap_or_default());
    Ok(reply::header(
        res,
        "x-docker-container-path-stat",
        &stat_header(&stat, call.libpod),
    ))
}

/// `PUT /containers/{name}/archive?path=`: extract the tar of the body
/// into the directory.
async fn archive_put(mut call: Call) -> ApiResult {
    let path = query_path(&call)?.to_string();
    let rename: HashMap<String, String> = match call.q("rename").filter(|r| !r.is_empty()) {
        Some(r) => serde_json::from_str(r)
            .map_err(|_| ApiError::bad_request(format!("invalid rename `{r}`")))?,
        None => Default::default(),
    };
    // Docker keeps the owners of the archive unless copyUIDGID; libpod
    // gives the files to the user of the container unless told not to
    let chown = call.q_bool("copyUIDGID", call.libpod)?;
    // podman cp --overwrite: a directory and what is not one replace each
    // other unless noOverwriteDirNonDir (which Docker and podman send)
    let overwrite = !call.q_bool("noOverwriteDirNonDir", false)?;
    let body = call.take_body();
    call.engine
        .container_archive_put(call.param(0), &path, rename, chown, overwrite, body)
        .await
        // (podman answers a body that is not a tar archive with a 500)
        .map_err(|e| {
            if e.is(velarx_proto::engine::Condition::InvalidArchive) {
                e.as_podman_failure()
            } else {
                e
            }
        })?;
    Ok(reply::empty(200))
}

/// `GET /containers/{name}/export`: the root file system as a tar.
async fn export(call: Call) -> ApiResult {
    let body = call.engine.container_export(call.param(0)).await?;
    Ok(reply::with_type(200, "application/x-tar", body))
}

/// `GET /containers/{name}/changes`; podman asks it for images too
/// (`diffType`).
async fn changes(call: Call) -> ApiResult {
    use velarx_proto::engine::{ChangeKind, DiffType};
    let diff_type = match call.q("diffType").unwrap_or("all") {
        "" | "all" => DiffType::All,
        "container" => DiffType::Container,
        "image" => DiffType::Image,
        t => {
            return Err(ApiError::bad_request(format!(
                "invalid diffType value {t:?}"
            )))
        }
    };
    let list = engine_call!(
        call.engine,
        container_diff(call.param(0), Some(diff_type), call.q("parent"))
    )?
    .changes;
    // (Docker's kinds of a `FilesystemChange`)
    let list: Vec<_> = list
        .into_iter()
        .map(|c| {
            let kind = match c.kind {
                ChangeKind::Modified => 0,
                ChangeKind::Added => 1,
                ChangeKind::Deleted => 2,
            };
            json!({"Path": c.path, "Kind": kind})
        })
        .collect();
    Ok(reply::json(200, &list))
}

/// libpod's `POST /containers/{name}/mount`: where the root is.
async fn mount(call: Call) -> ApiResult {
    let path = engine_call!(call.engine, container_mount(call.param(0)))?.path;
    Ok(reply::json(200, &path))
}

async fn unmount(call: Call) -> ApiResult {
    engine_call!(call.engine, container_unmount(call.param(0)))?;
    Ok(reply::empty(204))
}

/// libpod's `GET /containers/showmounted`: the mounted containers and where.
async fn show_mounted(call: Call) -> ApiResult {
    let out: serde_json::Map<String, serde_json::Value> =
        raw_call!(call.engine, container_mount_list())?
            .mounts
            .into_iter()
            .map(|(id, path)| (id, json!(path)))
            .collect();
    Ok(reply::json(200, &out))
}

pub(super) static ROUTES: &[Route] = &[
    route!(
        "GET",
        "/containers/showmounted",
        LIBPOD,
        Container,
        show_mounted
    ),
    route!("POST", "/containers/{}/mount", LIBPOD, Container, mount),
    route!("POST", "/containers/{}/unmount", LIBPOD, Container, unmount),
    route!("GET", "/containers/{*}/changes", BOTH, Container, changes),
    route!("GET", "/images/{*}/changes", LIBPOD, Image, changes),
    route!(
        "GET",
        "/containers/{}/archive",
        BOTH,
        Container,
        archive_get
    ),
    route!(
        "PUT",
        "/containers/{}/archive",
        BOTH,
        Container,
        archive_put
    ),
    route!("GET", "/containers/{}/export", BOTH, Container, export),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_has_gos_words() {
        assert_eq!(go_mode(0o040755), 0o755 | 1 << 31);
        assert_eq!(go_mode(0o120777), 0o777 | 1 << 27);
        assert_eq!(go_mode(0o104755), 0o755 | 1 << 23);
        assert_eq!(go_mode(0o100644), 0o644);
        assert_eq!(go_base("/srv/."), ".");
        assert_eq!(go_base("/srv/"), "srv");
        assert_eq!(go_base("/"), "/");
        assert_eq!(go_time(0), "0001-01-01T00:00:00Z");
        assert_eq!(go_time(1_700_000_000_000_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(
            go_time(1_700_000_000_123_000_000),
            "2023-11-14T22:13:20.123Z"
        );
        assert_eq!(
            go_time(951_782_400_000_000_001),
            "2000-02-29T00:00:00.000000001Z"
        );
    }
}
