// SPDX-License-Identifier: Apache-2.0
//! Artifacts: libpod's routes.

use super::call::Call;
use super::error::{ApiError, ApiResult};
use super::reply;
use super::{route, Route};
use crate::engine::engine_call;
use serde_json::json;
use velarx_proto::engine::ArtifactAddSpec;
use velarx_proto::retry::Retry;

async fn list(call: Call) -> ApiResult {
    let all = call.engine.artifact_list().await?;
    let docs: Vec<_> = all
        .iter()
        .map(velarx_shape::manifest::artifact_document)
        .collect();
    Ok(reply::json(200, &docs))
}

async fn inspect(call: Call) -> ApiResult {
    let artifact = engine_call!(call.engine, artifact_inspect(call.param(0)))?.artifact;
    Ok(reply::json(
        200,
        &velarx_shape::manifest::artifact_document(&artifact),
    ))
}

async fn remove(call: Call) -> ApiResult {
    let digest = engine_call!(call.engine, artifact_remove(call.param(0)))?.id;
    Ok(reply::json(200, &json!({"ArtifactDigests": [digest]})))
}

/// `DELETE /artifacts/remove?artifacts=...&all=&ignore=`
async fn remove_batch(call: Call) -> ApiResult {
    let all = call.q_bool("all", false)?;
    let ignore = call.q_bool("ignore", false)?;
    let mut names: Vec<String> = call
        .q_all("artifacts")
        .into_iter()
        .map(str::to_string)
        .collect();
    if all && !names.is_empty() {
        return Err(ApiError::bad_request(
            "when setting all to true, you may not pass any artifact names or digests",
        ));
    }
    if !all && names.is_empty() {
        return Err(ApiError::bad_request(
            "an artifact or all option must be specified",
        ));
    }
    if all {
        names = call
            .engine
            .artifact_list()
            .await?
            .into_iter()
            .map(|a| a.digest)
            .collect();
    }
    let mut digests = Vec::new();
    for n in names {
        match engine_call!(call.engine, artifact_remove(&n)).map(|r| r.id) {
            Ok(d) => digests.push(d),
            Err(e) if ignore && e.status == 404 => {}
            Err(e) => return Err(e),
        }
    }
    Ok(reply::json(200, &json!({"ArtifactDigests": digests})))
}

/// What `POST /artifacts/add` and `local/add` ask.
fn add_spec(call: &Call) -> ApiResult<ArtifactAddSpec> {
    Ok(ArtifactAddSpec {
        name: call.q("name").unwrap_or_default().to_string(),
        file_name: call.q("fileName").unwrap_or_default().to_string(),
        append: call.q_bool("append", false)?,
        replace: call.q_bool("replace", false)?,
        artifact_type: call.q("artifactMIMEType").map(str::to_string),
        file_type: call.q("fileMIMEType").map(str::to_string),
        annotations: super::call::annotations(call.q_all("annotations"))?,
        digest: None,
    })
}

/// `POST /artifacts/add`: the body is a file of the artifact.
async fn add(mut call: Call) -> ApiResult {
    let spec = add_spec(&call)?;
    let body = call.take_body();
    let digest = call.engine.artifact_add(spec, body).await?;
    Ok(reply::json(201, &json!({ "ArtifactDigest": digest })))
}

/// podman's `artifacts/local/add`: the file is on the host, at `path`
/// (the engine opens it).
async fn add_local(call: Call) -> ApiResult {
    let spec = add_spec(&call)?;
    let digest = call
        .engine
        .artifact_add_local(spec, call.q("path").unwrap_or_default())
        .await?;
    Ok(reply::json(201, &json!({ "ArtifactDigest": digest })))
}

/// The pull or the push of an artifact (`delay_key`: the name of its delay).
async fn transfer(call: Call, push: bool, delay_key: &str) -> ApiResult {
    let tls_verify = call.q_bool("tlsVerify", true)?;
    let access = call.registry_access()?;
    let count = call.q_i64("retry", 3)?.clamp(0, 100) as u32;
    let name = if push {
        call.param(0).to_string()
    } else {
        call.q("name").unwrap_or_default().to_string()
    };
    let digest = call
        .engine
        .artifact_transfer(
            push,
            &name,
            tls_verify,
            Retry {
                count,
                delay_ms: super::images::delay_ms(&call, delay_key)?,
            },
            &access,
        )
        .await?;
    Ok(reply::json(200, &json!({ "ArtifactDigest": digest })))
}

/// `POST /artifacts/pull?name=`
async fn pull(call: Call) -> ApiResult {
    transfer(call, false, "retryDelay").await
}

/// `POST /artifacts/{name}/push`
async fn push(call: Call) -> ApiResult {
    transfer(call, true, "retrydelay").await
}

/// `GET /artifacts/{name}/extract`: a tar of the blobs, named by their
/// titles (by their digests with `excludetitle`).
async fn extract(call: Call) -> ApiResult {
    let by_digest = call.q_bool("excludetitle", false)?;
    let tar = call
        .engine
        .artifact_extract(
            call.param(0),
            call.q("digest").filter(|d| !d.is_empty()),
            call.q("title").filter(|t| !t.is_empty()),
            by_digest,
        )
        .await?;
    Ok(reply::with_type(200, "application/x-tar", tar))
}

pub(super) static ROUTES: &[Route] = &[
    route!("GET", "/artifacts/json", LIBPOD, Artifact, list),
    route!("POST", "/artifacts/add", LIBPOD, Artifact, add),
    route!("POST", "/artifacts/local/add", LIBPOD, Artifact, add_local),
    route!(
        "DELETE",
        "/artifacts/remove",
        LIBPOD,
        Artifact,
        remove_batch
    ),
    route!("POST", "/artifacts/pull", LIBPOD, Artifact, pull),
    route!("POST", "/artifacts/{*}/push", LIBPOD, Artifact, push),
    route!("GET", "/artifacts/{*}/json", LIBPOD, Artifact, inspect),
    route!("GET", "/artifacts/{*}/extract", LIBPOD, Artifact, extract),
    route!("DELETE", "/artifacts/{*}", LIBPOD, Artifact, remove),
];
