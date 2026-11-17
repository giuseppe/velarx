// SPDX-License-Identifier: Apache-2.0
//! Volumes: libpod's and Docker's routes.

use super::call::Call;
use super::error::{ApiError, ApiResult};
use super::reply;
use super::{route, Route};
use crate::engine::engine_call;
use serde::Deserialize;
use std::collections::HashMap;
use velarx_proto::workload::VolumeSpec;

#[derive(Deserialize, Default)]
#[serde(default)]
struct CreateBody {
    #[serde(rename = "Name")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    name: String,
    #[serde(rename = "Driver")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    driver: String,
    /// podman sends the labels in "Label", Docker in "Labels"
    #[serde(rename = "Label")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    label: HashMap<String, String>,
    #[serde(rename = "Labels")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    labels: HashMap<String, String>,
    #[serde(rename = "Options", alias = "DriverOpts")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    options: HashMap<String, String>,
    #[serde(rename = "IgnoreIfExists")]
    ignore_if_exists: bool,
    /// The owner of the volume (libpod's), as the options `uid` and `gid`
    #[serde(rename = "UID")]
    uid: Option<u32>,
    #[serde(rename = "GID")]
    gid: Option<u32>,
    /// Swarm's: refused when set.
    #[serde(rename = "ClusterVolumeSpec")]
    cluster_volume_spec: Option<serde_json::Value>,
}

/// libpod's `UID` and `GID` are the options `uid` and `gid` (over those of
/// the options, as podman applies them after).
fn owner_options(options: &mut HashMap<String, String>, uid: Option<u32>, gid: Option<u32>) {
    for (key, owner) in [("uid", uid), ("gid", gid)] {
        if let Some(id) = owner {
            options.insert(key.to_string(), id.to_string());
        }
    }
}

/// `POST /volumes/create`: 201 with the volume.  Docker answers with the
/// one that exists, libpod only when asked (`IgnoreIfExists`).
async fn create(mut call: Call) -> ApiResult {
    let body: CreateBody = call.json_or_default().await?;
    if let Some(c) = &body.cluster_volume_spec {
        super::call::refuse_field("ClusterVolumeSpec", c)?;
    }
    // podman sends the labels in "Label", Docker in "Labels"
    let mut labels = body.label;
    labels.extend(body.labels);
    let mut options = body.options;
    owner_options(&mut options, body.uid, body.gid);
    let spec = VolumeSpec {
        name: body.name,
        driver: body.driver,
        labels: labels.into_iter().collect(),
        options: options.into_iter().collect(),
    };
    let volume = engine_call!(
        call.engine,
        volume_create(&spec, body.ignore_if_exists || !call.libpod)
    )
    .map(|r| r.volume)
    .map_err(|e| {
        // podman: any failure of NewVolume but a name it refuses is a 500
        if e.is(velarx_proto::engine::Condition::InvalidName) {
            e
        } else {
            e.as_podman_failure()
        }
    })?;
    Ok(reply::json(
        201,
        &velarx_shape::volume::document(&volume, call.libpod),
    ))
}

/// `GET /volumes/json` (libpod), `GET /volumes` (Docker)
async fn list(call: Call) -> ApiResult {
    let filters = call.filters()?;
    let volumes: Vec<serde_json::Value> = call
        .engine
        .volume_list(&filters)
        .await?
        .iter()
        .map(|v| velarx_shape::volume::document(v, call.libpod))
        .collect();
    if call.libpod {
        Ok(reply::json(200, &volumes))
    } else {
        Ok(reply::json(
            200,
            &serde_json::json!({"Volumes": volumes, "Warnings": []}),
        ))
    }
}

async fn inspect(call: Call) -> ApiResult {
    let volume = engine_call!(call.engine, volume_inspect(call.param(0)))?.volume;
    Ok(reply::json(
        200,
        &velarx_shape::volume::document(&volume, call.libpod),
    ))
}

async fn exists(call: Call) -> ApiResult {
    engine_call!(call.engine, volume_exists(call.param(0)))?;
    Ok(reply::empty(204))
}

async fn rename(call: Call) -> ApiResult {
    let new_name = call.q("newName").unwrap_or("");
    engine_call!(call.engine, volume_rename(call.param(0), new_name))?;
    Ok(reply::empty(204))
}

/// `DELETE /volumes/{name}`.  podman reads a parameter it cannot convert as
/// a 500 here.  libpod's `force` removes the containers that use the volume;
/// Docker's only means "no error for a volume that is not there" (a volume in
/// use is a 409 for either).
async fn remove(call: Call) -> ApiResult {
    let internal = |e: ApiError| e.with_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let force = call.q_flag("force").map_err(internal)?;
    // the time a running container that uses it has to stop
    let timeout = call.q_uint("timeout").map_err(internal)?;
    let result = engine_call!(
        call.engine,
        volume_remove(call.param(0), call.libpod && force, timeout)
    )
    .map(|_| ());
    match result {
        Err(e) if !call.libpod && force && e.status == axum::http::StatusCode::NOT_FOUND => {}
        Err(e) if e.status == axum::http::StatusCode::BAD_REQUEST => {
            return Err(e.as_podman_failure())
        }
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    Ok(reply::empty(204))
}

async fn prune(call: Call) -> ApiResult {
    let filters = call.filters()?;
    let dry_run = call.libpod && call.q_bool("dryrun", false)?;
    let deleted = call.engine.volume_prune(&filters, dry_run).await?;
    if call.libpod {
        let out: Vec<serde_json::Value> = deleted
            .iter()
            .map(|v| serde_json::json!({"Id": v.name, "Size": v.size}))
            .collect();
        Ok(reply::json(200, &out))
    } else {
        let names: Vec<&str> = deleted.iter().map(|v| v.name.as_str()).collect();
        let reclaimed: u64 = deleted.iter().map(|v| v.size).sum();
        Ok(reply::json(
            200,
            &serde_json::json!({"VolumesDeleted": names, "SpaceReclaimed": reclaimed}),
        ))
    }
}

/// libpod's `GET /volumes/{name}/export`: the content as a tar.
async fn export(call: Call) -> ApiResult {
    let body = call.engine.volume_export(call.param(0)).await?;
    Ok(reply::with_type(200, "application/x-tar", body))
}

/// libpod's `POST /volumes/{name}/import`: the tar of the body into the
/// volume.
async fn import(mut call: Call) -> ApiResult {
    let body = call.take_body();
    call.engine.volume_import(call.param(0), body).await?;
    Ok(reply::empty(204))
}

pub(super) static ROUTES: &[Route] = &[
    route!("GET", "/volumes/{}/export", LIBPOD, Volume, export),
    route!("POST", "/volumes/{}/import", LIBPOD, Volume, import),
    route!("POST", "/volumes/create", BOTH, Volume, create),
    route!("GET", "/volumes/json", LIBPOD, Volume, list),
    route!("GET", "/volumes", COMPAT, Volume, list),
    route!("POST", "/volumes/prune", BOTH, Volume, prune),
    route!("GET", "/volumes/{}/json", LIBPOD, Volume, inspect),
    route!("POST", "/volumes/{}/rename", LIBPOD, Volume, rename),
    route!("GET", "/volumes/{}/exists", LIBPOD, Volume, exists),
    route!("GET", "/volumes/{}", COMPAT, Volume, inspect),
    route!("DELETE", "/volumes/{}", BOTH, Volume, remove),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_owner_of_a_libpod_volume_is_its_options() {
        let body: CreateBody = serde_json::from_str(r#"{"Name":"v","UID":1000,"GID":0}"#).unwrap();
        let mut options = body.options;
        owner_options(&mut options, body.uid, body.gid);
        assert_eq!(options["uid"], "1000");
        assert_eq!(options["gid"], "0");
        // UID wins over an option, as podman applies it after them; none
        // given is none
        let mut options = HashMap::from([("uid".to_string(), "5".to_string())]);
        owner_options(&mut options, Some(7), None);
        assert_eq!(
            options,
            HashMap::from([("uid".to_string(), "7".to_string())])
        );
    }
}
