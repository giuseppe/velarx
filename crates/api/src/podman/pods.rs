// SPDX-License-Identifier: Apache-2.0
//! Pods: libpod's routes (the streams of `top` and `stats` come with the
//! routes that stream).

use super::call::Call;
use super::error::{ApiError, ApiResult};
use super::reply;
use super::{route, Route};
use crate::engine::engine_call;
use serde_json::{json, Map, Value};
use velarx_proto::engine::MAX_POD_SPEC;
use velarx_proto::godecode;
use velarx_proto::pod::PodResources;
use velarx_proto::podgen::{spec_of, Generator, SpecError};

fn spec_error(e: SpecError) -> ApiError {
    match e {
        SpecError::Invalid(m) => ApiError::bad_request(m),
        SpecError::NotImplemented(m) => ApiError::not_implemented(m),
    }
}

/// `POST /pods/create`: the body is a PodSpecGenerator, decoded here as the
/// API server decodes it (a body that does not decode is the error of Go's
/// decoder) into the typed spec the engine takes.  A body larger than
/// [`MAX_POD_SPEC`] is refused.
async fn create(mut call: Call) -> ApiResult {
    let body = call.body_bytes(MAX_POD_SPEC).await?;
    let g: Generator = godecode::from_slice(&body)?;
    let spec = serde_json::to_vec(&spec_of(g).map_err(spec_error)?)?;
    let id = call.engine.pod_create(bytes::Bytes::from(spec)).await?;
    Ok(reply::json(201, &json!({"Id": id})))
}

async fn list(call: Call) -> ApiResult {
    // podman's pod list says 400 where the others say 500
    let filters = call
        .filters()
        .map_err(|e| e.with_status(axum::http::StatusCode::BAD_REQUEST))?;
    let pods: Vec<Value> = call
        .engine
        .pod_list(&filters)
        .await?
        .iter()
        .map(velarx_shape::pod::libpod_list_entry)
        .collect();
    Ok(reply::json(200, &pods))
}

async fn inspect(call: Call) -> ApiResult {
    let pod = engine_call!(call.engine, pod_inspect(call.param(0)))?.pod;
    Ok(reply::json(200, &velarx_shape::pod::libpod_inspect(&pod)))
}

/// `POST /pods/{name}/update`: the body holds the limits as the
/// `resource_limits` of a pod create does.
async fn update(mut call: Call) -> ApiResult {
    let body = call.json_value().await?;
    let resources = PodResources::from_podman(body.as_ref(), None, None)
        .map_err(ApiError::bad_request)?
        .unwrap_or_default();
    let id = engine_call!(call.engine, pod_update(call.param(0), resources))?.id;
    Ok(reply::json(200, &json!({"Id": id})))
}

async fn exists(call: Call) -> ApiResult {
    engine_call!(call.engine, pod_exists(call.param(0)))?;
    Ok(reply::empty(204))
}

/// PodStartReport, PodStopReport, ...: no errors is `null`, as podman's
/// nil slice.
fn finish(id: &str, errs: Vec<String>) -> axum::response::Response {
    if errs.is_empty() {
        reply::json(200, &json!({"Errs": null, "Id": id}))
    } else {
        reply::json(409, &json!({"Errs": errs, "Id": id}))
    }
}

async fn run(call: Call, op: &str) -> ApiResult {
    // By default each container's own stop timeout
    let timeout = u64::try_from(call.q_i64("t", -1)?).ok();
    let signal = call.q("signal");
    match call
        .engine
        .pod_run(
            call.param(0),
            op,
            timeout,
            signal,
            &super::containers::verify_image(&call),
        )
        .await?
    {
        None => Ok(reply::empty(304)),
        Some((id, errs)) => Ok(finish(&id, errs)),
    }
}

async fn start(call: Call) -> ApiResult {
    run(call, "start").await
}
async fn stop(call: Call) -> ApiResult {
    run(call, "stop").await
}
async fn kill(call: Call) -> ApiResult {
    run(call, "kill").await
}
async fn pause(call: Call) -> ApiResult {
    run(call, "pause").await
}
async fn unpause(call: Call) -> ApiResult {
    run(call, "unpause").await
}
async fn restart(call: Call) -> ApiResult {
    run(call, "restart").await
}

async fn remove(call: Call) -> ApiResult {
    let force = call.q_flag("force")?;
    // (none given: the stop timeout of each container; below zero is
    // podman's 400)
    let timeout = call.q_uint("timeout")?;
    // (podman answers 500 for any failure but a pod that is not there)
    let (id, removed) = engine_call!(call.engine, pod_remove(call.param(0), force, timeout))
        .map(|r| (r.id, r.removed))
        .map_err(ApiError::as_podman_failure)?;
    let removed: Map<String, Value> = removed.into_iter().map(|id| (id, Value::Null)).collect();
    Ok(reply::json(
        200,
        &json!({"Err": null, "Id": id, "RemovedCtrs": removed}),
    ))
}

async fn prune(call: Call) -> ApiResult {
    let out: Vec<Value> = engine_call!(call.engine, pod_prune())?
        .removed
        .into_iter()
        .map(|id| json!({"Id": id, "Err": null}))
        .collect();
    Ok(reply::json(200, &out))
}

/// podman's `delay` of a top that streams: whole seconds, at least one.
pub(super) fn top_delay(call: &Call) -> ApiResult<std::time::Duration> {
    let delay = call.q_i64("delay", 5)?;
    if delay < 1 {
        return Err(ApiError::bad_request(format!(
            "\"delay\" parameter of value {delay} < 1"
        )));
    }
    Ok(std::time::Duration::from_secs(delay as u64))
}

/// podman's (and Docker's) document of the processes of a top.
pub(super) fn top_document(top: velarx_proto::engine::Processes) -> serde_json::Value {
    json!({"Processes": top.processes, "Titles": top.titles})
}

/// `GET /pods/{name}/top`: `ps_args` is one string of podman's.
async fn top(call: Call) -> ApiResult {
    let ps_args: Vec<String> = call
        .q("ps_args")
        .unwrap_or("")
        .split_whitespace()
        .map(String::from)
        .collect();
    let stream = call.q_bool("stream", false)?;
    let delay = top_delay(&call)?;
    let (engine, name) = (call.engine.clone(), call.param(0).to_string());
    let args = ps_args.clone();
    let top = engine_call!(engine, pod_top(&name, args))?;
    Ok(reply::reports(
        top_document(top),
        stream,
        delay,
        move || {
            let (engine, name, ps_args) = (engine.clone(), name.clone(), ps_args.clone());
            // (the pod went: the stream ends)
            async move {
                engine_call!(engine, pod_top(&name, ps_args))
                    .ok()
                    .map(top_document)
            }
        },
    ))
}

/// `GET /libpod/metrics/descriptors`
async fn metrics_descriptors(call: Call) -> ApiResult {
    let (body, length) = call.engine.metrics_descriptors().await?;
    Ok(reply::json_body(200, body, length))
}

/// `GET /libpod/pods/metrics`: the pods that run.
async fn metrics_all(call: Call) -> ApiResult {
    let (body, length) = call.engine.pods_metrics(None).await?;
    Ok(reply::json_body(200, body, length))
}

/// `GET /libpod/pods/{name}/metrics`
async fn metrics_one(call: Call) -> ApiResult {
    let (body, length) = call.engine.pods_metrics(Some(call.param(0))).await?;
    Ok(reply::json_body(200, body, length))
}

pub(super) static ROUTES: &[Route] = &[
    route!(
        "GET",
        "/metrics/descriptors",
        LIBPOD,
        None,
        metrics_descriptors
    ),
    route!("GET", "/pods/metrics", LIBPOD, Pod, metrics_all),
    route!("GET", "/pods/{}/metrics", LIBPOD, Pod, metrics_one),
    route!("POST", "/pods/create", LIBPOD, Pod, create),
    route!("GET", "/pods/json", LIBPOD, Pod, list),
    route!("POST", "/pods/prune", LIBPOD, Pod, prune),
    route!("GET", "/pods/{}/json", LIBPOD, Pod, inspect),
    route!("GET", "/pods/{}/exists", LIBPOD, Pod, exists),
    route!("POST", "/pods/{}/update", LIBPOD, Pod, update),
    route!("POST", "/pods/{}/start", LIBPOD, Pod, start),
    route!("POST", "/pods/{}/stop", LIBPOD, Pod, stop),
    route!("POST", "/pods/{}/kill", LIBPOD, Pod, kill),
    route!("POST", "/pods/{}/pause", LIBPOD, Pod, pause),
    route!("POST", "/pods/{}/unpause", LIBPOD, Pod, unpause),
    route!("POST", "/pods/{}/restart", LIBPOD, Pod, restart),
    route!("GET", "/pods/stats", LIBPOD, Pod, super::stats::pods),
    route!("GET", "/pods/{}/top", LIBPOD, Pod, top),
    route!("DELETE", "/pods/{}", LIBPOD, Pod, remove),
];
