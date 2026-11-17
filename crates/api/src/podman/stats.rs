// SPDX-License-Identifier: Apache-2.0
//! The stats of containers and pods: the samples of `ContainerStats` as
//! podman's reports and Docker's StatsJSON (velarx-shape), a line each
//! when they stream.

use super::call::Call;
use super::error::{ApiError, ApiResult};
use super::reply;
use crate::engine::engine_call;
use crate::engine::{Engine, Samples};
use serde_json::Value;
use velarx_proto::workload::StatsRecord;

/// The lines of `samples` as they come, each shaped by `line` (none: the
/// stream ends), as the body of the answer.
fn sample_lines<F>(first: Option<Value>, mut samples: Samples, mut line: F) -> axum::body::Body
where
    F: FnMut(Vec<StatsRecord>) -> Option<Value> + Send + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel::<std::io::Result<bytes::Bytes>>(1);
    tokio::spawn(async move {
        let mut next = first;
        loop {
            if let Some(v) = next.take() {
                let mut bytes = v.to_string().into_bytes();
                bytes.push(b'\n');
                if tx.send(Ok(bytes.into())).await.is_err() {
                    return;
                }
            }
            // (dropping the samples ends the call of the engine)
            let sample = tokio::select! {
                s = samples.next() => s,
                () = tx.closed() => return,
            };
            next = match sample {
                Some(Ok(s)) => match line(s) {
                    Some(v) => Some(v),
                    None => return,
                },
                _ => return,
            };
        }
    });
    axum::body::Body::from_stream(futures::stream::poll_fn(move |cx| rx.poll_recv(cx)))
}

/// libpod's `GET /containers/stats`: a report of the containers each
/// `interval` seconds (one without `stream`).  The errors before the
/// first are error responses: podman's clients cannot decode the `Error`
/// of a report.
pub(super) async fn containers(call: Call) -> ApiResult {
    let stream = call.q_bool("stream", true)?;
    let interval = call.q_i64("interval", 5)?;
    let names: Vec<String> = call
        .q_all("containers")
        .iter()
        .map(|s| s.to_string())
        .collect();
    let all = call.q_bool("all", false)?;
    let size = call.q_bool("size", false)?;
    let interval_ms = if interval <= 0 { 5 } else { interval as u64 } * 1000;
    let mut samples = call
        .engine
        .container_stats(&names, all, size, stream, Some(interval_ms))
        .await?;
    let first = match samples.next().await {
        Some(s) => s?,
        None => Vec::new(),
    };
    let first = velarx_shape::stats::libpod_report(&first);
    if !stream {
        return Ok(reply::json(200, &first));
    }
    let body = sample_lines(Some(first), samples, |s| {
        Some(velarx_shape::stats::libpod_report(&s))
    });
    Ok(reply::with_type(200, "application/json", body))
}

/// The one record of a sample of the container asked for, which runs.
fn running(sample: Option<ApiResult<Vec<StatsRecord>>>) -> ApiResult<StatsRecord> {
    let s = sample
        .ok_or_else(|| ApiError::internal("the engine sent no stats"))??
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::internal("the engine sent no stats"))?;
    if !s.running {
        return Err(ApiError::conflict("container is stopped").with_cause("container is stopped"));
    }
    Ok(s)
}

/// Docker's `GET /containers/{name}/stats`: a StatsJSON each second until
/// the container stops, or one: without `one-shot` of a second sample a
/// moment after the first, so that the client has the CPU use.
pub(super) async fn container(call: Call) -> ApiResult {
    let stream = call.q_bool("stream", true)?;
    let one_shot = call.q_bool("one-shot", false)?;
    if stream && one_shot {
        return Err(ApiError::bad_request("invalid argument").with_cause("invalid argument"));
    }
    let names = [call.param(0).to_string()];
    let libpod = call.libpod;
    // (Docker waits for a second sample: 100 ms later)
    let interval_ms = if stream { 1000 } else { 100 };
    let mut samples = call
        .engine
        .container_stats(&names, false, false, stream || !one_shot, Some(interval_ms))
        .await?;
    let first = running(samples.next().await)?;
    if !stream {
        let shown = if one_shot {
            velarx_shape::stats::docker(&first, None, libpod)
        } else {
            let second = running(samples.next().await)?;
            velarx_shape::stats::docker(&second, Some(&first), libpod)
        };
        return Ok(reply::json(200, &shown));
    }
    let line = velarx_shape::stats::docker(&first, None, libpod);
    let mut before = first;
    let body = sample_lines(Some(line), samples, move |s| {
        // (the container stopped: the stream ends)
        let now = s.into_iter().next().filter(|s| s.running)?;
        let line = velarx_shape::stats::docker(&now, Some(&before), libpod);
        before = now;
        Some(line)
    });
    Ok(reply::with_type(200, "application/json", body))
}

/// podman's PodStatsReport of the pods `ids` (all of them without), a row
/// for each of their containers, the infra container first.
async fn pods_report(engine: &Engine, ids: &[String]) -> ApiResult<Value> {
    let pods = if ids.is_empty() {
        engine.pod_list(&super::call::Filters::default()).await?
    } else {
        let mut pods = Vec::new();
        for id in ids {
            let pod = engine_call!(engine, pod_inspect(id))
                .map(|r| r.pod)
                .map_err(|mut e| {
                    e.message = format!("unable to get list of pods: {}", e.message);
                    e
                })?;
            pods.push(pod);
        }
        pods
    };
    let mut rows = Vec::new();
    for pod in &pods {
        let members: Vec<String> = pod.members.iter().map(|m| m.id.clone()).collect();
        if members.is_empty() {
            continue;
        }
        let mut samples = engine
            .container_stats(&members, true, false, false, None)
            .await?;
        let stats = samples.next().await.transpose()?.unwrap_or_default();
        rows.extend(velarx_shape::stats::pod_rows(&pod.id, &stats));
    }
    Ok(Value::Array(rows))
}

/// libpod's `GET /pods/stats`: the report of the pods named (all of them
/// with none), again each `delay` seconds with `stream`.
pub(super) async fn pods(call: Call) -> ApiResult {
    let names: Vec<String> = call
        .q_all("namesOrIDs")
        .iter()
        .map(|s| s.to_string())
        .collect();
    let all = call.q_bool("all", false)?;
    let stream = call.q_bool("stream", false)?;
    let delay = call.q_i64("delay", 5)?.max(1) as u64;
    if all && !names.is_empty() {
        let msg = "--all, --latest and arguments cannot be used together";
        return Err(ApiError::internal(msg).with_cause(msg));
    }
    let engine = call.engine.clone();
    let first = pods_report(&engine, &names).await?;
    Ok(reply::reports(
        first,
        stream,
        std::time::Duration::from_secs(delay),
        move || {
            let (engine, names) = (engine.clone(), names.clone());
            async move { pods_report(&engine, &names).await.ok() }
        },
    ))
}
