// SPDX-License-Identifier: Apache-2.0
//! The containers.

use super::call::Call;
use super::error::{ApiError, ApiResult};
use super::reply;
use super::{route, Route};
use crate::engine::engine_call;
use crate::engine::RemoveOptions;
use velarx_proto::engine::{AttachOptions, CheckpointFlags, Compression, LogOptions, RestoreFlags};
use velarx_proto::pod::RestartPolicy;
use velarx_proto::time::{parse_input_time, Toward};
use velarx_proto::wait::{parse_interval, WaitCondition};

/// `GET /containers/json`: podman's and Docker's list.
async fn list(call: Call) -> ApiResult {
    // podman's libpod list fails with a 500 on its parameters
    let status = |e: ApiError| {
        if call.libpod {
            e.with_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        } else {
            e
        }
    };
    // (`external` and `sync` are taken: the store has no containers of
    // other tools, and the state is always read from the runtime)
    let mut filters = call.filters()?;
    let all = call.q_bool("all", false).map_err(status)?;
    let size = call.q_bool("size", false).map_err(status)?;
    // libpod's `namespace`: the namespaces of each container (`ps --ns`)
    let namespace = call.libpod && call.q_bool("namespace", false).map_err(status)?;
    // libpod takes `last` as well, which wins
    let mut limit = call.q_i64("limit", -1).map_err(status)?;
    if call.libpod && call.q("last").is_some() {
        limit = call.q_i64("last", -1).map_err(status)?;
    }
    // Docker's "dead" and "restarting" match no container of ours: they are
    // dropped, and a status filter left empty matches nothing
    if !call.libpod {
        if let Some((_, v)) = filters.0.iter_mut().find(|(k, _)| k == "status") {
            v.retain(|s| s != "dead" && s != "restarting");
            if v.is_empty() {
                return Ok(reply::json(200, &serde_json::json!([])));
            }
        }
    }
    let mut containers = call
        .engine
        .container_list(&filters, all, size, namespace, limit)
        .await?;
    // the engine's newest first; libpod's list without a limit is in the
    // order of creation (podman's ps lists the oldest first)
    if call.libpod && limit <= 0 {
        containers.reverse();
    }
    let now = velarx_shape::time::now_ns();
    let list: Vec<serde_json::Value> = containers
        .iter()
        .map(|c| {
            if call.libpod {
                velarx_shape::container::libpod_list_entry(c)
            } else {
                velarx_shape::container::docker_summary(c, now)
            }
        })
        .collect();
    Ok(reply::json(200, &list))
}

/// `GET /containers/{name}/json`: podman's inspect (of podman 4 for its
/// clients older than 5.0), Docker's.
async fn inspect(call: Call) -> ApiResult {
    let size = call.q_bool("size", false)?;
    let c = engine_call!(call.engine, container_inspect(call.param(0), size))?.container;
    let document = if !call.libpod {
        velarx_shape::container::docker_inspect(&c)
    } else if !call.at_least(5, 0) {
        velarx_shape::container::libpod_v4_inspect(&c)
    } else {
        velarx_shape::container::libpod_inspect(&c)
    };
    Ok(reply::json(200, &document))
}

/// `POST /containers/create`: libpod's SpecGenerator, Docker's
/// configuration (`name` and `platform` of the query).
async fn create(mut call: Call) -> ApiResult {
    let body = call.json_value().await?;
    let docker = !call.libpod;
    let (name, platform) = if docker {
        (call.q("name"), call.q("platform"))
    } else {
        (None, None)
    };
    let created = call
        .engine
        .container_create_document(docker, name, platform, body)
        .await?;
    Ok(reply::json(
        201,
        &serde_json::json!({"Id": created.id, "Warnings": created.warnings}),
    ))
}

/// `POST /containers/prune`
async fn prune(call: Call) -> ApiResult {
    let filters = call.filters()?;
    let pruned = call.engine.container_prune(&filters).await?;
    if call.libpod {
        let list: Vec<serde_json::Value> = pruned
            .removed
            .iter()
            .map(|id| serde_json::json!({"Id": id, "Err": null, "Size": 0}))
            .collect();
        Ok(reply::json(200, &list))
    } else {
        Ok(reply::json(
            200,
            &serde_json::json!({"ContainersDeleted": pruned.removed, "SpaceReclaimed": pruned.space}),
        ))
    }
}

/// `POST /containers/{name}/update`: libpod's resources (and its restart
/// policy in the query), Docker's update.
async fn update(mut call: Call) -> ApiResult {
    let body = call.json_value().await?;
    let retries = call.q_i64("restartRetries", 0)?.max(0);
    let restart = call
        .q("restartPolicy")
        .filter(|p| !p.is_empty())
        .map(|p| RestartPolicy {
            name: p.to_string(),
            maximum_retry_count: u32::try_from(retries).unwrap_or(u32::MAX),
        });
    let spec = if call.libpod {
        super::update::libpod(body, restart)?
    } else {
        super::update::docker(body)?
    };
    let id = call.engine.container_amend(call.param(0), spec).await?;
    if call.libpod {
        Ok(reply::json(201, &serde_json::json!({ "Id": id })))
    } else {
        Ok(reply::json(200, &serde_json::json!({"Warnings": []})))
    }
}

/// Docker's `POST /containers/{name}/wait?condition=not-running|next-exit|removed`:
/// the head of the answer goes once the engine armed the wait (Docker's
/// clients start the container then), the body once the condition is met.
async fn wait_docker(call: Call) -> ApiResult {
    // (the last `condition` counts)
    let condition = match call.q_all("condition").last().copied().unwrap_or("") {
        "" => WaitCondition::NotRunning,
        c => WaitCondition::from_name(c)
            .filter(|c| WaitCondition::DOCKER.contains(c))
            .ok_or_else(|| {
                ApiError::bad_request(format!(
                    "failed to parse query parameter 'condition': {c:?}: not a valid docker condition"
                ))
                .with_cause("not a valid docker condition")
            })?,
    };
    let armed = call
        .engine
        .container_wait(call.param(0), vec![condition], 0)
        .await
        .map_err(|e| match e.status.as_u16() {
            // (podman's words for a container that is not there)
            404 => ApiError::not_found("no such container"),
            _ => e.as_podman_failure(),
        })?;
    let body = axum::body::Body::from_stream(futures::stream::once(async move {
        let shown = match armed.outcome().await {
            Ok(w) => serde_json::json!({"StatusCode": w.status_code.unwrap_or(-1), "Error": null}),
            // (the head went: the error is in the body, as Docker's)
            Err(e) => serde_json::json!({"StatusCode": -1, "Error": {"Message": e.message}}),
        };
        Ok::<_, std::io::Error>(axum::body::Bytes::from(format!("{shown}\n")))
    }));
    Ok(reply::with_type(200, "application/json", body))
}

/// libpod's `GET /containers/{name}/healthcheck`: run it, podman's
/// HealthCheckResults after it.
async fn healthcheck(call: Call) -> ApiResult {
    let health = engine_call!(call.engine, container_healthcheck(call.param(0)))?.health;
    Ok(reply::json(200, &velarx_shape::container::health(&health)))
}

/// podman's options of a checkpoint or restore that velarx has no
/// equivalent of: refused by name.
fn refuse_cr_options(call: &Call, names: &[(&str, &str)]) -> ApiResult<()> {
    for (name, why) in names {
        let on = match call.q(name) {
            Some(v) => !v.is_empty() && v != "false" && v != "0",
            None => false,
        };
        if on {
            return Err(ApiError::bad_request(format!(
                "{name} is not supported: {why}"
            )));
        }
    }
    Ok(())
}

/// libpod's `POST /containers/{name}/checkpoint`: a report, or with
/// `export` the archive.
async fn checkpoint(call: Call) -> ApiResult {
    let export = call.q_bool("export", false)?;
    if export && call.q_bool("printStats", false)? {
        return Err(ApiError::bad_request(
            "printStats is not supported with export: the archive is of a checkpoint alone",
        ));
    }
    let flags = CheckpointFlags {
        leave_running: call.q_bool("leaveRunning", false)?,
        create_image: call
            .q("createImage")
            .filter(|i| !i.is_empty())
            .map(str::to_string),
        tcp_established: call.q_bool("tcpEstablished", false)?,
        file_locks: call.q_bool("fileLocks", false)?,
        keep: call.q_bool("keep", false)?,
        ignore_rootfs: export && call.q_bool("ignoreRootFS", false)?,
        ignore_volumes: export && call.q_bool("ignoreVolumes", false)?,
        print_stats: call.q_bool("printStats", false)?,
        pre_checkpoint: call.q_bool("preCheckpoint", false)?,
        with_previous: call.q_bool("withPrevious", false)?,
        compress: match call.q("compress").filter(|c| !c.is_empty()) {
            None => None,
            Some(word) => Some(Compression::of_word(word).ok_or_else(|| {
                ApiError::bad_request(format!("{word:?} is not a compression of a checkpoint"))
            })?),
        },
    };
    if export {
        let archive = call
            .engine
            .container_checkpoint_export(call.param(0), flags)
            .await?;
        return Ok(reply::with_type(200, "application/x-tar", archive));
    }
    let done = call
        .engine
        .container_checkpoint_kept(call.param(0), flags)
        .await?;
    Ok(reply::json(
        200,
        &velarx_proto::workload::CheckpointReport {
            id: done.id,
            runtime_checkpoint_duration: done.runtime_checkpoint_duration,
            criu_statistics: done.criu_statistics,
        },
    ))
}

/// libpod's `POST /containers/{name}/restore`: in place, or with `import`
/// from the archive of the body (a new container), or the one a node
/// shares (velarx's `X-Velarx-Checkpoint-Reference`, a header: its key is
/// not for the logs of requests).
async fn restore(mut call: Call) -> ApiResult {
    let reference = call
        .header("x-velarx-checkpoint-reference")
        .filter(|r| !r.is_empty())
        .map(str::to_string);
    let import = call.q_bool("import", false)? || reference.is_some();
    let mut flags = RestoreFlags {
        tcp_established: call.q_bool("tcpEstablished", false)?,
        tcp_close: call.q_bool("tcpClose", false)?,
        file_locks: call.q_bool("fileLocks", false)?,
        keep: call.q_bool("keep", false)?,
        print_stats: call.q_bool("printStats", false)?,
        verify_image: verify_image(&call),
        ..Default::default()
    };
    let done = if import {
        flags.name = call.q("name").filter(|n| !n.is_empty()).map(str::to_string);
        flags.ignore_rootfs = call.q_bool("ignoreRootFS", false)?;
        flags.ignore_static_ip = call.q_bool("ignoreStaticIP", false)?;
        flags.ignore_static_mac = call.q_bool("ignoreStaticMAC", false)?;
        flags.pod = call.q("pod").filter(|p| !p.is_empty()).map(str::to_string);
        flags.publish = call
            .q("publishPorts")
            .unwrap_or_default()
            .split(',')
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();
        let body = call.take_body();
        call.engine
            .container_restore_import(flags, reference.as_deref(), body)
            .await?
    } else {
        refuse_cr_options(
            &call,
            &[
                ("pod", "it goes with import"),
                ("publishPorts", "it goes with import"),
            ],
        )?;
        call.engine
            .container_restore_kept(call.param(0), flags)
            .await?
    };
    Ok(reply::json(
        200,
        &velarx_proto::workload::RestoreReport {
            id: done.id,
            runtime_restore_duration: done.runtime_restore_duration.unwrap_or(0),
            criu_statistics: done.criu_statistics,
        },
    ))
}

/// `GET /containers/{name}/exists`
async fn exists(call: Call) -> ApiResult {
    engine_call!(call.engine, container_exists(call.param(0)))?;
    Ok(reply::empty(204))
}

/// `POST /containers/{name}/init`: 304 for one initialized or running.
async fn init(call: Call) -> ApiResult {
    let changed = engine_call!(call.engine, container_init(call.param(0)))?.changed;
    Ok(reply::empty(if changed { 204 } else { 304 }))
}

/// The digests typed on the request (`verify_image`, once for each), which an
/// enforced start holds the images of the container to.
pub(super) fn verify_image(call: &Call) -> Vec<String> {
    call.q_all("verify_image")
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// `POST /containers/{name}/start`: 304 for one that runs.
async fn start(call: Call) -> ApiResult {
    let started = call
        .engine
        .container_start(call.param(0), &verify_image(&call))
        .await
        .map_err(ApiError::as_podman_failure)?;
    Ok(reply::empty(if started { 204 } else { 304 }))
}

/// The seconds of `timeout` (libpod) or `t` (Docker), none if negative.
/// Used by restart, whose handler reads them as one number.
fn timeout_of(call: &Call) -> ApiResult<Option<u64>> {
    let timeout = call.q_i64(if call.libpod { "timeout" } else { "t" }, -1)?;
    Ok(u64::try_from(timeout).ok())
}

/// `POST /containers/{name}/stop`: 304 for one that does not run.  podman's
/// handler decodes `t` (an int, -1 is no limit) and `timeout` (a uint, -1 is
/// a 400) on both routes, and uses the one of its route.
async fn stop(call: Call) -> ApiResult {
    call.q_flag("ignore")?;
    let docker = call.q_int("t")?;
    let libpod = call.q_uint("timeout")?;
    let timeout = if call.libpod {
        libpod
    } else {
        // (Docker's -1 waits as long as can be: podman's MaxUint32)
        docker.map(|t| u64::try_from(t).unwrap_or(u64::from(u32::MAX)))
    };
    // (podman looks the container up first: `ignore` does not hide a
    // container that is not there)
    let stopped = engine_call!(
        call.engine,
        container_stop(call.param(0), timeout, false, None::<bool>)
    )
    .map(|r| r.changed)
    .map_err(ApiError::as_podman_failure)?;
    Ok(reply::empty(if stopped { 204 } else { 304 }))
}

/// `POST /containers/{name}/kill`
async fn kill(call: Call) -> ApiResult {
    engine_call!(call.engine, container_kill(call.param(0), call.q("signal")))?;
    Ok(reply::empty(204))
}

/// `POST /containers/{name}/restart`
async fn restart(call: Call) -> ApiResult {
    call.refuse_params(&["all"])?;
    let timeout = timeout_of(&call)?;
    let verify = verify_image(&call);
    engine_call!(
        call.engine,
        container_restart(call.param(0), timeout, verify)
    )
    .map_err(ApiError::as_podman_failure)?;
    Ok(reply::empty(204))
}

async fn pause(call: Call) -> ApiResult {
    engine_call!(
        call.engine,
        container_pause(call.param(0), true, None::<u64>)
    )
    .map_err(ApiError::as_podman_failure)?;
    Ok(reply::empty(204))
}

async fn unpause(call: Call) -> ApiResult {
    engine_call!(
        call.engine,
        container_pause(call.param(0), false, None::<u64>)
    )
    .map_err(ApiError::as_podman_failure)?;
    Ok(reply::empty(204))
}

/// `POST /containers/{name}/rename?name=NEW`
async fn rename(call: Call) -> ApiResult {
    let new = call.q("name").unwrap_or_default();
    engine_call!(call.engine, container_rename(call.param(0), new))?;
    Ok(reply::empty(204))
}

/// `DELETE /containers/{name}`: libpod answers a report for each container
/// removed, Docker 204.  podman's handler is one for both routes: it decodes
/// every parameter first (a `timeout` below zero is a 400 on either), then
/// uses the ones of the route; every failure but a missing container is a 500.
async fn remove(call: Call) -> ApiResult {
    let force = call.q_flag("force")?;
    let ignore = call.q_flag("ignore")?;
    let depend = call.q_flag("depend")?;
    let link = call.q_flag("link")?;
    let timeout = call.q_uint("timeout")?;
    let docker_volumes = call.q_flag("v")?;
    let libpod_volumes = call.q_flag("volumes")?;
    if !call.libpod && link {
        return Err(ApiError::bad_request("link is not supported"));
    }
    // libpod: the time a running container has to stop (none given: its
    // own stop timeout), and the containers that depend on it go first.
    // Docker's removal takes no time: the container's own, as podman's.
    let removed = call
        .engine
        .container_remove(
            call.param(0),
            RemoveOptions {
                force,
                volumes: if call.libpod {
                    libpod_volumes
                } else {
                    docker_volumes
                },
                ignore,
                depend: call.libpod && depend,
                timeout: if call.libpod { timeout } else { None },
            },
        )
        .await
        .map_err(ApiError::as_podman_failure)?;
    if !call.libpod {
        return Ok(reply::empty(204));
    }
    // (podman's report: `Err` only when there is one, no raw input)
    let reports: Vec<serde_json::Value> = removed
        .iter()
        .map(|r| serde_json::json!({"Id": r.id}))
        .collect();
    Ok(reply::json(200, &reports))
}

/// libpod's `POST /containers/{name}/wait?condition=...&interval=...`: the
/// exit code (-1 for a condition that is no exit).
async fn wait(call: Call) -> ApiResult {
    let names = call.q_all("condition");
    // an interval podman cannot read is a 500 with Go's words
    let interval = match call.q("interval") {
        None => 0,
        Some(i) => {
            // (a negative one is a poll interval Go reads, which podman's
            // wait takes; velarx's polls nothing)
            parse_interval(i, false)
                .ok_or_else(|| ApiError::internal(go_duration_error(i)))?
                .max(0)
        }
    };
    let conditions = match WaitCondition::parse_all(&names) {
        Ok(c) => c,
        Err(_) => {
            // podman cannot read the condition either, and answers an
            // exit code of 0 for a container that is there
            engine_call!(call.engine, container_exists(call.param(0)))
                .map(|_| ())
                .map_err(ApiError::as_podman_failure)?;
            return Ok(reply::with_type(200, "application/json", "0\n"));
        }
    };
    let waited = call
        .engine
        .container_wait(call.param(0), conditions, interval)
        .await
        .map_err(ApiError::as_podman_failure)?
        .outcome()
        .await
        .map_err(ApiError::as_podman_failure)?;
    Ok(reply::with_type(
        200,
        "application/json",
        format!("{}\n", waited.status_code.unwrap_or(-1)),
    ))
}

/// Go's `time.ParseDuration` error for `s`, which it cannot read.
fn go_duration_error(s: &str) -> String {
    let quote = |t: &str| format!("{t:?}");
    let invalid = || format!("time: invalid duration {}", quote(s));
    let mut rest = s.strip_prefix(['-', '+']).unwrap_or(s);
    if rest.is_empty() {
        return invalid();
    }
    while !rest.is_empty() {
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        let after = &rest[digits..];
        let (fraction, after) = match after.strip_prefix('.') {
            Some(f) => {
                let n = f.len() - f.trim_start_matches(|c: char| c.is_ascii_digit()).len();
                (n, &f[n..])
            }
            None => (0, after),
        };
        if digits == 0 && fraction == 0 {
            return invalid();
        }
        let unit_len = after
            .find(|c: char| c == '.' || c.is_ascii_digit())
            .unwrap_or(after.len());
        if unit_len == 0 {
            return format!("time: missing unit in duration {}", quote(s));
        }
        let unit = &after[..unit_len];
        if !["ns", "us", "\u{b5}s", "\u{3bc}s", "ms", "s", "m", "h"].contains(&unit) {
            return format!(
                "time: unknown unit {} in duration {}",
                quote(unit),
                quote(s)
            );
        }
        rest = &after[unit_len..];
    }
    // (a value out of range)
    invalid()
}

/// `GET /containers/{name}/logs`: Docker's multiplexed frames, or the raw
/// output of a container with a terminal (Docker's API).
async fn logs(call: Call) -> ApiResult {
    let (stdout, stderr) = (call.q_bool("stdout", false)?, call.q_bool("stderr", false)?);
    if !stdout && !stderr {
        return Err(ApiError::bad_request(format!(
            "Bad Request: you must choose at least one stream for {}",
            call.target
        )));
    }
    // (podman's words for a value it cannot read)
    let invalid = |name: &str, value: &str, cause: &str, message: String| {
        ApiError::bad_request(format!(
            "failed to parse query parameter '{name}': {value:?}: {message}"
        ))
        .with_cause(cause)
    };
    // (a number or `all`; a negative number is all)
    let tail = match call.q("tail").unwrap_or("") {
        "" | "all" => None,
        t => match t.parse::<i64>() {
            Ok(n) => (n >= 0).then_some(n),
            Err(e) => {
                let cause = match e.kind() {
                    std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow => {
                        "value out of range"
                    }
                    _ => "invalid syntax",
                };
                let message = format!("strconv.ParseInt: parsing {t:?}: {cause}");
                return Err(invalid("tail", t, cause, message));
            }
        },
    };
    // (0 and a time before the epoch, such as Go's zero time that podman
    // sends for a limit it does not set, are no limit)
    let now = velarx_shape::time::now_ns();
    let time = |name: &str, toward: Toward| match call.q(name).unwrap_or("") {
        "" => Ok(None),
        t => parse_input_time(t, now, toward, false)
            .map(|ns| Some(ns).filter(|&ns| ns > 0))
            .ok_or_else(|| {
                let cause = "unable to interpret time value";
                invalid(name, t, cause, cause.to_string())
            }),
    };
    let opts = LogOptions {
        stdout,
        stderr,
        follow: call.q_bool("follow", false)?,
        timestamps: call.q_bool("timestamps", false)?,
        tail,
        since_ns: time("since", Toward::Past)?,
        until_ns: time("until", Toward::Future)?,
    };
    let stream = call
        .engine
        .container_logs(call.param(0), opts)
        .await
        .map_err(|e| e.logs_failed(call.param(0)))?;
    // (libpod always frames the logs, Docker only those of a container
    // without a terminal)
    if stream.tty && !call.libpod {
        Ok(reply::with_type(
            200,
            "application/vnd.docker.raw-stream",
            stream.unframed_body(),
        ))
    } else {
        Ok(reply::with_type(
            200,
            "application/vnd.docker.multiplexed-stream",
            stream.body(),
        ))
    }
}

/// `GET /containers/{name}/top`
async fn top(call: Call) -> ApiResult {
    // (podman's client sends one ps_args for each argument)
    let ps_args: Vec<String> = call
        .q_all("ps_args")
        .into_iter()
        .map(String::from)
        .collect();
    let stream = call.q_bool("stream", false)?;
    let delay = super::pods::top_delay(&call)?;
    // (Docker's default; libpod's is podman's descriptors)
    let ps_args = if ps_args.is_empty() && !call.libpod {
        vec!["-ef".to_string()]
    } else {
        ps_args
    };
    let (engine, name) = (call.engine.clone(), call.param(0).to_string());
    let args = ps_args.clone();
    let top =
        engine_call!(engine, container_top(&name, args)).map_err(ApiError::as_podman_failure)?;
    Ok(reply::reports(
        super::pods::top_document(top),
        stream,
        delay,
        move || {
            let (engine, name, ps_args) = (engine.clone(), name.clone(), ps_args.clone());
            // (the container stopped: the stream ends)
            async move {
                engine_call!(engine, container_top(&name, ps_args))
                    .ok()
                    .map(super::pods::top_document)
            }
        },
    ))
}

/// `POST /containers/{name}/attach`: the streams of the container, spliced
/// with the client's connection.
async fn attach(mut call: Call) -> ApiResult {
    let (mut stdout, mut stderr) = (call.q_bool("stdout", false)?, call.q_bool("stderr", false)?);
    // (neither asked for: both)
    if !stdout && !stderr {
        (stdout, stderr) = (true, true);
    }
    let opts = AttachOptions {
        stdout,
        stderr,
        logs: call.q_bool("logs", false)?,
        stream: call.q_bool("stream", true)?,
        stdin: call.q_bool("stdin", false)?,
        detach_keys: call.q("detachKeys").map(str::to_string),
        stdin_once: false,
        stdin_keep_open: false,
        ..Default::default()
    };
    let name = call.param(0).to_string();
    let h = call.engine.container_attach(&name, opts).await?;
    super::hijack::respond(&mut call, h)
}

/// `POST /containers/{name}/resize`
async fn resize(call: Call) -> ApiResult {
    let (h, w) = (call.q_i64("h", 0)?, call.q_i64("w", 0)?);
    engine_call!(call.engine, container_resize(call.param(0), h, w))?;
    Ok(reply::with_type(200, "application/json", "{}\n"))
}

pub(super) static ROUTES: &[Route] = &[
    route!("GET", "/containers/json", BOTH, Container, list),
    route!("GET", "/containers/{}/json", BOTH, Container, inspect),
    route!("POST", "/containers/create", BOTH, Container, create),
    route!("POST", "/containers/prune", BOTH, Container, prune),
    route!("POST", "/containers/{}/update", BOTH, Container, update),
    route!(
        "POST",
        "/containers/{}/wait",
        COMPAT,
        Container,
        wait_docker
    ),
    route!(
        "GET",
        "/containers/{}/healthcheck",
        LIBPOD,
        Container,
        healthcheck
    ),
    route!(
        "POST",
        "/containers/{}/checkpoint",
        LIBPOD,
        Container,
        checkpoint
    ),
    route!("POST", "/containers/{}/restore", LIBPOD, None, restore),
    route!("GET", "/containers/{}/exists", LIBPOD, Container, exists),
    route!("POST", "/containers/{}/init", LIBPOD, Container, init),
    route!("POST", "/containers/{}/start", BOTH, Container, start),
    route!("POST", "/containers/{}/stop", BOTH, Container, stop),
    route!("POST", "/containers/{}/kill", BOTH, Container, kill),
    route!("POST", "/containers/{}/restart", BOTH, Container, restart),
    route!("POST", "/containers/{}/pause", BOTH, Container, pause),
    route!("POST", "/containers/{}/unpause", BOTH, Container, unpause),
    route!("POST", "/containers/{}/rename", BOTH, Container, rename),
    route!("POST", "/containers/{}/wait", LIBPOD, Container, wait),
    route!(
        "GET",
        "/containers/stats",
        LIBPOD,
        Container,
        super::stats::containers
    ),
    route!(
        "GET",
        "/containers/{}/stats",
        BOTH,
        Container,
        super::stats::container
    ),
    route!("GET", "/containers/{}/logs", BOTH, Container, logs),
    route!("GET", "/containers/{}/top", BOTH, Container, top),
    route!("POST", "/containers/{}/attach", BOTH, Container, attach),
    route!("POST", "/containers/{}/resize", BOTH, Container, resize),
    route!("DELETE", "/containers/{}", BOTH, Container, remove),
];

#[cfg(test)]
mod tests {
    use super::go_duration_error;

    #[test]
    fn durations_fail_in_go_words() {
        for (s, e) in [
            ("soon", r#"time: invalid duration "soon""#),
            ("", r#"time: invalid duration """#),
            ("5", r#"time: missing unit in duration "5""#),
            ("1x", r#"time: unknown unit "x" in duration "1x""#),
            ("-", r#"time: invalid duration "-""#),
        ] {
            assert_eq!(go_duration_error(s), e, "{s:?}");
        }
    }
}
