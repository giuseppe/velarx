// SPDX-License-Identifier: Apache-2.0
//! Containers: libpod's and Docker's routes.

use super::call::{id_matches, Filters};
use super::cinfo::{self, Info};
use super::error::{ApiError, ApiResult};
use super::lifecycle::{self, Started};
use super::logs;
use super::record::{self, ApiRecord};
use super::state::Chunk;
use super::stream::{STDERR, STDOUT};
use super::{images, spec};
use crate::api::AppState;
use futures::StreamExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use velarx_core::services::StartCheck;
use velarx_proto::engine::{UpdateBlockIo, UpdateDevice, UpdateHealth, UpdateSpec};
use velarx_proto::health::Healthcheck;
use velarx_proto::stream::{Event, Out};
use velarx_proto::workload::RunState;
use velarx_wire::wire::LogDriver;

/// The image of a create request must exist.
async fn check_image(state: &AppState, name: &str) -> ApiResult<String> {
    let rec = match images::resolve_image(state, name).await {
        Ok(rec) => rec,
        // A manifest list runs its instance for this host.
        Err(e) if e.status.as_u16() == 404 => {
            let Some(list) = state.image_service.manifest_lookup(name).await? else {
                return Err(e);
            };
            let host = velarx_registry::target::Platform::host();
            let rec = state
                .image_service
                .manifest_instance_for(&list, &host)
                .await
                .map_err(|e| ApiError::new(404, format!("{name}: {e}")))?;
            return Ok(rec.id);
        }
        Err(e) => return Err(e),
    };
    // the service takes a name or the id of the image
    if state.image_service.get(name).await.is_ok() {
        Ok(name.to_string())
    } else {
        Ok(rec.id)
    }
}

/// The name of `rec` that `name` meant, as podman records it in the
/// container (Config.Image): `alpine` is quay.io/libpod/alpine:latest when
/// that is the image found; `name` itself when it is an id or a digest.
fn resolved_name(name: &str, names: &[String]) -> String {
    if name.contains('@') || names.is_empty() {
        return name.to_string();
    }
    let slash = name.rfind('/').map_or(0, |i| i + 1);
    let (repo, tag) = match name[slash..].find(':') {
        Some(i) => (&name[..slash + i], &name[slash + i + 1..]),
        None => (name, "latest"),
    };
    names
        .iter()
        .find(|n| {
            let ns = n.rfind('/').map_or(0, |i| i + 1);
            let Some((nrepo, ntag)) = n[ns..].find(':').map(|i| (&n[..ns + i], &n[ns + i + 1..]))
            else {
                return false;
            };
            ntag == tag
                && nrepo
                    .strip_suffix(repo)
                    .is_some_and(|rest| rest.is_empty() || rest.ends_with('/'))
        })
        .cloned()
        .unwrap_or_else(|| name.to_string())
}

/// Make the container of a request of the API (`body` is the document it
/// came from, kept for its inspect): its id and the warnings of the create.
async fn finish_create(
    state: &Arc<AppState>,
    mut req: velarx_wire::request::CreateContainerRequest,
    body: Value,
    docker: bool,
    secrets: Vec<String>,
) -> ApiResult<(String, Vec<String>)> {
    let asked = req.image.clone();
    let image_name = if req.rootfs {
        String::new()
    } else {
        req.image = check_image(state, &asked).await?;
        match images::resolve_image(state, &asked).await {
            Ok(rec) => resolved_name(&asked, &images::image_display_names(state, &rec).await?),
            Err(_) => asked,
        }
    };
    // the supervisor removes the container once the clients have the exit code
    // the namespaces and the SELinux label of the pod's infra container
    // (the records keep the secrets by name, not their values)
    let secrets_dir = req
        .id
        .as_ref()
        .filter(|_| !secrets.is_empty())
        .map(|id| spec::secrets_dir(state, id));
    let asked = req.with_secrets_by_name(secrets_dir.as_deref());
    let pod = state.pod_service.prepare_member(&mut req).await?;
    let mut warnings = Vec::new();
    if let Some(netns) = req
        .network_mode
        .without_ports()
        .filter(|_| !req.ports.is_empty())
    {
        warnings.push(format!(
            "Port mappings have been discarded because \"{netns}\" network namespace mode does not support them"
        ));
        req.ports.clear();
    }
    let id = match state.container_service.create(req.clone()).await {
        Ok(id) => id,
        Err(e) => {
            if let Some(id) = &req.id {
                let dir = spec::secrets_dir(state, id);
                let _ =
                    crate::api::off_thread(move || velarx_base::tree::remove_dir_all(dir)).await;
            }
            return Err(e.into());
        }
    };
    if !secrets.is_empty() {
        let store = super::secrets::store(state).await?;
        for s in &secrets {
            if let Err(e) = store.mark_use(s, &id).await {
                tracing::warn!("cannot record the use of secret {s}: {e}");
            }
        }
    }
    if let Some(pod) = pod {
        if let Err(e) = state.pod_service.add_container(pod.id(), &id).await {
            let _ = state.container_service.delete(&id, true).await;
            return Err(e.into());
        }
    }
    let rec = ApiRecord {
        request: req.with_secrets_by_name(secrets_dir.as_deref()),
        body,
        docker,
        image_name: image_name.clone(),
        asked: Some(asked),
    };
    if let Err(e) = record::save(state, &id, &rec).await {
        tracing::warn!("cannot save the request of container {id}: {e}");
    }
    // the container service tells of the creation (events)
    Ok((id, warnings))
}

/// A container from the document of a podman client: libpod's
/// SpecGenerator, or Docker's configuration (with Docker's `name` and
/// `platform` of the query).  Its id and the warnings of the create.
pub(crate) async fn create_document_of(
    state: &Arc<AppState>,
    docker: bool,
    name: Option<&str>,
    platform: Option<&str>,
    body: Option<Value>,
) -> ApiResult<(String, Vec<String>)> {
    if !docker {
        let body = body.filter(Value::is_object).ok_or_else(|| {
            ApiError::bad_request("the request body must be a SpecGenerator object")
        })?;
        // (from the secrets' files to the container's row: see
        // `ContainerService::lock_store`)
        let _store = state
            .container_service
            .lock_store()
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        let (req, secrets) = spec::from_spec(state, &body).await?;
        return finish_create(state, req, body, false, secrets).await;
    }
    let mut body = body
        .filter(Value::is_object)
        .ok_or_else(|| ApiError::bad_request("the request body must be a container config"))?;
    if let Some(p) = platform.filter(|p| !p.is_empty()) {
        image_for_platform(state, &mut body, p).await?;
    }
    let req = spec::from_docker(state, name, &body).await?;
    docker_can_start(state, &req)?;
    finish_create(state, req, body, true, Vec::new()).await
}

/// A container made from a digest whose digests are enforced starts only
/// when the command that starts it gives the digest again (`--verify-image`,
/// the `verify_image` of a start): a Docker client has no way to, so such a
/// container could never be started by it.  Refused when it is made.
fn docker_can_start(
    state: &AppState,
    req: &velarx_wire::request::CreateContainerRequest,
) -> ApiResult<()> {
    let pinned = req.image.contains('@')
        && velarx_types::ImageReference::parse(&req.image).is_ok_and(|r| r.digest.is_some());
    if !pinned || req.rootfs {
        return Ok(());
    }
    let why = if state.image_service.composefs_digests() == velarx_config::ComposefsDigests::Require
    {
        "[storage] composefs_digests is \"require\""
    } else if req.security_opts.iter().any(|o| {
        let mut so = velarx_wire::request::SecurityOptions::default();
        so.apply(o).is_ok() && so.verity_enforce
    }) {
        "--security-opt verity=enforce"
    } else {
        return Ok(());
    };
    Err(ApiError::bad_request(format!(
        "{}: {why}: a container made from a digest is started with the digest given again (--verify-image, the verify_image of a libpod start), which a Docker client cannot give: create it with the libpod API or velarx, or name the image by a tag",
        req.image
    )))
}

/// Docker's platform of a create: the image must be for it, or be a
/// manifest list whose instance for it is in the store (which is then
/// the image), as podman looks it up.
async fn image_for_platform(state: &AppState, body: &mut Value, platform: &str) -> ApiResult<()> {
    let wanted = velarx_registry::target::Platform::parse(platform)
        .map_err(|e| ApiError::bad_request(format!("parsing platform: {e}")))?;
    let image = body
        .get("Image")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let not_found = || {
        ApiError::no_such(
            super::error::Kind::Image,
            format!("no such image: {image}: image not known"),
        )
    };
    if let Some(list) = state.image_service.manifest_lookup(&image).await? {
        let rec = state
            .image_service
            .manifest_instance_for(&list, &wanted)
            .await
            .map_err(|_| not_found())?;
        body["Image"] = json!(rec.id);
        return Ok(());
    }
    let rec = super::images::resolve_image(state, &image).await?;
    let config: Value = serde_json::from_str(&rec.config).unwrap_or(Value::Null);
    let field = |k: &str| config.get(k).and_then(Value::as_str).unwrap_or("");
    let variant_ok = wanted
        .variant
        .as_deref()
        .is_none_or(|v| field("variant").is_empty() || field("variant") == v);
    if field("os") != wanted.os || field("architecture") != wanted.arch || !variant_ok {
        return Err(not_found());
    }
    Ok(())
}

/// The container `name`; the size of its changes with `size`.
pub(crate) async fn inspect_of(
    state: &AppState,
    name: &str,
    size: bool,
) -> ApiResult<velarx_proto::workload::ContainerRecord> {
    let found = lifecycle::resolve_observed(state, name).await?;
    let image_id = found.0.image_id.clone();
    let info = cinfo::load_observed(state, found).await?;
    let record = crate::api::blocking(|| cinfo::record(&info, state))?;
    // (boxed: the future of the engine's dispatch is as large as its
    // largest call)
    let record = Box::pin(cinfo::with_spec(state, record)).await;
    Ok(if size {
        cinfo::with_size(state, record, &image_id, &mut HashMap::new()).await?
    } else {
        record
    })
}

/// Make the container `name` ready to start, without starting it: false
/// when it is initialized or runs already.
pub(crate) async fn init_of(state: &Arc<AppState>, name: &str) -> ApiResult<bool> {
    let rec = lifecycle::resolve(state, name).await?;
    lifecycle::init(state, &rec, true).await
}

struct Bounds {
    before: i64,
    since: i64,
}

fn labels_match(want: &str, labels: &HashMap<String, String>) -> bool {
    super::call::label_matches(labels, want)
}

/// podman's name filter: a regular expression (its slashes dropped),
/// matched anywhere in the name.
fn name_matches(name: &str, want: &str) -> bool {
    let want = want.replace('/', "");
    match regex_lite::Regex::new(&want) {
        Ok(r) => r.is_match(name),
        Err(_) => name.contains(&want),
    }
}

/// The restart policies podman knows (its RestartPolicyMap).
const RESTART_POLICIES: &[&str] = &["none", "no", "always", "on-failure", "unless-stopped"];

/// The filters podman's GenerateContainerFilterFuncs (or, for a prune,
/// GeneratePruneContainerFilterFuncs) takes: anything else is a 500, as
/// is a status that is not one.
fn check_filters(filters: &Filters, prune: bool) -> ApiResult<()> {
    const LIST: &[&str] = &[
        "id",
        "label",
        "label!",
        "annotation",
        "annotation!",
        "name",
        "exited",
        "status",
        "ancestor",
        "before",
        "since",
        "volume",
        "health",
        "until",
        "pod",
        "network",
        "restart-policy",
        "command",
        "should-start-on-boot",
        "is-task",
    ];
    const PRUNE: &[&str] = &["label", "label!", "annotation", "annotation!", "until"];
    const STATUSES: &[&str] = &[
        "unknown",
        "configured",
        "created",
        "running",
        "stopped",
        "paused",
        "exited",
        "removing",
        "stopping",
    ];
    for (key, values) in &filters.0 {
        if !(if prune { PRUNE } else { LIST }).contains(&key.as_str()) {
            let msg = format!("{key} is an invalid filter");
            return Err(ApiError::bad_request(msg.clone()).with_cause(msg));
        }
        if key == "restart-policy" {
            let bad: Vec<&str> = values
                .iter()
                .map(String::as_str)
                .filter(|v| !RESTART_POLICIES.contains(v))
                .collect();
            if !bad.is_empty() {
                let what = if bad.len() > 1 {
                    "invalid restart policies"
                } else {
                    "invalid restart policy"
                };
                let msg = format!("{} {what}", bad.join(", "));
                return Err(ApiError::internal(msg.clone()).with_cause(msg));
            }
        }
        if key == "status" {
            if let Some(bad) = values.iter().find(|v| !STATUSES.contains(&v.as_str())) {
                return Err(ApiError::internal(format!(
                    "unknown container state: {bad}: invalid argument"
                ))
                .with_cause("invalid argument"));
            }
        }
    }
    Ok(())
}

fn filter_match(filters: &Filters, info: &Info, bounds: &Bounds) -> bool {
    for (key, values) in &filters.0 {
        if values.is_empty() {
            continue;
        }
        let mut any = false;
        for want in values {
            let m = match key.as_str() {
                "id" => id_matches(&info.rec.id, want),
                "name" => name_matches(&info.name(), want),
                "status" => {
                    info.status.state.as_str() == want.as_str()
                        || (want == "stopped" && info.status.state == RunState::Exited)
                }
                "label" => labels_match(want, &info.cfg.labels),
                "ancestor" => {
                    info.image_name().contains(want.as_str())
                        || info.image_id().starts_with(want.as_str())
                        || info.image_names.iter().any(|n| n.contains(want.as_str()))
                }
                "pod" => info
                    .pod
                    .as_ref()
                    .is_some_and(|p| p.id.starts_with(want.as_str()) || &p.name == want),
                "exited" => {
                    info.status.state == RunState::Exited
                        && want
                            .parse::<i32>()
                            .is_ok_and(|c| c == info.status.exit_code)
                }
                "health" => info.health.as_ref().map_or("none", |h| h.status.word()) == want,
                "volume" => info.cfg.mounts.iter().any(|m| {
                    &m.target == want
                        || m.volume.as_deref() == Some(want.as_str())
                        || std::path::Path::new(&m.source)
                            .file_name()
                            .is_some_and(|n| n.to_string_lossy() == want.as_str())
                }),
                "network" => {
                    let nets = if info.cfg.networks.is_empty() {
                        vec!["bridge".to_string()]
                    } else {
                        info.cfg.networks.clone()
                    };
                    nets.iter().any(|n| n == want)
                        || (want == "bridge" && nets.iter().any(|n| n == "podman"))
                }
                "before" => info.created_ns() < bounds.before,
                "since" => info.created_ns() > bounds.since,
                "until" => super::events::parse_since(want).is_some_and(|t| info.created_ns() < t),
                "is-task" => want != "true",
                "should-start-on-boot" => {
                    let policy = info.cfg.restart_policy.as_ref().map(|p| p.policy.word());
                    let on_boot = velarx_core::services::boot::should_start_on_boot(
                        policy,
                        info.stopped_by_user,
                    );
                    want.parse::<bool>().is_ok_and(|w| w == on_boot)
                }
                "command" => info.args().first().is_some_and(|c| c == want),
                "annotation" | "annotation!" | "label!" => true,
                "restart-policy" => {
                    // podman's "none" is no policy at all
                    let cur = info.restart_policy();
                    let want = if want == "none" { "" } else { want.as_str() };
                    cur == want
                }
                _ => true,
            };
            if m {
                any = true;
                break;
            }
        }
        if !any {
            return false;
        }
    }
    // Docker and podman AND the label filters
    for want in filters.get("label") {
        if !labels_match(want, &info.cfg.labels) {
            return false;
        }
    }
    if filters
        .get("label!")
        .iter()
        .any(|w| labels_match(w, &info.cfg.labels))
    {
        return false;
    }
    let annotations = info.annotations();
    filters
        .get("annotation")
        .iter()
        .all(|w| labels_match(w, &annotations))
        && !filters
            .get("annotation!")
            .iter()
            .any(|w| labels_match(w, &annotations))
}

/// What a list of containers asks.
pub(crate) struct ListQuery {
    /// The containers that do not run too
    pub all: bool,
    /// The size of their changes
    pub size: bool,
    /// The namespaces of their processes
    pub namespace: bool,
    /// The most recent ones (-1: all)
    pub limit: i64,
    pub filters: Filters,
}

/// A container of the list with everything the listings show of it, the
/// runtime not asked again for what the list learned; an error names the
/// container.
async fn loaded_found(
    state: &Arc<AppState>,
    shared: &cinfo::Shared,
    found: (
        velarx_db::ContainerRecord,
        Option<velarx_runtime::container::ContainerStatus>,
    ),
) -> ApiResult<cinfo::Info> {
    let id = found.0.id.clone();
    cinfo::load_found(state, found, shared)
        .await
        .map_err(|e| e.in_context(format!("container {id}")))
}

/// The container of a record, with everything the listings show of it; an
/// error names the container.
async fn loaded(state: &Arc<AppState>, rec: velarx_db::ContainerRecord) -> ApiResult<cinfo::Info> {
    let id = rec.id.clone();
    cinfo::load(state, rec)
        .await
        .map_err(|e| e.in_context(format!("container {id}")))
}

/// The containers `q` selects, the newest first.
pub(crate) async fn list_of(
    state: &Arc<AppState>,
    q: ListQuery,
) -> ApiResult<Vec<velarx_proto::workload::ContainerRecord>> {
    let ListQuery {
        mut all,
        size,
        namespace,
        limit,
        filters,
    } = q;
    check_filters(&filters, false)?;
    // the most recent containers, running or not, and any status asked
    if limit > 0 || !filters.get("status").is_empty() {
        all = true;
    }
    let mut bounds = Bounds {
        before: i64::MAX,
        since: i64::MIN,
    };
    for (key, slot) in [("before", 0), ("since", 1)] {
        if let Some(r) = filters.get(key).first() {
            let c = lifecycle::resolve(state, r).await?;
            let ns = super::convert::record_time_ns(&c.created_at);
            if slot == 0 {
                bounds.before = ns;
            } else {
                bounds.since = ns;
            }
        }
    }
    let recs = match all {
        true => state.container_service.list_observed(true).await?,
        false => state.container_service.list_alive_observed().await?,
    };
    let shared = cinfo::Shared::read(state, recs.iter().map(|(rec, _)| rec)).await?;
    let shared = &shared;
    // The loads overlap: each may ask the monitor of a container nobody
    // follows for its health.
    let mut infos = futures::stream::iter(recs)
        .map(|found| loaded_found(state, shared, found))
        .buffered(16);
    let mut kept = Vec::new();
    while let Some(info) = infos.next().await {
        // (a record that cannot be read fails the list, naming the
        // container: `rm` still removes it)
        let info = info?;
        if !all && !info.status.alive() {
            continue;
        }
        if !filter_match(&filters, &info, &bounds) {
            continue;
        }
        kept.push(info);
    }
    // (the small reads of /proc of every container: one blocking turn)
    let records = crate::api::blocking(|| {
        kept.iter()
            .map(|info| {
                let mut record = cinfo::record(info, state)?;
                if namespace {
                    record.namespaces = cinfo::namespaces_of(record.pid);
                }
                Ok(record)
            })
            .collect::<Result<Vec<_>, velarx_base::ids::IdsError>>()
    })?;
    let mut out = Vec::new();
    let mut image_sizes = HashMap::new();
    for (info, mut record) in kept.iter().zip(records) {
        if size {
            record = cinfo::with_size(state, record, &info.rec.image_id, &mut image_sizes).await?;
        }
        out.push(record);
    }
    // newest first, and the limit keeps those
    out.sort_by_key(|c| std::cmp::Reverse(c.created_ns));
    if limit > 0 {
        out.truncate(limit as usize);
    }
    Ok(out)
}

/// Start the container `name`: whether it was started (not running yet).
pub(crate) async fn start_of(
    state: &Arc<AppState>,
    name: &str,
    check: &StartCheck,
) -> ApiResult<bool> {
    let rec = lifecycle::resolve(state, name).await?;
    let started = lifecycle::start(state, &rec, check).await;
    state.pod_service.settle_member(&rec.id).await;
    match started {
        Ok(Started::Started) => Ok(true),
        Ok(Started::AlreadyRunning) => Ok(false),
        Err(e) => {
            // as Docker: an auto-remove container that cannot start is removed
            if lifecycle::config_of(&rec)?.auto_remove {
                let _ = lifecycle::remove_now(state, &rec.id).await;
            }
            Err(e)
        }
    }
}

/// Start the container `name` with its monitor waiting for the client to
/// attach: its id, where its monitor is, and whether it was started (it did
/// not run).
pub(crate) async fn start_attached_of(
    state: &Arc<AppState>,
    name: &str,
    check: &StartCheck,
) -> ApiResult<(String, std::path::PathBuf, bool)> {
    let rec = lifecycle::resolve(state, name).await?;
    let dir = state.container_service.mon_dir(&rec.id);
    if lifecycle::status(state, &rec).await.alive() {
        check.refuse_unchecked(
            rec.name.as_deref().unwrap_or(&rec.id),
            "it runs, on the file systems its monitor mounted when it started",
        )?;
        return Ok((rec.id, dir, false));
    }
    let started = state.container_service.start_as(&rec.id, true, check).await;
    state.pod_service.settle_member(&rec.id).await;
    match started {
        Ok(dir) => {
            state.podman.notify_changed();
            Ok((rec.id, dir, true))
        }
        Err(velarx_core::services::ContainerError::AlreadyRunning(_)) => Ok((rec.id, dir, false)),
        Err(e) => {
            // as Docker: an auto-remove container that cannot start is removed
            if lifecycle::config_of(&rec)?.auto_remove {
                let _ = lifecycle::remove_now(state, &rec.id).await;
            }
            Err(e.into())
        }
    }
}

/// Stop the container `name` after `timeout` seconds (its own if none):
/// whether it was stopped (it was running), and podman's warning when the
/// stop signal did not stop it in time.  A container that is not there is
/// stopped with `ignore`.  `service`: the stop of a service manager (a
/// shutdown), not of a user.
pub(crate) async fn stop_of(
    state: &Arc<AppState>,
    name: &str,
    timeout: Option<u64>,
    ignore: bool,
    service: bool,
) -> ApiResult<(bool, Option<String>)> {
    let rec = match lifecycle::resolve(state, name).await {
        Ok(r) => r,
        Err(e) if ignore && e.status == 404 => return Ok((true, None)),
        Err(e) => return Err(e),
    };
    // the stop tells of itself (events)
    let timeout = timeout.map(|t| t.min(u32::MAX as u64) as u32);
    let stopped = if service {
        state
            .container_service
            .stop_as_service(&rec.id, timeout)
            .await
            .map(|()| velarx_core::services::Stop::Stopped)
    } else {
        state
            .container_service
            .stop_signalled(&rec.id, timeout, None)
            .await
    };
    use velarx_core::services::Stop;
    state.pod_service.settle_member(&rec.id).await;
    // podman's stop removes an `--rm` container, also one that does not run
    // (never started, left stopped by the stop of its pod) or that its exit
    // left (other containers depend on it: then the removal fails)
    if stopped.is_ok() && lifecycle::config_of(&rec)?.auto_remove {
        if let Ok(left) = lifecycle::resolve(state, &rec.id).await {
            if !lifecycle::status(state, &left).await.alive() {
                lifecycle::remove_now_with(state, &left.id, true).await?;
            }
        }
    }
    match stopped {
        Ok(Stop::NotRunning) => Ok((false, None)),
        // (none with -t 0: the kill is what was asked)
        Ok(Stop::Stopped) | Ok(Stop::Killed { seconds: 0, .. }) => Ok((true, None)),
        Ok(killed @ Stop::Killed { .. }) => Ok((true, lifecycle::kill_warning(&rec, &killed))),
        // a --rm container goes as it stops: gone after it was there is stopped
        Err(velarx_core::services::ContainerError::NotFound(_))
        | Err(velarx_core::services::ContainerError::Database(velarx_types::DbError::NotFound(
            _,
        ))) => Ok((true, None)),
        Err(e) => Err(e.into()),
    }
}

/// Send the signal (a name or a number; SIGKILL if none) to the container
/// `name`.
pub(crate) async fn kill_of(
    state: &Arc<AppState>,
    name: &str,
    signal: Option<&str>,
) -> ApiResult<()> {
    let rec = lifecycle::resolve(state, name).await?;
    let sig = match signal.filter(|s| !s.is_empty()) {
        Some(s) => lifecycle::parse_signal(s)
            .ok_or_else(|| ApiError::bad_request(format!("invalid signal: {s}")))?,
        None => 9,
    };
    let killed = lifecycle::kill(state, &rec, sig).await;
    state.pod_service.settle_member(&rec.id).await;
    killed
}

/// Stop and start the container `name`; an `--rm` container is not removed
/// as it stops.
pub(crate) async fn restart_of(
    state: &Arc<AppState>,
    name: &str,
    timeout: Option<u64>,
    check: &StartCheck,
) -> ApiResult<()> {
    let rec = lifecycle::resolve(state, name).await?;
    state.container_service.keep(&rec.id).await?;
    // a stop or a kill meanwhile waits for the restart to end, as podman's
    // (the event comes first, then the `died` of the stop, `init`, `start`)
    let _restarting = state.container_service.restart_lock(&rec.id).await?;
    state
        .container_service
        .notify_action_of(&rec.id, "restart", Vec::new())
        .await;
    let stopped = state
        .container_service
        .stop_unlocked(
            &rec.id,
            timeout.map(|t| t.min(u32::MAX as u64) as u32),
            None,
        )
        .await;
    state.pod_service.settle_member(&rec.id).await;
    stopped?;
    let rec = lifecycle::resolve(state, name).await?;
    let started = lifecycle::start(state, &rec, check).await;
    state.pod_service.settle_member(&rec.id).await;
    started?;
    Ok(())
}

/// Pause (or, with `pause` false, unpause) the container `name`.
pub(crate) async fn pause_of(state: &Arc<AppState>, name: &str, pause: bool) -> ApiResult<()> {
    let rec = lifecycle::resolve(state, name).await?;
    let done = if pause {
        lifecycle::pause(state, &rec).await
    } else {
        lifecycle::unpause(state, &rec).await
    };
    state.pod_service.settle_member(&rec.id).await;
    done
}

/// Pause the container `name` for a lease that ends at `until` (milliseconds
/// since the epoch): the ID the lease belongs to.
pub(crate) async fn pause_leased_of(
    state: &Arc<AppState>,
    name: &str,
    until: i64,
) -> ApiResult<String> {
    let rec = lifecycle::resolve(state, name).await?;
    lifecycle::pause_leased(state, &rec, until).await?;
    Ok(rec.id)
}

/// Give the container `name` the name `new`.
pub(crate) async fn rename_of(state: &Arc<AppState>, name: &str, new: &str) -> ApiResult<()> {
    if new.is_empty() {
        return Err(ApiError::bad_request("name parameter cannot be empty"));
    }
    let rec = lifecycle::resolve(state, name).await?;
    if state.db.get_container(new).await.is_ok() {
        return Err(ApiError::conflict(format!(
            "the container name \"{new}\" is already in use"
        )));
    }
    state.container_service.rename(&rec.id, new).await?;
    Ok(())
}

/// How a container is removed.
pub(crate) struct RemoveOptions {
    pub force: bool,
    /// Its anonymous volumes too
    pub volumes: bool,
    /// One that is not there is no error
    pub ignore: bool,
    /// The containers that depend on it go first
    pub depend: bool,
    /// The seconds a running container has to stop (none: its own)
    pub timeout: Option<u64>,
}

/// Remove the container `name`: the IDs removed, each with what named it,
/// and podman's warnings of the stops that needed the kill.
pub(crate) async fn remove_of(
    state: &Arc<AppState>,
    name: &str,
    opts: &RemoveOptions,
) -> ApiResult<(Vec<(String, String)>, Vec<String>)> {
    let RemoveOptions {
        force,
        volumes,
        ignore,
        depend,
        timeout,
    } = *opts;
    // (`lookup`: the name, or the id it was found as)
    let resolve = |lookup: String| async move {
        match lifecycle::resolve(state, &lookup).await {
            Ok(r) => Ok(Some(r)),
            Err(e) if ignore && e.status == 404 => Ok(None),
            // podman's removal says it this way round
            Err(mut e) if e.status == 404 => {
                e.message =
                    format!("no container with ID or name {name:?} found: no such container");
                Err(e)
            }
            Err(e) => Err(e),
        }
    };
    let Some(mut rec) = resolve(name.to_string()).await? else {
        return Ok(Default::default());
    };
    let pod = super::pods::pod_of_container(state, &rec.id).await;
    // a member of a pod goes between two operations on the pod (podman's
    // removal locks the pod): what is gone meanwhile went with it
    let _op = match &pod {
        Some((pod_id, _, false)) => {
            // (a pod removed meanwhile has no lock; a lock that cannot be
            // taken is an error, not a removal without it)
            let op = match state.pod_service.lock_operation(pod_id).await {
                Ok(op) => Some(op),
                Err(velarx_core::services::PodError::NotFound(_)) => None,
                Err(e) => return Err(e.into()),
            };
            match resolve(rec.id.clone()).await? {
                Some(r) => rec = r,
                None => return Ok(Default::default()),
            }
            op
        }
        _ => None,
    };
    // the infra container of a pod goes with its pod: its containers depend
    // on it, and so does the pod
    if let Some((pod_id, _, true)) = pod {
        if !depend {
            return Err(ApiError::internal(format!(
                "container {} is the infra container of pod {pod_id} and cannot be removed without removing the pod",
                rec.id
            )));
        }
        let pod = super::pods::get(state, &pod_id).await?;
        let (removed, warnings) = super::pods::remove_pod(state, &pod, force, timeout).await?;
        // (the infra container is named as the call named it)
        let removed = removed
            .into_iter()
            .map(|id| {
                let named = if id == rec.id {
                    name.to_string()
                } else {
                    id.clone()
                };
                (id, named)
            })
            .collect();
        return Ok((removed, warnings));
    }
    let mut order = Vec::new();
    if depend {
        dependents_first(state, &rec.id, &mut order).await?;
    }
    let mut removed = Vec::new();
    let mut warnings = Vec::new();
    for id in &order {
        let dep = lifecycle::resolve(state, id).await?;
        warnings
            .extend(lifecycle::remove_with_timeout(state, &dep, force, volumes, timeout).await?);
        removed.push((dep.id.clone(), dep.id));
    }
    warnings.extend(lifecycle::remove_with_timeout(state, &rec, force, volumes, timeout).await?);
    removed.push((rec.id, name.to_string()));
    Ok((removed, warnings))
}

/// The containers that depend on `id`, those that depend on them first.
async fn dependents_first(state: &AppState, id: &str, order: &mut Vec<String>) -> ApiResult<()> {
    let direct = state
        .container_service
        .dependents(id)
        .await
        .map_err(ApiError::from)?;
    for d in direct {
        if order.contains(&d) {
            continue;
        }
        Box::pin(dependents_first(state, &d, order)).await?;
        if !order.contains(&d) {
            order.push(d);
        }
    }
    Ok(())
}

/// Remove the containers that do not run and `filters` selects: their ids
/// and the size of their writable layers.
pub(crate) async fn prune_of(
    state: &Arc<AppState>,
    filters: &Filters,
) -> ApiResult<(Vec<String>, u64)> {
    check_filters(filters, true)?;
    filters.check_prune_until()?;
    let mut removed = Vec::new();
    let mut space = 0u64;
    // (all are read before any is removed: one that cannot be read stops the
    // prune, as it does the list)
    let mut infos = Vec::new();
    for rec in state.db.list_containers(true).await? {
        infos.push(loaded(state, rec).await?);
    }
    for info in infos {
        if info.status.alive() {
            continue;
        }
        if !filters
            .get("label")
            .iter()
            .all(|l| labels_match(l, &info.cfg.labels))
            || filters
                .get("label!")
                .iter()
                .any(|l| labels_match(l, &info.cfg.labels))
        {
            continue;
        }
        let annotations = info.annotations();
        if !filters
            .get("annotation")
            .iter()
            .all(|l| labels_match(l, &annotations))
            || filters
                .get("annotation!")
                .iter()
                .any(|l| labels_match(l, &annotations))
        {
            continue;
        }
        if let Some(until) = filters
            .get("until")
            .first()
            .and_then(|u| super::events::parse_since(u))
        {
            if info.created_ns() >= until {
                continue;
            }
        }
        space += super::archive::upper_size(state, &info.rec.id).await.max(0) as u64;
        let id = info.rec.id.clone();
        match lifecycle::remove_now(state, &id).await {
            Ok(()) => removed.push(id),
            Err(e) => tracing::warn!("cannot prune container {id}: {e}"),
        }
    }
    Ok((removed, space))
}

/// Change the size of the terminal of a container.
pub async fn resize_of(state: &Arc<AppState>, name: &str, h: i64, w: i64) -> ApiResult<()> {
    let rec = lifecycle::resolve(state, name).await?;
    if h <= 0 || w <= 0 || h > 65535 || w > 65535 {
        return Err(ApiError::bad_request(format!(
            "invalid terminal size {w}x{h}"
        )));
    }
    let st = lifecycle::status(state, &rec).await;
    if !st.alive() && !matches!(st.state, RunState::Created | RunState::Initialized) {
        return Err(ApiError::invalid_state(format!(
            "container {} is not running: container state improper",
            rec.id
        )));
    }
    // (a container not made in the runtime yet has no terminal to size: the
    // client that waits for its start gives it this size)
    state.podman.set_attach_size(&rec.id, h as u16, w as u16);
    if st.alive() || st.state == RunState::Initialized {
        // the monitor resizes the terminal (a container without one does
        // not mind the size)
        let _ = state
            .container_service
            .resize_terminal(&rec.id, h as u16, w as u16)
            .await;
    }
    Ok(())
}

/// Frame the output the way the client asked: raw with a terminal, else
/// Docker's multiplexed stream.
async fn write_chunk<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    tty: bool,
    want_out: bool,
    want_err: bool,
    c: &Chunk,
) -> std::io::Result<()> {
    if (c.stream == STDOUT && !want_out) || (c.stream == STDERR && !want_err) {
        return Ok(());
    }
    if tty {
        w.write_all(&c.data).await
    } else {
        super::stream::write_mux(w, c.stream, &c.data).await
    }
}

/// What a request to attach to a container asked.
pub struct AttachQuery {
    pub stdout: bool,
    pub stderr: bool,
    pub logs: bool,
    pub stream: bool,
    pub stdin: bool,
    /// `detachKeys` of the query
    pub detach_keys: Option<String>,
    /// The input of the container is closed when this client goes away
    pub stdin_once: bool,
    /// The end of the client's input does not close the container's
    pub stdin_keep_open: bool,
    /// The monitor waits for this attach to start the container
    pub start: bool,
    /// The size of the client's terminal (rows, columns)
    pub size: Option<(u16, u16)>,
}

/// An attach to a container, ready for the streams of its client.
pub struct AttachPlan {
    pub tty: bool,
    out: bool,
    err: bool,
    attach_stdin: bool,
    stdin_once: bool,
    stdin_keep_open: bool,
    start: bool,
    size: Option<(u16, u16)>,
    lines: Option<logs::Lines>,
    svc: Arc<velarx_core::services::ContainerService>,
    monitor: Option<std::path::PathBuf>,
    /// The container is not started: its client waits for its monitor.
    waiter: Option<super::state::AttachWaiter>,
    changes: tokio::sync::watch::Receiver<u64>,
    detach_keys: Vec<u8>,
}

/// Check the request and prepare what the client is sent: the errors before
/// the streams are the answer's.
pub async fn attach_of(state: &Arc<AppState>, name: &str, q: AttachQuery) -> ApiResult<AttachPlan> {
    let rec = lifecycle::resolve(state, name).await?;
    let (out, err) = (q.stdout, q.stderr);
    let (with_logs, stream, stdin) = (q.logs, q.stream, q.stdin);
    let cfg = lifecycle::config_of(&rec)?;
    // (the attach the container waits to start is its own run's, which has no
    // log to follow: its output is the monitor's)
    if cfg.log_driver == "passthrough" && !q.start {
        // (podman's words)
        return Err(ApiError::internal(format!(
            "attaching to container {}: this container is using the 'passthrough' log \
             driver, cannot attach: this container is not logging output",
            rec.id
        ))
        .with_cause("this container is not logging output"));
    }
    let tty = cfg.tty;
    let keys = q.detach_keys.as_deref().unwrap_or("ctrl-p,ctrl-q");
    let mut detach_keys = velarx_proto::stream::parse_detach_keys(keys)
        .map_err(|_| ApiError::bad_request(format!("Invalid detach keys ({keys}) provided")))?;
    // clients send the default keys whatever the container: without a
    // terminal the input is data, and the bytes of the keys are in it
    if !tty && keys == "ctrl-p,ctrl-q" {
        detach_keys.clear();
    }
    // a container started for this attach (`ContainerStartAttached`): its
    // monitor is there and waits for the attach, the runtime does not have
    // the container yet (it is not asked: that is a process to start)
    let waiting = q.start && stream && rec.state == velarx_db::RecordState::Running;
    let (alive, state_now) = if waiting {
        (false, RunState::Initialized)
    } else {
        let st = lifecycle::status(state, &rec).await;
        (st.alive(), st.state)
    };
    // its streams go through its monitor
    if (alive || waiting) && stream {
        state.container_service.check_monitor(&rec.id)?;
    }
    // (the file of the container, whatever `--log-opt path` made it)
    let log_file = if with_logs {
        Some(state.container_service.log_location(&rec.id).await?)
    } else {
        None
    };

    let mut snapshot = None;
    // podman initializes an exited container that a client attaches to,
    // to follow its next run (not for its logs only)
    let mut st_state = state_now;
    if st_state == RunState::Exited && stream {
        lifecycle::init(state, &rec, true).await?;
        st_state = RunState::Initialized;
    }
    // a container that is not started waits for it: its start gives the
    // monitor the time to wait for this client
    let waiter =
        (st_state == RunState::Created && stream).then(|| state.podman.attach_waiter(&rec.id));
    // the streams of a container go through its monitor
    let monitor =
        ((alive || waiting || matches!(st_state, RunState::Initialized | RunState::Created))
            && stream)
            .then(|| state.container_service.mon_dir(&rec.id));
    if let (Some(_), Some(loc)) = (&monitor, &log_file) {
        snapshot = Some(lifecycle::read_log(loc).await);
    }
    match st_state {
        _ if monitor.is_some() => {}
        RunState::Created
        | RunState::Initialized
        | RunState::Exited
        | RunState::Running
        | RunState::Paused
        | RunState::Stopping
            if log_file.is_some() =>
        {
            if let Some(loc) = &log_file {
                snapshot = Some(lifecycle::read_log(loc).await);
            }
        }
        RunState::Created
        | RunState::Initialized
        | RunState::Exited
        | RunState::Running
        | RunState::Paused
        | RunState::Stopping => {}
        RunState::Unknown => {
            return Err(ApiError::invalid_state(
                "can only attach to created or running containers: container state improper"
                    .to_string(),
            ))
        }
    }
    let lines = snapshot.filter(|_| with_logs).map(|snap| {
        logs::spawn_select(
            snap,
            logs::Select {
                stdout: true,
                stderr: true,
                ..Default::default()
            },
        )
    });
    let attach_stdin = stdin && cfg.stdin_open;
    Ok(AttachPlan {
        tty,
        out,
        err,
        attach_stdin,
        stdin_once: q.stdin_once,
        stdin_keep_open: q.stdin_keep_open,
        start: q.start,
        size: q.size,
        lines,
        svc: state.container_service.clone(),
        monitor,
        waiter,
        changes: state.podman.subscribe_changes(),
        detach_keys,
    })
}

impl AttachPlan {
    /// What the frontend is told about the session once it is taken.
    pub fn opened(&self) -> velarx_proto::engine::SessionOpened {
        velarx_proto::engine::SessionOpened {
            session: String::new(),
            tty: self.tty,
            stdin: self.attach_stdin,
            stdout: self.out,
            stderr: self.err,
            logs: self.lines.is_some().then_some(0),
            detach_keys: self.detach_keys.clone(),
            keep_open: self.stdin_keep_open,
        }
    }

    /// Open the streams of the container in its monitor and hand them to the
    /// frontend in `channel`, then follow the session until the container
    /// exits or the client goes away (the container goes on).  `log` is the
    /// pipe of the log so far, which the client is sent first.  The streams
    /// are not read here.
    pub async fn drive(
        self,
        channel: Out,
        log: Option<tokio::net::unix::pipe::Sender>,
        busy: Option<velarx_content::activation::Busy>,
    ) {
        let Self {
            tty,
            out,
            err,
            attach_stdin,
            stdin_once,
            start,
            size,
            lines,
            svc,
            monitor,
            waiter,
            mut changes,
            ..
        } = self;
        let _busy = busy;
        if let (Some(mut lines), Some(mut pipe)) = (lines, log) {
            while let Some(l) = lines.next().await {
                let c = Chunk {
                    stream: l.stream,
                    data: Arc::new(logs::render(&l, false)),
                };
                if write_chunk(&mut pipe, tty, out, err, &c).await.is_err() {
                    return;
                }
            }
        }
        let Some(dir) = monitor else { return };
        // (the monitor of a container that is not started is made by its
        // start, which waits for this client)
        if let Some(waiter) = &waiter {
            loop {
                if waiter.wait.cancelled() {
                    return;
                }
                if waiter.wait.ready() {
                    break;
                }
                tokio::select! {
                    r = changes.changed() => if r.is_err() { return },
                    // (the client left while it waits)
                    Event::Gone = channel.event() => return,
                }
            }
        }
        let want = velarx_wire::monitor::proto::Attach {
            stdin: attach_stdin,
            stdout: out,
            stderr: err,
            // (the monitor starts the container once this client is
            // attached)
            start: waiter.is_some() || start,
            stdin_once: attach_stdin && stdin_once,
        };
        let Ok((mut stream, streams)) = svc.attach_handed(&dir, &want).await else {
            return;
        };
        if let Some((rows, cols)) = waiter.as_ref().and_then(|w| w.wait.size()).or(size) {
            let _ = stream.resize(rows, cols).await;
        }
        let sent = channel
            .send_streams(streams.stdin, streams.stdout, streams.stderr)
            .await;
        if sent.is_err() {
            return;
        }
        loop {
            tokio::select! {
                // (the container exited, or the monitor went away)
                ended = stream.next() => {
                    let exit = match ended {
                        Ok(Some(velarx_core::services::AttachEvent::Exit(code))) => Some(i64::from(code)),
                        _ => None,
                    };
                    channel.end(exit).await;
                    return;
                }
                ev = channel.event() => match ev {
                    Event::InputClosed => {
                        let _ = stream.close_stdin().await;
                    }
                    Event::Detach | Event::Gone => return,
                },
            }
        }
    }
}

/// What a request for the logs of a container asked.
pub struct LogsQuery {
    pub stdout: bool,
    pub stderr: bool,
    pub follow: bool,
    pub timestamps: bool,
    pub tail: Option<i64>,
    pub since_ns: Option<i64>,
    pub until_ns: Option<i64>,
}

/// The logs of a container, ready to be sent.
pub struct LogsRun {
    /// The container has a terminal
    pub tty: bool,
    /// The lines of a log that is not a file (the journal), read already
    entries: Vec<velarx_core::services::LogEntry>,
    out: bool,
    err: bool,
    timestamps: bool,
    lines: logs::Lines,
    /// The container goes on: the lines wait for more
    follow: bool,
    /// The lines the journal gets next, until the container ends
    journal: Option<tokio::sync::mpsc::Receiver<velarx_core::services::LogEntry>>,
}

/// The lines of the log of a running container, and those it writes next,
/// read from the file whoever started the container; none when its monitor
/// is gone.
async fn follow_file(
    state: &Arc<AppState>,
    id: &str,
    loc: velarx_wire::wire::LogLocation,
    sel: &logs::Select,
) -> ApiResult<Option<logs::Lines>> {
    let dir = state.container_service.mon_dir(id);
    let Ok(watch) = logs::watch_exit(&dir).await else {
        return Ok(None);
    };
    logs::spawn_follow(loc.path, loc.allow_dir, sel.clone(), watch)
        .map(Some)
        .map_err(|e| {
            let status = if e.kind() == std::io::ErrorKind::ResourceBusy {
                503
            } else {
                500
            };
            ApiError::new(status, format!("cannot follow the log: {e}"))
        })
}

/// Check the query and read the log: the errors before the stream.
pub async fn logs_of(state: &Arc<AppState>, name: &str, q: LogsQuery) -> ApiResult<LogsRun> {
    let rec = lifecycle::resolve(state, name).await?;
    let (mut out, mut err) = (q.stdout, q.stderr);
    let tail = q.tail.and_then(|n| usize::try_from(n).ok());
    if !out && !err {
        out = true;
        err = true;
    }
    let tty = lifecycle::config_of(&rec)?.tty;
    let sel = logs::Select {
        tail,
        since_ns: q.since_ns.unwrap_or(0),
        until_ns: q.until_ns.unwrap_or(0),
        stdout: out,
        stderr: err,
    };
    let loc = state.container_service.log_location(&rec.id).await?;
    let following = q.follow && lifecycle::status(state, &rec).await.alive();
    if loc.driver != LogDriver::K8sFile {
        // (the journal, or a driver that keeps nothing to read: the service
        // knows, and refuses it with or without a follow)
        let query = velarx_core::services::LogQuery {
            tail,
            timestamps: q.timestamps,
            since_ns: q.since_ns,
            until_ns: q.until_ns,
        };
        // (a running container is followed in the journal itself: every
        // line once, in its order, until the container ends)
        let (entries, journal) = if following && loc.driver == LogDriver::Journald {
            let rx = state
                .container_service
                .follow_journal_logs(&rec.id, query)
                .await?;
            (Vec::new(), Some(rx))
        } else {
            let entries = state
                .container_service
                .collect_logs(&rec.id, &query)
                .await?;
            (entries, None)
        };
        return Ok(LogsRun {
            tty,
            entries,
            out,
            err,
            timestamps: q.timestamps,
            lines: logs::Lines::none(),
            follow: journal.is_some(),
            journal,
        });
    }
    // (the file of the container, whatever `--log-opt path` made it)
    let mut lines = None;
    if following {
        lines = follow_file(state, &rec.id, loc.clone(), &sel).await?;
    }
    let follow = lines.is_some();
    let lines = match lines {
        Some(l) => l,
        None => logs::spawn_select(lifecycle::read_log(&loc).await, sel),
    };
    Ok(LogsRun {
        tty,
        entries: Vec::new(),
        out,
        err,
        timestamps: q.timestamps,
        follow,
        lines,
        journal: None,
    })
}

impl LogsRun {
    /// Write the logs, then what is followed until the container ends or
    /// the reader goes away.  `framed`: Docker's multiplexed stream; else
    /// the raw output.
    pub async fn run<W: super::stream::Sink>(self, mut w: W, framed: bool) {
        let Self {
            out,
            err,
            timestamps,
            mut lines,
            follow,
            journal,
            entries,
            ..
        } = self;
        let tty = !framed;
        for e in entries {
            if write_entry(&mut w, tty, out, err, e).await.is_err() {
                return;
            }
        }
        loop {
            // (a container may say nothing for hours: only its end or the
            // reader's stops the wait)
            let next = if follow {
                tokio::select! {
                    l = lines.next() => l,
                    () = w.gone() => return,
                }
            } else {
                lines.next().await
            };
            let Some(l) = next else { break };
            let c = Chunk {
                stream: l.stream,
                data: Arc::new(logs::render(&l, timestamps)),
            };
            if write_chunk(&mut w, tty, out, err, &c).await.is_err() {
                return;
            }
        }
        if let Some(mut journal) = journal {
            loop {
                // (a container may say nothing for hours: only its end or
                // the reader's stops the wait)
                let got = tokio::select! {
                    e = journal.recv() => e,
                    () = w.gone() => return,
                };
                let Some(e) = got else { break };
                if write_entry(&mut w, tty, out, err, e).await.is_err() {
                    return;
                }
            }
        }
        let _ = w.shutdown().await;
    }
}

/// One line of the journal, written as the stream of its kind.
async fn write_entry<W: super::stream::Sink>(
    w: &mut W,
    tty: bool,
    out: bool,
    err: bool,
    e: velarx_core::services::LogEntry,
) -> std::io::Result<()> {
    use velarx_core::services::LogStream;
    let mut data = Vec::new();
    if let Some(t) = e.timestamp {
        data.extend_from_slice(t.as_bytes());
        data.push(b' ');
    }
    data.extend_from_slice(e.message.as_bytes());
    data.push(b'\n');
    let stream = match e.stream {
        LogStream::Stdout => STDOUT,
        LogStream::Stderr => STDERR,
    };
    let c = Chunk {
        stream,
        data: Arc::new(data),
    };
    write_chunk(w, tty, out, err, &c).await
}

/// The processes of the container `name` that runs, as `ps` with
/// `ps_args` (podman's descriptors, or the arguments of ps) shows them.
pub(crate) async fn processes_of(
    state: &AppState,
    name: &str,
    ps_args: &[String],
) -> ApiResult<(velarx_db::ContainerRecord, velarx_wire::wire::TopResult)> {
    let rec = lifecycle::resolve(state, name).await?;
    if !lifecycle::status(state, &rec).await.alive() {
        return Err(ApiError::invalid_state(format!(
            "container {} is not running: container state improper",
            rec.id
        )));
    }
    let top = state.container_service.top(&rec.id, ps_args).await?;
    Ok((rec, top))
}

/// Open the log file of the container `name` again.
pub(crate) async fn log_reopen_of(state: &AppState, name: &str) -> ApiResult<()> {
    let rec = lifecycle::resolve(state, name).await?;
    Ok(state.container_service.reopen_log(&rec.id).await?)
}

/// Run the health check of the container `name` now: its health after it.
pub(crate) async fn healthcheck_of(
    state: &Arc<AppState>,
    name: &str,
) -> ApiResult<velarx_proto::health::Health> {
    let rec = lifecycle::resolve(state, name).await?;
    let info = cinfo::load(state, rec).await?;
    if !info.req().is_some_and(|r| r.healthcheck.is_some()) {
        return Err(ApiError::invalid_state(format!(
            "container {} has no defined healthcheck",
            info.rec.id
        )));
    }
    if info.status.state != RunState::Running {
        return Err(ApiError::invalid_state(format!(
            "container {} is not running: container state improper",
            info.rec.id
        )));
    }
    state
        .container_service
        .run_health_check(&info.rec.id)
        .await
        .map_err(|e| ApiError::internal(format!("healthcheck: {e}")))
}

/// A file of the engine's for an archive in transit (not /tmp: it holds
/// process memory and may be big).
fn cr_staging(state: &AppState, what: &str) -> ApiResult<tempfile::TempPath> {
    let dir = state.container_service.root_dir.join(what);
    std::fs::create_dir_all(&dir).map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(tempfile::Builder::new()
        .prefix("archive-")
        .tempfile_in(&dir)
        .map_err(|e| ApiError::internal(e.to_string()))?
        .into_temp_path())
}

/// Checkpoint the container `name`, the checkpoint kept with it (for a
/// restore in place): podman's report.
pub(crate) async fn checkpoint_kept_of(
    state: &Arc<AppState>,
    name: &str,
    opts: &velarx_wire::wire::CheckpointOptions,
) -> ApiResult<velarx_proto::workload::CheckpointReport> {
    // (a rootless engine says so first, whatever the name)
    velarx_core::services::crcheckpoint::need_root()?;
    let rec = lifecycle::resolve(state, name).await?;
    let record = state.container_service.checkpoint(&rec.id, opts).await?;
    Ok((&record).into())
}

/// Checkpoint the container `name` into `out`, a file the client opened for
/// writing and passed as a descriptor (the engine service): the ID of the
/// container.  The archive is made in the engine's own directory and copied
/// into the file, which has to be a regular file with nothing in it; it is
/// emptied again when the copy fails.
pub(crate) async fn checkpoint_into(
    state: &Arc<AppState>,
    name: &str,
    mut opts: velarx_wire::wire::CheckpointOptions,
    out: std::fs::File,
) -> ApiResult<velarx_proto::workload::CheckpointReport> {
    use rustix::fs::{fcntl_getfl, fstat, FileType, OFlags};
    let refuse = |why: &str| ApiError::bad_request(format!("the archive descriptor {why}"));
    let st = fstat(&out).map_err(|e| ApiError::internal(e.to_string()))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(refuse("is not a regular file"));
    }
    if st.st_size != 0 {
        return Err(refuse("is not empty"));
    }
    let flags = fcntl_getfl(&out).map_err(|e| ApiError::internal(e.to_string()))?;
    if !flags.intersects(OFlags::WRONLY | OFlags::RDWR) {
        return Err(refuse("is not open for writing"));
    }
    if flags.contains(OFlags::APPEND) {
        return Err(refuse("is open for appending"));
    }
    let rec = lifecycle::resolve(state, name).await?;
    let staging = cr_staging(state, "checkpoint-export")?;
    opts.export = Some(staging.to_path_buf());
    let done = match state.container_service.checkpoint(&rec.id, &opts).await {
        Ok(record) => tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            // (the data only, cloned where the file system can: the holes
            // of the pages stay holes)
            let copied =
                velarx_storage::copy_file(&std::fs::File::open(&staging)?, &out, u64::MAX, || {
                    Ok(())
                })
                .and_then(|_| out.sync_all());
            if copied.is_err() {
                let _ = out.set_len(0);
            }
            copied
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))
        .and_then(|r| r.map_err(|e| ApiError::internal(format!("the archive: {e}"))))
        .map(|()| (&record).into()),
        Err(e) => Err(e.into()),
    };
    done
}

/// Stage the checkpoint of `archive`, a file the client opened for reading
/// and passed as a descriptor (the engine service), in the container `name`.
pub(crate) async fn restore_stage_from(
    state: &Arc<AppState>,
    name: &str,
    ignore_rootfs: bool,
    archive: std::fs::File,
) -> ApiResult<String> {
    use rustix::fs::{fcntl_getfl, fstat, FileType, OFlags};
    let refuse = |why: &str| ApiError::bad_request(format!("the archive descriptor {why}"));
    let st = fstat(&archive).map_err(|e| ApiError::internal(e.to_string()))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(refuse("is not a regular file"));
    }
    let flags = fcntl_getfl(&archive).map_err(|e| ApiError::internal(e.to_string()))?;
    if flags.contains(OFlags::WRONLY) {
        return Err(refuse("is not open for reading"));
    }
    let rec = lifecycle::resolve(state, name).await?;
    state
        .container_service
        .stage_restore(&rec.id, archive, ignore_rootfs)
        .await?;
    Ok(rec.id)
}

/// Checkpoint the container `name` into an archive (`opts.export` is the
/// engine's): the id of the container, and the archive, read as it is sent;
/// it is gone after.
pub(crate) async fn checkpoint_export_of(
    state: &Arc<AppState>,
    name: &str,
    mut opts: velarx_wire::wire::CheckpointOptions,
) -> ApiResult<(
    velarx_proto::workload::CheckpointReport,
    crate::api::ops::ByteStream,
)> {
    let rec = lifecycle::resolve(state, name).await?;
    let staging = cr_staging(state, "checkpoint-export")?;
    opts.export = Some(staging.to_path_buf());
    let record = state.container_service.checkpoint(&rec.id, &opts).await?;
    let file = tokio::fs::File::open(&staging)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    // the archive is gone with the stream
    let stream: crate::api::ops::ByteStream = Box::pin(futures::stream::unfold(
        (file, staging),
        |(mut file, staging)| async move {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; 256 * 1024];
            match file.read(&mut buf).await {
                Ok(0) => None,
                Ok(n) => {
                    buf.truncate(n);
                    Some((Ok(bytes::Bytes::from(buf)), (file, staging)))
                }
                Err(e) => Some((Err(e), (file, staging))),
            }
        },
    ));
    Ok(((&record).into(), stream))
}

/// Restore the container `name` from its own checkpoint: podman's report.
pub(crate) async fn restore_of(
    state: &Arc<AppState>,
    name: &str,
    opts: &velarx_wire::wire::RestoreOptions,
) -> ApiResult<velarx_proto::workload::RestoreReport> {
    velarx_core::services::crcheckpoint::need_root()?;
    let rec = match lifecycle::resolve(state, name).await {
        Ok(rec) => rec,
        // (a name that is no container may be a checkpoint image)
        Err(e) if e.status.as_u16() == 404 && state.image_service.get(name).await.is_ok() => {
            let record = state
                .container_service
                .restore_image(name, opts, &state.pod_service)
                .await?;
            return Ok((&record).into());
        }
        Err(e) => return Err(e),
    };
    let record = state.container_service.restore(&rec.id, opts).await?;
    Ok((&record).into())
}

/// Make a container of a checkpoint archive and restore it: the archive
/// is `input`, or with `reference` the one a node shares (from the content
/// sources).  podman's report.
pub(crate) async fn restore_import_of(
    state: &Arc<AppState>,
    mut opts: velarx_wire::wire::RestoreOptions,
    reference: Option<velarx_core::services::checkpoint::Reference>,
    input: crate::api::ops::ByteStream,
    previous: Option<crate::api::ops::ByteStream>,
) -> ApiResult<velarx_proto::workload::RestoreReport> {
    let staging = cr_staging(state, "checkpoint-import")?;
    if let Some(reference) = &reference {
        velarx_core::services::checkpoint::fetch(&*state.image_service, reference, &staging)
            .await
            .map_err(|e| {
                ApiError::no_such(
                    super::error::Kind::Container,
                    format!("the shared checkpoint {}: {e}", reference.public()),
                )
            })?;
    }
    upload_into(&staging, input, reference.is_some()).await?;
    opts.import = Some(staging.to_path_buf());
    let staging_previous = match previous {
        Some(previous) => {
            let staging = cr_staging(state, "checkpoint-import")?;
            upload_into(&staging, previous, false).await?;
            opts.import_previous = Some(staging.to_path_buf());
            Some(staging)
        }
        None => None,
    };
    let report = state
        .container_service
        .restore_into(&opts, &state.pod_service)
        .await;
    drop(staging);
    drop(staging_previous);
    Ok((&report?).into())
}

/// Append the pieces of the upload `input` (a checkpoint archive) to the
/// file `path`, checked as they come and within the limit of an upload.
async fn upload_into(
    path: &std::path::Path,
    mut input: crate::api::ops::ByteStream,
    shared: bool,
) -> ApiResult<()> {
    let mut out = tokio::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut size = 0u64;
    let mut guard = velarx_content::archive::guard::Guard::new(
        velarx_content::archive::guard::Accept::Compressed,
    );
    while let Some(piece) = futures::StreamExt::next(&mut input).await {
        if shared {
            return Err(ApiError::bad_request(
                "an archive is in the body or named by importReference, not both",
            ));
        }
        let piece = piece.map_err(|e| ApiError::internal(e.to_string()))?;
        guard
            .feed(&piece)
            .map_err(|e| ApiError::bad_request(format!("the checkpoint archive: {e}")))?;
        size += piece.len() as u64;
        if size > velarx_core::services::CHECKPOINT_UPLOAD_MAX {
            return Err(ApiError::bad_request(format!(
                "the archive is bigger than {} bytes",
                velarx_core::services::CHECKPOINT_UPLOAD_MAX
            )));
        }
        out.write_all(&piece)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    }
    guard
        .end()
        .map_err(|e| ApiError::bad_request(format!("the checkpoint archive: {e}")))?;
    out.flush()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(())
}

/// What an update changes, checked: the engine's [`UpdateSpec`] as the
/// pieces that are written to the configuration and to the bundle.
#[derive(Default)]
struct Update {
    memory: Option<i64>,
    memory_reservation: Option<i64>,
    memory_swap: Option<i64>,
    cpu_quota: Option<i64>,
    cpu_period: Option<u64>,
    cpu_shares: Option<u64>,
    cpuset_cpus: Option<String>,
    cpuset_mems: Option<String>,
    pids_limit: Option<i64>,
    restart: Option<velarx_wire::request::RestartPolicy>,
    /// OCI `blockIO`
    block_io: Option<Value>,
    /// OCI device rules (allows) added after those of the container
    device_rules: Vec<Value>,
    /// `NAME=VALUE` set, and names unset, in the environment of the next start
    env: Vec<String>,
    unset_env: Vec<String>,
    /// OCI rlimits of the next start
    rlimits: Option<Vec<Value>>,
}

fn bad(e: impl std::fmt::Display) -> ApiError {
    ApiError::bad_request(e.to_string())
}

/// A block IO weight, in range.
fn check_weight(w: u64) -> ApiResult<u64> {
    if (10..=1000).contains(&w) {
        Ok(w)
    } else {
        Err(bad(format!("invalid block IO weight {w}: 10 to 1000")))
    }
}

/// The numbers of a device of an update: its own, or those of the block
/// device at its path.
fn device_numbers(d: &UpdateDevice) -> ApiResult<(u64, u64)> {
    match (d.major, d.minor, d.path.as_deref()) {
        (Some(major), Some(minor), _) => Ok((major, minor)),
        (_, _, Some(path)) if !path.is_empty() => velarx_wire::options::throttle(path, 0)
            .map(|t| (t.major, t.minor))
            .map_err(bad),
        _ => Err(bad("a device has no numbers and no path")),
    }
}

/// An OCI `blockIO` of the limits an update sets, none when it sets none.
fn block_io_of(b: &UpdateBlockIo) -> ApiResult<Option<Value>> {
    let mut out = serde_json::Map::new();
    if let Some(w) = b.weight {
        out.insert("weight".into(), json!(check_weight(w)?));
    }
    for (key, list, weights) in [
        ("weightDevice", &b.weight_devices, true),
        ("throttleReadBpsDevice", &b.read_bps, false),
        ("throttleWriteBpsDevice", &b.write_bps, false),
        ("throttleReadIOPSDevice", &b.read_iops, false),
        ("throttleWriteIOPSDevice", &b.write_iops, false),
    ] {
        let mut devices = Vec::new();
        for d in list {
            let (major, minor) = device_numbers(d)?;
            devices.push(if weights {
                json!({"major": major, "minor": minor, "weight": check_weight(d.value)?})
            } else {
                json!({"major": major, "minor": minor, "rate": d.value})
            });
        }
        if !devices.is_empty() {
            out.insert(key.into(), Value::Array(devices));
        }
    }
    Ok((!out.is_empty()).then_some(Value::Object(out)))
}

/// An OCI device rule that allows.
fn device_rule_of(r: &velarx_wire::options::DeviceRule) -> ApiResult<Value> {
    if !matches!(r.typ.as_str(), "a" | "b" | "c") {
        return Err(bad(format!(
            "invalid device type in device-access-add: {}",
            r.typ
        )));
    }
    if r.access.is_empty() || r.access.chars().any(|c| !"rwm".contains(c)) {
        return Err(bad(format!(
            "invalid device access in device-access-add: {}",
            r.access
        )));
    }
    let mut rule = json!({"allow": true, "type": r.typ, "access": r.access});
    if let Some(m) = r.major {
        rule["major"] = json!(m);
    }
    if let Some(m) = r.minor {
        rule["minor"] = json!(m);
    }
    Ok(rule)
}

/// The health check of an update (podman's UpdateHealthCheckConfig applied
/// as its GetNewHealthCheckConfig does): `None` when the update says
/// nothing of it.
fn health_update(cur: Option<&Healthcheck>, u: &UpdateHealth) -> ApiResult<Option<Healthcheck>> {
    use velarx_proto::health::StartupHealthcheck;
    let regular = u.cmd.is_some()
        || u.interval.is_some()
        || u.retries.is_some()
        || u.timeout.is_some()
        || u.start_period.is_some();
    let startup = u.startup_cmd.is_some()
        || u.startup_interval.is_some()
        || u.startup_retries.is_some()
        || u.startup_timeout.is_some()
        || u.startup_success.is_some();
    let others = u.log_destination.is_some()
        || u.max_log_count.is_some()
        || u.max_log_size.is_some()
        || u.on_failure.is_some();
    if !u.none && !regular && !startup && !others {
        return Ok(None);
    }
    // MakeHealthCheckFromCli refuses a timeout below 1 ns for both checks
    if u.timeout == Some(0) || u.startup_timeout == Some(0) {
        return Err(ApiError::internal(
            "healthcheck-timeout must be at least 1 second",
        ));
    }
    let not_set = || ApiError::internal("startup healthcheck command is not set");
    let has_test =
        |h: Option<&Healthcheck>| h.is_some_and(|h| !h.test.is_empty() && h.test[0] != "NONE");
    if u.none && (regular || startup) {
        return Err(ApiError::internal(
            "cannot specify both --no-healthcheck and other HealthCheck flags",
        ));
    }
    if regular && u.cmd.is_none() && !has_test(cur) {
        return Err(not_set());
    }
    if startup && u.startup_cmd.is_none() && !cur.is_some_and(|h| h.startup.is_some()) {
        return Err(not_set());
    }
    // podman's defaults for what a new check does not give
    let mut h = cur.cloned().unwrap_or_else(|| Healthcheck {
        test: vec!["NONE".into()],
        interval_ns: 30_000_000_000,
        timeout_ns: 30_000_000_000,
        retries: 3,
        ..Default::default()
    });
    let command = |c: &str| -> Vec<String> {
        if c.eq_ignore_ascii_case("none") {
            return vec!["NONE".into()];
        }
        // a JSON array is the command itself
        match serde_json::from_str::<Vec<String>>(c) {
            Ok(v) if !v.is_empty() => std::iter::once("CMD".to_string()).chain(v).collect(),
            _ => vec!["CMD-SHELL".into(), c.to_string()],
        }
    };
    if u.none {
        h.test = vec!["NONE".into()];
        h.startup = None;
    }
    if let Some(c) = &u.cmd {
        h.test = command(c);
    }
    if let Some(d) = u.interval {
        // podman's `disable` (0): no timer, only `healthcheck run`
        h.interval_ns = d;
        h.interval_disabled = d == 0;
    }
    if let Some(n) = u.retries {
        h.retries = n;
    }
    if let Some(d) = u.timeout {
        h.timeout_ns = d;
    }
    if let Some(d) = u.start_period {
        h.start_period_ns = d;
    }
    if startup {
        let mut st = h.startup.take().unwrap_or_else(|| StartupHealthcheck {
            interval_ns: 30_000_000_000,
            timeout_ns: 30_000_000_000,
            ..Default::default()
        });
        if let Some(c) = &u.startup_cmd {
            st.test = command(c);
        }
        if let Some(d) = u.startup_interval {
            st.interval_ns = d;
        }
        if let Some(n) = u.startup_retries {
            st.retries = n;
        }
        if let Some(d) = u.startup_timeout {
            st.timeout_ns = d;
        }
        if let Some(n) = u.startup_success {
            st.successes = n;
        }
        h.startup = Some(st);
    }
    if let Some(d) = u.log_destination.as_deref() {
        match d {
            "local" | "events_logger" => {}
            dir if std::path::Path::new(dir).is_absolute() && std::path::Path::new(dir).is_dir() => {}
            dir => {
                return Err(ApiError::internal(format!(
                    "HealthCheck Log '{dir}' destination must be directory path, local or events_logger"
                )))
            }
        }
        h.log_destination = d.to_string();
    }
    if let Some(n) = u.max_log_count {
        h.max_log_count = Some(n);
    }
    if let Some(n) = u.max_log_size {
        h.max_log_size = Some(n);
    }
    if let Some(a) = u.on_failure {
        h.on_failure = a;
    }
    Ok(Some(h))
}

impl Update {
    /// `spec`, checked.
    fn of(spec: &UpdateSpec) -> ApiResult<Self> {
        let rlimits = spec
            .ulimits
            .as_ref()
            .map(|list| {
                list.iter()
                    .map(|r| {
                        velarx_wire::options::rlimit(&r.name, r.soft, r.hard)
                            .map(|l| json!({"type": l.typ, "soft": l.soft, "hard": l.hard}))
                            .map_err(ApiError::internal)
                    })
                    .collect::<ApiResult<Vec<_>>>()
            })
            .transpose()?;
        Ok(Self {
            memory: spec.memory,
            memory_reservation: spec.memory_reservation,
            memory_swap: spec.memory_swap,
            cpu_quota: spec.cpu_quota,
            cpu_period: spec.cpu_period,
            // (no shares: what the cgroup has)
            cpu_shares: spec.cpu_shares.filter(|s| *s > 0),
            cpuset_cpus: spec.cpuset_cpus.clone(),
            cpuset_mems: spec.cpuset_mems.clone(),
            pids_limit: spec.pids_limit,
            restart: spec.restart.clone(),
            block_io: block_io_of(&spec.block_io)?,
            device_rules: spec
                .device_rules
                .iter()
                .map(device_rule_of)
                .collect::<ApiResult<_>>()?,
            env: spec.env.clone(),
            unset_env: spec.unset_env.clone(),
            rlimits,
        })
    }
}

/// Change the container `name` as `spec` says: its ID.
pub(crate) async fn amend_of(
    state: &Arc<AppState>,
    name: &str,
    spec: &UpdateSpec,
) -> ApiResult<String> {
    let rec = lifecycle::resolve(state, name).await?;
    let u = Update::of(spec)?;
    // One change at a time, and none while the container starts or its exit
    // is recorded: the record as it is under the lock is the one changed,
    // and whether it runs stays true until the runtime has the limits.
    let lock = state.container_service.change_lock(&rec.id).await?;
    let rec = lifecycle::resolve(state, &rec.id).await?;
    // The configuration of the container, which a later start uses.
    let mut cfg = lifecycle::config_of(&rec)?;
    // a container with no cgroup of its own (made by the engine of a
    // command) has no limits to update: they would be dropped
    let limits = u
        .resources_patch()
        .as_object()
        .is_some_and(|p| !p.is_empty())
        || !u.device_rules.is_empty();
    if limits && cfg.cgroups_path.is_none() {
        let why = if cfg.cgroups == velarx_core::services::CgroupsMode::Disabled {
            "it was made with --cgroups=disabled"
        } else {
            "it has no cgroup of its own"
        };
        return Err(ApiError::invalid_state(format!(
            "cannot update the resources of container {}: {why}",
            rec.id
        )));
    }
    lifecycle::merge_env(&mut cfg.env, &u.env, &u.unset_env);
    let res = cfg.resources.get_or_insert_with(Default::default);
    if u.memory.is_some() {
        res.memory = u.memory;
    }
    if u.memory_reservation.is_some() {
        res.memory_reservation = u.memory_reservation;
    }
    if u.memory_swap.is_some() {
        res.memory_swap = u.memory_swap;
    }
    if u.cpu_quota.is_some() {
        res.cpu_quota = u.cpu_quota;
    }
    if u.cpu_period.is_some() {
        res.cpu_period = u.cpu_period;
    }
    if u.cpu_shares.is_some() {
        res.cpu_shares = u.cpu_shares;
    }
    if u.cpuset_cpus.is_some() {
        res.cpuset_cpus = u.cpuset_cpus.clone();
    }
    if u.cpuset_mems.is_some() {
        res.cpuset_mems = u.cpuset_mems.clone();
    }
    if u.pids_limit.is_some() {
        cfg.pids_limit = u.pids_limit;
    }
    // the health check, the restart policy (which its monitor takes at
    // once) and the rlimits (for the next start)
    let health = match &spec.health {
        Some(h) => health_update(cfg.healthcheck.as_ref(), h)?,
        None => None,
    };
    if let Some(h) = &health {
        cfg.healthcheck = Some(h.clone());
    }
    if let Some(r) = &u.restart {
        cfg.restart_policy = Some(velarx_wire::monitor::proto::RestartSettings {
            policy: velarx_wire::monitor::proto::RestartPolicy::from_word(&r.name)
                .unwrap_or_default(),
            max_retries: r.maximum_retry_count,
        });
    }
    // The bundle keeps them for the next start; a running container gets
    // them when it has a cgroup to put them in.  The runtime first: what it
    // refuses changes nothing.
    let alive = lifecycle::status(state, &rec).await.alive();
    let running = alive && cfg.cgroups_path.is_some();
    lifecycle::update_resources(
        state,
        &rec.id,
        &u.resources_patch(),
        &u.device_rules,
        running,
    )
    .await?;
    if let Some(r) = &u.rlimits {
        lifecycle::update_rlimits(state, &rec.id, r).await?;
    }
    if !u.env.is_empty() || !u.unset_env.is_empty() {
        lifecycle::update_env(state, &rec.id, &u.env, &u.unset_env).await?;
    }
    // then the configuration and what the API shows: what the runtime
    // refused above is in neither
    let json = serde_json::to_string(&cfg)?;
    let id = rec.id.clone();
    state
        .db
        .conn()
        .call(move |c| {
            c.execute(
                "UPDATE containers SET config = ?2 WHERE id = ?1",
                rusqlite::params![id, json],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    // What the API shows is the request that created the container.
    if let Some(mut api) = record::load(state, &rec.id).await {
        let r = api.request.resources.get_or_insert_with(Default::default);
        if u.memory.is_some() {
            r.memory = u.memory;
        }
        if u.memory_reservation.is_some() {
            r.memory_reservation = u.memory_reservation;
        }
        if u.memory_swap.is_some() {
            r.memory_swap = u.memory_swap;
        }
        if u.cpu_quota.is_some() {
            r.cpu_quota = u.cpu_quota;
        }
        if u.cpu_period.is_some() {
            r.cpu_period = u.cpu_period;
        }
        if u.cpu_shares.is_some() {
            r.cpu_shares = u.cpu_shares;
        }
        if u.cpuset_cpus.is_some() {
            r.cpuset_cpus = u.cpuset_cpus.clone();
        }
        if u.cpuset_mems.is_some() {
            r.cpuset_mems = u.cpuset_mems.clone();
        }
        if let Some(w) = u
            .block_io
            .as_ref()
            .and_then(|b| b.get("weight"))
            .and_then(Value::as_u64)
        {
            r.blkio_weight = Some(w as u16);
        }
        if u.pids_limit.is_some() {
            api.request.pids_limit = u.pids_limit;
        }
        if u.restart.is_some() {
            api.request.restart_policy = u.restart.clone();
        }
        record::save(state, &rec.id, &api).await?;
    }
    drop(lock);
    if alive {
        state
            .container_service
            .update_monitor(&rec.id, &cfg, u.restart.is_some(), health.is_some())
            .await;
    }
    state
        .container_service
        .notify_action_of(&rec.id, "update", Vec::new())
        .await;
    Ok(rec.id)
}

impl Update {
    /// The parts of `linux.resources` the update changes.
    fn resources_patch(&self) -> Value {
        let mut p = serde_json::Map::new();
        let mut put = |section: &str, key: &str, v: Value| {
            p.entry(section.to_string())
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .map(|o| o.insert(key.to_string(), v));
        };
        if let Some(v) = self.memory {
            put("memory", "limit", json!(v));
        }
        if let Some(v) = self.memory_reservation {
            put("memory", "reservation", json!(v));
        }
        if let Some(v) = self.memory_swap {
            put("memory", "swap", json!(v));
        }
        if let Some(v) = self.cpu_quota {
            put("cpu", "quota", json!(v));
        }
        if let Some(v) = self.cpu_period {
            put("cpu", "period", json!(v));
        }
        if let Some(v) = self.cpu_shares {
            put("cpu", "shares", json!(v));
        }
        if let Some(v) = &self.cpuset_cpus {
            put("cpu", "cpus", json!(v));
        }
        if let Some(v) = &self.cpuset_mems {
            put("cpu", "mems", json!(v));
        }
        if let Some(v) = self.pids_limit {
            put("pids", "limit", json!(v));
        }
        if let Some(Value::Object(b)) = &self.block_io {
            for (k, v) in b {
                put("blockIO", k, v.clone());
            }
        }
        Value::Object(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A container whose network setup cannot be read is neither left out
    /// of the list nor of the prune: the call fails and names it, and
    /// `rm` still removes it.
    #[tokio::test]
    async fn a_container_that_cannot_be_read_fails_the_list_and_the_prune_naming_it() {
        use crate::api::podman::test_store;
        let dir = tempfile::tempdir().unwrap();
        let state = test_store::state_in(dir.path()).await;
        test_store::image(&state, "img-a").await;
        for id in ["c1", "c2"] {
            let config = serde_json::to_string(&velarx_runtime::container::ContainerConfig {
                id: id.into(),
                ..Default::default()
            })
            .unwrap();
            test_store::container(&state, id, "img-a", &config).await;
        }
        let query = || ListQuery {
            all: true,
            size: false,
            namespace: false,
            limit: -1,
            filters: Filters::default(),
        };
        assert_eq!(list_of(&state, query()).await.unwrap().len(), 2);
        test_store::alter(
            &state,
            "INSERT INTO network_containers (container_id, spec) VALUES ('c2', 'not json')",
        );
        let Err(e) = list_of(&state, query()).await else {
            panic!("a container that cannot be read must not leave the list");
        };
        assert!(e.message.starts_with("container c2: "), "{}", e.message);
        assert_eq!(e.status.as_u16(), 500);
        let Err(e) = prune_of(&state, &Filters::default()).await else {
            panic!("a container that cannot be read must not leave the prune");
        };
        assert!(e.message.starts_with("container c2: "), "{}", e.message);
        // (nothing was pruned before the error)
        assert_eq!(state.db.list_containers(true).await.unwrap().len(), 2);
    }

    fn health(f: impl FnOnce(&mut UpdateHealth)) -> UpdateHealth {
        let mut h = UpdateHealth::default();
        f(&mut h);
        h
    }

    #[test]
    fn health_of_an_update() {
        // nothing of it
        assert!(health_update(None, &UpdateHealth::default())
            .unwrap()
            .is_none());
        // a time without a command, on a container without a check
        let e = health_update(None, &health(|h| h.interval = Some(10_000_000_000))).unwrap_err();
        assert!(e.message.contains("healthcheck command is not set"));
        let e = health_update(None, &health(|h| h.startup_retries = Some(5))).unwrap_err();
        assert!(e.message.contains("healthcheck command is not set"));
        // a new check with podman's defaults, and its startup check
        let h = health_update(
            None,
            &health(|h| {
                h.cmd = Some("echo hi".into());
                h.retries = Some(7);
                h.startup_cmd = Some("true".into());
                h.startup_success = Some(2);
            }),
        )
        .unwrap()
        .unwrap();
        assert_eq!(h.test, ["CMD-SHELL", "echo hi"]);
        assert_eq!((h.interval_ns, h.retries), (30_000_000_000, 7));
        let st = h.startup.as_ref().unwrap();
        assert_eq!(
            (st.test.as_slice(), st.successes),
            (&["CMD-SHELL".to_string(), "true".to_string()][..], 2)
        );
        // a time of an existing check
        let h2 = health_update(Some(&h), &health(|u| u.timeout = Some(5_000_000_000)))
            .unwrap()
            .unwrap();
        assert_eq!(
            (h2.timeout_ns, h2.test.clone()),
            (5_000_000_000, h.test.clone())
        );
        // a timeout of 0 (`disable`) is refused, as podman's
        for u in [
            health(|u| u.timeout = Some(0)),
            health(|u| u.startup_timeout = Some(0)),
        ] {
            let e = health_update(Some(&h), &u).unwrap_err();
            assert_eq!(e.message, "healthcheck-timeout must be at least 1 second");
        }
        // --no-healthcheck: NONE, no startup check; not with other flags
        let off = health_update(Some(&h), &health(|u| u.none = true))
            .unwrap()
            .unwrap();
        assert_eq!(
            (off.test.as_slice(), off.startup.is_none()),
            (&["NONE".to_string()][..], true)
        );
        assert!(health_update(
            Some(&h),
            &health(|u| {
                u.none = true;
                u.cmd = Some("x".into());
            })
        )
        .is_err());
        // a destination that is not a directory
        assert!(health_update(
            Some(&h),
            &health(|u| u.log_destination = Some("relative".into()))
        )
        .is_err());
        let h3 = health_update(
            Some(&h),
            &health(|u| u.on_failure = Some(velarx_proto::health::OnFailure::Kill)),
        )
        .unwrap()
        .unwrap();
        assert_eq!(h3.on_failure, velarx_proto::health::OnFailure::Kill);
        // --health-interval disable: no timer; a time again: a timer
        let off = health_update(Some(&h), &health(|u| u.interval = Some(0)))
            .unwrap()
            .unwrap();
        assert!(off.interval_disabled);
        assert_eq!(off.interval(), None);
        let on = health_update(Some(&off), &health(|u| u.interval = Some(7_000_000_000)))
            .unwrap()
            .unwrap();
        assert_eq!(on.interval(), Some(std::time::Duration::from_secs(7)));
    }

    #[test]
    fn rlimits_of_an_update() {
        let ulimit = |name: &str, soft, hard| velarx_proto::request::Ulimit {
            name: name.into(),
            soft,
            hard,
        };
        let spec = |list| UpdateSpec {
            ulimits: Some(list),
            ..Default::default()
        };
        let u = Update::of(&spec(vec![ulimit("nofile", 1024, 2048)])).unwrap();
        assert_eq!(
            u.rlimits.unwrap(),
            [json!({"type": "RLIMIT_NOFILE", "soft": 1024, "hard": 2048})]
        );
        assert!(Update::of(&spec(vec![ulimit("nofile", 4096, 1024)])).is_err());
        assert!(Update::of(&spec(vec![ulimit("bogus", 1, 1)])).is_err());
        assert!(Update::of(&spec(vec![]))
            .unwrap()
            .rlimits
            .unwrap()
            .is_empty());
        assert!(Update::of(&UpdateSpec::default())
            .unwrap()
            .rlimits
            .is_none());
    }

    #[test]
    fn device_limits_of_an_update() {
        let e = block_io_of(&UpdateBlockIo {
            write_iops: vec![UpdateDevice {
                path: Some("/dev/zero".into()),
                value: 1000,
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            e.message.contains("/dev/zero: not a block device"),
            "{}",
            e.message
        );
        assert!(block_io_of(&UpdateBlockIo::default()).unwrap().is_none());
        // devices by their numbers, a weight in range, a rule that allows
        let io = block_io_of(&UpdateBlockIo {
            weight: Some(300),
            weight_devices: vec![UpdateDevice {
                major: Some(8),
                minor: Some(0),
                value: 100,
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap()
        .unwrap();
        assert_eq!(
            io,
            json!({"weight": 300, "weightDevice": [{"major": 8, "minor": 0, "weight": 100}]})
        );
        let e = block_io_of(&UpdateBlockIo {
            weight: Some(5),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(e.status.as_u16(), 400);
        let rule = |typ: &str, access: &str| velarx_wire::options::DeviceRule {
            typ: typ.into(),
            major: Some(10),
            minor: None,
            access: access.into(),
        };
        assert_eq!(
            device_rule_of(&rule("c", "rw")).unwrap(),
            json!({"allow": true, "type": "c", "access": "rw", "major": 10})
        );
        assert!(device_rule_of(&rule("x", "rw")).is_err());
        assert!(device_rule_of(&rule("c", "rwx")).is_err());
    }

    #[test]
    fn id_and_name_filters_as_podman() {
        let id = "4ab0c3";
        assert!(id_matches(id, "4ab"));
        assert!(id_matches(id, "4AB"));
        assert!(id_matches(id, "^4"));
        assert!(!id_matches(id, "^5"));
        assert!(!id_matches(id, "ab0x"));
        assert!(name_matches("web-1", "^web"));
        assert!(name_matches("web-1", "/web"));
        assert!(!name_matches("web-1", "^db"));
        assert!(name_matches("a(b", "a(b"));
    }

    #[test]
    fn name_filters_take_the_go_regexp_forms_podman_users_write() {
        for (name, want, hit) in [
            ("web-1", "^web-[0-9]+$", true),
            ("web-1", r"^web-\d$", true),
            ("web-1", r"^\w+-\d$", true),
            ("web-1", "^(web|db)-", true),
            ("db-1", "^(?:web|db)-", true),
            ("web-12", "^web-[0-9]{3}$", false),
            ("Web-1", "(?i)^web", true),
            ("web-1", "[[:alpha:]]+-1", true),
            ("web.1", r"web\.1", true),
            ("webx1", r"web\.1", false),
            ("a\nb", "a.b", false),
            ("web-1", "(?P<n>web)", true),
        ] {
            assert_eq!(name_matches(name, want), hit, "{name:?} ~ {want:?}");
        }
        // what the syntax of the matcher does not have is not a match, as an
        // invalid expression is for podman: the name itself is searched
        assert!(!name_matches("web-1", r"\pL+-\d"));
        assert!(name_matches(r"x\pL", r"\pL"));
        assert!(!id_matches("4ab0c3", r"^\pN"));
    }

    #[test]
    fn names_resolve_to_the_name_found() {
        let names = vec![
            "quay.io/libpod/alpine:latest".to_string(),
            "localhost/x:1".to_string(),
        ];
        assert_eq!(
            resolved_name("alpine", &names),
            "quay.io/libpod/alpine:latest"
        );
        assert_eq!(
            resolved_name("libpod/alpine:latest", &names),
            "quay.io/libpod/alpine:latest"
        );
        assert_eq!(resolved_name("x:1", &names), "localhost/x:1");
        assert_eq!(resolved_name("b82e560ed57b", &names), "b82e560ed57b");
        assert_eq!(resolved_name("pine", &names), "pine");
    }

    #[test]
    fn the_patch_has_what_is_given() {
        let u = Update {
            memory: Some(1 << 20),
            cpu_shares: Some(100),
            block_io: Some(json!({"weight": 300})),
            ..Default::default()
        };
        assert_eq!(
            u.resources_patch(),
            json!({"memory": {"limit": 1 << 20}, "cpu": {"shares": 100}, "blockIO": {"weight": 300}})
        );
        assert_eq!(Update::default().resources_patch(), json!({}));
    }

    #[test]
    fn label_filters() {
        let mut l = HashMap::new();
        l.insert("k".to_string(), "v".to_string());
        assert!(labels_match("k", &l));
        assert!(labels_match("k=v", &l));
        assert!(!labels_match("k=x", &l));
        assert!(!labels_match("z", &l));
    }
}
