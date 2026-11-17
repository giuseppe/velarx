// SPDX-License-Identifier: Apache-2.0
//! Images: libpod's and Docker's routes.

use super::call::Filters;
use super::convert;
use super::error::{ApiError, ApiResult, Kind};
use super::events::Event;

use crate::api::AppState;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use velarx_core::services::PullOptions;
use velarx_db::{ImageRecord, ImageTag};
use velarx_types::ImageReference;

pub(crate) mod archive;
pub(crate) mod commit;
pub(crate) mod filters;
pub(crate) mod pull;
pub(crate) mod push;
pub(crate) mod remove;
pub(crate) use commit::distribution_of;
use filters::*;
pub(super) use push::*;
pub(crate) use remove::*;
use velarx_proto::engine::Condition;
use velarx_proto::workload::EventKind;

/// The id podman shows for an image: the digest of its config, without the
/// algorithm (64 hex digits for a sha256, 128 for a sha512).
pub(super) fn image_id(rec: &ImageRecord) -> String {
    rec.config_digest.hex()
}

pub(super) fn display_name(tag: &ImageTag) -> String {
    velarx_wire::events::display_name(&tag.repository, &tag.tag)
}

/// The name `repository@digest` (`docker.io/library/alpine@sha256:...`).
pub(super) fn display_digest_name(repository: &str, digest: &str) -> String {
    format!(
        "{}@{digest}",
        velarx_wire::events::display_repository(repository)
    )
}

/// The names of an image (`localhost:5000/alpine:chunked`), the newest
/// first.
pub(super) async fn image_display_names(
    state: &AppState,
    rec: &ImageRecord,
) -> ApiResult<Vec<String>> {
    Ok(state
        .db
        .get_tags_for_image(&rec.id)
        .await
        .map_err(|e| ApiError::db("reading the names of an image", e))?
        .iter()
        .map(display_name)
        .collect())
}

/// The image `name` designates: a name, an id or id prefix (config or
/// manifest digest, with or without `sha256:`).
pub(super) async fn resolve_image(state: &AppState, name: &str) -> ApiResult<ImageRecord> {
    use velarx_types::ImageError;
    match state.image_service.get(name).await {
        Ok(rec) => Ok(rec),
        // (podman refuses these before it looks, with the cause of the parse)
        Err(ImageError::Invalid(m)) => {
            let cause = m
                .strip_prefix("parsing reference")
                .and_then(|_| m.rsplit(": ").next())
                .unwrap_or(&m)
                .to_string();
            Err(ApiError::no_such(Kind::Image, m)
                .with_cause(cause)
                .with_condition(Condition::InvalidReference))
        }
        Err(ImageError::Pulling(m)) => Err(ApiError::no_such(Kind::Image, m)),
        Err(_) => Err(ApiError::no_such(
            Kind::Image,
            format!("{name}: image not known"),
        )),
    }
}

/// Everything the shapes are made of.
/// The size of the uncompressed tar of a layer (podman's sizes are those
/// of its layers so), as recorded at the pull: every row of a layer has it.
pub(super) fn layer_size(layer: &velarx_db::LayerRecord) -> ApiResult<i64> {
    layer
        .stream_size
        .ok_or_else(|| ApiError::internal(format!("layer {} has no recorded size", layer.key)))
}

/// Whether the manifest states layers.
fn manifest_has_layers(manifest: &str) -> bool {
    serde_json::from_str::<Value>(manifest)
        .ok()
        .and_then(|m| {
            m.get("layers")
                .and_then(Value::as_array)
                .map(|l| !l.is_empty())
        })
        .unwrap_or(false)
}

/// The size of the image `id` (a container's virtual size has it).
/// An image that is gone has no size (0), any other failure is one.
pub(super) async fn image_size(state: &AppState, id: &str) -> ApiResult<i64> {
    match state.image_service.get(id).await {
        Ok(rec) => Ok(View::load(state, rec).await?.map_or(0, |v| v.size)),
        Err(velarx_types::ImageError::NotFound(_)) => Ok(0),
        Err(e) => Err(e.into()),
    }
}

struct View {
    rec: ImageRecord,
    id: String,
    names: Vec<String>,
    /// Every name it had, the last one given first (podman's NamesHistory)
    names_history: Vec<String>,
    /// `repository@digest`, the names a pull by digest gave it
    digest_names: Vec<String>,
    size: i64,
    config: Value,
    manifest: Value,
    layers: Vec<velarx_db::LayerRecord>,
    /// Of an additional image store
    read_only: bool,
}

/// What the store says of an image besides its record.
pub(super) struct Rows {
    pub(super) names: Vec<String>,
    digest_names: Vec<String>,
    names_history: Vec<String>,
    pub(super) layers: Vec<velarx_db::LayerRecord>,
}

impl Rows {
    /// Read it; `None` when the image is gone (removed since it was
    /// listed).  Any other error of the database is one of the operation
    /// (a store of another build fails here, it does not give an image of
    /// no layers).
    pub(super) async fn read(
        db: &velarx_db::Database,
        rec: &ImageRecord,
    ) -> ApiResult<Option<Self>> {
        macro_rules! got {
            ($r:expr, $what:expr) => {
                match $r {
                    Ok(v) => v,
                    Err(e) if e.is_not_found() => return Ok(None),
                    Err(e) => {
                        return Err(ApiError::db(concat!("reading an image (", $what, ")"), e))
                    }
                }
            };
        }
        let names = got!(db.get_tags_for_image(&rec.id).await, "its names")
            .iter()
            .map(display_name)
            .collect();
        let digest_names = got!(
            db.get_digest_names_for_image(&rec.id).await,
            "its digest names"
        )
        .into_iter()
        .map(|(r, d)| display_digest_name(&r, &d.to_string()))
        .collect();
        let names_history = got!(db.get_name_history(&rec.id).await, "its names")
            .iter()
            .map(display_name)
            .collect();
        let layers = got!(db.get_image_layers_without_toc(&rec.id).await, "its layers");
        // (the rows of the layers go with the image: an image that has some
        // in its manifest and none in the store was removed meanwhile)
        if layers.is_empty() && manifest_has_layers(&rec.manifest) {
            match db.get_image(&rec.id).await {
                Ok(_) => {}
                Err(e) if e.is_not_found() => return Ok(None),
                Err(e) => return Err(ApiError::db("reading an image", e)),
            }
        }
        Ok(Some(Self {
            names,
            digest_names,
            names_history,
            layers,
        }))
    }
}

impl View {
    /// The image of a lookup that found it: gone since (`None`) is not an
    /// error of the caller of a list, which leaves it out.
    async fn load_required(state: &AppState, rec: ImageRecord) -> ApiResult<Self> {
        let id = rec.id.clone();
        Self::load(state, rec)
            .await?
            .ok_or_else(|| ApiError::no_such(Kind::Image, format!("{id}: image not known")))
    }

    /// Everything about the image `rec`.  `None`: it is gone (removed since
    /// it was listed); any other failure of the store is an error, never an
    /// empty answer (the sizes would be wrong).
    async fn load(state: &AppState, rec: ImageRecord) -> ApiResult<Option<Self>> {
        let Some(Rows {
            names,
            digest_names,
            names_history,
            layers,
        }) = Rows::read(&state.db, &rec).await?
        else {
            return Ok(None);
        };
        let read_only = state.db.read_only_store_of(&rec.id).await.is_some();
        let mut size = rec.manifest.len() as i64 + rec.config.len() as i64;
        for l in &layers {
            size += layer_size(l)?;
        }
        Ok(Some(Self {
            id: image_id(&rec),
            config: serde_json::from_str(&rec.config).unwrap_or(Value::Null),
            manifest: serde_json::from_str(&rec.manifest).unwrap_or(Value::Null),
            rec,
            names,
            names_history,
            digest_names,
            size,
            layers,
            read_only,
        }))
    }

    /// When the configuration says the image was made (0: it says not).
    fn config_created_ns(&self) -> i64 {
        self.config
            .get("created")
            .and_then(Value::as_str)
            .map_or(0, convert::record_time_ns)
            .max(0)
    }

    /// When it was made, else stored.
    fn created_ns(&self) -> i64 {
        match self.config_created_ns() {
            0 => convert::record_time_ns(&self.rec.created_at),
            n => n,
        }
    }

    /// The layers whose descriptors state the digest of their EROFS image.
    fn composefs(&self) -> Vec<velarx_proto::workload::ComposefsLayer> {
        let layers: Vec<velarx_types::OciDescriptor> = self
            .manifest
            .get("layers")
            .and_then(|l| serde_json::from_value(l.clone()).ok())
            .unwrap_or_default();
        layers
            .iter()
            .filter_map(|l| {
                let stated = l
                    .annotations
                    .get(velarx_core::services::LAYER_EROFS_ANNOTATION)?;
                Some(velarx_proto::workload::ComposefsLayer {
                    layer: l.digest.to_string(),
                    digests: stated.split(',').map(|d| d.trim().to_string()).collect(),
                })
            })
            .collect()
    }

    /// The record of the image (what the list adds left out).
    fn record(&self) -> velarx_proto::workload::ImageRecord {
        let s = |k: &str| {
            self.config
                .get(k)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let history = history_entries(&self.config);
        // podman's: the `comment` of a Docker configuration, else the
        // comment of the first step of the history
        let comment = match self.config.get("comment").and_then(Value::as_str) {
            Some(c) => c.to_string(),
            None => history
                .first()
                .map(|h| h.comment.clone())
                .unwrap_or_default(),
        };
        let config = config_record(self.config.get("config").unwrap_or(&Value::Null));
        velarx_proto::workload::ImageRecord {
            id: self.id.clone(),
            digests: {
                let mut digests: Vec<String> = self
                    .names
                    .iter()
                    .map(|n| repo_digest(n, &self.rec.manifest_digest.to_string()))
                    .collect();
                // podman: the repository with each digest of the image (a
                // pull by the digest of a list: the list's and the
                // instance's)
                for n in &self.digest_names {
                    let instance = n
                        .split_once('@')
                        .map(|(r, _)| format!("{r}@{}", self.rec.manifest_digest));
                    for d in std::iter::once(n.clone()).chain(instance) {
                        if !digests.contains(&d) {
                            digests.push(d);
                        }
                    }
                }
                digests
            },
            names: self.names.clone(),
            digest_names: self.digest_names.clone(),
            names_history: self.names_history.clone(),
            digest: self.rec.manifest_digest.to_string(),
            size: u64::try_from(self.size).unwrap_or(0),
            created_ns: self.config_created_ns(),
            stored_ns: convert::record_time_ns(&self.rec.created_at),
            read_only: self.read_only,
            os: s("os"),
            architecture: s("architecture"),
            variant: s("variant"),
            author: s("author"),
            comment,
            labels: config.labels.clone(),
            annotations: string_map(self.manifest.get("annotations")),
            manifest_type: self
                .manifest
                .get("mediaType")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            config,
            history,
            layers: strings(self.config.pointer("/rootfs/diff_ids")),
            ..Default::default()
        }
    }
}

/// The strings of a JSON array.
fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_str().map(str::to_string))
        .collect()
}

/// The members of a JSON object whose values are strings.
fn string_map(v: Option<&Value>) -> std::collections::BTreeMap<String, String> {
    v.and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
        .collect()
}

/// The `config` of an OCI image configuration.
fn config_record(c: &Value) -> velarx_proto::workload::ImageConfigRecord {
    let s = |k: &str| c.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let keys = |k: &str| {
        c.get(k)
            .and_then(Value::as_object)
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default()
    };
    velarx_proto::workload::ImageConfigRecord {
        user: s("User"),
        exposed_ports: keys("ExposedPorts"),
        env: strings(c.get("Env")),
        entrypoint: strings(c.get("Entrypoint")),
        cmd: strings(c.get("Cmd")),
        volumes: keys("Volumes"),
        working_dir: s("WorkingDir"),
        labels: string_map(c.get("Labels")),
        stop_signal: s("StopSignal"),
        args_escaped: c
            .get("ArgsEscaped")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        on_build: strings(c.get("OnBuild")),
        shell: strings(c.get("Shell")),
        healthcheck: c.get("Healthcheck").filter(|h| h.is_object()).map(|h| {
            let n = |k: &str| h.get(k).and_then(Value::as_i64).unwrap_or(0);
            velarx_proto::workload::ImageHealthcheck {
                test: strings(h.get("Test")),
                interval_ns: n("Interval"),
                timeout_ns: n("Timeout"),
                start_period_ns: n("StartPeriod"),
                start_interval_ns: n("StartInterval"),
                retries: n("Retries"),
            }
        }),
    }
}

/// The `history` of an OCI image configuration, the oldest first.
fn history_entries(config: &Value) -> Vec<velarx_proto::workload::ImageHistoryEntry> {
    config
        .get("history")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|h| {
            let st = |k: &str| h.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            velarx_proto::workload::ImageHistoryEntry {
                created_ns: h
                    .get("created")
                    .and_then(Value::as_str)
                    .map_or(0, convert::record_time_ns)
                    .max(0),
                created_by: st("created_by"),
                author: st("author"),
                comment: st("comment"),
                empty_layer: h
                    .get("empty_layer")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                ..Default::default()
            }
        })
        .collect()
}

/// `registry/repo:tag` to `registry/repo@digest`.
pub(super) fn repo_digest(name: &str, digest: &str) -> String {
    let after_slash = name.rfind('/').map_or(0, |i| i + 1);
    let end = match name.find('@') {
        Some(at) => at,
        None => name[after_slash..]
            .rfind(':')
            .map_or(name.len(), |c| after_slash + c),
    };
    format!("{}@{}", &name[..end], digest)
}

/// A manifest list in the list of images (no platform of its own).
fn list_record(l: &velarx_core::services::ManifestList) -> velarx_proto::workload::ImageRecord {
    let mut digests = Vec::new();
    for n in &l.names {
        digests.push(repo_digest(n, &l.digest.to_string()));
        for i in l.instances() {
            if let Some(d) = i["digest"].as_str() {
                digests.push(repo_digest(n, d));
            }
        }
    }
    let created = convert::record_time_ns(&l.created_at);
    velarx_proto::workload::ImageRecord {
        id: l.id.clone(),
        names: l.names.clone(),
        digests,
        digest: l.digest.to_string(),
        created_ns: created,
        stored_ns: created,
        manifest_list: true,
        ..Default::default()
    }
}

/// The images (and with `manifest_lists` the manifest lists) the filters
/// select, in the order they were stored, as podman's list: with `all` the
/// intermediate images of the builds too.
pub(crate) async fn list_of(
    state: &AppState,
    filters: &Filters,
    all: bool,
    manifest_lists: bool,
) -> ApiResult<Vec<velarx_proto::workload::ImageRecord>> {
    check_image_filters(filters)?;
    let before = match filters.get("before").first() {
        Some(r) => Some(created_of(state, r).await?),
        None => None,
    };
    let since = match filters
        .get("since")
        .first()
        .or(filters.get("after").first())
    {
        Some(r) => Some(created_of(state, r).await?),
        None => None,
    };
    let bounds = Bounds { before, since };
    // (podman: `intermediate=true` lists them without --all)
    let intermediates = filters.get("intermediate").iter().any(|v| v == "true");
    let mut out = Vec::new();
    if manifest_lists {
        for l in state.image_service.manifest_lists().await? {
            let r = list_record(&l);
            let patterns = filters.get("reference");
            if !patterns.is_empty()
                && !l
                    .names
                    .iter()
                    .any(|n| patterns.iter().any(|p| reference_match(n, p)))
            {
                continue;
            }
            if !filter_match(filters, &r, &bounds) {
                continue;
            }
            out.push(r);
        }
    }
    let records = state.image_service.list().await?;
    let api_ids: HashMap<&str, String> = records
        .iter()
        .map(|r| (r.id.as_str(), image_id(r)))
        .collect();
    let mut built_on = state.image_service.build_lineage().await?;
    built_on.retain(|_, p| p != velarx_db::BUILD_SCRATCH);
    let parents: HashSet<&str> = built_on.values().map(String::as_str).collect();
    for rec in records.iter().cloned() {
        let has_children = parents.contains(rec.id.as_str());
        let parent_id = built_on
            .get(&rec.id)
            .and_then(|p| api_ids.get(p.as_str()))
            .cloned()
            .unwrap_or_default();
        // (an image removed since the list is left out)
        let Some(v) = View::load(state, rec).await? else {
            continue;
        };
        // the intermediate images of the builds are shown with all, or
        // when they are asked for
        if !all && !intermediates && has_children && v.names.is_empty() {
            continue;
        }
        let mut r = v.record();
        r.parent_id = parent_id;
        r.has_children = has_children;
        r.containers = containers_using(state, &v.rec).await? as u64;
        if !filter_match(filters, &r, &bounds) {
            continue;
        }
        // every name of an image that matches, as podman lists them, but
        // for a single fully qualified reference with a tag or digest
        if let [one] = filters.get("reference") {
            narrow_names(&mut r.names, one);
        }
        out.push(r);
    }
    // in the order they were stored, as podman's
    out.sort_by_key(|r| r.stored_ns);
    Ok(out)
}

/// How many containers use the image `rec` (a failed query is an error,
/// not an image that no container uses).
async fn containers_using(state: &AppState, rec: &ImageRecord) -> ApiResult<usize> {
    state
        .db
        .containers_using_image(&rec.id)
        .await
        .map(|v| v.len())
        .map_err(|e| ApiError::db("listing the containers that use an image", e))
}

/// The image `name` (a name, an id or a prefix of one).
pub(crate) async fn inspect_of(
    state: &AppState,
    name: &str,
) -> ApiResult<velarx_proto::workload::ImageRecord> {
    let rec = resolve_image(state, name).await?;
    let view = View::load_required(state, rec).await?;
    // (an inspect only: the list does not parse the layers of every image)
    Ok(velarx_proto::workload::ImageRecord {
        composefs: view.composefs(),
        graph_driver: state.image_service.storage().graph_name().to_string(),
        ..view.record()
    })
}

/// Tag the image `name` (or the manifest list of that name) `repo:tag`.
pub(crate) async fn tag_of(
    state: &Arc<AppState>,
    libpod: bool,
    name: &str,
    repo: &str,
    tag: &str,
) -> ApiResult<()> {
    if repo.contains('@') || tag.contains('@') || repo == "sha256" {
        return Err(ApiError::bad_request(format!(
            "{repo}:{tag}: tag by digest not supported"
        )));
    }
    let target = format!("{}:{tag}", qualify_name(state, libpod, repo));
    parse_name(&target)?;
    let rec = match resolve_image(state, name).await {
        Ok(rec) => rec,
        Err(e) if e.status.as_u16() == 404 => {
            let svc = &state.image_service;
            let Some(list) = svc.manifest_lookup(name).await? else {
                return Err(e);
            };
            svc.manifest_tag(&list.id, &target).await?;
            state.podman.events.emit(
                Event::new(EventKind::Image, "tag", &list.id, &target).attr("name", target.clone()),
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    state.image_service.tag(&rec.id, &target).await?;
    state.podman.events.emit(
        Event::new(EventKind::Image, "tag", &image_id(&rec), &target).attr("name", target.clone()),
    );
    Ok(())
}

/// The image (or manifest list) `name` is there, or podman's error.
pub(crate) async fn found(state: &AppState, name: &str) -> ApiResult<()> {
    let not_found = || {
        let msg = format!("failed to find image {name}");
        Err(ApiError::not_found(msg.clone()).with_cause(msg))
    };
    match resolve_image(state, name).await {
        Ok(_) => Ok(()),
        Err(e) if e.status.as_u16() == 404 => {
            match state.image_service.manifest_lookup(name).await? {
                Some(_) => Ok(()),
                None => not_found(),
            }
        }
        Err(e) => Err(e),
    }
}

/// `name` with the registry a new name gets: its own, else Docker Hub for
/// the Docker API when the configuration asks, else `localhost`.
pub(crate) fn qualify_name(state: &AppState, libpod: bool, name: &str) -> String {
    let qualified = name
        .split_once('/')
        .is_some_and(|(first, _)| velarx_base::reference::is_registry_domain(first));
    if qualified {
        docker_hub_name(name)
    } else if !libpod && state.config.api.compat_api_enforce_docker_hub {
        if name.contains('/') {
            format!("docker.io/{name}")
        } else {
            format!("docker.io/library/{name}")
        }
    } else {
        format!("localhost/{name}")
    }
}

/// A name of Docker Hub as podman normalises it: `docker.io/foo` is
/// `docker.io/library/foo` (and `index.docker.io` is `docker.io`).
fn docker_hub_name(name: &str) -> String {
    let rest = name
        .strip_prefix("docker.io/")
        .or_else(|| name.strip_prefix("index.docker.io/"));
    match rest {
        Some(r) if !r.contains('/') => format!("docker.io/library/{r}"),
        Some(r) => format!("docker.io/{r}"),
        None => name.to_string(),
    }
}

/// The steps of the history of an image, the newest first, with the size
/// of the layer each made; the last step has the id and the names of the
/// image.
pub(crate) async fn history_of(
    state: &AppState,
    name: &str,
) -> ApiResult<Vec<velarx_proto::workload::ImageHistoryEntry>> {
    let rec = resolve_image(state, name).await?;
    let v = View::load_required(state, rec).await?;
    let entries = history_entries(&v.config);
    let mut layers = v.layers.iter().rev().peekable();
    let n = entries.len();
    let mut out = Vec::new();
    for (i, mut h) in entries.into_iter().enumerate().rev() {
        let empty = h.empty_layer;
        h.size = match (empty, layers.next_if(|_| !empty)) {
            (false, Some(l)) => u64::try_from(layer_size(l)?).unwrap_or(0),
            _ => 0,
        };
        if i + 1 == n {
            h.id = v.id.clone();
            h.tags = v.names.clone();
        }
        out.push(h);
    }
    Ok(out)
}

/// The names a pull of `name` would try: the alias, else each search
/// registry.
pub(crate) fn resolve_of(state: &AppState, name: &str) -> ApiResult<Vec<String>> {
    // the error containers/image gives, which clients match
    if repository_path(name)
        .chars()
        .any(|c| c.is_ascii_uppercase())
    {
        let cause = "repository name must be lowercase";
        return Err(ApiError::bad_request(format!("parsing {name:?}: {cause}")).with_cause(cause));
    }
    parse_name(name)
        .map_err(|e| ApiError::bad_request(format!("resolving `{name}`: {}", e.message)))?;
    // what a pull would try: the alias, else each search registry
    let candidates = state
        .image_service
        .candidates(name)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let names: Vec<String> = candidates
        .iter()
        .map(|c| {
            let r = ImageReference::parse(c).ok();
            match r {
                Some(r) => match (&r.digest, &r.tag) {
                    (Some(d), _) => {
                        format!("{}@{d}", velarx_wire::events::display_repository(&r.name()))
                    }
                    (None, Some(t)) => {
                        format!("{}:{t}", velarx_wire::events::display_repository(&r.name()))
                    }
                    _ => format!(
                        "{}:latest",
                        velarx_wire::events::display_repository(&r.name())
                    ),
                },
                None => c.clone(),
            }
        })
        .collect();
    Ok(names)
}

/// What registries have for `term` (`filters` are `key=value`: `stars`,
/// `is-official`, `is-automated`).
#[allow(
    clippy::too_many_arguments,
    reason = "one argument for each parameter of the search"
)]
pub(crate) async fn search_of(
    state: &AppState,
    term: &str,
    limit: usize,
    filters: &[String],
    list_tags: bool,
    tls_verify: Option<bool>,
    access: velarx_registry::auth::RegistryAccess,
) -> ApiResult<Vec<velarx_proto::engine::SearchHit>> {
    if term.is_empty() {
        return Err(ApiError::bad_request("term parameter cannot be empty"));
    }
    let filter = velarx_core::services::SearchFilter::parse(filters.iter().map(String::as_str))
        .map_err(ApiError::internal)?;
    let opts = velarx_core::services::SearchOptions {
        limit,
        list_tags,
        tls_verify,
        filter,
        access,
    };
    let found = state
        .image_service
        .search(term, &opts)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(found
        .into_iter()
        .map(|r| velarx_proto::engine::SearchHit {
            index: r.index,
            name: r.name,
            description: r.description,
            stars: r.stars,
            official: r.official,
            automated: r.automated,
            tag: r.tag,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(n: u8) -> velarx_types::digest::Digest {
        format!("sha256:{}", format!("{n:02x}").repeat(32))
            .parse()
            .unwrap()
    }

    /// A store in `dir` with one image of one layer; the manifest states
    /// the layer.
    async fn store_with_image(dir: &std::path::Path) -> (velarx_db::Database, ImageRecord) {
        let db = velarx_db::Database::open(dir.join("db.sqlite"))
            .await
            .unwrap();
        let rec = ImageRecord {
            id: "img1".into(),
            manifest_digest: digest_of(1),
            config_digest: digest_of(2),
            manifest: r#"{"layers":[{"digest":"sha256:0303030303030303030303030303030303030303030303030303030303030303"}]}"#.into(),
            config: "{}".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
            is_lazy: false,
        };
        db.insert_image(&rec).await.unwrap();
        let key = velarx_db::LayerKey::Whole(digest_of(3));
        db.insert_layer(&velarx_db::LayerRecord {
            stream_size: Some(1234),
            key,
            blob: Some(digest_of(3)),
            diff_id: Some(digest_of(4)),
            other_diff_id: None,
            size: 8_000_000,
            toc: Some("{}".into()),
            status: "ready".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
            registry_ref: None,
            erofs: None,
            owners: None,
        })
        .await
        .unwrap();
        db.insert_image_layer(&rec.id, &key, 0).await.unwrap();
        (db, rec)
    }

    /// The size of a layer is the one recorded at the pull: the row has no
    /// tar-split to decode (a listing would fail on it), and the table of
    /// contents is not read.
    #[tokio::test]
    async fn the_size_of_a_layer_is_the_one_recorded_at_the_pull() {
        let dir = tempfile::tempdir().unwrap();
        let (db, rec) = store_with_image(dir.path()).await;
        let rows = Rows::read(&db, &rec).await.unwrap().unwrap();
        assert_eq!(rows.layers[0].toc, None);
        assert_eq!(layer_size(&rows.layers[0]).unwrap(), 1234);
    }

    /// Every row of a layer has its size: a row without one is refused by
    /// the store, and a record without one (no row) is no size.
    #[tokio::test]
    async fn a_layer_without_a_recorded_size_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (db, rec) = store_with_image(dir.path()).await;
        let mut layer = Rows::read(&db, &rec).await.unwrap().unwrap().layers[0].clone();
        layer.key = velarx_db::LayerKey::Whole(digest_of(5));
        layer.stream_size = None;
        assert!(db.insert_layer(&layer).await.is_err());
        assert!(layer_size(&layer).is_err());
    }

    #[tokio::test]
    async fn the_rows_of_an_image_have_its_layers() {
        let dir = tempfile::tempdir().unwrap();
        let (db, rec) = store_with_image(dir.path()).await;
        let rows = Rows::read(&db, &rec).await.unwrap().unwrap();
        assert_eq!(rows.layers.len(), 1);
    }

    /// A store whose `layers` lacks a column is another build's: the view
    /// fails with the SQL error and the remedy, it does not show an image
    /// of no layers (a size of a few kB for megabytes).
    #[tokio::test]
    async fn a_store_of_another_shape_fails_the_rows_of_an_image() {
        let dir = tempfile::tempdir().unwrap();
        let (db, rec) = store_with_image(dir.path()).await;
        drop(db);
        let path = dir.path().join("db.sqlite");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("ALTER TABLE layers DROP COLUMN diff_id_other")
            .unwrap();
        drop(conn);
        let db = velarx_db::Database::open(&path).await.unwrap();
        let Err(e) = Rows::read(&db, &rec).await else {
            panic!("the rows of an image of a store of another shape must fail");
        };
        assert_eq!(e.status, 500);
        assert!(
            e.message.contains("reading an image (its layers)"),
            "{}",
            e.message
        );
        assert!(e.message.contains("no such column"), "{}", e.message);
        assert!(
            e.message
                .ends_with("the store was made by another build: remove it"),
            "{}",
            e.message
        );
    }

    /// An image removed between the listing and the load is skipped: no
    /// error, no image.
    #[tokio::test]
    async fn an_image_removed_since_the_list_is_left_out() {
        let dir = tempfile::tempdir().unwrap();
        let (db, rec) = store_with_image(dir.path()).await;
        db.delete_image(&rec.id).await.unwrap();
        assert!(Rows::read(&db, &rec).await.unwrap().is_none());
    }

    /// The names of an image of a store that fails are an error, not an
    /// image without names.
    #[tokio::test]
    async fn a_failed_read_of_the_names_is_an_error() {
        use crate::api::podman::test_store;
        let dir = tempfile::tempdir().unwrap();
        let state = test_store::state_in(dir.path()).await;
        let rec = test_store::image(&state, "img-a").await;
        test_store::alter(&state, "ALTER TABLE image_tags RENAME TO gone");
        let e = image_display_names(&state, &rec).await.unwrap_err();
        assert!(e.message.contains("no such table"), "{}", e.message);
        let Err(e) = Rows::read(&state.db, &rec).await else {
            panic!("the rows of an image whose names cannot be read must fail");
        };
        assert!(
            e.message.contains("reading an image (its names)"),
            "{}",
            e.message
        );
    }

    /// When the containers that use an image cannot be listed (one's
    /// configuration is not JSON: the query fails), `image rm` and the list
    /// fail: neither goes on as if no container used the image.
    #[tokio::test]
    async fn a_failed_read_of_the_users_of_an_image_fails() {
        use crate::api::podman::test_store;
        let dir = tempfile::tempdir().unwrap();
        let state = test_store::state_in(dir.path()).await;
        test_store::image(&state, "img-a").await;
        test_store::image(&state, "img-b").await;
        test_store::container(&state, "c1", "img-b", "{").await;
        let mut warnings = Vec::new();
        let e = remove::remove_one(
            &state,
            "localhost/img-a:latest",
            false,
            false,
            true,
            false,
            &mut warnings,
        )
        .await
        .unwrap_err();
        assert!(
            e.message
                .contains("listing the containers that use an image"),
            "{}",
            e.message
        );
        assert!(state.db.get_image("img-a").await.is_ok());
        let e = list_of(&state, &Filters::default(), false, false)
            .await
            .unwrap_err();
        assert!(
            e.message
                .contains("listing the containers that use an image"),
            "{}",
            e.message
        );
    }

    /// A prune that cannot tell whether containers use an image fails; it
    /// does not remove the image.
    #[tokio::test]
    async fn a_failed_read_of_the_containers_fails_the_prune() {
        use crate::api::podman::test_store;
        let dir = tempfile::tempdir().unwrap();
        let state = test_store::state_in(dir.path()).await;
        test_store::image(&state, "img-a").await;
        test_store::alter(&state, "ALTER TABLE containers RENAME TO gone");
        let e = state.image_service.prune(true, &[]).await.unwrap_err();
        assert!(e.to_string().contains("no such table"), "{e}");
        test_store::alter(&state, "ALTER TABLE gone RENAME TO containers");
        assert!(state.db.get_image("img-a").await.is_ok());
    }

    #[test]
    fn database_errors_say_what_failed() {
        let gone = ApiError::db("op", velarx_types::DbError::NotFound("x".into()));
        assert_eq!(gone.status, 404);
        let busy = tokio_rusqlite::Error::Rusqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("database is locked".into()),
        ));
        let e = ApiError::db("listing", velarx_types::DbError::Sqlite(busy));
        assert_eq!(e.status, 500);
        assert!(e.message.starts_with("listing: "), "{}", e.message);
        assert!(!e.message.contains("another build"), "{}", e.message);
    }

    /// A TLS server with a certificate no one signed: the handshake of a
    /// client fails, and the error says it by its type.
    async fn untrusted_https_error() -> velarx_types::ImageError {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::ssl::{SslAcceptor, SslMethod};
        use openssl::x509::{X509Builder, X509NameBuilder};
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
        let name = name.build();
        let mut cert = X509Builder::new().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = cert.build();
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        let acceptor = acceptor.build();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                // (the client leaves at the handshake)
                let _ = acceptor.accept(stream);
            }
        });
        let e = reqwest::Client::new()
            .get(format!("https://localhost:{port}/v2/"))
            .send()
            .await
            .unwrap_err();
        velarx_types::ImageError::from(e)
    }

    #[tokio::test]
    async fn push_errors_have_go_s_x509_cause() {
        let tls = untrusted_https_error().await;
        assert_eq!(
            tls.tls_error(),
            Some(velarx_types::TlsError::UnknownAuthority)
        );
        let e = push_error(400, "pushing: ", &tls);
        assert!(e.message.starts_with("pushing: "), "{}", e.message);
        assert!(
            e.message
                .ends_with(": x509: certificate signed by unknown authority"),
            "{}",
            e.message
        );
        let (status, cause, _) = e.finish(Kind::Image);
        assert_eq!(status, 400);
        assert_eq!(cause, "x509: certificate signed by unknown authority");
    }

    /// Text that only says it is a certificate failure is not one: a
    /// registry that answers with those words has no x509 cause.
    #[test]
    fn only_a_failed_verification_has_go_s_x509_cause() {
        let said = velarx_types::ImageError::Registry(
            "certificate verify failed (self-signed certificate)".into(),
        );
        let e = push_error(500, "", &said);
        assert!(!e.message.contains("x509"), "{}", e.message);
        let (_, cause, _) = e.finish(Kind::Image);
        assert!(!cause.contains("x509"), "{cause}");
        assert_eq!(
            push_error(
                500,
                "",
                &velarx_types::ImageError::Registry("connection refused".into())
            )
            .message,
            "registry error: connection refused"
        );
    }

    #[test]
    fn parents_are_found_by_their_layers() {
        let rec = |id: &str, created: &str| ImageRecord {
            id: id.into(),
            manifest_digest: velarx_types::digest::Digest::empty(
                velarx_types::digest::Algorithm::Sha256,
            ),
            config_digest: velarx_types::digest::Digest::empty(
                velarx_types::digest::Algorithm::Sha256,
            ),
            manifest: String::new(),
            config: String::new(),
            created_at: created.into(),
            is_lazy: false,
        };
        let l = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let images = vec![
            (rec("base", "2026-01-01T00:00:00Z"), l(&["a"])),
            (rec("one", "2026-01-02T00:00:00Z"), l(&["a", "b"])),
            (rec("same", "2026-01-03T00:00:00Z"), l(&["a", "b"])),
            (rec("other", "2026-01-01T00:00:00Z"), l(&["x"])),
        ];
        let child = l(&["a", "b", "c"]);
        let p = parent_of(&images, (&child, "2026-01-04T00:00:00Z"), "child").unwrap();
        assert_eq!(p.0.id, "same");
        // an image with the same layers made earlier is below
        let p = parent_of(&images, (&images[2].1, "2026-01-03T00:00:00Z"), "same").unwrap();
        assert_eq!(p.0.id, "one");
        let p = parent_of(&images, (&images[1].1, "2026-01-02T00:00:00Z"), "one").unwrap();
        assert_eq!(p.0.id, "base");
        assert!(parent_of(&images, (&images[0].1, "2026-01-01T00:00:00Z"), "base").is_none());
        assert!(parent_of(&images, (&l(&[]), "2026-01-05T00:00:00Z"), "empty").is_none());
    }

    #[test]
    fn docker_hub_names_are_normalised() {
        assert_eq!(
            docker_hub_name("docker.io/foo:1"),
            "docker.io/library/foo:1"
        );
        assert_eq!(
            docker_hub_name("index.docker.io/foo"),
            "docker.io/library/foo"
        );
        assert_eq!(docker_hub_name("docker.io/a/foo:1"), "docker.io/a/foo:1");
        assert_eq!(docker_hub_name("quay.io/foo:1"), "quay.io/foo:1");
    }

    fn image_filters(args: &[&str]) -> Filters {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        Filters::of_args(&args).unwrap_or_else(|_| panic!("filters"))
    }

    #[test]
    fn image_filters_of_libimage() {
        let mut r = velarx_proto::workload::ImageRecord {
            id: "abc".into(),
            names: vec!["localhost/a:1".into()],
            digest: "sha256:9999".into(),
            // (made two hours ago)
            created_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) - 7_200_000_000_000,
            ..Default::default()
        };
        let b = Bounds {
            before: None,
            since: None,
        };
        let m = |r: &velarx_proto::workload::ImageRecord, f: &[&str]| {
            let f = image_filters(f);
            check_image_filters(&f).is_ok() && filter_match(&f, r, &b)
        };
        assert!(m(
            &r,
            &["containers=false", "readonly=false", "manifest=false"]
        ));
        assert!(!m(&r, &["containers=true"]));
        assert!(!m(&r, &["readonly=true"]));
        assert!(!m(&r, &["manifest=true"]));
        assert!(!m(&r, &["intermediate=true"]));
        assert!(m(&r, &["digest=sha256:99"]));
        assert!(!m(&r, &["digest=sha256:1"]));
        assert!(m(&r, &["until=1h"]));
        // (a date alone, as libimage reads it)
        assert!(!m(&r, &["until=2020-01-01"]));
        assert!(m(&r, &["until=2200-01-01"]));
        assert!(!m(&r, &["until=3h"]));
        assert!(m(&r, &["reference!=other"]));
        assert!(!m(&r, &["reference!=a"]));
        assert!(!m(&r, &["id!=ab"]));
        r.containers = 1;
        r.read_only = true;
        r.manifest_list = true;
        assert!(m(
            &r,
            &["containers=true", "readonly=true", "manifest=true"]
        ));
        r.names.clear();
        r.has_children = true;
        assert!(m(&r, &["intermediate=true"]));
        assert!(!m(&r, &["dangling=true"]));
        // the words of libimage's errors
        for bad in [
            "dangling=x",
            "containers=x",
            "digest=9",
            "until=x",
            "nosuch=1",
        ] {
            assert!(
                check_image_filters(&image_filters(&[bad])).is_err(),
                "{bad}"
            );
        }
        assert!(check_image_filters(&image_filters(&["dangling=true", "dangling=false"])).is_err());
    }

    #[test]
    fn repository_paths() {
        assert_eq!(repository_path("reg.io:5000/a/B:t"), "a/B");
        assert_eq!(repository_path("noCAPITAL"), "noCAPITAL");
        assert_eq!(repository_path("Reg.IO/a@sha256:x"), "a");
        assert_eq!(repository_path("localhost/x:1"), "x");
    }

    #[test]
    fn reference_filter_narrows_a_tagged_name() {
        let names = || -> Vec<String> {
            ["localhost/a:1", "localhost/a:3", "quay.io/x/y:latest"]
                .map(String::from)
                .to_vec()
        };
        let after = |p: &str| {
            let mut s = names();
            narrow_names(&mut s, p);
            s
        };
        assert_eq!(after("localhost/a:1"), ["localhost/a:1"]);
        assert_eq!(
            after("localhost/a@sha256:00"),
            ["localhost/a:1", "localhost/a:3"]
        );
        for every in ["localhost/a", "a:1", "localhost/*:1", "localhost/a:*"] {
            assert_eq!(after(every), names(), "{every}");
        }
        assert!(fully_qualified("docker.io/alpine:3").is_none());
        assert_eq!(
            fully_qualified("docker.io/library/alpine:3"),
            Some(("docker.io/library/alpine", false))
        );
        assert_eq!(
            fully_qualified("localhost:5000/a/b:c"),
            Some(("localhost:5000/a/b", false))
        );
    }

    #[test]
    fn refused_by_id_of_several_names() {
        let id = "961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4";
        let two = vec!["localhost/a:1".to_string(), "localhost/b:2".to_string()];
        let e = refused_by_id("9617696764", id, &two).unwrap();
        assert_eq!(e.message, format!("unable to delete image \"{id}\" by ID with more than one tag ([localhost/a:1 localhost/b:2]): please force removal"));
        assert!(refused_by_id(&format!("sha256:{id}"), id, &two)
            .unwrap()
            .message
            .contains("by digest"));
        assert!(refused_by_id("9617696764", id, &two[..1]).is_none());
        assert!(refused_by_id("localhost/a:1", id, &two).is_none());
        assert!(refused_by_id("abcdef", id, &two).is_none());
    }

    #[test]
    fn reference_filter() {
        assert!(reference_match("localhost/fltimg:v1", "fltim*"));
        assert!(reference_match("localhost/fltimg:v1", "localhost/fltimg"));
        assert!(reference_match("localhost/fltimg:v1", "fltimg:v1"));
        assert!(reference_match("docker.io/library/alpine:3", "alpine"));
        assert!(!reference_match("localhost/other:v1", "fltim*"));
    }

    #[test]
    fn familiar() {
        assert_eq!(familiar_name("localhost:5000/alpine:x"), "alpine:x");
        assert_eq!(familiar_name("myorg/app"), "myorg/app");
    }

    #[test]
    fn repo_digests() {
        assert_eq!(
            repo_digest("localhost:5000/a:b", "sha256:1"),
            "localhost:5000/a@sha256:1"
        );
        assert_eq!(
            repo_digest("localhost:5000/a", "sha256:1"),
            "localhost:5000/a@sha256:1"
        );
        assert_eq!(repo_digest("a:b", "sha256:1"), "a@sha256:1");
    }

    #[test]
    fn reference_filters_with_a_digest() {
        let d = "sha256:9ed1f7432aed7eaabc9d0852efc1af25878d47590f3cedfcc54f0b88462efcc8";
        let digests = [
            format!("localhost:5000/alpine@{d}"),
            format!("docker.io/library/busybox@{d}"),
        ];
        let m = |want: &str| digest_reference_match(digests.iter().map(String::as_str), want);
        assert!(m(&format!("localhost:5000/alpine@{d}")));
        assert!(m(&format!("alpine@{d}")));
        assert!(m(&format!("localhost:5000/alpine:chunked@{d}")));
        assert!(m(&format!("busybox@{d}")));
        assert!(m(&format!("docker.io/library/busybox@{d}")));
        // not a pattern, and another repository or digest is not it
        assert!(!m(&format!("*@{d}")));
        assert!(!m("localhost:5000/alpine@sha256:9ed1*"));
        assert!(!m(&format!("localhost:5000/other@{d}")));
        assert!(!m("localhost:5000/alpine@sha256:0000"));
        assert!(!m("localhost:5000/alpine"));
        // the names shown are those of the repository
        assert_eq!(
            fully_qualified(&format!("localhost:5000/alpine:chunked@{d}")),
            Some(("localhost:5000/alpine", true))
        );
        assert_eq!(
            fully_qualified(&format!("localhost:5000/alpine@{d}")),
            Some(("localhost:5000/alpine", true))
        );
        assert_eq!(fully_qualified(&format!("alpine@{d}")), None);
    }

    #[test]
    fn display_names() {
        assert_eq!(
            velarx_wire::events::display_repository("library/alpine"),
            "docker.io/library/alpine"
        );
        assert_eq!(
            velarx_wire::events::display_repository("localhost:5000/alpine"),
            "localhost:5000/alpine"
        );
        assert_eq!(
            velarx_wire::events::display_repository("localhost/loaded"),
            "localhost/loaded"
        );
        assert_eq!(
            velarx_wire::events::display_repository("quay.io/a/b"),
            "quay.io/a/b"
        );
        assert_eq!(
            velarx_wire::events::display_repository("myorg/app"),
            "docker.io/myorg/app"
        );
        // a name of a pull by digest, and in the history
        assert_eq!(
            display_digest_name("library/alpine", "sha256:d"),
            "docker.io/library/alpine@sha256:d"
        );
        let history = ImageTag {
            repository: "library/alpine".into(),
            tag: "@sha256:d".into(),
            image_id: String::new(),
        };
        assert_eq!(display_name(&history), "docker.io/library/alpine@sha256:d");
    }
}
