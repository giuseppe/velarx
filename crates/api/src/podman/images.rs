// SPDX-License-Identifier: Apache-2.0
//! The images.

use super::call::Call;
use super::error::{ApiError, ApiResult, Kind};
use super::reply;
use super::{route, Route};
use crate::engine::engine_call;
use crate::engine::ImageRemoveOptions;
use serde_json::{json, Value};
use velarx_proto::engine::{CommitSpec, ImportSpec, PlatformSpec, PullPolicy, PullSpec, PushSpec};
use velarx_proto::retry::Retry;
use velarx_proto::workload::{Pulled, Pushed};

/// `GET /images/json`: podman's and Docker's list.
async fn list(call: Call) -> ApiResult {
    let mut filters = call.filters()?;
    // Docker 1.24's `filter`: a reference
    if let Some(f) = call.q("filter").filter(|f| !f.is_empty() && !call.libpod) {
        match filters.0.iter_mut().find(|(k, _)| k == "reference") {
            Some((_, v)) => v.push(f.to_string()),
            None => filters.0.push(("reference".into(), vec![f.to_string()])),
        }
    }
    let all = call.q_bool("all", false)?;
    let shared_size = call.q_bool("shared-size", false)?;
    // the manifest lists are images to libpod, not to Docker
    let images = call.engine.image_list(&filters, all, call.libpod).await?;
    let out: Vec<Value> = images
        .iter()
        .map(|i| {
            if call.libpod {
                velarx_shape::image::libpod_summary(i)
            } else {
                velarx_shape::image::docker_summary(i, call.version, shared_size)
            }
        })
        .collect();
    Ok(reply::json(200, &out))
}

/// `GET /images/{name}/exists`
async fn exists(call: Call) -> ApiResult {
    engine_call!(call.engine, image_exists(call.param(0)))?;
    Ok(reply::empty(204))
}

/// `GET /images/{name}/json`: podman's inspect, Docker's for its API.
async fn inspect(call: Call) -> ApiResult {
    let image = engine_call!(call.engine, image_inspect(call.param(0)))?.image;
    Ok(reply::json(
        200,
        &if call.libpod {
            velarx_shape::image::libpod_inspect(&image)
        } else {
            velarx_shape::image::docker_inspect(&image, call.version)
        },
    ))
}

/// `GET /images/{name}/history`
async fn history(call: Call) -> ApiResult {
    let steps = call.engine.image_history(call.param(0)).await?;
    let out: Vec<Value> = steps
        .iter()
        .map(|h| velarx_shape::image::history(h, !call.libpod))
        .collect();
    Ok(reply::json(200, &out))
}

/// `POST /images/{name}/tag?repo=&tag=`
async fn tag(call: Call) -> ApiResult {
    let repo = call.q("repo").unwrap_or("");
    if repo.is_empty() {
        return Err(ApiError::bad_request("repo parameter cannot be empty"));
    }
    let tag = call.q("tag").filter(|t| !t.is_empty()).unwrap_or("latest");
    engine_call!(
        call.engine,
        image_tag(call.param(0), repo, tag, !call.libpod)
    )?;
    Ok(reply::empty(201))
}

/// `POST /images/{name}/untag?repo=&tag=`
async fn untag(call: Call) -> ApiResult {
    let tag = call.q("tag").filter(|t| !t.is_empty()).unwrap_or("latest");
    let names = match call.q("repo").filter(|r| !r.is_empty()) {
        Some(repo) => vec![format!("{repo}:{tag}")],
        None => Vec::new(),
    };
    engine_call!(call.engine, image_untag(call.param(0), names))?;
    Ok(reply::empty(201))
}

/// `DELETE /images/{name}`: libpod's report, Docker's list.
async fn remove(call: Call) -> ApiResult {
    // (podman's decoders: libpod's reads booleans strictly, the Docker
    // routes' by Docker's words; a parameter that is not read is not checked)
    let force = call.q_flag("force")?;
    let noprune = !call.libpod && call.q_flag("noprune")?;
    let ignore = call.q_flag("ignore")?;
    let manifest_list = call.libpod && call.q_flag("lookupManifest")?;
    let opts = ImageRemoveOptions {
        force,
        // Docker refuses an image a container that runs uses, forced or not
        spare_running: !call.libpod,
        // Docker's noprune; libpod's removal always prunes, as podman's
        noprune,
        // a missing image is not an error with ignore
        ignore,
        manifest_list,
    };
    // (podman's 404, 409 and 500: a refusal of the arguments is a 500)
    let removed = call
        .engine
        .image_remove(call.param(0), opts)
        .await
        .map_err(|e| match e.status.as_u16() {
            400 => e.with_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
            _ => e,
        })?;
    if call.libpod {
        // (Go's omitempty: a list with nothing in it is not in the report)
        let mut report = serde_json::Map::new();
        if !removed.deleted.is_empty() {
            report.insert("Deleted".into(), json!(removed.deleted));
        }
        if !removed.untagged.is_empty() {
            report.insert("Untagged".into(), json!(removed.untagged));
        }
        report.insert("ExitCode".into(), json!(0));
        report.insert("Errors".into(), json!([]));
        return Ok(reply::json(200, &report));
    }
    let mut out: Vec<serde_json::Value> = removed
        .untagged
        .iter()
        .map(|u| serde_json::json!({"Untagged": u}))
        .collect();
    out.extend(
        removed
            .deleted
            .iter()
            .map(|d| serde_json::json!({"Deleted": velarx_shape::id_with_algorithm(d)})),
    );
    Ok(reply::json(200, &out))
}

/// `POST /images/prune`: libpod's report, Docker's.
async fn prune(call: Call) -> ApiResult {
    let filters = call.filters()?;
    let mut all = call
        .q_bool("all", false)
        .map_err(|e| e.with_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR))?;
    // Docker: dangling=false prunes the unused images too
    if filters
        .get("dangling")
        .first()
        .is_some_and(|d| d == "false")
    {
        all = true;
    }
    let build_cache = call.libpod
        && call
            .q_bool("buildcache", false)
            .map_err(|e| e.with_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR))?;
    let pruned = call
        .engine
        .image_prune(all, &filters.image_prune()?)
        .await?;
    // podman's --build-cache: the cache of the builds goes too (the
    // directories of RUN --mount=type=cache with it)
    if build_cache {
        engine_call!(call.engine, build_prune())?;
    }
    if call.libpod {
        let out: Vec<Value> = pruned
            .iter()
            .map(|p| json!({"Id": p.id, "Err": null, "Size": p.size}))
            .collect();
        return Ok(reply::json(200, &out));
    }
    let deleted: Vec<Value> = pruned.iter().map(|p| json!({"Deleted": p.id})).collect();
    let reclaimed = pruned.iter().fold(0u64, |n, p| n.saturating_add(p.size));
    Ok(reply::json(
        200,
        &json!({"ImagesDeleted": deleted, "SpaceReclaimed": reclaimed}),
    ))
}

/// `GET /distribution/{name}/json`: what the registry has for a name.
async fn distribution(call: Call) -> ApiResult {
    let tls_verify = call.q_bool("tlsVerify", true)?;
    let d = engine_call!(call.engine, image_remote_inspect(call.param(0), tls_verify))?;
    Ok(reply::json(200, &velarx_shape::image::distribution(&d)))
}

/// The registries on the loopback are insecure, as for the Docker daemon.
fn loopback_registry(reference: &str) -> bool {
    velarx_base::host::is_loopback_host(reference.split('/').next().unwrap_or(""))
}

/// A duration of the query (Go's syntax), in milliseconds.
pub(super) fn delay_ms(call: &Call, name: &str) -> ApiResult<Option<u64>> {
    match call.q(name).filter(|d| !d.is_empty()) {
        Some(d) => velarx_proto::duration::parse_go_duration(d)
            .map(|d| Some(u64::try_from(d.as_millis()).unwrap_or(u64::MAX)))
            .ok_or_else(|| call.bad_parameter(name)),
        None => Ok(None),
    }
}

/// The attempts of a pull or a push that fails on the way.
fn retries(call: &Call) -> ApiResult<u32> {
    match call.q("retry").filter(|r| !r.is_empty()) {
        Some(r) => r.parse::<u32>().map_err(|_| call.bad_parameter("retry")),
        // (podman's: libimage tries 3 times when the query has no count)
        None => Ok(3),
    }
}

/// Search registries (podman search): `registry/term` searches that
/// registry, a bare term the unqualified-search registries.
async fn search(call: Call) -> ApiResult {
    let term = call.q("term").unwrap_or("").to_string();
    if term.is_empty() {
        return Err(ApiError::bad_request("term parameter cannot be empty"));
    }
    let limit = u32::try_from(call.q_i64("limit", 0)?).unwrap_or(0);
    let filters = call.filters()?;
    let mut list: Vec<String> = Vec::new();
    for (k, values) in &filters.0 {
        // Docker (API 1.45 on) has no automated builds any more.
        if !call.libpod && k == "is-automated" {
            match values.first().map(String::as_str) {
                Some("true") => return Ok(reply::json(200, &json!([]))),
                _ => continue,
            }
        }
        if let Some(v) = values.first() {
            list.push(format!("{k}={v}"));
        }
    }
    // The bindings send the names of their fields in lower case.
    let list_tags = call.q_bool("listTags", false)? || call.q_bool("listtags", false)?;
    let tls_verify = match call.q("tlsVerify") {
        Some(_) => Some(call.q_bool("tlsVerify", true)?),
        None => None,
    };
    let found = call
        .engine
        .image_search(
            &term,
            limit,
            list,
            list_tags,
            tls_verify,
            &call.registry_access()?,
        )
        .await?;
    if !call.libpod && found.is_empty() {
        return Err(ApiError::no_such(
            Kind::Image,
            format!("{term}: image not known"),
        ));
    }
    let ok = |b: bool| if b { "[OK]" } else { "" };
    let out: Vec<Value> = found
        .iter()
        .map(|r| {
            if call.libpod {
                json!({"Index": r.index, "Name": r.name, "Description": r.description,
                       "Stars": r.stars, "Official": ok(r.official),
                       "Automated": ok(r.automated), "Tag": r.tag})
            } else {
                json!({"name": r.name, "description": r.description, "star_count": r.stars,
                       "is_official": r.official, "is_automated": false})
            }
        })
        .collect();
    Ok(reply::json(200, &out))
}

/// libpod's `GET /images/{name}/resolve`: the names a pull would try.
async fn resolve(call: Call) -> ApiResult {
    let names = engine_call!(call.engine, image_resolve(call.param(0)))?.names;
    Ok(reply::json(200, &json!({ "Names": names })))
}

/// libpod's `GET /images/{name}/tree`.
async fn tree(call: Call) -> ApiResult {
    let what_requires = call.q_bool("whatrequires", false)?;
    let tree = engine_call!(call.engine, image_tree(call.param(0)))?.tree;
    let text = velarx_shape::image::tree(&tree, what_requires);
    Ok(reply::json(200, &json!({ "Tree": text })))
}

/// The compression of an image scp, checked as podman's ExecuteTransfer
/// checks it: a known format, a level for it in its range.
fn scp_compression(format: &str, level: Option<&str>) -> Result<(), String> {
    let range = match format {
        "" => None,
        "gzip" => Some(0..=9),
        "zstd" | "zstd:chunked" => Some(1..=20),
        f => return Err(format!("unsupported compression format {f}")),
    };
    match (level, range) {
        (None, _) => Ok(()),
        (Some(_), None) => Err("a compression level needs a compression format".into()),
        (Some(l), Some(r)) => match l.parse::<i32>() {
            Ok(n) if r.contains(&n) => Ok(()),
            _ => Err(format!("invalid compression level {l} for {format}")),
        },
    }
}

/// libpod's `POST /images/scp/{name}`: its query is checked and the image
/// looked up, then refused (no transfer between hosts).
async fn scp(call: Call) -> ApiResult {
    call.q_bool("quiet", false)?;
    let format = call.q("compressionFormat").unwrap_or("");
    let level = call.q("compressionLevel").filter(|l| !l.is_empty());
    if let Err(e) = scp_compression(format, level) {
        return Err(
            ApiError::bad_request(format!("{e}: invalid argument")).with_cause("invalid argument")
        );
    }
    engine_call!(call.engine, image_exists(call.param(0)))?;
    Err(ApiError::not_implemented("image scp is not supported"))
}

/// libpod's `DELETE /images/remove`: a report of the removal of each.
async fn remove_many(call: Call) -> ApiResult {
    let images: Vec<String> = call.q_all("images").iter().map(|s| s.to_string()).collect();
    let (force, ignore, noprune) = (
        call.q_bool("force", false)?,
        call.q_bool("ignore", false)?,
        call.q_bool("noprune", false)?,
    );
    let (all, manifest_list) = (
        call.q_bool("all", false)?,
        call.q_bool("lookupManifest", false)?,
    );
    let r = engine_call!(
        call.engine,
        image_remove_many(images, force, ignore, noprune, all, manifest_list)
    )?;
    // (Go's omitempty for the lists of ids; no errors are `null`)
    let mut report = serde_json::Map::new();
    if !r.deleted.is_empty() {
        report.insert("Deleted".into(), json!(r.deleted));
    }
    if !r.untagged.is_empty() {
        report.insert("Untagged".into(), json!(r.untagged));
    }
    report.insert("ExitCode".into(), json!(r.exit_code));
    report.insert(
        "Errors".into(),
        if r.errors.is_empty() {
            serde_json::Value::Null
        } else {
            json!(r.errors)
        },
    );
    Ok(reply::json(200, &report))
}

/// Save images as an archive: `names`/`references` (and the path) say
/// which, `format` how (`oci-archive`, the default and the only one).
async fn save(call: Call) -> ApiResult {
    // the parameters are checked before the images (podman's 400)
    call.q_bool("compress", false)?;
    let mut images: Vec<String> = ["references", "names"]
        .iter()
        .flat_map(|k| call.q_all(k))
        .map(str::to_string)
        .collect();
    if !call.params.is_empty() {
        images.push(call.param(0).to_string());
    }
    // (an unknown word is podman's 500; Docker's formats are the engine's
    // refusal, a 501)
    match call.q("format").filter(|f| !f.is_empty()) {
        None | Some("oci-archive") => {}
        Some(f @ ("docker-archive" | "docker" | "v2s1" | "v2s2")) => {
            let message = velarx_base::docker::refuse_format_name(f)
                .err()
                .unwrap_or_default();
            return Err(ApiError::new(501, message));
        }
        Some(f) => {
            return Err(ApiError::internal(format!(
                "unsupported image format {f:?}"
            )));
        }
    }
    let archive = call.engine.image_save(images).await?;
    // what podman's WriteResponse says of the archive file it sends
    Ok(reply::with_type(
        200,
        "application/octet; charset=us-ascii",
        archive,
    ))
}

/// Load the images of the archive in the body.
async fn load(mut call: Call) -> ApiResult {
    let body = call.take_body();
    let platform = call.q("platform").map(str::to_string);
    let names = call.engine.image_load(platform.as_deref(), body).await?;
    if call.libpod {
        return Ok(reply::json(200, &json!({ "Names": names })));
    }
    // podman's compat answer: one message with all the names
    Ok(reply::json(
        200,
        &json!({"stream": format!("Loaded image: {}", names.join(","))}),
    ))
}

/// Load the images of an archive on the host of the server (podman's local
/// API, for a client on the same host): an absolute path to a file, which
/// the engine opens.
async fn load_local(call: Call) -> ApiResult {
    let names = call
        .engine
        .image_load_local(call.q("path").unwrap_or(""))
        .await?;
    Ok(reply::json(200, &json!({ "Names": names })))
}

/// Create an image from a tar: the body, or what `url` (libpod) or
/// `fromSrc` (Docker, `-` for the body) has.
async fn import(mut call: Call) -> ApiResult {
    let url = if call.libpod {
        call.q("url")
    } else {
        call.q("fromSrc")
    }
    .filter(|u| !u.is_empty() && *u != "-")
    .map(str::to_string);
    let mut changes = Vec::new();
    for c in call.q_all("changes") {
        if call.libpod {
            // a change each, which may span lines (a shell CMD)
            if !c.trim().is_empty() {
                changes.push(c.trim().to_string());
            }
        } else {
            // Docker sends the changes as one string, a change per line.
            changes.extend(
                c.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string),
            );
        }
    }
    // libpod's OS, Architecture and Variant, Docker's platform
    let platform = if call.libpod {
        PlatformSpec {
            platform: None,
            os: call.q_set("OS"),
            arch: call.q_set("Architecture"),
            variant: call.q_set("Variant"),
        }
    } else {
        PlatformSpec {
            platform: call.q_set("platform"),
            ..Default::default()
        }
    };
    let spec = ImportSpec {
        docker_hub: !call.libpod,
        changes,
        message: call.q("message").map(str::to_string),
        platform,
        reference: call.q("reference").map(str::to_string),
        repo: call.q("repo").map(str::to_string),
        tag: call.q("tag").map(str::to_string),
        url: url.clone(),
        digest: None,
    };
    let body = url.is_none().then(|| call.take_body());
    let id = velarx_shape::id_with_algorithm(&call.engine.image_import(spec, body).await?);
    if !call.libpod {
        return Ok(reply::json(
            200,
            &json!({"status": id, "progress": "", "progressDetail": {}, "id": id}),
        ));
    }
    Ok(reply::json(200, &json!({ "Id": id })))
}

/// `POST /commit`: the changes of a container as a new image.
async fn commit(mut call: Call) -> ApiResult {
    let body = call.json_value().await?;
    let mut changes = Vec::new();
    for c in call.q_all("changes") {
        // Docker sends the changes as one string, a change per line.
        changes.extend(
            c.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string),
        );
    }
    // libpod's stream: the result as a build reports it, the error too
    let stream = call.libpod && call.q_bool("stream", false)?;
    let spec = CommitSpec {
        container: call.q("container").unwrap_or("").to_string(),
        docker_hub: !call.libpod,
        format: call.q("format").map(str::to_string),
        repo: call.q("repo").map(str::to_string),
        tag: call.q("tag").map(str::to_string),
        author: call.q("author").map(str::to_string),
        comment: call.q("comment").map(str::to_string),
        changes,
        // Docker pauses by default, podman does not.
        pause: call.q_bool("pause", !call.libpod)?,
        include_volumes: call.q_bool("include-volumes", false)?,
        squash: call.q_bool("squash", false)?,
        digest: None,
    };
    if spec.container.is_empty() {
        return Err(ApiError::bad_request("missing the container"));
    }
    let id = match call.engine.container_commit(spec, body, stream).await? {
        Ok(id) => id,
        Err(message) => {
            return Ok(reply::json(200, &json!({"error": {"message": message}})));
        }
    };
    if stream {
        return Ok(reply::json(200, &json!({ "stream": id })));
    }
    // podman's compat API answers the id without its algorithm too.
    Ok(reply::json(
        if call.libpod { 200 } else { 201 },
        &json!({ "Id": id }),
    ))
}

/// How long the head of libpod's answer of a pull waits for the pull to
/// show progress (podman's maximalStreamingDelay).
const PULL_HEAD_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// The lines of a body that is written as it goes: what is sent to the
/// sender, until it is dropped; a send to a client that went away is
/// false.
fn lines_body() -> (LineSender, axum::body::Body) {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(16);
    let body = axum::body::Body::from_stream(futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|line| (line, rx))
    }));
    (LineSender(tx), body)
}

struct LineSender(tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>);

impl LineSender {
    /// Send the lines of JSON `lines`: false when the client went away.
    async fn send(&self, lines: Vec<Value>) -> bool {
        for v in lines {
            let mut line = v.to_string().into_bytes();
            line.push(b'\n');
            if self.0.send(Ok(line.into())).await.is_err() {
                return false;
            }
        }
        true
    }
}

/// The answer of a pull that started: `first` what the engine answered
/// before the head, then the rest of its replies, as the lines of `format`.
async fn pull_body(
    out: LineSender,
    mut lines: velarx_shape::transfer::PullLines,
    shown: String,
    first: Vec<Pulled>,
    mut rx: tokio::sync::mpsc::Receiver<ApiResult<Pulled>>,
) {
    // (an image of the store that is the answer pulls nothing)
    let present = first
        .first()
        .is_some_and(|p| p.progress.is_none() && p.present == Some(true));
    if !present && !out.send(lines.start(&shown)).await {
        return;
    }
    let mut first = first.into_iter();
    loop {
        let item = match first.next() {
            Some(p) => Ok(p),
            None => match rx.recv().await {
                Some(item) => item,
                None => Err(ApiError::internal(
                    "the engine ended the pull without an answer",
                )),
            },
        };
        let shown = match item {
            Ok(Pulled {
                progress: Some(p), ..
            }) => {
                if out.send(lines.progress(&p)).await {
                    continue;
                }
                return;
            }
            Ok(done) => lines.end(
                &done
                    .images
                    .unwrap_or_default()
                    .into_iter()
                    .map(|i| i.id)
                    .collect::<Vec<_>>(),
                done.present != Some(true),
            ),
            Err(e) => vec![lines.error(&e.message)],
        };
        out.send(shown).await;
        return;
    }
}

/// A pull of libpod (`compat`: Docker's progress) or Docker's: the head of
/// the answer comes with the first progress of a layer (libpod's after
/// [`PULL_HEAD_DELAY`] without), a pull that fails before is its error
/// (Docker's: the words of the registry alone).
async fn do_pull(call: Call, reference: String, compat: bool) -> ApiResult {
    use velarx_shape::transfer::{registry_error_text, PullFormat, PullLines};
    // (the REST API pulls from a registry, as podman's does: a path or a
    // transport is the command line's)
    velarx_types::transport::ImageLocation::registry(&reference, "the REST API")
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let tls_verify = call.q_bool("tlsVerify", true)? && !(compat && loopback_registry(&reference));
    let quiet = call.q_bool("quiet", false)?;
    // libpod's per-layer report (podman 6)
    let pull_progress = !compat && call.q_bool("pullProgress", false)?;
    if pull_progress && quiet {
        return Err(ApiError::bad_request(
            "'pullProgress' and 'quiet' cannot be used simultaneously",
        ));
    }
    // libpod: every tag of the repository, and the attempts of a pull
    // that fails on the way (not one the registry refuses)
    let all_tags = !compat && call.q_bool("allTags", false)?;
    let tagged = reference.contains('@')
        || reference
            .rsplit('/')
            .next()
            .is_some_and(|l| l.contains(':'));
    if all_tags && tagged {
        return Err(ApiError::bad_request(
            "tag can't be used with --all-tags/-a",
        ));
    }
    let policy = match call.q("policy").filter(|p| !p.is_empty()) {
        Some(p) => Some(
            PullPolicy::of_word(p)
                .ok_or_else(|| ApiError::bad_request(format!("unsupported pull policy {p:?}")))?,
        ),
        None => None,
    };
    let spec = PullSpec {
        source: reference.clone(),
        source_fd: None,
        artifact: false,
        docker_hub: compat,
        policy,
        all_tags,
        retry: Retry {
            count: retries(&call)?,
            delay_ms: delay_ms(&call, "retrydelay")?,
        },
        platform: PlatformSpec {
            platform: call.q_set("platform"),
            os: call.q_set("OS"),
            arch: call.q_set("Arch"),
            variant: call.q_set("Variant"),
        },
        tls_verify,
        lazy: false,
        sources: None,
    };
    let format = if compat {
        PullFormat::Docker
    } else if pull_progress {
        PullFormat::LibpodReport
    } else {
        PullFormat::Libpod
    };
    // podman's compat pull: the words of the registry, alone
    let refused = |e: ApiError| {
        if compat {
            let message = registry_error_text(&e.message).unwrap_or(e.message);
            Ok(reply::json(
                e.status.as_u16(),
                &json!({ "message": message }),
            ))
        } else {
            Err(e)
        }
    };
    let access = call.registry_access()?;
    let mut rx = match call.engine.image_pull(spec, &access).await {
        Ok(rx) => rx,
        Err(e) => return refused(e),
    };
    // As podman, the head waits for the first progress of the pull: a pull
    // that fails before it is answered with the status of the error.
    // libpod's head does not wait for ever: the client gets it after a
    // while; Docker's waits for the progress (podman's CompatPull)
    let deadline = (!compat).then(|| tokio::time::Instant::now() + PULL_HEAD_DELAY);
    let mut first = Vec::new();
    loop {
        let next = match deadline {
            Some(d) => match tokio::time::timeout_at(d, rx.recv()).await {
                Ok(next) => next,
                Err(_) => break,
            },
            None => rx.recv().await,
        };
        match next {
            None => break,
            Some(Err(e)) => return refused(e),
            Some(Ok(p)) => {
                let shows = match &p.progress {
                    Some(progress) => !progress.layer.is_empty(),
                    None => true,
                };
                first.push(p);
                if shows {
                    break;
                }
            }
        }
    }
    let shown = reference
        .strip_prefix("docker://")
        .unwrap_or(&reference)
        .to_string();
    let (out, body) = lines_body();
    tokio::spawn(pull_body(
        out,
        PullLines::new(format, quiet),
        shown,
        first,
        rx,
    ));
    Ok(reply::with_type(200, "application/json", body))
}

/// libpod's `POST /images/pull?reference=`
async fn pull(call: Call) -> ApiResult {
    let reference = call.q("reference").unwrap_or("").to_string();
    if reference.is_empty() {
        return Err(ApiError::bad_request("reference parameter cannot be empty"));
    }
    let compat = call.q_bool("compatMode", false)?;
    if compat && call.q_bool("pullProgress", false)? {
        return Err(ApiError::bad_request(
            "'compatMode' and 'pullProgress' cannot be used simultaneously",
        ));
    }
    do_pull(call, reference, compat).await
}

/// Docker's `POST /images/create`: a pull (`fromImage`), or an import
/// (`fromSrc`).
async fn compat_create(call: Call) -> ApiResult {
    let from = call.q("fromImage").unwrap_or("").to_string();
    let src = call.q("fromSrc").unwrap_or("");
    if !src.is_empty() && from.is_empty() {
        return import(call).await;
    }
    if from.is_empty() {
        return Err(ApiError::bad_request("fromImage parameter cannot be empty"));
    }
    let reference = match call.q("tag").filter(|t| !t.is_empty()) {
        Some(t) if !from.contains('@') => {
            let sep = if velarx_shape::without_algorithm(t) != t {
                '@'
            } else {
                ':'
            };
            format!("{from}{sep}{t}")
        }
        _ => from,
    };
    do_pull(call, reference, true).await
}

/// The answer of a push of Docker's API that failed after the lookup of its
/// image: podman's stream, status 500, with the error as its line.
fn push_failed(message: &str) -> axum::response::Response {
    let line = json!({"errorDetail": {"message": message}, "error": message});
    reply::with_type(500, "application/json", format!("{line}\n").into_bytes())
}

/// `POST /images/{name}/push`: libpod's progress, Docker's answer once it
/// is pushed.
async fn push(call: Call) -> ApiResult {
    let compression_level = match call.q_set("compressionLevel") {
        Some(l) => Some(
            l.parse::<i32>()
                .map_err(|_| ApiError::bad_request(format!("invalid compression level `{l}`")))?,
        ),
        None => None,
    };
    let image = call.param(0).to_string();
    let tag = call.q_set("tag");
    let quiet = call.q_bool("quiet", false)?;
    let spec = PushSpec {
        images: vec![image.clone()],
        tag: tag.clone(),
        destination: call.q_set("destination"),
        platform: PlatformSpec {
            platform: call.q_set("platform"),
            os: call.q_set("os"),
            arch: call.q_set("arch"),
            variant: call.q_set("variant"),
        },
        all: call.q_bool("all", true)?,
        all_tags: false,
        artifact: false,
        add_compression: Vec::new(),
        tls_verify: call.q_bool("tlsVerify", true)?,
        compression: match call.q_set("compressionFormat").as_deref() {
            None | Some("keep") => None,
            Some(c) => Some(
                velarx_proto::engine::LayerCompression::of_word(c)
                    .ok_or_else(|| ApiError::bad_request(format!("invalid compression `{c}`")))?,
            ),
        },
        compression_level,
        retry: Retry {
            count: retries(&call)?,
            delay_ms: delay_ms(&call, "retryDelay")?,
        },
        signing: None,
        format: call
            .q_set("format")
            .as_deref()
            .map(velarx_proto::engine::ManifestFormat::of_word)
            .transpose()
            .map_err(ApiError::bad_request)?,
        sinks: None,
        destination_fd: None,
    };
    let access = call.registry_access()?;
    let mut rx = call.engine.image_push(spec, &access).await?;
    if !call.libpod {
        // Docker's (podman's compat push): done before the head, a push
        // that fails is the error of the answer
        let done = loop {
            match rx.recv().await {
                Some(Ok(Pushed {
                    destination: Some(d),
                    pushed: Some(p),
                    ..
                })) => break (d, p),
                Some(Ok(_)) => continue,
                Some(Err(mut e)) if e.status.as_u16() == 404 => {
                    // podman's lookup before the push: its error document,
                    // of the image of the tag asked (NAME:TAG)
                    let named = match tag.as_deref() {
                        Some(t) if !image.contains('@') => {
                            let slash = image.rfind('/').map_or(0, |i| i + 1);
                            let repo = image[slash..]
                                .rfind(':')
                                .map_or(&image[..], |c| &image[..slash + c]);
                            format!("{repo}:{t}")
                        }
                        _ => image.clone(),
                    };
                    e.message = format!("failed to find image {named}: {named}: image not known");
                    return Err(e.with_cause("image not known"));
                }
                Some(Err(e)) => return Ok(push_failed(&e.message)),
                None => return Err(ApiError::internal("the engine ended the push")),
            }
        };
        let (destination, pushed) = done;
        let tag = tag.unwrap_or_else(|| "latest".to_string());
        let mut body = Vec::new();
        for v in
            velarx_shape::transfer::docker_pushed(&destination, &tag, &pushed.digest, pushed.size)
        {
            body.extend_from_slice(v.to_string().as_bytes());
            body.push(b'\n');
        }
        return Ok(reply::with_type(200, "application/json", body));
    }
    // libpod's: where the push goes is the head, its end in the body
    let destination = loop {
        match rx.recv().await {
            Some(Ok(Pushed {
                destination: Some(d),
                ..
            })) => break d,
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(e),
            None => return Err(ApiError::internal("the engine ended the push")),
        }
    };
    let (out, body) = lines_body();
    tokio::spawn(async move {
        use velarx_shape::transfer::{push_end, push_start};
        if !out.send(push_start(&destination, quiet)).await {
            return;
        }
        let end = loop {
            match rx.recv().await {
                Some(Ok(Pushed {
                    pushed: Some(p), ..
                })) => break push_end(&p.digest, quiet),
                Some(Ok(_)) => continue,
                Some(Err(e)) => break vec![json!({ "error": e.message })],
                None => break vec![json!({"error": "the engine ended the push"})],
            }
        };
        out.send(end).await;
    });
    Ok(reply::with_type(200, "application/json", body))
}

pub(super) static ROUTES: &[Route] = &[
    route!("GET", "/images/search", BOTH, None, search),
    route!("POST", "/images/pull", LIBPOD, Image, pull),
    route!("POST", "/images/create", COMPAT, Image, compat_create),
    route!("POST", "/commit", BOTH, Container, commit),
    route!("POST", "/images/{*}/push", BOTH, Image, push),
    route!("GET", "/images/{*}/tree", LIBPOD, Image, tree),
    route!("GET", "/images/{*}/resolve", LIBPOD, Image, resolve),
    route!("POST", "/images/scp/{*}", LIBPOD, Image, scp),
    route!("DELETE", "/images/remove", LIBPOD, Image, remove_many),
    route!("GET", "/images/get", COMPAT, Image, save),
    route!("GET", "/images/export", LIBPOD, Image, save),
    route!("POST", "/images/load", BOTH, None, load),
    route!("POST", "/local/images/load", LIBPOD, None, load_local),
    route!("POST", "/images/import", LIBPOD, None, import),
    route!("GET", "/images/{*}/get", BOTH, Image, save),
    route!("GET", "/distribution/{*}/json", COMPAT, Image, distribution),
    route!("GET", "/images/json", BOTH, Image, list),
    route!("POST", "/images/prune", BOTH, Image, prune),
    route!("GET", "/images/{*}/history", BOTH, Image, history),
    route!("GET", "/images/{*}/json", BOTH, Image, inspect),
    route!("GET", "/images/{*}/exists", LIBPOD, Image, exists),
    route!("POST", "/images/{*}/tag", BOTH, Image, tag),
    route!("POST", "/images/{*}/untag", LIBPOD, Image, untag),
    route!("DELETE", "/images/{*}", BOTH, Image, remove),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_loopback_is_insecure() {
        assert!(loopback_registry("localhost:5000/app"));
        assert!(loopback_registry("127.0.0.1:5000/app:1"));
        assert!(loopback_registry("[::1]:5000/app"));
        // (names that only begin like the loopback)
        assert!(!loopback_registry("127.evil.example/app"));
        assert!(!loopback_registry("localhost.evil.example:5000/app"));
        assert!(!loopback_registry("docker.io/library/alpine"));
    }
}
