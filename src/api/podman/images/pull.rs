// SPDX-License-Identifier: Apache-2.0
use super::*;
use velarx_proto::workload::EventKind;

/// Docker's `platform`, else libpod's `os`, `arch` and `variant` (the host's
/// for what is not given), as `os/arch[/variant]`.
pub(crate) fn platform_of(
    platform: Option<&str>,
    os: Option<&str>,
    arch: Option<&str>,
    variant: Option<&str>,
) -> Option<String> {
    if let Some(p) = platform.filter(|p| !p.is_empty()) {
        return Some(p.to_string());
    }
    fn some(v: Option<&str>) -> Option<&str> {
        v.filter(|v| !v.is_empty())
    }
    let (os, arch, variant) = (some(os), some(arch), some(variant));
    if os.is_none() && arch.is_none() && variant.is_none() {
        return None;
    }
    let mut p = format!(
        "{}/{}",
        os.unwrap_or("linux"),
        arch.unwrap_or(velarx_registry::target::host_arch())
    );
    if let Some(v) = variant {
        p.push('/');
        p.push_str(v);
    }
    Some(p)
}

/// The record of a progress of a pull (or of a push, a commit, a build):
/// what a blob does, as the interface has it.
pub(crate) fn progress_record(
    p: velarx_core::services::TransferProgress,
) -> velarx_proto::workload::TransferProgress {
    use velarx_core::services::meter::WARNING;
    use velarx_proto::workload::TransferStatus;
    let (status, message) = match p.status.as_str() {
        "downloading" => (TransferStatus::Downloading, String::new()),
        "exists" => (TransferStatus::Exists, String::new()),
        "complete" => (TransferStatus::Complete, String::new()),
        s => match s.strip_prefix(WARNING) {
            Some(text) => (TransferStatus::Warning, text.to_string()),
            None => (TransferStatus::Phase, p.status.clone()),
        },
    };
    velarx_proto::workload::TransferProgress {
        layer: p.subject.to_string(),
        status,
        message,
        current_bytes: p.current_bytes,
        total_bytes: p.total_bytes,
        complete: p.complete,
    }
}

/// Where the credentials of the completion of the lazily pulled image
/// `name` go.
pub(crate) async fn credential_scopes_of(state: &AppState, name: &str) -> ApiResult<Vec<String>> {
    if state.image_service.pulling(name).is_some() {
        return Ok(state.image_service.credential_scopes(name).await?);
    }
    let rec = resolve_image(state, name).await?;
    Ok(state.image_service.credential_scopes(&rec.id).await?)
}

/// Where the credentials of a pull (`push` false: the mirrors and the
/// registry) or a push (the registry) of `reference` go.
pub(crate) fn registry_scopes_of(
    state: &AppState,
    reference: &str,
    push: bool,
) -> ApiResult<Vec<String>> {
    Ok(state
        .image_service
        .reference_credential_scopes(reference, push)?)
}

/// Fetch what the lazily pulled image `name` lacks and prove its layers.
pub(crate) async fn complete_of(
    state: &AppState,
    name: &str,
    access: velarx_registry::auth::RegistryAccess,
) -> ApiResult<velarx_proto::workload::TransferStats> {
    // (the pull in progress that has the name, else the image of the store)
    let id = match state.image_service.pulling(name) {
        Some(entry) => entry.pull.id,
        None => resolve_image(state, name).await?.id,
    };
    let stats = state.image_service.complete_image_with(&id, access).await?;
    Ok(stats_of(&stats))
}

/// The pulls in progress.
pub(crate) async fn pulls_of(state: &AppState) -> ApiResult<velarx_proto::workload::PullsListed> {
    let pulls = state.image_service.pulls().await?;
    Ok(velarx_proto::workload::PullsListed {
        pulls: pulls
            .into_iter()
            .map(|p| velarx_proto::workload::PullListed {
                id: p.id,
                names: p.names,
                state: p.state,
                error: p.error.unwrap_or_default(),
                percent: p.percent,
                bytes_done: p.bytes_done,
                bytes_total: p.bytes_total,
                layers_done: p.layers_done,
                layers_total: p.layers_total,
                containers: p.containers,
                started_at: p.started_at,
            })
            .collect(),
    })
}

/// The record of the statistics of a pull.
pub(crate) fn stats_of(
    s: &velarx_core::services::TransferStats,
) -> velarx_proto::workload::TransferStats {
    velarx_proto::workload::TransferStats {
        by_source: s.by_source.clone(),
        layers_cached: s.layers_cached,
        duration_ms: s.duration_ms,
    }
}

/// The digest of the manifest the registry has for `reference` now (of
/// `platform`, else this host's, for a manifest list).
pub(crate) async fn registry_digest_of(
    state: &AppState,
    reference: &str,
    tls_verify: bool,
    platform: Option<String>,
    access: velarx_registry::auth::RegistryAccess,
) -> ApiResult<String> {
    let reference = registry_name(reference)?;
    let options = PullOptions {
        tls_verify,
        platform,
        access,
        ..PullOptions::default()
    };
    state
        .image_service
        .remote_digest(&reference, &options)
        .await
        .map(|d| d.to_string())
        .map_err(|e| {
            ApiError::of_transfer(&e, "", false)
                .unwrap_or_else(|| ApiError::new(e.registry_status(), e.to_string()))
        })
}

/// What a pull asks.
pub(crate) struct PullArgs {
    /// What to pull: a docker reference, a path (`oci:`, `oci-archive:`,
    /// `docker-archive:`, `dir:`, `archive:`) or a transport's location
    pub source: String,
    /// The path of `source` as the client opened it; none: the engine
    /// opens it (the local routes)
    pub target: Option<PullTarget>,
    /// `source` names an artifact: it goes to the artifact store
    pub artifact: bool,
    /// A short name is Docker Hub's when `[api] compat_api_enforce_docker_hub` says so
    /// (Docker's clients mean it), not of the search registries
    pub docker_hub: bool,
    /// `missing`, `never`, `always`, `newer` (or none: always)
    pub policy: Option<velarx_proto::engine::PullPolicy>,
    pub all_tags: bool,
    /// How a pull that fails on the way is tried again
    pub retry: velarx_proto::retry::Retry,
    pub platform: Option<String>,
    pub tls_verify: bool,
    /// Only the metadata: the files are fetched when they are read
    pub lazy: bool,
    pub access: velarx_registry::auth::RegistryAccess,
    /// The fetchers of the pull, in order; none: `[pull] sources`
    pub sources: Option<Vec<String>>,
}

/// The path of a pull as the client gave it.
pub(crate) enum PullTarget {
    /// A file or a directory it opened
    Fd(std::os::fd::OwnedFd),
    /// The frames of an upload (a pipe): the engine spools them
    Upload(crate::api::ops::ByteStream),
}

/// What a pull did.
pub(crate) struct PullDone {
    /// The images pulled (every tag of `all_tags`, every image of an
    /// archive), by podman's ids, the last the one asked for
    pub images: Vec<velarx_proto::workload::PulledImage>,
    /// Of the last pull
    pub stats: Option<velarx_proto::workload::TransferStats>,
    /// The image of the store was the answer (the policy): nothing pulled
    pub present: bool,
}

/// The `pull-error` event of a pull that failed.
fn pull_error(state: &AppState, reference: &str, msg: &str) {
    state.podman.events.emit(
        Event::new(EventKind::Image, "pull-error", "", reference)
            .attr("name", reference)
            .attr("error", msg),
    );
}

/// Pull what `args` asks, the progress of its blobs told on `progress`
/// (dropped when it is full): with the policy `missing` or `never` an
/// image of the store (or the instance of a manifest list of the store for
/// the platform) is the answer.  A pull that fails is an error with the
/// status the words of the registry give.
pub(crate) async fn pull_images(
    state: &Arc<AppState>,
    args: PullArgs,
    progress: tokio::sync::mpsc::Sender<velarx_core::services::TransferProgress>,
) -> ApiResult<PullDone> {
    let PullArgs {
        source,
        target,
        artifact,
        docker_hub,
        policy,
        all_tags,
        retry,
        platform,
        tls_verify,
        lazy,
        access,
        sources,
    } = args;
    use velarx_proto::engine::PullPolicy;
    // the lazy pulls that have no completer go on
    state.image_service.resume_pulls();
    let origin = velarx_content::origin::Origin::parse(&source)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let reference = match origin {
        velarx_content::origin::Origin::Registry(name) => name,
        // (a path or a transport: the engine asks its origin for the images)
        origin => {
            let options = PullOptions {
                tls_verify,
                platform,
                access,
                sources,
            };
            return pull_origin_of(state, &origin, target, &options, progress).await;
        }
    };
    if artifact {
        let digest =
            super::super::artifacts::pull_of(state, &reference, tls_verify, &access, &retry)
                .await?;
        return Ok(PullDone {
            images: vec![velarx_proto::workload::PulledImage {
                id: digest,
                names: Vec::new(),
            }],
            stats: None,
            present: false,
        });
    }
    // policy=missing: an image already in the store is used as it is
    // policy=never: only that one
    let stored = matches!(
        policy,
        Some(PullPolicy::Missing | PullPolicy::Never | PullPolicy::Newer)
    );
    let mut local = if stored {
        resolve_image(state, &reference).await.ok()
    } else {
        None
    };
    // A manifest list of the store: its instance for the platform.
    if local.is_none() && stored {
        if let Some(list) = state.image_service.manifest_lookup(&reference).await? {
            let wanted = match &platform {
                Some(p) => {
                    velarx_registry::target::Platform::parse(p).map_err(ApiError::bad_request)?
                }
                None => velarx_registry::target::Platform::host(),
            };
            local = state
                .image_service
                .manifest_instance_for(&list, &wanted)
                .await
                .ok();
        }
    }
    // policy=newer: the image of the store, unless the registry serves
    // another (or is not reachable: the one of the store is used)
    if let (Some(rec), Some(PullPolicy::Newer)) = (&local, policy) {
        let options = PullOptions {
            tls_verify,
            platform: platform.clone(),
            access: access.clone(),
            sources: None,
        };
        let remote = state
            .image_service
            .remote_digest(&reference, &options)
            .await;
        if remote.is_ok_and(|d| d != rec.manifest_digest) {
            local = None;
        }
    }
    if let Some(rec) = local {
        return Ok(PullDone {
            images: vec![velarx_proto::workload::PulledImage {
                id: image_id(&rec),
                names: Vec::new(),
            }],
            stats: None,
            present: true,
        });
    }
    if policy == Some(PullPolicy::Never) {
        return Err(ApiError::no_such(
            Kind::Image,
            format!("{reference}: image not known"),
        ));
    }
    // Docker's clients mean Docker Hub by a short name: the search registries
    // and the aliases are not consulted (`[api] compat_api_enforce_docker_hub` can say otherwise)
    let reference = if docker_hub && state.config.api.compat_api_enforce_docker_hub {
        qualify_name(state, false, &reference)
    } else {
        reference
    };
    parse_name(&reference)?;
    let svc = &state.image_service;
    let opts = PullOptions {
        tls_verify,
        platform,
        access,
        sources,
    };
    let pulled = async {
        let refs = if all_tags {
            let tags = svc.repository_tags(&reference, &opts).await?;
            tags.into_iter()
                .map(|t| format!("{reference}:{t}"))
                .collect()
        } else {
            vec![reference.clone()]
        };
        let mut results = Vec::new();
        for one in &refs {
            results.push(
                velarx_core::services::retried(
                    &retry,
                    || svc.pull_with(one, lazy, &opts, progress.clone()),
                    |e, a| {
                        use velarx_core::services::ProgressSink;
                        // (told to whoever pulls, as podman's warning)
                        let note = a.note(&e);
                        tracing::info!("Pull of {one}: {note}");
                        progress.report(velarx_core::services::TransferProgress::warning(&note));
                        async {}
                    },
                )
                .await?,
            );
        }
        Ok::<_, velarx_types::ImageError>(results)
    };
    let results = match pulled.await {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            pull_error(state, &reference, &msg);
            return Err(ApiError::of_transfer(&e, "", false)
                .unwrap_or_else(|| ApiError::new(e.registry_status(), msg)));
        }
    };
    let mut ids: Vec<String> = Vec::new();
    for res in &results {
        // (the store's id is not podman's)
        let id = match svc.get(&res.id).await {
            Ok(rec) => image_id(&rec),
            Err(_) => res.id.clone(),
        };
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    if ids.is_empty() {
        let msg = format!("{reference}: the repository has no tags");
        pull_error(state, &reference, &msg);
        return Err(ApiError::not_found(msg));
    }
    for id in &ids {
        state.podman.events.emit(
            Event::new(EventKind::Image, "pull", id, &reference).attr("name", reference.clone()),
        );
    }
    Ok(PullDone {
        images: ids
            .into_iter()
            .map(|id| velarx_proto::workload::PulledImage {
                id,
                names: Vec::new(),
            })
            .collect(),
        stats: results.last().map(|r| stats_of(&r.stats)),
        present: false,
    })
}

/// Pull the images of the origin `origin` (a path or a transport): the
/// engine spools an upload, opens a path the client did not, and asks the
/// origin for what it has.
async fn pull_origin_of(
    state: &Arc<AppState>,
    origin: &velarx_content::origin::Origin,
    target: Option<PullTarget>,
    options: &PullOptions,
    progress: tokio::sync::mpsc::Sender<velarx_core::services::TransferProgress>,
) -> ApiResult<PullDone> {
    use velarx_content::origin::Origin;
    let fd = match target {
        Some(PullTarget::Fd(fd)) => Some(fd),
        Some(PullTarget::Upload(input)) => {
            let file = crate::api::ops::image::spool(
                &state.image_service,
                input,
                Some(velarx_content::archive::guard::Accept::Compressed),
            )
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::InvalidData => {
                    ApiError::internal(crate::api::ops::image::unknown_format_message(&e))
                }
                _ => ApiError::internal(e.to_string()),
            })?;
            Some(file.into())
        }
        None => {
            if let Origin::Path { path, scheme, .. } = origin {
                if scheme.is_path() {
                    local_path(path, scheme.is_directory())?;
                }
            }
            None
        }
    };
    let loaded = state
        .image_service
        .pull_origin(origin, fd, options, progress)
        .await
        .map_err(|e| match e {
            velarx_types::ImageError::DockerFormat(_) => e.into(),
            e => ApiError::of_transfer(&e, "", false).unwrap_or_else(|| {
                ApiError::new(e.registry_status(), format!("unable to load image: {e}"))
            }),
        })?;
    Ok(PullDone {
        images: super::archive::loaded_images(state, &loaded).await,
        stats: None,
        present: false,
    })
}

/// The path of a pull the engine opens itself (podman's local routes): an
/// absolute one, with no `..`, that exists.
fn local_path(path: &std::path::Path, directory: bool) -> ApiResult<()> {
    if path.as_os_str().is_empty() {
        return Err(ApiError::bad_request("path query parameter is required"));
    }
    if !path.is_absolute()
        || path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(ApiError::bad_request(format!(
            "path {:?} is not an absolute path",
            path.display().to_string()
        )));
    }
    match std::fs::metadata(path) {
        Ok(m) if m.is_dir() == directory => Ok(()),
        Ok(_) => Err(ApiError::bad_request(format!(
            "{:?} is not a {}",
            path.display().to_string(),
            if directory { "directory" } else { "file" }
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ApiError::not_found(format!(
            "file does not exist: {:?}",
            path.display().to_string()
        ))),
        Err(e) => Err(ApiError::internal(format!("failed to access file: {e}"))),
    }
}
