// SPDX-License-Identifier: Apache-2.0
use super::*;
use velarx_proto::workload::{EventKind, PushedImage};

/// Docker's `platform` (JSON), else libpod's `os`, `arch` and `variant` (the
/// host's for what is not given).
pub(crate) fn push_platform_of(
    platform: Option<&str>,
    os: Option<&str>,
    arch: Option<&str>,
    variant: Option<&str>,
) -> ApiResult<Option<velarx_registry::target::Platform>> {
    if let Some(p) = platform.filter(|p| !p.is_empty()) {
        let v: Value = serde_json::from_str(p)
            .map_err(|e| ApiError::bad_request(format!("invalid platform `{p}`: {e}")))?;
        let field = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        return Ok(Some(velarx_registry::target::Platform {
            os: Some(field("os"))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "linux".into()),
            arch: field("architecture"),
            variant: Some(field("variant")).filter(|s| !s.is_empty()),
        }));
    }
    let arch = arch.unwrap_or("");
    let os = os.unwrap_or("");
    if arch.is_empty() && os.is_empty() {
        return Ok(None);
    }
    let host = velarx_registry::target::Platform::host();
    Ok(Some(velarx_registry::target::Platform {
        os: if os.is_empty() {
            host.os
        } else {
            os.to_string()
        },
        arch: if arch.is_empty() {
            host.arch
        } else {
            arch.to_string()
        },
        variant: variant.filter(|v| !v.is_empty()).map(str::to_string),
    }))
}

/// What a push asks.
pub(crate) struct PushArgs {
    /// One image, manifest list or artifact; several only to an archive
    pub images: Vec<String>,
    /// `images` name artifacts
    pub artifact: bool,
    pub tag: Option<String>,
    pub destination: Option<String>,
    /// The instance of a manifest list to push
    pub platform: Option<velarx_registry::target::Platform>,
    /// Every instance of a manifest list
    pub all: bool,
    /// Every tag of the repository of `image`
    pub all_tags: bool,
    pub tls_verify: bool,
    pub access: velarx_registry::auth::RegistryAccess,
    /// None: the layers keep theirs
    pub compression: Option<velarx_proto::engine::LayerCompression>,
    /// The level of the layers compressed in `compression`
    pub compression_level: Option<i32>,
    /// More instances of a manifest list, in these compressions
    pub add_compression: Vec<velarx_proto::engine::LayerCompression>,
    pub retry: velarx_proto::retry::Retry,
    pub format: Option<velarx_proto::engine::ManifestFormat>,
    /// Sign the manifests pushed
    pub sign: Option<velarx_proto::workload::SigningKey>,
    /// The pushers of the push, in the order they are asked
    pub sinks: Option<Vec<String>>,
    /// The destination, when it is a path the client opened: `destination`
    /// is its text
    pub path: Option<std::os::fd::OwnedFd>,
}

/// The push to a path that `destination` (`oci:`, `dir:`, `oci-archive:`)
/// and the descriptor the client opened for it make: the kind of the
/// descriptor is checked, and that a directory can be written to.
fn path_push_of(
    destination: &str,
    fd: std::os::fd::OwnedFd,
) -> ApiResult<velarx_core::services::PathPush> {
    use velarx_content::dir_push::{check_destination, Mode};
    use velarx_types::transport::ImageLocation;
    let location =
        ImageLocation::parse(destination).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let (mode, tag) = match location {
        ImageLocation::OciLayout { tag, .. } => (Mode::Layout, tag),
        ImageLocation::Dir { .. } => (Mode::Dir, None),
        ImageLocation::OciArchive { tag, .. } => (Mode::Archive, tag),
        _ => {
            return Err(ApiError::bad_request(format!(
                "{destination} is not a path the client opened"
            )))
        }
    };
    let file = std::fs::File::from(fd);
    let meta = file
        .metadata()
        .map_err(|e| ApiError::bad_request(format!("{destination}: {e}")))?;
    if meta.is_dir() != mode.is_directory() {
        return Err(ApiError::bad_request(format!(
            "{destination}: the descriptor is not {}",
            if mode.is_directory() {
                "a directory"
            } else {
                "a file"
            }
        )));
    }
    if mode.is_directory() {
        check_destination(&file, mode)
            .map_err(|e| ApiError::bad_request(format!("{destination}: {e}")))?;
    }
    Ok(velarx_core::services::PathPush {
        mode,
        dest: Arc::new(file.into()),
        names: tag.into_iter().collect(),
        label: destination.to_string(),
    })
}

/// The key of a push that signs, loaded (its passphrase is stretched with
/// scrypt, which takes a moment: not on the thread of the engine).
pub(crate) async fn signer_of(
    spec: Option<velarx_proto::workload::SigningKey>,
) -> ApiResult<Option<Arc<velarx_signature::sign::Signer>>> {
    let Some(mut spec) = spec else {
        return Ok(None);
    };
    // (the buffers move: the only copies are wiped on drop)
    let files = velarx_signature::sign::KeyFiles {
        key: std::mem::take(&mut spec.key).into_bytes(),
        passphrase: std::mem::take(&mut spec.passphrase).into_bytes(),
    };
    tokio::task::spawn_blocking(move || velarx_signature::sign::Signer::load(&files))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map(|s| Some(Arc::new(s)))
        .map_err(|e| ApiError::bad_request(format!("the signing key: {e}")))
}

type PushFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<velarx_proto::workload::PushedImage, velarx_types::ImageError>,
            > + Send,
    >,
>;

/// A push made ready: where it goes, and the push.
pub(crate) struct PushJob {
    pub destination: String,
    image_ref: String,
    push: PushFuture,
    /// An artifact: its event is the artifact's
    artifact: bool,
}

/// A push to `to` that failed on the way, told to whoever pushes (podman's
/// warning) before it is tried again.
fn told(
    progress: &tokio::sync::mpsc::Sender<velarx_core::services::TransferProgress>,
    to: &str,
    error: &str,
    at: velarx_core::services::Attempt,
) -> std::future::Ready<()> {
    use velarx_core::services::ProgressSink;
    let note = at.note(error);
    tracing::info!("Push to {to}: {note}");
    progress.report(velarx_core::services::TransferProgress::warning(&note));
    std::future::ready(())
}

/// The push of the artifact `name` to `destination` (its own name without
/// one), tried again as `retry` says.
async fn artifact_job(
    state: &Arc<AppState>,
    name: &str,
    destination: Option<String>,
    tls_verify: bool,
    access: &velarx_registry::auth::RegistryAccess,
    retry: velarx_proto::retry::Retry,
    progress: tokio::sync::mpsc::Sender<velarx_core::services::TransferProgress>,
) -> ApiResult<PushJob> {
    let (artifact, store) = crate::api::podman::artifacts::for_push(state, name).await?;
    let shown = destination.clone().unwrap_or_else(|| artifact.clone());
    let push: PushFuture = {
        let (state, access) = (state.clone(), access.clone());
        let to = shown.clone();
        Box::pin(async move {
            let (digest, placed) = velarx_core::services::retried(
                &retry,
                || {
                    state.image_service.push_oci_artifact(
                        store.clone(),
                        &artifact,
                        destination.as_deref(),
                        tls_verify,
                        &access,
                    )
                },
                |e, a| told(&progress, &to, &e, a),
            )
            .await?;
            Ok(PushedImage {
                digest: digest.to_string(),
                placed,
                ..Default::default()
            })
        })
    };
    Ok(PushJob {
        destination: shown,
        image_ref: name.to_string(),
        push,
        artifact: true,
    })
}

/// The image (or the manifest list) `args` asks to push and where to, the
/// progress of its blobs to be told on `progress`: what is wrong with the
/// request is an error here, before anything is pushed.
pub(crate) async fn push_prepare(
    state: &Arc<AppState>,
    args: PushArgs,
    progress: tokio::sync::mpsc::Sender<velarx_core::services::TransferProgress>,
) -> ApiResult<PushJob> {
    use velarx_proto::workload::PushedTag;
    let PushArgs {
        images,
        artifact,
        tag,
        destination,
        platform,
        all,
        all_tags,
        tls_verify,
        access,
        compression,
        compression_level,
        add_compression,
        retry,
        format,
        sign,
        sinks,
        path,
    } = args;
    // a push is one image, list or artifact; a save (archive) takes several
    let archive_mode = path
        .as_ref()
        .and(destination.as_deref())
        .and_then(|d| velarx_types::transport::ImageLocation::parse(d).ok())
        .and_then(|l| match l {
            velarx_types::transport::ImageLocation::OciLayout { tag, .. }
            | velarx_types::transport::ImageLocation::OciArchive { tag, .. } => Some(tag),
            _ => None,
        });
    let saving = matches!(archive_mode, Some(None));
    if images.is_empty() {
        return Err(ApiError::bad_request("no image to push"));
    }
    if images.len() > 1 && !saving {
        return Err(ApiError::bad_request(
            "several images go only to an archive (oci-archive: or oci: without a tag)",
        ));
    }
    let image = images[0].clone();
    let signer = signer_of(sign).await?;
    if artifact {
        return artifact_job(
            state,
            &image,
            destination,
            tls_verify,
            &access,
            retry,
            progress,
        )
        .await;
    }
    let level = compression_level;
    let list_compression = compression;
    let add_compression_words = add_compression;
    // the layers are written with it
    let compression = compression.map(super::super::manifests::writer_compression);
    velarx_content::layer::writer::Compression::check_level_of(compression, compression_level)
        .map_err(ApiError::bad_request)?;
    // the format of the manifest: oci, the only one written
    if let Some(f) = format {
        let f = f.word();
        velarx_core::services::check_manifest_format(f).map_err(|e| match e {
            velarx_types::ImageError::Invalid(_) => {
                ApiError::bad_request(format!("unsupported manifest type {f:?}"))
            }
            e => e.into(),
        })?;
    }
    // (a scheme of `[[transports]]`: its pusher takes the text as it is)
    let transport = match (&destination, &path) {
        (Some(d), None) => {
            velarx_types::transport::ImageLocation::external(d)?.map(|(scheme, _)| {
                velarx_core::services::TransportPush {
                    scheme: scheme.to_string(),
                    destination: d.clone(),
                }
            })
        }
        _ => None,
    };
    let destination = match (destination, &path, &transport) {
        (Some(d), None, None) => Some(registry_name(&d)?),
        (d, _, _) => d,
    };
    let state = state.clone();
    let options = velarx_core::services::PushOptions {
        tls_verify,
        access: access.clone(),
        compression,
        compression_level,
        progress: Some(progress.clone()),
        sign: signer.clone(),
        sinks: sinks.clone(),
        ..Default::default()
    };
    let landing = match (path, transport) {
        (Some(fd), _) => {
            let text = destination.clone().unwrap_or_default();
            Some((
                velarx_core::services::PushOptions {
                    path: Some(path_push_of(&text, fd)?),
                    ..options.clone()
                },
                text,
            ))
        }
        (None, Some(transport)) => Some((
            velarx_core::services::PushOptions {
                transport: Some(transport.clone()),
                ..options.clone()
            },
            transport.destination,
        )),
        (None, None) => None,
    };
    if let Some((options, text)) = landing {
        if all_tags {
            return Err(ApiError::bad_request(
                "a path or a transport takes one image: not --all-tags",
            ));
        }
        if saving {
            // (a save: every image with its names)
            let mut refs = Vec::new();
            for i in &images {
                resolve_image(&state, i).await?;
                refs.push(i.clone());
            }
            let named = state.image_service.save_names(&refs).await?;
            let path = options.path.clone().expect("a save has its path");
            let image_ref = images.join(",");
            let push: PushFuture = {
                let state = state.clone();
                Box::pin(async move {
                    state.image_service.save_images(&named, &path).await?;
                    Ok(PushedImage::default())
                })
            };
            return Ok(PushJob {
                destination: text,
                image_ref,
                push,
                artifact: false,
            });
        }
        let rec = resolve_image(&state, &image).await?;
        let image_ref = image_id(&rec);
        let push: PushFuture = {
            let state = state.clone();
            Box::pin(async move {
                let r = state.image_service.push_with(&rec.id, &options).await?;
                Ok(PushedImage {
                    digest: r.digest.to_string(),
                    size: r.size,
                    blobs_uploaded: r.blobs_uploaded,
                    blobs_mounted: r.blobs_mounted,
                    blobs_existing: r.blobs_existing,
                    placed: r.placed,
                    tags: Vec::new(),
                })
            })
        };
        return Ok(PushJob {
            destination: text,
            image_ref,
            push,
            artifact: false,
        });
    }
    if all_tags {
        // (a repository: its tags are the images)
        let shown = destination.clone().unwrap_or_else(|| image.clone());
        let image_ref = image.clone();
        let push: PushFuture = {
            let state = state.clone();
            let options = velarx_core::services::PushOptions {
                destination,
                ..options
            };
            Box::pin(async move {
                let pushed = velarx_core::services::retried(
                    &retry,
                    || state.image_service.push_all_tags(&image, &options),
                    |e, a| told(&progress, &image, &e, a),
                )
                .await?;
                Ok(PushedImage {
                    tags: pushed
                        .into_iter()
                        .map(|(tag, digest)| PushedTag {
                            tag,
                            digest: digest.to_string(),
                        })
                        .collect(),
                    ..Default::default()
                })
            })
        };
        return Ok(PushJob {
            destination: shown,
            image_ref,
            push,
            artifact: false,
        });
    }
    let svc = state.image_service.clone();
    // A manifest list: one instance (the platform asked) or all of it.
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
    let list = match svc.manifest_lookup(&named).await? {
        Some(l) => Some(l),
        None => svc.manifest_lookup(&image).await?,
    };
    // (a list pushed whole has no image of its own: its instances may be
    // artifacts)
    let (rec, list_push) = match list {
        Some(list) => match platform {
            Some(platform) => {
                let rec = svc
                    .manifest_instance_for(&list, &platform)
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                (Some(rec), None)
            }
            None => (None, Some(list)),
        },
        // the image of the tag asked, as podman looks up NAME:TAG
        None => (Some(resolve_image(&state, &named).await?), None),
    };
    let destination = match (destination, tag.as_deref()) {
        (Some(d), _) => d,
        (None, Some(t)) if !image.contains('@') => {
            let slash = image.rfind('/').map_or(0, |i| i + 1);
            let repo = image[slash..]
                .rfind(':')
                .map_or(&image[..], |c| &image[..slash + c]);
            format!("{repo}:{t}")
        }
        _ => named.clone(),
    };
    parse_name(&destination)?;
    let mut list_options = super::super::manifests::list_push_options(
        all,
        tls_verify,
        access,
        list_compression,
        level,
        add_compression_words,
    )?;
    list_options.sign = signer;
    list_options.sinks = sinks;
    let image_ref = match (&rec, &list_push) {
        (Some(rec), _) => image_id(rec),
        (None, Some(list)) => list.id.clone(),
        (None, None) => unreachable!("an image or a list"),
    };
    let push: PushFuture = {
        let (state, destination) = (state.clone(), destination.clone());
        Box::pin(async move {
            let options = velarx_core::services::PushOptions {
                destination: Some(destination.clone()),
                ..options
            };
            let to = &destination;
            velarx_core::services::retried(
                &retry,
                || async {
                    if let Some(list) = &list_push {
                        return super::super::manifests::push_of(
                            &state,
                            &list.id,
                            &destination,
                            &list_options,
                        )
                        .await
                        .map(|(digest, placed)| PushedImage {
                            digest,
                            placed,
                            ..Default::default()
                        });
                    }
                    let rec = rec.as_ref().expect("an image without a list");
                    state
                        .image_service
                        .push_with(&rec.id, &options)
                        .await
                        .map(|r| PushedImage {
                            digest: r.digest.to_string(),
                            size: r.size,
                            blobs_uploaded: r.blobs_uploaded,
                            blobs_mounted: r.blobs_mounted,
                            blobs_existing: r.blobs_existing,
                            placed: r.placed,
                            tags: Vec::new(),
                        })
                },
                |e, a| told(&progress, to, &e, a),
            )
            .await
        })
    };
    Ok(PushJob {
        destination,
        image_ref,
        push,
        artifact: false,
    })
}

impl PushJob {
    /// Push: what was pushed (an error has Go's words of TLS).
    pub(crate) async fn run(
        self,
        state: &AppState,
    ) -> ApiResult<velarx_proto::workload::PushedImage> {
        let pushed = self.push.await.map_err(|e| push_error(500, "", &e))?;
        state.podman.events.emit(if self.artifact {
            Event::new(EventKind::Artifact, "push", &pushed.digest, &self.image_ref)
        } else {
            Event::new(EventKind::Image, "push", &self.image_ref, &self.destination)
        });
        Ok(pushed)
    }
}

/// An error of a push, as podman's: `context` before the message of the
/// error, and for a TLS verification failure Go's x509 words as its cause,
/// which clients of podman match.
pub(in crate::api::podman) fn push_error(
    status: u16,
    context: &str,
    err: &velarx_types::ImageError,
) -> ApiError {
    let e = ApiError::of_transfer(err, context, true)
        .unwrap_or_else(|| ApiError::new(status, format!("{context}{err}")));
    match err.tls_error() {
        Some(tls) => e.with_cause(tls.go_words()),
        None => e,
    }
}

/// libpod (podman 5.6): the pull candidates of a name.
/// The repository of an image reference without its registry, its tag
/// or its digest (`a/B` of `reg.io:5000/a/B:t`).
pub(super) fn repository_path(name: &str) -> &str {
    let name = name.split('@').next().unwrap_or(name);
    let name = match name.split_once('/') {
        Some((first, rest)) if velarx_base::reference::is_registry_domain(first) => rest,
        _ => name,
    };
    let last = name.rfind('/').map_or(0, |i| i + 1);
    match name[last..].find(':') {
        Some(c) => &name[..last + c],
        None => name,
    }
}
