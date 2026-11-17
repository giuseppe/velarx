// SPDX-License-Identifier: Apache-2.0
use super::*;
use velarx_proto::workload::EventKind;

/// The images an archive loaded, with their load events.
pub(super) async fn loaded_images(
    state: &AppState,
    loaded: &[velarx_core::services::LoadedImage],
) -> Vec<velarx_proto::workload::PulledImage> {
    let mut images = Vec::new();
    for image in loaded {
        // (the store's id is not podman's)
        let id = match resolve_image(state, &image.id).await {
            Ok(rec) => image_id(&rec),
            Err(_) => image.id.clone(),
        };
        state
            .podman
            .events
            .emit(Event::new(EventKind::Image, "load", &id, ""));
        images.push(velarx_proto::workload::PulledImage {
            id,
            names: image.names.clone(),
        });
    }
    images
}

/// What an import asks, decoded from its request.
pub(crate) struct ImportArgs {
    /// A short repository is of Docker Hub when `[api] compat_api_enforce_docker_hub` says so
    pub docker_hub: bool,
    /// Where the tar is, else it is the upload
    pub url: Option<String>,
    pub changes: Vec<String>,
    pub message: Option<String>,
    pub platform: Option<velarx_registry::target::Platform>,
    /// libpod's name of the image
    pub reference: Option<String>,
    /// Docker's repository and tag of it
    pub repo: Option<String>,
    pub tag: Option<String>,
    /// `sha256` or `sha512`: the digests of the image (none: `[build] digest`)
    pub digest: Option<String>,
}

/// Create an image from a tar (`input`, or what `args.url` has): its id.
pub(crate) async fn import_of(
    state: &AppState,
    args: ImportArgs,
    input: crate::api::ops::ByteStream,
) -> ApiResult<String> {
    // libpod's reference, Docker's repo and tag
    let name = match (args.reference.as_deref(), args.repo.as_deref()) {
        (Some(r), _) if !r.is_empty() => Some(r.to_string()),
        (_, Some(repo)) if !repo.is_empty() => {
            let tag = args
                .tag
                .as_deref()
                .filter(|t| !t.is_empty())
                .unwrap_or("latest");
            Some(format!(
                "{}:{tag}",
                qualify_name(state, !args.docker_hub, repo)
            ))
        }
        _ => None,
    };
    let file = match args.url {
        Some(url) => state
            .image_service
            .download(&url)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?,
        None => crate::api::ops::image::spool(
            &state.image_service,
            input,
            Some(velarx_content::archive::guard::Accept::Compressed),
        )
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?,
    };
    let id = state
        .image_service
        .import_tar_for(
            file,
            name.as_deref(),
            &args.changes,
            args.message.as_deref(),
            args.platform.as_ref(),
            args.digest.as_deref(),
        )
        .await?;
    let rec = resolve_image(state, &id).await?;
    state.podman.events.emit(Event::new(
        EventKind::Image,
        "import",
        &image_id(&rec),
        name.as_deref().unwrap_or(""),
    ));
    Ok(image_id(&rec))
}

/// Docker's `platform`, else libpod's `os`, `arch` and `variant` (the host's
/// for what is not given).
pub(crate) fn import_platform_of(
    platform: Option<&str>,
    os: Option<&str>,
    arch: Option<&str>,
    variant: Option<&str>,
) -> ApiResult<Option<velarx_registry::target::Platform>> {
    if let Some(p) = platform.filter(|p| !p.is_empty()) {
        return velarx_registry::target::Platform::parse(p)
            .map(Some)
            .map_err(ApiError::bad_request);
    }
    let (os, arch) = (os.unwrap_or(""), arch.unwrap_or(""));
    if os.is_empty() && arch.is_empty() {
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
