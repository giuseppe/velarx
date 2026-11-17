// SPDX-License-Identifier: Apache-2.0
//! Manifest lists on the image service: the typed operations of
//! `org.velarx.Engine` (podman's bodies and documents are velarx-api's).

use super::error::{ApiError, ApiResult};
use super::events::Event;
use velarx_types::{ImageError, ImageResult};

use crate::api::AppState;
use serde_json::Value;
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use velarx_core::services::{AddOptions, ListPushOptions};
use velarx_proto::engine::{InstanceSpec, ManifestArtifactSpec};
use velarx_proto::workload::EventKind;
use velarx_proto::workload::{
    ImagePlatform, ManifestDescriptor, ManifestInstance, ManifestListRecord,
};
use velarx_wire::wire::InstanceOptions;

fn image_error(e: ImageError) -> ApiError {
    match e {
        ImageError::NotFound(m) => ApiError::not_found(m),
        ImageError::Manifest(m)
        | ImageError::Registry(m)
        | ImageError::Unauthorized(m)
        | ImageError::Forbidden(m)
        | ImageError::RegistryNotFound(m) => ApiError::bad_request(m),
        other => ApiError::internal(other.to_string()),
    }
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

/// How the images are instances, as the image service takes it.
pub(crate) fn instance_options(i: InstanceSpec) -> InstanceOptions {
    InstanceOptions {
        annotations: i.annotations,
        arch: non_empty(i.architecture),
        os: non_empty(i.os),
        os_version: non_empty(i.os_version),
        variant: non_empty(i.variant),
        features: i.features,
        os_features: i.os_features,
    }
}

/// How a manifest list is made, but its images.
pub(crate) struct CreateOptions {
    /// A list of the name that is there is added to
    pub amend: bool,
    /// Every instance of the lists of the images
    pub all: bool,
    pub tls_verify: bool,
    /// The annotations of the list
    pub annotations: BTreeMap<String, String>,
    pub instance: InstanceSpec,
    pub subject: Option<String>,
    /// `sha256` or `sha512`: the algorithm of the digest of the list (none:
    /// `[build] digest`)
    pub digest: Option<String>,
}

/// Make the manifest list `name` of `images`: its id.
pub(crate) async fn create_of(
    state: &AppState,
    name: &str,
    images: Vec<String>,
    o: CreateOptions,
    access: velarx_registry::auth::RegistryAccess,
) -> ApiResult<String> {
    if name.is_empty() {
        return Err(ApiError::bad_request("a manifest list needs a name"));
    }
    let add = AddOptions {
        all: o.all,
        tls_verify: o.tls_verify,
        access,
        instance: instance_options(o.instance),
    };
    let svc = &state.image_service;
    let id = svc
        .manifest_create(
            name,
            &images,
            &add,
            &o.annotations,
            o.amend,
            o.digest.as_deref(),
        )
        .await
        .map_err(|e| match e {
            ImageError::Storage(m) => ApiError::conflict(m),
            other => image_error(other),
        })?;
    if let Some(subject) = o.subject.and_then(non_empty) {
        svc.manifest_annotate(
            &id,
            None,
            &InstanceOptions::default(),
            &BTreeMap::new(),
            Some(&subject),
        )
        .await
        .map_err(image_error)?;
    }
    state
        .podman
        .events
        .emit(Event::new(EventKind::Image, "create", &id, name));
    Ok(id)
}

/// The manifest list is there.
pub(crate) async fn exists_of(state: &AppState, name: &str) -> ApiResult<()> {
    match state.image_service.manifest_lookup(name).await? {
        Some(_) => Ok(()),
        None => Err(ApiError::not_found(format!("{name}: manifest not found"))),
    }
}

fn text(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or_default().to_string()
}

fn texts(v: &Value, key: &str) -> Vec<String> {
    v[key]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn annotations(v: &Value) -> BTreeMap<String, String> {
    crate::client::string_map(&v["annotations"])
}

/// A descriptor of OCI's.
pub(crate) fn descriptor(v: &Value) -> ManifestDescriptor {
    ManifestDescriptor {
        media_type: text(v, "mediaType"),
        digest: text(v, "digest"),
        size: v["size"].as_u64().unwrap_or(0),
        artifact_type: text(v, "artifactType"),
        annotations: annotations(v),
        data: text(v, "data"),
    }
}

fn platform(v: &Value) -> ImagePlatform {
    ImagePlatform {
        architecture: text(v, "architecture"),
        os: text(v, "os"),
        os_version: text(v, "os.version"),
        os_features: texts(v, "os.features"),
        variant: text(v, "variant"),
        features: texts(v, "features"),
    }
}

/// The record of an index (or an image manifest) of `id`.
fn list_record(v: &Value, id: String) -> ManifestListRecord {
    let some = |k: &str| v.get(k).filter(|d| d.is_object()).map(descriptor);
    ManifestListRecord {
        id,
        schema_version: v["schemaVersion"].as_i64().unwrap_or(0),
        media_type: text(v, "mediaType"),
        artifact_type: text(v, "artifactType"),
        subject: some("subject"),
        annotations: annotations(v),
        manifests: v["manifests"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|m| ManifestInstance {
                        media_type: text(m, "mediaType"),
                        digest: text(m, "digest"),
                        size: m["size"].as_u64().unwrap_or(0),
                        artifact_type: text(m, "artifactType"),
                        annotations: annotations(m),
                        platform: m.get("platform").filter(|p| p.is_object()).map(platform),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        config: some("config"),
        layers: v["layers"]
            .as_array()
            .map(|a| a.iter().map(descriptor).collect())
            .unwrap_or_default(),
    }
}

/// The manifest list `name` (of the store, else of its registry).
pub(crate) async fn inspect_of(
    state: &AppState,
    name: &str,
    tls_verify: bool,
    access: velarx_registry::auth::RegistryAccess,
) -> ApiResult<ManifestListRecord> {
    let svc = &state.image_service;
    let not_found = |e: ImageError| ApiError::not_found(e.to_string());
    match svc.manifest_lookup(name).await.map_err(not_found)? {
        Some(list) => Ok(list_record(&list.index, list.id)),
        None => {
            let index = svc
                .remote_manifest(name, tls_verify, &access)
                .await
                .map_err(not_found)?;
            Ok(list_record(&index, String::new()))
        }
    }
}

/// Add `images` to the list `name`: its id.
pub(crate) async fn add_images_of(
    state: &AppState,
    name: &str,
    images: Vec<String>,
    all: bool,
    instance: InstanceSpec,
    tls_verify: bool,
    access: velarx_registry::auth::RegistryAccess,
) -> ApiResult<String> {
    let svc = &state.image_service;
    if svc.manifest_lookup(name).await?.is_none() {
        return Err(ApiError::not_found(format!(
            "{name}: no such manifest list"
        )));
    }
    let add = AddOptions {
        all,
        instance: instance_options(instance),
        tls_verify,
        access,
    };
    svc.manifest_add(name, &images, &add)
        .await
        .map_err(image_error)
}

/// Remove the instance `digest` of the list `name`: its id.
pub(crate) async fn remove_instance_of(
    state: &AppState,
    name: &str,
    digest: &str,
) -> ApiResult<String> {
    state
        .image_service
        .manifest_remove_instance(name, digest)
        .await
        .map_err(image_error)
}

/// Annotate an instance of the list `name`, or the list.
pub(crate) async fn annotate_of(
    state: &AppState,
    name: &str,
    instance: Option<&str>,
    spec: InstanceSpec,
    index_annotations: &BTreeMap<String, String>,
    subject: Option<&str>,
) -> ApiResult<String> {
    let svc = &state.image_service;
    if svc.manifest_lookup(name).await?.is_none() {
        return Err(ApiError::not_found(format!(
            "{name}: no such manifest list"
        )));
    }
    svc.manifest_annotate(
        name,
        instance,
        &instance_options(spec),
        index_annotations,
        subject,
    )
    .await
    .map_err(image_error)
}

/// Add an artifact of the files (the descriptors of `files`, one for each
/// title of `spec`) to the list `name`: its digest.
pub(crate) async fn add_artifact_of(
    state: &AppState,
    name: &str,
    spec: ManifestArtifactSpec,
    files: Vec<OwnedFd>,
    tls_verify: bool,
    access: velarx_registry::auth::RegistryAccess,
) -> ApiResult<String> {
    let svc = &state.image_service;
    if svc.manifest_lookup(name).await?.is_none() {
        return Err(ApiError::not_found(format!(
            "{name}: no such manifest list"
        )));
    }
    let opts = velarx_core::services::ArtifactOptions {
        artifact_type: spec.artifact_type,
        config_type: spec.config_type,
        config: spec.config,
        layer_type: spec.layer_type,
        exclude_titles: spec.exclude_titles,
        annotations: spec.annotations,
        subject: spec.subject,
    };
    // (the engine reads each descriptor as a file of its own)
    let paths: Vec<(String, std::path::PathBuf)> = spec
        .titles
        .iter()
        .zip(&files)
        .map(|(title, fd)| (title.clone(), velarx_sys::fd::proc_path(fd)))
        .collect();
    svc.manifest_add_artifact(
        name,
        &paths,
        &opts,
        &instance_options(spec.instance),
        tls_verify,
        &access,
    )
    .await
    .map(|d| d.to_string())
    .map_err(image_error)
}

/// The compression the layers of a push are written with.
pub(crate) fn writer_compression(
    c: velarx_proto::engine::LayerCompression,
) -> velarx_content::layer::writer::Compression {
    use velarx_content::layer::writer::Compression;
    use velarx_proto::engine::LayerCompression;
    match c {
        LayerCompression::Gzip => Compression::Gzip,
        LayerCompression::ZstdChunked => Compression::ZstdChunked,
        LayerCompression::None => Compression::None,
    }
}

/// The options of the push of a list.
pub(crate) fn list_push_options(
    all: bool,
    tls_verify: bool,
    access: velarx_registry::auth::RegistryAccess,
    compression: Option<velarx_proto::engine::LayerCompression>,
    compression_level: Option<i32>,
    add_compression: Vec<velarx_proto::engine::LayerCompression>,
) -> ApiResult<ListPushOptions> {
    use velarx_content::layer::writer::Compression;
    let of = writer_compression;
    let compression = compression.map(of);
    Compression::check_level_of(compression, compression_level).map_err(ApiError::bad_request)?;
    Ok(ListPushOptions {
        all,
        tls_verify,
        access,
        compression,
        compression_level,
        add_compression: add_compression.into_iter().map(of).collect(),
        sign: None,
        sinks: None,
    })
}

/// Push the list `name` to `destination` (without `opts.all`, the instance
/// of this host as an image): the digest, and how the destination resolves
/// it by each name.
pub(crate) async fn push_of(
    state: &AppState,
    name: &str,
    destination: &str,
    opts: &ListPushOptions,
) -> ImageResult<(String, Vec<velarx_proto::transfer::Placed>)> {
    // (a scheme of `[[transports]]`: its pusher takes the text as it is)
    let external = velarx_types::transport::ImageLocation::external(destination)
        .map_err(|e| ImageError::Invalid(e.to_string()))?
        .map(|(scheme, _)| scheme.to_string());
    let dest = match external {
        Some(_) => destination.to_string(),
        None => {
            let dest = super::images::registry_name(destination)
                .map_err(|e| ImageError::Invalid(e.message))?;
            let r = velarx_types::ImageReference::parse(&dest)?;
            r.validate()?;
            dest
        }
    };
    let svc = &state.image_service;
    let list = svc
        .manifest_lookup(name)
        .await?
        .ok_or_else(|| ImageError::NotFound(format!("{name}: no such manifest list")))?;
    let (digest, placed) = if opts.all {
        svc.manifest_push_noted(&list.id, &dest, opts).await
    } else {
        // Without the instances: the one of this host, as an image.
        match svc
            .manifest_instance_for(&list, &velarx_registry::target::Platform::host())
            .await
        {
            Ok(image) => svc
                .push_with(
                    &image.id,
                    &velarx_core::services::PushOptions {
                        tls_verify: opts.tls_verify,
                        compression: opts.compression,
                        destination: external.is_none().then(|| dest.to_string()),
                        transport: external.map(|scheme| velarx_core::services::TransportPush {
                            scheme,
                            destination: dest.to_string(),
                        }),
                        access: opts.access.clone(),
                        sinks: opts.sinks.clone(),
                        ..Default::default()
                    },
                )
                .await
                .map(|r| (r.digest, r.placed)),
            Err(e) => Err(e),
        }
    }?;
    Ok((digest.to_string(), placed))
}

/// Remove the manifest list `name` (its instances stay): its id and names.
pub(crate) async fn remove_of(
    state: &AppState,
    name: &str,
) -> ApiResult<velarx_proto::workload::ManifestRemoved> {
    match state.image_service.manifest_delete(name).await {
        Ok((id, names)) => {
            for n in &names {
                state
                    .podman
                    .events
                    .emit(Event::new(EventKind::Image, "untag", &id, n));
            }
            state.podman.events.emit(Event::new(
                EventKind::Image,
                "remove",
                &id,
                names.first().map_or("", String::as_str),
            ));
            Ok(velarx_proto::workload::ManifestRemoved { id, names })
        }
        Err(ImageError::NotFound(m)) => Err(ApiError::not_found(m)),
        Err(e) => Err(image_error(e)),
    }
}
