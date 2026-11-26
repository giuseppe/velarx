// SPDX-License-Identifier: Apache-2.0
//! Image pushes.
//!
//! The layers of the store are tar-splits and files, not blobs: a layer is
//! regenerated from them (and checked against its diff id) unless the
//! registry already has the blob the image names, or can mount it from the
//! repository the image was pulled from.  The configuration and the manifest
//! are the bytes that were pulled, so an image that is pushed as it is has
//! the digest it had.

use super::meter::{Meter, Subject};
use super::*;
mod signing;
use std::io::BufWriter;
use tokio::task::JoinSet;
use velarx_content::layer::reproduce::StoredLayer;
use velarx_content::layer::writer::{
    write_canonical_layer, write_layer_level, Compression, Written,
};
use velarx_content::push::staged_push::{Destinations, How, StagedPush};
use velarx_content::pusher::push::{Object, Role};
use velarx_db::BlobSource;

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
/// Check the format of the manifest a push writes (podman push --format):
/// `oci` is the only one, the Docker formats (`docker`, `v2s1`, `v2s2`) are
/// refused.
pub fn check_manifest_format(format: &str) -> ImageResult<()> {
    velarx_types::docker::refuse_format_name(format)?;
    match format {
        "oci" => Ok(()),
        _ => Err(ImageError::Invalid(format!(
            "unknown format {:?}. Choose on of the supported formats: 'oci'",
            velarx_types::printable(format)
        ))),
    }
}

/// How an image is pushed.
#[derive(Debug, Clone)]
pub struct PushOptions {
    pub tls_verify: bool,
    /// Compression of the layers that are regenerated; `None` keeps the one
    /// of each layer.
    pub compression: Option<Compression>,
    /// The level of the layers that are compressed (`None`: the default of
    /// their compression).
    pub compression_level: Option<i32>,
    /// The destination; by default the name of the image.
    pub destination: Option<String>,
    /// Credentials and certificates the client brought.
    pub access: velarx_registry::auth::RegistryAccess,
    /// Push the manifest by its digest, not a tag (an instance of a list).
    pub by_digest: bool,
    /// Where the progress of the blobs goes, if anyone watches.
    pub progress: Option<mpsc::Sender<TransferProgress>>,
    /// Sign the manifest pushed with this key.
    pub sign: Option<Arc<velarx_signature::sign::Signer>>,
    /// The name the signature gives the image, when it is not the
    /// destination (the instances of a list are signed with its name).
    pub sign_identity: Option<String>,
    /// The helper sinks of this push, in the order they are asked
    /// (`--sinks`): names of `[[sinks.external]]`; the destination's own
    /// pusher follows them, added by the engine; none: `[push] sinks`
    pub sinks: Option<Vec<String>>,
    /// The destination is a path the client opened (`oci:`, `dir:`,
    /// `oci-archive:`): `destination` is not used
    pub path: Option<PathPush>,
    /// The destination is of a scheme of `[[transports]]`:
    /// `destination` is not used
    pub transport: Option<TransportPush>,
}

/// A destination of a scheme of `[[transports]]`.
#[derive(Debug, Clone)]
pub struct TransportPush {
    pub scheme: String,
    /// What the user wrote (`SCHEME://...`): what the transport's pusher is
    /// told, and no other
    pub destination: String,
}

impl PushOptions {
    /// The image has no name of a registry at the destination: the pusher
    /// of a path or of a transport names it by what it was given.
    fn off_registry(&self) -> bool {
        self.path.is_some() || self.transport.is_some()
    }
}

/// A destination that is a path: what the client opened, and how it is
/// written ([`velarx_content::dir_push`]).
#[derive(Debug, Clone)]
pub struct PathPush {
    pub mode: velarx_content::dir_push::Mode,
    /// The directory, or the file of an archive, open for writing
    pub dest: Arc<std::os::fd::OwnedFd>,
    /// The names the image has in a layout or an archive (none: no name)
    pub names: Vec<String>,
    /// What the push says it wrote, as the user spelled it
    pub label: String,
}

impl Default for PushOptions {
    fn default() -> Self {
        Self {
            tls_verify: true,
            compression: None,
            compression_level: None,
            destination: None,
            access: Default::default(),
            by_digest: false,
            progress: None,
            sign: None,
            sign_identity: None,
            sinks: None,
            path: None,
            transport: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PushResult {
    /// Digest of the manifest that was pushed, its size and media type.
    pub digest: Digest,
    pub size: u64,
    pub media_type: String,
    pub blobs_uploaded: u64,
    pub blobs_mounted: u64,
    pub blobs_existing: u64,
    /// Layers that were regenerated (their blob was not in the registry).
    pub layers_regenerated: u64,
    /// How the destination resolves the manifest by each name and by its
    /// digest (a registry may take a sha512 manifest by its tag and refuse
    /// it by its digest).
    pub placed: Vec<velarx_proto::transfer::Placed>,
}

/// Put the manifest `body` as `reference` (a tag, or its own digest) by the
/// origin of `staged`: the digest of its bytes, and how the destination
/// resolves it by each name.
pub(super) async fn put_manifest_as(
    staged: &StagedPush,
    reference: &str,
    media_type: &str,
    body: &[u8],
    alg: Algorithm,
) -> ImageResult<(Digest, Vec<velarx_proto::transfer::Placed>)> {
    let (name, alg) = match reference.parse::<Digest>() {
        Ok(named) => {
            let ours = Digest::of(named.alg(), body);
            if ours != named {
                return Err(ImageError::DigestMismatch {
                    expected: named.to_string(),
                    actual: ours.to_string(),
                });
            }
            (None, named.alg())
        }
        Err(_) if reference.is_empty() => (None, alg),
        Err(_) => (Some(reference), alg),
    };
    let names: Vec<String> = name.map(str::to_string).into_iter().collect();
    let reply = staged.put_manifest(media_type, body, alg, &names).await?;
    Ok((Digest::of(alg, body), reply.placed))
}

/// How a blob got to the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Placed {
    Existing,
    Mounted,
    Uploaded,
}

/// A layer as the pushed manifest describes it.
#[derive(Clone)]
struct PushedLayer {
    descriptor: OciDescriptor,
    placed: Placed,
    regenerated: bool,
}

fn manifest_media_type(manifest: &OciManifest) -> &str {
    manifest.media_type.as_deref().unwrap_or(OCI_MANIFEST)
}

/// The repository a layer was pulled from, if it is on `registry` and is not
/// `repository`: a blob can be mounted from there.
fn mount_source(registry_ref: Option<&str>, registry: &str, repository: &str) -> Option<String> {
    let source = ImageReference::parse(registry_ref?).ok()?;
    (source.registry == registry && source.repository != repository).then_some(source.repository)
}

/// The destination's own pusher, the origin of the push: by the scheme of
/// the destination (`docker://` a registry, `oci:`, `dir:` and
/// `oci-archive:` a path, any other scheme the `[[transports]]` that has
/// it).  It is always the last of the pushers, and what the helper sinks of
/// `[push] sinks` are asked before.
pub(super) enum Origin<'a> {
    Registry {
        client: &'a Resolver,
        destination: &'a ImageReference,
        tls_verify: bool,
        access: &'a velarx_registry::auth::RegistryAccess,
    },
    Path(&'a PathPush),
    Transport {
        transport: &'a TransportPush,
        tls_verify: bool,
        access: &'a velarx_registry::auth::RegistryAccess,
    },
}

impl ImageService {
    /// The helper sinks of a push, in the order they are asked: `asked`
    /// (`--sinks`), or `[push] sinks`.  Each is a `[[sinks.external]]`, once;
    /// the destination's own pusher is never one of them: the engine adds it
    /// by the scheme of the destination.
    pub(super) fn helpers_of(&self, asked: Option<&[String]>) -> ImageResult<Vec<String>> {
        let names: Vec<String> = asked
            .map(<[String]>::to_vec)
            .or_else(|| self.push_config.sinks.clone())
            .unwrap_or_default();
        for (i, name) in names.iter().enumerate() {
            if velarx_config::BUILTIN_SINKS.contains(&name.as_str()) {
                return Err(ImageError::Invalid(format!(
                    "the sinks {}: `{name}` is the destination's own pusher, the engine adds it: name helper sinks only",
                    names.join(",")
                )));
            }
            if !self.sinks.iter().any(|f| f.name == *name) || names[..i].contains(name) {
                return Err(ImageError::Invalid(format!(
                    "the sinks {}: `{name}` is not a sink of [[sinks.external]], or is named twice",
                    names.join(",")
                )));
            }
        }
        Ok(names)
    }

    /// Connections to the helper sinks `names`, in their order, each on its
    /// socket.  A sink named by the push (`explicit`) that cannot be reached
    /// is an error; one of `[push] sinks` is left out.
    async fn helper_links(
        &self,
        names: &[String],
        explicit: bool,
    ) -> ImageResult<Vec<velarx_content::push::staged_push::PushLink>> {
        use velarx_content::fetcher::fetch_client::FetchConn;
        use velarx_content::push::staged_push::PushLink;
        let mut links = Vec::new();
        for name in names {
            let Some(def) = self.sinks.iter().find(|f| f.name == *name) else {
                continue;
            };
            match FetchConn::connect_checked(&def.socket).await {
                Ok(conn) => links.push(PushLink {
                    name: name.clone(),
                    conn,
                    credentials: def.credentials,
                    required: explicit,
                    idle: std::time::Duration::from_secs(def.idle_timeout_secs),
                }),
                Err(e) if explicit => {
                    return Err(ImageError::transfer(
                        name.clone(),
                        velarx_proto::transfer::FailureClass::Unavailable,
                        e.to_string(),
                    ))
                }
                Err(e) => debug!("The pusher {name} is left out: {e}"),
            }
        }
        Ok(links)
    }

    /// The pusher of the scheme `scheme` of `[[transports]]`.
    fn transport_of(&self, scheme: &str) -> ImageResult<&velarx_config::TransportConfig> {
        velarx_content::origin::transport_of(&self.transports, scheme)
    }

    /// The walker of a push to `origin`: the helper sinks `names` (none:
    /// `[push] sinks`), each in its own scope in the engine's order, then the
    /// destination's own pusher, which gets the credentials the destination
    /// is given (they go to no other pusher but a helper whose definition
    /// says so).  A helper is told the destination of a registry and of a
    /// transport as the origin is (`registry/repository`, the URL of the
    /// transport: neither is a local path); of a path only its scheme
    /// (`oci:`), never the text of the path.
    pub(super) async fn staged(
        &self,
        origin: Origin<'_>,
        names: Option<&[String]>,
    ) -> ImageResult<Arc<StagedPush>> {
        let helpers = self.helpers_of(names)?;
        let before = self.helper_links(&helpers, names.is_some()).await?;
        let (end, destinations, access, target) = match origin {
            Origin::Registry {
                client,
                destination,
                tls_verify,
                access,
            } => {
                // (the registry fetcher process: nothing of a push is sent by
                // this one)
                let end = self.origin()?.connect().await.map_err(|e| {
                    ImageError::transfer(
                        "registry",
                        velarx_proto::transfer::FailureClass::Transient,
                        e.to_string(),
                    )
                })?;
                let repository = format!("{}/{}", destination.registry, destination.repository);
                let access = velarx_content::pull::access::access_for(
                    client,
                    &repository,
                    tls_verify,
                    access,
                    false,
                )?;
                let access = (!access.is_empty())
                    .then(|| serde_json::to_vec(&access))
                    .transpose()?;
                (
                    end,
                    Destinations {
                        helpers: repository.clone(),
                        origin: repository,
                        tls_verify: Some(tls_verify),
                        external_origin: None,
                    },
                    access,
                    None,
                )
            }
            Origin::Path(path) => {
                let dest = path.dest.try_clone().map_err(ImageError::Io)?;
                let end = self
                    .origin()?
                    .connect_dir_origin(velarx_content::list::Direction::Push)
                    .await
                    .map_err(|e| {
                        ImageError::Io(std::io::Error::other(format!("the directory pusher: {e}")))
                    })?;
                // (the destination is a descriptor, and its name is told to
                // no pusher: the transport is all they hear)
                let scheme = path.mode.scheme().to_string();
                (
                    end,
                    Destinations {
                        helpers: scheme.clone(),
                        origin: scheme,
                        tls_verify: None,
                        external_origin: None,
                    },
                    None,
                    Some(dest),
                )
            }
            Origin::Transport {
                transport,
                tls_verify,
                access,
            } => {
                // (the engine refuses what the client refuses: no userinfo
                // reaches a pusher)
                velarx_types::transport::ImageLocation::external(&transport.destination)
                    .map_err(|e| ImageError::Invalid(e.to_string()))?;
                let def = self.transport_of(&transport.scheme)?;
                let end =
                    velarx_content::fetcher::fetch_client::FetchConn::connect_checked(&def.socket)
                        .await
                        .map_err(|e| {
                            ImageError::transfer(
                                transport.scheme.clone(),
                                velarx_proto::transfer::FailureClass::Unavailable,
                                e.to_string(),
                            )
                        })?;
                let access = if def.credentials {
                    // (the credentials of `SCHEME://AUTHORITY` and nothing
                    // a docker reference may mean, whatever tls_verify)
                    let access = velarx_content::pull::access::access_for_transport(
                        &transport.destination,
                        access,
                    )?;
                    (!access.is_empty())
                        .then(|| serde_json::to_vec(&access))
                        .transpose()?
                } else {
                    None
                };
                (
                    end,
                    Destinations {
                        helpers: transport.destination.clone(),
                        origin: transport.destination.clone(),
                        tls_verify: Some(tls_verify),
                        external_origin: Some((
                            transport.scheme.clone(),
                            std::time::Duration::from_secs(def.idle_timeout_secs),
                        )),
                    },
                    access,
                    None,
                )
            }
        };
        let staged = StagedPush::open(before, end, destinations, access.as_deref(), target).await?;
        debug!("The pushers of the push: {}", staged.sinks().join(", "));
        Ok(staged)
    }

    /// The walker of a push to the registry `destination`.
    pub(super) async fn staged_push(
        &self,
        client: &Resolver,
        destination: &ImageReference,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
        names: Option<&[String]>,
    ) -> ImageResult<Arc<StagedPush>> {
        self.staged(
            Origin::Registry {
                client,
                destination,
                tls_verify,
                access,
            },
            names,
        )
        .await
    }

    pub fn with_push_config(mut self, config: velarx_config::PushConfig) -> Self {
        self.push_config = config;
        self
    }

    pub async fn push_with(
        &self,
        image_ref: &str,
        options: &PushOptions,
    ) -> ImageResult<PushResult> {
        // A manifest list of the store is pushed with its instances
        // (`podman push LIST`), when no image has that name.
        if self.get(image_ref).await.is_err() {
            if let Some(list) = self.manifest_lookup(image_ref).await? {
                let destination = options
                    .transport
                    .as_ref()
                    .map(|t| t.destination.as_str())
                    .or(options.destination.as_deref())
                    .unwrap_or(image_ref);
                let opts = super::manifest::ListPushOptions {
                    all: true,
                    tls_verify: options.tls_verify,
                    access: options.access.clone(),
                    compression: options.compression,
                    compression_level: options.compression_level,
                    sinks: options.sinks.clone(),
                    ..Default::default()
                };
                let (digest, placed) =
                    Box::pin(self.manifest_push_noted(&list.id, destination, &opts)).await?;
                return Ok(PushResult {
                    digest,
                    size: 0,
                    media_type: "application/vnd.oci.image.index.v1+json".into(),
                    blobs_uploaded: 0,
                    blobs_mounted: 0,
                    blobs_existing: 0,
                    layers_regenerated: 0,
                    placed,
                });
            }
        }
        let client = self
            .resolver
            .with_tls_verify(options.tls_verify)
            .with_access(&options.access);
        self.push_with_client(&client, image_ref, options).await
    }

    /// `push --all-tags`: every tag of the repository `repository` names
    /// (its tag, if any, does not count), each to the same tag of the
    /// destination's repository (or its own).  The tags and their digests.
    pub async fn push_all_tags(
        &self,
        repository: &str,
        options: &PushOptions,
    ) -> ImageResult<Vec<(String, Digest)>> {
        let source = ImageReference::parse(repository)?;
        let dest_repo = match &options.destination {
            Some(d) => ImageReference::parse(d)?.name(),
            None => source.name(),
        };
        let mut tags = Vec::new();
        for image in self.list().await? {
            for t in self.db.get_tags_for_image(&image.id).await? {
                if t.repository == source.name() {
                    tags.push(t.tag);
                }
            }
        }
        tags.sort();
        tags.dedup();
        if tags.is_empty() {
            return Err(ImageError::NotFound(format!(
                "no tag of {} to push",
                source.name()
            )));
        }
        let mut out = Vec::new();
        for tag in tags {
            let opts = PushOptions {
                destination: Some(format!("{dest_repo}:{tag}")),
                ..options.clone()
            };
            let r = self
                .push_with(&format!("{}:{tag}", source.name()), &opts)
                .await?;
            // (one warning for each tag whose sha512 manifest the registry
            // refused by its digest, as `push` of one tag says it)
            if let Some(tx) = &options.progress {
                for refused in r.placed.iter().filter(|p| !p.accepted) {
                    let by = refused
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("{dest_repo}@{}", r.digest));
                    tx.report(TransferProgress::warning(&format!(
                        "the destination refused {by}: {}",
                        refused.reason.as_deref().unwrap_or("no reason given")
                    )));
                }
            }
            out.push((tag, r.digest));
        }
        Ok(out)
    }

    /// `options` with what `[push]` says where the push does not: the
    /// compression of the layers that are regenerated and its level.
    fn with_push_defaults(&self, options: &PushOptions) -> ImageResult<PushOptions> {
        let mut options = options.clone();
        if options.compression.is_none() {
            options.compression = self
                .push_config
                .compression
                .as_deref()
                .map(|c| {
                    Compression::parse(c)
                        .ok_or_else(|| ImageError::Invalid(format!("[push] compression: `{c}`")))
                })
                .transpose()?;
        }
        if options.compression_level.is_none() {
            options.compression_level = self.push_config.compression_level;
        }
        Ok(options)
    }

    /// Push with the given registry client.
    pub async fn push_with_client(
        &self,
        client: &Resolver,
        image_ref: &str,
        options: &PushOptions,
    ) -> ImageResult<PushResult> {
        let options = &self.with_push_defaults(options)?;
        if let Some(path) = &options.path {
            if options.sign.is_some() {
                return Err(ImageError::Invalid(
                    "signing is for the images of a registry: not to a path".into(),
                ));
            }
            let staged = self
                .staged(Origin::Path(path), options.sinks.as_deref())
                .await?;
            info!("Pushing image {} to {}", image_ref, path.label);
            let result = self
                .push_staged((&staged, client), image_ref, options, (None, None))
                .await?;
            staged.finish().await?;
            return Ok(result);
        }
        if let Some(transport) = &options.transport {
            if options.sign.is_some() {
                return Err(ImageError::Invalid(
                    "signing is for the images of a registry: not to the transport of a pusher"
                        .into(),
                ));
            }
            let staged = self
                .staged(
                    Origin::Transport {
                        transport,
                        tls_verify: options.tls_verify,
                        access: &options.access,
                    },
                    options.sinks.as_deref(),
                )
                .await?;
            info!(
                "Pushing image {} to {}",
                image_ref,
                velarx_types::transport::ImageLocation::loggable(&transport.destination)
            );
            let result = self
                .push_staged((&staged, client), image_ref, options, (None, None))
                .await?;
            staged.finish().await?;
            return Ok(result);
        }
        let destination =
            ImageReference::parse(options.destination.as_deref().unwrap_or(image_ref))?;
        // (refuses a blocked registry or a name that is not valid)
        client.push_target(&destination)?;
        let signing = match &options.sign {
            Some(signer) => {
                Some(self.signing_for(signer, &destination, options.sign_identity.as_deref())?)
            }
            None => None,
        };
        // The pushers, each in a process of its own.
        let staged = self
            .staged_push(
                client,
                &destination,
                options.tls_verify,
                &options.access,
                options.sinks.as_deref(),
            )
            .await?;
        info!("Pushing image {} to {}", image_ref, destination.full_name());
        let result = self
            .push_staged(
                (&staged, client),
                image_ref,
                options,
                (Some(&destination), signing.as_ref()),
            )
            .await?;
        staged.finish().await?;
        Ok(result)
    }

    /// Write the images `references` to the path of `path` (an archive or a
    /// layout the client opened), each under its names, by one pusher
    /// process: the layers uncompressed, as they are stored.  The images go
    /// in turn; the writer finishes once.
    pub async fn save_images(
        &self,
        references: &[(String, Vec<String>)],
        path: &PathPush,
    ) -> ImageResult<()> {
        // (no other pusher than the path's own: a save writes one file)
        let staged = self.staged(Origin::Path(path), Some(&[])).await?;
        let client = self.resolver.clone();
        for (reference, names) in references {
            let options = PushOptions {
                compression: Some(Compression::None),
                sinks: Some(Vec::new()),
                path: Some(PathPush {
                    names: names.clone(),
                    ..path.clone()
                }),
                ..Default::default()
            };
            let options = self.with_push_defaults(&options)?;
            info!("Saving image {} to {}", reference, path.label);
            self.push_staged((&staged, &client), reference, &options, (None, None))
                .await?;
        }
        staged.finish().await
    }

    /// The push of [`push_with_client`](Self::push_with_client) over the
    /// walker `staged`.
    async fn push_staged(
        &self,
        (staged, client): (&Arc<StagedPush>, &Resolver),
        image_ref: &str,
        options: &PushOptions,
        (destination, signing): (Option<&ImageReference>, Option<&signing::Signing>),
    ) -> ImageResult<PushResult> {
        let image = self.get(image_ref).await?;
        if signing.is_some() {
            Self::check_signable(&image.manifest_digest)?;
        }
        let manifest: OciManifest = serde_json::from_str(&image.manifest)?;
        let config: OciConfig = serde_json::from_str(&image.config)?;
        if manifest.layers.len() != config.rootfs.diff_ids.len() {
            return Err(ImageError::Manifest(format!(
                "the image has {} layers and {} diff ids",
                manifest.layers.len(),
                config.rootfs.diff_ids.len()
            )));
        }

        // the layers the image records, one for each of the manifest
        let records = self.db.get_image_layers(&image.id).await?;
        if records.len() != manifest.layers.len() {
            return Err(ImageError::Manifest(format!(
                "the image has {} layers and its manifest {}",
                records.len(),
                manifest.layers.len()
            )));
        }
        // The layers, a few at a time; the manifest lists them in order.
        let worker = Arc::new(self.push_worker(options.progress.clone()));

        let permits = Arc::new(Semaphore::new(self.push_config.parallel_layers.max(1)));
        let mut tasks: JoinSet<ImageResult<(usize, PushedLayer)>> = JoinSet::new();
        let mut first_use: HashMap<Digest, usize> = HashMap::new();
        for (index, (desc, diff_id)) in manifest
            .layers
            .iter()
            .zip(&config.rootfs.diff_ids)
            .enumerate()
        {
            // A layer the image uses twice is pushed once.
            if *first_use.entry(desc.digest).or_insert(index) != index {
                continue;
            }
            let this = worker.clone();
            let job = LayerPush {
                staged: staged.clone(),
                destination: destination.cloned(),
                desc: desc.clone(),
                record: records[index].clone(),
                diff_id: *diff_id,
                compression: options.compression,
                level: options.compression_level,
            };
            let permits = permits.clone();
            tasks.spawn(async move {
                let _permit = permits
                    .acquire_owned()
                    .await
                    .map_err(|_| ImageError::Layer("the push was cancelled".into()))?;
                let layer = this.push_layer(&job).await?;
                Ok((index, layer))
            });
        }
        let mut layers: Vec<Option<PushedLayer>> =
            (0..manifest.layers.len()).map(|_| None).collect();
        while let Some(joined) = tasks.join_next().await {
            let (index, layer) =
                joined.map_err(|e| ImageError::Layer(format!("push task: {e}")))??;
            layers[index] = Some(layer);
        }
        let mut pushed = Vec::with_capacity(layers.len());
        for (index, desc) in manifest.layers.iter().enumerate() {
            let first = first_use[&desc.digest];
            let layer = layers[first]
                .clone()
                .ok_or_else(|| ImageError::Layer("a layer was not pushed".into()))?;
            pushed.push(if first == index {
                layer
            } else {
                PushedLayer {
                    placed: Placed::Existing,
                    regenerated: false,
                    ..layer
                }
            });
        }
        let layers = pushed;

        // The configuration is pushed as it was pulled.
        let config_bytes = Bytes::from(image.config.clone().into_bytes());
        let config_digest = Digest::of(manifest.config.digest.alg(), &config_bytes);
        let config_known = worker
            .mount_sources(&config_digest, None, destination)
            .await;
        let config_object = worker.object(
            &config_digest,
            config_bytes.len() as u64,
            &manifest.config.media_type,
            Role::Config,
            config_known,
        );
        let placed = worker
            .ensure(
                staged,
                (&config_digest, &config_object),
                Source::Bytes(config_bytes.clone()),
                true,
            )
            .await?;
        worker.settled(&config_digest, placed, config_bytes.len() as u64);
        worker.record(destination, &[config_digest]).await;

        let alg = image.manifest_digest.alg();
        let unchanged = Digest::of(alg, image.manifest.as_bytes()) == image.manifest_digest
            && manifest_media_type(&manifest) == OCI_MANIFEST
            && config_digest == manifest.config.digest
            && layers
                .iter()
                .zip(&manifest.layers)
                .all(|(p, d)| p.descriptor.digest == d.digest);
        let (body, media_type) = if unchanged {
            (
                Bytes::from(image.manifest.clone().into_bytes()),
                manifest_media_type(&manifest).to_string(),
            )
        } else {
            // a manifest made here states its merged EROFS
            let merged = self.merged_erofs_id(&image.id, alg).await?;
            // ... and the EROFS image of each layer: the layers it was
            // pulled or made with, whatever the blobs pushed are (a layer
            // without one is a store to repair, not a manifest without it)
            let mut erofs = Vec::with_capacity(manifest.layers.len());
            for r in &records {
                erofs.push(r.erofs.clone().ok_or_else(|| {
                    ImageError::Storage(format!(
                        "the layer {} has no EROFS image recorded: `velarx system check --repair` makes it",
                        r.key
                    ))
                })?);
            }
            let rebuilt = OciManifest {
                schema_version: 2,
                media_type: Some(OCI_MANIFEST.to_string()),
                config: OciDescriptor {
                    media_type: OCI_CONFIG.to_string(),
                    digest: config_digest,
                    size: config_bytes.len() as i64,
                    annotations: HashMap::new(),
                },
                // (an image pulled in the Docker format is written as OCI)
                layers: layers
                    .iter()
                    .zip(&erofs)
                    .map(|(p, erofs)| {
                        let mut d = p.descriptor.clone();
                        d.media_type = velarx_types::docker::as_oci(&d.media_type).to_string();
                        super::seal::state_layer(&mut d, erofs);
                        d
                    })
                    .collect(),
                annotations: {
                    let mut a = manifest.annotations.clone();
                    if let Some((alg, id)) = merged {
                        a.entry(super::seal::merged_annotation(alg)).or_insert(id);
                    }
                    a
                },
            };
            (
                Bytes::from(serde_json::to_vec(&rebuilt)?),
                OCI_MANIFEST.to_string(),
            )
        };
        let reference = if options.by_digest {
            Digest::of(alg, &body).to_string()
        } else if let Some(transport) = &options.transport {
            // (the name the destination text gives it, if it does)
            velarx_types::transport::ImageLocation::external_name(&transport.destination)
                .unwrap_or_default()
        } else if options.off_registry() {
            // (a path names its image by what it was given: below)
            String::new()
        } else {
            destination
                .and_then(|d| d.digest.map(|d| d.to_string()).or_else(|| d.tag.clone()))
                .unwrap_or_else(|| "latest".to_string())
        };
        let mut result = PushResult {
            digest: image.manifest_digest,
            size: body.len() as u64,
            media_type: media_type.clone(),
            blobs_uploaded: 0,
            blobs_mounted: 0,
            blobs_existing: 0,
            layers_regenerated: 0,
            placed: Vec::new(),
        };
        worker.phase("pushing the manifest");
        // (by a tag, a sha512 manifest is put by its digest too)
        (result.digest, result.placed) = match &options.path {
            Some(path) if !options.by_digest => {
                let reply = staged
                    .put_manifest(&media_type, &body, alg, &path.names)
                    .await?;
                (Digest::of(alg, &body), reply.placed)
            }
            _ => put_manifest_as(staged, &reference, &media_type, &body, alg).await?,
        };
        if let (Some(signing), Some(destination)) = (signing, destination) {
            worker.phase("signing");
            let remote = signing::Remote {
                client,
                staged,
                worker: &worker,
                destination,
                tls_verify: options.tls_verify,
                access: &options.access,
            };
            self.sign_pushed(signing, &remote, result.digest).await?;
        }

        for p in layers.iter().map(|l| l.placed).chain([placed]) {
            match p {
                Placed::Existing => result.blobs_existing += 1,
                Placed::Mounted => result.blobs_mounted += 1,
                Placed::Uploaded => result.blobs_uploaded += 1,
            }
        }
        result.layers_regenerated = layers.iter().filter(|l| l.regenerated).count() as u64;
        info!(
            "Pushed {} as {}: {} uploaded, {} mounted, {} already there",
            image_ref,
            result.digest,
            result.blobs_uploaded,
            result.blobs_mounted,
            result.blobs_existing
        );
        Ok(result)
    }

    /// Copy the manifest `digest` of the registry repository `source` (and
    /// its blobs, mounted when the registry is the same) to the repository
    /// of `dest`, by its digest: an instance of a manifest list that is not
    /// in the store.
    pub(super) async fn copy_remote_manifest(
        &self,
        source: &str,
        digest: &Digest,
        dest: &ImageReference,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
        sinks: Option<&[String]>,
    ) -> ImageResult<()> {
        let client = self
            .resolver
            .with_tls_verify(tls_verify)
            .with_access(access);
        let src_ref = ImageReference::parse(&format!("{source}@{digest}"))?;
        src_ref.validate()?;
        self.check_policy(&src_ref)?;
        // (refuses a blocked registry or a name that is not valid)
        client.push_target(dest)?;
        // Both registries through the fetcher process.
        let src_net = self.inspect_net(&client, &src_ref, tls_verify, access)?;
        let staged = self
            .staged_push(&client, dest, tls_verify, access, sinks)
            .await?;
        let (body, _) = src_net
            .manifest_top(&super::pull::manifest_reference(&src_ref))
            .await?;
        velarx_registry::target::verify_digest(digest, &body)?;
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        if value.get("manifests").is_some() {
            return Err(ImageError::Manifest(format!(
                "{source}@{digest} is an index, not an image"
            )));
        }
        let media_type = value["mediaType"]
            .as_str()
            .unwrap_or(OCI_MANIFEST)
            .to_string();
        // (a manifest is copied as it is, so a Docker one is not written)
        velarx_types::docker::refuse_written_media_type(&media_type)?;
        let manifest: OciManifest = serde_json::from_slice(&body)?;
        let same_registry = src_ref.registry == dest.registry;
        let worker = self.push_worker(None);
        for blob in std::iter::once(&manifest.config).chain(&manifest.layers) {
            let from: Vec<String> = if same_registry && src_ref.repository != dest.repository {
                vec![src_ref.repository.clone()]
            } else {
                Vec::new()
            };
            let object = worker.object(
                &blob.digest,
                blob.size.max(0) as u64,
                &blob.media_type,
                Role::Blob,
                from,
            );
            if worker.find(&staged, &object).await?.is_some() {
                continue;
            }
            // Through a file of the staging area the fetcher writes, measured
            // against the descriptor.
            std::fs::create_dir_all(&self.staging_dir)?;
            let file = tempfile::tempfile_in(&self.staging_dir)?;
            let size = blob.size.max(0) as u64;
            src_net.blob(&blob.digest, size, &file).await?;
            worker
                .ensure(
                    &staged,
                    (&blob.digest, &object),
                    Source::File(Arc::new(file), size),
                    false,
                )
                .await?;
        }
        let (pushed, _) = put_manifest_as(
            &staged,
            &digest.to_string(),
            &media_type,
            &body,
            digest.alg(),
        )
        .await?;
        staged.finish().await?;
        if pushed != *digest {
            return Err(ImageError::DigestMismatch {
                expected: digest.to_string(),
                actual: pushed.to_string(),
            });
        }
        Ok(())
    }

    /// Push the artifact `digest` of the list `list_id` (its blobs, then
    /// its manifest by digest) to the repository of `dest`.
    pub(super) async fn push_artifact(
        &self,
        list_id: &str,
        digest: &Digest,
        dest: &ImageReference,
        opts: &super::ListPushOptions,
    ) -> ImageResult<()> {
        let path = self
            .artifact_blob(list_id, digest)
            .ok_or_else(|| ImageError::NotFound(format!("the artifact {digest} is gone")))?;
        let body = Bytes::from(tokio::fs::read(&path).await?);
        velarx_registry::target::verify_digest(digest, &body)?;
        let manifest: OciManifest = serde_json::from_slice(&body)?;
        let client = self
            .resolver
            .with_tls_verify(opts.tls_verify)
            .with_access(&opts.access);
        // (refuses a blocked registry or a name that is not valid)
        client.push_target(dest)?;
        let staged = self
            .staged_push(
                &client,
                dest,
                opts.tls_verify,
                &opts.access,
                opts.sinks.as_deref(),
            )
            .await?;
        let worker = self.push_worker(None);
        for blob in std::iter::once(&manifest.config).chain(&manifest.layers) {
            let object = worker.object(
                &blob.digest,
                blob.size.max(0) as u64,
                &blob.media_type,
                Role::Blob,
                Vec::new(),
            );
            if worker.find(&staged, &object).await?.is_some() {
                continue;
            }
            let path = self.artifact_blob(list_id, &blob.digest).ok_or_else(|| {
                ImageError::NotFound(format!("the blob {} of the artifact is gone", blob.digest))
            })?;
            let file = std::fs::File::open(&path)?;
            let size = file.metadata()?.len();
            if size != blob.size.max(0) as u64 {
                return Err(ImageError::Layer(format!(
                    "the blob {} has {size} bytes, not {}",
                    blob.digest, blob.size
                )));
            }
            // The registry checks the digest when the upload ends.
            worker
                .ensure(
                    &staged,
                    (&blob.digest, &object),
                    Source::File(Arc::new(file), size),
                    false,
                )
                .await?;
        }
        let (pushed, _) = put_manifest_as(
            &staged,
            &digest.to_string(),
            OCI_MANIFEST,
            &body,
            digest.alg(),
        )
        .await?;
        staged.finish().await?;
        if pushed != *digest {
            return Err(ImageError::DigestMismatch {
                expected: digest.to_string(),
                actual: pushed.to_string(),
            });
        }
        Ok(())
    }

    /// The parts of the service a push task needs.
    pub(super) fn push_worker(
        &self,
        progress: Option<mpsc::Sender<TransferProgress>>,
    ) -> PushWorker {
        PushWorker {
            progress,
            db: self.db.clone(),
            storage: self.storage.clone(),
            objects: Arc::new(self.objects()),
            staging_dir: self.staging_dir.clone(),
            mount: self.push_config.mount,
            skip_existing: self.push_config.skip_existing,
        }
    }
}

/// A layer of the image to push: the registry and what the layer is.
struct LayerPush {
    staged: Arc<StagedPush>,
    destination: Option<ImageReference>,
    desc: OciDescriptor,
    record: velarx_db::LayerRecord,
    diff_id: Digest,
    /// The compression asked for, and the level; the level applies to the
    /// layer's own compression when none is asked.
    compression: Option<Compression>,
    level: Option<i32>,
}

/// Where the bytes of a blob to upload are.
pub(super) enum Source {
    Bytes(Bytes),
    File(Arc<File>, u64),
}

impl Placed {
    fn of(how: How) -> Self {
        match how {
            How::Present => Placed::Existing,
            How::Linked => Placed::Mounted,
            How::Placed => Placed::Uploaded,
        }
    }
}

impl Source {
    fn size(&self) -> u64 {
        match self {
            Source::Bytes(b) => b.len() as u64,
            Source::File(_, size) => *size,
        }
    }
}

pub(super) struct PushWorker {
    progress: Option<mpsc::Sender<TransferProgress>>,
    db: Database,
    storage: Arc<dyn StorageDriver>,
    objects: Arc<dyn velarx_storage::ObjectOpener>,
    staging_dir: PathBuf,
    /// `[push] mount`: the pushers are told where the blobs may be linked from
    mount: bool,
    /// `[push] skip_existing`: they are asked what the destination has before
    /// a layer is regenerated
    skip_existing: bool,
}

impl PushWorker {
    /// The object as the pushers are asked for it: `known_at` are the
    /// repositories known to have it, sent when `[push] mount` says so.
    pub(super) fn object(
        &self,
        digest: &Digest,
        size: u64,
        media_type: &str,
        role: Role,
        known_at: Vec<String>,
    ) -> Object {
        Object {
            digest: digest.to_string(),
            size,
            media_type: media_type.to_string(),
            role,
            known_at: (self.mount && !known_at.is_empty()).then_some(known_at),
        }
    }

    /// Whether the destination has the object (a pusher says it has it, or
    /// linked it from a repository known to have it).  The caller holds the
    /// object told ([`StagedPush::tell`]) and forgets it when it is done.
    async fn probe_told(
        &self,
        staged: &StagedPush,
        object: &Object,
    ) -> ImageResult<Option<Placed>> {
        let found = staged
            .probe(std::slice::from_ref(object))
            .await?
            .remove(0)
            .map(|f| Placed::of(f.how));
        if let Some(placed) = found {
            debug!("Blob {} is in the registry ({placed:?})", object.digest);
        }
        Ok(found)
    }

    /// Whether the destination has the object, and nothing more asked of the
    /// pushers about it (for what is regenerated before it can be placed,
    /// under another digest).
    pub(super) async fn find(
        &self,
        staged: &StagedPush,
        object: &Object,
    ) -> ImageResult<Option<Placed>> {
        self.probe_told(staged, object).await
    }

    /// The destination has the object: what the pushers have of it is asked
    /// first when `probe_first`, and its bytes are sent if nobody has it.
    /// The progress is that of `label`, the blob the image names.
    pub(super) async fn ensure(
        &self,
        staged: &StagedPush,
        (label, object): (&Digest, &Object),
        source: Source,
        probe_first: bool,
    ) -> ImageResult<Placed> {
        self.ensure_told(staged, (label, object), source, probe_first)
            .await
    }

    async fn ensure_told(
        &self,
        staged: &StagedPush,
        (label, object): (&Digest, &Object),
        source: Source,
        probe_first: bool,
    ) -> ImageResult<Placed> {
        if probe_first {
            if let Some(placed) = self.probe_told(staged, object).await? {
                return Ok(placed);
            }
        }
        let size = source.size();
        let meter = std::sync::Mutex::new(Meter::new(
            self.progress.clone(),
            Subject::Digest(*label),
            "uploading",
            size,
        ));
        // the pusher reads the blob from its file
        let file = match &source {
            Source::File(file, _) => file.clone(),
            Source::Bytes(bytes) => Arc::new(std::fs::File::from(
                velarx_base::sealed::sealed_memory(bytes).map_err(ImageError::Io)?,
            )),
        };
        let found = staged
            .put(std::slice::from_ref(object), &[&file], &|_, sent| {
                meter.lock().unwrap_or_else(|e| e.into_inner()).set(sent)
            })
            .await?
            .remove(0);
        Ok(Placed::of(found.how))
    }

    /// The destination has these blobs now: later pushes can link them.
    async fn record(&self, destination: Option<&ImageReference>, digests: &[Digest]) {
        let Some(destination) = destination else {
            return;
        };
        let known: Vec<BlobSource> = digests
            .iter()
            .map(|digest| BlobSource {
                digest: *digest,
                registry: destination.registry.clone(),
                repository: destination.repository.clone(),
            })
            .collect();
        if let Err(e) = self.db.add_blob_sources(known).await {
            debug!("Cannot record where the blobs are: {e}");
        }
    }

    fn report(&self, progress: TransferProgress) {
        if let Some(tx) = &self.progress {
            tx.report(progress);
        }
    }

    /// What the push does now, for the image as a whole.
    fn phase(&self, status: &str) {
        self.report(TransferProgress::phase(status));
    }

    /// The blob `layer` is in the registry, put there or not.
    fn settled(&self, layer: &Digest, placed: Placed, size: u64) {
        let status = match placed {
            Placed::Existing => "exists",
            Placed::Mounted => "mounted",
            Placed::Uploaded => "complete",
        };
        self.report(TransferProgress::blob(
            Subject::Digest(*layer),
            status,
            size,
            size,
            true,
        ));
    }

    /// The repositories of the destination's registry known to have the blob:
    /// where it was fetched from or pushed to, the latest first, then the one
    /// the record of its layer names.
    async fn mount_sources(
        &self,
        digest: &Digest,
        layer: Option<&velarx_db::LayerRecord>,
        destination: Option<&ImageReference>,
    ) -> Vec<String> {
        // (a path is no registry: nothing is linked into it)
        let Some(destination) = destination else {
            return Vec::new();
        };
        let mut from = self
            .db
            .blob_sources(digest, &destination.registry)
            .await
            .unwrap_or_default();
        if let Some(record) = layer {
            from.extend(mount_source(
                record.registry_ref.as_deref(),
                &destination.registry,
                &destination.repository,
            ));
        }
        from.retain(|r| *r != destination.repository);
        let mut seen = std::collections::HashSet::new();
        from.retain(|r| seen.insert(r.clone()));
        from
    }

    /// Push one layer of the image.
    async fn push_layer(&self, job: &LayerPush) -> ImageResult<PushedLayer> {
        let LayerPush {
            staged,
            destination,
            desc,
            record,
            diff_id,
            compression,
            level,
        } = job;
        let (compression, level) = (*compression, *level);
        let stored = velarx_graph::objects::open_layer_expecting(
            self.storage.name(),
            &self.db,
            &record.key,
            diff_id,
        )
        .await
        .map_err(|e| ImageError::Layer(e.to_string()))?;
        if stored.diff_id != *diff_id {
            return Err(ImageError::Layer(format!(
                "layer {}: its diff id is {}, the image says {diff_id}",
                desc.digest, stored.diff_id
            )));
        }
        let mount = self
            .mount_sources(&desc.digest, Some(record), destination.as_ref())
            .await;
        // a layer that has the compression asked is pushed as it is; with
        // none asked, a layer that is not compressed (what a commit or a
        // build makes: compression is made here, once) is pushed
        // zstd:chunked, the others as they are
        let asked = compression;
        let compression = compression.filter(|c| !has_compression(desc, *c));
        let compression = compression.or_else(|| {
            (asked.is_none()
                && Compression::from_media_type(&desc.media_type) == Some(Compression::None))
            .then_some(Compression::ZstdChunked)
        });
        let size = desc.size.max(0) as u64;

        // The destination may have the blob the image names.
        if compression.is_none() && self.skip_existing {
            self.report(TransferProgress::blob(
                Subject::Digest(desc.digest),
                "checking",
                0,
                size,
                false,
            ));
            let object = self.object(&desc.digest, size, &desc.media_type, Role::Layer, mount);
            if let Some(placed) = self.find(staged, &object).await? {
                self.settled(&desc.digest, placed, size);
                self.record(destination.as_ref(), &[desc.digest]).await;
                return Ok(PushedLayer {
                    descriptor: desc.clone(),
                    placed,
                    regenerated: false,
                });
            }
        }

        let compression = match compression {
            Some(c) => c,
            None => Compression::from_media_type(&desc.media_type).ok_or_else(|| {
                ImageError::Layer(format!(
                    "the layer {} has the media type {}, which is not known",
                    desc.digest, desc.media_type
                ))
            })?,
        };
        let (file, written) = self
            .regenerate(&desc.digest, stored, compression, level)
            .await?;
        self.report(TransferProgress::blob(
            Subject::Digest(desc.digest),
            "checking",
            0,
            written.size,
            false,
        ));
        let object = self.object(
            &written.digest,
            written.size,
            written.media_type,
            Role::Layer,
            Vec::new(),
        );
        let placed = self
            .ensure(
                staged,
                (&desc.digest, &object),
                Source::File(Arc::new(file), written.size),
                true,
            )
            .await?;
        self.settled(&desc.digest, placed, written.size);
        self.record(destination.as_ref(), &[written.digest]).await;
        Ok(PushedLayer {
            descriptor: OciDescriptor {
                media_type: written.media_type.to_string(),
                digest: written.digest,
                size: written.size as i64,
                annotations: written.annotations.into_iter().collect(),
            },
            placed,
            regenerated: true,
        })
    }

    /// The blob of a stored layer in a temporary file; its diff id is
    /// checked against the stored one.
    async fn regenerate(
        &self,
        layer: &Digest,
        stored: StoredLayer,
        compression: Compression,
        level: Option<i32>,
    ) -> ImageResult<(File, Written)> {
        let objects = self.objects.clone();
        let staging = self.staging_dir.clone();
        let layer = *layer;
        // (every digest of the new blob is of the algorithm of the diff id
        // it has to reproduce)
        let alg = stored.diff_id.alg();
        let meter = Meter::new(
            self.progress.clone(),
            Subject::Digest(layer),
            "compressing",
            0,
        );
        tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&staging)?;
            let file = tempfile::tempfile_in(&staging)?;
            let out = BufWriter::new(file.try_clone()?);
            let layer_error = |e: std::io::Error| ImageError::Layer(format!("layer {layer}: {e}"));
            // (the stream is hashed once, by the layer writer: its diff id is
            // compared with the stored one below)
            let stream = stored.stream(objects).map_err(layer_error)?;
            let mut stream = super::meter::Counting::new(stream, meter);
            // (a canonical layer is written as one: its zstd:chunked blob has
            // no tar-split)
            let written = if stored.is_canonical() {
                write_canonical_layer(&mut stream, alg, compression, level, out)
            } else {
                write_layer_level(&mut stream, alg, compression, level, out)
            }
            .map_err(layer_error)?;
            stream.finish(false);
            if written.diff_id != stored.diff_id {
                let why = if stored.is_canonical() {
                    ": its table of contents does not describe the canonical tar the image claims"
                } else {
                    ""
                };
                return Err(ImageError::Layer(format!(
                    "layer {layer}: the regenerated layer has the diff id {}, not {}{why}",
                    written.diff_id, stored.diff_id
                )));
            }
            Ok((file, written))
        })
        .await
        .map_err(|e| ImageError::Layer(format!("regeneration task: {e}")))?
    }
}

/// Whether the layer of `desc` has the compression `c` (a zstd layer is
/// zstd:chunked if it has a TOC).
fn has_compression(desc: &OciDescriptor, c: Compression) -> bool {
    Compression::from_media_type(&desc.media_type) == Some(c)
        && (c != Compression::ZstdChunked
            || desc.annotations.contains_key(&format!(
                "{}manifest-checksum",
                velarx_content::layer::writer::ANNOTATION_PREFIX
            )))
}
