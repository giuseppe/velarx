// SPDX-License-Identifier: Apache-2.0
//! Pulls from an origin that is no registry: a path (`oci:`, `dir:`,
//! `oci-archive:`, `docker-archive:`, `archive:`, `rootfs:`) or the socket of
//! a Docker daemon (`docker-daemon:`), the origin `velarx-dir --origin`, or
//! a transport of `[[transports]]`.  It is a pull like the
//! others: the engine asks the origin for the index of what it has, the
//! manifests and the configurations, checks every digest, and its layers are
//! unpacked by the fetchers into the staging and replayed against the diff
//! ids.  Nothing of an archive is parsed in this process.

use super::archive::{archive_name, archive_tag, qualified_name};
use super::pull::{Incoming, PullNames};
use super::*;
use velarx_content::origin::{transport_of, Origin};
use velarx_content::pull::net::origin::{OriginNet, PathOrigin};
use velarx_content::pull::net::Net;

/// The most descriptors an origin's index may have.
const MAX_INDEX: usize = 4096;

/// Where the layers of a pull from an origin are unpacked.
#[derive(Clone)]
pub(super) enum Via {
    /// `velarx-dir --origin`
    Path(Arc<velarx_content::pull::net::origin::PathOrigin>),
    /// A transport's process, scoped to the location of the pull: its
    /// metadata connection hands out the one of the walker
    Transport { net: OriginNet, scheme: String },
}

impl Via {
    /// The name of the origin: the party of what it answers, and the source
    /// its bytes are counted under.
    pub(super) fn party(&self) -> &str {
        match self {
            Via::Path(_) => "dir",
            Via::Transport { scheme, .. } => scheme,
        }
    }
}

/// The images of an origin's index, by the digest of their manifests, each
/// with its names.
pub(super) fn images_of(index: &[u8]) -> ImageResult<Vec<(Digest, Vec<String>)>> {
    let value: serde_json::Value = serde_json::from_slice(index)
        .map_err(|e| ImageError::Manifest(format!("the index of the origin: {e}")))?;
    let manifests = value
        .get("manifests")
        .and_then(|m| m.as_array())
        .ok_or_else(|| ImageError::Manifest("the index of the origin has no manifests".into()))?;
    if manifests.len() > MAX_INDEX {
        return Err(ImageError::Manifest(format!(
            "the index of the origin has more than {MAX_INDEX} images"
        )));
    }
    let mut images: Vec<(Digest, Vec<String>)> = Vec::new();
    for d in manifests {
        let text = d.get("digest").and_then(|v| v.as_str()).unwrap_or("");
        let digest: Digest = text.parse().map_err(|e| {
            ImageError::Manifest(format!(
                "invalid digest `{}` in the index of the origin: {e}",
                printable(text)
            ))
        })?;
        let name = d
            .get("annotations")
            .and_then(|a| a.get("org.opencontainers.image.ref.name"))
            .and_then(|n| n.as_str())
            .map(str::to_string);
        match images.iter_mut().find(|(known, _)| *known == digest) {
            Some((_, names)) => names.extend(name.filter(|n| !names.contains(n))),
            None => images.push((digest, name.into_iter().collect())),
        }
    }
    if images.is_empty() {
        return Err(ImageError::NotFound("no image in the archive".into()));
    }
    Ok(images)
}

impl ImageService {
    /// Whether the files of a layer are given their fs-verity before they
    /// have a name: the store asks for it and the staging can have it.
    pub(super) fn staging_verity(&self) -> bool {
        self.fsverity != velarx_storage::VerityMode::Off
            && velarx_storage::probe(&self.staging_dir).is_ok()
    }

    /// The names of the helper fetchers of a pull from an origin, in the
    /// order they are asked: `asked` (`--sources`) and nothing else (a
    /// local file is not asked of the peers of the network).
    fn origin_sources(&self, asked: Option<&[String]>) -> ImageResult<Vec<String>> {
        let names: Vec<String> = asked.map(<[String]>::to_vec).unwrap_or_default();
        for (i, name) in names.iter().enumerate() {
            if !self.fetchers.iter().any(|f| f.name == *name) || names[..i].contains(name) {
                return Err(ImageError::Invalid(format!(
                    "the sources {}: `{name}` is not a fetcher of [[sources.external]], or is named twice; a pull of a path or a transport has no `registry`",
                    names.join(",")
                )));
            }
        }
        Ok(names)
    }

    /// The walker of the pull of the image of `manifest` from `via`.
    pub(super) async fn staged_origin(
        &self,
        via: &Via,
        sources: Option<&[String]>,
        manifest: &[u8],
    ) -> ImageResult<Arc<velarx_content::pull::staged_fetch::StagedFetch>> {
        use velarx_content::pull::staged_fetch::StagedFetch;
        let names = self.origin_sources(sources)?;
        let before = self.source_links(&names).await;
        let verity = self.staging_verity();
        let (end, name) = match via {
            Via::Path(path) => (
                (path.connect().await?, self.origin()?.idle()),
                via.party().to_string(),
            ),
            Via::Transport { net, scheme } => ((net.connect().await?, net.idle()), scheme.clone()),
        };
        StagedFetch::open_scoped(before, end, &name, &self.staging_dir, verity, manifest).await
    }

    /// Pull the images of `origin` (a path or a transport; a registry is
    /// pulled by [`ImageService::pull_with`]) into the store, each by the
    /// names it has there: those of an archive, or of the selector of
    /// `oci:DIR:NAME`.  `target`: the path as a descriptor the client opened
    /// (a directory, or the archive's file); none: the engine opens the
    /// path of `origin` as its own user (podman's local routes).
    pub async fn pull_origin(
        &self,
        origin: &Origin,
        target: Option<std::os::fd::OwnedFd>,
        options: &PullOptions,
        progress_tx: mpsc::Sender<TransferProgress>,
    ) -> ImageResult<Vec<LoadedImage>> {
        let platform = options
            .platform
            .as_deref()
            .map(Platform::parse)
            .transpose()
            .map_err(ImageError::Manifest)?;
        let (net, via, transport_name) = match origin {
            Origin::Registry(_) => {
                return Err(ImageError::Invalid(
                    "a registry is pulled by the registry fetcher, not as an origin".into(),
                ))
            }
            Origin::Path { path, scheme, .. } => {
                let fd = match target {
                    Some(fd) => fd,
                    None if !scheme.is_path() => {
                        let socket = self.pull_config.docker_socket.clone();
                        tokio::task::spawn_blocking(move || {
                            std::os::unix::net::UnixStream::connect(&socket).map_err(|e| {
                                ImageError::Io(std::io::Error::new(
                                    e.kind(),
                                    format!(
                                        "cannot connect to the Docker daemon at `{}`: {e}",
                                        socket.display()
                                    ),
                                ))
                            })
                        })
                        .await
                        .map_err(|e| ImageError::Layer(e.to_string()))??
                        .into()
                    }
                    None => {
                        let (path, directory) = (path.clone(), scheme.is_directory());
                        tokio::task::spawn_blocking(move || {
                            let mut open = std::fs::OpenOptions::new();
                            open.read(true);
                            if directory {
                                std::os::unix::fs::OpenOptionsExt::custom_flags(
                                    &mut open,
                                    libc::O_DIRECTORY,
                                );
                            }
                            open.open(&path).map_err(|e| {
                                ImageError::Io(std::io::Error::new(
                                    e.kind(),
                                    format!("cannot open `{}`: {e}", path.display()),
                                ))
                            })
                        })
                        .await
                        .map_err(|e| ImageError::Layer(e.to_string()))??
                        .into()
                    }
                };
                let started = PathOrigin::start(
                    self.origin()?,
                    &origin.source_text(),
                    fd,
                    self.staging_verity(),
                )
                .await?;
                (
                    Net::Origin(OriginNet::of_path(started.clone())),
                    Via::Path(started),
                    None,
                )
            }
            Origin::Transport { scheme, location } => {
                self.check_transport_policy(scheme)?;
                let def = transport_of(&self.transports, scheme)?;
                let access =
                    velarx_content::pull::access::access_for_transport(location, &options.access)?;
                let access = def
                    .credentials
                    .then(|| velarx_content::fetcher::fetch_client::Access::new(&access))
                    .transpose()
                    .map_err(ImageError::Io)?
                    .flatten();
                let net = OriginNet::of_transport(
                    def.reach(),
                    std::time::Duration::from_secs(def.idle_timeout_secs),
                    location.clone(),
                    options.tls_verify,
                )
                .with_access(access)
                .with_verity(self.staging_verity());
                (
                    Net::Origin(net.clone()),
                    Via::Transport {
                        net,
                        scheme: scheme.clone(),
                    },
                    Some(scheme.clone()),
                )
            }
        };
        // What the origin has: the images of a path; the one image a
        // transport's location is.
        let images = match &transport_name {
            // (an index that is not one: the origin's invalid content)
            None => images_of(&net.path_index().await?).map_err(|e| match e {
                ImageError::Manifest(why) => ImageError::transfer_of(
                    "dir",
                    "the index",
                    velarx_proto::transfer::FailureClass::Invalid,
                    why,
                ),
                e => e,
            })?,
            Some(_) => {
                let (_, digest) = net.manifest_top("").await?;
                vec![(digest, Vec::new())]
            }
        };
        let mut loaded = Vec::new();
        for (digest, names) in images {
            let start = std::time::Instant::now();
            let image_ref = ImageReference::parse(&format!("localhost/image@{digest}"))?;
            let (manifest, manifest_digest, manifest_bytes, _) = net
                .manifest_raw(&image_ref, platform.as_ref(), None)
                .await?;
            let (config, config_bytes) = net.config_raw(&manifest.config).await?;
            if let Some(p) = &platform {
                Self::check_platform(&config, p, &progress_tx);
            }
            let image_id = self
                .db
                .image_id_for(&manifest_digest, &manifest_digest)
                .await?;
            let named: Vec<(String, ImageTag)> = names
                .iter()
                .filter_map(|n| archive_tag(&archive_name(n), &image_id))
                .collect();
            let tags: Vec<ImageTag> = named.iter().map(|(_, t)| t.clone()).collect();
            let done = match self
                .already_stored(
                    &manifest_digest,
                    &manifest,
                    PullNames {
                        tags: &tags,
                        digest_names: &[],
                    },
                    None,
                    start,
                )
                .await?
            {
                Some(done) => done,
                None => {
                    let incoming = Incoming {
                        manifest,
                        manifest_bytes,
                        manifest_digest,
                        config,
                        config_bytes,
                        via: Some(via.clone()),
                        made: Vec::new(),
                        registry_ref: None,
                        tags,
                        digest_names: Vec::new(),
                        lazy: false,
                        sources: options.sources.clone(),
                        inline_threshold: options.inline_threshold,
                        reach: Default::default(),
                        seal: false,
                        states: false,
                        hold: None,
                        pulled: Vec::new(),
                        access: None,
                        indexes: Vec::new(),
                        recorded: Vec::new(),
                    };
                    self.install(net.clone(), incoming, progress_tx.clone(), start)
                        .await?
                }
            };
            loaded.push(LoadedImage {
                id: done.id,
                // (with the registry, docker.io too, as podman says it)
                names: named.iter().map(|(_, t)| qualified_name(t)).collect(),
            });
        }
        Ok(loaded)
    }
}
