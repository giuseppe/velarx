// SPDX-License-Identifier: Apache-2.0
//! The registry reached through the registry fetcher (`velarx-registry`):
//! this process holds no credentials for it and makes no request.
//!
//! A pull's metadata (manifests and small blobs) comes with `GetManifest` and
//! `GetBlob` on a connection scoped to its repository (`Open`), the calls of
//! `org.velarx.Registry` (tags, search, login, download) on a connection of
//! their own.
//! Everything the fetcher sends is untrusted: the callers check the digests.

use crate::fetcher::fetch::{Blob, FetcherError};
use crate::fetcher::fetch_client::{Access, CallError, FetchConn, Scoping};
use crate::fetcher::proto::{Hit, RegistryError, Remote};
use crate::list::RegistryOrigin;
use bytes::Bytes;
use std::sync::Arc;
use velarx_proto::transfer::FailureClass;
use velarx_registry::target::MAX_MANIFEST_SIZE;
use velarx_types::digest::Digest;
use velarx_types::{ImageError, ImageResult};

/// The party of the origin of a pull: the registry fetcher.
const REGISTRY: &str = "registry";

/// The process of the origin of a path (`velarx-dir --origin`) and the
/// connection that holds its scope: the metadata comes on a connection it
/// hands out (`Connect`), and so do the layers.
pub struct PathOrigin {
    scoped: tokio::sync::Mutex<FetchConn>,
}

impl PathOrigin {
    /// Start the origin process of `source` (the scheme and the selector,
    /// `Origin::source_text`) and give it `target`, the path as a
    /// descriptor the client opened.
    pub async fn start(
        origin: &RegistryOrigin,
        source: &str,
        target: std::os::fd::OwnedFd,
        verity: bool,
    ) -> ImageResult<Arc<Self>> {
        let party = "dir";
        let mut conn = origin
            .connect_dir_origin(crate::list::Direction::Pull)
            .await
            .map_err(|e| {
                ImageError::transfer(
                    party,
                    FailureClass::Transient,
                    format!("the directory origin: {e}"),
                )
            })?;
        let info = conn
            .get_info()
            .await
            .map_err(|e| image_error_of(party, e))?;
        if !info.can("origin") {
            return Err(ImageError::transfer(
                party,
                FailureClass::Failed,
                "the process is no origin",
            ));
        }
        conn.open(Scoping {
            verity,
            source: Some(source),
            tls_verify: None,
            target: Some(target),
            access: None,
            idle: crate::pull::staged_fetch::REGISTRY_IDLE,
            requires: &["metadata".to_string()],
        })
        .await
        .map_err(|e| image_error_of(party, e))?;
        Ok(Arc::new(Self {
            scoped: tokio::sync::Mutex::new(conn),
        }))
    }

    /// Another connection with the scope of the origin.
    pub async fn connect(&self) -> ImageResult<FetchConn> {
        self.scoped
            .lock()
            .await
            .connect()
            .await
            .map_err(|e| image_error_of("dir", e))
    }
}

/// What the registry fetcher answered, as an error of the image.
pub(super) fn image_error(e: CallError) -> ImageError {
    image_error_of(REGISTRY, e)
}

/// What the fetcher `party` answered, as an error of the image.
pub fn image_error_of(party: &str, e: CallError) -> ImageError {
    // (what the origin of a path refuses by name: a Docker format)
    if let (true, CallError::Fetcher(FetcherError::NotSupported { feature })) = (party == "dir", &e)
    {
        return ImageError::DockerFormat(feature.clone());
    }
    let (class, reason) = match e {
        CallError::Fetcher(FetcherError::Failed { failure })
        | CallError::Registry(RegistryError::Failed { failure }) => (failure.class, failure.reason),
        e => (FailureClass::Transient, e.to_string()),
    };
    ImageError::transfer(party, class, reason)
}

/// Whether the registry says it does not have the item.
fn absent(e: &CallError) -> bool {
    let failure = match e {
        CallError::Fetcher(FetcherError::Failed { failure })
        | CallError::Registry(RegistryError::Failed { failure }) => failure,
        _ => return false,
    };
    matches!(
        failure.class,
        FailureClass::Unavailable | FailureClass::NotFound
    )
}

/// The bytes of the sealed memory file `file` that `party` answered for
/// `name`: at most `max`, and sealed.
fn sealed_bytes(party: &str, file: &std::fs::File, max: u64, name: &str) -> ImageResult<Vec<u8>> {
    velarx_base::sealed::read_sealed_whole(file, max).map_err(|what| {
        ImageError::transfer_of(
            party,
            name,
            FailureClass::Invalid,
            format!("the item {what}"),
        )
    })
}

/// Which process answers the metadata calls of a pull.
#[derive(Clone)]
enum Via {
    /// The registry fetcher
    Registry(Arc<RegistryOrigin>),
    /// `velarx-dir --origin`: a path
    Path(Arc<PathOrigin>),
    /// The process of a `[[transports]]`, on its socket, and how long it may
    /// be silent in a call (its `idle_timeout_secs`)
    Transport(std::path::PathBuf, std::time::Duration),
}

/// Where one pull gets its metadata: the registry fetcher, on a connection
/// scoped to the repository (with its TLS setting and the credentials of
/// the command), made at the first call and kept for the next.
#[derive(Clone)]
pub struct OriginNet {
    via: Via,
    repository: String,
    tls_verify: bool,
    /// The credentials and certificates of the command, for the scope
    access: Option<Access>,
    conn: Arc<tokio::sync::Mutex<Option<FetchConn>>>,
    /// Asked in order: the registry, and fetchers for what a digest names
    sources: Vec<Source>,
}

/// One place [`OriginNet`] asks.
#[derive(Clone)]
pub enum Source {
    /// Fetchers of `[pull] sources`, for what a digest names
    Fetchers(Arc<MetadataSources>),
    /// The origin (the registry fetcher), for a tag too
    Registry,
}

impl OriginNet {
    /// What is asked, in order, instead of the registry alone; without
    /// [`Source::Registry`] the registry is not asked at all.
    pub fn with_sources(mut self, sources: Vec<Source>) -> Self {
        self.sources = sources;
        self
    }

    /// `repository`: the reference the image is pulled from, as it is
    /// recorded for its layers (`registry_ref`).
    pub fn new(origin: Arc<RegistryOrigin>, repository: String, tls_verify: bool) -> Self {
        Self {
            via: Via::Registry(origin),
            repository,
            tls_verify,
            access: None,
            conn: Arc::default(),
            sources: vec![Source::Registry],
        }
    }

    /// Where the metadata of a pull of a path comes from: the origin
    /// process, on a connection it hands out of its own scope.
    pub fn of_path(path: Arc<PathOrigin>) -> Self {
        Self {
            via: Via::Path(path),
            repository: String::new(),
            tls_verify: false,
            access: None,
            conn: Arc::default(),
            sources: vec![Source::Registry],
        }
    }

    /// Where the metadata of a pull from the transport on `socket` comes
    /// from: its process, scoped to `location` (`SCHEME://...`) and with
    /// the credentials of the command.
    pub fn of_transport(
        socket: std::path::PathBuf,
        idle: std::time::Duration,
        location: String,
        tls_verify: bool,
    ) -> Self {
        Self {
            via: Via::Transport(socket, idle),
            repository: location,
            tls_verify,
            access: None,
            conn: Arc::default(),
            sources: vec![Source::Registry],
        }
    }

    /// The party the answers are of.
    pub(crate) fn party(&self) -> &str {
        match &self.via {
            Via::Registry(_) => REGISTRY,
            Via::Path(_) => "dir",
            Via::Transport(..) => self.repository.split("://").next().unwrap_or("transport"),
        }
    }

    fn failed(&self, e: CallError) -> ImageError {
        image_error_of(self.party(), e)
    }

    /// The scope has the credentials and certificates of `access` (a sealed
    /// memory file the fetcher reads; none: it uses its own).
    pub fn with_access(mut self, access: Option<Access>) -> Self {
        self.access = access;
        self
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// The connection scoped to the repository (or the origin), made at the
    /// first call.
    async fn scoped<'a>(&self, slot: &'a mut Option<FetchConn>) -> ImageResult<&'a mut FetchConn> {
        if slot.is_none() {
            let mut conn = match &self.via {
                Via::Path(path) => {
                    *slot = Some(path.connect().await?);
                    return Ok(slot.as_mut().expect("made above"));
                }
                Via::Registry(origin) => origin.connect().await.map_err(|e| {
                    ImageError::transfer(REGISTRY, FailureClass::Transient, e.to_string())
                })?,
                Via::Transport(socket, _) => {
                    let mut conn = FetchConn::connect_checked(socket).await.map_err(|e| {
                        ImageError::transfer(self.party(), FailureClass::Unavailable, e.to_string())
                    })?;
                    // (a transport that does not serve a pull says so)
                    let info = conn.get_info().await.map_err(|e| self.failed(e))?;
                    if !info.can("origin") {
                        return Err(ImageError::transfer(
                            self.party(),
                            FailureClass::Failed,
                            format!("the transport `{}` does not pull", self.party()),
                        ));
                    }
                    conn
                }
            };
            conn.open(Scoping {
                verity: false,
                source: Some(&self.repository),
                tls_verify: Some(self.tls_verify),
                target: None,
                access: Access::fds(self.access.as_ref()).into_iter().next(),
                idle: match &self.via {
                    Via::Transport(_, idle) => *idle,
                    _ => crate::pull::staged_fetch::REGISTRY_IDLE,
                },
                requires: &["metadata".to_string()],
            })
            .await
            .map_err(|e| self.failed(e))?;
            *slot = Some(conn);
        }
        Ok(slot.as_mut().expect("made above"))
    }

    /// What a call to the registry fetcher answered: None when it does not
    /// have the item; a connection that failed is not used again.
    fn answered<T>(
        &self,
        slot: &mut Option<FetchConn>,
        got: Result<T, CallError>,
    ) -> ImageResult<Option<T>> {
        match got {
            Ok(item) => Ok(Some(item)),
            Err(e) if absent(&e) => Ok(None),
            Err(e) => {
                if matches!(e, CallError::Io(_) | CallError::Protocol(_)) {
                    *slot = None;
                }
                Err(self.failed(e))
            }
        }
    }

    /// What is said of `what` (a tag or a digest) when `registry` is not
    /// one of the sources and no other had it.
    fn unlisted(what: &str) -> ImageError {
        let reason = match what.parse::<Digest>() {
            Ok(_) => "`registry` is not one of the sources, and no other has it",
            Err(_) => "`registry` is not one of the sources",
        };
        ImageError::transfer_of(REGISTRY, what, FailureClass::Unavailable, reason)
    }

    /// The manifest `reference` (a tag or a digest) names and the digest of
    /// its bytes, from the first source that has it (only the registry
    /// resolves a tag); None if the registry does not have it.
    pub async fn manifest_opt(&self, reference: &str) -> ImageResult<Option<(Bytes, Digest)>> {
        let digest = reference.parse::<Digest>().ok();
        let mut got = Err(Self::unlisted(reference));
        for source in &self.sources {
            match (source, digest) {
                (Source::Registry, _) => {
                    got = self.registry_manifest(reference).await;
                    if matches!(got, Ok(Some(_))) {
                        break;
                    }
                }
                (Source::Fetchers(fetchers), Some(digest)) => {
                    if let Some(bytes) = fetchers.manifest(&digest).await {
                        return Ok(Some((bytes, digest)));
                    }
                }
                (Source::Fetchers(_), None) => {}
            }
        }
        got
    }

    async fn registry_manifest(&self, reference: &str) -> ImageResult<Option<(Bytes, Digest)>> {
        let mut slot = self.conn.lock().await;
        let conn = self.scoped(&mut slot).await?;
        let got = conn.get_manifest(reference, MAX_MANIFEST_SIZE).await;
        let Some((file, _)) = self.answered(&mut slot, got)? else {
            return Ok(None);
        };
        let body = sealed_bytes(self.party(), &file, MAX_MANIFEST_SIZE, reference)?;
        // (bytes that are not those of the digest asked for: the party lied)
        let digest =
            velarx_registry::target::manifest_digest(reference, &body).map_err(|e| match e {
                ImageError::DigestMismatch { .. } => ImageError::transfer_of(
                    self.party(),
                    reference,
                    FailureClass::Invalid,
                    e.to_string(),
                ),
                e => e,
            })?;
        Ok(Some((Bytes::from(body), digest)))
    }

    pub async fn manifest(&self, reference: &str) -> ImageResult<(Bytes, Digest)> {
        self.manifest_opt(reference).await?.ok_or_else(|| {
            let hint = match reference.parse::<Digest>() {
                Ok(d) if d.alg() != velarx_types::digest::Algorithm::Sha256 => format!(
                    ": a registry may not address manifests by {}; name the tag as well (NAME:TAG@{d})",
                    d.alg()
                ),
                _ => String::new(),
            };
            ImageError::transfer_of(
                self.party(),
                reference,
                FailureClass::NotFound,
                format!("manifest of {} is unknown{hint}", self.repository),
            )
        })
    }

    /// The index of the images of the origin of a path.
    pub async fn path_index(&self) -> ImageResult<Bytes> {
        let mut slot = self.conn.lock().await;
        let conn = self.scoped(&mut slot).await?;
        let (file, _) = match conn.get_manifest("", MAX_MANIFEST_SIZE).await {
            Ok(got) => got,
            Err(e) => {
                if matches!(e, CallError::Io(_) | CallError::Protocol(_)) {
                    *slot = None;
                }
                // (what the origin says of its index, absent or not, is
                // what is wrong with the archive)
                return Err(self.failed(e));
            }
        };
        Ok(Bytes::from(sealed_bytes(
            self.party(),
            &file,
            MAX_MANIFEST_SIZE,
            "the index",
        )?))
    }

    /// The signature at `url` of a lookaside storage, at most `limit`
    /// bytes; None when it has none there.
    pub async fn signature(&self, url: &str, limit: u64) -> ImageResult<Option<Vec<u8>>> {
        let file = rustix::fs::memfd_create("signature", rustix::fs::MemfdFlags::CLOEXEC)
            .map(std::fs::File::from)
            .map_err(|e| ImageError::Io(e.into()))?;
        // (a path has no lookaside storage)
        let Via::Registry(origin) = &self.via else {
            return Ok(None);
        };
        let mut conn = origin
            .connect()
            .await
            .map_err(|e| ImageError::transfer(REGISTRY, FailureClass::Transient, e.to_string()))?;
        match conn.download(url, limit.max(1), &file).await {
            Ok(got) => {
                let bytes = written_bytes(&file, got.length, limit, url)?;
                Ok(Some(bytes))
            }
            Err(e) if absent(&e) => Ok(None),
            Err(e) => Err(image_error(e)),
        }
    }

    /// A small blob of `size` bytes (its descriptor's); the caller checks
    /// its digest.
    pub async fn small_blob(&self, blob: &Blob, limit: u64) -> ImageResult<Bytes> {
        if blob.size > limit {
            return Err(ImageError::transfer_of(
                self.party(),
                blob.digest.clone(),
                FailureClass::Invalid,
                "the blob is too large",
            ));
        }
        let mut got = Err(Self::unlisted(&blob.digest));
        for source in &self.sources {
            match source {
                Source::Registry => {
                    got = self.registry_blob(blob).await;
                    if got.is_ok() {
                        break;
                    }
                }
                Source::Fetchers(fetchers) => {
                    if let Some(bytes) = fetchers.blob(blob).await {
                        return Ok(bytes);
                    }
                }
            }
        }
        got
    }

    async fn registry_blob(&self, blob: &Blob) -> ImageResult<Bytes> {
        let mut slot = self.conn.lock().await;
        let conn = self.scoped(&mut slot).await?;
        let got = conn.get_blob(blob).await;
        let file = self.answered(&mut slot, got)?.ok_or_else(|| {
            ImageError::transfer_of(
                self.party(),
                blob.digest.clone(),
                FailureClass::NotFound,
                if matches!(self.via, Via::Registry(_)) {
                    "the registry has no such blob"
                } else {
                    "the origin has no such blob"
                },
            )
        })?;
        Ok(Bytes::from(sealed_bytes(
            self.party(),
            &file,
            blob.size,
            &blob.digest,
        )?))
    }
}

/// The bytes of a file the fetcher wrote (not sealed: the engine made it and
/// the fetcher wrote into it): `length` of them, which the file has, at most
/// `max`.
fn written_bytes(file: &std::fs::File, length: u64, max: u64, name: &str) -> ImageResult<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let invalid =
        |what: String| ImageError::transfer_of(REGISTRY, name, FailureClass::Invalid, what);
    let meta = file.metadata().map_err(|e| invalid(e.to_string()))?;
    if length > max || meta.len() != length {
        return Err(invalid(format!(
            "the fetcher wrote {} bytes for {length}, at most {max}",
            meta.len()
        )));
    }
    let mut bytes = vec![0u8; length as usize];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|e| invalid(e.to_string()))?;
    Ok(bytes)
}

/// Fetchers of `[pull] sources` asked for the metadata of a pull by digest:
/// what one sends is untrusted, and is used only when it has the digest
/// asked for, so that the next source is asked when nobody sent it right.
pub struct MetadataSources {
    links: tokio::sync::Mutex<Vec<crate::pull::staged_fetch::Link>>,
}

impl MetadataSources {
    /// The links that accept a bare scope.
    pub async fn open(links: Vec<crate::pull::staged_fetch::Link>) -> Arc<Self> {
        let mut opened = Vec::new();
        for mut link in links {
            let scope = Scoping::bare(link.idle);
            match crate::idle::within(link.idle, link.conn.open(scope)).await {
                Ok(()) => opened.push(link),
                Err(e) => tracing::debug!("The fetcher {} is left out: {e}", link.name),
            }
        }
        Arc::new(Self {
            links: tokio::sync::Mutex::new(opened),
        })
    }

    /// The manifest `digest` names, from the first fetcher that has it.
    pub async fn manifest(&self, digest: &Digest) -> Option<Bytes> {
        let mut links = self.links.lock().await;
        for link in links.iter_mut() {
            let got = crate::idle::within(
                link.idle,
                link.conn
                    .get_manifest(&digest.to_string(), MAX_MANIFEST_SIZE),
            )
            .await;
            if let Some(bytes) =
                checked(&link.name, digest, got.ok().map(|g| g.0), MAX_MANIFEST_SIZE)
            {
                return Some(bytes);
            }
        }
        None
    }

    /// The blob `blob` names, of exactly its size, from the first fetcher
    /// that has it.
    pub async fn blob(&self, blob: &Blob) -> Option<Bytes> {
        let digest: Digest = blob.digest.parse().ok()?;
        let mut links = self.links.lock().await;
        for link in links.iter_mut() {
            let got = crate::idle::within(link.idle, link.conn.get_blob(blob)).await;
            if let Some(bytes) = checked(&link.name, &digest, got.ok(), blob.size)
                .filter(|b| b.len() as u64 == blob.size)
            {
                return Some(bytes);
            }
        }
        None
    }
}

/// The bytes of the sealed memory file `file` if they have the digest.
fn checked(party: &str, digest: &Digest, file: Option<std::fs::File>, max: u64) -> Option<Bytes> {
    let bytes = velarx_base::sealed::read_sealed_whole(&file?, max).ok()?;
    if Digest::of(digest.alg(), &bytes) != *digest {
        tracing::debug!("The fetcher {party}: {digest} is not what it says");
        return None;
    }
    Some(Bytes::from(bytes))
}

/// A repository of a registry reached through the registry fetcher for
/// what a pull does not do: the tags, a search, a login and a push.  This
/// process opens no connection to the registry and holds no credential of
/// it: the credentials and certificates of the command (when it has some)
/// go to the fetcher in a sealed memory file, never in a message.
#[derive(Clone)]
pub struct OriginRemote {
    origin: Arc<RegistryOrigin>,
    remote: Remote,
    access: Option<Access>,
}

impl OriginRemote {
    /// `repository`: `registry/name`, with no tag or digest.
    pub fn new(
        origin: Arc<RegistryOrigin>,
        repository: &str,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
    ) -> ImageResult<Self> {
        let access = Access::new(access).map_err(ImageError::Io)?;
        Ok(Self {
            remote: Remote {
                repository: repository.to_string(),
                tls_verify: Some(tls_verify),
                access: access.as_ref().map(|_| 0),
            },
            origin,
            access,
        })
    }

    /// A connection for one call.
    async fn conn(&self) -> ImageResult<FetchConn> {
        self.origin
            .connect()
            .await
            .map_err(|e| ImageError::transfer(REGISTRY, FailureClass::Transient, e.to_string()))
    }

    /// The tags of the repository, every page of them.
    pub async fn tags(&self) -> ImageResult<Vec<String>> {
        // (a call of the registry fetcher is bounded as those of a pull)
        let mut conn = self.conn().await?;
        crate::idle::within(
            crate::pull::staged_fetch::REGISTRY_IDLE,
            conn.tags(&self.remote, self.access.as_ref()),
        )
        .await
        .map_err(image_error)
    }

    /// The hits of a search of `needle` in the registry, at most `n`.
    pub async fn search(&self, needle: &str, n: usize) -> ImageResult<Vec<Hit>> {
        let mut conn = self.conn().await?;
        crate::idle::within(
            crate::pull::staged_fetch::REGISTRY_IDLE,
            conn.search(
                &self.remote,
                self.access.as_ref(),
                (needle, u64::try_from(n).unwrap_or(u64::MAX)),
            ),
        )
        .await
        .map_err(image_error)
    }

    /// Whether the registry takes the credentials of the command: why not
    /// otherwise (`Unauthorized`: it refused them, in its words).
    pub async fn login(&self) -> ImageResult<()> {
        let Some(access) = &self.access else {
            return Err(ImageError::transfer(
                REGISTRY,
                FailureClass::Failed,
                "there are no credentials to check",
            ));
        };
        let mut conn = self.conn().await?;
        match crate::idle::within(
            crate::pull::staged_fetch::REGISTRY_IDLE,
            conn.login(&self.remote, access),
        )
        .await
        {
            Ok(()) => Ok(()),
            Err(e) => Err(image_error(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_proto::transfer::Failure;

    /// Without `registry` among the sources a digest comes from the
    /// fetchers alone, and what they lack is said to be nobody's.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_digest_comes_from_the_fetchers_without_the_registry() {
        let body = br#"{"schemaVersion":2}"#;
        let right = Digest::of(velarx_types::digest::Algorithm::Sha256, body);
        let (sources, _keep) = sources_of(body).await;
        // (a socket that would be an error of another kind if it were used)
        let net = OriginNet::of_transport(
            "/nonexistent/velarx-registry.sock".into(),
            std::time::Duration::from_secs(5),
            "docker://example.com/a".into(),
            true,
        )
        .with_sources(vec![Source::Fetchers(sources)]);
        let got = net.manifest(&right.to_string()).await.unwrap();
        assert_eq!((&got.0[..], got.1), (&body[..], right));
        let wrong = Digest::of(velarx_types::digest::Algorithm::Sha256, b"other");
        let e = net.manifest(&wrong.to_string()).await.unwrap_err();
        assert!(e.to_string().contains("no other has it"), "{e}");
    }

    async fn sources_of(bytes: &[u8]) -> (Arc<MetadataSources>, crate::serve_fetch::LocalFetcher) {
        use crate::pull::staged_fetch::{Link, REGISTRY_IDLE};
        let fetcher = crate::serve_fetch::LocalFetcher::start(
            Arc::new(crate::fakes::Metadata(bytes.to_vec())),
            crate::activation::Limits::default(),
        )
        .unwrap();
        let conn = FetchConn::new(fetcher.connect().unwrap()).unwrap();
        let link = Link {
            name: "peer".into(),
            conn,
            idle: REGISTRY_IDLE,
        };
        (MetadataSources::open(vec![link]).await, fetcher)
    }

    /// What a fetcher sends for a digest is used when it has that digest and
    /// is not used otherwise: the pull then asks the next source.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fetcher_before_the_registry_is_believed_only_by_the_digest() {
        let body = br#"{"schemaVersion":2}"#;
        let right = Digest::of(velarx_types::digest::Algorithm::Sha256, body);
        let (sources, _keep) = sources_of(body).await;
        assert_eq!(sources.manifest(&right).await.as_deref(), Some(&body[..]));
        let blob = Blob {
            digest: right.to_string(),
            size: body.len() as u64,
            media_type: "x".into(),
            annotations: None,
        };
        assert!(sources.blob(&blob).await.is_some());
        // (a descriptor that says another size is not the blob sent)
        let bigger = Blob {
            size: blob.size + 1,
            ..blob.clone()
        };
        assert!(sources.blob(&bigger).await.is_none());
        let wrong = Digest::of(velarx_types::digest::Algorithm::Sha256, b"other");
        assert!(sources.manifest(&wrong).await.is_none());
        let other = Blob {
            digest: wrong.to_string(),
            ..blob
        };
        assert!(sources.blob(&other).await.is_none());
    }

    /// The refusals and the absences the fetcher tells keep their class: the
    /// status of the API comes from it.
    #[test]
    fn the_kind_of_a_registry_answer_survives_the_fetcher() {
        let of = |class| {
            let failure = Failure {
                class,
                reason: "x".into(),
            };
            (
                image_error(CallError::Registry(RegistryError::Failed {
                    failure: failure.clone(),
                }))
                .registry_status(),
                image_error(CallError::Fetcher(FetcherError::Failed { failure })).registry_status(),
            )
        };
        assert_eq!(of(FailureClass::Unauthorized), (401, 401));
        assert_eq!(of(FailureClass::Forbidden), (403, 403));
        assert_eq!(of(FailureClass::NotFound), (404, 404));
        assert_eq!(of(FailureClass::Failed), (500, 500));
    }
}

/// The bodies of http and https URLs (an import, an ADD of a build, a remote
/// build context), read by the registry fetcher: this process makes no
/// request.  The fetcher writes a body into a file with no name beneath the
/// staging and hands it over; its bytes are the server's, untrusted.
#[derive(Clone)]
pub struct OriginUrls {
    origin: Arc<RegistryOrigin>,
    /// Where the file a body is written into is made (with no name)
    staging: std::path::PathBuf,
}

impl OriginUrls {
    pub fn new(origin: Arc<RegistryOrigin>, staging: std::path::PathBuf) -> Self {
        Self { origin, staging }
    }

    /// The body of `url`, at most `limit` bytes, given to `sink` in order;
    /// a 404 is an error.
    pub async fn fetch(
        &self,
        url: &str,
        limit: u64,
        sink: &mut (dyn FnMut(&[u8]) -> std::io::Result<()> + Send),
    ) -> Result<UrlTrailer, UrlError> {
        self.fetch_opt(url, limit, sink)
            .await?
            .ok_or_else(|| UrlError::Failed(format!("{url}: 404 Not Found")))
    }

    /// [`OriginUrls::fetch`], None when the server answers 404.
    pub async fn fetch_opt(
        &self,
        url: &str,
        limit: u64,
        sink: &mut (dyn FnMut(&[u8]) -> std::io::Result<()> + Send),
    ) -> Result<Option<UrlTrailer>, UrlError> {
        use std::os::unix::fs::FileExt;
        let failed = |e: String| UrlError::Failed(e);
        let mut conn = self
            .origin
            .connect()
            .await
            .map_err(|e| failed(format!("the registry fetcher: {e}")))?;
        let file = crate::pull::unnamed::unnamed_file(&self.staging)
            .map_err(|e| failed(format!("a file for the body of {url}: {e}")))?;
        let reply = match conn.download(url, limit.max(1), &file).await {
            Ok(got) => got,
            Err(e) if absent(&e) => return Ok(None),
            Err(CallError::Registry(RegistryError::TooLarge { max })) => {
                return Err(UrlError::TooLarge(max))
            }
            Err(e) => return Err(failed(e.to_string())),
        };
        // (a regular file of the length said, no more than asked)
        let meta = file.metadata().map_err(|e| failed(e.to_string()))?;
        if !meta.is_file() || meta.len() != reply.length {
            return Err(failed(format!(
                "{url}: the fetcher handed {} bytes for {}",
                meta.len(),
                reply.length
            )));
        }
        if reply.length > limit {
            return Err(UrlError::TooLarge(limit));
        }
        let mut buf = vec![0u8; 1 << 20];
        let mut at = 0u64;
        while at < reply.length {
            let n = (reply.length - at).min(buf.len() as u64) as usize;
            file.read_exact_at(&mut buf[..n], at)
                .map_err(|e| failed(e.to_string()))?;
            sink(&buf[..n]).map_err(|e| failed(e.to_string()))?;
            at += n as u64;
        }
        Ok(Some(UrlTrailer {
            size: reply.length,
            last_modified: reply.modified,
        }))
    }
}

/// Why the download of a URL failed.
#[derive(Debug)]
pub enum UrlError {
    /// The body is longer than the limit (in bytes).
    TooLarge(u64),
    Failed(String),
}

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UrlError::TooLarge(limit) => write!(f, "larger than {limit} bytes"),
            UrlError::Failed(m) => f.write_str(m),
        }
    }
}

impl From<velarx_types::ImageError> for UrlError {
    fn from(e: velarx_types::ImageError) -> Self {
        UrlError::Failed(e.to_string())
    }
}

impl From<String> for UrlError {
    fn from(m: String) -> Self {
        UrlError::Failed(m)
    }
}

/// The reply to a URL request.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UrlTrailer {
    pub size: u64,
    /// The Last-Modified header, as the server sent it.
    pub last_modified: Option<String>,
}

/// The words of a failed login: what the registry or the connection said,
/// without the kind of the error before it.
pub fn failure_text(e: &ImageError) -> String {
    match e {
        ImageError::Transfer { failure, .. } => velarx_types::printable(&failure.reason),
        ImageError::Registry(what)
        | ImageError::Unauthorized(what)
        | ImageError::Forbidden(what)
        | ImageError::Unreachable(what)
        | ImageError::RegistryNotFound(what) => velarx_types::printable(what),
        e => e.to_string(),
    }
}
