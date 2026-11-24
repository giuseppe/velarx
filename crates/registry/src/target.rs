// SPDX-License-Identifier: Apache-2.0
//! Where the requests for an image go, and what they need, without making
//! any: the endpoints of a reference after `registries.conf` (the mirrors,
//! then the registry), the credentials and the certificates of each
//! (`auth.json`, the credential helpers, `certs.d`), the manifests and
//! platforms of an image.  The engine describes the endpoints with these to
//! a fetcher ([`EndpointSpec`]), which makes the requests with
//! [`super::client`]; this part links no HTTP client and no TLS stack.

use super::auth::{AuthConfig, Credentials};
use super::certs::{RawCerts, MAX_CERT_FILE_SIZE};
use super::config::RegistriesConfig;
use super::hints::{Hint, HintStore};
use bytes::Bytes;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, warn};
use velarx_types::digest::Digest;
use velarx_types::{ImageError, ImageReference, ImageResult, OciManifest};

/// Largest manifest accepted (container-libs uses the same limit).
pub const MAX_MANIFEST_SIZE: u64 = 4 * 1024 * 1024;

/// Largest image configuration accepted.
pub const MAX_CONFIG_SIZE: u64 = 4 * 1024 * 1024;

/// Directories searched for `certs.d/<host>`.
pub fn default_certs_dirs() -> Result<Vec<PathBuf>, velarx_base::ids::IdsError> {
    let mut dirs = vec![
        PathBuf::from("/etc/velarx/certs.d"),
        PathBuf::from("/etc/docker/certs.d"),
    ];
    dirs.extend(super::config::user_config_dir()?.map(|d| d.join("velarx/certs.d")));
    Ok(dirs)
}

/// Where the registries are and how they are trusted: `registries.conf`,
/// the `certs.d` directories, and whether TLS is verified.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub registries: RegistriesConfig,
    pub certs_dirs: Vec<PathBuf>,
    /// `false` for `--tls-verify=false`: no certificate checks, plain HTTP
    /// accepted for every registry.
    pub tls_verify: bool,
}

impl TransportConfig {
    /// The configuration of the system: `registries.conf` and the standard
    /// `certs.d` directories.
    pub fn system() -> Result<Self, velarx_base::ids::IdsError> {
        Ok(Self {
            registries: RegistriesConfig::load(),
            certs_dirs: default_certs_dirs()?,
            tls_verify: true,
        })
    }

    /// The registry and repository for `registry/repository`, after the
    /// `registries.conf` rules: blocked registries are refused and a block
    /// with a `location` rewrites the name.
    pub fn resolve(&self, registry: &str, repository: &str) -> ImageResult<Endpoint> {
        let mut all = self.endpoints(registry, repository, None, false)?;
        Ok(all.remove(0))
    }

    /// The endpoints to try for `registry/repository`, in order: the mirrors
    /// that apply (to a reference with or without a `digest`), then the
    /// registry itself.  Without `mirrors` only the registry.
    pub fn endpoints(
        &self,
        registry: &str,
        repository: &str,
        digest: Option<&Digest>,
        mirrors: bool,
    ) -> ImageResult<Vec<Endpoint>> {
        self.registries.check().map_err(ImageError::Registry)?;
        let ask = velarx_endpoint_core::Ask {
            has_digest: digest.is_some(),
            push: !mirrors,
            tls_verify: self.tls_verify,
        };
        let (host, path) = (registry.as_bytes(), repository.as_bytes());
        let all = velarx_endpoint_core::endpoints(&self.registries.blocks(), host, path, &ask)
            .map_err(|why| match why {
                velarx_endpoint_core::Refused::Blocked => ImageError::Registry(format!(
                    "registry `{registry}` is blocked in registries.conf"
                )),
                velarx_endpoint_core::Refused::NoRepository => ImageError::Registry(format!(
                    "registries.conf leaves no repository for `{registry}/{repository}`: \
                     a location needs a path where the name is the prefix"
                )),
            })?;
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        Ok(all
            .iter()
            .map(|e| Endpoint {
                host: text(&e.host),
                repository: text(&e.path),
                insecure: e.insecure,
                allow_private: e.allow_private,
                command_line: matches!(e.creds, velarx_endpoint_core::Creds::CommandLine),
                by_digest: digest.filter(|_| e.by_digest).copied(),
            })
            .collect())
    }
}

/// A registry endpoint resolved for an image name.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host: String,
    pub repository: String,
    pub insecure: bool,
    /// `allow-private-addresses` of the registry's block
    pub allow_private: bool,
    /// It may be given the credentials of the command line: it is on the
    /// host that was named, not on another one (a mirror, or a location)
    pub command_line: bool,
    /// The manifest is asked of this endpoint by this digest, not by the
    /// tag: a mirror for digests only, which does not serve what it
    /// cannot be checked of
    pub by_digest: Option<Digest>,
}

/// Read the file of a certificate or a key of `certs.d`.
fn read_cert_file(path: &Path) -> ImageResult<Vec<u8>> {
    // Symbolic links are common in certs.d (mounted secrets): follow them,
    // but only read regular files and no more than a certificate can need.
    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(ImageError::Registry(format!(
            "`{}` is not a regular file",
            path.display()
        )));
    }
    let mut data = Vec::new();
    file.take(MAX_CERT_FILE_SIZE + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_CERT_FILE_SIZE {
        return Err(ImageError::Registry(format!(
            "`{}` is too large",
            path.display()
        )));
    }
    Ok(data)
}

/// The files of `<dir>/<host>`: `*.crt` CA bundles, a `*.cert` client
/// certificate with the `*.key` of the same name.  `Ok(None)` if the
/// directory does not exist.  The files are only read: the fetcher that
/// connects parses them.
pub fn load_certs_dir(dir: &Path, host: &str) -> ImageResult<Option<RawCerts>> {
    let path = dir.join(host);
    let entries = match std::fs::read_dir(&path) {
        Ok(e) => e,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) || e.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            return Ok(None)
        }
        Err(e) => return Err(e.into()),
    };

    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .collect();
    names.sort();

    let text = |pem: Vec<u8>| String::from_utf8_lossy(&pem).into_owned();
    let mut certs = RawCerts::default();
    for name in &names {
        let file = path.join(name);
        if name.ends_with(".crt") {
            certs.ca.push(text(read_cert_file(&file)?));
        } else if let Some(stem) = name.strip_suffix(".cert") {
            if certs.cert.is_some() {
                continue;
            }
            let key = path.join(format!("{stem}.key"));
            if !key.exists() {
                return Err(ImageError::Registry(format!(
                    "missing key `{}` for client certificate `{}`",
                    key.display(),
                    file.display()
                )));
            }
            certs.cert = Some(text(read_cert_file(&file)?));
            certs.key = Some(text(read_cert_file(&key)?));
        } else if let Some(stem) = name.strip_suffix(".key") {
            if !path.join(format!("{stem}.cert")).exists() {
                return Err(ImageError::Registry(format!(
                    "missing client certificate `{}/{stem}.cert` for key `{name}`",
                    path.display()
                )));
            }
        }
    }
    Ok(Some(certs))
}

/// The certificates of a host from the directories that have them: the CA
/// bundles of all, the client certificate of the first that has one.
pub fn load_host_certs(dirs: &[PathBuf], host: &str) -> ImageResult<RawCerts> {
    let mut merged = RawCerts::default();
    for dir in dirs {
        if let Some(c) = load_certs_dir(dir, host)? {
            debug!("Using the certificates of {} in {}", host, dir.display());
            merged.ca.extend(c.ca);
            if merged.cert.is_none() {
                merged.cert = c.cert;
                merged.key = c.key;
            }
        }
    }
    Ok(merged)
}

/// What `GET /v2/` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Challenge {
    None,
    Basic,
    Bearer {
        realm: String,
        service: Option<String>,
    },
}

/// Parse the parameters of a `WWW-Authenticate` challenge: `k="v", k=v`.
/// Quoted values may contain commas (`scope="repository:a:pull,push"`).
pub(crate) fn parse_auth_params(s: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i] == b',' || b[i].is_ascii_whitespace()) {
            i += 1;
        }
        let start = i;
        while i < b.len() && b[i] != b'=' && b[i] != b',' {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            continue;
        }
        let key = s[start..i].trim().to_ascii_lowercase();
        i += 1;
        let mut value = String::new();
        if i < b.len() && b[i] == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' && i + 1 < b.len() {
                    i += 1;
                }
                value.push(b[i] as char);
                i += 1;
            }
            i += 1;
        } else {
            let vstart = i;
            while i < b.len() && b[i] != b',' {
                i += 1;
            }
            value = s[vstart..i].trim().to_string();
        }
        params.insert(key, value);
    }
    params
}

impl Challenge {
    pub fn parse(header: &str) -> ImageResult<Challenge> {
        let header = header.trim();
        let (scheme, rest) = header.split_once(' ').unwrap_or((header, ""));
        match scheme.to_ascii_lowercase().as_str() {
            "basic" => Ok(Challenge::Basic),
            "bearer" => {
                let params = parse_auth_params(rest);
                let realm = params.get("realm").cloned().ok_or_else(|| {
                    ImageError::Registry("Missing realm in WWW-Authenticate".into())
                })?;
                Ok(Challenge::Bearer {
                    realm,
                    service: params.get("service").cloned(),
                })
            }
            other => Err(ImageError::Registry(format!(
                "Unsupported authentication scheme `{other}`"
            ))),
        }
    }
}

/// The registry and repository of an image reference, ready to be
/// described to the fetcher that requests it.
#[derive(Clone, Debug)]
pub struct Target {
    pub endpoint: Endpoint,
    /// What `certs.d` (or the request) has for the host of the endpoint
    pub certs: RawCerts,
    /// Another repository of the registry that blobs are mounted from; the
    /// token must be allowed to read it.
    pub mount_from: Option<String>,
    /// What to try when this endpoint (a mirror) does not have what is
    /// asked, in order.  Everything that comes from an endpoint is verified
    /// by digest, so a mirror is as little trusted as the registry.
    pub fallbacks: Vec<Target>,
}

impl Target {
    /// The same target, with the right to read `repository` for a mount.
    pub fn mounting_from(&self, repository: &str) -> Target {
        Target {
            mount_from: Some(repository.to_string()),
            ..self.clone()
        }
    }

    /// `registry/repository` of each endpoint the target is fetched from
    /// (the mirrors, then the registry): where credentials may go.
    pub fn credential_scopes(&self) -> Vec<String> {
        self.chain()
            .map(|t| format!("{}/{}", t.endpoint.host, t.endpoint.repository))
            .collect()
    }

    /// This endpoint, then the ones to fall back to.
    pub fn chain(&self) -> impl Iterator<Item = &Target> {
        std::iter::once(self).chain(self.fallbacks.iter())
    }

    /// The key of the blob `digest` of this endpoint.
    pub fn blob_key(&self, digest: &Digest) -> String {
        format!(
            "{}/{}@{}",
            self.endpoint.host, self.endpoint.repository, digest
        )
    }
}

/// URL scheme of a registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Https,
    Http,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Https => "https",
            Scheme::Http => "http",
        }
    }
}

/// An endpoint described for a process that has no configuration of its own:
/// where it is, how to reach it and who to be.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EndpointSpec {
    pub host: String,
    pub repository: String,
    pub insecure: bool,
    /// The registry may send the client to private addresses
    #[serde(default)]
    pub allow_private: bool,
    pub credentials: Option<Credentials>,
    pub certs: RawCerts,
    /// The credentials stay with the daemon: the `Authorization` of the
    /// requests to this endpoint is asked for (the `AuthBroker` of the
    /// fetcher).
    #[serde(default)]
    pub brokered: bool,
    /// What the user's cache of hints says of this registry
    /// ([`super::hints`]), if the pull uses them
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<Hint>,
    /// Whether what the requests find out about the registry is told back,
    /// to be kept as a hint
    #[serde(default)]
    pub hints: bool,
    /// The least a download from this endpoint must bring
    #[serde(default)]
    pub min_speed: crate::speed::Speed,
    /// The scheme an insecure endpoint was found to speak, so that it is
    /// not probed again (ignored for an endpoint that is not insecure)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<Scheme>,
}

/// The configuration and the credentials of the registries: the endpoints
/// of a reference and what a fetcher needs to reach them.  Cheap to clone.
#[derive(Clone)]
pub struct Resolver {
    config: Arc<TransportConfig>,
    /// The certificates of every host instead of `certs.d` (`--cert-dir`).
    certs: Option<RawCerts>,
    auth: Arc<AuthConfig>,
    /// The hints of the user, for the specs to carry
    store: Option<Arc<HintStore>>,
    /// The least a download must bring
    speed: crate::speed::Speed,
    /// What the requests brought, kept to put it before the stored
    /// credentials of [`with_stored_credentials`](Self::with_stored_credentials)
    access: Option<Arc<super::auth::RegistryAccess>>,
}

impl Resolver {
    /// The configuration of the system: `registries.conf`, `certs.d`,
    /// `auth.json`.
    pub fn new() -> Result<Self, velarx_base::ids::IdsError> {
        Ok(Self::with_config(
            TransportConfig::system()?,
            AuthConfig::load()?,
        ))
    }

    pub fn with_config(config: TransportConfig, auth: AuthConfig) -> Self {
        Self {
            config: Arc::new(config),
            certs: None,
            auth: Arc::new(auth),
            store: None,
            speed: Default::default(),
            access: None,
        }
    }

    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    /// The certificates it uses instead of `certs.d`, if any.
    pub fn certs(&self) -> Option<&RawCerts> {
        self.certs.as_ref()
    }

    pub fn auth(&self) -> &Arc<AuthConfig> {
        &self.auth
    }

    /// The least a download must bring.
    pub fn speed(&self) -> crate::speed::Speed {
        self.speed
    }

    /// Keep what the registries asked for in `store`, and give it to the
    /// fetchers (`endpoint_specs`).
    pub fn set_hints(&mut self, store: Option<Arc<HintStore>>) {
        self.store = store;
    }

    /// Fail the downloads that bring less than this.
    pub fn set_min_speed(&mut self, speed: crate::speed::Speed) {
        self.speed = speed;
    }

    pub fn hint_store(&self) -> Option<&Arc<HintStore>> {
        self.store.as_ref()
    }

    /// The same configuration and credentials but with the TLS
    /// verification set to `tls_verify` (`--tls-verify=false`).
    pub fn with_tls_verify(&self, tls_verify: bool) -> Self {
        if self.config.tls_verify == tls_verify {
            return self.clone();
        }
        let mut config = (*self.config).clone();
        config.tls_verify = tls_verify;
        Self {
            config: Arc::new(config),
            ..self.clone()
        }
    }

    /// No credentials of its own (the auth files and the credential
    /// helpers are not read): for a process whose registry requests are
    /// made by the fetcher.  What a request brings
    /// ([`with_access`](Self::with_access)) it still uses.
    pub fn without_credentials(&self) -> Self {
        Self {
            auth: Arc::new(AuthConfig::default()),
            ..self.clone()
        }
    }

    /// The auth files read again (a `login` or a `logout` since it was
    /// made).  Why not when the files cannot be read now.  `files`: the
    /// auth files of the process ([`crate::auth::default_auth_files`]).
    pub fn with_reloaded_credentials(&self, files: &[PathBuf]) -> Result<Self, String> {
        Ok(Self {
            auth: Arc::new(self.auth.reloaded(files)?),
            ..self.clone()
        })
    }

    /// The stored credentials after all (the auth files and the credential
    /// helpers): what the request brought comes first.
    pub fn with_stored_credentials(&self) -> Result<Self, velarx_base::ids::IdsError> {
        let stored = AuthConfig::load()?;
        let auth = match &self.access {
            Some(access) => stored.with_access(access),
            None => stored,
        };
        Ok(Self {
            auth: Arc::new(auth),
            ..self.clone()
        })
    }

    /// What the request brought (credentials, certificates), if anything.
    pub fn request_access(&self) -> Option<&super::auth::RegistryAccess> {
        self.access.as_deref()
    }

    /// What a request brought: credentials before the stored ones,
    /// certificates instead of `certs.d`.
    pub fn with_access(&self, access: &super::auth::RegistryAccess) -> Self {
        if access.is_empty() {
            return self.clone();
        }
        Self {
            certs: access.certs.clone().or_else(|| self.certs.clone()),
            auth: Arc::new(self.auth.with_access(access)),
            access: Some(Arc::new(access.clone())),
            ..self.clone()
        }
    }

    /// Run the credential helpers in `runner` (this process cannot).
    pub fn set_helper_runner(&mut self, runner: Arc<super::helper::HelperRunner>) {
        self.auth = Arc::new((*self.auth).clone().with_helper_runner(runner));
    }

    /// The endpoints to pull `image_ref` from: the mirrors that apply, then
    /// the registry.
    pub fn target(&self, image_ref: &ImageReference) -> ImageResult<Target> {
        self.target_of(image_ref, true)
    }

    /// The registry to push `image_ref` to: never a mirror.
    pub fn push_target(&self, image_ref: &ImageReference) -> ImageResult<Target> {
        self.target_of(image_ref, false)
    }

    fn target_of(&self, image_ref: &ImageReference, mirrors: bool) -> ImageResult<Target> {
        image_ref.validate()?;
        let endpoints = self.config.endpoints(
            &image_ref.registry,
            &image_ref.repository,
            image_ref.digest.as_ref(),
            mirrors,
        )?;
        let mut targets = Vec::new();
        for endpoint in endpoints {
            let certs = match &self.certs {
                Some(raw) => raw.clone(),
                None => load_host_certs(&self.config.certs_dirs, &endpoint.host).map_err(|e| {
                    warn!("Cannot use the certificates of {}: {}", endpoint.host, e);
                    e
                })?,
            };
            targets.push(Target {
                endpoint,
                certs,
                mount_from: None,
                fallbacks: Vec::new(),
            });
        }
        let mut first = targets.remove(0);
        first.fallbacks = targets;
        Ok(first)
    }

    /// The endpoints of `t` (the mirrors, then the registry) with the
    /// credentials and the certificates to reach them.
    pub fn endpoint_specs(&self, t: &Target) -> ImageResult<Vec<EndpointSpec>> {
        t.chain()
            .map(|e| {
                Ok(EndpointSpec {
                    host: e.endpoint.host.clone(),
                    repository: e.endpoint.repository.clone(),
                    insecure: e.endpoint.insecure,
                    allow_private: e.endpoint.allow_private,
                    credentials: self.credentials(e)?,
                    certs: e.certs.clone(),
                    brokered: false,
                    hint: self.hint(&e.endpoint.host),
                    hints: self.store.is_some(),
                    min_speed: self.speed,
                    scheme: None,
                })
            })
            .collect()
    }

    fn hint(&self, host: &str) -> Option<Hint> {
        self.store.as_ref().and_then(|s| s.get(host))
    }

    /// The endpoints of `t` for fetchers that hold no credentials: an
    /// endpoint with credentials is `brokered` and has none; the second
    /// list has, for each endpoint, the spec with its credentials when it
    /// has some (for the worker that answers for it alone).
    pub fn brokered_specs(
        &self,
        t: &Target,
    ) -> ImageResult<(Vec<EndpointSpec>, Vec<Option<EndpointSpec>>)> {
        let full = self.endpoint_specs(t)?;
        let mut pull = Vec::with_capacity(full.len());
        let mut auth = Vec::with_capacity(full.len());
        for spec in full {
            if spec.credentials.is_some() {
                pull.push(EndpointSpec {
                    credentials: None,
                    brokered: true,
                    ..spec.clone()
                });
                auth.push(Some(spec));
            } else {
                pull.push(spec);
                auth.push(None);
            }
        }
        Ok((pull, auth))
    }

    /// The credentials for the repository of `t`, if any.
    pub fn credentials(&self, t: &Target) -> ImageResult<Option<Credentials>> {
        self.auth
            .lookup_for(
                t.endpoint.command_line,
                &t.endpoint.host,
                &t.endpoint.repository,
            )
            .map_err(ImageError::Registry)
    }

    /// The registries.conf rules.
    pub fn registries(&self) -> &RegistriesConfig {
        &self.config.registries
    }
}

/// Check `data` against `expected`, with the algorithm of `expected`.
pub fn verify_digest(expected: &Digest, data: &[u8]) -> ImageResult<()> {
    let actual = Digest::of(expected.alg(), data);
    if actual != *expected {
        return Err(ImageError::DigestMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

/// The digest `reference` of a manifest request names, or none for a tag.  A
/// tag has no `:`, so anything else is a digest and must be one this code
/// can check: a request never goes on unchecked.
pub(crate) fn manifest_reference(reference: &str) -> ImageResult<Option<Digest>> {
    if !reference.contains(':') {
        return Ok(None);
    }
    reference.parse().map(Some).map_err(|e| {
        ImageError::Registry(format!(
            "invalid manifest reference `{}`: {e}",
            velarx_types::printable(reference)
        ))
    })
}

/// The digest of the manifest `body` fetched as `reference`: the digest it
/// names, checked with that digest's algorithm (a request never goes on
/// unchecked), or for a tag the digest of the bytes in the algorithm of the
/// image ([`image_algorithm`]), whatever the registry addresses it by.
pub fn manifest_digest(reference: &str, body: &[u8]) -> ImageResult<Digest> {
    match manifest_reference(reference)? {
        Some(wanted) => {
            verify_digest(&wanted, body)?;
            Ok(wanted)
        }
        None => Ok(Digest::of(image_algorithm(body), body)),
    }
}

pub use velarx_types::digest::image_algorithm;

/// The tags of a `tags/list` answer.
pub fn parse_tags(body: &[u8]) -> serde_json::Result<Vec<String>> {
    let list: serde_json::Value = serde_json::from_slice(body)?;
    Ok(list["tags"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default())
}

/// The architecture name of the host, as OCI platforms spell it.
pub fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "powerpc64" => "ppc64le",
        "arm" => "arm",
        "s390x" => "s390x",
        "riscv64" => "riscv64",
        other => other,
    }
}

/// The manifest `image_ref` names: its bytes come from `fetch`, which gets a
/// tag or a digest and returns the bytes and their digest.  A digest
/// reference is checked, and an index is resolved to the instance for
/// `platform` (by default linux on the host architecture).  The digest
/// returned is the one of the bytes.
pub async fn resolve_manifest<F, Fut>(
    image_ref: &ImageReference,
    platform: Option<&Platform>,
    fetch: F,
) -> ImageResult<(OciManifest, Digest, Bytes)>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = ImageResult<(Bytes, Digest)>>,
{
    resolve_manifest_with(image_ref, platform, None, fetch).await
}

/// The bytes of the manifest with a digest that the caller has already (a
/// store that has the image): nothing is trusted about them, they are used
/// only when they are the manifest of that digest.
pub type KnownManifests<'a> =
    &'a (dyn Fn(&Digest) -> futures::future::BoxFuture<'a, Option<Bytes>> + Sync);

/// Like [`resolve_manifest`], taking the instance an index names from
/// `known` when it has it and its bytes are the manifest of the digest the
/// index names (the checks of a manifest from the registry apply as well):
/// the request for it is saved.  The first manifest, the one `image_ref`
/// names, always comes from `fetch`: it is what tells that the registry
/// still has, and lets the user have, this image.
pub async fn resolve_manifest_with<F, Fut>(
    image_ref: &ImageReference,
    platform: Option<&Platform>,
    known: Option<KnownManifests<'_>>,
    fetch: F,
) -> ImageResult<(OciManifest, Digest, Bytes)>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = ImageResult<(Bytes, Digest)>>,
{
    let (manifest, digest, body, _) =
        resolve_manifest_chain(image_ref, platform, known, fetch).await?;
    Ok((manifest, digest, body))
}

/// [`resolve_manifest_with`], and the indexes it went through to the
/// instance, `(digest, bytes)`, the one `image_ref` names first.
pub async fn resolve_manifest_chain<F, Fut>(
    image_ref: &ImageReference,
    platform: Option<&Platform>,
    known: Option<KnownManifests<'_>>,
    fetch: F,
) -> ImageResult<(OciManifest, Digest, Bytes, Vec<(Digest, Bytes)>)>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = ImageResult<(Bytes, Digest)>>,
{
    let mut indexes = Vec::new();
    let host = Platform::host();
    let platform = platform.unwrap_or(&host);
    let reference = match (&image_ref.locator_tag, &image_ref.digest, &image_ref.tag) {
        (Some(tag), _, _) | (None, None, Some(tag)) => tag.clone(),
        (None, Some(digest), _) => digest.to_string(),
        (None, None, None) => {
            return Err(ImageError::Manifest("No tag or digest specified".into()))
        }
    };
    let (mut body, mut digest) = fetch(reference).await?;
    velarx_types::docker::refuse_manifest(&body)?;
    if let Some(pinned) = &image_ref.digest {
        // fetched by a tag, the bytes are the digest's own algorithm to check
        verify_digest(pinned, &body)?;
        digest = *pinned;
    }
    // An index: pick the instance for this platform (an index may list
    // indexes, two levels of them).
    for level in 0.. {
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        let Some(instances) = instances_of(&value)? else {
            break;
        };
        if level == 2 {
            return Err(ImageError::Manifest(
                "an index under two others is not read".into(),
            ));
        }
        let wanted = select_platform(instances, platform).ok_or_else(|| {
            ImageError::Manifest(format!("no manifest for {platform} in the index"))
        })?;
        velarx_types::docker::refuse_instance(instances, &wanted)?;
        let wanted: Digest = wanted.parse().map_err(|e| {
            ImageError::Manifest(format!(
                "invalid digest `{}` in the index: {e}",
                velarx_types::printable(&wanted)
            ))
        })?;
        let kept = match known {
            Some(known) => known(&wanted)
                .await
                .filter(|b| b.len() as u64 <= MAX_MANIFEST_SIZE && wanted.verify(b)),
            None => None,
        };
        indexes.push((digest, body.clone()));
        body = match kept {
            Some(body) => body,
            None => fetch(wanted.to_string()).await?.0,
        };
        velarx_types::docker::refuse_manifest(&body)?;
        // whoever fetched it (a confined worker too), the instance is the
        // one the index names: its bytes are hashed here
        verify_digest(&wanted, &body)?;
        digest = wanted;
        if body.len() as u64 > MAX_MANIFEST_SIZE {
            break;
        }
    }
    let manifest: OciManifest = serde_json::from_slice(&body)?;
    Ok((manifest, digest, body, indexes))
}

/// The instances `value` lists when it is an index; none for an image
/// manifest.  A document that is both, by its fields or its media type, is
/// an error: other tools would read it as the one Velarx did not.
fn instances_of(value: &serde_json::Value) -> ImageResult<Option<&Vec<serde_json::Value>>> {
    const INDEXES: [&str; 2] = [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ];
    let typed = value.get("mediaType").and_then(|t| t.as_str());
    let both =
        || ImageError::Manifest("the document is both an index and an image manifest".into());
    let Some(listed) = value.get("manifests") else {
        return match typed.is_some_and(|t| INDEXES.contains(&t)) {
            true => Err(both()),
            false => Ok(None),
        };
    };
    if value.get("config").is_some()
        || value.get("layers").is_some()
        || typed.is_some_and(|t| !INDEXES.contains(&t))
    {
        return Err(both());
    }
    listed
        .as_array()
        .map(Some)
        .ok_or_else(|| ImageError::Manifest("the manifests of the index are no list".into()))
}

/// An OS and architecture (and variant) images are built for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub os: String,
    pub arch: String,
    pub variant: Option<String>,
}

fn normalize_arch(arch: &str) -> &str {
    match arch {
        "x86_64" | "x86-64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

impl Platform {
    /// linux on the architecture of this host.
    pub fn host() -> Self {
        Self {
            os: "linux".into(),
            arch: host_arch().into(),
            variant: None,
        }
    }

    /// `os/arch[/variant]`, or an architecture alone for linux.
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split('/').collect();
        let (os, arch, variant) = match parts.as_slice() {
            [arch] => ("linux", *arch, None),
            [os, arch] => (*os, *arch, None),
            [os, arch, variant] => (*os, *arch, Some(*variant)),
            _ => {
                return Err(format!(
                    "invalid platform `{s}`: expected OS/ARCH[/VARIANT]"
                ))
            }
        };
        if [os, arch].iter().any(|p| p.is_empty()) || variant == Some("") {
            return Err(format!(
                "invalid platform `{s}`: expected OS/ARCH[/VARIANT]"
            ));
        }
        Ok(Self {
            os: os.to_string(),
            arch: normalize_arch(arch).to_string(),
            variant: variant.map(str::to_string),
        })
    }

    pub fn matches(&self, os: &str, arch: &str, variant: Option<&str>) -> bool {
        self.os == os
            && self.arch == normalize_arch(arch)
            && self.variant.as_deref().is_none_or(|v| Some(v) == variant)
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.os, self.arch)?;
        if let Some(v) = &self.variant {
            write!(f, "/{v}")?;
        }
        Ok(())
    }
}

/// The digest of the instance of an index for `platform`.
pub fn select_platform(instances: &[serde_json::Value], platform: &Platform) -> Option<String> {
    instances
        .iter()
        .find(|m| {
            let p = m.get("platform");
            let field = |k: &str| p.and_then(|p| p.get(k)).and_then(|v| v.as_str());
            match (field("os"), field("architecture")) {
                (Some(os), Some(arch)) => platform.matches(os, arch, field("variant")),
                _ => false,
            }
        })
        .and_then(|m| m.get("digest"))
        .and_then(|d| d.as_str())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, content: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn test_missing_certs_dir_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load_certs_dir(tmp.path(), "registry.example:5000")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_cert_without_key_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("r:5000");
        write(&d, "client.cert", "x");
        assert!(load_certs_dir(tmp.path(), "r:5000").is_err());
    }

    #[test]
    fn test_key_without_cert_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("r:5000");
        write(&d, "client.key", "x");
        assert!(load_certs_dir(tmp.path(), "r:5000").is_err());
    }

    #[test]
    fn test_other_files_are_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("r:5000");
        write(&d, "README", "hello");
        write(&d, ".hidden.crt", "garbage");
        let c = load_certs_dir(tmp.path(), "r:5000").unwrap().unwrap();
        assert!(c.ca.is_empty() && c.cert.is_none());
    }

    #[test]
    fn test_oversized_cert_file_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("r:5000");
        write(&d, "ca.crt", &"A".repeat(MAX_CERT_FILE_SIZE as usize + 1));
        assert!(load_certs_dir(tmp.path(), "r:5000").is_err());
    }

    fn transport(conf: &str, tls_verify: bool) -> TransportConfig {
        TransportConfig {
            registries: RegistriesConfig::parse(conf).unwrap(),
            certs_dirs: vec![],
            tls_verify,
        }
    }

    #[test]
    fn test_resolve_insecure_and_blocked() {
        let t = transport(
            "[[registry]]\nlocation = \"localhost:5000\"\ninsecure = true\n\
             [[registry]]\nlocation = \"bad.example.com\"\nblocked = true\n",
            true,
        );
        assert!(t.resolve("localhost:5000", "a/b").unwrap().insecure);
        assert!(!t.resolve("quay.io", "a/b").unwrap().insecure);
        assert!(t.resolve("bad.example.com", "a/b").is_err());
        let t = transport("", false);
        assert!(t.resolve("quay.io", "a/b").unwrap().insecure);
    }

    #[test]
    fn test_resolve_docker_io_host() {
        let t = transport("", true);
        assert_eq!(
            t.resolve("docker.io", "library/alpine").unwrap().host,
            "registry-1.docker.io"
        );
    }

    /// The `location` of a block, a mirror and an alias of registries.conf
    /// are a host and a path, as a reference is: a file that names what
    /// would reach the host or the path of an endpoint as another thing
    /// is refused when it is read.
    #[test]
    fn a_location_of_registries_conf_must_be_a_host_and_a_path() {
        for (what, conf) in [
            (
                "a block",
                "[[registry]]\nprefix = \"quay.io\"\nlocation = \"a b?c#d/..e\"",
            ),
            (
                "a mirror",
                "[[registry]]\nprefix = \"docker.io\"\n[[registry.mirror]]\nlocation = \"m ?/%2f\"",
            ),
            ("an alias", "[aliases]\nal = \"bad.host?x#y/z\""),
        ] {
            assert!(RegistriesConfig::parse(conf).is_err(), "{what}");
        }
    }
    fn hosts(endpoints: &[Endpoint]) -> Vec<(&str, &str)> {
        endpoints
            .iter()
            .map(|e| (e.host.as_str(), e.repository.as_str()))
            .collect()
    }

    /// A prefix governs a name at the end of a component: `example.com`
    /// does not govern `example.com:5000`, which is another server (a name
    /// has no tag, so a colon is a port); a prefix that names the port
    /// does.
    #[test]
    fn a_prefix_without_a_port_does_not_govern_the_same_host_on_a_port() {
        let t = transport(
            "[[registry]]\nprefix = \"example.com\"\nlocation = \"first.test\"\n\
             insecure = true\n[[registry.mirror]]\nlocation = \"mirror.test\"\n",
            true,
        );
        let e = t.endpoints("example.com:5000", "x", None, true).unwrap();
        assert_eq!(hosts(&e), [("example.com:5000", "x")]);
        assert!(!e[0].insecure);
        // the registry without the port is governed
        let e = t.endpoints("example.com", "x", None, true).unwrap();
        assert_eq!(hosts(&e), [("mirror.test", "x"), ("first.test", "x")]);
        assert!(e[1].insecure && !e[0].insecure);
        // a prefix that is not at a boundary does not apply
        let e = t.endpoints("example.community", "x", None, true).unwrap();
        assert_eq!(hosts(&e), [("example.community", "x")]);
        // the block that names the port governs it, and a block that
        // blocks the registry does not block it on another port
        let t = transport(
            "[[registry]]\nprefix = \"example.com\"\nblocked = true\n\
             [[registry]]\nprefix = \"example.com:5000\"\ninsecure = true\n",
            true,
        );
        assert!(t.resolve("example.com:5000", "x").unwrap().insecure);
        assert!(t.resolve("example.com", "x").is_err());
        assert!(!t.resolve("example.com:6000", "x").unwrap().insecure);
    }

    /// A rewrite whose result has no repository (a location without a path,
    /// for the name that is the prefix) is an error, as it is for
    /// containers/image, and not the name as typed with the flags of the
    /// block; a longer name is rewritten as the file says.  The same for a
    /// mirror.
    #[test]
    fn a_location_without_a_path_is_an_error_for_the_name_that_is_the_prefix() {
        let t = transport(
            "[[registry]]\nprefix = \"docker.io/library/alpine\"\n\
             location = \"internal\"\ninsecure = true\n\
             [[registry.mirror]]\nlocation = \"cache.test\"\n",
            true,
        );
        let e = t
            .endpoints("docker.io", "library/alpine", None, true)
            .unwrap_err();
        assert!(e.to_string().contains("leaves no repository"), "{e}");
        assert!(t.resolve("docker.io", "library/alpine").is_err());
        // with a longer name the same block rewrites as it says
        let e = t
            .endpoints("docker.io", "library/alpine/x", None, true)
            .unwrap();
        assert_eq!(hosts(&e), [("cache.test", "x"), ("internal", "x")]);
    }

    /// A mirror is insecure by its own entry only (or `--tls-verify=false`),
    /// never because of a block.  It may reach private addresses if the
    /// block of its own location allows it, or the block that lists it as
    /// a mirror (the administrator wrote it there); the block of a registry
    /// that does not list it gives it nothing.
    #[test]
    fn a_mirror_may_reach_private_addresses_by_its_own_block_or_the_one_that_lists_it() {
        let t = transport(
            "[[registry]]\nprefix = \"a.test\"\nallow-private-addresses = true\n\
             insecure = true\n\
             [[registry.mirror]]\nlocation = \"m.test/mirror\"\n\
             [[registry.mirror]]\nlocation = \"n.test/mirror\"\ninsecure = true\n\
             [[registry]]\nprefix = \"c.test\"\n\
             [[registry.mirror]]\nlocation = \"d.test/mirror\"\n\
             [[registry]]\nprefix = \"d.test\"\nallow-private-addresses = true\n\
             insecure = true\n",
            true,
        );
        // a.test may reach private addresses and is insecure: its mirrors
        // may reach them (it lists them) and are insecure only if they say so
        let e = t.endpoints("a.test", "x", None, true).unwrap();
        assert_eq!(
            hosts(&e),
            [
                ("m.test", "mirror/x"),
                ("n.test", "mirror/x"),
                ("a.test", "x")
            ]
        );
        let flags: Vec<_> = e.iter().map(|e| (e.insecure, e.allow_private)).collect();
        assert_eq!(flags, [(false, true), (true, true), (true, true)]);
        // the block of the mirror's own location allows private addresses
        // for it; that block's `insecure` does not make it insecure, and the
        // registry that lists it has none to give
        let e = t.endpoints("c.test", "x", None, true).unwrap();
        assert_eq!(hosts(&e), [("d.test", "mirror/x"), ("c.test", "x")]);
        let flags: Vec<_> = e.iter().map(|e| (e.insecure, e.allow_private)).collect();
        assert_eq!(flags, [(false, true), (false, false)]);
        // no verification of the certificates: every endpoint is insecure
        let t = transport(
            "[[registry]]\nprefix = \"c.test\"\n[[registry.mirror]]\nlocation = \"d.test\"\n",
            false,
        );
        let e = t.endpoints("c.test", "x", None, true).unwrap();
        assert!(e.len() == 2 && e.iter().all(|e| e.insecure && !e.allow_private));
    }

    /// A mirror that its own block blocks is not used, as containers/image
    /// skips it when it contacts it; the registry is.
    #[test]
    fn a_mirror_that_is_blocked_is_skipped() {
        let t = transport(
            "[[registry]]\nprefix = \"a.test\"\n\
             [[registry.mirror]]\nlocation = \"b.test/mirror\"\n\
             [[registry.mirror]]\nlocation = \"c.test/mirror\"\n\
             [[registry]]\nprefix = \"b.test\"\nblocked = true\n",
            true,
        );
        let e = t.endpoints("a.test", "x", None, true).unwrap();
        assert_eq!(hosts(&e), [("c.test", "mirror/x"), ("a.test", "x")]);
        assert!(t.resolve("b.test", "mirror/x").is_err());
    }

    /// The credentials of the command line are for the host that was named:
    /// a registry that a `location` moves to another host, and a mirror
    /// there, have what is stored for them; a mirror on the same host has
    /// the credentials of the command line too.
    #[test]
    fn command_line_credentials_follow_the_host_that_was_named() {
        let t = transport(
            "[[registry]]\nprefix = \"a.test\"\nlocation = \"internal.test\"\n\
             [[registry]]\nprefix = \"b.test\"\n\
             [[registry.mirror]]\nlocation = \"b.test/m\"\n\
             [[registry.mirror]]\nlocation = \"c.test\"\n",
            true,
        );
        let e = t.endpoints("a.test", "x", None, true).unwrap();
        assert_eq!(hosts(&e), [("internal.test", "x")]);
        assert!(!e[0].command_line);
        let e = t.endpoints("b.test", "x", None, true).unwrap();
        let named: Vec<_> = e.iter().map(|e| e.command_line).collect();
        assert_eq!(named, [true, false, true]);
    }
}
