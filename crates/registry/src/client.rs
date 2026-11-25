// SPDX-License-Identifier: Apache-2.0
//! Client of the OCI distribution API (pull and push).
//!
//! The client owns the authentication (anonymous or with credentials,
//! `Bearer` token flow with expiry and renewal, `Basic`), the manual
//! following of redirects (the `Authorization` header is only sent to the
//! registry origin, and no more once a request has left it; nothing goes from
//! HTTPS to HTTP, a redirect or an upload location), and the
//! redirect cache of blobs.  The connections, TLS settings and the scheme of
//! each registry are in [`super::transport`].

use super::auth::{AuthConfig, Credentials};
use super::hints::{Auth as HintAuth, HintStore, Note, Notices};
use super::netpolicy::{local_host, local_ip, lookup};
use super::target::{
    manifest_digest, manifest_reference, resolve_manifest, verify_digest, Challenge, Endpoint,
    EndpointSpec, Platform, Resolver, Target, TransportConfig, MAX_MANIFEST_SIZE,
};
use super::transport::{HostTransport, RedirectCache, Transport};
use base64::Engine;
use bytes::Bytes;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use reqwest::header::{
    HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_RANGE, CONTENT_TYPE, LOCATION, RANGE,
};
use reqwest::{Method, Response, StatusCode};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info};
use velarx_send_core as send_core;
use velarx_send_core::{Action, Answer, Event, Request, Why};
use velarx_types::digest::{Algorithm, Digest};
use velarx_types::{ImageError, ImageReference, ImageResult, OciDescriptor, OciManifest};

/// What stays as it is in a value of a URL query: the unreserved characters
/// of RFC 3986.
const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// How long a connection made in advance may take.
const PRECONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Lifetime of a token whose response does not say.
const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(60);

/// The longest a token is kept, whatever the registry says: a huge
/// `expires_in` must not overflow the clock.
const MAX_TOKEN_LIFETIME: Duration = Duration::from_secs(24 * 3600);

/// The registry's `expires_in` for a token (a default when it says none),
/// held between 30 s and a day.
fn token_lifetime(expires_in: Option<u64>) -> Duration {
    expires_in
        .map_or(DEFAULT_TOKEN_LIFETIME, Duration::from_secs)
        .clamp(Duration::from_secs(30), MAX_TOKEN_LIFETIME)
}

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, \
     application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.docker.distribution.manifest.list.v2+json";

struct CachedToken {
    value: String,
    expires: Instant,
}

/// Where a client that has no credentials gets the `Authorization` of the
/// requests to an endpoint: a pull worker asks the daemon, which asks a
/// worker that has the credentials of that endpoint only.
pub trait AuthBroker: Send + Sync {
    /// The header value for the endpoint `endpoint` (its index in the
    /// specs) and `actions`; none when it needs none.  `refresh` when the
    /// last one was refused.
    fn authorization<'a>(
        &'a self,
        endpoint: usize,
        actions: &'a str,
        refresh: bool,
    ) -> futures::future::BoxFuture<'a, ImageResult<Option<String>>>;
}

/// A broker and the endpoints it answers for (`host/repository` to the
/// index of the endpoint).
#[derive(Clone)]
struct Brokered {
    broker: Arc<dyn AuthBroker>,
    endpoints: Arc<HashMap<String, usize>>,
}

/// Registry client.  Cheap to clone: the connections, the tokens and the
/// redirect cache are shared by the clones (a client of other credentials has
/// its own tokens and redirect cache).
#[derive(Clone)]
pub struct RegistryClient {
    /// The configuration, the credentials and the certificates
    resolver: Resolver,
    transport: Arc<Transport>,
    brokered: Option<Brokered>,
    tokens: Arc<Mutex<HashMap<String, CachedToken>>>,
    /// Where the registry sent a blob, for the callers that have these
    /// credentials: what a registry gave one caller is not for another.
    redirects: Arc<RedirectCache>,
    challenges: Arc<Mutex<HashMap<String, Challenge>>>,
    hinting: Arc<Hinting>,
}

/// What a hint of the cache did in the requests of this client.
#[derive(Default)]
struct Hinting {
    /// Registries whose challenge came from a hint, and whether a request
    /// that used it was served
    seeded: Mutex<HashMap<String, bool>>,
    /// What the cache has for each registry (so that it is told only what
    /// differs)
    known: Mutex<HashMap<String, HintAuth>>,
    /// The requests tell what they find out
    reporting: std::sync::atomic::AtomicBool,
    /// Registries whose hint did not work: what `/v2/` says next replaces it
    relearn: Mutex<std::collections::HashSet<String>>,
    notices: Mutex<Notices>,
}

/// A text for a line of the user's terminal: no control characters, short.
fn brief(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(120)
        .collect()
}

/// The scheme, host and port of `url`, for a message.
fn url_origin(url: &str) -> String {
    reqwest::Url::parse(url)
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_else(|_| "the token endpoint".into())
}

/// Whether the token endpoint `realm` is the registry's own host (a cached
/// realm gets the credentials only from there).
fn realm_of_registry(registry: &str, realm: &str, https: bool) -> bool {
    let scheme = if https { "https" } else { "http" };
    match (
        reqwest::Url::parse(realm),
        reqwest::Url::parse(&format!("{scheme}://{registry}")),
    ) {
        (Ok(r), Ok(m)) => {
            r.host_str().is_some()
                && r.host_str().map(str::to_ascii_lowercase)
                    == m.host_str().map(str::to_ascii_lowercase)
                && r.port_or_known_default() == m.port_or_known_default()
        }
        _ => false,
    }
}

/// A request to the registry for [`RegistryClient::send_url`].
struct SendUrl<'a> {
    method: Method,
    url: &'a str,
    headers: &'a HeaderMap,
    body: Option<Bytes>,
    actions: &'a str,
    cache_key: Option<&'a str>,
}

impl RegistryClient {
    /// A client configured like the system: `registries.conf`, `certs.d`,
    /// `auth.json`.
    pub fn new() -> Result<Self, velarx_base::ids::IdsError> {
        Ok(Self::with_config(
            TransportConfig::system()?,
            AuthConfig::load()?,
        ))
    }

    pub fn with_config(config: TransportConfig, auth: AuthConfig) -> Self {
        Self::of(Resolver::with_config(config, auth))
    }

    /// A client for what `resolver` describes.
    pub fn of(resolver: Resolver) -> Self {
        Self {
            resolver,
            transport: Arc::new(Transport::default()),
            brokered: None,
            tokens: Arc::new(Mutex::new(HashMap::new())),
            redirects: Arc::default(),
            challenges: Arc::new(Mutex::new(HashMap::new())),
            hinting: Arc::default(),
        }
    }

    /// The configuration and the credentials it uses.
    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    /// Keep what the registries asked for in `store`, and give it to the
    /// workers (`endpoint_specs`).
    pub fn set_hints(&mut self, store: Option<Arc<HintStore>>) {
        self.resolver.set_hints(store);
    }

    /// Fail the downloads of this client that bring less than this.
    pub fn set_min_speed(&mut self, speed: crate::speed::Speed) {
        self.resolver.set_min_speed(speed);
    }

    /// The body of a response to a request of this client.
    pub fn body(&self, resp: Response) -> crate::body::Body {
        crate::body::Body::new(resp, self.resolver.speed())
    }

    pub fn hint_store(&self) -> Option<&Arc<HintStore>> {
        self.resolver.hint_store()
    }

    /// The transport of the host of `t`, made on first use.
    fn host(&self, t: &Target) -> ImageResult<Arc<HostTransport>> {
        self.transport.host(&t.endpoint, &t.certs)
    }

    /// A client with the same configuration and credentials but with the
    /// TLS verification set to `tls_verify` (`--tls-verify=false`).
    pub fn with_tls_verify(&self, tls_verify: bool) -> Self {
        if self.resolver.config().tls_verify == tls_verify {
            return self.clone();
        }
        Self {
            resolver: self.resolver.with_tls_verify(tls_verify),
            transport: Arc::new(Transport::default()),
            redirects: Arc::default(),
            challenges: Arc::new(Mutex::new(HashMap::new())),
            hinting: Arc::default(),
            ..self.clone()
        }
    }

    /// A client that holds no credentials of its own (the auth files and the
    /// credential helpers are not read).  What a request
    /// brings ([`with_access`](Self::with_access)) it still uses.
    pub fn without_credentials(&self) -> Self {
        Self {
            resolver: self.resolver.without_credentials(),
            brokered: None,
            tokens: Arc::new(Mutex::new(HashMap::new())),
            redirects: Arc::default(),
            ..self.clone()
        }
    }

    /// This client with the auth files read again (a `login` or a `logout`
    /// since it was made): the tokens taken with the old ones are dropped.
    /// Why not when the files cannot be read now.  `files`: the auth files
    /// of the process ([`crate::auth::default_auth_files`]).
    pub fn with_reloaded_credentials(&self, files: &[std::path::PathBuf]) -> Result<Self, String> {
        Ok(Self {
            resolver: self.resolver.with_reloaded_credentials(files)?,
            tokens: Arc::new(Mutex::new(HashMap::new())),
            redirects: Arc::default(),
            ..self.clone()
        })
    }

    /// A client with what a request brought: credentials before the
    /// client's, certificates instead of `certs.d`.
    pub fn with_access(&self, access: &super::auth::RegistryAccess) -> Self {
        if access.is_empty() {
            return self.clone();
        }
        Self {
            resolver: self.resolver.with_access(access),
            transport: match &access.certs {
                Some(_) => Arc::new(Transport::default()),
                None => self.transport.clone(),
            },
            // credentials of the request: the client's own, not a broker's
            brokered: None,
            // what was got with other credentials is not for these
            tokens: Arc::new(Mutex::new(HashMap::new())),
            redirects: Arc::default(),
            challenges: Arc::new(Mutex::new(HashMap::new())),
            hinting: Arc::default(),
        }
    }

    /// The endpoints to pull `image_ref` from: the mirrors that apply, then
    /// the registry.
    pub fn target(&self, image_ref: &ImageReference) -> ImageResult<Target> {
        self.resolver.target(image_ref)
    }

    /// The registry to push `image_ref` to: never a mirror.
    pub fn push_target(&self, image_ref: &ImageReference) -> ImageResult<Target> {
        self.resolver.push_target(image_ref)
    }

    /// The endpoints of `t` (the mirrors, then the registry) with the
    /// credentials and the certificates to reach them.
    pub fn endpoint_specs(&self, t: &Target) -> ImageResult<Vec<EndpointSpec>> {
        self.resolver.endpoint_specs(t)
    }

    /// The `Authorization` of the requests to `t` for `actions`, as a
    /// string (what a worker with the credentials of one endpoint answers
    /// for the others).
    pub async fn authorization_value(
        &self,
        t: &Target,
        actions: &str,
        refresh: bool,
    ) -> ImageResult<Option<String>> {
        self.authorization(t, actions, refresh)
            .await?
            .map(|v| {
                v.to_str()
                    .map(str::to_string)
                    .map_err(|_| ImageError::Registry("invalid authorization".into()))
            })
            .transpose()
    }

    /// The endpoints of `t` for pull workers that hold no credentials
    /// ([`Resolver::brokered_specs`]).
    pub fn brokered_specs(
        &self,
        t: &Target,
    ) -> ImageResult<(Vec<EndpointSpec>, Vec<Option<EndpointSpec>>)> {
        self.resolver.brokered_specs(t)
    }

    /// Take the `Authorization` of the brokered endpoints of `specs` from
    /// `broker`.
    pub fn set_broker(&mut self, specs: &[EndpointSpec], broker: Arc<dyn AuthBroker>) {
        let endpoints: HashMap<String, usize> = specs
            .iter()
            .enumerate()
            .filter(|(_, s)| s.brokered)
            .map(|(i, s)| (format!("{}/{}", s.host, s.repository), i))
            .collect();
        if !endpoints.is_empty() {
            self.brokered = Some(Brokered {
                broker,
                endpoints: Arc::new(endpoints),
            });
        }
    }

    /// A client with no configuration but these endpoints, and the target
    /// that is the first of them with the others as fallbacks.
    pub fn from_specs(specs: &[EndpointSpec]) -> ImageResult<(Self, Target)> {
        let mut client = Self::with_config(
            TransportConfig {
                registries: Default::default(),
                certs_dirs: Vec::new(),
                tls_verify: true,
            },
            AuthConfig::from_credentials(
                specs
                    .iter()
                    .filter_map(|s| {
                        s.credentials
                            .clone()
                            .map(|c| (format!("{}/{}", s.host, s.repository), c))
                    })
                    .collect::<Vec<_>>()
                    .iter()
                    .map(|(k, c)| (k.as_str(), c.clone())),
            ),
        );
        client.hinting.reporting.store(
            specs.iter().any(|s| s.hints),
            std::sync::atomic::Ordering::Relaxed,
        );
        for spec in specs {
            client.seed(spec);
        }
        if let Some(spec) = specs.first() {
            client.resolver.set_min_speed(spec.min_speed);
        }
        let mut targets = Vec::new();
        for spec in specs {
            let target = Target {
                endpoint: Endpoint {
                    host: spec.host.clone(),
                    repository: spec.repository.clone(),
                    insecure: spec.insecure,
                    allow_private: spec.allow_private,
                    // (what the spec has is what the endpoint is given)
                    command_line: false,
                    by_digest: None,
                },
                certs: spec.certs.clone(),
                mount_from: None,
                fallbacks: Vec::new(),
            };
            // (certificates that cannot be used fail here, not at the first
            // request)
            let host = client.host(&target)?;
            if let Some(scheme) = spec.scheme {
                host.know_scheme(scheme);
            }
            targets.push(target);
        }
        if targets.is_empty() {
            return Err(ImageError::Registry("no endpoint".into()));
        }
        let mut first = targets.remove(0);
        first.fallbacks = targets;
        Ok((client, first))
    }

    /// The registries.conf rules the client uses.
    pub fn registries(&self) -> &super::config::RegistriesConfig {
        self.resolver.registries()
    }

    /// Whether a request for `actions` goes without `Authorization` to
    /// learn the challenge of the registry: a pull from one that has no
    /// credentials for it and whose challenge is not known yet.
    async fn probes(&self, t: &Target, actions: &str) -> bool {
        actions == "pull"
            && self.brokered.is_none()
            && t.mount_from.is_none()
            && !self
                .challenges
                .lock()
                .unwrap()
                .contains_key(&t.endpoint.host)
            && matches!(self.credentials_blocking(t).await, Ok(None))
    }

    async fn challenge(&self, t: &Target, refresh: bool) -> ImageResult<Challenge> {
        let key = t.endpoint.host.clone();
        if refresh {
            self.drop_hint(&key, "the registry refused the token");
        } else if let Some(c) = self.challenges.lock().unwrap().get(&key) {
            return Ok(c.clone());
        }
        let url = format!("{}/v2/", self.host(t)?.base_url().await?);
        let resp = self.host(t)?.client()?.get(&url).send().await?;
        let challenge = match resp.status() {
            s if s.is_success() => Challenge::None,
            StatusCode::UNAUTHORIZED => {
                let header = resp
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        ImageError::Registry("Missing WWW-Authenticate header".into())
                    })?;
                Challenge::parse(header)?
            }
            s => {
                return Err(ImageError::Registry(format!(
                    "Unexpected response from registry: {s}"
                )))
            }
        };
        self.challenges
            .lock()
            .unwrap()
            .insert(key, challenge.clone());
        // (what `/v2/` says is not what a pull without credentials gets: a
        // registry may serve public content without a token whatever it
        // says there, which the first request finds out)
        let relearn = self
            .hinting
            .relearn
            .lock()
            .unwrap()
            .remove(&t.endpoint.host);
        if relearn || matches!(self.credentials_blocking(t).await, Ok(Some(_))) {
            self.learned(t, &challenge).await;
        }
        Ok(challenge)
    }

    /// Open the connection to the registry of `t` and leave it in the pool,
    /// with a request that costs the registry nothing (`HEAD /v2/` with no
    /// `Authorization`); whatever the answer, none is needed.
    async fn connect(&self, t: &Target) {
        let Ok(host) = self.host(t) else { return };
        let (Ok(client), Ok(base)) = (host.client(), host.base_url().await) else {
            return;
        };
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            client.head(format!("{base}/v2/")).send(),
        )
        .await;
    }

    /// Take what a hint says of a registry as its challenge.  A cached
    /// realm is held to what a live one is (`fetch_token`), and gets the
    /// credentials only if it is the registry's own.
    fn seed(&self, spec: &EndpointSpec) {
        let Some(hint) = spec
            .hint
            .as_ref()
            .filter(|h| h.is_sound() && !spec.brokered)
        else {
            return;
        };
        let secure = hint.transport == "https";
        if !secure && !spec.insecure {
            return;
        }
        let challenge = match &hint.auth {
            HintAuth::None => return,
            HintAuth::Basic => Challenge::Basic,
            HintAuth::Bearer { realm, service } => {
                // The token request carries the credentials of the pull, so
                // a cached realm gets one only if it is the registry's own
                // host; any other realm is learned live from the registry's
                // 401.  A cached realm of another host is never taken,
                // whether or not this client has credentials: they are
                // looked up when the token is asked for.
                if !realm_of_registry(&spec.host, realm, secure) {
                    debug!(
                        "{}: ignoring the cached token realm of another host",
                        spec.host
                    );
                    return;
                }
                Challenge::Bearer {
                    realm: realm.clone(),
                    service: service.clone(),
                }
            }
        };
        debug!(
            "{}: asking for a token as the cache of hints says",
            spec.host
        );
        self.hinting
            .known
            .lock()
            .unwrap()
            .insert(spec.host.clone(), hint.auth.clone());
        self.hinting
            .seeded
            .lock()
            .unwrap()
            .insert(spec.host.clone(), false);
        self.challenges
            .lock()
            .unwrap()
            .insert(spec.host.clone(), challenge);
    }

    /// Whether the challenge of `host` came from a hint that no request
    /// has been served with yet.
    fn on_trial(&self, host: &str) -> bool {
        self.hinting.seeded.lock().unwrap().get(host) == Some(&false)
    }

    /// A request that carried what the hint led to was served.
    fn hint_served(&self, host: &str) {
        if let Some(served) = self.hinting.seeded.lock().unwrap().get_mut(host) {
            *served = true;
        }
    }

    /// The hint of `host` led to a refusal: it is forgotten, with the tokens
    /// it got, and the user is told once.  False when there is no hint on
    /// trial, which a refusal is then nothing to do with.
    fn drop_hint(&self, host: &str, why: &str) -> bool {
        if !self.on_trial(host) {
            return false;
        }
        self.hinting.seeded.lock().unwrap().remove(host);
        self.challenges.lock().unwrap().remove(host);
        let prefix = format!("{host}|");
        self.tokens
            .lock()
            .unwrap()
            .retain(|k, _| !k.starts_with(&prefix));
        self.hinting.known.lock().unwrap().remove(host);
        self.hinting
            .relearn
            .lock()
            .unwrap()
            .insert(host.to_string());
        let mut notices = self.hinting.notices.lock().unwrap();
        notices.warnings.push(format!(
            "{host}: the cached authentication hint did not work ({}); asked the registry again",
            brief(why)
        ));
        notices.hints.push(Note::Forget {
            registry: host.to_string(),
        });
        debug!("{host}: the cached authentication hint was dropped: {why}");
        true
    }

    /// The registry of `t` asked for `challenge` (it was told so): to be
    /// kept if it is not what the cache has.
    async fn learned(&self, t: &Target, challenge: &Challenge) {
        use std::sync::atomic::Ordering::Relaxed;
        if !self.hinting.reporting.load(Relaxed) {
            return;
        }
        let auth = match challenge {
            Challenge::None => HintAuth::None,
            Challenge::Basic => HintAuth::Basic,
            Challenge::Bearer { realm, service } => HintAuth::Bearer {
                realm: realm.clone(),
                service: service.clone(),
            },
        };
        let Ok(transport) = self.host(t) else { return };
        let Ok(scheme) = transport.scheme().await else {
            return;
        };
        let host = &t.endpoint.host;
        if self
            .hinting
            .known
            .lock()
            .unwrap()
            .insert(host.clone(), auth.clone())
            == Some(auth.clone())
        {
            return;
        }
        self.hinting.notices.lock().unwrap().hints.push(Note::Auth {
            registry: host.clone(),
            transport: scheme.as_str().to_string(),
            auth,
        });
    }

    /// What the requests found out since the last call.
    pub fn take_notices(&self) -> Notices {
        let mut notices = std::mem::take(&mut *self.hinting.notices.lock().unwrap());
        notices.schemes = self.transport.untold_schemes();
        notices
    }

    /// Where the endpoint that served the blob `digest` sent it, if it did,
    /// and the place of that endpoint in the chain of `t` (`get_blob` leaves
    /// the redirect of no other).
    pub fn redirect_of(&self, t: &Target, digest: &Digest) -> Option<(usize, String)> {
        t.chain()
            .enumerate()
            .find_map(|(i, e)| Some((i, self.redirects.get(&e.blob_key(digest))?)))
    }

    /// Remember where the registry sent the blob `digest` (another worker
    /// was told): an address that is not the registry's own, and not plain
    /// HTTP from a registry that is reached over HTTPS.
    pub async fn set_redirect(&self, t: &Target, digest: &Digest, url: &str) {
        let Ok(parsed) = reqwest::Url::parse(url) else {
            return;
        };
        let Ok(host) = self.host(t) else { return };
        let secure = host.base_url().await.is_ok_and(|b| b.starts_with("https:"));
        if !matches!(parsed.scheme(), "https" | "http") || (secure && parsed.scheme() != "https") {
            return;
        }
        if self.may_redirect_to(t, &parsed).await {
            self.redirects.put(&t.blob_key(digest), url);
        }
    }

    /// Whether the policy of the registry of `t` lets a request go to `url`
    /// (a private address only for a registry that is on one): a redirect
    /// is remembered, and used again, only if it does.
    async fn may_redirect_to(&self, t: &Target, url: &reqwest::Url) -> bool {
        match self.host(t) {
            Ok(host) => host.check_url(url).await.is_ok(),
            Err(_) => false,
        }
    }

    /// Open the connection to the registry of `t` and take the token for
    /// pulling, as the first request would, so that the requests that
    /// follow find them.
    pub async fn warm(&self, t: &Target) -> ImageResult<()> {
        self.authorization(t, "pull", false).await?;
        if self.brokered.is_some() {
            // (the token did not come from this connection)
            let url = format!("{}/v2/", self.host(t)?.base_url().await?);
            self.host(t)?.client()?.get(&url).send().await?;
        }
        Ok(())
    }

    /// Whether the registry of `t` takes the credentials of this client
    /// (`login`): `GET /v2/` with them, as `podman login` does.
    pub async fn check_login(&self, t: &Target) -> ImageResult<()> {
        let invalid = || ImageError::Unauthorized("invalid username/password".into());
        let host = t.endpoint.host.clone();
        // (a registry that cannot be reached is not one that refused)
        let unreachable = |url: &str, e: &(dyn std::error::Error + 'static)| {
            ImageError::Unreachable(format!(
                "authenticating creds for \"{host}\": pinging container registry {host}: Get \"{url}\": {}",
                go_cause(&host, e)
            ))
        };
        let base = match self.host(t)?.base_url().await {
            Ok(b) => b,
            Err(ImageError::Http(e)) => {
                return Err(unreachable(&format!("https://{host}/v2/"), e.cause()))
            }
            Err(e) => return Err(e),
        };
        let url = format!("{base}/v2/");
        let auth = match self.authorization(t, "", false).await {
            Ok(a) => a,
            Err(ImageError::Http(e)) => return Err(unreachable(&url, e.cause())),
            Err(_) => return Err(invalid()),
        };
        let mut request = self.host(t)?.client()?.get(&url);
        if let Some(a) = auth {
            request = request.header(AUTHORIZATION, a);
        }
        let status = request
            .send()
            .await
            .map_err(|e| unreachable(&url, &e))?
            .status();
        match status {
            s if s.is_success() => Ok(()),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(invalid()),
            s => Err(ImageError::Registry(format!(
                "unexpected status {s} from {url}"
            ))),
        }
    }

    /// Open a connection to the CDN at `url` (a hint, or where a blob was
    /// sent) and leave it in the pool of the registry's client, where the
    /// requests that are sent there later find it.  Nothing but the
    /// connection and a request for the address itself, without any
    /// `Authorization`, is sent; whatever happens is of no consequence.
    pub async fn preconnect(&self, t: &Target, url: Option<&str>) {
        let Some(url) = url.and_then(|u| reqwest::Url::parse(u).ok()) else {
            return;
        };
        let Ok(host) = self.host(t) else { return };
        let secure = host.base_url().await.is_ok_and(|b| b.starts_with("https:"));
        let registry_local = reqwest::Url::parse(&format!("https://{}/", t.endpoint.host))
            .ok()
            .and_then(|u| u.host_str().map(local_host))
            .unwrap_or(false);
        if !matches!(url.scheme(), "https" | "http")
            || (secure && url.scheme() != "https")
            || url
                .host_str()
                .is_none_or(|h| local_host(h) && !registry_local)
            || !url.username().is_empty()
        {
            return;
        }
        let Ok(client) = host.client() else { return };
        let port = url.port_or_known_default().unwrap_or(443);
        let connect = async {
            // A name is resolved here, once, and refused when it leads to
            // this machine or a private network (unless the registry is on
            // one); the connection is then made to the addresses that were
            // checked.
            let name = url
                .host_str()
                .filter(|h| h.parse::<std::net::IpAddr>().is_err() && !h.starts_with('['));
            let _pin = match name {
                Some(name) if !registry_local => {
                    let addrs = match lookup(name, port).await {
                        Ok(addrs) => addrs,
                        Err(e) => {
                            debug!("cannot resolve {name} to connect in advance: {e}");
                            return None;
                        }
                    };
                    let local = addrs.iter().any(|a| local_ip(a.ip()));
                    // (a test names the loopback address it can reach public)
                    #[cfg(test)]
                    let local = local && !hint_tests::pretend_public(name);
                    if addrs.is_empty() || local {
                        debug!("{name} is not connected to in advance: it is not a public address");
                        return None;
                    }
                    Some(host.pin(name, addrs))
                }
                _ => None,
            };
            Some(client.head(url.clone()).send().await)
        };
        match tokio::time::timeout(PRECONNECT_TIMEOUT, connect).await {
            Ok(Some(Ok(_))) => debug!("connected to {} in advance", url.authority()),
            Ok(Some(Err(e))) => debug!("cannot connect to {} in advance: {e}", url.authority()),
            Ok(None) => {}
            Err(_) => debug!("connecting to {} in advance took too long", url.authority()),
        }
    }

    /// Run the credential helpers in `runner` (this process cannot).
    pub fn set_helper_runner(&mut self, runner: Arc<super::helper::HelperRunner>) {
        self.resolver.set_helper_runner(runner);
    }

    fn credentials(&self, t: &Target) -> ImageResult<Option<Credentials>> {
        self.resolver.credentials(t)
    }

    /// [`credentials`](Self::credentials) for an async caller: a lookup that
    /// may run a helper (or wait for the runner's answer) is on a thread
    /// of the blocking pool, not on one of the runtime.
    async fn credentials_blocking(&self, t: &Target) -> ImageResult<Option<Credentials>> {
        if !self.resolver.auth().runs_helpers() {
            return self.credentials(t);
        }
        let auth = self.resolver.auth().clone();
        let (host, repository) = (t.endpoint.host.clone(), t.endpoint.repository.clone());
        let command_line = t.endpoint.command_line;
        tokio::task::spawn_blocking(move || auth.lookup_for(command_line, &host, &repository))
            .await
            .map_err(|e| ImageError::Registry(format!("credential lookup: {e}")))?
            .map_err(ImageError::Registry)
    }

    /// The `Authorization` header value for requests to the registry, if it
    /// needs one.  `actions` is `pull` or `pull,push`.
    async fn authorization(
        &self,
        t: &Target,
        actions: &str,
        refresh: bool,
    ) -> ImageResult<Option<HeaderValue>> {
        if let Some(b) = &self.brokered {
            let key = format!("{}/{}", t.endpoint.host, t.endpoint.repository);
            if let Some(&i) = b.endpoints.get(&key) {
                if t.mount_from.is_some() {
                    return Err(ImageError::Registry(
                        "a mount needs the credentials of the destination".into(),
                    ));
                }
                // kept a little: a pull makes many requests, each would ask
                let key = format!("brokered|{i}|{actions}");
                if !refresh {
                    if let Some(tok) = self.tokens.lock().unwrap().get(&key) {
                        if tok.expires > Instant::now() {
                            return Ok(Some(bearer_or_raw(&tok.value)?));
                        }
                    }
                }
                return match b.broker.authorization(i, actions, refresh).await? {
                    None => Ok(None),
                    Some(v) => {
                        let header = bearer_or_raw(&v)?;
                        self.tokens.lock().unwrap().insert(
                            key,
                            CachedToken {
                                value: v,
                                expires: Instant::now() + BROKERED_LIFETIME,
                            },
                        );
                        Ok(Some(header))
                    }
                };
            }
        }
        let challenge = self.challenge(t, refresh).await?;
        let value = match challenge {
            Challenge::None => return Ok(None),
            Challenge::Basic => {
                let c = self
                    .credentials_blocking(t)
                    .await?
                    .filter(Credentials::has_basic)
                    .ok_or_else(|| {
                        ImageError::Unauthorized(format!(
                            "{} requires credentials (see `login`)",
                            t.endpoint.host
                        ))
                    })?;
                let b64 = base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", c.username, c.password));
                format!("Basic {b64}")
            }
            Challenge::Bearer { realm, service } => {
                if let Some(token) = self
                    .credentials_blocking(t)
                    .await?
                    .and_then(|c| c.registry_token)
                {
                    return Ok(Some(bearer_header(&token)?));
                }
                let key = format!(
                    "{}|{}|{}|{}",
                    t.endpoint.host,
                    t.endpoint.repository,
                    actions,
                    t.mount_from.as_deref().unwrap_or("")
                );
                if !refresh {
                    let tokens = self.tokens.lock().unwrap();
                    if let Some(tok) = tokens.get(&key) {
                        if tok.expires > Instant::now() {
                            return Ok(Some(bearer_header(&tok.value)?));
                        }
                    }
                }
                // With the realm from a hint the registry is not spoken to
                // yet: its connection is made while the token comes, as it
                // would have been by the request that learns the realm.
                // The token does not wait for it: the connection is made
                // on its own, and a request that comes before it is made
                // opens one itself.
                if self.on_trial(&t.endpoint.host) {
                    let (client, target) = (self.clone(), t.clone());
                    tokio::spawn(async move { client.connect(&target).await });
                }
                let token = match self
                    .fetch_token(t, &realm, service.as_deref(), actions)
                    .await
                {
                    Ok(token) => token,
                    Err(e) => {
                        // a realm that came from a hint and does not work:
                        // the registry is asked what it wants
                        // (the status, not what the endpoint wrote)
                        let why = match &e {
                            ImageError::Http(_) => "network error".to_string(),
                            e => {
                                let text = e.to_string();
                                let text = text.trim_start_matches("registry error: ");
                                text.split(" - ").next().unwrap_or(text).to_string()
                            }
                        };
                        if self.drop_hint(&t.endpoint.host, &format!("token endpoint: {why}")) {
                            return Box::pin(self.authorization(t, actions, false)).await;
                        }
                        return Err(e);
                    }
                };
                let header = bearer_header(&token.value)?;
                self.tokens.lock().unwrap().insert(key, token);
                return Ok(Some(header));
            }
        };
        HeaderValue::from_str(&value)
            .map(|mut v| {
                v.set_sensitive(true);
                Some(v)
            })
            .map_err(|_| ImageError::Registry("invalid credentials".into()))
    }

    async fn fetch_token(
        &self,
        t: &Target,
        realm: &str,
        service: Option<&str>,
        actions: &str,
    ) -> ImageResult<CachedToken> {
        let url = reqwest::Url::parse(realm)
            .map_err(|e| ImageError::Registry(format!("invalid token realm `{realm}`: {e}")))?;
        if url.scheme() != "https" && !self.host(t)?.insecure {
            return Err(ImageError::Registry(format!(
                "refusing the token realm `{realm}`: not HTTPS"
            )));
        }
        self.host(t)?.check_url(&url).await?;
        let scope = format!("repository:{}:{}", t.endpoint.repository, actions);
        let mount_scope = t
            .mount_from
            .as_ref()
            .map(|from| format!("repository:{from}:pull"));
        let credentials = self.credentials_blocking(t).await?;
        let mut resp = None;
        if let Some(refresh) = credentials
            .as_ref()
            .and_then(|c| c.identity_token.as_deref())
        {
            // OAuth2: the refresh token for a bearer token, POSTed (never
            // in a URL); a realm that does not support it gets the GET
            let scopes = std::iter::once(scope.as_str())
                .chain(mount_scope.as_deref())
                .collect::<Vec<_>>()
                .join(" ");
            let form = [
                ("grant_type", "refresh_token"),
                ("client_id", "velarx"),
                ("service", service.unwrap_or("")),
                ("scope", scopes.as_str()),
                ("refresh_token", refresh),
            ];
            let r = self
                .host(t)?
                .client()?
                .post(url.clone())
                .form(&form)
                .send()
                .await?;
            if !matches!(
                r.status(),
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ) {
                resp = Some(r);
            }
        }
        let resp = match resp {
            Some(r) => r,
            None => {
                let mut url = url;
                {
                    let mut q = url.query_pairs_mut();
                    if let Some(service) = service {
                        q.append_pair("service", service);
                    }
                    q.append_pair("scope", &scope);
                    if let Some(m) = &mount_scope {
                        q.append_pair("scope", m);
                    }
                }
                let mut req = self.host(t)?.client()?.get(url);
                if let Some(c) = credentials.as_ref().filter(|c| c.has_basic()) {
                    req = req.basic_auth(&c.username, Some(&c.password));
                }
                req.send().await?
            }
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let body = read_limited(resp, 4096).await.unwrap_or_default();
            debug!(
                "token endpoint {realm} answered {status}: {}",
                brief(&String::from_utf8_lossy(&body))
            );
            return Err(answered(
                status,
                format!("Failed to get a token from {}: {status}", url_origin(realm)),
            ));
        }
        #[derive(Deserialize)]
        struct TokenResponse {
            token: Option<String>,
            access_token: Option<String>,
            expires_in: Option<u64>,
        }
        let body = read_limited(resp, 1024 * 1024).await?;
        let parsed: TokenResponse = serde_json::from_slice(&body)?;
        let value = parsed
            .token
            .or(parsed.access_token)
            .ok_or_else(|| ImageError::Registry("No token in response".into()))?;
        Ok(CachedToken {
            value,
            // Renew a little before the expiry.
            expires: Instant::now() + token_lifetime(parsed.expires_in) - Duration::from_secs(10),
        })
    }

    /// Send a request to the registry and follow the redirects by hand.
    /// `url` is absolute.  `headers` must not contain `Authorization`.  What
    /// is sent where, and when to stop, is decided by [`send_core`] from
    /// what each answer was.
    async fn send_url(&self, t: &Target, request: SendUrl<'_>) -> ImageResult<Response> {
        let SendUrl {
            method,
            url,
            headers,
            body,
            actions,
            cache_key,
        } = request;
        let mut start = reqwest::Url::parse(url)
            .map_err(|e| ImageError::Registry(format!("invalid URL `{url}`: {e}")))?;
        // The registry's own place: only a request to it gets the
        // credentials, and any other place is checked as a redirect is
        // (the URL of an upload session is the registry's word too).
        let host = self.host(t)?;
        let home = reqwest::Url::parse(&host.base_url().await?)
            .map_err(|e| ImageError::Registry(format!("invalid registry URL: {e}")))?;
        // The location an https registry behind a proxy that does not
        // pass the scheme gives is its own address over http: it is the
        // registry, and is asked over https.
        if home.scheme() == "https" && start.scheme() == "http" {
            let mut secure = start.clone();
            if secure.set_scheme("https").is_ok() && same_origin(&home, &secure) {
                start = secure;
            }
        }
        let (first, mut problem) = judge(&host, &home, &start, &start).await;
        let (mut state, mut action) = send_core::begin(&send_core::Begin {
            home_https: home.scheme() == "https",
            start: first,
            method: core_method(&method),
            body: body.as_ref().is_some_and(|b| !b.is_empty()),
            cacheable: cache_key.is_some(),
        });
        let (mut current, mut probe, mut auth, mut last) = (start.clone(), false, None, None);
        loop {
            let event = match action {
                Action::Pass { refresh } => {
                    // A registry that is not known to ask for a token is
                    // asked for the thing itself first: its 401 says what
                    // it wants, which the `GET /v2/` would cost a round
                    // trip to learn.
                    probe = !refresh && self.probes(t, actions).await;
                    auth = if probe {
                        None
                    } else {
                        self.authorization(t, actions, refresh).await?
                    };
                    current = start.clone();
                    Event::Authed {
                        probe,
                        held: auth.is_some(),
                    }
                }
                Action::Send(send) => {
                    let (verb, has_body, authorized, remember) = match send {
                        Request::Home { auth, method, body } => (method, body, auth, false),
                        Request::Away {
                            method,
                            body,
                            remember,
                        } => (method, body, false, remember),
                    };
                    let verb = match verb {
                        send_core::Method::Get => Method::GET,
                        send_core::Method::Head => Method::HEAD,
                        send_core::Method::Other => method.clone(),
                    };
                    // The target is remembered when the registry sent us to
                    // another place (the CDN of a blob).
                    if let (true, Some(key)) = (remember, cache_key) {
                        self.redirects.put(key, current.as_str());
                    }
                    // A connection the server closed while it was idle is
                    // found out by the request that uses it: a request that
                    // reads is sent again on another.
                    let mut again = 0;
                    let resp = loop {
                        let mut req = host
                            .client()?
                            .request(verb.clone(), current.clone())
                            .headers(headers.clone());
                        if let (true, Some(a)) = (authorized, &auth) {
                            req = req.header(AUTHORIZATION, a.clone());
                        }
                        if let Some(b) = body.as_ref().filter(|_| has_body) {
                            req = req.body(b.clone());
                        }
                        match req.send().await {
                            Ok(r) => break r,
                            Err(e)
                                if again < 2
                                    && (verb == Method::GET || verb == Method::HEAD)
                                    && connection_lost(&e) =>
                            {
                                again += 1;
                                debug!("{}: {e}: trying again", current);
                            }
                            Err(e) => return Err(e.into()),
                        }
                    };
                    let status = resp.status();
                    let hinted = authorized
                        && matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
                        && self.drop_hint(
                            &t.endpoint.host,
                            &format!("the registry answered {}", status.as_u16()),
                        );
                    if authorized && !hinted {
                        self.hint_served(&t.endpoint.host);
                    }
                    let home_probe = probe && matches!(send, Request::Home { .. });
                    if home_probe && (status.is_success() || status.is_redirection()) {
                        // served without a token: the registry asks for none
                        // (the next requests do not look up credentials
                        // again; a 401 later asks `/v2/` for the challenge)
                        self.challenges
                            .lock()
                            .unwrap()
                            .entry(t.endpoint.host.clone())
                            .or_insert(Challenge::None);
                    }
                    let answer = if hinted {
                        Answer::Hinted
                    } else if status == StatusCode::UNAUTHORIZED {
                        Answer::Unauthorized {
                            challenge: home_probe && self.learn(t, &resp).await,
                        }
                    } else if matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND) {
                        Answer::Missing
                    } else if status.is_redirection() && status != StatusCode::NOT_MODIFIED {
                        match location(&resp, &current) {
                            Ok(next) => {
                                let (to, refusal) = judge(&host, &home, &start, &next).await;
                                problem = refusal;
                                current = next;
                                Answer::Redirect {
                                    keeps: matches!(
                                        status,
                                        StatusCode::TEMPORARY_REDIRECT
                                            | StatusCode::PERMANENT_REDIRECT
                                    ),
                                    next: to,
                                }
                            }
                            Err(e) => {
                                problem = Some(e);
                                Answer::Unusable
                            }
                        }
                    } else {
                        Answer::Served
                    };
                    last = Some(resp);
                    Event::Got(answer)
                }
                Action::AskV2 => {
                    // Not every registry answers a request without a token
                    // with a 401: ask `/v2/`; the challenge it gives (kept
                    // for the host, so no request probes again) is used for
                    // one more try.  When `/v2/` does not say, the answer
                    // stands.
                    let learned = self.challenge(t, true).await;
                    debug!(
                        "{}: refused without a token, /v2/: {learned:?}",
                        t.endpoint.host
                    );
                    Event::V2(learned.is_ok())
                }
                Action::Done => return Ok(last.expect("a request is answered before it is done")),
                Action::Refuse(why) => {
                    return Err(match why {
                        Why::TooMany => {
                            ImageError::Registry(format!("too many redirects for `{url}`"))
                        }
                        Why::Downgrade if last.is_none() => ImageError::Registry(format!(
                            "the https registry gave an http:// location `{url}`; refused. \
                             Fix the registry: distribution `http.relativeurls: true`, or \
                             have the proxy pass `X-Forwarded-Proto: https`."
                        )),
                        Why::Downgrade => ImageError::Registry(format!(
                            "refusing to go from https to `{current}`"
                        )),
                        Why::Body => ImageError::Registry(format!(
                            "refusing to send the request body to `{}`",
                            current.origin().ascii_serialization()
                        )),
                        Why::Location | Why::Policy => {
                            problem.expect("the answer that is refused says why")
                        }
                        // the loop tells the events in the order it asks them
                        Why::OutOfTurn => ImageError::Registry(
                            "internal error: the send loop got an event out of turn".into(),
                        ),
                    });
                }
            };
            (state, action) = send_core::step(&state, &event);
        }
    }

    /// The challenge a registry gave to a request without a token, kept
    /// for it; false when it gave none that is understood.
    async fn learn(&self, t: &Target, resp: &Response) -> bool {
        let Some(c) = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .and_then(|h| Challenge::parse(h).ok())
        else {
            return false;
        };
        self.challenges
            .lock()
            .unwrap()
            .insert(t.endpoint.host.clone(), c.clone());
        self.learned(t, &c).await;
        true
    }

    fn api_url(base: &str, t: &Target, path: &str) -> String {
        format!("{}/v2/{}/{}", base, t.endpoint.repository, path)
    }

    /// GET a blob (the whole of it, or the bytes of `range`, a value for the
    /// `Range` header) from the first endpoint that has it.  The response is
    /// returned whatever its status is once the redirects are followed (the
    /// one of the last endpoint if none succeeded); the caller checks it.
    pub async fn get_blob(
        &self,
        t: &Target,
        digest: &Digest,
        range: Option<&str>,
    ) -> ImageResult<Response> {
        let mut last = Err(ImageError::Registry("no endpoint".into()));
        for (i, endpoint) in t.chain().enumerate() {
            match self.get_blob_from(endpoint, digest, range).await {
                Ok(resp) if resp.status().is_success() => {
                    // where the others sent it led nowhere
                    for other in t
                        .chain()
                        .enumerate()
                        .filter_map(|(j, e)| (j != i).then_some(e))
                    {
                        self.redirects.drop_key(&other.blob_key(digest));
                    }
                    return Ok(resp);
                }
                other => {
                    debug!(
                        "{} did not give {digest}: {}",
                        endpoint.endpoint.host,
                        match &other {
                            Ok(r) => r.status().to_string(),
                            Err(e) => e.to_string(),
                        }
                    );
                    last = other;
                }
            }
        }
        last
    }

    /// The answer of `tags/list` for the repository of T: every page of the
    /// tags (the `Link` to the next one, a `tags/list` of the same
    /// repository only, at most [`TAG_PAGES`] pages) as the JSON
    /// `{"name", "tags"}`, at most MAX_MANIFEST_SIZE bytes of pages.
    pub async fn list_tags_raw(&self, t: &Target) -> ImageResult<Bytes> {
        let base = self.host(t)?.base_url().await?;
        let first = Self::api_url(&base, t, "tags/list");
        let list = format!("/v2/{}/tags/list", t.endpoint.repository);
        let mut url = first;
        let mut tags: Vec<serde_json::Value> = Vec::new();
        let mut name = serde_json::Value::Null;
        let mut left = MAX_MANIFEST_SIZE;
        let mut pages = 0;
        loop {
            let resp = self
                .send_url(
                    t,
                    SendUrl {
                        method: Method::GET,
                        url: &url,
                        headers: &HeaderMap::new(),
                        body: None,
                        actions: "pull",
                        cache_key: None,
                    },
                )
                .await?;
            if !resp.status().is_success() {
                return Err(answered(
                    resp.status(),
                    format!(
                        "listing the tags of {}: {}",
                        t.endpoint.repository,
                        resp.status()
                    ),
                ));
            }
            let next = resp
                .headers()
                .get(reqwest::header::LINK)
                .and_then(|l| l.to_str().ok())
                .and_then(|l| next_page(l, &list));
            let body = read_limited_by(resp, left, self.resolver.speed()).await?;
            pages += 1;
            let Some(next) = next else {
                // one page: as the registry sent it
                if pages == 1 {
                    return Ok(body);
                }
                let page: serde_json::Value = serde_json::from_slice(&body)?;
                tags.extend(page["tags"].as_array().into_iter().flatten().cloned());
                break;
            };
            left = left.saturating_sub(body.len() as u64);
            let page: serde_json::Value = serde_json::from_slice(&body)?;
            if name.is_null() {
                name = page["name"].clone();
            }
            tags.extend(page["tags"].as_array().into_iter().flatten().cloned());
            if pages >= TAG_PAGES {
                return Err(ImageError::Registry(format!(
                    "listing the tags of {}: more than {TAG_PAGES} pages",
                    t.endpoint.repository
                )));
            }
            url = format!("{base}{next}");
        }
        Ok(Bytes::from(serde_json::to_vec(
            &serde_json::json!({ "name": name, "tags": tags }),
        )?))
    }

    /// What the registry of T answers to a search of NEEDLE: its v1 search
    /// (Docker's index for docker.io), else its catalog; the body (at most
    /// LIMIT bytes) and whether it is the v1 one.
    pub async fn search_raw(
        &self,
        t: &Target,
        needle: &str,
        n: usize,
        docker: bool,
        limit: u64,
    ) -> ImageResult<(bool, Bytes)> {
        let host = self.host(t)?;
        let http = host.client()?;
        let base = if docker {
            "https://index.docker.io".to_string()
        } else {
            host.base_url().await?
        };
        let v1 = http
            .get(format!("{base}/v1/search"))
            .query(&[("q", needle), ("n", &n.to_string())])
            .send()
            .await;
        if let Ok(resp) = v1 {
            if resp.status().is_success() {
                let body = read_limited_by(resp, limit, self.resolver.speed()).await?;
                if serde_json::from_slice::<serde_json::Value>(&body).is_ok() {
                    return Ok((true, body));
                }
            }
        }
        // the catalog's pages (its `Link` to the next one), LIMIT bytes in all
        let mut url = format!("{base}/v2/_catalog");
        let mut repositories: Vec<serde_json::Value> = Vec::new();
        let mut left = limit;
        for _ in 0..CATALOG_PAGES {
            // (with the credentials of the registry, as its other requests:
            // a registry may list its repositories to the users it knows only)
            let resp = self
                .send_url(
                    t,
                    SendUrl {
                        method: Method::GET,
                        url: &url,
                        headers: &HeaderMap::new(),
                        body: None,
                        actions: "pull",
                        cache_key: None,
                    },
                )
                .await?;
            if !resp.status().is_success() {
                return Err(answered(
                    resp.status(),
                    format!(
                        "the registry has no search and its catalog answered {}",
                        resp.status()
                    ),
                ));
            }
            let next = resp
                .headers()
                .get(reqwest::header::LINK)
                .and_then(|l| l.to_str().ok())
                .and_then(next_catalog_page);
            let body = read_limited_by(resp, left, self.resolver.speed()).await?;
            left = left.saturating_sub(body.len() as u64);
            let page: serde_json::Value = serde_json::from_slice(&body)?;
            repositories.extend(
                page["repositories"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .cloned(),
            );
            match next {
                Some(path) => url = format!("{base}{path}"),
                None => break,
            }
        }
        let body = serde_json::to_vec(&serde_json::json!({ "repositories": repositories }))?;
        Ok((false, Bytes::from(body)))
    }

    async fn get_blob_from(
        &self,
        t: &Target,
        digest: &Digest,
        range: Option<&str>,
    ) -> ImageResult<Response> {
        let mut headers = HeaderMap::new();
        if let Some(range) = range {
            headers.insert(
                reqwest::header::RANGE,
                HeaderValue::from_str(range).map_err(|e| ImageError::Registry(e.to_string()))?,
            );
        }
        let key = t.blob_key(digest);
        let cached = match self.redirects.get(&key) {
            Some(c) => match reqwest::Url::parse(&c) {
                Ok(url) if self.may_redirect_to(t, &url).await => Some(c),
                _ => {
                    self.redirects.drop_key(&key);
                    None
                }
            },
            None => None,
        };
        if let Some(cached) = cached {
            match self
                .host(t)?
                .client()?
                .get(&cached)
                .headers(headers.clone())
                .send()
                .await
            {
                Ok(resp)
                    if !matches!(
                        resp.status(),
                        StatusCode::UNAUTHORIZED
                            | StatusCode::FORBIDDEN
                            | StatusCode::NOT_FOUND
                            | StatusCode::GONE
                    ) && !resp.status().is_server_error()
                        && !resp.status().is_redirection() =>
                {
                    return Ok(resp);
                }
                Ok(resp) => {
                    debug!("cached redirect of {} answered {}", digest, resp.status());
                    self.redirects.drop_key(&key);
                }
                Err(e) => {
                    debug!("cached redirect of {} failed: {}", digest, e);
                    self.redirects.drop_key(&key);
                }
            }
        }
        let base = self.host(t)?.base_url().await?;
        let url = Self::api_url(&base, t, &format!("blobs/{digest}"));
        self.send_url(
            t,
            SendUrl {
                method: Method::GET,
                url: &url,
                headers: &headers,
                body: None,
                actions: "pull",
                cache_key: Some(&key),
            },
        )
        .await
    }

    /// GET a blob that must be small: at most `limit` bytes, whose digest
    /// and size are checked against the descriptor.
    pub async fn get_small_blob(
        &self,
        t: &Target,
        desc: &OciDescriptor,
        limit: u64,
    ) -> ImageResult<Bytes> {
        if desc.size < 0 || desc.size as u64 > limit {
            return Err(ImageError::Registry(format!(
                "blob {} is too large ({} bytes, at most {} are accepted)",
                desc.digest, desc.size, limit
            )));
        }
        let resp = self.get_blob(t, &desc.digest, None).await?;
        if !resp.status().is_success() {
            return Err(answered(
                resp.status(),
                format!("Failed to get blob {}: {}", desc.digest, resp.status()),
            ));
        }
        let body = read_limited_by(resp, desc.size as u64, self.resolver.speed()).await?;
        if body.len() as i64 != desc.size {
            return Err(ImageError::Registry(format!(
                "blob {} has {} bytes, the descriptor says {}",
                desc.digest,
                body.len(),
                desc.size
            )));
        }
        verify_digest(&desc.digest, &body)?;
        Ok(body)
    }

    /// The manifest of `image_ref` and its digest.  An index or manifest
    /// list is resolved to the manifest of the platform of the host.  A
    /// digest reference is checked against the bytes received; the digest
    /// returned is always the one computed here.
    pub async fn get_manifest(
        &self,
        image_ref: &ImageReference,
    ) -> ImageResult<(OciManifest, Digest)> {
        let (manifest, digest, _) = self.get_manifest_raw(image_ref, None).await?;
        Ok((manifest, digest))
    }

    /// Like `get_manifest`, with the bytes of the manifest, which `digest`
    /// is the digest of.
    pub async fn get_manifest_raw(
        &self,
        image_ref: &ImageReference,
        platform: Option<&Platform>,
    ) -> ImageResult<(OciManifest, Digest, Bytes)> {
        let t = self.target(image_ref)?;
        resolve_manifest(image_ref, platform, |reference| {
            let t = t.clone();
            async move { self.fetch_manifest(&t, &reference).await }
        })
        .await
    }

    /// A manifest from the first endpoint that has it, with the digest of
    /// its bytes ([`manifest_digest`]).
    pub async fn fetch_manifest(
        &self,
        t: &Target,
        reference: &str,
    ) -> ImageResult<(Bytes, Digest)> {
        self.fetch_manifest_or_missing(t, reference).await?
    }

    /// The manifest `reference`, or Err(Ok(the error of a 404)): the same
    /// request as `fetch_manifest`.
    pub async fn fetch_manifest_or_missing(
        &self,
        t: &Target,
        reference: &str,
    ) -> ImageResult<Result<(Bytes, Digest), ImageError>> {
        let mut last = Err(ImageError::Registry("no endpoint".into()));
        for endpoint in t.chain() {
            // a tag is not what a mirror for digests is asked by
            let asked = match &endpoint.endpoint.by_digest {
                Some(d) if manifest_reference(reference)?.is_none() => d.to_string(),
                _ => reference.to_string(),
            };
            match self.fetch_manifest_from(endpoint, &asked).await {
                Ok(Ok(found)) => return Ok(Ok(found)),
                Ok(Err(e)) => {
                    debug!("{} does not have {reference}: {e}", endpoint.endpoint.host);
                    last = Ok(Err(e));
                }
                Err(e) => {
                    debug!("{} did not give {reference}: {e}", endpoint.endpoint.host);
                    last = Err(e);
                }
            }
        }
        last
    }

    async fn fetch_manifest_from(
        &self,
        t: &Target,
        reference: &str,
    ) -> ImageResult<Result<(Bytes, Digest), ImageError>> {
        manifest_reference(reference)?;
        let base = self.host(t)?.base_url().await?;
        let url = Self::api_url(&base, t, &format!("manifests/{reference}"));
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static(MANIFEST_ACCEPT));
        let resp = self
            .send_url(
                t,
                SendUrl {
                    method: Method::GET,
                    url: &url,
                    headers: &headers,
                    body: None,
                    actions: "pull",
                    cache_key: None,
                },
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = read_limited(resp, 4096).await.unwrap_or_default();
            let e = answered(
                status,
                format!(
                    "Failed to get manifest: {} - {}",
                    status,
                    String::from_utf8_lossy(&text)
                ),
            );
            // a manifest that is not there is the caller's to judge
            if status == reqwest::StatusCode::NOT_FOUND {
                if let Some(d) =
                    manifest_reference(reference)?.filter(|d| d.alg() != Algorithm::Sha256)
                {
                    return Ok(Err(ImageError::Registry(format!(
                        "{e}: {} may not address manifests by {}; name the tag as well (NAME:TAG@{d})",
                        t.endpoint.host,
                        d.alg()
                    ))));
                }
                return Ok(Err(e));
            }
            return Err(e);
        }
        let body = read_limited_by(resp, MAX_MANIFEST_SIZE, self.resolver.speed()).await?;
        let digest = manifest_digest(reference, &body)?;
        Ok(Ok((body, digest)))
    }

    /// Check if a blob exists in the repository of `t`.
    pub async fn blob_exists(&self, t: &Target, digest: &Digest) -> ImageResult<bool> {
        let base = self.host(t)?.base_url().await?;
        let url = Self::api_url(&base, t, &format!("blobs/{digest}"));
        let resp = self
            .send_url(
                t,
                SendUrl {
                    method: Method::HEAD,
                    url: &url,
                    headers: &HeaderMap::new(),
                    body: None,
                    actions: "pull,push",
                    cache_key: None,
                },
            )
            .await?;
        match resp.status() {
            s if s.is_success() => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            s => Err(answered(s, format!("Failed to check blob {digest}: {s}"))),
        }
    }

    /// Start an upload.  With `mount` (a digest and the repository of the
    /// registry that has it) the registry may link the blob instead, which
    /// ends the upload.
    pub async fn start_upload(
        &self,
        t: &Target,
        mount: Option<(&Digest, &str)>,
    ) -> ImageResult<UploadStart> {
        let base = self.host(t)?.base_url().await?;
        let mut url = Self::api_url(&base, t, "blobs/uploads/");
        if let Some((digest, from)) = mount {
            url = format!(
                "{url}?mount={}&from={}",
                utf8_percent_encode(&digest.to_string(), QUERY_VALUE),
                utf8_percent_encode(from, QUERY_VALUE)
            );
        }
        let resp = self
            .send_url(
                t,
                SendUrl {
                    method: Method::POST,
                    url: &url,
                    headers: &HeaderMap::new(),
                    body: Some(Bytes::new()),
                    actions: "pull,push",
                    cache_key: None,
                },
            )
            .await?;
        match resp.status() {
            StatusCode::CREATED if mount.is_some() => Ok(UploadStart::Mounted),
            s if s.is_success() => Ok(UploadStart::Session(upload_location(&resp)?)),
            s => Err(answered(
                s,
                format!(
                    "Failed to initiate blob upload: {s} - {}",
                    String::from_utf8_lossy(&read_limited(resp, 4096).await.unwrap_or_default())
                ),
            )),
        }
    }

    /// Append `data`, which starts at `offset` of the blob, to an upload;
    /// returns the location for the next request.  A piece that fails for
    /// a reason that may pass (the connection, a 5xx, a 408, a 429) is
    /// sent again from what the registry says it has; a registry that
    /// refuses `Content-Range` gets the pieces without it.
    pub async fn upload_chunk(
        &self,
        t: &Target,
        session: &reqwest::Url,
        offset: u64,
        data: Bytes,
    ) -> ImageResult<reqwest::Url> {
        let (mut session, mut offset, mut data) = (session.clone(), offset, data);
        let mut failures = 0;
        loop {
            let ranged = !self
                .host(t)?
                .no_content_range
                .load(std::sync::atomic::Ordering::Relaxed);
            match self
                .patch(t, &session, ranged.then_some(offset), data.clone())
                .await
            {
                Ok(Patched::Done(next)) => return Ok(next),
                // (the first piece: nothing to lose by sending it again)
                Ok(Patched::RangeRefused) if ranged && offset == 0 => {
                    debug!(
                        "{} refuses Content-Range: uploads without it",
                        t.endpoint.host
                    );
                    self.host(t)?
                        .no_content_range
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(Patched::Failed(e)) if failures < UPLOAD_RETRIES => {
                    failures += 1;
                    tracing::warn!("An upload piece failed ({e}), sending it again");
                    tokio::time::sleep(upload_backoff(failures)).await;
                    // where the registry is: what it has of this piece
                    // is not sent again
                    let (have, next) = self.upload_status(t, &session).await.map_err(|s| {
                        ImageError::Registry(format!("{e}; the upload cannot go on: {s}"))
                    })?;
                    let end = offset + data.len() as u64;
                    if have >= end {
                        return Ok(next);
                    }
                    if have < offset {
                        return Err(ImageError::Registry(format!(
                            "{e}; the registry has {have} bytes of the upload, {offset} were sent"
                        )));
                    }
                    data = data.slice((have - offset) as usize..);
                    offset = have;
                    session = next;
                }
                Ok(Patched::Failed(e)) | Err(e) => return Err(e),
                Ok(Patched::RangeRefused) => {
                    return Err(ImageError::Registry(
                        "the registry refused the range of an upload piece".into(),
                    ))
                }
            }
        }
    }

    /// One PATCH of an upload.
    async fn patch(
        &self,
        t: &Target,
        session: &reqwest::Url,
        offset: Option<u64>,
        data: Bytes,
    ) -> ImageResult<Patched> {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        if let Some(offset) = offset {
            let end = offset + (data.len() as u64).max(1) - 1;
            if let Ok(v) = HeaderValue::from_str(&format!("{offset}-{end}")) {
                headers.insert(CONTENT_RANGE, v);
            }
        }
        let resp = match self
            .send_url(
                t,
                SendUrl {
                    method: Method::PATCH,
                    url: session.as_str(),
                    headers: &headers,
                    body: Some(data),
                    actions: "pull,push",
                    cache_key: None,
                },
            )
            .await
        {
            Ok(r) => r,
            // (the connection: worth another try)
            Err(e @ ImageError::Http(_)) => return Ok(Patched::Failed(e)),
            Err(e) => return Err(e),
        };
        let status = resp.status();
        if status.is_success() {
            return Ok(Patched::Done(upload_location(&resp)?));
        }
        let text = read_limited(resp, 4096).await.unwrap_or_default();
        let e = answered(
            status,
            format!(
                "Failed to upload a chunk: {status} - {}",
                String::from_utf8_lossy(&text)
            ),
        );
        Ok(match status {
            StatusCode::RANGE_NOT_SATISFIABLE | StatusCode::BAD_REQUEST if offset.is_some() => {
                Patched::RangeRefused
            }
            s if s.is_server_error()
                || s == StatusCode::REQUEST_TIMEOUT
                || s == StatusCode::TOO_MANY_REQUESTS =>
            {
                Patched::Failed(e)
            }
            _ => return Err(e),
        })
    }

    /// What the registry has of an upload (`GET` of its location, the end
    /// of its `Range`), and where it goes on.
    pub async fn upload_status(
        &self,
        t: &Target,
        session: &reqwest::Url,
    ) -> Result<(u64, reqwest::Url), String> {
        let resp = self
            .send_url(
                t,
                SendUrl {
                    method: Method::GET,
                    url: session.as_str(),
                    headers: &HeaderMap::new(),
                    body: None,
                    actions: "pull,push",
                    cache_key: None,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        if resp.status() != StatusCode::NO_CONTENT && !resp.status().is_success() {
            return Err(format!("the status of the upload is {}", resp.status()));
        }
        let range = resp
            .headers()
            .get(RANGE)
            .and_then(|v| v.to_str().ok())
            .ok_or("the registry does not say what it has (no Range)")?;
        let have = parse_upload_range(range).ok_or(format!("invalid Range {range:?}"))?;
        let next = upload_location(&resp).unwrap_or_else(|_| session.clone());
        Ok((have, next))
    }

    /// End an upload with the last bytes (maybe none), which start at
    /// `offset`, and the digest the registry has to check; tried again as
    /// the pieces are.
    pub async fn finish_upload(
        &self,
        t: &Target,
        session: &reqwest::Url,
        offset: u64,
        digest: &Digest,
        last: Bytes,
    ) -> ImageResult<()> {
        let (mut session, mut offset, mut last) = (session.clone(), offset, last);
        let mut failures = 0;
        loop {
            match self.put_upload(t, &session, digest, last.clone()).await {
                Ok(None) => return Ok(()),
                Ok(Some(e)) if failures < UPLOAD_RETRIES => {
                    failures += 1;
                    tracing::warn!("The end of an upload failed ({e}), trying again");
                    tokio::time::sleep(upload_backoff(failures)).await;
                    // it may have been taken before the answer was lost
                    if self.blob_exists(t, digest).await? {
                        return Ok(());
                    }
                    let (have, next) = self.upload_status(t, &session).await.map_err(|s| {
                        ImageError::Registry(format!("{e}; the upload cannot go on: {s}"))
                    })?;
                    let end = offset + last.len() as u64;
                    if have < offset || have > end {
                        return Err(ImageError::Registry(format!(
                            "{e}; the registry has {have} bytes of the upload, {offset} to {end} were sent"
                        )));
                    }
                    last = last.slice((have - offset) as usize..);
                    offset = have;
                    session = next;
                }
                Ok(Some(e)) => return Err(e),
                Err(e) => return Err(e),
            }
        }
    }

    /// The PUT that ends an upload: `Some` with a failure that may pass.
    async fn put_upload(
        &self,
        t: &Target,
        session: &reqwest::Url,
        digest: &Digest,
        last: Bytes,
    ) -> ImageResult<Option<ImageError>> {
        let mut url = session.clone();
        url.query_pairs_mut()
            .append_pair("digest", &digest.to_string());
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        let resp = match self
            .send_url(
                t,
                SendUrl {
                    method: Method::PUT,
                    url: url.as_str(),
                    headers: &headers,
                    body: Some(last),
                    actions: "pull,push",
                    cache_key: None,
                },
            )
            .await
        {
            Ok(r) => r,
            Err(e @ ImageError::Http(_)) => return Ok(Some(e)),
            Err(e) => return Err(e),
        };
        let status = resp.status();
        if status.is_success() {
            return Ok(None);
        }
        let text = read_limited(resp, 4096).await.unwrap_or_default();
        let e = answered(
            status,
            format!(
                "Failed to upload blob {digest}: {status} - {}",
                String::from_utf8_lossy(&text)
            ),
        );
        if status.is_server_error()
            || status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::TOO_MANY_REQUESTS
        {
            Ok(Some(e))
        } else {
            Err(e)
        }
    }

    /// Push the bytes of a manifest as `reference` (a tag or its digest);
    /// returns the digest of the bytes in `alg`.
    pub async fn push_manifest_bytes(
        &self,
        t: &Target,
        reference: &str,
        media_type: &str,
        body: Bytes,
        alg: Algorithm,
    ) -> ImageResult<Digest> {
        let base = self.host(t)?.base_url().await?;
        let url = Self::api_url(&base, t, &format!("manifests/{reference}"));
        let digest = Digest::of(alg, &body);
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(media_type)
                .map_err(|_| ImageError::Manifest(format!("invalid media type `{media_type}`")))?,
        );
        let resp = self
            .send_url(
                t,
                SendUrl {
                    method: Method::PUT,
                    url: &url,
                    headers: &headers,
                    body: Some(body.clone()),
                    actions: "pull,push",
                    cache_key: None,
                },
            )
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = read_limited(resp, 4096).await.unwrap_or_default();
            // (a registry that checks a manifest against its own sha256 only
            // refuses a PUT by another digest, and a list of such images can
            // not be pushed to it: said, not rewritten to sha256)
            let hint = match reference.parse::<Digest>() {
                Ok(d) if d.alg() != Algorithm::Sha256 && status.is_client_error() => format!(
                    " (the registry may not take a manifest by its {} digest: push the image by its tag; a manifest list of {} images needs a registry that does)",
                    d.alg(),
                    d.alg()
                ),
                _ => String::new(),
            };
            return Err(answered(
                status,
                format!(
                    "Failed to push manifest: {status} - {}{hint}",
                    // (without the line end of the body before the hint)
                    String::from_utf8_lossy(&text).trim_end()
                ),
            ));
        }
        if let Some(returned) = resp
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
        {
            let same = match returned.parse::<Digest>() {
                Ok(returned) if returned.alg() == digest.alg() => returned == digest,
                Ok(returned) => returned.verify(&body),
                Err(_) => false,
            };
            if !same {
                return Err(ImageError::DigestMismatch {
                    expected: digest.to_string(),
                    actual: returned.to_string(),
                });
            }
        }
        info!(
            "Successfully pushed manifest to {}:{}",
            t.endpoint.repository, reference
        );
        Ok(digest)
    }
}

/// What starting an upload led to.
#[derive(Debug)]
pub enum UploadStart {
    /// The registry linked the blob from another repository.
    Mounted,
    /// The URL to send the data to.
    Session(reqwest::Url),
}

/// The `Location` of an upload response, which may be relative.
/// How many times a piece of an upload is sent again.
const UPLOAD_RETRIES: u32 = 3;

fn upload_backoff(failures: u32) -> Duration {
    Duration::from_millis(200u64 << failures.min(5))
}

/// What a PATCH did.
enum Patched {
    Done(reqwest::Url),
    /// The registry refused the `Content-Range`
    RangeRefused,
    /// A failure that may pass
    Failed(ImageError),
}

/// The bytes a registry has of an upload, from its `Range: 0-END`
/// (inclusive; `0-0` with nothing yet, as distribution says it).
fn parse_upload_range(range: &str) -> Option<u64> {
    let (start, end) = range.trim().split_once('-')?;
    if start.trim() != "0" {
        return None;
    }
    let end: i64 = end.trim().parse().ok()?;
    Some(if end <= 0 { 0 } else { end as u64 + 1 })
}

/// The next URL of an upload, read against the URL that answered: a host
/// that is not the registry does not choose a path of the registry.
fn upload_location(resp: &Response) -> ImageResult<reqwest::Url> {
    let location = resp
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ImageError::Registry("No location header in upload response".into()))?;
    resp.url()
        .join(location)
        .map_err(|e| ImageError::Registry(format!("invalid upload location: {e}")))
}

/// How long a pull worker keeps an `Authorization` the daemon gave it:
/// tokens are valid for 60 s at least, a refused one is asked again.
const BROKERED_LIFETIME: Duration = Duration::from_secs(30);

/// A whole `Authorization` value (`Bearer ...`, `Basic ...`), sensitive.
fn bearer_or_raw(value: &str) -> ImageResult<HeaderValue> {
    HeaderValue::from_str(value)
        .map(|mut v| {
            v.set_sensitive(true);
            v
        })
        .map_err(|_| ImageError::Registry("invalid authorization".into()))
}

fn bearer_header(token: &str) -> ImageResult<HeaderValue> {
    let mut v = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| ImageError::Registry("the token has invalid characters".into()))?;
    v.set_sensitive(true);
    Ok(v)
}

/// Where a redirect of `resp` goes, read against the URL `from` that was
/// asked.
fn location(resp: &Response, from: &reqwest::Url) -> ImageResult<reqwest::Url> {
    let location = resp
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ImageError::Registry(format!("redirect without a location for `{from}`")))?;
    let next = from
        .join(location)
        .map_err(|e| ImageError::Registry(format!("invalid redirect to `{location}`: {e}")))?;
    if next.scheme() != "https" && next.scheme() != "http" {
        return Err(ImageError::Registry(format!(
            "invalid redirect to `{next}`"
        )));
    }
    Ok(next)
}

/// What [`send_core`] needs to know of `url`, and why the address policy
/// refuses it when it does.
async fn judge(
    host: &HostTransport,
    home: &reqwest::Url,
    start: &reqwest::Url,
    url: &reqwest::Url,
) -> (send_core::Target, Option<ImageError>) {
    let is_home = same_origin(home, url);
    let refusal = if is_home {
        None
    } else {
        host.check_url(url).await.err()
    };
    let target = send_core::Target {
        home: is_home,
        start: same_origin(start, url),
        https: url.scheme() == "https",
        allowed: refusal.is_none(),
    };
    (target, refusal)
}

fn core_method(method: &Method) -> send_core::Method {
    if *method == Method::GET {
        send_core::Method::Get
    } else if *method == Method::HEAD {
        send_core::Method::Head
    } else {
        send_core::Method::Other
    }
}

fn same_origin(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

#[cfg(test)]
fn sha256_of(data: &[u8]) -> Digest {
    Digest::of(Algorithm::Sha256, data)
}

/// The most pages of a registry's catalog a search reads.
const CATALOG_PAGES: usize = 100;

/// The most pages of the tags of a repository a listing reads.
const TAG_PAGES: usize = 1000;

/// The path of the next page of a catalog from its `Link` header
/// (`</v2/_catalog?last=x&n=100>; rel="next"`): a path of the catalog of
/// the same registry only.
fn next_catalog_page(link: &str) -> Option<String> {
    next_page(link, "/v2/_catalog")
}

/// The path of the next page from a `Link` header: a path of `list` with a
/// query, of the same registry.  A link with a scheme and a host gives only
/// its path and query (as podman reads it): the next page is asked of the
/// registry, never of the host a link names.
fn next_page(link: &str, list: &str) -> Option<String> {
    link.split(',').find_map(|part| {
        let (target, params) = part.trim().split_once(';')?;
        let target = target.trim().strip_prefix('<')?.strip_suffix('>')?;
        let next = params
            .split(';')
            .any(|p| matches!(p.trim(), "rel=\"next\"" | "rel=next"));
        let path = match reqwest::Url::parse(target) {
            Ok(url) if matches!(url.scheme(), "https" | "http") => {
                format!("{}?{}", url.path(), url.query()?)
            }
            Ok(_) => return None,
            Err(_) => target.to_string(),
        };
        (next && path.starts_with(&format!("{list}?")) && !path.contains(['#', ' ']))
            .then_some(path)
    })
}

/// The error for a registry that answered STATUS to a request: the registry
/// refused the credentials (401) or what they allow (403), does not have it
/// (404), or failed.
pub fn answered(status: StatusCode, message: String) -> ImageError {
    match status {
        StatusCode::UNAUTHORIZED => ImageError::Unauthorized(message),
        StatusCode::FORBIDDEN => ImageError::Forbidden(message),
        StatusCode::NOT_FOUND => ImageError::RegistryNotFound(message),
        _ => ImageError::Registry(message),
    }
}

pub async fn read_limited(resp: Response, limit: u64) -> ImageResult<Bytes> {
    read_limited_by(resp, limit, crate::speed::Speed::default()).await
}

/// [`read_limited`] of a body that must come at least as fast as `speed`.
pub async fn read_limited_by(
    resp: Response,
    limit: u64,
    speed: crate::speed::Speed,
) -> ImageResult<Bytes> {
    if let Some(len) = resp.content_length() {
        if len > limit {
            return Err(ImageError::Registry(format!(
                "response of {len} bytes exceeds the limit of {limit}"
            )));
        }
    }
    let mut out = Vec::new();
    let mut body = crate::body::Body::new(resp, speed);
    while let Some(chunk) = body.chunk().await? {
        if out.len() as u64 + chunk.len() as u64 > limit {
            return Err(ImageError::Registry(format!(
                "response exceeds the limit of {limit} bytes"
            )));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

#[cfg(test)]
pub(crate) mod hint_tests;
#[cfg(test)]
mod pin_tests;

/// Whether a request failed because the connection it used was closed (by
/// the server, or while it was idle) before the answer: nothing was done
/// that sending it again would repeat.
fn connection_lost(e: &reqwest::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(s) = source {
        if s.downcast_ref::<hyper::Error>()
            .is_some_and(hyper::Error::is_incomplete_message)
        {
            return true;
        }
        if s.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            )
        }) {
            return true;
        }
        source = s.source();
    }
    false
}

/// What Go says of a connection that failed, from the chain of the error of
/// the client: `dial tcp HOST:PORT: connect: connection refused`,
/// `dial tcp: lookup HOST: no such host`, else the chain.
fn go_cause(host: &str, e: &(dyn std::error::Error + 'static)) -> String {
    let mut chain = Vec::new();
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(s) = source {
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::ConnectionRefused {
                // (Go names the address it dialed, the first of the name)
                let addr = std::net::ToSocketAddrs::to_socket_addrs(host)
                    .ok()
                    .and_then(|mut a| a.next())
                    .map_or_else(|| host.to_string(), |a| a.to_string());
                return format!("dial tcp {addr}: connect: connection refused");
            }
            // (the io error holds the error of the resolver, which its own
            // source skips)
            if let Some(lookup) = io
                .get_ref()
                .and_then(|i| i.downcast_ref::<crate::netpolicy::LookupError>())
            {
                return format!("dial tcp: lookup {}: no such host", lookup.name);
            }
        }
        chain.push(s.to_string());
        source = s.source();
    }
    chain.join(": ")
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_huge_token_lifetime_does_not_overflow_the_clock() {
        use super::{Duration, Instant};
        for expires_in in [u64::MAX, u64::MAX / 2, 1 << 40] {
            let lifetime = super::token_lifetime(Some(expires_in));
            assert!(Instant::now().checked_add(lifetime).is_some());
        }
        assert_eq!(super::token_lifetime(None), Duration::from_secs(60));
        assert_eq!(super::token_lifetime(Some(1)), Duration::from_secs(30));
        assert_eq!(super::token_lifetime(Some(300)), Duration::from_secs(300));
    }

    #[test]
    fn a_query_value_escapes_all_but_the_unreserved_characters() {
        let enc = |s: &str| super::utf8_percent_encode(s, super::QUERY_VALUE).to_string();
        assert_eq!(enc("AZaz09-_.~"), "AZaz09-_.~");
        assert_eq!(enc(" /:@+?&=%#"), "%20%2F%3A%40%2B%3F%26%3D%25%23");
        assert_eq!(enc("sha256:ab"), "sha256%3Aab");
        assert_eq!(enc("library/alpine"), "library%2Falpine");
        assert_eq!(enc("é"), "%C3%A9");
    }

    #[test]
    fn answers_are_typed_by_status() {
        let kind = |s| answered(s, "x".into());
        assert!(matches!(
            kind(StatusCode::UNAUTHORIZED),
            ImageError::Unauthorized(_)
        ));
        assert!(matches!(
            kind(StatusCode::FORBIDDEN),
            ImageError::Forbidden(_)
        ));
        assert!(matches!(
            kind(StatusCode::NOT_FOUND),
            ImageError::RegistryNotFound(_)
        ));
        assert!(matches!(
            kind(StatusCode::BAD_GATEWAY),
            ImageError::Registry(_)
        ));
    }

    use super::*;
    use crate::hints::Hint;
    use crate::target::*;

    /// Only a 401 or a 403 is a refusal of the credentials.
    #[test]
    fn test_a_registry_that_refuses_the_credentials_is_told_by_its_status() {
        for (status, refused) in [
            (StatusCode::UNAUTHORIZED, true),
            (StatusCode::FORBIDDEN, true),
            (StatusCode::NOT_FOUND, false),
            (StatusCode::BAD_GATEWAY, false),
        ] {
            let e = answered(status, "no".into());
            assert_eq!(e.is_refusal(), refused, "{status}");
        }
    }

    #[test]
    fn test_the_next_page_of_a_catalog_is_one_of_the_same_registry() {
        assert_eq!(
            next_catalog_page(r#"</v2/_catalog?last=e2e%2Fx&n=100>; rel="next""#).as_deref(),
            Some("/v2/_catalog?last=e2e%2Fx&n=100")
        );
        // (a link with a host gives its path: the registry is asked)
        assert_eq!(
            next_catalog_page(r#"<https://elsewhere/v2/_catalog?last=a>; rel="next""#).as_deref(),
            Some("/v2/_catalog?last=a")
        );
        for other in [
            r#"<https://elsewhere/v2/x/tags/list?last=a>; rel="next""#,
            r#"</v2/x/tags/list?last=a>; rel="next""#,
            r#"</v2/_catalog?last=a>; rel="prev""#,
            "",
        ] {
            assert_eq!(next_catalog_page(other), None, "{other}");
        }
    }

    #[tokio::test]
    async fn test_docker_schema_2_manifests_are_resolved_and_the_others_refused() {
        let r = ImageReference::parse("example.com/a:latest").unwrap();
        let schema2 = br#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1},"layers":[]}"#;
        let schema1 = br#"{"schemaVersion":1,"name":"a","tag":"latest","fsLayers":[]}"#;
        let foreign = br#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1}]}"#;
        for body in [&schema1[..], &foreign[..]] {
            let fetch = |_: String| async move {
                Ok::<_, ImageError>((Bytes::from(body.to_vec()), sha256_of(body)))
            };
            let err = resolve_manifest(&r, None, fetch).await.unwrap_err();
            assert!(matches!(err, ImageError::DockerFormat(_)), "{err}");
            assert!(
                err.to_string()
                    .contains("only OCI and Docker schema 2 images"),
                "{err}"
            );
        }
        // the bytes and the digest are the registry's, as served
        let fetch = |_: String| async move {
            Ok::<_, ImageError>((Bytes::from(schema2.to_vec()), sha256_of(schema2)))
        };
        let (manifest, digest, body) = resolve_manifest(&r, None, fetch).await.unwrap();
        assert_eq!(&body[..], &schema2[..]);
        assert_eq!(digest, sha256_of(schema2));
        assert_eq!(
            manifest.media_type.as_deref(),
            Some("application/vnd.docker.distribution.manifest.v2+json")
        );
        // an index whose instance is a Docker manifest
        let docker = schema2.to_vec();
        let named = sha256_of(&docker);
        let index = format!(
            r#"{{"manifests":[{{"digest":"{named}","platform":{{"os":"linux","architecture":"{}"}}}}]}}"#,
            host_arch()
        );
        let fetch = |reference: String| {
            let body = if reference == "latest" {
                index.clone().into_bytes()
            } else {
                docker.clone()
            };
            async move {
                let d = sha256_of(&body);
                Ok::<_, ImageError>((Bytes::from(body), d))
            }
        };
        let (_, digest, body) = resolve_manifest(&r, None, fetch).await.unwrap();
        assert_eq!(digest, named);
        assert_eq!(body, docker);
        assert!(MANIFEST_ACCEPT.contains("manifest.list.v2+json"));
        // a list with a schema 1 instance: for another platform it is left
        // alone, for this one it is refused by name
        let v1 = "application/vnd.docker.distribution.manifest.v1+json";
        let v2 = "application/vnd.docker.distribution.manifest.v2+json";
        let other = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        for (theirs, ours, ok) in [(v1, v2, true), (v2, v1, false)] {
            let list = format!(
                r#"{{"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","manifests":[
                    {{"mediaType":"{theirs}","digest":"{other}","platform":{{"os":"linux","architecture":"s390x-not-this"}}}},
                    {{"mediaType":"{ours}","digest":"{named}","platform":{{"os":"linux","architecture":"{}"}}}}]}}"#,
                host_arch()
            );
            let fetch = |reference: String| {
                let body = if reference == "latest" {
                    list.clone().into_bytes()
                } else {
                    docker.clone()
                };
                async move {
                    let d = sha256_of(&body);
                    Ok::<_, ImageError>((Bytes::from(body), d))
                }
            };
            match resolve_manifest(&r, None, fetch).await {
                Ok((_, digest, _)) => assert!(ok && digest == named),
                Err(e) => {
                    assert!(!ok, "{e}");
                    assert!(matches!(e, ImageError::DockerFormat(_)), "{e}");
                    assert!(e.to_string().contains(v1), "{e}");
                }
            }
        }
    }

    /// A document is an index or an image manifest, never both: one with
    /// the list of an index and the configuration or layers of a manifest,
    /// or whose media type says the other, is refused, and so is an index
    /// below two others.
    #[tokio::test]
    async fn test_a_document_that_is_index_and_manifest_is_refused() {
        let r = ImageReference::parse("example.com/a:latest").unwrap();
        let index_type = "application/vnd.oci.image.index.v1+json";
        let manifest_type = "application/vnd.oci.image.manifest.v1+json";
        let config = r#""config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1},"layers":[]"#;
        let manifest = format!(r#"{{"schemaVersion":2,"mediaType":"{manifest_type}",{config}}}"#);
        let index_of = |body: &str, extra: &str| {
            format!(
                r#"{{"schemaVersion":2{extra},"manifests":[{{"digest":"{}","platform":{{"os":"linux","architecture":"{}"}}}}]}}"#,
                sha256_of(body.as_bytes()),
                host_arch()
            )
        };
        // the chain the tag names, the first document first
        let chain = |docs: Vec<String>| {
            move |reference: String| {
                let body = match reference.as_str() {
                    "latest" => docs[0].clone(),
                    d => docs
                        .iter()
                        .find(|b| sha256_of(b.as_bytes()).to_string() == d)
                        .unwrap()
                        .clone(),
                };
                async move {
                    let d = sha256_of(body.as_bytes());
                    Ok::<_, ImageError>((Bytes::from(body), d))
                }
            }
        };
        let one = index_of(&manifest, "");
        let two = index_of(&one, "");
        let three = index_of(&two, "");
        let (_, digest, _) = resolve_manifest(
            &r,
            None,
            chain(vec![two.clone(), one.clone(), manifest.clone()]),
        )
        .await
        .unwrap();
        assert_eq!(digest, sha256_of(manifest.as_bytes()));
        // (a fetch that says the digest the index names of other bytes)
        let named = sha256_of(manifest.as_bytes());
        let (top, other) = (one.clone(), format!("{manifest} "));
        let lying = |reference: String| {
            let body = match reference.as_str() {
                "latest" => top.clone(),
                _ => other.clone(),
            };
            async move { Ok::<_, ImageError>((Bytes::from(body), named)) }
        };
        assert!(matches!(
            resolve_manifest(&r, None, lying).await,
            Err(ImageError::DigestMismatch { .. })
        ));
        let both = index_of(&manifest, &format!(",{config}"));
        let typed_manifest = index_of(&manifest, &format!(r#","mediaType":"{manifest_type}""#));
        let typed_index = format!(r#"{{"schemaVersion":2,"mediaType":"{index_type}",{config}}}"#);
        for docs in [
            vec![both, manifest.clone()],
            vec![typed_manifest, manifest.clone()],
            vec![typed_index.clone()],
            vec![index_of(&typed_index, ""), typed_index],
            vec![three, two, one, manifest.clone()],
        ] {
            match resolve_manifest(&r, None, chain(docs)).await {
                Err(ImageError::Manifest(_)) => {}
                other => panic!("taken: {:?}", other.map(|(_, d, _)| d)),
            }
        }
    }

    /// The instance an index names, from a store that has a manifest of
    /// that digest: it saves the request, and only a manifest that is the
    /// one of the digest is taken.
    #[tokio::test]
    async fn test_the_instance_of_an_index_comes_from_the_store_only_if_it_is_the_one_named() {
        let manifest = br#"{"schemaVersion":2,"config":{"mediaType":"x","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1},"layers":[]}"#.to_vec();
        let another = br#"{"schemaVersion":2,"config":{"mediaType":"x","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","size":1},"layers":[]}"#.to_vec();
        let named = sha256_of(&manifest);
        let index = format!(
            r#"{{"manifests":[{{"digest":"{named}","platform":{{"os":"linux","architecture":"{}"}}}}]}}"#,
            host_arch()
        );
        let asked = std::sync::Mutex::new(Vec::<String>::new());
        let fetch = |reference: String| {
            asked.lock().unwrap().push(reference.clone());
            let body = if reference == "latest" {
                index.clone().into_bytes()
            } else {
                manifest.clone()
            };
            async move {
                let d = sha256_of(&body);
                Ok::<_, ImageError>((Bytes::from(body), d))
            }
        };
        let r = ImageReference::parse("example.com/a:latest").unwrap();
        // the store has it: the index is asked for, the instance is not
        let has = |_: &Digest| -> futures::future::BoxFuture<'_, Option<Bytes>> {
            Box::pin(async { Some(Bytes::from(manifest.clone())) })
        };
        let (_, digest, body) = resolve_manifest_with(&r, None, Some(&has), &fetch)
            .await
            .unwrap();
        assert_eq!((digest, &body[..]), (named, &manifest[..]));
        assert_eq!(*asked.lock().unwrap(), ["latest"]);
        // what the store has under that digest is another manifest, or no
        // manifest at all, or too much: the registry is asked
        let oversize = vec![b' '; MAX_MANIFEST_SIZE as usize + 1];
        for wrong in [
            Some(another.clone()),
            Some(b"{}".to_vec()),
            Some(oversize),
            None,
        ] {
            asked.lock().unwrap().clear();
            let has = |_: &Digest| -> futures::future::BoxFuture<'_, Option<Bytes>> {
                let wrong = wrong.clone().map(Bytes::from);
                Box::pin(async move { wrong })
            };
            let (_, digest, body) = resolve_manifest_with(&r, None, Some(&has), &fetch)
                .await
                .unwrap();
            assert_eq!((digest, &body[..]), (named, &manifest[..]));
            assert_eq!(
                *asked.lock().unwrap(),
                ["latest".to_string(), named.to_string()]
            );
        }
        // the manifest the reference itself names is the registry's to
        // give, whatever the store has
        asked.lock().unwrap().clear();
        let by_digest = ImageReference::parse(&format!("example.com/a@{named}")).unwrap();
        let has = |_: &Digest| -> futures::future::BoxFuture<'_, Option<Bytes>> {
            Box::pin(async { Some(Bytes::from(manifest.clone())) })
        };
        resolve_manifest_with(&by_digest, None, Some(&has), &fetch)
            .await
            .unwrap();
        assert_eq!(*asked.lock().unwrap(), [named.to_string()]);
    }

    #[tokio::test]
    async fn test_the_instance_of_an_index_is_checked() {
        let manifest = br#"{"schemaVersion":2,"config":{"mediaType":"x","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1},"layers":[]}"#.to_vec();
        let named = sha256_of(b"the manifest the index names");
        let index = |digest: &str| {
            format!(
                r#"{{"manifests":[{{"digest":"{digest}","platform":{{"os":"linux","architecture":"{}"}}}}]}}"#,
                host_arch()
            )
        };
        let r = ImageReference::parse("example.com/a:latest").unwrap();
        // a worker that answers another manifest than the one asked for
        let lying = |reference: String| {
            let (manifest, idx) = (manifest.clone(), index(&named.to_string()));
            async move {
                let body = if reference == "latest" {
                    idx.into_bytes()
                } else {
                    manifest
                };
                let d = sha256_of(&body);
                Ok::<_, ImageError>((Bytes::from(body), d))
            }
        };
        assert!(matches!(
            resolve_manifest(&r, None, lying).await,
            Err(ImageError::DigestMismatch { .. })
        ));
        let honest_digest = sha256_of(&manifest);
        let honest = |reference: String| {
            let (manifest, idx) = (manifest.clone(), index(&honest_digest.to_string()));
            async move {
                let body = if reference == "latest" {
                    idx.into_bytes()
                } else {
                    manifest
                };
                let d = sha256_of(&body);
                Ok::<_, ImageError>((Bytes::from(body), d))
            }
        };
        assert!(resolve_manifest(&r, None, honest).await.is_ok());
        let bad = |reference: String| {
            let idx = index("../../blobs/x");
            async move {
                assert_eq!(reference, "latest");
                let d = sha256_of(idx.as_bytes());
                Ok::<_, ImageError>((Bytes::from(idx), d))
            }
        };
        assert!(resolve_manifest(&r, None, bad).await.is_err());
    }

    #[test]
    fn test_platforms() {
        let p = Platform::parse("linux/arm64/v8").unwrap();
        assert_eq!(
            (p.os.as_str(), p.arch.as_str(), p.variant.as_deref()),
            ("linux", "arm64", Some("v8"))
        );
        assert_eq!(
            Platform::parse("aarch64").unwrap().to_string(),
            "linux/arm64"
        );
        assert_eq!(Platform::parse("windows/amd64").unwrap().os, "windows");
        for bad in ["", "a/b/c/d", "linux/", "/amd64", "linux/arm/"] {
            assert!(Platform::parse(bad).is_err(), "{bad}");
        }
        let index: Vec<serde_json::Value> = serde_json::from_str(
            r#"[
              {"digest":"sha256:a","platform":{"os":"linux","architecture":"amd64"}},
              {"digest":"sha256:b","platform":{"os":"linux","architecture":"arm","variant":"v6"}},
              {"digest":"sha256:c","platform":{"os":"linux","architecture":"arm","variant":"v7"}},
              {"digest":"sha256:d","platform":{"os":"unknown","architecture":"unknown"}}
            ]"#,
        )
        .unwrap();
        let pick = |s: &str| select_platform(&index, &Platform::parse(s).unwrap());
        assert_eq!(pick("linux/amd64").as_deref(), Some("sha256:a"));
        assert_eq!(pick("x86_64").as_deref(), Some("sha256:a"));
        assert_eq!(pick("linux/arm/v7").as_deref(), Some("sha256:c"));
        assert_eq!(pick("linux/arm").as_deref(), Some("sha256:c"));
        assert_eq!(pick("linux/arm/v6").as_deref(), Some("sha256:b"));
        assert_eq!(pick("linux/arm64"), None);
        assert_eq!(pick("freebsd/amd64"), None);
    }

    #[test]
    fn test_parse_bearer_challenge() {
        let c = Challenge::parse(
            r#"Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:a/b:pull,push""#,
        )
        .unwrap();
        assert_eq!(
            c,
            Challenge::Bearer {
                realm: "https://auth.example.com/token".into(),
                service: Some("registry.example.com".into())
            }
        );
    }

    #[test]
    fn test_parse_basic_and_unknown_challenge() {
        assert_eq!(
            Challenge::parse("Basic realm=\"x\"").unwrap(),
            Challenge::Basic
        );
        assert!(Challenge::parse("Negotiate").is_err());
        assert!(Challenge::parse("Bearer service=\"x\"").is_err());
    }

    #[test]
    fn test_auth_params_with_escapes() {
        let p = parse_auth_params(r#"a="x\"y", b=z , c="1,2""#);
        assert_eq!(p["a"], "x\"y");
        assert_eq!(p["b"], "z");
        assert_eq!(p["c"], "1,2");
    }

    #[test]
    fn test_select_platform() {
        let idx: Vec<serde_json::Value> = serde_json::from_str(&format!(
            r#"[{{"digest":"sha256:a","platform":{{"os":"linux","architecture":"s390x-nope"}}}},
                {{"digest":"sha256:b","platform":{{"os":"windows","architecture":"{0}"}}}},
                {{"digest":"sha256:c","platform":{{"os":"linux","architecture":"{0}"}}}}]"#,
            host_arch()
        ))
        .unwrap();
        assert_eq!(
            select_platform(&idx, &Platform::host()).as_deref(),
            Some("sha256:c")
        );
        assert_eq!(select_platform(&idx[..2], &Platform::host()), None);
    }

    fn select(index: &str, platform: &str) -> Option<String> {
        let index: Vec<serde_json::Value> = serde_json::from_str(index).unwrap();
        select_platform(&index, &Platform::parse(platform).unwrap())
    }

    /// arm64 with and without `v8` are one platform, as for
    /// containers/image.
    #[test]
    fn test_arm64_with_and_without_v8() {
        let bare = r#"[{"digest":"sha256:a","platform":{"os":"linux","architecture":"arm64"}}]"#;
        assert_eq!(select(bare, "linux/arm64/v8").as_deref(), Some("sha256:a"));
        let v8 = r#"[{"digest":"sha256:a","platform":{"os":"linux","architecture":"arm64","variant":"v8"}}]"#;
        assert_eq!(select(v8, "linux/arm64").as_deref(), Some("sha256:a"));
    }

    /// A platform without a variant takes the best arm entry (no variant,
    /// then v8, v7, v6, v5), not the first; a variant asked for takes it
    /// or one below it.
    #[test]
    fn test_arm_takes_the_best_entry() {
        let arm = r#"[
            {"digest":"sha256:a","platform":{"os":"linux","architecture":"arm","variant":"v5"}},
            {"digest":"sha256:b","platform":{"os":"linux","architecture":"arm","variant":"v7"}},
            {"digest":"sha256:c","platform":{"os":"linux","architecture":"arm","variant":"v8"}}]"#;
        assert_eq!(select(arm, "linux/arm").as_deref(), Some("sha256:c"));
        assert_eq!(select(arm, "linux/arm/v7").as_deref(), Some("sha256:b"));
        assert_eq!(select(arm, "linux/arm/v6").as_deref(), Some("sha256:a"));
        assert_eq!(select(arm, "linux/arm/v8").as_deref(), Some("sha256:c"));
    }

    /// An attestation is no image, not even for a request for it.
    #[test]
    fn test_an_attestation_is_not_chosen() {
        let index =
            r#"[{"digest":"sha256:a","platform":{"os":"unknown","architecture":"unknown"}}]"#;
        assert_eq!(select(index, "unknown/unknown"), None);
    }

    /// Rust's `powerpc64` is both endiannesses; the big-endian one is
    /// `ppc64`.
    #[test]
    fn test_powerpc64_has_two_names() {
        assert_eq!(oci_arch("powerpc64", true), "ppc64le");
        assert_eq!(oci_arch("powerpc64", false), "ppc64");
        assert_eq!(oci_arch("x86_64", false), "amd64");
    }

    fn manifest_of_size(size: usize) -> Vec<u8> {
        let mut body = br#"{"schemaVersion":2,"config":{"mediaType":"x","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1},"layers":[]}"#.to_vec();
        body.resize(size, b' ');
        body
    }

    /// Pins a problem: a manifest larger than MAX_MANIFEST_SIZE is used
    /// (parsed, hashed) and taken; expect an error, for the manifest of a
    /// tag and for the instance of an index alike.
    #[tokio::test]
    async fn test_an_oversized_manifest_is_taken_pinned() {
        let r = ImageReference::parse("example.com/a:latest").unwrap();
        let big = manifest_of_size(MAX_MANIFEST_SIZE as usize + 1);
        let alone = |_: String| {
            let body = big.clone();
            async move {
                let d = sha256_of(&body);
                Ok::<_, ImageError>((Bytes::from(body), d))
            }
        };
        assert!(resolve_manifest(&r, None, alone).await.is_ok());
        let index = format!(
            r#"{{"manifests":[{{"digest":"{}","platform":{{"os":"linux","architecture":"{}"}}}}]}}"#,
            sha256_of(&big),
            host_arch()
        );
        let nested = |reference: String| {
            let body = if reference == "latest" {
                index.clone().into_bytes()
            } else {
                big.clone()
            };
            async move {
                let d = sha256_of(&body);
                Ok::<_, ImageError>((Bytes::from(body), d))
            }
        };
        assert!(resolve_manifest(&r, None, nested).await.is_ok());
    }

    /// Pins a problem: the bytes are parsed (and refused as a Docker
    /// schema 1 manifest) before they are hashed; a body of another
    /// digest than the one that named it is a DigestMismatch whatever
    /// it holds.  Expect DigestMismatch in both cases.
    #[tokio::test]
    async fn test_bytes_are_parsed_before_they_are_hashed_pinned() {
        let schema1 = br#"{"schemaVersion":1,"name":"a","tag":"latest","fsLayers":[]}"#.to_vec();
        let named = sha256_of(b"the manifest that was asked for");
        // by a digest reference
        let by_digest = ImageReference::parse(&format!("example.com/a@{named}")).unwrap();
        let answer = schema1.clone();
        let fetch = |_: String| {
            let body = answer.clone();
            async move { Ok::<_, ImageError>((Bytes::from(body.clone()), sha256_of(&body))) }
        };
        let err = resolve_manifest(&by_digest, None, fetch).await.unwrap_err();
        assert!(matches!(err, ImageError::DockerFormat(_)), "{err}");
        // by the digest an index names
        let index = format!(
            r#"{{"manifests":[{{"digest":"{named}","platform":{{"os":"linux","architecture":"{}"}}}}]}}"#,
            host_arch()
        );
        let tag = ImageReference::parse("example.com/a:latest").unwrap();
        let fetch = |reference: String| {
            let body = if reference == "latest" {
                index.clone().into_bytes()
            } else {
                schema1.clone()
            };
            async move {
                let d = sha256_of(&body);
                Ok::<_, ImageError>((Bytes::from(body), d))
            }
        };
        let err = resolve_manifest(&tag, None, fetch).await.unwrap_err();
        assert!(matches!(err, ImageError::DockerFormat(_)), "{err}");
    }

    #[test]
    fn test_verify_digest() {
        let d = sha256_of(b"abc");
        assert!(verify_digest(&d, b"abc").is_ok());
        assert!(verify_digest(&d, b"abd").is_err());
    }

    use axum::extract::State;
    use axum::http::{header, HeaderMap as AxHeaders, StatusCode as AxStatus};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Hits {
        blob: AtomicUsize,
        cdn: AtomicUsize,
        token: AtomicUsize,
    }

    const BLOB: &[u8] = b"0123456789abcdef";

    /// A plain HTTP registry: a Bearer token is required for the blob,
    /// which is served through a redirect to another path ("the CDN").
    async fn start_registry() -> (String, Arc<Hits>) {
        let hits = Arc::new(Hits::default());
        let app = Router::new()
            .route(
                "/v2/",
                get(|h: AxHeaders| async move {
                    if h.get(header::AUTHORIZATION).is_some() {
                        AxStatus::OK.into_response()
                    } else {
                        let port = h.get(header::HOST).unwrap().to_str().unwrap().to_string();
                        (
                            AxStatus::UNAUTHORIZED,
                            [(
                                header::WWW_AUTHENTICATE,
                                format!("Bearer realm=\"http://{port}/token\",service=\"test\""),
                            )],
                        )
                            .into_response()
                    }
                }),
            )
            .route(
                "/token",
                get(|State(h): State<Arc<Hits>>| async move {
                    h.token.fetch_add(1, Ordering::SeqCst);
                    r#"{"token":"secret","expires_in":300}"#
                }),
            )
            .route(
                "/v2/r/blobs/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                get(|State(h): State<Arc<Hits>>, hd: AxHeaders| async move {
                    h.blob.fetch_add(1, Ordering::SeqCst);
                    if hd.get(header::AUTHORIZATION).map(|v| v.as_bytes()) != Some(b"Bearer secret")
                    {
                        return AxStatus::UNAUTHORIZED.into_response();
                    }
                    (
                        AxStatus::TEMPORARY_REDIRECT,
                        [(header::LOCATION, "/cdn/blob")],
                    )
                        .into_response()
                }),
            )
            .route(
                "/cdn/blob",
                get(|State(h): State<Arc<Hits>>| async move {
                    h.cdn.fetch_add(1, Ordering::SeqCst);
                    BLOB
                }),
            )
            .with_state(hits.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (addr.to_string(), hits)
    }

    fn client_for(host: &str, insecure: bool, tls_verify: bool) -> RegistryClient {
        let conf = format!("[[registry]]\nlocation = \"{host}\"\ninsecure = {insecure}\n");
        RegistryClient::with_config(
            TransportConfig {
                registries: super::super::config::RegistriesConfig::parse(&conf).unwrap(),
                certs_dirs: vec![],
                tls_verify,
            },
            AuthConfig::default(),
        )
    }

    fn reference(host: &str) -> ImageReference {
        ImageReference::parse(&format!("{host}/r:latest")).unwrap()
    }

    const MANIFEST: &[u8] = br#"{"schemaVersion":2,"config":{"mediaType":"x","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1},"layers":[]}"#;

    /// A registry that answers every manifest request with `body`, as the
    /// header `Docker-Content-Digest` says if `stated` is some.
    async fn manifest_registry(body: &'static [u8], stated: Option<String>) -> String {
        let app = Router::new().route(
            "/v2/r/manifests/:reference",
            get(move || {
                let stated = stated.clone();
                async move {
                    let mut headers = AxHeaders::new();
                    if let Some(s) = stated {
                        headers.insert("docker-content-digest", s.parse().unwrap());
                    }
                    (headers, body)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr.to_string()
    }

    #[tokio::test]
    async fn test_a_manifest_is_checked_with_the_algorithm_of_its_reference() {
        for alg in Algorithm::ALL {
            let host = manifest_registry(MANIFEST, None).await;
            let client = client_for(&host, true, true);
            let t = client.target(&reference(&host)).unwrap();
            let good = Digest::of(alg, MANIFEST);
            let (body, digest) = client.fetch_manifest(&t, &good.to_string()).await.unwrap();
            assert_eq!((&body[..], digest), (MANIFEST, good));
            // the same bytes under the digest of other bytes of that algorithm
            let wrong = Digest::of(alg, b"other bytes");
            let err = client
                .fetch_manifest(&t, &wrong.to_string())
                .await
                .unwrap_err();
            assert!(
                matches!(&err, ImageError::DigestMismatch { expected, .. } if *expected == wrong.to_string()),
                "{alg}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn test_a_reference_that_is_no_known_digest_is_refused_not_trusted() {
        let host = manifest_registry(MANIFEST, None).await;
        let client = client_for(&host, true, true);
        let t = client.target(&reference(&host)).unwrap();
        for bad in [
            "sha384:0",
            "blake3:00",
            "sha512:abc",
            &format!("sha512:{}", "0".repeat(64)),
        ] {
            let err = client.fetch_manifest(&t, bad).await.unwrap_err();
            assert!(
                err.to_string().contains("invalid manifest reference"),
                "{err}"
            );
        }
    }

    const MANIFEST512: &[u8] = br#"{"schemaVersion":2,"config":{"mediaType":"x","digest":"sha512:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","size":1},"layers":[]}"#;

    /// A manifest fetched by a tag is named in the algorithm of the image
    /// (its configuration), whatever the registry states: a sha256 image by
    /// its sha256, a sha512 one by its sha512 (its id has 128 digits).
    #[tokio::test]
    async fn test_a_manifest_fetched_by_tag_is_named_in_the_algorithm_of_the_image() {
        for (body, alg) in [
            (MANIFEST, Algorithm::Sha256),
            (MANIFEST512, Algorithm::Sha512),
        ] {
            for stated in [
                None,
                Some(Digest::of(Algorithm::Sha256, body).to_string()),
                Some(Digest::of(Algorithm::Sha512, body).to_string()),
            ] {
                let host = manifest_registry(body, stated).await;
                let client = client_for(&host, true, true);
                let t = client.target(&reference(&host)).unwrap();
                let (_, digest) = client.fetch_manifest(&t, "latest").await.unwrap();
                assert_eq!(digest, Digest::of(alg, body));
            }
        }
    }

    #[test]
    fn test_the_algorithm_of_an_image_is_that_of_its_own_descriptors() {
        let d = |alg| Digest::of(alg, b"x").to_string();
        let index = |a: &str, b: &str| {
            format!(r#"{{"manifests":[{{"digest":"{a}","size":1}},{{"digest":"{b}","size":1}}]}}"#)
        };
        let (s256, s512) = (d(Algorithm::Sha256), d(Algorithm::Sha512));
        assert_eq!(image_algorithm(MANIFEST), Algorithm::Sha256);
        assert_eq!(image_algorithm(MANIFEST512), Algorithm::Sha512);
        assert_eq!(
            image_algorithm(index(&s512, &s512).as_bytes()),
            Algorithm::Sha512
        );
        // mixed, unknown or no descriptor at all: sha256
        for body in [
            index(&s256, &s512),
            index(&s512, "blake3:00"),
            index("sha512:00", "sha512:00"),
            r#"{"manifests":[]}"#.to_string(),
            "not json".to_string(),
        ] {
            assert_eq!(
                image_algorithm(body.as_bytes()),
                Algorithm::Sha256,
                "{body}"
            );
        }
    }

    #[tokio::test]
    async fn test_name_tag_at_sha512_is_fetched_by_the_tag_and_checked_by_the_digest() {
        let host = manifest_registry(MANIFEST, None).await;
        let client = client_for(&host, true, true);
        let d = Digest::of(Algorithm::Sha512, MANIFEST);
        let r = ImageReference::parse(&format!("{host}/r:latest@{d}")).unwrap();
        let (m, digest, body) = client.get_manifest_raw(&r, None).await.unwrap();
        assert_eq!((digest, &body[..], m.layers.len()), (d, MANIFEST, 0));
        let wrong = Digest::of(Algorithm::Sha512, b"other");
        let r = ImageReference::parse(&format!("{host}/r:latest@{wrong}")).unwrap();
        let err = client.get_manifest_raw(&r, None).await.unwrap_err();
        assert!(matches!(err, ImageError::DigestMismatch { .. }), "{err}");
        // the sha256 of the same bytes does not stand for the sha512 asked for
        let r = ImageReference::parse(&format!("{host}/r:latest@{}", sha256_of(b"other"))).unwrap();
        assert!(client.get_manifest_raw(&r, None).await.is_err());
    }

    #[test]
    fn test_blobs_and_configs_are_verified_with_their_own_algorithm() {
        for alg in Algorithm::ALL {
            let d = Digest::of(alg, b"abc");
            assert!(verify_digest(&d, b"abc").is_ok());
            let err = verify_digest(&d, b"abd").unwrap_err();
            assert!(err.to_string().contains(alg.name()), "{err}");
        }
    }

    #[tokio::test]
    async fn test_insecure_registry_falls_back_to_http_and_authenticates() {
        let (host, hits) = start_registry().await;
        let client = client_for(&host, true, true);
        let t = client.target(&reference(&host)).unwrap();
        let resp = client
            .get_blob(
                &t,
                &"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .parse()
                    .unwrap(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(&resp.bytes().await.unwrap()[..], BLOB);
        assert_eq!(hits.token.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_secure_registry_does_not_fall_back_to_http() {
        let (host, _hits) = start_registry().await;
        let client = client_for(&host, false, true);
        let t = client.target(&reference(&host)).unwrap();
        assert!(client
            .get_blob(
                &t,
                &"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .parse()
                    .unwrap(),
                None
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_tls_verify_false_accepts_plain_http() {
        let (host, _hits) = start_registry().await;
        let client = client_for(&host, false, true).with_tls_verify(false);
        let t = client.target(&reference(&host)).unwrap();
        assert!(client
            .get_blob(
                &t,
                &"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .parse()
                    .unwrap(),
                None
            )
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_redirect_is_cached_and_tokens_are_reused() {
        let (host, hits) = start_registry().await;
        let client = client_for(&host, true, true);
        let t = client.target(&reference(&host)).unwrap();
        for _ in 0..3 {
            let resp = client
                .get_blob(
                    &t,
                    &"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .parse()
                        .unwrap(),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(&resp.bytes().await.unwrap()[..], BLOB);
        }
        // Same origin here, so the redirect is not cached (only redirects
        // to another origin are); every request goes through the registry.
        // (the first request went without a token and learnt the challenge
        // from the 401)
        assert_eq!(hits.token.load(Ordering::SeqCst), 1);
        assert_eq!(hits.blob.load(Ordering::SeqCst), 4);
        assert_eq!(hits.cdn.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_redirect_to_another_origin_is_cached() {
        let (cdn_host, cdn_hits) = start_registry().await;
        let hits = Arc::new(Hits::default());
        let location = format!("http://{cdn_host}/cdn/blob");
        let app = Router::new()
            .route("/v2/", get(|| async { AxStatus::OK }))
            .route(
                "/v2/r/blobs/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                get(|State(h): State<Arc<Hits>>| async move {
                    h.blob.fetch_add(1, Ordering::SeqCst);
                    (AxStatus::FOUND, [(header::LOCATION, location)]).into_response()
                }),
            )
            .with_state(hits.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = client_for(&host, true, true);
        let t = client.target(&reference(&host)).unwrap();
        for _ in 0..3 {
            let resp = client
                .get_blob(
                    &t,
                    &"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .parse()
                        .unwrap(),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(&resp.bytes().await.unwrap()[..], BLOB);
        }
        assert_eq!(hits.blob.load(Ordering::SeqCst), 1);
        assert_eq!(cdn_hits.cdn.load(Ordering::SeqCst), 3);
    }

    #[derive(Clone, Copy)]
    enum Tokenless {
        Challenge,
        Status(AxStatus),
        Open,
        Basic,
    }

    #[derive(Default)]
    struct Counts {
        ping: AtomicUsize,
        blob: AtomicUsize,
        token: AtomicUsize,
    }

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn digest() -> Digest {
        DIGEST.parse().unwrap()
    }

    /// A registry that answers a request without `Authorization` as `mode`
    /// says (the pings counted include the one that finds the scheme of an
    /// insecure registry); `/v2/` and the blob with a token (or the basic credentials)
    /// are served.
    async fn start_mode_registry(mode: Tokenless) -> (String, Arc<Counts>) {
        let counts = Arc::new(Counts::default());
        let challenge = move |host: &str| match mode {
            Tokenless::Basic => "Basic realm=\"test\"".to_string(),
            _ => format!("Bearer realm=\"http://{host}/token\",service=\"test\""),
        };
        let authorized = |h: &AxHeaders| match h.get(header::AUTHORIZATION) {
            Some(v) => v.as_bytes() == b"Bearer secret" || v.as_bytes().starts_with(b"Basic "),
            None => false,
        };
        let app = Router::new()
            .route(
                "/v2/",
                get(
                    move |State(c): State<Arc<Counts>>, h: AxHeaders| async move {
                        c.ping.fetch_add(1, Ordering::SeqCst);
                        let host = h.get(header::HOST).unwrap().to_str().unwrap().to_string();
                        match mode {
                            Tokenless::Open => AxStatus::OK.into_response(),
                            _ if authorized(&h) => AxStatus::OK.into_response(),
                            _ => (
                                AxStatus::UNAUTHORIZED,
                                [(header::WWW_AUTHENTICATE, challenge(&host))],
                            )
                                .into_response(),
                        }
                    },
                ),
            )
            .route(
                "/token",
                get(|State(c): State<Arc<Counts>>| async move {
                    c.token.fetch_add(1, Ordering::SeqCst);
                    r#"{"token":"secret","expires_in":300}"#
                }),
            )
            .route(
                &format!("/v2/r/blobs/{DIGEST}"),
                get(
                    move |State(c): State<Arc<Counts>>, h: AxHeaders| async move {
                        c.blob.fetch_add(1, Ordering::SeqCst);
                        if matches!(mode, Tokenless::Open) {
                            return BLOB.into_response();
                        }
                        if authorized(&h) {
                            return BLOB.into_response();
                        }
                        let host = h.get(header::HOST).unwrap().to_str().unwrap().to_string();
                        match mode {
                            Tokenless::Status(s) => s.into_response(),
                            _ => (
                                AxStatus::UNAUTHORIZED,
                                [(header::WWW_AUTHENTICATE, challenge(&host))],
                            )
                                .into_response(),
                        }
                    },
                ),
            )
            .with_state(counts.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (addr.to_string(), counts)
    }

    async fn get_twice(client: &RegistryClient, host: &str) {
        let t = client.target(&reference(host)).unwrap();
        for _ in 0..2 {
            let resp = client.get_blob(&t, &digest(), None).await.unwrap();
            assert_eq!(resp.status(), 200);
            assert_eq!(&resp.bytes().await.unwrap()[..], BLOB);
        }
    }

    #[tokio::test]
    async fn test_tokenless_401_with_a_challenge_needs_no_ping() {
        let (host, c) = start_mode_registry(Tokenless::Challenge).await;
        get_twice(&client_for(&host, true, true), &host).await;
        assert_eq!(c.ping.load(Ordering::SeqCst), 1);
        assert_eq!(c.token.load(Ordering::SeqCst), 1);
        assert_eq!(c.blob.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_tokenless_403_and_404_ask_v2_once_and_remember() {
        for status in [AxStatus::FORBIDDEN, AxStatus::NOT_FOUND] {
            let (host, c) = start_mode_registry(Tokenless::Status(status)).await;
            get_twice(&client_for(&host, true, true), &host).await;
            assert_eq!(c.ping.load(Ordering::SeqCst), 2, "{status}");
            assert_eq!(c.token.load(Ordering::SeqCst), 1, "{status}");
            // the tokenless try, then one request per call with the token
            assert_eq!(c.blob.load(Ordering::SeqCst), 3, "{status}");
        }
    }

    #[tokio::test]
    async fn test_tokenless_401_without_a_challenge_asks_v2() {
        let (host, c) = start_mode_registry(Tokenless::Status(AxStatus::UNAUTHORIZED)).await;
        get_twice(&client_for(&host, true, true), &host).await;
        assert_eq!(c.ping.load(Ordering::SeqCst), 2);
        assert_eq!(c.blob.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_tokenless_403_is_returned_when_v2_does_not_say() {
        let counts = Arc::new(Counts::default());
        let app = Router::new()
            .route(
                &format!("/v2/r/blobs/{DIGEST}"),
                get(|State(c): State<Arc<Counts>>| async move {
                    c.blob.fetch_add(1, Ordering::SeqCst);
                    AxStatus::FORBIDDEN
                }),
            )
            .with_state(counts.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = client_for(&host, true, true);
        let t = client.target(&reference(&host)).unwrap();
        let resp = client.get_blob(&t, &digest(), None).await.unwrap();
        assert_eq!(resp.status(), 403);
        assert_eq!(counts.blob.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_registry_that_needs_no_auth_is_remembered() {
        let (host, c) = start_mode_registry(Tokenless::Open).await;
        get_twice(&client_for(&host, true, true), &host).await;
        assert_eq!(c.ping.load(Ordering::SeqCst), 1);
        assert_eq!(c.token.load(Ordering::SeqCst), 0);
        assert_eq!(c.blob.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_basic_auth_registry_with_credentials() {
        let (host, c) = start_mode_registry(Tokenless::Basic).await;
        let conf = format!("[[registry]]\nlocation = \"{host}\"\ninsecure = true\n");
        let client = RegistryClient::with_config(
            TransportConfig {
                registries: super::super::config::RegistriesConfig::parse(&conf).unwrap(),
                certs_dirs: vec![],
                tls_verify: true,
            },
            AuthConfig::default().with_credentials(&host, Credentials::basic("u", "p")),
        );
        get_twice(&client, &host).await;
        assert_eq!(c.ping.load(Ordering::SeqCst), 2);
        assert_eq!(c.token.load(Ordering::SeqCst), 0);
    }

    /// A registry that wants basic credentials for its blob and sends the
    /// blob to `cdn`; and a "CDN" that notes whether a request of it had
    /// an `Authorization`.
    #[tokio::test]
    async fn test_credentials_do_not_follow_a_redirect_to_another_host() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::<Option<String>>::new()));
        let log = seen.clone();
        let cdn = Router::new().route(
            "/blob",
            get(move |h: AxHeaders| {
                let log = log.clone();
                async move {
                    log.lock().unwrap().push(
                        h.get(header::AUTHORIZATION)
                            .map(|v| v.to_str().unwrap().to_string()),
                    );
                    BLOB
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cdn_host = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { axum::serve(listener, cdn).await.unwrap() });
        let location = format!("http://{cdn_host}/blob");
        let basic = |h: &AxHeaders| {
            h.get(header::AUTHORIZATION).is_none().then(|| {
                (
                    AxStatus::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Basic realm=\"test\"".to_string())],
                )
                    .into_response()
            })
        };
        let registry = Router::new()
            .route(
                "/v2/",
                get(move |h: AxHeaders| async move {
                    basic(&h).unwrap_or_else(|| AxStatus::OK.into_response())
                }),
            )
            .route(
                &format!("/v2/r/blobs/{DIGEST}"),
                get(move |h: AxHeaders| {
                    let location = location.clone();
                    async move {
                        basic(&h).unwrap_or_else(|| {
                            (AxStatus::FOUND, [(header::LOCATION, location)]).into_response()
                        })
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { axum::serve(listener, registry).await.unwrap() });
        let conf = format!("[[registry]]\nlocation = \"{host}\"\ninsecure = true\n");
        let client = RegistryClient::with_config(
            TransportConfig {
                registries: super::super::config::RegistriesConfig::parse(&conf).unwrap(),
                certs_dirs: vec![],
                tls_verify: true,
            },
            AuthConfig::default().with_credentials(&host, Credentials::basic("u", "p")),
        );
        let t = client.target(&reference(&host)).unwrap();
        let resp = client.get_blob(&t, &digest(), None).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(&resp.bytes().await.unwrap()[..], BLOB);
        // the blob came from the other host, and nothing of the registry's
        // credentials went with the request
        assert_eq!(*seen.lock().unwrap(), vec![None]);
    }

    /// A registry that wants basic credentials and names an upload session
    /// on another host: the requests of the session go there without the
    /// registry's credentials.
    #[tokio::test]
    async fn test_credentials_do_not_go_to_an_upload_session_on_another_host() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::<(String, Option<String>)>::new()));
        let log = seen.clone();
        let session = Router::new().route(
            "/upload/1",
            axum::routing::any(move |m: axum::http::Method, h: AxHeaders| {
                let log = log.clone();
                async move {
                    log.lock().unwrap().push((
                        m.to_string(),
                        h.get(header::AUTHORIZATION)
                            .map(|v| v.to_str().unwrap().to_string()),
                    ));
                    AxStatus::CREATED
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let other = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { axum::serve(listener, session).await.unwrap() });
        let location = format!("http://{other}/upload/1");
        let basic = |h: &AxHeaders| {
            h.get(header::AUTHORIZATION).is_none().then(|| {
                (
                    AxStatus::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Basic realm=\"test\"".to_string())],
                )
                    .into_response()
            })
        };
        let registry = Router::new()
            .route(
                "/v2/",
                get(move |h: AxHeaders| async move {
                    basic(&h).unwrap_or_else(|| AxStatus::OK.into_response())
                }),
            )
            .route(
                "/v2/r/blobs/uploads/",
                axum::routing::post(move |h: AxHeaders| {
                    let location = location.clone();
                    async move {
                        basic(&h).unwrap_or_else(|| {
                            (AxStatus::ACCEPTED, [(header::LOCATION, location)]).into_response()
                        })
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { axum::serve(listener, registry).await.unwrap() });
        let conf = format!("[[registry]]\nlocation = \"{host}\"\ninsecure = true\n");
        let client = RegistryClient::with_config(
            TransportConfig {
                registries: super::super::config::RegistriesConfig::parse(&conf).unwrap(),
                certs_dirs: vec![],
                tls_verify: true,
            },
            AuthConfig::default().with_credentials(&host, Credentials::basic("u", "p")),
        );
        let t = client.push_target(&reference(&host)).unwrap();
        let UploadStart::Session(url) = client.start_upload(&t, None).await.unwrap() else {
            panic!("no upload session");
        };
        assert_eq!(url.as_str(), format!("http://{other}/upload/1"));
        client
            .finish_upload(&t, &url, 0, &digest(), Bytes::from_static(BLOB))
            .await
            .unwrap();
        // the session was asked, never with the registry's credentials
        let seen = seen.lock().unwrap();
        assert!(!seen.is_empty());
        assert!(seen.iter().all(|(_, auth)| auth.is_none()), "{seen:?}");
    }

    /// A registry with no search of its own that lists its catalog to the
    /// users it knows: the search asks it with the credentials.
    #[tokio::test]
    async fn test_the_catalog_is_asked_with_the_credentials() {
        let guarded = |body: &'static str| {
            move |h: AxHeaders| async move {
                match h.get(header::AUTHORIZATION) {
                    Some(_) => body.into_response(),
                    None => (
                        AxStatus::UNAUTHORIZED,
                        [(header::WWW_AUTHENTICATE, "Basic realm=\"test\"")],
                    )
                        .into_response(),
                }
            }
        };
        let app = Router::new()
            .route("/v1/search", get(|| async { AxStatus::NOT_FOUND }))
            .route("/v2/", get(guarded("{}")))
            .route("/v2/_catalog", get(guarded(r#"{"repositories":["a/b"]}"#)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let conf = format!("[[registry]]\nlocation = \"{host}\"\ninsecure = true\n");
        let client = RegistryClient::with_config(
            TransportConfig {
                registries: super::super::config::RegistriesConfig::parse(&conf).unwrap(),
                certs_dirs: vec![],
                tls_verify: true,
            },
            AuthConfig::default().with_credentials(&host, Credentials::basic("u", "p")),
        );
        let image = ImageReference::parse(&format!("{host}/search")).unwrap();
        let t = client.push_target(&image).unwrap();
        let (v1, body) = client
            .search_raw(&t, "a", 10, false, 1 << 20)
            .await
            .unwrap();
        assert!(!v1);
        assert_eq!(&body[..], br#"{"repositories":["a/b"]}"#);
    }

    /// The tags of a repository come in pages: the `Link` to the next one
    /// is followed, and only when it is a page of the same repository.
    #[tokio::test]
    async fn test_the_tags_of_every_page_are_listed() {
        use axum::extract::RawQuery;
        let page = |RawQuery(q): RawQuery| async move {
            match q.as_deref() {
                None => (
                    [(header::LINK, "</v2/r/tags/list?last=b&n=2>; rel=\"next\"")],
                    r#"{"name":"r","tags":["a","b"]}"#,
                )
                    .into_response(),
                Some("last=b&n=2") => (
                    [(header::LINK, "</v2/r/tags/list?last=d&n=2>; rel=\"next\"")],
                    r#"{"name":"r","tags":["c","d"]}"#,
                )
                    .into_response(),
                // (a link to another repository is not followed)
                _ => (
                    [(header::LINK, "</v2/other/tags/list?n=2>; rel=\"next\"")],
                    r#"{"name":"r","tags":["e"]}"#,
                )
                    .into_response(),
            }
        };
        let app = Router::new()
            .route("/v2/", get(|| async { AxStatus::OK }))
            .route("/v2/r/tags/list", get(page));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = client_for(&host, true, true);
        let t = client.target(&reference(&host)).unwrap();
        let body = client.list_tags_raw(&t).await.unwrap();
        assert_eq!(parse_tags(&body).unwrap(), ["a", "b", "c", "d", "e"]);
    }

    #[test]
    fn test_the_next_page_of_a_listing_is_a_path_of_that_listing() {
        let link = |path: &str| format!("<{path}>; rel=\"next\"");
        assert_eq!(
            next_page(&link("/v2/r/tags/list?last=b"), "/v2/r/tags/list").as_deref(),
            Some("/v2/r/tags/list?last=b")
        );
        // (a link with a host: its path, asked of the registry)
        assert_eq!(
            next_page(
                &link("https://elsewhere/v2/r/tags/list?last=b"),
                "/v2/r/tags/list"
            )
            .as_deref(),
            Some("/v2/r/tags/list?last=b")
        );
        for other in [
            "/v2/s/tags/list?last=b",
            "http://elsewhere/v2/s/tags/list?last=b",
            "file:///v2/r/tags/list?last=b",
            "https://elsewhere/v2/r/tags/list",
            "/v2/r/tags/list",
            "/v2/r/tags/list?a#b",
        ] {
            assert_eq!(next_page(&link(other), "/v2/r/tags/list"), None, "{other}");
        }
    }

    /// An upload endpoint: it appends what it gets, can lose a PATCH half
    /// way (half of the data kept, a 500), refuse ranges, fail a PUT.
    #[derive(Default)]
    struct Uploads {
        data: std::sync::Mutex<Vec<u8>>,
        lose_patches: AtomicUsize,
        fail_puts: AtomicUsize,
        refuse_ranges: bool,
        /// every PATCH is sent to a place the client refuses to go to
        misdirect: bool,
        patches: AtomicUsize,
        ranged_patches: AtomicUsize,
        done: std::sync::Mutex<Option<String>>,
    }

    async fn start_upload_registry(u: Uploads) -> (String, Arc<Uploads>) {
        use axum::body::Bytes as AxBytes;
        use axum::extract::RawQuery;
        let u = Arc::new(u);
        let range_of = |n: usize| format!("0-{}", n.saturating_sub(1));
        let app = Router::new()
            .route("/v2/", get(|| async { AxStatus::OK }))
            .route(
                "/v2/r/blobs/uploads/",
                axum::routing::post(|| async {
                    (AxStatus::ACCEPTED, [(header::LOCATION, "/up/1")]).into_response()
                }),
            )
            .route(
                "/up/1",
                axum::routing::patch(
                    move |State(u): State<Arc<Uploads>>, h: AxHeaders, body: AxBytes| async move {
                        u.patches.fetch_add(1, Ordering::SeqCst);
                        if u.misdirect {
                            return (AxStatus::TEMPORARY_REDIRECT, [(header::LOCATION, "ftp://elsewhere/")])
                                .into_response();
                        }
                        let mut data = u.data.lock().unwrap();
                        if let Some(r) = h.get(header::CONTENT_RANGE) {
                            u.ranged_patches.fetch_add(1, Ordering::SeqCst);
                            let start: usize = r.to_str().unwrap().split('-').next().unwrap().parse().unwrap();
                            if u.refuse_ranges || start != data.len() {
                                return AxStatus::RANGE_NOT_SATISFIABLE.into_response();
                            }
                        }
                        if u.lose_patches.load(Ordering::SeqCst) > 0 {
                            u.lose_patches.fetch_sub(1, Ordering::SeqCst);
                            data.extend_from_slice(&body[..body.len() / 2]);
                            return AxStatus::INTERNAL_SERVER_ERROR.into_response();
                        }
                        data.extend_from_slice(&body);
                        (
                            AxStatus::ACCEPTED,
                            [(header::LOCATION, "/up/1".to_string()), (header::RANGE, range_of(data.len()))],
                        )
                            .into_response()
                    },
                )
                .get(move |State(u): State<Arc<Uploads>>| async move {
                    let n = u.data.lock().unwrap().len();
                    (
                        AxStatus::NO_CONTENT,
                        [(header::LOCATION, "/up/1".to_string()), (header::RANGE, range_of(n))],
                    )
                        .into_response()
                })
                .put(move |State(u): State<Arc<Uploads>>, RawQuery(q): RawQuery, body: AxBytes| async move {
                    if u.fail_puts.load(Ordering::SeqCst) > 0 {
                        u.fail_puts.fetch_sub(1, Ordering::SeqCst);
                        return AxStatus::BAD_GATEWAY.into_response();
                    }
                    let mut data = u.data.lock().unwrap();
                    data.extend_from_slice(&body);
                    let digest = sha256_of(&data[..]).to_string();
                    let asked = q.unwrap_or_default().replace("digest=", "").replace("%3A", ":");
                    if asked != digest {
                        return AxStatus::BAD_REQUEST.into_response();
                    }
                    *u.done.lock().unwrap() = Some(digest);
                    AxStatus::CREATED.into_response()
                }),
            )
            .route(
                "/v2/r/blobs/{digest}",
                axum::routing::head(|| async { AxStatus::NOT_FOUND }),
            )
            .with_state(u.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (addr.to_string(), u)
    }

    /// Upload 3 pieces of 10 bytes and the last 5 bytes.
    async fn upload_all(host: &str) -> ImageResult<()> {
        let client = client_for(host, true, true);
        let t = client.push_target(&reference(host)).unwrap();
        let blob: Vec<u8> = (0..35u8).collect();
        let digest = sha256_of(&blob);
        let UploadStart::Session(mut session) = client.start_upload(&t, None).await? else {
            panic!("mounted")
        };
        for at in (0..30).step_by(10) {
            session = client
                .upload_chunk(
                    &t,
                    &session,
                    at as u64,
                    Bytes::copy_from_slice(&blob[at..at + 10]),
                )
                .await?;
        }
        client
            .finish_upload(
                &t,
                &session,
                30,
                &digest,
                Bytes::copy_from_slice(&blob[30..]),
            )
            .await
    }

    #[tokio::test]
    async fn a_lost_upload_piece_goes_on_from_what_the_registry_has() {
        let (host, u) = start_upload_registry(Uploads {
            lose_patches: AtomicUsize::new(2),
            fail_puts: AtomicUsize::new(1),
            ..Default::default()
        })
        .await;
        upload_all(&host).await.unwrap();
        assert_eq!(*u.data.lock().unwrap(), (0..35u8).collect::<Vec<_>>());
        assert!(u.done.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn a_registry_without_content_range_gets_streamed_pieces() {
        let (host, u) = start_upload_registry(Uploads {
            refuse_ranges: true,
            ..Default::default()
        })
        .await;
        upload_all(&host).await.unwrap();
        assert_eq!(*u.data.lock().unwrap(), (0..35u8).collect::<Vec<_>>());
        // one refused, then none asked
        assert_eq!(u.ranged_patches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_upload_that_keeps_failing_is_an_error() {
        let (host, _u) = start_upload_registry(Uploads {
            lose_patches: AtomicUsize::new(100),
            ..Default::default()
        })
        .await;
        assert!(upload_all(&host).await.is_err());
    }

    #[tokio::test]
    async fn a_refused_upload_request_is_not_tried_again() {
        let (host, u) = start_upload_registry(Uploads {
            misdirect: true,
            ..Default::default()
        })
        .await;
        assert!(upload_all(&host).await.is_err());
        assert_eq!(u.patches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn upload_ranges() {
        assert_eq!(parse_upload_range("0-9"), Some(10));
        assert_eq!(parse_upload_range("0-0"), Some(0));
        assert_eq!(parse_upload_range("0--1"), Some(0));
        assert_eq!(parse_upload_range("5-9"), None);
        assert_eq!(parse_upload_range("x"), None);
    }

    /// The resolver of the clients, as far as the report of a failure goes.
    struct Lookup;

    impl reqwest::dns::Resolve for Lookup {
        fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
            Box::pin(async move {
                let addrs = crate::netpolicy::lookup(name.as_str(), 0).await?;
                Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
            })
        }
    }

    #[tokio::test]
    async fn a_name_that_does_not_resolve_is_told_as_go_does() {
        let client = reqwest::Client::builder()
            .dns_resolver(Arc::new(Lookup))
            .build()
            .unwrap();
        let e = client
            .get("http://no-such-host.invalid/v2/")
            .send()
            .await
            .unwrap_err();
        assert_eq!(
            go_cause("no-such-host.invalid:80", &e),
            "dial tcp: lookup no-such-host.invalid: no such host"
        );
        assert!(!connection_lost(&e));
    }

    /// A server that closes the connection before it answers is a lost
    /// connection; one that answers is not.
    #[tokio::test]
    async fn a_connection_closed_before_the_answer_is_lost() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            drop(conn);
        });
        let e = reqwest::Client::new().get(&url).send().await.unwrap_err();
        server.await.unwrap();
        assert!(connection_lost(&e), "{e:?}");
        // a refused connection is not one that was lost (a port bound and
        // not listening: the port the listener had may be another test's
        // by now)
        let closed = tokio::net::TcpSocket::new_v4().unwrap();
        closed.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let url = format!("http://{}/", closed.local_addr().unwrap());
        let e = reqwest::Client::new().get(&url).send().await.unwrap_err();
        assert!(!connection_lost(&e), "{e:?}");
        assert!(go_cause("127.0.0.1:1", &e).contains("connection refused"));
    }

    type AuthLog = Arc<std::sync::Mutex<Vec<Option<String>>>>;

    /// A server whose every request is noted with its `Authorization`, and
    /// is answered with the token `token`.
    async fn start_logging_server(token: &'static str) -> (String, AuthLog) {
        let seen = AuthLog::default();
        let log = seen.clone();
        let app = Router::new().fallback(get(move |h: AxHeaders| {
            let log = log.clone();
            async move {
                log.lock().unwrap().push(
                    h.get(header::AUTHORIZATION)
                        .map(|v| v.to_str().unwrap().to_string()),
                );
                format!("{{\"token\":\"{token}\",\"expires_in\":300}}")
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (host, seen)
    }

    /// A registry that asks for a token from its own `/token` (which notes
    /// the `Authorization` of its requests) and serves the blob for it.
    async fn start_noting_registry() -> (String, AuthLog) {
        let seen = AuthLog::default();
        let log = seen.clone();
        let app = Router::new()
            .route(
                "/v2/",
                get(|h: AxHeaders| async move { challenge_or(&h, AxStatus::OK.into_response()) }),
            )
            .route(
                "/token",
                get(move |h: AxHeaders| {
                    let log = log.clone();
                    async move {
                        log.lock().unwrap().push(
                            h.get(header::AUTHORIZATION)
                                .map(|v| v.to_str().unwrap().to_string()),
                        );
                        r#"{"token":"secret","expires_in":300}"#
                    }
                }),
            )
            .route(
                &format!("/v2/r/blobs/{DIGEST}"),
                get(|h: AxHeaders| async move { challenge_or(&h, BLOB.into_response()) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (host, seen)
    }

    fn challenge_or(h: &AxHeaders, ok: axum::response::Response) -> axum::response::Response {
        if h.get(header::AUTHORIZATION).map(|v| v.as_bytes()) == Some(b"Bearer secret") {
            return ok;
        }
        let host = h.get(header::HOST).unwrap().to_str().unwrap().to_string();
        (
            AxStatus::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                format!("Bearer realm=\"http://{host}/token\",service=\"test\""),
            )],
        )
            .into_response()
    }

    fn spec_with_hint(host: &str, realm: &str, credentials: bool) -> EndpointSpec {
        EndpointSpec {
            host: host.to_string(),
            repository: "r".into(),
            insecure: true,
            allow_private: true,
            credentials: credentials.then(|| Credentials::basic("user", "hunter2")),
            certs: Default::default(),
            brokered: false,
            hint: Some(Hint {
                transport: "http".into(),
                auth: HintAuth::Bearer {
                    realm: realm.into(),
                    service: Some("test".into()),
                },
                cdn: None,
            }),
            hints: false,
            min_speed: Default::default(),
            scheme: None,
        }
    }

    /// The scheme a worker found an insecure registry to speak is told
    /// once, and a worker that is told it does not probe the registry.
    #[tokio::test]
    async fn test_a_scheme_found_is_told_and_not_probed_again() {
        let (host, c) = start_mode_registry(Tokenless::Open).await;
        let spec = EndpointSpec {
            hint: None,
            ..spec_with_hint(&host, "", false)
        };
        let (client, t) = RegistryClient::from_specs(std::slice::from_ref(&spec)).unwrap();
        assert_eq!(
            client.get_blob(&t, &digest(), None).await.unwrap().status(),
            200
        );
        assert_eq!(c.ping.load(Ordering::SeqCst), 1);
        assert_eq!(
            client.take_notices().schemes,
            [(host.clone(), Scheme::Http)]
        );
        assert!(client.take_notices().schemes.is_empty());

        let told = EndpointSpec {
            scheme: Some(Scheme::Http),
            ..spec.clone()
        };
        let (client, t) = RegistryClient::from_specs(&[told]).unwrap();
        assert_eq!(
            client.get_blob(&t, &digest(), None).await.unwrap().status(),
            200
        );
        assert_eq!(c.ping.load(Ordering::SeqCst), 1);
        assert!(client.take_notices().schemes.is_empty());

        // a registry that is not insecure is reached over HTTPS whatever
        // it is told
        let secure = EndpointSpec {
            insecure: false,
            scheme: Some(Scheme::Http),
            ..spec
        };
        let (client, t) = RegistryClient::from_specs(&[secure]).unwrap();
        let base = client.host(&t).unwrap().base_url().await.unwrap();
        assert_eq!(base, format!("https://{host}"));
    }

    async fn pull_with_hint(spec: EndpointSpec) {
        let (client, t) = RegistryClient::from_specs(&[spec]).unwrap();
        let resp = client.get_blob(&t, &digest(), None).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(&resp.bytes().await.unwrap()[..], BLOB);
    }

    /// A cached realm of another host gets no request, with or without
    /// credentials: the realm is learned from the registry.
    #[tokio::test]
    async fn test_cached_realm_of_another_host_gets_nothing() {
        for credentials in [true, false] {
            let (evil, evil_seen) = start_logging_server("evil").await;
            let (host, own_seen) = start_noting_registry().await;
            let realm = format!("http://{evil}/token");
            pull_with_hint(spec_with_hint(&host, &realm, credentials)).await;
            assert!(evil_seen.lock().unwrap().is_empty(), "{credentials}");
            let own = own_seen.lock().unwrap().clone();
            assert_eq!(own.len(), 1, "{credentials}");
            // the live realm is the registry's own, which is trusted with
            // the credentials
            assert_eq!(own[0].is_some(), credentials);
        }
    }

    /// A realm of another host that the registry names in its own 401 gets
    /// the credentials, cached or not: what the registry says live is
    /// trusted, only the cache is not.
    #[tokio::test]
    async fn test_live_realm_of_another_host_gets_the_credentials() {
        for cached in [false, true] {
            let (auth, auth_seen) = start_logging_server("secret").await;
            let realm = format!("http://{auth}/token");
            let challenge = realm.clone();
            let answer = move |h: AxHeaders, ok: &'static [u8]| {
                if h.get(header::AUTHORIZATION).map(|v| v.as_bytes()) == Some(b"Bearer secret") {
                    return ok.into_response();
                }
                (
                    AxStatus::UNAUTHORIZED,
                    [(
                        header::WWW_AUTHENTICATE,
                        format!("Bearer realm=\"{challenge}\",service=\"test\""),
                    )],
                )
                    .into_response()
            };
            let (a, b) = (answer.clone(), answer);
            let app = Router::new()
                .route("/v2/", get(move |h: AxHeaders| async move { a(h, b"") }))
                .route(
                    &format!("/v2/r/blobs/{DIGEST}"),
                    get(move |h: AxHeaders| async move { b(h, BLOB) }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let host = listener.local_addr().unwrap().to_string();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let mut spec = spec_with_hint(&host, &realm, true);
            if !cached {
                spec.hint = None;
            }
            pull_with_hint(spec).await;
            let seen = auth_seen.lock().unwrap().clone();
            assert_eq!(seen.len(), 1, "{cached}");
            assert!(
                seen[0].as_deref().unwrap().starts_with("Basic "),
                "{cached}"
            );
        }
    }

    /// The same host with another port is another host for a realm.
    #[tokio::test]
    async fn test_cached_realm_of_another_port_gets_nothing() {
        let (evil, evil_seen) = start_logging_server("evil").await;
        let (host, _) = start_noting_registry().await;
        let port = evil.rsplit(':').next().unwrap();
        let name = host.split(':').next().unwrap();
        let realm = format!("http://{name}:{port}/token");
        pull_with_hint(spec_with_hint(&host, &realm, true)).await;
        assert!(evil_seen.lock().unwrap().is_empty());
    }

    /// A cached realm of the registry's own host is used (the token is
    /// asked for once, with the credentials).
    #[tokio::test]
    async fn test_cached_realm_of_the_registry_gets_the_credentials() {
        let (host, seen) = start_noting_registry().await;
        let realm = format!("http://{host}/token");
        pull_with_hint(spec_with_hint(&host, &realm, true)).await;
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].as_deref().unwrap().starts_with("Basic "));
    }

    /// What is seeded: the registry's own realm, and nothing else.
    #[test]
    fn test_seed_holds_a_cached_realm_to_the_registry() {
        let seeded = |host: &str, realm: &str, credentials: bool| {
            let mut spec = spec_with_hint(host, realm, credentials);
            spec.insecure = false;
            spec.hint.as_mut().unwrap().transport = "https".into();
            let client = client_for(host, false, true);
            client.seed(&spec);
            let c = client.challenges.lock().unwrap().get(host).cloned();
            c
        };
        for credentials in [true, false] {
            assert!(seeded("reg.example", "https://reg.example/token", credentials).is_some());
            assert!(seeded("reg.example", "https://REG.example:443/token", credentials).is_some());
            assert!(seeded("reg.example", "https://evil.example/token", credentials).is_none());
            assert!(seeded("reg.example", "https://reg.example:8443/token", credentials).is_none());
            assert!(seeded("reg.example", "https://reg.example.evil/token", credentials).is_none());
            // (the realm of Docker Hub is another host than its registry)
            assert!(seeded(
                "registry-1.docker.io",
                "https://auth.docker.io/token",
                credentials
            )
            .is_none());
            assert!(seeded(
                "registry.example",
                "https://auth.docker.io/token",
                credentials
            )
            .is_none());
            assert!(seeded(
                "registry-1.docker.io",
                "https://evil.example/token",
                credentials
            )
            .is_none());
        }
    }
}
