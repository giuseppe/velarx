// SPDX-License-Identifier: Apache-2.0
//! HTTP transport for registries.
//!
//! One [`HostTransport`] per registry host: its own connection pool (HTTP/2
//! when the server speaks it, connections reused by all the requests of the
//! process), the TLS trust and client certificate configured for the host in
//! `certs.d`, and the scheme: registries marked `insecure` in
//! `registries.conf` (or every registry with `--tls-verify=false`) skip the
//! certificate checks and may be reached over plain HTTP, tried after HTTPS
//! like containers/image does.  The flag is the registry's, and so wide as
//! its requests: the client of a host is also the one of the token endpoint
//! the registry names and of the CDN it redirects a blob to, so those are
//! reached without certificate checks too (and with the client certificate
//! of the registry).
//!
//! The directories searched for `<dir>/<host[:port]>/` are
//! `/etc/velarx/certs.d`, `/etc/docker/certs.d` and, rootless,
//! `$XDG_CONFIG_HOME/velarx/certs.d` (`~/.config` without it).  In them `*.crt` files are CA
//! certificates added to the system roots, and a `*.cert` file with the
//! `*.key` file of the same name is a client certificate.

use super::netpolicy::Policy;
use reqwest::{Certificate, Identity};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, warn};
use velarx_types::{ImageError, ImageResult};

use super::certs::RawCerts;
use super::target::Endpoint;

/// How long to wait for a connection (and TLS handshake) to be established.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// A transfer that makes no progress for this long fails.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Entries kept by the redirect cache.
const REDIRECT_CACHE_SIZE: usize = 64;

/// What `certs.d/<host>` holds.
#[derive(Default, Clone)]
pub struct HostCerts {
    pub ca: Vec<Certificate>,
    pub identity: Option<Identity>,
    /// The files the above come from, for a process that cannot read
    /// `certs.d`: the CA bundles, the client certificate and its key.
    pub raw: RawCerts,
}

impl HostCerts {
    /// The certificates in PEM files.
    pub fn from_raw(raw: RawCerts) -> ImageResult<Self> {
        let mut certs = HostCerts::default();
        for pem in &raw.ca {
            certs.ca.extend(
                Certificate::from_pem_bundle(pem.as_bytes())
                    .map_err(|e| ImageError::Registry(format!("invalid CA certificate: {e}")))?,
            );
        }
        if let (Some(cert), Some(key)) = (&raw.cert, &raw.key) {
            certs.identity = Some(
                Identity::from_pkcs8_pem(cert.as_bytes(), key.as_bytes()).map_err(|e| {
                    ImageError::Registry(format!("invalid client certificate: {e}"))
                })?,
            );
        }
        certs.raw = raw;
        Ok(certs)
    }
}

pub use super::target::Scheme;

/// Names whose addresses were checked before a connection in advance, and
/// that the connections to them are made to (so that the name is resolved
/// once: what is checked is what is connected to).  A name stays for as long
/// as one of the connections in advance that pinned it is being made.
#[derive(Default)]
pub struct Pinned {
    names: Mutex<HashMap<String, (Vec<std::net::SocketAddr>, usize)>>,
}

/// The pin of a name, undone when it is dropped.
pub struct Pin {
    pinned: Arc<Pinned>,
    name: String,
}

impl Drop for Pin {
    fn drop(&mut self) {
        let mut names = self.pinned.names.lock().unwrap();
        if let Some(entry) = names.get_mut(&self.name) {
            entry.1 -= 1;
            if entry.1 == 0 {
                names.remove(&self.name);
            }
        }
    }
}

/// The resolver of the clients: the system's, but for the names pinned.
struct PinResolver(Arc<Pinned>, Arc<Policy>);

impl reqwest::dns::Resolve for PinResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let name = name.as_str().to_ascii_lowercase();
        let policy = self.1.clone();
        let pinned = self
            .0
            .names
            .lock()
            .unwrap()
            .get(&name)
            .map(|(addrs, _)| addrs.clone());
        Box::pin(async move {
            let addrs: Vec<std::net::SocketAddr> = match pinned {
                Some(addrs) => addrs,
                None => {
                    let addrs = super::netpolicy::lookup(&name, 0).await?;
                    policy.filter(&name, addrs).await?
                }
            };
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Connection state of one registry host.
pub struct HostTransport {
    pub host: String,
    pub insecure: bool,
    certs: HostCerts,
    /// Built when the first request is made: a process that only describes
    /// the registry to another one never needs it.
    client: std::sync::OnceLock<Result<reqwest::Client, String>>,
    scheme: tokio::sync::OnceCell<Scheme>,
    /// The scheme was told, or came from who found it out
    scheme_told: std::sync::atomic::AtomicBool,
    pinned: Arc<Pinned>,
    policy: Arc<Policy>,
    /// The registry refused a `Content-Range` on an upload: its pieces go
    /// without one (streamed, appended in order)
    pub no_content_range: std::sync::atomic::AtomicBool,
}

impl HostTransport {
    fn new(host: &str, insecure: bool, allow_private: bool, certs: HostCerts) -> Self {
        Self {
            host: host.to_string(),
            insecure,
            certs,
            client: std::sync::OnceLock::new(),
            scheme: tokio::sync::OnceCell::new(),
            scheme_told: std::sync::atomic::AtomicBool::new(false),
            pinned: Arc::default(),
            policy: Arc::new(Policy::new(host, allow_private)),
            no_content_range: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn build_client(&self) -> Result<reqwest::Client, String> {
        let certs = self.certs.clone();
        let insecure = self.insecure;
        let mut builder = reqwest::Client::builder()
            .user_agent("velarx/1.0")
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .tcp_nodelay(true)
            .dns_resolver(Arc::new(PinResolver(
                self.pinned.clone(),
                self.policy.clone(),
            )))
            .pool_max_idle_per_host(16)
            // Blobs are large: the default HTTP/2 flow control windows
            // (64 KiB) would stall the transfers on every round trip.
            .http2_initial_stream_window_size(8 * 1024 * 1024)
            .http2_initial_connection_window_size(32 * 1024 * 1024);
        for ca in certs.ca {
            builder = builder.add_root_certificate(ca);
        }
        if let Some(identity) = certs.identity {
            builder = builder.identity(identity);
        }
        if insecure {
            builder = builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }
        builder
            .build()
            .map_err(|e| format!("cannot create the HTTP client: {e}"))
    }

    /// The HTTP client of this host (connections are pooled and shared by
    /// all its clones).
    pub fn client(&self) -> ImageResult<&reqwest::Client> {
        self.client
            .get_or_init(|| self.build_client())
            .as_ref()
            .map_err(|e| ImageError::Registry(e.clone()))
    }

    /// Make the connections to `name` go to `addrs` (already checked) until
    /// the pin is dropped.
    pub fn pin(&self, name: &str, addrs: Vec<std::net::SocketAddr>) -> Pin {
        let name = name.to_ascii_lowercase();
        let mut names = self.pinned.names.lock().unwrap();
        let entry = names.entry(name.clone()).or_insert((Vec::new(), 0));
        entry.0 = addrs;
        entry.1 += 1;
        Pin {
            pinned: self.pinned.clone(),
            name,
        }
    }

    /// Refuse a URL that a registry gave (a token realm, a redirect) when it
    /// is a private address and the registry is not on one.
    pub async fn check_url(&self, url: &reqwest::Url) -> ImageResult<()> {
        self.policy
            .check_url(url)
            .await
            .map_err(ImageError::Registry)
    }

    /// How many names are pinned.
    #[cfg(test)]
    pub fn pinned_names(&self) -> usize {
        self.pinned.names.lock().unwrap().len()
    }

    /// What `certs.d` holds for the host.
    pub fn raw_certs(&self) -> &RawCerts {
        &self.certs.raw
    }

    /// The scheme to use.  A secure registry is reached over HTTPS only; an
    /// insecure one is probed once, HTTPS first, and falls back to HTTP when
    /// the HTTPS connection cannot be established.
    pub async fn scheme(&self) -> ImageResult<Scheme> {
        if !self.insecure {
            return Ok(Scheme::Https);
        }
        self.scheme
            .get_or_try_init(|| async {
                let https = format!("https://{}/v2/", self.host);
                match self.client()?.get(&https).send().await {
                    Ok(_) => Ok(Scheme::Https),
                    Err(https_err) => {
                        debug!(
                            "{} does not speak HTTPS ({}), trying HTTP",
                            self.host, https_err
                        );
                        let http = format!("http://{}/v2/", self.host);
                        match self.client()?.get(&http).send().await {
                            Ok(_) => Ok(Scheme::Http),
                            Err(_) => Err(https_err.into()),
                        }
                    }
                }
            })
            .await
            .copied()
    }

    /// Take `scheme` as the one an insecure host speaks (another process
    /// found it out): the host is not probed.
    pub fn know_scheme(&self, scheme: Scheme) {
        if self.insecure && self.scheme.set(scheme).is_ok() {
            self.scheme_told
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// The scheme the probe found, once.
    fn untold_scheme(&self) -> Option<Scheme> {
        let scheme = *self.scheme.get()?;
        (!self
            .scheme_told
            .swap(true, std::sync::atomic::Ordering::Relaxed))
        .then_some(scheme)
    }

    /// `scheme://host`.
    pub async fn base_url(&self) -> ImageResult<String> {
        Ok(format!("{}://{}", self.scheme().await?.as_str(), self.host))
    }
}

/// Where a registry redirected a blob to (typically the signed URL of a
/// CDN), for the requests that follow: it saves the round trip to the
/// registry and its redirect.  Bounded, the oldest entry is replaced.  A
/// client keeps one for the credentials it has: the URL is a signed answer
/// to the caller that was asked.
#[derive(Default)]
pub struct RedirectCache {
    entries: Mutex<VecDeque<(String, String)>>,
}

impl RedirectCache {
    pub fn get(&self, key: &str) -> Option<String> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, u)| u.clone())
    }

    pub fn put(&self, key: &str, url: &str) {
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|(k, _)| k != key);
        if entries.len() >= REDIRECT_CACHE_SIZE {
            entries.pop_front();
        }
        entries.push_back((key.to_string(), url.to_string()));
    }

    pub fn drop_key(&self, key: &str) {
        self.entries.lock().unwrap().retain(|(k, _)| k != key);
    }
}

/// The transports of all the registries a process talks to.
#[derive(Default)]
pub struct Transport {
    hosts: Mutex<HashMap<String, Arc<HostTransport>>>,
}

impl Transport {
    /// The transport of the host of `endpoint` with the certificates
    /// `certs`, made on first use.
    pub fn host(&self, endpoint: &Endpoint, certs: &RawCerts) -> ImageResult<Arc<HostTransport>> {
        let (host, insecure, allow_private) =
            (&endpoint.host, endpoint.insecure, endpoint.allow_private);
        let key = format!("{host}#{}{}", insecure as u8, allow_private as u8);
        let mut hosts = self.hosts.lock().unwrap();
        if let Some(h) = hosts.get(&key) {
            return Ok(h.clone());
        }
        let certs = HostCerts::from_raw(certs.clone()).map_err(|e| {
            warn!("Cannot use the certificates of {}: {}", host, e);
            e
        })?;
        let transport = Arc::new(HostTransport::new(host, insecure, allow_private, certs));
        hosts.insert(key, transport.clone());
        Ok(transport)
    }

    /// The schemes the insecure hosts were found to speak since the last
    /// call.
    pub fn untold_schemes(&self) -> Vec<(String, Scheme)> {
        self.hosts
            .lock()
            .unwrap()
            .values()
            .filter_map(|h| Some((h.host.clone(), h.untold_scheme()?)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_ca_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("r:5000");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("ca.crt"),
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let raw = crate::target::load_certs_dir(tmp.path(), "r:5000")
            .unwrap()
            .unwrap();
        assert!(HostCerts::from_raw(raw).is_err());
    }

    #[test]
    fn test_redirect_cache_is_bounded() {
        let cache = RedirectCache::default();
        for i in 0..REDIRECT_CACHE_SIZE + 10 {
            cache.put(&format!("k{i}"), &format!("http://cdn/{i}"));
        }
        assert!(cache.get("k0").is_none());
        assert_eq!(
            cache
                .get(&format!("k{}", REDIRECT_CACHE_SIZE + 9))
                .as_deref(),
            Some(&*format!("http://cdn/{}", REDIRECT_CACHE_SIZE + 9))
        );
        cache.put("k100", "http://a");
        cache.put("k100", "http://b");
        assert_eq!(cache.get("k100").as_deref(), Some("http://b"));
        cache.drop_key("k100");
        assert!(cache.get("k100").is_none());
    }
}
