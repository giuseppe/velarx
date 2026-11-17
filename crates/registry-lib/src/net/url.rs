// SPDX-License-Identifier: Apache-2.0
//! Downloads of http(s) URLs (`ADD https://...` of a build): the bytes of
//! an untrusted server, which the daemon does not parse itself when the
//! pulls are confined.  A confined pull worker makes the request (TLS,
//! HTTP, redirections) and sends the body back in frames; the daemon only
//! counts and stores them.

use super::pool::Pool;
use std::sync::Arc;
use velarx_content::pull::net::origin::{UrlError, UrlTrailer};

/// Longest a server may wait to connect, then between two reads.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Why a GET failed.
#[derive(Debug)]
pub(super) enum GetError {
    /// The server answered 404.
    NotFound(String),
    Failed(String),
}

impl std::fmt::Display for GetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetError::NotFound(m) | GetError::Failed(m) => f.write_str(m),
        }
    }
}

impl From<String> for GetError {
    fn from(m: String) -> Self {
        GetError::Failed(m)
    }
}

/// The response to a GET of URL (http or https), checked to be a success,
/// and its Last-Modified header.
pub(super) async fn get(url: &str) -> Result<(reqwest::Response, Option<String>), GetError> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid URL `{url}`: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!("unsupported URL scheme `{}`", parsed.scheme()).into());
    }
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(parsed).send().await.map_err(|e| e.to_string())?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(GetError::NotFound(resp.status().to_string()));
    }
    if !resp.status().is_success() {
        return Err(resp.status().to_string().into());
    }
    let last_modified = resp
        .headers()
        .get(reqwest::header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 64)
        .map(String::from);
    Ok((resp, last_modified))
}

/// Where downloads are made: in confined workers started by `spawner`, one
/// for each request, which may connect only to the port of the URL (or of
/// the registry) it is for ([`Pool::for_authority`]).
#[derive(Clone)]
pub struct Fetcher {
    spawner: Arc<velarx_sys::spawner::Spawner>,
    /// The confinement of the workers (`[pull]`)
    config: Arc<velarx_config::PullConfig>,
    /// The least a download must bring (`[pull] min_speed_kib`)
    min_speed: velarx_registry::speed::Speed,
}

impl Fetcher {
    /// `spawner`: what starts the pull workers; they have the
    /// confinement of `config`, as those of a pull (`require_userns`, the
    /// cgroup and its limits, `require_cgroup`).
    pub fn new(
        spawner: Arc<velarx_sys::spawner::Spawner>,
        config: &velarx_config::PullConfig,
    ) -> Self {
        Self {
            spawner,
            config: Arc::new(config.clone()),
            min_speed: Default::default(),
        }
    }

    /// The pool of the one worker of a request to `authority`.
    fn pool(&self, authority: &str, default_ports: &[u16]) -> Arc<Pool> {
        let pool = Pool::for_authority(self.spawner.clone(), authority, default_ports);
        pool.confine(&self.config);
        pool
    }

    /// Fail the downloads that bring less than `speed` (the default is
    /// that of `[pull] min_speed_kib`).
    pub fn with_min_speed(mut self, speed: velarx_registry::speed::Speed) -> Self {
        self.min_speed = speed;
        self
    }

    /// Whether the registry HOST accepts the credentials of ACCESS
    /// (`login`; the certificate is not checked without `tls_verify`); Err:
    /// why not (`Unauthorized`: it refused them), as podman says it.
    pub async fn login(
        &self,
        host: &str,
        access: &velarx_registry::auth::RegistryAccess,
        tls_verify: bool,
    ) -> velarx_types::ImageResult<()> {
        let certs_dirs = velarx_registry::target::default_certs_dirs()?;
        let access = super::login::with_certificates(host, access, tls_verify, certs_dirs)?;
        // (https, and http for a registry whose certificate is not checked)
        self.pool(host, &[443, 80])
            .login(host, &access, tls_verify)
            .await
    }

    /// The body of URL, given to SINK as it comes, at most LIMIT bytes.
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

    /// `fetch`, None when the server answers 404 (the signatures of
    /// lookaside storage end there).
    pub async fn fetch_opt(
        &self,
        url: &str,
        limit: u64,
        sink: &mut (dyn FnMut(&[u8]) -> std::io::Result<()> + Send),
    ) -> Result<Option<UrlTrailer>, UrlError> {
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| UrlError::Failed(format!("invalid URL `{url}`: {e}")))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(format!("unsupported URL scheme `{}`", parsed.scheme()).into());
        }
        let port = parsed.port_or_known_default().unwrap_or(443);
        // (the worker of this URL connects to its port; a redirection to
        // another port is refused)
        self.pool(
            &format!("{}:{port}", parsed.host_str().unwrap_or_default()),
            &[],
        )
        .url_opt(url, limit, self.min_speed, sink)
        .await
    }
}
