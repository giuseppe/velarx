// SPDX-License-Identifier: Apache-2.0
//! Registry credentials: auth files (the format of containers/image's and
//! Docker's), and credential helpers.
//!
//! The files are looked up in order and the first that has an answer for a
//! registry wins: `$REGISTRY_AUTH_FILE`,
//! `$XDG_RUNTIME_DIR/velarx/auth/auth.json` (`/run/velarx/auth/auth.json`
//! for root of the host), `$XDG_CONFIG_HOME/velarx/auth/auth.json` (or
//! `~/.config/...`) and
//! `$DOCKER_CONFIG/config.json` (or `~/.docker/config.json`).  In a file,
//! a `credHelpers` entry for the registry wins, then the `auths` entry with
//! the longest key that is the registry or a namespace or repository of it
//! (`quay.io/org` applies to `quay.io/org/img`), then `credsStore`.  A file
//! that cannot be read or parsed is an error, never skipped.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tracing::debug;

/// Largest auth file read.
const MAX_AUTH_FILE: u64 = 16 << 20;

/// What a credential helper may do: how long it runs and how much it
/// answers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HelperLimits {
    pub timeout: Duration,
    pub max_output: u64,
}

impl Default for HelperLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            max_output: 1 << 20,
        }
    }
}

/// How long a helper that was killed for its timeout is waited for.
const KILL_GRACE: Duration = Duration::from_secs(5);
/// How long the answer of a helper is kept when it names no expiry.
const ANSWER_TTL: Duration = Duration::from_secs(5);

/// How much earlier than its expiry an answer is asked for again.
const ANSWER_MARGIN: u64 = 10;

/// The longest an answer is kept, whatever its expiry says: a `logout` or a
/// new login is seen at the latest this late (and a far expiry, or a clock
/// that is off, keeps nothing longer).
const ANSWER_MAX_TTL: Duration = Duration::from_secs(300);

/// What a helper answered: the credentials (none when it has none) and, if
/// it said when they expire (`ExpiresAt`), for how many seconds more.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HelperAnswer {
    pub credentials: Option<Credentials>,
    pub valid_secs: Option<u64>,
}

/// An answer of a helper and the time it came: none for a helper with no
/// credentials for the server.
type KeptAnswer = (Instant, Option<Credentials>);

/// The answers of the helpers of a process, in memory only: one lookup of
/// a registry calls the helper once for the many requests of a pull.  An
/// answer is kept until its own expiry (a few seconds when it has none).
#[derive(Default)]
pub(crate) struct HelperAnswers {
    kept: std::sync::Mutex<std::collections::HashMap<(String, String), KeptAnswer>>,
}

impl std::fmt::Debug for HelperAnswers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HelperAnswers")
    }
}

impl HelperAnswers {
    /// The answer of `helper` for `server`: the one kept, else what `ask`
    /// gives (a failure is not kept).
    fn get(
        &self,
        helper: &str,
        server: &str,
        ask: impl FnOnce() -> Result<HelperAnswer, String>,
    ) -> Result<Option<Credentials>, String> {
        let key = (helper.to_string(), server.to_string());
        let now = Instant::now();
        {
            let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
            match kept.get(&key) {
                Some((until, c)) if *until > now => return Ok(c.clone()),
                Some(_) => {
                    kept.remove(&key);
                }
                None => {}
            }
        }
        let answer = ask()?;
        let ttl = match answer.valid_secs {
            Some(secs) => {
                Duration::from_secs(secs.saturating_sub(ANSWER_MARGIN)).min(ANSWER_MAX_TTL)
            }
            None => ANSWER_TTL,
        };
        if !ttl.is_zero() {
            let now = Instant::now();
            let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
            kept.retain(|_, (until, _)| *until > now);
            kept.insert(key, (now + ttl, answer.credentials.clone()));
        }
        Ok(answer.credentials)
    }
}

/// What authenticates to a registry.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    /// An OAuth2 refresh token, exchanged for a bearer token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_token: Option<String>,
    /// A bearer token sent as it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_token: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hide = |s: Option<&str>| s.map(|_| "<redacted>");
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field(
                "password",
                &hide(Some(&*self.password).filter(|p| !p.is_empty())),
            )
            .field("identity_token", &hide(self.identity_token.as_deref()))
            .field("registry_token", &hide(self.registry_token.as_deref()))
            .finish()
    }
}

impl Credentials {
    pub fn basic(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
            ..Default::default()
        }
    }

    /// Whether there is a user name and a password to send.
    pub fn has_basic(&self) -> bool {
        !self.username.is_empty() || !self.password.is_empty()
    }

    /// `USER:PASSWORD` of `--creds` (the password may be empty).
    pub fn parse_creds(creds: &str) -> Result<Self, String> {
        match creds.split_once(':') {
            Some((user, pass)) if !user.is_empty() => Ok(Self::basic(user, pass)),
            _ => Err("credentials must be USERNAME[:PASSWORD]".into()),
        }
    }
}

/// An entry of `auths`.
#[derive(Default, Deserialize)]
struct Entry {
    auth: Option<String>,
    username: Option<String>,
    password: Option<String>,
    identitytoken: Option<String>,
    registrytoken: Option<String>,
}

impl Entry {
    fn credentials(&self) -> Result<Option<Credentials>, String> {
        let mut c = Credentials::default();
        match self.auth.as_deref().filter(|a| !a.is_empty()) {
            Some(auth) => {
                let decoded = BASE64
                    .decode(auth.trim())
                    .ok()
                    .and_then(|d| String::from_utf8(d).ok())
                    .ok_or("invalid `auth` field")?;
                let (user, pass) = decoded
                    .split_once(':')
                    .ok_or("invalid `auth` field: missing `:`")?;
                c.username = user.to_string();
                c.password = pass.to_string();
            }
            None => {
                if let Some(user) = self.username.as_deref().filter(|u| !u.is_empty()) {
                    c.username = user.to_string();
                    c.password = self.password.clone().unwrap_or_default();
                }
            }
        }
        c.identity_token = self.identitytoken.clone().filter(|t| !t.is_empty());
        c.registry_token = self.registrytoken.clone().filter(|t| !t.is_empty());
        if c.username.is_empty() && c.identity_token.is_none() && c.registry_token.is_none() {
            return Ok(None);
        }
        Ok(Some(c))
    }
}

/// An auth file as it is read.
#[derive(Debug, Default, Deserialize)]
struct FileContent {
    #[serde(default)]
    auths: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(rename = "credsStore")]
    creds_store: Option<String>,
    #[serde(rename = "credHelpers", default)]
    cred_helpers: std::collections::BTreeMap<String, String>,
}

/// A parsed auth file: keys normalized.
#[derive(Debug, Clone, Default)]
struct AuthFile {
    path: PathBuf,
    auths: Vec<(String, Credentials)>,
    /// (normalized registry, key as written, helper)
    helpers: Vec<(String, String, String)>,
    store: Option<String>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hide = |s: &Option<String>| s.as_ref().map(|_| "<redacted>");
        f.debug_struct("Entry")
            .field("auth", &hide(&self.auth))
            .field("username", &self.username)
            .field("password", &hide(&self.password))
            .field("identitytoken", &hide(&self.identitytoken))
            .field("registrytoken", &hide(&self.registrytoken))
            .finish()
    }
}

/// The credentials of a process: auth files, and credentials given on the
/// command line or by an API client, which come first.
#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    /// Credentials for every registry (`--creds`).
    any: Option<Credentials>,
    explicit: Vec<(String, Credentials)>,
    files: Vec<AuthFile>,
    /// Why the files could not be loaded: every lookup fails with it.
    error: Option<String>,
    /// Where the credential helpers run when this process cannot run them
    /// (the confined fetcher).
    runner: Option<std::sync::Arc<super::helper::HelperRunner>>,
    /// The answers of the helpers, shared by the clones.
    answers: std::sync::Arc<HelperAnswers>,
}

/// "index.docker.io", "registry-1.docker.io" -> "docker.io".
fn normalize_registry(r: &str) -> &str {
    match r {
        "index.docker.io" | "registry-1.docker.io" => "docker.io",
        r => r,
    }
}

/// A key of `auths`: no scheme and no trailing slash; a key with a scheme
/// is in the legacy Docker form and its path is dropped
/// (`https://index.docker.io/v1/` is `docker.io`).
pub fn normalize_auth_key(key: &str) -> String {
    // (a key of another scheme, `s3://bucket`, is the key of a destination
    // of a push transport: no registry name, its scheme and authority in
    // lower case as `ImageLocation::credential_key` gives them, the rest as
    // written)
    if let Some((scheme, rest)) = key.split_once("://") {
        if !matches!(scheme, "https" | "http") {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            let (authority, tail) = rest.split_at(end);
            return format!(
                "{}://{}{tail}",
                scheme.to_ascii_lowercase(),
                authority.to_ascii_lowercase()
            )
            .trim_end_matches('/')
            .to_string();
        }
    }
    let (rest, had_scheme) = match key
        .strip_prefix("https://")
        .or_else(|| key.strip_prefix("http://"))
    {
        Some(r) => (r, true),
        None => (key, false),
    };
    let rest = rest.trim_end_matches('/');
    let rest = if had_scheme {
        rest.split('/').next().unwrap_or(rest)
    } else {
        rest
    };
    match rest.split_once('/') {
        Some((host, path)) => format!("{}/{path}", normalize_registry(host)),
        None => normalize_registry(rest).to_string(),
    }
}

/// The value of an environment variable, if set and not empty.
fn env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// velarx's auth file under a directory of its own (the runtime or the
/// configuration directory): in a directory that holds nothing else, the
/// one the confined fetcher may read (not the state of the
/// containers, config.toml or the API's token next to it).
pub const OWN_AUTH_FILE: &str = "velarx/auth/auth.json";

/// The auth file of the runtime directory: `/run/velarx/auth/auth.json`
/// for root of the host (the `$XDG_RUNTIME_DIR` `sudo` may leave is the
/// user's), else `$XDG_RUNTIME_DIR/velarx/auth/auth.json`.  It is the
/// login of the user, not state of an engine: as podman's login file of the
/// runtime directory, it does not follow `--runroot`, so that a `login` is found by every command and engine of that user,
/// whatever run root they are given.
fn runtime_auth_file() -> Result<Option<PathBuf>, velarx_base::ids::IdsError> {
    if velarx_base::ids::rootful()? {
        return Ok(Some(Path::new("/run").join(OWN_AUTH_FILE)));
    }
    Ok(env("XDG_RUNTIME_DIR").map(|d| d.join(OWN_AUTH_FILE)))
}

/// The auth files looked up, in order.
pub fn default_auth_files() -> Result<Vec<PathBuf>, velarx_base::ids::IdsError> {
    let home = env("HOME");
    let mut files = Vec::new();
    files.extend(env("REGISTRY_AUTH_FILE"));
    files.extend(runtime_auth_file()?);
    match env("XDG_CONFIG_HOME") {
        Some(x) => files.push(x.join(OWN_AUTH_FILE)),
        None => files.extend(home.as_ref().map(|h| h.join(".config").join(OWN_AUTH_FILE))),
    }
    match env("DOCKER_CONFIG") {
        Some(d) => files.push(d.join("config.json")),
        None => files.extend(home.map(|h| h.join(".docker/config.json"))),
    }
    Ok(files)
}

/// The file `login` writes: `$REGISTRY_AUTH_FILE`, else the one of the
/// runtime directory (`/run/velarx/auth/auth.json` for root of the host:
/// never a file in the home of the user `sudo` came from), else the user's
/// configuration.
pub fn default_auth_file() -> Result<PathBuf, String> {
    let explicit = env("REGISTRY_AUTH_FILE");
    let first = match explicit {
        Some(file) => Some(file),
        None => runtime_auth_file().map_err(|e| e.to_string())?,
    };
    first
        .or_else(|| env("XDG_CONFIG_HOME").map(|d| d.join(OWN_AUTH_FILE)))
        .or_else(|| env("HOME").map(|h| h.join(".config").join(OWN_AUTH_FILE)))
        .ok_or_else(|| "cannot determine the auth file location".to_string())
}

fn read_file(path: &Path, must_exist: bool) -> Result<Option<String>, String> {
    match super::read_config_file(path, MAX_AUTH_FILE) {
        Ok(c) => Ok(Some(c)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !must_exist => Ok(None),
        Err(e) => Err(format!(
            "cannot read the auth file `{}`: {e}",
            path.display()
        )),
    }
}

impl AuthFile {
    fn parse(path: &Path, content: &str) -> Result<Self, String> {
        let bad = |e: String| format!("invalid auth file `{}`: {e}", path.display());
        let raw: FileContent = if content.trim().is_empty() {
            FileContent::default()
        } else {
            serde_json::from_str(content).map_err(|e| bad(e.to_string()))?
        };
        let mut file = AuthFile {
            path: path.to_path_buf(),
            store: raw.creds_store.filter(|s| !s.is_empty()),
            ..Default::default()
        };
        for (key, value) in raw.auths {
            let entry: Entry =
                serde_json::from_value(value).map_err(|e| bad(format!("entry `{key}`: {e}")))?;
            if let Some(c) = entry
                .credentials()
                .map_err(|e| bad(format!("entry `{key}`: {e}")))?
            {
                file.auths.push((normalize_auth_key(&key), c));
            }
        }
        for (key, helper) in raw.cred_helpers {
            file.helpers.push((normalize_auth_key(&key), key, helper));
        }
        Ok(file)
    }

    /// The helper that holds the credentials of `registry` (normalized)
    /// and the server name it is asked for: the `credHelpers` entry for it,
    /// else `credsStore`.
    pub(crate) fn helper_for(&self, registry: &str) -> Option<(String, String)> {
        if let Some((_, key, helper)) = self.helpers.iter().find(|(r, _, _)| r == registry) {
            return Some((helper.clone(), key.clone()));
        }
        self.store.as_deref().map(|store| {
            let server = if registry == "docker.io" {
                "https://index.docker.io/v1/"
            } else {
                registry
            };
            (store.to_string(), server.to_string())
        })
    }

    /// The answer of this file for `registry` (normalized) and
    /// `repository`: `None` when it has none and the next file is asked.
    fn lookup(
        &self,
        registry: &str,
        repository: &str,
        runner: Option<&super::helper::HelperRunner>,
        answers: &HelperAnswers,
    ) -> Result<Option<Option<Credentials>>, String> {
        let ask = |(name, server): (String, String)| {
            answers.get(&name, &server, || match runner {
                Some(r) => r.get(&self.path, registry),
                None => run_credential_helper(&name, &server),
            })
        };
        if self.helpers.iter().any(|(r, _, _)| r == registry) {
            if let Some(h) = self.helper_for(registry) {
                return ask(h).map(Some);
            }
        }
        if let Some(c) = best_match(&self.auths, registry, repository) {
            return Ok(Some(Some(c.clone())));
        }
        if self.store.is_some() {
            if let Some(h) = self.helper_for(registry) {
                if let Some(c) = ask(h)? {
                    return Ok(Some(Some(c)));
                }
            }
        }
        Ok(None)
    }
}

/// The credentials a helper gives for `registry`, the helper being the one
/// the auth file `path` names for it: what the helper runner does for a
/// process that cannot run helpers.  The helper is never taken from the
/// asker.
pub(crate) fn helper_credentials(
    path: &Path,
    registry: &str,
    limits: HelperLimits,
) -> Result<HelperAnswer, String> {
    let content = read_file(path, true)?.unwrap_or_default();
    let file = AuthFile::parse(path, &content)?;
    let registry = normalize_registry(registry);
    let (name, server) = file.helper_for(registry).ok_or_else(|| {
        format!(
            "no credential helper is configured for `{registry}` in `{}`",
            path.display()
        )
    })?;
    run_credential_helper_in(&name, &server, None, limits)
}

/// The credentials of the longest key that is `registry` or a namespace or
/// repository of `registry/repository`.
fn best_match<'a>(
    entries: &'a [(String, Credentials)],
    registry: &str,
    repository: &str,
) -> Option<&'a Credentials> {
    let full = if repository.is_empty() {
        registry.to_string()
    } else {
        format!("{registry}/{repository}")
    };
    entries
        .iter()
        .filter(|(k, _)| {
            full.strip_prefix(k.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
                && (k == registry || k.starts_with(&format!("{registry}/")))
        })
        .max_by_key(|(k, _)| k.len())
        .map(|(_, c)| c)
}

/// What the auth files of the user are now (the inode, the time of the last
/// change and the size of each, none for a file that is not there): a
/// `login` or a `logout` changes it, for a process that lives longer than a
/// command to read the files again.
pub type AuthFilesStamp = Vec<Option<(u64, i64, i64, u64)>>;

/// [`AuthFilesStamp`] of `files` (those [`AuthConfig::load`] reads:
/// [`default_auth_files`], which a process asks once, they are its for its
/// whole life).
pub fn auth_files_stamp(files: &[PathBuf]) -> AuthFilesStamp {
    use std::os::unix::fs::MetadataExt;
    files
        .iter()
        .map(|f| {
            std::fs::metadata(f)
                .ok()
                .map(|m| (m.ino(), m.mtime(), m.mtime_nsec(), m.len()))
        })
        .collect()
}

impl AuthConfig {
    /// The auth files of the user (see the module documentation).  A file
    /// that cannot be read or parsed makes every lookup fail.
    pub fn load() -> Result<Self, velarx_base::ids::IdsError> {
        Ok(Self::load_paths(&default_auth_files()?, false))
    }

    /// The auth files `files` ([`default_auth_files`]) read again, with the
    /// helper runner of this one; why not when they cannot be read now.
    pub fn reloaded(&self, files: &[PathBuf]) -> Result<Self, String> {
        let mut config = Self::load_paths(files, false);
        if let Some(e) = config.error.take() {
            return Err(e);
        }
        config.runner = self.runner.clone();
        Ok(config)
    }

    /// Only the file `path` (`--authfile`), which must exist.
    pub fn load_file(path: &Path) -> Self {
        Self::load_paths(&[path.to_path_buf()], true)
    }

    fn load_paths(paths: &[PathBuf], must_exist: bool) -> Self {
        let mut config = Self::default();
        for path in paths {
            let parsed = read_file(path, must_exist)
                .and_then(|c| c.map(|c| AuthFile::parse(path, &c)).transpose());
            match parsed {
                Ok(Some(file)) => {
                    debug!("Using the auth file {:?}", path);
                    config.files.push(file);
                }
                Ok(None) => {}
                Err(e) => {
                    config.error = Some(e);
                    break;
                }
            }
        }
        config
    }

    /// A configuration with these credentials and nothing else: no helpers,
    /// no file.  The keys are registries or `registry/namespace` prefixes.
    pub fn from_credentials<'a>(
        credentials: impl IntoIterator<Item = (&'a str, Credentials)>,
    ) -> Self {
        let mut config = Self::default();
        for (key, c) in credentials {
            config = config.with_credentials(key, c);
        }
        config
    }

    /// These credentials for `key` (a registry or a `registry/namespace`
    /// prefix) before anything of the files.
    pub fn with_credentials(mut self, key: &str, c: Credentials) -> Self {
        let key = normalize_auth_key(key);
        self.explicit.retain(|(k, _)| *k != key);
        self.explicit.push((key, c));
        self
    }

    /// The credentials for `repository` of `registry`, if any.
    pub fn lookup(&self, registry: &str, repository: &str) -> Result<Option<Credentials>, String> {
        let registry = normalize_registry(registry);
        if let Some(c) = &self.any {
            return Ok(Some(c.clone()));
        }
        if let Some(c) = best_match(&self.explicit, registry, repository) {
            return Ok(Some(c.clone()));
        }
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        for file in &self.files {
            if let Some(answer) = file
                .lookup(registry, repository, self.runner.as_deref(), &self.answers)
                .map_err(|e| format!("auth file `{}`: {e}", file.path.display()))?
            {
                return Ok(answer);
            }
        }
        Ok(None)
    }
}

impl AuthConfig {
    /// Whether a lookup may run a credential helper.
    #[cfg(feature = "net")]
    pub(crate) fn runs_helpers(&self) -> bool {
        self.files
            .iter()
            .any(|f| f.store.is_some() || !f.helpers.is_empty())
    }

    /// Run the credential helpers in `runner` instead of this process.
    pub fn with_helper_runner(
        mut self,
        runner: std::sync::Arc<super::helper::HelperRunner>,
    ) -> Self {
        self.runner = Some(runner);
        self
    }

    /// This configuration with what a request brought first.
    pub fn with_access(&self, access: &RegistryAccess) -> Self {
        let mut c = self.clone();
        for (key, creds) in &access.auths {
            c = c.with_credentials(key, creds.clone());
        }
        if access.creds.is_some() {
            c.any = access.creds.clone();
        }
        c
    }

    /// The credentials of the `auths` of the files, by key (no helper is
    /// run): what a client sends to the daemon for `--authfile` when it
    /// does not know where the request goes.
    pub fn export(&self) -> Result<std::collections::BTreeMap<String, Credentials>, String> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        let mut out = std::collections::BTreeMap::new();
        for f in self.files.iter().rev() {
            for (k, c) in &f.auths {
                out.insert(k.clone(), c.clone());
            }
        }
        Ok(out)
    }
}

impl AuthConfig {
    /// The credentials the files have under exactly `key` (no prefix, no
    /// short name; the key of a destination of an external scheme,
    /// `SCHEME://AUTHORITY`): the one entry, if there is one.  What a client
    /// sends to the engine for `--authfile` of such a destination, and what
    /// the engine looks up for the pusher of that scheme.
    pub fn export_exact(
        &self,
        key: &str,
    ) -> Result<std::collections::BTreeMap<String, Credentials>, String> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        let key = normalize_auth_key(key);
        let mut out = std::collections::BTreeMap::new();
        if let Some(c) = self.lookup(&key, "")? {
            out.insert(key, c);
        }
        Ok(out)
    }

    /// The credentials for each of `scopes` (`registry/repository`), the
    /// full lookup of each (helpers included) and nothing else of the
    /// files: what `image complete --authfile` sends for the layers that
    /// need credentials.
    pub fn export_for(
        &self,
        scopes: &[String],
    ) -> Result<std::collections::BTreeMap<String, Credentials>, String> {
        // (a file that cannot be read is an error even when no scope
        // asks for it, as with `export`)
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        let mut out = std::collections::BTreeMap::new();
        for scope in scopes {
            let (registry, repository) = scope.split_once('/').unwrap_or((scope, ""));
            if let Some(c) = self.lookup(registry, repository)? {
                out.insert(normalize_auth_key(scope), c);
            }
        }
        Ok(out)
    }
}

/// What a client brings to reach the registries of one request: its
/// credentials (`--creds`, `--authfile`, `X-Registry-Auth`) and its
/// certificates (`--cert-dir`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryAccess {
    /// For every registry the request reaches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creds: Option<Credentials>,
    /// By registry or `registry/namespace`.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub auths: std::collections::BTreeMap<String, Credentials>,
    /// CA certificates and a client certificate for every registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certs: Option<super::certs::RawCerts>,
}

impl RegistryAccess {
    /// The credentials as what a call to the engine carries: the position of
    /// a sealed memory file with their JSON (the only descriptor) and the
    /// descriptor; none without credentials.
    pub fn sealed(&self) -> std::io::Result<(Option<u32>, Vec<std::os::fd::OwnedFd>)> {
        if self.is_empty() {
            return Ok((None, Vec::new()));
        }
        let bytes =
            zeroize::Zeroizing::new(serde_json::to_vec(self).map_err(std::io::Error::other)?);
        Ok((Some(0), vec![velarx_base::sealed::sealed_memory(&bytes)?]))
    }

    pub fn is_empty(&self) -> bool {
        self.creds.is_none() && self.auths.is_empty() && self.certs.is_none()
    }

    /// The `X-Registry-Auth` header of the Docker and podman APIs: the
    /// base64 (URL or standard alphabet) of the JSON of one credential
    /// (`username`, `password`, `auth`, `identitytoken`, `registrytoken`,
    /// with `serveraddress` it is for that registry only) or of a map
    /// from registries to credentials.
    pub fn from_registry_auth(header: &str) -> Result<Self, String> {
        let header = header.trim();
        let mut access = Self::default();
        if header.is_empty() {
            return Ok(access);
        }
        use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
        let raw = URL_SAFE
            .decode(header)
            .or_else(|_| URL_SAFE_NO_PAD.decode(header))
            .or_else(|_| BASE64.decode(header))
            .or_else(|_| STANDARD.decode(header.trim_end_matches('=')))
            .map_err(|_| "invalid X-Registry-Auth header".to_string())?;
        let v: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|_| "invalid X-Registry-Auth header".to_string())?;
        let obj = v.as_object().ok_or("invalid X-Registry-Auth header")?;
        let entry_keys = [
            "username",
            "password",
            "auth",
            "identitytoken",
            "registrytoken",
            "serveraddress",
            "email",
        ];
        let one = |o: &serde_json::Value| -> Result<Option<Credentials>, String> {
            let e: Entry = serde_json::from_value(o.clone())
                .map_err(|_| "invalid credentials in X-Registry-Auth".to_string())?;
            e.credentials()
        };
        if obj.keys().all(|k| entry_keys.contains(&k.as_str())) {
            let server = obj
                .get("serveraddress")
                .and_then(|s| s.as_str())
                .filter(|s| !s.is_empty());
            if let Some(c) = one(&v)? {
                match server {
                    Some(s) => {
                        access.auths.insert(normalize_auth_key(s), c);
                    }
                    None => access.creds = Some(c),
                }
            }
            return Ok(access);
        }
        for (k, e) in obj {
            if let Some(c) = one(e)? {
                access.auths.insert(normalize_auth_key(k), c);
            }
        }
        Ok(access)
    }
}

/// Write `root` to `path` atomically, readable by the owner only.
fn write_auth_file(path: &Path, root: &serde_json::Value) -> Result<(), String> {
    let err = |e: std::io::Error| format!("cannot write `{}`: {e}", path.display());
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(err)?;
    let data = serde_json::to_vec_pretty(root).map_err(|e| e.to_string())?;
    // created 0600 from the start, never readable by others
    let mut tmp = tempfile::Builder::new()
        .prefix(".auth.json")
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .tempfile_in(dir)
        .map_err(err)?;
    tmp.write_all(&data).map_err(err)?;
    tmp.as_file().sync_all().map_err(err)?;
    tmp.persist(path).map_err(|e| err(e.error))?;
    Ok(())
}

use std::os::unix::fs::DirBuilderExt;

/// The JSON of the auth file at `path` (an empty object if it does not
/// exist) and its `auths` object.
fn read_root(path: &Path) -> Result<serde_json::Value, String> {
    let root = match read_file(path, false)? {
        Some(c) if !c.trim().is_empty() => serde_json::from_str(&c)
            .map_err(|e| format!("invalid auth file `{}`: {e}", path.display()))?,
        _ => serde_json::json!({}),
    };
    if !root.is_object() || root.get("auths").is_some_and(|a| !a.is_object()) {
        return Err(format!("invalid auth file `{}`", path.display()));
    }
    Ok(root)
}

/// Remove the keys of `auths` that normalize to `key`; how many.
fn remove_keys(root: &mut serde_json::Value, key: &str) -> usize {
    let Some(auths) = root.get_mut("auths").and_then(|a| a.as_object_mut()) else {
        return 0;
    };
    let gone: Vec<String> = auths
        .keys()
        .filter(|k| normalize_auth_key(k) == key)
        .cloned()
        .collect();
    for k in &gone {
        auths.remove(k);
    }
    gone.len()
}

/// Store the credentials for `registry` (or a `registry/namespace`) in the
/// auth file `path` (by default [`default_auth_file`]); returns the file.
pub fn store_credentials(
    path: Option<&Path>,
    registry: &str,
    username: &str,
    password: &str,
) -> Result<PathBuf, String> {
    if registry.is_empty() {
        return Err("invalid empty registry".into());
    }
    if username.contains(':') {
        return Err("the user name cannot contain `:`".into());
    }
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => default_auth_file()?,
    };
    let mut root = read_root(&path)?;
    let key = normalize_auth_key(registry);
    remove_keys(&mut root, &key);
    let auths = root
        .as_object_mut()
        .ok_or("invalid auth file")?
        .entry("auths")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(auths) = auths.as_object_mut() {
        auths.insert(
            key,
            serde_json::json!({ "auth": BASE64.encode(format!("{username}:{password}")) }),
        );
    }
    write_auth_file(&path, &root)?;
    Ok(path)
}

/// Remove the credentials for `registry` from the auth file `path`.
pub fn remove_credentials(path: Option<&Path>, registry: &str) -> Result<(), String> {
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => default_auth_file()?,
    };
    let mut root = read_root(&path)?;
    if remove_keys(&mut root, &normalize_auth_key(registry)) == 0 {
        return Err(format!("not logged into {registry}"));
    }
    write_auth_file(&path, &root)
}

/// Remove every credential of the auth file `path`.
pub fn remove_all_credentials(path: Option<&Path>) -> Result<(), String> {
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => default_auth_file()?,
    };
    let mut root = read_root(&path)?;
    if let Some(o) = root.as_object_mut() {
        o.insert("auths".into(), serde_json::json!({}));
    }
    write_auth_file(&path, &root)
}

/// A helper is named `docker-credential-NAME` and found in `$PATH`: the
/// name cannot make it a path.
pub(crate) fn valid_helper_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// The search path of the credential helpers of root, wherever they run
/// (`sudo` may keep the `PATH` of the user).
pub const ROOT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin";

/// The executable `program` in the absolute entries of `search`: an empty
/// or relative entry would look in the current directory.
fn find_helper(program: &str, search: &std::ffi::OsStr) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::env::split_paths(search)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(program))
        .find(|p| {
            std::fs::metadata(p)
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

/// Run `docker-credential-NAME get` with `server` on its input: the
/// credentials, `None` if it has none.  It runs at most the time of
/// [`HelperLimits`], its answer is capped and its errors discarded.
fn run_credential_helper(name: &str, server: &str) -> Result<HelperAnswer, String> {
    run_credential_helper_in(name, server, None, HelperLimits::default())
}

/// Whether `fd` is readable (or hung up) before `deadline`.
fn wait_ready(fd: impl std::os::fd::AsFd, deadline: Instant) -> bool {
    use rustix::event::{poll, PollFd, PollFlags};
    let mut fds = [PollFd::new(&fd, PollFlags::IN)];
    loop {
        // (what is left of the time, again after a signal)
        let left = deadline.saturating_duration_since(Instant::now());
        let timeout = rustix::event::Timespec {
            tv_sec: i64::try_from(left.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(left.subsec_nanos()),
        };
        match poll(&mut fds, Some(&timeout)) {
            Err(rustix::io::Errno::INTR) => continue,
            Ok(n) => return n > 0,
            Err(_) => return false,
        }
    }
}

/// Read `from` to its end into `out`, or until `limit` bytes are there:
/// false when `deadline` came first.
fn read_until_end(
    from: &mut std::process::ChildStdout,
    out: &mut Vec<u8>,
    limit: u64,
    deadline: Instant,
) -> std::io::Result<bool> {
    while (out.len() as u64) < limit {
        if !wait_ready(&*from, deadline) {
            return Ok(false);
        }
        // (read into `out` itself: the answer holds a secret, no other
        // buffer gets a copy of it)
        let have = out.len();
        let want = 8192.min((limit - have as u64) as usize);
        out.resize(have + want, 0);
        let read = from.read(&mut out[have..]);
        out.truncate(have + *read.as_ref().unwrap_or(&0));
        match read {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// [`run_credential_helper`], the helper looked for in `dir` instead of
/// `$PATH` when given, and `limits` instead of the usual ones (a test does not change the environment of the
/// process, which its other tests share).
fn run_credential_helper_in(
    name: &str,
    server: &str,
    dir: Option<&std::path::Path>,
    limits: HelperLimits,
) -> Result<HelperAnswer, String> {
    let none = HelperAnswer {
        credentials: None,
        valid_secs: None,
    };
    if !valid_helper_name(name) {
        return Err(format!("invalid credential helper name `{name}`"));
    }
    let program = format!("docker-credential-{name}");
    let path = match dir {
        Some(d) => d.join(&program),
        None => {
            let search = if velarx_base::ids::rootful().map_err(|e| e.to_string())? {
                Some(std::ffi::OsString::from(ROOT_PATH))
            } else {
                std::env::var_os("PATH")
            };
            find_helper(&program, search.as_deref().unwrap_or_default())
                .ok_or_else(|| format!("cannot run `{program}`: not found in the search path"))?
        }
    };
    // (written whole before the answer is read: no longer than what a pipe
    // takes at once, so a helper that does not read it cannot block this)
    if server.len() > libc::PIPE_BUF {
        return Err(format!(
            "cannot run `{program}`: the server name is too long"
        ));
    }
    let mut child = Command::new(&path)
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run `{program}`: {e}"))?;
    let pidfd = rustix::process::pidfd_open(
        rustix::process::Pid::from_child(&child),
        rustix::process::PidfdFlags::empty(),
    )
    .map_err(|e| format!("cannot watch `{program}`: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        // a helper that does not read its input fails below
        let _ = stdin.write_all(server.as_bytes());
    }
    // (no thread reads for the caller: a caller that forks next has to be
    // single-threaded, and a thread that was joined is still counted by the
    // kernel for a moment)
    let deadline = Instant::now() + limits.timeout;
    let mut out = Vec::new();
    let read = match child.stdout.take() {
        Some(mut stdout) => read_until_end(&mut stdout, &mut out, limits.max_output + 1, deadline),
        None => Ok(true),
    };
    // (a helper that writes too much, or does not end, is killed by the
    // timeout)
    if matches!(read, Ok(false)) || !wait_ready(&pidfd, deadline) {
        let _ = rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL);
        if wait_ready(&pidfd, Instant::now() + KILL_GRACE) {
            let _ = child.wait();
        }
        return Err(format!("`{program}` timed out"));
    }
    let status = child.wait();
    let read = read.map(|_| ());
    read.map_err(|e| format!("cannot read the answer of `{program}`: {e}"))?;
    let status = status.map_err(|e| format!("`{program}`: {e}"))?;
    if out.len() as u64 > limits.max_output {
        return Err(format!("the answer of `{program}` is too big"));
    }
    let not_found = String::from_utf8_lossy(&out).contains("credentials not found");
    if !status.success() {
        if not_found {
            return Ok(none);
        }
        return Err(format!("`{program}` failed: {status}"));
    }
    if out.is_empty() || not_found {
        return Ok(none);
    }
    #[derive(Deserialize)]
    struct Answer {
        #[serde(rename = "Username", default)]
        username: String,
        #[serde(rename = "Secret", default)]
        secret: String,
        #[serde(rename = "ExpiresAt", default)]
        expires_at: Option<String>,
    }
    let answer: Answer =
        serde_json::from_slice(&out).map_err(|_| format!("invalid answer from `{program}`"))?;
    if answer.secret.is_empty() {
        return Ok(none);
    }
    // (an expiry that is not RFC 3339 is none)
    let valid_secs = answer
        .expires_at
        .as_deref()
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| {
            u64::try_from((t.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds())
                .unwrap_or(0)
        });
    Ok(HelperAnswer {
        credentials: Some(if answer.username == "<token>" {
            Credentials {
                identity_token: Some(answer.secret),
                ..Default::default()
            }
        } else {
            Credentials::basic(&answer.username, &answer.secret)
        }),
        valid_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_is_kept_at_most_answer_max_ttl() {
        let answers = HelperAnswers::default();
        let far = || {
            Ok(HelperAnswer {
                credentials: Some(Credentials::basic("u", "p")),
                valid_secs: Some(10 * 365 * 24 * 3600),
            })
        };
        answers.get("h", "s", far).unwrap();
        let kept = answers.kept.lock().unwrap();
        let (until, _) = kept.get(&("h".into(), "s".into())).unwrap();
        assert!(*until <= Instant::now() + ANSWER_MAX_TTL);
        drop(kept);
        // a failure is not kept: the next lookup asks again
        assert!(answers.get("h", "t", || Err("no".into())).is_err());
        let mut asked = false;
        answers
            .get("h", "t", || {
                asked = true;
                far()
            })
            .unwrap();
        assert!(asked);
    }

    fn file(json: &str) -> AuthConfig {
        AuthConfig {
            files: vec![AuthFile::parse(Path::new("t.json"), json).unwrap()],
            ..Default::default()
        }
    }

    fn user(c: Option<Credentials>) -> String {
        c.map(|c| format!("{}:{}", c.username, c.password))
            .unwrap_or_default()
    }

    #[test]
    fn test_decode_auth() {
        let c = file(&format!(
            r#"{{"auths": {{"r.io": {{"auth": "{}"}}, "s.io": {{"username": "u", "password": "p"}}}}}}"#,
            BASE64.encode("myuser:my:complex:password")
        ));
        assert_eq!(
            user(c.lookup("r.io", "x").unwrap()),
            "myuser:my:complex:password"
        );
        assert_eq!(user(c.lookup("s.io", "x").unwrap()), "u:p");
        assert!(AuthFile::parse(Path::new("t"), r#"{"auths": {"r.io": {"auth": "%%"}}}"#).is_err());
        assert!(AuthFile::parse(
            Path::new("t"),
            &format!(
                r#"{{"auths": {{"r.io": {{"auth": "{}"}}}}}}"#,
                BASE64.encode("nocolon")
            )
        )
        .is_err());
        assert!(AuthFile::parse(Path::new("t"), "[]").is_err());
    }

    #[test]
    fn test_scoped_keys() {
        let c = file(&format!(
            r#"{{"auths": {{
                "quay.io": {{"auth": "{}"}},
                "quay.io/org": {{"auth": "{}"}},
                "quay.io/org/img": {{"auth": "{}"}},
                "https://index.docker.io/v1/": {{"auth": "{}"}}
            }}}}"#,
            BASE64.encode("a:1"),
            BASE64.encode("b:2"),
            BASE64.encode("c:3"),
            BASE64.encode("d:4")
        ));
        assert_eq!(user(c.lookup("quay.io", "other/x").unwrap()), "a:1");
        assert_eq!(user(c.lookup("quay.io", "org/x").unwrap()), "b:2");
        assert_eq!(user(c.lookup("quay.io", "org/img").unwrap()), "c:3");
        assert_eq!(user(c.lookup("quay.io", "organization/x").unwrap()), "a:1");
        assert_eq!(
            user(c.lookup("registry-1.docker.io", "library/a").unwrap()),
            "d:4"
        );
        assert!(c.lookup("ghcr.io", "x").unwrap().is_none());
    }

    #[test]
    fn test_tokens() {
        let c = file(
            r#"{"auths": {"r.io": {"identitytoken": "refresh"}, "s.io": {"registrytoken": "bearer"}}}"#,
        );
        assert_eq!(
            c.lookup("r.io", "x")
                .unwrap()
                .unwrap()
                .identity_token
                .as_deref(),
            Some("refresh")
        );
        assert_eq!(
            c.lookup("s.io", "x")
                .unwrap()
                .unwrap()
                .registry_token
                .as_deref(),
            Some("bearer")
        );
    }

    /// The credentials of a destination of an external scheme are the entry
    /// of exactly `SCHEME://AUTHORITY`: no entry of a registry, whatever the
    /// text could be taken for, and no prefix of a path.
    #[test]
    fn test_the_credentials_of_a_transport_key_are_the_entry_of_that_key() {
        let c = file(&format!(
            r#"{{"auths": {{"docker.io": {{"auth": "{}"}}, "s3://bucket": {{"auth": "{}"}}, "quay.io": {{"auth": "{}"}}}}}}"#,
            BASE64.encode("hub:1"),
            BASE64.encode("s3:2"),
            BASE64.encode("quay:3"),
        ));
        let got = c.export_exact("s3://bucket").unwrap();
        assert_eq!(got.keys().collect::<Vec<_>>(), ["s3://bucket"]);
        assert_eq!(user(got.get("s3://bucket").cloned()), "s3:2");
        // (what a docker reference would resolve to is not an entry of it)
        for key in ["s3://bucket2", "s3://other", "s3://"] {
            assert!(c.export_exact(key).unwrap().is_empty(), "{key}");
        }
        assert!(c.export_exact("fake://bucket").unwrap().is_empty());
        assert_eq!(normalize_auth_key("s3://bucket/"), "s3://bucket");
        assert_eq!(normalize_auth_key("S3://Bucket:9000/"), "s3://bucket:9000");
    }

    #[test]
    fn test_explicit_credentials_come_first() {
        let c = file(&format!(
            r#"{{"auths": {{"r.io": {{"auth": "{}"}}}}}}"#,
            BASE64.encode("f:1")
        ))
        .with_credentials("r.io", Credentials::basic("cli", "2"));
        assert_eq!(user(c.lookup("r.io", "x").unwrap()), "cli:2");
        let broken = AuthConfig {
            error: Some("broken".into()),
            ..Default::default()
        };
        assert!(broken.lookup("r.io", "x").is_err());
        let broken = broken.with_credentials("r.io", Credentials::basic("cli", "2"));
        assert_eq!(user(broken.lookup("r.io", "x").unwrap()), "cli:2");
    }

    #[test]
    fn test_normalize_keys() {
        assert_eq!(
            normalize_auth_key("https://index.docker.io/v1/"),
            "docker.io"
        );
        assert_eq!(
            normalize_auth_key("http://localhost:5000/"),
            "localhost:5000"
        );
        assert_eq!(normalize_auth_key("quay.io/org/"), "quay.io/org");
        assert_eq!(
            normalize_auth_key("registry-1.docker.io/library"),
            "docker.io/library"
        );
    }

    #[test]
    fn test_registry_auth_header() {
        use base64::engine::general_purpose::URL_SAFE;
        let one = URL_SAFE.encode(r#"{"username":"u","password":"p"}"#);
        let a = RegistryAccess::from_registry_auth(&one).unwrap();
        assert_eq!(a.creds, Some(Credentials::basic("u", "p")));
        let scoped = URL_SAFE
            .encode(r#"{"username":"u","password":"p","serveraddress":"https://quay.io/"}"#);
        let a = RegistryAccess::from_registry_auth(&scoped).unwrap();
        assert!(a.creds.is_none());
        assert_eq!(a.auths["quay.io"], Credentials::basic("u", "p"));
        let map = URL_SAFE.encode(format!(
            r#"{{"quay.io":{{"auth":"{}"}},"docker.io":{{"identitytoken":"t"}}}}"#,
            BASE64.encode("x:y")
        ));
        let a = RegistryAccess::from_registry_auth(&map).unwrap();
        assert_eq!(a.auths["quay.io"], Credentials::basic("x", "y"));
        assert_eq!(a.auths["docker.io"].identity_token.as_deref(), Some("t"));
        assert!(RegistryAccess::from_registry_auth("").unwrap().is_empty());
        assert!(RegistryAccess::from_registry_auth("%%%").is_err());
        // an empty credential (podman sends `{}` without credentials)
        assert!(RegistryAccess::from_registry_auth(&URL_SAFE.encode("{}"))
            .unwrap()
            .is_empty());
        // --creds wins over everything
        let c = file(&format!(
            r#"{{"auths": {{"r.io": {{"auth": "{}"}}}}}}"#,
            BASE64.encode("f:1")
        ))
        .with_access(&RegistryAccess {
            creds: Some(Credentials::basic("cli", "2")),
            ..Default::default()
        });
        assert_eq!(user(c.lookup("r.io", "x").unwrap()), "cli:2");
        let exported = file(&format!(
            r#"{{"auths": {{"r.io/ns": {{"auth": "{}"}}}}}}"#,
            BASE64.encode("f:1")
        ))
        .export()
        .unwrap();
        assert_eq!(exported["r.io/ns"], Credentials::basic("f", "1"));
    }

    #[test]
    fn only_the_entries_of_the_scopes_are_exported() {
        let c = file(&format!(
            r#"{{"auths": {{
                "r.io": {{"auth": "{}"}},
                "other.io": {{"auth": "{}"}},
                "third.io/ns": {{"auth": "{}"}}
            }}}}"#,
            BASE64.encode("a:1"),
            BASE64.encode("b:2"),
            BASE64.encode("c:3")
        ));
        let out = c
            .export_for(&["r.io/team/app".to_string(), "none.io/x".to_string()])
            .unwrap();
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out["r.io/team/app"], Credentials::basic("a", "1"));
        let out = c.export_for(&["third.io/ns/x".to_string()]).unwrap();
        assert_eq!(out.keys().collect::<Vec<_>>(), ["third.io/ns/x"]);
        assert!(c.export_for(&[]).unwrap().is_empty());
    }

    /// The Docker Hub aliases: an entry under Docker's
    /// `https://index.docker.io/v1/` reaches the endpoint the daemon looks
    /// up under any of the names of the Hub, and an auth file that cannot
    /// be read is an error with no scope too.
    #[test]
    fn the_exported_hub_entry_is_found_by_the_daemon() {
        let c = file(&format!(
            r#"{{"auths": {{"https://index.docker.io/v1/": {{"auth": "{}"}}}}}}"#,
            BASE64.encode("hub:1")
        ));
        for scope in [
            "docker.io/library/alpine",
            "registry-1.docker.io/library/alpine",
        ] {
            let auths = c.export_for(&[scope.to_string()]).unwrap();
            assert_eq!(
                auths.keys().collect::<Vec<_>>(),
                ["docker.io/library/alpine"]
            );
            let daemon = AuthConfig::default().with_access(&RegistryAccess {
                auths,
                ..Default::default()
            });
            for host in ["docker.io", "index.docker.io", "registry-1.docker.io"] {
                assert_eq!(
                    user(daemon.lookup(host, "library/alpine").unwrap()),
                    "hub:1"
                );
            }
            assert_eq!(
                user(daemon.lookup("docker.io", "library/other").unwrap()),
                ""
            );
        }
        let broken = AuthConfig {
            error: Some("bad".into()),
            ..Default::default()
        };
        assert_eq!(broken.export_for(&[]).unwrap_err(), "bad");
    }

    #[test]
    fn test_parse_creds() {
        assert_eq!(
            Credentials::parse_creds("u:p:q").unwrap(),
            Credentials::basic("u", "p:q")
        );
        assert!(Credentials::parse_creds(":p").is_err());
        assert!(Credentials::parse_creds("u").is_err());
        assert!(!format!("{:?}", Credentials::basic("u", "secret")).contains("secret"));
    }

    #[test]
    fn test_store_and_remove() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/auth.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            r#"{"auths": {"https://quay.io/": {"auth": "eDp5"}}, "other": 1}"#,
        )
        .unwrap();
        store_credentials(Some(&p), "quay.io", "u", "p").unwrap();
        let c = AuthConfig::load_file(&p);
        assert_eq!(user(c.lookup("quay.io", "x").unwrap()), "u:p");
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(root["other"], 1);
        assert_eq!(root["auths"].as_object().unwrap().len(), 1);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(store_credentials(Some(&p), "quay.io", "a:b", "p").is_err());
        remove_credentials(Some(&p), "https://quay.io").unwrap();
        assert!(AuthConfig::load_file(&p)
            .lookup("quay.io", "x")
            .unwrap()
            .is_none());
        assert!(remove_credentials(Some(&p), "quay.io").is_err());
        store_credentials(Some(&p), "a.io", "u", "p").unwrap();
        remove_all_credentials(Some(&p)).unwrap();
        assert!(AuthConfig::load_file(&p)
            .lookup("a.io", "x")
            .unwrap()
            .is_none());
        // a new file in a new directory
        let q = d.path().join("new/dir/auth.json");
        store_credentials(Some(&q), "a.io", "u", "p").unwrap();
        assert_eq!(
            std::fs::metadata(q.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    /// A process that lives longer than a command sees a `login` in the
    /// stamp of its auth files, and reads those same files again.
    #[test]
    fn a_login_changes_the_stamp_and_is_read_again() {
        let d = tempfile::tempdir().unwrap();
        let files = vec![d.path().join("auth.json")];
        let before = auth_files_stamp(&files);
        assert_eq!(before, vec![None]);
        let empty = AuthConfig::load_paths(&files, false);
        assert!(empty.lookup("quay.io", "x").unwrap().is_none());
        store_credentials(Some(&files[0]), "quay.io", "u", "p").unwrap();
        assert_ne!(auth_files_stamp(&files), before);
        let reloaded = empty.reloaded(&files).unwrap();
        assert_eq!(user(reloaded.lookup("quay.io", "x").unwrap()), "u:p");
        std::fs::write(&files[0], "{").unwrap();
        assert!(empty.reloaded(&files).is_err());
    }

    #[test]
    fn test_missing_and_broken_files() {
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("missing.json");
        assert!(
            AuthConfig::load_paths(std::slice::from_ref(&missing), false)
                .lookup("a", "b")
                .unwrap()
                .is_none()
        );
        assert!(AuthConfig::load_file(&missing).lookup("a", "b").is_err());
        let broken = d.path().join("broken.json");
        std::fs::write(&broken, "{").unwrap();
        assert!(AuthConfig::load_paths(&[broken], false)
            .lookup("a", "b")
            .is_err());
    }

    #[test]
    fn test_helpers() {
        assert!(!valid_helper_name("../x"));
        assert!(!valid_helper_name("a/b"));
        assert!(!valid_helper_name(""));
        assert!(!valid_helper_name(".hidden"));
        assert!(valid_helper_name("secretservice"));
        assert!(valid_helper_name("ecr-login"));
        let c = file(r#"{"credHelpers": {"r.io": "../../bin/sh"}}"#);
        assert!(c.lookup("r.io", "x").is_err());
    }

    #[test]
    fn test_helper_answers_and_timeouts() {
        let d = tempfile::tempdir().unwrap();
        let helper = |name: &str, body: &str| {
            let p = d.path().join(format!("docker-credential-{name}"));
            velarx_base::testing::write_script(&p, body);
        };
        helper(
            "good",
            r#"read s; echo "{\"Username\":\"u-$s\",\"Secret\":\"p\"}""#,
        );
        helper("token", r#"echo '{"Username":"<token>","Secret":"rt"}'"#);
        helper(
            "none",
            "echo 'credentials not found in native keychain'; exit 1",
        );
        helper("fail", "echo boom >&2; exit 3");
        helper("big", "/usr/bin/head -c 2000000 /dev/zero");
        let run = |name: &str| {
            run_credential_helper_in(name, "r.io", Some(d.path()), HelperLimits::default())
                .map(|a| a.credentials)
        };
        let good = run("good").unwrap().unwrap();
        let token = run("token").unwrap().unwrap();
        let none = run("none").unwrap();
        let fail = run("fail");
        let big = run("big");
        let missing = run("missing");
        assert_eq!(good, Credentials::basic("u-r.io", "p"));
        assert_eq!(token.identity_token.as_deref(), Some("rt"));
        assert!(none.is_none());
        assert!(fail.is_err());
        assert!(big.is_err());
        assert!(missing.is_err());
    }

    /// The helpers that misbehave: each ends in time, with an error, and
    /// leaves no process behind.
    #[test]
    fn a_helper_that_misbehaves_is_refused_and_reaped() {
        let d = tempfile::tempdir().unwrap();
        let pid_of = |name: &str| d.path().join(format!("{name}.pid"));
        let helper = |name: &str, body: &str| {
            let p = d.path().join(format!("docker-credential-{name}"));
            velarx_base::testing::write_script(&p, body);
        };
        let pid_file = |name: &str| pid_of(name).display().to_string();
        helper(
            "hang",
            &format!("echo $$ > {}\nexec /usr/bin/sleep 3600", pid_file("hang")),
        );
        helper(
            "closed",
            &format!(
                "echo $$ > {}\nexec >&-\nexec /usr/bin/sleep 3600",
                pid_file("closed")
            ),
        );
        // its child keeps the output open after it answered and exited
        helper(
            "child",
            &format!(
                "/usr/bin/sleep 3600 &\necho $! > {}\necho '{{\"Username\":\"u\",\"Secret\":\"p\"}}'",
                pid_file("child")
            ),
        );
        helper("huge", "/usr/bin/head -c 10485760 /dev/zero");
        helper("partial", r#"printf '{"Username":"u","Sec'"#);
        helper("binary", r"printf '\377\376\375'");
        helper("refuses", r#"echo '{"Username":"u","Secret":"p"}'; exit 1"#);
        helper("deaf", r#"echo '{"Username":"u","Secret":"p"}'"#);
        // not executed
        std::fs::write(d.path().join("docker-credential-noexec"), "#!/bin/sh\n").unwrap();
        // (time enough for a shell to start and write its pid on a loaded
        // machine)
        let limits = HelperLimits {
            timeout: Duration::from_secs(1),
            ..HelperLimits::default()
        };
        let run = |name: &str, server: &str| {
            let start = Instant::now();
            let r = run_credential_helper_in(name, server, Some(d.path()), limits)
                .map(|a| a.credentials);
            assert!(
                start.elapsed() < KILL_GRACE,
                "{name} took {:?}",
                start.elapsed()
            );
            r
        };
        let gone = |name: &str| {
            let pid = std::fs::read_to_string(pid_of(name)).unwrap();
            // (a zombie is still listed)
            !Path::new(&format!("/proc/{}", pid.trim())).exists()
        };
        for name in ["hang", "closed"] {
            let e = run(name, "r.io").unwrap_err();
            assert!(e.contains("timed out"), "{name}: {e}");
            assert!(gone(name), "{name} is left");
        }
        let e = run("child", "r.io").unwrap_err();
        assert!(e.contains("timed out"), "{e}");
        let child = std::fs::read_to_string(pid_of("child")).unwrap();
        let _ = rustix::process::kill_process(
            rustix::process::Pid::from_raw(child.trim().parse().unwrap()).unwrap(),
            rustix::process::Signal::KILL,
        );
        let e = run("huge", "r.io").unwrap_err();
        assert!(e.contains("too big"), "{e}");
        for name in ["partial", "binary"] {
            let e = run(name, "r.io").unwrap_err();
            assert!(e.contains("invalid answer"), "{name}: {e}");
        }
        let e = run("refuses", "r.io").unwrap_err();
        assert!(e.contains("failed"), "{e}");
        let e = run("noexec", "r.io").unwrap_err();
        assert!(
            e.starts_with("cannot run `docker-credential-noexec`: "),
            "{e}"
        );
        // an input it does not read is no harm, up to the size a pipe takes
        // at once
        let deaf = run("deaf", &"r".repeat(libc::PIPE_BUF)).unwrap();
        assert_eq!(deaf, Some(Credentials::basic("u", "p")));
        let e = run("deaf", &"r".repeat(libc::PIPE_BUF + 1)).unwrap_err();
        assert!(e.contains("too long"), "{e}");
    }

    #[test]
    fn test_helpers_are_searched_in_absolute_entries_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("docker-credential-x");
        // not executed
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let find = |search: &str| find_helper("docker-credential-x", search.as_ref());
        let abs = format!("/nonexistent:{}", d.path().display());
        assert_eq!(find(&abs), Some(p.clone()));
        assert_eq!(find(""), None);
        assert_eq!(find(":/nonexistent"), None);
        assert_eq!(find(".:bin:../x"), None);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(find(&abs), None);
    }
}
