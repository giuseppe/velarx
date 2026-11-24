// SPDX-License-Identifier: Apache-2.0
//! Registry configuration parsing for `/etc/velarx/registries.conf`.
//!
//! The file has the TOML format of the registries.conf of podman and CRI-O,
//! in velarx's own directories.
//! See: https://github.com/containers/image/blob/main/docs/containers-registries.conf.5.md
//! Where the endpoints of a name come from is `velarx-endpoint-core`; the
//! differences from that format are in the README.
//!
//! A configuration that cannot be read or parsed fails closed: the client
//! refuses every registry operation with the error instead of going on
//! without the rules (a `blocked` registry silently allowed).

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Largest registries.conf (or drop-in) read.
const MAX_REGISTRIES_CONF: u64 = 1 << 20;

/// What is done with a short name that has several candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShortNameMode {
    /// Refused: there is no TTY to ask on
    Enforcing,
    /// The candidates are tried in order
    #[default]
    Permissive,
    /// The candidates are tried in order
    Disabled,
}

impl std::str::FromStr for ShortNameMode {
    type Err = String;

    fn from_str(word: &str) -> Result<Self, String> {
        match word {
            "enforcing" => Ok(Self::Enforcing),
            "permissive" => Ok(Self::Permissive),
            "disabled" => Ok(Self::Disabled),
            _ => Err(format!("invalid short-name-mode `{word}`")),
        }
    }
}

/// Main configuration structure for registries.conf
#[derive(Debug, Clone, Default)]
pub struct RegistriesConfig {
    /// Search these registries for short names that are no alias; none by
    /// default, as podman's
    pub search_registries: Vec<String>,

    /// The file that set `search_registries`
    search_origin: Option<String>,

    /// Per-registry configuration blocks, in the order of the files
    pub registry: Vec<RegistryConfig>,

    /// Credential helper programs to use
    pub credential_helpers: Vec<String>,

    /// Short name mode: "enforcing" refuses a short name with several
    /// candidates, "permissive" and "disabled" try them in order
    pub short_name_mode: ShortNameMode,

    /// Short name aliases: `"alpine" = "docker.io/library/alpine"`
    pub aliases: HashMap<String, String>,

    /// Why the configuration could not be loaded: every lookup fails with it.
    pub error: Option<String>,
}

/// Configuration for a single registry
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryConfig {
    /// Prefix to match (e.g., "docker.io", "quay.io/prometheus").  Defaults to
    /// `location` when omitted, as in containers/image.
    #[serde(default)]
    pub prefix: String,

    /// Actual registry location (if different from prefix)
    pub location: Option<String>,

    /// Allow insecure (HTTP) connections
    #[serde(default)]
    pub insecure: bool,

    /// Block pulls from this registry
    #[serde(default)]
    pub blocked: bool,

    /// Let the registry send the client to private addresses (a token
    /// realm or a redirect on this machine or a private network) although
    /// the registry itself is not on one
    #[serde(rename = "allow-private-addresses", default)]
    pub allow_private_addresses: bool,

    /// Mirror configurations (tried in order)
    #[serde(default)]
    pub mirror: Vec<MirrorConfig>,

    /// Registry level default of `pull-from-mirror` of the mirrors
    #[serde(rename = "pull-from-mirror", default = "default_pull_from_mirror")]
    pub pull_from_mirror: String,

    /// The mirrors are used only for references with a digest (the older
    /// form of `pull-from-mirror = "digest-only"`)
    #[serde(rename = "mirror-by-digest-only", default)]
    pub mirror_by_digest_only: bool,
}

fn default_pull_from_mirror() -> String {
    "all".to_string()
}

/// Configuration for a registry mirror
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorConfig {
    /// Mirror location URL
    pub location: String,

    /// Allow insecure (HTTP) connections to this mirror
    #[serde(default)]
    pub insecure: bool,

    /// When the mirror is used: "all", "digest-only" (references with a
    /// digest) or "tag-only"; by default the setting of the registry
    #[serde(rename = "pull-from-mirror")]
    pub pull_from_mirror: Option<String>,
}

/// One file (v2 format): what it sets, so that a drop-in changes only that.
/// A key that is not here is an error: a typo (`blokced = true`) would
/// leave the rule off.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfFile {
    #[serde(rename = "unqualified-search-registries")]
    search_registries: Option<Vec<String>>,
    #[serde(default)]
    registry: Vec<RegistryConfig>,
    #[serde(rename = "credential-helpers")]
    credential_helpers: Option<Vec<String>>,
    #[serde(rename = "short-name-mode")]
    short_name_mode: Option<String>,
    aliases: Option<HashMap<String, String>>,
    /// Podman's key that velarx does not have: warned about when set
    #[serde(rename = "additional-layer-store-auth-helper")]
    additional_layer_store_auth_helper: Option<String>,
}

/// The message of a TOML error; for an unknown key, the closest key that
/// exists if there is one.
fn toml_error(e: toml::de::Error) -> String {
    let message = e.message();
    let key = message
        .strip_prefix("unknown field `")
        .and_then(|m| m.split_once('`'));
    let Some((key, rest)) = key else {
        return e.to_string();
    };
    let known = rest.split('`').skip(1).step_by(2);
    format!("{e}{}", velarx_base::conf::did_you_mean(key, known))
}

/// The v1 format: `[registries.search]`, `[registries.insecure]` and
/// `[registries.block]`, each with a `registries` list.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1File {
    #[serde(default)]
    search: Option<V1List>,
    #[serde(default)]
    insecure: Option<V1List>,
    #[serde(default)]
    block: Option<V1List>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1List {
    #[serde(default)]
    registries: Vec<String>,
}

/// A location or a prefix: no scheme, no trailing slash, a host or a host
/// and a path (a prefix may be `*.` and a host).
fn normalize_location(what: &str, value: &str) -> Result<String, String> {
    if value.contains("://") {
        return Err(format!(
            "invalid {what} `{value}`: it must not contain a scheme"
        ));
    }
    let v = value.trim_end_matches('/');
    if v.is_empty() {
        return Err(format!("invalid empty {what}"));
    }
    let name = match v.strip_prefix("*.") {
        Some(domain) if what == "prefix" => domain,
        _ => v,
    };
    let why = if name.len() < v.len() {
        (!velarx_base::reference::host_ok(name.as_bytes()))
            .then(|| velarx_base::reference::why_not_a_host(name.as_bytes()))
    } else {
        (!velarx_base::reference::prefix_ok(v.as_bytes()))
            .then(|| velarx_base::reference::why_not_a_prefix(v.as_bytes()))
    };
    if let Some(why) = why {
        let after = if name.len() < v.len() {
            " (after `*.`)"
        } else {
            ""
        };
        return Err(format!("invalid {what} `{value}`: {why}{after}"));
    }
    Ok(v.to_string())
}

impl RegistryConfig {
    /// Check and fill in the defaults of a block, like containers/image.
    fn normalize(&mut self) -> Result<(), String> {
        self.location = match self.location.as_deref() {
            Some(l) if !l.is_empty() => Some(normalize_location("location", l)?),
            _ => None,
        };
        if self.prefix.is_empty() {
            match &self.location {
                Some(location) => self.prefix = location.clone(),
                None => return Err("a [[registry]] block needs a prefix or a location".into()),
            }
        } else {
            self.prefix = normalize_location("prefix", &self.prefix)?;
            // (a reference to index.docker.io is read as one to docker.io:
            // a prefix that is written so is, not one that comes from a
            // location)
            if let Some(rest) = self.prefix.strip_prefix("index.docker.io") {
                if rest.is_empty() || rest.starts_with('/') {
                    self.prefix = format!("docker.io{rest}");
                }
            }
            if self.prefix.starts_with("*.") && self.location.is_some() {
                return Err(format!(
                    "wildcard prefix `{}` cannot have a location",
                    self.prefix
                ));
            }
        }
        if !valid_pull_from_mirror(&self.pull_from_mirror) {
            return Err(format!(
                "invalid pull-from-mirror `{}`",
                self.pull_from_mirror
            ));
        }
        let digest_only = self.mirror_by_digest_only;
        if digest_only && self.pull_from_mirror == "all" {
            self.pull_from_mirror = "digest-only".to_string();
        }
        for m in &mut self.mirror {
            m.location = normalize_location("mirror location", &m.location)?;
            if let Some(mode) = &m.pull_from_mirror {
                if !valid_pull_from_mirror(mode) {
                    return Err(format!("invalid pull-from-mirror `{mode}`"));
                }
                if digest_only && mode != "all" && mode != "digest-only" {
                    return Err(format!(
                        "pull-from-mirror conflicts with mirror-by-digest-only for `{}`",
                        self.prefix
                    ));
                }
            }
        }
        if digest_only && self.pull_from_mirror != "digest-only" {
            return Err(format!(
                "pull-from-mirror conflicts with mirror-by-digest-only for `{}`",
                self.prefix
            ));
        }
        Ok(())
    }
}

fn valid_pull_from_mirror(mode: &str) -> bool {
    matches!(mode, "all" | "digest-only" | "tag-only")
}

pub(crate) use velarx_base::conf::{rootless, user_config_dir};

/// The variable that names the registries.conf to read instead of the
/// user's or the system's.
pub const REGISTRIES_CONF_ENV: &str = "VELARX_REGISTRIES_CONF";

/// The short name aliases that every configuration starts with (the table
/// podman's containers-common ships as `000-shortnames.conf`).
const SHORT_NAMES: &str = include_str!("shortnames.conf");

impl RegistriesConfig {
    /// Load the configuration like containers/image does its own: the file
    /// named by `$VELARX_REGISTRIES_CONF` (which must exist, and has no
    /// drop-ins), else the user's (rootless, `~/.config/velarx`) or the
    /// system's (`/etc/velarx`) registries.conf, then the drop-ins of
    /// `registries.conf.d` (system, then user; a user file overrides a
    /// system file of the same name), in the order of their names.  An
    /// error makes the configuration refuse everything.
    pub fn load() -> Self {
        Self::load_with(std::env::var_os(REGISTRIES_CONF_ENV))
    }

    /// [`load`](Self::load) with `env` for `$VELARX_REGISTRIES_CONF`
    /// (a test does not change the environment its other tests share).
    fn load_with(env: Option<std::ffi::OsString>) -> Self {
        match Self::load_checked(env) {
            Ok(config) => config,
            Err(e) => {
                warn!("registries.conf: {e}");
                Self {
                    error: Some(format!("invalid registries configuration: {e}")),
                    ..Self::default_config()
                }
            }
        }
    }

    /// The files [`load`](Self::load) reads, in order (those that do not
    /// exist too): what a process that keeps the configuration it read
    /// depends on.
    pub fn files() -> Vec<PathBuf> {
        Self::files_with(std::env::var_os(REGISTRIES_CONF_ENV).filter(|e| !e.is_empty()))
            .map(|(main, drop_ins)| main.into_iter().chain(drop_ins).collect())
            .unwrap_or_default()
    }

    /// The main file (`$VELARX_REGISTRIES_CONF` when `env` names one) and
    /// the drop-ins, in order.
    fn files_with(
        env: Option<std::ffi::OsString>,
    ) -> Result<(Option<PathBuf>, Vec<PathBuf>), String> {
        let user = if rootless().map_err(|e| e.to_string())? {
            user_config_dir().map_err(|e| e.to_string())?
        } else {
            None
        };
        let main = match &env {
            Some(path) => Some(PathBuf::from(path)),
            None => user
                .as_ref()
                .map(|u| u.join("velarx/registries.conf"))
                .filter(|p| p.exists())
                .or_else(|| Some(PathBuf::from("/etc/velarx/registries.conf"))),
        };
        if env.is_some() {
            return Ok((main, Vec::new()));
        }
        let mut dirs = vec![PathBuf::from("/etc/velarx/registries.conf.d")];
        dirs.extend(user.map(|u| u.join("velarx/registries.conf.d")));
        Ok((main, drop_ins(&dirs)))
    }

    fn load_checked(env: Option<std::ffi::OsString>) -> Result<Self, String> {
        let env = env.filter(|e| !e.is_empty());
        let named = env.is_some();
        let (main, drop_ins) = Self::files_with(env)?;
        let mut config = Self::default_config();
        let mut found = false;
        if let Some(path) = main {
            found = config.apply_path(&path, named)?;
        }
        for path in drop_ins {
            found |= config.apply_path(&path, false)?;
        }
        if !found {
            debug!("No registries.conf found, using defaults");
        }
        Ok(config)
    }

    /// Apply the file at `path`; false if it does not exist (and need not).
    fn apply_path(&mut self, path: &Path, must_exist: bool) -> Result<bool, String> {
        let content = match super::read_config_file(path, MAX_REGISTRIES_CONF) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !must_exist => return Ok(false),
            Err(e) => return Err(format!("cannot read `{}`: {e}", path.display())),
        };
        debug!("Loading registries config from {:?}", path);
        self.apply(&path.display().to_string(), &content)
            .map_err(|e| format!("`{}`: {e}", path.display()))?;
        Ok(true)
    }

    fn empty() -> Self {
        Self {
            short_name_mode: ShortNameMode::Permissive,
            ..Self::default()
        }
    }

    /// Parse the content of a registries.conf file.
    pub fn parse(content: &str) -> Result<Self, String> {
        Self::parse_all(&[content])
    }

    /// Parse a registries.conf and its drop-ins, in order.
    pub fn parse_all(contents: &[&str]) -> Result<Self, String> {
        let mut config = Self::empty();
        for c in contents {
            config.apply("registries.conf", c)?;
        }
        Ok(config)
    }

    /// Apply a file: what it sets replaces what the previous ones set; a
    /// registry block replaces the block of the same prefix where it was.
    fn apply(&mut self, file_name: &str, content: &str) -> Result<(), String> {
        let value: toml::Table = toml::from_str(content).map_err(|e| e.to_string())?;
        if let Some(v1) = value.get("registries") {
            if value.len() > 1 {
                return Err("mixing the v1 and v2 formats is not supported".into());
            }
            let v1: V1File = v1.clone().try_into().map_err(toml_error)?;
            return self.apply_v1(file_name, v1);
        }
        let file: ConfFile = value.try_into().map_err(toml_error)?;
        if file.additional_layer_store_auth_helper.is_some()
            && velarx_base::conf::first_time(&format!(
                "{file_name}: additional-layer-store-auth-helper"
            ))
        {
            warn!("{file_name}: additional-layer-store-auth-helper is not supported by velarx");
        }
        if let Some(list) = file.search_registries {
            if let Some(bad) = list
                .iter()
                .find(|r| !velarx_base::reference::host_ok(r.as_bytes()))
            {
                let why = velarx_base::reference::why_not_a_host(bad.as_bytes());
                return Err(format!(
                    "invalid unqualified search registry `{bad}`: {why}"
                ));
            }
            self.search_registries = list;
            self.search_origin = Some(file_name.to_string());
        }
        if let Some(mode) = file.short_name_mode.filter(|m| !m.is_empty()) {
            self.short_name_mode = mode.parse()?;
        }
        if let Some(helpers) = file.credential_helpers {
            // (`containers-auth.json` is the auth file, what velarx reads
            // anyway: podman's default says nothing)
            if helpers.iter().any(|h| h != "containers-auth.json")
                && velarx_base::conf::first_time(&format!("{file_name}: credential-helpers"))
            {
                warn!(
                    "{file_name}: credential-helpers is not supported by velarx: `login` keeps the credentials in its auth.json, and a credHelpers entry of Docker's config.json is read"
                );
            }
            self.credential_helpers = helpers;
        }
        let mut seen: Vec<(String, String)> = Vec::new();
        for mut reg in file.registry {
            let written = reg.prefix.clone();
            reg.normalize()?;
            if let Some((_, other)) = seen.iter().find(|(p, w)| *p == reg.prefix && *w != written) {
                return Err(format!(
                    "the prefixes `{other}` and `{written}` of two blocks are the same registry"
                ));
            }
            seen.push((reg.prefix.clone(), written));
            self.put_registry(reg);
        }
        for (name, value) in file.aliases.unwrap_or_default() {
            if !is_short_name(&name) {
                return Err(format!(
                    "alias `{name}` must be a short name without tag or digest"
                ));
            }
            if value.is_empty() {
                // removes an alias of a previous file
                self.aliases.remove(&name);
                continue;
            }
            if !is_qualified(&value) {
                return Err(format!(
                    "alias `{name}` must point to a fully qualified reference without digest"
                ));
            }
            self.aliases.insert(name, value);
        }
        Ok(())
    }

    fn apply_v1(&mut self, file_name: &str, v1: V1File) -> Result<(), String> {
        if let Some(search) = v1.search {
            self.search_registries = search.registries;
            self.search_origin = Some(file_name.to_string());
        }
        for (list, blocked) in [(v1.insecure, false), (v1.block, true)] {
            for name in list.map(|l| l.registries).unwrap_or_default() {
                let name = normalize_location("registry", &name)?;
                match self.registry.iter_mut().find(|r| r.prefix == name) {
                    Some(r) if blocked => r.blocked = true,
                    Some(r) => r.insecure = true,
                    None => self.registry.push(RegistryConfig {
                        prefix: name.clone(),
                        location: Some(name),
                        insecure: !blocked,
                        blocked,
                        allow_private_addresses: false,
                        mirror: Vec::new(),
                        pull_from_mirror: default_pull_from_mirror(),
                        mirror_by_digest_only: false,
                    }),
                }
            }
        }
        Ok(())
    }

    fn put_registry(&mut self, reg: RegistryConfig) {
        match self.registry.iter_mut().find(|r| r.prefix == reg.prefix) {
            Some(r) => *r = reg,
            None => self.registry.push(reg),
        }
    }

    /// The configuration with no file: the short name aliases of
    /// `shortnames.conf`, no unqualified search registry, as podman's.
    fn default_config() -> Self {
        let mut config = Self::empty();
        config
            .apply("the built-in short names", SHORT_NAMES)
            .expect("the built-in short names parse");
        config
    }

    /// The error of a configuration that could not be loaded.
    pub fn check(&self) -> Result<(), String> {
        match &self.error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    /// The blocks, for [`velarx_endpoint_core`].
    pub(crate) fn blocks(&self) -> Vec<velarx_endpoint_core::Block> {
        use velarx_endpoint_core::{Block, Mirror, Mode};
        let mode = |s: &str| match s {
            "digest-only" => Mode::DigestOnly,
            "tag-only" => Mode::TagOnly,
            _ => Mode::All,
        };
        let bytes = |s: &str| s.as_bytes().to_vec();
        let mirror = |reg: &RegistryConfig, m: &MirrorConfig| Mirror {
            location: bytes(&m.location),
            insecure: m.insecure,
            mode: mode(
                m.pull_from_mirror
                    .as_deref()
                    .unwrap_or(&reg.pull_from_mirror),
            ),
        };
        self.registry
            .iter()
            .map(|r| Block {
                prefix: bytes(&r.prefix),
                location: r.location.as_deref().map(bytes),
                insecure: r.insecure,
                blocked: r.blocked,
                allow_private: r.allow_private_addresses,
                mirrors: r.mirror.iter().map(|m| mirror(r, m)).collect(),
            })
            .collect()
    }

    /// Find registry config matching a given image reference
    pub fn find_registry(&self, image_ref: &str) -> Option<&RegistryConfig> {
        velarx_endpoint_core::select(&self.blocks(), image_ref.as_bytes())
            .map(|i| &self.registry[i])
    }

    /// Whether the registry block for `registry` (`host/repository`) allows
    /// insecure connections.
    pub fn is_insecure(&self, registry: &str) -> bool {
        self.find_registry(registry).is_some_and(|r| r.insecure)
    }

    /// Check if a registry is blocked
    pub fn is_blocked(&self, registry: &str) -> bool {
        self.find_registry(registry).is_some_and(|r| r.blocked)
    }

    /// The fully qualified references a reference can mean, in the order
    /// they are tried.  A reference with a registry is itself.  A short name
    /// is an alias if it has one, else it is looked up in the unqualified
    /// search registries (none: no candidate).
    pub fn candidates(&self, reference: &str) -> Vec<String> {
        // The name ends at the digest or at the tag.
        let Ok(spans) = velarx_base::reference::parse(reference.as_bytes()) else {
            return Vec::new();
        };
        if spans.host_end > 0 {
            return full(reference).into_iter().collect();
        }
        let (name, rest) = reference.split_at(spans.name_end);
        let named: Vec<String> = match self.aliases.get(name) {
            Some(target) => vec![format!("{target}{rest}")],
            None => self
                .search_registries
                .iter()
                .map(|registry| format!("{registry}/{name}{rest}"))
                .collect(),
        };
        named.iter().filter_map(|c| full(c)).collect()
    }

    /// Like [`candidates`](Self::candidates), but a short name that is no
    /// alias with no search registry is an error (as podman's), and one with
    /// several candidates is an error when the mode is `enforcing`:
    /// containers/image would ask which one is meant on a terminal, and
    /// Velarx never asks.
    pub fn resolve(&self, reference: &str) -> Result<Vec<String>, String> {
        self.check()?;
        if let Err(e) = velarx_base::reference::parse(reference.as_bytes()) {
            return Err(format!("invalid reference `{reference}`: {e}"));
        }
        let candidates = self.candidates(reference);
        if candidates.is_empty() {
            return Err(match &self.search_origin {
                Some(file) => format!(
                    "short-name \"{reference}\" did not resolve to an alias and no unqualified-search registries are defined in \"{file}\""
                ),
                None => format!(
                    "short-name \"{reference}\" did not resolve to an alias and no unqualified-search registries are defined in any registries.conf"
                ),
            });
        }
        if self.short_name_mode == ShortNameMode::Enforcing && candidates.len() > 1 {
            return Err(format!(
                "short-name resolution enforced but cannot prompt without a TTY: `{reference}` is ambiguous (candidates: {}); use a fully qualified name",
                candidates.join(", ")
            ));
        }
        Ok(candidates)
    }
}

/// The `*.conf` files of the drop-in directories, sorted by name; a file
/// of a later directory replaces the file of the same name of an earlier.
fn drop_ins(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut by_name: std::collections::BTreeMap<std::ffi::OsString, PathBuf> =
        std::collections::BTreeMap::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for e in entries.flatten() {
            let name = e.file_name();
            let s = name.to_string_lossy();
            if s.starts_with('.') || !s.ends_with(".conf") {
                continue;
            }
            by_name.insert(name, e.path());
        }
    }
    by_name.into_values().collect()
}

/// `reference` in its full form, after the defaults of docker.io: the one
/// name that the request, registries.conf and the policy read.
fn full(reference: &str) -> Option<String> {
    let bytes = reference.as_bytes();
    let spans = velarx_base::reference::parse(bytes).ok()?;
    let name = velarx_ref_core::normalize(bytes, &spans);
    let part = |r: Option<(usize, usize)>| r.map(|(from, to)| &bytes[from..to]);
    let text = velarx_ref_core::print(&name, part(spans.tag), part(spans.digest));
    String::from_utf8(text).ok()
}

/// Whether `name` is a reference with a registry and no digest.
fn is_qualified(name: &str) -> bool {
    velarx_base::reference::parse(name.as_bytes())
        .is_ok_and(|s| s.host_end > 0 && s.digest.is_none())
}

/// Whether `name` is a short name: a name without a registry, a tag or a
/// digest.
fn is_short_name(name: &str) -> bool {
    velarx_base::reference::parse(name.as_bytes())
        .is_ok_and(|s| s.host_end == 0 && s.tag.is_none() && s.digest.is_none())
}

#[cfg(test)]
impl RegistriesConfig {
    /// Get mirrors for a registry (in order of preference)
    pub fn get_mirrors(&self, registry: &str) -> Vec<&MirrorConfig> {
        self.find_registry(registry)
            .map_or(vec![], |r| r.mirror.iter().collect())
    }
}

#[cfg(test)]
impl RegistryConfig {
    /// Get the effective location for this registry
    pub fn effective_location(&self) -> &str {
        self.location.as_deref().unwrap_or(&self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mirrors of the registry for `name` (`registry/repository`) that
    /// apply to a reference with or without a digest, as the locations
    /// the name is rewritten to, and whether each is insecure.
    fn mirror_names(c: &RegistriesConfig, name: &str, has_digest: bool) -> Vec<(String, bool)> {
        let ask = velarx_endpoint_core::Ask {
            has_digest,
            push: false,
            tls_verify: true,
        };
        let (host, path) = name.split_once('/').unwrap();
        let mut all =
            velarx_endpoint_core::endpoints(&c.blocks(), host.as_bytes(), path.as_bytes(), &ask)
                .ok()
                .unwrap();
        all.pop();
        all.iter()
            .map(|e| {
                let at = format!("{}/{}", text(&e.host), text(&e.path));
                (at, e.insecure)
            })
            .collect()
    }

    fn text(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    /// Whether `prefix` governs `name`.
    fn prefix_matches(prefix: &str, name: &str) -> bool {
        let block = velarx_endpoint_core::Block {
            prefix: prefix.as_bytes().to_vec(),
            location: None,
            insecure: false,
            blocked: false,
            allow_private: false,
            mirrors: Vec::new(),
        };
        velarx_endpoint_core::select(&[block], name.as_bytes()).is_some()
    }

    #[test]
    fn a_key_that_is_not_a_setting_is_an_error() {
        for (text, key) in [
            ("unqualified-search-registry = [\"a\"]\n", "unqualified-search-registry"),
            ("[[registry]]\nlocation = \"a\"\nblokced = true\n", "blokced"),
            ("[[registry]]\nlocation = \"a\"\n[[registry.mirror]]\nlocation = \"b\"\ninsecur = true\n", "insecur"),
            ("[registries.search]\nregistries = []\n[registries.x]\n", "x"),
        ] {
            let e = RegistriesConfig::parse(text).unwrap_err();
            assert!(e.contains(key), "{text}: {e}");
        }
        let e = RegistriesConfig::parse("[[registry]]\nlocation = \"a\"\nblokced = true\n")
            .unwrap_err();
        assert!(e.contains("did you mean `blocked`"), "{e}");
        // podman's key that velarx does not have is accepted
        RegistriesConfig::parse("additional-layer-store-auth-helper = \"/x\"\n").unwrap();
    }

    #[test]
    fn test_default_config() {
        let config = RegistriesConfig::default_config();
        assert!(config.search_registries.is_empty());
        assert_eq!(config.short_name_mode, ShortNameMode::Permissive);
        // podman's table of aliases, and nothing else
        assert_eq!(
            config.resolve("alpine:3").unwrap(),
            ["docker.io/library/alpine:3"]
        );
        assert_eq!(
            config.resolve("fedora").unwrap(),
            ["registry.fedoraproject.org/fedora"]
        );
        assert_eq!(config.resolve("podman").unwrap(), ["quay.io/podman/stable"]);
        let e = config.resolve("nonexistentxyzq:1").unwrap_err();
        assert!(
            e.starts_with("short-name \"nonexistentxyzq:1\" did not resolve to an alias and no unqualified-search"),
            "{e}"
        );
        // a qualified name is itself
        assert_eq!(
            config.resolve("localhost:5000/x:1").unwrap(),
            ["localhost:5000/x:1"]
        );
    }

    #[test]
    fn test_a_file_names_its_search_registries_and_can_drop_an_alias() {
        let dir = std::env::temp_dir().join(format!("velarx-short-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("registries.conf");
        std::fs::write(
            &file,
            "unqualified-search-registries = []\n[aliases]\nalpine = \"\"\n",
        )
        .unwrap();
        let c = RegistriesConfig::load_with(Some(file.clone().into()));
        let e = c.resolve("alpine").unwrap_err();
        assert!(
            e.contains(&format!("defined in \"{}\"", file.display())),
            "{e}"
        );
        // the other aliases of the table stay
        assert_eq!(c.resolve("busybox").unwrap().len(), 1);
        std::fs::write(
            &file,
            "unqualified-search-registries = [\"quay.io\", \"docker.io\"]\nshort-name-mode = \"disabled\"\n",
        )
        .unwrap();
        let c = RegistriesConfig::load_with(Some(file.clone().into()));
        assert_eq!(
            c.resolve("zzz").unwrap(),
            ["quay.io/zzz", "docker.io/library/zzz"]
        );
        // an alias still wins over the list
        assert_eq!(c.resolve("alpine").unwrap(), ["docker.io/library/alpine"]);
        // and an alias of a file wins over the table's
        std::fs::write(&file, "[aliases]\nalpine = \"quay.io/x/alpine\"\n").unwrap();
        let c = RegistriesConfig::load_with(Some(file.into()));
        assert_eq!(c.resolve("alpine:3").unwrap(), ["quay.io/x/alpine:3"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_parse_registries_conf() {
        let toml = r#"
unqualified-search-registries = ["docker.io", "quay.io"]

[[registry]]
prefix = "docker.io"
insecure = false
blocked = false

[[registry.mirror]]
location = "mirror.gcr.io"
insecure = false

[[registry]]
prefix = "localhost:5000"
insecure = true
"#;

        let config = RegistriesConfig::parse(toml).unwrap();

        assert_eq!(config.search_registries.len(), 2);
        assert_eq!(config.registry.len(), 2);

        let docker = config.find_registry("docker.io/library/alpine").unwrap();
        assert!(!docker.insecure);
        assert!(!docker.blocked);
        assert_eq!(docker.mirror.len(), 1);
        assert_eq!(docker.mirror[0].location, "mirror.gcr.io");

        let localhost = config.find_registry("localhost:5000/myimage").unwrap();
        assert!(localhost.insecure);
    }

    fn config(toml: &str) -> RegistriesConfig {
        RegistriesConfig::parse(toml).unwrap()
    }

    #[test]
    fn test_candidates_of_a_short_name() {
        let c = config(r#"unqualified-search-registries = ["quay.io", "docker.io"]"#);
        assert_eq!(
            c.candidates("alpine"),
            ["quay.io/alpine", "docker.io/library/alpine"]
        );
        assert_eq!(
            c.candidates("prom/prometheus:v2"),
            ["quay.io/prom/prometheus:v2", "docker.io/prom/prometheus:v2"]
        );
        let d = format!("sha256:{}", "ab".repeat(32));
        assert_eq!(
            c.candidates(&format!("alpine@{d}")),
            [
                format!("quay.io/alpine@{d}"),
                format!("docker.io/library/alpine@{d}")
            ]
        );
        // Without search registries a name that is no alias has no candidate.
        assert!(config("").candidates("alpine").is_empty());
    }

    #[test]
    fn test_qualified_names_are_not_searched() {
        let c = config(r#"unqualified-search-registries = ["quay.io"]"#);
        let digested = format!("registry.example.com/img@sha256:{}", "ab".repeat(32));
        for name in [
            "quay.io/myuser/myrepo",
            "localhost/img:1",
            "localhost:5000/img",
            "127.0.0.1:5000/a/b:t",
            &digested,
        ] {
            assert_eq!(c.candidates(name), [name]);
        }
    }

    #[test]
    fn test_aliases_win_and_keep_the_tag() {
        let c = config(
            r#"
unqualified-search-registries = ["docker.io"]
[aliases]
"fedora" = "registry.fedoraproject.org/fedora"
"my/app" = "localhost:5000/team/app"
"#,
        );
        assert_eq!(
            c.candidates("fedora:43"),
            ["registry.fedoraproject.org/fedora:43"]
        );
        assert_eq!(
            c.candidates("fedora"),
            ["registry.fedoraproject.org/fedora"]
        );
        assert_eq!(c.candidates("my/app:2"), ["localhost:5000/team/app:2"]);
        assert_eq!(c.candidates("other"), ["docker.io/library/other"]);
    }

    #[test]
    fn test_enforcing_mode_refuses_ambiguous_names() {
        let c = config(
            r#"
short-name-mode = "enforcing"
unqualified-search-registries = ["quay.io", "docker.io"]
[aliases]
"known" = "quay.io/known"
"#,
        );
        assert!(c.resolve("ambiguous").is_err());
        assert_eq!(c.resolve("known").unwrap(), ["quay.io/known"]);
        assert_eq!(c.resolve("quay.io/x").unwrap(), ["quay.io/x"]);
        let one = config(
            "short-name-mode = \"enforcing\"\nunqualified-search-registries = [\"quay.io\"]",
        );
        assert_eq!(one.resolve("x").unwrap(), ["quay.io/x"]);
    }

    #[test]
    fn test_drop_ins_add_aliases() {
        let c = RegistriesConfig::parse_all(&[
            "[aliases]\na = \"x.io/a\"\nb = \"x.io/b\"\nd = \"x.io/d\"",
            "[aliases]\nb = \"y.io/b\"\nc = \"y.io/c\"\nd = \"\"",
        ])
        .unwrap();
        assert_eq!(c.candidates("a"), ["x.io/a"]);
        assert_eq!(c.candidates("b"), ["y.io/b"]);
        assert_eq!(c.candidates("c"), ["y.io/c"]);
        assert!(!c.aliases.contains_key("d"));
    }

    #[test]
    fn test_mirrors_by_reference_kind() {
        let c = config(
            r#"
[[registry]]
prefix = "docker.io"
pull-from-mirror = "digest-only"
[[registry.mirror]]
location = "mirror.example:5000"
insecure = true
[[registry.mirror]]
location = "tags.example"
pull-from-mirror = "tag-only"
[[registry.mirror]]
location = "any.example"
pull-from-mirror = "all"

[[registry]]
prefix = "*.corp.example"
[[registry.mirror]]
location = "cache.example/corp"
"#,
        );
        let name = "docker.io/library/alpine";
        assert_eq!(
            mirror_names(&c, name, true),
            [
                ("mirror.example:5000/library/alpine".to_string(), true),
                ("any.example/library/alpine".to_string(), false)
            ]
        );
        assert_eq!(
            mirror_names(&c, name, false),
            [
                ("tags.example/library/alpine".to_string(), false),
                ("any.example/library/alpine".to_string(), false)
            ]
        );
        assert_eq!(
            mirror_names(&c, "reg.corp.example/team/img", false),
            [("cache.example/corp/team/img".to_string(), false)]
        );
        assert!(mirror_names(&c, "quay.io/x/y", false).is_empty());
    }

    #[test]
    fn test_invalid_pull_from_mirror_is_refused() {
        assert!(RegistriesConfig::parse(
            "[[registry]]\nprefix = \"a\"\npull-from-mirror = \"sometimes\"\n"
        )
        .is_err());
    }

    #[test]
    fn test_is_blocked() {
        let config = RegistriesConfig {
            search_registries: vec![],
            search_origin: None,
            registry: vec![RegistryConfig {
                prefix: "untrusted.example.com".to_string(),
                location: None,
                insecure: false,
                blocked: true,
                allow_private_addresses: false,
                mirror: vec![],
                pull_from_mirror: "all".to_string(),
                mirror_by_digest_only: false,
            }],
            credential_helpers: vec![],
            short_name_mode: ShortNameMode::Permissive,
            aliases: HashMap::new(),
            error: None,
        };

        assert!(config.is_blocked("untrusted.example.com/image"));
        assert!(!config.is_blocked("docker.io/library/alpine"));
    }

    #[test]
    fn test_prefix_matching() {
        assert!(prefix_matches("localhost:5000", "localhost:5000/img:1"));
        assert!(prefix_matches("localhost:5000", "localhost:5000"));
        assert!(prefix_matches("quay.io/foo", "quay.io/foo/bar"));
        assert!(!prefix_matches("quay.io/foo", "quay.io/foo:tag"));
        assert!(!prefix_matches("quay.io", "quay.io:5000/foo"));
        assert!(!prefix_matches("localhost:5000", "localhost:50001/img"));
        assert!(!prefix_matches("quay.io/foo", "quay.io/foobar"));
        assert!(prefix_matches("*.example.com", "a.example.com/x"));
        assert!(prefix_matches("*.example.com", "a.b.example.com:5000/x"));
        assert!(!prefix_matches("*.example.com", "example.com/x"));
        assert!(!prefix_matches("*.example.com", "badexample.com/x"));
    }

    #[test]
    fn test_prefix_defaults_to_location() {
        let config = RegistriesConfig::parse(
            "[[registry]]\nlocation = \"localhost:5000\"\ninsecure = true\n",
        )
        .unwrap();
        assert!(config.is_insecure("localhost:5000/x"));
        assert!(!config.is_insecure("localhost:50001/x"));
        assert!(RegistriesConfig::parse("[[registry]]\ninsecure = true\n").is_err());
    }

    #[test]
    fn test_rewrite_to_location() {
        let config = RegistriesConfig::parse(
            "[[registry]]\nprefix = \"example.com/ns\"\nlocation = \"mirror.local:5000/other\"\n",
        )
        .unwrap();
        let ask = velarx_endpoint_core::Ask {
            has_digest: false,
            push: true,
            tls_verify: true,
        };
        let got =
            velarx_endpoint_core::endpoints(&config.blocks(), b"example.com", b"ns/img", &ask)
                .ok()
                .unwrap();
        assert_eq!(
            (text(&got[0].host), text(&got[0].path)),
            ("mirror.local:5000".to_string(), "other/img".to_string())
        );
    }

    #[test]
    fn test_is_insecure() {
        let config = RegistriesConfig {
            search_registries: vec![],
            search_origin: None,
            registry: vec![RegistryConfig {
                prefix: "localhost:5000".to_string(),
                location: None,
                insecure: true,
                blocked: false,
                allow_private_addresses: false,
                mirror: vec![],
                pull_from_mirror: "all".to_string(),
                mirror_by_digest_only: false,
            }],
            credential_helpers: vec![],
            short_name_mode: ShortNameMode::Permissive,
            aliases: HashMap::new(),
            error: None,
        };

        assert!(config.is_insecure("localhost:5000/myimage"));
        assert!(!config.is_insecure("docker.io/library/alpine"));
    }

    #[test]
    fn test_get_mirrors() {
        let config = RegistriesConfig {
            search_registries: vec![],
            search_origin: None,
            registry: vec![RegistryConfig {
                prefix: "docker.io".to_string(),
                location: None,
                insecure: false,
                blocked: false,
                allow_private_addresses: false,
                mirror: vec![
                    MirrorConfig {
                        location: "mirror1.example.com".to_string(),
                        insecure: false,
                        pull_from_mirror: None,
                    },
                    MirrorConfig {
                        location: "mirror2.example.com".to_string(),
                        insecure: true,
                        pull_from_mirror: None,
                    },
                ],
                pull_from_mirror: "all".to_string(),
                mirror_by_digest_only: false,
            }],
            credential_helpers: vec![],
            short_name_mode: ShortNameMode::Permissive,
            aliases: HashMap::new(),
            error: None,
        };

        let mirrors = config.get_mirrors("docker.io/library/alpine");
        assert_eq!(mirrors.len(), 2);
        assert_eq!(mirrors[0].location, "mirror1.example.com");
        assert_eq!(mirrors[1].location, "mirror2.example.com");
    }

    #[test]
    fn test_find_longest_prefix() {
        let config = RegistriesConfig {
            search_registries: vec![],
            search_origin: None,
            registry: vec![
                RegistryConfig {
                    prefix: "docker.io".to_string(),
                    location: None,
                    insecure: false,
                    blocked: false,
                    allow_private_addresses: false,
                    mirror: vec![],
                    pull_from_mirror: "all".to_string(),
                    mirror_by_digest_only: false,
                },
                RegistryConfig {
                    prefix: "docker.io/library".to_string(),
                    location: Some("mirror.example.com/library".to_string()),
                    insecure: false,
                    blocked: false,
                    allow_private_addresses: false,
                    mirror: vec![],
                    pull_from_mirror: "all".to_string(),
                    mirror_by_digest_only: false,
                },
            ],
            credential_helpers: vec![],
            short_name_mode: ShortNameMode::Permissive,
            aliases: HashMap::new(),
            error: None,
        };

        // Should match the more specific prefix
        let reg = config.find_registry("docker.io/library/alpine").unwrap();
        assert_eq!(reg.prefix, "docker.io/library");
        assert_eq!(reg.effective_location(), "mirror.example.com/library");

        // Should match less specific for non-library
        let reg = config.find_registry("docker.io/myuser/myrepo").unwrap();
        assert_eq!(reg.prefix, "docker.io");
    }

    #[test]
    fn test_merge_configs() {
        let c = RegistriesConfig::parse_all(&[
            r#"
unqualified-search-registries = ["docker.io"]
[[registry]]
prefix = "docker.io"
[[registry]]
prefix = "quay.io"
blocked = true
"#,
            r#"
unqualified-search-registries = ["quay.io", "docker.io"]
short-name-mode = "enforcing"
[[registry]]
prefix = "localhost:5000"
insecure = true
[[registry]]
prefix = "docker.io"
location = "mirror.example"
"#,
            "credential-helpers = [\"pass\"]",
        ])
        .unwrap();
        assert_eq!(c.search_registries, vec!["quay.io", "docker.io"]);
        assert_eq!(c.short_name_mode, ShortNameMode::Enforcing);
        // a block replaces the one of its prefix where it was
        let prefixes: Vec<_> = c.registry.iter().map(|r| r.prefix.as_str()).collect();
        assert_eq!(prefixes, ["docker.io", "quay.io", "localhost:5000"]);
        assert_eq!(c.registry[0].location.as_deref(), Some("mirror.example"));
        assert!(c.registry[1].blocked);
        assert_eq!(c.credential_helpers, ["pass"]);
        // a later file that does not set the mode keeps it
        let c = RegistriesConfig::parse_all(&[
            "short-name-mode = \"enforcing\"",
            "[aliases]\na = \"x.io/a\"",
        ])
        .unwrap();
        assert_eq!(c.short_name_mode, ShortNameMode::Enforcing);
    }

    #[test]
    fn test_v1_format() {
        let c = RegistriesConfig::parse(
            r#"
[registries.search]
registries = ["quay.io"]
[registries.insecure]
registries = ["localhost:5000"]
[registries.block]
registries = ["evil.example"]
"#,
        )
        .unwrap();
        assert_eq!(c.search_registries, ["quay.io"]);
        assert!(c.is_insecure("localhost:5000/x"));
        assert!(c.is_blocked("evil.example/x"));
        assert!(!c.is_blocked("quay.io/x"));
        assert!(RegistriesConfig::parse(
            "[registries.block]\nregistries = [\"a.io\"]\n[[registry]]\nprefix = \"b.io\""
        )
        .is_err());
    }

    #[test]
    fn test_locations_are_normalized() {
        let c = RegistriesConfig::parse("[[registry]]\nprefix = \"a.io/x/\"\nlocation = \"b.io/y/\"\n[[registry.mirror]]\nlocation = \"m.io/\"").unwrap();
        assert_eq!(c.registry[0].prefix, "a.io/x");
        assert_eq!(c.registry[0].location.as_deref(), Some("b.io/y"));
        assert_eq!(c.registry[0].mirror[0].location, "m.io");
        for bad in [
            "[[registry]]\nlocation = \"https://a.io\"",
            "[[registry]]\nprefix = \"http://a.io\"",
            "[[registry]]\nprefix = \"a.io\"\n[[registry.mirror]]\nlocation = \"https://m.io\"",
            "[[registry]]\nprefix = \"*.a.io\"\nlocation = \"b.io\"",
            "[[registry]]\nprefix = \"*a.io\"",
            "[[registry]]\nprefix = \"/\"",
            "[[registry]]\nprefix = \"[0::1]:5000\"",
            "unqualified-search-registries = [\"a.io/x\"]",
            "short-name-mode = \"loose\"",
            "[aliases]\n\"a.io/x\" = \"b.io/x\"",
            "[aliases]\nx = \"short\"",
            "[aliases]\nx = \"b.io/x@sha256:00\"",
            "not toml [",
        ] {
            assert!(RegistriesConfig::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_capital_in_a_host_of_the_file_says_to_write_it_in_lower_case() {
        let e = RegistriesConfig::parse("[[registry]]\nprefix = \"Quay.io\"").unwrap_err();
        assert!(e.contains("lower case"), "{e}");
        let e =
            RegistriesConfig::parse("unqualified-search-registries = [\"Quay.io\"]").unwrap_err();
        assert!(e.contains("lower case"), "{e}");
    }

    #[test]
    fn where_a_wildcard_prefix_is_wrong_is_said() {
        let e = RegistriesConfig::parse("[[registry]]\nprefix = \"*.Quay.io\"").unwrap_err();
        assert!(
            e.contains("lower case, at byte 0") && e.contains("after `*.`"),
            "{e}"
        );
    }

    #[test]
    fn a_prefix_of_index_docker_io_is_one_of_docker_io() {
        let c = RegistriesConfig::parse(
            "[[registry]]\nprefix = \"index.docker.io/a\"\nblocked = true\n\
             [[registry]]\nprefix = \"index.docker.io.example/a\"\ninsecure = true",
        )
        .unwrap();
        assert_eq!(c.registry[0].prefix, "docker.io/a");
        assert_eq!(c.registry[1].prefix, "index.docker.io.example/a");
        assert!(c.is_blocked("docker.io/a/b"));
    }

    #[test]
    fn two_blocks_of_one_registry_are_refused() {
        let e = RegistriesConfig::parse(
            "[[registry]]\nprefix = \"docker.io\"\n[[registry]]\nprefix = \"index.docker.io\"",
        )
        .unwrap_err();
        assert!(e.contains("`docker.io` and `index.docker.io`"), "{e}");
        // a block that has only a location keeps the prefix that the
        // location is, as written: it is not read as docker.io
        let c = RegistriesConfig::parse(
            "[[registry]]\nlocation = \"index.docker.io\"\n[[registry]]\nprefix = \"docker.io\"",
        )
        .unwrap();
        assert_eq!(c.registry[0].prefix, "index.docker.io");
        assert_eq!(c.registry[1].prefix, "docker.io");
    }

    #[test]
    fn test_mirror_by_digest_only() {
        let c = RegistriesConfig::parse(
            "[[registry]]\nprefix = \"docker.io\"\nmirror-by-digest-only = true\n[[registry.mirror]]\nlocation = \"m.io\"",
        )
        .unwrap();
        assert!(mirror_names(&c, "docker.io/library/a", false).is_empty());
        assert_eq!(mirror_names(&c, "docker.io/library/a", true).len(), 1);
        assert!(RegistriesConfig::parse(
            "[[registry]]\nprefix = \"docker.io\"\nmirror-by-digest-only = true\n[[registry.mirror]]\nlocation = \"m.io\"\npull-from-mirror = \"tag-only\""
        )
        .is_err());
    }

    #[test]
    fn test_a_broken_configuration_refuses_everything() {
        let c = RegistriesConfig {
            error: Some("broken".into()),
            ..RegistriesConfig::default_config()
        };
        assert!(c.resolve("alpine").is_err());
        assert!(c.check().is_err());
    }

    #[test]
    fn test_load_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        let conf = d.path().join("r.conf");
        std::fs::write(
            &conf,
            "[[registry]]\nprefix = \"evil.io\"\nblocked = true\n",
        )
        .unwrap();
        let ok = RegistriesConfig::load_with(Some(conf.clone().into()));
        assert!(ok.error.is_none());
        assert!(ok.is_blocked("evil.io/x"));
        std::fs::write(&conf, "[[registry]]\nprefix = \"evil.io\"\nblocked = tru\n").unwrap();
        assert!(RegistriesConfig::load_with(Some(conf.into()))
            .error
            .is_some());
        assert!(
            RegistriesConfig::load_with(Some(d.path().join("missing").into()))
                .error
                .is_some()
        );
    }

    #[test]
    fn test_drop_in_order() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        std::fs::write(a.path().join("10-x.conf"), "").unwrap();
        std::fs::write(a.path().join("20-y.conf"), "").unwrap();
        std::fs::write(a.path().join("ignored.txt"), "").unwrap();
        std::fs::write(b.path().join("10-x.conf"), "").unwrap();
        std::fs::write(b.path().join("05-z.conf"), "").unwrap();
        let got = drop_ins(&[a.path().to_path_buf(), b.path().to_path_buf()]);
        assert_eq!(
            got,
            [
                b.path().join("05-z.conf"),
                b.path().join("10-x.conf"),
                a.path().join("20-y.conf")
            ]
        );
    }

    const D: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const D1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn short(s: &str) -> String {
        if s.len() > 40 {
            format!("<{} bytes>", s.len())
        } else {
            format!("{s:?}")
        }
    }

    /// What `candidates` makes of `input` with one search registry and the
    /// alias `x`, and which block of a configuration with the prefixes
    /// `docker.io`, `quay.io`, `localhost` and `x:5000` applies to each
    /// candidate (`none`: no block).
    fn shown(input: &str) -> String {
        let config = RegistriesConfig::parse(
            r#"
unqualified-search-registries = ["example.org"]
[aliases]
alpine = "docker.io/library/alpine"
[[registry]]
prefix = "docker.io"
[[registry]]
prefix = "quay.io"
[[registry]]
prefix = "localhost"
[[registry]]
prefix = "x:5000"
"#,
        )
        .unwrap();
        let found = config
            .candidates(input)
            .iter()
            .map(|c| {
                let block = config
                    .find_registry(c)
                    .map_or("none", |r| r.prefix.as_str());
                format!("{} block {block}", short(c))
            })
            .collect::<Vec<_>>()
            .join(", ");
        if found.is_empty() {
            "no candidate".to_string()
        } else {
            found
        }
    }

    /// What the real code answers for the inputs of the table of the design of
    /// image references: what `candidates` makes of each with one search
    /// registry and the alias `alpine` (a name is qualified, an alias, or a short
    /// name of the search registry), and which `[[registry]]` block of
    /// registries.conf applies to each candidate, by the prefix match of
    /// `find_registry`.
    #[test]
    fn candidates_on_the_reference_table() {
        let table: Vec<(String, &str)> = vec![
            ("x".to_string(), "\"example.org/x\" block none"),
            ("x:tag".to_string(), "\"example.org/x:tag\" block none"),
            ("x:5000".to_string(), "\"example.org/x:5000\" block none"),
            ("x:5000/y".to_string(), "\"x:5000/y\" block x:5000"),
            ("localhost/x".to_string(), "\"localhost/x\" block localhost"),
            (
                "docker.io/alpine".to_string(),
                "\"docker.io/library/alpine\" block docker.io",
            ),
            (
                "index.docker.io/a/b".to_string(),
                "\"docker.io/a/b\" block docker.io",
            ),
            (
                "docker.io/a.b/c".to_string(),
                "\"docker.io/a.b/c\" block docker.io",
            ),
            ("Quay.IO/a/b".to_string(), "no candidate"),
            ("Foo/bar".to_string(), "no candidate"),
            ("quay.io/a..b".to_string(), "no candidate"),
            ("quay.io/a--_b".to_string(), "no candidate"),
            ("quay.io/a___b".to_string(), "no candidate"),
            (":5000/x".to_string(), "no candidate"),
            ("a.b:abc/x".to_string(), "no candidate"),
            ("a..b/x".to_string(), "no candidate"),
            ("a.-b/x".to_string(), "no candidate"),
            ("[::1]:5000/a".to_string(), "\"[::1]:5000/a\" block none"),
            ("quay.io//a".to_string(), "no candidate"),
            ("a/".to_string(), "no candidate"),
            ("/a".to_string(), "no candidate"),
            ("a:".to_string(), "no candidate"),
            ("a:.x".to_string(), "no candidate"),
            ("../x".to_string(), "no candidate"),
            ("%2f".to_string(), "no candidate"),
            ("?".to_string(), "no candidate"),
            ("#".to_string(), "no candidate"),
            ("quay.io/a b".to_string(), "no candidate"),
            ("quay.io/a\0b".to_string(), "no candidate"),
            ("quay.io/caf\u{e9}".to_string(), "no candidate"),
            (format!("quay.io/a:{}", "t".repeat(129)), "no candidate"),
            (format!("quay.io/a:t@{D}"), "<83 bytes> block quay.io"),
            (format!("quay.io/a:b c@{D}"), "no candidate"),
            (format!("x@y@{D}"), "no candidate"),
            (format!("a@{D1}@{D}"), "no candidate"),
            (format!("h.io@evil.com/a@{D}"), "no candidate"),
            (" alpine\n".to_string(), "no candidate"),
            ("a".repeat(258), "no candidate"),
            ("a".repeat(255), "no candidate"),
            (format!("quay.io/{}", "a".repeat(255)), "no candidate"),
            (format!("{}.io/x", "a".repeat(252)), "no candidate"),
            ("0123456789abcdef".repeat(4), "no candidate"),
            (
                format!("a@sha384:{}", "ab".repeat(48)),
                "<117 bytes> block none",
            ),
            (format!("a@foo:{}", "z".repeat(32)), "no candidate"),
            (format!("a@sha256:{}", "A".repeat(64)), "no candidate"),
            ("a@sha256:abc".to_string(), "no candidate"),
            ("alpine@".to_string(), "no candidate"),
            (
                format!("quay.io/a:v1@sha512:{}", "ab".repeat(64)),
                "<148 bytes> block quay.io",
            ),
        ];
        for (input, expected) in &table {
            assert_eq!(shown(input), *expected, "{input:?}");
        }
    }
}
