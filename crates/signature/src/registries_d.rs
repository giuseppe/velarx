// SPDX-License-Identifier: Apache-2.0
//! registries.d: where the signatures of the images of a registry
//! are, as containers/image reads it: the lookaside storage (`lookaside`,
//! formerly `sigstore`, and their `-staging` variants for writing) and
//! whether to look for sigstore attachments, for a namespace (`docker:`)
//! or by default (`default-docker:`).
//!
//! The YAML files of the drop-in directories are read in the order of
//! their names; a file of a directory of higher priority hides the file of
//! the same name of the others.  A namespace defined twice is an error.

use super::reference::DockerRef;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// Largest registries.d file read.
const MAX_FILE: u64 = 1 << 20;
/// Most signatures read from lookaside storage for an image.
pub const MAX_LOOKASIDE_SIGNATURES: usize = 128;

/// The configuration of a namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Namespace {
    pub lookaside: Option<String>,
    pub lookaside_staging: Option<String>,
    pub sigstore: Option<String>,
    pub sigstore_staging: Option<String>,
    pub use_sigstore_attachments: Option<bool>,
}

impl Namespace {
    /// The lookaside storage for reading, or for writing.
    fn top_level(&self, write: bool) -> Option<&str> {
        let staging = if write {
            self.lookaside_staging
                .as_deref()
                .or(self.sigstore_staging.as_deref())
        } else {
            None
        };
        staging
            .or(self.lookaside.as_deref())
            .or(self.sigstore.as_deref())
            .filter(|s| !s.is_empty())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistriesD {
    pub default_docker: Option<Namespace>,
    pub docker: HashMap<String, Namespace>,
}

/// The drop-in directories, highest priority first: the user's (rootless
/// only), then those of /etc and of /usr/share, each with its
/// `registries.rootless.d/UID`, `registries.rootless.d` (or
/// `registries.rootful.d`) and `registries.d`.
pub fn default_dirs() -> Result<Vec<PathBuf>, velarx_base::ids::IdsError> {
    let uid = rustix::process::geteuid().as_raw();
    let rootless = velarx_base::conf::rootless()?;
    let mut dirs = Vec::new();
    if rootless {
        if let Some(d) = velarx_base::conf::user_config_dir()? {
            dirs.push(d.join("velarx/registries.d"));
        }
    }
    for base in ["/etc/velarx", "/usr/share/velarx"] {
        if rootless {
            dirs.push(PathBuf::from(format!("{base}/registries.rootless.d/{uid}")));
            dirs.push(PathBuf::from(format!("{base}/registries.rootless.d")));
        } else {
            dirs.push(PathBuf::from(format!("{base}/registries.rootful.d")));
        }
        dirs.push(PathBuf::from(format!("{base}/registries.d")));
    }
    Ok(dirs)
}

fn yaml_string(v: &yaml_rust2::Yaml, what: &str) -> Result<Option<String>, String> {
    use yaml_rust2::Yaml;
    match v {
        Yaml::BadValue | Yaml::Null => Ok(None),
        Yaml::String(s) => Ok(Some(s.clone())),
        _ => Err(format!("{what} is not a string")),
    }
}

/// The keys of a namespace of containers/image's registries.d (all are read).
const NAMESPACE_KEYS: [&str; 5] = [
    "lookaside",
    "lookaside-staging",
    "sigstore",
    "sigstore-staging",
    "use-sigstore-attachments",
];

fn namespace(v: &yaml_rust2::Yaml, what: &str) -> Result<Namespace, String> {
    use yaml_rust2::Yaml;
    let Yaml::Hash(h) = v else {
        return match v {
            Yaml::Null => Ok(Namespace::default()),
            _ => Err(format!("{what} is not a mapping")),
        };
    };
    let mut ns = Namespace::default();
    for (k, v) in h {
        let Some(k) = k.as_str() else {
            return Err(format!("{what} has a key that is not a string"));
        };
        match k {
            "lookaside" => ns.lookaside = yaml_string(v, k)?,
            "lookaside-staging" => ns.lookaside_staging = yaml_string(v, k)?,
            "sigstore" => ns.sigstore = yaml_string(v, k)?,
            "sigstore-staging" => ns.sigstore_staging = yaml_string(v, k)?,
            "use-sigstore-attachments" => {
                ns.use_sigstore_attachments = match v {
                    Yaml::Boolean(b) => Some(*b),
                    Yaml::Null => None,
                    _ => return Err(format!("{what}: use-sigstore-attachments is not a boolean")),
                }
            }
            other => {
                return Err(format!(
                    "{what}: unknown key `{other}`{}",
                    velarx_base::conf::did_you_mean(other, NAMESPACE_KEYS)
                ))
            }
        }
    }
    Ok(ns)
}

impl RegistriesD {
    /// The configuration of the default directories.
    pub fn load() -> Result<Self, String> {
        Self::load_dirs(&default_dirs().map_err(|e| e.to_string())?)
    }

    /// The configuration of `dirs`, highest priority first.
    pub fn load_dirs(dirs: &[PathBuf]) -> Result<Self, String> {
        let mut files: BTreeMap<String, PathBuf> = BTreeMap::new();
        for dir in dirs.iter().rev() {
            let entries = match std::fs::read_dir(dir) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("{}: {e}", dir.display())),
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let is_file = entry.file_type().map(|t| !t.is_dir()).unwrap_or(false);
                if is_file && name.ends_with(".yaml") {
                    files.insert(name, entry.path());
                }
            }
        }
        let mut config = RegistriesD::default();
        for path in files.values() {
            let content = velarx_base::conf::read_config_file(path, MAX_FILE)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            config
                .add(&path.display().to_string(), &content)
                .map_err(|e| format!("parsing {}: {e}", path.display()))?;
        }
        Ok(config)
    }

    /// Add the configuration of the file `name`.
    pub fn add(&mut self, name: &str, content: &str) -> Result<(), String> {
        use yaml_rust2::Yaml;
        let docs = yaml_rust2::YamlLoader::load_from_str(content).map_err(|e| e.to_string())?;
        let Some(doc) = docs.first() else {
            return Ok(());
        };
        let Yaml::Hash(top) = doc else {
            return match doc {
                Yaml::Null => Ok(()),
                _ => Err("not a mapping".into()),
            };
        };
        for (k, v) in top {
            match k.as_str() {
                Some("default-docker") => {
                    if matches!(v, Yaml::Null) {
                        continue;
                    }
                    if self.default_docker.is_some() {
                        return Err(format!(
                            "\"default-docker\" defined twice (again in {name})"
                        ));
                    }
                    self.default_docker = Some(namespace(v, "default-docker")?);
                }
                Some("docker") => {
                    let Yaml::Hash(namespaces) = v else {
                        if matches!(v, Yaml::Null) {
                            continue;
                        }
                        return Err("\"docker\" is not a mapping".into());
                    };
                    for (scope, ns) in namespaces {
                        let Some(scope) = scope.as_str() else {
                            return Err("a namespace that is not a string".into());
                        };
                        if self.docker.contains_key(scope) {
                            return Err(format!(
                                "\"docker\" namespace {scope:?} defined twice (again in {name})"
                            ));
                        }
                        self.docker.insert(scope.to_string(), namespace(ns, scope)?);
                    }
                }
                Some(other) => {
                    return Err(format!(
                        "unknown key `{other}`{}",
                        velarx_base::conf::did_you_mean(other, ["default-docker", "docker"])
                    ))
                }
                None => return Err("a key that is not a string".into()),
            }
        }
        Ok(())
    }

    /// The namespaces of `r`, most specific first: the reference itself,
    /// the repository, its parents up to the host, the `*.domain`
    /// wildcards of the host (as the scopes of policy.json).
    fn scopes(r: &DockerRef) -> Vec<String> {
        let mut out = Vec::new();
        if !r.name_only() {
            out.push(r.string());
        }
        let name = r.name();
        let mut n = name.as_str();
        loop {
            out.push(n.to_string());
            match n.rsplit_once('/') {
                Some((parent, _)) => n = parent,
                None => break,
            }
        }
        if !r.domain.contains(':') {
            out.extend(
                r.domain
                    .match_indices('.')
                    .map(|(i, _)| format!("*{}", &r.domain[i..])),
            );
        }
        out
    }

    /// The lookaside storage of `r` configured, if any.
    pub fn lookaside(&self, r: &DockerRef, write: bool) -> Option<String> {
        for scope in Self::scopes(r) {
            if let Some(top) = self.docker.get(&scope).and_then(|ns| ns.top_level(write)) {
                return Some(top.to_string());
            }
        }
        self.default_docker
            .as_ref()
            .and_then(|ns| ns.top_level(write))
            .map(String::from)
    }

    /// The URL of the lookaside storage of the repository of `r`: the one
    /// configured, or the built-in default (a directory of the store's).
    pub fn lookaside_base(&self, r: &DockerRef, write: bool) -> Result<String, String> {
        let top = match self.lookaside(r, write) {
            Some(t) => t,
            None => format!("file://{}", default_lookaside_dir()?.display()),
        };
        if !(top.starts_with("file://")
            || top.starts_with("http://")
            || top.starts_with("https://"))
        {
            return Err(format!(
                "unsupported scheme of the signature storage {top:?}"
            ));
        }
        // the path of the repository, without its host: components that
        // cannot be `.` or `..` (DockerRef checks them)
        Ok(format!("{}/{}", top.trim_end_matches('/'), r.path))
    }

    /// Whether to look for sigstore attachments of `r`.
    pub fn use_sigstore_attachments(&self, r: &DockerRef) -> bool {
        for scope in Self::scopes(r) {
            if let Some(b) = self
                .docker
                .get(&scope)
                .and_then(|ns| ns.use_sigstore_attachments)
            {
                return b;
            }
        }
        self.default_docker
            .as_ref()
            .and_then(|ns| ns.use_sigstore_attachments)
            .unwrap_or(false)
    }
}

/// Where signatures are kept without configuration: as containers/image,
/// /var/lib/containers/sigstore for root, `$XDG_DATA_HOME/containers/sigstore`
/// (~/.local/share/containers/sigstore) for a rootless user, who has no such
/// place without a home.
pub fn default_lookaside_dir() -> Result<PathBuf, String> {
    let var = |name: &str| std::env::var_os(name).map(PathBuf::from);
    lookaside_dir_of(
        velarx_base::ids::rootful().map_err(|e| e.to_string())?,
        var("XDG_DATA_HOME"),
        var("HOME"),
    )
}

fn lookaside_dir_of(
    rootful: bool,
    xdg_data_home: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Result<PathBuf, String> {
    if rootful {
        return Ok(PathBuf::from("/var/lib/containers/sigstore"));
    }
    xdg_data_home
        .filter(|p| p.is_absolute())
        .or_else(|| {
            home.filter(|p| p.is_absolute())
                .map(|h| h.join(".local/share"))
        })
        .map(|d| d.join("containers/sigstore"))
        .ok_or_else(|| {
            "no place for the signatures: neither XDG_DATA_HOME nor HOME is set \
             (a lookaside in registries.d names one)"
                .to_string()
        })
}

/// The URL of the signature `index` (from 0) of the manifest `digest` in
/// the lookaside storage `base` (a `lookaside_base`).
pub fn lookaside_url(base: &str, digest: &str, index: usize) -> Result<String, String> {
    let (algo, hex) = digest
        .split_once(':')
        .filter(|(a, h)| {
            !a.is_empty()
                && !h.is_empty()
                && a.bytes()
                    .chain(h.bytes())
                    .all(|b| b.is_ascii_alphanumeric())
        })
        .ok_or_else(|| format!("invalid digest {digest:?}"))?;
    Ok(format!("{base}@{algo}={hex}/signature-{}", index + 1))
}

/// Write `blob` as the first `signature-N` of the manifest `digest` that is
/// not in the storage `base` (a `file:` URL of the repository).
pub fn write_lookaside(base: &str, digest: &str, blob: &[u8]) -> Result<(), String> {
    use std::io::Write;
    for i in 0..MAX_LOOKASIDE_SIGNATURES {
        let url = lookaside_url(base, digest, i)?;
        let path =
            file_path(&url).ok_or_else(|| format!("{url} is not a file: signature storage"))?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut f) => {
                return f
                    .write_all(blob)
                    .map_err(|e| format!("{}: {e}", path.display()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    Err(format!(
        "the signature storage already has {MAX_LOOKASIDE_SIGNATURES} signatures of {digest}"
    ))
}

/// The path of a `file://` URL.
pub fn file_path(url: &str) -> Option<&Path> {
    url.strip_prefix("file://").map(Path::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_written_to_the_next_free_file() {
        let dir = tempfile::tempdir().unwrap();
        let base = format!("file://{}/org/app", dir.path().display());
        write_lookaside(&base, "sha256:ab", b"one").unwrap();
        write_lookaside(&base, "sha256:ab", b"two").unwrap();
        let file = |n| dir.path().join(format!("org/app@sha256=ab/signature-{n}"));
        assert_eq!(std::fs::read(file(1)).unwrap(), b"one");
        assert_eq!(std::fs::read(file(2)).unwrap(), b"two");
        assert!(write_lookaside("https://x/y", "sha256:ab", b"").is_err());
    }

    fn r(s: &str) -> DockerRef {
        DockerRef::parse_normalized(s).unwrap()
    }

    #[test]
    fn the_default_lookaside_needs_a_home_and_is_not_the_root_directory() {
        let p = |s: &str| Some(PathBuf::from(s));
        assert_eq!(
            lookaside_dir_of(true, None, None).unwrap(),
            Path::new("/var/lib/containers/sigstore")
        );
        assert_eq!(
            lookaside_dir_of(false, None, p("/home/u")).unwrap(),
            Path::new("/home/u/.local/share/containers/sigstore")
        );
        assert_eq!(
            lookaside_dir_of(false, p("/data"), p("/home/u")).unwrap(),
            Path::new("/data/containers/sigstore")
        );
        for (xdg, home) in [(None, None), (p("data"), p("home"))] {
            assert!(lookaside_dir_of(false, xdg, home).is_err());
        }
    }

    #[test]
    fn namespaces_choose_the_most_specific() {
        let mut c = RegistriesD::default();
        c.add(
            "a.yaml",
            r#"
default-docker:
  lookaside: file:///var/lib/containers/sigstore
docker:
  registry.access.redhat.com:
    lookaside: https://access.redhat.com/webassets/docker/content/sigstore
  quay.io/team:
    sigstore: https://sigs.example.com/team
    use-sigstore-attachments: true
  quay.io/team/special:
    lookaside: https://special.example.com
    lookaside-staging: file:///tmp/staging
  "*.example.net":
    lookaside: https://wild.example.net
"#,
        )
        .unwrap();
        assert_eq!(
            c.lookaside_base(&r("registry.access.redhat.com/ubi9:latest"), false)
                .unwrap(),
            "https://access.redhat.com/webassets/docker/content/sigstore/ubi9"
        );
        assert_eq!(
            c.lookaside_base(&r("quay.io/team/app:v1"), false).unwrap(),
            "https://sigs.example.com/team/team/app"
        );
        assert_eq!(
            c.lookaside_base(&r("quay.io/team/special/x:v1"), false)
                .unwrap(),
            "https://special.example.com/team/special/x"
        );
        assert_eq!(
            c.lookaside_base(&r("quay.io/team/special/x:v1"), true)
                .unwrap(),
            "file:///tmp/staging/team/special/x"
        );
        assert_eq!(
            c.lookaside_base(&r("registry.example.net/a"), false)
                .unwrap(),
            "https://wild.example.net/a"
        );
        assert_eq!(
            c.lookaside_base(&r("docker.io/library/busybox"), false)
                .unwrap(),
            "file:///var/lib/containers/sigstore/library/busybox"
        );
        assert!(c.use_sigstore_attachments(&r("quay.io/team/app")));
        assert!(c.use_sigstore_attachments(&r("quay.io/team/special/x")));
        assert!(!c.use_sigstore_attachments(&r("quay.io/other")));
        assert_eq!(
            lookaside_url("https://s/a", "sha256:abcd", 0).unwrap(),
            "https://s/a@sha256=abcd/signature-1"
        );
        assert!(lookaside_url("https://s/a", "sha256:../x", 0).is_err());
    }

    #[test]
    fn files_are_merged_and_checked() {
        let mut c = RegistriesD::default();
        c.add("a.yaml", "docker:\n  quay.io:\n    lookaside: https://a\n")
            .unwrap();
        assert!(c
            .add("b.yaml", "docker:\n  quay.io:\n    lookaside: https://b\n")
            .is_err());
        c.add("c.yaml", "default-docker:\n  lookaside: https://c\n")
            .unwrap();
        assert!(c
            .add("d.yaml", "default-docker:\n  lookaside: https://d\n")
            .is_err());
        for bad in [
            "[1, 2]",
            "docker: 3",
            "docker:\n  quay.io: 3",
            "default-docker:\n  use-sigstore-attachments: maybe",
            "a: [",
            "docker:\n  quay.io:\n    lookaside: [1]",
        ] {
            assert!(RegistriesD::default().add("x.yaml", bad).is_err(), "{bad}");
        }
        // empty files, unknown keys
        RegistriesD::default().add("e.yaml", "").unwrap();
        RegistriesD::default().add("e.yaml", "# nothing\n").unwrap();
        for bad in [
            "other: 1\n",
            "default-docker:\n  lookasid: https://a\n",
            "docker:\n  quay.io:\n    sigstor: https://a\n",
        ] {
            let e = RegistriesD::default().add("e.yaml", bad).unwrap_err();
            assert!(e.contains("unknown key"), "{bad}: {e}");
            assert!(
                e.contains("did you mean") == (bad != "other: 1\n"),
                "{bad}: {e}"
            );
        }
        let mut c = RegistriesD::default();
        c.add("f.yaml", "default-docker:\n  lookaside: ftp://x\n")
            .unwrap();
        assert!(c.lookaside_base(&r("a"), false).is_err());
    }

    #[test]
    fn directories_hide_files_of_the_same_name() {
        let d = tempfile::tempdir().unwrap();
        let (high, low) = (d.path().join("high"), d.path().join("low"));
        std::fs::create_dir_all(&high).unwrap();
        std::fs::create_dir_all(&low).unwrap();
        std::fs::write(
            low.join("default.yaml"),
            "default-docker:\n  lookaside: https://low\n",
        )
        .unwrap();
        std::fs::write(
            high.join("default.yaml"),
            "default-docker:\n  lookaside: https://high\n",
        )
        .unwrap();
        std::fs::write(
            low.join("quay.yaml"),
            "docker:\n  quay.io:\n    use-sigstore-attachments: true\n",
        )
        .unwrap();
        std::fs::write(low.join("ignored.txt"), "not: yaml: at all: [").unwrap();
        let c = RegistriesD::load_dirs(&[high, low, d.path().join("missing")]).unwrap();
        assert_eq!(c.lookaside(&r("a"), false).as_deref(), Some("https://high"));
        assert!(c.use_sigstore_attachments(&r("quay.io/x")));
    }
}
