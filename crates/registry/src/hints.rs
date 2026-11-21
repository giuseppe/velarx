// SPDX-License-Identifier: Apache-2.0
//! What a registry asked for the last time, kept for the next pull.
//!
//! The first request of a pull to a registry goes without `Authorization`,
//! the registry answers 401 with the realm of its token endpoint, the client
//! asks the token endpoint and sends the request again: two round trips
//! before the first byte.  A hint remembers, for a registry, how it
//! authenticates (the scheme, the realm and the service of a bearer token)
//! and the host its blobs were last redirected to (its CDN), so that the next
//! pull asks the token endpoint at once and can connect to the CDN before it
//! is told where to go.
//!
//! A hint is never a secret: no token, no credential, no header the registry
//! sent but the realm and the service.  The file belongs to the user (mode
//! 0600 in a directory of mode 0700), holds a bounded number of registries
//! for a limited time, and anything wrong with it, or with an entry, is
//! ignored: the pull then does what it does without hints.  What a hint says
//! is checked like what a registry says in a 401, and when it does not work
//! the pull asks the registry again ([`super::client`]).

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Registries kept; the least recently seen go first.
pub const MAX_ENTRIES: usize = 256;

/// How long a hint is used after the registry was last seen.
pub const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

/// A hint seen less than this ago is not rewritten when it is seen again.
const REFRESH_AFTER: Duration = Duration::from_secs(24 * 3600);

/// Largest file read.
const MAX_FILE: u64 = 512 * 1024;

const FILE: &str = "registry-hints.json";

/// How a registry wants to be asked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Auth {
    /// Nothing is known (or the registry asks for nothing)
    #[default]
    None,
    Basic,
    Bearer {
        realm: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<String>,
    },
}

/// What is kept for a registry (`host[:port]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hint {
    /// `https` or `http`, as the registry was reached
    pub transport: String,
    #[serde(default)]
    pub auth: Auth,
    /// `host[:port]` the blobs were redirected to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdn: Option<String>,
}

fn clean(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

/// The host and the port of `host[:port]`: a name or an IPv4 address, or an
/// IPv6 address in brackets.
fn host_and_port(authority: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let ipv6 = host.contains(':')
            && host
                .chars()
                .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.'));
        let port = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix(':')?)
        };
        return ipv6.then_some((host, port));
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let name = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    name.then_some((host, port))
}

/// `host[:port]` of a name or an address, nothing more: an allow-list of
/// characters, and a port that is a number.  (The client parses the URL
/// again when it makes a request.)
pub fn valid_authority(authority: &str) -> bool {
    clean(authority, 255)
        && authority
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        && host_and_port(authority)
            .is_some_and(|(_, port)| port.is_none_or(|p| p.len() <= 5 && p.parse::<u16>().is_ok()))
}

impl Hint {
    /// Whether the hint is something a registry could have said.
    pub fn is_sound(&self) -> bool {
        let secure = match self.transport.as_str() {
            "https" => true,
            "http" => false,
            _ => return false,
        };
        let auth = match &self.auth {
            Auth::None | Auth::Basic => true,
            Auth::Bearer { realm, service } => {
                clean(realm, 1024)
                    && service.as_deref().is_none_or(|s| clean(s, 256))
                    && realm
                        .strip_prefix("https://")
                        .or_else(|| realm.strip_prefix("http://").filter(|_| !secure))
                        .is_some_and(|rest| {
                            valid_authority(rest.split(['/', '?', '#']).next().unwrap_or(""))
                        })
            }
        };
        auth && self.cdn.as_deref().is_none_or(valid_authority)
    }
}

/// What a hint changed in the registry of a request: told by the worker
/// that found out to the process that keeps the hints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "note", rename_all = "snake_case")]
pub enum Note {
    /// The registry no longer asks what the hint said
    Forget { registry: String },
    /// The registry asked for `auth`
    Auth {
        registry: String,
        transport: String,
        auth: Auth,
    },
}

/// What the requests of a worker have to tell besides their answer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notices {
    /// For the person who pulls: one line each
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<Note>,
    /// The schemes insecure registries were found to speak: the next
    /// workers do not probe them
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schemes: Vec<(String, crate::target::Scheme)>,
}

impl Notices {
    pub fn is_empty(&self) -> bool {
        self.warnings.is_empty() && self.hints.is_empty() && self.schemes.is_empty()
    }

    pub fn append(&mut self, mut other: Notices) {
        self.warnings.append(&mut other.warnings);
        self.hints.append(&mut other.hints);
        self.schemes.append(&mut other.schemes);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    registry: String,
    #[serde(flatten)]
    hint: Hint,
    /// Seconds since the epoch
    seen: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Content {
    #[serde(default)]
    entries: Vec<Entry>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The hints of the user, in a directory of its own.
pub struct HintStore {
    dir: PathBuf,
    /// The directory is one the user alone can write to (checked before the
    /// first write)
    ready: std::sync::OnceLock<bool>,
}

impl HintStore {
    /// `$XDG_CACHE_HOME/velarx`, `$HOME/.cache/velarx` or, for a
    /// process that has neither, `/var/cache/velarx`.  Root of the
    /// initial user namespace uses `/var/cache/velarx` whatever `HOME`
    /// and `XDG_*` say (they stay set under `sudo`): the host's directories,
    /// as for its store ([`velarx_base::ids::rootful`]).
    pub fn default_dir() -> Result<PathBuf, velarx_base::ids::IdsError> {
        Ok(Self::dir_for(velarx_base::ids::rootful()?, |name| {
            std::env::var_os(name)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        }))
    }

    fn dir_for(rootful: bool, env: impl Fn(&str) -> Option<PathBuf>) -> PathBuf {
        let var = |name: &str| env(name).filter(|p| p.is_absolute());
        if rootful {
            return PathBuf::from("/var/cache/velarx");
        }
        var("XDG_CACHE_HOME")
            .or_else(|| var("HOME").map(|h| h.join(".cache")))
            .unwrap_or_else(|| PathBuf::from("/var/cache"))
            .join("velarx")
    }

    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            ready: std::sync::OnceLock::new(),
        }
    }

    /// The store of the user, if hints are used.
    pub fn for_pull(
        enabled: bool,
    ) -> Result<Option<std::sync::Arc<Self>>, velarx_base::ids::IdsError> {
        if !enabled {
            return Ok(None);
        }
        Ok(Some(std::sync::Arc::new(Self::at(Self::default_dir()?))))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Make the directory if it is not there; false when it is not one the
    /// user alone can write to (a symbolic link, someone else's, open to
    /// others): it is then not used.
    pub fn prepare(&self) -> bool {
        use std::os::unix::fs::DirBuilderExt;
        let _ = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir);
        std::fs::symlink_metadata(&self.dir).is_ok_and(|m| {
            m.is_dir() && m.uid() == rustix::process::geteuid().as_raw() && m.mode() & 0o022 == 0
        })
    }

    fn read(&self) -> Content {
        let read = || -> Option<Content> {
            // The directory is held to what `prepare` asks (not a link, the
            // user's, closed to others) and the file is opened in the
            // directory that was checked.
            use rustix::fs::{openat, Mode, OFlags};
            let dir = rustix::fs::open(
                &self.dir,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .ok()?;
            let dir_meta = rustix::fs::fstat(&dir).ok()?;
            if dir_meta.st_uid != rustix::process::geteuid().as_raw()
                || dir_meta.st_mode & 0o022 != 0
            {
                return None;
            }
            let mut file = File::from(
                openat(
                    &dir,
                    FILE,
                    OFlags::RDONLY
                        | OFlags::NOFOLLOW
                        | OFlags::NONBLOCK
                        | OFlags::CLOEXEC
                        | OFlags::NOCTTY,
                    Mode::empty(),
                )
                .ok()?,
            );
            let meta = file.metadata().ok()?;
            if !meta.is_file()
                || meta.len() > MAX_FILE
                || meta.uid() != rustix::process::geteuid().as_raw()
                || meta.mode() & 0o022 != 0
            {
                return None;
            }
            let mut text = String::new();
            (&mut file).take(MAX_FILE).read_to_string(&mut text).ok()?;
            serde_json::from_str(&text).ok()
        };
        read().unwrap_or_default()
    }

    /// What is kept at `now`: the sound entries that are not too old.
    fn load(&self, now: u64) -> Content {
        let mut content = self.read();
        content.entries.retain(|e| {
            e.seen.saturating_add(MAX_AGE.as_secs()) > now
                && valid_authority(&e.registry)
                && e.hint.is_sound()
        });
        let excess = content.entries.len().saturating_sub(MAX_ENTRIES);
        content.entries.drain(..excess);
        content
    }

    fn save(&self, content: &Content) -> std::io::Result<()> {
        if !*self.ready.get_or_init(|| self.prepare()) {
            return Err(std::io::Error::other("not a private directory"));
        }
        static TEMPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let name = format!(
            ".{FILE}.{}.{}",
            std::process::id(),
            TEMPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let temp = self.dir.join(name);
        let written = (|| -> std::io::Result<()> {
            let mut file: File = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temp)?;
            file.write_all(&serde_json::to_vec(content).map_err(std::io::Error::other)?)?;
            std::fs::rename(&temp, self.dir.join(FILE))
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        written
    }

    /// The hint of `registry`.
    pub fn get(&self, registry: &str) -> Option<Hint> {
        self.get_at(registry, now())
    }

    fn get_at(&self, registry: &str, now: u64) -> Option<Hint> {
        self.load(now)
            .entries
            .into_iter()
            .find(|e| e.registry == registry)
            .map(|e| e.hint)
    }

    /// Change the hint of `registry` (made if there is none, as `new`) with
    /// `change`, which says whether it did.  The file is rewritten when a
    /// hint changed, or is not fresh; a failure is only debugged: hints are
    /// a convenience.
    fn update(&self, registry: &str, now: u64, new: &Hint, change: impl FnOnce(&mut Hint) -> bool) {
        if !valid_authority(registry) {
            return;
        }
        let mut content = self.load(now);
        let at = content.entries.iter().position(|e| e.registry == registry);
        let mut entry = match at {
            Some(at) => content.entries.remove(at),
            None => Entry {
                registry: registry.to_string(),
                hint: new.clone(),
                seen: 0,
            },
        };
        let changed = at.is_none() | change(&mut entry.hint);
        if !entry.hint.is_sound() {
            return;
        }
        let fresh = entry.seen + REFRESH_AFTER.as_secs() > now;
        if !changed && fresh {
            return;
        }
        entry.seen = now;
        content.entries.push(entry);
        let excess = content.entries.len().saturating_sub(MAX_ENTRIES);
        content.entries.drain(..excess);
        if let Err(e) = self.save(&content) {
            tracing::debug!(
                "cannot keep the registry hints in {}: {e}",
                self.dir.display()
            );
        }
    }

    /// `registry` was reached as `transport` and asked for `auth`.
    pub fn learn_auth(&self, registry: &str, transport: &str, auth: Auth) {
        self.learn_auth_at(registry, transport, auth, now());
    }

    fn learn_auth_at(&self, registry: &str, transport: &str, auth: Auth, now: u64) {
        let new = Hint {
            transport: transport.to_string(),
            auth: auth.clone(),
            cdn: None,
        };
        self.update(registry, now, &new, |h| {
            let changed = h.transport != transport || h.auth != auth;
            h.transport = transport.to_string();
            h.auth = auth;
            changed
        });
    }

    /// Blobs of `registry` (reached as `transport`) are served from `cdn`.
    pub fn learn_cdn(&self, registry: &str, transport: &str, cdn: &str) {
        self.learn_cdn_at(registry, transport, cdn, now());
    }

    fn learn_cdn_at(&self, registry: &str, transport: &str, cdn: &str, now: u64) {
        let new = Hint {
            transport: transport.to_string(),
            auth: Auth::None,
            cdn: Some(cdn.to_string()),
        };
        self.update(registry, now, &new, |h| {
            let changed = h.cdn.as_deref() != Some(cdn);
            h.cdn = Some(cdn.to_string());
            changed
        });
    }

    /// Keep what a worker found out, for the registries in `known` only (a
    /// worker is not trusted to name others).
    pub fn apply(&self, notes: &[Note], known: &[&str]) {
        for note in notes {
            match note {
                Note::Forget { registry } if known.contains(&registry.as_str()) => {
                    self.forget_auth(registry)
                }
                Note::Auth {
                    registry,
                    transport,
                    auth,
                } if known.contains(&registry.as_str()) => {
                    self.learn_auth(registry, transport, auth.clone())
                }
                _ => {}
            }
        }
    }

    /// What `registry` asked for does not work any more.
    pub fn forget_auth(&self, registry: &str) {
        self.forget_auth_at(registry, now());
    }

    fn forget_auth_at(&self, registry: &str, now: u64) {
        let mut content = self.load(now);
        let Some(entry) = content.entries.iter_mut().find(|e| e.registry == registry) else {
            return;
        };
        if entry.hint.auth == Auth::None {
            return;
        }
        entry.hint.auth = Auth::None;
        if let Err(e) = self.save(&content) {
            tracing::debug!(
                "cannot keep the registry hints in {}: {e}",
                self.dir.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn bearer(realm: &str) -> Auth {
        Auth::Bearer {
            realm: realm.into(),
            service: Some("registry".into()),
        }
    }

    fn store() -> (tempfile::TempDir, HintStore) {
        let d = tempfile::tempdir().unwrap();
        let s = HintStore::at(d.path().join("velarx"));
        assert!(s.prepare());
        (d, s)
    }

    #[test]
    fn root_keeps_its_hints_in_the_host_cache_directory() {
        let env = |name: &str| match name {
            "XDG_CACHE_HOME" => Some(PathBuf::from("/home/u/.xcache")),
            "HOME" => Some(PathBuf::from("/home/u")),
            _ => None,
        };
        assert_eq!(
            HintStore::dir_for(true, env),
            PathBuf::from("/var/cache/velarx")
        );
        assert_eq!(
            HintStore::dir_for(false, env),
            PathBuf::from("/home/u/.xcache/velarx")
        );
        let home = |name: &str| (name == "HOME").then(|| PathBuf::from("/home/u"));
        assert_eq!(
            HintStore::dir_for(false, home),
            PathBuf::from("/home/u/.cache/velarx")
        );
        assert_eq!(
            HintStore::dir_for(false, |_| Some(PathBuf::from("relative"))),
            PathBuf::from("/var/cache/velarx")
        );
    }

    #[test]
    fn a_hint_is_kept_and_read_back() {
        let (_d, s) = store();
        s.learn_auth_at("quay.io", "https", bearer("https://quay.io/v2/auth"), 1000);
        s.learn_cdn_at("quay.io", "https", "cdn01.quay.io", 1001);
        let h = s.get_at("quay.io", 1002).unwrap();
        assert_eq!(h.auth, bearer("https://quay.io/v2/auth"));
        assert_eq!(h.cdn.as_deref(), Some("cdn01.quay.io"));
        assert_eq!(s.get_at("ghcr.io", 1002), None);
    }

    #[test]
    fn the_file_is_private_and_holds_no_secret() {
        let (_d, s) = store();
        s.learn_auth_at("quay.io", "https", bearer("https://quay.io/v2/auth"), 1000);
        let meta = std::fs::metadata(s.dir().join(FILE)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let dir = std::fs::metadata(s.dir()).unwrap();
        assert_eq!(dir.permissions().mode() & 0o777, 0o700);
        let leftovers = std::fs::read_dir(s.dir()).unwrap().count();
        assert_eq!(leftovers, 1, "the temporary file went away");
    }

    #[test]
    fn hints_expire() {
        let (_d, s) = store();
        s.learn_auth_at("quay.io", "https", bearer("https://quay.io/v2/auth"), 1000);
        let day = 24 * 3600;
        assert!(s.get_at("quay.io", 1000 + 6 * day).is_some());
        assert!(s.get_at("quay.io", 1000 + 7 * day).is_none());
    }

    #[test]
    fn the_least_recently_seen_registry_goes_first() {
        let (_d, s) = store();
        for i in 0..MAX_ENTRIES + 5 {
            s.learn_auth_at(
                &format!("r{i}.example"),
                "https",
                Auth::Basic,
                1000 + i as u64,
            );
        }
        let now = 1000 + MAX_ENTRIES as u64 + 5;
        assert!(s.get_at("r0.example", now).is_none());
        assert!(s.get_at("r4.example", now).is_none());
        assert!(s.get_at("r5.example", now).is_some());
        assert!(s
            .get_at(&format!("r{}.example", MAX_ENTRIES + 4), now)
            .is_some());
        assert_eq!(s.load(now).entries.len(), MAX_ENTRIES);
    }

    #[test]
    fn a_fresh_hint_that_did_not_change_is_not_rewritten() {
        let (_d, s) = store();
        s.learn_auth_at("quay.io", "https", Auth::Basic, 1000);
        let before = std::fs::metadata(s.dir().join(FILE)).unwrap().ino();
        s.learn_auth_at("quay.io", "https", Auth::Basic, 1100);
        assert_eq!(std::fs::metadata(s.dir().join(FILE)).unwrap().ino(), before);
        s.learn_auth_at("quay.io", "https", Auth::Basic, 1000 + 2 * 24 * 3600);
        assert_ne!(std::fs::metadata(s.dir().join(FILE)).unwrap().ino(), before);
    }

    #[test]
    fn a_corrupt_file_is_ignored() {
        let (_d, s) = store();
        for junk in [
            "",
            "{",
            "[1,2]",
            "{\"entries\":[{\"registry\":3}]}",
            "\u{0}\u{1}",
        ] {
            std::fs::write(s.dir().join(FILE), junk).unwrap();
            std::fs::set_permissions(s.dir().join(FILE), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            assert_eq!(s.get_at("quay.io", 1), None, "{junk:?}");
        }
        s.learn_auth_at("quay.io", "https", Auth::Basic, 1000);
        assert!(
            s.get_at("quay.io", 1000).is_some(),
            "rewritten over the junk"
        );
    }

    #[test]
    fn a_file_others_can_write_or_a_link_is_ignored() {
        let (_d, s) = store();
        s.learn_auth_at("quay.io", "https", Auth::Basic, 1000);
        let file = s.dir().join(FILE);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(s.get_at("quay.io", 1000), None);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(s.get_at("quay.io", 1000).is_some());
        let real = s.dir().join("real");
        std::fs::rename(&file, &real).unwrap();
        std::os::unix::fs::symlink(&real, &file).unwrap();
        assert_eq!(s.get_at("quay.io", 1000), None);
    }

    #[test]
    fn a_directory_open_to_others_is_not_used() {
        let d = tempfile::tempdir().unwrap();
        let open = d.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!HintStore::at(&open).prepare());
        let target = d.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, d.path().join("link")).unwrap();
        assert!(!HintStore::at(d.path().join("link")).prepare());
    }

    #[test]
    fn a_directory_that_is_a_link_or_open_to_others_is_not_read() {
        let (d, s) = store();
        s.learn_auth_at("quay.io", "https", Auth::Basic, 1000);
        assert!(s.get_at("quay.io", 1000).is_some());
        // a link to the user's directory with a good file in it
        let link = d.path().join("link");
        std::os::unix::fs::symlink(s.dir(), &link).unwrap();
        assert_eq!(HintStore::at(&link).get_at("quay.io", 1000), None);
        // the directory itself open to others
        std::fs::set_permissions(s.dir(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(s.get_at("quay.io", 1000), None);
        std::fs::set_permissions(s.dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(s.get_at("quay.io", 1000).is_some());
        // the group may not write either
        std::fs::set_permissions(s.dir(), std::fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(s.get_at("quay.io", 1000), None);
        // (a directory that is not the user's cannot be made in a test that
        // is not root; the owner is compared as the file's is)
    }

    #[test]
    fn unsound_entries_are_dropped() {
        let (_d, s) = store();
        let text = |realm: &str, cdn: &str| {
            format!(
                "{{\"entries\":[{{\"registry\":\"a.example\",\"transport\":\"https\",\
                 \"auth\":{{\"type\":\"bearer\",\"realm\":\"{realm}\"}},\"cdn\":\"{cdn}\",\"seen\":1000}}]}}"
            )
        };
        let tries = [
            ("https://a.example/token", "cdn.example", true),
            ("http://a.example/token", "cdn.example", false),
            ("https://user:pw@a.example/token", "cdn.example", false),
            ("not a url", "cdn.example", false),
            ("https://a.example/token", "cdn.example/x", false),
            ("https://a.example/token", "u@cdn.example", false),
        ];
        for (realm, cdn, ok) in tries {
            std::fs::write(s.dir().join(FILE), text(realm, cdn)).unwrap();
            std::fs::set_permissions(s.dir().join(FILE), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            assert_eq!(s.get_at("a.example", 1000).is_some(), ok, "{realm} {cdn}");
        }
    }

    #[test]
    fn an_authority_is_a_host_and_a_port() {
        for ok in [
            "quay.io",
            "localhost:5000",
            "10.0.0.1:443",
            "[::1]",
            "[fe80::1]:5000",
        ] {
            assert!(valid_authority(ok), "{ok}");
        }
        for bad in [
            "", ":5000", "a:", "a:b", "a:70000", "a:1:2", "u@a", "a/b", "a b", "[a", "[::1]5",
            "[abc]", "[::1", "a[::1]", "[::1]:",
        ] {
            assert!(!valid_authority(bad), "{bad}");
        }
    }

    #[test]
    fn a_plain_http_realm_is_for_a_plain_http_registry() {
        let h = |transport: &str, realm: &str| Hint {
            transport: transport.into(),
            auth: bearer(realm),
            cdn: None,
        };
        assert!(h("http", "http://localhost:5000/token").is_sound());
        assert!(!h("https", "http://localhost:5000/token").is_sound());
    }

    #[test]
    fn forgetting_keeps_the_cdn() {
        let (_d, s) = store();
        s.learn_auth_at("quay.io", "https", bearer("https://quay.io/v2/auth"), 1000);
        s.learn_cdn_at("quay.io", "https", "cdn01.quay.io", 1000);
        s.forget_auth_at("quay.io", 1000);
        let h = s.get_at("quay.io", 1000).unwrap();
        assert_eq!(h.auth, Auth::None);
        assert_eq!(h.cdn.as_deref(), Some("cdn01.quay.io"));
    }
}
