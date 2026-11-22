// SPDX-License-Identifier: Apache-2.0
//! The stores the server holds: one for each pair of the uid of the peer and
//! the id of the store, each a directory with its own database, objects,
//! staging area and vfs driver.  The server records the layers it pulled in
//! the database of the store, as the engine does for an in-process driver,
//! because the vfs driver reads them there.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use tokio::runtime::Handle;
use velarx_db::Database;
use velarx_graph::{DriverError, DriverParts, DriverResult};
use velarx_storage::{FileStore, VerityMode};
use velarx_storage_client::proto::LayerRef;
use velarx_types::digest::Digest;
use velarx_vfs::{VfsDriver, VfsOptions};

/// What a pull is waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Pending,
    Commit,
    Abort,
}

/// Where a pull is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// Fetching, or waiting for the layers another pull holds.
    Running,
    /// Every object is in the store, the engine proves and decides.
    Staged,
    /// Over: published (`Ok`) or not.
    Over(Result<(), String>),
}

pub struct Pull {
    pub phase: Phase,
    pub decision: Decision,
    /// The objects of its layers, fetched or found in the store: what an
    /// `Abort` of another pull leaves, and what a collection keeps, while it
    /// lives.
    pub keys: HashSet<String>,
    /// When it was over: the record of its outcome is kept for an engine that
    /// asks again (`Commit` after a lost reply), and forgotten later.
    pub ended: Option<std::time::Instant>,
}

#[derive(Default)]
pub struct State {
    pub pulls: HashMap<String, Pull>,
    /// The layers a live pull is fetching, and the pull.
    pub claimed: HashMap<String, String>,
    /// The objects of the pulls that are staged, by pull: verified and not
    /// named in the store until the engine commits, where their bytes are
    /// (the engine reads them back before it decides).
    pub staged: HashMap<String, HashMap<String, PathBuf>>,
}

/// What the server keeps of a container: where its bundle is and what it was
/// made of.
#[derive(Serialize, Deserialize, Default)]
pub struct Container {
    pub bundle: PathBuf,
    pub workdir: PathBuf,
    pub image: Option<String>,
    pub layers: Vec<LayerRef>,
    pub volumes: BTreeMap<u32, Volume>,
}

#[derive(Serialize, Deserialize)]
pub struct Volume {
    pub image: String,
    pub layers: Vec<LayerRef>,
}

/// What the server waits on to know that it became busy or idle: a counter
/// that every change of what keeps it busy (a connection, the claims of a
/// pull) advances.
#[derive(Default)]
pub struct Activity {
    generation: Mutex<u64>,
    changed: Condvar,
}

impl Activity {
    /// Something that keeps the server busy came or went.
    pub fn notify(&self) {
        *self.generation.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.changed.notify_all();
    }

    /// The count now: read before looking at what it counts.
    pub fn generation(&self) -> u64 {
        *self.generation.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Wait until the count is not `seen` any more, for at most `limit`
    /// (without one, as long as it takes); whether it changed.
    pub fn wait_after(&self, seen: u64, limit: Option<std::time::Duration>) -> bool {
        let guard = self.generation.lock().unwrap_or_else(|e| e.into_inner());
        match limit {
            None => {
                *self
                    .changed
                    .wait_while(guard, |g| *g == seen)
                    .unwrap_or_else(|e| e.into_inner())
                    != seen
            }
            Some(limit) => {
                *self
                    .changed
                    .wait_timeout_while(guard, limit, |g| *g == seen)
                    .unwrap_or_else(|e| e.into_inner())
                    .0
                    != seen
            }
        }
    }
}

pub struct Store {
    pub dir: PathBuf,
    pub db: Database,
    pub files: Arc<FileStore>,
    pub vfs: Arc<VfsDriver>,
    pub rt: Handle,
    state: Mutex<State>,
    changed: Condvar,
    activity: Arc<Activity>,
    /// Held while a copy of an image for `MountImage` is made, so that two
    /// calls for one image make one.
    pub reading: Mutex<()>,
    /// The `Fetch` calls the server sent to the engine, and the objects
    /// they asked for.
    pub fetch_calls: AtomicU64,
    pub fetch_keys: AtomicU64,
    /// The `copy` events of the engine the server applied, and their bytes.
    pub copy_events: AtomicU64,
    pub copied_bytes: AtomicU64,
    /// The files the engine handed over verified, and the bytes of them the
    /// server had to copy (none where it could link the inode).
    pub handed_files: AtomicU64,
    pub handed_copied_bytes: AtomicU64,
}

/// The ids of the copies a server reads an image from for `MountImage` start
/// with this (the engine's containers are named by it: its ids are hex).
pub const READ_PREFIX: &str = "read-";

/// The records of containers in `dir` (a record of a copy of an image,
/// [`READ_PREFIX`], is not one).
fn count_containers(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".json") && !n.starts_with(READ_PREFIX))
                .count()
        })
        .unwrap_or(0)
}

/// The largest record of a container the server reads back.
const MAX_CONTAINER: u64 = 1 << 20;

/// A name the server makes a file or a directory of: not empty, not `.` or
/// `..`, and only letters, digits, `-`, `_` and `.`.
pub fn plain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn io(e: impl std::fmt::Display) -> DriverError {
    DriverError::storage("velarx-storage-ref", e.to_string())
}

impl State {
    /// Forget the pulls that were over before `before`: a `Commit` of one of
    /// them then answers from what the store has committed.
    pub fn forget_ended(&mut self, before: std::time::Instant) {
        self.pulls
            .retain(|_, p| p.ended.is_none_or(|t| t >= before));
    }
}

impl Store {
    pub fn open(dir: &Path, rt: Handle, activity: Arc<Activity>) -> DriverResult<Arc<Self>> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(io)?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(dir.join("containers"))
            .map_err(io)?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(dir.join("aliases"))
            .map_err(io)?;
        let db = rt.block_on(Database::open(dir.join("db"))).map_err(io)?;
        let files = Arc::new(FileStore::new(dir.join("objects")).map_err(io)?);
        // (no pull exists yet: what no row names is left by a crash)
        let named = rt
            .block_on(db.layer_digests())
            .map_err(io)?
            .iter()
            .map(velarx_types::LayerKey::file_stem)
            .collect();
        velarx_db::layer_files::sweep(velarx_db::layer_files::root_of(files.root()), &named)
            .map_err(io)?;

        let vfs = VfsDriver::new(DriverParts {
            db: db.clone(),
            store: files.clone(),
            staging_dir: dir.join("staging"),
            fsverity: VerityMode::Off,
        })
        .with_options(VfsOptions {
            ignore_chown_errors: !rustix::process::geteuid().is_root(),
            ..Default::default()
        });
        Ok(Arc::new(Self {
            dir: dir.to_path_buf(),
            db,
            files,
            vfs: Arc::new(vfs),
            rt,
            state: Mutex::default(),
            changed: Condvar::new(),
            activity,
            reading: Mutex::new(()),
            fetch_calls: AtomicU64::new(0),
            fetch_keys: AtomicU64::new(0),
            copy_events: AtomicU64::new(0),
            copied_bytes: AtomicU64::new(0),
            handed_files: AtomicU64::new(0),
            handed_copied_bytes: AtomicU64::new(0),
        }))
    }

    pub fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The state changed: the calls that wait for it go on, and the server
    /// looks whether it is busy.
    pub fn notify(&self) {
        self.changed.notify_all();
        self.activity.notify();
    }

    /// Wait for a change of the state, for at most `wait`.
    pub fn wait<'a>(
        &self,
        guard: MutexGuard<'a, State>,
        wait: std::time::Duration,
    ) -> MutexGuard<'a, State> {
        self.changed
            .wait_timeout(guard, wait)
            .unwrap_or_else(|e| e.into_inner())
            .0
    }

    /// The file of the container `id`: an id that is not a plain name (a
    /// path, `..`, anything but letters, digits, `-`, `_` and `.`) names no
    /// file of the server's, whatever the call.
    fn container_path(&self, id: &str) -> DriverResult<PathBuf> {
        if !plain(id) {
            return Err(io(format!(
                "{id:?} is not a container id the server can name a file by"
            )));
        }
        Ok(self.dir.join("containers").join(format!("{id}.json")))
    }

    /// What the server keeps of the container `id`; none when it has no root
    /// here.
    pub fn container(&self, id: &str) -> DriverResult<Option<Container>> {
        let path = self.container_path(id)?;
        let text = match velarx_base::conf::read_bounded(&path, MAX_CONTAINER) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(format!("{}: {e}", path.display()))),
        };
        serde_json::from_slice(&text)
            .map(Some)
            .map_err(|e| io(format!("{} is not a container record: {e}", path.display())))
    }

    pub fn save_container(&self, id: &str, c: &Container) -> DriverResult<()> {
        let path = self.container_path(id)?;
        velarx_base::atomic_file::write(&path, &serde_json::to_vec(c).map_err(io)?, 0o600)
            .map_err(io)
    }

    pub fn forget_container(&self, id: &str) -> DriverResult<()> {
        match std::fs::remove_file(self.container_path(id)?) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(io(e)),
            _ => Ok(()),
        }
    }

    /// The ids of the copies of images the server holds for `MountImage`.
    pub fn image_copies(&self) -> Vec<String> {
        let mut ids: Vec<String> = std::fs::read_dir(self.dir.join("containers"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let id = name.strip_suffix(".json")?;
                id.starts_with(READ_PREFIX).then(|| id.to_string())
            })
            .collect();
        ids.sort();
        ids
    }

    /// The containers the server holds: not the copies it reads images from,
    /// which are its own and go with the store.
    pub fn containers(&self) -> usize {
        count_containers(&self.dir.join("containers"))
    }

    /// The file that says which object has the content a key names when
    /// the key is the hash of the content (`sha256:HEX`, what a table of
    /// contents gives for a file that states no fs-verity digest): the
    /// store keeps objects by their fs-verity digest, and the engine reads
    /// back by the key it knows.  None for a key that names an object.
    fn alias_path(&self, key: &str) -> Option<PathBuf> {
        let d = Digest::parse(key).ok().filter(|d| !d.is_fsverity())?;
        Some(
            self.dir
                .join("aliases")
                .join(format!("{}-{}", d.alg(), d.hex())),
        )
    }

    /// Remember the object of each file of `entries`, the table of a layer
    /// the pull settled, that `handed`, the table the engine handed over
    /// (entry for entry), knows by the hash of its content, before the
    /// engine reads the layer back.  Those are the files it gives no
    /// fs-verity digest: their bytes were checked against that hash.  Where
    /// it gives one, the hash is the table's word.
    pub fn record_aliases(
        &self,
        handed: &[velarx_storage::TocEntry],
        entries: &[velarx_storage::TocEntry],
    ) -> DriverResult<()> {
        for (h, e) in handed.iter().zip(entries) {
            if h.verity().is_some() {
                continue;
            }
            let (Some(path), Some(object)) = (
                e.digest.as_deref().and_then(|d| self.alias_path(d)),
                e.verity(),
            ) else {
                continue;
            };
            if !path.exists() {
                velarx_base::atomic_file::write(&path, object.as_bytes(), 0o600).map_err(io)?;
            }
        }
        Ok(())
    }

    /// The name of the object `key` stands for: itself, or the object an alias
    /// says.
    pub fn resolve(&self, key: &str) -> String {
        self.alias_path(key)
            .and_then(|p| velarx_base::conf::read_bounded(&p, 256).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| key.to_string())
    }

    /// Forget the aliases of objects the store no longer has.
    pub fn forget_dangling_aliases(&self) {
        let Ok(dir) = std::fs::read_dir(self.dir.join("aliases")) else {
            return;
        };
        for e in dir.flatten() {
            let object = velarx_base::conf::read_bounded(&e.path(), 256)
                .ok()
                .and_then(|b| String::from_utf8(b).ok());
            if !object.is_some_and(|o| self.files.contains(&o)) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    /// Note that an engine opened the store.
    pub fn touch(&self) {
        let _ = std::fs::write(self.dir.join("last-open"), b"");
    }
}

/// The stores of the server.
pub struct Stores {
    root: PathBuf,
    rt: Handle,
    pub activity: Arc<Activity>,
    open: Mutex<HashMap<(u32, String), Arc<Store>>>,
}

impl Stores {
    pub fn new(root: &Path, rt: Handle) -> Self {
        Self {
            root: root.to_path_buf(),
            rt,
            activity: Arc::default(),
            open: Mutex::default(),
        }
    }

    fn path(&self, uid: u32, id: &str) -> PathBuf {
        self.root.join(uid.to_string()).join(id)
    }

    /// The store `id` of the user `uid`, opened if it is not.
    pub fn get(&self, uid: u32, id: &str) -> DriverResult<Arc<Store>> {
        if !velarx_graph::stores::is_store_id(id) {
            return Err(DriverError::storage(
                "velarx-storage-ref",
                format!("{id:?} is not a store id (32 hex digits)"),
            ));
        }
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = open.get(&(uid, id.to_string())) {
            return Ok(s.clone());
        }
        let store = Store::open(&self.path(uid, id), self.rt.clone(), self.activity.clone())?;
        store.touch();
        open.insert((uid, id.to_string()), store.clone());
        Ok(store)
    }

    /// Whether a pull holds claims of a store: one that is not over (it
    /// fetches, or is staged and waits for the engine's decision), or any
    /// layer claimed.
    pub fn holds_claims(&self) -> bool {
        let open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        open.values().any(|s| {
            let st = s.state();
            !st.claimed.is_empty()
                || st
                    .pulls
                    .values()
                    .any(|p| !matches!(p.phase, Phase::Over(_)))
        })
    }

    /// The stores on the disk of the user.
    pub fn list(&self, uid: u32) -> Vec<(String, u64, Option<u64>)> {
        let Ok(rd) = std::fs::read_dir(self.root.join(uid.to_string())) else {
            return Vec::new();
        };
        let mut out: Vec<_> = rd
            .flatten()
            .filter_map(|e| {
                let id = e.file_name().to_string_lossy().into_owned();
                if !velarx_graph::stores::is_store_id(&id) {
                    return None;
                }
                let bytes = velarx_graph::objects::files_usage(&e.path()).1;
                let last = std::fs::metadata(e.path().join("last-open"))
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());
                Some((id, bytes, last))
            })
            .collect();
        out.sort();
        out
    }

    /// Remove the store: `Busy` while a pull or a container of it lives.
    pub fn drop(&self, uid: u32, id: &str) -> DriverResult<()> {
        if !velarx_graph::stores::is_store_id(id) {
            return Err(DriverError::storage(
                "velarx-storage-ref",
                format!("{id:?} is not a store id (32 hex digits)"),
            ));
        }
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        let key = (uid, id.to_string());
        if let Some(s) = open.get(&key) {
            let live = s
                .state()
                .pulls
                .values()
                .any(|p| !matches!(p.phase, Phase::Over(_)));
            if live || s.containers() > 0 {
                return Err(DriverError::of(
                    "velarx-storage-ref",
                    velarx_graph::DriverErrorKind::Busy,
                    format!("the store {id} has a pull or a container in progress"),
                ));
            }
        } else if count_containers(&self.path(uid, id).join("containers")) > 0 {
            // (a store no call opened since the server started: its records,
            // read the same way)
            return Err(DriverError::of(
                "velarx-storage-ref",
                velarx_graph::DriverErrorKind::Busy,
                format!("the store {id} has a container"),
            ));
        }
        open.remove(&key);
        match velarx_base::tree::remove_dir_all(self.path(uid, id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pull that is not over holds claims; one that is over, none.
    #[test]
    fn a_pull_that_is_not_over_holds_claims() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let stores = Stores::new(root.path(), rt.handle().clone());
        let id = "0123456789abcdef0123456789abcdef";
        assert!(!stores.holds_claims());
        let store = stores.get(1000, id).unwrap();
        assert!(!stores.holds_claims(), "an open store holds nothing");
        let pull = |phase| Pull {
            phase,
            decision: Decision::Pending,
            keys: HashSet::new(),
            ended: None,
        };
        for phase in [Phase::Running, Phase::Staged] {
            store.state().pulls.insert("p".into(), pull(phase));
            assert!(stores.holds_claims());
        }
        store
            .state()
            .pulls
            .insert("p".into(), pull(Phase::Over(Ok(()))));
        assert!(
            !stores.holds_claims(),
            "the record of an ended pull holds none"
        );
        store.state().claimed.insert("k".into(), "p".into());
        assert!(stores.holds_claims(), "a claimed layer is held");
        store.state().claimed.clear();
        assert!(!stores.holds_claims());
    }

    /// A record that is not a container is an error, not a container the
    /// server has no root for: `CreateRoot` would overwrite it with a new one.
    #[test]
    fn a_record_that_is_not_a_container_is_an_error() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let stores = Stores::new(root.path(), rt.handle().clone());
        let store = stores
            .get(1000, "0123456789abcdef0123456789abcdef")
            .unwrap();
        assert!(store.container("none").unwrap().is_none());
        std::fs::create_dir_all(store.dir.join("containers")).unwrap();
        std::fs::write(store.dir.join("containers/bad.json"), "{not json").unwrap();
        let Err(e) = store.container("bad") else {
            panic!("a record that is no container")
        };
        assert!(e.to_string().contains("bad.json"), "{e}");
        store.save_container("good", &Container::default()).unwrap();
        assert!(store.container("good").unwrap().is_some());
    }

    #[test]
    fn the_copy_of_an_image_is_not_a_container() {
        let dir = tempfile::tempdir().unwrap();
        for n in ["read-ab12.json", "0123abcd.json", "0123abcd.tmp"] {
            std::fs::write(dir.path().join(n), "{}").unwrap();
        }
        assert_eq!(count_containers(dir.path()), 1);
        assert_eq!(count_containers(&dir.path().join("none")), 0);
    }

    #[test]
    fn a_store_not_opened_with_only_the_copy_of_an_image_is_dropped() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let stores = Stores::new(root.path(), rt.handle().clone());
        let (a, b) = (
            "0123456789abcdef0123456789abcdef",
            "fedcba9876543210fedcba9876543210",
        );
        for (id, record) in [(a, "read-ab12.json"), (b, "0123abcd.json")] {
            let dir = stores.path(1000, id).join("containers");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(record), "{}").unwrap();
        }
        stores.drop(1000, a).unwrap();
        assert!(!stores.path(1000, a).exists());
        let e = stores.drop(1000, b).unwrap_err();
        assert!(matches!(e.kind, velarx_graph::DriverErrorKind::Busy), "{e}");
        assert!(stores.path(1000, b).exists());
    }

    fn entry(digest: &str, verity: Option<&str>) -> velarx_storage::TocEntry {
        let mut e = serde_json::json!({"name": "f", "type": "reg", "size": 1, "digest": digest});
        if let Some(v) = verity {
            e["fsverity"] = v.into();
        }
        serde_json::from_value(e).unwrap()
    }

    /// A key that is the hash of the content stands for the object the pull
    /// of a layer known by that hash found it is, as long as the store has the
    /// object; an object's own name, and a key nothing is known of, stand for
    /// themselves.
    #[test]
    fn a_hash_of_the_content_names_the_object_that_has_it() {
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let store = Store::open(dir.path(), rt.handle().clone(), Arc::default()).unwrap();
        let sha = format!("sha256:{}", "ab".repeat(32));
        let object = format!("fsverity-sha256-12:{}", "cd".repeat(32));
        let toc = velarx_storage::toc_value(&velarx_storage::to_toc(&object).unwrap());
        let other = format!("sha256:{}", "ef".repeat(32));
        store
            .record_aliases(
                &[entry(&sha, None), entry(&other, None)],
                // (a file the pull found no object for is not known)
                &[entry(&sha, Some(&toc)), entry(&other, None)],
            )
            .unwrap();
        assert_eq!(store.resolve(&sha), object);
        assert_eq!(store.resolve(&object), object);
        assert_eq!(store.resolve(&other), other);
        // an alias of an object the store lacks goes with the next collection
        store.forget_dangling_aliases();
        assert_eq!(store.resolve(&sha), sha);
    }

    /// The content hash a table gives a file next to its fs-verity digest is
    /// the table's word: it names no object.
    #[test]
    fn the_hash_of_a_file_known_by_its_fs_verity_digest_names_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let store = Store::open(dir.path(), rt.handle().clone(), Arc::default()).unwrap();
        let sha = format!("sha256:{}", "ab".repeat(32));
        let object = format!("fsverity-sha256-12:{}", "cd".repeat(32));
        let toc = velarx_storage::toc_value(&velarx_storage::to_toc(&object).unwrap());
        let table = [entry(&sha, Some(&toc))];
        store.record_aliases(&table, &table).unwrap();
        assert_eq!(store.resolve(&sha), sha);
    }
}
