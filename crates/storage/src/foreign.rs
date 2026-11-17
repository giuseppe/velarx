// SPDX-License-Identifier: Apache-2.0
//! Foreign stores: read-only directories of files that other tools keep
//! (a composefs-rs repository, a podman `use_composefs` store, another
//! velarx store), searched for a file a pull would otherwise fetch
//! (`[storage] foreign_object_stores`, docs/STORAGE.md).
//!
//! The rules, all of them kept here and not by the callers:
//! * Only image data is looked at: the objects of a composefs-rs repository
//!   and of a velarx store (which hold no container data), and for
//!   containers/storage the layers of its images; the layers of its
//!   containers are never opened.
//! * Nothing of a foreign store is trusted.  A name is a hint: what is
//!   found is opened below the directory of the store (no symbolic link, no
//!   `..`, a regular file only, never waiting on a FIFO), its size is
//!   checked, and its content is measured (fs-verity, which the kernel
//!   enforces, for a hard link) or hashed again from our own reflink or copy
//!   before it is used.  The metadata files (`meta.json`, `images.json`...,
//!   at most 64 MiB each) only tell where to look.
//! * Nothing is written to a foreign store: it is opened `O_RDONLY` or
//!   `O_PATH`, no lock is taken, nothing is created.  A foreign directory is
//!   never a run-time data directory of a mount: a file is imported, as a
//!   reflink, a hard link or a copy.
//! * Another process may delete what we found at any time (the garbage
//!   collection of the store); a name that is gone is a miss, and a file
//!   that is open stays readable.
//! * A store that cannot be used (unreadable, not what its kind says, the
//!   store itself) is skipped with one warning, never an error.
use crate::{canonical_digest, copy_file, fsverity_digest_file, measure_file, Object};
use serde::Deserialize;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};
pub use velarx_base::foreign::{ForeignKind, ForeignStoreSpec};
use velarx_sys::fs::{open_beneath, Beneath, BeneathError};
use velarx_types::digest::{Algorithm, Digest, DigestWriter};

/// The most of a metadata file (`meta.json`, `layers.json`...) that is read:
/// a store with a bigger one is not used.
const MAX_METADATA: u64 = 64 << 20;
/// The most layers of one chain of parents that is followed.
const MAX_CHAIN: usize = 4096;

/// Why a foreign store is not used.
#[derive(Debug, thiserror::Error)]
pub enum ForeignError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Invalid(String),
}

impl From<rustix::io::Errno> for ForeignError {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}

/// What a lookup is made with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForeignKey {
    /// The fs-verity digest of the file (its name in the objects of
    /// composefs-rs and velarx).
    Verity(Digest),
    /// The sha256 of its content (its name in containers/storage).
    Content(Digest),
}

enum Layout {
    /// `objects/xx/yyy` by fs-verity digests of these algorithms.
    Objects(Vec<Algorithm>),
    /// `overlay/<layer>/diff/xx/yyy` by sha256 for these layers.
    Layers(Vec<String>),
}

/// A foreign store that is usable.
pub struct ForeignStore {
    path: PathBuf,
    kind: ForeignKind,
    link: bool,
    /// `objects` or `overlay`, as an `O_PATH` descriptor.
    base: OwnedFd,
    layout: Layout,
}

fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    Ok(rustix::fs::open(
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// `name` below `dir`; an error names it.
fn beneath(dir: &OwnedFd, name: &str, what: Beneath) -> io::Result<OwnedFd> {
    open_beneath(dir.as_fd(), Path::new(name), what).map_err(|e| match e {
        BeneathError::NotRegular => io::Error::other(format!("{name} is not a regular file")),
        e => {
            let e = io::Error::from(e);
            io::Error::new(e.kind(), format!("{name}: {e}"))
        }
    })
}

/// A metadata file of a store, whole (at most [`MAX_METADATA`] bytes).
fn read_metadata(root: &OwnedFd, name: &str) -> Result<Vec<u8>, ForeignError> {
    let file = File::from(beneath(root, name, Beneath::File)?);
    let mut body = Vec::new();
    file.take(MAX_METADATA + 1).read_to_end(&mut body)?;
    if body.len() as u64 > MAX_METADATA {
        return Err(ForeignError::Invalid(format!(
            "{name} is larger than {} MiB",
            MAX_METADATA >> 20
        )));
    }
    Ok(body)
}

/// A metadata file of a store, parsed.
fn read_json<T: serde::de::DeserializeOwned>(
    root: &OwnedFd,
    name: &str,
) -> Result<T, ForeignError> {
    let body = read_metadata(root, name)?;
    serde_json::from_slice(&body).map_err(|e| ForeignError::Invalid(format!("{name}: {e}")))
}

/// A visitor of a JSON array that hands each element to a function and
/// keeps none: a crafted file of many small elements (`[{},{},...]`) is not
/// made into a vector many times its size.
struct Each<T, F>(F, std::marker::PhantomData<fn(T)>);

impl<'de, T: Deserialize<'de>, F: FnMut(T)> serde::de::Visitor<'de> for Each<T, F> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("an array")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(mut self, mut seq: A) -> Result<(), A::Error> {
        while let Some(x) = seq.next_element::<T>()? {
            (self.0)(x);
        }
        Ok(())
    }
}

/// Each element of the JSON array of the metadata file `name`.
fn each<T: serde::de::DeserializeOwned>(
    root: &OwnedFd,
    name: &str,
    f: impl FnMut(T),
) -> Result<(), ForeignError> {
    let body = read_metadata(root, name)?;
    let mut de = serde_json::Deserializer::from_slice(&body);
    serde::Deserializer::deserialize_seq(&mut de, Each(f, std::marker::PhantomData))
        .and_then(|()| de.end())
        .map_err(|e| ForeignError::Invalid(format!("{name}: {e}")))
}

/// The layer ids of a JSON array of strings, the others dropped as they
/// are read.
fn layer_ids<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    let mut ids = Vec::new();
    d.deserialize_seq(Each(
        |id: String| {
            if is_layer_id(&id) {
                ids.push(id)
            }
        },
        std::marker::PhantomData,
    ))?;
    Ok(ids)
}

/// A layer id of containers/storage: 64 lower case hexadecimal digits.
fn is_layer_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The ids of the layers of the images of a containers/storage root: the
/// top layer of each image and its parents.  The layers of containers (and
/// whatever is not reachable from an image) are not in it.  Only the valid
/// ids of the files are kept, as they are read.
fn image_layers(root: &OwnedFd) -> Result<Vec<String>, ForeignError> {
    use std::collections::{HashMap, HashSet};
    #[derive(Deserialize)]
    struct Image {
        layer: Option<String>,
        #[serde(default, rename = "mapped-top-layers", deserialize_with = "layer_ids")]
        mapped: Vec<String>,
    }
    #[derive(Deserialize)]
    struct Layer {
        id: String,
        parent: Option<String>,
    }
    #[derive(Deserialize)]
    struct Container {
        layer: Option<String>,
    }
    let mut tops = Vec::new();
    each(root, "overlay-images/images.json", |i: Image| {
        tops.extend(
            i.layer
                .into_iter()
                .chain(i.mapped)
                .filter(|l| is_layer_id(l)),
        );
    })?;
    let mut parents: HashMap<String, Option<String>> = HashMap::new();
    each(root, "overlay-layers/layers.json", |l: Layer| {
        if is_layer_id(&l.id) {
            parents.insert(l.id, l.parent.filter(|p| is_layer_id(p)));
        }
    })?;
    // defense in depth: a layer a container names is never an image layer,
    // whatever the images say (an `-init` layer has no valid id: never
    // searched)
    let mut containers = HashSet::new();
    let _ = each(
        root,
        "overlay-containers/containers.json",
        |c: Container| {
            if let Some(l) = c.layer.filter(|l| is_layer_id(l)) {
                containers.insert(l);
            }
        },
    );
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    for top in &tops {
        let mut at = Some(top);
        let mut steps = 0;
        while let Some(id) = at {
            if steps >= MAX_CHAIN || !seen.insert(id) {
                break;
            }
            steps += 1;
            if !containers.contains(id) {
                found.push(id.clone());
            }
            at = parents.get(id).and_then(Option::as_ref);
        }
    }
    Ok(found)
}

impl ForeignStore {
    /// Open the store `spec`; `own` is the root of this velarx's own store,
    /// which is never a foreign one.
    pub fn open(spec: &ForeignStoreSpec, own: Option<&Path>) -> Result<Self, ForeignError> {
        if !spec.path.is_absolute() {
            return Err(ForeignError::Invalid("the path is not absolute".into()));
        }
        let root = open_dir(&spec.path)?;
        let ident = |fd: &OwnedFd| rustix::fs::fstat(fd).map(|s| (s.st_dev, s.st_ino));
        if let Some(own) = own {
            if let Ok(o) = open_dir(own) {
                if ident(&o)? == ident(&root)? {
                    return Err(ForeignError::Invalid("it is this store itself".into()));
                }
            }
        }
        let (base, layout) = match spec.kind {
            ForeignKind::ComposefsRs => {
                #[derive(Deserialize)]
                struct Features {
                    #[serde(default)]
                    incompatible: Vec<String>,
                }
                #[derive(Deserialize)]
                struct Meta {
                    version: u64,
                    algorithm: String,
                    #[serde(default)]
                    features: Option<Features>,
                }
                let meta: Meta = read_json(&root, "meta.json")?;
                if meta.version != 1 {
                    return Err(ForeignError::Invalid(format!(
                        "meta.json: repository format version {}, 1 is known",
                        meta.version
                    )));
                }
                if let Some(f) = meta.features.filter(|f| !f.incompatible.is_empty()) {
                    return Err(ForeignError::Invalid(format!(
                        "meta.json: incompatible features {:?}",
                        f.incompatible
                    )));
                }
                let alg = [Algorithm::Sha256, Algorithm::Sha512]
                    .into_iter()
                    .find(|a| meta.algorithm == format!("fsverity-{a}-12"))
                    .ok_or_else(|| {
                        ForeignError::Invalid(format!("meta.json: algorithm {:?}", meta.algorithm))
                    })?;
                (
                    beneath(&root, "objects", Beneath::DirectoryPath)?,
                    Layout::Objects(vec![alg]),
                )
            }
            ForeignKind::Velarx => (
                beneath(&root, "objects", Beneath::DirectoryPath)?,
                Layout::Objects(Algorithm::ALL.to_vec()),
            ),
            ForeignKind::ContainersStorage => {
                let layers = image_layers(&root)?;
                (
                    beneath(&root, "overlay", Beneath::DirectoryPath)?,
                    Layout::Layers(layers),
                )
            }
        };
        Ok(Self {
            path: spec.path.clone(),
            kind: spec.kind,
            link: spec.link,
            base,
            layout,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn kind(&self) -> ForeignKind {
        self.kind
    }

    /// The names a key can have in this store.
    fn names(&self, key: &ForeignKey) -> Vec<String> {
        match (&self.layout, key) {
            (Layout::Objects(algs), ForeignKey::Verity(d)) if algs.contains(&d.alg()) => {
                Object::of(d, false)
                    .map(|o| vec![o.rel()])
                    .unwrap_or_default()
            }
            (Layout::Layers(layers), ForeignKey::Content(d))
                if d.alg() == Algorithm::Sha256 && !d.is_fsverity() =>
            {
                let hex = d.hex();
                layers
                    .iter()
                    .map(|l| format!("{l}/diff/{}/{}", &hex[..2], &hex[2..]))
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    /// The candidates for `key`: files that are there, regular, and of
    /// `size` (the size the pull wants: nothing bigger is ever read).  Not
    /// yet trusted: see [`Candidate::import`].
    pub fn lookup(&self, key: &ForeignKey, size: u64) -> Vec<Candidate> {
        let mut found = Vec::new();
        for name in self.names(key) {
            let file = match beneath(&self.base, &name, Beneath::File) {
                Ok(fd) => File::from(fd),
                Err(e) => {
                    // (a miss, a store that is collected meanwhile, a file
                    // we may not read, a link, a FIFO)
                    debug!("foreign store {}: {e}", self.path.display());
                    continue;
                }
            };
            let meta = match file.metadata() {
                Ok(m) if m.is_file() => m,
                _ => continue,
            };
            if meta.len() != size {
                debug!(
                    "foreign store {}: {name} has another size",
                    self.path.display()
                );
                continue;
            }
            found.push(Candidate {
                file,
                size,
                dev: meta.dev(),
                key: key.clone(),
                link: self.link,
                name: self.path.join(name),
            });
        }
        found
    }
}

/// The foreign stores of the configuration that can be used, in their order.
#[derive(Default)]
pub struct ForeignStores {
    stores: Vec<ForeignStore>,
}

impl ForeignStores {
    /// Open the stores of `specs`; one that cannot be used is skipped, with
    /// a warning that says why.  Nothing is said when there are none.
    pub fn open(specs: &[ForeignStoreSpec], own: Option<&Path>) -> Self {
        let mut stores = Vec::new();
        for spec in specs {
            match ForeignStore::open(spec, own) {
                Ok(s) => stores.push(s),
                Err(e) => warn!(
                    "The foreign store {} ({}): {e}: not used",
                    spec.path.display(),
                    spec.kind.name()
                ),
            }
        }
        Self { stores }
    }

    pub fn is_empty(&self) -> bool {
        self.stores.is_empty()
    }

    pub fn stores(&self) -> &[ForeignStore] {
        &self.stores
    }

    /// The candidates of all the stores for `key`, in their order.
    pub fn lookup(&self, key: &ForeignKey, size: u64) -> Vec<Candidate> {
        self.stores
            .iter()
            .flat_map(|s| s.lookup(key, size))
            .collect()
    }
}

/// What a file of a foreign store is known to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// It has fs-verity with the digest of the key: the kernel enforces its
    /// content, which cannot change.
    Verity,
    /// Nothing is known: its content is hashed after it is copied.
    Unknown,
}

/// How a file was imported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Reflink,
    Hardlink,
    Copy,
}

/// A file of a foreign store that is open, regular and of the wanted size:
/// not yet trusted.
pub struct Candidate {
    file: File,
    size: u64,
    dev: u64,
    key: ForeignKey,
    link: bool,
    name: PathBuf,
}

impl Candidate {
    /// Where it is (for the log).
    pub fn name(&self) -> &Path {
        &self.name
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// The file, open for reading.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Whether the file has fs-verity with the digest it is named by.
    pub fn trust(&self) -> Trust {
        match &self.key {
            ForeignKey::Verity(d) => match measure_file(&self.file) {
                Ok(m)
                    if m.object().as_ref() == Some(d) && canonical_digest(&self.file, d.alg()) =>
                {
                    Trust::Verity
                }
                _ => Trust::Unknown,
            },
            ForeignKey::Content(_) => Trust::Unknown,
        }
    }

    /// Whether the content of `file` is what the key says.
    fn matches(&self, file: &File) -> io::Result<bool> {
        match &self.key {
            ForeignKey::Verity(d) => Ok(fsverity_digest_file(d.alg(), file)? == d.to_string()),
            ForeignKey::Content(d) => {
                let mut hasher = DigestWriter::new(d.alg());
                let mut buf = vec![0u8; 1 << 20];
                let mut at = 0;
                loop {
                    let n = match file.read_at(&mut buf, at) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    };
                    hasher.update(&buf[..n]);
                    at += n as u64;
                }
                Ok(&hasher.finalize() == d)
            }
        }
    }

    /// Make the file `dest` (which does not exist) with the content of the
    /// candidate, which is then what the key names: a reflink, else a hard
    /// link, else a copy.  A reflink or a copy is our own file and is hashed
    /// (from it, not from the foreign one; also when the foreign file has
    /// fs-verity: a clone shares its blocks without the kernel checking
    /// them); `dest` is removed and an error returned when it is not what
    /// the key names.  A hard link is made only when the store allows it, on
    /// the same file system, of a file of the user velarx runs as that has
    /// fs-verity with the digest of the key, measured on the descriptor that
    /// is linked: it is then the same inode, whose content nothing can
    /// change and whose mode and owner only this user or root can; it is not
    /// hashed, and the caller must neither chmod it nor enable fs-verity on
    /// it.  Nothing of the foreign inode is changed.
    pub fn import(&self, dest: &Path) -> io::Result<Method> {
        self.import_as(dest, self.trust())
    }

    /// Whether the file may be hard linked, its content guarded as `trust`.
    fn may_link(&self, trust: Trust) -> bool {
        self.link
            && trust == Trust::Verity
            && rustix::fs::fstat(&self.file)
                .is_ok_and(|st| st.st_uid == rustix::process::geteuid().as_raw())
    }

    fn import_as(&self, dest: &Path, trust: Trust) -> io::Result<Method> {
        let dest_dir = dest.parent().unwrap_or(Path::new("."));
        let same_fs = std::fs::metadata(dest_dir).is_ok_and(|m| m.dev() == self.dev);
        let result = (|| {
            if same_fs {
                if let Some(to) = self.reflink(dest)? {
                    self.check(&to)?;
                    return Ok(Method::Reflink);
                }
                if self.may_link(trust) {
                    // (the inode of the descriptor that was measured, not
                    // whatever the name is now)
                    match rustix::fs::linkat(
                        rustix::fs::CWD,
                        velarx_sys::fd::proc_str(&self.file),
                        rustix::fs::CWD,
                        dest,
                        rustix::fs::AtFlags::SYMLINK_FOLLOW,
                    ) {
                        Ok(()) => return Ok(Method::Hardlink),
                        // (no right, `fs.protected_hardlinks`, the file is
                        // gone: copy)
                        Err(e) => debug!("hard link of {}: {e}", self.name.display()),
                    }
                }
            }
            let to = self.copy(dest)?;
            self.check(&to)?;
            Ok(Method::Copy)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(dest);
        }
        result
    }

    fn create(dest: &Path) -> io::Result<File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dest)
    }

    /// `file`, ours, is what the key names.
    fn check(&self, file: &File) -> io::Result<()> {
        if !self.matches(file)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not what its name says", self.name.display()),
            ));
        }
        Ok(())
    }

    /// Clone the extents; none when the file system cannot.
    fn reflink(&self, dest: &Path) -> io::Result<Option<File>> {
        let to = Self::create(dest)?;
        match rustix::fs::ioctl_ficlone(&to, &self.file) {
            Ok(()) if to.metadata()?.len() == self.size => Ok(Some(to)),
            Ok(()) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{} changed size", self.name.display()),
            )),
            Err(e) => {
                debug!("reflink of {}: {e}", self.name.display());
                std::fs::remove_file(dest)?;
                Ok(None)
            }
        }
    }

    fn copy(&self, dest: &Path) -> io::Result<File> {
        let to = Self::create(dest)?;
        let n = copy_file(&self.file, &to, self.size, || Ok(()))?;
        if n != self.size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{} is shorter than it was", self.name.display()),
            ));
        }
        Ok(to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsverity_digest_of;
    use std::os::unix::fs::symlink;

    fn spec(path: &Path, kind: ForeignKind) -> ForeignStoreSpec {
        ForeignStoreSpec {
            path: path.to_path_buf(),
            kind,
            link: false,
        }
    }

    fn put(dir: &Path, rel: &str, body: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn vkey(alg: Algorithm, body: &[u8]) -> ForeignKey {
        ForeignKey::Verity(Digest::parse_fsverity(&fsverity_digest_of(alg, body)).unwrap())
    }

    fn ckey(body: &[u8]) -> ForeignKey {
        ForeignKey::Content(Digest::of(Algorithm::Sha256, body))
    }

    fn rel_of(key: &ForeignKey) -> String {
        match key {
            ForeignKey::Verity(d) => Object::of(d, false).unwrap().rel(),
            ForeignKey::Content(d) => {
                let h = d.hex();
                format!("{}/{}", &h[..2], &h[2..])
            }
        }
    }

    fn composefs_rs(alg: &str) -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        put(
            t.path(),
            "meta.json",
            format!(
                r#"{{"version":1,"algorithm":"fsverity-{alg}-12","features":{{"compatible":[],
                "read-only-compatible":["v1_erofs"],"incompatible":[]}},"erofs_formats":{{"default":1}}}}"#
            )
            .as_bytes(),
        );
        std::fs::create_dir(t.path().join("objects")).unwrap();
        t
    }

    fn n(body: &[u8]) -> u64 {
        body.len() as u64
    }

    fn import_to(c: &Candidate) -> (tempfile::TempDir, PathBuf, io::Result<Method>) {
        let d = tempfile::tempdir().unwrap();
        let dest = d.path().join("out");
        let r = c.import(&dest);
        (d, dest, r)
    }

    #[test]
    fn composefs_rs_finds_by_verity_in_its_algorithm_only() {
        let t = composefs_rs("sha256");
        let body = b"hello foreign world".repeat(100);
        let key = vkey(Algorithm::Sha256, &body);
        put(&t.path().join("objects"), &rel_of(&key), &body);
        let s = ForeignStore::open(&spec(t.path(), ForeignKind::ComposefsRs), None).unwrap();
        let found = s.lookup(&key, n(&body));
        assert_eq!(found.len(), 1);
        let (_d, dest, r) = import_to(&found[0]);
        assert_ne!(r.unwrap(), Method::Hardlink);
        assert_eq!(found[0].trust(), Trust::Unknown, "tmpfs has no fs-verity");
        assert_eq!(std::fs::read(dest).unwrap(), body);
        // the other algorithm, a content key and a wrong size are misses
        assert!(s
            .lookup(&vkey(Algorithm::Sha512, &body), n(&body))
            .is_empty());
        assert!(s.lookup(&ckey(&body), n(&body)).is_empty());
        assert!(s.lookup(&key, 1).is_empty());
    }

    #[test]
    fn composefs_rs_sha512_repository() {
        let t = composefs_rs("sha512");
        let body = b"x".repeat(5000);
        let key = vkey(Algorithm::Sha512, &body);
        put(&t.path().join("objects"), &rel_of(&key), &body);
        let s = ForeignStore::open(&spec(t.path(), ForeignKind::ComposefsRs), None).unwrap();
        assert_eq!(s.lookup(&key, n(&body)).len(), 1);
        assert!(s
            .lookup(&vkey(Algorithm::Sha256, &body), n(&body))
            .is_empty());
    }

    #[test]
    fn composefs_rs_refuses_what_it_does_not_know() {
        let bad = |meta: &str| {
            let t = tempfile::tempdir().unwrap();
            put(t.path(), "meta.json", meta.as_bytes());
            std::fs::create_dir(t.path().join("objects")).unwrap();
            ForeignStore::open(&spec(t.path(), ForeignKind::ComposefsRs), None)
                .err()
                .map(|e| e.to_string())
        };
        assert!(bad("garbage").unwrap().contains("meta.json"));
        assert!(bad(r#"{"version":2,"algorithm":"fsverity-sha256-12"}"#)
            .unwrap()
            .contains("version 2"));
        assert!(bad(r#"{"version":1,"algorithm":"fsverity-sha256-16"}"#)
            .unwrap()
            .contains("algorithm"));
        assert!(bad(
            r#"{"version":1,"algorithm":"fsverity-sha256-12","features":{"incompatible":["x"]}}"#
        )
        .unwrap()
        .contains("incompatible"));
        // no meta.json, no objects
        let t = tempfile::tempdir().unwrap();
        assert!(ForeignStore::open(&spec(t.path(), ForeignKind::ComposefsRs), None).is_err());
        // (the warning names what is missing)
        let e = ForeignStore::open(&spec(t.path(), ForeignKind::Velarx), None)
            .err()
            .unwrap()
            .to_string();
        assert!(e.starts_with("objects: "), "{e}");
        assert!(ForeignStore::open(&spec(t.path(), ForeignKind::ContainersStorage), None).is_err());
        // a relative path and a path that is not there
        assert!(ForeignStore::open(&spec(Path::new("rel"), ForeignKind::Velarx), None).is_err());
        assert!(
            ForeignStore::open(&spec(&t.path().join("none"), ForeignKind::Velarx), None).is_err()
        );
    }

    #[test]
    fn meta_json_that_is_a_link_or_a_fifo_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        put(
            outside.path(),
            "meta.json",
            br#"{"version":1,"algorithm":"fsverity-sha256-12"}"#,
        );
        symlink(outside.path().join("meta.json"), t.path().join("meta.json")).unwrap();
        std::fs::create_dir(t.path().join("objects")).unwrap();
        assert!(ForeignStore::open(&spec(t.path(), ForeignKind::ComposefsRs), None).is_err());
        std::fs::remove_file(t.path().join("meta.json")).unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            t.path().join("meta.json"),
            rustix::fs::Mode::RUSR,
        )
        .unwrap();
        assert!(ForeignStore::open(&spec(t.path(), ForeignKind::ComposefsRs), None).is_err());
    }

    #[test]
    fn velarx_store_has_both_algorithms() {
        let t = tempfile::tempdir().unwrap();
        let body = b"velarx object".repeat(50);
        for alg in Algorithm::ALL {
            let key = vkey(alg, &body);
            put(&t.path().join("objects"), &rel_of(&key), &body);
        }
        let s = ForeignStore::open(&spec(t.path(), ForeignKind::Velarx), None).unwrap();
        for alg in Algorithm::ALL {
            assert_eq!(s.lookup(&vkey(alg, &body), n(&body)).len(), 1);
        }
    }

    #[test]
    fn the_store_itself_is_not_foreign() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir(t.path().join("objects")).unwrap();
        let e = ForeignStore::open(&spec(t.path(), ForeignKind::Velarx), Some(t.path()))
            .err()
            .unwrap();
        assert!(e.to_string().contains("itself"));
        // reached by another name
        let l = tempfile::tempdir().unwrap();
        symlink(t.path(), l.path().join("alias")).unwrap();
        assert!(ForeignStore::open(
            &spec(&l.path().join("alias"), ForeignKind::Velarx),
            Some(t.path())
        )
        .is_err());
    }

    #[test]
    fn malicious_objects_are_not_candidates() {
        let t = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let body = b"secret".repeat(100);
        put(outside.path(), "target", &body);
        let objects = t.path().join("objects");
        std::fs::create_dir(&objects).unwrap();
        let s = ForeignStore::open(&spec(t.path(), ForeignKind::Velarx), None).unwrap();

        // a symbolic link out of the store
        let k1 = vkey(Algorithm::Sha256, &body);
        std::fs::create_dir_all(objects.join(rel_of(&k1)).parent().unwrap()).unwrap();
        symlink(outside.path().join("target"), objects.join(rel_of(&k1))).unwrap();
        assert!(s.lookup(&k1, n(&body)).is_empty());

        // a symbolic link in the fan-out directory
        let k2 = vkey(Algorithm::Sha256, b"other body");
        let rel2 = rel_of(&k2);
        symlink(outside.path(), objects.join(&rel2[..2])).unwrap();
        put(outside.path(), &rel2[3..], b"other body");
        assert!(s.lookup(&k2, n(b"other body")).is_empty());

        // a FIFO (not waited on), a directory, a device node
        let k3 = vkey(Algorithm::Sha256, b"fifo body");
        let p3 = objects.join(rel_of(&k3));
        std::fs::create_dir_all(p3.parent().unwrap()).unwrap();
        rustix::fs::mkfifoat(rustix::fs::CWD, &p3, rustix::fs::Mode::RUSR).unwrap();
        assert!(s.lookup(&k3, n(b"fifo body")).is_empty());
        let k4 = vkey(Algorithm::Sha256, b"dir body");
        std::fs::create_dir_all(objects.join(rel_of(&k4))).unwrap();
        assert!(s.lookup(&k4, n(b"dir body")).is_empty());
    }

    #[test]
    fn wrong_content_is_refused_and_leaves_nothing() {
        let t = tempfile::tempdir().unwrap();
        let body = b"the real content".repeat(64);
        let key = vkey(Algorithm::Sha256, &body);
        // right name and size, other content
        let mut forged = body.clone();
        forged[7] ^= 1;
        put(&t.path().join("objects"), &rel_of(&key), &forged);
        let s = ForeignStore::open(&spec(t.path(), ForeignKind::Velarx), None).unwrap();
        let found = s.lookup(&key, n(&body));
        assert_eq!(found.len(), 1);
        let (_d, dest, r) = import_to(&found[0]);
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(!dest.exists());
        // a reflink or a copy is hashed even of a file taken for one with
        // fs-verity (a clone shares blocks the kernel did not check)
        let d = tempfile::tempdir().unwrap();
        let dest = d.path().join("out");
        let r = found[0].import_as(&dest, Trust::Verity);
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(!dest.exists());
    }

    #[test]
    fn truncated_file_has_another_size() {
        let t = tempfile::tempdir().unwrap();
        let body = b"a long enough content".repeat(64);
        let key = vkey(Algorithm::Sha256, &body);
        put(
            &t.path().join("objects"),
            &rel_of(&key),
            &body[..body.len() / 2],
        );
        let s = ForeignStore::open(&spec(t.path(), ForeignKind::Velarx), None).unwrap();
        assert!(s.lookup(&key, n(&body)).is_empty());
        // at the size it has, the hash still refuses it
        let found = s.lookup(&key, n(&body) / 2);
        let (_d, dest, r) = import_to(&found[0]);
        assert!(r.is_err());
        assert!(!dest.exists());
    }

    #[test]
    fn file_that_changes_after_lookup_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let body = b"will be truncated".repeat(64);
        let key = vkey(Algorithm::Sha256, &body);
        put(&t.path().join("objects"), &rel_of(&key), &body);
        let s = ForeignStore::open(&spec(t.path(), ForeignKind::Velarx), None).unwrap();
        let found = s.lookup(&key, n(&body));
        // truncated by its owner while we hold it
        std::fs::OpenOptions::new()
            .write(true)
            .open(t.path().join("objects").join(rel_of(&key)))
            .unwrap()
            .set_len(10)
            .unwrap();
        let (_d, dest, r) = import_to(&found[0]);
        assert!(r.is_err());
        assert!(!dest.exists());
    }

    #[test]
    fn collected_while_open_still_imports_and_gone_is_a_miss() {
        let t = tempfile::tempdir().unwrap();
        let body = b"collected".repeat(100);
        let key = vkey(Algorithm::Sha256, &body);
        let path = t.path().join("objects").join(rel_of(&key));
        put(&t.path().join("objects"), &rel_of(&key), &body);
        let s = ForeignStore::open(&spec(t.path(), ForeignKind::Velarx), None).unwrap();
        let found = s.lookup(&key, n(&body));
        std::fs::remove_file(&path).unwrap();
        let (_d, dest, r) = import_to(&found[0]);
        r.unwrap();
        assert_eq!(std::fs::read(dest).unwrap(), body);
        assert!(s.lookup(&key, n(&body)).is_empty());
    }

    #[test]
    fn foreign_store_is_never_written() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let body = b"readonly".repeat(100);
        let key = vkey(Algorithm::Sha256, &body);
        let path = t.path().join("objects").join(rel_of(&key));
        put(&t.path().join("objects"), &rel_of(&key), &body);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let before = std::fs::metadata(&path).unwrap();
        let mut seen = Vec::new();
        let walk = |seen: &mut Vec<_>| {
            for e in walkdir(t.path()) {
                seen.push(e);
            }
        };
        walk(&mut seen);
        let s = ForeignStore::open(&spec(t.path(), ForeignKind::Velarx), None).unwrap();
        for c in s.lookup(&key, n(&body)) {
            let (_d, _dest, r) = import_to(&c);
            r.unwrap();
        }
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(before.mode(), after.mode());
        assert_eq!(before.mtime_nsec(), after.mtime_nsec());
        assert_eq!(before.nlink(), after.nlink());
        let mut now = Vec::new();
        walk(&mut now);
        assert_eq!(seen, now, "nothing was created in the foreign store");
    }

    fn walkdir(p: &Path) -> Vec<PathBuf> {
        let mut out = vec![p.to_path_buf()];
        if p.is_dir() {
            for e in std::fs::read_dir(p).unwrap() {
                out.extend(walkdir(&e.unwrap().path()));
            }
        }
        out.sort();
        out
    }

    #[test]
    fn hardlink_only_for_a_trusted_file_that_the_store_lets_link() {
        // (on a tmpfs, which does not clone, where there is one: a file
        // system that clones gives a reflink before any link)
        let t = tempfile::tempdir_in("/dev/shm")
            .or_else(|_| tempfile::tempdir())
            .unwrap();
        let body = b"linkable".repeat(100);
        let key = vkey(Algorithm::Sha256, &body);
        put(&t.path().join("objects"), &rel_of(&key), &body);
        let path = t.path().join("objects").join(rel_of(&key));
        let mut sp = spec(t.path(), ForeignKind::Velarx);
        let mut link_of = |link: bool, trust: Trust, dest: &Path| {
            sp.link = link;
            let s = ForeignStore::open(&sp, None).unwrap();
            let c = s.lookup(&key, n(&body)).pop().unwrap();
            c.import_as(dest, trust)
        };
        let out = tempfile::tempdir_in(t.path()).unwrap();
        // not allowed, or not trusted: never the same inode
        for (link, trust) in [(false, Trust::Verity), (true, Trust::Unknown)] {
            let dest = out.path().join(format!("{link}-{trust:?}"));
            let m = link_of(link, trust, &dest).unwrap();
            assert_ne!(m, Method::Hardlink);
            assert_ne!(
                std::fs::metadata(&dest).unwrap().ino(),
                std::fs::metadata(&path).unwrap().ino()
            );
        }
        assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 1);
        // allowed and trusted: the same inode, unchanged
        let mode = std::fs::metadata(&path).unwrap().mode();
        let dest = out.path().join("linked");
        let m = link_of(true, Trust::Verity, &dest).unwrap();
        if m == Method::Reflink {
            eprintln!("TMPDIR clones: the hard link is not tested");
            return;
        }
        assert_eq!(m, Method::Hardlink);
        assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 2);
        assert_eq!(std::fs::metadata(&path).unwrap().mode(), mode);
        assert_eq!(std::fs::read(&dest).unwrap(), body);
    }

    #[test]
    fn reflink_on_a_file_system_that_has_it() {
        // /var/tmp is XFS or btrfs on the development hosts; skip elsewhere
        let t = tempfile::tempdir_in("/var/tmp").unwrap();
        let body = b"cloned".repeat(2000);
        let key = vkey(Algorithm::Sha256, &body);
        put(&t.path().join("objects"), &rel_of(&key), &body);
        let s = ForeignStore::open(&spec(t.path(), ForeignKind::Velarx), None).unwrap();
        let c = s.lookup(&key, n(&body)).pop().unwrap();
        let out = tempfile::tempdir_in(t.path()).unwrap();
        let m = c.import(&out.path().join("f")).unwrap();
        // (a reflink where the file system clones)
        let clones = {
            let probe = t.path().join("probe");
            std::fs::write(&probe, b"x").unwrap();
            std::process::Command::new("cp")
                .args(["--reflink=always"])
                .arg(&probe)
                .arg(t.path().join("probe2"))
                .status()
                .is_ok_and(|s| s.success())
        };
        assert_eq!(
            m,
            if clones {
                Method::Reflink
            } else {
                Method::Copy
            }
        );
        assert_eq!(std::fs::read(out.path().join("f")).unwrap(), body);
    }

    #[test]
    fn a_destination_on_another_file_system_is_a_copy() {
        // /dev/shm is a tmpfs, /var/tmp is not
        let t = tempfile::tempdir_in("/var/tmp").unwrap();
        let Ok(out) = tempfile::tempdir_in("/dev/shm") else {
            return;
        };
        let body = b"across".repeat(100);
        let key = vkey(Algorithm::Sha256, &body);
        put(&t.path().join("objects"), &rel_of(&key), &body);
        let mut sp = spec(t.path(), ForeignKind::Velarx);
        sp.link = true;
        let s = ForeignStore::open(&sp, None).unwrap();
        let c = s.lookup(&key, n(&body)).pop().unwrap();
        if std::fs::metadata(out.path()).unwrap().dev() == c.dev {
            return;
        }
        let m = c.import_as(&out.path().join("f"), Trust::Verity).unwrap();
        assert_eq!(m, Method::Copy);
    }

    /// A containers/storage root with an image of two layers and a container.
    fn containers_storage() -> (tempfile::TempDir, [String; 4]) {
        let t = tempfile::tempdir().unwrap();
        let id = |c: char| c.to_string().repeat(64);
        let (base, top, ctr, other) = (id('a'), id('b'), id('c'), id('d'));
        put(
            t.path(),
            "overlay-images/images.json",
            format!(r#"[{{"id":"i","layer":"{top}"}}]"#).as_bytes(),
        );
        put(
            t.path(),
            "overlay-layers/layers.json",
            format!(
                r#"[{{"id":"{base}"}},{{"id":"{top}","parent":"{base}"}},
                {{"id":"{ctr}","parent":"{top}"}},{{"id":"{other}"}}]"#
            )
            .as_bytes(),
        );
        put(
            t.path(),
            "overlay-containers/containers.json",
            format!(r#"[{{"id":"c1","layer":"{ctr}"}}]"#).as_bytes(),
        );
        std::fs::create_dir_all(t.path().join("overlay")).unwrap();
        (t, [base, top, ctr, other])
    }

    #[test]
    fn containers_storage_finds_image_layers_by_sha256_never_container_layers() {
        let body = b"podman file".repeat(100);
        let key = ckey(&body);
        let (t, [base, top, ctr, other]) = containers_storage();
        let rel = rel_of(&key);
        // the same file in a container layer, an unreferenced layer, and
        // an image layer
        put(
            &t.path().join("overlay").join(&ctr).join("diff"),
            &rel,
            &body,
        );
        put(
            &t.path().join("overlay").join(&other).join("diff"),
            &rel,
            &body,
        );
        put(
            &t.path()
                .join("overlay")
                .join(format!("{ctr}-init"))
                .join("diff"),
            &rel,
            &body,
        );
        let s = ForeignStore::open(&spec(t.path(), ForeignKind::ContainersStorage), None).unwrap();
        assert!(
            s.lookup(&key, n(&body)).is_empty(),
            "container data is never read"
        );
        put(
            &t.path().join("overlay").join(&base).join("diff"),
            &rel,
            &body,
        );
        let found = s.lookup(&key, n(&body));
        assert_eq!(found.len(), 1);
        assert!(found[0].name().to_string_lossy().contains(&base));
        let _ = top;
        let (_d, dest, r) = import_to(&found[0]);
        r.unwrap();
        assert_eq!(std::fs::read(dest).unwrap(), body);
        // a verity key means nothing here
        assert!(s
            .lookup(&vkey(Algorithm::Sha256, &body), n(&body))
            .is_empty());
    }

    #[test]
    fn containers_storage_forged_file_and_bad_metadata() {
        let body = b"podman file".repeat(100);
        let key = ckey(&body);
        let (t, [base, ..]) = containers_storage();
        // the right name and size, other content
        let mut forged = body.clone();
        forged[0] ^= 1;
        put(
            &t.path().join("overlay").join(&base).join("diff"),
            &rel_of(&key),
            &forged,
        );
        let s = ForeignStore::open(&spec(t.path(), ForeignKind::ContainersStorage), None).unwrap();
        let found = s.lookup(&key, n(&body));
        assert_eq!(found.len(), 1);
        let (_d, dest, r) = import_to(&found[0]);
        assert!(r.is_err());
        assert!(!dest.exists());
        // without the list of images the scope cannot be known: not used
        std::fs::remove_file(t.path().join("overlay-images/images.json")).unwrap();
        assert!(ForeignStore::open(&spec(t.path(), ForeignKind::ContainersStorage), None).is_err());
        put(t.path(), "overlay-images/images.json", b"{not json");
        assert!(ForeignStore::open(&spec(t.path(), ForeignKind::ContainersStorage), None).is_err());
    }

    #[test]
    fn containers_storage_layer_ids_are_checked_and_chains_end() {
        let t = tempfile::tempdir().unwrap();
        let a = "a".repeat(64);
        put(
            t.path(),
            "overlay-images/images.json",
            format!(
                r#"[{{"layer":"../../etc"}},{{"layer":"{a}"}},{{"layer":"{}/x"}}]"#,
                "b".repeat(64)
            )
            .as_bytes(),
        );
        // a loop of parents, an id that is no id
        put(
            t.path(),
            "overlay-layers/layers.json",
            format!(r#"[{{"id":"{a}","parent":"{a}"}}]"#).as_bytes(),
        );
        std::fs::create_dir_all(t.path().join("overlay")).unwrap();
        let root = open_dir(t.path()).unwrap();
        assert_eq!(image_layers(&root).unwrap(), vec![a]);
    }

    #[test]
    fn containers_storage_metadata_is_bounded() {
        let t = tempfile::tempdir_in("/var/tmp").unwrap();
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        // many small elements and ids that are none are dropped as read; a
        // mapped top layer is an image layer
        let mut images = String::from("[");
        for _ in 0..100_000 {
            images.push_str(r#"{"names":["x"],"mapped-top-layers":["","..",null]},"#);
        }
        images.push_str(&format!(
            r#"{{"layer":"{a}","mapped-top-layers":["{b}",""]}}]"#
        ));
        put(t.path(), "overlay-images/images.json", images.as_bytes());
        put(
            t.path(),
            "overlay-layers/layers.json",
            format!(r#"[{{"id":"{a}","parent":"../x"}},{{"id":"{b}","parent":"{a}"}}]"#).as_bytes(),
        );
        let root = open_dir(t.path()).unwrap();
        // (a null in the list of mapped layers is no string: not used)
        assert!(image_layers(&root).is_err());
        let images = images.replace(",null]", "]");
        put(t.path(), "overlay-images/images.json", images.as_bytes());
        assert_eq!(image_layers(&root).unwrap(), vec![a.clone(), b]);
        // a metadata file over the limit is not read
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(t.path().join("overlay-layers/layers.json"))
            .unwrap();
        f.set_len(MAX_METADATA + 1).unwrap();
        let e = image_layers(&root).unwrap_err().to_string();
        assert!(e.contains("larger than"), "{e}");
        // not an array, trailing garbage
        for bad in ["{}", "[] x", "[{\"id\":1}]"] {
            put(t.path(), "overlay-layers/layers.json", bad.as_bytes());
            assert!(image_layers(&root).is_err(), "{bad}");
        }
    }

    /// On a file system with fs-verity (VELARX_VERITY_DIR, e.g. an ext4 made
    /// with `-O verity`): the kernel's measurement of a foreign file, the
    /// hard link of one that has fs-verity, and of nothing else.
    #[test]
    fn verity_files_are_measured_and_linked_on_a_verity_filesystem() {
        use crate::{FsVerityConfig, FsVerityHashAlgorithm, FsVerityManager};
        let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") else {
            eprintln!("VELARX_VERITY_DIR not set: skipped");
            return;
        };
        let t = tempfile::tempdir_in(&dir).unwrap();
        let out = tempfile::tempdir_in(&dir).unwrap();
        let ino = |p: &Path| std::fs::metadata(p).unwrap().ino();
        for alg in Algorithm::ALL {
            let enable = |p: &Path| {
                FsVerityManager::with_config(FsVerityConfig {
                    hash_algorithm: FsVerityHashAlgorithm::of(alg),
                    ..FsVerityConfig::default()
                })
                .enable(p)
                .unwrap()
            };
            let body = format!("verity {alg} ").repeat(3000).into_bytes();
            let key = vkey(alg, &body);
            let path = t.path().join("objects").join(rel_of(&key));
            put(&t.path().join("objects"), &rel_of(&key), &body);
            let mut sp = spec(t.path(), ForeignKind::Velarx);
            sp.link = true;
            let store = ForeignStore::open(&sp, None).unwrap();
            // without fs-verity: not trusted, copied (ext4 does not clone)
            // and hashed
            let c = store.lookup(&key, n(&body)).pop().unwrap();
            assert_eq!(c.trust(), Trust::Unknown);
            let dest = out.path().join(format!("{alg}-plain"));
            assert_eq!(c.import(&dest).unwrap(), Method::Copy);
            assert_ne!(ino(&dest), ino(&path));
            drop(c);
            enable(&path);
            let mode = std::fs::metadata(&path).unwrap().mode();
            let c = store.lookup(&key, n(&body)).pop().unwrap();
            assert_eq!(c.trust(), Trust::Verity);
            let dest = out.path().join(format!("{alg}-linked"));
            assert_eq!(c.import(&dest).unwrap(), Method::Hardlink);
            assert_eq!(ino(&dest), ino(&path));
            assert_eq!(std::fs::metadata(&path).unwrap().mode(), mode);
            assert_eq!(std::fs::read(&dest).unwrap(), body);
            // the store does not allow links: a copy
            sp.link = false;
            let c = ForeignStore::open(&sp, None)
                .unwrap()
                .lookup(&key, n(&body))
                .pop()
                .unwrap();
            let dest = out.path().join(format!("{alg}-copy"));
            assert_eq!(c.import(&dest).unwrap(), Method::Copy);
            assert_ne!(ino(&dest), ino(&path));
            // fs-verity of other content under the name: not trusted, and
            // refused by the hash
            let mut forged = body.clone();
            forged[3] ^= 1;
            std::fs::remove_file(&path).unwrap();
            put(&t.path().join("objects"), &rel_of(&key), &forged);
            enable(&path);
            let c = store.lookup(&key, n(&body)).pop().unwrap();
            assert_eq!(c.trust(), Trust::Unknown);
            let dest = out.path().join(format!("{alg}-forged"));
            assert_eq!(
                c.import(&dest).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(!dest.exists());
            // as root: a file of another user is not linked (its owner could
            // chmod or relabel what would be our file)
            if rustix::process::geteuid().is_root() {
                std::fs::remove_file(&path).unwrap();
                put(&t.path().join("objects"), &rel_of(&key), &body);
                enable(&path);
                std::os::unix::fs::chown(&path, Some(65534), Some(65534)).unwrap();
                let c = store.lookup(&key, n(&body)).pop().unwrap();
                assert_eq!(c.trust(), Trust::Verity);
                let dest = out.path().join(format!("{alg}-other-owner"));
                assert_eq!(c.import(&dest).unwrap(), Method::Copy);
                assert_ne!(ino(&dest), ino(&path));
            }
        }
    }

    #[test]
    fn stores_skips_unusable_ones_without_error() {
        let good = composefs_rs("sha256");
        let bad = tempfile::tempdir().unwrap();
        let specs = [
            spec(&bad.path().join("missing"), ForeignKind::Velarx),
            spec(bad.path(), ForeignKind::ComposefsRs),
            spec(good.path(), ForeignKind::ComposefsRs),
        ];
        let stores = ForeignStores::open(&specs, None);
        assert_eq!(stores.stores().len(), 1);
        assert_eq!(stores.stores()[0].kind(), ForeignKind::ComposefsRs);
        assert!(ForeignStores::open(&[], None).is_empty());
    }

    #[test]
    fn spec_parses_and_refuses_unknown_fields() {
        let s: ForeignStoreSpec =
            serde_json::from_str(r#"{"path":"/x","kind":"containers-storage","link":true}"#)
                .unwrap();
        assert_eq!(s.kind, ForeignKind::ContainersStorage);
        assert!(s.link);
        assert!(
            serde_json::from_str::<ForeignStoreSpec>(r#"{"path":"/x","kind":"other"}"#).is_err()
        );
        assert!(
            serde_json::from_str::<ForeignStoreSpec>(r#"{"path":"/x","kind":"velarx","z":1}"#)
                .is_err()
        );
    }
}
