// SPDX-License-Identifier: Apache-2.0
//! Where the bytes of a pull go: the sink.
//!
//! The pull code fetches, decompresses and checks the chunks of a layer and
//! writes them into files.  It does not care whose files they are.  A [`Stage`]
//! is what the writers need (a place for the content of a key, the notice of a
//! complete file, the files of the store to read a chunk from); a [`Sink`] is
//! a stage that also answers the questions the planning of a pull asks (which
//! files are there already, where to make the scratch files).
//!
//! Two kinds exist:
//!
//! * the staging [`Session`] of a store in this process (composefs): the
//!   files are made in its directory, under names that are no digest, known
//!   by what they are known by when they are complete, and given the name of
//!   their fs-verity digest as they move into the store at the commit.  It keeps
//!   what is staged, reads chunks from the store, and the pull replays the
//!   layer over the staged files to prove its diff id as the files arrive;
//! * a driver with files of its own (the `varlink` driver): [`Stage::place`]
//!   gives the file and the offset the driver chose for a key, the bytes are
//!   written there, `adopt` tells the driver a key is whole, and the diff id
//!   is not proved here: the engine reads the layer back from the driver
//!   ([`Sink::proves_in_fetch`] is false);

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::session::Session;
use super::staged_fetch::LayerStaging;
use velarx_types::digest::{Algorithm, Digest, DigestWriter};

/// A file that is complete and verified, for the stage to give its place.
pub struct Finished {
    /// The file, when the stage takes it ([`Stage::takes_files`]); else the
    /// stage names it by its path
    pub file: Option<Arc<File>>,
    pub temp: Option<PathBuf>,
    /// What the file is known by
    pub key: String,
    pub name: String,
    pub size: u64,
    /// The key is the fs-verity digest the TOC gives: the commit refuses
    /// a file with another
    pub verity_keyed: bool,
}

/// The place of the content of a key: `size` bytes from `base` in `file`.
pub struct Placement {
    pub file: Arc<File>,
    /// Where the content starts in the file: 0 for a file of its own.
    pub base: u64,
    /// The path the file has until it is adopted (none when it has no name).
    pub temp: Option<PathBuf>,
}

/// Files from this size are read by the replay while they are written.
pub const FOLLOW_MIN: u64 = 4 << 20;

/// Where the files of a layer are written and handed to: the session of the
/// pull, a job that sends them to it, or the files of a driver.
pub trait Stage: Send + Sync {
    /// A new file for content whose digest is not known yet, and the path
    /// it has until it is adopted (none when it has no name).
    fn create_temp(&self) -> io::Result<(File, Option<PathBuf>)>;
    /// A name of the stage for `file`, which has none: linked to it, not
    /// copied.
    fn link_temp(&self, _file: &File) -> io::Result<PathBuf> {
        Err(not_here("a file with a name"))
    }
    /// The place for the content of `key` (`size` bytes): the file is at
    /// least `base + size` bytes long, and nothing but this content is
    /// written there.  The default is a file of its own, sized.
    fn place(&self, _key: &str, size: u64) -> io::Result<Placement> {
        let (file, temp) = self.create_temp()?;
        file.set_len(size)?;
        Ok(Placement {
            file: Arc::new(file),
            base: 0,
            temp,
        })
    }
    /// Give a complete file its place; whether it was kept.
    fn adopt(&self, finished: Finished) -> io::Result<bool>;
    /// A file of at least [`FOLLOW_MIN`] bytes was created: the stage may
    /// let the replay read it while it is written.
    fn opened(&self, _key: &str, _size: u64, _file: &File) {}
    /// `len` bytes from `at` of the content of `key` are zeros: a hole of
    /// the file, which the stage may leave as it is.
    fn hole(&self, _key: &str, _at: u64, _len: u64) {}
    /// The file of the store with this content, to read a chunk from.
    fn open_object(&self, digest: &str) -> io::Result<File>;
    /// `len` bytes from `from_offset` of the object `from`, which the owner
    /// of the stage holds, are the bytes of `key` from `at`: the stage's
    /// owner copies them itself, and the engine fetches and writes nothing.
    /// Whether the stage took the copy (it did not: the bytes are read from
    /// `open_object` and written as any chunk is).
    fn copy_chunk(
        &self,
        _key: &str,
        _at: u64,
        _from: &str,
        _from_offset: u64,
        _len: u64,
    ) -> io::Result<bool> {
        Ok(false)
    }
    /// Where the content is, for a replay that follows the download.
    fn content_path(&self, digest: &str) -> Option<PathBuf>;
    /// The digest of the content of `key` at its place, of the kind the key
    /// is (its fs-verity digest, or the hash of its content), measured when
    /// the key is whole: for a stage whose files nothing checks after the
    /// fetch.  None for a stage that checks them itself (the commit of a
    /// session measures every file by its key; the parent of a job reads
    /// what the job gives it).
    fn measure(&self, _key: &str) -> io::Result<Option<Digest>> {
        Ok(None)
    }
}

/// What a pull needs of the place it writes to, beyond the files of
/// [`Stage`].
pub trait Sink: Stage {
    fn as_any(&self) -> &dyn std::any::Any;
    /// The name of the pull this sink is for (its staging session, or the id
    /// the driver knows it by).
    fn name(&self) -> String;
    /// A directory of the engine's, closed to others, for the files with no
    /// name the pull makes (metadata, the files of a job).
    fn dir(&self) -> &Path;
    /// Whether the file known by `key`, of `size` bytes, is there already
    /// and whole, so that it is not fetched.
    fn holds(&self, key: &str, size: u64) -> bool;
    /// Whether the content of `key` is read from the store's own file only.
    fn in_store_only(&self, key: &str) -> bool;
    /// The file of the store the key names, to read chunks from; none when
    /// the sink has no store of the engine's.
    fn store_path(&self, key: &str) -> Option<PathBuf>;
    /// Which of the objects `keys` the sink can take a chunk from, in the
    /// order asked: the files of the store the sink has, or the objects a
    /// storage driver says it holds.  May block.
    fn held(&self, keys: &[String]) -> io::Result<Vec<bool>> {
        Ok(keys.iter().map(|k| self.store_path(k).is_some()).collect())
    }
    /// The file `name` staged as `key` is known by its fs-verity digest.
    fn known_by_verity(&self, key: &str, name: &str);
    /// Stage content that is in memory; whether it was added.
    fn put_as(&self, key: &str, data: &[u8]) -> io::Result<bool>;
    /// Stage the `size` bytes `entry` reads, known by their hash in `alg`;
    /// the key and whether it was added.  None: this sink has no way of its
    /// own to take a stream, and the content goes through files with a name.
    fn put_reader(
        &self,
        _alg: Algorithm,
        _entry: &mut dyn Read,
        _size: u64,
    ) -> io::Result<Option<(String, bool)>> {
        Ok(None)
    }
    /// Stage the complete file `temp` as `key`; whether it was kept.
    fn adopt_as(&self, temp: &Path, key: &str, size: u64) -> io::Result<bool>;
    /// [`Sink::adopt_as`] for a file whose content was hashed (`key`, the
    /// hash of the layer's algorithm) and measured (`verity`, its fs-verity
    /// digest) in the one pass that wrote it: a sink that has the file by its
    /// fs-verity digest drops `temp`, and the file is known by `verity`.  The
    /// key the file is known by, and whether it was added.
    fn adopt_measured(
        &self,
        temp: &Path,
        key: &str,
        _verity: &str,
        size: u64,
    ) -> io::Result<(String, bool)> {
        self.adopt_as(temp, key, size)
            .map(|added| (key.to_string(), added))
    }
    /// [`Sink::adopt_measured`] for content in memory, which a sink that has
    /// the file does not write.
    fn put_measured(&self, key: &str, _verity: &str, data: &[u8]) -> io::Result<(String, bool)> {
        self.put_as(key, data).map(|added| (key.to_string(), added))
    }
    /// Give a complete file with no name its place as `key`; whether it was
    /// kept.
    fn adopt_file(&self, file: &File, key: &str, verity_keyed: Option<&str>) -> io::Result<bool>;
    /// Give the file `file`, which a fetcher staged as `key` in the staging
    /// of `layer` and the engine opened and measured, its place as `key`.
    /// The default takes the bytes ([`Sink::adopt_file`]) and the name of the
    /// file in the staging goes (unless a lazy pull keeps the layer, whose
    /// containers find the file there); a session commits it where it is,
    /// which it holds the staging for.
    fn adopt_staged(
        &self,
        layer: &Arc<LayerStaging>,
        file: &File,
        key: &str,
        verity_keyed: Option<&str>,
    ) -> io::Result<bool> {
        let kept = self.adopt_file(file, key, verity_keyed)?;
        if !layer.kept() {
            layer.forget_name(key);
        }
        Ok(kept)
    }
    /// Give the file `file`, which the engine verified (its fs-verity digest
    /// is `verity`: [`super::commit::verify_file`]) and handed over, its place
    /// as `key`: the sink keeps it its own way (a link of the inode where the
    /// file system allows, else a copy of its own) and names it by `verity`
    /// without reading it.  The sink of a driver that trusts the engine.
    fn adopt_verified(
        &self,
        _file: &File,
        _key: &str,
        _verity: &str,
    ) -> io::Result<super::session::Adopted> {
        Err(not_here("a file the engine verified"))
    }
    /// A sink inside this one, for what is not checked yet.
    fn scratch(self: Arc<Self>) -> io::Result<Arc<dyn Sink>>;
    /// Move what this sink staged and `keep` names into `other`.
    fn transfer_into(&self, other: &dyn Sink, keep: &HashSet<&str>) -> io::Result<Vec<String>>;
    /// The layer is replayed over the staged files while they arrive, which
    /// proves its diff id and builds the table of contents it records.  A
    /// sink that is not proved here is read back by the engine.
    fn proves_in_fetch(&self) -> bool {
        true
    }
    /// The staging session, for the sink of a store in this process.
    fn session(self: Arc<Self>) -> Option<Arc<Session>> {
        None
    }
}

impl Stage for Session {
    fn create_temp(&self) -> io::Result<(File, Option<PathBuf>)> {
        Session::create_temp(self).map(|(f, p)| (f, Some(p)))
    }

    fn link_temp(&self, file: &File) -> io::Result<PathBuf> {
        Session::link_temp(self, file)
    }

    fn adopt(&self, finished: Finished) -> io::Result<bool> {
        if finished.verity_keyed {
            self.known_by_verity(&finished.key, &finished.name);
        }
        let temp = finished
            .temp
            .ok_or_else(|| io::Error::other("a file of the session has a name"))?;
        self.adopt_as(&temp, &finished.key, finished.size)
    }

    fn open_object(&self, digest: &str) -> io::Result<File> {
        let path = self
            .store()
            .get_path(digest)
            .ok_or_else(|| io::Error::other(format!("{digest} is not in the store any more")))?;
        File::open(path)
    }

    fn content_path(&self, digest: &str) -> Option<PathBuf> {
        Session::content_path(self, digest)
    }
}

impl Sink for Session {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> String {
        Session::name(self)
    }

    fn dir(&self) -> &Path {
        Session::dir(self)
    }

    fn holds(&self, key: &str, size: u64) -> bool {
        Session::holds(self, key, size)
    }

    fn in_store_only(&self, key: &str) -> bool {
        Session::in_store_only(self, key)
    }

    fn store_path(&self, key: &str) -> Option<PathBuf> {
        self.store().get_path(key)
    }

    fn known_by_verity(&self, key: &str, name: &str) {
        Session::known_by_verity(self, key, name)
    }

    fn put_as(&self, key: &str, data: &[u8]) -> io::Result<bool> {
        Session::put_as(self, key, data)
    }

    fn adopt_as(&self, temp: &Path, key: &str, size: u64) -> io::Result<bool> {
        Session::adopt_as(self, temp, key, size)
    }

    fn adopt_verified(
        &self,
        file: &File,
        key: &str,
        verity: &str,
    ) -> io::Result<super::session::Adopted> {
        Session::adopt_verified(self, file, key, verity)
    }

    fn adopt_measured(
        &self,
        temp: &Path,
        key: &str,
        verity: &str,
        size: u64,
    ) -> io::Result<(String, bool)> {
        Session::adopt_measured(self, temp, key, verity, size)
    }

    fn put_measured(&self, key: &str, verity: &str, data: &[u8]) -> io::Result<(String, bool)> {
        Session::put_measured(self, key, verity, data)
    }

    fn adopt_file(&self, file: &File, key: &str, verity_keyed: Option<&str>) -> io::Result<bool> {
        Session::adopt_file(self, file, key, verity_keyed)
    }

    fn adopt_staged(
        &self,
        layer: &Arc<LayerStaging>,
        file: &File,
        key: &str,
        verity_keyed: Option<&str>,
    ) -> io::Result<bool> {
        Session::adopt_staged(self, layer, file, key, verity_keyed)
    }

    fn scratch(self: Arc<Self>) -> io::Result<Arc<dyn Sink>> {
        Session::scratch(&self).map(|s| s as Arc<dyn Sink>)
    }

    fn transfer_into(&self, other: &dyn Sink, keep: &HashSet<&str>) -> io::Result<Vec<String>> {
        let other = other.as_any().downcast_ref::<Session>().ok_or_else(|| {
            io::Error::other("only a staging session takes what a session staged")
        })?;
        Session::transfer_into(self, other, keep)
    }

    fn session(self: Arc<Self>) -> Option<Arc<Session>> {
        Some(self)
    }
}

/// A place the caller chose for the content of a key.
pub struct Slot {
    /// Shared by the slots of one file (the pack file of a call).
    pub file: Arc<File>,
    /// Where the content starts in `file`.
    pub base: u64,
    pub size: u64,
}

/// What a [`FilesSink`] tells of the files as they are written.
pub enum Written {
    /// `len` bytes from `at` of the content of the key are zeros.
    Hole { key: String, at: u64, len: u64 },
    /// The content of the key is whole, every chunk of it checked.
    Whole { key: String },
    /// The content of the key is whole and verified by the engine, which
    /// hands the file itself over (no byte of it is written to a place of
    /// the driver): `verity` is its fs-verity digest.  The driver keeps the
    /// file its own way (a link where it can, else a copy of its own).
    Staged {
        key: String,
        file: Arc<File>,
        verity: String,
        /// The staging of the layer the file is in: its name there must
        /// last until the driver has linked the file, which the caller
        /// ensures by holding this until then
        layer: Arc<LayerStaging>,
    },
    /// `len` bytes from `at` of the content of the key are the bytes from
    /// `from_offset` of the object `from` of the caller: it copies them, and
    /// the key is not measured here (the engine reads the layer back).
    Copy {
        key: String,
        at: u64,
        from: String,
        from_offset: u64,
        len: u64,
    },
}

/// What says which of a list of objects a driver holds.
pub type Holds = Arc<dyn Fn(&[String]) -> io::Result<Vec<bool>> + Send + Sync>;

/// A sink over files the caller hands over: the files of a storage driver.
/// Each key it is given is written at its place (`Stage::place`), the
/// content of a key that is whole is told to `told`, and nothing else is
/// kept or read: the layer is not replayed here, the engine reads it back
/// from the driver to prove its diff id.
pub struct FilesSink {
    name: String,
    dir: PathBuf,
    slots: std::collections::HashMap<String, Slot>,
    told: Box<dyn Fn(Written) + Send + Sync>,
    /// The objects the driver holds, when it can be asked
    holds: Option<Holds>,
    /// The keys with a chunk the driver copies: their content is not whole
    /// here, so it is not measured
    copied: Mutex<HashSet<String>>,
    /// The keys told whole whose every chunk this process checked as it
    /// wrote it
    checked: Mutex<HashSet<String>>,
    /// The bytes of the files handed over that were read to verify them
    /// (once each: tests count them)
    hashed: std::sync::atomic::AtomicU64,
}

impl FilesSink {
    /// A sink for the `slots` (key and place); `dir` is a directory of the
    /// engine's for the files with no name it makes while it fetches.  The
    /// files are made at least as long as their content ends: a file that
    /// holds several keys is as long as the last ends.
    pub fn new(
        name: &str,
        dir: &Path,
        slots: impl IntoIterator<Item = (String, Slot)>,
        told: impl Fn(Written) + Send + Sync + 'static,
    ) -> io::Result<Arc<Self>> {
        Self::holding(name, dir, slots, told, None)
    }

    /// [`FilesSink::new`] for a driver that says which objects it holds
    /// (`holds`): a chunk another object of it has is copied by the driver
    /// (`Written::Copy`), not fetched.
    pub fn holding(
        name: &str,
        dir: &Path,
        slots: impl IntoIterator<Item = (String, Slot)>,
        told: impl Fn(Written) + Send + Sync + 'static,
        holds: Option<Holds>,
    ) -> io::Result<Arc<Self>> {
        let slots: std::collections::HashMap<String, Slot> = slots.into_iter().collect();
        // (the end of each file once: a pack file has a slot for each of
        // its objects, and the file system is asked its length once for the
        // file, not for each)
        let mut ends: std::collections::HashMap<*const File, (&File, u64)> = Default::default();
        for slot in slots.values() {
            let end = slot
                .base
                .checked_add(slot.size)
                .ok_or_else(|| io::Error::other("a place ends beyond the file"))?;
            let e = ends
                .entry(Arc::as_ptr(&slot.file))
                .or_insert((&slot.file, 0));
            e.1 = e.1.max(end);
        }
        for (file, end) in ends.into_values() {
            if file.metadata()?.len() < end {
                file.set_len(end)?;
            }
        }
        Ok(Arc::new(Self {
            name: name.to_string(),
            dir: dir.to_path_buf(),
            slots,
            told: Box::new(told),
            holds,
            copied: Mutex::default(),
            checked: Mutex::default(),
            hashed: 0.into(),
        }))
    }

    /// A sink with no place yet, for the context of a pull before its first
    /// fetch.
    pub fn none(name: &str, dir: &Path) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            dir: dir.to_path_buf(),
            slots: Default::default(),
            told: Box::new(|_| {}),
            holds: None,
            copied: Mutex::default(),
            checked: Mutex::default(),
            hashed: 0.into(),
        })
    }

    /// The bytes read to verify the files handed over.
    pub fn hashed(&self) -> u64 {
        self.hashed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether `key` has a place here.
    pub fn wants(&self, key: &str) -> bool {
        self.slots.contains_key(key)
    }

    /// The keys told whole whose every chunk this process checked against the
    /// table of contents as it wrote it: not one with a chunk the driver
    /// copies.  Where the chunks of the table of
    /// contents are in these objects is what they are.
    pub fn chunks_checked(&self) -> HashSet<String> {
        self.checked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

fn not_here(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what}: the files of a storage driver are written at the places it chose"),
    )
}

impl Stage for FilesSink {
    fn create_temp(&self) -> io::Result<(File, Option<PathBuf>)> {
        Err(not_here("a file with no place"))
    }

    fn place(&self, key: &str, size: u64) -> io::Result<Placement> {
        let slot = self
            .slots
            .get(key)
            .ok_or_else(|| io::Error::other(format!("{key} has no place in the files given")))?;
        if slot.size != size {
            return Err(io::Error::other(format!(
                "{key} has {size} bytes in the layer and a place for {}",
                slot.size
            )));
        }
        Ok(Placement {
            file: slot.file.clone(),
            base: slot.base,
            temp: None,
        })
    }

    fn adopt(&self, finished: Finished) -> io::Result<bool> {
        let lock = |m: &Mutex<HashSet<String>>| {
            m.lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&finished.key)
        };
        if !lock(&self.copied) {
            self.checked
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(finished.key.clone());
        }
        (self.told)(Written::Whole { key: finished.key });
        Ok(true)
    }

    fn hole(&self, key: &str, at: u64, len: u64) {
        (self.told)(Written::Hole {
            key: key.to_string(),
            at,
            len,
        });
    }

    fn open_object(&self, digest: &str) -> io::Result<File> {
        Err(not_here(&format!("{digest} cannot be read here")))
    }

    fn content_path(&self, _digest: &str) -> Option<PathBuf> {
        None
    }

    fn copy_chunk(
        &self,
        key: &str,
        at: u64,
        from: &str,
        from_offset: u64,
        len: u64,
    ) -> io::Result<bool> {
        let Some(slot) = self.slots.get(key) else {
            return Err(io::Error::other(format!(
                "{key} has no place in the files given"
            )));
        };
        if self.holds.is_none() || at.checked_add(len).is_none_or(|end| end > slot.size) {
            return Ok(false);
        }
        self.copied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string());
        (self.told)(Written::Copy {
            key: key.to_string(),
            at,
            from: from.to_string(),
            from_offset,
            len,
        });
        Ok(true)
    }

    /// The bytes at the place of `key`, read back and hashed the way the
    /// key says: the chunks of a file are checked as they arrive, but not
    /// that the file is what its key names (the one chunk of a file known by
    /// the hash of its content has no digest of its own, and nothing in the
    /// table of contents ties an fs-verity digest to the chunks), and a
    /// driver keeps an object by its key.
    fn measure(&self, key: &str) -> io::Result<Option<Digest>> {
        // (a chunk the driver copies is not at its place yet: the engine
        // reads the object back from the driver when it proves the layer)
        if self
            .copied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(key)
        {
            return Ok(None);
        }
        let slot = self
            .slots
            .get(key)
            .ok_or_else(|| io::Error::other(format!("{key} has no place in the files given")))?;
        let kind = Digest::parse_key(key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{key}: {e}")))?;
        measure_place(&slot.file, slot.base, slot.size, &kind).map(Some)
    }
}

/// The digest of the `size` bytes from `base` in `file`, of the kind of
/// `kind` (its fs-verity digest or the hash of the content, in its
/// algorithm).
pub fn measure_place(file: &File, base: u64, size: u64, kind: &Digest) -> io::Result<Digest> {
    use std::os::unix::fs::FileExt;
    let mut verity = kind
        .is_fsverity()
        .then(|| velarx_storage::VerityHasher::new(kind.alg()));
    let mut content = DigestWriter::new(kind.alg());
    let mut buf = vec![0u8; size.min(1 << 20) as usize];
    let mut at = 0u64;
    while at < size {
        let n = (size - at).min(buf.len() as u64) as usize;
        let end = base
            .checked_add(at)
            .ok_or_else(|| io::Error::other("a place ends beyond the file"))?;
        file.read_exact_at(&mut buf[..n], end)?;
        match &mut verity {
            Some(v) => v.update(&buf[..n]),
            None => content.update(&buf[..n]),
        }
        at += n as u64;
    }
    match verity {
        Some(v) => Digest::parse_fsverity(&v.finish()).map_err(|e| io::Error::other(e.to_string())),
        None => Ok(content.finalize()),
    }
}

impl Sink for FilesSink {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn dir(&self) -> &Path {
        &self.dir
    }

    fn holds(&self, key: &str, _size: u64) -> bool {
        !self.wants(key)
    }

    fn in_store_only(&self, _key: &str) -> bool {
        false
    }

    fn store_path(&self, _key: &str) -> Option<PathBuf> {
        None
    }

    fn held(&self, keys: &[String]) -> io::Result<Vec<bool>> {
        match &self.holds {
            Some(holds) => holds(keys),
            None => Ok(vec![false; keys.len()]),
        }
    }

    fn known_by_verity(&self, _key: &str, _name: &str) {}

    fn put_as(&self, _key: &str, _data: &[u8]) -> io::Result<bool> {
        Err(not_here("content in memory"))
    }

    fn adopt_as(&self, _temp: &Path, _key: &str, _size: u64) -> io::Result<bool> {
        Err(not_here("a file with a name"))
    }

    fn adopt_file(
        &self,
        _file: &File,
        _key: &str,
        _verity_keyed: Option<&str>,
    ) -> io::Result<bool> {
        Err(not_here("a file to copy: staged files are handed over"))
    }

    /// A file a fetcher staged: verified once ([`super::commit::verify_file`]:
    /// the kernel's measure, else one read), then handed over as it is, a
    /// descriptor the driver links or copies its own way.  Nothing is written
    /// or read again here.
    fn adopt_staged(
        &self,
        layer: &Arc<LayerStaging>,
        file: &File,
        key: &str,
        _verity_keyed: Option<&str>,
    ) -> io::Result<bool> {
        let note = |n: usize| {
            self.hashed
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        };
        let verity = match super::commit::verify_file(file, key, &note)? {
            Ok(verity) => verity,
            Err(why) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the staged file {key} is {why}"),
                ))
            }
        };
        let size = file.metadata()?.len();
        self.place(key, size)?;
        self.checked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string());
        (self.told)(Written::Staged {
            key: key.to_string(),
            file: Arc::new(file.try_clone()?),
            verity,
            layer: layer.clone(),
        });
        // (the name of the file in the staging stays until the driver has
        // linked the inode: a file with no name cannot be linked)
        Ok(true)
    }

    fn scratch(self: Arc<Self>) -> io::Result<Arc<dyn Sink>> {
        Err(not_here("a scratch area"))
    }

    fn transfer_into(&self, _other: &dyn Sink, _keep: &HashSet<&str>) -> io::Result<Vec<String>> {
        Err(not_here("a transfer"))
    }

    fn proves_in_fetch(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The objects whose chunks this process checked are those it wrote
    /// itself: not one the driver copies into.
    #[test]
    fn only_what_the_engine_wrote_itself_is_checked_chunk_by_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let file = Arc::new(tempfile::tempfile().unwrap());
        let slots = ["a", "b", "c"].iter().enumerate().map(|(i, k)| {
            (
                k.to_string(),
                Slot {
                    file: file.clone(),
                    base: i as u64 * 4096,
                    size: 10,
                },
            )
        });
        let holds: Holds = Arc::new(|keys: &[String]| Ok(vec![true; keys.len()]));
        let sink = FilesSink::holding("p", dir.path(), slots, |_| {}, Some(holds)).unwrap();
        assert!(sink.copy_chunk("b", 0, "other", 0, 5).unwrap());
        for key in ["a", "b", "c"] {
            sink.adopt(Finished {
                file: None,
                temp: None,
                name: key.into(),
                key: key.into(),
                size: 10,
                verity_keyed: false,
            })
            .unwrap();
        }
        assert_eq!(
            sink.chunks_checked(),
            HashSet::from(["a".to_string(), "c".to_string()])
        );
    }

    #[test]
    fn a_staged_file_is_verified_once_and_handed_over_as_it_is() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let layer = LayerStaging::made_for_test(root.path(), "one");
        let place = Arc::new(tempfile::tempfile().unwrap());
        let content = vec![3u8; 70_000];
        let key = Digest::of(Algorithm::Sha256, &content).to_string();
        let other = "sha256:".to_string() + &"0".repeat(64);
        let slots = [key.clone(), other.clone()].map(|k| {
            (
                k,
                Slot {
                    file: place.clone(),
                    base: 0,
                    size: content.len() as u64,
                },
            )
        });
        let told = Arc::new(Mutex::new(Vec::new()));
        let sink = FilesSink::new("p", root.path(), slots, {
            let told = told.clone();
            move |w| {
                if let Written::Staged {
                    key, file, verity, ..
                } = w
                {
                    told.lock()
                        .unwrap()
                        .push((key, file.metadata().unwrap().ino(), verity));
                }
            }
        })
        .unwrap();
        let stage = |key: &str, bytes: &[u8]| {
            let path = layer.path().join(crate::stager::staged_rel(key).unwrap());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes).unwrap();
            (File::open(&path).unwrap(), path)
        };
        let (wrong, _) = stage(&other, &content);
        assert!(sink.adopt_staged(&layer, &wrong, &other, None).is_err());
        assert!(told.lock().unwrap().is_empty(), "a wrong file is not told");
        let (file, path) = stage(&key, &content);
        let ino = std::fs::metadata(&path).unwrap().ino();
        assert!(sink.adopt_staged(&layer, &file, &key, None).unwrap());
        let told = told.lock().unwrap();
        assert_eq!(told.len(), 1);
        assert_eq!((told[0].0.as_str(), told[0].1), (key.as_str(), ino));
        assert_eq!(
            told[0].2,
            velarx_storage::fsverity_digest_of(Algorithm::Sha256, &content)
        );
        // (read once for the content digest and the fs-verity digest
        // together; of the file refused, once too; the place got no byte)
        assert_eq!(sink.hashed(), 2 * content.len() as u64);
        assert_eq!(place.metadata().unwrap().blocks(), 0, "nothing written");
        assert!(
            path.exists(),
            "the name stays until the driver has the file"
        );
    }
}
