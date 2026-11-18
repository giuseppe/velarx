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
//! * the staging [`Session`] of a store in this process (composefs, vfs): the
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
//! * a [`Spool`], for a layer with no table of contents that a driver with
//!   files of its own is to store: the layer is read whole into one file of
//!   the engine's, its files known by their hash as the tar is parsed, and
//!   the driver is then given the files it lacks from there.

use std::collections::{HashMap, HashSet};
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
    /// Made with a chunk of the store or of a local source: the store's,
    /// not the pull's
    pub copy: bool,
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
/// Bytes written in order between two notices of the progress of a file.
pub const FOLLOW_STEP: u64 = 8 << 20;

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
    /// Whether the stage takes the files of the layer: they are not left
    /// open to be read again, and not hashed here.
    fn takes_files(&self) -> bool;
    /// Give a complete file its place; whether it was kept.
    fn adopt(&self, finished: Finished) -> io::Result<bool>;
    /// A file of at least [`FOLLOW_MIN`] bytes was created: the stage may
    /// let the replay read it while it is written.
    fn opened(&self, _key: &str, _size: u64, _file: &File) {}
    /// The file is written in order up to `upto` bytes (at every
    /// [`FOLLOW_STEP`] or so).
    fn advanced(&self, _key: &str, _upto: u64) {}
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
    /// Whether the file known by `key` is there already, so that it is not
    /// fetched.
    fn have(&self, key: &str) -> bool;
    /// Whether the content of `key` came from the store as it was before the
    /// pull (not staged by it, or a copy of what the store had).
    fn existed(&self, key: &str) -> bool;
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
    fn put_as(&self, key: &str, data: &[u8], copy: bool) -> io::Result<bool>;
    /// Stage the `size` bytes `entry` reads, known by their hash in `alg`;
    /// the key and whether it was added.  None: this sink has no way of its
    /// own to take a stream, and the content goes through files with a name.
    fn put_reader(
        &self,
        _alg: Algorithm,
        _entry: &mut dyn Read,
        _size: u64,
        _copy: bool,
    ) -> io::Result<Option<(String, bool)>> {
        Ok(None)
    }
    /// Stage the complete file `temp` as `key`; whether it was kept.
    fn adopt_as(&self, temp: &Path, key: &str, size: u64, copy: bool) -> io::Result<bool>;
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
        copy: bool,
    ) -> io::Result<(String, bool)> {
        self.adopt_as(temp, key, size, copy)
            .map(|added| (key.to_string(), added))
    }
    /// [`Sink::adopt_measured`] for content in memory, which a sink that has
    /// the file does not write.
    fn put_measured(
        &self,
        key: &str,
        _verity: &str,
        data: &[u8],
        copy: bool,
    ) -> io::Result<(String, bool)> {
        self.put_as(key, data, copy)
            .map(|added| (key.to_string(), added))
    }
    /// Give a complete file with no name its place as `key`; whether it was
    /// kept.
    fn adopt_file(
        &self,
        file: &File,
        key: &str,
        copy: bool,
        verity_keyed: Option<&str>,
    ) -> io::Result<bool>;
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
        copy: bool,
        verity_keyed: Option<&str>,
    ) -> io::Result<bool> {
        let kept = self.adopt_file(file, key, copy, verity_keyed)?;
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

    fn takes_files(&self) -> bool {
        false
    }

    fn adopt(&self, finished: Finished) -> io::Result<bool> {
        if finished.verity_keyed {
            self.known_by_verity(&finished.key, &finished.name);
        }
        let temp = finished
            .temp
            .ok_or_else(|| io::Error::other("a file of the session has a name"))?;
        self.adopt_as(&temp, &finished.key, finished.size, finished.copy)
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

    fn have(&self, key: &str) -> bool {
        Session::have(self, key)
    }

    fn existed(&self, key: &str) -> bool {
        Session::from_store(self, key)
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

    fn put_as(&self, key: &str, data: &[u8], copy: bool) -> io::Result<bool> {
        Session::put_as(self, key, data, copy)
    }

    fn adopt_as(&self, temp: &Path, key: &str, size: u64, copy: bool) -> io::Result<bool> {
        Session::adopt_as(self, temp, key, size, copy)
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
        copy: bool,
    ) -> io::Result<(String, bool)> {
        Session::adopt_measured(self, temp, key, verity, size, copy)
    }

    fn put_measured(
        &self,
        key: &str,
        verity: &str,
        data: &[u8],
        copy: bool,
    ) -> io::Result<(String, bool)> {
        Session::put_measured(self, key, verity, data, copy)
    }

    fn adopt_file(
        &self,
        file: &File,
        key: &str,
        copy: bool,
        verity_keyed: Option<&str>,
    ) -> io::Result<bool> {
        Session::adopt_file(self, file, key, copy, verity_keyed)
    }

    fn adopt_staged(
        &self,
        layer: &Arc<LayerStaging>,
        file: &File,
        key: &str,
        copy: bool,
        verity_keyed: Option<&str>,
    ) -> io::Result<bool> {
        Session::adopt_staged(self, layer, file, key, copy, verity_keyed)
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

    /// The size of the place of `key`.
    pub fn size_of(&self, key: &str) -> Option<u64> {
        self.slots.get(key).map(|s| s.size)
    }

    /// Whether the `len` bytes from `at` of the content of `key`, at its
    /// place, are zeros.
    pub fn zeros_at(&self, key: &str, at: u64, len: u64) -> io::Result<bool> {
        use std::os::unix::fs::FileExt;
        let slot = self
            .slots
            .get(key)
            .ok_or_else(|| io::Error::other(format!("{key} has no place in the files given")))?;
        let end = at
            .checked_add(len)
            .filter(|e| *e <= slot.size)
            .ok_or_else(|| io::Error::other(format!("a run of {key} beyond its place")))?;
        let mut buf = vec![0u8; len.min(1 << 20) as usize];
        let mut from = at;
        while from < end {
            let n = (end - from).min(buf.len() as u64) as usize;
            slot.file.read_exact_at(&mut buf[..n], slot.base + from)?;
            if buf[..n].iter().any(|b| *b != 0) {
                return Ok(false);
            }
            from += n as u64;
        }
        Ok(true)
    }
}

/// A sink that keeps the content of the files of a layer read whole in a
/// single file with no name, one after the other, known by its hash (a
/// content of [`SPOOL_ALIGN`] bytes or more at a multiple of it, so that it
/// can be cloned; smaller ones packed, so that a layer of many small files
/// does not cost a block each): what a layer
/// that has no table of contents is read into, to be given to a driver that
/// asks for the files it lacks once the keys are known.  A file that the
/// layer has twice is kept once.
pub struct Spool {
    name: String,
    dir: PathBuf,
    file: File,
    inner: Mutex<SpoolIndex>,
    /// The free bytes of the directory of the spool (a function of the
    /// directory so that a test can say how many).
    free: FreeBytes,
}

/// What tells the free bytes of a directory.
type FreeBytes = Box<dyn Fn(&Path) -> io::Result<u64> + Send + Sync>;

#[derive(Default)]
struct SpoolIndex {
    end: u64,
    /// The length given to the file: ahead of `end`, so that a layer of
    /// many small files does not ask for a new length at each of them.
    len: u64,
    /// The end up to which the spool is known to fit: the free space was
    /// looked at for it.
    checked: u64,
    at: HashMap<String, (u64, u64)>,
}

/// How often the free space of the directory of a spool is looked at: before
/// its first content, then each time it has grown by this much (or by what
/// was free, when less was), and before each content that is larger.
const SPOOL_STEP: u64 = 16 << 20;

/// How far ahead of its contents the spool file is given a length.
const SPOOL_AHEAD: u64 = 1 << 20;

/// The bytes of the file system of `dir` that a process that is not root may
/// still write (`f_bavail`: the blocks reserved for root are not counted, so
/// an engine that runs as root is refused a little early, never late), or
/// `u64::MAX` for a file system that tells no size (`f_blocks` 0: some
/// network and FUSE file systems), which is not looked at.
fn free_bytes(dir: &Path) -> io::Result<u64> {
    let st = rustix::fs::statvfs(dir)?;
    if st.f_blocks == 0 {
        return Ok(u64::MAX);
    }
    Ok(st.f_bavail.saturating_mul(st.f_frsize.max(1)))
}

/// Where the content of each file of this size or more in a [`Spool`]
/// starts.
pub const SPOOL_ALIGN: u64 = 4096;

impl Spool {
    /// A spool whose file is in `dir` (a directory of the engine's, closed to
    /// others), for the pull `name`.
    pub fn new(name: &str, dir: &Path) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            name: name.to_string(),
            dir: dir.to_path_buf(),
            file: super::unnamed::unnamed_file(dir)?,
            inner: Mutex::default(),
            free: Box::new(free_bytes),
        }))
    }

    /// [`Spool::new`] with the free space of the directory told by `free`.
    #[cfg(test)]
    pub(crate) fn with_free(
        name: &str,
        dir: &Path,
        free: impl Fn(&Path) -> io::Result<u64> + Send + Sync + 'static,
    ) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            name: name.to_string(),
            dir: dir.to_path_buf(),
            file: super::unnamed::unnamed_file(dir)?,
            inner: Mutex::default(),
            free: Box::new(free),
        }))
    }

    /// The directory has room for the next content of `size` bytes, or the
    /// layer is refused now, before it is written, and not when the disk is
    /// full: the free space is looked at when the spool would grow past what
    /// was known to fit (before the first content, then at about each
    /// [`SPOOL_STEP`], and before a content larger than that).  A layer is
    /// refused only when the content does not fit in what is free; a
    /// directory whose free space cannot be read is not looked at (the write
    /// fails as it did before, when the disk is full).
    fn room(&self, index: &mut SpoolIndex, size: u64) -> io::Result<()> {
        if index.end.saturating_add(size) <= index.checked {
            return Ok(());
        }
        let free = match (self.free)(&self.dir) {
            Ok(free) => free,
            Err(e) => {
                tracing::debug!(
                    "the free space of {} cannot be read ({e}): not looked at",
                    self.dir.display()
                );
                index.checked = index.end.saturating_add(size.max(SPOOL_STEP));
                return Ok(());
            }
        };
        if free < size {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                format!(
                    "not enough free space for the files of the layer being read: {} has {free} bytes free and the next file needs {size} bytes (the spool holds {} bytes already)",
                    self.dir.display(),
                    index.end
                ),
            ));
        }
        // (what was free is known to fit, up to a step: others write to the
        // same file system)
        index.checked = index.end.saturating_add(free.min(size.max(SPOOL_STEP)));
        Ok(())
    }

    fn index(&self) -> std::sync::MutexGuard<'_, SpoolIndex> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether the content of `key` is in the spool.
    pub fn has(&self, key: &str) -> bool {
        self.index().at.contains_key(key)
    }

    /// Copy the content of `key` to `to_at` of `to` (its holes stay holes);
    /// `step` is called between the pieces, and an error from it ends the
    /// copy.
    pub fn copy_to(
        &self,
        key: &str,
        to: &File,
        to_at: u64,
        step: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.copy_to_holes(key, to, to_at, step, &mut |_, _| {})
    }

    /// [`Spool::copy_to`], telling `hole(at, length)` of each hole of the
    /// content, which the copy leaves a hole.
    pub fn copy_to_holes(
        &self,
        key: &str,
        to: &File,
        to_at: u64,
        step: impl FnMut() -> io::Result<()>,
        hole: &mut dyn FnMut(u64, u64),
    ) -> io::Result<()> {
        let (at, size) = self
            .index()
            .at
            .get(key)
            .copied()
            .ok_or_else(|| io::Error::other(format!("{key} is not in the layer")))?;
        velarx_storage::copy_region_holes(&self.file, at, to, to_at, size, step, hole)
    }

    fn put(&self, alg: Algorithm, entry: &mut dyn Read, size: u64) -> io::Result<(String, bool)> {
        let mut index = self.index();
        let base = if size >= SPOOL_ALIGN {
            index.end.next_multiple_of(SPOOL_ALIGN)
        } else {
            index.end
        };
        let end = base
            .checked_add(size)
            .ok_or_else(|| io::Error::other("a file ends beyond the spool"))?;
        self.room(&mut index, size)?;
        if end > index.len {
            index.len = end.saturating_add(SPOOL_AHEAD);
            self.file.set_len(index.len)?;
        }
        let mut hasher = DigestWriter::new(alg);
        let mut buf = vec![0u8; size.min(256 * 1024) as usize];
        let mut at = 0u64;
        let written = (|| {
            while at < size {
                let want = (size - at).min(buf.len() as u64) as usize;
                let n = entry.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                hasher.update(&buf[..n]);
                velarx_storage::write_at_sparse(&self.file, &buf[..n], base + at)?;
                at += n as u64;
            }
            Ok(())
        })();
        if let Err(e) = written {
            // (what was written of it goes: the next content is written at
            // the same place, and the blocks of zeros of a content are not
            // written, so nothing of this one may be left under them)
            if at > 0 {
                self.file.set_len(base)?;
                index.len = base;
            }
            return Err(e);
        }
        let key = hasher.finalize().to_string();
        if index.at.contains_key(&key) {
            // (what was written goes: the next content is written over a
            // file with nothing there, its blocks of zeros left alone)
            self.file.set_len(base)?;
            index.len = base;
            return Ok((key, false));
        }
        index.at.insert(key.clone(), (base, size));
        index.end = end;
        Ok((key, true))
    }
}

impl Stage for Spool {
    fn create_temp(&self) -> io::Result<(File, Option<PathBuf>)> {
        Err(not_here("a file with no place"))
    }

    fn takes_files(&self) -> bool {
        false
    }

    fn adopt(&self, _finished: Finished) -> io::Result<bool> {
        Err(not_here("a file with a name"))
    }

    fn open_object(&self, digest: &str) -> io::Result<File> {
        Err(not_here(&format!("{digest} cannot be read here")))
    }

    fn content_path(&self, _digest: &str) -> Option<PathBuf> {
        None
    }
}

impl Sink for Spool {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn dir(&self) -> &Path {
        &self.dir
    }

    fn have(&self, _key: &str) -> bool {
        false
    }

    fn existed(&self, _key: &str) -> bool {
        false
    }

    fn in_store_only(&self, _key: &str) -> bool {
        false
    }

    fn store_path(&self, _key: &str) -> Option<PathBuf> {
        None
    }

    fn known_by_verity(&self, _key: &str, _name: &str) {}

    fn put_as(&self, key: &str, data: &[u8], _copy: bool) -> io::Result<bool> {
        let kind = Digest::parse_key(key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{key}: {e}")))?;
        let (made, added) = self.put(kind.alg(), &mut &data[..], data.len() as u64)?;
        if made != key {
            return Err(io::Error::other(format!(
                "{key} is not the hash of its content"
            )));
        }
        Ok(added)
    }

    fn put_reader(
        &self,
        alg: Algorithm,
        entry: &mut dyn Read,
        size: u64,
        _copy: bool,
    ) -> io::Result<Option<(String, bool)>> {
        self.put(alg, entry, size).map(Some)
    }

    fn adopt_as(&self, _temp: &Path, _key: &str, _size: u64, _copy: bool) -> io::Result<bool> {
        Err(not_here("a file with a name"))
    }

    fn adopt_file(
        &self,
        _file: &File,
        _key: &str,
        _copy: bool,
        _verity_keyed: Option<&str>,
    ) -> io::Result<bool> {
        Err(not_here("a file of a job"))
    }

    fn scratch(self: Arc<Self>) -> io::Result<Arc<dyn Sink>> {
        Err(not_here("a scratch area"))
    }

    fn transfer_into(&self, _other: &dyn Sink, _keep: &HashSet<&str>) -> io::Result<Vec<String>> {
        Err(not_here("a transfer"))
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

    fn takes_files(&self) -> bool {
        true
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

    fn have(&self, key: &str) -> bool {
        !self.wants(key)
    }

    fn existed(&self, _key: &str) -> bool {
        false
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

    fn put_as(&self, _key: &str, _data: &[u8], _copy: bool) -> io::Result<bool> {
        Err(not_here("content in memory"))
    }

    fn adopt_as(&self, _temp: &Path, _key: &str, _size: u64, _copy: bool) -> io::Result<bool> {
        Err(not_here("a file with a name"))
    }

    fn adopt_file(
        &self,
        _file: &File,
        _key: &str,
        _copy: bool,
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
        _copy: bool,
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
    use std::os::unix::fs::FileExt;

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
                copy: false,
                verity_keyed: false,
            })
            .unwrap();
        }
        assert_eq!(
            sink.chunks_checked(),
            HashSet::from(["a".to_string(), "c".to_string()])
        );
    }

    fn spool() -> (tempfile::TempDir, Arc<Spool>) {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::new("pull", dir.path()).unwrap();
        (dir, spool)
    }

    fn put(spool: &Spool, data: &[u8]) -> (String, bool) {
        spool
            .put_reader(Algorithm::Sha256, &mut &data[..], data.len() as u64, false)
            .unwrap()
            .unwrap()
    }

    /// The content is known by its hash, a file the layer has twice is kept
    /// once and gives its space back, and each file is copied out whole to
    /// the place asked, holes included.
    #[test]
    fn a_spool_keeps_each_content_once_and_gives_it_back_at_a_place() {
        let (dir, spool) = spool();
        let mut holey = vec![0u8; 3 << 20];
        holey[10..20].fill(7);
        let tail = holey.len() - 5;
        holey[tail..].fill(9);
        let small = b"hello".to_vec();
        let (k_small, added) = put(&spool, &small);
        assert!(added);
        assert_eq!(k_small, Digest::of(Algorithm::Sha256, &small).to_string());
        let (k_holey, added) = put(&spool, &holey);
        assert!(added);
        let (again, added) = put(&spool, &small);
        assert_eq!((again.as_str(), added), (k_small.as_str(), false));
        let (_, added) = put(&spool, &holey);
        assert!(!added);
        assert!(spool.has(&k_holey) && !spool.has("sha256:0"));
        // (the space of a duplicate is given back)
        let used = spool.file.metadata().unwrap().len();
        assert_eq!(used, 4096 + holey.len() as u64);

        let out = File::create(dir.path().join("out")).unwrap();
        spool.copy_to(&k_small, &out, 0, || Ok(())).unwrap();
        spool.copy_to(&k_holey, &out, 8192, || Ok(())).unwrap();
        let got = std::fs::read(dir.path().join("out")).unwrap();
        assert_eq!(&got[..5], &small[..]);
        assert_eq!(&got[8192..], &holey[..]);
        assert!(spool.copy_to("sha256:1", &out, 0, || Ok(())).is_err());
        let e = spool
            .copy_to(&k_holey, &out, 0, || Err(io::Error::other("stop")))
            .unwrap_err();
        assert_eq!(e.to_string(), "stop");
    }

    /// Small contents are packed, a large one starts at a multiple of
    /// [`SPOOL_ALIGN`]: a layer of many small files costs their bytes, not a
    /// block each.
    #[test]
    fn small_contents_are_packed_and_large_ones_aligned() {
        let (_dir, spool) = spool();
        let mut keys = Vec::new();
        for i in 0..1000u32 {
            let data = format!("{i}\n");
            keys.push((put(&spool, data.as_bytes()).0, data));
        }
        let small_end = spool.index().end;
        assert!(small_end < 8192, "{small_end}");
        let big = vec![5u8; 10_000];
        let (k_big, _) = put(&spool, &big);
        let (at, _) = spool.index().at[&k_big];
        assert_eq!(at % SPOOL_ALIGN, 0);
        assert!(at >= small_end);
        let (k_tail, _) = put(&spool, b"tail");
        assert_eq!(spool.index().at[&k_tail].0, at + big.len() as u64);
        for (key, data) in keys.iter().chain([(k_big.clone(), String::new())].iter()) {
            let out = tempfile::tempfile().unwrap();
            spool.copy_to(key, &out, 0, || Ok(())).unwrap();
            let mut got = Vec::new();
            (&out).read_to_end(&mut got).unwrap();
            if key == &k_big {
                assert_eq!(got, big);
            } else {
                assert_eq!(got, data.as_bytes());
            }
        }
    }

    /// The spool looks at the free space of its directory before the first
    /// content, once for every step it grows by and before a large content,
    /// not for each file; a layer that needs more than there is is refused
    /// naming the directory and the bytes, with nothing written.
    #[test]
    fn the_free_space_is_looked_at_before_the_spool_grows() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let looked = Arc::new(AtomicU64::new(0));
        let free = Arc::new(AtomicU64::new(u64::MAX));
        let spool = {
            let (looked, free) = (looked.clone(), free.clone());
            Spool::with_free("t", dir.path(), move |_| {
                looked.fetch_add(1, Ordering::SeqCst);
                Ok(free.load(Ordering::SeqCst))
            })
            .unwrap()
        };
        for i in 0..1000u32 {
            put(&spool, format!("{i}\n").as_bytes());
        }
        assert_eq!(
            looked.load(Ordering::SeqCst),
            1,
            "once for 1000 small files"
        );
        // a content larger than a step is looked at before it is written
        free.store(1 << 20, Ordering::SeqCst);
        let big = vec![7u8; (SPOOL_STEP + 1) as usize];
        let key = Digest::of(Algorithm::Sha256, &big).to_string();
        let e = spool.put_as(&key, &big, false).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::StorageFull);
        let msg = e.to_string();
        assert!(msg.contains(&dir.path().display().to_string()), "{msg}");
        assert!(msg.contains(&(SPOOL_STEP + 1).to_string()), "{msg}");
        assert!(msg.contains("1048576 bytes free"), "{msg}");
        assert!(!spool.has(&key), "nothing of it is kept");
        // and it goes on when there is room
        free.store(u64::MAX, Ordering::SeqCst);
        assert!(spool.put_as(&key, &big, false).unwrap());
    }

    /// The holes of a content are told as they are copied, with offsets from
    /// the start of the content.
    #[test]
    fn the_holes_of_a_copy_are_told() {
        let (dir, spool) = spool();
        let mut data = vec![1u8; 4096];
        data.extend(vec![0u8; 3 * 4096]);
        data.extend(vec![2u8; 100]);
        let (key, _) = put(&spool, &data);
        let out = tempfile::tempfile().unwrap();
        let mut holes = Vec::new();
        spool
            .copy_to_holes(&key, &out, 8192, || Ok(()), &mut |at, len| {
                holes.push((at, len))
            })
            .unwrap();
        // (a file system that cannot tell holes tells none)
        if !holes.is_empty() {
            assert_eq!(holes, [(4096, 3 * 4096)]);
        }
        let mut got = vec![0u8; data.len()];
        out.read_exact_at(&mut got, 8192).unwrap();
        assert!(got == data);
        drop(dir);
    }

    /// A stream that ends before its size leaves nothing in the spool, and
    /// the spool stores through `put_as` the same.
    #[test]
    fn a_short_stream_leaves_nothing() {
        let (_dir, spool) = spool();
        let e = spool
            .put_reader(Algorithm::Sha256, &mut &b"abc"[..], 10, false)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(spool.index().end, 0);
        assert!(spool.index().at.is_empty());
        let key = Digest::of(Algorithm::Sha256, b"abc").to_string();
        assert!(spool.put_as(&key, b"abc", false).unwrap());
        assert!(!spool.put_as(&key, b"abc", false).unwrap());
        let other = Digest::of(Algorithm::Sha256, b"abd").to_string();
        assert!(spool.put_as(&other, b"abc", false).is_err());
        let out = tempfile::tempfile().unwrap();
        spool.copy_to(&key, &out, 4096, || Ok(())).unwrap();
        let mut got = [0u8; 3];
        out.read_exact_at(&mut got, 4096).unwrap();
        assert_eq!(&got, b"abc");
        // (no file with a name, and no stage of files)
        assert!(spool.create_temp().is_err() && spool.open_object(&key).is_err());
    }

    /// A content cut short leaves none of its bytes where the next content
    /// goes: the blocks of zeros of that one are not written, and would
    /// otherwise read as the bytes of the one cut short.
    #[test]
    fn a_content_cut_short_leaves_nothing_under_the_next() {
        let (_dir, spool) = spool();
        let cut = vec![9u8; 3 * 4096];
        let e = spool
            .put_reader(Algorithm::Sha256, &mut &cut[..], 4 * 4096, false)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        let mut zeros = vec![0u8; 4 * 4096];
        zeros[4 * 4096 - 1] = 1;
        let (key, added) = put(&spool, &zeros);
        assert!(added);
        let out = tempfile::tempfile().unwrap();
        spool.copy_to(&key, &out, 0, || Ok(())).unwrap();
        let mut got = vec![0u8; zeros.len()];
        out.read_exact_at(&mut got, 0).unwrap();
        assert!(got == zeros, "the content is its own bytes");
    }

    /// A content that fits in what is free is not refused however little
    /// that is, the space is looked at again once the spool has grown by
    /// what was free, and a directory whose free space cannot be read is not
    /// looked at.
    #[test]
    fn the_free_space_refuses_only_what_does_not_fit() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let looked = Arc::new(AtomicU64::new(0));
        let spool = {
            let looked = looked.clone();
            Spool::with_free("t", dir.path(), move |_| {
                looked.fetch_add(1, Ordering::SeqCst);
                Ok(1000)
            })
            .unwrap()
        };
        for i in 0..100u32 {
            put(&spool, format!("{i:09}\n").as_bytes());
        }
        assert_eq!(looked.load(Ordering::SeqCst), 1, "1000 bytes fit in 1000");
        put(&spool, b"0123456789");
        assert_eq!(looked.load(Ordering::SeqCst), 2, "past what was free");
        let e = spool
            .put_reader(Algorithm::Sha256, &mut &[1u8; 1001][..], 1001, false)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::StorageFull, "{e}");
        assert!(e.to_string().contains("needs 1001 bytes"), "{e}");
        let blind =
            Spool::with_free("t", dir.path(), |_| Err(io::Error::other("no statvfs"))).unwrap();
        put(&blind, &[3u8; 70_000]);
        // (the real look: a file system whose size is known says what is free)
        assert!(free_bytes(dir.path()).unwrap() > 0);
    }

    /// A file a fetcher staged is verified once (read once, the store of the
    /// engine having no fs-verity) and handed over as it is: the descriptor
    /// told is the staged inode, nothing is written to a place of the
    /// driver, and a file that is not its key is refused and not told.
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
        assert!(sink
            .adopt_staged(&layer, &wrong, &other, false, None)
            .is_err());
        assert!(told.lock().unwrap().is_empty(), "a wrong file is not told");
        let (file, path) = stage(&key, &content);
        let ino = std::fs::metadata(&path).unwrap().ino();
        assert!(sink.adopt_staged(&layer, &file, &key, false, None).unwrap());
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
