// SPDX-License-Identifier: Apache-2.0
//! The staging session of a pull.
//!
//! Everything a pull downloads is written to a directory of its own, under
//! names that are no digest (`tmp-N`): what a file is known by (its fs-verity
//! digest when the TOC gives one, else the hash of its content in the
//! algorithm of its layer) is a claim until the commit has measured it, and a
//! name made of a digest says the file is what it names.  The file is given
//! the name of its fs-verity digest in that algorithm (SHA-256 or SHA-512)
//! only by the commit, in the store, after fs-verity is enabled on it (where
//! the file system has it) and measured, with
//! one `syncfs` before and one after the renames, once the whole image is
//! verified: there is no `fsync` per file, and nothing a failed pull wrote is ever visible.  The directory
//! is removed when the session is dropped.

use super::staged_fetch::LayerStaging;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tracing::warn;
use velarx_storage::{FileStore, FsVerityManager, Object};

pub struct Session {
    dir: PathBuf,
    store: Arc<FileStore>,
    /// Content staged by this session: what it is known by -> its size and
    /// the name it waits under (`tmp-N` of the directory of the session,
    /// never made of the key).
    staged: Mutex<HashMap<String, Staged>>,
    counter: AtomicU64,
    /// The session this one is the scratch of: what it staged is here too
    parent: std::sync::OnceLock<Arc<Session>>,
    /// The staged files that are copies of files of read-only stores: the
    /// store's, not the pull's; never given
    copies: Mutex<std::collections::HashSet<String>>,
    /// The staged files known by their fs-verity digest, and their names:
    /// the commit moves nothing unless each has it
    by_verity: Mutex<HashMap<String, String>>,
    /// The files a job gave that are known by the hash of their content
    /// (sha256 or sha512, the algorithm of their layer), and the fs-verity
    /// digest of the content a replay proved (checked to be that hash as it
    /// was read): the commit stores a file only with that content, once the
    /// job is gone (a file no replay read is read for its hash)
    by_content: Mutex<HashMap<String, Option<String>>>,
    /// The files the engine handed over, verified: their fs-verity digests
    /// (the commit reads none of them)
    verified: Mutex<HashMap<String, String>>,
}

/// A file that waits in a session.
struct Staged {
    size: u64,
    path: PathBuf,
    /// The staging of the layer the file waits in (a fetcher wrote it
    /// there): committed from there, in place, and held until then.  None:
    /// the directory of the session.
    home: Option<Arc<LayerStaging>>,
    /// The engine wrote the file itself, in the directory of the session: no
    /// other process holds its inode (a file a fetcher made, and a file in
    /// the staging of a layer, is not).
    own: bool,
}

/// The directories of a session that its temporary files are spread over.
const SHARDS: u64 = 64;

impl Session {
    /// Create `<staging_root>/<random>`.
    pub fn create(staging_root: &Path, store: Arc<FileStore>) -> io::Result<Arc<Self>> {
        fs::create_dir_all(staging_root)?;
        let dir = staging_root.join(format!("pull-{}", velarx_base::random::uuid()));
        // Only the owner may see or touch what is being pulled.
        let private = || {
            let mut dir = fs::DirBuilder::new();
            std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
            dir
        };
        private().create(&dir)?;
        for shard in 0..SHARDS {
            private().create(dir.join(format!("{shard:02x}")))?;
        }
        Ok(Arc::new(Self {
            dir,
            store,
            staged: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(0),
            parent: std::sync::OnceLock::new(),
            copies: Mutex::new(std::collections::HashSet::new()),
            by_verity: Mutex::new(HashMap::new()),
            by_content: Mutex::new(HashMap::new()),
            verified: Mutex::new(HashMap::new()),
        }))
    }

    /// The directories the temporary files of the session are in.
    #[cfg(test)]
    pub(crate) fn temp_dirs(&self) -> Vec<PathBuf> {
        (0..SHARDS)
            .map(|shard| self.dir.join(format!("{shard:02x}")))
            .collect()
    }

    /// The temporary files the session holds, whatever directory they are
    /// in.
    #[cfg(test)]
    pub(crate) fn temp_files(&self) -> Vec<PathBuf> {
        let in_dir = |dir: PathBuf| fs::read_dir(dir).unwrap().flatten().map(|e| e.path());
        self.temp_dirs().into_iter().flat_map(in_dir).collect()
    }

    /// Remove the sessions left by pulls that stopped in the middle: those
    /// whose lease `held` does not say a process holds.  Only call it with
    /// the lock of the store held exclusive: no pull starts meanwhile (one
    /// that runs holds the lock of its lease, not the one of the store,
    /// through its download).
    pub fn sweep(staging_root: &Path, held: impl Fn(&str) -> bool) {
        let Ok(entries) = fs::read_dir(staging_root) else {
            return;
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if Self::is_session_name(&name) && !held(&name) {
                if let Err(err) = velarx_base::tree::remove_dir_all(e.path()) {
                    warn!(
                        "Cannot remove the stale pull session {:?}: {}",
                        e.path(),
                        err
                    );
                }
            }
        }
    }

    /// A session inside this one, of the same store, for what is not
    /// checked yet: it sees what this one staged, and the lease of this one
    /// keeps it (a sweep or a collection looks at the sessions of the
    /// staging directory only).
    pub fn scratch(self: &Arc<Self>) -> io::Result<Arc<Session>> {
        let s = Session::create(&self.dir, self.store.clone())?;
        let _ = s.parent.set(self.clone());
        Ok(s)
    }

    /// Whether this session staged any file.
    pub fn has_staged_files(&self) -> bool {
        !self.staged.lock().unwrap().is_empty()
    }

    /// Whether this session staged `digest` (not the store).
    pub fn has_staged(&self, digest: &str) -> bool {
        self.staged.lock().unwrap().contains_key(digest)
    }

    /// Whether the content of `digest` is read from this store's own file:
    /// neither this session nor the one it is next to staged it (what a
    /// pull staged may be a file of its job, a copy or not).
    pub fn in_store_only(&self, digest: &str) -> bool {
        !self.has_staged(digest)
            && !self.parent.get().is_some_and(|p| p.has_staged(digest))
            && self.store.contains_local(digest)
    }

    /// Whether `digest` is a copy of a file of a read-only store, or was
    /// made with what the store or a local source had: not what the pull
    /// got.
    pub fn is_copy(&self, digest: &str) -> bool {
        self.copies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(digest)
            || self.parent.get().is_some_and(|p| p.is_copy(digest))
    }

    /// Whether `digest` came from the store as it was before this pull:
    /// not staged by it, or a copy of a read-only store's.
    pub fn from_store(&self, digest: &str) -> bool {
        !self.has_staged(digest) || self.is_copy(digest)
    }

    /// Move what this session staged and `keep` names into `other`
    /// the rest goes with this one.
    /// Returns the digests moved.
    pub fn transfer_into(
        &self,
        other: &Session,
        keep: &std::collections::HashSet<&str>,
    ) -> io::Result<Vec<String>> {
        let staged: Vec<(String, Staged)> = {
            let mut s = self.staged.lock().unwrap_or_else(|e| e.into_inner());
            let kept: Vec<String> = s
                .keys()
                .filter(|d| keep.contains(d.as_str()))
                .cloned()
                .collect();
            kept.into_iter()
                .filter_map(|d| s.remove(&d).map(|n| (d, n)))
                .collect()
        };
        let mut moved = Vec::with_capacity(staged.len());
        for (
            digest,
            Staged {
                size,
                path,
                home,
                own,
            },
        ) in staged
        {
            // a copy stays one there too
            let copy = self.is_copy(&digest);
            let kept = match home {
                // (committed from the staging it is in, which the other
                // session holds from now on)
                Some(home) => other.stage_in(&home, &path, &digest, (size, copy), None)?,
                None => other.adopt_path(&path, &digest, (size, copy), own)?,
            };
            if kept {
                moved.push(digest);
            }
        }
        Ok(moved)
    }

    /// The file `name` staged (or to be) as `key` is known by its
    /// fs-verity digest, `key`: the commit fails, before it moves anything,
    /// if its content has another.
    pub fn known_by_verity(&self, key: &str, name: &str) {
        self.by_verity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string(), name.to_string());
    }

    /// The name of the session (of its directory in the staging root).
    pub fn name(&self) -> String {
        self.dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Whether `name` is the name of a session directory.
    pub fn is_session_name(name: &str) -> bool {
        name.strip_prefix("pull-").is_some_and(|id| {
            !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
        })
    }

    pub fn store(&self) -> &FileStore {
        &self.store
    }

    /// The directory of the session.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether the content is in the store or already staged.  What only
    /// a read-only store has is staged from there, checked: the
    /// images of this store keep only files of their own.
    pub fn have(&self, digest: &str) -> bool {
        if self.staged.lock().unwrap().contains_key(digest) || self.store.contains_local(digest) {
            return true;
        }
        if self.parent.get().is_some_and(|p| p.has_staged(digest)) {
            return true;
        }
        match self.store.find_additional(digest) {
            Some(src) => match self.stage_copy(&src, digest) {
                Ok(()) => true,
                Err(e) => {
                    warn!("{digest} of {}: {e}: fetched", src.display());
                    false
                }
            },
            None => false,
        }
    }

    /// Stage the copy of a file of a read-only store, whose content must
    /// have its fs-verity digest.
    fn stage_copy(&self, src: &Path, digest: &str) -> io::Result<()> {
        let mut from = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(src)?;
        if !from.metadata()?.is_file() {
            return Err(io::Error::other("not a regular file"));
        }
        let (to, temp) = self.create_temp()?;
        let copied = (|| {
            let alg = super::key_algorithm(digest)
                .ok_or_else(|| io::Error::other("it is no key of a file"))?;
            let mut hasher = velarx_storage::VerityHasher::new(alg);
            let size = velarx_storage::copy_sparse(&mut from, &to, |b| hasher.update(b))?;
            let got = hasher.finish();
            if got != digest {
                return Err(io::Error::other(format!("its content is {got}")));
            }
            Ok(size)
        })();
        match copied {
            Ok(size) => self.adopt_as(&temp, digest, size, true).map(|_| ()),
            Err(e) => {
                let _ = fs::remove_file(&temp);
                Err(e)
            }
        }
    }

    /// Where the content with this digest can be read, if it is available.
    pub fn content_path(&self, digest: &str) -> Option<PathBuf> {
        if let Some(path) = self.staged_path(digest) {
            return Some(path);
        }
        if let Some(path) = self.parent.get().and_then(|p| p.staged_path(digest)) {
            return Some(path);
        }
        self.store.get_path(digest)
    }

    /// The name `digest` waits under, if this session staged it.
    fn staged_path(&self, digest: &str) -> Option<PathBuf> {
        self.staged
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(digest)
            .map(|s| s.path.clone())
    }

    /// A name for a file of this session: it is made of a counter, never of
    /// a digest.  The files are spread over directories: threads that make
    /// them side by side would wait for the one lock of a directory.
    fn temp_path(&self) -> PathBuf {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        self.dir.join(format!("{:02x}/tmp-{n}", n % SHARDS))
    }

    /// A new file for content whose digest is not known yet.  Created
    /// exclusively and never through a symbolic link.
    pub fn create_temp(&self) -> io::Result<(File, PathBuf)> {
        let path = self.temp_path();
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            // Writable by its owner until it is committed: enabling
            // fs-verity needs write access to the inode.
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        Ok((file, path))
    }

    /// A name of the session for `file`, a file that has none: it is linked
    /// there, and the name is the file's.
    pub fn link_temp(&self, file: &File) -> io::Result<PathBuf> {
        use rustix::fs::{linkat, AtFlags, CWD};
        let to = self.temp_path();
        // (an unprivileged process may link a file with no name by its
        // descriptor on newer kernels only: the other way works on all)
        match linkat(file, "", CWD, &to, AtFlags::EMPTY_PATH) {
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::PERM | rustix::io::Errno::INVAL) => {
                linkat(
                    CWD,
                    velarx_sys::fd::proc_str(&file),
                    CWD,
                    &to,
                    AtFlags::SYMLINK_FOLLOW,
                )
            }
            r => r,
        }?;
        Ok(to)
    }

    /// Stage the complete file `temp` as `digest`; `copy`: the file is a copy
    /// of what the store or a local source had, which is the store's, not the
    /// pull's.  The file keeps a name of the session (`tmp-N`): `digest` is
    /// what it is known by, not what it is called, and the commit gives it
    /// the name of its fs-verity digest after it has measured it.  Dropped if
    /// the session has the content already, or the store.  Whether the file
    /// was kept.
    pub(crate) fn adopt_as(
        &self,
        temp: &Path,
        digest: &str,
        size: u64,
        copy: bool,
    ) -> io::Result<bool> {
        self.adopt_path(temp, digest, (size, copy), true)
    }

    /// [`Session::adopt_as`] of a file that `own`s its inode or not.
    fn adopt_path(
        &self,
        temp: &Path,
        digest: &str,
        (size, copy): (u64, bool),
        own: bool,
    ) -> io::Result<bool> {
        if self.staged.lock().unwrap().contains_key(digest) || self.store.contains_local(digest) {
            fs::remove_file(temp)?;
            return Ok(false);
        }
        // (a file of the session already; one of another session, which goes
        // with that one, moves in)
        let path = if temp.parent().and_then(Path::parent) == Some(self.dir.as_path()) {
            temp.to_path_buf()
        } else {
            let to = self.temp_path();
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                temp,
                rustix::fs::CWD,
                &to,
                rustix::fs::RenameFlags::NOREPLACE,
            )?;
            to
        };
        let mut staged = self.staged.lock().unwrap();
        if staged.contains_key(digest) {
            drop(staged);
            fs::remove_file(&path)?;
            return Ok(false);
        }
        // A copy is one before it is staged: the store's, not the pull's.
        if copy {
            self.copies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(digest.to_string());
        }
        staged.insert(
            digest.to_string(),
            Staged {
                size,
                path,
                home: None,
                own,
            },
        );
        Ok(true)
    }

    /// Whether the file with the fs-verity digest `verity` is in the store
    /// itself (not in a read-only one: what only that has is staged from
    /// there by [`Session::have`]) or staged here: nothing needs to be
    /// written for it.
    fn holds_object(&self, verity: &str) -> bool {
        self.has_staged(verity)
            || self.parent.get().is_some_and(|p| p.has_staged(verity))
            || self.store.contains_local(verity)
    }

    /// [`Session::adopt_as`] for a file whose content was measured in both
    /// ways while it was written: `key` is the hash of the content (what the
    /// layer it came from knows it by) and `verity` its fs-verity digest (what
    /// the store knows it by).  If the store or the session has the file the
    /// temporary file goes, nothing is staged, and the file is known by
    /// `verity`.  Returns the key the file is known by and whether it was
    /// added.
    pub(crate) fn adopt_measured(
        &self,
        temp: &Path,
        key: &str,
        verity: &str,
        size: u64,
        copy: bool,
    ) -> io::Result<(String, bool)> {
        if self.holds_object(verity) {
            fs::remove_file(temp)?;
            return Ok((verity.to_string(), false));
        }
        let added = self.adopt_as(temp, key, size, copy)?;
        if added {
            // (the commit's measure of the file must be the digest it was
            // written with: its tree is not made a third time to know it)
            self.by_content
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key.to_string(), Some(verity.to_string()));
        }
        Ok((key.to_string(), added))
    }

    /// [`Session::adopt_measured`] for content in memory: a file the store or
    /// the session has is not written at all.
    pub(crate) fn put_measured(
        &self,
        key: &str,
        verity: &str,
        data: &[u8],
        copy: bool,
    ) -> io::Result<(String, bool)> {
        if self.holds_object(verity) {
            return Ok((verity.to_string(), false));
        }
        self.put_as(key, data, copy)
            .map(|added| (key.to_string(), added))
    }

    /// Give the file `file` (made by a fetcher, complete
    /// and verified) its place as `digest` in the session: it is linked
    /// under a name of the session, never over a name that is there, or
    /// dropped if the content is staged
    /// or in the store.  `verity_keyed` is the name of a file known by the
    /// fs-verity digest the TOC gives: the commit fails if its content has
    /// another.  Whether the file was kept.
    pub fn adopt_file(
        &self,
        file: &File,
        digest: &str,
        copy: bool,
        verity_keyed: Option<&str>,
    ) -> io::Result<bool> {
        let size = file.metadata()?.len();
        if self.staged.lock().unwrap().contains_key(digest) || self.store.contains_local(digest) {
            return Ok(false);
        }
        let to = self.link_temp(file)?;
        let mut staged = self.staged.lock().unwrap();
        if staged.contains_key(digest) {
            drop(staged);
            fs::remove_file(&to)?;
            return Ok(false);
        }
        match verity_keyed {
            Some(name) => self.known_by_verity(digest, name),
            None => {
                self.by_content
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(digest.to_string(), None);
            }
        }
        if copy {
            self.copies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(digest.to_string());
        }
        staged.insert(
            digest.to_string(),
            Staged {
                size,
                path: to,
                home: None,
                own: false,
            },
        );
        Ok(true)
    }

    /// Give the file `file`, which the engine verified and handed over (its
    /// fs-verity digest is `verity`), its place as `digest` in the session:
    /// its inode is linked under a name of the session, or, in another file
    /// system, copied (the way of this store).  Never over a name that is
    /// there.  Whether the file was kept, and how many bytes were copied
    /// (none when its inode was linked).
    pub fn adopt_verified(&self, file: &File, digest: &str, verity: &str) -> io::Result<Adopted> {
        use rustix::fs::{linkat, AtFlags, CWD};
        let size = file.metadata()?.len();
        if self.staged.lock().unwrap().contains_key(digest) || self.store.contains_local(digest) {
            return Ok(Adopted::default());
        }
        let mut copied = 0;
        let mut to = self.temp_path();
        let linked = match linkat(file, "", CWD, &to, AtFlags::EMPTY_PATH) {
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::PERM | rustix::io::Errno::INVAL) => {
                linkat(
                    CWD,
                    velarx_sys::fd::proc_str(&file),
                    CWD,
                    &to,
                    AtFlags::SYMLINK_FOLLOW,
                )
            }
            r => r,
        };
        match linked {
            Ok(()) => {}
            Err(rustix::io::Errno::XDEV) => {
                // (another file system: this store keeps its own copy of the
                // bytes, which the engine has verified)
                let (copy, path) = self.create_temp()?;
                let mut from = file.try_clone()?;
                io::Seek::rewind(&mut from)?;
                copied = velarx_storage::copy_sparse(&mut from, &copy, |_| {})?;
                self.store.note_copied(copied as usize);
                io::Write::flush(&mut &copy)?;
                to = path;
            }
            Err(e) => return Err(e.into()),
        }
        let mut staged = self.staged.lock().unwrap();
        if staged.contains_key(digest) {
            drop(staged);
            fs::remove_file(&to)?;
            return Ok(Adopted::default());
        }
        if velarx_types::digest::Digest::parse_fsverity(digest).is_ok() {
            self.known_by_verity(digest, digest);
        }
        self.verified
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(digest.to_string(), verity.to_string());
        staged.insert(
            digest.to_string(),
            Staged {
                size,
                path: to,
                home: None,
                // (the engine's file: nothing else of this store holds it)
                own: true,
            },
        );
        Ok(Adopted { kept: true, copied })
    }

    /// The file `file`, which a fetcher staged as `key` in the staging of
    /// `layer` and which was opened and measured against its name, is the
    /// content of `key`: it is committed where it is, from the staging
    /// (which the session holds until then): no link into the directory of
    /// the session, no copy.  `verity_keyed` is as for
    /// [`Session::adopt_file`].  Whether the file was kept: a content that
    /// is staged or in the store is not, and its name stays in the staging
    /// that goes with the layer.
    pub fn adopt_staged(
        &self,
        layer: &Arc<LayerStaging>,
        file: &File,
        digest: &str,
        copy: bool,
        verity_keyed: Option<&str>,
    ) -> io::Result<bool> {
        let rel = crate::stager::staged_rel(digest)
            .and_then(|r| r.strip_prefix("files/").map(str::to_string))
            .ok_or_else(|| io::Error::other(format!("{digest} is not the key of a file")))?;
        let size = file.metadata()?.len();
        let path = layer.files().join(rel);
        self.stage_in(layer, &path, digest, (size, copy), Some(verity_keyed))
    }

    /// Record the file at `path` of the staging of `layer` as staged as
    /// `digest`; `known`: how it is known (the name of a file known by its
    /// fs-verity digest, or the hash of its content), when it is to be
    /// recorded.
    fn stage_in(
        &self,
        layer: &Arc<LayerStaging>,
        path: &Path,
        digest: &str,
        (size, copy): (u64, bool),
        known: Option<Option<&str>>,
    ) -> io::Result<bool> {
        let mut staged = self.staged.lock().unwrap();
        if staged.contains_key(digest) || self.store.contains_local(digest) {
            return Ok(false);
        }
        match known {
            Some(Some(name)) => self.known_by_verity(digest, name),
            Some(None) => {
                self.by_content
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(digest.to_string(), None);
            }
            None => {}
        }
        if copy {
            self.copies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(digest.to_string());
        }
        staged.insert(
            digest.to_string(),
            Staged {
                size,
                path: path.to_path_buf(),
                home: Some(layer.clone()),
                own: false,
            },
        );
        Ok(true)
    }

    /// Stage content that is in memory; a `copy` (of what the store or a
    /// local source had) is the store's, not the pull's.
    pub fn put_as(&self, digest: &str, data: &[u8], copy: bool) -> io::Result<bool> {
        if self.have(digest) {
            return Ok(false);
        }
        let (mut file, temp) = self.create_temp()?;
        if let Err(e) = io::Write::write_all(&mut file, data) {
            let _ = fs::remove_file(&temp);
            return Err(e);
        }
        drop(file);
        self.adopt_as(&temp, digest, data.len() as u64, copy)
    }

    /// Make the staged content part of the store, through the commit of a
    /// layer ([`super::commit::commit_layer`]): one `syncfs` of the staging
    /// file system, the links, one `syncfs` of the store.  Each file is
    /// named by its fs-verity digest (blocks of 4096 bytes): with `verity`
    /// fs-verity is enabled on it before it is named and the kernel
    /// measures it (`checked`), else (or on a file system of smaller
    /// blocks) the file the engine wrote is named by the digest it was
    /// written with (read once when it has none), and one a fetcher wrote
    /// is copied and the digest computed as it is copied.  A file known by its fs-verity
    /// digest must have it, one a job gave known by the hash of its content
    /// must have that content (or the measure a replay proved); the others
    /// the engine wrote.  An object that is there already is kept.  Returns
    /// the object of each staged key: the caller checks that a key that is
    /// an fs-verity digest is its object's.  The algorithm of a file is the
    /// one of its key.  A file that is not what it is known by fails the
    /// commit.
    pub fn commit(&self, verity: Option<&FsVerityManager>) -> io::Result<Vec<Committed>> {
        self.commit_with(verity, None)
    }

    /// [`Session::commit`] with `after_link`: it runs with what was
    /// committed once the files are linked, before the barrier of the store,
    /// which makes durable what it wrote in the store (it returns whether
    /// it wrote any); it does not run for a file that is refused, and its
    /// error fails the commit.
    pub fn commit_with(
        &self,
        verity: Option<&FsVerityManager>,
        after_link: Option<&mut AfterCommit<'_>>,
    ) -> io::Result<Vec<Committed>> {
        let verification = self.verify(verity)?;
        self.commit_verified(verification, after_link)
    }

    /// The staging phase of a commit: every staged file is verified (once,
    /// by the kernel's measure or by one read; see
    /// [`super::commit::verify_layers`]).  Nothing is named, and no lock of
    /// the store is needed: [`Session::commit_verified`] only links, renames
    /// and syncs.
    pub fn verify(&self, verity: Option<&FsVerityManager>) -> io::Result<Verification> {
        use super::commit::{verify_layers, Check, Staging, Want};
        let staged: Vec<(String, Staged)> = self
            .staged
            .lock()
            .unwrap()
            .iter()
            .map(|(d, s)| {
                (
                    d.clone(),
                    Staged {
                        size: s.size,
                        path: s.path.clone(),
                        home: s.home.clone(),
                        own: s.own,
                    },
                )
            })
            .collect();
        if staged.is_empty() {
            return Ok(Verification(None));
        }
        let by_verity = self
            .by_verity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let by_content = self
            .by_content
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let verified = self
            .verified
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        // One staging for the session's own directory and one for each layer
        // staging its files wait in: one commit, one barrier before the
        // links and one after, whatever the number of layers.
        let mut homes: Vec<(PathBuf, Option<Arc<LayerStaging>>)> = vec![(self.dir.clone(), None)];
        let mut by_home: Vec<Vec<Want>> = vec![Vec::new()];
        for (key, s) in &staged {
            let alg = super::key_algorithm(key).ok_or_else(|| {
                io::Error::other(format!("{key} is not the key of a file (an OCI digest)"))
            })?;
            let at = match &s.home {
                None => 0,
                Some(home) => match homes
                    .iter()
                    .position(|(_, h)| h.as_ref().is_some_and(|h| Arc::ptr_eq(h, home)))
                {
                    Some(at) => at,
                    None => {
                        homes.push((home.files(), Some(home.clone())));
                        by_home.push(Vec::new());
                        homes.len() - 1
                    }
                },
            };
            let rel = s
                .path
                .strip_prefix(&homes[at].0)
                .map_err(|_| io::Error::other(format!("{key} is not staged in the session")))?
                .to_string_lossy()
                .into_owned();
            let check = if let Some(v) = verified.get(key) {
                Check::Verified(v.clone())
            } else if by_verity.contains_key(key) {
                Check::Verity(key.clone())
            } else if let Some(read) = by_content.get(key) {
                Check::Content(read.clone())
            } else {
                Check::Engine
            };
            by_home[at].push(Want {
                key: key.clone(),
                alg,
                rel,
                size: Some(s.size),
                check,
                own: s.own,
            });
        }
        let staging: Vec<Staging<'_>> = homes
            .iter()
            .zip(&by_home)
            .map(|((dir, _), wants)| Staging {
                dir,
                wants: wants.clone(),
                image: None,
            })
            .collect();
        let verified = verify_layers(&staging, &self.store, verity)?;
        Ok(Verification(Some(Verified {
            homes,
            by_home,
            by_verity,
            verified,
        })))
    }

    /// The locked part of a commit of what [`Session::verify`] verified: the
    /// links, `after_link` and the barriers, which hash and copy nothing.
    pub fn commit_verified(
        &self,
        verification: Verification,
        after_link: Option<&mut AfterCommit<'_>>,
    ) -> io::Result<Vec<Committed>> {
        use super::commit::{commit_verified, Refusal, Staging};
        let mut after_link = after_link;
        let Some(Verified {
            homes,
            by_home,
            by_verity,
            verified,
        }) = verification.0
        else {
            if let Some(after) = after_link {
                if after(&[])? {
                    self.store.barrier(self.store.root())?;
                }
            }
            return Ok(Vec::new());
        };
        let keys: Vec<Vec<(String, String)>> = by_home
            .iter()
            .map(|wants| {
                wants
                    .iter()
                    .map(|w| (w.key.clone(), w.rel.clone()))
                    .collect()
            })
            .collect();
        let staging: Vec<Staging<'_>> = homes
            .iter()
            .zip(by_home)
            .map(|((dir, _), wants)| Staging {
                dir,
                wants,
                image: None,
            })
            .collect();
        let mut committed: Vec<Committed> = Vec::new();
        let mut between = |done: &[super::commit::Linked]| -> io::Result<bool> {
            for (at, (linked, keys)) in done.iter().zip(&keys).enumerate() {
                if let Some((i, why)) = linked.refused.first() {
                    let (key, rel) = &keys[*i];
                    let why = match why {
                        Refusal::Missing => "it is gone".to_string(),
                        Refusal::Wrong(why) => why.clone(),
                    };
                    let name = by_verity.get(key).unwrap_or(rel);
                    // (a file a fetcher staged: the fetcher is named)
                    let by = homes[at]
                        .1
                        .as_ref()
                        .and_then(|home| home.staged_by(key))
                        .map(|f| format!("the fetcher {f} staged it, and "))
                        .unwrap_or_default();
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("`{name}` is not committed as {key}: {by}{why}"),
                    ));
                }
                committed.extend(linked.objects.iter().map(|(i, object)| Committed {
                    digest: keys[*i].0.clone(),
                    object: object.clone(),
                }));
            }
            match after_link.as_mut() {
                Some(after) => after(&committed),
                None => Ok(false),
            }
        };
        commit_verified(&staging, verified, &self.store, Some(&mut between))?;
        self.staged.lock().unwrap().clear();
        Ok(committed)
    }
}

/// What [`Session::adopt_verified`] did with a file.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Adopted {
    /// The file was kept (the session did not have it)
    pub kept: bool,
    /// The bytes copied to keep it: none when its inode was linked
    pub copied: u64,
}

/// What [`Session::verify`] made of the staged files: the files, verified,
/// waiting for the locked part of the commit.
pub struct Verification(Option<Verified>);

struct Verified {
    homes: Vec<(PathBuf, Option<Arc<LayerStaging>>)>,
    by_home: Vec<Vec<super::commit::Want>>,
    by_verity: HashMap<String, String>,
    verified: super::commit::Verified,
}

/// What runs between the link step of a session's commit and the barrier of
/// the store ([`Session::commit_with`]).
pub type AfterCommit<'a> = dyn FnMut(&[Committed]) -> io::Result<bool> + 'a;

/// A file a commit put in the store: the key it was staged by, and its
/// object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committed {
    pub digest: String,
    pub object: Object,
}

/// Start writing a complete file to the disk now: the sync of the commit
/// then has little of the pull left to wait for.  It can wait for the disk:
/// for files written in parallel, not in the way of a stream.
pub fn start_writeback(f: &File) {
    velarx_sys::fd::start_writeback(std::os::fd::AsFd::as_fd(f));
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(e) = velarx_base::tree::remove_dir_all(&self.dir) {
            if e.kind() != io::ErrorKind::NotFound {
                warn!("Cannot remove the pull session {:?}: {}", self.dir, e);
            }
        }
    }
}

#[cfg(test)]
impl Session {
    /// Stage content that is in memory.
    pub fn put(&self, digest: &str, data: &[u8]) -> io::Result<bool> {
        self.put_as(digest, data, false)
    }

    /// Number of files and bytes staged.
    pub fn staged_totals(&self) -> (usize, u64) {
        let staged = self.staged.lock().unwrap();
        (staged.len(), staged.values().map(|s| s.size).sum())
    }

    /// Stage a temporary file, or drop it if the content is already
    /// available.  Returns whether the file was kept.
    ///
    /// The file keeps a name of the session, which is no digest: a key is
    /// recorded at once, under the lock of the session, and a content that
    /// another thread recorded first has the same bytes, so this file goes.
    pub fn adopt(&self, temp: &Path, digest: &str, size: u64) -> io::Result<bool> {
        self.adopt_as(temp, digest, size, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn session() -> (tempfile::TempDir, Arc<Session>) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let s = Session::create(&tmp.path().join("staging"), store).unwrap();
        (tmp, s)
    }

    /// Threads that stage the same content at once: one keeps its file,
    /// the content is staged for all; a copy stays one whoever wins, and
    /// is never registered for the peers.
    #[test]
    fn the_same_content_staged_at_once() {
        for copy in [true, false] {
            let (_tmp, s) = session();
            let data = format!("same content {copy}");
            let d = velarx_storage::fsverity_digest_of(
                velarx_types::digest::Algorithm::Sha256,
                data.as_bytes(),
            );
            let kept: usize = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..8)
                    .map(|_| {
                        scope.spawn(|| {
                            let (mut f, temp) = s.create_temp().unwrap();
                            f.write_all(data.as_bytes()).unwrap();
                            drop(f);
                            s.adopt_as(&temp, &d, data.len() as u64, copy).unwrap()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| usize::from(h.join().unwrap()))
                    .sum()
            });
            assert_eq!(kept, 1);
            assert!(s.has_staged(&d));
            assert_eq!(
                fs::read(s.content_path(&d).unwrap()).unwrap(),
                data.as_bytes()
            );
            assert_eq!(s.is_copy(&d), copy);
            assert_eq!(s.from_store(&d), copy);
            let left = s.temp_files().len();
            assert_eq!(left, 1);
        }
    }

    /// A file only a read-only store has is copied into the session to be
    /// used, but it is the store's: never registered for the peers nor
    /// counted as the store's, and still a copy when it moves
    /// to another session.
    #[test]
    fn copies_of_read_only_stores_are_the_stores() {
        let tmp = tempfile::tempdir().unwrap();
        let ro = FileStore::new(tmp.path().join("ro")).unwrap();
        let store = Arc::new(
            FileStore::new(tmp.path().join("files"))
                .unwrap()
                .with_additional(vec![tmp.path().join("ro")]),
        );
        let s = Session::create(&tmp.path().join("staging"), store.clone()).unwrap();
        let mut digests = Vec::new();
        for i in 0..4 {
            let d = ro
                .put(
                    velarx_types::digest::Algorithm::Sha256,
                    format!("private {i}").as_bytes(),
                )
                .unwrap();
            assert!(s.have(&d));
            digests.push(d);
        }
        for d in &digests {
            assert!(s.is_copy(d) && s.from_store(d));
            // (a copy is a file of the session: what reads it hashes it)
            assert!(!s.in_store_only(d));
        }
        let own = store
            .put(velarx_types::digest::Algorithm::Sha256, b"of the store")
            .unwrap();
        assert!(s.have(&own) && s.in_store_only(&own));
        // what the pull itself got is the pull's
        let mine =
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, b"fetched");
        s.put(&mine, b"fetched").unwrap();
        assert!(!s.from_store(&mine) && !s.in_store_only(&mine));
        // a copy moved to another session is still one
        let scratch = s.scratch().unwrap();
        let other = ro
            .put(velarx_types::digest::Algorithm::Sha256, b"private other")
            .unwrap();
        assert!(scratch.have(&other));
        let keep: std::collections::HashSet<&str> = [other.as_str()].into();
        scratch.transfer_into(&s, &keep).unwrap();
        assert!(s.has_staged(&other) && s.is_copy(&other));
    }

    /// A scratch session finds what its parent staged; what it stages
    /// itself is its own until it is moved.
    #[test]
    fn a_scratch_session_sees_its_parent() {
        let (_tmp, parent) = session();
        let d = velarx_storage::fsverity_digest_of(
            velarx_types::digest::Algorithm::Sha256,
            b"of the parent",
        );
        parent.put(&d, b"of the parent").unwrap();
        let scratch = parent.scratch().unwrap();
        assert!(scratch.have(&d));
        assert!(!parent.in_store_only(&d) && !scratch.in_store_only(&d));
        assert_eq!(
            fs::read(scratch.content_path(&d).unwrap()).unwrap(),
            b"of the parent"
        );
        let mine = velarx_storage::fsverity_digest_of(
            velarx_types::digest::Algorithm::Sha256,
            b"of the scratch",
        );
        scratch.put(&mine, b"of the scratch").unwrap();
        assert!(!parent.have(&mine));
        let keep: std::collections::HashSet<&str> = [mine.as_str()].into();
        assert_eq!(
            scratch.transfer_into(&parent, &keep).unwrap(),
            vec![mine.clone()]
        );
        assert!(parent.have(&mine));
    }

    /// What only a read-only store has is staged from there, checked
    /// against its digest; the store's own file is not touched.
    #[test]
    fn files_of_read_only_stores_are_copied_checked() {
        let tmp = tempfile::tempdir().unwrap();
        let ro = FileStore::new(tmp.path().join("ro")).unwrap();
        let good = ro
            .put(velarx_types::digest::Algorithm::Sha256, b"good content")
            .unwrap();
        let bad = velarx_storage::fsverity_digest_of(
            velarx_types::digest::Algorithm::Sha256,
            b"what it should be",
        );
        // a file of the other store whose content is not its digest's
        let bad_path = ro.local_path(&bad).unwrap();
        fs::create_dir_all(bad_path.parent().unwrap()).unwrap();
        fs::write(&bad_path, b"something else").unwrap();
        let store = Arc::new(
            FileStore::new(tmp.path().join("files"))
                .unwrap()
                .with_additional(vec![tmp.path().join("ro")]),
        );
        let s = Session::create(&tmp.path().join("staging"), store.clone()).unwrap();
        assert!(s.have(&good));
        assert_eq!(s.staged_totals(), (1, 12));
        assert!(!s.have(&bad));
        assert_eq!(s.staged_totals(), (1, 12));
        s.commit(None).unwrap();
        assert!(store.contains_local(&good));
        assert_eq!(
            fs::read(ro.get_path(&good).unwrap()).unwrap(),
            b"good content"
        );
    }

    /// On a file system with fs-verity (VELARX_VERITY_DIR): the commit
    /// enables and measures it, and a file of the store that lost it (or
    /// another content under its name) is replaced by the checked one.
    fn has_verity(path: &Path, expected: &str) -> bool {
        File::open(path)
            .ok()
            .and_then(|f| velarx_storage::measure_file(&f).ok())
            .and_then(|m| m.object())
            .is_some_and(|o| o.to_string() == expected)
    }

    #[test]
    fn verity_is_measured_at_commit_and_restored() {
        let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") else {
            eprintln!("VELARX_VERITY_DIR not set: skipped");
            return;
        };
        let tmp = tempfile::tempdir_in(dir).unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let verity = velarx_storage::VerityMode::On.manager().unwrap();
        let d =
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, b"hello");
        let s = Session::create(&tmp.path().join("staging"), store.clone()).unwrap();
        s.put(&d, b"hello").unwrap();
        let c = s.commit(Some(&verity)).unwrap();
        let v = c[0].object.verity.clone();
        assert!(v.starts_with("fsverity-sha256-12:"));
        let path = store.local_path(&d).unwrap();
        assert!(has_verity(&path, &v));

        // the file of the store replaced by one without fs-verity: a file
        // of checked content committed there replaces it
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"evil!").unwrap();
        let s = Session::create(&tmp.path().join("staging"), store.clone()).unwrap();
        let (mut f, temp) = s.create_temp().unwrap();
        io::Write::write_all(&mut f, b"hello").unwrap();
        drop(f);
        s.adopt_as(&temp, &v, 5, false).unwrap();
        s.known_by_verity(&v, "f");
        s.commit(Some(&verity)).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"hello");
        assert!(has_verity(&path, &v));

        // a file that has it is kept
        let ino = std::os::unix::fs::MetadataExt::ino(&fs::metadata(&path).unwrap());
        let s = Session::create(&tmp.path().join("staging"), store.clone()).unwrap();
        let (mut f, temp) = s.create_temp().unwrap();
        io::Write::write_all(&mut f, b"hello").unwrap();
        drop(f);
        s.adopt_as(
            &temp,
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            5,
            false,
        )
        .unwrap();
        s.commit(Some(&verity)).unwrap();
        assert_eq!(
            std::os::unix::fs::MetadataExt::ino(&fs::metadata(&path).unwrap()),
            ino
        );
    }

    /// On a file system with fs-verity (VELARX_VERITY_DIR): with
    /// `fsverity_require` the commit refuses a file whose fs-verity is made
    /// with blocks smaller than 4096 bytes (as a file system with smaller
    /// blocks makes it), naming the size: its digest is not the one that
    /// names it.  Without the requirement it is committed.
    #[test]
    fn required_verity_refuses_the_digests_of_small_blocks_at_commit() {
        use velarx_storage::{FsVerityConfig, FsVerityManager};
        let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") else {
            eprintln!("VELARX_VERITY_DIR not set: skipped");
            return;
        };
        let small = |required| {
            FsVerityManager::with_config(FsVerityConfig {
                block_size: 1024,
                required,
                ..FsVerityConfig::default()
            })
        };
        let d =
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, b"hello");
        for required in [true, false] {
            let tmp = tempfile::tempdir_in(&dir).unwrap();
            let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
            let s = Session::create(&tmp.path().join("staging"), store.clone()).unwrap();
            s.put(&d, b"hello").unwrap();
            match s.commit(Some(&small(required))) {
                Ok(_) => assert!(!required, "committed with fsverity_require"),
                Err(e) => {
                    assert!(required, "{e}");
                    let e = e.to_string();
                    assert!(
                        e.contains("fsverity_require") && e.contains("1024 bytes"),
                        "{e}"
                    );
                    assert!(!store.contains_local(&d));
                }
            }
        }
    }

    /// A file system without fs-verity is an error when it is required.
    #[test]
    fn required_verity_is_not_skipped_where_there_is_none() {
        let tmp = tempfile::tempdir_in("/dev/shm").unwrap();
        let d = velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, b"x");
        for (mode, ok) in [
            (velarx_storage::VerityMode::On, true),
            (velarx_storage::VerityMode::Require, false),
        ] {
            let store = Arc::new(FileStore::new(tmp.path().join(format!("{mode:?}"))).unwrap());
            let s = Session::create(&tmp.path().join("staging"), store).unwrap();
            s.put(&d, b"x").unwrap();
            assert_eq!(s.commit(mode.manager().as_ref()).is_ok(), ok, "{mode:?}");
        }
    }

    /// A file a job gave, known by its sha256, that was written after it
    /// was checked (the job kept a descriptor) is not committed; one that
    /// was not is.
    #[test]
    fn a_file_a_job_changed_after_it_was_checked_is_not_committed() {
        use std::io::Write;
        use std::os::unix::fs::FileExt;
        for change in [false, true] {
            let (_tmp, s) = session();
            let key = crate::sha256_text(b"abc");
            let mut kept = File::from(
                rustix::fs::open(
                    s.dir(),
                    rustix::fs::OFlags::TMPFILE | rustix::fs::OFlags::RDWR,
                    rustix::fs::Mode::from_raw_mode(0o644),
                )
                .unwrap(),
            );
            kept.write_all(b"abc").unwrap();
            let given = File::open(velarx_sys::fd::proc_str(&kept)).unwrap();
            assert!(s.adopt_file(&given, &key, false, None).unwrap());
            if change {
                kept.write_all_at(b"xyz", 0).unwrap();
            }
            let committed = s.commit(None);
            if change {
                let err = committed.unwrap_err();
                assert!(err.to_string().contains("is not committed"), "{err}");
                assert!(s
                    .store()
                    .get_path(&velarx_storage::fsverity_digest_of(
                        velarx_types::digest::Algorithm::Sha256,
                        b"xyz"
                    ))
                    .is_none());
            } else {
                committed.unwrap();
                assert!(s.store().contains(&velarx_storage::fsverity_digest_of(
                    velarx_types::digest::Algorithm::Sha256,
                    b"abc"
                )));
            }
        }
    }

    /// A file known by an fs-verity digest its content does not have makes
    /// the commit fail before anything moves.
    #[test]
    fn a_file_without_the_digest_it_is_known_by_is_not_committed() {
        let (_tmp, s) = session();
        let good =
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, b"good");
        let lie = velarx_storage::fsverity_digest_of(
            velarx_types::digest::Algorithm::Sha256,
            b"what it should be",
        );
        s.put(&good, b"good").unwrap();
        s.put(&lie, b"something else").unwrap();
        s.known_by_verity(&lie, "a/file");
        let err = s.commit(None).unwrap_err();
        assert!(
            err.to_string().contains(&lie) && err.to_string().contains("a/file"),
            "{err}"
        );
        // (what was verified may be in the store, named by nothing: the
        // lie is not)
        assert!(!s.store().contains(&lie));
        assert!(!s.store().contains(&velarx_storage::fsverity_digest_of(
            velarx_types::digest::Algorithm::Sha256,
            b"something else"
        )));
    }

    /// A file waits in the session under a name that is no digest, whatever
    /// way it came (bytes in memory, a file with a name, a file with none, a
    /// session inside this one), whatever it is known by: the digest of a
    /// claim nothing checked yet is no name for a file, and none is given
    /// before the commit has checked it.
    #[test]
    fn a_staged_file_is_not_named_by_its_digest() {
        use crate::pull::testnames::digest_names;
        let (_tmp, s) = session();
        let alg = velarx_types::digest::Algorithm::Sha256;
        let by_verity = |data: &[u8]| velarx_storage::fsverity_digest_of(alg, data);
        let by_hash = |data: &[u8]| crate::sha256_text(data);
        // bytes in memory, known by a claim of fs-verity digest or a hash
        assert!(s.put(&by_verity(b"in memory"), b"in memory").unwrap());
        assert!(s.put(&by_hash(b"hashed"), b"hashed").unwrap());
        // a lie: the claim is not the digest of its bytes
        let lie = by_verity(b"what it claims to be");
        assert!(s.put(&lie, b"something else").unwrap());
        s.known_by_verity(&lie, "a/file");
        // a file with a name
        let (mut f, temp) = s.create_temp().unwrap();
        f.write_all(b"with a name").unwrap();
        drop(f);
        assert!(s
            .adopt_as(&temp, &by_verity(b"with a name"), 11, false)
            .unwrap());
        // a file with no name
        let mut kept = File::from(
            rustix::fs::open(
                s.dir(),
                rustix::fs::OFlags::TMPFILE | rustix::fs::OFlags::RDWR,
                rustix::fs::Mode::from_raw_mode(0o644),
            )
            .unwrap(),
        );
        kept.write_all(b"no name").unwrap();
        let given = File::open(velarx_sys::fd::proc_str(&kept)).unwrap();
        assert!(s
            .adopt_file(&given, &by_verity(b"no name"), false, Some("b/file"))
            .unwrap());
        // a session inside, whose file moves out
        let scratch = s.scratch().unwrap();
        let inner = by_verity(b"of the scratch");
        scratch.put(&inner, b"of the scratch").unwrap();
        assert_eq!(digest_names(scratch.dir()), Vec::<PathBuf>::new());
        let keep: std::collections::HashSet<&str> = [inner.as_str()].into();
        scratch.transfer_into(&s, &keep).unwrap();
        drop(scratch);

        assert_eq!(s.staged_totals().0, 6);
        assert_eq!(digest_names(s.dir()), Vec::<PathBuf>::new());
        for d in [&inner, &lie, &by_verity(b"in memory"), &by_hash(b"hashed")] {
            assert!(s.has_staged(d), "{d}");
        }
        // what is staged is read at the place it waits in
        assert_eq!(
            fs::read(s.content_path(&inner).unwrap()).unwrap(),
            b"of the scratch"
        );
        // the commit refuses the lie (what it verified may be in the store,
        // named by no row)
        let err = s.commit(None).unwrap_err();
        assert!(err.to_string().contains("a/file"), "{err}");
        assert!(!s.store().contains(&lie));
    }

    /// A digest names a file in the store only once the file has it: the
    /// commit enables fs-verity under the name it waits with, then moves
    /// it; whoever finds the name finds the file sealed (VELARX_VERITY_DIR).
    #[test]
    fn a_file_has_its_name_in_the_store_only_with_fs_verity() {
        use crate::pull::testnames::Names;
        let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") else {
            eprintln!("VELARX_VERITY_DIR not set: skipped");
            return;
        };
        let tmp = tempfile::tempdir_in(dir).unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let verity = velarx_storage::VerityMode::On.manager().unwrap();
        let s = Session::create(&tmp.path().join("staging"), store.clone()).unwrap();
        let alg = velarx_types::digest::Algorithm::Sha256;
        let data: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8; 5000 + i]).collect();
        for d in &data {
            s.put(&velarx_storage::fsverity_digest_of(alg, d), d)
                .unwrap();
        }
        // (the directories of the objects are there before: the watch is on
        // them, and tells each name as the commit gives it)
        let dirs: Vec<PathBuf> = data
            .iter()
            .map(|d| {
                let path = store
                    .local_path(&velarx_storage::fsverity_digest_of(alg, d))
                    .unwrap();
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                path.parent().unwrap().to_path_buf()
            })
            .collect();
        let dirs: Vec<&Path> = dirs.iter().map(PathBuf::as_path).collect();
        let names = Names::inspecting(
            &dirs,
            Box::new(|path| {
                let sealed = File::open(path)
                    .ok()
                    .and_then(|f| velarx_storage::measure_file(&f).ok())
                    .and_then(|m| m.object())
                    .is_some();
                (!sealed).then(|| format!("{} has its name and no fs-verity", path.display()))
            }),
        );
        let committed = s.commit(Some(&verity)).unwrap();
        assert_eq!(committed.len(), data.len());
        let (seen, complaints) = names.finish();
        assert_eq!(seen.len(), data.len(), "{seen:?}");
        assert!(complaints.is_empty(), "{complaints:?}");
        assert!(committed.iter().all(|c| c.object.checked));
    }

    /// A file the engine wrote and measured as it wrote it (a layer that was
    /// built, a stream that was ingested) is linked by its inode at the
    /// commit, whatever the store: no copy, and not a byte read to hash it
    /// again.
    #[test]
    fn a_file_measured_as_it_was_written_is_linked_and_not_read_again() {
        use std::os::unix::fs::MetadataExt;
        let (_tmp, s) = session();
        let alg = velarx_types::digest::Algorithm::Sha256;
        let data = vec![5u8; 300_000];
        let verity = velarx_storage::fsverity_digest_of(alg, &data);
        let (mut f, temp) = s.create_temp().unwrap();
        f.write_all(&data).unwrap();
        drop(f);
        let ino = fs::metadata(&temp).unwrap().ino();
        let key = crate::sha256_text(&data);
        s.adopt_measured(&temp, &key, &verity, data.len() as u64, false)
            .unwrap();
        let committed = s.commit(None).unwrap();
        assert_eq!(committed[0].object.verity, verity);
        let object = s.store().object_path(&committed[0].object);
        assert_eq!(fs::metadata(object).unwrap().ino(), ino);
        assert_eq!(s.store().hashed(), 0);
    }

    /// A file measured in both ways is known by its fs-verity digest, and
    /// nothing is staged for it, when the store or the session has it; else
    /// it is staged by its hash.  The temporary file of a hit goes.
    #[test]
    fn a_file_the_store_has_is_not_staged_again() {
        let (_tmp, s) = session();
        let alg = velarx_types::digest::Algorithm::Sha256;
        let by_verity = |data: &[u8]| velarx_storage::fsverity_digest_of(alg, data);
        let temp_with = |data: &[u8]| {
            let (mut f, temp) = s.create_temp().unwrap();
            f.write_all(data).unwrap();
            temp
        };
        let in_store = vec![1u8; 400_000];
        let verity = s.store().put(alg, &in_store).unwrap();
        // a file of the store: a temporary file goes, bytes in memory are not
        // written
        let temp = temp_with(&in_store);
        let key = crate::sha256_text(&in_store);
        assert_eq!(
            s.adopt_measured(&temp, &key, &verity, 400_000, false)
                .unwrap(),
            (verity.clone(), false)
        );
        assert!(!temp.exists());
        assert_eq!(
            s.put_measured(&key, &verity, &in_store, false).unwrap(),
            (verity.clone(), false)
        );
        assert_eq!(s.temp_files().len(), 0);
        assert_eq!(s.staged_totals(), (0, 0));

        // a file the session staged by its fs-verity digest (a layer of a
        // table of contents that names it so)
        let claimed = by_verity(b"staged by its digest");
        s.put(&claimed, b"staged by its digest").unwrap();
        let key = crate::sha256_text(b"staged by its digest");
        let temp = temp_with(b"staged by its digest");
        assert_eq!(
            s.adopt_measured(&temp, &key, &claimed, 20, false).unwrap(),
            (claimed.clone(), false)
        );
        assert!(!temp.exists());
        assert_eq!(s.staged_totals().0, 1);

        // a file nobody has: staged by its hash, once
        let new = b"nobody has it";
        let (key, verity) = (crate::sha256_text(new), by_verity(new));
        assert_eq!(
            s.put_measured(&key, &verity, new, false).unwrap(),
            (key.clone(), true)
        );
        assert_eq!(
            s.put_measured(&key, &verity, new, false).unwrap(),
            (key.clone(), false)
        );
        let temp = temp_with(new);
        assert_eq!(
            s.adopt_measured(&temp, &key, &verity, 13, false).unwrap(),
            (key.clone(), false)
        );
        assert!(!temp.exists());
        assert_eq!(s.staged_totals().0, 2);
        // (a scratch session sees what its parent staged by digest)
        let scratch = s.scratch().unwrap();
        assert_eq!(
            scratch
                .put_measured(
                    &crate::sha256_text(b"staged by its digest"),
                    &claimed,
                    b"x",
                    false
                )
                .unwrap(),
            (claimed, false)
        );
    }

    #[test]
    fn test_put_commit_and_dedup() {
        let (_tmp, s) = session();
        let d =
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, b"hello");
        assert!(!s.have(&d));
        assert!(s.put(&d, b"hello").unwrap());
        assert!(s.have(&d));
        assert!(!s.put(&d, b"hello").unwrap());
        assert!(!s.store().contains(&d));
        assert_eq!(s.staged_totals(), (1, 5));
        let moved = s.commit(None).unwrap();
        assert_eq!(
            moved,
            vec![Committed {
                digest: d.clone(),
                object: Object::new(&d, false).unwrap()
            }]
        );
        assert_eq!(
            fs::read(s.store().local_path(&d).unwrap()).unwrap(),
            b"hello"
        );
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &fs::metadata(s.store().local_path(&d).unwrap())
                .unwrap()
                .permissions(),
        );
        assert_eq!(mode & 0o777, 0o444);
        assert!(s.have(&d));
        assert_eq!(s.staged_totals(), (0, 0));
    }

    #[test]
    fn test_concurrent_puts_of_the_same_content() {
        let (_tmp, s) = session();
        let data = vec![7u8; 64 * 1024];
        let d = velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, &data);
        let added: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| s.put(&d, &data).unwrap()))
                .collect();
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum()
        });
        assert!(added >= 1);
        assert_eq!(fs::read(s.content_path(&d).unwrap()).unwrap(), data);
    }

    #[test]
    fn test_adopt_temp_files() {
        let (_tmp, s) = session();
        let d = velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, b"abc");
        let (mut f, p) = s.create_temp().unwrap();
        f.write_all(b"abc").unwrap();
        assert!(s.adopt(&p, &d, 3).unwrap());
        let (mut f, p2) = s.create_temp().unwrap();
        f.write_all(b"abc").unwrap();
        assert!(!s.adopt(&p2, &d, 3).unwrap());
        assert!(!p2.exists());
        assert_eq!(fs::read(s.content_path(&d).unwrap()).unwrap(), b"abc");
    }

    #[test]
    fn test_dropped_session_leaves_nothing() {
        let (tmp, s) = session();
        let d = velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, b"x");
        s.put(&d, b"x").unwrap();
        let dir = s.dir().to_path_buf();
        assert!(dir.exists());
        drop(s);
        assert!(!dir.exists());
        assert!(!tmp.path().join("files").join(&d[7..9]).exists());
    }

    #[test]
    fn the_temporary_files_are_spread_over_directories() {
        let (_tmp, s) = session();
        let made: Vec<_> = (0..SHARDS * 2)
            .map(|_| s.create_temp().unwrap().1)
            .collect();
        let dirs: std::collections::HashSet<_> = made.iter().map(|p| p.parent()).collect();
        assert_eq!(dirs.len() as u64, SHARDS);
        assert!(made.iter().all(|p| p.is_file()));
    }

    #[test]
    fn test_temp_files_are_exclusive() {
        let (_tmp, s) = session();
        let (_f, p) = s.create_temp().unwrap();
        std::os::unix::fs::symlink("/etc/passwd", s.dir().join("05/tmp-5")).unwrap();
        s.counter.store(5, Ordering::Relaxed);
        assert!(s.create_temp().is_err());
        assert!(p.exists());
    }

    #[test]
    fn test_session_names() {
        let (_tmp, s) = session();
        assert!(Session::is_session_name(&s.name()));
        assert!(!Session::is_session_name("pull-"));
        assert!(!Session::is_session_name("pull-../x"));
        assert!(!Session::is_session_name("other"));
    }

    /// A commit has two barriers (the staging, then the store) and none
    /// with `[storage] sync = "none"`.
    #[test]
    fn syncfs_setting_decides_the_barriers_of_a_commit() {
        for (sync, barriers) in [
            (velarx_base::sync::SyncMode::Syncfs, 2),
            (velarx_base::sync::SyncMode::None, 0),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let store = Arc::new(
                FileStore::new(tmp.path().join("files"))
                    .unwrap()
                    .with_sync(sync),
            );
            let s = Session::create(&tmp.path().join("staging"), store.clone()).unwrap();
            let d = velarx_storage::fsverity_digest_of(
                velarx_types::digest::Algorithm::Sha256,
                b"content",
            );
            s.put(&d, b"content").unwrap();
            let committed = s.commit(None).unwrap();
            assert_eq!(committed.len(), 1);
            assert!(store.contains_local(&committed[0].object.verity));
            assert_eq!(store.barriers(), barriers);
        }
    }

    /// The files of two layers' stagings and of the session itself are
    /// committed where they are staged, from one call: the two barriers of
    /// a commit, whatever the number of layers, and no link of a file into
    /// the session.
    #[test]
    fn the_files_of_the_stagings_of_layers_are_one_commit() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FileStore::new(tmp.path().join("files"))
                .unwrap()
                .with_sync(velarx_base::sync::SyncMode::Syncfs),
        );
        let root = tmp.path().join("staging");
        let s = Session::create(&root, store.clone()).unwrap();
        let key_of = |data: &[u8]| {
            velarx_types::digest::Digest::of_reader(velarx_types::digest::Algorithm::Sha256, data)
                .unwrap()
                .to_string()
        };
        for (stem, data) in [("one", &b"first"[..]), ("two", &b"second"[..])] {
            let layer = LayerStaging::made_for_test(&root, stem);
            let key = key_of(data);
            let rel = crate::stager::staged_rel(&key).unwrap();
            let path = layer.path().join(&rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, data).unwrap();
            let file = File::open(&path).unwrap();
            assert!(s.adopt_staged(&layer, &file, &key, false, None).unwrap());
            // (the file is where the fetcher staged it: one name)
            assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
        }
        let own =
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, b"third");
        s.put(&own, b"third").unwrap();
        let committed = s.commit(None).unwrap();
        assert_eq!(committed.len(), 3);
        for c in &committed {
            assert!(store.contains_local(&c.object.verity));
        }
        // (two stagings and the session: one barrier before the links, one
        // after)
        assert_eq!(store.barriers(), 2);
        // (the staging of a layer goes with the commit: the last holder
        // lets go)
        let dirs: Vec<_> = ["one", "two"]
            .iter()
            .map(|stem| root.join("layers").join(stem))
            .collect();
        assert!(dirs.iter().all(|d| !d.exists()));
    }

    /// A pull on a store without fs-verity (composefs, vfs: the session): the
    /// engine reads each staged byte once to verify it (before the locks) and
    /// names the very inode the fetcher wrote, so that no byte is written a
    /// second time; the locked part reads, hashes and copies nothing.
    #[test]
    fn a_pull_without_verity_reads_each_staged_byte_once_and_writes_none() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FileStore::new(tmp.path().join("files"))
                .unwrap()
                .with_sync(velarx_base::sync::SyncMode::Syncfs),
        );
        let root = tmp.path().join("staging");
        let s = Session::create(&root, store.clone()).unwrap();
        let layer = LayerStaging::made_for_test(&root, "one");
        let mut inodes = Vec::new();
        let mut total = 0u64;
        for data in [&b"first file"[..], b"the second", &[7u8; 100_000][..]] {
            let key = velarx_types::digest::Digest::of_reader(
                velarx_types::digest::Algorithm::Sha256,
                data,
            )
            .unwrap()
            .to_string();
            let path = layer.path().join(crate::stager::staged_rel(&key).unwrap());
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, data).unwrap();
            inodes.push(fs::metadata(&path).unwrap().ino());
            total += data.len() as u64;
            let file = File::open(&path).unwrap();
            assert!(s.adopt_staged(&layer, &file, &key, false, None).unwrap());
        }
        assert_eq!(store.hashed(), 0, "nothing is read before the verification");
        let verified = s.verify(None).unwrap();
        assert_eq!(
            store.hashed(),
            total,
            "each byte is read once, to verify it"
        );
        let before = (store.hashed(), store.copied());
        let mut inside = None;
        let mut between = |_: &[Committed]| {
            inside = Some((store.hashed(), store.copied()));
            Ok(false)
        };
        let committed = s.commit_verified(verified, Some(&mut between)).unwrap();
        assert_eq!(inside, Some(before), "nothing moved in the locked part");
        assert_eq!((store.hashed(), store.copied()), (before.0, 0));
        let mut stored: Vec<u64> = committed
            .iter()
            .map(|c| fs::metadata(store.object_path(&c.object)).unwrap().ino())
            .collect();
        stored.sort_unstable();
        inodes.sort_unstable();
        assert_eq!(stored, inodes, "the store has the inodes the fetcher wrote");
    }

    /// What is written between the link of the files and the barrier of the
    /// store (the images of the layers) is made durable by that barrier: a
    /// commit with the hook has the same two barriers, and one with no file
    /// but a write has the one of the store.
    #[test]
    fn what_the_hook_writes_has_no_barrier_of_its_own() {
        for (files, barriers) in [(true, 2), (false, 1)] {
            let tmp = tempfile::tempdir().unwrap();
            let store = Arc::new(
                FileStore::new(tmp.path().join("files"))
                    .unwrap()
                    .with_sync(velarx_base::sync::SyncMode::Syncfs),
            );
            let s = Session::create(&tmp.path().join("staging"), store.clone()).unwrap();
            if files {
                let d = velarx_storage::fsverity_digest_of(
                    velarx_types::digest::Algorithm::Sha256,
                    b"content",
                );
                s.put(&d, b"content").unwrap();
            }
            let image = store.root().join("image");
            let mut seen = 0;
            let mut hook = |committed: &[Committed]| {
                seen = committed.len();
                fs::write(&image, b"an image")?;
                Ok(true)
            };
            s.commit_with(None, Some(&mut hook)).unwrap();
            assert_eq!(seen, usize::from(files));
            assert!(image.is_file());
            assert_eq!(store.barriers(), barriers);
        }
    }

    /// The sweep removes the sessions of pulls that ended, not those of a
    /// pull that holds its lease (nor what is no session).
    #[test]
    fn test_sweep_removes_only_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("pull-0a1d/x")).unwrap();
        fs::create_dir_all(tmp.path().join("pull-11fe/x")).unwrap();
        // (a directory that only starts as a session does is not one)
        fs::create_dir_all(tmp.path().join("pull-other/x")).unwrap();
        fs::create_dir_all(tmp.path().join("other")).unwrap();
        Session::sweep(tmp.path(), |s| s == "pull-11fe");
        assert!(!tmp.path().join("pull-0a1d").exists());
        assert!(tmp.path().join("pull-11fe/x").exists());
        assert!(tmp.path().join("pull-other/x").exists());
        assert!(tmp.path().join("other").exists());
    }

    /// A scratch session is inside its parent: what keeps the parent keeps
    /// it, and it goes with it.
    #[test]
    fn a_scratch_session_is_inside_its_parent() {
        let (_tmp, parent) = session();
        let scratch = parent.scratch().unwrap();
        assert_eq!(scratch.dir().parent(), Some(parent.dir()));
        let staging = parent.dir().parent().unwrap().to_path_buf();
        Session::sweep(&staging, |s| s == parent.name());
        assert!(scratch.dir().is_dir());
        drop(scratch);
        assert_eq!(parent.temp_files().len(), 0);
    }
}
