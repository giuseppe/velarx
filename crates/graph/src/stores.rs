// SPDX-License-Identifier: Apache-2.0
//! The identity of the engine's store, for a driver that serves several
//! stores (a driver in another process, which keeps the data of every engine
//! that connects).
//!
//! Every call of such a driver carries the id of the store it is about.  The
//! id is **not** in the engine's database: the database is deleted as the
//! remedy for a broken or a foreign one, and a new database with a new id
//! would leave everything the driver holds under the old one (layers, roots,
//! staging) named by nobody, so that no `Collect` of the new store ever frees
//! it.  The id is a file of the graph root, `<root>/varlink/store-id`, made once
//! (0600) and read back at every start; a rebuilt database finds the same
//! store, and the layers the driver still has are matched by `has_layers` (the
//! engine does not pull them again).  A store that no engine opens any more is
//! listed ([`crate::StorageDriver::list_stores`]) and dropped
//! ([`crate::StorageDriver::drop_store`]).
//!
//! The drivers of the engine's process keep one store and need no id: the
//! engine makes no file for them.  The wire client opens its store with
//! [`StoreId::of_root`] (`velarx_storage_client::VarlinkDriver::open`) and
//! sends the id with every call.

use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The directory of the graph root that holds the id.
pub const DIR: &str = "varlink";
/// The file of [`DIR`].
pub const FILE: &str = "store-id";

/// The id of a store: a v4 UUID (122 random bits) as 32 hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoreId(String);

/// A store a driver holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreInfo {
    pub store: String,
    /// What the store takes on the driver's disk.
    pub bytes: u64,
    /// When an engine last opened it (seconds since the epoch), none if the
    /// driver does not know.
    pub last_open: Option<i64>,
}

fn valid(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl StoreId {
    /// The path of the id file of the graph root `root`.
    pub fn path(root: &Path) -> PathBuf {
        root.join(DIR).join(FILE)
    }

    /// The id of the store of the graph root `root`: the one in its file, made
    /// (once, at the first call) when there is none.  Two engines that make it
    /// at the same time get the same id.  A file that is not an id is an
    /// error and is **not** replaced: a new id would orphan what the driver
    /// holds under the old one.
    pub fn of_root(root: &Path) -> io::Result<Self> {
        let path = Self::path(root);
        match Self::read(&path) {
            Ok(id) => return Ok(id),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let dir = root.join(DIR);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        // (written whole to a name of its own, then linked: the file appears
        // with its content or not at all, and the first to link wins)
        let tmp = dir.join(format!(".{FILE}.{}", velarx_base::random::token()));
        let id = velarx_base::random::token();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(format!("{id}\n").as_bytes())?;
        f.sync_all()?;
        drop(f);
        let linked = std::fs::hard_link(&tmp, &path);
        let _ = std::fs::remove_file(&tmp);
        match linked {
            Ok(()) => {
                // (the directory entry is durable before the id is used)
                std::fs::File::open(&dir)?.sync_all()?;
                Ok(Self(id))
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Self::read(&path),
            Err(e) => Err(e),
        }
    }

    /// The id of the store of the graph root `root` as its file has it,
    /// never made here: for a question about the store an engine opened
    /// (`NotFound` when the file is gone since).
    pub fn of_root_as_made(root: &Path) -> io::Result<Self> {
        Self::read(&Self::path(root))
    }

    fn read(path: &Path) -> io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let id = text.trim_end_matches('\n');
        if !valid(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is not a store id (32 hex digits): it is not replaced, since a new id would leave what the storage driver holds for the old one named by nobody; restore the file, or drop the old store with the driver's `DropStore` first",
                    path.display()
                ),
            ));
        }
        Ok(Self(id.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for StoreId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `id` can be the id of a store (what a driver accepts in `DropStore`
/// before it removes anything named by it: a name is never a path).
pub fn is_store_id(id: &str) -> bool {
    valid(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_id_is_made_once_and_survives_the_database() {
        let root = tempfile::tempdir().unwrap();
        let a = StoreId::of_root(root.path()).unwrap();
        assert!(is_store_id(a.as_str()));
        let mode = std::fs::metadata(StoreId::path(root.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir = std::fs::metadata(root.path().join(DIR)).unwrap();
        assert_eq!(dir.permissions().mode() & 0o777, 0o700);
        // (the database is deleted and made again: the file is not in it)
        std::fs::create_dir(root.path().join("db")).unwrap();
        std::fs::remove_dir_all(root.path().join("db")).unwrap();
        assert_eq!(StoreId::of_root(root.path()).unwrap(), a);
        // no temporary file is left
        let names: Vec<_> = std::fs::read_dir(root.path().join(DIR))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from(FILE)]);
        // another root is another store
        let other = tempfile::tempdir().unwrap();
        assert_ne!(StoreId::of_root(other.path()).unwrap(), a);
    }

    #[test]
    fn engines_that_make_it_together_get_one_id() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_path_buf();
        let ids: Vec<_> = (0..8)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || StoreId::of_root(&p).unwrap())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect();
        assert!(ids.windows(2).all(|w| w[0] == w[1]), "{ids:?}");
        assert_eq!(StoreId::of_root(&path).unwrap(), ids[0]);
    }

    #[test]
    fn a_file_that_is_not_an_id_is_not_replaced() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(DIR)).unwrap();
        let path = StoreId::path(root.path());
        for bad in [
            "",
            "short\n",
            &"G".repeat(32),
            &format!("{}\n\n", "a".repeat(33)),
        ] {
            std::fs::write(&path, bad).unwrap();
            let e = StoreId::of_root(root.path()).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            assert!(e.to_string().contains("not replaced"), "{e}");
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                bad,
                "kept as it was"
            );
        }
    }
}
