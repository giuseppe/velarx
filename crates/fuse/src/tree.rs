// SPDX-License-Identifier: Apache-2.0
//! What the FUSE file system needs of the tree it serves: the images of the
//! layers, read where they are mapped (`erofs_tree::Layers`).  Inode numbers
//! are the tree's.

use fuser::FileType;
use std::time::SystemTime;

/// The attributes of a node, with the owners of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    pub kind: FileType,
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub rdev: u32,
    pub mtime: SystemTime,
    pub atime: SystemTime,
    pub ctime: SystemTime,
}

/// A time as seconds since the epoch (negative before it) and nanoseconds
/// (0 to 999 999 999, after the seconds).
pub(crate) fn unix_parts(t: SystemTime) -> (i64, u32) {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            match d.subsec_nanos() {
                0 => (-(d.as_secs() as i64), 0),
                n => (-(d.as_secs() as i64) - 1, 1_000_000_000 - n),
            }
        }
    }
}

/// The content of a regular file: a file of the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRef {
    pub digest: Option<String>,
    pub size: u64,
    /// The index of the layer that has it, for the fetch of what the store
    /// lacks.
    pub layer: usize,
    /// The bytes of a file that the image holds itself (composefs-rs puts
    /// the small ones in it): nothing to fetch.
    pub inline: Option<Vec<u8>>,
}

pub trait Tree: Send + Sync + 'static {
    /// The number of nodes, for `statfs`.
    fn len(&self) -> u64;

    /// The inode of `name` in the directory `parent`.
    fn lookup(&self, parent: u64, name: &str) -> Option<u64>;

    fn attr(&self, ino: u64) -> Option<Attr>;

    /// The target of a link; an error when the image does not have it.
    fn readlink(&self, ino: u64) -> std::io::Result<Vec<u8>>;

    /// What a regular file holds.
    fn file(&self, ino: u64) -> Option<FileRef>;

    /// The entries of a directory but the first `skip`, in order, until `f`
    /// (given the inode, the kind and the name) says the reply is full.  An
    /// error if `ino` is not a directory or the image does not have its
    /// entries whole.
    fn readdir(
        &self,
        ino: u64,
        skip: usize,
        f: &mut dyn FnMut(u64, FileType, &[u8]) -> bool,
    ) -> std::io::Result<()>;

    /// The attributes that are shown, with their values.
    fn xattrs(&self, ino: u64) -> Option<Vec<(String, Vec<u8>)>>;
}
