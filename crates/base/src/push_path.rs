// SPDX-License-Identifier: Apache-2.0
//! What a push to a path writes and where it may write it: the command line
//! checks a destination before it hands it over, the pusher of a path
//! (`velarx-dir --push`) learns its mode from the scheme of its destination.

use rustix::fs::AtFlags;
use std::fs::File;
use std::os::fd::AsFd;

/// What the destination is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Layout,
    Dir,
    Archive,
}

impl Mode {
    /// The transport that says it: what a pusher is told of the
    /// destination, never the path.
    pub fn scheme(self) -> &'static str {
        match self {
            Mode::Layout => "oci:",
            Mode::Dir => "dir:",
            Mode::Archive => "oci-archive:",
        }
    }

    /// The mode a destination's text says by its transport: `oci:`, `dir:`
    /// or `oci-archive:` (what the engine tells a pusher of a path; never
    /// the path).
    pub fn of_scheme(destination: &str) -> Option<Self> {
        [Mode::Layout, Mode::Dir, Mode::Archive]
            .into_iter()
            .find(|m| {
                destination
                    .strip_prefix(m.scheme())
                    .is_some_and(|rest| rest.is_empty())
            })
    }

    /// Whether the destination is a directory (else a file).
    pub fn is_directory(self) -> bool {
        self != Mode::Archive
    }
}

/// Whether a directory can be written to as the destination of `mode`:
/// a layout is an empty directory or one with an `index.json`, a `dir:` an
/// empty one.  The refusal says why.
pub fn check_destination(dir: &File, mode: Mode) -> Result<(), String> {
    let has = |name: &str| rustix::fs::statat(dir.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW).is_ok();
    let empty = {
        let mut entries = rustix::fs::Dir::read_from(dir.as_fd()).map_err(|e| e.to_string())?;
        !entries.any(|e| e.is_ok_and(|e| !matches!(e.file_name().to_bytes(), b"." | b"..")))
    };
    match mode {
        Mode::Layout if !empty && !has("index.json") => {
            Err("it is not empty and is no OCI layout".into())
        }
        Mode::Dir if !empty => Err("it is not empty".into()),
        _ => Ok(()),
    }
}
