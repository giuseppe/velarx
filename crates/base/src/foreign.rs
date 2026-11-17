// SPDX-License-Identifier: Apache-2.0
//! The foreign stores of `[storage] foreign_object_stores`, as the
//! configuration names them (what reads them is `velarx_storage::foreign`).
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// What a foreign store is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForeignKind {
    /// A composefs-rs repository: `meta.json` and `objects/`, named by the
    /// fs-verity digest of the one algorithm of the repository.
    #[serde(rename = "composefs-rs")]
    ComposefsRs,
    /// The root of another velarx store: its `objects/`, with both
    /// algorithms.
    #[serde(rename = "velarx")]
    Velarx,
    /// The graph root of containers/storage (podman, buildah, CRI-O) with
    /// `use_composefs`: `overlay/<layer>/diff/xx/yyy`, named by the sha256 of
    /// the content, for the layers of its images.
    #[serde(rename = "containers-storage")]
    ContainersStorage,
}

impl ForeignKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::ComposefsRs => "composefs-rs",
            Self::Velarx => "velarx",
            Self::ContainersStorage => "containers-storage",
        }
    }
}

/// A foreign store of the configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignStoreSpec {
    /// Its root: an absolute path.
    pub path: PathBuf,
    pub kind: ForeignKind,
    /// A file that already has fs-verity and is owned by the user velarx
    /// runs as may be hard linked (it then shares the inode of the foreign
    /// store, and the space of the file is not freed by that store's prune);
    /// else files are reflinked or copied.
    #[serde(default)]
    pub link: bool,
}
