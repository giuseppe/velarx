// SPDX-License-Identifier: Apache-2.0
//! Small helpers on directories of the store and on the names of a layer.

use std::io;
use std::path::Path;

/// Refuse a name that is not one component of a path: a layer may not have
/// it, and nothing is made by it.
pub(crate) fn check_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("`{name}` is not a name a layer may have"),
        ));
    }
    Ok(())
}

/// The bytes of the regular files below `dir`.
pub fn tree_size(dir: &Path) -> u64 {
    velarx_base::tree::usage(
        dir,
        &velarx_base::tree::Measure {
            lenient: true,
            ..Default::default()
        },
    )
    .map_or(0, |u| u.file_bytes)
}
