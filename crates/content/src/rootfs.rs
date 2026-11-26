// SPDX-License-Identifier: Apache-2.0
//! `rootfs:DIR`: a root file system in a directory as the image of one
//! layer.  The directory is walked in the order of a canonical tar (what the
//! layer of a commit is made of), the tar is the layer and the diff id, and
//! the configuration has nothing that changes from one run to the other: the
//! same directory is the same image.

use crate::archive::{Archive, ArchiveImage, LAYER, OCI_CONFIG, OCI_MANIFEST};
use crate::layer::dirtar;
use crate::layer::holes::SparseFile;
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use velarx_types::digest::{Algorithm, Digest};

/// The image of the directory `dir` (open): its layer is written in a file
/// without a name in `staging`, with the configuration after it.
pub fn image(dir: &File, staging: &File) -> io::Result<(Archive, ArchiveImage)> {
    let mut tar = SparseFile::new(crate::pull::unnamed::unnamed_file_at(staging)?);
    let opts = dirtar::Options {
        root: dirtar::Root::Always,
        ..Default::default()
    };
    dirtar::write(dir.as_fd(), &opts, &mut tar)?;
    let file = tar.finish()?;
    let size = file.metadata()?.len();
    let (layer, _) = Digest::of_file_at(Algorithm::Sha256, &file, size)?;
    let config = serde_json::to_vec(&serde_json::json!({
        "architecture": velarx_registry::target::host_arch(),
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [layer]},
    }))
    .map_err(io::Error::other)?;
    file.write_all_at(&config, size)?;
    let config_digest = Digest::of(Algorithm::Sha256, &config);
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {
            "mediaType": OCI_CONFIG,
            "digest": config_digest,
            "size": config.len(),
        },
        "layers": [{"mediaType": LAYER, "digest": layer, "size": size}],
    }))
    .map_err(io::Error::other)?;
    let image = ArchiveImage {
        digest: Digest::of(Algorithm::Sha256, &manifest),
        media_type: OCI_MANIFEST.to_string(),
        manifest,
        names: Vec::new(),
        aliases: Vec::new(),
    };
    let archive = Archive::blobs(
        file,
        &[(layer, 0, size), (config_digest, size, config.len() as u64)],
    );
    Ok((archive, image))
}
