// SPDX-License-Identifier: Apache-2.0
//! The image of the infra containers of pods when none is configured: a
//! local image with one layer that holds a static `catatonit`, as podman
//! builds `localhost/podman-pause`.  Nothing is pulled for it.

use super::*;
use serde_json::json;
use std::path::Path;

/// Where the distributions install a static `catatonit`.
const CATATONIT: &[&str] = &[
    "/usr/libexec/podman/catatonit",
    "/usr/libexec/catatonit/catatonit",
    "/usr/local/libexec/podman/catatonit",
    "/usr/bin/catatonit",
    "/usr/local/bin/catatonit",
];

/// The name of the local pause image of this version.
pub fn pause_image_name() -> String {
    format!("localhost/velarx-pause:{}", env!("CARGO_PKG_VERSION"))
}

/// The image of the infra containers: the first of `wanted` (the pod's, the
/// configured one) that names one, else the local pause image.
pub fn infra_image_name<'a>(wanted: impl IntoIterator<Item = Option<&'a str>>) -> String {
    wanted
        .into_iter()
        .flatten()
        .find(|i| !i.is_empty())
        .map_or_else(pause_image_name, str::to_string)
}

/// Whether the ELF executable `data` needs no program interpreter (it is
/// linked statically, and runs in an empty root file system).
pub(crate) fn is_static_elf(data: &[u8]) -> bool {
    const PT_INTERP: u32 = 3;
    let u16_at = |o: usize| data.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| {
        data.get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let u64_at = |o: usize| {
        data.get(o..o + 8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_le_bytes)
    };
    // 64-bit little-endian ELF executable or position independent one
    if data.get(..6) != Some(&[0x7f, b'E', b'L', b'F', 2, 1][..]) {
        return false;
    }
    if !matches!(u16_at(16), Some(2 | 3)) {
        return false;
    }
    let (Some(phoff), Some(phentsize), Some(phnum)) = (u64_at(0x20), u16_at(0x36), u16_at(0x38))
    else {
        return false;
    };
    let Ok(phoff) = usize::try_from(phoff) else {
        return false;
    };
    let phentsize = usize::from(phentsize);
    if phentsize < 4 || phnum == 0 {
        return false;
    }
    (0..usize::from(phnum)).all(|i| {
        phoff
            .checked_add(i.saturating_mul(phentsize))
            .and_then(u32_at)
            .is_some_and(|t| t != PT_INTERP)
    })
}

/// A static `catatonit` of the host.
fn find_catatonit() -> Option<std::path::PathBuf> {
    let from_path = std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("catatonit"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    CATATONIT
        .iter()
        .map(std::path::PathBuf::from)
        .chain(from_path)
        .find(|p| std::fs::read(p).is_ok_and(|data| is_static_elf(&data)))
}

impl ImageService {
    /// The local pause image, built from the host's `catatonit` when it is
    /// not in the store yet.
    pub async fn pause_image(&self) -> ImageResult<String> {
        let name = pause_image_name();
        // (a store that cannot be read is an error, not a missing image)
        let built = |found: ImageResult<_>| match found {
            Ok(_) => Ok(true),
            Err(ImageError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        };
        if built(self.get(&name).await)? {
            return Ok(name);
        }
        // (one build at a time in the store, across processes)
        let path = self
            .file_store
            .root()
            .with_file_name("locks")
            .join("pause-image");
        let _build = tokio::task::spawn_blocking(move || {
            velarx_storage::locks::lock(&path, true)
                .map(|f| f.expect("a wait gives the lock or an error"))
        })
        .await
        .map_err(|e| ImageError::Storage(e.to_string()))?
        .map_err(ImageError::Io)?;
        if built(self.get(&name).await)? {
            return Ok(name);
        }
        // (the candidates are read whole, and the root is copied: off the
        // threads of the runtime)
        let bin = crate::off_thread(|| Ok(find_catatonit()))
            .await?
            .ok_or_else(|| {
                ImageError::Layer(
                    "no infra image is configured and no static catatonit was found to build \
                 the local pause image: install catatonit, or set infra_image in the \
                 [containers] section of the configuration"
                        .into(),
                )
            })?;
        let (staging, from) = (self.staging_dir.clone(), bin.clone());
        let dir = crate::off_thread(move || {
            std::fs::create_dir_all(&staging)?;
            let dir = tempfile::tempdir_in(&staging)?;
            build_root(dir.path(), &from)?;
            Ok(dir)
        })
        .await?;
        let opts = CommitOptions {
            edits: vec![
                ConfigEdit::Set("Entrypoint".into(), json!(["/catatonit", "-P"])),
                ConfigEdit::Unset("Cmd".into()),
            ],
            created_by: format!("velarx: the pause image from {}", bin.display()),
            names: vec![name.clone()],
            ..Default::default()
        };
        self.commit_dir(None, Some(dir.path()), &opts).await?;
        info!("Built the pause image {} from {}", name, bin.display());
        Ok(name)
    }
}

/// The root of the image: `/catatonit` only.
fn build_root(root: &Path, bin: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755))?;
    let dest = root.join("catatonit");
    std::fs::copy(bin, &dest)?;
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf(e_type: u16, interp: bool) -> Vec<u8> {
        let mut d = vec![0u8; 0x40 + 2 * 56];
        d[..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1]);
        d[16..18].copy_from_slice(&e_type.to_le_bytes());
        d[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        d[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        d[0x38..0x3a].copy_from_slice(&2u16.to_le_bytes());
        d[0x40..0x44].copy_from_slice(&1u32.to_le_bytes());
        let second: u32 = if interp { 3 } else { 1 };
        d[0x40 + 56..0x40 + 60].copy_from_slice(&second.to_le_bytes());
        d
    }

    /// The pod's image wins over the configured one, an empty name is none,
    /// and with none the image is the local pause image.
    #[test]
    fn the_infra_image_is_the_first_named_else_the_pause_image() {
        assert_eq!(infra_image_name([Some("a"), Some("b")]), "a");
        assert_eq!(infra_image_name([Some(""), Some("b")]), "b");
        assert_eq!(infra_image_name([None, Some("b")]), "b");
        assert_eq!(infra_image_name([None, Some("")]), pause_image_name());
        assert_eq!(infra_image_name([]), pause_image_name());
    }

    #[test]
    fn a_static_executable_is_told_from_a_dynamic_one() {
        assert!(is_static_elf(&elf(2, false)));
        assert!(is_static_elf(&elf(3, false)));
        assert!(!is_static_elf(&elf(2, true)));
        assert!(!is_static_elf(&elf(1, false)));
        // not executed
        assert!(!is_static_elf(b"#!/bin/sh\n"));
        assert!(!is_static_elf(&elf(2, false)[..0x50]));
        if let Ok(sh) = std::fs::read("/bin/sh") {
            assert!(!is_static_elf(&sh), "/bin/sh is dynamic");
        }
    }

    #[test]
    fn the_root_holds_the_executable() {
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("bin");
        std::fs::write(&bin, b"x").unwrap();
        let root = d.path().join("root");
        std::fs::create_dir(&root).unwrap();
        build_root(&root, &bin).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&root), 0o755);
        assert_eq!(mode(&root.join("catatonit")), 0o755);
    }
}
