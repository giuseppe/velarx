// SPDX-License-Identifier: Apache-2.0
//! What the readers of the EROFS images of the layers (`layer_erofs`) share,
//! with the reader of the `composefs` crate: the attributes of an inode, its
//! owners, the entries of a directory.  A regular file is only its inode, with
//! the redirect to the file of the store that gives its digest (`ab/cdef...`
//! is `fsverity-sha256-12:abcdef...` with 62 digits after the directory,
//! `fsverity-sha512-12:abcdef...` with 126).

use composefs::erofs::format::XATTR_PREFIXES;
use composefs::erofs::reader::{Image, InodeOps, InodeType};
use velarx_storage::FsVerityHashAlgorithm;
use velarx_types::digest::{Algorithm, Digest};

pub(crate) fn full_name(x: &composefs::erofs::reader::XAttr) -> Vec<u8> {
    let idx = x.header.name_index as usize;
    let prefix = XATTR_PREFIXES.get(idx).copied().unwrap_or(b"");
    let mut name = prefix.to_vec();
    name.extend_from_slice(x.suffix().unwrap_or(b""));
    name
}

/// The attributes of an inode, by full name.
pub(crate) fn xattrs(img: &Image, inode: &InodeType) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let Some(section) = inode.xattrs().ok().flatten() else {
        return out;
    };
    if let Ok(shared) = section.shared() {
        for id in shared {
            if let Ok(x) = img.shared_xattr(id.get()) {
                out.push((full_name(x), x.value().unwrap_or(b"").to_vec()));
            }
        }
    }
    if let Ok(local) = section.local() {
        for x in local.flatten() {
            out.push((full_name(x), x.value().unwrap_or(b"").to_vec()));
        }
    }
    out
}

/// The owner and the modification time (seconds) of an inode.
#[cfg(test)]
pub(crate) fn owner_time(img: &Image, inode: &InodeType) -> (u32, u32, u64) {
    match inode {
        InodeType::Extended(i) => (i.header.uid.get(), i.header.gid.get(), i.header.mtime.get()),
        InodeType::Compact(i) => (
            u32::from(i.header.uid.get()),
            u32::from(i.header.gid.get()),
            img.sb.build_time.get(),
        ),
    }
}

/// The digest of the file of the store a `redirect` says (`/ab/cdef...`):
/// the object it names, of the algorithm whose digests have that many
/// digits; None for a path that is no object.
pub(crate) fn redirect_digest(value: &[u8]) -> Option<String> {
    // (exactly the path the kernel follows: `/`, two digits, `/`, the rest)
    let [b'/', a, b, b'/', rest @ ..] = value else {
        return None;
    };
    if rest.contains(&b'/') {
        return None;
    }
    let hex = format!(
        "{}{}{}",
        *a as char,
        *b as char,
        std::str::from_utf8(rest).ok()?
    );
    let alg = Algorithm::ALL
        .into_iter()
        .find(|a| a.len() * 2 == hex.len())?;
    Digest::parse_fsverity(&format!("fsverity-{alg}-12:{hex}"))
        .ok()
        .map(|d| d.to_string())
}

/// The digest a `metacopy` states (struct ovl_metacopy: version 0, length,
/// flags 0, the fs-verity algorithm, then the digest): the object of the
/// algorithm it says, when the digest has the length of that algorithm;
/// None for anything else.
pub(crate) fn metacopy_digest(value: &[u8]) -> Option<String> {
    let [0, len, 0, algorithm, digest @ ..] = value else {
        return None;
    };
    let alg = match *algorithm {
        a if a == FsVerityHashAlgorithm::Sha256 as u8 => Algorithm::Sha256,
        a if a == FsVerityHashAlgorithm::Sha512 as u8 => Algorithm::Sha512,
        _ => return None,
    };
    (usize::from(*len) == 4 + alg.len() && digest.len() == alg.len())
        .then(|| Digest::fsverity(alg, digest).ok())
        .flatten()
        .map(|d| d.to_string())
}

/// The directory entries (not `.` and `..`) of a directory inode.
#[cfg(test)]
pub(crate) fn dir_entries(img: &Image, inode: &InodeType) -> Result<Vec<(Vec<u8>, u64)>, String> {
    use composefs::erofs::reader::DirectoryBlock;
    use zerocopy::FromBytes as _;
    let mut out = Vec::new();
    let mut add = |block: &DirectoryBlock| -> Result<(), String> {
        for e in block.entries().map_err(|e| e.to_string())?.flatten() {
            if e.name != b"." && e.name != b".." {
                out.push((e.name.to_vec(), e.nid()));
            }
        }
        Ok(())
    };
    if let Some(inline) = inode.inline() {
        if let Ok(block) = DirectoryBlock::ref_from_bytes(inline) {
            add(block)?;
        }
    }
    for b in img.inode_blocks(inode).map_err(|e| e.to_string())? {
        add(img.directory_block(b).map_err(|e| e.to_string())?)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_metacopy_states_a_digest_of_its_algorithm_or_nothing() {
        for (alg, hash, len) in [
            (Algorithm::Sha256, 1u8, 32usize),
            (Algorithm::Sha512, 2, 64),
        ] {
            let digest = Digest::fsverity(alg, &vec![0xab; len]).unwrap();
            let good = crate::layer_erofs::metacopy(&digest);
            // (version 0, 4 + the digest, no flags, the hash, the digest)
            assert_eq!(&good[..4], &[0, (4 + len) as u8, 0, hash]);
            assert_eq!(good.len(), 4 + len);
            assert_eq!(metacopy_digest(&good), Some(digest.to_string()));
            // the digest of the redirect is the one the stub states
            assert_eq!(
                metacopy_digest(&good),
                redirect_digest(&crate::layer_erofs::redirect(&digest))
            );
            let mut short = good.clone();
            short.pop();
            short[1] -= 1;
            let mut long = good.clone();
            long.push(0);
            long[1] += 1;
            // the other algorithm's byte on the same digest, or the length
            // of the other algorithm with this one's byte
            let mut other_algorithm = good.clone();
            other_algorithm[3] = 3 - hash;
            let mut unknown = good.clone();
            unknown[3] = 9;
            let mut flagged = good.clone();
            flagged[2] = 1;
            for bad in [
                &b""[..],
                &short,
                &long,
                &other_algorithm,
                &unknown,
                &flagged,
            ] {
                assert_eq!(metacopy_digest(bad), None, "{alg} {bad:?}");
            }
        }
        // a redirect of neither length is no object
        assert_eq!(redirect_digest(b"/ab/cd"), None);
        // (the digits of an object in another shape are not its path)
        let hex = "ab".repeat(32);
        let good = format!("/{}/{}", &hex[..2], &hex[2..]);
        assert!(redirect_digest(good.as_bytes()).is_some());
        for bad in [
            format!("{}/{}", &hex[..2], &hex[2..]),
            format!("/{}/{}", &hex[..1], &hex[1..]),
            format!("/{}/{}", &hex[..3], &hex[3..]),
            format!("/{}/{}/", &hex[..2], &hex[2..]),
            format!("/{}/{}/{}", &hex[..2], &hex[2..4], &hex[4..]),
        ] {
            assert_eq!(redirect_digest(bad.as_bytes()), None, "{bad}");
        }
        assert_eq!(redirect_digest(&[b'/'; 3]), None);
    }
}
