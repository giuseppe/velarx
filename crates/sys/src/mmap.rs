// SPDX-License-Identifier: Apache-2.0
//! Files mapped in memory.

use std::ops::Deref;
use std::os::fd::AsFd;

/// A file mapped read-only and private (`PROT_READ`, `MAP_PRIVATE`); the
/// mapping ends with the value.
pub struct Mmap {
    ptr: *mut std::ffi::c_void,
    len: usize,
}

// SAFETY: the mapping is read-only and private, and the value owns it:
// nothing writes through it, so sharing and moving it between threads is
// the same as for a `&[u8]`.
unsafe impl Send for Mmap {}
// SAFETY: see `Send`.
unsafe impl Sync for Mmap {}

impl Deref for Mmap {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: `ptr` is the start of a live mapping of `len` readable
        // bytes (until `drop`); nothing in this process writes to it.
        unsafe { std::slice::from_raw_parts(self.ptr.cast::<u8>(), self.len) }
    }
}

impl AsRef<[u8]> for Mmap {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        if self.len != 0 {
            // SAFETY: `ptr` and `len` are those of the mapping made in
            // `map_file`, which nothing else unmaps; no reference into it
            // outlives the value.
            let _ = unsafe { rustix::mm::munmap(self.ptr, self.len) };
        }
    }
}

/// Map `file` read-only and private (`PROT_READ`, `MAP_PRIVATE`), its
/// length from `fstat` of that descriptor: what is read is that open file,
/// whatever its path names afterwards.  The files that are mapped are those
/// of the store, which are made aside and renamed and which nobody writes: a
/// truncation by another process would be an error of that process, not
/// something this one defends against.
pub fn map_file(file: &std::fs::File) -> std::io::Result<Mmap> {
    let len = usize::try_from(rustix::fs::fstat(file)?.st_size)
        .map_err(|_| std::io::Error::other("file too large to map"))?;
    if len == 0 {
        // (mmap refuses a length of 0)
        return Ok(Mmap {
            ptr: std::ptr::null_mut(),
            len: 0,
        });
    }
    // SAFETY: a new mapping at an address the kernel chooses (no
    // MAP_FIXED), so it overlaps no memory of ours; the file is not
    // modified while mapped (see above); the mapping is read-only.
    let ptr = unsafe {
        rustix::mm::mmap(
            std::ptr::null_mut(),
            len,
            rustix::mm::ProtFlags::READ,
            rustix::mm::MapFlags::PRIVATE,
            file.as_fd(),
            0,
        )
    }?;
    Ok(Mmap { ptr, len })
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_file_is_mapped() {
        let dir = std::env::temp_dir().join(format!("velarx-sys-map-{}", std::process::id()));
        std::fs::write(&dir, b"abc").unwrap();
        let map = super::map_file(&std::fs::File::open(&dir).unwrap()).unwrap();
        assert_eq!(&map[..], b"abc");
        std::fs::remove_file(&dir).unwrap();
    }

    #[test]
    fn an_empty_file_is_an_empty_map() {
        let file = tempfile::tempfile().unwrap();
        let map = super::map_file(&file).unwrap();
        assert!(map.is_empty());
    }
}
