// SPDX-License-Identifier: Apache-2.0
//! Sealed memory files: how bytes that must not change go to another
//! process without a name: the credentials of a call to a fetcher, the
//! configuration of a process, the data of a reply of a fetcher.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;

/// The seals of [`sealed_memory`]: nothing can change, grow or shrink it,
/// nor lift the seals.
pub fn memory_seals() -> rustix::fs::SealFlags {
    use rustix::fs::SealFlags;
    SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL
}

/// A file in memory holding `bytes`, sealed: it never touches a disk, no
/// process can change it, and it has no name.  What a secret travels in (the
/// credentials of a call to the fetcher), never data.
pub fn sealed_memory(bytes: &[u8]) -> io::Result<OwnedFd> {
    use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags};
    let fd = memfd_create("access", MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)?;
    io::Write::write_all(&mut File::from(fd.try_clone()?), bytes)?;
    fcntl_add_seals(&fd, memory_seals())?;
    Ok(fd)
}

/// The bytes of a sealed memory file another process passed
/// ([`sealed_memory`]): a regular file of exactly `length` bytes, 1 to `max`,
/// that nothing can change ([`memory_seals`]), read whole at its places (its
/// offset is the sender's too).  The error says what the file is not, for the
/// caller to name it.
pub fn read_sealed(file: &File, length: u64, max: u64) -> Result<Vec<u8>, &'static str> {
    use std::os::unix::fs::FileExt;
    if length == 0 || length > max {
        return Err("has no bytes or too many");
    }
    let meta = file.metadata().map_err(|_| "cannot be read")?;
    if !meta.is_file() || meta.len() != length {
        return Err("is not a regular file of the length said");
    }
    if rustix::fs::fcntl_get_seals(file).ok() != Some(memory_seals()) {
        return Err("is not a sealed memory file");
    }
    let mut bytes = vec![0u8; length as usize];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|_| "cannot be read")?;
    Ok(bytes)
}

/// [`read_sealed`] of a file whose length is what it says it is: 1 to `max`
/// bytes (the receiver of a call that names it by position, with no length
/// of its own).
pub fn read_sealed_whole(file: &File, max: u64) -> Result<Vec<u8>, &'static str> {
    let length = file.metadata().map_err(|_| "cannot be read")?.len();
    read_sealed(file, length, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A memory file that is not sealed, for the tests of what refuses it.
    fn unsealed_memory(bytes: &[u8]) -> io::Result<OwnedFd> {
        let fd = rustix::fs::memfd_create("open", rustix::fs::MemfdFlags::CLOEXEC)?;
        io::Write::write_all(&mut File::from(fd.try_clone()?), bytes)?;
        Ok(fd)
    }

    #[test]
    fn a_memory_file_that_is_not_sealed_is_not_read() {
        // (the asker could still change it while it is read)
        let open = File::from(unsealed_memory(b"{\"x\":1}").unwrap());
        assert!(read_sealed(&open, 7, 100).is_err());
    }

    #[test]
    fn sealed_memory_holds_the_bytes_and_cannot_change() {
        let file = File::from(sealed_memory(b"secret").unwrap());
        assert_eq!(rustix::fs::fcntl_get_seals(&file).unwrap(), memory_seals());
        let mut back = vec![0u8; 6];
        std::os::unix::fs::FileExt::read_exact_at(&file, &mut back, 0).unwrap();
        assert_eq!(back, b"secret");
        assert!(std::io::Write::write_all(&mut &file, b"more").is_err());
        assert!(file.set_len(0).is_err());
    }
}
