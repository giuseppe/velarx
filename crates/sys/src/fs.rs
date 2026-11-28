// SPDX-License-Identifier: Apache-2.0
//! File system calls that `rustix` does not wrap, and the open of a name
//! below a directory that no link can lead out of (`open_beneath`).

use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

/// A file handle (`name_to_handle_at`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHandle {
    pub handle_type: i32,
    pub mount_id: i32,
    pub bytes: Vec<u8>,
}

/// `struct file_handle` with room for `MAX_HANDLE_SZ` (128) bytes of handle.
#[repr(C)]
struct Buf {
    handle_bytes: u32,
    handle_type: i32,
    f_handle: [u8; 128],
}

/// The handle of the file `fd` is (a namespace file of `/proc` has one of
/// 16 bytes on a kernel that gives them), `None` when the kernel gives
/// none.
pub fn handle_of(fd: BorrowedFd<'_>) -> Option<FileHandle> {
    let mut buf = Buf {
        handle_bytes: 128,
        handle_type: 0,
        f_handle: [0; 128],
    };
    let mut mount_id = 0;
    // SAFETY: the buffer has the layout of struct file_handle followed by
    // the room its handle_bytes announces, and outlives the call.
    let r = unsafe {
        libc::name_to_handle_at(
            fd.as_raw_fd(),
            c"".as_ptr(),
            std::ptr::addr_of_mut!(buf).cast(),
            &mut mount_id,
            libc::AT_EMPTY_PATH,
        )
    };
    (r == 0).then(|| FileHandle {
        handle_type: buf.handle_type,
        mount_id,
        bytes: buf.f_handle[..(buf.handle_bytes as usize).min(128)].to_vec(),
    })
}

/// Open the file a handle names (`open_by_handle_at`) with `O_RDONLY |
/// O_CLOEXEC`.  `mount_fd` is a descriptor of the file system the handle
/// is of; for the handle of a namespace file, [`NSFS_ROOT`].  The kernel
/// decides who may open a namespace: root of the initial user namespace,
/// and a process that is in the namespace already; for any other caller
/// (an owner of the namespace's user namespace included) it answers
/// `ESTALE`, as for a namespace that is gone.
pub fn open_handle(mount_fd: RawFd, handle: &FileHandle) -> std::io::Result<OwnedFd> {
    if handle.bytes.len() > 128 {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut buf = Buf {
        handle_bytes: handle.bytes.len() as u32,
        handle_type: handle.handle_type,
        f_handle: [0; 128],
    };
    buf.f_handle[..handle.bytes.len()].copy_from_slice(&handle.bytes);
    // SAFETY: the buffer has the layout of struct file_handle followed by
    // the room its handle_bytes announces, and outlives the call.
    let fd = unsafe {
        libc::open_by_handle_at(
            mount_fd,
            std::ptr::addr_of_mut!(buf).cast(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: open_by_handle_at returned a new descriptor that nothing else
    // owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The `mount_fd` of [`open_handle`] for a handle of a namespace file: the
/// root of the namespace file system (`FD_NSFS_ROOT`, Linux 6.18).
pub const NSFS_ROOT: RawFd = -10003;

/// A `struct flock` asking for a write lock of the whole file.
fn whole_file_lock() -> libc::flock {
    // SAFETY: flock is a plain C structure of integers: all zeros is a
    // valid value of it.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as libc::c_short;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    lock
}

/// Take a write lock on the whole file of `fd` for this process (a lock of
/// `fcntl` of the process, not of the open file): it is held until the
/// process ends or closes any descriptor of that file, and the kernel tells
/// the pid of the holder to whoever asks ([`lock_holder`]).  Fails with
/// `WouldBlock` when another process holds it.
pub fn lock_for_process(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    let lock = whole_file_lock();
    // SAFETY: F_SETLK reads the flock structure, which outlives the call.
    let r = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETLK, &lock) };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        // (a held lock is EACCES or EAGAIN)
        return Err(match e.raw_os_error() {
            Some(libc::EACCES) => std::io::ErrorKind::WouldBlock.into(),
            _ => e,
        });
    }
    Ok(())
}

/// The pid of the process that holds [`lock_for_process`] on the file of
/// `fd`, none if it is not locked.  Asking takes nothing.  A lock of
/// another pid namespace has no pid here: an error.
pub fn lock_holder(fd: BorrowedFd<'_>) -> std::io::Result<Option<u32>> {
    let mut lock = whole_file_lock();
    // SAFETY: F_GETLK reads and writes the flock structure, which outlives
    // the call.
    let r = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETLK, &mut lock) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if lock.l_type == libc::F_UNLCK as libc::c_short {
        return Ok(None);
    }
    u32::try_from(lock.l_pid)
        .ok()
        .filter(|p| *p > 0)
        .map(Some)
        .ok_or_else(|| std::io::Error::other("the lock is held from another pid namespace"))
}

/// A `stat` of all zeros, for code that fills in the few fields it has (a
/// file made from a tar header, not read from a disk).
pub fn zeroed_stat() -> rustix::fs::Stat {
    // SAFETY: stat is a plain C structure of integers: all zeros is a valid
    // value of it.
    unsafe { std::mem::zeroed() }
}

/// What [`open_beneath`] opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Beneath {
    /// A regular file, to read: anything else is refused, a FIFO too,
    /// without waiting for a writer (opened `O_NONBLOCK`, cleared after).
    File,
    /// A directory, to read.
    Directory,
    /// A directory, as a place to name files from (`O_PATH`).
    DirectoryPath,
    /// Whatever the name is, as a place (`O_PATH`), never followed.
    Path,
}

/// Why [`open_beneath`] opened nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeneathError {
    /// The call failed: `ENOENT` nothing there, `ELOOP` a link, `EXDEV` a
    /// way out of the directory, `ENOTDIR` no directory.
    Errno(rustix::io::Errno),
    /// A file asked for ([`Beneath::File`]) is something else.
    NotRegular,
}

impl From<rustix::io::Errno> for BeneathError {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Errno(e)
    }
}

impl std::fmt::Display for BeneathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Errno(e) => e.fmt(f),
            Self::NotRegular => f.write_str("not a regular file"),
        }
    }
}

impl From<BeneathError> for std::io::Error {
    fn from(e: BeneathError) -> Self {
        match e {
            BeneathError::Errno(e) => e.into(),
            BeneathError::NotRegular => std::io::Error::other("not a regular file"),
        }
    }
}

/// `openat2` that is tried again when it fails with `EAGAIN`: the kernel
/// answers that to a resolution with `RESOLVE_IN_ROOT` or `RESOLVE_BENEATH`
/// that crossed `..` while something on the system was renamed or mounted.
pub fn openat2_retry<P: rustix::path::Arg + Copy>(
    dir: BorrowedFd<'_>,
    path: P,
    flags: rustix::fs::OFlags,
    mode: rustix::fs::Mode,
    resolve: rustix::fs::ResolveFlags,
) -> rustix::io::Result<OwnedFd> {
    let mut tries = 0;
    loop {
        match rustix::fs::openat2(dir, path, flags, mode, resolve) {
            Err(rustix::io::Errno::AGAIN) if tries < 128 => tries += 1,
            r => return r,
        }
    }
}

/// Open the file `rel` read-only as it is in the file system whose root is
/// `root`: links are followed but stay inside it (`RESOLVE_IN_ROOT`, no
/// magic links, `extra` more), a leading `/` is the root (the kernel starts
/// an absolute path at `root` with `RESOLVE_IN_ROOT`).  It does not block on
/// a fifo in the way (`O_NONBLOCK`) and tries again on `EAGAIN`.
pub fn open_in_root<P: rustix::path::Arg + Copy>(
    root: BorrowedFd<'_>,
    rel: P,
    extra: rustix::fs::ResolveFlags,
) -> rustix::io::Result<OwnedFd> {
    use rustix::fs::{OFlags, ResolveFlags};
    openat2_retry(
        root,
        rel,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS | extra,
    )
}

/// The content of the file `rel` of the file system whose root is `root`
/// (see [`open_in_root`]), at most `limit` bytes.  `None` when it is missing
/// or not a regular file.
pub fn read_in_root<P: rustix::path::Arg + Copy>(
    root: BorrowedFd<'_>,
    rel: P,
    limit: u64,
) -> std::io::Result<Option<Vec<u8>>> {
    use rustix::io::Errno;
    use std::io::Read;
    let fd = match open_in_root(root, rel, rustix::fs::ResolveFlags::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT | Errno::NOTDIR | Errno::ISDIR) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let f = std::fs::File::from(fd);
    if !f.metadata()?.is_file() {
        return Ok(None);
    }
    let mut buf = Vec::new();
    f.take(limit).read_to_end(&mut buf)?;
    Ok(Some(buf))
}

/// Open `name` below `dir` as `what` is: a name that stays below it
/// (`RESOLVE_BENEATH`: no absolute path, no `..` above it), has no
/// symbolic link (`RESOLVE_NO_SYMLINKS`), magic links of `/proc` included
/// (`RESOLVE_NO_MAGICLINKS`); a link that is the name is refused (`ELOOP`)
/// but by [`Beneath::Path`], which opens the link itself.  What is checked of the
/// descriptor is what is used of it, whatever is renamed meanwhile.
pub fn open_beneath(
    dir: BorrowedFd<'_>,
    name: &Path,
    what: Beneath,
) -> Result<OwnedFd, BeneathError> {
    open_beneath_with(dir, name, what, rustix::fs::ResolveFlags::empty())
}

/// [`open_beneath`] with more resolve flags: `RESOLVE_NO_XDEV` for a
/// directory that is one mount (a mounted image), whose
/// names never lead into another mount (`EXDEV`).
pub fn open_beneath_with(
    dir: BorrowedFd<'_>,
    name: &Path,
    what: Beneath,
    extra: rustix::fs::ResolveFlags,
) -> Result<OwnedFd, BeneathError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    // (`O_NOFOLLOW` makes a name that is a link a descriptor of the link
    // with `O_PATH`; a directory that is a link is refused as a link,
    // `ELOOP`, without it)
    let flags = match what {
        // (`O_NOCTTY`: a terminal device under the name is refused below,
        // after its open, which must not make it ours)
        Beneath::File => OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::NOCTTY,
        Beneath::Directory => OFlags::RDONLY | OFlags::DIRECTORY,
        Beneath::DirectoryPath => OFlags::PATH | OFlags::DIRECTORY,
        Beneath::Path => OFlags::PATH | OFlags::NOFOLLOW,
    };
    let fd = openat2_retry(
        dir,
        name,
        flags | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS | extra,
    )?;
    if what == Beneath::File {
        let st = rustix::fs::fstat(&fd)?;
        if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::RegularFile {
            return Err(BeneathError::NotRegular);
        }
        rustix::fs::fcntl_setfl(&fd, OFlags::empty())?;
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::{open_beneath, Beneath, BeneathError};
    use rustix::io::Errno;
    use std::os::fd::AsFd;
    use std::path::Path;

    /// A directory with a file, a directory, a FIFO, a link to the file and
    /// a file outside it.
    fn layout() -> (tempfile::TempDir, std::fs::File) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("file"), b"in").unwrap();
        std::fs::write(dir.join("sub/file"), b"sub").unwrap();
        std::fs::write(tmp.path().join("outside"), b"out").unwrap();
        rustix::fs::mkfifoat(rustix::fs::CWD, dir.join("fifo"), rustix::fs::Mode::RUSR).unwrap();
        std::os::unix::fs::symlink("file", dir.join("link")).unwrap();
        let d = std::fs::File::open(&dir).unwrap();
        (tmp, d)
    }

    fn open(d: &std::fs::File, name: &str, what: Beneath) -> Result<std::fs::File, BeneathError> {
        open_beneath(d.as_fd(), Path::new(name), what).map(std::fs::File::from)
    }

    #[test]
    fn a_regular_file_below_the_directory_is_opened_to_read() {
        let (_tmp, d) = layout();
        let f = open(&d, "file", Beneath::File).unwrap();
        assert_eq!(std::io::read_to_string(&f).unwrap(), "in");
        // (the O_NONBLOCK of the open is gone)
        let flags = rustix::fs::fcntl_getfl(&f).unwrap();
        assert!(!flags.contains(rustix::fs::OFlags::NONBLOCK));
        assert_eq!(
            std::io::read_to_string(open(&d, "sub/file", Beneath::File).unwrap()).unwrap(),
            "sub"
        );
    }

    #[test]
    fn no_link_and_no_way_out_is_followed() {
        let (tmp, d) = layout();
        assert_eq!(
            open(&d, "link", Beneath::File).unwrap_err(),
            BeneathError::Errno(Errno::LOOP)
        );
        // (a place: the link itself, not what it names)
        let link = open(&d, "link", Beneath::Path).unwrap();
        assert_eq!(
            rustix::fs::FileType::from_raw_mode(rustix::fs::fstat(&link).unwrap().st_mode),
            rustix::fs::FileType::Symlink
        );
        std::fs::create_dir(tmp.path().join("d/sub/inner")).unwrap();
        std::os::unix::fs::symlink("sub", tmp.path().join("d/dirlink")).unwrap();
        assert_eq!(
            open(&d, "dirlink/file", Beneath::Path).unwrap_err(),
            BeneathError::Errno(Errno::LOOP)
        );
        assert_eq!(
            open(&d, "../outside", Beneath::File).unwrap_err(),
            BeneathError::Errno(Errno::XDEV)
        );
        assert_eq!(
            open(&d, "sub/../../outside", Beneath::File).unwrap_err(),
            BeneathError::Errno(Errno::XDEV)
        );
        let absolute = tmp.path().join("outside");
        assert_eq!(
            open(&d, absolute.to_str().unwrap(), Beneath::File).unwrap_err(),
            BeneathError::Errno(Errno::XDEV)
        );
        // a magic link of /proc, from a directory where it is below
        let proc = std::fs::File::open("/proc/self").unwrap();
        assert_eq!(
            open(&proc, "exe", Beneath::File).unwrap_err(),
            BeneathError::Errno(Errno::LOOP)
        );
        assert_eq!(
            open(&proc, "root/etc", Beneath::DirectoryPath).unwrap_err(),
            BeneathError::Errno(Errno::LOOP)
        );
        // (`..` that stays below is fine)
        assert!(open(&d, "sub/../file", Beneath::File).is_ok());
    }

    #[test]
    fn a_file_is_a_regular_file_and_a_fifo_is_not_waited_on() {
        let (_tmp, d) = layout();
        assert_eq!(
            open(&d, "fifo", Beneath::File).unwrap_err(),
            BeneathError::NotRegular
        );
        assert_eq!(
            open(&d, "sub", Beneath::File).unwrap_err(),
            BeneathError::NotRegular
        );
        assert_eq!(
            open(&d, "none", Beneath::File).unwrap_err(),
            BeneathError::Errno(Errno::NOENT)
        );
        // what it is, as a place
        assert!(open(&d, "fifo", Beneath::Path).is_ok());
    }

    #[test]
    fn a_directory_is_a_directory() {
        let (tmp, d) = layout();
        let sub = open(&d, "sub", Beneath::Directory).unwrap();
        assert!(rustix::fs::Dir::read_from(&sub).is_ok());
        let place = open(&d, "sub", Beneath::DirectoryPath).unwrap();
        assert!(rustix::fs::fcntl_getfl(&place)
            .unwrap()
            .contains(rustix::fs::OFlags::PATH));
        assert!(open(&d, ".", Beneath::DirectoryPath).is_ok());
        std::os::unix::fs::symlink("sub", tmp.path().join("d/dirlink")).unwrap();
        for what in [Beneath::Directory, Beneath::DirectoryPath] {
            assert_eq!(
                open(&d, "dirlink", what).unwrap_err(),
                BeneathError::Errno(Errno::LOOP)
            );
            assert_eq!(
                open(&d, "file", what).unwrap_err(),
                BeneathError::Errno(Errno::NOTDIR)
            );
        }
    }

    /// What was opened stays what is read, renamed or replaced meanwhile.
    #[test]
    fn the_descriptor_is_the_file_opened_whatever_is_renamed() {
        let (tmp, d) = layout();
        let f = open(&d, "file", Beneath::File).unwrap();
        let dir = tmp.path().join("d");
        std::fs::rename(dir.join("file"), dir.join("moved")).unwrap();
        std::fs::write(dir.join("file"), b"replaced").unwrap();
        assert_eq!(std::io::read_to_string(&f).unwrap(), "in");
    }

    /// The holder is told by its pid, from another process: a forked child
    /// takes the lock and this one asks; nobody holds it once it is gone.
    #[test]
    fn the_holder_of_a_process_lock_is_known_by_pid() {
        use std::os::fd::AsFd;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, "").unwrap();
        let asking = std::fs::File::open(&path).unwrap();
        assert_eq!(super::lock_holder(asking.as_fd()).unwrap(), None);
        let (ready_r, ready_w) = rustix::pipe::pipe().unwrap();
        let held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        // SAFETY: the child only locks, writes to a pipe and waits for a
        // signal: calls that are safe after the fork of a threaded process.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let locked = super::lock_for_process(held.as_fd()).is_ok();
            let _ = rustix::io::write(&ready_w, &[u8::from(locked)]);
            // SAFETY: pause and _exit take no pointers.
            unsafe {
                libc::pause();
                libc::_exit(0)
            }
        }
        let mut one = [0u8];
        rustix::io::read(&ready_r, &mut one).unwrap();
        assert_eq!(one[0], 1);
        assert_eq!(
            super::lock_holder(asking.as_fd()).unwrap(),
            Some(child as u32)
        );
        // another process cannot take it
        let other = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert_eq!(
            super::lock_for_process(other.as_fd()).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        // SAFETY: kill and waitpid of the child made above.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
        assert_eq!(super::lock_holder(asking.as_fd()).unwrap(), None);
    }

    #[test]
    fn a_zeroed_stat_is_zero() {
        assert_eq!(super::zeroed_stat().st_size, 0);
    }

    #[test]
    fn a_regular_file_has_a_handle_or_the_file_system_has_none() {
        let f = std::fs::File::open("/proc/self/ns/user").unwrap();
        // (what the kernel says is not ours to test: it must not fail badly)
        let _ = super::handle_of(std::os::fd::AsFd::as_fd(&f));
    }
}
