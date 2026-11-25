// SPDX-License-Identifier: Apache-2.0
//! The mounts of a mount namespace as the kernel tells them: `statmount(2)`
//! and `listmount(2)`, with the options of a file system as an array
//! (`STATMOUNT_OPT_ARRAY`).  It needs the kernel the README states (7.3):
//! the by-fd flag and the reserved empty string.  Nothing is parsed from
//! text: a path comes as the bytes the kernel has (no `\040` escapes, no
//! UTF-8 needed) and an option as one string.
//!
//! A mount is named by its 64-bit unique id (`statx` with
//! `STATX_MNT_ID_UNIQUE`, or [`table`]), never by the id of `mountinfo`,
//! which the kernel reuses.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

const SYS_STATMOUNT: libc::c_long = 457;
const SYS_LISTMOUNT: libc::c_long = 458;

const STATMOUNT_SB_BASIC: u64 = 0x1;
const STATMOUNT_MNT_BASIC: u64 = 0x2;
const STATMOUNT_MNT_ROOT: u64 = 0x8;
const STATMOUNT_MNT_POINT: u64 = 0x10;
const STATMOUNT_FS_TYPE: u64 = 0x20;
const STATMOUNT_OPT_ARRAY: u64 = 0x400;
const STATMOUNT_SUPPORTED_MASK: u64 = 0x1000;
/// What [`Mount`] has.
const WANTED: u64 = STATMOUNT_SB_BASIC
    | STATMOUNT_MNT_BASIC
    | STATMOUNT_MNT_ROOT
    | STATMOUNT_MNT_POINT
    | STATMOUNT_FS_TYPE
    | STATMOUNT_OPT_ARRAY
    | STATMOUNT_SUPPORTED_MASK;

const STATMOUNT_BY_FD: libc::c_uint = 1;
/// `listmount` of the root mount: every mount of the namespace.
const LSMT_ROOT: u64 = u64::MAX;

/// `struct mnt_id_req` (version 1, 32 bytes).
#[repr(C)]
struct MntIdReq {
    size: u32,
    /// `mnt_fd` (with `STATMOUNT_BY_FD`) or `mnt_ns_fd`.
    fd: u32,
    mnt_id: u64,
    /// The mask of `statmount`, the last listed id of `listmount`.
    param: u64,
    mnt_ns_id: u64,
}

/// The fixed part of `struct statmount`; the strings follow it.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawStatmount {
    size: u32,
    mnt_opts: u32,
    mask: u64,
    sb_dev_major: u32,
    sb_dev_minor: u32,
    sb_magic: u64,
    sb_flags: u32,
    fs_type: u32,
    mnt_id: u64,
    mnt_parent_id: u64,
    mnt_id_old: u32,
    mnt_parent_id_old: u32,
    mnt_attr: u64,
    mnt_propagation: u64,
    mnt_peer_group: u64,
    mnt_master: u64,
    propagate_from: u64,
    mnt_root: u32,
    mnt_point: u32,
    mnt_ns_id: u64,
    fs_subtype: u32,
    sb_source: u32,
    opt_num: u32,
    opt_array: u32,
    opt_sec_num: u32,
    opt_sec_array: u32,
    supported_mask: u64,
    mnt_uidmap_num: u32,
    mnt_uidmap: u32,
    mnt_gidmap_num: u32,
    mnt_gidmap: u32,
    spare2: [u64; 43],
}

const FIXED: usize = std::mem::size_of::<RawStatmount>();
const _: () = assert!(FIXED == 512);

/// One mount, as `statmount` tells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// The unique id of the mount.
    pub id: u64,
    /// The mount this one is mounted on (its own id for the root mount).
    pub parent: u64,
    /// The device of the file system: two mounts of one file system have
    /// the same.
    pub device: (u32, u32),
    /// The directory of the file system that is the root of the mount.
    pub root: PathBuf,
    /// Where it is mounted, from the root of this process; `None` when that
    /// is out of reach of it (the kernel also drops it for a detached mount
    /// read by its descriptor).
    pub point: Option<PathBuf>,
    pub fs_type: String,
    /// The options of the file system, one each, as the file system shows
    /// them (`upperdir=...` of an overlay, the path as it is).
    pub options: Vec<OsString>,
    /// `MOUNT_ATTR_*` of the mount.
    pub attr: u64,
    /// `MS_SHARED`, `MS_SLAVE`, `MS_PRIVATE` or `MS_UNBINDABLE` (a mount
    /// that is both shared and a slave has both bits).
    pub propagation: u64,
    /// The peer group of a shared mount, else 0.
    pub peer_group: u64,
    /// The peer group a slave mount receives from, else 0.
    pub master: u64,
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("statmount gave {what}"))
}

/// A string of the reply at the offset the kernel gave, up to its NUL.
fn string(strings: &[u8], offset: u32) -> io::Result<&[u8]> {
    let tail = strings
        .get(offset as usize..)
        .ok_or_else(|| invalid("a string out of its buffer"))?;
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| invalid("a string without its end"))?;
    Ok(&tail[..end])
}

fn parse(buf: &[u8]) -> io::Result<Mount> {
    if buf.len() < FIXED {
        return Err(invalid("less than its fixed part"));
    }
    // SAFETY: `buf` has at least `FIXED` bytes, and `RawStatmount` is
    // integers only, for which every bit pattern is a value; the read has
    // no alignment requirement.
    let raw = unsafe { buf.as_ptr().cast::<RawStatmount>().read_unaligned() };
    for (bit, what) in [
        (STATMOUNT_SB_BASIC, "no device"),
        (STATMOUNT_MNT_BASIC, "no ids"),
        (STATMOUNT_MNT_ROOT, "no root"),
        (STATMOUNT_FS_TYPE, "no file system type"),
        (STATMOUNT_SUPPORTED_MASK, "no supported mask"),
    ] {
        if raw.mask & bit == 0 {
            return Err(invalid(what));
        }
    }
    // A file system that shows no options (`mqueue`) has no array in the
    // reply.  That is "no options" only for a kernel that does give the
    // array: for one that does not, it is an error, never an empty list.
    let opt_num = if raw.mask & STATMOUNT_OPT_ARRAY != 0 {
        raw.opt_num as usize
    } else if raw.supported_mask & STATMOUNT_OPT_ARRAY != 0 {
        0
    } else {
        return Err(invalid("no options"));
    };
    let strings = buf
        .get(FIXED..raw.size as usize)
        .ok_or_else(|| invalid("a size out of its buffer"))?;
    let path =
        |offset| string(strings, offset).map(|b| PathBuf::from(OsString::from_vec(b.to_vec())));
    let mut options = Vec::with_capacity(opt_num.min(strings.len()));
    let mut at = raw.opt_array as usize;
    for _ in 0..opt_num {
        let o = string(strings, at as u32)?;
        options.push(OsString::from_vec(o.to_vec()));
        at += o.len() + 1;
    }
    Ok(Mount {
        id: raw.mnt_id,
        parent: raw.mnt_parent_id,
        device: (raw.sb_dev_major, raw.sb_dev_minor),
        root: path(raw.mnt_root)?,
        point: if raw.mask & STATMOUNT_MNT_POINT == 0 {
            None
        } else {
            Some(path(raw.mnt_point)?)
        },
        fs_type: String::from_utf8_lossy(string(strings, raw.fs_type)?).into_owned(),
        options,
        attr: raw.mnt_attr,
        propagation: raw.mnt_propagation,
        peer_group: raw.mnt_peer_group,
        master: raw.mnt_master,
    })
}

/// `statmount` of the mount `id` of this mount namespace (`fd` is 0), or of
/// the mount of the descriptor `fd` (`id` is 0), in `buf`, which grows as
/// the strings need.
fn stat(id: u64, fd: Option<BorrowedFd<'_>>, buf: &mut Vec<u8>) -> io::Result<Mount> {
    let req = MntIdReq {
        size: std::mem::size_of::<MntIdReq>() as u32,
        fd: fd.map_or(0, |f| f.as_raw_fd() as u32),
        mnt_id: id,
        param: WANTED,
        mnt_ns_id: 0,
    };
    let flags = if fd.is_some() { STATMOUNT_BY_FD } else { 0 };
    loop {
        // SAFETY: statmount reads the request and writes at most
        // `buf.len()` bytes at `buf`, both live for the call.
        let r = unsafe {
            libc::syscall(
                SYS_STATMOUNT,
                &req as *const MntIdReq,
                buf.as_mut_ptr(),
                buf.len(),
                flags,
            )
        };
        if r == 0 {
            return parse(buf);
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EOVERFLOW) || buf.len() >= 1 << 20 {
            return Err(e);
        }
        buf.resize(buf.len() * 2, 0);
    }
}

const START: usize = 16 * 1024;

/// The mount `id` of this mount namespace (`ENOENT` when it is not in it,
/// or gone).
pub fn of_id(id: u64) -> io::Result<Mount> {
    stat(id, None, &mut vec![0; START])
}

/// The mount the file `fd` is on.
pub fn of_fd(fd: BorrowedFd<'_>) -> io::Result<Mount> {
    stat(0, Some(fd), &mut vec![0; START])
}

/// What `statx` says of a file about its mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMount {
    /// `st_mode`: the type of the file.
    pub mode: u32,
    /// The unique id of the mount the file is on.
    pub mount: u64,
    /// `st_dev` of the file.
    pub device: (u32, u32),
}

/// The type, the device and the unique id of the mount of the file `name`
/// of the directory `dir` (`statx` with `STATX_MNT_ID_UNIQUE`; `flags` are
/// those of `statx`, such as `AT_SYMLINK_NOFOLLOW`).
pub fn file_mount(
    dir: BorrowedFd<'_>,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
) -> io::Result<FileMount> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    statx_mount(dir.as_raw_fd(), &name, flags)
}

fn statx_mount(
    dir: libc::c_int,
    name: &std::ffi::CStr,
    flags: libc::c_int,
) -> io::Result<FileMount> {
    let mut st = std::mem::MaybeUninit::<libc::statx>::uninit();
    // SAFETY: statx reads the NUL terminated `name` and fills `st`, both
    // live for the call.
    let r = unsafe {
        libc::statx(
            dir,
            name.as_ptr(),
            flags,
            libc::STATX_TYPE | libc::STATX_MNT_ID_UNIQUE,
            st.as_mut_ptr(),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statx returned 0, so it filled the struct.
    let st = unsafe { st.assume_init() };
    if st.stx_mask & libc::STATX_MNT_ID_UNIQUE == 0 {
        return Err(io::Error::from_raw_os_error(libc::ENOSYS));
    }
    Ok(FileMount {
        mode: st.stx_mode.into(),
        mount: st.stx_mnt_id,
        device: (st.stx_dev_major, st.stx_dev_minor),
    })
}

/// The unique id of the mount of `path`, following a link at its end.
pub fn id_of_path(path: &std::path::Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    statx_mount(libc::AT_FDCWD, &path, 0).map(|f| f.mount)
}

/// The unique id of the mount of the file `fd`.
pub fn id_of_fd(fd: BorrowedFd<'_>) -> io::Result<u64> {
    statx_mount(fd.as_raw_fd(), c"", libc::AT_EMPTY_PATH).map(|f| f.mount)
}

/// Whether `path` (a link at its end is not followed) is the root of its
/// mount: a mount point.  A path that cannot be looked up is an error
/// (`ENOENT` for one that is not there), never "no".
pub fn is_mount_point(path: &std::path::Path) -> io::Result<bool> {
    use rustix::fs::{statx, AtFlags, StatxAttributes, StatxFlags};
    let st = statx(
        rustix::fs::CWD,
        path,
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::empty(),
    )?;
    Ok(st.stx_attributes.contains(StatxAttributes::MOUNT_ROOT))
}

/// Whether the file `fd` is the root of its mount.
pub fn is_mount_root(fd: BorrowedFd<'_>) -> io::Result<bool> {
    use rustix::fs::{statx, AtFlags, StatxAttributes, StatxFlags};
    let st = statx(fd, "", AtFlags::EMPTY_PATH, StatxFlags::empty())?;
    Ok(st.stx_attributes.contains(StatxAttributes::MOUNT_ROOT))
}

/// The ids of the mounts of this mount namespace, in the order of their
/// making.
fn list() -> io::Result<Vec<u64>> {
    const PAGE: usize = 512;
    let mut ids = Vec::new();
    let mut page = [0u64; PAGE];
    loop {
        let req = MntIdReq {
            size: std::mem::size_of::<MntIdReq>() as u32,
            fd: 0,
            mnt_id: LSMT_ROOT,
            param: ids.last().copied().unwrap_or(0),
            mnt_ns_id: 0,
        };
        // SAFETY: listmount reads the request and writes at most `PAGE`
        // ids at `page`, both live for the call.
        let n = unsafe {
            libc::syscall(
                SYS_LISTMOUNT,
                &req as *const MntIdReq,
                page.as_mut_ptr(),
                PAGE,
                0u32,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        ids.extend_from_slice(&page[..n as usize]);
        if (n as usize) < PAGE {
            return Ok(ids);
        }
    }
}

/// The mounts of this mount namespace that are within reach of the root of
/// this process (those with a point), in the order of their making.  A mount
/// that goes, or moves out of reach, while the table is read is not in it.
/// `EACCES` (a security module refusing the read) is an error: a mount left
/// out for it would make "no mount below this directory" true by failing
/// open.
pub fn table() -> io::Result<Vec<Mount>> {
    let mut buf = vec![0; START];
    let mut mounts = Vec::new();
    for id in list()? {
        match stat(id, None, &mut buf) {
            Ok(m) if m.point.is_some() => mounts.push(m),
            Ok(_) => {}
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::EPERM)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(mounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::mount::{mount, mount_change, MountFlags, MountPropagationFlags};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    /// Run `body` in a child with a mount namespace of its own: false
    /// (nothing to test) where this user may not have one.
    fn in_namespace(body: fn(&Path) -> Result<(), String>) {
        let code = crate::process::fork_status(|| {
            if crate::namespace::unshare_user_mapped_to_root(rustix::thread::UnshareFlags::NEWNS)
                .is_err()
            {
                return 0;
            }
            mount_change(
                "/",
                MountPropagationFlags::REC | MountPropagationFlags::PRIVATE,
            )
            .unwrap();
            let dir = tempfile::tempdir().unwrap();
            match body(dir.path()) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        })
        .unwrap();
        assert_eq!(code, 0);
    }

    fn tmpfs(at: &Path) {
        std::fs::create_dir_all(at).unwrap();
        mount("t", at, "tmpfs", MountFlags::NODEV, Some(c"mode=700")).unwrap();
    }

    /// A path the kernel's table shows escaped (`\040`, `\012`, `\134`,
    /// `\011`) or that is not UTF-8 comes as the bytes it has, and the
    /// mounts are found by the id of their directory.
    #[test]
    fn a_mount_has_the_bytes_of_its_path_and_its_ids() {
        in_namespace(|d| {
            let odd = d.join(std::ffi::OsStr::from_bytes(b"a b\nc\\d\te\xffz"));
            tmpfs(&odd);
            tmpfs(&odd.join("in"));
            let id = id_of_path(&odd).map_err(|e| e.to_string())?;
            let m = of_id(id).map_err(|e| e.to_string())?;
            assert_eq!(m.id, id);
            assert_eq!(m.point.as_deref(), Some(odd.as_path()));
            assert_eq!(m.root, Path::new("/"));
            assert_eq!(m.fs_type, "tmpfs");
            assert!(m.options.iter().any(|o| o == "mode=700"), "{:?}", m.options);
            assert_eq!(m.attr & libc::MOUNT_ATTR_NODEV, libc::MOUNT_ATTR_NODEV);
            let inner = id_of_path(&odd.join("in")).map_err(|e| e.to_string())?;
            let table = table().map_err(|e| e.to_string())?;
            let child = table.iter().find(|c| c.id == inner).ok_or("not listed")?;
            assert_eq!(child.parent, id);
            assert_eq!(child.point, Some(odd.join("in")));
            // a table is in the order of the making
            let at = |i| table.iter().position(|c| c.id == i).unwrap();
            assert!(at(id) < at(inner));
            // the mount of a descriptor is the mount of its file
            let f = std::fs::File::open(odd.join("in")).unwrap();
            assert_eq!(
                of_fd(std::os::fd::AsFd::as_fd(&f))
                    .map_err(|e| e.to_string())?
                    .id,
                inner
            );
            // a mount that is gone is not found
            rustix::mount::unmount(odd.join("in"), rustix::mount::UnmountFlags::DETACH).unwrap();
            let e = of_id(inner).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::ENOENT));
            Ok(())
        });
    }

    /// A reply as the kernel writes it: the fixed part, then the strings
    /// (`point` and `opts` are the strings at their offsets).
    fn reply(mask: u64, supported: u64, point: &str, opts: &[&str], opt_num: u32) -> Vec<u8> {
        let mut strings = Vec::new();
        let mut at = |s: &str| {
            let o = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            o
        };
        let (root, mnt_point, fs_type) = (at("/"), at(point), at("tmpfs"));
        let offsets: Vec<u32> = opts.iter().map(|o| at(o)).collect();
        let opt_array = offsets.first().copied().unwrap_or(0);
        // SAFETY: integers only, all zero is a value.
        let mut raw: RawStatmount = unsafe { std::mem::zeroed() };
        raw.size = (FIXED + strings.len()) as u32;
        raw.mask = mask;
        raw.supported_mask = supported;
        raw.mnt_root = root;
        raw.mnt_point = mnt_point;
        raw.fs_type = fs_type;
        raw.opt_num = opt_num;
        raw.opt_array = opt_array;
        // SAFETY: `RawStatmount` is plain integers, read as bytes.
        let mut buf = unsafe {
            std::slice::from_raw_parts((&raw as *const RawStatmount).cast::<u8>(), FIXED)
        }
        .to_vec();
        buf.extend_from_slice(&strings);
        buf
    }

    const ALL: u64 = WANTED;
    const KERNEL: u64 = STATMOUNT_OPT_ARRAY;

    /// A reply without one of the fields every mount has is an error that
    /// names it; a missing point is `None`; a missing option array is "no
    /// options" only for a kernel that gives the array (`mqueue` shows
    /// none), an error for one that does not; a count of options that the
    /// strings do not have is an error, not an allocation.
    #[test]
    fn a_reply_is_checked_for_what_it_has() {
        let m = parse(&reply(ALL, KERNEL, "/p", &["a=1"], 1)).unwrap();
        assert_eq!(m.point.as_deref(), Some(Path::new("/p")));
        assert_eq!(m.options, ["a=1"]);
        for (bit, what) in [
            (STATMOUNT_SB_BASIC, "no device"),
            (STATMOUNT_MNT_BASIC, "no ids"),
            (STATMOUNT_MNT_ROOT, "no root"),
            (STATMOUNT_FS_TYPE, "no file system type"),
            (STATMOUNT_SUPPORTED_MASK, "no supported mask"),
        ] {
            let e = parse(&reply(ALL & !bit, KERNEL, "/p", &["a=1"], 1)).unwrap_err();
            assert!(e.to_string().contains(what), "{e}");
        }
        let none = ALL & !STATMOUNT_OPT_ARRAY;
        assert!(parse(&reply(none, KERNEL, "/p", &[], 0))
            .unwrap()
            .options
            .is_empty());
        let e = parse(&reply(none, 0, "/p", &[], 0)).unwrap_err();
        assert!(e.to_string().contains("no options"), "{e}");
        let m = parse(&reply(ALL & !STATMOUNT_MNT_POINT, KERNEL, "", &["a=1"], 1)).unwrap();
        assert_eq!(m.point, None);
        let e = parse(&reply(ALL, KERNEL, "/p", &["a=1"], u32::MAX)).unwrap_err();
        assert!(e.to_string().contains("string"), "{e}");
    }

    /// An option longer than the first buffer, and a table of more mounts
    /// than one page of `listmount`, are read whole.
    #[test]
    fn a_long_string_and_a_long_table_are_read_whole() {
        in_namespace(|d| {
            let long = d.join("x".repeat(200)).join("y".repeat(200));
            tmpfs(&long);
            let id = id_of_path(&long).map_err(|e| e.to_string())?;
            let mut small = vec![0; FIXED];
            let m = stat(id, None, &mut small).map_err(|e| e.to_string())?;
            assert_eq!(m.point, Some(long));
            assert!(small.len() > FIXED);
            for i in 0..600 {
                tmpfs(&d.join(format!("m{i}")));
            }
            let t = table().map_err(|e| e.to_string())?;
            assert_eq!(
                t.iter()
                    .filter(|m| m.point.as_deref().is_some_and(|p| p.starts_with(d)))
                    .count(),
                601,
                "the mounts of the directory"
            );
            Ok(())
        });
    }
}
