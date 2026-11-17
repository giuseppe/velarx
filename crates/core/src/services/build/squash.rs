// SPDX-License-Identifier: Apache-2.0
//! `--squash`: the upper directories of the steps of a stage merged into
//! one, as an overlay would show them, committed as one layer on the base
//! of the stage.  The directories are those of the build (a RUN container
//! wrote them): nothing in them is followed.

use super::copy::remove_tree;
use rustix::fd::{BorrowedFd, OwnedFd};
use rustix::fs::{
    chownat, fchmod, fchown, fsetxattr, fstat, futimens, mkdirat, mknodat, openat, readlinkat,
    statat, symlinkat, utimensat, AtFlags, FileType, Gid, Mode, OFlags, Stat, Timespec, Timestamps,
    Uid, XattrFlags,
};
use std::ffi::OsStr;
use std::io::{self};
use std::path::Path;
use velarx_base::walk::{Cursor, Visit, Walk};
use velarx_content::layer::dirtar;
use velarx_wire::cp::{reopen, MAX_DEPTH};

fn open_dir(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<OwnedFd> {
    Ok(openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

fn times(st: &Stat) -> Timestamps {
    let t = Timespec {
        tv_sec: st.st_mtime,
        tv_nsec: st.st_mtime_nsec as _,
    };
    Timestamps {
        last_access: t,
        last_modification: t,
    }
}

/// An overlay whiteout: a 0:0 character device, or the xattr form where
/// devices cannot be made.
fn whiteout(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<()> {
    if mknodat(
        dir,
        name,
        FileType::CharacterDevice,
        Mode::from_raw_mode(0o600),
        0,
    )
    .is_ok()
    {
        return Ok(());
    }
    let fd = openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    fsetxattr(&fd, "user.overlay.whiteout", b"y", XattrFlags::empty())?;
    Ok(())
}

fn set_opaque(dir: BorrowedFd<'_>) -> io::Result<()> {
    let t = fsetxattr(dir, "trusted.overlay.opaque", b"y", XattrFlags::empty());
    let u = fsetxattr(dir, "user.overlay.opaque", b"y", XattrFlags::empty());
    match (t, u) {
        (Err(e), Err(_)) => Err(e.into()),
        _ => Ok(()),
    }
}

/// The merge of an upper directory into another: the upper directory is
/// walked, the other follows with a cursor of its own.
struct Merge<'a> {
    walk: &'a dirtar::Options,
    dst: Cursor,
}

/// What the walk keeps of a directory: its path (with the `/` after it), and
/// its status, set last on the directory it made.
struct MergeDir {
    prefix: String,
    st: Stat,
}

impl Merge<'_> {
    fn owner(&self, st: &Stat) -> io::Result<(Uid, Gid)> {
        let (u, g) = self.walk.to_container(st.st_uid, st.st_gid)?;
        Ok((Uid::from_raw_unchecked(u), Gid::from_raw_unchecked(g)))
    }
}

impl Visit for Merge<'_> {
    type Dir = MergeDir;

    fn entry(
        &mut self,
        src: BorrowedFd<'_>,
        name: &OsStr,
        st: &Stat,
        _: usize,
        parent: &mut MergeDir,
    ) -> io::Result<Option<MergeDir>> {
        let dst = self.dst.fd();
        let path = format!("{}{}", parent.prefix, name.to_string_lossy());
        let kind = FileType::from_raw_mode(st.st_mode);
        if kind != FileType::Directory && self.walk.excluded(&path) {
            return Ok(None);
        }
        let (is_whiteout, opaque) = dirtar::overlay_marks(src, name, st)?;
        if is_whiteout {
            remove_tree(dst, name)?;
            whiteout(dst, name)?;
            return Ok(None);
        }
        if kind == FileType::Directory {
            let existing = statat(dst, name, AtFlags::SYMLINK_NOFOLLOW).ok();
            let is_dir =
                existing.is_some_and(|s| FileType::from_raw_mode(s.st_mode) == FileType::Directory);
            if existing.is_some() && (!is_dir || opaque) {
                remove_tree(dst, name)?;
            }
            match mkdirat(dst, name, Mode::from_raw_mode(0o700)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
            self.dst.adopt(name, open_dir(dst, name)?)?;
            if opaque {
                set_opaque(self.dst.fd())?;
            }
            return Ok(Some(MergeDir {
                prefix: format!("{path}/"),
                st: *st,
            }));
        }
        remove_tree(dst, name)?;
        match kind {
            FileType::RegularFile => {
                let p = openat(
                    src,
                    name,
                    OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                let pst = fstat(&p)?;
                if FileType::from_raw_mode(pst.st_mode) != FileType::RegularFile {
                    return Err(io::Error::other(format!(
                        "`{path}` changed while it was read"
                    )));
                }
                let input = reopen(&p, &pst, OFlags::RDONLY | OFlags::NOCTTY)?;
                let out = openat(
                    dst,
                    name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )?;
                velarx_storage::copy_file(
                    &std::fs::File::from(input),
                    &std::fs::File::from(out.try_clone()?),
                    pst.st_size.max(0) as u64,
                    || Ok(()),
                )?;
                let (u, g) = self.owner(&pst)?;
                fchown(&out, Some(u), Some(g))?;
                fchmod(&out, Mode::from_raw_mode(pst.st_mode & 0o7777))?;
                futimens(&out, &times(&pst))?;
            }
            FileType::Symlink => {
                let target = readlinkat(src, name, Vec::new())?;
                symlinkat(target.as_c_str(), dst, name)?;
                let (u, g) = self.owner(st)?;
                chownat(dst, name, Some(u), Some(g), AtFlags::SYMLINK_NOFOLLOW)?;
                utimensat(dst, name, &times(st), AtFlags::SYMLINK_NOFOLLOW)?;
            }
            FileType::Fifo | FileType::CharacterDevice | FileType::BlockDevice => {
                mknodat(
                    dst,
                    name,
                    kind,
                    Mode::from_raw_mode(st.st_mode & 0o7777),
                    st.st_rdev,
                )?;
                let (u, g) = self.owner(st)?;
                chownat(dst, name, Some(u), Some(g), AtFlags::SYMLINK_NOFOLLOW)?;
            }
            _ => {}
        }
        Ok(None)
    }

    fn leave(
        &mut self,
        _: BorrowedFd<'_>,
        _: &mut MergeDir,
        _: &OsStr,
        _: OwnedFd,
        state: MergeDir,
    ) -> io::Result<()> {
        let (_, d) = self.dst.ascend()?;
        let (u, g) = self.owner(&state.st)?;
        fchown(&d, Some(u), Some(g))?;
        fchmod(&d, Mode::from_raw_mode(state.st.st_mode & 0o7777))?;
        futimens(&d, &times(&state.st))?;
        Ok(())
    }
}

/// Merge the upper directory `src` into `dst`.
pub fn merge(src: &Path, dst: &Path, walk: &dirtar::Options) -> io::Result<()> {
    let open = |p: &Path| -> io::Result<OwnedFd> {
        Ok(openat(
            rustix::fs::CWD,
            p,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?)
    };
    let (s, d) = (open(src)?, open(dst)?);
    let st = fstat(&s)?;
    Walk {
        max_depth: MAX_DEPTH,
        sorted: true,
        skip_gone: false,
        lenient: false,
    }
    .run(
        s,
        MergeDir {
            prefix: String::new(),
            st,
        },
        &mut Merge {
            walk,
            dst: Cursor::new(d)?,
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn test_later_changes_win() {
        let d = tempfile::tempdir().unwrap();
        let (a, b, out) = (d.path().join("a"), d.path().join("b"), d.path().join("out"));
        for p in [&a, &b, &out] {
            std::fs::create_dir(p).unwrap();
        }
        std::fs::create_dir_all(a.join("dir/sub")).unwrap();
        std::fs::write(a.join("dir/f"), "1").unwrap();
        std::fs::write(a.join("dir/sub/g"), "g").unwrap();
        std::fs::write(a.join("x"), "x").unwrap();
        std::fs::write(b.join("dir"), "now a file").unwrap();
        std::os::unix::fs::symlink("dir", b.join("x")).unwrap();
        let w = dirtar::Options::default();
        merge(&a, &out, &w).unwrap();
        assert_eq!(std::fs::read_to_string(out.join("dir/sub/g")).unwrap(), "g");
        merge(&b, &out, &w).unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join("dir")).unwrap(),
            "now a file"
        );
        assert_eq!(std::fs::read_link(out.join("x")).unwrap(), Path::new("dir"));
        let m = std::fs::metadata(out.join("dir")).unwrap();
        assert_eq!(m.uid(), rustix::process::getuid().as_raw());
    }
}
