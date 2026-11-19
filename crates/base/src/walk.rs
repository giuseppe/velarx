// SPDX-License-Identifier: Apache-2.0
//! Walking a directory tree by descriptors, the one walker of the engine.
//!
//! The walk is iterative and holds a few descriptors whatever the depth: a
//! [`Cursor`] has the directory it is in open, and goes back to its parent
//! by `..`, checked to be the directory it came from (a directory moved
//! while it is walked is an error, not a way out of the tree).  It never
//! follows a symbolic link, and refuses a tree deeper than its limit.  What
//! a walk does with the entries is a [`Visit`]'s; one that needs a second
//! tree (a copy) walks it with a cursor of its own.
//!
//! What is done to a whole tree with it (its space, its removal) is in
//! [`crate::tree`].
//!
//! What recurses anyway (a walk of the table of contents of an image along
//! with the tree, the stream of a commit) runs on a thread of
//! [`WALK_STACK`].

use rustix::fs::{fstat, openat, statat, AtFlags, Dir, Mode, OFlags, Stat};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;

/// What tells a directory: its device and inode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ident {
    dev: u64,
    ino: u64,
}

impl Ident {
    fn of(st: &Stat) -> Self {
        Ident {
            dev: st.st_dev,
            ino: st.st_ino,
        }
    }
}

/// Open the directory `name` of `dir` without following a symbolic link.
pub fn open_dir_at(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<OwnedFd> {
    openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(io::Error::from)
}

/// The directory `path` (names of directories, as [`Cursor::path`] gives
/// them) below `root`, opened one name at a time without following a link.
pub fn open_dir_path(root: BorrowedFd<'_>, path: &[OsString]) -> io::Result<OwnedFd> {
    let mut fd = open_dir_at(root, OsStr::new("."))?;
    for name in path {
        fd = open_dir_at(fd.as_fd(), name)?;
    }
    Ok(fd)
}

/// The names in a directory, without `.` and `..`, in the order of the
/// directory.
pub fn names(dir: BorrowedFd<'_>) -> io::Result<Vec<OsString>> {
    names_at_most(dir, usize::MAX)
}

/// [`names`], refused once the directory has more than `max` names: a
/// directory of a tree the caller does not trust is not read whole first.
pub fn names_at_most(dir: BorrowedFd<'_>, max: usize) -> io::Result<Vec<OsString>> {
    let mut out = Vec::new();
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            if out.len() >= max {
                return Err(io::Error::other(format!(
                    "a directory has more than {max} names"
                )));
            }
            out.push(OsString::from_vec(name.to_vec()));
        }
    }
    Ok(out)
}

/// The error of a tree deeper than `max` levels.
pub fn too_deep(max: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("the directory tree is too deep (more than {max} levels)"),
    )
}

/// A directory of a tree, open, and the way back to the root of the tree:
/// the names and identities of the directories above it, not descriptors.
pub struct Cursor {
    fd: OwnedFd,
    /// the root, to go back up from a directory whose `..` cannot be
    /// looked up (one that may be read and not searched)
    root: OwnedFd,
    /// the root, then each directory down to the current one
    path: Vec<(OsString, Ident)>,
}

impl Cursor {
    /// At the root of a tree.
    pub fn new(root: OwnedFd) -> io::Result<Self> {
        let st = fstat(&root)?;
        Ok(Cursor {
            root: root.try_clone()?,
            fd: root,
            path: vec![(OsString::new(), Ident::of(&st))],
        })
    }

    /// The current directory.
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// How many directories below the root it is.
    pub fn depth(&self) -> usize {
        self.path.len() - 1
    }

    /// The names of the directories from the root down to the current one.
    pub fn path(&self) -> Vec<OsString> {
        self.path[1..].iter().map(|(n, _)| n.clone()).collect()
    }

    /// Into the directory `name`, without following a link.  With `seen`
    /// (what a stat of `name` showed), it must be that directory.
    pub fn descend(&mut self, name: &OsStr, seen: Option<&Stat>) -> io::Result<()> {
        let fd = open_dir_at(self.fd(), name)?;
        let st = fstat(&fd)?;
        if seen.is_some_and(|s| Ident::of(s) != Ident::of(&st)) {
            return Err(moved(name));
        }
        self.path.push((name.to_os_string(), Ident::of(&st)));
        self.fd = fd;
        Ok(())
    }

    /// Into the directory `name`, which the caller opened (or made) in the
    /// current directory: `fd` is that directory, opened without following a
    /// link.
    pub fn adopt(&mut self, name: &OsStr, fd: OwnedFd) -> io::Result<()> {
        let st = fstat(&fd)?;
        self.path.push((name.to_os_string(), Ident::of(&st)));
        self.fd = fd;
        Ok(())
    }

    /// Back into the parent; gives the directory it leaves, and its name.
    pub fn ascend(&mut self) -> io::Result<(OsString, OwnedFd)> {
        if self.path.len() < 2 {
            return Err(io::Error::other("the root of a walk has no parent"));
        }
        let parent = match open_dir_at(self.fd(), OsStr::new("..")) {
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => self.parent_from_root()?,
            r => r?,
        };
        let st = fstat(&parent)?;
        let (name, _) = self
            .path
            .pop()
            .ok_or_else(|| io::Error::other("an empty walk"))?;
        if self.path.last().is_none_or(|(_, id)| *id != Ident::of(&st)) {
            return Err(moved(&name));
        }
        Ok((name, std::mem::replace(&mut self.fd, parent)))
    }

    /// The parent of the current directory opened down from the root, each
    /// directory on the way the one walked into.
    fn parent_from_root(&self) -> io::Result<OwnedFd> {
        let mut fd = open_dir_at(self.root.as_fd(), OsStr::new("."))?;
        for (name, id) in &self.path[1..self.path.len() - 1] {
            fd = open_dir_at(fd.as_fd(), name)?;
            if Ident::of(&fstat(&fd)?) != *id {
                return Err(moved(name));
            }
        }
        Ok(fd)
    }
}

fn moved(name: &OsStr) -> io::Error {
    io::Error::other(format!(
        "the directory `{}` was moved while it was walked",
        name.to_string_lossy()
    ))
}

/// What a walk does with a tree.  Each directory has a `Dir`: the root's
/// is given to [`Walk::run`], the others are made by [`Visit::entry`].
pub trait Visit {
    /// What it keeps of a directory while it walks it.
    type Dir;

    /// The directory `dir` was listed: its `names`, in the order of the walk,
    /// before any of them is given to [`Visit::entry`].
    fn enter(
        &mut self,
        dir: BorrowedFd<'_>,
        names: &[OsString],
        state: &mut Self::Dir,
    ) -> io::Result<()> {
        let _ = (dir, names, state);
        Ok(())
    }

    /// The entry `name` of the directory `dir` (whose state is `parent`),
    /// with its stat (not following a link); `depth` is that of `dir` (0 for
    /// the root).  A `Dir` walks into it: it must be a directory.
    fn entry(
        &mut self,
        dir: BorrowedFd<'_>,
        name: &OsStr,
        st: &Stat,
        depth: usize,
        parent: &mut Self::Dir,
    ) -> io::Result<Option<Self::Dir>>;

    /// After the entries of the directory `dir`, the root's too.
    fn exit(&mut self, dir: BorrowedFd<'_>, state: &mut Self::Dir) -> io::Result<()> {
        let _ = (dir, state);
        Ok(())
    }

    /// Back in `parent` (whose state is `parent_state`) from its directory
    /// `name`, which is `dir`.
    fn leave(
        &mut self,
        parent: BorrowedFd<'_>,
        parent_state: &mut Self::Dir,
        name: &OsStr,
        dir: OwnedFd,
        state: Self::Dir,
    ) -> io::Result<()> {
        let _ = (parent, parent_state, name, dir, state);
        Ok(())
    }
}

/// How a tree is walked.
#[derive(Clone, Copy, Debug)]
pub struct Walk {
    /// The deepest directory walked into, below the root; deeper is an error
    /// ([`too_deep`]).
    pub max_depth: usize,
    /// The entries of a directory sorted by name, not in the order of the
    /// directory.
    pub sorted: bool,
    /// An entry gone between the listing and its stat is skipped, not an
    /// error.
    pub skip_gone: bool,
    /// What the system refuses below the root (a directory that cannot be
    /// opened or listed, an entry that cannot be stat'ed) is skipped, not an
    /// error: a count of what can be read.  A tree that is too deep or was
    /// moved is still an error.  A directory skipped so gets no
    /// [`Visit::enter`], [`Visit::exit`] or [`Visit::leave`]: the state
    /// [`Visit::entry`] made for it is dropped.
    pub lenient: bool,
}

struct Frame<D> {
    names: std::vec::IntoIter<OsString>,
    /// the name of the directory (empty for the root)
    name: OsString,
    state: D,
}

impl Walk {
    /// Walk the tree of `root`, whose state is `state`: each entry is given
    /// to `v`, the directories it asks for are walked into, depth first.
    /// Gives back the state of the root.
    pub fn run<V: Visit>(&self, root: OwnedFd, state: V::Dir, v: &mut V) -> io::Result<V::Dir> {
        let mut cur = Cursor::new(root)?;
        let mut stack = vec![self.frame(&cur, OsString::new(), state, v)?];
        // (the root is the last frame popped: it returns)
        while let Some(frame) = stack.last_mut() {
            let Some(name) = frame.names.next() else {
                let Some(mut frame) = stack.pop() else {
                    break;
                };
                v.exit(cur.fd(), &mut frame.state)?;
                let Some(parent) = stack.last_mut() else {
                    return Ok(frame.state);
                };
                let (_, dir) = cur.ascend()?;
                v.leave(cur.fd(), &mut parent.state, &frame.name, dir, frame.state)?;
                continue;
            };
            // (an automount point is not mounted by being looked at)
            let st = match statat(
                cur.fd(),
                &name,
                AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT,
            ) {
                Ok(st) => st,
                Err(rustix::io::Errno::NOENT) if self.skip_gone => continue,
                Err(_) if self.lenient => continue,
                Err(e) => return Err(io::Error::from(e)),
            };
            let Some(state) = v.entry(cur.fd(), &name, &st, cur.depth(), &mut frame.state)? else {
                continue;
            };
            if cur.depth() >= self.max_depth {
                return Err(too_deep(self.max_depth));
            }
            match cur.descend(&name, Some(&st)) {
                Err(e) if self.lenient && e.raw_os_error().is_some() => continue,
                r => r?,
            }
            match self.frame(&cur, name, state, v) {
                Ok(frame) => stack.push(frame),
                Err(e) if self.lenient && e.raw_os_error().is_some() => {
                    cur.ascend()?;
                }
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("a walk without its root"))
    }

    fn frame<V: Visit>(
        &self,
        cur: &Cursor,
        name: OsString,
        mut state: V::Dir,
        v: &mut V,
    ) -> io::Result<Frame<V::Dir>> {
        let names = self.names(cur.fd())?;
        v.enter(cur.fd(), &names, &mut state)?;
        Ok(Frame {
            names: names.into_iter(),
            name,
            state,
        })
    }

    fn names(&self, dir: BorrowedFd<'_>) -> io::Result<Vec<OsString>> {
        let mut out = names(dir)?;
        if self.sorted {
            out.sort();
        }
        Ok(out)
    }
}

/// The stack of the thread of a walk that recurses: a walk of the table of
/// contents of an image along with a tree (as deep as a pull takes,
/// `MAX_PATH_DEPTH`, 512 levels, or as a container makes it) needs more than
/// the stack of a thread of the blocking pool (2 MiB: a debug build
/// overflowed at about 300 levels, and an overflow aborts the process).  The
/// pages are taken only as they are used.
pub const WALK_STACK: usize = 64 << 20;

#[cfg(test)]
mod tests {
    use super::*;

    fn open(p: &std::path::Path) -> OwnedFd {
        openat(
            rustix::fs::CWD,
            p,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    /// Every path, in the order seen, and the leaves in order.
    #[derive(Default)]
    struct Paths {
        prefix: Vec<String>,
        seen: Vec<String>,
        left: Vec<String>,
        open_at_deepest: usize,
        /// what enter and exit saw: the names listed, the directories done
        listed: Vec<usize>,
        exited: usize,
    }

    fn open_fds() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

    impl Visit for Paths {
        type Dir = ();

        fn enter(&mut self, _: BorrowedFd<'_>, names: &[OsString], _: &mut ()) -> io::Result<()> {
            self.listed.push(names.len());
            Ok(())
        }

        fn exit(&mut self, _: BorrowedFd<'_>, _: &mut ()) -> io::Result<()> {
            self.exited += 1;
            Ok(())
        }
        fn entry(
            &mut self,
            _: BorrowedFd<'_>,
            name: &OsStr,
            st: &Stat,
            depth: usize,
            _: &mut (),
        ) -> io::Result<Option<()>> {
            assert_eq!(depth, self.prefix.len());
            let path = [self.prefix.join("/"), name.to_string_lossy().into()]
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join("/");
            self.seen.push(path);
            let dir =
                rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Directory;
            if dir {
                self.prefix.push(name.to_string_lossy().into());
                self.open_at_deepest = self.open_at_deepest.max(open_fds());
            }
            Ok(dir.then_some(()))
        }
        fn leave(
            &mut self,
            _: BorrowedFd<'_>,
            _: &mut (),
            name: &OsStr,
            _: OwnedFd,
            _: (),
        ) -> io::Result<()> {
            assert_eq!(self.prefix.pop().as_deref(), name.to_str());
            self.left.push(name.to_string_lossy().into());
            Ok(())
        }
    }

    #[test]
    fn names_at_most_refuses_a_directory_with_more() {
        let tmp = tempfile::tempdir().unwrap();
        for n in ["a", "b", "c"] {
            std::fs::write(tmp.path().join(n), b"").unwrap();
        }
        let dir = std::fs::File::open(tmp.path()).unwrap();
        assert_eq!(names_at_most(dir.as_fd(), 3).unwrap().len(), 3);
        assert!(names_at_most(dir.as_fd(), 2).is_err());
    }

    #[test]
    fn test_a_tree_is_walked_depth_first_without_following_links() {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        std::fs::create_dir_all(t.join("a/b")).unwrap();
        std::fs::create_dir(t.join("c")).unwrap();
        std::fs::write(t.join("a/b/f"), "").unwrap();
        std::fs::write(t.join("z"), "").unwrap();
        std::os::unix::fs::symlink("/", t.join("a/root")).unwrap();
        let mut p = Paths::default();
        let walk = Walk {
            max_depth: 10,
            sorted: true,
            skip_gone: false,
            lenient: false,
        };
        walk.run(open(t), (), &mut p).unwrap();
        assert_eq!(p.seen, ["a", "a/b", "a/b/f", "a/root", "c", "z"]);
        let mut cur = Cursor::new(open(t)).unwrap();
        cur.descend(OsStr::new("a"), None).unwrap();
        cur.descend(OsStr::new("b"), None).unwrap();
        assert_eq!(cur.path(), ["a", "b"]);
        let fd = open_dir_path(open(t).as_fd(), &cur.path()).unwrap();
        assert_eq!(names(fd.as_fd()).unwrap(), ["f"]);
        assert!(cur.descend(OsStr::new("f"), None).is_err());
        assert!(open_dir_path(open(t).as_fd(), &["a".into(), "root".into()]).is_err());
        assert_eq!(cur.ascend().unwrap().0, "b");
        assert_eq!(cur.depth(), 1);
        assert_eq!(p.left, ["b", "a", "c"]);
        // the root, a, a/b, c: listed before their entries, exited after
        assert_eq!((p.listed, p.exited), (vec![3, 2, 1, 0], 4));
    }

    /// Lenient: a directory that cannot be read is left out, the rest is
    /// walked; without it, an error.  Too deep stays an error.
    #[test]
    fn test_a_lenient_walk_skips_what_cannot_be_read_and_nothing_else() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        std::fs::create_dir_all(t.join("a/closed/x")).unwrap();
        std::fs::create_dir_all(t.join("b/c")).unwrap();
        std::fs::write(t.join("a/closed/f"), "").unwrap();
        // (read and not searched: listed, each entry refused, and left)
        std::fs::write(t.join("b/c/g"), "").unwrap();
        let set = |m| {
            for (d, m) in [("a/closed", m), ("b/c", m | 0o600)] {
                std::fs::set_permissions(t.join(d), std::fs::Permissions::from_mode(m)).unwrap()
            }
        };
        set(0o000);
        let walk = |lenient, max_depth| Walk {
            max_depth,
            sorted: true,
            skip_gone: false,
            lenient,
        };
        /// (the path of a directory is its state: a directory skipped is
        /// dropped with it)
        #[derive(Default)]
        struct Seen(Vec<String>);
        impl Visit for Seen {
            type Dir = String;
            fn entry(
                &mut self,
                _: BorrowedFd<'_>,
                name: &OsStr,
                st: &Stat,
                _: usize,
                parent: &mut String,
            ) -> io::Result<Option<String>> {
                let p = format!("{parent}{}", name.to_string_lossy());
                self.0.push(p.clone());
                let dir = rustix::fs::FileType::from_raw_mode(st.st_mode)
                    == rustix::fs::FileType::Directory;
                Ok(dir.then(|| format!("{p}/")))
            }
        }
        let mut p = Seen::default();
        let r = walk(true, 10).run(open(t), String::new(), &mut p);
        let root = rustix::process::geteuid().is_root();
        let strict = walk(false, 10).run(open(t), String::new(), &mut Seen::default());
        let deep = walk(true, 1).run(open(t), String::new(), &mut Seen::default());
        set(0o700);
        r.unwrap();
        if root {
            assert_eq!(p.0.len(), 7);
        } else {
            assert_eq!(p.0, ["a", "a/closed", "b", "b/c"]);
            assert_eq!(strict.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        }
        assert!(deep.unwrap_err().to_string().contains("too deep"));
    }

    /// A deep tree: a few descriptors whatever the depth, and the limit.
    #[test]
    fn test_a_deep_tree_holds_a_few_descriptors_and_the_depth_is_limited() {
        // (the descriptors of the process are counted: in a child process
        // that runs this test alone, under a limit a descriptor per level
        // could not keep to; the other tests open theirs meanwhile)
        if std::env::var_os("VELARX_WALK_FD_TEST").is_none() {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(
                    r#"ulimit -Sn 64 && exec "$0" --exact walk::tests::test_a_deep_tree_holds_a_few_descriptors_and_the_depth_is_limited"#,
                )
                .arg(std::env::current_exe().unwrap())
                .env("VELARX_WALK_FD_TEST", "1")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"));
            return;
        }
        const DEPTH: usize = 2000;
        let tmp = tempfile::tempdir().unwrap();
        // (the tree is deeper than a path can be: a removal by path, the
        // directory's own at its end, fails and leaves it behind)
        struct Deep(std::path::PathBuf);
        impl Drop for Deep {
            fn drop(&mut self) {
                let _ = crate::tree::remove_dir_all(&self.0);
            }
        }
        let _deep = Deep(tmp.path().join("d"));
        let mut fd = open(tmp.path());
        for _ in 0..DEPTH {
            rustix::fs::mkdirat(&fd, "d", Mode::from_raw_mode(0o700)).unwrap();
            fd = open_dir_at(fd.as_fd(), OsStr::new("d")).unwrap();
        }
        drop(fd);
        let before = open_fds();
        let mut p = Paths::default();
        let walk = |max_depth| Walk {
            max_depth,
            sorted: false,
            skip_gone: false,
            lenient: false,
        };
        // (on a small stack: the walk does not recurse)
        std::thread::scope(|s| {
            std::thread::Builder::new()
                .stack_size(64 << 10)
                .spawn_scoped(s, || walk(DEPTH).run(open(tmp.path()), (), &mut p).unwrap())
                .unwrap()
                .join()
                .unwrap()
        });
        assert_eq!((p.seen.len(), p.left.len()), (DEPTH, DEPTH));
        assert!(
            p.open_at_deepest <= before + 4,
            "{} > {before} + 4",
            p.open_at_deepest
        );
        let e = walk(DEPTH - 1)
            .run(open(tmp.path()), (), &mut Paths::default())
            .unwrap_err();
        assert!(e.to_string().contains("too deep"), "{e}");
    }

    /// A directory moved out of the tree while it is walked: the walk does
    /// not follow it out.
    #[test]
    fn test_a_directory_moved_away_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path().to_path_buf();
        std::fs::create_dir_all(t.join("tree/a/b")).unwrap();
        std::fs::create_dir(t.join("out")).unwrap();
        struct Mover(std::path::PathBuf);
        impl Visit for Mover {
            type Dir = ();
            fn entry(
                &mut self,
                _: BorrowedFd<'_>,
                name: &OsStr,
                _: &Stat,
                _: usize,
                _: &mut (),
            ) -> io::Result<Option<()>> {
                if name == "b" {
                    std::fs::rename(self.0.join("tree/a"), self.0.join("out/a")).unwrap();
                }
                Ok(Some(()))
            }
        }
        let e = Walk {
            max_depth: 10,
            sorted: true,
            skip_gone: false,
            lenient: false,
        }
        .run(open(&t.join("tree")), (), &mut Mover(t.clone()))
        .unwrap_err();
        assert!(e.to_string().contains("was moved"), "{e}");
    }

    /// A directory replaced by another between its stat and the walk into it.
    #[test]
    fn test_a_directory_replaced_after_its_stat_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path().to_path_buf();
        std::fs::create_dir_all(t.join("tree/a")).unwrap();
        struct Swapper(std::path::PathBuf);
        impl Visit for Swapper {
            type Dir = ();
            fn entry(
                &mut self,
                _: BorrowedFd<'_>,
                _: &OsStr,
                _: &Stat,
                _: usize,
                _: &mut (),
            ) -> io::Result<Option<()>> {
                std::fs::rename(self.0.join("tree/a"), self.0.join("a")).unwrap();
                std::fs::create_dir(self.0.join("tree/a")).unwrap();
                Ok(Some(()))
            }
        }
        // (lenient too: a moved directory is no permission refused)
        let e = Walk {
            max_depth: 10,
            sorted: true,
            skip_gone: false,
            lenient: true,
        }
        .run(open(&t.join("tree")), (), &mut Swapper(t.clone()))
        .unwrap_err();
        assert!(e.to_string().contains("was moved"), "{e}");
    }

    /// A cursor takes a directory the caller made.
    #[test]
    fn test_a_cursor_adopts_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        std::fs::create_dir_all(t.join("a/b")).unwrap();
        let mut cur = Cursor::new(open(t)).unwrap();
        let a = open_dir_at(cur.fd(), OsStr::new("a")).unwrap();
        cur.adopt(OsStr::new("a"), a).unwrap();
        assert_eq!((cur.depth(), cur.path()), (1, vec![OsString::from("a")]));
        assert_eq!(cur.ascend().unwrap().0, "a");
    }
}
