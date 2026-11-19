// SPDX-License-Identifier: Apache-2.0
//! The layer of a build or a commit, made as the directory is walked: each
//! file is read once, and that one read stages it (by its fs-verity name),
//! builds its entry of the table of contents and feeds the hash of the tar
//! stream, which is the diff id.  The stream is the canonical tar of the
//! layer ([`velarx_storage::canonical`]): it needs no tar-split, its table
//! of contents has the version that says so.  No tar is written, kept or
//! parsed: the stream the walk would emit is hashed on the fly.

use super::entry::{self, FileUse, MAX_ENTRIES};
use super::sink::Sink;
use super::stream::{stage_file, Ingested};
use super::tar::{Header, Kind};
use super::LayerReport;
use crate::layer::dirtar::{self, check_after, open_content, Content, Out};
use rustix::fd::BorrowedFd;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, Read};
use std::sync::Arc;
use velarx_storage::{canonical, Toc, TocEntry, TocEntryType, TOC_VERSION_CANONICAL};
use velarx_types::digest::{Algorithm, Digest, DigestWriter};

const BLOCK: u64 = 512;

/// Called with the bytes of the tar stream made so far; an error stops the
/// walk (the operation was cancelled).
pub type Observe<'a> = Box<dyn FnMut(u64) -> io::Result<()> + 'a>;

/// The tar stream the walk stands for: hashed as it goes by, never stored.
struct Stream<'a> {
    diff: DigestWriter,
    size: u64,
    max: u64,
    observe: Observe<'a>,
}

impl Stream<'_> {
    fn push(&mut self, data: &[u8]) -> io::Result<()> {
        self.size += data.len() as u64;
        if self.size > self.max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the layer is larger than {} bytes ([pull] max_layer_gib)",
                    self.max
                ),
            ));
        }
        self.diff.update(data);
        (self.observe)(data.len() as u64)
    }
}

/// The content of a file as it is read: what goes by is the stream's.
struct Tee<'s, 'a, R> {
    file: R,
    stream: &'s mut Stream<'a>,
}

impl<R: Read> Read for Tee<'_, '_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read(buf)?;
        self.stream.push(&buf[..n])?;
        Ok(n)
    }
}

struct MadeOut<'a> {
    session: &'a dyn Sink,
    alg: Algorithm,
    /// The extended attributes of the next entry.
    xattrs: BTreeMap<String, Vec<u8>>,
    stream: Stream<'a>,
    entries: Vec<TocEntry>,
    files: Vec<FileUse>,
    report: LayerReport,
}

fn kind_of(t: tar::EntryType) -> io::Result<Kind> {
    Ok(match t {
        tar::EntryType::Regular | tar::EntryType::Continuous => Kind::Regular,
        tar::EntryType::Directory => Kind::Directory,
        tar::EntryType::Symlink => Kind::Symlink,
        tar::EntryType::Link => Kind::Hardlink,
        tar::EntryType::Char => Kind::Char,
        tar::EntryType::Block => Kind::Block,
        tar::EntryType::Fifo => Kind::Fifo,
        other => {
            return Err(io::Error::other(format!(
                "no entry of type {other:?} in a layer"
            )))
        }
    })
}

impl MadeOut<'_> {
    /// The header of the entry `h` in the walk.
    fn header(&mut self, h: &tar::Header, path: &str, link: Option<String>) -> io::Result<Header> {
        let kind = kind_of(h.entry_type())?;
        let device = |f: io::Result<Option<u32>>| f.map(|v| v.unwrap_or(0));
        let (dev_major, dev_minor) = if matches!(kind, Kind::Char | Kind::Block) {
            (device(h.device_major())?, device(h.device_minor())?)
        } else {
            (0, 0)
        };
        let header = Header {
            path: path.to_string(),
            kind,
            size: h.size()?,
            mode: h.mode()? & 0o7777,
            uid: u32::try_from(h.uid()?).map_err(|_| io::Error::other("uid is too large"))?,
            gid: u32::try_from(h.gid()?).map_err(|_| io::Error::other("gid is too large"))?,
            mtime: (i64::try_from(h.mtime()?).unwrap_or(0), 0),
            link,
            dev_major,
            dev_minor,
            xattrs: std::mem::take(&mut self.xattrs),
        };
        Ok(header)
    }

    /// The entry of the table of contents of the header, as the canonical
    /// tar names it, and its header sent on: the content is not known yet.
    fn begin(&mut self, header: &Header) -> io::Result<TocEntry> {
        let empty = Digest::empty(self.alg).to_string();
        let mut e = entry::from_header(header, (header.kind == Kind::Regular).then_some(&*empty))?;
        if e.name != "./" {
            e.name = format!("./{}", e.name);
        }
        if e.entry_type == TocEntryType::Dir && e.name != "./" {
            e.name.push('/');
        }
        if e.entry_type == TocEntryType::Hardlink {
            e.link_name = e.link_name.map(|l| format!("./{l}"));
            // (they are the xattrs of the file it is a link to)
            e.xattrs.clear();
        }
        self.stream
            .push(&canonical::header(&e, self.entries.is_empty())?)?;
        Ok(e)
    }

    fn record(&mut self, e: TocEntry) -> io::Result<()> {
        if self.entries.len() >= MAX_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the layer has too many entries (more than {MAX_ENTRIES})"),
            ));
        }
        // (a layer holds paths of `MAX_PATH_DEPTH` components at most:
        // what reads it back, and the EROFS image made from its table,
        // recurse for each)
        if let Some(problem) = entry::toc_problem(std::slice::from_ref(&e)) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, problem));
        }
        self.entries.push(e);
        Ok(())
    }
}

impl Out for MadeOut<'_> {
    fn pax(&mut self, records: &[(String, &[u8])]) -> io::Result<()> {
        for (k, v) in records {
            if let Some(name) = k.strip_prefix("SCHILY.xattr.") {
                self.xattrs.insert(name.to_string(), v.to_vec());
            }
        }
        Ok(())
    }

    fn entry(&mut self, h: &mut tar::Header, path: &str, content: Content<'_>) -> io::Result<()> {
        let opened = open_content(&content)?;
        let header = self.header(h, path, None)?;
        let mut e = self.begin(&header)?;
        let mut size = 0;
        if header.kind == Kind::Regular && header.size > 0 {
            let (file, len) = opened
                .as_ref()
                .ok_or_else(|| io::Error::other(format!("`{path}` has no content")))?;
            size = *len;
            if size != header.size {
                return Err(dirtar_changed(path));
            }
            let mut tee = Tee {
                file,
                stream: &mut self.stream,
            };
            let staged = stage_file(self.session, self.alg, &mut tee, size, false)?;
            if staged.added {
                self.report.fetched_files += 1;
            } else {
                self.report.reused_files += 1;
            }
            self.files.push(FileUse {
                digest: staged.key.clone(),
                size,
            });
            e.fsverity = velarx_storage::to_toc(&staged.key);
            e.chunk_digest = Some(staged.content.clone());
            e.digest = Some(staged.content);
        }
        let padding = (BLOCK - size % BLOCK) % BLOCK;
        if padding > 0 {
            let zeros = [0u8; BLOCK as usize];
            self.stream.push(&zeros[..padding as usize])?;
        }
        if let Some((file, _)) = &opened {
            match &content {
                Content::Upper { seen, shown, .. }
                | Content::Opened {
                    seen: Some(seen),
                    shown,
                    ..
                } => check_after(file, seen, shown)?,
                _ => {}
            }
        }
        self.record(e)
    }

    fn link(&mut self, h: &mut tar::Header, path: &str, target: &OsStr) -> io::Result<()> {
        let link = target
            .to_str()
            .ok_or_else(|| io::Error::other(format!("the link `{path}` has no UTF-8 target")))?;
        let header = self.header(h, path, Some(link.to_string()))?;
        let e = self.begin(&header)?;
        self.record(e)
    }
}

fn dirtar_changed(path: &str) -> io::Error {
    crate::layer::holes::changed(path)
}

/// Make the layer of the changes in `dir`: its files staged in `session`,
/// its table of contents, tar-split and diff id, all from the one walk.
/// Returns what was made and the size of the tar stream it stands for.
pub fn from_dir(
    dir: BorrowedFd<'_>,
    opts: &dirtar::Options,
    session: &Arc<dyn Sink>,
    alg: Algorithm,
    max_size: u64,
    observe: Observe<'_>,
) -> io::Result<(Ingested, u64)> {
    // (the walk gives the entries in the order of the directories, a
    // whiteout in the place of the file it hides: the layer has them in
    // the order of its tar)
    let mut entries = dirtar::record(dir, opts)?;
    dirtar::sort_canonical(&mut entries);
    from_walk(session, alg, max_size, observe, |out| {
        entries.iter().try_for_each(|e| dirtar::replay(e, dir, out))
    })
}

/// Make a layer of what `walk` gives to the [`Out`] it is called with, in
/// order, as the entries of a tar stream (the directory of a build, the
/// merged tree of a squash): each file read once.
pub fn from_walk(
    session: &Arc<dyn Sink>,
    alg: Algorithm,
    max_size: u64,
    observe: Observe<'_>,
    walk: impl FnOnce(&mut dyn Out) -> io::Result<()>,
) -> io::Result<(Ingested, u64)> {
    let mut out = MadeOut {
        session: &**session,
        alg,
        xattrs: BTreeMap::new(),
        stream: Stream {
            diff: DigestWriter::new(alg),
            size: 0,
            max: max_size,
            observe,
        },
        entries: Vec::new(),
        files: Vec::new(),
        report: LayerReport::default(),
    };
    walk(&mut out)?;
    // (what the walk gave is what the stream was hashed as: the layer
    // is not made unless the table says the same tar)
    canonical::validate_entries(&out.entries).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the layer is not a canonical tar: {e}"),
        )
    })?;
    out.stream.push(&[0u8; 2 * BLOCK as usize])?;
    let size = out.stream.size;
    Ok((
        Ingested {
            toc: Arc::new(Toc {
                version: TOC_VERSION_CANONICAL,
                entries: out.entries,
                tar_split_digest: None,
            }),
            files: out.files,
            report: out.report,
            diff_id: out.stream.diff.finalize(),
            tarsplit: bytes::Bytes::new(),
            from_local_source: true,
        },
        size,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pull::session::Session;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use velarx_storage::FileStore;

    fn session(tmp: &std::path::Path, name: &str) -> Arc<Session> {
        let store = Arc::new(FileStore::new(tmp.join(name).join("files")).unwrap());
        Session::create(&tmp.join(name).join("staging"), store).unwrap()
    }

    /// What the walk makes in its one pass is the canonical tar of the
    /// table of contents it makes: its digest is the diff id, and its files
    /// are the ones staged.
    #[test]
    fn the_walk_makes_the_canonical_tar_of_its_table() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("d/e")).unwrap();
        std::fs::write(root.join("d/a"), b"hello").unwrap();
        std::fs::write(root.join("d/e/big"), vec![7u8; 700_000]).unwrap();
        std::fs::write(root.join("empty"), b"").unwrap();
        std::fs::write(root.join("same"), b"hello").unwrap();
        std::fs::hard_link(root.join("d/a"), root.join("d/link")).unwrap();
        symlink("a", root.join("d/sym")).unwrap();
        std::fs::set_permissions(root.join("d/a"), std::fs::Permissions::from_mode(0o751)).unwrap();
        let name = "n".repeat(150);
        std::fs::write(root.join(&name), b"long").unwrap();
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            &root,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let opts = dirtar::Options::default();
        let alg = Algorithm::Sha256;
        let by_walk = session(tmp.path(), "walk");
        let sink: Arc<dyn Sink> = by_walk.clone();
        let mut seen = 0u64;
        let (made, size) = from_dir(
            rustix::fd::AsFd::as_fd(&fd),
            &opts,
            &sink,
            alg,
            u64::MAX,
            Box::new(|n| {
                seen += n;
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(seen, size);
        assert!(made.toc.is_canonical() && made.tarsplit.is_empty());
        assert_eq!(made.toc.tar_split_digest, None);
        let names: Vec<_> = made.toc.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "./d/",
                "./d/a",
                "./d/e/",
                "./d/e/big",
                "./d/link",
                "./d/sym",
                "./empty",
                &format!("./{name}"),
                "./same"
            ]
        );
        assert_eq!(made.toc.entries[4].link_name.as_deref(), Some("./d/a"));
        canonical::validate_entries(&made.toc.entries).unwrap();
        // the tar of the table, with the files that were staged
        let mut tar = Vec::new();
        canonical::write(&made.toc.entries, &mut tar, |e, out| {
            let key = e.content_key().unwrap();
            let path = by_walk.content_path(&key).unwrap();
            out.write_all(&std::fs::read(path).unwrap())
        })
        .unwrap();
        assert_eq!(size, tar.len() as u64);
        assert_eq!(made.diff_id, Digest::of(alg, &tar));
        canonical::validate_tar(&tar[..]).unwrap();
        assert_eq!(made.files.len(), 4);
    }

    /// A whiteout is where its own name sorts, not where the file it hides
    /// was, and has the mode, owner and time every whiteout has.
    #[test]
    fn a_whiteout_is_in_the_order_of_its_own_name() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        for f in [".a", "b", "c", "z"] {
            std::fs::write(root.join(f), b"x").unwrap();
        }
        std::fs::write(root.join("gone"), b"").unwrap();
        let path = std::ffi::CString::new(root.join("gone").to_str().unwrap()).unwrap();
        let name = std::ffi::CString::new("user.overlay.whiteout").unwrap();
        if rustix::fs::lsetxattr(&path, &name, b"y", rustix::fs::XattrFlags::empty()).is_err() {
            eprintln!("user xattrs are not supported here: skipped");
            return;
        }
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            &root,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let sink: Arc<dyn Sink> = session(tmp.path(), "walk");
        let (made, size) = from_dir(
            rustix::fd::AsFd::as_fd(&fd),
            &dirtar::Options::default(),
            &sink,
            Algorithm::Sha256,
            u64::MAX,
            Box::new(|_| Ok(())),
        )
        .unwrap();
        let names: Vec<_> = made.toc.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["./.a", "./.wh.gone", "./b", "./c", "./z"]);
        let wh = &made.toc.entries[1];
        assert_eq!((wh.mode, wh.uid, wh.gid, wh.size), (0o644, 0, 0, 0));
        assert_eq!(wh.mtime(), (0, 0));
        assert_eq!(size, canonical::stream_size(&made.toc.entries).unwrap());
    }

    /// A tree deeper than a layer holds is refused as the walk reaches it:
    /// the reader of the layer and the EROFS image made from its table
    /// recurse for each level.
    #[test]
    fn a_tree_deeper_than_a_layer_holds_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let deep = vec!["d"; crate::pull::tar::MAX_PATH_DEPTH + 2].join("/");
        std::fs::create_dir_all(root.join(deep)).unwrap();
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            &root,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let sink: Arc<dyn Sink> = session(tmp.path(), "walk");
        let e = from_dir(
            rustix::fd::AsFd::as_fd(&fd),
            &dirtar::Options::default(),
            &sink,
            Algorithm::Sha256,
            u64::MAX,
            Box::new(|_| Ok(())),
        )
        .map(|_| ())
        .unwrap_err();
        assert!(e.to_string().contains("too deep"), "{e}");
    }

    /// The root of the directory is the first entry when the walk is asked
    /// for it: always, or when it is not the plain root a layer without the
    /// entry has (0755, root, no attributes).
    #[test]
    fn the_root_of_the_directory_is_the_first_entry_when_asked() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        // ('!' sorts before the `.` of the root's name)
        std::fs::write(root.join("!x"), b"x").unwrap();
        std::fs::write(root.join("a"), b"a").unwrap();
        let own = |host| {
            vec![dirtar::IdRange {
                container: 0,
                host,
                size: 1,
            }]
        };
        let names = |mode: u32, root_entry: dirtar::Root, below: Option<u32>| {
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(mode)).unwrap();
            let fd = rustix::fs::openat(
                rustix::fs::CWD,
                &root,
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            let opts = dirtar::Options {
                uid_map: own(rustix::process::getuid().as_raw()),
                gid_map: own(rustix::process::getgid().as_raw()),
                root: root_entry,
                below: below.map(|mode| {
                    std::sync::Arc::new(velarx_storage::TocEntry {
                        mode,
                        ..velarx_storage::TocEntry::new("./", velarx_storage::TocEntryType::Dir)
                    })
                }),
                ..Default::default()
            };
            let sink: Arc<dyn Sink> = session(tmp.path(), "walk");
            let (made, size) = from_dir(
                rustix::fd::AsFd::as_fd(&fd),
                &opts,
                &sink,
                Algorithm::Sha256,
                u64::MAX,
                Box::new(|_| Ok(())),
            )
            .unwrap();
            assert_eq!(size, canonical::stream_size(&made.toc.entries).unwrap());
            let e = &made.toc.entries[0];
            if e.name == "./" && below.is_none() {
                assert_eq!((e.mode, e.uid, e.gid), (mode, 0, 0));
            }
            let names: Vec<String> = made.toc.entries.iter().map(|e| e.name.clone()).collect();
            names
        };
        assert_eq!(
            names(0o755, dirtar::Root::Always, None),
            ["./", "./!x", "./a"]
        );
        assert_eq!(
            names(0o700, dirtar::Root::Changed, None),
            ["./", "./!x", "./a"]
        );
        assert_eq!(names(0o755, dirtar::Root::Changed, None), ["./!x", "./a"]);
        assert_eq!(names(0o700, dirtar::Root::Never, None), ["./!x", "./a"]);
        // the root of the file system the directory is a copy into is the
        // entry, whatever the directory has
        assert_eq!(
            names(0o755, dirtar::Root::Changed, Some(0o1750)),
            ["./", "./!x", "./a"]
        );
        assert_eq!(
            names(0o700, dirtar::Root::Changed, Some(0o755)),
            ["./!x", "./a"]
        );
    }
}
