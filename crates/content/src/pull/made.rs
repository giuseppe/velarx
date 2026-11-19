// SPDX-License-Identifier: Apache-2.0
//! The layer of a build or a commit, made as the directory is walked: each
//! file is read once, and that one read stages it (by its fs-verity name),
//! builds its entry of the table of contents, feeds the tar-split and the
//! tar stream's hash, which is the diff id.  No tar is written, kept or
//! parsed: the stream the walk would emit is hashed on the fly.

use super::entry::{self, FileUse, MAX_ENTRIES};
use super::sink::Sink;
use super::stream::{stage_file, Ingested};
use super::tar::{Header, Kind};
use super::tarsplit::Recorder;
use super::LayerReport;
use crate::layer::dirtar::{self, check_after, open_content, Content, Out};
use rustix::fd::BorrowedFd;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, Read};
use std::sync::Arc;
use velarx_storage::{Toc, TocEntry, TOC_VERSION};
use velarx_tarsplit::tar::Sink as _;
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

/// The content of a file as it is read: what goes by is the stream's, the
/// tar-split's.
struct Tee<'s, 'a, R> {
    file: R,
    stream: &'s mut Stream<'a>,
    split: &'s mut Recorder,
}

impl<R: Read> Read for Tee<'_, '_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read(buf)?;
        self.stream.push(&buf[..n])?;
        self.split.file_data(&buf[..n])?;
        Ok(n)
    }
}

struct MadeOut<'a> {
    session: &'a dyn Sink,
    alg: Algorithm,
    /// The bytes of the headers of the entry being made.
    builder: tar::Builder<Vec<u8>>,
    /// The extended attributes of the next entry.
    xattrs: BTreeMap<String, Vec<u8>>,
    stream: Stream<'a>,
    split: Recorder,
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
    /// The header bytes the builder has, sent on, and the header they make.
    fn header(&mut self, h: &tar::Header, path: &str, link: Option<String>) -> io::Result<Header> {
        let bytes = std::mem::take(self.builder.get_mut());
        self.stream.push(&bytes)?;
        self.split.segment(&bytes)?;
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
        self.split.file_begin(&header)?;
        Ok(header)
    }

    fn record(
        &mut self,
        header: &Header,
        digest: Option<&str>,
        verity: Option<String>,
    ) -> io::Result<()> {
        if self.entries.len() >= MAX_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the layer has too many entries (more than {MAX_ENTRIES})"),
            ));
        }
        if let Some(mut e) = entry::from_header(header, digest)? {
            // (a layer holds paths of `MAX_PATH_DEPTH` components at most:
            // what reads it back, and the EROFS image made from its table,
            // recurse for each)
            if let Some(problem) = entry::toc_problem(std::slice::from_ref(&e)) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, problem));
            }
            e.fsverity = verity;
            self.entries.push(e);
        }
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
        self.builder
            .append_pax_extensions(records.iter().map(|(k, v)| (k.as_str(), *v)))
    }

    fn entry(&mut self, h: &mut tar::Header, path: &str, content: Content<'_>) -> io::Result<()> {
        let opened = open_content(&content)?;
        self.builder.append_data(h, path, io::empty())?;
        let header = self.header(h, path, None)?;
        let mut verity = None;
        let mut digest = None;
        let mut size = 0;
        if header.kind == Kind::Regular && header.size == 0 {
            digest = Some(Digest::empty(self.alg).to_string());
        } else if header.kind == Kind::Regular {
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
                split: &mut self.split,
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
            verity = velarx_storage::to_toc(&staged.key);
            digest = Some(staged.content);
        }
        self.split.file_end()?;
        let padding = (BLOCK - size % BLOCK) % BLOCK;
        if padding > 0 {
            let zeros = [0u8; BLOCK as usize];
            self.stream.push(&zeros[..padding as usize])?;
            self.split.segment(&zeros[..padding as usize])?;
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
        self.record(&header, digest.as_deref(), verity)
    }

    fn link(&mut self, h: &mut tar::Header, path: &str, target: &OsStr) -> io::Result<()> {
        self.builder
            .append_link(h, path, std::path::PathBuf::from(target))?;
        let link = target
            .to_str()
            .ok_or_else(|| io::Error::other(format!("the link `{path}` has no UTF-8 target")))?;
        let header = self.header(h, path, Some(link.to_string()))?;
        self.split.file_end()?;
        self.record(&header, None, None)
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
    from_walk(session, alg, max_size, observe, |out| {
        dirtar::walk(dir, opts, out)
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
        builder: tar::Builder::new(Vec::new()),
        xattrs: BTreeMap::new(),
        stream: Stream {
            diff: DigestWriter::new(alg),
            size: 0,
            max: max_size,
            observe,
        },
        split: Recorder::new()?,
        entries: Vec::new(),
        files: Vec::new(),
        report: LayerReport::default(),
    };
    walk(&mut out)?;
    let end = [0u8; 2 * BLOCK as usize];
    out.stream.push(&end)?;
    out.split.segment(&end)?;
    let tarsplit = out.split.finish()?.compressed;
    let size = out.stream.size;
    Ok((
        Ingested {
            toc: Arc::new(Toc {
                version: TOC_VERSION,
                entries: out.entries,
                tar_split_digest: Some(Digest::of(alg, &tarsplit).to_string()),
            }),
            files: out.files,
            report: out.report,
            diff_id: out.stream.diff.finalize(),
            tarsplit: tarsplit.into(),
            from_local_source: true,
        },
        size,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pull::session::Session;
    use crate::pull::stream::{parse, Frame};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use velarx_storage::FileStore;

    fn session(tmp: &std::path::Path, name: &str) -> Arc<Session> {
        let store = Arc::new(FileStore::new(tmp.join(name).join("files")).unwrap());
        Session::create(&tmp.join(name).join("staging"), store).unwrap()
    }

    /// What the walk makes in its one pass is what the tar it stands for
    /// makes when it is written and read: the same table of contents,
    /// tar-split, diff id and files.
    #[test]
    fn the_walk_makes_what_its_tar_would() {
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

        let mut tar = Vec::new();
        dirtar::write(rustix::fd::AsFd::as_fd(&fd), &opts, &mut tar).unwrap();
        let alg = Algorithm::Sha256;
        let by_tar = session(tmp.path(), "tar");
        let (tx, rx) = tokio::sync::mpsc::channel::<Frame>(4);
        let sent = tar.clone();
        let feeder = std::thread::spawn(move || {
            for c in sent.chunks(100_000) {
                tx.blocking_send(Ok(bytes::Bytes::copy_from_slice(c)))
                    .unwrap();
            }
        });
        let mut report = LayerReport::default();
        let (entries, files, tarsplit) = parse(rx, alg, &*by_tar, &mut report, false).unwrap();
        feeder.join().unwrap();

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
        assert_eq!(size, tar.len() as u64);
        assert_eq!(seen, size);
        assert_eq!(made.diff_id, Digest::of(alg, &tar));
        assert_eq!(
            serde_json::to_value(&made.toc.entries).unwrap(),
            serde_json::to_value(&entries).unwrap()
        );
        assert_eq!(made.tarsplit.to_vec(), tarsplit);
        let keys = |f: &[FileUse]| {
            f.iter()
                .map(|f| (f.digest.clone(), f.size))
                .collect::<Vec<_>>()
        };
        assert_eq!(keys(&made.files), keys(&files));
        assert_eq!(made.report.fetched_files, report.fetched_files);
        assert_eq!(made.report.reused_files, report.reused_files);
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
}
