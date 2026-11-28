// SPDX-License-Identifier: Apache-2.0
//! The files an image holds itself (`layer_erofs::Inline`): what the writer
//! makes of them, what the reader gives back, and the memory the writer
//! needs.

use crate::erofs_tree::Layer;
use crate::layer_erofs::{layer_image, write_layer_image, Inline, Written};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use velarx_storage::{TocEntry, TocEntryType, VerityHasher};
use velarx_types::digest::{Algorithm, Digest};

/// The bytes of a test file: not the same from one size or seed to another.
pub(crate) fn bytes(seed: u8, size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8 ^ seed)
        .collect()
}

/// Files by digest, where `Inline::open` finds them.
pub(crate) struct Contents {
    dir: tempfile::TempDir,
    pub(crate) paths: HashMap<Digest, PathBuf>,
}

impl Contents {
    pub(crate) fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            paths: HashMap::new(),
        }
    }

    /// The entry of a file of this content, which the store now has.
    pub(crate) fn file(&mut self, name: &str, data: &[u8]) -> TocEntry {
        let digest =
            Digest::parse_fsverity(&velarx_storage::fsverity_digest_of(Algorithm::Sha256, data))
                .unwrap();
        let path = self.dir.path().join(digest.hex());
        std::fs::write(&path, data).unwrap();
        self.paths.insert(digest, path);
        let mut e = crate::dir_entry(name);
        e.entry_type = TocEntryType::Reg;
        e.mode = 0o644;
        e.mod_time = Some("2024-01-02T03:04:05+00:00".into());
        (e.size, e.fsverity) = (data.len() as u64, Some(digest));
        e
    }

    pub(crate) fn open(&self, digest: &Digest) -> std::io::Result<std::fs::File> {
        std::fs::File::open(&self.paths[digest])
    }
}

fn dir(name: &str) -> TocEntry {
    let mut e = crate::dir_entry(name);
    e.entry_type = TocEntryType::Dir;
    e.mode = 0o755;
    e
}

/// The nid of `path` in the layer.
fn nid(layer: &Layer, path: &str) -> u64 {
    path.split('/')
        .fold(layer.root(), |d, c| layer.lookup(d, c.as_bytes()).unwrap())
}

/// A writer that hashes what it is given as an fs-verity file: the digest
/// of an image written in order is the one of the image in memory.
struct Hashing(VerityHasher);

impl Write for Hashing {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.update(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The sizes at the edges of the inline rule, of the blocks, and a big one.
const SIZES: [usize; 11] = [1, 63, 64, 65, 3000, 4000, 4095, 4096, 4097, 9000, 3 << 20];

fn layer_of(contents: &mut Contents) -> (Vec<TocEntry>, Vec<(String, Vec<u8>)>) {
    let mut entries = vec![dir("d")];
    let mut files = Vec::new();
    for (i, size) in SIZES.into_iter().enumerate() {
        let data = bytes(i as u8, size);
        let name = format!("d/f{size}");
        entries.push(contents.file(&name, &data));
        files.push((name, data));
    }
    // a file with attributes that leave no room for 4000 bytes in a block
    let data = bytes(100, 4000);
    let mut big_attrs = contents.file("d/attrs", &data);
    big_attrs
        .xattrs
        .insert("user.big".into(), STANDARD.encode(vec![b'x'; 300]));
    entries.push(big_attrs);
    files.push(("d/attrs".into(), data.clone()));
    // the same content under another name: two files, one extent
    entries.push(contents.file("d/again", &data));
    files.push(("d/again".into(), data));
    // a hard link: one file
    let mut link = crate::dir_entry("d/link");
    link.entry_type = TocEntryType::Hardlink;
    link.link_name = Some("d/f65".into());
    entries.push(link);
    files.push(("d/link".into(), bytes(3, 65)));
    entries.push({
        let mut e = crate::dir_entry("d/empty");
        e.entry_type = TocEntryType::Reg;
        e.mode = 0o644;
        e
    });
    (entries, files)
}

fn written(entries: &[TocEntry], contents: &Contents, threshold: i64) -> (Vec<u8>, Written) {
    let mut image = Vec::new();
    let open = |d: &Digest| contents.open(d);
    let w = write_layer_image(
        entries,
        &Inline {
            threshold,
            open: &open,
        },
        &mut image,
    )
    .unwrap();
    (image, w)
}

fn held_at(threshold: i64, size: usize) -> bool {
    threshold < 0 || size as i64 <= threshold
}

/// With 0 the image is the one of the table; with `N` the files of at most
/// `N` bytes are in it and the others are stubs; with -1 every file is.
/// What the reader gives for a file is its content, and its extent is where
/// the content is.
#[test]
fn the_files_the_image_holds_are_read_back() {
    let mut contents = Contents::new();
    let (entries, files) = layer_of(&mut contents);
    let plain = layer_image(&entries).unwrap();
    for threshold in [0, 64, 4000, -1] {
        let (image, w) = written(&entries, &contents, threshold);
        if threshold == 0 {
            assert!(image == plain.image && w.index == plain.index && w.extents.is_empty());
        }
        let layer = Layer::open(Box::new(image.clone())).unwrap();
        let mut held_digests = std::collections::BTreeSet::new();
        for (name, data) in &files {
            let n = nid(&layer, name);
            let size = if name == "d/link" { 65 } else { data.len() };
            let holds = held_at(threshold, size) && threshold != 0;
            match layer.read_held(n, 0, usize::MAX) {
                Some(got) => {
                    let got = got.unwrap();
                    assert!(holds, "{name} is held with {threshold}");
                    assert!(got == *data, "{name} with {threshold}");
                    held_digests.insert(
                        Digest::parse_fsverity(&velarx_storage::fsverity_digest_of(
                            Algorithm::Sha256,
                            data,
                        ))
                        .unwrap(),
                    );
                    // (no stub: no redirect, no digest)
                    assert_eq!(layer.content(n).unwrap().0, None, "{name}");
                    assert!(layer
                        .raw_xattrs(n)
                        .iter()
                        .all(|(k, _)| !k.starts_with(b"trusted.overlay")));
                }
                None => {
                    assert!(!holds, "{name} is not held with {threshold}");
                    assert!(layer.content(n).unwrap().0.is_some(), "{name}");
                }
            }
        }
        // the extents: one per digest, where the bytes are
        assert_eq!(w.extents.len(), held_digests.len(), "{threshold}");
        for e in &w.extents {
            let at = e.offset as usize;
            let want = std::fs::read(&contents.paths[&e.digest]).unwrap();
            assert_eq!(e.size as usize, want.len());
            assert!(
                image[at..at + want.len()] == want[..],
                "{threshold}: {}",
                e.digest
            );
        }
        // a file under a block that fits is after its inode, the others in
        // blocks of their own
        for e in &w.extents {
            if e.size >= 4096 {
                assert_eq!(e.offset % 4096, 0, "{threshold}: {}", e.size);
            }
        }
        // the stubs are the index of the layer: no more
        let stubs: std::collections::BTreeSet<_> = files
            .iter()
            .filter(|(n, d)| {
                let size = if n == "d/link" { 65 } else { d.len() };
                !(held_at(threshold, size) && threshold != 0)
            })
            .map(|(_, d)| velarx_storage::fsverity_digest_of(Algorithm::Sha256, d))
            .collect();
        let index = crate::erofs_tree::Index::from_bytes(Box::new(w.index)).unwrap();
        assert_eq!(index.count(), stubs.len(), "{threshold}");
        // (a layer of stubs only is chunk based, one of files of its own
        // is not)
        let chunked = u32::from_le_bytes(image[1024 + 80..1024 + 84].try_into().unwrap()) & 4;
        assert_eq!(chunked != 0, !stubs.is_empty(), "{threshold}");
    }
}

/// An image written in order is the one in memory, and what the hash of
/// the file sees is the bytes of the image.
#[test]
fn an_image_written_to_a_hash_is_the_image_in_memory() {
    let mut contents = Contents::new();
    let (entries, _) = layer_of(&mut contents);
    let (image, _) = written(&entries, &contents, -1);
    let open = |d: &Digest| contents.open(d);
    let mut hash = Hashing(VerityHasher::new(Algorithm::Sha256));
    write_layer_image(
        &entries,
        &Inline {
            threshold: -1,
            open: &open,
        },
        &mut hash,
    )
    .unwrap();
    assert_eq!(
        hash.0.finish(),
        velarx_storage::fsverity_digest_of(Algorithm::Sha256, &image)
    );
}

/// The image is a good EROFS one, with the content of the files it holds,
/// for erofs-utils where it is installed.  (Mounted by the kernel, which
/// takes a mount as root, the same image: `VELARX_EROFS_SAMPLE` leaves it
/// where it can be.)
#[test]
fn fsck_erofs_extracts_the_files_the_image_holds() {
    let mut contents = Contents::new();
    let (entries, files) = layer_of(&mut contents);
    let (image, _) = written(&entries, &contents, -1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layer.erofs");
    std::fs::write(&path, &image).unwrap();
    if let Some(keep) = std::env::var_os("VELARX_EROFS_SAMPLE_HELD") {
        std::fs::write(keep, &image).unwrap();
    }
    let out_dir = dir.path().join("out");
    let out = match std::process::Command::new("fsck.erofs")
        .arg(format!("--extract={}", out_dir.display()))
        .arg(&path)
        .output()
    {
        Ok(o) => o,
        Err(_) => return eprintln!("skipped: no fsck.erofs"),
    };
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for (name, data) in &files {
        assert!(
            std::fs::read(out_dir.join(name)).unwrap() == *data,
            "{name}"
        );
    }
}

/// A file that cannot be read, or has fewer bytes than the table says, is
/// an error that names it; the same layer without holding it is made.
#[test]
fn a_file_that_is_not_what_the_table_says_is_an_error() {
    let mut contents = Contents::new();
    let data = bytes(1, 100);
    let entries = vec![contents.file("f", &data)];
    let digest = entries[0].fsverity.unwrap();
    let missing = |_: &Digest| Err(std::io::ErrorKind::NotFound.into());
    let e = write_layer_image(
        &entries,
        &Inline {
            threshold: -1,
            open: &missing,
        },
        std::io::sink(),
    )
    .err()
    .unwrap();
    assert!(e.contains(&digest.to_string()), "{e}");
    std::fs::write(&contents.paths[&digest], &data[..60]).unwrap();
    let open = |d: &Digest| contents.open(d);
    let e = write_layer_image(
        &entries,
        &Inline {
            threshold: -1,
            open: &open,
        },
        std::io::sink(),
    )
    .err()
    .unwrap();
    assert!(e.contains("has 60 bytes, its table says 100"), "{e}");
    assert!(write_layer_image(&entries, &Inline::NONE, std::io::sink()).is_ok());
}

/// An image cut short, or with the place of a file changed, has no content
/// for it, and no panic.
#[test]
fn a_held_file_that_is_not_in_its_image_is_none() {
    let mut contents = Contents::new();
    let (entries, files) = layer_of(&mut contents);
    let (image, _) = written(&entries, &contents, -1);
    let whole = Layer::open(Box::new(image.clone())).unwrap();
    let last = files.iter().find(|(n, _)| n == "d/f9000").unwrap();
    assert!(whole.read_held(nid(&whole, &last.0), 0, 1).is_some());
    for cut in [image.len() - 4096, image.len() / 2] {
        let layer = Layer::open(Box::new(image[..cut].to_vec())).unwrap();
        for (name, _) in &files {
            if let Some(n) = layer.lookup(nid(&layer, "d"), &name.as_bytes()[2..]) {
                let _ = layer.read_held(n, 0, usize::MAX);
            }
        }
        assert!(layer.read_held(nid(&layer, &last.0), 0, 1).is_none());
    }
}

/// A file the image holds is read from the image file, from any offset,
/// and an image file cut short after it was mapped (an NFS server that
/// fails) is an error of the read, not a fault in the mapping.
#[test]
fn a_held_file_is_read_from_the_image_file() {
    let mut contents = Contents::new();
    let (entries, files) = layer_of(&mut contents);
    let (image, w) = written(&entries, &contents, -1);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layer.erofs");
    std::fs::write(&path, &image).unwrap();
    let layer = Layer::map(&path).unwrap();
    for (name, data) in &files {
        let n = nid(&layer, name);
        for (at, len) in [
            (0, usize::MAX),
            (1, 7),
            (data.len() / 2, 4096),
            (data.len(), 1),
        ] {
            let got = layer.read_held(n, at as u64, len).unwrap().unwrap();
            let want = &data[at.min(data.len())..at.saturating_add(len).min(data.len())];
            assert!(got == want, "{name} at {at}");
        }
    }
    // (the inodes are before the blocks of data: they stay)
    let big = nid(&layer, "d/f3145728");
    let at = w.extents.iter().find(|e| e.size == 3 << 20).unwrap().offset;
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(at + 4096)
        .unwrap();
    assert!(layer.read_held(big, 8192, 4096).unwrap().is_err());
}

/// What the writer needs of memory when the image is huge: the resident
/// memory it adds at its peak, in bytes.
fn peak_added(write: impl FnOnce()) -> u64 {
    let field = |name: &str| -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let line = status.lines().find(|l| l.starts_with(name)).unwrap();
        line.split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u64>()
            .unwrap()
            << 10
    };
    // (the peak starts again from what is resident now)
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
    let before = field("VmRSS:");
    write();
    field("VmHWM:").saturating_sub(before)
}

/// Counts what it is given.
#[derive(Default)]
struct Count(u64);

impl Write for Count {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 += b.len() as u64;
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// An image of 4 GiB of files it holds is written with a memory that does
/// not depend on it: the content passes through, a buffer at a time.  (The
/// files are sparse: the test needs no disk.)
#[test]
fn an_image_of_gigabytes_is_written_in_a_few_megabytes() {
    velarx_base::testing::in_child(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sparse");
        let size = 64u64 << 20;
        std::fs::File::create(&path).unwrap().set_len(size).unwrap();
        let entries: Vec<TocEntry> = (0..64u8)
            .map(|i| {
                let mut e = crate::dir_entry(&format!("f{i}"));
                e.entry_type = TocEntryType::Reg;
                e.size = size;
                e.fsverity = Some(
                    Digest::parse_fsverity(&format!(
                        "fsverity-sha256-12:{}",
                        format!("{i:02x}").repeat(32)
                    ))
                    .unwrap(),
                );
                e
            })
            .collect();
        let open = |_: &Digest| std::fs::File::open(&path);
        let mut count = Count::default();
        let added = peak_added(|| {
            write_layer_image(
                &entries,
                &Inline {
                    threshold: -1,
                    open: &open,
                },
                &mut count,
            )
            .unwrap();
        });
        assert!(count.0 >= 64 * size, "{}", count.0);
        assert!(added < 16 << 20, "the writer added {added} bytes");
    });
}

/// An image of very many small files is written with memory for its tree,
/// under a KiB a file, not for their content: held, each in a block of
/// its own (-1), or stubs, each with its overlay attributes (0).
#[test]
fn an_image_of_very_many_small_files_is_written_with_its_tree_alone() {
    const FILES: u32 = 200_000;
    for threshold in [-1, 0] {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("small");
            std::fs::File::create(&path).unwrap().set_len(3000).unwrap();
            let entries: Vec<TocEntry> = (0..FILES)
                .map(|i| {
                    let mut e = crate::dir_entry(&format!("d{}/f{i}", i % 100));
                    e.entry_type = TocEntryType::Reg;
                    e.size = 3000;
                    let mut raw = [0u8; 32];
                    raw[..4].copy_from_slice(&i.to_le_bytes());
                    e.fsverity = Some(Digest::fsverity(Algorithm::Sha256, &raw).unwrap());
                    e
                })
                .collect();
            let open = |_: &Digest| std::fs::File::open(&path);
            let mut count = Count::default();
            let added = peak_added(|| {
                write_layer_image(
                    &entries,
                    &Inline {
                        threshold,
                        open: &open,
                    },
                    &mut count,
                )
                .unwrap();
            });
            if threshold < 0 {
                // (a block each)
                assert!(count.0 >= u64::from(FILES) * 4096, "{}", count.0);
            }
            assert!(
                added < u64::from(FILES) << 10,
                "{threshold}: the writer added {added} for {FILES} files"
            );
        });
    }
}
