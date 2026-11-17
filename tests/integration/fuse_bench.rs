// SPDX-License-Identifier: Apache-2.0
//! Throughput of the file system of the images of the layers: a large file read
//! sequentially, by one reader and by four on disjoint ranges, and the
//! whole tree of small files read by one and by eight readers (a parallel
//! find and cat).  Ignored by default; run it with the release build:
//!
//!     FUSE_BENCH_DIR=/var/tmp/x cargo test --release --test integration -- --ignored --nocapture fuse_bench::
//!
//! Each case mounts the image again (a detached mount, as the image server
//! makes it: as root, or in `unshare -Urm`), so the kernel's cache of the
//! FUSE files is cold (the store's files are in the page cache).  "translated"
//! is the mount of a container with a user namespace (its files are always
//! served by the daemon), "plain" may use FUSE passthrough where the
//! process may (root).  Each case runs three times, the best is shown.
//! FUSE_BENCH_KEEP=1 keeps the store for the next run.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use velarx_fuse::{IdTranslate, ImageMounts};
use velarx_storage::{FileStore, Toc, TocEntry, TocEntryType};
use velarx_wire::request::IdMapping;

const BIG: usize = 512 << 20;
const SMALL_FILES: usize = 20_000;
const DIRS: usize = 200;

fn entry(name: &str, t: TocEntryType) -> TocEntry {
    let mut e: TocEntry = serde_json::from_value(serde_json::json!({
        "name": name, "type": "reg", "mode": 0o644
    }))
    .unwrap();
    e.entry_type = t;
    e
}

/// Bytes that do not compress or deduplicate.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// The file in the store, and its fs-verity digest as a TOC has it.
fn put(store: &FileStore, data: &[u8]) -> Option<String> {
    velarx_storage::to_toc(
        &store
            .put(velarx_types::digest::Algorithm::Sha256, data)
            .unwrap(),
    )
}

fn image(store: &FileStore) -> Toc {
    let mut entries = Vec::new();
    let mut big = entry("big", TocEntryType::Reg);
    big.fsverity = put(store, &noise(1, BIG));
    big.size = BIG as u64;
    entries.push(big);
    for d in 0..DIRS {
        let mut dir = entry(&format!("d{d:03}"), TocEntryType::Dir);
        dir.mode = 0o755;
        entries.push(dir);
    }
    for f in 0..SMALL_FILES {
        let size = 1024 + (f * 7919) % (32 * 1024);
        let data = noise(f as u64 + 2, size);
        let mut e = entry(&format!("d{:03}/f{f:05}", f % DIRS), TocEntryType::Reg);
        e.fsverity = put(store, &data);
        e.size = size as u64;
        entries.push(e);
    }
    Toc {
        version: 1,
        entries,
        tar_split_digest: None,
    }
}

/// Read `path` from `start` for `len` bytes (to its end if more).
fn read_range(path: &Path, start: u64, len: u64) -> u64 {
    use std::os::unix::fs::FileExt;
    let f = std::fs::File::open(path).unwrap();
    let mut buf = vec![0u8; 1 << 20];
    let mut done = 0u64;
    while done < len {
        let want = buf.len().min((len - done) as usize);
        let n = f.read_at(&mut buf[..want], start + done).unwrap();
        if n == 0 {
            break;
        }
        done += n as u64;
    }
    done
}

fn mb_s(bytes: u64, secs: f64) -> String {
    format!("{:8.1} MB/s", bytes as f64 / secs / 1e6)
}

fn files_of(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let t = e.file_type().unwrap();
            if t.is_dir() {
                todo.push(e.path());
            } else if t.is_file() && e.file_name() != "big" {
                out.push(e.path());
            }
        }
    }
    out
}

/// find and cat with `readers` threads: files, bytes, seconds.
fn find_cat(root: &Path, readers: usize) -> (usize, u64, f64) {
    let start = Instant::now();
    let files = Arc::new(files_of(root));
    let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let threads: Vec<_> = (0..readers)
        .map(|_| {
            let (files, next) = (files.clone(), next.clone());
            std::thread::spawn(move || {
                let mut bytes = 0u64;
                let mut buf = Vec::new();
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(p) = files.get(i) else { break };
                    buf.clear();
                    bytes += std::fs::File::open(p)
                        .unwrap()
                        .read_to_end(&mut buf)
                        .unwrap() as u64;
                }
                bytes
            })
        })
        .collect();
    let bytes = threads.into_iter().map(|t| t.join().unwrap()).sum();
    (files.len(), bytes, start.elapsed().as_secs_f64())
}

#[test]
#[ignore = "a benchmark: set FUSE_BENCH_DIR"]
fn fuse_bench() {
    let dir = PathBuf::from(std::env::var("FUSE_BENCH_DIR").expect("set FUSE_BENCH_DIR"));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(FileStore::new(dir.join("files")).unwrap());
    let t = Instant::now();
    let toc = image(&store);
    eprintln!("store ready in {:.1}s", t.elapsed().as_secs_f64());
    let layers = [("l0".to_string(), toc)];
    let translate = IdTranslate {
        uid: vec![IdMapping {
            container_id: 0,
            host_id: 100_000,
            size: 65536,
        }],
        gid: vec![IdMapping {
            container_id: 0,
            host_id: 100_000,
            size: 65536,
        }],
        squash: false,
    };
    let modes: [(&str, Option<&IdTranslate>); 2] =
        [("translated", Some(&translate)), ("plain", None)];
    for (name, tr) in modes {
        let fresh = || {
            let mounts = ImageMounts::new(store.clone());
            let built = velarx_fuse::layer_erofs::layer_image(&layers[0].1.entries).unwrap();
            let tree = velarx_fuse::erofs_tree::Layers::new(
                vec![velarx_fuse::erofs_tree::Layer::open(Box::new(built.image)).unwrap()],
                None,
                false,
                velarx_fuse::erofs_tree::Stubs::Every,
            );
            let mount = mounts
                .mount_tree_detached(Arc::new(tree), vec![layers[0].0.clone()], built.owners, tr)
                .unwrap();
            let path = PathBuf::from(format!(
                "/proc/self/fd/{}/layer1",
                std::os::fd::AsRawFd::as_raw_fd(&mount)
            ));
            (mounts, mount, path)
        };
        let best = |f: &dyn Fn() -> (u64, f64)| {
            (0..3)
                .map(|_| f())
                .max_by(|a, b| (a.0 as f64 / a.1).total_cmp(&(b.0 as f64 / b.1)))
                .unwrap()
        };
        let (n, secs) = best(&|| {
            let (m, mount, p) = fresh();
            let s = Instant::now();
            let n = read_range(&p.join("big"), 0, BIG as u64);
            let r = (n, s.elapsed().as_secs_f64());
            drop(mount);
            m.wait_detached();
            r
        });
        eprintln!("{name:10} sequential read, 1 reader   {}", mb_s(n, secs));
        let (n, secs) = best(&|| {
            let (m, mount, p) = fresh();
            let s = Instant::now();
            let quarter = (BIG / 4) as u64;
            let threads: Vec<_> = (0..4)
                .map(|i| {
                    let big = p.join("big");
                    std::thread::spawn(move || read_range(&big, i * quarter, quarter))
                })
                .collect();
            let n: u64 = threads.into_iter().map(|t| t.join().unwrap()).sum();
            let r = (n, s.elapsed().as_secs_f64());
            drop(mount);
            m.wait_detached();
            r
        });
        eprintln!("{name:10} sequential read, 4 readers  {}", mb_s(n, secs));
        for readers in [1, 8] {
            let (bytes, secs) = best(&|| {
                let (m, mount, p) = fresh();
                let (_, bytes, secs) = find_cat(&p, readers);
                drop(mount);
                m.wait_detached();
                (bytes, secs)
            });
            eprintln!(
                "{name:10} find+cat, {readers} readers       {} ({SMALL_FILES} files in {secs:.2}s, {:.0} files/s)",
                mb_s(bytes, secs),
                SMALL_FILES as f64 / secs
            );
        }
    }
    if std::env::var_os("FUSE_BENCH_KEEP").is_none() {
        let _ = std::fs::remove_dir_all(&dir);
    }
}
