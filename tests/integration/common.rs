// SPDX-License-Identifier: Apache-2.0
//! An in-process registry that serves and accepts synthetic layers, and
//! the services that pull from it.

#![allow(dead_code)]

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::Router;
use base64::Engine;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use velarx_config::PullConfig;
use velarx_content::layer::writer::{write_canonical_layer, Compression};
use velarx_core::services::ImageService;
use velarx_db::Database;
use velarx_registry::config::RegistriesConfig;
use velarx_registry::target::Resolver;
use velarx_registry::target::TransportConfig;
use velarx_registry::AuthConfig;
use velarx_storage::{canonical, FileStore, TocEntry, TocEntryType};
pub use velarx_types::digest::{Algorithm, Digest};

pub fn sha(data: &[u8]) -> Digest {
    Digest::of(Algorithm::Sha256, data)
}

/// The id of a file of the store: the fs-verity digest of its content.
pub fn vid(data: &[u8]) -> String {
    velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, data)
}

pub fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn frame(data: &[u8]) -> Vec<u8> {
    zstd::encode_all(data, 3).unwrap()
}

pub fn skippable(len: usize) -> Vec<u8> {
    let mut v = 0x184D2A50u32.to_le_bytes().to_vec();
    v.extend((len as u32).to_le_bytes());
    v
}

pub enum Item {
    Dir(&'static str),
    File {
        name: &'static str,
        data: Vec<u8>,
        chunk: usize,
    },
    Symlink(&'static str, &'static str),
}

#[derive(Clone)]
pub struct Built {
    pub blob: Vec<u8>,
    pub diff_id: Digest,
    pub annotations: HashMap<String, String>,
}

/// The layer of the store whose blob is `blob` (the test pulled that blob
/// by one route); the layer of the blob when there is none.
pub async fn stored_key(db: &Database, blob: &Digest) -> velarx_db::LayerKey {
    db.list_layers()
        .await
        .unwrap()
        .into_iter()
        .filter(|l| l.blob.as_ref() == Some(blob))
        .map(|l| l.key)
        .min()
        .unwrap_or(velarx_db::LayerKey::Whole(*blob))
}

impl Built {
    /// The names a store announces the layer by: its key and its blob, sorted.
    pub fn announced_names(&self) -> Vec<String> {
        let mut names = vec![self.key().to_string(), self.whole().to_string()];
        names.sort();
        names.dedup();
        names
    }

    /// The layer of the store a pull of it as a zstd layer makes, as the
    /// pull keys it: by the table its annotations name, or by its blob.
    pub fn key(&self) -> velarx_db::LayerKey {
        velarx_db::LayerKey::expected(&velarx_types::OciDescriptor {
            media_type: ZSTD.into(),
            digest: sha(&self.blob),
            size: self.blob.len() as i64,
            annotations: self.annotations.clone(),
        })
    }

    /// The layer of the store a pull of the whole blob makes.
    pub fn whole(&self) -> velarx_db::LayerKey {
        velarx_db::LayerKey::Whole(sha(&self.blob))
    }
}

/// A zstd:chunked layer: frames for the headers, the chunks and the zero
/// padding, then the TOC and the tar-split in skippable frames.
/// A zstd:chunked layer as velarx writes them: the TOC gives the
/// fs-verity digest of each file.
pub fn build_chunked(items: &[Item]) -> Built {
    build_chunked_verity(items, &|_, d| Some(toc_verity(d)))
}

/// A zstd:chunked layer whose TOC gives only the sha256 of the files, as
/// containers/storage writes them.
pub fn build_chunked_plain(items: &[Item]) -> Built {
    build_chunked_verity(items, &|_, _| None)
}

/// The fs-verity digest of `data` as a TOC gives it.
pub fn toc_verity(data: &[u8]) -> String {
    velarx_storage::toc_value(
        &velarx_storage::to_toc(&velarx_storage::fsverity_digest_of(
            velarx_types::digest::Algorithm::Sha256,
            data,
        ))
        .unwrap(),
    )
}

/// [`build_chunked`], the files with the `fsverity` digest `verity` gives
/// for their name and content.
pub fn build_chunked_verity(
    items: &[Item],
    verity: &dyn Fn(&str, &[u8]) -> Option<String>,
) -> Built {
    build_chunked_bloated(items, verity, 0)
}

/// [`build_chunked_verity`] with `extra` directories in the TOC that the
/// layer does not have: a TOC that inflates to many entries.
pub fn build_chunked_bloated(
    items: &[Item],
    verity: &dyn Fn(&str, &[u8]) -> Option<String>,
    extra: usize,
) -> Built {
    let mut tar = Vec::new();
    let mut blob = Vec::new();
    let mut toc = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    let mut segment: Vec<u8> = Vec::new();
    let mut position = 0;
    let flush = |segment: &mut Vec<u8>, lines: &mut Vec<String>, position: &mut i32| {
        if !segment.is_empty() {
            lines.push(format!(
                "{{\"type\":2,\"payload\":\"{}\",\"position\":{}}}",
                b64(segment),
                position
            ));
            *position += 1;
            segment.clear();
        }
    };
    for item in items {
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o644);
        h.set_mtime(1_700_000_000);
        h.set_uid(0);
        h.set_gid(0);
        match item {
            Item::Dir(name) => {
                h.set_entry_type(tar::EntryType::Directory);
                h.set_size(0);
                h.set_mode(0o755);
                h.set_path(name).unwrap();
                h.set_cksum();
                tar.extend(h.as_bytes());
                blob.extend(frame(h.as_bytes()));
                segment.extend(h.as_bytes());
                toc.push(serde_json::json!({"type":"dir","name":name.trim_end_matches('/'),"mode":0o755,"modtime":"2023-11-14T22:13:20Z"}));
            }
            Item::Symlink(name, target) => {
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_size(0);
                h.set_path(name).unwrap();
                h.set_link_name(target).unwrap();
                h.set_cksum();
                tar.extend(h.as_bytes());
                blob.extend(frame(h.as_bytes()));
                segment.extend(h.as_bytes());
                toc.push(serde_json::json!({"type":"symlink","name":name,"linkName":target,"mode":0o644,"modtime":"2023-11-14T22:13:20Z"}));
            }
            Item::File { name, data, chunk } => {
                h.set_entry_type(tar::EntryType::Regular);
                h.set_size(data.len() as u64);
                h.set_path(name).unwrap();
                h.set_cksum();
                tar.extend(h.as_bytes());
                blob.extend(frame(h.as_bytes()));
                segment.extend(h.as_bytes());
                if data.is_empty() {
                    toc.push(serde_json::json!({"type":"reg","name":name,"mode":0o644,"size":0,"digest":sha(b""),"modtime":"2023-11-14T22:13:20Z"}));
                    continue;
                }
                let start = blob.len();
                let mut chunks = Vec::new();
                let mut off = 0;
                for c in data.chunks(*chunk) {
                    let at = blob.len();
                    blob.extend(frame(c));
                    let zeros = c.iter().all(|&b| b == 0);
                    chunks.push((off, c.len(), sha(c), at, zeros));
                    off += c.len();
                }
                let end = blob.len();
                let mut first = serde_json::json!({
                    "type":"reg","name":name,"mode":0o644,"size":data.len(),"digest":sha(data),"modtime":"2023-11-14T22:13:20Z",
                    "offset":start,"endOffset":end,"chunkSize":chunks[0].1,"chunkDigest":chunks[0].2
                });
                if chunks[0].4 {
                    first["chunkType"] = "zeros".into();
                }
                if let Some(v) = verity(name, data) {
                    first["fsverity"] = v.into();
                }
                toc.push(first);
                for (off, len, d, at, zeros) in &chunks[1..] {
                    let mut c = serde_json::json!({
                        "type":"chunk","name":name,"offset":at,"chunkSize":len,"chunkOffset":off,"chunkDigest":d
                    });
                    if *zeros {
                        c["chunkType"] = "zeros".into();
                    }
                    toc.push(c);
                }
                tar.extend(data);
                let pad = (512 - data.len() % 512) % 512;
                tar.extend(vec![0u8; pad]);
                if pad > 0 {
                    blob.extend(frame(&vec![0u8; pad]));
                }
                flush(&mut segment, &mut lines, &mut position);
                lines.push(format!(
                    "{{\"type\":1,\"name_raw\":\"{}\",\"size\":{},\"payload\":\"{}\",\"position\":{}}}",
                    b64(name.as_bytes()),
                    data.len(),
                    b64(&[0u8; 8]),
                    position
                ));
                position += 1;
                segment.extend(vec![0u8; pad]);
            }
        }
    }
    tar.extend(vec![0u8; 1024]);
    segment.extend(vec![0u8; 1024]);
    blob.extend(frame(&[0u8; 1024]));
    flush(&mut segment, &mut lines, &mut position);

    let toc_json = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "entries": toc,
        "tarSplitDigest": "PLACEHOLDER"
    }))
    .unwrap();
    let ts_z = frame((lines.join("\n") + "\n").as_bytes());
    let mut toc_json = String::from_utf8(toc_json)
        .unwrap()
        .replace("PLACEHOLDER", &sha(&ts_z).to_string());
    if extra > 0 {
        let at = toc_json.find("],\"tarSplitDigest\"").unwrap();
        let mut bloat = String::with_capacity(extra * 40);
        for i in 0..extra {
            bloat.push_str(&format!(",{{\"type\":\"dir\",\"name\":\"b/{i:08}\"}}"));
        }
        toc_json.insert_str(at, &bloat);
    }
    let toc_z = frame(toc_json.as_bytes());
    blob.extend(skippable(toc_z.len()));
    let toc_off = blob.len();
    blob.extend(&toc_z);
    blob.extend(skippable(ts_z.len()));
    let ts_off = blob.len();
    blob.extend(&ts_z);

    let p = "io.github.containers.zstd-chunked.";
    let annotations = HashMap::from([
        (
            format!("{p}manifest-position"),
            format!("{toc_off}:{}:{}:1", toc_z.len(), toc_json.len()),
        ),
        (format!("{p}manifest-checksum"), sha(&toc_z).to_string()),
        (
            format!("{p}tarsplit-position"),
            format!("{ts_off}:{}:{}", ts_z.len(), lines.join("\n").len() + 1),
        ),
    ]);
    Built {
        diff_id: sha(&tar),
        blob,
        annotations,
    }
}

/// `layer` with the table of contents `edit` makes of its own (the manifest
/// vouches for the new one): what the tar stream and the tar-split of the
/// layer say is not changed.
pub fn with_toc(layer: &Built, edit: impl FnOnce(&mut serde_json::Value)) -> Built {
    let p = "io.github.containers.zstd-chunked.";
    let numbers = |name: &str| -> Vec<usize> {
        layer.annotations[&format!("{p}{name}")]
            .split(':')
            .map(|x| x.parse().unwrap())
            .collect()
    };
    let pos = numbers("manifest-position");
    let toc = zstd::decode_all(&layer.blob[pos[0]..pos[0] + pos[1]]).unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(&toc).unwrap();
    edit(&mut json);
    let json = serde_json::to_vec(&json).unwrap();
    let toc_z = frame(&json);
    let mut blob = layer.blob[..pos[0]].to_vec();
    let header = skippable(toc_z.len());
    let at = pos[0] - header.len();
    blob[at..pos[0]].copy_from_slice(&header);
    blob.extend(&toc_z);
    blob.extend(&layer.blob[pos[0] + pos[1]..]);
    let shift = toc_z.len() as i64 - pos[1] as i64;
    let ts = numbers("tarsplit-position");
    let mut annotations = layer.annotations.clone();
    annotations.insert(
        format!("{p}tarsplit-position"),
        format!("{}:{}:{}", ts[0] as i64 + shift, ts[1], ts[2]),
    );
    annotations.insert(
        format!("{p}manifest-position"),
        format!("{}:{}:{}:1", pos[0], toc_z.len(), json.len()),
    );
    annotations.insert(format!("{p}manifest-checksum"), sha(&toc_z).to_string());
    Built {
        blob,
        diff_id: layer.diff_id,
        annotations,
    }
}

pub fn tar_of(items: &[Item]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for item in items {
        match item {
            Item::Dir(n) => {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Directory);
                h.set_mode(0o755);
                h.set_size(0);
                b.append_data(&mut h, n, std::io::empty()).unwrap();
            }
            Item::File { name, data, .. } => {
                let mut h = tar::Header::new_gnu();
                h.set_mode(0o644);
                h.set_size(data.len() as u64);
                b.append_data(&mut h, name, &data[..]).unwrap();
            }
            Item::Symlink(n, t) => {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_size(0);
                b.append_link(&mut h, n, t).unwrap();
            }
        }
    }
    b.into_inner().unwrap()
}

pub fn build_gzip(items: &[Item]) -> Built {
    let tar = tar_of(items);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar).unwrap();
    Built {
        diff_id: sha(&tar),
        blob: gz.finish().unwrap(),
        annotations: HashMap::new(),
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum RangeMode {
    Normal,
    /// The server answers 200 with the whole blob.
    Ignore,
    /// The server refuses more than one range.
    SingleOnly,
    /// The server answers ranges with other bytes than the ones requested.
    Lie,
    /// The server refuses any request for a range (416): a blob is only
    /// served whole.
    Refuse,
    /// The server answers 206 with the bytes of the first range and no
    /// `Content-Range`.
    NoContentRange,
}

pub struct Registry {
    /// The requests that came on a connection of this process (the daemon
    /// under test), not of a worker.
    pub mine: AtomicUsize,
    pub blobs: Mutex<HashMap<String, Vec<u8>>>,
    pub mode: Mutex<RangeMode>,
    pub requests: AtomicUsize,
    pub ranged: AtomicUsize,
    /// The blobs each repository other than `test` holds (`test` holds
    /// everything that was published).
    pub repos: Mutex<HashMap<String, HashSet<String>>>,
    pub uploads: Mutex<HashMap<String, Vec<u8>>>,
    /// `METHOD path` of the upload and manifest requests.
    pub log: Mutex<Vec<String>>,
    pub manifest_types: Mutex<HashMap<String, String>>,
    /// Milliseconds a blob request waits before it is answered.
    pub delay_ms: AtomicU64,
    /// A blob request waits until this many have arrived (0: no wait), for
    /// at most [`RENDEZVOUS_LIMIT`]
    pub rendezvous: AtomicUsize,
    /// How many blob requests arrived
    pub arrived: tokio::sync::watch::Sender<usize>,
    /// Whether a request of the rendezvous gave up waiting for the others
    pub apart: std::sync::atomic::AtomicBool,
    /// Requests for each blob.
    pub hits: Mutex<HashMap<Digest, usize>>,
    /// The `Range` of each range request.
    pub range_log: Mutex<Vec<String>>,
    /// Range answers cut short after half of their body, from now on.
    pub cut: AtomicUsize,
    /// Milliseconds between the bytes of a whole blob (0: all at once).
    pub trickle_ms: AtomicU64,
    /// Bytes of blob bodies the server has handed to the connections.
    pub served: AtomicU64,
    /// A blob (by its digest) that is not served as it is when it is sent
    /// whole.
    pub tamper: Mutex<Option<(String, Tamper)>>,
}

/// What a server does to the body of a blob it sends whole.
pub enum Tamper {
    /// Zeros after the end of the blob
    Append(usize),
    /// Half of the blob
    Cut,
    /// A byte of the blob changed
    Flip,
}

impl Registry {
    pub fn has(&self, repo: &str, digest: &impl std::fmt::Display) -> bool {
        let digest = digest.to_string();
        if repo == "test" {
            return self.blobs.lock().unwrap().contains_key(&digest);
        }
        self.repos
            .lock()
            .unwrap()
            .get(repo)
            .is_some_and(|r| r.contains(&digest))
    }

    pub fn logged(&self, prefix: &str) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with(prefix))
            .count()
    }
}

pub fn parse_ranges(h: &str, len: usize) -> Option<Vec<(usize, usize)>> {
    let list = h.strip_prefix("bytes=")?;
    let mut out = Vec::new();
    for r in list.split(',') {
        let (a, b) = r.split_once('-')?;
        let (a, b): (usize, usize) = (a.parse().ok()?, b.parse().ok()?);
        if a > b || b >= len {
            return None;
        }
        out.push((a, b));
    }
    Some(out)
}

/// Until a task of this process is asleep in `flock(2)` on the file `lock`
/// (`velarx_base::testing::lock_has_waiter`, from `/proc/locks`): the proof
/// that it reached its blocking point, which a timer only guesses.  There is
/// no event for it, so it is looked at every few milliseconds, with a limit
/// that fails the test and says what was waited for.  Async, unlike
/// `testing::wait_lock_waiter`: the task that is to take the lock may need
/// the thread of a current-thread runtime to get there.
pub async fn wait_for_lock_waiter(lock: &std::path::Path) {
    let limit = tokio::time::Instant::now() + RENDEZVOUS_LIMIT;
    while !velarx_base::testing::lock_has_waiter(lock) {
        assert!(
            tokio::time::Instant::now() < limit,
            "nothing waits for the lock {}",
            lock.display()
        );
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
}

/// Look at `ready` until it says yes, at most [`RENDEZVOUS_LIMIT`]: for a
/// state that nothing announces (a row of the database).  Fails the test
/// with `what` when it never comes.
pub async fn poll_until<F, Fut>(what: &str, mut ready: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let limit = tokio::time::Instant::now() + RENDEZVOUS_LIMIT;
    while !ready().await {
        assert!(tokio::time::Instant::now() < limit, "never came: {what}");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

/// How long a request waits for the others of a rendezvous: only a test that
/// fails gets to it.
const RENDEZVOUS_LIMIT: std::time::Duration = std::time::Duration::from_secs(20);

/// The bytes of the answer are counted as the connection takes them.
pub async fn serve_blob(
    State(reg): State<Arc<Registry>>,
    path: axum::extract::Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    use futures::StreamExt;
    let counter = reg.clone();
    let (parts, body) = answer_blob(State(reg), path, headers).await.into_parts();
    // (in pieces: a body of one frame would be counted whole as soon as it is
    // taken, whatever the client reads of it)
    let body = body
        .into_data_stream()
        .flat_map(|chunk| {
            futures::stream::iter(match chunk {
                Ok(c) => c
                    .chunks(16 * 1024)
                    .map(|p| Ok(axum::body::Bytes::copy_from_slice(p)))
                    .collect(),
                Err(e) => vec![Err(e)],
            })
        })
        .inspect(move |chunk| {
            if let Ok(chunk) = chunk {
                counter
                    .served
                    .fetch_add(chunk.len() as u64, Ordering::SeqCst);
            }
        });
    Response::from_parts(parts, axum::body::Body::from_stream(body))
}

async fn answer_blob(
    State(reg): State<Arc<Registry>>,
    axum::extract::Path((name, digest)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    reg.requests.fetch_add(1, Ordering::SeqCst);
    if let Ok(d) = digest.parse::<Digest>() {
        *reg.hits.lock().unwrap().entry(d).or_default() += 1;
    }
    let delay = reg.delay_ms.load(Ordering::SeqCst);
    if delay > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
    }
    let together = reg.rendezvous.load(Ordering::SeqCst);
    if together > 0 {
        let mut arrived = reg.arrived.subscribe();
        reg.arrived.send_modify(|n| *n += 1);
        let met = tokio::time::timeout(RENDEZVOUS_LIMIT, arrived.wait_for(|n| *n >= together))
            .await
            .is_ok();
        if !met {
            reg.apart.store(true, Ordering::SeqCst);
        }
    }
    if !reg.has(&name, &digest) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let blobs = reg.blobs.lock().unwrap();
    let Some(blob) = blobs.get(&digest) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mode = *reg.mode.lock().unwrap();
    let range = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
    if range.is_some() && mode == RangeMode::Refuse {
        return StatusCode::RANGE_NOT_SATISFIABLE.into_response();
    }
    let (Some(range), true) = (range, mode != RangeMode::Ignore) else {
        let every = reg.trickle_ms.load(Ordering::SeqCst);
        if every > 0 {
            // a server that sends a byte now and then
            let rest = blob.clone();
            let body = futures::stream::unfold(0usize, move |at| {
                let byte = rest.get(at).copied();
                async move {
                    let byte = byte?;
                    tokio::time::sleep(std::time::Duration::from_millis(every)).await;
                    Some((Ok::<_, std::io::Error>(vec![byte]), at + 1))
                }
            });
            return axum::body::Body::from_stream(body).into_response();
        }
        let mut body = blob.clone();
        if let Some((tampered, how)) = &*reg.tamper.lock().unwrap() {
            if *tampered == digest {
                match how {
                    Tamper::Append(n) => body.resize(body.len() + n, 0),
                    Tamper::Cut => body.truncate(body.len() / 2),
                    Tamper::Flip => {
                        let middle = body.len() / 2;
                        body[middle] ^= 1;
                    }
                }
            }
        }
        return body.into_response();
    };
    reg.ranged.fetch_add(1, Ordering::SeqCst);
    reg.range_log.lock().unwrap().push(range.to_string());
    let mut cut = false;
    let mut n = reg.cut.load(Ordering::SeqCst);
    while n > 0 {
        match reg
            .cut
            .compare_exchange_weak(n, n - 1, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => {
                cut = true;
                break;
            }
            Err(seen) => n = seen,
        }
    }
    let Some(ranges) = parse_ranges(range, blob.len()) else {
        return StatusCode::RANGE_NOT_SATISFIABLE.into_response();
    };
    if ranges.len() > 1 && mode == RangeMode::SingleOnly {
        return StatusCode::RANGE_NOT_SATISFIABLE.into_response();
    }
    if mode == RangeMode::NoContentRange {
        let (a, b) = ranges[0];
        return (StatusCode::PARTIAL_CONTENT, blob[a..=b].to_vec()).into_response();
    }
    if mode == RangeMode::Lie {
        let (a, b) = ranges[0];
        let n = b - a + 1;
        let shifted = blob[blob.len() - n..].to_vec();
        return (
            StatusCode::PARTIAL_CONTENT,
            [(
                header::CONTENT_RANGE,
                format!("bytes {a}-{b}/{}", blob.len()),
            )],
            shifted,
        )
            .into_response();
    }
    if ranges.len() == 1 {
        let (a, b) = ranges[0];
        let mut body = blob[a..=b].to_vec();
        if cut {
            body.truncate(body.len() / 2);
        }
        return (
            StatusCode::PARTIAL_CONTENT,
            [(
                header::CONTENT_RANGE,
                format!("bytes {a}-{b}/{}", blob.len()),
            )],
            body,
        )
            .into_response();
    }
    let mut body = Vec::new();
    for (a, b) in ranges {
        body.extend(
            format!(
                "--SEP\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes {a}-{b}/{}\r\n\r\n",
                blob.len()
            )
            .as_bytes(),
        );
        body.extend(&blob[a..=b]);
        body.extend(b"\r\n");
    }
    body.extend(b"--SEP--\r\n");
    if cut {
        body.truncate(body.len() / 2);
    }
    (
        StatusCode::PARTIAL_CONTENT,
        [(header::CONTENT_TYPE, "multipart/byteranges; boundary=SEP")],
        body,
    )
        .into_response()
}

pub type Query = axum::extract::Query<HashMap<String, String>>;

pub async fn start_upload(
    State(reg): State<Arc<Registry>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::extract::Query(q): Query,
) -> Response {
    reg.log.lock().unwrap().push(format!(
        "POST {name} mount={} from={}",
        q.contains_key("mount"),
        q.get("from").map_or("", |f| f.as_str())
    ));
    if let (Some(digest), Some(from)) = (q.get("mount"), q.get("from")) {
        if reg.has(from, digest) {
            reg.repos
                .lock()
                .unwrap()
                .entry(name)
                .or_default()
                .insert(digest.clone());
            return StatusCode::CREATED.into_response();
        }
    }
    // (a number of its own for each upload: concurrent uploads, and one
    // started after another ended, must not share a session)
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = format!(
        "up{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    reg.uploads.lock().unwrap().insert(id.clone(), Vec::new());
    (
        StatusCode::ACCEPTED,
        [(header::LOCATION, format!("/v2/{name}/blobs/uploads/{id}"))],
    )
        .into_response()
}

pub async fn patch_upload(
    State(reg): State<Arc<Registry>>,
    axum::extract::Path((name, id)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let mut uploads = reg.uploads.lock().unwrap();
    let Some(data) = uploads.get_mut(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let start = headers
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split('-').next())
        .and_then(|v| v.parse::<usize>().ok());
    reg.log
        .lock()
        .unwrap()
        .push(format!("PATCH {name} {start:?}"));
    if start != Some(data.len()) {
        return StatusCode::RANGE_NOT_SATISFIABLE.into_response();
    }
    data.extend(&body);
    (
        StatusCode::ACCEPTED,
        [(header::LOCATION, format!("/v2/{name}/blobs/uploads/{id}"))],
    )
        .into_response()
}

pub async fn put_upload(
    State(reg): State<Arc<Registry>>,
    axum::extract::Path((name, id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(q): Query,
    body: axum::body::Bytes,
) -> Response {
    reg.log.lock().unwrap().push(format!("PUT {name}"));
    let Some(mut data) = reg.uploads.lock().unwrap().remove(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    data.extend(&body);
    let digest = sha(&data);
    if q.get("digest") != Some(&digest.to_string()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    reg.blobs.lock().unwrap().insert(digest.to_string(), data);
    reg.repos
        .lock()
        .unwrap()
        .entry(name)
        .or_default()
        .insert(digest.to_string());
    StatusCode::CREATED.into_response()
}

pub async fn put_manifest(
    State(reg): State<Arc<Registry>>,
    axum::extract::Path((name, reference)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    reg.log
        .lock()
        .unwrap()
        .push(format!("PUT-MANIFEST {name} {reference}"));
    let digest = sha(&body);
    if reference.starts_with("sha256:") && reference != digest.to_string() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let media = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.oci.image.manifest.v1+json")
        .to_string();
    let mut blobs = reg.blobs.lock().unwrap();
    blobs.insert(format!("manifest:{reference}"), body.to_vec());
    blobs.insert(format!("manifest:{digest}"), body.to_vec());
    let mut types = reg.manifest_types.lock().unwrap();
    types.insert(reference, media.clone());
    types.insert(digest.to_string(), media);
    (
        StatusCode::CREATED,
        [("docker-content-digest", digest.to_string())],
    )
        .into_response()
}

/// Let go of the `flock` of `file` before it is closed: a program that
/// another thread of the test binary starts holds a copy of the descriptor
/// until the program is executed, and the lock with it.
pub fn unlock(file: &impl std::os::fd::AsFd) {
    rustix::fs::flock(file, rustix::fs::FlockOperation::Unlock).unwrap();
}

pub async fn start_registry() -> (String, Arc<Registry>) {
    let reg = Arc::new(Registry {
        mine: AtomicUsize::new(0),
        blobs: Mutex::new(HashMap::new()),
        mode: Mutex::new(RangeMode::Normal),
        requests: AtomicUsize::new(0),
        ranged: AtomicUsize::new(0),
        repos: Mutex::new(HashMap::new()),
        uploads: Mutex::new(HashMap::new()),
        log: Mutex::new(Vec::new()),
        manifest_types: Mutex::new(HashMap::new()),
        delay_ms: AtomicU64::new(0),
        rendezvous: AtomicUsize::new(0),
        arrived: tokio::sync::watch::channel(0).0,
        apart: std::sync::atomic::AtomicBool::new(false),
        hits: Mutex::new(HashMap::new()),
        range_log: Mutex::new(Vec::new()),
        cut: AtomicUsize::new(0),
        trickle_ms: AtomicU64::new(0),
        served: AtomicU64::new(0),
        tamper: Mutex::new(None),
    });
    let app = Router::new()
        .route("/v2/", get(|| async { StatusCode::OK }))
        .route(
            "/v2/_catalog",
            get(|| async { r#"{"repositories":["test","other"]}"# }),
        )
        .route(
            "/v2/:name/tags/list",
            get(|axum::extract::Path(n): axum::extract::Path<String>| async move {
                format!(r#"{{"name":"{n}","tags":["latest","v1"]}}"#)
            }),
        )
        .route("/v2/:name/blobs/:digest", get(serve_blob))
        .route(
            "/v2/:name/manifests/:reference",
            get(
                |State(reg): State<Arc<Registry>>,
                 axum::extract::Path((_n, r)): axum::extract::Path<(String, String)>| async move {
                    reg.log.lock().unwrap().push(format!("GET-MANIFEST {r}"));
                    let blobs = reg.blobs.lock().unwrap();
                    match blobs.get(&format!("manifest:{r}")) {
                        Some(m) => (
                            [(
                                header::CONTENT_TYPE,
                                reg.manifest_types
                                    .lock()
                                    .unwrap()
                                    .get(&r)
                                    .cloned()
                                    .unwrap_or_else(|| {
                                        "application/vnd.oci.image.manifest.v1+json".to_string()
                                    }),
                            )],
                            m.clone(),
                        )
                            .into_response(),
                        None => StatusCode::NOT_FOUND.into_response(),
                    }
                },
            )
            .put(put_manifest),
        )
        .route("/v2/:name/blobs/uploads/", post(start_upload))
        .route(
            "/v2/:name/blobs/uploads/:id",
            patch(patch_upload).put(put_upload),
        )
        .layer(axum::extract::DefaultBodyLimit::disable())
        .with_state(reg.clone());
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    // (a small send buffer: what the server has handed to a connection is
    // about what the client has read of it)
    socket.set_send_buffer_size(16 * 1024).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(1024).unwrap();
    let host = listener.local_addr().unwrap().to_string();
    let port = listener.local_addr().unwrap().port();
    let watched = reg.clone();
    let app = app.layer(axum::middleware::from_fn(
        move |axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<
            std::net::SocketAddr,
        >,
              req: axum::extract::Request,
              next: axum::middleware::Next| {
            let watched = watched.clone();
            async move {
                if connection_is_mine(peer.port(), port) {
                    watched.mine.fetch_add(1, Ordering::SeqCst);
                }
                next.run(req).await
            }
        },
    ));
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    (host, reg)
}

/// The files under `dir`, by their paths, sorted.
fn files_under(dir: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut left = vec![dir.to_path_buf()];
    while let Some(d) = left.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            match e.file_type().unwrap().is_dir() {
                true => left.push(e.path()),
                false => out.push(e.path().strip_prefix(dir).unwrap().display().to_string()),
            }
        }
    }
    out.sort();
    out
}

/// What a store holds ([`Env::stored`]).
#[derive(Debug, PartialEq, Eq)]
pub struct Stored {
    objects: Vec<String>,
    rows: Vec<i64>,
    staged: usize,
    pulls: usize,
}

pub struct Env {
    pub _tmp: tempfile::TempDir,
    pub host: String,
    pub reg: Arc<Registry>,
    /// Never dropped: the service owns a runtime, which cannot be dropped
    /// from an async test.
    pub service: std::mem::ManuallyDrop<ImageService>,
    pub db: Database,
    pub store: Arc<FileStore>,
    pub staging: std::path::PathBuf,
    /// The registry fetcher process of the environment (another service on
    /// its store uses it too)
    pub origin: Arc<velarx_content::list::RegistryOrigin>,
}

pub async fn env() -> Env {
    env_with(PullConfig::default()).await
}

pub async fn env_with(pull: PullConfig) -> Env {
    env_full(pull, velarx_config::PushConfig::default()).await
}

/// An environment whose service has the `[[transports]]` `transports`.
pub async fn env_transports(transports: Vec<velarx_config::TransportConfig>) -> Env {
    let push = velarx_config::PushConfig {
        chunk_mib: 1,
        ..Default::default()
    };
    env_built(
        Database::open_in_memory().await.unwrap(),
        PullConfig::default(),
        push,
        Fetchers::default(),
        None,
        |service| service.with_transports(transports),
    )
    .await
}

pub async fn env_full(pull: PullConfig, push: velarx_config::PushConfig) -> Env {
    env_sources(pull, push, Fetchers::default()).await
}

pub async fn env_sources(
    pull: PullConfig,
    push: velarx_config::PushConfig,
    sources: Fetchers,
) -> Env {
    env_sources_over(pull, push, sources, None).await
}

/// An environment whose store has the objects of a read-only store (its
/// `objects` directory) under it.
pub async fn env_sources_over(
    pull: PullConfig,
    push: velarx_config::PushConfig,
    sources: Fetchers,
    read_only: Option<std::path::PathBuf>,
) -> Env {
    let db = Database::open_in_memory().await.unwrap();
    env_on(db, pull, push, sources, read_only).await
}

/// An environment of the database `db` (with its read-only stores), whose
/// store has the objects of a read-only store under it.
pub async fn env_on(
    db: Database,
    pull: PullConfig,
    push: velarx_config::PushConfig,
    sources: Fetchers,
    read_only: Option<std::path::PathBuf>,
) -> Env {
    env_built(db, pull, push, sources, read_only, |service| service).await
}

/// [`env_on`], with the service `built` makes of the one it made.
pub async fn env_built(
    db: Database,
    pull: PullConfig,
    push: velarx_config::PushConfig,
    sources: Fetchers,
    read_only: Option<std::path::PathBuf>,
    built: impl FnOnce(ImageService) -> ImageService,
) -> Env {
    env_built_in(None, db, pull, push, sources, read_only, built).await
}

/// [`env_built`] with the directory of the environment made in `base` (the
/// temporary directory where it is None): a test that needs a file system
/// with fs-verity.
pub async fn env_built_in(
    base: Option<&std::path::Path>,
    db: Database,
    mut pull: PullConfig,
    push: velarx_config::PushConfig,
    sources: Fetchers,
    read_only: Option<std::path::PathBuf>,
    built: impl FnOnce(ImageService) -> ImageService,
) -> Env {
    if pull.sources == PullConfig::default().sources && !sources.0.is_empty() {
        pull.sources = sources.0.iter().map(|f| f.name.clone()).collect();
        pull.sources.push("registry".into());
    }
    // The tests run in the test binary, which is not a worker: the pulls
    // need the binary that is (a test that names a worker keeps it).
    if pull.worker_path.is_none() {
        pull.worker_path = Some(registry_bin().into());
    }
    let (host, reg) = start_registry().await;
    let tmp = match base {
        Some(base) => tempfile::tempdir_in(base),
        None => tempfile::tempdir(),
    }
    .unwrap();
    // (the files of the layers are in the directory of the store)
    let db = db.with_layer_files(Arc::new(velarx_db::layer_files::Directory(
        tmp.path().to_path_buf(),
    )));
    let store = Arc::new(
        FileStore::new(tmp.path().join("objects"))
            .unwrap()
            .with_additional(read_only.into_iter().collect()),
    );
    let staging = tmp.path().join("staging");
    let origin = origin_with(tmp.path(), &conf_for(&[&host]), (&pull, &push));
    let service = built(
        ImageService::new(
            db.clone(),
            store.clone(),
            staging.clone(),
            velarx_storage::VerityMode::Off,
        )
        .unwrap()
        .with_pull_config(pull)
        .unwrap()
        .with_push_config(push)
        .with_fetchers(sources.0)
        .with_resolver(client_for(&[&host]))
        .with_origin(origin.clone()),
    );
    Env {
        _tmp: tmp,
        host,
        reg,
        service: std::mem::ManuallyDrop::new(service),
        db,
        store,
        staging,
        origin,
    }
}

impl Env {
    pub fn client(&self) -> Resolver {
        client_for(&[&self.host])
    }

    /// The registry fetcher of this environment knows `hosts` too, as plain
    /// http: before its first pull (it reads its registries.conf when it
    /// starts).
    pub fn trust(&self, hosts: &[&str]) {
        let path = self._tmp.path().join("registries.conf");
        let mut conf = std::fs::read_to_string(&path).unwrap();
        conf.push_str(&conf_for(hosts));
        std::fs::write(&path, conf).unwrap();
    }

    /// Publish an image of these layers as `<host>/test:latest`.
    pub fn publish(&self, layers: &[&Built], media: &[&str]) {
        publish_to(&self.reg, layers, media);
    }

    pub async fn pull(
        &self,
    ) -> Result<velarx_core::services::PullResult, velarx_types::ImageError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let image = format!("{}/test:latest", self.host);
        // The service has its own client: point it to this registry.
        self.service
            .pull_with_client(&self.client(), &image, tx)
            .await
    }

    /// Pull only the metadata of what can be.
    pub async fn pull_lazy(
        &self,
    ) -> Result<velarx_core::services::PullResult, velarx_types::ImageError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let image = format!("{}/test:latest", self.host);
        self.service
            .pull_lazy_with_client(&self.client(), &image, tx)
            .await
    }

    /// What a pull or a completion left in the staging directory: sessions
    /// (the pulls, `pulls`, and the EROFS images of their layers,
    /// `composefs` with the stand-in of its objects, are looked at on their
    /// own).
    pub fn staged_leftovers(&self) -> usize {
        use velarx_content::pull::staged_fetch::{LAYERS, META};
        let stand_in = self.area().objects_stand_in();
        std::fs::read_dir(&self.staging).map_or(0, |d| {
            d.flatten()
                .filter(|e| {
                    use velarx_content::pull::staged::{BOOT, COMPOSEFS, PULLS};
                    !matches!(e.file_name().to_str(), Some(PULLS | COMPOSEFS | BOOT))
                        && e.path() != stand_in
                })
                .map(|e| match e.file_name().to_str() {
                    // (the directories of the layers being staged: what is in
                    // them, but the layers a lazy pull keeps)
                    Some(LAYERS | META) => std::fs::read_dir(e.path()).map_or(0, |d| {
                        d.flatten()
                            .filter(|l| {
                                !self
                                    .staging
                                    .join(META)
                                    .join(l.file_name())
                                    .join("layer.json")
                                    .is_file()
                            })
                            .count()
                    }),
                    _ => 1,
                })
                .sum()
        })
    }

    /// What is stored: the objects, the rows of the layers, files, images
    /// and their layers, and what is staged or being pulled.
    pub async fn stored(&self) -> Stored {
        let rows = self
            .db
            .conn()
            .call(|c| {
                ["layers", "files", "images", "image_layers"]
                    .iter()
                    .map(|t| {
                        Ok(c.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))?)
                    })
                    .collect()
            })
            .await
            .unwrap();
        Stored {
            objects: files_under(&self._tmp.path().join("objects")),
            rows,
            staged: self.staged_leftovers(),
            pulls: self.area().pulls().len(),
        }
    }

    /// The staging area of lazy pulls of the store.
    pub fn area(&self) -> velarx_content::pull::staged::Staging {
        velarx_content::pull::staged::Staging::new(&self.staging)
    }

    /// The files staged in the staging directories of the layers, by
    /// fs-verity digest.
    pub fn pooled(&self) -> Vec<String> {
        let layers = self.staging.join(velarx_content::pull::staged::LAYERS);
        let mut out = Vec::new();
        for layer in std::fs::read_dir(&layers).into_iter().flatten().flatten() {
            let root = layer.path().join("files");
            for prefix in std::fs::read_dir(&root).into_iter().flatten().flatten() {
                for f in std::fs::read_dir(prefix.path())
                    .into_iter()
                    .flatten()
                    .flatten()
                {
                    if let Some(o) =
                        velarx_storage::Object::from_rel(std::path::Path::new(&format!(
                            "{}/{}",
                            prefix.file_name().to_string_lossy(),
                            f.file_name().to_string_lossy()
                        )))
                    {
                        out.push(o.verity);
                    }
                }
            }
        }
        out
    }
}

pub const ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
pub const GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

pub fn sample() -> Vec<Item> {
    let mut big = vec![7u8; 100_000];
    for (i, b) in big.iter_mut().enumerate() {
        *b = (i * 31 % 251) as u8;
    }
    // A file with a run of zeros in the middle (sparse hole chunks).
    let mut holes = vec![1u8; 4096];
    holes.extend(vec![0u8; 8192]);
    holes.extend(vec![2u8; 4096]);
    vec![
        Item::Dir("etc/"),
        Item::File {
            name: "etc/small",
            data: b"hello\n".to_vec(),
            chunk: 4096,
        },
        Item::File {
            name: "etc/copy",
            data: b"hello\n".to_vec(),
            chunk: 4096,
        },
        Item::File {
            name: "etc/empty",
            data: vec![],
            chunk: 1,
        },
        Item::File {
            name: "usr/big",
            data: big,
            chunk: 16 * 1024,
        },
        Item::File {
            name: "usr/holes",
            data: holes,
            chunk: 4096,
        },
        Item::Symlink("etc/link", "small"),
    ]
}

pub fn names(toc: &velarx_storage::Toc) -> Vec<String> {
    toc.entries
        .iter()
        .filter(|e| e.entry_type != velarx_storage::TocEntryType::Chunk)
        .map(|e| e.name.clone())
        .collect()
}

/// A layer written by the layer writer: pushing it again gives the same blob.
pub fn build_written(tar: &[u8], compression: velarx_content::layer::writer::Compression) -> Built {
    let mut blob = Vec::new();
    let w = velarx_content::layer::writer::write_layer(
        tar,
        velarx_types::digest::Algorithm::Sha256,
        compression,
        &mut blob,
    )
    .unwrap();
    Built {
        diff_id: w.diff_id,
        blob,
        annotations: w.annotations.into_iter().collect(),
    }
}

/// The registry fetcher process of a store under `dir` (its staging
/// `DIR/staging`, the only place it writes), started on the first
/// connection: `DIR/registries.conf` is `conf`, which it reads when it
/// starts (a test may add to it before its first pull), and its socket
/// is in `DIR/services`.  It leaves with its last connection.
pub fn fetcher_spawner(
    dir: &std::path::Path,
    conf: &str,
) -> (
    Arc<velarx_content::shared::SharedRegistry>,
    std::path::PathBuf,
) {
    fetcher_spawner_with(
        dir,
        &dir.join("staging"),
        conf,
        &velarx_config::Config::default(),
    )
}

/// [`fetcher_spawner`] for the staging area `staging` with the
/// configuration `config` (the `[pull]` of the service the fetcher is for),
/// as an engine hands it its own.
pub fn fetcher_spawner_with(
    dir: &std::path::Path,
    staging: &std::path::Path,
    conf: &str,
    config: &velarx_config::Config,
) -> (
    Arc<velarx_content::shared::SharedRegistry>,
    std::path::PathBuf,
) {
    let registries = dir.join("registries.conf");
    std::fs::write(&registries, conf).unwrap();
    let json = serde_json::to_vec(config).unwrap();
    let incoming = dir.join("incoming");
    velarx_base::ipc::ensure_private_dir(&incoming).unwrap();
    let config = velarx_content::pull::unnamed::read_only_unnamed(&incoming, &json).unwrap();
    // (the staging of the layers of the store: the only place the fetcher
    // writes)
    let layers = staging.join(velarx_content::pull::staged::LAYERS);
    velarx_base::ipc::ensure_private_dir(&layers).unwrap();
    let staging: std::os::fd::OwnedFd = std::fs::File::open(&layers).unwrap().into();
    let exe = std::path::Path::new(registry_bin());
    let services = dir.join("services");
    velarx_base::ipc::ensure_private_dir(&services).unwrap();
    let socket = services.join("registry.sock");
    let shared = velarx_content::shared::SharedRegistry::new(
        socket.clone(),
        services.join("fetcher.log"),
        vec![config, staging],
        {
            let (exe, registries, socket) = (exe.to_path_buf(), registries.clone(), socket.clone());
            let cache = dir.join("cache");
            // (the auth file of `login` is the test's: in this runtime directory)
            let run = dir.join("run");
            velarx_base::ipc::ensure_private_dir(&run).unwrap();
            move || {
                let mut cmd = std::process::Command::new(&exe);
                cmd.args(["--listen-fd", "3"])
                    .args(["--config-fd", "4", "--staging-fd", "5", "--shared"])
                    .arg(&socket)
                    .env("VELARX_REGISTRIES_CONF", &registries)
                    .env("XDG_RUNTIME_DIR", &run)
                    .env("XDG_CACHE_HOME", &cache);
                cmd
            }
        },
    );
    (Arc::new(shared), socket)
}

/// The registries.conf that knows `hosts` as plain http.
pub fn conf_for(hosts: &[&str]) -> String {
    hosts
        .iter()
        .map(|h| format!("[[registry]]\nlocation = \"{h}\"\ninsecure = true\n"))
        .collect()
}

pub fn client_for(hosts: &[&str]) -> Resolver {
    client_conf(&conf_for(hosts))
}

/// The registry fetcher of a service whose store is under `dir`, with the
/// registries.conf `conf` and the `[pull]` configuration `pull`: the
/// registry is reached through it, as an engine reaches it.
pub fn origin_for(
    dir: &std::path::Path,
    conf: &str,
    pull: &PullConfig,
) -> Arc<velarx_content::list::RegistryOrigin> {
    origin_with(dir, conf, (pull, &velarx_config::PushConfig::default()))
}

/// [`origin_for`] with the `[push]` configuration the fetcher serves (the
/// size of the pieces of an upload is the fetcher's).
pub fn origin_with(
    dir: &std::path::Path,
    conf: &str,
    (pull, push): (&PullConfig, &velarx_config::PushConfig),
) -> Arc<velarx_content::list::RegistryOrigin> {
    let mut config = velarx_config::Config {
        pull: pull.clone(),
        push: push.clone(),
        ..Default::default()
    };
    // (the other fetchers the engine starts, those of a `dir`, write the
    // staging of this store)
    config.storage.root = dir.to_path_buf();
    config.pull.registry_path = Some(registry_bin().into());
    config.pull.dir_path = Some(dir_bin().into());
    let (spawner, _) = fetcher_spawner_with(dir, &dir.join("staging"), conf, &config);
    velarx_content::list::RegistryOrigin::with_shared(spawner, &config)
}

/// A service with a store of its own, to pull what another one pushed.
pub struct Side {
    _tmp: tempfile::TempDir,
    pub service: std::mem::ManuallyDrop<ImageService>,
    pub db: Database,
    pub store: Arc<FileStore>,
}

pub async fn side() -> Side {
    side_with(None).await
}

/// A service with its own store and, if given, the registries.conf `conf`
/// (its client's and its registry fetcher's).
pub async fn side_with(conf: Option<&str>) -> Side {
    let tmp = tempfile::tempdir().unwrap();
    let db = Database::open_in_memory()
        .await
        .unwrap()
        .with_layer_files(Arc::new(velarx_db::layer_files::Directory(
            tmp.path().to_path_buf(),
        )));
    let store = Arc::new(FileStore::new(tmp.path().join("objects")).unwrap());
    let service = ImageService::new(
        db.clone(),
        store.clone(),
        tmp.path().join("staging"),
        velarx_storage::VerityMode::Off,
    )
    .unwrap();
    let pull = PullConfig {
        worker_path: Some(registry_bin().into()),
        registry_hints: false,
        ..PullConfig::default()
    };
    let origin = origin_for(tmp.path(), conf.unwrap_or_default(), &pull);
    let service = service.with_pull_config(pull).unwrap().with_origin(origin);
    let service = match conf {
        Some(c) => service.with_resolver(client_conf(c)),
        None => service,
    };
    Side {
        _tmp: tmp,
        service: std::mem::ManuallyDrop::new(service),
        db,
        store,
    }
}

impl Side {
    /// Pull a reference as `pull` does: short names are resolved, mirrors
    /// used, with the platform asked for.
    pub async fn pull_ref(
        &self,
        reference: &str,
        platform: Option<&str>,
    ) -> Result<velarx_core::services::PullResult, velarx_types::ImageError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        self.service
            .pull_with(
                reference,
                false,
                &velarx_core::services::PullOptions {
                    tls_verify: true,
                    platform: platform.map(str::to_string),
                    ..Default::default()
                },
                tx,
            )
            .await
    }

    pub async fn pull(
        &self,
        client: &Resolver,
        reference: &str,
    ) -> Result<velarx_core::services::PullResult, velarx_types::ImageError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        self.service.pull_with_client(client, reference, tx).await
    }

    /// Pull only the metadata of what can be.
    pub async fn pull_lazy(
        &self,
        client: &Resolver,
        reference: &str,
    ) -> Result<velarx_core::services::PullResult, velarx_types::ImageError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        self.service
            .pull_lazy_with_client(client, reference, tx)
            .await
    }
}

/// Put an image of these layers in a registry as `test:latest`; returns the
/// digest of its manifest.
pub fn publish_to(reg: &Registry, layers: &[&Built], media: &[&str]) -> Digest {
    publish_arch(reg, layers, media, "amd64", "latest")
}

/// Like `publish_to`, for a platform and a reference (a tag or `*`: the
/// manifest is published by its digest only).
pub fn publish_arch(
    reg: &Registry,
    layers: &[&Built],
    media: &[&str],
    arch: &str,
    reference: &str,
) -> Digest {
    publish_annotated(reg, layers, media, arch, reference, serde_json::json!({}))
}

/// Like `publish_arch`, the manifest with these annotations.
pub fn publish_annotated(
    reg: &Registry,
    layers: &[&Built],
    media: &[&str],
    arch: &str,
    reference: &str,
    annotations: serde_json::Value,
) -> Digest {
    let config = serde_json::json!({
        "architecture": arch, "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": layers.iter().map(|l| l.diff_id).collect::<Vec<_>>()},
    })
    .to_string();
    let mut blobs = reg.blobs.lock().unwrap();
    let mut descs = Vec::new();
    for (l, m) in layers.iter().zip(media) {
        let d = sha(&l.blob);
        blobs.insert(d.to_string(), l.blob.clone());
        descs.push(serde_json::json!({
            "mediaType": m, "digest": d, "size": l.blob.len(), "annotations": l.annotations
        }));
    }
    let cd = sha(config.as_bytes());
    blobs.insert(cd.to_string(), config.clone().into_bytes());
    let mut manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cd, "size": config.len()},
        "layers": descs,
    });
    if annotations.as_object().is_some_and(|a| !a.is_empty()) {
        manifest["annotations"] = annotations;
    }
    let manifest = manifest.to_string();
    let digest = sha(manifest.as_bytes());
    blobs.insert(format!("manifest:{digest}"), manifest.clone().into_bytes());
    if reference != "*" {
        blobs.insert(format!("manifest:{reference}"), manifest.into_bytes());
    }
    digest
}

/// A client with this `registries.conf`; `{}` holds nothing but the hosts
/// of the registries are plain HTTP (`insecure` in the blocks).
pub fn client_conf(conf: &str) -> Resolver {
    Resolver::with_config(
        TransportConfig {
            registries: RegistriesConfig::parse(conf).unwrap(),
            certs_dirs: vec![],
            tls_verify: true,
        },
        AuthConfig::default(),
    )
}

/// A binary that cargo built (see `velarx_base::testing::built_binary`).  The
/// binaries are in the package `velarx-bin`, whose tests make `cargo test`
/// build them: `cargo test -p velarx` alone does not (`cargo build --bins`
/// first).
pub fn built_binary(name: &str) -> Option<std::path::PathBuf> {
    velarx_base::testing::built_binary(name)
}

/// The daemon binary of this package (its build workers too), from
/// `VELARX_TEST_WORKER` when set (a copy that another build cannot replace
/// while the tests run), else the one cargo built.  A run of these tests
/// alone (`cargo test --test integration NAME`) builds no binary: without
/// one the test fails saying so, not with a `velarx` of the `PATH` that
/// cannot be started or is of another version.  (The tests of other
/// packages include this file, and run no worker.)
pub fn worker() -> &'static str {
    static WORKER: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    WORKER.get_or_init(|| {
        pick_worker(
            std::env::var("VELARX_TEST_WORKER").ok(),
            built_binary("velarx").as_deref().and_then(|p| p.to_str()),
        )
        .expect(
            "no velarx binary next to the tests: build it first (`cargo build --bins`, \
             or `make test`) or set VELARX_TEST_WORKER",
        )
    })
}

/// The registry fetcher, `velarx-registry`, that cargo built (a copy from
/// `VELARX_TEST_REGISTRY` when set).
pub fn registry_bin() -> &'static str {
    static FETCHER: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    FETCHER.get_or_init(|| {
        pick_worker(
            std::env::var("VELARX_TEST_REGISTRY").ok(),
            built_binary("velarx-registry")
                .as_deref()
                .and_then(|p| p.to_str()),
        )
        .expect(
            "no velarx-registry binary next to the tests: build it first (`cargo build --bins`, \
             or `make test`) or set VELARX_TEST_REGISTRY",
        )
    })
}

/// The directory fetcher, `velarx-dir`, that cargo built (a copy from
/// `VELARX_TEST_DIR` when set).
pub fn dir_bin() -> &'static str {
    static DIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        pick_worker(
            std::env::var("VELARX_TEST_DIR").ok(),
            built_binary("velarx-dir")
                .as_deref()
                .and_then(|p| p.to_str()),
        )
        .expect(
            "no velarx-dir binary next to the tests: build it first (`cargo build --bins`, \
             or `make test`) or set VELARX_TEST_DIR",
        )
    })
}

pub fn pick_worker(over: Option<String>, built: Option<&str>) -> Option<String> {
    match over {
        Some(path) if !path.is_empty() => Some(path),
        _ => built.map(str::to_string),
    }
}

/// The fetchers of `[[sources.external]]` of an environment, put before the
/// registry fetcher in the list of its pulls in their order (unless its
/// `[pull] sources` says otherwise).
#[derive(Clone, Default)]
pub struct Fetchers(pub Vec<velarx_config::ExternalSourceConfig>);

/// A fetcher on a unix socket, serving what is put in `items` by digest
/// (the bytes may be other than the digest says: that is the point of some
/// tests; the index of a layer is `index:DIGEST`), and counting the items
/// it gave.
pub struct FakeSource {
    pub items: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    /// Items asked for
    pub has_calls: Arc<AtomicUsize>,
    /// Items given
    pub fetched: Arc<AtomicUsize>,
    /// Run when the first item is asked for
    pub on_first: OnFirst,
    pub socket: std::path::PathBuf,
    _dir: tempfile::TempDir,
    _server: velarx_content::serve_fetch::ServerThread,
}

/// What a fake source runs when it is asked for its first item.
pub type OnFirst = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

struct MapItems {
    items: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    has_calls: Arc<AtomicUsize>,
    fetched: Arc<AtomicUsize>,
    on_first: OnFirst,
}

impl MapItems {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        if let Some(f) = self.on_first.lock().unwrap().take() {
            f();
        }
        self.has_calls.fetch_add(1, Ordering::SeqCst);
        let data = self.items.lock().unwrap().get(key).cloned()?;
        self.fetched.fetch_add(1, Ordering::SeqCst);
        Some(data)
    }
}

impl velarx_content::dir_fetch::Items for MapItems {
    fn item(&self, name: &str, size: Option<u64>, max: u64) -> Option<Vec<u8>> {
        let data = self.get(name)?;
        (size.is_none_or(|s| s == data.len() as u64) && data.len() as u64 <= max).then_some(data)
    }

    fn index(&self, layer: &str) -> Option<Vec<u8>> {
        self.get(&format!("index:{layer}"))
    }
}

pub async fn fake_source() -> FakeSource {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("source.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let items = Arc::new(Mutex::new(HashMap::new()));
    let (has_calls, fetched) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let on_first = OnFirst::default();
    let provider = velarx_content::dir_fetch::ItemFetch::of(
        "fake",
        MapItems {
            items: items.clone(),
            has_calls: has_calls.clone(),
            fetched: fetched.clone(),
            on_first: on_first.clone(),
        },
    );
    let server = velarx_content::serve_fetch::serve_in_thread(
        listener,
        provider,
        velarx_content::activation::Limits::default(),
    )
    .unwrap();
    FakeSource {
        items,
        has_calls,
        fetched,
        on_first,
        socket,
        _dir: dir,
        _server: server,
    }
}

/// The blob `digest` of `size` bytes from the fetcher on `socket`, as the
/// engine asks for it (`GetBlob` on a scope of its own); none when it has not
/// got it.
pub async fn blob_from(socket: &std::path::Path, digest: &str, size: u64) -> Option<Vec<u8>> {
    let mut conn = scoped(socket).await?;
    let blob = velarx_content::fetcher::fetch::Blob {
        digest: digest.to_string(),
        size,
        media_type: "application/octet-stream".into(),
        annotations: None,
    };
    let file = conn.get_blob(&blob).await.ok()?;
    let length = file.metadata().ok()?.len();
    velarx_base::sealed::read_sealed(&file, length, size).ok()
}

/// The startup profile of `image` (at most `max` bytes) from the fetcher on
/// `socket` (`GetProfile`); none when it has not got it.
pub async fn profile_from(socket: &std::path::Path, image: &str, max: u64) -> Option<Vec<u8>> {
    let mut conn = scoped(socket).await?;
    let file = conn.get_profile(image, max).await.ok()?;
    let length = file.metadata().ok()?.len();
    velarx_base::sealed::read_sealed(&file, length, max).ok()
}

async fn scoped(
    socket: &std::path::Path,
) -> Option<velarx_content::fetcher::fetch_client::FetchConn> {
    let mut conn = velarx_content::fetcher::fetch_client::FetchConn::connect_checked(socket)
        .await
        .ok()?;
    conn.open(velarx_content::fetcher::fetch_client::Scoping::bare(
        std::time::Duration::from_secs(60),
    ))
    .await
    .ok()?;
    Some(conn)
}

/// The fetchers of the peers on `sockets`.
pub fn chain_of(sockets: &[&std::path::Path]) -> Fetchers {
    Fetchers(
        sockets
            .iter()
            .enumerate()
            .map(|(i, s)| velarx_config::ExternalSourceConfig {
                name: format!("source{i}"),
                socket: Some(s.to_path_buf()),
                dir: None,
                idle_timeout_secs: velarx_config::default_source_idle_secs(),
                settings: Default::default(),
            })
            .collect(),
    )
}

/// The service of the store of `env`, served on `socket` from a thread of
/// its own, until the guard is dropped.
pub async fn serve_store(
    service: velarx_core::store_service::StoreService,
    socket: &std::path::Path,
) -> StoreServer {
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        tokio::task::LocalSet::new().block_on(&runtime, async move {
            listener.set_nonblocking(true).unwrap();
            let listener = tokio::net::UnixListener::from_std(listener).unwrap();
            tokio::select! {
                _ = velarx_core::store_service::serve(listener, service, None, |_| true, velarx_content::activation::Limits::default()) => {}
                _ = stopped => {}
            }
        });
    });
    StoreServer { _stop: stop }
}

/// A store service that stops when this is dropped.
pub struct StoreServer {
    _stop: tokio::sync::oneshot::Sender<()>,
}

/// An environment whose chunks may come from these sockets, in order.
pub async fn env_with_sources(sockets: &[&std::path::Path]) -> Env {
    env_sources(
        PullConfig::default(),
        velarx_config::PushConfig::default(),
        chain_of(sockets),
    )
    .await
}

/// Whether the TCP connection a server on port SERVER accepted from port
/// PEER was opened by this process (the daemon's code under test), not by
/// a worker it started: the socket of the client side, found by its ports
/// in the tables of the namespace, is one of the descriptors of this
/// process.  The client socket exists while the server holds the
/// connection, so the check is not a sample.
pub fn connection_is_mine(peer: u16, server: u16) -> bool {
    let mut inodes = Vec::new();
    for table in ["/proc/self/net/tcp", "/proc/self/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(table) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            let port = |a: &str| {
                a.rsplit(':')
                    .next()
                    .and_then(|p| u16::from_str_radix(p, 16).ok())
            };
            if f.len() > 9 && port(f[1]) == Some(peer) && port(f[2]) == Some(server) {
                inodes.push(format!("socket:[{}]", f[9]));
            }
        }
    }
    assert!(!inodes.is_empty(), "no client socket for port {peer}");
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .flatten()
        .filter_map(|e| std::fs::read_link(e.path()).ok())
        .any(|l| inodes.iter().any(|i| l.to_str() == Some(i)))
}

/// A server on 127.0.0.1 that answers every request with RESPONSE, and
/// counts the connections this process opened to it.
pub fn watched_http_server(response: &'static [u8]) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let mine = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = mine.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let peer = s.peer_addr().unwrap().port();
            if connection_is_mine(peer, port) {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(response);
        }
    });
    (port, mine)
}

/// An HTTPS front for the plain registry at `backend`, with a self-signed
/// certificate for 127.0.0.1: its address, and the certificate in PEM (what
/// a `--cert-dir` would hold).
pub struct TlsFront {
    pub host: String,
    pub ca: String,
}

pub fn tls_front(backend: &str) -> TlsFront {
    use openssl::ssl::{SslAcceptor, SslMethod};
    let key = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "127.0.0.1").unwrap();
    let name = name.build();
    let mut b = openssl::x509::X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let san = openssl::x509::extension::SubjectAlternativeName::new()
        .ip("127.0.0.1")
        .build(&b.x509v3_context(None, None))
        .unwrap();
    b.append_extension(san).unwrap();
    b.sign(&key, openssl::hash::MessageDigest::sha256())
        .unwrap();
    let cert = b.build();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    let acceptor = Arc::new(acceptor.build());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let host = listener.local_addr().unwrap().to_string();
    let backend = backend.to_string();
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let (acceptor, backend) = (acceptor.clone(), backend.clone());
            std::thread::spawn(move || tls_bridge(&acceptor, client, &backend));
        }
    });
    TlsFront {
        host,
        ca: String::from_utf8(cert.to_pem().unwrap()).unwrap(),
    }
}

/// One connection: the TLS side is decrypted and passed to the plain
/// backend, and the answers are encrypted back, until either side ends.
fn tls_bridge(acceptor: &openssl::ssl::SslAcceptor, client: std::net::TcpStream, backend: &str) {
    use rustix::event::{poll, PollFd, PollFlags};
    use std::io::{Read, Write};
    let Ok(mut tls) = acceptor.accept(client.try_clone().unwrap()) else {
        return;
    };
    let Ok(mut plain) = std::net::TcpStream::connect(backend) else {
        return;
    };
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // (what the TLS layer has read already is not seen by the socket)
        let buffered = tls.ssl().pending() > 0;
        let (from_client, from_backend) = if buffered {
            (true, false)
        } else {
            let mut fds = [
                PollFd::new(&client, PollFlags::IN),
                PollFd::new(&plain, PollFlags::IN),
            ];
            if poll(&mut fds, None).is_err() {
                return;
            }
            (!fds[0].revents().is_empty(), !fds[1].revents().is_empty())
        };
        if from_client {
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if plain.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            }
        }
        if from_backend {
            match plain.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if tls.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// The scope of a connection to a pusher: `destination`, no target, no
/// credentials, 60 seconds of silence.
pub async fn push_scope(
    conn: &mut velarx_content::fetcher::fetch_client::FetchConn,
    destination: &str,
    requires: &[String],
) -> Result<(), velarx_content::fetcher::fetch_client::CallError> {
    conn.push_open(velarx_content::pusher::push_client::PushScoping {
        destination,
        tls_verify: None,
        target: None,
        access: None,
        idle: std::time::Duration::from_secs(60),
        requires,
    })
    .await
}

/// The table of contents a layer of the store is stored by.
pub async fn stored_toc(db: &Database, key: &velarx_db::LayerKey) -> velarx_storage::Toc {
    velarx_content::pull::stored::stored_toc(db, key)
        .await
        .unwrap()
        .expect("the layer has a table of contents")
}

/// The tables of contents of the layers of an image, the lowest first.
pub async fn image_tocs(db: &Database, image: &str) -> Vec<velarx_storage::Toc> {
    let mut tocs = Vec::new();
    for l in db.get_image_layers(image).await.unwrap() {
        tocs.push(stored_toc(db, &l.key).await);
    }
    tocs
}

/// The table of contents of a staged layer.
pub fn staged_toc(layer: &velarx_content::pull::staged::StagedLayer) -> velarx_storage::Toc {
    layer.toc().unwrap()
}

/// Stage `toc` as the table of the layer `key` (the table as it came is
/// replaced by the zstd of its JSON).
pub fn restage_toc(e: &Env, key: &velarx_db::LayerKey, toc: &velarx_storage::Toc) {
    let z = zstd::encode_all(&serde_json::to_vec(toc).unwrap()[..], 3).unwrap();
    std::fs::write(e.area().layer_dir(key).join("toc.zst"), z).unwrap();
}

pub fn entry(name: &str, kind: TocEntryType, size: u64) -> TocEntry {
    TocEntry {
        mode: if kind == TocEntryType::Dir {
            0o755
        } else {
            0o644
        },
        size,
        mod_time: Some("2023-11-14T22:13:20.5Z".to_string()),
        ..TocEntry::new(name.to_string(), kind)
    }
}

/// The canonical tar of the items, in the order of its paths.
pub fn tar_of_items(items: &[Item]) -> Vec<u8> {
    let mut entries = Vec::new();
    let mut data: HashMap<String, Vec<u8>> = HashMap::new();
    for item in items {
        match item {
            Item::Dir(n) => entries.push(entry(&format!("./{n}"), TocEntryType::Dir, 0)),
            Item::File { name, data: d, .. } => {
                entries.push(entry(
                    &format!("./{name}"),
                    TocEntryType::Reg,
                    d.len() as u64,
                ));
                data.insert(format!("./{name}"), d.clone());
            }
            Item::Symlink(n, t) => {
                let mut e = entry(&format!("./{n}"), TocEntryType::Symlink, 0);
                e.link_name = Some(t.to_string());
                entries.push(e);
            }
        }
    }
    let key = |e: &TocEntry| {
        e.name
            .trim_end_matches('/')
            .split('/')
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    entries.sort_by_key(key);
    let mut tar = Vec::new();
    canonical::write(&entries, &mut tar, |e, out| out.write_all(&data[&e.name])).unwrap();
    tar
}

/// A layer of version 2 as a producer that is not this engine writes it:
/// the canonical tar of the items, as a blob.
pub fn build_canonical(items: &[Item]) -> Built {
    let tar = tar_of_items(items);
    let mut blob = Vec::new();
    let w = write_canonical_layer(
        &tar[..],
        velarx_types::digest::Algorithm::Sha256,
        Compression::ZstdChunked,
        None,
        &mut blob,
    )
    .unwrap();
    assert_eq!(w.diff_id, sha(&tar));
    Built {
        blob,
        diff_id: w.diff_id,
        annotations: w.annotations.into_iter().collect(),
    }
}
