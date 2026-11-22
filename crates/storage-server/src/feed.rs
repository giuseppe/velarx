// SPDX-License-Identifier: Apache-2.0
//! The server as the client of `org.velarx.StorageFeed`: `WireFeed` is the
//! [`PullFeed`] of the vfs driver over the socket `BeginPull` handed over.
//! The driver asks it for a layer; it asks the engine, with `Fetch`, for the
//! files the store lacks, in a pack file and in files of their own, and makes
//! staged files of what the engine wrote, which the staging session of the
//! driver then commits as it does for its own pulls.

use crate::store::Store;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use velarx_content::pull::stream::FileUse;
use velarx_content::pull::LayerDone;
use velarx_graph::{FeedLayer, Incoming, LayerIndex, PullFeed};
use velarx_storage_client::feed_proto::{
    request, Copy, EventKind, FeedInfo, Fetched, Want, INTERFACE, MAX_FETCH_BYTES, MAX_FILES,
    MAX_WANTS,
};
use velarx_types::{ImageError, ImageResult};
use velarx_wire::varlink::Conn;

/// The connections of the feed the server uses at the same time: what the
/// engine allows (`max_fetches`), at most four.
fn max_fetches(info: &FeedInfo) -> u32 {
    info.limits
        .get("max_fetches")
        .map_or(1, |n| (*n).min(4) as u32)
}

/// The objects at least this big get a file of their own.
const OWN_FILE: u64 = 1 << 20;

/// An error the feed answered, by its name.
fn feed_error(m: &Value) -> Option<String> {
    let name = m.get("error")?.as_str()?;
    let reason = m["parameters"]["reason"]
        .as_str()
        .or_else(|| m["parameters"]["failure"]["reason"].as_str())
        .or_else(|| m["parameters"]["key"].as_str())
        .or_else(|| m["parameters"]["layer"].as_str())
        .unwrap_or("");
    Some(format!(
        "the engine's feed answered {}: {reason}",
        name.rsplit('.').next().unwrap_or(name)
    ))
}

/// `Release` of the layer `key` on `conn`.  An engine that does not know the
/// call (`MethodNotFound`: older than it) frees what it kept when the pull is
/// staged, which is no error; any other error is.
fn release_on(conn: &mut Conn, key: &str) -> ImageResult<()> {
    send(conn, &request::Release { layer: key }, &[])?;
    let bytes = conn
        .message()
        .map_err(|e| ImageError::Storage(format!("the engine's feed: {e}")))?;
    drop(conn.take_fds());
    let m: Value = serde_json::from_slice(&bytes)
        .map_err(|e| ImageError::Storage(format!("the engine's feed: {e}")))?;
    if m.get("error").and_then(Value::as_str) == Some("org.varlink.service.MethodNotFound") {
        return Ok(());
    }
    match feed_error(&m) {
        Some(e) => Err(ImageError::Storage(e)),
        None => Ok(()),
    }
}

fn send<M: velarx_wire::varlink::Method>(
    conn: &mut Conn,
    m: &M,
    fds: &[std::os::fd::BorrowedFd<'_>],
) -> Result<(), ImageError> {
    conn.send_method(m, fds)
        .map_err(|e| ImageError::Storage(format!("the engine's feed: {e}")))
}

/// Whether the other end of `stream` is closed, without reading it: a byte
/// is looked at, not taken.
fn peer_closed(stream: &UnixStream) -> bool {
    let mut byte = [0u8; 1];
    match rustix::net::recv(
        stream,
        &mut byte,
        rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
    ) {
        Ok((0, _)) => true,
        Ok(_) => false,
        Err(e) => e != rustix::io::Errno::AGAIN && e != rustix::io::Errno::INTR,
    }
}

/// A thread that waits for the other end of a socket to close, and calls a
/// function when it does; it ends when this is dropped.
pub struct EngineWatch {
    wake: Option<OwnedFd>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl EngineWatch {
    fn on(socket: OwnedFd, closed: impl FnOnce() + Send + 'static) -> std::io::Result<Self> {
        use rustix::event::{poll, PollFd, PollFlags};
        let (stop, wake) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
        let thread = std::thread::Builder::new()
            .name("engine-watch".into())
            .spawn(move || loop {
                let mut fds = [
                    PollFd::new(&socket, PollFlags::RDHUP),
                    PollFd::new(&stop, PollFlags::IN),
                ];
                match poll(&mut fds, None) {
                    Ok(_) if !fds[1].revents().is_empty() => return,
                    Ok(_) if !fds[0].revents().is_empty() => return closed(),
                    Ok(_) | Err(rustix::io::Errno::INTR) => {}
                    Err(e) => panic!("poll the feed of the engine: {e}"),
                }
            })?;
        Ok(Self {
            wake: Some(wake),
            thread: Some(thread),
        })
    }
}

impl Drop for EngineWatch {
    fn drop(&mut self) {
        // (the pipe is closed at its write end: the thread sees it hung up)
        drop(self.wake.take());
        if let Some(t) = self.thread.take() {
            if t.join().is_err() {
                panic!("the watch of the engine's feed panicked");
            }
        }
    }
}

fn next(conn: &mut Conn) -> Result<(Value, Vec<OwnedFd>), ImageError> {
    let bytes = conn
        .message()
        .map_err(|e| ImageError::Storage(format!("the engine's feed: {e}")))?;
    let m: Value = serde_json::from_slice(&bytes)
        .map_err(|e| ImageError::Storage(format!("the engine's feed: {e}")))?;
    if let Some(e) = feed_error(&m) {
        return Err(ImageError::Storage(e));
    }
    Ok((m, conn.take_fds()))
}

fn parameters<T: DeserializeOwned>(m: &Value) -> Result<T, ImageError> {
    serde_json::from_value(m["parameters"].clone())
        .map_err(|e| ImageError::Storage(format!("the engine's feed: {e}")))
}

/// The connections to the feed, taken one for each call.
struct Pool {
    free: Mutex<Vec<Conn>>,
    freed: Condvar,
}

pub struct WireFeed {
    store: Arc<Store>,
    /// The pull this feed is for.
    pull: String,
    pool: Pool,
    /// A duplicate of the main connection, to watch for the engine closing
    /// it ([`EngineWatch`]).
    main: OwnedFd,
    pub info: FeedInfo,
    indexes: Mutex<HashMap<String, LayerIndex>>,
    /// The objects fetched, for the pull that holds them.
    fetched: Mutex<Vec<String>>,
}

impl WireFeed {
    /// The feed on `stream`: `GetInfo`, and as many connections as the engine
    /// allows at once (at most four).
    pub fn open(
        store: Arc<Store>,
        pull: &str,
        stream: std::os::unix::net::UnixStream,
    ) -> ImageResult<Self> {
        let mut main = Conn::from_stream(stream);
        send(&mut main, &request::GetInfo {}, &[])?;
        let (m, _) = next(&mut main)?;
        let info: FeedInfo = parameters(&m)?;
        velarx_proto::info::check(
            INTERFACE,
            &info.shared(),
            velarx_storage_client::proto::PROTO,
        )
        .map_err(|e| ImageError::Storage(format!("the engine's feed: {e}")))?;
        let mut conns = Vec::new();
        for _ in 1..max_fetches(&info) {
            send(&mut main, &request::Connect {}, &[])?;
            let (_, mut fds) = next(&mut main)?;
            if fds.len() != 1 {
                return Err(ImageError::Storage(
                    "the engine's feed answered Connect without a descriptor".into(),
                ));
            }
            conns.push(Conn::from_stream(std::os::unix::net::UnixStream::from(
                fds.remove(0),
            )));
        }
        let watched = rustix::io::fcntl_dupfd_cloexec(main.socket(), 0)
            .map_err(|e| ImageError::Storage(format!("the engine's feed: {e}")))?;
        conns.push(main);
        Ok(Self {
            store,
            pull: pull.to_string(),
            pool: Pool {
                free: Mutex::new(conns),
                freed: Condvar::new(),
            },
            main: watched,
            info,
            indexes: Mutex::default(),
            fetched: Mutex::default(),
        })
    }

    fn take(&self) -> Conn {
        let mut free = self.pool.free.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(c) = free.pop() {
                return c;
            }
            free = self
                .pool
                .freed
                .wait(free)
                .unwrap_or_else(|e| e.into_inner());
        }
    }

    fn give(&self, c: Conn) {
        self.pool
            .free
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(c);
        self.pool.freed.notify_one();
    }

    /// Whether the engine is gone: the feed is closed at its end (the engine
    /// holds it open until it has decided the pull, so a closed feed with no
    /// decision is a pull nobody will decide).  A feed in use, or one the
    /// engine wrote to, is not.
    pub fn engine_gone(&self) -> bool {
        let free = self.pool.free.lock().unwrap_or_else(|e| e.into_inner());
        let Some(conn) = free.last() else {
            return false;
        };
        peer_closed(conn.socket())
    }

    /// Call `closed` when the engine closes the feed, until the result is
    /// dropped (the connection that is kept open until the pull is decided).
    pub fn watch_engine(
        &self,
        closed: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<EngineWatch> {
        EngineWatch::on(rustix::io::fcntl_dupfd_cloexec(&self.main, 0)?, closed)
    }

    /// The objects this feed fetched.
    pub fn fetched(&self) -> Vec<String> {
        self.fetched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn index_blocking(&self, key: &str) -> ImageResult<LayerIndex> {
        if let Some(i) = self
            .indexes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
        {
            return Ok(i.clone());
        }
        let mut conn = self.take();
        let result = (|| {
            send(&mut conn, &request::Index { layer: key }, &[])?;
            let (_, fds) = next(&mut conn)?;
            let n = fds.len();
            let [toc_fd, tarsplit_fd]: [OwnedFd; 2] = fds.try_into().map_err(|_| {
                ImageError::Storage(format!(
                    "the engine's feed answered Index with {n} descriptors, not two"
                ))
            })?;
            // (sealed memory files, read at their places, of the sizes a
            // verified table of contents and tar-split can have)
            let read = |file: &File, what: &str, max: u64| {
                velarx_base::sealed::read_sealed_whole(file, max).map_err(|e| {
                    ImageError::Storage(format!("the {what} the engine's feed gave {e}"))
                })
            };
            use velarx_content::pull::chunked::MAX_METADATA_COMPRESSED;
            let key = velarx_types::LayerKey::parse(key)
                .ok_or_else(|| ImageError::Storage(format!("{key} is not the key of a layer")))?;
            let toc_z = read(&File::from(toc_fd), "toc.zst", MAX_METADATA_COMPRESSED)?;
            let toc = velarx_content::pull::stored::stored_view(&toc_z, &key)?;
            // (a canonical layer has no tar-split: an empty file)
            let tarsplit_file = File::from(tarsplit_fd);
            let tarsplit =
                if toc.is_canonical() && tarsplit_file.metadata().is_ok_and(|m| m.len() == 0) {
                    Vec::new()
                } else {
                    read(&tarsplit_file, "tar-split", MAX_METADATA_COMPRESSED)?
                };
            Ok::<_, ImageError>(LayerIndex {
                key,
                toc_z: toc_z.into(),
                toc: Arc::new(toc),
                tarsplit: tarsplit.into(),
            })
        })();
        self.give(conn);
        let index = result?;
        self.indexes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string(), index.clone());
        Ok(index)
    }

    /// The layer needs nothing more from the engine (`Release`).
    fn release(&self, key: &str) -> ImageResult<()> {
        let mut conn = self.take();
        let result = release_on(&mut conn, key);
        self.give(conn);
        result
    }

    /// One `Fetch` of `wants` (key, size) into staged files of the session.
    fn fetch_batch(
        &self,
        layer: &str,
        wants: &[(String, u64)],
        sink: &Arc<dyn velarx_content::pull::sink::Sink>,
    ) -> ImageResult<()> {
        let io = |e: std::io::Error| ImageError::Storage(e.to_string());
        // the biggest objects (at most MAX_FILES - 1) in files of their own
        let mut order: Vec<usize> = (0..wants.len()).collect();
        order.sort_by_key(|i| std::cmp::Reverse(wants[*i].1));
        let own: Vec<usize> = order
            .into_iter()
            .take(MAX_FILES - 1)
            .filter(|i| wants[*i].1 >= OWN_FILE)
            .collect();
        let mut files: Vec<(File, std::path::PathBuf)> = Vec::new();
        let mut spec = Vec::with_capacity(wants.len());
        let (pack, pack_path) = sink.create_temp().map_err(io)?;
        let pack_path =
            pack_path.ok_or_else(|| ImageError::Storage("a file with no name".into()))?;
        files.push((pack, pack_path));
        let mut slot_of: HashMap<usize, usize> = HashMap::new();
        for (i, (key, size)) in wants.iter().enumerate() {
            if own.contains(&i) {
                let (f, p) = sink.create_temp().map_err(io)?;
                let p = p.ok_or_else(|| ImageError::Storage("a file with no name".into()))?;
                files.push((f, p));
                slot_of.insert(i, files.len() - 1);
                spec.push(Want {
                    key: key.clone(),
                    size: *size,
                    file: Some(files.len() as u32 - 1),
                });
            } else {
                spec.push(Want {
                    key: key.clone(),
                    size: *size,
                    file: None,
                });
            }
        }
        let fds: Vec<std::os::fd::BorrowedFd<'_>> = files.iter().map(|(f, _)| f.as_fd()).collect();
        self.store.fetch_calls.fetch_add(1, Ordering::Relaxed);
        self.store
            .fetch_keys
            .fetch_add(wants.len() as u64, Ordering::Relaxed);
        let mut conn = self.take();
        let result = (|| {
            send(
                &mut conn,
                &request::Fetch {
                    layer,
                    wants: &spec,
                },
                &fds,
            )?;
            let mut place: HashMap<u32, (u32, u64, u64)> = HashMap::new();
            let mut complete = vec![false; wants.len()];
            let mut copies: Vec<Copy> = Vec::new();
            let mut handed: HashMap<u32, (File, String)> = HashMap::new();
            loop {
                let (m, fds) = next(&mut conn)?;
                let continues = m["continues"] == true;
                // (the last reply has no event)
                let Some(ev) = parameters::<Fetched>(&m)?.event else {
                    if !continues {
                        break;
                    }
                    continue;
                };
                match ev.kind {
                    EventKind::Staged => {
                        // (the files of objects the engine verified, handed
                        // over whole: no byte is written to a place of ours)
                        let mut fds: Vec<Option<OwnedFd>> = fds.into_iter().map(Some).collect();
                        for h in ev.handed {
                            let fd = fds
                                .get_mut(h.fd as usize)
                                .and_then(Option::take)
                                .ok_or_else(|| {
                                    ImageError::Layer(format!(
                                        "the engine handed over the file {} and the message carries {}",
                                        h.fd,
                                        fds.len()
                                    ))
                                })?;
                            handed.insert(h.want, (File::from(fd), h.verity));
                        }
                    }
                    EventKind::Ready => {
                        for p in ev.pieces {
                            place.insert(p.want, (p.region.fd, p.region.offset, p.region.length));
                        }
                    }
                    EventKind::Copy => copies.extend(ev.copies),
                    EventKind::Complete => {
                        for w in ev.wants {
                            if let Some(c) = complete.get_mut(w as usize) {
                                *c = true;
                            }
                        }
                    }
                    EventKind::Failed => {
                        return Err(ImageError::Layer(format!(
                            "the engine could not fetch {} of the files asked for: {}",
                            ev.wants.len(),
                            ev.failure.map_or_else(String::new, |f| format!(
                                "{} ({:?})",
                                f.reason, f.class
                            ))
                        )))
                    }
                    _ => {}
                }
                if !continues {
                    break;
                }
            }
            if let Some(i) = complete.iter().position(|c| !c) {
                return Err(ImageError::Layer(format!(
                    "the engine did not write {}",
                    wants[i].0
                )));
            }
            Ok((place, copies, handed))
        })();
        self.give(conn);
        let (place, copies, mut handed) = result?;
        for (i, (key, size)) in wants.iter().enumerate() {
            if let Some((file, verity)) = handed.remove(&(i as u32)) {
                // (verified by the engine, once: linked where this store is
                // in the same file system, else copied, and never read)
                if file.metadata().map_err(io)?.len() != *size {
                    return Err(ImageError::Layer(format!(
                        "the file of {key} is not the {size} bytes asked for"
                    )));
                }
                let adopted = sink.adopt_verified(&file, key, &verity).map_err(io)?;
                self.store.handed_files.fetch_add(1, Ordering::Relaxed);
                self.store
                    .handed_copied_bytes
                    .fetch_add(adopted.copied, Ordering::Relaxed);
                continue;
            }
            let (_, offset, length) = place.get(&(i as u32)).copied().ok_or_else(|| {
                ImageError::Layer(format!("the engine did not say where {key} is"))
            })?;
            if length != *size {
                return Err(ImageError::Layer(format!(
                    "the engine wrote {length} bytes of {key}, the table of contents says {size}"
                )));
            }
            if velarx_types::digest::Digest::parse_fsverity(key).is_ok() {
                sink.known_by_verity(key, key);
            }
            let copied = copies.iter().filter(|c| c.want as usize == i);
            match slot_of.get(&i) {
                Some(slot) => {
                    let (file, path) = &files[*slot];
                    if offset != 0 || file.metadata().map_err(io)?.len() != *size {
                        return Err(ImageError::Layer(format!(
                            "the file of {key} is not the {size} bytes asked for"
                        )));
                    }
                    for c in copied {
                        self.apply_copy(file, *size, c)?;
                    }
                    sink.adopt_as(path, key, *size).map_err(io)?;
                }
                None => {
                    let (pack, _) = &files[0];
                    let (tmp, path) = sink.create_temp().map_err(io)?;
                    let path =
                        path.ok_or_else(|| ImageError::Storage("a file with no name".into()))?;
                    let mut from = Region {
                        file: pack,
                        at: offset,
                        left: length,
                    };
                    velarx_storage::copy_sparse(&mut from, &tmp, |_| {}).map_err(io)?;
                    for c in copied {
                        self.apply_copy(&tmp, *size, c)?;
                    }
                    drop(tmp);
                    sink.adopt_as(&path, key, *size).map_err(io)?;
                }
            }
        }
        // (the pack file and the own files that were adopted are gone from
        // their names)
        let (_, pack_path) = &files[0];
        let _ = std::fs::remove_file(pack_path);
        self.fetched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(wants.iter().map(|w| w.0.clone()));
        Ok(())
    }

    /// Apply a `copy` of the engine: `length` bytes from `from_offset` of the
    /// object of this store that `from` names go to `at` of the staged object
    /// `file` (of `size` bytes), as a copy of our own object.  The engine named
    /// an object it had asked about (`HasObjects`); one that is not here any
    /// more, or too short, fails the fetch (the layer is fetched again).
    fn apply_copy(&self, file: &File, size: u64, c: &Copy) -> ImageResult<()> {
        let fail =
            |why: String| ImageError::Layer(format!("the engine's copy from {}: {why}", c.from));
        let end = c.at.checked_add(c.length).filter(|e| *e <= size);
        let source_end = c.from_offset.checked_add(c.length);
        if end.is_none() || source_end.is_none() {
            return Err(fail(format!(
                "{} bytes at {} do not fit an object of {size} bytes",
                c.length, c.at
            )));
        }
        let path = self
            .store
            .files
            .get_path(&self.store.resolve(&c.from))
            .ok_or_else(|| fail("the object is not in the store".into()))?;
        let from = File::open(path).map_err(|e| fail(e.to_string()))?;
        let have = from.metadata().map_err(|e| fail(e.to_string()))?.len();
        if source_end.is_some_and(|e| e > have) {
            return Err(fail(format!("the object has {have} bytes")));
        }
        velarx_storage::copy_region_holes(
            &from,
            c.from_offset,
            file,
            c.at,
            c.length,
            || Ok(()),
            &mut |_, _| {},
        )
        .map_err(|e| fail(e.to_string()))?;
        self.store.copy_events.fetch_add(1, Ordering::Relaxed);
        self.store
            .copied_bytes
            .fetch_add(c.length, Ordering::Relaxed);
        Ok(())
    }

    fn fetch_blocking(
        &self,
        layer: &FeedLayer,
        into: &Arc<dyn Incoming>,
    ) -> ImageResult<LayerDone> {
        let key = layer.key.to_string();
        let index = self.index_blocking(&key)?;
        let files = FileUse::of_toc(&index.toc);
        let mut seen: std::collections::HashSet<String> =
            files.iter().map(|f| f.digest.clone()).collect();
        let mut wants: Vec<(String, u64)> = Vec::new();
        // (the objects of the layer are the pull's while it lives, before the
        // store is asked whether it has them: an `Abort` of another pull that
        // staged one of them leaves it, see `release`)
        {
            let mut st = self.store.state();
            if let Some(p) = st.pulls.get_mut(&self.pull) {
                p.keys.extend(seen.iter().cloned());
            }
        }
        for f in &files {
            if seen.remove(&f.digest) && into.wants(&f.digest, f.size) {
                wants.push((f.digest.clone(), f.size));
            }
        }
        let sink = into.sink().clone();
        let (mut batch, mut bytes) = (Vec::new(), 0u64);
        let mut fetched = (0u64, 0u64);
        for w in wants {
            if batch.len() >= MAX_WANTS || bytes + w.1 > MAX_FETCH_BYTES {
                self.fetch_batch(&key, &batch, &sink)?;
                batch.clear();
                bytes = 0;
            }
            fetched.0 += 1;
            fetched.1 += w.1;
            bytes += w.1;
            batch.push(w);
        }
        if !batch.is_empty() {
            self.fetch_batch(&key, &batch, &sink)?;
        }
        // (every file of the layer that the store lacks is staged: the engine
        // frees what it kept to serve them)
        self.release(&key)?;
        let total: u64 = files.iter().map(|f| f.size).sum();
        let count = files.len() as u64;
        Ok(LayerDone {
            key: layer.key,
            blob: layer.descriptor.digest,
            diff_id: layer.diff_id,
            size: layer.descriptor.size,
            // (where the chunks of the layer are in the objects of this store:
            // the engine names a chunk it need not fetch when a later layer
            // has it)
            chunks: velarx_content::pull::chunked::located_chunks(&index.toc),
            toc: index.toc.clone(),
            files,
            report: velarx_content::pull::LayerReport {
                fetched_bytes: fetched.1,
                fetched_files: fetched.0,
                reused_bytes: total.saturating_sub(fetched.1),
                reused_files: count.saturating_sub(fetched.0),
                ..Default::default()
            },
            tarsplit: index.tarsplit.clone(),
            lazy: false,
            blob_checked: false,
            checked: Default::default(),
            toc_z: index.toc_z.clone(),
        })
    }
}

/// A region of a file, read in order.
struct Region<'a> {
    file: &'a File,
    at: u64,
    left: u64,
}

impl Read for Region<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.left as usize);
        if n == 0 {
            return Ok(0);
        }
        let got = self.file.read_at(&mut buf[..n], self.at)?;
        self.at += got as u64;
        self.left -= got as u64;
        Ok(got)
    }
}

/// The `PullFeed` the vfs driver pulls through.
#[derive(Clone)]
pub struct Feed(pub Arc<WireFeed>);

#[async_trait]
impl PullFeed for Feed {
    async fn begin(&self, _into: &Arc<dyn Incoming>) -> ImageResult<()> {
        Ok(())
    }

    fn parallel(&self) -> usize {
        max_fetches(&self.0.info) as usize
    }

    async fn index(&self, layer: &FeedLayer) -> ImageResult<Option<LayerIndex>> {
        let (feed, key) = (self.0.clone(), layer.key.to_string());
        let i = tokio::task::spawn_blocking(move || feed.index_blocking(&key))
            .await
            .map_err(|e| ImageError::Storage(e.to_string()))??;
        Ok(Some(i))
    }

    async fn fetch(&self, layer: &FeedLayer, into: &Arc<dyn Incoming>) -> ImageResult<LayerDone> {
        let (feed, layer, into) = (self.0.clone(), layer.clone(), into.clone());
        tokio::task::spawn_blocking(move || feed.fetch_blocking(&layer, &into))
            .await
            .map_err(|e| ImageError::Storage(e.to_string()))?
    }

    async fn finish(&self) -> ImageResult<()> {
        Ok(())
    }

    fn end(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    #[test]
    fn a_closed_peer_is_seen_and_an_open_one_is_not() {
        let (mine, theirs) = UnixStream::pair().unwrap();
        assert!(!peer_closed(&mine));
        // (what it sent is not taken)
        (&theirs).write_all(b"x").unwrap();
        assert!(!peer_closed(&mine));
        drop(theirs);
        // (the byte comes first, then the end)
        assert!(!peer_closed(&mine));
        let mut b = [0u8; 1];
        assert_eq!(std::io::Read::read(&mut &mine, &mut b).unwrap(), 1);
        assert!(peer_closed(&mine));
    }

    /// The watch calls its function when the other end closes, at once and
    /// once; one that is dropped first never calls it.
    #[test]
    fn the_watch_of_the_engine_says_when_the_feed_is_closed() {
        let dup = |s: &UnixStream| rustix::io::fcntl_dupfd_cloexec(s, 0).unwrap();
        let (mine, theirs) = UnixStream::pair().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let watch = EngineWatch::on(dup(&mine), move || tx.send(()).unwrap()).unwrap();
        (&theirs).write_all(b"x").unwrap();
        drop(theirs);
        rx.recv().expect("the close is seen");
        drop(watch);
        let (mine, theirs) = UnixStream::pair().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let watch = EngineWatch::on(dup(&mine), move || tx.send(()).unwrap()).unwrap();
        drop(watch);
        drop(theirs);
        assert!(rx.recv().is_err(), "a watch that was dropped called back");
    }

    /// `Release` is no error with an engine that does not know it (older
    /// than the call), and the other errors of the feed are errors.
    #[test]
    fn release_tolerates_an_engine_without_the_call() {
        use velarx_wire::varlink::{encode_error, encode_reply, parse_call};
        let answer = |reply: Vec<u8>| {
            let (mine, theirs) = UnixStream::pair().unwrap();
            let engine = std::thread::spawn(move || {
                let mut c = Conn::from_stream(theirs);
                let call = c.message().unwrap();
                let head = parse_call(&call).unwrap();
                assert_eq!(head.method, "org.velarx.StorageFeed.Release");
                c.send(&reply, &[]).unwrap();
            });
            let r = release_on(&mut Conn::from_stream(mine), "sha256:aa");
            engine.join().unwrap();
            r
        };
        answer(encode_reply(&json!({}), false)).unwrap();
        answer(encode_error(
            "org.varlink.service.MethodNotFound",
            &json!({ "method": "Release" }),
        ))
        .unwrap();
        let e = answer(encode_error(
            "org.velarx.StorageFeed.UnknownLayer",
            &json!({ "layer": "sha256:aa" }),
        ))
        .unwrap_err();
        assert!(e.to_string().contains("UnknownLayer"), "{e}");
    }
}
