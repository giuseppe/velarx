// SPDX-License-Identifier: Apache-2.0
//! The engine's side of `org.velarx.StorageFeed`: what a driver is offered
//! during a pull, served on the socket pair that `BeginPull` hands it.
//!
//! The feed is scoped to one pull.  The driver may ask for the index of the
//! layers of the pull (`Index`) and for objects whose keys are in the tables
//! of contents of those layers; anything else is refused by name, and
//! nothing a call says is a URL, a repository or a digest of a blob.  The
//! files it passes are checked before the engine writes to one: a regular,
//! empty file open for writing, on a file system whose writes do not block.
//! What one pull may ask for is bounded (the wants of a call, the bytes of a
//! layer, the calls at the same time).
//!
//! The write: a `Fetch` that passes the checks above is handed to the
//! engine's fetching code (`velarx_graph::PullFeed::fetch`), with a sink
//! (`velarx_content::pull::sink::FilesSink`) that puts each object where the
//! driver asked: in a file of its own (`Want.file`), or in the pack file
//! (descriptor 0) at an offset the engine chooses, a multiple of 4096.  The
//! engine plans the layer for the wants alone, merges the ranges by cost,
//! fetches, checks every chunk against the table of contents and writes, reads
//! each whole object back to check it is what its key names, and tells the
//! driver as it goes: `zeros` for the holes of an object, `ready`
//! with the place of each object that is whole, and `complete` with its
//! position among the wants.  An object a fetcher staged and the engine
//! verified (once) is not written to a place of the driver at all: `staged`
//! hands the file itself over (a descriptor of the message, with the
//! fs-verity digest the engine verified) and the driver keeps it its own way
//! (a link where it can, else a copy of its own).  The diff id is not proved by the fetch: the
//! engine reads the layer back from the driver (`ReadObjects`) after
//! `BeginPull` says `staged`.  A layer with no table of contents (a gzip
//! layer, one the engine made by a commit, a build step or an import) is not
//! a call of its own: the engine reads it whole, before `BeginPull`, into a
//! spool of its own, makes its table of contents and tar-split from the
//! headers, and the driver sees it as any other layer (`Index`), asks for the
//! files it lacks (`Fetch`), and gets them from the spool.

use crate::feed_proto::{
    Ack, Copy, EventKind, FeedError, FeedInfo, FeedLayer, FetchEvent, Fetched, Handed, Piece,
    Region, Want, Zeros, INTERFACE, MAX_FETCHES, MAX_FETCH_BYTES, MAX_FILES, MAX_WANTS, PROTO,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use velarx_content::pull::sink::{FilesSink, Slot, Written};
use velarx_graph::{FilesIncoming, LayerIndex, PullFeed};
use velarx_proto::transfer::{Failure, FailureClass};
use velarx_types::ImageError;
use velarx_wire::varlink::{
    call_parameters, encode_error, encode_reply, parse_call, BadCall, CallHead, Conn,
};

/// The objects of a pack file start at a multiple of this, so that a driver
/// may reflink them.
const PACK_ALIGN: u64 = 4096;

/// What the feed fetches with: the engine's fetching code, and the runtime
/// that runs it.
#[derive(Clone)]
pub struct Engine {
    pub feed: Arc<dyn PullFeed>,
    pub runtime: tokio::runtime::Handle,
    /// A directory of the engine's for the files with no name a fetch makes.
    pub scratch: std::path::PathBuf,
    /// Which of a list of objects the driver holds, when it says it can be
    /// asked: a chunk another object of its has is then copied by the driver
    /// (`copy` events), not fetched.
    pub holds: Option<velarx_content::pull::sink::Holds>,
}

struct Layer {
    graph: velarx_graph::FeedLayer,
    info: FeedLayer,
    /// The key of every file with content, and its size.
    keys: HashMap<String, u64>,
    toc: Vec<u8>,
    tarsplit: bytes::Bytes,
    /// The bytes still to be asked for: twice the planned bytes of the layer.
    left: AtomicU64,
    /// The driver said it has every file it lacks (`Release`): the engine
    /// keeps nothing for the layer, and a `Fetch` of it is refused.
    released: AtomicBool,
    /// The stagings of the layer that files were handed over from: their
    /// names last until the driver has linked the inodes, which it has when
    /// it says `Release`.
    held: Mutex<Vec<Arc<velarx_content::pull::staged_fetch::LayerStaging>>>,
}

/// The feed of one pull.
pub struct Feed {
    pull: String,
    engine: Engine,
    /// What a fetch failed with: the engine's verdict, which is the reason a
    /// pull fails whatever the driver says after it.
    failed: Mutex<Option<ImageError>>,
    /// Files and bytes written for each layer.
    fetched: Mutex<HashMap<String, (u64, u64)>>,
    /// The objects the driver was told to copy chunks into: nothing measured
    /// them at the fetch, the proof of the layer does when it reads them back.
    copied: Mutex<HashSet<String>>,
    /// The objects the engine wrote whole itself, every chunk of them checked
    /// against the table of contents as it was written: the chunks of these
    /// alone are recorded where they are (a later pull has the driver copy
    /// them).
    checked: Mutex<HashSet<String>>,
    layers: Vec<Layer>,
    live: AtomicU32,
    /// The connections served, by a number of their own, to close at the
    /// end; each leaves when its thread ends, so a driver that connects and
    /// closes over and over holds no descriptor of the engine's.
    open: Mutex<Open>,
}

#[derive(Default)]
struct Open {
    next: u64,
    streams: HashMap<u64, UnixStream>,
    /// The fetches of the engine in progress, by a number of their own: the
    /// end of the pull stops them, so that nothing writes into the files of
    /// the driver after `BeginPull` answered.
    fetches: HashMap<u64, tokio::task::AbortHandle>,
    /// The pull is over: no connection is served any more.
    closed: bool,
}

#[derive(Deserialize, Default)]
struct OfLayer {
    #[serde(default)]
    layer: String,
}

#[derive(Deserialize, Default)]
struct FetchCall {
    #[serde(default)]
    layer: String,
    #[serde(default)]
    wants: Vec<Want>,
}

/// One answer: the messages, each with its descriptors.
type Out = Vec<(Vec<u8>, Vec<OwnedFd>)>;

impl Feed {
    /// The feed of `pull` for the layers the driver brings in, each with its
    /// index.
    pub fn new(
        pull: &str,
        engine: Engine,
        layers: Vec<(velarx_graph::FeedLayer, LayerIndex)>,
    ) -> Result<Arc<Self>, String> {
        let mut out = Vec::with_capacity(layers.len());
        let mut seen = HashSet::new();
        for (layer, index) in layers {
            let mut layer = layer;
            layer.key = index.key;
            if !seen.insert(layer.key.to_string()) {
                continue;
            }
            let toc = serde_json::to_vec(&*index.toc).map_err(|e| e.to_string())?;
            let mut keys = HashMap::new();
            for e in &index.toc.entries {
                if e.entry_type == velarx_storage::TocEntryType::Reg && e.size > 0 {
                    if let Some(k) = e.content_key() {
                        keys.insert(k, e.size);
                    }
                }
            }
            let entries = index.toc.entries.len() as u64;
            let tarsplit = index.tarsplit;
            let size: u64 = keys.values().sum();
            out.push(Layer {
                graph: layer.clone(),
                info: FeedLayer {
                    key: layer.key.to_string(),
                    diff_id: layer.diff_id.to_string(),
                    toc_length: toc.len() as u64,
                    tarsplit_length: tarsplit.len() as u64,
                    entries,
                    size,
                },
                keys,
                toc,
                tarsplit,
                left: AtomicU64::new(size.saturating_mul(2)),
                released: AtomicBool::new(false),
                held: Mutex::default(),
            });
        }
        Ok(Arc::new(Self {
            pull: pull.to_string(),
            engine,
            failed: Mutex::new(None),
            fetched: Mutex::default(),
            copied: Mutex::default(),
            checked: Mutex::default(),
            layers: out,
            live: AtomicU32::new(0),
            open: Mutex::default(),
        }))
    }

    /// Serve the connection `stream` from a thread of its own, until the
    /// driver closes it or the feed is shut down.
    pub fn serve(self: &Arc<Self>, stream: UnixStream) -> std::io::Result<()> {
        let keep = stream.try_clone()?;
        let id = {
            let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
            if open.closed {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "the feed of the pull is closed",
                ));
            }
            open.next += 1;
            let id = open.next;
            open.streams.insert(id, keep);
            id
        };
        self.live.fetch_add(1, Ordering::SeqCst);
        let feed = self.clone();
        let spawned = std::thread::Builder::new()
            .name("storage-feed".into())
            .spawn(move || {
                feed.run(Conn::from_stream(stream));
                feed.forget(id);
            });
        if spawned.is_err() {
            self.forget(id);
        }
        spawned.map(drop)
    }

    /// The files and bytes the engine fetched for a layer so far.
    pub fn fetched(&self, layer: &str) -> (u64, u64) {
        self.fetched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(layer)
            .copied()
            .unwrap_or_default()
    }

    /// The objects the driver was told to copy chunks into.
    pub fn copied(&self) -> HashSet<String> {
        self.copied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The objects the engine wrote whole itself, each chunk checked as it
    /// was written (not one the driver copied into).
    pub fn checked(&self) -> HashSet<String> {
        self.checked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// What a fetch of the engine failed with, once.
    pub fn take_failure(&self) -> Option<ImageError> {
        self.failed.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    /// A connection that is over: its descriptor is closed.
    fn forget(&self, id: u64) {
        self.open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .streams
            .remove(&id);
        self.live.fetch_sub(1, Ordering::SeqCst);
    }

    /// The driver has staged the pull: no fetch goes on.  The connections
    /// stay open ([`Feed::shutdown`] closes them): a driver that sees the feed
    /// closed knows its engine is gone.
    pub fn abort_fetches(&self) {
        let open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        for f in open.fetches.values() {
            f.abort();
        }
    }

    /// The pull is over: the connections are closed, and the threads that
    /// serve them end.
    pub fn shutdown(&self) {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        open.closed = true;
        for s in open.streams.values() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        for f in open.fetches.values() {
            f.abort();
        }
    }

    fn run(self: &Arc<Self>, mut conn: Conn) {
        loop {
            let Ok(bytes) = conn.message() else { return };
            let fds = conn.take_fds();
            let Ok(head) = parse_call(&bytes) else { return };
            if head.method == format!("{INTERFACE}.Fetch") && head.more {
                match call_parameters::<FetchCall>(&bytes) {
                    Ok(p) => {
                        if let Err(e) = self.fetch(&mut conn, &p, fds) {
                            if conn.send(&error_message(&e), &[]).is_err() {
                                return;
                            }
                        }
                    }
                    Err(_) => {
                        let bad = encode_error(
                            "org.varlink.service.InvalidParameter",
                            &serde_json::json!({ "parameter": "parameters" }),
                        );
                        if conn.send(&bad, &[]).is_err() {
                            return;
                        }
                    }
                }
                continue;
            }
            let out = self.answer(&head, &bytes);
            for (message, fds) in out {
                let borrowed: Vec<_> = fds.iter().map(AsFd::as_fd).collect();
                if conn.send(&message, &borrowed).is_err() {
                    return;
                }
            }
        }
    }

    fn answer(self: &Arc<Self>, head: &CallHead, bytes: &[u8]) -> Out {
        let Some(method) = head
            .method
            .strip_prefix(INTERFACE)
            .and_then(|m| m.strip_prefix('.'))
        else {
            return vec![(
                encode_error(
                    "org.varlink.service.InterfaceNotFound",
                    &serde_json::json!({ "interface": head.method }),
                ),
                Vec::new(),
            )];
        };
        let bad = |parameter: &str| {
            vec![(
                encode_error(
                    "org.varlink.service.InvalidParameter",
                    &serde_json::json!({ "parameter": parameter }),
                ),
                Vec::new(),
            )]
        };
        let result: Result<Out, FeedError> = match method {
            "GetInfo" => Ok(vec![(encode_reply(&self.info(), false), Vec::new())]),
            "Connect" => self.connect(),
            "Index" => match call_parameters::<OfLayer>(bytes) {
                Ok(p) => self.index(&p.layer),
                Err(BadCall::InvalidParameter(p)) => return bad(&p),
                Err(BadCall::NotACall(_)) => return bad("parameters"),
            },
            "Release" => match call_parameters::<OfLayer>(bytes) {
                Ok(p) => self.release(&p.layer),
                Err(BadCall::InvalidParameter(p)) => return bad(&p),
                Err(BadCall::NotACall(_)) => return bad("parameters"),
            },
            "Fetch" => Err(FeedError::failed("a fetch is asked for with more")),
            other => {
                return vec![(
                    encode_error(
                        "org.varlink.service.MethodNotFound",
                        &serde_json::json!({ "method": other }),
                    ),
                    Vec::new(),
                )]
            }
        };
        result.unwrap_or_else(|e| vec![(error_message(&e), Vec::new())])
    }

    /// What `GetInfo` answers.
    pub fn info(&self) -> FeedInfo {
        FeedInfo {
            name: "velarx".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            proto: PROTO,
            capabilities: Vec::new(),
            limits: BTreeMap::from([
                ("max_wants".to_string(), MAX_WANTS as u64),
                ("max_fetches".to_string(), u64::from(MAX_FETCHES)),
                ("max_fetch_bytes".to_string(), MAX_FETCH_BYTES),
            ]),
            pull: self.pull.clone(),
            layers: self.layers.iter().map(|l| l.info.clone()).collect(),
        }
    }

    fn layer(&self, key: &str) -> Result<&Layer, FeedError> {
        self.layers
            .iter()
            .find(|l| l.info.key == key)
            .ok_or_else(|| FeedError::UnknownLayer {
                layer: key.chars().take(128).collect(),
            })
    }

    /// Another connection: the reply carries its descriptor, and the feed
    /// serves the other end of the pair as it serves this one.
    fn connect(self: &Arc<Self>) -> Result<Out, FeedError> {
        if self.live.load(Ordering::SeqCst) >= MAX_FETCHES {
            return Err(FeedError::TooMuch {
                reason: format!("at most {MAX_FETCHES} connections at the same time"),
            });
        }
        let (ours, theirs) = UnixStream::pair().map_err(|e| FeedError::failed(e.to_string()))?;
        self.serve(ours)
            .map_err(|e| FeedError::failed(e.to_string()))?;
        Ok(vec![(
            encode_reply(&Ack {}, false),
            vec![OwnedFd::from(theirs)],
        )])
    }

    fn index(&self, key: &str) -> Result<Out, FeedError> {
        let layer = self.layer(key)?;
        let memory = |bytes: &[u8]| {
            velarx_base::sealed::sealed_memory(bytes).map_err(|e| FeedError::failed(e.to_string()))
        };
        let fds = vec![memory(&layer.toc)?, memory(&layer.tarsplit)?];
        Ok(vec![(encode_reply(&Ack {}, false), fds)])
    }

    /// The driver has every file of the layer that it lacks: what the engine
    /// keeps for the layer goes, and a `Fetch` of it is refused.  Idempotent.
    fn release(&self, key: &str) -> Result<Out, FeedError> {
        let layer = self.layer(key)?;
        if !layer.released.swap(true, Ordering::SeqCst) {
            self.engine.feed.release(&layer.graph);
            layer.held.lock().unwrap_or_else(|e| e.into_inner()).clear();
        }
        Ok(vec![(encode_reply(&Ack {}, false), Vec::new())])
    }

    /// A `Fetch`: the checks, then the engine fetches the wants into the
    /// files, and the events go to the driver as the objects are whole.
    fn fetch(&self, conn: &mut Conn, call: &FetchCall, fds: Vec<OwnedFd>) -> Result<(), FeedError> {
        let layer = self.layer(&call.layer)?;
        if layer.released.load(Ordering::SeqCst) {
            return Err(FeedError::failed(format!(
                "the layer {} was released: nothing is kept to fetch from",
                call.layer
            )));
        }
        if call.wants.len() > MAX_WANTS {
            return Err(FeedError::TooMuch {
                reason: format!("at most {MAX_WANTS} wants in a fetch"),
            });
        }
        incoming_files(&fds, true)?;
        let mut seen = HashSet::new();
        let mut files = HashSet::new();
        let mut bytes = 0u64;
        for w in &call.wants {
            let size = layer
                .keys
                .get(&w.key)
                .ok_or_else(|| FeedError::UnknownObject {
                    key: w.key.chars().take(128).collect(),
                })?;
            if *size != w.size {
                return Err(FeedError::UnknownObject {
                    key: format!(
                        "{}: the table of contents says {size} bytes, not {}",
                        w.key.chars().take(128).collect::<String>(),
                        w.size
                    ),
                });
            }
            if !seen.insert(&w.key) {
                return Err(FeedError::TooMuch {
                    reason: format!("the object {} is asked for twice in a call", w.key),
                });
            }
            if let Some(f) = w.file {
                // (the file 0 is the pack file; a file of one object is used
                // by that object alone)
                if f == 0 || f as usize >= fds.len() || !files.insert(f) {
                    return Err(FeedError::BadFile {
                        reason: format!(
                            "the object {} names the file {f}, and the call carries {} files (the file 0 is the pack file; a file holds one object)",
                            w.key,
                            fds.len()
                        ),
                    });
                }
            }
            bytes = bytes.saturating_add(w.size);
        }
        if bytes > MAX_FETCH_BYTES {
            return Err(FeedError::TooMuch {
                reason: format!("{bytes} bytes in a call, at most {MAX_FETCH_BYTES}"),
            });
        }
        // the budget of the layer: twice its planned bytes in all
        layer
            .left
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(bytes))
            .map_err(|left| FeedError::TooMuch {
                reason: format!(
                    "the layer {} was asked for {bytes} bytes more, and {left} are left of twice its {} planned bytes",
                    call.layer, layer.info.size
                ),
            })?;
        let failed = |reason: String| FeedError::failed(reason);
        // the place of each want: its own file, or the pack file one after the
        // other
        let files: Vec<Arc<File>> = fds
            .iter()
            .map(|fd| fd.try_clone().map(|fd| Arc::new(File::from(fd))))
            .collect::<Result<_, _>>()
            .map_err(|e| failed(e.to_string()))?;
        let mut slots = Vec::with_capacity(call.wants.len());
        let mut places = Vec::with_capacity(call.wants.len());
        let mut base = 0u64;
        for w in &call.wants {
            let (n, at) = match w.file {
                Some(f) => (f, 0),
                None => {
                    let at = base;
                    base = (base + w.size).next_multiple_of(PACK_ALIGN);
                    (0, at)
                }
            };
            slots.push((
                w.key.clone(),
                Slot {
                    file: files[n as usize].clone(),
                    base: at,
                    size: w.size,
                },
            ));
            places.push((n, at, w.size));
        }
        let (tx, rx) = std::sync::mpsc::channel::<Told>();
        let sink = {
            let tx = tx.clone();
            FilesSink::holding(
                &self.pull,
                &self.engine.scratch,
                slots,
                move |w| {
                    let _ = tx.send(Told::Written(w));
                },
                self.engine.holds.clone(),
            )
            .map_err(|e| failed(e.to_string()))?
        };
        let into = FilesIncoming::of(&self.pull, sink.clone());
        let (engine, graph) = (self.engine.feed.clone(), layer.graph.clone());
        let _fetching = {
            let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
            if open.closed {
                return Err(failed("the pull is over".into()));
            }
            let end = Ending(Some(tx));
            let task = self.engine.runtime.spawn(async move {
                let done = engine.fetch(&graph, &into).await;
                end.with(done.map(|_| ()));
            });
            open.next += 1;
            let n = open.next;
            open.fetches.insert(n, task.abort_handle());
            Fetching {
                feed: self,
                n,
                task,
            }
        };
        let index: HashMap<&str, usize> = call
            .wants
            .iter()
            .enumerate()
            .map(|(i, w)| (w.key.as_str(), i))
            .collect();
        let mut whole = vec![false; call.wants.len()];
        let mut verdict = None;
        let send = |conn: &mut Conn, event: FetchEvent, continues: bool| {
            conn.send(
                &encode_reply(&Fetched { event: Some(event) }, continues),
                &[],
            )
        };
        while verdict.is_none() {
            let Ok(first) = rx.recv() else { break };
            // (what arrived together is told together)
            let mut holes = Vec::new();
            let mut copies = Vec::new();
            let mut ready = Vec::new();
            let mut handed: Vec<(u32, Arc<File>, String)> = Vec::new();
            for told in std::iter::once(first).chain(std::iter::from_fn(|| rx.try_recv().ok())) {
                match told {
                    Told::Written(Written::Hole { key, at, len }) => {
                        if let Some(&want) = index.get(key.as_str()) {
                            holes.push(Zeros {
                                want: want as u32,
                                at,
                                length: len,
                            });
                        }
                    }
                    Told::Written(Written::Copy {
                        key,
                        at,
                        from,
                        from_offset,
                        len,
                    }) => {
                        if let Some(&want) = index.get(key.as_str()) {
                            self.copied
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(key);
                            copies.push(Copy {
                                want: want as u32,
                                at,
                                from,
                                from_offset,
                                length: len,
                            });
                        }
                    }
                    Told::Written(Written::Whole { key }) => {
                        if let Some(&want) = index.get(key.as_str()) {
                            whole[want] = true;
                            ready.push(want as u32);
                        }
                    }
                    Told::Written(Written::Staged {
                        key,
                        file,
                        verity,
                        layer: staging,
                    }) => {
                        if let Some(&want) = index.get(key.as_str()) {
                            whole[want] = true;
                            handed.push((want as u32, file, verity));
                            let mut held = layer.held.lock().unwrap_or_else(|e| e.into_inner());
                            if !held.iter().any(|h| Arc::ptr_eq(h, &staging)) {
                                held.push(staging);
                            }
                        }
                    }
                    Told::Finished(result) => verdict = Some(result),
                }
            }
            let sent = (|| {
                if !holes.is_empty() {
                    send(
                        conn,
                        FetchEvent {
                            kind: EventKind::Zeros,
                            zeros: holes,
                            ..event(EventKind::Zeros)
                        },
                        true,
                    )?;
                }
                if !copies.is_empty() {
                    send(
                        conn,
                        FetchEvent {
                            kind: EventKind::Copy,
                            copies,
                            ..event(EventKind::Copy)
                        },
                        true,
                    )?;
                }
                // (the files of the objects the engine verified: a message
                // carries at most MAX_FILES descriptors)
                for chunk in handed.chunks(MAX_FILES) {
                    let fds: Vec<std::os::fd::BorrowedFd<'_>> =
                        chunk.iter().map(|(_, f, _)| f.as_fd()).collect();
                    let event = FetchEvent {
                        handed: chunk
                            .iter()
                            .enumerate()
                            .map(|(i, (want, _, verity))| Handed {
                                want: *want,
                                fd: i as u32,
                                verity: verity.clone(),
                            })
                            .collect(),
                        ..event(EventKind::Staged)
                    };
                    conn.send(&encode_reply(&Fetched { event: Some(event) }, true), &fds)?;
                    send(
                        conn,
                        FetchEvent {
                            wants: chunk.iter().map(|(w, _, _)| *w).collect(),
                            ..self::event(EventKind::Complete)
                        },
                        true,
                    )?;
                }
                if !ready.is_empty() {
                    let pieces = ready
                        .iter()
                        .map(|&w| {
                            let (fd, offset, length) = places[w as usize];
                            Piece {
                                want: w,
                                at: 0,
                                region: Region { fd, offset, length },
                            }
                        })
                        .collect();
                    send(
                        conn,
                        FetchEvent {
                            pieces,
                            ..event(EventKind::Ready)
                        },
                        true,
                    )?;
                    send(
                        conn,
                        FetchEvent {
                            wants: ready,
                            ..event(EventKind::Complete)
                        },
                        true,
                    )?;
                }
                Ok::<_, std::io::Error>(())
            })();
            if sent.is_err() {
                // (the driver closed the connection: the call is cancelled,
                // and the fetch stops with `_fetching`)
                return Ok(());
            }
        }
        self.checked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(sink.chunks_checked());
        let result = verdict.unwrap_or_else(|| {
            Err(ImageError::Storage(
                "the fetch of the engine ended without a verdict".into(),
            ))
        });
        let lacking: Vec<u32> = whole
            .iter()
            .enumerate()
            .filter(|(_, w)| !**w)
            .map(|(i, _)| i as u32)
            .collect();
        let lacking_none = result.is_ok() && lacking.is_empty();
        let sent = match result {
            Ok(()) if lacking.is_empty() => Ok(()),
            outcome => {
                let failure = match outcome {
                    Err(e) => {
                        let failure = Failure {
                            class: class_of(&e),
                            reason: e.to_string(),
                        };
                        self.failed
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get_or_insert(e);
                        failure
                    }
                    Ok(()) => Failure {
                        class: FailureClass::Failed,
                        reason:
                            "the engine fetched the layer and did not write every object asked for"
                                .into(),
                    },
                };
                send(
                    conn,
                    FetchEvent {
                        wants: lacking,
                        failure: Some(failure),
                        ..event(EventKind::Failed)
                    },
                    true,
                )
            }
        };
        if lacking_none {
            let mut counts = self.fetched.lock().unwrap_or_else(|e| e.into_inner());
            let c = counts.entry(call.layer.clone()).or_default();
            c.0 += call.wants.len() as u64;
            c.1 += bytes;
        }
        // (the last reply has no record)
        let _ = sent.and_then(|()| conn.send(&encode_reply(&Fetched::default(), false), &[]));
        Ok(())
    }
}

/// A fetch of the engine in progress: stopped when the call that asked for
/// it ends, whatever the way.
struct Fetching<'a> {
    feed: &'a Feed,
    n: u64,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fetching<'_> {
    fn drop(&mut self) {
        self.task.abort();
        self.feed
            .open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .fetches
            .remove(&self.n);
    }
}

/// What the engine's fetch tells the thread that serves the call.
enum Told {
    Written(Written),
    Finished(Result<(), ImageError>),
}

/// The end of the engine's fetch, told to the thread that serves the call:
/// with the fetch's result, or, when the task is dropped before it has one
/// (the pull ended, the task was aborted), as a failure.  The thread would
/// otherwise wait for a verdict that no one sends (the sink of the fetch
/// holds a sender of its own), and hold the pull of the engine open.
struct Ending(Option<std::sync::mpsc::Sender<Told>>);

impl Ending {
    fn with(mut self, result: Result<(), ImageError>) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(Told::Finished(result));
        }
    }
}

impl Drop for Ending {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(Told::Finished(Err(ImageError::Storage(
                "the fetch of the engine was stopped".into(),
            ))));
        }
    }
}

/// An event with nothing in it but its kind.
fn event(kind: EventKind) -> FetchEvent {
    FetchEvent {
        kind,
        pieces: Vec::new(),
        copies: Vec::new(),
        handed: Vec::new(),
        zeros: Vec::new(),
        wants: Vec::new(),
        failure: None,
    }
}

/// What a fetch failed with, for the driver: the class of the party that
/// failed (a chunk that is not what the table of contents says is `invalid`);
/// what the engine itself found wrong (a digest, the spool's refusal for want
/// of free space) is read as the same.
fn class_of(e: &ImageError) -> FailureClass {
    if let Some(class) = e.class() {
        return class;
    }
    match e {
        ImageError::DigestMismatch { .. } | ImageError::Contradicted(_) => FailureClass::Invalid,
        ImageError::Io(e) if e.kind() == std::io::ErrorKind::StorageFull => FailureClass::NoSpace,
        _ => FailureClass::Failed,
    }
}

/// The files of a `Fetch`: the pack file and the files of one object each.
/// Each must be a regular file, empty, open for writing, on a file system
/// whose writes do not block; `pack` says the descriptor 0 must be there.
fn incoming_files(fds: &[OwnedFd], pack: bool) -> Result<(), FeedError> {
    let bad = |reason: String| Err(FeedError::BadFile { reason });
    if pack && fds.is_empty() {
        return bad("the call carries no pack file (the file 0)".into());
    }
    if fds.len() > MAX_FILES {
        return bad(format!(
            "the call carries {} files, at most {MAX_FILES}",
            fds.len()
        ));
    }
    for (n, fd) in fds.iter().enumerate() {
        let file = File::from(fd.try_clone().map_err(|e| FeedError::BadFile {
            reason: e.to_string(),
        })?);
        if let Err(e) = acceptable(&file) {
            return bad(format!("the file {n}: {e}"));
        }
        let meta = file.metadata().map_err(|e| FeedError::BadFile {
            reason: format!("the file {n}: {e}"),
        })?;
        if meta.len() != 0 {
            return bad(format!("the file {n} is not empty ({} bytes)", meta.len()));
        }
        let writable = rustix::fs::fcntl_getfl(&file)
            .is_ok_and(|f| f.intersects(rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR));
        if !writable {
            return bad(format!("the file {n} is not open for writing"));
        }
    }
    Ok(())
}

/// The message of an error of the feed.
pub fn error_message(e: &FeedError) -> Vec<u8> {
    #[derive(Serialize)]
    struct Layer<'a> {
        layer: &'a str,
    }
    #[derive(Serialize)]
    struct Key<'a> {
        key: &'a str,
    }
    #[derive(Serialize)]
    struct Reason<'a> {
        reason: &'a str,
    }
    #[derive(Serialize)]
    struct Failed<'a> {
        failure: &'a velarx_proto::transfer::Failure,
    }
    let name = |n: &str| format!("{INTERFACE}.{n}");
    match e {
        FeedError::UnknownLayer { layer } => encode_error(&name("UnknownLayer"), &Layer { layer }),
        FeedError::UnknownObject { key } => encode_error(&name("UnknownObject"), &Key { key }),
        FeedError::BadFile { reason } => encode_error(&name("BadFile"), &Reason { reason }),
        FeedError::TooMuch { reason } => encode_error(&name("TooMuch"), &Reason { reason }),
        FeedError::Failed { failure } => encode_error(&name("Failed"), &Failed { failure }),
    }
}

#[cfg(test)]
impl Feed {
    /// The connections served now.
    pub(crate) fn connections(&self) -> usize {
        self.open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .streams
            .len()
    }
}

/// The files a peer passes must not be of a file system whose reads can
/// block for good (a fetcher's, a storage driver's).
fn acceptable(file: &File) -> std::io::Result<()> {
    use std::io;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a descriptor that is not a plain file",
        ));
    }
    let fs = rustix::fs::fstatfs(file)?;
    // fuse, nfs, smb2, cifs, 9p, afs, ceph, coda
    const NETWORK: [i64; 8] = [
        0x65735546, 0x6969, 0xfe534d42, 0xff534d42, 0x01021997, 0x5346414f, 0x00c36400, 0x73757245,
    ];
    if NETWORK.contains(&(fs.f_type as i64)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a file of a file system that can block",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod ending_tests {
    use super::*;

    /// A fetch task that is dropped (aborted) before it has a result tells
    /// the thread that waits for it that it failed: the thread ends.
    #[test]
    fn a_fetch_dropped_without_a_result_is_told_as_a_failure() {
        let (tx, rx) = std::sync::mpsc::channel::<Told>();
        // (the sink of the fetch holds a sender too: the channel stays open)
        let _sink = tx.clone();
        drop(Ending(Some(tx)));
        assert!(matches!(rx.recv(), Ok(Told::Finished(Err(_)))));
        let (tx, rx) = std::sync::mpsc::channel::<Told>();
        Ending(Some(tx)).with(Ok(()));
        assert!(matches!(rx.recv(), Ok(Told::Finished(Ok(())))));
        assert!(rx.try_recv().is_err(), "told once");
    }
}
