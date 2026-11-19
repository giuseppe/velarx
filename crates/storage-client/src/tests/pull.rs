// SPDX-License-Identifier: Apache-2.0
//! The pull through the wire: `BeginPull` with the feed on a socket pair, the
//! proof by reading back with the id of the pull, the engine's check, `Commit`
//! and `Abort`; and what the feed refuses.

use super::*;
use crate::fake::Call;
use async_trait::async_trait;
use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use velarx_content::pull::tarsplit::tar::TarReader;
use velarx_content::pull::tarsplit::Recorder;
use velarx_graph::{
    CheckId, Checked, FeedLayer, Identities, LayerArtifact, LayerDone, LayerIndex, PullFeed,
    Settled, Settlement, Verdict,
};
use velarx_types::{ImageError, ImageResult, OciDescriptor};

/// A layer with a directory and a file, as the engine holds it: the table of
/// contents, the tar-split, and the diff id of the tar.
pub(crate) struct Built {
    pub diff: Digest,
    pub toc: velarx_storage::Toc,
    pub tarsplit: Vec<u8>,
    pub content: Vec<u8>,
    pub object: String,
}

pub(crate) fn built() -> Built {
    let content = b"hello, storage driver".to_vec();
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Directory);
    h.set_mode(0o755);
    h.set_size(0);
    b.append_data(&mut h, "d/", &b""[..]).unwrap();
    let mut h = tar::Header::new_gnu();
    h.set_mode(0o644);
    h.set_size(content.len() as u64);
    b.append_data(&mut h, "d/f", &content[..]).unwrap();
    let tar = b.into_inner().unwrap();
    let mut r = TarReader::with_sink(&tar[..], Recorder::new().unwrap());
    while r.next_entry().unwrap().is_some() {}
    let (_, rec) = r.finish().unwrap();
    let object = Digest::of(Algorithm::Sha256, &content).to_string();
    let toc: velarx_storage::Toc = serde_json::from_value(json!({
        "version": 1,
        "entries": [
            {"type": "dir", "name": "d/"},
            {"type": "reg", "name": "d/f", "size": content.len(), "digest": object},
        ]
    }))
    .unwrap();
    Built {
        diff: Digest::of(Algorithm::Sha256, &tar),
        toc,
        tarsplit: rec.finish().unwrap().compressed,
        content,
        object,
    }
}

/// What the engine's side of the pull does, as the driver sees it.
struct TestFeed {
    layers: Vec<(LayerKey, LayerIndex)>,
    /// The bytes of the one object of the layers.
    content: Vec<u8>,
    /// What `fetch` fails with, when it is to.
    fetch_fails: Mutex<Option<ImageError>>,
    /// The wants of each `fetch`, by key.
    fetched: Mutex<Vec<Vec<String>>>,
    began: Mutex<Option<String>>,
    /// How many times the feed was told a layer is released.
    released: AtomicUsize,
    ended: AtomicBool,
    finished: AtomicBool,
    /// An object the fetch asks the sink whether the driver holds, and names
    /// as the source of a copy when it does.
    copy_from: Mutex<Option<String>>,
    /// What the sink answered to that question.
    held: Mutex<Vec<bool>>,
}

#[async_trait]
impl PullFeed for TestFeed {
    async fn begin(&self, into: &Arc<dyn velarx_graph::Incoming>) -> ImageResult<()> {
        // a driver whose store is not the engine's: its files are written
        // where it chose, and the layer is not proved here
        assert!(!into.sink().proves_in_fetch());
        *self.began.lock().unwrap() = Some(into.pull_id());
        Ok(())
    }

    fn parallel(&self) -> usize {
        1
    }

    async fn index(&self, layer: &FeedLayer) -> ImageResult<Option<LayerIndex>> {
        Ok(self
            .layers
            .iter()
            .find(|(k, _)| *k == layer.key)
            .map(|(_, i)| i.clone()))
    }

    async fn fetch(
        &self,
        layer: &FeedLayer,
        into: &Arc<dyn velarx_graph::Incoming>,
    ) -> ImageResult<velarx_content::pull::LayerDone> {
        use std::os::unix::fs::FileExt;
        use velarx_content::pull::sink::Finished;
        let index = self
            .layers
            .iter()
            .find(|(k, _)| *k == layer.key)
            .map(|(_, i)| i.clone())
            .ok_or_else(|| ImageError::Layer("a layer that is not offered".into()))?;
        let sink = into.sink();
        let mut wanted = Vec::new();
        for e in index.toc.entries.iter().filter(|e| e.size > 0) {
            let key = e.content_key().unwrap();
            if !into.wants(&key) {
                continue;
            }
            wanted.push(key.clone());
            if let Some(e) = self.fetch_fails.lock().unwrap().take() {
                return Err(e);
            }
            let place = sink
                .place(&key, e.size)
                .map_err(|e| ImageError::Layer(e.to_string()))?;
            if let Some(from) = self.copy_from.lock().unwrap().clone() {
                let held = sink
                    .held(std::slice::from_ref(&from))
                    .map_err(|e| ImageError::Layer(e.to_string()))?;
                self.held.lock().unwrap().extend(&held);
                if held[0] {
                    sink.copy_chunk(&key, 0, &from, 3, 5)
                        .map_err(|e| ImageError::Layer(e.to_string()))?;
                }
            }
            place
                .file
                .write_all_at(&self.content, place.base)
                .map_err(|e| ImageError::Layer(e.to_string()))?;
            sink.adopt(Finished {
                file: Some(place.file),
                temp: None,
                key,
                name: e.name.clone(),
                size: e.size,
                copy: false,
                verity_keyed: false,
            })
            .map_err(|e| ImageError::Layer(e.to_string()))?;
        }
        self.fetched.lock().unwrap().push(wanted);
        Ok(velarx_content::pull::LayerDone {
            key: layer.key,
            blob: layer.descriptor.digest,
            diff_id: layer.diff_id,
            size: layer.descriptor.size,
            toc: index.toc,
            files: Vec::new(),
            chunks: Vec::new(),
            report: Default::default(),
            tarsplit: index.tarsplit,
            lazy: false,
            proven: false,
            blob_checked: false,
            checked: Default::default(),
        })
    }

    fn release(&self, _layer: &FeedLayer) {
        self.released.fetch_add(1, Ordering::SeqCst);
    }

    async fn finish(&self) -> ImageResult<()> {
        self.finished.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn end(&self) {
        self.ended.store(true, Ordering::SeqCst);
    }
}

fn feed_layer(n: u8, built: &Built, stored: bool) -> FeedLayer {
    FeedLayer {
        key: key(n),
        descriptor: OciDescriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+zstd".into(),
            digest: digest(0x70 + n),
            size: 1234,
            annotations: HashMap::new(),
        },
        diff_id: built.diff,
        chain_id: built.diff,
        parent: None,
        stored,
    }
}

fn feed_of(built: &Built, keys: &[u8]) -> Arc<TestFeed> {
    Arc::new(TestFeed {
        content: built.content.clone(),
        fetch_fails: Mutex::new(None),
        fetched: Mutex::default(),
        layers: keys
            .iter()
            .map(|n| {
                (
                    key(*n),
                    LayerIndex {
                        key: key(*n),
                        toc: Arc::new(built.toc.clone()),
                        tarsplit: built.tarsplit.clone().into(),
                    },
                )
            })
            .collect(),
        began: Mutex::default(),
        released: AtomicUsize::new(0),
        ended: AtomicBool::new(false),
        finished: AtomicBool::new(false),
        copy_from: Mutex::default(),
        held: Mutex::default(),
    })
}

/// What the fake driver does when it is called `BeginPull`.
#[derive(Clone, Copy, PartialEq)]
enum Behavior {
    /// Reads the index, says progress, says staged.
    Good,
    /// Asks the feed what it must not, and writes down what it answered.
    Probes,
    /// Asks the feed to fetch what it lacks, into a file of its own.
    Fetches,
    /// The same, into the pack file.
    FetchesPack,
    /// The first connection is dropped without a reply.
    DiesOnce,
    /// A reply of a kind that is not known.
    NewKind,
    /// Says progress and waits for the engine to hang up.
    Hangs,
}

struct Script {
    behavior: Mutex<Behavior>,
    log: Mutex<Vec<String>>,
    probes: Mutex<Vec<(String, String)>>,
    begins: AtomicUsize,
    /// What a read of the objects answers.
    garble: AtomicBool,
    kept: Mutex<Option<Conn>>,
    object: String,
    content: Vec<u8>,
}

fn feed_call(
    conn: &mut Conn,
    method: &str,
    params: Value,
    more: bool,
    fds: &[std::os::fd::BorrowedFd<'_>],
) -> Result<(Value, Vec<OwnedFd>), (String, Value)> {
    conn.call_raw(
        &format!("org.velarx.StorageFeed.{method}"),
        Some(params.to_string().as_bytes()),
        more,
        fds,
    )
    .unwrap();
    let bytes = conn.message().map_err(|e| (format!("{e}"), Value::Null))?;
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    match v.get("error") {
        Some(e) => Err((
            e.as_str().unwrap().rsplit('.').next().unwrap().to_string(),
            v["parameters"].clone(),
        )),
        None => {
            let mut params = v["parameters"].clone();
            if v["continues"] == true {
                params["_continues"] = json!(true);
            }
            Ok((params, conn.take_fds()))
        }
    }
}

/// The events of a `Fetch` until the last one.
fn fetch_events(
    conn: &mut Conn,
    layer: &str,
    wants: Value,
    fds: &[std::os::fd::BorrowedFd<'_>],
) -> Result<Vec<Value>, (String, Value)> {
    let mut events = Vec::new();
    let (mut v, _) = feed_call(
        conn,
        "Fetch",
        json!({"layer": layer, "wants": wants}),
        true,
        fds,
    )?;
    loop {
        let more = v["_continues"] == true;
        // (the last reply has no event: it is the end)
        match v.get("event") {
            Some(event) => events.push(event.clone()),
            None => assert!(!more, "a reply with no event ends the call"),
        }
        if !more {
            return Ok(events);
        }
        let bytes = conn.message().map_err(|e| (e.to_string(), Value::Null))?;
        let m: Value = serde_json::from_slice(&bytes).unwrap();
        if let Some(e) = m.get("error") {
            return Err((
                e.as_str().unwrap().rsplit('.').next().unwrap().to_string(),
                m["parameters"].clone(),
            ));
        }
        v = m["parameters"].clone();
        if m["continues"] == true {
            v["_continues"] = json!(true);
        }
    }
}

fn start_script(e: &Env, built: &Built, behavior: Behavior) -> Arc<Script> {
    let script = Arc::new(Script {
        behavior: Mutex::new(behavior),
        log: Mutex::default(),
        probes: Mutex::default(),
        begins: AtomicUsize::new(0),
        garble: AtomicBool::new(false),
        kept: Mutex::default(),
        object: built.object.clone(),
        content: built.content.clone(),
    });
    let s = script.clone();
    e.fake.handle(move |c: Call, conn| {
        s.log.lock().unwrap().push(c.method.clone());
        match c.method.as_str() {
            "BeginPull" => begin_pull(&s, c, conn),
            "ReadObjects" => read(&s, c, conn),
            _ => reply(conn, &json!({}), false, &[]),
        }
    });
    script
}

fn read(s: &Script, mut c: Call, conn: &mut Conn) {
    let pipe = std::fs::File::from(c.fds.remove(0));
    let ranges = c.params["ranges"].as_array().unwrap().clone();
    for (i, r) in ranges.iter().enumerate() {
        assert_eq!(r["key"], s.object.as_str(), "the only object there is");
        let (off, len) = (
            r["offset"].as_u64().unwrap() as usize,
            r["length"].as_u64().unwrap() as usize,
        );
        if off + len > s.content.len() {
            error(
                conn,
                "org.velarx.Storage.Corrupt",
                &json!({"reason": "past the end", "remedy": "pull_again"}),
            );
            return;
        }
        reply(conn, &json!({"index": i}), i + 1 < ranges.len(), &[]);
        let mut bytes = s.content.clone();
        if s.garble.load(Ordering::SeqCst) {
            bytes[0] ^= 0xff;
        }
        let off = r["offset"].as_u64().unwrap() as usize;
        let len = r["length"].as_u64().unwrap() as usize;
        (&pipe).write_all(&bytes[off..off + len]).unwrap();
    }
}

fn begin_pull(s: &Script, mut c: Call, conn: &mut Conn) {
    let attempt = s.begins.fetch_add(1, Ordering::SeqCst);
    let feed_fd = c.fds.remove(0);
    let mut feed = Conn::from_stream(UnixStream::from(feed_fd));
    let behavior = *s.behavior.lock().unwrap();
    if behavior == Behavior::DiesOnce && attempt == 0 {
        let _ = conn.socket().shutdown(std::net::Shutdown::Both);
        return;
    }
    let (info, _) = feed_call(&mut feed, "GetInfo", json!({}), false, &[]).unwrap();
    s.probes
        .lock()
        .unwrap()
        .push(("info".into(), info.to_string()));
    let layers = info["layers"].as_array().unwrap().clone();
    let first = layers
        .first()
        .map(|l| l["key"].as_str().unwrap().to_string());
    if let Some(first) = &first {
        let (_, fds) = feed_call(&mut feed, "Index", json!({"layer": first}), false, &[]).unwrap();
        assert_eq!(fds.len(), 2);
        let (toc, tarsplit) = {
            let mut it = fds.into_iter();
            (it.next().unwrap(), it.next().unwrap())
        };
        s.probes.lock().unwrap().push((
            "index".into(),
            format!(
                "{} {} {}",
                rustix::fs::fcntl_get_seals(&toc).unwrap() == velarx_base::sealed::memory_seals(),
                read_bytes(toc).len(),
                read_bytes(tarsplit).len()
            ),
        ));
    }
    reply(
        conn,
        &json!({"kind": "progress", "progress": {"message": "working"}}),
        true,
        &[],
    );
    match behavior {
        Behavior::Probes => {
            probe(s, &mut feed, first.as_deref().unwrap());
            *s.kept.lock().unwrap() = Some(feed);
        }
        Behavior::Fetches => {
            let f = memfd("");
            let own = memfd("");
            let wants = json!([{"key": s.object, "size": s.content.len(), "file": 1}]);
            let r = fetch_events(
                &mut feed,
                first.as_ref().unwrap(),
                wants,
                &[f.as_fd(), own.as_fd()],
            );
            match r {
                Ok(events) => {
                    let kinds: Vec<String> = events
                        .iter()
                        .map(|e| e["kind"].as_str().unwrap_or("").to_string())
                        .collect();
                    s.probes
                        .lock()
                        .unwrap()
                        .push(("fetch events".into(), kinds.join(",")));
                    s.probes.lock().unwrap().push((
                        "fetch copies".into(),
                        events
                            .iter()
                            .flat_map(|e| e["copies"].as_array().cloned().unwrap_or_default())
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(" "),
                    ));
                    s.probes.lock().unwrap().push((
                        "fetch pieces".into(),
                        events
                            .iter()
                            .flat_map(|e| e["pieces"].as_array().cloned().unwrap_or_default())
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(" "),
                    ));
                    s.probes.lock().unwrap().push((
                        "fetch bytes".into(),
                        String::from_utf8(read_bytes(own)).unwrap(),
                    ));
                }
                Err((name, params)) => {
                    error(
                        conn,
                        "org.velarx.Storage.Failed",
                        &json!({"reason": format!("the feed answered {name}: {}", params["reason"].as_str().or(params["failure"]["reason"].as_str()).unwrap_or(""))}),
                    );
                    return;
                }
            }
        }
        Behavior::FetchesPack => {
            // two fetches of the same object into the pack file: the second
            // is a fetch the engine may repeat
            let pack = memfd("");
            let wants = json!([{"key": s.object, "size": s.content.len()}]);
            let events =
                fetch_events(&mut feed, first.as_ref().unwrap(), wants, &[pack.as_fd()]).unwrap();
            s.probes.lock().unwrap().push((
                "pack events".into(),
                events
                    .iter()
                    .map(|e| e["kind"].as_str().unwrap_or("").to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ));
            s.probes.lock().unwrap().push((
                "pack bytes".into(),
                String::from_utf8(read_bytes(pack))
                    .unwrap()
                    .trim_end_matches('\0')
                    .to_string(),
            ));
        }
        Behavior::NewKind => {
            reply(conn, &json!({"kind": "teleported"}), false, &[]);
            return;
        }
        Behavior::Hangs => {
            *s.kept.lock().unwrap() = Some(feed);
            s.log.lock().unwrap().push("hanging".into());
            // until the engine closes the connection of the call
            while conn.message().is_ok() {}
            s.log.lock().unwrap().push("closed".into());
            return;
        }
        _ => {}
    }
    reply(conn, &json!({"kind": "staged"}), false, &[]);
}

fn probe(s: &Script, feed: &mut Conn, layer: &str) {
    let note = |what: &str, r: Result<(Value, Vec<OwnedFd>), (String, Value)>| {
        let text = match r {
            Ok((v, _)) => format!("ok {v}"),
            Err((name, p)) => format!(
                "{name} {}",
                p["reason"]
                    .as_str()
                    .or(p["failure"]["reason"].as_str())
                    .or(p["key"].as_str())
                    .or(p["layer"].as_str())
                    .unwrap_or("")
            ),
        };
        s.probes.lock().unwrap().push((what.to_string(), text));
    };
    let object = s.object.clone();
    let size = s.content.len();
    let want = |k: &str, n: usize| json!({"key": k, "size": n});
    let fetch =
        |feed: &mut Conn, layer: &str, wants: Value, fds: &[std::os::fd::BorrowedFd<'_>]| {
            fetch_events(feed, layer, wants, fds).map(|e| (json!(e), Vec::new()))
        };
    let empty = memfd("");
    let full = memfd("not empty");
    let readonly = std::fs::File::open("/dev/null").unwrap();
    note(
        "unknown layer",
        fetch(feed, "sha256:nope", json!([]), &[empty.as_fd()]),
    );
    note(
        "unknown key",
        fetch(
            feed,
            layer,
            json!([want("sha256:00", size)]),
            &[empty.as_fd()],
        ),
    );
    note(
        "wrong size",
        fetch(
            feed,
            layer,
            json!([want(&object, size + 1)]),
            &[empty.as_fd()],
        ),
    );
    note(
        "no file",
        fetch(feed, layer, json!([want(&object, size)]), &[]),
    );
    note(
        "a file with bytes",
        fetch(feed, layer, json!([want(&object, size)]), &[full.as_fd()]),
    );
    note(
        "a file not for writing",
        fetch(
            feed,
            layer,
            json!([want(&object, size)]),
            &[readonly.as_fd()],
        ),
    );
    let (r, w) = rustix::pipe::pipe().unwrap();
    note(
        "a pipe",
        fetch(feed, layer, json!([want(&object, size)]), &[w.as_fd()]),
    );
    drop(r);
    note("file 0 for an object", {
        fetch(
            feed,
            layer,
            json!([{"key": object, "size": size, "file": 0}]),
            &[empty.as_fd()],
        )
    });
    note("file out of the call", {
        fetch(
            feed,
            layer,
            json!([{"key": object, "size": size, "file": 3}]),
            &[empty.as_fd()],
        )
    });
    note(
        "twice in a call",
        fetch(
            feed,
            layer,
            json!([want(&object, size), want(&object, size)]),
            &[empty.as_fd()],
        ),
    );
    let many: Vec<Value> = (0..4097).map(|_| want(&object, size)).collect();
    note(
        "too many wants",
        fetch(feed, layer, json!(many), &[empty.as_fd()]),
    );
    // twice the planned bytes of the layer: two fetches, and the third is too much
    let (first, pack, own, last) = (memfd(""), memfd(""), memfd(""), memfd(""));
    note(
        "budget 1",
        fetch(feed, layer, json!([want(&object, size)]), &[first.as_fd()]),
    );
    note(
        "a file of its own",
        fetch(
            feed,
            layer,
            json!([{"key": object, "size": size, "file": 1}]),
            &[pack.as_fd(), own.as_fd()],
        ),
    );
    note(
        "budget 3",
        fetch(feed, layer, json!([want(&object, size)]), &[last.as_fd()]),
    );
    // not with more
    let r = feed_call(
        feed,
        "Fetch",
        json!({"layer": layer, "wants": []}),
        false,
        &[empty.as_fd()],
    );
    note("without more", r);
    note(
        "a method it has not",
        feed_call(feed, "Delete", json!({}), false, &[]),
    );
    feed.call_raw("org.velarx.Fetcher.Get", Some(b"{}"), false, &[])
        .unwrap();
    let bytes = feed.message().unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    s.probes
        .lock()
        .unwrap()
        .push(("another interface".into(), v["error"].to_string()));
    // a call the feed does not have
    note(
        "FetchLayer",
        feed_call(
            feed,
            "FetchLayer",
            json!({"layer": layer}),
            true,
            &[empty.as_fd()],
        ),
    );
    // a layer is released once, whatever the times it is said; a fetch of it
    // after is refused; one that is no layer of the pull is unknown
    note(
        "release unknown",
        feed_call(feed, "Release", json!({"layer": "sha256:nope"}), false, &[]),
    );
    note(
        "release",
        feed_call(feed, "Release", json!({"layer": layer}), false, &[]),
    );
    note(
        "release again",
        feed_call(feed, "Release", json!({"layer": layer}), false, &[]),
    );
    note(
        "fetch after release",
        fetch(feed, layer, json!([want(&object, size)]), &[empty.as_fd()]),
    );
    // other connections, up to the most
    let mut conns = Vec::new();
    let mut outcome = String::new();
    for n in 0..9 {
        match feed_call(feed, "Connect", json!({}), false, &[]) {
            Ok((_, mut fds)) => {
                let mut c = Conn::from_stream(UnixStream::from(fds.remove(0)));
                let (info, _) = feed_call(&mut c, "GetInfo", json!({}), false, &[]).unwrap();
                assert_eq!(info["layers"][0]["key"], layer);
                conns.push(c);
            }
            Err((name, _)) => {
                outcome = format!("{name} at {n}");
                break;
            }
        }
    }
    s.probes.lock().unwrap().push(("connect".into(), outcome));
    s.probes
        .lock()
        .unwrap()
        .push(("others".into(), conns.len().to_string()));
}

fn settled_ok(calls: Arc<AtomicUsize>, log: Arc<Script>) -> Settled {
    settled_by(CheckId::fresh(), calls, log)
}

/// The engine's check `check`, which seals its verdict with its id.
fn settled_by(check: CheckId, calls: Arc<AtomicUsize>, log: Arc<Script>) -> Settled {
    Box::new(move |pulled: &mut Vec<LayerDone>, _| {
        calls.fetch_add(1, Ordering::SeqCst);
        log.log.lock().unwrap().push("settled".into());
        let artifacts: HashMap<_, _> = pulled
            .iter()
            .map(|p| {
                (
                    p.key,
                    LayerArtifact {
                        image_digest: "fsverity-sha256-12:aa".into(),
                        owners: "[[0],[0]]".into(),
                    },
                )
            })
            .collect();
        Ok(Settlement {
            verdict: Verdict::sealed(
                &check,
                Checked {
                    layer_keys: pulled.iter().map(|p| p.key).collect(),
                    merged_id: None,
                    stored_erofs: HashMap::new(),
                    ours: artifacts.clone(),
                },
            ),
            identities: Identities {
                artifacts,
                images: HashMap::new(),
            },
        })
    })
}

fn run_pull(
    e: &Env,
    feed: &Arc<TestFeed>,
    layers: &[FeedLayer],
    settled: Settled,
) -> Result<velarx_graph::Pulled, DriverError> {
    let dyn_feed: Arc<dyn PullFeed> = feed.clone();
    futures::executor::block_on(async {
        // (the driver is called from the runtime of the engine)
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let driver = &e.driver;
        let r = rt.block_on(driver.pull(&dyn_feed, layers, settled));
        rt.shutdown_background();
        r
    })
}

/// The pull: the layers of the image, the feed, the proof read back with the
/// id of the pull, the engine's check, `Commit`; the feed is the engine's end
/// of the socket pair and is closed when the pull is over.
#[test]
fn a_pull_is_driven_by_the_driver_proved_by_reading_back_and_committed() {
    let e = env();
    let b = built();
    let script = start_script(&e, &b, Behavior::Probes);
    let feed = feed_of(&b, &[1]);
    let layers = [feed_layer(1, &b, false), feed_layer(2, &b, true)];
    let checks = Arc::new(AtomicUsize::new(0));
    let check = CheckId::fresh();
    let pulled = run_pull(
        &e,
        &feed,
        &layers,
        settled_by(check.clone(), checks.clone(), script.clone()),
    )
    .unwrap();
    // the pull
    assert_eq!(pulled.layers.len(), 1);
    assert_eq!(pulled.layers[0].key, key(1));
    assert!(pulled.artifacts.contains_key(&key(1)));
    // the verdict of the check in the engine's process is what the pull
    // returns (it never crossed the wire)
    let checked = pulled
        .verdict
        .open(&check)
        .expect("the verdict of the check");
    assert_eq!(checked.layer_keys, vec![key(1)]);
    assert_eq!(checked.ours, pulled.artifacts);
    // the file the table of contents knows by the hash of its content is
    // recorded with the fs-verity digest of the bytes the proof read
    let f = pulled.layers[0]
        .toc
        .entries
        .iter()
        .find(|e| e.name == "d/f")
        .unwrap();
    assert_eq!(
        f.verity(),
        Some(velarx_storage::fsverity_digest_of(
            Algorithm::Sha256,
            &b.content
        ))
    );
    assert!(
        pulled.layers[0]
            .files
            .iter()
            .any(|u| u.digest == f.verity().unwrap()),
        "the files of the layer are named by it"
    );
    assert_eq!(checks.load(Ordering::SeqCst), 1);
    let begin = &e.fake.calls_of("BeginPull")[0];
    let id = begin["pull"].as_str().unwrap().to_string();
    assert!(velarx_graph::is_pull_id(&id), "{id}");
    assert_eq!(feed.began.lock().unwrap().as_deref(), Some(id.as_str()));
    assert!(feed.finished.load(Ordering::SeqCst) && feed.ended.load(Ordering::SeqCst));
    // the whole ordered list, with what is stored
    let sent = begin["layers"].as_array().unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(
        (sent[0]["stored"].as_bool(), sent[1]["stored"].as_bool()),
        (Some(false), Some(true))
    );
    assert_eq!(sent[1]["key"], key(2).to_string());
    assert_eq!(begin["store"], e.driver.store().as_str());
    // the proof reads what the pull staged, by its id, before the engine's
    // check and before the commit
    let reads = e.fake.calls_of("ReadObjects");
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0]["pull"], id.as_str());
    let order = script.log.lock().unwrap().clone();
    let at = |m: &str| {
        order
            .iter()
            .position(|x| x == m)
            .unwrap_or_else(|| panic!("{m} {order:?}"))
    };
    assert!(
        at("BeginPull") < at("ReadObjects")
            && at("ReadObjects") < at("settled")
            && at("settled") < at("Commit")
    );
    assert!(!order.contains(&"Abort".to_string()));
    let commit = &e.fake.calls_of("Commit")[0];
    assert_eq!(commit["pull"], id.as_str());
    assert_eq!(
        commit["layers"].as_array().unwrap().len(),
        1,
        "the layers the pull brought in"
    );
    // what the feed told and refused
    let probes = script.probes.lock().unwrap().clone();
    let p = |what: &str| {
        probes
            .iter()
            .find(|(w, _)| w == what)
            .unwrap_or_else(|| panic!("{what} {probes:?}"))
            .1
            .clone()
    };
    let info: Value = serde_json::from_str(&p("info")).unwrap();
    assert_eq!(info["pull"], id.as_str());
    assert_eq!(
        info["layers"].as_array().unwrap().len(),
        1,
        "the layers to fetch only"
    );
    assert_eq!(info["limits"]["max_wants"], 4096);
    assert!(p("index").starts_with("true "), "sealed: {}", p("index"));
    assert_eq!(
        p("index")
            .split(' ')
            .nth(1)
            .unwrap()
            .parse::<u64>()
            .unwrap(),
        info["layers"][0]["toc_length"].as_u64().unwrap()
    );
    assert!(
        p("unknown layer").starts_with("UnknownLayer"),
        "{}",
        p("unknown layer")
    );
    assert!(
        p("unknown key").starts_with("UnknownObject"),
        "{}",
        p("unknown key")
    );
    assert!(
        p("wrong size").starts_with("UnknownObject"),
        "{}",
        p("wrong size")
    );
    for bad in [
        "no file",
        "a file with bytes",
        "a file not for writing",
        "a pipe",
        "file 0 for an object",
        "file out of the call",
    ] {
        assert!(p(bad).starts_with("BadFile"), "{bad}: {}", p(bad));
    }
    for much in ["twice in a call", "too many wants", "budget 3"] {
        assert!(p(much).starts_with("TooMuch"), "{much}: {}", p(much));
    }
    // the checks pass and the engine writes: the last reply has no event
    for fetched in ["budget 1", "a file of its own"] {
        assert!(
            p(fetched).starts_with("ok") && p(fetched).contains("\"kind\":\"complete\""),
            "{fetched}: {}",
            p(fetched)
        );
    }
    assert!(p("without more").starts_with("Failed") && p("without more").contains("with more"));
    assert!(
        p("a method it has not").starts_with("MethodNotFound"),
        "{}",
        p("a method it has not")
    );
    assert!(
        p("another interface").contains("InterfaceNotFound"),
        "{}",
        p("another interface")
    );
    assert!(
        p("FetchLayer").starts_with("MethodNotFound"),
        "{}",
        p("FetchLayer")
    );
    assert!(
        p("release unknown").starts_with("UnknownLayer"),
        "{}",
        p("release unknown")
    );
    assert!(p("release").starts_with("ok"), "{}", p("release"));
    assert!(
        p("release again").starts_with("ok"),
        "{}",
        p("release again")
    );
    assert!(
        p("fetch after release").starts_with("Failed")
            && p("fetch after release").contains("released"),
        "{}",
        p("fetch after release")
    );
    assert_eq!(feed.released.load(Ordering::SeqCst), 1);
    assert!(p("connect").starts_with("TooMuch"), "{}", p("connect"));
    assert_eq!(p("others"), "7");
    // the feed is closed with the pull
    let mut kept = script.kept.lock().unwrap().take().unwrap();
    let gone = kept.call_bare("org.velarx.StorageFeed.GetInfo").is_err() || kept.message().is_err();
    assert!(gone, "the feed is still open after the pull");
}

#[test]
fn a_pull_that_fails_is_aborted_and_publishes_nothing() {
    let b = built();
    // the proof finds what the driver stored is not the layer
    let e = env();
    let script = start_script(&e, &b, Behavior::Good);
    script.garble.store(true, Ordering::SeqCst);
    let feed = feed_of(&b, &[1]);
    let checks = Arc::new(AtomicUsize::new(0));
    let err = expect_err(
        run_pull(
            &e,
            &feed,
            &[feed_layer(1, &b, false)],
            settled_ok(checks.clone(), script.clone()),
        )
        .map(|_| ()),
        "garbled",
    );
    assert!(
        matches!(
            err.kind,
            DriverErrorKind::Corrupt {
                remedy: Remedy::PullAgain
            }
        ),
        "{err:?}"
    );
    assert_eq!(
        checks.load(Ordering::SeqCst),
        0,
        "the engine's check comes after the proof"
    );
    let order = script.log.lock().unwrap().clone();
    assert!(
        order.contains(&"Abort".to_string()) && !order.contains(&"Commit".to_string()),
        "{order:?}"
    );
    assert_eq!(
        e.fake.calls_of("Abort")[0]["pull"],
        e.fake.calls_of("BeginPull")[0]["pull"]
    );
    assert!(feed.ended.load(Ordering::SeqCst));
    // the engine's check refuses: nothing is published
    let e = env();
    let script = start_script(&e, &b, Behavior::Good);
    let feed = feed_of(&b, &[1]);
    let refuse: Settled =
        Box::new(|_, _| Err(ImageError::Contradicted("the manifest lies".into())));
    let err = expect_err(
        run_pull(&e, &feed, &[feed_layer(1, &b, false)], refuse).map(|_| ()),
        "refused",
    );
    assert!(matches!(err.kind, DriverErrorKind::Refused(_)), "{err:?}");
    let order = script.log.lock().unwrap().clone();
    assert!(
        order.contains(&"Abort".to_string()) && !order.contains(&"Commit".to_string()),
        "{order:?}"
    );
    // the driver asks the feed to fetch, and the engine's fetch fails with
    // its verdict: the pull is refused with that verdict, not with what the
    // driver says after it
    let e = env();
    let script = start_script(&e, &b, Behavior::Fetches);
    let feed = feed_of(&b, &[1]);
    *feed.fetch_fails.lock().unwrap() = Some(ImageError::Contradicted("the bytes lie".into()));
    let checks = Arc::new(AtomicUsize::new(0));
    let err = expect_err(
        run_pull(
            &e,
            &feed,
            &[feed_layer(1, &b, false)],
            settled_ok(checks.clone(), script.clone()),
        )
        .map(|_| ()),
        "fetch",
    );
    assert!(matches!(err.kind, DriverErrorKind::Refused(_)), "{err:?}");
    assert!(err.message().contains("the bytes lie"), "{err}");
    assert_eq!(checks.load(Ordering::SeqCst), 0, "the check was not run");
    assert!(script.log.lock().unwrap().contains(&"Abort".to_string()));
    // a kind of reply that is not known
    let e = env();
    let script = start_script(&e, &b, Behavior::NewKind);
    let feed = feed_of(&b, &[1]);
    let checks = Arc::new(AtomicUsize::new(0));
    let err = expect_err(
        run_pull(
            &e,
            &feed,
            &[feed_layer(1, &b, false)],
            settled_ok(checks, script),
        )
        .map(|_| ()),
        "kind",
    );
    assert!(matches!(err.kind, DriverErrorKind::Storage), "{err:?}");
    assert!(err.message().contains("teleported"), "{err}");
    // a feed that cannot index a layer: refused by name before the driver is
    // asked anything
    let e = env();
    let script = start_script(&e, &b, Behavior::Good);
    let feed = feed_of(&b, &[]);
    let checks = Arc::new(AtomicUsize::new(0));
    let err = expect_err(
        run_pull(
            &e,
            &feed,
            &[feed_layer(1, &b, false)],
            settled_ok(checks, script),
        )
        .map(|_| ()),
        "stream",
    );
    assert!(matches!(err.kind, DriverErrorKind::Unsupported), "{err:?}");
    assert!(err.message().contains("cannot be indexed"), "{err}");
    assert!(e.fake.calls_of("BeginPull").is_empty());
    assert!(feed.ended.load(Ordering::SeqCst));
}

/// A driver that opens feed connections and closes them over and over holds
/// no descriptor of the engine's, and nothing is served after the pull.
#[test]
fn feed_connections_are_forgotten_when_they_end() {
    let b = built();
    let index = LayerIndex {
        key: key(1),
        toc: Arc::new(b.toc.clone()),
        tarsplit: b.tarsplit.clone().into(),
    };
    let indexed = vec![(feed_layer(1, &b, false), index)];
    let engine = crate::feed::Engine {
        feed: feed_of(&b, &[1]),
        runtime: tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .handle()
            .clone(),
        scratch: std::env::temp_dir(),
        holds: None,
    };
    let served =
        crate::feed::Feed::new("0123456789abcdef0123456789abcdef", engine, indexed).unwrap();
    for _ in 0..3 * crate::feed_proto::MAX_FETCHES {
        let (mine, theirs) = UnixStream::pair().unwrap();
        served.serve(mine).unwrap();
        let mut c = Conn::from_stream(theirs);
        c.set_deadline(Instant::now() + Duration::from_secs(5));
        c.call_bare("org.velarx.StorageFeed.Connect").unwrap();
        c.message().unwrap();
        let extra = c.take_fds();
        assert_eq!(extra.len(), 1);
        assert_eq!(served.connections(), 2);
        drop((c, extra));
        // (both connections end, and leave)
        let waited = Instant::now();
        while served.connections() > 0 {
            assert!(
                waited.elapsed() < Duration::from_secs(5),
                "{} connections still held",
                served.connections()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    served.shutdown();
    let (mine, _theirs) = UnixStream::pair().unwrap();
    assert!(served.serve(mine).is_err());
}

/// A driver that goes away is asked once more with the same pull id: it
/// resumes what it staged.
#[test]
fn a_driver_that_goes_away_is_asked_again_with_the_same_pull() {
    let e = env();
    let b = built();
    let script = start_script(&e, &b, Behavior::DiesOnce);
    let feed = feed_of(&b, &[1]);
    let checks = Arc::new(AtomicUsize::new(0));
    run_pull(
        &e,
        &feed,
        &[feed_layer(1, &b, false)],
        settled_ok(checks.clone(), script),
    )
    .unwrap();
    let begins = e.fake.calls_of("BeginPull");
    assert_eq!(begins.len(), 2);
    assert_eq!(begins[0]["pull"], begins[1]["pull"]);
    assert_eq!(checks.load(Ordering::SeqCst), 1);
}

/// Every layer stored: nothing is fetched, the driver is told so, and the
/// pull still goes through the check.
#[test]
fn a_pull_of_stored_layers_fetches_nothing() {
    let e = env();
    let b = built();
    let script = start_script(&e, &b, Behavior::Good);
    let feed = feed_of(&b, &[]);
    let checks = Arc::new(AtomicUsize::new(0));
    let pulled = run_pull(
        &e,
        &feed,
        &[feed_layer(1, &b, true)],
        settled_ok(checks.clone(), script.clone()),
    )
    .unwrap();
    assert!(pulled.layers.is_empty());
    assert_eq!(checks.load(Ordering::SeqCst), 1);
    assert!(e.fake.calls_of("ReadObjects").is_empty());
    let info: Value = serde_json::from_str(&script.probes.lock().unwrap()[0].1).unwrap();
    assert!(info["layers"].as_array().unwrap().is_empty());
}

/// A pull that the engine cancels (its future is dropped) closes the
/// connection of `BeginPull` and the feed: the driver sees both closed and
/// drops what it did not stage.
#[test]
fn a_cancelled_pull_closes_the_call_and_the_feed() {
    let e = Arc::new(env());
    let b = built();
    let script = start_script(&e, &b, Behavior::Hangs);
    let feed = feed_of(&b, &[1]);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let layer = feed_layer(1, &b, false);
    let task = {
        let (e, feed, script) = (e.clone(), feed.clone(), script.clone());
        rt.spawn(async move {
            let dyn_feed: Arc<dyn PullFeed> = feed;
            let settled = settled_ok(Arc::new(AtomicUsize::new(0)), script);
            e.driver.pull(&dyn_feed, &[layer], settled).await
        })
    };
    let waited = Instant::now();
    while !script.log.lock().unwrap().contains(&"hanging".to_string()) {
        assert!(
            waited.elapsed() < Duration::from_secs(5),
            "the driver was never called"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    task.abort();
    let waited = Instant::now();
    while !script.log.lock().unwrap().contains(&"closed".to_string()) {
        assert!(
            waited.elapsed() < Duration::from_secs(5),
            "the call was not closed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut kept = script.kept.lock().unwrap().take().unwrap();
    kept.set_deadline(Instant::now() + Duration::from_secs(5));
    match kept.message() {
        Err(velarx_wire::varlink::CallError::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof, "{e}")
        }
        other => panic!("the feed is still open: {other:?}"),
    }
    assert!(e.fake.calls_of("Commit").is_empty());
    rt.shutdown_background();
}

/// A driver that asks for a file gets it written where it chose, and is told:
/// `zeros` for holes, `ready` with the place of each object, `complete`, `done`.
/// The pull then goes on as one that has all it needs.
#[test]
fn the_engine_writes_the_files_a_driver_asks_for() {
    let b = built();
    for (behavior, events, bytes) in [
        (Behavior::Fetches, "fetch events", "fetch bytes"),
        (Behavior::FetchesPack, "pack events", "pack bytes"),
    ] {
        let e = env();
        let script = start_script(&e, &b, behavior);
        let feed = feed_of(&b, &[1]);
        let checks = Arc::new(AtomicUsize::new(0));
        run_pull(
            &e,
            &feed,
            &[feed_layer(1, &b, false)],
            settled_ok(checks.clone(), script.clone()),
        )
        .expect("a pull that fetches");
        let probes = script.probes.lock().unwrap().clone();
        let p = |n: &str| probes.iter().find(|(w, _)| w == n).map(|(_, t)| t.clone());
        assert_eq!(p(events).as_deref(), Some("ready,complete"));
        assert_eq!(
            p(bytes).as_deref(),
            Some(String::from_utf8(b.content.clone()).unwrap().as_str())
        );
        assert_eq!(
            feed.fetched.lock().unwrap().clone(),
            vec![vec![b.object.clone()]]
        );
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        let log = script.log.lock().unwrap().clone();
        assert!(log.contains(&"Commit".to_string()), "{log:?}");
    }
}

/// A driver that says it holds objects is asked which of the objects a chunk
/// is in it holds (`HasObjects`), and is told to copy the chunk from one it
/// does (`copy` before `ready`); a driver that says nothing is asked nothing
/// and told nothing.  The object the driver was told to copy into is checked
/// against its key when the layer is read back.
#[test]
fn a_driver_that_holds_objects_is_told_to_copy_a_chunk_from_one() {
    let mut b = built();
    // (a file of one chunk with a digest: where it is, is recorded)
    for e in b.toc.entries.iter_mut().filter(|e| e.size > 0) {
        e.chunk_digest = Some(b.object.clone());
    }
    for (objects, garble) in [(None, false), (Some(true), false), (Some(true), true)] {
        let fake = crate::fake::Fake::start();
        if objects == Some(true) {
            fake.info.lock().unwrap()["capabilities"]
                .as_array_mut()
                .unwrap()
                .push(json!("objects"));
        }
        let e = env_over(fake, Duration::from_secs(5));
        let script = start_script(&e, &b, Behavior::Fetches);
        script.garble.store(garble, Ordering::SeqCst);
        let held = "fsverity-sha256-12:".to_string() + &"ab".repeat(32);
        e.fake.handle({
            let s = script.clone();
            let held = held.clone();
            move |c: Call, conn| {
                s.log.lock().unwrap().push(c.method.clone());
                match c.method.as_str() {
                    "BeginPull" => begin_pull(&s, c, conn),
                    "ReadObjects" => read(&s, c, conn),
                    "HasObjects" => {
                        let asked = c.params["objects"].as_array().unwrap().clone();
                        let have: Vec<bool> = asked.iter().map(|k| k == &json!(held)).collect();
                        reply(conn, &json!({ "have": have }), false, &[]);
                    }
                    _ => reply(conn, &json!({}), false, &[]),
                }
            }
        });
        let feed = feed_of(&b, &[1]);
        *feed.copy_from.lock().unwrap() = Some(held.clone());
        let checks = Arc::new(AtomicUsize::new(0));
        let pulled = run_pull(
            &e,
            &feed,
            &[feed_layer(1, &b, false)],
            settled_ok(checks.clone(), script.clone()),
        );
        let probes = script.probes.lock().unwrap().clone();
        let p = |n: &str| probes.iter().find(|(w, _)| w == n).map(|(_, t)| t.clone());
        let asked: Vec<Value> = e
            .fake
            .calls_of("HasObjects")
            .into_iter()
            .map(|c| c["objects"].clone())
            .collect();
        if objects.is_none() {
            let pulled = pulled.expect("a pull");
            assert_eq!(
                pulled.layers[0].chunks.len(),
                1,
                "the chunk of an object the engine wrote is recorded"
            );
            assert!(asked.is_empty(), "nothing is asked: {asked:?}");
            assert_eq!(*feed.held.lock().unwrap(), [false]);
            assert_eq!(p("fetch events").as_deref(), Some("ready,complete"));
            continue;
        }
        assert_eq!(asked, vec![json!([held])]);
        assert_eq!(*feed.held.lock().unwrap(), [true]);
        assert_eq!(p("fetch events").as_deref(), Some("copy,ready,complete"));
        if garble {
            // (the bytes the driver gives back are not the object its key
            // names: refused when the object is read back, before the diff
            // id of the layer is looked at)
            let Err(err) = pulled else {
                panic!("a copied object that is not its key is refused")
            };
            assert!(!err.message().contains("hashes to"), "{err}");
            continue;
        }
        let pulled = pulled.expect("a pull");
        assert!(
            pulled.layers[0].chunks.is_empty(),
            "an object the driver copied into gives no chunk records: {:?}",
            pulled.layers[0].chunks
        );
        assert_eq!(
            p("fetch copies").as_deref(),
            Some(
                format!(r#"{{"at":0,"from":"{held}","from_offset":3,"length":5,"want":0}}"#)
                    .as_str()
            )
        );
    }
}
