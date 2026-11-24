// SPDX-License-Identifier: Apache-2.0
//! The pull: `BeginPull` drives the vfs driver's pull through the feed of the
//! engine, replies `staged` once every object is in the store, and waits for
//! the engine's `Commit` or `Abort`; `ReadObjects` reads what was staged or
//! committed.
//!
//! A layer is fetched by one pull at a time: a pull that needs a layer
//! another live pull holds waits for it (telling the engine it goes on), and
//! then finds it committed, or fetches it itself when the other was aborted.
//! So a layer two concurrent pulls share is fetched at most once.

use crate::feed::{Feed, WireFeed};
use crate::service::{failed, reply, Call, Server, NAME};
use crate::store::Store;
use std::collections::HashMap;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::Instant;
use velarx_content::pull::LayerDone;
use velarx_graph::{
    CheckId, Checked, DriverError, DriverErrorKind, DriverResult, FeedLayer, Identities,
    LayerArtifact, ObjectRange, ObjectSink, PullFeed, Settled, Settlement, StorageDriver, Verdict,
};
use velarx_pull_core::{Asked, Begin, Claim, Commit, Why};
use velarx_storage_client::convert;
use velarx_storage_client::proto::{self, PullEventKind};
use velarx_storage_client::request;
use velarx_types::digest::Digest;
use velarx_types::{ImageError, ImageResult, LayerKey, OciDescriptor};
use velarx_wire::varlink::{encode_reply, Conn};

type Out = Vec<(Vec<u8>, Vec<OwnedFd>)>;

enum Event {
    Staged,
    Finished(Result<(), String>),
}

/// The identity the server makes of each layer from its table of contents,
/// which the engine checks again (`Repair` says the same), and the verdict
/// the vfs driver under the server hands back (the server is not the engine:
/// its verdict is its own identities, the keys it pulled, no merged image and
/// no stored ones, and `publish` does not read it).
fn settle(pulled: &[LayerDone]) -> ImageResult<Settlement> {
    let mut ids = Identities::default();
    for l in pulled {
        let id = velarx_fuse::layer_erofs::layer_identity(l.key.digest().alg(), &l.toc.entries)
            .map_err(ImageError::Layer)?;
        ids.artifacts.insert(
            l.key,
            LayerArtifact {
                image_digest: id.erofs,
                owners: id.owners,
            },
        );
    }
    let verdict = Verdict::sealed(
        &CheckId::fresh(),
        Checked {
            layer_keys: pulled.iter().map(|l| l.key).collect(),
            merged_id: None,
            stored_erofs: HashMap::new(),
            ours: ids.artifacts.clone(),
        },
    );
    Ok(Settlement {
        identities: ids,
        verdict,
    })
}

fn feed_layer(l: &proto::PullLayer, stored: bool) -> DriverResult<FeedLayer> {
    let r = convert::layer_ref(&proto::LayerRef {
        key: l.key.clone(),
        diff_id: l.diff_id.clone(),
        chain_id: l.chain_id.clone(),
    })?;
    Ok(FeedLayer {
        descriptor: OciDescriptor {
            media_type: String::new(),
            digest: *r.key.digest(),
            size: 0,
            annotations: Default::default(),
        },
        key: r.key,
        diff_id: r.diff_id,
        chain_id: r.chain_id,
        parent: match &l.parent {
            Some(p) => Some(
                p.parse::<Digest>()
                    .map_err(|_| failed(format!("{p:?} is no chain id")))?,
            ),
            None => None,
        },
        stored,
    })
}

impl Server {
    pub(crate) fn begin_pull(
        self: &Arc<Self>,
        mut call: Call<'_>,
        conn: &mut Conn,
    ) -> DriverResult<Out> {
        let p: request::BeginPull<String, Vec<proto::PullLayer>> = call.params()?;
        let store = self.store(&call, &p.store)?;
        if !velarx_graph::is_pull_id(&p.pull) {
            return Err(failed(format!("{:?} is not a pull id", p.pull)));
        }
        if call.fds.len() != 1 {
            return Err(failed("BeginPull carries the feed as its descriptor 0"));
        }
        let feed_stream = UnixStream::from(call.fds.remove(0));
        let interval = velarx_graph::longcall::progress_interval(self.config.timeout);
        let progress = |conn: &mut Conn, what: &str| {
            conn.send(
                &encode_reply(
                    &proto::PullEvent {
                        kind: PullEventKind::Progress.into(),
                        progress: Some(proto::Progress {
                            message: Some(what.to_string()),
                            ..Default::default()
                        }),
                    },
                    true,
                ),
                &[],
            )
        };
        // the layers it fetches: those not stored, each once
        let mut layers: Vec<FeedLayer> = p
            .layers
            .iter()
            .map(|l| feed_layer(l, l.stored))
            .collect::<DriverResult<_>>()?;
        let mut mine: Vec<String> = layers
            .iter()
            .filter(|l| !l.stored)
            .map(|l| l.key.to_string())
            .collect();
        mine.sort();
        mine.dedup();
        // all or nothing, so that two pulls cannot hold one layer each and
        // wait for the other's
        let n = {
            let mut st = store.state();
            // (the outcomes of old pulls go: the map does not grow with every
            // pull the server ever ran)
            if let Some(before) = Instant::now().checked_sub(self.config.decision) {
                st.forget_ended(before);
            }
            // (a pull with this id that the server has resumes)
            let n = match st.begin(&p.pull) {
                Begin::Started(n) => n,
                Begin::Resumed => return Ok(staged()),
                Begin::Busy => {
                    return Err(DriverError::of(
                        NAME,
                        DriverErrorKind::Busy,
                        format!("the pull {} is running", p.pull),
                    ))
                }
            };
            loop {
                match st.claim(n, &mine) {
                    Claim::Yes => break n,
                    Claim::Wait => {}
                    Claim::Stopped => {
                        st.pulls.remove(&p.pull);
                        st.core.forget(n);
                        store.notify();
                        return Err(failed("the pull was cancelled"));
                    }
                }
                st = store.wait(st, interval);
                if progress(conn, "waiting for a pull of the same layers").is_err() {
                    st.core.stop(n, Why::Gone);
                }
            }
        };
        // a layer committed while it waited is not fetched
        let refs: Vec<velarx_graph::LayerRef> = layers
            .iter()
            .map(|l| velarx_graph::LayerRef {
                key: l.key,
                diff_id: l.diff_id,
                chain_id: l.chain_id,
            })
            .collect();
        let have = self.rt.block_on(store.vfs.has_layers(&refs));
        let have = match have {
            Ok(h) => h,
            Err(e) => {
                release(&store, &p.pull, Err(e.message().to_string()));
                return Err(e);
            }
        };
        for (l, h) in layers.iter_mut().zip(have) {
            l.stored |= h;
        }
        let wire = match WireFeed::open(store.clone(), &p.pull, feed_stream) {
            Ok(w) => Arc::new(w),
            Err(e) => {
                release(&store, &p.pull, Err(e.to_string()));
                return Err(failed(e));
            }
        };
        let (tx, rx): (Sender<Event>, Receiver<Event>) = std::sync::mpsc::channel();
        let decision = self.config.decision;
        let settled: Settled = {
            let (store, id, tx, wire) = (store.clone(), p.pull.clone(), tx.clone(), wire.clone());
            Box::new(move |pulled: &mut Vec<LayerDone>, objects| {
                let settlement = settle(pulled)?;
                // (the files are named in the store once the engine commits:
                // until then the engine reads them where they are)
                let staged = pulled
                    .iter()
                    .flat_map(|l| l.toc.entries.iter())
                    .filter_map(|e| e.verity())
                    .filter_map(|v| Some((v.clone(), objects(&v)?)))
                    .collect();
                store.state().staged.insert(id.clone(), staged);
                let _unstage = Unstage(&store, &id);
                // (before the engine reads the layers back by the keys it
                // knows)
                for l in pulled.iter() {
                    let handed = wire.index_blocking(&l.key.to_string())?;
                    store
                        .record_aliases(&handed.toc.entries, &l.toc.entries)
                        .map_err(|e| ImageError::Storage(e.message().to_string()))?;
                }
                // (a pull that was stopped meanwhile is not staged)
                let staged = store.state().core.staged(n);
                if staged {
                    store.notify();
                    let _ = tx.send(Event::Staged);
                }
                let until = Instant::now() + decision;
                // (the engine keeps the feed open until it has decided: the
                // watch wakes the wait below when it closes it)
                let _watch = wire
                    .watch_engine({
                        let store = store.clone();
                        move || {
                            // (under the lock the wait takes: a close between its
                            // look and its sleep is not lost)
                            let _st = store.state();
                            store.notify();
                        }
                    })
                    .map_err(|e| ImageError::Layer(format!("watch the engine's feed: {e}")))?;
                let mut st = store.state();
                loop {
                    match st.core.asked(n) {
                        Asked::Publish => return Ok(settlement),
                        Asked::Stop(why) => return Err(ImageError::Layer(reason(why).into())),
                        Asked::Wait => {}
                    }
                    // (the engine keeps the feed open until it has decided: a
                    // feed that is closed is an engine that is gone, and its
                    // claims go now, not in `decision` seconds)
                    if wire.engine_gone() {
                        st.core.stop(n, Why::Gone);
                        continue;
                    }
                    let left = until.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        st.core.stop(n, Why::Late);
                        continue;
                    }
                    st = store.wait(st, left);
                }
            })
        };
        let task = {
            let (store, id, wire) = (store.clone(), p.pull.clone(), wire.clone());
            self.rt.spawn(async move {
                let feed: Arc<dyn PullFeed> = Arc::new(Feed(wire.clone()));
                let result = store.vfs.pull(&feed, &layers, settled).await;
                let outcome = match result {
                    Ok(pulled) => publish(&store, pulled.layers, pulled.artifacts).await,
                    Err(e) => Err(e.message().to_string()),
                };
                {
                    let mut st = store.state();
                    if let Some(pull) = st.pulls.get_mut(&id) {
                        pull.keys.extend(wire.fetched());
                    }
                }
                // (it may read the database: not on a thread of the runtime)
                let ended = {
                    let (store, id, outcome) = (store.clone(), id.clone(), outcome.clone());
                    tokio::task::spawn_blocking(move || release(&store, &id, outcome)).await
                };
                let _ = ended;
                let _ = tx.send(Event::Finished(outcome));
            })
        };
        loop {
            match rx.recv_timeout(interval) {
                Ok(Event::Staged) => return Ok(staged()),
                Ok(Event::Finished(Ok(()))) => return Ok(staged()),
                Ok(Event::Finished(Err(e))) => return Err(failed(e)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if progress(conn, "fetching").is_err() {
                        // (the engine went away)
                        task.abort();
                        release(&store, &p.pull, Err("the pull was cancelled".into()));
                        return Err(failed("the pull was cancelled"));
                    }
                }
                Err(_) => return Err(failed("the pull ended without a result")),
            }
        }
    }

    pub(crate) fn commit(&self, call: Call<'_>) -> DriverResult<Out> {
        let p: request::Commit<String, Vec<proto::LayerRef>> = call.params()?;
        let store = self.store(&call, &p.store)?;
        let refs = crate::service::refs(&p.layers)?;
        // a layer committed with another diff id is not this one
        let states = self
            .rt
            .block_on(
                store
                    .db
                    .get_own_layer_states(&refs.iter().map(|r| r.key).collect::<Vec<_>>()),
            )
            .map_err(failed)?;
        for r in &refs {
            if let Some(s) = states.iter().find(|s| s.key == r.key) {
                if !s.matches_diff_id(&r.diff_id) {
                    return Err(DriverError::of(
                        NAME,
                        DriverErrorKind::Busy,
                        format!("the layer {} is committed with another diff id", r.key),
                    ));
                }
            }
        }
        let mut st = store.state();
        let Some(n) = st.pulls.get(&p.pull).map(|pull| pull.n) else {
            // (committed already, by this pull or another)
            let all = self.rt.block_on(store.vfs.has_layers(&refs))?;
            return if all.iter().all(|h| *h) {
                Ok(reply(&proto::Ack {}))
            } else {
                Err(DriverError::of(
                    NAME,
                    DriverErrorKind::NotFound,
                    format!("the pull {} is not there", p.pull),
                ))
            };
        };
        let mut asked = st.core.commit(n);
        store.notify();
        let until = Instant::now() + self.config.decision;
        loop {
            match asked {
                Commit::Over(None) => return Ok(reply(&proto::Ack {})),
                Commit::Over(Some(_)) => return Err(failed(&st.pulls[&p.pull].error)),
                Commit::Early => {
                    return Err(DriverError::of(
                        NAME,
                        DriverErrorKind::Busy,
                        format!("the pull {} is not staged yet", p.pull),
                    ))
                }
                Commit::Unknown => return Err(failed("the pull is gone")),
                Commit::Wait => {}
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(failed("the pull did not end"));
            }
            st = store.wait(st, left);
            asked = st.core.commit(n);
        }
    }

    pub(crate) fn abort(&self, call: Call<'_>) -> DriverResult<Out> {
        let p: request::OfPull<String> = call.params()?;
        let store = self.store(&call, &p.store)?;
        let mut st = store.state();
        let Some(n) = st.pulls.get(&p.pull).map(|pull| pull.n) else {
            return Ok(reply(&proto::Ack {}));
        };
        st.core.stop(n, Why::Aborted);
        store.notify();
        // (within the engine's idle deadline: the call has no progress; a pull
        // that is fetching ends when its `BeginPull` finds the engine gone,
        // at its next progress, half the deadline at most)
        let until = Instant::now() + self.config.decision.min(self.config.timeout * 3 / 4);
        while st.core.live(n) {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            st = store.wait(st, left);
        }
        Ok(reply(&proto::Ack {}))
    }

    pub(crate) fn read_objects(&self, mut call: Call<'_>, conn: &mut Conn) -> DriverResult<Out> {
        let p: request::ReadObjects<String, Vec<proto::Range>> = call.params()?;
        let store = self.store(&call, &p.store)?;
        if call.fds.len() != 1 {
            return Err(failed("ReadObjects carries the write end of a pipe"));
        }
        let pipe = std::fs::File::from(call.fds.remove(0));
        for (i, r) in p.ranges.iter().enumerate() {
            let key = store.resolve(&r.key);
            let range = ObjectRange {
                key: key.clone(),
                offset: r.offset,
                length: r.length,
            };
            // (an object of a staged pull is read where it waits for its
            // name)
            let staged = store
                .state()
                .staged
                .values()
                .find_map(|s| s.get(&key).cloned());
            // (the object is there and long enough: a reply is sent for a
            // range that can be read; it tells the size of the object)
            let size = match &staged {
                Some(path) => staged_size(path, &range)?,
                None => velarx_graph::objects::range_object_size(NAME, &store.files, &range)?,
            };
            let last = i + 1 == p.ranges.len();
            conn.send(
                &encode_reply(
                    &proto::Read {
                        index: i as u64,
                        size: Some(size),
                    },
                    !last,
                ),
                &[],
            )
            .map_err(failed)?;
            match &staged {
                Some(path) => read_staged(path, &range, &pipe)?,
                None => store.vfs.read_objects(&[range], &mut ToPipe(&pipe))?,
            }
        }
        Ok(Vec::new())
    }
}

/// The objects of a staged pull are read where they are only while the pull
/// waits for the engine.
struct Unstage<'a>(&'a Store, &'a str);

impl Drop for Unstage<'_> {
    fn drop(&mut self) {
        self.0.state().staged.remove(self.1);
    }
}

/// The size of the object at `path` (verified, not named in the store yet)
/// of which the range `r` is read.
fn staged_size(path: &std::path::Path, r: &ObjectRange) -> DriverResult<u64> {
    let len = std::fs::metadata(path)
        .map_err(|e| DriverError::io(NAME, e))?
        .len();
    if r.offset.checked_add(r.length).is_none_or(|end| end > len) {
        return Err(DriverError::corrupt(
            NAME,
            format!(
                "the object {} has {len} bytes, the range is {} bytes from {}",
                r.key, r.length, r.offset
            ),
            velarx_graph::Remedy::PullAgain,
        ));
    }
    Ok(len)
}

/// The range `r` of the object at `path`, into `pipe`.
fn read_staged(path: &std::path::Path, r: &ObjectRange, pipe: &std::fs::File) -> DriverResult<()> {
    use std::io::{Read, Seek};
    let io = |e: std::io::Error| DriverError::io(NAME, e);
    let mut file = std::fs::File::open(path).map_err(io)?;
    file.seek(std::io::SeekFrom::Start(r.offset)).map_err(io)?;
    let mut pipe = pipe;
    std::io::copy(&mut file.take(r.length), &mut pipe).map_err(io)?;
    Ok(())
}

struct ToPipe<'a>(&'a std::fs::File);

impl ObjectSink for ToPipe<'_> {
    fn data(&mut self, _: usize, bytes: &[u8]) -> std::io::Result<()> {
        let mut f = self.0;
        f.write_all(bytes)
    }
}

fn staged() -> Out {
    reply(&proto::PullEvent {
        kind: PullEventKind::Staged.into(),
        progress: None,
    })
}

/// Record the layers a pull committed, as the engine does for the layers of
/// a driver of its own process.
async fn publish(
    store: &Arc<Store>,
    layers: Vec<LayerDone>,
    artifacts: std::collections::HashMap<LayerKey, LayerArtifact>,
) -> Result<(), String> {
    let mut commits = Vec::new();
    for l in layers {
        let done: LayerDone = l;
        let mut commit =
            velarx_content::pull::layer_commit(&done, None).map_err(|e| e.to_string())?;
        if let Some(a) = artifacts.get(&done.key) {
            commit.record.erofs = Some(a.image_digest.clone());
            commit.record.owners = Some(a.owners.clone());
        }
        commits.push(commit);
    }
    store
        .db
        .commit_layers(commits, vec![])
        .await
        .map_err(|e| e.to_string())
}

/// What a pull that was stopped says.
fn reason(why: Why) -> &'static str {
    match why {
        Why::Aborted => "the pull was aborted",
        Why::Late => "the engine did not commit or abort the pull in time",
        Why::Gone => "the engine went away before it committed or aborted the pull",
        Why::Failed => "the pull failed",
    }
}

/// The pull is over: its layers are free for the pulls that wait for them,
/// and what it staged and nothing records goes when it did not commit.
fn release(store: &Arc<Store>, id: &str, outcome: Result<(), String>) {
    // (under the lock to the end: a pull that registers an object of its
    // layers (`WireFeed::fetch_blocking`) before it looks whether the store
    // has it either is counted here, or finds it gone and fetches it)
    let mut guard = store.state();
    let st = &mut *guard;
    let mut keys = Vec::new();
    if let Some(pull) = st.pulls.get_mut(id) {
        st.core.end(pull.n, outcome.is_ok());
        pull.ended = Some(Instant::now());
        if let Err(error) = outcome {
            keys = pull.keys.iter().cloned().collect();
            pull.error = error;
        }
    }
    // (this pull is over: what is left is what the others hold)
    let others = st.live_keys();
    store.notify();
    for key in keys {
        if others.contains(&key) {
            continue;
        }
        if recorded(store, &key).is_ok_and(|r| !r) {
            let _ = store.files.remove(&key);
        }
    }
}

/// Whether a layer the store committed records the object `key`.
pub(crate) fn recorded(store: &Store, key: &str) -> Result<bool, String> {
    store
        .rt
        .block_on(store.db.conn().call({
            let key = key.to_string();
            move |conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM file_refs WHERE file_digest = ?1",
                    [&key],
                    |r| r.get::<_, i64>(0),
                )?)
            }
        }))
        .map(|n| n > 0)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::Config;
    use std::time::Duration;
    use velarx_pull_core::Phase;

    const STORE: &str = "0123456789abcdef0123456789abcdef";
    const PULL: &str = "fedcba9876543210fedcba9876543210";
    const UID: u32 = 1000;

    /// A server whose waits are short, and one of its stores.
    fn setup() -> (tempfile::TempDir, Arc<Server>, Arc<Store>) {
        setup_with(Duration::from_millis(400), Duration::from_millis(300))
    }

    fn setup_with(
        timeout: Duration,
        decision: Duration,
    ) -> (tempfile::TempDir, Arc<Server>, Arc<Store>) {
        let dir = tempfile::tempdir().unwrap();
        let server = Server::new(Config {
            root: dir.path().to_path_buf(),
            timeout,
            decision,
        })
        .unwrap();
        let store = server.stores.get(UID, STORE).unwrap();
        (dir, server, store)
    }

    fn layer(n: u8) -> proto::LayerRef {
        let d = format!("sha256:{}", format!("{n:02x}").repeat(32));
        proto::LayerRef {
            key: d.clone(),
            diff_id: d.clone(),
            chain_id: d,
        }
    }

    fn call_of(body: serde_json::Value, fds: Vec<OwnedFd>) -> (Vec<u8>, Vec<OwnedFd>) {
        (
            serde_json::to_vec(&serde_json::json!({ "parameters": body })).unwrap(),
            fds,
        )
    }

    fn commit(server: &Server, id: &str, layers: &[proto::LayerRef]) -> DriverResult<Out> {
        let (bytes, fds) = call_of(
            serde_json::json!({ "store": STORE, "pull": id, "layers": layers }),
            vec![],
        );
        server.commit(Call {
            bytes: &bytes,
            fds,
            uid: UID,
        })
    }

    fn abort(server: &Server, id: &str) -> DriverResult<Out> {
        let (bytes, fds) = call_of(serde_json::json!({ "store": STORE, "pull": id }), vec![]);
        server.abort(Call {
            bytes: &bytes,
            fds,
            uid: UID,
        })
    }

    fn begin(server: &Arc<Server>, id: &str, layers: &[proto::PullLayer]) -> DriverResult<Out> {
        let (mine, _theirs) = UnixStream::pair().unwrap();
        let (conn, _engine) = UnixStream::pair().unwrap();
        begin_on(server, id, layers, mine, conn)
    }

    /// BeginPull with the feed and the connection of the call given.
    fn begin_on(
        server: &Arc<Server>,
        id: &str,
        layers: &[proto::PullLayer],
        feed: UnixStream,
        conn: UnixStream,
    ) -> DriverResult<Out> {
        let (bytes, fds) = call_of(
            serde_json::json!({ "store": STORE, "pull": id, "layers": layers }),
            vec![OwnedFd::from(feed)],
        );
        server.begin_pull(
            Call {
                bytes: &bytes,
                fds,
                uid: UID,
            },
            &mut Conn::from_stream(conn),
        )
    }

    fn bytes(out: DriverResult<Out>) -> Vec<Vec<u8>> {
        out.unwrap().into_iter().map(|(b, _)| b).collect()
    }

    fn ack() -> Vec<Vec<u8>> {
        bytes(Ok(reply(&proto::Ack {})))
    }

    fn kind_of(e: &DriverError) -> &'static str {
        match e.kind {
            DriverErrorKind::Busy => "busy",
            DriverErrorKind::NotFound => "not found",
            DriverErrorKind::Storage => "storage",
            _ => "other",
        }
    }

    fn phase(store: &Store, id: &str) -> Phase {
        let st = store.state();
        st.core.phase(st.pulls[id].n).unwrap()
    }

    /// Commit on a pull that is fetching is refused as busy, and the pull is
    /// not touched.
    #[test]
    fn commit_on_a_running_pull_is_busy() {
        let (_d, server, store) = setup();
        store.state().put(PULL, Phase::Fetching);
        let e = commit(&server, PULL, &[]).unwrap_err();
        assert_eq!(kind_of(&e), "busy");
        assert!(e.message().contains("not staged yet"), "{}", e.message());
        assert_eq!(phase(&store, PULL), Phase::Fetching);
    }

    /// Commit on a pull that is over answers its outcome: Ack when it was
    /// published, its error when it was not.
    #[test]
    fn commit_on_an_ended_pull_answers_its_outcome() {
        let (_d, server, store) = setup();
        store.state().put(PULL, Phase::Over(None));
        assert_eq!(bytes(commit(&server, PULL, &[])), ack());
        store
            .state()
            .put(PULL, Phase::Over(Some(Why::Failed)))
            .error = "it failed".into();
        let e = commit(&server, PULL, &[]).unwrap_err();
        assert_eq!(kind_of(&e), "storage");
        assert!(e.message().contains("it failed"), "{}", e.message());
        assert_eq!(phase(&store, PULL), Phase::Over(Some(Why::Failed)));
    }

    /// Commit on an id the server does not have answers from the store: Ack
    /// when it has every layer (none asked: Ack), not found when it lacks one.
    #[test]
    fn commit_on_an_unknown_pull_answers_from_the_store() {
        let (_d, server, store) = setup();
        assert_eq!(bytes(commit(&server, PULL, &[])), ack());
        let e = commit(&server, PULL, &[layer(1)]).unwrap_err();
        assert_eq!(kind_of(&e), "not found");
        assert!(e.message().contains("is not there"), "{}", e.message());
        assert!(store.state().pulls.is_empty(), "no record is made");
    }

    /// Abort on a staged pull returns, with Ack, once the pull is over (the
    /// pull failing), and it stopped the pull before.
    #[test]
    fn abort_on_a_staged_pull_returns_once_it_is_over() {
        let (_d, server, store) = setup_with(Duration::from_secs(60), Duration::from_secs(60));
        store.state().put(PULL, Phase::Staged);
        let started = Instant::now();
        let ender = {
            let store = store.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                let mut st = store.state();
                assert_eq!(
                    st.core.phase(st.pulls[PULL].n),
                    Some(Phase::Stopping(Why::Aborted))
                );
                st.put(PULL, Phase::Over(Some(Why::Aborted)));
                drop(st);
                store.notify();
            })
        };
        assert_eq!(bytes(abort(&server, PULL)), ack());
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "it waited the deadline"
        );
        ender.join().unwrap();
        assert_eq!(phase(&store, PULL), Phase::Over(Some(Why::Aborted)));
    }

    /// Abort on an unknown pull, or one that is over, answers Ack at once and
    /// changes nothing.
    #[test]
    fn abort_on_an_unknown_or_ended_pull_is_an_ack() {
        let (_d, server, store) = setup();
        assert_eq!(bytes(abort(&server, PULL)), ack());
        assert!(store.state().pulls.is_empty());
        store.state().put(PULL, Phase::Over(None));
        assert_eq!(bytes(abort(&server, PULL)), ack());
        assert_eq!(phase(&store, PULL), Phase::Over(None));
    }

    /// Abort on a pull that is fetching stops it and answers Ack after the
    /// wait: the pull ends when it is staged.
    #[test]
    fn abort_on_a_fetching_pull_stops_it() {
        let (_d, server, store) = setup();
        store.state().put(PULL, Phase::Fetching);
        assert_eq!(bytes(abort(&server, PULL)), ack());
        assert_eq!(phase(&store, PULL), Phase::Stopping(Why::Aborted));
    }

    /// BeginPull on an id that is staged answers `staged` again, and one that
    /// is fetching or stopping is busy; neither changes the record.
    #[test]
    fn begin_pull_on_a_staged_or_live_id() {
        let (_d, server, store) = setup();
        store.state().put(PULL, Phase::Staged);
        assert_eq!(bytes(begin(&server, PULL, &[])), bytes(Ok(staged())));
        assert_eq!(phase(&store, PULL), Phase::Staged);
        for live in [Phase::Fetching, Phase::Stopping(Why::Aborted)] {
            store.state().put(PULL, Phase::Over(None));
            store.state().put(PULL, live);
            let e = begin(&server, PULL, &[]).unwrap_err();
            assert_eq!(kind_of(&e), "busy");
            assert!(e.message().contains("is running"), "{}", e.message());
            assert_eq!(phase(&store, PULL), live);
        }
    }

    /// Commit and Abort on a staged pull: the first one wins, the second
    /// changes nothing and answers as before.
    #[test]
    fn the_first_decision_on_a_staged_pull_wins() {
        let (_d, server, store) = setup();
        store.state().put(PULL, Phase::Staged);
        // (it does not end: Commit gives up after the decision time)
        let e = commit(&server, PULL, &[]).unwrap_err();
        assert!(e.message().contains("did not end"), "{}", e.message());
        assert_eq!(phase(&store, PULL), Phase::Committing);
        assert_eq!(bytes(abort(&server, PULL)), ack());
        assert_eq!(phase(&store, PULL), Phase::Committing);
        store.state().put(PULL, Phase::Over(None));
        store.state().put(PULL, Phase::Staged);
        assert_eq!(bytes(abort(&server, PULL)), ack());
        let e = commit(&server, PULL, &[]).unwrap_err();
        assert!(e.message().contains("did not end"), "{}", e.message());
        assert_eq!(phase(&store, PULL), Phase::Stopping(Why::Aborted));
    }

    fn to_fetch(n: u8) -> proto::PullLayer {
        let l = layer(n);
        proto::PullLayer {
            key: l.key,
            diff_id: l.diff_id,
            chain_id: l.chain_id,
            parent: None,
            stored: false,
        }
    }

    /// The pull `owner` claims the layer `n`, and fetches.
    fn claim(store: &Store, n: u8, owner: &str) -> String {
        let key = layer(n).key;
        let mut st = store.state();
        let pull = st.put(owner, Phase::Waiting).n;
        st.claim(pull, std::slice::from_ref(&key));
        key
    }

    fn claimed(store: &Store, key: &str) -> bool {
        store.state().claimed_layers().any(|l| l == key)
    }

    fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let until = Instant::now() + Duration::from_secs(30);
        while !done() {
            assert!(Instant::now() < until, "gave up waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A pull that needs a layer another pull claimed waits, and claims it
    /// once the other is released; its own end gives the claim back.
    #[test]
    fn a_waiting_pull_claims_after_the_release_of_the_other() {
        let (_d, server, store) = setup();
        let key = claim(&store, 1, "other");
        let (feed, engine_feed) = UnixStream::pair().unwrap();
        let (conn, _engine) = UnixStream::pair().unwrap();
        let waiter = {
            let server = server.clone();
            std::thread::spawn(move || begin_on(&server, PULL, &[to_fetch(1)], feed, conn))
        };
        wait_for("the record of the waiter", || {
            store.state().pulls.contains_key(PULL)
        });
        std::thread::sleep(Duration::from_millis(500));
        {
            assert_eq!(phase(&store, PULL), Phase::Waiting, "the other lives");
            assert_eq!(phase(&store, "other"), Phase::Fetching);
        }
        release(&store, "other", Ok(()));
        wait_for("the claim of the waiter", || {
            phase(&store, PULL) == Phase::Fetching && claimed(&store, &key)
        });
        // (the engine's feed goes: the pull cannot go on, and ends)
        drop(engine_feed);
        assert!(waiter.join().unwrap().is_err());
        assert!(!claimed(&store, &key));
        assert_eq!(phase(&store, PULL), Phase::Over(Some(Why::Failed)));
    }

    /// An Abort of a pull that waits for layers stops it at once: it does not
    /// claim, fetch and then abort.
    #[test]
    fn an_aborted_waiter_stops_at_once() {
        let (_d, server, store) = setup();
        let key = claim(&store, 1, "other");
        let (feed, _engine_feed) = UnixStream::pair().unwrap();
        let (conn, _engine) = UnixStream::pair().unwrap();
        let waiter = {
            let server = server.clone();
            std::thread::spawn(move || begin_on(&server, PULL, &[to_fetch(1)], feed, conn))
        };
        wait_for("the record of the waiter", || {
            store.state().pulls.contains_key(PULL)
        });
        assert_eq!(bytes(abort(&server, PULL)), ack());
        let e = waiter.join().unwrap().unwrap_err();
        assert!(e.message().contains("cancelled"), "{}", e.message());
        assert!(!store.state().pulls.contains_key(PULL));
        assert!(claimed(&store, &key), "the claim of the other stands");
    }

    /// A pull with the id of one that lives is busy, whoever asks: the record
    /// of the first stands.
    #[test]
    fn a_second_begin_of_a_waiting_id_is_busy() {
        let (_d, server, store) = setup();
        claim(&store, 1, "other");
        store.state().put(PULL, Phase::Waiting);
        let e = begin(&server, PULL, &[to_fetch(1)]).unwrap_err();
        assert_eq!(kind_of(&e), "busy");
        assert_eq!(phase(&store, PULL), Phase::Waiting);
    }

    /// A waiter whose engine is gone is cancelled: its record goes, the
    /// claim of the other is not touched.
    #[test]
    fn the_record_of_a_cancelled_waiter_goes() {
        let (_d, server, store) = setup();
        let key = claim(&store, 1, "other");
        let (feed, _engine_feed) = UnixStream::pair().unwrap();
        let (conn, engine) = UnixStream::pair().unwrap();
        drop(engine);
        let e = begin_on(&server, PULL, &[to_fetch(1)], feed, conn).unwrap_err();
        assert!(e.message().contains("cancelled"), "{}", e.message());
        assert!(!store.state().pulls.contains_key(PULL));
        assert!(claimed(&store, &key), "the claim of the other stands");
        assert!(store.state().pulls.contains_key("other"));
    }

    /// `release` frees the claims of the pull, sets it over, and removes of
    /// its objects only those that no live pull holds and no row records; a
    /// pull that ends well removes none.
    #[test]
    fn release_frees_the_claims_and_removes_what_nothing_holds() {
        use velarx_types::digest::Algorithm;
        let (_d, _server, store) = setup();
        let put = |data: &[u8]| store.files.put(Algorithm::Sha256, data).unwrap();
        let (alone, held, recorded_key, over) =
            (put(b"alone"), put(b"held"), put(b"recorded"), put(b"over"));
        let layer_a = claim(&store, 1, "a");
        let layer_other = claim(&store, 2, "other");
        {
            let mut st = store.state();
            for (id, phase, keys) in [
                (
                    "a",
                    Phase::Fetching,
                    vec![&alone, &held, &recorded_key, &over],
                ),
                ("other", Phase::Fetching, vec![&held]),
                ("done", Phase::Over(None), vec![&over]),
            ] {
                st.put(id, phase).keys.extend(keys.into_iter().cloned());
            }
        }
        let key = recorded_key.clone();
        store
            .rt
            .block_on(store.db.conn().call(move |c| {
                c.execute_batch("PRAGMA foreign_keys = OFF")?;
                c.execute(
                    "INSERT INTO file_refs (layer_id, file_digest, ref_count) VALUES ('l', ?1, 1)",
                    [&key],
                )?;
                Ok(())
            }))
            .unwrap();
        release(&store, "a", Err("failed".into()));
        assert!(!claimed(&store, &layer_a));
        assert!(claimed(&store, &layer_other));
        assert_eq!(phase(&store, "a"), Phase::Over(Some(Why::Failed)));
        assert_eq!(store.state().pulls["a"].error, "failed");
        assert!(store.state().pulls["a"].ended.is_some());
        assert_eq!(phase(&store, "other"), Phase::Fetching);
        assert!(!store.files.contains(&alone), "no one holds it");
        assert!(store.files.contains(&held), "a live pull holds it");
        assert!(store.files.contains(&recorded_key), "a row records it");
        assert!(!store.files.contains(&over), "an ended pull holds nothing");
        // (a pull that published removes nothing)
        let kept = put(b"kept");
        store
            .state()
            .pulls
            .get_mut("other")
            .unwrap()
            .keys
            .insert(kept.clone());
        store.state().put("other", Phase::Committing);
        release(&store, "other", Ok(()));
        assert!(store.files.contains(&kept));
        assert!(store.files.contains(&held));
        assert!(!claimed(&store, &layer_other));
        assert_eq!(phase(&store, "other"), Phase::Over(None));
    }
}
