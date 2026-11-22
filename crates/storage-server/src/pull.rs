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
use crate::store::{Decision, Phase, Pull, Store};
use std::collections::{HashMap, HashSet};
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
        // a pull with this id that the server has resumes
        {
            let st = store.state();
            if let Some(old) = st.pulls.get(&p.pull) {
                match &old.phase {
                    Phase::Staged => return Ok(staged()),
                    Phase::Running => {
                        return Err(DriverError::of(
                            NAME,
                            DriverErrorKind::Busy,
                            format!("the pull {} is running", p.pull),
                        ))
                    }
                    Phase::Over(_) => {}
                }
            }
        }
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
        {
            let mut st = store.state();
            // (the outcomes of old pulls go: the map does not grow with every
            // pull the server ever ran)
            if let Some(before) = Instant::now().checked_sub(self.config.decision) {
                st.forget_ended(before);
            }
            st.pulls.insert(
                p.pull.clone(),
                Pull {
                    phase: Phase::Running,
                    decision: Decision::Pending,
                    keys: HashSet::new(),
                    ended: None,
                },
            );
            loop {
                if mine.iter().all(|k| !st.claimed.contains_key(k)) {
                    for k in &mine {
                        st.claimed.insert(k.clone(), p.pull.clone());
                    }
                    break;
                }
                st = store.wait(st, interval);
                if progress(conn, "waiting for a pull of the same layers").is_err() {
                    st.pulls.remove(&p.pull);
                    store.notify();
                    return Err(failed("the pull was cancelled"));
                }
            }
        }
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
                {
                    let mut st = store.state();
                    if let Some(pull) = st.pulls.get_mut(&id) {
                        pull.phase = Phase::Staged;
                    }
                }
                store.notify();
                let _ = tx.send(Event::Staged);
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
                    let d = st.pulls.get(&id).map_or(Decision::Abort, |p| p.decision);
                    match d {
                        Decision::Commit => return Ok(settlement),
                        Decision::Abort => {
                            return Err(ImageError::Layer("the pull was aborted".into()))
                        }
                        Decision::Pending => {}
                    }
                    // (the engine keeps the feed open until it has decided: a
                    // feed that is closed is an engine that is gone, and its
                    // claims go now, not in `decision` seconds)
                    if wire.engine_gone() {
                        return Err(ImageError::Layer(
                            "the engine went away before it committed or aborted the pull".into(),
                        ));
                    }
                    let left = until.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(ImageError::Layer(
                            "the engine did not commit or abort the pull in time".into(),
                        ));
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
        let Some(pull) = st.pulls.get_mut(&p.pull) else {
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
        match &pull.phase {
            Phase::Over(Ok(())) => return Ok(reply(&proto::Ack {})),
            Phase::Over(Err(e)) => return Err(failed(e)),
            Phase::Running => {
                return Err(DriverError::of(
                    NAME,
                    DriverErrorKind::Busy,
                    format!("the pull {} is not staged yet", p.pull),
                ))
            }
            Phase::Staged => pull.decision = Decision::Commit,
        }
        store.notify();
        let until = Instant::now() + self.config.decision;
        loop {
            match st.pulls.get(&p.pull).map(|p| p.phase.clone()) {
                Some(Phase::Over(Ok(()))) => return Ok(reply(&proto::Ack {})),
                Some(Phase::Over(Err(e))) => return Err(failed(e)),
                None => return Err(failed("the pull is gone")),
                _ => {}
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(failed("the pull did not end"));
            }
            st = store.wait(st, left);
        }
    }

    pub(crate) fn abort(&self, call: Call<'_>) -> DriverResult<Out> {
        let p: request::OfPull<String> = call.params()?;
        let store = self.store(&call, &p.store)?;
        let mut st = store.state();
        if let Some(pull) = st.pulls.get_mut(&p.pull) {
            if !matches!(pull.phase, Phase::Over(_)) {
                pull.decision = Decision::Abort;
            }
        }
        store.notify();
        // (within the engine's idle deadline: the call has no progress; a pull
        // that is fetching ends when its `BeginPull` finds the engine gone,
        // at its next progress, half the deadline at most)
        let until = Instant::now() + self.config.decision.min(self.config.timeout * 3 / 4);
        loop {
            match st.pulls.get(&p.pull).map(|p| p.phase.clone()) {
                None | Some(Phase::Over(_)) => break,
                // (it is fetching: the connection of the call ends it)
                Some(Phase::Running) if until <= Instant::now() => break,
                _ => {}
            }
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
    let root = velarx_db::layer_files::root_of(store.files.root());
    for l in layers {
        let done: LayerDone = l;
        // (the files of the layer, made durable before the row names it)
        done.write_files(root).map_err(|e| e.to_string())?;
        let mut commit =
            velarx_content::pull::layer_commit(&done, None).map_err(|e| e.to_string())?;
        if let Some(a) = artifacts.get(&done.key) {
            commit.record.erofs = Some(a.image_digest.clone());
            commit.record.owners = Some(a.owners.clone());
        }
        commits.push(commit);
    }
    store
        .files
        .barrier(&velarx_db::layer_files::layers_dir(root))
        .map_err(|e| e.to_string())?;
    store
        .db
        .commit_layers(commits, vec![])
        .await
        .map_err(|e| e.to_string())
}

/// The pull is over: its layers are free for the pulls that wait for them,
/// and what it staged and nothing records goes when it did not commit.
fn release(store: &Arc<Store>, id: &str, outcome: Result<(), String>) {
    // (under the lock to the end: a pull that registers an object of its
    // layers (`WireFeed::fetch_blocking`) before it looks whether the store
    // has it either is counted here, or finds it gone and fetches it)
    let mut st = store.state();
    st.claimed.retain(|_, owner| owner != id);
    let mut keys = Vec::new();
    if outcome.is_err() {
        if let Some(pull) = st.pulls.get(id) {
            keys = pull.keys.iter().cloned().collect();
        }
    }
    if let Some(pull) = st.pulls.get_mut(id) {
        pull.phase = Phase::Over(outcome);
        pull.ended = Some(Instant::now());
    }
    let others: HashSet<String> = st
        .pulls
        .iter()
        .filter(|(k, p)| k.as_str() != id && !matches!(p.phase, Phase::Over(_)))
        .flat_map(|(_, p)| p.keys.iter().cloned())
        .collect();
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
