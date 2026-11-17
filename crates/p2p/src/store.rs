// SPDX-License-Identifier: Apache-2.0
//! The P2P service as a client of the store service
//! (`org.velarx.Store`, [`velarx_core::store_service`]): the chunks, indexes and
//! profiles it gives to peers come from there, as read-only descriptors,
//! and what the peers are told this node has (the filter of its layers, and
//! with `announce_images` its images) is what the service says may be
//! announced.  The service opens neither the
//! database nor the objects.

use super::limits::MAX_ITEM_BYTES;
use super::P2PNode;
use crate::ChunkProvider;
use futures::StreamExt;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};
use velarx_core::store_service::Announcement;
use velarx_core::store_service::{
    self, Change, ChangeKind, ImageInfo, StoreProxy, Want, MAX_LOOKUP,
};
use velarx_storage::ChunkFile;

type Conn = zlink::Connection<zlink::tokio::unix::Stream>;

/// What the store service gives, for the peers.
pub struct StoreContent {
    socket: PathBuf,
    runtime: tokio::runtime::Handle,
    /// Connections not in use
    idle: Mutex<Vec<Conn>>,
}

/// Connections kept for the next call.
const KEPT: usize = 4;

impl StoreContent {
    /// Must be created inside the runtime of the service; its methods are
    /// called from blocking threads.
    pub fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            runtime: tokio::runtime::Handle::current(),
            idle: Mutex::new(Vec::new()),
        }
    }

    async fn connection(&self) -> io::Result<Conn> {
        let kept = self.idle.lock().unwrap_or_else(|e| e.into_inner()).pop();
        match kept {
            Some(conn) => Ok(conn),
            None => store_service::connect(&self.socket).await,
        }
    }

    fn keep(&self, conn: Conn) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < KEPT {
            idle.push(conn);
        }
    }

    /// The files of `digests` (at most [`MAX_LOOKUP`]), for those the store
    /// gives.
    async fn lookup(&self, digests: &[String]) -> io::Result<Vec<Option<ChunkFile>>> {
        let wants = digests
            .iter()
            .map(|d| Want {
                digest: d.clone(),
                size: None,
            })
            .collect();
        let mut conn = self.connection().await?;
        let (reply, mut fds) = conn
            .lookup(wants)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        let reply = reply.map_err(io::Error::other)?;
        if reply.items.len() != digests.len() {
            return Err(io::Error::other("the store service lost a digest"));
        }
        let mut taken: Vec<Option<OwnedFd>> = fds.drain(..).map(Some).collect();
        let files = reply
            .items
            .into_iter()
            .map(|item| {
                let fd = taken.get_mut(item.fd? as usize)?.take()?;
                Some(ChunkFile {
                    file: std::fs::File::from(fd),
                    offset: item.offset,
                    len: item.length,
                })
            })
            .collect();
        self.keep(conn);
        Ok(files)
    }

    /// The bytes of a read-only file the service sent, to its end: at
    /// most [`MAX_ITEM_BYTES`].
    fn read_all(fd: OwnedFd) -> io::Result<Vec<u8>> {
        // (from offset 0 whatever the offset of the shared open file is)
        let file = std::fs::File::from(fd);
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let n = file.read_at(&mut chunk, bytes.len() as u64)?;
            if n == 0 {
                return Ok(bytes);
            }
            bytes.extend_from_slice(&chunk[..n]);
            if bytes.len() > MAX_ITEM_BYTES {
                return Err(io::Error::other("the store service sent a file too large"));
            }
        }
    }

    /// The bytes of the file at position `at` among the descriptors the
    /// store service passed.
    fn item(mut fds: Vec<OwnedFd>, at: u32) -> io::Result<Vec<u8>> {
        if at as usize >= fds.len() {
            return Err(io::Error::other(
                "the store service named a descriptor it did not pass",
            ));
        }
        Self::read_all(fds.swap_remove(at as usize))
    }
}

impl ChunkProvider for StoreContent {
    fn get_chunk(&self, digest: &str) -> io::Result<Option<Vec<u8>>> {
        let digests = [digest.to_string()];
        let Some(found) = self
            .runtime
            .block_on(self.lookup(&digests))?
            .pop()
            .flatten()
        else {
            return Ok(None);
        };
        if found.len > MAX_ITEM_BYTES as u64 {
            return Ok(None);
        }
        let mut bytes = vec![0u8; found.len as usize];
        found.file.read_exact_at(&mut bytes, found.offset)?;
        Ok(Some(bytes))
    }

    fn get_index(&self, layer: &str) -> io::Result<Option<Vec<u8>>> {
        self.runtime.block_on(async {
            let mut conn = self.connection().await?;
            let answer = conn
                .index(layer, MAX_ITEM_BYTES as u64)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            self.keep(conn);
            match answer {
                (Ok(reply), fds) => Self::item(fds, reply.fd).map(Some),
                (Err(store_service::StoreError::NotFound { .. }), _) => Ok(None),
                (Err(e), _) => Err(io::Error::other(e)),
            }
        })
    }

    fn get_profile(&self, image: &str) -> io::Result<Option<Vec<u8>>> {
        self.runtime.block_on(async {
            let mut conn = self.connection().await?;
            let answer = conn
                .profile(image, velarx_content::fetcher::fetch::PROFILE_MAX_BYTES)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            self.keep(conn);
            match answer {
                (Ok(reply), fds) => Self::item(fds, reply.file).map(Some),
                (Err(store_service::StoreError::NotFound { .. }), _) => Ok(None),
                (Err(e), _) => Err(io::Error::other(e)),
            }
        })
    }

    fn open_chunks(&self, digests: &[String]) -> io::Result<Vec<Option<ChunkFile>>> {
        let mut files = Vec::with_capacity(digests.len());
        for wave in digests.chunks(MAX_LOOKUP) {
            files.extend(self.runtime.block_on(self.lookup(wave))?);
        }
        Ok(files)
    }
}

/// What a change of the store service tells the peers about layers (the
/// images are asked for as a whole: [`stored_images`]).
fn announcement(change: Change) -> Announcement {
    Announcement {
        content: Vec::new(),
        layers: change.layers,
        images: Vec::new(),
    }
}

/// The images the store service has, whole: the ones it may give to the
/// peers (a lazy image is not announced before its completion).
async fn stored_images(socket: &std::path::Path) -> io::Result<Vec<ImageInfo>> {
    let mut conn = store_service::connect(socket).await?;
    let images = store_service::image_list(&mut conn).await?;
    Ok(images.into_iter().filter(|i| i.complete).collect())
}

/// The layers of the image `name` names, as keys, and its id as a digest
/// (its startup profile is asked for by it): the image whose id (or the
/// start of it, at least 6 characters), manifest digest or a name it shares
/// is `name`; nothing when the store has no such image, or is not there.
pub async fn layers_of_image(socket: &std::path::Path, name: &str) -> Vec<String> {
    if name.len() < 6 || crate::limits::is_digest(name) {
        return Vec::new();
    }
    let Ok(images) = stored_images(socket).await else {
        return Vec::new();
    };
    let has = |i: &ImageInfo| {
        i.id.starts_with(name.trim_start_matches("sha256:"))
            || i.manifest_digest == name
            || i.tags
                .iter()
                .chain(&i.repo_digests)
                .any(|t| t == name || t.contains(name))
    };
    images
        .iter()
        .find(|i| has(i))
        .map(|i| {
            i.layers
                .iter()
                .cloned()
                .chain([format!("sha256:{}", i.id)])
                .collect()
        })
        .unwrap_or_default()
}

/// Tell the peers what a change of the store service changes in the layers
/// this node has: a removal withdraws them, a snapshot withdraws what it
/// does not have and announces the rest, an addition announces.  Whether
/// the images are to be asked for again.
pub async fn apply_change(node: &P2PNode, change: Change) -> bool {
    let images = change.kind == ChangeKind::Snapshot || !change.images.is_empty();
    // (what the store has, it gives; what it lost is gone: the files kept
    // for the peers while a pull staged them are not needed)
    node.release_staged(&change.layers);
    if change.kind == ChangeKind::Removed {
        // (the peers forget what the DHT does not renew)
        node.withdraw_layers(&change.layers).await;
        debug!(
            "{} layers and {} images are not shared any more",
            change.layers.len(),
            change.images.len()
        );
    } else {
        if change.kind == ChangeKind::Snapshot {
            // (the snapshot is the whole truth: what the store lost while
            // the service was away goes)
            node.withdraw_layers_not_in(&change.layers).await;
            info!(
                "Announcing {} layers and {} images of the store",
                change.layers.len(),
                change.images.iter().filter(|i| i.complete).count()
            );
        }
        super::service::announce_to_peers(node, announcement(change)).await;
    }
    images
}

/// Waits for the socket of a service to be made (again): a name created or
/// moved into its directory.  A service that was restarted binds its socket
/// anew; no timer guesses when.
struct Appearance {
    watch: velarx_sys::watch::Watch,
    woken: tokio::io::unix::AsyncFd<OwnedFd>,
}

impl Appearance {
    fn new(socket: &std::path::Path) -> io::Result<Self> {
        let dir = socket.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "a socket without a directory")
        })?;
        let watch = velarx_sys::watch::Watch::new()?;
        watch.creations_in(dir)?;
        let woken = velarx_sys::fd::register(watch.owned_fd()?, tokio::io::Interest::READABLE)?;
        Ok(Self { watch, woken })
    }

    /// Forget the creations so far: the socket is looked at after this.
    fn look(&self) {
        self.watch.clear();
    }

    /// Return when a name was created since the last [`look`](Self::look).
    async fn created(&self) -> io::Result<()> {
        let mut ready = self.woken.readable().await?;
        ready.clear_ready();
        Ok(())
    }
}

/// [`follow_store`] on a thread of its own, until `shutdown`: the stream of
/// the typed call is not `Send`, so it is read on a `LocalSet`.
pub fn follow_store_on_thread(
    node: Arc<P2PNode>,
    socket: PathBuf,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) -> io::Result<std::thread::JoinHandle<()>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    std::thread::Builder::new()
        .name("p2p-store-follower".into())
        .spawn(move || {
            tokio::task::LocalSet::new().block_on(&runtime, follow_store(node, socket, shutdown));
        })
}

/// Follow what the store service says may be announced: a snapshot first,
/// then what is added, and announce it to the peers.  The service may be
/// restarted: connect again when its socket is made again.  Not `Send`: it
/// runs on a `LocalSet` ([`follow_store_on_thread`]).
async fn follow_store(
    node: Arc<P2PNode>,
    socket: PathBuf,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    let appearance = match Appearance::new(&socket) {
        Ok(a) => a,
        Err(e) => {
            warn!(
                "Not announcing what the store has: cannot watch {}: {e}",
                socket.display()
            );
            return;
        }
    };
    let mut refused = false;
    loop {
        appearance.look();
        // (connect checks the protocol: a store service of another
        // version is said once, the one that is not there is retried)
        let mut conn = match store_service::connect(&socket).await {
            Ok(conn) => conn,
            Err(e) => {
                if e.kind() == io::ErrorKind::InvalidData && !refused {
                    warn!("Not announcing what the store has: {e}");
                    refused = true;
                } else {
                    debug!("The store service is not there: {e}");
                }
                // (its socket is made again when it starts)
                if !wait_for(&appearance, &mut shutdown).await {
                    return;
                }
                continue;
            }
        };
        refused = false;
        let stream = match conn.subscribe().await {
            Ok(stream) => stream,
            Err(e) => {
                debug!("The store service does not announce: {e}");
                if !wait_for(&appearance, &mut shutdown).await {
                    return;
                }
                continue;
            }
        };
        futures::pin_mut!(stream);
        let mut heard = false;
        loop {
            let change = tokio::select! {
                change = stream.next() => change,
                _ = shutdown.recv() => return,
            };
            match change {
                Some(Ok(Ok(change))) => {
                    heard = true;
                    // (an image that was added, completed or removed: the
                    // list is the whole truth, and replaces what peers are
                    // told)
                    if apply_change(&node, change).await && node.gossip().is_announcing() {
                        match stored_images(&socket).await {
                            Ok(images) => node.announce_images(images).await,
                            Err(e) => debug!("The images of the store service: {e}"),
                        }
                    }
                }
                Some(Ok(Err(e))) => {
                    debug!("The store service: {e}");
                    break;
                }
                Some(Err(e)) => {
                    debug!("The announcements of the store service stopped: {e}");
                    break;
                }
                None => break,
            }
        }
        // The service ended its stream: it was stopped or restarted.  One
        // that answered without a change is not asked again at once: it
        // is asked when its socket is made again.
        if !heard && !wait_for(&appearance, &mut shutdown).await {
            return;
        }
    }
}

/// Wait for the socket to be made, or for the shutdown: whether to go on.
async fn wait_for(
    appearance: &Appearance,
    shutdown: &mut tokio::sync::broadcast::Receiver<()>,
) -> bool {
    tokio::select! {
        created = appearance.created() => match created {
            Ok(()) => true,
            Err(e) => {
                warn!("Not announcing what the store has any more: {e}");
                false
            }
        },
        _ = shutdown.recv() => false,
    }
}
