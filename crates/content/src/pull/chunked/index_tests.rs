// SPDX-License-Identifier: Apache-2.0
//! A layer with no table of contents pulled from the index of a source and
//! the files the store lacks.

use super::*;
use crate::activation::Limits;
use crate::fetcher::fetch::{Blob, EventKind, FetchEvent as Event, FetcherError, NotLazy};
use crate::fetcher::fetch::{Parts, Probed, TocSource};
use crate::fetcher::fetch_client::FetchConn;
use crate::pull::staged_fetch::{Link, StagedFetch, TEST_IDLE};
use crate::pull::{Limits as PullLimits, PullCtx};
use crate::serve_fetch::{
    Described, FetchCall, LayerScope, LocalFetcher, Out, Scope, StagingFetcher, UnpackCall,
};
use crate::stager::{name_of, LayerToc, Unnamed};
use async_trait::async_trait;
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// A layer of a few files and what a node that has it knows of it.
struct Made {
    desc: OciDescriptor,
    diff: Digest,
    /// The table as a node records it: the digest and the fs-verity digest
    /// of each file
    toc: Toc,
    tarsplit_z: Vec<u8>,
    /// The files by their fs-verity key
    bodies: HashMap<String, Vec<u8>>,
}

fn verity(data: &[u8]) -> String {
    velarx_storage::fsverity_digest_of(Algorithm::Sha256, data)
}

fn made(files: &[(&str, Vec<u8>)]) -> Made {
    let mut entries = vec![TocEntry {
        mode: 0o755,
        ..TocEntry::new("./".to_string(), TocEntryType::Dir)
    }];
    let mut bodies = HashMap::new();
    for (name, data) in files {
        entries.push(TocEntry {
            mode: 0o644,
            size: data.len() as u64,
            digest: Some(Digest::of(Algorithm::Sha256, data).to_string()),
            fsverity: velarx_storage::to_toc(&verity(data)),
            ..TocEntry::new(format!("./{name}"), TocEntryType::Reg)
        });
        bodies.insert(verity(data), data.clone());
    }
    let content: HashMap<String, &Vec<u8>> = files
        .iter()
        .map(|(name, data)| (format!("./{name}"), data))
        .collect();
    let mut tar = Vec::new();
    velarx_storage::canonical::write(&entries, &mut tar, |e, out| out.write_all(content[&e.name]))
        .unwrap();
    let mut reader = TarReader::with_sink(
        std::io::Cursor::new(tar.clone()),
        crate::pull::tarsplit::Recorder::new().unwrap(),
    );
    while reader.next_entry().unwrap().is_some() {}
    let tarsplit_z = reader.finish().unwrap().1.finish().unwrap().compressed;
    let toc = Toc {
        version: TOC_VERSION,
        entries,
        tar_split_digest: Some(Digest::of(Algorithm::Sha256, &tarsplit_z).to_string()),
    };
    Made {
        desc: OciDescriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            digest: Digest::of(Algorithm::Sha256, b"the blob"),
            size: 4096,
            annotations: Default::default(),
        },
        diff: Digest::of(Algorithm::Sha256, &tar),
        toc,
        tarsplit_z,
        bodies,
    }
}

impl Made {
    fn index(&self) -> Vec<u8> {
        let toc_z = zstd::encode_all(&serde_json::to_vec(&self.toc).unwrap()[..], 3).unwrap();
        crate::pull::index::encode_compressed(&toc_z, &self.tarsplit_z).unwrap()
    }

    fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.bodies.keys().cloned().collect();
        keys.sort();
        keys
    }
}

fn files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("a", b"the first file".to_vec()),
        ("b", b"the second file".to_vec()),
        ("c", vec![7u8; 100_000]),
    ]
}

/// A source that has the index of the layer (`again`: the one another of
/// its providers has) and the files `bodies` (by key: they may not be the
/// files of the layer), and records what it is asked.
struct Source_ {
    index: Option<Vec<u8>>,
    again: Option<Vec<u8>>,
    bodies: HashMap<String, Vec<u8>>,
    asked: Mutex<Vec<String>>,
}

#[async_trait]
impl StagingFetcher for Source_ {
    fn described(&self) -> Described {
        Described {
            name: "peers".into(),
            capabilities: Vec::new(),
            max_objects: 8,
        }
    }

    async fn probe(
        &self,
        _scope: &Scope,
        layers: Vec<Blob>,
        (again, _): (bool, Parts),
        out: &Out<Probed>,
    ) -> Result<(), FetcherError> {
        let gone = |_| FetcherError::failed("gone");
        let index = if again { &self.again } else { &self.index };
        for at in 0..layers.len() as u32 {
            let none = Probed {
                layer: at,
                toc: TocSource::None,
                on_demand: false,
                reason: Some(NotLazy::Unreachable),
                toc_file: None,
                tarsplit_file: None,
            };
            let Some(index) = index else {
                out.send(none).await.map_err(gone)?;
                continue;
            };
            let (toc_z, ts_z) = crate::pull::index::split(index).unwrap();
            let fds = vec![
                velarx_base::sealed::sealed_memory(toc_z).unwrap(),
                velarx_base::sealed::sealed_memory(ts_z).unwrap(),
            ];
            let reply = Probed {
                toc: TocSource::Carried,
                reason: Some(NotLazy::NoToc),
                toc_file: Some(0),
                tarsplit_file: Some(1),
                ..none
            };
            out.send_with(reply, fds).await.map_err(gone)?;
        }
        Ok(())
    }

    async fn fetch(
        &self,
        scope: &Scope,
        layer: &LayerScope,
        call: FetchCall,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        let failed = |e: String| FetcherError::failed(e);
        let indexed = LayerToc::kept(layer)?;
        let (mut staged, mut nobody) = (Vec::new(), Vec::new());
        for (i, key) in call.objects.iter().enumerate() {
            self.asked.lock().unwrap().push(key.clone());
            let Some(body) = self.bodies.get(key) else {
                nobody.push(i as u32);
                continue;
            };
            let entry = &indexed.toc.entries[indexed.at[key]];
            let (_, name) = name_of(entry).unwrap();
            let file = Unnamed::begin(layer.staging.as_fd(), body.len() as u64)
                .map_err(|e| failed(e.to_string()))?;
            file.write_chunk(0, body, None)
                .map_err(|e| failed(e.to_string()))?;
            file.finish(layer.staging.as_fd(), &name, scope.verity)
                .map_err(|e| failed(e.to_string()))?;
            staged.push(i as u32);
        }
        for (kind, objects) in [
            (EventKind::Staged, staged),
            (EventKind::Unavailable, nobody),
        ] {
            if !objects.is_empty() {
                let event = Event {
                    objects,
                    ..Event::of(kind)
                };
                out.send(event).await.map_err(|_| failed("gone".into()))?;
            }
        }
        Ok(())
    }
}

/// The origin: it unpacks the layer, handing over its files, and says
/// whether it was told the table of a source.
struct Origin {
    layer: Made,
    unpacked: AtomicUsize,
    told: AtomicUsize,
    fetched: AtomicUsize,
}

fn in_memory(bytes: &[u8]) -> std::os::fd::OwnedFd {
    let fd = rustix::fs::memfd_create(
        "file",
        rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
    )
    .unwrap();
    std::io::Write::write_all(&mut std::fs::File::from(fd.try_clone().unwrap()), bytes).unwrap();
    fd
}

#[async_trait]
impl StagingFetcher for Origin {
    fn described(&self) -> Described {
        Described {
            name: "registry".into(),
            capabilities: Vec::new(),
            max_objects: 8,
        }
    }

    async fn fetch(
        &self,
        _scope: &Scope,
        _layer: &LayerScope,
        _call: FetchCall,
        _out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        self.fetched.fetch_add(1, Ordering::SeqCst);
        Err(FetcherError::failed("the origin is not asked for files"))
    }

    async fn unpack(
        &self,
        _scope: &Scope,
        layer: &LayerScope,
        _call: UnpackCall,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        self.unpacked.fetch_add(1, Ordering::SeqCst);
        if layer.toc.is_some() {
            self.told.fetch_add(1, Ordering::SeqCst);
        }
        let bodies: Vec<_> = self.layer.bodies.values().collect();
        let event = Event {
            files: Some((0..bodies.len() as u32).collect()),
            ..Event::of(EventKind::Staged)
        };
        out.send_with(event, bodies.iter().map(|b| in_memory(b)).collect())
            .await
            .map_err(|_| FetcherError::failed("gone"))?;
        let mut toc = self.layer.toc.clone();
        for e in &mut toc.entries {
            e.fsverity = None;
        }
        crate::unpack::put_claim(&layer.staging, &toc, &self.layer.tarsplit_z)
            .map_err(|e| FetcherError::failed(e.to_string()))
    }
}

/// A pull of the layer from `peers` with the origin `origin`: the context,
/// the peers' fetcher, and the staging area of the pull.
struct Rig {
    ctx: PullCtx,
    peers: Arc<Source_>,
    origin: Arc<Origin>,
    staging_root: PathBuf,
    _tmp: tempfile::TempDir,
    _fetchers: Vec<LocalFetcher>,
}

async fn rig(layer: &Made, index: Option<Vec<u8>>, bodies: HashMap<String, Vec<u8>>) -> Rig {
    rig_with(layer, [index, None], bodies).await
}

/// [`rig`], with the index the source gives when it is asked `again`.
async fn rig_with(
    layer: &Made,
    [index, again]: [Option<Vec<u8>>; 2],
    bodies: HashMap<String, Vec<u8>>,
) -> Rig {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let peers = Arc::new(Source_ {
        index,
        again,
        bodies,
        asked: Mutex::default(),
    });
    let origin = Arc::new(Origin {
        layer: made_again(layer),
        unpacked: AtomicUsize::new(0),
        told: AtomicUsize::new(0),
        fetched: AtomicUsize::new(0),
    });
    let peer_fetcher = LocalFetcher::start(peers.clone(), Limits::default()).unwrap();
    let origin_fetcher = LocalFetcher::start(origin.clone(), Limits::default()).unwrap();
    let links = vec![Link {
        name: "peers".into(),
        conn: FetchConn::new(peer_fetcher.connect().unwrap()).unwrap(),
        idle: TEST_IDLE,
    }];
    let manifest = format!(
        r#"{{"schemaVersion":2,"config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{}","size":2}},"layers":[{}]}}"#,
        "4".repeat(64),
        serde_json::to_string(&layer.desc).unwrap()
    );
    let staging_root = root.join("fetch");
    let staged = StagedFetch::open(
        (
            links,
            Some((
                FetchConn::new(origin_fetcher.connect().unwrap()).unwrap(),
                TEST_IDLE,
            )),
            Vec::new(),
        ),
        &staging_root,
        false,
        ("localhost/a", true),
        Some(b"{}"),
        manifest.as_bytes(),
    )
    .await
    .unwrap();
    let store = Arc::new(velarx_storage::FileStore::new(root.join("objects")).unwrap());
    let session = crate::pull::session::Session::create(&root.join("staging"), store).unwrap();
    let db = velarx_db::Database::open_in_memory().await.unwrap();
    let limits = PullLimits::from_config(&velarx_config::PullConfig::default());
    let ctx =
        PullCtx::new(crate::pull::net::Net::offline(), session, db, limits).with_staged(staged);
    Rig {
        ctx,
        peers,
        origin,
        staging_root,
        _tmp: tmp,
        _fetchers: vec![peer_fetcher, origin_fetcher],
    }
}

fn made_again(layer: &Made) -> Made {
    Made {
        desc: layer.desc.clone(),
        diff: layer.diff,
        toc: layer.toc.clone(),
        tarsplit_z: layer.tarsplit_z.clone(),
        bodies: layer.bodies.clone(),
    }
}

impl Rig {
    async fn pull(&self, layer: &Made) -> ImageResult<crate::pull::LayerDone> {
        crate::pull::pull_layer(&self.ctx, &layer.desc, &layer.diff, Arc::new(|_| {})).await
    }

    fn session(&self) -> Arc<crate::pull::session::Session> {
        self.ctx.sink.clone().session().unwrap()
    }

    fn asked(&self) -> Vec<String> {
        let mut asked = self.peers.asked.lock().unwrap().clone();
        asked.sort();
        asked
    }

    /// Nothing of the staging of a layer is left.
    fn staging_is_empty(&self) -> bool {
        let layers = self.staging_root.join(crate::pull::staged_fetch::LAYERS);
        std::fs::read_dir(layers).map_or(true, |d| d.count() == 0)
    }
}

/// With an empty store every file comes from the source, and the layer is
/// the layer of its blob, the diff id of the configuration, its blob not
/// checked (nobody read it).
#[tokio::test(flavor = "multi_thread")]
async fn a_layer_comes_from_the_index_of_a_source() {
    let layer = made(&files());
    let rig = rig(&layer, Some(layer.index()), layer.bodies.clone()).await;
    let done = rig.pull(&layer).await.unwrap();
    assert_eq!(done.key, velarx_types::LayerKey::Whole(layer.desc.digest));
    assert_eq!(done.diff_id, layer.diff);
    assert!(!done.blob_checked);
    assert_eq!(rig.asked(), layer.keys());
    assert_eq!(rig.origin.unpacked.load(Ordering::SeqCst), 0);
    assert_eq!(done.report.fetched_files, 3);
    assert_eq!(done.report.sources.len(), 1);
    // (the files are the pull's, named by their fs-verity digest)
    let digests: HashSet<String> = done.files.iter().map(|f| f.digest.clone()).collect();
    assert_eq!(digests, layer.keys().into_iter().collect());
    assert!(layer.keys().iter().all(|k| rig.session().has_staged(k)));
    // (committed where they are staged: the session holds the staging)
    assert!(!rig.staging_is_empty());
    // (the table is the stream's, with the objects)
    assert!(done
        .toc
        .entries
        .iter()
        .filter(|e| e.entry_type == TocEntryType::Reg)
        .all(|e| e.verity().is_some()));
}

/// The files the store, or an earlier layer of the pull, has are not asked
/// of the sources.
#[tokio::test(flavor = "multi_thread")]
async fn only_the_files_the_store_lacks_are_fetched() {
    let layer = made(&files());
    let rig = rig(&layer, Some(layer.index()), layer.bodies.clone()).await;
    let all = layer.keys();
    let (staged, stored) = (&layer.bodies[&all[0]], &layer.bodies[&all[1]]);
    rig.session().put(&all[0], staged).unwrap();
    // (a file the store had before the pull)
    rig.session()
        .store()
        .put(Algorithm::Sha256, stored)
        .unwrap();
    let done = rig.pull(&layer).await.unwrap();
    assert_eq!(rig.asked(), [all[2].clone()]);
    assert_eq!(done.diff_id, layer.diff);
    assert_eq!(done.report.fetched_files, 1);
    assert_eq!(rig.origin.unpacked.load(Ordering::SeqCst), 0);
}

/// A claim that the files do not replay to is given up for the origin,
/// which is not told it, and nothing of it is left: a file swapped for one of
/// the same size, a header edited, a fs-verity digest that is another file's,
/// a file nobody has, a file with no fs-verity digest, a file whose digest
/// is a fs-verity digest.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_index_is_given_up_for_the_origin() {
    let layer = made(&files());
    let all = layer.keys();
    let swapped = {
        let mut bodies = layer.bodies.clone();
        let body = bodies.get_mut(&all[0]).unwrap();
        body[0] ^= 1;
        bodies
    };
    let edited = {
        // (the table says another size: the tar-split does not replay)
        let mut other = made(&files());
        other.toc.entries[1].size += 1;
        other.index()
    };
    let other_file = {
        let mut other = made(&files());
        let (a, b) = (other.toc.entries[1].fsverity, other.toc.entries[2].fsverity);
        other.toc.entries[1].fsverity = b;
        other.toc.entries[2].fsverity = a;
        other.index()
    };
    let no_verity = {
        let mut other = made(&files());
        other.toc.entries[1].fsverity = None;
        other.index()
    };
    let verity_named = {
        // (a file keyed by the fs-verity digest of another: the stream is
        // right, the table would name the other)
        let mut other = made(&files());
        other.toc.entries[1].digest = other.toc.entries[2].verity();
        other.index()
    };
    let cases = [
        (Some(layer.index()), swapped),
        (Some(edited), layer.bodies.clone()),
        (Some(other_file), layer.bodies.clone()),
        (Some(no_verity), layer.bodies.clone()),
        (Some(verity_named), layer.bodies.clone()),
        (Some(layer.index()), HashMap::new()),
    ];
    for (index, bodies) in cases {
        let rig = rig(&layer, index, bodies).await;
        let wrong = unpack_by_index(&rig.ctx, &layer.desc, &layer.diff, false, &|_| {}).await;
        assert!(wrong.is_err());
        assert!(rig.staging_is_empty());
        assert!(layer.keys().iter().all(|k| !rig.session().has_staged(k)));
        let done = rig.pull(&layer).await.unwrap();
        assert_eq!(done.diff_id, layer.diff);
        assert_eq!(rig.origin.unpacked.load(Ordering::SeqCst), 1);
        assert_eq!(rig.origin.told.load(Ordering::SeqCst), 0);
        assert_eq!(rig.origin.fetched.load(Ordering::SeqCst), 0);
        // (the layer is the origin's: its blob was hashed there)
        assert!(done.blob_checked);
        assert!(rig.staging_is_empty());
    }
}

/// A claim that keys a file by an object (here one the store has)
/// while its bytes are another's is refused, and nothing the pull records
/// names that object: what a record names is what the engine opened.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_never_names_an_object_the_pull_did_not_open() {
    let layer = made(&files());
    let held = b"a file of the store";
    let secret = verity(held);
    let claim = {
        let mut other = made(&files());
        other.toc.entries[1].digest = Some(secret.clone());
        other.index()
    };
    let rig = rig(&layer, Some(claim), layer.bodies.clone()).await;
    let stored = rig.session().store().put(Algorithm::Sha256, held).unwrap();
    assert_eq!(stored, secret);
    let wrong = unpack_by_index(&rig.ctx, &layer.desc, &layer.diff, false, &|_| {}).await;
    assert!(
        matches!(wrong, Err(ImageError::Contradicted(_))),
        "{:?}",
        wrong.err()
    );
    let done = rig.pull(&layer).await.unwrap();
    assert_eq!(rig.origin.unpacked.load(Ordering::SeqCst), 1);
    assert!(done.files.iter().all(|f| f.digest != secret));
    assert!(done
        .toc
        .entries
        .iter()
        .all(|e| e.verity().as_deref() != Some(secret.as_str())
            && e.digest.as_deref() != Some(secret.as_str())));
}

/// A layer made from an index on a store without fs-verity (`VerityMode::Off`,
/// which the rig's store is): the commit measures each file in userspace and
/// names it by that measure, and a file that is not the one the replay read
/// is refused, with nothing of it named.
#[tokio::test(flavor = "multi_thread")]
async fn a_layer_by_index_on_a_store_without_fs_verity() {
    let layer = made(&files());
    for wrong in [false, true] {
        let rig = rig(&layer, Some(layer.index()), layer.bodies.clone()).await;
        assert_eq!(
            rig.session().store().verity(),
            velarx_storage::VerityMode::Off
        );
        let done = rig.pull(&layer).await.unwrap();
        assert_eq!(done.diff_id, layer.diff);
        let keys = layer.keys();
        if wrong {
            // (the same size, other bytes, after the replay)
            let path = rig.session().content_path(&keys[0]).unwrap();
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[0] ^= 1;
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644))
                .unwrap();
            std::fs::write(&path, bytes).unwrap();
            let e = rig.session().commit(None).unwrap_err().to_string();
            assert!(e.contains("not the fs-verity digest it is known by"), "{e}");
            assert!(!rig.session().store().contains(&keys[0]));
            continue;
        }
        let committed = rig.session().commit(None).unwrap();
        let mut named: Vec<String> = committed.iter().map(|c| c.object.verity.clone()).collect();
        named.sort();
        assert_eq!(named, keys);
        for (key, body) in &layer.bodies {
            assert_eq!(&verity(body), key);
            assert!(rig.session().store().contains(key));
        }
    }
}

/// An index that does not replay is asked for again, of another provider
/// (the source is told: `again`), before the origin; one that does not
/// replay either leaves the layer to the origin.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_index_is_asked_for_again_before_the_origin() {
    let layer = made(&files());
    let wrong = {
        let mut other = made(&files());
        other.toc.entries[1].size += 1;
        other.index()
    };
    for (again, from_origin) in [(Some(layer.index()), false), (Some(wrong.clone()), true)] {
        let rig = rig_with(&layer, [Some(wrong.clone()), again], layer.bodies.clone()).await;
        let done = rig.pull(&layer).await.unwrap();
        assert_eq!(done.diff_id, layer.diff);
        assert_eq!(
            rig.origin.unpacked.load(Ordering::SeqCst),
            usize::from(from_origin)
        );
        assert_eq!(done.blob_checked, from_origin);
    }
}

/// With no source that has an index the origin unpacks the layer.
#[tokio::test(flavor = "multi_thread")]
async fn a_layer_nobody_has_an_index_of_comes_from_the_origin() {
    let layer = made(&files());
    let rig = rig(&layer, None, HashMap::new()).await;
    let done = rig.pull(&layer).await.unwrap();
    assert_eq!(rig.origin.unpacked.load(Ordering::SeqCst), 1);
    assert!(done.blob_checked);
    assert!(rig.asked().is_empty());
}

/// A file of `len` bytes that does not repeat.
fn noise(len: usize) -> Vec<u8> {
    let mut x = 88172645463325252u64;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// The pieces of a file too big for a peer to give whole (a layer that has
/// no table of contents has none for it): the replay cuts it in 4 MiB
/// pieces whichever way the layer comes, the table has them as the chunks of
/// the file, and they are recorded where a peer finds them.  What the table
/// says of the rest of the layer is what it said.
#[tokio::test(flavor = "multi_thread")]
async fn the_pieces_of_a_big_file_are_in_the_table() {
    let big = noise(40 << 20);
    let layer = made(&[("a", b"small".to_vec()), ("big", big.clone())]);
    let (from_origin, from_index) = (
        rig(&layer, None, HashMap::new()).await,
        rig(&layer, Some(layer.index()), layer.bodies.clone()).await,
    );
    let mut tables = Vec::new();
    for rig in [&from_origin, &from_index] {
        let done = rig.pull(&layer).await.unwrap();
        assert_eq!(done.diff_id, layer.diff);
        let at = done
            .toc
            .entries
            .iter()
            .position(|e| e.name.ends_with("big"))
            .unwrap();
        let pieces: Vec<&TocEntry> = std::iter::once(&done.toc.entries[at])
            .chain(
                done.toc.entries[at + 1..]
                    .iter()
                    .take_while(|e| e.entry_type == TocEntryType::Chunk),
            )
            .collect();
        assert_eq!(pieces.len(), 10);
        for (i, (piece, bytes)) in pieces.iter().zip(big.chunks(PIECE as usize)).enumerate() {
            assert_eq!(piece.chunk_size, PIECE, "{i}");
            assert_eq!(piece.chunk_offset, i as u64 * PIECE);
            assert_eq!(
                piece.chunk_digest.as_deref(),
                Some(Digest::of(Algorithm::Sha256, bytes).to_string().as_str())
            );
        }
        // (the file itself is the digest of all of it, and a small one has
        // no pieces)
        assert_eq!(
            done.toc.entries[at].digest.as_deref(),
            Some(Digest::of(Algorithm::Sha256, &big).to_string().as_str())
        );
        assert_eq!(done.toc.entries.len(), at + 10);
        let small = done
            .toc
            .entries
            .iter()
            .find(|e| e.name.ends_with("a"))
            .unwrap();
        assert_eq!(small.chunk_size, 5);
        // (recorded for a peer: the pieces, by the key of the file, which
        // the commit makes its fs-verity digest where the origin gave it)
        let key = done.toc.entries[at].content_key().unwrap();
        assert_eq!(done.chunks.len(), 10);
        assert!(done
            .chunks
            .iter()
            .all(|c| c.file_digest == key && c.size == PIECE));
        // (the same stream whatever the pieces)
        let mut without = (*done.toc).clone();
        without
            .entries
            .retain(|e| e.entry_type != TocEntryType::Chunk);
        assert_eq!(
            crate::layer::reproduce::stream_size(&done.toc, &done.tarsplit).unwrap(),
            crate::layer::reproduce::stream_size(&without, &done.tarsplit).unwrap()
        );
        // (the objects of the files the origin handed over are known at the
        // commit)
        let mut table = (*done.toc).clone();
        for e in &mut table.entries {
            e.fsverity = None;
        }
        tables.push(serde_json::to_string(&table).unwrap());
    }
    // (the table is the stream's, the same from the origin and from an index)
    assert!(tables[0] == tables[1]);
}

/// A table with no offsets (that of a layer without a table of contents)
/// gives the pieces of a file to the fetchers, which ask for them by digest;
/// the table of a blob is still refused with the offsets it has not.
#[test]
fn the_pieces_of_a_table_without_a_blob_are_given_to_the_fetchers() {
    let mut file = TocEntry {
        size: 10 << 20,
        digest: Some(crate::sha256_text(b"file")),
        chunk_digest: Some(crate::sha256_text(b"one")),
        chunk_size: 4 << 20,
        ..TocEntry::new("f", TocEntryType::Reg)
    };
    file.fsverity = velarx_storage::to_toc(&verity(b"file"));
    let chunk = |offset: u64, size: u64, text: &[u8]| TocEntry {
        chunk_digest: Some(crate::sha256_text(text)),
        chunk_size: size,
        chunk_offset: offset,
        ..TocEntry::new("f", TocEntryType::Chunk)
    };
    let toc = Toc {
        version: TOC_VERSION,
        entries: vec![
            file,
            chunk(4 << 20, 4 << 20, b"two"),
            chunk(8 << 20, 2 << 20, b"three"),
        ],
        tar_split_digest: None,
    };
    let got = file_chunks(&toc, Algorithm::Sha256, 0, None, 16 << 20).unwrap();
    let places: Vec<(u64, u64)> = got.chunks.iter().map(|c| (c.offset, c.size)).collect();
    assert_eq!(
        places,
        [(0, 4 << 20), (4 << 20, 4 << 20), (8 << 20, 2 << 20)]
    );
    assert!(file_chunks(&toc, Algorithm::Sha256, 0, Some(1 << 30), 16 << 20).is_err());
}

/// A layer with a table of contents is pulled by it from whatever origin
/// the fetchers reach, when they carry the table and the files: its source
/// is not a registry.
#[tokio::test(flavor = "multi_thread")]
async fn a_layer_with_a_table_is_pulled_by_it_from_any_origin() {
    use super::tests::{pulled, without_table, written};
    let (blob, desc) = written(Algorithm::Sha256, false);
    // (a table in JSON: the fetchers of the rig read no other)
    let desc = without_table(&desc);
    let info = parse_info(&desc).unwrap().unwrap();
    let range = |(off, len, _): (u64, u64, u64)| blob[off as usize..(off + len) as usize].to_vec();
    let tarsplit = info.tarsplit.map(range).unwrap_or_default();
    let index = crate::pull::index::encode_compressed(&range(info.toc), &tarsplit).unwrap();
    let bodies = pulled(&blob, &desc, false)
        .unwrap()
        .toc
        .entries
        .iter()
        .filter(|e| e.entry_type == TocEntryType::Reg)
        .map(|e| {
            let data: Vec<u8> = (0..e.size).map(|i| (i * 7 % 251) as u8).collect();
            (verity(&data), data)
        })
        .collect();
    let layer = Made {
        desc,
        ..made(&files())
    };
    let rig = rig(&layer, Some(index), bodies).await;
    let done = rig.pull(&layer).await.unwrap();
    assert_eq!(done.key, velarx_types::LayerKey::Toc(info.checksum));
    assert_eq!(rig.origin.unpacked.load(Ordering::SeqCst), 0);
    assert_eq!(done.report.fetched_files, 2);
}
