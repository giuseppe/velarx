// SPDX-License-Identifier: Apache-2.0
//! The store service (`org.velarx.Store`): what the store holds, given
//! by digest as read-only descriptors; the changes of what may be
//! announced; and the service started by a socket on descriptor 3, with
//! no daemon.

use crate::common::*;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;
use velarx_core::store_service::{self, ChangeKind, StoreProxy, StoreService, Want};

/// The service of `e`'s store on a socket of `dir`, served in the
/// `LocalSet` the test runs in.
async fn serve(dir: &Path, service: StoreService) -> PathBuf {
    let socket = dir.join("store.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    tokio::task::spawn_local(store_service::serve(
        listener,
        service,
        None,
        |_| true,
        velarx_content::activation::Limits::default(),
    ));
    socket
}

fn want(digest: &impl std::fmt::Display) -> Want {
    Want {
        digest: digest.to_string(),
        size: None,
    }
}

/// The bytes of an answer: `length` bytes from `offset` of its descriptor.
fn bytes_of(fd: &OwnedFd, offset: u64, length: u64) -> Vec<u8> {
    let mut file = std::fs::File::from(fd.try_clone().unwrap());
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut out = vec![0u8; length as usize];
    file.read_exact(&mut out).unwrap();
    out
}

/// The whole of a file, to its end.
fn whole(fd: &OwnedFd) -> Vec<u8> {
    let mut file = std::fs::File::from(fd.try_clone().unwrap());
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut out = Vec::new();
    file.read_to_end(&mut out).unwrap();
    out
}

fn not_found<T: std::fmt::Debug>(reply: Result<T, store_service::StoreError>) -> bool {
    matches!(reply, Err(store_service::StoreError::NotFound { .. }))
}

fn read_only(fd: &OwnedFd) -> bool {
    rustix::fs::fcntl_getfl(fd)
        .is_ok_and(|f| !f.intersects(rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR))
}

/// A layer pulled: its files are given, as read-only descriptors with
/// their place; what is not in the store, or is larger than asked, is not;
/// more than a batch is refused.
#[tokio::test]
async fn test_what_the_store_holds_is_given_read_only() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let layer = build_chunked(&sample());
            let e = env().await;
            e.publish(&[&layer], &[ZSTD]);
            e.pull().await.unwrap();
            let hello = vid(b"hello\n");

            let service = StoreService::new(e.db.clone(), e.store.clone())
                .await
                .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let socket = serve(dir.path(), service).await;
            let mut conn = store_service::connect(&socket).await.unwrap();

            let info = conn.get_info().await.unwrap().unwrap();
            assert_eq!(info.proto, store_service::PROTO);
            assert_eq!(
                info.limit("max_lookup").unwrap() as usize,
                store_service::MAX_LOOKUP
            );

            let absent = sha(b"not in the store");
            let wrong_size = Want {
                digest: hello.to_string(),
                size: Some(1),
            };
            let (reply, fds) = conn
                .lookup(vec![want(&hello), want(&absent), wrong_size])
                .await
                .unwrap();
            let items = reply.unwrap().items;
            assert_eq!(items.len(), 3);
            assert_eq!(fds.len(), 1, "one descriptor for the one item given");
            let given = &items[0];
            assert_eq!(given.digest, hello);
            let fd = &fds[given.fd.unwrap() as usize];
            assert!(read_only(fd), "the descriptor is read-only");
            assert_eq!(bytes_of(fd, given.offset, given.length), b"hello\n");
            assert!(items[1].fd.is_none(), "what the store lacks");
            assert!(items[2].fd.is_none(), "a size other than the one asked");

            // more than a batch, or what is not a digest
            let many: Vec<Want> = (0..=store_service::MAX_LOOKUP)
                .map(|i| want(&sha(format!("{i}").as_bytes())))
                .collect();
            let (reply, fds) = conn.lookup(many).await.unwrap();
            assert!(reply.is_err() && fds.is_empty());
            let (reply, _) = conn.lookup(vec![want(&"../../etc/passwd")]).await.unwrap();
            assert!(reply.is_err());
        })
        .await;
}

/// What a pull with credentials brought is given like the rest: its file by
/// its fs-verity digest, a chunk, its manifest, configuration, kept index,
/// the index of its layer and its startup profile, each by its digest, and
/// what the store does not have is not.
#[tokio::test]
async fn test_every_object_of_the_store_is_given_by_its_digest() {
    use velarx_registry::auth::{Credentials, RegistryAccess};
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let layer = build_chunked(&sample());
            let e = env().await;
            e.publish(&[&layer], &[ZSTD]);
            let client = e.client().with_access(&RegistryAccess {
                creds: Some(Credentials::basic("alice", "secret")),
                ..Default::default()
            });
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            let result = e
                .service
                .pull_with_client(&client, &format!("{}/test:latest", e.host), tx)
                .await
                .unwrap();
            let record = e.service.get(&result.id).await.unwrap();
            let index = sha(b"a kept index");
            e.db.set_index(&index, "an index").await.unwrap();
            let profile = velarx_fuse::composefs::profile_path(e.store.root(), &result.id);
            let text = format!(r#"{{"v":1,"files":["{}"]}}"#, vid(b"hello\n"));
            std::fs::create_dir_all(profile.parent().unwrap()).unwrap();
            std::fs::write(&profile, &text).unwrap();

            let service = StoreService::new(e.db.clone(), e.store.clone())
                .await
                .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let socket = serve(dir.path(), service).await;
            let mut conn = store_service::connect(&socket).await.unwrap();

            let given = [
                (vid(b"hello\n"), b"hello\n".to_vec()),
                (sha(b"hello\n").to_string(), b"hello\n".to_vec()),
                (
                    record.manifest_digest.to_string(),
                    record.manifest.clone().into_bytes(),
                ),
                (
                    record.config_digest.to_string(),
                    record.config.clone().into_bytes(),
                ),
                (index.to_string(), b"an index".to_vec()),
            ];
            let mut wants: Vec<Want> = given.iter().map(|(d, _)| want(d)).collect();
            wants.push(want(&sha(b"not in the store")));
            let (reply, fds) = conn.lookup(wants).await.unwrap();
            let items = reply.unwrap().items;
            for (item, (digest, data)) in items.iter().zip(&given) {
                let fd = &fds[item.fd.unwrap_or_else(|| panic!("{digest} not given")) as usize];
                assert_eq!(&bytes_of(fd, item.offset, item.length), data, "{digest}");
            }
            assert!(items[given.len()].fd.is_none());

            let (reply, fds) = conn.index(&layer.key().to_string(), 1 << 20).await.unwrap();
            assert!(velarx_content::pull::index::decode(
                &whole(&fds[reply.unwrap().fd as usize]),
                1 << 20
            )
            .is_ok());
            let (reply, fds) = conn
                .index(&sha(b"no layer").to_string(), 1 << 20)
                .await
                .unwrap();
            assert!(not_found(reply) && fds.is_empty());
            let (reply, fds) = conn
                .profile(&format!("sha256:{}", result.id), 1 << 20)
                .await
                .unwrap();
            assert_eq!(whole(&fds[reply.unwrap().file as usize]), text.as_bytes());

            // announced too
            let a = announced(&e).await;
            assert_eq!(a.layers, layer.announced_names());
            assert_eq!(a.images.len(), 1);
        })
        .await;
}

/// A file only a read-only store has (`additional_image_stores`) is given
/// by its digest as any other.
#[tokio::test]
async fn test_an_object_of_a_read_only_store_is_given() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let ro = velarx_storage::FileStore::new(dir.path().join("ro-objects")).unwrap();
            let held = ro
                .put(
                    velarx_types::digest::Algorithm::Sha256,
                    b"of the read-only store",
                )
                .unwrap();
            let e = env_sources_over(
                velarx_config::PullConfig::default(),
                velarx_config::PushConfig::default(),
                Fetchers::default(),
                Some(dir.path().join("ro-objects")),
            )
            .await;
            assert!(!e.store.contains_local(&held));
            let service = StoreService::new(e.db.clone(), e.store.clone())
                .await
                .unwrap();
            let socket = serve(dir.path(), service).await;
            let mut conn = store_service::connect(&socket).await.unwrap();
            let (reply, fds) = conn.lookup(vec![want(&held)]).await.unwrap();
            let item = &reply.unwrap().items[0];
            let fd = &fds[item.fd.expect("given") as usize];
            assert!(read_only(fd));
            assert_eq!(
                bytes_of(fd, item.offset, item.length),
                b"of the read-only store"
            );
        })
        .await;
}

/// What the store may announce now.
async fn announced(e: &Env) -> store_service::Announcement {
    store_service::Announcement::from_database(&e.db)
        .await
        .unwrap()
}

/// A node that pulls lazily.
async fn lazy_env() -> Env {
    env_with(velarx_config::PullConfig {
        lazy_window_files: 0,
        ..velarx_config::PullConfig::default()
    })
    .await
}

/// A lazy layer is neither announced nor indexed before its completion: it
/// is not in the store.  It is, with its image, in the commit that
/// completes it; a layer marked incomplete (its tar-split gone) is not
/// again.
#[tokio::test]
async fn test_a_lazy_layer_is_neither_announced_nor_indexed_before_its_completion() {
    let e = lazy_env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    let result = e.pull_lazy().await.unwrap();
    assert!(e.service.get(&result.id).await.is_err());
    let service = StoreService::new(e.db.clone(), e.store.clone())
        .await
        .unwrap();
    let key = layer.key().to_string();
    // (nothing of it is listed, nothing is given)
    let before = announced(&e).await;
    assert!(before.layers.is_empty());
    assert!(before.images.is_empty());
    assert!(service.index_of(&key, 1 << 20).await.unwrap().is_none());

    // a container read a file: it is the layer's own, fetched and checked
    e.service
        .fetch_lazy_file(&vid(b"hello\n"), &layer.key())
        .await
        .unwrap();
    assert!(announced(&e).await.images.is_empty());
    assert!(service.index_of(&key, 1 << 20).await.unwrap().is_none());

    e.service
        .complete_image(&format!("{}/test:latest", e.host))
        .await
        .unwrap();
    let after = announced(&e).await;
    assert_eq!(after.layers, layer.announced_names());
    assert_eq!(after.images.len(), 1);
    assert_eq!(after.images[0].id, result.id);
    assert!(service.index_of(&key, 1 << 20).await.unwrap().is_some());
    assert!(e.store.contains(&vid(b"hello\n")));

    // a layer whose tar-split went is not complete
    e.db.mark_layer_incomplete(&layer.key()).await.unwrap();
    assert!(announced(&e).await.layers.is_empty());
    assert!(service.index_of(&key, 1 << 20).await.unwrap().is_none());
}

/// A layer made partly of files the store had (an image of a new version
/// pulled over the old one) is announced as any other, and its index and
/// all its files are given.
#[tokio::test]
async fn test_a_layer_made_partly_of_store_files_is_announced_and_given() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let e = lazy_env().await;
            let v1 = build_chunked(&sample());
            e.publish(&[&v1], &[ZSTD]);
            e.pull().await.unwrap();

            let mut items = sample();
            items.push(Item::File {
                name: "etc/other",
                data: b"other\n".to_vec(),
                chunk: 4096,
            });
            let v2 = build_chunked(&items);
            e.publish(&[&v2], &[ZSTD]);
            e.pull_lazy().await.unwrap();
            e.service
                .complete_image(&format!("{}/test:latest", e.host))
                .await
                .unwrap();

            let a = announced(&e).await;
            for name in v2.announced_names() {
                assert!(a.layers.contains(&name), "{name} not announced");
            }
            let service = StoreService::new(e.db.clone(), e.store.clone())
                .await
                .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let socket = serve(dir.path(), service).await;
            let mut conn = store_service::connect(&socket).await.unwrap();
            let (reply, fds) = conn.index(&v2.key().to_string(), 1 << 20).await.unwrap();
            assert!(!fds.is_empty() && reply.is_ok());
            // the file of the old version and the new one
            let (reply, fds) = conn
                .lookup(vec![want(&vid(b"hello\n")), want(&vid(b"other\n"))])
                .await
                .unwrap();
            let items = reply.unwrap().items;
            assert!(items.iter().all(|i| i.fd.is_some()) && fds.len() == 2);
        })
        .await;
}

/// The next change of a stream, within a few seconds.
async fn next_change<S>(stream: &mut std::pin::Pin<&mut S>) -> store_service::Change
where
    S: futures::Stream<
        Item = zlink::Result<Result<store_service::Change, store_service::StoreError>>,
    >,
{
    use futures::StreamExt;
    tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("a change, once committed")
        .unwrap()
        .unwrap()
        .unwrap()
}

/// The store lists its images with what they are made of, none while a lazy
/// pull is in progress; one image is asked for by id, digest, name or the
/// start of its id; the stream tells that an image appeared and that it
/// went; a local name of it is given too.
#[tokio::test]
async fn test_the_store_lists_its_images_and_tells_when_one_appears() {
    use store_service::StoreError;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let db_path = dir.path().join("db.sqlite");
            let writer = velarx_db::Database::open(&db_path).await.unwrap();
            let e = env_on(
                writer,
                velarx_config::PullConfig {
                    lazy_window_files: 0,
                    ..velarx_config::PullConfig::default()
                },
                velarx_config::PushConfig::default(),
                Fetchers::default(),
                None,
            )
            .await;
            let reader = velarx_db::Database::open(&db_path).await.unwrap();
            let service = StoreService::new(reader, e.store.clone()).await.unwrap();
            let socket = serve(dir.path(), service).await;
            let mut conn = store_service::connect(&socket).await.unwrap();
            let info = conn.get_info().await.unwrap().unwrap();
            assert_eq!(info.proto, store_service::PROTO);
            assert!(store_service::image_list(&mut conn)
                .await
                .unwrap()
                .is_empty());

            let mut watching = store_service::connect(&socket).await.unwrap();
            let stream = watching.subscribe().await.unwrap();
            futures::pin_mut!(stream);
            assert_eq!(next_change(&mut stream).await.kind, ChangeKind::Snapshot);

            let layer = build_chunked(&sample());
            e.publish(&[&layer], &[ZSTD]);
            let name = format!("{}/test:latest", e.host);
            let result = e.pull_lazy().await.unwrap();

            // a pull in progress is not an image of the store: nothing is
            // listed or announced
            assert!(store_service::image_list(&mut conn)
                .await
                .unwrap()
                .is_empty());

            e.service.complete_image(&name).await.unwrap();
            let record = e.service.get(&result.id).await.unwrap();
            // (the layer enters the store in a transaction of its own, the
            // image in the one of its last layer: a reader sees the layer
            // before or with the image, never an image with a layer lacking)
            let mut layers_in = Vec::new();
            let appeared = loop {
                let change = next_change(&mut stream).await;
                assert_eq!(change.kind, ChangeKind::Added);
                layers_in.extend(change.layers.clone());
                if !change.images.is_empty() {
                    break change;
                }
            };
            assert_eq!(layers_in, layer.announced_names());
            assert_eq!(appeared.images.len(), 1);
            let listed = store_service::image_list(&mut conn).await.unwrap();
            assert_eq!(listed, appeared.images);
            let image = &listed[0];
            assert_eq!(image.id, result.id);
            assert_eq!(image.manifest_digest, record.manifest_digest.to_string());
            assert_eq!(image.config_digest, record.config_digest.to_string());
            assert_eq!(image.layers, vec![layer.key().to_string()]);
            assert_eq!(image.size, layer.blob.len() as u64);
            assert_eq!(image.tags, vec![name.clone()]);
            assert_eq!(
                image.repo_digests,
                vec![format!("{}/test@{}", e.host, record.manifest_digest)]
            );

            // by id, digest, name, repository and digest, the start of the id
            for reference in [
                image.id.clone(),
                image.manifest_digest.clone(),
                name.clone(),
                image.repo_digests[0].clone(),
                image.id[..12].to_string(),
            ] {
                let got = conn.image_inspect(&reference).await.unwrap().unwrap();
                assert_eq!(&got.image, image, "{reference}");
            }
            for (reference, bad) in [
                ("sha256:".to_string() + &"0".repeat(64), false),
                ("nothing:here".to_string(), false),
                (String::new(), true),
                ("x".repeat(1000), true),
            ] {
                match conn.image_inspect(&reference).await.unwrap() {
                    Err(StoreError::NotFound { .. }) => assert!(!bad, "{reference:?}"),
                    Err(StoreError::InvalidArgument { .. }) => assert!(bad, "{reference:?}"),
                    other => panic!("{reference:?}: {other:?}"),
                }
            }

            // a local name is listed and found like the others
            e.service.tag(&name, "localhost/mine:1").await.unwrap();
            let listed = store_service::image_list(&mut conn).await.unwrap();
            assert!(listed[0].tags.contains(&"localhost/mine:1".to_string()));
            assert_eq!(
                conn.image_inspect("localhost/mine:1")
                    .await
                    .unwrap()
                    .unwrap()
                    .image
                    .id,
                image.id
            );

            e.service.remove(&result.id, true).await.unwrap();
            // (the local name above is announced as the image changed, or in
            // the one change of what follows)
            let gone = loop {
                let change = next_change(&mut stream).await;
                if change.kind == ChangeKind::Removed {
                    break change;
                }
                assert_eq!(change.kind, ChangeKind::Added);
            };
            assert_eq!(gone.images.len(), 1);
            assert_eq!(gone.images[0].id, image.id);
            assert!(store_service::image_list(&mut conn)
                .await
                .unwrap()
                .is_empty());
        })
        .await;
}

/// The list has every image of the store with its names: one pulled with
/// credentials, a local commit and its local tag.
#[tokio::test]
async fn test_the_list_has_every_image_and_its_names() {
    use velarx_registry::auth::{Credentials, RegistryAccess};
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let layer = build_chunked(&sample());
            let e = env().await;
            e.publish(&[&layer], &[ZSTD]);
            let client = e.client().with_access(&RegistryAccess {
                creds: Some(Credentials::basic("alice", "secret")),
                ..Default::default()
            });
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            let name = format!("{}/test:latest", e.host);
            let pulled = e
                .service
                .pull_with_client(&client, &name, tx)
                .await
                .unwrap();

            // a commit: another image of the same layers, with a local name
            let mut record = e.db.list_images().await.unwrap()[0].clone();
            let committed = "c".repeat(64);
            record.id = committed.clone();
            record.manifest_digest = sha(b"another manifest");
            e.db.insert_image(&record).await.unwrap();
            for (i, l) in
                e.db.get_image_layers(&pulled.id)
                    .await
                    .unwrap()
                    .iter()
                    .enumerate()
            {
                e.db.insert_image_layer(&committed, &l.key, i as i32)
                    .await
                    .unwrap();
            }
            e.db.insert_image_tag(&velarx_db::ImageTag {
                repository: "localhost/committed".into(),
                tag: "latest".into(),
                image_id: committed.clone(),
            })
            .await
            .unwrap();

            let service = StoreService::new(e.db.clone(), e.store.clone())
                .await
                .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let socket = serve(dir.path(), service).await;
            let mut conn = store_service::connect(&socket).await.unwrap();
            let listed = store_service::image_list(&mut conn).await.unwrap();
            assert_eq!(listed.len(), 2);
            for (id, tag) in [
                (&pulled.id, name.as_str()),
                (&committed, "localhost/committed:latest"),
            ] {
                let image = listed.iter().find(|i| &i.id == id).unwrap();
                assert_eq!(image.tags, vec![tag.to_string()]);
                assert_eq!(
                    conn.image_inspect(tag).await.unwrap().unwrap().image,
                    *image
                );
            }
        })
        .await;
}

/// A regular file opened for reading only.
fn assert_read_only_file(fd: &OwnedFd) {
    assert!(read_only(fd));
    assert!(std::fs::File::from(fd.try_clone().unwrap())
        .metadata()
        .unwrap()
        .is_file());
}

/// The index of a gzip layer comes in a file with no name.
#[tokio::test]
async fn test_the_index_of_a_layer_is_a_file_with_no_name() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let layer = build_gzip(&sample());
            let e = env().await;
            e.publish(&[&layer], &[GZIP]);
            e.pull().await.unwrap();
            let digest = sha(&layer.blob);

            let service = StoreService::new(e.db.clone(), e.store.clone())
                .await
                .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let socket = serve(dir.path(), service).await;
            let mut conn = store_service::connect(&socket).await.unwrap();
            let (reply, fds) = conn.index(&digest.to_string(), 16 << 20).await.unwrap();
            let reply = reply.unwrap();
            let fd = &fds[reply.fd as usize];
            assert_read_only_file(fd);
            let index = whole(fd);
            assert!(!index.is_empty());
            assert!(velarx_content::pull::index::decode(&index, 16 << 20).is_ok());
            let (reply, fds) = conn.index(&digest.to_string(), 1).await.unwrap();
            assert!(not_found(reply) && fds.is_empty());
        })
        .await;
}

/// A subscriber gets what may be announced, then what another connection
/// to the database (another process) commits: the service watches it.
#[tokio::test]
async fn test_subscribers_learn_what_another_process_commits() {
    use futures::StreamExt;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let db_path = dir.path().join("db.sqlite");
            let writer = velarx_db::Database::open(&db_path).await.unwrap();
            let e = env_on(
                writer,
                velarx_config::PullConfig::default(),
                velarx_config::PushConfig::default(),
                Fetchers::default(),
                None,
            )
            .await;
            let reader = velarx_db::Database::open(&db_path).await.unwrap();
            let service = StoreService::new(reader, e.store.clone()).await.unwrap();
            let socket = serve(dir.path(), service).await;
            let mut conn = store_service::connect(&socket).await.unwrap();
            let stream = conn.subscribe().await.unwrap();
            futures::pin_mut!(stream);
            let first = stream.next().await.unwrap().unwrap().unwrap();
            assert_eq!(first.kind, ChangeKind::Snapshot);
            assert!(first.layers.is_empty());

            let layer = build_chunked(&sample());
            e.publish(&[&layer], &[ZSTD]);
            e.pull().await.unwrap();
            // (woken by the writes of the commit: no timer runs)
            let next = tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await
                .expect("a change, once committed")
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(next.kind, ChangeKind::Added);
            assert_eq!(next.layers, layer.announced_names());
            assert_eq!(next.images.len(), 1);
        })
        .await;
}

/// The configuration of a store in `base`, written there; its path.
fn write_config(base: &Path) -> PathBuf {
    let path = base.join("config.toml");
    std::fs::write(
        &path,
        format!(
            "[server]\nsocket = \"{}\"\nstate_dir = \"{}\"\nroot_dir = \"{}\"\n\
             [storage]\nroot = \"{}\"\n",
            base.join("run/api.sock").display(),
            base.join("state").display(),
            base.join("root").display(),
            base.join("storage").display(),
        ),
    )
    .unwrap();
    path
}

/// The `velarx` binary of this build, linked where the test keeps it:
/// the target directory may be shared, and another build replace it.
fn velarx_binary(keep: &Path) -> PathBuf {
    let exe = Path::new(crate::common::worker());
    let dir = keep.join("bin");
    std::fs::create_dir_all(&dir).unwrap();
    let kept = dir.join("velarx");
    if std::fs::hard_link(exe, &kept).is_err() {
        velarx_base::testing::copy_program(exe, &kept);
    }
    kept
}

/// A connection to the store service of `config`, started if nothing serves
/// it: `exe store-service` with the socket bound here as its descriptor 3
/// (the way a client without systemd or a daemon gets it).
async fn connect_or_start(
    config: &velarx_config::Config,
    config_path: &Path,
    exe: &Path,
    idle: Duration,
) -> std::io::Result<zlink::Connection<zlink::tokio::unix::Stream>> {
    let socket = store_service::socket_path(config);
    if let Ok(conn) = store_service::connect(&socket).await {
        return Ok(conn);
    }
    let cmd = store_service::start_command(exe, config_path, Some(idle));
    let (stream, child) = tokio::task::spawn_blocking(move || {
        velarx_content::activation::start(&socket, cmd, std::process::Stdio::inherit())
    })
    .await
    .map_err(std::io::Error::other)??;
    if let Some(mut child) = child {
        // (it lives on: reaped in the background)
        std::thread::spawn(move || child.wait());
    }
    stream.set_nonblocking(true)?;
    velarx_content::activation::checked(tokio::net::UnixStream::from_std(stream)?)
}

/// Without a daemon or systemd: the first client starts the service (the
/// socket it binds on descriptor 3), the next ones use that one instance,
/// and it leaves once idle; the next client starts it again.
#[tokio::test]
async fn test_a_client_starts_the_service_which_leaves_when_idle() {
    let base = tempfile::tempdir().unwrap();
    let config_path = write_config(base.path());
    let config = velarx_config::Config::load_or_default(&config_path).unwrap();
    let socket = store_service::socket_path(&config);
    let keep = tempfile::tempdir_in(Path::new(crate::common::worker()).parent().unwrap()).unwrap();
    let exe = &velarx_binary(keep.path());
    let idle = Duration::from_secs(2);

    let mut conn = connect_or_start(&config, &config_path, exe, idle)
        .await
        .unwrap();
    assert_eq!(
        conn.get_info().await.unwrap().unwrap().proto,
        store_service::PROTO
    );
    let (reply, fds) = conn.lookup(vec![want(&sha(b"x"))]).await.unwrap();
    assert!(reply.unwrap().items[0].fd.is_none() && fds.is_empty());
    assert!(socket.exists(), "the started instance serves the socket");
    let mut again = connect_or_start(&config, &config_path, exe, idle)
        .await
        .unwrap();
    assert!(again.get_info().await.unwrap().is_ok());
    drop((conn, again));
    let quiet = std::time::Instant::now();

    // idle: it leaves, and takes its socket away, once idle for its time
    assert!(socket_goes(&socket).await, "it did not leave");
    let left = quiet.elapsed();
    assert!(
        left >= idle - Duration::from_millis(200) && left < idle + Duration::from_secs(2),
        "it left after {left:?} without a connection, not about {idle:?}"
    );
    let mut conn = connect_or_start(&config, &config_path, exe, idle)
        .await
        .unwrap();
    assert!(conn.get_info().await.unwrap().is_ok());
}

/// Started by systemd: the listening socket on descriptor 3, with
/// `LISTEN_PID` and `LISTEN_FDS`.
#[tokio::test]
async fn test_the_service_takes_a_socket_from_systemd() {
    let base = tempfile::tempdir().unwrap();
    let config_path = write_config(base.path());
    let config = velarx_config::Config::load_or_default(&config_path).unwrap();
    let socket = store_service::socket_path(&config);
    let listener = velarx_base::ipc::bind_private(&socket).unwrap();
    let keep = tempfile::tempdir_in(Path::new(crate::common::worker()).parent().unwrap()).unwrap();
    let exe = velarx_binary(keep.path());
    let mut cmd = std::process::Command::new("sh");
    cmd.arg("-c")
        .arg("LISTEN_PID=$$ LISTEN_FDS=1 exec \"$0\" \"$@\"")
        .arg(&exe)
        .arg("store-service")
        .arg("--config")
        .arg(&config_path)
        .arg("--idle-exit")
        .arg("30");
    velarx_base::spawn::pass_as_fd3(&mut cmd, listener.as_raw_fd());
    let mut child = cmd.spawn().unwrap();
    drop(listener);
    let mut conn = store_service::connect(&socket).await.unwrap();
    let info = conn.get_info().await.unwrap().unwrap();
    assert_eq!(info.proto, store_service::PROTO);
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Served from a process that lives on (`velarx varlink`): in a
/// thread of its own, once; another instance does not start beside it.
#[tokio::test]
async fn test_a_daemon_serves_it_once() {
    let base = tempfile::tempdir().unwrap();
    let config_path = write_config(base.path());
    let config = velarx_config::Config::load_or_default(&config_path).unwrap();
    // (stopped before the directory goes: else it makes the store again)
    let _thread = store_service::spawn_thread(&config).unwrap().unwrap();
    let socket = store_service::socket_path(&config);
    let mut conn = store_service::connect(&socket).await.unwrap();
    assert!(conn.get_info().await.unwrap().is_ok());
    assert!(
        store_service::spawn_thread(&config).unwrap().is_none(),
        "a second one"
    );
    assert!(socket.exists());
}

/// The thread of a daemon that is dropped is gone with the service: nothing
/// answers on the socket.
#[tokio::test]
async fn test_a_dropped_service_thread_serves_no_more() {
    let base = tempfile::tempdir().unwrap();
    let config_path = write_config(base.path());
    let config = velarx_config::Config::load_or_default(&config_path).unwrap();
    let thread = store_service::spawn_thread(&config).unwrap().unwrap();
    let socket = store_service::socket_path(&config);
    let mut conn = store_service::connect(&socket).await.unwrap();
    assert!(conn.get_info().await.unwrap().is_ok());
    drop(conn);
    drop(thread);
    assert!(store_service::connect(&socket).await.is_err());
}

/// Clients that find nothing serving start it at the same time: each gets
/// a connection that is served, at once (no retries), from the one socket
/// bound under the lock.
#[tokio::test]
async fn test_clients_racing_to_start_it_are_all_served() {
    let base = tempfile::tempdir().unwrap();
    let config_path = write_config(base.path());
    let config = velarx_config::Config::load_or_default(&config_path).unwrap();
    let keep = tempfile::tempdir_in(Path::new(crate::common::worker()).parent().unwrap()).unwrap();
    let exe = velarx_binary(keep.path());
    let idle = Duration::from_secs(1);
    let clients = (0..4).map(|_| {
        let (config, config_path, exe) = (config.clone(), config_path.clone(), exe.clone());
        tokio::spawn(async move {
            let mut conn = connect_or_start(&config, &config_path, &exe, idle)
                .await
                .unwrap();
            conn.get_info().await.unwrap().unwrap().proto
        })
    });
    for proto in futures::future::join_all(clients).await {
        assert_eq!(proto.unwrap(), store_service::PROTO);
    }
    let socket = store_service::socket_path(&config);
    assert!(socket_goes(&socket).await, "it did not leave");
}

/// The pieces and the manifest of a checkpoint this node shares are given
/// as read-only descriptors and announced (the manifest as a layer, the
/// pieces as content), and what is shared or unshared later reaches the
/// subscribers: the service watches the shares, no daemon tells it.
#[tokio::test]
async fn test_the_pieces_of_a_shared_checkpoint_are_given_and_announced() {
    use futures::StreamExt;
    use velarx_core::services::checkpoint::SharedCheckpoints;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let e = env().await;
            let shared = std::sync::Arc::new(SharedCheckpoints::new(dir.path()).unwrap());
            let archive = |name: &str, data: &[u8]| {
                let path = dir.path().join(name);
                std::fs::write(&path, data).unwrap();
                path
            };
            let (first, first_digests) = shared.share(&archive("a.tar", b"first archive")).unwrap();
            let service =
                StoreService::with_checkpoints(e.db.clone(), e.store.clone(), shared.clone())
                    .await
                    .unwrap();
            let socket = serve(dir.path(), service).await;
            let mut conn = store_service::connect(&socket).await.unwrap();

            // a piece: its bytes, read-only; what is not shared: nothing
            let piece = &first_digests[0];
            let (reply, fds) = conn
                .lookup(vec![want(piece), want(&sha(b"not shared"))])
                .await
                .unwrap();
            let items = reply.unwrap().items;
            let at = items[0].fd.expect("a piece of a shared checkpoint") as usize;
            assert!(read_only(&fds[at]));
            let bytes = bytes_of(&fds[at], items[0].offset, items[0].length);
            assert_eq!(sha(&bytes).to_string(), *piece);
            assert!(items[1].fd.is_none());

            let mut conn2 = store_service::connect(&socket).await.unwrap();
            let stream = conn2.subscribe().await.unwrap();
            futures::pin_mut!(stream);
            let snapshot = stream.next().await.unwrap().unwrap().unwrap();
            assert_eq!(snapshot.kind, ChangeKind::Snapshot);
            assert!(snapshot.layers.contains(&first.manifest.to_string()));
            for d in &first_digests {
                assert!(snapshot.content.contains(d));
            }

            // another share, by another handle of the same directory
            let other = SharedCheckpoints::new(dir.path()).unwrap();
            let (second, second_digests) =
                other.share(&archive("b.tar", b"second archive")).unwrap();
            let added = tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await
                .expect("a change, once shared")
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(added.kind, ChangeKind::Added);
            assert!(added.layers.contains(&second.manifest.to_string()));
            assert!(second_digests.iter().all(|d| added.content.contains(d)));

            assert!(other
                .unshare_manifest(&second.manifest.to_string())
                .unwrap());
            let removed = tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await
                .expect("a change, once unshared")
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(removed.kind, ChangeKind::Removed);
            assert!(removed.layers.contains(&second.manifest.to_string()));
            let (reply, fds) = conn.lookup(vec![want(&second_digests[0])]).await.unwrap();
            assert!(reply.unwrap().items[0].fd.is_none() && fds.is_empty());
        })
        .await;
}

/// The startup profile of an image is a read-only file of the store, when
/// it is at most what the asker takes.
#[tokio::test]
async fn test_the_profile_of_an_image_is_given() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let layer = build_chunked(&sample());
            let e = env().await;
            e.publish(&[&layer], &[ZSTD]);
            e.pull().await.unwrap();
            let id = e.db.list_images().await.unwrap()[0].id.clone();
            let profile = velarx_fuse::composefs::profile_path(e.store.root(), &id);
            let text = format!(r#"{{"v":1,"files":["{}"]}}"#, vid(b"hello\n"));
            std::fs::create_dir_all(profile.parent().unwrap()).unwrap();
            std::fs::write(&profile, &text).unwrap();

            let service = StoreService::new(e.db.clone(), e.store.clone())
                .await
                .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let socket = serve(dir.path(), service).await;
            let mut conn = store_service::connect(&socket).await.unwrap();
            let image = format!("sha256:{id}");
            let (reply, fds) = conn.profile(&image, 1 << 20).await.unwrap();
            let reply = reply.unwrap();
            assert_read_only_file(&fds[reply.file as usize]);
            assert_eq!(whole(&fds[reply.file as usize]), text.as_bytes());
            // bigger than the asker takes: nothing to give
            let (small, _) = conn.profile(&image, 4).await.unwrap();
            assert!(not_found(small));
            let (reply, _) = conn
                .profile(&sha(b"no image").to_string(), 1 << 20)
                .await
                .unwrap();
            assert!(not_found(reply));
        })
        .await;
}

/// Set for the subscriber process of the test below.
const SUBSCRIBE_TO: &str = "VELARX_TEST_SUBSCRIBE_TO";

/// Not a test by itself: the client the next test runs in a process of its
/// own, which subscribes and then waits to be killed.
#[test]
fn subscriber_process() {
    use futures::StreamExt;
    let Some(socket) = std::env::var_os(SUBSCRIBE_TO) else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut conn = store_service::connect(Path::new(&socket)).await.unwrap();
        let stream = conn.subscribe().await.unwrap();
        futures::pin_mut!(stream);
        stream.next().await.unwrap().unwrap().unwrap();
        println!("subscribed");
        std::future::pending::<()>().await;
    });
}

/// A subscriber that dies (SIGKILL) is dropped by the service, which does
/// not read a connection that has a reply stream: the service is not kept
/// busy by it and leaves when idle.
#[tokio::test]
async fn test_a_dead_subscriber_does_not_keep_the_service_busy() {
    use std::io::BufRead;
    let base = tempfile::tempdir().unwrap();
    let config_path = write_config(base.path());
    let config = velarx_config::Config::load_or_default(&config_path).unwrap();
    let socket = store_service::socket_path(&config);
    let keep = tempfile::tempdir_in(Path::new(crate::common::worker()).parent().unwrap()).unwrap();
    let exe = velarx_binary(keep.path());
    let idle = Duration::from_secs(1);
    let conn = connect_or_start(&config, &config_path, &exe, idle)
        .await
        .unwrap();
    drop(conn);

    let mut client = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "store_service_tests::subscriber_process",
            "--nocapture",
        ])
        .env(SUBSCRIBE_TO, &socket)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let out = client.stdout.take().unwrap();
    let ready = tokio::task::spawn_blocking(move || {
        std::io::BufReader::new(out)
            .lines()
            .map_while(Result::ok)
            .any(|l| l == "subscribed")
    })
    .await
    .unwrap();
    assert!(ready, "the client subscribed");
    // alive: the service stays, beyond its idle time (a window)
    tokio::time::sleep(idle * 2).await;
    assert!(socket.exists(), "a subscriber keeps the service");

    client.kill().unwrap();
    client.wait().unwrap();
    assert!(
        socket_goes(&socket).await,
        "the service did not leave after its subscriber died"
    );
}

/// When what the service watches goes away it cannot follow the store any
/// more: it exits with an error (and is started again), it does not go on
/// announcing nothing.
#[tokio::test]
async fn test_the_service_exits_when_it_loses_its_watch() {
    let base = tempfile::tempdir().unwrap();
    let config_path = write_config(base.path());
    let config = velarx_config::Config::load_or_default(&config_path).unwrap();
    let socket = store_service::socket_path(&config);
    let keep = tempfile::tempdir_in(Path::new(crate::common::worker()).parent().unwrap()).unwrap();
    let exe = velarx_binary(keep.path());
    let listener = velarx_base::ipc::bind_private(&socket).unwrap();
    let mut cmd = store_service::start_command(&exe, &config_path, None);
    velarx_base::spawn::pass_as_fd3(&mut cmd, listener.as_raw_fd());
    let mut child = cmd.spawn().unwrap();
    drop(listener);
    let mut conn = store_service::connect(&socket).await.unwrap();
    assert!(conn.get_info().await.unwrap().is_ok());

    let shares = base.path().join("storage/shared/shares");
    assert!(shares.is_dir());
    std::fs::remove_dir_all(&shares).unwrap();
    let status = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::task::spawn_blocking(move || child.wait()),
    )
    .await
    .expect("the service exited")
    .unwrap()
    .unwrap();
    assert!(!status.success(), "it exited with an error: {status}");
}

/// Whether the socket of a service that leaves goes within 20 s (inotify,
/// in a thread of its own: the runtime of the test goes on meanwhile).
async fn socket_goes(socket: &Path) -> bool {
    let socket = socket.to_path_buf();
    tokio::task::spawn_blocking(move || {
        velarx_base::testing::wait_gone(&socket, Duration::from_secs(20))
    })
    .await
    .unwrap()
}
