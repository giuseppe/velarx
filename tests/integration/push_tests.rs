// SPDX-License-Identifier: Apache-2.0
//! Pushes against in-process registries: exact blobs and manifests, mounts,
//! chunked uploads, regenerated layers, and what the registry gets pulled
//! back.

use crate::common::*;
use velarx_config::{PullConfig, PushConfig};
use velarx_content::layer::writer::Compression;
use velarx_core::services::PushOptions;
use velarx_types::OciManifest;

const ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
const GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

fn random_file(name: &'static str, len: usize) -> Item {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(len as u64);
    let mut data = vec![0u8; len];
    rng.fill(&mut data[..]);
    Item::File {
        name,
        data,
        chunk: 64 * 1024,
    }
}

fn items() -> Vec<Item> {
    vec![
        Item::Dir("etc/"),
        Item::File {
            name: "etc/hello",
            data: b"hello\n".to_vec(),
            chunk: 4096,
        },
        Item::File {
            name: "etc/empty",
            data: vec![],
            chunk: 1,
        },
        random_file("usr/random", 3 * 1024 * 1024),
        Item::Symlink("etc/link", "hello"),
    ]
}

fn manifest_of(reg: &Registry, reference: impl std::fmt::Display) -> Vec<u8> {
    reg.blobs
        .lock()
        .unwrap()
        .get(&format!("manifest:{reference}"))
        .cloned()
        .unwrap_or_else(|| panic!("no manifest {reference}"))
}

async fn pull(e: &Env) -> velarx_core::services::PullResult {
    e.pull().await.unwrap()
}

fn one_mib() -> PushConfig {
    PushConfig {
        chunk_mib: 1,
        ..PushConfig::default()
    }
}

/// Our own layers are regenerated bit for bit: pushed to an empty registry
/// they have the digests they had, and so does the manifest.
#[tokio::test]
async fn test_push_to_an_empty_registry_reproduces_the_manifest() {
    let a = env_full(PullConfig::default(), one_mib()).await;
    let (host_b, b) = start_registry().await;
    a.trust(&[&host_b]);
    let tar = tar_of(&items());
    let chunked = build_written(&tar, Compression::ZstdChunked);
    let gzip = build_written(&tar_of(&items()[..3]), Compression::Gzip);
    a.publish(&[&gzip, &chunked], &[GZIP, ZSTD]);
    pull(&a).await;
    let original = manifest_of(&a.reg, "latest");

    let client = client_for(&[&a.host, &host_b]);
    let result = a
        .service
        .push_with_client(
            &client,
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{host_b}/copy:v1")),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(result.layers_regenerated, 2);
    assert_eq!(result.blobs_uploaded, 3);
    assert_eq!((result.blobs_mounted, result.blobs_existing), (0, 0));

    // The manifest is the one that was pulled, byte for byte, and so are the
    // blobs.
    assert_eq!(result.digest, sha(&original));
    assert_eq!(manifest_of(&b, "v1"), original);
    assert_eq!(manifest_of(&b, result.digest), original);
    for blob in [&gzip.blob, &chunked.blob] {
        assert_eq!(
            b.blobs.lock().unwrap().get(&sha(blob).to_string()),
            Some(blob)
        );
        assert!(b.has("copy", &sha(blob)));
    }
    assert!(b.logged("PATCH") >= 2, "{:?}", b.log.lock().unwrap());

    let other = side_with(Some(&conf_for(&[&a.host, &host_b]))).await;
    let reference = format!("{host_b}/copy@{}", result.digest);
    other.pull(&client, &reference).await.unwrap();
    let image = other.db.get_image_by_digest(&result.digest).await.unwrap();
    assert_eq!(image.manifest_digest, result.digest);
    let manifest: OciManifest = serde_json::from_str(&image.manifest).unwrap();
    assert_eq!(manifest.layers.len(), 2);
    assert!(other.store.contains(&vid(&items_random())));
}

fn items_random() -> Vec<u8> {
    match random_file("x", 3 * 1024 * 1024) {
        Item::File { data, .. } => data,
        _ => unreachable!(),
    }
}

/// Pushed to another repository of the registry the image came from, the
/// blobs are mounted and nothing is uploaded, whatever made the layers.
#[tokio::test]
async fn test_push_to_another_repository_mounts_the_blobs() {
    let a = env().await;
    let chunked = build_chunked(&items());
    let gzip = build_gzip(&items());
    a.publish(&[&gzip, &chunked], &[GZIP, ZSTD]);
    pull(&a).await;
    let original = manifest_of(&a.reg, "latest");

    let result = a
        .service
        .push_with_client(
            &a.client(),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{}/copy:latest", a.host)),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(result.blobs_mounted, 3);
    assert_eq!(result.blobs_uploaded, 0);
    assert_eq!(result.layers_regenerated, 0);
    assert_eq!(result.digest, sha(&original));
    assert_eq!(manifest_of(&a.reg, "latest"), original);
    assert_eq!(a.reg.logged("PATCH"), 0);
    assert!(a
        .reg
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|l| l == "POST copy mount=true from=test"));
    assert!(a.reg.has("copy", &sha(&gzip.blob)));

    let again = a
        .service
        .push_with_client(
            &a.client(),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{}/copy:again", a.host)),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!((again.blobs_existing, again.blobs_mounted), (3, 0));
    assert_eq!(a.reg.logged("POST copy"), 3);
}

/// Layers from other tools cannot be rebuilt bit for bit: they are
/// regenerated from the tar-split, the diff ids and the configuration stay
/// and the registry hands back an image that pulls.
#[tokio::test]
async fn test_foreign_layers_are_regenerated_for_another_registry() {
    let a = env().await;
    let (host_b, b) = start_registry().await;
    a.trust(&[&host_b]);
    let chunked = build_chunked(&items());
    let gzip = build_gzip(&items());
    a.publish(&[&gzip, &chunked], &[GZIP, ZSTD]);
    pull(&a).await;
    let original: OciManifest = serde_json::from_slice(&manifest_of(&a.reg, "latest")).unwrap();

    let client = client_for(&[&a.host, &host_b]);
    let result = a
        .service
        .push_with_client(
            &client,
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{host_b}/copy:latest")),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(result.layers_regenerated, 2);
    let pushed: OciManifest = serde_json::from_slice(&manifest_of(&b, "latest")).unwrap();
    assert_eq!(pushed.config.digest, original.config.digest);
    assert_ne!(pushed.layers[0].digest, original.layers[0].digest);
    assert_eq!(pushed.layers[0].media_type, GZIP);
    assert_eq!(pushed.layers[1].media_type, ZSTD);
    assert!(pushed.layers[1]
        .annotations
        .keys()
        .any(|k| k.ends_with("manifest-position")));

    let other = side_with(Some(&conf_for(&[&a.host, &host_b]))).await;
    other
        .pull(&client, &format!("{host_b}/copy@{}", result.digest))
        .await
        .unwrap();
    for (l, original) in pushed.layers.iter().zip(&original.layers) {
        let (a, b) = (
            other
                .db
                .get_layer(&stored_key(&other.db, &l.digest).await)
                .await
                .unwrap(),
            a.db.get_layer(&stored_key(&a.db, &original.digest).await)
                .await
                .unwrap(),
        );
        assert_eq!(a.diff_id, b.diff_id);
    }
}

#[tokio::test]
async fn test_compression_format_is_applied() {
    let a = env().await;
    let (host_b, b) = start_registry().await;
    a.trust(&[&host_b]);
    let tar = tar_of(&items()[..4]);
    let gzip = build_written(&tar, Compression::Gzip);
    a.publish(&[&gzip], &[GZIP]);
    pull(&a).await;
    let client = client_for(&[&a.host, &host_b]);
    for (format, media) in [
        (Compression::ZstdChunked, ZSTD),
        (Compression::None, "application/vnd.oci.image.layer.v1.tar"),
        (Compression::Gzip, GZIP),
    ] {
        let result = a
            .service
            .push_with_client(
                &client,
                &format!("{}/test:latest", a.host),
                &PushOptions {
                    destination: Some(format!("{host_b}/fmt:latest")),
                    compression: Some(format),
                    ..PushOptions::default()
                },
            )
            .await
            .unwrap();
        let m: OciManifest = serde_json::from_slice(&manifest_of(&b, result.digest)).unwrap();
        assert_eq!(m.layers[0].media_type, media);
        // Uncompressed, the blob is the tar: its digest is the diff id.
        if format == Compression::None {
            assert_eq!(m.layers[0].digest, gzip.diff_id);
        }
    }
    // a layer that has the compression asked is the blob the registry has,
    // though the layer writer would make another blob of it
    let c = env().await;
    let other = build_gzip(&items()[..4]);
    c.publish(&[&other], &[GZIP]);
    pull(&c).await;
    let client = c.client();
    let result = c
        .service
        .push_with_client(
            &client,
            &format!("{}/test:latest", c.host),
            &PushOptions {
                destination: Some(format!("{}/kept:latest", c.host)),
                compression: Some(Compression::Gzip),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    let m: OciManifest = serde_json::from_slice(&manifest_of(&c.reg, result.digest)).unwrap();
    assert_eq!(m.layers[0].digest, sha(&other.blob));
}

/// A manifest velarx writes states the fs-verity digest of the EROFS image of
/// each layer; the registry gives it back and the pull checks it, eager or
/// lazy: a manifest edited in the registry has a digest that is none of
/// ours and is pulled, the layer held to its record.
#[tokio::test]
async fn test_a_pushed_manifest_states_the_erofs_digest_of_each_layer() {
    const KEY: &str = "io.containers.composefs.digest";
    let a = env().await;
    let (host_b, b) = start_registry().await;
    a.trust(&[&host_b]);
    let tar = tar_of(&items()[..4]);
    let gzip = build_written(&tar, Compression::Gzip);
    a.publish(&[&gzip], &[GZIP]);
    pull(&a).await;
    let ours = a.db.get_layer(&gzip.key()).await.unwrap().erofs.unwrap();
    let client = client_for(&[&a.host, &host_b]);
    let result = a
        .service
        .push_with_client(
            &client,
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{host_b}/rebuilt:v1")),
                compression: Some(Compression::ZstdChunked),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    let body = manifest_of(&b, result.digest);
    let m: OciManifest = serde_json::from_slice(&body).unwrap();
    // (the layer was regenerated: the blob is not the one pulled, the image
    // of the layer is)
    assert_ne!(m.layers[0].digest, sha(&gzip.blob));
    assert_eq!(m.layers[0].annotations[KEY], ours);

    for lazy in [false, true] {
        // (its registry client knows both registries, as the engine's
        // configuration would: the registry fetcher reaches them with it)
        let other = side_with(Some(&conf_for(&[&a.host, &host_b]))).await;
        let reference = format!("{host_b}/rebuilt@{}", result.digest);
        if lazy {
            other.pull_lazy(&client, &reference).await.unwrap();
        } else {
            other.pull(&client, &reference).await.unwrap();
        }
        // edited in the registry: the same layer, another digest
        let mut edited: serde_json::Value = serde_json::from_slice(&body).unwrap();
        edited["layers"][0]["annotations"][KEY] =
            serde_json::json!(format!("sha256:{}", "ab".repeat(32)));
        let edited = serde_json::to_vec(&edited).unwrap();
        b.blobs
            .lock()
            .unwrap()
            .insert(format!("manifest:{}", sha(&edited)), edited.clone());
        let other = side_with(Some(&conf_for(&[&a.host, &host_b]))).await;
        let reference = format!("{host_b}/rebuilt@{}", sha(&edited));
        if lazy {
            other.pull_lazy(&client, &reference).await
        } else {
            other.pull(&client, &reference).await
        }
        .unwrap();
        // (an image in the store, or a pull in progress)
        assert_eq!(
            other.db.list_images().await.unwrap().len()
                + other.service.staging_area().pulls().len(),
            1
        );
    }
}

#[tokio::test]
async fn test_push_fails_without_pushing_a_manifest_when_the_store_lost_a_file() {
    let a = env().await;
    let (host_b, b) = start_registry().await;
    a.trust(&[&host_b]);
    a.publish(
        &[&build_written(&tar_of(&items()[..4]), Compression::Gzip)],
        &[GZIP],
    );
    pull(&a).await;
    let client = client_for(&[&a.host, &host_b]);
    a.store.remove(&vid(b"hello\n")).unwrap();
    let err = a
        .service
        .push_with_client(
            &client,
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{host_b}/lost:latest")),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("etc/hello"), "{err}");
    assert_eq!(b.logged("PUT-MANIFEST"), 0);
    assert!(!b.has("lost", &sha(b"anything")));
}

#[tokio::test]
async fn test_layer_without_tarsplit_cannot_be_pushed() {
    let a = env().await;
    let (host_b, _) = start_registry().await;
    a.trust(&[&host_b]);
    let layer = build_written(&tar_of(&items()[..4]), Compression::Gzip);
    a.publish(&[&layer], &[GZIP]);
    pull(&a).await;
    a.db.conn()
        .call(|c| {
            c.execute("UPDATE layers SET tarsplit_digest = NULL", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let err = a
        .service
        .push_with_client(
            &client_for(&[&a.host, &host_b]),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{host_b}/x:latest")),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("pull the image again"), "{err}");
    pull(&a).await;
    assert!(a
        .db
        .get_layer_tarsplit(&layer.key())
        .await
        .unwrap()
        .is_some());
}

/// A layer of a table of contents was pulled with no diff id, held to its
/// table only: a push that has to upload it recreates its stream and refuses
/// it when the stream is not the diff id of the configuration.
#[tokio::test]
async fn test_a_layer_of_a_table_whose_stream_is_not_its_diff_id_is_not_pushed() {
    let a = env().await;
    let (host_b, b) = start_registry().await;
    a.trust(&[&host_b]);
    let mut layer = build_chunked(&items());
    layer.diff_id = sha(b"another layer");
    a.publish(&[&layer], &[ZSTD]);
    pull(&a).await;
    let err = a
        .service
        .push_with_client(
            &client_for(&[&a.host, &host_b]),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{host_b}/x:latest")),
                compression: Some(Compression::Gzip),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("the regenerated layer has the diff id"),
        "{err}"
    );
    assert!(!b.has("x", &sha(b"anything")));
}

/// A registry that fails the final request of an upload leaves no blob.
#[tokio::test]
async fn test_registry_rejecting_an_upload_fails_the_push() {
    let a = env().await;
    a.publish(
        &[&build_written(&tar_of(&items()[..4]), Compression::Gzip)],
        &[GZIP],
    );
    pull(&a).await;
    let client = client_for(&[&a.host, "127.0.0.1:1"]);
    let err = a
        .service
        .push_with_client(
            &client,
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some("127.0.0.1:1/x:latest".into()),
                ..PushOptions::default()
            },
        )
        .await;
    assert!(err.is_err());
}

/// The repositories a blob was pulled from or pushed to are kept, not only
/// the first one: a layer pulled again under another name, or pushed
/// somewhere, is mounted from there, and the manifest keeps its digest.
#[tokio::test]
async fn test_blobs_are_mounted_from_every_repository_that_has_them() {
    let a = env().await;
    let gzip = build_gzip(&items());
    a.publish(&[&gzip], &[GZIP]);
    pull(&a).await;
    let original = manifest_of(&a.reg, "latest");
    let blob = sha(&gzip.blob);

    a.reg.repos.lock().unwrap().insert(
        "mirror".into(),
        a.reg.blobs.lock().unwrap().keys().cloned().collect(),
    );
    a.reg
        .blobs
        .lock()
        .unwrap()
        .insert("manifest:other".into(), original.clone());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    a.service
        .pull_with_client(&a.client(), &format!("{}/mirror:other", a.host), tx)
        .await
        .unwrap();
    let sources = a.db.blob_sources(&blob, &a.host).await.unwrap();
    assert!(sources.contains(&"test".to_string()) && sources.contains(&"mirror".to_string()));

    let push = |to: &'static str| {
        let a = &a;
        async move {
            a.service
                .push_with_client(
                    &a.client(),
                    &format!("{}/test:latest", a.host),
                    &PushOptions {
                        destination: Some(format!("{}/{to}:latest", a.host)),
                        ..PushOptions::default()
                    },
                )
                .await
                .unwrap()
        }
    };
    let first = push("copy").await;
    assert_eq!((first.blobs_mounted, first.blobs_uploaded), (2, 0));
    assert_eq!(first.digest, sha(&original));

    // Pushed to a third place, it comes from the place it was pushed to last.
    let second = push("third").await;
    assert_eq!((second.blobs_mounted, second.blobs_uploaded), (2, 0));
    assert_eq!(second.layers_regenerated, 0);
    assert!(a
        .reg
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|l| l == "POST third mount=true from=copy"));
}

/// A push tells what it does with each blob, then the manifest, with the
/// events of a pull.
#[tokio::test]
async fn test_push_tells_its_progress() {
    let a = env_full(PullConfig::default(), one_mib()).await;
    let (host_b, _b) = start_registry().await;
    a.trust(&[&host_b]);
    let gzip = build_written(&tar_of(&items()), Compression::Gzip);
    a.publish(&[&gzip], &[GZIP]);
    pull(&a).await;

    let client = client_for(&[&a.host, &host_b]);
    let (tx, mut rx) = tokio::sync::mpsc::channel(1000);
    a.service
        .push_with_client(
            &client,
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{host_b}/copy:v1")),
                progress: Some(tx),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    let mut events = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push((
            e.subject.to_string(),
            e.status,
            e.current_bytes,
            e.total_bytes,
        ));
    }
    let layer = sha(&gzip.blob).to_string();
    let of = |layer: &str, status: &str| {
        events
            .iter()
            .filter(|e| e.0 == layer && e.1 == status)
            .collect::<Vec<_>>()
    };
    assert!(!of(&layer, "compressing").is_empty(), "{events:?}");
    let uploading = of(&layer, "uploading");
    assert!(
        uploading.iter().all(|e| e.3 == gzip.blob.len() as u64),
        "{events:?}"
    );
    let complete = of(&layer, "complete");
    assert_eq!(complete.len(), 1, "{events:?}");
    assert_eq!(complete[0].2, complete[0].3);
    assert!(
        events
            .iter()
            .any(|e| e.0.is_empty() && e.1.contains("manifest")),
        "{events:?}"
    );
    let first_complete = events.iter().position(|e| e.1 == "complete").unwrap();
    let manifest = events.iter().position(|e| e.0.is_empty()).unwrap();
    assert!(first_complete < manifest, "{events:?}");
}

/// A pusher of `[[sinks.external]]` in a thread of the test: it answers by
/// what it was told to, and records what it was asked.
mod sink {
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};
    use velarx_content::pusher::push::{EventKind, Have, Object, Probed, PusherError, PutEvent};
    use velarx_content::serve_fetch::{Described, Out, StagingFetcher};
    use velarx_content::serve_push::{CommittedCall, PushScope, Pushing, PutCall};
    use velarx_proto::transfer::{Failure, FailureClass};

    /// What the sink says of every object it is asked about.
    #[derive(Clone, Copy)]
    pub enum Says {
        /// The destination has it (a lie, when it has not)
        Present,
        /// It places nothing
        Unavailable,
        /// It fails
        Fails,
        /// It never answers
        Hangs,
        /// It places nothing, and never answers a commit
        HangsAtCommit,
        /// It places nothing, answers a commit, and never the end
        HangsAtFinish,
    }

    pub struct Sink {
        pub says: Says,
        /// `probe` and `put`, with the digests, in order
        pub asked: Mutex<Vec<String>>,
        /// The credentials of its scope
        pub access: Mutex<Option<Vec<u8>>>,
        /// What it was told the destination is
        pub destination: Mutex<Option<String>>,
        /// The digests of the manifests it was told are committed, and
        /// whether it was told the end
        pub committed: Mutex<Vec<String>>,
        /// The names of the commits it was told of
        pub names: Mutex<Vec<Vec<String>>>,
        pub finished: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl Pushing for Sink {
        fn described(&self) -> Described {
            Described {
                name: "mirror".into(),
                capabilities: Vec::new(),
                max_objects: 4,
            }
        }

        async fn probe(
            &self,
            scope: &PushScope,
            objects: Vec<Object>,
            out: &Out<Probed>,
        ) -> Result<(), PusherError> {
            *self.access.lock().unwrap() = scope.access.as_ref().map(|a| a.to_vec());
            *self.destination.lock().unwrap() = Some(scope.destination.clone());
            if matches!(self.says, Says::Hangs) {
                // (until the engine gives up and closes the connection)
                std::future::pending::<()>().await;
            }
            for (index, o) in objects.iter().enumerate() {
                self.asked
                    .lock()
                    .unwrap()
                    .push(format!("probe {}", o.digest));
                let have = match self.says {
                    Says::Present => Have::Present,
                    _ => Have::Unavailable,
                };
                let _ = out
                    .send(Probed {
                        index: index as u32,
                        have,
                        failure: None,
                    })
                    .await;
            }
            Ok(())
        }

        async fn put(
            &self,
            _scope: &PushScope,
            call: PutCall,
            out: &Out<PutEvent>,
        ) -> Result<(), PusherError> {
            for (index, o) in call.objects.iter().enumerate() {
                self.asked.lock().unwrap().push(format!("put {}", o.digest));
                let event = match self.says {
                    Says::Fails => PutEvent {
                        failure: Some(Failure {
                            class: FailureClass::Failed,
                            reason: "no room".into(),
                        }),
                        ..PutEvent::of(EventKind::Failed)
                    },
                    _ => PutEvent::of(EventKind::Unavailable),
                };
                let _ = out
                    .send(PutEvent {
                        objects: vec![index as u32],
                        ..event
                    })
                    .await;
            }
            Ok(())
        }

        async fn committed(
            &self,
            _scope: &PushScope,
            call: CommittedCall,
        ) -> Result<(), PusherError> {
            if matches!(self.says, Says::HangsAtCommit) {
                std::future::pending::<()>().await;
            }
            self.committed
                .lock()
                .unwrap()
                .push(call.manifest.digest.clone());
            self.names.lock().unwrap().push(call.names);
            Ok(())
        }

        async fn finish(&self, _scope: &PushScope) -> Result<(), PusherError> {
            if matches!(self.says, Says::HangsAtFinish) {
                std::future::pending::<()>().await;
            }
            self.finished
                .store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    struct Api(Arc<Sink>);

    #[async_trait]
    impl StagingFetcher for Api {
        fn described(&self) -> Described {
            Described {
                name: "mirror".into(),
                capabilities: Vec::new(),
                max_objects: 1,
            }
        }

        fn pusher(&self) -> Option<Arc<dyn Pushing>> {
            Some(self.0.clone())
        }
    }

    /// The sink, served on a socket in `dir`; the guard stops it.
    pub fn serve(
        dir: &std::path::Path,
        says: Says,
    ) -> (
        Arc<Sink>,
        std::path::PathBuf,
        velarx_content::serve_fetch::ServerThread,
    ) {
        let sink = Arc::new(Sink {
            says,
            asked: Mutex::default(),
            access: Mutex::default(),
            destination: Mutex::default(),
            committed: Mutex::default(),
            names: Mutex::default(),
            finished: Default::default(),
        });
        let socket = dir.join("mirror.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let thread = velarx_content::serve_fetch::serve_in_thread(
            listener,
            Arc::new(Api(sink.clone())),
            velarx_content::activation::Limits::default(),
        )
        .unwrap();
        (sink, socket, thread)
    }
}

/// An environment with a pusher `mirror` that says `says`, and a second
/// registry to push to.
async fn with_sink(
    says: sink::Says,
    push: PushConfig,
) -> (
    Env,
    String,
    std::sync::Arc<Registry>,
    std::sync::Arc<sink::Sink>,
    (tempfile::TempDir, velarx_content::serve_fetch::ServerThread),
) {
    let dir = tempfile::tempdir().unwrap();
    let (mirror, socket, thread) = sink::serve(dir.path(), says);
    let a = env_built(
        velarx_db::Database::open_in_memory().await.unwrap(),
        PullConfig::default(),
        push,
        Fetchers::default(),
        None,
        |service| {
            service.with_sinks(vec![
                velarx_config::ExternalSinkConfig {
                    name: "mirror".into(),
                    socket: Some(socket),
                    command: Vec::new(),
                    idle_timeout_secs: 1,
                    credentials: false,
                },
                // (nobody serves it)
                velarx_config::ExternalSinkConfig {
                    name: "gone".into(),
                    socket: Some("/nonexistent/gone.sock".into()),
                    command: Vec::new(),
                    idle_timeout_secs: 15,
                    credentials: false,
                },
            ])
        },
    )
    .await;
    let (host_b, b) = start_registry().await;
    a.trust(&[&host_b]);
    (a, host_b, b, mirror, (dir, thread))
}

async fn published(a: &Env) -> Vec<u8> {
    let tar = tar_of(&items());
    let chunked = build_written(&tar, Compression::ZstdChunked);
    let gzip = build_written(&tar_of(&items()[..3]), Compression::Gzip);
    a.publish(&[&gzip, &chunked], &[GZIP, ZSTD]);
    pull(a).await;
    manifest_of(&a.reg, "latest")
}

/// A pusher whose claim the destination's own pusher cannot confirm ends the
/// push with an error that names it and the object: nobody else is asked
/// to mend it, and no manifest is put.
#[tokio::test]
async fn test_a_pusher_that_says_the_destination_has_what_it_has_not_fails_the_push() {
    let (a, host_b, b, mirror, _keep) = with_sink(sink::Says::Present, one_mib()).await;
    published(&a).await;
    let client = client_for(&[&a.host, &host_b]);
    let e = a
        .service
        .push_with_client(
            &client,
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{host_b}/copy:v1")),
                sinks: Some(vec!["mirror".into()]),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&e, velarx_types::ImageError::Transfer { party, failure, .. } if party == "mirror" && failure.class == velarx_proto::transfer::FailureClass::Invalid),
        "{e}"
    );
    assert!(b.blobs.lock().unwrap().is_empty());
    let asked = mirror.asked.lock().unwrap().clone();
    assert!(asked.iter().any(|a| a.starts_with("probe ")), "{asked:?}");
    // (the credentials of the destination are not for a sink that was not
    // allowed them)
    assert_eq!(*mirror.access.lock().unwrap(), None);
}

#[tokio::test]
async fn test_pushers_that_place_nothing_or_fail_are_skipped_and_the_registry_places() {
    for says in [sink::Says::Unavailable, sink::Says::Fails] {
        // (named by [push] sinks, not by the push)
        let push = PushConfig {
            sinks: Some(vec!["mirror".into()]),
            ..one_mib()
        };
        let (a, host_b, b, mirror, _keep) = with_sink(says, push).await;
        let original = published(&a).await;
        let client = client_for(&[&a.host, &host_b]);
        let result = a
            .service
            .push_with_client(
                &client,
                &format!("{}/test:latest", a.host),
                &PushOptions {
                    destination: Some(format!("{host_b}/copy:v1")),
                    ..PushOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(result.blobs_uploaded, 3);
        assert_eq!(manifest_of(&b, "v1"), original);
        let asked = mirror.asked.lock().unwrap().clone();
        assert!(asked.iter().any(|a| a.starts_with("put ")), "{asked:?}");
        if matches!(says, sink::Says::Fails) {
            let puts = asked.iter().filter(|a| a.starts_with("put ")).count();
            assert!(puts < 3, "{asked:?}");
        }
    }
}

#[tokio::test]
async fn test_a_sink_that_is_not_defined_is_refused() {
    let a = env_full(PullConfig::default(), one_mib()).await;
    let (host_b, _b) = start_registry().await;
    a.trust(&[&host_b]);
    published(&a).await;
    let client = client_for(&[&a.host, &host_b]);
    for sinks in [vec!["nobody"], vec!["nobody", "nobody"]] {
        let e = a
            .service
            .push_with_client(
                &client,
                &format!("{}/test:latest", a.host),
                &PushOptions {
                    destination: Some(format!("{host_b}/copy:v1")),
                    sinks: Some(sinks.iter().map(|s| s.to_string()).collect()),
                    ..PushOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(e.to_string().contains("not a sink"), "{e}");
    }
}

/// An image pushed to a path (a layout, a `dir:`, an archive) has the
/// manifest it was pulled with, and its blobs.
#[tokio::test]
async fn test_push_to_a_path_writes_the_layout_the_directory_and_the_archive() {
    use velarx_content::dir_push::Mode;
    use velarx_core::services::PathPush;
    let a = env().await;
    let original = published(&a).await;
    let digest = sha(&original);
    let tmp = tempfile::tempdir().unwrap();
    let path_push = |mode: Mode, dest: std::fs::File, tag: Option<&str>| PushOptions {
        path: Some(PathPush {
            mode,
            dest: std::sync::Arc::new(dest.into()),
            names: tag.map(str::to_string).into_iter().collect(),
            label: "test".into(),
        }),
        ..PushOptions::default()
    };
    let from = format!("{}/test:latest", a.host);
    let layout = tmp.path().join("layout");
    std::fs::create_dir(&layout).unwrap();
    for tag in ["one", "two"] {
        let dest = std::fs::File::open(&layout).unwrap();
        let result = a
            .service
            .push_with_client(
                &a.client(),
                &from,
                &path_push(Mode::Layout, dest, Some(tag)),
            )
            .await
            .unwrap();
        assert_eq!(result.digest, digest);
    }
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(layout.join("index.json")).unwrap()).unwrap();
    let names: Vec<&str> = index["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["annotations"]["org.opencontainers.image.ref.name"].as_str())
        .collect();
    assert_eq!(names, ["one", "two"]);
    assert_eq!(
        std::fs::read(layout.join(format!("blobs/sha256/{}", digest.hex()))).unwrap(),
        original
    );
    assert!(layout.join("oci-layout").is_file());
    // (pushed again, the blobs are there: nothing is regenerated)
    let dest = std::fs::File::open(&layout).unwrap();
    let again = a
        .service
        .push_with_client(
            &a.client(),
            &from,
            &path_push(Mode::Layout, dest, Some("one")),
        )
        .await
        .unwrap();
    assert_eq!(again.blobs_existing, 3);
    assert_eq!(again.layers_regenerated, 0);

    let dir = tmp.path().join("dir");
    std::fs::create_dir(&dir).unwrap();
    let dest = std::fs::File::open(&dir).unwrap();
    a.service
        .push_with_client(&a.client(), &from, &path_push(Mode::Dir, dest, None))
        .await
        .unwrap();
    assert_eq!(std::fs::read(dir.join("manifest.json")).unwrap(), original);
    assert!(dir.join("version").is_file());

    let archive = tmp.path().join("image.tar");
    let dest = std::fs::File::create(&archive).unwrap();
    a.service
        .push_with_client(
            &a.client(),
            &from,
            &path_push(Mode::Archive, dest, Some("one")),
        )
        .await
        .unwrap();
    let mut members = tar::Archive::new(std::fs::File::open(&archive).unwrap());
    let names: Vec<String> = members
        .entries()
        .unwrap()
        .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.first().map(String::as_str), Some("oci-layout"));
    assert_eq!(names.last().map(String::as_str), Some("index.json"));
    assert!(names.contains(&format!("blobs/sha256/{}", digest.hex())));
}

/// The helper sinks are the push's; the destination's own pusher is added by
/// its scheme, so the same list serves a registry and a path, and naming the
/// destination's own pusher in it is an error.
#[tokio::test]
async fn test_helper_sinks_serve_a_path_and_a_registry_and_the_origin_is_never_in_the_list() {
    use velarx_content::dir_push::Mode;
    use velarx_core::services::PathPush;
    let push = PushConfig {
        sinks: Some(vec!["mirror".into()]),
        ..one_mib()
    };
    let (a, host_b, _b, mirror, _keep) = with_sink(sink::Says::Unavailable, push).await;
    let original = published(&a).await;
    let digest = sha(&original);
    let from = format!("{}/test:latest", a.host);
    let tmp = tempfile::tempdir().unwrap();
    // The path has a name longer than a pusher takes of a text, and a
    // newline: the destination is the descriptor, not the text.
    let mut dir = tmp.path().to_path_buf();
    while dir.as_os_str().len() < 400 {
        dir.push("a-directory-with-a-name\nof-some-length");
    }
    std::fs::create_dir_all(&dir).unwrap();
    // `[push] sinks`, and `--sinks` empty, and `--sinks mirror`: all three
    // write the path
    for (n, sinks) in [None, Some(vec![]), Some(vec!["mirror".to_string()])]
        .into_iter()
        .enumerate()
    {
        let layout = dir.join(format!("layout{n}"));
        std::fs::create_dir(&layout).unwrap();
        let result = a
            .service
            .push_with_client(
                &a.client(),
                &from,
                &PushOptions {
                    path: Some(PathPush {
                        mode: Mode::Layout,
                        dest: std::sync::Arc::new(std::fs::File::open(&layout).unwrap().into()),
                        names: vec!["one".into()],
                        label: layout.display().to_string(),
                    }),
                    sinks,
                    ..PushOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(result.digest, digest);
        assert_eq!(
            std::fs::read(layout.join(format!("blobs/sha256/{}", digest.hex()))).unwrap(),
            original
        );
    }
    // (the helper heard the transport, not the path)
    assert_eq!(mirror.destination.lock().unwrap().as_deref(), Some("oci:"));
    // it was told of the commit and of the end
    assert!(mirror
        .committed
        .lock()
        .unwrap()
        .contains(&digest.to_string()));
    assert!(mirror.finished.load(std::sync::atomic::Ordering::Relaxed));

    let client = client_for(&[&a.host, &host_b]);
    a.service
        .push_with_client(
            &client,
            &from,
            &PushOptions {
                destination: Some(format!("{host_b}/copy:v1")),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert!(mirror
        .destination
        .lock()
        .unwrap()
        .as_deref()
        .is_some_and(|d| d.ends_with("/copy")));

    // the destination's own pusher is not a helper, to a path or a registry
    for own in ["registry", "dir"] {
        for sinks in [vec![own], vec!["mirror", own]] {
            let sinks = Some(sinks.iter().map(|s| s.to_string()).collect::<Vec<_>>());
            let layout = dir.join("refused");
            std::fs::create_dir_all(&layout).unwrap();
            let e = a
                .service
                .push_with_client(
                    &a.client(),
                    &from,
                    &PushOptions {
                        path: Some(PathPush {
                            mode: Mode::Layout,
                            dest: std::sync::Arc::new(std::fs::File::open(&layout).unwrap().into()),
                            names: Vec::new(),
                            label: "x".into(),
                        }),
                        sinks: sinks.clone(),
                        ..PushOptions::default()
                    },
                )
                .await
                .unwrap_err();
            assert!(e.to_string().contains("destination's own pusher"), "{e}");
            let e = a
                .service
                .push_with_client(
                    &client,
                    &from,
                    &PushOptions {
                        destination: Some(format!("{host_b}/copy:v2")),
                        sinks,
                        ..PushOptions::default()
                    },
                )
                .await
                .unwrap_err();
            assert!(e.to_string().contains("destination's own pusher"), "{e}");
        }
    }
}

/// A helper sink the push names that cannot be reached is an error that
/// names it; one of `[push] sinks` is left out.
#[tokio::test]
async fn test_a_sink_the_push_names_that_is_not_there_is_an_error() {
    let push = PushConfig {
        sinks: Some(vec!["gone".into()]),
        ..one_mib()
    };
    let (a, host_b, b, _mirror, _keep) = with_sink(sink::Says::Unavailable, push).await;
    let original = published(&a).await;
    let client = client_for(&[&a.host, &host_b]);
    let push_to = |to: &str, sinks: Option<Vec<String>>| {
        let (a, client) = (&a, client.clone());
        let options = PushOptions {
            destination: Some(format!("{host_b}/{to}")),
            sinks,
            ..PushOptions::default()
        };
        let from = format!("{}/test:latest", a.host);
        async move { a.service.push_with_client(&client, &from, &options).await }
    };
    // (`[push] sinks` says `gone`: it is skipped)
    push_to("copy:v1", None).await.unwrap();
    assert_eq!(manifest_of(&b, "v1"), original);
    let e = push_to("copy:v2", Some(vec!["gone".into()]))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, velarx_types::ImageError::Transfer { party, .. } if party == "gone"),
        "{e}"
    );
}

/// A pusher of `[[transports]]` is the origin of its scheme: it places
/// the objects and commits the manifest, and a helper sink is told the
/// destination too (a transport's is no local path) and the name committed.
mod transport {
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::os::unix::fs::FileExt;
    use std::sync::{Arc, Mutex};
    use velarx_content::pusher::push::{
        CommitReply, EventKind, Have, Object, Placed, Probed, PusherError, PutEvent,
    };
    use velarx_content::serve_fetch::{Described, Out, StagingFetcher};
    use velarx_content::serve_push::{CommitCall, PushScope, Pushing, PutCall};

    /// A destination in memory.
    #[derive(Default)]
    pub struct Fake {
        pub blobs: Mutex<HashMap<String, Vec<u8>>>,
        /// The manifests, by the names they were committed as
        pub manifests: Mutex<Vec<(Vec<String>, Vec<u8>)>>,
        pub destination: Mutex<Option<String>>,
        pub access: Mutex<Option<Vec<u8>>>,
        pub finished: std::sync::atomic::AtomicBool,
        /// It never answers a probe (until the engine gives up)
        pub hangs: bool,
    }

    #[async_trait]
    impl Pushing for Fake {
        fn described(&self) -> Described {
            Described {
                name: "fake".into(),
                capabilities: Vec::new(),
                max_objects: 4,
            }
        }

        async fn probe(
            &self,
            scope: &PushScope,
            objects: Vec<Object>,
            out: &Out<Probed>,
        ) -> Result<(), PusherError> {
            *self.destination.lock().unwrap() = Some(scope.destination.clone());
            *self.access.lock().unwrap() = scope.access.as_ref().map(|a| a.to_vec());
            if self.hangs {
                std::future::pending::<()>().await;
            }
            for (index, o) in objects.iter().enumerate() {
                let have = if self.blobs.lock().unwrap().contains_key(&o.digest) {
                    Have::Present
                } else {
                    Have::Needed
                };
                let _ = out
                    .send(Probed {
                        index: index as u32,
                        have,
                        failure: None,
                    })
                    .await;
            }
            Ok(())
        }

        async fn put(
            &self,
            _scope: &PushScope,
            call: PutCall,
            out: &Out<PutEvent>,
        ) -> Result<(), PusherError> {
            for (index, (o, file)) in call.objects.iter().zip(&call.data).enumerate() {
                let mut bytes = vec![0u8; o.size as usize];
                file.read_exact_at(&mut bytes, 0).unwrap();
                self.blobs.lock().unwrap().insert(o.digest.clone(), bytes);
                let _ = out
                    .send(PutEvent {
                        objects: vec![index as u32],
                        ..PutEvent::of(EventKind::Placed)
                    })
                    .await;
            }
            Ok(())
        }

        async fn commit(
            &self,
            _scope: &PushScope,
            call: CommitCall,
        ) -> Result<CommitReply, PusherError> {
            self.manifests.lock().unwrap().push((call.names, call.body));
            Ok(CommitReply {
                digest: call.manifest.digest,
                placed: vec![Placed {
                    name: None,
                    accepted: true,
                    reason: None,
                }],
            })
        }

        async fn finish(&self, _scope: &PushScope) -> Result<(), PusherError> {
            self.finished
                .store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    struct Api(Arc<Fake>);

    #[async_trait]
    impl StagingFetcher for Api {
        fn described(&self) -> Described {
            Pushing::described(&*self.0)
        }

        fn pusher(&self) -> Option<Arc<dyn Pushing>> {
            Some(self.0.clone())
        }
    }

    pub fn serve(
        dir: &std::path::Path,
    ) -> (
        Arc<Fake>,
        std::path::PathBuf,
        velarx_content::serve_fetch::ServerThread,
    ) {
        serve_as(dir, "fake", false)
    }

    /// The fake, on the socket `NAME.sock` of `dir`; one that `hangs` never
    /// answers a probe.
    pub fn serve_as(
        dir: &std::path::Path,
        name: &str,
        hangs: bool,
    ) -> (
        Arc<Fake>,
        std::path::PathBuf,
        velarx_content::serve_fetch::ServerThread,
    ) {
        let fake = Arc::new(Fake {
            hangs,
            ..Fake::default()
        });
        let socket = dir.join(format!("{name}.sock"));
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let thread = velarx_content::serve_fetch::serve_in_thread(
            listener,
            Arc::new(Api(fake.clone())),
            velarx_content::activation::Limits::default(),
        )
        .unwrap();
        (fake, socket, thread)
    }
}

#[tokio::test]
async fn test_an_external_transport_is_the_origin_of_its_scheme() {
    use velarx_core::services::TransportPush;
    let dir = tempfile::tempdir().unwrap();
    let (fake, socket, _thread) = transport::serve(dir.path());
    let mirror_dir = tempfile::tempdir().unwrap();
    let (mirror, mirror_socket, _mirror_thread) =
        sink::serve(mirror_dir.path(), sink::Says::Unavailable);
    let transports = vec![velarx_config::TransportConfig {
        scheme: "fake".into(),
        socket: Some(socket),
        command: Vec::new(),
        idle_timeout_secs: 15,
        credentials: false,
    }];
    let a = env_built(
        velarx_db::Database::open_in_memory().await.unwrap(),
        PullConfig::default(),
        one_mib(),
        Fetchers::default(),
        None,
        |service| {
            service.with_transports(transports).with_sinks(vec![
                velarx_config::ExternalSinkConfig {
                    name: "mirror".into(),
                    socket: Some(mirror_socket),
                    command: Vec::new(),
                    idle_timeout_secs: 15,
                    credentials: false,
                },
            ])
        },
    )
    .await;
    let original = published(&a).await;
    let digest = sha(&original);
    let from = format!("{}/test:latest", a.host);
    let to = |scheme: &str| PushOptions {
        transport: Some(TransportPush {
            scheme: scheme.into(),
            destination: format!("{scheme}://bucket/private/name:1"),
        }),
        sinks: Some(vec!["mirror".into()]),
        ..PushOptions::default()
    };
    let result = a
        .service
        .push_with_client(&a.client(), &from, &to("fake"))
        .await
        .unwrap();
    assert_eq!(result.digest, digest);
    assert_eq!(result.blobs_uploaded, 3);
    // the origin has what the image has, and the manifest as it was pulled
    assert_eq!(fake.blobs.lock().unwrap().len(), 3);
    assert_eq!(
        fake.blobs.lock().unwrap().get(&digest.to_string()),
        None,
        "(the manifest is committed, not placed)"
    );
    let manifests = fake.manifests.lock().unwrap().clone();
    assert_eq!(manifests.len(), 1);
    assert_eq!(manifests[0].1, original);
    assert!(fake.finished.load(std::sync::atomic::Ordering::Relaxed));
    // it heard the destination as it was written, and so did the helper:
    // a transport's destination is no local path; both are told the name
    // the commit gives the image
    assert_eq!(
        fake.destination.lock().unwrap().as_deref(),
        Some("fake://bucket/private/name:1")
    );
    assert_eq!(
        mirror.destination.lock().unwrap().as_deref(),
        Some("fake://bucket/private/name:1")
    );
    assert_eq!(manifests[0].0, ["1"]);
    assert_eq!(
        mirror.names.lock().unwrap().clone(),
        [vec!["1".to_string()]]
    );
    // (no credentials to a transport that is not defined to take them)
    assert_eq!(*fake.access.lock().unwrap(), None);
    assert!(mirror
        .committed
        .lock()
        .unwrap()
        .contains(&digest.to_string()));
    let again = a
        .service
        .push_with_client(&a.client(), &from, &to("fake"))
        .await
        .unwrap();
    assert_eq!(again.blobs_existing, 3);
    assert_eq!(again.layers_regenerated, 0);

    let e = a
        .service
        .push_with_client(&a.client(), &from, &to("nobody"))
        .await
        .unwrap_err();
    assert!(
        e.to_string()
            .contains("no transport is configured for nobody://"),
        "{e}"
    );
}

/// A helper sink that says nothing for its idle time ends its call: the push
/// that named it fails with an error that names it; one of `[push] sinks`
/// is skipped and the destination's own pusher places.
#[tokio::test]
async fn test_a_sink_that_hangs_does_not_hold_the_push() {
    let push = PushConfig {
        sinks: Some(vec!["mirror".into()]),
        ..one_mib()
    };
    let (a, host_b, b, _mirror, _keep) = with_sink(sink::Says::Hangs, push).await;
    let original = published(&a).await;
    let client = client_for(&[&a.host, &host_b]);
    let from = format!("{}/test:latest", a.host);
    let push_to = |to: &str, sinks: Option<Vec<String>>| {
        let options = PushOptions {
            destination: Some(format!("{host_b}/{to}")),
            sinks,
            ..PushOptions::default()
        };
        let (a, client, from) = (&a, client.clone(), from.clone());
        async move { a.service.push_with_client(&client, &from, &options).await }
    };
    let e = push_to("copy:v1", Some(vec!["mirror".into()]))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, velarx_types::ImageError::Transfer { party, failure, .. } if party == "mirror" && failure.reason.contains("silent")),
        "{e}"
    );
    assert!(b.blobs.lock().unwrap().is_empty());
    // (the sink of `[push] sinks` is left out once it is silent)
    push_to("copy:v2", None).await.unwrap();
    assert_eq!(manifest_of(&b, "v2"), original);
}

/// A save of images asks the one pusher about more objects than a scope
/// keeps told at once (1024): what the pushers have found or placed is
/// forgotten, so the limit is for what is in flight.  The 1053 objects are
/// all distinct, so only the forgetting keeps the scope under the limit.
#[tokio::test]
async fn test_a_save_of_images_with_more_than_1024_objects_in_all() {
    use velarx_content::dir_push::Mode;
    use velarx_core::services::PathPush;
    let a = env().await;
    let layer = |i: usize| {
        let name: &'static str = Box::leak(format!("f{i}").into_boxed_str());
        build_written(
            &tar_of(&[Item::File {
                name,
                data: i.to_string().into_bytes(),
                chunk: 64,
            }]),
            Compression::Gzip,
        )
    };
    // (an image holds at most 498 layers: three of 350 layers of their own)
    let mut references = Vec::new();
    for k in 0..3 {
        let own: Vec<Built> = (0..350).map(|i| layer(k * 350 + i)).collect();
        let layers: Vec<&Built> = own.iter().collect();
        let media = vec![GZIP; layers.len()];
        publish_arch(&a.reg, &layers, &media, "amd64", &format!("v{k}"));
        let reference = format!("{}/test:v{k}", a.host);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        a.service
            .pull_with_client(&a.client(), &reference, tx)
            .await
            .unwrap();
        references.push((reference, vec![format!("v{k}")]));
    }
    let tmp = tempfile::tempdir().unwrap();
    a.service
        .save_images(
            &references,
            &PathPush {
                mode: Mode::Layout,
                dest: std::sync::Arc::new(std::fs::File::open(tmp.path()).unwrap().into()),
                names: Vec::new(),
                label: "save".into(),
            },
        )
        .await
        .unwrap();
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(tmp.path().join("index.json")).unwrap()).unwrap();
    assert_eq!(index["manifests"].as_array().unwrap().len(), 3);
    let blobs = std::fs::read_dir(tmp.path().join("blobs/sha256"))
        .unwrap()
        .count();
    assert_eq!(blobs, 1050 + 3 + 3);
}

/// A helper that the push named and that says nothing at the commit or at the
/// end fails the push, naming it; one of `[push] sinks` is skipped, and the
/// image is at the destination either way.
#[tokio::test]
async fn test_a_helper_that_is_silent_at_the_commit_or_the_end_fails_the_push_that_named_it() {
    for says in [sink::Says::HangsAtCommit, sink::Says::HangsAtFinish] {
        let push = PushConfig {
            sinks: Some(vec!["mirror".into()]),
            ..one_mib()
        };
        let (a, host_b, b, _mirror, _keep) = with_sink(says, push).await;
        let original = published(&a).await;
        let client = client_for(&[&a.host, &host_b]);
        let from = format!("{}/test:latest", a.host);
        let push_to = |to: &str, sinks: Option<Vec<String>>| {
            let options = PushOptions {
                destination: Some(format!("{host_b}/{to}")),
                sinks,
                ..PushOptions::default()
            };
            let (a, client, from) = (&a, client.clone(), from.clone());
            async move { a.service.push_with_client(&client, &from, &options).await }
        };
        let e = push_to("copy:v1", Some(vec!["mirror".into()]))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, velarx_types::ImageError::Transfer { party, failure, .. } if party == "mirror" && failure.reason.contains("silent")),
            "{e}"
        );
        // (the named helper's silence does not undo what the origin has)
        assert_eq!(manifest_of(&b, "v1"), original);
        // one of `[push] sinks` is left out
        push_to("copy:v2", None).await.unwrap();
        assert_eq!(manifest_of(&b, "v2"), original);
    }
}

/// An origin of `[[transports]]` that says nothing for its idle time
/// fails the push with an error that names the transport by its scheme.
#[tokio::test]
async fn test_a_transport_that_hangs_fails_the_push_naming_its_scheme() {
    use velarx_core::services::TransportPush;
    let dir = tempfile::tempdir().unwrap();
    let (_fake, socket, _thread) = transport::serve_as(dir.path(), "hangs", true);
    // (one that answers nothing at all: not even the description)
    let silent = dir.path().join("silent.sock");
    let listener = std::os::unix::net::UnixListener::bind(&silent).unwrap();
    let (stop, stopped) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let mut held = Vec::new();
        listener.set_nonblocking(false).unwrap();
        while let Ok((conn, _)) = listener.accept() {
            if stopped.try_recv().is_ok() {
                break;
            }
            held.push(conn);
        }
    });
    let transports = vec![
        velarx_config::TransportConfig {
            scheme: "hangs".into(),
            socket: Some(socket),
            command: Vec::new(),
            idle_timeout_secs: 1,
            credentials: false,
        },
        velarx_config::TransportConfig {
            scheme: "silent".into(),
            socket: Some(silent.clone()),
            command: Vec::new(),
            idle_timeout_secs: 1,
            credentials: false,
        },
    ];
    let a = env_transports(transports).await;
    published(&a).await;
    let from = format!("{}/test:latest", a.host);
    for scheme in ["hangs", "silent"] {
        let e = a
            .service
            .push_with_client(
                &a.client(),
                &from,
                &PushOptions {
                    transport: Some(TransportPush {
                        scheme: scheme.into(),
                        destination: format!("{scheme}://bucket/name:1"),
                    }),
                    ..PushOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&e, velarx_types::ImageError::Transfer { party, failure, .. } if party == scheme && failure.reason.contains("silent")),
            "{scheme}: {e}"
        );
    }
    // (the accept loop ends with a connection after the stop)
    stop.send(()).unwrap();
    let _ = std::os::unix::net::UnixStream::connect(&silent);
    holder.join().unwrap();
}

/// The credentials a transport gets are the ones under its own key
/// `SCHEME://AUTHORITY`: never the entries a docker reference could mean,
/// whether TLS is verified or not; a transport defined without
/// `credentials` gets none.
#[tokio::test]
async fn test_a_transport_gets_the_credentials_of_its_own_key_and_no_others() {
    use velarx_core::services::TransportPush;
    use velarx_registry::{auth::RegistryAccess, Credentials};
    let dir = tempfile::tempdir().unwrap();
    let (taking, taking_socket, _t1) = transport::serve_as(dir.path(), "taking", false);
    let (refusing, refusing_socket, _t2) = transport::serve_as(dir.path(), "refusing", false);
    let transports = vec![
        velarx_config::TransportConfig {
            scheme: "taking".into(),
            socket: Some(taking_socket),
            command: Vec::new(),
            idle_timeout_secs: 15,
            credentials: true,
        },
        velarx_config::TransportConfig {
            scheme: "refusing".into(),
            socket: Some(refusing_socket),
            command: Vec::new(),
            idle_timeout_secs: 15,
            credentials: false,
        },
    ];
    let a = env_transports(transports).await;
    published(&a).await;
    let from = format!("{}/test:latest", a.host);
    let creds = |user: &str| Credentials::parse_creds(&format!("{user}:secret")).unwrap();
    let mut access = RegistryAccess::default();
    for key in ["docker.io", "docker.io/bucket", "quay.io", "taking://other"] {
        access.auths.insert(key.into(), creds("hub"));
    }
    access.auths.insert("taking://bucket".into(), creds("mine"));
    for (tls_verify, scheme, fake) in [
        (true, "taking", &taking),
        (false, "taking", &taking),
        (true, "refusing", &refusing),
    ] {
        *fake.access.lock().unwrap() = None;
        a.service
            .push_with_client(
                &a.client(),
                &from,
                &PushOptions {
                    tls_verify,
                    access: access.clone(),
                    transport: Some(TransportPush {
                        scheme: scheme.into(),
                        destination: format!("{scheme}://bucket/docker.io/name:1"),
                    }),
                    ..PushOptions::default()
                },
            )
            .await
            .unwrap();
        let given = fake.access.lock().unwrap().clone();
        if scheme == "refusing" {
            assert_eq!(given, None);
            continue;
        }
        let given: RegistryAccess = serde_json::from_slice(&given.unwrap()).unwrap();
        assert_eq!(
            given.auths.keys().collect::<Vec<_>>(),
            ["taking://bucket"],
            "tls_verify={tls_verify}"
        );
        assert!(given.creds.is_none());
    }
}

/// A destination with userinfo or without an authority is refused by the
/// engine too (whatever the client did), before any pusher hears of it, with
/// an error that does not repeat the secret; the key of the credentials has
/// no case.
#[tokio::test]
async fn test_a_transport_destination_with_userinfo_is_refused_and_its_key_has_no_case() {
    use velarx_core::services::{ListPushOptions, TransportPush};
    use velarx_registry::{auth::RegistryAccess, Credentials};
    let dir = tempfile::tempdir().unwrap();
    let (fake, socket, _thread) = transport::serve_as(dir.path(), "fake", false);
    let transports = vec![velarx_config::TransportConfig {
        scheme: "fake".into(),
        socket: Some(socket),
        command: Vec::new(),
        idle_timeout_secs: 15,
        credentials: true,
    }];
    let a = env_transports(transports).await;
    published(&a).await;
    let from = format!("{}/test:latest", a.host);
    let to = |destination: &str, access: RegistryAccess| PushOptions {
        access,
        transport: Some(TransportPush {
            scheme: "fake".into(),
            destination: destination.into(),
        }),
        ..PushOptions::default()
    };
    for bad in [
        "fake://AKID:SECRET@bucket/x:1",
        "fake://SECRET@bucket",
        "fake:///x:1",
    ] {
        let e = a
            .service
            .push_with_client(&a.client(), &from, &to(bad, RegistryAccess::default()))
            .await
            .unwrap_err();
        let text = format!("{e} {e:?}");
        assert!(!text.contains("SECRET") && !text.contains("AKID"), "{text}");
        assert!(text.contains("fake://"), "{text}");
        let e = a
            .service
            .manifest_push("nolist", bad, &ListPushOptions::default())
            .await
            .unwrap_err();
        let text = format!("{e} {e:?}");
        assert!(!text.contains("SECRET") && !text.contains("AKID"), "{text}");
    }
    assert_eq!(
        *fake.destination.lock().unwrap(),
        None,
        "no pusher was told"
    );
    // (an entry written as `Fake://Bucket/` is the one of `fake://BUCKET/x`)
    let mut access = RegistryAccess::default();
    access.auths.insert(
        velarx_registry::auth::normalize_auth_key("Fake://Bucket/"),
        Credentials::parse_creds("mine:secret").unwrap(),
    );
    a.service
        .push_with_client(&a.client(), &from, &to("fake://BUCKET/x:1", access))
        .await
        .unwrap();
    let given = fake.access.lock().unwrap().clone().unwrap();
    let given: RegistryAccess = serde_json::from_slice(&given).unwrap();
    assert_eq!(given.auths.keys().collect::<Vec<_>>(), ["fake://bucket"]);
}

/// `manifest push` takes a destination of a `[[transports]]` scheme as
/// `push` does: the instances go by their digests to its repository, the
/// list under the name the destination gives it, through the same origin.
#[tokio::test]
async fn test_a_manifest_list_is_pushed_to_a_transport() {
    use std::collections::BTreeMap;
    use velarx_core::services::{AddOptions, ListPushOptions};
    let dir = tempfile::tempdir().unwrap();
    let (fake, socket, _thread) = transport::serve(dir.path());
    let transports = vec![velarx_config::TransportConfig {
        scheme: "fake".into(),
        socket: Some(socket),
        command: Vec::new(),
        idle_timeout_secs: 15,
        credentials: false,
    }];
    let a = env_transports(transports).await;
    let original = published(&a).await;
    let svc = &a.service;
    let image = svc.get(&format!("{}/test:latest", a.host)).await.unwrap();
    svc.manifest_create(
        "mlist",
        &[format!("containers-storage:{}", image.id)],
        &AddOptions::default(),
        &BTreeMap::new(),
        false,
        None,
    )
    .await
    .unwrap();
    let opts = ListPushOptions {
        all: true,
        ..ListPushOptions::default()
    };
    let digest = svc
        .manifest_push("mlist", "fake://bucket/lists/x:v1", &opts)
        .await
        .unwrap();
    // (the instances were probed in the repository of the destination)
    assert_eq!(
        fake.destination.lock().unwrap().as_deref(),
        Some("fake://bucket/lists/x")
    );
    let manifests = fake.manifests.lock().unwrap().clone();
    assert_eq!(manifests.len(), 2, "the instance, then the list");
    assert_eq!(manifests[0], (Vec::<String>::new(), original));
    assert_eq!(manifests[1].0, ["v1"]);
    assert_eq!(sha(&manifests[1].1), digest);
    assert_eq!(fake.blobs.lock().unwrap().len(), 3);
    assert!(fake.finished.load(std::sync::atomic::Ordering::Relaxed));
    let e = svc
        .manifest_push("mlist", "nobody://bucket/x:v1", &opts)
        .await
        .unwrap_err();
    assert!(
        e.to_string()
            .contains("no transport is configured for nobody://"),
        "{e}"
    );
}
