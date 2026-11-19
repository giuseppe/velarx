// SPDX-License-Identifier: Apache-2.0
//! Commits of a directory of changes on top of an image: the layer is made
//! by the layer writer and installed like a pulled one.

use crate::common::*;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use velarx_content::layer::dirtar;
use velarx_content::layer::reproduce::StoredLayer;
use velarx_core::services::{CommitOptions, ConfigEdit};
use velarx_types::OciManifest;

const GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
const TAR: &str = "application/vnd.oci.image.layer.v1.tar";

fn items() -> Vec<Item> {
    vec![
        Item::Dir("etc/"),
        Item::File {
            name: "etc/hello",
            data: b"hello\n".to_vec(),
            chunk: 4096,
        },
        Item::File {
            name: "usr/big",
            data: (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect(),
            chunk: 65536,
        },
    ]
}

/// A store with `<host>/test:latest`, two layers.
async fn source() -> Env {
    source_trusting(&[]).await
}

/// [`source`], its fetcher knowing the registries `hosts` too.
async fn source_trusting(hosts: &[&str]) -> Env {
    let e = env().await;
    e.trust(hosts);
    let first = build_gzip(&items());
    let second = build_chunked(&items()[..2]);
    e.publish(&[&first, &second], &[GZIP, ZSTD]);
    e.pull().await.unwrap();
    e
}

/// The changes a container could have made.
fn changes(dir: &Path) {
    std::fs::create_dir_all(dir.join("etc")).unwrap();
    std::fs::write(dir.join("etc/hello"), "changed\n").unwrap();
    std::fs::write(dir.join("etc/hosts"), "127.0.0.1 engine\n").unwrap();
    std::fs::create_dir_all(dir.join("app/sub")).unwrap();
    std::fs::write(dir.join("app/new"), vec![b'x'; 200_000]).unwrap();
    std::fs::hard_link(dir.join("app/new"), dir.join("app/sub/link")).unwrap();
    std::os::unix::fs::symlink("../app/new", dir.join("app/sym")).unwrap();
    // The same times for every run: the layer only depends on the tree.
    for p in ["etc", "etc/hello", "app", "app/sub", "app/new"] {
        let f = std::fs::File::open(dir.join(p)).unwrap();
        f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000))
            .unwrap();
    }
}

fn options(names: &[&str]) -> CommitOptions {
    CommitOptions {
        edits: vec![ConfigEdit::Env(vec![("FROM_EDIT".into(), "1".into())])],
        changes: vec!["ENV A=b".into(), "CMD [\"/app/new\"]".into()],
        author: Some("tester".into()),
        message: Some("a message".into()),
        names: names.iter().map(|s| s.to_string()).collect(),
        walk: dirtar::Options {
            exclude: dirtar::ENGINE_FILES.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        },
        ..CommitOptions::default()
    }
}

async fn layer_tar(e: &Env, digest: &Digest) -> Vec<u8> {
    let layer = StoredLayer::load(&e.db, &stored_key(&e.db, digest).await)
        .await
        .unwrap();
    let mut out = Vec::new();
    layer
        .verified_stream(e.store.clone())
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// The names of the entries, without the `./` every name of a canonical tar
/// starts with (the root is `./`).
fn tar_names(tar: &[u8]) -> Vec<String> {
    tar::Archive::new(tar)
        .entries()
        .unwrap()
        .map(|e| {
            let name = e.unwrap().path().unwrap().to_string_lossy().to_string();
            match name.strip_prefix("./") {
                Some(rest) if !rest.is_empty() => rest.to_string(),
                _ => name,
            }
        })
        .collect()
}

#[tokio::test]
async fn test_commit_adds_a_verified_layer_on_top_of_the_parent() {
    let e = source().await;
    let parent = e
        .service
        .get(&format!("{}/test:latest", e.host))
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    changes(dir.path());

    let id = e
        .service
        .commit_dir(
            Some(&parent.id),
            Some(dir.path()),
            &options(&["committed:v1"]),
        )
        .await
        .unwrap();
    let image = e.service.get("localhost/committed:v1").await.unwrap();
    assert_eq!(image.id, id);
    assert!(!image.is_lazy);

    let pm: OciManifest = serde_json::from_str(&parent.manifest).unwrap();
    let m: OciManifest = serde_json::from_str(&image.manifest).unwrap();
    assert_eq!(m.layers.len(), 3);
    for (a, b) in pm.layers.iter().zip(&m.layers) {
        assert_eq!(a.digest, b.digest);
    }
    // the manifest states the digest of the merged EROFS, and the id is
    // the digest of the configuration (the manifest is written by the push)
    let sealed = &m.annotations["composefs.merged.erofs.v1.fsverity-sha256-12"];
    assert!(sealed.len() == 64 && sealed.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(
        format!("sha256:{id}"),
        sha(image.config.as_bytes()).to_string()
    );
    // ... and the digest of the EROFS image of each layer, a parent's too
    for l in &m.layers {
        let erofs =
            e.db.get_layer(&stored_key(&e.db, &l.digest).await)
                .await
                .unwrap()
                .erofs
                .unwrap();
        assert_eq!(
            l.annotations["io.containers.composefs.digest"], erofs,
            "{}",
            l.digest
        );
    }
    let top = &m.layers[2];
    assert_eq!(top.media_type, TAR);
    assert_eq!(top.digest.to_string(), config_diff_id(&image, 2));

    let config: serde_json::Value = serde_json::from_str(&image.config).unwrap();
    assert_eq!(config["rootfs"]["diff_ids"].as_array().unwrap().len(), 3);
    let env = config["config"]["Env"].as_array().unwrap();
    assert!(env.contains(&serde_json::json!("A=b")));
    assert!(env.contains(&serde_json::json!("FROM_EDIT=1")));
    assert_eq!(config["config"]["Cmd"], serde_json::json!(["/app/new"]));
    assert_eq!(config["author"], "tester");
    let history = config["history"].as_array().unwrap();
    assert_eq!(history.last().unwrap()["comment"], "a message");

    // The layer is stored with its tar-split and gives back the stream of
    // the diff id; the engine files are not in it.
    let rec =
        e.db.get_layer(&stored_key(&e.db, &top.digest).await)
            .await
            .unwrap();
    assert_eq!(rec.status, "ready");
    let tar = layer_tar(&e, &top.digest).await;
    assert_eq!(
        rec.diff_id.as_ref(),
        Some(&sha(&tar)),
        "the diff id is the digest of the stream"
    );
    assert_eq!(
        tar_names(&tar),
        [
            "app/",
            "app/new",
            "app/sub/",
            "app/sub/link",
            "app/sym",
            "etc/",
            "etc/hello"
        ]
    );
    assert!(e.store.contains(&vid(b"changed\n")));
    assert!(e.store.contains(&vid(&vec![b'x'; 200_000])));

    let diff = e.service.image_changes(&id).await.unwrap();
    let shown: Vec<String> = diff
        .iter()
        .map(|(p, c)| format!("{} {p}", c.letter()))
        .collect();
    assert_eq!(
        shown,
        [
            "A /app",
            "A /app/new",
            "A /app/sub",
            "A /app/sub/link",
            "A /app/sym",
            "C /etc",
            "C /etc/hello"
        ]
    );
    assert_eq!(e.staged_leftovers(), 0);
}

#[tokio::test]
async fn test_configuration_only_and_scratch_commits() {
    let e = source().await;
    let parent = e
        .service
        .get(&format!("{}/test:latest", e.host))
        .await
        .unwrap();
    let id = e
        .service
        .commit_dir(Some(&parent.id), None, &options(&["onlyconfig"]))
        .await
        .unwrap();
    let image = e.service.get("localhost/onlyconfig:latest").await.unwrap();
    assert_eq!(image.id, id);
    let m: OciManifest = serde_json::from_str(&image.manifest).unwrap();
    assert_eq!(m.layers.len(), 2);
    let config: serde_json::Value = serde_json::from_str(&image.config).unwrap();
    assert_eq!(
        config["history"].as_array().unwrap().last().unwrap()["empty_layer"],
        true
    );

    // An image of its own: one layer, an empty directory gives an empty one.
    let dir = tempfile::tempdir().unwrap();
    let id = e
        .service
        .commit_dir(None, Some(dir.path()), &CommitOptions::default())
        .await
        .unwrap();
    let image = e.service.get(&id).await.unwrap();
    let m: OciManifest = serde_json::from_str(&image.manifest).unwrap();
    assert_eq!(m.layers.len(), 1);
    assert_eq!(layer_tar(&e, &m.layers[0].digest).await, vec![0u8; 1024]);

    assert!(e
        .service
        .commit_dir(None, None, &CommitOptions::default())
        .await
        .is_err());
}

#[tokio::test]
async fn test_failed_commits_leave_nothing() {
    let e = source().await;
    let parent = format!("{}/test:latest", e.host);
    let before = e.service.list().await.unwrap().len();
    let dir = tempfile::tempdir().unwrap();
    changes(dir.path());
    let bad = CommitOptions {
        changes: vec!["NOTANINSTRUCTION x".into()],
        ..options(&["bad"])
    };
    assert!(e
        .service
        .commit_dir(Some(&parent), Some(dir.path()), &bad)
        .await
        .is_err());
    // A directory that is not one.
    let file = dir.path().join("app/new");
    assert!(e
        .service
        .commit_dir(Some(&parent), Some(&file), &options(&["bad"]))
        .await
        .is_err());
    // A name that is not one.
    assert!(e
        .service
        .commit_dir(Some(&parent), Some(dir.path()), &options(&["Not A Name"]))
        .await
        .is_err());
    assert!(e.service.get("localhost/bad:latest").await.is_err());
    assert_eq!(e.service.list().await.unwrap().len(), before);
    assert_eq!(e.staged_leftovers(), 0);
}

#[tokio::test]
async fn test_a_leased_commit_is_not_pruned() {
    let e = source().await;
    let lease = e.service.take_lease("build-test").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    changes(dir.path());
    let opts = CommitOptions {
        lease: Some(lease.id().to_string()),
        ..options(&[])
    };
    let id = e
        .service
        .commit_dir(
            Some(&format!("{}/test:latest", e.host)),
            Some(dir.path()),
            &opts,
        )
        .await
        .unwrap();
    // Untagged, but leased: a prune leaves it.
    let pruned: Vec<String> = e
        .service
        .prune(true, &[])
        .await
        .unwrap()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert!(!pruned.contains(&id), "{pruned:?}");
    assert!(e.service.get(&id).await.is_ok());
    lease.release().await.unwrap();
    let pruned: Vec<String> = e
        .service
        .prune(false, &[])
        .await
        .unwrap()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert!(pruned.contains(&id), "{pruned:?}");
}

#[tokio::test]
async fn test_a_parent_that_is_being_pulled_is_refused() {
    let e = env().await;
    let layer = build_chunked(&items());
    e.publish(&[&layer], &[ZSTD]);
    e.pull_lazy().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let err = e
        .service
        .commit_dir(
            Some(&format!("{}/test:latest", e.host)),
            Some(dir.path()),
            &options(&[]),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("is being pulled"), "{err}");
    // a squash of all its layers too, and nothing is left behind
    let err = e
        .service
        .commit_dir(
            Some(&format!("{}/test:latest", e.host)),
            None,
            &CommitOptions {
                squash_all: true,
                ..CommitOptions::default()
            },
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("is being pulled"), "{err}");
    assert_eq!(e.staged_leftovers(), 0);
}

/// A commit tells how its layer is written and stored, as a pull does.
#[tokio::test]
async fn test_commit_tells_its_progress() {
    let e = source().await;
    let parent = e
        .service
        .get(&format!("{}/test:latest", e.host))
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    changes(dir.path());
    let (tx, mut rx) = tokio::sync::mpsc::channel(1000);
    let opts = CommitOptions {
        progress: Some(tx),
        ..options(&["progress:v1"])
    };
    e.service
        .commit_dir(Some(&parent.id), Some(dir.path()), &opts)
        .await
        .unwrap();
    drop(opts);
    let mut events = Vec::new();
    while let Some(p) = rx.recv().await {
        events.push((
            p.subject.to_string(),
            p.status,
            p.current_bytes,
            p.total_bytes,
        ));
    }
    let written: Vec<_> = events.iter().filter(|e| e.0 == "new layer").collect();
    assert_eq!(written.first().unwrap().1, "streaming", "{events:?}");
    let last = written.last().unwrap();
    assert_eq!(last.1, "complete", "{events:?}");
    assert!(last.2 > 200_000 && last.2 == last.3, "{events:?}");
    assert!(
        events
            .iter()
            .any(|e| e.0.starts_with("sha256:") && e.1 == "complete"),
        "{events:?}"
    );
}

fn view(tree: &velarx_fuse::MergedTree) -> Vec<String> {
    fn walk(t: &velarx_fuse::MergedTree, idx: usize, path: &str, out: &mut Vec<String>) {
        let n = t.node(idx).unwrap();
        for (name, &c) in &n.children {
            let p = format!("{path}/{name}");
            let e = &t.node(c).unwrap().entry;
            out.push(format!(
                "{p} {:?} {:o} {}:{} {} {:?} {:?}",
                e.entry_type,
                e.mode,
                e.uid,
                e.gid,
                e.size,
                e.verity(),
                e.link_name
            ));
            walk(t, c, &p, out);
        }
    }
    let mut out = Vec::new();
    walk(tree, 0, "", &mut out);
    out
}

async fn tree_of(e: &Env, id: &str) -> velarx_fuse::MergedTree {
    let tocs: Vec<velarx_storage::Toc> =
        e.db.get_image_layers(id)
            .await
            .unwrap()
            .iter()
            .map(|l| serde_json::from_str(l.toc.as_deref().unwrap()).unwrap())
            .collect();
    velarx_fuse::MergedTree::build(&tocs.iter().collect::<Vec<_>>()).unwrap()
}

/// `squash_all`: one layer holding the merged view of three (whiteouts
/// resolved), the configuration kept, one history entry, sealed, and it
/// goes through a registry in the layer's format.
#[tokio::test]
async fn test_squash_all_makes_one_layer_of_the_merged_tree() {
    let e = env().await;
    let (host_b, b) = start_registry().await;
    e.trust(&[&host_b]);
    let big: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let l1 = build_gzip(&[
        Item::Dir("etc/"),
        Item::File {
            name: "etc/gone",
            data: b"gone\n".to_vec(),
            chunk: 4096,
        },
        Item::File {
            name: "etc/hello",
            data: b"hello\n".to_vec(),
            chunk: 4096,
        },
        Item::File {
            name: "usr/big",
            data: big.clone(),
            chunk: 65536,
        },
        Item::Symlink("etc/link", "hello"),
    ]);
    let l2 = build_gzip(&[
        Item::File {
            name: "etc/.wh.gone",
            data: vec![],
            chunk: 1,
        },
        Item::File {
            name: "etc/hello",
            data: b"changed\n".to_vec(),
            chunk: 4096,
        },
    ]);
    let l3 = build_chunked(&[Item::File {
        name: "top",
        data: b"top\n".to_vec(),
        chunk: 4096,
    }]);
    e.publish(&[&l1, &l2, &l3], &[GZIP, GZIP, ZSTD]);
    e.pull().await.unwrap();
    let parent = e
        .service
        .get(&format!("{}/test:latest", e.host))
        .await
        .unwrap();
    // (a configuration and one more history entry)
    let id = e
        .service
        .commit_dir(Some(&parent.id), None, &options(&[]))
        .await
        .unwrap();
    let parent = e.service.get(&id).await.unwrap();
    let before = view(&tree_of(&e, &parent.id).await);

    let opts = CommitOptions {
        squash_all: true,
        created_by: "squash".into(),
        names: vec!["squashed:v1".into()],
        ..CommitOptions::default()
    };
    let id = e
        .service
        .commit_dir(Some(&parent.id), None, &opts)
        .await
        .unwrap();
    let image = e.service.get(&id).await.unwrap();
    let m: OciManifest = serde_json::from_str(&image.manifest).unwrap();
    assert_eq!(m.layers.len(), 1);
    assert_eq!(m.layers[0].media_type, TAR);
    let sealed = &m.annotations["composefs.merged.erofs.v1.fsverity-sha256-12"];
    assert!(sealed.len() == 64 && sealed.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(view(&tree_of(&e, &id).await), before);

    let config: serde_json::Value = serde_json::from_str(&image.config).unwrap();
    let pconfig: serde_json::Value = serde_json::from_str(&parent.config).unwrap();
    assert_eq!(config["config"], pconfig["config"]);
    assert_eq!(config["config"]["Cmd"], serde_json::json!(["/app/new"]));
    assert_eq!(pconfig["history"].as_array().unwrap().len(), 1);
    assert_eq!(config["rootfs"]["diff_ids"].as_array().unwrap().len(), 1);
    let history = config["history"].as_array().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["created_by"], "squash");
    assert!(history[0].get("empty_layer").is_none());

    let tar = layer_tar(&e, &m.layers[0].digest).await;
    assert_eq!(
        tar_names(&tar),
        [
            "./",
            "etc/",
            "etc/hello",
            "etc/link",
            "top",
            "usr/",
            "usr/big"
        ]
    );
    assert_eq!(e.staged_leftovers(), 0);
    // the same tree, the same layer
    let untagged = CommitOptions {
        squash_all: true,
        created_by: "squash".into(),
        ..CommitOptions::default()
    };
    let again = e
        .service
        .commit_dir(Some(&parent.id), None, &untagged)
        .await
        .unwrap();
    let again: OciManifest =
        serde_json::from_str(&e.service.get(&again).await.unwrap().manifest).unwrap();
    assert_eq!(again.layers[0].digest, m.layers[0].digest);

    // pushed and pulled back: the blob, its table of contents and the
    // image are the same
    let client = client_for(&[&e.host, &host_b]);
    let pushed = e
        .service
        .push_with_client(
            &client,
            "localhost/squashed:v1",
            &velarx_core::services::PushOptions {
                destination: Some(format!("{host_b}/squashed:v1")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let pushed_manifest: OciManifest =
        serde_json::from_slice(&b.blobs.lock().unwrap()[&format!("manifest:{}", pushed.digest)])
            .unwrap();
    assert!(b.has("squashed", &pushed_manifest.layers[0].digest));
    assert_eq!(pushed_manifest.layers[0].media_type, ZSTD);
    let other = side_with(Some(&conf_for(&[&e.host, &host_b]))).await;
    other
        .pull(&client, &format!("{host_b}/squashed@{}", pushed.digest))
        .await
        .unwrap();
    let back = other.db.get_image_by_digest(&pushed.digest).await.unwrap();
    assert_eq!(back.config, image.config);
    assert_eq!(back.manifest_digest, pushed.digest);
    assert!(other.store.contains(&vid(&big)));
}

/// `commit --squash`: the changes of a container applied to the merged
/// tree of a three layer image make one layer; the tree is the one of the
/// unsquashed commit, the configuration too, the history one entry.
#[tokio::test]
async fn test_commit_squash_makes_one_layer_of_the_image_and_the_changes() {
    let e = env().await;
    let (host_b, b) = start_registry().await;
    e.trust(&[&host_b]);
    let l1 = build_gzip(&items());
    let l2 = build_gzip(&[
        Item::File {
            name: "etc/.wh.hello",
            data: vec![],
            chunk: 1,
        },
        Item::File {
            name: "etc/two",
            data: b"two\n".to_vec(),
            chunk: 4096,
        },
    ]);
    let l3 = build_chunked(&[Item::File {
        name: "top",
        data: b"top\n".to_vec(),
        chunk: 4096,
    }]);
    e.publish(&[&l1, &l2, &l3], &[GZIP, GZIP, ZSTD]);
    e.pull().await.unwrap();
    let parent = e
        .service
        .get(&format!("{}/test:latest", e.host))
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    changes(dir.path());
    std::fs::write(dir.path().join("top"), "top changed\n").unwrap();

    let plain = e
        .service
        .commit_dir(Some(&parent.id), Some(dir.path()), &options(&[]))
        .await
        .unwrap();
    let opts = CommitOptions {
        squash_all: true,
        ..options(&["squashed:v1"])
    };
    let id = e
        .service
        .commit_dir(Some(&parent.id), Some(dir.path()), &opts)
        .await
        .unwrap();
    let (plain_image, image) = (
        e.service.get(&plain).await.unwrap(),
        e.service.get(&id).await.unwrap(),
    );
    let pm: OciManifest = serde_json::from_str(&plain_image.manifest).unwrap();
    let m: OciManifest = serde_json::from_str(&image.manifest).unwrap();
    assert_eq!(pm.layers.len(), 4);
    assert_eq!(m.layers.len(), 1);
    let sealed = &m.annotations["composefs.merged.erofs.v1.fsverity-sha256-12"];
    assert!(sealed.len() == 64 && sealed.bytes().all(|b| b.is_ascii_hexdigit()));

    let view = view(&tree_of(&e, &id).await);
    assert_eq!(view, self::view(&tree_of(&e, &plain).await));
    assert!(view.iter().any(|l| l.starts_with("/app/sub/link ")));
    assert!(view.iter().any(|l| l.starts_with("/etc/hello Reg")));

    let config: serde_json::Value = serde_json::from_str(&image.config).unwrap();
    let pconfig: serde_json::Value = serde_json::from_str(&plain_image.config).unwrap();
    assert_eq!(config["config"], pconfig["config"]);
    assert_eq!(config["author"], "tester");
    assert_eq!(config["config"]["Cmd"], serde_json::json!(["/app/new"]));
    assert_eq!(config["rootfs"]["diff_ids"].as_array().unwrap().len(), 1);
    let history = config["history"].as_array().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["comment"], "a message");

    let tar = layer_tar(&e, &m.layers[0].digest).await;
    let names = tar_names(&tar);
    assert_eq!(names[0], "./");
    assert!(names.contains(&"app/sub/link".to_string()));
    assert!(!names.iter().any(|n| n.contains(".wh.")));
    assert_eq!(e.staged_leftovers(), 0);

    // the same input, the same layer
    let untagged = CommitOptions {
        names: vec![],
        ..opts.clone()
    };
    let again = e
        .service
        .commit_dir(Some(&parent.id), Some(dir.path()), &untagged)
        .await
        .unwrap();
    let again: OciManifest =
        serde_json::from_str(&e.service.get(&again).await.unwrap().manifest).unwrap();
    assert_eq!(again.layers[0].digest, m.layers[0].digest);

    // through a registry and back
    let client = client_for(&[&e.host, &host_b]);
    let pushed = e
        .service
        .push_with_client(
            &client,
            "localhost/squashed:v1",
            &velarx_core::services::PushOptions {
                destination: Some(format!("{host_b}/squashed:v1")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let pushed_manifest: OciManifest =
        serde_json::from_slice(&b.blobs.lock().unwrap()[&format!("manifest:{}", pushed.digest)])
            .unwrap();
    assert!(b.has("squashed", &pushed_manifest.layers[0].digest));
    assert_eq!(pushed_manifest.layers[0].media_type, ZSTD);
    let other = side_with(Some(&conf_for(&[&e.host, &host_b]))).await;
    other
        .pull(&client, &format!("{host_b}/squashed@{}", pushed.digest))
        .await
        .unwrap();
    let back = other.db.get_image_by_digest(&pushed.digest).await.unwrap();
    assert_eq!(back.config, image.config);
    assert_eq!(back.manifest_digest, pushed.digest);
}

/// A sparse file in the changes (8 MiB with a few bytes at both ends) is
/// the same file in the layer of a commit and of a squashed commit: the
/// layer has a chunk of zeros for it, the store a sparse file, and the
/// squash spools no content.
#[tokio::test]
async fn test_a_sparse_file_is_a_chunk_of_zeros_in_both_commits() {
    use std::os::unix::fs::{FileExt, MetadataExt};
    use velarx_storage::{Toc, VerityHasher};
    const SIZE: u64 = 8 << 20;
    let (host_b, registry) = start_registry().await;
    let e = source_trusting(&[&host_b]).await;
    let parent = e
        .service
        .get(&format!("{}/test:latest", e.host))
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    changes(dir.path());
    let f = std::fs::File::create(dir.path().join("app/sparse")).unwrap();
    f.set_len(SIZE).unwrap();
    f.write_all_at(b"head", 0).unwrap();
    f.write_all_at(b"end", SIZE - 3).unwrap();
    // (a file system without holes still has to give the same layer)
    let holes = dir.path().join("app/sparse");
    let has_holes = std::fs::metadata(&holes).unwrap().blocks() * 512 < SIZE / 2;

    let plain = e
        .service
        .commit_dir(Some(&parent.id), Some(dir.path()), &options(&["plain:v1"]))
        .await
        .unwrap();
    let squashed = e
        .service
        .commit_dir(
            Some(&parent.id),
            Some(dir.path()),
            &CommitOptions {
                squash_all: true,
                ..options(&["squashed:v1"])
            },
        )
        .await
        .unwrap();
    assert_eq!(e.staged_leftovers(), 0);
    let client = client_for(&[&e.host, &host_b]);
    let mut pushed = HashMap::new();
    for (name, id) in [("plain", plain.clone()), ("squashed", squashed.clone())] {
        let result = e
            .service
            .push_with_client(
                &client,
                &format!("localhost/{name}:v1"),
                &velarx_core::services::PushOptions {
                    destination: Some(format!("{host_b}/{name}:v1")),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        pushed.insert(id, result.digest);
    }
    // the layer of each as the registry has it (the layers are compressed
    // by the push)
    let pushed_layer = |id: &String| {
        let body = registry.blobs.lock().unwrap()[&format!("manifest:{}", pushed[id])].clone();
        let m: OciManifest = serde_json::from_slice(&body).unwrap();
        m.layers.last().unwrap().clone()
    };

    let mut expected = VerityHasher::new(velarx_types::digest::Algorithm::Sha256);
    expected.update(b"head");
    expected.update_zeros(SIZE - 7);
    expected.update(b"end");
    let object = expected.finish();
    let in_store = e.store.get_path(&object).expect("the file is in the store");
    let stored = std::fs::metadata(in_store).unwrap();
    assert_eq!(stored.len(), SIZE);
    if has_holes {
        assert!(
            stored.blocks() * 512 < SIZE / 2,
            "{} blocks",
            stored.blocks()
        );
    }

    let layer_of = |id: String| {
        let service = &e.service;
        async move {
            let image = service.get(&id).await.unwrap();
            let m: OciManifest = serde_json::from_str(&image.manifest).unwrap();
            m.layers.last().unwrap().digest
        }
    };
    let plain_layer = layer_of(plain.clone()).await;
    for id in [plain.clone(), squashed] {
        let image = e.service.get(&id).await.unwrap();
        let m: OciManifest = serde_json::from_str(&image.manifest).unwrap();
        let layer = m.layers.last().unwrap();
        let tar = layer_tar(&e, &layer.digest).await;
        let mut ar = tar::Archive::new(&tar[..]);
        let mut found = false;
        for entry in ar.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().to_string_lossy() != "./app/sparse" {
                continue;
            }
            found = true;
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            assert_eq!(data.len() as u64, SIZE);
            assert_eq!(&data[..4], b"head");
            assert_eq!(&data[SIZE as usize - 3..], b"end");
            assert!(data[4..SIZE as usize - 3].iter().all(|&b| b == 0));
        }
        assert!(found);
        // the table of contents of the blob, as the registry has it
        let layer = pushed_layer(&id);
        let blob = registry.blobs.lock().unwrap()[&layer.digest.to_string()].clone();
        let position = &layer.annotations["io.github.containers.zstd-chunked.manifest-position"];
        let [offset, length]: [usize; 2] = {
            let v: Vec<usize> = position
                .split(':')
                .take(2)
                .map(|n| n.parse().unwrap())
                .collect();
            [v[0], v[1]]
        };
        let toc: Toc =
            serde_json::from_slice(&zstd::decode_all(&blob[offset..offset + length]).unwrap())
                .unwrap();
        let chunks = toc.get_file_chunks("./app/sparse");
        assert_eq!(chunks.iter().filter(|c| c.is_zeros_chunk()).count(), 1);
        assert_eq!(
            toc.find_by_name("./app/sparse")
                .unwrap()
                .verity()
                .as_deref(),
            Some(object.as_str())
        );
    }

    // the same bytes written as data, with the same time: the same layer
    let mtime = std::fs::metadata(&holes).unwrap().modified().unwrap();
    let mut dense = vec![0u8; SIZE as usize];
    dense[..4].copy_from_slice(b"head");
    dense[SIZE as usize - 3..].copy_from_slice(b"end");
    std::fs::write(&holes, &dense).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&holes)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    assert!(std::fs::metadata(&holes).unwrap().blocks() * 512 >= SIZE);
    let rewritten = e
        .service
        .commit_dir(Some(&parent.id), Some(dir.path()), &options(&["plain:v2"]))
        .await
        .unwrap();
    assert_eq!(layer_of(rewritten).await, plain_layer);
}

/// A layer made here is the canonical tar of its table of contents: pushed as
/// zstd:chunked it is a blob of version 2 with no tar-split, whose tar any
/// reader of zstd has (its diff id is the digest of the tar), and which an
/// engine pulls, eagerly or lazily, by its table alone, next to the layers of
/// version 1 of the same image.
#[tokio::test]
async fn test_a_layer_built_here_is_a_version_2_layer_to_every_reader() {
    use velarx_content::layer::writer::Compression;
    use velarx_core::services::PushOptions;
    use velarx_storage::{canonical, Toc};
    const PREFIX: &str = "io.github.containers.zstd-chunked.";
    let (host_b, b) = start_registry().await;
    let e = source_trusting(&[&host_b]).await;
    let dir = tempfile::tempdir().unwrap();
    changes(dir.path());
    let parent = e
        .service
        .get(&format!("{}/test:latest", e.host))
        .await
        .unwrap();
    e.service
        .commit_dir(Some(&parent.id), Some(dir.path()), &options(&["v2:v1"]))
        .await
        .unwrap();
    let client = client_for(&[&e.host, &host_b]);
    let pushed = e
        .service
        .push_with_client(
            &client,
            "localhost/v2:v1",
            &PushOptions {
                destination: Some(format!("{host_b}/v2:v1")),
                compression: Some(Compression::ZstdChunked),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    let body = b.blobs.lock().unwrap()[&format!("manifest:{}", pushed.digest)].clone();
    let manifest: OciManifest = serde_json::from_slice(&body).unwrap();
    let config: velarx_types::OciConfig =
        serde_json::from_str(&e.service.get("localhost/v2:v1").await.unwrap().config).unwrap();
    let layer = manifest.layers.last().unwrap();
    assert_eq!(layer.annotations[&format!("{PREFIX}version")], "2");
    assert!(!layer
        .annotations
        .contains_key(&format!("{PREFIX}tarsplit-position")));
    // (the layer under it, made by a v1 writer, has a tar-split and no version)
    let below = &manifest.layers[1];
    assert!(below
        .annotations
        .contains_key(&format!("{PREFIX}tarsplit-position")));
    assert!(!below.annotations.contains_key(&format!("{PREFIX}version")));

    // the blob is a zstd stream of the canonical tar, the diff id its digest
    let blob = b.blobs.lock().unwrap()[&layer.digest.to_string()].clone();
    let tar = zstd::decode_all(&blob[..]).unwrap();
    assert_eq!(&sha(&tar), config.rootfs.diff_ids.last().unwrap());
    canonical::validate_tar(&tar[..]).unwrap();
    let position: Vec<usize> = layer.annotations[&format!("{PREFIX}manifest-position")]
        .split(':')
        .map(|n| n.parse().unwrap())
        .collect();
    let toc: Toc = serde_json::from_slice(
        &zstd::decode_all(&blob[position[0]..position[0] + position[1]]).unwrap(),
    )
    .unwrap();
    assert!(toc.is_canonical() && toc.tar_split_digest.is_none());
    // GNU tar reads it as it reads any tar
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &blob).unwrap();
    if let Ok(out) = std::process::Command::new("tar")
        .args(["--zstd", "-tf"])
        .arg(file.path())
        .output()
    {
        if out.status.success() {
            let list = String::from_utf8_lossy(&out.stdout);
            assert!(list.lines().any(|l| l == "./app/new"), "{list}");
            assert!(
                out.stderr.is_empty(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    // the same tar, compressed another way
    for (compression, media) in [(Compression::Gzip, GZIP), (Compression::None, TAR)] {
        let result = e
            .service
            .push_with_client(
                &client,
                "localhost/v2:v1",
                &PushOptions {
                    destination: Some(format!("{host_b}/v2:other{}", media.len())),
                    compression: Some(compression),
                    ..PushOptions::default()
                },
            )
            .await
            .unwrap();
        let body = b.blobs.lock().unwrap()[&format!("manifest:{}", result.digest)].clone();
        let m: OciManifest = serde_json::from_slice(&body).unwrap();
        let blob = b.blobs.lock().unwrap()[&m.layers.last().unwrap().digest.to_string()].clone();
        let mut back = Vec::new();
        match compression {
            Compression::Gzip => {
                flate2::read::GzDecoder::new(&blob[..])
                    .read_to_end(&mut back)
                    .unwrap();
            }
            _ => back = blob,
        }
        assert_eq!(back, tar);
    }

    // pulled eagerly and lazily by an engine that has nothing of it: the
    // layer is a layer of its table of contents, with no tar-split, whose
    // stream is the tar
    let reference = format!("{host_b}/v2:v1");
    let client = client_for(&[&host_b]);
    for lazy in [false, true] {
        let other = env_with(velarx_config::PullConfig {
            lazy_window_files: 0,
            ..Default::default()
        })
        .await;
        other.trust(&[&host_b]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        if lazy {
            other
                .service
                .pull_lazy_with_client(&client, &reference, tx)
                .await
                .unwrap();
            other.service.complete_image(&reference).await.unwrap();
        } else {
            other
                .service
                .pull_with_client(&client, &reference, tx)
                .await
                .unwrap();
        }
        let key = velarx_db::LayerKey::Toc(
            layer.annotations[&format!("{PREFIX}manifest-checksum")]
                .parse()
                .unwrap(),
        );
        let record = other.db.get_layer(&key).await.unwrap();
        assert_eq!(record.status, "ready", "lazy: {lazy}");
        let stored: Toc = serde_json::from_str(record.toc.as_deref().unwrap()).unwrap();
        assert!(stored.is_canonical());
        let rows = other.db.get_layer_tarsplit(&key).await.unwrap();
        assert_eq!(rows, Some(Vec::new()), "no tar-split, lazy: {lazy}");
        // its stream is the tar of the image's diff id, the tar-split layer
        // below is as it was
        let diff = config.rootfs.diff_ids.last().unwrap();
        let stored = StoredLayer::load_expecting(&other.db, &key, Some(diff.alg()), Some(diff))
            .await
            .unwrap();
        let mut back = Vec::new();
        stored
            .verified_stream(other.store.clone())
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert_eq!(back, tar, "lazy: {lazy}");
        let below = velarx_db::LayerKey::Toc(
            manifest.layers[1].annotations[&format!("{PREFIX}manifest-checksum")]
                .parse()
                .unwrap(),
        );
        assert!(other
            .db
            .get_layer_tarsplit(&below)
            .await
            .unwrap()
            .is_some_and(|t| !t.is_empty()));
    }
}

/// What `--digest sha512` makes: every digest of the image is SHA-512 (the
/// image id has 128 digits and the merged EROFS is stated with SHA-512), a
/// commit on top of it follows it, and a sha512 layer on a sha256 parent is
/// a mixed image: each link its own algorithm, the inherited layers and diff
/// ids as they were, and no merged EROFS statement.
#[tokio::test]
async fn test_a_sha512_commit_has_only_sha512_digests_and_a_mixed_one_keeps_the_parents() {
    let e = source().await;
    let sha512 = |names: &[&str]| CommitOptions {
        digest: Some(Algorithm::Sha512),
        ..options(names)
    };
    let uniform = |image: &velarx_db::ImageRecord, alg: Algorithm| {
        let m: OciManifest = serde_json::from_str(&image.manifest).unwrap();
        let config: serde_json::Value = serde_json::from_str(&image.config).unwrap();
        assert_eq!(image.manifest_digest.alg(), alg);
        assert_eq!(
            image.manifest_digest,
            Digest::of(alg, image.manifest.as_bytes())
        );
        assert_eq!(m.config.digest, Digest::of(alg, image.config.as_bytes()));
        (m, config)
    };

    // an image of its own
    let dir = tempfile::tempdir().unwrap();
    changes(dir.path());
    let id = e
        .service
        .commit_dir(None, Some(dir.path()), &sha512(&["own512:v1"]))
        .await
        .unwrap();
    let image = e.service.get("localhost/own512:v1").await.unwrap();
    assert_eq!(id.len(), 128);
    assert_eq!(image.id, id);
    let (m, config) = uniform(&image, Algorithm::Sha512);
    assert_eq!(m.layers.len(), 1);
    let layer = &m.layers[0];
    assert_eq!(layer.digest.alg(), Algorithm::Sha512);
    let diff_ids = config["rootfs"]["diff_ids"].as_array().unwrap();
    assert!(diff_ids[0].as_str().unwrap().starts_with("sha512:"));
    let sealed = &m.annotations["composefs.merged.erofs.v1.fsverity-sha512-12"];
    assert_eq!(sealed.len(), 128, "{sealed}");
    assert!(!m
        .annotations
        .keys()
        .any(|k| k.ends_with("fsverity-sha256-12")));
    let tar = layer_tar(&e, &layer.digest).await;
    assert_eq!(
        diff_ids[0].as_str(),
        Some(Digest::of(Algorithm::Sha512, &tar).to_string().as_str())
    );
    assert!(e.store.contains(&velarx_storage::fsverity_digest_of(
        Algorithm::Sha512,
        b"changed\n"
    )));

    // a commit on top of it follows it, and an explicit sha256 on top of it is mixed
    let follow = e
        .service
        .commit_dir(Some(&id), Some(dir.path()), &options(&["follow:v1"]))
        .await
        .unwrap();
    assert_eq!(follow.len(), 128);
    let (m, _) = uniform(&e.service.get(&follow).await.unwrap(), Algorithm::Sha512);
    assert_eq!(m.layers.len(), 2);
    let down = e
        .service
        .commit_dir(
            Some(&id),
            Some(dir.path()),
            &CommitOptions {
                digest: Some(Algorithm::Sha256),
                ..options(&["down:v1"])
            },
        )
        .await
        .unwrap();
    assert_eq!(down.len(), 64);
    let (m, config) = uniform(&e.service.get(&down).await.unwrap(), Algorithm::Sha256);
    assert_eq!(m.layers[0].digest.alg(), Algorithm::Sha512);
    assert_eq!(m.layers[1].digest.alg(), Algorithm::Sha256);
    let ids: Vec<&str> = config["rootfs"]["diff_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap())
        .collect();
    assert!(
        ids[0].starts_with("sha512:") && ids[1].starts_with("sha256:"),
        "{ids:?}"
    );
    assert!(!m
        .annotations
        .keys()
        .any(|k| k.starts_with("composefs.merged")));

    // sha512 on a sha256 parent
    let parent = e
        .service
        .get(&format!("{}/test:latest", e.host))
        .await
        .unwrap();
    let pm: OciManifest = serde_json::from_str(&parent.manifest).unwrap();
    let pc: serde_json::Value = serde_json::from_str(&parent.config).unwrap();
    let mixed = e
        .service
        .commit_dir(Some(&parent.id), Some(dir.path()), &sha512(&["mixed:v1"]))
        .await
        .unwrap();
    assert_eq!(mixed.len(), 128);
    let image = e.service.get(&mixed).await.unwrap();
    let (m, config) = uniform(&image, Algorithm::Sha512);
    assert_eq!(m.layers.len(), 3);
    assert_eq!(m.layers[0].digest, pm.layers[0].digest);
    assert_eq!(m.layers[1].digest, pm.layers[1].digest);
    assert_eq!(m.layers[2].digest.alg(), Algorithm::Sha512);
    let ids = config["rootfs"]["diff_ids"].as_array().unwrap();
    assert_eq!(ids[..2], pc["rootfs"]["diff_ids"].as_array().unwrap()[..]);
    assert!(ids[2].as_str().unwrap().starts_with("sha512:"));
    assert!(
        !m.annotations
            .keys()
            .any(|k| k.starts_with("composefs.merged")),
        "a mixed image has no merged EROFS statement: {:?}",
        m.annotations
    );
    // the image can be committed on again, and still runs the chain
    let on = e
        .service
        .commit_dir(Some(&mixed), Some(dir.path()), &options(&["on:v1"]))
        .await
        .unwrap();
    assert_eq!(on.len(), 128);
    assert_eq!(e.staged_leftovers(), 0);
}

/// The diff id of layer `n` of an image.
fn config_diff_id(image: &velarx_db::ImageRecord, n: usize) -> String {
    let config: serde_json::Value = serde_json::from_str(&image.config).unwrap();
    config["rootfs"]["diff_ids"][n]
        .as_str()
        .unwrap()
        .to_string()
}

/// The layer a commit makes is stored uncompressed; the push compresses it
/// `zstd:chunked` unless another compression is asked, and the configuration
/// (its diff id, so the id of the image) is the same whatever is asked.
#[tokio::test]
async fn test_a_committed_layer_is_compressed_by_the_push_as_asked() {
    use velarx_content::layer::writer::Compression;
    use velarx_core::services::PushOptions;
    let (host_b, b) = start_registry().await;
    let e = source_trusting(&[&host_b]).await;
    let dir = tempfile::tempdir().unwrap();
    changes(dir.path());
    let parent = e
        .service
        .get(&format!("{}/test:latest", e.host))
        .await
        .unwrap();
    let id = e
        .service
        .commit_dir(Some(&parent.id), Some(dir.path()), &options(&["pushed:v1"]))
        .await
        .unwrap();
    let image = e.service.get("localhost/pushed:v1").await.unwrap();
    let local: OciManifest = serde_json::from_str(&image.manifest).unwrap();
    let config: velarx_types::OciConfig = serde_json::from_str(&image.config).unwrap();
    let top = local.layers.last().unwrap();
    assert_eq!(top.media_type, TAR);
    assert_eq!(&top.digest, config.rootfs.diff_ids.last().unwrap());
    assert_eq!(id, image.config_digest.hex());
    drop(parent);
    let client = client_for(&[&e.host, &host_b]);
    for (n, (asked, media)) in [
        (None, ZSTD),
        (Some(Compression::ZstdChunked), ZSTD),
        (Some(Compression::Gzip), GZIP),
        (Some(Compression::None), TAR),
    ]
    .into_iter()
    .enumerate()
    {
        let result = e
            .service
            .push_with_client(
                &client,
                "localhost/pushed:v1",
                &velarx_core::services::PushOptions {
                    destination: Some(format!("{host_b}/pushed:{n}")),
                    compression: asked,
                    ..PushOptions::default()
                },
            )
            .await
            .unwrap();
        let bytes = b
            .blobs
            .lock()
            .unwrap()
            .get(&format!("manifest:{}", result.digest))
            .cloned()
            .expect("the manifest pushed");
        let m: OciManifest = serde_json::from_slice(&bytes).unwrap();
        let layer = m.layers.last().unwrap();
        assert_eq!(layer.media_type, media, "{asked:?}");
        assert_eq!(m.config.digest, image.config_digest, "{asked:?}");
        if media == ZSTD {
            assert!(
                layer
                    .annotations
                    .contains_key("io.github.containers.zstd-chunked.manifest-checksum"),
                "the default is zstd:chunked"
            );
        } else if media == TAR {
            assert_eq!(&layer.digest, config.rootfs.diff_ids.last().unwrap());
        } else {
            assert!(!layer
                .annotations
                .contains_key("io.github.containers.zstd-chunked.manifest-checksum"));
        }
    }
}
