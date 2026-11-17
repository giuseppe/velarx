// SPDX-License-Identifier: Apache-2.0
//! Manifest lists of the store: create, add images of the store, annotate,
//! remove an instance, names, delete; and the push of a list to a registry.

use crate::common::*;
use std::collections::BTreeMap;
use velarx_core::services::{AddOptions, ListPushOptions};
use velarx_wire::wire::InstanceOptions;

const ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

async fn source() -> Env {
    let e = env().await;
    let layer = build_chunked(&[Item::File {
        name: "etc/hello",
        data: b"hello\n".to_vec(),
        chunk: 4096,
    }]);
    e.publish(&[&layer], &[ZSTD]);
    e.pull().await.unwrap();
    e
}

/// Changes of one list at once all stay: each reads the list, changes it
/// and writes it back only if it is still what it read.
#[tokio::test]
async fn test_changes_of_one_list_at_once_are_all_kept() {
    let e = env().await;
    let mut locals = Vec::new();
    for i in 0..8u8 {
        let layer = build_chunked(&[Item::File {
            name: "etc/hello",
            data: vec![i; 100],
            chunk: 4096,
        }]);
        e.publish(&[&layer], &[ZSTD]);
        let pulled = e.pull().await.unwrap();
        locals.push(format!("containers-storage:{}", pulled.id));
    }
    let svc = &e.service;
    let id = svc
        .manifest_create(
            "racing",
            &[],
            &AddOptions::default(),
            &BTreeMap::new(),
            false,
            None,
        )
        .await
        .unwrap();
    let adds: Vec<_> = locals
        .iter()
        .map(|local| {
            let svc = (**svc).clone();
            let local = local.clone();
            tokio::spawn(async move {
                svc.manifest_add("racing", &[local], &AddOptions::default())
                    .await
            })
        })
        .collect();
    for a in adds {
        a.await.unwrap().unwrap();
    }
    let list = svc.manifest_lookup("racing").await.unwrap().unwrap();
    assert_eq!(list.id, id);
    assert_eq!(list.instances().len(), locals.len(), "{:?}", list.index);
    // annotations of the index and removals at once too
    let digests: Vec<String> = list
        .instances()
        .iter()
        .map(|m| m["digest"].as_str().unwrap().to_string())
        .collect();
    let mut changes = Vec::new();
    for (i, d) in digests.iter().enumerate() {
        let svc = (**svc).clone();
        let d = d.clone();
        changes.push(tokio::spawn(async move {
            if i % 2 == 0 {
                svc.manifest_remove_instance("racing", &d).await
            } else {
                let notes = [(format!("k{i}"), "v".to_string())].into();
                svc.manifest_annotate("racing", None, &InstanceOptions::default(), &notes, None)
                    .await
            }
        }));
    }
    for c in changes {
        c.await.unwrap().unwrap();
    }
    let list = svc.manifest_lookup("racing").await.unwrap().unwrap();
    assert_eq!(list.instances().len(), digests.len() / 2);
    assert_eq!(list.index["annotations"].as_object().unwrap().len(), 4);
}

#[tokio::test]
async fn test_a_list_of_images_of_the_store() {
    let e = source().await;
    let svc = &e.service;
    let image = svc.get(&format!("{}/test:latest", e.host)).await.unwrap();
    let local = format!("containers-storage:{}", image.id);

    let id = svc
        .manifest_create(
            "mlist",
            &[],
            &AddOptions::default(),
            &BTreeMap::new(),
            false,
            None,
        )
        .await
        .unwrap();
    assert_eq!(id.len(), 64);
    // A name is the list's, an existing one is refused unless amended.
    assert!(svc
        .manifest_create(
            "mlist",
            &[],
            &AddOptions::default(),
            &BTreeMap::new(),
            false,
            None,
        )
        .await
        .is_err());
    let again = svc
        .manifest_create(
            "mlist",
            &[],
            &AddOptions::default(),
            &BTreeMap::new(),
            true,
            None,
        )
        .await
        .unwrap();
    assert_eq!(again, id);
    for name in [
        "mlist",
        "localhost/mlist",
        "localhost/mlist:latest",
        &id[..12],
        &id,
    ] {
        assert_eq!(
            svc.manifest_lookup(name).await.unwrap().map(|l| l.id),
            Some(id.clone()),
            "{name}"
        );
    }

    let add = AddOptions {
        instance: InstanceOptions {
            arch: Some("arm64".into()),
            annotations: [("k".to_string(), "v".to_string())].into(),
            ..Default::default()
        },
        ..AddOptions::default()
    };
    svc.manifest_add("mlist", std::slice::from_ref(&local), &add)
        .await
        .unwrap();
    // The same image again replaces its instance.
    svc.manifest_add("mlist", std::slice::from_ref(&local), &add)
        .await
        .unwrap();
    let list = svc.manifest_lookup("mlist").await.unwrap().unwrap();
    assert_eq!(list.instances().len(), 1);
    let entry = &list.instances()[0];
    assert_eq!(entry["digest"], image.manifest_digest.to_string());
    assert_eq!(entry["size"], image.manifest.len());
    assert_eq!(entry["platform"]["architecture"], "arm64");
    assert_eq!(entry["annotations"]["k"], "v");

    let opts = InstanceOptions {
        variant: Some("v8".into()),
        ..Default::default()
    };
    svc.manifest_annotate(
        "mlist",
        Some(&image.manifest_digest.to_string()),
        &opts,
        &[("top".to_string(), "x".to_string())].into(),
        None,
    )
    .await
    .unwrap();
    let list = svc.manifest_lookup("mlist").await.unwrap().unwrap();
    assert_eq!(list.instances()[0]["platform"]["variant"], "v8");
    assert_eq!(list.index["annotations"]["top"], "x");

    svc.manifest_tag("mlist", "other:v1").await.unwrap();
    let list = svc.manifest_lookup("other:v1").await.unwrap().unwrap();
    assert_eq!(list.id, id);
    assert_eq!(list.names.len(), 2);

    // Push: the instance by its digest, then the index.
    let digest = svc
        .manifest_push(
            "mlist",
            &format!("{}/pushed:list", e.host),
            &ListPushOptions {
                tls_verify: false,
                ..ListPushOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(digest.alg(), Algorithm::Sha256);

    svc.manifest_remove_instance("mlist", &image.manifest_digest.to_string())
        .await
        .unwrap();
    assert!(svc
        .manifest_remove_instance("mlist", &image.manifest_digest.to_string())
        .await
        .is_err());
    let (deleted, names) = svc.manifest_delete("mlist").await.unwrap();
    assert_eq!(deleted, id);
    assert_eq!(names.len(), 2);
    assert!(svc.manifest_lookup("mlist").await.unwrap().is_none());
    assert!(svc.get(&image.id).await.is_ok());
}

#[tokio::test]
async fn test_images_and_lists_do_not_share_a_name() {
    let e = source().await;
    let svc = &e.service;
    let image = svc.get(&format!("{}/test:latest", e.host)).await.unwrap();
    svc.tag(&image.id, "localhost/shared:latest").await.unwrap();
    svc.manifest_create(
        "shared",
        &[],
        &AddOptions::default(),
        &BTreeMap::new(),
        false,
        None,
    )
    .await
    .unwrap();
    // The list took the name from the image.
    assert!(svc.get("localhost/shared:latest").await.is_err());
    svc.tag(&image.id, "localhost/shared:latest").await.unwrap();
    assert!(svc.manifest_lookup("shared").await.unwrap().is_none());
    assert!(svc.get("localhost/shared:latest").await.is_ok());
}

/// `manifest create --digest sha512`: the digest of the list is SHA-512 and
/// stays so through the changes of the list; an existing list of the other
/// algorithm is refused when one is asked for, and used when none is.
#[tokio::test]
async fn test_a_manifest_list_with_sha512_digest() {
    use velarx_types::digest::{Algorithm, Digest};
    let e = env().await;
    let svc = &e.service;
    let id = svc
        .manifest_create(
            "big",
            &[],
            &AddOptions::default(),
            &BTreeMap::new(),
            false,
            Some("sha512"),
        )
        .await
        .unwrap();
    let list = svc.manifest_lookup("big").await.unwrap().unwrap();
    assert_eq!(list.alg, Algorithm::Sha512);
    assert_eq!(
        list.digest,
        Digest::of(Algorithm::Sha512, &serde_json::to_vec(&list.index).unwrap())
    );
    // the algorithm is no part of the index
    assert!(list.index.get("io.velarx.digest").is_none());
    // a change keeps it
    svc.manifest_annotate(
        "big",
        None,
        &InstanceOptions::default(),
        &BTreeMap::from([("k".to_string(), "v".to_string())]),
        None,
    )
    .await
    .unwrap();
    let again = svc.manifest_lookup(&id).await.unwrap().unwrap();
    assert_eq!(again.alg, Algorithm::Sha512);
    // an existing list: the other algorithm is refused by name, none asked is fine
    let e1 = svc
        .manifest_create(
            "big",
            &[],
            &AddOptions::default(),
            &BTreeMap::new(),
            true,
            Some("sha256"),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(e1.contains("has sha512 digests, not sha256"), "{e1}");
    let same = svc
        .manifest_create(
            "big",
            &[],
            &AddOptions::default(),
            &BTreeMap::new(),
            true,
            None,
        )
        .await
        .unwrap();
    assert_eq!(same, id);
    svc.manifest_create(
        "small",
        &[],
        &AddOptions::default(),
        &BTreeMap::new(),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        svc.manifest_lookup("small").await.unwrap().unwrap().alg,
        Algorithm::Sha256
    );
    let e2 = svc
        .manifest_create(
            "bad",
            &[],
            &AddOptions::default(),
            &BTreeMap::new(),
            false,
            Some("sha1"),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(e2.contains("unknown digest algorithm `sha1`"), "{e2}");
}

/// The file of an artifact is copied into the list as it is hashed: the
/// blob named by its digest is the content that was hashed, whatever the
/// caller writes to its own file after the add, and the caller's file is
/// not taken from it.
#[tokio::test]
async fn test_an_artifact_blob_is_the_content_its_digest_names() {
    use std::io::Write;
    let e = env().await;
    let svc = &e.service;
    svc.manifest_create(
        "arts",
        &[],
        &AddOptions::default(),
        &BTreeMap::new(),
        false,
        None,
    )
    .await
    .unwrap();
    // (on the file system of the store: a rename into the list would work)
    let file = e._tmp.path().join("payload.txt");
    std::fs::write(&file, b"what the caller had\n").unwrap();
    let mut writer = std::fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .unwrap();
    svc.manifest_add_artifact(
        "arts",
        &[("payload.txt".to_string(), file.clone())],
        &velarx_core::services::ArtifactOptions::default(),
        &InstanceOptions::default(),
        false,
        &velarx_registry::auth::RegistryAccess::default(),
    )
    .await
    .unwrap();
    assert!(file.exists(), "the caller's file stays its own");
    writer.write_all(b"written after the add\n").unwrap();
    let hex = velarx_types::digest::Digest::of(
        velarx_types::digest::Algorithm::Sha256,
        b"what the caller had\n",
    )
    .hex();
    let mut found = Vec::new();
    let mut todo = vec![e._tmp.path().to_path_buf()];
    while let Some(dir) = todo.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            if entry.file_type().unwrap().is_dir() {
                todo.push(entry.path());
            } else if entry.file_name().to_string_lossy() == hex {
                found.push(entry.path());
            }
        }
    }
    let [blob] = found.as_slice() else {
        panic!("one blob named by the digest: {found:?}");
    };
    assert_eq!(std::fs::read(blob).unwrap(), b"what the caller had\n");
}
