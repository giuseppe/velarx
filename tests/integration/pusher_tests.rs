// SPDX-License-Identifier: Apache-2.0
//! The registry as a pusher (`org.velarx.Pusher`): what the registry
//! fetcher process does for the objects of an image, over its socket, against
//! the in-tree registry.

use crate::common::*;
use std::fs::File;
use std::io::Write;
use velarx_content::fetcher::fetch_client::FetchConn;
use velarx_content::pusher::push::{EventKind, Have, Object, Role};
use velarx_proto::transfer::FailureClass;

const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// A connection to the registry fetcher whose pusher scope is the
/// repository `repo` of the registry at `host`.
async fn scoped(dir: &std::path::Path, host: &str, repo: &str) -> FetchConn {
    let origin = origin_for(dir, &conf_for(&[host]), &Default::default());
    let mut conn = origin.connect().await.unwrap();
    push_scope(
        &mut conn,
        &format!("{host}/{repo}"),
        &["origin".to_string()],
    )
    .await
    .unwrap();
    conn
}

fn object(body: &[u8], known_at: &[&str]) -> Object {
    Object {
        digest: sha(body).to_string(),
        size: body.len() as u64,
        media_type: "application/octet-stream".into(),
        role: Role::Layer,
        known_at: (!known_at.is_empty()).then(|| known_at.iter().map(|s| s.to_string()).collect()),
    }
}

fn file_of(body: &[u8]) -> File {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(body).unwrap();
    file
}

async fn probed(conn: &mut FetchConn, objects: &[Object]) -> Vec<Have> {
    let mut replies = conn.push_probe(objects).await.unwrap();
    let mut have = vec![Have::Unknown; objects.len()];
    while let Some((reply, _)) = replies.probed().await.unwrap() {
        have[reply.index as usize] = reply.have;
    }
    have
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_blob_is_present_linked_or_needed() {
    let (host, reg) = start_registry().await;
    let dir = tempfile::tempdir().unwrap();
    // `test` has what was published; `other` has one blob of its own
    let (there, elsewhere, nowhere) = (b"there".as_slice(), b"elsewhere".as_slice(), b"nowhere");
    reg.blobs
        .lock()
        .unwrap()
        .insert(sha(there).to_string(), there.to_vec());
    reg.blobs
        .lock()
        .unwrap()
        .insert(sha(elsewhere).to_string(), elsewhere.to_vec());
    let hidden = b"hidden".as_slice();
    reg.blobs
        .lock()
        .unwrap()
        .insert(sha(hidden).to_string(), hidden.to_vec());
    reg.repos
        .lock()
        .unwrap()
        .entry("other".into())
        .or_default()
        .extend([sha(elsewhere).to_string(), sha(hidden).to_string()]);
    let mut conn = scoped(dir.path(), &host, "mine").await;
    // (`mine` is not `test`: nothing is in it)
    let objects = [
        object(there, &[]),
        object(elsewhere, &["other"]),
        object(hidden, &["unknown"]),
        object(nowhere, &["other"]),
    ];
    assert_eq!(
        probed(&mut conn, &objects).await,
        [Have::Needed, Have::Linked, Have::Needed, Have::Needed]
    );
    assert_eq!(reg.logged("POST mine mount=true from=other"), 2);
    // (what was mounted is present now)
    assert_eq!(probed(&mut conn, &objects[1..2]).await, [Have::Present]);
    // `test` has what was published, and nothing is mounted for it
    let mut conn = scoped(dir.path(), &host, "test").await;
    assert_eq!(probed(&mut conn, &objects[..1]).await, [Have::Present]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_blobs_are_uploaded_and_a_wrong_digest_is_a_failure_of_that_object() {
    let (host, reg) = start_registry().await;
    let dir = tempfile::tempdir().unwrap();
    let mut conn = scoped(dir.path(), &host, "mine").await;
    let big = vec![7u8; 3 << 20];
    let mut wrong = object(b"declared", &[]);
    wrong.digest = sha(b"something else").to_string();
    let objects = [object(&big, &[]), wrong, object(b"small", &[])];
    let files = [file_of(&big), file_of(b"declared"), file_of(b"small")];
    let mut replies = conn
        .push_put(&objects, &files.iter().collect::<Vec<_>>())
        .await
        .unwrap();
    let mut placed = Vec::new();
    let mut failed = Vec::new();
    let mut sent = 0;
    while let Some((event, fds)) = replies.event().await.unwrap() {
        assert!(fds.is_empty());
        match event.kind {
            EventKind::Placed => placed.extend(event.objects),
            EventKind::Failed => failed.push((event.objects, event.failure.map(|f| f.class))),
            EventKind::Progress if event.objects == [0] => {
                assert!(event.bytes.unwrap() >= sent, "progress goes forward");
                sent = event.bytes.unwrap();
            }
            _ => {}
        }
    }
    drop(replies);
    assert_eq!(placed, [0, 2]);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].0, [1]);
    // (what the registry client says of a refused finalize is a failure of
    // the registry's, which carries a class: not a refusal of credentials)
    assert!(
        matches!(
            failed[0].1,
            Some(FailureClass::Transient | FailureClass::Failed | FailureClass::Invalid)
        ),
        "{:?}",
        failed[0].1
    );
    assert!(reg.has("mine", &sha(&big)));
    assert!(reg.has("mine", &sha(b"small")));
    assert!(!reg.has("mine", &sha(b"declared")));
    assert_eq!(reg.blobs.lock().unwrap()[&sha(&big).to_string()], big);
    // (what was put is present now)
    assert_eq!(
        probed(&mut conn, &[objects[0].clone(), objects[2].clone()]).await,
        [Have::Present, Have::Present]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_manifest_is_put_by_each_tag_and_a_sha512_one_by_its_digest_too() {
    use velarx_types::digest::{Algorithm, Digest};
    let (host, reg) = start_registry().await;
    let dir = tempfile::tempdir().unwrap();
    let mut conn = scoped(dir.path(), &host, "mine").await;
    let body = br#"{"schemaVersion":2,"layers":[]}"#;
    let manifest = |digest: Digest| Object {
        digest: digest.to_string(),
        size: body.len() as u64,
        media_type: MANIFEST.into(),
        role: Role::Manifest,
        known_at: None,
    };
    let d256 = Digest::of(Algorithm::Sha256, body);
    let names = ["v1".to_string(), "latest".to_string()];
    let reply = conn
        .push_commit(&manifest(d256), &names, &file_of(body))
        .await
        .unwrap();
    assert_eq!(reply.digest, d256.to_string());
    assert!(reply.placed.iter().all(|p| p.accepted));
    assert_eq!(
        reg.logged("PUT-MANIFEST mine"),
        2,
        "{:?}",
        reg.log.lock().unwrap()
    );
    // sha512 by a tag: the tag, then its digest
    let d512 = Digest::of(Algorithm::Sha512, body);
    let reply = conn
        .push_commit(&manifest(d512), &["t".to_string()], &file_of(body))
        .await
        .unwrap();
    assert_eq!(reply.digest, d512.to_string());
    assert!(reply.placed.iter().all(|p| p.accepted));
    let log = reg.log.lock().unwrap().clone();
    let puts: Vec<_> = log
        .iter()
        .filter(|l| l.starts_with("PUT-MANIFEST"))
        .collect();
    assert_eq!(puts.len(), 4);
    assert_eq!(puts[2], "PUT-MANIFEST mine t");
    assert_eq!(*puts[3], format!("PUT-MANIFEST mine {d512}"));
    let before = puts.len();
    conn.push_commit(&manifest(d256), &[], &file_of(body))
        .await
        .unwrap();
    assert_eq!(reg.logged("PUT-MANIFEST mine"), before + 1);
    // a manifest that is not the digest the call says is refused
    let e = conn
        .push_commit(&manifest(d256), &[], &file_of(b"{}  "))
        .await;
    assert!(e.is_err());
    conn.push_finish().await.unwrap();
}

/// registry:3 answers 201 to the mount of a blob by a sha512 and does not
/// link it (its HEAD says the blob is not there): the pusher looks for the
/// blob after such a mount, and does not say it linked it; a sha256 mount
/// is believed.  The registry here is a mock that behaves as registry 3.1.2
/// was measured to (a mount by sha512 answers 201 and a HEAD in the new
/// repository 404): this shows the code path, not the registry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_sha512_mount_a_registry_answers_but_did_not_make_is_not_linked() {
    use axum::http::StatusCode;
    use axum::routing::{get, head, post};
    use velarx_types::digest::{Algorithm, Digest};
    let app = axum::Router::new()
        .route("/v2/", get(|| async { "{}" }))
        .route(
            "/v2/r/blobs/uploads/",
            post(|| async { StatusCode::CREATED }),
        )
        .route(
            "/v2/r/blobs/:digest",
            head(|| async { StatusCode::NOT_FOUND }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let mut conn = scoped(dir.path(), &host, "r").await;
    let of = |alg| Object {
        digest: Digest::of(alg, b"blob").to_string(),
        size: 4,
        media_type: "application/octet-stream".into(),
        role: Role::Layer,
        known_at: Some(vec!["other".into()]),
    };
    // (a sha256 mount is believed, as registries make it; its HEAD would say
    // the blob is not there, and is not asked)
    assert_eq!(
        probed(&mut conn, &[of(Algorithm::Sha256), of(Algorithm::Sha512)]).await,
        [Have::Linked, Have::Needed]
    );
}
