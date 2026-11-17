// SPDX-License-Identifier: Apache-2.0
//! What registries.conf says about a pull: mirrors, short names, aliases and
//! search registries, and the platform of an index.

use crate::common::*;
use std::sync::atomic::Ordering;

fn layer() -> Built {
    build_gzip(&[
        Item::Dir("etc/"),
        Item::File {
            name: "etc/hello",
            data: b"hello\n".to_vec(),
            chunk: 4096,
        },
    ])
}

fn blob_requests(r: &Registry) -> usize {
    r.requests.load(Ordering::SeqCst)
}

fn insecure(host: &str) -> String {
    format!("[[registry]]\nprefix = \"{host}\"\ninsecure = true\n")
}

#[tokio::test]
async fn test_a_mirror_is_asked_first() {
    let (primary, a) = start_registry().await;
    let (mirror, m) = start_registry().await;
    let l = layer();
    publish_to(&a, &[&l], &[GZIP]);
    publish_to(&m, &[&l], &[GZIP]);
    let conf = format!(
        "[[registry]]\nprefix = \"{primary}\"\ninsecure = true\n[[registry.mirror]]\nlocation = \"{mirror}\"\ninsecure = true\n"
    );
    let s = side_with(Some(&conf)).await;
    s.pull_ref(&format!("{primary}/test:latest"), None)
        .await
        .unwrap();
    assert!(blob_requests(&m) > 0);
    assert_eq!(blob_requests(&a), 0);
    assert!(s.store.contains(&vid(b"hello\n")));
}

/// Where credentials may go: the mirrors and the registry of a pull, the
/// registry alone of a push, nothing else.
#[tokio::test]
async fn test_the_credentials_of_a_reference_go_to_its_mirrors_and_registry() {
    let (primary, _a) = start_registry().await;
    let (mirror, _m) = start_registry().await;
    let conf = format!(
        "[[registry]]\nprefix = \"{primary}\"\ninsecure = true\n[[registry.mirror]]\nlocation = \"{mirror}\"\ninsecure = true\n"
    );
    let s = side_with(Some(&conf)).await;
    let reference = format!("{primary}/ns/test:latest");
    let mut pull = s
        .service
        .reference_credential_scopes(&reference, false)
        .unwrap();
    pull.sort();
    let mut want = vec![format!("{primary}/ns/test"), format!("{mirror}/ns/test")];
    want.sort();
    assert_eq!(pull, want);
    assert_eq!(
        s.service
            .reference_credential_scopes(&reference, true)
            .unwrap(),
        [format!("{primary}/ns/test")]
    );
}

/// The scopes follow the rewrites of registries.conf: a `prefix` with a
/// `location` elsewhere, and a mirror only for references by digest.
#[tokio::test]
async fn test_the_credential_scopes_follow_rewrites_and_digest_only_mirrors() {
    let (primary, _a) = start_registry().await;
    let (mirror, _m) = start_registry().await;
    let conf = format!(
        "[[registry]]\nprefix = \"rewritten.example/team\"\nlocation = \"{primary}/elsewhere\"\ninsecure = true\n\
         [[registry.mirror]]\nlocation = \"{mirror}/m\"\ninsecure = true\npull-from-mirror = \"digest-only\"\n"
    );
    let s = side_with(Some(&conf)).await;
    let scopes = |r: &str| {
        let mut v = s.service.reference_credential_scopes(r, false).unwrap();
        v.sort();
        v
    };
    // by tag: the rewritten registry alone, not the digest-only mirror
    assert_eq!(
        scopes("rewritten.example/team/app:latest"),
        [format!("{primary}/elsewhere/app")]
    );
    // by digest: the mirror as well
    let digest = format!("sha256:{}", "a".repeat(64));
    let mut want = vec![
        format!("{primary}/elsewhere/app"),
        format!("{mirror}/m/app"),
    ];
    want.sort();
    assert_eq!(
        scopes(&format!("rewritten.example/team/app@{digest}")),
        want
    );
    // never the name that was written
    assert!(scopes("rewritten.example/team/app:latest")
        .iter()
        .all(|s| !s.starts_with("rewritten.example")));
}

#[tokio::test]
async fn test_a_mirror_without_the_image_falls_back_to_the_registry() {
    let (primary, a) = start_registry().await;
    let (mirror, m) = start_registry().await;
    publish_to(&a, &[&layer()], &[GZIP]);
    let conf = format!(
        "[[registry]]\nprefix = \"{primary}\"\ninsecure = true\n[[registry.mirror]]\nlocation = \"{mirror}\"\ninsecure = true\n"
    );
    let s = side_with(Some(&conf)).await;
    s.pull_ref(&format!("{primary}/test:latest"), None)
        .await
        .unwrap();
    // The mirror was asked and answered 404.
    assert!(blob_requests(&m) > 0);
    assert!(blob_requests(&a) > 0);
    // A mirror that is not there at all is no obstacle either.
    let conf = format!(
        "[[registry]]\nprefix = \"{primary}\"\ninsecure = true\n[[registry.mirror]]\nlocation = \"127.0.0.1:1\"\ninsecure = true\n"
    );
    let s = side_with(Some(&conf)).await;
    s.pull_ref(&format!("{primary}/test:latest"), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_pull_from_mirror_digest_only() {
    let (primary, a) = start_registry().await;
    let (mirror, m) = start_registry().await;
    let l = layer();
    let digest = publish_to(&a, &[&l], &[GZIP]);
    publish_to(&m, &[&l], &[GZIP]);
    let conf = format!(
        "[[registry]]\nprefix = \"{primary}\"\ninsecure = true\npull-from-mirror = \"digest-only\"\n[[registry.mirror]]\nlocation = \"{mirror}\"\ninsecure = true\n"
    );
    let s = side_with(Some(&conf)).await;
    s.pull_ref(&format!("{primary}/test:latest"), None)
        .await
        .unwrap();
    assert!(blob_requests(&a) > 0);
    assert_eq!(blob_requests(&m), 0);
    let before = blob_requests(&a);
    let s = side_with(Some(&conf)).await;
    s.pull_ref(&format!("{primary}/test@{digest}"), None)
        .await
        .unwrap();
    assert!(blob_requests(&m) > 0);
    assert_eq!(blob_requests(&a), before);
}

#[tokio::test]
async fn test_a_mirror_that_lies_is_caught_by_the_digests() {
    let (primary, a) = start_registry().await;
    let (mirror, m) = start_registry().await;
    let l = layer();
    publish_to(&a, &[&l], &[GZIP]);
    publish_to(&m, &[&l], &[GZIP]);
    // The mirror serves other bytes under the digest of the layer.
    m.blobs.lock().unwrap().insert(
        sha(&l.blob).to_string(),
        build_gzip(&[Item::Dir("evil/")]).blob,
    );
    let conf = format!(
        "[[registry]]\nprefix = \"{primary}\"\ninsecure = true\n[[registry.mirror]]\nlocation = \"{mirror}\"\ninsecure = true\n"
    );
    let s = side_with(Some(&conf)).await;
    assert!(s
        .pull_ref(&format!("{primary}/test:latest"), None)
        .await
        .is_err());
    assert!(s.db.list_images().await.unwrap().is_empty());
    assert!(!s.store.contains(&vid(b"hello\n")));
}

#[tokio::test]
async fn test_short_names_aliases_and_search_registries() {
    let (first, a) = start_registry().await;
    let (second, b) = start_registry().await;
    publish_to(&b, &[&layer()], &[GZIP]);
    // The first search registry does not have it, the second does.
    let conf = format!(
        "unqualified-search-registries = [\"{first}\", \"{second}\"]\n{}{}",
        insecure(&first),
        insecure(&second)
    );
    let s = side_with(Some(&conf)).await;
    s.pull_ref("test:latest", None).await.unwrap();
    assert_eq!(blob_requests(&a), 0);
    assert!(blob_requests(&b) > 0);
    // The image is known by the name it was pulled as, and by the short name.
    assert!(s
        .service
        .get(&format!("{second}/test:latest"))
        .await
        .is_ok());
    assert!(s.service.get("test").await.is_ok());

    // An alias wins over the search.
    let conf = format!(
        "unqualified-search-registries = [\"{first}\"]\n[aliases]\n\"myimg\" = \"{second}/test\"\n{}{}",
        insecure(&first),
        insecure(&second)
    );
    let s = side_with(Some(&conf)).await;
    s.pull_ref("myimg:latest", None).await.unwrap();
    assert!(s
        .service
        .get(&format!("{second}/test:latest"))
        .await
        .is_ok());

    // Nothing has it: one candidate, its own error.
    let s = side_with(Some(&conf)).await;
    assert!(s.pull_ref("unknown:1", None).await.is_err());
}

/// containers/image goes on to the next registry whatever the failure of the
/// first was, and says what each one answered when none works.
#[tokio::test]
async fn test_a_search_registry_that_is_down_is_skipped() {
    // (a port nobody listens on)
    let down = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("127.0.0.1:{}", l.local_addr().unwrap().port())
    };
    let (second, b) = start_registry().await;
    publish_to(&b, &[&layer()], &[GZIP]);
    let conf = format!(
        "unqualified-search-registries = [\"{down}\", \"{second}\"]\n{}{}",
        insecure(&down),
        insecure(&second)
    );
    let s = side_with(Some(&conf)).await;
    s.pull_ref("test:latest", None).await.unwrap();
    assert!(blob_requests(&b) > 0);
    assert!(s.service.get("test").await.is_ok());
}

#[tokio::test]
async fn test_every_candidate_is_named_when_none_has_the_image() {
    let (first, a) = start_registry().await;
    let (second, b) = start_registry().await;
    let conf = format!(
        "unqualified-search-registries = [\"{first}\", \"{second}\"]\n{}{}",
        insecure(&first),
        insecure(&second)
    );
    let s = side_with(Some(&conf)).await;
    let err = s.pull_ref("nothing:1", None).await.unwrap_err().to_string();
    assert!(err.contains("2 tried"), "{err}");
    assert!(err.contains(&format!("{first}/nothing:1")), "{err}");
    assert!(err.contains(&format!("{second}/nothing:1")), "{err}");
    assert_eq!(blob_requests(&a) + blob_requests(&b), 0);
    // one candidate: its error alone
    let conf = format!(
        "unqualified-search-registries = [\"{first}\"]\n{}",
        insecure(&first)
    );
    let s = side_with(Some(&conf)).await;
    let err = s.pull_ref("nothing:1", None).await.unwrap_err().to_string();
    assert!(!err.contains("tried"), "{err}");
}

#[tokio::test]
async fn test_enforcing_mode_refuses_an_ambiguous_short_name() {
    let (first, _a) = start_registry().await;
    let (second, b) = start_registry().await;
    publish_to(&b, &[&layer()], &[GZIP]);
    let conf = format!(
        "short-name-mode = \"enforcing\"\nunqualified-search-registries = [\"{first}\", \"{second}\"]\n{}{}",
        insecure(&first),
        insecure(&second)
    );
    let s = side_with(Some(&conf)).await;
    let err = s.pull_ref("test:latest", None).await.unwrap_err();
    assert!(err.to_string().contains("ambiguous"), "{err}");
    assert!(err.to_string().contains("without a TTY"), "{err}");
    s.pull_ref(&format!("{second}/test:latest"), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_platform_selects_the_instance_of_an_index() {
    let (host, r) = start_registry().await;
    let amd = build_gzip(&[Item::Dir("amd/")]);
    let arm = build_gzip(&[Item::Dir("arm/")]);
    let d_amd = publish_arch(&r, &[&amd], &[GZIP], "amd64", "*");
    let d_arm = publish_arch(&r, &[&arm], &[GZIP], "arm64", "*");
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": d_amd, "size": 1,
             "platform": {"os": "linux", "architecture": "amd64"}},
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": d_arm, "size": 1,
             "platform": {"os": "linux", "architecture": "arm64"}},
        ]
    })
    .to_string();
    r.blobs
        .lock()
        .unwrap()
        .insert("manifest:latest".into(), index.into_bytes());
    let conf = insecure(&host);
    let image = format!("{host}/test:latest");

    let s = side_with(Some(&conf)).await;
    s.pull_ref(&image, Some("linux/arm64")).await.unwrap();
    assert!(s.db.get_image_by_digest(&d_arm).await.is_ok());
    assert!(s.db.get_image_by_digest(&d_amd).await.is_err());

    let s = side_with(Some(&conf)).await;
    s.pull_ref(&image, Some("amd64")).await.unwrap();
    assert!(s.db.get_image_by_digest(&d_amd).await.is_ok());

    for bad in ["linux/s390x", "windows/amd64", "linux//"] {
        let s = side_with(Some(&conf)).await;
        assert!(s.pull_ref(&image, Some(bad)).await.is_err(), "{bad}");
    }

    // A single manifest for another platform is taken, as podman takes it
    // (with its warning, in the progress of the pull).
    publish_arch(&r, &[&amd], &[GZIP], "amd64", "single");
    let s = side_with(Some(&conf)).await;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<velarx_core::services::TransferProgress>(64);
    let said = tokio::spawn(async move {
        let mut said = Vec::new();
        while let Some(p) = rx.recv().await {
            said.push(p.status);
        }
        said
    });
    s.service
        .pull_with(
            &format!("{host}/test:single"),
            false,
            &velarx_core::services::PullOptions {
                tls_verify: true,
                platform: Some("linux/arm64".into()),
                ..Default::default()
            },
            tx,
        )
        .await
        .unwrap();
    let said = said.await.unwrap();
    assert!(
        said.iter().any(|s| s
            == "warning: image platform (linux/amd64) does not match the expected platform (linux/arm64)"),
        "{said:?}"
    );
    s.pull_ref(&format!("{host}/test:single"), Some("linux/amd64"))
        .await
        .unwrap();
}
