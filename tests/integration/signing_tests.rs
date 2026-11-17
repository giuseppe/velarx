// SPDX-License-Identifier: Apache-2.0
//! Signed pushes: the sigstore attachment a push writes, pulled back under a
//! sigstoreSigned policy; a tampered manifest, an unsigned push and a push
//! with nowhere to put the signature; the instances and the index of a list.

use crate::common::*;
use std::sync::Arc;
use velarx_config::PullConfig;
use velarx_core::services::{AddOptions, ListPushOptions, PushOptions, SignatureJudging};
use velarx_signature::sign::{KeyFiles, Signer};
use velarx_signature::sigstore::{self, TrustRoot};
use velarx_types::OciManifest;

/// A key made by `skopeo generate-sigstore-key` with the passphrase `secret`.
const KEY: &str = "-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----
eyJrZGYiOnsibmFtZSI6InNjcnlwdCIsInBhcmFtcyI6eyJOIjo2NTUzNiwiciI6
OCwicCI6MX0sInNhbHQiOiJ2V1pEcTlQNUFLemZ0V0JhYjBhZzlCY1BHM2cva3ht
RGZSdUhNNG5MdUlZPSJ9LCJjaXBoZXIiOnsibmFtZSI6Im5hY2wvc2VjcmV0Ym94
Iiwibm9uY2UiOiJnSlJ5MjJJYzRrNUdYS0pmT1JUVGFtb0JFQi9aNU0vZiJ9LCJj
aXBoZXJ0ZXh0IjoiRzk3ZWZTUXhjQlNBdEFWOUQ3VXZmOGdKckw0a1pNTitSMnBi
T2lydUNLTVB4VlZ6OFlNUW0wOThIamNqMEZnVCsyZnBVOU5zT012MDA5b0tQbnFt
ZUxrU1pLcnZ1N0QrQlZoMXFYRHBUcGx3N0VLWHNXRFZjNVVCWW1JSys1Vll6K1Jm
R3Qya25HZzQ3WXRUQXNKQVRnQ1dCYkprb3BLb0NNQzJHQlJpRGxVMk9YWEdGUTNk
WDdpbXJsR1pqUi9hQ1VMTXE2aGdsTGdXeFE9PSJ9
-----END ENCRYPTED COSIGN PRIVATE KEY-----
";
const PUBLIC: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjRMvLZLP+3IgpEbDgdtuZjXJ7pLb
QSGFaQFE7Zydj1mCzfDh04I5w3jAN/qNAPyq+1IDO890Q8MinNL9NNNEuQ==
-----END PUBLIC KEY-----
";

fn signer() -> Arc<Signer> {
    Arc::new(
        Signer::load(&KeyFiles {
            key: KEY.as_bytes().to_vec(),
            passphrase: b"secret".to_vec(),
        })
        .unwrap(),
    )
}

/// The configuration of a service that finds sigstore attachments and
/// requires the key's signature of `scope`: its directories, written by
/// `allow`.
struct Dirs {
    dir: tempfile::TempDir,
}

impl Dirs {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("registries.d")).unwrap();
        std::fs::write(dir.path().join("key.pub"), PUBLIC).unwrap();
        std::fs::write(
            dir.path().join("policy.json"),
            r#"{"default":[{"type":"insecureAcceptAnything"}]}"#,
        )
        .unwrap();
        Self { dir }
    }

    fn config(&self) -> PullConfig {
        PullConfig {
            policy_path: Some(self.dir.path().join("policy.json")),
            registries_d: Some(self.dir.path().join("registries.d")),
            ..PullConfig::default()
        }
    }

    /// Attachments are written and read for the registry `host`; its
    /// repository `repo` needs the signature of the key.
    fn allow(&self, host: &str, repo: &str) {
        std::fs::write(
            self.dir.path().join("registries.d/e.yaml"),
            format!("docker:\n  {host}:\n    use-sigstore-attachments: true\n"),
        )
        .unwrap();
        let key = self.dir.path().join("key.pub");
        std::fs::write(
            self.dir.path().join("policy.json"),
            serde_json::json!({
                "default": [{"type": "insecureAcceptAnything"}],
                "transports": {"docker": {
                    format!("{host}/{repo}"): [{"type": "sigstoreSigned", "keyPath": key}],
                }},
            })
            .to_string(),
        )
        .unwrap();
    }
}

fn tag_of(digest: &str) -> String {
    format!("manifest:{}.sig", digest.replacen(':', "-", 1))
}

/// The layers of the attachment manifest of `digest` in `reg`.
fn attachments(reg: &Registry, digest: &Digest) -> Option<OciManifest> {
    let body = reg
        .blobs
        .lock()
        .unwrap()
        .get(&tag_of(&digest.to_string()))?
        .clone();
    Some(serde_json::from_slice(&body).unwrap())
}

/// An engine with the policy of `dirs` that reads the registry `host` (its
/// fetcher has the registry configuration of the engine).
async fn reader_of(dirs: &Dirs, host: &str) -> Env {
    let client = client_for(&[host]);
    let reader = env_built(
        velarx_db::Database::open_in_memory().await.unwrap(),
        dirs.config(),
        Default::default(),
        Fetchers::default(),
        None,
        move |s| s.with_resolver(client),
    )
    .await;
    // (it pulls from `host`, through its fetcher)
    reader.trust(&[host]);
    reader
}

async fn pulled(host: &str, dirs: &Dirs, reference: &str) -> Result<(), velarx_types::ImageError> {
    let reader = reader_of(dirs, host).await;
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let result = reader
        .service
        .pull_with_client(&client_for(&[host]), reference, tx)
        .await;
    result.map(|_| ())
}

async fn source(dirs: &Dirs) -> Env {
    source_trusting(dirs, &[]).await
}

/// [`source`], its fetcher knowing the registries `hosts` too.
async fn source_trusting(dirs: &Dirs, hosts: &[&str]) -> Env {
    let a = env_with(dirs.config()).await;
    a.trust(hosts);
    a.publish(
        &[&build_gzip(&[Item::File {
            name: "etc/hello",
            data: b"hello\n".to_vec(),
            chunk: 4096,
        }])],
        &[GZIP],
    );
    a.pull().await.unwrap();
    a
}

#[tokio::test]
async fn test_a_signed_push_is_pulled_under_a_sigstore_policy() {
    let dirs = Dirs::new();
    let a = source(&dirs).await;
    dirs.allow(&a.host, "copy");
    let pushed = a
        .service
        .push_with_client(
            &a.client(),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{}/copy:v1", a.host)),
                sign: Some(signer()),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();

    // The attachment: one layer, the payload of the signature, which says
    // the digest and the name of the push
    let manifest = attachments(&a.reg, &pushed.digest).expect("a sigstore attachment");
    assert_eq!(manifest.layers.len(), 1);
    let layer = &manifest.layers[0];
    assert_eq!(layer.media_type, sigstore::SIGSTORE_MEDIA_TYPE);
    let payload = a
        .reg
        .blobs
        .lock()
        .unwrap()
        .get(&layer.digest.to_string())
        .cloned()
        .unwrap();
    let signature = sigstore::Sigstore {
        mime_type: layer.media_type.clone(),
        payload,
        annotations: layer.annotations.clone().into_iter().collect(),
    };
    let root = TrustRoot {
        public_keys: vec![sigstore::public_key_from_pem(PUBLIC.as_bytes()).unwrap()],
        ..Default::default()
    };
    let verified = root.verify(&signature, 0).unwrap();
    assert_eq!(verified.manifest_digest, pushed.digest.to_string());
    assert_eq!(verified.docker_reference, format!("{}/copy:v1", a.host));
    assert!(sigstore::manifest_matches(
        &a.reg.blobs.lock().unwrap()[&format!("manifest:{}", pushed.digest)],
        &verified.manifest_digest
    ));

    pulled(&a.host, &dirs, &format!("{}/copy:v1", a.host))
        .await
        .unwrap();

    let other = a
        .service
        .push_with_client(
            &a.client(),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{}/copy:v2", a.host)),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(other.digest, pushed.digest);
    let e = pulled(&a.host, &dirs, &format!("{}/copy:v2", a.host))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("Source image rejected"), "{e}");

    // An edited manifest is another manifest: no signature covers it
    let mut edited: serde_json::Value = serde_json::from_slice(
        &a.reg.blobs.lock().unwrap()[&format!("manifest:{}", pushed.digest)],
    )
    .unwrap();
    edited["annotations"] = serde_json::json!({"edited": "yes"});
    let edited = serde_json::to_vec(&edited).unwrap();
    {
        let mut blobs = a.reg.blobs.lock().unwrap();
        blobs.insert("manifest:v1".into(), edited.clone());
        blobs.insert(format!("manifest:{}", sha(&edited)), edited);
    }
    let e = pulled(&a.host, &dirs, &format!("{}/copy:v1", a.host))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("Source image rejected"), "{e}");

    let again = a
        .service
        .push_with_client(
            &a.client(),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{}/copy:v3", a.host)),
                sign: Some(signer()),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(again.digest, pushed.digest);
    assert_eq!(attachments(&a.reg, &pushed.digest).unwrap().layers.len(), 2);
}

#[tokio::test]
async fn test_a_signed_push_without_a_place_for_the_signature_fails_first() {
    let dirs = Dirs::new();
    // registries.d says nothing of the registry
    let (host_b, b) = start_registry().await;
    let a = source_trusting(&dirs, &[&host_b]).await;
    let e = a
        .service
        .push_with_client(
            &client_for(&[&a.host, &host_b]),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{host_b}/copy:v1")),
                sign: Some(signer()),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("no applicable signature storage"), "{e}");
    assert_eq!(b.logged("PUT-MANIFEST"), 0);
    assert_eq!(b.logged("PATCH"), 0);
}

#[tokio::test]
async fn test_a_signature_goes_to_the_staging_storage_of_the_signature_files() {
    let dirs = Dirs::new();
    let a = source(&dirs).await;
    let store = tempfile::tempdir().unwrap();
    std::fs::write(
        dirs.dir.path().join("registries.d/e.yaml"),
        format!(
            "docker:\n  {}:\n    lookaside-staging: file://{}\n",
            a.host,
            store.path().display()
        ),
    )
    .unwrap();
    let pushed = a
        .service
        .push_with_client(
            &a.client(),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{}/copy:v1", a.host)),
                sign: Some(signer()),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert!(attachments(&a.reg, &pushed.digest).is_none());
    let file = store.path().join(format!(
        "copy@{}/signature-1",
        pushed.digest.to_string().replacen(':', "=", 1)
    ));
    let blob = std::fs::read(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    let velarx_signature::sigstore::Signature::Sigstore(s) =
        velarx_signature::sigstore::Signature::from_blob(&blob).unwrap()
    else {
        panic!("not a sigstore signature");
    };
    let root = TrustRoot {
        public_keys: vec![sigstore::public_key_from_pem(PUBLIC.as_bytes()).unwrap()],
        ..Default::default()
    };
    assert_eq!(
        root.verify(&s, 0).unwrap().manifest_digest,
        pushed.digest.to_string()
    );
}

/// An http server of the files of `dir` (a lookaside storage): its
/// address and the requests it was asked.
async fn serve_files(dir: &std::path::Path) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (root, count) = (dir.to_path_buf(), asked.clone());
    let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
        let (root, count) = (root.clone(), count.clone());
        async move {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let rel = uri.path().trim_start_matches('/').to_string();
            match std::fs::read(root.join(rel)) {
                Ok(body) => (axum::http::StatusCode::OK, body),
                Err(_) => (axum::http::StatusCode::NOT_FOUND, Vec::new()),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr.to_string(), asked)
}

/// A signature in a lookaside storage over http is read by the registry
/// fetcher (the engine opens no connection for it) and satisfies the
/// policy; with none there, the pull is refused.
#[tokio::test]
async fn test_a_signature_of_a_lookaside_storage_over_http_is_read_by_the_fetcher() {
    let dirs = Dirs::new();
    let a = source(&dirs).await;
    let store = tempfile::tempdir().unwrap();
    let conf = dirs.dir.path().join("registries.d/e.yaml");
    std::fs::write(
        &conf,
        format!(
            "docker:\n  {}:\n    lookaside-staging: file://{}\n",
            a.host,
            store.path().display()
        ),
    )
    .unwrap();
    let pushed = a
        .service
        .push_with_client(
            &a.client(),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{}/copy:v1", a.host)),
                sign: Some(signer()),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert!(attachments(&a.reg, &pushed.digest).is_none());
    // the readers: the policy needs the key's signature, found over http
    dirs.allow(&a.host, "copy");
    let (server, asked) = serve_files(store.path()).await;
    std::fs::write(
        &conf,
        format!("docker:\n  {}:\n    lookaside: http://{server}\n", a.host),
    )
    .unwrap();
    let name = format!("{}/copy:v1", a.host);
    pulled(&a.host, &dirs, &name).await.unwrap();
    assert!(
        asked.load(std::sync::atomic::Ordering::SeqCst) >= 2,
        "signature-1 and the end"
    );
    // nothing there: refused
    std::fs::remove_dir_all(
        store
            .path()
            .join("copy@".to_string() + &pushed.digest.to_string().replacen(':', "=", 1)),
    )
    .unwrap();
    let e = pulled(&a.host, &dirs, &name).await.unwrap_err().to_string();
    assert!(e.contains("signature"), "{e}");
}

#[tokio::test]
async fn test_a_list_push_signs_the_instances_and_the_list_with_the_name_of_the_list() {
    let dirs = Dirs::new();
    let a = source(&dirs).await;
    dirs.allow(&a.host, "listed");
    let svc = &a.service;
    let image = svc.get(&format!("{}/test:latest", a.host)).await.unwrap();
    svc.manifest_create(
        "mlist",
        &[format!("containers-storage:{}", image.id)],
        &AddOptions::default(),
        &Default::default(),
        false,
        None,
    )
    .await
    .unwrap();
    let digest = svc
        .manifest_push(
            "mlist",
            &format!("{}/listed:v1", a.host),
            &ListPushOptions {
                tls_verify: false,
                sign: Some(signer()),
                ..ListPushOptions::default()
            },
        )
        .await
        .unwrap();
    let root = TrustRoot {
        public_keys: vec![sigstore::public_key_from_pem(PUBLIC.as_bytes()).unwrap()],
        ..Default::default()
    };
    let list = svc.manifest_lookup("mlist").await.unwrap().unwrap();
    let mut signed = vec![digest];
    signed.extend(
        list.instances()
            .iter()
            .filter_map(|i| i["digest"].as_str().map(|d| d.parse::<Digest>().unwrap())),
    );
    assert_eq!(signed.len(), 2);
    for d in &signed {
        let manifest = attachments(&a.reg, d).unwrap_or_else(|| panic!("no signature of {d}"));
        let layer = &manifest.layers[0];
        let signature = sigstore::Sigstore {
            mime_type: layer.media_type.clone(),
            payload: a
                .reg
                .blobs
                .lock()
                .unwrap()
                .get(&layer.digest.to_string())
                .cloned()
                .unwrap(),
            annotations: layer.annotations.clone().into_iter().collect(),
        };
        let v = root.verify(&signature, 0).unwrap();
        assert_eq!(v.manifest_digest, d.to_string());
        // (the instances are signed with the name of the list)
        assert_eq!(v.docker_reference, format!("{}/listed:v1", a.host));
    }
}

/// The requests of the signature (the attachment's manifest read, its
/// blobs and manifest put) go through the confined workers like those of
/// the push, which connect: the daemon connects to nothing itself.
#[tokio::test]
async fn test_a_signed_push_through_confined_workers() {
    let dirs = Dirs::new();
    let a = env_with(PullConfig {
        worker_path: Some(registry_bin().into()),
        ..dirs.config()
    })
    .await;
    let (host_b, b) = start_registry().await;
    a.trust(&[&host_b]);
    a.publish(
        &[&build_gzip(&[Item::File {
            name: "etc/hello",
            data: b"hello\n".to_vec(),
            chunk: 4096,
        }])],
        &[GZIP],
    );
    a.pull().await.unwrap();
    dirs.allow(&host_b, "copy");
    let pushed = a
        .service
        .push_with_client(
            &client_for(&[&a.host, &host_b]),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{host_b}/copy:v1")),
                sign: Some(signer()),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(attachments(&b, &pushed.digest).unwrap().layers.len(), 1);
    assert_eq!(b.mine.load(std::sync::atomic::Ordering::SeqCst), 0);
    // and the second signature finds the first one to add to
    a.service
        .push_with_client(
            &client_for(&[&a.host, &host_b]),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{host_b}/copy:v1")),
                sign: Some(signer()),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(attachments(&b, &pushed.digest).unwrap().layers.len(), 2);
}

/// The signatures a container's image must have: `require` wants a
/// requirement of the policy that a signature satisfied for every name of
/// the image, and an image with no name is refused; in every mode the names
/// an image was pulled by are names, judged as its tags.
#[tokio::test]
async fn test_a_required_signature_is_checked_for_every_name_of_the_image() {
    let dirs = Dirs::new();
    let a = source(&dirs).await;
    dirs.allow(&a.host, "copy");
    a.service
        .push_with_client(
            &a.client(),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{}/copy:v1", a.host)),
                sign: Some(signer()),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    let reader = reader_of(&dirs, &a.host).await;
    let name = format!("{}/copy:v1", a.host);
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    reader
        .service
        .pull_with_client(&client_for(&[&a.host]), &name, tx)
        .await
        .unwrap();
    let svc = &reader.service;
    let image = svc.get(&name).await.unwrap();
    let why: &'static str = "[containers] image_signature is \"require\"";
    // (the tags of now, as a create reads them with the image)
    let id = &image.id;
    let tags = move || async move { svc.get_tags(id).await.unwrap() };

    svc.verify_stored(&name, &image, &tags().await, SignatureJudging::Require(why))
        .await
        .unwrap();
    svc.verify_stored(&name, &image, &tags().await, SignatureJudging::Policy)
        .await
        .unwrap();

    // another name, which the policy accepts without a signature
    svc.tag(&image.id, "localhost/free:1").await.unwrap();
    let e = svc
        .verify_stored(&name, &image, &tags().await, SignatureJudging::Require(why))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("localhost/free:1")
            && e.contains("accepts it without a signature")
            && e.ends_with(why),
        "{e}"
    );
    svc.verify_stored(&name, &image, &tags().await, SignatureJudging::Policy)
        .await
        .unwrap();
    svc.untag(&image.id, &["localhost/free:1".to_string()])
        .await
        .unwrap();

    // no tag: the name it was pulled by is a name, judged with the
    // signature stored by the pull, under require as under check
    svc.untag(&image.id, std::slice::from_ref(&name))
        .await
        .unwrap();
    assert!(tags().await.is_empty());
    svc.verify_stored(
        &image.id,
        &image,
        &tags().await,
        SignatureJudging::Require(why),
    )
    .await
    .unwrap();
    svc.verify_stored(&image.id, &image, &tags().await, SignatureJudging::Check)
        .await
        .unwrap();
    // an image never pulled and without a tag has no name: refused under
    // check and require, as by podman's branch, with the same words; the
    // default of a create runs it
    let mut empty = tempfile::tempfile().unwrap();
    std::io::Write::write_all(&mut empty, &[0u8; 1024]).unwrap();
    let id = svc.import_tar(empty, None, &[], None).await.unwrap();
    let unnamed = svc.get(&id).await.unwrap();
    assert!(svc.get_tags(&id).await.unwrap().is_empty());
    let e = svc
        .verify_stored(&id, &unnamed, &[], SignatureJudging::Check)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        e.contains(&format!(
            "image {} has no name the signature policy can be applied to",
            &unnamed.config_digest.hex()[..12]
        )) && e.ends_with("signature=check judges an image by its names"),
        "{e}"
    );
    let e = svc
        .verify_stored(&id, &unnamed, &[], SignatureJudging::Require(why))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("has no name the signature policy can be applied to") && e.ends_with(why),
        "{e}"
    );
    svc.verify_stored(&id, &unnamed, &[], SignatureJudging::Policy)
        .await
        .unwrap();
    // without `require`, the name it was pulled by is judged: it passes
    // with the signature stored by the pull ...
    svc.verify_stored(&image.id, &image, &tags().await, SignatureJudging::Policy)
        .await
        .unwrap();
    // ... and not once the policy wants another key
    let other = openssl::ec::EcKey::generate(
        &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
    )
    .unwrap();
    let other = openssl::pkey::PKey::from_ec_key(other).unwrap();
    std::fs::write(
        dirs.dir.path().join("other.pub"),
        other.public_key_to_pem().unwrap(),
    )
    .unwrap();
    let policy = std::fs::read_to_string(dirs.dir.path().join("policy.json")).unwrap();
    std::fs::write(
        dirs.dir.path().join("policy.json"),
        policy.replace("key.pub", "other.pub"),
    )
    .unwrap();
    let e = svc
        .verify_stored(&image.id, &image, &tags().await, SignatureJudging::Policy)
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("Source image rejected"), "{e}");
    // ... under require too: the name it was pulled by is judged, as by
    // check
    let e = svc
        .verify_stored(
            &image.id,
            &image,
            &tags().await,
            SignatureJudging::Require(why),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("Source image rejected"), "{e}");
}

/// The policy of now judges the image at a start, as `signature=check`
/// asks: signature rules must be satisfied, `reject` refuses (a key removed
/// from the policy, a scope rejected after the container was made), an
/// image the policy accepts without a signature runs; `require` wants a
/// signature for every name; the default of a create applies the signature
/// rules, not `reject` (as podman, which runs the images of its store).
#[tokio::test]
async fn test_the_policy_of_now_is_judged_whole_for_check_and_require() {
    use SignatureJudging::{Check, Policy, Require};
    let dirs = Dirs::new();
    let a = source(&dirs).await;
    dirs.allow(&a.host, "copy");
    a.service
        .push_with_client(
            &a.client(),
            &format!("{}/test:latest", a.host),
            &PushOptions {
                destination: Some(format!("{}/copy:v1", a.host)),
                sign: Some(signer()),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    let reader = reader_of(&dirs, &a.host).await;
    let name = format!("{}/copy:v1", a.host);
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    reader
        .service
        .pull_with_client(&client_for(&[&a.host]), &name, tx)
        .await
        .unwrap();
    let svc = &reader.service;
    let image = svc.get(&name).await.unwrap();
    let tags = svc.get_tags(&image.id).await.unwrap();
    let why: &'static str = "--security-opt signature=require";
    let policy = |json: serde_json::Value| {
        std::fs::write(dirs.dir.path().join("policy.json"), json.to_string()).unwrap()
    };
    let judge = |j| svc.verify_stored(&name, &image, &tags, j);
    let scope = format!("{}/copy", a.host);
    let key = dirs.dir.path().join("key.pub");

    // the signature satisfies the rule
    for j in [Policy, Check, Require(why)] {
        judge(j).await.unwrap();
    }
    // the key is removed from the policy (another one asked): no signature
    // satisfies it
    let other = openssl::ec::EcKey::generate(
        &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dirs.dir.path().join("other.pub"),
        openssl::pkey::PKey::from_ec_key(other)
            .unwrap()
            .public_key_to_pem()
            .unwrap(),
    )
    .unwrap();
    policy(serde_json::json!({
        "default": [{"type": "insecureAcceptAnything"}],
        "transports": {"docker": {&scope: [{"type": "sigstoreSigned", "keyPath": dirs.dir.path().join("other.pub")}]}},
    }));
    for j in [Policy, Check, Require(why)] {
        let e = judge(j).await.unwrap_err().to_string();
        assert!(e.contains("Source image rejected"), "{j:?}: {e}");
    }
    // a scope that is rejected: check and require refuse, naming the scope,
    // also with a signature rule beside it; the default of a create does not
    for reqs in [
        serde_json::json!([{"type": "reject"}]),
        serde_json::json!([{"type": "sigstoreSigned", "keyPath": key}, {"type": "reject"}]),
        serde_json::json!([{"type": "insecureAcceptAnything"}, {"type": "reject"}]),
    ] {
        policy(serde_json::json!({
            "default": [{"type": "insecureAcceptAnything"}],
            "transports": {"docker": {&scope: reqs}},
        }));
        judge(Policy).await.unwrap();
        for j in [Check, Require(why)] {
            let e = judge(j).await.unwrap_err().to_string();
            assert!(
                e.contains("rejects it")
                    && e.contains(&format!("scope {scope}"))
                    && !e.contains("without a signature"),
                "{j:?}: {e}"
            );
        }
    }
    // the policy accepts it without a signature: it runs, unless a
    // signature is required
    policy(serde_json::json!({"default": [{"type": "insecureAcceptAnything"}]}));
    judge(Policy).await.unwrap();
    judge(Check).await.unwrap();
    let e = judge(Require(why)).await.unwrap_err().to_string();
    assert!(e.contains("accepts it without a signature"), "{e}");
    // and under a default that rejects, check and require refuse a name of
    // a registry, naming the default; the default of a create does not
    policy(serde_json::json!({"default": [{"type": "reject"}]}));
    judge(Policy).await.unwrap();
    for j in [Check, Require(why)] {
        let e = judge(j).await.unwrap_err().to_string();
        assert!(e.contains("rejects it (the default)"), "{j:?}: {e}");
    }
}

/// An image velarx made states the fs-verity digest of the EROFS image of
/// each layer on its descriptor: a signed push signs those bytes, so the
/// signature covers the digests, and a manifest whose layer annotation was
/// edited is another manifest that no signature covers.
#[tokio::test]
async fn test_a_signed_push_of_a_velarx_image_signs_the_layer_digests() {
    const KEY: &str = velarx_core::services::LAYER_EROFS_ANNOTATION;
    let dirs = Dirs::new();
    let a = source(&dirs).await;
    dirs.allow(&a.host, "built");
    let parent = a
        .service
        .get(&format!("{}/test:latest", a.host))
        .await
        .unwrap();
    let changes = tempfile::tempdir().unwrap();
    std::fs::create_dir(changes.path().join("app")).unwrap();
    std::fs::write(changes.path().join("app/new"), b"made by velarx\n").unwrap();
    let id = a
        .service
        .commit_dir(
            Some(&parent.id),
            Some(changes.path()),
            &velarx_core::services::CommitOptions {
                names: vec!["built:v1".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let pushed = a
        .service
        .push_with_client(
            &a.client(),
            &id,
            &PushOptions {
                destination: Some(format!("{}/built:v1", a.host)),
                sign: Some(signer()),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();

    // The manifest signed is the one velarx wrote, with the digests
    let body = a.reg.blobs.lock().unwrap()[&format!("manifest:{}", pushed.digest)].clone();
    assert_eq!(sha(&body), pushed.digest);
    let m: OciManifest = serde_json::from_slice(&body).unwrap();
    assert_eq!(m.layers.len(), 2);
    // (the layers of the image are what the push compressed: the EROFS
    // images are those of the layers of the store)
    let stored = a.db.get_image_layers(&id).await.unwrap();
    assert_eq!(stored.len(), m.layers.len());
    for (l, record) in m.layers.iter().zip(&stored) {
        assert_eq!(
            l.annotations[KEY],
            record.erofs.clone().unwrap(),
            "{}",
            l.digest
        );
    }
    let attachment = attachments(&a.reg, &pushed.digest).expect("a sigstore attachment");
    let layer = &attachment.layers[0];
    let signature = sigstore::Sigstore {
        mime_type: layer.media_type.clone(),
        payload: a.reg.blobs.lock().unwrap()[&layer.digest.to_string()].clone(),
        annotations: layer.annotations.clone().into_iter().collect(),
    };
    let root = TrustRoot {
        public_keys: vec![sigstore::public_key_from_pem(PUBLIC.as_bytes()).unwrap()],
        ..Default::default()
    };
    let verified = root.verify(&signature, 0).unwrap();
    assert_eq!(verified.manifest_digest, pushed.digest.to_string());
    assert!(sigstore::manifest_matches(&body, &verified.manifest_digest));
    pulled(&a.host, &dirs, &format!("{}/built:v1", a.host))
        .await
        .unwrap();

    // The same manifest with another digest in the annotation of a layer,
    // under the signed tag: the signature is not over it
    let mut edited: serde_json::Value = serde_json::from_slice(&body).unwrap();
    edited["layers"][1]["annotations"][KEY] =
        serde_json::json!(format!("sha256:{}", "ab".repeat(32)));
    let edited = serde_json::to_vec(&edited).unwrap();
    assert!(!sigstore::manifest_matches(
        &edited,
        &verified.manifest_digest
    ));
    {
        let mut blobs = a.reg.blobs.lock().unwrap();
        blobs.insert("manifest:v1".into(), edited.clone());
        blobs.insert(format!("manifest:{}", sha(&edited)), edited);
    }
    let reader = reader_of(&dirs, &a.host).await;
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let e = reader
        .service
        .pull_with_client(&client_for(&[&a.host]), &format!("{}/built:v1", a.host), tx)
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("Source image rejected"), "{e}");
    assert!(reader.db.list_images().await.unwrap().is_empty());
}
