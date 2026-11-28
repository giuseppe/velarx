// SPDX-License-Identifier: Apache-2.0
//! The tags, searches, logins, remote inspections and pushes of a command
//! reach the registry through the fetcher: the process that
//! asks (here, the test, standing for the engine) opens no connection to
//! the registry and, for the credentials a command brings, passes them in a
//! sealed memory file.

use crate::common::*;
use crate::fetcher_tests::registry_spawner_for;
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use velarx_content::layer::writer::Compression;
use velarx_content::pull::net::origin::OriginRemote;
use velarx_core::services::{PullOptions, PushOptions, SearchOptions};
use velarx_registry::auth::RegistryAccess;
use velarx_registry::Credentials;

const ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

/// An environment whose registry requests go to a fetcher
/// process: its own client could not reach the registries.
struct Remote {
    env: Env,
    origin: Arc<velarx_content::list::RegistryOrigin>,
    /// A second registry, to push to
    other_host: String,
    other: Arc<Registry>,
    _dir: tempfile::TempDir,
}

async fn remote() -> Remote {
    remote_with(&[]).await
}

/// [`remote`], the fetcher knowing also the registries `more` as plain
/// http.
async fn remote_with(more: &[&str]) -> Remote {
    let mut env = env().await;
    let (other_host, other) = start_registry().await;
    let dir = tempfile::tempdir().unwrap();
    let mut hosts = vec![env.host.as_str(), other_host.as_str()];
    hosts.extend(more);
    // (the fetcher writes into the staging of the environment's store)
    let (spawner, _) = registry_spawner_for(env._tmp.path(), &hosts, true);
    let origin = velarx_content::list::RegistryOrigin::with_shared(spawner, &Default::default());
    let service = std::mem::ManuallyDrop::into_inner(env.service);
    env.service = std::mem::ManuallyDrop::new(service.with_origin(origin.clone()));
    Remote {
        env,
        origin,
        other_host,
        other,
        _dir: dir,
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
    ]
}

/// No connection of the registries came from this process, and they were
/// asked.
fn nothing_from_here(r: &Remote) {
    for reg in [&r.env.reg, &r.other] {
        assert!(reg.requests.load(Ordering::SeqCst) > 0);
        assert_eq!(
            reg.mine.load(Ordering::SeqCst),
            0,
            "a request of the engine"
        );
    }
}

/// The pull, the inspection, the tags, the search and the push of an image
/// are all made by the fetcher.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_the_engine_opens_no_connection_to_a_registry() {
    let r = remote().await;
    let layer = build_written(&tar_of(&items()), Compression::ZstdChunked);
    let digest = publish_to(&r.env.reg, &[&layer], &[ZSTD]);
    // (the pull of the test is made with the client the test gives it)
    r.env.pull().await.unwrap();
    r.env.reg.mine.store(0, Ordering::SeqCst);
    let host = r.env.host.clone();
    let options = PullOptions::default();

    // what the remote registry has, without pulling it
    let described = r
        .env
        .service
        .remote_descriptor(&format!("{host}/test:latest"), &options)
        .await
        .unwrap();
    assert_eq!(described.digest, digest);

    let tags = r
        .env
        .service
        .repository_tags(&format!("{host}/test"), &options)
        .await
        .unwrap();
    assert_eq!(tags, ["latest", "v1"]);
    let listed = r
        .env
        .service
        .search(
            &format!("{host}/test"),
            &SearchOptions {
                list_tags: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(listed.len(), 2);

    // a search (the registry has no search of its own: its catalog)
    let found = r
        .env
        .service
        .search(&format!("{host}/test"), &SearchOptions::default())
        .await
        .unwrap();
    assert!(
        found.iter().any(|f| f.name == format!("{host}/test")),
        "{found:?}"
    );

    // a push: the blobs, a mount-free upload and the manifest
    let client = client_for(&[&host, &r.other_host]);
    let pushed = r
        .env
        .service
        .push_with_client(
            &client,
            &format!("{host}/test:latest"),
            &PushOptions {
                destination: Some(format!("{}/copy:v1", r.other_host)),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(pushed.digest, digest);
    assert!(r.other.has("copy", &sha(&layer.blob)));
    assert!(
        r.other.logged("PUT") >= 1,
        "{:?}",
        r.other.log.lock().unwrap()
    );

    nothing_from_here(&r);
}

/// A registry that wants basic credentials.  It notes the `Authorization`
/// of each request and whether the connection was this process's.
struct Guarded {
    host: String,
    seen: Arc<Mutex<Vec<Option<String>>>>,
    mine: Arc<AtomicUsize>,
}

async fn guarded(user: &'static str, password: &'static str) -> Guarded {
    use base64::Engine as _;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mine = Arc::new(AtomicUsize::new(0));
    let wanted = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    );
    let gate = move |h: &HeaderMap, seen: &Mutex<Vec<Option<String>>>| {
        let got = h
            .get(header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap().to_string());
        seen.lock().unwrap().push(got.clone());
        (got.as_deref() != Some(wanted.as_str())).then(|| {
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"test\"")],
            )
                .into_response()
        })
    };
    let (s1, g1) = (seen.clone(), gate.clone());
    let (s2, g2) = (seen.clone(), gate);
    let app = Router::new()
        .route(
            "/v2/",
            get(move |h: HeaderMap| {
                let (s, g) = (s1.clone(), g1.clone());
                async move { g(&h, &s).unwrap_or_else(|| StatusCode::OK.into_response()) }
            }),
        )
        .route(
            "/v2/r/tags/list",
            get(move |h: HeaderMap| {
                let (s, g) = (s2.clone(), g2.clone());
                async move {
                    g(&h, &s)
                        .unwrap_or_else(|| r#"{"name":"r","tags":["guarded"]}"#.into_response())
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let host = format!("127.0.0.1:{port}");
    let count = mine.clone();
    let app = app.layer(axum::middleware::from_fn(
        move |ConnectInfo(peer): ConnectInfo<SocketAddr>,
              req: axum::extract::Request,
              next: axum::middleware::Next| {
            let count = count.clone();
            async move {
                if connection_is_mine(peer.port(), port) {
                    count.fetch_add(1, Ordering::SeqCst);
                }
                next.run(req).await
            }
        },
    ));
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap()
    });
    Guarded { host, seen, mine }
}

fn access_of(user: &str, password: &str) -> RegistryAccess {
    RegistryAccess {
        creds: Some(Credentials::basic(user, password)),
        ..Default::default()
    }
}

/// The credentials of a command reach the fetcher in a sealed memory file, the
/// registry gets them from it, and a wrong password is refused there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_the_credentials_of_a_command_go_to_the_fetcher_in_a_file() {
    let g = guarded("u", "marker-password").await;
    let r = remote_with(&[&g.host]).await;
    let tags = format!("{}/r", g.host);
    let with = |user, password| PullOptions {
        access: access_of(user, password),
        ..PullOptions::default()
    };
    let got = r
        .env
        .service
        .repository_tags(&tags, &with("u", "marker-password"))
        .await
        .unwrap();
    assert_eq!(got, ["guarded"]);
    assert!(g
        .seen
        .lock()
        .unwrap()
        .iter()
        .any(|a| a.as_deref().is_some_and(|a| a.starts_with("Basic "))));

    // the wrong password, and none at all, are refused
    let denied = r
        .env
        .service
        .repository_tags(&tags, &with("u", "wrong"))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        denied.contains("401") || denied.contains("nauthorized"),
        "{denied}"
    );
    r.env
        .service
        .repository_tags(&tags, &PullOptions::default())
        .await
        .unwrap_err();

    // a login: the registry takes the credentials, or it does not
    let login = |user: &str, password: &str| {
        OriginRemote::new(
            r.origin.clone(),
            &format!("{}/library/login", g.host),
            true,
            &access_of(user, password),
        )
        .unwrap()
    };
    login("u", "marker-password").login().await.unwrap();
    let refused = login("u", "wrong").login().await.unwrap_err();
    assert!(
        matches!(&refused, velarx_types::ImageError::Transfer { failure, .. } if failure.class == velarx_proto::transfer::FailureClass::Unauthorized && failure.reason == "invalid username/password"),
        "{refused}"
    );
    // the login of the Podman API (`POST /auth`) is checked there too (a
    // registry on the loopback that registries.conf marks insecure: podman
    // checks no certificate of the loopback there)
    let host = &g.host;
    let service = &(*r.env.service).clone().with_resolver(client_for(&[host]));
    service
        .login(host, &access_of("u", "marker-password"))
        .await
        .unwrap();
    let refused = service
        .login(host, &access_of("u", "wrong"))
        .await
        .unwrap_err();
    assert!(
        matches!(&refused, velarx_types::ImageError::Transfer { failure, .. } if failure.class == velarx_proto::transfer::FailureClass::Unauthorized && failure.reason == "invalid username/password"),
        "{refused}"
    );

    assert_eq!(g.mine.load(Ordering::SeqCst), 0, "a request of the engine");
}

/// A pull with the credentials of the command, and the completion of a lazy
/// pull that needs them again, are made by the fetcher too: the engine
/// opens no connection to the registry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_pull_with_credentials_is_made_by_the_fetcher() {
    let r = remote().await;
    let host = r.env.host.clone();
    let layer = build_written(&tar_of(&items()), Compression::ZstdChunked);
    publish_to(&r.env.reg, &[&layer], &[ZSTD]);
    let other = build_written(
        &tar_of(&[Item::File {
            name: "etc/other",
            data: b"other\n".to_vec(),
            chunk: 4096,
        }]),
        Compression::ZstdChunked,
    );
    publish_arch(&r.env.reg, &[&other], &[ZSTD], "amd64", "lazy");
    let options = PullOptions {
        access: access_of("u", "marker-password"),
        ..PullOptions::default()
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    r.env
        .service
        .pull_with(&format!("{host}/test:latest"), false, &options, tx.clone())
        .await
        .unwrap();
    let lazy = format!("{host}/test:lazy");
    r.env
        .service
        .pull_with(&lazy, true, &options, tx)
        .await
        .unwrap();
    r.env
        .service
        .complete_image_with(&lazy, options.access.clone())
        .await
        .unwrap();
    assert!(r.env.reg.requests.load(Ordering::SeqCst) > 0);
    assert_eq!(
        r.env.reg.mine.load(Ordering::SeqCst),
        0,
        "a request of the engine"
    );
}

/// A fetcher that runs longer than a command reads a `login` or a
/// `logout` made since it started: the credentials of the auth file are
/// used once they are there, and no more once they are gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_running_fetcher_reads_a_login_and_a_logout() {
    use base64::Engine as _;
    let g = guarded("u", "marker-password").await;
    let r = remote_with(&[&g.host]).await;
    // (the file `login` writes, in the runtime directory of the fetcher)
    let auth = r.env._tmp.path().join("run/velarx/auth/auth.json");
    let tags = format!("{}/r", g.host);
    let none = PullOptions::default();
    r.env
        .service
        .repository_tags(&tags, &none)
        .await
        .unwrap_err();
    // (written as `login` does: a new file put in place)
    let write = |json: String| {
        let new = auth.with_extension("new");
        std::fs::write(&new, json).unwrap();
        std::fs::rename(&new, &auth).unwrap();
    };
    let basic = base64::engine::general_purpose::STANDARD.encode("u:marker-password");
    write(format!(
        r#"{{"auths":{{"{}":{{"auth":"{basic}"}}}}}}"#,
        g.host
    ));
    let got = r.env.service.repository_tags(&tags, &none).await.unwrap();
    assert_eq!(got, ["guarded"]);
    write(r#"{"auths":{}}"#.to_string());
    r.env
        .service
        .repository_tags(&tags, &none)
        .await
        .unwrap_err();
    assert_eq!(g.mine.load(Ordering::SeqCst), 0, "a request of the engine");
}

/// The password is in no message and no debug text of the asker: only in
/// the file.
#[tokio::test]
async fn test_no_secret_is_in_a_message() {
    let dir = tempfile::tempdir().unwrap();
    let access =
        velarx_content::fetcher::fetch_client::Access::new(&access_of("user", "marker-password"))
            .unwrap()
            .unwrap();
    let remote = velarx_content::fetcher::proto::Remote {
        repository: "registry.example/r".into(),
        tls_verify: Some(true),
        access: Some(0),
    };
    for text in [
        format!("{access:?}"),
        format!("{remote:?}"),
        serde_json::to_string(&remote).unwrap(),
    ] {
        assert!(!text.contains("marker-password"), "{text}");
    }
    // it is in memory: nothing was made in the directory
    assert!(!dir.path().join("incoming").exists());
}

/// `--tls-verify=false` for a registry that registries.conf does not mark
/// insecure: the fetcher makes the requests on the asker's word, with the
/// credentials of the call first and then its own, as for a verified
/// request, so the same bytes reach the same unchecked host whoever looked
/// them up; this process opens no connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_request_without_tls_verification_uses_the_credentials_of_the_call_then_its_own() {
    use base64::Engine as _;
    let g = guarded("u", "marker-password").await;
    let dir = tempfile::tempdir().unwrap();
    // (the registry is not marked insecure)
    let (spawner, _) = registry_spawner_for(dir.path(), &[&g.host], false);
    let origin = velarx_content::list::RegistryOrigin::with_shared(spawner, &Default::default());
    // the fetcher has credentials of its own for it
    let auth = dir.path().join("run/velarx/auth/auth.json");
    std::fs::create_dir_all(auth.parent().unwrap()).unwrap();
    let basic = base64::engine::general_purpose::STANDARD.encode("u:marker-password");
    std::fs::write(
        &auth,
        format!(r#"{{"auths":{{"{}":{{"auth":"{basic}"}}}}}}"#, g.host),
    )
    .unwrap();
    let tags = |access: RegistryAccess| {
        let (origin, repository) = (origin.clone(), format!("{}/r", g.host));
        async move {
            OriginRemote::new(origin, &repository, false, &access)
                .unwrap()
                .tags()
                .await
        }
    };
    let sent = |g: &Guarded| {
        let seen = g.seen.lock().unwrap();
        let last = seen.last().cloned().flatten();
        let all_anonymous = seen.iter().all(Option::is_none);
        (last, all_anonymous)
    };
    // a call without credentials is answered with the fetcher's own
    g.seen.lock().unwrap().clear();
    assert_eq!(tags(RegistryAccess::default()).await.unwrap(), ["guarded"]);
    let (stored, all_anonymous) = sent(&g);
    assert!(!all_anonymous);
    assert_eq!(stored.as_deref(), Some(format!("Basic {basic}").as_str()));
    // the credentials of the call are the same bytes on the wire
    g.seen.lock().unwrap().clear();
    assert_eq!(
        tags(access_of("u", "marker-password")).await.unwrap(),
        ["guarded"]
    );
    assert_eq!(sent(&g).0, stored);
    // and come first: wrong ones are refused, the stored ones are not tried
    g.seen.lock().unwrap().clear();
    let refused = tags(access_of("u", "wrong")).await.unwrap_err().to_string();
    assert!(
        refused.contains("401") || refused.contains("nauthorized"),
        "{refused}"
    );
    assert!(
        !g.seen.lock().unwrap().contains(&stored),
        "the stored credentials were tried after the call's"
    );
    assert_eq!(g.mine.load(Ordering::SeqCst), 0, "a request of the engine");
}

/// A registry that names a manifest put by a tag with its sha256 (as
/// registry:3 and zot do), takes the manifest by a sha256 digest, and by a
/// sha512 digest only if `takes_sha512`; the references put are what it
/// returns.  The puts go through the registry fetcher, as a pusher.
async fn manifest_registry(
    dir: &std::path::Path,
    takes_sha512: bool,
) -> (
    velarx_content::fetcher::fetch_client::FetchConn,
    Arc<Mutex<Vec<String>>>,
) {
    use axum::extract::{Path, State};
    use velarx_types::digest::{Algorithm, Digest};
    let puts = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/v2/", get(|| async { "{}" }))
        .route(
            "/v2/r/manifests/:reference",
            axum::routing::put(
                move |State(puts): State<Arc<Mutex<Vec<String>>>>,
                      Path(reference): Path<String>,
                      body: axum::body::Bytes| async move {
                    puts.lock().unwrap().push(reference.clone());
                    if reference.starts_with("sha512:") && !takes_sha512 {
                        return (
                            StatusCode::BAD_REQUEST,
                            r#"{"errors":[{"code":"DIGEST_INVALID","message":"provided digest did not match uploaded content"}]}"#,
                        )
                            .into_response();
                    }
                    let named = if reference.starts_with("sha512:") {
                        Digest::of(Algorithm::Sha512, &body)
                    } else {
                        Digest::of(Algorithm::Sha256, &body)
                    };
                    (
                        StatusCode::CREATED,
                        [("docker-content-digest", named.to_string())],
                    )
                        .into_response()
                },
            ),
        )
        .with_state(puts.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let origin = origin_for(dir, &conf_for(&[&host]), &Default::default());
    let mut conn = origin.connect().await.unwrap();
    push_scope(&mut conn, &format!("{host}/r")).await.unwrap();
    (conn, puts)
}

const MANIFEST_MEDIA: &str = "application/vnd.oci.image.manifest.v1+json";
const MANIFEST_BODY: &[u8] = br#"{"schemaVersion":2,"layers":[]}"#;

/// The manifest of `MANIFEST_BODY` in the algorithm `alg`, and a data file
/// that holds it.
fn manifest_of(
    alg: velarx_types::digest::Algorithm,
) -> (velarx_content::pusher::push::Object, std::fs::File) {
    use std::io::Write;
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(MANIFEST_BODY).unwrap();
    let object = velarx_content::pusher::push::Object {
        digest: velarx_types::digest::Digest::of(alg, MANIFEST_BODY).to_string(),
        size: MANIFEST_BODY.len() as u64,
        media_type: MANIFEST_MEDIA.into(),
        role: velarx_content::pusher::push::Role::Manifest,
        known_at: None,
    };
    (object, file)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_sha512_manifest_put_by_a_tag_is_put_by_its_digest_too() {
    use velarx_types::digest::Algorithm;
    let dir = tempfile::tempdir().unwrap();
    let (mut conn, puts) = manifest_registry(dir.path(), true).await;
    let (manifest, body) = manifest_of(Algorithm::Sha512);
    let reply = conn
        .push_commit(&manifest, &["t".to_string()], &body)
        .await
        .unwrap();
    assert_eq!(reply.digest, manifest.digest);
    assert!(
        reply.placed.iter().all(|p| p.accepted),
        "{:?}",
        reply.placed
    );
    assert_eq!(reply.placed.len(), 2);
    assert_eq!(*puts.lock().unwrap(), ["t".to_string(), manifest.digest]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_registry_that_refuses_the_digest_keeps_the_tag_and_says_so() {
    use velarx_types::digest::Algorithm;
    let dir = tempfile::tempdir().unwrap();
    let (mut conn, puts) = manifest_registry(dir.path(), false).await;
    let (manifest, body) = manifest_of(Algorithm::Sha512);
    let reply = conn
        .push_commit(&manifest, &["t".to_string()], &body)
        .await
        .unwrap();
    assert_eq!(reply.digest, manifest.digest);
    let refused: Vec<_> = reply.placed.iter().filter(|p| !p.accepted).collect();
    assert_eq!(refused.len(), 1, "{:?}", reply.placed);
    assert_eq!(refused[0].name, None, "the digest is the one refused");
    assert!(reply
        .placed
        .iter()
        .any(|p| p.name.as_deref() == Some("t") && p.accepted));
    let answer = refused[0].reason.clone().expect("the refusal is told");
    assert!(answer.starts_with("400 Bad Request"), "{answer}");
    assert!(answer.contains("DIGEST_INVALID"), "{answer}");
    assert!(!answer.contains("push the image by its tag"), "{answer}");
    assert_eq!(puts.lock().unwrap().len(), 2);
    // the explicit push by the digest fails by name
    let e = conn.push_commit(&manifest, &[], &body).await.unwrap_err();
    assert!(
        e.to_string().contains("Failed to push manifest: 400"),
        "{e}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_sha256_manifest_or_a_digest_reference_is_put_once() {
    use velarx_types::digest::Algorithm;
    let dir = tempfile::tempdir().unwrap();
    let (mut conn, puts) = manifest_registry(dir.path(), false).await;
    let (manifest, body) = manifest_of(Algorithm::Sha256);
    let reply = conn
        .push_commit(&manifest, &["t".to_string()], &body)
        .await
        .unwrap();
    assert!(
        reply.placed.iter().all(|p| p.accepted),
        "{:?}",
        reply.placed
    );
    assert_eq!(*puts.lock().unwrap(), ["t".to_string()]);
    conn.push_commit(&manifest, &[], &body).await.unwrap();
    assert_eq!(puts.lock().unwrap().len(), 2);
}
